use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{JSXText, RegExpLiteral, StringLiteral, TemplateElement};
use oxc_ast_visit::Visit;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use regex::Regex;
use std::borrow::Cow;
use std::panic::AssertUnwindSafe;

pub(super) struct SourceContext<'s> {
    pub stripped: Cow<'s, str>,
    pub executable: Vec<u8>,
    pub complete: bool,
    pub calls: Option<super::bindings::CallFacts>,
    /// Whether the parser found a random-looking string literal, or `None`
    /// when it didn't read the literals.
    pub random_literal: Option<bool>,
}

/// Room kept below a parse's stack floor: the parser checks the floor once
/// per token, the literal visitor once per node, so this covers the frames
/// between two checks and the unwinding after one fails.
const STACK_RED_ZONE: usize = 256 * 1024;

/// Stack for a parse that ran out of the stack its caller had left. A
/// source that runs out of this too is read without parsing; an adversary
/// can make a parse touch at most this much of it.
const DEEP_PARSE_STACK: usize = 64 * 1024 * 1024;

/// Stack semantic analysis takes before any nesting, and per level of AST
/// depth: the most measured for any construct, with room for platforms
/// whose frames are larger. Semantic analysis is the one recursive pass
/// that can't check the stack itself, so the literal visitor measures the
/// AST's depth first and the pass runs only when this much stack is left.
const SEMANTIC_BASE_STACK: usize = 128 * 1024;
const SEMANTIC_LEVEL_STACK: usize = if cfg!(debug_assertions) {
    8 * 1024
} else {
    2 * 1024
};

/// A visitor stopped at the stack floor.
struct StackExhausted;

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
    random_literal: bool,
    stack_floor: usize,
    depth: usize,
    max_depth: usize,
}

impl LiteralSpans<'_> {
    fn note_value(&mut self, value: Option<&str>) {
        self.random_literal |= value.is_some_and(super::supply_chain::looks_random);
    }
}

fn mask(bytes: &mut [u8], span: Span) {
    if let Some(range) = bytes.get_mut(span.start as usize..span.end as usize) {
        for byte in range {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
}

/// An address in the calling frame, close to the stack pointer.
#[inline(always)]
fn stack_address() -> usize {
    let marker = 0u8;
    (&raw const marker).addr()
}

impl<'a> Visit<'a> for LiteralSpans<'_> {
    fn enter_node(&mut self, _kind: AstKind<'a>) {
        if stack_address() < self.stack_floor {
            std::panic::resume_unwind(Box::new(StackExhausted));
        }
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
    }

    fn leave_node(&mut self, _kind: AstKind<'a>) {
        self.depth -= 1;
    }

    fn visit_string_literal(&mut self, literal: &StringLiteral<'a>) {
        mask(self.executable, literal.span);
        if !self.random_literal {
            self.note_value(literal.value.as_str());
        }
    }

    fn visit_reg_exp_literal(&mut self, literal: &RegExpLiteral<'a>) {
        mask(self.executable, literal.span);
    }

    fn visit_template_element(&mut self, literal: &TemplateElement<'a>) {
        mask(self.executable, literal.span);
        if !self.random_literal {
            let value = match literal.value.cooked {
                Some(cooked) => cooked.as_str(),
                None => Some(literal.value.raw.as_str()),
            };
            self.note_value(value);
        }
    }

    fn visit_jsx_text(&mut self, literal: &JSXText<'a>) {
        mask(self.executable, literal.span);
    }
}

/// What parsing a source file found.
struct Parsed {
    executable: Vec<u8>,
    complete: bool,
    calls: Option<super::bindings::CallFacts>,
    random_literal: Option<bool>,
}

/// Parses `source` and runs the syntax passes over it, masking its comments
/// in `stripped`, which holds a copy of it. `None` when a pass would go
/// below `stack_floor`: the source nests too deeply for the stack left.
fn parse_above(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
    stack_floor: usize,
) -> Option<Parsed> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            stack_floor,
            ..ParseOptions::default()
        })
        .parse();
    if parsed.stack_exhausted {
        return None;
    }
    for comment in &parsed.program.comments {
        mask(stripped, comment.span);
    }
    let mut executable = stripped.to_vec();
    let mut literals = LiteralSpans {
        executable: &mut executable,
        random_literal: false,
        stack_floor,
        depth: 0,
        max_depth: 0,
    };
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        literals.visit_program(&parsed.program);
    }))
    .ok()?;
    let random_literal = (!parsed.fatal_error).then_some(literals.random_literal);
    let complete = !parsed.fatal_error && !parsed.diagnostics.has_errors();
    let semantic_stack = literals
        .max_depth
        .saturating_mul(SEMANTIC_LEVEL_STACK)
        .saturating_add(SEMANTIC_BASE_STACK);
    if complete && stack_address().saturating_sub(stack_floor) < semantic_stack {
        return None;
    }
    let calls = complete.then(|| super::bindings::analyze(&parsed.program, complete_input));
    Some(Parsed {
        executable,
        complete,
        calls,
        random_literal,
    })
}

/// The lowest address a parse on the current stack may use, or `None` when
/// the stack's extent isn't known or less than the red zone is left.
fn current_stack_floor() -> Option<usize> {
    let remaining = stacker::remaining_stack()?;
    (remaining > 2 * STACK_RED_ZONE)
        .then(|| stack_address().saturating_sub(remaining) + STACK_RED_ZONE)
}

/// Parses `source` on the stack its caller has left, or, when it nests too
/// deeply for that, on a [`DEEP_PARSE_STACK`] segment. `None` when it nests
/// too deeply for that too.
fn parse(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
) -> Option<Parsed> {
    let remaining = stacker::remaining_stack().unwrap_or(0);
    if let Some(floor) = current_stack_floor()
        && let Some(parsed) = parse_above(source, source_type, stripped, complete_input, floor)
    {
        return Some(parsed);
    }
    if remaining >= DEEP_PARSE_STACK {
        return None;
    }
    stacker::grow(DEEP_PARSE_STACK, || {
        let floor = current_stack_floor()?;
        parse_above(source, source_type, stripped, complete_input, floor)
    })
}

impl<'s> SourceContext<'s> {
    pub fn new(source: &str, filename: &str, stripped: &'s mut Vec<u8>) -> Self {
        Self::with_complete_input(source, filename, stripped, true)
    }

    /// Reads `source`, parsed when `filename` names JavaScript or
    /// TypeScript and it nests no deeper than a parse has stack for. Other
    /// source is read without parsing, by the linear detectors.
    pub fn with_complete_input(
        source: &str,
        filename: &str,
        stripped: &'s mut Vec<u8>,
        complete_input: bool,
    ) -> Self {
        stripped.clear();
        stripped.extend_from_slice(source.as_bytes());
        let parsed = SourceType::from_path(filename)
            .ok()
            .and_then(|source_type| parse(source, source_type, stripped, complete_input));
        let Parsed {
            executable,
            complete,
            calls,
            random_literal,
        } = parsed.unwrap_or_else(|| Parsed {
            executable: source.as_bytes().to_vec(),
            complete: false,
            calls: None,
            random_literal: None,
        });
        Self {
            stripped: String::from_utf8_lossy(stripped),
            executable,
            complete,
            calls,
            random_literal,
        }
    }

    pub fn find_with_context(&self, regex: &Regex, bare: bool) -> Option<usize> {
        self.matches_with_context(regex, bare).next()
    }

    pub fn count_with_context(&self, regex: &Regex, bare: bool) -> usize {
        self.matches_with_context(regex, bare).count()
    }

    /// Starts of the matches that begin in code, outside comments and literals,
    /// and with `bare`, not as a property of something else.
    fn matches_with_context<'r>(
        &'r self,
        regex: &'r Regex,
        bare: bool,
    ) -> impl Iterator<Item = usize> + 'r {
        regex
            .find_iter(&self.stripped)
            .filter(move |matched| {
                self.executable
                    .get(matched.start())
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                    && (!bare
                        || !self.stripped.as_bytes()[..matched.start()]
                            .iter()
                            .rev()
                            .find(|byte| !byte.is_ascii_whitespace())
                            .is_some_and(|byte| matches!(byte, b'.' | b'$')))
            })
            .map(|matched| matched.start())
    }
}
