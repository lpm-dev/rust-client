use oxc_allocator::Allocator;
use oxc_ast::ast::{JSXText, RegExpLiteral, StringLiteral, TemplateElement};
use oxc_ast_visit::Visit;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use regex::Regex;
use std::borrow::Cow;

pub(super) struct SourceContext<'s> {
    pub stripped: Cow<'s, str>,
    pub executable: Vec<u8>,
    pub complete: bool,
    pub calls: Option<super::bindings::CallFacts>,
    /// Whether the parser found a random-looking string literal, or `None`
    /// when it didn't read the literals.
    pub random_literal: Option<bool>,
}

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
    random_literal: bool,
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

impl<'a> Visit<'a> for LiteralSpans<'_> {
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

/// Parses `source`, masking its comments in `stripped`, which holds a copy
/// of it.
fn parse(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
) -> Parsed {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            ..ParseOptions::default()
        })
        .parse();
    for comment in &parsed.program.comments {
        mask(stripped, comment.span);
    }
    let mut executable = stripped.to_vec();
    let mut literals = LiteralSpans {
        executable: &mut executable,
        random_literal: false,
    };
    literals.visit_program(&parsed.program);
    let random_literal = (!parsed.fatal_error).then_some(literals.random_literal);
    let complete = !parsed.fatal_error && !parsed.diagnostics.has_errors();
    let calls = complete.then(|| super::bindings::analyze(&parsed.program, complete_input));
    Parsed {
        executable,
        complete,
        calls,
        random_literal,
    }
}

/// The most stack a parse takes on the thread that asks for it. A deeper
/// parse runs on a thread of its own with the stack it needs, so it doesn't
/// depend on the stack left to a caller such as a rayon worker.
const INLINE_STACK_BYTES: usize = 1024 * 1024;

/// Runs `parse` with `stack_bytes` of stack. `None` when a thread with that
/// much stack can't be started.
fn with_stack<T: Send>(stack_bytes: usize, parse: impl FnOnce() -> T + Send) -> Option<T> {
    if stack_bytes <= INLINE_STACK_BYTES {
        return Some(parse());
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("lpm-source-parse".into())
            .stack_size(stack_bytes)
            .spawn_scoped(scope, parse)
            .ok()?
            .join()
            .ok()
    })
}

impl<'s> SourceContext<'s> {
    pub fn new(source: &str, filename: &str, stripped: &'s mut Vec<u8>) -> Self {
        Self::with_complete_input(source, filename, stripped, true)
    }

    /// Reads `source`, parsed when `filename` names JavaScript or
    /// TypeScript and the parse fits the stack a parse is given. Other
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
            .and_then(|source_type| {
                let stack_bytes = super::nesting::parse_stack_bytes(source.as_bytes())?;
                let stripped = &mut stripped[..];
                with_stack(stack_bytes, move || {
                    parse(source, source_type, stripped, complete_input)
                })
            });
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
