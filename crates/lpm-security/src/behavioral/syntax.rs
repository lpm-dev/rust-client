use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{Expression, JSXText, RegExpLiteral, Statement, StringLiteral, TemplateElement};
use oxc_ast_visit::{Visit, walk};
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

/// How far below the stack floor the literal visitor gives up on a node
/// by unwinding. Expressions and statements, which deep nesting recurses
/// through, stop at the floor itself without unwinding; only recursion
/// through other nodes gets this far. The red zone below the floor holds
/// it.
const UNWIND_BELOW_FLOOR: usize = 64 * 1024;

/// Stack for a parse that ran out of the stack its caller had left. A
/// source that runs out of this too is read without parsing; an adversary
/// can make a parse touch at most this much of it.
const DEEP_PARSE_STACK: usize = 64 * 1024 * 1024;

/// Stack semantic analysis takes before any nesting, and per level of AST
/// depth: at least twice the most measured for any construct, so platforms
/// with larger frames fit too. Semantic analysis is the one recursive pass
/// that can't check the stack itself, so the literal visitor measures the
/// AST's depth first, and the pass runs on a stack this large.
const SEMANTIC_BASE_STACK: usize = 128 * 1024;
const SEMANTIC_LEVEL_STACK: usize = if cfg!(debug_assertions) {
    8 * 1024
} else {
    2 * 1024
};

/// The most stack semantic analysis is given. Only pages it touches use
/// memory, and a left-deep chain, the deepest AST a source can have without
/// the parser recursing, touches a small fraction of its reservation.
const SEMANTIC_MAX_STACK: usize = 256 * 1024 * 1024;

/// Lookups semantic analysis may spend resolving names, per byte of
/// source and for any source. Resolving a reference looks for its name in
/// each scope around it, and a reference in a function's parameters is
/// looked up again for each function around it, so a source that nests
/// thousands of scopes around each of its references makes the analysis
/// quadratic. Real code nests a few scopes deep.
const RESOLUTION_LOOKUPS_PER_BYTE: u64 = 16;
const RESOLUTION_LOOKUPS_FLOOR: u64 = 1 << 20;

/// A visitor stopped at the stack floor.
struct StackExhausted;

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
    random_literal: bool,
    stack_floor: usize,
    depth: usize,
    max_depth: usize,
    /// Scopes around the node being visited.
    scopes: u64,
    /// Function parameter lists around the node being visited.
    parameter_lists: u64,
    /// The most lookups semantic analysis can make resolving the
    /// references visited so far.
    resolution_lookups: u64,
    /// The visitor reached the stack floor and skips the rest.
    stopped: bool,
}

/// Whether semantic analysis gives nodes of this kind a scope of their own.
fn has_scope(kind: AstKind<'_>) -> bool {
    matches!(
        kind,
        AstKind::Program(_)
            | AstKind::BlockStatement(_)
            | AstKind::ForStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::SwitchStatement(_)
            | AstKind::CatchClause(_)
            | AstKind::WithStatement(_)
            | AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::Class(_)
            | AstKind::StaticBlock(_)
            | AstKind::TSEnumBody(_)
            | AstKind::TSTypeAliasDeclaration(_)
            | AstKind::TSInterfaceDeclaration(_)
            | AstKind::TSCallSignatureDeclaration(_)
            | AstKind::TSConstructSignatureDeclaration(_)
            | AstKind::TSMethodSignature(_)
            | AstKind::TSConstructorType(_)
            | AstKind::TSFunctionType(_)
            | AstKind::TSConditionalType(_)
            | AstKind::TSMappedType(_)
            | AstKind::TSExternalModuleDeclaration(_)
            | AstKind::TSNamespaceDeclaration(_)
            | AstKind::TSGlobalDeclaration(_)
    )
}

impl LiteralSpans<'_> {
    fn note_value(&mut self, value: Option<&str>) {
        self.random_literal |= value.is_some_and(super::supply_chain::looks_random);
    }

    /// Whether the visitor reached the stack floor. Expressions and
    /// statements are the nodes deep nesting recurses through, and skipping
    /// them there returns up the stack. Unwinding instead costs microseconds
    /// a frame, and a crafted source can put tens of thousands of frames
    /// above the floor.
    fn reached_floor(&mut self) -> bool {
        self.stopped |= stack_address() < self.stack_floor;
        self.stopped
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
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if !self.reached_floor() {
            walk::walk_expression(self, expression);
        }
    }

    fn visit_statement(&mut self, statement: &Statement<'a>) {
        if !self.reached_floor() {
            walk::walk_statement(self, statement);
        }
    }

    fn enter_node(&mut self, kind: AstKind<'a>) {
        if stack_address() < self.stack_floor.saturating_sub(UNWIND_BELOW_FLOOR) {
            std::panic::resume_unwind(Box::new(StackExhausted));
        }
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        match kind {
            AstKind::IdentifierReference(_) => {
                self.resolution_lookups = self
                    .resolution_lookups
                    .saturating_add(self.scopes.saturating_mul(1 + self.parameter_lists));
            }
            AstKind::FormalParameters(_) => self.parameter_lists += 1,
            _ if has_scope(kind) => self.scopes += 1,
            _ => {}
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        self.depth -= 1;
        match kind {
            AstKind::FormalParameters(_) => self.parameter_lists -= 1,
            _ if has_scope(kind) => self.scopes -= 1,
            _ => {}
        }
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

/// Why a source wasn't parsed.
enum Unparsed {
    /// It nests too deeply for the stack the parse had; more may do.
    OutOfStack,
    /// Its AST is too deep for semantic analysis on any stack it's given.
    TooDeep,
    /// Resolving its names would take more lookups than a source its size
    /// is given.
    TooManyNestedReferences,
}

/// Parses `source` and runs the syntax passes over it, masking its comments
/// in `stripped`, which holds a copy of it. The parser and the literal
/// visitor stop at `stack_floor`; semantic analysis runs on a stack sized
/// for the AST's depth.
fn parse_above(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
    stack_floor: usize,
) -> Result<Parsed, Unparsed> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            stack_floor,
            ..ParseOptions::default()
        })
        .parse();
    if parsed.stack_exhausted {
        return Err(Unparsed::OutOfStack);
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
        scopes: 0,
        parameter_lists: 0,
        resolution_lookups: 0,
        stopped: false,
    };
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        literals.visit_program(&parsed.program);
    }))
    .map_err(|_| Unparsed::OutOfStack)?;
    if literals.stopped {
        return Err(Unparsed::OutOfStack);
    }
    let random_literal = (!parsed.fatal_error).then_some(literals.random_literal);
    let complete = !parsed.fatal_error && !parsed.diagnostics.has_errors();
    let resolution_budget = (source.len() as u64)
        .saturating_mul(RESOLUTION_LOOKUPS_PER_BYTE)
        .max(RESOLUTION_LOOKUPS_FLOOR);
    if complete && literals.resolution_lookups > resolution_budget {
        return Err(Unparsed::TooManyNestedReferences);
    }
    let calls = if complete {
        let semantic_stack = literals
            .max_depth
            .saturating_mul(SEMANTIC_LEVEL_STACK)
            .saturating_add(SEMANTIC_BASE_STACK);
        let analyze = || super::bindings::analyze(&parsed.program, complete_input);
        Some(
            if stack_address().saturating_sub(stack_floor) >= semantic_stack {
                analyze()
            } else if semantic_stack <= SEMANTIC_MAX_STACK {
                on_new_stack(semantic_stack, analyze).ok_or(Unparsed::TooDeep)?
            } else {
                return Err(Unparsed::TooDeep);
            },
        )
    } else {
        None
    };
    // Rules that ran out of steps keep what they found, but the file's
    // coverage is incomplete.
    let complete = complete && !calls.as_ref().is_some_and(|calls| calls.over_budget);
    Ok(Parsed {
        executable,
        complete,
        calls,
        random_literal,
    })
}

/// Runs `task` on a new stack segment of `bytes`. `None` when the segment
/// can't be mapped: the stack crate panics then, before switching stacks.
fn on_new_stack<T>(bytes: usize, task: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(AssertUnwindSafe(|| stacker::grow(bytes, task))).ok()
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
    if let Some(floor) = current_stack_floor() {
        match parse_above(source, source_type, stripped, complete_input, floor) {
            Ok(parsed) => return Some(parsed),
            Err(Unparsed::TooDeep | Unparsed::TooManyNestedReferences) => return None,
            Err(Unparsed::OutOfStack) => {}
        }
    }
    if remaining >= DEEP_PARSE_STACK {
        return None;
    }
    on_new_stack(DEEP_PARSE_STACK, || {
        let floor = current_stack_floor()?;
        parse_above(source, source_type, stripped, complete_input, floor).ok()
    })
    .flatten()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Visits `source` with the floor `room` bytes below where the visit
    /// starts, on a stack deep enough to parse it, and returns whether the
    /// visitor stopped at the floor and whether it unwound.
    fn visit_with_floor_below_here(source: String, room: usize) -> (bool, bool) {
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || visit_with_floor(&source, room))
            .unwrap()
            .join()
            .unwrap()
    }

    fn visit_with_floor(source: &str, room: usize) -> (bool, bool) {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();
        assert!(!parsed.stack_exhausted);
        let mut executable = source.as_bytes().to_vec();
        let mut literals = LiteralSpans {
            executable: &mut executable,
            random_literal: false,
            stack_floor: stack_address().saturating_sub(room),
            depth: 0,
            max_depth: 0,
            scopes: 0,
            parameter_lists: 0,
            resolution_lookups: 0,
            stopped: false,
        };
        let unwound = std::panic::catch_unwind(AssertUnwindSafe(|| {
            literals.visit_program(&parsed.program);
        }))
        .is_err();
        (literals.stopped, unwound)
    }

    #[test]
    fn a_visitor_that_reaches_the_floor_inside_nested_expressions_returns_without_unwinding() {
        // The parser reads a left-deep chain without recursing, so only the
        // visitor goes deep; unwinding from its floor cost a second.
        for source in [
            format!("x=a{};", ".b".repeat(20_000)),
            format!("x=a{};", "/b".repeat(20_000)),
            format!("x={}0{};", "f(".repeat(20_000), ")".repeat(20_000)),
            format!("{}0;{}", "{".repeat(20_000), "}".repeat(20_000)),
        ] {
            let start = source[..40].to_owned();
            assert_eq!(
                visit_with_floor_below_here(source, 64 * 1024),
                (true, false),
                "{start}"
            );
        }
    }

    #[test]
    fn a_visitor_with_room_for_the_whole_source_visits_it_all() {
        let (stopped, unwound) =
            visit_with_floor_below_here(format!("x=a{};", ".b".repeat(200)), 1024 * 1024);
        assert!(!stopped && !unwound);
    }
}
