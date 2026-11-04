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
    /// Where the first random-looking string literal the parser found starts,
    /// or `None` when the parser stopped before reading the literals.
    pub random_literal: Option<Option<usize>>,
}

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
    random_literal: Option<usize>,
}

impl LiteralSpans<'_> {
    fn note_value(&mut self, value: Option<&str>, span: Span) {
        if self.random_literal.is_none() && value.is_some_and(super::supply_chain::looks_random) {
            self.random_literal = Some(span.start as usize);
        }
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
        self.note_value(literal.value.as_str(), literal.span);
    }

    fn visit_reg_exp_literal(&mut self, literal: &RegExpLiteral<'a>) {
        mask(self.executable, literal.span);
    }

    fn visit_template_element(&mut self, literal: &TemplateElement<'a>) {
        mask(self.executable, literal.span);
        let value = match literal.value.cooked {
            Some(cooked) => cooked.as_str(),
            None => Some(literal.value.raw.as_str()),
        };
        self.note_value(value, literal.span);
    }

    fn visit_jsx_text(&mut self, literal: &JSXText<'a>) {
        mask(self.executable, literal.span);
    }
}

impl<'s> SourceContext<'s> {
    pub fn new(source: &str, filename: &str, stripped: &'s mut Vec<u8>) -> Self {
        Self::with_complete_input(source, filename, stripped, true)
    }

    pub fn with_complete_input(
        source: &str,
        filename: &str,
        stripped: &'s mut Vec<u8>,
        complete_input: bool,
    ) -> Self {
        let allocator = Allocator::default();
        let source_type = SourceType::from_path(filename).unwrap_or_else(|_| SourceType::tsx());
        let parsed = Parser::new(&allocator, source, source_type)
            .with_options(ParseOptions {
                allow_return_outside_function: true,
                ..ParseOptions::default()
            })
            .parse();
        stripped.clear();
        stripped.extend_from_slice(source.as_bytes());
        for comment in &parsed.program.comments {
            mask(stripped, comment.span);
        }
        let mut executable = stripped.clone();
        let mut literals = LiteralSpans {
            executable: &mut executable,
            random_literal: None,
        };
        literals.visit_program(&parsed.program);
        let random_literal = (!parsed.fatal_error).then_some(literals.random_literal);
        let complete = !parsed.fatal_error && !parsed.diagnostics.has_errors();
        let calls = complete.then(|| super::bindings::analyze(&parsed.program, complete_input));
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
