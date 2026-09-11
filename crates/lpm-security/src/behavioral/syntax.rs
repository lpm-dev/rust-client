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
}

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
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
    }

    fn visit_reg_exp_literal(&mut self, literal: &RegExpLiteral<'a>) {
        mask(self.executable, literal.span);
    }

    fn visit_template_element(&mut self, literal: &TemplateElement<'a>) {
        mask(self.executable, literal.span);
    }

    fn visit_jsx_text(&mut self, literal: &JSXText<'a>) {
        mask(self.executable, literal.span);
    }
}

impl<'s> SourceContext<'s> {
    pub fn new(source: &str, filename: &str, stripped: &'s mut Vec<u8>) -> Self {
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
        LiteralSpans {
            executable: &mut executable,
        }
        .visit_program(&parsed.program);
        Self {
            stripped: String::from_utf8_lossy(stripped),
            executable,
            complete: !parsed.panicked && parsed.errors.is_empty(),
        }
    }

    pub fn matches_with_context(&self, regex: &Regex, bare: bool) -> bool {
        regex.find_iter(&self.stripped).any(|matched| {
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
    }
}
