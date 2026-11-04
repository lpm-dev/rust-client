//! How much stack parsing a source file takes, estimated before the parser
//! runs.
//!
//! The parser and the syntax visitors recurse once per level of nesting, and
//! a thread's stack can't grow to fit: a file nested deeply enough overflows
//! it and aborts the process. A linear scan bounds how deeply a file nests,
//! so the parse can be given the stack it needs, and a file that would need
//! more than any parse is given goes unparsed, read by the linear detectors.
//!
//! The scan skips strings, comments, template text and regular expressions,
//! so brackets inside them don't count. Where a `/` could start either a
//! regular expression or a division, it decides from the token before it, as
//! a tokenizer without a parser has to: source written to make that guess
//! wrong can nest deeper than its estimate.

/// Stack a parse takes before any nesting.
const BASE_STACK_BYTES: usize = if cfg!(debug_assertions) {
    512 * 1024
} else {
    128 * 1024
};

/// Stack for one level of nesting in the parser and visitors: the most any
/// construct measured takes (object literals, near 3.7 KiB unoptimized and
/// 1.1 KiB optimized), with room for platforms whose frames are larger.
const LEVEL_STACK_BYTES: usize = if cfg!(debug_assertions) {
    5 * 1024
} else {
    1536
};

/// The most stack a parse is given.
const MAX_STACK_BYTES: usize = 64 * 1024 * 1024;

/// The stack parsing `source` takes, or `None` when it nests deeper than a
/// parse is given stack for.
pub(super) fn parse_stack_bytes(source: &[u8]) -> Option<usize> {
    let bytes = nesting_levels(source)
        .checked_mul(LEVEL_STACK_BYTES)?
        .checked_add(BASE_STACK_BYTES)?;
    (bytes <= MAX_STACK_BYTES).then_some(bytes)
}

/// The kind of the last token read, as far as what follows it goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    /// An operator, an opening bracket, a keyword an expression follows, or
    /// the start of the file: a `/` here starts a regular expression.
    ExpressionStart,
    /// A name, a literal, or a closing `}`.
    Operand,
    /// A `)` or `]`: what follows can extend a call or member chain, and a
    /// `/` divides.
    Close,
    /// `;` or `,`.
    Separator,
    /// The head of a statement whose body nests: `if (…)`, `else`, `do`.
    StatementHead,
}

#[derive(Clone, Copy, Default)]
struct Level {
    /// Operators and chained calls since the last separator.
    chain: usize,
    /// Statements nested in one another.
    statements: usize,
    /// The level is a template literal's `${…}`.
    template: bool,
}

struct Scan {
    /// The innermost level, kept apart from `outer` for the hot path.
    top: Level,
    /// The levels around `top`, outermost first; empty at the file's level.
    outer: Vec<Level>,
    /// Open levels plus every level's chain and statements.
    total: usize,
    deepest: usize,
    previous: Token,
}

impl Scan {
    fn new() -> Self {
        Self {
            top: Level::default(),
            outer: Vec::new(),
            total: 0,
            deepest: 0,
            previous: Token::ExpressionStart,
        }
    }

    #[inline]
    fn chain(&mut self) {
        self.top.chain += 1;
        self.total += 1;
        self.deepest = self.deepest.max(self.total);
    }

    fn open(&mut self, template: bool) {
        self.outer.push(std::mem::replace(
            &mut self.top,
            Level {
                template,
                ..Level::default()
            },
        ));
        self.total += 1;
        self.deepest = self.deepest.max(self.total);
    }

    /// Closes the innermost level, if it's a bracket and not the file.
    fn close(&mut self) {
        if !self.top.template && !self.outer.is_empty() {
            self.pop();
        }
    }

    fn pop(&mut self) {
        if let Some(outer) = self.outer.pop() {
            let closed = std::mem::replace(&mut self.top, outer);
            self.total -= 1 + closed.chain + closed.statements;
        }
    }

    #[inline]
    fn separate(&mut self) {
        self.total -= std::mem::take(&mut self.top.chain);
    }

    fn statement(&mut self) {
        let nested = matches!(self.previous, Token::Close | Token::StatementHead);
        let before = self.top.statements;
        self.top.statements = if nested { before + 1 } else { 1 };
        self.total = self.total - before + self.top.statements;
        self.deepest = self.deepest.max(self.total);
    }
}

/// What a byte can start, for the scan.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Space,
    Word,
    Quote,
    Backtick,
    Slash,
    Open,
    CloseParen,
    CloseBrace,
    Separator,
    Dot,
    Less,
    Operator,
    Colon,
    Other,
}

const CLASSES: [Class; 256] = {
    let mut classes = [Class::Other; 256];
    let mut byte = 0;
    while byte < 256 {
        let value = byte as u8;
        classes[byte] = match value {
            b' ' | b'\t' | b'\n' | b'\r' => Class::Space,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$' | b'#' | b'@' | 0x80.. => {
                Class::Word
            }
            b'\'' | b'"' => Class::Quote,
            b'`' => Class::Backtick,
            b'/' => Class::Slash,
            b'(' | b'[' | b'{' => Class::Open,
            b')' | b']' => Class::CloseParen,
            b'}' => Class::CloseBrace,
            b';' | b',' => Class::Separator,
            b'.' => Class::Dot,
            b'<' => Class::Less,
            b'=' | b'!' | b'~' | b'+' | b'-' | b'*' | b'%' | b'>' | b'&' | b'|' | b'^' | b'?' => {
                Class::Operator
            }
            b':' => Class::Colon,
            _ => Class::Other,
        };
        byte += 1;
    }
    classes
};

#[inline]
fn class(byte: u8) -> Class {
    CLASSES[usize::from(byte)]
}

/// An upper estimate of how many levels deep the parser and visitors recurse
/// to read `source`.
fn nesting_levels(source: &[u8]) -> usize {
    let mut scan = Scan::new();
    let mut index = if source.starts_with(b"#!") {
        line_end(source, 0)
    } else {
        0
    };
    while let Some(&byte) = source.get(index) {
        index += 1;
        let token = match class(byte) {
            Class::Space | Class::Other => continue,
            Class::Word => {
                let start = index - 1;
                index = source[index..]
                    .iter()
                    .position(|&byte| class(byte) != Class::Word)
                    .map_or(source.len(), |offset| index + offset);
                word(&source[start..index], &mut scan)
            }
            Class::Slash => match source.get(index) {
                Some(b'/') => {
                    index = line_end(source, index);
                    continue;
                }
                Some(b'*') => {
                    index = memchr::memmem::find(&source[index + 1..], b"*/")
                        .map_or(source.len(), |offset| index + 1 + offset + 2);
                    continue;
                }
                _ if matches!(
                    scan.previous,
                    Token::ExpressionStart | Token::Separator | Token::StatementHead
                ) =>
                {
                    index = regex_end(source, index);
                    Token::Operand
                }
                _ => {
                    scan.chain();
                    Token::ExpressionStart
                }
            },
            Class::Quote => {
                index = string_end(source, index, byte);
                Token::Operand
            }
            Class::Backtick => {
                index = template_text_end(source, index, &mut scan);
                Token::Operand
            }
            Class::Open => {
                if byte != b'{' && scan.previous == Token::Close {
                    scan.chain();
                }
                scan.open(false);
                Token::ExpressionStart
            }
            Class::CloseParen => {
                scan.close();
                Token::Close
            }
            Class::CloseBrace => {
                if scan.top.template {
                    scan.pop();
                    index = template_text_end(source, index, &mut scan);
                } else {
                    scan.close();
                }
                Token::Operand
            }
            Class::Separator => {
                scan.separate();
                Token::Separator
            }
            Class::Dot => {
                if source[index..].starts_with(b"..") {
                    index += 2;
                }
                scan.chain();
                Token::ExpressionStart
            }
            Class::Less => {
                if source.get(index) == Some(&b'/') {
                    index += 1;
                }
                scan.chain();
                Token::ExpressionStart
            }
            Class::Operator => {
                scan.chain();
                Token::ExpressionStart
            }
            Class::Colon => Token::ExpressionStart,
        };
        scan.previous = token;
    }
    scan.deepest
}

/// Reads a name, number or keyword. A statement keyword nests its statement
/// in the one before when that one is an `if`, loop, `else` or `do` head; an
/// operator keyword nests what follows it.
fn word(word: &[u8], scan: &mut Scan) -> Token {
    if !(2..=10).contains(&word.len()) || !word[0].is_ascii_lowercase() {
        return Token::Operand;
    }
    match word {
        b"else" => {
            scan.previous = Token::StatementHead;
            scan.statement();
            Token::StatementHead
        }
        b"do" => {
            scan.statement();
            Token::StatementHead
        }
        b"if" | b"for" | b"while" | b"with" => {
            scan.statement();
            Token::Operand
        }
        b"new" | b"typeof" | b"void" | b"delete" | b"await" | b"yield" | b"in" | b"instanceof" => {
            scan.chain();
            Token::ExpressionStart
        }
        b"function" | b"class" | b"keyof" | b"extends" | b"infer" | b"as" | b"satisfies" => {
            scan.chain();
            Token::Operand
        }
        b"return" | b"case" | b"throw" | b"of" => Token::ExpressionStart,
        _ => Token::Operand,
    }
}

fn line_end(source: &[u8], from: usize) -> usize {
    memchr::memchr(b'\n', &source[from..]).map_or(source.len(), |offset| from + offset)
}

/// The index after a string that opened with `quote` before `from`. An
/// unterminated string ends at its line.
fn string_end(source: &[u8], mut from: usize, quote: u8) -> usize {
    while let Some(offset) = source
        .get(from..)
        .and_then(|rest| memchr::memchr3(quote, b'\\', b'\n', rest))
    {
        let at = from + offset;
        match source[at] {
            b'\\' => from = at + 2,
            b'\n' => return at,
            _ => return at + 1,
        }
    }
    source.len()
}

/// The index after a regular expression whose opening `/` is before `from`,
/// and its flags.
fn regex_end(source: &[u8], mut from: usize) -> usize {
    let mut in_class = false;
    while let Some(&byte) = source.get(from) {
        from += 1;
        match byte {
            b'\\' => from += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            b'/' if !in_class => break,
            b'\n' => return from - 1,
            _ => {}
        }
    }
    while source
        .get(from)
        .is_some_and(|&byte| class(byte) == Class::Word)
    {
        from += 1;
    }
    from
}

/// Reads template text from `from` to the closing backtick, returning the
/// index after it, or to a `${`, opening its level and returning the index
/// after it.
fn template_text_end(source: &[u8], mut from: usize, scan: &mut Scan) -> usize {
    while let Some(offset) = source
        .get(from..)
        .and_then(|rest| memchr::memchr3(b'`', b'\\', b'$', rest))
    {
        let at = from + offset;
        match source[at] {
            b'\\' => from = at + 2,
            b'`' => return at + 1,
            _ if source.get(at + 1) == Some(&b'{') => {
                scan.open(true);
                return at + 2;
            }
            _ => from = at + 1,
        }
    }
    source.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn levels(source: &str) -> usize {
        nesting_levels(source.as_bytes())
    }

    #[test]
    fn counts_brackets_operator_chains_and_nested_statements() {
        assert_eq!(
            levels(&format!("x={}1{};", "[".repeat(50), "]".repeat(50))),
            51
        );
        assert!(levels(&format!("x={}1;", "a=>".repeat(40))) >= 80);
        assert!(levels(&format!("x={}1;", "!".repeat(40))) >= 40);
        assert!(levels(&format!("x=1{};", "+1".repeat(40))) >= 40);
        assert!(levels(&format!("x={}1;", "a?b:".repeat(40))) >= 40);
        assert!(levels(&format!("x=a{};", ".b()".repeat(40))) >= 40);
        assert!(levels(&format!("x=a{};", ".b".repeat(40))) >= 40);
        assert!(levels(&format!("{}x;", "if(a)x;else ".repeat(40))) >= 40);
        assert!(levels(&format!("{}x;", "if(a)".repeat(40))) >= 40);
        assert!(levels(&format!("x=`{}1{}`;", "${`".repeat(40), "`}".repeat(40))) >= 40);
    }

    #[test]
    fn sibling_statements_and_closed_brackets_do_not_add_up() {
        let siblings = "if (a) { b(); } else { c(); }\nfor (;;) {}\nwhile (x) y();\n".repeat(500);
        assert!(levels(&siblings) <= 4, "{}", levels(&siblings));

        let calls = "call(a, [b, c], { d: e });\n".repeat(500);
        assert!(levels(&calls) <= 4, "{}", levels(&calls));
    }

    #[test]
    fn brackets_in_strings_comments_templates_and_regular_expressions_do_not_count() {
        let source = r#"
            const a = "((((((((";
            const b = '[[[[[[[[';
            // ((((((((((
            /* [[[[[[[[[[ */
            const c = `{{{{{{ ${ d } ((((((`;
            const e = /[(((((]\(+/g;
            const f = x / y / z;
        "#;
        assert!(levels(source) <= 4, "{}", levels(source));
    }

    #[test]
    fn a_source_too_deep_for_any_parse_gets_no_stack() {
        let shallow = "module.exports = function (a) { return a + 1; };";
        assert!(parse_stack_bytes(shallow.as_bytes()).is_some_and(|bytes| bytes < 1024 * 1024));

        let deep = format!("x={}1{};", "[".repeat(100_000), "]".repeat(100_000));
        assert_eq!(parse_stack_bytes(deep.as_bytes()), None);
    }
}
