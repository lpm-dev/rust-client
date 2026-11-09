//! Swift sources and the evaluated manifest (`swift package dump-package`)
//! as the quality checks read them.

use super::js_api::{DocSummary, doc_text};
use serde_json::Value;
use std::collections::HashMap;

/// What one Swift source file declares.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SwiftFileFacts {
    pub public_declarations: usize,
    pub documented_declarations: usize,
    /// Names of its public and open declarations.
    pub public_names: Vec<String>,
    /// It declares an `XCTestCase` subclass or a `@Test` function.
    pub declares_tests: bool,
    /// Types it declares that code outside the module can't reach.
    pub internal_types: Vec<String>,
    /// The public members of its extensions, which it counts. Code outside
    /// the module can't reach one whose extended type the module declares
    /// internal; that takes every file of the module to decide.
    pub extension_members: Vec<ExtensionMember>,
}

/// A public member of an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtensionMember {
    pub extended: String,
    pub name: String,
    pub documented: bool,
}

/// At most this many public names are kept per file.
const MAX_NAMES_PER_FILE: usize = 4096;

/// How far the declaration walks look from an access modifier: past
/// modifiers to the declaration keyword, and back over modifiers and
/// attributes. Real declarations stay far inside these; a file built to
/// make each walk cross the whole file can't.
const MAX_MODIFIER_TOKENS: usize = 32;
const MAX_ATTRIBUTE_TOKENS: usize = 256;

#[derive(Debug)]
struct Token<'s> {
    text: &'s str,
    line: usize,
}

struct DocComment {
    last_line: usize,
    /// The index of the token that follows it.
    next_token: usize,
    text: String,
    /// A run of `///` lines, which the next `///` line continues.
    line_doc: bool,
}

/// The source's tokens outside comments and string literals, and its doc
/// comments with the lines they span.
struct Scan<'s> {
    tokens: Vec<Token<'s>>,
    docs: Vec<DocComment>,
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_alphabetic()
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

fn scan(source: &str) -> Scan<'_> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut docs: Vec<DocComment> = Vec::new();
    let mut line = 1usize;
    let mut index = 0usize;
    // Interpolations open inside strings: for each, the parenthesis depth
    // the code inside it has reached and the string to return to.
    let mut interpolations: Vec<(usize, StringKind)> = Vec::new();
    let mut depth = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'\n' => {
                line += 1;
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let end = memchr::memchr(b'\n', &bytes[index..]).map_or(bytes.len(), |n| index + n);
                let comment = &source[index..end];
                if comment.starts_with("///") && !comment.starts_with("////") {
                    let text = comment[3..].trim();
                    match docs.last_mut() {
                        Some(doc) if doc.line_doc && doc.last_line + 1 == line => {
                            if !text.is_empty() {
                                if !doc.text.is_empty() {
                                    doc.text.push(' ');
                                }
                                doc.text.push_str(text);
                            }
                            doc.last_line = line;
                            doc.next_token = tokens.len();
                        }
                        _ => docs.push(DocComment {
                            last_line: line,
                            next_token: tokens.len(),
                            text: text.to_string(),
                            line_doc: true,
                        }),
                    }
                }
                index = end;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index;
                let mut nesting = 0usize;
                while index < bytes.len() {
                    if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                        nesting += 1;
                        index += 2;
                    } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        nesting -= 1;
                        index += 2;
                        if nesting == 0 {
                            break;
                        }
                    } else {
                        if bytes[index] == b'\n' {
                            line += 1;
                        }
                        index += 1;
                    }
                }
                let comment = &source[start..index];
                if comment.starts_with("/**") && !comment.starts_with("/**/") {
                    let inner = comment.trim_start_matches("/**").trim_end_matches("*/");
                    docs.push(DocComment {
                        last_line: line,
                        next_token: tokens.len(),
                        text: doc_text(inner),
                        line_doc: false,
                    });
                }
            }
            b'"' | b'#' => {
                let Some((kind, opened)) = starts_string(bytes, index) else {
                    // A run of `#` that opens no raw string is one token;
                    // stepping through it a byte at a time would count the
                    // rest of the run again at each `#`.
                    let end = index
                        + bytes[index..]
                            .iter()
                            .take_while(|&&byte| byte == b'#')
                            .count()
                            .max(1);
                    tokens.push(Token {
                        text: &source[index..end],
                        line,
                    });
                    index = end;
                    continue;
                };
                index += opened;
                match skip_string(bytes, index, kind, &mut line) {
                    StringEnd::Closed(next) => index = next,
                    StringEnd::Interpolation(next) => {
                        interpolations.push((depth, kind));
                        depth += 1;
                        index = next;
                    }
                }
            }
            b'(' => {
                depth += 1;
                tokens.push(Token { text: "(", line });
                index += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                if interpolations
                    .last()
                    .is_some_and(|(open_depth, _)| *open_depth == depth)
                {
                    let (_, kind) = interpolations.pop().unwrap_or((
                        0,
                        StringKind {
                            hashes: 0,
                            multiline: false,
                        },
                    ));
                    match skip_string(bytes, index + 1, kind, &mut line) {
                        StringEnd::Closed(next) => index = next,
                        StringEnd::Interpolation(next) => {
                            interpolations.push((depth, kind));
                            depth += 1;
                            index = next;
                        }
                    }
                } else {
                    tokens.push(Token { text: ")", line });
                    index += 1;
                }
            }
            b'`' => {
                let end = source[index + 1..]
                    .find(['`', '\n'])
                    .map_or(bytes.len(), |n| index + 1 + n);
                if end > index + 1 {
                    tokens.push(Token {
                        text: &source[index + 1..end],
                        line,
                    });
                }
                index = (end + 1).min(bytes.len());
            }
            _ => {
                let ch = source[index..].chars().next().unwrap_or(' ');
                if is_identifier_start(ch) {
                    let end = source[index..]
                        .char_indices()
                        .find(|(_, c)| !is_identifier_char(*c))
                        .map_or(bytes.len(), |(n, _)| index + n);
                    tokens.push(Token {
                        text: &source[index..end],
                        line,
                    });
                    index = end;
                } else if ch.is_whitespace() {
                    index += ch.len_utf8();
                } else {
                    tokens.push(Token {
                        text: &source[index..index + ch.len_utf8()],
                        line,
                    });
                    index += ch.len_utf8();
                }
            }
        }
    }
    Scan { tokens, docs }
}

#[derive(Clone, Copy, Debug)]
struct StringKind {
    hashes: usize,
    multiline: bool,
}

enum StringEnd {
    Closed(usize),
    /// An interpolation opens; the code inside it starts here.
    Interpolation(usize),
}

/// The string literal opening at `index`: its kind and how many bytes its
/// opening delimiter takes.
fn starts_string(bytes: &[u8], index: usize) -> Option<(StringKind, usize)> {
    let hashes = bytes[index..]
        .iter()
        .take_while(|&&byte| byte == b'#')
        .count();
    let quote = index + hashes;
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let multiline = bytes.get(quote + 1) == Some(&b'"') && bytes.get(quote + 2) == Some(&b'"');
    Some((
        StringKind { hashes, multiline },
        hashes + if multiline { 3 } else { 1 },
    ))
}

fn skip_string(bytes: &[u8], mut index: usize, kind: StringKind, line: &mut usize) -> StringEnd {
    let closes_at = |index: usize| {
        let quotes = if kind.multiline { 3 } else { 1 };
        bytes
            .get(index..index + quotes)
            .is_some_and(|run| run.iter().all(|&b| b == b'"'))
            && bytes
                .get(index + quotes..index + quotes + kind.hashes)
                .is_some_and(|run| run.iter().all(|&b| b == b'#'))
    };
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                *line += 1;
                if !kind.multiline {
                    return StringEnd::Closed(index);
                }
                index += 1;
            }
            b'\\' => {
                let escape_hashes = bytes[index + 1..]
                    .iter()
                    .take_while(|&&byte| byte == b'#')
                    .count();
                if escape_hashes != kind.hashes {
                    index += 1;
                    continue;
                }
                let after = index + 1 + escape_hashes;
                if bytes.get(after) == Some(&b'(') {
                    return StringEnd::Interpolation(after + 1);
                }
                index = after + 1;
            }
            b'"' if closes_at(index) => {
                let quotes = if kind.multiline { 3 } else { 1 };
                return StringEnd::Closed(index + quotes + kind.hashes);
            }
            _ => index += 1,
        }
    }
    StringEnd::Closed(bytes.len())
}

const DECLARATION_KEYWORDS: &[&str] = &[
    "class",
    "struct",
    "enum",
    "protocol",
    "func",
    "var",
    "let",
    "typealias",
    "actor",
    "init",
    "subscript",
    "macro",
    "associatedtype",
];

const MODIFIERS: &[&str] = &[
    "final",
    "static",
    "override",
    "convenience",
    "required",
    "mutating",
    "nonmutating",
    "nonisolated",
    "lazy",
    "dynamic",
    "indirect",
    "weak",
    "unowned",
    "optional",
    "prefix",
    "postfix",
    "infix",
    "distributed",
    "consuming",
    "borrowing",
    "isolated",
    "private",
    "fileprivate",
    "internal",
    "package",
    "public",
    "open",
];

const ACCESS_MODIFIERS: &[&str] = &[
    "private",
    "fileprivate",
    "internal",
    "package",
    "public",
    "open",
];

/// How far a test check looks past `class Name` for `XCTestCase` in the
/// inheritance clause.
const MAX_INHERITANCE_TOKENS: usize = 64;

/// A type's body the walk is inside.
#[derive(Clone, Copy)]
struct Scope<'s> {
    /// The depth of its members.
    depth: usize,
    /// Code outside the module can reach its members: every type around it
    /// is public or open.
    visible: bool,
    /// Its members without an access modifier of their own are public: a
    /// `public extension` or `public protocol`.
    members_public: bool,
    /// A public enum, whose cases are public declarations.
    enum_cases: bool,
    /// The type an extension extends.
    extended: Option<&'s str>,
}

/// How far a `case` declaration's list of names is read.
const MAX_CASE_TOKENS: usize = 4096;

/// Reads a Swift source file.
pub(crate) fn file_facts(source: &str) -> SwiftFileFacts {
    let Scan { tokens, docs } = scan(source);
    // Each doc comment by the token after it, summarized once however many
    // declarations it leads; of several, the nearest wins.
    let docs: HashMap<usize, (usize, DocSummary)> = docs
        .iter()
        .map(|doc| (doc.next_token, (doc.last_line, DocSummary::of(&doc.text))))
        .collect();
    let mut facts = SwiftFileFacts::default();
    let mut depth = 0usize;
    let mut scopes: Vec<Scope<'_>> = Vec::new();
    // A type declaration whose `{` hasn't been reached: its body, and the
    // token past which its header has run too long to be one.
    let mut pending: Option<(Scope<'_>, usize)> = None;
    for (index, token) in tokens.iter().enumerate() {
        match token.text {
            "{" => {
                if let Some((scope, _)) = pending.take_if(|(scope, _)| scope.depth == depth + 1) {
                    scopes.push(scope);
                }
                depth += 1;
                continue;
            }
            "}" => {
                if scopes.last().is_some_and(|scope| scope.depth == depth) {
                    scopes.pop();
                }
                depth = depth.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        if pending.is_some_and(|(_, limit)| index > limit) {
            pending = None;
        }
        if !facts.declares_tests && declares_test(&tokens, index) {
            facts.declares_tests = true;
        }
        if index > 0 && matches!(tokens[index - 1].text, "." | "(" | ",") {
            continue;
        }
        // The type body this token is a direct member of, if any; `None` at
        // the top level, and in a function or accessor body, which declares
        // nothing outside the module can reach.
        let container = scopes.last().filter(|scope| scope.depth == depth);
        let reachable = if depth == 0 {
            true
        } else {
            container.is_some_and(|scope| scope.visible)
        };
        if let Some(scope) = type_body(&tokens, index, depth, reachable, container) {
            if !scope.visible
                && scope.extended.is_none()
                && facts.internal_types.len() < MAX_NAMES_PER_FILE
                && let Some(name) = tokens.get(index + 1)
            {
                facts.internal_types.push(name.text.to_string());
            }
            pending = Some((scope, index + MAX_ATTRIBUTE_TOKENS));
        }
        let extended = container.and_then(|scope| scope.extended);
        if !reachable {
            continue;
        }
        if token.text == "public" || token.text == "open" {
            let Some((keyword_index, name)) = declaration_after(&tokens, index + 1) else {
                continue;
            };
            if tokens[index + 1..keyword_index]
                .iter()
                .any(|token| token.text == "public" || token.text == "open")
            {
                continue;
            }
            record_public(&mut facts, &tokens, &docs, index, name, extended);
        } else if token.text == "case" && container.is_some_and(|scope| scope.enum_cases) {
            for name in case_names(&tokens, index) {
                record_public(&mut facts, &tokens, &docs, index, name, extended);
            }
        } else if container.is_some_and(|scope| scope.members_public)
            && let Some(name) = implicitly_public_member(&tokens, index)
        {
            record_public(&mut facts, &tokens, &docs, index, name, extended);
        }
    }
    facts
}

/// The body a type declaration at `index` opens, when it is one: `class`,
/// `struct`, `enum`, `actor`, `protocol` or `extension`. A type is public
/// with a `public` or `open` modifier, or without one inside a `public
/// extension`; its members are reachable when it is public and code can
/// reach it. An extension's explicitly public members are, unless it is
/// private.
fn type_body<'s>(
    tokens: &[Token<'s>],
    index: usize,
    depth: usize,
    reachable: bool,
    container: Option<&Scope<'s>>,
) -> Option<Scope<'s>> {
    let keyword = tokens[index].text;
    if !matches!(
        keyword,
        "class" | "struct" | "enum" | "actor" | "protocol" | "extension"
    ) {
        return None;
    }
    // `class func`: a modifier, not a type; `protocol P: class`: a
    // constraint.
    if keyword == "class"
        && (tokens.get(index + 1).is_some_and(|next| {
            matches!(next.text, "func" | "var" | "let" | "subscript")
                || MODIFIERS.contains(&next.text)
        }) || index > 0 && tokens[index - 1].text == ":")
    {
        return None;
    }
    let start = declaration_start(tokens, index);
    let access = tokens[start..index]
        .iter()
        .rev()
        .find(|token| ACCESS_MODIFIERS.contains(&token.text))
        .map(|token| token.text);
    let public = match access {
        Some(access) => access == "public" || access == "open",
        None => container.is_some_and(|scope| scope.members_public),
    };
    let visible = reachable
        && match keyword {
            "extension" => !matches!(access, Some("private" | "fileprivate")),
            _ => public,
        };
    Some(Scope {
        depth: depth + 1,
        visible,
        members_public: visible
            && access == Some("public")
            && matches!(keyword, "extension" | "protocol"),
        enum_cases: visible && keyword == "enum",
        extended: (keyword == "extension")
            .then(|| tokens.get(index + 1).map(|name| name.text))
            .flatten(),
    })
}

/// The names a `case` declaration at `index` declares: `case a, b(Int)`.
fn case_names(tokens: &[Token<'_>], index: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut expects_name = true;
    let mut parentheses = 0usize;
    for token in tokens.iter().skip(index + 1).take(MAX_CASE_TOKENS) {
        match token.text {
            "(" => parentheses += 1,
            ")" => parentheses = parentheses.saturating_sub(1),
            "," if parentheses == 0 => expects_name = true,
            // No `case` declares inside another's parentheses, so an
            // unclosed one can't make every later case rescan the file.
            "case" => break,
            "{" | "}" | ";" | "@" | "#" if parentheses == 0 => break,
            text if parentheses == 0
                && (DECLARATION_KEYWORDS.contains(&text) || MODIFIERS.contains(&text)) =>
            {
                break;
            }
            text if parentheses == 0 && expects_name && text.starts_with(is_identifier_start) => {
                names.push(text.to_string());
                expects_name = false;
            }
            _ => {}
        }
    }
    names
}

fn record_public(
    facts: &mut SwiftFileFacts,
    tokens: &[Token<'_>],
    docs: &HashMap<usize, (usize, DocSummary)>,
    at: usize,
    name: String,
    extended: Option<&str>,
) {
    let start = declaration_start(tokens, at);
    let start_line = tokens[start].line;
    // A doc comment documents the declaration it leads, ending on the line
    // above it or on its own line.
    let documented = docs.get(&start).is_some_and(|(last_line, summary)| {
        start_line.saturating_sub(*last_line) <= 1 && summary.documents(&name)
    });
    if let Some(extended) = extended
        && facts.extension_members.len() < MAX_NAMES_PER_FILE
    {
        facts.extension_members.push(ExtensionMember {
            extended: extended.to_string(),
            name: name.clone(),
            documented,
        });
    }
    facts.public_declarations += 1;
    if documented {
        facts.documented_declarations += 1;
    }
    if facts.public_names.len() < MAX_NAMES_PER_FILE {
        facts.public_names.push(name);
    }
}

/// The name a declaration keyword at `index` declares, directly inside a
/// `public extension` or `public protocol`, when no access modifier of its
/// own sets its access.
fn implicitly_public_member(tokens: &[Token<'_>], index: usize) -> Option<String> {
    let text = tokens[index].text;
    if !DECLARATION_KEYWORDS.contains(&text) {
        return None;
    }
    // `class func`: `func` is the declaration.
    if text == "class"
        && tokens.get(index + 1).is_some_and(|next| {
            matches!(next.text, "func" | "var" | "let" | "subscript")
                || MODIFIERS.contains(&next.text)
        })
    {
        return None;
    }
    let start = declaration_start(tokens, index);
    if tokens[start..index]
        .iter()
        .any(|token| ACCESS_MODIFIERS.contains(&token.text))
    {
        return None;
    }
    match text {
        "init" | "subscript" => Some(text.to_string()),
        _ => Some(tokens.get(index + 1)?.text.to_string()),
    }
}

/// The token at `index` starts a test declaration: a class whose
/// inheritance clause names `XCTestCase`, or a `@Test` function.
fn declares_test(tokens: &[Token<'_>], index: usize) -> bool {
    match tokens[index].text {
        "class" => {
            let Some(name) = tokens.get(index + 1) else {
                return false;
            };
            if !name.text.starts_with(is_identifier_start)
                || matches!(name.text, "func" | "var" | "let" | "subscript")
                || MODIFIERS.contains(&name.text)
            {
                return false;
            }
            let mut position = index + 2;
            if tokens.get(position).is_some_and(|token| token.text == "<") {
                let mut depth = 0usize;
                while let Some(token) = tokens.get(position)
                    && position < index + MAX_INHERITANCE_TOKENS
                {
                    position += 1;
                    match token.text {
                        "<" => depth += 1,
                        ">" => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if tokens.get(position).is_none_or(|token| token.text != ":") {
                return false;
            }
            tokens
                .iter()
                .skip(position + 1)
                .take(MAX_INHERITANCE_TOKENS)
                .take_while(|token| token.text != "{" && token.text != "where")
                .any(|token| token.text == "XCTestCase")
        }
        "Test" if index > 0 && tokens[index - 1].text == "@" => {
            let mut position = index + 1;
            let limit = index + MAX_ATTRIBUTE_TOKENS;
            let skip_arguments = |position: &mut usize| {
                if tokens.get(*position).is_none_or(|token| token.text != "(") {
                    return true;
                }
                let mut depth = 0usize;
                while let Some(token) = tokens.get(*position)
                    && *position < limit
                {
                    *position += 1;
                    match token.text {
                        "(" => depth += 1,
                        ")" => {
                            depth -= 1;
                            if depth == 0 {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
                false
            };
            if !skip_arguments(&mut position) {
                return false;
            }
            while let Some(token) = tokens.get(position)
                && position < limit
            {
                match token.text {
                    "func" => return true,
                    "@" => {
                        position += 2;
                        if !skip_arguments(&mut position) {
                            return false;
                        }
                    }
                    text if MODIFIERS.contains(&text) => position += 1,
                    _ => return false,
                }
            }
            false
        }
        _ => false,
    }
}

/// After an access modifier: the declaration keyword it applies to and the
/// declared name, skipping other modifiers and `(set)`.
fn declaration_after(tokens: &[Token<'_>], mut index: usize) -> Option<(usize, String)> {
    let limit = index.saturating_add(MAX_MODIFIER_TOKENS);
    while index < limit
        && let Some(token) = tokens.get(index)
    {
        let text = token.text;
        if text == "(" {
            // `private(set)`
            if tokens.get(index + 2).is_some_and(|token| token.text == ")") {
                index += 3;
                continue;
            }
            return None;
        }
        if text == "class"
            && tokens.get(index + 1).is_some_and(|next| {
                matches!(next.text, "func" | "var" | "let" | "subscript")
                    || MODIFIERS.contains(&next.text)
            })
        {
            index += 1;
            continue;
        }
        if DECLARATION_KEYWORDS.contains(&text) {
            let name = match text {
                "init" | "subscript" => text.to_string(),
                _ => tokens.get(index + 1)?.text.to_string(),
            };
            return Some((index, name));
        }
        if MODIFIERS.contains(&text) {
            index += 1;
            continue;
        }
        return None;
    }
    None
}

/// The first token of the declaration whose access modifier is at
/// `modifier`: earlier modifiers and attributes on the lines above it count.
fn declaration_start(tokens: &[Token<'_>], modifier: usize) -> usize {
    let mut start = modifier;
    let floor = modifier.saturating_sub(MAX_ATTRIBUTE_TOKENS);
    loop {
        if start <= floor {
            return start;
        }
        let previous = &tokens[start - 1];
        if MODIFIERS.contains(&previous.text) {
            start -= 1;
            continue;
        }
        // `private(set)` before the declaration's other modifiers.
        if previous.text == ")"
            && start >= 4
            && tokens[start - 2].text == "set"
            && tokens[start - 3].text == "("
            && ACCESS_MODIFIERS.contains(&tokens[start - 4].text)
        {
            start -= 4;
            continue;
        }
        // `@Attr` or `@Attr(...)`
        if previous.text == ")" {
            let mut depth = 0usize;
            let mut open = None;
            for index in (floor..start).rev() {
                match tokens[index].text {
                    ")" => depth += 1,
                    "(" => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            open = Some(index);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(open) = open
                && open >= 2
                && tokens[open - 2].text == "@"
            {
                start = open - 2;
                continue;
            }
            return start;
        }
        if start >= 2 && tokens[start - 2].text == "@" && previous.text != "@" {
            start -= 2;
            continue;
        }
        return start;
    }
}

/// The identifiers a code sample uses, and the `Module.Name` references it
/// makes, for the modules it imports.
pub(crate) struct SampleUse {
    pub imports: Vec<String>,
    pub identifiers: Vec<String>,
    pub qualified: Vec<(String, String)>,
}

pub(crate) fn sample_use(code: &str) -> SampleUse {
    let Scan { tokens, .. } = scan(code);
    let mut imports = Vec::new();
    let mut identifiers = Vec::new();
    let mut qualified = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let text = tokens[index].text;
        if text == "import" {
            // `import Module`, `import struct Module.Name`
            let mut next = index + 1;
            if tokens.get(next).is_some_and(|token| {
                matches!(
                    token.text,
                    "struct" | "class" | "enum" | "protocol" | "func" | "var" | "let" | "typealias"
                )
            }) {
                next += 1;
            }
            if let Some(module) = tokens.get(next) {
                imports.push(module.text.to_string());
            }
            index = next + 1;
            continue;
        }
        if text.starts_with(is_identifier_start) {
            identifiers.push(text.to_string());
            if tokens.get(index + 1).is_some_and(|token| token.text == ".")
                && let Some(member) = tokens.get(index + 2)
                && member.text.starts_with(is_identifier_start)
            {
                qualified.push((text.to_string(), member.text.to_string()));
            }
        }
        index += 1;
    }
    SampleUse {
        imports,
        identifiers,
        qualified,
    }
}

/// The evaluated manifest's view of a package.
pub(crate) struct Manifest<'m> {
    json: &'m Value,
}

pub(crate) struct TargetInfo {
    pub name: String,
    pub kind: String,
    /// The directory its sources are in, package-relative; empty for the
    /// package root.
    pub path: String,
    /// Its `sources`, package-relative, when it lists them.
    sources: Option<Vec<String>>,
    /// Its `exclude`, package-relative.
    exclude: Vec<String>,
    /// The Swift language mode its settings set, when they set one.
    pub language_mode: Option<String>,
    pub unsafe_flags: bool,
}

impl TargetInfo {
    /// Whether the package-relative `file` is one of its sources.
    pub fn contains(&self, file: &str) -> bool {
        let within = |dir: &str| {
            dir.is_empty()
                || file
                    .strip_prefix(dir)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        };
        within(&self.path)
            && self
                .sources
                .as_ref()
                .is_none_or(|sources| sources.iter().any(|source| within(source)))
            && !self.exclude.iter().any(|excluded| within(excluded))
    }
}

impl<'m> Manifest<'m> {
    pub fn new(json: &'m Value) -> Self {
        Self { json }
    }

    /// `swift-tools-version` as (major, minor).
    pub fn tools_version(&self) -> Option<(u64, u64)> {
        let version = self.json.get("toolsVersion")?.get("_version")?.as_str()?;
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor))
    }

    pub fn platforms(&self) -> Vec<(String, Option<String>)> {
        self.json
            .get("platforms")
            .and_then(Value::as_array)
            .map(|platforms| {
                platforms
                    .iter()
                    .filter_map(|platform| {
                        let name = platform.get("platformName")?.as_str()?.to_string();
                        let version = platform
                            .get("version")
                            .and_then(Value::as_str)
                            .filter(|version| !version.is_empty())
                            .map(str::to_string);
                        Some((name, version))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The language mode targets get without a setting of their own:
    /// the newest of the package's `swiftLanguageModes`, or the tools
    /// version's default.
    pub fn default_language_mode(&self) -> String {
        let declared = self
            .json
            .get("swiftLanguageVersions")
            .or_else(|| self.json.get("swiftLanguageModes"))
            .and_then(Value::as_array)
            .map(|modes| {
                modes
                    .iter()
                    .filter_map(Value::as_str)
                    .max_by(|a, b| compare_versions(a, b))
                    .map(str::to_string)
            });
        match declared {
            Some(Some(mode)) => mode,
            _ => match self.tools_version() {
                Some((major, _)) if major >= 6 => "6".to_string(),
                Some((major, _)) if major <= 4 => "4".to_string(),
                _ => "5".to_string(),
            },
        }
    }

    pub fn targets(&self) -> Vec<TargetInfo> {
        let Some(targets) = self.json.get("targets").and_then(Value::as_array) else {
            return Vec::new();
        };
        targets
            .iter()
            .filter_map(|target| {
                let name = target.get("name")?.as_str()?.to_string();
                let kind = target.get("type")?.as_str()?.to_string();
                let path = target
                    .get("path")
                    .and_then(Value::as_str)
                    .and_then(super::npm::normalize)
                    .unwrap_or_else(|| {
                        let root = match kind.as_str() {
                            "test" => "Tests",
                            "plugin" => "Plugins",
                            _ => "Sources",
                        };
                        format!("{root}/{name}")
                    });
                let relative = |key: &str| {
                    target.get(key).and_then(Value::as_array).map(|entries| {
                        entries
                            .iter()
                            .filter_map(Value::as_str)
                            .filter_map(|entry| {
                                super::npm::normalize(&if path.is_empty() {
                                    entry.to_string()
                                } else {
                                    format!("{path}/{entry}")
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                };
                let sources = relative("sources");
                let exclude = relative("exclude").unwrap_or_default();
                let mut language_mode = None;
                let mut unsafe_flags = false;
                for setting in target
                    .get("settings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let Some(kind) = setting.get("kind") else {
                        continue;
                    };
                    if kind.get("unsafeFlags").is_some() {
                        unsafe_flags = true;
                    }
                    if let Some(mode) = kind
                        .get("swiftLanguageMode")
                        .or_else(|| kind.get("swiftLanguageVersion"))
                        .and_then(|mode| mode.get("_0"))
                        .and_then(Value::as_str)
                    {
                        language_mode = Some(mode.to_string());
                    }
                }
                Some(TargetInfo {
                    name,
                    kind,
                    path,
                    sources,
                    exclude,
                    language_mode,
                    unsafe_flags,
                })
            })
            .collect()
    }

    /// Modules of the targets library products contain.
    pub fn library_modules(&self) -> Vec<String> {
        let mut modules = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for product in self
            .json
            .get("products")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if product
                .get("type")
                .and_then(|kind| kind.get("library"))
                .is_none()
            {
                continue;
            }
            for target in product
                .get("targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let module = module_name(target);
                if seen.insert(module.clone()) {
                    modules.push(module);
                }
            }
        }
        modules
    }

    /// Each dependency's identity and whether a version requirement pins it.
    pub fn dependencies(&self) -> Vec<(String, bool)> {
        self.json
            .get("dependencies")
            .and_then(Value::as_array)
            .map(|dependencies| {
                dependencies
                    .iter()
                    .map(|dependency| {
                        let (kind, entry) = dependency
                            .as_object()
                            .and_then(|object| object.iter().next())
                            .map_or(("unknown", None), |(kind, value)| {
                                (
                                    kind.as_str(),
                                    value.as_array().and_then(|items| items.first()),
                                )
                            });
                        let identity = entry
                            .and_then(|entry| entry.get("identity"))
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string();
                        let versioned = kind != "fileSystem"
                            && entry
                                .and_then(|entry| entry.get("requirement"))
                                .and_then(Value::as_object)
                                .is_some_and(|requirement| {
                                    requirement.contains_key("range")
                                        || requirement.contains_key("exact")
                                });
                        (identity, versioned)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A target's module name, as SwiftPM derives it: characters that can't
/// appear in an identifier become `_`.
pub(crate) fn module_name(target: &str) -> String {
    let mut name: String = target
        .chars()
        .map(|ch| if is_identifier_char(ch) { ch } else { '_' })
        .collect();
    if name.starts_with(|ch: char| ch.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |value: &str| -> Vec<u64> {
        value
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    };
    parts(a).cmp(&parts(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_declarations_with_docs_directly_above_count_as_documented() {
        let facts = file_facts(
            "/// Renders the view's content as Markdown text.\n@MainActor\npublic final class Renderer {\n    /// short\n    public static func make() -> Renderer { .init() }\n    public private(set) var count = 0\n    func internalOnly() {}\n    public init() {}\n}\n\n/// Parses the Markdown source into a document tree.\n\npublic func parse(_ s: String) {}\n",
        );
        assert_eq!(facts.public_declarations, 5);
        assert_eq!(facts.documented_declarations, 1);
        assert_eq!(
            facts.public_names,
            ["Renderer", "make", "count", "init", "parse"]
        );
        assert!(!facts.declares_tests);
    }

    #[test]
    fn a_setter_access_before_public_still_lets_the_doc_comment_lead() {
        let facts = file_facts(
            "/// The number of items the cache holds right now.\nprivate(set) public var count: Int = 0\n",
        );
        assert_eq!(facts.public_declarations, 1);
        assert_eq!(facts.documented_declarations, 1);
    }

    #[test]
    fn only_declarations_code_outside_the_module_reaches_count() {
        let facts = file_facts(
            "struct Internal {\n    /// A method nobody outside the module can call.\n    public func hidden() {}\n}\nprivate extension Internal {\n    public func alsoHidden() {}\n}\n/// Renders Markdown text into sanitized HTML output.\npublic func render() {}\n",
        );
        assert_eq!(facts.public_names, ["render"]);
        assert_eq!(facts.documented_declarations, 1);
    }

    #[test]
    fn a_public_enum_counts_each_case_as_a_declaration() {
        let facts = file_facts(
            "/// How a document renders its headings and links.\npublic enum Style {\n    /// Plain text without any markup at all.\n    case plain\n    case rich(level: Int), compact\n    indirect case nested(Style)\n    func describe() -> String {\n        switch self { case .plain: return \"\" default: return \"\" }\n    }\n}\nenum Hidden { case a, b }\n",
        );
        assert_eq!(
            facts.public_names,
            ["Style", "plain", "rich", "compact", "nested"]
        );
        assert_eq!(facts.public_declarations, 5);
        assert_eq!(facts.documented_declarations, 2);
    }

    #[test]
    fn declarations_inside_comments_and_strings_do_not_count() {
        let facts = file_facts(
            "// public func a() {}\n/* public struct B {} /* nested public enum C {} */ */\nlet s = \"public func d() \\(value(\"public let e\")) public var f\"\nlet t = #\"public func g() \"#\nlet u = \"\"\"\npublic class H {}\n\"\"\"\npublic func real() {}\n",
        );
        assert_eq!(facts.public_names, ["real"]);
    }

    #[test]
    fn open_as_a_method_name_is_not_an_access_modifier() {
        let facts = file_facts(
            "public struct File {\n    public func open() {}\n    func run() { file.open() }\n}\n",
        );
        assert_eq!(facts.public_names, ["File", "open"]);
    }

    #[test]
    fn block_doc_comments_document_the_declaration_below() {
        let facts = file_facts(
            "/**\n Returns the number of items in the cache.\n */\npublic var count: Int { 0 }\n",
        );
        assert_eq!(facts.documented_declarations, 1);
    }

    #[test]
    fn hostile_modifier_chains_and_parentheses_stay_linear() {
        for source in [
            "public ".repeat(200_000),
            format!("{} public func a() {{}}", ")".repeat(200_000)),
            format!("{}func a() {{}}", "public ( ".repeat(100_000)),
            "/// A documented declaration here.\npublic func a() {}\n".repeat(50_000),
            format!("{}\npublic func a() {{}}", "#".repeat(1_000_000)),
        ] {
            let facts = file_facts(&source);
            assert!(facts.public_declarations <= 50_000);
        }
    }

    #[test]
    fn a_case_left_inside_parentheses_ends_at_the_next_case() {
        let facts = file_facts(&format!(
            "public enum E {{\n{}}}",
            "case a(x ".repeat(200_000)
        ));
        assert_eq!(facts.public_declarations, 200_001);
    }

    #[test]
    fn a_class_constraint_keeps_the_protocol_body() {
        let facts = file_facts("public protocol P: class {\n    func a()\n    func b()\n}\n");
        assert_eq!(facts.public_declarations, 3);
    }

    #[test]
    fn an_extension_records_the_type_it_extends_for_each_public_member() {
        let facts =
            file_facts("struct Cache {}\nextension Cache {\n    public func clear() {}\n}\n");
        assert_eq!(facts.internal_types, ["Cache"]);
        assert_eq!(
            facts.extension_members,
            [ExtensionMember {
                extended: "Cache".to_string(),
                name: "clear".to_string(),
                documented: false,
            }]
        );
    }

    #[test]
    fn tests_are_xctestcase_subclasses_or_test_functions() {
        assert!(file_facts("import XCTest\nfinal class T: XCTestCase {}\n").declares_tests);
        assert!(file_facts("import Testing\n@Test func adds() {}\n").declares_tests);
        assert!(!file_facts("import XCTest\n// XCTestCase\n@testable import Lib\n").declares_tests);
    }

    #[test]
    fn a_comment_documents_only_the_declaration_it_leads() {
        let facts = file_facts(
            "/** Renders the Markdown text into HTML. */ public func a() {} public func b() {} public func c() {}\n",
        );
        assert_eq!(facts.public_declarations, 3);
        assert_eq!(facts.documented_declarations, 1);
    }

    #[test]
    fn many_declarations_on_one_line_stay_linear() {
        let line = "/** Renders the Markdown text into HTML. */ public func a() {} ".repeat(40_000);
        let facts = file_facts(&line);
        assert_eq!(facts.public_declarations, 40_000);
        assert_eq!(facts.documented_declarations, 40_000);
    }

    #[test]
    fn a_mention_of_xctestcase_declares_no_test() {
        assert!(!file_facts("import XCTest\nlet unused: XCTestCase? = nil\n").declares_tests);
        assert!(!file_facts("func make() -> XCTestCase { fatalError() }\n").declares_tests);
        assert!(!file_facts("@Test let notAFunction = 1\n").declares_tests);
        assert!(
            file_facts("final class T<Value>: XCTestCase, @unchecked Sendable {}\n").declares_tests
        );
        assert!(
            file_facts("@Test(\"adds\", .tags(.math)) @MainActor func adds() {}\n").declares_tests
        );
    }

    #[test]
    fn members_of_a_public_extension_or_protocol_are_public() {
        let facts = file_facts(
            "public extension String {\n    /// Renders the string as Markdown into HTML.\n    func markdown() -> String { let inner = 1; return self }\n    private func hidden() {}\n    internal var count2: Int { 0 }\n    struct Nested { func notPublic() {} }\n    public func explicit() {}\n}\nextension Int {\n    func internalOnly() {}\n}\npublic protocol Renderer {\n    func render() -> String\n    var name: String { get }\n}\n",
        );
        assert_eq!(
            facts.public_names,
            [
                "markdown", "Nested", "explicit", "Renderer", "render", "name"
            ]
        );
        assert_eq!(facts.documented_declarations, 1);
    }

    #[test]
    fn a_target_at_the_package_root_holds_its_listed_sources() {
        let json = json!({
            "targets": [
                { "name": "Kit", "type": "regular", "path": ".", "sources": ["Kit.swift", "Sources"], "exclude": ["Sources/Old"] },
                { "name": "KitTests", "type": "test", "path": ".", "sources": ["KitTests.swift"] }
            ]
        });
        let manifest = Manifest::new(&json);
        let targets = manifest.targets();
        assert_eq!(targets[0].path, "");
        assert!(targets[0].contains("Kit.swift"));
        assert!(targets[0].contains("Sources/A.swift"));
        assert!(!targets[0].contains("Sources/Old/B.swift"));
        assert!(!targets[0].contains("KitTests.swift"));
        assert!(!targets[0].contains("Kit.swiftx"));
        assert!(targets[1].contains("KitTests.swift"));
        assert!(!targets[1].contains("Kit.swift"));
    }

    #[test]
    fn samples_report_imports_identifiers_and_qualified_names() {
        let sample = sample_use(
            "import Lib\nimport struct Other.Thing\nlet r = Lib.Renderer()\nparse(\"x\")\n",
        );
        assert_eq!(sample.imports, ["Lib", "Other"]);
        assert!(sample.identifiers.contains(&"parse".to_string()));
        assert_eq!(
            sample.qualified,
            [("Lib".to_string(), "Renderer".to_string())]
        );
    }

    fn manifest() -> Value {
        json!({
            "toolsVersion": { "_version": "6.0.0" },
            "platforms": [{ "platformName": "macos", "version": "13.0", "options": [] }],
            "swiftLanguageVersions": ["5", "6"],
            "products": [
                { "name": "Lib", "type": { "library": ["automatic"] }, "targets": ["Lib", "lib-extras"] },
                { "name": "tool", "type": { "executable": null }, "targets": ["Tool"] }
            ],
            "targets": [
                { "name": "Lib", "type": "regular", "path": null, "settings": [
                    { "tool": "swift", "kind": { "swiftLanguageMode": { "_0": "5" } } },
                    { "tool": "swift", "kind": { "unsafeFlags": { "_0": ["-Onone"] } } }
                ] },
                { "name": "LibTests", "type": "test", "path": null, "settings": [] },
                { "name": "Tool", "type": "executable", "path": "./Sources/tool", "settings": [] }
            ],
            "dependencies": [
                { "sourceControl": [{ "identity": "swift-log", "requirement": { "range": [{ "lowerBound": "1.5.0", "upperBound": "2.0.0" }] } }] },
                { "sourceControl": [{ "identity": "swift-nio", "requirement": { "branch": ["main"] } }] },
                { "registry": [{ "identity": "lpmdev.neo_thing", "requirement": { "exact": ["1.0.0"] } }] },
                { "fileSystem": [{ "identity": "local", "path": "/tmp/local" }] }
            ]
        })
    }

    #[test]
    fn manifests_report_targets_modes_and_flags() {
        let json = manifest();
        let manifest = Manifest::new(&json);
        assert_eq!(manifest.tools_version(), Some((6, 0)));
        assert_eq!(manifest.default_language_mode(), "6");
        let targets = manifest.targets();
        assert_eq!(targets[0].path, "Sources/Lib");
        assert_eq!(targets[0].language_mode.as_deref(), Some("5"));
        assert!(targets[0].unsafe_flags);
        assert_eq!(targets[1].path, "Tests/LibTests");
        assert_eq!(targets[2].path, "Sources/tool");
        assert_eq!(manifest.library_modules(), ["Lib", "lib_extras"]);
        assert_eq!(
            manifest.dependencies(),
            [
                ("swift-log".to_string(), true),
                ("swift-nio".to_string(), false),
                ("lpmdev.neo_thing".to_string(), true),
                ("local".to_string(), false),
            ]
        );
    }

    #[test]
    fn the_default_language_mode_follows_the_tools_version_without_declared_modes() {
        let json = json!({ "toolsVersion": { "_version": "5.10.0" } });
        assert_eq!(Manifest::new(&json).default_language_mode(), "5");
        let json =
            json!({ "toolsVersion": { "_version": "6.1.0" }, "swiftLanguageVersions": null });
        assert_eq!(Manifest::new(&json).default_language_mode(), "6");
    }
}
