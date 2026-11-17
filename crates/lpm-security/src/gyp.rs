//! What a gyp build file runs while node-gyp configures and builds it.
//!
//! gyp evaluates a build file as Python, expands `<!(…)` into the output
//! of a shell command, evaluates each condition as a Python expression,
//! and writes the commands of actions and rules into the build. This
//! reads the files written as a plain literal, which is how they are
//! written in practice, and says so when it meets anything else.

use regex::Regex;
use std::sync::LazyLock;

/// What reading a gyp file found.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct GypCommands {
    /// Shell commands gyp runs as it reads the file, as it runs them.
    pub(crate) shell: Vec<String>,
    /// The file may run something this didn't read as a shell command.
    pub(crate) unresolved: bool,
}

/// Reads `content`, a gyp or gypi file.
pub(crate) fn commands(content: &str) -> GypCommands {
    let mut found = GypCommands::default();
    match Parser::new(content).file() {
        Some(file) => found.build(&file),
        None => {
            // Not a plain literal: gyp would still expand what the text
            // spells, so that much is reported.
            found.unresolved = true;
            found.expansions(content);
        }
    }
    found
}

enum Node {
    Dict(Vec<(String, Node)>),
    List(Vec<Node>),
    Text(String),
    Atom,
}

/// A gyp expansion: `<`, `>` or `^` for when it happens, `!` for a
/// command, `@` for a list, `|` for a file gyp writes, and a name gyp
/// reads before the bracket.
static EXPANSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[<>^](!?@?|\|)([-A-Za-z0-9_.]+)?\(").expect("valid gyp expansion regex")
});

/// A variable a condition compares, which gyp replaces before it
/// evaluates the condition.
static VARIABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[<>^]@?\([-A-Za-z0-9_.]+\)").expect("valid gyp variable regex"));

/// Keys whose values gyp only passes to the compiler, the linker or the
/// generated project, or that hold more of the same.
const INERT_KEYS: &[&str] = &[
    "abstract",
    "all_dependent_settings",
    "arflags",
    "cflags",
    "cflags_c",
    "cflags_cc",
    "cflags_objc",
    "cflags_objcc",
    "copies",
    "default_configuration",
    "defines",
    "destination",
    "direct_dependent_settings",
    "files",
    "hard_dependency",
    "include_dirs",
    "inherit_from",
    "ldflags",
    "libraries",
    "library_dirs",
    "link_settings",
    "mac_bundle",
    "msvs_configuration_platform",
    "msvs_disabled_warnings",
    "msvs_guid",
    "msvs_precompiled_header",
    "msvs_precompiled_source",
    "msvs_target_platform_minversion",
    "msvs_target_platform_version",
    "msvs_windows_sdk_version",
    "product_dir",
    "product_extension",
    "product_name",
    "product_prefix",
    "sources",
    "standalone_static_library",
    "target_defaults",
    "target_name",
    "targets",
    "toolsets",
    "type",
    "win_delay_load_hook",
];

/// Keys under which a tool's settings are listed by the tool's own names.
const SETTINGS_KEYS: &[&str] = &[
    "msbuild_configuration_attributes",
    "msbuild_settings",
    "msvs_configuration_attributes",
    "msvs_settings",
    "xcode_settings",
];

/// Settings that name the program a build step runs.
const PROGRAM_SETTINGS: &[&str] = &[
    "AR",
    "CC",
    "CPLUSPLUS",
    "CXX",
    "LD",
    "LDPLUSPLUS",
    "LIBTOOL",
];

/// The suffixes gyp reads off a key to merge, replace or filter its list.
const MERGE_SUFFIXES: [char; 5] = ['+', '=', '?', '!', '/'];

impl GypCommands {
    fn build(&mut self, node: &Node) {
        match node {
            Node::Text(text) => self.expansions(text),
            Node::List(items) => items.iter().for_each(|item| self.build(item)),
            Node::Dict(entries) => {
                for (key, value) in entries {
                    self.expansions(key);
                    match key.trim_end_matches(MERGE_SUFFIXES) {
                        "variables" => self.values(value),
                        "conditions" | "target_conditions" => self.conditions(value),
                        "configurations" => self.configurations(value),
                        "dependencies" | "export_dependent_settings" => {
                            self.unresolved |= names_build_file(value);
                            self.build(value);
                        }
                        base if SETTINGS_KEYS.contains(&base) => self.settings(value),
                        base if INERT_KEYS.contains(&base) => self.build(value),
                        // Actions, rules, included files and anything this
                        // doesn't know.
                        _ => {
                            self.unresolved = true;
                            self.build(value);
                        }
                    }
                }
            }
            Node::Atom => {}
        }
    }

    /// A value read for what its strings expand to, whatever its keys
    /// are: `variables`, where every key is a name the file chose.
    fn values(&mut self, node: &Node) {
        match node {
            Node::Text(text) => self.expansions(text),
            Node::List(items) => items.iter().for_each(|item| self.values(item)),
            Node::Dict(entries) => {
                for (key, value) in entries {
                    self.expansions(key);
                    self.values(value);
                }
            }
            Node::Atom => {}
        }
    }

    /// A tool's settings. Its keys are the tool's, and some of them hold
    /// a command line or the program to run.
    fn settings(&mut self, node: &Node) {
        match node {
            Node::Text(text) => self.expansions(text),
            Node::List(items) => items.iter().for_each(|item| self.settings(item)),
            Node::Dict(entries) => {
                for (key, value) in entries {
                    self.expansions(key);
                    let base = key.trim_end_matches(MERGE_SUFFIXES);
                    self.unresolved |= PROGRAM_SETTINGS.contains(&base)
                        || ["Event", "CustomBuild", "Command"]
                            .iter()
                            .any(|marker| base.contains(marker));
                    self.settings(value);
                }
            }
            Node::Atom => {}
        }
    }

    /// `configurations` maps names the file chose to build settings.
    fn configurations(&mut self, node: &Node) {
        let Node::Dict(entries) = node else {
            self.unresolved = true;
            return self.build(node);
        };
        for (name, settings) in entries {
            self.expansions(name);
            self.build(settings);
        }
    }

    /// A list of conditions, each an expression followed by the settings
    /// that apply when it holds and, optionally, when it doesn't.
    fn conditions(&mut self, node: &Node) {
        let Node::List(conditions) = node else {
            self.unresolved = true;
            return self.build(node);
        };
        for condition in conditions {
            let Node::List(parts) = condition else {
                self.unresolved = true;
                self.build(condition);
                continue;
            };
            for part in parts {
                match part {
                    Node::Text(expression) => {
                        self.unresolved |= !compares_plain_values(expression);
                        self.expansions(expression);
                    }
                    Node::Dict(_) => self.build(part),
                    _ => {
                        self.unresolved = true;
                        self.build(part);
                    }
                }
            }
        }
    }

    fn expansions(&mut self, text: &str) {
        for expansion in EXPANSION.captures_iter(text) {
            let kind = &expansion[1];
            if kind == "|" {
                self.unresolved = true;
                continue;
            }
            if !kind.starts_with('!') {
                continue;
            }
            let argument = balanced_argument(&text[expansion.get(0).expect("the match").end()..]);
            match argument {
                // A plain command: no name before the bracket, which gyp
                // would run as something else, no list, which it runs
                // without a shell, and nothing gyp fills in first.
                Some(command)
                    if expansion.get(2).is_none()
                        && !command.trim_start().starts_with('[')
                        && !EXPANSION.is_match(command) =>
                {
                    self.shell.push(command.to_owned());
                }
                _ => self.unresolved = true,
            }
        }
    }
}

/// What an expansion holds up to the bracket that closes it, counting the
/// brackets inside as gyp does; `None` when it never closes.
fn balanced_argument(rest: &str) -> Option<&str> {
    let mut depth = 1_usize;
    for (index, byte) in rest.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&rest[..index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether a dependency list names a target in another build file, which
/// gyp then loads.
fn names_build_file(node: &Node) -> bool {
    match node {
        Node::Text(text) => text.contains(".gyp"),
        Node::List(items) => items.iter().any(names_build_file),
        Node::Dict(entries) => entries.iter().any(|(_, value)| names_build_file(value)),
        Node::Atom => false,
    }
}

/// Whether a condition only compares names, strings and numbers. gyp
/// evaluates a condition as Python, where reaching into a value or
/// calling one can run anything.
fn compares_plain_values(expression: &str) -> bool {
    let expression = VARIABLE.replace_all(expression, "v");
    let bytes = expression.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        at += 1;
        match byte {
            b' ' | b'\t' | b'(' | b')' => {}
            b'=' | b'!' => {
                if bytes.get(at) != Some(&b'=') {
                    return false;
                }
                at += 1;
            }
            b'<' | b'>' => {
                if bytes.get(at) == Some(&b'=') {
                    at += 1;
                }
            }
            b'\'' | b'"' => {
                let Some(length) = bytes[at..]
                    .iter()
                    .position(|&next| next == byte || next == b'\\')
                else {
                    return false;
                };
                if bytes[at + length] == b'\\' {
                    return false;
                }
                at += length + 1;
            }
            b'0'..=b'9' => {
                while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                    at += 1;
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = at - 1;
                while bytes
                    .get(at)
                    .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_')
                {
                    at += 1;
                }
                let word = &expression[start..at];
                let operator = matches!(word, "and" | "or" | "not" | "in");
                let called = bytes[at..]
                    .iter()
                    .find(|next| !next.is_ascii_whitespace())
                    .is_some_and(|next| *next == b'(');
                if word.contains("__") || (called && !operator) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// A reader of the Python literals a gyp file is made of: dictionaries,
/// lists, strings, numbers and the three constants. Anything else, an
/// operator or a call among them, is not read.
struct Parser<'a> {
    text: &'a str,
    at: usize,
}

const MAX_DEPTH: usize = 64;

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    fn file(mut self) -> Option<Node> {
        let file = self.value(0)?;
        self.skip_blank();
        (self.at == self.text.len()).then_some(file)
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    /// Skips spaces, line ends and `#` comments.
    fn skip_blank(&mut self) {
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => self.at += 1,
                b'#' => {
                    let rest = &self.text[self.at..];
                    self.at += rest.find('\n').unwrap_or(rest.len());
                }
                _ => break,
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Node> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_blank();
        match self.peek()? {
            b'{' => {
                self.at += 1;
                let mut entries = Vec::new();
                loop {
                    self.skip_blank();
                    if self.peek()? == b'}' {
                        self.at += 1;
                        return Some(Node::Dict(entries));
                    }
                    let Node::Text(key) = self.value(depth + 1)? else {
                        return None;
                    };
                    self.skip_blank();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.at += 1;
                    entries.push((key, self.value(depth + 1)?));
                    self.separator(b'}')?;
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_blank();
                    if self.peek()? == b']' {
                        self.at += 1;
                        return Some(Node::List(items));
                    }
                    items.push(self.value(depth + 1)?);
                    self.separator(b']')?;
                }
            }
            b'\'' | b'"' => self.text_literal().map(Node::Text),
            byte if byte.is_ascii_digit() || byte == b'-' => {
                let start = self.at;
                self.at += 1;
                while self
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || next == b'.')
                {
                    self.at += 1;
                }
                self.text[start..self.at]
                    .parse::<f64>()
                    .ok()
                    .map(|_| Node::Atom)
            }
            byte if byte.is_ascii_alphabetic() => {
                let start = self.at;
                while self
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || next == b'_')
                {
                    self.at += 1;
                }
                // A word before a quote is a string prefix, which changes
                // how the string is read.
                let constant = matches!(&self.text[start..self.at], "True" | "False" | "None");
                (constant && !matches!(self.peek(), Some(b'\'' | b'"'))).then_some(Node::Atom)
            }
            _ => None,
        }
    }

    /// After an item: a comma, or the bracket that closes the collection,
    /// which is left for the caller.
    fn separator(&mut self, close: u8) -> Option<()> {
        self.skip_blank();
        match self.peek()? {
            b',' => {
                self.at += 1;
                Some(())
            }
            byte if byte == close => Some(()),
            _ => None,
        }
    }

    /// One string, or several written one after another, which Python
    /// joins.
    fn text_literal(&mut self) -> Option<String> {
        let mut text = String::new();
        loop {
            self.quoted(&mut text)?;
            self.skip_blank();
            if !matches!(self.peek(), Some(b'\'' | b'"')) {
                return Some(text);
            }
        }
    }

    fn quoted(&mut self, text: &mut String) -> Option<()> {
        let rest = &self.text[self.at..];
        let quote = rest.chars().next()?;
        // A triple-quoted string isn't read.
        if rest[1..].starts_with(quote) && rest[2..].starts_with(quote) {
            return None;
        }
        let mut chars = rest.char_indices().skip(1);
        while let Some((index, next)) = chars.next() {
            match next {
                next if next == quote => {
                    self.at += index + 1;
                    return Some(());
                }
                '\n' => return None,
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    match escaped {
                        '\n' => {}
                        '\\' | '\'' | '"' => text.push(escaped),
                        'a' => text.push('\u{7}'),
                        'b' => text.push('\u{8}'),
                        'f' => text.push('\u{c}'),
                        'n' => text.push('\n'),
                        'r' => text.push('\r'),
                        't' => text.push('\t'),
                        'v' => text.push('\u{b}'),
                        'x' => text.push(code_point(&mut chars, 2, 16)?),
                        'u' => text.push(code_point(&mut chars, 4, 16)?),
                        'U' => text.push(code_point(&mut chars, 8, 16)?),
                        '0'..='7' => {
                            let mut value = escaped.to_digit(8)?;
                            for _ in 0..2 {
                                let mut ahead = chars.clone();
                                match ahead.next().and_then(|(_, digit)| digit.to_digit(8)) {
                                    Some(digit) => {
                                        value = value * 8 + digit;
                                        chars = ahead;
                                    }
                                    None => break,
                                }
                            }
                            text.push(char::from_u32(value)?);
                        }
                        // A character named by `\N{…}` isn't read.
                        'N' => return None,
                        other => {
                            text.push('\\');
                            text.push(other);
                        }
                    }
                }
                next => text.push(next),
            }
        }
        None
    }
}

fn code_point(
    chars: &mut impl Iterator<Item = (usize, char)>,
    digits: usize,
    radix: u32,
) -> Option<char> {
    let mut value = 0;
    for _ in 0..digits {
        value = value * radix + chars.next()?.1.to_digit(radix)?;
    }
    char::from_u32(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(content: &str) -> Vec<String> {
        commands(content).shell
    }

    #[test]
    fn a_command_is_read_as_python_spells_the_string_it_is_in() {
        assert_eq!(shell(r#"{'v': '<!(node -p "1")'}"#), [r#"node -p "1""#]);
        assert_eq!(
            shell(r#"{"v": "<!(node -e \"require('nan')\")"}"#),
            [r#"node -e "require('nan')""#]
        );
        assert_eq!(shell(r"{'v': '<!(\x62un\tinstall)'}"), ["bun\tinstall"]);
        assert_eq!(shell(r"{'v': '\74!(bun install)'}"), ["bun install"]);
        assert_eq!(shell("{'v': '<!(bun' ' install)'}"), ["bun install"]);
        assert_eq!(shell(r"{'v': '<!(b\un install)'}"), [r"b\un install"]);
    }

    #[test]
    fn a_file_that_is_not_a_plain_literal_is_unresolved_and_still_searched() {
        for content in [
            "{'v': '<!' + '(bun install)'}",
            "{'v': r'<!(bun install)'}",
            "{'v': '''<!(bun install)'''}",
            "{'v': '\\N{LESS-THAN SIGN}!(bun install)'}",
            "{'v': ('<!(bun install)',)}",
            "{'v': '<!(bun install)'} + {}",
            "{'v': '<!(bun install)'",
        ] {
            let found = commands(content);
            assert!(found.unresolved, "{content}");
        }
        assert_eq!(shell("{'v': r'<!(bun install)'}"), ["bun install"]);
    }

    #[test]
    fn a_condition_that_does_more_than_compare_is_unresolved() {
        for plain in [
            r#"OS=="win""#,
            r#"OS!="win" and target_arch=="x64""#,
            r#"not (OS in "linux freebsd") or <(module_abi) >= 93"#,
            "node_shared=='true'",
        ] {
            assert!(compares_plain_values(plain), "{plain}");
        }
        for code in [
            "().__class__",
            "OS.startswith('w')",
            "len(OS)==3",
            "OS in ['win']",
            "OS=='w\\x69n'",
            "__import__",
            "OS=='win'; x",
        ] {
            assert!(!compares_plain_values(code), "{code}");
        }
    }
}
