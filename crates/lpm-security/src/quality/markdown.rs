//! The parts of a README the quality checks read: its prose, its fenced
//! code blocks, and the install commands in them.

use std::collections::{HashMap, HashSet};

/// A fenced code block: its info string's first word, lowercased, and its
/// body.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CodeBlock<'a> {
    pub language: String,
    pub body: &'a str,
}

/// The README split into its fenced code blocks and the text outside them.
pub(crate) struct Readme<'a> {
    pub blocks: Vec<CodeBlock<'a>>,
    prose: String,
    /// The labels of its link reference definitions (`[label]: url`),
    /// normalized as [`normalize_label`] does.
    definitions: HashSet<String>,
}

impl<'a> Readme<'a> {
    pub fn parse(text: &'a str) -> Self {
        let mut blocks = Vec::new();
        let mut prose = String::with_capacity(text.len());
        let mut definitions = HashSet::new();
        let mut in_comment = false;
        let mut in_paragraph = false;
        let mut lines = LineSpans::new(text);
        while let Some((start, end)) = lines.next() {
            let line = &text[start..end];
            // An HTML comment block runs from a line that starts with `<!--`
            // to the line holding `-->`. The comment renders nothing, fences
            // in it included; what follows `-->` on its last line does.
            if in_comment || starts_html_comment(line) {
                let body = if in_comment {
                    line
                } else {
                    &line.trim_start_matches(' ')[4..]
                };
                match body.find("-->") {
                    Some(close) => {
                        in_comment = false;
                        prose.push_str(&body[close + 3..]);
                    }
                    None => in_comment = true,
                }
                end_block(&mut prose);
                in_paragraph = false;
                continue;
            }
            if line.trim().is_empty() {
                end_block(&mut prose);
                in_paragraph = false;
                continue;
            }
            if !in_paragraph && let Some(label) = reference_definition(line) {
                definitions.insert(label);
                end_block(&mut prose);
                continue;
            }
            // `[label]:` with its destination on the next line, as CommonMark
            // allows: both lines are the definition. A next line that isn't
            // a destination makes both a paragraph.
            if !in_paragraph
                && let Some(label) = reference_label(line)
                && let Some((next_start, next_end)) = lines.peek()
                && is_destination_line(&text[next_start..next_end])
            {
                lines.next();
                definitions.insert(label);
                end_block(&mut prose);
                continue;
            }
            let Some(fence) = opening_fence(line) else {
                prose.push_str(line);
                prose.push('\n');
                in_paragraph = !is_atx_heading(line);
                continue;
            };
            in_paragraph = false;
            end_block(&mut prose);
            let language = line.trim_start()[fence.len..]
                .trim()
                .split(|c: char| c.is_whitespace() || c == '{' || c == ',')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let body_start = lines.position();
            let mut body_end = text.len();
            while let Some((line_start, line_end)) = lines.next() {
                if closes(&text[line_start..line_end], &fence) {
                    body_end = line_start;
                    break;
                }
            }
            blocks.push(CodeBlock {
                language,
                body: &text[body_start.min(body_end)..body_end],
            });
        }
        Self {
            blocks,
            prose,
            definitions,
        }
    }

    /// Characters of prose: the text outside code blocks, without HTML,
    /// comments, images, badges, link targets or reference definitions, its
    /// whitespace runs counted as one.
    pub fn prose_chars(&self) -> usize {
        let text = strip_html(&self.prose);
        let text = strip_images_and_link_targets(&text, &self.definitions);
        let mut count = 0;
        let mut in_space = true;
        for ch in text.chars() {
            if ch.is_whitespace() {
                if !in_space {
                    count += 1;
                    in_space = true;
                }
            } else {
                count += 1;
                in_space = false;
            }
        }
        if in_space && count > 0 {
            count -= 1;
        }
        count
    }
}

struct Fence {
    marker: u8,
    len: usize,
}

/// Ends the prose's paragraph, so brackets don't pair across a block.
fn end_block(prose: &mut String) {
    prose.push_str("\n\n");
}

/// The most a link label may hold, as CommonMark limits it.
const MAX_LABEL_BYTES: usize = 999;

fn leading_spaces(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn starts_html_comment(line: &str) -> bool {
    leading_spaces(line) <= 3 && line.trim_start_matches(' ').starts_with("<!--")
}

fn is_atx_heading(line: &str) -> bool {
    let rest = line.trim_start_matches(' ');
    let hashes = rest.bytes().take_while(|&byte| byte == b'#').count();
    leading_spaces(line) <= 3
        && (1..=6).contains(&hashes)
        && rest[hashes..]
            .chars()
            .next()
            .is_none_or(|ch| ch == ' ' || ch == '\t')
}

/// The normalized label of a line that is a one-line link reference
/// definition (`[label]: destination`), which renders nothing.
fn reference_definition(line: &str) -> Option<String> {
    let (label, destination) = reference_parts(line)?;
    if destination.is_empty() {
        return None;
    }
    normalize_label(label)
}

/// Whether `line` is a link destination, as the line after a bare
/// `[label]:` must be: `<...>` or one run without whitespace, then nothing
/// or a title in quotes or parentheses.
fn is_destination_line(line: &str) -> bool {
    let line = line.trim();
    let rest = if let Some(bracketed) = line.strip_prefix('<') {
        match bracketed.find('>') {
            Some(end) => &bracketed[end + 1..],
            None => return false,
        }
    } else {
        match line.find(char::is_whitespace) {
            Some(end) => &line[end..],
            None => "",
        }
    };
    if line.is_empty() {
        return false;
    }
    let title = rest.trim_start();
    title.is_empty() || title.starts_with(['"', '\'', '('])
}

/// The normalized label of a line holding only `[label]:`, a definition
/// whose destination follows on the next line.
fn reference_label(line: &str) -> Option<String> {
    let (label, destination) = reference_parts(line)?;
    if !destination.is_empty() {
        return None;
    }
    normalize_label(label)
}

/// A reference definition's label and what follows its `:`, trimmed.
fn reference_parts(line: &str) -> Option<(&str, &str)> {
    if leading_spaces(line) > 3 {
        return None;
    }
    let rest = line.trim_start_matches(' ').strip_prefix('[')?;
    let close = rest.find(']')?;
    let label = &rest[..close];
    if label.contains('[') || label.len() > MAX_LABEL_BYTES {
        return None;
    }
    let destination = rest[close + 1..].strip_prefix(':')?.trim();
    Some((label, destination))
}

/// A link label as CommonMark matches it: case-folded, its whitespace runs
/// collapsed and trimmed, or `None` when nothing is left.
fn normalize_label(label: &str) -> Option<String> {
    let mut normalized = String::with_capacity(label.len());
    for word in label.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.extend(word.chars().flat_map(char::to_lowercase));
    }
    (!normalized.is_empty()).then_some(normalized)
}

fn opening_fence(line: &str) -> Option<Fence> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line.as_bytes()[indent..];
    let marker = *rest.first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let len = rest.iter().take_while(|&&byte| byte == marker).count();
    if len < 3 {
        return None;
    }
    if marker == b'`' && rest[len..].contains(&b'`') {
        return None;
    }
    Some(Fence { marker, len })
}

fn closes(line: &str, fence: &Fence) -> bool {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return false;
    }
    let rest = line[indent..].trim_end();
    rest.len() >= fence.len && rest.bytes().all(|byte| byte == fence.marker)
}

/// Line spans of a text, without their line breaks.
#[derive(Clone)]
struct LineSpans<'a> {
    text: &'a str,
    position: usize,
}

impl<'a> LineSpans<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    /// The next line's span, without moving past it.
    fn peek(&self) -> Option<(usize, usize)> {
        self.clone().next()
    }

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.position >= self.text.len() {
            return None;
        }
        let start = self.position;
        let rest = &self.text[start..];
        let (end, next) = match memchr::memchr(b'\n', rest.as_bytes()) {
            Some(index) => (start + index, start + index + 1),
            None => (self.text.len(), self.text.len()),
        };
        self.position = next;
        let end = if end > start && self.text.as_bytes()[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        Some((start, end))
    }
}

/// The text without HTML comments and tags. A `<` that opens no tag stays.
/// Linear in the text: once no `>` follows, nothing after can close a tag.
fn strip_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let after = &rest[open..];
        if let Some(body) = after.strip_prefix("<!--") {
            rest = body.find("-->").map_or("", |close| &body[close + 3..]);
            continue;
        }
        let opens_tag = after
            .as_bytes()
            .get(1)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'/' | b'!'));
        if !opens_tag {
            out.push('<');
            rest = &after[1..];
            continue;
        }
        match after.find('>') {
            Some(close) => rest = &after[close + 1..],
            None => {
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text without Markdown images (badges among them) and with each
/// link's target dropped, keeping its text. Images and links that point
/// through a reference definition (`![badge][ci]`, `[docs][]`, `[docs]`)
/// count when `definitions` holds their label. Brackets are matched in one
/// pass, within a paragraph, and each target's `)` is looked up in a table,
/// so text a hostile README fills with brackets stays linear.
fn strip_images_and_link_targets(text: &str, definitions: &HashSet<String>) -> String {
    let bytes = text.as_bytes();
    let closing = matching_brackets(bytes);
    let next_paren_or_newline = next_paren_or_newline(bytes);
    // A label names a definition only when it holds no bracket, so only the
    // innermost bracket pairs are looked up, and their spans don't overlap.
    let defined = |open: usize, close: usize| {
        !definitions.is_empty()
            && close - open - 1 <= MAX_LABEL_BYTES
            && memchr::memchr2(b'[', b']', &bytes[open + 1..close]).is_none()
            && normalize_label(&text[open + 1..close])
                .is_some_and(|label| definitions.contains(&label))
    };
    // The part of each link whose text is being kept that comes after its
    // `]`, by the index of that `]`: links nest, and walking into the label
    // keeps this linear.
    let mut skips: HashMap<usize, usize> = HashMap::new();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut copied = 0;
    while index < bytes.len() {
        if let Some(after) = skips.remove(&index) {
            out.push_str(&text[copied..index]);
            index = after;
            copied = after;
            continue;
        }
        let image = bytes[index] == b'!' && bytes.get(index + 1) == Some(&b'[');
        let open = index + usize::from(image);
        let target_end = if bytes[open] == b'['
            && let Some(&label_end) = closing.get(&open)
        {
            match bytes.get(label_end + 1) {
                Some(b'(') => next_paren_or_newline
                    .get(label_end + 2)
                    .copied()
                    .filter(|&close| bytes.get(close) == Some(&b')'))
                    .map(|close| (label_end, close + 1)),
                Some(b'[') => closing.get(&(label_end + 1)).and_then(|&reference_end| {
                    let collapsed = reference_end == label_end + 2;
                    let found = if collapsed {
                        defined(open, label_end)
                    } else {
                        defined(label_end + 1, reference_end)
                    };
                    found.then_some((label_end, reference_end + 1))
                }),
                _ => defined(open, label_end).then_some((label_end, label_end + 1)),
            }
        } else {
            None
        };
        if let Some((label_end, after)) = target_end {
            out.push_str(&text[copied..index]);
            if image {
                index = after;
            } else {
                skips.insert(label_end, after);
                index = open + 1;
            }
            copied = index;
            continue;
        }
        index += 1;
    }
    out.push_str(&text[copied..]);
    out
}

/// Each `[` that a `]` closes in the same paragraph, mapped to that `]`.
fn matching_brackets(bytes: &[u8]) -> HashMap<usize, usize> {
    let mut closing = HashMap::new();
    let mut open: Vec<usize> = Vec::new();
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'[' => open.push(index),
            b']' => {
                if let Some(start) = open.pop() {
                    closing.insert(start, index);
                }
            }
            b'\n' if bytes.get(index + 1) == Some(&b'\n') => open.clear(),
            _ => {}
        }
    }
    closing
}

/// For each index, the index of the first `)` or line break at or after
/// it, or the text's length.
fn next_paren_or_newline(bytes: &[u8]) -> Vec<usize> {
    let mut next = vec![bytes.len(); bytes.len() + 1];
    for index in (0..bytes.len()).rev() {
        next[index] = if matches!(bytes[index], b')' | b'\n') {
            index
        } else {
            next[index + 1]
        };
    }
    next
}

/// Which commands count as installing a package.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Installers {
    /// npm, pnpm, yarn and bun, which install JavaScript packages.
    pub javascript: bool,
    /// `lpm add`, which copies a source package's files into a project
    /// rather than installing it as a dependency.
    pub source_delivery: bool,
}

/// The JavaScript package managers whose commands install a package, each
/// with the subcommands that do.
const JAVASCRIPT_INSTALLERS: &[(&str, &[&str])] = &[
    ("npm", &["install", "i", "add"]),
    ("pnpm", &["add", "install", "i"]),
    ("yarn", &["add"]),
    ("bun", &["add", "install", "i"]),
];

/// The first line of a code block that installs `package` with a command
/// `installers` accepts, when one does. The package may carry a version or
/// range (`@lpm.dev/acme.ui@^2`).
pub(crate) fn find_install_command<'b>(
    blocks: &[CodeBlock<'b>],
    package: &str,
    installers: Installers,
) -> Option<&'b str> {
    blocks.iter().find_map(|block| {
        block.body.lines().find(|line| {
            line.split(['&', ';', '|'])
                .any(|command| installs(command, package, installers))
        })
    })
}

fn installs(command: &str, package: &str, installers: Installers) -> bool {
    let mut words = command
        .split_whitespace()
        .skip_while(|word| matches!(*word, "$" | ">" | "%" | "#" | "sudo"));
    let Some(manager) = words.next() else {
        return false;
    };
    let manager = manager.trim_start_matches('$');
    let Some(subcommand) = words.next() else {
        return false;
    };
    let installing = if manager == "lpm" {
        matches!(subcommand, "install" | "i") || (installers.source_delivery && subcommand == "add")
    } else {
        installers.javascript
            && JAVASCRIPT_INSTALLERS
                .iter()
                .any(|(name, subcommands)| *name == manager && subcommands.contains(&subcommand))
    };
    installing && words.any(|word| names_package(word, package))
}

fn names_package(word: &str, package: &str) -> bool {
    let word = word.trim_matches(|c| c == '"' || c == '\'' || c == '`');
    word.strip_prefix(package)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('@'))
}

/// The first line of a code block that declares the Swift registry
/// dependency `identity` (`.package(id: "lpmdev.acme_ui", …)`), compared
/// as SE-0292 identities compare, without case.
pub(crate) fn find_swift_package_declaration<'b>(
    blocks: &[CodeBlock<'b>],
    identity: &str,
) -> Option<&'b str> {
    blocks.iter().find_map(|block| {
        block.body.lines().find(|line| {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let Some(start) = compact.find(".package(id:\"") else {
                return false;
            };
            let rest = &compact[start + ".package(id:\"".len()..];
            rest.split('"')
                .next()
                .is_some_and(|declared| declared.eq_ignore_ascii_case(identity))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const JAVASCRIPT: Installers = Installers {
        javascript: true,
        source_delivery: false,
    };

    #[test]
    fn prose_excludes_code_blocks_html_badges_and_link_targets() {
        let readme = Readme::parse(
            "# Title\n\n[![build](https://ci.example/badge.svg)](https://ci.example)\n<p align=\"center\"><img src=\"x.png\"></p>\n<!-- hidden note -->\nSee [the docs](https://example.com/a/very/long/path).\n\n```js\nconsole.log('code')\n```\n",
        );
        assert_eq!(
            readme.prose_chars(),
            "# Title See the docs.".chars().count()
        );
        assert_eq!(readme.blocks.len(), 1);
        assert_eq!(readme.blocks[0].language, "js");
        assert_eq!(readme.blocks[0].body, "console.log('code')\n");
    }

    #[test]
    fn fences_inside_an_html_comment_are_not_code_blocks() {
        let readme = Readme::parse(
            "<!--\n```sh\nlpm install @lpm.dev/a.b\n```\n\n```js\nimport { a } from '@lpm.dev/a.b'\n```\n-->\n",
        );
        assert!(readme.blocks.is_empty());
        assert_eq!(readme.prose_chars(), 0);

        let readme = Readme::parse("  <!-- note --> Shown.\n```sh\nnpm i x\n```\n");
        assert_eq!(readme.blocks.len(), 1);
        assert_eq!(readme.prose_chars(), "Shown.".len());
    }

    #[test]
    fn a_comment_that_opens_mid_paragraph_hides_no_fence() {
        let readme = Readme::parse("Install it <!--\n```sh\nnpm i x\n```\n-->\n");
        assert_eq!(readme.blocks.len(), 1);
    }

    #[test]
    fn reference_style_images_links_and_definitions_are_not_prose() {
        let mut text = String::from("# Kit\n\n");
        for index in 0..100 {
            text.push_str(&format!("[![badge {index}][shield]][site] "));
        }
        text.push_str("\n\nRead [the guide][guide], the [Docs][] and [FAQ].\n\n");
        text.push_str("[shield]: https://img.shields.io/badge/very/long/path.svg\n");
        text.push_str("[site]: https://example.com\n[guide]: https://example.com/guide\n");
        text.push_str("[docs]: https://example.com/docs\n[faq]: https://example.com/faq\n");
        let readme = Readme::parse(&text);
        assert_eq!(
            readme.prose_chars(),
            "# Kit Read the guide, the Docs and FAQ.".chars().count()
        );
    }

    #[test]
    fn a_definition_with_its_url_on_the_next_line_is_no_prose_either() {
        let mut text = String::from("# Kit\n\n");
        for index in 0..100 {
            text.push_str(&format!("[![badge {index}][shield]][site] "));
        }
        text.push_str("\n\n[shield]:\n  https://img.shields.io/badge/very/long/path.svg\n");
        text.push_str("[site]:\n  https://example.com\n");
        let readme = Readme::parse(&text);
        assert_eq!(readme.prose_chars(), "# Kit".chars().count());
    }

    #[test]
    fn a_label_line_followed_by_a_blank_line_stays_text() {
        let readme = Readme::parse("[note]:\n\nKeep this line.\n");
        assert_eq!(
            readme.prose_chars(),
            "[note]: Keep this line.".chars().count()
        );
    }

    #[test]
    fn a_label_line_followed_by_prose_stays_text() {
        let readme =
            Readme::parse("[note]:\nThis is ordinary text with several words, not a link.\n");
        assert_eq!(
            readme.prose_chars(),
            "[note]: This is ordinary text with several words, not a link."
                .chars()
                .count()
        );
    }

    #[test]
    fn a_label_line_followed_by_a_destination_and_title_is_a_definition() {
        for destination in [
            "  https://example.com",
            "  https://example.com \"Home\"",
            "  <https://example.com/a b> 'Home'",
        ] {
            let text = format!("# Kit\n\n[site]:\n{destination}\n");
            let readme = Readme::parse(&text);
            assert_eq!(
                readme.prose_chars(),
                "# Kit".chars().count(),
                "{destination}"
            );
        }
    }

    #[test]
    fn brackets_without_a_definition_stay_text() {
        let readme = Readme::parse("- [x] done\n- [ ] [later][nowhere]\n");
        assert_eq!(
            readme.prose_chars(),
            "- [x] done - [ ] [later][nowhere]".chars().count()
        );
    }

    #[test]
    fn a_definition_cannot_interrupt_a_paragraph() {
        let readme = Readme::parse("Some text\n[a]: https://example.com\n");
        assert_eq!(
            readme.prose_chars(),
            "Some text [a]: https://example.com".chars().count()
        );
    }

    #[test]
    fn an_unclosed_fence_runs_to_the_end_of_the_readme() {
        let readme = Readme::parse("intro\n~~~~ sh\nnpm i x\n```\nmore\n");
        assert_eq!(readme.blocks.len(), 1);
        assert_eq!(readme.blocks[0].language, "sh");
        assert_eq!(readme.blocks[0].body, "npm i x\n```\nmore\n");
        assert_eq!(readme.prose_chars(), "intro".len());
    }

    #[test]
    fn a_fence_indented_four_spaces_is_not_a_fence() {
        let readme = Readme::parse("    ```\n    code\n    ```\n");
        assert!(readme.blocks.is_empty());
    }

    #[test]
    fn hostile_brackets_and_tags_stay_linear() {
        for text in [
            "[".repeat(400_000),
            "<a".repeat(200_000),
            "[a](".repeat(100_000),
            format!("{}{}", "[".repeat(200_000), "]".repeat(200_000)),
            format!("{}\n\n[a]: x\n", "[a][a]".repeat(100_000)),
            format!(
                "{}{}\n\n[a]: x\n",
                "![".repeat(100_000),
                "]".repeat(100_000)
            ),
        ] {
            let readme = Readme::parse(&text);
            assert!(readme.prose_chars() <= text.len());
        }
    }

    #[test]
    fn nested_and_unclosed_links_keep_their_text() {
        let readme = Readme::parse("A [b [c](x) d](y) and [e](no close\n");
        assert_eq!(
            readme.prose_chars(),
            "A b c d and [e](no close".chars().count()
        );
    }

    #[test]
    fn install_commands_must_name_the_exact_package() {
        let readme = Readme::parse(
            "```sh\n$ npm install @lpm.dev/acme.ui-kit\nnpm i -D @lpm.dev/acme.ui@^2 && echo ok\n```\n",
        );
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/acme.ui", JAVASCRIPT),
            Some("npm i -D @lpm.dev/acme.ui@^2 && echo ok")
        );
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/acme.uikit", JAVASCRIPT),
            None
        );
    }

    #[test]
    fn install_commands_outside_code_blocks_do_not_count() {
        let readme = Readme::parse("Run lpm install @lpm.dev/acme.ui to install.\n");
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/acme.ui", JAVASCRIPT),
            None
        );
    }

    #[test]
    fn every_supported_installer_counts() {
        for line in [
            "lpm install @lpm.dev/a.b",
            "lpm i @lpm.dev/a.b",
            "npm add @lpm.dev/a.b",
            "pnpm add @lpm.dev/a.b",
            "yarn add @lpm.dev/a.b",
            "bun add @lpm.dev/a.b",
        ] {
            let text = format!("```\n{line}\n```\n");
            let readme = Readme::parse(&text);
            assert!(
                find_install_command(&readme.blocks, "@lpm.dev/a.b", JAVASCRIPT).is_some(),
                "{line}"
            );
        }
        let readme = Readme::parse("```\nyarn install @lpm.dev/a.b\n```\n");
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/a.b", JAVASCRIPT),
            None
        );
    }

    #[test]
    fn lpm_add_installs_only_a_source_package() {
        let readme = Readme::parse("```sh\nlpm add @lpm.dev/a.b\n```\n");
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/a.b", JAVASCRIPT),
            None
        );
        let source = Installers {
            source_delivery: true,
            ..JAVASCRIPT
        };
        assert!(find_install_command(&readme.blocks, "@lpm.dev/a.b", source).is_some());
    }

    #[test]
    fn javascript_package_managers_dont_install_a_swift_package() {
        let readme = Readme::parse("```sh\nnpm install @lpm.dev/a.b\n```\n");
        let swift = Installers {
            javascript: false,
            source_delivery: false,
        };
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/a.b", swift),
            None
        );
        let readme = Readme::parse("```sh\nlpm install @lpm.dev/a.b\n```\n");
        assert!(find_install_command(&readme.blocks, "@lpm.dev/a.b", swift).is_some());
    }

    #[test]
    fn swift_registry_declarations_match_the_identity_without_case() {
        let readme =
            Readme::parse("```swift\n.package(id: \"LPMdev.acme_ui\", from: \"1.0.0\")\n```\n");
        assert!(find_swift_package_declaration(&readme.blocks, "lpmdev.acme_ui").is_some());
        assert!(find_swift_package_declaration(&readme.blocks, "lpmdev.acme_uix").is_none());
    }
}
