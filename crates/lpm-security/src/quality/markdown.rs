//! The parts of a README the quality checks read: its prose, its fenced
//! code blocks, and the install commands in them.

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
}

impl<'a> Readme<'a> {
    pub fn parse(text: &'a str) -> Self {
        let mut blocks = Vec::new();
        let mut prose = String::with_capacity(text.len());
        let mut lines = LineSpans::new(text);
        while let Some((start, end)) = lines.next() {
            let line = &text[start..end];
            let Some(fence) = opening_fence(line) else {
                prose.push_str(line);
                prose.push('\n');
                continue;
            };
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
        Self { blocks, prose }
    }

    /// Characters of prose: the text outside code blocks, without HTML,
    /// comments, images, badges or link targets, its whitespace runs counted
    /// as one.
    pub fn prose_chars(&self) -> usize {
        let text = strip_html(&self.prose);
        let text = strip_images_and_link_targets(&text);
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
/// link's target dropped, keeping its text. Brackets are matched in one
/// pass, within a paragraph, and each target's `)` is looked up in a table,
/// so text a hostile README fills with brackets stays linear.
fn strip_images_and_link_targets(text: &str) -> String {
    let bytes = text.as_bytes();
    let closing = matching_brackets(bytes);
    let next_paren_or_newline = next_paren_or_newline(bytes);
    // The `](target)` of each link whose text is being kept, by the index
    // of its `]`: links nest, and walking into the label keeps this linear.
    let mut skips: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
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
        if bytes[open] == b'['
            && let Some(&label_end) = closing.get(&open)
            && bytes.get(label_end + 1) == Some(&b'(')
            && let Some(close) = next_paren_or_newline.get(label_end + 2).copied()
            && bytes.get(close) == Some(&b')')
        {
            out.push_str(&text[copied..index]);
            if image {
                index = close + 1;
            } else {
                skips.insert(label_end, close + 1);
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
fn matching_brackets(bytes: &[u8]) -> std::collections::HashMap<usize, usize> {
    let mut closing = std::collections::HashMap::new();
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

/// The package managers whose commands install a package, each with the
/// subcommands that do.
const INSTALLERS: &[(&str, &[&str])] = &[
    ("lpm", &["install", "i", "add"]),
    ("npm", &["install", "i", "add"]),
    ("pnpm", &["add", "install", "i"]),
    ("yarn", &["add"]),
    ("bun", &["add", "install", "i"]),
];

/// The first line of a code block that installs `package` with lpm, npm,
/// pnpm, yarn or bun, when one does. The package may carry a version or
/// range (`@lpm.dev/acme.ui@^2`).
pub(crate) fn find_install_command<'b>(blocks: &[CodeBlock<'b>], package: &str) -> Option<&'b str> {
    blocks.iter().find_map(|block| {
        block.body.lines().find(|line| {
            line.split(['&', ';', '|'])
                .any(|command| installs(command, package))
        })
    })
}

fn installs(command: &str, package: &str) -> bool {
    let mut words = command
        .split_whitespace()
        .skip_while(|word| matches!(*word, "$" | ">" | "%" | "#" | "sudo"));
    let Some(manager) = words.next() else {
        return false;
    };
    let manager = manager.trim_start_matches('$');
    let Some((_, subcommands)) = INSTALLERS.iter().find(|(name, _)| *name == manager) else {
        return false;
    };
    let Some(subcommand) = words.next() else {
        return false;
    };
    subcommands.contains(&subcommand) && words.any(|word| names_package(word, package))
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
            find_install_command(&readme.blocks, "@lpm.dev/acme.ui"),
            Some("npm i -D @lpm.dev/acme.ui@^2 && echo ok")
        );
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/acme.uikit"),
            None
        );
    }

    #[test]
    fn install_commands_outside_code_blocks_do_not_count() {
        let readme = Readme::parse("Run lpm install @lpm.dev/acme.ui to install.\n");
        assert_eq!(
            find_install_command(&readme.blocks, "@lpm.dev/acme.ui"),
            None
        );
    }

    #[test]
    fn every_supported_installer_counts() {
        for line in [
            "lpm install @lpm.dev/a.b",
            "lpm add @lpm.dev/a.b",
            "npm add @lpm.dev/a.b",
            "pnpm add @lpm.dev/a.b",
            "yarn add @lpm.dev/a.b",
            "bun add @lpm.dev/a.b",
        ] {
            let text = format!("```\n{line}\n```\n");
            let readme = Readme::parse(&text);
            assert!(
                find_install_command(&readme.blocks, "@lpm.dev/a.b").is_some(),
                "{line}"
            );
        }
        let readme = Readme::parse("```\nyarn install @lpm.dev/a.b\n```\n");
        assert_eq!(find_install_command(&readme.blocks, "@lpm.dev/a.b"), None);
    }

    #[test]
    fn swift_registry_declarations_match_the_identity_without_case() {
        let readme =
            Readme::parse("```swift\n.package(id: \"LPMdev.acme_ui\", from: \"1.0.0\")\n```\n");
        assert!(find_swift_package_declaration(&readme.blocks, "lpmdev.acme_ui").is_some());
        assert!(find_swift_package_declaration(&readme.blocks, "lpmdev.acme_uix").is_none());
    }
}
