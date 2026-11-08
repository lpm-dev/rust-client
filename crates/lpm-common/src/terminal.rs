use std::borrow::Cow;

#[derive(Clone, Copy)]
enum WhitespacePolicy {
    Inline,
    Multiline,
}

#[derive(Clone, Copy)]
enum StringControl {
    Osc,
    Other,
}

#[derive(Clone, Copy)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    String(StringControl),
    StringEscape(StringControl),
}

/// Sanitizes an externally controlled value for one LPM-owned terminal row.
///
/// Printable Unicode is preserved. Newlines, carriage returns, tabs, raw C0/C1
/// controls, BEL, backspace, and DEL become `?`. Complete terminal escape
/// sequences are removed as units, including their parameters or payloads.
/// Unterminated terminal string controls consume the rest of the input so their
/// payload cannot become terminal syntax. Inputs that need no changes are
/// returned without allocation.
pub fn sanitize_terminal_inline(input: &str) -> Cow<'_, str> {
    sanitize_terminal(input, WhitespacePolicy::Inline)
}

/// Sanitizes an intentionally multiline, externally controlled terminal block.
///
/// This has the same escape-sequence policy as [`sanitize_terminal_inline`],
/// but preserves newline and tab structure. CRLF is normalized to LF and lone
/// carriage returns become `?`, preventing terminal line rewriting. Callers
/// that add LPM-owned prefixes or styling should sanitize individual lines
/// before formatting them.
pub fn sanitize_terminal_multiline(input: &str) -> Cow<'_, str> {
    sanitize_terminal(input, WhitespacePolicy::Multiline)
}

/// Sanitizes an untrusted inline terminal field.
///
/// Prefer [`sanitize_terminal_inline`] in new code; this name remains as a
/// compatibility wrapper for callers that adopted the original owned return
/// type.
pub fn sanitize_for_terminal(input: &str) -> String {
    sanitize_terminal_inline(input).into_owned()
}

/// Text a server sent, fit for one LPM-owned terminal row and for `--json`:
/// sanitized as [`sanitize_terminal_inline`] does, with each run of
/// whitespace, line breaks included, collapsed to one space, and cut to at
/// most `max_chars` characters with an ellipsis. A remote registry controls
/// this text, so it can't add rows, move the cursor, or reorder what's shown.
pub fn sanitize_server_text(input: &str, max_chars: usize) -> String {
    let flattened: String = input
        .chars()
        .map(|ch| {
            if matches!(ch, '\n' | '\r' | '\t') {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let sanitized = sanitize_terminal_inline(&flattened);
    let mut collapsed = String::with_capacity(sanitized.len());
    for word in sanitized.split(' ').filter(|word| !word.is_empty()) {
        if !collapsed.is_empty() {
            collapsed.push(' ');
        }
        collapsed.push_str(word);
    }
    if collapsed.chars().count() <= max_chars {
        return collapsed;
    }
    let mut cut: String = collapsed
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect();
    cut.truncate(cut.trim_end().len());
    cut.push('…');
    cut
}

fn sanitize_terminal(input: &str, whitespace: WhitespacePolicy) -> Cow<'_, str> {
    let mut output = None;
    let mut state = State::Ground;
    let mut chars = input.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        match state {
            State::Ground => match ch {
                '\u{001b}' => {
                    mark_changed(&mut output, input, index);
                    state = State::Escape;
                }
                '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                    mark_changed(&mut output, input, index);
                    state = State::String(StringControl::Other);
                }
                '\u{009b}' => {
                    mark_changed(&mut output, input, index);
                    state = State::Csi;
                }
                '\u{009d}' => {
                    mark_changed(&mut output, input, index);
                    state = State::String(StringControl::Osc);
                }
                '\n' | '\t' if matches!(whitespace, WhitespacePolicy::Multiline) => {
                    push_if_owned(&mut output, ch);
                }
                _ if is_terminal_control(ch) => {
                    let out = mark_changed(&mut output, input, index);
                    push_neutralized_control(out, ch, whitespace, chars.peek().map(|(_, c)| *c));
                }
                _ => push_if_owned(&mut output, ch),
            },
            State::Escape => match ch {
                '[' | '\u{009b}' => state = State::Csi,
                ']' | '\u{009d}' => state = State::String(StringControl::Osc),
                'P' | 'X' | '^' | '_' | '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                    state = State::String(StringControl::Other);
                }
                '\u{001b}' => state = State::Escape,
                '\u{0020}'..='\u{002f}' => state = State::EscapeIntermediate,
                '\u{0030}'..='\u{007e}' => state = State::Ground,
                _ => {
                    state = State::Ground;
                    push_recovered_char(
                        output.as_mut().expect("escape initializes output"),
                        ch,
                        whitespace,
                        chars.peek().map(|(_, c)| *c),
                    );
                }
            },
            State::EscapeIntermediate => match ch {
                '\u{001b}' => state = State::Escape,
                '\u{0020}'..='\u{002f}' => {}
                '\u{0030}'..='\u{007e}' => state = State::Ground,
                _ => {
                    state = State::Ground;
                    push_recovered_char(
                        output
                            .as_mut()
                            .expect("escape intermediate initializes output"),
                        ch,
                        whitespace,
                        chars.peek().map(|(_, c)| *c),
                    );
                }
            },
            State::Csi => match ch {
                '\u{0040}'..='\u{007e}' => state = State::Ground,
                '\u{001b}' => state = State::Escape,
                '\u{009b}' => state = State::Csi,
                '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                    state = State::String(StringControl::Other);
                }
                '\u{009d}' => state = State::String(StringControl::Osc),
                _ => {}
            },
            State::String(kind) => match ch {
                '\u{009c}' => state = State::Ground,
                '\u{001b}' => state = State::StringEscape(kind),
                '\u{0007}' if matches!(kind, StringControl::Osc) => state = State::Ground,
                _ => {}
            },
            State::StringEscape(kind) => match ch {
                '\\' | '\u{009c}' => state = State::Ground,
                '\u{001b}' => state = State::StringEscape(kind),
                '\u{0007}' if matches!(kind, StringControl::Osc) => state = State::Ground,
                _ => state = State::String(kind),
            },
        }
    }

    match output {
        Some(output) => Cow::Owned(output),
        None => Cow::Borrowed(input),
    }
}

#[inline]
fn mark_changed<'a>(output: &'a mut Option<String>, input: &str, index: usize) -> &'a mut String {
    output.get_or_insert_with(|| {
        let mut changed = String::with_capacity(input.len());
        changed.push_str(&input[..index]);
        changed
    })
}

#[inline]
fn push_if_owned(output: &mut Option<String>, ch: char) {
    if let Some(output) = output {
        output.push(ch);
    }
}

#[inline]
fn push_recovered_char(
    output: &mut String,
    ch: char,
    whitespace: WhitespacePolicy,
    next: Option<char>,
) {
    if is_terminal_control(ch) {
        push_neutralized_control(output, ch, whitespace, next);
    } else {
        output.push(ch);
    }
}

#[inline]
fn push_neutralized_control(
    output: &mut String,
    ch: char,
    whitespace: WhitespacePolicy,
    next: Option<char>,
) {
    match (whitespace, ch) {
        (WhitespacePolicy::Multiline, '\n' | '\t') => output.push(ch),
        (WhitespacePolicy::Multiline, '\r') if next == Some('\n') => {}
        _ => output.push('?'),
    }
}

/// C0/C1 controls and DEL, and the Unicode format characters that reorder or
/// hide what a terminal shows (bidi embeddings, overrides, isolates and marks,
/// zero-width space, word joiner, BOM) or break the row (line and paragraph
/// separators). Joiners U+200C/U+200D stay: scripts and emoji need them, and
/// they can't reorder text.
#[inline]
fn is_terminal_control(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00..=0x1f
            | 0x7f..=0x9f
            | 0x061c
            | 0x200b
            | 0x200e
            | 0x200f
            | 0x2028..=0x202e
            | 0x2060
            | 0x2066..=0x2069
            | 0xfeff
    )
}

#[cfg(test)]
mod server_text_tests {
    use super::*;

    #[test]
    fn neutralizes_reordering_and_invisible_format_characters() {
        for ch in [
            '\u{202e}', '\u{2066}', '\u{2069}', '\u{200e}', '\u{200f}', '\u{061c}', '\u{200b}',
            '\u{2060}', '\u{feff}', '\u{2028}', '\u{2029}',
        ] {
            let text = format!("evil{ch}gpj.exe");
            assert_eq!(sanitize_terminal_inline(&text), "evil?gpj.exe", "{ch:?}");
        }
    }

    #[test]
    fn keeps_joiners_scripts_and_emoji_need() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        assert_eq!(sanitize_terminal_inline(family), family);
        assert_eq!(
            sanitize_terminal_inline("می\u{200c}خواهم"),
            "می\u{200c}خواهم"
        );
    }

    #[test]
    fn server_text_is_one_row_without_escapes() {
        let text = "denied\n\u{1b}[31m  fake hint\r\n\u{1b}]8;;https://x\u{7}link\u{1b}]8;;\u{7}";
        assert_eq!(sanitize_server_text(text, 200), "denied fake hint link");
    }

    #[test]
    fn server_text_is_cut_to_its_limit_with_an_ellipsis() {
        let text = "a".repeat(50);
        let cut = sanitize_server_text(&text, 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with('…'));
        assert_eq!(sanitize_server_text("short", 10), "short");
        assert_eq!(sanitize_server_text("exactly-10", 10), "exactly-10");
    }

    #[test]
    fn server_text_trims_and_collapses_whitespace() {
        assert_eq!(sanitize_server_text("  a \t\t b  ", 50), "a b");
        assert_eq!(sanitize_server_text("", 50), "");
    }
}
