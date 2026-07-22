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

#[inline]
fn is_terminal_control(ch: char) -> bool {
    matches!(ch as u32, 0x00..=0x1f | 0x7f..=0x9f)
}
