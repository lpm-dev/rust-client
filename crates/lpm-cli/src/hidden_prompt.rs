//! A one-value prompt whose input never shows: no echo and no mask, so
//! neither the value nor its length reaches the screen.
//!
//! The terminal is in raw mode with bracketed paste while it reads, so a
//! pasted value that spans lines arrives as one paste instead of one Enter
//! per line: nothing of it is left behind for the shell to run once the
//! prompt ends. Where a terminal can't mark pastes, lines left after Enter
//! are drained and the value is refused rather than cut short. Ctrl+C and
//! Ctrl+D on an empty line cancel; the terminal is restored on every exit,
//! a panic included.

use std::io::{self, Write as _};

use zeroize::Zeroizing;

/// One thing the person did at the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Input {
    Char(char),
    /// Text the terminal marked as pasted, line breaks included.
    Paste(String),
    Enter,
    Backspace,
    /// Ctrl+U: forget what was typed so far.
    ClearLine,
    /// Ctrl+C.
    Interrupt,
    /// Ctrl+D.
    EndOfFile,
    /// A key that edits nothing, such as an arrow.
    Other,
}

/// What a prompt does after one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Continue,
    Submit,
    Cancel,
}

/// Why a prompt returned no value.
#[derive(Debug)]
pub(crate) enum PromptError {
    /// The person cancelled with Ctrl+C or Ctrl+D.
    Cancelled,
    /// Lines were still waiting after Enter: a paste of several lines the
    /// terminal didn't mark as one.
    SeveralLines,
    Terminal(io::Error),
}

/// The text typed or pasted so far, wiped when dropped.
#[derive(Default)]
pub(crate) struct HiddenLine {
    text: Zeroizing<String>,
}

impl HiddenLine {
    pub(crate) fn apply(&mut self, input: Input) -> Step {
        match input {
            Input::Char(character) if !character.is_control() => {
                self.text.push(character);
                Step::Continue
            }
            Input::Paste(pasted) => {
                self.push_pasted(&pasted);
                Step::Continue
            }
            Input::Enter => Step::Submit,
            Input::Backspace => {
                self.text.pop();
                Step::Continue
            }
            Input::ClearLine => {
                self.text.clear();
                Step::Continue
            }
            Input::Interrupt => Step::Cancel,
            Input::EndOfFile if self.text.is_empty() => Step::Cancel,
            Input::Char(_) | Input::EndOfFile | Input::Other => Step::Continue,
        }
    }

    /// Terminals send a pasted line break as `\r`; the value keeps `\n`.
    fn push_pasted(&mut self, pasted: &str) {
        self.text.reserve(pasted.len());
        let mut characters = pasted.chars().peekable();
        while let Some(character) = characters.next() {
            if character == '\r' {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                self.text.push('\n');
            } else {
                self.text.push(character);
            }
        }
    }

    pub(crate) fn into_text(self) -> Zeroizing<String> {
        self.text
    }
}

/// Ask for one value on the terminal, showing `prompt` and nothing of what's
/// typed. The caller checks that stdin and stdout are a terminal first. The
/// prompt goes to stderr, or to stdout when stderr is redirected, so the
/// person always sees what they're asked.
pub(crate) fn read_hidden(prompt: &str) -> Result<Zeroizing<String>, PromptError> {
    let shown_on_stderr = io::IsTerminal::is_terminal(&io::stderr());
    show(shown_on_stderr, prompt.as_bytes()).map_err(PromptError::Terminal)?;
    let result = {
        let _terminal = RawTerminal::enter(shown_on_stderr).map_err(PromptError::Terminal)?;
        read_line()
    };
    let _ = show(shown_on_stderr, b"\n");
    result
}

fn show(on_stderr: bool, bytes: &[u8]) -> io::Result<()> {
    if on_stderr {
        let mut stderr = io::stderr().lock();
        stderr.write_all(bytes)?;
        stderr.flush()
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()
    }
}

fn read_line() -> Result<Zeroizing<String>, PromptError> {
    let mut line = HiddenLine::default();
    loop {
        let input = next_input().map_err(PromptError::Terminal)?;
        match line.apply(input) {
            Step::Continue => {}
            Step::Cancel => return Err(PromptError::Cancelled),
            Step::Submit => {
                return if drain_pending().map_err(PromptError::Terminal)? {
                    Err(PromptError::SeveralLines)
                } else {
                    Ok(line.into_text())
                };
            }
        }
    }
}

fn next_input() -> io::Result<Input> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};

    loop {
        let key = match crossterm::event::read()? {
            Event::Paste(pasted) => return Ok(Input::Paste(pasted)),
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        return Ok(match key.code {
            KeyCode::Char('c' | 'C') if control => Input::Interrupt,
            KeyCode::Char('d' | 'D') if control => Input::EndOfFile,
            KeyCode::Char('u' | 'U') if control => Input::ClearLine,
            KeyCode::Char(_) if control => Input::Other,
            KeyCode::Char(character) => Input::Char(character),
            KeyCode::Enter => Input::Enter,
            KeyCode::Backspace => Input::Backspace,
            _ => Input::Other,
        });
    }
}

/// Read and discard every input already waiting, and say whether any of it
/// was text.
fn drain_pending() -> io::Result<bool> {
    use crossterm::event::{Event, KeyCode};

    let mut text_left = false;
    while crossterm::event::poll(std::time::Duration::ZERO)? {
        match crossterm::event::read()? {
            Event::Paste(_) => text_left = true,
            Event::Key(key) => {
                text_left |= matches!(key.code, KeyCode::Char(_) | KeyCode::Enter);
            }
            _ => {}
        }
    }
    Ok(text_left)
}

/// Raw mode and bracketed paste for as long as it lives. The paste mode is
/// switched on the stream the prompt is shown on, which is the terminal.
struct RawTerminal {
    bracketed_paste_on_stderr: Option<bool>,
}

impl RawTerminal {
    fn enter(on_stderr: bool) -> io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        let enabled = if on_stderr {
            crossterm::execute!(io::stderr(), crossterm::event::EnableBracketedPaste)
        } else {
            crossterm::execute!(io::stdout(), crossterm::event::EnableBracketedPaste)
        };
        Ok(Self {
            bracketed_paste_on_stderr: enabled.is_ok().then_some(on_stderr),
        })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        match self.bracketed_paste_on_stderr {
            Some(true) => {
                let _ = crossterm::execute!(io::stderr(), crossterm::event::DisableBracketedPaste);
            }
            Some(false) => {
                let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableBracketedPaste);
            }
            None => {}
        }
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(inputs: impl IntoIterator<Item = Input>) -> (Step, String) {
        let mut line = HiddenLine::default();
        let mut step = Step::Continue;
        for input in inputs {
            step = line.apply(input);
            if step != Step::Continue {
                break;
            }
        }
        (step, line.into_text().to_string())
    }

    #[test]
    fn typed_characters_are_kept_and_enter_submits_them() {
        let (step, text) = typed("s3cret".chars().map(Input::Char).chain([Input::Enter]));
        assert_eq!(step, Step::Submit);
        assert_eq!(text, "s3cret");
    }

    #[test]
    fn backspace_and_ctrl_u_edit_what_was_typed() {
        let (step, text) = typed([
            Input::Char('a'),
            Input::Char('b'),
            Input::Backspace,
            Input::Char('c'),
            Input::ClearLine,
            Input::Char('x'),
            Input::Backspace,
            Input::Backspace,
            Input::Char('y'),
            Input::Enter,
        ]);
        assert_eq!(step, Step::Submit);
        assert_eq!(text, "y");
    }

    #[test]
    fn a_paste_keeps_its_line_breaks_as_line_feeds() {
        let (step, text) = typed([
            Input::Paste("-----BEGIN KEY-----\rAAAA\r\n-----END KEY-----\n".to_owned()),
            Input::Enter,
        ]);
        assert_eq!(step, Step::Submit);
        assert_eq!(text, "-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n");
    }

    #[test]
    fn ctrl_c_cancels_and_ctrl_d_cancels_only_an_empty_line() {
        assert_eq!(typed([Input::Char('a'), Input::Interrupt]).0, Step::Cancel);
        assert_eq!(typed([Input::EndOfFile]).0, Step::Cancel);
        let (step, text) = typed([Input::Char('a'), Input::EndOfFile, Input::Enter]);
        assert_eq!(step, Step::Submit);
        assert_eq!(text, "a");
    }

    #[test]
    fn control_characters_and_other_keys_add_nothing() {
        let (step, text) = typed([
            Input::Char('\u{7}'),
            Input::Other,
            Input::Char('k'),
            Input::Enter,
        ]);
        assert_eq!(step, Step::Submit);
        assert_eq!(text, "k");
    }
}
