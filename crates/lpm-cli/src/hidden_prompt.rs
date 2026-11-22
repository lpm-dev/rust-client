//! A one-value prompt whose input never shows: no echo and no mask, so
//! neither the value nor its length reaches the screen.
//!
//! The terminal stops echoing before the prompt shows, and keys are read as
//! they're pressed. On Unix, bracketed paste marks a pasted value that spans
//! lines as one paste instead of one Enter per line. Whatever arrives once
//! the line has ended, the rest of a paste a terminal didn't mark or sent in
//! pieces, or what's typed after Ctrl+C, is read until the terminal is quiet
//! and discarded, so none of it reaches the shell or shows once echo returns;
//! text in it refuses the value rather than cutting it short. Each buffer
//! that holds what was typed is wiped, and the terminal is restored on every
//! exit, a panic included.

use std::fmt;
use std::io::{self, IsTerminal as _, Write as _};
use std::time::{Duration, Instant};

use zeroize::{Zeroize as _, Zeroizing};

mod decode;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

/// How long the terminal must stay quiet once the line ends before the rest
/// of a paste is taken to have arrived. A terminal delivers a long paste in
/// pieces milliseconds apart.
const QUIET: Duration = Duration::from_millis(100);

/// The longest leftovers are read for, so input that never stops can't hold
/// the prompt open; whatever is still unread then is discarded.
const LEFTOVERS_LIMIT: Duration = Duration::from_secs(2);

/// Why a prompt returned no value.
#[derive(Debug)]
pub(crate) enum PromptError {
    /// The person cancelled with Ctrl+C or Ctrl+D.
    Cancelled,
    /// Text arrived after the line ended: a paste of several lines the
    /// terminal didn't mark as one.
    SeveralLines,
    /// More than the prompt's limit was typed or pasted.
    TooLarge,
    /// What was typed isn't UTF-8, as a terminal set to another encoding
    /// sends.
    NotText,
    Terminal(io::Error),
}

/// Ask for one value of at most `limit` bytes on the terminal, showing
/// `prompt` and nothing of what's typed. The caller checks that stdin and
/// stdout are a terminal first. The prompt goes to stderr, or to stdout when
/// stderr is redirected, so the person always sees what they're asked.
pub(crate) fn read_hidden(prompt: &str, limit: usize) -> Result<Zeroizing<String>, PromptError> {
    let output = Output::for_prompt();
    let result = {
        let mut terminal = platform::Terminal::enter(output).map_err(PromptError::Terminal)?;
        output
            .write(prompt.as_bytes())
            .map_err(PromptError::Terminal)?;
        read_line(&mut terminal, limit)
    };
    let _ = output.write(b"\n");
    result
}

/// Where the prompt shows.
#[derive(Clone, Copy)]
enum Output {
    Stderr,
    Stdout,
}

impl Output {
    fn for_prompt() -> Self {
        if io::stderr().is_terminal() {
            Self::Stderr
        } else {
            Self::Stdout
        }
    }

    fn write(self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Stderr => {
                let mut stderr = io::stderr().lock();
                stderr.write_all(bytes)?;
                stderr.flush()
            }
            Self::Stdout => {
                let mut stdout = io::stdout().lock();
                stdout.write_all(bytes)?;
                stdout.flush()
            }
        }
    }
}

/// Where a prompt's keys come from.
trait Keyboard {
    /// Wait for input, at most `wait` when given, and pass each key or byte
    /// of text it holds to `each`, in order. False when nothing arrived in
    /// time.
    fn read(&mut self, wait: Option<Duration>, each: &mut dyn FnMut(Event)) -> io::Result<bool>;
}

/// One key, or one byte of text, read from the terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Event {
    /// A byte of typed text, part of a UTF-8 character.
    Typed(u8),
    /// A byte of text the terminal marked as pasted, its line breaks `\n`.
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "only a Unix terminal marks pastes")
    )]
    Pasted(u8),
    #[cfg_attr(
        not(any(unix, test)),
        expect(dead_code, reason = "only a Unix terminal marks pastes")
    )]
    PasteEnded,
    Enter,
    Backspace,
    /// Ctrl+W: erase the word before the end.
    EraseWord,
    /// Ctrl+U: erase everything.
    ClearLine,
    /// Ctrl+C.
    Interrupt,
    /// Ctrl+D, or Ctrl+Z on Windows.
    EndOfFile,
    /// A key that edits nothing, such as an arrow.
    Ignored,
}

impl Event {
    /// Whether the event carries text, which, left once the line ended,
    /// means a value didn't arrive whole.
    fn is_text(self) -> bool {
        matches!(self, Self::Typed(_) | Self::Pasted(_))
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Typed(_) => "Typed(..)",
            Self::Pasted(_) => "Pasted(..)",
            Self::PasteEnded => "PasteEnded",
            Self::Enter => "Enter",
            Self::Backspace => "Backspace",
            Self::EraseWord => "EraseWord",
            Self::ClearLine => "ClearLine",
            Self::Interrupt => "Interrupt",
            Self::EndOfFile => "EndOfFile",
            Self::Ignored => "Ignored",
        })
    }
}

/// What a typed control character does.
fn control(byte: u8) -> Event {
    match byte {
        b'\r' | b'\n' => Event::Enter,
        b'\t' => Event::Typed(b'\t'),
        0x08 | 0x7f => Event::Backspace,
        0x17 => Event::EraseWord,
        0x15 => Event::ClearLine,
        0x03 => Event::Interrupt,
        0x04 => Event::EndOfFile,
        _ => Event::Ignored,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Continue,
    End(Ending),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Submit,
    Cancel,
    TooLarge,
}

/// The text typed or pasted so far. Its buffer holds the most a value may
/// from the start and never grows, so no copy of what was typed is left in
/// freed memory; it's wiped when dropped.
struct HiddenLine {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    /// A paste went past the limit; the rest of it is read and dropped.
    overflowed: bool,
}

impl HiddenLine {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
            overflowed: false,
        }
    }

    fn apply(&mut self, event: Event) -> Step {
        match event {
            Event::Typed(byte) => {
                if self.bytes.len() == self.limit {
                    return Step::End(Ending::TooLarge);
                }
                self.bytes.push(byte);
            }
            Event::Pasted(byte) => {
                if self.overflowed {
                } else if self.bytes.len() == self.limit {
                    self.overflowed = true;
                    self.bytes.clear();
                } else {
                    self.bytes.push(byte);
                }
            }
            Event::PasteEnded if self.overflowed => return Step::End(Ending::TooLarge),
            Event::Enter => return Step::End(Ending::Submit),
            Event::Backspace => self.erase_character(),
            Event::EraseWord => self.erase_word(),
            Event::ClearLine => self.bytes.clear(),
            Event::Interrupt => return Step::End(Ending::Cancel),
            Event::EndOfFile if self.bytes.is_empty() => return Step::End(Ending::Cancel),
            Event::PasteEnded | Event::EndOfFile | Event::Ignored => {}
        }
        Step::Continue
    }

    fn erase_character(&mut self) {
        while let Some(byte) = self.bytes.pop() {
            if byte & 0b1100_0000 != 0b1000_0000 {
                break;
            }
        }
    }

    fn erase_word(&mut self) {
        let is_space = |byte: &u8| matches!(byte, b' ' | b'\t');
        while self.bytes.last().is_some_and(is_space) {
            self.bytes.pop();
        }
        while self.bytes.last().is_some_and(|byte| !is_space(byte)) {
            self.bytes.pop();
        }
    }

    fn into_text(mut self) -> Result<Zeroizing<String>, PromptError> {
        match String::from_utf8(std::mem::take(&mut *self.bytes)) {
            Ok(text) => Ok(Zeroizing::new(text)),
            Err(error) => {
                error.into_bytes().zeroize();
                Err(PromptError::NotText)
            }
        }
    }
}

struct Reading {
    line: HiddenLine,
    ended: Option<Ending>,
    text_left: bool,
}

impl Reading {
    fn take(&mut self, event: Event) {
        match self.ended {
            None => {
                if let Step::End(ending) = self.line.apply(event) {
                    self.ended = Some(ending);
                }
            }
            Some(_) => self.text_left |= event.is_text(),
        }
    }
}

fn read_line(keyboard: &mut impl Keyboard, limit: usize) -> Result<Zeroizing<String>, PromptError> {
    let mut reading = Reading {
        line: HiddenLine::new(limit),
        ended: None,
        text_left: false,
    };
    let ending = loop {
        if let Some(ending) = reading.ended {
            break ending;
        }
        keyboard
            .read(None, &mut |event| reading.take(event))
            .map_err(PromptError::Terminal)?;
    };
    // A failure ends the wait too: the line has ended, and a terminal that
    // can't be read passes nothing on either.
    let deadline = Instant::now() + LEFTOVERS_LIMIT;
    while Instant::now() < deadline
        && matches!(
            keyboard.read(Some(QUIET), &mut |event| reading.take(event)),
            Ok(true)
        )
    {}
    match ending {
        Ending::Submit if reading.text_left => Err(PromptError::SeveralLines),
        Ending::Submit => reading.line.into_text(),
        Ending::Cancel => Err(PromptError::Cancelled),
        Ending::TooLarge => Err(PromptError::TooLarge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn typed(text: &str) -> impl Iterator<Item = Event> + '_ {
        text.bytes().map(Event::Typed)
    }

    fn pasted(text: &str) -> impl Iterator<Item = Event> + '_ {
        text.bytes()
            .map(Event::Pasted)
            .chain(std::iter::once(Event::PasteEnded))
    }

    fn line(events: impl IntoIterator<Item = Event>, limit: usize) -> (Step, String) {
        let mut line = HiddenLine::new(limit);
        let mut step = Step::Continue;
        for event in events {
            step = line.apply(event);
            if step != Step::Continue {
                break;
            }
        }
        let text = line.into_text().map(|text| text.to_string());
        (step, text.unwrap_or_else(|_| "<not text>".to_owned()))
    }

    #[test]
    fn typed_text_is_kept_and_enter_submits_it() {
        let (step, text) = line(typed("s3cret").chain([Event::Enter]), 100);
        assert_eq!(step, Step::End(Ending::Submit));
        assert_eq!(text, "s3cret");
    }

    #[test]
    fn backspace_erases_a_whole_character_and_ctrl_u_everything() {
        let (step, text) = line(
            typed("aé")
                .chain([Event::Backspace])
                .chain(typed("c"))
                .chain([Event::ClearLine])
                .chain(typed("x"))
                .chain([Event::Backspace, Event::Backspace])
                .chain(typed("y"))
                .chain([Event::Enter]),
            100,
        );
        assert_eq!(step, Step::End(Ending::Submit));
        assert_eq!(text, "y");
        let (_, text) = line(typed("aé").chain([Event::Backspace, Event::Enter]), 100);
        assert_eq!(text, "a");
    }

    #[test]
    fn ctrl_w_erases_the_spaces_and_the_word_before_the_end() {
        let (_, text) = line(
            typed("one two  ").chain([Event::EraseWord, Event::Enter]),
            100,
        );
        assert_eq!(text, "one ");
        let (_, text) = line(
            typed("one").chain([Event::EraseWord, Event::EraseWord, Event::Enter]),
            100,
        );
        assert_eq!(text, "");
    }

    #[test]
    fn ctrl_c_cancels_and_ctrl_d_cancels_only_an_empty_line() {
        assert_eq!(
            line(typed("a").chain([Event::Interrupt]), 100).0,
            Step::End(Ending::Cancel)
        );
        assert_eq!(line([Event::EndOfFile], 100).0, Step::End(Ending::Cancel));
        let (step, text) = line(typed("a").chain([Event::EndOfFile, Event::Enter]), 100);
        assert_eq!(step, Step::End(Ending::Submit));
        assert_eq!(text, "a");
    }

    #[test]
    fn typing_past_the_limit_ends_the_line_at_once() {
        assert_eq!(
            line(typed("1234").chain([Event::Enter]), 4).0,
            Step::End(Ending::Submit)
        );
        assert_eq!(
            line(typed("12345").chain([Event::Enter]), 4).0,
            Step::End(Ending::TooLarge)
        );
    }

    #[test]
    fn a_paste_past_the_limit_is_read_to_its_end_then_refused() {
        let (step, _) = line(pasted("12345").chain(typed("6")), 4);
        assert_eq!(step, Step::End(Ending::TooLarge));
        let mut line = HiddenLine::new(4);
        for event in "12345".bytes().map(Event::Pasted) {
            assert_eq!(line.apply(event), Step::Continue);
        }
        assert_eq!(line.apply(Event::PasteEnded), Step::End(Ending::TooLarge));
    }

    #[test]
    fn bytes_that_are_not_utf8_are_refused() {
        let mut line = HiddenLine::new(10);
        line.apply(Event::Typed(0xff));
        assert!(matches!(line.into_text(), Err(PromptError::NotText)));
    }

    #[test]
    fn events_never_show_the_text_they_carry() {
        assert_eq!(
            format!("{:?}", [Event::Typed(b's'), Event::Pasted(b'k')]),
            "[Typed(..), Pasted(..)]"
        );
    }

    /// A keyboard that hands out one batch of events each read, then
    /// nothing.
    struct Script {
        batches: VecDeque<Vec<Event>>,
        waits: Vec<Option<Duration>>,
    }

    impl Script {
        fn new(batches: impl IntoIterator<Item = Vec<Event>>) -> Self {
            Self {
                batches: batches.into_iter().collect(),
                waits: Vec::new(),
            }
        }
    }

    impl Keyboard for Script {
        fn read(
            &mut self,
            wait: Option<Duration>,
            each: &mut dyn FnMut(Event),
        ) -> io::Result<bool> {
            self.waits.push(wait);
            match self.batches.pop_front() {
                Some(batch) => {
                    batch.into_iter().for_each(each);
                    Ok(true)
                }
                None if wait.is_some() => Ok(false),
                None => panic!("the prompt waited for a key the script doesn't hold"),
            }
        }
    }

    fn outcome(script: &mut Script) -> Result<String, String> {
        read_line(script, 100)
            .map(|text| text.to_string())
            .map_err(|error| format!("{error:?}"))
    }

    #[test]
    fn a_value_submits_once_the_terminal_stays_quiet() {
        let mut script = Script::new([typed("fixture").chain([Event::Enter]).collect()]);
        assert_eq!(outcome(&mut script).as_deref(), Ok("fixture"));
        assert_eq!(script.waits, [None, Some(QUIET)]);
    }

    #[test]
    fn text_after_enter_refuses_the_value_whether_it_came_with_it_or_after() {
        let mut together = Script::new([typed("one")
            .chain([Event::Enter])
            .chain(typed("two"))
            .collect()]);
        assert_eq!(outcome(&mut together), Err("SeveralLines".to_owned()));
        let mut later = Script::new([
            typed("one").chain([Event::Enter]).collect(),
            vec![Event::Ignored],
            typed("two").collect(),
        ]);
        assert_eq!(outcome(&mut later), Err("SeveralLines".to_owned()));
        assert_eq!(later.waits, [None, Some(QUIET), Some(QUIET), Some(QUIET)]);
    }

    #[test]
    fn keys_without_text_after_enter_leave_the_value_whole() {
        let mut script = Script::new([
            typed("fixture").chain([Event::Enter]).collect(),
            vec![Event::Enter, Event::Ignored, Event::Backspace],
        ]);
        assert_eq!(outcome(&mut script).as_deref(), Ok("fixture"));
    }

    #[test]
    fn what_follows_ctrl_c_is_read_and_dropped() {
        let mut script = Script::new([
            typed("partial").chain([Event::Interrupt]).collect(),
            typed("rest").chain([Event::Enter]).collect(),
        ]);
        assert_eq!(outcome(&mut script), Err("Cancelled".to_owned()));
        assert!(script.batches.is_empty());
    }
}
