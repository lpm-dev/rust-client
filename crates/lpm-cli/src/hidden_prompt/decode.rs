//! What a terminal sends, as prompt events: on Unix the bytes of raw mode,
//! with escape sequences for keys that edit nothing and bracketed pastes; on
//! Windows the UTF-16 characters the console reads.

use super::{Event, control};

#[cfg(any(unix, test))]
const PASTE_END: &[u8] = b"\x1b[201~";

#[cfg(any(unix, test))]
/// The bytes a Unix terminal sends in raw mode.
#[derive(Default)]
pub(super) struct Bytes {
    state: State,
    after_carriage_return: bool,
    /// The escape that began the current state came in the read being fed.
    escape_in_read: bool,
}

#[cfg(any(unix, test))]
#[derive(Default, Clone, Copy)]
enum State {
    #[default]
    Ground,
    Escape,
    /// In a control sequence, `ESC [` and its parameters; the first three
    /// are kept to recognize the start of a paste, `ESC [ 200 ~`.
    ControlSequence {
        parameters: [u8; 3],
        length: u8,
        crossed: bool,
        /// A parameter came after a read ended inside the sequence.
        taken: bool,
    },
    /// `ESC O` and the one byte that ends it; `late` when the `O` came in a
    /// later read than its escape, so it may have been typed.
    SingleShift {
        crossed: bool,
        late: bool,
    },
    /// The three bytes of an X10 mouse report, `ESC [ M` and its button and
    /// position, left to skip.
    MouseReport {
        remaining: u8,
        crossed: bool,
    },
    /// A string a terminal sends, such as an `ESC ]` reply, which ends with
    /// BEL or `ESC \\`; `escape` once an `ESC` of that end was read. A
    /// terminal sends a string with what it holds, so one that `held`
    /// nothing when its read ended began with a key: `introducer` after the
    /// Escape key, or with it as a Meta chord when `chord`.
    TerminalString {
        escape: bool,
        held: bool,
        introducer: u8,
        chord: bool,
    },
    /// After a Meta chord with a string's introducer, such as Alt+P, that
    /// ended its read: a key that's no text acts, and text can't be told
    /// from the rest of a terminal's string.
    AfterChord,
    /// In a bracketed paste, with `matched` bytes of its end marker read.
    Paste {
        matched: u8,
    },
}

#[cfg(any(unix, test))]
impl Bytes {
    pub(super) fn feed(&mut self, byte: u8, each: &mut dyn FnMut(Event)) {
        match self.state {
            State::Ground => self.ground(byte, each),
            State::Escape => match byte {
                // A key and its escape that come in one read are a Meta
                // chord, such as Alt+B, which edits nothing, as an arrow
                // doesn't.
                0x20..=0x7e if self.escape_in_read && !b"[O]P_^X".contains(&byte) => {
                    self.state = State::Ground;
                }
                // An escape that ended an earlier read may have been the
                // Escape key, so its introducer and what follows may have
                // been typed.
                b'[' => {
                    self.state = State::ControlSequence {
                        parameters: [0; 3],
                        length: 0,
                        crossed: !self.escape_in_read,
                        taken: !self.escape_in_read,
                    };
                }
                b'O' => {
                    self.state = State::SingleShift {
                        crossed: !self.escape_in_read,
                        late: !self.escape_in_read,
                    }
                }
                b']' | b'P' | b'_' | b'^' | b'X' => {
                    self.state = State::TerminalString {
                        escape: false,
                        held: false,
                        introducer: byte,
                        chord: self.escape_in_read,
                    };
                }
                // An escape that starts no sequence edits nothing, and what
                // follows it is read on its own.
                _ => {
                    self.state = State::Ground;
                    self.ground(byte, each);
                }
            },
            State::ControlSequence {
                mut parameters,
                length,
                crossed,
                taken,
            } => match byte {
                0x20..=0x3f => {
                    if let Some(slot) = parameters.get_mut(usize::from(length)) {
                        *slot = byte;
                    }
                    self.state = State::ControlSequence {
                        parameters,
                        length: length.saturating_add(1),
                        crossed,
                        taken: taken || crossed,
                    };
                }
                0x40..=0x7e => {
                    let paste = byte == b'~' && length == 3 && parameters == *b"200";
                    // A paste's start is the terminal's, wherever a read ends.
                    self.took_after_read(crossed && !paste, each);
                    self.state = if paste {
                        State::Paste { matched: 0 }
                    } else if byte == b'M' && length == 0 {
                        State::MouseReport {
                            remaining: 3,
                            crossed: false,
                        }
                    } else {
                        State::Ground
                    };
                }
                // A byte no sequence holds ends it unfinished, and is read
                // on its own. A terminal ends every sequence it sends, so
                // what this one took was typed.
                _ => {
                    self.took_after_read(taken || length > 0, each);
                    self.state = State::Ground;
                    self.ground(byte, each);
                }
            },
            State::SingleShift { crossed, late } => {
                self.state = State::Ground;
                if (0x40..=0x7e).contains(&byte) {
                    self.took_after_read(crossed, each);
                } else {
                    self.took_after_read(late, each);
                    self.ground(byte, each);
                }
            }
            // A report holds no control byte, so one shows the report was
            // typed text, and acts.
            State::MouseReport { .. } if matches!(byte, 0x00..=0x1f | 0x7f) => {
                self.state = State::Ground;
                each(Event::Lost);
                self.ground(byte, each);
            }
            State::MouseReport { remaining, crossed } => {
                // The report took a byte after a read ended inside it.
                self.took_after_read(crossed, each);
                self.state = match remaining {
                    0 | 1 => State::Ground,
                    _ => State::MouseReport {
                        remaining: remaining - 1,
                        crossed: false,
                    },
                };
            }
            State::TerminalString {
                escape,
                held,
                introducer,
                chord,
            } => {
                let string = |escape, held| State::TerminalString {
                    escape,
                    held,
                    introducer,
                    chord,
                };
                match (escape, byte) {
                    (_, 0x07) | (true, b'\\') => self.state = State::Ground,
                    (_, 0x1b) => self.state = string(true, held),
                    // CAN and SUB cancel the string, as ECMA-48 has them.
                    (_, 0x18 | 0x1a) => self.end_string(held, each),
                    // A string a terminal sends holds no other control, so
                    // one is a key that ends it: Enter or Ctrl+C after Alt+P.
                    (_, 0x00..=0x1f | 0x7f) => {
                        self.end_string(held, each);
                        self.ground(byte, each);
                    }
                    _ => self.state = string(false, true),
                }
            }
            State::Paste { matched } => self.paste(byte, matched, each),
            State::AfterChord => {
                self.state = State::Ground;
                if !matches!(byte, 0x00..=0x1f | 0x7f) {
                    each(Event::Lost);
                }
                self.ground(byte, each);
            }
        }
    }

    /// Whether a paste or a terminal string has begun and not ended, so
    /// every byte that comes is read as part of it, Enter's and Ctrl+C's
    /// included.
    pub(super) fn unfinished(&self) -> bool {
        matches!(
            self.state,
            State::Paste { .. } | State::TerminalString { .. }
        )
    }

    /// End a paste or a terminal string whose end never came. What began
    /// like a paste's end marker was pasted text, and the paste is cut off;
    /// a terminal string adds nothing.
    pub(super) fn end_unfinished(&mut self, each: &mut dyn FnMut(Event)) {
        match self.state {
            State::Paste { matched } => {
                for &held in &PASTE_END[..usize::from(matched)] {
                    self.pasted(held, each);
                }
                self.state = State::Ground;
                self.after_carriage_return = false;
                each(Event::PasteCut);
            }
            State::TerminalString { held, .. } => self.end_string(held, each),
            _ => {}
        }
    }

    /// A terminal string ends without its end, which a terminal always
    /// sends: what it `held` may have been typed, and is lost.
    fn end_string(&mut self, held: bool, each: &mut dyn FnMut(Event)) {
        self.state = State::Ground;
        if held {
            each(Event::Lost);
        }
    }

    /// The read being fed ended. A terminal string that holds nothing yet
    /// may have begun with a key: Escape and the key in one read are a Meta
    /// chord, which edits nothing, though text after it can't be told from
    /// the rest of a string; a key that came after the Escape key's read may
    /// have been typed. A terminal sends a key's sequence whole, so what a
    /// sequence takes from a later read may have been typed, such as digits
    /// after Alt+[.
    pub(super) fn end_of_read(&mut self, each: &mut dyn FnMut(Event)) {
        match &mut self.state {
            State::TerminalString {
                escape: false,
                held: false,
                chord,
                ..
            } => {
                if *chord {
                    self.state = State::AfterChord;
                } else {
                    self.state = State::Ground;
                    each(Event::Lost);
                }
            }
            State::ControlSequence { crossed, .. }
            | State::SingleShift { crossed, .. }
            | State::MouseReport { crossed, .. } => *crossed = true,
            _ => {}
        }
    }

    /// A sequence took a byte; one from a read after its start may have
    /// been typed, and is lost.
    fn took_after_read(&self, crossed: bool, each: &mut dyn FnMut(Event)) {
        if crossed {
            each(Event::Lost);
        }
    }

    /// Whether the last byte was an escape that may start a sequence.
    pub(super) fn after_escape(&self) -> bool {
        matches!(self.state, State::Escape)
    }

    /// The escape just read was the Escape key, which edits nothing, rather
    /// than the start of a sequence.
    pub(super) fn escape_key(&mut self) {
        if self.after_escape() {
            self.state = State::Ground;
        }
    }

    /// The next bytes fed come in a read of their own.
    pub(super) fn next_read(&mut self) {
        self.escape_in_read = false;
    }

    fn ground(&mut self, byte: u8, each: &mut dyn FnMut(Event)) {
        match byte {
            0x1b => {
                self.state = State::Escape;
                self.escape_in_read = true;
            }
            0x00..=0x1f | 0x7f => each(control(byte)),
            _ => each(Event::Typed(byte)),
        }
    }

    fn paste(&mut self, byte: u8, matched: u8, each: &mut dyn FnMut(Event)) {
        let matched_length = usize::from(matched);
        if byte == PASTE_END[matched_length] {
            if matched_length + 1 == PASTE_END.len() {
                self.state = State::Ground;
                self.after_carriage_return = false;
                each(Event::PasteEnded);
            } else {
                self.state = State::Paste {
                    matched: matched + 1,
                };
            }
            return;
        }
        // What began like the end marker was pasted text.
        for &held in &PASTE_END[..matched_length] {
            self.pasted(held, each);
        }
        if byte == PASTE_END[0] {
            self.state = State::Paste { matched: 1 };
        } else {
            self.state = State::Paste { matched: 0 };
            self.pasted(byte, each);
        }
    }

    /// A terminal sends a pasted line break as `\r`; the value keeps `\n`,
    /// one for a `\r\n`.
    fn pasted(&mut self, byte: u8, each: &mut dyn FnMut(Event)) {
        let after_carriage_return =
            std::mem::replace(&mut self.after_carriage_return, byte == b'\r');
        match byte {
            b'\r' => each(Event::Pasted(b'\n')),
            b'\n' if after_carriage_return => {}
            _ => each(Event::Pasted(byte)),
        }
    }
}

#[cfg(any(windows, test))]
/// The UTF-16 code units the Windows console reads, a character outside the
/// Basic Multilingual Plane split across two, which may arrive in two reads.
#[derive(Default)]
pub(super) struct Utf16 {
    high_surrogate: Option<u16>,
}

#[cfg(any(windows, test))]
impl Utf16 {
    pub(super) fn feed(&mut self, unit: u16, each: &mut dyn FnMut(Event)) {
        if let Some(high) = self.high_surrogate.take() {
            if (0xDC00..=0xDFFF).contains(&unit) {
                let character = char::decode_utf16([high, unit]).next().and_then(Result::ok);
                console_character(character.unwrap_or(char::REPLACEMENT_CHARACTER), each);
                return;
            }
            console_character(char::REPLACEMENT_CHARACTER, each);
        }
        if (0xD800..=0xDBFF).contains(&unit) {
            self.high_surrogate = Some(unit);
            return;
        }
        console_character(
            char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER),
            each,
        );
    }

    /// End what was typed before a paste: a high surrogate still waiting
    /// for its pair types a replacement character there, as one any other
    /// unit follows does, rather than after the pasted text.
    pub(super) fn end(&mut self, each: &mut dyn FnMut(Event)) {
        if self.high_surrogate.take().is_some() {
            console_character(char::REPLACEMENT_CHARACTER, each);
        }
    }
}

/// The character a console key record types: a key press types one, and so
/// does the release of Alt that ends an Alt code, which is how the classic
/// console delivers a pasted character its keyboard layout lacks. Any other
/// release, Enter's included, types nothing.
#[cfg(any(windows, test))]
pub(super) fn typed_unit(key_down: bool, virtual_key: u16, unit: u16) -> Option<u16> {
    const VK_MENU: u16 = 0x12;
    (unit != 0 && (key_down || virtual_key == VK_MENU)).then_some(unit)
}

/// The clipboard's units a paste needs: its text up to the NUL that ends it,
/// but never more than a value of `limit` bytes can come from. Every two
/// units make at least one byte of UTF-8, as `\r\n` does, so a longer text
/// is known to be too large from that bounded prefix, whatever the
/// clipboard holds.
#[cfg(any(windows, test))]
pub(super) fn clipboard_units(held: &[u16], limit: usize) -> &[u16] {
    let held = &held[..held.len().min(limit.saturating_mul(2).saturating_add(1))];
    held.iter()
        .position(|&unit| unit == 0)
        .map_or(held, |end| &held[..end])
}

/// Text pasted from the clipboard, as UTF-16, the way a terminal's paste
/// arrives: pasted bytes with each `\r\n` or `\r` a `\n`, then its end.
#[cfg(any(windows, test))]
pub(super) fn paste_units(units: &[u16], each: &mut dyn FnMut(Event)) {
    let mut encoded = [0_u8; 4];
    let mut characters = char::decode_utf16(units.iter().copied())
        .map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER))
        .peekable();
    while let Some(character) = characters.next() {
        let character = if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            '\n'
        } else {
            character
        };
        for &byte in character.encode_utf8(&mut encoded).as_bytes() {
            each(Event::Pasted(byte));
        }
    }
    zeroize::Zeroize::zeroize(&mut encoded);
    each(Event::PasteEnded);
}

#[cfg(any(windows, test))]
/// A character the console read: Ctrl+Z ends input there, as Ctrl+D does on
/// Unix.
fn console_character(character: char, each: &mut dyn FnMut(Event)) {
    match u8::try_from(character) {
        Ok(0x1a) => each(Event::EndOfFile),
        Ok(byte @ (0x00..=0x1f | 0x7f)) => each(control(byte)),
        _ => {
            let mut encoded = [0_u8; 4];
            for &byte in character.encode_utf8(&mut encoded).as_bytes() {
                each(Event::Typed(byte));
            }
            zeroize::Zeroize::zeroize(&mut encoded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Events written so a test can compare them: text as itself, a paste
    /// starting `<paste>`, each other event as `<Name>`.
    #[derive(Default)]
    struct Shown {
        shown: String,
        text: Vec<u8>,
        pasting: bool,
    }

    impl Shown {
        fn take(&mut self, event: Event) {
            match event {
                Event::Typed(byte) => {
                    if self.pasting {
                        self.flush();
                        self.pasting = false;
                    }
                    self.text.push(byte);
                }
                Event::Pasted(byte) => {
                    if !self.pasting {
                        self.flush();
                        self.shown.push_str("<paste>");
                        self.pasting = true;
                    }
                    self.text.push(byte);
                }
                other => {
                    self.flush();
                    self.pasting = false;
                    self.shown.push_str(&format!("<{other:?}>"));
                }
            }
        }

        fn flush(&mut self) {
            self.shown.push_str(&String::from_utf8_lossy(&self.text));
            self.text.clear();
        }

        fn finish(mut self) -> String {
            self.flush();
            self.shown
        }
    }

    /// What `chunks` show, each one read on its own.
    fn decoded(chunks: &[&[u8]]) -> String {
        let mut bytes = Bytes::default();
        let mut shown = Shown::default();
        for chunk in chunks {
            bytes.next_read();
            for &byte in *chunk {
                bytes.feed(byte, &mut |event| shown.take(event));
            }
            bytes.end_of_read(&mut |event| shown.take(event));
        }
        shown.finish()
    }

    #[test]
    fn typed_text_and_control_keys() {
        assert_eq!(
            decoded(&[b"ab\tc\x7f\x08\x17\x15\x03\x04\x1a\r\n"]),
            "ab\tc<Backspace><Backspace><EraseWord><ClearLine><Interrupt><EndOfFile><Ignored><Enter><Enter>"
        );
        assert_eq!(decoded(&["é€".as_bytes()]), "é€");
    }

    #[test]
    fn keys_sent_as_escape_sequences_edit_nothing() {
        assert_eq!(decoded(&[b"a\x1b[A\x1bOB\x1b[3~\x1b[15~\x1b[1;5Cb"]), "ab");
    }

    #[test]
    fn a_meta_chord_adds_nothing_and_an_escape_key_drops_only_itself() {
        assert_eq!(decoded(&[b"\x1bx\x1b\x1b[Dy"]), "y", "Alt+X adds nothing");
        assert_eq!(decoded(&[b"\x1b", b"x"]), "x", "Escape, then x typed later");
        assert_eq!(
            decoded(&[b"\x1b\r"]),
            "<Enter>",
            "a control after it is its key"
        );
        assert_eq!(
            decoded(&[b"\x1b[1\x03"]),
            "<Lost><Interrupt>",
            "the 1 Alt+[ took may have been typed, and Ctrl+C still cancels"
        );
    }

    #[test]
    fn a_control_key_ends_a_terminal_string_so_enter_and_ctrl_c_still_work() {
        assert_eq!(decoded(&[b"\x1bP\r"]), "<Enter>", "Alt+P, then Enter");
        assert_eq!(
            decoded(&[b"\x1b]\x03"]),
            "<Interrupt>",
            "Alt+], then Ctrl+C"
        );
        assert_eq!(
            decoded(&[b"\x1bPab\x18cd"]),
            "<Lost>cd",
            "CAN cancels the string, which may have held typed text"
        );
        assert_eq!(
            decoded(&[b"\x1b_x\x1ayz"]),
            "<Lost>yz",
            "SUB cancels it too"
        );
        assert_eq!(
            decoded(&[b"\x1bP1$r0m\x1b\\a"]),
            "a",
            "a string a terminal ends adds and loses nothing"
        );
    }

    #[test]
    fn a_sequence_that_runs_into_a_later_read_may_have_taken_typed_text() {
        assert_eq!(
            decoded(&[b"a", b"\x1b[", b"12345\r"]),
            "a<Lost><Enter>",
            "Alt+[, then digits"
        );
        assert_eq!(
            decoded(&[b"a", b"\x1bO", b"bc\r"]),
            "a<Lost>c<Enter>",
            "Alt+Shift+O, then letters"
        );
        assert_eq!(
            decoded(&[b"a", b"\x1b[", b"\x03"]),
            "a<Interrupt>",
            "a key no sequence holds takes nothing"
        );
        for (split, what) in [
            (&[&b"\x1b"[..], b"[Ab"], "a CSI"),
            (&[&b"\x1b"[..], b"OPb"], "an SS3"),
            (&[&b"\x1b"[..], b"[M !!b"], "a mouse report"),
        ] {
            assert_eq!(
                decoded(split),
                "<Lost>b",
                "{what} after an escape that ended its read may be the Escape key and typed text"
            );
        }
        assert_eq!(
            decoded(&[b"\x1b", b"[200~x\x1b[201~"]),
            "<paste>x<PasteEnded>",
            "a paste's start is the terminal's, wherever a read ends"
        );
    }

    #[test]
    fn a_string_introducer_that_ends_its_read_leaves_what_follows_unclear() {
        assert_eq!(
            decoded(&[b"a", b"\x1bP", b"\r"]),
            "a<Enter>",
            "Alt+P, then a key that's no text, adds nothing"
        );
        assert_eq!(
            decoded(&[b"a", b"\x1bP", b"b"]),
            "a<Lost>b",
            "text after Alt+P can't be told from the rest of a terminal's string"
        );
        assert_eq!(
            decoded(&[b"ab", b"\x1b]", b"11;x\x07", b"\r"]),
            "ab<Lost>11;x<Ignored><Enter>",
            "a terminal's reply split after its start"
        );
        assert_eq!(
            decoded(&[b"ab", b"\x1b", b"]", b"11;x\x07", b"\r"]),
            "ab<Lost>11;x<Ignored><Enter>",
            "] after the Escape key, or a reply split twice"
        );
        assert_eq!(
            decoded(&[b"a", b"\x1bPb", b"\r"]),
            "a<Lost><Enter>",
            "text read with Alt+P can't be told from a terminal's string"
        );
    }

    #[test]
    fn a_sequence_that_ends_unfinished_may_have_taken_typed_text() {
        for (chunks, shown, what) in [
            (
                &[&b"ab"[..], b"\x1b", b"[", b"\r"][..],
                "ab<Lost><Enter>",
                "[ after the Escape key",
            ),
            (
                &[b"ab", b"\x1b", b"O", b"\r"],
                "ab<Lost><Enter>",
                "O after the Escape key",
            ),
            (
                &[b"abc", b"\x1b", b"[", b"\x7f", b"\r"],
                "abc<Lost><Backspace><Enter>",
                "[ after the Escape key, then Backspace",
            ),
            (
                &[b"a\x1b[123", b"\r"],
                "a<Lost><Enter>",
                "Alt+[ and digits, then Enter",
            ),
            (&[b"a\x1b[123\r"], "a<Lost><Enter>", "the same in one read"),
            (&[b"a\x1b[\r"], "a<Enter>", "Alt+[, then Enter"),
            (
                &[b"a\x1b[M\x03"],
                "a<Lost><Interrupt>",
                "Alt+[ and M, then Ctrl+C",
            ),
            (
                &[b"a\x1b[M !\r"],
                "a<Lost><Enter>",
                "a control key ends a mouse report",
            ),
        ] {
            assert_eq!(decoded(chunks), shown, "{what}");
        }
    }

    #[test]
    fn the_escape_key_followed_later_by_text_drops_only_itself() {
        let mut bytes = Bytes::default();
        let mut shown = Shown::default();
        for &byte in b"a\x1b" {
            bytes.feed(byte, &mut |event| shown.take(event));
        }
        assert!(bytes.after_escape());
        bytes.escape_key();
        assert!(!bytes.after_escape());
        for &byte in b"[b" {
            bytes.feed(byte, &mut |event| shown.take(event));
        }
        assert_eq!(shown.finish(), "a[b");
    }

    #[test]
    fn a_paste_is_text_whatever_it_holds_with_its_line_breaks_made_line_feeds() {
        assert_eq!(
            decoded(&[b"\x1b[200~one\rtwo\r\nthree\n\x03\x1b[A\x1b[201~\r"]),
            "<paste>one\ntwo\nthree\n\x03\x1b[A<PasteEnded><Enter>"
        );
    }

    #[test]
    fn a_paste_split_at_every_byte_decodes_the_same() {
        let whole: &[u8] = b"x\x1b[200~a\r\nb\x1b[20\x1b[201~y\r";
        let expected = decoded(&[whole]);
        assert_eq!(expected, "x<paste>a\nb\x1b[20<PasteEnded>y<Enter>");
        for split in 1..whole.len() {
            let (first, second) = whole.split_at(split);
            assert_eq!(decoded(&[first, second]), expected, "split at {split}");
        }
    }

    #[test]
    fn a_carriage_return_ending_one_read_and_a_line_feed_starting_the_next_are_one_break() {
        assert_eq!(
            decoded(&[b"\x1b[200~a\r", b"\nb\x1b[201~"]),
            "<paste>a\nb<PasteEnded>"
        );
    }

    fn console(units: &[u16]) -> String {
        let mut utf16 = Utf16::default();
        let mut shown = Shown::default();
        for &unit in units {
            utf16.feed(unit, &mut |event| shown.take(event));
        }
        shown.finish()
    }

    #[test]
    fn console_characters_are_text_and_control_keys() {
        let units: Vec<u16> = "a€\t"
            .encode_utf16()
            .chain([0x08, 0x1a, 0x03, 0x0d])
            .collect();
        assert_eq!(
            console(&units),
            "a€\t<Backspace><EndOfFile><Interrupt><Enter>"
        );
    }

    #[test]
    fn a_character_in_two_code_units_is_one_character_and_a_lone_half_is_replaced() {
        let emoji: Vec<u16> = "🔑".encode_utf16().collect();
        assert_eq!(console(&emoji), "🔑");
        assert_eq!(console(&[emoji[1], 0x61]), "\u{fffd}a");
        assert_eq!(console(&[emoji[0], 0x61]), "\u{fffd}a");
        assert_eq!(console(&[emoji[0], emoji[0], emoji[1]]), "\u{fffd}🔑");
        assert_eq!(console(&[emoji[0]]), "");
    }

    #[test]
    fn a_key_press_types_a_character_and_only_alt_s_release_does() {
        const VK_A: u16 = 0x41;
        const VK_RETURN: u16 = 0x0d;
        const VK_MENU: u16 = 0x12;
        assert_eq!(
            typed_unit(true, VK_A, u16::from(b'a')),
            Some(u16::from(b'a'))
        );
        assert_eq!(typed_unit(false, VK_A, u16::from(b'a')), None);
        assert_eq!(
            typed_unit(false, VK_RETURN, 0x0d),
            None,
            "the release of Enter"
        );
        assert_eq!(
            typed_unit(true, 0x10, 0),
            None,
            "a key that types nothing, such as Shift"
        );
        assert_eq!(
            typed_unit(false, VK_MENU, 0x20ac),
            Some(0x20ac),
            "an Alt code, as a pasted character the layout lacks arrives"
        );
        assert_eq!(
            typed_unit(false, VK_MENU, 0),
            None,
            "a plain release of Alt"
        );
    }

    #[test]
    fn a_clipboard_paste_copies_no_more_than_decides_its_value() {
        let limit = 8;
        let padded: Vec<u16> = "fixture\0junk after the end".encode_utf16().collect();
        assert_eq!(clipboard_units(&padded, limit), &padded[..7]);
        let long = vec![u16::from(b'x'); 10_000];
        assert_eq!(clipboard_units(&long, limit).len(), 2 * limit + 1);

        let breaks: Vec<u16> = "\r\n".repeat(10_000).encode_utf16().collect();
        let mut line = super::super::HiddenLine::new(limit);
        let mut ended = None;
        paste_units(clipboard_units(&breaks, limit), &mut |event| {
            if let super::super::Step::End(ending) = line.apply(event) {
                ended.get_or_insert(ending);
            }
        });
        assert!(
            matches!(ended, Some(super::super::Ending::TooLarge)),
            "even line breaks that make one byte each overflow the value"
        );
    }

    #[test]
    fn a_clipboard_paste_is_pasted_text_with_its_line_breaks_made_line_feeds() {
        let units: Vec<u16> = "one\r\ntwo\rthree\n🔑".encode_utf16().collect();
        let mut shown = Shown::default();
        paste_units(&units, &mut |event| shown.take(event));
        assert_eq!(shown.finish(), "<paste>one\ntwo\nthree\n🔑<PasteEnded>");
    }

    #[test]
    fn a_surrogate_typed_before_a_paste_is_replaced_before_the_pasted_text() {
        let mut typed = Utf16::default();
        let mut shown = Shown::default();
        typed.feed(0xD83D, &mut |event| shown.take(event));
        typed.end(&mut |event| shown.take(event));
        let units: Vec<u16> = "ab".encode_utf16().collect();
        paste_units(&units, &mut |event| shown.take(event));
        typed.end(&mut |event| shown.take(event));
        assert_eq!(shown.finish(), "\u{FFFD}<paste>ab<PasteEnded>");
    }

    #[test]
    fn a_terminal_string_that_never_ends_ends_once_quiet_so_ctrl_c_cancels_again() {
        for unfinished in [&b"\x1b]0;fixture-title"[..], b"\x1bPfixture-device"] {
            let mut bytes = Bytes::default();
            let mut events = Vec::new();
            for &byte in unfinished {
                bytes.feed(byte, &mut |event| events.push(event));
            }
            assert!(bytes.unfinished());
            bytes.end_unfinished(&mut |event| events.push(event));
            assert!(!bytes.unfinished(), "quiet ends it");
            bytes.feed(b'z', &mut |event| events.push(event));
            bytes.feed(0x03, &mut |event| events.push(event));
            assert_eq!(
                events,
                [Event::Lost, Event::Typed(b'z'), Event::Interrupt],
                "what it held may have been typed; a key after it is a key again"
            );
        }
    }

    #[test]
    fn mouse_reports_and_terminal_strings_add_nothing() {
        assert_eq!(decoded(&[b"a\x1b[M #!b"]), "ab", "an X10 mouse report");
        assert_eq!(
            decoded(&[b"a\x1b]11;rgb:0/0/0\x07b"]),
            "ab",
            "an OSC reply ended by BEL"
        );
        assert_eq!(
            decoded(&[b"a\x1bP1$r0m\x1b\\b"]),
            "ab",
            "a DCS reply ended by ST"
        );
        assert_eq!(decoded(&[b"a\x1b_x\x1b\\", b"b"]), "ab");
    }

    #[test]
    fn a_paste_ended_without_its_marker_keeps_what_began_like_one() {
        let mut bytes = Bytes::default();
        let mut shown = Shown::default();
        for &byte in b"\x1b[200~ab\x1b[20" {
            bytes.feed(byte, &mut |event| shown.take(event));
        }
        assert!(bytes.unfinished());
        bytes.end_unfinished(&mut |event| shown.take(event));
        assert!(!bytes.unfinished());
        for &byte in b"c" {
            bytes.feed(byte, &mut |event| shown.take(event));
        }
        assert_eq!(shown.finish(), "<paste>ab\x1b[20<PasteCut>c");
    }
}
