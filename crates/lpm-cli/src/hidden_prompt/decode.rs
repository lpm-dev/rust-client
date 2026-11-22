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
    },
    /// `ESC O` and the one byte that ends it.
    SingleShift,
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
                b'[' => {
                    self.state = State::ControlSequence {
                        parameters: [0; 3],
                        length: 0,
                    };
                }
                b'O' => self.state = State::SingleShift,
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
            } => match byte {
                0x20..=0x3f => {
                    if let Some(slot) = parameters.get_mut(usize::from(length)) {
                        *slot = byte;
                    }
                    self.state = State::ControlSequence {
                        parameters,
                        length: length.saturating_add(1),
                    };
                }
                0x40..=0x7e => {
                    self.state = if byte == b'~' && length == 3 && parameters == *b"200" {
                        State::Paste { matched: 0 }
                    } else {
                        State::Ground
                    };
                }
                // A byte no sequence holds ends it unfinished, and is read
                // on its own.
                _ => {
                    self.state = State::Ground;
                    self.ground(byte, each);
                }
            },
            State::SingleShift => {
                self.state = State::Ground;
                if !(0x40..=0x7e).contains(&byte) {
                    self.ground(byte, each);
                }
            }
            State::Paste { matched } => self.paste(byte, matched, each),
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

    fn ground(&mut self, byte: u8, each: &mut dyn FnMut(Event)) {
        match byte {
            0x1b => self.state = State::Escape,
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

    fn decoded(chunks: &[&[u8]]) -> String {
        let mut bytes = Bytes::default();
        let mut shown = Shown::default();
        for chunk in chunks {
            for &byte in *chunk {
                bytes.feed(byte, &mut |event| shown.take(event));
            }
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
    fn an_escape_that_starts_no_sequence_drops_only_itself() {
        assert_eq!(decoded(&[b"\x1bx\x1b\x1b[Dy"]), "xy");
        assert_eq!(decoded(&[b"\x1b[1\x03"]), "<Interrupt>");
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
}
