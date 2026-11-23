//! A reader for the JSON env storage keeps, which holds secret values. It
//! exists because serde_json decodes an escaped string through a scratch
//! buffer it grows and frees without wiping: here a string is decoded only
//! when it's kept, into a buffer sized to its encoded length, which the
//! decoded string never exceeds, so no buffer is moved or left with a copy.
//! A string that's only checked is read in place.

use std::borrow::Cow;
use std::fmt;

use zeroize::Zeroizing;

/// Why stored JSON didn't read, and where. It holds the names the reader's
/// caller put in it, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    message: String,
    at: usize,
    syntax: bool,
}

impl ReadError {
    /// Whether the text isn't JSON, rather than JSON of another shape.
    pub fn is_syntax(&self) -> bool {
        self.syntax
    }

    /// The byte at which the text was found wrong.
    pub fn offset(&self) -> usize {
        self.at
    }
}

/// The line and column, both from 1, of byte `offset` of `text`.
pub fn line_and_column(text: &[u8], offset: usize) -> (usize, usize) {
    let before = &text[..offset.min(text.len())];
    let line_start = before
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let line = 1 + before.iter().filter(|&&byte| byte == b'\n').count();
    (line, before.len() - line_start + 1)
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at byte {}", self.message, self.at)
    }
}

impl std::error::Error for ReadError {}

/// Reads JSON text as serde_json does, one value at a time, without leaving
/// a copy of what it decodes.
pub struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    /// An error for JSON of another shape than the caller reads, here.
    pub fn unexpected(&self, message: &str) -> ReadError {
        ReadError {
            message: message.to_owned(),
            at: self.at,
            syntax: false,
        }
    }

    fn syntax(&self, message: &str) -> ReadError {
        ReadError {
            message: message.to_owned(),
            at: self.at,
            syntax: true,
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.text.as_bytes().get(self.at),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.at += 1;
        }
    }

    fn next_is(&mut self, byte: u8) -> bool {
        self.skip_whitespace();
        if self.text.as_bytes().get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    /// The end of the text, where only whitespace may follow the value.
    pub fn end(&mut self) -> Result<(), ReadError> {
        self.skip_whitespace();
        if self.at == self.text.len() {
            Ok(())
        } else {
            Err(self.syntax("trailing characters"))
        }
    }

    /// An object, calling `member` with each key once its colon is read. A
    /// key without escapes is borrowed from the text.
    pub fn object(
        &mut self,
        mut member: impl FnMut(&mut Self, Cow<'a, str>) -> Result<(), ReadError>,
    ) -> Result<(), ReadError> {
        if !self.next_is(b'{') {
            return Err(self.unexpected("expected an object"));
        }
        if self.next_is(b'}') {
            return Ok(());
        }
        loop {
            let key = self.key()?;
            if !self.next_is(b':') {
                return Err(self.syntax("expected `:`"));
            }
            member(self, key)?;
            if self.next_is(b'}') {
                return Ok(());
            }
            if !self.next_is(b',') {
                return Err(self.syntax("expected `,` or `}`"));
            }
        }
    }

    /// An array, calling `element` to read each element.
    pub fn array(
        &mut self,
        mut element: impl FnMut(&mut Self) -> Result<(), ReadError>,
    ) -> Result<(), ReadError> {
        if !self.next_is(b'[') {
            return Err(self.unexpected("expected an array"));
        }
        if self.next_is(b']') {
            return Ok(());
        }
        loop {
            element(self)?;
            if self.next_is(b']') {
                return Ok(());
            }
            if !self.next_is(b',') {
                return Err(self.syntax("expected `,` or `]`"));
            }
        }
    }

    /// A whole number from 0 to 65535 as JSON writes one, which serde reads
    /// into a `u16`: no sign, fraction or exponent.
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        self.skip_whitespace();
        let bytes = self.text.as_bytes();
        let start = self.at;
        let digits = bytes[start..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return Err(self.unexpected("expected a number"));
        }
        if digits > 1 && bytes[start] == b'0' {
            return Err(self.syntax("invalid number"));
        }
        self.at += digits;
        if matches!(bytes.get(self.at), Some(b'.' | b'e' | b'E')) {
            return Err(self.unexpected("expected a whole number"));
        }
        self.text[start..self.at]
            .parse()
            .map_err(|_| self.unexpected("a number out of range"))
    }

    fn key(&mut self) -> Result<Cow<'a, str>, ReadError> {
        self.skip_whitespace();
        let text = self.text;
        let bytes = text.as_bytes();
        if bytes.get(self.at) == Some(&b'"') {
            let end = special_byte(bytes, self.at + 1);
            if bytes.get(end) == Some(&b'"') {
                let key = &text[self.at + 1..end];
                self.at = end + 1;
                return Ok(Cow::Borrowed(key));
            }
        }
        self.string().map(Cow::Owned)
    }

    /// A string, decoded into a buffer the size of its encoded form, which
    /// is wiped if the string doesn't read.
    pub fn string(&mut self) -> Result<String, ReadError> {
        let mut decoded = Zeroizing::new(String::new());
        self.decode_string(Some(&mut decoded))?;
        Ok(std::mem::take(&mut *decoded))
    }

    /// A string checked as [`string`](Self::string) decodes it, keeping
    /// nothing of it; true when it decodes to one with a NUL character.
    pub fn skip_string(&mut self) -> Result<bool, ReadError> {
        self.decode_string(None)
    }

    /// Reads a string in one pass, decoding it into `decoded` when given,
    /// which first takes room for the whole encoded string; true when it
    /// holds a NUL, which only an escape can write.
    fn decode_string(&mut self, mut decoded: Option<&mut String>) -> Result<bool, ReadError> {
        if !self.next_is(b'"') {
            return Err(self.unexpected("expected a string"));
        }
        if let Some(decoded) = decoded.as_deref_mut() {
            decoded.reserve_exact(self.encoded_length()?);
        }
        let bytes = self.text.as_bytes();
        let mut nul = false;
        loop {
            let run = special_byte(bytes, self.at);
            if let Some(decoded) = decoded.as_deref_mut() {
                decoded.push_str(&self.text[self.at..run]);
            }
            self.at = run;
            let character = match bytes.get(self.at) {
                None => return Err(self.syntax("unterminated string")),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(nul);
                }
                Some(b'\\') => {
                    self.at += 1;
                    self.escape()?
                }
                Some(_) => return Err(self.syntax("control character in a string")),
            };
            nul |= character == '\0';
            if let Some(decoded) = decoded.as_deref_mut() {
                decoded.push(character);
            }
        }
    }

    /// The length of the string from here to its closing quote, which a
    /// decoded string never exceeds.
    fn encoded_length(&mut self) -> Result<usize, ReadError> {
        let bytes = self.text.as_bytes();
        let mut end = self.at;
        loop {
            end = special_byte(bytes, end);
            match bytes.get(end) {
                None => {
                    self.at = bytes.len();
                    return Err(self.syntax("unterminated string"));
                }
                Some(b'"') => return Ok(end - self.at),
                Some(b'\\') => end += 2,
                Some(_) => end += 1,
            }
        }
    }

    /// The character an escape names, after its backslash.
    fn escape(&mut self) -> Result<char, ReadError> {
        let escaped = self.text.as_bytes().get(self.at).copied();
        self.at += 1;
        Ok(match escaped {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => self.unicode_escape()?,
            _ => return Err(self.syntax("invalid escape")),
        })
    }

    /// The character a `\u` escape names, after its `\u`: a surrogate pair
    /// takes two escapes, and a lone surrogate is refused.
    fn unicode_escape(&mut self) -> Result<char, ReadError> {
        let high = self.hex4()?;
        let code = match high {
            0xD800..=0xDBFF => {
                if self.text.as_bytes().get(self.at..self.at + 2) != Some(b"\\u") {
                    return Err(self.syntax("lone leading surrogate in a \\u escape"));
                }
                self.at += 2;
                let low = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.syntax("lone leading surrogate in a \\u escape"));
                }
                0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.syntax("lone trailing surrogate in a \\u escape")),
            code => code,
        };
        char::from_u32(code).ok_or_else(|| self.syntax("invalid \\u escape"))
    }

    /// Four hex digits, which a string's closing quote is never one of.
    fn hex4(&mut self) -> Result<u32, ReadError> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| self.syntax("invalid \\u escape"))?;
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|_| self.syntax("invalid \\u escape"))
    }
}

/// Where the first quote, backslash or control character at or after
/// `from` is, or the end of `bytes`. Most of what's stored is plain value
/// bytes, so it skips whole chunks first.
fn special_byte(bytes: &[u8], from: usize) -> usize {
    let at = skip_plain::<16>(bytes, skip_plain::<64>(bytes, from.min(bytes.len())));
    bytes[at..]
        .iter()
        .position(|&byte| is_special(byte))
        .map_or(bytes.len(), |offset| at + offset)
}

/// `at` moved past every whole `N`-byte chunk with no special byte in it.
fn skip_plain<const N: usize>(bytes: &[u8], mut at: usize) -> usize {
    while let Some(chunk) = bytes
        .get(at..at + N)
        .and_then(|chunk| <&[u8; N]>::try_from(chunk).ok())
    {
        // Folding every byte, without stopping early, is what compiles to
        // vector compares: a scan that stops at the first special byte runs
        // a byte at a time, four times slower than serde_json's.
        if chunk
            .iter()
            .fold(0_u8, |found, &byte| found | u8::from(is_special(byte)))
            != 0
        {
            break;
        }
        at += N;
    }
    at
}

fn is_special(byte: u8) -> bool {
    (byte == b'"') | (byte == b'\\') | (byte < 0x20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_special_byte_is_found_wherever_it_falls_against_the_chunks() {
        for length in [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 200] {
            for at in 0..length {
                for special in [b'"', b'\\', b'\n', 0x00, 0x1f] {
                    let mut bytes = vec![b'x'; length];
                    bytes[at] = special;
                    assert_eq!(special_byte(&bytes, 0), at, "{length} {at} {special}");
                    assert_eq!(special_byte(&bytes, at), at, "{length} {at} {special}");
                    assert_eq!(special_byte(&bytes, at + 1), length, "{length} {at}");
                }
            }
            assert_eq!(special_byte(&vec![b'x'; length], 0), length);
        }
        assert_eq!(special_byte(b"xx", 5), 2, "a start past the end");
    }

    #[test]
    fn a_skipped_string_says_whether_it_holds_a_nul() {
        for (text, nul) in [
            (r#""plain""#, false),
            (r#""a\u0000b""#, true),
            (r#""\n\"\\""#, false),
        ] {
            assert_eq!(Reader::new(text).skip_string(), Ok(nul), "{text}");
            let mut reader = Reader::new(text);
            assert_eq!(reader.string().map(|text| text.contains('\0')), Ok(nul));
            assert_eq!(reader.end(), Ok(()));
        }
    }

    #[test]
    fn whole_numbers_read_as_serde_reads_a_u16() {
        for (text, read) in [
            ("0", Some(0)),
            ("1", Some(1)),
            (" 65535 ", Some(65535)),
            ("65536", None),
            ("01", None),
            ("-1", None),
            ("1.0", None),
            ("1e0", None),
            ("\"1\"", None),
            ("", None),
        ] {
            let mut reader = Reader::new(text);
            let ours = reader
                .u16()
                .and_then(|number| reader.end().map(|()| number));
            let serde = serde_json::from_str::<u16>(text);
            assert_eq!(ours.ok(), read, "{text:?}");
            assert_eq!(serde.ok(), read, "{text:?}: serde agrees");
        }
    }

    #[test]
    fn an_error_says_its_line_and_column() {
        let text = "{\n  \"a\": x\n}";
        let mut reader = Reader::new(text);
        let error = reader
            .object(|reader, _| reader.skip_string().map(drop))
            .expect_err("not a string");
        assert_eq!(line_and_column(text.as_bytes(), error.offset()), (2, 8));
        assert!(!error.is_syntax());
    }
}
