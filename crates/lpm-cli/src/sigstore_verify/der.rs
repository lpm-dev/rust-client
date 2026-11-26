//! A strict reader for the DER structures an RFC 3161 timestamp carries.
//!
//! Only DER is accepted: definite lengths in their shortest form and
//! single-byte tags. Every structure the timestamp verifier reads uses
//! low tag numbers, so a high-tag-number form is refused as malformed.

pub(super) const TAG_BOOLEAN: u8 = 0x01;
pub(super) const TAG_INTEGER: u8 = 0x02;
pub(super) const TAG_BIT_STRING: u8 = 0x03;
pub(super) const TAG_OCTET_STRING: u8 = 0x04;
pub(super) const TAG_NULL: u8 = 0x05;
pub(super) const TAG_OID: u8 = 0x06;
pub(super) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(super) const TAG_SEQUENCE: u8 = 0x30;
pub(super) const TAG_SET: u8 = 0x31;

/// `[n]` with the constructed bit set, as context-specific tags on
/// constructed values are encoded.
pub(super) const fn context_constructed(n: u8) -> u8 {
    0xA0 | n
}

/// `[n]` without the constructed bit, as context-specific tags on
/// primitive values are encoded.
pub(super) const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Element<'a> {
    pub(super) tag: u8,
    pub(super) contents: &'a [u8],
    /// The whole encoding: tag, length and contents.
    pub(super) encoded: &'a [u8],
}

#[derive(Debug, Clone)]
pub(super) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(super) fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    pub(super) fn element(&mut self) -> Result<Element<'a>, String> {
        let input = self.rest;
        let (&tag, after_tag) = input
            .split_first()
            .ok_or_else(|| "a DER element ends before its tag".to_string())?;
        if tag & 0x1F == 0x1F {
            return Err(format!("DER tag {tag:#04x} uses the high-tag-number form"));
        }
        let (&first, after_first) = after_tag
            .split_first()
            .ok_or_else(|| format!("DER element {tag:#04x} ends before its length"))?;
        let (length, after_length) = if first < 0x80 {
            (usize::from(first), after_first)
        } else {
            let count = usize::from(first & 0x7F);
            if count == 0 {
                return Err(format!(
                    "DER element {tag:#04x} uses an indefinite length, which DER forbids"
                ));
            }
            if count > std::mem::size_of::<usize>() || after_first.len() < count {
                return Err(format!("DER element {tag:#04x} has a malformed length"));
            }
            let (length_bytes, after_length) = after_first.split_at(count);
            if length_bytes[0] == 0 {
                return Err(format!(
                    "DER element {tag:#04x} encodes its length with a leading zero byte"
                ));
            }
            let length = length_bytes
                .iter()
                .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
            if length < 0x80 {
                return Err(format!(
                    "DER element {tag:#04x} uses the long length form for a short length"
                ));
            }
            (length, after_length)
        };
        if after_length.len() < length {
            return Err(format!(
                "DER element {tag:#04x} declares {length} bytes but only {} remain",
                after_length.len()
            ));
        }
        let (contents, rest) = after_length.split_at(length);
        let encoded = &input[..input.len() - rest.len()];
        self.rest = rest;
        Ok(Element {
            tag,
            contents,
            encoded,
        })
    }

    /// The next element, which must carry `tag`.
    pub(super) fn expect(&mut self, tag: u8, what: &str) -> Result<Element<'a>, String> {
        let element = self.element()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(format!(
                "{what} has tag {:#04x} where {tag:#04x} was expected",
                element.tag
            ))
        }
    }

    /// The next element when it carries `tag`, else nothing.
    pub(super) fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>, String> {
        if self.peek_tag() == Some(tag) {
            self.element().map(Some)
        } else {
            Ok(None)
        }
    }

    /// A reader over the contents of the next element, which must carry `tag`.
    pub(super) fn nested(&mut self, tag: u8, what: &str) -> Result<Reader<'a>, String> {
        Ok(Reader::new(self.expect(tag, what)?.contents))
    }

    pub(super) fn finish(&self, what: &str) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{what} has {} unexpected trailing bytes",
                self.rest.len()
            ))
        }
    }
}

/// The contents of a DER INTEGER, checked for the shortest encoding.
pub(super) fn integer_contents<'a>(element: &Element<'a>, what: &str) -> Result<&'a [u8], String> {
    if element.tag != TAG_INTEGER {
        return Err(format!("{what} is not an INTEGER"));
    }
    match element.contents {
        [] => Err(format!("{what} is an empty INTEGER")),
        [0x00, next, ..] if next & 0x80 == 0 => Err(format!(
            "{what} is an INTEGER with a redundant leading zero"
        )),
        [0xFF, next, ..] if next & 0x80 != 0 => Err(format!(
            "{what} is an INTEGER with a redundant leading 0xFF"
        )),
        contents => Ok(contents),
    }
}

/// A small non-negative DER INTEGER, such as a structure's version.
pub(super) fn small_unsigned(element: &Element<'_>, what: &str) -> Result<u32, String> {
    let contents = integer_contents(element, what)?;
    if contents[0] & 0x80 != 0 {
        return Err(format!("{what} is negative"));
    }
    if contents.len() > 4 {
        return Err(format!("{what} is out of range"));
    }
    Ok(contents
        .iter()
        .fold(0u32, |value, &byte| (value << 8) | u32::from(byte)))
}

/// The DER encoding of a SET OF whose contents are `contents`.
pub(super) fn encode_set(contents: &[u8]) -> Vec<u8> {
    let length = encode_length(contents.len());
    let mut encoded = Vec::with_capacity(1 + length.len() + contents.len());
    encoded.push(TAG_SET);
    encoded.extend_from_slice(&length);
    encoded.extend_from_slice(contents);
    encoded
}

pub(super) fn encode_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes = length.to_be_bytes();
    let significant = &bytes[bytes.iter().take_while(|&&byte| byte == 0).count()..];
    let mut encoded = Vec::with_capacity(1 + significant.len());
    encoded.push(0x80 | significant.len() as u8);
    encoded.extend_from_slice(significant);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(bytes: &[u8]) -> Result<Element<'_>, String> {
        let mut reader = Reader::new(bytes);
        let element = reader.element()?;
        reader.finish("test input")?;
        Ok(element)
    }

    #[test]
    fn reads_short_and_long_definite_lengths() {
        let short = element(&[TAG_OCTET_STRING, 2, 0xAB, 0xCD]).unwrap();
        assert_eq!(short.contents, [0xAB, 0xCD]);

        let mut long = vec![TAG_OCTET_STRING, 0x81, 0x80];
        long.extend(std::iter::repeat_n(7, 0x80));
        let long_element = element(&long).unwrap();
        assert_eq!(long_element.contents.len(), 0x80);
        assert_eq!(long_element.encoded, long.as_slice());
    }

    #[test]
    fn refuses_encodings_that_are_not_der() {
        let indefinite = element(&[TAG_SEQUENCE, 0x80, 0, 0]).unwrap_err();
        assert!(indefinite.contains("indefinite"), "{indefinite}");

        let long_for_short = element(&[TAG_OCTET_STRING, 0x81, 0x01, 0xAA]).unwrap_err();
        assert!(
            long_for_short.contains("long length form"),
            "{long_for_short}"
        );

        let mut leading_zero = vec![TAG_OCTET_STRING, 0x82, 0x00, 0x80];
        leading_zero.extend(std::iter::repeat_n(7, 0x80));
        let leading_zero = element(&leading_zero).unwrap_err();
        assert!(leading_zero.contains("leading zero"), "{leading_zero}");

        let high_tag = element(&[0x1F, 0x22, 0x00]).unwrap_err();
        assert!(high_tag.contains("high-tag-number"), "{high_tag}");

        let truncated = element(&[TAG_OCTET_STRING, 3, 1, 2]).unwrap_err();
        assert!(truncated.contains("only 2 remain"), "{truncated}");
    }

    #[test]
    fn refuses_trailing_bytes() {
        let trailing = element(&[TAG_NULL, 0, 0xFF]).unwrap_err();
        assert!(trailing.contains("trailing"), "{trailing}");
    }

    #[test]
    fn integers_must_use_the_shortest_encoding() {
        let parse = |contents: &[u8]| {
            let mut bytes = vec![TAG_INTEGER, contents.len() as u8];
            bytes.extend_from_slice(contents);
            let element = element(&bytes).unwrap();
            integer_contents(&element, "test").map(<[u8]>::to_vec)
        };
        assert_eq!(parse(&[0x00, 0x80]).unwrap(), [0x00, 0x80]);
        assert!(parse(&[0x00, 0x7F]).is_err());
        assert!(parse(&[0xFF, 0x80]).is_err());
        assert!(parse(&[]).is_err());

        let version = element(&[TAG_INTEGER, 1, 3]).unwrap();
        assert_eq!(small_unsigned(&version, "version").unwrap(), 3);
        let negative = element(&[TAG_INTEGER, 1, 0xFF]).unwrap();
        assert!(small_unsigned(&negative, "version").is_err());
    }

    #[test]
    fn encode_length_round_trips_through_the_reader() {
        for length in [0usize, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1_0000] {
            let contents = vec![0u8; length];
            let encoded = encode_set(&contents);
            let parsed = element(&encoded).unwrap();
            assert_eq!(parsed.tag, TAG_SET);
            assert_eq!(parsed.contents.len(), length);
        }
    }
}
