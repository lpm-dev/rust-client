const UTF8_BOM_BYTES: &[u8] = b"\xEF\xBB\xBF";

/// Removes one leading UTF-8 byte-order mark from decoded text.
#[inline]
pub fn strip_utf8_bom_str(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

/// Removes one leading UTF-8 byte-order mark from raw bytes.
#[inline]
pub fn strip_utf8_bom_bytes(content: &[u8]) -> &[u8] {
    content.strip_prefix(UTF8_BOM_BYTES).unwrap_or(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_utf8_bom_str_removes_one_leading_marker() {
        assert_eq!(
            strip_utf8_bom_str("\u{feff}{\"name\":\"pkg\"}"),
            "{\"name\":\"pkg\"}"
        );
    }

    #[test]
    fn strip_utf8_bom_str_preserves_unmarked_text() {
        assert_eq!(
            strip_utf8_bom_str("{\"name\":\"pkg\"}"),
            "{\"name\":\"pkg\"}"
        );
    }

    #[test]
    fn strip_utf8_bom_bytes_removes_one_leading_marker() {
        assert_eq!(strip_utf8_bom_bytes(b"\xEF\xBB\xBF{}"), b"{}");
    }

    #[test]
    fn strip_utf8_bom_bytes_preserves_unmarked_bytes() {
        assert_eq!(strip_utf8_bom_bytes(b"{}"), b"{}");
    }
}
