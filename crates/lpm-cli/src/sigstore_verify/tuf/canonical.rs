//! The canonical JSON form TUF signs: the OLPC encoding that
//! securesystemslib and go-securesystemslib produce.
//!
//! Object keys are sorted by code point, nothing is indented, strings escape
//! only `\` and `"` and keep every other character as raw UTF-8, and numbers
//! must be integers. `serde_json` can't produce this itself: it escapes
//! control characters, and with `preserve_order` it keeps keys in document
//! order.

use serde_json::Value;

/// Append the canonical encoding of `value` to `out`.
///
/// Fails on a number that isn't an integer, which TUF metadata never holds.
pub(super) fn encode(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                out.extend_from_slice(unsigned.to_string().as_bytes());
            } else if let Some(signed) = number.as_i64() {
                out.extend_from_slice(signed.to_string().as_bytes());
            } else {
                return Err(format!("{number} is not an integer"));
            }
        }
        Value::String(text) => encode_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            out.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode_string(key, out);
                out.push(b':');
                encode(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn encode_string(text: &str, out: &mut Vec<u8>) {
    out.reserve(text.len() + 2);
    out.push(b'"');
    for byte in text.bytes() {
        if byte == b'\\' || byte == b'"' {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::encode;
    use serde_json::json;

    fn canonical(value: serde_json::Value) -> String {
        let mut out = Vec::new();
        encode(&value, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn object_keys_are_sorted_by_code_point_at_every_level() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"é":true,"z":null,"A":[3,{"y":2,"x":1}]}}"#)
                .unwrap();
        assert_eq!(
            canonical(value),
            r#"{"a":{"A":[3,{"x":1,"y":2}],"z":null,"é":true},"b":1}"#
        );
    }

    #[test]
    fn strings_escape_only_backslash_and_quote() {
        let value = json!({"k": "tab\there \"quoted\" back\\slash\nnewline\u{0001}"});
        assert_eq!(
            canonical(value),
            "{\"k\":\"tab\there \\\"quoted\\\" back\\\\slash\nnewline\u{0001}\"}"
        );
    }

    #[test]
    fn negative_and_large_integers_keep_their_digits() {
        assert_eq!(
            canonical(json!([-7, 0, 18446744073709551615u64])),
            "[-7,0,18446744073709551615]"
        );
    }

    #[test]
    fn a_fractional_number_is_refused() {
        let mut out = Vec::new();
        assert!(encode(&json!({"threshold": 1.5}), &mut out).is_err());
    }
}
