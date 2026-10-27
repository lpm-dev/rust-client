//! The characters in env values that are hard to see, by `lpm-env`'s rule,
//! so an app flags exactly what the CLI flags. Reports never contain values;
//! only showing and fixing one value returns text made from it.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::Deserialize;
use serde::ser::{Serialize, SerializeMap, SerializeStruct, Serializer};

use crate::{ABI_VERSION, LPMEnvResult, OUTPUT_LIMIT, bytes, failure, result};

/// Removes each flagged character other than whitespace at an end.
const FIX_REMOVE_HIDDEN: u32 = 1;
/// Removes the whitespace flagged at either end.
const FIX_TRIM_ENDS: u32 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckInput {
    environments: BTreeMap<String, BTreeMap<String, String>>,
}

/// Each environment's values that hold flagged characters, each checked
/// while it's written, so only one report is held at a time and output
/// stops, and checking with it, at the limit.
struct Environments<'a>(&'a BTreeMap<String, BTreeMap<String, String>>);

impl Serialize for Environments<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            self.0
                .iter()
                .map(|(name, values)| (name, FlaggedValues(values))),
        )
    }
}

struct FlaggedValues<'a>(&'a BTreeMap<String, String>);

impl Serialize for FlaggedValues<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self.0 {
            if let Some(found) = lpm_env::check_value_characters(value) {
                map.serialize_entry(key, &Report(&found))?;
            }
        }
        map.end()
    }
}

struct Report<'a>(&'a lpm_env::ValueCharacters);

impl Serialize for Report<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("Report", 4)?;
        fields.serialize_field("characters", &Characters(&self.0.characters))?;
        fields.serialize_field("more", &self.0.more)?;
        fields.serialize_field("removable", &self.0.removable)?;
        fields.serialize_field("trimmable", &self.0.trimmable)?;
        fields.end()
    }
}

struct Characters<'a>(&'a [lpm_env::FoundCharacter]);

impl Serialize for Characters<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(Character))
    }
}

struct Character<'a>(&'a lpm_env::FoundCharacter);

impl Serialize for Character<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct Run {
            position: usize,
            count: usize,
        }
        let found = self.0;
        let mut fields = serializer.serialize_struct("Character", 7)?;
        fields.serialize_field("kind", found.kind.code())?;
        fields.serialize_field("codePoint", &found.character.code_point())?;
        fields.serialize_field("escape", &found.character.escape())?;
        fields.serialize_field("name", found.character.name())?;
        fields.serialize_field("group", &found.character.group())?;
        fields.serialize_field("count", &found.count)?;
        fields.serialize_field(
            "runs",
            &found
                .runs
                .iter()
                .map(|run| Run {
                    position: run.position,
                    count: run.count,
                })
                .collect::<Vec<_>>(),
        )?;
        fields.end()
    }
}

/// Find the characters that are hard to see in each environment's values,
/// by the rule the CLI uses, without a schema. Values are never in the output.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_check_characters(input: *const u8, length: usize) -> LPMEnvResult {
    if input.is_null() || length == 0 || length > lpm_env_source::MAX_SCHEMA_BYTES {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller supplies a live readable range; its length was bounded above.
        let input = unsafe { std::slice::from_raw_parts(input, length) };
        if std::str::from_utf8(input).is_err() {
            return failure(2, "env.invalid_utf8");
        }
        let Ok(input) = serde_json::from_slice::<CheckInput>(input) else {
            return failure(2, "env.invalid_input");
        };
        if input.environments.iter().any(|(name, values)| {
            lpm_env::resolver::validate_env_name(name).is_err()
                || !values.keys().all(|key| lpm_env::is_valid_env_var_name(key))
        }) {
            return failure(2, "env.invalid_input");
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output<'a> {
            abi_version: u32,
            environments: Environments<'a>,
        }
        let output = Output {
            abi_version: ABI_VERSION,
            environments: Environments(&input.environments),
        };
        match lpm_env_source::bounded_json(&output, OUTPUT_LIMIT) {
            Ok(bytes) => result(0, bytes, None),
            Err(_) => failure(4, "env.output_budget"),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// One value, borrowed as text, or the failure to return for it.
///
/// # Safety
/// A non-null pointer must reference `length` readable bytes for the call.
unsafe fn value<'a>(value: *const u8, length: usize) -> Result<&'a str, LPMEnvResult> {
    if length > lpm_env_source::MAX_SCHEMA_BYTES {
        return Err(failure(2, "env.invalid_input"));
    }
    // SAFETY: Forwarded from this function's contract; the length is bounded above.
    let Some(raw) = (unsafe { bytes(value, length) }) else {
        return Err(failure(2, "env.invalid_input"));
    };
    std::str::from_utf8(raw).map_err(|_| failure(2, "env.invalid_utf8"))
}

/// Show one value with each flagged character written as its escape.
/// # Safety
/// The pointer must reference `length` readable bytes during the call, and
/// may be null only when `length` is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_show_characters(input: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let text = match unsafe { value(input, length) } {
        Ok(text) => text,
        Err(failure) => return failure,
    };
    catch_unwind(AssertUnwindSafe(|| {
        let shown = lpm_env::show_hidden_characters(text);
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output<'a> {
            abi_version: u32,
            text: &'a str,
            marks: Vec<[usize; 2]>,
        }
        let output = Output {
            abi_version: ABI_VERSION,
            text: &shown.text,
            marks: shown
                .marks
                .iter()
                .map(|mark| [mark.start, mark.end - mark.start])
                .collect(),
        };
        match lpm_env_source::bounded_json(&output, OUTPUT_LIMIT) {
            Ok(bytes) => result(0, bytes, None),
            Err(_) => failure(4, "env.output_budget"),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// Fix one value as a person chose: remove its hidden characters, or trim
/// its ends. The output is the fixed value as UTF-8, not JSON.
/// # Safety
/// The pointer must reference `length` readable bytes during the call, and
/// may be null only when `length` is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_fix_characters(
    input: *const u8,
    length: usize,
    fix: u32,
) -> LPMEnvResult {
    if !matches!(fix, FIX_REMOVE_HIDDEN | FIX_TRIM_ENDS) {
        return failure(2, "env.invalid_input");
    }
    // SAFETY: Forwarded from this function's contract.
    let text = match unsafe { value(input, length) } {
        Ok(text) => text,
        Err(failure) => return failure,
    };
    catch_unwind(AssertUnwindSafe(|| {
        let fixed = if fix == FIX_REMOVE_HIDDEN {
            lpm_env::remove_hidden_characters(text)
        } else {
            std::borrow::Cow::Borrowed(lpm_env::trim_ends(text))
        };
        // A buffer of exactly the value's length, so release wipes all of it.
        result(0, Box::<[u8]>::from(fixed.as_bytes()).into_vec(), None)
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpm_env_release;

    fn take(result: LPMEnvResult) -> (u32, Vec<u8>) {
        let output = if result.data.is_null() {
            Vec::new()
        } else {
            // SAFETY: A live result's data references `length` bytes until released.
            unsafe { std::slice::from_raw_parts(result.data, result.length) }.to_vec()
        };
        let status = result.status;
        // SAFETY: Each result is released exactly once, here.
        unsafe { lpm_env_release(result) };
        (status, output)
    }

    fn check(input: &str) -> (u32, serde_json::Value) {
        // SAFETY: The input stays live throughout the synchronous call.
        let (status, output) =
            take(unsafe { lpm_env_check_characters(input.as_ptr(), input.len()) });
        (
            status,
            serde_json::from_slice(&output).expect("JSON output"),
        )
    }

    fn fix(value: &str, fix: u32) -> (u32, Vec<u8>) {
        // SAFETY: The value stays live throughout the synchronous call.
        take(unsafe { lpm_env_fix_characters(value.as_ptr(), value.len(), fix) })
    }

    #[test]
    fn check_reports_each_flagged_value_by_environment_without_values() {
        let input = serde_json::json!({"environments": {
            "default": {"API_KEY": "sk_live_\u{200B}abc", "CLEAN": "value", "PEM": "a\nb\n"},
            "production": {"URL": "https://example.com \n"},
            "staging": {"OK": "fine"},
        }})
        .to_string();
        let (status, output) = check(&input);
        assert_eq!(status, 0);
        assert_eq!(
            output,
            serde_json::json!({
                "abiVersion": 1,
                "environments": {
                    "default": {"API_KEY": {
                        "characters": [{
                            "kind": "invisible", "codePoint": "U+200B", "escape": "\\u{200b}",
                            "name": "ZERO WIDTH SPACE", "group": null, "count": 1,
                            "runs": [{"position": 9, "count": 1}],
                        }],
                        "more": 0, "removable": true, "trimmable": false,
                    }},
                    "production": {"URL": {
                        "characters": [
                            {"kind": "trailing_whitespace", "codePoint": "U+0020", "escape": "\\u{20}",
                             "name": "SPACE", "group": null, "count": 1, "runs": [{"position": 20, "count": 1}]},
                            {"kind": "trailing_whitespace", "codePoint": "U+000A", "escape": "\\n",
                             "name": "LINE FEED", "group": null, "count": 1, "runs": [{"position": 21, "count": 1}]},
                        ],
                        "more": 0, "removable": false, "trimmable": true,
                    }},
                    "staging": {},
                },
            })
        );
        assert!(!output.to_string().contains("sk_live_"));
    }

    #[test]
    fn check_reports_groups_without_telling_their_characters_apart() {
        let input = r#"{"environments":{"default":{"TOKEN":"ok󠁨󠁩"}}}"#;
        let (status, output) = check(input);
        assert_eq!(status, 0);
        let character = &output["environments"]["default"]["TOKEN"]["characters"][0];
        assert_eq!(character["group"], "tags");
        assert_eq!(character["codePoint"], serde_json::Value::Null);
        assert_eq!(character["escape"], serde_json::Value::Null);
        assert_eq!(character["name"], "tag characters");
    }

    #[test]
    fn check_needs_no_schema_and_refuses_malformed_input() {
        let (status, output) = check(r#"{"environments":{}}"#);
        assert_eq!(
            (status, output),
            (0, serde_json::json!({"abiVersion": 1, "environments": {}}))
        );
        for input in [
            r#"{"environments":{"default":{"bad key":"v"}}}"#,
            r#"{"environments":{"../x":{"KEY":"v"}}}"#,
            r#"{"environments":{"default":{"KEY":1}}}"#,
            r#"{"environments":{},"schema":{}}"#,
        ] {
            assert_eq!(check(input).0, 2, "{input}");
        }
        // SAFETY: A null pointer is refused before it is read.
        assert_eq!(
            take(unsafe { lpm_env_check_characters(std::ptr::null(), 4) }).0,
            2
        );
        let invalid = [0xFF_u8, 0xFE];
        // SAFETY: The input stays live throughout the synchronous call.
        assert_eq!(
            take(unsafe { lpm_env_check_characters(invalid.as_ptr(), invalid.len()) }).0,
            2
        );
    }

    #[test]
    fn check_stops_at_the_output_limit() {
        // Eight different spaces, each in eight runs, report far more than
        // the value's own bytes, so an input under its limit outgrows the output's.
        let value = "\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}x".repeat(8);
        let mut input = String::from(r#"{"environments":{"default":{"#);
        let mut index = 0;
        while input.len() < lpm_env_source::MAX_SCHEMA_BYTES - 1024 {
            if index > 0 {
                input.push(',');
            }
            input.push_str(&format!(r#""K{index}":"{value}""#));
            index += 1;
        }
        input.push_str("}}}");
        // SAFETY: The input stays live throughout the synchronous call.
        let (status, _) = take(unsafe { lpm_env_check_characters(input.as_ptr(), input.len()) });
        assert_eq!(status, 4);
    }

    #[test]
    fn show_escapes_flagged_characters_and_marks_them_in_utf16() {
        let value = "😀a\u{200B}b ";
        // SAFETY: The value stays live throughout the synchronous call.
        let (status, output) =
            take(unsafe { lpm_env_show_characters(value.as_ptr(), value.len()) });
        assert_eq!(status, 0);
        let output: serde_json::Value = serde_json::from_slice(&output).expect("JSON output");
        assert_eq!(
            output,
            serde_json::json!({"abiVersion": 1, "text": "😀a\\u{200b}b\\u{20}", "marks": [[3, 8], [12, 6]]})
        );
        // SAFETY: An empty value may be null.
        let (status, output) = take(unsafe { lpm_env_show_characters(std::ptr::null(), 0) });
        assert_eq!(status, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).expect("JSON output"),
            serde_json::json!({"abiVersion": 1, "text": "", "marks": []})
        );
    }

    #[test]
    fn fix_removes_hidden_characters_or_trims_as_asked() {
        let value = " a\u{200B}b\u{A0}c\r\n";
        assert_eq!(
            fix(value, FIX_REMOVE_HIDDEN),
            (0, " ab c\r\n".as_bytes().to_vec())
        );
        assert_eq!(
            fix(value, FIX_TRIM_ENDS),
            (0, "a\u{200B}b\u{A0}c".as_bytes().to_vec())
        );
        assert_eq!(fix("", FIX_TRIM_ENDS), (0, Vec::new()));
        assert_eq!(fix(value, 0).0, 2);
        assert_eq!(fix(value, 3).0, 2);
        let invalid = [b'a', 0xFF];
        // SAFETY: The value stays live throughout the synchronous call.
        assert_eq!(
            take(unsafe { lpm_env_fix_characters(invalid.as_ptr(), invalid.len(), FIX_TRIM_ENDS) })
                .0,
            2
        );
        // SAFETY: A null pointer with a nonzero length is refused before it is read.
        assert_eq!(
            take(unsafe { lpm_env_fix_characters(std::ptr::null(), 1, FIX_TRIM_ENDS) }).0,
            2
        );
    }
}
