use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use lpm_common::stored_env::json::{ReadError, Reader};
use zeroize::Zeroizing;

use crate::{EnvironmentMap, SecretMap};
pub(crate) use lpm_common::stored_env::is_valid_environment_name;
use lpm_common::stored_env::is_valid_variable_name;
use lpm_env::{DEFAULT_ENVIRONMENT, reads_default_environment};

/// Why a stored payload didn't parse. It names keys and environments,
/// never a value.
pub(crate) type PayloadError = ReadError;

#[cfg(test)]
mod serde_oracle;

/// Every environment of the stored payload, as [`parse_payload`] reads it.
pub(crate) fn parse_all(json: &str) -> Result<EnvironmentMap, PayloadError> {
    let mut environments = crate::history::ZeroizingValues::default();
    let any = parse_payload(json, |reader, environment| {
        secrets(
            reader,
            Some(environments.entry(environment.into_owned()).or_default()),
        )
    })?;
    if !any {
        environments.insert(DEFAULT_ENVIRONMENT.to_owned(), HashMap::new());
    }
    Ok(std::mem::take(&mut *environments))
}

pub(crate) fn parse(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, PayloadError> {
    select(json, selected_environment, false)
}

pub(crate) fn parse_with_default_fallback(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, PayloadError> {
    select(json, selected_environment, true)
}

/// `selected_environment`'s values from the stored payload or, with
/// `default_fallback`, the default environment's where
/// [`reads_default_environment`] says so. Every other environment is checked
/// as [`parse_payload`] checks it, and none of its values is kept.
fn select(
    json: &str,
    selected_environment: &str,
    default_fallback: bool,
) -> Result<SelectedVaultPayload, PayloadError> {
    let mut selected = None::<crate::wiping::ParsedValues>;
    let mut fallback = None::<crate::wiping::ParsedValues>;
    let any = parse_payload(json, |reader, environment| {
        let kept = if environment == selected_environment {
            Some(&mut selected)
        } else if default_fallback && environment == DEFAULT_ENVIRONMENT {
            Some(&mut fallback)
        } else {
            None
        };
        secrets(
            reader,
            kept.map(|slot| &mut **slot.insert(Default::default())),
        )
    })?;
    let take = |mut values: crate::wiping::ParsedValues| std::mem::take(&mut *values);
    let selected = if !any && selected_environment == DEFAULT_ENVIRONMENT {
        Some(SecretMap::new())
    } else if default_fallback
        && reads_default_environment(
            selected_environment,
            selected.as_ref().is_some_and(|values| !values.is_empty()),
        )
    {
        fallback.map(take)
    } else {
        selected.map(take)
    };
    Ok(SelectedVaultPayload::Versioned(selected))
}

/// Reads the stored payload `{"environments":{name:{KEY: VALUE}}}` by the
/// rules serde applies to it: one `environments` field, unique valid
/// environment and variable names, and string values. `environment` reads
/// each environment's variables, given its name once that's checked, and
/// the result says whether there was any environment. It reads with
/// [`Reader`], which leaves no copy of a value.
fn parse_payload<'a>(
    json: &'a str,
    mut environment: impl FnMut(&mut Reader<'a>, Cow<'a, str>) -> Result<(), PayloadError>,
) -> Result<bool, PayloadError> {
    let mut reader = Reader::new(json);
    let mut names = HashSet::new();
    let mut found = false;
    reader.object(|reader, field| {
        if field != "environments" {
            return Err(
                reader.unexpected(&format!("unknown field `{field}`, expected `environments`"))
            );
        }
        if std::mem::replace(&mut found, true) {
            return Err(reader.unexpected("duplicate field `environments`"));
        }
        reader.object(|reader, name| {
            if !is_valid_environment_name(&name) {
                return Err(reader.unexpected(&format!("environment name {name:?} is invalid")));
            }
            if !names.insert(name.clone()) {
                return Err(reader.unexpected(&format!("duplicate environment name {name:?}")));
            }
            environment(reader, name)
        })
    })?;
    reader.end()?;
    if !found {
        return Err(reader.unexpected("missing field `environments`"));
    }
    Ok(!names.is_empty())
}

/// An environment's variables: valid, unique names with string values,
/// decoded into `kept` or, without it, only checked.
fn secrets(reader: &mut Reader<'_>, mut kept: Option<&mut SecretMap>) -> Result<(), PayloadError> {
    let mut checked = HashSet::new();
    reader.object(|reader, variable| {
        if !is_valid_variable_name(&variable) {
            return Err(reader.unexpected(&format!("env variable name {variable:?} is invalid")));
        }
        let seen = kept.as_deref().map_or_else(
            || checked.contains(&variable),
            |secrets| secrets.contains_key(&*variable),
        );
        if seen {
            return Err(reader.unexpected(&format!("duplicate env variable name {variable:?}")));
        }
        match kept.as_deref_mut() {
            Some(secrets) => {
                let value = reader.string()?;
                secrets.insert(variable.into_owned(), value);
            }
            None => {
                reader.skip_string()?;
                checked.insert(variable);
            }
        }
        Ok(())
    })
}

pub(crate) enum SelectedVaultPayload {
    Versioned(Option<SecretMap>),
}

impl SelectedVaultPayload {
    pub(crate) fn into_selected(self) -> Option<SecretMap> {
        match self {
            Self::Versioned(selected) => selected,
        }
    }
}

pub(crate) fn validate_environments(environments: &EnvironmentMap) -> Result<(), String> {
    for (environment, secrets) in environments {
        if !is_valid_environment_name(environment) {
            return Err(format!("environment name {environment:?} is invalid"));
        }
        if let Some(variable) = secrets.keys().find(|name| !is_valid_variable_name(name)) {
            return Err(format!("env variable name {variable:?} is invalid"));
        }
    }
    Ok(())
}

/// The stored payload of `environments`. It holds the values, so it's wiped
/// when dropped, and no buffer it outgrows while being written keeps a copy.
pub(crate) fn serialize(environments: &EnvironmentMap) -> Result<Zeroizing<String>, String> {
    #[derive(serde::Serialize)]
    struct BorrowedPayload<'a> {
        environments: &'a EnvironmentMap,
    }

    validate_environments(environments)?;
    if environments.is_empty() {
        return Ok(Zeroizing::new(
            r#"{"environments":{"default":{}}}"#.to_owned(),
        ));
    }
    let mut payload = crate::wiping::WipingBuffer::with_capacity(unescaped_len(environments));
    serde_json::to_writer(&mut payload, &BorrowedPayload { environments })
        .map_err(|error| format!("failed to serialize environments: {error}"))?;
    crate::zeroizing_text(payload.into_bytes())
        .map_err(|_| "serialized environments are not UTF-8".to_owned())
}

/// Room for the payload when nothing in it needs escaping, a few bytes
/// over its length.
fn unescaped_len(environments: &EnvironmentMap) -> usize {
    // `{"environments":{` and `}}`; per environment `"name":{},`; per
    // value `"KEY":"value",`.
    environments.iter().fold(19, |length, (name, keys)| {
        keys.iter()
            .fold(length + name.len() + 6, |length, (key, value)| {
                length + key.len() + value.len() + 6
            })
    })
}

#[cfg(test)]
mod tests {
    use super::serde_oracle::{parse_all_with_serde, parse_with_serde};
    use super::*;

    /// Payloads with an escape, or a byte a string can't hold, at every
    /// offset of values long enough to cross the reader's 16- and 64-byte
    /// steps twice, in `environment` and in another one.
    fn special_bytes_at_every_offset(environment: &str) -> Vec<String> {
        let mut payloads = Vec::new();
        for special in [
            "\\n",
            "\\\"",
            "\\\\",
            "\\u00e9",
            "\\ud83d\\ude00",
            "\n",
            "\u{1f}",
            "\"",
            "\\",
        ] {
            for offset in 0..140 {
                let value = format!(
                    "{}{special}{}",
                    "x".repeat(offset),
                    "y".repeat(140 - offset)
                );
                payloads.push(format!(
                    r#"{{"environments":{{"{environment}":{{"A":"{value}"}},"other":{{"B":"{value}"}}}}}}"#
                ));
            }
        }
        payloads
    }

    #[test]
    fn the_payload_parser_agrees_with_serde_on_every_payload() {
        let cases = [
            r#"{"environments":{}}"#,
            r#"{"environments":{"default":{"A":"1"}}}"#,
            " { \"environments\" : { \"default\" : { \"A\" : \"1\" , \"B\" : \"\" } ,\n\t\"staging\" : { } } }\r\n",
            r#"{"environments":{"default":{"A":"line\nbreak \"quoted\" back\\slash \/ \b\f\r\t"}}}"#,
            r#"{"environments":{"default":{"A":"é中😀 \u0000 ﻿"}}}"#,
            r#"{"environments":{"default":{"A":"é中😀"}}}"#,
            r#"{"environments":{"default":{"A":"x"}}}"#,
            "",
            "{",
            "{}",
            "null",
            "[]",
            r#"{"environments":null}"#,
            r#"{"environments":[]}"#,
            r#"{"environments":{"default":{"A":1}}}"#,
            r#"{"environments":{"default":{"A":null}}}"#,
            r#"{"environments":{"default":{"A":{"B":"c"}}}}"#,
            r#"{"environments":{"default":{"A":"1"}}} x"#,
            r#"{"environments":{"default":{"A":"1"}}}}"#,
            r#"{"environments":{},"extra":true}"#,
            r#"{"environments":{},"environments":{}}"#,
            r#"{"environments":{"default":{},"default":{}}}"#,
            r#"{"environments":{"default":{"A":"1","A":"2"}}}"#,
            r#"{"environments":{"bad name":{}}}"#,
            r#"{"environments":{"default":{"1BAD":"x"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83d"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83dx"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83dA"}}}"#,
            r#"{"environments":{"default":{"A":"\ude00"}}}"#,
            r#"{"environments":{"default":{"A":"\x"}}}"#,
            r#"{"environments":{"default":{"A":"\u12"}}}"#,
            r#"{"environments":{"default":{"A":"\u12g4"}}}"#,
            "{\"environments\":{\"default\":{\"A\":\"tab\there\"}}}",
            "{\"environments\":{\"default\":{\"A\":\"new\nline\"}}}",
            r#"{"environments":{"default":{"A":"1",}}}"#,
            r#"{"environments":{"default":{"A" "1"}}}"#,
            r#"{"environments":{"default":{"A":"unterminated}}}"#,
            r#"{"environments":{"default":{"A":"ends in a backslash\"#,
            "\u{feff}{\"environments\":{}}",
            r#"[{"default":{"A":"1"}}]"#,
            r#"{"environments":[{"A":"1"}]}"#,
            r#"{"environments":{"default":{"A":"1","\u0041":"2"}}}"#,
            r#"{"environments":{"default":{"A":"1"},"\u0064efault":{}}}"#,
            r#"{"\u0065nvironments":{"default":{"A":"1"}}}"#,
            "{\"environments\":{\"default\":{\"A\u{1}\":\"1\"}}}",
            r#"{"environments":{"default":{"A\u0001":"1"}}}"#,
        ];
        let long = special_bytes_at_every_offset("default");
        for case in cases.into_iter().chain(long.iter().map(String::as_str)) {
            match (parse_all(case), parse_all_with_serde(case)) {
                (Ok(ours), Ok(serde)) => assert_eq!(ours, serde, "{case:?}"),
                (Err(_), Err(_)) => {}
                (ours, serde) => panic!("{case:?}: ours {ours:?}, serde {serde:?}"),
            }
        }
    }

    #[test]
    fn selecting_an_environment_agrees_with_serde_on_every_payload() {
        let cases = [
            r#"{"environments":{}}"#,
            r#"{"environments":{"default":{"A":"1"}}}"#,
            r#"{"environments":{"default":{"A":"1"},"live":{"B":"2"},"empty":{}}}"#,
            r#"{"environments":{"live":{"B":"line\nbreak \"quoted\" \u00e9"},"other":{"C":"\ud83d\ude00"}}}"#,
            r#"{"environments":{"default":{},"live":{}}}"#,
            r#"{"environments":{"default":{"A":"1"},"live":{"B":2}}}"#,
            r#"{"environments":{"default":{"A":"1"},"other":{"B":null}}}"#,
            r#"{"environments":{"default":{"A":"1"},"other":{"B":"\x"}}}"#,
            r#"{"environments":{"default":{"A":"1"},"other":{"B":"\ud83d"}}}"#,
            r#"{"environments":{"default":{"A":"1"},"other":{"1BAD":"x"}}}"#,
            r#"{"environments":{"default":{"A":"1"},"other":{"B":"x","B":"y"}}}"#,
            r#"{"environments":{"live":{"B":"x","B":"y"}}}"#,
            r#"{"environments":{"live":{},"live":{}}}"#,
            r#"{"environments":{"other":{},"other":{}}}"#,
            r#"{"environments":{"bad name":{}}}"#,
            r#"{"environments":{},"environments":{}}"#,
            r#"{"environments":{},"extra":true}"#,
            r#"{"environments":{"live":{"B":"1"}}} x"#,
            r#"{"environments":{"other":{"B":"unterminated}}}"#,
            "{\"environments\":{\"other\":{\"B\":\"new\nline\"}}}",
            r#"{"A":"one"}"#,
            r#"{"environments":"legacy-value"}"#,
            "",
            "{}",
            "\u{feff}{\"environments\":{}}",
            r#"[{"live":{"B":"1"}}]"#,
            r#"{"environments":{"live":[{"B":"1"}]}}"#,
            r#"{"environments":{"other":{"B":"1","\u0042":"2"},"live":{"A":"1"}}}"#,
            r#"{"environments":{"live":{"A":"1"},"\u006cive":{"A":"2"}}}"#,
        ];
        let long = special_bytes_at_every_offset("live");
        for case in cases.into_iter().chain(long.iter().map(String::as_str)) {
            for environment in ["default", "live", "empty", "missing"] {
                for fallback in [false, true] {
                    let ours = if fallback {
                        parse_with_default_fallback(case, environment)
                    } else {
                        parse(case, environment)
                    };
                    match (ours, parse_with_serde(case, environment, fallback)) {
                        (Ok(ours), Ok(serde)) => assert_eq!(
                            ours.into_selected(),
                            serde.into_selected(),
                            "{case:?} {environment} {fallback}"
                        ),
                        (Err(_), Err(_)) => {}
                        (ours, serde) => panic!(
                            "{case:?} {environment} {fallback}: ours {:?}, serde {:?}",
                            ours.map(SelectedVaultPayload::into_selected),
                            serde.map(SelectedVaultPayload::into_selected)
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn the_payload_parser_reads_back_whatever_serialize_writes() {
        let values = (0_u32..0x250)
            .chain([0x2028, 0x2029, 0xFEFF, 0x1F600])
            .filter_map(char::from_u32)
            .map(|character| format!("a{character}b"));
        let environments = EnvironmentMap::from([
            (
                "default".to_owned(),
                values
                    .enumerate()
                    .map(|(index, value)| (format!("KEY_{index}"), value))
                    .collect(),
            ),
            ("empty".to_owned(), SecretMap::new()),
        ]);
        let serialized = serialize(&environments).expect("serializes");
        assert_eq!(parse_all(&serialized).expect("parses"), environments);
        assert_eq!(
            parse_all_with_serde(&serialized).expect("parses"),
            environments
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn parsing_escaped_values_leaves_no_copy_of_them_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        // A newline and a quote need escaping, as in a PEM private key.
        let payload = format!(
            r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n-----END-----","QUOTED":"say \"{MARKER}\""}}}}}}"#
        );
        let (read, found) = watch(|| {
            let mut environments = parse_all(&payload).expect("parses");
            let key = &environments["default"]["KEY"];
            let read = key.strip_prefix(MARKER) == Some("\n-----END-----");
            crate::history::wipe_values(&mut environments);
            read
        });
        assert!(read);
        assert!(!found, "no buffer the parser used keeps an escaped value");

        let truncated = format!(r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n"#);
        let (failed, found) = watch(|| parse_all(&truncated).is_err());
        assert!(failed);
        assert!(
            !found,
            "a payload that doesn't parse leaves nothing behind either"
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn selecting_an_environment_leaves_no_copy_of_any_value_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        let payload = format!(
            r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n-----END-----"}},"empty":{{}},"live":{{"KEY":"{MARKER}\n","QUOTED":"say \"{MARKER}\""}}}}}}"#
        );
        for (environment, fallback) in [
            ("live", false),
            ("default", false),
            ("missing", false),
            ("live", true),
            ("empty", true),
        ] {
            let (read, found) = watch(|| {
                let selected = if fallback {
                    parse_with_default_fallback(&payload, environment)
                } else {
                    parse(&payload, environment)
                };
                let mut selected = selected.expect("parses").into_selected();
                let read = selected
                    .as_ref()
                    .map(|values| values["KEY"].starts_with(MARKER));
                if let Some(values) = &mut selected {
                    crate::history::wipe_environment(values);
                }
                read
            });
            assert_eq!(
                read,
                (environment != "missing").then_some(true),
                "{environment}"
            );
            assert!(
                !found,
                "{environment}, fallback {fallback}: no value selected, passed over or validated is left behind"
            );
        }

        let unfinished = format!(
            r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n"}},"live":{{"KEY":"{MARKER}\n","#
        );
        for environment in ["default", "live"] {
            let (failed, found) = watch(|| parse(&unfinished, environment).is_err());
            assert!(failed);
            assert!(
                !found,
                "{environment}: a payload that doesn't parse leaves nothing behind"
            );
        }
    }

    #[test]
    fn a_payload_with_nothing_to_escape_is_written_without_moving() {
        let environments = EnvironmentMap::from([
            (
                "default".to_owned(),
                SecretMap::from([
                    ("API_KEY".to_owned(), "abc123".to_owned()),
                    ("EMPTY".to_owned(), String::new()),
                ]),
            ),
            ("preview".to_owned(), SecretMap::new()),
        ]);
        let serialized = serialize(&environments).expect("serialize");
        assert_eq!(parse_all(&serialized).expect("parse"), environments);
        assert_eq!(serialized.capacity(), unescaped_len(&environments));
        assert!(unescaped_len(&environments) - serialized.len() < 8);
    }

    #[cfg(not(miri))]
    #[test]
    fn serializing_values_leaves_no_copy_of_them_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        // Control characters are written as six-byte escapes, so the
        // payload outgrows a buffer sized from the values' own lengths.
        let environments = EnvironmentMap::from([(
            "default".to_owned(),
            (0..64)
                .map(|index| {
                    (
                        format!("KEY_{index}"),
                        format!("{MARKER}\"{index}\n{}", "\u{1}".repeat(index)),
                    )
                })
                .collect(),
        )]);
        let (serialized, found) = watch(|| serialize(&environments).expect("serialize"));
        assert!(
            serialized.len() > unescaped_len(&environments),
            "the payload outgrew its first buffer"
        );
        assert!(!found, "no buffer outgrown while writing keeps a copy");
        assert_eq!(parse_all(&serialized).expect("parse"), environments);
        let ((), found) = watch(move || drop(serialized));
        assert!(!found, "the payload is wiped when dropped");
    }

    #[test]
    fn selects_only_the_requested_versioned_environment() {
        let payload = parse(
            r#"{"environments":{"default":{"A":"one"},"live":{"B":"two"}}}"#,
            "live",
        )
        .expect("parse versioned payload");

        assert_eq!(
            payload.into_selected(),
            Some(HashMap::from([("B".to_owned(), "two".to_owned())]))
        );
    }

    #[test]
    fn validates_an_unselected_environment_without_retaining_it() {
        let error = parse(
            r#"{"environments":{"default":{"A":"one"},"live":{"BROKEN":7}}}"#,
            "default",
        )
        .err()
        .expect("malformed unselected environment must be rejected");

        assert!(error.to_string().contains("expected a string"), "{error}");
    }

    #[test]
    fn rejects_legacy_flat_payload_selection() {
        assert!(parse(r#"{"A":"one"}"#, "default").is_err());
    }

    #[test]
    fn rejects_a_string_instead_of_the_environments_map() {
        assert!(parse(r#"{"environments":"legacy-value"}"#, "default").is_err());
    }

    #[test]
    fn selects_requested_or_default_in_one_validating_pass() {
        let payload = r#"{"environments":{"default":{"A":"fallback"},"empty":{},"live":{"A":"selected"},"other":{"B":"validated"}}}"#;

        assert_eq!(
            parse_with_default_fallback(payload, "live")
                .expect("select populated environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "selected".to_owned())]))
        );
        assert_eq!(
            parse_with_default_fallback(payload, "empty")
                .expect("fall back from empty environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "fallback".to_owned())]))
        );
        assert_eq!(
            parse_with_default_fallback(payload, "missing")
                .expect("fall back from missing environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "fallback".to_owned())]))
        );
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        assert!(parse(r#"{"environments":{"default":{}},"version":3}"#, "default").is_err());
        assert!(parse_all(r#"{"environments":{},"extra":true}"#).is_err());
    }

    #[test]
    fn rejects_duplicate_top_level_environment_and_variable_keys() {
        assert!(parse(r#"{"environments":{},"environments":{}}"#, "default").is_err());
        assert!(parse_all(r#"{"environments":{"default":{},"default":{}}}"#).is_err());
        assert!(
            parse(
                r#"{"environments":{"default":{"TOKEN":"one","TOKEN":"two"}}}"#,
                "default"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_environment_and_variable_names() {
        let oversized = "a".repeat(65);
        for environment in ["", "../live", "__index__", "live/team", oversized.as_str()] {
            let payload = format!(r#"{{"environments":{{"{environment}":{{}}}}}}"#);
            assert!(parse_all(&payload).is_err(), "accepted {environment:?}");
        }
        for variable in ["", "1TOKEN", "BAD-NAME", "ÜNICODE"] {
            let payload = format!(r#"{{"environments":{{"default":{{"{variable}":"x"}}}}}}"#);
            assert!(parse_all(&payload).is_err(), "accepted {variable:?}");
        }
    }

    #[test]
    fn normalizes_an_empty_environment_wrapper_to_default() {
        assert_eq!(
            parse_all(r#"{"environments":{}}"#).unwrap(),
            HashMap::from([("default".to_owned(), HashMap::new())])
        );
        assert_eq!(
            parse(r#"{"environments":{}}"#, "default")
                .unwrap()
                .into_selected(),
            Some(HashMap::new())
        );
    }
}
