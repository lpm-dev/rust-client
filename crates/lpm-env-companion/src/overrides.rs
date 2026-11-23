//! Personal overrides, version 1: values one Mac sets or unsets on top of an
//! env project's team values, per environment.
//!
//! ```json
//! {"schemaVersion": 1, "vaultId": "…", "environments": {
//!   "development": {"set": {"API_URL": "http://localhost:4000"}, "unset": ["SENTRY_DSN"]}
//! }}
//! ```

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use lpm_common::stored_env::json::{ReadError, Reader, line_and_column};
use lpm_common::stored_env::{is_valid_environment_name, is_valid_variable_name};
use zeroize::Zeroizing;

use crate::gate::{Damage, ProjectGate};
use crate::marker::{FeatureEntry, FeatureState, Level, MAX_RECORD_BYTES};

pub mod change;
#[cfg(test)]
mod serde_oracle;

pub const OVERRIDES_KIND: &str = "overrides";
/// The version of the record this client writes.
pub const VERSION: u16 = 1;

/// The marker entry for overrides v1. A client that doesn't support a
/// version refuses the project: running with team values instead of this
/// computer's overrides would quietly run something else.
pub fn feature_entry() -> FeatureEntry {
    FeatureEntry {
        version: VERSION,
        if_unsupported: Level::Refuse,
        kinds: vec![OVERRIDES_KIND.to_owned()],
        state: FeatureState::Active,
    }
}

const _: () = assert!(crate::graph::OVERRIDES.supported_versions[0] == VERSION);

/// The overrides of the selected environment.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PersonalOverrides {
    /// Values that replace the project's, an empty string included.
    pub set: HashMap<String, String>,
    /// Names whose project value is removed.
    pub unset: Vec<String>,
}

/// Names only: an override's value is a secret.
impl fmt::Debug for PersonalOverrides {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.layer().fmt(formatter)
    }
}

impl PersonalOverrides {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }

    /// How many names the overrides touch.
    pub fn len(&self) -> usize {
        self.set.len() + self.unset.len()
    }

    /// The overrides as layer 4 of a project's environment applies them.
    pub fn layer(&self) -> lpm_env::PersonalOverrideLayer<'_> {
        lpm_env::PersonalOverrideLayer {
            set: &self.set,
            unset: &self.unset,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOverrides(pub String);

impl fmt::Display for InvalidOverrides {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn invalid(reason: impl Into<String>) -> InvalidOverrides {
    InvalidOverrides(reason.into())
}

/// An environment's overrides as the record holds them. Values are wiped
/// when dropped, so a record that fails to read leaves none behind.
#[derive(Default)]
struct EnvironmentEntry {
    set: BTreeMap<String, Zeroizing<String>>,
    unset: Vec<String>,
}

impl EnvironmentEntry {
    fn into_overrides(self) -> PersonalOverrides {
        PersonalOverrides {
            set: self
                .set
                .into_iter()
                .map(|(key, mut value)| (key, std::mem::take(&mut *value)))
                .collect(),
            unset: self.unset,
        }
    }
}

/// What every environment of a record names, which the record's rules
/// judge whether or not its values are kept: each set name with whether
/// its value holds a NUL, and the unset names.
#[derive(Default)]
struct EntryNames<'a> {
    set: BTreeMap<Cow<'a, str>, bool>,
    unset: Vec<String>,
}

/// Which environments a read of the record keeps the values of. Every other
/// one is checked in place.
#[derive(Clone, Copy)]
enum Keep<'a> {
    Every,
    One(&'a str),
}

/// Validate the whole record stored for `vault_id`, then keep only
/// `environment`'s overrides. `version` is the marker's version for the
/// feature, which the record must repeat.
pub fn parse_selected(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    environment: &str,
) -> Result<PersonalOverrides, InvalidOverrides> {
    parse_selected_with_case_policy(bytes, vault_id, version, environment, cfg!(windows))
}

/// Validate the whole record and keep every environment's overrides.
pub fn parse_all(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
) -> Result<BTreeMap<String, PersonalOverrides>, InvalidOverrides> {
    Ok(
        read_record(bytes, vault_id, version, cfg!(windows), Keep::Every)?
            .into_iter()
            .map(|(name, entry)| (name, entry.into_overrides()))
            .collect(),
    )
}

/// The selected environment's personal overrides, from the overrides record
/// an Apply read always reads, found or not, so a missing marker can't hide
/// a record and a missing record can't pass for no overrides. The gate must
/// have allowed the Apply read, which it never does for a version this
/// client doesn't support.
pub fn evaluate(
    gate: &ProjectGate,
    vault_id: &str,
    environment: &str,
    record: Option<&[u8]>,
) -> Result<PersonalOverrides, Damage> {
    evaluate_with(gate, record, |bytes, version| {
        parse_selected(bytes, vault_id, version, environment)
    })
}

/// Every environment's personal overrides, under the same rules as
/// [`evaluate`].
pub fn evaluate_all(
    gate: &ProjectGate,
    vault_id: &str,
    record: Option<&[u8]>,
) -> Result<BTreeMap<String, PersonalOverrides>, Damage> {
    evaluate_with(gate, record, |bytes, version| {
        parse_all(bytes, vault_id, version)
    })
}

fn evaluate_with<T: Default>(
    gate: &ProjectGate,
    record: Option<&[u8]>,
    parse: impl FnOnce(&[u8], u16) -> Result<T, InvalidOverrides>,
) -> Result<T, Damage> {
    let entry = gate
        .marker()
        .and_then(|marker| marker.feature(OVERRIDES_KIND))
        .filter(|entry| entry.state == FeatureState::Active);
    let kind = || OVERRIDES_KIND.to_owned();
    match (entry, record) {
        (None, None) => Ok(T::default()),
        (None, Some(_)) => Err(Damage::UnlistedRecord { kind: kind() }),
        (Some(_), None) => Err(Damage::MissingRecord { kind: kind() }),
        (Some(entry), Some(bytes)) => {
            parse(bytes, entry.version).map_err(|error| Damage::InvalidRecord {
                kind: kind(),
                reason: error.to_string(),
            })
        }
    }
}

/// Reads the record stored for `vault_id` by the rules serde applies to it,
/// objects only: the fields `schemaVersion` (the marker's `version`),
/// `vaultId` and `environments`, each environment's `set` and `unset`, no
/// other field and none twice. Every environment is judged, and the values
/// of those `keep` names are kept. It reads with [`Reader`], which leaves no
/// copy of a value.
fn read_record(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    case_insensitive: bool,
    keep: Keep<'_>,
) -> Result<BTreeMap<String, EnvironmentEntry>, InvalidOverrides> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("the personal overrides are too large"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|error| malformed(bytes, error.valid_up_to(), true))?;
    let mut kept = BTreeMap::new();
    let mut names = BTreeMap::new();
    let (mut schema_version, mut record_vault_id, mut found_environments) = (None, None, false);
    let mut reader = Reader::new(text);
    reader
        .object(|reader, field| match &*field {
            "schemaVersion" if schema_version.is_none() => {
                schema_version = Some(reader.u16()?);
                Ok(())
            }
            "vaultId" if record_vault_id.is_none() => {
                record_vault_id = Some(reader.string()?);
                Ok(())
            }
            "environments" if !std::mem::replace(&mut found_environments, true) => {
                reader.object(|reader, name| {
                    if names.contains_key(&name) {
                        return Err(reader.unexpected("an environment named twice"));
                    }
                    let keeps = match keep {
                        Keep::Every => true,
                        Keep::One(selected) => name == selected,
                    };
                    let (entry_names, entry) = read_entry(reader, keeps)?;
                    if let Some(entry) = entry {
                        kept.insert(name.clone().into_owned(), entry);
                    }
                    names.insert(name, entry_names);
                    Ok(())
                })
            }
            _ => Err(reader.unexpected("an unknown or repeated field")),
        })
        .and_then(|()| reader.end())
        .map_err(|error| malformed_at(bytes, &error))?;
    let (Some(schema_version), Some(record_vault_id), true) =
        (schema_version, record_vault_id, found_environments)
    else {
        return Err(malformed(bytes, bytes.len(), false));
    };
    if schema_version != version {
        return Err(invalid(
            "the personal overrides' version differs from the feature marker's",
        ));
    }
    if record_vault_id != vault_id {
        return Err(invalid("the personal overrides name another env project"));
    }
    for (name, entry_names) in &names {
        validate_environment(name, entry_names, case_insensitive)?;
    }
    Ok(kept)
}

/// One environment's `set` and `unset`, with its values kept when `keep`.
fn read_entry<'a>(
    reader: &mut Reader<'a>,
    keep: bool,
) -> Result<(EntryNames<'a>, Option<EnvironmentEntry>), ReadError> {
    let mut names = EntryNames::default();
    let mut entry = keep.then(EnvironmentEntry::default);
    let (mut found_set, mut found_unset) = (false, false);
    reader.object(|reader, field| match &*field {
        "set" if !std::mem::replace(&mut found_set, true) => reader.object(|reader, key| {
            if names.set.contains_key(&key) {
                return Err(reader.unexpected("a name set twice"));
            }
            let nul = match entry.as_mut() {
                Some(entry) => {
                    let value = Zeroizing::new(reader.string()?);
                    let nul = value.contains('\0');
                    entry.set.insert(key.clone().into_owned(), value);
                    nul
                }
                None => reader.skip_string()?,
            };
            names.set.insert(key, nul);
            Ok(())
        }),
        "unset" if !std::mem::replace(&mut found_unset, true) => reader.array(|reader| {
            names.unset.push(reader.string()?);
            Ok(())
        }),
        _ => Err(reader.unexpected("an unknown or repeated field")),
    })?;
    if !(found_set && found_unset) {
        return Err(reader.unexpected("a missing field"));
    }
    if let Some(entry) = entry.as_mut() {
        entry.unset.clone_from(&names.unset);
    }
    Ok((names, entry))
}

fn malformed_at(bytes: &[u8], error: &ReadError) -> InvalidOverrides {
    malformed(bytes, error.offset(), error.is_syntax())
}

/// Where the record stopped reading, never what it holds.
fn malformed(bytes: &[u8], offset: usize, syntax: bool) -> InvalidOverrides {
    let (line, column) = line_and_column(bytes, offset);
    let problem = if syntax {
        "invalid JSON"
    } else {
        "an unexpected field or value"
    };
    invalid(format!(
        "the personal overrides are malformed: {problem} at line {line}, column {column}"
    ))
}

fn parse_selected_with_case_policy(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    environment: &str,
    case_insensitive: bool,
) -> Result<PersonalOverrides, InvalidOverrides> {
    Ok(read_record(
        bytes,
        vault_id,
        version,
        case_insensitive,
        Keep::One(environment),
    )?
    .remove(environment)
    .map(EnvironmentEntry::into_overrides)
    .unwrap_or_default())
}

fn validate_environment(
    name: &str,
    entry: &EntryNames<'_>,
    case_insensitive: bool,
) -> Result<(), InvalidOverrides> {
    if !is_valid_environment_name(name) {
        return Err(invalid(
            "the personal overrides name an invalid environment",
        ));
    }
    if entry.set.is_empty() && entry.unset.is_empty() {
        return Err(invalid(format!(
            "the personal overrides for {name:?} are empty"
        )));
    }
    let mut seen = HashSet::with_capacity(entry.set.len() + entry.unset.len());
    let mut remember = |key: &str| {
        if case_insensitive {
            seen.insert(key.to_ascii_uppercase())
        } else {
            seen.insert(key.to_owned())
        }
    };
    for (key, &nul) in &entry.set {
        validate_key(key)?;
        if nul {
            return Err(invalid(format!(
                "the personal override of {key} contains a NUL character"
            )));
        }
        if !remember(key) {
            return Err(invalid(format!(
                "the personal overrides for {name:?} name {key} twice"
            )));
        }
    }
    for key in &entry.unset {
        validate_key(key)?;
        if !remember(key) {
            return Err(invalid(format!(
                "the personal overrides for {name:?} name {key} twice"
            )));
        }
    }
    Ok(())
}

/// A name LPM never passes to a process stays valid here: the runner drops
/// it when it composes the environment, so widening that list never turns a
/// stored record into damage.
fn validate_key(key: &str) -> Result<(), InvalidOverrides> {
    if !is_valid_variable_name(key) {
        return Err(invalid("the personal overrides name an invalid variable"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::serde_oracle::parse_all_with_serde;
    use super::*;

    const ACTIVE_MARKER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;

    fn record(environments: &str) -> String {
        format!(r#"{{"schemaVersion":1,"vaultId":"proj","environments":{{{environments}}}}}"#)
    }

    /// Records the reader and serde must agree on: valid ones, every rule a
    /// record breaks, and escapes or bytes a string can't hold at every
    /// offset of values that cross the reader's 16- and 64-byte steps, in
    /// an environment read and one only checked.
    fn records() -> Vec<Vec<u8>> {
        let mut records: Vec<Vec<u8>> = [
            record(""),
            record(r#""development":{"set":{"A":"1","B":""},"unset":["C"]},"staging":{"set":{},"unset":["D"]}"#),
            record(r#""development":{"set":{"A":"line\nbreak \"quoted\" back\\slash \/ \b\f\r\t é中😀 é 😀"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"a\u0000b"},"unset":[]}"#),
            record(r#""staging":{"set":{"A":"a\u0000b"},"unset":[]},"development":{"set":{"B":"1"},"unset":[]}"#),
            record(r#""development":{"set":{},"unset":[]}"#),
            record(r#""bad name":{"set":{"A":"1"},"unset":[]}"#),
            record(r#""development":{"set":{"1BAD":"1"},"unset":[]}"#),
            record(r#""development":{"set":{},"unset":["BAD-NAME"]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":["A"]}"#),
            record(r#""development":{"set":{"A":"1","a":"2"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":["a"]}"#),
            record(r#""development":{"set":{"A":"1","A":"2"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1","A":"2"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":[]},"development":{"set":{"B":"1"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":[]},"development":{"set":{"B":"1"},"unset":[]}"#),
            record(r#""development":{"set":{"A":1},"unset":[]}"#),
            record(r#""development":{"set":{"A":null},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":"B"}"#),
            record(r#""development":{"set":{"A":"1"},"unset":[1]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":["B",]}"#),
            record(r#""development":{"set":{"A":"1"}}"#),
            record(r#""development":{"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":[],"extra":true}"#),
            record(r#""development":{"set":{"A":"1"},"set":{"B":"1"},"unset":[]}"#),
            record(r#""development":{"set":{"A":"1"},"unset":[],"unset":[]}"#),
            r#"{"schemaVersion":2,"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":1,"vaultId":"other","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":1.0,"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":01,"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":-1,"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":"1","vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":70000,"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":1,"environments":{}}"#.to_owned(),
            r#"{"schemaVersion":1,"vaultId":"proj"}"#.to_owned(),
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{},"extra":1}"#.to_owned(),
            r#"{"schemaVersion":1,"vaultId":"proj","vaultId":"proj","environments":{}}"#.to_owned(),
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{}} x"#.to_owned(),
            " {\n \"schemaVersion\" : 1 ,\t\"vaultId\" : \"proj\" , \"environments\" : { } }\r\n".to_owned(),
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{}}"#.to_owned(),
            "\u{feff}{\"schemaVersion\":1,\"vaultId\":\"proj\",\"environments\":{}}".to_owned(),
            String::new(),
            "{".to_owned(),
            "null".to_owned(),
            "[]".to_owned(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect();
        records
            .push(b"{\"schemaVersion\":1,\"vaultId\":\"proj\xff\",\"environments\":{}}".to_vec());
        records.push(
            record(&format!(
                r#""development":{{"set":{{"A":"{}"}},"unset":[]}}"#,
                "x".repeat(MAX_RECORD_BYTES)
            ))
            .into_bytes(),
        );
        for special in [
            "\\n",
            "\\\"",
            "\\\\",
            "\\u00e9",
            "\\ud83d\\ude00",
            "\\u0000",
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
                records.push(
                    record(&format!(
                        r#""development":{{"set":{{"A":"{value}"}},"unset":[]}},"staging":{{"set":{{"B":"{value}"}},"unset":[]}}"#
                    ))
                    .into_bytes(),
                );
            }
        }
        records
    }

    fn agree<T: PartialEq + fmt::Debug>(
        case: &[u8],
        ours: Result<T, InvalidOverrides>,
        serde: Result<T, InvalidOverrides>,
    ) {
        let malformed =
            |error: &InvalidOverrides| error.0.starts_with("the personal overrides are malformed");
        match (ours, serde) {
            (Ok(ours), Ok(serde)) => assert_eq!(ours, serde, "{}", String::from_utf8_lossy(case)),
            (Err(ours), Err(serde)) if malformed(&serde) => {
                assert!(
                    malformed(&ours),
                    "{}: {ours}",
                    String::from_utf8_lossy(case)
                );
            }
            (Err(ours), Err(serde)) => {
                assert_eq!(ours, serde, "{}", String::from_utf8_lossy(case));
            }
            (ours, serde) => panic!(
                "{}: ours {ours:?}, serde {serde:?}",
                String::from_utf8_lossy(case)
            ),
        }
    }

    #[test]
    fn the_record_reader_agrees_with_serde_on_every_record() {
        for case in records() {
            for case_insensitive in [false, true] {
                let serde = parse_all_with_serde(&case, "proj", 1, case_insensitive);
                agree(
                    &case,
                    read_record(&case, "proj", 1, case_insensitive, Keep::Every).map(|every| {
                        every
                            .into_iter()
                            .map(|(name, entry)| (name, entry.into_overrides()))
                            .collect::<BTreeMap<_, _>>()
                    }),
                    serde.clone(),
                );
                for environment in ["development", "staging", "missing"] {
                    agree(
                        &case,
                        parse_selected_with_case_policy(
                            &case,
                            "proj",
                            1,
                            environment,
                            case_insensitive,
                        ),
                        serde
                            .clone()
                            .map(|mut every| every.remove(environment).unwrap_or_default()),
                    );
                }
            }
        }
    }

    #[test]
    fn a_record_or_an_environment_written_as_an_array_is_refused() {
        for case in [
            r#"[1,"proj",{}]"#.to_owned(),
            record(r#""development":[{"A":"1"},[]]"#),
        ] {
            assert!(
                parse_all_with_serde(case.as_bytes(), "proj", 1, false).is_ok(),
                "serde's derived structs take {case}"
            );
            let refused = parse_all(case.as_bytes(), "proj", 1).expect_err("objects only");
            assert!(
                refused.0.starts_with("the personal overrides are malformed: an unexpected field or value at line 1, column "),
                "{refused}"
            );
            let gate = crate::assessment::gate_of("proj", Some(ACTIVE_MARKER.as_bytes()));
            assert!(
                matches!(
                    evaluate(&gate, "proj", "development", Some(case.as_bytes())),
                    Err(Damage::InvalidRecord { .. })
                ),
                "an Apply read finds it damaged"
            );
        }
    }

    fn parse(json: &str, environment: &str) -> Result<PersonalOverrides, InvalidOverrides> {
        parse_selected_with_case_policy(json.as_bytes(), "proj", 1, environment, false)
    }

    #[test]
    fn only_the_selected_environment_is_kept_after_the_whole_record_validates() {
        let json = r#"{"schemaVersion":1,"vaultId":"proj","environments":{
            "development":{"set":{"API_URL":"http://localhost:4000","EMPTY":""},"unset":["SENTRY_DSN"]},
            "staging":{"set":{"API_URL":"https://staging"},"unset":[]}}}"#;
        let selected = parse(json, "development").expect("valid overrides");
        assert_eq!(selected.set["API_URL"], "http://localhost:4000");
        assert_eq!(selected.set["EMPTY"], "");
        assert_eq!(selected.unset, ["SENTRY_DSN"]);
        assert!(
            parse(json, "production")
                .expect("valid overrides")
                .is_empty()
        );
    }

    #[test]
    fn an_invalid_entry_anywhere_rejects_the_record() {
        let invalid_records = [
            r#"{"schemaVersion":2,"vaultId":"proj","environments":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"other","environments":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{},"extra":true}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{},"unset":[]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1"}}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"bad name":{"set":{"A":"1"},"unset":[]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"1A":"1"},"unset":[]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"x\u0000y"},"unset":[]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1"},"unset":["A"]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{},"unset":["A","A"]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1","A":"2"},"unset":[]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1"},"unset":[]},"staging":{"set":{"B":"1"},"unset":[]}}}"#,
        ];
        for json in invalid_records {
            assert!(parse(json, "development").is_err(), "{json}");
        }
    }

    #[test]
    fn a_name_lpm_never_passes_keeps_the_record_valid() {
        let json = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"NODE_OPTIONS":"--inspect","A":"1"},"unset":["CLASSPATH"]}}}"#;
        let staging = parse(json, "staging").expect("a later deny list can't damage a record");
        assert_eq!(staging.set["NODE_OPTIONS"], "--inspect");
        assert_eq!(staging.unset, ["CLASSPATH"]);
    }

    #[test]
    fn a_malformed_record_is_described_without_its_contents() {
        let json = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":4815162342},"unset":[]}}}"#;
        let error = parse(json, "staging").expect_err("a value must be a string");
        assert!(!error.0.contains("4815162342"), "{error}");
        assert!(error.0.contains("line 1"), "{error}");
    }

    #[test]
    fn names_that_differ_only_in_case_conflict_where_the_host_ignores_case() {
        let json = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"Api":"1"},"unset":["API"]}}}"#;
        assert!(
            parse_selected_with_case_policy(json.as_bytes(), "proj", 1, "staging", false).is_ok()
        );
        assert!(
            parse_selected_with_case_policy(json.as_bytes(), "proj", 1, "staging", true).is_err()
        );
    }

    #[test]
    fn overrides_are_damaged_when_the_marker_and_the_record_disagree() {
        use crate::marker::{FeatureEntry, Level, Marker, ProjectState};

        let plain = ProjectGate::Plain;
        assert_eq!(
            evaluate(&plain, "proj", "default", None),
            Ok(PersonalOverrides::default())
        );
        assert_eq!(
            evaluate(&plain, "proj", "default", Some(b"{}")),
            Err(Damage::UnlistedRecord {
                kind: "overrides".to_owned()
            })
        );
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            "overrides".to_owned(),
            FeatureEntry {
                version: 1,
                if_unsupported: Level::Refuse,
                kinds: vec!["overrides".to_owned()],
                state: FeatureState::Active,
            },
        );
        let marked = ProjectGate::Marked(marker);
        assert_eq!(
            evaluate(&marked, "proj", "default", None),
            Err(Damage::MissingRecord {
                kind: "overrides".to_owned()
            })
        );
        assert!(matches!(
            evaluate_all(&marked, "proj", Some(b"[]")),
            Err(Damage::InvalidRecord { .. })
        ));
        let record = br#"{"schemaVersion":1,"vaultId":"proj","environments":{"default":{"set":{"A":"1"},"unset":[]}}}"#;
        let overrides = evaluate(&marked, "proj", "default", Some(record)).expect("valid");
        assert_eq!(overrides.set["A"], "1");
        assert_eq!(
            evaluate_all(&marked, "proj", Some(record)).expect("valid")["default"],
            overrides
        );
    }

    #[test]
    fn records_larger_than_the_record_limit_are_rejected_before_parsing() {
        let oversized = vec![b' '; MAX_RECORD_BYTES + 1];
        assert!(parse_selected(&oversized, "proj", 1, "default").is_err());
    }

    #[test]
    fn debug_output_names_overrides_and_never_shows_their_values() {
        let overrides = PersonalOverrides {
            set: HashMap::from([("TOKEN".to_owned(), "fixture-secret".to_owned())]),
            unset: vec!["SENTRY_DSN".to_owned()],
        };
        let printed = format!("{overrides:?}");
        assert!(!printed.contains("fixture-secret"), "{printed}");
        assert!(
            printed.contains("TOKEN") && printed.contains("SENTRY_DSN"),
            "{printed}"
        );
    }
}
