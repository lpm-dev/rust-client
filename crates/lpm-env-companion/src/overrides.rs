//! Personal overrides, version 1: values one Mac sets or unsets on top of an
//! env project's team values, per environment.
//!
//! ```json
//! {"schemaVersion": 1, "vaultId": "…", "environments": {
//!   "development": {"set": {"API_URL": "http://localhost:4000"}, "unset": ["SENTRY_DSN"]}
//! }}
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use lpm_common::stored_env::{is_valid_environment_name, is_valid_variable_name};
use serde::{Deserialize, Deserializer};

use crate::gate::{Damage, ProjectGate};
use crate::marker::{FeatureState, MAX_RECORD_BYTES, UniqueMapVisitor, describe_json_error};

pub const OVERRIDES_KIND: &str = "overrides";

/// The overrides of the selected environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonalOverrides {
    /// Values that replace the project's, an empty string included.
    pub set: HashMap<String, String>,
    /// Names whose project value is removed.
    pub unset: Vec<String>,
}

impl PersonalOverrides {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }

    /// How many names the overrides touch.
    pub fn len(&self) -> usize {
        self.set.len() + self.unset.len()
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OverridesRecord {
    schema_version: u16,
    vault_id: String,
    #[serde(deserialize_with = "unique_environments")]
    environments: BTreeMap<String, EnvironmentEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntry {
    #[serde(deserialize_with = "unique_values")]
    set: BTreeMap<String, String>,
    unset: Vec<String>,
}

fn unique_environments<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, EnvironmentEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
}

fn unique_values<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
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
    let record = parse_record(bytes, vault_id, version, cfg!(windows))?;
    Ok(record
        .environments
        .into_iter()
        .map(|(name, entry)| {
            (
                name,
                PersonalOverrides {
                    set: entry.set.into_iter().collect(),
                    unset: entry.unset,
                },
            )
        })
        .collect())
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

fn parse_record(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    case_insensitive: bool,
) -> Result<OverridesRecord, InvalidOverrides> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("the personal overrides are too large"));
    }
    let record: OverridesRecord = serde_json::from_slice(bytes).map_err(|error| {
        invalid(format!(
            "the personal overrides are malformed: {}",
            describe_json_error(&error)
        ))
    })?;
    if record.schema_version != version {
        return Err(invalid(
            "the personal overrides' version differs from the feature marker's",
        ));
    }
    if record.vault_id != vault_id {
        return Err(invalid("the personal overrides name another env project"));
    }
    for (name, entry) in &record.environments {
        validate_environment(name, entry, case_insensitive)?;
    }
    Ok(record)
}

fn parse_selected_with_case_policy(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    environment: &str,
    case_insensitive: bool,
) -> Result<PersonalOverrides, InvalidOverrides> {
    let mut record = parse_record(bytes, vault_id, version, case_insensitive)?;
    Ok(record
        .environments
        .remove(environment)
        .map(|entry| PersonalOverrides {
            set: entry.set.into_iter().collect(),
            unset: entry.unset,
        })
        .unwrap_or_default())
}

fn validate_environment(
    name: &str,
    entry: &EnvironmentEntry,
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
    for (key, value) in &entry.set {
        validate_key(key)?;
        if value.contains('\0') {
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
    use super::*;

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
}
