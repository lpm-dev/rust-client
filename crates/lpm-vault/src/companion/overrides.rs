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

use super::marker::{MAX_RECORD_BYTES, UniqueMapVisitor};

pub(crate) const OVERRIDES_KIND: &str = "overrides";

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
pub(crate) struct InvalidOverrides(pub(crate) String);

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
pub(crate) fn parse_selected(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    environment: &str,
) -> Result<PersonalOverrides, InvalidOverrides> {
    parse_selected_with_case_policy(bytes, vault_id, version, environment, cfg!(windows))
}

fn parse_selected_with_case_policy(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    environment: &str,
    case_insensitive: bool,
) -> Result<PersonalOverrides, InvalidOverrides> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("the personal overrides are too large"));
    }
    let mut record: OverridesRecord = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("the personal overrides are malformed: {error}")))?;
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

fn validate_key(key: &str) -> Result<(), InvalidOverrides> {
    if !is_valid_variable_name(key) {
        return Err(invalid("the personal overrides name an invalid variable"));
    }
    if lpm_env::is_denied_env_var(key) {
        return Err(invalid(format!(
            "the personal overrides name {key}, which LPM never passes to a process"
        )));
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
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"NODE_OPTIONS":"--inspect"},"unset":[]}}}"#,
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
    fn records_larger_than_the_record_limit_are_rejected_before_parsing() {
        let oversized = vec![b' '; MAX_RECORD_BYTES + 1];
        assert!(parse_selected(&oversized, "proj", 1, "default").is_err());
    }
}
