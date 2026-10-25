//! The feature marker: one open record per project naming the features its
//! companion records belong to, their versions, what a client that doesn't
//! support a version does, and the project's lifecycle state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::account::{is_valid_identifier, is_valid_kind};
use crate::graph::{self, SHARED_KEY_KIND};

pub const MARKER_SCHEMA_VERSION: u8 = 1;
pub const MAX_RECORD_BYTES: usize = 100 * 1024;
const MAX_FEATURES: usize = 16;
const MAX_KINDS_PER_FEATURE: usize = 8;

/// What a client that doesn't support a feature's version may do, from most
/// to least permissive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Level {
    Ignore,
    ReadOnly,
    Refuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectState {
    Active,
    Deleting,
    Discarding,
    Restoring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FeatureState {
    Active,
    Removing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RestorePhase {
    Staging,
    Activating,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureEntry {
    pub version: u16,
    pub if_unsupported: Level,
    pub kinds: Vec<String>,
    pub state: FeatureState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Restore {
    pub phase: RestorePhase,
    pub replaces: Vec<String>,
    #[serde(deserialize_with = "unique_features")]
    pub features: BTreeMap<String, FeatureEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Marker {
    pub schema_version: u8,
    pub vault_id: String,
    pub state: ProjectState,
    #[serde(deserialize_with = "unique_features")]
    pub features: BTreeMap<String, FeatureEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<Restore>,
}

/// Why a marker can't be used; any of these makes its project damaged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidMarker(pub String);

impl fmt::Display for InvalidMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn invalid(reason: impl Into<String>) -> InvalidMarker {
    InvalidMarker(reason.into())
}

impl Marker {
    pub fn empty(vault_id: &str, state: ProjectState) -> Self {
        Self {
            schema_version: MARKER_SCHEMA_VERSION,
            vault_id: vault_id.to_owned(),
            state,
            features: BTreeMap::new(),
            restore: None,
        }
    }

    /// Parse and validate the marker stored for `vault_id`.
    pub fn parse(vault_id: &str, bytes: &[u8]) -> Result<Self, InvalidMarker> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("the feature marker is too large"));
        }
        let marker: Self = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("the feature marker is malformed: {error}")))?;
        if marker.vault_id != vault_id {
            return Err(invalid("the feature marker names another env project"));
        }
        marker.validate()?;
        Ok(marker)
    }

    pub fn encode(&self) -> Result<Vec<u8>, InvalidMarker> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("the feature marker can't be encoded: {error}")))?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(invalid("the feature marker is too large"));
        }
        Ok(encoded)
    }

    pub fn validate(&self) -> Result<(), InvalidMarker> {
        if self.schema_version != MARKER_SCHEMA_VERSION {
            return Err(invalid("the feature marker's schema version is unknown"));
        }
        if !lpm_common::stored_env::is_safe_vault_id(&self.vault_id) {
            return Err(invalid("the feature marker's env project ID is invalid"));
        }
        validate_features(&self.features, false)?;
        match (&self.state, &self.restore) {
            (ProjectState::Restoring, Some(restore)) => self.validate_restore(restore),
            (ProjectState::Restoring, None) => Err(invalid(
                "a restoring feature marker must describe the restore",
            )),
            (_, Some(_)) => Err(invalid(
                "only a restoring feature marker describes a restore",
            )),
            (_, None) => Ok(()),
        }
    }

    fn validate_restore(&self, restore: &Restore) -> Result<(), InvalidMarker> {
        if restore.features.is_empty() {
            return Err(invalid("a restore must restore at least one feature"));
        }
        validate_features(&restore.features, true)?;
        if restore.replaces.len() > MAX_FEATURES {
            return Err(invalid("a restore replaces too many features"));
        }
        let mut replaces = BTreeSet::new();
        for name in &restore.replaces {
            if !self.features.contains_key(name) {
                return Err(invalid(format!(
                    "a restore replaces feature {name:?}, which the project doesn't have"
                )));
            }
            if !replaces.insert(name.as_str()) {
                return Err(invalid("a restore lists a replaced feature twice"));
            }
        }
        for name in restore.features.keys() {
            if self.features.contains_key(name) && !replaces.contains(name.as_str()) {
                return Err(invalid(format!(
                    "a restore of feature {name:?} must replace the project's own"
                )));
            }
        }
        let restores_key = restore
            .features
            .values()
            .any(|entry| entry.kinds.iter().any(|kind| kind == SHARED_KEY_KIND));
        if restores_key
            && self.features.iter().any(|(name, entry)| {
                entry.kinds.iter().any(|kind| kind == SHARED_KEY_KIND)
                    && !replaces.contains(name.as_str())
            })
        {
            return Err(invalid(
                "a restore of key-dependent data must replace every key-dependent feature",
            ));
        }
        validate_features(&self.post_restore_features(restore), false)
    }

    /// The features a restore leaves: the project's own without the replaced
    /// ones, plus the restored ones.
    pub fn post_restore_features(&self, restore: &Restore) -> BTreeMap<String, FeatureEntry> {
        let mut features = self.features.clone();
        for name in &restore.replaces {
            features.remove(name);
        }
        features.extend(
            restore
                .features
                .iter()
                .map(|(name, entry)| (name.clone(), entry.clone())),
        );
        features
    }

    /// Whether some feature entry lists `kind`, or, during a restore, some
    /// restored feature does, for staged records.
    pub fn lists_kind(&self, kind: &str) -> bool {
        self.features
            .values()
            .any(|entry| entry.kinds.iter().any(|listed| listed == kind))
    }

    pub fn restore_lists_kind(&self, kind: &str) -> bool {
        self.restore.as_ref().is_some_and(|restore| {
            restore
                .features
                .values()
                .any(|entry| entry.kinds.iter().any(|listed| listed == kind))
        })
    }

    /// The project's level: the strictest contribution of its features whose
    /// version this client doesn't support.
    pub fn level(&self) -> Level {
        self.features
            .iter()
            .filter_map(|(name, entry)| unsupported_contribution(name, entry))
            .max()
            .unwrap_or(Level::Ignore)
    }

    /// The first feature, by name, that contributes the project's level.
    pub fn strictest_unsupported(&self) -> Option<(&str, &FeatureEntry)> {
        let level = self.level();
        self.features
            .iter()
            .find(|(name, entry)| unsupported_contribution(name, entry) == Some(level))
            .map(|(name, entry)| (name.as_str(), entry))
    }

    pub fn feature(&self, name: &str) -> Option<&FeatureEntry> {
        self.features.get(name)
    }
}

/// What a feature contributes to its project's level, or `None` when this
/// client supports its version.
fn unsupported_contribution(name: &str, entry: &FeatureEntry) -> Option<Level> {
    match graph::known_feature(name) {
        Some(known) if known.supported_versions.contains(&entry.version) => None,
        Some(known) => Some(entry.if_unsupported.max(known.minimum)),
        None => Some(entry.if_unsupported),
    }
}

pub fn is_supported(name: &str, version: u16) -> bool {
    graph::known_feature(name).is_some_and(|known| known.supported_versions.contains(&version))
}

fn validate_features(
    features: &BTreeMap<String, FeatureEntry>,
    restored: bool,
) -> Result<(), InvalidMarker> {
    if features.len() > MAX_FEATURES {
        return Err(invalid("the feature marker lists too many features"));
    }
    let mut owners = BTreeMap::<&str, &str>::new();
    for (name, entry) in features {
        if !is_valid_identifier(name) {
            return Err(invalid("a feature name is invalid"));
        }
        if entry.version == 0 {
            return Err(invalid(format!("feature {name:?} has an invalid version")));
        }
        if restored && entry.state != FeatureState::Active {
            return Err(invalid(format!("restored feature {name:?} must be active")));
        }
        if entry.kinds.is_empty() || entry.kinds.len() > MAX_KINDS_PER_FEATURE {
            return Err(invalid(format!(
                "feature {name:?} lists an invalid number of kinds"
            )));
        }
        let mut listed = BTreeSet::new();
        for kind in &entry.kinds {
            if !is_valid_kind(kind) {
                return Err(invalid(format!("feature {name:?} lists an invalid kind")));
            }
            if !listed.insert(kind.as_str()) {
                return Err(invalid(format!(
                    "feature {name:?} lists kind {kind:?} twice"
                )));
            }
            if let Some(owner) = graph::reserved_owner(kind)
                && owner != name
            {
                return Err(invalid(format!(
                    "feature {name:?} lists kind {kind:?}, which only {owner:?} may list"
                )));
            }
            if kind != SHARED_KEY_KIND
                && let Some(other) = owners.insert(kind, name)
            {
                return Err(invalid(format!(
                    "features {other:?} and {name:?} both list kind {kind:?}"
                )));
            }
        }
        if is_supported(name, entry.version)
            && let Some(known) = graph::known_feature(name)
            && (entry.kinds.len() != known.kinds.len()
                || !known.kinds.iter().all(|kind| listed.contains(kind)))
        {
            return Err(invalid(format!(
                "feature {name:?} doesn't list exactly its records"
            )));
        }
    }
    Ok(())
}

fn unique_features<'de, D>(deserializer: D) -> Result<BTreeMap<String, FeatureEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
}

/// A JSON object read into a map, refusing a repeated key instead of keeping
/// the last value.
pub struct UniqueMapVisitor<V>(pub std::marker::PhantomData<V>);

impl<'de, V: Deserialize<'de>> Visitor<'de> for UniqueMapVisitor<V> {
    type Value = BTreeMap<String, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object without repeated keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if entries.contains_key(&key) {
                return Err(A::Error::custom(format!("repeated key {key:?}")));
            }
            entries.insert(key, value);
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(version: u16, level: Level, kinds: &[&str]) -> FeatureEntry {
        FeatureEntry {
            version,
            if_unsupported: level,
            kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
            state: FeatureState::Active,
        }
    }

    fn marker(features: &[(&str, FeatureEntry)]) -> Marker {
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features = features
            .iter()
            .map(|(name, entry)| ((*name).to_owned(), entry.clone()))
            .collect();
        marker
    }

    #[test]
    fn a_marker_round_trips_through_its_exact_json() {
        let json = br#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;
        let parsed = Marker::parse("proj", json).expect("valid marker");
        assert_eq!(parsed.encode().expect("encode"), json.to_vec());
    }

    #[test]
    fn markers_with_unknown_repeated_or_missing_fields_are_invalid() {
        for json in [
            r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{},"extra":1}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","vaultId":"proj","state":"active","features":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","features":{}}"#,
            r#"{"schemaVersion":2,"vaultId":"proj","state":"active","features":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"other","state":"active","features":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","state":"paused","features":{}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"},"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"]}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":0,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#,
            r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":70000,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#,
        ] {
            assert!(Marker::parse("proj", json.as_bytes()).is_err(), "{json}");
        }
    }

    #[test]
    fn a_supported_version_must_list_exactly_its_records() {
        assert!(
            marker(&[("overrides", entry(1, Level::Refuse, &["overrides"]))])
                .validate()
                .is_ok()
        );
        assert!(
            marker(&[(
                "overrides",
                entry(1, Level::Refuse, &["overrides", "extra"])
            )])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn an_unsupported_version_of_a_known_feature_may_add_a_kind() {
        let marker = marker(&[(
            "overrides",
            entry(2, Level::Ignore, &["overrides", "overrides-index"]),
        )]);
        assert!(marker.validate().is_ok());
        assert_eq!(marker.level(), Level::Refuse);
    }

    #[test]
    fn unknown_features_cannot_claim_known_kinds_but_may_share_key() {
        for kind in [
            "overrides",
            "history",
            "history-head",
            "releases",
            "releases-head",
            "meta",
            "notes",
        ] {
            assert!(
                marker(&[("future", entry(1, Level::Ignore, &[kind]))])
                    .validate()
                    .is_err(),
                "{kind}"
            );
        }
        assert!(
            marker(&[
                (
                    "history",
                    entry(1, Level::Ignore, &["history-head", "history", "key"])
                ),
                ("future", entry(1, Level::Ignore, &["future-log", "key"])),
            ])
            .validate()
            .is_ok()
        );
        assert!(
            marker(&[
                ("alpha", entry(1, Level::Ignore, &["shared"])),
                ("beta", entry(1, Level::Ignore, &["shared"])),
            ])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn feature_names_follow_the_identifier_grammar() {
        for name in [
            "",
            "Over",
            "a\u{1b}[31m",
            "na\u{202e}me",
            "é",
            &"a".repeat(33),
        ] {
            assert!(
                marker(&[(name, entry(1, Level::Ignore, &["thing"]))])
                    .validate()
                    .is_err(),
                "{name:?}"
            );
        }
        let longest = format!("a{}", "b".repeat(31));
        assert!(
            marker(&[(&longest, entry(1, Level::Ignore, &["thing"]))])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn the_project_level_is_the_strictest_unsupported_contribution() {
        let cases = [
            (vec![], Level::Ignore),
            (
                vec![("overrides", entry(1, Level::Ignore, &["overrides"]))],
                Level::Ignore,
            ),
            (
                vec![("overrides", entry(2, Level::Ignore, &["overrides"]))],
                Level::Refuse,
            ),
            (
                vec![(
                    "history",
                    entry(1, Level::Ignore, &["history-head", "history", "key"]),
                )],
                Level::Ignore,
            ),
            (
                vec![(
                    "history",
                    entry(1, Level::ReadOnly, &["history-head", "history", "key"]),
                )],
                Level::ReadOnly,
            ),
            (
                vec![("future", entry(3, Level::ReadOnly, &["thing"]))],
                Level::ReadOnly,
            ),
            (
                vec![
                    ("future", entry(3, Level::ReadOnly, &["thing"])),
                    ("later", entry(1, Level::Ignore, &["other"])),
                ],
                Level::ReadOnly,
            ),
            (
                vec![
                    ("future", entry(3, Level::ReadOnly, &["thing"])),
                    ("overrides", entry(5, Level::Ignore, &["overrides"])),
                ],
                Level::Refuse,
            ),
        ];
        for (features, expected) in cases {
            let marker = marker(&features);
            marker.validate().expect("valid marker");
            assert_eq!(marker.level(), expected, "{features:?}");
        }
    }

    #[test]
    fn a_restore_must_replace_what_it_restores_and_leave_a_valid_post_state() {
        let mut base = marker(&[(
            "history",
            entry(1, Level::Ignore, &["history-head", "history", "key"]),
        )]);
        base.state = ProjectState::Restoring;
        base.restore = Some(Restore {
            phase: RestorePhase::Staging,
            replaces: vec!["history".to_owned()],
            features: [(
                "history".to_owned(),
                entry(1, Level::Ignore, &["history-head", "history", "key"]),
            )]
            .into(),
        });
        assert!(base.validate().is_ok());

        let mut missing_replace = base.clone();
        missing_replace.restore.as_mut().unwrap().replaces.clear();
        assert!(missing_replace.validate().is_err());

        let mut key_conflict = base.clone();
        key_conflict.features.insert(
            "releases".to_owned(),
            entry(1, Level::Ignore, &["releases-head", "releases", "key"]),
        );
        assert!(key_conflict.validate().is_err());

        let mut nested = base.clone();
        nested
            .restore
            .as_mut()
            .unwrap()
            .features
            .get_mut("history")
            .unwrap()
            .state = FeatureState::Removing;
        assert!(nested.validate().is_err());

        let mut unexpected = base.clone();
        unexpected.state = ProjectState::Active;
        assert!(unexpected.validate().is_err());

        let mut absent = base.clone();
        absent.restore = None;
        assert!(absent.validate().is_err());

        let mut unknown_replace = base;
        unknown_replace
            .restore
            .as_mut()
            .unwrap()
            .replaces
            .push("overrides".to_owned());
        assert!(unknown_replace.validate().is_err());
    }
}
