//! The record's rules as serde applies them: the oracle the reader is tested
//! against. A derived struct also takes the positional array forms, which
//! the reader refuses, as the record's format is objects only.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use super::{EntryNames, InvalidOverrides, PersonalOverrides, invalid, validate_environment};
use crate::marker::{MAX_RECORD_BYTES, UniqueMapVisitor};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SerdeRecord {
    schema_version: u16,
    vault_id: String,
    #[serde(deserialize_with = "unique_environments")]
    environments: BTreeMap<String, SerdeEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerdeEntry {
    #[serde(deserialize_with = "unique_values")]
    set: BTreeMap<String, String>,
    unset: Vec<String>,
}

fn unique_environments<'de, D>(deserializer: D) -> Result<BTreeMap<String, SerdeEntry>, D::Error>
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

/// Every environment's overrides, read by serde and judged by the record's
/// rules.
pub(super) fn parse_all_with_serde(
    bytes: &[u8],
    vault_id: &str,
    version: u16,
    case_insensitive: bool,
) -> Result<BTreeMap<String, PersonalOverrides>, InvalidOverrides> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("the personal overrides are too large"));
    }
    let record: SerdeRecord = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the personal overrides are malformed"))?;
    if record.schema_version != version {
        return Err(invalid(
            "the personal overrides' version differs from the feature marker's",
        ));
    }
    if record.vault_id != vault_id {
        return Err(invalid("the personal overrides name another env project"));
    }
    for (name, entry) in &record.environments {
        let names = EntryNames {
            set: entry
                .set
                .iter()
                .map(|(key, value)| (Cow::Borrowed(key.as_str()), value.contains('\0')))
                .collect(),
            unset: entry.unset.clone(),
        };
        validate_environment(name, &names, case_insensitive)?;
    }
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
