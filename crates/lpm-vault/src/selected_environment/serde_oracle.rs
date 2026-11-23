//! The stored payload's rules as serde applies them: the oracle the
//! hand-written parser is tested against.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

use lpm_common::stored_env::{is_valid_environment_name, is_valid_variable_name};
use lpm_env::{DEFAULT_ENVIRONMENT, reads_default_environment};
use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, Visitor};

use super::SelectedVaultPayload;
use crate::{EnvironmentMap, SecretMap};

/// The payload's one field. A derived struct would also take the
/// positional `[{…}]`, which the stored format never is.
struct CompleteVaultPayloadVisitor;

impl<'de> Visitor<'de> for CompleteVaultPayloadVisitor {
    type Value = EnvironmentMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with exactly an environments field")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut environments = None;
        while let Some(field) = map.next_key::<Cow<'de, str>>()? {
            if field != "environments" {
                return Err(A::Error::unknown_field(&field, &["environments"]));
            }
            if environments.is_some() {
                return Err(A::Error::duplicate_field("environments"));
            }
            environments = Some(map.next_value_seed(EnvironmentMapSeed)?);
        }
        environments.ok_or_else(|| A::Error::missing_field("environments"))
    }
}

struct EnvironmentMapSeed;

impl<'de> DeserializeSeed<'de> for EnvironmentMapSeed {
    type Value = EnvironmentMap;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(EnvironmentMapVisitor)
    }
}

/// `parse_all` as serde parses it.
pub(super) fn parse_all_with_serde(json: &str) -> Result<EnvironmentMap, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let mut environments = deserializer.deserialize_map(CompleteVaultPayloadVisitor)?;
    deserializer.end()?;
    if environments.is_empty() {
        environments.insert(DEFAULT_ENVIRONMENT.to_owned(), HashMap::new());
    }
    Ok(environments)
}

struct EnvironmentMapVisitor;

impl<'de> Visitor<'de> for EnvironmentMapVisitor {
    type Value = EnvironmentMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an environment map with unique valid names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut environments = HashMap::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(environment) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_environment_name(&environment) {
                return Err(A::Error::custom(format!(
                    "environment name {environment:?} is invalid"
                )));
            }
            let secrets = map.next_value_seed(RetainedSecretMapSeed)?;
            if environments
                .insert(environment.clone().into_owned(), secrets)
                .is_some()
            {
                return Err(A::Error::custom(format!(
                    "duplicate environment name {environment:?}"
                )));
            }
        }
        Ok(environments)
    }
}

/// `parse` or, with `default_fallback`, `parse_with_default_fallback` as
/// serde parses it.
pub(super) fn parse_with_serde(
    json: &str,
    selected_environment: &str,
    default_fallback: bool,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let payload = SelectedPayloadSeed {
        selected_environment,
        default_fallback,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(payload)
}

struct SelectedPayloadSeed<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> DeserializeSeed<'de> for SelectedPayloadSeed<'_> {
    type Value = SelectedVaultPayload;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedPayloadVisitor {
            selected_environment: self.selected_environment,
            default_fallback: self.default_fallback,
        })
    }
}

struct SelectedPayloadVisitor<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> Visitor<'de> for SelectedPayloadVisitor<'_> {
    type Value = SelectedVaultPayload;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object containing exactly one environments map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut selected = None;
        let mut saw_environments = false;

        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key != "environments" {
                return Err(A::Error::unknown_field(&key, &["environments"]));
            }
            if saw_environments {
                return Err(A::Error::duplicate_field("environments"));
            }
            saw_environments = true;
            let parsed = map.next_value_seed(SelectedEnvironmentsSeed {
                selected_environment: self.selected_environment,
                default_fallback: self.default_fallback,
            })?;
            selected = if parsed.is_empty && self.selected_environment == DEFAULT_ENVIRONMENT {
                Some(HashMap::new())
            } else {
                parsed.selected
            };
        }

        if !saw_environments {
            return Err(A::Error::missing_field("environments"));
        }
        Ok(SelectedVaultPayload::Versioned(selected))
    }
}

struct SelectedEnvironments {
    selected: Option<SecretMap>,
    is_empty: bool,
}

struct SelectedEnvironmentsSeed<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> DeserializeSeed<'de> for SelectedEnvironmentsSeed<'_> {
    type Value = SelectedEnvironments;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedEnvironmentsVisitor {
            selected_environment: self.selected_environment,
            default_fallback: self.default_fallback,
        })
    }
}

struct SelectedEnvironmentsVisitor<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> Visitor<'de> for SelectedEnvironmentsVisitor<'_> {
    type Value = SelectedEnvironments;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an environment map")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        visit_selected_environments_map(map, self.selected_environment, self.default_fallback)
    }
}

fn visit_selected_environments_map<'de, A>(
    mut map: A,
    selected_environment: &str,
    default_fallback: bool,
) -> Result<SelectedEnvironments, A::Error>
where
    A: MapAccess<'de>,
{
    let mut selected = None;
    let mut fallback = None;
    let mut names = HashSet::with_capacity(map.size_hint().unwrap_or_default());
    while let Some(environment) = map.next_key::<Cow<'de, str>>()? {
        if !is_valid_environment_name(&environment) {
            return Err(A::Error::custom(format!(
                "environment name {environment:?} is invalid"
            )));
        }
        if !names.insert(environment.clone().into_owned()) {
            return Err(A::Error::custom(format!(
                "duplicate environment name {environment:?}"
            )));
        }
        if environment == selected_environment {
            selected = Some(map.next_value_seed(RetainedSecretMapSeed)?);
        } else if default_fallback && environment == DEFAULT_ENVIRONMENT {
            fallback = Some(map.next_value_seed(RetainedSecretMapSeed)?);
        } else {
            map.next_value_seed(ValidateSecretMapSeed)?;
        }
    }
    let selected = if default_fallback
        && reads_default_environment(
            selected_environment,
            selected.as_ref().is_some_and(|values| !values.is_empty()),
        ) {
        fallback
    } else {
        selected
    };
    Ok(SelectedEnvironments {
        selected,
        is_empty: names.is_empty(),
    })
}

struct RetainedSecretMapSeed;

impl<'de> DeserializeSeed<'de> for RetainedSecretMapSeed {
    type Value = SecretMap;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RetainedSecretMapVisitor)
    }
}

struct RetainedSecretMapVisitor;

impl<'de> Visitor<'de> for RetainedSecretMapVisitor {
    type Value = SecretMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret map containing unique valid variable names and string values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut secrets = HashMap::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(variable) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_variable_name(&variable) {
                return Err(A::Error::custom(format!(
                    "env variable name {variable:?} is invalid"
                )));
            }
            let value = map.next_value::<Cow<'de, str>>()?.into_owned();
            if secrets
                .insert(variable.clone().into_owned(), value)
                .is_some()
            {
                return Err(A::Error::custom(format!(
                    "duplicate env variable name {variable:?}"
                )));
            }
        }
        Ok(secrets)
    }
}

struct ValidateSecretMapSeed;

impl<'de> DeserializeSeed<'de> for ValidateSecretMapSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ValidateSecretMapVisitor)
    }
}

struct ValidateSecretMapVisitor;

impl<'de> Visitor<'de> for ValidateSecretMapVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret map containing string values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = HashSet::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(variable) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_variable_name(&variable) {
                return Err(A::Error::custom(format!(
                    "env variable name {variable:?} is invalid"
                )));
            }
            if !names.insert(variable.clone().into_owned()) {
                return Err(A::Error::custom(format!(
                    "duplicate env variable name {variable:?}"
                )));
            }
            map.next_value_seed(ValidateStringSeed)?;
        }
        Ok(())
    }
}

struct ValidateStringSeed;

impl<'de> DeserializeSeed<'de> for ValidateStringSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(ValidateStringVisitor)
    }
}

struct ValidateStringVisitor;

impl Visitor<'_> for ValidateStringVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string secret value")
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }
}
