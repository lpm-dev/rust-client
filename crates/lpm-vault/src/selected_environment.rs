use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, Visitor};

use crate::{EnvironmentMap, SecretMap};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteVaultPayload {
    #[serde(deserialize_with = "deserialize_environment_map")]
    environments: EnvironmentMap,
}

pub(crate) fn parse_all(json: &str) -> Result<EnvironmentMap, serde_json::Error> {
    let payload = serde_json::from_str::<CompleteVaultPayload>(json)?;
    let mut environments = payload.environments;
    if environments.is_empty() {
        environments.insert("default".to_owned(), HashMap::new());
    }
    Ok(environments)
}

fn deserialize_environment_map<'de, D>(deserializer: D) -> Result<EnvironmentMap, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(EnvironmentMapVisitor)
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

pub(crate) fn serialize(environments: &EnvironmentMap) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct BorrowedPayload<'a> {
        environments: &'a EnvironmentMap,
    }

    validate_environments(environments)?;
    if environments.is_empty() {
        return Ok(r#"{"environments":{"default":{}}}"#.to_owned());
    }
    serde_json::to_string(&BorrowedPayload { environments })
        .map_err(|error| format!("failed to serialize environments: {error}"))
}

pub(crate) fn is_valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "__index__"
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_valid_variable_name(name: &str) -> bool {
    let Some(first) = name.bytes().next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && name
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn parse(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    parse_with_optional_fallback(json, selected_environment, None)
}

pub(crate) fn parse_with_default_fallback(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    parse_with_optional_fallback(json, selected_environment, Some("default"))
}

fn parse_with_optional_fallback(
    json: &str,
    selected_environment: &str,
    fallback_environment: Option<&str>,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let payload = SelectedPayloadSeed {
        selected_environment,
        fallback_environment,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(payload)
}

struct SelectedPayloadSeed<'selection> {
    selected_environment: &'selection str,
    fallback_environment: Option<&'selection str>,
}

impl<'de> DeserializeSeed<'de> for SelectedPayloadSeed<'_> {
    type Value = SelectedVaultPayload;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedPayloadVisitor {
            selected_environment: self.selected_environment,
            fallback_environment: self.fallback_environment,
        })
    }
}

struct SelectedPayloadVisitor<'selection> {
    selected_environment: &'selection str,
    fallback_environment: Option<&'selection str>,
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
                fallback_environment: self.fallback_environment,
            })?;
            selected = if parsed.is_empty && self.selected_environment == "default" {
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
    fallback_environment: Option<&'selection str>,
}

impl<'de> DeserializeSeed<'de> for SelectedEnvironmentsSeed<'_> {
    type Value = SelectedEnvironments;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedEnvironmentsVisitor {
            selected_environment: self.selected_environment,
            fallback_environment: self.fallback_environment,
        })
    }
}

struct SelectedEnvironmentsVisitor<'selection> {
    selected_environment: &'selection str,
    fallback_environment: Option<&'selection str>,
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
        visit_selected_environments_map(map, self.selected_environment, self.fallback_environment)
    }
}

fn visit_selected_environments_map<'de, A>(
    mut map: A,
    selected_environment: &str,
    fallback_environment: Option<&str>,
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
        } else if fallback_environment.is_some_and(|fallback| environment == fallback) {
            fallback = Some(map.next_value_seed(RetainedSecretMapSeed)?);
        } else {
            map.next_value_seed(ValidateSecretMapSeed)?;
        }
    }
    let selected = if fallback_environment.is_some_and(|fallback| fallback != selected_environment)
        && selected.as_ref().is_none_or(HashMap::is_empty)
    {
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

#[cfg(test)]
mod tests {
    use super::*;

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

        assert!(error.to_string().contains("string secret value"), "{error}");
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
