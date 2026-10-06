//! Authored schema definitions. Filesystem resolution belongs to lpm-env-source.

use crate::{EnvSchema, EnvVarRule, VarGroup};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A local schema document. Overrides replace complete inherited declarations.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields)]
pub struct EnvSchemaDefinition {
    /// Variable declarations authored in this document.
    #[serde(default, deserialize_with = "crate::schema::deserialize_unique_vars")]
    #[schemars(extend("propertyNames" = {"pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 4096))]
    pub vars: HashMap<String, EnvVarRule>,
    /// Additional public prefixes. Matching variables must declare client: true.
    #[serde(
        default,
        rename = "clientPrefixes",
        deserialize_with = "crate::schema::deserialize_client_prefixes",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(length(max = 32))]
    #[schemars(extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^(?:_|[A-Za-z_][A-Za-z0-9_]{0,254}_)$"}))]
    pub client_prefixes: Vec<String>,
    /// Relations between declared variables, checked against their effective values.
    #[serde(
        default,
        deserialize_with = "crate::schema::deserialize_unique_groups",
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[schemars(extend("propertyNames" = {"pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 128))]
    pub groups: HashMap<String, VarGroup>,
    /// Relative fragments or offline built-in presets: preset:node, preset:nextjs, preset:vite.
    #[serde(
        default,
        deserialize_with = "deserialize_extends",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(length(max = 32))]
    #[schemars(extend("uniqueItems" = true, "items" = {"type":"string","minLength":1,"maxLength":512}))]
    pub extends: Vec<String>,
    /// Complete replacement rules for variables inherited from imports.
    #[serde(
        default,
        deserialize_with = "crate::schema::deserialize_unique_vars",
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[schemars(extend("propertyNames" = {"pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 4096))]
    pub overrides: HashMap<String, EnvVarRule>,
    /// Complete replacement groups for relations inherited from imports.
    #[serde(
        default,
        rename = "groupOverrides",
        deserialize_with = "crate::schema::deserialize_unique_groups",
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[schemars(extend("propertyNames" = {"pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 128))]
    pub group_overrides: HashMap<String, VarGroup>,
}

crate::object::object_only!(EnvSchemaDefinition);

impl EnvSchemaDefinition {
    pub fn requires_resolution(&self) -> bool {
        !self.extends.is_empty() || !self.overrides.is_empty() || !self.group_overrides.is_empty()
    }

    pub fn local_schema(&self) -> EnvSchema {
        EnvSchema {
            vars: self.vars.clone(),
            client_prefixes: self.client_prefixes.clone(),
            groups: self.groups.clone(),
        }
    }
}

fn deserialize_extends<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct Imports;
    impl<'de> serde::de::Visitor<'de> for Imports {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 32 unique bounded schema imports")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(32));
            while let Some(value) = seq.next_element::<String>()? {
                if out.len() == 32
                    || value.is_empty()
                    || value.len() > 512
                    || value.chars().any(char::is_control)
                    || out.contains(&value)
                {
                    return Err(serde::de::Error::custom(
                        "invalid or repeated schema import",
                    ));
                }
                out.push(value);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Imports)
}

/// Presets are offline declarations without application credentials or defaults.
pub fn env_schema_preset(name: &str) -> Option<EnvSchemaDefinition> {
    if !matches!(name, "node" | "nextjs" | "vite") {
        return None;
    }
    let mut vars = HashMap::with_capacity(if name == "nextjs" { 2 } else { 1 });
    vars.insert(
        "NODE_ENV".into(),
        EnvVarRule {
            enum_values: Some(vec![
                "development".into(),
                "test".into(),
                "production".into(),
            ]),
            ..Default::default()
        },
    );
    if name == "nextjs" {
        vars.insert(
            "NEXT_RUNTIME".into(),
            EnvVarRule {
                enum_values: Some(vec!["nodejs".into(), "edge".into()]),
                ..Default::default()
            },
        );
    }
    if name != "node" {
        vars.remove("NODE_ENV");
    }
    Some(EnvSchemaDefinition {
        vars,
        extends: if name == "node" {
            Vec::new()
        } else {
            vec!["preset:node".into()]
        },
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_parser_rejects_unknown_duplicate_and_unbounded_imports() {
        for text in [
            r#"{"vars":{"A":{},"A":{}}}"#,
            r#"{"overrides":{"A":{},"A":{}}}"#,
            r#"{"extends":["a","a"]}"#,
            r#"{"extneds":[]}"#,
            r#"{"groupOverrides":null}"#,
            "[]",
            "[{}]",
            r#"{"vars":{"A":[]}}"#,
        ] {
            assert!(
                serde_json::from_str::<EnvSchemaDefinition>(text).is_err(),
                "{text}"
            );
        }
        let text =
            serde_json::json!({"extends": (0..33).map(|n| n.to_string()).collect::<Vec<_>>()});
        assert!(serde_json::from_value::<EnvSchemaDefinition>(text).is_err());
    }
    #[test]
    fn presets_contain_no_required_values_secrets_or_defaults() {
        for name in ["node", "nextjs", "vite"] {
            let schema = env_schema_preset(name).unwrap().local_schema();
            assert!(crate::validate_schema(&schema).is_empty());
            assert!(schema.vars.values().all(|r| !r.required
                && !r.secret
                && r.default.is_none()
                && r.defaults_in.is_empty()));
        }
        assert!(env_schema_preset("unknown").is_none());
    }
}

#[cfg(test)]
mod documentation_tests {
    #[test]
    fn authored_definition_fields_have_public_schema_descriptions() {
        let schema =
            serde_json::to_value(schemars::schema_for!(super::EnvSchemaDefinition)).unwrap();
        for field in [
            "vars",
            "clientPrefixes",
            "groups",
            "extends",
            "overrides",
            "groupOverrides",
        ] {
            let text = schema["properties"][field]["description"]
                .as_str()
                .unwrap_or_default();
            assert!(!text.is_empty(), "{field} lacks a description");
            assert!(!text.contains("versioned"));
        }
    }
}
