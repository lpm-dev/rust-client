//! Schema types for environment variable validation.
//!
//! Parsed from the `envSchema` section of `lpm.json`.

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;

/// The full env schema: a map of variable names to their rules.
///
/// Deserialized from `lpm.json`:
/// ```json
/// { "envSchema": { "vars": { "DATABASE_URL": { "required": true, "format": "url" } } } }
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields)]
pub struct EnvSchema {
    #[serde(default, deserialize_with = "deserialize_unique_vars")]
    #[schemars(extend("propertyNames" = {"pattern": "^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 4096))]
    pub vars: HashMap<String, EnvVarRule>,
}

/// Validation rules for a single environment variable.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields)]
#[schemars(extend("allOf" = [{"if":{"properties":{"secret":{"const":true}},"required":["secret"]},"then":{"properties":{"default":{"type":"null"},"enum":{"type":"null"}}}}]))]
pub struct EnvVarRule {
    /// Whether the variable must be set and non-empty.
    #[serde(default)]
    pub required: bool,

    /// Built-in format validator.
    #[serde(default)]
    pub format: Option<VarFormat>,

    /// Rust regular expression the value must match.
    /// Use `^` and `$` to require a full-value match.
    #[serde(default)]
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub pattern: Option<String>,

    /// Allowlist of valid values.
    #[serde(default, rename = "enum")]
    #[schemars(length(min = 1))]
    #[schemars(extend("items" = {"type":"string", "pattern":r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"}))]
    pub enum_values: Option<Vec<String>>,

    /// Default value if not set. It must satisfy the same validation rules.
    #[serde(default)]
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub default: Option<String>,

    /// Whether this variable contains sensitive data (fully redacted in errors and logs).
    #[serde(default)]
    pub secret: bool,

    /// Whether this variable is safe for client-side exposure.
    #[serde(default)]
    pub client: bool,

    /// Human-readable description (shown in error messages and .env.example).
    #[serde(default)]
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub description: Option<String>,

    /// Treatment of an explicitly empty value. Missing preserves the child override.
    #[serde(default)]
    pub empty: EmptyPolicy,
}

/// Empty values can trigger defaults, remain subject to validation, or be rejected.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum EmptyPolicy {
    #[default]
    Missing,
    Allow,
    Reject,
}

fn deserialize_unique_vars<'de, D>(deserializer: D) -> Result<HashMap<String, EnvVarRule>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueVars;
    impl<'de> Visitor<'de> for UniqueVars {
        type Value = HashMap<String, EnvVarRule>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique environment variable names")
        }
        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut vars = HashMap::with_capacity(access.size_hint().unwrap_or(0).min(4096));
            while let Some((name, rule)) = access.next_entry::<String, EnvVarRule>()? {
                if vars.insert(name, rule).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate environment variable definition",
                    ));
                }
                if vars.len() > 4096 {
                    return Err(serde::de::Error::custom(
                        "envSchema exceeds 4096 variable definitions",
                    ));
                }
            }
            Ok(vars)
        }
    }
    deserializer.deserialize_map(UniqueVars)
}

/// Built-in format validators for common value types.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VarFormat {
    Url,
    Port,
    Email,
    Boolean,
    Integer,
    Hostname,
    Ip,
}

impl std::fmt::Display for VarFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Url => "url",
            Self::Port => "port",
            Self::Email => "email",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Hostname => "hostname",
            Self::Ip => "ip",
        })
    }
}

impl EnvVarRule {
    /// Whether this variable is a secret that should be redacted in output.
    pub fn is_secret(&self) -> bool {
        self.secret
    }
}

impl EnvSchema {
    /// Returns true if the schema has no variable definitions.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Returns the number of variables defined in the schema.
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Check if a given key is marked as `secret` in the schema.
    pub fn is_secret(&self, key: &str) -> bool {
        self.vars.get(key).is_some_and(|r| r.secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_rule() {
        let json = r#"{"required": true}"#;
        let rule: EnvVarRule = serde_json::from_str(json).unwrap();
        assert!(rule.required);
        assert!(rule.format.is_none());
        assert!(rule.pattern.is_none());
        assert!(rule.enum_values.is_none());
        assert!(rule.default.is_none());
        assert!(!rule.secret);
        assert!(!rule.client);
        assert!(rule.description.is_none());
    }

    #[test]
    fn deserialize_full_rule() {
        let json = r#"{
            "required": true,
            "format": "url",
            "pattern": "^postgres://.*$",
            "secret": true,
            "client": false,
            "description": "PostgreSQL connection string",
            "default": "postgres://localhost:5432/dev"
        }"#;
        let rule: EnvVarRule = serde_json::from_str(json).unwrap();
        assert!(rule.required);
        assert_eq!(rule.format, Some(VarFormat::Url));
        assert_eq!(rule.pattern.as_deref(), Some("^postgres://.*$"));
        assert!(rule.secret);
        assert!(!rule.client);
        assert_eq!(
            rule.description.as_deref(),
            Some("PostgreSQL connection string")
        );
        assert_eq!(
            rule.default.as_deref(),
            Some("postgres://localhost:5432/dev")
        );
    }

    #[test]
    fn deserialize_enum_rule() {
        let json = r#"{"enum": ["debug", "info", "warn", "error"], "default": "info"}"#;
        let rule: EnvVarRule = serde_json::from_str(json).unwrap();
        assert_eq!(
            rule.enum_values.as_deref(),
            Some(
                &[
                    "debug".to_string(),
                    "info".into(),
                    "warn".into(),
                    "error".into()
                ][..]
            )
        );
        assert_eq!(rule.default.as_deref(), Some("info"));
    }

    #[test]
    fn deserialize_all_formats() {
        for (json, expected) in [
            (r#""url""#, VarFormat::Url),
            (r#""port""#, VarFormat::Port),
            (r#""email""#, VarFormat::Email),
            (r#""boolean""#, VarFormat::Boolean),
            (r#""integer""#, VarFormat::Integer),
            (r#""hostname""#, VarFormat::Hostname),
            (r#""ip""#, VarFormat::Ip),
        ] {
            let format: VarFormat = serde_json::from_str(json).unwrap();
            assert_eq!(format, expected);
        }
    }

    #[test]
    fn deserialize_schema_from_lpm_json_fragment() {
        let json = r#"{
            "vars": {
                "DATABASE_URL": { "required": true, "format": "url", "secret": true },
                "PORT": { "default": "3000", "format": "port" },
                "LOG_LEVEL": { "enum": ["debug", "info", "warn", "error"], "default": "info" }
            }
        }"#;
        let schema: EnvSchema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.len(), 3);
        assert!(!schema.is_empty());
        assert!(schema.is_secret("DATABASE_URL"));
        assert!(!schema.is_secret("PORT"));
        assert!(!schema.is_secret("UNKNOWN_KEY"));
    }

    #[test]
    fn empty_schema() {
        let schema = EnvSchema::default();
        assert!(schema.is_empty());
        assert_eq!(schema.len(), 0);
        assert!(!schema.is_secret("anything"));
    }

    #[test]
    fn default_rule_is_permissive() {
        let rule = EnvVarRule::default();
        assert!(!rule.required);
        assert!(!rule.secret);
        assert!(!rule.client);
        assert!(rule.format.is_none());
        assert!(rule.pattern.is_none());
        assert!(rule.enum_values.is_none());
        assert!(rule.default.is_none());
        assert!(rule.description.is_none());
    }
    #[test]
    fn misspelled_secret_fields_are_rejected() {
        assert!(
            serde_json::from_str::<EnvSchema>(r#"{"vars":{"TOKEN":{"secert":true}}}"#).is_err()
        );
    }

    #[test]
    fn duplicate_variable_definitions_are_rejected() {
        assert!(
            serde_json::from_str::<EnvSchema>(
                r#"{"vars":{"TOKEN":{"secret":true},"TOKEN":{"secret":false}}}"#
            )
            .is_err()
        );
    }
    #[test]
    fn variable_limit_matches_the_generated_schema() {
        let generated = serde_json::to_value(schemars::schema_for!(EnvSchema)).unwrap();
        assert_eq!(generated["properties"]["vars"]["maxProperties"], 4096);
        for count in [4096, 4097] {
            let vars: std::collections::BTreeMap<_, _> = (0..count)
                .map(|index| (format!("V_{index}"), serde_json::json!({})))
                .collect();
            assert_eq!(
                serde_json::from_value::<EnvSchema>(serde_json::json!({"vars":vars})).is_ok(),
                count == 4096
            );
        }
    }
}

#[cfg(test)]
mod object_shape_tests {
    use super::*;
    #[test]
    fn schema_and_rules_require_json_objects() {
        for input in ["[]", "[{}]", r#"{"vars":{"VALUE":[]}}"#] {
            assert!(serde_json::from_str::<EnvSchema>(input).is_err(), "{input}");
        }
        assert!(serde_json::from_str::<EnvVarRule>("[]").is_err());
        assert!(serde_json::from_str::<EnvSchema>(r#"{"vars":{"VALUE":{}}}"#).is_ok());
    }
}

crate::object::object_only!(EnvSchema);
crate::object::object_only!(EnvVarRule);
