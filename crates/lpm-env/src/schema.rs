//! Schema types for environment variable validation.
//!
//! Parsed from the `env.schema` section of `lpm.json`.

use serde::Deserialize;
use std::collections::HashMap;

/// The full env schema: a map of variable names to their rules.
///
/// Deserialized from `lpm.json`:
/// ```json
/// { "env": { "schema": { "DATABASE_URL": { "required": true, "format": "url" } } } }
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvSchema {
    #[serde(default)]
    pub vars: HashMap<String, EnvVarRule>,
}

/// Validation rules for a single environment variable.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvVarRule {
    /// Whether the variable must be set and non-empty.
    #[serde(default)]
    pub required: bool,

    /// Built-in format validator.
    #[serde(default)]
    pub format: Option<VarFormat>,

    /// Regex pattern the value must match.
    #[serde(default)]
    pub pattern: Option<String>,

    /// Allowlist of valid values.
    #[serde(default, rename = "enum")]
    pub enum_values: Option<Vec<String>>,

    /// Default value if not set (injected at runtime, not written to files).
    #[serde(default)]
    pub default: Option<String>,

    /// Whether this variable contains sensitive data (redacted in logs).
    #[serde(default)]
    pub secret: bool,

    /// Whether this variable is safe for client-side exposure.
    #[serde(default)]
    pub client: bool,

    /// Human-readable description (shown in error messages and .env.example).
    #[serde(default)]
    pub description: Option<String>,
}

/// Built-in format validators for common value types.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
            "pattern": "postgres://.*",
            "secret": true,
            "client": false,
            "description": "PostgreSQL connection string",
            "default": "postgres://localhost:5432/dev"
        }"#;
        let rule: EnvVarRule = serde_json::from_str(json).unwrap();
        assert!(rule.required);
        assert_eq!(rule.format, Some(VarFormat::Url));
        assert_eq!(rule.pattern.as_deref(), Some("postgres://.*"));
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
}
