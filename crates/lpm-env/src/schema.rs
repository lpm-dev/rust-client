//! Schema types for environment variable validation.
//!
//! Parsed from the `envSchema` section of `lpm.json`.

use serde::de::{MapAccess, SeqAccess, Visitor};
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
    /// Additional browser-visible variable prefixes. Framework prefixes remain enforced.
    #[serde(
        default,
        rename = "clientPrefixes",
        deserialize_with = "deserialize_client_prefixes",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(length(max = 32))]
    #[schemars(extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^(?:_|[A-Za-z_][A-Za-z0-9_]{0,254}_)$"}))]
    pub client_prefixes: Vec<String>,
    /// Relationships between declared variables.
    #[serde(
        default,
        deserialize_with = "deserialize_unique_groups",
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[schemars(extend("propertyNames" = {"pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}, "maxProperties" = 128))]
    pub groups: HashMap<String, VarGroup>,
}

/// Validation rules for a single environment variable.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, remote = "Self")]
#[schemars(deny_unknown_fields)]
#[schemars(extend("allOf" = [{"if":{"properties":{"secret":{"const":true}},"required":["secret"]},"then":{"properties":{"default":{"type":"null"},"enum":{"type":"null"},"client":{"const":false},"ci":{"enum":["secret",null]}}}}]))]
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

    /// GitHub Actions storage classification, independent of browser visibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<CiStorage>,

    /// Inclusive exact integer bound. Serialized as decimal text for lossless metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bound",
        serialize_with = "serialize_bound",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Option<NumericBound>")]
    pub min: Option<i64>,
    /// Inclusive exact integer bound. Serialized as decimal text for lossless metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bound",
        serialize_with = "serialize_bound",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Option<NumericBound>")]
    pub max: Option<i64>,
    /// Minimum Unicode scalar count.
    #[serde(
        default,
        rename = "minLength",
        deserialize_with = "deserialize_length",
        serialize_with = "serialize_length",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Option<LengthBound>")]
    pub min_length: Option<u32>,
    /// Maximum Unicode scalar count.
    #[serde(
        default,
        rename = "maxLength",
        deserialize_with = "deserialize_length",
        serialize_with = "serialize_length",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Option<LengthBound>")]
    pub max_length: Option<u32>,
    /// Allowed lowercase URL schemes, without a colon.
    #[serde(
        default,
        deserialize_with = "deserialize_protocols",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(length(min = 1, max = 32))]
    #[schemars(extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^[a-z][a-z0-9+.-]{0,255}$"}))]
    pub protocols: Option<Vec<String>>,
    /// Require a nonempty value when another declared variable satisfies this predicate.
    #[serde(
        default,
        rename = "requiredWhen",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_when: Option<RequiredWhen>,

    /// Human-readable description (shown in error messages and .env.example).
    #[serde(default)]
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub description: Option<String>,

    /// Treatment of an explicitly empty value. Missing preserves the child override.
    #[serde(default)]
    pub empty: EmptyPolicy,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum NumericBound {
    Number(i64),
    Decimal(#[schemars(extend("pattern" = r"^[+-]?[0-9]{1,19}$"))] String),
}

fn deserialize_bound<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    Option::<NumericBound>::deserialize(deserializer)?
        .map(|bound| match bound {
            NumericBound::Number(value) => Ok(value),
            NumericBound::Decimal(text) => {
                let digits = text.strip_prefix(['+', '-']).unwrap_or(&text);
                if digits.is_empty()
                    || digits.len() > 19
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(serde::de::Error::custom(
                        "integer bound must be signed decimal text with at most 19 digits",
                    ));
                }
                text.parse().map_err(|_| {
                    serde::de::Error::custom("integer bound is outside the signed 64-bit range")
                })
            }
        })
        .transpose()
}

fn serialize_bound<S: serde::Serializer>(
    value: &Option<i64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum LengthBound {
    Number(u32),
    Decimal(#[schemars(extend("pattern" = r"^[0-9]{1,10}$"))] String),
}

fn deserialize_length<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u32>, D::Error> {
    Option::<LengthBound>::deserialize(deserializer)?
        .map(|bound| match bound {
            LengthBound::Number(value) => Ok(value),
            LengthBound::Decimal(text)
                if !text.is_empty()
                    && text.len() <= 10
                    && text.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                text.parse().map_err(|_| {
                    serde::de::Error::custom("length bound is outside the unsigned 32-bit range")
                })
            }
            LengthBound::Decimal(_) => Err(serde::de::Error::custom(
                "length bound must be decimal text with at most 10 digits",
            )),
        })
        .transpose()
}

fn serialize_length<S: serde::Serializer>(
    value: &Option<u32>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

/// Exactly one predicate is accepted. Presence means a nonempty effective value.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RequiredWhen {
    Equals(EqualityCondition),
    Present(PresenceCondition),
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EqualityCondition {
    #[schemars(extend("pattern" = "^[A-Za-z_][A-Za-z0-9_]{0,255}$"))]
    pub variable: String,
    #[schemars(extend("pattern" = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]*$"))]
    pub equals: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PresenceCondition {
    #[schemars(extend("pattern" = "^[A-Za-z_][A-Za-z0-9_]{0,255}$"))]
    pub variable: String,
    pub present: bool,
}

impl RequiredWhen {
    pub fn variable(&self) -> &str {
        match self {
            Self::Equals(condition) => &condition.variable,
            Self::Present(condition) => &condition.variable,
        }
    }
    pub fn matches(&self, values: &HashMap<String, String>) -> bool {
        match self {
            Self::Equals(condition) => values
                .get(&condition.variable)
                .is_some_and(|value| value == &condition.equals),
            Self::Present(condition) => {
                values
                    .get(&condition.variable)
                    .is_some_and(|value| !value.is_empty())
                    == condition.present
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VarGroup {
    pub mode: VarGroupMode,
    #[schemars(length(min = 1, max = 4096))]
    #[schemars(extend("uniqueItems" = true, "items" = {"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,255}$"}))]
    #[serde(deserialize_with = "deserialize_group_members")]
    pub vars: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum VarGroupMode {
    AllOrNone,
    ExactlyOne,
    AtLeastOne,
}

fn deserialize_unique_groups<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<String, VarGroup>, D::Error> {
    struct Groups;
    impl<'de> Visitor<'de> for Groups {
        type Value = HashMap<String, VarGroup>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .write_str("at most 128 unique variable groups with at most 4096 total members")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut groups = HashMap::with_capacity(access.size_hint().unwrap_or(0).min(128));
            let mut members = 0usize;
            while let Some(name) = access.next_key::<String>()? {
                if groups.contains_key(&name) {
                    return Err(serde::de::Error::custom("duplicate variable group"));
                }
                if groups.len() == 128 {
                    return Err(serde::de::Error::custom(
                        "envSchema group count exceeded 128",
                    ));
                }
                let group = access.next_value::<VarGroup>()?;
                if group.vars.len() > 4096 - members {
                    return Err(serde::de::Error::custom(
                        "envSchema group count or member budget exceeded",
                    ));
                }
                members += group.vars.len();
                if groups.insert(name, group).is_some() {
                    return Err(serde::de::Error::custom("duplicate variable group"));
                }
            }
            Ok(groups)
        }
    }
    deserializer.deserialize_map(Groups)
}

fn deserialize_group_members<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct Members;
    impl<'de> Visitor<'de> for Members {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 4096 group members")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut members = Vec::with_capacity(access.size_hint().unwrap_or(0).min(4096));
            for _ in 0..4096 {
                let Some(member) = access.next_element::<String>()? else {
                    return Ok(members);
                };
                members.push(member);
            }
            if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("groups exceed 4096 members"));
            }
            Ok(members)
        }
    }
    deserializer.deserialize_seq(Members)
}

fn deserialize_protocols<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    struct OptionalList;
    impl<'de> Visitor<'de> for OptionalList {
        type Value = Option<Vec<String>>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("null or at most 32 protocols")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserialize_client_prefixes(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(OptionalList)
}

/// Storage namespace used when synchronizing to GitHub Actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CiStorage {
    Secret,
    Variable,
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

fn deserialize_client_prefixes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Prefixes;
    impl<'de> Visitor<'de> for Prefixes {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 32 client prefixes")
        }
        fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut prefixes = Vec::with_capacity(access.size_hint().unwrap_or(0).min(32));
            while let Some(prefix) = access.next_element::<String>()? {
                if prefixes.len() == 32 {
                    return Err(serde::de::Error::custom(
                        "envSchema exceeds 32 client prefixes",
                    ));
                }
                prefixes.push(prefix);
            }
            Ok(prefixes)
        }
    }
    deserializer.deserialize_seq(Prefixes)
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

impl EnvVarRule {
    /// Whether this variable is a secret that should be redacted in output.
    pub fn is_secret(&self) -> bool {
        self.secret
    }
}

impl EnvSchema {
    /// Whether a name is public under a framework or project prefix.
    pub fn has_client_prefix(&self, name: &str) -> bool {
        Self::has_framework_client_prefix(name)
            || self
                .client_prefixes
                .iter()
                .take(32)
                .any(|prefix| name.starts_with(prefix))
    }

    pub(crate) fn has_framework_client_prefix(name: &str) -> bool {
        name.get(..10)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("REACT_APP_"))
            || [
                "NEXT_PUBLIC_",
                "VITE_",
                "PUBLIC_",
                "EXPO_PUBLIC_",
                "GATSBY_",
                "NUXT_PUBLIC_",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

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
    fn more_than_32_client_prefixes_are_rejected_during_parsing() {
        let input = serde_json::json!({"clientPrefixes": (0..33).map(|index| format!("CUSTOM_{index}_")).collect::<Vec<_>>()});
        assert!(serde_json::from_value::<EnvSchema>(input).is_err());
    }

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
