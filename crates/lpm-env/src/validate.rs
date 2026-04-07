//! Pure validation engine for environment variables against a schema.
//!
//! Takes `(schema, env_map)` → `Vec<ValidationError>`. No side effects.

use crate::schema::{EnvSchema, EnvVarRule, VarFormat};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A single validation error for one environment variable.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// The variable name that failed validation.
    pub key: String,
    /// What went wrong.
    pub kind: ValidationErrorKind,
    /// The variable's description from the schema (if any).
    pub description: Option<String>,
    /// Whether this variable is marked as secret.
    pub is_secret: bool,
}

/// The specific validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErrorKind {
    /// Required variable is not set (or is empty).
    Missing,
    /// Value doesn't match the expected format.
    InvalidFormat { expected: VarFormat, got: String },
    /// Value doesn't match the regex pattern.
    PatternMismatch { pattern: String, got: String },
    /// Value is not in the allowed enum list.
    NotInEnum { allowed: Vec<String>, got: String },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ValidationErrorKind::Missing => {
                write!(f, "{}: missing (required)", self.key)?;
                if let Some(desc) = &self.description {
                    write!(f, " — {desc}")?;
                }
            }
            ValidationErrorKind::InvalidFormat { expected, got } => {
                let display_value = if self.is_secret {
                    redact_value(got)
                } else {
                    got.clone()
                };
                write!(
                    f,
                    "{}: invalid format, expected {expected:?}, got \"{display_value}\"",
                    self.key
                )?;
            }
            ValidationErrorKind::PatternMismatch { pattern, got } => {
                let display_value = if self.is_secret {
                    redact_value(got)
                } else {
                    got.clone()
                };
                write!(
                    f,
                    "{}: must match pattern `{pattern}`, got \"{display_value}\"",
                    self.key
                )?;
            }
            ValidationErrorKind::NotInEnum { allowed, got } => {
                let display_value = if self.is_secret {
                    redact_value(got)
                } else {
                    got.clone()
                };
                write!(
                    f,
                    "{}: must be one of [{}], got \"{display_value}\"",
                    self.key,
                    allowed.join(", ")
                )?;
            }
        }
        Ok(())
    }
}

/// Redact a secret value for display: show first 4 and last 3 chars if long enough.
fn redact_value(value: &str) -> String {
    if value.len() > 10 {
        let start = &value[..4];
        let end = &value[value.len() - 3..];
        format!("{start}...{end}")
    } else {
        "••••••".to_string()
    }
}

/// Validate environment variables against a schema.
///
/// This is the core validation function — synchronous, pure, no side effects.
/// Returns an empty `Vec` if all validations pass.
///
/// **Default injection:** if a variable is not set but has a `default` in the schema,
/// the default is injected into `env_vars` (mutated in place) and no error is raised.
pub fn validate(
    schema: &EnvSchema,
    env_vars: &mut HashMap<String, String>,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Sort keys for deterministic output order
    let mut keys: Vec<&String> = schema.vars.keys().collect();
    keys.sort();

    for key in keys {
        let rule = &schema.vars[key];

        // Check if the variable is set
        let value = env_vars.get(key.as_str());

        let is_missing_or_empty = value.is_none() || value.is_some_and(|v| v.is_empty());

        if is_missing_or_empty {
            if let Some(default) = &rule.default {
                env_vars.insert(key.clone(), default.clone());
            } else if rule.required {
                errors.push(ValidationError {
                    key: key.clone(),
                    kind: ValidationErrorKind::Missing,
                    description: rule.description.clone(),
                    is_secret: rule.secret,
                });
            }
        } else if let Some(value) = value {
            validate_value(key, value, rule, &mut errors);
        }
    }

    errors
}

/// Validate a single value against its rule.
fn validate_value(key: &str, value: &str, rule: &EnvVarRule, errors: &mut Vec<ValidationError>) {
    // Format validation
    if let Some(format) = &rule.format
        && !validate_format(value, format)
    {
        errors.push(ValidationError {
            key: key.to_string(),
            kind: ValidationErrorKind::InvalidFormat {
                expected: format.clone(),
                got: value.to_string(),
            },
            description: rule.description.clone(),
            is_secret: rule.secret,
        });
        // Don't check further rules if format is wrong
        return;
    }

    // Pattern validation (simple glob-like matching, not full regex)
    if let Some(pattern) = &rule.pattern
        && !matches_pattern(value, pattern)
    {
        errors.push(ValidationError {
            key: key.to_string(),
            kind: ValidationErrorKind::PatternMismatch {
                pattern: pattern.clone(),
                got: value.to_string(),
            },
            description: rule.description.clone(),
            is_secret: rule.secret,
        });
        return;
    }

    // Enum validation
    if let Some(allowed) = &rule.enum_values
        && !allowed.iter().any(|a| a == value)
    {
        errors.push(ValidationError {
            key: key.to_string(),
            kind: ValidationErrorKind::NotInEnum {
                allowed: allowed.clone(),
                got: value.to_string(),
            },
            description: rule.description.clone(),
            is_secret: rule.secret,
        });
    }
}

/// Validate a value against a built-in format.
fn validate_format(value: &str, format: &VarFormat) -> bool {
    match format {
        VarFormat::Url => validate_url(value),
        VarFormat::Port => validate_port(value),
        VarFormat::Email => validate_email(value),
        VarFormat::Boolean => validate_boolean(value),
        VarFormat::Integer => validate_integer(value),
        VarFormat::Hostname => validate_hostname(value),
        VarFormat::Ip => validate_ip(value),
    }
}

/// URL: must start with a scheme (http://, https://, postgres://, etc.) and have a host.
///
/// This is a heuristic check, not a strict RFC 3986 parser. It catches the
/// common mistakes (missing scheme, empty host) without rejecting exotic but
/// technically valid URIs. Acceptable trade-off for dev tooling.
fn validate_url(value: &str) -> bool {
    // Must have scheme://host at minimum
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    // Scheme must be non-empty and alphabetic (with optional + - .)
    if scheme.is_empty() || !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return false;
    }
    // Must have non-empty host portion
    let host = rest.split('/').next().unwrap_or("");
    let host = host.split('?').next().unwrap_or(host);
    let host = host.split('#').next().unwrap_or(host);
    // Strip userinfo (user:pass@host)
    let host = host.rsplit('@').next().unwrap_or(host);
    // Strip port
    let host_only = if host.starts_with('[') {
        // IPv6: [::1]:8080
        host.split(']').next().unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    !host_only.is_empty()
}

/// Port: must be a number between 1 and 65535.
fn validate_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Email: must contain exactly one `@` with non-empty local and domain parts.
fn validate_email(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(3, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Boolean: must be one of the standard boolean string representations.
fn validate_boolean(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no"
    )
}

/// Integer: must parse as i64.
fn validate_integer(value: &str) -> bool {
    value.parse::<i64>().is_ok()
}

/// Hostname: alphanumeric + hyphens + dots, each label 1-63 chars, total ≤ 253.
fn validate_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// IP: must be a valid IPv4 or IPv6 address.
fn validate_ip(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok() || value.parse::<Ipv6Addr>().is_ok()
}

/// Simple pattern matching with `*` wildcards.
///
/// Supports `*` as a wildcard matching any sequence of characters, and `.*` for
/// regex-like "any chars" patterns. This is NOT full regex — it's deliberately
/// simple to avoid pulling in the `regex` crate (which adds ~1MB to the binary).
///
/// For complex patterns, the `*` wildcard covers the most common use cases:
/// - `sk_(test|live)_*` — matches `sk_test_abc123` or `sk_live_xyz`
/// - `postgres://*` — matches any postgres URL
/// - `*.example.com` — matches subdomains
///
/// Parenthesized alternation `(a|b)` is supported, including multiple groups:
/// `(api|app)_key_(v1|v2)` expands via recursive calls. Nested parens `((a))` are
/// NOT supported — the parser finds the first `(` and first `)` after it.
fn matches_pattern(value: &str, pattern: &str) -> bool {
    // Handle alternation groups: `sk_(test|live)_*`
    if let Some(start) = pattern.find('(')
        && let Some(end) = pattern[start..].find(')')
    {
        let prefix = &pattern[..start];
        let group = &pattern[start + 1..start + end];
        let suffix = &pattern[start + end + 1..];
        let alternatives: Vec<&str> = group.split('|').collect();
        return alternatives
            .iter()
            .any(|alt| matches_pattern(value, &format!("{prefix}{alt}{suffix}")));
    }

    // Simple glob matching with `*`
    glob_match(value, pattern)
}

/// Glob-style matching: `*` matches any sequence of characters.
fn glob_match(value: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcards — exact match
        return value == pattern;
    }

    let mut pos = 0;

    // First part must be a prefix
    if !parts[0].is_empty() {
        if !value.starts_with(parts[0]) {
            return false;
        }
        pos = parts[0].len();
    }

    // Last part must be a suffix
    let last = parts[parts.len() - 1];
    if !last.is_empty() {
        if !value.ends_with(last) {
            return false;
        }
        // Ensure we don't overlap with the prefix
        if value.len() < pos + last.len() {
            return false;
        }
    }

    // Middle parts must appear in order
    for &part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EnvSchema;

    fn schema_from_json(json: &str) -> EnvSchema {
        serde_json::from_str(json).unwrap()
    }

    // ── Missing / Required ──

    #[test]
    fn missing_required_var_is_error() {
        let schema = schema_from_json(r#"{"vars": {"DATABASE_URL": {"required": true}}}"#);
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key, "DATABASE_URL");
        assert_eq!(errors[0].kind, ValidationErrorKind::Missing);
    }

    #[test]
    fn missing_optional_var_is_ok() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"required": false}}}"#);
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
    }

    #[test]
    fn empty_required_var_is_error() {
        let schema = schema_from_json(r#"{"vars": {"KEY": {"required": true}}}"#);
        let mut env = HashMap::from([("KEY".into(), "".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, ValidationErrorKind::Missing);
    }

    #[test]
    fn present_required_var_is_ok() {
        let schema = schema_from_json(r#"{"vars": {"KEY": {"required": true}}}"#);
        let mut env = HashMap::from([("KEY".into(), "value".into())]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
    }

    // ── Defaults ──

    #[test]
    fn default_injected_when_missing() {
        let schema =
            schema_from_json(r#"{"vars": {"PORT": {"default": "3000", "format": "port"}}}"#);
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
        assert_eq!(env.get("PORT").unwrap(), "3000");
    }

    #[test]
    fn default_injected_when_empty() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"default": "3000"}}}"#);
        let mut env = HashMap::from([("PORT".into(), "".into())]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
        assert_eq!(env.get("PORT").unwrap(), "3000");
    }

    #[test]
    fn default_not_injected_when_set() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"default": "3000"}}}"#);
        let mut env = HashMap::from([("PORT".into(), "8080".into())]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
        assert_eq!(env.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn required_with_default_does_not_error_when_missing() {
        let schema =
            schema_from_json(r#"{"vars": {"PORT": {"required": true, "default": "3000"}}}"#);
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
        assert_eq!(env.get("PORT").unwrap(), "3000");
    }

    // ── Format: URL ──

    #[test]
    fn valid_urls() {
        for url in [
            "http://localhost",
            "https://example.com",
            "postgres://user:pass@host:5432/db",
            "redis://localhost:6379",
            "http://[::1]:8080/path",
            "https://sub.domain.example.com/path?q=1#frag",
        ] {
            assert!(validate_url(url), "should be valid: {url}");
        }
    }

    #[test]
    fn invalid_urls() {
        for url in ["", "not-a-url", "://missing-scheme", "http://"] {
            assert!(!validate_url(url), "should be invalid: {url}");
        }
    }

    #[test]
    fn format_url_validation() {
        let schema = schema_from_json(r#"{"vars": {"URL": {"format": "url"}}}"#);
        let mut env = HashMap::from([("URL".into(), "not-a-url".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::InvalidFormat {
                expected: VarFormat::Url,
                ..
            }
        ));
    }

    // ── Format: Port ──

    #[test]
    fn valid_ports() {
        for port in ["1", "80", "443", "3000", "8080", "65535"] {
            assert!(validate_port(port), "should be valid: {port}");
        }
    }

    #[test]
    fn invalid_ports() {
        for port in ["0", "65536", "-1", "abc", "", "3.14", "3000 "] {
            assert!(!validate_port(port), "should be invalid: {port}");
        }
    }

    // ── Format: Email ──

    #[test]
    fn valid_emails() {
        for email in [
            "user@example.com",
            "admin@sub.domain.org",
            "test+tag@gmail.com",
        ] {
            assert!(validate_email(email), "should be valid: {email}");
        }
    }

    #[test]
    fn invalid_emails() {
        for email in [
            "",
            "@",
            "user@",
            "@domain.com",
            "nodomain@test",
            "two@@at.com",
        ] {
            assert!(!validate_email(email), "should be invalid: {email}");
        }
    }

    // ── Format: Boolean ──

    #[test]
    fn valid_booleans() {
        for b in [
            "true", "false", "TRUE", "False", "1", "0", "yes", "no", "YES", "No",
        ] {
            assert!(validate_boolean(b), "should be valid: {b}");
        }
    }

    #[test]
    fn invalid_booleans() {
        for b in ["", "maybe", "2", "on", "off", "yep"] {
            assert!(!validate_boolean(b), "should be invalid: {b}");
        }
    }

    // ── Format: Integer ──

    #[test]
    fn valid_integers() {
        for i in ["0", "42", "-1", "9999999", "-0"] {
            assert!(validate_integer(i), "should be valid: {i}");
        }
    }

    #[test]
    fn invalid_integers() {
        for i in ["", "3.14", "abc", "1e5", "1,000"] {
            assert!(!validate_integer(i), "should be invalid: {i}");
        }
    }

    // ── Format: Hostname ──

    #[test]
    fn valid_hostnames() {
        for h in [
            "localhost",
            "example.com",
            "sub.domain.example.com",
            "my-host",
            "a",
        ] {
            assert!(validate_hostname(h), "should be valid: {h}");
        }
    }

    #[test]
    fn invalid_hostnames() {
        for h in [
            "",
            "-start.com",
            "end-.com",
            "has space.com",
            ".leading.dot",
        ] {
            assert!(!validate_hostname(h), "should be invalid: {h}");
        }
    }

    // ── Format: IP ──

    #[test]
    fn valid_ips() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "192.168.1.1",
            "::1",
            "::ffff:192.168.1.1",
            "2001:db8::1",
        ] {
            assert!(validate_ip(ip), "should be valid: {ip}");
        }
    }

    #[test]
    fn invalid_ips() {
        for ip in ["", "999.999.999.999", "abc", "localhost", "192.168.1"] {
            assert!(!validate_ip(ip), "should be invalid: {ip}");
        }
    }

    // ── Pattern matching ──

    #[test]
    fn pattern_exact_match() {
        assert!(matches_pattern("hello", "hello"));
        assert!(!matches_pattern("hello", "world"));
    }

    #[test]
    fn pattern_wildcard() {
        assert!(matches_pattern("sk_test_abc123", "sk_test_*"));
        assert!(matches_pattern("sk_live_xyz", "sk_live_*"));
        assert!(!matches_pattern("rk_test_abc", "sk_test_*"));
        assert!(matches_pattern("anything", "*"));
        assert!(matches_pattern("prefix_middle_suffix", "prefix_*_suffix"));
    }

    #[test]
    fn pattern_alternation() {
        assert!(matches_pattern("sk_test_abc", "sk_(test|live)_*"));
        assert!(matches_pattern("sk_live_xyz", "sk_(test|live)_*"));
        assert!(!matches_pattern("sk_dev_abc", "sk_(test|live)_*"));
    }

    #[test]
    fn pattern_multiple_alternation_groups() {
        // Multiple groups: (api|app)_key_(v1|v2)
        // Recursive expansion handles this — first group expands, recursive call finds second
        assert!(matches_pattern("api_key_v1", "(api|app)_key_(v1|v2)"));
        assert!(matches_pattern("app_key_v2", "(api|app)_key_(v1|v2)"));
        assert!(matches_pattern("api_key_v2", "(api|app)_key_(v1|v2)"));
        assert!(matches_pattern("app_key_v1", "(api|app)_key_(v1|v2)"));
        assert!(!matches_pattern("web_key_v1", "(api|app)_key_(v1|v2)"));
        assert!(!matches_pattern("api_key_v3", "(api|app)_key_(v1|v2)"));
    }

    #[test]
    fn pattern_postgres_url() {
        assert!(matches_pattern(
            "postgres://user:pass@localhost:5432/db",
            "postgres://*"
        ));
        assert!(!matches_pattern("mysql://localhost", "postgres://*"));
    }

    // ── Enum validation ──

    #[test]
    fn enum_valid_value() {
        let schema =
            schema_from_json(r#"{"vars": {"LOG": {"enum": ["debug", "info", "warn", "error"]}}}"#);
        let mut env = HashMap::from([("LOG".into(), "info".into())]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
    }

    #[test]
    fn enum_invalid_value() {
        let schema =
            schema_from_json(r#"{"vars": {"LOG": {"enum": ["debug", "info", "warn", "error"]}}}"#);
        let mut env = HashMap::from([("LOG".into(), "verbose".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::NotInEnum { .. }
        ));
    }

    // ── Pattern validation in schema context ──

    #[test]
    fn schema_pattern_validation() {
        let schema = schema_from_json(r#"{"vars": {"KEY": {"pattern": "sk_(test|live)_*"}}}"#);
        let mut env = HashMap::from([("KEY".into(), "sk_test_abc".into())]);
        assert!(validate(&schema, &mut env).is_empty());

        let mut env = HashMap::from([("KEY".into(), "rk_test_abc".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::PatternMismatch { .. }
        ));
    }

    // ── Secret redaction ──

    #[test]
    fn secret_values_redacted_in_display() {
        let err = ValidationError {
            key: "STRIPE_KEY".into(),
            kind: ValidationErrorKind::PatternMismatch {
                pattern: "sk_*".into(),
                got: "rk_live_supersecretvalue123".into(),
            },
            description: None,
            is_secret: true,
        };
        let msg = err.to_string();
        assert!(
            !msg.contains("supersecretvalue123"),
            "secret should be redacted"
        );
        assert!(msg.contains("rk_l"), "should show first 4 chars");
        assert!(msg.contains("123"), "should show last 3 chars");
    }

    #[test]
    fn non_secret_values_shown_in_display() {
        let err = ValidationError {
            key: "PORT".into(),
            kind: ValidationErrorKind::InvalidFormat {
                expected: VarFormat::Port,
                got: "not_a_port".into(),
            },
            description: None,
            is_secret: false,
        };
        let msg = err.to_string();
        assert!(msg.contains("not_a_port"), "non-secret should be shown");
    }

    #[test]
    fn short_secret_fully_redacted() {
        let redacted = redact_value("short");
        assert_eq!(redacted, "••••••");
    }

    #[test]
    fn long_secret_partially_shown() {
        let redacted = redact_value("sk_test_abc123xyz");
        assert_eq!(redacted, "sk_t...xyz");
    }

    // ── Multiple errors ──

    #[test]
    fn multiple_errors_collected() {
        let schema = schema_from_json(
            r#"{"vars": {
                "A": {"required": true},
                "B": {"required": true},
                "C": {"format": "port"}
            }}"#,
        );
        let mut env = HashMap::from([("C".into(), "not_a_port".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 3); // A missing, B missing, C invalid format
    }

    // ── Deterministic order ──

    #[test]
    fn errors_sorted_by_key_name() {
        let schema = schema_from_json(
            r#"{"vars": {
                "ZEBRA": {"required": true},
                "ALPHA": {"required": true},
                "MIDDLE": {"required": true}
            }}"#,
        );
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        let keys: Vec<&str> = errors.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["ALPHA", "MIDDLE", "ZEBRA"]);
    }

    // ── Empty schema ──

    #[test]
    fn empty_schema_passes_everything() {
        let schema = EnvSchema::default();
        let mut env = HashMap::from([
            ("ANYTHING".into(), "goes".into()),
            ("HERE".into(), "too".into()),
        ]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
    }

    // ── Extra env vars not in schema pass through silently ──

    #[test]
    fn extra_vars_not_in_schema_are_ignored() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"format": "port"}}}"#);
        let mut env = HashMap::from([
            ("PORT".into(), "3000".into()),
            ("UNKNOWN_VAR".into(), "whatever".into()),
        ]);
        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty());
        // Extra var is still in the map
        assert_eq!(env.get("UNKNOWN_VAR").unwrap(), "whatever");
    }

    // ── Format validation stops further checks ──

    #[test]
    fn format_error_skips_pattern_check() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"format": "port", "pattern": "3*"}}}"#);
        let mut env = HashMap::from([("PORT".into(), "abc".into())]);
        let errors = validate(&schema, &mut env);
        // Only format error, not pattern error too
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0].kind,
            ValidationErrorKind::InvalidFormat { .. }
        ));
    }

    // ── Full integration test ──

    #[test]
    fn full_schema_integration() {
        let schema = schema_from_json(
            r#"{"vars": {
                "DATABASE_URL": {"required": true, "format": "url", "secret": true, "description": "PostgreSQL connection string"},
                "PORT": {"default": "3000", "format": "port"},
                "STRIPE_SECRET_KEY": {"required": true, "secret": true, "pattern": "sk_(test|live)_*"},
                "LOG_LEVEL": {"enum": ["debug", "info", "warn", "error"], "default": "info"},
                "ENABLE_ANALYTICS": {"format": "boolean", "default": "false"},
                "APP_URL": {"required": true, "format": "url", "client": true}
            }}"#,
        );

        let mut env = HashMap::from([
            (
                "DATABASE_URL".into(),
                "postgres://localhost:5432/mydb".into(),
            ),
            ("STRIPE_SECRET_KEY".into(), "sk_test_abc123def456".into()),
            ("APP_URL".into(), "https://myapp.com".into()),
        ]);

        let errors = validate(&schema, &mut env);
        assert!(errors.is_empty(), "errors: {errors:?}");

        // Defaults should have been injected
        assert_eq!(env.get("PORT").unwrap(), "3000");
        assert_eq!(env.get("LOG_LEVEL").unwrap(), "info");
        assert_eq!(env.get("ENABLE_ANALYTICS").unwrap(), "false");
    }

    // ── Description shown in missing error ──

    #[test]
    fn missing_error_includes_description() {
        let schema = schema_from_json(
            r#"{"vars": {"DB": {"required": true, "description": "Database URL"}}}"#,
        );
        let mut env = HashMap::new();
        let errors = validate(&schema, &mut env);
        let msg = errors[0].to_string();
        assert!(msg.contains("Database URL"));
    }

    // ── Glob matching edge cases ──

    #[test]
    fn glob_empty_pattern() {
        assert!(glob_match("", ""));
        assert!(!glob_match("a", ""));
    }

    #[test]
    fn glob_only_wildcard() {
        assert!(glob_match("anything", "*"));
        assert!(glob_match("", "*"));
    }

    #[test]
    fn glob_multiple_wildcards() {
        assert!(glob_match("abc_def_ghi", "*_def_*"));
        assert!(glob_match("a_b_c_d", "*_b_*_d"));
        assert!(!glob_match("a_x_c_d", "*_b_*_d"));
    }

    #[test]
    fn glob_suffix_only() {
        assert!(glob_match("test.js", "*.js"));
        assert!(!glob_match("test.ts", "*.js"));
    }

    #[test]
    fn glob_prefix_and_suffix() {
        assert!(glob_match("sk_test_abc", "sk_*_abc"));
        assert!(glob_match("sk_live_abc", "sk_*_abc"));
        assert!(!glob_match("sk_test_xyz", "sk_*_abc"));
    }
}
