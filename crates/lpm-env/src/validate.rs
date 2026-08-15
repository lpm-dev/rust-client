//! Pure validation engine for environment variables against a schema.
//!
//! Takes `(schema, env_map)` → `Vec<ValidationError>`. No side effects.

use crate::schema::{EnvSchema, EnvVarRule, VarFormat};
use regex_automata::{
    Input, MatchKind, PatternID, PatternSet, meta::Regex, nfa::thompson::WhichCaptures,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

const REDACTED_VALUE: &str = "[REDACTED]";
const MAX_ENV_VAR_NAME_BYTES: usize = 256;
const MAX_PATTERN_BATCH_SIZE: usize = 64;
const REGEX_NFA_SIZE_LIMIT_BYTES: usize = 1024 * 1024;
const REGEX_DFA_SIZE_LIMIT_BYTES: usize = 256 * 1024;
const REGEX_HYBRID_CACHE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_REGEX_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const REGEX_MEMORY_BUDGET_ERROR: &str =
    "combined envSchema patterns exceed the 8 MiB compiled-regex memory limit";

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
    /// The schema key is not a portable environment variable name.
    InvalidVariableName,
    /// The configured regular expression cannot be compiled safely.
    InvalidPattern { pattern: String, message: String },
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
        let key = TerminalSafe(&self.key);
        match &self.kind {
            ValidationErrorKind::InvalidVariableName => {
                write!(
                    f,
                    "{}: invalid environment variable name. Use 1 to 256 ASCII letters, numbers, or underscores. Start with a letter or underscore",
                    key
                )?;
            }
            ValidationErrorKind::InvalidPattern { pattern, message } => {
                write!(
                    f,
                    "{}: invalid regex `{}` in envSchema.pattern: {}",
                    key,
                    TerminalSafe(pattern),
                    TerminalSafe(message)
                )?;
            }
            ValidationErrorKind::Missing => {
                write!(f, "{}: missing (required)", key)?;
                if let Some(desc) = &self.description {
                    write!(f, " — {}", TerminalSafe(desc))?;
                }
            }
            ValidationErrorKind::InvalidFormat { expected, got } => {
                let display_value = display_value(got, self.is_secret);
                write!(
                    f,
                    "{}: invalid format, expected {expected:?}, got \"{}\"",
                    key,
                    TerminalSafe(display_value)
                )?;
            }
            ValidationErrorKind::PatternMismatch { pattern, got } => {
                let display_value = display_value(got, self.is_secret);
                write!(
                    f,
                    "{}: must match pattern `{}`, got \"{}\"",
                    key,
                    TerminalSafe(pattern),
                    TerminalSafe(display_value)
                )?;
            }
            ValidationErrorKind::NotInEnum { allowed, got } => {
                let display_value = display_value(got, self.is_secret);
                write!(f, "{}: must be one of [", key)?;
                write_allowed_values(f, allowed, self.is_secret)?;
                write!(f, "], got \"{}\"", TerminalSafe(display_value))?;
            }
        }
        Ok(())
    }
}

struct TerminalSafe<'a>(&'a str);

impl std::fmt::Display for TerminalSafe<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for character in self.0.chars() {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                for escaped in character.escape_default() {
                    std::fmt::Write::write_char(f, escaped)?;
                }
            } else {
                std::fmt::Write::write_char(f, character)?;
            }
        }
        Ok(())
    }
}

fn write_allowed_values(
    f: &mut std::fmt::Formatter<'_>,
    allowed: &[String],
    is_secret: bool,
) -> std::fmt::Result {
    if is_secret {
        return f.write_str(REDACTED_VALUE);
    }
    for (index, value) in allowed.iter().enumerate() {
        if index != 0 {
            f.write_str(", ")?;
        }
        write!(f, "{}", TerminalSafe(value))?;
    }
    Ok(())
}

fn display_value(value: &str, is_secret: bool) -> &str {
    if is_secret { REDACTED_VALUE } else { value }
}

fn retained_value(value: &str, is_secret: bool) -> String {
    if is_secret {
        REDACTED_VALUE.to_string()
    } else {
        value.to_string()
    }
}

struct CompiledRule<'a> {
    key: &'a str,
    rule: &'a EnvVarRule,
    pattern_index: Option<usize>,
}

#[derive(Clone, Copy)]
struct PatternLocation {
    batch: usize,
    pattern: PatternID,
}

enum CompiledPattern {
    Valid(PatternLocation),
    Invalid(InvalidPatternReason),
}

enum InvalidPatternReason {
    Compiler(String),
    MemoryBudgetExceeded,
}

impl InvalidPatternReason {
    fn message(&self) -> String {
        match self {
            Self::Compiler(message) => message.clone(),
            Self::MemoryBudgetExceeded => REGEX_MEMORY_BUDGET_ERROR.to_string(),
        }
    }
}

/// A reusable validator that deduplicates and compiles configured regexes in batches.
pub struct EnvValidator<'a> {
    rules: Vec<CompiledRule<'a>>,
    patterns: Vec<CompiledPattern>,
    pattern_batches: Vec<Regex>,
}

impl<'a> EnvValidator<'a> {
    /// Compile a deterministic validation plan for an environment schema.
    pub fn new(schema: &'a EnvSchema) -> Self {
        let mut keys = Vec::with_capacity(schema.vars.len());
        keys.extend(schema.vars.keys().map(String::as_str));
        keys.sort_unstable();

        let mut unique_pattern_indices = HashMap::new();
        let mut unique_patterns = Vec::new();
        let mut rules = Vec::with_capacity(keys.len());
        for key in keys {
            let rule = &schema.vars[key];
            let pattern_index = rule.pattern.as_deref().map(|pattern| {
                *unique_pattern_indices.entry(pattern).or_insert_with(|| {
                    let index = unique_patterns.len();
                    unique_patterns.push(pattern);
                    index
                })
            });
            rules.push(CompiledRule {
                key,
                rule,
                pattern_index,
            });
        }

        let mut patterns = std::iter::repeat_with(|| None)
            .take(unique_patterns.len())
            .collect::<Vec<Option<CompiledPattern>>>();
        let mut pattern_batches = Vec::new();
        let mut retained_regex_memory = 0;
        let mut memory_budget_exceeded = false;
        let indexed_patterns = unique_patterns.into_iter().enumerate().collect::<Vec<_>>();
        for batch in indexed_patterns.chunks(MAX_PATTERN_BATCH_SIZE) {
            if !compile_pattern_batch(
                batch,
                &mut patterns,
                &mut pattern_batches,
                &mut retained_regex_memory,
            ) {
                memory_budget_exceeded = true;
                break;
            }
        }
        if memory_budget_exceeded {
            pattern_batches.clear();
            for pattern in &mut patterns {
                if !matches!(
                    pattern,
                    Some(CompiledPattern::Invalid(InvalidPatternReason::Compiler(_)))
                ) {
                    *pattern = Some(CompiledPattern::Invalid(
                        InvalidPatternReason::MemoryBudgetExceeded,
                    ));
                }
            }
        }
        let patterns = patterns
            .into_iter()
            .map(|pattern| pattern.expect("every pattern is compiled or rejected"))
            .collect();

        Self {
            rules,
            patterns,
            pattern_batches,
        }
    }

    /// Validate values and inject only defaults that satisfy their complete rule.
    pub fn validate(&self, env_vars: &mut HashMap<String, String>) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        let mut matched_patterns = PatternSet::new(MAX_PATTERN_BATCH_SIZE);

        for compiled in &self.rules {
            let key = compiled.key;
            let rule = compiled.rule;

            if !is_valid_env_var_name(key) {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidVariableName,
                ));
                continue;
            }

            let pattern = match compiled.pattern_index.map(|index| &self.patterns[index]) {
                Some(CompiledPattern::Valid(location)) => Some(*location),
                Some(CompiledPattern::Invalid(reason)) => {
                    errors.push(validation_error(
                        key,
                        rule,
                        ValidationErrorKind::InvalidPattern {
                            pattern: rule.pattern.clone().unwrap_or_default(),
                            message: reason.message(),
                        },
                    ));
                    continue;
                }
                None => None,
            };

            let is_missing_or_empty = env_vars.get(key).is_none_or(String::is_empty);
            if is_missing_or_empty {
                if let Some(default) = &rule.default {
                    if rule.required && default.is_empty() {
                        errors.push(validation_error(key, rule, ValidationErrorKind::Missing));
                        continue;
                    }
                    let error_count = errors.len();
                    let pattern_matches = pattern.map(|location| {
                        self.matches_pattern(default, location, &mut matched_patterns)
                    });
                    validate_value(key, default, rule, pattern_matches, &mut errors);
                    if errors.len() == error_count {
                        env_vars.insert(key.to_string(), default.clone());
                    }
                } else if rule.required {
                    errors.push(validation_error(key, rule, ValidationErrorKind::Missing));
                }
            } else if let Some(value) = env_vars.get(key) {
                let pattern_matches = pattern
                    .map(|location| self.matches_pattern(value, location, &mut matched_patterns));
                validate_value(key, value, rule, pattern_matches, &mut errors);
            }
        }

        errors
    }

    fn matches_pattern(
        &self,
        value: &str,
        location: PatternLocation,
        matched_patterns: &mut PatternSet,
    ) -> bool {
        matched_patterns.clear();
        self.pattern_batches[location.batch]
            .which_overlapping_matches(&Input::new(value), matched_patterns);
        matched_patterns.contains(location.pattern)
    }
}

/// Validate environment variables against a schema.
///
/// This is the core validation function — synchronous, pure, no side effects.
/// Returns an empty `Vec` if all validations pass.
///
/// **Default injection:** if a variable is not set, a valid non-empty `default` is
/// injected into `env_vars`. Invalid defaults return the corresponding validation error.
/// An empty default cannot satisfy a required variable.
pub fn validate(
    schema: &EnvSchema,
    env_vars: &mut HashMap<String, String>,
) -> Vec<ValidationError> {
    EnvValidator::new(schema).validate(env_vars)
}

/// Validate a single value against its rule.
fn validate_value(
    key: &str,
    value: &str,
    rule: &EnvVarRule,
    pattern_matches: Option<bool>,
    errors: &mut Vec<ValidationError>,
) {
    // Format validation
    if let Some(format) = &rule.format
        && !validate_format(value, format)
    {
        errors.push(validation_error(
            key,
            rule,
            ValidationErrorKind::InvalidFormat {
                expected: format.clone(),
                got: retained_value(value, rule.secret),
            },
        ));
        // Don't check further rules if format is wrong
        return;
    }

    if pattern_matches == Some(false) {
        errors.push(validation_error(
            key,
            rule,
            ValidationErrorKind::PatternMismatch {
                pattern: rule.pattern.clone().unwrap_or_default(),
                got: retained_value(value, rule.secret),
            },
        ));
        return;
    }

    // Enum validation
    if let Some(allowed) = &rule.enum_values
        && !allowed.iter().any(|a| a == value)
    {
        errors.push(validation_error(
            key,
            rule,
            ValidationErrorKind::NotInEnum {
                allowed: if rule.secret {
                    Vec::new()
                } else {
                    allowed.clone()
                },
                got: retained_value(value, rule.secret),
            },
        ));
    }
}

fn validation_error(key: &str, rule: &EnvVarRule, kind: ValidationErrorKind) -> ValidationError {
    ValidationError {
        key: key.to_string(),
        kind,
        description: rule.description.clone(),
        is_secret: rule.secret,
    }
}

fn compile_pattern_batch(
    indexed_patterns: &[(usize, &str)],
    compiled_patterns: &mut [Option<CompiledPattern>],
    batches: &mut Vec<Regex>,
    retained_memory: &mut usize,
) -> bool {
    let patterns = indexed_patterns
        .iter()
        .map(|(_, pattern)| *pattern)
        .collect::<Vec<_>>();
    match build_pattern_batch(&patterns) {
        Ok(regex) => {
            let Some(next_retained_memory) = retained_memory
                .checked_add(compiled_regex_memory_usage(&regex))
                .filter(|memory| *memory <= MAX_TOTAL_REGEX_MEMORY_BYTES)
            else {
                return false;
            };
            let batch = batches.len();
            batches.push(regex);
            *retained_memory = next_retained_memory;
            for (local_index, (original_index, _)) in indexed_patterns.iter().enumerate() {
                compiled_patterns[*original_index] =
                    Some(CompiledPattern::Valid(PatternLocation {
                        batch,
                        pattern: PatternID::must(local_index),
                    }));
            }
            true
        }
        Err(message) if indexed_patterns.len() == 1 => {
            compiled_patterns[indexed_patterns[0].0] = Some(CompiledPattern::Invalid(
                InvalidPatternReason::Compiler(message),
            ));
            true
        }
        Err(_) => {
            let middle = indexed_patterns.len() / 2;
            compile_pattern_batch(
                &indexed_patterns[..middle],
                compiled_patterns,
                batches,
                retained_memory,
            ) && compile_pattern_batch(
                &indexed_patterns[middle..],
                compiled_patterns,
                batches,
                retained_memory,
            )
        }
    }
}

fn compiled_regex_memory_usage(regex: &Regex) -> usize {
    let cache_memory = regex
        .create_cache()
        .memory_usage()
        .max(2 * REGEX_HYBRID_CACHE_BYTES);
    regex.memory_usage().saturating_add(cache_memory)
}

fn build_pattern_batch(patterns: &[&str]) -> Result<Regex, String> {
    Regex::builder()
        .configure(
            Regex::config()
                .match_kind(MatchKind::All)
                .which_captures(WhichCaptures::None)
                .nfa_size_limit(Some(REGEX_NFA_SIZE_LIMIT_BYTES))
                .dfa_size_limit(Some(REGEX_DFA_SIZE_LIMIT_BYTES))
                .hybrid_cache_capacity(REGEX_HYBRID_CACHE_BYTES),
        )
        .build_many(patterns)
        .map_err(|error| error.to_string())
}

fn is_valid_env_var_name(key: &str) -> bool {
    if key.len() > MAX_ENV_VAR_NAME_BYTES {
        return false;
    }
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
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

#[cfg(test)]
fn matches_pattern(value: &str, pattern: &str) -> bool {
    let Ok(compiled) = build_pattern_batch(&[pattern]) else {
        return false;
    };
    let mut matched_patterns = PatternSet::new(1);
    compiled.which_overlapping_matches(&Input::new(value), &mut matched_patterns);
    matched_patterns.contains(PatternID::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EnvSchema;

    fn schema_from_json(json: &str) -> EnvSchema {
        serde_json::from_str(json).unwrap()
    }

    fn schema_exceeding_compiled_regex_budget() -> EnvSchema {
        let vars = (0..256)
            .map(|index| {
                (
                    format!("PATTERN_{index:03}"),
                    EnvVarRule {
                        pattern: Some(format!(r"^(?:a?){{1024}}{index}$")),
                        ..EnvVarRule::default()
                    },
                )
            })
            .collect();
        EnvSchema { vars }
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

    #[test]
    fn empty_default_does_not_satisfy_required_variable() {
        let schema = schema_from_json(r#"{"vars": {"TOKEN": {"required": true, "default": ""}}}"#);
        let mut env = HashMap::new();

        let errors = validate(&schema, &mut env);

        assert!(matches!(
            errors.as_slice(),
            [ValidationError {
                kind: ValidationErrorKind::Missing,
                ..
            }]
        ));
        assert!(!env.contains_key("TOKEN"));
    }

    #[test]
    fn invalid_format_default_is_rejected_without_injection() {
        let schema =
            schema_from_json(r#"{"vars": {"PORT": {"default": "70000", "format": "port"}}}"#);
        let mut env = HashMap::new();

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0].kind,
            ValidationErrorKind::InvalidFormat {
                expected: VarFormat::Port,
                ..
            }
        ));
        assert!(!env.contains_key("PORT"));
    }

    #[test]
    fn invalid_enum_default_is_rejected_without_injection() {
        let schema = schema_from_json(
            r#"{"vars": {"LOG_LEVEL": {"default": "verbose", "enum": ["info", "warn"]}}}"#,
        );
        let mut env = HashMap::new();

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0].kind,
            ValidationErrorKind::NotInEnum { .. }
        ));
        assert!(!env.contains_key("LOG_LEVEL"));
    }

    #[test]
    fn invalid_pattern_default_is_rejected_without_injection() {
        let schema = schema_from_json(
            r#"{"vars": {"API_KEY": {"default": "invalid", "pattern": "^sk_(test|live)_.*$"}}}"#,
        );
        let mut env = HashMap::new();

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0].kind,
            ValidationErrorKind::PatternMismatch { .. }
        ));
        assert!(!env.contains_key("API_KEY"));
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
    fn regex_without_anchors_matches_a_substring() {
        assert!(matches_pattern("prefix_hello_suffix", "hello"));
    }

    #[test]
    fn pattern_regex_quantifiers() {
        assert!(matches_pattern("sk_test_abc123", r"^sk_test_.*$"));
        assert!(matches_pattern("sk_live_xyz", r"^sk_live_\w+$"));
        assert!(!matches_pattern("rk_test_abc", r"^sk_test_.*$"));
        assert!(matches_pattern("anything", r"^.*$"));
        assert!(matches_pattern(
            "prefix_middle_suffix",
            r"^prefix_.*_suffix$"
        ));
    }

    #[test]
    fn pattern_alternation() {
        assert!(matches_pattern("sk_test_abc", r"^sk_(test|live)_.*$"));
        assert!(matches_pattern("sk_live_xyz", r"^sk_(test|live)_.*$"));
        assert!(!matches_pattern("sk_dev_abc", r"^sk_(test|live)_.*$"));
    }

    #[test]
    fn documented_anchored_regex_accepts_an_allowed_value() {
        let schema = schema_from_json(
            r#"{"vars": {"LOG_LEVEL": {"pattern": "^(trace|debug|info|warn|error)$"}}}"#,
        );
        let mut env = HashMap::from([("LOG_LEVEL".into(), "info".into())]);

        let errors = validate(&schema, &mut env);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn regex_dot_star_matches_arbitrary_suffix() {
        let schema =
            schema_from_json(r#"{"vars": {"API_KEY": {"pattern": "^sk_(test|live)_.*$"}}}"#);
        let mut env = HashMap::from([("API_KEY".into(), "sk_test_abc".into())]);

        let errors = validate(&schema, &mut env);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn invalid_regex_is_reported_as_a_schema_error() {
        let schema = schema_from_json(r#"{"vars": {"VALUE": {"pattern": "["}}}"#);
        let mut env = HashMap::from([("VALUE".into(), "anything".into())]);

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].to_string().contains("invalid regex"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn invalid_regex_does_not_disable_valid_patterns_in_the_same_batch() {
        let schema = schema_from_json(
            r#"{"vars": {
                "BROKEN": {"pattern": "["},
                "VALID": {"pattern": "^accepted$"}
            }}"#,
        );
        let mut env = HashMap::from([
            ("BROKEN".into(), "anything".into()),
            ("VALID".into(), "accepted".into()),
        ]);

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key, "BROKEN");
        assert!(matches!(
            errors[0].kind,
            ValidationErrorKind::InvalidPattern { .. }
        ));
    }

    #[test]
    fn batched_regex_checks_only_the_rule_assigned_to_each_variable() {
        let schema = schema_from_json(
            r#"{"vars": {
                "FIRST": {"pattern": "^alpha$"},
                "SECOND": {"pattern": "^beta$"}
            }}"#,
        );
        let mut env = HashMap::from([
            ("FIRST".into(), "beta".into()),
            ("SECOND".into(), "beta".into()),
        ]);

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key, "FIRST");
        assert!(matches!(
            errors[0].kind,
            ValidationErrorKind::PatternMismatch { .. }
        ));
    }

    #[test]
    fn pattern_multiple_alternation_groups() {
        let pattern = r"^(api|app)_key_(v1|v2)$";
        assert!(matches_pattern("api_key_v1", pattern));
        assert!(matches_pattern("app_key_v2", pattern));
        assert!(matches_pattern("api_key_v2", pattern));
        assert!(matches_pattern("app_key_v1", pattern));
        assert!(!matches_pattern("web_key_v1", pattern));
        assert!(!matches_pattern("api_key_v3", pattern));
    }

    #[test]
    fn pattern_postgres_url() {
        assert!(matches_pattern(
            "postgres://user:pass@localhost:5432/db",
            r"^postgres://.*$"
        ));
        assert!(!matches_pattern("mysql://localhost", r"^postgres://.*$"));
    }

    #[test]
    fn dense_alternation_is_matched_without_recursive_expansion() {
        let pattern = format!("^{}$", "(a|b)".repeat(32));
        let value = "a".repeat(32);

        assert!(matches_pattern(&value, &pattern));
    }

    #[test]
    fn compiled_regex_memory_stays_within_the_schema_budget() {
        let schema = schema_exceeding_compiled_regex_budget();

        let validator = EnvValidator::new(&schema);
        let retained_memory = validator
            .pattern_batches
            .iter()
            .map(compiled_regex_memory_usage)
            .sum::<usize>();

        assert!(
            retained_memory <= MAX_TOTAL_REGEX_MEMORY_BYTES,
            "compiled regexes retained {retained_memory} bytes"
        );
    }

    #[test]
    fn schema_over_the_compiled_regex_budget_returns_a_truthful_error() {
        let schema = schema_exceeding_compiled_regex_budget();
        let validator = EnvValidator::new(&schema);

        let errors = validator.validate(&mut HashMap::new());

        assert_eq!(errors.len(), 256);
        assert!(errors.iter().all(|error| {
            matches!(
                &error.kind,
                ValidationErrorKind::InvalidPattern { message, .. }
                    if message == REGEX_MEMORY_BUDGET_ERROR
            )
        }));
    }

    #[test]
    fn regex_batch_boundary_accepts_64_and_65_patterns() {
        for count in [64, 65] {
            let vars = (0..count)
                .map(|index| {
                    (
                        format!("PATTERN_{index:02}"),
                        EnvVarRule {
                            pattern: Some(format!("^value_{index}$")),
                            ..EnvVarRule::default()
                        },
                    )
                })
                .collect::<HashMap<_, _>>();
            let mut env = (0..count)
                .map(|index| (format!("PATTERN_{index:02}"), format!("value_{index}")))
                .collect();
            let schema = EnvSchema { vars };

            let errors = EnvValidator::new(&schema).validate(&mut env);

            assert!(errors.is_empty(), "{count} patterns failed: {errors:?}");
        }
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

    #[test]
    fn secret_validation_errors_do_not_retain_or_display_the_value() {
        let secret = "prefix_private_material_suffix";
        for rule in [
            r#"{"format": "url", "secret": true}"#,
            r#"{"pattern": "^allowed$", "secret": true}"#,
            r#"{"enum": ["allowed_secret"], "secret": true}"#,
        ] {
            let schema = schema_from_json(&format!(r#"{{"vars": {{"TOKEN": {rule}}}}}"#));
            let mut env = HashMap::from([("TOKEN".into(), secret.into())]);

            let errors = validate(&schema, &mut env);
            let display = errors[0].to_string();
            let debug = format!("{errors:?}");

            for fragment in [
                secret,
                "prefix",
                "suffix",
                "private_material",
                "allowed_secret",
            ] {
                assert!(!display.contains(fragment), "display leaked {fragment}");
                assert!(!debug.contains(fragment), "debug leaked {fragment}");
            }
        }
    }

    #[test]
    fn invalid_schema_variable_name_is_rejected() {
        let schema = schema_from_json(r#"{"vars": {"DATABASE-URL": {"required": true}}}"#);
        let mut env = HashMap::new();

        let errors = validate(&schema, &mut env);

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .to_string()
                .contains("invalid environment variable name"),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn invalid_variable_name_error_escapes_terminal_control_characters() {
        let schema = EnvSchema {
            vars: HashMap::from([(
                "BAD\u{1b}[31m\n\u{202e}KEY".to_string(),
                EnvVarRule::default(),
            )]),
        };

        let message = validate(&schema, &mut HashMap::new())[0].to_string();

        assert!(!message.chars().any(char::is_control), "{message:?}");
        assert!(!message.contains('\u{202e}'), "{message:?}");
    }

    #[test]
    fn schema_variable_name_over_256_bytes_is_rejected() {
        let key = "A".repeat(257);
        let schema = EnvSchema {
            vars: HashMap::from([(key, EnvVarRule::default())]),
        };

        let errors = validate(&schema, &mut HashMap::new());

        assert!(matches!(
            errors.as_slice(),
            [ValidationError {
                kind: ValidationErrorKind::InvalidVariableName,
                ..
            }]
        ));
    }

    // ── Pattern validation in schema context ──

    #[test]
    fn schema_pattern_validation() {
        let schema = schema_from_json(r#"{"vars": {"KEY": {"pattern": "^sk_(test|live)_.*$"}}}"#);
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
                pattern: "^sk_.*$".into(),
                got: "rk_live_supersecretvalue123".into(),
            },
            description: None,
            is_secret: true,
        };
        let msg = err.to_string();
        assert!(!msg.contains("rk_live_supersecretvalue123"));
        assert!(msg.contains(REDACTED_VALUE));
    }

    #[test]
    fn non_secret_value_error_escapes_terminal_control_characters() {
        let schema = schema_from_json(r#"{"vars": {"PORT": {"format": "port"}}}"#);
        let mut env = HashMap::from([("PORT".into(), "70000\u{1b}[31m\n".into())]);

        let message = validate(&schema, &mut env)[0].to_string();

        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn invalid_pattern_error_escapes_terminal_control_characters() {
        let schema = EnvSchema {
            vars: HashMap::from([(
                "TOKEN".to_string(),
                EnvVarRule {
                    pattern: Some("\u{1b}[31m(".to_string()),
                    ..EnvVarRule::default()
                },
            )]),
        };

        let message = validate(&schema, &mut HashMap::new())[0].to_string();

        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn enum_error_escapes_terminal_control_characters() {
        let schema = EnvSchema {
            vars: HashMap::from([(
                "MODE".to_string(),
                EnvVarRule {
                    enum_values: Some(vec!["safe\u{1b}[31m\n".to_string()]),
                    ..EnvVarRule::default()
                },
            )]),
        };
        let mut env = HashMap::from([("MODE".into(), "other".into())]);

        let message = validate(&schema, &mut env)[0].to_string();

        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn missing_description_error_escapes_terminal_control_characters() {
        let schema = EnvSchema {
            vars: HashMap::from([(
                "TOKEN".to_string(),
                EnvVarRule {
                    required: true,
                    description: Some("description\u{1b}[31m\n".to_string()),
                    ..EnvVarRule::default()
                },
            )]),
        };

        let message = validate(&schema, &mut HashMap::new())[0].to_string();

        assert!(!message.chars().any(char::is_control), "{message:?}");
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
    fn validation_error_with_multibyte_secret_does_not_panic() {
        // End-to-end check: a `secret: true` rule firing on a value
        // dense in multibyte codepoints must format cleanly. Pre-fix
        // this `to_string()` panicked at `byte index 4 is not a char
        // boundary`.
        let schema = schema_from_json(
            r#"{"vars": {"TOKEN": {"required": true, "secret": true, "format": "url"}}}"#,
        );
        let mut env = HashMap::from([("TOKEN".into(), "あいうえおかきくけこさ".into())]);
        let errors = validate(&schema, &mut env);
        assert_eq!(errors.len(), 1);
        let _ = errors[0].to_string();
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
                "STRIPE_SECRET_KEY": {"required": true, "secret": true, "pattern": "^sk_(test|live)_.*$"},
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
}
