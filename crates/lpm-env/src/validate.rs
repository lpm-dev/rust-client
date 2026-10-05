//! Pure validation engine for environment variables against a schema.
//!
//! Takes `(schema, env_map)` → `Vec<ValidationError>`. No side effects.

use crate::schema::{EmptyPolicy, EnvSchema, EnvVarRule, VarFormat};
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
    /// The declaration cannot be safely evaluated.
    InvalidRule { message: &'static str },
    /// An empty value is explicitly forbidden.
    Empty,
    /// A value contains a NUL byte and cannot become a process environment value.
    InvalidValue,
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
    /// A numeric, length, or URL-protocol restriction failed.
    ConstraintViolation { constraint: &'static str },
    /// A relationship failed; the error is associated with each affected variable.
    GroupViolation {
        group: String,
        mode: crate::VarGroupMode,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = TerminalSafe(&self.key);
        match &self.kind {
            ValidationErrorKind::ConstraintViolation { constraint } => {
                write!(f, "{key}: violates {constraint} constraint")?
            }
            ValidationErrorKind::GroupViolation { group, mode } => write!(
                f,
                "{key}: group {} requires {}",
                TerminalSafe(group),
                match mode {
                    crate::VarGroupMode::AllOrNone => "all values or no values to be non-empty",
                    crate::VarGroupMode::ExactlyOne => "exactly one non-empty value",
                    crate::VarGroupMode::AtLeastOne => "at least one non-empty value",
                }
            )?,
            ValidationErrorKind::InvalidRule { message } => {
                write!(f, "{key}: invalid envSchema rule: {message}")?
            }
            ValidationErrorKind::Empty => write!(f, "{key}: empty values are not allowed")?,
            ValidationErrorKind::InvalidValue => {
                write!(f, "{key}: values cannot contain NUL bytes")?
            }
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
    schema: &'a EnvSchema,
    groups: Vec<(&'a str, &'a crate::VarGroup)>,
    rules: Vec<CompiledRule<'a>>,
    patterns: Vec<CompiledPattern>,
    pattern_batches: Vec<Regex>,
    definition_errors: Vec<ValidationError>,
}

impl<'a> EnvValidator<'a> {
    /// Compile a deterministic validation plan for an environment schema.
    pub fn new(schema: &'a EnvSchema) -> Self {
        if !crate::scopes::budgets_valid(schema) {
            return Self {
                schema,
                groups: Vec::new(),
                rules: Vec::new(),
                patterns: Vec::new(),
                pattern_batches: Vec::new(),
                definition_errors: vec![ValidationError {
                    key: "envSchema".into(),
                    kind: ValidationErrorKind::InvalidRule {
                        message: "scope definitions exceed 4096 selectors or 16384 dimension values",
                    },
                    description: None,
                    is_secret: false,
                }],
            };
        }
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

        let mut validator = Self {
            schema,
            groups: crate::constraints::ordered_groups(schema),
            rules,
            patterns,
            pattern_batches,
            definition_errors: Vec::new(),
        };
        validator.definition_errors = validator.check_definitions();
        validator
    }

    /// The immutable schema used to compile this plan.
    pub fn schema(&self) -> &'a EnvSchema {
        self.schema
    }

    /// Return declaration errors independently of supplied values.
    pub fn schema_errors(&self) -> &[ValidationError] {
        &self.definition_errors
    }

    fn check_definitions(&self) -> Vec<ValidationError> {
        let mut errors = crate::constraints::definition_errors(self.schema);
        let mut prefixes =
            std::collections::HashSet::with_capacity(self.schema.client_prefixes.len().min(32));
        let prefixes_invalid = self.schema.client_prefixes.len() > 32
            || self.schema.client_prefixes.iter().any(|prefix| {
                !is_valid_env_var_name(prefix) || !prefix.ends_with('_') || !prefixes.insert(prefix)
            });
        if prefixes_invalid {
            errors.push(validation_error(
                "envSchema",
                &EnvVarRule::default(),
                ValidationErrorKind::InvalidRule {
                    message: "clientPrefixes must contain at most 32 unique portable prefixes ending in '_'",
                },
            ));
        }
        let mut matches = PatternSet::new(MAX_PATTERN_BATCH_SIZE);
        for compiled in &self.rules {
            let key = compiled.key;
            let rule = compiled.rule;
            if let Some(message) = crate::scopes::rule_error(rule) {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidRule { message },
                ));
                continue;
            }
            if !is_valid_env_var_name(key) {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidVariableName,
                ));
                continue;
            }
            if rule
                .description
                .iter()
                .chain(rule.pattern.iter())
                .chain(rule.default.iter())
                .chain(rule.defaults_in.iter().map(|default| &default.value))
                .chain(rule.enum_values.iter().flatten())
                .any(|value| {
                    value.chars().any(|character| {
                        matches!(character as u32, 0..=8 | 11..=12 | 14..=31 | 127..=159)
                    })
                })
            {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidRule {
                        message: "schema text cannot contain unsafe control characters",
                    },
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
            let exposure_error = if rule.secret && rule.client {
                Some("secret rules cannot be client-visible")
            } else if rule.secret && rule.ci == Some(crate::CiStorage::Variable) {
                Some("secret rules cannot use readable CI variable storage")
            } else if (EnvSchema::has_framework_client_prefix(key)
                || !prefixes_invalid && self.schema.has_client_prefix(key))
                != rule.client
            {
                Some("client visibility must match a framework or declared client prefix")
            } else {
                None
            };
            if let Some(message) = exposure_error {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidRule { message },
                ));
                continue;
            }
            if rule.secret && (rule.default.is_some() || rule.enum_values.is_some()) {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidRule {
                        message: "secret rules cannot contain literal defaults or enum values",
                    },
                ));
                continue;
            }
            if rule.enum_values.as_ref().is_some_and(Vec::is_empty) {
                errors.push(validation_error(
                    key,
                    rule,
                    ValidationErrorKind::InvalidRule {
                        message: "enum must contain at least one value",
                    },
                ));
                continue;
            }
            for (default, scoped) in rule.default.iter().map(|value| (value, false)).chain(
                rule.defaults_in
                    .iter()
                    .map(|default| (&default.value, true)),
            ) {
                if default.is_empty() && rule.empty == EmptyPolicy::Reject {
                    errors.push(ValidationError {
                        key: key.into(),
                        kind: ValidationErrorKind::Empty,
                        description: None,
                        is_secret: rule.secret,
                    });
                } else if default.is_empty() && rule.required {
                    errors.push(ValidationError {
                        key: key.into(),
                        kind: ValidationErrorKind::Missing,
                        description: None,
                        is_secret: rule.secret,
                    });
                } else {
                    validate_value(
                        key,
                        default,
                        rule,
                        || {
                            pattern.map(|location| {
                                self.matches_pattern(default, location, &mut matches)
                            })
                        },
                        scoped,
                        &mut errors,
                    );
                }
            }
        }
        errors
    }

    /// Validate values and inject only defaults that satisfy their complete rule.
    pub fn validate(&self, env_vars: &mut HashMap<String, String>) -> Vec<ValidationError> {
        self.validate_with_context(env_vars, crate::EvalContext::default())
    }

    /// Validate the same plan for a resolved environment, command stage, and service.
    pub fn validate_with_context(
        &self,
        env_vars: &mut HashMap<String, String>,
        context: crate::EvalContext<'_>,
    ) -> Vec<ValidationError> {
        self.validate_with_default_policy(env_vars, context, |_| true)
    }

    /// Validate values while restricting which absent keys can receive defaults.
    pub fn validate_with_default_policy(
        &self,
        env_vars: &mut HashMap<String, String>,
        context: crate::EvalContext<'_>,
        allow_default: impl Fn(&str) -> bool,
    ) -> Vec<ValidationError> {
        if !self.definition_errors.is_empty() {
            return self.definition_errors.clone();
        }
        if !context.is_valid() {
            return vec![validation_error(
                "envSchema",
                &EnvVarRule::default(),
                ValidationErrorKind::InvalidRule {
                    message: "evaluation context requires valid environment and service names",
                },
            )];
        }
        for compiled in &self.rules {
            let missing = env_vars.get(compiled.key).is_none_or(|value| {
                value.is_empty() && compiled.rule.empty == EmptyPolicy::Missing
            });
            if missing
                && allow_default(compiled.key)
                && let Some(default) = crate::scopes::default_for_context(compiled.rule, context)
            {
                env_vars.insert(compiled.key.to_string(), default.to_string());
            }
        }
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

            let value_is_empty = env_vars.get(key).is_some_and(String::is_empty);
            if value_is_empty && rule.empty == EmptyPolicy::Reject {
                errors.push(validation_error(key, rule, ValidationErrorKind::Empty));
                continue;
            }
            let is_missing_or_empty = !env_vars.contains_key(key)
                || (value_is_empty && rule.empty == EmptyPolicy::Missing);
            let required = rule.required
                || rule
                    .required_in
                    .iter()
                    .any(|selector| selector.matches(context))
                || rule
                    .required_when
                    .as_ref()
                    .is_some_and(|condition| condition.matches(env_vars));
            if is_missing_or_empty {
                if required {
                    errors.push(validation_error(key, rule, ValidationErrorKind::Missing));
                }
            } else if let Some(value) = env_vars.get(key) {
                if value.is_empty() && required {
                    errors.push(validation_error(key, rule, ValidationErrorKind::Missing));
                    continue;
                }
                validate_value(
                    key,
                    value,
                    rule,
                    || {
                        pattern.map(|location| {
                            self.matches_pattern(value, location, &mut matched_patterns)
                        })
                    },
                    false,
                    &mut errors,
                );
            }
        }

        crate::constraints::validate_groups(self.schema, &self.groups, env_vars, &mut errors);
        errors.sort_by(|a, b| a.key.cmp(&b.key));
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

/// Validate declarations and all defaults without requiring environment values.
pub fn validate_schema(schema: &EnvSchema) -> Vec<ValidationError> {
    EnvValidator::new(schema).definition_errors
}

/// Validate a single value against its rule.
fn validate_value(
    key: &str,
    value: &str,
    rule: &EnvVarRule,
    pattern_matches: impl FnOnce() -> Option<bool>,
    declaration: bool,
    errors: &mut Vec<ValidationError>,
) {
    let error = |kind| ValidationError {
        key: key.to_string(),
        kind: if declaration {
            ValidationErrorKind::InvalidRule {
                message: match kind {
                    ValidationErrorKind::InvalidFormat { .. } => {
                        "scoped default does not satisfy its format"
                    }
                    ValidationErrorKind::NotInEnum { .. } => {
                        "scoped default does not satisfy its enum"
                    }
                    ValidationErrorKind::PatternMismatch { .. } => {
                        "scoped default does not satisfy its pattern"
                    }
                    ValidationErrorKind::ConstraintViolation { .. } => {
                        "scoped default does not satisfy its scalar constraints"
                    }
                    _ => "scoped default is not a process environment value",
                },
            }
        } else {
            kind
        },
        description: if declaration {
            None
        } else {
            rule.description.clone()
        },
        is_secret: rule.secret,
    };
    if value.as_bytes().contains(&0) {
        errors.push(error(ValidationErrorKind::InvalidValue));
        return;
    }
    if let Some(format) = &rule.format
        && !validate_format(value, format)
    {
        errors.push(error(ValidationErrorKind::InvalidFormat {
            expected: format.clone(),
            got: retained_value(value, rule.secret || declaration),
        }));
        // Don't check further rules if format is wrong
        return;
    }

    if let Some(constraint) = crate::constraints::value_violation(value, rule) {
        errors.push(error(ValidationErrorKind::ConstraintViolation {
            constraint,
        }));
        return;
    }
    if pattern_matches() == Some(false) {
        errors.push(error(ValidationErrorKind::PatternMismatch {
            pattern: if declaration {
                String::new()
            } else {
                rule.pattern.clone().unwrap_or_default()
            },
            got: retained_value(value, rule.secret || declaration),
        }));
        return;
    }

    // Enum validation
    if let Some(allowed) = &rule.enum_values
        && !allowed.iter().any(|a| a == value)
    {
        errors.push(error(ValidationErrorKind::NotInEnum {
            allowed: if rule.secret || declaration {
                Vec::new()
            } else {
                allowed.clone()
            },
            got: retained_value(value, rule.secret || declaration),
        }));
    }
}

pub(crate) fn validation_error(
    key: &str,
    rule: &EnvVarRule,
    kind: ValidationErrorKind,
) -> ValidationError {
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

/// A URL must have a valid authority and contain no raw whitespace or control characters.
fn validate_url(value: &str) -> bool {
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((scheme, tail)) = value.split_once("://") else {
        return false;
    };
    let authority_end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
    let authority = &tail[..authority_end];
    let hosts = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hosts)| hosts);
    if hosts.is_empty() || hosts.contains(['\\', '^', '{', '}', '|']) {
        return false;
    }
    let special = ["http", "https", "ftp", "file", "ws", "wss"]
        .iter()
        .any(|special| scheme.eq_ignore_ascii_case(special));
    let allow_non_url_code_points = if special && authority.contains('@') {
        let mut without_credentials =
            String::with_capacity(scheme.len() + 3 + hosts.len() + tail.len() - authority_end);
        without_credentials.push_str(scheme);
        without_credentials.push_str("://");
        without_credentials.push_str(hosts);
        without_credentials.push_str(&tail[authority_end..]);
        parsed_url_is_valid(&without_credentials, false)
    } else {
        !special
    };
    let candidate;
    let value = if hosts.contains(',') {
        if special || !hosts.split(',').all(valid_database_endpoint) {
            return false;
        }
        let first = hosts.split(',').next().unwrap_or_default();
        let prefix_end = value.len() - tail.len() + authority.len() - hosts.len();
        let mut normalized =
            String::with_capacity(prefix_end + first.len() + tail.len() - authority_end);
        normalized.push_str(&value[..prefix_end]);
        normalized.push_str(first);
        normalized.push_str(&tail[authority_end..]);
        candidate = normalized;
        candidate.as_str()
    } else {
        value
    };
    parsed_url_is_valid(value, allow_non_url_code_points)
}

fn parsed_url_is_valid(value: &str, allow_non_url_code_points: bool) -> bool {
    let invalid = std::cell::Cell::new(false);
    let on_violation = |violation| {
        if violation != url::SyntaxViolation::EmbeddedCredentials
            && !(allow_non_url_code_points && violation == url::SyntaxViolation::NonUrlCodePoint)
        {
            invalid.set(true);
        }
    };
    url::Url::options()
        .syntax_violation_callback(Some(&on_violation))
        .parse(value)
        .is_ok_and(|url| url.host().is_some())
        && !invalid.get()
}

fn valid_database_endpoint(endpoint: &str) -> bool {
    let (host, port) = if endpoint.starts_with('[') {
        let Some(end) = endpoint.find(']') else {
            return false;
        };
        if endpoint[1..end].parse::<Ipv6Addr>().is_err() {
            return false;
        }
        let suffix = &endpoint[end + 1..];
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        (&endpoint[..=end], Some(port))
    } else {
        match endpoint.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (endpoint, None),
        }
    };
    !host.is_empty()
        && url::Host::parse(host).is_ok()
        && port.is_none_or(|port| {
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        })
}

/// Port: must be a number between 1 and 65535.
fn validate_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Email accepts an ASCII dot-atom local part and a dotted DNS hostname.
fn validate_email(value: &str) -> bool {
    if value.len() > 254 || !value.is_ascii() {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&byte))
        && domain.contains('.')
        && validate_hostname(domain)
}

/// Boolean: must be one of the standard boolean string representations.
fn validate_boolean(value: &str) -> bool {
    matches!(value, "1" | "0")
        || ["true", "false", "yes", "no"]
            .iter()
            .any(|token| value.eq_ignore_ascii_case(token))
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
        EnvSchema {
            vars,
            ..Default::default()
        }
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
    fn database_urls_accept_replica_sets_and_unescaped_credentials() {
        for value in [
            "mongodb://h1:27017,h2:27017/db",
            "postgresql://user:p^ss{word}|@h1:5432,h2:5432/db",
            "postgres://user:p^ss{word}|@host:5432/db",
            "postgres://host:5432/path^{value}|",
            "mongodb://[::1]:27017,[::2]:27017/db",
        ] {
            assert!(validate_url(value), "database URL rejected: {value}");
        }
    }

    #[test]
    fn database_replica_sets_reject_invalid_endpoints() {
        for value in [
            "mongodb://h1:27017,,h2:27017/db",
            "mongodb://h1:27017,h2:invalid/db",
            "mongodb://h1:27017,h2:65536/db",
            "mongodb://h1:27017,:27017/db",
            "mongodb://h1:27017,[invalid]:27017/db",
            "https://h1:443,h2:443/path",
            "https://example.com/{raw}",
            "https://example.com/<raw>",
        ] {
            assert!(!validate_url(value), "invalid URL accepted: {value}");
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
            let schema = EnvSchema {
                vars,
                ..Default::default()
            };

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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            r#"{"clientPrefixes":["APP_"],"vars": {
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
    #[test]
    fn schema_literals_reject_unsafe_metadata_controls() {
        for field in ["description", "pattern", "default"] {
            let schema = schema_from_json(&format!(
                r#"{{"vars":{{"VALUE":{{"{field}":"private\u001b[31m"}}}}}}"#
            ));
            assert!(!validate_schema(&schema).is_empty(), "{field}");
        }
    }

    #[test]
    fn oversized_programmatic_prefix_policy_skips_custom_matching() {
        let schema = EnvSchema {
            client_prefixes: vec!["".into(); 100_000],
            groups: HashMap::new(),
            vars: (0..4096)
                .map(|index| (format!("KEY_{index}"), EnvVarRule::default()))
                .collect(),
        };
        let errors = validate_schema(&schema);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key, "envSchema");
    }

    #[test]
    fn create_react_app_public_prefix_is_case_insensitive() {
        for name in ["react_app_token", "React_App_Token", "REACT_APP_TOKEN"] {
            let schema = schema_from_json(&format!(r#"{{"vars":{{"{name}":{{"secret":true}}}}}}"#));
            assert!(!validate_schema(&schema).is_empty(), "{name}");
        }
    }

    #[test]
    fn secret_client_and_public_prefix_server_rules_are_rejected() {
        for json in [
            r#"{"vars":{"PUBLIC_TOKEN":{"secret":true,"client":true}}}"#,
            r#"{"vars":{"NEXT_PUBLIC_TOKEN":{"secret":true}}}"#,
            r#"{"vars":{"VITE_ENDPOINT":{}}}"#,
            r#"{"vars":{"EXPO_PUBLIC_TOKEN":{"secret":true}}}"#,
            r#"{"vars":{"GATSBY_TOKEN":{"secret":true}}}"#,
            r#"{"vars":{"NUXT_PUBLIC_TOKEN":{"secret":true}}}"#,
        ] {
            assert!(
                !validate_schema(&schema_from_json(json)).is_empty(),
                "{json}"
            );
        }
    }

    #[test]
    fn invalid_prefix_policy_does_not_hide_invalid_variable_rules() {
        let schema = schema_from_json(
            r#"{"clientPrefixes":[""],"vars":{"PUBLIC_TOKEN":{"client":true,"secret":true},"PORT":{"format":"port","default":"99999"}}}"#,
        );
        let errors = validate_schema(&schema);
        assert_eq!(errors.len(), 3);
        assert!(errors.iter().any(|error| error.key == "envSchema"));
        assert!(errors.iter().any(|error| error.key == "PUBLIC_TOKEN"));
        assert!(errors.iter().any(|error| error.key == "PORT"));
    }

    #[test]
    fn client_prefix_and_ci_storage_policies_are_independent() {
        for json in [
            r#"{"vars":{"BUILD_MODE":{"ci":"variable"},"PUBLIC_API":{"client":true}}}"#,
            r#"{"clientPrefixes":["APP_"],"vars":{"APP_API":{"client":true,"ci":"secret"}}}"#,
        ] {
            assert!(validate_schema(&schema_from_json(json)).is_empty());
        }
        for json in [
            r#"{"vars":{"TOKEN":{"secret":true,"ci":"variable"}}}"#,
            r#"{"vars":{"API":{"client":true}}}"#,
            r#"{"clientPrefixes":[""],"vars":{}}"#,
            r#"{"clientPrefixes":["APP_","APP_"],"vars":{}}"#,
        ] {
            assert!(!validate_schema(&schema_from_json(json)).is_empty());
        }
    }

    #[test]
    fn malformed_urls_fail_format_validation() {
        let schema = schema_from_json(r#"{"vars":{"APP_URL":{"format":"url"}}}"#);
        for value in [
            "http://[",
            "ht!tp://example.com",
            "https://example.com:abc",
            "https://host name",
        ] {
            let mut values = HashMap::from([("APP_URL".into(), value.into())]);
            assert!(
                !validate(&schema, &mut values).is_empty(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn malformed_email_fails_format_validation() {
        let schema = schema_from_json(r#"{"vars":{"EMAIL":{"format":"email"}}}"#);
        let mut values = HashMap::from([("EMAIL".into(), "a b@x..com".into())]);
        assert!(!validate(&schema, &mut values).is_empty());
    }

    #[test]
    fn invalid_defaults_fail_even_when_explicit_values_are_valid() {
        let schema = schema_from_json(r#"{"vars":{"PORT":{"format":"port","default":"70000"}}}"#);
        let mut values = HashMap::from([("PORT".into(), "3000".into())]);
        assert!(!validate(&schema, &mut values).is_empty());
        assert_eq!(values["PORT"], "3000");
    }

    #[test]
    fn secret_defaults_are_rejected_without_retaining_the_default() {
        let schema =
            schema_from_json(r#"{"vars":{"TOKEN":{"secret":true,"default":"private-fixture"}}}"#);
        let errors = validate(&schema, &mut HashMap::new());
        assert!(!errors.is_empty());
        assert!(!format!("{errors:?}").contains("private-fixture"));
    }

    #[test]
    fn secret_allowlists_are_rejected_without_retaining_the_literals() {
        let schema =
            schema_from_json(r#"{"vars":{"TOKEN":{"secret":true,"enum":["private-fixture"]}}}"#);
        let errors = validate(&schema, &mut HashMap::new());
        assert!(!errors.is_empty());
        assert!(!format!("{errors:?}").contains("private-fixture"));
    }

    #[test]
    fn reject_empty_policy_rejects_optional_empty_values() {
        let schema = schema_from_json(r#"{"vars":{"VALUE":{"empty":"reject"}}}"#);
        let mut values = HashMap::from([("VALUE".into(), String::new())]);
        assert!(!validate(&schema, &mut values).is_empty());
    }

    #[test]
    fn nul_defaults_and_values_are_rejected_before_process_construction() {
        let schema = schema_from_json(r#"{"vars":{"VALUE":{"default":"a\u0000b"}}}"#);
        assert!(!validate(&schema, &mut HashMap::new()).is_empty());
        let schema = schema_from_json(r#"{"vars":{"VALUE":{}}}"#);
        let mut values = HashMap::from([("VALUE".into(), "a\0b".into())]);
        assert!(!validate(&schema, &mut values).is_empty());
    }
    #[test]
    fn urls_that_require_parser_repairs_are_rejected() {
        for value in [
            "https:///example.com",
            "https:/example.com?next=://foo",
            r"https://example.com\oops",
            "https://example.com/%ZZ",
        ] {
            assert!(!validate_url(value), "{value}");
        }
    }

    #[test]
    fn optional_rejected_empty_default_reports_an_empty_error() {
        let schema = schema_from_json(r#"{"vars":{"OPTIONAL":{"default":"","empty":"reject"}}}"#);
        assert_eq!(validate_schema(&schema)[0].kind, ValidationErrorKind::Empty);
    }

    #[test]
    fn empty_allow_policy_validates_empty_values_without_using_defaults() {
        for default in [None, Some("fallback")] {
            let mut rule = EnvVarRule {
                empty: EmptyPolicy::Allow,
                default: default.map(str::to_string),
                ..Default::default()
            };
            let mut schema = EnvSchema {
                vars: HashMap::from([("VALUE".into(), rule.clone())]),
                ..Default::default()
            };
            let mut values = HashMap::from([("VALUE".into(), "".into())]);
            assert!(validate(&schema, &mut values).is_empty());
            assert_eq!(values["VALUE"], "");
            rule.format = Some(VarFormat::Integer);
            rule.default = default.map(|_| "3".into());
            schema.vars.insert("VALUE".into(), rule.clone());
            assert!(matches!(
                validate(&schema, &mut values)[0].kind,
                ValidationErrorKind::InvalidFormat { .. }
            ));
            rule.format = None;
            rule.required = true;
            schema.vars.insert("VALUE".into(), rule);
            assert_eq!(
                validate(&schema, &mut values)[0].kind,
                ValidationErrorKind::Missing
            );
        }
    }
}

#[cfg(test)]
mod scope_diagnostic_budget_tests {
    use super::*;
    #[test]
    fn global_scope_budget_rejects_before_compiling_rules_or_patterns() {
        let mut vars = serde_json::Map::new();
        for index in 0..129 {
            let selectors: Vec<_> = (0..32)
                .map(|value| serde_json::json!({"environment":[format!("e{value}")]}))
                .collect();
            vars.insert(
                format!("V{index}"),
                serde_json::json!({"pattern":"[a-z]+","requiredIn":selectors}),
            );
        }
        let schema: EnvSchema = serde_json::from_value(serde_json::json!({"vars":vars})).unwrap();
        let plan = EnvValidator::new(&schema);
        assert!(!plan.schema_errors().is_empty());
        assert!(
            plan.rules.is_empty() && plan.pattern_batches.is_empty(),
            "over-budget definitions continued expensive setup"
        );
    }
    #[test]
    fn invalid_scoped_defaults_do_not_multiply_description_or_allowlist_memory() {
        let defaults:Vec<_>=(0..32).map(|value|serde_json::json!({"when":{"environment":[format!("e{value}")]},"value":"invalid"})).collect();
        let schema:EnvSchema=serde_json::from_value(serde_json::json!({"vars":{"VALUE":{"description":"x".repeat(1024*1024),"enum":["y".repeat(1024*1024)],"defaultsIn":defaults}}})).unwrap();
        let plan = EnvValidator::new(&schema);
        assert!(!plan.schema_errors().is_empty());
        let retained: usize = plan
            .schema_errors()
            .iter()
            .map(|error| {
                error.description.as_ref().map_or(0, String::len)
                    + match &error.kind {
                        ValidationErrorKind::NotInEnum { allowed, .. } => {
                            allowed.iter().map(String::len).sum()
                        }
                        _ => 0,
                    }
            })
            .sum();
        assert!(
            retained < 1024 * 1024,
            "definition diagnostics retained {retained} repeated bytes"
        );
    }
}
