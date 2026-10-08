//! Rules for stored project env values, shared by every reader of them.

use crate::{CasingConflict, EnvValidator, EvalContext, ValidationError, ValidationErrorKind};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The environment whose stored values an environment without values of its own uses.
pub const DEFAULT_ENVIRONMENT: &str = "default";

const DENIED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "GIT_SSH_COMMAND",
    "BASH_ENV",
    "ENV",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
];

/// Whether LPM refuses to pass `key` to a process from project env, compared
/// without case. The runner drops these variables whatever their source and
/// never fills them from schema defaults.
#[inline]
pub fn is_denied_env_var(key: &str) -> bool {
    DENIED_ENV_VARS
        .iter()
        .any(|denied| key.eq_ignore_ascii_case(denied))
}

/// Whether reading `environment` uses the [`DEFAULT_ENVIRONMENT`]'s stored
/// values, because `environment` has none of its own.
#[inline]
pub fn reads_default_environment(environment: &str, has_own_values: bool) -> bool {
    !has_own_values && environment != DEFAULT_ENVIRONMENT
}

/// What evaluating one environment's stored values at runtime finds.
#[derive(Debug)]
pub struct StoredValuesCheck {
    /// The environment has no stored values of its own, so the
    /// [`DEFAULT_ENVIRONMENT`]'s values were evaluated instead.
    pub reads_default_environment: bool,
    /// Rule violations ordered by key. Unlike the other fields, these can
    /// carry stored values, so callers must not expose them verbatim.
    pub errors: Vec<ValidationError>,
    /// Declared keys without a usable stored value that a schema default fills.
    pub defaults: BTreeMap<String, String>,
    /// Stored keys the runner never passes to a process, ordered by key.
    pub ignored: Vec<String>,
}

/// Evaluate the values stored for `environment` the way the runner does at
/// runtime, without project files or the process environment: select the
/// environment's values, reject unusable values, drop denied variables,
/// give declared keys their declared casing where the host ignores case, then
/// apply the schema. Fails where the runner fails: on names that differ only
/// in case on such a host.
pub fn check_stored_values(
    validator: &EnvValidator<'_>,
    environment: &str,
    environments: &BTreeMap<String, HashMap<String, String>>,
) -> Result<StoredValuesCheck, CasingConflict> {
    check_stored_values_with_case_policy(validator, environment, environments, cfg!(windows))
}

fn check_stored_values_with_case_policy(
    validator: &EnvValidator<'_>,
    environment: &str,
    environments: &BTreeMap<String, HashMap<String, String>>,
    case_insensitive: bool,
) -> Result<StoredValuesCheck, CasingConflict> {
    let own = environments.get(environment);
    let reads_default =
        reads_default_environment(environment, own.is_some_and(|values| !values.is_empty()));
    let stored = if reads_default {
        environments.get(DEFAULT_ENVIRONMENT)
    } else {
        own
    };
    let schema = validator.schema();
    let mut values = HashMap::with_capacity(stored.map_or(0, HashMap::len));
    let mut ignored = Vec::new();
    let mut errors = Vec::new();
    let mut stored_names = case_insensitive.then(BTreeSet::new);
    for (key, value) in stored.into_iter().flatten() {
        if let Some(names) = &mut stored_names
            && !names.insert(crate::EnvName::new(key))
        {
            return Err(CasingConflict::Stored(key.clone()));
        }
        // The runner rejects a NUL anywhere before it drops denied variables.
        let unusable = value.as_bytes().contains(&0);
        let denied = is_denied_env_var(key);
        if unusable && (denied || !schema.vars.contains_key(key)) {
            errors.push(ValidationError {
                key: key.clone(),
                kind: ValidationErrorKind::InvalidValue,
                description: None,
                is_secret: false,
            });
        }
        if denied {
            ignored.push(key.clone());
        } else if !unusable || schema.vars.contains_key(key) {
            values.insert(key.clone(), value.clone());
        }
    }
    ignored.sort_unstable();
    if case_insensitive {
        crate::align_declared_casing(&mut values, schema)?;
    }
    // Declared keys a default can fill, and whether each held an empty value.
    let unset = schema
        .vars
        .keys()
        .filter_map(|key| match values.get(key) {
            None => Some((key.as_str(), false)),
            Some(value) if value.is_empty() => Some((key.as_str(), true)),
            Some(_) => None,
        })
        .collect::<HashMap<_, _>>();
    errors.extend(validator.validate_with_default_policy(
        &mut values,
        EvalContext {
            environment,
            ..Default::default()
        },
        |key| !is_denied_env_var(key),
    ));
    errors.sort_by(|a, b| a.key.cmp(&b.key));
    let defaults = schema
        .vars
        .keys()
        .filter_map(|key| {
            let was_empty = *unset.get(key.as_str())?;
            let value = values.get(key)?;
            (!was_empty || !value.is_empty()).then(|| (key.clone(), value.clone()))
        })
        .collect();
    Ok(StoredValuesCheck {
        reads_default_environment: reads_default,
        errors,
        defaults,
        ignored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_values_cannot_hide_casing_collisions() {
        let schema: crate::EnvSchema = serde_json::from_str(r#"{"vars":{"TOKEN":{}}}"#).unwrap();
        let validator = EnvValidator::new(&schema);
        for (upper, lower, value) in [
            ("NODE_OPTIONS", "node_options", "x"),
            ("UNDECLARED", "undeclared", "\0"),
        ] {
            let stored = environments(&[("default", &[(upper, value), (lower, value)])]);
            for environment in ["default", "production"] {
                assert!(matches!(
                    check_stored_values_with_case_policy(&validator, environment, &stored, true),
                    Err(CasingConflict::Stored(_))
                ));
            }
            assert!(
                check_stored_values_with_case_policy(&validator, "default", &stored, false).is_ok()
            );
        }
    }

    #[test]
    fn denied_variables_match_without_case_and_ordinary_names_pass() {
        assert!(is_denied_env_var("NODE_OPTIONS"));
        assert!(is_denied_env_var("node_options"));
        assert!(is_denied_env_var("Path"));
        assert!(!is_denied_env_var("NODE_ENV"));
        assert!(!is_denied_env_var("DATABASE_URL"));
    }

    fn environments(
        entries: &[(&str, &[(&str, &str)])],
    ) -> BTreeMap<String, HashMap<String, String>> {
        entries
            .iter()
            .map(|(name, values)| {
                let values = values
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect();
                ((*name).to_owned(), values)
            })
            .collect()
    }

    fn codes(check: &StoredValuesCheck) -> Vec<(&str, &'static str)> {
        check
            .errors
            .iter()
            .map(|error| {
                let code = match error.kind {
                    ValidationErrorKind::Missing => "missing",
                    ValidationErrorKind::InvalidFormat { .. } => "format",
                    ValidationErrorKind::InvalidValue => "value",
                    ValidationErrorKind::GroupViolation { .. } => "group",
                    ValidationErrorKind::ConstraintViolation { .. } => "constraint",
                    _ => "other",
                };
                (error.key.as_str(), code)
            })
            .collect()
    }

    #[test]
    fn stored_values_are_checked_with_scoped_rules_and_defaults_for_their_environment() {
        let schema: crate::EnvSchema = serde_json::from_str(
            r#"{"vars":{
                "API_TOKEN":{"secret":true,"requiredIn":[{"environment":["production"]}]},
                "PORT":{"format":"port","default":"3000"},
                "LOG_LEVEL":{"default":"info","defaultsIn":[{"when":{"environment":["production"]},"value":"warn"}]},
                "WORKERS":{"format":"integer","min":"1"}
            }}"#,
        )
        .unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[
            ("default", &[("PORT", "not-a-port"), ("WORKERS", "0")]),
            (
                "production",
                &[("PORT", "8080"), ("NODE_OPTIONS", "--inspect")],
            ),
        ]);

        let default = check_stored_values(&validator, "default", &stored).unwrap();
        assert!(!default.reads_default_environment);
        assert_eq!(
            codes(&default),
            [("PORT", "format"), ("WORKERS", "constraint")]
        );
        assert_eq!(
            default.defaults,
            BTreeMap::from([("LOG_LEVEL".to_owned(), "info".to_owned())])
        );
        assert!(default.ignored.is_empty());

        let production = check_stored_values(&validator, "production", &stored).unwrap();
        assert!(!production.reads_default_environment);
        assert_eq!(codes(&production), [("API_TOKEN", "missing")]);
        assert_eq!(
            production.defaults,
            BTreeMap::from([("LOG_LEVEL".to_owned(), "warn".to_owned())])
        );
        assert_eq!(production.ignored, ["NODE_OPTIONS"]);
    }

    #[test]
    fn an_environment_without_stored_values_is_checked_with_the_default_environments_values() {
        let schema: crate::EnvSchema =
            serde_json::from_str(r#"{"vars":{"DATABASE_URL":{"required":true,"format":"url"}}}"#)
                .unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[
            ("default", &[("DATABASE_URL", "https://db.example.com")]),
            ("staging", &[]),
        ]);
        for environment in ["staging", "preview"] {
            let check = check_stored_values(&validator, environment, &stored).unwrap();
            assert!(check.reads_default_environment, "{environment}");
            assert!(check.errors.is_empty(), "{environment}: {:?}", check.errors);
        }
        let empty = environments(&[("staging", &[])]);
        let check = check_stored_values(&validator, "staging", &empty).unwrap();
        assert!(check.reads_default_environment);
        assert_eq!(codes(&check), [("DATABASE_URL", "missing")]);
    }

    #[test]
    fn denied_and_unusable_stored_values_never_satisfy_rules() {
        let schema: crate::EnvSchema = serde_json::from_str(
            r#"{"vars":{"NODE_OPTIONS":{"required":true},"TOKEN":{},"OTHER":{}},
                "groups":{"credentials":{"mode":"exactlyOne","vars":["TOKEN","OTHER"]}}}"#,
        )
        .unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[(
            "default",
            &[
                ("NODE_OPTIONS", "--require hook"),
                ("TOKEN", "a\0b"),
                ("UNDECLARED", "x\0y"),
                ("OTHER", "set"),
            ],
        )]);
        let check = check_stored_values(&validator, "default", &stored).unwrap();
        assert_eq!(check.ignored, ["NODE_OPTIONS"]);
        assert_eq!(
            codes(&check),
            [
                ("NODE_OPTIONS", "missing"),
                ("OTHER", "group"),
                ("TOKEN", "value"),
                ("TOKEN", "group"),
                ("UNDECLARED", "value"),
            ]
        );
    }

    #[test]
    fn a_denied_variable_with_an_unusable_value_still_fails() {
        let schema: crate::EnvSchema = serde_json::from_str(r#"{"vars":{"TOKEN":{}}}"#).unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[("default", &[("NODE_OPTIONS", "a\0b"), ("TOKEN", "ok")])]);
        let check = check_stored_values(&validator, "default", &stored).unwrap();
        assert_eq!(codes(&check), [("NODE_OPTIONS", "value")]);
        assert_eq!(check.ignored, ["NODE_OPTIONS"]);
    }

    #[test]
    fn hosts_that_ignore_case_check_a_value_under_its_declared_spelling() {
        let schema: crate::EnvSchema =
            serde_json::from_str(r#"{"vars":{"PORT":{"format":"port","default":"3000"}}}"#)
                .unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[("default", &[("port", "invalid")])]);
        let insensitive =
            check_stored_values_with_case_policy(&validator, "default", &stored, true).unwrap();
        assert_eq!(codes(&insensitive), [("PORT", "format")]);
        assert!(insensitive.defaults.is_empty());
        let sensitive =
            check_stored_values_with_case_policy(&validator, "default", &stored, false).unwrap();
        assert!(sensitive.errors.is_empty());
        assert_eq!(
            sensitive.defaults,
            BTreeMap::from([("PORT".to_owned(), "3000".to_owned())])
        );

        let ambiguous = environments(&[("default", &[("port", "1"), ("PORT", "2")])]);
        assert!(matches!(
            check_stored_values_with_case_policy(&validator, "default", &ambiguous, true),
            Err(CasingConflict::Stored(_))
        ));
    }

    #[test]
    fn only_a_named_environment_without_values_reads_the_default_environment() {
        assert!(reads_default_environment("production", false));
        assert!(!reads_default_environment("production", true));
        assert!(!reads_default_environment(DEFAULT_ENVIRONMENT, false));
        assert!(!reads_default_environment(DEFAULT_ENVIRONMENT, true));
    }
}
