//! Rules for stored project env values, shared by every reader of them.

use crate::{CasingConflict, EnvValidator, EvalContext, ValidationError, ValidationErrorKind};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The environment whose stored values an environment without values of its own uses.
pub const DEFAULT_ENVIRONMENT: &str = "default";

/// Names that make a process run code it wasn't asked to run: libraries the
/// dynamic linker preloads, interpreter options and startup files, the module
/// search paths, profilers and libraries a runtime loads, and the helpers and
/// configuration files Git, SSH, Cargo, npm and Yarn execute. Build settings a
/// project deliberately hands its own toolchain, such as `CC`, `RUSTFLAGS` or
/// `JAVA_HOME`, aren't among them.
///
/// .NET reads each runtime setting as `DOTNET_<name>`, falling back to
/// `CORECLR_<name>` for profilers and `COMPlus_<name>` otherwise, so every
/// spelling is listed.
const CODE_RUNNING_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "DOTNET_STARTUP_HOOKS",
    "DOTNET_ADDITIONAL_DEPS",
    "DOTNET_SHARED_STORE",
    "DOTNET_ENABLE_PROFILING",
    "DOTNET_PROFILER",
    "DOTNET_PROFILER_PATH",
    "CORECLR_ENABLE_PROFILING",
    "CORECLR_PROFILER",
    "CORECLR_PROFILER_PATH",
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "DOTNET_ENABLE_NOTIFICATION_PROFILERS",
    "DOTNET_NOTIFICATION_PROFILERS",
    "CORECLR_ENABLE_NOTIFICATION_PROFILERS",
    "CORECLR_NOTIFICATION_PROFILERS",
    "DOTNET_GCNAME",
    "DOTNET_GCPATH",
    "COMPLUS_GCNAME",
    "COMPLUS_GCPATH",
    "DOTNET_JITNAME",
    "COMPLUS_JITNAME",
    "DOTNET_ALTJITNAME",
    "COMPLUS_ALTJITNAME",
    "PHPRC",
    "PHP_INI_SCAN_DIR",
    "LUA_INIT",
    "LUA_PATH",
    "LUA_CPATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_TEMPLATE_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "NPM_CONFIG_GLOBALCONFIG",
    "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_SCRIPT_SHELL",
    "NPM_CONFIG_SHELL",
    "NPM_CONFIG_GIT",
    "NPM_CONFIG_NODE_GYP",
    "NPM_CONFIG_NODE_OPTIONS",
    "YARN_YARN_PATH",
    "YARN_RC_FILENAME",
];

/// Numbered, versioned and per-architecture forms of the names above, such
/// as `GIT_CONFIG_KEY_0`, `LUA_PATH_5_4` and `CORECLR_PROFILER_PATH_64`.
/// `GIT_CONFIG_NOSYSTEM` and the other Git settings that run nothing don't
/// share these prefixes.
const CODE_RUNNING_ENV_PREFIXES: &[&str] = &[
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
    "LUA_INIT_",
    "LUA_PATH_",
    "LUA_CPATH_",
    "DOTNET_PROFILER_PATH_",
    "CORECLR_PROFILER_PATH_",
    "COR_PROFILER_PATH_",
    "DOTNET_NOTIFICATION_PROFILERS_",
    "CORECLR_NOTIFICATION_PROFILERS_",
];

/// Names that describe the process's own environment, which project env
/// never replaces.
const PROCESS_ENV_VARS: &[&str] = &["PATH", "HOME", "LPM_HOME", "USER", "SHELL", "TERM"];

/// Runtime hooks LPM also removes from the environment a process inherits,
/// even when the person's own shell set them, so no value for one reaches a
/// child. Each is also a name project env can't set. Tool settings such as
/// `NPM_CONFIG_USERCONFIG` or `RUSTC_WRAPPER` stay inherited: CI and
/// toolchains set them on purpose.
pub const INHERITED_RUNTIME_HOOKS: &[&str] = &[
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
];

/// Whether no value for `key` reaches a process, from project env or from
/// the shell LPM was started from, compared without ASCII case.
pub fn is_never_passed(key: &str) -> bool {
    INHERITED_RUNTIME_HOOKS
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
}

/// Whether LPM refuses to pass `key` to a process from project env, compared
/// without case. The runner drops these variables whatever their source and
/// never fills them from schema defaults.
#[inline]
pub fn is_denied_env_var(key: &str) -> bool {
    env_var_runs_code(key)
        || PROCESS_ENV_VARS
            .iter()
            .any(|name| key.eq_ignore_ascii_case(name))
}

/// Whether `key` makes a process run code it wasn't asked to run, compared
/// without ASCII case. Windows compares environment names with an uppercase
/// table that leaves lookalikes such as `ſ` and `ı` distinct from `S` and `I`,
/// so no other folding can reach a process under a denied name.
fn env_var_runs_code(key: &str) -> bool {
    let key = key.as_bytes();
    CODE_RUNNING_ENV_VARS
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name.as_bytes()))
        || CODE_RUNNING_ENV_PREFIXES.iter().any(|prefix| {
            key.len() > prefix.len() && key[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
        })
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

    /// Names that make a process run code it wasn't asked to run, beyond
    /// the dynamic linker's: interpreter options and startup files, module
    /// search paths, and the helpers Git, SSH, Cargo and npm execute.
    const CODE_RUNNING: &[&str] = &[
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
        "NODE_PATH",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PERLLIB",
        "GIT_SSH",
        "GIT_PROXY_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_12",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_SCRIPT_SHELL",
        "NPM_CONFIG_NODE_OPTIONS",
        "ZDOTDIR",
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_ENABLE_PROFILING",
        "COR_ENABLE_PROFILING",
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        "LUA_INIT",
        "LUA_INIT_5_4",
        "LUA_PATH",
        "LUA_PATH_5_4",
        "LUA_CPATH",
        "LUA_CPATH_5_3",
        "DOTNET_ADDITIONAL_DEPS",
        "DOTNET_SHARED_STORE",
        "DOTNET_ENABLE_PROFILING",
        "DOTNET_PROFILER",
        "DOTNET_PROFILER_PATH",
        "DOTNET_PROFILER_PATH_64",
        "CORECLR_PROFILER",
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_ARM64",
        "COR_PROFILER",
        "COR_PROFILER_PATH",
        "COR_PROFILER_PATH_32",
        "DOTNET_ENABLE_NOTIFICATION_PROFILERS",
        "DOTNET_NOTIFICATION_PROFILERS",
        "DOTNET_NOTIFICATION_PROFILERS_ARM64",
        "CORECLR_ENABLE_NOTIFICATION_PROFILERS",
        "CORECLR_NOTIFICATION_PROFILERS",
        "CORECLR_NOTIFICATION_PROFILERS_64",
        "DOTNET_GCName",
        "DOTNET_GCPath",
        "COMPlus_GCName",
        "COMPlus_GCPath",
        "DOTNET_JitName",
        "COMPlus_JitName",
        "DOTNET_AltJitName",
        "COMPlus_AltJitName",
        "NPM_CONFIG_NODE_GYP",
        "NPM_CONFIG_GIT",
        "NPM_CONFIG_SHELL",
        "GIT_TEMPLATE_DIR",
        "YARN_YARN_PATH",
        "YARN_RC_FILENAME",
    ];

    #[test]
    fn names_that_make_a_process_run_other_code_are_denied_in_any_case() {
        for name in CODE_RUNNING {
            assert!(is_denied_env_var(name), "{name}");
            assert!(is_denied_env_var(&name.to_ascii_lowercase()), "{name}");
        }
    }

    #[test]
    fn names_ordinary_projects_set_stay_usable() {
        for name in [
            "JAVA_HOME",
            "CARGO_HOME",
            "GEM_HOME",
            "GEM_PATH",
            "RUSTFLAGS",
            "GOFLAGS",
            "CC",
            "CXX",
            "AR",
            "LD",
            "NPM_CONFIG_REGISTRY",
            "NPM_CONFIG_CACHE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
            "GIT_EDITOR",
            "GIT_SEQUENCE_EDITOR",
            "PAGER",
            "GIT_PAGER",
            "TMPDIR",
            "TEMP",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_SSH_VARIANT",
            "SSH_AUTH_SOCK",
            "CLASSPATH_PREFIX",
            "LUA_VERSION",
            "DOTNET_ROOT",
            "DOTNET_ENVIRONMENT",
            "DOTNET_CLI_TELEMETRY_OPTOUT",
            "DOTNET_gcServer",
            "YARN_ENABLE_IMMUTABLE_INSTALLS",
            "NPM_CONFIG_GIT_TAG_VERSION",
        ] {
            assert!(!is_denied_env_var(name), "{name}");
        }
    }

    #[test]
    fn a_stored_code_running_name_is_ignored_and_never_satisfies_a_rule() {
        let schema: crate::EnvSchema =
            serde_json::from_str(r#"{"vars":{"CLASSPATH":{"required":true}}}"#).unwrap();
        let validator = EnvValidator::new(&schema);
        let stored = environments(&[(
            "default",
            &[
                ("CLASSPATH", "evil.jar"),
                ("GIT_CONFIG_KEY_0", "core.sshCommand"),
            ],
        )]);
        let check = check_stored_values(&validator, "default", &stored).unwrap();
        assert_eq!(check.ignored, ["CLASSPATH", "GIT_CONFIG_KEY_0"]);
        assert_eq!(codes(&check), [("CLASSPATH", "missing")]);
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
