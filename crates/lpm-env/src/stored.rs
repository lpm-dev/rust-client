//! Rules for stored project env values, shared by every reader of them.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_variables_match_without_case_and_ordinary_names_pass() {
        assert!(is_denied_env_var("NODE_OPTIONS"));
        assert!(is_denied_env_var("node_options"));
        assert!(is_denied_env_var("Path"));
        assert!(!is_denied_env_var("NODE_ENV"));
        assert!(!is_denied_env_var("DATABASE_URL"));
    }

    #[test]
    fn only_a_named_environment_without_values_reads_the_default_environment() {
        assert!(reads_default_environment("production", false));
        assert!(!reads_default_environment("production", true));
        assert!(!reads_default_environment(DEFAULT_ENVIRONMENT, false));
        assert!(!reads_default_environment(DEFAULT_ENVIRONMENT, true));
    }
}
