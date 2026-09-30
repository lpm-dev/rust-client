//! Inherited environment that LPM removes before spawning a child process.

use std::process::Command;

/// Inherited-env names that MUST be stripped from any `lpm run` /
/// `lpm exec` child before spawn.
///
/// The script runner spawns a platform shell without clearing the inherited
/// process environment, so credentials and runtime-injection hooks must be
/// removed explicitly before project env values are added.
///
/// We can't `env_clear` outright — legitimate scripts depend on
/// `HOME`, `USER`, `LANG`, `PATH`, etc. Instead each entry is removed
/// explicitly.
///
/// Credential carriers + dynamic-linker hijacks live in one list;
/// suffix-shaped patterns (`*_SECRET`, `*_TOKEN`, etc.) get
/// stripped programmatically via `STRIPPED_INHERITED_ENV_SUFFIXES`.
const STRIPPED_INHERITED_ENV_PATTERNS: &[&str] = &[
    // Credential carriers
    "LPM_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "LPM_KEY_PASSPHRASE",
    // Runtime-hijack carriers
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

const STRIPPED_INHERITED_ENV_SUFFIXES: &[&str] = &[
    "_SECRET",
    "_PASSWORD",
    "_KEY",
    "_PRIVATE_KEY",
    "_KEY_ID",
    "_TOKEN",
];

/// Whether LPM removes the inherited variable `name` from its child processes.
pub fn inherited_env_is_stripped(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    STRIPPED_INHERITED_ENV_PATTERNS.contains(&upper.as_str())
        || STRIPPED_INHERITED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
}

/// Strip credential + runtime-hijack inherited env vars from `cmd`
/// before spawn. Must run before any `command.envs(...)` that adds
/// project-resolved `.env` values, so a project that legitimately
/// overrides one of these names via its `.env` file (rare) still
/// takes effect.
///
/// Whitelisted: explicit project `envs` map values flowing through
/// `ShellCommand.envs`, since those are project-controlled and
/// already gated by the project's `.env` policy.
pub fn strip_inherited_env_hooks(cmd: &mut Command) {
    for &pattern in STRIPPED_INHERITED_ENV_PATTERNS {
        cmd.env_remove(pattern);
    }
    for (key, _value) in std::env::vars() {
        if inherited_env_is_stripped(&key) {
            cmd.env_remove(&key);
        }
    }
}
