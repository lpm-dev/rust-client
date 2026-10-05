//! Inherited environment that LPM removes before spawning a child process.

use std::ffi::OsStr;
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
    inherited_env_key_is_stripped(OsStr::new(name))
}

/// [`inherited_env_is_stripped`] for a key that may not be valid UTF-8. The
/// match runs on the key's bytes, so such a key is still stripped when it
/// ends in a credential suffix.
pub fn inherited_env_key_is_stripped(name: &OsStr) -> bool {
    let upper = name.as_encoded_bytes().to_ascii_uppercase();
    STRIPPED_INHERITED_ENV_PATTERNS
        .iter()
        .any(|pattern| upper == pattern.as_bytes())
        || STRIPPED_INHERITED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix.as_bytes()))
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
    for (key, _value) in std::env::vars_os() {
        if inherited_env_key_is_stripped(&key) {
            cmd.env_remove(&key);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    const CHILD: &str = "LPM_TEST_CHILD_ENV_NON_UTF8";

    /// Re-runs `test` in a child process whose environment holds a non-UTF-8
    /// key and a non-UTF-8 value. Returns true in the parent.
    fn rerun_in_non_utf8_environment(test: &str) -> bool {
        if std::env::var_os(CHILD).is_some() {
            return false;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, "1")
            .env(OsStr::from_bytes(b"LPM_TEST_\xff_TOKEN"), "secret")
            .env("LPM_TEST_PLAIN", OsStr::from_bytes(b"value-\xff"))
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[test]
    fn scrub_handles_non_utf8_environment_entries() {
        if rerun_in_non_utf8_environment(
            "child_env::tests::scrub_handles_non_utf8_environment_entries",
        ) {
            return;
        }
        let mut command = Command::new("/usr/bin/env");
        strip_inherited_env_hooks(&mut command);

        let listed = command.output().unwrap().stdout;
        let lines: Vec<&[u8]> = listed.split(|&byte| byte == b'\n').collect();

        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with(b"LPM_TEST_\xff_TOKEN="))
        );
        assert!(lines.contains(&b"LPM_TEST_PLAIN=value-\xff".as_slice()));
    }

    #[test]
    fn stripped_names_match_without_regard_to_case() {
        assert!(inherited_env_is_stripped("npm_token"));
        assert!(inherited_env_is_stripped("My_Service_Secret"));
        assert!(!inherited_env_is_stripped("PATH"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn inherited_secret_suffix_filter_matches_windows_process_names() {
        let alias = "APP_ſECRET";
        let mut command = Command::new("unused");
        command.env("APP_SECRET", "first").env(alias, "last");
        if command.get_envs().count() == 1 {
            assert!(inherited_env_is_stripped(alias), "Windows secret alias survived");
        }
    }
}
