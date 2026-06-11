use std::collections::HashMap;

/// Env var names stripped from the lifecycle script environment.
/// Mirrors the dotenv loader's `DENIED_ENV_VARS` so the same shape
/// applies whether a value flowed in via parent env or via a `.env`
/// file. `RUSTC` and `CARGO` are intentionally NOT stripped — rustup
/// sets them to its proxy binaries.
const STRIPPED_ENV_PATTERNS: &[&str] = &[
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
    "RUSTC_BOOTSTRAP",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// Env var suffix patterns — any var ending with these is stripped.
const STRIPPED_ENV_SUFFIXES: &[&str] = &[
    "_SECRET",
    "_PASSWORD",
    "_KEY",
    "_PRIVATE_KEY",
    "_KEY_ID",
    "_TOKEN",
    "_URL",
    "_URI",
    "_DSN",
    "_CONNECTION_STRING",
];

pub(super) fn build_sanitized_env() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    for (key, value) in std::env::vars() {
        // Skip explicitly blocked vars
        let upper = key.to_ascii_uppercase();
        if STRIPPED_ENV_PATTERNS.contains(&upper.as_str()) {
            continue;
        }

        // Skip vars matching suffix patterns
        if STRIPPED_ENV_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
        {
            continue;
        }

        env.insert(key, value);
    }

    // lifecycle scripts run with CWD = the package's directory.
    // Nested tools (`git`, `npm`, `python`) consult package-local
    // dotfiles by default — `<pkg>/.gitconfig`, `<pkg>/.npmrc`,
    // `<pkg>/.netrc` — so a malicious package can plant
    // `script-shell=/tmp/evil` or `registry=…attacker…` in a
    // dotfile and have nested tools honour it. Neutralise the
    // discovery path by pointing HOME / GIT_CONFIG_GLOBAL /
    // NPM_CONFIG_GLOBALCONFIG / etc. at /dev/null on Unix (or an
    // empty temp dir on Windows where /dev/null doesn't exist).
    // The package's OWN scripts still run; what we suppress is the
    // implicit "tool reads ./dotfile" surface that the package
    // never asked for and the user never consented to.
    #[cfg(unix)]
    {
        env.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
        env.insert("GIT_CONFIG_SYSTEM".to_string(), "/dev/null".to_string());
        env.insert(
            "NPM_CONFIG_GLOBALCONFIG".to_string(),
            "/dev/null".to_string(),
        );
        env.insert("NPM_CONFIG_USERCONFIG".to_string(), "/dev/null".to_string());
    }

    env
}
