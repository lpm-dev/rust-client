const RUNTIME_ENV: &[&str] = &[
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
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
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "NPM_CONFIG_GLOBALCONFIG",
    "NPM_CONFIG_USERCONFIG",
    "INIT_CWD",
    "TMPDIR",
    "TMP",
    "TEMP",
];

pub(crate) fn reserved_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || upper.starts_with("GIT_CONFIG_")
        || RUNTIME_ENV.contains(&upper.as_str())
}
