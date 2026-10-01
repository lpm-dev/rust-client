use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};

/// The environment a lifecycle script or toolchain probe runs with. Values keep
/// their exact bytes, which need not be valid UTF-8.
pub(in crate::commands) type ChildEnvironment = HashMap<OsString, OsString>;

const BASELINE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "CI",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
];

pub(in crate::commands) fn build_sanitized_env() -> ChildEnvironment {
    collect_environment(std::env::vars_os(), &BTreeSet::new())
}

pub(super) fn build_env_with_approved_names(
    approved: &BTreeSet<String>,
) -> Result<ChildEnvironment, String> {
    if let Some(name) = approved
        .iter()
        .find(|name| crate::capability::reserved_env_name(name))
    {
        return Err(format!(
            "passEnv cannot override reserved runtime variable {name}"
        ));
    }
    Ok(collect_environment(std::env::vars_os(), approved))
}

fn collect_environment(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    approved: &BTreeSet<String>,
) -> ChildEnvironment {
    let mut env = HashMap::with_capacity(BASELINE_ENV.len() + approved.len());
    for (name, value) in parent {
        // Every selectable name is ASCII, so a name that is not valid UTF-8
        // can never be selected.
        let Some(text) = name.to_str() else {
            continue;
        };
        #[cfg(windows)]
        let requested = approved.iter().any(|key| key.eq_ignore_ascii_case(text));
        #[cfg(not(windows))]
        let requested = approved.contains(text);
        if !crate::capability::reserved_env_name(text)
            && (requested
                || BASELINE_ENV
                    .iter()
                    .any(|baseline| OsStr::new(baseline).eq_ignore_ascii_case(&name)))
        {
            env.insert(name, value);
        }
    }
    #[cfg(unix)]
    for name in [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_USERCONFIG",
    ] {
        env.insert(name.into(), "/dev/null".into());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_passthrough_does_not_bypass_runtime_environment_reservations() {
        for name in [
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "GIT_CONFIG_COUNT",
            "TMPDIR",
        ] {
            let error =
                build_env_with_approved_names(&BTreeSet::from([name.to_string()])).unwrap_err();
            assert!(error.contains(name));
        }
    }

    #[cfg(unix)]
    #[test]
    fn values_keep_their_bytes_and_names_that_are_not_utf8_are_never_selected() {
        use std::os::unix::ffi::OsStrExt;

        let env = collect_environment(
            [
                (
                    "HOME".into(),
                    OsStr::from_bytes(b"/home/\xff").to_os_string(),
                ),
                (OsStr::from_bytes(b"HOME\xff").to_os_string(), "x".into()),
                (OsStr::from_bytes(b"APP\xff").to_os_string(), "x".into()),
            ],
            &BTreeSet::from(["APP".to_string()]),
        );

        assert_eq!(
            env.get(OsStr::new("HOME"))
                .map(|value| value.as_encoded_bytes()),
            Some(b"/home/\xff".as_slice())
        );
        assert!(env.keys().all(|name| name.to_str().is_some()));
    }

    #[test]
    fn environment_names_are_exact_and_do_not_authorize_similar_secrets() {
        let env = collect_environment(
            [
                ("APP_TOKEN".into(), "dummy".into()),
                ("APP_TOKEN_OTHER".into(), "dummy".into()),
                ("OTHER".into(), "dummy".into()),
            ],
            &BTreeSet::from(["APP_TOKEN".to_string()]),
        );
        assert_eq!(
            env.get(OsStr::new("APP_TOKEN")),
            Some(&OsString::from("dummy"))
        );
        assert!(!env.contains_key(OsStr::new("APP_TOKEN_OTHER")));
        assert!(!env.contains_key(OsStr::new("OTHER")));
    }
}
