use std::collections::{BTreeSet, HashMap};

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

pub(in crate::commands) fn build_sanitized_env() -> HashMap<String, String> {
    collect_environment(std::env::vars(), &BTreeSet::new())
}

pub(super) fn build_env_with_approved_names(
    approved: &BTreeSet<String>,
) -> Result<HashMap<String, String>, String> {
    if let Some(name) = approved
        .iter()
        .find(|name| crate::capability::reserved_env_name(name))
    {
        return Err(format!(
            "passEnv cannot override reserved runtime variable {name}"
        ));
    }
    Ok(collect_environment(std::env::vars(), approved))
}

fn collect_environment(
    parent: impl IntoIterator<Item = (String, String)>,
    approved: &BTreeSet<String>,
) -> HashMap<String, String> {
    let mut env = HashMap::with_capacity(BASELINE_ENV.len() + approved.len());
    for (name, value) in parent {
        let upper = name.to_ascii_uppercase();
        #[cfg(windows)]
        let requested = approved.iter().any(|key| key.eq_ignore_ascii_case(&name));
        #[cfg(not(windows))]
        let requested = approved.contains(&name);
        if !crate::capability::reserved_env_name(&name)
            && (requested || BASELINE_ENV.contains(&upper.as_str()))
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
        env.insert(name.to_string(), "/dev/null".to_string());
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
        assert_eq!(env.get("APP_TOKEN").map(String::as_str), Some("dummy"));
        assert!(!env.contains_key("APP_TOKEN_OTHER"));
        assert!(!env.contains_key("OTHER"));
    }
}
