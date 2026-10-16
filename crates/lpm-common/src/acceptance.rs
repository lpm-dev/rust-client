//! The check that lets a release build compiled with acceptance-test hooks
//! use file-backed credential storage and test signing keys: only when the
//! acceptance run isolated this machine's state.

use std::path::Path;

/// Whether the environment flag `name` is on: `1`, `true` or `yes`, in any
/// ASCII case.
pub fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        ["1", "true", "yes"]
            .iter()
            .any(|enabled| value.eq_ignore_ascii_case(enabled))
    })
}

/// Whether an acceptance run isolated credential storage:
/// `LPM_ACCEPTANCE_FILE_STORAGE` is on, `ACCEPTANCE_RUN_ID` is set, and both
/// `$HOME` and the LPM root lie strictly inside `ACCEPTANCE_RUN_DIR`.
pub fn acceptance_storage_isolated() -> bool {
    if !env_flag_enabled("LPM_ACCEPTANCE_FILE_STORAGE")
        || std::env::var("ACCEPTANCE_RUN_ID").is_ok_and(|value| value.trim().is_empty())
        || std::env::var_os("ACCEPTANCE_RUN_ID").is_none()
    {
        return false;
    }
    let (Some(run_dir), Some(home)) = (
        std::env::var_os("ACCEPTANCE_RUN_DIR"),
        std::env::var_os("HOME"),
    ) else {
        return false;
    };
    let (Ok(run_dir), Ok(home), Ok(root)) = (
        std::fs::canonicalize(run_dir),
        std::fs::canonicalize(home),
        crate::LpmRoot::from_env(),
    ) else {
        return false;
    };
    strictly_inside(&home, &run_dir) && strictly_inside(&root.identity(), &run_dir)
}

fn strictly_inside(path: &Path, ancestor: &Path) -> bool {
    path != ancestor && path.starts_with(ancestor)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VARIABLES: [&str; 5] = [
        "HOME",
        "LPM_HOME",
        "ACCEPTANCE_RUN_DIR",
        "ACCEPTANCE_RUN_ID",
        "LPM_ACCEPTANCE_FILE_STORAGE",
    ];

    fn with_environment(values: &[(&str, &std::ffi::OsStr)], check: impl FnOnce()) {
        let _guard = crate::paths::test_env_lock();
        let previous: Vec<_> = VARIABLES
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        unsafe {
            for name in VARIABLES {
                std::env::remove_var(name);
            }
            for (name, value) in values {
                std::env::set_var(name, value);
            }
        }
        check();
        unsafe {
            for (name, value) in previous {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn isolation_requires_home_and_lpm_root_inside_the_run_directory() {
        let run = tempfile::tempdir().unwrap();
        let home = run.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let base = [
            ("HOME", home.as_os_str()),
            ("ACCEPTANCE_RUN_DIR", run.path().as_os_str()),
            ("ACCEPTANCE_RUN_ID", "run".as_ref()),
            ("LPM_ACCEPTANCE_FILE_STORAGE", "YES".as_ref()),
        ];

        // The default LPM root follows `$HOME` on Unix. On Windows it is in
        // the user's profile folder, which `$HOME` doesn't move, so only
        // `LPM_HOME` isolates it there.
        with_environment(&base, || {
            assert_eq!(acceptance_storage_isolated(), cfg!(unix));
        });
        let custom_root = run.path().join("custom-root");
        let mut inside = base.to_vec();
        inside.push(("LPM_HOME", custom_root.as_os_str()));
        with_environment(&inside, || assert!(acceptance_storage_isolated()));
        let mut escaped = base.to_vec();
        escaped.push(("LPM_HOME", outside.path().as_os_str()));
        with_environment(&escaped, || assert!(!acceptance_storage_isolated()));
        let mut home_is_run = base.to_vec();
        home_is_run[1] = ("ACCEPTANCE_RUN_DIR", home.as_os_str());
        with_environment(&home_is_run, || assert!(!acceptance_storage_isolated()));
        with_environment(&base[..3], || assert!(!acceptance_storage_isolated()));
    }

    #[test]
    fn flags_accept_one_true_and_yes_in_any_case() {
        for (value, enabled) in [
            ("1", true),
            ("TRUE", true),
            ("Yes", true),
            ("0", false),
            ("on", false),
            ("", false),
        ] {
            with_environment(&[("LPM_ACCEPTANCE_FILE_STORAGE", value.as_ref())], || {
                assert_eq!(
                    env_flag_enabled("LPM_ACCEPTANCE_FILE_STORAGE"),
                    enabled,
                    "{value}"
                );
            });
        }
    }
}
