use super::prelude::*;
use std::path::Path;

/// Runs `f` with the security store, managed policy and LPM home under
/// `dir`, a fixed signing secret, and native approval answering "approve".
pub(crate) fn with_test_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let policy_path = dir.join("managed-security-policy.toml");
    let lpm_home = dir.join("lpm-home");
    let _env = crate::test_env::ScopedEnv::update([
        ("LPM_HOME", Some(lpm_home.as_os_str().to_owned())),
        (SECURITY_DIR_ENV, Some(dir.as_os_str().to_owned())),
        (
            SECURITY_POLICY_PATH_ENV,
            Some(policy_path.as_os_str().to_owned()),
        ),
        (
            TEST_SECRET_ENV,
            Some(std::ffi::OsString::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
        ),
        (
            TEST_AUTH_RESULT_ENV,
            Some(std::ffi::OsString::from("approve")),
        ),
        ("LPM_NPM_FIREWALL", None),
        ("LPM_EXPERIMENT_NPM_FIREWALL", None),
        ("LPM_PROVENANCE_ENFORCE", None),
        ("LPM_FORCE_FILE_VAULT", None),
    ]);
    f()
}

/// How many `persistent-guarded-attempt` entries the audit log holds.
pub(crate) fn guarded_attempts() -> usize {
    std::fs::read_to_string(super::paths::audit_log_path().unwrap())
        .unwrap_or_default()
        .matches("\"event\":\"persistent-guarded-attempt\"")
        .count()
}

/// The details of every `event` in the audit log, oldest first.
pub(crate) fn audit_details(event: &str) -> Vec<Option<String>> {
    audit_records(event)
        .into_iter()
        .map(|record| record.detail)
        .collect()
}

/// What tests check of an audit record.
#[derive(Debug)]
pub(crate) struct RecordedAudit {
    pub(crate) allowed: bool,
    pub(crate) detail: Option<String>,
    pub(crate) project_root: Option<String>,
}

/// Every `event` in the audit log, oldest first.
pub(crate) fn audit_records(event: &str) -> Vec<RecordedAudit> {
    let Ok(content) = std::fs::read_to_string(audit_log_path().unwrap()) else {
        return Vec::new();
    };
    content
        .lines()
        .map(|line| {
            serde_json::from_str::<SignedAuditEnvelope>(line)
                .unwrap()
                .payload
        })
        .filter(|payload| payload.event == event)
        .map(|payload| RecordedAudit {
            allowed: payload.allowed,
            detail: payload.detail,
            project_root: payload.project_root,
        })
        .collect()
}

thread_local! {
    static RESOLVED_ON_WINDOWS: std::cell::RefCell<Option<(PathBuf, String)>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` with `dir` resolving to `resolved`, a verbatim path such as
/// `\\?\C:\work\app`, the way Windows resolves a directory, so the code that
/// names projects can be tested on every platform.
pub(crate) fn resolving_on_windows<T>(dir: &Path, resolved: &str, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            RESOLVED_ON_WINDOWS.with(|slot| slot.borrow_mut().take());
        }
    }
    RESOLVED_ON_WINDOWS.with(|slot| {
        *slot.borrow_mut() = Some((dir.to_path_buf(), resolved.to_owned()));
    });
    let _reset = Reset;
    f()
}

/// What [`resolving_on_windows`] makes `dir` resolve to, if anything.
pub(super) fn resolved_on_windows(dir: &Path) -> Option<String> {
    RESOLVED_ON_WINDOWS.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(resolving, _)| resolving == dir)
            .map(|(_, resolved)| resolved.clone())
    })
}
