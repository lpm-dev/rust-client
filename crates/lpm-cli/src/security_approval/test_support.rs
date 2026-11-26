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
