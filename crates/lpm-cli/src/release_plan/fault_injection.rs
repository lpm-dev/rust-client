//! Process aborts at fixed release-transaction points, used by hermetic
//! workflow tests to prove crash recovery. Only builds with the
//! `internal-test-sigstore-mock` feature honour them.

use lpm_common::LpmError;

const ABORT_AFTER_MANIFEST_WRITES_ENV: &str =
    "LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_MANIFEST_WRITES";
const ABORT_AFTER_COMMIT_ENV: &str = "LPM_INTERNAL_TEST_RELEASE_ABORT_AFTER_COMMIT";
const ABORT_AFTER_GIT_STAGE_ENV: &str = "LPM_INTERNAL_TEST_VERSION_ABORT_AFTER_GIT_STAGE";

/// Refuses to run when a fault-injection variable is set but this build
/// cannot honour it, so a crash-recovery test never silently runs a release
/// to completion instead of aborting.
pub(crate) fn ensure_fault_injection_supported() -> Result<(), LpmError> {
    if cfg!(feature = "internal-test-sigstore-mock") {
        return Ok(());
    }
    match [
        ABORT_AFTER_MANIFEST_WRITES_ENV,
        ABORT_AFTER_COMMIT_ENV,
        ABORT_AFTER_GIT_STAGE_ENV,
    ]
    .into_iter()
    .find(|name| std::env::var_os(name).is_some())
    {
        Some(name) => Err(LpmError::Registry(format!(
            "{name} is reserved for hermetic workflow tests; this lpm-rs binary was built \
             without the internal-test-sigstore-mock feature (run workflow tests through \
             scripts/ci/with-hermetic-workflow-cli.sh)"
        ))),
        None => Ok(()),
    }
}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(super) fn abort_after_manifest_write(write_count: usize) {
    if std::env::var(ABORT_AFTER_MANIFEST_WRITES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        == Some(write_count)
    {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(super) fn abort_after_manifest_write(_write_count: usize) {}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(super) fn abort_after_release_commit() {
    if std::env::var_os(ABORT_AFTER_COMMIT_ENV).is_some() {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(super) fn abort_after_release_commit() {}

#[cfg(feature = "internal-test-sigstore-mock")]
pub(super) fn abort_after_git_stage(stage: &str) {
    if std::env::var_os(ABORT_AFTER_GIT_STAGE_ENV).is_some_and(|value| value == stage) {
        std::process::abort();
    }
}

#[cfg(not(feature = "internal-test-sigstore-mock"))]
pub(super) fn abort_after_git_stage(_stage: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_injection_variables_are_refused_only_without_the_feature() {
        let _env = crate::test_env::ScopedEnv::set([(ABORT_AFTER_COMMIT_ENV, "1".into())]);
        let result = ensure_fault_injection_supported();
        if cfg!(feature = "internal-test-sigstore-mock") {
            result.expect("feature builds honour fault injection");
        } else {
            let message = result.expect_err("plain builds must refuse").to_string();
            assert!(message.contains(ABORT_AFTER_COMMIT_ENV), "{message}");
            assert!(
                message.contains("with-hermetic-workflow-cli.sh"),
                "{message}"
            );
        }
    }

    #[test]
    fn plain_runs_are_unaffected() {
        let _env = crate::test_env::ScopedEnv::update([
            (ABORT_AFTER_MANIFEST_WRITES_ENV, None),
            (ABORT_AFTER_COMMIT_ENV, None),
            (ABORT_AFTER_GIT_STAGE_ENV, None),
        ]);
        ensure_fault_injection_supported().expect("no fault injection requested");
    }
}
