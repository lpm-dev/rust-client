/// Test-only deterministic-panic injection hook.
///
/// In debug builds only, when `LPM_TEST_PANIC_AT` matches the stage
/// argument, panics with a recognizable message that includes the stage
/// name. Release builds silently treat this as a no-op.
///
/// **Why a panic, not an error.** The hook exists to drive workflow
/// tests that pin the [`crate::manifest_tx::ManifestTransaction`]
/// Drop-based rollback. Drop fires on `?` early-return AND on panic
/// AND during normal scope exit. A `?`-early-return path can already
/// be tested by injecting a recoverable error (e.g., an invalid
/// `--policy=` flag); the panic path needed a separate hook because
/// no recoverable error reliably triggers Drop after EVERY stage
/// in the install pipeline. SIGKILL bypasses Drop entirely.
///
/// **Stages currently wired in `run_add_packages`:**
///
/// - `"after-snapshot"` — right after
///   `snapshot_install_state` succeeds; the manifest is unchanged.
///   Drop should be a no-op (snapshot bytes == on-disk bytes).
/// - `"after-stage"` — right after
///   `stage_packages_to_manifest` writes the `*` placeholder into
///   `package.json`. Drop must restore the pre-stage bytes — this
///   is the load-bearing test for the rollback contract.
/// - `"after-install"` — right after
///   `run_with_options` returns Ok. The lockfile is now fresh; the
///   manifest still has `*` placeholders. Drop must restore both.
/// - `"after-finalize"` — right after
///   `finalize_packages_in_manifest` resolves the `*` to concrete
///   versions. Drop runs one step before commit; the test asserts
///   the manifest snaps back to its pre-stage shape rather than
///   landing in a half-committed state.
pub(super) fn maybe_test_panic(stage: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    if std::env::var("LPM_TEST_PANIC_AT").as_deref() == Ok(stage) {
        panic!("LPM_TEST_PANIC_AT={stage} (test-only panic injection)");
    }
}

/// Test-only failure injection for the audit-after-install wrapper.
///
/// Returns `true` when the workflow harness has asked us to simulate
/// an audit-pass failure. The install pipeline then skips the real
/// `audit::run_install_summary` call, logs a `tracing::warn!`, and
/// proceeds as if the audit had errored — letting the workflow test
/// pin the "errors degrade to no envelope field, install still exits
/// 0" contract without depending on a real audit failure mode
/// (network outage, store-lock contention, lockfile corruption).
///
/// Gated the same way as [`maybe_test_panic`]: enabled only in debug
/// builds. Production release builds never honor the trigger env.
pub(super) fn maybe_test_audit_after_install_should_fail() -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    std::env::var("LPM_TEST_AUDIT_AFTER_INSTALL_FAIL").as_deref() == Ok("1")
}

pub(super) fn maybe_test_pause_before_local_materialization() {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(marker) = std::env::var("LPM_TEST_PAUSE_BEFORE_LOCAL_MATERIALIZATION") else {
        return;
    };
    let marker = std::path::PathBuf::from(marker);
    std::fs::write(&marker, b"ready").expect("write local materialization test marker");
    let resume = marker.with_extension("resume");
    for _ in 0..1_000 {
        if resume.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for local materialization test resume marker {}",
        resume.display()
    );
}
