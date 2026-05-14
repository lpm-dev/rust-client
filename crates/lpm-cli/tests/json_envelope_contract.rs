//! Cli-binary survivor — `lpm --json <cmd>` envelope + exit-code contract.
//!
//! Pins two paired contracts that previously drifted in opposite
//! directions:
//!
//! 1. **Envelope universality (finding #76):** every `lpm --json <cmd>`
//!    that errors BEFORE reaching the command's own JSON-output branch
//!    must still emit a structured `{"success": false, "error": ...,
//!    "error_code": ...}` envelope on stdout — not a miette-formatted
//!    error on stderr. Pre-fix, a `?` early-exit inside a match arm
//!    body short-circuited `async_main` directly, bypassing the
//!    top-level envelope handler.
//!
//! 2. **Exit-code mirroring (finding #73):** when stdout carries a
//!    `success: false` envelope, the process must exit non-zero. The
//!    contract: exit code mirrors the envelope's `success` field on
//!    every supported path.
//!
//! Repro uses `lpm --json approve-scripts --group` (without
//! `--global`) — a representative early-error path that:
//! - Lives in a match arm before the command's own JSON branch.
//! - Hits a synchronous `return Err(LpmError::Script(...))` path that
//!   pre-fix carried a `.into_diagnostic()` short-circuit to miette.
//! - Requires no network, store state, or workspace seeding beyond a
//!   bare `package.json` — so the envelope assertion is uncontaminated
//!   by unrelated initialisation paths.

mod common;

use common::{parse_json_stdout, run_lpm};
use tempfile::TempDir;

/// Bare `package.json` is the minimum surface needed for the
/// approve-scripts arm to reach its `--group` validator. Any earlier
/// path (workspace discovery, manifest read, etc.) is intentionally
/// out-of-scope — this test pins the dispatch-level contract, not the
/// per-command behaviour.
fn isolated_project_with_package_json() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"json-envelope-fixture","version":"1.0.0"}"#,
    )
    .expect("seed package.json");
    (project, lpm_home)
}

/// **Finding #76 contract.** `lpm --json approve-scripts --group`
/// (without `--global`) takes a `return Err(LpmError::Script(...))`
/// branch inside the match arm body. Pre-fix, this propagated to
/// `async_main`'s outer `Result<(), miette::Report>` and surfaced as a
/// colored miette block on stderr, with no JSON on stdout. Post-fix,
/// the entire dispatch sits inside an outer `async { ... }.await`
/// returning `Result<(), LpmError>`, so the error becomes the value of
/// `result` and the top-level `--json` envelope handler renders it.
#[test]
fn json_dispatch_early_error_emits_envelope_on_stdout() {
    let (project, lpm_home) = isolated_project_with_package_json();
    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "approve-scripts", "--group"],
    );

    assert!(
        !status.success(),
        "early-error `--json` path must exit non-zero (got status={status:?}, stderr={stderr:?})",
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "envelope must carry success=false; full envelope={envelope}",
    );
    let error_msg = envelope["error"]
        .as_str()
        .expect("envelope must carry an `error` string field");
    assert!(
        error_msg.contains("--group") && error_msg.contains("--global"),
        "envelope `error` must surface the actual validator message \
         ({error_msg:?}) — pre-fix this was lost to miette stderr",
    );
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("script"),
        "envelope must carry the LpmError::Script error code so agents \
         can branch on it; full envelope={envelope}",
    );
}

/// **Finding #73 contract.** When stdout carries a
/// `success: false` envelope, exit code MUST be `1`. Pre-fix, the
/// `?`-early-exit paths that bypassed the envelope also bypassed the
/// exit-code mirror at the bottom of `async_main` — leaving CI
/// scripts that branch on `$?` after `lpm --json …` to silently miss
/// the failure encoded inside the envelope. The contract pinned
/// here is the precise direction of the mirror: not just
/// "non-zero", but specifically `1`, because that's what every
/// supported `LpmError` variant maps to under the top-level handler
/// (the only exception is `LpmError::ExitCode(code)`, which skips
/// the envelope path entirely so a command that already wrote its
/// own structured doc can carry an arbitrary code through).
///
/// The companion `json_dispatch_early_error_emits_envelope_on_stdout`
/// test above asserts `!status.success()`. This one tightens the
/// guarantee: it must be `Some(1)`, not just non-zero — so a future
/// regression that accidentally exits 2 (clap's
/// missing-arg semantics) or 101 (panic) on this path also fails the
/// test.
#[test]
fn json_envelope_failure_exit_code_mirrors_success_field() {
    let (project, lpm_home) = isolated_project_with_package_json();
    let (status, stdout, stderr) = run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "approve-scripts", "--group"],
    );

    let envelope = parse_json_stdout(&stdout);
    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "precondition: envelope must report failure on this path \
         (stderr={stderr:?})",
    );
    assert_eq!(
        status.code(),
        Some(1),
        "envelope success=false must mirror to exit code 1 \
         (got code={:?}, full envelope={envelope}, stderr={stderr:?})",
        status.code(),
    );
}
