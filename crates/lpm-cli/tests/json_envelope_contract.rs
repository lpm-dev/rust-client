//! Cli-binary survivor — `lpm --json <cmd>` envelope + exit-code contract.
//!
//! Pins two paired contracts that previously drifted in opposite
//! directions:
//!
//! 1. **Envelope universality (finding #76):** every `lpm --json <cmd>`
//!    that errors BEFORE reaching the command's own JSON-output branch
//!    must still emit a structured `{"success": false, "error": ...,
//!    "error_code": ...}` envelope on stdout — not a human-formatted
//!    error on stderr. Pre-fix, a `?` early-exit inside a match arm
//!    body short-circuited `async_main` directly, bypassing the
//!    top-level envelope handler.
//!
//! 2. **Exit-code mirroring (finding #73):** when stdout carries a
//!    `success: false` envelope, the process must exit non-zero. The
//!    contract: exit code mirrors the envelope's `success` field on
//!    every supported path.
//!
//! The outer `async {}.await` fix is structurally universal (it covers
//! every arm at once), but a future refactor that accidentally
//! reintroduces a `.into_diagnostic()?` inside a single arm body would
//! silently regress that arm only. To catch that shape, the matrix
//! below exercises three distinct early-error paths covering three
//! mutually-exclusive arms:
//!
//! - `approve-scripts --group` — `return Err(LpmError::Script(...))`
//!   from an explicit early-return inside the ApproveScripts arm body.
//! - `install --policy=invalid` — `?` early-exit through
//!   `.map_err(LpmError::Script)?` from the policy-parse helper,
//!   inside the Install arm body. Finding #76 named this as a known
//!   pre-fix-failing path.
//! - `use --pin` (without a spec) — explicit `return Err` via
//!   `.ok_or_else(|| LpmError::Script(...))?` from inside the Use arm
//!   body, which was flattened from a per-arm `async {}.await` wrap
//!   to the outer wrap (finding A); this case proves the outer wrap
//!   handles flattened arms correctly.
//!
//! All three need only a bare `package.json` and no network, so the
//! envelope assertion is uncontaminated by unrelated initialisation
//! paths.

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

/// One row of the matrix below. Each row pins both contracts (#76
/// envelope universality, #73 exit-code mirror) on one arm-body
/// shape that the outer-wrap fix must handle uniformly.
struct DispatchCase {
    /// Stable identifier surfaced in assertion failure messages — the
    /// arm under test, NOT the full argv. Reading `dispatch_case = Use`
    /// in a CI log immediately points the next maintainer at the
    /// flattened Use arm in `main.rs`.
    arm: &'static str,
    args: &'static [&'static str],
    /// Substrings the envelope's `error` field MUST contain. We don't
    /// pin the full message because output wording changes with locale
    /// and helper-text updates; we pin the load-bearing tokens
    /// (flag names, validator nouns) that name the actual failure mode.
    expected_error_substrs: &'static [&'static str],
    /// The `error_code` enum tag — `LpmError::error_code()` shape.
    /// Every case below is `LpmError::Script`, so the tag is "script";
    /// pinning it ensures the routing predicate in main.rs
    /// (`matches!(e, ExitCode(_))`) doesn't accidentally swallow this
    /// variant into a generic "internal" classification.
    expected_error_code: &'static str,
}

const CASES: &[DispatchCase] = &[
    // ApproveScripts arm: explicit `return Err(LpmError::Script(...))`
    // path inside the arm body. Pre-finding-#76 this was lost to
    // human stderr.
    DispatchCase {
        arm: "ApproveScripts",
        args: &["--json", "approve-scripts", "--group"],
        expected_error_substrs: &["--group", "--global"],
        expected_error_code: "script",
    },
    // Install arm: `?` early-exit through `.map_err(LpmError::Script)?`
    // from `collapse_policy_flags`. Finding #76 named this as a
    // verified pre-fix-failing path.
    DispatchCase {
        arm: "Install",
        args: &["--json", "install", "--policy=invalid"],
        expected_error_substrs: &["--policy", "invalid"],
        expected_error_code: "script",
    },
    // Use arm: `return Err` via `.ok_or_else()?` from the `--pin
    // (no-spec)` branch. Tests the flattened Use arm specifically —
    // finding A removed its per-arm `async {}.await` wrap so the
    // outer wrap is now the sole envelope route for this arm.
    DispatchCase {
        arm: "Use",
        args: &["--json", "use", "--pin"],
        expected_error_substrs: &["missing version", "lpm use --pin"],
        expected_error_code: "script",
    },
];

/// **Finding #76 contract.** Every `lpm --json <cmd>` whose arm body
/// errors before reaching the command's own JSON-output branch must
/// still emit a structured envelope on stdout. The matrix below
/// exercises three distinct arm-body shapes (explicit `return Err`,
/// `.map_err(...)?`, `.ok_or_else()?`) across three arms.
///
/// The outer `async { match command { ... } }.await` wrap covers all
/// 38 arms by construction; running three rows here catches a
/// regression where someone accidentally reintroduces a
/// `.into_diagnostic()?` inside one arm's body — the wrap stays
/// intact, but THAT arm silently bypasses the envelope handler.
#[test]
fn json_dispatch_early_error_emits_envelope_on_stdout() {
    for case in CASES {
        let (project, lpm_home) = isolated_project_with_package_json();
        let (status, stdout, stderr) = run_lpm(project.path(), lpm_home.path(), None, case.args);

        assert!(
            !status.success(),
            "case={}: early-error `--json` path must exit non-zero \
             (got status={status:?}, stderr={stderr:?})",
            case.arm,
        );

        let envelope = parse_json_stdout(&stdout);
        assert_eq!(
            envelope["success"],
            serde_json::json!(false),
            "case={}: envelope must carry success=false; full envelope={envelope}",
            case.arm,
        );
        assert_eq!(
            envelope["schema_version"],
            serde_json::json!(1),
            "case={}: envelope must carry shared error schema_version=1; full envelope={envelope}",
            case.arm,
        );

        let error_msg = envelope["error"]
            .as_str()
            .unwrap_or_else(|| panic!("case={}: envelope must carry an `error` string", case.arm));
        for needle in case.expected_error_substrs {
            assert!(
                error_msg.contains(needle),
                "case={}: envelope `error` must surface the actual \
                 validator message — needle {needle:?} not in {error_msg:?}",
                case.arm,
            );
        }

        assert_eq!(
            envelope["error_code"],
            serde_json::json!(case.expected_error_code),
            "case={}: envelope must carry the expected error code; full envelope={envelope}",
            case.arm,
        );
    }
}

/// **Finding #73 contract.** When stdout carries `success: false`,
/// exit code MUST be `1` — not just non-zero. Pre-fix, the
/// `?`-early-exit paths that bypassed the envelope also bypassed the
/// exit-code mirror at the bottom of `async_main`. The contract
/// pinned here is the precise direction of the mirror: every
/// supported `LpmError` variant maps to 1 under the top-level handler
/// (the only exception is `LpmError::ExitCode(code)`, which skips the
/// envelope so a command that already wrote its own structured doc
/// can carry an arbitrary code through).
///
/// Tightens the companion test above: code 2 (clap missing-arg) or
/// 101 (panic) also fail this assertion, so a future regression that
/// silently degrades the exit shape is caught.
#[test]
fn json_envelope_failure_exit_code_mirrors_success_field() {
    for case in CASES {
        let (project, lpm_home) = isolated_project_with_package_json();
        let (status, stdout, stderr) = run_lpm(project.path(), lpm_home.path(), None, case.args);

        let envelope = parse_json_stdout(&stdout);
        assert_eq!(
            envelope["success"],
            serde_json::json!(false),
            "case={}: precondition: envelope must report failure on this path \
             (stderr={stderr:?})",
            case.arm,
        );
        assert_eq!(
            envelope["schema_version"],
            serde_json::json!(1),
            "case={}: precondition: envelope must expose shared error schema_version=1 \
             (stderr={stderr:?})",
            case.arm,
        );
        assert_eq!(
            status.code(),
            Some(1),
            "case={}: envelope success=false must mirror to exit code 1 \
             (got code={:?}, full envelope={envelope}, stderr={stderr:?})",
            case.arm,
            status.code(),
        );
    }
}
