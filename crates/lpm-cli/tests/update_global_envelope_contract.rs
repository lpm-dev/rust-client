//! Cli-binary survivor — `lpm --json global update` rich-envelope
//! contract.
//!
//! **Tier placement: cli-binary.** This test touches
//! `~/.lpm/global/manifest.toml` and pins binary-level stdout shape, so the
//! workflow tier's per-project `TempProject` model can't isolate cleanly.
//!
//! ## Contract under test
//!
//! `global update` ships its own rich JSON envelope:
//!
//! ```jsonc
//! { "success": false, "dry_run": false, "results": [ ... ] }
//! ```
//!
//! When a package fails to update, `update_global::run` writes this
//! envelope on stdout via `emit_results(...)`, then returns
//! `Err(LpmError::ExitCode(1))` to propagate a non-zero exit status
//! WITHOUT triggering the top-level `--json` envelope handler in
//! `main.rs` — that handler skips emission when it sees
//! `matches!(e, LpmError::ExitCode(_))`. The combination preserves the
//! single-JSON-document contract: agents that parse stdout see exactly
//! one envelope with the per-package failure list, not a generic
//! "{success: false, error: ..., error_code: ...}" envelope tacked on
//! after.
//!
//! ## Why an explicit binary test
//!
//! `update_global/mod.rs` already has a unit test that asserts the
//! function returns `Err(LpmError::ExitCode(1))` on json-mode failure
//! (`run_json_failure_returns_exit_code_not_script_error`). That
//! test pins the Rust-level contract but cannot observe the
//! load-bearing routing predicate in `main.rs::async_main` (lines
//! ~4230) — the `matches!(e, ExitCode(_))` check that decides whether
//! to print the generic envelope. A refactor that flips the predicate
//! to `matches!(e, ExitCode(0))` or drops it entirely would still
//! pass the unit test while silently double-emitting an envelope on
//! the real binary.
//!
//! This file plugs that gap.

mod common;

use common::{parse_json_stdout, run_lpm_with_env};
use lpm_common::LpmRoot;
use lpm_global::{PackageEntry, PackageSource, write_for};
use tempfile::TempDir;
use wiremock::MockServer;

/// Seed `~/.lpm/global/manifest.toml` with a single fake package so
/// `update_global::collect_targets` has something to iterate.
fn seed_minimal_global_manifest(lpm_home: &std::path::Path, package: &str, version: &str) {
    let root = LpmRoot::from_dir(lpm_home);
    std::fs::create_dir_all(root.global_root()).unwrap();
    let mut manifest = lpm_global::GlobalManifest::default();
    manifest.packages.insert(
        package.to_string(),
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: version.into(),
            integrity: format!("sha512-{package}-{version}-fixture"),
            source: PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: format!("installs/{package}@{version}"),
            commands: vec![],
        },
    );
    write_for(&root, &manifest).unwrap();
}

/// **Finding C contract.** A failed `lpm --json global update` must
/// write exactly ONE JSON document on stdout — the rich envelope from
/// `emit_results(...)` — and exit non-zero. The generic
/// `{"success": false, "error": ..., "error_code": ...}` envelope
/// from `main.rs` must NOT appear after.
#[tokio::test]
async fn json_update_global_failure_emits_rich_envelope_only() {
    // wiremock with no routes mounted → every metadata fetch 404s.
    // Deterministic enough to drive `UpgradeResult::Failed` without
    // depending on real network state.
    let mock = MockServer::start().await;

    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");
    seed_minimal_global_manifest(lpm_home.path(), "ghost-pkg", "1.0.0");

    let (status, stdout, stderr) = run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&mock.uri()),
        &[],
        &["--json", "global", "update"],
    );

    // (1) Exit code is 1 — `Err(LpmError::ExitCode(1))` from `run` is
    //     forwarded verbatim by the top-level `match e { ExitCode(c)
    //     => process::exit(*c) }` arm.
    assert_eq!(
        status.code(),
        Some(1),
        "rich-envelope failure must exit 1 (got code={:?}, stdout={stdout:?}, stderr={stderr:?})",
        status.code(),
    );

    // (2) stdout parses as exactly one JSON document.
    let envelope = parse_json_stdout(&stdout);

    // (3) Envelope is the RICH shape — has `results`, no `error_code`.
    //     The presence of `results` is the positive marker; the
    //     absence of `error_code` is the negative one. Both are
    //     load-bearing — a future regression that emits both the
    //     rich AND the generic envelope would either (a) make
    //     `parse_json_stdout` fail (two documents, not parseable as
    //     one) or (b) drop one of the two markers.
    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "rich envelope must carry success=false; full envelope={envelope}",
    );
    assert!(
        envelope["results"].is_array(),
        "rich envelope must carry a `results` array (rich shape — \
         the command-specific envelope was once emitted before the generic envelope, which \
         would have replaced it). Full envelope={envelope}",
    );
    assert!(
        envelope.get("error_code").is_none(),
        "rich envelope must NOT carry `error_code` — that field only \
         exists on the GENERIC envelope emitted by `main.rs`'s top-level \
         handler. Its presence would mean the routing predicate \
         `matches!(e, ExitCode(_))` no longer skips emission, and the \
         rich envelope was clobbered. Full envelope={envelope}",
    );

    // (4) The rich envelope's `results` contains an entry for the
    //     seeded package with `action: "failed"`. This pins the
    //     per-package detail that distinguishes the rich envelope
    //     from a stub "success: false" — a future regression that
    //     collapses to a single success-flag envelope without the
    //     per-package list would fail here.
    let results = envelope["results"].as_array().expect("results is array");
    let ghost = results
        .iter()
        .find(|r| r["package"] == serde_json::json!("ghost-pkg"))
        .unwrap_or_else(|| panic!("results must include ghost-pkg entry: {envelope}"));
    assert_eq!(
        ghost["action"],
        serde_json::json!("failed"),
        "ghost-pkg must surface as `failed` since the wiremock 404s its \
         metadata fetch: {envelope}",
    );
}

// Note: the rich-envelope test above ALSO catches routing-predicate
// regressions implicitly — if `matches!(e, ExitCode(_))` in main.rs
// flips, stdout would carry two JSON documents (rich + generic) and
// `parse_json_stdout` would fail with a serde "trailing characters"
// panic naming both envelopes verbatim. A dedicated routing-predicate
// test was prototyped here but removed as redundant; the single test
// above is sufficient because its assertions reach inside the parsed
// envelope (the negative `error_code is None` assertion is the
// load-bearing one — a double-emit can't satisfy it).

/// L46. `lpm --json global update --dry-run` against a manifest whose
/// packages all fail to plan (wiremock 404s every metadata fetch) must
/// surface `"success": false` AND exit non-zero. Pre-fix `emit_dry_run`
/// hard-coded `"success": true` and `run` returned `Ok(())` after the
/// dry-run emit regardless of planning outcome, so automation that
/// gated on the top-level success flag treated corrupt manifest rows
/// or registry failures as a healthy diagnostic outcome.
#[tokio::test]
async fn json_update_global_dry_run_failure_surfaces_non_zero_success_and_exit_code() {
    let mock = MockServer::start().await;

    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");
    seed_minimal_global_manifest(lpm_home.path(), "phantom-pkg", "1.0.0");

    let (status, stdout, stderr) = run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        Some(&mock.uri()),
        &[],
        &["--json", "global", "update", "--dry-run"],
    );

    assert_eq!(
        status.code(),
        Some(1),
        "L46: dry-run with any PlanError must exit 1 (got code={:?}, stdout={stdout:?}, stderr={stderr:?})",
        status.code(),
    );

    let envelope = parse_json_stdout(&stdout);

    assert_eq!(
        envelope["success"],
        serde_json::json!(false),
        "L46: top-level success must be false when any plan failed; envelope={envelope}",
    );
    assert_eq!(
        envelope["dry_run"],
        serde_json::json!(true),
        "L46: dry_run flag must still be true; envelope={envelope}",
    );
    let plans = envelope["plans"].as_array().expect("plans is array");
    let phantom = plans
        .iter()
        .find(|p| p["package"] == serde_json::json!("phantom-pkg"))
        .unwrap_or_else(|| panic!("plans must include phantom-pkg entry: {envelope}"));
    assert_eq!(
        phantom["action"],
        serde_json::json!("plan_error"),
        "phantom-pkg must surface as plan_error since wiremock 404s its metadata: {envelope}",
    );
    assert!(
        envelope.get("error_code").is_none(),
        "L46: rich dry-run envelope must NOT carry `error_code` — that field belongs to the \
         generic top-level envelope from main.rs. The `LpmError::ExitCode(1)` return from `run` \
         is what suppresses the generic envelope; presence here means the routing predicate broke.",
    );
}
