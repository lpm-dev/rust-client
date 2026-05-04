//! Workflow tests for `lpm lint` / `lpm fmt` / `lpm check` workspace mode.
//!
//! These tests exercise the orchestrator's selection, JSON envelope, and
//! failure-mode contracts WITHOUT requiring oxlint / biome / tsc to actually
//! execute — every test runs against the empty-set or spawn-failure paths
//! so they're fast and network-free in CI.

mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

// ─── empty-match contract ───────────────────────────────────────

#[test]
fn lint_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["lint", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm lint");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No packages matched"),
        "expected 'No packages matched' in stderr, got:\n{stderr}"
    );
}

#[test]
fn lint_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "lint",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm lint");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero, got: 0\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched") || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}

// ─── JSON envelope: empty match ─────────────────────────────────

#[test]
fn lint_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "lint", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm lint --json");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(0));
    assert_eq!(json["succeeded"], serde_json::json!(0));
    assert_eq!(json["failed"], serde_json::json!(0));
    assert_eq!(json["members"], serde_json::json!([]));
    assert!(
        json["duration_ms"].is_number(),
        "duration_ms must be numeric"
    );
}

// ─── JSON envelope: spawn failure path ──────────────────────────

#[test]
fn check_workspace_json_emits_valid_envelope_per_member() {
    // `lpm check` shells out to tsc which won't be on PATH inside the isolated
    // test HOME. Each workspace member's spawn fails — exercises the non-exit
    // failure branch (exit_code: null + error field) AND proves the orchestrator
    // emits a single, valid JSON envelope (no interleaved child output).
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        // Strip PATH so tsc cannot be found anywhere — guarantees spawn failure
        // even on a developer machine that has tsc installed globally.
        .env("PATH", "")
        .args(["--json", "check", "--all"])
        .output()
        .expect("failed to run lpm check --all --json");

    assert!(
        !output.status.success(),
        "spawn failures must surface as non-zero exit, got: 0"
    );

    // Verify stdout is a single, valid JSON document — proves child output
    // didn't bleed into the envelope.
    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
            panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
        });

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["succeeded"], serde_json::json!(0));
    assert_eq!(json["failed"], serde_json::json!(3));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3);

    for member in members {
        assert_eq!(member["success"], serde_json::json!(false));
        // exit_code MUST be null (spawn failure, not a non-zero exit)
        assert_eq!(
            member["exit_code"],
            serde_json::Value::Null,
            "spawn failure must have exit_code: null, got: {}",
            member["exit_code"],
        );
        assert!(
            member["error"].is_string(),
            "spawn failure must populate the error field, member: {member}"
        );
        assert!(
            member["duration_ms"].is_number(),
            "duration_ms must be numeric, member: {member}"
        );
    }
}

// ─── --affected with no changes keeps its specific success message ──
//
// Regression guard: the empty-target branch was previously folding every
// empty result into the generic "No packages matched" warning. The
// `--affected --base HEAD` case (no diff vs the base ref) is the common
// "nothing changed" signal and gets its own success message so it doesn't
// read like a filter typo.

#[test]
fn lint_affected_with_no_changes_prints_specific_success_message() {
    use std::process::Command;

    let project = TempProject::from_fixture("workspace-monorepo");

    // Initialize a git repo at HEAD so `--affected --base HEAD` is meaningful
    // and the diff-vs-HEAD set is empty (nothing has changed since HEAD).
    Command::new("git")
        .args(["init", "-q"])
        .current_dir(project.path())
        .status()
        .expect("git init failed");
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(project.path())
        .status()
        .expect("git add failed");
    Command::new("git")
        .args([
            "-c",
            "user.email=t@t.t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ])
        .current_dir(project.path())
        .status()
        .expect("git commit failed");

    let output = lpm(&project)
        .args(["lint", "--affected", "--base", "HEAD"])
        .output()
        .expect("failed to run lpm lint --affected");

    assert!(
        output.status.success(),
        "empty --affected must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nothing to lint") || stderr.contains("no packages affected"),
        "expected affected-specific success message, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("No packages matched"),
        "must not fall into the filter-miss path, got:\n{stderr}"
    );
}

// ─── workspace-mode requires a workspace ────────────────────────

#[test]
fn lint_all_outside_workspace_errors_clearly() {
    let project = TempProject::empty(r#"{"name": "single", "version": "1.0.0"}"#);

    let output = lpm(&project)
        .args(["lint", "--all"])
        .output()
        .expect("failed to run lpm lint --all");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace") || stderr.contains("monorepo"),
        "expected workspace-required error, got:\n{stderr}"
    );
}

// Parser-level coverage for `--filter` / `--fail-if-no-match` lives in
// `crates/lpm-cli/src/commands/tools.rs::tests` (lint_filter_parses_with_grammar,
// fmt_filter_and_check_compose, check_filter_parses). The compat contract that
// positional args don't get claimed by `--filter` falls out of clap's grammar
// (`--filter` is `Vec<String>` requiring the explicit flag).
