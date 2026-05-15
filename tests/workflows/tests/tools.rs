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

// ─── Happy-path workspace lint E2E (network-gated) ─────────────
//
// The only test that proves "tool exited 0 across N members" end-to-end.
// Every other tools test exercises empty-set, failure, or detection-failure
// branches. This one downloads oxlint (real network), runs it across three
// workspace members with clean source files, and asserts the success
// envelope shape.
//
// Gated on `LPM_E2E_NETWORK=1` because:
//   - First run downloads ~3-5 MB
//   - Adds ~2-5s to the CI run cold, ~1s warm
//   - Pinning a specific oxlint version in the fixture would silently
//     break when that version retired upstream; following the registry
//     default matches what real users experience but means the test's
//     stability is tied to the shipped plugin version's lint behavior
//     against trivial JS files (clean files → safe).

#[test]
fn lint_all_happy_path_e2e_network_gated() {
    // Explicit truthy gate so `LPM_E2E_NETWORK=0` reads as "off" instead of
    // "set, therefore on." Accepts `1` and `true` (case-insensitive).
    let enabled = std::env::var("LPM_E2E_NETWORK")
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false);
    if !enabled {
        eprintln!(
            "skipping lint_all_happy_path_e2e_network_gated (set LPM_E2E_NETWORK=1 to run; real-network test downloads oxlint)"
        );
        return;
    }

    let project = TempProject::from_fixture("workspace-monorepo-lintable");

    let output = lpm(&project)
        // Suppress the interactive "Plugin not installed. Downloading..." banner
        // so stdout stays a clean JSON envelope. The env var ONLY suppresses
        // the banner — the download itself is unconditional on cache miss.
        .env("LPM_PLUGIN_QUIET", "1")
        .args(["--json", "lint", "--all"])
        .output()
        .expect("failed to run lpm lint --all --json");

    assert!(
        output.status.success(),
        "happy-path lint must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("happy-path workspace lint must emit a single valid JSON envelope. Parse error: {e}\nRaw stdout:\n{raw}\nstderr:\n{}", String::from_utf8_lossy(&output.stderr))
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(
        json["packages"],
        serde_json::json!(3),
        "all 3 workspace members must be in the envelope"
    );
    assert_eq!(json["succeeded"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(0));

    // Reviewer add: prove all three members actually ran by asserting the
    // member array contains entries for each. The fixture is utils → core
    // → app; topology order is preserved by the orchestrator.
    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3, "envelope must list all 3 members");

    let names: std::collections::HashSet<&str> =
        members.iter().filter_map(|m| m["name"].as_str()).collect();
    for expected in &["@test/utils", "@test/core", "@test/app"] {
        assert!(
            names.contains(expected),
            "envelope members must include {expected}, got: {names:?}"
        );
    }

    // Every member should report success and a real exit code.
    for member in members {
        assert_eq!(
            member["success"],
            serde_json::json!(true),
            "every member must succeed in the happy path, got: {member}"
        );
        assert_eq!(
            member["exit_code"],
            serde_json::json!(0),
            "every member must report exit_code: 0, got: {member}"
        );
        // Success-case members must NOT carry stdout/stderr/error fields.
        assert!(
            member.get("stdout").is_none(),
            "success member must not include stdout, got: {member}"
        );
        assert!(
            member.get("stderr").is_none(),
            "success member must not include stderr, got: {member}"
        );
        assert!(
            member.get("error").is_none(),
            "success member must not include error, got: {member}"
        );
    }
}

// Parser-level coverage for `--filter` / `--fail-if-no-match` lives in
// `crates/lpm-cli/src/commands/tools.rs::tests` (lint_filter_parses_with_grammar,
// fmt_filter_and_check_compose, check_filter_parses). The compat contract that
// positional args don't get claimed by `--filter` falls out of clap's grammar
// (`--filter` is `Vec<String>` requiring the explicit flag).

// ─── Test/Bench workspace surface ──────────────────────

#[test]
fn test_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "test",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm test");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );
}

#[test]
fn test_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "test", "--filter", "does-not-exist"])
        .output()
        .expect("failed to run lpm test --json");

    assert!(output.status.success());

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });

    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["packages"], serde_json::json!(0));
    assert_eq!(json["members"], serde_json::json!([]));
}

#[test]
fn test_multi_member_watch_is_rejected_with_count() {
    // Selection resolves to 3 members (--all against the 3-member fixture).
    // Watch must reject with a count-aware message, not the old blanket
    // "workspace mode" wording.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--all", "--watch"])
        .output()
        .expect("failed to run lpm test --all --watch");

    assert!(!output.status.success(), "multi-member watch must reject");

    // The renderer line-wraps long error messages with `│ ` continuation
    // markers, so we assert the load-bearing tokens individually.
    // The renderer line-wraps long error messages with `│ ` continuation
    // markers, so we assert on individual tokens that survive wrapping
    // rather than on multi-word phrases that may get split.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.replace(['\n', '│', ' '], "");
    assert!(
        normalized.contains("resolvesto3members") || normalized.contains("3members"),
        "reject message must surface the actual count, got:\n{stderr}"
    );
    assert!(
        normalized.contains("startonewatcherpermember"),
        "reject must explain the footgun, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm test"),
        "reject must mention `lpm test`, got:\n{stderr}"
    );
    assert!(
        stderr.contains("--filter"),
        "reject must point at narrowing the filter, got:\n{stderr}"
    );
}

#[test]
fn bench_multi_member_watch_is_rejected_with_count() {
    // Symmetric reject for bench — `vitest bench --watch` is just as much
    // a footgun as `vitest run --watch`.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["bench", "--all", "--watch"])
        .output()
        .expect("failed to run lpm bench --all --watch");

    assert!(
        !output.status.success(),
        "multi-member watch must reject for bench too"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.replace(['\n', '│', ' '], "");
    assert!(
        normalized.contains("resolvesto3members") || normalized.contains("3members"),
        "reject must surface the count, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm bench"),
        "reject must reference bench, not test, got:\n{stderr}"
    );
}

/// `lpm --json bench --watch` outside a workspace (so the dispatcher
/// falls through to the single-package path) and without vitest /
/// `scripts.bench` defined emits the "no benchmark runner found"
/// error envelope on stdout. The load-bearing claim is the envelope
/// shape — actual bench runner detection is covered by the existing
/// detect_bench_runner tests in tools.rs.
#[test]
fn bench_no_runner_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"bench-noop","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "bench", "--watch"])
        .output()
        .expect("failed to run lpm --json bench --watch");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json bench --watch error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("benchmark runner") || s.contains("bench")),
        "error must reference the missing-runner condition, got: {envelope}",
    );
}

// ─── one-member watch IS allowed (hands off to single-package) ──
//
// The reviewer caught that the previous blanket reject contradicted the
// documented `lpm test --filter <name> --watch` workaround. The dispatcher
// now resolves selection upfront: when --watch is requested AND the filter
// resolves to exactly one member, hand off to the single-package path
// against that member's directory.
//
// We can't run vitest here without installing it, but we can prove the
// dispatcher took the single-package path: the failure mode shifts from
// the workspace-watch reject to the single-package "no test runner found"
// detection error.

#[test]
fn test_filter_one_member_with_watch_hands_off_to_single_package() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--filter", "@test/app", "--watch"])
        .output()
        .expect("failed to run lpm test --filter @test/app --watch");

    // No runner installed → single-package path errors with detection failure.
    assert!(
        !output.status.success(),
        "no runner installed → single-package failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no test runner found"),
        "must reach single-package detection, got:\n{stderr}"
    );
    // Critically: must NOT have hit the workspace-watch reject.
    assert!(
        !stderr.contains("would start one watcher per member"),
        "must NOT trigger the multi-member watch reject — \
         this is the load-bearing test that the documented workaround works. Got:\n{stderr}"
    );
    assert!(
        !stderr.contains("nothing to watch"),
        "must NOT trigger the empty-selection watch reject. Got:\n{stderr}"
    );
}

#[test]
fn bench_filter_one_member_with_watch_hands_off_to_single_package() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["bench", "--filter", "@test/utils", "--watch"])
        .output()
        .expect("failed to run lpm bench --filter @test/utils --watch");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no benchmark runner found"),
        "must reach single-package bench detection, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("would start one watcher per member"),
        "one-member bench watch must hand off to single-package, got:\n{stderr}"
    );
}

#[test]
fn test_zero_member_watch_rejects_with_nothing_to_watch() {
    // A filter that resolves to zero members + --watch is degenerate. Distinct
    // from the multi-member reject (different message).
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["test", "--filter", "does-not-exist", "--watch"])
        .output()
        .expect("failed to run lpm test --filter does-not-exist --watch");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nothing to watch"),
        "expected the empty-selection watch message, got:\n{stderr}"
    );
}

#[test]
fn test_workspace_json_emits_valid_envelope_per_member() {
    // Mirrors the `check_workspace_json_emits_valid_envelope_per_member` shape
    // for the test runner: every workspace member's detect_test_runner fails
    // (no vitest/jest/mocha installed in the fixture, no scripts.test) so
    // every member surfaces with `exit_code: null` + an `error` string. Proves
    // the test/bench arms route through the same envelope contract as
    // lint/fmt/check.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "test", "--all"])
        .output()
        .expect("failed to run lpm test --all --json");

    assert!(!output.status.success());

    let raw = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_else(|e| {
        panic!("workspace --json must emit a single valid JSON document. Parse error: {e}\nRaw stdout:\n{raw}")
    });

    assert_eq!(json["success"], serde_json::json!(false));
    assert_eq!(json["packages"], serde_json::json!(3));
    assert_eq!(json["failed"], serde_json::json!(3));

    let members = json["members"]
        .as_array()
        .expect("members must be an array");
    assert_eq!(members.len(), 3);

    for member in members {
        assert_eq!(member["success"], serde_json::json!(false));
        assert_eq!(
            member["exit_code"],
            serde_json::Value::Null,
            "detect_test_runner failure must surface as exit_code: null"
        );
        let err = member["error"]
            .as_str()
            .expect("error must be populated for detection failure");
        assert!(
            err.contains("no test runner found"),
            "error must reference the missing-runner cause, got: {err}"
        );
    }
}

// ─── compat-seam end-to-end ────────────────────────────
//
// The reviewer's load-bearing test: prove that `lpm test -- --all` still
// forwards `--all` to the underlying runner after it claims `--all`
// as an LPM workspace flag. We use a `scripts.test` fallback that simply
// echoes a literal sentinel (no shell-positional `$@` — the runner path
// builds a single command string with args appended, not passed as `$@`).

#[test]
fn test_double_dash_still_forwards_recognized_flags_to_runner() {
    // scripts.test = "echo args:" — args are appended to the command string
    // by build_safe_command, so the actual exec is `sh -c "echo args: '--all'"`.
    // Stdout therefore contains `args: --all` only when --all is forwarded,
    // and `args:` alone when --all is claimed by clap as a workspace flag.
    let project = TempProject::empty(
        r#"{
            "name": "compat-test",
            "version": "1.0.0",
            "scripts": { "test": "echo args:" }
        }"#,
    );

    // CASE A: `lpm test -- --all` — `--` is the separator, `--all` must reach
    // the runner.
    let output = lpm(&project)
        .args(["test", "--", "--all"])
        .output()
        .expect("failed to run lpm test -- --all");

    assert!(
        output.status.success(),
        "exit code: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("args: '--all'") || combined.contains("args: --all"),
        "with `--`, --all MUST reach the runner. Got:\n{combined}"
    );
}

#[test]
fn test_no_double_dash_claims_all_as_workspace_flag() {
    // CASE B: `lpm test --all` (no `--` separator) — `--all` is claimed by
    // clap as a workspace flag and must NOT reach the runner. In a single-
    // package project (no workspace), this errors with "no workspace found".
    let project = TempProject::empty(
        r#"{
            "name": "compat-test",
            "version": "1.0.0",
            "scripts": { "test": "echo args:" }
        }"#,
    );

    let output = lpm(&project)
        .args(["test", "--all"])
        .output()
        .expect("failed to run lpm test --all");

    assert!(
        !output.status.success(),
        "without `--`, --all is claimed by clap and triggers workspace mode in a non-workspace"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace") || stderr.contains("monorepo"),
        "expected workspace-required error, got:\n{stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("args:"),
        "the runner must NOT execute when --all enters workspace mode, got stdout:\n{stdout}"
    );
}

// ─── fmt: workspace dispatch + JSON envelope ────────────────────────
//
// These tests cover the orchestrator's selection / failure-mode contract
// without requiring biome to be installed. The empty-match path never
// invokes the underlying formatter, and the `PATH=""` path forces a
// spawn failure to exercise the failure-envelope shape.

#[test]
fn fmt_filter_typo_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["fmt", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt");

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
fn fmt_filter_typo_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "fmt",
            "--filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm fmt");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched") || stderr.contains("--fail-if-no-match"),
        "expected error message mentioning the empty-match condition, got:\n{stderr}"
    );
}

#[test]
fn fmt_filter_typo_json_emits_valid_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "fmt", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt --json");

    assert!(output.status.success(), "fmt --json failed");

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

#[test]
fn fmt_check_flag_is_accepted_alongside_filter() {
    // The mutually-exclusive group rule (clap `conflicts_with_all`)
    // applies to the selection axes — `--all` / `--filter` / `--affected`.
    // `--check` is orthogonal: it must compose with `--filter` without
    // tripping the conflict rule.
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["fmt", "--check", "--filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm fmt --check --filter");

    assert!(
        output.status.success(),
        "fmt --check --filter <typo> empty-match must exit 0, got: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}
