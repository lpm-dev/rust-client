//! Workflow tests for `lpm filter <expr>` — the workspace-dispatch
//! preview primitive. Drives the same `FilterEngine` as `lpm run --filter`,
//! so behavior pinned here also locks the dispatch contract for `run`,
//! `lint`, `fmt`, `check`, `test`, `bench`, `install`, `uninstall`, etc.

mod support;

use support::{TempProject, lpm};

// ─── exact-name selector ───────────────────────────────────────────────

#[test]
fn filter_exact_name_selects_only_that_member() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["filter", "@test/app"])
        .output()
        .expect("failed to run lpm filter");

    assert!(
        output.status.success(),
        "lpm filter on existing member must succeed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let names: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        names,
        vec!["@test/app"],
        "exact-name match must yield exactly one row, got: {names:?}\nfull stdout:\n{stdout}",
    );
}

// ─── glob selector ─────────────────────────────────────────────────────

#[test]
fn filter_glob_matches_multiple_members() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["filter", "@test/*"])
        .output()
        .expect("failed to run lpm filter glob");

    assert!(output.status.success(), "glob filter must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["@test/app", "@test/core", "@test/utils"],
        "@test/* must select all three members, got: {names:?}",
    );
}

// ─── forward closure (deps) ────────────────────────────────────────────

#[test]
fn filter_forward_closure_includes_dependencies() {
    let project = TempProject::from_fixture("workspace-monorepo");

    // app depends on core, core depends on utils. `@test/app...`
    // selects app + its transitive workspace deps (core + utils).
    let output = lpm(&project)
        .args(["filter", "@test/app..."])
        .output()
        .expect("failed to run lpm filter forward closure");

    assert!(output.status.success(), "forward closure must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["@test/app", "@test/core", "@test/utils"],
        "forward closure of @test/app must include all transitive deps, got: {names:?}",
    );
}

// ─── reverse closure (dependents) ──────────────────────────────────────

#[test]
fn filter_reverse_closure_includes_dependents() {
    let project = TempProject::from_fixture("workspace-monorepo");

    // `...@test/utils` selects utils + everything that depends on it
    // (core via direct workspace:*, app via transitive core).
    let output = lpm(&project)
        .args(["filter", "...@test/utils"])
        .output()
        .expect("failed to run lpm filter reverse closure");

    assert!(output.status.success(), "reverse closure must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["@test/app", "@test/core", "@test/utils"],
        "reverse closure of @test/utils must include all dependents, got: {names:?}",
    );
}

// ─── exclusion ─────────────────────────────────────────────────────────

#[test]
fn filter_exclusion_removes_matched_packages() {
    let project = TempProject::from_fixture("workspace-monorepo");

    // Select all then exclude utils.
    let output = lpm(&project)
        .args(["filter", "@test/*", "!@test/utils"])
        .output()
        .expect("failed to run lpm filter with exclusion");

    assert!(output.status.success(), "exclusion filter must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    names.sort();
    assert_eq!(
        names,
        vec!["@test/app", "@test/core"],
        "exclusion must remove @test/utils, got: {names:?}",
    );
}

// ─── empty-match contract ──────────────────────────────────────────────

#[test]
fn filter_no_match_without_fail_flag_exits_zero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["filter", "this-package-does-not-exist"])
        .output()
        .expect("failed to run lpm filter (no match)");

    assert!(
        output.status.success(),
        "empty-match without --fail-if-no-match must exit 0",
    );
}

#[test]
fn filter_no_match_with_fail_flag_exits_nonzero() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args([
            "filter",
            "this-package-does-not-exist",
            "--fail-if-no-match",
        ])
        .output()
        .expect("failed to run lpm filter (no match, fail flag)");

    assert!(
        !output.status.success(),
        "empty-match with --fail-if-no-match must exit non-zero",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace packages matched") || stderr.contains("--fail-if-no-match"),
        "stderr must mention the empty-match condition, got:\n{stderr}",
    );
}

// ─── --json envelope ───────────────────────────────────────────────────

#[test]
fn filter_json_envelope_carries_selected_names_and_count() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "filter", "@test/utils"])
        .output()
        .expect("failed to run lpm filter --json");

    assert!(output.status.success(), "filter --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("filter --json must be valid JSON: {e}\n---\n{stdout}"));

    let selected = envelope["selected"]
        .as_array()
        .expect("selected must be an array");
    assert_eq!(selected.len(), 1, "expected one match: {envelope}");
    assert_eq!(selected[0], serde_json::json!("@test/utils"));
    assert_eq!(envelope["selected_count"], serde_json::json!(1));
    assert_eq!(envelope["total_members"], serde_json::json!(3));
    assert_eq!(envelope["input"], serde_json::json!(["@test/utils"]));
}

#[test]
fn filter_json_envelope_includes_trace_entries() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["--json", "filter", "@test/*"])
        .output()
        .expect("failed to run lpm filter --json glob");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("filter --json must be valid JSON: {e}\n---\n{stdout}"));

    let traces = envelope["traces"]
        .as_array()
        .expect("traces must be an array");
    assert_eq!(
        traces.len(),
        3,
        "every selected member must carry a trace, got {} traces: {envelope}",
        traces.len(),
    );
    for trace in traces {
        assert!(
            trace["package"].is_string(),
            "trace must include package name: {trace}"
        );
        assert!(
            trace["reason"].is_object(),
            "trace must include reason: {trace}"
        );
    }
}

// ─── outside a workspace ───────────────────────────────────────────────

#[test]
fn filter_outside_workspace_fails_with_helpful_message() {
    // A non-monorepo project — `lpm filter` must refuse rather than
    // returning an empty result.
    let project = TempProject::empty(r#"{"name":"single","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["filter", "anything"])
        .output()
        .expect("failed to run lpm filter outside workspace");

    assert!(
        !output.status.success(),
        "filter outside workspace must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace") || stderr.contains("monorepo"),
        "stderr must indicate the workspace requirement, got:\n{stderr}",
    );
}

// ─── --explain mode renders trace ──────────────────────────────────────

#[test]
fn filter_explain_mode_renders_per_package_trace() {
    let project = TempProject::from_fixture("workspace-monorepo");

    let output = lpm(&project)
        .args(["filter", "@test/utils", "--explain"])
        .output()
        .expect("failed to run lpm filter --explain");

    assert!(output.status.success(), "explain mode must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Explain mode shows the reason annotation alongside the name.
    assert!(
        stdout.contains("@test/utils") && stdout.contains("matched"),
        "explain mode must show the match reason, got:\n{stdout}",
    );
}
