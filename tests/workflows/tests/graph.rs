//! Workflow tests for `lpm graph`.
//!
//! Pins the file-write contract for `--format html` (writes to
//! `<project>/.lpm/graph.html`, suppresses auto-open with `--no-open`,
//! warns when `--no-open` is passed without `--format html`) and the
//! graph-level depth contract that every output format must honor.
//!
//! These exercise the real binary so the assertions reflect what users
//! actually see — unit tests at the renderer layer can't pin the
//! file-write side effect or the `output::warn` stderr surface.

mod support;

use support::TempProject;
use support::lpm;

/// Use the existing graph fixture (package.json + lpm.lock with a real
/// transitive shape including a duplicate `ms` package). Copying the
/// fixture into a TempProject keeps each test isolated.
fn graph_fixture() -> TempProject {
    TempProject::from_fixture("graph-project")
}

// ─── --format html writes to .lpm/graph.html ────────────────────────

#[test]
fn graph_html_writes_to_dot_lpm_dir_and_respects_no_open() {
    let project = graph_fixture();

    // `--no-open` is load-bearing here: without it, the test machine
    // could spawn a browser tab during CI / local runs.
    let output = lpm(&project)
        .args(["graph", "--format", "html", "--no-open"])
        .output()
        .expect("failed to run lpm graph");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "lpm graph --format html should succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // File written to the documented location.
    assert!(
        project.file_exists(".lpm/graph.html"),
        ".lpm/graph.html should exist after `lpm graph --format html`"
    );

    let html = project.read_file(".lpm/graph.html");
    assert!(
        html.contains("<!DOCTYPE html>"),
        "graph.html should be a self-contained HTML document"
    );
    assert!(
        html.contains("LPM Dependency Graph"),
        "graph.html should contain the LPM dependency-graph header"
    );
    assert!(
        html.contains("express"),
        "graph.html should include packages from the fixture lockfile"
    );

    // Success message names the path. Goes through cliclack which writes
    // to stderr, so check both streams.
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(".lpm/graph.html") || combined.contains("graph.html"),
        "success message should name the output file: {combined}"
    );
}

#[test]
fn graph_html_writes_human_readable_size() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "html", "--no-open"])
        .output()
        .expect("failed to run lpm graph");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The size suffix must read as KB or MB — never "0 KB" via integer
    // division. The fixture renders well over 1 KB of HTML, so KB is the
    // expected unit.
    assert!(
        combined.contains(" KB)") || combined.contains(" MB)"),
        "size in success message should use a human-readable unit: {combined}"
    );
    assert!(
        !combined.contains("(0 KB)"),
        "size must never collapse to 0 KB via integer truncation: {combined}"
    );
}

// ─── --no-open warns when format is not html ────────────────────────

#[test]
fn graph_no_open_without_html_warns_and_prints_to_stdout() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--no-open", "--format", "json"])
        .output()
        .expect("failed to run lpm graph");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "json format should still succeed:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The warning fires on stderr (cliclack's log::warning writes there).
    assert!(
        stderr.contains("--no-open"),
        "stderr should warn that --no-open has no effect: {stderr}"
    );

    // The actual JSON still goes to stdout, undisturbed.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout should be valid JSON");
    assert_eq!(parsed["success"], serde_json::json!(true));
}

#[test]
fn graph_no_open_warning_suppressed_under_global_json_flag() {
    let project = graph_fixture();

    // `--json` + `--no-open` + `--format json`: no warning should appear,
    // since the JSON flag pins a machine-readable contract on stderr too
    // for tooling that captures both streams.
    let output = lpm(&project)
        .args(["--json", "graph", "--no-open", "--format", "json"])
        .output()
        .expect("failed to run lpm graph");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "graph --json should succeed: stderr: {stderr}"
    );
    assert!(
        !stderr.contains("--no-open"),
        "the human-facing warning must be suppressed under --json: {stderr}"
    );
}

// ─── --depth applied at the graph level ─────────────────────────────

#[test]
fn graph_depth_truncates_json_format() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "json", "--depth", "2"])
        .output()
        .expect("failed to run lpm graph");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "lpm graph --format json --depth 2 should succeed: {stdout}"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout should be valid JSON");
    let names: Vec<&str> = parsed["nodes"]
        .as_array()
        .expect("nodes field should be an array")
        .iter()
        .map(|n| n["name"].as_str().unwrap())
        .collect();

    // --depth 2 keeps root + direct deps. The fixture's direct deps
    // include `express` (and optionally `vitest` from devDeps + the
    // lpm.dev neo.highlight package). Transitives like `ms` (depth 3)
    // and `mime-types` (depth 3) must NOT appear in any format.
    assert!(
        names.contains(&"express"),
        "json should keep the direct dep at depth 2: {names:?}"
    );
    assert!(
        !names.contains(&"ms"),
        "json should drop deep transitive at --depth 2: {names:?}"
    );
    assert!(
        !names.contains(&"mime-types"),
        "json should drop deep transitive at --depth 2: {names:?}"
    );
}

#[test]
fn graph_depth_truncates_html_stats_summary() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "html", "--depth", "2", "--no-open"])
        .output()
        .expect("failed to run lpm graph");
    assert!(output.status.success());

    let html = project.read_file(".lpm/graph.html");
    // The stats summary embedded in the HTML header reports duplicates
    // by name@version. Before the fix, depth-prune did not flow through
    // to the stats summary so `ms@2.0.0` and `ms@2.1.3` would still be
    // listed even after depth truncation removed the nodes themselves.
    assert!(
        !html.contains("ms@2.0.0"),
        "deep transitive must not appear in HTML at --depth 2"
    );
}

/// Pins the 1-based displayed `Max depth` contract end-to-end. The
/// `--depth N` flag and the displayed `Max depth: N` use the same
/// numbering scheme (root = level 1, direct = level 2). Before this
/// landed, `lpm graph --format stats --depth 2` reported "Max depth: 1"
/// because stats derived from the 0-based BFS `node.depth` directly.
#[test]
fn graph_stats_max_depth_matches_flag_input() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "stats", "--depth", "2"])
        .output()
        .expect("failed to run lpm graph");
    assert!(
        output.status.success(),
        "lpm graph --format stats --depth 2 should succeed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Max depth: 2"),
        "stats output should display the 1-based depth matching --depth: {stdout}"
    );

    // JSON mirror: same number, same scheme.
    let json_output = lpm(&project)
        .args(["graph", "--format", "json", "--depth", "2"])
        .output()
        .expect("failed to run lpm graph --format json");
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("stdout should be valid JSON");
    assert_eq!(
        parsed["max_depth"].as_u64(),
        Some(2),
        "json max_depth must match the --depth input: {parsed}"
    );
}
