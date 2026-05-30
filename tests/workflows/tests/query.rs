//! Workflow tests for `lpm query <selector>` and its flag variants.
//!
//! Query inspects the resolved tree (lockfile or `node_modules/`) and
//! filters by behavioral tags + dependency relationships. These tests
//! seed a non-LPM-managed project (no `lpm.lock`) so discovery falls
//! through to `node_modules/`, and each package carries real source
//! code that the behavioral analyzer will flag.
//!
//! Why real source code instead of a hand-crafted `.lpm-security.json`:
//! the inventory's fallback path for non-store projects calls
//! `analyze_package` (the *uncached* entry point) directly, so a
//! sidecar file is never consulted in this code path.

mod support;

use support::{TempProject, lpm};

/// Seed a package with a tiny `package.json` plus one JS source file
/// containing the patterns required to trigger the requested tags.
fn seed_pkg_with_source(project: &TempProject, name: &str, version: &str, source: &str) {
    let pkg = serde_json::json!({ "name": name, "version": version });
    project.write_file(
        &format!("node_modules/{name}/package.json"),
        &pkg.to_string(),
    );
    project.write_file(&format!("node_modules/{name}/index.js"), source);
}

/// Source patterns derived from `crates/lpm-security/src/behavioral/source.rs`.
const SRC_EVAL: &str = "module.exports = function () { eval('1+1') }\n";
const SRC_NETWORK: &str = "module.exports = function () { fetch('https://example.com') }\n";
const SRC_EVAL_AND_NETWORK: &str =
    "module.exports = function () { eval('1+1'); fetch('https://example.com') }\n";
const SRC_CLEAN: &str = "module.exports = function () { return 42 }\n";

// ─── basic selector ───────────────────────────────────────────────────

#[test]
fn query_eval_selects_only_packages_with_eval_tag() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval"])
        .output()
        .expect("failed to run lpm query :eval");

    assert!(
        output.status.success(),
        "query :eval must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-pkg"),
        "stdout must list eval-pkg, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("clean-pkg"),
        "stdout must NOT list clean-pkg (no eval), got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! 1 package matched :eval"),
        "query must report a slim match summary, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('▲'),
        "query status output must not use legacy/cliclack glyphs, got:\n{stderr}"
    );
}

// ─── --json format ────────────────────────────────────────────────────

#[test]
fn query_eval_json_carries_matched_array() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["--json", "query", ":eval"])
        .output()
        .expect("failed to run lpm query :eval --json");

    assert!(output.status.success(), "query :eval --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("query --json must be valid JSON: {e}\n---\n{stdout}"));

    let arr = envelope
        .as_array()
        .expect("query --json must emit a top-level array");
    assert_eq!(arr.len(), 1, "exactly one match expected: {envelope}");
    assert_eq!(arr[0]["name"], serde_json::json!("eval-pkg"));
    assert_eq!(arr[0]["version"], serde_json::json!("1.0.0"));
}

// ─── --count ──────────────────────────────────────────────────────────

#[test]
fn query_count_mode_emits_tag_counts_grouped_by_severity() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["--json", "query", "--count"])
        .output()
        .expect("failed to run lpm query --count --json");

    assert!(
        output.status.success(),
        "query --count --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("query --count --json must be valid JSON: {e}\n---\n{stdout}"));

    let json_str = envelope.to_string();
    assert!(
        json_str.contains("\"eval\""),
        "count output must mention the eval tag, got:\n{json_str}",
    );
}

// ─── --assert-none ─────────────────────────────────────────────────────

#[test]
fn query_assert_none_exits_zero_when_match_set_empty() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .output()
        .expect("failed to run lpm query --assert-none");

    assert!(
        output.status.success(),
        "--assert-none on empty match must exit 0\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn query_assert_none_exits_nonzero_when_at_least_one_matches() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);

    let output = lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .output()
        .expect("failed to run lpm query :eval --assert-none");

    assert!(
        !output.status.success(),
        "--assert-none must exit non-zero when packages matched the selector"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("assertion") || stderr.contains("matched"),
        "stderr must explain the assertion failure, got:\n{stderr}",
    );
}

// ─── selector combinators ─────────────────────────────────────────────

#[test]
fn query_intersection_selector_requires_both_tags() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-and-net":"^1.0.0","eval-only":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-and-net", "1.0.0", SRC_EVAL_AND_NETWORK);
    seed_pkg_with_source(&project, "eval-only", "1.0.0", SRC_EVAL);

    let output = lpm(&project)
        .args(["query", ":eval:network"])
        .output()
        .expect("failed to run lpm query :eval:network");

    assert!(
        output.status.success(),
        "intersection selector must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-and-net"),
        "intersection must include package with BOTH tags, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("eval-only"),
        "intersection must exclude package with only one tag, got:\n{stdout}",
    );
}

#[test]
fn query_union_selector_includes_either_tag() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","net-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "net-pkg", "1.0.0", SRC_NETWORK);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval,:network"])
        .output()
        .expect("failed to run lpm query :eval,:network");

    assert!(output.status.success(), "union selector must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-pkg") && stdout.contains("net-pkg"),
        "union must include both eval-pkg and net-pkg, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("clean-pkg"),
        "union must exclude clean-pkg (no tag matches), got:\n{stdout}",
    );
}

// ─── unknown selector ─────────────────────────────────────────────────

#[test]
fn query_invalid_selector_syntax_fails_with_helpful_error() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", "::::::nonsense"])
        .output()
        .expect("failed to run lpm query with bad selector");

    assert!(
        !output.status.success(),
        "invalid selector must exit non-zero"
    );
}

// ─── empty match ──────────────────────────────────────────────────────

#[test]
fn query_no_match_human_output_indicates_zero_packages() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":crypto"])
        .output()
        .expect("failed to run lpm query :crypto (no match)");

    assert!(output.status.success(), "empty match must exit 0");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No packages match :crypto"),
        "stderr must indicate zero matches with slim UI, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('▲'),
        "query empty-match status output must not use legacy/cliclack glyphs, got:\n{stderr}",
    );
}
