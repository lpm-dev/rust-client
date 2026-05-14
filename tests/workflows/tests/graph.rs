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

// ─── bare `lpm graph` (tree default): --json error envelope ──────────

/// `lpm --json graph` on a project without `lpm.lock` must surface the
/// missing-lockfile error as a JSON envelope on stdout (not a free-form
/// stderr message). The default `tree` format renderer doesn't emit a
/// success envelope — that's `--format json` (a separate surface). The
/// load-bearing claim on the bare-tree surface is the error path's
/// envelope shape.
#[test]
fn graph_bare_under_json_without_lockfile_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"graph-bare","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "graph"])
        .output()
        .expect("failed to run lpm --json graph");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json graph must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("lpm.lock") || s.contains("lockfile")),
        "error message must reference the missing lockfile, got: {envelope}",
    );
}

/// `lpm --json graph --format html --no-open` on a project without
/// `lpm.lock` surfaces the missing-lockfile error as a JSON envelope.
/// Pins the contract that `--format html`'s failure mode is
/// machine-readable; the happy path (file emission) is covered by
/// `graph_html_writes_*` below and is intentionally non-JSON (it
/// writes an HTML file, not an envelope).
#[test]
fn graph_format_html_under_json_without_lockfile_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"graph-html","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "graph", "--format", "html", "--no-open"])
        .output()
        .expect("failed to run lpm --json graph --format html");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json graph --format html must emit JSON on error: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("lpm.lock") || s.contains("lockfile")),
        "error must reference the missing lockfile, got: {envelope}",
    );
}

/// `--format dot`, `--format mermaid`, and `--format stats` share the
/// same lockfile-read prelude as the rest of `lpm graph`. On a
/// missing-lockfile project, all three surface the same error envelope
/// on stdout under `--json`. One test covers the contract for the
/// whole group — the per-format text rendering on the happy path is
/// covered by the existing `graph_format_dot_emits_valid_dot_syntax_to_stdout`
/// and friends below.
#[test]
fn graph_format_dot_mermaid_stats_under_json_without_lockfile_emit_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"graph-fmt","version":"1.0.0"}"#);

    for format in ["dot", "mermaid", "stats"] {
        let output = lpm(&project)
            .args(["--json", "graph", "--format", format])
            .output()
            .expect("failed to run lpm --json graph --format <fmt>");

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("--json graph --format {format} must emit JSON: {e}\n---\n{stdout}")
        });
        assert_eq!(
            envelope["success"],
            serde_json::json!(false),
            "graph --format {format} envelope must carry success: false"
        );
        assert!(
            envelope["error"]
                .as_str()
                .is_some_and(|s| s.contains("lpm.lock") || s.contains("lockfile")),
            "graph --format {format} error must reference the missing lockfile, got: {envelope}",
        );
    }
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

// ─── Phase 65 Step 6.2d-ii — `lpm graph --why <pkg>` overrides trace ────
//
// When `.lpm/overrides-state.json` records an applied override for a
// package, `lpm graph --why <pkg>` decorates output (human + JSON) with
// the from→to summary. The state file is the source of truth — graph
// loads it directly, no install pipeline needed.

/// UTF-8-safe ANSI escape stripper. Iterates `chars()` and skips CSI
/// sequences without re-encoding bytes individually.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Synthetic `lpm.lock` containing the given `(name, version, deps)` entries.
fn write_simple_lockfile(project: &TempProject, entries: &[(&str, &str, &[&str])]) {
    let pkgs: Vec<String> = entries
        .iter()
        .map(|(name, version, deps)| {
            let deps_block = if deps.is_empty() {
                String::new()
            } else {
                let inner = deps
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("\ndependencies = [{inner}]")
            };
            format!("[[packages]]\nname = \"{name}\"\nversion = \"{version}\"{deps_block}\n")
        })
        .collect();
    let toml = format!(
        "[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n\n{}\n",
        pkgs.join("\n")
    );
    project.write_file("lpm.lock", &toml);
}

/// Write a synthetic `.lpm/overrides-state.json`. Mirrors what the
/// install pipeline persists; lets these graph tests run without
/// driving a real install.
fn write_overrides_state(
    project: &TempProject,
    fingerprint: &str,
    parsed: &[(&str, &str)],
    applied: &[(&str, &str, &str, Option<&str>)],
) {
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(key, target)| {
            serde_json::json!({
                "raw_key": key,
                "source": "lpm.overrides",
                "selector": { "kind": "name", "name": key },
                "target": target,
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(|(pkg, from, to, via)| {
            serde_json::json!({
                "raw_key": pkg,
                "source": "lpm.overrides",
                "package": pkg,
                "from_version": from,
                "to_version": to,
                "via_parent": via,
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-11T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    project.write_file(
        ".lpm/overrides-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Human output of `lpm graph --why <pkg>` shows the override section
/// with the from→to summary and a source reference.
#[test]
fn graph_why_human_output_shows_override_trace() {
    let project = TempProject::empty(
        r#"{"name":"why-human-trace","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    write_overrides_state(
        &project,
        "sha256-test-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let out = lpm(&project)
        .args(["graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why");
    assert!(
        out.status.success(),
        "graph --why must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(
        stdout_clean.contains("Overrides applied to this package"),
        "human output must show override section; got:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("4.17.21 → 4.17.20"),
        "human output must show from→to; got:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("lpm.overrides.lodash"),
        "human output must reference source; got:\n{stdout_clean}"
    );
}

/// `lpm graph --why <pkg> --json` emits an `applied_overrides` array
/// populated from `.lpm/overrides-state.json`. Per-entry fields:
/// `package`, `from_version`, `to_version`, `via_parent`.
#[test]
fn graph_why_json_output_includes_applied_overrides() {
    let project = TempProject::empty(
        r#"{"name":"why-json-trace","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    write_overrides_state(
        &project,
        "sha256-test-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", Some("debug"))],
    );

    let out = lpm(&project)
        .args(["--json", "graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why --json");
    assert!(
        out.status.success(),
        "graph --why --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout:\n{stdout_clean}"));
    let arr = parsed["applied_overrides"]
        .as_array()
        .expect("applied_overrides must be an array");
    assert_eq!(
        arr.len(),
        1,
        "applied_overrides should have one entry; got: {parsed}"
    );
    assert_eq!(arr[0]["package"].as_str(), Some("lodash"));
    assert_eq!(arr[0]["from_version"].as_str(), Some("4.17.21"));
    assert_eq!(arr[0]["to_version"].as_str(), Some("4.17.20"));
    assert_eq!(arr[0]["via_parent"].as_str(), Some("debug"));
}

/// Graceful absence: with no `.lpm/overrides-state.json`, JSON output
/// still succeeds and emits an empty `applied_overrides` array — not
/// `null`, not absent. Pins the empty-state contract for downstream
/// consumers that diff the array.
#[test]
fn graph_why_json_output_returns_empty_overrides_when_no_state_file() {
    let project = TempProject::empty(
        r#"{"name":"why-no-state","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    // No overrides-state.json on disk.

    let out = lpm(&project)
        .args(["--json", "graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why --json");
    assert!(
        out.status.success(),
        "graph --why --json must succeed without state file; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_clean)
        .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\nstdout:\n{stdout_clean}"));
    let arr = parsed["applied_overrides"]
        .as_array()
        .expect("applied_overrides must be present as an empty array, not null/absent");
    assert!(
        arr.is_empty(),
        "applied_overrides should be empty when no state file; got: {parsed}"
    );
}

// ─── Phase 65 Step 6.4c — `lpm graph --why <pkg>` patch trace ───────────
//
// `lpm graph --why <pkg>` reads `.lpm/patch-state.json` and surfaces the
// patch provenance: patch-path reference (human + JSON) and the
// `originalIntegrity` recorded at apply-time. State is the source of
// truth — these tests stage it directly without driving an install.

type AppliedPatchTuple<'a> = (
    &'a str,       // name
    &'a str,       // version
    &'a str,       // patch_path
    &'a [&'a str], // locations
    usize,         // modified
    usize,         // added
    usize,         // deleted
);

/// Write a synthetic `.lpm/patch-state.json` for `lpm graph --why`
/// decoration. The `parsed` arm encodes the manifest's
/// `lpm.patchedDependencies` map; the `applied` arm encodes per-package
/// apply outcomes.
fn write_patch_state(
    project: &TempProject,
    fingerprint: &str,
    parsed: &[(&str, &str, &str, &str)],
    applied: &[AppliedPatchTuple<'_>],
) {
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(raw_key, name, version, path)| {
            serde_json::json!({
                "raw_key": raw_key,
                "name": name,
                "version": version,
                "path": path,
                "original_integrity": "sha512-fixture",
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(
            |(name, version, patch_path, locations, modified, added, deleted)| {
                serde_json::json!({
                    "raw_key": format!("{name}@{version}"),
                    "name": name,
                    "version": version,
                    "patch_path": patch_path,
                    "locations": locations.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "files_modified": modified,
                    "files_added": added,
                    "files_deleted": deleted,
                })
            },
        )
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-12T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    project.write_file(
        ".lpm/patch-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Human output of `lpm graph --why <pkg>` shows the "Patches applied
/// to this package" section with the patch-path reference.
#[test]
fn graph_why_human_output_shows_patch_trace() {
    let project = TempProject::empty(
        r#"{"name":"why-patch-human","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &project,
        "sha256-test-fp",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &[".lpm/wrappers/lodash@4.17.21/node_modules/lodash"],
            2,
            0,
            0,
        )],
    );

    let out = lpm(&project)
        .args(["graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why");
    assert!(
        out.status.success(),
        "graph --why must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(
        stdout_clean.contains("Patches applied to this package"),
        "human output must include patches section; got:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("patches/lodash@4.17.21.patch"),
        "human output must reference the patch path; got:\n{stdout_clean}"
    );
}

/// `--json` output's `applied_patches[]` is populated from
/// `.lpm/patch-state.json` with `name`, `patch_path`, `files_modified`.
#[test]
fn graph_why_json_output_includes_applied_patches() {
    let project = TempProject::empty(
        r#"{"name":"why-patch-json","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    write_patch_state(
        &project,
        "sha256-test-fp",
        &[(
            "lodash@4.17.21",
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
        )],
        &[(
            "lodash",
            "4.17.21",
            "patches/lodash@4.17.21.patch",
            &[".lpm/wrappers/lodash@4.17.21/node_modules/lodash"],
            2,
            0,
            0,
        )],
    );

    let out = lpm(&project)
        .args(["--json", "graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why --json");
    assert!(
        out.status.success(),
        "graph --why --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout)))
            .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}"));
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"].as_str(), Some("lodash"));
    assert_eq!(
        arr[0]["patch_path"].as_str(),
        Some("patches/lodash@4.17.21.patch")
    );
    assert_eq!(arr[0]["files_modified"].as_u64(), Some(2));
}

/// No `.lpm/patch-state.json` → `applied_patches` is an empty array
/// (not null/absent). Pin the empty-state contract for downstream
/// consumers that diff the array.
#[test]
fn graph_why_json_output_returns_empty_applied_patches_when_no_state_file() {
    let project = TempProject::empty(
        r#"{"name":"why-patch-no-state","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.21", &[])]);
    // No patch-state.json on disk.

    let out = lpm(&project)
        .args(["--json", "graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why --json");
    assert!(
        out.status.success(),
        "graph --why --json must succeed without state; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out.stdout))).unwrap();
    let arr = parsed["applied_patches"]
        .as_array()
        .expect("applied_patches must be an array, not null/absent");
    assert!(arr.is_empty(), "applied_patches should be empty");
}

/// Audit fix (2026-04-12, Low): patch provenance must include the
/// recorded `originalIntegrity` in both human and JSON output. Pre-fix,
/// human emitted the literal "originalIntegrity recorded" placeholder
/// and JSON omitted the field.
#[test]
fn graph_why_includes_original_integrity_in_human_and_json() {
    let project = TempProject::empty(
        r#"{"name":"why-patch-integrity","version":"0.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
    );
    write_simple_lockfile(&project, &[("lodash", "4.17.21", &[])]);

    // Recognizable integrity hash to match against.
    let test_integrity = "sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ";

    // Write the state file directly with `original_integrity` populated
    // on the applied entry (the helper writes "sha512-fixture" by
    // default, which doesn't exercise this path).
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": "sha256-test",
        "captured_at": "2026-04-12T00:00:00Z",
        "parsed": [{
            "raw_key": "lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
            "path": "patches/lodash@4.17.21.patch",
            "original_integrity": test_integrity,
        }],
        "applied": [{
            "raw_key": "lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
            "patch_path": "patches/lodash@4.17.21.patch",
            "original_integrity": test_integrity,
            "locations": [".lpm/wrappers/lodash@4.17.21/node_modules/lodash"],
            "files_modified": 1,
            "files_added": 0,
            "files_deleted": 0,
        }],
    });
    project.write_file(
        ".lpm/patch-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );

    // Human mode: surfaces the integrity prefix; must NOT emit the
    // literal "originalIntegrity recorded" placeholder.
    let out_human = lpm(&project)
        .args(["graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why");
    assert!(
        out_human.status.success(),
        "graph --why must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out_human.stdout),
        String::from_utf8_lossy(&out_human.stderr)
    );
    let stdout_clean = strip_ansi(&String::from_utf8_lossy(&out_human.stdout));
    assert!(
        !stdout_clean.contains("originalIntegrity recorded"),
        "human output must NOT emit the literal placeholder; got:\n{stdout_clean}"
    );
    assert!(
        stdout_clean.contains("sha512-AbCdEfGh"),
        "human output must include the integrity prefix; got:\n{stdout_clean}"
    );

    // JSON mode: full integrity hash present in `applied_patches[0].original_integrity`.
    let out_json = lpm(&project)
        .args(["--json", "graph", "--why", "lodash"])
        .output()
        .expect("spawn lpm graph --why --json");
    assert!(out_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_str(&strip_ansi(&String::from_utf8_lossy(&out_json.stdout))).unwrap();
    let arr = parsed["applied_patches"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["original_integrity"].as_str(),
        Some(test_integrity),
        "JSON output must include the full original_integrity hash"
    );
}

// ─── --format dot ──────────────────────────────────────────────────────

#[test]
fn graph_format_dot_emits_valid_dot_syntax_to_stdout() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "dot"])
        .output()
        .expect("failed to run lpm graph --format dot");

    assert!(
        output.status.success(),
        "graph --format dot must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Minimal DOT grammar check: must start with `digraph` (or `graph`)
    // and contain at least one `->` edge (the fixture has a transitive
    // tree, so there will be edges).
    assert!(
        stdout.contains("digraph") || stdout.contains("graph "),
        "dot output must begin with a graph declaration, got:\n{stdout}",
    );
    assert!(
        stdout.contains("->"),
        "dot output must contain at least one edge (->), got:\n{stdout}",
    );
}

// ─── --format mermaid ─────────────────────────────────────────────────

#[test]
fn graph_format_mermaid_emits_valid_mermaid_syntax_to_stdout() {
    let project = graph_fixture();

    let output = lpm(&project)
        .args(["graph", "--format", "mermaid"])
        .output()
        .expect("failed to run lpm graph --format mermaid");

    assert!(
        output.status.success(),
        "graph --format mermaid must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Mermaid grammar: must declare a graph (`graph TD` / `graph LR` /
    // `flowchart`) and use `-->` edges.
    assert!(
        stdout.contains("graph ") || stdout.contains("flowchart"),
        "mermaid output must begin with a graph declaration, got:\n{stdout}",
    );
    assert!(
        stdout.contains("-->"),
        "mermaid output must contain at least one edge (-->), got:\n{stdout}",
    );
}

// ─── --format json envelope snapshot ────────────────────────────────────

#[test]
fn graph_format_json_envelope_matches_snapshot() {
    let project = graph_fixture();

    // Use --depth 1 so the snapshot is small and the fixture's
    // transitive shape doesn't bloat the diff.
    let output = lpm(&project)
        .args(["graph", "--format", "json", "--depth", "1"])
        .output()
        .expect("failed to run lpm graph --format json");

    assert!(output.status.success(), "graph --format json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("graph --format json must be valid JSON: {e}\n---\n{stdout}"));

    insta::with_settings!({ filters => vec![
        // Redact any numeric per-node metadata that may shift across
        // platforms (file sizes, line counts, etc.) — depth/name
        // structure is the stable contract.
        (r#""size":\s*\d+"#, r#""size":[N]"#),
    ]}, {
        insta::assert_json_snapshot!("graph_format_json_depth1_envelope", envelope);
    });
}
