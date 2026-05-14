//! Workflow tests for `lpm use --list`.
//!
//! The local-only "list installed Node versions" path. `lpm use node@<v>`
//! itself triggers a real download from nodejs.org and is out of scope
//! for the workflow tier — `--list` is the deterministic read surface.
//!
//! `lpm_runtime::node::list_installed()` reads `<HOME>/.lpm/runtime/node/`,
//! which is empty in a fresh isolated HOME.

mod support;

use support::{TempProject, lpm};

#[test]
fn use_list_on_empty_runtime_succeeds_with_empty_set() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "--list"])
        .output()
        .expect("failed to run lpm use --list");

    assert!(
        output.status.success(),
        "lpm use --list on a fresh HOME must exit 0, got: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn use_list_json_envelope_reports_empty_versions_on_fresh_home() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "use", "--list"])
        .output()
        .expect("failed to run lpm use --list --json");

    assert!(output.status.success(), "lpm use --list --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("use --list --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["runtime"], serde_json::json!("node"));

    let versions = envelope["versions"]
        .as_array()
        .expect("versions must be an array");
    assert!(
        versions.is_empty(),
        "fresh HOME must have zero installed node versions, got: {versions:?}",
    );
}

#[test]
fn use_no_args_falls_through_to_list_path() {
    // `lpm use` with no positional and no flags routes to the list
    // action (see dispatch in main.rs::Commands::Use). Behavior-pin
    // for the implicit-list path so it can't silently shift later.
    let project = TempProject::empty(r#"{"name":"use-no-args","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use"])
        .output()
        .expect("failed to run bare lpm use");

    assert!(
        output.status.success(),
        "bare `lpm use` must succeed (falls through to list)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn use_list_with_unsupported_runtime_filter_fails_cleanly() {
    let project = TempProject::empty(r#"{"name":"use-list","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "deno", "--list"])
        .output()
        .expect("failed to run lpm use deno --list");

    assert!(
        !output.status.success(),
        "unsupported runtime filter must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deno") || stderr.contains("not yet supported"),
        "stderr must indicate the unsupported runtime, got:\n{stderr}"
    );
}
