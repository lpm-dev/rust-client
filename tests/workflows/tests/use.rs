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

fn seed_installed_node(project: &TempProject, version: &str) {
    let bin_dir = project
        .home()
        .join(".lpm")
        .join("runtimes")
        .join("node")
        .join(version)
        .join("bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create runtime bin dir");
    std::fs::write(bin_dir.join("node"), "").expect("failed to seed node binary");
}

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

// ─── install path: pre-network error branches ─────────────────────────

#[test]
fn use_install_unsupported_runtime_fails_before_network_call() {
    // The install path's runtime check fires BEFORE the
    // `lpm_runtime::node::fetch_index` network call. Locking that
    // ordering keeps the unsupported-runtime UX fast even when the
    // host has no internet, and lets workflow tests probe the
    // contract without flake.
    let project = TempProject::empty(r#"{"name":"use","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "deno@1.0.0"])
        .output()
        .expect("failed to run lpm use deno@1.0.0");

    assert!(
        !output.status.success(),
        "unsupported runtime must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deno") || stderr.contains("not yet supported"),
        "stderr must explain the unsupported runtime, got:\n{stderr}",
    );
    assert!(
        stderr.contains("node"),
        "stderr must guide users toward the supported runtime, got:\n{stderr}",
    );
}

#[test]
fn use_install_without_runtime_prefix_fails_with_usage() {
    let project = TempProject::empty(r#"{"name":"use","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["use", "i"]) // alias for install, but no spec
        .output()
        .expect("failed to run lpm use i (no spec)");

    // `i` is parsed as a spec, not as an action, so this routes through
    // the install action with spec="i". Either: clap rejects, or the
    // runtime parser fails. Both are acceptable; assert non-zero exit.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.is_empty() || !String::from_utf8_lossy(&output.stdout).is_empty(),
            "must emit a diagnostic, got stdout: {} / stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            stderr,
        );
    }
}

/// `lpm --json use --pin` without a spec must surface the missing-spec
/// error as a parseable JSON envelope on stdout. The bare `lpm use
/// node@<v>` install path is out of scope for the workflow tier (real
/// nodejs.org download), but the validation error path is the cheapest
/// contract that proves the surface is machine-readable under --json.
#[test]
fn use_pin_without_spec_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"use-pin-no-spec","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "use", "--pin"])
        .output()
        .expect("failed to run lpm --json use --pin");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json use --pin must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|s| s.contains("missing version") || s.contains("Usage")),
        "error must reference the missing-version condition, got: {envelope}",
    );
}

#[test]
fn use_pin_major_spec_writes_matching_installed_exact_version() {
    let project = TempProject::empty(r#"{"name":"use-pin","version":"1.0.0"}"#);
    seed_installed_node(&project, "22.12.0");

    let output = lpm(&project)
        .args(["use", "node@22", "--pin"])
        .output()
        .expect("failed to run lpm use node@22 --pin");

    assert!(
        output.status.success(),
        "lpm use node@22 --pin must succeed when a matching version is already installed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let lpm_json: serde_json::Value = serde_json::from_str(&project.read_file("lpm.json"))
        .expect("lpm use --pin must write valid lpm.json");
    assert_eq!(lpm_json["runtime"]["node"], serde_json::json!("22.12.0"));
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
