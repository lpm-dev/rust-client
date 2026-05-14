//! Workflow tests for `lpm setup` (CI .npmrc generation).
//!
//! The OIDC contract paths are pinned by the cli-binary survivor
//! [`crates/lpm-cli/tests/oidc_setup_snippet_contract.rs`]. This file
//! covers the non-OIDC branches that don't need a real CI environment:
//!
//! - scoped registry config (default)
//! - `--proxy` widens to "all npm traffic through lpm.dev"
//! - `--registry <url>` overrides the registry URL
//! - JSON envelope shape (path, content, uses_env_var, oidc, proxy)
//! - missing-token fallback uses the `${LPM_TOKEN}` placeholder

mod support;

use support::{TempProject, lpm};

// ─── default scoped config ────────────────────────────────────────────

#[test]
fn setup_default_writes_scoped_registry_line_to_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--registry", "https://lpm.example.test", "setup"])
        .output()
        .expect("failed to run lpm setup");

    assert!(
        output.status.success(),
        "lpm setup failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup must write .npmrc");
    assert!(
        npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        ".npmrc must use the scoped registry line by default, got:\n{npmrc}",
    );
    // The default path (no stored token) falls back to `${LPM_TOKEN}`.
    assert!(
        npmrc.contains("${LPM_TOKEN}") || npmrc.contains("_authToken="),
        ".npmrc must include an authToken entry, got:\n{npmrc}",
    );
}

#[test]
fn setup_proxy_flag_writes_non_scoped_registry_line() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--registry", "https://lpm.example.test", "setup", "--proxy"])
        .output()
        .expect("failed to run lpm setup --proxy");

    assert!(output.status.success(), "lpm setup --proxy failed");

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup must write .npmrc");
    // `--proxy` mode: bare `registry=` (catches all packages), NOT scoped.
    assert!(
        npmrc.contains("registry=https://lpm.example.test/api/registry/"),
        ".npmrc must use the unscoped registry line under --proxy, got:\n{npmrc}",
    );
    assert!(
        !npmrc.contains("@lpm.dev:registry="),
        ".npmrc must NOT use the scoped form under --proxy, got:\n{npmrc}",
    );
}

// ─── --json envelope ──────────────────────────────────────────────────

#[test]
fn setup_json_envelope_carries_path_content_and_flag_state() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "--json",
            "setup",
            "--proxy",
        ])
        .output()
        .expect("failed to run lpm setup --json");

    assert!(output.status.success(), "lpm setup --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["proxy"], serde_json::json!(true));
    assert_eq!(envelope["oidc"], serde_json::json!(false));
    assert_eq!(envelope["uses_env_var"], serde_json::json!(true));

    let path = envelope["path"].as_str().expect("path must be a string");
    assert!(
        path.ends_with(".npmrc"),
        "envelope path must point at .npmrc, got: {path}"
    );

    let content = envelope["content"]
        .as_str()
        .expect("content must be a string");
    assert!(
        content.contains("registry=https://lpm.example.test/api/registry/"),
        "envelope content must include the unscoped registry line under --proxy, got:\n{content}",
    );
}
