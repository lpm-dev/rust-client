//! Workflow tests for `lpm setup ci` (CI `.npmrc` generation).
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
fn setup_ci_default_writes_scoped_registry_line_to_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--registry", "https://lpm.example.test", "setup", "ci"])
        .output()
        .expect("failed to run lpm setup ci");

    assert!(
        output.status.success(),
        "lpm setup ci failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup ci must write .npmrc");
    assert!(
        npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        ".npmrc must use the scoped registry line by default, got:\n{npmrc}",
    );
    // The default path (no stored token) falls back to `${LPM_TOKEN}`.
    assert!(
        npmrc.contains("${LPM_TOKEN}") || npmrc.contains("_authToken="),
        ".npmrc must include an authToken entry, got:\n{npmrc}",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human setup ci should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Generated .npmrc"),
        "human setup ci should report file generation with the slim done line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("! No token found — .npmrc uses ${LPM_TOKEN} placeholder."),
        "human setup ci should surface the placeholder warning on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Set LPM_TOKEN in your CI environment."),
        "human setup ci should keep the CI env-var hint, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from setup ci stderr, got:\n{stderr}"
    );
}

#[test]
fn setup_ci_color_output_uses_plain_file_and_cyan_env_var() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--color=always",
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
        ])
        .output()
        .expect("failed to run lpm setup ci --color=always");

    assert!(output.status.success(), "lpm setup ci failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Generated .npmrc") && !stderr.contains("Generated \u{1b}[1m.npmrc"),
        ".npmrc should remain plain in setup ci output, got:\n{stderr}"
    );
    assert!(
        stderr.contains("\u{1b}[36mLPM_TOKEN"),
        "LPM_TOKEN should use the env-var color role, got:\n{stderr}"
    );
}

#[test]
fn setup_ci_proxy_flag_writes_non_scoped_registry_line() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "--proxy",
        ])
        .output()
        .expect("failed to run lpm setup ci --proxy");

    assert!(output.status.success(), "lpm setup ci --proxy failed");

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup ci must write .npmrc");
    // `--proxy` mode: bare `registry=` (catches all packages), NOT scoped.
    assert!(
        npmrc.contains("registry=https://lpm.example.test/api/registry/"),
        ".npmrc must use the unscoped registry line under --proxy, got:\n{npmrc}",
    );
    assert!(
        !npmrc.contains("@lpm.dev:registry="),
        ".npmrc must NOT use the scoped form under --proxy, got:\n{npmrc}",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human setup ci --proxy should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Generated .npmrc"),
        "human setup ci --proxy should report file generation with the slim done line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("› Using proxy mode — all npm traffic routed through lpm.dev."),
        "human setup ci --proxy should report proxy mode on a slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("! No token found — .npmrc uses ${LPM_TOKEN} placeholder."),
        "human setup ci --proxy should surface the placeholder warning on stderr, got:\n{stderr}"
    );
}

// ─── --json envelope ──────────────────────────────────────────────────

#[test]
fn setup_ci_json_envelope_carries_path_content_and_flag_state() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "--json",
            "setup",
            "ci",
            "--proxy",
        ])
        .output()
        .expect("failed to run lpm setup ci --json");

    assert!(output.status.success(), "lpm setup ci --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup ci --json must be valid JSON: {e}\n---\n{stdout}"));

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
