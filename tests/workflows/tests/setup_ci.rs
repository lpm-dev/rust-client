//! Workflow tests for `lpm setup ci npmrc` (CI `.npmrc` generation).
//!
//! The OIDC contract paths are pinned by the cli-binary survivor
//! [`crates/lpm-cli/tests/oidc_setup_snippet_contract.rs`]. This file
//! covers the non-OIDC branches that don't need a real CI environment:
//!
//! - scoped registry config (default)
//! - removed `--proxy` flag is rejected before writing `.npmrc`
//! - legacy `proxy = true` config no longer widens `.npmrc`
//! - `--registry <url>` overrides the registry URL
//! - JSON envelope shape (path, content, uses_env_var, oidc, proxy)
//! - missing-token fallback uses the `${LPM_TOKEN}` placeholder

mod support;

use support::auth_state::{SessionSeed, seed_sessions};
use support::{TempProject, lpm};

// ─── default scoped config ────────────────────────────────────────────

#[test]
fn setup_ci_default_writes_scoped_registry_line_to_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc");

    assert!(
        output.status.success(),
        "lpm setup ci npmrc failed:\nstdout: {}\nstderr: {}",
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
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --color=always");

    assert!(output.status.success(), "lpm setup ci npmrc failed");

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
fn setup_ci_proxy_flag_is_rejected_before_dot_npmrc_is_written() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
            "--proxy",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --proxy");

    assert!(
        !output.status.success(),
        "lpm setup ci npmrc --proxy must be rejected"
    );
    assert!(
        !project.file_exists(".npmrc"),
        "rejected --proxy setup must not write .npmrc"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--proxy"),
        "rejection must name the removed flag, got:\n{stderr}"
    );
}

#[test]
fn setup_ci_ignores_legacy_proxy_config_when_writing_dot_npmrc() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).expect("create isolated lpm home");
    std::fs::write(lpm_dir.join("config.toml"), "proxy = true\n")
        .expect("write legacy proxy config");

    let output = lpm(&project)
        .args([
            "--registry",
            "https://lpm.example.test",
            "setup",
            "ci",
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc");

    assert!(
        output.status.success(),
        "lpm setup ci npmrc failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let npmrc =
        std::fs::read_to_string(project.path().join(".npmrc")).expect("setup ci must write .npmrc");
    assert!(
        npmrc.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        "legacy proxy config must not widen setup output, got:\n{npmrc}",
    );
    assert!(
        !npmrc.lines().any(|line| line.starts_with("registry=")),
        "legacy proxy config must not write a bare registry line, got:\n{npmrc}",
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
            "npmrc",
        ])
        .output()
        .expect("failed to run lpm setup ci npmrc --json");

    assert!(output.status.success(), "lpm setup ci npmrc --json failed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup ci --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["proxy"], serde_json::json!(false));
    assert_eq!(envelope["oidc"], serde_json::json!(false));
    assert_eq!(envelope["uses_env_var"], serde_json::json!(true));
    assert_eq!(envelope["storage_backend"], serde_json::Value::Null);
    assert_eq!(envelope["storage_degraded"], serde_json::json!(false));

    let path = envelope["path"].as_str().expect("path must be a string");
    assert!(
        path.ends_with(".npmrc"),
        "envelope path must point at .npmrc, got: {path}"
    );

    let content = envelope["content"]
        .as_str()
        .expect("content must be a string");
    assert!(
        content.contains("@lpm.dev:registry=https://lpm.example.test/api/registry/"),
        "envelope content must include the scoped registry line, got:\n{content}",
    );
}

#[test]
fn setup_ci_json_reports_file_backed_storage_backend_for_stored_token() {
    let project = TempProject::empty(r#"{"name":"setup","version":"1.0.0"}"#);
    let registry_url = "https://lpm.example.test";
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("stored-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm(&project)
        .args(["--registry", registry_url, "--json", "setup", "ci", "npmrc"])
        .output()
        .expect("failed to run lpm setup ci npmrc --json");

    assert!(
        output.status.success(),
        "lpm setup ci npmrc --json with stored token failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("setup ci --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["uses_env_var"], serde_json::json!(false));
    assert_eq!(
        envelope["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(envelope["storage_degraded"], serde_json::json!(true));
}
