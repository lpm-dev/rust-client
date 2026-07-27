//! Workflow tests for `lpm self-update`.
//!
//! The full happy path probes npm + GitHub Releases for the latest
//! version and then shells out to the installer, neither of which is
//! reproducible in CI. Workflow coverage focuses on the cache-driven
//! branches that don't require network: cache-hit "already on latest"
//! and the recent-failure backoff path.

mod support;

use std::time::{SystemTime, UNIX_EPOCH};
use support::{TempProject, lpm, lpm_from_path};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("update-check.json")
}

fn read_current_version(project: &TempProject) -> String {
    let output = lpm(project)
        .arg("--version")
        .output()
        .expect("failed to run lpm --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: `lpm-rs 0.40.0` (or similar)
    stdout
        .split_whitespace()
        .last()
        .unwrap_or("0.0.0")
        .trim()
        .to_string()
}

fn npm_managed_lpm_path(project: &TempProject) -> std::path::PathBuf {
    let source = assert_cmd::cargo::cargo_bin("lpm-rs");
    let file_name = if cfg!(windows) {
        "lpm-rs.exe"
    } else {
        "lpm-rs"
    };
    let destination = project
        .path()
        .join("node_modules")
        .join("@lpm-registry")
        .join("cli")
        .join(file_name);
    std::fs::create_dir_all(destination.parent().unwrap()).expect("create npm-shaped path");
    std::fs::copy(source, &destination).expect("copy lpm binary into npm-shaped path");
    destination
}

// ─── cache-hit "already on latest" ───────────────────────────────────

#[test]
fn self_update_cache_hit_with_matching_latest_reports_up_to_date() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    // Seed the cache so the network probe is skipped entirely.
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["--json", "self-update"])
        .output()
        .expect("failed to run lpm self-update --json");

    assert!(
        output.status.success(),
        "cache-hit on matching latest must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("self-update --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["up_to_date"], serde_json::json!(true));
    assert_eq!(envelope["cache_hit"], serde_json::json!(true));
    assert_eq!(envelope["current"], serde_json::json!(current));
    assert_eq!(envelope["latest"], serde_json::json!(current));
    assert_eq!(envelope["channel"], serde_json::json!("stable"));
    assert_eq!(envelope["target_channel"], serde_json::json!("stable"));
    assert_eq!(envelope["channel_changed"], serde_json::json!(false));

    let mut snapshot = envelope;
    snapshot["current"] = serde_json::json!("<current-version>");
    snapshot["latest"] = serde_json::json!("<current-version>");
    insta::assert_json_snapshot!(snapshot, @r#"
    {
      "success": true,
      "current": "<current-version>",
      "latest": "<current-version>",
      "up_to_date": true,
      "cache_hit": true,
      "channel": "stable",
      "target_channel": "stable",
      "channel_changed": false
    }
    "#);
}

#[test]
fn self_update_explicit_nightly_switch_returns_exact_npm_install_plan() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let nightly = "999.0.0-nightly.20260728.42.d82ceea";

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "nightly": {
            "latest": nightly,
            "lastCheck": now_secs(),
        }
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed nightly cache");

    let binary = npm_managed_lpm_path(&project);
    let output = lpm_from_path(&project, &binary)
        .args(["--json", "self-update", "--channel", "nightly"])
        .output()
        .expect("run npm-managed lpm self-update");

    assert!(
        output.status.success(),
        "stable to nightly plan must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("self-update JSON must parse: {error}\n{stdout}"));
    assert_eq!(envelope["channel"], "stable");
    assert_eq!(envelope["target_channel"], "nightly");
    assert_eq!(envelope["channel_changed"], true);
    assert_eq!(envelope["latest"], nightly);
    assert_eq!(envelope["install_method"], "npm");
    assert_eq!(
        envelope["update_command"],
        format!("npm install -g @lpm-registry/cli@{nightly}")
    );

    let mut snapshot = envelope;
    snapshot["current"] = serde_json::json!("<current-version>");
    insta::assert_json_snapshot!(snapshot, @r#"
    {
      "success": true,
      "current": "<current-version>",
      "latest": "999.0.0-nightly.20260728.42.d82ceea",
      "up_to_date": false,
      "install_method": "npm",
      "update_command": "npm install -g @lpm-registry/cli@999.0.0-nightly.20260728.42.d82ceea",
      "cache_hit": true,
      "channel": "stable",
      "target_channel": "nightly",
      "channel_changed": true
    }
    "#);
}

#[test]
fn self_update_human_cache_hit_uses_slim_status() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["self-update"])
        .output()
        .expect("failed to run lpm self-update");

    assert!(
        output.status.success(),
        "cache-hit on matching latest must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Checking for updates")
            && stderr.contains("current")
            && stderr.contains("latest")
            && stderr.contains("✓ Done · already on latest version"),
        "self-update cache hit must use slim status output, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "self-update must not use cliclack spinner/gutter output, got:\n{stderr}",
    );
}

#[test]
fn self_update_human_cache_hit_applies_slim_color_roles_when_forced() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);
    let current = read_current_version(&project);

    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "latest": current,
        "lastCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["--color=always", "self-update"])
        .output()
        .expect("failed to run colored lpm self-update");

    assert!(
        output.status.success(),
        "colored cache-hit self-update must exit 0\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\x1b[2mcurrent\x1b[22m")
            && stderr.contains("\x1b[2mlatest\x1b[22m")
            && stderr.contains("\x1b[32m")
            && stderr.contains("\x1b[33m"),
        "self-update should dim labels, green latest status, and yellow version targets, got:\n{stderr:?}",
    );
}

// ─── failure-backoff path ─────────────────────────────────────────────

#[test]
fn self_update_recent_failure_short_circuits_with_backoff_error() {
    let project = TempProject::empty(r#"{"name":"su","version":"1.0.0"}"#);

    // Seed a recent failure so the backoff gate trips before probing.
    std::fs::create_dir_all(cache_path(&project).parent().unwrap()).expect("mkdir ~/.lpm");
    let payload = serde_json::json!({
        "lastFailureCheck": now_secs(),
    });
    std::fs::write(cache_path(&project), payload.to_string()).expect("seed cache");

    let output = lpm(&project)
        .args(["self-update"])
        .output()
        .expect("failed to run lpm self-update");

    assert!(
        !output.status.success(),
        "recent-failure backoff must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("last attempt failed") || stderr.contains("--refresh"),
        "stderr must mention the backoff condition + --refresh, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('◇'),
        "self-update backoff must not use cliclack spinner glyphs, got:\n{stderr}",
    );
}
