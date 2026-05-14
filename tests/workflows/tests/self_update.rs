//! Workflow tests for `lpm self-update`.
//!
//! The full happy path probes npm + GitHub Releases for the latest
//! version and then shells out to the installer, neither of which is
//! reproducible in CI. Workflow coverage focuses on the cache-driven
//! branches that don't require network: cache-hit "already on latest"
//! and the recent-failure backoff path.

mod support;

use std::time::{SystemTime, UNIX_EPOCH};
use support::{TempProject, lpm};

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
}
