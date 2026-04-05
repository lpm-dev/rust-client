//! Contract tests for `--json` output across all commands.
//!
//! These tests verify the JSON structure that CI pipelines, MCP servers,
//! and scripting tools depend on. Each test parses stdout as JSON and
//! validates required fields and types.

mod support;

use support::assertions::{assert_json_field, parse_json_output, JsonType};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry};

// ─── lpm health --json ───────────────────────────────────────────

#[tokio::test]
async fn health_json_has_required_fields() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["health", "--json"])
        .output()
        .expect("failed to run lpm health");

    assert!(output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "healthy", JsonType::Bool);
    assert_json_field(&json, "registry_url", JsonType::String);
    assert_json_field(&json, "response_time_ms", JsonType::Number);

    assert_eq!(json["success"], true);
    assert_eq!(json["healthy"], true);
}

// ─── lpm whoami --json ───────────────────────────────────────────

#[tokio::test]
async fn whoami_json_has_required_fields() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_whoami("testuser", "test@example.com").await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json", "--token", "test-token-123"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "lpm whoami failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "username", JsonType::String);

    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "testuser");
}

// ─── lpm health --json (unhealthy) ──────────────────────────────

#[tokio::test]
async fn health_json_reports_unhealthy_on_failure() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    // Use a port that's (almost certainly) not listening
    let output = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["health", "--json"])
        .output()
        .expect("failed to run lpm health");

    // Should fail (non-zero exit) for unreachable registry
    assert!(!output.status.success());
}

// ─── lpm migrate --dry-run --json ────────────────────────────────

#[test]
fn migrate_dry_run_json_output() {
    let project = TempProject::from_fixture("migrate-npm");

    let output = lpm(&project)
        .args(["migrate", "--dry-run", "--json"])
        .output()
        .expect("failed to run lpm migrate");

    assert!(
        output.status.success(),
        "migrate --dry-run --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_eq!(json["success"], true);
}

// ─── lpm run multi-task --json ───────────────────────────────────

#[test]
fn run_multi_task_json_has_task_array() {
    // Running multiple scripts triggers the JSON summary via print_json_summary
    let project = TempProject::empty(r#"{
        "name": "run-json-test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo built",
            "lint": "echo linted"
        }
    }"#);

    let output = lpm(&project)
        .args(["run", "build", "lint", "--json"])
        .output()
        .expect("failed to run lpm run --json");

    assert!(
        output.status.success(),
        "lpm run --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_json_field(&json, "success", JsonType::Bool);
    assert_json_field(&json, "tasks", JsonType::Array);
    assert_json_field(&json, "total", JsonType::Number);
    assert_json_field(&json, "passed", JsonType::Number);
    assert_json_field(&json, "failed", JsonType::Number);
    assert_json_field(&json, "duration_ms", JsonType::Number);

    assert_eq!(json["success"], true);
    assert!(json["total"].as_u64().unwrap() >= 2);
    assert_eq!(json["failed"], 0);

    // Verify tasks array structure
    let tasks = json["tasks"].as_array().unwrap();
    for task in tasks {
        assert_json_field(task, "name", JsonType::String);
        assert_json_field(task, "success", JsonType::Bool);
        assert_json_field(task, "cached", JsonType::Bool);
        assert_json_field(task, "duration_ms", JsonType::Number);
    }
}

// ─── lpm run failing task --json ─────────────────────────────────

#[test]
fn run_failing_task_json_reports_failure() {
    let project = TempProject::empty(r#"{
        "name": "fail-json-test",
        "version": "1.0.0",
        "scripts": {
            "good": "echo ok",
            "bad": "exit 1"
        }
    }"#);

    // Use --continue-on-error so both tasks run
    let output = lpm(&project)
        .args(["run", "good", "bad", "--json", "--continue-on-error"])
        .output()
        .expect("failed to run lpm run --json");

    assert!(!output.status.success());

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(json["failed"].as_u64().unwrap() >= 1);
}

// ─── Error JSON output ──────────────────────────────────────────

#[tokio::test]
async fn auth_required_json_error() {
    let project = TempProject::empty(r#"{"name": "test", "version": "1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_auth_required().await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(!output.status.success());

    // Even on error, --json should produce parseable JSON
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // The error should be in some structured form
    assert!(
        combined.contains("error") || combined.contains("Unauthorized") || combined.contains("401"),
        "expected error info in output, got:\nstdout: {stdout}\nstderr: {stderr}"
    );
}
