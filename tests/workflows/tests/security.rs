mod support;

use std::path::Path;
use support::{TempProject, lpm};

fn json_output(output: &std::process::Output, command_name: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{command_name} must emit valid JSON: {err}\n---\n{stdout}"))
}

fn write_unverified_approved_posture(project: &TempProject) -> std::path::PathBuf {
    let security_dir = project.home().join(".lpm/security");
    std::fs::create_dir_all(&security_dir).expect("create security dir");
    let path = security_dir.join("approved-posture.json");
    let envelope = serde_json::json!({
        "payload": {
            "schema_version": 1,
            "updated_at": "2026-05-26T22:12:18Z",
            "script_policy": "deny",
            "minimum_release_age_secs": 259200,
            "sandbox_mode": "default",
            "sandbox_allow_degraded": false,
            "sigstore_verify": "deny"
        },
        "signature": "0000000000000000000000000000000000000000000000000000000000000000"
    });
    std::fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap())
        .expect("write unverified approved posture");
    path
}

fn signing_secret_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm/security/signing-secret.hex")
}

#[test]
fn security_status_json_defaults_to_project_target() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "security", "status"])
        .output()
        .expect("failed to run lpm --json security status");

    assert!(
        output.status.success(),
        "security status must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = json_output(&output, "lpm --json security status");
    let expected_root = std::fs::canonicalize(project.path())
        .expect("canonicalize temp project")
        .to_string_lossy()
        .to_string();
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["status"]["target"], serde_json::json!("project"));
    assert_eq!(
        envelope["status"]["project_root"],
        serde_json::json!(expected_root)
    );
    assert_eq!(
        envelope["status"]["effective_floor"]["firewall_mode"],
        serde_json::json!("off")
    );
}

#[test]
fn security_status_human_uses_slim_completion() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["security", "status"])
        .output()
        .expect("failed to run lpm security status");

    assert!(
        output.status.success(),
        "security status must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("target   project")
            && stdout.contains("effective floor")
            && stdout.contains("npm firewall")
            && stdout.contains("active unlocks"),
        "security status must render the status sections to stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Security floor loaded"),
        "security status must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "security status must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn security_status_json_reports_unverified_local_state_without_creating_secret() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);
    write_unverified_approved_posture(&project);

    let output = lpm(&project)
        .args(["--json", "security", "status"])
        .output()
        .expect("failed to run lpm --json security status");

    assert!(
        !output.status.success(),
        "security status must fail closed for unverified local state"
    );

    let envelope = json_output(&output, "lpm --json security status");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("security_approval_store")
    );
    assert!(
        envelope["error"]
            .as_str()
            .expect("error must be a string")
            .contains("signing secret"),
        "unexpected error envelope: {envelope}",
    );
    assert!(
        !signing_secret_path(&project).exists(),
        "status verification must not create a replacement signing secret",
    );
}

#[test]
fn security_repair_json_quarantines_unverified_local_state() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);
    let posture_path = write_unverified_approved_posture(&project);

    let output = lpm(&project)
        .args(["--json", "security", "repair"])
        .output()
        .expect("failed to run lpm --json security repair");

    assert!(
        output.status.success(),
        "security repair must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = json_output(&output, "lpm --json security repair");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(
        envelope["repair"]["quarantined"][0]["reason"],
        serde_json::json!("signing secret missing")
    );
    let quarantine_path = envelope["repair"]["quarantined"][0]["quarantine_path"]
        .as_str()
        .expect("quarantine path must be a string");
    assert!(!posture_path.exists());
    assert!(Path::new(quarantine_path).exists());
    assert!(
        !signing_secret_path(&project).exists(),
        "repair must not create a replacement signing secret",
    );

    let mut snapshot = envelope;
    snapshot["repair"]["security_dir"] = serde_json::json!("[SECURITY_DIR]");
    snapshot["repair"]["quarantined"][0]["original_path"] = serde_json::json!("[ORIGINAL_PATH]");
    snapshot["repair"]["quarantined"][0]["quarantine_path"] =
        serde_json::json!("[QUARANTINE_PATH]");
    insta::assert_json_snapshot!(
        "security_repair_json_quarantines_unverified_state",
        snapshot
    );

    let status_output = lpm(&project)
        .args(["--json", "security", "status"])
        .output()
        .expect("failed to run lpm --json security status after repair");
    assert!(
        status_output.status.success(),
        "security status must fall back to builtin defaults after repair\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status_output.stdout),
        String::from_utf8_lossy(&status_output.stderr),
    );
}

#[test]
fn security_lock_json_defaults_to_global_target() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "security", "lock", "default"])
        .output()
        .expect("failed to run lpm --json security lock default");

    assert!(
        output.status.success(),
        "security lock must succeed when nothing matches\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let envelope = json_output(&output, "lpm --json security lock default");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["target"], serde_json::json!("global"));
    assert_eq!(envelope["scope"], serde_json::json!("default"));
    assert_eq!(envelope["revocations"], serde_json::json!([]));
}

#[test]
fn security_lock_human_reports_empty_revocation_as_slim_warning() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["security", "lock", "default"])
        .output()
        .expect("failed to run lpm security lock default");

    assert!(
        output.status.success(),
        "security lock must succeed when nothing matches\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No active global unlocks matched default."),
        "security lock must report the no-op with a slim warning, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "security lock must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn security_unlock_bundle_rejects_package_filters_before_interactive_guard() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "security",
            "unlock",
            "default",
            "--package",
            "esbuild",
        ])
        .output()
        .expect("failed to run lpm --json security unlock default --package esbuild");

    assert!(
        !output.status.success(),
        "bundle unlock with package filters must fail"
    );

    let envelope = json_output(
        &output,
        "lpm --json security unlock default --package esbuild",
    );
    assert_eq!(envelope["success"], serde_json::json!(false));

    let error = envelope["error"]
        .as_str()
        .expect("error envelope must include a message");
    assert!(error.contains("`--package`"), "unexpected error: {error}");
    assert!(error.contains("default"), "unexpected error: {error}");
}

#[test]
fn security_unlock_rejects_empty_package_filter_before_interactive_guard() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "security",
            "unlock",
            "provenance-unverified",
            "--package",
            "   ",
        ])
        .output()
        .expect("failed to run lpm --json security unlock provenance-unverified --package blank");

    assert!(
        !output.status.success(),
        "empty package filter must fail before approval"
    );

    let envelope = json_output(
        &output,
        "lpm --json security unlock provenance-unverified --package blank",
    );
    assert_eq!(envelope["success"], serde_json::json!(false));

    let error = envelope["error"]
        .as_str()
        .expect("error envelope must include a message");
    assert!(error.contains("`--package`"), "unexpected error: {error}");
    assert!(
        error.contains("must not be empty"),
        "unexpected error: {error}"
    );
}

#[test]
fn security_unlock_typosquat_disable_scope_reaches_approval_guard() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "security",
            "unlock",
            "typosquat-disable",
            "--project",
            ".",
        ])
        .output()
        .expect("failed to run lpm --json security unlock typosquat-disable");

    assert!(
        !output.status.success(),
        "non-interactive typosquat-disable unlock must require approval"
    );

    let envelope = json_output(&output, "lpm --json security unlock typosquat-disable");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("security_approval_required")
    );
    assert_eq!(
        envelope["error"]["requested_scopes"][0],
        "typosquat-disable"
    );
}

#[test]
fn security_lock_rejects_empty_package_filter() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "security",
            "lock",
            "provenance-unverified",
            "--package",
            "",
        ])
        .output()
        .expect("failed to run lpm --json security lock provenance-unverified --package blank");

    assert!(
        !output.status.success(),
        "empty lock package filter must fail"
    );

    let envelope = json_output(
        &output,
        "lpm --json security lock provenance-unverified --package blank",
    );
    assert_eq!(envelope["success"], serde_json::json!(false));

    let error = envelope["error"]
        .as_str()
        .expect("error envelope must include a message");
    assert!(error.contains("`--package`"), "unexpected error: {error}");
    assert!(
        error.contains("must not be empty"),
        "unexpected error: {error}"
    );
}
