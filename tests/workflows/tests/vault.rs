//! Workflow tests for the hidden `lpm vault` command.
//!
//! The product contract is intentionally narrow: the command still
//! parses for internal continuity, but it is hidden from top-level help
//! and always returns an explicit "not publicly available" error. That
//! keeps the user-facing CLI honest while the macOS app remains private
//! and not ready for public support.

mod support;

use support::{TempProject, lpm};

#[test]
fn vault_command_is_hidden_from_top_level_help() {
    let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

    let out = lpm(&project)
        .arg("--help")
        .output()
        .expect("failed to run lpm --help");

    assert!(out.status.success(), "lpm --help must succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("vault"),
        "hidden lpm vault command must not appear in top-level help, got:\n{stdout}",
    );
}

#[test]
fn vault_command_reports_not_publicly_available() {
    let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["vault", "open"])
        .output()
        .expect("failed to run lpm vault open");

    assert!(
        !out.status.success(),
        "lpm vault must exit non-zero while unavailable"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not publicly available") && stderr.contains("lpm env"),
        "stderr must explain the hidden/unavailable contract, got:\n{stderr}",
    );
}

#[test]
fn vault_command_under_json_emits_unavailable_error_envelope() {
    let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

    let out = lpm(&project)
        .args(["--json", "vault", "version"])
        .output()
        .expect("failed to run lpm --json vault version");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("vault --json unavailable path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));

    let combined = format!("{}{}", envelope, String::from_utf8_lossy(&out.stderr));
    assert!(
        combined.contains("not publicly available") && combined.contains("lpm env"),
        "envelope or stderr must explain the unavailable contract, got:\n{combined}",
    );
}
