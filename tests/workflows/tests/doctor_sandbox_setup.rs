//! Explicit Windows sandbox permission setup through the CLI.

mod support;

#[cfg(not(windows))]
use support::{TempProject, lpm};

#[cfg(not(windows))]
#[test]
fn sandbox_setup_preview_reports_unsupported_platform_without_mutating_the_project() {
    let project = TempProject::empty(r#"{"name":"sandbox-preview","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["doctor", "sandbox-setup", "--json"])
        .current_dir(project.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(value, @r#"
    {
      "success": true,
      "supported": false,
      "operation": "preview",
      "grants": [],
      "count": 0
    }
    "#);
    assert!(!project.path().join("lpm.lock").exists());
}

#[cfg(not(windows))]
#[test]
fn sandbox_setup_changes_are_refused_on_unsupported_platforms() {
    let project = TempProject::empty(r#"{"name":"sandbox-refusal","version":"1.0.0"}"#);
    for operation in ["--apply", "--remove"] {
        let output = lpm(&project)
            .args(["doctor", "sandbox-setup", operation, "--yes", "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["error_code"], "script");
        assert!(value["error"].as_str().unwrap().contains("only on Windows"));
    }
}

#[test]
fn sandbox_setup_apply_and_remove_are_mutually_exclusive() {
    let project = support::TempProject::empty(r#"{"name":"sandbox-conflict","version":"1.0.0"}"#);
    let output = support::lpm(&project)
        .args(["doctor", "sandbox-setup", "--apply", "--remove"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

#[cfg(windows)]
#[test]
fn sandbox_setup_preview_identifies_the_user_and_exact_grants_without_applying_them() {
    let project = support::TempProject::empty(r#"{"name":"sandbox-preview","version":"1.0.0"}"#);
    let output = support::lpm(&project)
        .args(["doctor", "sandbox-setup", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["user_sid"].as_str().unwrap().starts_with("S-1-5-21-"));
    assert!(!value["grants"].as_array().unwrap().is_empty());
    assert_eq!(
        value["count"].as_u64().unwrap() as usize,
        value["grants"].as_array().unwrap().len()
    );
    for grant in value["grants"].as_array().unwrap() {
        assert_eq!(grant["permission"], "metadata");
        assert!(grant["path"].is_string());
        assert!(grant["configured"].is_boolean());
    }
    assert_eq!(value["apply_args"][0], "doctor");
    insta::assert_json_snapshot!(serde_json::json!({
        "success": value["success"], "supported": value["supported"],
        "operation": value["operation"], "grant_fields": ["path", "permission", "configured"],
        "has_apply_args": value["apply_args"].is_array(),
    }), @r#"
    {
      "success": true,
      "supported": true,
      "operation": "preview",
      "grant_fields": [
        "path",
        "permission",
        "configured"
      ],
      "has_apply_args": true
    }
    "#);
    assert!(!project.path().join("lpm.lock").exists());
}

#[cfg(windows)]
#[test]
fn sandbox_setup_json_requires_explicit_confirmation_and_rejects_invalid_users() {
    let project = support::TempProject::empty(r#"{"name":"sandbox-confirm","version":"1.0.0"}"#);
    for args in [
        vec!["--apply"],
        vec!["--remove"],
        vec!["--user-sid", "not-a-sid"],
    ] {
        let output = support::lpm(&project)
            .args(["doctor", "sandbox-setup", "--json"])
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["success"], false);
        assert_eq!(value["error_code"], "script");
        let error = value["error"].as_str().unwrap();
        assert!(
            error.contains("--yes")
                || error.contains("administrator terminal")
                || error.contains("invalid target user SID"),
            "{error}"
        );
    }
}

#[test]
fn doctor_catalog_explains_the_windows_setup_requirement() {
    let project = support::TempProject::empty(r#"{"name":"sandbox-catalog","version":"1.0.0"}"#);
    let output = support::lpm(&project)
        .args([
            "doctor",
            "list",
            "--code",
            "sandbox_setup_required",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("sandbox_setup_required"));
    assert!(text.contains("sandbox-setup"));
}
