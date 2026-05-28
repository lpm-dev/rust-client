mod support;

use support::{TempProject, lpm};

fn json_output(output: &std::process::Output, command_name: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{command_name} must emit valid JSON: {err}\n---\n{stdout}"))
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