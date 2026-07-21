//! Intentionally minimal binary-surface coverage: sudo refusal happens during
//! process startup, before any command implementation or workflow harness runs.

mod common;

#[test]
fn sudo_refusal_uses_the_json_error_envelope() {
    let project = tempfile::tempdir().unwrap();
    let lpm_home = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"sudo-json","version":"1.0.0"}"#,
    )
    .unwrap();

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[
            ("LPM_TEST_FORCE_ROOT_SUDO_POLICY", "1"),
            ("SUDO_UID", "501"),
            ("SUDO_USER", "developer"),
        ],
        &["--json", "install"],
    );

    assert!(!status.success(), "sudo startup must be refused");
    assert!(
        stderr.trim().is_empty(),
        "JSON errors belong on stdout: {stderr}"
    );
    let envelope = common::parse_json_stdout(&stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("sudo_execution_refused")
    );
}

#[test]
fn sudo_hosts_helper_reaches_its_own_validation() {
    let project = tempfile::tempdir().unwrap();
    let lpm_home = tempfile::tempdir().unwrap();
    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[
            ("LPM_TEST_FORCE_ROOT_SUDO_POLICY", "1"),
            ("SUDO_UID", "501"),
            ("SUDO_USER", "developer"),
        ],
        &["internal-hosts-file", "invalid-action"],
    );

    assert!(!status.success(), "invalid helper action must fail");
    assert!(stdout.trim().is_empty(), "plain errors belong on stderr");
    assert!(
        stderr.contains("unknown internal hosts-file action 'invalid-action'"),
        "helper validation must run instead of the sudo startup refusal: {stderr}",
    );
    assert!(!stderr.contains("sudo_execution_refused"));
}
