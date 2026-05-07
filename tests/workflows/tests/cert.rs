mod support;

use support::{TempProject, lpm};

fn cert_command(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(project));
    cmd
}

fn trust_store_dir(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("test-trust-store")
}

fn trust_store_entry(project: &TempProject) -> std::path::PathBuf {
    trust_store_dir(project).join("lpm-local-ca.pem")
}

fn ca_cert_path(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("certs").join("rootCA.pem")
}

fn ca_key_path(project: &TempProject) -> std::path::PathBuf {
    project
        .home()
        .join(".lpm")
        .join("certs")
        .join("rootCA-key.pem")
}

fn project_cert_path(project: &TempProject) -> std::path::PathBuf {
    project.path().join(".lpm").join("certs").join("cert.pem")
}

fn project_key_path(project: &TempProject) -> std::path::PathBuf {
    project.path().join(".lpm").join("certs").join("key.pem")
}

fn assert_success(output: &std::process::Output, command_name: &str) {
    assert!(
        output.status.success(),
        "{command_name} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn json_envelope(output: &std::process::Output, command_name: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{command_name} must be valid JSON: {e}\n---\n{stdout}"))
}

#[test]
fn cert_status_json_reports_absent_ca_and_project_cert() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let output = cert_command(&project)
        .args(["cert", "status", "--json"])
        .output()
        .expect("failed to run lpm cert status --json");

    assert_success(&output, "lpm cert status --json");

    let envelope = json_envelope(&output, "lpm cert status --json");
    assert_eq!(envelope["success"], serde_json::json!(true));

    insta::assert_json_snapshot!("cert_status_json_absent_state", envelope);
}

#[test]
fn cert_trust_json_generates_ca_and_installs_into_isolated_test_store() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let output = cert_command(&project)
        .args(["cert", "trust", "--json"])
        .output()
        .expect("failed to run lpm cert trust --json");

    assert_success(&output, "lpm cert trust --json");

    let envelope = json_envelope(&output, "lpm cert trust --json");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["ca_installed"], serde_json::json!(true));

    insta::assert_json_snapshot!("cert_trust_json_installs_ca", envelope);

    assert!(
        ca_cert_path(&project).exists(),
        "trust must write the root CA cert"
    );
    assert!(
        ca_key_path(&project).exists(),
        "trust must write the root CA key"
    );
    assert!(
        trust_store_entry(&project).exists(),
        "trust must install the CA into the isolated test trust store"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(ca_key_path(&project))
            .expect("root CA key must exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "root CA key must be owner-only on unix");
    }
}

#[test]
fn cert_uninstall_json_removes_trust_store_entry_but_keeps_ca_files() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let trust_output = cert_command(&project)
        .args(["cert", "trust", "--json"])
        .output()
        .expect("failed to run lpm cert trust --json");
    assert_success(&trust_output, "lpm cert trust --json");

    let uninstall_output = cert_command(&project)
        .args(["cert", "uninstall", "--json"])
        .output()
        .expect("failed to run lpm cert uninstall --json");

    assert_success(&uninstall_output, "lpm cert uninstall --json");

    let envelope = json_envelope(&uninstall_output, "lpm cert uninstall --json");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["ca_uninstalled"], serde_json::json!(true));

    insta::assert_json_snapshot!("cert_uninstall_json_removes_trust_store_entry", envelope);

    assert!(
        ca_cert_path(&project).exists(),
        "uninstall must keep the CA cert on disk"
    );
    assert!(
        ca_key_path(&project).exists(),
        "uninstall must keep the CA key on disk"
    );
    assert!(
        !trust_store_entry(&project).exists(),
        "uninstall must remove the isolated trust-store marker"
    );

    let status_output = cert_command(&project)
        .args(["cert", "status", "--json"])
        .output()
        .expect("failed to run lpm cert status --json after uninstall");
    assert_success(&status_output, "lpm cert status --json");

    let status = json_envelope(&status_output, "lpm cert status --json");
    assert_eq!(status["ca"]["exists"], serde_json::json!(true));
    assert_eq!(status["ca"]["trusted"], serde_json::json!(false));
}

#[test]
fn cert_generate_json_regenerates_when_requested_host_is_missing() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let initial_output = cert_command(&project)
        .args(["cert", "generate", "--json"])
        .output()
        .expect("failed to run initial lpm cert generate --json");

    assert_success(&initial_output, "lpm cert generate --json");

    let initial = json_envelope(&initial_output, "lpm cert generate --json");
    assert_eq!(initial["success"], serde_json::json!(true));
    assert_eq!(initial["ca_freshly_installed"], serde_json::json!(true));
    assert_eq!(initial["cert_freshly_generated"], serde_json::json!(true));

    let refreshed_output = cert_command(&project)
        .args(["cert", "generate", "--json", "--host", "myapp.local"])
        .output()
        .expect("failed to rerun lpm cert generate --json with --host");

    assert_success(
        &refreshed_output,
        "lpm cert generate --json --host myapp.local",
    );

    let mut envelope = json_envelope(
        &refreshed_output,
        "lpm cert generate --json --host myapp.local",
    );
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["ca_freshly_installed"], serde_json::json!(false));
    assert_eq!(envelope["cert_freshly_generated"], serde_json::json!(true));

    assert!(
        project_cert_path(&project).exists(),
        "generate must write the project cert"
    );
    assert!(
        project_key_path(&project).exists(),
        "generate must write the project key"
    );
    assert!(
        trust_store_entry(&project).exists(),
        "generate must install the CA into the isolated test trust store"
    );

    envelope["cert_path"] = serde_json::json!("[CERT_PATH]");
    envelope["key_path"] = serde_json::json!("[KEY_PATH]");
    insta::assert_json_snapshot!(
        "cert_generate_json_regenerates_for_requested_host",
        envelope
    );

    let status_output = cert_command(&project)
        .args(["cert", "status", "--json"])
        .output()
        .expect("failed to run lpm cert status --json after generate");

    assert_success(&status_output, "lpm cert status --json");

    let status = json_envelope(&status_output, "lpm cert status --json");
    let hostnames = status["project"]["hostnames"]
        .as_array()
        .expect("project hostnames must be an array");

    assert_eq!(status["ca"]["exists"], serde_json::json!(true));
    assert_eq!(status["ca"]["trusted"], serde_json::json!(true));
    assert_eq!(status["project"]["exists"], serde_json::json!(true));
    assert_eq!(status["project"]["needs_renewal"], serde_json::json!(false));
    assert!(
        hostnames.iter().any(|hostname| {
            hostname
                .as_str()
                .is_some_and(|hostname| hostname.contains("myapp.local"))
        }),
        "generate --host must regenerate the cert so the requested SAN is present, got: {hostnames:?}"
    );
}
