#![cfg(debug_assertions)]

mod support;

use support::{TempProject, lpm};

fn cert_command(project: &TempProject) -> assert_cmd::Command {
    let mut cmd = lpm(project);
    cmd.env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(project));
    cmd.env("LPM_CERT_AUDIT_DIR", audit_dir(project));
    cmd
}

fn trust_store_dir(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("test-trust-store")
}

fn audit_dir(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("audit")
}

fn audit_actions(project: &TempProject) -> Vec<String> {
    let log = audit_dir(project).join("cert.jsonl");
    if !log.exists() {
        return Vec::new();
    }
    let s = std::fs::read_to_string(&log).unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            v["action"].as_str().map(|s| s.to_string())
        })
        .collect()
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
fn cert_status_human_uses_slim_status_for_absent_state() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let output = cert_command(&project)
        .args(["cert", "status"])
        .output()
        .expect("failed to run lpm cert status");

    assert_success(&output, "lpm cert status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Root CA")
            && stdout.contains("status     not installed")
            && stdout.contains("Project cert")
            && stdout.contains("status     not generated"),
        "cert status must render the report to stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! HTTPS certificates need setup"),
        "cert status must finish with a slim warning for incomplete setup, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "cert status must not use cliclack gutter output, got:\n{stderr}",
    );
}

#[test]
fn cert_status_human_reports_ready_state_with_slim_completion() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);

    let trust_output = cert_command(&project)
        .args(["cert", "trust", "--json"])
        .output()
        .expect("failed to run lpm cert trust --json");
    assert_success(&trust_output, "lpm cert trust --json");

    let generate_output = cert_command(&project)
        .args(["cert", "generate", "--json"])
        .output()
        .expect("failed to run lpm cert generate --json");
    assert_success(&generate_output, "lpm cert generate --json");

    let output = cert_command(&project)
        .args(["cert", "status"])
        .output()
        .expect("failed to run lpm cert status");

    assert_success(&output, "lpm cert status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Root CA")
            && stdout.contains("status     trusted")
            && stdout.contains("Project cert")
            && stdout.contains("status     valid")
            && stdout.contains("hosts"),
        "cert status must render ready certificate details to stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ HTTPS certificates are ready"),
        "cert status must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "cert status must not use cliclack gutter output, got:\n{stderr}",
    );
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

    let actions = audit_actions(&project);
    assert!(
        actions.contains(&"ca.generate".to_string()),
        "lpm cert trust must record ca.generate; got {actions:?}"
    );
    assert!(
        actions.contains(&"ca.trust_install".to_string()),
        "lpm cert trust must record ca.trust_install; got {actions:?}"
    );
}

#[test]
fn cert_uninstall_takes_trust_away_from_a_home_git_could_commit() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    assert_success(
        &cert_command(&project)
            .args(["cert", "trust", "--json"])
            .output()
            .expect("failed to run lpm cert trust --json"),
        "lpm cert trust --json",
    );
    // The home has since become a repository's root.
    let home = project.home().join(".lpm");
    std::fs::remove_file(home.join(".gitignore")).unwrap();
    std::fs::create_dir(home.join(".git")).unwrap();

    let trust = cert_command(&project)
        .args(["cert", "trust", "--json"])
        .output()
        .expect("failed to run lpm cert trust --json");
    assert!(!trust.status.success());
    assert_eq!(
        json_envelope(&trust, "lpm cert trust --json")["error_code"],
        "lpm_home"
    );

    let uninstall = cert_command(&project)
        .args(["cert", "uninstall", "--json"])
        .output()
        .expect("failed to run lpm cert uninstall --json");
    assert_success(&uninstall, "lpm cert uninstall --json");
    assert_eq!(
        json_envelope(&uninstall, "lpm cert uninstall --json")["ca_uninstalled"],
        serde_json::json!(true)
    );
    assert!(!trust_store_entry(&project).exists());
    let stderr = String::from_utf8_lossy(&uninstall.stderr);
    assert!(
        stderr.contains("it is the root of a git repository")
            && stderr.contains("point LPM_HOME at a directory of its own"),
        "{stderr}"
    );
    assert!(!home.join(".gitignore").exists());
}

/// Leaves the pair `cert` and `key` as a write that stopped before it
/// replaced the authority's files would, then makes the LPM home a
/// repository's root, where git could commit what is written there.
fn leave_a_pending_pair_in_an_exposed_home(project: &TempProject, cert: &str, key: &str) {
    let certs = project.home().join(".lpm/certs");
    std::fs::write(
        certs.join(".lpm-ca-pair-transaction.json"),
        serde_json::json!({
            "cert_name": "rootCA.pem",
            "key_name": "rootCA-key.pem",
            "cert_pem": cert,
            "key_pem": key,
            "staged_cert_name": ".lpm-cert-staged-cert",
            "staged_key_name": ".lpm-cert-staged-key",
        })
        .to_string(),
    )
    .unwrap();
    let home = project.home().join(".lpm");
    std::fs::remove_file(home.join(".gitignore")).unwrap();
    std::fs::create_dir(home.join(".git")).unwrap();
}

#[test]
fn cert_uninstall_in_a_home_git_could_commit_writes_no_key_a_stopped_write_left() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    assert_success(
        &cert_command(&project)
            .args(["cert", "trust", "--json"])
            .output()
            .expect("failed to run lpm cert trust --json"),
        "lpm cert trust --json",
    );
    let cert = std::fs::read_to_string(ca_cert_path(&project)).unwrap();
    let key = std::fs::read_to_string(ca_key_path(&project)).unwrap();
    std::fs::remove_file(ca_key_path(&project)).unwrap();
    leave_a_pending_pair_in_an_exposed_home(&project, &cert, &key);

    let uninstall = cert_command(&project)
        .args(["cert", "uninstall", "--json"])
        .output()
        .expect("failed to run lpm cert uninstall --json");

    assert_success(&uninstall, "lpm cert uninstall --json");
    assert!(!trust_store_entry(&project).exists());
    assert!(
        !ca_key_path(&project).exists(),
        "the authority's key was written where git could commit it"
    );
    assert!(
        !project
            .home()
            .join(".lpm/certs/.lpm-ca-pair-transaction.json")
            .exists(),
        "the pending write, which holds the authority's key, is left behind"
    );
}

#[test]
fn cert_uninstall_in_a_home_git_could_commit_takes_trust_from_a_pending_authority() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    assert_success(
        &cert_command(&project)
            .args(["cert", "trust", "--json"])
            .output()
            .expect("failed to run lpm cert trust --json"),
        "lpm cert trust --json",
    );
    // Another authority, trusted in place of the first, which a rotation
    // stopped before it replaced the first's files.
    let other_home = project.home().join("other-lpm-home");
    assert_success(
        &cert_command(&project)
            .env("LPM_HOME", &other_home)
            .args(["cert", "trust", "--json"])
            .output()
            .expect("failed to run lpm cert trust --json"),
        "lpm cert trust --json (other authority)",
    );
    let pending_cert = std::fs::read_to_string(other_home.join("certs/rootCA.pem")).unwrap();
    let pending_key = std::fs::read_to_string(other_home.join("certs/rootCA-key.pem")).unwrap();
    assert!(trust_store_entry(&project).exists());
    leave_a_pending_pair_in_an_exposed_home(&project, &pending_cert, &pending_key);

    let uninstall = cert_command(&project)
        .args(["cert", "uninstall", "--json"])
        .output()
        .expect("failed to run lpm cert uninstall --json");

    assert_success(&uninstall, "lpm cert uninstall --json");
    assert!(
        !trust_store_entry(&project).exists(),
        "the pending authority is still trusted"
    );
    assert_ne!(
        std::fs::read_to_string(ca_cert_path(&project)).unwrap(),
        pending_cert,
        "nothing pending was written into the exposed home"
    );
    assert!(
        !project
            .home()
            .join(".lpm/certs/.lpm-ca-pair-transaction.json")
            .exists(),
        "the pending write, which holds the authority's key, is left behind"
    );
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

    let actions = audit_actions(&project);
    assert!(
        actions.contains(&"ca.trust_uninstall".to_string()),
        "lpm cert uninstall must record ca.trust_uninstall; got {actions:?}"
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
    // `lpm cert generate` declines trust-store install — the CA lands on disk
    // but is not pushed into the trust store; the user runs `lpm cert trust`
    // separately for that. `ca_freshly_installed` reflects trust-store state.
    assert_eq!(initial["ca_freshly_installed"], serde_json::json!(false));
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
        !trust_store_entry(&project).exists(),
        "generate must NOT install the CA into the trust store (use `lpm cert trust` for that)"
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
    assert_eq!(
        status["ca"]["trusted"],
        serde_json::json!(false),
        "trust-store install requires an explicit `lpm cert trust`"
    );
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

#[test]
fn cert_generate_uses_lpm_json_extra_permitted_dns_for_constrained_chain() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{"cert":{"extraPermittedDns":["myapp.local"]}}"#,
    );

    let output = cert_command(&project)
        .args(["cert", "generate", "--json"])
        .output()
        .expect("failed to run lpm cert generate --json");

    assert_success(&output, "lpm cert generate --json");
    let envelope = json_envelope(&output, "lpm cert generate --json");
    assert_eq!(envelope["success"], serde_json::json!(true));

    let cert_pem = std::fs::read_to_string(project_cert_path(&project))
        .expect("generate must write project cert");
    let cert_blocks = cert_pem.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(
        cert_blocks, 2,
        "extraPermittedDns should force a leaf + constrained intermediate chain"
    );
}

fn cert_material_snapshot(
    project: &TempProject,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn collect(
        path: &std::path::Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        if !path.exists() {
            return;
        }
        if path.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                collect(&entry.unwrap().path(), out);
            }
        } else if !path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".lock")
        {
            out.insert(path.to_path_buf(), std::fs::read(path).unwrap());
        }
    }
    let mut files = std::collections::BTreeMap::new();
    for path in [
        project.home().join(".lpm/certs"),
        project.path().join(".lpm/certs"),
        trust_store_dir(project),
        audit_dir(project),
        project.home().join(".lpm/cert-grace.json"),
    ] {
        collect(&path, &mut files);
    }
    files
}

#[test]
fn cert_rejects_inapplicable_flags_without_mutating_material() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    assert_success(
        &cert_command(&project)
            .args(["cert", "trust"])
            .output()
            .unwrap(),
        "trust",
    );
    assert_success(
        &cert_command(&project)
            .args(["cert", "generate"])
            .output()
            .unwrap(),
        "generate",
    );
    let before = cert_material_snapshot(&project);
    for args in [
        vec!["rotate", "--dry-run"],
        vec!["trust", "--dry-run"],
        vec!["uninstall", "--dry-run"],
        vec!["generate", "--dry-run"],
        vec!["status", "--dry-run"],
        vec!["reconcile", "--host", "app.localhost"],
        vec!["generate", "--project", "."],
        vec!["status", "--keep-old-trusted", "1"],
        vec!["trust", "--fail-on-missing"],
    ] {
        let output = cert_command(&project)
            .args(["--json", "cert"])
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("only valid"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            before,
            cert_material_snapshot(&project),
            "mutated for {args:?}"
        );
    }
}

#[test]
fn cert_status_detects_unusable_project_material_without_repairing_it() {
    for damage in ["missing key", "wrong key", "stale chain"] {
        let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
        assert_success(
            &cert_command(&project)
                .args(["cert", "trust"])
                .output()
                .unwrap(),
            "trust",
        );
        assert_success(
            &cert_command(&project)
                .args(["cert", "generate"])
                .output()
                .unwrap(),
            "generate",
        );
        let (other_ca, other_key) = lpm_cert::ca::generate_ca().unwrap();
        match damage {
            "missing key" => std::fs::remove_file(project_key_path(&project)).unwrap(),
            "wrong key" => {
                lpm_cert::write_key_file(&project_key_path(&project), other_key.as_bytes()).unwrap()
            }
            _ => std::fs::write(ca_cert_path(&project), other_ca).unwrap(),
        }
        let before = cert_material_snapshot(&project);
        let output = cert_command(&project)
            .args(["cert", "status", "--json"])
            .output()
            .unwrap();
        assert_success(&output, "status");
        let value = json_envelope(&output, "status");
        assert_eq!(value["project"]["valid"], false, "{damage}");
        assert!(
            value["project"]["error"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
        assert_eq!(before, cert_material_snapshot(&project));
        let output = cert_command(&project)
            .args(["cert", "status"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains("HTTPS certificates are ready"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("HTTPS certificates are ready"));
    }
}

#[test]
fn cert_reconcile_dry_run_preserves_pending_rotation_and_pair_recovery() {
    for phase in ["reissuing", "promoted", "pair"] {
        let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
        assert_success(
            &cert_command(&project)
                .args(["cert", "trust"])
                .output()
                .unwrap(),
            "trust",
        );
        assert_success(
            &cert_command(&project)
                .args(["cert", "generate"])
                .output()
                .unwrap(),
            "generate",
        );
        let old_cert = std::fs::read_to_string(ca_cert_path(&project)).unwrap();
        let old_key = std::fs::read_to_string(ca_key_path(&project)).unwrap();
        let (new_cert, new_key) = lpm_cert::ca::generate_ca().unwrap();
        let ca_dir = ca_cert_path(&project).parent().unwrap().to_path_buf();
        let fingerprint = |pem: &str| {
            lpm_cert::cert::fingerprint_hex(
                &lpm_cert::cert::fingerprint_sha256_bytes(pem.as_bytes()).unwrap(),
            )
        };
        if phase == "pair" {
            let journal = serde_json::json!({ "cert_name":"rootCA.pem", "key_name":"rootCA-key.pem", "cert_pem":new_cert, "key_pem":new_key, "staged_cert_name":".lpm-cert-stagecert", "staged_key_name":".lpm-cert-stagekey" });
            lpm_cert::write_key_file(
                &ca_dir.join(".lpm-ca-pair-transaction.json"),
                &serde_json::to_vec(&journal).unwrap(),
            )
            .unwrap();
        } else {
            let journal = serde_json::json!({
                "version":1, "phase":phase, "mode":"hard_cutover",
                "oldFingerprint":fingerprint(&old_cert), "newFingerprint":fingerprint(&new_cert),
                "oldCertPem":old_cert, "oldKeyPem":old_key, "newCertPem":new_cert, "newKeyPem":new_key,
                "leafBackups":[], "reissuedLeaves":[], "skippedMissing":[]
            });
            lpm_cert::write_key_file(
                &ca_dir.join("rootCA.rotation.json"),
                &serde_json::to_vec(&journal).unwrap(),
            )
            .unwrap();
            if phase == "promoted" {
                std::fs::write(ca_cert_path(&project), new_cert).unwrap();
                lpm_cert::write_key_file(&ca_key_path(&project), new_key.as_bytes()).unwrap();
            }
        }
        let before = cert_material_snapshot(&project);
        let output = cert_command(&project)
            .args(["cert", "reconcile", "--dry-run", "--json"])
            .output()
            .unwrap();
        assert_success(&output, "reconcile dry-run");
        assert!(
            before == cert_material_snapshot(&project),
            "changed {phase} recovery state"
        );
        assert_eq!(
            json_envelope(&output, "reconcile dry-run")["pending_recovery"],
            true
        );
    }
}

#[test]
fn cert_reconcile_dry_run_leaves_an_empty_home_unchanged() {
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    let output = cert_command(&project)
        .args(["cert", "reconcile", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert_success(&output, "empty reconcile dry-run");
    assert!(!ca_cert_path(&project).parent().unwrap().exists());
    insta::assert_json_snapshot!(
        "cert_reconcile_json_empty_preview",
        json_envelope(&output, "empty reconcile dry-run")
    );
}

#[cfg(unix)]
#[test]
fn cert_reconcile_preview_preserves_directory_and_audit_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let project = TempProject::empty(r#"{"name":"cert-test","version":"1.0.0"}"#);
    assert_success(
        &cert_command(&project)
            .args(["cert", "trust"])
            .output()
            .unwrap(),
        "trust",
    );
    let paths = [
        (project.home().join(".lpm"), 0o755),
        (project.home().join(".lpm/certs"), 0o755),
        (audit_dir(&project), 0o755),
        (audit_dir(&project).join("cert.jsonl"), 0o644),
    ];
    for (path, mode) in &paths {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
    let output = cert_command(&project)
        .args(["cert", "reconcile", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert_success(&output, "reconcile dry-run");
    for (path, mode) in &paths {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            *mode,
            "{}",
            path.display()
        );
    }
}
