mod support;

use std::path::Path;
use support::{TempProject, lpm};

fn json_output(output: &std::process::Output, command_name: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{command_name} must emit valid JSON: {err}\n---\n{stdout}"))
}

fn redact_protect_policy_paths(envelope: &mut serde_json::Value) {
    let Some(protect) = envelope.get_mut("protect") else {
        return;
    };
    protect["path"] = serde_json::json!("[POLICY_PATH]");
    if let Some(managed_policy) = protect
        .get_mut("managed_policy")
        .and_then(serde_json::Value::as_object_mut)
    {
        managed_policy.insert(
            "path".to_string(),
            serde_json::json!("[MANAGED_POLICY_PATH]"),
        );
    }
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
fn security_protect_json_reports_status_enable_and_disable() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let status_output = lpm(&project)
        .args(["--json", "security", "protect", "status"])
        .output()
        .expect("failed to run lpm --json security protect status");
    assert!(
        status_output.status.success(),
        "security protect status must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status_output.stdout),
        String::from_utf8_lossy(&status_output.stderr),
    );
    let mut status_envelope = json_output(&status_output, "lpm --json security protect status");
    redact_protect_policy_paths(&mut status_envelope);
    insta::assert_json_snapshot!("security_protect_status_json_inactive", status_envelope);

    let enable_output = lpm(&project)
        .args(["--json", "security", "protect", "enable"])
        .output()
        .expect("failed to run lpm --json security protect enable");
    assert!(
        enable_output.status.success(),
        "security protect enable must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&enable_output.stdout),
        String::from_utf8_lossy(&enable_output.stderr),
    );
    let mut enable_envelope = json_output(&enable_output, "lpm --json security protect enable");
    redact_protect_policy_paths(&mut enable_envelope);
    insta::assert_json_snapshot!("security_protect_enable_json_enforce", enable_envelope);

    let disable_output = lpm(&project)
        .args(["--json", "security", "protect", "disable"])
        .output()
        .expect("failed to run lpm --json security protect disable");
    assert!(
        disable_output.status.success(),
        "security protect disable must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&disable_output.stdout),
        String::from_utf8_lossy(&disable_output.stderr),
    );
    let mut disable_envelope = json_output(&disable_output, "lpm --json security protect disable");
    redact_protect_policy_paths(&mut disable_envelope);
    insta::assert_json_snapshot!("security_protect_disable_json", disable_envelope);
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
    assert_eq!(
        envelope["status"]["effective_floor"]["install_time_source_analysis"],
        serde_json::json!(false)
    );
    assert_eq!(
        envelope["status"]["floor_sources"]["install_time_source_analysis"],
        serde_json::json!("builtin-default")
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
fn security_status_human_reports_install_time_source_analysis_and_source() {
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
    let source_analysis_row = stdout
        .lines()
        .find(|line| line.contains("install-time source analysis"));
    assert!(
        source_analysis_row
            .is_some_and(|line| { line.contains("false") && line.contains("(builtin-default)") }),
        "security status must show the install-time source analysis value and source, got:\n{stdout}",
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
fn security_unlock_source_analysis_disable_scope_reaches_approval_guard() {
    let project = TempProject::empty(r#"{"name":"security-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "security",
            "unlock",
            "source-analysis-disable",
            "--project",
            ".",
        ])
        .output()
        .expect("failed to run lpm --json security unlock source-analysis-disable");

    assert!(
        !output.status.success(),
        "non-interactive source-analysis-disable unlock must require approval"
    );
    let envelope = json_output(
        &output,
        "lpm --json security unlock source-analysis-disable",
    );
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("security_approval_required")
    );
    assert_eq!(
        envelope["error"]["requested_scopes"][0],
        "source-analysis-disable"
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

#[test]
fn disabling_firewall_preserves_managed_source_analysis() {
    let project = TempProject::empty(r#"{"name":"managed-source","version":"1.0.0"}"#);
    let path = project.home().join(".lpm/security-policy.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "install-time-source-analysis = true\n[firewall]\nmode = \"enforce\"\n",
    )
    .unwrap();
    let output = lpm(&project)
        .args(["security", "protect", "disable", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        path.exists(),
        "firewall removal deleted source-analysis protection"
    );
    let saved: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(saved["install-time-source-analysis"].as_bool(), Some(true));
    assert!(saved.get("firewall").is_none());
}

#[test]
fn managed_security_sections_reject_scalar_and_array_shapes() {
    for section in ["sandbox", "sigstore"] {
        for value in ["\"strict\"", "[]", "false"] {
            let project = TempProject::empty(r#"{"name":"managed-shape","version":"1.0.0"}"#);
            let path = project.home().join(".lpm/security-policy.toml");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("{section} = {value}\n")).unwrap();
            let output = lpm(&project)
                .args(["security", "status", "--json"])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "accepted {section}={value}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                json_output(&output, "security status")["error"]
                    .as_str()
                    .unwrap()
                    .contains(section)
            );
        }
    }
}

#[test]
fn managed_firewall_status_distinguishes_off_from_active_protection() {
    for (mode, active) in [("off", false), ("monitor", true), ("enforce", true)] {
        let project = TempProject::empty(r#"{"name":"managed-status","version":"1.0.0"}"#);
        let path = project.home().join(".lpm/security-policy.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("[firewall]\nmode = \"{mode}\"\n")).unwrap();
        let output = lpm(&project)
            .args(["security", "protect", "status", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            json_output(&output, "security protect")["protect"]["active"],
            active,
            "mode={mode}"
        );
    }
}

#[test]
fn concurrent_scope_revocations_share_one_transaction_lock() {
    let project = TempProject::empty(r#"{"name":"scope-lock","version":"1.0.0"}"#);
    support::write_signed_unlock(&project, &["scripts-allow", "sandbox-none"]);
    let path = project.home().join(".lpm/security/unlocks.lock");
    let lock = lpm_common::acquire_exclusive_lock(&path).unwrap();
    let mut children = Vec::new();
    for scope in ["scripts-allow", "sandbox-none"] {
        let marker = project.home().join(format!("waiting-{scope}"));
        let mut child = support::lpm_spawnable(&project)
            .env(support::LOCK_CONTENTION_MARKER_ENV, &marker)
            .args([
                "security",
                "lock",
                scope,
                "--project",
                project.path().to_str().unwrap(),
                "--json",
            ])
            .spawn()
            .unwrap();
        support::wait_for_lock_contention(&mut child, &marker, &path);
        children.push(child);
    }
    drop(lock);
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let output = lpm(&project)
        .args(["security", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        json_output(&output, "security status")["status"]
            .get("active_unlocks")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
    );
}

#[test]
fn security_repair_quarantines_inconsistent_audit_history_and_allows_new_events() {
    for damage in ["truncated", "empty", "missing", "invalid"] {
        let project = TempProject::empty(r#"{"name":"repair-audit","version":"1.0.0"}"#);
        let revoke = || {
            lpm(&project)
                .args([
                    "security",
                    "lock",
                    "scripts-allow",
                    "--project",
                    project.path().to_str().unwrap(),
                    "--json",
                ])
                .output()
                .unwrap()
        };
        for _ in 0..2 {
            support::write_signed_unlock(&project, &["scripts-allow"]);
            assert!(revoke().status.success());
        }
        let directory = project.home().join(".lpm/security");
        let path = directory.join("audit.jsonl");
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(original.lines().count() >= 2);
        match damage {
            "truncated" => {
                std::fs::write(&path, format!("{}\n", original.lines().next().unwrap())).unwrap()
            }
            "empty" => std::fs::write(&path, "").unwrap(),
            "missing" => std::fs::remove_file(&path).unwrap(),
            "invalid" => std::fs::write(&path, "{invalid}\n").unwrap(),
            _ => unreachable!(),
        }
        let output = lpm(&project)
            .args(["security", "repair", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let json = json_output(&output, "security repair");
        assert_eq!(
            json["repair"]["quarantined"].as_array().unwrap().len(),
            if damage == "missing" { 1 } else { 2 },
            "{damage}: {json}"
        );
        for entry in json["repair"]["quarantined"].as_array().unwrap() {
            assert!(Path::new(entry["quarantine_path"].as_str().unwrap()).exists());
        }
        support::write_signed_unlock(&project, &["scripts-allow"]);
        assert!(revoke().status.success());
        let head: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("audit-head.json")).unwrap())
                .unwrap();
        assert_eq!(
            head["payload"]["entry_count"], 1,
            "new audit event must be recorded after {damage} repair"
        );
    }
}

fn rewrite_fixture_unlock(project: &TempProject, edit: impl FnOnce(&mut serde_json::Value)) {
    use hmac::Mac;
    let path = std::fs::read_dir(project.home().join(".lpm/security/unlocks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut envelope["payload"]);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&[42u8; 32]).unwrap();
    mac.update(&serde_json::to_vec(&envelope["payload"]).unwrap());
    envelope["signature"] = serde_json::json!(hex::encode(mac.finalize().into_bytes()));
    std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
}

#[test]
fn only_active_global_floor_edit_grants_authorize_persistent_weakening() {
    for scenario in ["global", "project", "expired", "managed", "forced"] {
        let project = TempProject::empty(r#"{"name":"floor-edit","version":"1.0.0"}"#);
        support::write_signed_unlock(&project, &["floor-edit"]);
        if scenario != "project" {
            rewrite_fixture_unlock(&project, |payload| {
                payload["target"] = serde_json::json!("global");
                payload["project_root"] = serde_json::Value::Null;
                if scenario == "expired" {
                    payload["expires_at"] = serde_json::json!(
                        (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()
                    );
                }
            });
        }
        if scenario == "managed" {
            std::fs::write(
                project.home().join(".lpm/security-policy.toml"),
                "script-policy = \"deny\"\n",
            )
            .unwrap();
        }
        if scenario == "forced" {
            std::fs::write(
                project.home().join(".lpm/config.toml"),
                "force-security-floor = true\nscript-policy = \"deny\"\n",
            )
            .unwrap();
        }
        let output = lpm(&project)
            .args(["config", "scripts", "--set", "allow", "--json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            scenario == "global",
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn only_active_unrestricted_global_floor_edit_grants_can_remove_force_floor() {
    for scenario in [
        "global",
        "missing",
        "project",
        "expired",
        "package-scoped",
        "default",
    ] {
        for action in ["false", "0", "no", "off", "disabled", "unset"] {
            let project = TempProject::empty(r#"{"name":"forced-floor-edit","version":"1.0.0"}"#);
            if scenario != "missing" {
                support::write_signed_unlock(
                    &project,
                    if scenario == "default" {
                        &["scripts-allow"]
                    } else {
                        &["floor-edit"]
                    },
                );
                if scenario != "project" {
                    rewrite_fixture_unlock(&project, |payload| {
                        payload["target"] = serde_json::json!("global");
                        payload["project_root"] = serde_json::Value::Null;
                        if scenario == "expired" {
                            payload["expires_at"] = serde_json::json!(
                                (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()
                            );
                        }
                        if scenario == "package-scoped" {
                            payload["packages"] = serde_json::json!(["fixture"]);
                        }
                    });
                }
            }
            let path = project.home().join(".lpm/config.toml");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "force-security-floor = true\n").unwrap();
            let args = if action == "unset" {
                vec!["config", "unset", "force-security-floor", "--json"]
            } else {
                vec!["config", "set", "force-security-floor", action, "--json"]
            };
            let output = lpm(&project).args(args).output().unwrap();
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                output.status.success(),
                scenario == "global",
                "{scenario} {action}: {envelope}"
            );
            let audit_path = project.home().join(".lpm/security/audit.jsonl");
            let changed_events = || {
                std::fs::read_to_string(&audit_path)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| {
                        serde_json::from_str::<serde_json::Value>(line).unwrap()["payload"]["event"]
                            == "force-security-floor-changed"
                    })
                    .count()
            };
            assert_eq!(
                changed_events(),
                usize::from(scenario == "global"),
                "{scenario} {action}"
            );
            if scenario == "global" {
                lpm(&project)
                    .args(["config", "unset", "force-security-floor", "--json"])
                    .assert()
                    .success();
                assert_eq!(
                    changed_events(),
                    1,
                    "no-op mutation recorded another successful weakening"
                );
            }
            if scenario != "global" {
                assert_eq!(
                    envelope["error_code"], "security_approval_required",
                    "{envelope}"
                );
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    "force-security-floor = true\n"
                );
            }
        }
    }
}

#[test]
fn floor_edit_removes_local_switch_without_weakening_managed_policy() {
    let project = TempProject::empty(r#"{"name":"managed-floor-edit","version":"1.0.0"}"#);
    support::write_signed_unlock(&project, &["floor-edit"]);
    rewrite_fixture_unlock(&project, |payload| {
        payload["target"] = serde_json::json!("global");
        payload["project_root"] = serde_json::Value::Null;
    });
    std::fs::write(
        project.home().join(".lpm/config.toml"),
        "force-security-floor = true\n",
    )
    .unwrap();
    std::fs::write(
        project.home().join(".lpm/security-policy.toml"),
        "script-policy = \"deny\"\n",
    )
    .unwrap();
    lpm(&project)
        .args(["config", "unset", "force-security-floor", "--json"])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["config", "scripts", "--set", "allow", "--json"])
        .output()
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{envelope}");
    assert_eq!(envelope["error_code"], "security_floor");
}
