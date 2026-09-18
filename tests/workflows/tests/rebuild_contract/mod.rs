use super::*;
use serde_json::{Value, json};

fn contract_project(name: &str, script: &str) -> (TempProject, std::path::PathBuf) {
    let project = TempProject::empty(r#"{"name":"rebuild-contract","version":"1.0.0"}"#);
    write_signed_unlock_for(&project, project.path(), &["sandbox-none", "scripts-allow"]);
    let store = seed_scripted_package(&project, name, "1.0.0", script);
    seed_wrapper(&project, &store, name, "1.0.0");
    write_lockfile_for_packages(&project, &[(name, "1.0.0")]);
    (project, store)
}

#[test]
fn rebuild_json_routes_script_output_to_stderr() {
    let (project, _) = contract_project("output-test", "echo lifecycle-sentinel");
    let output = lpm(&project)
        .args(["rebuild", "--all", "--no-sandbox", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("stdout must contain one JSON report");
    assert_eq!(report["success"], true);
    assert_eq!(report["built"], 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("lifecycle-sentinel"));
}

#[test]
fn rebuild_json_returns_one_failure_report() {
    let (project, _) = contract_project("failed-test", "exit 1");
    let output = lpm(&project)
        .args(["rebuild", "--all", "--no-sandbox", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("failure must remain one JSON report");
    assert_eq!(report["success"], false);
    assert_eq!(report["failed"], 1);
}

#[test]
fn rebuild_deny_all_emits_a_json_report_for_live_and_dry_runs() {
    for configured in [false, true] {
        for dry_run in [false, true] {
            let project = TempProject::empty(if configured {
                r#"{"lpm":{"scripts":{"denyAll":true}}}"#
            } else {
                "{}"
            });
            let mut command = lpm(&project);
            command.args(["rebuild", "--json"]);
            if !configured {
                command.arg("--deny-all");
            }
            if dry_run {
                command.arg("--dry-run");
            }
            let output = command.output().unwrap();
            assert!(output.status.success());
            let report: Value =
                serde_json::from_slice(&output.stdout).expect("deny-all must report its no-op");
            assert_eq!(report["success"], true);
            assert_eq!(report["denied_all"], true);
        }
    }
}

#[test]
fn rebuild_validates_named_requests_when_no_install_scripts_exist() {
    let project = TempProject::empty("{}");
    write_lockfile_for_packages(&project, &[]);
    let output = lpm(&project)
        .args(["rebuild", "absent-package", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn rebuild_overlapping_selectors_execute_each_package_once() {
    let (project, _) = contract_project("team.foo", "echo execution >> runs.txt");
    let output = lpm(&project)
        .args([
            "rebuild",
            "foo",
            "team.foo",
            "--force",
            "--no-sandbox",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["built"], 1);
    let runs = project.read_file(".lpm/wrappers/team.foo@1.0.0/node_modules/team.foo/runs.txt");
    assert_eq!(runs.lines().count(), 1);
}

#[test]
fn rebuild_exact_names_take_precedence_over_suffix_matches() {
    let (project, _) = contract_project("foo", "exit 0");
    let store = seed_scripted_package(&project, "team.foo", "1.0.0", "exit 0");
    seed_wrapper(&project, &store, "team.foo", "1.0.0");
    write_lockfile_for_packages(&project, &[("foo", "1.0.0"), ("team.foo", "1.0.0")]);
    let output = lpm(&project)
        .args(["rebuild", "foo", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["packages"].as_array().unwrap().len(), 1);
    assert_eq!(report["packages"][0]["name"], "foo");
}

#[test]
fn rebuild_discovers_escaped_lifecycle_keys() {
    let (project, store) = contract_project("escaped-test", "exit 0");
    std::fs::write(
        store.join("package.json"),
        r#"{"name":"escaped-test","version":"1.0.0","scr\u0069pts":{"postinstall":"exit 0"}}"#,
    )
    .unwrap();
    let output = lpm(&project)
        .args(["rebuild", "--all", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["packages"].as_array().unwrap().len(), 1);
}

#[test]
fn rebuild_dry_run_reports_success_and_package_count() {
    let (project, _) = contract_project("dry-test", "exit 0");
    let output = lpm(&project)
        .args(["rebuild", "--all", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["count"], 1);
    insta::assert_json_snapshot!(report, @r#"
    {
      "success": true,
      "dry_run": true,
      "count": 1,
      "packages": [
        {
          "name": "dry-test",
          "version": "1.0.0",
          "scripts": {
            "postinstall": "exit 0"
          },
          "trusted": false
        }
      ]
    }
    "#);
}

#[test]
fn rebuild_changed_generic_scripts_invalidate_existing_build_markers() {
    let (project, store) = contract_project("marker-test", "echo first > result.txt");
    let arguments = ["rebuild", "--all", "--no-sandbox", "--json"];
    let first = lpm(&project).args(arguments).output().unwrap();
    assert!(first.status.success());
    let second = lpm(&project).args(arguments).output().unwrap();
    assert!(second.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&second.stdout).unwrap()["built"],
        0
    );
    let manifest=json!({"name":"marker-test","version":"1.0.0","scripts":{"postinstall":"echo second > result.txt"}}).to_string();
    std::fs::write(store.join("package.json"), &manifest).unwrap();
    project.write_file(
        ".lpm/wrappers/marker-test@1.0.0/node_modules/marker-test/package.json",
        &manifest,
    );
    let changed = lpm(&project).args(arguments).output().unwrap();
    assert!(changed.status.success());
    let report: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(report["built"], 1);
    assert_eq!(
        project
            .read_file(".lpm/wrappers/marker-test@1.0.0/node_modules/marker-test/result.txt")
            .trim(),
        "second"
    );
}

#[test]
fn rebuild_explicit_untrusted_selection_requires_signed_authorization() {
    for force_floor in [false, true] {
        for named in [false, true] {
            let project = TempProject::empty(r#"{"name":"rebuild-contract","version":"1.0.0"}"#);
            seed_scripted_package(&project, "untrusted-test", "1.0.0", "exit 0");
            write_lockfile_for_packages(&project, &[("untrusted-test", "1.0.0")]);
            if force_floor {
                std::fs::create_dir_all(project.home().join(".lpm")).unwrap();
                std::fs::write(
                    project.home().join(".lpm/config.toml"),
                    "force-security-floor = true\n",
                )
                .unwrap();
            }
            let selection = if named { "untrusted-test" } else { "--all" };
            let output = lpm(&project)
                .args(["rebuild", selection, "--dry-run", "--json"])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "force_floor={force_floor},named={named}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["error_code"], "security_approval_required");
            assert!(report.to_string().contains("scripts-allow"));
            write_signed_unlock_for(&project, project.path(), &["scripts-allow"]);
            let allowed = lpm(&project)
                .args(["rebuild", selection, "--dry-run", "--json"])
                .output()
                .unwrap();
            assert!(
                allowed.status.success(),
                "{}",
                String::from_utf8_lossy(&allowed.stdout)
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&allowed.stdout).unwrap()["packages"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}

#[test]
fn rebuild_explicit_allow_does_not_bypass_project_capability_authorization() {
    let (project, _) = contract_project("capability-test", "exit 0");
    project.write_file(
        "package.json",
        r#"{"name":"host","lpm":{"scripts":{"passEnv":["CUSTOM_SECRET"]}}}"#,
    );
    let output = lpm(&project)
        .args(["rebuild", "--all", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["error_code"], "security_approval_required");
    assert!(report.to_string().contains("capability-widen"));
}

#[test]
fn rebuild_reads_bom_prefixed_lifecycle_manifests() {
    let (project, store) = contract_project("bom-test", "exit 0");
    let content = std::fs::read_to_string(store.join("package.json")).unwrap();
    std::fs::write(store.join("package.json"), format!("\u{feff}{content}")).unwrap();
    let output = lpm(&project)
        .args(["rebuild", "--all", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn rebuild_rejects_non_object_lifecycle_manifests() {
    for content in ["null", "[]", r#"[{"postinstall":"exit 0"}]"#] {
        let (project, store) = contract_project("invalid-test", "exit 0");
        std::fs::write(store.join("package.json"), content).unwrap();
        let output = lpm(&project)
            .args(["rebuild", "--all", "--dry-run", "--json"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "input={content}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[cfg(unix)]
#[test]
fn rebuild_does_not_wait_on_a_fifo_manifest() {
    use std::time::{Duration, Instant};
    let (project, store) = contract_project("fifo-test", "exit 0");
    let path = store.join("package.json");
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut child = lpm_spawnable(&project)
        .args(["rebuild", "--all", "--dry-run", "--json"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if started.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("rebuild blocked on a FIFO manifest");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn rebuild_rejects_ambiguous_suffix_selectors() {
    let (project, _) = contract_project("one.foo", "exit 0");
    seed_scripted_package(&project, "two.foo", "1.0.0", "exit 0");
    write_lockfile_for_packages(&project, &[("one.foo", "1.0.0"), ("two.foo", "1.0.0")]);
    let output = lpm(&project)
        .args(["rebuild", "foo", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("ambiguous"));
}

#[test]
fn rebuild_replaces_legacy_empty_markers_after_one_build() {
    let (project, store) = contract_project("legacy-test", "echo rebuilt > result.txt");
    std::fs::write(store.join(".lpm-built"), "").unwrap();
    for expected in [1, 0] {
        let output = lpm(&project)
            .args(["rebuild", "--all", "--no-sandbox", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["built"],
            expected
        );
    }
}

#[test]
fn rebuild_changed_delegate_bytes_invalidate_generic_markers() {
    let (project, store) = contract_project("delegate-test", "node install.js");
    for (value, expected) in [("first", 1), ("first", 0), ("second", 1)] {
        let script = format!("require('fs').writeFileSync('result.txt', '{value}');");
        std::fs::write(store.join("install.js"), &script).unwrap();
        project.write_file(
            ".lpm/wrappers/delegate-test@1.0.0/node_modules/delegate-test/install.js",
            &script,
        );
        let output = lpm(&project)
            .args(["rebuild", "--all", "--no-sandbox", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["built"],
            expected
        );
    }
    assert_eq!(
        project
            .read_file(".lpm/wrappers/delegate-test@1.0.0/node_modules/delegate-test/result.txt"),
        "second"
    );
}

#[test]
fn rebuild_named_selection_honors_package_limited_script_authorization() {
    use hmac::Mac;
    let (project, _) = contract_project("scoped-test", "exit 0");
    let unlocks = project.home().join(".lpm/security/unlocks");
    for entry in std::fs::read_dir(unlocks).unwrap() {
        let path = entry.unwrap().path();
        let mut envelope: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        envelope["payload"]["packages"] = json!(["scoped-test"]);
        let secret = hex::decode(
            std::fs::read_to_string(project.home().join(".lpm/security/signing-secret.hex"))
                .unwrap(),
        )
        .unwrap();
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&secret).unwrap();
        mac.update(&serde_json::to_vec(&envelope["payload"]).unwrap());
        envelope["signature"] = json!(hex::encode(mac.finalize().into_bytes()));
        std::fs::write(path, envelope.to_string()).unwrap();
    }
    let output = lpm(&project)
        .args(["rebuild", "scoped-test", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let broad = lpm(&project)
        .args(["rebuild", "--policy=allow", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !broad.status.success(),
        "a package grant must not authorize a broad policy override"
    );
}

#[tokio::test]
async fn install_auto_build_emits_one_json_document_on_success_and_failure() {
    for script in ["exit 0", "exit 1"] {
        let registry = crate::support::mock_registry::MockRegistry::start().await;
        registry
            .with_manifest_package(
                json!({"name":"auto-json","version":"1.0.0","scripts":{"postinstall":script}}),
                &[],
            )
            .await;
        let project = TempProject::empty(
            r#"{"name":"host","version":"1.0.0","dependencies":{"auto-json":"1.0.0"},"lpm":{"trustedDependencies":["auto-json"]}}"#,
        );
        write_signed_unlock_for(
            &project,
            project.path(),
            &["sandbox-none", "trust-bulk-approve"],
        );
        let output = crate::support::lpm_with_registry(&project, &registry.url())
            .args(["install", "--auto-build", "--no-sandbox", "--json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            script == "exit 0",
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: Value = serde_json::from_slice(&output.stdout)
            .expect("install must own its JSON document during auto-build");
        assert_eq!(report["success"], script == "exit 0");
    }
}
