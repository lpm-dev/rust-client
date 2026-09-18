use super::*;

#[test]
fn trust_diff_human_recommends_reviewing_the_manifest() {
    let project = TempProject::empty("{}");
    write_pkg_with_trust(
        &project,
        json!({"example@1.0.0":{"integrity":"sha512-example"}}),
    );
    let output = lpm(&project).args(["trust", "diff"]).output().unwrap();
    assert!(output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("review package.json"), "{combined}");
    assert!(!combined.contains("lpm trust review"));
}

#[test]
fn trust_commands_accept_bom_prefixed_project_manifests() {
    let mut failures = Vec::new();
    for args in [
        vec!["diff"],
        vec!["prune", "--dry-run"],
        vec!["lifecycle-scope", "list"],
        vec!["release-age-exclude", "list"],
        vec!["release-age-exclude", "add", "react"],
        vec!["lifecycle-scope", "add", "@company/*"],
    ] {
        let project = TempProject::empty("\u{feff}{\"name\":\"trust-bom\",\"version\":\"1.0.0\"}");
        write_lockfile(&project, &[]);
        write_signed_unlock(&project, &["trust-scope-widen"]);
        let output = lpm(&project)
            .arg("trust")
            .args(&args)
            .arg("--json")
            .output()
            .unwrap();
        if !output.status.success() {
            failures.push(format!(
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stdout)
            ));
            continue;
        }
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], true);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn trust_prune_rejects_non_object_project_manifests() {
    let project = TempProject::empty("null");
    write_lockfile(&project, &[]);
    let output = lpm(&project)
        .args(["trust", "prune", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn trust_commands_do_not_wait_on_special_input_files() {
    use std::time::{Duration, Instant};
    let mut failures = Vec::new();
    for (file, args) in [
        ("package.json", vec!["diff"]),
        ("package.json", vec!["prune", "--dry-run"]),
        ("package.json", vec!["lifecycle-scope", "list"]),
        ("package.json", vec!["release-age-exclude", "list"]),
        (".lpm/trust-snapshot.json", vec!["diff"]),
    ] {
        let project = TempProject::empty("{}");
        write_lockfile(&project, &[]);
        let path = project.path().join(file);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let mut child = lpm_spawnable(&project)
            .arg("trust")
            .args(&args)
            .arg("--json")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                if file == "package.json" {
                    assert!(!status.success(), "{args:?}");
                }
                break;
            }
            if started.elapsed() > Duration::from_secs(3) {
                child.kill().unwrap();
                child.wait().unwrap();
                failures.push(format!("{args:?} blocked on {file}"));
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

async fn assert_failed_root_lifecycle_preserves_snapshot(command_name: &str, force: bool) {
    use support::mock_registry::{MockRegistry, make_tarball};
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "snapshot-dep",
            "1.0.0",
            &make_tarball("snapshot-dep", "1.0.0"),
        )
        .await;
    let project = TempProject::empty(
        r#"{"name":"snapshot-host","version":"1.0.0","dependencies":{"snapshot-dep":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    support::lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    let snapshot_path = project.path().join(".lpm/trust-snapshot.json");
    let before = std::fs::read(&snapshot_path).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    manifest["scripts"] = json!({"postinstall":"exit 1"});
    manifest["lpm"] = json!({"trustedDependencies":["snapshot-dep"]});
    project.write_file("package.json", &manifest.to_string());
    write_signed_unlock(&project, &["trust-bulk-approve"]);
    let mut command = support::lpm_with_registry(&project, &registry.url());
    command.arg(command_name);
    if command_name == "install" {
        command.args(["--no-skills", "--no-security-summary"]);
    }
    if force {
        command.arg("--force");
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("postinstall"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&snapshot_path).unwrap(),
        before,
        "force={force}"
    );
}

#[tokio::test]
async fn failed_warm_root_lifecycle_preserves_the_previous_trust_snapshot() {
    assert_failed_root_lifecycle_preserves_snapshot("install", false).await;
}
#[tokio::test]
async fn failed_forced_root_lifecycle_preserves_the_previous_trust_snapshot() {
    assert_failed_root_lifecycle_preserves_snapshot("install", true).await;
}
#[tokio::test]
async fn failed_ci_root_lifecycle_preserves_the_previous_trust_snapshot() {
    assert_failed_root_lifecycle_preserves_snapshot("ci", false).await;
}

#[tokio::test]
async fn successful_root_script_changes_remain_visible_in_the_trust_diff() {
    use support::mock_registry::{MockRegistry, make_tarball};
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "snapshot-dep",
            "1.0.0",
            &make_tarball("snapshot-dep", "1.0.0"),
        )
        .await;
    let script = "node -e 'const fs=require(\"fs\");const p=JSON.parse(fs.readFileSync(\"package.json\",\"utf8\"));p.lpm={trustedDependencies:[\"added-by-script\"]};fs.writeFileSync(\"package.json\",JSON.stringify(p));'";
    let project = TempProject::empty(&json!({"name":"snapshot-host","version":"1.0.0","dependencies":{"snapshot-dep":"1.0.0"},"scripts":{"postinstall":script}}).to_string());
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    support::lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    let snapshot: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/trust-snapshot.json")).unwrap();
    assert_eq!(snapshot["bindings"], json!({}));
    let output = lpm(&project)
        .args(["trust", "diff", "--json", "--assert-none"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["added"][0]["key"], "added-by-script");
}

#[tokio::test]
async fn failed_dependency_auto_build_preserves_the_previous_trust_snapshot() {
    use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        json!({"name":"snapshot-build","version":"1.0.0","scripts":{"postinstall":"exit 1"}}),
        &[],
    );
    registry
        .with_package("snapshot-build", "1.0.0", &tarball)
        .await;
    let project = TempProject::empty(
        r#"{"name":"snapshot-host","version":"1.0.0","dependencies":{"snapshot-build":"1.0.0"},"lpm":{"trustedDependencies":["snapshot-build"]}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}\n", registry.url()));
    write_trust_snapshot(&project, json!({}));
    let before = project.read_file(".lpm/trust-snapshot.json");
    write_signed_unlock(
        &project,
        &["scripts-allow", "sandbox-none", "trust-bulk-approve"],
    );
    let output = support::lpm_with_registry(&project, &registry.url())
        .args([
            "install",
            "--policy",
            "allow",
            "--no-sandbox",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("script"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file(".lpm/trust-snapshot.json"), before);
}
