use super::*;

#[tokio::test]
async fn audit_fix_rejects_a_candidate_without_canonical_version_metadata() {
    let project = TempProject::empty(
        r#"{"name":"candidate-identity","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let metadata = serde_json::json!({"name":"vuln-pkg","dist-tags":{"latest":"v1.0.1"},"versions":{
        "1.0.0":{"name":"vuln-pkg","version":"1.0.0"},
        "v1.0.1":{"name":"vuln-pkg","version":"9.0.0"}
    }});
    for route in ["/api/registry/vuln-pkg", "/vuln-pkg"] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
            .with_priority(1)
            .mount(mock.server())
            .await;
    }
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-candidate",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;
    std::fs::remove_dir_all(project.cache_dir().join("metadata")).unwrap();
    let output = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{envelope}");
    assert_eq!(envelope["planned"], 0);
    assert!(
        envelope["skipped"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("metadata"),
        "{envelope}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn audit_fallback_rejects_linked_manifests() {
    unsafe_manifest_fixture(false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn audit_fallback_rejects_fifo_manifests_without_blocking() {
    unsafe_manifest_fixture(false, true).await;
}

#[cfg(unix)]
#[tokio::test]
async fn audit_fix_rejects_linked_manifests() {
    unsafe_manifest_fixture(true, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn audit_fix_rejects_fifo_manifests_without_blocking() {
    unsafe_manifest_fixture(true, true).await;
}

#[cfg(unix)]
async fn unsafe_manifest_fixture(fix: bool, fifo: bool) {
    let project = TempProject::empty(
        r#"{"name":"unsafe-manifest","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    if fix {
        install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    } else {
        project.write_file("node_modules/vuln-pkg/package.json", "{}");
    }
    mock.with_osv_querybatch(vec![vec![]]).await;
    let manifest = project.path().join("node_modules/vuln-pkg/package.json");
    std::fs::remove_file(&manifest).unwrap();
    let outside = tempfile::tempdir().unwrap();
    if fifo {
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&manifest)
                .status()
                .unwrap()
                .success()
        );
    } else {
        let target = outside.path().join("package.json");
        std::fs::write(&target, r#"{"name":"vuln-pkg","version":"1.0.0"}"#).unwrap();
        std::os::unix::fs::symlink(&target, &manifest).unwrap();
    }
    assert_unsafe_manifest_rejected(&project, &mock, fix);
}

#[cfg(unix)]
fn assert_unsafe_manifest_rejected(project: &TempProject, mock: &MockRegistry, fix: bool) {
    let mut command = lpm_with_registry(project, &mock.url());
    command
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args(["audit", "--json"])
        .timeout(std::time::Duration::from_secs(5));
    if fix {
        command.args(["fix", "--dry-run"]);
    }
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "audit must reject unsafe manifests promptly"
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], false);
    let reason = if fix {
        &envelope["skipped"][0]["reason"]
    } else {
        &envelope["error"]
    };
    assert!(
        reason
            .as_str()
            .is_some_and(|reason| reason.contains("package.json")),
        "{envelope}"
    );
}

#[test]
fn audit_fix_accepts_a_bom_manifest_without_changing_it_during_preview() {
    let project = TempProject::empty("\u{feff}{\"name\":\"bom-audit\",\"version\":\"1.0.0\"}");
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = {}\nresolved-with = \"pubgrub\"\n",
            2
        ),
    );
    let before = std::fs::read(project.path().join("package.json")).unwrap();
    let output = lpm(&project)
        .args(["audit", "fix", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        std::fs::read(project.path().join("package.json")).unwrap(),
        before
    );
}

#[test]
fn audit_subcommands_reject_ignored_scan_flags_before_discovery() {
    let project = TempProject::empty(r#"{"name":"scan-flags","version":"1.0.0"}"#);
    project.write_file(
        "lpm.lock",
        &format!(
            "[metadata]\nlockfile-version = {}\nresolved-with = \"pubgrub\"\n",
            2
        ),
    );
    for mode in ["fix", "signatures"] {
        for flag in ["--level=critical", "--fail-on=all", "--fail-on=invalid"] {
            let output = lpm(&project)
                .args(["audit", flag, mode, "--json"])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "audit {flag} {mode} silently accepted an ignored flag: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(envelope["error_code"], "usage");
        }
    }
}

#[test]
fn audit_secrets_fails_closed_when_a_source_file_exceeds_the_read_limit() {
    let project = TempProject::empty(r#"{"name":"large-secret-source","version":"1.0.0"}"#);
    let source = "x".repeat(2 * 1024 * 1024 + 1);
    seed_node_modules_package(&project, "large-source", &[("index.js", &source)]);
    let output = lpm(&project)
        .args(["audit", "--secrets", "--fail-on=vuln", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], false);
    assert!(envelope["error"].as_str().unwrap().contains("index.js"));
}

#[cfg(unix)]
#[test]
fn audit_secrets_fails_closed_when_a_source_file_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"unreadable-secret-source","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "unreadable-source",
        &[("index.js", "const value = 1;")],
    );
    let path = project
        .path()
        .join("node_modules/unreadable-source/index.js");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
    let output = lpm(&project)
        .args(["audit", "--secrets", "--json"])
        .output()
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn audit_secrets_fails_closed_when_a_source_directory_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt;

    let project = TempProject::empty(r#"{"name":"unreadable-secret-directory","version":"1.0.0"}"#);
    seed_node_modules_package(
        &project,
        "unreadable-source",
        &[("lib/index.js", "const value = 1;")],
    );
    let path = project.path().join("node_modules/unreadable-source/lib");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
    let output = lpm(&project)
        .args(["audit", "--secrets", "--json"])
        .output()
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn audit_secrets_fails_closed_for_dangling_package_links() {
    let project = TempProject::empty(r#"{"name":"dangling-secret-package","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    std::os::unix::fs::symlink(
        "missing-package",
        project.path().join("node_modules/broken"),
    )
    .unwrap();
    let output = lpm(&project)
        .args(["audit", "--secrets", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn audit_fallback_rejects_an_unreadable_package_inventory() {
    for manifest in ["not json", "{}", r#"{"name":"invalid","version":3}"#] {
        let project = TempProject::empty(r#"{"name":"fallback-inventory","version":"1.0.0"}"#);
        project.write_file("node_modules/invalid/package.json", manifest);
        let mock = MockRegistry::start().await;
        mock.with_osv_querybatch(vec![]).await;
        let output = run_audit_json(&project, &mock, &[]);
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn audit_fallback_does_not_report_a_complete_inventory_after_skipping_package_links() {
    let project = TempProject::empty(r#"{"name":"fallback-links","version":"1.0.0"}"#);
    project.write_file(
        "packages/local/package.json",
        r#"{"name":"local","version":"1.0.0"}"#,
    );
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    std::os::unix::fs::symlink(
        "../packages/local",
        project.path().join("node_modules/local"),
    )
    .unwrap();
    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![]).await;
    let output = run_audit_json(&project, &mock, &[]);
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

async fn registry_audit_fixture(
    version: &str,
    severity: Option<&str>,
) -> (TempProject, MockRegistry) {
    let package = "@lpm.dev/test.audit-contract";
    let project = TempProject::empty(&format!(
        r#"{{"name":"registry-audit-contract","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    install_one(&project, &mock, package).await;
    let mut entry = serde_json::json!({"name":package,"version":version,"dependencies":{}});
    if let Some(severity) = severity {
        entry["_vulnerabilities"] =
            serde_json::json!([{"id":"REGISTRY-CONTRACT","severity":severity}]);
    }
    let metadata = serde_json::json!({"name":package,"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":entry}});
    let batch = format!(
        "{}\n",
        serde_json::json!({"name":package,"metadata":metadata})
    );
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(batch, "application/x-ndjson"))
        .with_priority(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .with_priority(1)
        .mount(mock.server())
        .await;
    mock.with_osv_querybatch(vec![]).await;
    let _ = std::fs::remove_dir_all(project.cache_dir().join("metadata"));
    (project, mock)
}

#[tokio::test]
async fn audit_registry_severity_cannot_hide_an_advisory_from_the_failure_policy() {
    for severity in ["HIGH ", "unknown"] {
        let (project, mock) = registry_audit_fixture("1.0.0", Some(severity)).await;
        let output = run_audit_json(&project, &mock, &["--level=high", "--fail-on=vuln"]);
        assert!(
            !output.status.success(),
            "{severity}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if severity == "HIGH " {
            assert_eq!(envelope["success"], true);
            assert!(
                envelope["packages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|package| {
                        package["issues"].as_array().unwrap().iter().any(|issue| {
                            issue["severity"] == "high" && issue["category"] == "vulnerability"
                        })
                    }),
                "{envelope}"
            );
        } else {
            assert!(
                envelope["error"]
                    .as_str()
                    .unwrap()
                    .contains("unsupported audit severity")
            );
        }
    }
}

#[tokio::test]
async fn audit_rejects_registry_version_identity_mismatches() {
    let (project, mock) = registry_audit_fixture("2.0.0", None).await;
    let output = run_audit_json(&project, &mock, &[]);
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn audit_fix_rejects_registry_version_identity_mismatches() {
    let (project, mock) = registry_audit_fixture("2.0.0", None).await;
    let output = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn audit_fix_uses_the_exact_root_instance_among_duplicate_coordinates() {
    let project = TempProject::empty(
        r#"{"name":"exact-root-fix","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let lock_path = project.path().join("lpm.lock");
    let mut lock = lpm_lockfile::Lockfile::read_fast(&lock_path).unwrap();
    let mut other = lock.find_package("vuln-pkg").unwrap().clone();
    other.instance_id = Some(lpm_common::PackageInstanceId::derive(
        &other.name,
        &other.version,
        other.source.as_deref().unwrap(),
        "fixture/local-fork",
    ));
    let mut second_root = lock.root_resolutions["vuln-pkg"].clone();
    second_root.instance_id = other.instance_id;
    lock.root_resolutions
        .insert("other-vuln".into(), second_root);
    lock.importers
        .get_mut(".")
        .unwrap()
        .dependencies
        .insert("other-vuln".into(), "npm:vuln-pkg@1.0.0".into());
    project.write_file("package.json", r#"{"name":"exact-root-fix","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0","other-vuln":"npm:vuln-pkg@1.0.0"}}"#);
    project.write_file(
        "node_modules/other-vuln/package.json",
        r#"{"name":"vuln-pkg","version":"1.0.0"}"#,
    );
    lock.add_package(other);
    lock.write_all(&lock_path).unwrap();
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-exact-root",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;
    let output = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["planned"], 2);
    assert_eq!(envelope["packages"][0]["to"], "1.0.1");
}

#[tokio::test]
async fn audit_fix_accepts_lockfiles_larger_than_the_configuration_file_limit() {
    let project = TempProject::empty(
        r#"{"name":"large-lock-fix","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let mut content = project.read_file("lpm.lock");
    content.push_str("\n#");
    content.extend(std::iter::repeat_n(
        'x',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize,
    ));
    content.push('\n');
    project.write_file("lpm.lock", &content);
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln(
        "GHSA-large-lock",
        "vuln-pkg",
        "1.0.1",
    )]])
    .await;
    let output = run_audit_json(&project, &mock, &["fix"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["fixed"], 1);
}

#[tokio::test]
async fn install_does_not_report_an_incomplete_source_audit_as_completed() {
    let project = TempProject::empty(
        r#"{"name":"partial-install-audit","version":"1.0.0","dependencies":{"partial-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    let tarball = make_tarball_with_files("partial-pkg", "1.0.0", &[("index.js", b"function {")]);
    mock.with_package("partial-pkg", "1.0.0", &tarball).await;
    mock.with_osv_querybatch(vec![vec![]]).await;
    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args([
            "install",
            "--audit-after-install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("Audited"), "{stderr}");
    assert!(stderr.contains("audit-after-install failed"), "{stderr}");
}

#[tokio::test]
async fn audit_fix_accepts_an_installed_dependency_manifest_with_a_bom() {
    let project = TempProject::empty(
        r#"{"name":"installed-bom-fix","version":"1.0.0","dependencies":{"vuln-pkg":"1.0.0"}}"#,
    );
    let mock = MockRegistry::start().await;
    install_vulnerable_direct_dep_with_fixed_version(&project, &mock).await;
    let path = "node_modules/vuln-pkg/package.json";
    let content = project.read_file(path);
    project.write_file(path, &format!("\u{feff}{content}"));
    mock.with_osv_querybatch(vec![vec![osv_fixed_vuln("GHSA-bom", "vuln-pkg", "1.0.1")]])
        .await;
    let output = run_audit_json(&project, &mock, &["fix", "--dry-run"]);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{envelope}");
    assert_eq!(envelope["planned"], 1);
}

#[tokio::test]
async fn audit_fix_rolls_back_when_verification_metadata_changes_version_identity() {
    let package = "@lpm.dev/test.verify-identity";
    let project = TempProject::empty(&format!(
        r#"{{"name":"verify-identity","version":"1.0.0","dependencies":{{"{package}":"1.0.0"}}}}"#
    ));
    let mock = MockRegistry::start().await;
    let vulnerable = make_tarball(package, "1.0.0");
    let fixed = make_tarball(package, "1.0.1");
    let metadata = serde_json::json!({
        "name": package, "dist-tags": {"latest": "1.0.1"},
        "versions": {
            "1.0.0": {"name": package, "version": "1.0.0", "dist": {
                "tarball": format!("{}{}", mock.url(), MockRegistry::tarball_path(package, "1.0.0")),
                "integrity": support::mock_registry::compute_integrity(&vulnerable)
            }, "_vulnerabilities": [{"id": "VERIFY-ID", "severity": "high"}]},
            "1.0.1": {"name": package, "version": "1.0.1", "dist": {
                "tarball": format!("{}{}", mock.url(), MockRegistry::tarball_path(package, "1.0.1")),
                "integrity": support::mock_registry::compute_integrity(&fixed)
            }}
        }
    });
    mock.with_package_metadata_and_tarballs(
        package,
        metadata.clone(),
        &[("1.0.0", vulnerable), ("1.0.1", fixed.clone())],
    )
    .await;
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed_tarball = served.clone();
    Mock::given(method("GET"))
        .and(path(MockRegistry::tarball_path(package, "1.0.1")))
        .respond_with(move |_: &wiremock::Request| {
            observed_tarball.store(true, std::sync::atomic::Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_bytes(fixed.clone())
        })
        .with_priority(1)
        .mount(mock.server())
        .await;
    let observed = served.clone();
    Mock::given(method("GET"))
        .and(path(format!("/api/registry/{package}")))
        .respond_with(move |_: &wiremock::Request| {
            let mut response = metadata.clone();
            if observed.load(std::sync::atomic::Ordering::SeqCst) {
                response["versions"]["1.0.1"]["version"] = "2.0.0".into();
            }
            ResponseTemplate::new(200).set_body_json(response)
        })
        .with_priority(1)
        .mount(mock.server())
        .await;
    let manifest = project.read_file("package.json");
    let lockfile = project.read_file("lpm.lock");
    let output = run_audit_json(&project, &mock, &["fix"]);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        served.load(std::sync::atomic::Ordering::SeqCst),
        "{envelope}"
    );
    assert!(!output.status.success(), "{envelope}");
    assert!(
        envelope["error"]
            .as_str()
            .unwrap()
            .contains("inconsistent version metadata"),
        "{envelope}"
    );
    assert_eq!(project.read_file("package.json"), manifest);
    assert_eq!(project.read_file("lpm.lock"), lockfile);
}
