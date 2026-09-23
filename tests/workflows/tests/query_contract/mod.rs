use super::*;

#[test]
fn query_rejects_incompatible_count_options() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    for args in [
        vec!["query", "--count", "--assert-none"],
        vec!["query", "--count", "#sample"],
        vec!["query", "--count", "--format", "mermaid"],
    ] {
        let output = lpm(&project).args(&args).output().unwrap();
        assert!(
            !output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn query_rejects_mermaid_with_json() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    let output = lpm(&project)
        .args(["--json", "query", "#sample", "--format", "mermaid"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
}

#[test]
fn query_assertion_json_is_one_result_array() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN);
    let output = lpm(&project)
        .args(["--json", "query", "#sample", "--assert-none"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
}

#[test]
fn query_empty_counts_keep_the_count_schema() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    let output = lpm(&project)
        .args(["--json", "query", "--count"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["total"], 0);
    assert_eq!(report["eval"], 0);
}

#[test]
fn query_mermaid_honors_assert_none() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    let integrity = integrity_for(b"mermaid-sample");
    seed_v1_lpm_package(&project, "sample", "1.0.0", &integrity, SRC_CLEAN);
    write_lpm_lockfile(&project, &[("sample", "1.0.0", &integrity)]);
    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["query", "#sample", "--format", "mermaid", "--assert-none"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("graph TD"));
}

#[test]
fn query_refuses_missing_source_for_behavioral_and_disk_state_gates() {
    for selector in [":eval", ":scripts", ":built", ":not(:eval)"] {
        let project = TempProject::empty(
            r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#,
        );
        seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
        std::fs::remove_dir_all(project.path().join("node_modules/sample")).unwrap();
        let output = lpm(&project)
            .args(["--json", "query", selector, "--assert-none"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{selector}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["error"].is_string(), "{selector}: {report}");
    }
}

#[test]
fn query_refuses_partial_source_for_behavioral_gates() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", "function {", Some("MIT"));
    let output = lpm(&project)
        .args(["--json", "query", ":eval", "--assert-none"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"].is_string());
}

#[test]
fn query_refuses_invalid_script_manifest_for_script_gates() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    project.write_file("node_modules/sample/package.json", "{");
    let output = lpm(&project)
        .args(["--json", "query", ":scripts", "--assert-none"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"].is_string());
}

#[test]
fn query_workspace_root_children_use_standalone_root_dependencies() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    let output = lpm(&project)
        .args(["--json", "query", ":workspace-root > #sample"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
}

#[test]
fn query_root_children_include_optional_dependencies_from_nested_directories() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","optionalDependencies":{"sample":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    std::fs::create_dir_all(project.path().join("src/nested")).unwrap();
    for current in [
        project.path().to_path_buf(),
        project.path().join("src/nested"),
    ] {
        let output = lpm(&project)
            .current_dir(current)
            .args(["--json", "query", ":root > #sample"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report.as_array().unwrap().len(), 1);
    }
}

#[test]
fn query_exact_versions_accept_semver_build_metadata() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0+build.1"}}"#,
    );
    seed_pkg_with_source(&project, "sample", "1.0.0+build.1", SRC_CLEAN);
    let output = lpm(&project)
        .args(["--json", "query", "#sample@1.0.0+build.1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn query_deprecation_uses_the_configured_registry_without_lpm_disclosure() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"private-pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "private-pkg", "1.0.0", SRC_CLEAN);
    let lpm_registry = MockRegistry::start().await;
    let private_registry = MockRegistry::start().await;
    project.write_file(".npmrc", &format!("registry={}\n", private_registry.url()));
    let metadata = serde_json::json!({"name":"private-pkg","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"private-pkg","version":"1.0.0","deprecated":"use replacement"}}});
    Mock::given(method("GET"))
        .and(path("/private-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata.clone()))
        .mount(private_registry.server())
        .await;
    let mut stale = metadata;
    stale["versions"]["1.0.0"]
        .as_object_mut()
        .unwrap()
        .remove("deprecated");
    lpm_registry.with_batch_metadata(vec![stale]).await;
    let output = lpm(&project)
        .args(["--registry", &lpm_registry.url(), "--insecure"])
        .args(["query", ":deprecated", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1, "{report}");
    let requests = lpm_registry.server().received_requests().await.unwrap();
    assert!(
        !requests
            .iter()
            .any(|request| String::from_utf8_lossy(&request.body).contains("private-pkg"))
    );
}

#[test]
fn query_direct_children_include_exact_peer_targets() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"consumer":"1.0.0","peer":"1.0.0"}}"#,
    );
    let source = "registry+https://registry.npmjs.org";
    let consumer_id =
        lpm_common::PackageInstanceId::derive("consumer", "1.0.0", source, "consumer");
    let peer_id = lpm_common::PackageInstanceId::derive("peer", "1.0.0", source, "peer");
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
    for (name, instance_id) in [("consumer", consumer_id), ("peer", peer_id)] {
        let integrity = integrity_for(name.as_bytes());
        seed_v1_lpm_package(&project, name, "1.0.0", &integrity, SRC_CLEAN);
        let mut package = lpm_lockfile::LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            instance_id: Some(instance_id),
            source: Some(source.into()),
            integrity: Some(integrity),
            ..Default::default()
        };
        if name == "consumer" {
            package.peer_targets.insert("peer".into(), peer_id);
            package
                .peer_edges
                .push(lpm_common::PeerEdge::registry("peer", "peer", "1.0.0"));
        }
        lockfile.add_package(package);
        lockfile.root_resolutions.insert(
            name.into(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: name.into(),
                version: "1.0.0".into(),
                source: Some(source.into()),
            },
        );
    }
    lockfile.importers.insert(
        ".".into(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: std::collections::BTreeMap::from([
                ("consumer".into(), "1.0.0".into()),
                ("peer".into(), "1.0.0".into()),
            ]),
            ..Default::default()
        },
    );
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["query", "#consumer > #peer", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1, "{report}");
}

#[test]
fn query_virtual_root_anchors_do_not_match_dependency_rows() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    std::fs::create_dir_all(project.path().join("src/nested")).unwrap();
    let output = lpm(&project)
        .current_dir(project.path().join("src/nested"))
        .args(["query", ":workspace-root", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 0);
}

#[test]
fn query_root_selection_rejects_malformed_manifest_instead_of_passing_a_gate() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    project.write_file("package.json", "{");
    let output = lpm(&project)
        .args(["query", ":root > #sample", "--assert-none", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"].is_string());
}

#[test]
fn query_root_selection_accepts_bom_prefixed_manifest() {
    let project = TempProject::empty(
        "\u{feff}{\"name\":\"q\",\"version\":\"1.0.0\",\"dependencies\":{\"sample\":\"1.0.0\"}}",
    );
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    let output = lpm(&project)
        .args(["query", ":root > #sample", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1);
}

#[test]
fn query_empty_mermaid_is_a_valid_empty_graph() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);
    write_lpm_lockfile(&project, &[]);
    let output = lpm(&project)
        .args(["query", "#missing", "--format", "mermaid", "--assert-none"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("graph TD"));
}

#[test]
fn query_root_children_resolve_alias_installation_names() {
    for alias in ["my-lib", "@local/my-lib"] {
        let project = TempProject::empty(&serde_json::json!({"name":"q","version":"1.0.0","dependencies":{alias:"npm:real-lib@1.0.0"}}).to_string());
        project.write_file(
            &format!("node_modules/{alias}/package.json"),
            r#"{"name":"real-lib","version":"1.0.0","license":"MIT"}"#,
        );
        project.write_file(&format!("node_modules/{alias}/index.js"), SRC_CLEAN);
        for selector in [
            "#real-lib",
            ":root > #real-lib",
            ":workspace-root > #real-lib",
        ] {
            let output = lpm(&project)
                .args(["query", selector, "--json"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{alias} {selector}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report.as_array().unwrap().len(),
                1,
                "{alias} {selector}: {report}"
            );
        }
    }
}

#[test]
fn query_manifest_gates_reject_missing_or_invalid_manifests() {
    for manifest in [None, Some("{"), Some("null")] {
        let project = TempProject::empty(
            r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#,
        );
        seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
        if let Some(content) = manifest {
            project.write_file("node_modules/sample/package.json", content);
        } else {
            std::fs::remove_file(project.path().join("node_modules/sample/package.json")).unwrap();
        }
        for selector in [":copyleft", ":no-license", ":not(:copyleft)"] {
            let output = lpm(&project)
                .args(["query", selector, "--assert-none", "--json"])
                .output()
                .unwrap();
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                output.status.code(),
                Some(1),
                "{manifest:?} {selector}: {report}"
            );
            assert!(
                report["error"].is_string(),
                "{manifest:?} {selector}: {report}"
            );
        }
    }
}

#[test]
fn query_script_gates_reject_non_object_manifests() {
    for manifest in ["null", "[]"] {
        let project = TempProject::empty(
            r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#,
        );
        seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
        project.write_file("node_modules/sample/package.json", manifest);
        let output = lpm(&project)
            .args(["query", ":scripts", "--assert-none", "--json"])
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1), "{manifest}: {report}");
        assert!(report["error"].is_string(), "{manifest}: {report}");
    }
}

#[test]
fn query_root_gates_reject_non_object_manifests() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"sample":"1.0.0"}}"#);
    seed_locked_pkg_with_source(&project, "sample", "1.0.0", SRC_CLEAN, Some("MIT"));
    project.write_file("package.json", "null");
    let output = lpm(&project)
        .args(["query", ":root > #sample", "--assert-none", "--json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert!(report["error"].is_string(), "{report}");
}

#[test]
fn query_member_identity_does_not_require_the_workspace_root_manifest() {
    let project = support::workspace_projection_project();
    project.write_file("package.json", "{");
    let output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .args(["query", "#app-only", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1, "{report}");
}

#[test]
fn query_package_relationships_do_not_require_a_project_manifest() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);
    seed_pkg_with_source(&project, "parent", "1.0.0", SRC_CLEAN);
    seed_pkg_with_source(&project, "child", "1.0.0", SRC_CLEAN);
    project.write_file(
        "node_modules/parent/package.json",
        r#"{"name":"parent","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#,
    );
    std::fs::remove_file(project.path().join("package.json")).unwrap();
    let output = lpm(&project)
        .args(["query", "#parent > #child", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 1, "{report}");
}
