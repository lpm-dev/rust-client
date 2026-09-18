use super::*;

fn show(project: &TempProject) -> Output {
    lpm(project)
        .args(["catalog", "show", "--resolved", "--json"])
        .output()
        .unwrap()
}

fn snapshot(reference: &str, specifier: &str, version: &str) -> lpm_lockfile::Lockfile {
    let mut lock = lpm_lockfile::Lockfile::new();
    lock.catalogs.entry("default".into()).or_default().insert(
        "addon".into(),
        lpm_lockfile::CatalogSnapshotEntry {
            specifier: specifier.into(),
            version: version.into(),
            reference: reference.into(),
        },
    );
    lock
}

fn workspace() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"default":{"addon":"^1"}}}"#,
    );
    for name in ["a", "b"] {
        project.write_file(
            &format!("packages/{name}/package.json"),
            &format!(r#"{{"name":"{name}","dependencies":{{"addon":"catalog:"}}}}"#),
        );
    }
    project
}

#[test]
fn resolved_catalog_does_not_require_peer_only_or_shadowed_references() {
    for manifest in [
        r#"{"peerDependencies":{"addon":"catalog:"}}"#,
        r#"{"devDependencies":{"addon":"catalog:"},"dependencies":{"addon":"1.0.0"}}"#,
        r#"{"dependencies":{"addon":"catalog:"},"optionalDependencies":{"addon":"1.0.0"}}"#,
        r#"{"overrides":{"addon":"catalog:"}}"#,
    ] {
        let mut value: serde_json::Value = serde_json::from_str(manifest).unwrap();
        value["catalogs"] = serde_json::json!({"default":{"addon":"^1"}});
        let project = TempProject::empty(&value.to_string());
        lpm_lockfile::Lockfile::new()
            .write_all(&project.path().join("lpm.lock"))
            .unwrap();
        let output = show(&project);
        assert!(
            output.status.success(),
            "{}: {}",
            manifest,
            output_text(&output)
        );
    }
}

#[test]
fn resolved_catalog_validates_each_recorded_importer_before_aggregation() {
    let project = workspace();
    let mut union = lpm_lockfile::Lockfile::new();
    union
        .absorb_importer("packages/a", snapshot("catalog:", "^1", "1.0.0"))
        .unwrap();
    union
        .absorb_importer("packages/b", lpm_lockfile::Lockfile::new())
        .unwrap();
    union.write_all(&project.path().join("lpm.lock")).unwrap();
    let output = show(&project);
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("packages/b"));
}

#[test]
fn resolved_catalog_ignores_importers_outside_the_saved_scope() {
    let project = workspace();
    project.write_file(
        "packages/b/package.json",
        r#"{"name":"b","dependencies":{"missing":"catalog:other"}}"#,
    );
    let mut union = lpm_lockfile::Lockfile::new();
    union
        .absorb_importer("packages/a", snapshot("catalog:", "^1", "1.0.0"))
        .unwrap();
    union.write_all(&project.path().join("lpm.lock")).unwrap();
    let output = show(&project);
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn resolved_catalog_normalizes_equivalent_default_references_without_changing_lockfile() {
    let project = workspace();
    let mut union = lpm_lockfile::Lockfile::new();
    union
        .absorb_importer("packages/a", snapshot("catalog:default", "^1", "1.0.0"))
        .unwrap();
    union
        .absorb_importer("packages/b", snapshot("catalog:", "^1", "1.0.0"))
        .unwrap();
    union.write_all(&project.path().join("lpm.lock")).unwrap();
    let before = project.read_file("lpm.lock");
    let output = show(&project);
    assert!(output.status.success(), "{}", output_text(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["entries"][0]["reference"], "catalog:");
    assert_eq!(before, project.read_file("lpm.lock"));
}

#[test]
fn resolved_catalog_rejects_different_versions_or_specifiers() {
    for (range, version) in [("^1.0", "1.0.0"), ("^1", "1.1.0")] {
        let project = workspace();
        let mut union = lpm_lockfile::Lockfile::new();
        union
            .absorb_importer("packages/a", snapshot("catalog:", "^1", "1.0.0"))
            .unwrap();
        union
            .absorb_importer("packages/b", snapshot("catalog:default", range, version))
            .unwrap();
        union.write_all(&project.path().join("lpm.lock")).unwrap();
        let output = show(&project);
        assert!(!output.status.success(), "{}", output_text(&output));
    }
}

#[tokio::test]
async fn optional_missing_catalog_dependency_allows_install_inspection_and_replay() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"app","dependencies":{"is-positive":"1.0.0"},"optionalDependencies":{"missing-addon":"catalog:"},"catalogs":{"default":{"missing-addon":"^1"}}}"#,
    );
    let output = run_install(&project, &mock, &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(catalog_snapshot_entry_optional(&project, "default", "missing-addon").is_none());
    let output = show(&project);
    assert!(output.status.success(), "{}", output_text(&output));
    for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
        let output = run_install(&project, &mock, args);
        assert!(output.status.success(), "{}", output_text(&output));
    }
}

#[tokio::test]
async fn transitive_package_cannot_supply_a_skipped_optional_catalog_snapshot() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mock.with_full_package_metadata(
        "host",
        "1.0.0",
        &[(
            "1.0.0",
            serde_json::json!({"is-positive":"1.0.0"}),
            Some(make_tarball("host", "1.0.0")),
        )],
    )
    .await;
    let project = TempProject::empty(
        r#"{"name":"app","dependencies":{"host":"1.0.0"},"optionalDependencies":{"is-positive":"catalog:"},"catalogs":{"default":{"is-positive":"^99"}}}"#,
    );
    let output = run_install(&project, &mock, &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        catalog_snapshot_entry_optional(&project, "default", "is-positive").is_none(),
        "{}",
        project.read_file("lpm.lock")
    );
    let saved = lpm_lockfile::Lockfile::read_for_project(project.path())
        .unwrap()
        .lockfile;
    assert!(!saved.root_resolutions.contains_key("is-positive"));
    for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
        let output = run_install(&project, &mock, args);
        assert!(output.status.success(), "{}", output_text(&output));
    }
}

#[tokio::test]
async fn selected_platform_optional_catalog_requires_its_saved_snapshot() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({"name":"addon","version":"1.0.0","os":["unavailable-platform"]}),
        &[],
    )
    .await;
    mount_is_positive_versions(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"app","dependencies":{"is-positive":"1.0.0"},"optionalDependencies":{"addon":"catalog:"},"catalogs":{"default":{"addon":"^1"}}}"#,
    );
    let output = run_install(&project, &mock, &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        catalog_snapshot_entry(&project, "default", "addon").version,
        "1.0.0"
    );
    assert!(!project.path().join("node_modules/addon").exists());
    let mut lock = lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap();
    lock.catalogs.clear();
    for importer in lock.importers.values_mut() {
        importer.catalog_resolutions.clear();
    }
    lock.write_all(&project.path().join("lpm.lock")).unwrap();
    let output = show(&project);
    assert!(!output.status.success(), "{}", output_text(&output));
    let output = run_install(&project, &mock, &["--frozen-lockfile"]);
    assert!(!output.status.success(), "{}", output_text(&output));
}

#[tokio::test]
async fn ambient_peer_cannot_supply_a_skipped_optional_catalog_snapshot() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mock.with_manifest_package(serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"is-positive":"^1"}}), &[]).await;
    let project = TempProject::empty(
        r#"{"name":"app","dependencies":{"host":"1.0.0"},"optionalDependencies":{"is-positive":"catalog:"},"catalogs":{"default":{"is-positive":"^99"}}}"#,
    );
    let output = run_install(&project, &mock, &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        catalog_snapshot_entry_optional(&project, "default", "is-positive").is_none(),
        "{}",
        project.read_file("lpm.lock")
    );
    let output = show(&project);
    assert!(output.status.success(), "{}", output_text(&output));
    for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
        let output = run_install(&project, &mock, args);
        assert!(output.status.success(), "{}", output_text(&output));
    }
}

#[tokio::test]
async fn workspace_ambient_peer_does_not_resolve_a_skipped_optional_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mock.with_manifest_package(serde_json::json!({"name":"host","version":"1.0.0","peerDependencies":{"is-positive":"^1"}}), &[]).await;
    let project = TempProject::empty(
        r#"{"name":"root","private":true,"workspaces":["packages/*"],"catalogs":{"default":{"is-positive":"^99"}}}"#,
    );
    project.write_file("packages/app/package.json",r#"{"name":"app","dependencies":{"host":"1.0.0"},"optionalDependencies":{"is-positive":"catalog:"}}"#);
    project.write_file("packages/other/package.json", r#"{"name":"other","dependencies":{"host":"1.0.0"},"optionalDependencies":{"is-positive":"catalog:"}}"#);
    let output = lpm_with_registry(&project, &mock.url())
        .env("RUST_LOG", "lpm=debug")
        .arg("--verbose")
        .args(INSTALL_ARGS)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let lock = lpm_lockfile::Lockfile::read_for_project(&project.path().join("packages/app"))
        .unwrap()
        .lockfile;
    assert!(lock.catalogs.is_empty(), "{:?}", lock.catalogs);
    assert!(
        lock.ambient_peer_installs
            .iter()
            .any(|name| name == "is-positive")
    );
    let output = show(&project);
    assert!(output.status.success(), "{}", output_text(&output));
    for args in [&["--frozen-lockfile"][..], &["--offline"][..]] {
        let output = run_install(&project, &mock, args);
        assert!(output.status.success(), "{}", output_text(&output));
    }
}
