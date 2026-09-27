use super::*;

async fn mount_versions(mock: &MockRegistry, name: &str, latest: &str, versions: &[&str]) {
    let tarballs: Vec<_> = versions
        .iter()
        .map(|v| (*v, make_tarball(name, v)))
        .collect();
    let mut entries = serde_json::Map::new();
    let mut times = serde_json::Map::new();
    for (version, tarball) in &tarballs {
        entries.insert(version.to_string(), serde_json::json!({
            "name": name, "version": version,
            "dist": {"tarball": mock.tarball_url(name, version), "integrity": compute_integrity(tarball)}
        }));
        times.insert(
            version.to_string(),
            serde_json::json!("2025-01-01T00:00:00.000Z"),
        );
    }
    mock.with_package_metadata_and_tarballs(
        name,
        serde_json::json!({
            "name": name, "dist-tags": {"latest": latest}, "versions": entries, "time": times
        }),
        &tarballs,
    )
    .await;
}

fn lock_roots(project: &TempProject, roots: &[(&str, &str, &str)]) {
    let mut lock = lpm_lockfile::Lockfile::new();
    for (_, name, version) in roots {
        lock.add_package(lpm_lockfile::LockedPackage {
            name: (*name).into(),
            version: (*version).into(),
            source: Some("registry+https://lpm.dev".into()),
            ..Default::default()
        });
    }
    support::finalize_exact_lockfile_fixture(&mut lock, roots);
    lock.write_all(&project.path().join("lpm.lock")).unwrap();
}

#[tokio::test]
async fn targeted_upgrade_preserves_unselected_locked_root() {
    let a = "@lpm.dev/owner.selected";
    let b = "@lpm.dev/owner.unselected";
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "targeted-upgrade", "dependencies": {a: "^1.0.0", b: "^1.0.0"}
        })
        .to_string(),
    );
    lock_roots(&project, &[(a, a, "1.0.0"), (b, b, "1.0.0")]);
    let mock = MockRegistry::start().await;
    mount_versions(&mock, a, "1.1.0", &["1.0.0", "1.1.0"]).await;
    mount_versions(&mock, b, "1.2.0", &["1.0.0", "1.2.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", a, "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file(&format!("node_modules/{b}/package.json")))
            .unwrap();
    assert_eq!(
        installed["version"], "1.0.0",
        "unselected root must keep its locked version"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"][b], "^1.0.0");
}

#[tokio::test]
async fn targeted_upgrade_preserves_other_alias_version() {
    alias_snapshot("greedy-fusion").await;
}

#[tokio::test]
async fn targeted_upgrade_preserves_alias_snapshot_with_pubgrub() {
    alias_snapshot("pubgrub").await;
}

async fn alias_snapshot(resolver: &str) {
    let package = "@lpm.dev/owner.aliased";
    let project = TempProject::empty(&serde_json::json!({
        "name": "alias-upgrade", "dependencies": {"zzz": format!("npm:{package}@^1.0.0"), "aaa": format!("npm:{package}@^2.0.0")}
    }).to_string());
    lock_roots(
        &project,
        &[("zzz", package, "1.0.0"), ("aaa", package, "2.0.0")],
    );
    let mock = MockRegistry::start().await;
    mount_versions(&mock, package, "2.0.0", &["1.0.0", "1.1.0", "2.0.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .env("LPM_RESOLVER", resolver)
        .args(["upgrade", "zzz", "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "alias upgrade must retain the other version: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let requests = mock.server().received_requests().await.unwrap();
    let metadata_requests = requests
        .iter()
        .filter(|request| {
            request.url.path() == format!("/api/registry/{package}")
                || request.url.path() == "/api/registry/batch-metadata"
        })
        .count();
    assert_eq!(
        metadata_requests, 1,
        "all aliases must use the planned metadata snapshot: {requests:?}"
    );
    for (alias, expected) in [("zzz", "1.1.0"), ("aaa", "2.0.0")] {
        let manifest: serde_json::Value =
            serde_json::from_str(&project.read_file(&format!("node_modules/{alias}/package.json")))
                .unwrap();
        assert_eq!(manifest["version"], expected);
    }
}

#[tokio::test]
async fn upgrade_rejects_catalog_target_without_replacing_protocol() {
    let name = "@lpm.dev/owner.catalog";
    let project = TempProject::empty(&serde_json::json!({
        "name": "catalog-upgrade", "dependencies": {name: "catalog:"}, "catalogs": {"default": {name: "^1.0.0"}}
    }).to_string());
    lock_roots(&project, &[(name, name, "1.0.0")]);
    let before = project.read_file("package.json");
    let mock = MockRegistry::start().await;
    mount_versions(&mock, name, "2.0.0", &["1.0.0", "2.0.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", name, "-y", "--major", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "catalog must not be proposed as a plain range: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        parse_stdout_json(&out.stdout, &out.stderr)["error"]
            .as_str()
            .unwrap()
            .contains("catalog")
    );
    assert_eq!(project.read_file("package.json"), before);
}

#[tokio::test]
async fn upgrade_respects_rolled_back_latest_tag() {
    let name = "@lpm.dev/owner.rollback";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, name, "^1.0.0", "1.0.0");
    let mock = MockRegistry::start().await;
    mount_versions(&mock, name, "1.1.0", &["1.0.0", "1.1.0", "1.2.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        parse_stdout_json(&out.stdout, &out.stderr)["packages"][0]["to"],
        "1.1.0"
    );
}

#[tokio::test]
async fn upgrade_does_not_downgrade_a_stored_tag() {
    let name = "@lpm.dev/owner.tag";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, name, "latest", "2.0.0");
    let mock = MockRegistry::start().await;
    mount_versions(&mock, name, "1.9.0", &["1.9.0", "2.0.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(parse_stdout_json(&out.stdout, &out.stderr)["upgraded"], 0);
}

#[tokio::test]
async fn upgrade_preview_reports_npm_lifecycle_signals() {
    for signals in [
        serde_json::json!({"scripts": {"postinstall": "node build.js"}}),
        serde_json::json!({"hasInstallScript": true}),
    ] {
        let name = "script-preview";
        let project = TempProject::empty("");
        seed_pinned_dep(&project, name, "^1.0.0", "1.0.0");
        project.write_file(
            "lpm.lock",
            &project.read_file("lpm.lock").replace(
                "registry+https://lpm.dev",
                "registry+https://registry.npmjs.org",
            ),
        );
        let mock = MockRegistry::start().await;
        let mut target = serde_json::json!({"name": name, "version": "1.1.0"});
        target
            .as_object_mut()
            .unwrap()
            .extend(signals.as_object().unwrap().clone());
        mock.with_package_metadata_and_tarballs(
            name,
            serde_json::json!({
                "name": name, "dist-tags": {"latest": "1.1.0"},
                "versions": {"1.0.0": {"name": name, "version": "1.0.0"}, "1.1.0": target},
                "time": {"1.0.0": "2025-01-01T00:00:00.000Z", "1.1.0": "2025-01-01T00:00:00.000Z"}
            }),
            &[],
        )
        .await;
        let out = lpm_with_registry(&project, &mock.url())
            .args(["upgrade", "-y", "--dry-run", "--json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            parse_stdout_json(&out.stdout, &out.stderr)["packages"][0]["has_install_scripts"],
            true
        );
    }
}

#[tokio::test]
async fn upgrade_uses_effective_dependency_section_only() {
    let name = "@lpm.dev/owner.duplicate";
    for optional in [false, true] {
        let project = TempProject::empty(&serde_json::json!({
            "name": "duplicate-upgrade",
            "dependencies": {name: "^1.0.0"}, "devDependencies": {name: "^2.0.0"},
            "optionalDependencies": if optional { serde_json::json!({name: "^3.0.0"}) } else { serde_json::json!({}) }
        }).to_string());
        lock_roots(
            &project,
            &[(name, name, if optional { "3.0.0" } else { "1.0.0" })],
        );
        let mock = MockRegistry::start().await;
        mount_versions(
            &mock,
            name,
            "3.1.0",
            &["1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0", "3.1.0"],
        )
        .await;
        let out = lpm_with_registry(&project, &mock.url())
            .args(["upgrade", "-y", "--json", "--dry-run"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let json = parse_stdout_json(&out.stdout, &out.stderr);
        assert_eq!(json["packages"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["packages"][0]["to"],
            if optional { "3.1.0" } else { "1.1.0" }
        );
        assert_eq!(json["packages"][0]["is_dev"], false);
    }
}

#[tokio::test]
async fn upgrade_applies_selected_tag_without_replaying_old_lock() {
    let name = "@lpm.dev/owner.same-tag";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, name, "latest", "1.0.0");
    let mock = MockRegistry::start().await;
    mount_versions(&mock, name, "1.1.0", &["1.0.0", "1.1.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"][name], "latest");
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file(&format!("node_modules/{name}/package.json")))
            .unwrap();
    assert_eq!(installed["version"], "1.1.0");
}

#[tokio::test]
async fn targeted_upgrade_preserves_unselected_catalog_alias() {
    let selected = "@lpm.dev/owner.selected";
    let canonical = "@lpm.dev/owner.catalog-alias";
    let project = TempProject::empty(&serde_json::json!({
        "name": "catalog-alias-upgrade", "dependencies": {selected: "^1.0.0", "other": "catalog:"},
        "catalogs": {"default": {"other": format!("npm:{canonical}@^1.0.0")}}
    }).to_string());
    lock_roots(
        &project,
        &[(selected, selected, "1.0.0"), ("other", canonical, "1.0.0")],
    );
    let mock = MockRegistry::start().await;
    mount_versions(&mock, selected, "1.1.0", &["1.0.0", "1.1.0"]).await;
    mount_versions(&mock, canonical, "1.2.0", &["1.0.0", "1.2.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", selected, "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file("node_modules/other/package.json")).unwrap();
    assert_eq!(installed["version"], "1.0.0");
}

#[tokio::test]
async fn upgrade_rejects_a_missing_stored_tag() {
    let name = "@lpm.dev/owner.deleted-tag";
    let project = TempProject::empty("");
    seed_pinned_dep(&project, name, "next", "1.0.0");
    let before = project.read_file("package.json");
    let mock = MockRegistry::start().await;
    mount_versions(&mock, name, "1.1.0", &["1.0.0", "1.1.0"]).await;
    for flags in [
        vec!["upgrade", "-y", "--json", "--dry-run"],
        vec!["upgrade", "-y", "--json"],
    ] {
        let out = lpm_with_registry(&project, &mock.url())
            .args(flags)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "missing tag must fail: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(project.read_file("package.json"), before);
    }
}

#[tokio::test]
async fn targeted_upgrade_honors_a_changed_unselected_tag() {
    for (changed, catalog) in [(false, false), (true, false), (false, true), (true, true)] {
        let selected = "@lpm.dev/owner.selected";
        let tagged = "@lpm.dev/owner.tagged";
        let project = TempProject::empty(
            &serde_json::json!({
                "name": "changed-tag", "dependencies": {selected: "^1.0.0", tagged: if catalog { "catalog:" } else { "next" }},
                "catalogs": {"default": {tagged: "next"}}
            })
            .to_string(),
        );
        lock_roots(
            &project,
            &[(selected, selected, "1.0.0"), (tagged, tagged, "1.0.0")],
        );
        let mut lock =
            lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
        lock.importers.insert(
            ".".into(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: std::collections::BTreeMap::from([
                    (selected.into(), "^1.0.0".into()),
                    (
                        tagged.into(),
                        if catalog {
                            "catalog:"
                        } else if changed {
                            "^1.0.0"
                        } else {
                            "next"
                        }
                        .into(),
                    ),
                ]),
                ..Default::default()
            },
        );
        if catalog {
            lock.catalogs.insert(
                "default".into(),
                std::collections::BTreeMap::from([(
                    tagged.into(),
                    lpm_lockfile::CatalogSnapshotEntry {
                        specifier: if changed { "latest" } else { "next" }.into(),
                        version: "1.0.0".into(),
                        reference: "catalog:".into(),
                    },
                )]),
            );
        }
        lock.write_all(&project.path().join("lpm.lock")).unwrap();
        let mock = MockRegistry::start().await;
        mount_versions(&mock, selected, "1.1.0", &["1.0.0", "1.1.0"]).await;
        let mut versions = serde_json::Map::new();
        let tarballs: Vec<_> = ["1.0.0", "2.0.0"]
            .iter()
            .map(|v| (*v, make_tarball(tagged, v)))
            .collect();
        for (version, tarball) in &tarballs {
            versions.insert(version.to_string(), serde_json::json!({"name": tagged, "version": version, "dist": {"tarball": mock.tarball_url(tagged, version), "integrity": compute_integrity(tarball)}}));
        }
        mock.with_package_metadata_and_tarballs(tagged, serde_json::json!({"name": tagged, "dist-tags": {"latest": "2.0.0", "next": "2.0.0"}, "versions": versions, "time": {"1.0.0": "2025-01-01T00:00:00.000Z", "2.0.0": "2025-01-01T00:00:00.000Z"}}), &tarballs).await;
        let out = lpm_with_registry(&project, &mock.url())
            .args(["upgrade", selected, "-y", "--json"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let installed: serde_json::Value = serde_json::from_str(
            &project.read_file(&format!("node_modules/{tagged}/package.json")),
        )
        .unwrap();
        assert_eq!(
            installed["version"],
            if changed { "2.0.0" } else { "1.0.0" }
        );
    }
}

#[tokio::test]
async fn targeted_upgrade_keeps_planned_integrity_when_other_roots_need_metadata() {
    let selected = "@lpm.dev/owner.selected";
    let other = "@lpm.dev/owner.other";
    let project = TempProject::empty(&serde_json::json!({"name": "batch-snapshot", "dependencies": {selected: "^1.0.0", other: "^1.0.0"}}).to_string());
    lock_roots(
        &project,
        &[(selected, selected, "1.0.0"), (other, other, "1.0.0")],
    );
    let mock = MockRegistry::start().await;
    mount_versions(&mock, selected, "1.1.0", &["1.0.0", "1.1.0"]).await;
    mount_versions(&mock, other, "1.0.0", &["1.0.0"]).await;
    let changed = serde_json::json!({"name": selected, "dist-tags": {"latest": "1.1.0"},
        "versions": {"1.1.0": {"name": selected, "version": "1.1.0", "dist": {"tarball": mock.tarball_url(selected, "1.1.0"), "integrity": compute_integrity(b"changed bytes")}}},
        "time": {"1.1.0": "2025-01-01T00:00:00.000Z"}});
    Mock::given(method("POST"))
        .and(wiremock_path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(
                "{}\n",
                serde_json::json!({"name": selected, "metadata": changed})
            ),
            "application/x-ndjson",
        ))
        .with_priority(1)
        .expect(1)
        .mount(mock.server())
        .await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", selected, "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "planned integrity must survive unrelated metadata: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    assert_eq!(
        lock.packages
            .iter()
            .find(|p| p.name == selected)
            .unwrap()
            .integrity,
        Some(compute_integrity(&make_tarball(selected, "1.1.0")))
    );
}

#[tokio::test]
async fn targeted_upgrade_does_not_pin_a_previous_local_source() {
    let selected = "@lpm.dev/owner.selected";
    let other = "@lpm.dev/owner.changed-source";
    let project = TempProject::empty(&serde_json::json!({"name": "source-change", "dependencies": {selected: "^1.0.0", other: "^1.0.0"}}).to_string());
    let roots = [(selected, selected, "1.0.0"), (other, other, "1.0.0")];
    lock_roots(&project, &roots);
    let mut lock =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    lock.packages
        .iter_mut()
        .find(|p| p.name == other)
        .unwrap()
        .source = Some("directory+../local".into());
    lock.packages
        .iter_mut()
        .find(|p| p.name == other)
        .unwrap()
        .manifest_fingerprint = Some(format!("sha256-{}", "ab".repeat(32)));
    support::finalize_exact_lockfile_fixture(&mut lock, &roots);
    lock.write_all(&project.path().join("lpm.lock")).unwrap();
    let mock = MockRegistry::start().await;
    mount_versions(&mock, selected, "1.1.0", &["1.0.0", "1.1.0"]).await;
    mount_versions(&mock, other, "1.2.0", &["1.2.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .args(["upgrade", selected, "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "previous source must not pin the new registry dependency: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file(&format!("node_modules/{other}/package.json")))
            .unwrap();
    assert_eq!(installed["version"], "1.2.0");
}

#[tokio::test]
async fn upgrade_pubgrub_alias_preserves_canonical_parent_path_override() {
    let parent = "@lpm.dev/owner.override-parent";
    let child = "@lpm.dev/owner.override-child";
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "alias-override-upgrade",
            "dependencies": {"alias": format!("npm:{parent}@^1.0.0")},
            "lpm": {"overrides": {format!("{parent}>{child}"): "1.1.0"}}
        })
        .to_string(),
    );
    lock_roots(&project, &[("alias", parent, "1.0.0")]);
    let mock = MockRegistry::start().await;
    mock.with_full_package_metadata(
        parent,
        "1.1.0",
        &[
            (
                "1.0.0",
                serde_json::json!({child: "^1.0.0"}),
                Some(make_tarball(parent, "1.0.0")),
            ),
            (
                "1.1.0",
                serde_json::json!({child: "^1.0.0"}),
                Some(make_tarball(parent, "1.1.0")),
            ),
        ],
    )
    .await;
    mount_versions(&mock, child, "1.2.0", &["1.1.0", "1.2.0"]).await;
    let out = lpm_with_registry(&project, &mock.url())
        .env("LPM_RESOLVER", "pubgrub")
        .args(["upgrade", "alias", "-y", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let versions: Vec<_> = lock
        .packages
        .iter()
        .filter(|package| package.name == child)
        .map(|package| package.version.as_str())
        .collect();
    assert_eq!(
        versions,
        ["1.1.0"],
        "canonical parent path override must survive root alias identity"
    );
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/overrides-state.json")).unwrap();
    assert!(
        state["applied"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["package"] == child
                && hit["to_version"] == "1.1.0"
                && hit["via_parent"] == parent),
        "{state}"
    );
}
