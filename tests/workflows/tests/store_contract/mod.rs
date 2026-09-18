use super::*;
use std::path::{Path, PathBuf};

fn run_install(project: &TempProject, path: &Path, version: &str) {
    let output = lpm(project)
        .current_dir(path)
        .env("LPM_STORE_VERSION", version)
        .args(["install", "--no-security-summary"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "install failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify(project: &TempProject, path: &Path) -> (bool, serde_json::Value) {
    let output = lpm(project)
        .current_dir(path)
        .args(["store", "verify", "--deep", "--json"])
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap();
    (output.status.success(), report)
}

fn write_archive(path: &Path, marker: &str) {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut encoder);
        for (name, bytes) in [
            (
                "package.json",
                br#"{"name":"store-identity-fixture","version":"1.0.0"}"#.as_slice(),
            ),
            ("marker.txt", marker.as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{name}"), bytes)
                .unwrap();
        }
        builder.finish().unwrap();
    }
    encoder.flush().unwrap();
    std::fs::write(path, encoder.finish().unwrap()).unwrap();
}

fn two_source_projects(version: &str) -> (TempProject, PathBuf, PathBuf) {
    let project = TempProject::empty(r#"{"name":"fixture"}"#);
    let paths: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|name| {
            let dir = project.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            write_archive(&dir.join(format!("{name}.tgz")), name);
            std::fs::write(
                dir.join("package.json"),
                serde_json::json!({
                    "name": format!("project-{name}"),
                    "dependencies": { format!("fixture-{name}"): format!("file:./{name}.tgz") }
                })
                .to_string(),
            )
            .unwrap();
            run_install(&project, &dir, version);
            dir
        })
        .collect();
    (project, paths[0].clone(), paths[1].clone())
}

#[test]
fn deep_verify_distinguishes_source_artifacts_shared_between_projects() {
    for version in ["v2", "v3"] {
        let (project, a, b) = two_source_projects(version);
        for path in [&a, &b, project.path()] {
            let (success, report) = verify(&project, path);
            assert!(success, "{version}: {report}");
            assert_eq!(report["corrupted"], 0);
        }
    }
}

#[test]
fn deep_verify_distinguishes_same_coordinate_root_aliases() {
    for version in ["v2", "v3"] {
        let project = TempProject::empty(
            r#"{"name":"fixture","dependencies":{"@test/first":"file:./a.tgz","second":"file:./b.tgz"}}"#,
        );
        write_archive(&project.path().join("a.tgz"), "a");
        write_archive(&project.path().join("b.tgz"), "b");
        run_install(&project, project.path(), version);
        let (success, report) = verify(&project, project.path());
        assert!(success, "{version}: {report}");
    }
}

#[test]
fn deep_verify_rejects_a_root_retargeted_to_another_valid_artifact() {
    let (project, a, b) = two_source_projects("v2");
    let link = a.join("node_modules/fixture-a");
    let other = b.join("node_modules/fixture-b").canonicalize().unwrap();
    lpm_common::symlink::remove_symlink_or_junction_entry(&link).unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(&other, &link).unwrap();
    let (success, report) = verify(&project, &a);
    assert!(!success, "{report}");
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("integrity mismatch")),
        "{report}"
    );
}

#[test]
fn reinstall_repairs_deleted_package_local_dependency_links() {
    for version in ["v2", "v3"] {
        for (parent_name, local_name, child_name) in [
            ("parent", "child", "child"),
            ("parent", "@scope/alias", "child"),
            ("parent", "parent", "parent"),
            ("@scope/parent", "@scope/parent", "@scope/parent"),
        ] {
            let project = TempProject::empty(
                r#"{"name":"fixture","dependencies":{"entry":"file:./parent-src"}}"#,
            );
            project.write_file("parent-src/package.json", &serde_json::json!({
                "name":parent_name,"version":"1.0.0","dependencies":{local_name:"file:../child-src"}
            }).to_string());
            project.write_file(
                "child-src/package.json",
                &serde_json::json!({"name":child_name,"version":"2.0.0"}).to_string(),
            );
            project.write_file("child-src/index.js", "module.exports = 1");
            run_install(&project, project.path(), version);
            let parent = project
                .path()
                .join("node_modules/entry")
                .canonicalize()
                .unwrap();
            let link = if local_name == parent_name {
                parent.join("node_modules").join(local_name)
            } else {
                let node_modules = if parent_name.starts_with('@') {
                    parent.parent().unwrap().parent().unwrap()
                } else {
                    parent.parent().unwrap()
                };
                node_modules.join(local_name)
            };
            let expected = link.canonicalize().unwrap();
            lpm_common::symlink::remove_symlink_or_junction_entry(&link).unwrap();
            std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
            run_install(&project, project.path(), version);
            assert_eq!(
                link.canonicalize().unwrap(),
                expected,
                "{version}: {local_name}"
            );
        }
    }
}

#[test]
fn deep_verify_reports_unmatched_lockfile_records_without_installed_links() {
    let (project, a, _) = two_source_projects("v2");
    std::fs::remove_dir_all(a.join("node_modules")).unwrap();
    let (success, report) = verify(&project, &a);
    assert!(success, "{report}");
    assert_eq!(
        report["lockfile_comparison"],
        serde_json::json!({
            "status": "partial", "packages": 1, "compared_packages": 0, "uncompared_packages": 1
        })
    );
    insta::assert_json_snapshot!("store_verify_unmatched_lockfile_json_envelope", report);
}

#[test]
fn deep_verify_checks_legacy_registry_integrity_through_installed_links() {
    let project = TempProject::empty(r#"{"name":"fixture"}"#);
    seed_v1_entry(&project, "legacy", "1.0.0", true);
    let expected = v2_sri_and_segment(b"expected").0;
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "legacy".into(),
        version: "1.0.0".into(),
        source: Some("registry+https://registry.npmjs.org".into()),
        integrity: Some(expected.clone()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "legacy".into(),
        lpm_lockfile::LockedRootResolution {
            package: "legacy".into(),
            version: "1.0.0".into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            ..Default::default()
        },
    );
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    std::fs::create_dir(project.path().join("node_modules")).unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(
        &v1_entry_dir(&project, "legacy", "1.0.0"),
        &project.path().join("node_modules/legacy"),
    )
    .unwrap();
    let marker = v1_entry_dir(&project, "legacy", "1.0.0").join(".integrity");
    std::fs::write(&marker, expected).unwrap();
    let (success, report) = verify(&project, project.path());
    assert!(success, "{report}");
    assert_eq!(report["lockfile_comparison"]["compared_packages"], 1);
    std::fs::write(marker, v2_sri_and_segment(b"other").0).unwrap();
    let (success, report) = verify(&project, project.path());
    assert!(!success, "{report}");
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("integrity mismatch")),
        "{report}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deep_verify_does_not_bind_an_unrelated_v1_coordinate_to_a_virtual_install() {
    let registry = support::mock_registry::MockRegistry::start().await;
    registry
        .with_package("legacy", "1.0.0", &npm_tarball("legacy", "1.0.0"))
        .await;
    let project = TempProject::empty(r#"{"name":"fixture","dependencies":{"legacy":"1.0.0"}}"#);
    seed_v1_entry(&project, "legacy", "1.0.0", true);
    std::fs::write(
        v1_entry_dir(&project, "legacy", "1.0.0").join(".integrity"),
        v2_sri_and_segment(b"other-registry").0,
    )
    .unwrap();
    let output = support::lpm_with_registry_and_npm(&project, &registry.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["install", "--no-security-summary"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (success, report) = verify(&project, project.path());
    assert!(success, "{report}");
}

#[test]
fn deep_verify_does_not_claim_comparison_without_a_stored_marker() {
    let project = TempProject::empty(r#"{"name":"fixture","dependencies":{"legacy":"1.0.0"}}"#);
    seed_v1_entry(&project, "legacy", "1.0.0", true);
    let expected = v2_sri_and_segment(b"expected").0;
    let source = "registry+https://registry.npmjs.org";
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "legacy".into(),
        version: "1.0.0".into(),
        source: Some(source.into()),
        integrity: Some(expected),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "legacy".into(),
        lpm_lockfile::LockedRootResolution {
            package: "legacy".into(),
            version: "1.0.0".into(),
            source: Some(source.into()),
            ..Default::default()
        },
    );
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    std::fs::create_dir(project.path().join("node_modules")).unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(
        &v1_entry_dir(&project, "legacy", "1.0.0"),
        &project.path().join("node_modules/legacy"),
    )
    .unwrap();
    let (success, report) = verify(&project, project.path());
    assert!(success, "{report}");
    assert_eq!(
        report["lockfile_comparison"]["status"], "partial",
        "{report}"
    );
}

#[test]
fn deep_verify_rejects_unreadable_legacy_integrity_markers() {
    let project = TempProject::empty(r#"{"name":"fixture"}"#);
    seed_v1_entry(&project, "legacy", "1.0.0", true);
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = 12;
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "legacy".into(),
        version: "1.0.0".into(),
        integrity: Some(v2_sri_and_segment(b"expected").0),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "legacy".into(),
        lpm_lockfile::LockedRootResolution {
            package: "legacy".into(),
            version: "1.0.0".into(),
            ..Default::default()
        },
    );
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    std::fs::create_dir(project.path().join("node_modules")).unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(
        &v1_entry_dir(&project, "legacy", "1.0.0"),
        &project.path().join("node_modules/legacy"),
    )
    .unwrap();
    let marker = v1_entry_dir(&project, "legacy", "1.0.0").join(".integrity");
    for bytes in [vec![0xff], vec![b'a'; 16 * 1024 * 1024 + 1]] {
        std::fs::write(&marker, bytes).unwrap();
        let (success, report) = verify(&project, project.path());
        assert!(!success, "{report}");
        assert!(
            report["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue
                    .as_str()
                    .unwrap()
                    .contains("unreadable integrity marker")),
            "{report}"
        );
        assert_eq!(
            report["lockfile_comparison"]["status"], "partial",
            "{report}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deep_verify_follows_scoped_dependency_and_peer_links() {
    for version in ["v2", "v3"] {
        for peer in [false, true] {
            let registry = support::mock_registry::MockRegistry::start().await;
            let local = if peer {
                "store-identity-fixture"
            } else {
                "@scope/slot"
            };
            let mut parent = serde_json::json!({"name":"@scope/parent","version":"1.0.0"});
            if peer {
                parent["peerDependencies"] = serde_json::json!({local:"1.0.0"});
            } else {
                parent["dependencies"] =
                    serde_json::json!({local:"npm:store-identity-fixture@1.0.0"});
            }
            registry.with_manifest_package(parent, &[]).await;
            registry
                .with_manifest_package(
                    serde_json::json!({"name":"store-identity-fixture","version":"1.0.0"}),
                    &[("marker.txt", b"registry")],
                )
                .await;
            let mut manifest = serde_json::json!({"name":"fixture", "dependencies": {
                "@scope/parent":"1.0.0", "replacement":"file:./b.tgz"
            }});
            if peer {
                manifest["dependencies"][local] = serde_json::json!("1.0.0");
            }
            let project = TempProject::empty(&manifest.to_string());
            write_archive(&project.path().join("b.tgz"), "archive");
            let output = support::lpm_with_registry_and_npm(&project, &registry.url())
                .env("LPM_STORE_VERSION", version)
                .args(["install", "--no-security-summary"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let (success, report) = verify(&project, project.path());
            assert!(success, "{version} peer={peer}: {report}");
            assert_eq!(
                report["lockfile_comparison"]["status"], "complete",
                "{report}"
            );
            let lockfile =
                lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
            let locked_parent = lockfile
                .packages
                .iter()
                .find(|package| package.name == "@scope/parent")
                .unwrap();
            let targets = if peer {
                &locked_parent.peer_targets
            } else {
                &locked_parent.dependency_targets
            };
            assert!(targets.contains_key(local));
            let parent = project
                .path()
                .join("node_modules/@scope/parent")
                .canonicalize()
                .unwrap();
            let link = parent.parent().unwrap().parent().unwrap().join(local);
            let other = project
                .path()
                .join("node_modules/replacement")
                .canonicalize()
                .unwrap();
            assert_ne!(link.canonicalize().unwrap(), other);
            lpm_common::symlink::remove_symlink_or_junction_entry(&link).unwrap();
            lpm_common::symlink::create_dir_symlink_or_junction(&other, &link).unwrap();
            let (success, report) = verify(&project, project.path());
            assert!(!success, "{version} peer={peer}: {report}");
            assert!(
                report["issues"].as_array().unwrap().iter().any(|issue| {
                    let issue = issue.as_str().unwrap();
                    issue.contains("integrity mismatch")
                        || issue.contains("conflicting lockfile integrity")
                }),
                "{report}"
            );
        }
    }
}

#[test]
fn deep_verify_does_not_replace_ambiguous_dependency_slots_with_peers() {
    let project = TempProject::empty(r#"{"name":"fixture","dependencies":{"parent":"1.0.0"}}"#);
    seed_v2_entry(&project, "parent", "1.0.0");
    seed_v2_entry(&project, "slot", "1.0.0");
    let links = store_root(&project).join("v2/links");
    let parent = links.join("parent@1.0.0+0123456789abcdef/node_modules/parent");
    let child = links.join("slot@1.0.0+0123456789abcdef/node_modules/slot");
    std::fs::create_dir(project.path().join("node_modules")).unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(
        &parent,
        &project.path().join("node_modules/parent"),
    )
    .unwrap();
    lpm_common::symlink::create_dir_symlink_or_junction(
        &child,
        &parent.parent().unwrap().join("slot"),
    )
    .unwrap();
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.metadata.lockfile_version = 11;
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "parent".into(),
        version: "1.0.0".into(),
        dependencies: vec!["slot@1.0.0".into()],
        peers: vec!["slot@2.0.0".into()],
        ..Default::default()
    });
    for (version, source) in [
        ("1.0.0", "registry+https://registry-a.example"),
        ("1.0.0", "registry+https://registry-b.example"),
        ("2.0.0", "registry+https://registry-a.example"),
    ] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "slot".into(),
            version: version.into(),
            source: Some(source.into()),
            integrity: Some(v2_sri_and_segment(&npm_tarball("slot", version)).0),
            ..Default::default()
        });
    }
    lockfile.root_resolutions.insert(
        "parent".into(),
        lpm_lockfile::LockedRootResolution {
            package: "parent".into(),
            version: "1.0.0".into(),
            ..Default::default()
        },
    );
    project.write_file("lpm.lock", &lockfile.to_toml().unwrap());
    let (success, report) = verify(&project, project.path());
    assert!(success, "{report}");
    assert_eq!(report["lockfile_comparison"]["status"], "partial");
}
