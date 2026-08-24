//! Workflow tests for `lpm query <selector>` and its flag variants.
//!
//! Query inspects the resolved tree (lockfile or `node_modules/`) and
//! filters by behavioral tags + dependency relationships. These tests
//! seed a non-LPM-managed project (no `lpm.lock`) so discovery falls
//! through to `node_modules/`, and each package carries real source
//! code that the behavioral analyzer will flag.
//!
//! Why real source code instead of a hand-crafted `.lpm-security.json`:
//! the inventory's fallback path for non-store projects calls
//! `analyze_package` (the *uncached* entry point) directly, so a
//! sidecar file is never consulted in this code path.

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, VALID_TEST_INTEGRITY, lpm};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn integrity_for(seed: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;

    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(seed))
    )
}

/// Seed a package with a tiny `package.json` plus one JS source file
/// containing the patterns required to trigger the requested tags.
fn seed_pkg_with_source(project: &TempProject, name: &str, version: &str, source: &str) {
    let pkg = serde_json::json!({ "name": name, "version": version });
    project.write_file(
        &format!("node_modules/{name}/package.json"),
        &pkg.to_string(),
    );
    project.write_file(&format!("node_modules/{name}/index.js"), source);
}

fn seed_locked_pkg_with_source(
    project: &TempProject,
    name: &str,
    version: &str,
    source: &str,
    license: Option<&str>,
) {
    let mut package = serde_json::json!({ "name": name, "version": version });
    if let Some(license) = license {
        package["license"] = serde_json::json!(license);
    }
    project.write_file(
        &format!("node_modules/{name}/package.json"),
        &package.to_string(),
    );
    project.write_file(&format!("node_modules/{name}/index.js"), source);
    project.write_file(
        "package-lock.json",
        &serde_json::json!({
            "name": "q",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "q",
                    "version": "1.0.0",
                    "dependencies": { name: version }
                },
                format!("node_modules/{name}"): {
                    "name": name,
                    "version": version,
                    "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                    "integrity": VALID_TEST_INTEGRITY
                }
            }
        })
        .to_string(),
    );
}

fn seed_v1_lpm_package(
    project: &TempProject,
    name: &str,
    version: &str,
    integrity: &str,
    source: &str,
) {
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let package_dir = lpm_store::PackageStore::from_root(&root).package_dir(name, version);
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        serde_json::json!({ "name": name, "version": version, "license": "MIT" }).to_string(),
    )
    .unwrap();
    std::fs::write(package_dir.join("index.js"), source).unwrap();
    std::fs::write(package_dir.join(".integrity"), integrity).unwrap();
    let analysis = lpm_security::behavioral::analyze_package(&package_dir);
    lpm_security::behavioral::write_cached_analysis(&package_dir, &analysis).unwrap();
}

fn write_lpm_lockfile(project: &TempProject, packages: &[(&str, &str, &str)]) {
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
    for &(name, version, integrity) in packages {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some(integrity.to_string()),
            ..Default::default()
        });
    }
    let roots = packages
        .iter()
        .enumerate()
        .map(|(index, (name, version, _))| (format!("dep-{index}"), *name, *version))
        .collect::<Vec<_>>();
    let root_refs = roots
        .iter()
        .map(|(local, name, version)| (local.as_str(), *name, *version))
        .collect::<Vec<_>>();
    support::finalize_exact_lockfile_fixture(&mut lockfile, &root_refs);
    lockfile.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: roots
                .into_iter()
                .map(|(local, _, version)| (local, version.to_string()))
                .collect(),
            ..Default::default()
        },
    );
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
}

#[cfg(unix)]
fn seed_v2_link(
    project: &TempProject,
    graph_suffix: &str,
    integrity: &str,
    source: &str,
) -> std::path::PathBuf {
    let store_root = project.home().join(".lpm/store/v2");
    let link_dir = store_root
        .join("links")
        .join(format!("duplicate@1.0.0+{graph_suffix}"));
    let package_dir = link_dir.join("node_modules/duplicate");
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::write(
        package_dir.join("package.json"),
        r#"{"name":"duplicate","version":"1.0.0","license":"MIT"}"#,
    )
    .unwrap();
    std::fs::write(package_dir.join("index.js"), source).unwrap();
    let analysis = lpm_security::behavioral::analyze_package(&package_dir);
    lpm_security::behavioral::write_cached_analysis(&package_dir, &analysis).unwrap();

    let store = lpm_store::v2::Store::at(&store_root);
    let object_dir = store.paths().object_dir(integrity).unwrap();
    std::fs::create_dir_all(&object_dir).unwrap();
    std::fs::copy(
        package_dir.join("package.json"),
        object_dir.join("package.json"),
    )
    .unwrap();
    std::fs::copy(package_dir.join("index.js"), object_dir.join("index.js")).unwrap();
    lpm_security::behavioral::write_cached_analysis(&object_dir, &analysis).unwrap();

    let digest = graph_suffix.repeat(4);
    std::fs::write(
        link_dir.join(".lpm-link-meta.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "graph_key": format!("duplicate@1.0.0+{graph_suffix}"),
            "graph_key_digest_hex": digest,
            "name": "duplicate",
            "version": "1.0.0",
            "source_sri": integrity,
            "object_path": "objects/fixture",
            "deps": [],
            "platform": { "os": "darwin", "cpu": "arm64", "libc": null },
            "created_at": "2026-01-01T00:00:00Z",
            "last_referenced_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
    package_dir
}

/// Source patterns derived from `crates/lpm-security/src/behavioral/source.rs`.
const SRC_EVAL: &str = "module.exports = function () { eval('1+1') }\n";
const SRC_NETWORK: &str = "module.exports = function () { fetch('https://example.com') }\n";
const SRC_EVAL_AND_NETWORK: &str =
    "module.exports = function () { eval('1+1'); fetch('https://example.com') }\n";
const SRC_CLEAN: &str = "module.exports = function () { return 42 }\n";
const SRC_INFO: &str =
    "module.exports = process.env.NODE_ENV;\nconst docs = 'https://example.com/docs';\n";

#[test]
fn query_reanalyzes_when_cached_source_bytes_change() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"mutable-pkg":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "mutable-pkg", "1.0.0", SRC_CLEAN, Some("MIT"));

    lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .success();
    project.write_file("node_modules/mutable-pkg/index.js", SRC_EVAL);

    lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure();
}

#[test]
fn query_reanalyzes_when_cached_manifest_bytes_change() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"mutable-pkg":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "mutable-pkg", "1.0.0", SRC_CLEAN, Some("MIT"));

    lpm(&project)
        .args(["query", ":no-license", "--assert-none"])
        .assert()
        .success();
    project.write_file(
        "node_modules/mutable-pkg/package.json",
        r#"{"name":"mutable-pkg","version":"1.0.0"}"#,
    );

    lpm(&project)
        .args(["query", ":no-license", "--assert-none"])
        .assert()
        .failure();
}

#[test]
fn query_does_not_trust_a_repository_supplied_matching_integrity_cache() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"forged-pkg":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "forged-pkg", "1.0.0", SRC_EVAL, Some("MIT"));
    let forged_analysis = lpm_security::behavioral::PackageAnalysis {
        version: lpm_security::behavioral::SCHEMA_VERSION,
        analyzed_at: "1970-01-01T00:00:00Z".to_string(),
        source: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        meta: Default::default(),
    };
    project.write_file(
        ".lpm/audit-cache.json",
        &serde_json::json!({
            "cacheVersion": 3,
            "behavioralSchemaVersion": lpm_security::behavioral::SCHEMA_VERSION,
            "manager": "npm",
            "entries": {
                "node_modules/forged-pkg": {
                    "name": "forged-pkg",
                    "version": "1.0.0",
                    "integrity": VALID_TEST_INTEGRITY,
                    "analysis": forged_analysis
                }
            }
        })
        .to_string(),
    );

    lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn query_rejects_a_package_root_symlink_that_escapes_the_project() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"linked-pkg":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "linked-pkg", "1.0.0", SRC_CLEAN, Some("MIT"));
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("package.json"),
        r#"{"name":"outside","version":"9.0.0","license":"MIT"}"#,
    )
    .unwrap();
    std::fs::write(outside.path().join("index.js"), SRC_EVAL).unwrap();
    let package_dir = project.path().join("node_modules/linked-pkg");
    std::fs::remove_dir_all(&package_dir).unwrap();
    symlink(outside.path(), &package_dir).unwrap();

    lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "lockfile package path resolves outside the project",
        ));
}

#[cfg(unix)]
#[test]
fn query_does_not_write_a_cache_through_a_symlinked_project_state_directory() {
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"1.0.0"}}"#,
    );
    seed_locked_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN, Some("MIT"));
    let outside = tempfile::tempdir().unwrap();
    let external_cache = outside.path().join("audit-cache.json");
    std::fs::write(&external_cache, b"outside-state").unwrap();
    symlink(outside.path(), project.path().join(".lpm")).unwrap();

    lpm(&project).args(["query", ":eval"]).assert().success();

    assert_eq!(std::fs::read(&external_cache).unwrap(), b"outside-state");
}

#[test]
fn query_keeps_behavioral_analysis_qualified_by_lpm_package_version() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"dep-0":"1.0.0","dep-1":"2.0.0"}}"#,
    );
    let packages = [
        ("duplicate", "1.0.0", VALID_TEST_INTEGRITY),
        ("duplicate", "2.0.0", VALID_TEST_INTEGRITY),
    ];
    write_lpm_lockfile(&project, &packages);
    seed_v1_lpm_package(
        &project,
        "duplicate",
        "1.0.0",
        VALID_TEST_INTEGRITY,
        SRC_EVAL,
    );
    seed_v1_lpm_package(
        &project,
        "duplicate",
        "2.0.0",
        VALID_TEST_INTEGRITY,
        SRC_CLEAN,
    );

    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["--json", "query", ":eval"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let matches: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let matches = matches.as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["name"], "duplicate");
    assert_eq!(matches[0]["version"], "1.0.0");
    assert_eq!(matches[0]["instanceId"].as_str().unwrap().len(), 64);
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let expected_path = lpm_store::PackageStore::from_root(&root).package_dir("duplicate", "1.0.0");
    assert_eq!(matches[0]["path"], expected_path.to_string_lossy().as_ref());
}

#[test]
fn query_fresh_scans_a_store_package_when_its_sidecar_and_project_link_are_missing() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"dep-0":"1.0.0"}}"#);
    let packages = [("store-only", "1.0.0", VALID_TEST_INTEGRITY)];
    write_lpm_lockfile(&project, &packages);
    seed_v1_lpm_package(
        &project,
        "store-only",
        "1.0.0",
        VALID_TEST_INTEGRITY,
        SRC_EVAL,
    );
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let package_dir = lpm_store::PackageStore::from_root(&root).package_dir("store-only", "1.0.0");
    std::fs::remove_file(package_dir.join(".lpm-security.json")).unwrap();

    lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure();
}

#[test]
fn query_scans_v1_directory_dependencies_from_their_live_source() {
    use std::collections::BTreeMap;

    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"local":"file:./packages/local"}}"#,
    );
    project.write_file(
        "packages/local/package.json",
        r#"{"name":"local","version":"1.0.0","license":"MIT","scripts":{"postinstall":"node setup.js"}}"#,
    );
    project.write_file("packages/local/index.js", SRC_EVAL);
    let source = "directory+packages/local";
    let instance_id = lpm_common::PackageInstanceId::derive("local", "1.0.0", source, "root/local");
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(instance_id),
        name: "local".to_string(),
        version: "1.0.0".to_string(),
        source: Some(source.to_string()),
        unpacked_size: None,
        manifest_fingerprint: Some(format!("sha256-{}", "ab".repeat(32))),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "local".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(instance_id),
            package: "local".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
        },
    );
    lockfile.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: BTreeMap::from([(
                "local".to_string(),
                "file:./packages/local".to_string(),
            )]),
            ..Default::default()
        },
    );
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();

    for selector in [":eval", ":scripts"] {
        lpm(&project)
            .env("LPM_STORE_VERSION", "v1")
            .args(["query", selector, "--assert-none"])
            .assert()
            .failure();
    }
}

#[cfg(unix)]
#[test]
fn query_fresh_scans_a_v2_store_package_when_project_links_are_missing() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"dep-0":"1.0.0"}}"#);
    let integrity = integrity_for(b"v2-store-only");
    write_lpm_lockfile(&project, &[("duplicate", "1.0.0", &integrity)]);
    seed_v2_link(&project, "cccccccccccccccc", &integrity, SRC_EVAL);

    lpm(&project)
        .env("LPM_STORE_VERSION", "v2")
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure();
}

#[test]
fn query_does_not_trust_a_store_sidecar_that_is_not_bound_to_current_source() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"dep-0":"1.0.0"}}"#);
    let packages = [("mutable-store", "1.0.0", VALID_TEST_INTEGRITY)];
    write_lpm_lockfile(&project, &packages);
    seed_v1_lpm_package(
        &project,
        "mutable-store",
        "1.0.0",
        VALID_TEST_INTEGRITY,
        SRC_CLEAN,
    );
    let root = lpm_common::LpmRoot::from_dir(project.home().join(".lpm"));
    let package_dir =
        lpm_store::PackageStore::from_root(&root).package_dir("mutable-store", "1.0.0");
    std::fs::write(package_dir.join("index.js"), SRC_EVAL).unwrap();

    lpm(&project)
        .env("LPM_STORE_VERSION", "v1")
        .args(["query", ":eval", "--assert-none"])
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn query_uses_instance_qualified_analysis_for_same_sri_lpm_packages() {
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"source-a":"1.0.0","source-b":"1.0.0"}}"#,
    );
    let source_a = "registry+https://registry-a.example";
    let source_b = "registry+https://registry-b.example";
    let integrity_a = integrity_for(b"shared-source");
    let integrity_b = integrity_a.clone();
    let id_a =
        lpm_common::PackageInstanceId::derive("duplicate", "1.0.0", source_a, "root/source-a");
    let id_b =
        lpm_common::PackageInstanceId::derive("duplicate", "1.0.0", source_b, "root/source-b");
    let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
    for (instance_id, source, integrity) in [
        (id_a, source_a, integrity_a.as_str()),
        (id_b, source_b, integrity_b.as_str()),
    ] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
            integrity: Some(integrity.to_string()),
            ..Default::default()
        });
    }
    lockfile.root_resolutions = BTreeMap::from([
        (
            "source-a".to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(id_a),
                package: "duplicate".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source_a.to_string()),
            },
        ),
        (
            "source-b".to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(id_b),
                package: "duplicate".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source_b.to_string()),
            },
        ),
    ]);
    lockfile.importers.insert(
        ".".to_string(),
        lpm_lockfile::ImporterSnapshot {
            dependencies: BTreeMap::from([
                ("source-a".to_string(), "1.0.0".to_string()),
                ("source-b".to_string(), "1.0.0".to_string()),
            ]),
            ..Default::default()
        },
    );
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();

    let package_a = seed_v2_link(&project, "aaaaaaaaaaaaaaaa", &integrity_a, SRC_EVAL);
    let package_b = seed_v2_link(
        &project,
        "bbbbbbbbbbbbbbbb",
        &integrity_b,
        "require('child_process').exec('echo source-b')\n",
    );
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    symlink(&package_a, project.path().join("node_modules/source-a")).unwrap();
    symlink(&package_b, project.path().join("node_modules/source-b")).unwrap();

    let output = lpm(&project)
        .env("LPM_STORE_VERSION", "v2")
        .args(["--json", "query", ":eval,:child-process", "--verbose"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let matches: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut observed = matches
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["analysis"]["source"]["eval"]
                    .as_bool()
                    .unwrap_or(false),
                entry["analysis"]["source"]["childProcess"]
                    .as_bool()
                    .unwrap_or(false),
            )
        })
        .collect::<Vec<_>>();
    observed.sort_unstable();

    assert_eq!(observed, vec![(false, true), (true, false)]);

    let root_eval = lpm(&project)
        .env("LPM_STORE_VERSION", "v2")
        .args(["--json", "query", ":root > :eval", "--verbose"])
        .output()
        .unwrap();
    assert!(
        root_eval.status.success(),
        "{}",
        String::from_utf8_lossy(&root_eval.stderr)
    );
    let root_matches: serde_json::Value = serde_json::from_slice(&root_eval.stdout).unwrap();
    let root_matches = root_matches.as_array().unwrap();
    assert_eq!(root_matches.len(), 1);
    assert_eq!(root_matches[0]["analysis"]["source"]["eval"], true);

    let mermaid = lpm(&project)
        .env("LPM_STORE_VERSION", "v2")
        .args(["query", ":eval,:child-process", "--format", "mermaid"])
        .output()
        .unwrap();
    assert!(
        mermaid.status.success(),
        "{}",
        String::from_utf8_lossy(&mermaid.stderr)
    );
    let mermaid = String::from_utf8(mermaid.stdout).unwrap();
    assert_eq!(
        mermaid.matches("duplicate@1.0.0\\n").count(),
        2,
        "{mermaid}"
    );
    assert!(mermaid.contains(&id_a.to_string()[..12]), "{mermaid}");
    assert!(mermaid.contains(&id_b.to_string()[..12]), "{mermaid}");
}

#[cfg(unix)]
#[test]
fn workspace_root_selector_uses_the_owning_root_exact_instances_from_member_directories() {
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    let project = TempProject::empty(
        r#"{"name":"workspace-query","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{"root-duplicate":"1.0.0"}}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"member-duplicate":"1.0.0"}}"#,
    );
    std::fs::create_dir_all(project.path().join("packages/app/src/nested")).unwrap();

    let source = "registry+https://registry.npmjs.org";
    let root_id =
        lpm_common::PackageInstanceId::derive("duplicate", "1.0.0", source, "root/duplicate");
    let member_id = lpm_common::PackageInstanceId::derive(
        "duplicate",
        "1.0.0",
        source,
        "packages/app/duplicate",
    );
    let root_integrity = integrity_for(b"workspace-root-instance");
    let member_integrity = integrity_for(b"workspace-member-instance");
    let projection = |instance_id, integrity: &str, local_name: &str| {
        let mut lockfile = lpm_lockfile::Lockfile::new_with_resolver("pubgrub");
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "duplicate".to_string(),
            version: "1.0.0".to_string(),
            source: Some(source.to_string()),
            integrity: Some(integrity.to_string()),
            ..Default::default()
        });
        lockfile.root_resolutions.insert(
            local_name.to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: "duplicate".to_string(),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
            },
        );
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: BTreeMap::from([(local_name.to_string(), "1.0.0".to_string())]),
                ..Default::default()
            },
        );
        lockfile
    };
    let mut union = lpm_lockfile::Lockfile::new();
    union
        .absorb_importer(".", projection(root_id, &root_integrity, "root-duplicate"))
        .unwrap();
    union
        .absorb_importer(
            "packages/app",
            projection(member_id, &member_integrity, "member-duplicate"),
        )
        .unwrap();
    union.write_all(&project.path().join("lpm.lock")).unwrap();

    let root_package = seed_v2_link(&project, "aaaaaaaaaaaaaaaa", &root_integrity, SRC_EVAL);
    let member_package = seed_v2_link(&project, "bbbbbbbbbbbbbbbb", &member_integrity, SRC_CLEAN);
    std::fs::create_dir_all(project.path().join("node_modules")).unwrap();
    std::fs::create_dir_all(project.path().join("packages/app/node_modules")).unwrap();
    symlink(
        root_package,
        project.path().join("node_modules/root-duplicate"),
    )
    .unwrap();
    symlink(
        member_package,
        project
            .path()
            .join("packages/app/node_modules/member-duplicate"),
    )
    .unwrap();

    for current_dir in [
        project.path().join("packages/app"),
        project.path().join("packages/app/src/nested"),
    ] {
        let output = lpm(&project)
            .current_dir(current_dir)
            .env("LPM_STORE_VERSION", "v2")
            .args(["--json", "query", ":workspace-root > :eval", "--verbose"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let matches: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(matches.as_array().unwrap().len(), 1, "{matches}");
        assert_eq!(matches[0]["instanceId"], root_id.to_string());
        assert_eq!(matches[0]["analysis"]["source"]["eval"], true);
    }
}

// ─── basic selector ───────────────────────────────────────────────────

#[test]
fn query_eval_selects_only_packages_with_eval_tag() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval"])
        .output()
        .expect("failed to run lpm query :eval");

    assert!(
        output.status.success(),
        "query :eval must succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-pkg"),
        "stdout must list eval-pkg, got:\n{stdout}"
    );
    assert!(
        stdout.contains("tags: eval"),
        "stdout must render package tags on a second line, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("clean-pkg"),
        "stdout must NOT list clean-pkg (no eval), got:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! 1 package matched :eval"),
        "query must report a slim match summary, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('▲'),
        "query status output must not use legacy/cliclack glyphs, got:\n{stderr}"
    );
}

#[test]
fn query_info_selects_metadata_that_does_not_match_critical() {
    let project =
        TempProject::empty(r#"{"name":"q","version":"1.0.0","dependencies":{"info-pkg":"1.0.0"}}"#);
    seed_pkg_with_source(&project, "info-pkg", "1.0.0", SRC_INFO);

    let info = lpm(&project)
        .args(["query", ":info"])
        .output()
        .expect("run lpm query :info");
    assert!(
        info.status.success(),
        "query :info failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&info.stdout),
        String::from_utf8_lossy(&info.stderr)
    );
    let info_stdout = String::from_utf8_lossy(&info.stdout);
    assert!(info_stdout.contains("info-pkg"), "{info_stdout}");
    assert!(info_stdout.contains("env"), "{info_stdout}");
    assert!(info_stdout.contains("url-strings"), "{info_stdout}");

    let critical = lpm(&project)
        .args(["query", ":critical"])
        .output()
        .expect("run lpm query :critical");
    assert!(critical.status.success());
    assert!(String::from_utf8_lossy(&critical.stderr).contains("No packages match :critical"));
}

// ─── --json format ────────────────────────────────────────────────────

#[test]
fn query_eval_json_carries_matched_array() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["--json", "query", ":eval"])
        .output()
        .expect("failed to run lpm query :eval --json");

    assert!(output.status.success(), "query :eval --json must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("query --json must be valid JSON: {e}\n---\n{stdout}"));

    let arr = envelope
        .as_array()
        .expect("query --json must emit a top-level array");
    assert_eq!(arr.len(), 1, "exactly one match expected: {envelope}");
    assert_eq!(arr[0]["name"], serde_json::json!("eval-pkg"));
    assert_eq!(arr[0]["version"], serde_json::json!("1.0.0"));
}

// ─── --count ──────────────────────────────────────────────────────────

#[test]
fn query_count_mode_emits_tag_counts_grouped_by_severity() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["--json", "query", "--count"])
        .output()
        .expect("failed to run lpm query --count --json");

    assert!(
        output.status.success(),
        "query --count --json must succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("query --count --json must be valid JSON: {e}\n---\n{stdout}"));

    let json_str = envelope.to_string();
    assert!(
        json_str.contains("\"eval\""),
        "count output must mention the eval tag, got:\n{json_str}",
    );
}

// ─── --assert-none ─────────────────────────────────────────────────────

#[test]
fn query_assert_none_exits_zero_when_match_set_empty() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .output()
        .expect("failed to run lpm query --assert-none");

    assert!(
        output.status.success(),
        "--assert-none on empty match must exit 0\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn query_assert_none_exits_nonzero_when_at_least_one_matches() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);

    let output = lpm(&project)
        .args(["query", ":eval", "--assert-none"])
        .output()
        .expect("failed to run lpm query :eval --assert-none");

    assert!(
        !output.status.success(),
        "--assert-none must exit non-zero when packages matched the selector"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("assertion") || stderr.contains("matched"),
        "stderr must explain the assertion failure, got:\n{stderr}",
    );
}

// ─── selector combinators ─────────────────────────────────────────────

#[test]
fn query_intersection_selector_requires_both_tags() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-and-net":"^1.0.0","eval-only":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-and-net", "1.0.0", SRC_EVAL_AND_NETWORK);
    seed_pkg_with_source(&project, "eval-only", "1.0.0", SRC_EVAL);

    let output = lpm(&project)
        .args(["query", ":eval:network"])
        .output()
        .expect("failed to run lpm query :eval:network");

    assert!(
        output.status.success(),
        "intersection selector must succeed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-and-net"),
        "intersection must include package with BOTH tags, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("eval-only"),
        "intersection must exclude package with only one tag, got:\n{stdout}",
    );
}

#[test]
fn query_union_selector_includes_either_tag() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"eval-pkg":"^1.0.0","net-pkg":"^1.0.0","clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "eval-pkg", "1.0.0", SRC_EVAL);
    seed_pkg_with_source(&project, "net-pkg", "1.0.0", SRC_NETWORK);
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":eval,:network"])
        .output()
        .expect("failed to run lpm query :eval,:network");

    assert!(output.status.success(), "union selector must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("eval-pkg") && stdout.contains("net-pkg"),
        "union must include both eval-pkg and net-pkg, got:\n{stdout}",
    );
    assert!(
        !stdout.contains("clean-pkg"),
        "union must exclude clean-pkg (no tag matches), got:\n{stdout}",
    );
}

// ─── unknown selector ─────────────────────────────────────────────────

#[test]
fn query_invalid_selector_syntax_fails_with_helpful_error() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", "::::::nonsense"])
        .output()
        .expect("failed to run lpm query with bad selector");

    assert!(
        !output.status.success(),
        "invalid selector must exit non-zero"
    );
}

// ─── empty match ──────────────────────────────────────────────────────

#[test]
fn query_no_match_human_output_indicates_zero_packages() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"clean-pkg":"^1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "clean-pkg", "1.0.0", SRC_CLEAN);

    let output = lpm(&project)
        .args(["query", ":crypto"])
        .output()
        .expect("failed to run lpm query :crypto (no match)");

    assert!(output.status.success(), "empty match must exit 0");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No packages match :crypto"),
        "stderr must indicate zero matches with slim UI, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('▲'),
        "query empty-match status output must not use legacy/cliclack glyphs, got:\n{stderr}",
    );
}

#[test]
fn query_rejects_unknown_output_formats_at_argument_parsing() {
    let project = TempProject::empty(r#"{"name":"q","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["query", "#anything", "--format", "yaml"])
        .output()
        .expect("failed to run lpm query with an invalid output format");

    assert!(!output.status.success(), "unknown formats must be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("yaml"),
        "clap must identify the invalid format, got:\n{stderr}"
    );
}

#[tokio::test]
async fn query_skips_external_metadata_when_the_selector_and_output_do_not_use_it() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"@lpm.dev/clean.pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "@lpm.dev/clean.pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "@lpm.dev/clean.pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"name": "@lpm.dev/clean.pkg", "version": "1.0.0"}
        }
    })])
    .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "--json",
            "query",
            "#@lpm.dev/clean.pkg",
        ])
        .output()
        .expect("failed to run a query that does not need external metadata");

    assert!(output.status.success(), "name query must succeed");
    let metadata_requests = mock
        .server()
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.url.path() == "/api/registry/batch-metadata")
        .count();
    assert_eq!(
        metadata_requests, 0,
        "unrelated selectors must not fetch registry metadata"
    );
}

fn project_for_vulnerability_source_failure() -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"plain-pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "plain-pkg", "1.0.0", SRC_CLEAN);
    project
}

fn run_vulnerability_assertion(project: &TempProject, osv_url: &str) -> std::process::Output {
    lpm(project)
        .env("LPM_OSV_URL", osv_url)
        .args(["query", ":vulnerable", "--assert-none"])
        .output()
        .expect("failed to run vulnerability assertion")
}

#[tokio::test]
async fn query_vulnerability_assertion_fails_when_osv_returns_an_error_status() {
    let project = project_for_vulnerability_source_failure();
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(503))
        .mount(mock.server())
        .await;

    let output = run_vulnerability_assertion(&project, &format!("{}/v1/querybatch", mock.url()));

    assert!(
        !output.status.success(),
        "a vulnerability assertion must fail closed on OSV status errors"
    );
}

#[tokio::test]
async fn query_vulnerability_assertion_fails_when_osv_returns_invalid_json() {
    let project = project_for_vulnerability_source_failure();
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{"))
        .mount(mock.server())
        .await;

    let output = run_vulnerability_assertion(&project, &format!("{}/v1/querybatch", mock.url()));

    assert!(
        !output.status.success(),
        "a vulnerability assertion must fail closed on malformed OSV data"
    );
}

#[tokio::test]
async fn query_vulnerability_assertion_fails_when_osv_omits_result_slots() {
    let project = project_for_vulnerability_source_failure();
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"results": []})))
        .mount(mock.server())
        .await;

    let output = run_vulnerability_assertion(&project, &format!("{}/v1/querybatch", mock.url()));

    assert!(
        !output.status.success(),
        "a vulnerability assertion must fail closed on incomplete OSV data"
    );
}

#[tokio::test]
async fn query_vulnerable_matches_an_osv_advisory_for_the_installed_version() {
    let project = project_for_vulnerability_source_failure();
    let mock = MockRegistry::start().await;
    mock.with_osv_querybatch(vec![vec![serde_json::json!({
        "id": "GHSA-query-positive",
        "summary": "query positive-path advisory",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "npm", "name": "plain-pkg"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]
            }]
        }]
    })]])
    .await;

    let output = run_vulnerability_assertion(&project, &format!("{}/v1/querybatch", mock.url()));

    assert!(
        !output.status.success(),
        "an OSV advisory affecting the installed version must match :vulnerable"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("1 package matched :vulnerable"),
        "the failure must come from the matched vulnerability assertion"
    );
}

#[test]
fn query_vulnerability_assertion_fails_when_osv_cannot_be_reached() {
    let project = project_for_vulnerability_source_failure();

    let output = run_vulnerability_assertion(&project, "http://127.0.0.1:1/v1/querybatch");

    assert!(
        !output.status.success(),
        "a vulnerability assertion must fail closed on OSV transport errors"
    );
}

#[tokio::test]
async fn query_vulnerability_assertion_fails_when_registry_metadata_is_unavailable() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"@lpm.dev/example.pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "@lpm.dev/example.pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(503))
        .mount(mock.server())
        .await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let output = lpm(&project)
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "query",
            ":vulnerable",
            "--assert-none",
        ])
        .output()
        .expect("failed to run registry-backed vulnerability assertion");

    assert!(
        !output.status.success(),
        "a vulnerability assertion must fail closed on registry errors"
    );
}

#[tokio::test]
async fn query_vulnerable_matches_registry_advisories_for_lpm_packages() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"@lpm.dev/example.pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "@lpm.dev/example.pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "@lpm.dev/example.pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "@lpm.dev/example.pkg",
                "version": "1.0.0",
                "_vulnerabilities": [{"id": "LPM-QUERY-POSITIVE"}]
            }
        }
    })])
    .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "query",
            ":vulnerable",
            "--assert-none",
        ])
        .output()
        .expect("failed to run registry-backed vulnerability query");

    assert!(
        !output.status.success(),
        "a registry advisory affecting the installed version must match :vulnerable"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("1 package matched :vulnerable"),
        "the failure must come from the matched vulnerability assertion"
    );
}

#[tokio::test]
async fn query_deprecated_matches_the_installed_deprecated_version() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"legacy-pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "legacy-pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "legacy-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "legacy-pkg",
                "version": "1.0.0",
                "deprecated": "use replacement-pkg"
            }
        }
    })])
    .await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let output = lpm(&project)
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "query",
            ":deprecated",
            "--assert-none",
        ])
        .output()
        .expect("failed to run deprecated-package query");

    assert!(
        !output.status.success(),
        "the installed deprecated version must match :deprecated"
    );
}

#[tokio::test]
async fn query_deprecated_ignores_an_empty_registry_deprecation_message() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"current-pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "current-pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "current-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "current-pkg",
                "version": "1.0.0",
                "deprecated": ""
            }
        }
    })])
    .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "query",
            ":deprecated",
            "--assert-none",
        ])
        .output()
        .expect("failed to query a package with an empty deprecation message");

    assert!(
        output.status.success(),
        "an empty npm deprecation message clears the deprecated state"
    );
}

#[tokio::test]
async fn query_rejects_registry_metadata_that_omits_the_installed_version() {
    let project = TempProject::empty(
        r#"{"name":"q","version":"1.0.0","dependencies":{"@lpm.dev/example.pkg":"1.0.0"}}"#,
    );
    seed_pkg_with_source(&project, "@lpm.dev/example.pkg", "1.0.0", SRC_CLEAN);
    let mock = MockRegistry::start().await;
    mock.with_batch_metadata(vec![serde_json::json!({
        "name": "@lpm.dev/example.pkg",
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "2.0.0": {
                "name": "@lpm.dev/example.pkg",
                "version": "2.0.0",
                "_vulnerabilities": [{"id": "LATEST-ONLY"}]
            }
        }
    })])
    .await;
    mock.with_osv_querybatch(vec![vec![]]).await;

    let output = lpm(&project)
        .env("LPM_OSV_URL", format!("{}/v1/querybatch", mock.url()))
        .args([
            "--registry",
            &mock.url(),
            "--insecure",
            "query",
            ":vulnerable",
            "--assert-none",
        ])
        .output()
        .expect("failed to run query with incomplete version metadata");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "incomplete metadata must fail closed"
    );
    assert!(
        stderr.contains("does not include installed version 1.0.0"),
        "query must identify the missing installed version instead of applying latest metadata, got:\n{stderr}"
    );
}
