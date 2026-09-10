//! Local archive installs through the default virtual store and frozen replay.

mod support;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_v1_with_registry, lpm_with_registry};

fn archive_project(dependencies: serde_json::Value) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"archive-consumer","version":"1.0.0","dependencies":{"archive-alias":"file:fixture.tgz"}}"#,
    );
    let archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": "archive-package", "version": "1.0.0",
            "main": "entry.cjs", "dependencies": dependencies,
        }),
        &[("entry.cjs", b"module.exports = 42;\n")],
    );
    std::fs::write(project.path().join("fixture.tgz"), archive).unwrap();
    project
}

#[test]
fn local_tarball_installs_in_default_store_and_replays_after_removal() {
    let project = archive_project(serde_json::json!({}));
    for args in [vec!["install"], vec!["install", "--force"], vec!["ci"]] {
        lpm(&project)
            .args(args)
            .args(["--json", "--no-skills", "--no-editor-setup"])
            .assert()
            .success();
        assert_eq!(
            std::fs::read_to_string(project.path().join("node_modules/archive-alias/entry.cjs"))
                .unwrap(),
            "module.exports = 42;\n",
        );
        std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    }
}

async fn assert_archive_registry_dependencies(v1: bool) {
    let mock = MockRegistry::start().await;
    let dependency = make_tarball_from_pkg_json(
        serde_json::json!({"name":"archive-child","version":"1.0.0"}),
        &[],
    );
    mock.with_package("archive-child", "1.0.0", &dependency)
        .await;
    let project = archive_project(serde_json::json!({"archive-child":"1.0.0"}));
    let mut command = if v1 {
        lpm_v1_with_registry(&project, &mock.url())
    } else {
        lpm_with_registry(&project, &mock.url())
    };
    command
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let lockfile =
        lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let archive = lockfile
        .packages
        .iter()
        .find(|package| package.name == "archive-package")
        .unwrap();
    assert!(
        archive
            .dependencies
            .iter()
            .any(|name| name.starts_with("archive-child@"))
    );
    assert!(
        project
            .path()
            .join("node_modules/archive-child/package.json")
            .is_file()
    );
}

#[tokio::test]
async fn local_tarball_installs_registry_dependencies_in_default_store() {
    assert_archive_registry_dependencies(false).await;
}

#[tokio::test]
async fn local_tarball_installs_registry_dependencies_in_legacy_store() {
    assert_archive_registry_dependencies(true).await;
}

#[test]
fn local_tarball_serial_linking_and_cold_store_frozen_replay_preserve_bytes() {
    let project = archive_project(serde_json::json!({}));
    lpm(&project)
        .env("LPM_SERIAL_LINK", "1")
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    std::fs::remove_dir_all(project.home().join(".lpm/store")).unwrap();
    lpm(&project)
        .env("LPM_SERIAL_LINK", "1")
        .args(["ci", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    assert_eq!(
        project.read_file("node_modules/archive-alias/entry.cjs"),
        "module.exports = 42;\n"
    );
}

#[test]
fn changed_local_tarball_is_rejected_by_ci_and_refreshed_by_install() {
    let project = archive_project(serde_json::json!({}));
    lpm(&project)
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let original_lock = project.read_file("lpm.lock");
    let archive = make_tarball_from_pkg_json(
        serde_json::json!({"name":"archive-package","version":"1.0.0","main":"entry.cjs"}),
        &[("entry.cjs", b"module.exports = 43;\n")],
    );
    std::fs::write(project.path().join("fixture.tgz"), archive).unwrap();
    lpm(&project)
        .args(["ci", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .failure();
    assert_eq!(project.read_file("lpm.lock"), original_lock);
    lpm(&project)
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    assert_eq!(
        project.read_file("node_modules/archive-alias/entry.cjs"),
        "module.exports = 43;\n"
    );
}

#[tokio::test]
async fn local_tarball_respects_dependency_range_when_root_requires_another_version() {
    use support::mock_registry::compute_integrity;
    let mock = MockRegistry::start().await;
    let mut versions = serde_json::Map::new();
    let mut tarballs = Vec::new();
    for version in ["1.0.0", "2.0.0"] {
        let data = make_tarball_from_pkg_json(
            serde_json::json!({"name":"archive-child","version":version}),
            &[],
        );
        versions.insert(version.to_string(), serde_json::json!({
            "name":"archive-child", "version":version,
            "dist":{"tarball":mock.tarball_url("archive-child",version),"integrity":compute_integrity(&data)}
        }));
        tarballs.push((version, data));
    }
    mock.with_package_metadata_and_tarballs(
        "archive-child",
        serde_json::json!({
            "name":"archive-child", "dist-tags":{"latest":"2.0.0"}, "versions":versions,
        }),
        &tarballs,
    )
    .await;
    let project = archive_project(serde_json::json!({"archive-child":"1.0.0"}));
    project.write_file("package.json", r#"{"name":"archive-consumer","version":"1.0.0","dependencies":{"archive-alias":"file:fixture.tgz","archive-child":"2.0.0"}}"#);
    lpm_with_registry(&project, &mock.url())
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let archive = lock
        .packages
        .iter()
        .find(|p| p.name == "archive-package")
        .unwrap();
    assert!(
        archive
            .dependencies
            .contains(&"archive-child@1.0.0".to_string()),
        "{:?}",
        archive.dependencies
    );
    let root: serde_json::Value =
        serde_json::from_str(&project.read_file("node_modules/archive-child/package.json"))
            .unwrap();
    assert_eq!(root["version"], "2.0.0");
    assert!(
        !lock
            .root_resolutions
            .keys()
            .any(|name| name.starts_with("lpm-archive-"))
    );
    for entry in std::fs::read_dir(project.path().join("node_modules")).unwrap() {
        assert!(
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("lpm-archive-")
        );
    }
    std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    lpm_with_registry(&project, &mock.url())
        .args(["ci", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let output = std::process::Command::new("node").current_dir(project.path())
        .args(["-e", "const {createRequire}=require('node:module');const r=createRequire(require.resolve('archive-alias'));if(r('archive-child/package.json').version!=='1.0.0')process.exit(1)"])
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn local_tarball_skips_unavailable_optional_and_development_dependencies() {
    let mock = MockRegistry::start().await;
    let project = archive_project(serde_json::json!({}));
    let archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name":"archive-package", "version":"1.0.0",
            "optionalDependencies":{"unavailable-archive-optional":"1.0.0"},
            "devDependencies":{"unavailable-archive-dev":"1.0.0"},
            "peerDependencies":{"unavailable-archive-peer":"1.0.0"},
            "peerDependenciesMeta":{"unavailable-archive-peer":{"optional":true}}
        }),
        &[],
    );
    std::fs::write(project.path().join("fixture.tgz"), archive).unwrap();
    lpm_with_registry(&project, &mock.url())
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    assert_eq!(lock.packages.len(), 1);
}

#[test]
fn local_tarball_rejects_nested_local_source_dependencies() {
    let project = archive_project(serde_json::json!({"nested":"link:../../outside"}));
    lpm(&project)
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .failure()
        .stdout(predicates::str::contains(
            "unsupported nested non-registry dependency",
        ));
    assert!(!project.path().join("node_modules/archive-alias").exists());
}

#[tokio::test]
async fn local_tarball_preserves_registry_dependency_aliases() {
    let mock = MockRegistry::start().await;
    let dependency = make_tarball_from_pkg_json(
        serde_json::json!({"name":"archive-child","version":"1.0.0"}),
        &[],
    );
    mock.with_package("archive-child", "1.0.0", &dependency)
        .await;
    let project = archive_project(serde_json::json!({"child-alias":"npm:archive-child@1.0.0"}));
    lpm_with_registry(&project, &mock.url())
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let output = std::process::Command::new("node").current_dir(project.path())
        .args(["-e", "const {createRequire}=require('node:module');const r=createRequire(require.resolve('archive-alias'));if(r('child-alias/package.json').name!=='archive-child')process.exit(1)"])
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn unavailable_archive_optional_range_does_not_use_incompatible_root() {
    let mock = MockRegistry::start().await;
    let dependency = make_tarball_from_pkg_json(
        serde_json::json!({"name":"archive-child","version":"2.0.0"}),
        &[],
    );
    mock.with_package("archive-child", "2.0.0", &dependency)
        .await;
    let project = archive_project(serde_json::json!({}));
    let archive = make_tarball_from_pkg_json(
        serde_json::json!({
            "name":"archive-package", "version":"1.0.0", "optionalDependencies":{"archive-child":"1.0.0"}
        }),
        &[],
    );
    std::fs::write(project.path().join("fixture.tgz"), archive).unwrap();
    project.write_file("package.json", r#"{"name":"archive-consumer","version":"1.0.0","dependencies":{"archive-alias":"file:fixture.tgz","archive-child":"2.0.0"}}"#);
    lpm_with_registry(&project, &mock.url())
        .args(["install", "--json", "--no-skills", "--no-editor-setup"])
        .assert()
        .success();
    let lock = lpm_lockfile::Lockfile::read_from_file(&project.path().join("lpm.lock")).unwrap();
    let archive = lock
        .packages
        .iter()
        .find(|p| p.name == "archive-package")
        .unwrap();
    assert!(
        archive.dependencies.is_empty(),
        "{:?}",
        archive.dependencies
    );
}
