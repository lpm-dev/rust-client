//! End-to-end workspace graph and runtime acceptance checks.

mod support;

use serde_json::{Value, json};
use std::path::Path;
use std::process::Output;
use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
use support::{TempProject, lpm_with_registry_and_npm};

const FLAGS: &[&str] = &[
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
    "--no-audit-after-install",
];

async fn package(mock: &MockRegistry, name: &str, versions: &[(&str, Value, &str)]) {
    let mut metadata = json!({"name": name, "dist-tags": {"latest": versions.last().unwrap().0}, "versions": {}, "time": {}});
    let mut tarballs = Vec::with_capacity(versions.len());
    for (version, fields, body) in versions {
        let mut manifest = fields.clone();
        manifest["name"] = name.into();
        manifest["version"] = (*version).into();
        manifest["main"] = "probe.cjs".into();
        let tarball =
            make_tarball_from_pkg_json(manifest.clone(), &[("probe.cjs", body.as_bytes())]);
        manifest["dist"] = json!({"tarball": mock.tarball_url(name, version), "integrity": compute_integrity(&tarball)});
        metadata["versions"][version] = manifest;
        metadata["time"][version] = "2025-01-01T00:00:00.000Z".into();
        tarballs.push((*version, tarball));
    }
    mock.with_package_metadata_and_tarballs(name, metadata, &tarballs)
        .await;
}

async fn standard_registry() -> MockRegistry {
    let mock = MockRegistry::start().await;
    package(
        &mock,
        "runtime-core",
        &[
            ("1.0.0", json!({}), "module.exports = '1.0.0'"),
            ("2.0.0", json!({}), "module.exports = '2.0.0'"),
        ],
    )
    .await;
    package(
        &mock,
        "runtime-plugin",
        &[(
            "1.0.0",
            json!({"peerDependencies":{"runtime-core":"*"}}),
            "module.exports = require('runtime-core')",
        )],
    )
    .await;
    package(
        &mock,
        "runtime-parent",
        &[(
            "1.0.0",
            json!({"dependencies":{"runtime-core":"1.0.0"}}),
            "module.exports = require('runtime-core')",
        )],
    )
    .await;
    mock
}

fn project(extra: Value, members: &[(&str, Value)]) -> TempProject {
    let mut root = json!({"name":"workspace-acceptance", "version":"1.0.0", "private":true, "workspaces":["packages/*"]});
    root.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let project = TempProject::empty(&root.to_string());
    for (name, fields) in members {
        let mut member =
            json!({"name":format!("@acceptance/{name}"),"version":"1.0.0","private":true});
        member
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        project.write_file(
            &format!("packages/{name}/package.json"),
            &member.to_string(),
        );
    }
    project
}

fn record(project: &TempProject, case: &str, step: &str, output: &Output) {
    if let Some(root) = std::env::var_os("LPM_WORKSPACE_ACCEPTANCE_EVIDENCE") {
        let root = Path::new(&root).join(case).join(step);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
        std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
        std::fs::write(root.join("exit.txt"), output.status.to_string()).unwrap();
        for file in ["package.json", "lpm.lock", "lpm.lockb"] {
            if let Ok(bytes) = std::fs::read(project.path().join(file)) {
                std::fs::write(root.join(file), bytes).unwrap();
            }
        }
        for entry in std::fs::read_dir(project.path().join("packages")).unwrap() {
            let entry = entry.unwrap();
            let dest = root.join("packages").join(entry.file_name());
            std::fs::create_dir_all(&dest).unwrap();
            std::fs::copy(entry.path().join("package.json"), dest.join("package.json")).unwrap();
        }
    }
}

fn install(
    project: &TempProject,
    mock: &MockRegistry,
    case: &str,
    step: &str,
    args: &[&str],
) -> Output {
    let output = lpm_with_registry_and_npm(project, &mock.url())
        .arg("install")
        .args(FLAGS)
        .args(args)
        .output()
        .unwrap();
    record(project, case, step, &output);
    output
}

fn replace_root(project: &TempProject, field: &str, value: Value) {
    let mut root: Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    root[field] = value;
    project.write_file("package.json", &root.to_string());
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn runtime(project: &TempProject, member: &str, dependency: &str) -> Value {
    let output = std::process::Command::new("node").args([
        "-e", "const r=require('module').createRequire(require('path').resolve(process.argv[1])); console.log(JSON.stringify(r(process.argv[2])))",
    ]).arg(project.path().join(format!("packages/{member}/package.json"))).arg(dependency).output().unwrap();
    success(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn clear_install(project: &TempProject) {
    for root in std::iter::once(project.path().to_path_buf()).chain(
        std::fs::read_dir(project.path().join("packages"))
            .unwrap()
            .map(|entry| entry.unwrap().path()),
    ) {
        for name in ["node_modules", ".lpm"] {
            let path = root.join(name);
            if path.is_dir() {
                std::fs::remove_dir_all(path).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn conflicting_peer_versions_load_correctly_from_each_member_after_all_replays() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[
            (
                "old",
                json!({"dependencies":{"runtime-core":"1.0.0","runtime-plugin":"1.0.0"}}),
            ),
            (
                "new",
                json!({"dependencies":{"runtime-core":"2.0.0","runtime-plugin":"1.0.0"}}),
            ),
        ],
    );
    for (step, args) in [
        ("fresh", vec![]),
        ("warm", vec![]),
        ("frozen", vec!["--frozen-lockfile"]),
        ("offline", vec!["--frozen-lockfile", "--offline"]),
    ] {
        if step == "frozen" {
            clear_install(&project);
        }
        success(&install(&project, &mock, "peers", step, &args));
        assert_eq!(
            runtime(&project, "old", "runtime-plugin"),
            "1.0.0",
            "{step}: old importer"
        );
        assert_eq!(
            runtime(&project, "new", "runtime-plugin"),
            "2.0.0",
            "{step}: new importer"
        );
    }
}

#[tokio::test]
async fn member_overrides_preserve_transitive_runtime_contexts_after_frozen_replay() {
    let mock = standard_registry().await;
    let project = project(
        json!({"overrides":{"runtime-core":"1.0.0"}}),
        &[
            ("old", json!({"dependencies":{"runtime-parent":"1.0.0"}})),
            (
                "new",
                json!({"dependencies":{"runtime-parent":"1.0.0"},"overrides":{"runtime-core":"2.0.0"}}),
            ),
        ],
    );
    for (step, args) in [
        ("fresh", vec![]),
        ("warm", vec![]),
        ("frozen", vec!["--frozen-lockfile"]),
    ] {
        if step == "frozen" {
            clear_install(&project);
        }
        success(&install(&project, &mock, "overrides", step, &args));
        assert_eq!(
            runtime(&project, "old", "runtime-parent"),
            "1.0.0",
            "{step}: old importer"
        );
        assert_eq!(
            runtime(&project, "new", "runtime-parent"),
            "2.0.0",
            "{step}: new importer"
        );
    }
}

#[tokio::test]
async fn default_and_named_catalogs_replay_with_conflicting_peer_contexts() {
    let mock = standard_registry().await;
    let project = project(
        json!({"catalogs":{"default":{"runtime-core":"1.0.0"},"modern":{"runtime-core":"2.0.0"}}}),
        &[
            (
                "old",
                json!({"dependencies":{"runtime-core":"catalog:","runtime-plugin":"1.0.0"}}),
            ),
            (
                "new",
                json!({"dependencies":{"runtime-core":"catalog:modern","runtime-plugin":"1.0.0"}}),
            ),
        ],
    );
    success(&install(&project, &mock, "catalogs", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    for step in ["warm", "clean"] {
        if step == "clean" {
            clear_install(&project);
        }
        success(&install(
            &project,
            &mock,
            "catalogs",
            step,
            &["--frozen-lockfile"],
        ));
        assert_eq!(project.read_file("lpm.lock"), lock);
        assert_eq!(runtime(&project, "old", "runtime-plugin"), "1.0.0");
        assert_eq!(runtime(&project, "new", "runtime-plugin"), "2.0.0");
    }
}

#[tokio::test]
async fn frozen_workspace_rejects_catalog_drift_without_changing_existing_files() {
    let mock = standard_registry().await;
    let project = project(
        json!({"catalogs":{"default":{"runtime-core":"1.0.0"}}}),
        &[("app", json!({"dependencies":{"runtime-core":"catalog:"}}))],
    );
    success(&install(&project, &mock, "catalog-drift", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    let mut root: Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    root["catalogs"]["default"]["runtime-core"] = "2.0.0".into();
    project.write_file("package.json", &root.to_string());
    let output = install(
        &project,
        &mock,
        "catalog-drift",
        "frozen",
        &["--frozen-lockfile"],
    );
    assert!(!output.status.success(), "frozen catalog drift must fail");
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert_eq!(runtime(&project, "app", "runtime-core"), "1.0.0");
    success(&install(&project, &mock, "catalog-drift", "mutable", &[]));
    assert_eq!(runtime(&project, "app", "runtime-core"), "2.0.0");
}

#[tokio::test]
async fn frozen_workspace_rejects_override_drift_and_mutable_install_updates_runtime() {
    let mock = standard_registry().await;
    let project = project(
        json!({"overrides":{"runtime-core":"1.0.0"}}),
        &[("app", json!({"dependencies":{"runtime-parent":"1.0.0"}}))],
    );
    success(&install(&project, &mock, "override-drift", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    let mut root: Value = serde_json::from_str(&project.read_file("package.json")).unwrap();
    root["overrides"]["runtime-core"] = "2.0.0".into();
    project.write_file("package.json", &root.to_string());
    let output = install(
        &project,
        &mock,
        "override-drift",
        "frozen",
        &["--frozen-lockfile"],
    );
    assert!(!output.status.success(), "frozen override drift must fail");
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert_eq!(runtime(&project, "app", "runtime-parent"), "1.0.0");
    success(&install(&project, &mock, "override-drift", "mutable", &[]));
    assert_eq!(runtime(&project, "app", "runtime-parent"), "2.0.0");
}

#[tokio::test]
async fn optional_peer_is_not_invented_for_a_member_that_does_not_provide_it() {
    let mock = standard_registry().await;
    package(&mock,"optional-plugin",&[("1.0.0",json!({"peerDependencies":{"runtime-core":"*"},"peerDependenciesMeta":{"runtime-core":{"optional":true}}}),"try {module.exports = require('runtime-core')} catch(e) {if(e.code !== 'MODULE_NOT_FOUND') throw e; module.exports = 'absent'}")]).await;
    let project = project(
        json!({}),
        &[
            (
                "with",
                json!({"dependencies":{"optional-plugin":"1.0.0","runtime-core":"1.0.0"}}),
            ),
            (
                "without",
                json!({"dependencies":{"optional-plugin":"1.0.0"}}),
            ),
        ],
    );
    success(&install(&project, &mock, "optional-peer", "fresh", &[]));
    assert_eq!(runtime(&project, "with", "optional-plugin"), "1.0.0");
    assert_eq!(runtime(&project, "without", "optional-plugin"), "absent");
}

#[tokio::test]
async fn production_replay_retains_peers_for_production_plugins() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[(
            "app",
            json!({"dependencies":{"runtime-plugin":"1.0.0"},"devDependencies":{"runtime-core":"1.0.0"}}),
        )],
    );
    success(&install(&project, &mock, "production-peer", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    clear_install(&project);
    success(&install(
        &project,
        &mock,
        "production-peer",
        "production",
        &["--prod", "--frozen-lockfile"],
    ));
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert_eq!(runtime(&project, "app", "runtime-plugin"), "1.0.0");
}

#[tokio::test]
async fn incompatible_optional_packages_stay_locked_and_are_not_linked() {
    let mock = standard_registry().await;
    let other_os = if cfg!(target_os = "macos") {
        "linux"
    } else {
        "darwin"
    };
    package(
        &mock,
        "other-platform",
        &[(
            "1.0.0",
            json!({"os":[other_os]}),
            "module.exports = 'wrong-platform'",
        )],
    )
    .await;
    let project = project(
        json!({}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"1.0.0"},"optionalDependencies":{"other-platform":"1.0.0"}}),
        )],
    );
    success(&install(&project, &mock, "optional-platform", "fresh", &[]));
    assert!(
        !project
            .path()
            .join("packages/app/node_modules/other-platform")
            .exists()
    );
    let lock = project.read_file("lpm.lock");
    assert!(
        lock.contains("other-platform"),
        "portable lock must retain the other platform dependency"
    );
    clear_install(&project);
    success(&install(
        &project,
        &mock,
        "optional-platform",
        "frozen",
        &["--frozen-lockfile"],
    ));
    assert_eq!(project.read_file("lpm.lock"), lock);
}

#[tokio::test]
async fn unavailable_optional_dependency_replays_in_a_frozen_workspace() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"1.0.0"},"optionalDependencies":{"missing-optional":"1.0.0"}}),
        )],
    );
    success(&install(&project, &mock, "optional-missing", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    clear_install(&project);
    success(&install(
        &project,
        &mock,
        "optional-missing",
        "frozen",
        &["--frozen-lockfile"],
    ));
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert_eq!(runtime(&project, "app", "runtime-core"), "1.0.0");
}

#[tokio::test]
async fn required_dependency_is_not_hidden_by_another_members_optional_edge() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[
            (
                "optional",
                json!({"optionalDependencies":{"missing-shared":"1.0.0"}}),
            ),
            (
                "required",
                json!({"dependencies":{"missing-shared":"1.0.0"}}),
            ),
        ],
    );
    let output = install(&project, &mock, "optional-required", "fresh", &[]);
    assert!(
        !output.status.success(),
        "missing required package must fail despite another optional edge"
    );
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn ci_environment_rejects_manifest_drift_and_preserves_lockfile() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[("app", json!({"dependencies":{"runtime-core":"1.0.0"}}))],
    );
    success(&install(&project, &mock, "ci-drift", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    let mut member: Value =
        serde_json::from_str(&project.read_file("packages/app/package.json")).unwrap();
    member["dependencies"]["runtime-core"] = "2.0.0".into();
    project.write_file("packages/app/package.json", &member.to_string());
    let output = lpm_with_registry_and_npm(&project, &mock.url())
        .arg("install")
        .args(FLAGS)
        .env("CI", "true")
        .output()
        .unwrap();
    record(&project, "ci-drift", "auto-frozen", &output);
    assert!(
        !output.status.success(),
        "CI must reject changed workspace manifest"
    );
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert_eq!(runtime(&project, "app", "runtime-core"), "1.0.0");
}

#[tokio::test]
async fn root_override_change_refreshes_unchanged_members_without_a_prior_failed_install() {
    let mock = standard_registry().await;
    let project = project(
        json!({"overrides":{"runtime-core":"1.0.0"}}),
        &[("app", json!({"dependencies":{"runtime-parent":"1.0.0"}}))],
    );
    success(&install(
        &project,
        &mock,
        "override-direct-change",
        "fresh",
        &[],
    ));
    replace_root(&project, "overrides", json!({"runtime-core":"2.0.0"}));
    success(&install(
        &project,
        &mock,
        "override-direct-change",
        "mutable",
        &[],
    ));
    let actual = runtime(&project, "app", "runtime-parent");
    clear_install(&project);
    success(&install(
        &project,
        &mock,
        "override-direct-change",
        "cleared-state",
        &[],
    ));
    assert_eq!(
        actual, "2.0.0",
        "root override change must refresh an otherwise unchanged member"
    );
}

#[tokio::test]
async fn named_catalog_versions_replay_without_any_peer_dependencies() {
    let mock = standard_registry().await;
    let project = project(
        json!({"catalogs":{"default":{"runtime-core":"1.0.0"},"modern":{"runtime-core":"2.0.0"}}}),
        &[
            ("old", json!({"dependencies":{"runtime-core":"catalog:"}})),
            (
                "new",
                json!({"dependencies":{"runtime-core":"catalog:modern"}}),
            ),
        ],
    );
    success(&install(&project, &mock, "catalog-no-peers", "fresh", &[]));
    success(&install(
        &project,
        &mock,
        "catalog-no-peers",
        "frozen",
        &["--frozen-lockfile"],
    ));
    assert_eq!(runtime(&project, "old", "runtime-core"), "1.0.0");
    assert_eq!(runtime(&project, "new", "runtime-core"), "2.0.0");
}

#[tokio::test]
async fn frozen_catalog_failure_preserves_the_specific_root_error() {
    let mock = standard_registry().await;
    let project = project(
        json!({"catalogs":{"default":{"runtime-core":"1.0.0"},"modern":{"runtime-core":"2.0.0"}}}),
        &[
            (
                "old",
                json!({"dependencies":{"runtime-core":"catalog:","runtime-plugin":"1.0.0"}}),
            ),
            (
                "new",
                json!({"dependencies":{"runtime-core":"catalog:modern","runtime-plugin":"1.0.0"}}),
            ),
        ],
    );
    success(&install(
        &project,
        &mock,
        "catalog-root-error",
        "fresh",
        &[],
    ));
    let lock = project.read_file("lpm.lock");
    let root = install(
        &project,
        &mock,
        "catalog-root-error",
        "root-only",
        &["--no-recursive", "--frozen-lockfile"],
    );
    let recursive = install(
        &project,
        &mock,
        "catalog-root-error",
        "recursive",
        &["--frozen-lockfile"],
    );
    assert_eq!(project.read_file("lpm.lock"), lock);
    success(&root);
    success(&recursive);
}

#[tokio::test]
async fn strict_peer_mode_accepts_an_auto_installed_compatible_peer() {
    let mock = standard_registry().await;
    package(
        &mock,
        "strict-plugin",
        &[(
            "1.0.0",
            json!({"peerDependencies":{"runtime-core":"^1.0.0"}}),
            "module.exports = require('runtime-core')",
        )],
    )
    .await;
    let project = project(
        json!({}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"2.0.0","strict-plugin":"1.0.0"}}),
        )],
    );
    let output = install(
        &project,
        &mock,
        "strict-peers",
        "fresh",
        &["--strict-peer-dependencies"],
    );
    success(&output);
    assert_eq!(runtime(&project, "app", "strict-plugin"), "1.0.0");
    assert_eq!(runtime(&project, "app", "runtime-core"), "2.0.0");
}

#[tokio::test]
async fn strict_peer_mode_fails_when_no_compatible_peer_exists() {
    let mock = standard_registry().await;
    package(
        &mock,
        "strict-plugin",
        &[(
            "1.0.0",
            json!({"peerDependencies":{"runtime-core":"^3.0.0"}}),
            "module.exports = require('runtime-core')",
        )],
    )
    .await;
    let project = project(
        json!({}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"2.0.0","strict-plugin":"1.0.0"}}),
        )],
    );
    let output = install(
        &project,
        &mock,
        "unsatisfied-strict-peer",
        "fresh",
        &["--strict-peer-dependencies"],
    );
    assert!(
        !output.status.success(),
        "an unsatisfied strict peer must fail"
    );
    assert!(!project.file_exists("lpm.lock"));
}

#[tokio::test]
async fn frozen_workspace_rejects_a_change_to_inherited_peer_rules() {
    let mock = standard_registry().await;
    let project = project(
        json!({"lpm":{"peerDependencyRules":{"allowAny":["runtime-core"]}}}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"1.0.0","runtime-plugin":"1.0.0"}}),
        )],
    );
    success(&install(&project, &mock, "peer-rule-drift", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    replace_root(
        &project,
        "lpm",
        json!({"peerDependencyRules":{"allowAny":[]}}),
    );
    let output = install(
        &project,
        &mock,
        "peer-rule-drift",
        "frozen",
        &["--frozen-lockfile"],
    );
    assert!(
        !output.status.success(),
        "changed peer rules must fail a frozen install"
    );
    assert_eq!(project.read_file("lpm.lock"), lock);
}

#[tokio::test]
async fn frozen_workspace_rejects_a_change_to_auto_install_peers() {
    let mock = standard_registry().await;
    let project = project(
        json!({"lpm":{"autoInstallPeers":true}}),
        &[(
            "app",
            json!({"dependencies":{"runtime-core":"1.0.0","runtime-plugin":"1.0.0"}}),
        )],
    );
    success(&install(&project, &mock, "auto-peer-drift", "fresh", &[]));
    let lock = project.read_file("lpm.lock");
    replace_root(&project, "lpm", json!({"autoInstallPeers":false}));
    let output = install(
        &project,
        &mock,
        "auto-peer-drift",
        "frozen",
        &["--frozen-lockfile"],
    );
    assert!(
        !output.status.success(),
        "changed auto-peer policy must fail a frozen install"
    );
    assert_eq!(project.read_file("lpm.lock"), lock);
}

#[tokio::test]
async fn removing_a_member_prunes_its_importer_on_mutable_install() {
    let mock = standard_registry().await;
    let project = project(
        json!({}),
        &[
            ("old", json!({"dependencies":{"runtime-core":"1.0.0"}})),
            ("new", json!({"dependencies":{"runtime-core":"2.0.0"}})),
        ],
    );
    success(&install(&project, &mock, "removed-member", "fresh", &[]));
    std::fs::remove_dir_all(project.path().join("packages/old")).unwrap();
    success(&install(&project, &mock, "removed-member", "mutable", &[]));
    let lock: Value = serde_json::to_value(
        lpm_lockfile::Lockfile::read_fast(&project.path().join("lpm.lock")).unwrap(),
    )
    .unwrap();
    assert!(lock["importers"].get("packages/old").is_none());
    assert_eq!(runtime(&project, "new", "runtime-core"), "2.0.0");
}
