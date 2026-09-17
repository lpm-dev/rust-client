//! Manifest retention and machine-readable results for package removal.

mod support;

use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};

async fn assert_optional_install_retained(workspace: bool) {
    let registry = MockRegistry::start().await;
    let tarball = make_tarball_from_pkg_json(
        serde_json::json!({"name":"retained-tool","version":"1.0.0","bin":{"retained-tool":"cli.js"}}),
        &[("cli.js", b"#!/usr/bin/env node\nconsole.log('retained');\n")],
    );
    registry
        .with_package("retained-tool", "1.0.0", &tarball)
        .await;
    let manifest = r#"{"name":"consumer","version":"1.0.0","dependencies":{"retained-tool":"1.0.0"},"optionalDependencies":{"retained-tool":"1.0.0"}}"#;
    let project = TempProject::empty(if workspace {
        r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#
    } else {
        manifest
    });
    let target = if workspace { "packages/consumer" } else { "." };
    if workspace {
        project.write_file(&format!("{target}/package.json"), manifest);
    }
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    lpm_with_registry(&project, &registry.url())
        .current_dir(project.path().join(target))
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    let installed = format!("{target}/node_modules/retained-tool/package.json");
    let shim = format!("{target}/node_modules/.bin/retained-tool");
    assert!(project.file_exists(&installed));
    assert!(project.file_exists(&shim));

    lpm(&project)
        .current_dir(project.path().join(target))
        .args(["uninstall", "retained-tool", "--json"])
        .assert()
        .success();
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file(&format!("{target}/package.json"))).unwrap();
    assert!(manifest["dependencies"].get("retained-tool").is_none());
    assert_eq!(manifest["optionalDependencies"]["retained-tool"], "1.0.0");
    assert!(
        project.file_exists(&installed),
        "the retained optional dependency must stay installed"
    );
    assert!(
        project.file_exists(&shim),
        "the retained optional dependency must keep its command"
    );
}

#[tokio::test]
async fn standalone_uninstall_keeps_a_remaining_optional_dependency_installed() {
    assert_optional_install_retained(false).await;
}

#[tokio::test]
async fn workspace_uninstall_keeps_a_remaining_optional_dependency_installed() {
    assert_optional_install_retained(true).await;
}

#[test]
fn uninstall_unknown_package_returns_a_success_json_envelope() {
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["uninstall", "missing-package", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("successful uninstall must emit a JSON object");
    assert_eq!(envelope["target_set"].as_array().unwrap().len(), 1);
    envelope["target_set"] = serde_json::json!(["[MANIFEST]"]);
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "success": true,
      "removed": [],
      "not_found": [
        "missing-package"
      ],
      "target_set": [
        "[MANIFEST]"
      ]
    }
    "#);
}

#[test]
fn uninstall_empty_workspace_selection_returns_a_success_json_envelope() {
    let project = TempProject::from_fixture("workspace-monorepo");
    let output = lpm(&project)
        .args([
            "uninstall",
            "missing-package",
            "--filter",
            "absent-member",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("successful empty selection must emit a JSON object");
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "success": true,
      "removed": [],
      "not_found": [],
      "target_set": []
    }
    "#);
}

#[tokio::test]
async fn uninstall_orphaned_version_keeps_the_remaining_direct_version() {
    let registry = MockRegistry::start().await;
    registry
        .with_full_package_metadata(
            "shared",
            "2.0.0",
            &[
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(support::mock_registry::make_tarball("shared", "1.0.0")),
                ),
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(support::mock_registry::make_tarball("shared", "2.0.0")),
                ),
            ],
        )
        .await;
    registry.with_manifest_package(
        serde_json::json!({"name":"parent","version":"1.0.0","dependencies":{"shared":"1.0.0"}}),
        &[],
    ).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"parent":"1.0.0","shared":"2.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    lpm(&project)
        .args(["uninstall", "parent"])
        .assert()
        .success();
    assert!(
        project.file_exists("node_modules/shared/package.json"),
        "removing shared@1 must retain the direct shared@2 link"
    );
    let installed: serde_json::Value =
        serde_json::from_str(&project.read_file("node_modules/shared/package.json")).unwrap();
    assert_eq!(installed["version"], "2.0.0");
}

#[test]
fn uninstall_rejects_path_traversal_before_manifest_or_file_changes() {
    let project = TempProject::empty(r#"{"name":"consumer","dependencies":{"../victim":"1.0.0"}}"#);
    project.write_file("node_modules/.keep", "");
    project.write_file("victim/keep.txt", "outside node_modules");
    let before = project.read_file("package.json");
    let output = lpm(&project)
        .args(["uninstall", "../victim", "--json"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a path must not be accepted as a package name"
    );
    assert_eq!(project.read_file("package.json"), before);
    assert_eq!(project.read_file("victim/keep.txt"), "outside node_modules");
}

#[cfg(any(unix, windows))]
fn assert_symlinked_cleanup_parent_rejected(parent: &str, package: &str) {
    let project = TempProject::empty(
        &serde_json::json!({"name":"consumer","dependencies":{package:"1.0.0"}}).to_string(),
    );
    let outside = tempfile::tempdir().unwrap();
    let target = if parent.ends_with(".bin") {
        outside.path().to_path_buf()
    } else {
        outside.path().join(package.rsplit('/').next().unwrap())
    };
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep.txt"), "outside project").unwrap();
    project.write_file("node_modules/.keep", "");
    if parent == "node_modules" {
        std::fs::remove_dir_all(project.path().join("node_modules")).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), project.path().join(parent)).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), project.path().join(parent)).unwrap();
    let before = project.read_file("package.json");
    let output = lpm(&project).args(["uninstall", package]).output().unwrap();
    assert!(
        !output.status.success(),
        "cleanup must reject a symlinked {parent}"
    );
    assert_eq!(project.read_file("package.json"), before);
    assert_eq!(
        std::fs::read_to_string(target.join("keep.txt")).unwrap(),
        "outside project"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn uninstall_rejects_a_symlinked_node_modules_directory() {
    assert_symlinked_cleanup_parent_rejected("node_modules", "victim");
}

#[cfg(any(unix, windows))]
#[test]
fn uninstall_rejects_a_symlinked_scope_directory() {
    assert_symlinked_cleanup_parent_rejected("node_modules/@scope", "@scope/victim");
}

#[cfg(any(unix, windows))]
#[test]
fn uninstall_rejects_a_symlinked_bin_directory() {
    assert_symlinked_cleanup_parent_rejected("node_modules/.bin", "victim");
}

#[tokio::test]
async fn uninstall_accepts_an_unavailable_optional_root_in_the_remaining_manifest() {
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "remove-me",
            "1.0.0",
            &support::mock_registry::make_tarball("remove-me", "1.0.0"),
        )
        .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"remove-me":"1.0.0"},"optionalDependencies":{"unavailable":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    lpm(&project)
        .args(["uninstall", "remove-me"])
        .assert()
        .success();
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["optionalDependencies"]["unavailable"], "1.0.0");
}

#[cfg(unix)]
#[test]
fn uninstall_preserves_editor_files_outside_the_project() {
    for parent in [".cursor", ".cursor/rules"] {
        let project = TempProject::empty(
            r#"{"name":"consumer","dependencies":{"@lpm.dev/acme.widget":"1.0.0"}}"#,
        );
        let outside = tempfile::tempdir().unwrap();
        let rules = if parent == ".cursor" {
            outside.path().join("rules")
        } else {
            outside.path().to_path_buf()
        };
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("acme.widget--guide.md"), "outside project").unwrap();
        if parent == ".cursor/rules" {
            std::fs::create_dir(project.path().join(".cursor")).unwrap();
        }
        std::os::unix::fs::symlink(outside.path(), project.path().join(parent)).unwrap();
        lpm(&project)
            .args(["uninstall", "@lpm.dev/acme.widget"])
            .assert()
            .success();
        assert_eq!(
            std::fs::read_to_string(rules.join("acme.widget--guide.md")).unwrap(),
            "outside project"
        );
    }
}

#[test]
fn uninstall_preserves_user_authored_editor_rules_with_a_package_prefix() {
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"@lpm.dev/acme.widget":"1.0.0"}}"#,
    );
    project.write_file(".cursor/rules/acme.widget--guide.md", "user-authored rule");
    lpm(&project)
        .args(["uninstall", "@lpm.dev/acme.widget"])
        .assert()
        .success();
    assert_eq!(
        project.read_file(".cursor/rules/acme.widget--guide.md"),
        "user-authored rule"
    );
}

#[cfg(unix)]
#[test]
fn uninstall_removes_its_owned_bin_shim_when_the_script_is_missing() {
    let project =
        TempProject::empty(r#"{"name":"consumer","dependencies":{"broken-cli":"1.0.0"}}"#);
    project.write_file(
        "node_modules/broken-cli/package.json",
        r#"{"name":"broken-cli","version":"1.0.0","bin":{"broken-cli":"cli.js"}}"#,
    );
    std::fs::create_dir(project.path().join("node_modules/.bin")).unwrap();
    let shim = project.path().join("node_modules/.bin/broken-cli");
    std::os::unix::fs::symlink("../broken-cli/cli.js", &shim).unwrap();
    lpm(&project)
        .args(["uninstall", "broken-cli"])
        .assert()
        .success();
    assert!(
        shim.symlink_metadata().is_err(),
        "an owned dangling shim must not survive uninstall"
    );
}

#[tokio::test]
async fn uninstall_reports_the_installed_direct_version_when_the_graph_has_multiple_versions() {
    let registry = MockRegistry::start().await;
    registry
        .with_full_package_metadata(
            "shared",
            "2.0.0",
            &[
                (
                    "1.0.0",
                    serde_json::json!({}),
                    Some(support::mock_registry::make_tarball("shared", "1.0.0")),
                ),
                (
                    "2.0.0",
                    serde_json::json!({}),
                    Some(support::mock_registry::make_tarball("shared", "2.0.0")),
                ),
            ],
        )
        .await;
    registry.with_manifest_package(serde_json::json!({"name":"parent","version":"1.0.0","dependencies":{"shared":"2.0.0"}}), &[]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"shared":"1.0.0","parent":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    let output = lpm(&project)
        .args(["uninstall", "shared"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("- shared@1.0.0"), "{stderr}");
    assert!(!stderr.contains("- shared@2.0.0"), "{stderr}");
}

#[test]
fn uninstall_rejects_test_pattern_outside_a_workspace_before_mutation() {
    let project = TempProject::empty(r#"{"name":"consumer","dependencies":{"remove-me":"1.0.0"}}"#);
    let manifest = project.read_file("package.json");
    lpm(&project)
        .args(["uninstall", "remove-me", "--test-pattern", "**/*.test.js"])
        .assert()
        .failure();
    assert_eq!(project.read_file("package.json"), manifest);
}

#[tokio::test]
async fn uninstall_preserves_required_peer_roots_for_frozen_offline_replay() {
    let registry = MockRegistry::start().await;
    registry.with_manifest_package(serde_json::json!({"name":"peer-host","version":"1.0.0","peerDependencies":{"ghost-peer":"^1.0.0"}}), &[]).await;
    for name in ["ghost-peer", "remove-me"] {
        registry
            .with_package(
                name,
                "1.0.0",
                &support::mock_registry::make_tarball(name, "1.0.0"),
            )
            .await;
    }
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"peer-host":"1.0.0","remove-me":"1.0.0"}}"#,
    );
    project.write_file(".npmrc", &format!("registry={}/\n", registry.url()));
    lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    lpm(&project)
        .args(["uninstall", "remove-me"])
        .assert()
        .success();
    assert!(project.file_exists("node_modules/ghost-peer/package.json"));
    assert!(
        project
            .read_file("lpm.lock")
            .contains("ambient-peer-installs = [\"ghost-peer\"]")
    );
    lpm(&project)
        .args([
            "install",
            "--frozen-lockfile",
            "--offline",
            "--no-skills",
            "--no-security-summary",
        ])
        .assert()
        .success();
    assert!(project.file_exists("node_modules/ghost-peer/package.json"));
}

#[test]
fn install_rejects_test_pattern_outside_a_workspace_before_mutation() {
    let project = TempProject::empty(r#"{"name":"consumer"}"#);
    let manifest = project.read_file("package.json");
    lpm(&project)
        .args(["install", "--test-pattern", "**/*.test.js"])
        .assert()
        .failure();
    assert_eq!(project.read_file("package.json"), manifest);
    assert!(!project.file_exists("lpm.lock"));
}

#[test]
fn uninstall_legacy_alias_reports_its_canonical_version_without_installed_files() {
    let project = TempProject::empty(
        r#"{"name":"consumer","dependencies":{"local":"npm:canonical@1.0.0","host":"1.0.0"}}"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::default();
    lockfile.metadata.lockfile_version = 2;
    lockfile
        .root_aliases
        .insert("local".into(), "canonical".into());
    for (name, version, dependencies) in [
        ("canonical", "1.0.0", vec![]),
        ("host", "1.0.0", vec!["local@2.0.0".into()]),
        ("local", "2.0.0", vec![]),
    ] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: name.into(),
            version: version.into(),
            dependencies,
            ..Default::default()
        });
    }
    lockfile
        .write_all(&project.path().join("lpm.lock"))
        .unwrap();
    let output = lpm(&project).args(["uninstall", "local"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("- local@1.0.0"), "{stderr}");
    assert!(!stderr.contains("- local@2.0.0"), "{stderr}");
}

#[tokio::test]
async fn uninstall_rejects_a_missing_required_root_and_restores_the_manifest() {
    let registry = MockRegistry::start().await;
    registry
        .with_package(
            "remove-me",
            "1.0.0",
            &support::mock_registry::make_tarball("remove-me", "1.0.0"),
        )
        .await;
    let project = TempProject::empty(r#"{"name":"consumer","dependencies":{"remove-me":"1.0.0"}}"#);
    lpm_with_registry(&project, &registry.url())
        .args(["install", "--no-skills", "--no-security-summary"])
        .assert()
        .success();
    let manifest =
        r#"{"name":"consumer","dependencies":{"remove-me":"1.0.0","required-missing":"1.0.0"}}"#;
    project.write_file("package.json", manifest);
    let lock = project.read_file("lpm.lock");
    let output = lpm(&project)
        .args(["uninstall", "remove-me"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing an exact dependency target"));
    assert_eq!(project.read_file("package.json"), manifest);
    assert_eq!(project.read_file("lpm.lock"), lock);
    assert!(project.file_exists("node_modules/remove-me/package.json"));
}
