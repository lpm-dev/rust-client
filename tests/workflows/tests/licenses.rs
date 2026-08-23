//! Workflow tests for `lpm licenses`.

mod support;

use support::{
    TempProject, installed_manifest_dependency_graph, lpm, lpm_v1, workspace_projection_project,
};

#[tokio::test]
async fn licenses_resolves_hoisted_and_isolated_transitives_before_applying_policy() {
    for linker in ["hoisted", "isolated"] {
        let project = installed_manifest_dependency_graph(linker).await;
        let output = lpm(&project)
            .args(["licenses", "--fail-on", "copyleft,missing", "--json"])
            .output()
            .expect("run licenses policy against installed linker graph");
        assert!(
            !output.status.success(),
            "{linker} licenses policy must fail after inventorying transitive manifests:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("licenses policy stdout must be valid JSON");
        assert_eq!(
            envelope["summary"]["copyleft"],
            serde_json::json!(1),
            "{linker} licenses output must contain a policy summary: {envelope:#}"
        );
        assert_eq!(
            envelope["summary"]["missing"],
            serde_json::json!(1),
            "{linker} licenses output must contain a policy summary: {envelope:#}"
        );
        assert_eq!(
            package_for_version(&envelope, "multi-license", "1.0.0")
                .and_then(|package| package["license_expression"].as_str()),
            Some("Apache-2.0")
        );
        assert_eq!(
            package_for_version(&envelope, "multi-license", "2.0.0")
                .and_then(|package| package["license_expression"].as_str()),
            Some("BSD-3-Clause")
        );
        assert!(
            package_for_version(&envelope, "platform-only-leaf", "1.0.0").is_none(),
            "platform-skipped optional package must not be reported as installed"
        );
        assert!(
            package_for_version(&envelope, "optional-platform-runtime", "1.0.0").is_none(),
            "a descendant of a platform-skipped optional package must not be reported as installed"
        );

        for policy in ["copyleft", "missing"] {
            let policy_output = lpm(&project)
                .args(["licenses", "--fail-on", policy, "--json"])
                .output()
                .unwrap_or_else(|error| panic!("run {policy} policy: {error}"));
            assert!(
                !policy_output.status.success(),
                "{linker} {policy} policy must fail independently:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&policy_output.stdout),
                String::from_utf8_lossy(&policy_output.stderr)
            );
            let policy_envelope: serde_json::Value = serde_json::from_slice(&policy_output.stdout)
                .unwrap_or_else(|error| panic!("parse {policy} policy JSON: {error}"));
            assert_eq!(
                policy_envelope["policy"]["fail_on"],
                serde_json::json!([policy])
            );
            assert_eq!(policy_envelope["policy"]["failed"], serde_json::json!(true));
        }
    }
}

fn seed_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
            "name": "licenses-app",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "left-pad": "^1.3.0"
            },
            "devDependencies": {
                "ansi-regex": "^5.0.1"
            }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["ansi-regex@5.0.1".to_string()],
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[
            ("left-pad", "left-pad", "1.3.0"),
            ("ansi-regex", "ansi-regex", "5.0.1"),
        ],
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to write lpm.lock");
    project.write_file(
        "node_modules/left-pad/package.json",
        r#"{
            "name": "left-pad",
            "version": "1.3.0",
            "license": "WTFPL"
        }"#,
    );
    project.write_file(
        "node_modules/ansi-regex/package.json",
        r#"{
            "name": "ansi-regex",
            "version": "5.0.1",
            "license": "MIT"
        }"#,
    );
    project
}

fn write_v1_package_manifest(project: &TempProject, name: &str, version: &str, manifest: &str) {
    let package_dir = project
        .store_dir()
        .join("v1")
        .join(format!("{name}@{version}"));
    std::fs::create_dir_all(&package_dir).expect("create v1 package fixture");
    std::fs::write(package_dir.join("package.json"), manifest)
        .expect("write v1 package manifest fixture");
    std::fs::write(package_dir.join(".integrity"), "sha512-fixture")
        .expect("write v1 package integrity fixture");
}

#[test]
fn licenses_from_workspace_member_exclude_sibling_lockfile_projection() {
    let project = workspace_projection_project();
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/app"));
    let output = command
        .args(["licenses", "--json"])
        .output()
        .expect("run licenses from workspace member");

    assert!(
        output.status.success(),
        "member licenses must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert!(package_scope(&envelope, "app-only").is_some());
    assert!(package_scope(&envelope, "sibling-only").is_none());
}

#[test]
fn licenses_json_inventories_installed_package_licenses() {
    let project = seed_project();

    let output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("failed to run lpm licenses --json");
    assert!(
        output.status.success(),
        "licenses --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(
        package_scope(&envelope, "ansi-regex"),
        Some("required"),
        "a package reachable from a production dependency must stay required even when it is also listed in devDependencies"
    );
    insta::assert_json_snapshot!("licenses_json_inventory", envelope);
}

#[test]
fn licenses_human_output_sanitizes_manifest_fields_without_changing_json() {
    let project = seed_project();
    let hostile_license = "MIT\nforged-row\u{1b}[2J";
    project.write_file(
        "node_modules/left-pad/package.json",
        &serde_json::json!({
            "name": "left-pad",
            "version": "1.3.0",
            "license": hostile_license,
        })
        .to_string(),
    );

    let human_output = lpm(&project)
        .args(["licenses"])
        .output()
        .expect("run human licenses inventory");
    assert!(
        human_output.status.success(),
        "human licenses must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&human_output.stdout),
        String::from_utf8_lossy(&human_output.stderr)
    );
    assert!(
        !human_output.stdout.contains(&b'\x1b'),
        "terminal escape bytes must not reach human output: {:?}",
        String::from_utf8_lossy(&human_output.stdout)
    );
    let human_stdout = String::from_utf8(human_output.stdout).expect("human output is UTF-8");
    assert!(
        human_stdout.lines().all(|line| line != "forged-row"),
        "manifest fields must not create forged terminal rows: {human_stdout:?}"
    );

    let json_output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("run JSON licenses inventory");
    assert!(json_output.status.success());
    let envelope: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("licenses stdout must be valid JSON");
    let package = package_for_version(&envelope, "left-pad", "1.3.0")
        .expect("left-pad must be present in the inventory");
    assert_eq!(
        package["license_expression"],
        serde_json::json!(hostile_license)
    );
    assert_eq!(package["licenses"], serde_json::json!([hostile_license]));
}

#[test]
fn licenses_scope_follows_exact_root_and_dependency_instances() {
    let project = TempProject::empty(
        r#"{
            "name": "licenses-exact-instances",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "prod-parent": "1.0.0"
            },
            "devDependencies": {
                "dev-parent": "1.0.0"
            }
        }"#,
    );
    let registry_source = "registry+https://registry.example.test";
    let dev_source = "registry+https://dev-registry.example.test";
    let prod_parent_id = lpm_common::PackageInstanceId::derive(
        "prod-parent",
        "1.0.0",
        registry_source,
        "licenses/prod-parent",
    );
    let dev_parent_id = lpm_common::PackageInstanceId::derive(
        "dev-parent",
        "1.0.0",
        registry_source,
        "licenses/dev-parent",
    );
    let prod_shared_id = lpm_common::PackageInstanceId::derive(
        "shared",
        "1.0.0",
        registry_source,
        "licenses/prod-shared",
    );
    let dev_shared_id =
        lpm_common::PackageInstanceId::derive("shared", "1.0.0", dev_source, "licenses/dev-shared");

    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(prod_parent_id),
        name: "prod-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some(registry_source.to_string()),
        dependencies: vec!["shared@1.0.0".to_string()],
        dependency_targets: [("shared".to_string(), prod_shared_id)].into(),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(dev_parent_id),
        name: "dev-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some(registry_source.to_string()),
        dependencies: vec!["shared@1.0.0".to_string()],
        dependency_targets: [("shared".to_string(), dev_shared_id)].into(),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(prod_shared_id),
        name: "shared".to_string(),
        version: "1.0.0".to_string(),
        source: Some(registry_source.to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(dev_shared_id),
        name: "shared".to_string(),
        version: "1.0.0".to_string(),
        source: Some(dev_source.to_string()),
        ..Default::default()
    });
    lockfile.root_resolutions.insert(
        "prod-parent".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(prod_parent_id),
            package: "prod-parent".to_string(),
            version: "1.0.0".to_string(),
            source: Some(registry_source.to_string()),
        },
    );
    lockfile.root_resolutions.insert(
        "dev-parent".to_string(),
        lpm_lockfile::LockedRootResolution {
            instance_id: Some(dev_parent_id),
            package: "dev-parent".to_string(),
            version: "1.0.0".to_string(),
            source: Some(registry_source.to_string()),
        },
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write exact-instance lockfile");
    for name in ["prod-parent", "dev-parent", "shared"] {
        project.write_file(
            &format!("node_modules/{name}/package.json"),
            &serde_json::json!({
                "name": name,
                "version": "1.0.0",
                "license": "MIT",
            })
            .to_string(),
        );
    }

    let output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("run licenses against exact-instance graph");
    assert!(
        output.status.success(),
        "licenses must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(
        package_scope_for_source(&envelope, "shared", registry_source),
        Some("required")
    );
    assert_eq!(
        package_scope_for_source(&envelope, "shared", dev_source),
        Some("excluded")
    );
}

#[test]
fn licenses_scope_marks_dev_only_alias_transitives_as_excluded() {
    let project = TempProject::empty(
        r#"{
            "name": "licenses-dev-alias",
            "version": "1.0.0",
            "license": "MIT",
            "devDependencies": {
                "ansi-regex-dev": "npm:ansi-regex@^5.0.1"
            }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile
        .root_aliases
        .insert("ansi-regex-dev".to_string(), "ansi-regex".to_string());
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["strip-ansi@6.0.0".to_string()],
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "strip-ansi".to_string(),
        version: "6.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[("ansi-regex-dev", "ansi-regex", "5.0.1")],
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to write aliased dev-only lockfile");
    project.write_file(
        "node_modules/ansi-regex/package.json",
        r#"{
            "name": "ansi-regex",
            "version": "5.0.1",
            "license": "MIT"
        }"#,
    );
    project.write_file(
        "node_modules/strip-ansi/package.json",
        r#"{
            "name": "strip-ansi",
            "version": "6.0.0",
            "license": "MIT"
        }"#,
    );

    let output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("failed to run lpm licenses --json");
    assert!(
        output.status.success(),
        "licenses --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(package_scope(&envelope, "ansi-regex"), Some("excluded"));
    assert_eq!(package_scope(&envelope, "strip-ansi"), Some("excluded"));
}

#[test]
fn licenses_scope_keeps_dev_only_duplicate_versions_excluded() {
    let project = TempProject::empty(
        r#"{
            "name": "licenses-duplicate-name",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "foo": "^1.0.0"
            },
            "devDependencies": {
                "dev-parent": "^1.0.0"
            }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "foo".to_string(),
        version: "2.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "dev-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["foo@2.0.0".to_string()],
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[
            ("foo", "foo", "1.0.0"),
            ("dev-parent", "dev-parent", "1.0.0"),
        ],
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to write duplicate-name lockfile");
    project.write_file(
        "node_modules/foo/package.json",
        r#"{
            "name": "foo",
            "version": "1.0.0",
            "license": "MIT"
        }"#,
    );
    project.write_file(
        "node_modules/dev-parent/package.json",
        r#"{
            "name": "dev-parent",
            "version": "1.0.0",
            "license": "MIT"
        }"#,
    );
    write_v1_package_manifest(
        &project,
        "foo",
        "2.0.0",
        r#"{
            "name": "foo",
            "version": "2.0.0",
            "license": "MIT"
        }"#,
    );

    let output = lpm_v1(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("failed to run lpm licenses --json");
    assert!(
        output.status.success(),
        "licenses --json must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(
        package_scope_for_version(&envelope, "foo", "1.0.0"),
        Some("required")
    );
    assert_eq!(
        package_scope_for_version(&envelope, "foo", "2.0.0"),
        Some("excluded")
    );
}

#[test]
fn licenses_ignores_stale_v1_copy_when_virtual_install_is_missing_version() {
    let project = TempProject::empty(
        r#"{
            "name": "licenses-duplicate-manifest",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {
                "foo": "^1.0.0"
            },
            "devDependencies": {
                "dev-parent": "^1.0.0"
            }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "foo".to_string(),
        version: "2.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "dev-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["foo@2.0.0".to_string()],
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(
        &mut lockfile,
        &[
            ("foo", "foo", "1.0.0"),
            ("dev-parent", "dev-parent", "1.0.0"),
        ],
    );
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to write duplicate-name lockfile");
    project.write_file(
        "node_modules/foo/package.json",
        r#"{
            "name": "foo",
            "version": "1.0.0",
            "license": "MIT"
        }"#,
    );
    project.write_file(
        "node_modules/dev-parent/package.json",
        r#"{
            "name": "dev-parent",
            "version": "1.0.0",
            "license": "MIT"
        }"#,
    );
    write_v1_package_manifest(
        &project,
        "foo",
        "2.0.0",
        r#"{
            "name": "foo",
            "version": "2.0.0",
            "license": "MIT"
        }"#,
    );

    let output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("run licenses with a missing installed version");
    assert!(
        !output.status.success(),
        "licenses must fail for foo@2 without an installed manifest; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(envelope["error_code"], serde_json::json!("not_found"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|error| error.contains("foo@2.0.0")
                && error.contains("Run `lpm install`")),
        "missing installed version must return a repairable error: {envelope:#}"
    );
}

#[test]
fn licenses_reports_the_path_of_a_corrupt_installed_manifest() {
    let project = seed_project();
    project.write_file("node_modules/left-pad/package.json", "{not valid JSON");

    let output = lpm(&project)
        .args(["licenses", "--json"])
        .output()
        .expect("run licenses against corrupt installed manifest");
    assert!(!output.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses error stdout must be valid JSON");
    assert_eq!(envelope["error_code"], serde_json::json!("store"));
    assert!(
        envelope["error"].as_str().is_some_and(|error| error
            .contains("failed to parse installed package manifest")
            && error.contains("node_modules/left-pad/package.json")),
        "corrupt manifest error must identify the installed path: {envelope:#}"
    );
}

#[test]
fn licenses_fail_on_copyleft_exits_nonzero_with_json_policy_result() {
    let project = seed_project();
    project.write_file(
        "node_modules/left-pad/package.json",
        r#"{
            "name": "left-pad",
            "version": "1.3.0",
            "license": "GPL-3.0"
        }"#,
    );

    let output = lpm(&project)
        .args(["licenses", "--json", "--fail-on", "copyleft"])
        .output()
        .expect("failed to run lpm licenses --fail-on copyleft --json");
    assert!(!output.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["summary"]["copyleft"], serde_json::json!(1));
    assert_eq!(envelope["policy"]["failed"], serde_json::json!(true));
}

#[test]
fn licenses_deny_exact_license_exits_nonzero() {
    let project = seed_project();

    let output = lpm(&project)
        .args(["licenses", "--json", "--deny", "WTFPL"])
        .output()
        .expect("failed to run lpm licenses --deny WTFPL --json");
    assert!(!output.status.success());

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["summary"]["denied"], serde_json::json!(1));
    assert_eq!(
        envelope["packages"][1]["denied_licenses"],
        serde_json::json!(["WTFPL"])
    );
}

fn package_scope<'a>(envelope: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    envelope["packages"]
        .as_array()?
        .iter()
        .find(|package| package["name"] == serde_json::json!(name))?
        .get("scope")?
        .as_str()
}

fn package_scope_for_version<'a>(
    envelope: &'a serde_json::Value,
    name: &str,
    version: &str,
) -> Option<&'a str> {
    package_for_version(envelope, name, version)?
        .get("scope")?
        .as_str()
}

fn package_scope_for_source<'a>(
    envelope: &'a serde_json::Value,
    name: &str,
    source: &str,
) -> Option<&'a str> {
    envelope["packages"]
        .as_array()?
        .iter()
        .find(|package| {
            package["name"] == serde_json::json!(name)
                && package["source"] == serde_json::json!(source)
        })?
        .get("scope")?
        .as_str()
}

fn package_for_version<'a>(
    envelope: &'a serde_json::Value,
    name: &str,
    version: &str,
) -> Option<&'a serde_json::Value> {
    envelope["packages"].as_array()?.iter().find(|package| {
        package["name"] == serde_json::json!(name)
            && package["version"] == serde_json::json!(version)
    })
}
