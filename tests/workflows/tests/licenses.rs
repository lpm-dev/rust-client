//! Workflow tests for `lpm licenses`.

mod support;

use support::{TempProject, lpm, workspace_projection_project};

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
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["ansi-regex@5.0.1".to_string()],
        ..Default::default()
    });
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
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["strip-ansi@6.0.0".to_string()],
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "strip-ansi".to_string(),
        version: "6.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
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
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "foo".to_string(),
        version: "2.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "dev-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["foo@2.0.0".to_string()],
        ..Default::default()
    });
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
        package_scope_for_version(&envelope, "foo", "1.0.0"),
        Some("required")
    );
    assert_eq!(
        package_scope_for_version(&envelope, "foo", "2.0.0"),
        Some("excluded")
    );
}

#[test]
fn licenses_missing_policy_does_not_reuse_root_manifest_for_duplicate_version() {
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
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "foo".to_string(),
        version: "2.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "dev-parent".to_string(),
        version: "1.0.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        dependencies: vec!["foo@2.0.0".to_string()],
        ..Default::default()
    });
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

    let output = lpm(&project)
        .args(["licenses", "--json", "--fail-on", "missing"])
        .output()
        .expect("failed to run lpm licenses --fail-on missing --json");
    assert!(
        !output.status.success(),
        "licenses --fail-on missing must fail for foo@2 without matching metadata; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("licenses stdout must be valid JSON");
    assert_eq!(envelope["summary"]["missing"], serde_json::json!(1));
    let foo_two =
        package_for_version(&envelope, "foo", "2.0.0").expect("foo@2.0.0 must be reported");
    assert_eq!(foo_two["missing"], serde_json::json!(true));
    assert_eq!(
        foo_two["license_expression"],
        serde_json::json!("NOASSERTION")
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
