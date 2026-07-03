//! Workflow tests for `lpm licenses`.

mod support;

use support::{TempProject, lpm};

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
