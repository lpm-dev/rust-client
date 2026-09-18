use super::*;

#[test]
fn licenses_nested_invocation_uses_the_selected_project() {
    let project = seed_project();
    project.write_file("src/index.js", "");
    let output = lpm(&project)
        .current_dir(project.path().join("src"))
        .args(["licenses", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["root"]["name"], "licenses-app");
    assert_eq!(report["packages"].as_array().unwrap().len(), 2);
}

#[test]
fn licenses_nested_workspace_member_excludes_sibling_dependencies() {
    let project = workspace_projection_project();
    project.write_file("packages/app/src/index.js", "");
    let root_output = lpm(&project)
        .current_dir(project.path().join("packages/app"))
        .args(["licenses", "--json"])
        .output()
        .unwrap();
    assert!(root_output.status.success());
    let nested_output = lpm(&project)
        .current_dir(project.path().join("packages/app/src"))
        .args(["licenses", "--json"])
        .output()
        .unwrap();
    assert!(
        nested_output.status.success(),
        "{}",
        String::from_utf8_lossy(&nested_output.stdout)
    );
    let expected: serde_json::Value = serde_json::from_slice(&root_output.stdout).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&nested_output.stdout).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn licenses_missing_policy_rejects_whitespace_in_all_declaration_shapes() {
    for license in [
        serde_json::json!(" \t"),
        serde_json::json!({"type":" "}),
        serde_json::json!([" ",{"type":"\n"}]),
    ] {
        let project = seed_project();
        project.write_file(
            "node_modules/left-pad/package.json",
            &serde_json::json!({"name":"left-pad","version":"1.3.0","license":license}).to_string(),
        );
        let output = lpm(&project)
            .args(["licenses", "--json", "--fail-on", "missing"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["summary"]["missing"], 1);
    }
}

#[test]
fn licenses_preserves_compound_declaration_grouping() {
    let project = seed_project();
    project.write_file(
        "node_modules/left-pad/package.json",
        r#"{"name":"left-pad","version":"1.3.0","licenses":["MIT OR Apache-2.0","BSD-3-Clause"]}"#,
    );
    let output = lpm(&project).args(["licenses", "--json"]).output().unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let package = report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "left-pad")
        .unwrap();
    assert_eq!(
        package["license_expression"],
        "BSD-3-Clause AND (MIT OR Apache-2.0)"
    );
}
