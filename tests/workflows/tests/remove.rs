mod support;

use support::{TempProject, lpm};

#[test]
fn remove_json_cleans_source_package_paths_and_editor_links() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);
    project.write_file(".lpm/skills/owner.widget/build.md", "# Widget skill\n");
    project.write_file("components/widget/index.ts", "export const widget = true;\n");
    project.write_file(".cursor/rules/owner.widget--build.md", "linked skill\n");

    let output = lpm(&project)
        .args(["remove", "owner.widget", "--json"])
        .output()
        .expect("failed to run lpm remove --json");

    assert!(
        output.status.success(),
        "lpm remove --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("remove --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["package"], serde_json::json!("owner.widget"));
    assert_eq!(
        envelope["removed"],
        serde_json::json!([
            ".lpm/skills/owner.widget/",
            "components/widget/"
        ])
    );

    insta::assert_json_snapshot!("remove_json_envelope_cleans_source_package_paths", envelope);

    assert!(
        !project.file_exists(".lpm/skills/owner.widget/build.md"),
        "remove must delete the package skills directory"
    );
    assert!(
        !project.file_exists("components/widget/index.ts"),
        "remove must delete copied source files from common target directories"
    );
    assert!(
        !project.file_exists(".cursor/rules/owner.widget--build.md"),
        "remove must clean editor-integrated Cursor skill links for the package"
    );
}

#[test]
fn rm_alias_warns_and_exits_zero_when_no_files_match() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["rm", "owner.widget"])
        .output()
        .expect("failed to run lpm rm");

    assert!(output.status.success(), "lpm rm must exit zero when nothing matches");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No files found for") && combined.contains("custom path"),
        "expected missing-files warning, got:\n{combined}"
    );
}
