mod support;

use serde_json::json;
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{TempProject, lpm, lpm_with_registry};

fn make_source_pkg_tarball(
    name: &str,
    version: &str,
    lpm_config: serde_json::Value,
    source_files: &[(&str, &[u8])],
) -> Vec<u8> {
    let pkg_json = json!({
        "name": name,
        "version": version,
        "main": "index.js",
    });
    let lpm_config_bytes = serde_json::to_vec_pretty(&lpm_config).unwrap();

    let mut extras: Vec<(String, Vec<u8>)> = Vec::new();
    extras.push(("lpm.config.json".to_string(), lpm_config_bytes));
    for (rel, bytes) in source_files {
        extras.push(((*rel).to_string(), bytes.to_vec()));
    }
    let extras_borrowed: Vec<(&str, &[u8])> = extras
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();

    make_tarball_from_pkg_json(pkg_json, &extras_borrowed)
}

#[test]
fn remove_json_cleans_source_package_paths_and_editor_links() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);
    project.write_file(".lpm/skills/owner.widget/build.md", "# Widget skill\n");
    project.write_file(
        "components/widget/index.ts",
        "export const widget = true;\n",
    );
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
        serde_json::json!([".lpm/skills/owner.widget/", "components/widget/"])
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
fn remove_human_output_uses_slim_done_line_and_stderr_only_paths() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);
    project.write_file(".lpm/skills/owner.widget/build.md", "# Widget skill\n");
    project.write_file(
        "components/widget/index.ts",
        "export const widget = true;\n",
    );
    project.write_file(".cursor/rules/owner.widget--build.md", "linked skill\n");

    let output = lpm(&project)
        .args(["remove", "owner.widget"])
        .output()
        .expect("failed to run lpm remove");

    assert!(
        output.status.success(),
        "lpm remove failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human remove should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Removing tracked source files for owner.widget"),
        "remove should start with the slim removal phase, got:\n{stderr}"
    );
    assert!(
        stderr.contains("- .lpm/skills/owner.widget/")
            && stderr.contains("- components/widget/")
            && stderr.contains("✓ Cleaned empty directories"),
        "remove should report removed paths and directory cleanup on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · removed 2 files in "),
        "remove should use the timed slim terminus, got:\n{stderr}"
    );
    assert!(
        stderr.contains(".lpm/skills/owner.widget/") && stderr.contains("components/widget/"),
        "remove should keep the removed path list on stderr, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from remove stderr, got:\n{stderr}"
    );
}

#[test]
fn rm_alias_uses_slim_warning_and_exits_zero_when_no_files_match() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["rm", "owner.widget"])
        .output()
        .expect("failed to run lpm rm");

    assert!(
        output.status.success(),
        "lpm rm must exit zero when nothing matches"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human rm should not write to stdout when nothing matches, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("! No files found for owner.widget") && stderr.contains("custom path"),
        "expected slim missing-files warning, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from rm stderr, got:\n{stderr}"
    );
}

#[tokio::test]
async fn remove_reverses_manifest_tracked_custom_path_add_for_bare_package() {
    let mock = MockRegistry::start().await;
    let source_tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({
            "ecosystem": "js",
            "files": [{ "src": "Foo.tsx" }]
        }),
        &[("Foo.tsx", b"export const Foo = () => null;\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &source_tarball)
        .await;

    let project =
        TempProject::empty(r#"{"name":"remove-test","version":"1.0.0","dependencies":{}}"#);

    let add_output = lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--path",
            "custom/widgets",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run lpm add for manifest-backed remove test");

    assert!(
        add_output.status.success(),
        "lpm add failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&add_output.stdout),
        String::from_utf8_lossy(&add_output.stderr),
    );
    assert!(
        project.file_exists("custom/widgets/Foo.tsx"),
        "add must copy the source file into the custom path before remove runs"
    );

    let remove_output = lpm(&project)
        .args(["remove", "source-pkg", "--json"])
        .output()
        .expect("failed to run lpm remove --json after add");

    assert!(
        remove_output.status.success(),
        "lpm remove --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&remove_output.stdout),
        String::from_utf8_lossy(&remove_output.stderr),
    );

    let stdout = String::from_utf8_lossy(&remove_output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("remove --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["package"], serde_json::json!("source-pkg"));
    assert!(
        envelope["removed"].as_array().is_some_and(|removed| removed
            .iter()
            .any(|value| value == "custom/widgets/Foo.tsx")),
        "remove must report the manifest-tracked custom file path, got: {envelope}"
    );
    assert!(
        !project.file_exists("custom/widgets/Foo.tsx"),
        "remove must delete the manifest-tracked custom path file"
    );
}
