mod support;

use serde_json::json;
use sha2::{Digest, Sha256};
use support::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use support::{
    LOCK_CONTENTION_MARKER_ENV, TempProject, lpm, lpm_spawnable, lpm_with_registry,
    wait_for_lock_contention,
};

fn digest(content: &[u8]) -> String {
    format!("sha256-{}", hex::encode(Sha256::digest(content)))
}

fn write_source_state(project: &TempProject, packages: serde_json::Value) {
    project.write_file(
        ".lpm/added-sources.json",
        &serde_json::to_string_pretty(&json!({
            "schema_version": 2,
            "packages": packages,
        }))
        .unwrap(),
    );
}

fn created_file(content: &[u8]) -> serde_json::Value {
    json!({
        "installed_digest": digest(content),
        "action": "create",
    })
}

fn write_materialized_package_skill(
    project: &TempProject,
    package: &str,
    skill: &str,
    content: &str,
) {
    let directory = format!(".lpm/skills/{package}");
    project.write_file(&format!("{directory}/{skill}.md"), content);
    project.write_file(
        &format!("{directory}/.lpm-package-skills.json"),
        &serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "package": package,
            "version": "1.0.0",
            "skills": {
                skill: hex::encode(Sha256::digest(content.as_bytes()))
            }
        }))
        .unwrap(),
    );
}

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
    write_materialized_package_skill(&project, "owner.widget", "build", "# Widget skill\n");
    project.write_file(
        "components/widget/index.ts",
        "export const widget = true;\n",
    );
    project.write_file(".cursor/rules/owner.widget--build.md", "linked skill\n");
    write_source_state(
        &project,
        json!({
            "@lpm.dev/owner.widget": {
                "files": {
                    "components/widget/index.ts": created_file(b"export const widget = true;\n")
                },
                "skillPackageShort": "owner.widget"
            }
        }),
    );

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
            "components/widget/index.ts",
            ".lpm/skills/owner.widget/",
            ".cursor/rules/owner.widget--build.md"
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
fn remove_human_output_uses_slim_done_line_and_stderr_only_paths() {
    let project = TempProject::empty(r#"{"name":"remove-test","version":"1.0.0"}"#);
    write_materialized_package_skill(&project, "owner.widget", "build", "# Widget skill\n");
    project.write_file(
        "components/widget/index.ts",
        "export const widget = true;\n",
    );
    project.write_file(".cursor/rules/owner.widget--build.md", "linked skill\n");
    write_source_state(
        &project,
        json!({
            "@lpm.dev/owner.widget": {
                "files": {
                    "components/widget/index.ts": created_file(b"export const widget = true;\n")
                },
                "skillPackageShort": "owner.widget"
            }
        }),
    );

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
            && stderr.contains("- components/widget/index.ts")
            && stderr.contains("- .cursor/rules/owner.widget--build.md")
            && stderr.contains("✓ Removed package skill directory"),
        "remove should report every removed path on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · removed 3 paths in "),
        "remove should use the timed slim terminus, got:\n{stderr}"
    );
    assert!(
        stderr.contains(".lpm/skills/owner.widget/")
            && stderr.contains("components/widget/index.ts"),
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
        stderr.contains("! No tracked source files found for owner.widget"),
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

#[test]
fn remove_without_source_state_preserves_unowned_matching_directories_and_skills() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/source-pkg/index.ts", "user source\n");
    project.write_file(".lpm/skills/source-pkg/guide.md", "user skill\n");

    let output = lpm(&project)
        .args(["remove", "source-pkg", "--json"])
        .output()
        .expect("run remove without source state");

    assert!(output.status.success());
    assert_eq!(
        project.read_file("components/source-pkg/index.ts"),
        "user source\n"
    );
    assert_eq!(
        project.read_file(".lpm/skills/source-pkg/guide.md"),
        "user skill\n"
    );
}

#[test]
fn remove_rejects_an_absolute_tracked_path_without_deleting_outside_the_project() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("outside.ts");
    std::fs::write(&outside_file, b"outside\n").unwrap();
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "files": {
                    (outside_file.to_string_lossy().to_string()): created_file(b"outside\n"),
                }
            }
        }),
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("run remove with forged absolute path");

    assert!(!output.status.success());
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside\n");
}

#[cfg(unix)]
#[test]
fn remove_rejects_a_linked_tracked_parent_without_deleting_the_link_target() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("outside.ts"), b"outside\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), project.path().join("linked")).unwrap();
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "files": {
                    "linked/outside.ts": created_file(b"outside\n"),
                }
            }
        }),
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("run remove through linked parent");

    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(outside.path().join("outside.ts")).unwrap(),
        b"outside\n"
    );
}

#[test]
fn remove_preserves_a_tracked_created_file_that_the_user_modified() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/Source.ts", "user edit\n");
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "files": {
                    "components/Source.ts": created_file(b"installed\n"),
                }
            }
        }),
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg", "--json"])
        .output()
        .expect("remove modified source");

    assert!(output.status.success());
    assert_eq!(project.read_file("components/Source.ts"), "user edit\n");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["preserved"], json!(["components/Source.ts"]));
}

#[test]
fn remove_preserves_version_one_files_without_destructive_provenance() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/legacy.ts", "legacy\n");
    project.write_file(
        ".lpm/added-sources.json",
        r#"{"schema_version":1,"packages":{"source-pkg":{"files":["components/legacy.ts"]}}}"#,
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("remove version-one state");

    assert!(output.status.success());
    assert_eq!(project.read_file("components/legacy.ts"), "legacy\n");
}

#[tokio::test]
async fn remove_restores_the_original_file_after_a_tracked_overwrite() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"installed\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            project.path().join("custom/Source.ts"),
            std::fs::Permissions::from_mode(0o751),
        )
        .unwrap();
    }
    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--force",
            "--path",
            "custom",
            "--no-skills",
            "--no-install-deps",
        ])
        .assert()
        .success();

    lpm(&project)
        .args(["remove", "source-pkg"])
        .assert()
        .success();

    assert_eq!(project.read_file("custom/Source.ts"), "original\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(project.path().join("custom/Source.ts"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o751);
    }
}

#[tokio::test]
async fn remove_preserves_a_tracked_overwrite_that_the_user_modified() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"installed\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--force",
            "--path",
            "custom",
            "--no-skills",
            "--no-install-deps",
        ])
        .assert()
        .success();
    project.write_file("custom/Source.ts", "user edit\n");
    let state_before = project.read_file(".lpm/added-sources.json");

    let output = lpm(&project)
        .args(["remove", "source-pkg", "--json"])
        .output()
        .expect("remove modified overwrite");

    assert!(output.status.success());
    assert_eq!(project.read_file("custom/Source.ts"), "user edit\n");
    let state_after: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let state_before: serde_json::Value = serde_json::from_str(&state_before).unwrap();
    assert_eq!(
        state_after["packages"]["source-pkg"]["files"]["custom/Source.ts"],
        state_before["packages"]["source-pkg"]["files"]["custom/Source.ts"]
    );
}

#[tokio::test]
async fn remove_rejects_a_tampered_overwrite_backup_before_mutating_the_destination() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"installed\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--force",
            "--path",
            "custom",
            "--no-skills",
            "--no-install-deps",
        ])
        .assert()
        .success();
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    let backup = state["packages"]["source-pkg"]["files"]["custom/Source.ts"]["backup_path"]
        .as_str()
        .unwrap();
    project.write_file(backup, "tampered\n");

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("remove with tampered backup");

    assert!(!output.status.success());
    assert_eq!(project.read_file("custom/Source.ts"), "installed\n");
    assert_eq!(project.read_file(backup), "tampered\n");
}

#[tokio::test]
async fn remove_restores_the_original_when_the_managed_overwrite_is_missing() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"installed\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--force",
            "--path",
            "custom",
            "--no-skills",
            "--no-install-deps",
        ])
        .assert()
        .success();
    std::fs::remove_file(project.path().join("custom/Source.ts")).unwrap();

    lpm(&project)
        .args(["remove", "source-pkg"])
        .assert()
        .success();

    assert_eq!(project.read_file("custom/Source.ts"), "original\n");
}

#[tokio::test]
async fn remove_rejects_a_forged_overwrite_backup_path_before_mutating_files() {
    let mock = MockRegistry::start().await;
    let tarball = make_source_pkg_tarball(
        "source-pkg",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"installed\n")],
    );
    mock.with_package("source-pkg", "1.0.0", &tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    lpm_with_registry(&project, &mock.url())
        .args([
            "add",
            "source-pkg",
            "--yes",
            "--force",
            "--path",
            "custom",
            "--no-skills",
            "--no-install-deps",
        ])
        .assert()
        .success();
    let outside = tempfile::tempdir().unwrap();
    let outside_backup = outside.path().join("outside.bak");
    std::fs::write(&outside_backup, b"outside\n").unwrap();
    let mut state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    state["packages"]["source-pkg"]["files"]["custom/Source.ts"]["backup_path"] =
        json!(outside_backup);
    project.write_file(
        ".lpm/added-sources.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("remove with forged backup path");

    assert!(!output.status.success());
    assert_eq!(project.read_file("custom/Source.ts"), "installed\n");
    assert_eq!(std::fs::read(&outside_backup).unwrap(), b"outside\n");
}

#[test]
fn remove_preserves_a_file_still_tracked_by_another_source_package() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("components/shared.ts", "shared\n");
    write_source_state(
        &project,
        json!({
            "source-a": {"files": {"components/shared.ts": created_file(b"shared\n")}},
            "source-b": {"files": {"components/shared.ts": created_file(b"shared\n")}},
        }),
    );

    lpm(&project)
        .args(["remove", "source-a"])
        .assert()
        .success();

    assert_eq!(project.read_file("components/shared.ts"), "shared\n");
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert!(state["packages"].get("source-a").is_none());
    assert!(
        state["packages"]["source-b"]["files"]
            .get("components/shared.ts")
            .is_some()
    );
}

#[tokio::test]
async fn remove_unwinds_overlapping_overwrites_in_reverse_delivery_order() {
    let mock = MockRegistry::start().await;
    let lower_tarball = make_source_pkg_tarball(
        "source-a",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"lower\n")],
    );
    let upper_tarball = make_source_pkg_tarball(
        "source-b",
        "1.0.0",
        json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
        &[("Source.ts", b"upper\n")],
    );
    mock.with_package("source-a", "1.0.0", &lower_tarball).await;
    mock.with_package("source-b", "1.0.0", &upper_tarball).await;
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");

    for package in ["source-a", "source-b"] {
        lpm_with_registry(&project, &mock.url())
            .args([
                "add",
                package,
                "--yes",
                "--force",
                "--path",
                "custom",
                "--no-skills",
                "--no-install-deps",
            ])
            .assert()
            .success();
    }

    lpm(&project)
        .args(["remove", "source-b"])
        .assert()
        .success();
    assert_eq!(project.read_file("custom/Source.ts"), "lower\n");

    lpm(&project)
        .args(["remove", "source-a"])
        .assert()
        .success();
    assert_eq!(project.read_file("custom/Source.ts"), "original\n");
}

#[test]
fn remove_preflight_failure_keeps_earlier_tracked_files_and_state_unchanged() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("a.ts", "first\n");
    std::fs::create_dir(project.path().join("z-directory")).unwrap();
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "files": {
                    "a.ts": created_file(b"first\n"),
                    "z-directory": created_file(b"not a file"),
                }
            }
        }),
    );
    let original_state = project.read_file(".lpm/added-sources.json");

    let output = lpm(&project)
        .args(["remove", "source-pkg"])
        .output()
        .expect("remove with invalid later path");

    assert!(!output.status.success());
    assert_eq!(project.read_file("a.ts"), "first\n");
    assert_eq!(project.read_file(".lpm/added-sources.json"), original_state);
}

#[test]
fn remove_deletes_an_unchanged_exclusively_owned_dependency() {
    let project = TempProject::empty(
        r#"{"name":"host","version":"1.0.0","dependencies":{"dep":"^1.0.0","kept":"^2.0.0"}}"#,
    );
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "dependencies": {
                    "dep": {"spec": "^1.0.0", "section": "dependencies", "inserted": true}
                }
            }
        }),
    );

    let output = lpm(&project)
        .args(["remove", "source-pkg", "--json"])
        .output()
        .expect("remove source-owned dependency");
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["dependenciesRemoved"], json!(["dep"]));
    insta::assert_json_snapshot!("remove_json_deletes_source_owned_dependency", envelope);

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert!(manifest["dependencies"].get("dep").is_none());
    assert_eq!(manifest["dependencies"]["kept"], "^2.0.0");
}

#[test]
fn remove_preserves_a_source_owned_dependency_that_the_user_changed() {
    let project =
        TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{"dep":"^2.0.0"}}"#);
    write_source_state(
        &project,
        json!({
            "source-pkg": {
                "dependencies": {
                    "dep": {"spec": "^1.0.0", "section": "dependencies", "inserted": true}
                }
            }
        }),
    );

    lpm(&project)
        .args(["remove", "source-pkg"])
        .assert()
        .success();

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"]["dep"], "^2.0.0");
}

#[test]
fn remove_transfers_dependency_ownership_to_another_source_package() {
    let project =
        TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{"dep":"^1.0.0"}}"#);
    write_source_state(
        &project,
        json!({
            "source-a": {"dependencies": {"dep": {
                "spec": "^1.0.0", "section": "dependencies", "inserted": true
            }}},
            "source-b": {"dependencies": {"dep": {
                "spec": "^1.0.0", "section": "dependencies", "inserted": false
            }}},
        }),
    );

    lpm(&project)
        .args(["remove", "source-a"])
        .assert()
        .success();

    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["dependencies"]["dep"], "^1.0.0");
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/added-sources.json")).unwrap();
    assert_eq!(
        state["packages"]["source-b"]["dependencies"]["dep"]["inserted"],
        true
    );
}

#[test]
fn remove_rejects_a_skill_directory_not_bound_to_the_recorded_package() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file(".lpm/skills/owner.victim/guide.md", "victim\n");
    write_source_state(
        &project,
        json!({
            "@lpm.dev/owner.source": {"skillPackageShort": "owner.victim"}
        }),
    );

    let output = lpm(&project)
        .args(["remove", "@lpm.dev/owner.source"])
        .output()
        .expect("remove with forged skill identity");

    assert!(!output.status.success());
    assert_eq!(
        project.read_file(".lpm/skills/owner.victim/guide.md"),
        "victim\n"
    );
}

#[test]
fn remove_waits_for_the_same_project_install_lock_as_add() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("tracked.ts", "tracked\n");
    write_source_state(
        &project,
        json!({
            "source-pkg": {"files": {"tracked.ts": created_file(b"tracked\n")}}
        }),
    );
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    let marker_path = project.home().join("remove-lock-contention");
    let mut command = lpm_spawnable(&project);
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path);
    command.args(["remove", "source-pkg"]);
    let mut child = command.spawn().expect("spawn contending remove");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    assert!(project.file_exists("tracked.ts"));
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish contending remove");
    assert!(output.status.success());
    assert!(!project.file_exists("tracked.ts"));
}

#[test]
fn remove_from_a_workspace_member_waits_for_the_workspace_install_lock() {
    let project = TempProject::empty(
        r#"{"name":"root","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0"}"#,
    );
    project.write_file("packages/app/tracked.ts", "tracked\n");
    project.write_file(
        "packages/app/.lpm/added-sources.json",
        &serde_json::to_string_pretty(&json!({
            "schema_version": 2,
            "packages": {
                "source-pkg": {"files": {"tracked.ts": created_file(b"tracked\n")}}
            }
        }))
        .unwrap(),
    );
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    let marker_path = project.home().join("workspace-remove-lock-contention");
    let mut command = lpm_spawnable(&project);
    command.current_dir(project.path().join("packages/app"));
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path);
    command.args(["remove", "source-pkg"]);
    let mut child = command.spawn().expect("spawn workspace-member remove");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    assert!(project.file_exists("packages/app/tracked.ts"));
    drop(transaction_lock);

    let output = child
        .wait_with_output()
        .expect("finish workspace-member remove");
    assert!(output.status.success());
    assert!(!project.file_exists("packages/app/tracked.ts"));
}

#[test]
fn remove_rejects_a_workspace_that_appears_while_waiting_for_the_lock() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("tracked.ts", "tracked\n");
    write_source_state(
        &project,
        json!({
            "source-pkg": {"files": {"tracked.ts": created_file(b"tracked\n")}}
        }),
    );
    let lock_path = lpm_common::project_install_lock(project.path());
    let transaction_lock = lpm_common::acquire_exclusive_lock(&lock_path).unwrap();
    let marker_path = project.home().join("remove-workspace-appeared");
    let mut command = lpm_spawnable(&project);
    command.env(LOCK_CONTENTION_MARKER_ENV, &marker_path);
    command.args(["remove", "source-pkg"]);
    let mut child = command.spawn().expect("spawn contending remove");

    wait_for_lock_contention(&mut child, &marker_path, &lock_path);
    project.write_file(
        "package.json",
        r#"{"name":"host","version":"1.0.0","private":true,"workspaces":["packages/*"]}"#,
    );
    drop(transaction_lock);

    let output = child.wait_with_output().expect("finish contending remove");
    assert!(!output.status.success());
    assert!(project.file_exists("tracked.ts"));
    assert!(project.file_exists(".lpm/added-sources.json"));
}

#[tokio::test]
async fn remove_lower_create_owner_before_upper_overwrite_preserves_complete_cleanup() {
    let mock = MockRegistry::start().await;
    for (package, content) in [("source-a", b"lower\n"), ("source-b", b"upper\n")] {
        let tarball = make_source_pkg_tarball(
            package,
            "1.0.0",
            json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
            &[("Source.ts", content)],
        );
        mock.with_package(package, "1.0.0", &tarball).await;
    }
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    for package in ["source-a", "source-b"] {
        lpm_with_registry(&project, &mock.url())
            .args([
                "add",
                package,
                "--yes",
                "--force",
                "--path",
                "custom",
                "--no-install-deps",
                "--no-skills",
            ])
            .assert()
            .success();
    }

    lpm(&project)
        .args(["remove", "source-a"])
        .assert()
        .success();
    lpm(&project)
        .args(["remove", "source-b"])
        .assert()
        .success();

    assert!(!project.file_exists("custom/Source.ts"));
    assert!(!project.file_exists(".lpm/added-sources.json"));
}

#[tokio::test]
async fn remove_lower_overwrite_owner_before_upper_overwrite_restores_original_content() {
    let mock = MockRegistry::start().await;
    for (package, content) in [("source-a", b"lower\n"), ("source-b", b"upper\n")] {
        let tarball = make_source_pkg_tarball(
            package,
            "1.0.0",
            json!({"ecosystem": "js", "files": [{"src": "Source.ts"}]}),
            &[("Source.ts", content)],
        );
        mock.with_package(package, "1.0.0", &tarball).await;
    }
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    project.write_file("custom/Source.ts", "original\n");
    for package in ["source-a", "source-b"] {
        lpm_with_registry(&project, &mock.url())
            .args([
                "add",
                package,
                "--yes",
                "--force",
                "--path",
                "custom",
                "--no-install-deps",
                "--no-skills",
            ])
            .assert()
            .success();
    }

    lpm(&project)
        .args(["remove", "source-a"])
        .assert()
        .success();
    lpm(&project)
        .args(["remove", "source-b"])
        .assert()
        .success();

    assert_eq!(project.read_file("custom/Source.ts"), "original\n");
    assert!(!project.file_exists(".lpm/added-sources.json"));
}

#[test]
fn remove_owned_dependency_invalidates_the_install_hash() {
    let project =
        TempProject::empty(r#"{"name":"host","version":"1.0.0","dependencies":{"dep":"^1.0.0"}}"#);
    project.write_file(".lpm/install-hash", "stale\n");
    write_source_state(
        &project,
        json!({
            "source-pkg": {"dependencies": {"dep": {
                "spec": "^1.0.0", "section": "dependencies", "inserted": true
            }}}
        }),
    );

    lpm(&project)
        .args(["remove", "source-pkg"])
        .assert()
        .success();

    assert!(!project.file_exists(".lpm/install-hash"));
}

#[test]
fn remove_rejects_a_package_skill_directory_with_untracked_content() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    write_materialized_package_skill(&project, "owner.widget", "guide", "managed\n");
    project.write_file(".lpm/skills/owner.widget/user-notes.md", "user\n");
    write_source_state(
        &project,
        json!({
            "@lpm.dev/owner.widget": {"skillPackageShort": "owner.widget"}
        }),
    );

    let output = lpm(&project)
        .args(["remove", "owner.widget"])
        .output()
        .expect("remove package with mixed skill ownership");

    assert!(!output.status.success());
    assert_eq!(
        project.read_file(".lpm/skills/owner.widget/user-notes.md"),
        "user\n"
    );
    assert!(project.file_exists(".lpm/added-sources.json"));
}

#[test]
fn remove_deletes_only_editor_links_declared_by_the_package_skill_manifest() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    write_materialized_package_skill(&project, "owner.widget", "guide", "managed\n");
    project.write_file(".cursor/rules/owner.widget--guide.md", "managed link\n");
    project.write_file(
        ".cursor/rules/owner.widget--user-notes.md",
        "untracked user link\n",
    );
    write_source_state(
        &project,
        json!({
            "@lpm.dev/owner.widget": {"skillPackageShort": "owner.widget"}
        }),
    );

    lpm(&project)
        .args(["remove", "owner.widget"])
        .assert()
        .success();

    assert!(!project.file_exists(".cursor/rules/owner.widget--guide.md"));
    assert_eq!(
        project.read_file(".cursor/rules/owner.widget--user-notes.md"),
        "untracked user link\n"
    );
}

#[test]
fn remove_preserves_a_preexisting_directory_after_its_last_managed_file_is_deleted() {
    let project = TempProject::empty(r#"{"name":"host","version":"1.0.0"}"#);
    std::fs::create_dir_all(project.path().join("custom/preexisting")).unwrap();
    project.write_file("custom/preexisting/Source.ts", "managed\n");
    write_source_state(
        &project,
        json!({
            "source-pkg": {"files": {
                "custom/preexisting/Source.ts": created_file(b"managed\n")
            }}
        }),
    );

    lpm(&project)
        .args(["remove", "source-pkg"])
        .assert()
        .success();

    assert!(project.path().join("custom/preexisting").is_dir());
}
