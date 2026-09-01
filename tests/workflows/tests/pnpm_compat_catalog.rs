//! Workflow tests for pnpm-sourced catalog compatibility scenarios.

mod support;

use std::process::Output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

const INSTALL_ARGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

#[tokio::test]
async fn default_catalog_mode_saves_raw_range_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_without_mode("^2.0.0");

    let output = run_install(&project, &mock, &["is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "default catalog mode install must succeed\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "^2.0.0",
        "absent catalogMode must keep the existing raw save policy"
    );
}

#[tokio::test]
async fn manual_catalog_mode_saves_raw_range_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_with_mode("manual", "^2.0.0");

    let output = run_install(&project, &mock, &["is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "manual catalog mode install must succeed\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "^2.0.0",
        "manual catalogMode must keep raw save specs even when a catalog entry matches"
    );
}

#[tokio::test]
async fn prefer_catalog_mode_saves_catalog_reference_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_with_mode("prefer", "^2.0.0");

    let output = run_install(&project, &mock, &["is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "prefer catalog mode install must succeed\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:",
        "prefer catalogMode must save matching catalog entries as catalog:"
    );
}

#[tokio::test]
async fn strict_catalog_mode_saves_catalog_reference_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_with_mode("strict", "^2.0.0");

    let output = run_install(&project, &mock, &["is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "strict catalog mode install must succeed when the requested version matches the catalog\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:",
        "strict catalogMode must save matching catalog entries as catalog:"
    );
}

#[tokio::test]
async fn install_catalog_flag_saves_default_catalog_reference_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_without_mode("^2.0.0");

    let output = run_install(&project, &mock, &["--catalog", "is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install --catalog must succeed when the default catalog entry matches\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:",
        "--catalog must force a default catalog reference independent of catalogMode"
    );
}

#[tokio::test]
async fn install_catalog_flag_persists_snapshot_for_immediate_resolved_inspection() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_without_mode("^2.0.0");

    let install_output = run_install(&project, &mock, &["--catalog", "is-positive"]);
    let install_text = output_text(&install_output);
    assert!(
        install_output.status.success(),
        "install --catalog must succeed before resolved inspection\n{install_text}"
    );

    let output = lpm(&project)
        .args(["--json", "catalog", "show", "--resolved"])
        .output()
        .expect("inspect the catalog snapshot immediately after install --catalog");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install --catalog must persist the snapshot needed by catalog show --resolved\n{text}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("catalog show output is valid JSON");
    assert_eq!(envelope["count"], serde_json::json!(1));
    assert_eq!(envelope["entries"][0]["package"], "is-positive");
    assert_eq!(envelope["entries"][0]["version"], "2.0.0");
    assert_eq!(envelope["entries"][0]["reference"], "catalog:");
}

#[tokio::test]
async fn install_named_catalog_flag_saves_named_catalog_reference_when_catalog_range_matches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = named_catalog_project("testing", "^2.0.0");

    let output = run_install(&project, &mock, &["--catalog=testing", "is-positive"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install --catalog=<name> must succeed when the named catalog entry matches\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:testing",
        "--catalog=<name> must force a named catalog reference"
    );
}

#[tokio::test]
async fn strict_catalog_mode_rejects_direct_range_outside_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_with_mode("strict", "^1.0.0");

    let output = run_install(&project, &mock, &["is-positive@2.0.0"]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "strict catalog mode must reject a direct request outside the catalog range\n{text}"
    );
    assert!(
        text.contains("catalogMode strict")
            && text.contains("is-positive@2.0.0")
            && text.contains("catalog:^1.0.0"),
        "strict mismatch error must name the requested and catalog specs\n{text}"
    );
    assert!(
        !text.contains("Installing 1 package") && !text.contains("+ is-positive@2.0.0"),
        "strict catalog mismatch must fail before install progress output\n{text}"
    );
    assert!(
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed strict install must roll package.json back"
    );
    assert!(
        !project.file_exists("lpm.lock") && !project.file_exists("lpm.lockb"),
        "strict catalog mismatch must not leave lockfiles behind"
    );
    assert!(
        !project.file_exists("node_modules") && !project.file_exists("node_modules/is-positive"),
        "strict catalog mismatch must not materialize node_modules"
    );
}

#[tokio::test]
async fn install_catalog_flag_rejects_direct_range_outside_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_without_mode("^1.0.0");

    let output = run_install(&project, &mock, &["--catalog", "is-positive@2.0.0"]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "install --catalog must reject a request outside the default catalog range\n{text}"
    );
    assert!(
        text.contains("--catalog")
            && text.contains("is-positive@2.0.0")
            && text.contains("catalog:^1.0.0"),
        "forced catalog mismatch error must name the requested and catalog specs\n{text}"
    );
    assert!(
        !text.contains("Installing 1 package") && !text.contains("+ is-positive@2.0.0"),
        "forced catalog mismatch must fail before install progress output\n{text}"
    );
    assert!(
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed forced catalog install must roll package.json back"
    );
    assert!(
        !project.file_exists("lpm.lock") && !project.file_exists("lpm.lockb"),
        "forced catalog mismatch must not leave lockfiles behind"
    );
    assert!(
        !project.file_exists("node_modules") && !project.file_exists("node_modules/is-positive"),
        "forced catalog mismatch must not materialize node_modules"
    );
}

#[tokio::test]
async fn install_named_catalog_flag_rejects_missing_entry_before_manifest_commit() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "catalogs": {
                "testing": {}
            }
        }"#,
    );

    let output = run_install(&project, &mock, &["--catalog=testing", "is-positive"]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "install --catalog=<name> must reject packages absent from that catalog\n{text}"
    );
    assert!(
        text.contains("--catalog=testing")
            && text.contains("is-positive")
            && text.contains("catalog entry"),
        "forced catalog missing-entry error must name the flag, package, and missing entry\n{text}"
    );
    assert!(
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed forced catalog install must roll package.json back"
    );
}

#[tokio::test]
async fn strict_catalog_mode_rejects_package_missing_from_default_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "catalogs": {
                "default": {}
            },
            "lpm": {
                "catalogMode": "strict"
            }
        }"#,
    );

    let output = run_install(&project, &mock, &["is-positive"]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "strict catalog mode must reject packages absent from the default catalog\n{text}"
    );
    assert!(
        text.contains("catalogMode strict")
            && text.contains("is-positive")
            && text.contains("no default")
            && text.contains("catalog entry"),
        "strict missing-catalog-entry error must name the package and missing entry\n{text}"
    );
    assert!(
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed strict install must roll package.json back"
    );
}

#[tokio::test]
async fn prefer_catalog_mode_warns_and_saves_direct_range_when_catalog_mismatches() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = catalog_project_with_mode("prefer", "^1.0.0");

    let output = run_install(&project, &mock, &["is-positive@2.0.0"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "prefer catalog mode must fall back to direct save on mismatch\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "2.0.0",
        "prefer catalogMode must preserve the direct requested spec when it is outside the catalog"
    );
    assert!(
        text.contains("Catalog version mismatch for is-positive")
            && text.contains("2.0.0")
            && text.contains("^1.0.0"),
        "prefer mismatch must warn that it fell back to the direct spec\n{text}"
    );
}

#[tokio::test]
async fn catalog_entry_recursive_definition_fails_with_clear_error() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "catalog:loop"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "recursive catalog entries must fail install\n{text}"
    );
    assert!(
        text.contains("recursive")
            && text.contains("is-positive")
            && text.contains("catalog default")
            && text.contains("specifier catalog:loop"),
        "recursive catalog error must name the package and catalog\n{text}"
    );
}

#[tokio::test]
async fn recursive_catalog_definition_json_uses_catalog_error_code() {
    let mock = MockRegistry::start().await;
    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "catalog:loop"
                }
            }
        }"#,
    );

    let output = run_install_json(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "recursive catalog entries must fail install\n{text}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("recursive catalog JSON error must be valid JSON: {error}\n{text}")
        });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("catalog_entry_invalid_recursive_definition")
    );
    assert!(
        envelope["error"].as_str().is_some_and(|error| {
            error.contains("is-positive")
                && error.contains("catalog 'default'")
                && error.contains("catalog:loop")
        }),
        "recursive catalog JSON error must name the package, catalog, and recursive spec\n{text}"
    );
}

#[tokio::test]
async fn pnpm_workspace_default_catalog_resolves_catalog_dependency() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install must resolve catalog: from pnpm-workspace.yaml catalog\n{text}"
    );
    assert_eq!(
        resolved_version(&project, "is-positive"),
        "2.0.0",
        "default pnpm workspace catalog should feed catalog: resolution"
    );
}

#[tokio::test]
async fn recursive_workspace_member_resolves_pnpm_default_catalog_dependency() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "private": true,
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "app",
            "version": "1.0.0",
            "dependencies": {
                "catalog-provider": "workspace:*"
            }
        }"#,
    );
    project.write_file(
        "packages/catalog-provider/package.json",
        r#"{
            "name": "catalog-provider",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to run recursive lpm install");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "recursive install must resolve member catalog: from pnpm-workspace.yaml\n{text}"
    );
    assert_eq!(
        resolved_version_at(&project, "packages/app", "is-positive"),
        "2.0.0",
        "workspace-member provider closures should inherit the root pnpm default catalog"
    );
}

#[tokio::test]
async fn pnpm_workspace_named_catalog_resolves_catalog_dependency() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:testing"
            }
        }"#,
        r#"packages:
  - "packages/*"
catalogs:
  testing:
    is-positive: ^2.0.0
"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install must resolve catalog:<name> from pnpm-workspace.yaml catalogs\n{text}"
    );
    assert_eq!(
        resolved_version(&project, "is-positive"),
        "2.0.0",
        "named pnpm workspace catalog should feed catalog:<name> resolution"
    );
}

#[tokio::test]
async fn package_json_catalog_entry_overrides_pnpm_workspace_catalog_entry() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^1.0.0
"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "package.json catalog must win when pnpm-workspace.yaml defines the same entry\n{text}"
    );
    assert_eq!(
        resolved_version(&project, "is-positive"),
        "2.0.0",
        "package.json catalog entry should take precedence over pnpm-workspace.yaml"
    );
}

#[tokio::test]
async fn install_catalog_flag_saves_reference_from_pnpm_workspace_default_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0"
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );

    let output = run_install(
        &project,
        &mock,
        &["is-positive", "--workspace-root", "--catalog"],
    );
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install --catalog must see pnpm-workspace.yaml default catalog entries\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:",
        "--catalog should save catalog: when pnpm-workspace.yaml default catalog matches"
    );
}

#[tokio::test]
async fn install_named_catalog_flag_saves_reference_from_pnpm_workspace_named_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0"
        }"#,
        r#"packages:
  - "packages/*"
catalogs:
  testing:
    is-positive: ^2.0.0
"#,
    );

    let output = run_install(
        &project,
        &mock,
        &["is-positive", "--workspace-root", "--catalog=testing"],
    );
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install --catalog=<name> must see pnpm-workspace.yaml named catalog entries\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:testing",
        "--catalog=<name> should save catalog:<name> when pnpm-workspace.yaml named catalog matches"
    );
}

#[tokio::test]
async fn prefer_catalog_mode_saves_reference_from_pnpm_workspace_default_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "lpm": {
                "catalogMode": "prefer"
            }
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );

    let output = run_install(&project, &mock, &["is-positive", "--workspace-root"]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "catalogMode prefer must see pnpm-workspace.yaml default catalog entries\n{text}"
    );
    assert_eq!(
        dependency_spec(&project, "is-positive"),
        "catalog:",
        "prefer mode should save catalog: when pnpm-workspace.yaml default catalog matches"
    );
}

#[tokio::test]
async fn nested_workspace_member_uses_nearest_workspace_catalog() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = nested_pnpm_workspace_catalog_project();

    let output = run_install_in_dir(&project, &mock, "packages/app/packages/leaf", &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install from a nested workspace member must succeed\n{text}"
    );
    assert_eq!(
        resolved_version_at(&project, "packages/app/packages/leaf", "is-positive"),
        "2.0.0",
        "nested workspace members must resolve catalog: from the nearest workspace root, not an outer workspace root"
    );
    let entry = catalog_snapshot_entry_at(
        &project,
        "packages/app/packages/leaf",
        "default",
        "is-positive",
    );
    assert_eq!(entry.specifier, "^2.0.0");
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.reference, "catalog:");
}

#[tokio::test]
async fn cleanup_unused_catalogs_defaults_to_preserving_package_json_entries() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0",
                    "is-negative": "^1.0.0"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with default cleanupUnusedCatalogs setting must succeed\n{text}"
    );
    assert_eq!(
        catalog_entry(&project, "default", "is-negative"),
        "^1.0.0",
        "cleanupUnusedCatalogs must default to preserving unused catalog entries"
    );
}

#[tokio::test]
async fn cleanup_unused_catalogs_removes_unused_package_json_default_entries() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0",
                    "is-negative": "^1.0.0"
                }
            },
            "lpm": {
                "cleanupUnusedCatalogs": true
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with cleanupUnusedCatalogs must succeed\n{text}"
    );
    assert_eq!(
        catalog_entry(&project, "default", "is-positive"),
        "^2.0.0",
        "referenced default catalog entry must stay"
    );
    assert!(
        catalog_entry_optional(&project, "default", "is-negative").is_none(),
        "unused default catalog entry must be removed"
    );
}

#[tokio::test]
async fn cleanup_unused_catalogs_removes_unused_package_json_named_entries() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:testing"
            },
            "catalogs": {
                "testing": {
                    "is-positive": "^2.0.0",
                    "is-negative": "^1.0.0"
                },
                "unused": {
                    "is-negative": "^1.0.0"
                }
            },
            "lpm": {
                "cleanupUnusedCatalogs": true
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with named cleanupUnusedCatalogs catalog must succeed\n{text}"
    );
    assert_eq!(
        catalog_entry(&project, "testing", "is-positive"),
        "^2.0.0",
        "referenced named catalog entry must stay"
    );
    assert!(
        catalog_entry_optional(&project, "testing", "is-negative").is_none(),
        "unused named catalog entry must be removed"
    );
    assert!(
        catalog_entry_optional(&project, "unused", "is-negative").is_none(),
        "catalogs left empty by cleanup must be removed"
    );
}

#[tokio::test]
async fn cleanup_unused_catalogs_removes_unused_pnpm_workspace_catalog_entries() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
        r#"packages:
  - "packages/*"
cleanupUnusedCatalogs: true
catalog:
  is-positive: ^2.0.0
  is-negative: ^1.0.0
"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with pnpm-workspace.yaml cleanupUnusedCatalogs must succeed\n{text}"
    );
    let workspace_yaml = project.read_file("pnpm-workspace.yaml");
    assert!(
        workspace_yaml.contains("is-positive"),
        "referenced pnpm workspace catalog entry must stay\n{workspace_yaml}"
    );
    assert!(
        !workspace_yaml.contains("is-negative"),
        "unused pnpm workspace catalog entry must be removed\n{workspace_yaml}"
    );
}

#[tokio::test]
async fn lockfile_catalog_snapshot_records_default_catalog_resolution() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with default catalog dependency must succeed\n{text}"
    );
    let entry = catalog_snapshot_entry(&project, "default", "is-positive");
    assert_eq!(entry.specifier, "^2.0.0");
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.reference, "catalog:");
}

#[tokio::test]
async fn lockfile_catalog_snapshot_records_named_catalog_resolution() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:testing"
            },
            "catalogs": {
                "testing": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with named catalog dependency must succeed\n{text}"
    );
    let entry = catalog_snapshot_entry(&project, "testing", "is-positive");
    assert_eq!(entry.specifier, "^2.0.0");
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.reference, "catalog:testing");
}

#[tokio::test]
async fn frozen_catalog_install_replays_override_selected_direct_version() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "needs-positive-two",
            "version": "1.0.0",
            "peerDependencies": {
                "is-positive": "^2.0.0"
            }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:",
                "needs-positive-two": "^1.0.0"
            },
            "catalogs": {
                "default": {
                    "is-positive": ">=1.0.0"
                }
            },
            "lpm": {
                "overrides": {
                    "is-positive": "1.0.0"
                }
            }
        }"#,
    );

    let first = run_install(&project, &mock, &[]);
    let first_text = output_text(&first);
    assert!(
        first.status.success(),
        "initial catalog install with an override must succeed\n{first_text}"
    );

    let frozen = run_install(&project, &mock, &["--frozen-lockfile"]);
    let frozen_text = output_text(&frozen);
    assert!(
        frozen.status.success(),
        "frozen replay must accept the override-selected direct catalog version\n{frozen_text}"
    );
}

#[tokio::test]
async fn frozen_catalog_replay_allows_unused_catalog_backed_resolution() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "resolutions": {
                "is-negative": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0",
                    "is-negative": "^1.0.0"
                }
            }
        }"#,
    );

    let first = run_install(&project, &mock, &[]);
    let first_text = output_text(&first);
    assert!(
        first.status.success(),
        "initial catalog install with an unused resolution must succeed\n{first_text}"
    );
    assert!(
        catalog_snapshot_entry_optional(&project, "default", "is-negative").is_none(),
        "an unused catalog-backed resolution must not be persisted as applied"
    );

    let frozen = run_install(&project, &mock, &["--frozen-lockfile"]);
    let frozen_text = output_text(&frozen);
    assert!(
        frozen.status.success(),
        "frozen replay must accept a configured catalog-backed resolution that was not applied\n{frozen_text}"
    );
}

#[tokio::test]
async fn warm_install_updates_catalog_snapshot_when_catalog_specifier_drifts() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
    );

    let first_output = run_install(&project, &mock, &[]);
    let first_text = output_text(&first_output);
    assert!(
        first_output.status.success(),
        "initial catalog install must succeed\n{first_text}"
    );
    assert_eq!(
        catalog_snapshot_entry(&project, "default", "is-positive").specifier,
        "^2.0.0"
    );

    project.write_file(
        "package.json",
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": ">=1.0.0"
                }
            }
        }"#,
    );

    let second_output = run_install(&project, &mock, &[]);
    let second_text = output_text(&second_output);
    assert!(
        second_output.status.success(),
        "warm install after catalog drift must succeed\n{second_text}"
    );
    let entry = catalog_snapshot_entry(&project, "default", "is-positive");
    assert_eq!(
        entry.specifier, ">=1.0.0",
        "warm install must refresh lockfile catalog provenance when the catalog range changes"
    );
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.reference, "catalog:");
}

#[tokio::test]
async fn warm_install_updates_pnpm_workspace_catalog_snapshot_when_catalog_specifier_drifts() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = pnpm_workspace_catalog_project(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^1.0.0
"#,
    );

    let first = run_install(&project, &mock, &[]);
    let first_text = output_text(&first);
    assert!(
        first.status.success(),
        "initial pnpm-workspace catalog install must succeed\n{first_text}"
    );
    assert_eq!(
        catalog_snapshot_entry(&project, "default", "is-positive").specifier,
        "^1.0.0"
    );

    project.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );

    let second = run_install(&project, &mock, &[]);
    let second_text = output_text(&second);
    assert!(
        second.status.success(),
        "warm install after pnpm-workspace catalog drift must succeed\n{second_text}"
    );
    let entry = catalog_snapshot_entry(&project, "default", "is-positive");
    assert_eq!(
        entry.specifier, "^2.0.0",
        "warm install must refresh lockfile catalog provenance when pnpm-workspace.yaml changes"
    );
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.reference, "catalog:");
}

#[tokio::test]
async fn override_default_catalog_reference_resolves_to_catalog_range() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mount_is_positive_consumer(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "uses-is-positive": "^1.0.0"
            },
            "overrides": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^1.0.0"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with default catalog override must succeed\n{text}"
    );
    assert_eq!(
        resolved_version(&project, "is-positive"),
        "1.0.0",
        "override value catalog: must resolve through the default catalog before override parsing"
    );
    let entry = catalog_snapshot_entry(&project, "default", "is-positive");
    assert_eq!(entry.specifier, "^1.0.0");
    assert_eq!(entry.version, "1.0.0");
    assert_eq!(entry.reference, "catalog:");
}

#[tokio::test]
async fn override_named_catalog_reference_resolves_to_catalog_range() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mount_is_positive_consumer(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "uses-is-positive": "^1.0.0"
            },
            "overrides": {
                "is-positive": "catalog:testing"
            },
            "catalogs": {
                "testing": {
                    "is-positive": "^1.0.0"
                }
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with named catalog override must succeed\n{text}"
    );
    assert_eq!(
        resolved_version(&project, "is-positive"),
        "1.0.0",
        "override value catalog:<name> must resolve through the named catalog before override parsing"
    );
    let entry = catalog_snapshot_entry(&project, "testing", "is-positive");
    assert_eq!(entry.specifier, "^1.0.0");
    assert_eq!(entry.version, "1.0.0");
    assert_eq!(entry.reference, "catalog:testing");
}

#[tokio::test]
async fn cleanup_unused_catalogs_preserves_catalog_entries_used_by_overrides() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;
    mount_is_positive_consumer(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "uses-is-positive": "^1.0.0"
            },
            "overrides": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^1.0.0",
                    "is-negative": "^1.0.0"
                }
            },
            "lpm": {
                "cleanupUnusedCatalogs": true
            }
        }"#,
    );

    let output = run_install(&project, &mock, &[]);
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "install with cleanupUnusedCatalogs and catalog override must succeed\n{text}"
    );
    assert_eq!(
        catalog_entry(&project, "default", "is-positive"),
        "^1.0.0",
        "cleanupUnusedCatalogs must keep catalog entries referenced by overrides"
    );
    assert!(
        catalog_entry_optional(&project, "default", "is-negative").is_none(),
        "cleanupUnusedCatalogs should still prune entries unused by deps or overrides"
    );
}

#[test]
fn catalog_list_unused_json_reports_unreferenced_catalog_entries() {
    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0",
                    "is-negative": "^1.0.0"
                },
                "testing": {
                    "is-odd": "^3.0.0"
                }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["--json", "catalog", "list", "--unused"])
        .output()
        .expect("failed to run lpm catalog list --unused --json");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "catalog list --unused --json must succeed\n{text}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("catalog list output is valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["mode"], serde_json::json!("unused"));
    assert_eq!(envelope["count"], serde_json::json!(2));
    assert!(
        envelope["entries"]
            .as_array()
            .expect("entries is an array")
            .iter()
            .any(|entry| entry["catalog"] == "default" && entry["package"] == "is-negative"),
        "unused default catalog entry must be reported\n{envelope:#}"
    );
    assert!(
        envelope["entries"]
            .as_array()
            .expect("entries is an array")
            .iter()
            .any(|entry| entry["catalog"] == "testing" && entry["package"] == "is-odd"),
        "unused named catalog entry must be reported\n{envelope:#}"
    );

    insta::assert_json_snapshot!("catalog_list_unused_json_envelope", envelope);
}

#[tokio::test]
async fn catalog_show_resolved_json_reports_lockfile_catalog_snapshot() {
    let mock = MockRegistry::start().await;
    mount_is_positive_versions(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
    );

    let install_output = run_install(&project, &mock, &[]);
    let install_text = output_text(&install_output);
    assert!(
        install_output.status.success(),
        "install with catalog dependency must succeed before catalog show\n{install_text}"
    );

    let output = lpm(&project)
        .args(["--json", "catalog", "show", "--resolved"])
        .output()
        .expect("failed to run lpm catalog show --resolved --json");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "catalog show --resolved --json must succeed\n{text}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("catalog show output is valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["count"], serde_json::json!(1));
    let entry = envelope["entries"]
        .as_array()
        .expect("entries is an array")
        .first()
        .expect("resolved catalog entry is present");
    assert_eq!(entry["catalog"], serde_json::json!("default"));
    assert_eq!(entry["package"], serde_json::json!("is-positive"));
    assert_eq!(entry["specifier"], serde_json::json!("^2.0.0"));
    assert_eq!(entry["version"], serde_json::json!("2.0.0"));
    assert_eq!(entry["reference"], serde_json::json!("catalog:"));

    insta::assert_json_snapshot!("catalog_show_resolved_json_envelope", envelope);
}

#[test]
fn catalog_show_resolved_aggregates_member_projections_from_the_workspace_lockfile() {
    let project = TempProject::empty(
        r#"{
            "name": "catalog-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "catalogs": {
                "default": { "is-positive": "^2.0.0" }
            }
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "catalog-app",
            "version": "1.0.0",
            "dependencies": { "is-positive": "catalog:" }
        }"#,
    );
    let mut app = lpm_lockfile::Lockfile::new();
    app.catalogs
        .entry("default".to_string())
        .or_default()
        .insert(
            "is-positive".to_string(),
            lpm_lockfile::CatalogSnapshotEntry {
                specifier: "^2.0.0".to_string(),
                version: "2.0.0".to_string(),
                reference: "catalog:".to_string(),
            },
        );
    let mut union = lpm_lockfile::Lockfile::new();
    union
        .absorb_importer("packages/app", app)
        .expect("absorb catalog importer");
    union
        .write_all(&project.path().join("lpm.lock"))
        .expect("write workspace lockfile");

    let output = lpm(&project)
        .args(["--json", "catalog", "show", "--resolved"])
        .output()
        .expect("show resolved workspace catalogs");
    assert!(
        output.status.success(),
        "catalog show must aggregate importer snapshots:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("catalog output must be JSON");
    assert_eq!(envelope["count"], 1);
    assert_eq!(envelope["entries"][0]["package"], "is-positive");
    assert_eq!(envelope["entries"][0]["version"], "2.0.0");
}

#[test]
fn catalog_show_resolved_rejects_lockfile_missing_referenced_catalog_snapshot() {
    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            },
            "catalogs": {
                "default": {
                    "is-positive": "^2.0.0"
                }
            }
        }"#,
    );
    lpm_lockfile::Lockfile::new()
        .write_to_file(&project.path().join("lpm.lock"))
        .expect("empty stale lockfile writes");

    let output = lpm(&project)
        .args(["--json", "catalog", "show", "--resolved"])
        .output()
        .expect("failed to run lpm catalog show --resolved --json");
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "catalog show --resolved must reject a lockfile without referenced catalog snapshots\n{text}"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("stale catalog snapshot error must be valid JSON: {error}\n{text}")
        });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert!(
        envelope["error"].as_str().is_some_and(|error| {
            error.contains("lpm.lock")
                && error.contains("catalog snapshot")
                && error.contains("default")
                && error.contains("is-positive")
                && error.contains("lpm install")
        }),
        "catalog stale-lockfile error must name the missing reference and remediation\n{text}"
    );
}

async fn mount_is_positive_versions(mock: &MockRegistry) {
    mock.with_full_package_metadata(
        "is-positive",
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("is-positive", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("is-positive", "2.0.0")),
            ),
        ],
    )
    .await;
}

async fn mount_is_positive_consumer(mock: &MockRegistry) {
    mock.with_full_package_metadata(
        "uses-is-positive",
        "1.0.0",
        &[(
            "1.0.0",
            serde_json::json!({
                "is-positive": "*"
            }),
            Some(make_tarball("uses-is-positive", "1.0.0")),
        )],
    )
    .await;
}

fn catalog_project_without_mode(catalog_range: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "catalogs": {{
                "default": {{
                    "is-positive": "{catalog_range}"
                }}
            }}
        }}"#
    ))
}

fn catalog_project_with_mode(mode: &str, catalog_range: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "catalogs": {{
                "default": {{
                    "is-positive": "{catalog_range}"
                }}
            }},
            "lpm": {{
                "catalogMode": "{mode}"
            }}
        }}"#
    ))
}

fn named_catalog_project(catalog_name: &str, catalog_range: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "pnpm-compat-catalog",
            "version": "1.0.0",
            "catalogs": {{
                "{catalog_name}": {{
                    "is-positive": "{catalog_range}"
                }}
            }}
        }}"#
    ))
}

fn pnpm_workspace_catalog_project(package_json: &str, pnpm_workspace_yaml: &str) -> TempProject {
    let project = TempProject::empty(package_json);
    project.write_file("pnpm-workspace.yaml", pnpm_workspace_yaml);
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "app",
            "version": "1.0.0"
        }"#,
    );
    project
}

fn nested_pnpm_workspace_catalog_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
            "name": "outer-workspace",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^1.0.0
"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "inner-workspace",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "packages/app/pnpm-workspace.yaml",
        r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
    );
    project.write_file(
        "packages/app/packages/leaf/package.json",
        r#"{
            "name": "leaf",
            "version": "1.0.0",
            "dependencies": {
                "is-positive": "catalog:"
            }
        }"#,
    );
    project
}

fn run_install(project: &TempProject, mock: &MockRegistry, packages: &[&str]) -> Output {
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.args(INSTALL_ARGS);
    cmd.args(packages);
    cmd.output().expect("failed to run lpm install")
}

fn run_install_in_dir(
    project: &TempProject,
    mock: &MockRegistry,
    rel_dir: &str,
    packages: &[&str],
) -> Output {
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.current_dir(project.path().join(rel_dir));
    cmd.args(INSTALL_ARGS);
    cmd.args(packages);
    cmd.output().expect("failed to run lpm install")
}

fn run_install_json(project: &TempProject, mock: &MockRegistry, packages: &[&str]) -> Output {
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.arg("--json");
    cmd.args(INSTALL_ARGS);
    cmd.args(packages);
    cmd.output().expect("failed to run lpm install --json")
}

fn resolved_version(project: &TempProject, package: &str) -> String {
    let lockfile = lpm_lockfile::Lockfile::read_for_project(project.path())
        .expect("lpm.lock parses")
        .lockfile;
    lockfile
        .packages
        .iter()
        .find(|pkg| pkg.name == package)
        .unwrap_or_else(|| panic!("expected `{package}` in lpm.lock"))
        .version
        .clone()
}

fn resolved_version_at(project: &TempProject, rel_dir: &str, package: &str) -> String {
    let lockfile = lpm_lockfile::Lockfile::read_for_project(&project.path().join(rel_dir))
        .expect("lpm.lock parses")
        .lockfile;
    lockfile
        .packages
        .iter()
        .find(|pkg| pkg.name == package)
        .unwrap_or_else(|| panic!("expected `{package}` in lpm.lock"))
        .version
        .clone()
}

fn dependency_spec(project: &TempProject, package: &str) -> String {
    dependency_spec_optional(project, package)
        .unwrap_or_else(|| panic!("expected dependency `{package}` in package.json"))
}

fn dependency_spec_optional(project: &TempProject, package: &str) -> Option<String> {
    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("package.json parses");
    package_json
        .get("dependencies")
        .and_then(|deps| deps.get(package))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn catalog_entry(project: &TempProject, catalog: &str, package: &str) -> String {
    catalog_entry_optional(project, catalog, package)
        .unwrap_or_else(|| panic!("expected catalog `{catalog}` entry for `{package}`"))
}

fn catalog_entry_optional(project: &TempProject, catalog: &str, package: &str) -> Option<String> {
    let package_json: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).expect("package.json parses");
    package_json
        .get("catalogs")
        .and_then(|catalogs| catalogs.get(catalog))
        .and_then(|entries| entries.get(package))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn catalog_snapshot_entry(
    project: &TempProject,
    catalog: &str,
    package: &str,
) -> lpm_lockfile::CatalogSnapshotEntry {
    catalog_snapshot_entry_optional(project, catalog, package).unwrap_or_else(|| {
        panic!(
            "expected lockfile catalog snapshot `{catalog}` entry for `{package}`\n{}",
            project.read_file("lpm.lock")
        )
    })
}

fn catalog_snapshot_entry_optional(
    project: &TempProject,
    catalog: &str,
    package: &str,
) -> Option<lpm_lockfile::CatalogSnapshotEntry> {
    let lockfile = lpm_lockfile::Lockfile::read_for_project(project.path())
        .expect("lpm.lock parses")
        .lockfile;
    lockfile
        .catalogs
        .get(catalog)
        .and_then(|entries| entries.get(package))
        .cloned()
}

fn catalog_snapshot_entry_at(
    project: &TempProject,
    rel_dir: &str,
    catalog: &str,
    package: &str,
) -> lpm_lockfile::CatalogSnapshotEntry {
    let lockfile = lpm_lockfile::Lockfile::read_for_project(&project.path().join(rel_dir))
        .expect("lpm.lock parses")
        .lockfile;
    lockfile
        .catalogs
        .get(catalog)
        .and_then(|entries| entries.get(package))
        .unwrap_or_else(|| {
            panic!(
                "expected lockfile catalog snapshot `{catalog}` entry for `{package}`\n{}",
                project.read_file(&format!("{rel_dir}/lpm.lock"))
            )
        })
        .clone()
}

fn output_text(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
