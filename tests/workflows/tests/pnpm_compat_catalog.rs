//! Workflow tests for pnpm-sourced catalog compatibility scenarios.

mod support;

use std::process::Output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

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
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed strict install must roll package.json back"
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
        dependency_spec_optional(&project, "is-positive").is_none(),
        "failed forced catalog install must roll package.json back"
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
            && text.contains("catalog 'default'"),
        "recursive catalog error must name the package and catalog\n{text}"
    );
}

async fn mount_is_positive_versions(mock: &MockRegistry) {
    mock.with_full_package_metadata(
        "is-positive",
        "1.0.0",
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

fn run_install(project: &TempProject, mock: &MockRegistry, packages: &[&str]) -> Output {
    let mut cmd = lpm_with_registry(project, &mock.url());
    cmd.args(INSTALL_ARGS);
    cmd.args(packages);
    cmd.output().expect("failed to run lpm install")
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

fn output_text(output: &Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
