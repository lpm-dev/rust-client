//! A dependency tree whose optional native package no host can install:
//! `native-host` takes `native-wasm` (`cpu: ["wasm32"]`) as an optional
//! dependency, and `native-wasm` depends on `native-wasm-runtime`. Install
//! keeps all three in the lockfile but skips both `native-wasm` packages.

use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use super::mock_registry::MockRegistry;
use super::{TempProject, lpm_with_registry};

pub const HOST: &str = "native-host";
pub const SKIPPED_OPTIONAL: &str = "native-wasm";
pub const SKIPPED_DESCENDANT: &str = "native-wasm-runtime";

pub const PROJECT_MANIFEST: &str =
    r#"{"name":"platform-skip-project","version":"1.0.0","dependencies":{"native-host":"1.0.0"}}"#;

pub async fn mount_platform_skipped_optional_tree(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": HOST,
            "version": "1.0.0",
            "license": "MIT",
            "optionalDependencies": { SKIPPED_OPTIONAL: "1.0.0" }
        }),
        &[("index.js", b"module.exports = 1;\n")],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": SKIPPED_OPTIONAL,
            "version": "1.0.0",
            "license": "MIT",
            "cpu": ["wasm32"],
            "dependencies": { SKIPPED_DESCENDANT: "1.0.0" }
        }),
        &[("index.js", b"module.exports = 2;\n")],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": SKIPPED_DESCENDANT,
            "version": "1.0.0",
            "license": "MIT"
        }),
        &[("index.js", b"module.exports = 3;\n")],
    )
    .await;
}

/// Install [`PROJECT_MANIFEST`]'s tree and check that the lockfile kept the
/// skipped packages while the project left them out.
pub async fn install_platform_skipped_optional_tree(project: &TempProject, mock: &MockRegistry) {
    mount_platform_skipped_optional_tree(mock).await;
    lpm_with_registry(project, &mock.url())
        .args(["install", "--no-security-summary", "--no-skills"])
        .assert()
        .success();
    let lockfile = project.read_file("lpm.lock");
    for name in [HOST, SKIPPED_OPTIONAL, SKIPPED_DESCENDANT] {
        assert!(
            lockfile.contains(&format!("\"{name}\"")),
            "lpm.lock must keep {name}:\n{lockfile}"
        );
    }
    assert!(project.path().join("node_modules").join(HOST).exists());
    assert!(
        !project
            .path()
            .join("node_modules")
            .join(SKIPPED_OPTIONAL)
            .exists()
    );
}

/// Answer every OSV query in a batch with no advisories.
pub async fn answer_osv_with_no_advisories(mock: &MockRegistry) {
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let results = body["queries"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|_| serde_json::json!({ "vulns": [] }))
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .mount(mock.server())
        .await;
}
