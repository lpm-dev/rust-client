//! An installed `@lpm.dev` package whose npm dependency an OSV advisory
//! affects. OSV doesn't know LPM packages, so this is the only way one is
//! vulnerable.

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use super::{TempProject, lpm_with_registry};

pub const WRAPPER: &str = "@lpm.dev/test.wrapper";
pub const DEPENDENCY: &str = "dep-pkg";
pub const ADVISORY: &str = "GHSA-dep-pkg-fixed-in-1-0-1";
/// The `_vulnerabilities` entry the registry served before it stopped.
pub const STALE_REGISTRY_ADVISORY: &str = "LPM-STALE-REGISTRY-ADVISORY";

/// One release of the wrapper and the range it gives `dep-pkg`, under its
/// own name or, with `alias`, as `"<alias>": "npm:dep-pkg@<range>"`.
pub struct WrapperRelease<'a> {
    pub version: &'a str,
    pub dependency_range: &'a str,
    pub alias: Option<&'a str>,
}

impl WrapperRelease<'_> {
    fn dependencies(&self) -> serde_json::Value {
        match self.alias {
            Some(alias) => serde_json::json!({
                alias: format!("npm:{DEPENDENCY}@{}", self.dependency_range)
            }),
            None => serde_json::json!({ DEPENDENCY: self.dependency_range }),
        }
    }
}

/// The project manifest that depends on the wrapper's first release.
pub fn wrapper_project(first: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"wrapper-app","version":"1.0.0","dependencies":{{"{WRAPPER}":"{first}"}}}}"#
    ))
}

/// What the mock registry serves for the wrapper.
pub struct WrapperFixture {
    /// The wrapper's package metadata, as the per-package route serves it.
    pub metadata: serde_json::Value,
    /// Each release's tarball, by version.
    pub tarballs: std::collections::HashMap<String, Vec<u8>>,
}

impl WrapperFixture {
    pub fn tarball(&self, version: &str) -> Vec<u8> {
        self.tarballs[version].clone()
    }
}

/// Serves `dep-pkg` 1.0.0 and 1.0.1 (latest) and the wrapper's `releases`.
/// With `stale_registry_advisory`, the wrapper's first release still carries
/// a critical `_vulnerabilities` entry in batch metadata, as a cache written
/// before the registry stopped serving them.
pub async fn mount_wrapper_with_npm_dependency(
    mock: &MockRegistry,
    releases: &[WrapperRelease<'_>],
    stale_registry_advisory: bool,
) -> WrapperFixture {
    let dependency_versions = ["1.0.0", "1.0.1"].map(|version| {
        let tarball = make_tarball_from_pkg_json(
            serde_json::json!({
                "name": DEPENDENCY,
                "version": version,
                "license": "MIT",
                "main": "index.js"
            }),
            &[],
        );
        (version, serde_json::json!({}), Some(tarball))
    });
    let dependency = mock
        .mount_full_package_metadata_routes(DEPENDENCY, "1.0.1", &dependency_versions)
        .await;

    let wrapper_versions = releases
        .iter()
        .map(|release| {
            let dependencies = release.dependencies();
            let tarball = make_tarball_from_pkg_json(
                serde_json::json!({
                    "name": WRAPPER,
                    "version": release.version,
                    "license": "MIT",
                    "main": "index.js",
                    "dependencies": dependencies
                }),
                &[],
            );
            (release.version, dependencies, Some(tarball))
        })
        .collect::<Vec<_>>();
    let latest = releases
        .last()
        .expect("the wrapper needs a release")
        .version;
    let metadata = mock
        .mount_full_package_metadata_routes(WRAPPER, latest, &wrapper_versions)
        .await;
    let mut batch_entry = metadata.clone();
    if stale_registry_advisory {
        batch_entry["versions"][releases[0].version]["_vulnerabilities"] = serde_json::json!([{
            "id": STALE_REGISTRY_ADVISORY,
            "summary": "a registry advisory no longer served",
            "severity": "critical"
        }]);
    }
    mock.with_batch_metadata(vec![dependency, batch_entry])
        .await;

    WrapperFixture {
        metadata,
        tarballs: wrapper_versions
            .into_iter()
            .map(|(version, _, tarball)| (version.to_string(), tarball.expect("built above")))
            .collect(),
    }
}

/// Mounts the wrapper as [`mount_wrapper_with_npm_dependency`] does and
/// installs the project.
pub async fn install_wrapper_with_npm_dependency(
    project: &TempProject,
    mock: &MockRegistry,
    releases: &[WrapperRelease<'_>],
    stale_registry_advisory: bool,
) -> WrapperFixture {
    let fixture = mount_wrapper_with_npm_dependency(mock, releases, stale_registry_advisory).await;
    lpm_with_registry(project, &mock.url())
        .args(["install", "--no-security-summary", "--no-skills"])
        .assert()
        .success();
    fixture
}

/// A critical OSV advisory on `dep-pkg`, fixed in 1.0.1.
pub fn dependency_advisory() -> serde_json::Value {
    serde_json::json!({
        "id": ADVISORY,
        "summary": "dep-pkg advisory",
        "severity": [{ "type": "CVSS_V3", "score": "9.8" }],
        "affected": [{
            "package": { "ecosystem": "npm", "name": DEPENDENCY },
            "ranges": [{
                "type": "SEMVER",
                "events": [{ "introduced": "0" }, { "fixed": "1.0.1" }]
            }]
        }]
    })
}

/// Answers OSV for a tree whose only npm package is `dep-pkg` at `version`.
pub async fn answer_osv_for_dependency(
    mock: &MockRegistry,
    version: &str,
    advisories: Vec<serde_json::Value>,
) {
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(serde_json::json!({
            "queries": [{
                "package": { "name": DEPENDENCY, "ecosystem": "npm" },
                "version": version
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{ "vulns": advisories }]
        })))
        .mount(mock.server())
        .await;
}
