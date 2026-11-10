//! An installed `@lpm.dev` package whose npm dependency an OSV advisory
//! affects. OSV doesn't know LPM packages, so this is the only way one is
//! vulnerable.

use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::mock_registry::{MockRegistry, make_tarball_from_pkg_json};
use super::{TempProject, lpm_with_registry};

pub const WRAPPER: &str = "@lpm.dev/test.wrapper";
pub const DEPENDENCY: &str = "dep-pkg";
/// An npm package that depends on `dep-pkg` 1.0.0 exactly, so the tree keeps
/// that version whatever the wrapper does.
pub const ANCHOR: &str = "anchor-pkg";
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

/// A wrapper release by its manifest fields, for a dependency on `dep-pkg`
/// that [`WrapperRelease`] doesn't describe, such as a peer or none.
pub struct WrapperManifest<'a> {
    pub version: &'a str,
    pub fields: serde_json::Value,
}

/// The project manifest that depends on the wrapper's first release and on
/// [`ANCHOR`].
pub fn wrapper_beside_an_anchor_project(first: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"wrapper-app","version":"1.0.0","dependencies":{{"{WRAPPER}":"{first}","{ANCHOR}":"1.0.0"}}}}"#
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
    let dependency = mount_dependency(mock).await;
    let manifests = releases
        .iter()
        .map(|release| WrapperManifest {
            version: release.version,
            fields: serde_json::json!({ "dependencies": release.dependencies() }),
        })
        .collect::<Vec<_>>();
    let fixture = mount_wrapper_manifests(mock, &manifests).await;
    let mut batch_entry = fixture.metadata.clone();
    if stale_registry_advisory {
        batch_entry["versions"][releases[0].version]["_vulnerabilities"] = serde_json::json!([{
            "id": STALE_REGISTRY_ADVISORY,
            "summary": "a registry advisory no longer served",
            "severity": "critical"
        }]);
    }
    mock.with_batch_metadata(vec![dependency, batch_entry])
        .await;
    fixture
}

/// Serves `dep-pkg` as [`mount_wrapper_with_npm_dependency`] does, the
/// wrapper's `releases`, and [`ANCHOR`], then installs the project.
pub async fn install_wrapper_beside_an_anchor(
    project: &TempProject,
    mock: &MockRegistry,
    releases: &[WrapperManifest<'_>],
) -> WrapperFixture {
    let dependency = mount_dependency(mock).await;
    let anchor_tarball = make_tarball_from_pkg_json(
        serde_json::json!({
            "name": ANCHOR,
            "version": "1.0.0",
            "license": "MIT",
            "main": "index.js",
            "dependencies": { DEPENDENCY: "1.0.0" }
        }),
        &[],
    );
    let anchor = mock
        .mount_full_package_metadata_routes(
            ANCHOR,
            "1.0.0",
            &[(
                "1.0.0",
                serde_json::json!({ DEPENDENCY: "1.0.0" }),
                Some(anchor_tarball),
            )],
        )
        .await;
    let fixture = mount_wrapper_manifests(mock, releases).await;
    mock.with_batch_metadata(vec![dependency, anchor, fixture.metadata.clone()])
        .await;
    lpm_with_registry(project, &mock.url())
        .args(["install", "--no-security-summary", "--no-skills"])
        .assert()
        .success();
    fixture
}

/// Serves `dep-pkg` 1.0.0 and 1.0.1 (latest), and returns its metadata.
async fn mount_dependency(mock: &MockRegistry) -> serde_json::Value {
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
    mock.mount_full_package_metadata_routes(DEPENDENCY, "1.0.1", &dependency_versions)
        .await
}

/// Serves the wrapper's `releases`, the last of them latest.
async fn mount_wrapper_manifests(
    mock: &MockRegistry,
    releases: &[WrapperManifest<'_>],
) -> WrapperFixture {
    let wrapper_versions = releases
        .iter()
        .map(|release| {
            let mut manifest = serde_json::json!({
                "name": WRAPPER,
                "version": release.version,
                "license": "MIT",
                "main": "index.js"
            });
            if let (Some(manifest), Some(fields)) =
                (manifest.as_object_mut(), release.fields.as_object())
            {
                manifest.extend(fields.clone());
            }
            let tarball = make_tarball_from_pkg_json(manifest, &[]);
            (release.version, release.fields.clone(), Some(tarball))
        })
        .collect::<Vec<_>>();
    let latest = releases
        .last()
        .expect("the wrapper needs a release")
        .version;
    let metadata = mock
        .mount_package_manifest_routes(WRAPPER, latest, &wrapper_versions)
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

/// Answers every OSV query: `advisories` for `dep-pkg` at `version`, none
/// for any other package or version.
pub async fn answer_osv_for_tree(
    mock: &MockRegistry,
    version: &str,
    advisories: Vec<serde_json::Value>,
) {
    let vulnerable = version.to_string();
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(move |request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let results = body["queries"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|query| {
                    let flagged = query["package"]["name"] == DEPENDENCY
                        && query["version"] == vulnerable.as_str();
                    serde_json::json!({
                        "vulns": if flagged { advisories.clone() } else { Vec::new() }
                    })
                })
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .mount(mock.server())
        .await;
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
