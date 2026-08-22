//! Workflow tests for `lpm sbom`.

mod support;

use support::{
    TempProject, installed_manifest_dependency_graph, lpm, workspace_projection_project,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct RecordDelayedSbomMetadataStart {
    starts: std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    delay: std::time::Duration,
}

impl Respond for RecordDelayedSbomMetadataStart {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.starts
            .lock()
            .expect("record SBOM metadata request start")
            .push(std::time::Instant::now());
        let name = request
            .url
            .path()
            .strip_prefix("/api/registry/")
            .unwrap_or_default();
        ResponseTemplate::new(200)
            .set_delay(self.delay)
            .set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": { "name": name, "version": "1.0.0" }
                }
            }))
    }
}

#[tokio::test]
async fn sbom_resolves_hoisted_and_isolated_transitives_with_distinct_versions() {
    for linker in ["hoisted", "isolated"] {
        let project = installed_manifest_dependency_graph(linker).await;
        let output = lpm(&project)
            .args(["sbom", "--json"])
            .output()
            .expect("run SBOM against installed linker graph");
        assert!(
            output.status.success(),
            "{linker} SBOM must resolve transitive manifests:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("SBOM stdout must be valid JSON");
        let components = document["components"]
            .as_array()
            .expect("CycloneDX components must be an array");
        assert_eq!(
            component_license(components, "multi-license", "1.0.0"),
            Some("Apache-2.0")
        );
        assert_eq!(
            component_license(components, "multi-license", "2.0.0"),
            Some("BSD-3-Clause")
        );
        assert!(
            components.iter().all(|component| {
                component["name"] != "platform-only-leaf"
                    && component["name"] != "optional-platform-runtime"
            }),
            "platform-skipped optional packages must not be emitted in the installed SBOM"
        );
    }
}

fn component_license<'a>(
    components: &'a [serde_json::Value],
    name: &str,
    version: &str,
) -> Option<&'a str> {
    let license = components
        .iter()
        .find(|component| component["name"] == name && component["version"] == version)?
        .get("licenses")?
        .as_array()?
        .first()?
        .get("license")?;
    license.get("id").or_else(|| license.get("name"))?.as_str()
}

fn patch_sha256(project: &TempProject, rel_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(project.path().join(rel_path)).unwrap();
    format!("sha256-{}", hex::encode(Sha256::digest(bytes)))
}

fn seed_lockfile(project: &TempProject) {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some(support::VALID_TEST_INTEGRITY.to_string()),
        tarball: Some("https://registry.npmjs.org/ansi-regex/-/ansi-regex-5.0.1.tgz".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some(support::VALID_TEST_INTEGRITY.to_string()),
        dependencies: vec!["ansi-regex@5.0.1".to_string()],
        tarball: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".to_string()),
        ..Default::default()
    });
    lockfile.patches.insert(
        "left-pad@1.3.0".to_string(),
        lpm_lockfile::LockfilePatch {
            path: "patches/left-pad@1.3.0.patch".to_string(),
            sha256: patch_sha256(project, "patches/left-pad@1.3.0.patch"),
            original_integrity: "sha512-leftpad-original".to_string(),
        },
    );
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[("left-pad", "left-pad", "1.3.0")]);
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("failed to write lpm.lock");
}

fn seed_project() -> TempProject {
    let project = TempProject::empty(
        r#"{
        "name": "sbom-app",
        "version": "1.0.0",
        "license": "MIT",
        "dependencies": {
            "left-pad": "^1.3.0"
        },
        "lpm": {
            "patchedDependencies": {
                "left-pad@1.3.0": {
                    "path": "patches/left-pad@1.3.0.patch",
                    "originalIntegrity": "sha512-leftpad-original"
                }
            }
        }
    }"#,
    );
    project.write_file(
        "patches/left-pad@1.3.0.patch",
        "diff --git a/index.js b/index.js\n",
    );
    seed_lockfile(&project);
    project.write_file(
        "node_modules/left-pad/package.json",
        r#"{
            "name": "left-pad",
            "version": "1.3.0",
            "description": "left pad test fixture",
            "license": "WTFPL",
            "homepage": "https://example.test/left-pad",
            "repository": { "url": "git+https://example.test/left-pad.git" },
            "author": { "name": "Fixture Author" }
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

fn contextual_sbom_project() -> TempProject {
    const SOURCE: &str = "registry+https://registry.npmjs.org";

    let project = TempProject::empty(
        r#"{
            "name": "contextual-sbom",
            "version": "1.0.0",
            "dependencies": {
                "parent-a": "1.0.0",
                "parent-b": "1.0.0"
            }
        }"#,
    );
    let shared_a = lpm_common::PackageInstanceId::derive("shared", "1.0.0", SOURCE, "a");
    let shared_b = lpm_common::PackageInstanceId::derive("shared", "1.0.0", SOURCE, "b");
    let parent_a = lpm_common::PackageInstanceId::derive("parent-a", "1.0.0", SOURCE, "root-a");
    let parent_b = lpm_common::PackageInstanceId::derive("parent-b", "1.0.0", SOURCE, "root-b");

    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(parent_a),
        name: "parent-a".to_string(),
        version: "1.0.0".to_string(),
        source: Some(SOURCE.to_string()),
        dependencies: vec!["shared@1.0.0".to_string()],
        dependency_targets: [("shared".to_string(), shared_a)].into(),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        instance_id: Some(parent_b),
        name: "parent-b".to_string(),
        version: "1.0.0".to_string(),
        source: Some(SOURCE.to_string()),
        dependencies: vec!["shared@1.0.0".to_string()],
        dependency_targets: [("shared".to_string(), shared_b)].into(),
        ..Default::default()
    });
    for instance_id in [shared_a, shared_b] {
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: "shared".to_string(),
            version: "1.0.0".to_string(),
            source: Some(SOURCE.to_string()),
            ..Default::default()
        });
    }
    for (local_name, package, instance_id) in [
        ("parent-a", "parent-a", parent_a),
        ("parent-b", "parent-b", parent_b),
    ] {
        lockfile.root_resolutions.insert(
            local_name.to_string(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: package.to_string(),
                version: "1.0.0".to_string(),
                source: Some(SOURCE.to_string()),
            },
        );
    }
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write contextual SBOM lockfile");
    for name in ["parent-a", "parent-b", "shared"] {
        project.write_file(
            &format!("node_modules/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    project
}

fn component_reference(document: &serde_json::Value, name: &str) -> String {
    document["components"]
        .as_array()
        .expect("CycloneDX components")
        .iter()
        .find(|component| component["name"] == name)
        .and_then(|component| component["bom-ref"].as_str())
        .unwrap_or_else(|| panic!("missing component reference for {name}"))
        .to_string()
}

fn dependency_targets(document: &serde_json::Value, reference: &str) -> Vec<String> {
    document["dependencies"]
        .as_array()
        .expect("CycloneDX dependencies")
        .iter()
        .find(|dependency| dependency["ref"] == reference)
        .and_then(|dependency| dependency["dependsOn"].as_array())
        .unwrap_or_else(|| panic!("missing dependency entry for {reference}"))
        .iter()
        .map(|target| {
            target
                .as_str()
                .expect("dependency target string")
                .to_string()
        })
        .collect()
}

#[test]
fn sbom_cyclonedx_preserves_contextual_instances_and_exact_edges() {
    let project = contextual_sbom_project();

    let output = lpm(&project).args(["sbom"]).output().expect("run SBOM");
    assert!(
        output.status.success(),
        "contextual CycloneDX generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CycloneDX JSON");
    let shared_refs = document["components"]
        .as_array()
        .expect("CycloneDX components")
        .iter()
        .filter(|component| component["name"] == "shared")
        .map(|component| {
            component["bom-ref"]
                .as_str()
                .expect("shared bom-ref")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let parent_a = component_reference(&document, "parent-a");
    let parent_b = component_reference(&document, "parent-b");
    let parent_a_targets = dependency_targets(&document, &parent_a);
    let parent_b_targets = dependency_targets(&document, &parent_b);

    assert_eq!(
        shared_refs.len(),
        2,
        "contextual instances need unique bom-ref values"
    );
    assert_eq!(parent_a_targets.len(), 1);
    assert_eq!(parent_b_targets.len(), 1);
    assert_ne!(
        parent_a_targets, parent_b_targets,
        "each parent must retain its exact contextual target"
    );
}

#[test]
fn sbom_spdx_preserves_contextual_package_ids_and_exact_edges() {
    let project = contextual_sbom_project();

    let output = lpm(&project)
        .args(["sbom", "--format", "spdx"])
        .output()
        .expect("run SPDX SBOM");
    assert!(
        output.status.success(),
        "contextual SPDX generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).expect("SPDX JSON");
    let shared_ids = document["packages"]
        .as_array()
        .expect("SPDX packages")
        .iter()
        .filter(|package| package["name"] == "shared")
        .map(|package| {
            package["SPDXID"]
                .as_str()
                .expect("shared SPDXID")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let parent_edges = document["relationships"]
        .as_array()
        .expect("SPDX relationships")
        .iter()
        .filter(|relationship| relationship["relationshipType"] == "DEPENDS_ON")
        .filter_map(|relationship| {
            let source = relationship["spdxElementId"].as_str()?;
            let target = relationship["relatedSpdxElement"].as_str()?;
            source.contains("parent-").then(|| target.to_string())
        })
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        shared_ids.len(),
        2,
        "contextual instances need unique SPDX IDs"
    );
    assert_eq!(
        parent_edges.len(),
        2,
        "each parent must retain its exact contextual SPDX target"
    );
}

#[test]
fn sbom_propagates_optional_and_development_scopes_to_transitive_dependencies() {
    const SOURCE: &str = "registry+https://registry.npmjs.org";

    let project = TempProject::empty(
        r#"{
            "name": "scope-sbom",
            "version": "1.0.0",
            "optionalDependencies": { "optional-root": "1.0.0" },
            "devDependencies": { "dev-root": "1.0.0" }
        }"#,
    );
    let mut lockfile = lpm_lockfile::Lockfile::new();
    for (index, (name, dependency)) in [
        ("optional-root", Some("optional-child")),
        ("optional-child", None),
        ("dev-root", Some("dev-child")),
        ("dev-child", None),
    ]
    .into_iter()
    .enumerate()
    {
        let instance_id =
            lpm_common::PackageInstanceId::derive(name, "1.0.0", SOURCE, &format!("scope/{index}"));
        let dependency_targets = dependency
            .map(|target| {
                let target_index = if target == "optional-child" { 1 } else { 3 };
                [(
                    target.to_string(),
                    lpm_common::PackageInstanceId::derive(
                        target,
                        "1.0.0",
                        SOURCE,
                        &format!("scope/{target_index}"),
                    ),
                )]
                .into()
            })
            .unwrap_or_default();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source: Some(SOURCE.to_string()),
            dependencies: dependency
                .map(|target| vec![format!("{target}@1.0.0")])
                .unwrap_or_default(),
            dependency_targets,
            ..Default::default()
        });
        if matches!(name, "optional-root" | "dev-root") {
            lockfile.root_resolutions.insert(
                name.to_string(),
                lpm_lockfile::LockedRootResolution {
                    instance_id: Some(instance_id),
                    package: name.to_string(),
                    version: "1.0.0".to_string(),
                    source: Some(SOURCE.to_string()),
                },
            );
        }
        project.write_file(
            &format!("node_modules/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write scope SBOM lockfile");

    let output = lpm(&project).args(["sbom"]).output().expect("run SBOM");
    assert!(
        output.status.success(),
        "scope CycloneDX generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CycloneDX JSON");
    let scope = |name: &str| {
        document["components"]
            .as_array()
            .expect("CycloneDX components")
            .iter()
            .find(|component| component["name"] == name)
            .and_then(|component| component["scope"].as_str())
            .unwrap_or_else(|| panic!("missing scope for {name}"))
    };

    assert_eq!(scope("optional-child"), "optional");
    assert_eq!(scope("dev-child"), "excluded");
}

#[tokio::test]
async fn sbom_registry_metadata_rejects_a_response_that_omits_the_locked_version() {
    const PACKAGE: &str = "@lpm.dev/sbom.metadata";
    const SOURCE: &str = "registry+https://lpm.dev";

    let project = TempProject::empty(&format!(
        r#"{{"name":"registry-sbom","version":"1.0.0","dependencies":{{"{PACKAGE}":"1.0.0"}}}}"#
    ));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: PACKAGE.to_string(),
        version: "1.0.0".to_string(),
        source: Some(SOURCE.to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(PACKAGE, PACKAGE, "1.0.0")]);
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write registry SBOM lockfile");
    project.write_file(
        "node_modules/@lpm.dev/sbom.metadata/package.json",
        &format!(r#"{{"name":"{PACKAGE}","version":"1.0.0"}}"#),
    );
    let registry = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/sbom.metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": PACKAGE,
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "2.0.0": {"name": PACKAGE, "version": "2.0.0"}
            }
        })))
        .mount(registry.server())
        .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &registry.url(),
            "--insecure",
            "sbom",
            "--registry-metadata",
        ])
        .output()
        .expect("run registry-enriched SBOM");

    assert!(
        !output.status.success(),
        "explicit registry enrichment must fail when locked metadata is absent"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not include locked version 1.0.0"),
        "missing-version failure must identify the locked version: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn sbom_registry_metadata_propagates_fetch_failures() {
    const PACKAGE: &str = "@lpm.dev/sbom.fetch-failure";
    const SOURCE: &str = "registry+https://lpm.dev";

    let project = TempProject::empty(&format!(
        r#"{{"name":"registry-sbom","version":"1.0.0","dependencies":{{"{PACKAGE}":"1.0.0"}}}}"#
    ));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: PACKAGE.to_string(),
        version: "1.0.0".to_string(),
        source: Some(SOURCE.to_string()),
        ..Default::default()
    });
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(PACKAGE, PACKAGE, "1.0.0")]);
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write registry SBOM lockfile");
    project.write_file(
        "node_modules/@lpm.dev/sbom.fetch-failure/package.json",
        &format!(r#"{{"name":"{PACKAGE}","version":"1.0.0"}}"#),
    );
    let registry = support::mock_registry::MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/sbom.fetch-failure"))
        .respond_with(ResponseTemplate::new(503))
        .mount(registry.server())
        .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &registry.url(),
            "--insecure",
            "sbom",
            "--registry-metadata",
        ])
        .output()
        .expect("run registry-enriched SBOM");

    assert!(
        !output.status.success(),
        "explicit registry enrichment must propagate registry failures"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to fetch registry metadata"),
        "registry failure must retain enrichment context: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn sbom_fetches_independent_registry_metadata_concurrently() {
    const SOURCE: &str = "registry+https://lpm.dev";
    const PACKAGE_COUNT: usize = 8;

    let dependencies = (0..PACKAGE_COUNT)
        .map(|index| format!(r#""@lpm.dev/sbom.concurrent-{index}":"1.0.0""#))
        .collect::<Vec<_>>()
        .join(",");
    let project = TempProject::empty(&format!(
        r#"{{"name":"concurrent-sbom","version":"1.0.0","dependencies":{{{dependencies}}}}}"#
    ));
    let mut lockfile = lpm_lockfile::Lockfile::new();
    for index in 0..PACKAGE_COUNT {
        let name = format!("@lpm.dev/sbom.concurrent-{index}");
        let instance_id =
            lpm_common::PackageInstanceId::derive(&name, "1.0.0", SOURCE, "sbom/root");
        lockfile.add_package(lpm_lockfile::LockedPackage {
            instance_id: Some(instance_id),
            name: name.clone(),
            version: "1.0.0".to_string(),
            source: Some(SOURCE.to_string()),
            ..Default::default()
        });
        lockfile.root_resolutions.insert(
            name.clone(),
            lpm_lockfile::LockedRootResolution {
                instance_id: Some(instance_id),
                package: name.clone(),
                version: "1.0.0".to_string(),
                source: Some(SOURCE.to_string()),
            },
        );
        project.write_file(
            &format!("node_modules/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    lockfile
        .write_to_file(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write concurrent SBOM lockfile");

    let registry = support::mock_registry::MockRegistry::start().await;
    let starts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/api/registry/@lpm\.dev/sbom\.concurrent-[0-7]$",
        ))
        .respond_with(RecordDelayedSbomMetadataStart {
            starts: starts.clone(),
            delay: std::time::Duration::from_millis(200),
        })
        .mount(registry.server())
        .await;

    let output = lpm(&project)
        .args([
            "--registry",
            &registry.url(),
            "--insecure",
            "sbom",
            "--registry-metadata",
        ])
        .output()
        .expect("run registry-enriched SBOM");
    assert!(
        output.status.success(),
        "concurrent SBOM enrichment failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let starts = starts.lock().expect("read SBOM request starts");
    assert_eq!(starts.len(), PACKAGE_COUNT);
    let spread = starts
        .iter()
        .max()
        .expect("latest request")
        .duration_since(*starts.iter().min().expect("earliest request"));
    assert!(
        spread < std::time::Duration::from_millis(400),
        "independent metadata requests started too far apart: {spread:?}"
    );
}

#[cfg(unix)]
#[test]
fn sbom_output_rejects_a_final_symlink_without_overwriting_its_target() {
    use std::os::unix::fs::symlink;

    let project = seed_project();
    let outside = tempfile::tempdir().expect("create external SBOM directory");
    let sentinel = outside.path().join("sentinel.json");
    std::fs::write(&sentinel, "sentinel").expect("write external sentinel");
    symlink(&sentinel, project.path().join("bom.json")).expect("link SBOM output");

    let output = lpm(&project)
        .args(["sbom", "--output", "bom.json"])
        .output()
        .expect("run SBOM with linked output");

    assert!(
        !output.status.success(),
        "linked SBOM output must be rejected"
    );
    assert_eq!(
        std::fs::read_to_string(sentinel).expect("read external sentinel"),
        "sentinel"
    );
}

#[cfg(unix)]
#[test]
fn sbom_output_rejects_a_symlinked_parent_without_writing_outside_the_project() {
    use std::os::unix::fs::symlink;

    let project = seed_project();
    let outside = tempfile::tempdir().expect("create external SBOM directory");
    symlink(outside.path(), project.path().join("reports")).expect("link SBOM output parent");

    let output = lpm(&project)
        .args(["sbom", "--output", "reports/bom.json"])
        .output()
        .expect("run SBOM with linked output parent");

    assert!(
        !output.status.success(),
        "linked SBOM output parent must be rejected"
    );
    assert!(
        !outside.path().join("bom.json").exists(),
        "SBOM must not be written through a linked parent"
    );
}

#[test]
fn sbom_from_workspace_member_excludes_sibling_lockfile_projection() {
    let project = workspace_projection_project();
    let mut command = lpm(&project);
    command.current_dir(project.path().join("packages/app"));
    let output = command.args(["sbom"]).output().expect("run member SBOM");

    assert!(
        output.status.success(),
        "member SBOM must succeed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SBOM stdout must be valid JSON");
    let components = document["components"]
        .as_array()
        .expect("CycloneDX components must be an array");
    assert!(
        components
            .iter()
            .any(|component| component["name"] == "app-only")
    );
    assert!(
        !components
            .iter()
            .any(|component| component["name"] == "sibling-only")
    );
}

#[test]
fn sbom_cyclonedx_includes_lockfile_graph_patch_and_local_metadata() {
    let project = seed_project();

    let output = lpm(&project)
        .args(["sbom"])
        .output()
        .expect("failed to run lpm sbom");

    assert!(
        output.status.success(),
        "lpm sbom failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("sbom stdout must be valid JSON");
    assert_eq!(envelope["bomFormat"], "CycloneDX");
    assert_eq!(envelope["specVersion"], "1.7");
    envelope["metadata"]["tools"]["components"][0]["version"] = "[VERSION]".into();

    let components = envelope["components"]
        .as_array()
        .expect("components must be an array");
    let left_pad = components
        .iter()
        .find(|component| component["name"] == "left-pad")
        .expect("left-pad component must be present");
    assert_eq!(left_pad["description"], "left pad test fixture");
    assert_eq!(
        left_pad["pedigree"]["patches"][0]["type"],
        serde_json::json!("unofficial")
    );
    assert_eq!(
        left_pad["pedigree"]["patches"][0]["diff"]["url"],
        serde_json::json!("patches/left-pad@1.3.0.patch")
    );
    assert!(
        left_pad["properties"]
            .as_array()
            .expect("left-pad properties must be an array")
            .iter()
            .any(|property| {
                property["name"] == "lpm:patch:path"
                    && property["value"] == "patches/left-pad@1.3.0.patch"
            }),
        "left-pad component must include patch metadata: {left_pad:#?}"
    );
    let expected_sha = patch_sha256(&project, "patches/left-pad@1.3.0.patch");
    assert!(
        left_pad["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| {
                property["name"] == "lpm:patch:sha256" && property["value"] == expected_sha
            }),
        "left-pad component must include lockfile patch checksum: {left_pad:#?}"
    );

    insta::assert_json_snapshot!("sbom_cyclonedx_lockfile_graph", envelope, {
        ".metadata.timestamp" => "[TIMESTAMP]",
    });
}

#[test]
fn sbom_spdx_includes_lockfile_relationships() {
    let project = seed_project();

    let output = lpm(&project)
        .args(["sbom", "--format", "spdx"])
        .output()
        .expect("failed to run lpm sbom --format spdx");

    assert!(
        output.status.success(),
        "lpm sbom --format spdx failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("spdx stdout must be valid JSON");
    assert_eq!(envelope["spdxVersion"], "SPDX-2.3");
    envelope["creationInfo"]["creators"][0] = "[TOOL]".into();
    assert!(
        envelope["relationships"]
            .as_array()
            .expect("relationships must be an array")
            .iter()
            .any(|relationship| relationship["relationshipType"] == "DEPENDS_ON"),
        "SPDX output must include dependency relationships"
    );

    insta::assert_json_snapshot!("sbom_spdx_lockfile_relationships", envelope, {
        ".creationInfo.created" => "[TIMESTAMP]",
    });
}

#[test]
fn sbom_uses_verified_lockfile_provenance_when_cache_is_empty() {
    const PACKAGE: &str = "locked-provenance-pkg";
    const VERSION: &str = "1.0.0";
    const INTEGRITY: &str = "sha512-3Y8yrqLSwjuzpXuZ0oIYZ/XGgLwUIBU3uLvbcpb0pidD9ctpShJd43KSlEEkVQg6DS0G9NKyzOvBfUtDKEyHvQ==";

    let project = TempProject::empty(&format!(
        r#"{{
            "name": "sbom-locked-provenance-test",
            "version": "1.0.0",
            "dependencies": {{ "{PACKAGE}": "{VERSION}" }}
        }}"#
    ));
    let package = lpm_lockfile::LockedPackage {
        instance_id: None,
        dependency_targets: std::collections::BTreeMap::new(),
        peer_targets: std::collections::BTreeMap::new(),
        name: PACKAGE.to_string(),
        version: VERSION.to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some(INTEGRITY.to_string()),
        ..Default::default()
    };
    let integrity = lpm_common::Integrity::parse(INTEGRITY).expect("valid fixture integrity");
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(package.clone());
    support::finalize_exact_lockfile_fixture(&mut lockfile, &[(PACKAGE, PACKAGE, VERSION)]);
    lockfile.set_verified_provenance(
        &package.package_key(),
        lpm_lockfile::LockedProvenance {
            snapshot: lpm_common::ProvenanceSnapshot {
                present: true,
                publisher: Some("github:example/locked-provenance-pkg".to_string()),
                workflow_path: Some(".github/workflows/publish.yml".to_string()),
                workflow_ref: Some("refs/tags/v1.0.0".to_string()),
                attestation_cert_sha256: Some(format!("sha256-{}", "11".repeat(32))),
            },
            subject_name: lpm_common::npm_package_purl(PACKAGE, VERSION),
            subject_sha512: hex::encode(integrity.hash),
            integrated_time_secs: 1_700_000_000,
            log_id: "rekor-test-log".to_string(),
            log_index: 42,
            bundle_sha256: format!("sha256-{}", "22".repeat(32)),
        },
    );
    lockfile
        .write_all(&project.path().join(lpm_lockfile::LOCKFILE_NAME))
        .expect("write lockfile with provenance");
    project.write_file(
        &format!("node_modules/{PACKAGE}/package.json"),
        &format!(
            r#"{{
                "name": "{PACKAGE}",
                "version": "{VERSION}"
            }}"#
        ),
    );
    assert!(
        !project.cache_dir().join("metadata/attestations").exists(),
        "test must start with a cold provenance cache"
    );

    let output = lpm(&project).args(["sbom"]).output().expect("run lpm sbom");
    assert!(
        output.status.success(),
        "lpm sbom failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("sbom stdout must be valid JSON");
    let component = envelope["components"]
        .as_array()
        .expect("components array")
        .iter()
        .find(|component| component["name"] == PACKAGE)
        .expect("locked package component");
    let properties = component["properties"]
        .as_array()
        .expect("provenance properties");
    assert!(
        properties.iter().any(|property| {
            property["name"] == "lpm:provenance:status" && property["value"] == "verified"
        }),
        "locked verified status must enrich the component: {component:#?}"
    );
    assert!(
        properties.iter().any(|property| {
            property["name"] == "lpm:provenance:publisher"
                && property["value"] == "github:example/locked-provenance-pkg"
        }),
        "locked publisher identity must enrich the component: {component:#?}"
    );
}

#[test]
fn sbom_output_writes_file_without_stdout_payload() {
    let project = seed_project();

    let output = lpm(&project)
        .args(["sbom", "--output", "bom.json"])
        .output()
        .expect("failed to run lpm sbom --output bom.json");

    assert!(
        output.status.success(),
        "lpm sbom --output failed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stdout.is_empty(),
        "--output should not duplicate the SBOM JSON to stdout"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Generating CycloneDX SBOM from lpm.lock"),
        "sbom should show slim generation phase; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("packages") && stderr.contains("2"),
        "sbom should summarize package count; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("format") && stderr.contains("cyclonedx"),
        "sbom should summarize output format; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("output") && stderr.contains("bom.json"),
        "sbom should summarize output path; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Included patch metadata"),
        "sbom should report included metadata; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · wrote SBOM in"),
        "sbom should show elapsed write terminus; stderr:\n{stderr}"
    );

    let written: serde_json::Value =
        serde_json::from_str(&project.read_file("bom.json")).expect("bom.json must be valid JSON");
    assert_eq!(written["bomFormat"], "CycloneDX");
}
