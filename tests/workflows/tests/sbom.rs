//! Workflow tests for `lpm sbom`.

mod support;

use support::{
    TempProject, installed_manifest_dependency_graph, lpm, workspace_projection_project,
};

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
