//! Workflow tests for `lpm sbom`.

mod support;

use support::{TempProject, lpm};

fn seed_lockfile(project: &TempProject) {
    let mut lockfile = lpm_lockfile::Lockfile::new();
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "ansi-regex".to_string(),
        version: "5.0.1".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-ansi".to_string()),
        tarball: Some("https://registry.npmjs.org/ansi-regex/-/ansi-regex-5.0.1.tgz".to_string()),
        ..Default::default()
    });
    lockfile.add_package(lpm_lockfile::LockedPackage {
        name: "left-pad".to_string(),
        version: "1.3.0".to_string(),
        source: Some("registry+https://registry.npmjs.org".to_string()),
        integrity: Some("sha512-leftpad".to_string()),
        dependencies: vec!["ansi-regex@5.0.1".to_string()],
        tarball: Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".to_string()),
        ..Default::default()
    });
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
    project.write_file(
        "patches/left-pad@1.3.0.patch",
        "diff --git a/index.js b/index.js\n",
    );
    project
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
