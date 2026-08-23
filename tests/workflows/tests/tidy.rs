//! Workflow tests for `lpm tidy`.

mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm, lpm_with_registry};

const REPORT_PACKAGE_JSON: &str = r#"{
  "name": "tidy-report",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc -p tsconfig.json"
  },
  "dependencies": {
    "lodash": "^4.17.21",
    "react": "^18.2.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0"
  }
}"#;

fn write_report_sources(project: &TempProject) {
    project.write_file(
        "src/index.js",
        r#"import React from "react";
import leftPad from "left-pad";
console.log(React, leftPad);
"#,
    );
}

fn manifest(project: &TempProject) -> serde_json::Value {
    serde_json::from_str(&project.read_file("package.json")).expect("package.json parses")
}

async fn mount_basic_packages(mock: &MockRegistry) {
    for (name, version) in [("react", "18.2.0"), ("lodash", "4.17.21")] {
        mock.with_package(name, version, &make_tarball(name, version))
            .await;
    }
}

#[test]
fn tidy_reports_unused_and_phantom_without_mutating_manifest() {
    let project = TempProject::empty(REPORT_PACKAGE_JSON);
    write_report_sources(&project);
    let before = project.read_file("package.json");

    let output = lpm(&project)
        .args(["tidy"])
        .output()
        .expect("failed to run lpm tidy");

    assert_eq!(
        output.status.code(),
        Some(1),
        "tidy must exit 1 when findings remain\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("package.json"),
        before,
        "report-only tidy must not rewrite package.json"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lodash") && stderr.contains("unused"),
        "stderr must report unused lodash dependency:\n{stderr}"
    );
    assert!(
        stderr.contains("left-pad") && stderr.contains("phantom"),
        "stderr must report phantom left-pad import:\n{stderr}"
    );
    assert!(
        !stderr.contains("typescript"),
        "script-used TypeScript must not be reported unused:\n{stderr}"
    );
}

#[test]
fn tidy_json_envelope_reports_unused_and_phantom_findings() {
    let project = TempProject::empty(REPORT_PACKAGE_JSON);
    write_report_sources(&project);

    let output = lpm(&project)
        .args(["tidy", "--json"])
        .output()
        .expect("failed to run lpm tidy --json");
    assert_eq!(
        output.status.code(),
        Some(1),
        "tidy --json must exit 1 when findings remain\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("tidy --json must be valid JSON");
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["counts"]["unused"], serde_json::json!(1));
    assert_eq!(envelope["counts"]["phantoms"], serde_json::json!(1));

    insta::with_settings!({
        filters => vec![
            (r#""elapsed_ms": \d+"#, r#""elapsed_ms": "[ELAPSED]""#),
        ],
    }, {
        insta::assert_json_snapshot!("tidy_json_envelope_reports_unused_and_phantom_findings", envelope);
    });
}

#[test]
fn tidy_recognizes_multiline_and_repeated_same_line_imports() {
    let project = TempProject::empty(
        r#"{
  "name": "tidy-import-shapes",
  "version": "1.0.0",
  "dependencies": {
    "multiline-package": "1.0.0",
    "first-package": "1.0.0",
    "second-package": "1.0.0"
  }
}"#,
    );
    project.write_file(
        "src/index.js",
        r#"import {
  value
} from "multiline-package";
import "first-package"; import "second-package";
console.log(value);
"#,
    );

    let output = lpm(&project)
        .args(["tidy", "--json"])
        .output()
        .expect("failed to run lpm tidy --json");

    assert!(
        output.status.success(),
        "every imported dependency must be retained\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tidy_ignores_import_syntax_inside_comments_and_strings() {
    let project = TempProject::empty(
        r#"{
  "name": "tidy-comment-imports",
  "version": "1.0.0"
}"#,
    );
    project.write_file(
        "src/index.js",
        r#"const value = 1; // require("line-comment-package")
const text = "import('string-package')";
/* import "block-comment-package"; */
console.log(value, text);
"#,
    );

    let output = lpm(&project)
        .args(["tidy", "--json"])
        .output()
        .expect("failed to run lpm tidy --json");

    assert!(
        output.status.success(),
        "comments and strings must not create phantom dependencies\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn tidy_fix_preserves_manifest_when_a_source_file_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let project = TempProject::empty(
        r#"{
  "name": "tidy-unreadable-source",
  "version": "1.0.0",
  "dependencies": {
    "possibly-used": "1.0.0"
  }
}"#,
    );
    project.write_file("src/index.js", r#"import "possibly-used";"#);
    let source_path = project.path().join("src/index.js");
    let mut permissions = std::fs::metadata(&source_path).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&source_path, permissions).unwrap();
    let before = project.read_file("package.json");

    let output = lpm(&project)
        .args(["tidy", "--fix"])
        .output()
        .expect("failed to run lpm tidy --fix");

    assert!(
        !output.status.success(),
        "tidy --fix must fail closed when source evidence cannot be read"
    );
    assert_eq!(
        project.read_file("package.json"),
        before,
        "tidy --fix must not mutate the manifest after incomplete analysis"
    );
}

#[tokio::test]
async fn tidy_fix_removes_unused_dependency_and_reconciles_lockfile() {
    let mock = MockRegistry::start().await;
    mount_basic_packages(&mock).await;
    let project = TempProject::empty(
        r#"{
  "name": "tidy-fix",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "react": "^18.2.0"
  }
}"#,
    );
    project.write_file(
        "src/index.js",
        r#"import React from "react";
console.log(React);
"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .output()
        .expect("failed to seed install before tidy");
    assert!(
        install.status.success(),
        "seed install failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        project.read_file("lpm.lock").contains("lodash"),
        "seed lockfile must include lodash before tidy"
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["tidy", "--fix"])
        .output()
        .expect("failed to run lpm tidy --fix");
    assert!(
        output.status.success(),
        "tidy --fix failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let after = manifest(&project);
    assert!(after["dependencies"].get("lodash").is_none());
    assert_eq!(after["dependencies"]["react"], "^18.2.0");
    assert!(
        !project.read_file("lpm.lock").contains("lodash"),
        "tidy --fix must reconcile lpm.lock after pruning"
    );
    assert!(
        !project.path().join("node_modules").join("lodash").exists(),
        "tidy --fix must reconcile node_modules after pruning"
    );
}

#[tokio::test]
async fn workspace_member_tidy_fix_preserves_the_sibling_root_lockfile_projection() {
    let mock = MockRegistry::start().await;
    mount_basic_packages(&mock).await;
    mock.with_package(
        "sibling-pkg",
        "1.0.0",
        &make_tarball("sibling-pkg", "1.0.0"),
    )
    .await;
    let project = TempProject::empty(
        r#"{
  "name": "tidy-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"]
}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
  "name": "tidy-app",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "lodash": "^4.17.21",
    "react": "^18.2.0"
  }
}"#,
    );
    project.write_file(
        "packages/app/src/index.js",
        "import React from \"react\";\nconsole.log(React);\n",
    );
    project.write_file(
        "packages/sibling/package.json",
        r#"{"name":"tidy-sibling","version":"1.0.0","private":true,"dependencies":{"sibling-pkg":"1.0.0"}}"#,
    );

    let install = lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--recursive",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
            "--no-audit-after-install",
        ])
        .output()
        .expect("seed recursive workspace install before tidy");
    assert!(
        install.status.success(),
        "workspace seed install failed: stdout={} stderr={}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    let lockfile_path = project.path().join("lpm.lock");
    let before = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    let sibling_before = before.project_importer("packages/sibling").unwrap();
    let app_dir = project.path().join("packages/app");

    let output = lpm_with_registry(&project, &mock.url())
        .current_dir(&app_dir)
        .args(["tidy", "--fix"])
        .output()
        .expect("run tidy --fix from workspace member");
    assert!(
        output.status.success(),
        "workspace tidy --fix failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let updated = lpm_lockfile::Lockfile::read_fast(&lockfile_path).unwrap();
    let app_projection = updated.project_importer("packages/app").unwrap();
    assert!(app_projection.find_package("lodash").is_none());
    assert!(app_projection.find_package("react").is_some());
    assert_eq!(
        updated.project_importer("packages/sibling").unwrap(),
        sibling_before
    );
    assert!(!app_dir.join("lpm.lock").exists());
    assert!(!app_dir.join("lpm.lockb").exists());
}

#[test]
fn tidy_fix_reports_peer_dependencies_without_removing_them() {
    let project = TempProject::empty(
        r#"{
  "name": "tidy-peer",
  "version": "1.0.0",
  "peerDependencies": {
    "react": "^18.0.0"
  }
}"#,
    );
    project.write_file("src/index.js", "console.log('peer library');\n");

    let output = lpm(&project)
        .args(["tidy", "--fix"])
        .output()
        .expect("failed to run lpm tidy --fix");

    assert_eq!(
        output.status.code(),
        Some(1),
        "report-only peer finding must remain after --fix\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let after = manifest(&project);
    assert_eq!(after["peerDependencies"]["react"], "^18.0.0");
}

#[test]
fn tidy_lpm_toml_ignores_unused_and_phantom_packages() {
    let project = TempProject::empty(REPORT_PACKAGE_JSON);
    write_report_sources(&project);
    project.write_file(
        "lpm.toml",
        r#"[tidy]
ignore-unused = ["lodash"]
ignore-phantom = ["left-pad"]
"#,
    );

    let output = lpm(&project)
        .args(["tidy"])
        .output()
        .expect("failed to run lpm tidy");

    assert!(
        output.status.success(),
        "ignored tidy findings should exit cleanly\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
