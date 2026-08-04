//! Workflow coverage for managed Node selection and engines.node compatibility.

mod support;

use support::{TempProject, configure_fake_node, lpm};
use wiremock::MockServer;

fn node_version_project(engines: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name": "runtime-selection",
            "version": "1.0.0",
            "engines": {{"node": "{engines}"}},
            "scripts": {{"node-version": "node --version"}}
        }}"#
    ))
}

#[cfg(unix)]
fn install_fake_managed_node(project: &TempProject, version: &str) {
    use std::os::unix::fs::PermissionsExt;

    let binary = project
        .home()
        .join(".lpm/runtimes/node")
        .join(version)
        .join("bin/node");
    std::fs::create_dir_all(binary.parent().unwrap()).expect("create managed Node bin directory");
    std::fs::write(&binary, format!("#!/bin/sh\necho v{version}\n"))
        .expect("write managed Node binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("mark managed Node executable");
}

fn command_output_text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn run_uses_path_node_without_downloading_for_engines_constraint() {
    let server = MockServer::start().await;
    let project = node_version_project(">=18");
    let runtimes_dir = project.home().join(".lpm/runtimes");
    std::fs::create_dir_all(&runtimes_dir).expect("create runtime cache directory");
    std::fs::write(
        runtimes_dir.join("index-cache.json"),
        serde_json::json!([{
            "version": "v18.0.0",
            "date": "2022-04-19",
            "lts": false,
            "dist_base_url": server.uri(),
        }])
        .to_string(),
    )
    .expect("write runtime index cache");

    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let output = command
        .env_remove("LPM_NO_AUTO_INSTALL")
        .args(["run", "node-version"])
        .output()
        .expect("run with engines.node compatibility constraint");
    let combined = command_output_text(&output);
    let requests = server
        .received_requests()
        .await
        .expect("read runtime download requests");

    assert!(output.status.success(), "run failed:\n{combined}");
    assert!(
        combined.contains("v22.0.0"),
        "PATH Node was not used:\n{combined}"
    );
    assert!(
        !combined.contains("Using Node.js 18.0.0")
            && !combined.contains("Auto-installed Node.js 18.0.0"),
        "engines.node selected a runtime:\n{combined}"
    );
    assert!(
        requests.is_empty(),
        "engines.node triggered a runtime download"
    );
}
#[cfg(unix)]
#[test]
fn run_prefers_path_node_over_compatible_installed_managed_runtime() {
    let project = node_version_project(">=18");
    install_fake_managed_node(&project, "18.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");

    let output = command
        .args(["run", "node-version"])
        .output()
        .expect("run with PATH and managed Node runtimes");
    let combined = command_output_text(&output);

    assert!(output.status.success(), "run failed:\n{combined}");
    assert!(
        combined.contains("v20.0.0"),
        "PATH Node was not retained:\n{combined}"
    );
    assert!(
        !combined.contains("v18.0.0"),
        "managed Node replaced PATH Node:\n{combined}"
    );
}

#[test]
fn run_rejects_incompatible_path_node_without_installing_from_engines() {
    let project = node_version_project(">=18");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "16.0.0");

    let output = command
        .env("LPM_NO_AUTO_INSTALL", "1")
        .args(["run", "node-version"])
        .output()
        .expect("run with incompatible PATH Node");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "engine mismatch did not fail:\n{combined}"
    );
    assert!(
        combined.contains(">=18"),
        "constraint missing from diagnostic:\n{combined}"
    );
    assert!(
        combined.contains("16.0.0"),
        "PATH Node missing from diagnostic:\n{combined}"
    );
    assert!(
        !combined.contains("Auto-installed Node.js"),
        "engine mismatch installed a runtime:\n{combined}"
    );
}

#[test]
fn run_warns_for_incompatible_path_node_when_engine_strict_is_disabled() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-selection-soft-engine",
            "version": "1.0.0",
            "engines": {"node": ">=18"},
            "lpm": {"engineStrict": false},
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "16.0.0");

    let output = command
        .env("LPM_NO_AUTO_INSTALL", "1")
        .args(["run", "node-version"])
        .output()
        .expect("run with soft engine mismatch");
    let combined = command_output_text(&output);

    assert!(
        output.status.success(),
        "soft engine policy failed the run:\n{combined}"
    );
    assert!(
        combined.contains("v16.0.0"),
        "PATH Node was not retained:\n{combined}"
    );
    assert!(
        combined.contains("engine-strict disabled"),
        "soft engine mismatch warning missing:\n{combined}"
    );
    assert!(
        !combined.contains("Auto-installed Node.js"),
        "soft engine mismatch installed a runtime:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn run_lpm_json_selector_overrides_path_and_is_validated_against_engines() {
    let project = node_version_project(">=22");
    project.write_file("lpm.json", r#"{"runtime":{"node":"22"}}"#);
    install_fake_managed_node(&project, "22.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");

    let output = command
        .args(["run", "node-version"])
        .output()
        .expect("run with lpm.json runtime selector");
    let combined = command_output_text(&output);

    assert!(
        output.status.success(),
        "selected Node failed validation:\n{combined}"
    );
    assert!(
        combined.contains("v22.0.0"),
        "managed Node 22 was not selected:\n{combined}"
    );
    assert!(
        combined.contains("lpm.json > runtime.node"),
        "selector source missing from diagnostic:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn run_nvmrc_selector_overrides_newer_path_node() {
    let project = node_version_project(">=18");
    project.write_file(".nvmrc", "20.19.0\n");
    install_fake_managed_node(&project, "20.19.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "node-version"])
        .output()
        .expect("run with .nvmrc runtime selector");
    let combined = command_output_text(&output);

    assert!(output.status.success(), "run failed:\n{combined}");
    assert!(
        combined.contains("v20.19.0"),
        ".nvmrc Node was not selected:\n{combined}"
    );
    assert!(
        combined.contains("from .nvmrc"),
        "selector source missing:\n{combined}"
    );
}

#[test]
fn run_ci_matrix_retains_each_path_node_for_engines_constraint() {
    for version in ["20.0.0", "22.0.0", "24.0.0"] {
        let project = node_version_project(">=18");
        let mut command = lpm(&project);
        configure_fake_node(&mut command, &project, version);

        let output = command
            .env("CI", "true")
            .env("LPM_NO_AUTO_INSTALL", "1")
            .args(["run", "node-version"])
            .output()
            .expect("run CI matrix job");
        let combined = command_output_text(&output);

        assert!(
            output.status.success(),
            "Node {version} job failed:\n{combined}"
        );
        assert!(
            combined.contains(&format!("v{version}")),
            "Node {version} was replaced:\n{combined}"
        );
        assert!(
            !combined.contains("package.json engines")
                && !combined.contains("Auto-installed Node.js")
                && !combined.contains("Using Node.js"),
            "Node {version} job treated engines.node as a selector:\n{combined}"
        );
    }
}

#[test]
fn run_without_path_node_reports_engine_constraint_and_explicit_selector_hint() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-selection-missing-node",
            "version": "1.0.0",
            "engines": {"node": ">=18"},
            "scripts": {"probe": "echo should-not-run"}
        }"#,
    );
    let empty_path = project.home().join("empty-path");
    std::fs::create_dir_all(&empty_path).expect("create empty PATH directory");

    let output = lpm(&project)
        .env("PATH", &empty_path)
        .env("LPM_NO_AUTO_INSTALL", "1")
        .args(["run", "probe"])
        .output()
        .expect("run without Node on PATH");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "missing Node did not fail:\n{combined}"
    );
    assert!(
        combined.contains("package.json > engines.node") && combined.contains(">=18"),
        "engine constraint source missing:\n{combined}"
    );
    assert!(
        combined.contains("lpm use node@22"),
        "explicit selector hint missing:\n{combined}"
    );
    assert!(
        !combined.contains("should-not-run"),
        "script ran without Node:\n{combined}"
    );
}

#[test]
fn run_no_auto_install_only_blocks_explicit_runtime_selector_installation() {
    let project = node_version_project(">=18");
    project.write_file("lpm.json", r#"{"runtime":{"node":"20.19.0"}}"#);
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .env("LPM_NO_AUTO_INSTALL", "1")
        .args(["run", "node-version"])
        .output()
        .expect("run with auto-install disabled");
    let combined = command_output_text(&output);

    assert!(output.status.success(), "run failed:\n{combined}");
    assert!(
        combined.contains("v22.0.0"),
        "PATH Node was not used:\n{combined}"
    );
    assert!(
        combined.contains("lpm.json > runtime.node") && combined.contains("20.19.0"),
        "explicit selector warning missing:\n{combined}"
    );
    assert!(
        !combined.contains("package.json engines"),
        "engines.node entered the auto-install path:\n{combined}"
    );
}
