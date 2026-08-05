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

#[cfg(unix)]
fn install_counting_fake_managed_node(project: &TempProject, version: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let binary = project
        .home()
        .join(".lpm/runtimes/node")
        .join(version)
        .join("bin/node");
    let counter = project.home().join("managed-node-version-probe-count");
    std::fs::create_dir_all(binary.parent().expect("managed Node has a parent"))
        .expect("create managed Node bin directory");
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\ncount=0\nif [ -f \"$LPM_NODE_PROBE_COUNT\" ]; then count=$(cat \"$LPM_NODE_PROBE_COUNT\"); fi\ncount=$((count + 1))\nprintf '%s\\n' \"$count\" > \"$LPM_NODE_PROBE_COUNT\"\necho v{version}\n"
        ),
    )
    .expect("write counting managed Node binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("mark managed Node executable");
    counter
}

fn install_fake_project_node(project: &TempProject, version: &str) {
    let binary = if cfg!(windows) {
        project.path().join("node_modules/.bin/node.cmd")
    } else {
        project.path().join("node_modules/.bin/node")
    };
    std::fs::create_dir_all(binary.parent().expect("project Node has a parent"))
        .expect("create project Node bin directory");
    let script = if cfg!(windows) {
        format!("@echo off\r\necho v{version}\r\n")
    } else {
        format!("#!/bin/sh\necho v{version}\n")
    };
    std::fs::write(&binary, script).expect("write project Node binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("mark project Node executable");
    }
}

fn install_fake_member_root_node(project: &TempProject, member_dir: &str, version: &str) {
    let binary = if cfg!(windows) {
        project.path().join(member_dir).join("node.cmd")
    } else {
        project.path().join(member_dir).join("node")
    };
    let script = if cfg!(windows) {
        format!("@echo off\r\necho v{version}\r\n")
    } else {
        format!("#!/bin/sh\necho v{version}\n")
    };
    std::fs::write(&binary, script).expect("write member-root Node binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("mark member-root Node executable");
    }
}

fn configure_cwd_sensitive_fake_node(command: &mut assert_cmd::Command, project: &TempProject) {
    let bin_dir = project.home().join("cwd-sensitive-node-bin");
    std::fs::create_dir_all(&bin_dir).expect("create cwd-sensitive Node bin directory");
    let binary = if cfg!(windows) {
        bin_dir.join("node.cmd")
    } else {
        bin_dir.join("node")
    };
    let script = if cfg!(windows) {
        "@echo off\r\nfor %%I in (\"%CD%\") do set \"LPM_NODE_MEMBER=%%~nxI\"\r\nif \"%LPM_NODE_MEMBER%\"==\"a\" goto compatible\r\necho v18.0.0\r\nexit /b 0\r\n:compatible\r\necho v22.0.0\r\n"
    } else {
        "#!/bin/sh\nif [ \"$(basename \"$(pwd)\")\" = \"a\" ]; then\n  echo v22.0.0\nelse\n  echo v18.0.0\nfi\n"
    };
    std::fs::write(&binary, script).expect("write cwd-sensitive Node binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("mark cwd-sensitive Node executable");
    }

    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin_dir).chain(std::env::split_paths(&existing_path));
    command.env(
        "PATH",
        std::env::join_paths(paths).expect("construct PATH with cwd-sensitive Node"),
    );
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

#[cfg(unix)]
#[test]
fn run_workspace_rejects_member_runtime_that_violates_root_node_engine() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-selection-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "runtime-selection-app",
            "version": "1.0.0",
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    project.write_file("packages/app/.nvmrc", "18.0.0\n");
    install_fake_managed_node(&project, "18.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "node-version", "--all"])
        .output()
        .expect("run workspace member with conflicting runtime selector");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "workspace member ran with an incompatible Node:\n{combined}"
    );
    assert!(
        combined.contains(">=22") && combined.contains("18.0.0") && combined.contains(".nvmrc"),
        "member runtime mismatch did not identify the constraint and selector:\n{combined}"
    );
}

#[test]
fn doctor_reports_node_engine_mismatch_for_incompatible_system_runtime() {
    let project = node_version_project("^20");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor with incompatible system Node");
    let json = support::assertions::parse_json_output(&output.stdout);
    let engine_check = json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"] == "node_engine_mismatch")
        .unwrap_or_else(|| panic!("doctor omitted node engine mismatch: {json}"));

    assert_eq!(
        engine_check["severity"], "fail",
        "unexpected check: {engine_check}"
    );
    assert!(
        engine_check["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("^20") && detail.contains("v22.0.0")),
        "doctor mismatch lacks required and actual versions: {engine_check}"
    );
    insta::assert_json_snapshot!("doctor_node_engine_mismatch", engine_check);
}

#[test]
fn doctor_reports_node_engine_compatibility_for_matching_system_runtime() {
    let project = node_version_project("^20");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.19.0");

    let output = command
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor with compatible system Node");
    let json = support::assertions::parse_json_output(&output.stdout);
    let engine_check = json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"] == "node_engine_compatible")
        .unwrap_or_else(|| panic!("doctor omitted node engine compatibility: {json}"));

    assert_eq!(
        engine_check["severity"], "pass",
        "unexpected check: {engine_check}"
    );
    insta::assert_json_snapshot!("doctor_node_engine_compatible", engine_check);
}

#[test]
fn doctor_warns_for_node_engine_mismatch_when_strictness_is_disabled() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-selection-doctor-soft-engine",
            "version": "1.0.0",
            "engines": {"node": "^20"},
            "lpm": {"engineStrict": false}
        }"#,
    );
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor with a soft engine mismatch");
    let json = support::assertions::parse_json_output(&output.stdout);
    let engine_check = json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"] == "node_engine_mismatch")
        .unwrap_or_else(|| panic!("doctor omitted soft node engine mismatch: {json}"));

    assert_eq!(
        engine_check["severity"], "warn",
        "unexpected check: {engine_check}"
    );
    insta::assert_json_snapshot!("doctor_node_engine_mismatch_warning", engine_check);
}

#[test]
fn run_missing_node_suggests_selector_compatible_with_engine_range() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-selection-compatible-hint",
            "version": "1.0.0",
            "engines": {"node": "^20"},
            "scripts": {"probe": "echo should-not-run"}
        }"#,
    );
    let empty_path = project.home().join("empty-path-compatible-hint");
    std::fs::create_dir_all(&empty_path).expect("create empty PATH directory");

    let output = lpm(&project)
        .env("PATH", &empty_path)
        .env("LPM_NO_AUTO_INSTALL", "1")
        .args(["run", "probe"])
        .output()
        .expect("run without Node for a bounded engine range");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "missing Node did not fail:\n{combined}"
    );
    assert!(
        combined.contains("lpm use node@20"),
        "diagnostic did not suggest a compatible selector:\n{combined}"
    );
    assert!(
        !combined.contains("lpm use node@22"),
        "diagnostic suggested an incompatible selector:\n{combined}"
    );
}

#[test]
fn run_engine_mismatch_help_only_mentions_supported_opt_outs() {
    let project = node_version_project(">=18");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "16.0.0");

    let output = command
        .args(["run", "node-version"])
        .output()
        .expect("run with an engine mismatch");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "engine mismatch did not fail:\n{combined}"
    );
    assert!(
        !combined.contains("--no-engine-strict"),
        "run diagnostic advertised an unsupported flag:\n{combined}"
    );
    assert!(
        combined.contains("engineStrict") && combined.contains("engine-strict"),
        "run diagnostic omitted supported project and user opt-outs:\n{combined}"
    );
}

#[test]
fn run_validates_node_from_project_bin_before_executing_script() {
    let project = node_version_project(">=18");
    install_fake_project_node(&project, "16.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "node-version"])
        .output()
        .expect("run with a project-local Node binary");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "project-local Node bypassed engine validation:\n{combined}"
    );
    assert!(
        combined.contains("16.0.0") && combined.contains(">=18"),
        "engine mismatch did not use the project-local Node:\n{combined}"
    );
}

#[test]
fn doctor_validates_node_from_project_bin() {
    let project = node_version_project(">=18");
    install_fake_project_node(&project, "16.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor with a project-local Node binary");
    let json = support::assertions::parse_json_output(&output.stdout);
    let engine_check = json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"] == "node_engine_mismatch")
        .unwrap_or_else(|| panic!("doctor omitted project-local Node mismatch: {json}"));

    assert_eq!(engine_check["severity"], "fail");
    assert!(
        engine_check["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("v16.0.0") && detail.contains(">=18")),
        "doctor mismatch did not use the project-local Node: {engine_check}"
    );
}

#[cfg(unix)]
#[test]
fn workspace_runtime_preflight_follows_topological_order() {
    let project = TempProject::empty(
        r#"{
            "name": "runtime-preflight-order-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/core/package.json",
        r#"{
            "name": "runtime-preflight-core",
            "version": "1.0.0",
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    project.write_file("packages/core/lpm.json", r#"{"runtime":{"node":"20.0.0"}}"#);
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "runtime-preflight-app",
            "version": "1.0.0",
            "dependencies": {"runtime-preflight-core": "workspace:*"},
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    project.write_file("packages/app/lpm.json", r#"{"runtime":{"node":"18.0.0"}}"#);
    install_fake_managed_node(&project, "18.0.0");
    install_fake_managed_node(&project, "20.0.0");

    for attempt in 0..12 {
        let mut command = lpm(&project);
        configure_fake_node(&mut command, &project, "22.0.0");
        let output = command
            .args(["run", "node-version", "--all"])
            .output()
            .expect("preflight workspace runtimes");
        let combined = command_output_text(&output);

        assert!(
            !output.status.success(),
            "workspace preflight unexpectedly succeeded on attempt {attempt}:\n{combined}"
        );
        assert!(
            combined.contains("20.0.0") && !combined.contains("actual 18.0.0"),
            "workspace preflight did not fail on the dependency first on attempt {attempt}:\n{combined}"
        );
    }
}

#[test]
fn workspace_validates_project_bin_node_for_member_without_selector() {
    let project = TempProject::empty(
        r#"{
            "name": "member-project-node-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "member-project-node-app",
            "version": "1.0.0",
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    let member_node = if cfg!(windows) {
        project
            .path()
            .join("packages/app/node_modules/.bin/node.cmd")
    } else {
        project.path().join("packages/app/node_modules/.bin/node")
    };
    std::fs::create_dir_all(member_node.parent().expect("member Node has a parent"))
        .expect("create member Node bin directory");
    let script = if cfg!(windows) {
        "@echo off\r\necho v18.0.0\r\n"
    } else {
        "#!/bin/sh\necho v18.0.0\n"
    };
    std::fs::write(&member_node, script).expect("write member Node binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&member_node, std::fs::Permissions::from_mode(0o755))
            .expect("mark member Node executable");
    }
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "node-version", "--all"])
        .output()
        .expect("preflight member project Node");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "member project Node bypassed workspace preflight:\n{combined}"
    );
    assert!(
        combined.contains("18.0.0") && combined.contains(">=22"),
        "member project Node mismatch was not reported:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn workspace_skips_runtime_preflight_for_member_without_requested_task() {
    let project = TempProject::empty(
        r#"{
            "name": "skip-runtime-preflight-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "skip-runtime-preflight-app",
            "version": "1.0.0",
            "scripts": {"test": "echo app-tested"}
        }"#,
    );
    project.write_file(
        "packages/docs/package.json",
        r#"{
            "name": "skip-runtime-preflight-docs",
            "version": "1.0.0"
        }"#,
    );
    project.write_file("packages/docs/lpm.json", r#"{"runtime":{"node":"18.0.0"}}"#);
    install_fake_managed_node(&project, "18.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "test", "--all"])
        .output()
        .expect("run only members defining the requested task");
    let combined = command_output_text(&output);

    assert!(
        output.status.success(),
        "skipped member aborted runtime preflight:\n{combined}"
    );
    assert!(
        combined.contains("app-tested") && !combined.contains("Using Node.js 18.0.0"),
        "skipped member was prepared or runnable member did not execute:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn workspace_resolves_relative_path_node_from_member_script_cwd() {
    let project = TempProject::empty(
        r#"{
            "name": "relative-node-path-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "relative-node-path-app",
            "version": "1.0.0",
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    install_fake_member_root_node(&project, "packages/app", "18.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = [
        std::path::PathBuf::from("."),
        project.home().join("fake-node-bin"),
    ]
    .into_iter()
    .chain(std::env::split_paths(&existing_path));
    command.env(
        "PATH",
        std::env::join_paths(paths).expect("construct PATH with relative member lookup"),
    );

    let output = command
        .args(["run", "node-version", "--all"])
        .output()
        .expect("validate relative PATH from the member cwd");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "member cwd Node bypassed engine validation:\n{combined}"
    );
    assert!(
        combined.contains("18.0.0") && combined.contains(">=22"),
        "member cwd mismatch did not report the executed Node:\n{combined}"
    );
}

#[cfg(windows)]
#[test]
fn workspace_resolves_windows_current_directory_node_before_path() {
    let project = TempProject::empty(
        r#"{
            "name": "windows-cwd-node-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{
            "name": "windows-cwd-node-app",
            "version": "1.0.0",
            "scripts": {"node-version": "node --version"}
        }"#,
    );
    install_fake_member_root_node(&project, "packages/app", "18.0.0");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "22.0.0");

    let output = command
        .args(["run", "node-version", "--all"])
        .output()
        .expect("validate Windows current-directory Node lookup");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success(),
        "member current-directory Node bypassed engine validation:\n{combined}"
    );
    assert!(
        combined.contains("18.0.0") && combined.contains(">=22"),
        "Windows cwd mismatch did not report the executed Node:\n{combined}"
    );
}

#[test]
fn workspace_does_not_reuse_shared_node_shim_version_across_member_cwds() {
    let project = TempProject::empty(
        r#"{
            "name": "cwd-sensitive-node-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file(
        "packages/a/package.json",
        r#"{
            "name": "cwd-sensitive-node-a",
            "version": "1.0.0",
            "scripts": {"test": "echo a-tested"}
        }"#,
    );
    project.write_file(
        "packages/b/package.json",
        r#"{
            "name": "cwd-sensitive-node-b",
            "version": "1.0.0",
            "dependencies": {"cwd-sensitive-node-a": "workspace:*"},
            "scripts": {"test": "echo b-tested"}
        }"#,
    );
    let mut command = lpm(&project);
    configure_cwd_sensitive_fake_node(&mut command, &project);

    let output = command
        .args(["run", "test", "--all"])
        .output()
        .expect("preflight members sharing one cwd-sensitive Node shim");
    let combined = command_output_text(&output);

    assert!(
        !output.status.success() && combined.contains("18.0.0") && combined.contains(">=22"),
        "member B reused member A's cached Node version:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn workspace_reuses_lpm_managed_node_version_across_member_cwds() {
    let project = TempProject::empty(
        r#"{
            "name": "managed-node-probe-workspace",
            "version": "1.0.0",
            "private": true,
            "workspaces": ["packages/*"],
            "engines": {"node": ">=22"}
        }"#,
    );
    project.write_file("lpm.json", r#"{"runtime":{"node":"22.0.0"}}"#);
    for member in ["app", "docs", "shared"] {
        project.write_file(
            &format!("packages/{member}/package.json"),
            &format!(
                r#"{{
                    "name": "managed-node-probe-{member}",
                    "version": "1.0.0",
                    "scripts": {{"test": "echo {member}-tested"}}
                }}"#
            ),
        );
    }
    let counter = install_counting_fake_managed_node(&project, "22.0.0");
    let mut command = lpm(&project);
    command.env("LPM_NODE_PROBE_COUNT", &counter);

    let output = command
        .args(["run", "test", "--all"])
        .output()
        .expect("preflight members sharing one LPM-managed Node executable");
    let combined = command_output_text(&output);

    assert!(output.status.success(), "workspace run failed:\n{combined}");
    assert_eq!(
        std::fs::read_to_string(counter)
            .expect("read managed Node probe count")
            .trim(),
        "1",
        "LPM-managed Node was probed more than once:\n{combined}"
    );
}
