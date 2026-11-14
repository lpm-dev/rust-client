//! Which package a green lifecycle command runs.
//!
//! Under `script-policy = "triage"` a package whose lifecycle command is on
//! the green allowlist (`tsc`, `node-gyp rebuild`, …) runs without an
//! approval. The allowlist reads the command's text; the shell finds the
//! executable on the lifecycle `PATH`, where a package's dependencies and
//! the project put the commands their `bin` fields declare. These tests pin
//! that a green run reaches the tool's own registry package or nothing a
//! package supplies.
#![cfg(unix)]

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry, write_signed_unlock};

const VICTIM: &str = "victim-green";

fn shell_script(body: &str) -> Vec<u8> {
    format!("#!/bin/sh\n{body}\n").into_bytes()
}

/// A package whose `postinstall` is the green command `tsc`.
async fn mount_victim(mock: &MockRegistry, dependencies: serde_json::Value) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": VICTIM,
            "version": "1.0.0",
            "scripts": { "postinstall": "tsc" },
            "dependencies": dependencies,
        }),
        &[],
    )
    .await;
}

/// A package that is not `typescript` and declares a command named
/// `command`, which leaves `<package>-ran.txt` where it runs.
async fn mount_claimant(mock: &MockRegistry, name: &str, command: &str) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": name,
            "version": "1.0.0",
            "bin": { command: "run.sh" },
        }),
        &[(
            "run.sh",
            &shell_script(&format!("echo ran > \"$PWD/{name}-ran.txt\"")),
        )],
    )
    .await;
}

/// The registry's `typescript`, whose `tsc` runs `body` and then leaves
/// `tsc-ran.txt`.
async fn mount_typescript(mock: &MockRegistry, body: &str) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "typescript",
            "version": "5.0.0",
            "bin": { "tsc": "bin/tsc" },
        }),
        &[(
            "bin/tsc",
            &shell_script(&format!("{body}\necho ran > \"$PWD/tsc-ran.txt\"")),
        )],
    )
    .await;
}

fn triage_project(dependencies: serde_json::Value) -> TempProject {
    let project = TempProject::empty(
        &serde_json::json!({
            "name": "green-tools-fixture",
            "version": "1.0.0",
            "dependencies": dependencies,
            "lpm": { "scriptPolicy": "triage" },
        })
        .to_string(),
    );
    write_signed_unlock(&project, &["scripts-triage", "sandbox-none"]);
    project
}

fn install(project: &TempProject, mock: &MockRegistry) -> std::process::Output {
    lpm_with_registry(project, &mock.url())
        .args([
            "install",
            "--triage",
            "--auto-build",
            "--no-sandbox",
            "--no-skills",
            "--no-security-summary",
        ])
        .output()
        .expect("spawn lpm install")
}

fn output_text(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn left_in_victim(project: &TempProject, file: &str) -> bool {
    project
        .path()
        .join("node_modules")
        .join(VICTIM)
        .join(file)
        .exists()
}

fn blocked_victim(project: &TempProject) -> Option<serde_json::Value> {
    let state: serde_json::Value =
        serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
    state["blocked_packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == VICTIM)
        .cloned()
}

#[tokio::test]
async fn green_command_is_not_auto_run_from_a_dependency_that_only_claims_its_name() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({ "attacker-tsc": "1.0.0" })).await;
    mount_claimant(&mock, "attacker-tsc", "tsc").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(
        !left_in_victim(&project, "attacker-tsc-ran.txt"),
        "a dependency that is not typescript ran as `tsc` without an approval\n{text}"
    );
    let blocked = blocked_victim(&project)
        .unwrap_or_else(|| panic!("the package must stay reviewable\n{text}"));
    assert_eq!(
        blocked["reach"]["findings"],
        serde_json::json!([{
            "kind": "runs-tool-from-other-package",
            "command": "tsc",
            "provider": "attacker-tsc@1.0.0",
        }]),
        "{blocked}"
    );
}

#[tokio::test]
async fn green_command_runs_from_the_registry_package_that_publishes_it() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({ "typescript": "5.0.0" })).await;
    mount_typescript(&mock, ":").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(left_in_victim(&project, "tsc-ran.txt"), "{text}");
    assert!(blocked_victim(&project).is_none(), "{text}");
}

#[tokio::test]
async fn green_run_does_not_find_the_commands_of_the_packages_other_dependencies() {
    let mock = MockRegistry::start().await;
    mount_victim(
        &mock,
        serde_json::json!({ "typescript": "5.0.0", "attacker-helper": "1.0.0" }),
    )
    .await;
    // The tool starts another program by name, as node-gyp starts python
    // and make.
    mount_typescript(&mock, "build-helper || true").await;
    mount_claimant(&mock, "attacker-helper", "build-helper").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(left_in_victim(&project, "tsc-ran.txt"), "{text}");
    assert!(
        !left_in_victim(&project, "attacker-helper-ran.txt"),
        "a dependency's command answered a program the green tool started\n{text}"
    );
}

#[tokio::test]
async fn green_run_does_not_use_a_project_dependency_that_only_claims_the_tools_name() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({})).await;
    mount_claimant(&mock, "attacker-tsc", "tsc").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0", "attacker-tsc": "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(
        !left_in_victim(&project, "attacker-tsc-ran.txt"),
        "the project's `.bin` answered a green command with a package that is not typescript\n{text}"
    );
    assert!(
        blocked_victim(&project).is_some(),
        "a green script that did not run must stay reviewable\n{text}"
    );
}

#[tokio::test]
async fn green_command_runs_from_the_projects_registry_package_that_publishes_it() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({})).await;
    mount_typescript(&mock, ":").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0", "typescript": "5.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(left_in_victim(&project, "tsc-ran.txt"), "{text}");
}
