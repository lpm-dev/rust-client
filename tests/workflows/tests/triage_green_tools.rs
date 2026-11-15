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

use support::mock_registry::{MockRegistry, compute_integrity, make_tarball_from_pkg_json};
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
    install_with_path(project, mock, None)
}

/// Installs with `first_on_path` ahead of the inherited `PATH`, as when LPM
/// is started from a package script.
fn install_with_path(
    project: &TempProject,
    mock: &MockRegistry,
    first_on_path: Option<&std::path::Path>,
) -> std::process::Output {
    let mut command = lpm_with_registry(project, &mock.url());
    if let Some(first) = first_on_path {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let entries = std::iter::once(first.to_path_buf()).chain(std::env::split_paths(&inherited));
        command.env("PATH", std::env::join_paths(entries).unwrap());
    }
    command
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
async fn a_script_whose_second_line_runs_a_file_of_the_package_is_left_for_review() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": VICTIM,
            "version": "1.0.0",
            "scripts": { "postinstall": "echo\n./payload" },
        }),
        &[(
            "payload",
            &shell_script("echo ran > \"$PWD/payload-ran.txt\""),
        )],
    )
    .await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(
        !left_in_victim(&project, "payload-ran.txt"),
        "the package's own file ran without an approval\n{text}"
    );
    assert!(blocked_victim(&project).is_some(), "{text}");
}

#[tokio::test]
async fn a_dependency_that_claims_the_name_in_another_case_is_named_for_review() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({ "attacker-tsc": "1.0.0" })).await;
    mount_claimant(&mock, "attacker-tsc", "Tsc").await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(!left_in_victim(&project, "attacker-tsc-ran.txt"), "{text}");
    let blocked = blocked_victim(&project)
        .unwrap_or_else(|| panic!("the package must stay reviewable\n{text}"));
    // A file system that ignores case gives `tsc` the command declared as
    // `Tsc`.
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

#[tokio::test]
async fn green_command_is_not_run_from_a_tarball_the_project_installed_under_the_publishers_name() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({})).await;
    mount_typescript(&mock, ":").await;
    let project = triage_project(serde_json::json!({
        VICTIM: "1.0.0",
        "typescript": mock.tarball_url("typescript", "5.0.0"),
    }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(
        project
            .path()
            .join("node_modules/typescript/bin/tsc")
            .exists(),
        "the tarball must be installed for this to test anything\n{text}"
    );
    assert!(
        !left_in_victim(&project, "tsc-ran.txt"),
        "a package that only carries the name typescript ran as `tsc`\n{text}"
    );
}

#[tokio::test]
async fn green_tool_finds_the_other_commands_of_its_own_package() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": VICTIM,
            "version": "1.0.0",
            "scripts": { "install": "node-gyp-build" },
            "dependencies": { "node-gyp-build": "4.8.4" },
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "node-gyp-build",
            "version": "4.8.4",
            "bin": {
                "node-gyp-build": "bin.sh",
                "node-gyp-build-test": "test.sh",
            },
        }),
        &[
            (
                "bin.sh",
                &shell_script("node-gyp-build-test || exit 3\necho ran > \"$PWD/built.txt\""),
            ),
            ("test.sh", &shell_script("exit 0")),
        ],
    )
    .await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(left_in_victim(&project, "built.txt"), "{text}");
}

#[tokio::test]
async fn green_run_drops_the_projects_bin_directory_from_an_inherited_path() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({ "typescript": "5.0.0" })).await;
    mount_typescript(&mock, "build-helper || true").await;
    mount_claimant(&mock, "attacker-helper", "build-helper").await;
    let project =
        triage_project(serde_json::json!({ VICTIM: "1.0.0", "attacker-helper": "1.0.0" }));

    let output = install_with_path(
        &project,
        &mock,
        Some(&project.path().join("node_modules/.bin")),
    );

    let text = output_text(&output);
    assert!(left_in_victim(&project, "tsc-ran.txt"), "{text}");
    assert!(
        !left_in_victim(&project, "attacker-helper-ran.txt"),
        "the project's `.bin` on the inherited PATH answered a program the green tool started\n{text}"
    );
}

#[tokio::test]
async fn green_command_prefers_the_packages_own_publisher_to_the_projects() {
    let mock = MockRegistry::start().await;
    mount_victim(&mock, serde_json::json!({ "typescript": "5.0.0" })).await;
    let manifest = |version: &str| {
        serde_json::json!({
            "name": "typescript",
            "version": version,
            "bin": { "tsc": "bin/tsc" },
        })
    };
    let tarball = |version: &str| {
        make_tarball_from_pkg_json(
            manifest(version),
            &[(
                "bin/tsc",
                &shell_script(&format!("echo {version} > \"$PWD/tsc-ran.txt\"")),
            )],
        )
    };
    let versions = [("4.0.0", tarball("4.0.0")), ("5.0.0", tarball("5.0.0"))];
    let mut packument = serde_json::json!({
        "name": "typescript",
        "dist-tags": { "latest": "5.0.0" },
        "versions": {},
        "time": {},
    });
    for (version, bytes) in &versions {
        let mut entry = manifest(version);
        entry["dist"] = serde_json::json!({
            "tarball": mock.tarball_url("typescript", version),
            "integrity": compute_integrity(bytes),
        });
        packument["versions"][version] = entry;
        packument["time"][version] = "2024-01-01T00:00:00.000Z".into();
    }
    mock.with_package_metadata_and_tarballs("typescript", packument, &versions)
        .await;
    let project = triage_project(serde_json::json!({ VICTIM: "1.0.0", "typescript": "4.0.0" }));

    let output = install(&project, &mock);

    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert_eq!(
        std::fs::read_to_string(
            project
                .path()
                .join("node_modules")
                .join(VICTIM)
                .join("tsc-ran.txt")
        )
        .unwrap()
        .trim(),
        "5.0.0",
        "{text}"
    );
}
