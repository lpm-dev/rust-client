//! Workflow coverage for the native build a package gets without naming it.

mod support;

use support::mock_registry::MockRegistry;
#[cfg(unix)]
use support::write_signed_unlock_for;
use support::{TempProject, lpm, lpm_with_registry};

const INSTALL: [&str; 3] = ["install", "--no-skills", "--no-security-summary"];

fn consumer_of(dependency: &str) -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"consumer","version":"1.0.0","dependencies":{{"{dependency}":"1.0.0"}}}}"#
    ))
}

/// What `approve-scripts --list` reports as waiting for review.
fn waiting_for_review(project: &TempProject) -> serde_json::Value {
    let listed = lpm(project)
        .args(["--json", "approve-scripts", "--list"])
        .output()
        .expect("spawn lpm approve-scripts --list");
    assert!(listed.status.success(), "{listed:?}");
    serde_json::from_slice(&listed.stdout).expect("approve-scripts --list --json prints JSON")
}

#[tokio::test]
async fn a_package_with_a_binding_gyp_and_no_install_script_waits_for_review_of_its_build() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({ "name": "native", "version": "1.0.0" }),
            &[("binding.gyp", br#"{"targets":[{"target_name":"native"}]}"#)],
        )
        .await;
    let project = consumer_of("native");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let waiting = waiting_for_review(&project);
    assert_eq!(waiting["blocked_count"], 1, "{waiting:#}");
    let native = &waiting["blocked"][0];
    assert_eq!(native["name"], "native", "{waiting:#}");
    assert_eq!(
        native["phases_present"],
        serde_json::json!(["install"]),
        "{waiting:#}"
    );
    assert_eq!(native["static_tier"], "green", "{waiting:#}");
}

#[tokio::test]
async fn a_package_that_opts_out_of_the_implied_build_has_nothing_to_review() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({ "name": "prebuilt", "version": "1.0.0", "gypfile": false }),
            &[(
                "binding.gyp",
                br#"{"targets":[{"target_name":"prebuilt"}]}"#,
            )],
        )
        .await;
    let project = consumer_of("prebuilt");

    lpm_with_registry(&project, &registry.url())
        .args(INSTALL)
        .assert()
        .success();

    let waiting = waiting_for_review(&project);
    assert_eq!(waiting["blocked_count"], 0, "{waiting:#}");
}

/// A Node installation whose npm ships a stand-in `node-gyp` that writes
/// its arguments to `built-by.txt` where it runs. Its `node` starts the
/// machine's. Returns the directory to put first on `PATH`.
#[cfg(unix)]
fn node_with_npm(prefix: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .expect("Node is installed");
    assert!(node.status.success(), "{node:?}");
    let node = String::from_utf8(node.stdout).unwrap();
    let bin = prefix.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("node"),
        format!("#!/bin/sh\nexec '{}' \"$@\"\n", node.trim()),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("node"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let node_gyp = prefix.join("lib/node_modules/npm/node_modules/node-gyp");
    std::fs::create_dir_all(node_gyp.join("bin")).unwrap();
    std::fs::write(
        node_gyp.join("bin/node-gyp.js"),
        "require('fs').writeFileSync('built-by.txt', process.argv.slice(2).join(' '));\n",
    )
    .unwrap();
    std::fs::write(
        node_gyp.join("package.json"),
        r#"{"name":"node-gyp","version":"11.2.0"}"#,
    )
    .unwrap();
    bin
}

#[cfg(unix)]
#[tokio::test]
async fn the_implied_build_runs_the_node_gyp_of_the_npm_beside_node() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({ "name": "native", "version": "1.0.0" }),
            &[("binding.gyp", br#"{"targets":[{"target_name":"native"}]}"#)],
        )
        .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"native":"1.0.0"},"lpm":{"trustedDependencies":["native"]}}"#,
    );
    let installation = tempfile::tempdir().unwrap();
    let node_bin = node_with_npm(installation.path());
    let path = std::env::join_paths(
        std::iter::once(node_bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    write_signed_unlock_for(
        &project,
        project.path(),
        &["sandbox-none", "trust-bulk-approve"],
    );

    lpm_with_registry(&project, &registry.url())
        .env("PATH", path)
        .args(INSTALL)
        .args(["--no-sandbox", "--auto-build"])
        .assert()
        .success();

    assert_eq!(
        project.read_file("node_modules/native/built-by.txt"),
        "rebuild"
    );
}
