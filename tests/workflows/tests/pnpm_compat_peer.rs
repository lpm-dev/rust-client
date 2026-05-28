//! Workflow tests for pnpm-sourced peer-dependency compatibility scenarios.

mod support;

use std::process::Output;
use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

const INSTALL_ARGS: &[&str] = &[
    "install",
    "--no-security-summary",
    "--no-skills",
    "--no-editor-setup",
];

#[tokio::test]
async fn optional_peer_dependency_missing_does_not_warn_or_install_peer() {
    let mock = MockRegistry::start().await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "optional-peer-host",
            "version": "1.0.0",
            "peerDependencies": {
                "ghost-peer": "^1.0.0"
            },
            "peerDependenciesMeta": {
                "ghost-peer": {
                    "optional": true
                }
            }
        }),
        &[],
    )
    .await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "optional-peer-host": "^1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install with missing optional peer must succeed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let node_modules = project.path().join("node_modules");
    assert!(
        node_modules
            .join("optional-peer-host")
            .join("package.json")
            .exists(),
        "the package declaring the optional peer must be installed"
    );
    assert!(
        !node_modules.join("ghost-peer").exists(),
        "missing optional peer must not be auto-installed"
    );
    assert!(
        !stdout.contains("requires peer ghost-peer")
            && !stderr.contains("requires peer ghost-peer"),
        "missing optional peer must not produce a peer warning\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[tokio::test]
async fn required_peer_dependency_missing_warns_and_succeeds_without_strict_mode() {
    let mock = MockRegistry::start().await;
    mount_required_peer_host(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "required-peer-host": "^1.0.0"
            },
            "lpm": {
                "autoInstallPeers": false
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "missing required peer must remain non-fatal by default\n{text}"
    );
    assert!(
        text.contains("peer dep: required-peer-host@1.0.0 requires peer missing-peer (^1.0.0)"),
        "missing required peer must still warn by default\n{text}"
    );
}

#[tokio::test]
async fn strict_peer_dependencies_cli_fails_when_required_peer_is_missing() {
    let mock = MockRegistry::start().await;
    mount_required_peer_host(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "required-peer-host": "^1.0.0"
            },
            "lpm": {
                "autoInstallPeers": false
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .arg("--strict-peer-dependencies")
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "strict mode must fail when a required peer is missing\n{text}"
    );
    assert!(
        text.contains("strict-peer-dependencies failed")
            && text.contains("required-peer-host@1.0.0 requires peer missing-peer (^1.0.0)"),
        "strict missing-peer failure must name the peer issue\n{text}"
    );
}

#[tokio::test]
async fn strict_peer_dependencies_global_config_fails_when_required_peer_is_missing() {
    let mock = MockRegistry::start().await;
    mount_required_peer_host(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "required-peer-host": "^1.0.0"
            },
            "lpm": {
                "autoInstallPeers": false
            }
        }"#,
    );
    let config_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&config_dir).expect("failed to create isolated lpm config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        "strict-peer-dependencies = true\n",
    )
    .expect("failed to write isolated lpm config");

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "strict global config must fail when a required peer is missing\n{text}"
    );
    assert!(
        text.contains("strict-peer-dependencies failed")
            && text.contains("required-peer-host@1.0.0 requires peer missing-peer (^1.0.0)"),
        "strict global-config failure must name the peer issue\n{text}"
    );
}

#[tokio::test]
async fn strict_peer_dependencies_config_fails_when_peer_ranges_conflict() {
    let mock = MockRegistry::start().await;
    mount_conflicting_peer_graph(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "peer-consumer-a": "^1.0.0",
                "peer-consumer-b": "^1.0.0"
            },
            "lpm": {
                "strictPeerDependencies": true
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "strict config must fail when peer ranges conflict\n{text}"
    );
    assert!(
        text.contains("strict-peer-dependencies failed")
            && text.contains("peer conflict: shared-peer pinned to")
            && text.contains("peer-consumer-"),
        "strict conflict failure must name the chosen peer and unsatisfied consumer\n{text}"
    );
}

#[tokio::test]
async fn peer_conflict_auto_isolates_default_linker_and_stays_up_to_date() {
    let mock = MockRegistry::start().await;
    mount_conflicting_peer_graph(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "peer-consumer-a": "^1.0.0",
                "peer-consumer-b": "^1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "peer conflict must stay warn-only by default while auto-isolating the layout\n{text}"
    );
    assert!(
        text.contains("peer shared-peer pinned to"),
        "peer conflict must still warn in default mode\n{text}"
    );
    assert_install_hash_linker(project.path(), "isolated");
    let lockfile = std::fs::read_to_string(project.path().join("lpm.lock"))
        .expect("failed to read generated lockfile");
    assert!(
        lockfile.contains("auto-isolated-peer-conflicts = true"),
        "lockfile must persist the peer-conflict auto-isolated layout decision\n{lockfile}"
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("failed to rerun lpm install");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "warm install after peer-conflict auto-isolation must succeed\n{text}"
    );
    assert!(
        text.contains("Up to date"),
        "persisted auto-isolated linker mode should keep the second install on the fast path\n{text}"
    );
    assert_install_hash_linker(project.path(), "isolated");
}

#[tokio::test]
async fn peer_conflict_respects_explicit_hoisted_linker() {
    let mock = MockRegistry::start().await;
    mount_conflicting_peer_graph(&mock).await;

    let project = TempProject::empty(
        r#"{
            "name": "pnpm-compat-peer",
            "version": "1.0.0",
            "dependencies": {
                "peer-consumer-a": "^1.0.0",
                "peer-consumer-b": "^1.0.0"
            }
        }"#,
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(INSTALL_ARGS)
        .args(["--linker", "hoisted"])
        .env("LPM_STORE_VERSION", "v2")
        .output()
        .expect("failed to run lpm install");
    let text = output_text(&output);

    assert!(
        output.status.success(),
        "explicit hoisted linker must remain an opt-out from peer-conflict auto-isolation\n{text}"
    );
    assert_install_hash_linker(project.path(), "hoisted");
    let lockfile = std::fs::read_to_string(project.path().join("lpm.lock"))
        .expect("failed to read generated lockfile");
    assert!(
        !lockfile.contains("auto-isolated-peer-conflicts = true"),
        "explicit hoisted linker must not persist auto-isolation metadata\n{lockfile}"
    );
}

async fn mount_required_peer_host(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "required-peer-host",
            "version": "1.0.0",
            "peerDependencies": {
                "missing-peer": "^1.0.0"
            }
        }),
        &[],
    )
    .await;
}

async fn mount_conflicting_peer_graph(mock: &MockRegistry) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer-a",
            "version": "1.0.0",
            "peerDependencies": {
                "shared-peer": "^1.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": "peer-consumer-b",
            "version": "1.0.0",
            "peerDependencies": {
                "shared-peer": "^2.0.0"
            }
        }),
        &[],
    )
    .await;
    mock.with_full_package_metadata(
        "shared-peer",
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("shared-peer", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("shared-peer", "2.0.0")),
            ),
        ],
    )
    .await;
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_install_hash_linker(project_dir: &std::path::Path, expected: &str) {
    let install_hash = std::fs::read_to_string(project_dir.join(".lpm").join("install-hash"))
        .expect("failed to read .lpm/install-hash");
    assert!(
        install_hash
            .lines()
            .any(|line| line == format!("l:{expected}")),
        "expected install hash to record linker {expected:?}\n{install_hash}"
    );
}
