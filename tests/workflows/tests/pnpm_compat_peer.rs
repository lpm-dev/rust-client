//! Workflow tests for pnpm-sourced peer-dependency compatibility scenarios.

mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

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
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
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
