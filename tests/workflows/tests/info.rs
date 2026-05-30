mod support;

use support::mock_registry::{MockRegistry, make_tarball};
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn info_human_output_uses_slim_completion_and_stdout_report() {
    let project = TempProject::empty(r#"{"name":"info-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let tarball = make_tarball("@lpm.dev/owner.react", "1.0.0");
    mock.with_package_and_deps(
        "@lpm.dev/owner.react",
        "1.0.0",
        &tarball,
        serde_json::json!({
            "react": "^19.0.0",
            "@radix-ui/react-dialog": "^1.1.6"
        }),
    )
    .await;

    let output = lpm_with_registry(&project, &mock.url())
        .args(["info", "owner.react", "--version", "1.0.0"])
        .output()
        .expect("failed to run lpm info");

    assert!(
        output.status.success(),
        "lpm info failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("@lpm.dev/owner.react")
            && stdout.contains("version      1.0.0")
            && stdout.contains("dependencies")
            && stdout.contains("@radix-ui/react-dialog")
            && stdout.contains("react"),
        "info report must stay on stdout, got:\n{stdout}",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Loaded package metadata"),
        "info must finish with a slim completion line, got:\n{stderr}",
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "info must not use cliclack gutter output, got:\n{stderr}",
    );
}
