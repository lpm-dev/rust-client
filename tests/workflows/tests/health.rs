mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn health_human_output_uses_slim_success_line() {
    let project = TempProject::empty(r#"{"name":"health","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;

    let output = lpm_with_registry(&project, &mock.url())
        .arg("health")
        .output()
        .expect("failed to run lpm health");

    assert!(
        output.status.success(),
        "healthy lpm health must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human health should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("✓ Registry is healthy"),
        "healthy health should use the slim success line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from health stderr, got:\n{stderr}"
    );
}

#[tokio::test]
async fn health_human_output_uses_slim_warning_for_unhealthy_registry() {
    let project = TempProject::empty(r#"{"name":"health","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health_status(503).await;

    let output = lpm_with_registry(&project, &mock.url())
        .arg("health")
        .output()
        .expect("failed to run unhealthy lpm health");

    assert!(
        !output.status.success(),
        "unhealthy lpm health must exit non-zero, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "unhealthy human health should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("! Registry at {} is unreachable", mock.url())),
        "unhealthy health should use the slim warning line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from health stderr, got:\n{stderr}"
    );
}
