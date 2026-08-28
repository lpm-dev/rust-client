mod support;

use std::time::{Duration, Instant};

use support::assertions::parse_json_output;
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

fn registry_url_with_credentials(url: &str) -> String {
    url.replacen("://", "://audit-user:audit-secret@", 1)
}

#[tokio::test]
async fn health_human_output_renders_registry_status_table() {
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
        stderr.contains("Registry") && stderr.contains(&mock.url()),
        "healthy health should render the registry URL row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Status") && stderr.contains("● healthy"),
        "healthy health should render the status row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Response") && stderr.contains(" ms"),
        "healthy health should render the response-time row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Registry is reachable"),
        "healthy health should use the slim reachable terminus, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from health stderr, got:\n{stderr}"
    );
}

#[tokio::test]
async fn health_human_output_redacts_registry_credentials() {
    let project = TempProject::empty(r#"{"name":"health","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    let registry_url = registry_url_with_credentials(&mock.url());

    let output = lpm_with_registry(&project, &registry_url)
        .arg("health")
        .output()
        .expect("failed to run lpm health");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains("audit-user") && !stderr.contains("audit-secret"),
        "health must not expose registry URL credentials: {stderr}"
    );
    assert!(stderr.contains(&mock.url()), "{stderr}");
}

#[tokio::test]
async fn health_json_output_redacts_registry_credentials() {
    let project = TempProject::empty(r#"{"name":"health","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health().await;
    let registry_url = registry_url_with_credentials(&mock.url());

    let output = lpm_with_registry(&project, &registry_url)
        .args(["health", "--json"])
        .output()
        .expect("failed to run lpm health --json");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(
        !stdout.contains("audit-user") && !stdout.contains("audit-secret"),
        "health JSON must not expose registry URL credentials: {stdout}"
    );
    assert_eq!(
        parse_json_output(&output.stdout)["registry_url"],
        mock.url()
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
        stderr.contains("Registry") && stderr.contains(&mock.url()),
        "unhealthy health should render the registry URL row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Status") && stderr.contains("● unreachable"),
        "unhealthy health should render the unreachable status row, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Response") && stderr.contains(" ms"),
        "unhealthy health should render the response-time row, got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("! Registry at {} is unreachable", mock.url())),
        "unhealthy health should use the slim warning line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from health stderr, got:\n{stderr}"
    );
}

#[tokio::test]
async fn health_json_exits_nonzero_when_registry_returns_unhealthy_status() {
    let project = TempProject::empty(r#"{"name":"health","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_health_status(304).await;

    let registry_url = registry_url_with_credentials(&mock.url());
    let output = lpm_with_registry(&project, &registry_url)
        .args(["health", "--json"])
        .output()
        .expect("failed to run unhealthy lpm health --json");

    assert!(
        !output.status.success(),
        "unhealthy JSON health must exit non-zero, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false, "{json:#}");
    assert_eq!(json["error_code"], "network", "{json:#}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("is unreachable")),
        "the JSON error must explain the failed health status: {json:#}"
    );
    assert!(
        !json["error"]
            .as_str()
            .is_some_and(|error| error.contains("audit-secret")),
        "the JSON error must redact registry credentials: {json:#}"
    );
    insta::with_settings!({
        filters => vec![(r"http://127\.0\.0\.1:\d+", "[registry-url]")],
    }, {
        insta::assert_json_snapshot!("health_json_unhealthy_http_status", json);
    });
}

#[tokio::test]
async fn health_stops_at_the_diagnostic_deadline_without_transport_retries() {
    let project = TempProject::empty(r#"{"name":"health-deadline","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_delayed_health(Duration::from_secs(30)).await;

    let started = Instant::now();
    let output = lpm_with_registry(&project, &mock.url())
        .args(["health", "--json"])
        .output()
        .expect("failed to run delayed lpm health --json");
    let elapsed = started.elapsed();
    let json = parse_json_output(&output.stdout);

    assert!(!output.status.success(), "{json:#}");
    assert!(
        (Duration::from_secs(4)..Duration::from_secs(8)).contains(&elapsed),
        "health must enforce its five-second operation deadline, elapsed={elapsed:?}: {json:#}"
    );
    assert_eq!(json["error_code"], "network", "{json:#}");
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|error| error.contains("5-second deadline")),
        "the timeout must remain actionable: {json:#}"
    );
}
