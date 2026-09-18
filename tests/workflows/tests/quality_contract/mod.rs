use super::*;
use support::auth_state::{SessionSeed, read_credentials, seed_sessions};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

fn registry_report() -> serde_json::Value {
    serde_json::json!({
        "name": "@lpm.dev/owner.widget", "score": 0, "maxScore": 100,
        "tier": "needs-work", "ecosystem": "js",
        "categories": {"documentation": {"score": 0, "max": 30}},
        "publishedAt": "2026-09-18T00:00:00Z",
        "checks": [{"id": "readme", "label": "README", "passed": false,
            "points": 0, "max_points": 10, "detail": "Add a README."}]
    })
}

#[tokio::test]
async fn quality_attaches_explicit_credentials_for_private_reports() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    Mock::given(method("GET"))
        .and(path("/api/registry/quality"))
        .and(header("authorization", "Bearer owner-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(registry_report()))
        .expect(1)
        .mount(mock.server())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args([
            "quality",
            "owner.widget",
            "--token",
            "owner-token",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["score"], 0);
}

#[tokio::test]
async fn quality_recovers_a_stored_session_after_concealed_access_denial() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("GET"))
        .and(path("/api/registry/quality"))
        .and(header("authorization", "Bearer expired-access"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/quality"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(registry_report()))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_refresh_expected(
        "valid-refresh",
        "rotated-access",
        "rotated-refresh",
        "2099-01-01T00:00:00Z",
        1,
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        read_credentials(project.home())[mock.url()],
        "rotated-access"
    );
}

#[tokio::test]
async fn quality_public_report_does_not_require_session_refresh() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("expired-refresh"),
            session_access_expires_at: Some("2020-01-01T00:00:00Z"),
        }],
    );
    mock.with_quality_report("owner.widget", registry_report())
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(401))
        .expect(0)
        .mount(mock.server())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn quality_preserves_server_fields_and_check_maxima() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report("owner.widget", registry_report())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["checks"][0]["maxPoints"], 10);
    assert_eq!(json["available"], true);
    assert_eq!(json["count"], 1);
    assert_eq!(json["categories"]["documentation"]["max"], 30);
    assert_eq!(json["published_at"], "2026-09-18T00:00:00Z");
    insta::assert_json_snapshot!("quality_server_report", json);
}

#[tokio::test]
async fn quality_human_report_shows_server_check_maxima() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report("owner.widget", registry_report())
        .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.contains("README") && line.ends_with("0/10")),
        "{output:?}"
    );
}

#[tokio::test]
async fn quality_unavailable_json_retains_status_and_reason() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report(
        "owner.widget",
        serde_json::json!({
            "name": "owner.widget", "available": false, "score": null,
            "message": "No quality data available."
        }),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["available"], false);
    assert_eq!(json["message"], "No quality data available.");
    assert_eq!(json["count"], 0);
    insta::assert_json_snapshot!("quality_unavailable_report", json);
}

#[tokio::test]
async fn quality_unavailable_human_report_does_not_claim_readiness() {
    let project = TempProject::empty(r#"{"name":"quality-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_quality_report(
        "owner.widget",
        serde_json::json!({
            "name": "owner.widget", "available": false, "message": "No quality data available."
        }),
    )
    .await;
    let output = lpm_with_registry(&project, &mock.url())
        .args(["quality", "owner.widget"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("No quality data available."), "{text}");
    assert!(!text.contains("Quality report ready"), "{text}");
}
