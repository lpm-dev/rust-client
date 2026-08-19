mod support;

use support::auth_state::{
    SessionSeed, credentials_path, read_credentials, read_expiry_metadata, seed_sessions,
    token_expiry_path,
};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const VALID_OTP: &str = "123456";

struct ReplaceSessionThenReject {
    home: std::path::PathBuf,
    registry_url: String,
}

impl Respond for ReplaceSessionThenReject {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        seed_sessions(
            &self.home,
            &[SessionSeed {
                registry_url: &self.registry_url,
                access_token: Some("peer-access-token"),
                refresh_token: Some("peer-refresh-token"),
                session_access_expires_at: Some("2032-01-03T04:05:06Z"),
            }],
        );
        ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized",
        }))
    }
}

async fn mount_external_token_rotation(mock: &MockRegistry, bearer_token: &str) {
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", format!("Bearer {bearer_token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "replacement-must-not-be-stored",
            "expiresAt": "2032-01-03T04:05:06Z",
        })))
        .mount(mock.server())
        .await;
}

fn seed_stored_fallback(project: &TempProject, registry_url: &str) -> serde_json::Value {
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url,
            access_token: Some("stored-fallback-token"),
            ..Default::default()
        }],
    );
    read_credentials(project.home())
}

async fn mount_otp_error(mock: &MockRegistry, bearer_token: &str, otp: Option<&str>, code: &str) {
    let mut request = Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", format!("Bearer {bearer_token}")));
    if let Some(otp) = otp {
        request = request.and(header("x-otp", otp));
    }
    request
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": if code == "OTP_REQUIRED" {
                "Two-factor authentication code required to rotate this token."
            } else {
                "Invalid two-factor authentication code."
            },
            "code": code,
        })))
        .expect(1)
        .mount(mock.server())
        .await;
}

#[tokio::test]
async fn token_rotate_json_replaces_stored_session_token_and_expiry_metadata() {
    let project = TempProject::empty(r#"{"name":"token-rotate-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("old-session-token"),
            ..Default::default()
        }],
    );

    mock.with_token_rotate(
        "old-session-token",
        "new-session-token",
        "2032-01-03T04:05:06Z",
    )
    .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run lpm token-rotate --json");

    assert!(
        output.status.success(),
        "lpm token-rotate --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("token-rotate --json must be valid JSON: {e}\n---\n{stdout}"));

    assert_eq!(envelope["success"], serde_json::json!(true));
    assert_eq!(envelope["rotated"], serde_json::json!(true));
    assert_eq!(
        envelope["expires_at"],
        serde_json::json!("2032-01-03T04:05:06Z")
    );

    insta::assert_json_snapshot!(
        "token_rotate_json_envelope_updates_session_metadata",
        envelope
    );

    let credentials = read_credentials(project.home());
    assert_eq!(
        credentials[registry_url.as_str()],
        serde_json::json!("new-session-token")
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[registry_url.as_str()]["expires"],
        serde_json::json!("2032-01-03")
    );
}

#[tokio::test]
async fn token_rotate_human_output_uses_slim_progress_and_completion() {
    let project = TempProject::empty(r#"{"name":"token-rotate-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("old-session-token"),
            ..Default::default()
        }],
    );

    mock.with_token_rotate(
        "old-session-token",
        "new-session-token",
        "2032-01-03T04:05:06Z",
    )
    .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate"])
        .output()
        .expect("failed to run lpm token-rotate");

    assert!(
        output.status.success(),
        "lpm token-rotate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "human token-rotate must keep expiry details on stderr, got stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("› Rotating lpm.dev token"),
        "token-rotate must use a slim phase line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Old token invalidated") && stderr.contains("✓ New token stored"),
        "token-rotate must show the middle token rotation steps, got:\n{stderr}"
    );
    assert!(
        stderr.contains("secure storage backend: encrypted file fallback"),
        "token-rotate must show the secure storage backend, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Encrypted file fallback is active"),
        "token-rotate must warn when auth storage uses the encrypted file fallback, got:\n{stderr}"
    );
    assert!(
        stderr.contains("✓ Done · session token rotated successfully"),
        "token-rotate must use a slim completion line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Expires:") && stderr.contains("2032-01-03T04:05:06Z"),
        "token-rotate must keep expiry detail on stderr, got:\n{stderr}"
    );
    assert!(
        !stderr.contains('●') && !stderr.contains('│') && !stderr.contains('◇'),
        "token-rotate output must not use cliclack gutter output, got:\n{stderr}"
    );
}

#[tokio::test]
async fn token_rotate_with_otp_sends_the_header_on_the_first_request() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("old-session-token"),
            ..Default::default()
        }],
    );

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer old-session-token"))
        .and(header("x-otp", VALID_OTP))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "new-session-token",
            "expiresAt": "2032-01-03T04:05:06Z",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--otp", VALID_OTP, "--json"])
        .output()
        .expect("failed to run lpm token-rotate with --otp");

    assert!(
        output.status.success(),
        "lpm token-rotate --otp failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        read_credentials(project.home())[registry_url.as_str()],
        serde_json::json!("new-session-token")
    );
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_text.contains(VALID_OTP));
    assert!(!output_text.contains("old-session-token"));
    assert!(!output_text.contains("new-session-token"));
}

#[tokio::test]
async fn token_rotate_refreshes_rejected_stored_session_and_retries_once() {
    let project = TempProject::empty(r#"{"name":"token-rotate-refresh","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("rejected-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer rejected-access-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized",
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_refresh_expected(
        "refresh-token",
        "refreshed-access-token",
        "rotated-refresh-token",
        "2030-01-02T00:00:00Z",
        1,
    )
    .await;
    mock.with_token_rotate(
        "refreshed-access-token",
        "manually-rotated-access-token",
        "2032-01-03T04:05:06Z",
    )
    .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run lpm token-rotate with a refreshable session");

    assert!(
        output.status.success(),
        "token rotation did not recover from the rejected access token:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let credentials = read_credentials(project.home());
    assert_eq!(
        credentials[registry_url.as_str()],
        "manually-rotated-access-token"
    );
    assert_eq!(
        credentials[format!("refresh:{registry_url}")],
        "rotated-refresh-token"
    );
}

#[tokio::test]
async fn token_rotate_does_not_replay_an_ambiguous_server_failure() {
    let project = TempProject::empty(r#"{"name":"token-rotate-ambiguous","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer stored-fallback-token"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "response outcome unavailable",
        })))
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "0")
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run token rotation with an ambiguous response");

    let rotation_requests = mock
        .server()
        .received_requests()
        .await
        .expect("record token rotation requests")
        .into_iter()
        .filter(|request| request.url.path() == "/api/registry/-/token/rotate")
        .count();
    assert_eq!(
        rotation_requests, 1,
        "a mutation without an idempotency key must be submitted only once"
    );
    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
}

#[tokio::test]
async fn token_rotate_preserves_session_after_transient_refresh_failure() {
    let project =
        TempProject::empty(r#"{"name":"token-rotate-refresh-failure","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("rejected-access-token"),
            refresh_token: Some("stored-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let credentials_before = read_credentials(project.home());
    let expiry_before = read_expiry_metadata(project.home());
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer rejected-access-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized",
        })))
        .expect(1)
        .mount(mock.server())
        .await;
    Mock::given(method("POST"))
        .and(path("/api/cli/refresh"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "error": "temporarily unavailable",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run token rotation with transient refresh failure");

    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert_eq!(read_expiry_metadata(project.home()), expiry_before);
}

#[tokio::test]
async fn token_rotate_rejects_an_empty_replacement_without_changing_credentials() {
    let project = TempProject::empty(r#"{"name":"token-rotate-empty","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "",
            "expiresAt": "2032-01-03T04:05:06Z",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run token rotation with an empty replacement");

    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
}

#[tokio::test]
async fn token_rotate_rejects_an_invalid_expiry_without_changing_credentials() {
    let project = TempProject::empty(r#"{"name":"token-rotate-expiry","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "replacement-token",
            "expiresAt": "not-a-timestamp",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run token rotation with an invalid expiry");

    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
}

#[tokio::test]
async fn token_rotate_rejects_a_missing_expiry_without_changing_credentials() {
    let project = TempProject::empty(r#"{"name":"token-rotate-expiry","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "replacement-token",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run token rotation with a missing expiry");

    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
}

#[tokio::test]
async fn token_rotate_json_reports_otp_required_without_changing_credentials() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_otp_error(&mock, "stored-fallback-token", None, "OTP_REQUIRED").await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run challenged lpm token-rotate --json");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    let stdout = String::from_utf8(output.stdout).expect("JSON output must be UTF-8");
    assert!(!stdout.contains("stored-fallback-token"));
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("OTP challenge must be JSON: {error}\n{stdout}"));
    assert_eq!(envelope["error_code"], serde_json::json!("otp_required"));
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "schema_version": 1,
      "success": false,
      "error_code": "otp_required",
      "error": {
        "code": "OTP_REQUIRED",
        "message": "one-time password required for `lpm token-rotate`",
        "command": "lpm token-rotate"
      }
    }
    "#);
}

#[tokio::test]
async fn token_rotate_otp_challenge_does_not_refresh_a_valid_session() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-must-not-run"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let credentials_before = read_credentials(project.home());
    mount_otp_error(&mock, "session-access-token", None, "OTP_REQUIRED").await;
    mock.with_refresh_expected(
        "refresh-must-not-run",
        "unused-access-token",
        "unused-refresh-token",
        "2030-01-02T00:00:00Z",
        0,
    )
    .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run challenged token rotation");

    assert!(!output.status.success());
    assert_eq!(read_credentials(project.home()), credentials_before);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["error_code"], "otp_required");
}

#[tokio::test]
async fn token_rotate_noninteractive_human_run_instructs_the_user_to_pass_otp() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_otp_error(&mock, "stored-fallback-token", None, "OTP_REQUIRED").await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate"])
        .output()
        .expect("failed to run challenged lpm token-rotate");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    let stderr = String::from_utf8(output.stderr).expect("human output must be UTF-8");
    assert!(stderr.contains("One-time password required"));
    assert!(stderr.contains("--otp <CODE>"));
    assert!(!stderr.contains("stored-fallback-token"));
}

#[tokio::test]
async fn token_rotate_rejects_malformed_otp_before_network_or_storage_changes() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_external_token_rotation(&mock, "stored-fallback-token").await;
    let malformed_otp = "12secret";

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--otp", malformed_otp, "--json"])
        .output()
        .expect("failed to run lpm token-rotate with malformed --otp");

    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("record rotation requests")
            .is_empty(),
        "a malformed OTP must fail before any registry request"
    );
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("JSON output must be UTF-8");
    assert!(!stdout.contains(malformed_otp));
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("invalid OTP error must be JSON: {error}\n{stdout}"));
    assert_eq!(envelope["error_code"], serde_json::json!("otp_invalid"));
}

#[tokio::test]
async fn token_rotate_maps_rejected_otp_to_stable_json_without_changing_credentials() {
    let project = TempProject::empty(r#"{"name":"token-rotate-otp","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_otp_error(
        &mock,
        "stored-fallback-token",
        Some(VALID_OTP),
        "OTP_INVALID",
    )
    .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--otp", VALID_OTP, "--json"])
        .output()
        .expect("failed to run lpm token-rotate with rejected --otp");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    let stdout = String::from_utf8(output.stdout).expect("JSON output must be UTF-8");
    assert!(!stdout.contains(VALID_OTP));
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("rejected OTP error must be JSON: {error}\n{stdout}"));
    assert_eq!(envelope["error_code"], serde_json::json!("otp_invalid"));
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "schema_version": 1,
      "success": false,
      "error_code": "otp_invalid",
      "error": {
        "code": "OTP_INVALID",
        "message": "invalid or expired one-time password for `lpm token-rotate`",
        "command": "lpm token-rotate"
      }
    }
    "#);
}

#[tokio::test]
async fn token_rotate_unknown_unauthorized_response_remains_an_auth_failure() {
    let project = TempProject::empty(r#"{"name":"token-rotate-auth","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    seed_stored_fallback(&project, &registry_url);

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer stored-fallback-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "Unauthorized",
        })))
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run unauthorized lpm token-rotate");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert!(
        !credentials_path(project.home()).exists(),
        "a non-OTP 401 must retain the existing invalid-token cleanup"
    );
    assert!(!token_expiry_path(project.home()).exists());
    let stdout = String::from_utf8(output.stdout).expect("JSON output must be UTF-8");
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("auth failure must be JSON: {error}\n{stdout}"));
    assert_eq!(envelope["error_code"], serde_json::json!("auth_required"));
    assert!(!stdout.contains("stored-fallback-token"));
}

#[tokio::test]
async fn token_rotate_rejection_preserves_a_session_replaced_while_the_request_is_in_flight() {
    let project = TempProject::empty(r#"{"name":"token-rotate-race","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    seed_stored_fallback(&project, &registry_url);

    Mock::given(method("POST"))
        .and(path("/api/registry/-/token/rotate"))
        .and(header("authorization", "Bearer stored-fallback-token"))
        .respond_with(ReplaceSessionThenReject {
            home: project.home().to_path_buf(),
            registry_url: registry_url.clone(),
        })
        .expect(1)
        .mount(mock.server())
        .await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run unauthorized lpm token-rotate");

    assert!(!output.status.success());
    let credentials = read_credentials(project.home());
    assert_eq!(
        credentials[registry_url.as_str()],
        serde_json::json!("peer-access-token")
    );
    assert_eq!(
        credentials[format!("refresh:{registry_url}")],
        serde_json::json!("peer-refresh-token")
    );
    assert_eq!(
        read_expiry_metadata(project.home())[registry_url.as_str()]["session_access_expires_at"],
        serde_json::json!("2032-01-03T04:05:06Z")
    );
}

#[tokio::test]
async fn token_rotate_rejects_lpm_token_before_network_or_storage_changes() {
    let project = TempProject::empty(r#"{"name":"token-rotate-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_external_token_rotation(&mock, "external-env-token").await;

    let output = lpm_with_registry(&project, &registry_url)
        .env("LPM_TOKEN", "external-env-token")
        .args(["token-rotate", "--json"])
        .output()
        .expect("failed to run lpm token-rotate with LPM_TOKEN");

    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("record rotation requests")
            .is_empty(),
        "LPM_TOKEN rotation must fail before any registry request"
    );
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("JSON output must be UTF-8");
    assert!(!stdout.contains("external-env-token"));
    assert!(!stdout.contains("replacement-must-not-be-stored"));
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("token-rotate rejection must be JSON: {error}\n{stdout}"));
    assert_eq!(
        envelope["error_code"],
        serde_json::json!("unsupported_auth_source")
    );
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "schema_version": 1,
      "success": false,
      "error_code": "unsupported_auth_source",
      "error": {
        "code": "UNSUPPORTED_AUTH_SOURCE",
        "message": "unsupported authentication source for `lpm token-rotate`: LPM_TOKEN",
        "command": "lpm token-rotate",
        "source": "LPM_TOKEN"
      }
    }
    "#);
}

#[tokio::test]
async fn token_rotate_rejects_explicit_token_before_network_or_storage_changes() {
    let project = TempProject::empty(r#"{"name":"token-rotate-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_external_token_rotation(&mock, "external-flag-token").await;

    let output = lpm_with_registry(&project, &registry_url)
        .args(["--token", "external-flag-token", "token-rotate"])
        .output()
        .expect("failed to run lpm token-rotate with --token");

    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("record rotation requests")
            .is_empty(),
        "--token rotation must fail before any registry request"
    );
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("human output must be UTF-8");
    assert!(stderr.contains("Unsupported authentication source"));
    assert!(stderr.contains("--token"));
    assert!(stderr.contains("lpm login"));
    assert!(!stderr.contains("external-flag-token"));
    assert!(!stderr.contains("replacement-must-not-be-stored"));
}

#[tokio::test]
async fn token_rotate_rejects_ci_token_before_network_or_storage_changes() {
    let project = TempProject::empty(r#"{"name":"token-rotate-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let registry_url = mock.url();
    let credentials_before = seed_stored_fallback(&project, &registry_url);
    mount_external_token_rotation(&mock, "ci-exchanged-token").await;

    let output = lpm_with_registry(&project, &registry_url)
        .env("LPM_TOKEN", "ci-exchanged-token")
        .env("CI", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-context-token")
        .args(["token-rotate"])
        .output()
        .expect("failed to run lpm token-rotate with a CI token");

    assert!(
        mock.server()
            .received_requests()
            .await
            .expect("record rotation requests")
            .is_empty(),
        "CI token rotation must fail before any registry request"
    );
    assert_eq!(read_credentials(project.home()), credentials_before);
    assert!(!token_expiry_path(project.home()).exists());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("human output must be UTF-8");
    assert!(stderr.contains("Unsupported authentication source"));
    assert!(stderr.contains("CI token"));
    assert!(stderr.contains("secret store"));
    assert!(!stderr.contains("ci-exchanged-token"));
    assert!(!stderr.contains("oidc-context-token"));
    assert!(!stderr.contains("replacement-must-not-be-stored"));
}
