mod support;

use support::auth_state::{
    SessionSeed, read_credentials, read_expiry_metadata, seed_sessions, token_expiry_path,
};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

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
