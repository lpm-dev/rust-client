mod support;

use support::auth_state::{SessionSeed, read_credentials, read_expiry_metadata, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

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
        stderr.contains("✓ Old token invalidated")
            && stderr.contains("✓ New token stored in Keychain"),
        "token-rotate must show the middle token rotation steps, got:\n{stderr}"
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
