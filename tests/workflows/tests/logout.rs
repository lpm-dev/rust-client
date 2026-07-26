mod support;

use support::auth_state::{SessionSeed, credentials_path, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

#[tokio::test]
async fn logout_human_output_uses_slim_logged_out_notice() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .arg("logout")
        .output()
        .expect("failed to run lpm logout");

    assert!(
        output.status.success(),
        "logged-out logout must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human logout should not write to stdout when already logged out, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› No stored lpm.dev session"),
        "logged-out logout should use the slim session notice, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from logout stderr, got:\n{stderr}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "logged-out logout should not hit the network, got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn logout_human_output_uses_slim_done_line_and_clears_state() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .arg("logout")
        .output()
        .expect("failed to run authenticated lpm logout");

    assert!(
        output.status.success(),
        "logout must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human logout should not write to stdout on success, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Clearing stored lpm.dev session")
            && stderr.contains("✓ Done · signed out of lpm.dev"),
        "logout should use the slim done line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Token revoked on server"),
        "plain logout should not print revoke-only detail lines, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from logout stderr, got:\n{stderr}"
    );

    let requests = mock
        .server()
        .received_requests()
        .await
        .expect("wiremock request log must be available");
    assert!(
        requests.is_empty(),
        "logout without --revoke should not hit the network, got {} request(s)",
        requests.len()
    );
}

#[tokio::test]
async fn logout_revoke_human_output_uses_slim_phase_then_done() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_revoke_all_pairings().await;
    mock.with_revoke_token("access-primary").await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: Some("refresh-primary"),
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--revoke"])
        .output()
        .expect("failed to run lpm logout --revoke");

    assert!(
        output.status.success(),
        "logout --revoke must exit 0, stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human logout --revoke should not write to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Clearing stored lpm.dev session")
            && stderr.contains("✓ Revoked browser pairings")
            && stderr.contains("✓ Revoked server-side CLI session")
            && stderr.contains("✓ Done · signed out of lpm.dev"),
        "logout --revoke should show the slim clear/revoke/done lines, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Token revoked on server"),
        "logout --revoke should drop the redundant post-success revoke detail, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("●") && !stderr.contains("◆") && !stderr.contains("│"),
        "legacy cliclack glyphs must be gone from logout stderr, got:\n{stderr}"
    );

    let requests = mock.server().received_requests().await.unwrap();
    let paths: Vec<_> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();
    assert_eq!(
        paths,
        vec!["/api/vault/pair/revoke-all", "/api/cli/revoke"],
        "pairings must be revoked before the session bearer"
    );
}

#[tokio::test]
async fn logout_revoke_json_remote_failure_is_nonzero_but_clears_local_once() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_revoke_all_pairings_status(503).await;
    mock.with_revoke_token("access-primary").await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-primary"),
            refresh_token: Some("refresh-primary"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "logout", "--revoke"])
        .output()
        .expect("run logout --revoke JSON failure");

    assert!(!output.status.success());
    let documents: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("logout JSON must parse");
    assert_eq!(documents.len(), 1);
    let json = &documents[0];
    assert_eq!(json["success"], false);
    assert_eq!(json["revoke_requested"], true);
    assert_eq!(json["pairings_revoked"], false);
    assert_eq!(json["server_revoked"], true);
    assert_eq!(json["local_cleared"], true);
    assert!(!credentials_path(project.home()).exists());
}
