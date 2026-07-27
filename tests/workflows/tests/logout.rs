mod support;

use support::auth_state::{
    SessionSeed, credentials_path, custom_registries_path, read_credentials,
    seed_custom_registries, seed_sessions,
};
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
async fn logout_json_fails_when_lpm_token_remains_in_the_process_environment() {
    let project = TempProject::empty(r#"{"name":"logout-env-token","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "environment-only-token")
        .args(["--json", "logout"])
        .output()
        .expect("run logout with only LPM_TOKEN configured");

    assert!(
        !output.status.success(),
        "logout cannot report success while LPM_TOKEN remains active"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], false);
    assert_eq!(json["local_cleared"], false);
    assert!(
        json["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| {
                error
                    .as_str()
                    .is_some_and(|message| message.contains("unset LPM_TOKEN"))
            })),
        "logout must explain that only the parent environment can remove LPM_TOKEN: {json}"
    );
}

#[tokio::test]
async fn logout_revoke_uses_the_stored_session_when_lpm_token_is_active() {
    let project = TempProject::empty(r#"{"name":"logout-mixed-auth","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_revoke_all_pairings_for("stored-access").await;
    mock.with_revoke_token("stored-access").await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stored-access"),
            refresh_token: Some("stored-refresh"),
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "environment-token")
        .args(["--json", "logout", "--revoke"])
        .output()
        .expect("run logout --revoke with stored and environment credentials");

    assert!(
        !output.status.success(),
        "the active parent-process LPM_TOKEN must keep the overall result unsuccessful"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], false);
    assert_eq!(json["pairings_revoked"], true);
    assert_eq!(json["server_revoked"], true);
    assert_eq!(json["local_cleared"], false);
    assert!(
        json["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| {
                error
                    .as_str()
                    .is_some_and(|message| message.contains("unset LPM_TOKEN"))
            })),
        "logout must report only the environment credential as remaining: {json}"
    );
    assert!(
        !credentials_path(project.home()).exists(),
        "the stored session must be cleared after remote revocation"
    );
}

#[tokio::test]
async fn logout_revoke_refreshes_stale_stored_access_without_expiry_metadata() {
    let project = TempProject::empty(r#"{"name":"logout-stale-access","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    mock.with_revoke_all_pairings_for_status("stale-access", 401, 1)
        .await;
    mock.with_refresh_expected(
        "stored-refresh",
        "rotated-access",
        "rotated-refresh",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_revoke_all_pairings_for_status("rotated-access", 200, 1)
        .await;
    mock.with_revoke_token("rotated-access").await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stale-access"),
            refresh_token: Some("stored-refresh"),
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "logout", "--revoke"])
        .output()
        .expect("run logout --revoke with stale stored access");

    assert!(
        output.status.success(),
        "logout should refresh and retry before local cleanup:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], true);
    assert_eq!(json["pairings_revoked"], true);
    assert_eq!(json["server_revoked"], true);
    assert_eq!(json["local_cleared"], true);
    assert_eq!(json["errors"], serde_json::json!([]));
    assert!(
        !credentials_path(project.home()).exists(),
        "the refreshed stored session must be removed after remote revocation"
    );

    let requests = mock.server().received_requests().await.unwrap();
    let paths: Vec<_> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/vault/pair/revoke-all",
            "/api/cli/refresh",
            "/api/vault/pair/revoke-all",
            "/api/cli/revoke",
        ],
        "a stale bearer must trigger one refresh before ordered revocation retries"
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

#[tokio::test]
async fn logout_all_revoke_remote_failure_still_clears_every_local_registry_credential() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";
    mock.with_revoke_all_pairings_status(503).await;
    mock.with_revoke_token("access-primary").await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-primary"),
                refresh_token: Some("refresh-primary"),
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: "https://registry.npmjs.org",
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: "https://npm.pkg.github.com",
                access_token: Some("github-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: "https://gitlab.com/api/v4/packages/npm",
                access_token: Some("gitlab-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: custom_registry,
                access_token: Some("custom-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
        ],
    );
    seed_custom_registries(project.home(), &[custom_registry]);

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "logout", "--all", "--revoke"])
        .output()
        .expect("run logout --all --revoke with remote failure");

    assert!(!output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], false);
    assert_eq!(json["local_cleared"], true);
    assert!(!credentials_path(project.home()).exists());
    assert!(!custom_registries_path(project.home()).exists());
}

#[tokio::test]
async fn logout_revoke_with_specific_target_is_rejected_before_credentials_change() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-primary"),
                refresh_token: Some("refresh-primary"),
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: "https://registry.npmjs.org",
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
        ],
    );
    let before = read_credentials(project.home());

    let output = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--revoke", "--npm"])
        .output()
        .expect("run logout --revoke --npm");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--revoke can only be used for the LPM.dev session")
    );
    assert_eq!(read_credentials(project.home()), before);
}

#[tokio::test]
async fn logout_all_json_reports_failure_when_the_local_credential_store_cannot_be_cleared() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    std::fs::create_dir_all(credentials_path(project.home()))
        .expect("create broken credentials-path directory");

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "environment-session-token")
        .args(["--json", "logout", "--all"])
        .output()
        .expect("run logout --all with a broken credential store");

    assert!(
        !output.status.success(),
        "logout --all must fail when any requested local store cannot be cleared"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], false);
    assert_eq!(json["local_cleared"], false);
}

#[tokio::test]
async fn targeted_logout_json_reports_failure_when_its_credential_store_cannot_be_cleared() {
    let project = TempProject::empty(r#"{"name":"logout","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    std::fs::create_dir_all(credentials_path(project.home()))
        .expect("create broken credentials-path directory");

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--json", "logout", "--npm"])
        .output()
        .expect("run targeted npm logout with a broken credential store");

    assert!(
        !output.status.success(),
        "targeted logout must fail when its credential cannot be cleared"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("logout must emit one JSON document");
    assert_eq!(json["success"], false);
    assert_eq!(json["local_cleared"], false);
}
