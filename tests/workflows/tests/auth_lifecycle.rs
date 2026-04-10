//! Workflow tests for CLI auth state transitions.
//!
//! These exercise the real binary across startup token loading, silent refresh,
//! logout, and command execution, using isolated file-backed auth state.

mod support;

use support::assertions::parse_json_output;
use support::auth_state::{
    SessionSeed, credentials_path, custom_registries_path, mark_recent_token_validation,
    read_credentials, read_expiry_metadata, seed_custom_registries, seed_sessions,
    token_expiry_path, write_credentials_store,
};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm_with_registry};

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
const GITHUB_REGISTRY_URL: &str = "https://npm.pkg.github.com";
const GITLAB_REGISTRY_URL: &str = "https://gitlab.com/packages/npm";

fn seed_expiry_metadata(home: &std::path::Path, entries: &[(&str, serde_json::Value)]) {
    let expiries = serde_json::Value::Object(
        entries
            .iter()
            .map(|(registry, value)| (registry.to_string(), value.clone()))
            .collect(),
    );

    std::fs::write(
        token_expiry_path(home),
        serde_json::to_vec_pretty(&expiries).expect("failed to encode token expiry json"),
    )
    .expect("failed to write token expiry metadata");
}

fn builtin_expiry_key(registry_url: &str) -> &'static str {
    match registry_url {
        NPM_REGISTRY_URL => "npmjs.org",
        GITHUB_REGISTRY_URL => "github.com",
        GITLAB_REGISTRY_URL => "gitlab.com",
        _ => panic!("unexpected builtin registry: {registry_url}"),
    }
}

async fn assert_targeted_builtin_logout_preserves_primary_session(
    project_name: &str,
    flag: &str,
    target_registry: &str,
) {
    let project = TempProject::empty(&format!(r#"{{"name":"{project_name}","version":"1.0.0"}}"#));
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-primary", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(0).await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-primary"),
                refresh_token: Some("refresh-primary"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            },
            SessionSeed {
                registry_url: NPM_REGISTRY_URL,
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITHUB_REGISTRY_URL,
                access_token: Some("github-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITLAB_REGISTRY_URL,
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
    seed_expiry_metadata(
        project.home(),
        &[
            (
                mock.url().as_str(),
                serde_json::json!({
                    "expires": "",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": "2030-01-01T00:00:00Z",
                }),
            ),
            (
                "npmjs.org",
                serde_json::json!({
                    "expires": "2030-02-01",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
            (
                "github.com",
                serde_json::json!({
                    "expires": "2030-02-02",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
            (
                "gitlab.com",
                serde_json::json!({
                    "expires": "2030-02-03",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
        ],
    );
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", flag])
        .output()
        .expect("failed to run targeted builtin logout");

    assert!(
        logout.status.success(),
        "targeted builtin logout failed for {flag}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-primary");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-primary"
    );
    assert_eq!(credentials[custom_registry], "custom-token");

    for registry_url in [NPM_REGISTRY_URL, GITHUB_REGISTRY_URL, GITLAB_REGISTRY_URL] {
        if registry_url == target_registry {
            assert!(
                credentials.get(registry_url).is_none(),
                "targeted builtin logout should remove only {target_registry}"
            );
        } else {
            assert!(
                credentials.get(registry_url).is_some(),
                "targeted builtin logout should preserve non-target builtin registry {registry_url}"
            );
        }
    }

    let tracked_custom_registries: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(custom_registries_path(project.home()))
            .expect("tracked custom registries file should remain for targeted builtin logout"),
    )
    .expect("tracked custom registries file should contain valid json");
    assert_eq!(tracked_custom_registries, vec![custom_registry.to_string()]);

    let expiry = read_expiry_metadata(project.home());
    assert!(
        expiry.get(mock.url()).is_some(),
        "targeted builtin logout should preserve primary registry session expiry metadata"
    );
    for registry_url in [NPM_REGISTRY_URL, GITHUB_REGISTRY_URL, GITLAB_REGISTRY_URL] {
        let expiry_key = builtin_expiry_key(registry_url);
        if registry_url == target_registry {
            assert!(
                expiry.get(expiry_key).is_none(),
                "targeted builtin logout should remove expiry metadata for {expiry_key}"
            );
        } else {
            assert!(
                expiry.get(expiry_key).is_some(),
                "targeted builtin logout should preserve expiry metadata for {expiry_key}"
            );
        }
    }

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami after targeted builtin logout");

    assert!(
        whoami.status.success(),
        "primary LPM session should remain usable after targeted builtin logout {flag}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}

#[tokio::test]
async fn whoami_recovers_session_from_refresh_token_only() {
    let project = TempProject::empty(r#"{"name":"auth-refresh-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
    )
    .await;
    mock.with_authenticated_whoami("access-from-refresh", "testuser", "test@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let output = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami");

    assert!(
        output.status.success(),
        "whoami with refresh-only session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "testuser");

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[&mock.url()]["session_access_expires_at"],
        "2030-01-01T00:00:00Z"
    );
}

#[tokio::test]
async fn refresh_only_session_logout_then_startup_does_not_rehydrate_again() {
    let project =
        TempProject::empty(r#"{"name":"auth-refresh-logout-chain-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_authenticated_whoami("access-from-refresh", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let first_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run initial whoami for refresh/logout chain");

    assert!(
        first_whoami.status.success(),
        "initial whoami failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let json = parse_json_output(&first_whoami.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "testuser");

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run logout in refresh/logout chain");

    assert!(
        logout.status.success(),
        "logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after a refreshed session"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove refreshed session expiry metadata"
        );
    }

    let second_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run post-logout whoami in refresh/logout chain");

    assert!(
        !second_whoami.status.success(),
        "post-logout whoami unexpectedly succeeded:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr),
    );

    let second_output = format!(
        "{}{}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr)
    );
    assert!(
        second_output.contains("Unauthorized")
            || second_output.contains("401")
            || second_output.contains("error"),
        "expected post-logout auth failure output, got: {second_output}"
    );
}

#[tokio::test]
async fn refresh_only_session_logout_all_clears_everything_and_does_not_rehydrate() {
    let project =
        TempProject::empty(r#"{"name":"auth-refresh-logout-all-chain-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_authenticated_whoami("access-from-refresh", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: None,
                refresh_token: Some("refresh-seed-token"),
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: NPM_REGISTRY_URL,
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITHUB_REGISTRY_URL,
                access_token: Some("github-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITLAB_REGISTRY_URL,
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

    let first_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run initial whoami for refresh/logout-all chain");

    assert!(
        first_whoami.status.success(),
        "initial whoami failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run logout --all in refresh/logout-all chain");

    assert!(
        logout.status.success(),
        "logout --all failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after refreshed-session recovery"
    );
    assert!(
        !custom_registries_path(project.home()).exists(),
        "logout --all should remove tracked custom registries after refreshed-session recovery"
    );

    let second_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run post-logout-all whoami in refresh/logout-all chain");

    assert!(
        !second_whoami.status.success(),
        "post-logout-all whoami unexpectedly succeeded:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr),
    );
}

#[tokio::test]
async fn invalid_access_token_entry_with_valid_refresh_token_recovers_and_normalizes_store() {
    let project =
        TempProject::empty(r#"{"name":"auth-corrupt-access-refresh-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-valid-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_authenticated_whoami("access-from-refresh", "testuser", "test@example.com")
        .await;

    write_credentials_store(
        project.home(),
        &serde_json::json!({
            mock.url(): { "corrupt": true },
            format!("refresh:{}", mock.url()): "refresh-valid-token",
        }),
    );

    let first_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with invalid access token entry");

    assert!(
        first_whoami.status.success(),
        "whoami failed to recover from invalid access token entry:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let first_json = parse_json_output(&first_whoami.stdout);
    assert_eq!(first_json["success"], true);
    assert_eq!(first_json["username"], "testuser");

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let second_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run second whoami after access-token normalization");

    assert!(
        second_whoami.status.success(),
        "second whoami failed after normalization:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr),
    );

    let second_json = parse_json_output(&second_whoami.stdout);
    assert_eq!(second_json["success"], true);
    assert_eq!(second_json["username"], "testuser");
}

#[tokio::test]
async fn malformed_session_expiry_metadata_triggers_refresh_and_rewrites_valid_expiry_state() {
    let project =
        TempProject::empty(r#"{"name":"auth-corrupt-expiry-refresh-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-valid-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_authenticated_whoami("access-from-refresh", "testuser", "test@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stale-access-token"),
            refresh_token: Some("refresh-valid-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    std::fs::write(token_expiry_path(project.home()), "{not valid json")
        .expect("failed to write malformed token expiry metadata");

    let first_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with malformed session expiry metadata");

    assert!(
        first_whoami.status.success(),
        "whoami failed to self-heal malformed session expiry metadata:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let first_json = parse_json_output(&first_whoami.stdout);
    assert_eq!(first_json["success"], true);
    assert_eq!(first_json["username"], "testuser");

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[&mock.url()]["session_access_expires_at"],
        "2030-01-01T00:00:00Z"
    );

    let second_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to rerun whoami after expiry metadata normalization");

    assert!(
        second_whoami.status.success(),
        "second whoami failed after expiry metadata normalization:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr),
    );

    let second_json = parse_json_output(&second_whoami.stdout);
    assert_eq!(second_json["success"], true);
    assert_eq!(second_json["username"], "testuser");
}

#[tokio::test]
async fn env_token_takes_precedence_over_refreshable_stored_session() {
    let project =
        TempProject::empty(r#"{"name":"auth-env-token-precedence-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-should-not-run",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        0,
    )
    .await;
    mock.with_authenticated_whoami("env-access-token", "envuser", "env@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stale-stored-access"),
            refresh_token: Some("refresh-should-not-run"),
            session_access_expires_at: Some("2000-01-01T00:00:00Z"),
        }],
    );

    let credentials_before = read_credentials(project.home());

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "env-access-token")
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with env token precedence test");

    assert!(
        output.status.success(),
        "whoami with env token precedence failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "envuser");

    let credentials_after = read_credentials(project.home());
    assert_eq!(
        credentials_after, credentials_before,
        "using LPM_TOKEN should not rewrite stored access or refresh tokens"
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[&mock.url()]["session_access_expires_at"],
        "2000-01-01T00:00:00Z",
        "using LPM_TOKEN should not mutate stored session expiry metadata"
    );
}

#[tokio::test]
async fn cli_token_takes_precedence_over_env_and_refreshable_stored_session() {
    let project =
        TempProject::empty(r#"{"name":"auth-cli-token-precedence-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-should-not-run",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        0,
    )
    .await;
    mock.with_authenticated_whoami("cli-access-token", "cliuser", "cli@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stale-stored-access"),
            refresh_token: Some("refresh-should-not-run"),
            session_access_expires_at: Some("2000-01-01T00:00:00Z"),
        }],
    );

    let credentials_before = read_credentials(project.home());

    let output = lpm_with_registry(&project, &mock.url())
        .env("LPM_TOKEN", "env-access-token")
        .args(["--token", "cli-access-token", "whoami", "--json"])
        .output()
        .expect("failed to run whoami with cli token precedence test");

    assert!(
        output.status.success(),
        "whoami with cli token precedence failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "cliuser");

    let credentials_after = read_credentials(project.home());
    assert_eq!(
        credentials_after, credentials_before,
        "using --token should not rewrite stored access or refresh tokens"
    );

    let expiry = read_expiry_metadata(project.home());
    assert_eq!(
        expiry[&mock.url()]["session_access_expires_at"],
        "2000-01-01T00:00:00Z",
        "using --token should not mutate stored session expiry metadata"
    );
}

#[tokio::test]
async fn env_token_takes_precedence_over_stored_custom_registry_token_without_mutating_tracking() {
    let project = TempProject::empty(
        r#"{"name":"auth-custom-registry-env-precedence-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;
    let custom_registry = mock.url();

    mock.with_authenticated_whoami("env-custom-token", "customenv", "customenv@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &custom_registry,
            access_token: Some("stored-custom-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );
    seed_custom_registries(project.home(), &[custom_registry.as_str()]);

    let credentials_before = read_credentials(project.home());

    let output = lpm_with_registry(&project, &custom_registry)
        .env("LPM_TOKEN", "env-custom-token")
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with custom registry env precedence test");

    assert!(
        output.status.success(),
        "whoami with custom registry env precedence failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["username"], "customenv");

    let credentials_after = read_credentials(project.home());
    assert_eq!(
        credentials_after, credentials_before,
        "using LPM_TOKEN against a custom registry should not rewrite the stored custom token"
    );

    let tracked_custom_registries: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(custom_registries_path(project.home()))
            .expect("custom registry tracking file should remain present"),
    )
    .expect("custom registry tracking file should contain valid json");

    assert_eq!(tracked_custom_registries, vec![custom_registry]);
}

#[tokio::test]
async fn malformed_custom_registry_entry_does_not_break_primary_session_and_targeted_logout_normalizes_it()
 {
    let project =
        TempProject::empty(r#"{"name":"auth-custom-registry-corruption-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-primary", "primaryuser", "primary@example.com")
        .await;

    write_credentials_store(
        project.home(),
        &serde_json::json!({
            mock.url(): "access-primary",
            format!("refresh:{}", mock.url()): "refresh-primary",
            custom_registry: {
                "unexpected": "object-shape"
            }
        }),
    );
    seed_custom_registries(project.home(), &[custom_registry]);
    mark_recent_token_validation(project.home());

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with malformed custom registry entry present");

    assert!(
        whoami.status.success(),
        "primary whoami should still succeed with unrelated malformed custom registry state:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );

    let whoami_json = parse_json_output(&whoami.stdout);
    assert_eq!(whoami_json["success"], true);
    assert_eq!(whoami_json["username"], "primaryuser");

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--logout-registry", custom_registry])
        .output()
        .expect("failed to run targeted logout for malformed custom registry entry");

    assert!(
        logout.status.success(),
        "targeted logout should normalize malformed custom registry state:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let credentials_after = read_credentials(project.home());
    assert_eq!(credentials_after[&mock.url()], "access-primary");
    assert_eq!(
        credentials_after[&format!("refresh:{}", mock.url())],
        "refresh-primary"
    );
    assert!(
        credentials_after.get(custom_registry).is_none(),
        "targeted logout should remove malformed custom registry entries from the shared auth store"
    );
    assert!(
        !custom_registries_path(project.home()).exists(),
        "targeted logout should remove stale custom-registry tracking once the malformed entry is cleared"
    );

    let second_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to rerun whoami after targeted custom registry normalization");

    assert!(
        second_whoami.status.success(),
        "primary session should remain usable after normalizing malformed custom registry state:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&second_whoami.stdout),
        String::from_utf8_lossy(&second_whoami.stderr),
    );
}

#[tokio::test]
async fn logout_prevents_startup_session_rehydration() {
    let project = TempProject::empty(r#"{"name":"auth-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh(
        "refresh-before-logout",
        "access-after-refresh",
        "refresh-after-logout-bug",
        "2030-01-01T00:00:00Z",
    )
    .await;
    mock.with_authenticated_whoami("access-before-logout", "testuser", "test@example.com")
        .await;
    mock.with_authenticated_whoami("access-after-refresh", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-before-logout"),
            refresh_token: Some("refresh-before-logout"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run lpm logout");

    assert!(
        logout.status.success(),
        "logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials file"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove session expiry metadata"
        );
    }

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami after logout");

    assert!(
        !whoami.status.success(),
        "whoami unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}

#[tokio::test]
async fn logout_all_clears_lpm_and_external_registry_state() {
    let project = TempProject::empty(r#"{"name":"auth-logout-all-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-before-logout-all", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-before-logout-all"),
                refresh_token: Some("refresh-before-logout-all"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            },
            SessionSeed {
                registry_url: NPM_REGISTRY_URL,
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITHUB_REGISTRY_URL,
                access_token: Some("github-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITLAB_REGISTRY_URL,
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
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run lpm logout --all");

    assert!(
        logout.status.success(),
        "logout --all failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove the shared credentials file when all tokens are cleared"
    );
    assert!(
        !custom_registries_path(project.home()).exists(),
        "logout --all should remove tracked custom registry state"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata for the active registry"
        );
    }

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run lpm whoami after logout --all");

    assert!(
        !whoami.status.success(),
        "whoami unexpectedly succeeded after logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}

#[tokio::test]
async fn logout_npm_clears_only_npm_registry_state() {
    assert_targeted_builtin_logout_preserves_primary_session(
        "auth-logout-npm-targeted-test",
        "--npm",
        NPM_REGISTRY_URL,
    )
    .await;
}

#[tokio::test]
async fn logout_github_clears_only_github_registry_state() {
    assert_targeted_builtin_logout_preserves_primary_session(
        "auth-logout-github-targeted-test",
        "--github",
        GITHUB_REGISTRY_URL,
    )
    .await;
}

#[tokio::test]
async fn logout_gitlab_clears_only_gitlab_registry_state() {
    assert_targeted_builtin_logout_preserves_primary_session(
        "auth-logout-gitlab-targeted-test",
        "--gitlab",
        GITLAB_REGISTRY_URL,
    )
    .await;
}

#[tokio::test]
async fn logout_npm_and_github_clear_both_targets_and_preserve_gitlab_state() {
    let project =
        TempProject::empty(r#"{"name":"auth-logout-npm-github-targeted-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-primary", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(0).await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-primary"),
                refresh_token: Some("refresh-primary"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            },
            SessionSeed {
                registry_url: NPM_REGISTRY_URL,
                access_token: Some("npm-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITHUB_REGISTRY_URL,
                access_token: Some("github-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: GITLAB_REGISTRY_URL,
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
    seed_expiry_metadata(
        project.home(),
        &[
            (
                mock.url().as_str(),
                serde_json::json!({
                    "expires": "",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": "2030-01-01T00:00:00Z",
                }),
            ),
            (
                "npmjs.org",
                serde_json::json!({
                    "expires": "2030-02-01",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
            (
                "github.com",
                serde_json::json!({
                    "expires": "2030-02-02",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
            (
                "gitlab.com",
                serde_json::json!({
                    "expires": "2030-02-03",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": null,
                }),
            ),
        ],
    );
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--npm", "--github"])
        .output()
        .expect("failed to run targeted builtin multi-logout");

    assert!(
        logout.status.success(),
        "targeted builtin multi-logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-primary");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-primary"
    );
    assert_eq!(credentials[custom_registry], "custom-token");
    assert!(credentials.get(NPM_REGISTRY_URL).is_none());
    assert!(credentials.get(GITHUB_REGISTRY_URL).is_none());
    assert_eq!(credentials[GITLAB_REGISTRY_URL], "gitlab-token");

    let expiry = read_expiry_metadata(project.home());
    assert!(expiry.get(mock.url()).is_some());
    assert!(expiry.get("npmjs.org").is_none());
    assert!(expiry.get("github.com").is_none());
    assert!(expiry.get("gitlab.com").is_some());

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami after targeted builtin multi-logout");

    assert!(
        whoami.status.success(),
        "primary LPM session should remain usable after targeted builtin multi-logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}

#[tokio::test]
async fn logout_all_normalizes_malformed_custom_registry_tracking_and_clears_file_backed_tokens() {
    let project = TempProject::empty(
        r#"{"name":"auth-logout-all-malformed-custom-tracking-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-before-logout-all", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-before-logout-all"),
                refresh_token: Some("refresh-before-logout-all"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            },
            SessionSeed {
                registry_url: custom_registry,
                access_token: Some("custom-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
        ],
    );
    std::fs::write(custom_registries_path(project.home()), "{not valid json")
        .expect("failed to write malformed custom registry tracking file");
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run lpm logout --all with malformed custom tracking");

    assert!(
        logout.status.success(),
        "logout --all should recover from malformed custom registry tracking:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should still clear the shared credentials file when malformed custom tracking hid a stored custom token; leftover store: {:?}",
        if credentials_path(project.home()).exists() {
            Some(read_credentials(project.home()))
        } else {
            None
        }
    );
    assert!(
        !custom_registries_path(project.home()).exists(),
        "logout --all should remove malformed custom-registry tracking after normalizing file-backed state"
    );

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami after logout --all normalization");

    assert!(
        !whoami.status.success(),
        "whoami unexpectedly succeeded after logout --all normalized malformed custom tracking:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}

#[tokio::test]
async fn logout_skips_browser_pairing_revocation_without_refresh_token() {
    let project =
        TempProject::empty(r#"{"name":"auth-logout-access-only-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_revoke_all_pairings_expected(0).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-without-refresh"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run lpm logout for access-only session");

    assert!(
        logout.status.success(),
        "logout for access-only session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should clear local credentials even when no pairing revocation runs"
    );
}

#[tokio::test]
async fn logout_clears_recent_token_validation_marker() {
    let project =
        TempProject::empty(r#"{"name":"auth-logout-token-check-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("access-before-logout"),
            refresh_token: Some("refresh-before-logout"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    mark_recent_token_validation(project.home());

    let token_check_path = project.home().join(".lpm").join(".token-check");
    assert!(
        token_check_path.exists(),
        "test setup should create the recent token validation marker"
    );

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run lpm logout for token-check cleanup");

    assert!(
        logout.status.success(),
        "logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !token_check_path.exists(),
        "logout should remove the recent token validation marker"
    );
}

#[tokio::test]
async fn logout_registry_clears_only_targeted_custom_registry_state() {
    let project =
        TempProject::empty(r#"{"name":"auth-logout-custom-registry-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let custom_registry_a = "https://packages.example.internal/npm";
    let custom_registry_b = "https://mirror.example.internal/npm";

    mock.with_authenticated_whoami("access-primary", "testuser", "test@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[
            SessionSeed {
                registry_url: &mock.url(),
                access_token: Some("access-primary"),
                refresh_token: Some("refresh-primary"),
                session_access_expires_at: Some("2030-01-01T00:00:00Z"),
            },
            SessionSeed {
                registry_url: custom_registry_a,
                access_token: Some("custom-a-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
            SessionSeed {
                registry_url: custom_registry_b,
                access_token: Some("custom-b-token"),
                refresh_token: None,
                session_access_expires_at: None,
            },
        ],
    );
    seed_custom_registries(project.home(), &[custom_registry_a, custom_registry_b]);
    mark_recent_token_validation(project.home());

    let logout = lpm_with_registry(&project, &mock.url())
        .args(["logout", "--logout-registry", custom_registry_a])
        .output()
        .expect("failed to run targeted custom-registry logout");

    assert!(
        logout.status.success(),
        "targeted custom-registry logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "access-primary");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-primary"
    );
    assert_eq!(credentials[custom_registry_b], "custom-b-token");
    assert!(
        credentials.get(custom_registry_a).is_none(),
        "targeted logout should remove only the requested custom registry token"
    );

    let tracked_custom_registries: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(custom_registries_path(project.home()))
            .expect("tracked custom registries file should remain for other entries"),
    )
    .expect("tracked custom registries file should contain valid json");

    assert_eq!(
        tracked_custom_registries,
        vec![custom_registry_b.to_string()]
    );

    let whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami after targeted custom-registry logout");

    assert!(
        whoami.status.success(),
        "primary LPM session should remain usable after targeted custom-registry logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&whoami.stdout),
        String::from_utf8_lossy(&whoami.stderr),
    );
}
