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
use support::{TempProject, lpm, lpm_spawnable, lpm_with_registry};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

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

#[cfg(unix)]
fn write_fake_host_command(dir: &std::path::Path, name: &str, script: &str) {
    let path = dir.join(name);
    std::fs::write(&path, script).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
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

    insta::with_settings!({
        sort_maps => true,
        filters => vec![
            (r"http://127\.0\.0\.1:\d+", "[MOCK]"),
            (r#"/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/private/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/tmp/[^"\s]+"#, "[TEMP]"),
        ],
    }, {
        insta::assert_json_snapshot!(
            "whoami_json_envelope_recovers_from_refresh_only",
            json,
            { ".duration_ms" => "[DURATION]" }
        );
    });
}

#[tokio::test]
async fn login_uses_refresh_session_before_starting_browser_flow() {
    let project =
        TempProject::empty(r#"{"name":"login-refresh-preflight-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer expired-access"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(mock.server())
        .await;
    mock.with_refresh_expected(
        "valid-refresh",
        "rotated-access",
        "rotated-refresh",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_authenticated_whoami("rotated-access", "testuser", "test@example.com")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("expired-access"),
            refresh_token: Some("valid-refresh"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );

    let mut command = lpm_spawnable(&project);
    command
        .args(["--registry", &mock.url(), "--insecure", "login", "--json"])
        .env("BROWSER", "false");
    let mut child = command.spawn().expect("failed to spawn lpm login");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .expect("failed to poll lpm login")
            .is_some()
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("failed to stop stuck browser login");
            let output = child
                .wait_with_output()
                .expect("failed to collect stuck login output");
            panic!(
                "login started the browser callback flow instead of refreshing:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let output = child
        .wait_with_output()
        .expect("failed to collect login output");
    assert!(
        output.status.success(),
        "refresh-backed login preflight failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn login_reports_a_transient_preflight_failure_without_starting_browser_authentication() {
    let project = TempProject::empty(r#"{"name":"login-transient-preflight","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer valid-access"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
        .expect(4)
        .mount(mock.server())
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("valid-access"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
            ..Default::default()
        }],
    );

    let mut command = lpm_spawnable(&project);
    command
        .args(["--registry", &mock.url(), "--insecure", "login", "--json"])
        .env("BROWSER", "false")
        .env("LPM_RETRY_BACKOFF_MS_OVERRIDE", "0");
    let mut child = command.spawn().expect("failed to spawn lpm login");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .expect("failed to poll lpm login")
            .is_some()
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("failed to stop stuck browser login");
            let output = child
                .wait_with_output()
                .expect("failed to collect stuck login output");
            panic!(
                "login started browser authentication after a transient preflight failure:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let output = child
        .wait_with_output()
        .expect("failed to collect login output");
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let envelope = parse_json_output(&output.stdout);
    assert_eq!(envelope["error_code"], serde_json::json!("http"));
    assert!(
        envelope["error"]
            .as_str()
            .is_some_and(|message| message.contains("503"))
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
    mock.with_revoke_all_pairings_expected(0).await;

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
    mock.with_revoke_all_pairings_expected(0).await;

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
async fn invalid_access_token_entry_reports_failure_and_preserves_credential_store() {
    let project =
        TempProject::empty(r#"{"name":"auth-corrupt-access-refresh-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-valid-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        0,
    )
    .await;

    let original_credentials = serde_json::json!({
        mock.url(): { "corrupt": true },
        format!("refresh:{}", mock.url()): "refresh-valid-token",
    });
    write_credentials_store(project.home(), &original_credentials);

    let first_whoami = lpm_with_registry(&project, &mock.url())
        .args(["whoami", "--json"])
        .output()
        .expect("failed to run whoami with invalid access token entry");

    assert!(
        !first_whoami.status.success(),
        "whoami accepted an invalid access token entry:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let first_json = parse_json_output(&first_whoami.stdout);
    assert_eq!(first_json["success"], false);
    assert_eq!(first_json["error_code"], "credential_storage");
    assert!(
        first_json["error"]
            .as_str()
            .is_some_and(|error| error.contains("credential entry is not a string"))
    );
    assert_eq!(read_credentials(project.home()), original_credentials);
}

#[tokio::test]
async fn malformed_session_expiry_metadata_is_reported_before_authenticated_request() {
    let project =
        TempProject::empty(r#"{"name":"auth-corrupt-expiry-refresh-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_refresh_expected(
        "refresh-valid-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        0,
    )
    .await;
    mock.with_authenticated_whoami_error("stale-access-token", 401, 0)
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
        !first_whoami.status.success(),
        "whoami replaced malformed session expiry metadata:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&first_whoami.stdout),
        String::from_utf8_lossy(&first_whoami.stderr),
    );

    let first_json = parse_json_output(&first_whoami.stdout);
    assert_eq!(first_json["success"], false);
    assert_eq!(first_json["error_code"], "credential_storage");
    assert!(
        first_json["error"]
            .as_str()
            .is_some_and(|error| error.contains("token-expiry metadata JSON error"))
    );

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[&mock.url()], "stale-access-token");
    assert_eq!(
        credentials[&format!("refresh:{}", mock.url())],
        "refresh-valid-token"
    );

    assert_eq!(
        std::fs::read_to_string(token_expiry_path(project.home()))
            .expect("failed to read preserved token expiry metadata"),
        "{not valid json"
    );
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
async fn rejected_explicit_token_preserves_stored_session_credentials() {
    let project =
        TempProject::empty(r#"{"name":"auth-explicit-token-rejection-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .and(header("authorization", "Bearer rejected-explicit-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(mock.server())
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("stored-access-token"),
            refresh_token: Some("stored-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let credentials_before = read_credentials(project.home());

    let output = lpm_with_registry(&project, &mock.url())
        .args(["--token", "rejected-explicit-token", "whoami", "--json"])
        .output()
        .expect("failed to run whoami with rejected explicit token");

    assert!(
        !output.status.success(),
        "rejected explicit token unexpectedly succeeded:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        read_credentials(project.home()),
        credentials_before,
        "rejecting an explicit token must not delete an unrelated stored session"
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
    mock.with_revoke_all_pairings_expected(0).await;

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
        .args(["--json", "logout"])
        .output()
        .expect("failed to run lpm logout");

    assert!(
        logout.status.success(),
        "logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let logout_envelope = parse_json_output(&logout.stdout);
    assert_eq!(logout_envelope["success"], serde_json::json!(true));

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
    mock.with_revoke_all_pairings_expected(0).await;

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
        .args(["--json", "logout", "--all"])
        .output()
        .expect("failed to run lpm logout --all");

    assert!(
        logout.status.success(),
        "logout --all failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    let logout_envelope = parse_json_output(&logout.stdout);
    assert_eq!(logout_envelope["success"], serde_json::json!(true));

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
async fn logout_all_reports_malformed_custom_registry_tracking_after_clearing_discovered_tokens() {
    let project = TempProject::empty(
        r#"{"name":"auth-logout-all-malformed-custom-tracking-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;
    let custom_registry = "https://packages.example.internal/npm";

    mock.with_authenticated_whoami("access-before-logout-all", "testuser", "test@example.com")
        .await;
    mock.with_revoke_all_pairings_expected(0).await;

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
        .args(["--json", "logout", "--all"])
        .output()
        .expect("failed to run lpm logout --all with malformed custom tracking");

    assert!(
        !logout.status.success(),
        "logout --all must report malformed custom registry tracking:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );
    let envelope = parse_json_output(&logout.stdout);
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["local_cleared"], serde_json::json!(false));
    assert!(
        envelope["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| {
                error
                    .as_str()
                    .is_some_and(|error| error.contains("custom registry tracking"))
            })),
        "logout error must identify custom registry tracking cleanup: {envelope}"
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
        custom_registries_path(project.home()).exists(),
        "logout --all must preserve malformed custom-registry tracking for inspection"
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

    mock.with_revoke_all_pairings_expected(0).await;

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

// ─── --json error envelope contracts for login --npm/--github/--gitlab/--login-registry ───
//
// These tests pin the machine-readable login contracts for third-party targets.

#[test]
fn login_npm_without_token_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"login-npm-noauth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "login", "--npm"])
        .output()
        .expect("failed to run lpm --json login --npm");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json login --npm must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("interactive terminal")
            && err.contains("--token")
            && err.contains("NPM_TOKEN"),
        "error must direct non-interactive npm login to TTY, --token, or NPM_TOKEN, got: {err}",
    );
}

#[test]
fn login_github_without_token_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"login-gh-noauth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "login", "--github"])
        .output()
        .expect("failed to run lpm --json login --github");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json login --github must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("gh auth login") && err.contains("--token") && err.contains("GITHUB_TOKEN"),
        "error must direct user to gh auth, --token, or GITHUB_TOKEN, got: {err}",
    );
}

#[test]
fn login_gitlab_without_token_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"login-gl-noauth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "login", "--gitlab"])
        .output()
        .expect("failed to run lpm --json login --gitlab");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("--json login --gitlab must emit JSON: {e}\n---\n{stdout}"));
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("glab auth login") && err.contains("--token") && err.contains("GITLAB_TOKEN"),
        "error must direct user to glab auth, --token, or GitLab token env, got: {err}",
    );
}

#[test]
fn login_npm_with_explicit_token_under_json_stores_fallback_token() {
    let project = TempProject::empty(r#"{"name":"login-npm-token","version":"1.0.0"}"#);
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .args(["--json", "login", "--npm", "--token", "npm-fallback-token"])
        .output()
        .expect("failed to run lpm --json login --npm --token");

    assert!(
        output.status.success(),
        "explicit npm token login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["source"], serde_json::json!("explicit-token"));
    assert_eq!(json["stored"], serde_json::json!(true));

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[NPM_REGISTRY_URL], "npm-fallback-token");
}

#[test]
fn login_npm_with_env_token_under_json_stores_fallback_token() {
    let project = TempProject::empty(r#"{"name":"login-npm-env-token","version":"1.0.0"}"#);
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .env("NPM_TOKEN", "npm-env-token")
        .args(["--json", "login", "--npm"])
        .output()
        .expect("failed to run lpm --json login --npm with NPM_TOKEN");

    assert!(
        output.status.success(),
        "npm env-token login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["source"], serde_json::json!("env:NPM_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(true));

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[NPM_REGISTRY_URL], "npm-env-token");
}

#[test]
fn login_github_with_explicit_token_under_json_stores_fallback_token() {
    let project = TempProject::empty(r#"{"name":"login-gh-token","version":"1.0.0"}"#);
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .args([
            "--json",
            "login",
            "--github",
            "--token",
            "github-fallback-token",
        ])
        .output()
        .expect("failed to run lpm --json login --github --token");

    assert!(
        output.status.success(),
        "explicit GitHub token login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["source"], serde_json::json!("explicit-token"));
    assert_eq!(json["stored"], serde_json::json!(true));

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[GITHUB_REGISTRY_URL], "github-fallback-token");
}

#[test]
fn login_gitlab_with_explicit_token_under_json_stores_fallback_token() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-token","version":"1.0.0"}"#);
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .args([
            "--json",
            "login",
            "--gitlab",
            "--token",
            "gitlab-fallback-token",
        ])
        .output()
        .expect("failed to run lpm --json login --gitlab --token");

    assert!(
        output.status.success(),
        "explicit GitLab token login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], serde_json::json!(true));
    assert_eq!(json["source"], serde_json::json!("explicit-token"));
    assert_eq!(json["stored"], serde_json::json!(true));

    let credentials = read_credentials(project.home());
    assert_eq!(credentials[GITLAB_REGISTRY_URL], "gitlab-fallback-token");
}

#[test]
fn login_github_with_environment_token_reports_transient_auth_without_storing_it() {
    let project = TempProject::empty(r#"{"name":"login-gh-env","version":"1.0.0"}"#);
    let secret = "github-environment-secret";

    let output = lpm(&project)
        .env("GITHUB_TOKEN", secret)
        .args(["--json", "login", "--github"])
        .output()
        .expect("failed to run lpm --json login --github with GITHUB_TOKEN");

    assert!(
        output.status.success(),
        "GitHub environment login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:GITHUB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert_eq!(json["storage_backend"], serde_json::Value::Null);
    assert_eq!(json["storage_degraded"], serde_json::json!(false));
    assert!(
        !credentials_path(project.home()).exists(),
        "transient GitHub environment login must not create credential storage"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));

    insta::assert_json_snapshot!("login_github_environment_token_is_transient", json);
}

#[test]
fn login_gitlab_with_environment_token_reports_transient_auth_without_storing_it() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-env","version":"1.0.0"}"#);
    let secret = "gitlab-environment-secret";

    let output = lpm(&project)
        .env("GITLAB_TOKEN", secret)
        .args(["--json", "login", "--gitlab"])
        .output()
        .expect("failed to run lpm --json login --gitlab with GITLAB_TOKEN");

    assert!(
        output.status.success(),
        "GitLab environment login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:GITLAB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert!(
        !credentials_path(project.home()).exists(),
        "transient GitLab environment login must not create credential storage"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

#[test]
fn login_gitlab_with_ci_job_token_reports_transient_auth_without_storing_it() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-ci-env","version":"1.0.0"}"#);
    let secret = "gitlab-ci-job-secret";

    let output = lpm(&project)
        .env("CI_JOB_TOKEN", secret)
        .args(["--json", "login", "--gitlab"])
        .output()
        .expect("failed to run lpm --json login --gitlab with CI_JOB_TOKEN");

    assert!(
        output.status.success(),
        "GitLab CI job login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:CI_JOB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert!(
        !credentials_path(project.home()).exists(),
        "transient GitLab CI job login must not create credential storage"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

#[test]
fn login_gitlab_prefers_gitlab_token_over_ci_job_token() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-env-precedence","version":"1.0.0"}"#);
    let gitlab_secret = "gitlab-preferred-secret";
    let ci_secret = "gitlab-ci-lower-priority-secret";

    let output = lpm(&project)
        .env("GITLAB_TOKEN", gitlab_secret)
        .env("CI_JOB_TOKEN", ci_secret)
        .args(["--json", "login", "--gitlab"])
        .output()
        .expect("failed to run lpm --json login --gitlab with both environment tokens");

    assert!(output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:GITLAB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(gitlab_secret));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ci_secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(gitlab_secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(ci_secret));
}

#[test]
fn login_github_explicit_token_overrides_environment_token() {
    let project =
        TempProject::empty(r#"{"name":"login-gh-explicit-precedence","version":"1.0.0"}"#);
    let environment_secret = "github-lower-priority-secret";
    let explicit_secret = "github-explicit-secret";
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .env("GITHUB_TOKEN", environment_secret)
        .args(["--json", "login", "--github", "--token", explicit_secret])
        .output()
        .expect("failed to run explicit GitHub login with GITHUB_TOKEN set");

    assert!(output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("explicit-token"));
    assert_eq!(json["stored"], serde_json::json!(true));
    assert_eq!(
        read_credentials(project.home())[GITHUB_REGISTRY_URL],
        explicit_secret
    );
    for secret in [environment_secret, explicit_secret] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[test]
fn login_github_save_env_token_rejects_global_token_before_storage() {
    let project =
        TempProject::empty(r#"{"name":"login-gh-global-token-conflict","version":"1.0.0"}"#);
    let explicit_secret = "github-global-explicit-secret";
    let environment_secret = "github-global-environment-secret";
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .env("GITHUB_TOKEN", environment_secret)
        .args([
            "--json",
            "--token",
            explicit_secret,
            "login",
            "--github",
            "--save-env-token",
        ])
        .output()
        .expect("failed to run conflicting global token import");

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["error_code"], serde_json::json!("usage"));
    assert_eq!(json["kind"], serde_json::json!("argument_conflict"));
    assert_eq!(read_credentials(project.home()), serde_json::json!({}));
    for secret in [explicit_secret, environment_secret] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[test]
fn login_github_save_env_token_persists_environment_credential() {
    let project = TempProject::empty(r#"{"name":"login-gh-env-import","version":"1.0.0"}"#);
    let secret = "github-import-secret";
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .env("GITHUB_TOKEN", secret)
        .args(["--json", "login", "--github", "--save-env-token"])
        .output()
        .expect("failed to import GITHUB_TOKEN");

    assert!(
        output.status.success(),
        "GitHub environment import should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:GITHUB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(true));
    assert_eq!(
        read_credentials(project.home())[GITHUB_REGISTRY_URL],
        secret
    );
    let encrypted = std::fs::read_to_string(credentials_path(project.home()))
        .expect("encrypted credential file should exist");
    assert!(!encrypted.contains(secret));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

#[test]
fn login_gitlab_save_env_token_persists_environment_credential() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-env-import","version":"1.0.0"}"#);
    let secret = "gitlab-import-secret";
    write_credentials_store(project.home(), &serde_json::json!({}));

    let output = lpm(&project)
        .env("GITLAB_TOKEN", secret)
        .args(["--json", "login", "--gitlab", "--save-env-token"])
        .output()
        .expect("failed to import GITLAB_TOKEN");

    assert!(
        output.status.success(),
        "GitLab environment import should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("env:GITLAB_TOKEN"));
    assert_eq!(json["stored"], serde_json::json!(true));
    assert_eq!(
        read_credentials(project.home())[GITLAB_REGISTRY_URL],
        secret
    );
    let encrypted = std::fs::read_to_string(credentials_path(project.home()))
        .expect("encrypted credential file should exist");
    assert!(!encrypted.contains(secret));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

#[test]
fn login_gitlab_save_env_token_rejects_ci_job_token_without_mutation() {
    let project = TempProject::empty(r#"{"name":"login-gitlab-ci-import","version":"1.0.0"}"#);
    let secret = "gitlab-ci-rejected-secret";
    write_credentials_store(
        project.home(),
        &serde_json::json!({ GITLAB_REGISTRY_URL: "stored-token-before-import" }),
    );

    let output = lpm(&project)
        .env("CI_JOB_TOKEN", secret)
        .args(["--json", "login", "--gitlab", "--save-env-token"])
        .output()
        .expect("failed to run rejected CI_JOB_TOKEN import");

    assert!(!output.status.success(), "CI_JOB_TOKEN import must fail");
    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["error_code"],
        serde_json::json!("credential_import_rejected")
    );
    assert_eq!(
        read_credentials(project.home())[GITLAB_REGISTRY_URL],
        "stored-token-before-import"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));

    insta::assert_json_snapshot!("login_gitlab_rejects_ci_job_token_import", json);
}

#[test]
fn login_github_save_env_token_requires_github_token_without_mutation() {
    let project = TempProject::empty(r#"{"name":"login-gh-env-import-missing","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "login", "--github", "--save-env-token"])
        .output()
        .expect("failed to run GitHub environment import without GITHUB_TOKEN");

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["error_code"],
        serde_json::json!("credential_import_unavailable")
    );
    assert_eq!(json["error"]["expected"], serde_json::json!("GITHUB_TOKEN"));
    assert!(!credentials_path(project.home()).exists());
}

#[test]
fn login_gitlab_save_env_token_requires_gitlab_token_without_mutation() {
    let project =
        TempProject::empty(r#"{"name":"login-gitlab-env-import-missing","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "login", "--gitlab", "--save-env-token"])
        .output()
        .expect("failed to run GitLab environment import without GITLAB_TOKEN");

    assert!(!output.status.success());
    let json = parse_json_output(&output.stdout);
    assert_eq!(
        json["error_code"],
        serde_json::json!("credential_import_unavailable")
    );
    assert_eq!(json["error"]["expected"], serde_json::json!("GITLAB_TOKEN"));
    assert!(!credentials_path(project.home()).exists());
}

#[test]
fn login_github_with_stored_token_reports_persistent_auth_source() {
    let project = TempProject::empty(r#"{"name":"login-gh-stored","version":"1.0.0"}"#);
    write_credentials_store(
        project.home(),
        &serde_json::json!({ GITHUB_REGISTRY_URL: "github-stored-secret" }),
    );

    let output = lpm(&project)
        .args(["--json", "login", "--github"])
        .output()
        .expect("failed to run lpm --json login --github with stored token");

    assert!(
        output.status.success(),
        "stored GitHub login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("stored"));
    assert_eq!(json["stored"], serde_json::json!(true));
    assert_eq!(
        json["storage_backend"],
        serde_json::json!("encrypted_file_fallback")
    );
    assert_eq!(json["storage_degraded"], serde_json::json!(true));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("github-stored-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("github-stored-secret"));
}

#[cfg(unix)]
#[test]
fn login_github_with_gh_auth_under_json_does_not_store_cli_token() {
    let project = TempProject::empty(r#"{"name":"login-gh-cli","version":"1.0.0"}"#);
    let bin = tempfile::tempdir().expect("failed to create fake bin dir");
    write_fake_host_command(
        bin.path(),
        "gh",
        "#!/bin/sh\n[ \"$1\" = auth ] && [ \"$2\" = token ] && printf 'gh-cli-token\\n'\n",
    );

    let output = lpm(&project)
        .env("PATH", bin.path())
        .env_remove("LPM_DISABLE_HOST_CLI_AUTH")
        .args(["--json", "login", "--github"])
        .output()
        .expect("failed to run lpm --json login --github with fake gh");

    assert!(
        output.status.success(),
        "GitHub CLI backed login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("gh"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert!(
        !credentials_path(project.home()).exists(),
        "gh-backed login must not copy the GitHub CLI token into LPM storage"
    );
}

#[cfg(unix)]
#[test]
fn login_gitlab_with_glab_auth_under_json_does_not_store_cli_token() {
    let project = TempProject::empty(r#"{"name":"login-glab-cli","version":"1.0.0"}"#);
    let bin = tempfile::tempdir().expect("failed to create fake bin dir");
    write_fake_host_command(
        bin.path(),
        "glab",
        "#!/bin/sh\n[ \"$1\" = auth ] && [ \"$2\" = token ] && printf 'glab-cli-token\\n'\n",
    );

    let output = lpm(&project)
        .env("PATH", bin.path())
        .env_remove("LPM_DISABLE_HOST_CLI_AUTH")
        .args(["--json", "login", "--gitlab"])
        .output()
        .expect("failed to run lpm --json login --gitlab with fake glab");

    assert!(
        output.status.success(),
        "GitLab CLI backed login should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let json = parse_json_output(&output.stdout);
    assert_eq!(json["source"], serde_json::json!("glab"));
    assert_eq!(json["stored"], serde_json::json!(false));
    assert!(
        !credentials_path(project.home()).exists(),
        "glab-backed login must not copy the GitLab CLI token into LPM storage"
    );
}

#[test]
fn login_custom_registry_without_token_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"login-custom-noauth","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--json",
            "login",
            "--login-registry",
            "https://packages.example.invalid",
        ])
        .output()
        .expect("failed to run lpm --json login --login-registry");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json login --login-registry must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    let err = envelope["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("--token"),
        "error must reference --token requirement, got: {err}",
    );
}
