mod support;

use support::{TempProject, lpm_with_registry, mock_registry::MockRegistry};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn device_login_json_starts_without_a_browser_and_completes_on_the_execution_host() {
    let project = TempProject::empty(r#"{"name":"device-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    support::auth_state::seed_sessions(project.home(), &[]);
    let output = lpm_with_registry(&project, &registry.url())
        .args(["login", "--device", "--json"])
        .env("BROWSER", "false")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let started: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(started["success"], true);
    assert_eq!(started["status"], "authorization_pending");
    insta::assert_json_snapshot!("device_login_pending_envelope", started, {
        ".login_id" => "[login-id]",
        ".registry" => "[registry]",
        ".verification_uri" => "[verification-uri]",
        ".request_code" => "[request-code]",
        ".expires_at" => "[expires-at]",
    });
    let id = started["login_id"].as_str().unwrap();
    let url = reqwest::Url::parse(started["verification_uri"].as_str().unwrap()).unwrap();
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "mode" && value == "device")
    );
    assert!(
        !url.query_pairs()
            .any(|(key, _)| key == "port" || key == "code_verifier")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("code_verifier"));
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );

    Mock::given(method("POST"))
        .and(path("/api/cli/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "device-access",
            "refreshToken": "device-refresh",
            "expiresIn": 3600,
            "expiresAt": "2030-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(registry.server())
        .await;
    registry
        .with_authenticated_whoami("device-access", "testuser", "test@example.com")
        .await;
    let output = lpm_with_registry(&project, &registry.url())
        .args(["login", "--complete", id, "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let completed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(completed["success"], true);
    assert_eq!(completed["username"], "testuser");
    insta::assert_json_snapshot!("device_login_completed_envelope", completed, {
        ".registry" => "[registry]",
    });
    let requests = registry.server().received_requests().await.unwrap();
    let poll = requests
        .iter()
        .find(|request| request.url.path() == "/api/cli/device")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&poll.body).unwrap();
    use base64::Engine;
    use sha2::Digest;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
        body["code_verifier"].as_str().unwrap().as_bytes(),
    ));
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "code_challenge" && value == expected)
    );
    assert!(!poll.headers.contains_key("authorization"));
    let credentials = support::auth_state::read_credentials(project.home());
    assert_eq!(credentials[&registry.url()], "device-access");
    assert_eq!(
        credentials[&format!("refresh:{}", registry.url())],
        "device-refresh"
    );
    assert!(
        !project
            .home()
            .join(".lpm/login-requests")
            .join(format!("{id}.json"))
            .exists()
    );
}

fn start(project: &TempProject, registry: &MockRegistry) -> serde_json::Value {
    let output = lpm_with_registry(project, &registry.url())
        .args(["login", "--device", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn device_login_does_not_save_a_session_rejected_by_whoami() {
    let project = TempProject::empty(r#"{"name":"rejected-session","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let started = start(&project, &registry);
    Mock::given(method("POST"))
        .and(path("/api/cli/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token": "invalid-access",
            "refreshToken": "device-refresh",
            "expiresIn": 3600,
            "expiresAt": "2030-01-01T00:00:00Z",
        })))
        .mount(registry.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/-/whoami"))
        .respond_with(ResponseTemplate::new(401))
        .mount(registry.server())
        .await;
    let output = lpm_with_registry(&project, &registry.url())
        .args([
            "login",
            "--complete",
            started["login_id"].as_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("verification failed")
    );
    assert!(!project.home().join(".lpm/.credentials").exists());
}

#[tokio::test]
async fn device_login_modes_reject_third_party_and_explicit_token_flags() {
    let project = TempProject::empty(r#"{"name":"login-flags","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    for flags in [
        vec!["--device", "--npm"],
        vec!["--device", "--token", "secret"],
        vec!["--device", "--complete", "0123456789abcdef0123456789abcdef"],
        vec!["--complete", "0123456789abcdef0123456789abcdef", "--github"],
    ] {
        let output = lpm_with_registry(&project, &registry.url())
            .arg("login")
            .args(flags)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!project.home().join(".lpm/login-requests").exists());
}

#[tokio::test]
async fn device_login_pending_poll_keeps_the_private_request_for_later_completion() {
    let project = TempProject::empty(r#"{"name":"pending-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let started = start(&project, &registry);
    let id = started["login_id"].as_str().unwrap();
    Mock::given(method("POST"))
        .and(path("/api/cli/device"))
        .respond_with(ResponseTemplate::new(202).insert_header("retry-after", "7"))
        .expect(1)
        .mount(registry.server())
        .await;
    let output = lpm_with_registry(&project, &registry.url())
        .args(["login", "--complete", id, "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pending: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pending["status"], "authorization_pending");
    assert_eq!(pending["interval"], 7);
    assert_eq!(pending["login_id"], id);
    let state_path = project
        .home()
        .join(".lpm/login-requests")
        .join(format!("{id}.json"));
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert!(state["code_verifier"].is_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!project.home().join(".lpm/.credentials").exists());
}

#[tokio::test]
async fn device_login_never_sends_the_verifier_to_a_redirect_target() {
    let project = TempProject::empty(r#"{"name":"redirect-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let target = MockRegistry::start().await;
    let started = start(&project, &registry);
    Mock::given(method("POST"))
        .and(path("/api/cli/device"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/stolen", target.url())),
        )
        .mount(registry.server())
        .await;
    let output = lpm_with_registry(&project, &registry.url())
        .args([
            "login",
            "--complete",
            started["login_id"].as_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        target
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn device_login_rejects_expired_requests_before_network_access() {
    let project = TempProject::empty(r#"{"name":"expired-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let started = start(&project, &registry);
    let id = started["login_id"].as_str().unwrap();
    let state_path = project
        .home()
        .join(".lpm/login-requests")
        .join(format!("{id}.json"));
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["expires_at"] = 1.into();
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let output = lpm_with_registry(&project, &registry.url())
        .args(["login", "--complete", id, "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!state_path.exists());
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn device_login_rejects_another_registry_before_sending_the_verifier() {
    let project = TempProject::empty(r#"{"name":"registry-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let target = MockRegistry::start().await;
    let started = start(&project, &registry);
    let output = lpm_with_registry(&project, &target.url())
        .args([
            "login",
            "--complete",
            started["login_id"].as_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        target
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn device_login_rejects_incomplete_or_oversized_sessions_without_storing_credentials() {
    for body in [
        serde_json::json!({"token":"incomplete"}),
        serde_json::json!({"token":"x".repeat(128 * 1024)}),
    ] {
        let project = TempProject::empty(r#"{"name":"malformed-login","version":"1.0.0"}"#);
        let registry = MockRegistry::start().await;
        let started = start(&project, &registry);
        Mock::given(method("POST"))
            .and(path("/api/cli/device"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(registry.server())
            .await;
        let output = lpm_with_registry(&project, &registry.url())
            .args([
                "login",
                "--complete",
                started["login_id"].as_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!project.home().join(".lpm/.credentials").exists());
    }
}

#[tokio::test]
async fn login_without_a_session_returns_json_instructions_instead_of_waiting_for_a_hidden_callback()
 {
    let project = TempProject::empty(r#"{"name":"json-login","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let output = lpm_with_registry(&project, &registry.url())
        .args(["login", "--json"])
        .timeout(std::time::Duration::from_secs(5))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["success"], false);
    assert_eq!(error["error_code"], "registry");
    assert!(error["error"].as_str().unwrap().contains("--device"));
}

#[tokio::test]
async fn device_login_declined_or_consumed_requests_are_retired_without_saving_credentials() {
    for status in [403, 410] {
        let project = TempProject::empty(r#"{"name":"retired-login","version":"1.0.0"}"#);
        let registry = MockRegistry::start().await;
        let started = start(&project, &registry);
        let id = started["login_id"].as_str().unwrap();
        Mock::given(method("POST"))
            .and(path("/api/cli/device"))
            .respond_with(ResponseTemplate::new(status))
            .mount(registry.server())
            .await;
        let output = lpm_with_registry(&project, &registry.url())
            .args(["login", "--complete", id, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            !project
                .home()
                .join(".lpm/login-requests")
                .join(format!("{id}.json"))
                .exists()
        );
        assert!(!project.home().join(".lpm/.credentials").exists());
    }
}

#[tokio::test]
async fn device_login_outages_and_rate_limits_keep_the_request_and_return_actionable_json_errors() {
    for status in [429, 503] {
        let project = TempProject::empty(r#"{"name":"retry-login","version":"1.0.0"}"#);
        let registry = MockRegistry::start().await;
        let started = start(&project, &registry);
        let id = started["login_id"].as_str().unwrap();
        Mock::given(method("POST"))
            .and(path("/api/cli/device"))
            .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "9"))
            .mount(registry.server())
            .await;
        let output = lpm_with_registry(&project, &registry.url())
            .args(["login", "--complete", id, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            error["error_code"],
            if status == 429 {
                "rate_limited"
            } else {
                "registry"
            }
        );
        assert!(
            project
                .home()
                .join(".lpm/login-requests")
                .join(format!("{id}.json"))
                .exists()
        );
    }
}

#[tokio::test]
#[cfg(unix)]
async fn device_login_rejects_a_saved_request_symlink_without_network_access() {
    #[cfg(unix)]
    {
        let project = TempProject::empty(r#"{"name":"linked-login","version":"1.0.0"}"#);
        let registry = MockRegistry::start().await;
        let started = start(&project, &registry);
        let id = started["login_id"].as_str().unwrap();
        let path = project
            .home()
            .join(".lpm/login-requests")
            .join(format!("{id}.json"));
        let target = project.path().join("target.json");
        std::fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let output = lpm_with_registry(&project, &registry.url())
            .args(["login", "--complete", id, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            registry
                .server()
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(target.exists());
    }
}

#[tokio::test]
async fn device_login_rejects_path_traversal_ids_before_network_access() {
    let project = TempProject::empty(r#"{"name":"invalid-id","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    for id in [
        "../credentials",
        "/tmp/request",
        "invalid",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let output = lpm_with_registry(&project, &registry.url())
            .args(["login", "--complete", id, "--json"])
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
    assert!(
        registry
            .server()
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}
