mod support;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use p256::SecretKey as P256SecretKey;
use support::assertions::parse_json_output;
use support::auth_state::{
    SessionSeed, credentials_path, read_credentials, read_expiry_metadata, seed_sessions,
    token_expiry_path,
};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm};

fn write_file_backed_vault(home: &std::path::Path, vault_id: &str, payload: serde_json::Value) {
    let lpm_dir = home.join(".lpm");
    let vaults_dir = lpm_dir.join("vaults");
    std::fs::create_dir_all(&vaults_dir).expect("failed to create test vault directory");

    let fallback_key = "workflow-test-fallback-key-workflow-test-fallback-key-123456";
    let salt = [0x42u8; 32];
    std::fs::write(lpm_dir.join(".vault-fallback-key"), fallback_key)
        .expect("failed to write fallback vault key");
    std::fs::write(lpm_dir.join(".vault-salt"), salt).expect("failed to write vault salt");

    let params = scrypt::Params::new(10, 8, 1, 32).expect("invalid test scrypt params");
    let mut derived_key = [0u8; 32];
    scrypt::scrypt(fallback_key.as_bytes(), &salt, &params, &mut derived_key)
        .expect("failed to derive fallback vault key");

    let plaintext = serde_json::to_string(&payload).expect("failed to serialize local vault payload");
    let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("failed to create vault cipher");
    let iv = [0x11u8; 12];
    let nonce = GenericArray::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("failed to encrypt local vault payload");
    let tag_start = ciphertext.len() - 16;
    let (encrypted, auth_tag) = ciphertext.split_at(tag_start);
    let encoded = format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(encrypted)
    );

    std::fs::write(vaults_dir.join(format!("{vault_id}.enc")), encoded)
        .expect("failed to write encrypted local vault file");
}

#[tokio::test]
async fn use_vars_pair_uppercases_code_and_approves_browser_pairing() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_pairing_session("ABC123", "session-access-token", &browser_public_key)
        .await;
    mock.with_pairing_approval("ABC123", "session-access-token")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "abc123"])
        .output()
        .expect("failed to run lpm use vars pair");

    assert!(
        output.status.success(),
        "pair command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{stdout}\n{stderr}");
    assert!(
        combined_output.contains("browser paired successfully")
            || combined_output.contains("dashboard can now decrypt your vault secrets"),
        "expected pairing success output, got combined output: {combined_output}"
    );
    assert!(
        project.home().join(".lpm").join(".vault-key").exists(),
        "workflow vault pairing should use the file-backed wrapping key in isolated HOME"
    );
}

#[tokio::test]
async fn use_vars_unpair_requires_session_based_login() {
    let project = TempProject::empty(r#"{"name":"vault-unpair-legacy-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_revoke_all_pairings_expected(0).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("legacy-token"),
            refresh_token: None,
            session_access_expires_at: None,
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run lpm use vars unpair");

    assert!(
        !output.status.success(),
        "unpair unexpectedly succeeded for legacy token login:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("legacy token") || stderr.contains("doesn't support vault operations"),
        "expected legacy-token vault error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn use_vars_pull_overwrites_local_state_with_remote_environments() {
    let project = TempProject::empty(r#"{"name":"vault-pull-overwrite-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let vault_id = "vault-pull-overwrite";

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "vault": vault_id,
        })
        .to_string(),
    );
    write_file_backed_vault(
        project.home(),
        vault_id,
        serde_json::json!({
            "environments": {
                "default": {
                    "STALE_DEFAULT": "old-default",
                    "REMOVE_ME": "local-only"
                },
                "preview": {
                    "PREVIEW_ONLY": "stale-preview",
                    "SHARED_ENV": "stale-preview"
                }
            }
        }),
    );

    mock.with_personal_pull(
        vault_id,
        "session-access-token",
        serde_json::json!({
            "environments": {
                "default": {
                    "API_URL": "https://api.example.com",
                    "SHARED_ENV": "remote-default"
                },
                "live": {
                    "LIVE_ONLY": "remote-live"
                }
            }
        }),
        7,
    )
    .await;

    let pull = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pull", "--yes"])
        .output()
        .expect("failed to run personal vars pull");

    assert!(
        pull.status.success(),
        "personal vars pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );

    let default_list = lpm(&project)
        .args(["--json", "use", "vars", "list", "--reveal"])
        .output()
        .expect("failed to list default vault secrets after pull");
    assert!(
        default_list.status.success(),
        "default list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&default_list.stdout),
        String::from_utf8_lossy(&default_list.stderr),
    );
    assert_eq!(
        parse_json_output(&default_list.stdout),
        serde_json::json!({
            "API_URL": "https://api.example.com",
            "SHARED_ENV": "remote-default"
        })
    );

    let live_list = lpm(&project)
        .args(["--json", "use", "vars", "list", "--env=live", "--reveal"])
        .output()
        .expect("failed to list live vault secrets after pull");
    assert!(
        live_list.status.success(),
        "live list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&live_list.stdout),
        String::from_utf8_lossy(&live_list.stderr),
    );
    assert_eq!(
        parse_json_output(&live_list.stdout),
        serde_json::json!({
            "LIVE_ONLY": "remote-live"
        })
    );

    let preview_list = lpm(&project)
        .args(["--json", "use", "vars", "list", "--env=preview", "--reveal"])
        .output()
        .expect("failed to list preview vault secrets after pull");
    assert!(
        preview_list.status.success(),
        "preview list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&preview_list.stdout),
        String::from_utf8_lossy(&preview_list.stderr),
    );
    assert_eq!(parse_json_output(&preview_list.stdout), serde_json::json!({}));

    let synced_config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).expect("failed to re-read lpm.json");
    assert_eq!(synced_config["vault"].as_str(), Some(vault_id));
    assert_eq!(synced_config["vaultSync"]["personalVersion"].as_i64(), Some(7));
}

#[tokio::test]
async fn use_vars_pair_refresh_only_session_then_unpair_reuses_normalized_session() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"vault-pair-refresh-chain-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_session("RFH123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("RFH123", "access-from-refresh")
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

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "rfh123"])
        .output()
        .expect("failed to run lpm use vars pair with refresh-only session");

    assert!(
        pair.status.success(),
        "pair with refresh-only session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

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

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run lpm use vars unpair after refresh-only pairing");

    assert!(
        unpair.status.success(),
        "unpair after refresh-only pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );
}

#[tokio::test]
async fn use_vars_pair_then_logout_revokes_pairings_and_blocks_future_pairing_commands() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_pairing_session("PAIR01", "session-access-token", &browser_public_key)
        .await;
    mock.with_pairing_approval("PAIR01", "session-access-token")
        .await;
    mock.with_revoke_all_pairings_expected(1).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "pair01"])
        .output()
        .expect("failed to run pair before logout");

    assert!(
        pair.status.success(),
        "pair before logout failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );
    assert!(
        project.home().join(".lpm").join(".vault-key").exists(),
        "pair should materialize the local wrapping key file in isolated HOME"
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run logout after pairing");

    assert!(
        logout.status.success(),
        "logout after pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after revoking pairings"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after revoking pairings"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "new123"])
        .output()
        .expect("failed to run pair after logout");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );
    let pair_after_logout_stderr = String::from_utf8_lossy(&pair_after_logout.stderr);
    assert!(
        pair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout pair auth error, got stderr: {pair_after_logout_stderr}"
    );

    let unpair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run unpair after logout");

    assert!(
        !unpair_after_logout.status.success(),
        "unpair unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout.stdout),
        String::from_utf8_lossy(&unpair_after_logout.stderr),
    );
    let unpair_after_logout_stderr = String::from_utf8_lossy(&unpair_after_logout.stderr);
    assert!(
        unpair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout unpair auth error, got stderr: {unpair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_pair_refresh_only_session_then_logout_revokes_pairings_and_blocks_future_pairing_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project =
        TempProject::empty(r#"{"name":"vault-pair-refresh-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_session("RLG123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("RLG123", "access-from-refresh")
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

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "rlg123"])
        .output()
        .expect("failed to run pair before logout for refresh-only session");

    assert!(
        pair.status.success(),
        "pair before logout failed for refresh-only session:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
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

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run logout after refresh-only pairing");

    assert!(
        logout.status.success(),
        "logout after refresh-only pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after refresh-only pairing"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry = read_expiry_metadata(project.home());
        assert!(
            expiry.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after refresh-only pairing"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "ABC123"])
        .output()
        .expect("failed to run pair after logout for refresh-only session");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after refresh-only logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );
    let pair_after_logout_stderr = String::from_utf8_lossy(&pair_after_logout.stderr);
    assert!(
        pair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout pair auth error, got stderr: {pair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_pair_unpair_then_logout_on_refresh_backed_session_keeps_normalized_state_and_blocks_future_vault_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(
        r#"{"name":"vault-pair-unpair-logout-refresh-chain-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_session("UPL123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("UPL123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_expected(2).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "upl123"])
        .output()
        .expect("failed to run pair before unpair/logout refresh chain");

    assert!(
        pair.status.success(),
        "pair failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let credentials_after_pair = read_credentials(project.home());
    assert_eq!(credentials_after_pair[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials_after_pair[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run unpair in refresh-backed chain");

    assert!(
        unpair.status.success(),
        "unpair failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );

    let credentials_after_unpair = read_credentials(project.home());
    assert_eq!(credentials_after_unpair, credentials_after_pair);

    let expiry_after_unpair = read_expiry_metadata(project.home());
    assert_eq!(
        expiry_after_unpair[&mock.url()]["session_access_expires_at"],
        "2030-01-01T00:00:00Z"
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run logout in refresh-backed chain");

    assert!(
        logout.status.success(),
        "logout failed in refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after a refresh-backed pair/unpair chain"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after a refresh-backed pair/unpair chain"
        );
    }

    let pair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "NEW123"])
        .output()
        .expect("failed to run pair after refresh-backed logout chain");

    assert!(
        !pair_after_logout.status.success(),
        "pair unexpectedly succeeded after refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout.stdout),
        String::from_utf8_lossy(&pair_after_logout.stderr),
    );

    let unpair_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run unpair after refresh-backed logout chain");

    assert!(
        !unpair_after_logout.status.success(),
        "unpair unexpectedly succeeded after refresh-backed pair/unpair/logout chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout.stdout),
        String::from_utf8_lossy(&unpair_after_logout.stderr),
    );
    let unpair_after_logout_stderr = String::from_utf8_lossy(&unpair_after_logout.stderr);
    assert!(
        unpair_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout unpair auth error, got stderr: {unpair_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_pair_unpair_then_logout_all_on_refresh_backed_session_clears_auth_state_and_blocks_future_vault_commands()
 {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(
        r#"{"name":"vault-pair-unpair-logout-all-refresh-chain-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_pairing_session("UAL123", "access-from-refresh", &browser_public_key)
        .await;
    mock.with_pairing_approval("UAL123", "access-from-refresh")
        .await;
    mock.with_revoke_all_pairings_expected(2).await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: None,
            refresh_token: Some("refresh-seed-token"),
            session_access_expires_at: None,
        }],
    );

    let pair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "ual123"])
        .output()
        .expect("failed to run pair before refresh-backed logout-all chain");

    assert!(
        pair.status.success(),
        "pair failed in refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair.stdout),
        String::from_utf8_lossy(&pair.stderr),
    );

    let unpair = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run unpair before refresh-backed logout-all chain");

    assert!(
        unpair.status.success(),
        "unpair failed in refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );

    let credentials_after_unpair = read_credentials(project.home());
    assert_eq!(credentials_after_unpair[&mock.url()], "access-from-refresh");
    assert_eq!(
        credentials_after_unpair[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run logout --all in refresh-backed vault chain");

    assert!(
        logout_all.status.success(),
        "logout --all failed in refresh-backed pair/unpair chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after a refresh-backed pair/unpair chain"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after a refresh-backed pair/unpair chain"
        );
    }

    let pair_after_logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "NEW123"])
        .output()
        .expect("failed to run pair after refresh-backed logout-all chain");

    assert!(
        !pair_after_logout_all.status.success(),
        "pair unexpectedly succeeded after refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pair_after_logout_all.stdout),
        String::from_utf8_lossy(&pair_after_logout_all.stderr),
    );

    let unpair_after_logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "unpair"])
        .output()
        .expect("failed to run unpair after refresh-backed logout-all chain");

    assert!(
        !unpair_after_logout_all.status.success(),
        "unpair unexpectedly succeeded after refresh-backed pair/unpair/logout-all chain:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair_after_logout_all.stdout),
        String::from_utf8_lossy(&unpair_after_logout_all.stderr),
    );
}

#[tokio::test]
async fn use_vars_pull_oidc_writes_env_file_with_sorted_and_quoted_values() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-pull-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let output_file = project.path().join(".env.ci");

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-ci-123"}"#,
    )
    .expect("failed to write lpm.json");

    mock.with_oidc_exchange(
        "ci-oidc-token",
        "vault-ci-123",
        Some("preview"),
        "lpm-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-ci-123",
        "lpm-ci-token",
        Some("preview"),
        serde_json::json!({
            "Z_LAST": "plain",
            "API_KEY": "secret value",
            "MULTILINE": "line1\nline2",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_VAULT_ID", "vault-ci-123")
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .args([
            "use",
            "vars",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--output={}", output_file.display()),
        ])
        .output()
        .expect("failed to run lpm use vars pull --oidc");

    assert!(
        output.status.success(),
        "oidc pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let written = std::fs::read_to_string(&output_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", output_file.display()));

    assert!(written.contains("# LPM vault secrets (env: preview)"));
    assert!(written.contains("API_KEY=\"secret value\""));
    assert!(written.contains("MULTILINE=\"line1\nline2\""));

    let api_key_index = written
        .find("API_KEY=")
        .expect("API_KEY missing from output");
    let multiline_index = written
        .find("MULTILINE=")
        .expect("MULTILINE missing from output");
    let z_last_index = written.find("Z_LAST=").expect("Z_LAST missing from output");
    assert!(api_key_index < multiline_index && multiline_index < z_last_index);
}

#[tokio::test]
async fn use_vars_pull_oidc_prefers_gitlab_ci_job_jwt_and_emits_json() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-gitlab-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-gitlab-json-123"}"#);

    mock.with_oidc_exchange(
        "gitlab-job-jwt",
        "vault-gitlab-json-123",
        Some("preview"),
        "lpm-gitlab-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-gitlab-json-123",
        "lpm-gitlab-ci-token",
        Some("preview"),
        serde_json::json!({
            "CI_PROVIDER": "gitlab",
            "SECRET_ONE": "value-1",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("CI_JOB_JWT_V2", "gitlab-job-jwt")
        .env("LPM_OIDC_TOKEN", "generic-fallback-token")
        .args(["--json", "use", "vars", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run GitLab OIDC pull --json");

    assert!(
        output.status.success(),
        "GitLab OIDC pull --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["env"], "preview");
    assert_eq!(json["count"], 2);
    assert_eq!(json["vars"]["CI_PROVIDER"], "gitlab");
    assert_eq!(json["vars"]["SECRET_ONE"], "value-1");
}

#[tokio::test]
async fn use_vars_oidc_allow_missing_repo_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-json-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "use", "vars", "oidc", "allow", "--env=preview"])
        .output()
        .expect("failed to run oidc allow JSON error test");

    assert!(
        !output.status.success(),
        "oidc allow missing repo unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .expect("error should be string")
            .contains("missing --repo flag")
    );
}

#[tokio::test]
async fn use_vars_oidc_list_without_vault_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-list-json-error-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run oidc list JSON error test");

    assert!(
        !output.status.success(),
        "oidc list without vault unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .expect("error should be string")
            .contains("no vault configured")
    );
}

#[tokio::test]
async fn use_vars_pull_oidc_uses_github_actions_runtime_token() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-runtime-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let output_file = project.path().join(".env.github-ci");

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-github-oidc-123"}"#,
    )
    .expect("failed to write lpm.json for GitHub OIDC pull");

    mock.with_github_oidc_runtime_token("github-request-token", "github-runtime-oidc-token")
        .await;
    mock.with_oidc_exchange(
        "github-runtime-oidc-token",
        "vault-github-oidc-123",
        Some("preview"),
        "lpm-gh-ci-token",
    )
    .await;
    mock.with_ci_pull(
        "vault-github-oidc-123",
        "lpm-gh-ci-token",
        Some("preview"),
        serde_json::json!({
            "GITHUB_ONLY": "from-runtime-token",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args([
            "use",
            "vars",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--output={}", output_file.display()),
        ])
        .output()
        .expect("failed to run GitHub OIDC pull");

    assert!(
        output.status.success(),
        "GitHub OIDC pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let written = std::fs::read_to_string(&output_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", output_file.display()));
    assert!(written.contains("GITHUB_ONLY=from-runtime-token"));
}

#[tokio::test]
async fn use_vars_pull_oidc_requires_github_request_token_when_actions_env_is_set() {
    let project = TempProject::empty(
        r#"{"name":"vault-oidc-github-missing-request-token","version":"1.0.0"}"#,
    );

    project.write_file("lpm.json", r#"{"vault":"vault-github-missing-token-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env("LPM_OIDC_TOKEN", "generic-fallback-token")
        .args(["use", "vars", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub missing request token test");

    assert!(
        !output.status.success(),
        "missing GitHub request token unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set"));
}

#[tokio::test]
async fn use_vars_pull_oidc_requires_github_request_url_when_actions_env_is_set() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-missing-request-url","version":"1.0.0"}"#);

    project.write_file("lpm.json", r#"{"vault":"vault-github-missing-url-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .args(["use", "vars", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub missing request url test");

    assert!(
        !output.status.success(),
        "missing GitHub request url unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ACTIONS_ID_TOKEN_REQUEST_URL not set"));
}

#[tokio::test]
async fn use_vars_pull_oidc_surfaces_github_runtime_request_failures() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-runtime-failure","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-github-runtime-failure-123"}"#,
    );

    mock.with_github_oidc_runtime_response(
        "github-request-token",
        500,
        serde_json::json!({
            "error": "runtime unavailable",
        }),
    )
    .await;

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args(["use", "vars", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub runtime failure test");

    assert!(
        !output.status.success(),
        "GitHub runtime failure unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GitHub OIDC token request failed (500 Internal Server Error)"));
}

#[tokio::test]
async fn use_vars_pull_oidc_rejects_github_runtime_responses_without_value() {
    let project = TempProject::empty(
        r#"{"name":"vault-oidc-github-runtime-missing-value","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    project.write_file(
        "lpm.json",
        r#"{"vault":"vault-github-runtime-missing-value-123"}"#,
    );

    mock.with_github_oidc_runtime_response(
        "github-request-token",
        200,
        serde_json::json!({
            "unexpected": true,
        }),
    )
    .await;

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/github/oidc?existing=1", mock.url()),
        )
        .args(["use", "vars", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub missing runtime value test");

    assert!(
        !output.status.success(),
        "GitHub runtime response without value unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no token in GitHub OIDC response"));
}

#[tokio::test]
async fn use_vars_pull_oidc_surfaces_exchange_error_hint() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-exchange-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-oidc-error-123"}"#,
    )
    .expect("failed to write lpm.json for OIDC exchange error");

    mock.with_oidc_exchange_failure(
        "ci-oidc-token",
        "vault-oidc-error-123",
        Some("preview"),
        403,
        "OIDC subject is not allowed for this vault",
        Some("Run 'lpm use vars oidc allow --repo=owner/repo --env=preview' first."),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .args(["use", "vars", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run oidc pull exchange error test");

    assert!(
        !output.status.success(),
        "OIDC pull unexpectedly succeeded:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OIDC subject is not allowed for this vault"));
    assert!(stderr.contains("Hint:"));
    assert!(stderr.contains("lpm use vars oidc allow --repo=owner/repo --env=preview"));
}

#[tokio::test]
async fn use_vars_pull_oidc_exchange_error_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-pull-json-error-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-oidc-pull-json-error-123"}"#);

    mock.with_oidc_exchange_failure(
        "ci-oidc-token",
        "vault-oidc-pull-json-error-123",
        Some("preview"),
        403,
        "OIDC subject is not allowed for this vault",
        Some("Add an OIDC policy before pulling secrets."),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .args(["--json", "use", "vars", "pull", "--oidc", "--env=preview"])
        .output()
        .expect("failed to run oidc pull JSON error test");

    assert!(
        !output.status.success(),
        "oidc pull exchange error unexpectedly succeeded"
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], false);
    let error = json["error"].as_str().expect("error should be string");
    assert!(error.contains("OIDC subject is not allowed for this vault"));
    assert!(error.contains("Hint: Add an OIDC policy before pulling secrets."));
}

#[tokio::test]
async fn use_vars_pair_surfaces_expired_code_error() {
    let project = TempProject::empty(r#"{"name":"vault-pair-expired-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_pairing_session_error("EXPIRE", "session-access-token", 410, "pairing expired")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "expire"])
        .output()
        .expect("failed to run lpm use vars pair for expired code");

    assert!(
        !output.status.success(),
        "expired pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pairing error: pairing expired"),
        "expected expired pairing error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn use_vars_pair_rejects_non_pending_session_status() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-status-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_pairing_session_status(
        "USED12",
        "session-access-token",
        "approved",
        Some(&browser_public_key),
    )
    .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "used12"])
        .output()
        .expect("failed to run lpm use vars pair for non-pending code");

    assert!(
        !output.status.success(),
        "non-pending pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expected 'pending'") && stderr.contains("approved"),
        "expected non-pending pairing error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn use_vars_pair_rejects_malformed_browser_key() {
    let project =
        TempProject::empty(r#"{"name":"vault-pair-malformed-key-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    mock.with_pairing_session("BADKEY", "session-access-token", "not-base64")
        .await;

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "pair", "badkey"])
        .output()
        .expect("failed to run lpm use vars pair for malformed key");

    assert!(
        !output.status.success(),
        "malformed-key pairing unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("browser public key decode")
            || stderr.contains("invalid browser P-256 public key"),
        "expected malformed browser key error, got stderr: {stderr}"
    );
}

#[tokio::test]
async fn use_vars_oidc_allow_then_list_shows_policy_and_escrow_success() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-allow-list-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-policy-123"}"#,
    )
    .expect("failed to write lpm.json for oidc allow/list");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-123",
        "acme/repo",
        &["main", "release"],
        &["production"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-123")
        .await;
    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-123",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main", "release"],
                "allowedEnvironments": ["production"],
                "allowForks": false,
            }
        ]),
    )
    .await;

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main,release",
            "--env=production",
        ])
        .output()
        .expect("failed to run lpm use vars oidc allow");

    assert!(allow.status.success(), "oidc allow failed");
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("CI escrow enabled"));

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run lpm use vars oidc list");

    assert!(list.status.success(), "oidc list failed");
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(list_output.contains("github"));
    assert!(list_output.contains("repo:acme/repo"));
    assert!(list_output.contains("main, release") || list_output.contains("main,release"));
    assert!(list_output.contains("production"));
}

#[tokio::test]
async fn use_vars_oidc_allow_emits_json_response() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-allow-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-policy-json-123"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-json-123",
        "acme/repo",
        &["main"],
        &["production"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-json-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=production",
        ])
        .output()
        .expect("failed to run oidc allow --json");

    assert!(
        output.status.success(),
        "oidc allow --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["provider"], "github");
    assert_eq!(json["subject"], "repo:acme/repo");
}

#[tokio::test]
async fn use_vars_oidc_list_emits_json_response() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-list-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-policy-list-json-123"}"#);

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_list(
        "session-access-token",
        "vault-policy-list-json-123",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["production"],
                "allowForks": false,
            },
            {
                "provider": "github",
                "subject": "repo:acme/preview",
                "allowedBranches": ["develop"],
                "allowedEnvironments": ["preview"],
                "allowForks": true,
            }
        ]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run oidc list --json");

    assert!(
        output.status.success(),
        "oidc list --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_json_output(&output.stdout);
    let policies = json["policies"]
        .as_array()
        .expect("policies should be an array");
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["subject"], "repo:acme/repo");
    assert_eq!(policies[1]["allowForks"], true);
}

#[tokio::test]
async fn use_vars_oidc_allow_warns_when_escrow_upload_fails() {
    let project = TempProject::empty(r#"{"name":"vault-oidc-escrow-warn-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-policy-456"}"#,
    )
    .expect("failed to write lpm.json for oidc escrow warning");

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-456",
        "acme/repo",
        &["main"],
        &["preview"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "session-access-token",
        "vault-policy-456",
        "escrow backend unavailable",
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
        ])
        .output()
        .expect("failed to run oidc allow with escrow failure");

    assert!(
        output.status.success(),
        "oidc allow should succeed even if escrow upload fails"
    );
    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined_output.contains("OIDC policy set: github"));
    assert!(combined_output.contains("Failed to escrow wrapping key"));
    assert!(combined_output.contains("escrow backend unavailable"));
}

#[tokio::test]
async fn use_vars_oidc_allow_and_list_on_refresh_backed_session_then_logout_all_clears_auth_state()
{
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-refresh-logout-all-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-policy-refresh-logout-all-123"}"#,
    )
    .expect("failed to write lpm.json for refresh-backed oidc allow/list");

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-logout-all-123",
        "acme/repo",
        &["main"],
        &["preview"],
    )
    .await;
    mock.with_escrow_upload_success("access-from-refresh", "vault-policy-refresh-logout-all-123")
        .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-logout-all-123",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
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

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow");

    assert!(
        allow.status.success(),
        "refresh-backed oidc allow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
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

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run refresh-backed oidc list");

    assert!(
        list.status.success(),
        "refresh-backed oidc list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(list_output.contains("repo:acme/repo"));

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run logout --all after refresh-backed oidc allow/list");

    assert!(
        logout_all.status.success(),
        "logout --all after refresh-backed oidc allow/list failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after refresh-backed oidc allow/list"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after refresh-backed oidc allow/list"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout --all");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout-all oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_oidc_allow_warns_on_refresh_backed_session_then_logout_clears_auth_state() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-refresh-escrow-logout-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-policy-refresh-escrow-logout-123"}"#,
    )
    .expect("failed to write lpm.json for refresh-backed oidc escrow warning flow");

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        "acme/repo",
        &["main"],
        &["preview"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        "escrow backend unavailable",
    )
    .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-123",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
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

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow with escrow warning");

    assert!(
        allow.status.success(),
        "refresh-backed oidc allow with escrow warning failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("Failed to escrow wrapping key"));
    assert!(allow_output.contains("escrow backend unavailable"));

    let credentials_after_refresh = read_credentials(project.home());
    assert_eq!(
        credentials_after_refresh[&mock.url()],
        "access-from-refresh"
    );
    assert_eq!(
        credentials_after_refresh[&format!("refresh:{}", mock.url())],
        "refresh-rotated-token"
    );

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run oidc list after refresh-backed escrow warning");

    assert!(
        list.status.success(),
        "oidc list failed after refresh-backed escrow warning:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );

    let logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout"])
        .output()
        .expect("failed to run logout after refresh-backed escrow warning flow");

    assert!(
        logout.status.success(),
        "logout after refresh-backed escrow warning flow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout.stdout),
        String::from_utf8_lossy(&logout.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout should remove credentials after refresh-backed oidc escrow warning flow"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout should remove session expiry metadata after refresh-backed oidc escrow warning flow"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_oidc_allow_warns_on_refresh_backed_session_then_logout_all_clears_auth_state() {
    let project = TempProject::empty(
        r#"{"name":"vault-oidc-refresh-escrow-logout-all-test","version":"1.0.0"}"#,
    );
    let mock = MockRegistry::start().await;

    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"vault":"vault-policy-refresh-escrow-logout-all-123"}"#,
    )
    .expect("failed to write lpm.json for refresh-backed oidc escrow warning logout-all flow");

    mock.with_refresh_expected(
        "refresh-seed-token",
        "access-from-refresh",
        "refresh-rotated-token",
        "2030-01-01T00:00:00Z",
        1,
    )
    .await;
    mock.with_oidc_policy_create(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        "acme/repo",
        &["main"],
        &["preview"],
    )
    .await;
    mock.with_escrow_upload_failure(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        "escrow backend unavailable",
    )
    .await;
    mock.with_oidc_policy_list(
        "access-from-refresh",
        "vault-policy-refresh-escrow-logout-all-123",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["preview"],
                "allowForks": false,
            }
        ]),
    )
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

    let allow = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
        ])
        .output()
        .expect("failed to run refresh-backed oidc allow with escrow warning before logout --all");

    assert!(
        allow.status.success(),
        "refresh-backed oidc allow with escrow warning failed before logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("Failed to escrow wrapping key"));
    assert!(allow_output.contains("escrow backend unavailable"));

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to run oidc list after refresh-backed escrow warning before logout --all");

    assert!(
        list.status.success(),
        "oidc list failed after refresh-backed escrow warning before logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr),
    );

    let logout_all = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["logout", "--all"])
        .output()
        .expect("failed to run logout --all after refresh-backed escrow warning flow");

    assert!(
        logout_all.status.success(),
        "logout --all after refresh-backed escrow warning flow failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&logout_all.stdout),
        String::from_utf8_lossy(&logout_all.stderr),
    );

    assert!(
        !credentials_path(project.home()).exists(),
        "logout --all should remove credentials after refresh-backed oidc escrow warning flow"
    );

    if token_expiry_path(project.home()).exists() {
        let expiry_after_logout = read_expiry_metadata(project.home());
        assert!(
            expiry_after_logout.get(mock.url()).is_none(),
            "logout --all should remove session expiry metadata after refresh-backed oidc escrow warning flow"
        );
    }

    let list_after_logout = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["use", "vars", "oidc", "list"])
        .output()
        .expect("failed to rerun oidc list after logout --all");

    assert!(
        !list_after_logout.status.success(),
        "oidc list unexpectedly succeeded after logout --all:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list_after_logout.stdout),
        String::from_utf8_lossy(&list_after_logout.stderr),
    );
    let list_after_logout_stderr = String::from_utf8_lossy(&list_after_logout.stderr);
    assert!(
        list_after_logout_stderr.contains("not logged in. Run `lpm login` first"),
        "expected post-logout-all oidc list auth error, got stderr: {list_after_logout_stderr}"
    );
}

#[tokio::test]
async fn use_vars_oidc_allow_canonicalizes_env_aliases_before_storing_policy() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-canonical-env-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file(
        "lpm.json",
        r#"{
  "vault": "vault-policy-canonical-123",
  "env": {
    "dev": ".env.development"
  }
}"#,
    );

    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some("session-access-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_oidc_policy_create(
        "session-access-token",
        "vault-policy-canonical-123",
        "acme/repo",
        &["main"],
        &["development"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-canonical-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "use",
            "vars",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=dev",
        ])
        .output()
        .expect("failed to run oidc allow canonicalization test");

    assert!(
        output.status.success(),
        "oidc allow canonicalization failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined_output.contains("resolved \"dev\" → canonical \"development\""));
    assert!(combined_output.contains("envs [development]"));
}
