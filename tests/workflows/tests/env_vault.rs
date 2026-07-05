#![cfg(debug_assertions)]

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

fn doctor_check<'a>(json: &'a serde_json::Value, code: &str) -> &'a serde_json::Value {
    json["checks"]
        .as_array()
        .expect("doctor checks must be an array")
        .iter()
        .find(|check| check["code"].as_str() == Some(code))
        .unwrap_or_else(|| panic!("doctor output must include `{code}`: {json}"))
}

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

    let plaintext =
        serde_json::to_string(&payload).expect("failed to serialize local vault payload");
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

fn parse_clean_json_stdout(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim_start().starts_with('{'),
        "JSON mode must not prefix stdout with human text:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    parse_json_output(&output.stdout)
}

#[test]
fn doctor_json_reports_file_vault_fallback_when_forced_file_backend_is_active() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_fallback");

    assert_eq!(check["severity"].as_str(), Some("warn"));
    assert_eq!(check["passed"].as_bool(), Some(true));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn doctor_json_reports_native_vault_storage_when_native_key_is_active() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);
    let native_key_hex = hex::encode([0x5au8; 32]);

    let output = lpm(&project)
        .env_remove("LPM_FORCE_FILE_VAULT")
        .env("LPM_TEST_VAULT_NATIVE_KEY_HEX", native_key_hex)
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_native");

    assert_eq!(check["severity"].as_str(), Some("pass"));
    assert_eq!(check["passed"].as_bool(), Some(true));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn doctor_json_reports_unavailable_vault_storage_when_blob_has_no_key_source() {
    let project = TempProject::empty(r#"{"name":"vault-doctor","version":"1.0.0"}"#);
    let vaults_dir = project.home().join(".lpm").join("vaults");
    std::fs::create_dir_all(&vaults_dir).expect("failed to create vaults dir");
    std::fs::write(
        vaults_dir.join("missing-key.enc"),
        "not decrypted during status",
    )
    .expect("failed to seed vault blob");

    let output = lpm(&project)
        .env_remove("LPM_FORCE_FILE_VAULT")
        .env(
            "LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR",
            "native store locked",
        )
        .args(["doctor", "--json"])
        .output()
        .expect("failed to run lpm doctor --json");
    let json = parse_json_output(&output.stdout);
    let check = doctor_check(&json, "vault_storage_unavailable");

    assert_eq!(check["severity"].as_str(), Some("fail"));
    assert_eq!(check["passed"].as_bool(), Some(false));
    assert!(
        check["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("native store locked")),
        "unavailable detail should include native backend error: {check}"
    );
}

#[tokio::test]
async fn env_pair_uppercases_code_and_approves_browser_pairing() {
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
        .args(["env", "pair", "abc123", "--yes"])
        .output()
        .expect("failed to run lpm env pair");

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
async fn env_pair_refuses_when_stdin_is_not_a_tty_and_yes_flag_absent() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // The headline H1 phishing payload — "run this command from a tutorial /
    // pipe / heredoc" — relies on the CLI completing the wrap with no human
    // pause. Defense: refuse outright unless either (a) the user is sitting at
    // a real terminal where the confirmation prompt can render, or (b) the
    // user explicitly passed --yes after reading the help. The mock pair
    // routes are mounted with `.expect(0)` so the regression check fails if
    // the CLI ever reaches the GET (let alone the approve POST).
    let project = TempProject::empty(r#"{"name":"vault-pair-non-tty-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    mock.with_pairing_session_call_count("NOTTY1", "session-access-token", &browser_public_key, 0)
        .await;
    mock.with_pairing_approval_call_count("NOTTY1", "session-access-token", 0)
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
        .args(["env", "pair", "notty1"])
        .output()
        .expect("failed to spawn lpm env pair without --yes");

    assert!(
        !output.status.success(),
        "pair without --yes on non-TTY stdin must FAIL — refusing the wrap is the H1 fix.\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("--yes"),
        "stderr must explain why the pair refused and how to bypass: {stderr}"
    );
}

#[tokio::test]
async fn env_pair_with_yes_prints_browser_key_fingerprint_and_match_number_before_approving() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let project = TempProject::empty(r#"{"name":"vault-pair-meta-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
    let browser_public_key = BASE64.encode(
        browser_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );

    mock.with_pairing_session_with_metadata(
        "META01",
        "session-access-token",
        &browser_public_key,
        Some("Safari on iOS"),
        Some("2026-05-20T12:34:56Z"),
        Some("203.0.113.0/24"),
    )
    .await;
    mock.with_pairing_approval("META01", "session-access-token")
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
        .args(["env", "pair", "meta01", "--yes"])
        .output()
        .expect("failed to run lpm env pair --yes");

    assert!(
        output.status.success(),
        "pair --yes with metadata-rich session failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Audit trail: even with --yes, the binding info must be in the
    // terminal scrollback so the user has post-hoc evidence of what they
    // approved sight-unseen.
    assert!(
        combined.contains("Browser key fingerprint"),
        "binding info missing — expected fingerprint label: {combined}"
    );
    assert!(
        combined.contains("Safari on iOS"),
        "binding info missing — expected sanitized device label: {combined}"
    );
    assert!(
        combined.contains("203.0.113.0/24"),
        "binding info missing — expected createdFromIp: {combined}"
    );
    assert!(
        combined.contains("Verify the dashboard shows the same number"),
        "binding info missing — expected match-number caption: {combined}"
    );
    assert!(
        combined.contains("skipped browser-identity verification"),
        "--yes audit warning missing: {combined}"
    );
}

#[tokio::test]
async fn env_unpair_requires_session_based_login() {
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
        .args(["env", "unpair"])
        .output()
        .expect("failed to run lpm env unpair");

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
async fn env_pull_overwrites_local_state_with_remote_environments() {
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
        .args(["env", "pull", "--yes"])
        .output()
        .expect("failed to run personal vars pull");

    assert!(
        pull.status.success(),
        "personal vars pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&pull.stdout),
        String::from_utf8_lossy(&pull.stderr),
    );

    let default_list = lpm(&project)
        .args(["--json", "env", "list", "--reveal"])
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
        .args(["--json", "env", "list", "--env=live", "--reveal"])
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
        .args(["--json", "env", "list", "--env=preview", "--reveal"])
        .output()
        .expect("failed to list preview vault secrets after pull");
    assert!(
        preview_list.status.success(),
        "preview list after pull failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&preview_list.stdout),
        String::from_utf8_lossy(&preview_list.stderr),
    );
    assert_eq!(
        parse_json_output(&preview_list.stdout),
        serde_json::json!({})
    );

    let synced_config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).expect("failed to re-read lpm.json");
    assert_eq!(synced_config["vault"].as_str(), Some(vault_id));
    assert_eq!(
        synced_config["vaultSync"]["personalVersion"].as_i64(),
        Some(7)
    );
}

#[tokio::test]
async fn env_pair_refresh_only_session_then_unpair_reuses_normalized_session() {
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
        .args(["env", "pair", "rfh123", "--yes"])
        .output()
        .expect("failed to run lpm env pair with refresh-only session");

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
        .args(["env", "unpair"])
        .output()
        .expect("failed to run lpm env unpair after refresh-only pairing");

    assert!(
        unpair.status.success(),
        "unpair after refresh-only pairing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&unpair.stdout),
        String::from_utf8_lossy(&unpair.stderr),
    );
}

#[tokio::test]
async fn env_pair_then_logout_revokes_pairings_and_blocks_future_pairing_commands() {
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
        .args(["env", "pair", "pair01", "--yes"])
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
        .args(["env", "pair", "new123"])
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
        .args(["env", "unpair"])
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
async fn env_pair_refresh_only_session_then_logout_revokes_pairings_and_blocks_future_pairing_commands()
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
        .args(["env", "pair", "rlg123", "--yes"])
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
        .args(["env", "pair", "ABC123"])
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
async fn env_pair_unpair_then_logout_on_refresh_backed_session_keeps_normalized_state_and_blocks_future_vault_commands()
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
        .args(["env", "pair", "upl123", "--yes"])
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
        .args(["env", "unpair"])
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
        .args(["env", "pair", "NEW123"])
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
        .args(["env", "unpair"])
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
async fn env_pair_unpair_then_logout_all_on_refresh_backed_session_clears_auth_state_and_blocks_future_vault_commands()
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
        .args(["env", "pair", "ual123", "--yes"])
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
        .args(["env", "unpair"])
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
        .args(["env", "pair", "NEW123"])
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
        .args(["env", "unpair"])
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
async fn env_pull_oidc_writes_env_file_with_sorted_and_quoted_values() {
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
            "env",
            "pull",
            "--oidc",
            "--env=preview",
            &format!("--output={}", output_file.display()),
        ])
        .output()
        .expect("failed to run lpm env pull --oidc");

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
async fn env_pull_oidc_uses_lpm_oidc_token_canonical_and_ignores_ci_job_jwt_v2() {
    // Locks the contract that LPM_OIDC_TOKEN is the canonical registry-exchange
    // input on every provider, and CI_JOB_JWT_V2 (whose default audience is the
    // GitLab instance URL, NOT https://lpm.dev) is intentionally ignored — the
    // origin's vault verifier rejects anything but `aud=https://lpm.dev`, so
    // honoring CI_JOB_JWT_V2 would produce confusing 401s.
    let project = TempProject::empty(r#"{"name":"vault-oidc-gitlab-json-test","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-gitlab-json-123"}"#);

    mock.with_oidc_exchange(
        "lpm-oidc-token-with-aud-lpm-dev",
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
        // Both set: the contract requires LPM_OIDC_TOKEN to win and
        // CI_JOB_JWT_V2 to be ignored. If anyone reverts and starts honoring
        // CI_JOB_JWT_V2 again, the mock's exchange handler will see the wrong
        // input token and the test fails.
        .env("CI_JOB_JWT_V2", "should-be-ignored")
        .env("LPM_OIDC_TOKEN", "lpm-oidc-token-with-aud-lpm-dev")
        .args(["--json", "env", "pull", "--oidc", "--env=preview"])
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

    insta::with_settings!({
        sort_maps => true,
        filters => vec![
            (r#"/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/private/var/folders/[^"\s]+"#, "[TEMP]"),
            (r#"/tmp/[^"\s]+"#, "[TEMP]"),
            (r"http://127\.0\.0\.1:\d+", "[MOCK]"),
        ],
    }, {
        insta::assert_json_snapshot!(
            "env_pull_oidc_gitlab_two_vars_envelope",
            json,
            { ".duration_ms" => "[DURATION]" }
        );
    });
}

#[tokio::test]
async fn env_oidc_allow_missing_repo_emits_json_error() {
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
        .args(["--json", "env", "oidc", "allow", "--env=preview"])
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
async fn env_oidc_allow_missing_workflow_flag_errors_loudly() {
    // `--workflow` is required at the CLI layer. Without it the server's Zod
    // `.min(1)` on `allowedWorkflows` would reject anyway; we surface the
    // failure client-side so the user gets a fast, actionable error.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-missing-workflow","version":"1.0.0"}"#);
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
        .args([
            "env",
            "oidc",
            "allow",
            "--repo=acme/repo",
            "--branch=main",
            "--env=production",
            // --workflow deliberately omitted
        ])
        .output()
        .expect("failed to run oidc allow missing-workflow test");

    assert!(
        !output.status.success(),
        "missing --workflow should fail closed",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing --workflow flag"),
        "expected missing-workflow message, got: {stderr}",
    );
}

#[tokio::test]
async fn env_oidc_allow_rejects_workflow_in_subdirectory() {
    // The workflow regex pins .github/workflows/<file>.{yml,yaml} only.
    // Subdirectories aren't supported by GitHub Actions and aren't accepted
    // by the server's Zod schema either; the CLI catches it before the
    // network round-trip.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-allow-workflow-subdir","version":"1.0.0"}"#);
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
        .args([
            "env",
            "oidc",
            "allow",
            "--repo=acme/repo",
            "--workflow=.github/workflows/nested/deploy.yml",
            "--branch=main",
            "--env=production",
        ])
        .output()
        .expect("failed to run oidc allow subdir-workflow test");

    assert!(
        !output.status.success(),
        "subdir workflow path should be rejected",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(".github/workflows/<file>.yml"),
        "expected workflow-path-shape error, got: {stderr}",
    );
}

#[tokio::test]
async fn env_oidc_list_without_vault_emits_json_error() {
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-list-json-error-test","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "env", "oidc", "list"])
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
async fn env_pull_oidc_uses_github_actions_runtime_token() {
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
            "env",
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
async fn env_pull_oidc_partial_github_signal_token_only_falls_through() {
    // A partial GitHub Actions signal — only ACTIONS_ID_TOKEN_REQUEST_TOKEN
    // set, no URL — must NOT trigger a runtime fetch attempt. With no other
    // signal present, the resolver falls through to the named-vars error.
    // This is the new contract: GITHUB_ACTIONS by itself is no longer a gate;
    // both runtime vars must be present together to take the GH path.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-partial-token-only","version":"1.0.0"}"#);

    project.write_file("lpm.json", r#"{"vault":"vault-github-partial-token-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "partial-gh-token")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("LPM_OIDC_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub partial-token-only test");

    assert!(
        !output.status.success(),
        "partial GitHub signal (token only) unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no OIDC signal"),
        "stderr should fall through to the named-vars error, got: {stderr}"
    );
    assert!(
        stderr.contains("LPM_OIDC_TOKEN"),
        "error must name the canonical bypass var: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_partial_github_signal_url_only_falls_through() {
    // Symmetric to the token-only case: only the URL is set, no TOKEN. Must
    // also fall through rather than try the runtime fetch with a half-built
    // request.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-github-partial-url-only","version":"1.0.0"}"#);

    project.write_file("lpm.json", r#"{"vault":"vault-github-partial-url-123"}"#);

    let output = lpm(&project)
        .env("GITHUB_ACTIONS", "true")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://example.invalid/oidc",
        )
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("LPM_OIDC_TOKEN")
        .env_remove("LPM_GITLAB_OIDC_TOKEN")
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub partial-url-only test");

    assert!(
        !output.status.success(),
        "partial GitHub signal (URL only) unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no OIDC signal"),
        "stderr should fall through to the named-vars error, got: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_surfaces_github_runtime_request_failures() {
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
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub runtime failure test");

    assert!(
        !output.status.success(),
        "GitHub runtime failure unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("GitHub OIDC fetch failed"),
        "stderr should surface the runtime fetch failure, got: {stderr}"
    );
    assert!(
        stderr.contains("500"),
        "stderr should name the upstream status, got: {stderr}"
    );
}

#[tokio::test]
async fn env_pull_oidc_rejects_github_runtime_responses_without_value() {
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
        .args(["env", "pull", "--oidc"])
        .output()
        .expect("failed to run GitHub missing runtime value test");

    assert!(
        !output.status.success(),
        "GitHub runtime response without value unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GitHub OIDC response missing 'value' field"));
}

#[tokio::test]
async fn env_pull_oidc_surfaces_exchange_error_hint() {
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
        Some("Run 'lpm env oidc allow --repo=owner/repo --env=preview' first."),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .env("LPM_OIDC_TOKEN", "ci-oidc-token")
        .args(["env", "pull", "--oidc", "--env=preview"])
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
    assert!(stderr.contains("lpm env oidc allow --repo=owner/repo --env=preview"));
}

#[tokio::test]
async fn env_pull_oidc_exchange_error_emits_json_error() {
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
        .args(["--json", "env", "pull", "--oidc", "--env=preview"])
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
async fn env_pair_surfaces_expired_code_error() {
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
        .args(["env", "pair", "expire", "--yes"])
        .output()
        .expect("failed to run lpm env pair for expired code");

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
async fn env_pair_rejects_non_pending_session_status() {
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
        .args(["env", "pair", "used12", "--yes"])
        .output()
        .expect("failed to run lpm env pair for non-pending code");

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
async fn env_pair_rejects_malformed_browser_key() {
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
        .args(["env", "pair", "badkey", "--yes"])
        .output()
        .expect("failed to run lpm env pair for malformed key");

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
async fn env_oidc_allow_then_list_shows_policy_and_escrow_success() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
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
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main,release",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
        ])
        .output()
        .expect("failed to run lpm env oidc allow");

    assert!(
        allow.status.success(),
        "oidc allow failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr),
    );
    let allow_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&allow.stdout),
        String::from_utf8_lossy(&allow.stderr)
    );
    assert!(allow_output.contains("OIDC policy set: github"));
    assert!(allow_output.contains("CI escrow enabled"));

    let list = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run lpm env oidc list");

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
async fn env_oidc_allow_emits_json_response() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-json-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=production",
            "--workflow=.github/workflows/deploy.yml",
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
async fn env_oidc_list_emits_json_response() {
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
                "allowedWorkflows": [".github/workflows/deploy.yml"],
                "allowedEvents": ["push"],
                "allowForks": false,
            },
            {
                "provider": "github",
                "subject": "repo:acme/preview",
                "allowedBranches": ["develop"],
                "allowedEnvironments": ["preview"],
                "allowedWorkflows": [
                    ".github/workflows/ci.yml",
                    ".github/workflows/preview.yml"
                ],
                "allowedEvents": ["push", "pull_request_target"],
                "allowForks": true,
            }
        ]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "oidc", "list"])
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
    // Pin every field end-to-end so a future schema/CLI drift trips
    // here, not in production.
    assert_eq!(policies[0]["provider"], "github");
    assert_eq!(policies[0]["subject"], "repo:acme/repo");
    assert_eq!(policies[0]["allowedBranches"], serde_json::json!(["main"]));
    assert_eq!(
        policies[0]["allowedEnvironments"],
        serde_json::json!(["production"]),
    );
    assert_eq!(
        policies[0]["allowedWorkflows"],
        serde_json::json!([".github/workflows/deploy.yml"]),
    );
    assert_eq!(policies[0]["allowedEvents"], serde_json::json!(["push"]));
    assert_eq!(policies[0]["allowForks"], false);

    assert_eq!(policies[1]["subject"], "repo:acme/preview");
    assert_eq!(
        policies[1]["allowedWorkflows"],
        serde_json::json!([".github/workflows/ci.yml", ".github/workflows/preview.yml"]),
    );
    assert_eq!(
        policies[1]["allowedEvents"],
        serde_json::json!(["push", "pull_request_target"]),
    );
    assert_eq!(policies[1]["allowForks"], true);
}

#[tokio::test]
async fn env_oidc_list_human_output_renders_new_fields() {
    // The CLI's human-readable `lpm env oidc list` output must surface
    // allowedWorkflows and allowedEvents; without this the dashboard-vs-CLI
    // inspection paths drift and CLI users would not see the policy fields
    // that gate their next CI mint.
    let project =
        TempProject::empty(r#"{"name":"vault-oidc-list-human-fields","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;

    project.write_file("lpm.json", r#"{"vault":"vault-policy-list-human-1"}"#);

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
        "vault-policy-list-human-1",
        serde_json::json!([
            {
                "provider": "github",
                "subject": "repo:acme/repo",
                "allowedBranches": ["main"],
                "allowedEnvironments": ["production"],
                "allowedWorkflows": [".github/workflows/deploy.yml"],
                "allowedEvents": ["push", "release"],
                "allowForks": false,
            }
        ]),
    )
    .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["env", "oidc", "list"])
        .output()
        .expect("failed to run oidc list");

    assert!(output.status.success(), "oidc list failed");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains(".github/workflows/deploy.yml"),
        "expected workflow path in human output, got: {combined}",
    );
    assert!(
        combined.contains("push") && combined.contains("release"),
        "expected event names in human output, got: {combined}",
    );
    assert!(
        combined.contains("workflows:"),
        "expected `workflows:` label in human output, got: {combined}",
    );
    assert!(
        combined.contains("events:"),
        "expected `events:` label in human output, got: {combined}",
    );
}

#[tokio::test]
async fn env_oidc_allow_warns_when_escrow_upload_fails() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
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
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
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
async fn env_oidc_allow_and_list_on_refresh_backed_session_then_logout_all_clears_auth_state() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
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
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
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
        .args(["env", "oidc", "list"])
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
        .args(["env", "oidc", "list"])
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
async fn env_oidc_allow_warns_on_refresh_backed_session_then_logout_clears_auth_state() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
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
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
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
        .args(["env", "oidc", "list"])
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
        .args(["env", "oidc", "list"])
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
async fn env_oidc_allow_warns_on_refresh_backed_session_then_logout_all_clears_auth_state() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
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
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=preview",
            "--workflow=.github/workflows/deploy.yml",
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
        .args(["env", "oidc", "list"])
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
        .args(["env", "oidc", "list"])
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
async fn env_oidc_allow_canonicalizes_env_aliases_before_storing_policy() {
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
        &[".github/workflows/deploy.yml"],
        &["push"],
    )
    .await;
    mock.with_escrow_upload_success("session-access-token", "vault-policy-canonical-123")
        .await;

    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "env",
            "oidc",
            "allow",
            "--provider=github",
            "--repo=acme/repo",
            "--branch=main",
            "--env=dev",
            "--workflow=.github/workflows/deploy.yml",
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

#[tokio::test]
async fn env_share_refuses_force_flag_with_actionable_remediation() {
    // The share command never implemented --force — before this commit
    // the CLI silently dropped the flag and re-sent the same request,
    // so a user trying to resolve an org-vault version conflict with
    // --force was lied to by the UX. The server-side org 409 hints no
    // longer mention --force either; this assertion locks in the
    // matching CLI refusal so the two surfaces stay in sync.
    //
    // The rejection fires before any vault / network state is touched,
    // so the test does not need a configured vault, mock registry, or
    // session seed — the CLI must refuse at flag parse time.
    let project = TempProject::empty(r#"{"name":"share-force-refusal","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "share", "--org", "acme", "--force"])
        .output()
        .expect("failed to run lpm env share --force");

    assert!(
        !output.status.success(),
        "share --force must fail with a non-zero exit:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("`lpm env share --force` is not supported"),
        "expected the explicit refusal sentence; got: {combined}"
    );
    assert!(
        combined.contains("lpm env pull --org"),
        "expected the pull-then-retry remediation hint; got: {combined}"
    );
}

#[tokio::test]
async fn env_share_force_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"share-force-json","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["--json", "env", "share", "--org", "acme", "--force"])
        .output()
        .expect("failed to run lpm env share --force --json");

    assert!(
        !output.status.success(),
        "share --force --json must fail with a non-zero exit:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let json = parse_clean_json_stdout(&output);
    assert_eq!(json["success"], false);
    assert_eq!(json["error_code"], "script");
    let error = json["error"].as_str().expect("error should be a string");
    assert!(error.contains("`lpm env share --force` is not supported"));
    assert!(error.contains("lpm env pull --org"));
}

#[tokio::test]
async fn env_platform_json_success_paths_emit_success_envelopes() {
    let project = TempProject::empty(r#"{"name":"platform-json-contract","version":"1.0.0"}"#);
    let mock = MockRegistry::start().await;
    let bearer_token = "platform-json-session-token";
    let vault_id = "vault-platform-json-123";

    project.write_file("lpm.json", &format!(r#"{{"vault":"{vault_id}"}}"#));
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &mock.url(),
            access_token: Some(bearer_token),
            refresh_token: Some("platform-json-refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );

    mock.with_platform_connect_success(
        bearer_token,
        vault_id,
        "vercel",
        "project-123",
        serde_json::json!({
            "status": "connected",
            "platform": "vercel",
            "projectId": "project-123",
        }),
    )
    .await;
    mock.with_platform_status_success(
        bearer_token,
        vault_id,
        serde_json::json!({
            "platforms": [
                {
                    "platform": "vercel",
                    "label": "production",
                    "env": "default",
                    "status": "synced",
                    "lastPushAt": "2030-01-01T00:00:00Z"
                }
            ]
        }),
    )
    .await;

    let connect = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args([
            "--json",
            "env",
            "connect",
            "vercel",
            "--project",
            "project-123",
            "--token",
            "vercel-token",
            "--label",
            "production",
        ])
        .output()
        .expect("failed to run lpm env connect --json");
    assert!(
        connect.status.success(),
        "env connect --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&connect.stdout),
        String::from_utf8_lossy(&connect.stderr),
    );
    let connect_json = parse_clean_json_stdout(&connect);
    assert_eq!(connect_json["success"], true);
    assert_eq!(connect_json["status"], "connected");
    assert_eq!(connect_json["platform"], "vercel");

    let status = lpm(&project)
        .env("LPM_REGISTRY_URL", mock.url())
        .args(["--json", "env", "status"])
        .output()
        .expect("failed to run lpm env status --json");
    assert!(
        status.status.success(),
        "env status --json failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = parse_clean_json_stdout(&status);
    assert_eq!(status_json["success"], true);
    assert_eq!(status_json["count"], 1);
    assert_eq!(status_json["platforms"][0]["platform"], "vercel");
}

#[tokio::test]
async fn env_platform_json_error_paths_emit_error_envelopes_on_stdout() {
    let cases: &[(&[&str], &str)] = &[
        (&["--json", "env", "log"], "no vault configured"),
        (&["--json", "env", "rotate-key"], "no vault configured"),
        (&["--json", "env", "list-remote"], "not logged in"),
    ];

    for (args, expected_error) in cases {
        let project = TempProject::empty(r#"{"name":"platform-json-errors","version":"1.0.0"}"#);
        let output = lpm(&project)
            .args(*args)
            .output()
            .unwrap_or_else(|error| panic!("failed to run lpm {args:?}: {error}"));

        assert!(
            !output.status.success(),
            "lpm {args:?} unexpectedly succeeded:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let json = parse_clean_json_stdout(&output);
        assert_eq!(json["success"], false, "lpm {args:?} envelope: {json}");
        assert_eq!(
            json["error_code"], "script",
            "lpm {args:?} envelope: {json}"
        );
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|error| error.contains(expected_error)),
            "lpm {args:?} should mention {expected_error:?}; got {json}",
        );
    }
}

#[tokio::test]
async fn env_rotate_sharing_key_refuses_without_a_tty() {
    // `lpm env rotate-sharing-key` is an interactive recovery surface
    // — it prompts for typed `ROTATE` confirmation AND for password /
    // TOTP via cliclack. Running it from a non-TTY context (CI,
    // unattended runner, `curl | sh`) would either block on stdin
    // forever or silently accept hostile input. The command MUST
    // refuse outright at flag-parse / TTY-detect time so the operator
    // never gets a half-rotated state.
    //
    // This test runs without a controlling TTY (cargo test inherits
    // the worker's pipe-backed stdin), so the refusal must fire
    // before any network, vault-state, or pending-key side effect.
    let project = TempProject::empty(r#"{"name":"rotate-sharing-key-non-tty","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "rotate-sharing-key"])
        .output()
        .expect("failed to run lpm env rotate-sharing-key");

    assert!(
        !output.status.success(),
        "rotate-sharing-key must fail with non-zero exit when stdin is not a TTY:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The cliclack error box wraps long lines and inserts `│`
    // continuation bars between segments, so we match on stable
    // substrings that don't span those wraps. The two pinned phrases
    // are load-bearing for the refusal semantics: the command name
    // (so a future error-message rewrite that drops it gets caught)
    // and "TTY" (so a regression that allows non-interactive flow
    // gets caught).
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("rotate-sharing-key"),
        "refusal must name the command so users know what was rejected; got: {combined}"
    );
    assert!(
        combined.contains("TTY"),
        "refusal must mention the TTY requirement so users know the cause; got: {combined}"
    );
}

#[tokio::test]
async fn env_rotate_sharing_key_refuses_yes_flag_explicitly() {
    // `--yes` is the conventional "skip prompt" flag elsewhere in the
    // CLI, but for the sharing-key rotation flow there is no safe way
    // to bypass the typed ROTATE confirmation + step-up reauth: the
    // command's whole purpose is to be the one rotation surface that
    // CANNOT be driven from an automated context. Pin the refusal so
    // a future change cannot accidentally turn `--yes` into a working
    // CI bypass.
    let project =
        TempProject::empty(r#"{"name":"rotate-sharing-key-yes-refused","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["env", "rotate-sharing-key", "--yes"])
        .output()
        .expect("failed to run lpm env rotate-sharing-key --yes");

    assert!(
        !output.status.success(),
        "rotate-sharing-key --yes must still fail:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("rotate-sharing-key") && combined.contains("TTY"),
        "expected the explicit refusal regardless of --yes; got: {combined}"
    );
}
