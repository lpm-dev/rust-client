#![cfg(debug_assertions)]

mod support;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::auth_state::{SessionSeed, seed_sessions};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, write_private_file};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, ResponseTemplate};

const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";

async fn organization_pairing(key_matches: bool, account_changes: bool) {
    let project =
        TempProject::empty(r#"{"name":"organization-browser-pairing","version":"1.0.0"}"#);
    let registry = MockRegistry::start().await;
    let (private_key, public_key) = lpm_vault::crypto::generate_x25519_keypair();
    let registry_url = registry.url();
    let mut scope_hash = Sha256::new();
    for component in [registry_url.as_bytes(), ACCOUNT.as_bytes()] {
        scope_hash.update((component.len() as u64).to_be_bytes());
        scope_hash.update(component);
    }
    let lpm_dir = project.home().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let key_path = lpm_dir.join(format!(
        ".x25519-key-{}",
        hex::encode(scope_hash.finalize())
    ));
    write_private_file(&key_path, private_key);
    let registered_key = if key_matches {
        public_key
    } else {
        lpm_vault::crypto::generate_x25519_keypair().1
    };
    let count = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/api/users/me/public-key"))
        .and(header("authorization", "Bearer session-token"))
        .respond_with(move |request: &wiremock::Request| {
            let call = count.fetch_add(1, Ordering::SeqCst);
            let principal = if account_changes && call > 0 { "22222222-2222-4222-8222-222222222222" } else { ACCOUNT };
            let body = serde_json::json!({
                "envelopeVersion": 3, "operation": "sharingKey.read", "outcome": "present",
                "requestNonce": request.headers["x-lpm-vault-request-nonce"].to_str().unwrap(),
                "binding": {"scope": "account", "principalId": principal},
                "data": { "sharingKey": { "publicKey": BASE64.encode(registered_key), "algorithm": "X25519", "version": 1, "createdAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-09-01T00:00:00Z", "fingerprint": hex::encode(Sha256::digest(registered_key)) } }
            }).to_string();
            let (key_id, signature) = lpm_vault::signature::sign_response_for_test(200, body.as_bytes());
            ResponseTemplate::new(200)
                .insert_header(lpm_vault::signature::KEY_ID_HEADER, key_id.as_str())
                .insert_header(lpm_vault::signature::SIGNATURE_HEADER, signature.as_str())
                .set_body_string(body)
        }).expect(2).mount(registry.server()).await;
    let browser_private = SecretKey::random(&mut rand::thread_rng());
    let browser_public = BASE64.encode(
        browser_private
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    Mock::given(method("GET"))
        .and(path("/api/vault/pair/ORG123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "status": "pending", "protocolVersion": 4, "browserPublicKey": browser_public })))
        .expect(1).mount(registry.server()).await;
    Mock::given(method("POST"))
        .and(path("/api/vault/pair/ORG123"))
        .and(body_partial_json(serde_json::json!({"action": "stage", "protocolVersion": 4, "expectedPrincipalId": ACCOUNT})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "confirming"})))
        .expect(1).mount(registry.server()).await;
    Mock::given(method("POST"))
        .and(path("/api/vault/pair/ORG123"))
        .and(body_partial_json(serde_json::json!({"action": "approve", "protocolVersion": 4, "expectedPrincipalId": ACCOUNT})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true})))
        .expect(u64::from(key_matches && !account_changes)).mount(registry.server()).await;
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: &registry_url,
            access_token: Some("session-token"),
            refresh_token: Some("refresh-token"),
            session_access_expires_at: Some("2030-01-01T00:00:00Z"),
        }],
    );
    let output = lpm(&project)
        .env("LPM_REGISTRY_URL", &registry_url)
        .args(["env", "pair", "org123", "--yes"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        key_matches && !account_changes,
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(key_path).unwrap(), private_key);
    assert!(
        !lpm_dir.join(".vault-key").exists(),
        "organization pairing must not create or transfer a personal key"
    );
    if output.status.success() {
        let requests = registry.server().received_requests().await.unwrap();
        let approvals: Vec<serde_json::Value> = requests
            .iter()
            .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
            .filter(|b| b["action"] == "approve")
            .collect();
        assert_eq!(approvals.len(), 1);
        let cli_public = p256::PublicKey::from_sec1_bytes(
            &BASE64
                .decode(approvals[0]["ephemeralPublicKey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let shared =
            p256::ecdh::diffie_hellman(browser_private.to_nonzero_scalar(), cli_public.as_affine());
        let mut transport_key = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, shared.raw_secret_bytes())
            .expand(b"lpm-dashboard-pair-org-v4", &mut transport_key)
            .unwrap();
        let transferred = lpm_vault::crypto::decrypt(
            &transport_key,
            approvals[0]["encryptedWrappingKey"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(transferred, private_key);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(if account_changes {
                "account changed"
            } else {
                "registered organization sharing key"
            }),
            "{stderr}"
        );
    }
}

#[tokio::test]
async fn organization_pairing_transfers_only_the_registered_account_sharing_key() {
    organization_pairing(true, false).await;
}

#[tokio::test]
async fn organization_pairing_rejects_a_different_local_sharing_key() {
    organization_pairing(false, false).await;
}

#[tokio::test]
async fn organization_pairing_rejects_an_account_change_before_key_transfer() {
    organization_pairing(true, true).await;
}
