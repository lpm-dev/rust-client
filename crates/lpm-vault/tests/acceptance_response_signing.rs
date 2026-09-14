//! Runs the non-test library path; unit builds use a separate signing-key verifier.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use lpm_vault::{signature, sync};
use sha2::{Digest, Sha256};
use std::process::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn signed_response(request: &wiremock::Request, tampered: bool) -> ResponseTemplate {
    let key_id = "vault-test-rfc8032";
    let body = serde_json::json!({
        "envelopeVersion": 3,
        "operation": "sharingKey.read",
        "outcome": "absent",
        "requestNonce": request.headers["x-lpm-vault-request-nonce"].to_str().unwrap(),
        "binding": { "scope": "account", "principalId": "acceptance-principal" },
        "data": {}
    })
    .to_string();
    let seed = URL_SAFE_NO_PAD
        .decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
        .unwrap();
    let key = SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
    let mut frame = b"lpm-authenticated-response\0".to_vec();
    frame.push(4);
    frame.extend_from_slice(&200u16.to_be_bytes());
    frame.push(key_id.len() as u8);
    frame.extend_from_slice(key_id.as_bytes());
    frame.extend_from_slice(&(body.len() as u64).to_be_bytes());
    frame.extend_from_slice(&Sha256::digest(body.as_bytes()));
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&frame).to_bytes());
    ResponseTemplate::new(200)
        .insert_header(signature::KEY_ID_HEADER, key_id)
        .insert_header(signature::SIGNATURE_HEADER, signature)
        .set_body_string(if tampered {
            body.replace("acceptance-principal", "changed-principal")
        } else {
            body
        })
}

fn run_case(name: &str, isolated: bool, tampered: bool, accepted: bool) {
    if std::env::var("LPM_SIGNATURE_TEST_CHILD").as_deref() == Ok(name) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/users/me/public-key"))
                .respond_with(move |request: &wiremock::Request| signed_response(request, tampered))
                .expect(1)
                .mount(&server)
                .await;
            let result = sync::get_my_public_key_state(&server.uri(), "test-token").await;
            if accepted {
                let state = result.expect("isolated signed response must verify");
                assert_eq!(state.principal_id, "acceptance-principal");
                assert_eq!(state.public_key_b64, None);
                #[cfg(any(debug_assertions, feature = "acceptance-test-hooks"))]
                for address in [
                    "https://lpm.dev",
                    "http://example.com",
                    "http://localhost.example.com",
                    "https://127.0.0.1",
                    "https://localhost",
                ] {
                    assert!(!signature::is_local_development_key(
                        &reqwest::Url::parse(address).unwrap(),
                        Some("vault-test-rfc8032"),
                    ));
                }
            } else {
                let error = result.expect_err("test signing key must not bypass verification");
                assert!(
                    error.to_string().contains(
                        if tampered
                            && cfg!(any(debug_assertions, feature = "acceptance-test-hooks"))
                        {
                            "signature does not match"
                        } else {
                            "signing key ID is unknown"
                        }
                    ),
                    "{error}"
                );
            }
        });
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    std::fs::create_dir_all(home.join(".lpm")).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env("LPM_SIGNATURE_TEST_CHILD", name)
        .env("HOME", &home)
        .env("LPM_HOME", home.join(".lpm"))
        .env("LPM_ACCEPTANCE_FILE_STORAGE", "1")
        .env("ACCEPTANCE_RUN_ID", "response-signature-test")
        .env(
            "ACCEPTANCE_RUN_DIR",
            if isolated { directory.path() } else { &home },
        );
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn isolated_acceptance_uses_only_compiled_signing_keys() {
    run_case(
        "isolated_acceptance_uses_only_compiled_signing_keys",
        true,
        false,
        cfg!(any(debug_assertions, feature = "acceptance-test-hooks")),
    );
}

#[test]
fn release_verification_rejects_test_keys_without_storage_isolation() {
    run_case(
        "release_verification_rejects_test_keys_without_storage_isolation",
        false,
        false,
        cfg!(debug_assertions),
    );
}

#[test]
fn isolated_acceptance_rejects_tampered_signed_responses() {
    run_case(
        "isolated_acceptance_rejects_tampered_signed_responses",
        true,
        true,
        false,
    );
}
