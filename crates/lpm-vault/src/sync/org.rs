use std::collections::HashMap;

use super::http::{
    read_capped_error_text, read_verified_response, sync_http_client_builder, url_path_segment,
};
use super::personal::{
    ListVaultsResponse, PushMetadata, PushResponse, RemoteVault, format_push_error,
};
use super::public_key::{MemberPublicKey, ensure_public_key, get_org_member_keys};
use crate::crypto;

/// List all shared vaults for an org.
pub async fn list_org_vaults(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<Vec<RemoteVault>, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults",
        url_path_segment(org_slug)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("server error: {body}"));
    }

    let data: ListVaultsResponse = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

    Ok(data.vaults)
}

// ── Org Vault Sync ───────────────────────────────────────────────

/// Pull an org vault.
pub async fn pull_org(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    private_key: &[u8; 32],
) -> Result<(String, i32), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    if !status.is_success() {
        let message = std::str::from_utf8(&body).unwrap_or("");
        return Err(format!("server error: {message}"));
    }

    let data: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("parse error: {e}"))?;

    let blob = data
        .get("encryptedBlob")
        .and_then(|v| v.as_str())
        .ok_or("no encryptedBlob in response")?;
    let wrapped = data
        .get("wrappedKey")
        .and_then(|v| v.as_str())
        .ok_or("no wrappedKey in response (you may not have access)")?;
    let version = data.get("version").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

    // Unwrap AES key with our X25519 private key, then decrypt
    let aes_key = crypto::unwrap_key_from_sender(wrapped, private_key)?;
    let plaintext = crypto::decrypt(&aes_key, blob)?;
    let json = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;

    Ok((json, version))
}

/// Push an org vault with proper X25519 key wrapping for all members.
pub async fn push_org_with_keys(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    secrets_json: &str,
    expected_version: Option<i32>,
    metadata: Option<&PushMetadata<'_>>,
) -> Result<PushResponse, String> {
    // 1. Ensure our public key is registered
    let _private = ensure_public_key(registry_url, auth_token).await?;

    // 2. Fetch all org members' public keys
    let members = get_org_member_keys(registry_url, auth_token, org_slug).await?;

    let members_with_keys = select_members_with_keys(&members)?;

    // 3. Encrypt secrets with random AES key
    let aes_key = crypto::generate_aes_key();
    let encrypted_blob = crypto::encrypt(&aes_key, secrets_json.as_bytes())?;

    // 4. Wrap AES key for each member with their X25519 public key
    let wrapped_keys = wrap_keys_for_members(&aes_key, &members_with_keys)?;

    // 5. Push to server
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );

    let keys_json: Vec<serde_json::Value> = wrapped_keys
        .iter()
        .map(|(uid, wk)| serde_json::json!({"userId": uid, "wrappedKey": wk}))
        .collect();

    let mut body = serde_json::json!({
        "encryptedBlob": encrypted_blob,
        "wrappedKeys": keys_json,
    });
    if let Some(version) = expected_version {
        body["expectedVersion"] = serde_json::json!(version);
    }
    if let Some(meta) = metadata {
        if let Some(name) = meta.name {
            body["name"] = serde_json::json!(name);
        }
        if let Some(schema) = meta.schema {
            body["schema"] = schema.clone();
        }
    }

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(super::http::network_error)?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(format_push_error(&result, status));
    }

    Ok(result)
}

fn select_members_with_keys(members: &[MemberPublicKey]) -> Result<Vec<&MemberPublicKey>, String> {
    let members_with_keys: Vec<&MemberPublicKey> = members
        .iter()
        .filter(|member| member.has_public_key && member.public_key.is_some())
        .collect();

    if members_with_keys.is_empty() {
        return Err("no org members have registered public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into());
    }

    Ok(members_with_keys)
}

fn wrap_keys_for_members(
    aes_key: &[u8; 32],
    members_with_keys: &[&MemberPublicKey],
) -> Result<Vec<(String, String)>, String> {
    let mut wrapped_keys: Vec<(String, String)> = Vec::new();

    // Surface the (user_id, public_key) pairs every time we wrap. The
    // server-supplied member set is not locally pinned, so a compromised
    // registry could insert an extra "member" and receive a wrapped AES
    // key. Until recipient-key pinning exists, these warnings make each
    // recipient visible to an operator scanning logs. The pubkey prefix is
    // an eyeball-comparable discriminator, not a verification primitive.
    tracing::warn!(
        target: "lpm_vault::sync",
        recipient_count = members_with_keys.len(),
        "wrapping vault AES key for {} org member recipient(s) — verify each listed pubkey/userId tuple matches your expected member set; a compromised server can insert extra recipients",
        members_with_keys.len()
    );

    for member in members_with_keys {
        let pub_b64 = member
            .public_key
            .as_ref()
            .ok_or_else(|| format!("missing public key for user {}", member.user_id))?;
        let pub_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pub_b64)
            .map_err(|e| format!("invalid public key for user {}: {e}", member.user_id))?;

        if pub_bytes.len() != 32 {
            return Err(format!(
                "invalid public key for user {}: expected 32 bytes, got {}",
                member.user_id,
                pub_bytes.len()
            ));
        }

        // Per-recipient audit line so each one is individually visible.
        // The truncated pubkey gives an eyeball-comparable discriminator
        // without dumping the full base64.
        let pub_short = pub_b64.chars().take(12).collect::<String>();
        tracing::warn!(
            target: "lpm_vault::sync",
            user_id = %member.user_id,
            public_key_prefix = %pub_short,
            "vault share recipient"
        );

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);

        let wrapped = crypto::wrap_key_for_recipient(aes_key, &pub_key)?;
        wrapped_keys.push((member.user_id.clone(), wrapped));
    }

    if wrapped_keys.is_empty() {
        return Err(
            "no org members have valid public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into(),
        );
    }

    Ok(wrapped_keys)
}

/// Push an org vault (legacy — does NOT wrap keys, kept for backwards compat).
pub async fn push_org(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
    vault_id: &str,
    secrets: &HashMap<String, String>,
    wrapped_keys: &[(String, String)], // (userId, wrappedKey) pairs
) -> Result<PushResponse, String> {
    let secrets_json =
        serde_json::to_string(secrets).map_err(|e| format!("failed to serialize secrets: {e}"))?;

    // For org sync, caller provides already-wrapped keys
    // The vault blob is encrypted with a random AES key that the caller manages
    let aes_key = crypto::generate_aes_key();
    let encrypted_blob = crypto::encrypt(&aes_key, secrets_json.as_bytes())?;

    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );

    let keys: Vec<serde_json::Value> = wrapped_keys
        .iter()
        .map(|(user_id, key)| serde_json::json!({"userId": user_id, "wrappedKey": key}))
        .collect();

    let body = serde_json::json!({
        "encryptedBlob": encrypted_blob,
        "wrappedKeys": keys,
    });

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .send()
        .await
        .map_err(super::http::network_error)?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(format_push_error(&result, status));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(debug_assertions)]
    use crate::signature;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::env_lock_guard;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    #[cfg(debug_assertions)]
    use std::sync::{Arc, Mutex as StdMutex};
    #[cfg(debug_assertions)]
    use wiremock::matchers::{body_string_contains, header, method, path};
    #[cfg(debug_assertions)]
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[cfg(debug_assertions)]
    #[test]
    fn push_org_with_keys_regenerates_corrupted_forced_file_key_and_skips_members_without_keys() {
        let _guard = env_lock_guard();
        let temp = tempfile::tempdir().expect("failed to create temp home for forced vault test");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }

        let key_path = temp.path().join(".lpm").join(".x25519_key");
        std::fs::create_dir_all(
            key_path
                .parent()
                .expect("forced key path should have a parent"),
        )
        .expect("failed to create forced key dir");
        std::fs::write(&key_path, [3u8; 31]).expect("failed to seed corrupted forced key file");

        let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
                auth_token: &'static str,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone())
                        .expect("push_org_with_keys request body should be valid utf-8 json");
                    *self.body.lock().unwrap() = Some(body);
                    let response_body = serde_json::json!({
                        "version": 8,
                        "status": "ok"
                    });
                    let body_str = serde_json::to_string(&response_body)
                        .expect("response body should serialize");
                    let sig = signature::sign_body(body_str.as_bytes(), self.auth_token);
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "application/json")
                        .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
                        .set_body_string(body_str)
                }
            }

            let server = MockServer::start().await;
            let captured_body = Arc::new(StdMutex::new(None));
            let (_, member_public_key) = crypto::generate_x25519_keypair();

            Mock::given(method("GET"))
                .and(path("/api/users/me/public-key"))
                .and(header("authorization", "Bearer auth-token"))
                // Server's "no key on file" shape is a 200 with publicKey: null,
                // not a 404 — the prior `Ok(None)` collapse on non-2xx hid this.
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "publicKey": null,
                })))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/users/me/public-key"))
                .and(header("authorization", "Bearer auth-token"))
                .and(body_string_contains("\"publicKey\":\""))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true
                })))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .and(header("authorization", "Bearer auth-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "userId": "user-keyed",
                        "role": "admin",
                        "publicKey": BASE64.encode(member_public_key),
                        "hasPublicKey": true
                    },
                    {
                        "userId": "user-missing",
                        "role": "developer",
                        "publicKey": null,
                        "hasPublicKey": false
                    }
                ])))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/orgs/acme/vaults/vault-123"))
                .and(header("authorization", "Bearer auth-token"))
                .respond_with(CapturePushResponder {
                    body: Arc::clone(&captured_body),
                    auth_token: "auth-token",
                })
                .expect(1)
                .mount(&server)
                .await;

            let result = push_org_with_keys(
                &server.uri(),
                "auth-token",
                "acme",
                "vault-123",
                r#"{"API_KEY":"secret-value"}"#,
                Some(7),
                None,
            )
            .await
            .expect("org push should succeed with a mixed member-key set");

            assert_eq!(result.version, Some(8));
            let repaired_key = std::fs::read(&key_path)
                .expect("forced file-backed X25519 key should exist after repair");
            assert_eq!(
                repaired_key.len(),
                32,
                "corrupted forced file-backed X25519 state should be repaired before pushing"
            );

            let push_body = captured_body
                .lock()
                .unwrap()
                .clone()
                .expect("org push body should be captured");
            assert!(push_body.contains("\"expectedVersion\":7"));
            assert!(push_body.contains("\"userId\":\"user-keyed\""));
            assert!(
                !push_body.contains("\"userId\":\"user-missing\""),
                "members without a registered public key should not receive wrapped org vault keys"
            );
            assert!(push_body.contains("\"encryptedBlob\":\""));
            assert!(push_body.contains("\"wrappedKeys\":["));
        });

        original_home.restore();
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn push_org_with_keys_round_trips_name_and_schema_metadata() {
        // Org pushes used to omit `name` + `schema` from the request body, so
        // the dashboard for an org vault froze whatever schema was set at
        // creation time and never reflected later CLI pushes. This test pins
        // the contract: when the caller passes `PushMetadata`, both fields
        // land on the wire alongside the encrypted blob and wrapped keys.
        let _guard = env_lock_guard();
        let temp = tempfile::tempdir().expect("tempdir for metadata round-trip test");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }

        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
                auth_token: &'static str,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone())
                        .expect("push request body must be valid utf-8");
                    *self.body.lock().unwrap() = Some(body);
                    let response_body = serde_json::json!({
                        "version": 4,
                        "status": "ok"
                    });
                    let body_str = serde_json::to_string(&response_body).expect("serialize");
                    let sig = signature::sign_body(body_str.as_bytes(), self.auth_token);
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "application/json")
                        .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
                        .set_body_string(body_str)
                }
            }

            let server = MockServer::start().await;
            let captured_body = Arc::new(StdMutex::new(None));
            let (_, member_public_key) = crypto::generate_x25519_keypair();

            // ensure_public_key: server has no key → CLI uploads its key.
            // We can't predict the locally-generated keypair, so the GET
            // returns 404 and the POST upload accepts whatever the CLI sends.
            Mock::given(method("GET"))
                .and(path("/api/users/me/public-key"))
                // Server's "no key on file" shape is a 200 with publicKey: null,
                // not a 404 — the prior `Ok(None)` collapse on non-2xx hid this.
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "publicKey": null,
                })))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/users/me/public-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "userId": "user-1",
                        "role": "admin",
                        "publicKey": BASE64.encode(member_public_key),
                        "hasPublicKey": true
                    }
                ])))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/orgs/acme/vaults/vault-meta"))
                .respond_with(CapturePushResponder {
                    body: Arc::clone(&captured_body),
                    auth_token: "auth-token",
                })
                .expect(1)
                .mount(&server)
                .await;

            let schema = serde_json::json!({
                "version": 2,
                "envSchema": {
                    "DATABASE_URL": { "required": true, "format": "url" }
                }
            });
            let metadata = PushMetadata {
                name: Some("acme-api"),
                schema: Some(&schema),
            };

            let result = push_org_with_keys(
                &server.uri(),
                "auth-token",
                "acme",
                "vault-meta",
                r#"{"DATABASE_URL":"postgres://"}"#,
                Some(3),
                Some(&metadata),
            )
            .await
            .expect("org push should succeed when metadata is supplied");

            assert_eq!(result.version, Some(4));

            let raw = captured_body
                .lock()
                .unwrap()
                .clone()
                .expect("captured push body");
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("push body must be valid JSON");

            assert_eq!(
                parsed.get("name"),
                Some(&serde_json::json!("acme-api")),
                "org push must round-trip the project name field"
            );
            assert_eq!(
                parsed
                    .get("schema")
                    .and_then(|s| s.get("envSchema"))
                    .and_then(|e| e.get("DATABASE_URL"))
                    .and_then(|d| d.get("required")),
                Some(&serde_json::json!(true)),
                "org push must round-trip the envSchema content alongside the encrypted blob"
            );
            assert!(
                parsed.get("encryptedBlob").is_some(),
                "encryptedBlob field must still be present alongside metadata"
            );
            assert!(
                parsed.get("wrappedKeys").is_some(),
                "wrappedKeys field must still be present alongside metadata"
            );
            assert_eq!(
                parsed.get("expectedVersion"),
                Some(&serde_json::json!(3)),
                "expectedVersion must still be present alongside metadata"
            );
        });

        original_home.restore();
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn push_org_with_keys_omits_metadata_fields_when_caller_passes_none() {
        // Symmetry with the round-trip test above: when no metadata is
        // supplied, the body must NOT contain `name` or `schema` fields.
        // This pins the "explicit None means don't touch dashboard
        // metadata" contract — server keeps last-known-good schema/name.
        let _guard = env_lock_guard();
        let temp = tempfile::tempdir().expect("tempdir for None-metadata test");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }

        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
                auth_token: &'static str,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone()).expect("push body utf-8");
                    *self.body.lock().unwrap() = Some(body);
                    let response_body = serde_json::json!({
                        "version": 1,
                        "status": "ok"
                    });
                    let body_str = serde_json::to_string(&response_body).expect("serialize");
                    let sig = signature::sign_body(body_str.as_bytes(), self.auth_token);
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "application/json")
                        .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
                        .set_body_string(body_str)
                }
            }

            let server = MockServer::start().await;
            let captured_body = Arc::new(StdMutex::new(None));
            let (_, member_public_key) = crypto::generate_x25519_keypair();

            Mock::given(method("GET"))
                .and(path("/api/users/me/public-key"))
                // Server's "no key on file" shape is a 200 with publicKey: null,
                // not a 404 — the prior `Ok(None)` collapse on non-2xx hid this.
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "publicKey": null,
                })))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/users/me/public-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "userId": "user-1",
                        "role": "admin",
                        "publicKey": BASE64.encode(member_public_key),
                        "hasPublicKey": true
                    }
                ])))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/api/orgs/acme/vaults/vault-no-meta"))
                .respond_with(CapturePushResponder {
                    body: Arc::clone(&captured_body),
                    auth_token: "auth-token",
                })
                .expect(1)
                .mount(&server)
                .await;

            push_org_with_keys(
                &server.uri(),
                "auth-token",
                "acme",
                "vault-no-meta",
                r#"{"K":"V"}"#,
                None,
                None,
            )
            .await
            .expect("org push should succeed without metadata");

            let raw = captured_body
                .lock()
                .unwrap()
                .clone()
                .expect("captured body");
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("body must parse as JSON");

            assert!(
                parsed.get("name").is_none(),
                "name must not be sent when metadata is None"
            );
            assert!(
                parsed.get("schema").is_none(),
                "schema must not be sent when metadata is None"
            );
        });

        original_home.restore();
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[test]
    fn wrap_keys_for_members_rejects_malformed_public_key_length() {
        let aes_key = crypto::generate_aes_key();
        let short_key = BASE64.encode([9u8; 31]);
        let member = MemberPublicKey {
            user_id: "user-short".into(),
            role: "admin".into(),
            public_key: Some(short_key),
            has_public_key: true,
        };

        let result = wrap_keys_for_members(&aes_key, &[&member]);

        assert!(matches!(
            result,
            Err(message)
                if message == "invalid public key for user user-short: expected 32 bytes, got 31"
        ));
    }

    #[test]
    fn wrap_keys_for_members_wraps_each_valid_member_key() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let member_a = MemberPublicKey {
            user_id: "user-a".into(),
            role: "admin".into(),
            public_key: Some(BASE64.encode(public_a)),
            has_public_key: true,
        };
        let member_b = MemberPublicKey {
            user_id: "user-b".into(),
            role: "developer".into(),
            public_key: Some(BASE64.encode(public_b)),
            has_public_key: true,
        };

        let result = wrap_keys_for_members(&aes_key, &[&member_a, &member_b])
            .expect("valid member keys should wrap successfully");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "user-a");
        assert!(!result[0].1.is_empty());
        assert_eq!(result[1].0, "user-b");
        assert!(!result[1].1.is_empty());
    }

    #[test]
    fn select_members_with_keys_skips_members_without_registered_keys() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_key) = crypto::generate_x25519_keypair();
        let member_with_key = MemberPublicKey {
            user_id: "user-keyed".into(),
            role: "admin".into(),
            public_key: Some(BASE64.encode(public_key)),
            has_public_key: true,
        };
        let member_without_key = MemberPublicKey {
            user_id: "user-missing".into(),
            role: "developer".into(),
            public_key: None,
            has_public_key: false,
        };
        let member_with_incomplete_registration = MemberPublicKey {
            user_id: "user-incomplete".into(),
            role: "developer".into(),
            public_key: None,
            has_public_key: true,
        };

        let members = [
            member_without_key,
            member_with_key,
            member_with_incomplete_registration,
        ];

        let selected = select_members_with_keys(&members)
            .expect("at least one keyed member should keep org sharing enabled");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].user_id, "user-keyed");

        let wrapped = wrap_keys_for_members(&aes_key, &selected)
            .expect("only the keyed member should receive a wrapped AES key");

        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0].0, "user-keyed");
        assert!(!wrapped[0].1.is_empty());
    }

    #[test]
    fn wrap_keys_for_members_drops_stale_recipients_when_member_set_changes_between_shares() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let (_, public_c) = crypto::generate_x25519_keypair();
        let member_a = MemberPublicKey {
            user_id: "user-a".into(),
            role: "admin".into(),
            public_key: Some(BASE64.encode(public_a)),
            has_public_key: true,
        };
        let member_b = MemberPublicKey {
            user_id: "user-b".into(),
            role: "developer".into(),
            public_key: Some(BASE64.encode(public_b)),
            has_public_key: true,
        };
        let member_c = MemberPublicKey {
            user_id: "user-c".into(),
            role: "developer".into(),
            public_key: Some(BASE64.encode(public_c)),
            has_public_key: true,
        };

        let first_share = wrap_keys_for_members(&aes_key, &[&member_a, &member_b])
            .expect("first share should wrap current member set");
        let second_share = wrap_keys_for_members(&aes_key, &[&member_b, &member_c])
            .expect("second share should wrap updated member set");

        let first_ids: std::collections::BTreeSet<_> = first_share
            .iter()
            .map(|(user_id, _)| user_id.as_str())
            .collect();
        let second_ids: std::collections::BTreeSet<_> = second_share
            .iter()
            .map(|(user_id, _)| user_id.as_str())
            .collect();

        assert_eq!(
            first_ids,
            std::collections::BTreeSet::from(["user-a", "user-b"])
        );
        assert_eq!(
            second_ids,
            std::collections::BTreeSet::from(["user-b", "user-c"])
        );
        assert!(
            !second_ids.contains("user-a"),
            "stale recipients from prior shares must not remain in a new wrapped-key set"
        );
    }
}
