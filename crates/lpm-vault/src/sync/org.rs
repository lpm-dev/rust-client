use super::http::{
    read_capped_error_text, read_verified_response, sync_http_client_builder, url_path_segment,
};
use super::personal::{
    ListVaultsResponse, PushMetadata, PushResponse, RemoteVault, format_push_error,
};
use super::public_key::{MemberPublicKey, get_org_member_keys, public_key_fingerprint};
use crate::crypto;

/// Decrypted organization env payload and its remote concurrency epochs.
#[derive(Debug)]
pub struct PulledOrgVault {
    /// Complete decrypted JSON payload.
    pub raw_json: String,
    /// Ciphertext version used for compare-and-swap writes.
    pub version: i32,
    /// Version of the organization content key that encrypted the payload.
    pub content_key_version: i32,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WrappedMemberKey {
    user_id: String,
    wrapped_key: String,
    public_key_version: i32,
    public_key_fingerprint: String,
}

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
) -> Result<PulledOrgVault, String> {
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

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PullOrgResponse {
        encrypted_blob: String,
        wrapped_key: String,
        version: i32,
        content_key_version: i32,
        recipient_public_key_version: i32,
        recipient_public_key_fingerprint: String,
    }

    let data: PullOrgResponse =
        serde_json::from_slice(&body).map_err(|e| format!("parse error: {e}"))?;

    let local_public_key =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private_key));
    let local_fingerprint = public_key_fingerprint(local_public_key.as_bytes());
    if data.recipient_public_key_fingerprint != local_fingerprint {
        return Err(
            "organization env wrap targets a different local sharing-key fingerprint; rotate or restore the correct sharing key before retrying"
                .into(),
        );
    }
    if data.version <= 0 || data.content_key_version <= 0 || data.recipient_public_key_version <= 0
    {
        return Err("organization env response contains an invalid key/version binding".into());
    }

    // Unwrap AES key with our X25519 private key, then decrypt
    let aes_key = crypto::unwrap_key_from_sender(&data.wrapped_key, private_key)?;
    let plaintext = crypto::decrypt(&aes_key, &data.encrypted_blob)?;
    let json = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;

    Ok(PulledOrgVault {
        raw_json: json,
        version: data.version,
        content_key_version: data.content_key_version,
    })
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
    let members = get_org_member_keys(registry_url, auth_token, org_slug).await?;

    let members_with_keys = select_members_with_keys(&members)?;

    let aes_key = crypto::generate_aes_key();
    let encrypted_blob = crypto::encrypt(&aes_key, secrets_json.as_bytes())?;

    let wrapped_keys = wrap_keys_for_members(&aes_key, &members_with_keys)?;

    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/vaults/{}",
        url_path_segment(org_slug),
        url_path_segment(vault_id)
    );

    let mut body = serde_json::json!({
        "encryptedBlob": encrypted_blob,
        "wrappedKeys": wrapped_keys,
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
    let mut members_with_keys = Vec::with_capacity(members.len());
    for member in members {
        if !member.has_public_key {
            if member.public_key.is_some()
                || member.public_key_version.is_some()
                || member.public_key_fingerprint.is_some()
            {
                return Err(format!(
                    "inconsistent public-key state for organization member {}",
                    member.user_id
                ));
            }
            continue;
        }
        if member.public_key.is_none()
            || member.public_key_version.is_none()
            || member.public_key_fingerprint.is_none()
        {
            return Err(format!(
                "organization member {} has an incomplete public-key binding",
                member.user_id
            ));
        }
        members_with_keys.push(member);
    }

    if members_with_keys.is_empty() {
        return Err("no org members have registered public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into());
    }

    Ok(members_with_keys)
}

fn wrap_keys_for_members(
    aes_key: &[u8; 32],
    members_with_keys: &[&MemberPublicKey],
) -> Result<Vec<WrappedMemberKey>, String> {
    let mut wrapped_keys = Vec::with_capacity(members_with_keys.len());

    // The registry supplies the member set. Log every recipient so an operator
    // can compare the set against the organization roster before distribution.
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

        let pub_short = pub_b64.chars().take(12).collect::<String>();
        tracing::warn!(
            target: "lpm_vault::sync",
            user_id = %member.user_id,
            public_key_prefix = %pub_short,
            "vault share recipient"
        );

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);
        let fingerprint = public_key_fingerprint(&pub_key);
        let expected_fingerprint = member
            .public_key_fingerprint
            .as_deref()
            .ok_or_else(|| format!("missing public-key fingerprint for user {}", member.user_id))?;
        if fingerprint != expected_fingerprint {
            return Err(format!(
                "public-key fingerprint mismatch for organization member {}",
                member.user_id
            ));
        }
        let public_key_version = member
            .public_key_version
            .filter(|version| *version > 0)
            .ok_or_else(|| format!("invalid public-key version for user {}", member.user_id))?;

        let wrapped = crypto::wrap_key_for_recipient(aes_key, &pub_key)?;
        wrapped_keys.push(WrappedMemberKey {
            user_id: member.user_id.clone(),
            wrapped_key: wrapped,
            public_key_version,
            public_key_fingerprint: fingerprint,
        });
    }

    if wrapped_keys.is_empty() {
        return Err(
            "no org members have valid public keys. Each member needs to run `lpm env share --org <slug>` once to generate their keypair.".into(),
        );
    }

    Ok(wrapped_keys)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(debug_assertions)]
    use crate::signature;
    #[cfg(debug_assertions)]
    use crate::sync::test_support::{env_lock_guard, signed_ok_response};
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Digest, Sha256};
    #[cfg(debug_assertions)]
    use std::sync::{Arc, Mutex as StdMutex};
    #[cfg(debug_assertions)]
    use wiremock::matchers::{header, method, path};
    #[cfg(debug_assertions)]
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn registered_member(
        user_id: &str,
        role: &str,
        public_key: [u8; 32],
        public_key_version: i32,
    ) -> MemberPublicKey {
        MemberPublicKey {
            user_id: user_id.into(),
            role: role.into(),
            public_key: Some(BASE64.encode(public_key)),
            public_key_version: Some(public_key_version),
            public_key_fingerprint: Some(public_key_fingerprint(&public_key)),
            has_public_key: true,
        }
    }

    #[cfg(debug_assertions)]
    fn encrypted_org_pull_body(
        private_key: &[u8; 32],
        payload: &str,
        version: i32,
        content_key_version: i32,
        fingerprint: String,
    ) -> serde_json::Value {
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private_key));
        let content_key = crypto::generate_aes_key();
        serde_json::json!({
            "encryptedBlob": crypto::encrypt(&content_key, payload.as_bytes())
                .expect("encrypt org pull fixture"),
            "wrappedKey": crypto::wrap_key_for_recipient(&content_key, public_key.as_bytes())
                .expect("wrap org pull fixture key"),
            "version": version,
            "contentKeyVersion": content_key_version,
            "recipientPublicKeyVersion": 4,
            "recipientPublicKeyFingerprint": fingerprint,
        })
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_returns_plaintext_and_bound_versions_for_current_recipient_key() {
        let private_key = [11u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let body = encrypted_org_pull_body(
            &private_key,
            r#"{"environments":{"default":{"TOKEN":"secret"}}}"#,
            8,
            3,
            public_key_fingerprint(public_key.as_bytes()),
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-1"))
            .respond_with(signed_ok_response(body, "auth-token"))
            .expect(1)
            .mount(&server)
            .await;

        let pulled = pull_org(&server.uri(), "auth-token", "acme", "vault-1", &private_key)
            .await
            .expect("bound org payload should decrypt");

        assert_eq!(pulled.version, 8);
        assert_eq!(pulled.content_key_version, 3);
        assert_eq!(
            pulled.raw_json,
            r#"{"environments":{"default":{"TOKEN":"secret"}}}"#
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_wrap_for_different_recipient_fingerprint() {
        let private_key = [12u8; 32];
        let body =
            encrypted_org_pull_body(&private_key, r#"{"TOKEN":"secret"}"#, 2, 1, "a".repeat(64));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-2"))
            .respond_with(signed_ok_response(body, "auth-token"))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(&server.uri(), "auth-token", "acme", "vault-2", &private_key)
            .await
            .expect_err("stale recipient fingerprint must fail closed");

        assert!(error.contains("different local sharing-key fingerprint"));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn pull_org_rejects_non_positive_content_key_version() {
        let private_key = [13u8; 32];
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key));
        let body = encrypted_org_pull_body(
            &private_key,
            r#"{"TOKEN":"secret"}"#,
            2,
            0,
            public_key_fingerprint(public_key.as_bytes()),
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/vaults/vault-3"))
            .respond_with(signed_ok_response(body, "auth-token"))
            .expect(1)
            .mount(&server)
            .await;

        let error = pull_org(&server.uri(), "auth-token", "acme", "vault-3", &private_key)
            .await
            .expect_err("invalid content-key epoch must fail closed");

        assert_eq!(
            error,
            "organization env response contains an invalid key/version binding"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn push_org_with_keys_skips_members_without_keys_and_binds_current_recipient() {
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
                let body_str =
                    serde_json::to_string(&response_body).expect("response body should serialize");
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
        let member_fingerprint = format!("{:x}", Sha256::digest(member_public_key));

        Mock::given(method("GET"))
            .and(path("/api/orgs/acme/members/public-keys"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "userId": "user-keyed",
                    "role": "admin",
                    "publicKey": BASE64.encode(member_public_key),
                    "publicKeyVersion": 7,
                    "publicKeyFingerprint": member_fingerprint,
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

        let push_body = captured_body
            .lock()
            .unwrap()
            .clone()
            .expect("org push body should be captured");
        assert!(push_body.contains("\"expectedVersion\":7"));
        assert!(push_body.contains("\"userId\":\"user-keyed\""));
        assert!(push_body.contains("\"publicKeyVersion\":7"));
        assert!(push_body.contains(&format!(
            "\"publicKeyFingerprint\":\"{member_fingerprint}\""
        )));
        assert!(
            !push_body.contains("\"userId\":\"user-missing\""),
            "members without a registered public key should not receive wrapped org vault keys"
        );
        assert!(push_body.contains("\"encryptedBlob\":\""));
        assert!(push_body.contains("\"wrappedKeys\":["));
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

            Mock::given(method("GET"))
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "userId": "user-1",
                        "role": "admin",
                        "publicKey": BASE64.encode(member_public_key),
                        "publicKeyVersion": 1,
                        "publicKeyFingerprint": public_key_fingerprint(&member_public_key),
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
                .and(path("/api/orgs/acme/members/public-keys"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "userId": "user-1",
                        "role": "admin",
                        "publicKey": BASE64.encode(member_public_key),
                        "publicKeyVersion": 1,
                        "publicKeyFingerprint": public_key_fingerprint(&member_public_key),
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
            public_key_version: Some(1),
            public_key_fingerprint: Some("a".repeat(64)),
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
        let member_a = registered_member("user-a", "admin", public_a, 3);
        let member_b = registered_member("user-b", "developer", public_b, 5);

        let result = wrap_keys_for_members(&aes_key, &[&member_a, &member_b])
            .expect("valid member keys should wrap successfully");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].user_id, "user-a");
        assert!(!result[0].wrapped_key.is_empty());
        assert_eq!(result[0].public_key_version, 3);
        assert_eq!(
            result[0].public_key_fingerprint,
            public_key_fingerprint(&public_a)
        );
        assert_eq!(result[1].user_id, "user-b");
        assert!(!result[1].wrapped_key.is_empty());
        assert_eq!(result[1].public_key_version, 5);
        assert_eq!(
            result[1].public_key_fingerprint,
            public_key_fingerprint(&public_b)
        );
    }

    #[test]
    fn select_members_with_keys_skips_members_without_registered_keys() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_key) = crypto::generate_x25519_keypair();
        let member_with_key = registered_member("user-keyed", "admin", public_key, 1);
        let member_without_key = MemberPublicKey {
            user_id: "user-missing".into(),
            role: "developer".into(),
            public_key: None,
            public_key_version: None,
            public_key_fingerprint: None,
            has_public_key: false,
        };

        let members = [member_without_key, member_with_key];

        let selected = select_members_with_keys(&members)
            .expect("at least one keyed member should keep org sharing enabled");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].user_id, "user-keyed");

        let wrapped = wrap_keys_for_members(&aes_key, &selected)
            .expect("only the keyed member should receive a wrapped AES key");

        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0].user_id, "user-keyed");
        assert!(!wrapped[0].wrapped_key.is_empty());
    }

    #[test]
    fn select_members_with_keys_rejects_incomplete_registered_member_binding() {
        let member = MemberPublicKey {
            user_id: "user-incomplete".into(),
            role: "developer".into(),
            public_key: Some(BASE64.encode([7u8; 32])),
            public_key_version: None,
            public_key_fingerprint: None,
            has_public_key: true,
        };

        let error =
            select_members_with_keys(&[member]).expect_err("incomplete bindings must fail closed");

        assert_eq!(
            error,
            "organization member user-incomplete has an incomplete public-key binding"
        );
    }

    #[test]
    fn wrap_keys_for_members_drops_stale_recipients_when_member_set_changes_between_shares() {
        let aes_key = crypto::generate_aes_key();
        let (_, public_a) = crypto::generate_x25519_keypair();
        let (_, public_b) = crypto::generate_x25519_keypair();
        let (_, public_c) = crypto::generate_x25519_keypair();
        let member_a = registered_member("user-a", "admin", public_a, 1);
        let member_b = registered_member("user-b", "developer", public_b, 1);
        let member_c = registered_member("user-c", "developer", public_c, 1);

        let first_share = wrap_keys_for_members(&aes_key, &[&member_a, &member_b])
            .expect("first share should wrap current member set");
        let second_share = wrap_keys_for_members(&aes_key, &[&member_b, &member_c])
            .expect("second share should wrap updated member set");

        let first_ids: std::collections::BTreeSet<_> = first_share
            .iter()
            .map(|wrapped| wrapped.user_id.as_str())
            .collect();
        let second_ids: std::collections::BTreeSet<_> = second_share
            .iter()
            .map(|wrapped| wrapped.user_id.as_str())
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
