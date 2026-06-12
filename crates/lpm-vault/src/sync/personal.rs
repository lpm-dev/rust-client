use std::collections::HashMap;

use super::http::{
    read_capped_error_text, read_verified_response, sync_http_client_builder, sync_request_timeout,
    url_path_segment,
};
use crate::crypto;

/// Response from push endpoint.
///
/// Carries both success-path fields (`version`, `status`) and the structured
/// error-path fields the server sends with 4xx responses
/// (`error`, `code`, `server_version`, `hint`). The error envelope is shared
/// across the personal sync route and the org sync route. Two codes that
/// command-layer callers may want to switch on:
///
///   - `vault_version_conflict` — caller's `expectedVersion` did not match
///     the server's current version. Already produced by the existing CAS path.
///   - `vault_expected_version_required` — caller omitted `expectedVersion`
///     against an existing row. The server refuses the overwrite. Hint asks
///     the user to pull first then retry.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResponse {
    pub version: Option<i32>,
    pub status: Option<String>,
    pub error: Option<String>,
    pub code: Option<String>,
    pub server_version: Option<i32>,
    pub hint: Option<String>,
}

/// Render a server-supplied error envelope into a single user-facing string.
/// Appends `hint` when present so the CLI surface shows both the cause and
/// the actionable remediation in one message.
pub(super) fn format_push_error(result: &PushResponse, status: reqwest::StatusCode) -> String {
    let base = result
        .error
        .clone()
        .unwrap_or_else(|| format!("server error: {status}"));
    match result.hint.as_deref() {
        Some(hint) if !hint.is_empty() => format!("{base}\n\nHint: {hint}"),
        _ => base,
    }
}

/// Response from pull endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub vault_id: Option<String>,
    pub encrypted_blob: Option<String>,
    pub wrapped_key: Option<String>,
    pub version: Option<i32>,
    pub error: Option<String>,
}

/// Remote vault entry from list endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteVault {
    pub vault_id: String,
    pub version: Option<i32>,
    pub updated_at: Option<String>,
}

/// Response from list vaults endpoint.
#[derive(serde::Deserialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<RemoteVault>,
}

/// List all cloud vaults for the authenticated user.
pub async fn list_remote(registry_url: &str, auth_token: &str) -> Result<Vec<RemoteVault>, String> {
    let url = format!("{registry_url}/api/vaults");
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

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

/// Push a vault to the cloud (personal sync).
pub async fn push(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    secrets: &HashMap<String, String>,
    expected_version: Option<i32>,
    force: bool,
) -> Result<PushResponse, String> {
    let secrets_json =
        serde_json::to_string(secrets).map_err(|e| format!("failed to serialize secrets: {e}"))?;

    push_raw(
        registry_url,
        auth_token,
        vault_id,
        &secrets_json,
        expected_version,
        force,
        None,
    )
    .await
}

/// Optional metadata sent alongside a vault push.
pub struct PushMetadata<'a> {
    /// Project name (from package.json, lpm.json, or directory name).
    pub name: Option<&'a str>,
    /// Env schema from `lpm.json` `envSchema` field (as a JSON value).
    pub schema: Option<&'a serde_json::Value>,
}

/// Push pre-serialized JSON to the cloud. Used when pushing all environments.
pub async fn push_raw(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    secrets_json: &str,
    expected_version: Option<i32>,
    force: bool,
    metadata: Option<&PushMetadata<'_>>,
) -> Result<PushResponse, String> {
    let secrets_json = secrets_json.to_string();

    let (encrypted_blob, wrapped_key) = crypto::encrypt_vault_for_sync(&secrets_json)?;

    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );

    let mut body = serde_json::json!({
        "encryptedBlob": encrypted_blob,
        "wrappedKey": wrapped_key,
    });
    if let Some(v) = expected_version {
        body["expectedVersion"] = serde_json::json!(v);
    }
    if force {
        body["force"] = serde_json::json!(true);
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
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    if !status.is_success() {
        if let Ok(result) = serde_json::from_slice::<PushResponse>(&body) {
            return Err(format_push_error(&result, status));
        }

        let message = std::str::from_utf8(&body).unwrap_or("").trim();
        return Err(if message.is_empty() {
            format!("server error: {status}")
        } else {
            message.to_string()
        });
    }

    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    Ok(result)
}

/// Pull a vault from the cloud (personal sync).
pub async fn pull(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(HashMap<String, String>, i32), String> {
    let client = sync_http_client_builder()
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PullResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    let encrypted_blob = result
        .encrypted_blob
        .ok_or("server returned no encrypted data")?;
    let wrapped_key = result.wrapped_key.ok_or("server returned no wrapped key")?;
    let version = result.version.unwrap_or(0);

    let result = crypto::decrypt_vault_from_sync(auth_token, &encrypted_blob, &wrapped_key)?;
    let secrets_json = &result.plaintext;

    if result.needs_reencrypt {
        attempt_legacy_reencrypt_push(registry_url, auth_token, vault_id, version, secrets_json)
            .await;
    }

    // Try environments format first: {"environments": {"default": {...}, "live": {...}}}
    if let Ok(wrapper) = serde_json::from_str::<
        HashMap<String, HashMap<String, HashMap<String, String>>>,
    >(secrets_json)
        && let Some(envs) = wrapper.get("environments")
    {
        // Return "default" env for backwards compat
        let default = envs.get("default").cloned().unwrap_or_default();
        return Ok((default, version));
    }

    // Fall back to flat format: {"KEY": "VALUE"}
    let secrets: HashMap<String, String> = serde_json::from_str(secrets_json)
        .map_err(|e| format!("failed to parse decrypted secrets: {e}"))?;

    Ok((secrets, version))
}

/// Pull and return the raw decrypted JSON (for callers that handle environments themselves).
pub async fn pull_raw(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(String, i32), String> {
    let client = sync_http_client_builder()
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PullResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    let encrypted_blob = result
        .encrypted_blob
        .ok_or("server returned no encrypted data")?;
    let wrapped_key = result.wrapped_key.ok_or("server returned no wrapped key")?;
    let version = result.version.unwrap_or(0);

    let result = crypto::decrypt_vault_from_sync(auth_token, &encrypted_blob, &wrapped_key)?;

    if result.needs_reencrypt {
        attempt_legacy_reencrypt_push(
            registry_url,
            auth_token,
            vault_id,
            version,
            &result.plaintext,
        )
        .await;
    }

    Ok((result.plaintext, version))
}

/// Re-encrypt a legacy-decrypted vault with the new stored wrapping key and
/// push the result back, on a best-effort basis. Called by `pull` and
/// `pull_raw` after [`crypto::decrypt_vault_from_sync`] reports
/// `needs_reencrypt = true` so the vault converges to the new key without
/// an extra user step.
///
/// Best-effort by design — a successful pull must not fail because the
/// migration push hit a transient network error or version race. Failures
/// are logged at `warn` so they're observable, not silently swallowed; the
/// next successful pull will re-attempt the migration.
async fn attempt_legacy_reencrypt_push(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    version: i32,
    secrets_json: &str,
) {
    tracing::info!("migrating vault {vault_id} to stored wrapping key");

    let (new_blob, new_wrapped) = match crypto::encrypt_vault_for_sync(secrets_json) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                "legacy vault migration: encrypt failed for vault {vault_id}: {e} \
                 (will retry on next successful pull)"
            );
            return;
        }
    };

    let client = match sync_http_client_builder()
        .timeout(sync_request_timeout(std::time::Duration::from_secs(15)))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("legacy vault migration: client build failed for vault {vault_id}: {e}");
            return;
        }
    };

    let url = format!(
        "{registry_url}/api/vaults/{}/sync",
        url_path_segment(vault_id)
    );
    let body = serde_json::json!({
        "encryptedBlob": new_blob,
        "wrappedKey": new_wrapped,
        "expectedVersion": version,
    });

    match client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if !status.is_success() {
                tracing::warn!(
                    "legacy vault migration: re-push returned {status} for vault {vault_id} \
                     (will retry on next successful pull)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "legacy vault migration: re-push failed for vault {vault_id}: {e} \
                 (will retry on next successful pull)"
            );
        }
    }
}

/// Pull secrets for a specific environment from the cloud vault.
///
/// Unlike [`pull`] which always returns "default", this extracts the
/// requested environment from the multi-env payload. Returns an empty
/// map if the requested env doesn't exist in the cloud vault. Falls
/// back to flat format parsing for legacy single-env vaults.
pub async fn pull_env(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    env_name: &str,
) -> Result<(HashMap<String, String>, i32), String> {
    let (raw_json, version) = pull_raw(registry_url, auth_token, vault_id).await?;

    // Try multi-env format: {"environments": {"default": {...}, "staging": {...}}}
    if let Ok(wrapper) =
        serde_json::from_str::<HashMap<String, HashMap<String, HashMap<String, String>>>>(&raw_json)
        && let Some(envs) = wrapper.get("environments")
    {
        let secrets = envs.get(env_name).cloned().unwrap_or_default();
        return Ok((secrets, version));
    }

    // Flat format: {"KEY": "VALUE"} — only valid for "default"
    if env_name != "default" {
        return Ok((HashMap::new(), version));
    }

    let secrets: HashMap<String, String> = serde_json::from_str(&raw_json)
        .map_err(|e| format!("failed to parse decrypted secrets: {e}"))?;
    Ok((secrets, version))
}

#[cfg(test)]
// These tests hold the crate-wide env lock across mocked HTTP awaits so env
// mutation stays isolated for the whole request/response round-trip.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::signature;
    use crate::sync::test_support::{IsolatedVaultKeyEnv, env_lock_guard, signed_ok_response};
    use std::sync::{Arc, Mutex as StdMutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[tokio::test]
    async fn pull_attempts_migration_repush_after_legacy_decrypt() {
        // When the cloud blob is encrypted with the legacy token-derived key
        // but the local stored key has rotated past it, decrypt_vault_from_sync
        // falls back, returns plaintext + needs_reencrypt = true, and `pull`
        // re-encrypts under the stored key and pushes back. This pins the
        // automatic-migration contract end-to-end.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // Encrypt the blob under the legacy auth-token-derived key so the
        // stored-key path fails first and the legacy fallback succeeds.
        let auth_token = "auth-token";
        let secrets_json = r#"{"DATABASE_URL":"postgres://legacy"}"#;
        let legacy_wrapping_key = crypto::derive_legacy_wrapping_key(auth_token);
        let aes_key = crypto::generate_aes_key();
        let encrypted_blob =
            crypto::encrypt(&aes_key, secrets_json.as_bytes()).expect("encrypt legacy blob");
        let wrapped_key =
            crypto::wrap_key(&legacy_wrapping_key, &aes_key).expect("wrap aes under legacy key");

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-legacy/sync"))
            .and(header("authorization", &*format!("Bearer {auth_token}")))
            .respond_with(signed_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 9
                }),
                auth_token,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let migration_hits = Arc::new(StdMutex::new(0u32));
        let hits_for_responder = Arc::clone(&migration_hits);

        #[derive(Clone)]
        struct CountingMigrationResponder {
            hits: Arc<StdMutex<u32>>,
            auth_token: &'static str,
        }
        impl Respond for CountingMigrationResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                *self.hits.lock().unwrap() += 1;
                let body = serde_json::json!({ "version": 10, "status": "ok" });
                let body_str = serde_json::to_string(&body).expect("serialize");
                let sig = signature::sign_body(body_str.as_bytes(), self.auth_token);
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
                    .set_body_string(body_str)
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-legacy/sync"))
            .respond_with(CountingMigrationResponder {
                hits: hits_for_responder,
                auth_token,
            })
            .expect(1)
            .mount(&server)
            .await;

        let (secrets, version) = pull(&server.uri(), auth_token, "vault-legacy")
            .await
            .expect("pull must succeed when legacy fallback unwraps the blob");

        assert_eq!(version, 9, "pull returns the server-reported version");
        assert_eq!(
            secrets.get("DATABASE_URL").map(String::as_str),
            Some("postgres://legacy"),
            "legacy-encrypted secrets must round-trip into the returned map"
        );
        assert_eq!(
            *migration_hits.lock().unwrap(),
            1,
            "pull must attempt exactly one migration re-push after legacy decrypt"
        );
    }

    #[tokio::test]
    async fn pull_succeeds_even_when_migration_repush_fails() {
        // Migration is best-effort: a pull must still return Ok with the
        // decrypted secrets when the re-push fails (network blip, version
        // race, or transient origin error). Failure is logged at warn for
        // observability; the next successful pull retries the migration.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let auth_token = "auth-token";
        let secrets_json = r#"{"API_KEY":"legacy-value"}"#;
        let legacy_wrapping_key = crypto::derive_legacy_wrapping_key(auth_token);
        let aes_key = crypto::generate_aes_key();
        let encrypted_blob =
            crypto::encrypt(&aes_key, secrets_json.as_bytes()).expect("encrypt legacy blob");
        let wrapped_key =
            crypto::wrap_key(&legacy_wrapping_key, &aes_key).expect("wrap aes under legacy key");

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-legacy-fail/sync"))
            .and(header("authorization", &*format!("Bearer {auth_token}")))
            .respond_with(signed_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 1
                }),
                auth_token,
            ))
            .expect(1)
            .mount(&server)
            .await;

        // Migration re-push returns 500 — pull must still succeed.
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-legacy-fail/sync"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(1)
            .mount(&server)
            .await;

        let (secrets, version) = pull(&server.uri(), auth_token, "vault-legacy-fail")
            .await
            .expect("pull must remain Ok even when the migration re-push fails");

        assert_eq!(version, 1);
        assert_eq!(
            secrets.get("API_KEY").map(String::as_str),
            Some("legacy-value"),
            "decrypted secrets must round-trip even when the migration push fails"
        );
    }

    #[tokio::test]
    async fn push_raw_returns_plain_text_conflict_body_on_non_json_error() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(409).set_body_string("vault version conflict"))
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"API_KEY":"secret-value"}"#,
            Some(3),
            false,
            None,
        )
        .await;

        assert!(matches!(result, Err(message) if message == "vault version conflict"));
    }

    /// 2xx responses without an X-LPM-Signature header must be rejected before
    /// any parsing — pull side. Old servers that haven't been updated to sign
    /// responses surface here, with a message that points at the upgrade path.
    #[tokio::test]
    async fn pull_rejects_unsigned_success_response() {
        let server = MockServer::start().await;

        // Note: the legacy unsigned shape — ResponseTemplate::set_body_json
        // is what an unupdated origin would send. No X-LPM-Signature header.
        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "encryptedBlob": "ignored",
                "wrappedKey": "ignored",
                "version": 1
            })))
            .mount(&server)
            .await;

        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("missing signature must fail-closed");
        assert!(
            err.contains(signature::SIGNATURE_HEADER),
            "error should name the missing header so users can act, got: {err:?}"
        );
        assert!(
            err.contains("missing"),
            "error should say the header is missing, got: {err:?}"
        );
    }

    /// Tampered or replayed responses (correct shape, wrong signature) must be
    /// rejected before any parsing. A successful-looking body that fails HMAC
    /// verification cannot reach the decryption path.
    #[tokio::test]
    async fn pull_rejects_tampered_body_with_mismatched_signature() {
        let server = MockServer::start().await;

        // Mint a signature against ONE body, but send a DIFFERENT body —
        // simulates a TLS-terminating intermediary swapping the response.
        let original_body = serde_json::json!({
            "encryptedBlob": "ignored",
            "wrappedKey": "ignored",
            "version": 1
        });
        let original_sig = signature::sign_body(
            serde_json::to_string(&original_body).unwrap().as_bytes(),
            "auth-token",
        );

        let tampered_body = serde_json::json!({
            "encryptedBlob": "ignored",
            "wrappedKey": "ignored",
            "version": 999
        });
        let tampered_body_str = serde_json::to_string(&tampered_body).unwrap();

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .insert_header(signature::SIGNATURE_HEADER, original_sig.as_str())
                    .set_body_string(tampered_body_str),
            )
            .mount(&server)
            .await;

        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("mismatched signature must fail-closed");
        assert!(
            err.contains("does not match") || err.contains("tampering"),
            "mismatch error should be specific, got: {err:?}"
        );
    }

    /// Non-2xx responses are NOT signed by the server, so verification must
    /// not run on them — error formatting from the body proceeds normally.
    /// This guards against a regression where the helper accidentally
    /// requires a signature on every response.
    #[tokio::test]
    async fn push_does_not_require_signature_on_error_responses() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        // 409 conflict body, no X-LPM-Signature — origin sends this shape
        // for vault_version_conflict (NextResponse.json, not signed).
        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "Version conflict",
                "code": "vault_version_conflict",
                "serverVersion": 7,
                "expectedVersion": 3
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"K":"v"}"#,
            Some(3),
            false,
            None,
        )
        .await;

        let err = result.expect_err("push should surface the conflict error");
        assert_eq!(err, "Version conflict");
    }

    /// Push success path must verify the signature before returning the
    /// PushResponse. Mirror of the pull test on the response-write surface.
    #[tokio::test]
    async fn push_rejects_unsigned_success_response() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vaultId": "vault-123",
                "version": 4,
                "status": "synced"
            })))
            .mount(&server)
            .await;

        let result = push_raw(
            &server.uri(),
            "auth-token",
            "vault-123",
            r#"{"K":"v"}"#,
            Some(3),
            false,
            None,
        )
        .await;

        let err = result.expect_err("missing signature on push must fail-closed");
        assert!(err.contains(signature::SIGNATURE_HEADER));
    }

    /// `pull` (the higher-level wrapper) must not bypass verification.
    /// Belt-and-braces test alongside `pull_raw` since the two functions
    /// duplicate the request loop and a future refactor could drift them.
    #[tokio::test]
    async fn pull_top_level_rejects_unsigned_success_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "encryptedBlob": "ignored",
                "wrappedKey": "ignored",
                "version": 1
            })))
            .mount(&server)
            .await;

        let result = pull(&server.uri(), "auth-token", "vault-123").await;

        let err = result.expect_err("pull must require signature too");
        assert!(err.contains(signature::SIGNATURE_HEADER));
    }

    #[tokio::test]
    async fn pull_env_returns_empty_for_non_default_legacy_flat_vault() {
        let _guard = env_lock_guard();

        // Hermetic env: force file-backed wrapping key + isolated HOME so
        // the in-process `crypto::encrypt_vault_for_sync` call below
        // doesn't hit the real keyring (unreliable on Linux CI without
        // a D-Bus / secret-service session).
        let _vault_env = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        let secrets_json = serde_json::json!({
            "API_KEY": "legacy-secret",
            "NODE_ENV": "production"
        })
        .to_string();
        let (encrypted_blob, wrapped_key) =
            crypto::encrypt_vault_for_sync(&secrets_json).expect("vault payload should encrypt");

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(signed_ok_response(
                serde_json::json!({
                    "encryptedBlob": encrypted_blob,
                    "wrappedKey": wrapped_key,
                    "version": 7
                }),
                "auth-token",
            ))
            .expect(1)
            .mount(&server)
            .await;

        let (secrets, version) = pull_env(&server.uri(), "auth-token", "vault-123", "staging")
            .await
            .expect("non-default env lookup should not fail for legacy flat vaults");

        assert_eq!(version, 7);
        assert!(
            secrets.is_empty(),
            "legacy flat vaults should only resolve the default env"
        );
    }

    #[tokio::test]
    async fn pull_raw_times_out_when_server_stalls() {
        let _guard = env_lock_guard();
        let server = MockServer::start().await;
        let original_timeout = std::env::var_os("LPM_TEST_SYNC_TIMEOUT_MS");

        unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", "50") };

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/sync"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(
                signed_ok_response(
                    serde_json::json!({
                        "encryptedBlob": "ignored",
                        "wrappedKey": "ignored",
                        "version": 1
                    }),
                    "auth-token",
                )
                .set_delay(std::time::Duration::from_secs(2)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let started_at = std::time::Instant::now();
        let result = pull_raw(&server.uri(), "auth-token", "vault-123").await;
        let elapsed = started_at.elapsed();

        match original_timeout {
            Some(value) => unsafe { std::env::set_var("LPM_TEST_SYNC_TIMEOUT_MS", value) },
            None => unsafe { std::env::remove_var("LPM_TEST_SYNC_TIMEOUT_MS") },
        }

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "pull_raw should respect the configured request timeout, took {elapsed:?}"
        );
        assert!(
            result.is_err(),
            "pull_raw should fail when the sync endpoint stalls"
        );
    }

    #[test]
    fn format_push_error_appends_hint_when_present() {
        let response = PushResponse {
            version: None,
            status: None,
            error: Some(
                "Vault exists on the server. Pull first then push with the synced version, or pass --force to overwrite.".into(),
            ),
            code: Some("vault_expected_version_required".into()),
            server_version: Some(7),
            hint: Some("Run `lpm env pull` then retry the push.".into()),
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert!(rendered.contains("Vault exists on the server"));
        assert!(
            rendered.contains("Hint: Run `lpm env pull` then retry the push."),
            "hint must be surfaced so the user sees the remediation in one message: {rendered}"
        );
    }

    #[test]
    fn format_push_error_falls_back_to_error_only_when_hint_absent() {
        let response = PushResponse {
            version: None,
            status: None,
            error: Some("Version conflict".into()),
            code: Some("vault_version_conflict".into()),
            server_version: Some(9),
            hint: None,
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert_eq!(rendered, "Version conflict");
    }

    #[test]
    fn format_push_error_falls_back_to_status_when_error_field_missing() {
        let response = PushResponse {
            version: None,
            status: None,
            error: None,
            code: None,
            server_version: None,
            hint: None,
        };

        let rendered = format_push_error(&response, reqwest::StatusCode::CONFLICT);
        assert!(
            rendered.contains("409"),
            "fallback must include the HTTP status so the user has something actionable: {rendered}"
        );
    }

    #[tokio::test]
    async fn push_raw_surfaces_expected_version_required_hint_on_409() {
        // Pins the wire-level contract between the server's
        // vault_expected_version_required response and what the CLI surface
        // sees. Old clients that omit expectedVersion against an existing
        // row now get a 409 from the server with both an error sentence and
        // a hint; this test asserts both make it through into the Err string
        // the command layer renders.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        let response_body = serde_json::json!({
            "error": "Vault exists on the server. Pull first then push with the synced version, or pass --force to overwrite.",
            "code": "vault_expected_version_required",
            "serverVersion": 7,
            "hint": "Run `lpm env pull` then retry the push.",
        });
        let body_str = serde_json::to_string(&response_body).expect("serialize");
        let sig = signature::sign_body(body_str.as_bytes(), "auth-token");

        Mock::given(method("POST"))
            .and(path("/api/vaults/vault-1/sync"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_string(body_str)
                    .insert_header("content-type", "application/json")
                    .insert_header("x-lpm-vault-signature", sig.as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let err = push_raw(
            &server.uri(),
            "auth-token",
            "vault-1",
            r#"{"API_KEY":"v"}"#,
            None,
            false,
            None,
        )
        .await
        .expect_err("server 409 must propagate as Err");

        assert!(
            err.contains("Vault exists on the server"),
            "error sentence must be preserved: {err}"
        );
        assert!(
            err.contains("Hint: Run `lpm env pull` then retry the push."),
            "hint must be appended so the user gets the remediation in one shot: {err}"
        );
    }
}
