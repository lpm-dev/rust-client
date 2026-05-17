//! Cloud sync for vault secrets.
//!
//! Handles push/pull of encrypted vault data to/from the LPM API.
//!
//! Successful responses from signed vault endpoints carry an
//! `X-LPM-Signature` header (HMAC-SHA256 over the body keyed by
//! SHA-256 of the auth token). Every signed surface routes through
//! [`read_verified_response`], which reads the body once, snapshots
//! the signature header, and verifies before any caller-side parsing
//! or decryption. Error responses (non-2xx) are not signed and are
//! returned unverified for the caller to format.

use crate::{crypto, signature};
use futures::StreamExt;
use std::collections::HashMap;

/// Hard cap on a single vault-sync response body. Encrypted envelopes
/// are small (kilobytes); a multi-MB cap leaves multiple orders of
/// magnitude of headroom while stopping a malicious / compromised
/// platform endpoint from OOM-ing the CLI on the signed-read path
/// that runs before any signature verification.
const MAX_VAULT_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with the vault size cap applied in two stages.
///
/// Stage 1 (pre-stream): refuse when the server's declared
/// `Content-Length` exceeds `MAX_VAULT_RESPONSE_BYTES`. Stage 2
/// (mid-stream): accumulate `bytes_stream()` chunks and abort the
/// moment another chunk would cross the cap. Closing the response
/// at that point drops the underlying connection.
async fn read_capped_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_VAULT_RESPONSE_BYTES
    {
        return Err(format!(
            "response too large: declared length {declared} exceeds cap {MAX_VAULT_RESPONSE_BYTES}"
        ));
    }

    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("response read error: {e}"))?;
        if buf.len().saturating_add(chunk.len()) > MAX_VAULT_RESPONSE_BYTES {
            return Err(format!(
                "response too large: streamed body exceeded cap {MAX_VAULT_RESPONSE_BYTES}"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a (typically error) response body as UTF-8 text under the
/// vault cap. Mirrors the previous `response.text().await.unwrap_or_default()`
/// shape — failures become empty strings so error formatting still
/// produces a usable message — but the buffer is now bounded.
async fn read_capped_error_text(response: reqwest::Response) -> String {
    match read_capped_body(response).await {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

/// Read a vault sync response and verify its `X-LPM-Signature` header
/// against the body. Only 2xx responses are signed by the server, so
/// error responses are returned unverified for the caller to format.
///
/// Returning `(status, body)` rather than the parsed response gives every
/// call site identical verification semantics and keeps the parse step
/// downstream — so a failed signature can never reach decryption.
async fn read_verified_response(
    response: reqwest::Response,
    auth_token: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
    let status = response.status();
    // Snapshot the signature header first — body-drain consumes
    // `self`, so we cannot read headers afterwards.
    let signature_header = response
        .headers()
        .get(signature::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body = read_capped_body(response).await?;

    if status.is_success() {
        signature::verify_response_body(&body, auth_token, signature_header.as_deref())
            .map_err(|e| e.to_string())?;
    }

    Ok((status, body))
}

fn sync_request_timeout(default: std::time::Duration) -> std::time::Duration {
    match std::env::var("LPM_TEST_SYNC_TIMEOUT_MS") {
        Ok(value) => value
            .parse::<u64>()
            .map(std::time::Duration::from_millis)
            .unwrap_or(default),
        Err(_) => default,
    }
}

/// Build the lpm-vault HTTP client with an explicit redirect policy
/// pinned. reqwest's `Policy::limited` strips `Authorization` on
/// cross-origin redirects by default; pinning it here documents the
/// contract so a future builder edit can't drop the strip implicitly.
/// The bearer-leak shape — a malicious or misconfigured registry
/// 30x'ing to `attacker.example` and having our bearer follow — is
/// the L16 hazard this closes alongside the `bearer_auth` migration.
fn sync_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10))
}

/// Percent-encode a URL path segment.
///
/// M32: vault sync calls interpolate `vault_id`, `org_slug`, `code`
/// directly into the request path. Raw `/`, `?`, `#`, `..`, `&` etc.
/// in any of those would alter the route — e.g.,
/// `/api/orgs/{org}/vaults/{vault}` with `vault = "foo/../bar"` would
/// hit a different endpoint server-side. Routing all path components
/// through this helper closes the request-confusion shape.
fn url_path_segment(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Response from push endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct PushResponse {
    pub version: Option<i32>,
    pub status: Option<String>,
    pub error: Option<String>,
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

/// Response from audit log endpoint.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResponse {
    pub entries: Option<Vec<AuditEntry>>,
    pub next_cursor: Option<String>,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
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
            return Err(result
                .error
                .unwrap_or_else(|| format!("server error: {status}")));
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

// ── Public Key Management ─────────────────────────────────────────

/// Upload the user's X25519 public key to the server.
pub async fn upload_public_key(
    registry_url: &str,
    auth_token: &str,
    public_key_b64: &str,
) -> Result<(), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/users/me/public-key");
    let body = serde_json::json!({"publicKey": public_key_b64});

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("failed to upload public key: {body}"));
    }

    Ok(())
}

/// Check if the user's public key is already on the server.
pub async fn get_my_public_key(
    registry_url: &str,
    auth_token: &str,
) -> Result<Option<String>, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/users/me/public-key");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

    Ok(data
        .get("publicKey")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

/// Org member public key info.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPublicKey {
    pub user_id: String,
    pub role: String,
    pub public_key: Option<String>,
    pub has_public_key: bool,
}

/// Fetch all org members' public keys.
pub async fn get_org_member_keys(
    registry_url: &str,
    auth_token: &str,
    org_slug: &str,
) -> Result<Vec<MemberPublicKey>, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!(
        "{registry_url}/api/orgs/{}/members/public-keys",
        url_path_segment(org_slug)
    );

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("failed to fetch member keys: {body}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Honoured only on macOS — the keychain backend is the default there
/// and this env var is the test-only escape hatch that pins file-backed
/// storage. Linux and Windows already use the file backend
/// unconditionally, so the function is gated to avoid a `dead_code`
/// warning on those targets (project CLAUDE.md "Cross-Platform
/// Hygiene" rule).
#[cfg(target_os = "macos")]
fn force_file_x25519_keypair() -> bool {
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn get_or_create_file_backed_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let key_path = dirs::home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key");

    if key_path.exists() {
        let data =
            std::fs::read(&key_path).map_err(|e| format!("failed to read X25519 key: {e}"))?;
        if data.len() == 32 {
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&data);
            let secret = x25519_dalek::StaticSecret::from(private_key);
            let public_key = x25519_dalek::PublicKey::from(&secret);
            return Ok((private_key, *public_key.as_bytes()));
        }
    }

    let (private_key, public_key) = crate::crypto::generate_x25519_keypair();
    let parent = key_path.parent().ok_or("invalid X25519 key path")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create X25519 key dir: {e}"))?;
    std::fs::write(&key_path, private_key)
        .map_err(|e| format!("failed to write X25519 key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set X25519 key permissions: {e}"))?;
    }

    Ok((private_key, public_key))
}

/// Ensure the user's public key is registered on the server.
/// Generates a keypair if none exists locally, uploads if not on server.
pub async fn ensure_public_key(registry_url: &str, auth_token: &str) -> Result<[u8; 32], String> {
    #[cfg(target_os = "macos")]
    let (private, public) = if force_file_x25519_keypair() {
        get_or_create_file_backed_x25519_keypair()?
    } else {
        crate::keychain::get_or_create_x25519_keypair()?
    };
    #[cfg(not(target_os = "macos"))]
    let (private, public) = get_or_create_file_backed_x25519_keypair()?;

    let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public);

    // Check if already uploaded
    let server_key = get_my_public_key(registry_url, auth_token).await?;
    if server_key.as_deref() != Some(&pub_b64) {
        upload_public_key(registry_url, auth_token, &pub_b64).await?;
    }

    Ok(private)
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
        .map_err(|e| format!("network error: {e}"))?;

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
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    Ok(result)
}

fn select_members_with_keys(members: &[MemberPublicKey]) -> Result<Vec<&MemberPublicKey>, String> {
    let members_with_keys: Vec<&MemberPublicKey> = members
        .iter()
        .filter(|member| member.has_public_key && member.public_key.is_some())
        .collect();

    if members_with_keys.is_empty() {
        return Err("no org members have registered public keys. Each member needs to run `lpm env vars share --org` once to generate their keypair.".into());
    }

    Ok(members_with_keys)
}

fn wrap_keys_for_members(
    aes_key: &[u8; 32],
    members_with_keys: &[&MemberPublicKey],
) -> Result<Vec<(String, String)>, String> {
    let mut wrapped_keys: Vec<(String, String)> = Vec::new();

    // M25: surface the (user_id, public_key) pairs every time we wrap.
    // Pre-fix the server-supplied member set was trusted without any
    // local pin / history check / TOFU primitive, so a compromised
    // registry could insert an extra "member" and silently receive
    // every subsequent share's wrapped AES key. We don't yet have a
    // local member-pubkey pin store (tracked as follow-up; needs a
    // sync-history JSON next to the vault data), but we DO surface
    // each recipient so an operator scanning logs can detect a
    // new/unexpected user_id or a flipped pubkey. The pubkey is
    // truncated to the first 12 chars of base64 for readability —
    // enough bits to detect a substituted key by eyeball, not enough
    // to be a verification primitive on its own.
    tracing::warn!(
        target: "lpm_vault::sync",
        recipient_count = members_with_keys.len(),
        "wrapping vault AES key for {} org member recipient(s) — verify each listed pubkey/userId tuple matches your expected member set; a compromised server can insert extra recipients (M25)",
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

        // M25: per-recipient audit line so each one is individually
        // visible. The truncated pubkey gives an eyeball-comparable
        // discriminator without dumping the full base64.
        let pub_short = pub_b64.chars().take(12).collect::<String>();
        tracing::warn!(
            target: "lpm_vault::sync",
            user_id = %member.user_id,
            public_key_prefix = %pub_short,
            "vault share recipient (M25)"
        );

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);

        let wrapped = crypto::wrap_key_for_recipient(aes_key, &pub_key)?;
        wrapped_keys.push((member.user_id.clone(), wrapped));
    }

    if wrapped_keys.is_empty() {
        return Err(
            "no org members have valid public keys. Each member needs to run `lpm env vars share --org` once to generate their keypair.".into(),
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
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    Ok(result)
}

// ── Device Pairing (Dashboard) ───────────────────────────────────

/// Response from GET /api/vault/pair/:code (pending session).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSession {
    pub status: String,
    pub browser_public_key: Option<String>,
}

/// Fetch a pending pairing session to get the browser's P-256 public key.
pub async fn get_pairing_session(
    registry_url: &str,
    auth_token: &str,
    code: &str,
) -> Result<PairingSession, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/{}", url_path_segment(code));

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("pairing error: {body}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Approve a pairing session by sending the ECDH-wrapped wrapping key.
pub async fn approve_pairing(
    registry_url: &str,
    auth_token: &str,
    code: &str,
    encrypted_wrapping_key: &str,
    ephemeral_public_key: &str,
) -> Result<(), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/{}", url_path_segment(code));

    let body = serde_json::json!({
        "encryptedWrappingKey": encrypted_wrapping_key,
        "ephemeralPublicKey": ephemeral_public_key,
    });

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("approval failed: {body}"));
    }

    Ok(())
}

/// Revoke all browser pairings for the authenticated user.
pub async fn unpair_all(registry_url: &str, auth_token: &str) -> Result<(), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/pair/revoke-all");

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .header("content-type", "application/json")
        .body("{}")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("unpair failed: {body}"));
    }

    Ok(())
}

// ─── CI Escrow ──────────────────────────────────────────────────

/// Response from the CI pull endpoint (server-side decrypted secrets).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CiPullResponse {
    pub env: Option<String>,
    pub vars: Option<HashMap<String, String>>,
    pub error: Option<String>,
}

/// Pull vault secrets via CI escrow (OIDC flow).
/// The server decrypts using the escrowed wrapping key — no local keychain needed.
pub async fn ci_pull(
    registry_url: &str,
    oidc_token: &str,
    vault_id: &str,
    env: Option<&str>,
) -> Result<(HashMap<String, String>, String), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let mut url = format!(
        "{registry_url}/api/vaults/{}/ci-pull",
        url_path_segment(vault_id)
    );
    if let Some(e) = env {
        // Env names are alphanumeric/dashes — safe for query strings without encoding
        url = format!("{url}?env={}", url_path_segment(e));
    }

    let response = client
        .get(&url)
        .bearer_auth(oidc_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: CiPullResponse = response
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    let env_name = result.env.unwrap_or_else(|| "default".to_string());
    let vars = result
        .vars
        .ok_or_else(|| "server returned no vars".to_string())?;

    Ok((vars, env_name))
}

/// Upload the wrapping key to the server for CI escrow.
/// Called during `lpm env oidc allow` to enable server-side decryption.
pub async fn upload_escrow_key(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    wrapping_key_hex: &str,
) -> Result<(), String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vault/oidc/escrow");

    let body = serde_json::json!({
        "vaultId": vault_id,
        "wrappingKeyHex": wrapping_key_hex,
    });

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        // Try to extract error message from JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(err) = json["error"].as_str()
        {
            return Err(err.to_string());
        }
        return Err(format!("escrow upload failed: {body}"));
    }

    Ok(())
}

/// Get the vault audit log.
pub async fn get_audit_log(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    cursor: Option<&str>,
) -> Result<AuditResponse, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let mut url = format!(
        "{registry_url}/api/vaults/{}/audit",
        url_path_segment(vault_id)
    );
    if let Some(c) = cursor {
        url = format!("{url}?cursor={}", url_path_segment(c));
    }

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: AuditResponse = response
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(result
            .error
            .unwrap_or_else(|| format!("server error: {status}")));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use std::sync::{Arc, Mutex as StdMutex, OnceLock};
    use tokio::sync::Mutex;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Build a 200 response that mirrors what the LPM origin actually sends
    /// for signed vault endpoints — body bytes plus matching X-LPM-Signature
    /// header. Tests that drive `pull*`/`push*` for `auth_token` must use
    /// this helper or the response fails verification.
    fn signed_ok_response(body: serde_json::Value, auth_token: &str) -> ResponseTemplate {
        let body_str = serde_json::to_string(&body).expect("test body should serialize");
        let sig = signature::sign_body(body_str.as_bytes(), auth_token);
        ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/json")
            .insert_header(signature::SIGNATURE_HEADER, sig.as_str())
            .set_body_string(body_str)
    }

    /// Hermetic env for tests that touch `crypto::encrypt_vault_for_sync`
    /// or `crypto::decrypt_vault_from_sync` in-process. Snapshots `HOME`
    /// and `LPM_FORCE_FILE_VAULT`, points HOME at a fresh tempdir and
    /// pins file-only mode. Drop restores both.
    ///
    /// Caller must already hold `env_lock()` — this struct does not
    /// acquire it. The async tests in this module take `env_lock`
    /// immediately and the lock guard outlives this struct.
    struct IsolatedVaultKeyEnv {
        _tmp: tempfile::TempDir,
        prior_home: Option<std::ffi::OsString>,
        prior_force_file: Option<std::ffi::OsString>,
    }

    impl IsolatedVaultKeyEnv {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir for vault key isolation");
            let prior_home = std::env::var_os("HOME");
            let prior_force_file = std::env::var_os("LPM_FORCE_FILE_VAULT");
            // SAFETY: caller holds env_lock(), serialising env mutation
            // across this module's tests.
            unsafe {
                std::env::set_var("HOME", tmp.path());
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            IsolatedVaultKeyEnv {
                _tmp: tmp,
                prior_home,
                prior_force_file,
            }
        }
    }

    impl Drop for IsolatedVaultKeyEnv {
        fn drop(&mut self) {
            // SAFETY: still inside the env_lock-protected section.
            unsafe {
                match &self.prior_home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
                match &self.prior_force_file {
                    Some(v) => std::env::set_var("LPM_FORCE_FILE_VAULT", v),
                    None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
                }
            }
        }
    }

    /// `read_capped_body` rejects pre-stream when the server declares a
    /// `Content-Length` over the vault cap. A malicious / compromised
    /// platform endpoint must not be able to coerce
    /// `read_verified_response` into allocating a multi-GB buffer
    /// before any signature check runs.
    #[tokio::test]
    async fn read_capped_body_rejects_oversized_declared_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_VAULT_RESPONSE_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let response = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("connect");
        let err = read_capped_body(response)
            .await
            .expect_err("oversized declared length must reject pre-stream");
        assert!(
            err.contains("declared length"),
            "expected pre-stream rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn pull_attempts_migration_repush_after_legacy_decrypt() {
        // When the cloud blob is encrypted with the legacy token-derived key
        // but the local stored key has rotated past it, decrypt_vault_from_sync
        // falls back, returns plaintext + needs_reencrypt = true, and `pull`
        // re-encrypts under the stored key and pushes back. This pins the
        // automatic-migration contract end-to-end.
        let _guard = env_lock().lock().await;
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
        let _guard = env_lock().lock().await;
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
    async fn get_pairing_session_returns_pending_session_with_browser_key() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "pending",
                "browserPublicKey": "browser-key"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = get_pairing_session(&server.uri(), "auth-token", "ABC123")
            .await
            .expect("pairing session should parse");

        assert_eq!(result.status, "pending");
        assert_eq!(result.browser_public_key.as_deref(), Some("browser-key"));
    }

    #[tokio::test]
    async fn get_pairing_session_returns_body_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vault/pair/EXPIRED"))
            .respond_with(ResponseTemplate::new(410).set_body_string("pairing expired"))
            .expect(1)
            .mount(&server)
            .await;

        let result = get_pairing_session(&server.uri(), "auth-token", "EXPIRED").await;

        assert!(matches!(result, Err(message) if message == "pairing error: pairing expired"));
    }

    #[tokio::test]
    async fn approve_pairing_posts_wrapped_key_payload() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/ABC123"))
            .and(header("authorization", "Bearer auth-token"))
            .and(body_string_contains(
                "\"encryptedWrappingKey\":\"wrapped-key\"",
            ))
            .and(body_string_contains(
                "\"ephemeralPublicKey\":\"ephemeral-key\"",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        approve_pairing(
            &server.uri(),
            "auth-token",
            "ABC123",
            "wrapped-key",
            "ephemeral-key",
        )
        .await
        .expect("approve pairing should succeed");
    }

    #[tokio::test]
    async fn unpair_all_returns_body_on_failure() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/vault/pair/revoke-all"))
            .and(header("authorization", "Bearer auth-token"))
            .and(body_string_contains("{}"))
            .respond_with(ResponseTemplate::new(500).set_body_string("vault revoke failed"))
            .expect(1)
            .mount(&server)
            .await;

        let result = unpair_all(&server.uri(), "auth-token").await;

        assert!(matches!(result, Err(message) if message == "unpair failed: vault revoke failed"));
    }

    #[tokio::test]
    async fn ci_pull_returns_vars_and_requested_env() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .and(query_param("env", "preview"))
            .and(header("authorization", "Bearer oidc-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "env": "preview",
                "vars": {
                    "API_KEY": "secret-value",
                    "NODE_ENV": "preview"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (vars, env_name) = ci_pull(&server.uri(), "oidc-token", "vault-123", Some("preview"))
            .await
            .expect("ci pull should succeed");

        assert_eq!(env_name, "preview");
        assert_eq!(
            vars.get("API_KEY").map(String::as_str),
            Some("secret-value")
        );
        assert_eq!(vars.get("NODE_ENV").map(String::as_str), Some("preview"));
    }

    #[tokio::test]
    async fn ci_pull_defaults_env_when_server_omits_it() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vars": {
                    "API_KEY": "secret-value"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (vars, env_name) = ci_pull(&server.uri(), "oidc-token", "vault-123", None)
            .await
            .expect("ci pull should default env name");

        assert_eq!(env_name, "default");
        assert_eq!(
            vars.get("API_KEY").map(String::as_str),
            Some("secret-value")
        );
    }

    #[tokio::test]
    async fn ci_pull_returns_server_error_message_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "oidc subject not allowed"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = ci_pull(&server.uri(), "oidc-token", "vault-123", None).await;

        assert!(matches!(result, Err(message) if message == "oidc subject not allowed"));
    }

    #[tokio::test]
    async fn ci_pull_errors_when_server_returns_no_vars() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/vaults/vault-123/ci-pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "env": "production"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = ci_pull(&server.uri(), "oidc-token", "vault-123", None).await;

        assert!(matches!(result, Err(message) if message == "server returned no vars"));
    }

    #[tokio::test]
    async fn push_raw_returns_plain_text_conflict_body_on_non_json_error() {
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
        let _guard = env_lock().lock().await;

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
        let _guard = env_lock().lock().await;
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
    fn push_org_with_keys_regenerates_corrupted_forced_file_key_and_skips_members_without_keys() {
        let _guard = env_lock().blocking_lock();
        let temp = tempfile::tempdir().expect("failed to create temp home for forced vault test");
        let original_home = std::env::var_os("HOME");
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("HOME", temp.path());
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
                .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
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

        match original_home {
            Some(value) => unsafe { std::env::set_var("HOME", value) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[test]
    fn push_org_with_keys_round_trips_name_and_schema_metadata() {
        // Org pushes used to omit `name` + `schema` from the request body, so
        // the dashboard for an org vault froze whatever schema was set at
        // creation time and never reflected later CLI pushes. This test pins
        // the contract: when the caller passes `PushMetadata`, both fields
        // land on the wire alongside the encrypted blob and wrapped keys.
        let _guard = env_lock().blocking_lock();
        let temp = tempfile::tempdir().expect("tempdir for metadata round-trip test");
        let original_home = std::env::var_os("HOME");
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("HOME", temp.path());
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
                .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
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

        match original_home {
            Some(value) => unsafe { std::env::set_var("HOME", value) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match original_force_file_vault {
            Some(value) => unsafe { std::env::set_var("LPM_FORCE_FILE_VAULT", value) },
            None => unsafe { std::env::remove_var("LPM_FORCE_FILE_VAULT") },
        }
    }

    #[test]
    fn push_org_with_keys_omits_metadata_fields_when_caller_passes_none() {
        // Symmetry with the round-trip test above: when no metadata is
        // supplied, the body must NOT contain `name` or `schema` fields.
        // This pins the "explicit None means don't touch dashboard
        // metadata" contract — server keeps last-known-good schema/name.
        let _guard = env_lock().blocking_lock();
        let temp = tempfile::tempdir().expect("tempdir for None-metadata test");
        let original_home = std::env::var_os("HOME");
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");

        unsafe {
            std::env::set_var("HOME", temp.path());
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
                .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
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

        match original_home {
            Some(value) => unsafe { std::env::set_var("HOME", value) },
            None => unsafe { std::env::remove_var("HOME") },
        }
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
