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
            .map_or(default, std::time::Duration::from_millis),
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
fn format_push_error(result: &PushResponse, status: reqwest::StatusCode) -> String {
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

// ── CLI Step-Up (Workstream 2 reauth) ─────────────────────────────

/// HTTP header the server expects the CLI step-up proof JWT in. Mirrors
/// `CLI_STEP_UP_HEADER_NAME` exported from the dashboard's
/// `lib/auth/cli-step-up.js`. Defined here as a constant so the upload
/// site and any future caller route the proof through the same name.
pub const CLI_STEP_UP_HEADER_NAME: &str = "X-LPM-Step-Up-Proof";

/// Step-up policy resolved by the server for the calling user. The CLI
/// prompts for the credential named in `method` (or refuses outright
/// when `unavailable`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliStepUpPolicy {
    /// `"password"`, `"totp"`, or `"unavailable"`. The CLI MUST refuse
    /// any flow when `unavailable` because the prompt would ask for a
    /// credential the user cannot satisfy.
    pub method: String,
    /// Present only when `method == "unavailable"`. Currently the only
    /// observed value is `"set_password_required"`.
    pub reason: Option<String>,
    /// TTL the server applies to a freshly-minted proof. Surfaced so the
    /// CLI can render an honest "expires in N seconds" hint.
    pub ttl_seconds: Option<u32>,
    /// Header name the server expects the minted proof in. Echoed so a
    /// future server-side rename gets picked up without coordinating
    /// constants.
    pub header: Option<String>,
}

/// Credential the CLI supplies on mint. Two shapes — password-only for
/// users with no MFA, and password+TOTP for MFA-enrolled users (CLI
/// step-up cannot drive TOTP alone — see WS2's route docstring).
pub enum CliStepUpCredential<'a> {
    Password { password: &'a str },
    Totp { password: &'a str, code: &'a str },
}

/// Discover the step-up method the server expects for the calling
/// user — does not consume any credential, no rate-limit cost beyond
/// the per-IP shield. Used by the CLI to decide what to prompt for
/// before asking the user to type a password / TOTP.
pub async fn discover_cli_step_up_policy(
    registry_url: &str,
    auth_token: &str,
) -> Result<CliStepUpPolicy, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/auth/cli-step-up");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("step-up policy: {status}: {body}"));
    }

    response
        .json::<CliStepUpPolicy>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Successful mint response from `POST /api/auth/cli-step-up`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintCliStepUpResponse {
    ok: Option<bool>,
    proof: Option<String>,
}

/// Mint a CLI step-up proof against the server.
///
/// On success, returns the JWT the caller carries in the
/// `X-LPM-Step-Up-Proof` header for the subsequent sensitive write
/// (public-key set/rotate, force-push, etc).
///
/// On failure, the returned error includes the server's response body
/// so the CLI can surface the structured envelope (`code:
/// wrong_credential`, `code: rate_limited`, etc) to the user.
pub async fn mint_cli_step_up_proof(
    registry_url: &str,
    auth_token: &str,
    scope: &str,
    credential: &CliStepUpCredential<'_>,
) -> Result<String, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/auth/cli-step-up");

    let body = match credential {
        CliStepUpCredential::Password { password } => serde_json::json!({
            "scope": scope,
            "method": "password",
            "password": password,
        }),
        CliStepUpCredential::Totp { password, code } => serde_json::json!({
            "scope": scope,
            "method": "totp",
            "password": password,
            "totpCode": code,
        }),
    };

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("step-up mint: {status}: {body}"));
    }

    let parsed = response
        .json::<MintCliStepUpResponse>()
        .await
        .map_err(|e| format!("parse error: {e}"))?;
    if parsed.ok != Some(true) {
        return Err("step-up mint: server returned ok=false on 2xx response (unexpected)".into());
    }
    parsed
        .proof
        .ok_or_else(|| "step-up mint: server response missing proof".into())
}

// ── Public Key Management ─────────────────────────────────────────

/// Server response from `POST /api/users/me/public-key`.
///
/// The dashboard hardened that route to return a structured envelope
/// per the WS3 public-key state machine. Old servers (pre-hardening)
/// returned `{ status: "saved" }`; we forward-compat-parse that shape
/// too — every field below is optional, so a missing key is just
/// `None` rather than a deserialization failure.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadPublicKeyResponse {
    /// `true` on 2xx success. Old servers omit this field — treat absent
    /// as success (the route returned 2xx).
    pub ok: Option<bool>,
    /// `"set" | "unchanged" | "rotated"` from the WS3 route. Old servers
    /// return `"saved"`.
    pub status: Option<String>,
    /// SHA-256 prefix of the new key (only on `set` and `rotated`).
    pub fingerprint_prefix: Option<String>,
    /// SHA-256 prefix of the previous key (only on `rotated`).
    pub previous_fingerprint_prefix: Option<String>,
    /// Count of `vault_org_keys` rows the rotation invalidated.
    pub invalidated_wrapped_keys: Option<u32>,
    /// Count of distinct orgs whose wrapped-key rows were invalidated.
    pub affected_orgs: Option<u32>,
}

/// Upload the user's X25519 public key to the server.
///
/// `step_up_proof` carries the WS2 CLI step-up JWT in the
/// `X-LPM-Step-Up-Proof` header. The server requires a proof minted
/// with audience `vault:public-key:set` for first-set, or
/// `vault:public-key:rotate` for rotation; an idempotent same-key
/// repost does not require a proof and is reported back as
/// `status: "unchanged"`.
///
/// Callers that pass `None` should expect the server to refuse any
/// mutating write with HTTP 403 and the structured `code:
/// "step_up_required"` envelope — that's the correct failure mode
/// against the WS3-hardened server. Against pre-WS3 servers, the
/// header is silently ignored and the legacy write path runs.
pub async fn upload_public_key(
    registry_url: &str,
    auth_token: &str,
    public_key_b64: &str,
    step_up_proof: Option<&str>,
) -> Result<UploadPublicKeyResponse, String> {
    let client = sync_http_client_builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/users/me/public-key");
    let body = serde_json::json!({"publicKey": public_key_b64});

    let mut request = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15));
    if let Some(proof) = step_up_proof {
        request = request.header(CLI_STEP_UP_HEADER_NAME, proof);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("failed to upload public key: {body}"));
    }

    // `response.json()` would happily Err if the body isn't JSON. Old
    // servers reliably return JSON; the explicit error keeps the
    // message tight for any future server that 2xxes with HTML.
    response
        .json::<UploadPublicKeyResponse>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

/// Check if the user's public key is already on the server.
///
/// Wire contract — distinguishes "no key on server" from "server is
/// failing" so callers can branch correctly:
///
///   - 2xx with `{ publicKey: "<b64>" }` → `Ok(Some(...))`
///   - 2xx with `{ publicKey: null }` or `publicKey` field absent → `Ok(None)`
///   - 2xx whose body is malformed JSON → `Err(...)`
///   - any non-2xx (401, 403, 5xx, redirect) → `Err(...)` with the
///     response status + body summary
///
/// The previous implementation collapsed every non-2xx response to
/// `Ok(None)`, which meant a transient 500 or a 401 (expired token)
/// would be misclassified as "no key on server" and the silent
/// `ensure_public_key` retry path would try to overwrite — exactly the
/// silent-overwrite vector the WS3 server hardening was built to
/// close. This implementation fails fast so the caller's classification
/// path can render an honest error.
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

    let status = response.status();
    if !status.is_success() {
        let body = read_capped_error_text(response).await;
        return Err(format!("get public key: {status}: {body}"));
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

/// Locally-resolved sharing keypair material. The private half stays
/// in memory and on disk (keychain on macOS, file fallback otherwise);
/// the public half is the canonical Base64 form the server expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPublicKeyState {
    /// Raw 32-byte X25519 private key. Callers should not log or surface
    /// this material.
    pub private_key: [u8; 32],
    /// Standard Base64 encoding of the matching X25519 public key.
    pub public_key_b64: String,
}

/// Classification of the local-vs-server sharing-key state, produced by
/// {@link classify_public_key_state}. The CLI command layer (Workstream
/// 4) branches on this enum to decide whether to proceed silently,
/// prompt for the WS2 step-up proof and register, or refuse and direct
/// the user to the explicit `lpm env rotate-sharing-key` flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyRegistrationState {
    /// Server-stored key matches the local key. No write needed; callers
    /// can proceed with the wrap/unwrap operation that prompted the
    /// check.
    Matches(LocalPublicKeyState),
    /// Server has no key for this user. Caller must acquire a CLI
    /// step-up proof (`vault:public-key:set` scope) and call
    /// `upload_public_key(..., Some(proof))` to register before
    /// proceeding.
    NeedsInitialSet(LocalPublicKeyState),
    /// Server has a key but it differs from the local one. The caller
    /// MUST NOT silently overwrite — this is the silent-rotation
    /// vector the WS3 hardening exists to close. The CLI command layer
    /// surfaces this state by refusing the operation and instructing
    /// the user to run the explicit rotation flow (`lpm env
    /// rotate-sharing-key`), which acquires a `vault:public-key:rotate`
    /// proof.
    RotationRequired {
        local: LocalPublicKeyState,
        server_public_key_b64: String,
    },
}

/// Load (or create) the local sharing keypair and classify it against
/// the server's current state.
///
/// Pure classifier — does not mutate server state. Three outcomes:
///
///   - `Matches` — same key on both sides; caller can no-op.
///   - `NeedsInitialSet` — no key on server; caller can register the
///     local key with a `vault:public-key:set` proof.
///   - `RotationRequired` — different key on server; caller MUST refuse
///     to silently upload (the prior `ensure_public_key` path did
///     overwrite here, which was the security bug WS3 closes).
///
/// All server errors propagate as `Err(...)` — a 401, 403, or 5xx will
/// NOT be misclassified as "no key on server" the way the old
/// `get_my_public_key` `Ok(None)` collapse did.
pub async fn classify_public_key_state(
    registry_url: &str,
    auth_token: &str,
) -> Result<PublicKeyRegistrationState, String> {
    let local = load_local_public_key_state()?;
    let server_key = get_my_public_key(registry_url, auth_token).await?;

    match server_key {
        None => Ok(PublicKeyRegistrationState::NeedsInitialSet(local)),
        Some(server) if server == local.public_key_b64 => {
            Ok(PublicKeyRegistrationState::Matches(local))
        }
        Some(server) => Ok(PublicKeyRegistrationState::RotationRequired {
            local,
            server_public_key_b64: server,
        }),
    }
}

/// Load the local X25519 keypair, creating one if absent. Shared by
/// `ensure_public_key` and {@link classify_public_key_state} so the two
/// entry points agree on storage location, generation policy, and
/// canonical Base64 encoding.
fn load_local_public_key_state() -> Result<LocalPublicKeyState, String> {
    #[cfg(target_os = "macos")]
    let (private_key, public) = if should_use_file_backed_x25519_keypair(
        force_file_x25519_keypair(),
        live_x25519_key_path()?.exists(),
    ) {
        get_or_create_file_backed_x25519_keypair()?
    } else {
        crate::keychain::get_or_create_x25519_keypair()?
    };
    #[cfg(not(target_os = "macos"))]
    let (private_key, public) = get_or_create_file_backed_x25519_keypair()?;

    let public_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public);
    Ok(LocalPublicKeyState {
        private_key,
        public_key_b64,
    })
}

/// Pending sharing-keypair lifecycle helpers used by the
/// `rotate-sharing-key` flow.
///
/// Rotation is split across two writes: server-side upload of the new
/// public key, then local promotion of the matching private key into
/// the live slot. A crash, network drop, or process kill between those
/// two steps must NOT leave the live slot pointing at a key the server
/// no longer knows about (the user would silently lose access to every
/// org vault). The pending slot is the recovery primitive:
///
///   1. Generate a fresh keypair and persist it to the pending slot
///      WITHOUT touching the live slot.
///   2. Upload the pending public key with a `vault:public-key:rotate`
///      step-up proof.
///   3. On HTTP success, atomically promote the pending slot into the
///      live slot.
///   4. On restart (or any future invocation), if the pending slot
///      contains a key that matches the server's current public key,
///      the previous run was interrupted between steps 2 and 3 — finish
///      promotion. If the pending slot exists but doesn't match the
///      server, the upload failed before commit; discard the pending.
///
/// Storage backend: ALWAYS the file-backed slots (`.x25519_key.pending`
/// in the user's `~/.lpm` directory). The macOS keychain backend only
/// supports a single named entry per service/account pair; juggling a
/// transient pending entry there adds complexity (and a multi-keychain-
/// item ACL surface) that the file slot avoids cleanly. Promotion
/// writes the new private key to the live slot via the same code path
/// `get_or_create_file_backed_x25519_keypair` uses for first-set, so
/// permissions stay consistent (`0o600` on Unix).

#[derive(Debug, Clone)]
pub struct PendingPublicKey {
    pub private_key: [u8; 32],
    pub public_key_b64: String,
}

fn pending_x25519_key_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key.pending"))
}

fn live_x25519_key_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::lpm_home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".x25519_key"))
}

/// Generate a fresh X25519 keypair and persist it to the pending slot.
/// Does NOT touch the live slot. Overwrites any existing pending slot —
/// the caller's `rotate-sharing-key` flow has already verified the
/// pending state via [`read_pending_x25519_keypair`] and confirmed it's
/// safe to overwrite (stale orphan from a failed prior attempt).
pub fn create_pending_x25519_keypair() -> Result<PendingPublicKey, String> {
    let (private_key, public_key) = crate::crypto::generate_x25519_keypair();
    let path = pending_x25519_key_path()?;
    let parent = path.parent().ok_or("invalid pending key path")?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create pending key dir: {e}"))?;
    std::fs::write(&path, private_key).map_err(|e| format!("failed to write pending key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set pending key permissions: {e}"))?;
    }
    Ok(PendingPublicKey {
        private_key,
        public_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public_key,
        ),
    })
}

/// Read the pending slot without promoting. Returns `Ok(None)` when no
/// pending slot exists (the steady state). Used on every
/// `rotate-sharing-key` invocation to detect crash-interrupted prior
/// rotations.
pub fn read_pending_x25519_keypair() -> Result<Option<PendingPublicKey>, String> {
    let path = pending_x25519_key_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path).map_err(|e| format!("failed to read pending key: {e}"))?;
    if data.len() != 32 {
        return Err(format!(
            "pending key file has invalid length {} (expected 32)",
            data.len()
        ));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&data);
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public_key = x25519_dalek::PublicKey::from(&secret);
    let public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key.as_bytes(),
    );
    Ok(Some(PendingPublicKey {
        private_key,
        public_key_b64,
    }))
}

/// Atomically promote the pending slot into the live slot.
///
/// Writes the pending private key to the live file with `0o600` perms,
/// then deletes the pending file. The write-then-delete order means a
/// crash between the two steps leaves BOTH files with the same key
/// (next promotion is a no-op); a crash before the write leaves only
/// pending (next rotation discovers it). Both orderings are safe; the
/// only unsafe state would be "live updated, pending still present
/// with a stale key" — which cannot happen because pending always
/// holds the key we just wrote to live.
///
/// Also clears any prior keychain entry on macOS so subsequent
/// `load_local_public_key_state` calls observe the new file-backed key
/// instead of the stale keychain entry. (The keychain entry survives
/// across rotations otherwise.)
pub fn promote_pending_x25519_keypair() -> Result<(), String> {
    let pending = read_pending_x25519_keypair()?.ok_or("no pending key to promote")?;
    let live_path = live_x25519_key_path()?;
    let parent = live_path.parent().ok_or("invalid live key path")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create live key dir: {e}"))?;
    std::fs::write(&live_path, pending.private_key)
        .map_err(|e| format!("failed to write live key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&live_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set live key permissions: {e}"))?;
    }

    // Clear macOS keychain entry if present so subsequent reads see
    // the file-backed key. Best-effort: a "not found" error here is
    // expected when the user was already on the file fallback, so we
    // intentionally swallow keychain errors.
    #[cfg(target_os = "macos")]
    {
        let _ = crate::keychain::delete_x25519_keypair();
    }

    discard_pending_x25519_keypair()
}

/// Delete the pending slot without promoting. Called when the prior
/// upload failed before commit (pending key doesn't match server's
/// current key), or after a successful promotion.
pub fn discard_pending_x25519_keypair() -> Result<(), String> {
    let path = pending_x25519_key_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("failed to delete pending key: {e}"))?;
    }
    Ok(())
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

#[cfg(target_os = "macos")]
fn should_use_file_backed_x25519_keypair(force_file: bool, live_key_exists: bool) -> bool {
    force_file || live_key_exists
}

fn get_or_create_file_backed_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let key_path = crate::lpm_home_dir()
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
///
/// Legacy entry point retained for callers that have not yet migrated
/// to the WS3 classification + explicit step-up flow ({@link
/// classify_public_key_state} + proof-aware {@link upload_public_key}).
/// Against the WS3-hardened server, the no-proof upload here will
/// surface as a server-side `step_up_required` error for the
/// `NeedsInitialSet` and `RotationRequired` cohorts — which is the
/// correct failure mode; silent overwrite was the security bug WS3
/// closes. The CLI command-layer migration in the next slice replaces
/// every caller of this function with explicit classification +
/// reauth UX, at which point this helper becomes a candidate for
/// removal.
pub async fn ensure_public_key(registry_url: &str, auth_token: &str) -> Result<[u8; 32], String> {
    let local = load_local_public_key_state()?;
    let server_key = get_my_public_key(registry_url, auth_token).await?;
    if server_key.as_deref() != Some(&local.public_key_b64) {
        upload_public_key(registry_url, auth_token, &local.public_key_b64, None).await?;
    }

    Ok(local.private_key)
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
        .map_err(|e| format!("network error: {e}"))?;

    let (status, body) = read_verified_response(response, auth_token).await?;
    let result: PushResponse =
        serde_json::from_slice(&body).map_err(|e| format!("response parse error: {e}"))?;

    if !status.is_success() {
        return Err(format_push_error(&result, status));
    }

    Ok(result)
}

// ── Device Pairing (Dashboard) ───────────────────────────────────

/// Response from GET /api/vault/pair/:code (pending session).
///
/// The CLI derives the browser-key fingerprint and the short authentication
/// string locally from `browser_public_key` and the user-typed pairing code —
/// trusting the server for those derived values would let a malicious server
/// silently approve any pair, defeating the visual confirmation. Only the
/// genuinely server-side facts (`device_label`, `created_at`,
/// `created_from_ip`) are wire-supplied, and all three are optional so a
/// newer CLI built against an older server still parses the response and
/// simply omits the missing fields from the confirmation prompt.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSession {
    pub status: String,
    pub browser_public_key: Option<String>,
    pub device_label: Option<String>,
    pub created_at: Option<String>,
    pub created_from_ip: Option<String>,
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
// The shared env-mutation lock is a `std::sync::Mutex`, and several
// async tests in this module hold its guard across `.await` points
// to keep env serialised for the full duration of the wiremock
// round-trip. Clippy would normally flag this as `await_holding_lock`
// because in production code that would block a tokio worker thread.
// In tests it's safe: each `#[tokio::test]` runs in its own runtime,
// so the only blocked thread is the test's own worker — there are no
// other tasks to starve. Allow the lint at the module level.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use std::sync::{Arc, Mutex as StdMutex};
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Acquire the crate-wide env-mutation lock so this module's
    /// tests serialise with `crypto::tests` and the top-level
    /// `lib.rs::tests`. The lock must cover the full window from
    /// env-mutation through any code that reads the same env vars,
    /// so one module's test cannot read another's in-flight env
    /// state. Blocking briefly inside `#[tokio::test]` is safe —
    /// each tokio test runs in its own runtime, so blocking on a
    /// `std::sync::Mutex` doesn't starve any other task.
    fn env_lock_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env_lock::acquire_env_lock()
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
    /// Caller must already hold `env_lock_guard()` — this struct does not
    /// acquire it. The async tests in this module take `env_lock`
    /// immediately and the lock guard outlives this struct.
    struct IsolatedVaultKeyEnv {
        _tmp: tempfile::TempDir,
        prior_home: Option<crate::test_env_lock::HomeEnvSnapshot>,
        prior_force_file: Option<std::ffi::OsString>,
    }

    impl IsolatedVaultKeyEnv {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir for vault key isolation");
            let prior_home = Some(crate::test_env_lock::HomeEnvSnapshot::set(tmp.path()));
            let prior_force_file = std::env::var_os("LPM_FORCE_FILE_VAULT");
            // SAFETY: caller holds env_lock_guard(), serialising env mutation
            // across all of this crate's tests (shared lock).
            unsafe {
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
                match &self.prior_force_file {
                    Some(v) => std::env::set_var("LPM_FORCE_FILE_VAULT", v),
                    None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
                }
            }
            if let Some(prior_home) = self.prior_home.take() {
                prior_home.restore();
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

    #[tokio::test]
    async fn get_my_public_key_returns_err_on_non_2xx() {
        // The previous implementation collapsed every non-2xx to
        // `Ok(None)`, which silently turned a 401 / 403 / 500 into "no
        // key on server" and routed the caller into the silent-overwrite
        // path. Pin the new semantics: any non-2xx is an error.
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .expect(1)
            .mount(&server)
            .await;
        let err = get_my_public_key(&server.uri(), "bad-token")
            .await
            .expect_err("401 must propagate as Err, not Ok(None)");
        assert!(
            err.contains("401"),
            "error must include the HTTP status so the caller can branch: {err}"
        );
    }

    #[tokio::test]
    async fn get_my_public_key_returns_some_on_2xx_with_key() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": "abc=",
                "createdAt": null,
                "updatedAt": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("happy path must succeed");
        assert_eq!(key.as_deref(), Some("abc="));
    }

    #[tokio::test]
    async fn get_my_public_key_returns_none_on_2xx_with_null_field() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": null,
                "createdAt": null,
                "updatedAt": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let key = get_my_public_key(&server.uri(), "token")
            .await
            .expect("null publicKey is the explicit 'no key' signal");
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn upload_public_key_sends_step_up_proof_header_when_provided() {
        // The WS3 server route refuses any mutating write without a
        // valid `X-LPM-Step-Up-Proof` header. Pin that the helper
        // emits the header when a proof is supplied, AND that it omits
        // the header when None is passed (so old servers don't reject
        // a spurious empty header).
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let server = MockServer::start().await;
        let captured_proof = Arc::new(StdMutex::new(Vec::<Option<String>>::new()));

        let captured_for_responder = Arc::clone(&captured_proof);
        #[derive(Clone)]
        struct CaptureResponder {
            captured: Arc<StdMutex<Vec<Option<String>>>>,
        }
        impl Respond for CaptureResponder {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let proof = request
                    .headers
                    .get(CLI_STEP_UP_HEADER_NAME)
                    .map(|v| v.to_str().unwrap_or("").to_string());
                self.captured.lock().unwrap().push(proof);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "status": "set",
                    "fingerprintPrefix": "deadbeef0bad1dea",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(CaptureResponder {
                captured: captured_for_responder,
            })
            .expect(2)
            .mount(&server)
            .await;

        // With a proof — header must be present and match.
        let result_with =
            upload_public_key(&server.uri(), "auth-token", "abc=", Some("proof-jwt-here"))
                .await
                .expect("happy path with proof");
        assert_eq!(result_with.status.as_deref(), Some("set"));
        assert_eq!(result_with.ok, Some(true));
        assert_eq!(
            result_with.fingerprint_prefix.as_deref(),
            Some("deadbeef0bad1dea")
        );

        // Without a proof — header must be absent.
        upload_public_key(&server.uri(), "auth-token", "abc=", None)
            .await
            .expect("no-proof call still completes against this mock");

        let captured = captured_proof.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].as_deref(), Some("proof-jwt-here"));
        assert!(
            captured[1].is_none(),
            "passing None must NOT send the header at all"
        );
    }

    #[tokio::test]
    async fn upload_public_key_propagates_server_error_envelope_on_non_2xx() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "ok": false,
                "code": "step_up_required",
                "error": "Fresh step-up verification required.",
                "expectedScope": "vault:public-key:set",
                "header": CLI_STEP_UP_HEADER_NAME,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let err = upload_public_key(&server.uri(), "token", "abc=", None)
            .await
            .expect_err("403 must propagate as Err");
        assert!(
            err.contains("step_up_required") || err.contains("Fresh step-up"),
            "error must surface the server envelope so the CLI can render the actionable hint: {err}"
        );
    }

    #[tokio::test]
    async fn classify_public_key_state_matches_when_server_key_equals_local() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // Pre-warm the local keypair so we know its public form.
        let local = load_local_public_key_state().expect("load local keypair");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": local.public_key_b64.clone(),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds against happy server");
        match state {
            PublicKeyRegistrationState::Matches(l) => {
                assert_eq!(l.public_key_b64, local.public_key_b64);
            }
            other => panic!("expected Matches, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_public_key_state_needs_initial_set_when_server_returns_null() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": null,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds for empty server state");
        assert!(matches!(
            state,
            PublicKeyRegistrationState::NeedsInitialSet(_)
        ));
    }

    #[tokio::test]
    async fn classify_public_key_state_rotation_required_when_server_key_differs() {
        // Critical regression guard: the previous `ensure_public_key`
        // path would silently upload here, overwriting whatever key
        // was on the server. The new classifier must surface this
        // state so the CLI command layer can refuse and direct the
        // user to the explicit rotation flow.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let state = classify_public_key_state(&server.uri(), "token")
            .await
            .expect("classification succeeds against mismatch");
        match state {
            PublicKeyRegistrationState::RotationRequired {
                local: _,
                server_public_key_b64,
            } => {
                assert_eq!(
                    server_public_key_b64,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                );
            }
            other => panic!("expected RotationRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_public_key_state_propagates_server_errors_instead_of_collapsing() {
        // The prior `get_my_public_key` mapped 401/500 to `Ok(None)`,
        // which would have made the classifier return
        // `NeedsInitialSet` for a token that was actually expired or a
        // server that was simply broken. Pin that errors propagate.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/me/public-key"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .expect(1)
            .mount(&server)
            .await;

        let err = classify_public_key_state(&server.uri(), "token")
            .await
            .expect_err("server 500 must propagate, not be misclassified");
        assert!(err.contains("500"), "got: {err}");
    }

    #[tokio::test]
    async fn discover_cli_step_up_policy_parses_password_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "password",
                "ttlSeconds": 300,
                "header": "X-LPM-Step-Up-Proof",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let policy = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect("happy path");
        assert_eq!(policy.method, "password");
        assert!(policy.reason.is_none());
        assert_eq!(policy.ttl_seconds, Some(300));
        assert_eq!(policy.header.as_deref(), Some("X-LPM-Step-Up-Proof"));
    }

    #[tokio::test]
    async fn discover_cli_step_up_policy_parses_unavailable_with_reason() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "unavailable",
                "reason": "set_password_required",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let policy = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect("happy path");
        assert_eq!(policy.method, "unavailable");
        assert_eq!(policy.reason.as_deref(), Some("set_password_required"));
    }

    #[tokio::test]
    async fn discover_cli_step_up_policy_errors_on_non_2xx() {
        // A 401 here can't be silently collapsed — the CLI would
        // proceed to prompt for a credential the server can't accept.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired token"))
            .expect(1)
            .mount(&server)
            .await;

        let err = discover_cli_step_up_policy(&server.uri(), "token")
            .await
            .expect_err("401 must propagate");
        assert!(err.contains("401"), "got: {err}");
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_password_sends_expected_body() {
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let captured = Arc::new(StdMutex::new(Vec::<String>::new()));
        let server = MockServer::start().await;

        #[derive(Clone)]
        struct CaptureBody(Arc<StdMutex<Vec<String>>>);
        impl Respond for CaptureBody {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                self.0
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request.body).to_string());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "proof": "test-jwt",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(CaptureBody(Arc::clone(&captured)))
            .expect(1)
            .mount(&server)
            .await;

        let proof = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:set",
            &CliStepUpCredential::Password {
                password: "hunter2",
            },
        )
        .await
        .expect("happy path");
        assert_eq!(proof, "test-jwt");

        let body = captured.lock().unwrap()[0].clone();
        assert!(body.contains("\"method\":\"password\""));
        assert!(body.contains("\"scope\":\"vault:public-key:set\""));
        assert!(body.contains("\"password\":\"hunter2\""));
        assert!(
            !body.contains("totpCode"),
            "password-only request must not include totpCode field: {body}"
        );
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_totp_sends_both_password_and_code() {
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;

        let captured = Arc::new(StdMutex::new(Vec::<String>::new()));
        let server = MockServer::start().await;

        #[derive(Clone)]
        struct CaptureBody(Arc<StdMutex<Vec<String>>>);
        impl Respond for CaptureBody {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                self.0
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request.body).to_string());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                    "proof": "totp-jwt",
                }))
            }
        }

        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(CaptureBody(Arc::clone(&captured)))
            .expect(1)
            .mount(&server)
            .await;

        let proof = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:rotate",
            &CliStepUpCredential::Totp {
                password: "hunter2",
                code: "123456",
            },
        )
        .await
        .expect("happy path");
        assert_eq!(proof, "totp-jwt");

        let body = captured.lock().unwrap()[0].clone();
        assert!(body.contains("\"method\":\"totp\""));
        assert!(body.contains("\"scope\":\"vault:public-key:rotate\""));
        assert!(body.contains("\"password\":\"hunter2\""));
        assert!(body.contains("\"totpCode\":\"123456\""));
    }

    #[tokio::test]
    async fn mint_cli_step_up_proof_propagates_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/cli-step-up"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "ok": false,
                "code": "wrong_credential",
                "error": "Incorrect password.",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let err = mint_cli_step_up_proof(
            &server.uri(),
            "token",
            "vault:public-key:set",
            &CliStepUpCredential::Password { password: "wrong" },
        )
        .await
        .expect_err("401 must propagate");
        assert!(err.contains("401"), "got: {err}");
        assert!(
            err.contains("wrong_credential") || err.contains("Incorrect password"),
            "error envelope should be preserved so CLI can render it: {err}"
        );
    }

    #[test]
    fn pending_key_lifecycle_round_trips_through_create_read_promote() {
        // Create → read → promote, verifying that promote leaves the
        // live slot with the pending bytes and clears the pending file.
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // No pending at first.
        assert!(
            read_pending_x25519_keypair()
                .expect("read pending")
                .is_none(),
            "fresh HOME should have no pending key"
        );

        // Create — pending file now exists, live slot still untouched.
        let pending = create_pending_x25519_keypair().expect("create pending");
        let pending_path = pending_x25519_key_path().expect("path");
        let live_path = live_x25519_key_path().expect("path");
        assert!(pending_path.exists(), "create must persist the pending key");
        assert!(
            !live_path.exists(),
            "create must NOT touch the live slot until promotion"
        );

        // Read returns the same key bytes.
        let read_back = read_pending_x25519_keypair()
            .expect("read pending")
            .expect("pending should be present");
        assert_eq!(read_back.public_key_b64, pending.public_key_b64);

        // Promote — live slot now holds the pending bytes; pending is gone.
        promote_pending_x25519_keypair().expect("promote");
        assert!(live_path.exists(), "live slot must be present post-promote");
        assert!(
            !pending_path.exists(),
            "pending must be deleted after promote"
        );
        let live_bytes = std::fs::read(&live_path).expect("read live");
        assert_eq!(live_bytes, &pending.private_key);

        // Subsequent classify-equivalent: load_local_public_key_state
        // should see the new live key.
        let live = load_local_public_key_state().expect("load live");
        assert_eq!(live.public_key_b64, pending.public_key_b64);
    }

    #[test]
    fn pending_key_discard_removes_orphan_without_touching_live() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        // Pre-seed a live key.
        let live = load_local_public_key_state().expect("seed live");
        let live_path = live_x25519_key_path().expect("path");
        assert!(live_path.exists());

        // Create + discard pending.
        let _ = create_pending_x25519_keypair().expect("create pending");
        let pending_path = pending_x25519_key_path().expect("path");
        assert!(pending_path.exists());

        discard_pending_x25519_keypair().expect("discard");
        assert!(!pending_path.exists());
        assert!(live_path.exists(), "discard must NOT touch live");
        // Live key bytes unchanged.
        let live_after = load_local_public_key_state().expect("load live");
        assert_eq!(live_after.public_key_b64, live.public_key_b64);
    }

    #[test]
    fn pending_key_promote_when_no_pending_is_explicit_error() {
        let _guard = env_lock_guard();
        let _isolated = IsolatedVaultKeyEnv::new();

        let err = promote_pending_x25519_keypair()
            .expect_err("promote with no pending must Err, not silently succeed");
        assert!(err.contains("no pending"), "got: {err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn x25519_backend_selection_uses_live_file_after_rotation_without_force_env() {
        assert!(
            should_use_file_backed_x25519_keypair(false, true),
            "a promoted live file must win over the default keychain path so post-rotation reads keep using the rotated key"
        );
        assert!(!should_use_file_backed_x25519_keypair(false, false));
        assert!(should_use_file_backed_x25519_keypair(true, false));
    }
}
