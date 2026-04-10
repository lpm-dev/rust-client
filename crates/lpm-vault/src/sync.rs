//! Cloud sync for vault secrets.
//!
//! Handles push/pull of encrypted vault data to/from the LPM API.

use crate::crypto;
use std::collections::HashMap;

fn sync_request_timeout(default: std::time::Duration) -> std::time::Duration {
    match std::env::var("LPM_TEST_SYNC_TIMEOUT_MS") {
        Ok(value) => value
            .parse::<u64>()
            .map(std::time::Duration::from_millis)
            .unwrap_or(default),
        Err(_) => default,
    }
}

/// Response from push endpoint.
#[derive(serde::Deserialize)]
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
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
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

    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/vaults/{vault_id}/sync");

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
        .header("Authorization", format!("Bearer {auth_token}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        if let Ok(result) = serde_json::from_str::<PushResponse>(&body) {
            return Err(result
                .error
                .unwrap_or_else(|| format!("server error: {status}")));
        }

        let message = body.trim();
        return Err(if message.is_empty() {
            format!("server error: {status}")
        } else {
            message.to_string()
        });
    }

    let result = response
        .json::<PushResponse>()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

    Ok(result)
}

/// Pull a vault from the cloud (personal sync).
pub async fn pull(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(HashMap<String, String>, i32), String> {
    let client = reqwest::Client::builder()
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vaults/{vault_id}/sync");

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {auth_token}"))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: PullResponse = response
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

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

    // If decrypted with legacy key, re-encrypt with new stored key and push back
    if result.needs_reencrypt {
        tracing::info!("migrating vault {vault_id} to stored wrapping key");
        if let Ok((new_blob, new_wrapped)) = crypto::encrypt_vault_for_sync(secrets_json) {
            let reencrypt_client = reqwest::Client::builder()
                .timeout(sync_request_timeout(std::time::Duration::from_secs(15)))
                .build();
            let reencrypt_url = format!("{registry_url}/api/vaults/{vault_id}/sync");
            let reencrypt_body = serde_json::json!({
                "encryptedBlob": new_blob,
                "wrappedKey": new_wrapped,
                "expectedVersion": version,
            });
            // Best-effort re-push — don't fail the pull if this fails
            if let Ok(reencrypt_client) = reencrypt_client {
                let _ = reencrypt_client
                    .post(&reencrypt_url)
                    .header("Authorization", format!("Bearer {auth_token}"))
                    .json(&reencrypt_body)
                    .send()
                    .await;
            }
        }
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
    let client = reqwest::Client::builder()
        .timeout(sync_request_timeout(std::time::Duration::from_secs(30)))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;
    let url = format!("{registry_url}/api/vaults/{vault_id}/sync");

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {auth_token}"))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: PullResponse = response
        .json()
        .await
        .map_err(|e| format!("response parse error: {e}"))?;

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

    // Best-effort re-encrypt on legacy migration
    if result.needs_reencrypt {
        tracing::info!("migrating vault {vault_id} to stored wrapping key (pull_raw)");
        if let Ok((new_blob, new_wrapped)) = crypto::encrypt_vault_for_sync(&result.plaintext) {
            let reencrypt_client = reqwest::Client::builder()
                .timeout(sync_request_timeout(std::time::Duration::from_secs(10)))
                .build();
            let reencrypt_url = format!("{registry_url}/api/vaults/{vault_id}/sync");
            let reencrypt_body = serde_json::json!({
                "encryptedBlob": new_blob,
                "wrappedKey": new_wrapped,
                "expectedVersion": version,
            });
            if let Ok(reencrypt_client) = reencrypt_client {
                let _ = reencrypt_client
                    .post(&reencrypt_url)
                    .header("Authorization", format!("Bearer {auth_token}"))
                    .json(&reencrypt_body)
                    .send()
                    .await;
            }
        }
    }

    Ok((result.plaintext, version))
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
    let client = reqwest::Client::new();
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
        let body = response.text().await.unwrap_or_default();
        return Err(format!("failed to upload public key: {body}"));
    }

    Ok(())
}

/// Check if the user's public key is already on the server.
pub async fn get_my_public_key(
    registry_url: &str,
    auth_token: &str,
) -> Result<Option<String>, String> {
    let client = reqwest::Client::new();
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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/members/public-keys");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("failed to fetch member keys: {body}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

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
        let data = std::fs::read(&key_path).map_err(|e| format!("failed to read X25519 key: {e}"))?;
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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/vaults");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/vaults/{vault_id}");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("server error: {body}"));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/vaults/{vault_id}");

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

    let response = client
        .post(&url)
        .bearer_auth(auth_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: PushResponse = response
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

    for member in members_with_keys {
        let pub_b64 = member.public_key.as_ref().ok_or_else(|| {
            format!("missing public key for user {}", member.user_id)
        })?;
        let pub_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pub_b64)
            .map_err(|e| format!("invalid public key for user {}: {e}", member.user_id))?;

        if pub_bytes.len() != 32 {
            return Err(format!(
                "invalid public key for user {}: expected 32 bytes, got {}",
                member.user_id,
                pub_bytes.len()
            ));
        }

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

    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/vaults/{vault_id}");

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
        .header("Authorization", format!("Bearer {auth_token}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    let status = response.status();
    let result: PushResponse = response
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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/vault/pair/{code}");

    let response = client
        .get(&url)
        .bearer_auth(auth_token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
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
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/vault/pair/{code}");

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
        let body = response.text().await.unwrap_or_default();
        return Err(format!("approval failed: {body}"));
    }

    Ok(())
}

/// Revoke all browser pairings for the authenticated user.
pub async fn unpair_all(registry_url: &str, auth_token: &str) -> Result<(), String> {
    let client = reqwest::Client::new();
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
        let body = response.text().await.unwrap_or_default();
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
    let client = reqwest::Client::new();
    let mut url = format!("{registry_url}/api/vaults/{vault_id}/ci-pull");
    if let Some(e) = env {
        // Env names are alphanumeric/dashes — safe for query strings without encoding
        url = format!("{url}?env={e}");
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
/// Called during `lpm use vars oidc allow` to enable server-side decryption.
pub async fn upload_escrow_key(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
    wrapping_key_hex: &str,
) -> Result<(), String> {
    let client = reqwest::Client::new();
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
        let body = response.text().await.unwrap_or_default();
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
    let client = reqwest::Client::new();
    let mut url = format!("{registry_url}/api/vaults/{vault_id}/audit");
    if let Some(c) = cursor {
        url = format!("{url}?cursor={c}");
    }

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {auth_token}"))
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
            .and(body_string_contains("\"encryptedWrappingKey\":\"wrapped-key\""))
            .and(body_string_contains("\"ephemeralPublicKey\":\"ephemeral-key\""))
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
        assert_eq!(vars.get("API_KEY").map(String::as_str), Some("secret-value"));
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
        assert_eq!(vars.get("API_KEY").map(String::as_str), Some("secret-value"));
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

    #[tokio::test]
    async fn pull_env_returns_empty_for_non_default_legacy_flat_vault() {
        let _guard = env_lock().lock().await;
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "encryptedBlob": encrypted_blob,
                "wrappedKey": wrapped_key,
                "version": 7
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (secrets, version) = pull_env(&server.uri(), "auth-token", "vault-123", "staging")
            .await
            .expect("non-default env lookup should not fail for legacy flat vaults");

        assert_eq!(version, 7);
        assert!(secrets.is_empty(), "legacy flat vaults should only resolve the default env");
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
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(2))
                    .set_body_json(serde_json::json!({
                        "encryptedBlob": "ignored",
                        "wrappedKey": "ignored",
                        "version": 1
                    })),
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

        assert!(elapsed < std::time::Duration::from_secs(1), "pull_raw should respect the configured request timeout, took {elapsed:?}");
        assert!(result.is_err(), "pull_raw should fail when the sync endpoint stalls");
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
        std::fs::create_dir_all(key_path.parent().expect("forced key path should have a parent"))
            .expect("failed to create forced key dir");
        std::fs::write(&key_path, [3u8; 31]).expect("failed to seed corrupted forced key file");

        let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
        runtime.block_on(async {
            #[derive(Clone)]
            struct CapturePushResponder {
                body: Arc<StdMutex<Option<String>>>,
            }

            impl Respond for CapturePushResponder {
                fn respond(&self, request: &Request) -> ResponseTemplate {
                    let body = String::from_utf8(request.body.clone())
                        .expect("push_org_with_keys request body should be valid utf-8 json");
                    *self.body.lock().unwrap() = Some(body);
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "version": 8,
                        "status": "ok"
                    }))
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

        let first_ids: std::collections::BTreeSet<_> =
            first_share.iter().map(|(user_id, _)| user_id.as_str()).collect();
        let second_ids: std::collections::BTreeSet<_> =
            second_share.iter().map(|(user_id, _)| user_id.as_str()).collect();

        assert_eq!(first_ids, std::collections::BTreeSet::from(["user-a", "user-b"]));
        assert_eq!(second_ids, std::collections::BTreeSet::from(["user-b", "user-c"]));
        assert!(
            !second_ids.contains("user-a"),
            "stale recipients from prior shares must not remain in a new wrapped-key set"
        );
    }
}
