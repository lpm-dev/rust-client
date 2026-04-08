//! Cloud sync for vault secrets.
//!
//! Handles push/pull of encrypted vault data to/from the LPM API.

use crate::crypto;
use std::collections::HashMap;

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

/// Pull a vault from the cloud (personal sync).
pub async fn pull(
    registry_url: &str,
    auth_token: &str,
    vault_id: &str,
) -> Result<(HashMap<String, String>, i32), String> {
    let client = reqwest::Client::new();
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
            let reencrypt_client = reqwest::Client::new();
            let reencrypt_url = format!("{registry_url}/api/vaults/{vault_id}/sync");
            let reencrypt_body = serde_json::json!({
                "encryptedBlob": new_blob,
                "wrappedKey": new_wrapped,
                "expectedVersion": version,
            });
            // Best-effort re-push — don't fail the pull if this fails
            let _ = reencrypt_client
                .post(&reencrypt_url)
                .header("Authorization", format!("Bearer {auth_token}"))
                .json(&reencrypt_body)
                .send()
                .await;
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
    let client = reqwest::Client::new();
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
            let reencrypt_client = reqwest::Client::new();
            let reencrypt_url = format!("{registry_url}/api/vaults/{vault_id}/sync");
            let reencrypt_body = serde_json::json!({
                "encryptedBlob": new_blob,
                "wrappedKey": new_wrapped,
                "expectedVersion": version,
            });
            let _ = reencrypt_client
                .post(&reencrypt_url)
                .header("Authorization", format!("Bearer {auth_token}"))
                .json(&reencrypt_body)
                .send()
                .await;
        }
    }

    Ok((result.plaintext, version))
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

/// Ensure the user's public key is registered on the server.
/// Generates a keypair if none exists locally, uploads if not on server.
pub async fn ensure_public_key(registry_url: &str, auth_token: &str) -> Result<[u8; 32], String> {
    #[cfg(target_os = "macos")]
    let (private, public) = crate::keychain::get_or_create_x25519_keypair()?;
    #[cfg(not(target_os = "macos"))]
    let (private, public) = {
        // Non-macOS: persist X25519 keypair in ~/.lpm/.x25519_key (0o600 permissions)
        let key_path = dirs::home_dir()
            .ok_or("no home directory")?
            .join(".lpm")
            .join(".x25519_key");

        if key_path.exists() {
            // Read existing keypair
            let data =
                std::fs::read(&key_path).map_err(|e| format!("failed to read X25519 key: {e}"))?;
            if data.len() == 32 {
                let mut private_key = [0u8; 32];
                private_key.copy_from_slice(&data);
                let secret = x25519_dalek::StaticSecret::from(private_key);
                let public_key = x25519_dalek::PublicKey::from(&secret);
                (private_key, *public_key.as_bytes())
            } else {
                // Corrupted — regenerate
                let (priv_key, pub_key) = crate::crypto::generate_x25519_keypair();
                let _ = std::fs::create_dir_all(key_path.parent().unwrap());
                let _ = std::fs::write(&key_path, priv_key);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
                }
                (priv_key, pub_key)
            }
        } else {
            // Generate new keypair and persist
            let (priv_key, pub_key) = crate::crypto::generate_x25519_keypair();
            let _ = std::fs::create_dir_all(key_path.parent().unwrap());
            std::fs::write(&key_path, priv_key)
                .map_err(|e| format!("failed to write X25519 key: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            (priv_key, pub_key)
        }
    };

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
) -> Result<PushResponse, String> {
    // 1. Ensure our public key is registered
    let _private = ensure_public_key(registry_url, auth_token).await?;

    // 2. Fetch all org members' public keys
    let members = get_org_member_keys(registry_url, auth_token, org_slug).await?;

    let members_with_keys: Vec<&MemberPublicKey> = members
        .iter()
        .filter(|m| m.has_public_key && m.public_key.is_some())
        .collect();

    if members_with_keys.is_empty() {
        return Err("no org members have registered public keys. Each member needs to run `lpm env vars share --org` once to generate their keypair.".into());
    }

    // 3. Encrypt secrets with random AES key
    let aes_key = crypto::generate_aes_key();
    let encrypted_blob = crypto::encrypt(&aes_key, secrets_json.as_bytes())?;

    // 4. Wrap AES key for each member with their X25519 public key
    let mut wrapped_keys: Vec<(String, String)> = Vec::new();
    for member in &members_with_keys {
        let pub_b64 = member.public_key.as_ref().unwrap();
        let pub_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pub_b64)
            .map_err(|e| format!("invalid public key for user {}: {e}", member.user_id))?;

        if pub_bytes.len() != 32 {
            continue;
        }

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);

        let wrapped = crypto::wrap_key_for_recipient(&aes_key, &pub_key)?;
        wrapped_keys.push((member.user_id.clone(), wrapped));
    }

    // 5. Push to server
    let client = reqwest::Client::new();
    let url = format!("{registry_url}/api/orgs/{org_slug}/vaults/{vault_id}");

    let keys_json: Vec<serde_json::Value> = wrapped_keys
        .iter()
        .map(|(uid, wk)| serde_json::json!({"userId": uid, "wrappedKey": wk}))
        .collect();

    let body = serde_json::json!({
        "encryptedBlob": encrypted_blob,
        "wrappedKeys": keys_json,
    });

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
