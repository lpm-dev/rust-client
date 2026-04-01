//! macOS Keychain integration for vault secrets.
//!
//! Uses the `security` CLI tool for compatibility with the SwiftUI Vault app.
//! Both CLI and app share the same Keychain items via an index-based design:
//!
//! - **Index item**: service=`dev.lpm.vault`, account=`__index__`
//!   JSON array of `[{"id":"vault-id","name":"project-name","path":"/project/path"}]`
//! - **Data items**: service=`dev.lpm.vault`, account=`{vault-id}`
//!   JSON dict of `{"KEY": "VALUE", ...}`
//!
//! This avoids `SecItemCopyMatching` with `kSecMatchLimitAll` which is unreliable.

use std::collections::HashMap;

/// Keychain service name — shared with the SwiftUI Vault app.
const SERVICE: &str = "dev.lpm.vault";

/// Account name for the project index.
const INDEX_ACCOUNT: &str = "__index__";

/// Maximum recommended vault size (90KB warning threshold).
const MAX_VAULT_SIZE_WARNING: usize = 90 * 1024;

/// A project entry in the index.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct IndexEntry {
    pub id: String,
    pub name: String,
    pub path: String,
}

/// Wrapper for the environments Keychain format.
#[derive(serde::Serialize, serde::Deserialize)]
struct EnvironmentsWrapper {
    environments: HashMap<String, HashMap<String, String>>,
}

/// Read all secrets for a vault ID from the Keychain.
/// Handles both new format (`{"environments": {...}}`) and old flat format (`{"KEY": "VALUE"}`).
/// The `env` parameter selects which environment to return (default: "default").
pub fn read_vault(vault_id: &str) -> Option<HashMap<String, String>> {
    read_vault_env(vault_id, "default")
}

/// Read secrets for a specific environment from the Keychain.
pub fn read_vault_env(vault_id: &str, env: &str) -> Option<HashMap<String, String>> {
    let json = read_keychain_password(SERVICE, vault_id)?;

    // Try new format first
    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return wrapper.environments.get(env).cloned();
    }

    // Fall back to old flat format (treat as "default" environment)
    if env == "default" {
        return serde_json::from_str(&json).ok();
    }

    None
}

/// Read all environments for a vault ID.
pub fn read_all_environments(vault_id: &str) -> Option<HashMap<String, HashMap<String, String>>> {
    let json = read_keychain_password(SERVICE, vault_id)?;

    // Try new format
    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return Some(wrapper.environments);
    }

    // Fall back to old flat format
    if let Ok(flat) = serde_json::from_str::<HashMap<String, String>>(&json) {
        let mut envs = HashMap::new();
        envs.insert("default".to_string(), flat);
        return Some(envs);
    }

    None
}

/// Write secrets to the Keychain using the environments format.
pub fn write_vault(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    secrets: &HashMap<String, String>,
) -> Result<(), String> {
    write_vault_env(vault_id, project_name, project_path, "default", secrets)
}

/// Write secrets for a specific environment to the Keychain.
pub fn write_vault_env(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    secrets: &HashMap<String, String>,
) -> Result<(), String> {
    // Read existing environments, update the target env, write back
    let mut all_envs = read_all_environments(vault_id).unwrap_or_default();
    all_envs.insert(env.to_string(), secrets.clone());

    let wrapper = EnvironmentsWrapper {
        environments: all_envs,
    };
    let json = serde_json::to_string(&wrapper)
        .map_err(|e| format!("failed to serialize environments: {e}"))?;

    if json.len() > MAX_VAULT_SIZE_WARNING {
        tracing::warn!(
            "vault data is {} bytes (approaching ~100KB Keychain limit)",
            json.len()
        );
    }

    // Write secrets data
    write_keychain_password(SERVICE, vault_id, &json)?;

    // Update project index
    let mut index = read_index();
    if let Some(entry) = index.iter_mut().find(|e| e.id == vault_id) {
        entry.name = project_name.to_string();
        entry.path = project_path.to_string();
    } else {
        index.push(IndexEntry {
            id: vault_id.to_string(),
            name: project_name.to_string(),
            path: project_path.to_string(),
        });
    }
    write_index(&index)?;

    Ok(())
}

/// Delete a vault from the Keychain and remove from index.
pub fn delete_vault(vault_id: &str) -> Result<(), String> {
    delete_keychain_password(SERVICE, vault_id);

    let mut index = read_index();
    index.retain(|e| e.id != vault_id);
    write_index(&index)?;

    Ok(())
}

/// List all vault projects from the index.
pub fn list_vaults() -> Vec<IndexEntry> {
    read_index()
}

// ─── X25519 Private Key Storage ───────────────────────────────────

const X25519_ACCOUNT: &str = "__x25519_private_key__";

/// Read the stored X25519 private key from Keychain.
pub fn read_x25519_private_key() -> Option<[u8; 32]> {
    let b64 = read_keychain_password(SERVICE, X25519_ACCOUNT)?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Store an X25519 private key in Keychain.
pub fn write_x25519_private_key(private_key: &[u8; 32]) -> Result<(), String> {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
    write_keychain_password(SERVICE, X25519_ACCOUNT, &b64)
}

/// Get or create the X25519 keypair. Returns (private_key, public_key).
/// Generates and stores a new keypair if none exists.
pub fn get_or_create_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    if let Some(private) = read_x25519_private_key() {
        let public = crate::crypto::x25519_public_from_private(&private);
        return Ok((private, public));
    }

    let (private, public) = crate::crypto::generate_x25519_keypair();
    write_x25519_private_key(&private)?;
    Ok((private, public))
}

// ─── Index Management ──────────────────────────────────────────────

fn read_index() -> Vec<IndexEntry> {
    read_keychain_password(SERVICE, INDEX_ACCOUNT)
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn write_index(entries: &[IndexEntry]) -> Result<(), String> {
    let json =
        serde_json::to_string(entries).map_err(|e| format!("failed to serialize index: {e}"))?;
    write_keychain_password(SERVICE, INDEX_ACCOUNT, &json)
}

// ─── macOS Keychain via `security` CLI ─────────────────────────────

fn read_keychain_password(service: &str, account: &str) -> Option<String> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .ok()?;

    if output.status.success() {
        let value = String::from_utf8(output.stdout).ok()?;
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn write_keychain_password(service: &str, account: &str, password: &str) -> Result<(), String> {
    // Vault secrets (dev.lpm.vault) are shared between the Rust CLI and the
    // SwiftUI LPMVault macOS app. Both need to read/write the same Keychain
    // entries. The Swift app uses Security.framework with
    // kSecAttrAccessibleWhenUnlocked which doesn't set per-app ACLs.
    //
    // For shared services: use delete+add pattern. The `security` CLI without
    // -A or -T creates an ACL that only trusts `security` itself — blocking
    // the Swift app. With -A, any app when keychain is unlocked can access
    // (matching the Swift app's behavior). This is acceptable because:
    // 1. macOS Keychain encrypts at rest (locked keychain = no access)
    // 2. Physical access + unlocked session already implies full compromise
    // 3. Lifecycle scripts are blocked by lpm-security (no postinstall)
    //
    // For CLI-only services (lpm-cli auth tokens): use -U without -A for
    // stricter ACL. Those entries don't need Swift app access.

    // Delete existing entry first (ignore errors if missing)
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Add new entry — shared services get -A for cross-app access
    let is_shared = service == SERVICE;
    let mut args = vec!["add-generic-password"];
    if is_shared {
        args.push("-A"); // Allow access from Swift LPMVault app
    }
    args.extend(["-s", service, "-a", account, "-w", password]);

    let status = std::process::Command::new("security")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("keychain write error: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err("security add-generic-password failed".to_string())
    }
}

fn delete_keychain_password(service: &str, account: &str) {
    let _ = std::process::Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests hit the real macOS Keychain with a unique service name.
    // Each test cleans up after itself.

    fn test_service() -> String {
        format!("dev.lpm.vault.test.{}", std::process::id())
    }

    fn cleanup_item(service: &str, account: &str) {
        let _ = std::process::Command::new("security")
            .args(["delete-generic-password", "-s", service, "-a", account])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[test]
    fn keychain_round_trip() {
        let svc = test_service();
        let account = "test-round-trip";
        defer_cleanup(&svc, account);

        write_keychain_password(&svc, account, "hello-vault").unwrap();
        let result = read_keychain_password(&svc, account);
        assert_eq!(result.as_deref(), Some("hello-vault"));

        cleanup_item(&svc, account);
    }

    #[test]
    fn keychain_read_missing() {
        let svc = test_service();
        let result = read_keychain_password(&svc, "nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn keychain_overwrite() {
        let svc = test_service();
        let account = "test-overwrite";
        defer_cleanup(&svc, account);

        write_keychain_password(&svc, account, "value-1").unwrap();
        write_keychain_password(&svc, account, "value-2").unwrap();
        let result = read_keychain_password(&svc, account);
        assert_eq!(result.as_deref(), Some("value-2"));

        cleanup_item(&svc, account);
    }

    #[test]
    fn keychain_json_secrets() {
        let svc = test_service();
        let account = "test-json";
        defer_cleanup(&svc, account);

        let mut secrets = HashMap::new();
        secrets.insert("DB_HOST".to_string(), "localhost".to_string());
        secrets.insert("API_KEY".to_string(), "sk-123".to_string());

        let json = serde_json::to_string(&secrets).unwrap();
        write_keychain_password(&svc, account, &json).unwrap();

        let stored = read_keychain_password(&svc, account).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed["DB_HOST"], "localhost");
        assert_eq!(parsed["API_KEY"], "sk-123");

        cleanup_item(&svc, account);
    }

    fn defer_cleanup(_svc: &str, _account: &str) {
        // Marker function — cleanup_item is called explicitly.
        // Using defer pattern would require a Drop impl, but explicit cleanup is fine for tests.
    }
}
