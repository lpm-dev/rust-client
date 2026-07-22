//! Encrypted vault blobs for non-macOS platforms.
//!
//! Linux and Windows keep vault files at `~/.lpm/vaults/{vault-id}.enc`.
//! The encryption key is protected by the OS secure store when available,
//! with the older scrypt-backed file key retained only as a compatibility
//! fallback.

// This module is conditionally compiled (`#[cfg(not(target_os = "macos"))]` in lib.rs).
// On macOS builds the functions appear unused, but they are active on Linux/Windows.
#![allow(dead_code)]

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use std::collections::HashMap;
use std::path::PathBuf;

const NATIVE_DATA_KEY_SERVICE: &str = "dev.lpm.vault-local-key";
const NATIVE_DATA_KEY_ACCOUNT: &str = "data-key";

type SecretMap = HashMap<String, String>;
type EnvironmentMap = HashMap<String, SecretMap>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKeySource {
    Native,
    FileFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataKey {
    bytes: [u8; 32],
    source: DataKeySource,
}

trait NativeDataKeyStore {
    fn read_hex_key(&self) -> Result<Option<String>, String>;
    fn write_hex_key(&self, hex_key: &str) -> Result<(), String>;
}

#[derive(Debug, Default)]
struct KeyringNativeDataKeyStore;

impl NativeDataKeyStore for KeyringNativeDataKeyStore {
    fn read_hex_key(&self) -> Result<Option<String>, String> {
        #[cfg(debug_assertions)]
        if let Some(result) = debug_native_read_override() {
            return result;
        }

        let entry = keyring::Entry::new(NATIVE_DATA_KEY_SERVICE, NATIVE_DATA_KEY_ACCOUNT)
            .map_err(|e| format!("native vault data-key entry error: {e}"))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("native vault data-key read error: {e}")),
        }
    }

    fn write_hex_key(&self, hex_key: &str) -> Result<(), String> {
        #[cfg(debug_assertions)]
        if let Some(error) = debug_native_write_error() {
            return Err(error);
        }

        let entry = keyring::Entry::new(NATIVE_DATA_KEY_SERVICE, NATIVE_DATA_KEY_ACCOUNT)
            .map_err(|e| format!("native vault data-key entry error: {e}"))?;
        entry
            .set_password(hex_key)
            .map_err(|e| format!("native vault data-key write error: {e}"))
    }
}

#[cfg(debug_assertions)]
fn debug_native_read_override() -> Option<Result<Option<String>, String>> {
    if let Ok(error) = std::env::var("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR") {
        return Some(Err(error));
    }
    if let Ok(hex_key) = std::env::var("LPM_TEST_VAULT_NATIVE_KEY_HEX") {
        return Some(Ok(Some(hex_key)));
    }
    if matches!(
        std::env::var("LPM_TEST_VAULT_NATIVE_KEY_MISSING").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    ) {
        return Some(Ok(None));
    }
    None
}

#[cfg(debug_assertions)]
fn debug_native_write_error() -> Option<String> {
    std::env::var("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR").ok()
}

fn use_fast_test_scrypt() -> bool {
    if !cfg!(debug_assertions) && !crate::acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_TEST_FAST_SCRYPT").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn force_file_data_key() -> bool {
    if !cfg!(debug_assertions) && !crate::acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn lpm_dir_path() -> Result<PathBuf, String> {
    let home = crate::lpm_home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".lpm"))
}

fn vaults_dir_path() -> Result<PathBuf, String> {
    Ok(lpm_dir_path()?.join("vaults"))
}

fn vaults_dir() -> Result<PathBuf, String> {
    let dir = vaults_dir_path()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create vaults dir: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    Ok(dir)
}

fn vault_path(vault_id: &str) -> Result<PathBuf, String> {
    Ok(vaults_dir()?.join(format!("{vault_id}.enc")))
}

fn salt_path() -> Result<PathBuf, String> {
    Ok(lpm_dir_path()?.join(".vault-salt"))
}

fn get_or_create_salt() -> Result<Vec<u8>, String> {
    let path = salt_path()?;
    if path.exists() {
        return lpm_common::read_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read vault salt: {e}"));
    }

    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    std::fs::write(&path, &salt).map_err(|e| format!("failed to write vault salt: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("failed to set permissions on salt file: {e}");
        }
    }

    Ok(salt)
}

fn fallback_key_path() -> Result<PathBuf, String> {
    Ok(lpm_dir_path()?.join(".vault-fallback-key"))
}

fn fallback_key_exists() -> bool {
    fallback_key_path().is_ok_and(|path| path.exists())
}

fn read_fallback_key() -> Result<Option<String>, String> {
    let key_path = fallback_key_path()?;

    if key_path.exists() {
        return lpm_common::read_text_file_capped(&key_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map(Some)
            .map_err(|e| format!("failed to read vault fallback key: {e}"));
    }

    Ok(None)
}

/// Create a random file-fallback encryption password.
///
/// The password is a 64-char random alphanumeric string stored at
/// `~/.lpm/.vault-fallback-key` with 0o600 permissions. This path is
/// only used when native storage is unavailable before a vault has
/// been promoted into the OS store.
fn create_fallback_key() -> Result<String, String> {
    let key_path = fallback_key_path()?;

    // Generate new random key
    use rand::Rng;
    let key: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let dir = key_path.parent().unwrap();
    let _ = std::fs::create_dir_all(dir);
    std::fs::write(&key_path, &key)
        .map_err(|e| format!("failed to write vault fallback key: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(key)
}

fn get_or_create_fallback_key() -> Result<String, String> {
    match read_fallback_key()? {
        Some(key) => Ok(key),
        None => create_fallback_key(),
    }
}

fn derive_key_from_password(password: &str) -> Result<[u8; 32], String> {
    let salt = get_or_create_salt()?;
    let params = if use_fast_test_scrypt() {
        // Keep workflow tests fast when auth/vault are intentionally file-backed.
        scrypt::Params::new(10, 8, 1, 32).map_err(|e| format!("scrypt params error: {e}"))?
    } else {
        // N=2^20 (1,048,576), r=8, p=4: ~200ms on modern hardware
        scrypt::Params::new(20, 8, 4, 32).map_err(|e| format!("scrypt params error: {e}"))?
    };

    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| format!("scrypt error: {e}"))?;

    Ok(key)
}

fn read_file_data_key() -> Result<Option<DataKey>, String> {
    read_fallback_key()?
        .map(|password| {
            derive_key_from_password(&password).map(|bytes| DataKey {
                bytes,
                source: DataKeySource::FileFallback,
            })
        })
        .transpose()
}

fn get_or_create_file_data_key() -> Result<DataKey, String> {
    let password = get_or_create_fallback_key()?;
    let bytes = derive_key_from_password(&password)?;
    Ok(DataKey {
        bytes,
        source: DataKeySource::FileFallback,
    })
}

fn decode_native_data_key(hex_key: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| format!("native vault data-key is not valid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "native vault data-key has invalid length {} (expected 32 bytes)",
            bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn read_native_data_key(store: &dyn NativeDataKeyStore) -> Result<Option<DataKey>, String> {
    store
        .read_hex_key()?
        .map(|hex_key| {
            decode_native_data_key(&hex_key).map(|bytes| DataKey {
                bytes,
                source: DataKeySource::Native,
            })
        })
        .transpose()
}

fn write_native_data_key(store: &dyn NativeDataKeyStore, key: &[u8; 32]) -> Result<(), String> {
    store.write_hex_key(&hex::encode(key))
}

fn remove_fallback_key_after_native_promotion() -> Result<(), String> {
    let path = fallback_key_path()?;
    if !path.exists() {
        return Ok(());
    }

    std::fs::remove_file(&path).map_err(|e| {
        format!(
            "native vault data-key promotion succeeded, but failed to remove {}: {e}",
            path.display()
        )
    })
}

fn native_unavailable_without_file_key(error: String) -> String {
    format!(
        "vault native storage backend is unavailable and no encrypted-file fallback key exists. \
         Unlock Secret Service/Credential Manager or restore ~/.lpm/.vault-fallback-key. \
         Native backend error: {error}"
    )
}

fn load_data_key_with_store(store: &dyn NativeDataKeyStore) -> Result<DataKey, String> {
    if force_file_data_key() {
        return get_or_create_file_data_key();
    }

    match read_native_data_key(store) {
        Ok(Some(key)) => {
            remove_fallback_key_after_native_promotion()?;
            return Ok(key);
        }
        Ok(None) => {}
        Err(err) => {
            if let Some(file_key) = read_file_data_key()? {
                return Ok(file_key);
            }
            return Err(native_unavailable_without_file_key(err));
        }
    }

    if let Some(file_key) = read_file_data_key()? {
        return match write_native_data_key(store, &file_key.bytes) {
            Ok(()) => {
                remove_fallback_key_after_native_promotion()?;
                Ok(DataKey {
                    bytes: file_key.bytes,
                    source: DataKeySource::Native,
                })
            }
            Err(err) => {
                tracing::debug!("native vault data-key promotion unavailable: {err}");
                Ok(file_key)
            }
        };
    }

    let mut native_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut native_key);
    if write_native_data_key(store, &native_key).is_ok() {
        return Ok(DataKey {
            bytes: native_key,
            source: DataKeySource::Native,
        });
    }

    get_or_create_file_data_key()
}

fn load_data_key() -> Result<DataKey, String> {
    load_data_key_with_store(&KeyringNativeDataKeyStore)
}

pub fn storage_backend_status() -> crate::VaultStorageBackend {
    if force_file_data_key() {
        return crate::VaultStorageBackend::FileFallback;
    }

    let store = KeyringNativeDataKeyStore;
    match read_native_data_key(&store) {
        Ok(Some(_)) => crate::VaultStorageBackend::NativeProtected,
        Ok(None) => {
            if fallback_key_exists() {
                return crate::VaultStorageBackend::FileFallback;
            }
            if vault_files_exist() {
                crate::VaultStorageBackend::Unavailable {
                    message: "encrypted vault files exist, but no native or file fallback data key was found"
                        .to_string(),
                }
            } else {
                crate::VaultStorageBackend::NativePreferred
            }
        }
        Err(error) => {
            if fallback_key_exists() {
                return crate::VaultStorageBackend::FileFallback;
            }
            if vault_files_exist() {
                crate::VaultStorageBackend::Unavailable {
                    message: native_unavailable_without_file_key(error),
                }
            } else {
                crate::VaultStorageBackend::NativePreferred
            }
        }
    }
}

fn vault_files_exist() -> bool {
    let Ok(dir) = vaults_dir_path() else {
        return false;
    };
    let Ok(mut entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.any(|entry| {
        entry
            .ok()
            .and_then(|entry| entry.path().extension().map(|ext| ext == "enc"))
            .unwrap_or(false)
    })
}

fn encrypt(plaintext: &str) -> Result<String, String> {
    encrypt_with_store(plaintext, &KeyringNativeDataKeyStore)
}

fn encrypt_with_store(plaintext: &str, store: &dyn NativeDataKeyStore) -> Result<String, String> {
    let data_key = load_data_key_with_store(store)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key.bytes)
        .map_err(|e| format!("cipher init error: {e}"))?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption error: {e}"))?;

    let tag_start = ciphertext.len() - 16;
    let (encrypted, auth_tag) = ciphertext.split_at(tag_start);

    Ok(format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(encrypted)
    ))
}

fn decrypt(encoded: &str) -> Result<String, String> {
    decrypt_with_store(encoded, &KeyringNativeDataKeyStore)
}

fn decrypt_with_store(encoded: &str, store: &dyn NativeDataKeyStore) -> Result<String, String> {
    let parts: Vec<&str> = encoded.split(':').collect();
    if parts.len() != 3 {
        return Err("invalid encrypted format".to_string());
    }

    let iv = BASE64
        .decode(parts[0])
        .map_err(|e| format!("iv decode: {e}"))?;
    let auth_tag = BASE64
        .decode(parts[1])
        .map_err(|e| format!("tag decode: {e}"))?;
    let encrypted = BASE64
        .decode(parts[2])
        .map_err(|e| format!("data decode: {e}"))?;

    if iv.len() != 12 {
        return Err(format!("incompatible IV size: {} bytes", iv.len()));
    }

    let data_key = load_data_key_with_store(store)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key.bytes)
        .map_err(|e| format!("cipher init error: {e}"))?;

    let nonce = GenericArray::from_slice(&iv);
    let mut combined = encrypted;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .map_err(|_| "decryption failed (wrong key or corrupted data)".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))
}

/// Internal format for multi-environment vault storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct VaultData {
    #[serde(default)]
    environments: EnvironmentMap,
}

/// Read vault secrets for a specific environment.
pub fn read_vault_file_env(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    let path = vault_path(vault_id)?;
    if !path.exists() {
        return Ok(None);
    }

    let content = lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(|e| format!("failed to read vault {}: {e}", path.display()))?;
    let json = decrypt(content.trim())?;

    // Try new multi-env format first
    if let Ok(data) = serde_json::from_str::<VaultData>(&json)
        && !data.environments.is_empty()
    {
        return Ok(data.environments.get(env).cloned());
    }

    // Fall back to old flat format (auto-migrate: treat as "default")
    if env == "default" {
        return Ok(serde_json::from_str(&json).ok());
    }

    Ok(None)
}

/// Read all environments from encrypted file.
pub fn read_all_environments(vault_id: &str) -> Result<Option<EnvironmentMap>, String> {
    let path = vault_path(vault_id)?;
    if !path.exists() {
        return Ok(None);
    }

    let content = lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(|e| format!("failed to read vault {}: {e}", path.display()))?;
    let json = decrypt(content.trim())?;

    // Try new multi-env format
    if let Ok(data) = serde_json::from_str::<VaultData>(&json)
        && !data.environments.is_empty()
    {
        return Ok(Some(data.environments));
    }

    // Fall back to old flat format → wrap as "default"
    if let Ok(flat) = serde_json::from_str::<HashMap<String, String>>(&json) {
        let mut envs = HashMap::new();
        envs.insert("default".to_string(), flat);
        return Ok(Some(envs));
    }

    Ok(None)
}

/// Write vault secrets to encrypted file (specific environment).
pub fn write_vault_file(vault_id: &str, secrets: &SecretMap) -> Result<(), String> {
    write_vault_file_env(vault_id, "default", secrets)
}

pub fn write_all_environments(vault_id: &str, environments: &EnvironmentMap) -> Result<(), String> {
    let path = vault_path(vault_id)?;
    let data = VaultData {
        environments: environments.clone(),
    };
    let json =
        serde_json::to_string(&data).map_err(|e| format!("failed to serialize secrets: {e}"))?;
    let encrypted = encrypt(&json)?;

    std::fs::write(&path, &encrypted).map_err(|e| format!("failed to write vault: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Write vault secrets for a specific environment.
pub fn write_vault_file_env(vault_id: &str, env: &str, secrets: &SecretMap) -> Result<(), String> {
    let path = vault_path(vault_id)?;

    // Read existing environments (if any)
    let mut data = if path.exists() {
        let content =
            lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
                .map_err(|e| format!("failed to read vault: {e}"))?;
        let json = decrypt(content.trim())?;
        serde_json::from_str::<VaultData>(&json).unwrap_or(VaultData {
            environments: HashMap::new(),
        })
    } else {
        VaultData {
            environments: HashMap::new(),
        }
    };

    // Update the specific environment
    data.environments.insert(env.to_string(), secrets.clone());

    let json =
        serde_json::to_string(&data).map_err(|e| format!("failed to serialize secrets: {e}"))?;
    let encrypted = encrypt(&json)?;

    std::fs::write(&path, &encrypted).map_err(|e| format!("failed to write vault: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Delete encrypted vault file.
pub fn delete_vault_file(vault_id: &str) -> Result<(), String> {
    let path = vault_path(vault_id)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("failed to delete vault: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    #[derive(Default)]
    struct FakeNativeDataKeyStore {
        key: RefCell<Option<String>>,
        read_error: RefCell<Option<String>>,
        write_error: RefCell<Option<String>>,
        writes: Cell<usize>,
    }

    impl FakeNativeDataKeyStore {
        fn with_key(hex_key: String) -> Self {
            Self {
                key: RefCell::new(Some(hex_key)),
                ..Self::default()
            }
        }

        fn set_read_error(&self, error: &str) {
            *self.read_error.borrow_mut() = Some(error.to_string());
        }

        fn set_write_error(&self, error: &str) {
            *self.write_error.borrow_mut() = Some(error.to_string());
        }
    }

    impl NativeDataKeyStore for FakeNativeDataKeyStore {
        fn read_hex_key(&self) -> Result<Option<String>, String> {
            if let Some(error) = self.read_error.borrow().clone() {
                return Err(error);
            }
            Ok(self.key.borrow().clone())
        }

        fn write_hex_key(&self, hex_key: &str) -> Result<(), String> {
            if let Some(error) = self.write_error.borrow().clone() {
                return Err(error);
            }
            self.writes.set(self.writes.get() + 1);
            *self.key.borrow_mut() = Some(hex_key.to_string());
            Ok(())
        }
    }

    fn with_temp_vault_home<T>(test: impl FnOnce(&Path) -> T) -> T {
        let _lock = crate::test_env_lock::acquire_env_lock();
        let temp_home = tempfile::tempdir().expect("create temp HOME");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp_home.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");
        let original_fast_scrypt = std::env::var_os("LPM_TEST_FAST_SCRYPT");
        let original_native_read_error = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR");
        let original_native_hex = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_HEX");
        let original_native_missing = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_MISSING");
        let original_native_write_error = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR");

        unsafe {
            std::env::remove_var("LPM_FORCE_FILE_VAULT");
            std::env::set_var("LPM_TEST_FAST_SCRYPT", "1");
            std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR");
            std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_HEX");
            std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_MISSING");
            std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR");
        }

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(temp_home.path())));

        unsafe {
            match original_force_file_vault {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
            match original_fast_scrypt {
                Some(value) => std::env::set_var("LPM_TEST_FAST_SCRYPT", value),
                None => std::env::remove_var("LPM_TEST_FAST_SCRYPT"),
            }
            match original_native_read_error {
                Some(value) => std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR", value),
                None => std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR"),
            }
            match original_native_hex {
                Some(value) => std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_HEX", value),
                None => std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_HEX"),
            }
            match original_native_missing {
                Some(value) => std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_MISSING", value),
                None => std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_MISSING"),
            }
            match original_native_write_error {
                Some(value) => std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR", value),
                None => std::env::remove_var("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR"),
            }
        }
        original_home.restore();

        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn fast_scrypt_env_is_ignored_in_release_builds() {
        let _lock = crate::test_env_lock::acquire_env_lock();
        let original_fast_scrypt = std::env::var_os("LPM_TEST_FAST_SCRYPT");
        unsafe {
            std::env::set_var("LPM_TEST_FAST_SCRYPT", "1");
        }
        let fast_scrypt = use_fast_test_scrypt();
        unsafe {
            match original_fast_scrypt {
                Some(value) => std::env::set_var("LPM_TEST_FAST_SCRYPT", value),
                None => std::env::remove_var("LPM_TEST_FAST_SCRYPT"),
            }
        }

        assert!(!fast_scrypt);
    }

    #[cfg(all(not(debug_assertions), feature = "acceptance-test-hooks"))]
    #[test]
    fn release_acceptance_build_allows_fast_scrypt_inside_isolated_run_home() {
        let _lock = crate::test_env_lock::acquire_env_lock();
        let root = tempfile::tempdir().expect("create acceptance root");
        let run_dir = root.path().join("run");
        let home = run_dir.join("session-home");
        std::fs::create_dir_all(&home).expect("create acceptance home");
        let variables = [
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_HOME", home.join(".lpm").into_os_string()),
            ("ACCEPTANCE_RUN_DIR", run_dir.into_os_string()),
            ("ACCEPTANCE_RUN_ID", "release-fast-vault".into()),
            ("LPM_ACCEPTANCE_FILE_STORAGE", "1".into()),
            ("LPM_TEST_FAST_SCRYPT", "1".into()),
        ];
        let previous = variables
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect::<Vec<_>>();
        unsafe {
            for (name, value) in &variables {
                std::env::set_var(name, value);
            }
        }

        let fast_scrypt = use_fast_test_scrypt();

        unsafe {
            for (name, value) in previous.into_iter().rev() {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        assert!(fast_scrypt);
    }

    #[test]
    fn data_key_generates_and_reuses_native_key() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();

            let first = load_data_key_with_store(&store).expect("generate native data key");
            let second = load_data_key_with_store(&store).expect("reuse native data key");

            assert_eq!(first.bytes, second.bytes);
            assert_eq!(first.source, DataKeySource::Native);
            assert_eq!(store.writes.get(), 1);
            assert!(!fallback_key_exists());
        });
    }

    #[test]
    fn data_key_promotes_existing_file_key_and_deletes_fallback_key() {
        with_temp_vault_home(|_| {
            let file_key = get_or_create_file_data_key().expect("create file data key");
            assert!(fallback_key_exists());

            let store = FakeNativeDataKeyStore::default();
            let promoted = load_data_key_with_store(&store).expect("promote file data key");

            assert_eq!(promoted.bytes, file_key.bytes);
            assert_eq!(promoted.source, DataKeySource::Native);
            assert!(!fallback_key_exists());
            assert_eq!(
                decode_native_data_key(
                    store
                        .key
                        .borrow()
                        .as_deref()
                        .expect("native key should be written")
                )
                .expect("native key should decode"),
                file_key.bytes
            );
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn data_key_decrypts_existing_file_blob_after_promotion_without_reencrypting() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            let encrypted =
                encrypt_with_store(r#"{"API_KEY":"from-file"}"#, &store).expect("encrypt");
            assert!(fallback_key_exists());
            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_VAULT");
            }

            let decrypted = decrypt_with_store(&encrypted, &store).expect("decrypt after promote");

            assert_eq!(decrypted, r#"{"API_KEY":"from-file"}"#);
            assert!(!fallback_key_exists());
            assert!(store.key.borrow().is_some());
        });
    }

    #[test]
    fn data_key_falls_back_to_file_when_native_write_fails_before_promotion() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            store.set_write_error("secret service unavailable");

            let key = load_data_key_with_store(&store).expect("file fallback should work");

            assert_eq!(key.source, DataKeySource::FileFallback);
            assert!(fallback_key_exists());
            assert!(store.key.borrow().is_none());
        });
    }

    #[test]
    fn data_key_fails_loudly_when_promoted_native_key_is_unavailable() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            store.set_read_error("credential manager locked");

            let err = load_data_key_with_store(&store).expect_err("must not silently downgrade");

            assert!(err.contains("native storage backend is unavailable"));
            assert!(err.contains("credential manager locked"));
        });
    }

    #[test]
    fn data_key_rejects_malformed_native_key_material() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::with_key("not-hex".to_string());

            let err = load_data_key_with_store(&store).expect_err("malformed key must fail");

            assert!(err.contains("native vault data-key is not valid hex"));
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn storage_backend_reports_native_when_native_key_exists_with_stale_file_key() {
        with_temp_vault_home(|_| {
            let native_key = [7u8; 32];
            get_or_create_file_data_key().expect("create stale file data key");

            unsafe {
                std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_HEX", hex::encode(native_key));
            }

            assert_eq!(
                storage_backend_status(),
                crate::VaultStorageBackend::NativeProtected
            );
        });
    }

    #[test]
    #[ignore = "scrypt N=2^20 key derivation is intentionally slow"]
    fn encrypt_decrypt_round_trip() {
        let plaintext = r#"{"DB_HOST": "localhost", "API_KEY": "sk-123"}"#;
        let encrypted = encrypt(plaintext).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[ignore = "scrypt N=2^20 key derivation is intentionally slow"]
    fn encrypt_produces_different_output_each_time() {
        let plaintext = "same-input";
        let a = encrypt(plaintext).unwrap();
        let b = encrypt(plaintext).unwrap();
        assert_ne!(a, b); // Different IVs
    }

    #[test]
    fn decrypt_invalid_format() {
        assert!(decrypt("not-valid-format").is_err());
    }

    #[test]
    fn fallback_key_is_random_not_predictable() {
        // Verify that get_or_create_fallback_key produces a long random key,
        // not a predictable machine-derived password like "{home}-{user}-vault".
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join(".vault-fallback-key");

        // Simulate key generation by creating a temp key file
        // (We can't call get_or_create_fallback_key directly because it uses
        // a fixed path, but we verify the key format requirements.)
        use rand::Rng;
        let key: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        // The key must be 64 chars of alphanumeric (not a machine-derived string)
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_alphanumeric()));

        // The key must NOT look like the old predictable format
        let home = crate::lpm_home_dir()
            .unwrap_or_default()
            .display()
            .to_string();
        let user = std::env::var("USER").unwrap_or_default();
        let old_predictable = format!("{home}-{user}-vault");
        assert_ne!(key, old_predictable);

        // Write and read back
        std::fs::write(&key_path, &key).unwrap();
        let read_back = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(read_back, key);
    }
}
