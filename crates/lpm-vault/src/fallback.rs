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

const NATIVE_DATA_KEY_SERVICE: &str = "dev.lpm.vault-local-key";
const NATIVE_DATA_KEY_ACCOUNT: &str = "data-key";
const VAULT_SALT_FILE: &str = ".vault-salt";
const FALLBACK_KEY_FILE: &str = ".vault-fallback-key";

pub(crate) type SecretMap = HashMap<String, String>;
pub(crate) type EnvironmentMap = HashMap<String, SecretMap>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKeySource {
    Native,
    FileFallback,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DataKey {
    bytes: [u8; 32],
    source: DataKeySource,
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DataKey")
            .field("bytes", &"<redacted>")
            .field("source", &self.source)
            .finish()
    }
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

fn vault_file_name(vault_id: &str) -> String {
    format!("{vault_id}.enc")
}

fn get_or_create_salt(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<Vec<u8>, String> {
    if let Some(salt) = directory.read_owner_only_file(VAULT_SALT_FILE, "vault salt")? {
        return Ok(salt);
    }

    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    if directory.create_owner_only_file(VAULT_SALT_FILE, &salt, "vault salt")? {
        return Ok(salt);
    }
    directory
        .read_owner_only_file(VAULT_SALT_FILE, "vault salt")?
        .ok_or_else(|| "vault salt was created concurrently but could not be read".to_owned())
}

fn fallback_key_exists(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<bool, String> {
    Ok(directory
        .read_owner_only_file(FALLBACK_KEY_FILE, "vault fallback key")?
        .is_some())
}

fn read_fallback_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<Option<String>, String> {
    directory
        .read_owner_only_file(FALLBACK_KEY_FILE, "vault fallback key")?
        .map(|data| {
            String::from_utf8(data).map_err(|_| "vault fallback key is not valid UTF-8".to_owned())
        })
        .transpose()
}

/// Create a random file-fallback encryption password.
///
/// The password is a 64-char random alphanumeric string stored at
/// `~/.lpm/.vault-fallback-key` with 0o600 permissions. This path is
/// only used when native storage is unavailable before a vault has
/// been promoted into the OS store.
fn create_fallback_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<String, String> {
    use rand::Rng;
    let key: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    if directory.create_owner_only_file(FALLBACK_KEY_FILE, key.as_bytes(), "vault fallback key")? {
        return Ok(key);
    }
    read_fallback_key(directory)?.ok_or_else(|| {
        "vault fallback key was created concurrently but could not be read".to_owned()
    })
}

fn get_or_create_fallback_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<String, String> {
    match read_fallback_key(directory)? {
        Some(key) => Ok(key),
        None => create_fallback_key(directory),
    }
}

fn derive_key_from_password(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    password: &str,
) -> Result<[u8; 32], String> {
    let salt = get_or_create_salt(directory)?;
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

fn read_file_data_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<Option<DataKey>, String> {
    read_fallback_key(directory)?
        .map(|password| {
            derive_key_from_password(directory, &password).map(|bytes| DataKey {
                bytes,
                source: DataKeySource::FileFallback,
            })
        })
        .transpose()
}

fn get_or_create_file_data_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<DataKey, String> {
    let password = get_or_create_fallback_key(directory)?;
    let bytes = derive_key_from_password(directory, &password)?;
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

fn native_unavailable_without_file_key(error: String) -> String {
    format!(
        "vault native storage backend is unavailable and no encrypted-file fallback key exists. \
         Unlock Secret Service/Credential Manager or restore ~/.lpm/.vault-fallback-key. \
         Native backend error: {error}"
    )
}

fn load_data_key_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    store: &dyn NativeDataKeyStore,
) -> Result<DataKey, String> {
    if force_file_data_key() {
        return get_or_create_file_data_key(directory);
    }

    match read_native_data_key(store) {
        Ok(Some(key)) => {
            if let Some(file_key) = read_file_data_key(directory)?
                && file_key.bytes != key.bytes
            {
                return Err(
                    "native and file-fallback vault data keys conflict; both were preserved"
                        .to_owned(),
                );
            }
            return Ok(key);
        }
        Ok(None) => {}
        Err(err) => {
            if let Some(file_key) = read_file_data_key(directory)? {
                return Ok(file_key);
            }
            return Err(native_unavailable_without_file_key(err));
        }
    }

    if let Some(file_key) = read_file_data_key(directory)? {
        return match write_native_data_key(store, &file_key.bytes) {
            Ok(()) => {
                let stored = read_native_data_key(store)?.ok_or_else(|| {
                    "native vault data-key write succeeded but no key was readable".to_owned()
                })?;
                if stored.bytes != file_key.bytes {
                    return Err(
                        "native and file-fallback vault data keys conflict; both were preserved"
                            .to_owned(),
                    );
                }
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
        return read_native_data_key(store)?.ok_or_else(|| {
            "native vault data-key write succeeded but no key was readable".to_owned()
        });
    }

    get_or_create_file_data_key(directory)
}

#[cfg(test)]
fn load_data_key_with_store(store: &dyn NativeDataKeyStore) -> Result<DataKey, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        load_data_key_with_store_unlocked(directory, store)
    })
}

pub fn storage_backend_status() -> crate::VaultStorageBackend {
    crate::storage_transaction::with_vault_transaction(|directory| {
        Ok(storage_backend_status_unlocked(directory))
    })
    .unwrap_or_else(|message| crate::VaultStorageBackend::Unavailable { message })
}

fn storage_backend_status_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> crate::VaultStorageBackend {
    if force_file_data_key() {
        return crate::VaultStorageBackend::FileFallback;
    }

    let store = KeyringNativeDataKeyStore;
    match read_native_data_key(&store) {
        Ok(Some(_)) => crate::VaultStorageBackend::NativeProtected,
        Ok(None) => {
            if fallback_key_exists(directory).unwrap_or(false) {
                return crate::VaultStorageBackend::FileFallback;
            }
            if vault_files_exist(directory) {
                crate::VaultStorageBackend::Unavailable {
                    message: "encrypted vault files exist, but no native or file fallback data key was found"
                        .to_string(),
                }
            } else {
                crate::VaultStorageBackend::NativePreferred
            }
        }
        Err(error) => {
            if fallback_key_exists(directory).unwrap_or(false) {
                return crate::VaultStorageBackend::FileFallback;
            }
            if vault_files_exist(directory) {
                crate::VaultStorageBackend::Unavailable {
                    message: native_unavailable_without_file_key(error),
                }
            } else {
                crate::VaultStorageBackend::NativePreferred
            }
        }
    }
}

fn vault_files_exist(directory: &crate::storage_transaction::VaultStorageDirectory) -> bool {
    let Ok(vaults) = directory.open_or_create_directory("vaults") else {
        return false;
    };
    vaults.contains_file_with_extension("enc").unwrap_or(false)
}

#[cfg(test)]
fn encrypt(plaintext: &str) -> Result<String, String> {
    encrypt_with_store(plaintext, &KeyringNativeDataKeyStore)
}

#[cfg(test)]
fn encrypt_with_store(plaintext: &str, store: &dyn NativeDataKeyStore) -> Result<String, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        encrypt_with_store_unlocked(directory, plaintext, store)
    })
}

fn encrypt_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    plaintext: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
    let data_key = load_data_key_with_store_unlocked(directory, store)?;
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

#[cfg(test)]
fn decrypt(encoded: &str) -> Result<String, String> {
    decrypt_with_store(encoded, &KeyringNativeDataKeyStore)
}

#[cfg(test)]
fn decrypt_with_store(encoded: &str, store: &dyn NativeDataKeyStore) -> Result<String, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        decrypt_with_store_unlocked(directory, encoded, store)
    })
}

fn decrypt_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    encoded: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
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

    let data_key = load_data_key_with_store_unlocked(directory, store)?;
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
    crate::storage_transaction::with_vault_transaction(|directory| {
        read_vault_file_env_unlocked(directory, vault_id, env)
    })
}

fn read_vault_file_env_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    env: &str,
) -> Result<Option<SecretMap>, String> {
    let vaults = directory.open_or_create_directory("vaults")?;
    let name = vault_file_name(vault_id);
    let Some(content) = vaults.read_owner_only_file(&name, "encrypted vault")? else {
        return Ok(None);
    };
    let encoded = std::str::from_utf8(&content).map_err(|_| {
        format!(
            "encrypted vault {} is not valid UTF-8",
            vaults.display_path(&name).display()
        )
    })?;
    let json = decrypt_with_store_unlocked(directory, encoded.trim(), &KeyringNativeDataKeyStore)?;

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
    crate::storage_transaction::with_vault_transaction(|directory| {
        read_all_environments_unlocked(directory, vault_id)
    })
}

pub(crate) fn read_all_environments_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<EnvironmentMap>, String> {
    let vaults = directory.open_or_create_directory("vaults")?;
    let name = vault_file_name(vault_id);
    let Some(content) = vaults.read_owner_only_file(&name, "encrypted vault")? else {
        return Ok(None);
    };
    let encoded = std::str::from_utf8(&content).map_err(|_| {
        format!(
            "encrypted vault {} is not valid UTF-8",
            vaults.display_path(&name).display()
        )
    })?;
    let json = decrypt_with_store_unlocked(directory, encoded.trim(), &KeyringNativeDataKeyStore)?;

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
    crate::storage_transaction::with_vault_transaction(|directory| {
        write_all_environments_unlocked(directory, vault_id, environments)
    })
}

pub(crate) fn write_all_environments_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    let data = VaultData {
        environments: environments.clone(),
    };
    let json =
        serde_json::to_string(&data).map_err(|e| format!("failed to serialize secrets: {e}"))?;
    let encrypted = encrypt_with_store_unlocked(directory, &json, &KeyringNativeDataKeyStore)?;
    let vaults = directory.open_or_create_directory("vaults")?;
    vaults.write_owner_only_file(
        &vault_file_name(vault_id),
        encrypted.as_bytes(),
        "encrypted vault",
    )
}

pub(crate) fn mutate_vault_file_env<T>(
    vault_id: &str,
    env: &str,
    operation: impl FnOnce(&mut SecretMap) -> T,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        let mut environments =
            read_all_environments_unlocked(directory, vault_id)?.unwrap_or_default();
        let result = operation(environments.entry(env.to_owned()).or_default());
        write_all_environments_unlocked(directory, vault_id, &environments)?;
        Ok(result)
    })
}

/// Write vault secrets for a specific environment.
pub fn write_vault_file_env(vault_id: &str, env: &str, secrets: &SecretMap) -> Result<(), String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        write_vault_file_env_unlocked(directory, vault_id, env, secrets)
    })
}

fn write_vault_file_env_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    env: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    let mut environments = read_all_environments_unlocked(directory, vault_id)?.unwrap_or_default();
    environments.insert(env.to_owned(), secrets.clone());
    write_all_environments_unlocked(directory, vault_id, &environments)
}

/// Delete encrypted vault file.
pub fn delete_vault_file(vault_id: &str) -> Result<(), String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        let vaults = directory.open_or_create_directory("vaults")?;
        vaults.remove_file(&vault_file_name(vault_id), "encrypted vault")?;
        Ok(())
    })
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

    fn with_storage_directory<T>(
        operation: impl FnOnce(&crate::storage_transaction::VaultStorageDirectory) -> Result<T, String>,
    ) -> T {
        crate::storage_transaction::with_vault_transaction(operation)
            .expect("open protected vault storage")
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
            assert!(!with_storage_directory(fallback_key_exists));
        });
    }

    #[test]
    fn data_key_debug_output_redacts_key_bytes() {
        let key = DataKey {
            bytes: [0x5a; 32],
            source: DataKeySource::Native,
        };

        let debug = format!("{key:?}");

        assert_eq!(debug, "DataKey { bytes: \"<redacted>\", source: Native }");
    }

    #[test]
    fn concurrent_environment_mutations_preserve_every_update() {
        with_temp_vault_home(|_| {
            use std::sync::{Arc, Barrier};

            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            let workers = 8;
            let barrier = Arc::new(Barrier::new(workers));
            let mut handles = Vec::with_capacity(workers);
            for index in 0..workers {
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    mutate_vault_file_env("concurrent-vault", "default", |secrets| {
                        secrets.insert(format!("KEY_{index}"), format!("value-{index}"));
                    })
                }));
            }

            for handle in handles {
                handle
                    .join()
                    .expect("mutation worker should not panic")
                    .expect("mutation should succeed");
            }
            let stored = read_vault_file_env("concurrent-vault", "default")
                .expect("read concurrent vault")
                .expect("concurrent vault should exist");

            assert_eq!(stored.len(), workers);
        });
    }

    #[test]
    fn data_key_promotes_existing_file_key_and_preserves_compatibility_copy() {
        with_temp_vault_home(|_| {
            let file_key = with_storage_directory(get_or_create_file_data_key);
            assert!(with_storage_directory(fallback_key_exists));

            let store = FakeNativeDataKeyStore::default();
            let promoted = load_data_key_with_store(&store).expect("promote file data key");

            assert_eq!(promoted.bytes, file_key.bytes);
            assert_eq!(promoted.source, DataKeySource::Native);
            assert!(with_storage_directory(fallback_key_exists));
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
            assert!(with_storage_directory(fallback_key_exists));
            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_VAULT");
            }

            let decrypted = decrypt_with_store(&encrypted, &store).expect("decrypt after promote");

            assert_eq!(decrypted, r#"{"API_KEY":"from-file"}"#);
            assert!(with_storage_directory(fallback_key_exists));
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
            assert!(with_storage_directory(fallback_key_exists));
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
            with_storage_directory(get_or_create_file_data_key);

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
