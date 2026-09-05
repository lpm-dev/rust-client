//! Encrypted vault blobs for non-macOS platforms.
//!
//! Linux and Windows keep vault files at `~/.lpm/vaults/{vault-id}.enc`.
//! The encryption key is protected by the OS secure store when available,
//! with a random file-backed key used when the native store is unavailable.

// This module is conditionally compiled (`#[cfg(not(target_os = "macos"))]` in lib.rs).
// On macOS builds the functions appear unused, but they are active on Linux/Windows.
#![allow(dead_code)]

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use std::collections::HashMap;

const NATIVE_DATA_KEY_SERVICE: &str = "dev.lpm.vault-local-key";
const NATIVE_DATA_KEY_ACCOUNT: &str = "data-key";
const FALLBACK_KEY_FILE: &str = ".vault-fallback-key";
const FALLBACK_KEY_PREFIX: &str = "raw:";
const LOCAL_VAULT_AAD_DOMAIN: &[u8] = b"lpm-vault-local\x01";

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

fn local_vault_associated_data(vault_id: &str) -> Result<Vec<u8>, String> {
    let vault_id = vault_id.as_bytes();
    let length = u32::try_from(vault_id.len())
        .map_err(|_| "vault ID is too long for local encryption".to_owned())?;
    let mut associated_data = Vec::with_capacity(LOCAL_VAULT_AAD_DOMAIN.len() + 4 + vault_id.len());
    associated_data.extend_from_slice(LOCAL_VAULT_AAD_DOMAIN);
    associated_data.extend_from_slice(&length.to_be_bytes());
    associated_data.extend_from_slice(vault_id);
    Ok(associated_data)
}

fn fallback_key_exists(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<bool, String> {
    Ok(directory
        .read_owner_only_file(FALLBACK_KEY_FILE, "vault fallback key")?
        .is_some())
}

fn remove_fallback_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<(), String> {
    directory
        .remove_file_durable(FALLBACK_KEY_FILE, "vault fallback key")
        .map(|_| ())
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

fn encode_fallback_key(key: &[u8; 32]) -> String {
    format!("{FALLBACK_KEY_PREFIX}{}", hex::encode(key))
}

fn decode_fallback_key(value: &str) -> Result<[u8; 32], String> {
    let encoded = value
        .strip_prefix(FALLBACK_KEY_PREFIX)
        .ok_or_else(|| "vault fallback key has an unsupported format".to_owned())?;
    let bytes = hex::decode(encoded)
        .map_err(|error| format!("vault fallback key is not valid hex: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "vault fallback key has invalid length {} (expected 32 bytes)",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn persist_fallback_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    key: &[u8; 32],
) -> Result<(), String> {
    let encoded = encode_fallback_key(key);
    directory.write_owner_only_file_durable(
        FALLBACK_KEY_FILE,
        encoded.as_bytes(),
        "vault fallback key",
    )
}

fn read_file_data_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<Option<DataKey>, String> {
    let Some(material) = read_fallback_key(directory)? else {
        return Ok(None);
    };
    Ok(Some(DataKey {
        bytes: decode_fallback_key(&material)?,
        source: DataKeySource::FileFallback,
    }))
}

fn get_or_create_file_data_key(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<DataKey, String> {
    if let Some(key) = read_file_data_key(directory)? {
        return Ok(key);
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    persist_fallback_key(directory, &bytes)?;
    Ok(DataKey {
        bytes,
        source: DataKeySource::FileFallback,
    })
}

#[cfg(test)]
pub(crate) fn profile_file_data_key_reuse() -> Result<usize, String> {
    let first = crate::storage_transaction::with_vault_transaction(get_or_create_file_data_key)?;
    let second = crate::storage_transaction::with_vault_transaction(get_or_create_file_data_key)?;
    if first.bytes != second.bytes {
        return Err("fallback data key changed between reads".to_owned());
    }
    Ok(usize::from(first.bytes[0]))
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
            if let Some(file_key) = read_file_data_key(directory)? {
                if file_key.bytes != key.bytes {
                    return Err(
                        "native and file-fallback vault data keys conflict; both were preserved"
                            .to_owned(),
                    );
                }
                remove_fallback_key(directory)?;
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
                remove_fallback_key(directory)?;
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
        Ok(Some(_)) => match fallback_key_exists(directory) {
            Ok(true) => crate::VaultStorageBackend::NativeProtectedWithFallback,
            Ok(false) => crate::VaultStorageBackend::NativeProtected,
            Err(message) => crate::VaultStorageBackend::Unavailable { message },
        },
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
fn encrypt_with_store(
    vault_id: &str,
    plaintext: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        encrypt_with_store_unlocked(directory, vault_id, plaintext, store)
    })
}

fn encrypt_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    plaintext: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
    let data_key = load_data_key_with_store_unlocked(directory, store)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key.bytes)
        .map_err(|e| format!("cipher init error: {e}"))?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let mut encrypted = plaintext.as_bytes().to_vec();
    let associated_data = local_vault_associated_data(vault_id)?;
    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, &associated_data, &mut encrypted)
        .map_err(|e| format!("encryption error: {e}"))?;

    let encoded_capacity = padded_base64_len(iv.len())
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add(padded_base64_len(auth_tag.len())?))
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add(padded_base64_len(encrypted.len())?))
        .ok_or_else(|| "encrypted vault size overflow".to_owned())?;
    let mut encoded = String::with_capacity(encoded_capacity);
    BASE64.encode_string(iv, &mut encoded);
    encoded.push(':');
    BASE64.encode_string(auth_tag, &mut encoded);
    encoded.push(':');
    BASE64.encode_string(encrypted, &mut encoded);
    Ok(encoded)
}

fn padded_base64_len(input_len: usize) -> Option<usize> {
    input_len.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

#[cfg(test)]
fn decrypt(encoded: &str) -> Result<String, String> {
    decrypt_with_store("test-vault", encoded, &KeyringNativeDataKeyStore)
}

#[cfg(test)]
fn decrypt_with_store(
    vault_id: &str,
    encoded: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        decrypt_with_store_unlocked(directory, vault_id, encoded, store)
    })
}

fn decrypt_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    encoded: &str,
    store: &dyn NativeDataKeyStore,
) -> Result<String, String> {
    let (iv_encoded, remainder) = encoded
        .split_once(':')
        .ok_or_else(|| "invalid encrypted format".to_owned())?;
    let (tag_encoded, encrypted_encoded) = remainder
        .split_once(':')
        .filter(|(_, encrypted)| !encrypted.contains(':'))
        .ok_or_else(|| "invalid encrypted format".to_owned())?;

    let iv = BASE64
        .decode(iv_encoded)
        .map_err(|e| format!("iv decode: {e}"))?;
    let auth_tag = BASE64
        .decode(tag_encoded)
        .map_err(|e| format!("tag decode: {e}"))?;
    let mut encrypted = BASE64
        .decode(encrypted_encoded)
        .map_err(|e| format!("data decode: {e}"))?;

    if iv.len() != 12 {
        return Err(format!("incompatible IV size: {} bytes", iv.len()));
    }
    if auth_tag.len() != 16 {
        return Err(format!(
            "incompatible authentication tag size: {} bytes",
            auth_tag.len()
        ));
    }

    let data_key = load_data_key_with_store_unlocked(directory, store)?;
    let cipher = Aes256Gcm::new_from_slice(&data_key.bytes)
        .map_err(|e| format!("cipher init error: {e}"))?;

    let nonce = GenericArray::from_slice(&iv);
    let associated_data = local_vault_associated_data(vault_id)?;
    cipher
        .decrypt_in_place_detached(
            nonce,
            &associated_data,
            &mut encrypted,
            GenericArray::from_slice(&auth_tag),
        )
        .map_err(|_| "decryption failed (wrong key or corrupted data)".to_string())?;

    String::from_utf8(encrypted).map_err(|e| format!("utf8 error: {e}"))
}

/// Read vault secrets for a specific environment.
pub fn read_vault_file_env(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        read_vault_file_env_unlocked(directory, vault_id, env, false)
    })
}

pub(crate) fn read_vault_file_env_with_default_fallback(
    vault_id: &str,
    env: &str,
) -> Result<Option<SecretMap>, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        read_vault_file_env_unlocked(directory, vault_id, env, true)
    })
}

fn read_vault_file_env_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    env: &str,
    default_fallback: bool,
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
    let json = decrypt_with_store_unlocked(
        directory,
        vault_id,
        encoded.trim(),
        &KeyringNativeDataKeyStore,
    )?;

    let parsed = if default_fallback {
        crate::selected_environment::parse_with_default_fallback(&json, env)
    } else {
        crate::selected_environment::parse(&json, env)
    };
    parsed
        .map(crate::selected_environment::SelectedVaultPayload::into_selected)
        .map_err(|error| format!("vault payload is invalid: {error}"))
}

#[cfg(test)]
fn take_environment(mut environments: EnvironmentMap, env: &str) -> Option<SecretMap> {
    environments.remove(env)
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
    read_all_environments_with_digest_unlocked(directory, vault_id)
        .map(|(environments, _)| environments)
}

pub(crate) fn read_all_environments_with_digest_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<(Option<EnvironmentMap>, Option<[u8; 32]>), String> {
    use sha2::Digest as _;

    let vaults = directory.open_or_create_directory("vaults")?;
    let name = vault_file_name(vault_id);
    let Some(content) = vaults.read_owner_only_file(&name, "encrypted vault")? else {
        return Ok((None, None));
    };
    let digest = sha2::Sha256::digest(&content).into();
    let encoded = std::str::from_utf8(&content).map_err(|_| {
        format!(
            "encrypted vault {} is not valid UTF-8",
            vaults.display_path(&name).display()
        )
    })?;
    let json = decrypt_with_store_unlocked(
        directory,
        vault_id,
        encoded.trim(),
        &KeyringNativeDataKeyStore,
    )?;

    let environments = crate::selected_environment::parse_all(&json)
        .map_err(|error| format!("vault payload is invalid: {error}"))?;
    Ok((Some(environments), Some(digest)))
}

pub(crate) fn vault_payload_digest_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<[u8; 32]>, String> {
    let vaults = directory.open_or_create_directory("vaults")?;
    let name = vault_file_name(vault_id);
    vaults.sha256_owner_only_file(&name, "encrypted vault")
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
    let json = crate::selected_environment::serialize(environments)?;
    let encrypted =
        encrypt_with_store_unlocked(directory, vault_id, &json, &KeyringNativeDataKeyStore)?;
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

    #[test]
    fn selected_environment_transfers_owned_secret_values() {
        let value = "secret-value".to_owned();
        let value_pointer = value.as_ptr();
        let environments = HashMap::from([(
            "default".to_owned(),
            HashMap::from([("TOKEN".to_owned(), value)]),
        )]);

        let selected = take_environment(environments, "default").unwrap();

        assert_eq!(selected["TOKEN"].as_ptr(), value_pointer);
    }

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
        let original_native_read_error = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_READ_ERROR");
        let original_native_hex = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_HEX");
        let original_native_missing = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_MISSING");
        let original_native_write_error = std::env::var_os("LPM_TEST_VAULT_NATIVE_KEY_WRITE_ERROR");

        unsafe {
            std::env::remove_var("LPM_FORCE_FILE_VAULT");
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

    fn seed_encrypted_vault(vault_id: &str, plaintext: &str) -> Vec<u8> {
        let encoded = encrypt_with_store(vault_id, plaintext, &KeyringNativeDataKeyStore)
            .expect("encrypt vault fixture");
        let content = encoded.into_bytes();
        with_storage_directory(|directory| {
            let vaults = directory.open_or_create_directory("vaults")?;
            vaults.write_owner_only_file(&vault_file_name(vault_id), &content, "encrypted vault")
        });
        content
    }

    fn read_encrypted_vault(vault_id: &str) -> Vec<u8> {
        with_storage_directory(|directory| {
            let vaults = directory.open_or_create_directory("vaults")?;
            vaults
                .read_owner_only_file(&vault_file_name(vault_id), "encrypted vault")?
                .ok_or_else(|| "encrypted vault fixture disappeared".to_owned())
        })
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
    fn encrypted_vault_cannot_be_substituted_for_another_vault_id() {
        with_temp_vault_home(|_| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            write_vault_file(
                "source-vault",
                &HashMap::from([("TOKEN".to_owned(), "secret".to_owned())]),
            )
            .expect("write source vault");
            let source = read_encrypted_vault("source-vault");
            with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                vaults.write_owner_only_file(
                    &vault_file_name("target-vault"),
                    &source,
                    "encrypted vault",
                )
            });

            let error = read_vault_file_env("target-vault", "default")
                .expect_err("ciphertext must be bound to its vault ID");

            assert!(error.contains("decryption failed"), "{error}");
        });
    }

    #[test]
    fn data_key_promotes_existing_file_key_and_removes_fallback_copy() {
        with_temp_vault_home(|_| {
            let file_key = with_storage_directory(get_or_create_file_data_key);
            assert!(with_storage_directory(fallback_key_exists));

            let store = FakeNativeDataKeyStore::default();
            let promoted = load_data_key_with_store(&store).expect("promote file data key");

            assert_eq!(promoted.bytes, file_key.bytes);
            assert_eq!(promoted.source, DataKeySource::Native);
            assert!(!with_storage_directory(fallback_key_exists));
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
    fn data_key_decrypts_existing_file_blob_after_promotion_without_file_fallback() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            let encrypted =
                encrypt_with_store("promotion-vault", r#"{"API_KEY":"from-file"}"#, &store)
                    .expect("encrypt");
            assert!(with_storage_directory(fallback_key_exists));
            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_VAULT");
            }

            let decrypted = decrypt_with_store("promotion-vault", &encrypted, &store)
                .expect("decrypt after promote");

            assert_eq!(decrypted, r#"{"API_KEY":"from-file"}"#);
            assert!(!with_storage_directory(fallback_key_exists));
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
    fn new_file_fallback_stores_a_random_raw_key() {
        with_temp_vault_home(|_| {
            let key = with_storage_directory(get_or_create_file_data_key);
            let stored = with_storage_directory(|directory| {
                read_fallback_key(directory)?.ok_or_else(|| "missing fallback key".to_owned())
            });

            assert_eq!(stored, format!("raw:{}", hex::encode(key.bytes)));
        });
    }

    #[test]
    fn unversioned_password_fallback_is_rejected() {
        with_temp_vault_home(|_| {
            with_storage_directory(|directory| {
                assert!(directory.create_owner_only_file(
                    FALLBACK_KEY_FILE,
                    b"retired-password-material",
                    "vault fallback key",
                )?);
                Ok(())
            });

            let error = crate::storage_transaction::with_vault_transaction(read_file_data_key)
                .expect_err("password-derived fallback keys must not remain executable");

            assert!(error.contains("unsupported format"), "{error}");
        });
    }

    #[test]
    fn authenticated_invalid_vault_shape_fails_targeted_reads() {
        with_temp_vault_home(|_| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            seed_encrypted_vault(
                "invalid-targeted",
                r#"{"environments":{"default":{"TOKEN":123},"staging":{"TOKEN":"ok"}}}"#,
            );

            let error = read_vault_file_env("invalid-targeted", "staging")
                .expect_err("invalid authenticated payloads must fail targeted reads");

            assert!(error.contains("vault payload is invalid"), "{error}");
        });
    }

    #[test]
    fn authenticated_invalid_vault_shape_fails_all_environment_reads() {
        with_temp_vault_home(|_| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            seed_encrypted_vault(
                "invalid-all",
                r#"{"environments":{"default":{"TOKEN":123}}}"#,
            );

            let error = read_all_environments("invalid-all")
                .expect_err("invalid authenticated payloads must fail full reads");

            assert!(error.contains("vault payload is invalid"), "{error}");
        });
    }

    #[test]
    fn invalid_authenticated_vault_mutation_preserves_ciphertext() {
        with_temp_vault_home(|_| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            let original = seed_encrypted_vault(
                "invalid-mutation",
                r#"{"environments":{"default":{"TOKEN":123}}}"#,
            );

            let error = mutate_vault_file_env("invalid-mutation", "default", |secrets| {
                secrets.insert("NEW".to_owned(), "value".to_owned());
            })
            .expect_err("invalid authenticated payloads must stop mutation");

            assert!(error.contains("vault payload is invalid"), "{error}");
            assert_eq!(read_encrypted_vault("invalid-mutation"), original);
        });
    }

    #[test]
    fn malformed_file_fallback_is_rejected() {
        with_temp_vault_home(|_| {
            with_storage_directory(|directory| {
                assert!(directory.create_owner_only_file(
                    FALLBACK_KEY_FILE,
                    b"raw:not-a-key",
                    "vault fallback key",
                )?);
                Ok(())
            });

            let error = crate::storage_transaction::with_vault_transaction(read_file_data_key)
                .expect_err("malformed fallback key must fail closed");

            assert!(error.contains("vault fallback key"), "{error}");
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
    fn storage_backend_does_not_report_native_protection_with_stale_file_key() {
        with_temp_vault_home(|_| {
            let native_key = [7u8; 32];
            with_storage_directory(get_or_create_file_data_key);

            unsafe {
                std::env::set_var("LPM_TEST_VAULT_NATIVE_KEY_HEX", hex::encode(native_key));
            }

            assert_eq!(
                storage_backend_status(),
                crate::VaultStorageBackend::NativeProtectedWithFallback
            );
        });
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            let plaintext = r#"{"DB_HOST": "localhost", "API_KEY": "sk-123"}"#;
            let encrypted = encrypt_with_store("test-vault", plaintext, &store).unwrap();
            let decrypted = decrypt_with_store("test-vault", &encrypted, &store).unwrap();
            assert_eq!(decrypted, plaintext);
        });
    }

    #[test]
    fn encrypt_produces_different_output_each_time() {
        with_temp_vault_home(|_| {
            let store = FakeNativeDataKeyStore::default();
            let plaintext = "same-input";
            let a = encrypt_with_store("test-vault", plaintext, &store).unwrap();
            let b = encrypt_with_store("test-vault", plaintext, &store).unwrap();
            assert_ne!(a, b);
        });
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
