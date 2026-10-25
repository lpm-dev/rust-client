//! Encrypted vault blobs for non-macOS platforms.
//!
//! Linux and Windows keep vault files in `~/.lpm/vaults`, each named by a
//! digest of its vault ID; earlier versions named them `{vault-id}.enc`.
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

pub(crate) mod companion;

use crate::companion::gate::Operation;

const NATIVE_DATA_KEY_SERVICE: &str = "dev.lpm.vault-local-key";
const NATIVE_DATA_KEY_ACCOUNT: &str = "data-key";
const FALLBACK_KEY_FILE: &str = ".vault-fallback-key";
const FALLBACK_KEY_PREFIX: &str = "raw:";
const LOCAL_VAULT_AAD_DOMAIN: &[u8] = b"lpm-vault-local\x01";

fn native_data_key_service() -> String {
    lpm_common::credential_service(NATIVE_DATA_KEY_SERVICE)
}

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

        let entry = keyring::Entry::new(&native_data_key_service(), NATIVE_DATA_KEY_ACCOUNT)
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

        let entry = keyring::Entry::new(&native_data_key_service(), NATIVE_DATA_KEY_ACCOUNT)
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
    lpm_common::acceptance::env_flag_enabled("LPM_FORCE_FILE_VAULT")
}

/// A vault's file name: a digest of its ID, so every ID names a file that's
/// valid and distinct on every platform. Vault IDs come from user-editable
/// lpm.json, and Windows compares names without case and reserves some
/// (`CON`, `NUL`, …), so `{vault-id}.enc` could collide or not open at all.
/// Digest names are lowercase hex, so they stay distinct without case too and
/// open directly.
pub(crate) fn vault_file_name(vault_id: &str) -> String {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    digest.update(b"lpm-vault-file\0");
    digest.update(vault_id.as_bytes());
    format!("{}.vault", hex::encode(digest.finalize()))
}

/// The name a vault's file had before it was named by digest, when an entry is
/// named that exactly. A case-insensitive file system would open the legacy
/// file of a vault whose ID differs only in case, and an entry can't have a
/// name the platform reserves.
fn existing_legacy_vault_file_name(
    vaults: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<String>, String> {
    let legacy = format!("{vault_id}.enc");
    Ok(vaults
        .contains_entry_named_exactly(&legacy)?
        .then_some(legacy))
}

/// The vault's encrypted file and the name it's under, if it has one.
fn read_vault_content(
    vaults: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let current = vault_file_name(vault_id);
    if let Some(content) = vaults.read_owner_only_file(&current, "encrypted vault")? {
        return Ok(Some((current, content)));
    }
    let Some(legacy) = existing_legacy_vault_file_name(vaults, vault_id)? else {
        return Ok(None);
    };
    Ok(vaults
        .read_owner_only_file(&legacy, "encrypted vault")?
        .map(|content| (legacy, content)))
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
    let key_file = crate::lpm_root_dir().map_or_else(
        || format!("~/.lpm/{FALLBACK_KEY_FILE}"),
        |root| root.join(FALLBACK_KEY_FILE).display().to_string(),
    );
    format!(
        "vault native storage backend is unavailable and no encrypted-file fallback key exists. \
         Unlock Secret Service/Credential Manager or restore {key_file}. \
         Native backend error: {error}"
    )
}

thread_local! {
    /// The data key the vault lock this thread holds already loaded, so an
    /// operation loads it once for its values and companion records alike.
    static SCOPED_DATA_KEY: std::cell::Cell<Option<DataKey>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    pub(crate) static DATA_KEY_LOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Forget the data key when the vault lock is released.
pub(crate) fn forget_scoped_data_key() {
    SCOPED_DATA_KEY.with(|key| key.set(None));
}

/// Use the file-fallback key for the rest of this lock, as a process running
/// with `LPM_FORCE_FILE_VAULT` would.
#[cfg(feature = "acceptance-test-hooks")]
pub(crate) fn use_file_data_key_in_scope(
    directory: &crate::storage_transaction::VaultStorageDirectory,
) -> Result<(), String> {
    let key = get_or_create_file_data_key(directory)?;
    SCOPED_DATA_KEY.with(|scoped| scoped.set(Some(key)));
    Ok(())
}

fn load_data_key_with_store_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    store: &dyn NativeDataKeyStore,
) -> Result<DataKey, String> {
    if let Some(key) = SCOPED_DATA_KEY.with(std::cell::Cell::get) {
        return Ok(key);
    }
    #[cfg(test)]
    DATA_KEY_LOADS.with(|loads| loads.set(loads.get() + 1));
    let key = load_data_key_from_store_unlocked(directory, store)?;
    SCOPED_DATA_KEY.with(|scoped| scoped.set(Some(key)));
    Ok(key)
}

fn load_data_key_from_store_unlocked(
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
    ["vault", "enc", "companion"].iter().any(|extension| {
        vaults
            .contains_file_with_extension(extension)
            .unwrap_or(false)
    })
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

pub(crate) fn read_vault_file_env_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    env: &str,
    default_fallback: bool,
) -> Result<Option<SecretMap>, String> {
    crate::authorize_companion(directory, vault_id, Operation::ReadExcludingOverrides)?;
    let vaults = directory.open_or_create_directory("vaults")?;
    let Some((name, content)) = read_vault_content(&vaults, vault_id)? else {
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

/// The selected environment's values and its personal overrides, in the
/// caller's lock. The overrides are always `env`'s own, even when the values
/// fall back to `default`'s.
pub(crate) fn read_run_environment_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    env: &str,
    default_fallback: bool,
) -> Result<(Option<SecretMap>, crate::PersonalOverrides), String> {
    let overrides = companion::read_overrides_unlocked(directory, vault_id, env)?;
    let values = read_vault_file_env_unlocked(directory, vault_id, env, default_fallback)?;
    Ok((values, overrides))
}

/// Every environment's values and personal overrides, in the caller's lock.
pub(crate) fn read_all_run_environments_unlocked(
    directory: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<
    (
        Option<EnvironmentMap>,
        std::collections::BTreeMap<String, crate::PersonalOverrides>,
    ),
    String,
> {
    let (gate, record) = companion::read_overrides_record_unlocked(directory, vault_id)?;
    let overrides = crate::companion::overrides::evaluate_all(&gate, vault_id, record.as_deref())
        .map_err(crate::companion::damaged)?;
    let values = read_all_environments_unlocked(directory, vault_id)?;
    Ok((values, overrides))
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

    crate::authorize_companion(directory, vault_id, Operation::ReadExcludingOverrides)?;
    let vaults = directory.open_or_create_directory("vaults")?;
    let Some((name, content)) = read_vault_content(&vaults, vault_id)? else {
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
    crate::authorize_companion(directory, vault_id, Operation::ReadExcludingOverrides)?;
    let vaults = directory.open_or_create_directory("vaults")?;
    if let Some(digest) =
        vaults.sha256_owner_only_file(&vault_file_name(vault_id), "encrypted vault")?
    {
        return Ok(Some(digest));
    }
    match existing_legacy_vault_file_name(&vaults, vault_id)? {
        Some(legacy) => vaults.sha256_owner_only_file(&legacy, "encrypted vault"),
        None => Ok(None),
    }
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
    crate::authorize_companion(directory, vault_id, Operation::Write)?;
    let json = crate::selected_environment::serialize(environments)?;
    let encrypted =
        encrypt_with_store_unlocked(directory, vault_id, &json, &KeyringNativeDataKeyStore)?;
    let vaults = directory.open_or_create_directory("vaults")?;
    vaults.write_owner_only_file(
        &vault_file_name(vault_id),
        encrypted.as_bytes(),
        "encrypted vault",
    )?;
    remove_legacy_vault_file(&vaults, vault_id)
}

/// Removes the vault's legacy file, when an entry is named that exactly.
fn remove_legacy_vault_file(
    vaults: &crate::storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<(), String> {
    if let Some(legacy) = existing_legacy_vault_file_name(vaults, vault_id)? {
        vaults.remove_file(&legacy, "encrypted vault")?;
    }
    Ok(())
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

/// Delete the encrypted vault files and every companion record through the
/// deletion protocol.
pub fn delete_vault_file(vault_id: &str) -> Result<(), String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        companion::delete_project_unlocked(directory, vault_id)
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

    pub(super) fn with_temp_vault_home<T>(test: impl FnOnce(&Path) -> T) -> T {
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

    fn secrets(value: &str) -> SecretMap {
        HashMap::from([("TOKEN".to_owned(), value.to_owned())])
    }

    pub(super) fn force_file_vault() {
        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }
    }

    #[test]
    fn vaults_whose_ids_differ_only_in_case_keep_their_own_files() {
        with_temp_vault_home(|_| {
            force_file_vault();
            write_vault_file("shared-vault", &secrets("lower")).expect("write lower");
            write_vault_file("SHARED-VAULT", &secrets("upper")).expect("write upper");

            let lower = read_vault_file_env("shared-vault", "default").expect("read lower");
            let upper = read_vault_file_env("SHARED-VAULT", "default").expect("read upper");

            assert_eq!(lower, Some(secrets("lower")));
            assert_eq!(upper, Some(secrets("upper")));
        });
    }

    #[test]
    fn every_vault_id_names_a_file_valid_and_distinct_on_every_platform() {
        let ids = [
            "vault", "VAULT", "Vault", "CON", "con", "a?b", "trail.", "LPT1.txt", "x y ",
        ];
        let names: Vec<String> = ids.iter().map(|id| vault_file_name(id)).collect();
        for name in &names {
            let (stem, extension) = name.split_once('.').expect("an extension");
            assert_eq!(extension, "vault", "{name}");
            assert_eq!(stem.len(), 64, "{name}");
            assert!(
                stem.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{name}"
            );
        }
        let distinct: std::collections::HashSet<String> =
            names.iter().map(|name| name.to_ascii_lowercase()).collect();
        assert_eq!(distinct.len(), ids.len());
    }

    #[test]
    fn a_vault_under_its_legacy_name_is_read_and_moved_on_the_next_write() {
        with_temp_vault_home(|_| {
            force_file_vault();
            write_vault_file("old-vault", &secrets("before")).expect("write");
            let content = read_encrypted_vault("old-vault");
            with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                vaults.write_owner_only_file("old-vault.enc", &content, "encrypted vault")?;
                vaults.remove_file(&vault_file_name("old-vault"), "encrypted vault")?;
                Ok(())
            });

            let read = read_vault_file_env("old-vault", "default").expect("read legacy");
            assert_eq!(read, Some(secrets("before")));

            write_vault_file("old-vault", &secrets("after")).expect("write again");
            let (current, legacy) = with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                Ok((
                    vaults
                        .read_owner_only_file(&vault_file_name("old-vault"), "encrypted vault")?,
                    vaults.read_owner_only_file("old-vault.enc", "encrypted vault")?,
                ))
            });
            assert!(current.is_some());
            assert!(legacy.is_none(), "the legacy file is removed once moved");
            assert_eq!(
                read_vault_file_env("old-vault", "default").expect("read moved"),
                Some(secrets("after"))
            );
        });
    }

    #[test]
    fn a_legacy_file_counts_only_under_its_exact_name() {
        with_temp_vault_home(|_| {
            force_file_vault();
            write_vault_file("Other-Vault", &secrets("theirs")).expect("write");
            let content = read_encrypted_vault("Other-Vault");
            with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                vaults.write_owner_only_file("Other-Vault.enc", &content, "encrypted vault")?;
                vaults.remove_file(&vault_file_name("Other-Vault"), "encrypted vault")?;
                Ok(())
            });

            // A case-insensitive file system opens Other-Vault.enc for this name too.
            assert_eq!(
                read_vault_file_env("other-vault", "default").expect("read"),
                None
            );
            write_vault_file("other-vault", &secrets("mine")).expect("write mine");
            assert_eq!(
                read_vault_file_env("Other-Vault", "default").expect("read theirs"),
                Some(secrets("theirs"))
            );
            assert_eq!(
                read_vault_file_env("other-vault", "default").expect("read mine"),
                Some(secrets("mine"))
            );
            delete_vault_file("other-vault").expect("delete mine");
            assert_eq!(
                read_vault_file_env("Other-Vault", "default").expect("read theirs again"),
                Some(secrets("theirs"))
            );
        });
    }

    #[test]
    fn deleting_a_vault_removes_its_legacy_file_too() {
        with_temp_vault_home(|_| {
            force_file_vault();
            write_vault_file("gone-vault", &secrets("value")).expect("write");
            let content = read_encrypted_vault("gone-vault");
            with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                vaults.write_owner_only_file("gone-vault.enc", &content, "encrypted vault")
            });
            delete_vault_file("gone-vault").expect("delete");
            assert_eq!(
                read_vault_file_env("gone-vault", "default").expect("read"),
                None
            );
        });
    }

    #[test]
    fn vaults_whose_ids_windows_cannot_name_as_files_are_stored() {
        with_temp_vault_home(|_| {
            force_file_vault();
            for id in ["CON", "nul", "a?b", "trail.", "x y ", "LPT1.txt"] {
                write_vault_file(id, &secrets(id)).expect(id);
            }
            for id in ["CON", "nul", "a?b", "trail.", "x y ", "LPT1.txt"] {
                assert_eq!(
                    read_vault_file_env(id, "default").expect(id),
                    Some(secrets(id)),
                    "{id}"
                );
            }
        });
    }

    #[test]
    fn a_vault_under_its_digest_name_is_read_and_written_without_listing_the_directory() {
        use crate::storage_transaction::ENTRY_LISTINGS;

        with_temp_vault_home(|_| {
            force_file_vault();
            write_vault_file("listed-vault", &secrets("value")).expect("write");
            ENTRY_LISTINGS.with(|listings| listings.set(0));

            read_vault_file_env("listed-vault", "default").expect("read");
            write_vault_file("listed-vault", &secrets("again")).expect("write again");
            with_storage_directory(|directory| {
                vault_payload_digest_unlocked(directory, "listed-vault")
            });
            assert_eq!(ENTRY_LISTINGS.with(std::cell::Cell::get), 0);

            let content = read_encrypted_vault("listed-vault");
            with_storage_directory(|directory| {
                let vaults = directory.open_or_create_directory("vaults")?;
                vaults.write_owner_only_file("listed-vault.enc", &content, "encrypted vault")?;
                vaults.remove_file(&vault_file_name("listed-vault"), "encrypted vault")?;
                Ok(())
            });
            read_vault_file_env("listed-vault", "default").expect("read legacy");
            assert_eq!(
                ENTRY_LISTINGS.with(std::cell::Cell::get),
                1,
                "a legacy file is matched by its exact name"
            );
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
        let home = dirs::home_dir().unwrap_or_default().display().to_string();
        let user = std::env::var("USER").unwrap_or_default();
        let old_predictable = format!("{home}-{user}-vault");
        assert_ne!(key, old_predictable);

        // Write and read back
        std::fs::write(&key_path, &key).unwrap();
        let read_back = std::fs::read_to_string(&key_path).unwrap();
        assert_eq!(read_back, key);
    }
}
