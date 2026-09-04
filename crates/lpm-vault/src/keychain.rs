//! macOS Keychain integration shared with the native LPM Vault app.
//!
//! The signed CLI and app use the same Team-ID-scoped access group in the
//! Data Protection Keychain. During the staged rollout, an existing legacy
//! record remains authoritative so the current CLI can coexist with new signed
//! clients. Reads copy and verify it into the protected store, and writes keep
//! both copies synchronized. A persistent cutover marker will make new clients
//! ignore legacy records after the coordinated CLI rollout.

use std::collections::HashMap;

use crate::macos_keychain::{
    delete as delete_keychain_password, read_string as try_read_keychain_password,
    with_keychain_transaction, write_string as write_keychain_password,
};

type SecretMap = HashMap<String, String>;
type EnvironmentMap = HashMap<String, SecretMap>;

const SERVICE: &str = "dev.lpm.vault";
const INDEX_ACCOUNT: &str = "__index__";
const X25519_ACCOUNT: &str = "__x25519_private_key__";
const X25519_PENDING_ACCOUNT: &str = "__x25519_private_key__.pending";
const MAX_VAULT_SIZE_WARNING: usize = 90 * 1024;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EnvironmentsWrapper {
    environments: EnvironmentMap,
}

#[derive(serde::Serialize)]
struct BorrowedEnvironmentsWrapper<'a> {
    environments: &'a EnvironmentMap,
}

pub fn read_vault(vault_id: &str) -> Option<SecretMap> {
    try_read_vault(vault_id).ok().flatten()
}

pub fn try_read_vault(vault_id: &str) -> Result<Option<SecretMap>, String> {
    try_read_vault_env(vault_id, "default")
}

pub fn read_vault_env(vault_id: &str, env: &str) -> Option<SecretMap> {
    try_read_vault_env(vault_id, env).ok().flatten()
}

pub fn try_read_vault_env(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    with_keychain_transaction(|| try_read_vault_env_unlocked(vault_id, env))
}

fn try_read_vault_env_unlocked(vault_id: &str, env: &str) -> Result<Option<SecretMap>, String> {
    let Some(json) = try_read_keychain_password(SERVICE, vault_id)? else {
        return Ok(None);
    };

    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return Ok(take_environment(wrapper.environments, env));
    }

    match serde_json::from_str::<SecretMap>(&json) {
        Ok(flat) if env == "default" => Ok(Some(flat)),
        Ok(_) => Ok(None),
        Err(error) => Err(format!("vault keychain data is not valid JSON: {error}")),
    }
}

fn take_environment(mut environments: EnvironmentMap, env: &str) -> Option<SecretMap> {
    environments.remove(env)
}

pub fn read_all_environments(vault_id: &str) -> Option<EnvironmentMap> {
    try_read_all_environments(vault_id).ok().flatten()
}

pub fn try_read_all_environments(vault_id: &str) -> Result<Option<EnvironmentMap>, String> {
    with_keychain_transaction(|| try_read_all_environments_unlocked(vault_id))
}

pub(crate) fn try_read_all_environments_unlocked(
    vault_id: &str,
) -> Result<Option<EnvironmentMap>, String> {
    try_read_all_environments_with_digest_unlocked(vault_id).map(|(environments, _)| environments)
}

pub(crate) fn try_read_all_environments_with_digest_unlocked(
    vault_id: &str,
) -> Result<(Option<EnvironmentMap>, Option<[u8; 32]>), String> {
    use sha2::Digest as _;

    let Some(json) = try_read_keychain_password(SERVICE, vault_id)? else {
        return Ok((None, None));
    };
    let digest = sha2::Sha256::digest(json.as_bytes()).into();

    if let Ok(wrapper) = serde_json::from_str::<EnvironmentsWrapper>(&json) {
        return Ok((Some(wrapper.environments), Some(digest)));
    }

    if let Ok(flat) = serde_json::from_str::<SecretMap>(&json) {
        let mut environments = HashMap::with_capacity(1);
        environments.insert("default".to_owned(), flat);
        return Ok((Some(environments), Some(digest)));
    }

    Err("vault keychain data is not a valid vault payload".to_owned())
}

pub(crate) fn vault_payload_digest_unlocked(vault_id: &str) -> Result<Option<[u8; 32]>, String> {
    use sha2::Digest as _;

    try_read_keychain_password(SERVICE, vault_id)
        .map(|json| json.map(|json| sha2::Sha256::digest(json.as_bytes()).into()))
}

pub fn write_vault(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    write_vault_env(vault_id, project_name, project_path, "default", secrets)
}

pub fn write_all_environments(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        write_all_environments_unlocked(vault_id, project_name, project_path, environments)
    })
}

pub(crate) fn write_all_environments_unlocked(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    let wrapper = BorrowedEnvironmentsWrapper { environments };
    let data = serde_json::to_string(&wrapper)
        .map_err(|error| format!("failed to serialize environments: {error}"))?;
    warn_if_large(data.len());
    save_vault_data_unlocked(vault_id, project_name, project_path, &data)
}

pub fn write_vault_env(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    secrets: &SecretMap,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        let mut environments = try_read_all_environments_unlocked(vault_id)?.unwrap_or_default();
        environments.insert(env.to_owned(), secrets.clone());

        let data = serde_json::to_string(&EnvironmentsWrapper { environments })
            .map_err(|error| format!("failed to serialize environments: {error}"))?;
        warn_if_large(data.len());
        save_vault_data_unlocked(vault_id, project_name, project_path, &data)
    })
}

pub(crate) fn mutate_vault_env<T>(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    operation: impl FnOnce(&mut SecretMap) -> T,
) -> Result<T, String> {
    crate::storage_transaction::with_vault_transaction(|directory| {
        let mut environments = match try_read_all_environments_unlocked(vault_id)? {
            Some(environments) => environments,
            None => crate::fallback::read_all_environments_unlocked(directory, vault_id)?
                .unwrap_or_default(),
        };
        let result = operation(environments.entry(env.to_owned()).or_default());
        let data = serde_json::to_string(&EnvironmentsWrapper { environments })
            .map_err(|error| format!("failed to serialize environments: {error}"))?;
        warn_if_large(data.len());
        save_vault_data_unlocked(vault_id, project_name, project_path, &data)?;
        Ok(result)
    })
}

fn warn_if_large(size: usize) {
    if size > MAX_VAULT_SIZE_WARNING {
        tracing::warn!("vault data is {size} bytes (approaching ~100KB Keychain limit)");
    }
}

fn save_vault_data_unlocked(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    data: &str,
) -> Result<(), String> {
    let mut index = try_read_index_unlocked()?;
    let index_changed =
        add_index_entry_if_missing(&mut index, vault_id, project_name, project_path);
    let previous_data = if index_changed {
        try_read_keychain_password(SERVICE, vault_id)?
    } else {
        None
    };

    write_keychain_password(SERVICE, vault_id, data)?;
    if !index_changed {
        return Ok(());
    }

    if let Err(index_error) = write_index_unlocked(&index) {
        let rollback = match previous_data {
            Some(previous) => write_keychain_password(SERVICE, vault_id, &previous),
            None => delete_keychain_password(SERVICE, vault_id).map(|_| ()),
        };
        return match rollback {
            Ok(()) => Err(index_error),
            Err(rollback_error) => Err(format!(
                "{index_error}; vault data rollback also failed: {rollback_error}"
            )),
        };
    }

    Ok(())
}

fn add_index_entry_if_missing(
    index: &mut Vec<IndexEntry>,
    vault_id: &str,
    project_name: &str,
    project_path: &str,
) -> bool {
    if index.iter().all(|entry| entry.id != vault_id) {
        index.push(IndexEntry {
            id: vault_id.to_owned(),
            name: project_name.to_owned(),
            path: project_path.to_owned(),
        });
        true
    } else {
        false
    }
}

pub fn delete_vault(vault_id: &str) -> Result<(), String> {
    with_keychain_transaction(|| delete_vault_unlocked(vault_id))
}

fn delete_vault_unlocked(vault_id: &str) -> Result<(), String> {
    let previous_data = try_read_keychain_password(SERVICE, vault_id)?;
    let previous_index = try_read_index_unlocked()?;

    delete_keychain_password(SERVICE, vault_id)?;

    let mut index = previous_index;
    index.retain(|entry| entry.id != vault_id);
    if let Err(index_error) = write_index_unlocked(&index) {
        let rollback = previous_data.as_deref().map_or(Ok(()), |data| {
            write_keychain_password(SERVICE, vault_id, data)
        });
        return match rollback {
            Ok(()) => Err(index_error),
            Err(rollback_error) => Err(format!(
                "{index_error}; deleted vault rollback also failed: {rollback_error}"
            )),
        };
    }

    Ok(())
}

pub fn list_vaults() -> Vec<IndexEntry> {
    with_keychain_transaction(try_read_index_unlocked).unwrap_or_default()
}

pub fn read_x25519_private_key() -> Option<[u8; 32]> {
    try_read_x25519_private_key().ok().flatten()
}

pub fn try_read_x25519_private_key() -> Result<Option<[u8; 32]>, String> {
    with_keychain_transaction(|| try_read_x25519_private_key_for_account_unlocked(X25519_ACCOUNT))
}

fn try_read_x25519_private_key_for_account_unlocked(
    account: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(encoded) = try_read_keychain_password(SERVICE, account)? else {
        return Ok(None);
    };
    decode_x25519_private_key(&encoded).map(Some)
}

pub(crate) fn try_read_x25519_private_key_for_account(
    account: &str,
) -> Result<Option<[u8; 32]>, String> {
    with_keychain_transaction(|| try_read_x25519_private_key_for_account_unlocked(account))
}

pub fn write_x25519_private_key(private_key: &[u8; 32]) -> Result<(), String> {
    with_keychain_transaction(|| write_x25519_private_key_unlocked(private_key))
}

fn write_x25519_private_key_unlocked(private_key: &[u8; 32]) -> Result<(), String> {
    write_x25519_private_key_for_account_unlocked(X25519_ACCOUNT, private_key)
}

pub(crate) fn write_x25519_private_key_for_account(
    account: &str,
    private_key: &[u8; 32],
) -> Result<(), String> {
    with_keychain_transaction(|| {
        write_x25519_private_key_for_account_unlocked(account, private_key)
    })
}

fn write_x25519_private_key_for_account_unlocked(
    account: &str,
    private_key: &[u8; 32],
) -> Result<(), String> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
    write_keychain_password(SERVICE, account, &encoded)
}

pub fn get_or_create_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    get_or_create_x25519_keypair_for_account(X25519_ACCOUNT)
}

pub(crate) fn get_or_create_x25519_keypair_for_account(
    account: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    with_keychain_transaction(|| {
        if let Some(private) = try_read_x25519_private_key_for_account_unlocked(account)? {
            let public = crate::crypto::x25519_public_from_private(&private);
            return Ok((private, public));
        }

        let (candidate, _) = crate::crypto::generate_x25519_keypair();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, candidate);
        let stored = crate::macos_keychain::get_or_insert_string(SERVICE, account, &encoded)?;
        let private = decode_x25519_private_key(&stored)?;
        let public = crate::crypto::x25519_public_from_private(&private);
        Ok((private, public))
    })
}

pub fn delete_x25519_keypair() -> Result<(), String> {
    with_keychain_transaction(|| delete_keychain_password(SERVICE, X25519_ACCOUNT).map(|_| ()))
}

pub(crate) fn read_pending_x25519_private_key() -> Result<Option<[u8; 32]>, String> {
    try_read_x25519_private_key_for_account(X25519_PENDING_ACCOUNT)
}

pub(crate) fn promote_x25519_private_key_accounts(
    pending_account: &str,
    live_account: &str,
) -> Result<(), String> {
    with_keychain_transaction(|| {
        let encoded = try_read_keychain_password(SERVICE, pending_account)?
            .ok_or_else(|| "no pending key to promote".to_owned())?;
        decode_x25519_private_key(&encoded)?;
        write_keychain_password(SERVICE, live_account, &encoded)?;
        let verified = try_read_keychain_password(SERVICE, live_account)?;
        if verified.as_deref() != Some(encoded.as_str()) {
            return Err("live X25519 Keychain promotion verification failed".to_owned());
        }
        delete_keychain_password(SERVICE, pending_account).map(|_| ())
    })
}

pub(crate) fn delete_x25519_private_key_for_account(account: &str) -> Result<(), String> {
    with_keychain_transaction(|| delete_keychain_password(SERVICE, account).map(|_| ()))
}

fn decode_x25519_private_key(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.as_bytes(),
    )
    .map_err(|_| "vault X25519 key is not valid base64".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "vault X25519 key must contain exactly 32 bytes".to_owned())
}

fn try_read_index_unlocked() -> Result<Vec<IndexEntry>, String> {
    let Some(json) = try_read_keychain_password(SERVICE, INDEX_ACCOUNT)? else {
        return Ok(Vec::new());
    };
    serde_json::from_str(&json).map_err(|error| format!("vault index is not valid JSON: {error}"))
}

fn write_index_unlocked(entries: &[IndexEntry]) -> Result<(), String> {
    let json = serde_json::to_string(entries)
        .map_err(|error| format!("failed to serialize vault index: {error}"))?;
    write_keychain_password(SERVICE, INDEX_ACCOUNT, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environments_wrapper_round_trips_multiple_environments() {
        let environments = HashMap::from([
            (
                "default".to_owned(),
                HashMap::from([("TOKEN".to_owned(), "one".to_owned())]),
            ),
            (
                "staging".to_owned(),
                HashMap::from([("TOKEN".to_owned(), "two".to_owned())]),
            ),
        ]);

        let json = serde_json::to_string(&EnvironmentsWrapper {
            environments: environments.clone(),
        })
        .unwrap();
        let decoded: EnvironmentsWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.environments, environments);
    }

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

    #[test]
    fn shared_access_group_matches_the_native_app_contract() {
        assert_eq!(
            crate::macos_keychain::SHARED_ACCESS_GROUP,
            "823S8YKMRW.dev.lpm.vault.shared"
        );
    }

    #[test]
    fn keychain_delete_outcomes_remain_distinct() {
        assert_ne!(
            crate::macos_keychain::KeychainDeleteOutcome::Deleted,
            crate::macos_keychain::KeychainDeleteOutcome::NotFound
        );
    }

    #[test]
    fn cli_write_preserves_existing_vault_project_metadata() {
        let mut index = vec![IndexEntry {
            id: "vault-id".to_owned(),
            name: "Vault project name".to_owned(),
            path: "/original/project/path".to_owned(),
        }];

        assert!(!add_index_entry_if_missing(
            &mut index,
            "vault-id",
            "directory-name",
            "/cli/path",
        ));

        assert_eq!(index[0].name, "Vault project name");
        assert_eq!(index[0].path, "/original/project/path");
    }

    #[test]
    fn cli_write_marks_a_new_vault_index_entry_as_changed() {
        let mut index = Vec::new();

        let changed =
            add_index_entry_if_missing(&mut index, "vault-id", "directory-name", "/cli/path");

        assert!(changed);
    }
}
