use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

const AUTHORITY_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialKind {
    Access,
    Refresh,
}

impl CredentialKind {
    fn label(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }

    pub(super) fn file_key(self, registry: &str) -> String {
        match self {
            Self::Access => registry.to_owned(),
            Self::Refresh => format!("refresh:{registry}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CredentialBackend {
    Keychain,
    EncryptedFileFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(super) enum CredentialAuthority {
    Active {
        backend: CredentialBackend,
        credential_digest: String,
        stale_file_cleanup_pending: bool,
    },
    Revoked,
}

impl CredentialAuthority {
    pub(super) fn active(backend: CredentialBackend, token: &str) -> Self {
        Self::Active {
            backend,
            credential_digest: token_digest(token),
            stale_file_cleanup_pending: false,
        }
    }

    pub(super) fn keychain_cleanup_pending(token: &str) -> Self {
        Self::Active {
            backend: CredentialBackend::Keychain,
            credential_digest: token_digest(token),
            stale_file_cleanup_pending: true,
        }
    }

    pub(super) fn backend(&self) -> Option<CredentialBackend> {
        match self {
            Self::Active { backend, .. } => Some(*backend),
            Self::Revoked => None,
        }
    }

    pub(super) fn matches_token(&self, token: &str) -> bool {
        match self {
            Self::Active {
                credential_digest, ..
            } => credential_digest == &token_digest(token),
            Self::Revoked => false,
        }
    }

    pub(super) fn has_pending_keychain_cleanup(&self) -> bool {
        matches!(
            self,
            Self::Active {
                backend: CredentialBackend::Keychain,
                stale_file_cleanup_pending: true,
                ..
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialAuthorityStore {
    version: u8,
    credentials: BTreeMap<String, CredentialAuthority>,
}

impl Default for CredentialAuthorityStore {
    fn default() -> Self {
        Self {
            version: AUTHORITY_SCHEMA_VERSION,
            credentials: BTreeMap::new(),
        }
    }
}

pub(super) fn read(
    registry: &str,
    kind: CredentialKind,
) -> Result<Option<CredentialAuthority>, String> {
    let store = read_store()?;
    Ok(store
        .credentials
        .get(&credential_id(registry, kind))
        .cloned())
}

pub(super) fn set(
    registry: &str,
    kind: CredentialKind,
    authority: CredentialAuthority,
) -> Result<(), String> {
    let mut store = read_store()?;
    store
        .credentials
        .insert(credential_id(registry, kind), authority);
    write_store(&store)
}

pub(super) fn clear(registry: &str, kind: CredentialKind) -> Result<(), String> {
    let path = authority_path()?;
    if !path.exists() {
        return Ok(());
    }

    let mut store = read_store()?;
    store.credentials.remove(&credential_id(registry, kind));
    write_store(&store)
}

fn credential_id(registry: &str, kind: CredentialKind) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.label().as_bytes());
    digest.update([0]);
    digest.update(registry.as_bytes());
    hex::encode(digest.finalize())
}

fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn read_store() -> Result<CredentialAuthorityStore, String> {
    let path = authority_path()?;
    if !path.exists() {
        return Ok(CredentialAuthorityStore::default());
    }

    let content = lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(|error| format!("credential authority read error: {error}"))?;
    let store: CredentialAuthorityStore = serde_json::from_str(&content)
        .map_err(|error| format!("credential authority JSON error: {error}"))?;
    if store.version != AUTHORITY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported credential authority schema version {}",
            store.version
        ));
    }
    Ok(store)
}

fn write_store(store: &CredentialAuthorityStore) -> Result<(), String> {
    let path = authority_path()?;
    let directory = path
        .parent()
        .ok_or_else(|| "credential authority path has no parent".to_owned())?;
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("credential authority mkdir error: {error}"))?;
    let json = serde_json::to_vec(store)
        .map_err(|error| format!("credential authority JSON error: {error}"))?;
    lpm_common::write_file_atomic_with_options(
        &path,
        json,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )
    .map_err(|error| format!("credential authority write error: {error}"))
}

fn authority_path() -> Result<PathBuf, String> {
    Ok(super::lpm_dir()?.join(".credential-authority.json"))
}

#[cfg(test)]
pub(super) fn path_for_test() -> Result<PathBuf, String> {
    authority_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_authority_without_cleanup_field_is_rejected() {
        let result = serde_json::from_str::<CredentialAuthority>(
            r#"{"state":"active","backend":"keychain","credential_digest":"digest"}"#,
        );

        assert!(result.is_err());
    }
}
