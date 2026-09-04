//! LPM Vault — Keychain-backed secret storage for project environment variables.
//!
//! Provides a secure, per-project secret store that integrates with `lpm run`
//! for automatic env var injection. Secrets are stored in the macOS Keychain
//! on macOS. Linux and Windows keep encrypted local vault blobs on disk while
//! protecting the local data key with the OS secure store when available.
//!
//! ## Keychain Contract (shared with SwiftUI Vault app)
//!
//! Both the CLI and the native macOS Vault app read/write the same Keychain items:
//! - Service: `dev.lpm.vault`
//! - Index item (account: `__index__`): JSON array of project metadata
//! - Data items (account: `{vault-id}`): JSON dict of secrets
//!
//! ## Usage
//!
//! ```ignore
//! // Store a secret
//! lpm_vault::set(&project_dir, &[("DB_HOST", "localhost")])?;
//!
//! // Get all secrets (for lpm run injection)
//! let secrets = lpm_vault::get_all(&project_dir);
//! ```

pub mod crypto;
mod fallback;
pub mod signature;
pub mod sync;
pub mod vault_id;

mod storage_transaction;

#[cfg(target_os = "macos")]
pub mod keychain;

#[cfg(all(target_os = "macos", not(feature = "legacy-macos-keychain")))]
mod macos_keychain;

#[cfg(all(target_os = "macos", feature = "legacy-macos-keychain"))]
#[path = "legacy_macos_keychain.rs"]
mod macos_keychain;

#[cfg(test)]
pub(crate) mod test_env_lock;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub type SecretMap = HashMap<String, String>;
pub type EnvironmentMap = HashMap<String, SecretMap>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStorageBackend {
    MacosKeychain,
    NativeProtected,
    NativeProtectedWithFallback,
    NativePreferred,
    FileFallback,
    Unavailable { message: String },
}

fn force_file_vault_backend() -> bool {
    if !cfg!(debug_assertions) && !acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[cfg(feature = "acceptance-test-hooks")]
pub(crate) fn acceptance_file_storage_enabled() -> bool {
    if !matches!(
        std::env::var("LPM_ACCEPTANCE_FILE_STORAGE").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    ) || std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }

    let (Some(run_dir), Some(home), Some(lpm_home)) = (
        std::env::var_os("ACCEPTANCE_RUN_DIR").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("LPM_HOME").map(PathBuf::from),
    ) else {
        return false;
    };
    if lpm_home != home.join(".lpm") {
        return false;
    }

    let (Ok(run_dir), Ok(home)) = (std::fs::canonicalize(run_dir), std::fs::canonicalize(home))
    else {
        return false;
    };
    home != run_dir && home.starts_with(run_dir)
}

#[cfg(not(feature = "acceptance-test-hooks"))]
pub(crate) const fn acceptance_file_storage_enabled() -> bool {
    false
}

pub(crate) fn lpm_home_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("LPM_TEST_HOME") {
        return Some(PathBuf::from(path));
    }

    dirs::home_dir()
}

pub fn storage_backend() -> VaultStorageBackend {
    if force_file_vault_backend() {
        return VaultStorageBackend::FileFallback;
    }

    #[cfg(target_os = "macos")]
    {
        VaultStorageBackend::MacosKeychain
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::storage_backend_status()
    }
}

/// Validate a vault key against the POSIX env var name shape
/// (`^[A-Za-z_][A-Za-z0-9_]*$`).
///
/// Vault values are later interpolated into shell, dotenv, Docker
/// `--env-file`, and GitHub Actions outputs. A key like
/// `A; touch /tmp/pwn #` turns the documented
/// `eval $(lpm env print --format=shell)` flow into command execution.
/// Rejecting at write time prevents the malformed key from ever
/// landing in the keychain or the encrypted file fallback.
fn is_valid_vault_key(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn reject_invalid_keys<'a>(pairs: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let bad: Vec<&str> = pairs
        .into_iter()
        .filter(|k| !is_valid_vault_key(k))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "env keys must match [A-Za-z_][A-Za-z0-9_]* (rejected: {})",
            bad.join(", ")
        ))
    }
}

/// Get a single secret value by key (from "default" environment).
pub fn get(project_dir: &Path, key: &str) -> Option<String> {
    try_get(project_dir, key).ok().flatten()
}

pub fn try_get(project_dir: &Path, key: &str) -> Result<Option<String>, String> {
    let secrets = try_get_all(project_dir)?;
    Ok(secrets.get(key).cloned())
}

/// Get all vault secrets for the project (from "default" environment).
///
/// Returns an empty HashMap if no vault exists (backwards compatible).
pub fn get_all(project_dir: &Path) -> HashMap<String, String> {
    try_get_all(project_dir).unwrap_or_default()
}

pub fn try_get_all(project_dir: &Path) -> Result<HashMap<String, String>, String> {
    try_get_all_env(project_dir, "default")
}

/// Get all environments with their secrets.
///
/// Returns `{"default": {"KEY": "VALUE"}, "live": {"KEY": "VALUE"}}`.
/// Empty map if no vault exists.
pub fn get_all_environments(project_dir: &Path) -> HashMap<String, HashMap<String, String>> {
    try_get_all_environments(project_dir).unwrap_or_default()
}

pub fn try_get_all_environments(
    project_dir: &Path,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Ok(HashMap::new()),
    };

    try_get_all_environments_for_vault_id(&vault_id)
}

pub fn try_get_all_environments_for_vault_id(
    vault_id: &str,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    validate_explicit_vault_id(vault_id)?;
    storage_transaction::with_vault_transaction(|directory| {
        Ok(read_all_environments_unlocked(directory, vault_id)?.unwrap_or_default())
    })
}

/// Get all vault secrets for a specific environment.
pub fn get_all_env(project_dir: &Path, env: &str) -> HashMap<String, String> {
    try_get_all_env(project_dir, env).unwrap_or_default()
}

pub fn try_get_all_env(project_dir: &Path, env: &str) -> Result<HashMap<String, String>, String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Ok(HashMap::new()),
    };

    try_get_all_env_for_vault_id(&vault_id, env)
}

pub fn try_get_all_env_for_vault_id(
    vault_id: &str,
    env: &str,
) -> Result<HashMap<String, String>, String> {
    validate_explicit_vault_id(vault_id)?;
    Ok(read_secrets_env(vault_id, env)?.unwrap_or_default())
}

fn validate_explicit_vault_id(vault_id: &str) -> Result<(), String> {
    if vault_id::is_safe_vault_id(vault_id) {
        Ok(())
    } else {
        Err("vault id contains path-traversal or non-portable characters".to_owned())
    }
}

/// Set one or more secrets in the vault.
///
/// Creates the vault (and vault ID in lpm.json) if it doesn't exist.
pub fn set(project_dir: &Path, pairs: &[(&str, &str)]) -> Result<(), String> {
    reject_invalid_keys(pairs.iter().map(|(k, _)| *k))?;

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    mutate_secrets_env(
        &vault_id,
        &project_name,
        &project_path,
        "default",
        |secrets| {
            for (key, value) in pairs {
                secrets.insert((*key).to_owned(), (*value).to_owned());
            }
        },
    )
}

/// Set secrets for a specific environment.
pub fn set_env(project_dir: &Path, env: &str, pairs: &[(&str, &str)]) -> Result<(), String> {
    reject_invalid_keys(pairs.iter().map(|(k, _)| *k))?;

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    mutate_secrets_env(&vault_id, &project_name, &project_path, env, |secrets| {
        for (key, value) in pairs {
            secrets.insert((*key).to_owned(), (*value).to_owned());
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The number of values copied and skipped by [`copy_environment`].
pub struct EnvironmentCopyResult {
    pub copied: usize,
    pub skipped: usize,
}

/// One dotenv source considered during batched vault initialization.
pub struct EnvironmentFileInitialization {
    pub environment: String,
    pub source_path: std::path::PathBuf,
    pub import_if_present: bool,
    pub create_if_missing: bool,
}

/// A decoded vault snapshot that can be reused by batched environment initialization.
pub struct EnvironmentInitializationSnapshot {
    vault_id: Option<String>,
    environments: EnvironmentMap,
    payload_digest: Option<[u8; 32]>,
}

impl EnvironmentInitializationSnapshot {
    /// Iterate over environment names without exposing or copying their secret values.
    pub fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.environments.keys().map(String::as_str)
    }

    /// Return the number of variables stored for one environment.
    pub fn environment_variable_count(&self, environment: &str) -> Option<usize> {
        self.environments.get(environment).map(HashMap::len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentFileInitializationResult {
    pub file_present: bool,
    pub file_variable_count: usize,
    pub imported_count: Option<usize>,
    pub created_empty: bool,
}

#[cfg(test)]
static ENVIRONMENT_SOURCE_READ_LOCK_PROBE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
static ENVIRONMENT_FULL_DECODE_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn record_environment_source_read_lock_state() {
    use std::sync::atomic::Ordering;

    if ENVIRONMENT_SOURCE_READ_LOCK_PROBE
        .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let lock_is_available = storage_transaction::try_acquire_named_lock(
        ".vault-keychain.lock",
        "vault transaction lock probe",
    )
    .expect("probe vault transaction lock")
    .is_some();
    ENVIRONMENT_SOURCE_READ_LOCK_PROBE
        .store(if lock_is_available { 2 } else { 3 }, Ordering::SeqCst);
}

struct EnvironmentInitializationVault {
    vault_id: Option<String>,
    project_name: String,
    project_path: String,
    environments: EnvironmentMap,
    changed: bool,
}

struct PreparedEnvironmentFileInitialization<'a> {
    initialization: &'a EnvironmentFileInitialization,
    file_present: bool,
    file_variable_count: usize,
    secrets: Option<SecretMap>,
}

/// Decode a vault once for inventory planning and later initialization.
pub fn capture_environment_initialization_snapshot(
    vault_id: Option<&str>,
) -> Result<EnvironmentInitializationSnapshot, String> {
    let Some(vault_id) = vault_id else {
        return Ok(EnvironmentInitializationSnapshot {
            vault_id: None,
            environments: HashMap::new(),
            payload_digest: None,
        });
    };
    validate_explicit_vault_id(vault_id)?;
    storage_transaction::with_vault_transaction(|directory| {
        let (environments, payload_digest) =
            read_all_environments_with_digest_unlocked(directory, vault_id)?;
        Ok(EnvironmentInitializationSnapshot {
            vault_id: Some(vault_id.to_owned()),
            environments: environments.unwrap_or_default(),
            payload_digest,
        })
    })
}

fn prepare_environment_file_initializations<'a>(
    initializations: &'a [EnvironmentFileInitialization],
    source_budget_bytes: u64,
) -> Result<Vec<PreparedEnvironmentFileInitialization<'a>>, String> {
    let mut prepared = Vec::with_capacity(initializations.len());
    let mut source_bytes = 0u64;
    for initialization in initializations {
        #[cfg(test)]
        record_environment_source_read_lock_state();
        let content = match lpm_common::read_text_file_capped(
            &initialization.source_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                prepared.push(PreparedEnvironmentFileInitialization {
                    initialization,
                    file_present: false,
                    file_variable_count: 0,
                    secrets: None,
                });
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "failed to read {}: {error}",
                    initialization.source_path.display()
                ));
            }
        };
        source_bytes = source_bytes
            .checked_add(u64::try_from(content.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| "dotenv source size overflowed".to_owned())?;
        if source_bytes > source_budget_bytes {
            return Err(format!(
                "dotenv sources exceed the {source_budget_bytes}-byte aggregate limit"
            ));
        }
        let secrets = parse_env_content(&content);
        let file_variable_count = secrets.len();
        if initialization.import_if_present && !secrets.is_empty() {
            reject_invalid_keys(secrets.keys().map(String::as_str))?;
        }
        prepared.push(PreparedEnvironmentFileInitialization {
            initialization,
            file_present: true,
            file_variable_count,
            secrets: (initialization.import_if_present && !secrets.is_empty()).then_some(secrets),
        });
    }
    Ok(prepared)
}

fn load_environment_initialization_vault<'a>(
    state: &'a mut Option<EnvironmentInitializationVault>,
    project_dir: &Path,
    directory: &storage_transaction::VaultStorageDirectory,
) -> Result<&'a mut EnvironmentInitializationVault, String> {
    if state.is_none() {
        let vault_id = vault_id::read_vault_id(project_dir);
        let project_name = vault_id::read_project_name(project_dir);
        let project_path = project_dir
            .canonicalize()
            .unwrap_or_else(|_| project_dir.to_path_buf())
            .display()
            .to_string();
        let environments = match vault_id.as_deref() {
            Some(vault_id) => {
                read_all_environments_unlocked(directory, vault_id)?.unwrap_or_default()
            }
            None => HashMap::new(),
        };
        *state = Some(EnvironmentInitializationVault {
            vault_id,
            project_name,
            project_path,
            environments,
            changed: false,
        });
    }
    state
        .as_mut()
        .ok_or_else(|| "vault initialization state is unavailable".to_owned())
}

/// Inspect and initialize multiple dotenv sources in one vault transaction.
///
/// Sources are read and parsed one at a time. Results retain input order.
pub fn initialize_environments_from_files(
    project_dir: &Path,
    initializations: &[EnvironmentFileInitialization],
    overwrite: bool,
) -> Result<Vec<EnvironmentFileInitializationResult>, String> {
    initialize_environments_from_files_inner(project_dir, initializations, overwrite, None)
}

/// Initialize dotenv sources while reusing an earlier decoded inventory snapshot when unchanged.
pub fn initialize_environments_from_files_with_snapshot(
    project_dir: &Path,
    initializations: &[EnvironmentFileInitialization],
    overwrite: bool,
    snapshot: EnvironmentInitializationSnapshot,
) -> Result<Vec<EnvironmentFileInitializationResult>, String> {
    initialize_environments_from_files_inner(
        project_dir,
        initializations,
        overwrite,
        Some(snapshot),
    )
}

fn initialize_environments_from_files_inner(
    project_dir: &Path,
    initializations: &[EnvironmentFileInitialization],
    overwrite: bool,
    snapshot: Option<EnvironmentInitializationSnapshot>,
) -> Result<Vec<EnvironmentFileInitializationResult>, String> {
    if initializations.is_empty() {
        return Ok(Vec::new());
    }

    let prepared = prepare_environment_file_initializations(
        initializations,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    let imported_sources = prepared
        .iter()
        .filter(|source| source.secrets.is_some())
        .map(|source| source.initialization.source_path.clone())
        .collect::<Vec<_>>();
    let needs_vault_access = prepared.iter().any(|source| {
        source.secrets.is_some()
            || (!source.file_present && source.initialization.create_if_missing)
    });
    if !needs_vault_access {
        return Ok(prepared
            .into_iter()
            .map(|source| EnvironmentFileInitializationResult {
                file_present: source.file_present,
                file_variable_count: source.file_variable_count,
                imported_count: (source.file_present && source.initialization.import_if_present)
                    .then_some(0),
                created_empty: false,
            })
            .collect());
    }

    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let results = storage_transaction::with_vault_transaction(|directory| {
        let current_vault_id = vault_id::read_vault_id(project_dir);
        let mut state = match snapshot {
            Some(snapshot) if snapshot.vault_id == current_vault_id => {
                let current_digest = match current_vault_id.as_deref() {
                    Some(vault_id) => vault_payload_digest_unlocked(directory, vault_id)?,
                    None => None,
                };
                (current_digest == snapshot.payload_digest).then_some(
                    EnvironmentInitializationVault {
                        vault_id: current_vault_id,
                        project_name: project_name.clone(),
                        project_path: project_path.clone(),
                        environments: snapshot.environments,
                        changed: false,
                    },
                )
            }
            _ => None,
        };
        let mut results = Vec::with_capacity(initializations.len());
        for source in prepared {
            let initialization = source.initialization;
            if !source.file_present {
                if initialization.create_if_missing {
                    let vault =
                        load_environment_initialization_vault(&mut state, project_dir, directory)?;
                    if !vault.environments.contains_key(&initialization.environment) {
                        vault
                            .environments
                            .insert(initialization.environment.clone(), HashMap::new());
                        vault.changed = true;
                    }
                }
                results.push(EnvironmentFileInitializationResult {
                    file_present: false,
                    file_variable_count: 0,
                    imported_count: None,
                    created_empty: initialization.create_if_missing,
                });
                continue;
            }

            let imported_count = match source.secrets {
                Some(secrets) => {
                    let vault =
                        load_environment_initialization_vault(&mut state, project_dir, directory)?;
                    let target = vault
                        .environments
                        .entry(initialization.environment.clone())
                        .or_default();
                    let mut imported = 0;
                    for (key, value) in secrets {
                        if overwrite || !target.contains_key(&key) {
                            target.insert(key, value);
                            imported += 1;
                        }
                    }
                    if imported > 0 {
                        vault.changed = true;
                    }
                    Some(imported)
                }
                None if initialization.import_if_present => Some(0),
                None => None,
            };
            results.push(EnvironmentFileInitializationResult {
                file_present: true,
                file_variable_count: source.file_variable_count,
                imported_count,
                created_empty: false,
            });
        }

        if let Some(vault) = state.filter(|vault| vault.changed) {
            let vault_id = match vault.vault_id {
                Some(vault_id) => vault_id,
                None => vault_id::get_or_create_vault_id(project_dir)?,
            };
            write_all_environments_unlocked(
                directory,
                &vault_id,
                &vault.project_name,
                &vault.project_path,
                &vault.environments,
            )?;
        }

        Ok(results)
    })?;

    add_paths_to_gitignore(
        project_dir,
        imported_sources.iter().map(std::path::PathBuf::as_path),
    );
    Ok(results)
}

/// Copy values between two environments in one vault transaction.
///
/// The result is `None` when the source environment is absent or empty.
pub fn copy_environment(
    project_dir: &Path,
    source: &str,
    target: &str,
    overwrite: bool,
) -> Result<Option<EnvironmentCopyResult>, String> {
    if source == target {
        return Err("source and target environments are the same".to_owned());
    }
    let Some(vault_id) = vault_id::read_vault_id(project_dir) else {
        return Ok(None);
    };
    validate_explicit_vault_id(&vault_id)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    storage_transaction::with_vault_transaction(|directory| {
        let mut environments =
            read_all_environments_unlocked(directory, &vault_id)?.unwrap_or_default();
        let Some(source_secrets) = environments.remove(source) else {
            return Ok(None);
        };
        if source_secrets.is_empty() {
            return Ok(None);
        }

        let target_secrets = environments.entry(target.to_owned()).or_default();
        let mut copied = 0;
        let mut skipped = 0;
        for (key, value) in &source_secrets {
            if target_secrets.contains_key(key) && !overwrite {
                skipped += 1;
            } else {
                target_secrets.insert(key.clone(), value.clone());
                copied += 1;
            }
        }

        if copied > 0 {
            environments.insert(source.to_owned(), source_secrets);
            write_all_environments_unlocked(
                directory,
                &vault_id,
                &project_name,
                &project_path,
                &environments,
            )?;
        }
        Ok(Some(EnvironmentCopyResult { copied, skipped }))
    })
}

pub fn replace_all_environments(
    project_dir: &Path,
    environments: &HashMap<String, HashMap<String, String>>,
) -> Result<(), String> {
    reject_invalid_keys(
        environments
            .values()
            .flat_map(|m| m.keys().map(String::as_str)),
    )?;

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    write_all_environments(&vault_id, &project_name, &project_path, environments)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSyncTarget {
    Personal,
    Organization { slug: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEnvironmentCommit {
    Committed(EnvironmentMap),
    Conflict(EnvironmentMap),
}

/// Commit a cloud pull against the snapshot captured before the request.
///
/// `expected_vault_id` must be the ID used to fetch `remote`; the commit is
/// rejected if `lpm.json` names a different vault by the time the locks are
/// acquired.
///
/// Personal pulls preserve their explicit replacement semantics and reject
/// any intervening local mutation. Organization pulls merge remote keys into
/// the latest local snapshot, but reject a key changed locally to a different
/// value while the request was in flight. Vault contents and sync-version
/// metadata are written under the shared Vault/CLI transaction lock; a
/// metadata failure restores the prior vault snapshot.
pub fn commit_remote_environments(
    project_dir: &Path,
    expected_vault_id: &str,
    baseline: &EnvironmentMap,
    remote: EnvironmentMap,
    target: &RemoteSyncTarget,
    version: i32,
) -> Result<RemoteEnvironmentCommit, String> {
    commit_remote_environments_inner(
        project_dir,
        expected_vault_id,
        baseline,
        remote,
        target,
        version,
        None,
    )
}

pub fn commit_remote_environments_for_principal(
    project_dir: &Path,
    expected_vault_id: &str,
    baseline: &EnvironmentMap,
    remote: EnvironmentMap,
    target: &RemoteSyncTarget,
    version: i32,
    principal: vault_id::SyncPrincipal<'_>,
) -> Result<RemoteEnvironmentCommit, String> {
    commit_remote_environments_inner(
        project_dir,
        expected_vault_id,
        baseline,
        remote,
        target,
        version,
        Some(principal),
    )
}

fn commit_remote_environments_inner(
    project_dir: &Path,
    expected_vault_id: &str,
    baseline: &EnvironmentMap,
    remote: EnvironmentMap,
    target: &RemoteSyncTarget,
    version: i32,
    principal: Option<vault_id::SyncPrincipal<'_>>,
) -> Result<RemoteEnvironmentCommit, String> {
    reject_invalid_keys(
        remote
            .values()
            .flat_map(|map| map.keys().map(String::as_str)),
    )?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    storage_transaction::with_vault_transaction(|directory| {
        let latest =
            read_all_environments_unlocked(directory, expected_vault_id)?.unwrap_or_default();
        let resolved = match target {
            RemoteSyncTarget::Personal => {
                if &latest != baseline {
                    return Ok(RemoteEnvironmentCommit::Conflict(latest));
                }
                remote
            }
            RemoteSyncTarget::Organization { .. } => {
                let mut merged = latest.clone();
                for (environment, remote_secrets) in remote {
                    for (key, remote_value) in &remote_secrets {
                        let baseline_value =
                            baseline.get(&environment).and_then(|map| map.get(key));
                        let latest_value = latest.get(&environment).and_then(|map| map.get(key));
                        if latest_value != baseline_value && latest_value != Some(remote_value) {
                            return Ok(RemoteEnvironmentCommit::Conflict(latest));
                        }
                    }
                    merged
                        .entry(environment)
                        .or_default()
                        .extend(remote_secrets);
                }
                merged
            }
        };

        let mut vault_written = false;
        let sync_target = match target {
            RemoteSyncTarget::Personal => vault_id::SyncVersionTarget::Personal,
            RemoteSyncTarget::Organization { slug } => {
                vault_id::SyncVersionTarget::Organization(slug)
            }
        };
        let commit = || {
            write_all_environments_unlocked(
                directory,
                expected_vault_id,
                &project_name,
                &project_path,
                &resolved,
            )?;
            vault_written = true;
            Ok(())
        };
        let metadata_result = match principal {
            Some(principal) => vault_id::commit_sync_version_for_principal_if_vault_matches(
                project_dir,
                expected_vault_id,
                sync_target,
                version,
                principal,
                commit,
            ),
            None => vault_id::commit_sync_version_if_vault_matches(
                project_dir,
                expected_vault_id,
                sync_target,
                version,
                commit,
            ),
        };
        if let Err(metadata_error) = metadata_result {
            if !vault_written {
                return Err(metadata_error);
            }
            return match write_all_environments_unlocked(
                directory,
                expected_vault_id,
                &project_name,
                &project_path,
                &latest,
            ) {
                Ok(()) => Err(metadata_error),
                Err(rollback_error) => Err(format!(
                    "{metadata_error}; vault rollback also failed: {rollback_error}"
                )),
            };
        }
        Ok(RemoteEnvironmentCommit::Committed(resolved))
    })
}

fn read_all_environments_unlocked(
    directory: &storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<EnvironmentMap>, String> {
    read_all_environments_with_digest_unlocked(directory, vault_id)
        .map(|(environments, _)| environments)
}

fn read_all_environments_with_digest_unlocked(
    directory: &storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<(Option<EnvironmentMap>, Option<[u8; 32]>), String> {
    #[cfg(test)]
    ENVIRONMENT_FULL_DECODE_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    if force_file_vault_backend() {
        return fallback::read_all_environments_with_digest_unlocked(directory, vault_id);
    }
    #[cfg(target_os = "macos")]
    {
        keychain::try_read_all_environments_with_digest_unlocked(vault_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::read_all_environments_with_digest_unlocked(directory, vault_id)
    }
}

fn vault_payload_digest_unlocked(
    directory: &storage_transaction::VaultStorageDirectory,
    vault_id: &str,
) -> Result<Option<[u8; 32]>, String> {
    if force_file_vault_backend() {
        return fallback::vault_payload_digest_unlocked(directory, vault_id);
    }
    #[cfg(target_os = "macos")]
    {
        keychain::vault_payload_digest_unlocked(vault_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::vault_payload_digest_unlocked(directory, vault_id)
    }
}

fn write_all_environments_unlocked(
    directory: &storage_transaction::VaultStorageDirectory,
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &EnvironmentMap,
) -> Result<(), String> {
    if force_file_vault_backend() {
        return fallback::write_all_environments_unlocked(directory, vault_id, environments);
    }
    #[cfg(target_os = "macos")]
    {
        keychain::write_all_environments_unlocked(
            vault_id,
            project_name,
            project_path,
            environments,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path);
        fallback::write_all_environments_unlocked(directory, vault_id, environments)
    }
}

/// Delete one or more secrets from the vault.
pub fn delete(project_dir: &Path, keys: &[&str]) -> Result<(), String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Err("no vault configured for this project".to_string()),
    };

    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    mutate_secrets_env(
        &vault_id,
        &project_name,
        &project_path,
        "default",
        |secrets| {
            for key in keys {
                secrets.remove(*key);
            }
        },
    )
}

/// Get a single secret from a specific environment.
pub fn get_env(project_dir: &Path, env: &str, key: &str) -> Option<String> {
    try_get_env(project_dir, env, key).ok().flatten()
}

pub fn try_get_env(project_dir: &Path, env: &str, key: &str) -> Result<Option<String>, String> {
    let secrets = try_get_all_env(project_dir, env)?;
    Ok(secrets.get(key).cloned())
}

/// Delete secrets from a specific environment.
pub fn delete_env(project_dir: &Path, env: &str, keys: &[&str]) -> Result<(), String> {
    let vault_id = match vault_id::read_vault_id(project_dir) {
        Some(id) => id,
        None => return Err("no vault configured for this project".to_string()),
    };

    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    mutate_secrets_env(&vault_id, &project_name, &project_path, env, |secrets| {
        for key in keys {
            secrets.remove(*key);
        }
    })
}

/// List all secret keys (without values) for the project.
pub fn list_keys(project_dir: &Path) -> Vec<String> {
    let secrets = get_all(project_dir);
    let mut keys: Vec<String> = secrets.into_keys().collect();
    keys.sort();
    keys
}

/// Import secrets from a .env file into the vault.
///
/// Returns the number of imported secrets.
pub fn import_env_file(
    project_dir: &Path,
    env_path: &Path,
    overwrite: bool,
) -> Result<usize, String> {
    let content =
        lpm_common::read_text_file_capped(env_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;

    let parsed = parse_env_content(&content);
    if parsed.is_empty() {
        return Ok(0);
    }

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let imported = mutate_secrets_env(
        &vault_id,
        &project_name,
        &project_path,
        "default",
        |secrets| {
            let mut imported = 0;
            for (key, value) in &parsed {
                if overwrite || !secrets.contains_key(key) {
                    secrets.insert(key.clone(), value.clone());
                    imported += 1;
                }
            }
            imported
        },
    )?;

    // Auto-add the .env file to .gitignore
    add_to_gitignore(project_dir, env_path);

    Ok(imported)
}

/// Import secrets from a .env file into a specific environment.
///
/// Returns the number of imported secrets.
pub fn import_env_file_to_env(
    project_dir: &Path,
    env: &str,
    env_path: &Path,
    overwrite: bool,
) -> Result<usize, String> {
    let content =
        lpm_common::read_text_file_capped(env_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read {}: {e}", env_path.display()))?;

    let parsed = parse_env_content(&content);
    if parsed.is_empty() {
        return Ok(0);
    }

    let vault_id = vault_id::get_or_create_vault_id(project_dir)?;
    let project_name = vault_id::read_project_name(project_dir);
    let project_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string();

    let imported = mutate_secrets_env(&vault_id, &project_name, &project_path, env, |secrets| {
        let mut imported = 0;
        for (key, value) in &parsed {
            if overwrite || !secrets.contains_key(key) {
                secrets.insert(key.clone(), value.clone());
                imported += 1;
            }
        }
        imported
    })?;
    add_to_gitignore(project_dir, env_path);

    Ok(imported)
}

/// Serialize a secret map into sorted dotenv lines, applying the
/// same quoting rules both export paths share.
fn format_env_file_content(secrets: &HashMap<String, String>) -> String {
    let mut entries: Vec<(&str, &str, bool, usize)> = secrets
        .iter()
        .map(|(key, value)| {
            let (requires_quotes, escape_expansion) = env_value_layout(value);
            (
                key.as_str(),
                value.as_str(),
                requires_quotes,
                escape_expansion,
            )
        })
        .collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));

    let capacity = entries.iter().fold(
        0usize,
        |size, (key, value, requires_quotes, escape_expansion)| {
            size.saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(*escape_expansion)
                .saturating_add(if *requires_quotes { 4 } else { 2 })
        },
    );
    let mut output = String::with_capacity(capacity);
    for (key, value, requires_quotes, _) in entries {
        output.push_str(key);
        output.push('=');
        if requires_quotes {
            output.push('"');
            for character in value.chars() {
                match character {
                    '\\' => output.push_str("\\\\"),
                    '"' => output.push_str("\\\""),
                    '\r' => output.push_str("\\r"),
                    '\t' => output.push_str("\\t"),
                    other => output.push(other),
                }
            }
            output.push('"');
        } else {
            output.push_str(value);
        }
        output.push('\n');
    }
    output
}

fn env_value_layout(value: &str) -> (bool, usize) {
    let (requires_quotes, escape_expansion) = value.chars().fold(
        (false, 0usize),
        |(requires_quotes, escape_expansion), character| {
            let requires_quotes =
                requires_quotes || character.is_whitespace() || matches!(character, '"' | '\'');
            let escape_expansion =
                escape_expansion + usize::from(matches!(character, '\\' | '"' | '\r' | '\t'));
            (requires_quotes, escape_expansion)
        },
    );
    (
        requires_quotes,
        if requires_quotes { escape_expansion } else { 0 },
    )
}

/// Atomically write a dotenv export with owner-only permissions.
///
/// The output contains plaintext vault secrets. `std::fs::write`
/// honours the inherited umask (typically `0o644`), which on shared
/// hosts exposes credentials to any local uid. Other agents on the
/// system may also race the write — atomic rename + 0o600 closes
/// both the perms shape and the read-during-write window.
fn write_env_file_owner_only(output_path: &Path, content: &[u8]) -> Result<(), String> {
    lpm_common::write_file_atomic_with_options(
        output_path,
        content,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file(),
    )
    .map_err(|e| format!("failed to write {}: {e}", output_path.display()))
}

/// Export secrets from a specific environment to a .env file.
///
/// Returns the number of exported secrets.
pub fn export_env_file_from_env(
    project_dir: &Path,
    env: &str,
    output_path: &Path,
) -> Result<usize, String> {
    let secrets = try_get_all_env(project_dir, env)?;
    if secrets.is_empty() {
        return Ok(0);
    }

    let content = format_env_file_content(&secrets);
    write_env_file_owner_only(output_path, content.as_bytes())?;

    add_to_gitignore(project_dir, output_path);

    Ok(secrets.len())
}

/// Export vault secrets to a .env file.
///
/// Returns the number of exported secrets.
pub fn export_env_file(project_dir: &Path, output_path: &Path) -> Result<usize, String> {
    let secrets = try_get_all(project_dir)?;
    if secrets.is_empty() {
        return Ok(0);
    }

    let content = format_env_file_content(&secrets);
    write_env_file_owner_only(output_path, content.as_bytes())?;

    add_to_gitignore(project_dir, output_path);

    Ok(secrets.len())
}

// ─── Platform dispatch ─────────────────────────────────────────────

fn read_secrets_env(vault_id: &str, env: &str) -> Result<Option<HashMap<String, String>>, String> {
    if force_file_vault_backend() {
        return fallback::read_vault_file_env(vault_id, env);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(secrets) = keychain::try_read_vault_env(vault_id, env)? {
            return Ok(Some(secrets));
        }
    }

    // Fallback now supports environments
    fallback::read_vault_file_env(vault_id, env)
}

fn mutate_secrets_env<T>(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    env: &str,
    operation: impl FnOnce(&mut HashMap<String, String>) -> T,
) -> Result<T, String> {
    if force_file_vault_backend() {
        return fallback::mutate_vault_file_env(vault_id, env, operation);
    }

    #[cfg(target_os = "macos")]
    {
        keychain::mutate_vault_env(vault_id, project_name, project_path, env, operation)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path);
        fallback::mutate_vault_file_env(vault_id, env, operation)
    }
}

fn write_all_environments(
    vault_id: &str,
    project_name: &str,
    project_path: &str,
    environments: &HashMap<String, HashMap<String, String>>,
) -> Result<(), String> {
    if force_file_vault_backend() {
        return fallback::write_all_environments(vault_id, environments);
    }

    #[cfg(target_os = "macos")]
    {
        keychain::write_all_environments(vault_id, project_name, project_path, environments)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (project_name, project_path);
        fallback::write_all_environments(vault_id, environments)
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

/// Parse a .env file content into key-value pairs.
///
/// Public so callers like `vars init` can count variables before importing.
pub fn parse_env_content(content: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export ` prefix
        let line = line.strip_prefix("export ").unwrap_or(line);

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = parse_env_value(value.trim_start(), &mut lines);

            if !key.is_empty() {
                vars.insert(key, value);
            }
        }
    }

    vars
}

fn parse_env_value(value: &str, lines: &mut std::str::Lines<'_>) -> String {
    if let Some(rest) = value.strip_prefix('"') {
        return parse_quoted_env_value(rest, '"', lines);
    }

    if let Some(rest) = value.strip_prefix('\'') {
        return parse_quoted_env_value(rest, '\'', lines);
    }

    value.trim().to_string()
}

fn parse_quoted_env_value(value: &str, quote: char, lines: &mut std::str::Lines<'_>) -> String {
    let mut collected = String::new();
    let mut fragment = value;

    loop {
        if let Some(close_idx) = find_closing_quote(fragment, quote) {
            collected.push_str(&fragment[..close_idx]);
            return if quote == '"' {
                unescape_double_quoted(&collected)
            } else {
                collected
            };
        }

        collected.push_str(fragment);

        match lines.next() {
            Some(next_line) => {
                collected.push('\n');
                fragment = next_line;
            }
            None => {
                return if quote == '"' {
                    unescape_double_quoted(&collected)
                } else {
                    collected
                };
            }
        }
    }
}

fn find_closing_quote(value: &str, quote: char) -> Option<usize> {
    if quote == '\'' {
        return value.find(quote);
    }

    let mut escaped = false;
    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == quote {
            return Some(idx);
        }
    }

    None
}

fn unescape_double_quoted(value: &str) -> String {
    let mut unescaped = String::new();
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            unescaped.push(ch);
            continue;
        }

        match chars.next() {
            Some('n') => unescaped.push('\n'),
            Some('r') => unescaped.push('\r'),
            Some('t') => unescaped.push('\t'),
            Some('"') => unescaped.push('"'),
            Some('\\') => unescaped.push('\\'),
            Some(other) => {
                unescaped.push('\\');
                unescaped.push(other);
            }
            None => unescaped.push('\\'),
        }
    }

    unescaped
}

fn add_to_gitignore(project_dir: &Path, file_path: &Path) {
    add_paths_to_gitignore(project_dir, std::iter::once(file_path));
}

fn add_paths_to_gitignore<'a>(project_dir: &Path, file_paths: impl IntoIterator<Item = &'a Path>) {
    let gitignore_path = project_dir.join(".gitignore");
    let existing = match lpm_common::read_text_file_capped(
        &gitignore_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(existing) => existing,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => String::new(),
        Err(error) => {
            tracing::warn!(path = %gitignore_path.display(), %error, "failed to inspect .gitignore");
            return;
        }
    };

    let existing_entries = existing.lines().map(str::trim).collect::<HashSet<_>>();
    let mut pending_entries = Vec::new();
    let mut pending_set = HashSet::new();
    for file_path in file_paths {
        let relative = file_path.strip_prefix(project_dir).map_or_else(
            |_| file_path.display().to_string(),
            |path| path.display().to_string(),
        );
        if existing_entries.contains(relative.as_str())
            || existing_entries.contains(format!("/{relative}").as_str())
            || !pending_set.insert(relative.clone())
        {
            continue;
        }
        pending_entries.push(relative);
    }
    if pending_entries.is_empty() {
        return;
    }

    let required_capacity = pending_entries
        .iter()
        .fold(1usize, |size, entry| size.saturating_add(entry.len() + 1));
    let mut addition = String::with_capacity(required_capacity);
    if !existing.ends_with('\n') && !existing.is_empty() {
        addition.push('\n');
    }
    for entry in pending_entries {
        addition.push_str(&entry);
        addition.push('\n');
    }

    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(addition.as_bytes())
        })
    {
        tracing::debug!("failed to update .gitignore: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests share `crate::test_env_lock::ENV_LOCK` (with crypto.rs)
    // so env mutations are serialised across the crate, not just
    // within one module.

    /// Clean up Keychain items created by a test (prevents Keychain pollution).
    #[cfg(debug_assertions)]
    fn cleanup_vault(project_dir: &Path) {
        if let Some(vault_id) = vault_id::read_vault_id(project_dir) {
            #[cfg(target_os = "macos")]
            {
                if !force_file_vault_backend() {
                    let _ = keychain::delete_vault(&vault_id);
                }
            }
            let _ = fallback::delete_vault_file(&vault_id);
        }
    }

    #[cfg(debug_assertions)]
    fn with_forced_file_vault_backend<T>(test: impl FnOnce() -> T) -> T {
        let _lock = crate::test_env_lock::acquire_env_lock();
        let temp_home = tempfile::tempdir().expect("create temp HOME");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp_home.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");
        let original_fast_scrypt = std::env::var_os("LPM_TEST_FAST_SCRYPT");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
                std::env::set_var("LPM_TEST_FAST_SCRYPT", "1");
            }
            test()
        }));

        unsafe {
            match original_force_file_vault {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
            match original_fast_scrypt {
                Some(value) => std::env::set_var("LPM_TEST_FAST_SCRYPT", value),
                None => std::env::remove_var("LPM_TEST_FAST_SCRYPT"),
            }
        }
        original_home.restore();

        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn parse_env_basic() {
        let content = "DB_HOST=localhost\nAPI_KEY=sk-123\nPORT=3000";
        let vars = parse_env_content(content);
        assert_eq!(vars["DB_HOST"], "localhost");
        assert_eq!(vars["API_KEY"], "sk-123");
        assert_eq!(vars["PORT"], "3000");
    }

    #[test]
    fn parse_env_with_quotes() {
        let content = r#"KEY1="value with spaces"
KEY2='literal value'
KEY3=no-quotes"#;
        let vars = parse_env_content(content);
        assert_eq!(vars["KEY1"], "value with spaces");
        assert_eq!(vars["KEY2"], "literal value");
        assert_eq!(vars["KEY3"], "no-quotes");
    }

    #[test]
    fn parse_env_skips_comments_and_empty() {
        let content = "# comment\n\nKEY=value\n  # another comment\n";
        let vars = parse_env_content(content);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars["KEY"], "value");
    }

    #[test]
    fn parse_env_export_prefix() {
        let content = "export DB_HOST=localhost\nexport API_KEY=sk-123";
        let vars = parse_env_content(content);
        assert_eq!(vars["DB_HOST"], "localhost");
        assert_eq!(vars["API_KEY"], "sk-123");
    }

    #[test]
    fn parse_env_value_with_equals() {
        let content = "DATABASE_URL=postgres://user:pass@host:5432/db?ssl=true";
        let vars = parse_env_content(content);
        assert_eq!(
            vars["DATABASE_URL"],
            "postgres://user:pass@host:5432/db?ssl=true"
        );
    }

    #[test]
    fn parse_env_multiline_double_quoted_value_round_trips_export_format() {
        let content = "PRIVATE_KEY=\"line one\nline two \\\"quoted\\\" \\\\ path\"\nNEXT=value\n";
        let vars = parse_env_content(content);

        assert_eq!(vars["PRIVATE_KEY"], "line one\nline two \"quoted\" \\ path");
        assert_eq!(vars["NEXT"], "value");
    }

    #[test]
    fn add_to_gitignore_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env.local");

        add_to_gitignore(dir.path(), &env_path);

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".env.local"));
    }

    #[test]
    fn add_to_gitignore_skips_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".env.local\n").unwrap();

        let env_path = dir.path().join(".env.local");
        add_to_gitignore(dir.path(), &env_path);

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content.matches(".env.local").count(), 1);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn set_and_get_all_round_trip() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            set(
                dir.path(),
                &[("DB_HOST", "localhost"), ("API_KEY", "sk-123")],
            )
            .unwrap();

            let secrets = get_all(dir.path());
            assert_eq!(secrets["DB_HOST"], "localhost");
            assert_eq!(secrets["API_KEY"], "sk-123");

            let vault_id = vault_id::read_vault_id(dir.path());
            assert!(vault_id.is_some());

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn delete_secrets() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            set(dir.path(), &[("A", "1"), ("B", "2"), ("C", "3")]).unwrap();
            delete(dir.path(), &["B"]).unwrap();

            let secrets = get_all(dir.path());
            assert_eq!(secrets.len(), 2);
            assert!(secrets.contains_key("A"));
            assert!(!secrets.contains_key("B"));
            assert!(secrets.contains_key("C"));

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn list_keys_sorted() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            set(
                dir.path(),
                &[("ZEBRA", "z"), ("APPLE", "a"), ("MANGO", "m")],
            )
            .unwrap();

            let keys = list_keys(dir.path());
            assert_eq!(keys, vec!["APPLE", "MANGO", "ZEBRA"]);

            cleanup_vault(dir.path());
        });
    }

    #[test]
    fn get_all_returns_empty_without_vault() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = get_all(dir.path());
        assert!(secrets.is_empty());
    }

    #[test]
    fn dotenv_export_format_preserves_sorted_quoting_and_escaping() {
        let secrets = HashMap::from([
            ("PLAIN".to_owned(), "value".to_owned()),
            ("APOSTROPHE".to_owned(), "it's".to_owned()),
            (
                "MULTILINE".to_owned(),
                "line one\nline \"two\" \\ path".to_owned(),
            ),
        ]);

        let output = format_env_file_content(&secrets);

        assert_eq!(
            output,
            "APOSTROPHE=\"it's\"\nMULTILINE=\"line one\nline \\\"two\\\" \\\\ path\"\nPLAIN=value\n"
        );
    }

    #[test]
    fn dotenv_export_round_trips_control_whitespace() {
        let secrets = HashMap::from([
            ("EDGE_TABS".to_owned(), "\tTOKEN\t".to_owned()),
            ("TAB_ONLY".to_owned(), "\t".to_owned()),
            ("CARRIAGE_RETURN".to_owned(), "before\rafter\r".to_owned()),
        ]);

        let output = format_env_file_content(&secrets);

        assert_eq!(parse_env_content(&output), secrets);
        assert_eq!(
            output,
            "CARRIAGE_RETURN=\"before\\rafter\\r\"\nEDGE_TABS=\"\\tTOKEN\\t\"\nTAB_ONLY=\"\\t\"\n"
        );
    }

    #[test]
    fn dotenv_export_does_not_reserve_escape_expansion_for_unquoted_values() {
        let secrets = HashMap::from([("BACKSLASHES".to_owned(), "\\".repeat(8 * 1024))]);

        let output = format_env_file_content(&secrets);

        assert_eq!(output.capacity(), output.len());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn import_and_export_round_trip() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            let env_file = dir.path().join(".env.import-test");
            std::fs::write(&env_file, "DB=localhost\nPORT=3000\n").unwrap();

            let imported = import_env_file(dir.path(), &env_file, false).unwrap();
            assert_eq!(imported, 2);

            let export_file = dir.path().join(".env.exported");
            let exported = export_env_file(dir.path(), &export_file).unwrap();
            assert_eq!(exported, 2);

            let content = std::fs::read_to_string(&export_file).unwrap();
            assert!(content.contains("DB=localhost"));
            assert!(content.contains("PORT=3000"));

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn import_and_export_round_trip_multiline_secret() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            let env_file = dir.path().join(".env.multiline");
            std::fs::write(
                &env_file,
                "PRIVATE_KEY=\"line one\nline two \\\"quoted\\\" \\\\ path\"\nPLAIN=value\n",
            )
            .unwrap();

            let imported = import_env_file(dir.path(), &env_file, false).unwrap();
            assert_eq!(imported, 2);

            let secrets = get_all(dir.path());
            assert_eq!(
                secrets["PRIVATE_KEY"],
                "line one\nline two \"quoted\" \\ path"
            );
            assert_eq!(secrets["PLAIN"], "value");

            let export_file = dir.path().join(".env.multiline.exported");
            let exported = export_env_file(dir.path(), &export_file).unwrap();
            assert_eq!(exported, 2);

            let reparsed = parse_env_content(&std::fs::read_to_string(&export_file).unwrap());
            assert_eq!(
                reparsed["PRIVATE_KEY"],
                "line one\nline two \"quoted\" \\ path"
            );
            assert_eq!(reparsed["PLAIN"], "value");

            cleanup_vault(dir.path());
        });
    }

    /// Vault setters refuse keys that would let a downstream shell-eval,
    /// dotenv, or env-file consumer interpret the key as command syntax.
    /// The check is independent of OS keychain availability because it runs
    /// before the keychain hop.
    #[test]
    fn set_rejects_keys_that_break_shell_or_dotenv_syntax() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "A; touch /tmp/pwn #",
            "FOO=$(id)",
            "1LEADING_DIGIT",
            "with space",
            "with-dash",
            "",
            "\n",
            "BAR\nINJECT=evil",
        ] {
            let err =
                set(dir.path(), &[(bad, "v")]).expect_err(&format!("must reject key {bad:?}"));
            assert!(
                err.contains("env keys must match"),
                "expected validation error for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn set_env_rejects_keys_that_break_shell_or_dotenv_syntax() {
        let dir = tempfile::tempdir().unwrap();
        let err = set_env(dir.path(), "live", &[("A; rm -rf /; #", "v")])
            .expect_err("must reject injection-shaped key");
        assert!(err.contains("env keys must match"));
    }

    #[test]
    fn replace_all_environments_rejects_invalid_keys_in_any_env() {
        let dir = tempfile::tempdir().unwrap();
        let mut envs: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut default_env = HashMap::new();
        default_env.insert("OK_KEY".to_string(), "ok".to_string());
        envs.insert("default".to_string(), default_env);
        let mut live_env = HashMap::new();
        live_env.insert("BAD KEY".to_string(), "v".to_string());
        envs.insert("live".to_string(), live_env);
        let err = replace_all_environments(dir.path(), &envs)
            .expect_err("must reject if any env has an invalid key");
        assert!(err.contains("env keys must match"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn file_backed_vault_rejects_an_encoded_value_above_the_read_limit_without_replacing_data() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "preserved")]).unwrap();
            let oversized = "x".repeat(lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize);

            let error = set(dir.path(), &[("API_KEY", &oversized)])
                .expect_err("an unreadable encrypted vault must not be persisted");

            assert!(error.contains("exceeds"), "{error}");
            assert_eq!(
                try_get(dir.path(), "API_KEY").unwrap().as_deref(),
                Some("preserved")
            );
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn personal_remote_commit_rejects_an_intervening_local_change() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            set(dir.path(), &[("LOCAL", "two")]).unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "three".to_owned())]),
            )]);

            let result = commit_remote_environments(
                dir.path(),
                &vault_id::read_vault_id(dir.path()).unwrap(),
                &baseline,
                remote,
                &RemoteSyncTarget::Personal,
                7,
            )
            .unwrap();

            assert!(matches!(result, RemoteEnvironmentCommit::Conflict(_)));
            assert_eq!(
                get_all(dir.path()).get("LOCAL").map(String::as_str),
                Some("two")
            );
            assert_eq!(vault_id::read_personal_sync_version(dir.path()), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn organization_remote_commit_merges_disjoint_local_changes_atomically() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            set(dir.path(), &[("LOCAL", "two")]).unwrap();
            let remote = HashMap::from([(
                "live".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "three".to_owned())]),
            )]);

            let result = commit_remote_environments(
                dir.path(),
                &vault_id::read_vault_id(dir.path()).unwrap(),
                &baseline,
                remote,
                &RemoteSyncTarget::Organization {
                    slug: "acme".to_owned(),
                },
                9,
            )
            .unwrap();

            let RemoteEnvironmentCommit::Committed(environments) = result else {
                panic!("disjoint changes should commit");
            };
            assert_eq!(environments["default"]["LOCAL"], "two");
            assert_eq!(environments["live"]["REMOTE"], "three");
            assert_eq!(vault_id::read_org_sync_version(dir.path(), "acme"), Some(9));
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn organization_remote_commit_rejects_an_overlapping_local_change() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "baseline")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            set(dir.path(), &[("API_KEY", "local")]).unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("API_KEY".to_owned(), "remote".to_owned())]),
            )]);

            let result = commit_remote_environments(
                dir.path(),
                &vault_id::read_vault_id(dir.path()).unwrap(),
                &baseline,
                remote,
                &RemoteSyncTarget::Organization {
                    slug: "acme".to_owned(),
                },
                9,
            )
            .unwrap();

            assert!(matches!(result, RemoteEnvironmentCommit::Conflict(_)));
            assert_eq!(get_all(dir.path())["API_KEY"], "local");
            assert_eq!(vault_id::read_org_sync_version(dir.path(), "acme"), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn personal_remote_commit_rejects_a_version_below_the_durable_floor() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "current")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            vault_id::write_personal_sync_version(dir.path(), 5).unwrap();
            let metadata_before = std::fs::read(dir.path().join("lpm.json")).unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("API_KEY".to_owned(), "stale".to_owned())]),
            )]);

            let error = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Personal,
                4,
            )
            .expect_err("a stale personal revision must not lower the durable floor");

            assert!(error.contains("older"), "{error}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(
                std::fs::read(dir.path().join("lpm.json")).unwrap(),
                metadata_before
            );
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn organization_remote_commit_rejects_a_version_below_the_durable_floor() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "current")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            vault_id::write_org_sync_version(dir.path(), "acme", 5).unwrap();
            let metadata_before = std::fs::read(dir.path().join("lpm.json")).unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("API_KEY".to_owned(), "stale".to_owned())]),
            )]);

            let error = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Organization {
                    slug: "acme".to_owned(),
                },
                4,
            )
            .expect_err("a stale organization revision must not lower the durable floor");

            assert!(error.contains("older"), "{error}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(
                std::fs::read(dir.path().join("lpm.json")).unwrap(),
                metadata_before
            );
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn personal_remote_commit_accepts_the_current_durable_version() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "current")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            vault_id::write_personal_sync_version(dir.path(), 5).unwrap();

            let result = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                baseline.clone(),
                &RemoteSyncTarget::Personal,
                5,
            )
            .expect("the current durable revision remains valid");

            assert_eq!(result, RemoteEnvironmentCommit::Committed(baseline));
            assert_eq!(vault_id::read_personal_sync_version(dir.path()), Some(5));
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn organization_remote_commit_accepts_the_current_durable_version() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("API_KEY", "current")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            vault_id::write_org_sync_version(dir.path(), "acme", 5).unwrap();

            let result = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                baseline.clone(),
                &RemoteSyncTarget::Organization {
                    slug: "acme".to_owned(),
                },
                5,
            )
            .expect("the current durable revision remains valid");

            assert_eq!(result, RemoteEnvironmentCommit::Committed(baseline));
            assert_eq!(vault_id::read_org_sync_version(dir.path(), "acme"), Some(5));
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn remote_commit_rolls_back_vault_when_sync_metadata_write_fails() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            let padding = "x".repeat(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize - 128);
            std::fs::write(
                dir.path().join("lpm.json"),
                format!(r#"{{"vault":"{vault_id}","padding":"{padding}"}}"#),
            )
            .unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "two".to_owned())]),
            )]);

            let error = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Personal,
                7,
            )
            .expect_err("oversized sync metadata must reject the commit");

            assert!(error.contains("exceeds"), "{error}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(vault_id::read_personal_sync_version(dir.path()), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn remote_commit_rejects_malformed_sync_metadata_before_writing_vault() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            let vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            std::fs::write(
                dir.path().join("lpm.json"),
                format!(r#"{{"vault":"{vault_id}","vaultSync":[]}}"#),
            )
            .unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "two".to_owned())]),
            )]);

            let error = commit_remote_environments(
                dir.path(),
                &vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Personal,
                7,
            )
            .expect_err("malformed sync metadata must reject the commit");

            assert!(error.contains("vaultSync"), "{error}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(vault_id::read_personal_sync_version(dir.path()), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn personal_remote_commit_rejects_a_vault_id_replaced_after_fetch_started() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let fetched_vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            lpm_common::update_lpm_json(dir.path(), |root, _| {
                root.insert("vault".to_owned(), serde_json::json!("replacement-vault"));
                Ok(lpm_common::LpmJsonMutation::Changed(()))
            })
            .unwrap();
            replace_all_environments(dir.path(), &baseline).unwrap();
            let remote = HashMap::from([(
                "default".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "two".to_owned())]),
            )]);

            let result = commit_remote_environments(
                dir.path(),
                &fetched_vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Personal,
                7,
            );

            assert!(result.is_err(), "fetched vault was {fetched_vault_id}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(vault_id::read_personal_sync_version(dir.path()), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn organization_remote_commit_rejects_a_vault_id_replaced_after_fetch_started() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("BASE", "one")]).unwrap();
            let fetched_vault_id = vault_id::read_vault_id(dir.path()).unwrap();
            let baseline = try_get_all_environments(dir.path()).unwrap();
            lpm_common::update_lpm_json(dir.path(), |root, _| {
                root.insert("vault".to_owned(), serde_json::json!("replacement-vault"));
                Ok(lpm_common::LpmJsonMutation::Changed(()))
            })
            .unwrap();
            replace_all_environments(dir.path(), &baseline).unwrap();
            let remote = HashMap::from([(
                "live".to_owned(),
                HashMap::from([("REMOTE".to_owned(), "two".to_owned())]),
            )]);

            let result = commit_remote_environments(
                dir.path(),
                &fetched_vault_id,
                &baseline,
                remote,
                &RemoteSyncTarget::Organization {
                    slug: "acme".to_owned(),
                },
                9,
            );

            assert!(result.is_err(), "fetched vault was {fetched_vault_id}");
            assert_eq!(try_get_all_environments(dir.path()).unwrap(), baseline);
            assert_eq!(vault_id::read_org_sync_version(dir.path(), "acme"), None);
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn set_accepts_canonical_env_var_names() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(
                dir.path(),
                &[
                    ("DB_URL", "postgres://x"),
                    ("_HIDDEN", "h"),
                    ("a1b2", "v"),
                    ("API_KEY_2024", "k"),
                ],
            )
            .expect("canonical names must be accepted");
            cleanup_vault(dir.path());
        });
    }

    /// `export_env_file` materializes plaintext vault secrets to disk.
    /// On Unix the file must be created at 0o600 — default-umask
    /// writes (typically 0o644) would expose credentials to every
    /// other local uid on shared hosts.
    #[cfg(all(unix, debug_assertions))]
    #[test]
    fn export_env_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();
            set(dir.path(), &[("DB", "postgres://localhost/x")]).unwrap();
            let export_file = dir.path().join(".env.export-perms");
            export_env_file(dir.path(), &export_file).expect("export must succeed");
            let mode = std::fs::metadata(&export_file)
                .expect("export file must exist")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o600,
                "exported dotenv must be 0o600, got {:#o}",
                mode
            );
            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn import_no_overwrite() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            set(dir.path(), &[("KEY", "original")]).unwrap();

            let env_file = dir.path().join(".env.test");
            std::fs::write(&env_file, "KEY=overwritten\nNEW=added").unwrap();

            let imported = import_env_file(dir.path(), &env_file, false).unwrap();
            assert_eq!(imported, 1);

            let secrets = get_all(dir.path());
            assert_eq!(secrets["KEY"], "original");
            assert_eq!(secrets["NEW"], "added");

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn import_with_overwrite() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            set(dir.path(), &[("KEY", "original")]).unwrap();

            let env_file = dir.path().join(".env.test");
            std::fs::write(&env_file, "KEY=overwritten").unwrap();

            let imported = import_env_file(dir.path(), &env_file, true).unwrap();
            assert_eq!(imported, 1);

            let secrets = get_all(dir.path());
            assert_eq!(secrets["KEY"], "overwritten");

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn import_adds_to_gitignore() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().unwrap();

            let env_file = dir.path().join(".env.local");
            std::fs::write(&env_file, "KEY=val").unwrap();

            import_env_file(dir.path(), &env_file, false).unwrap();

            let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
            assert!(gitignore.contains(".env.local"));

            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn initialize_environments_from_files_imports_one_hundred_bounded_sources() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            let mut initializations = Vec::with_capacity(100);
            for index in 0..100 {
                let environment = format!("environment-{index:03}");
                let source_path = dir.path().join(format!(".env.{environment}"));
                std::fs::write(&source_path, format!("KEY_{index:03}=value-{index}\n"))
                    .expect("write dotenv source");
                initializations.push(EnvironmentFileInitialization {
                    environment,
                    source_path,
                    import_if_present: true,
                    create_if_missing: false,
                });
            }

            let results = initialize_environments_from_files(dir.path(), &initializations, false)
                .expect("initialize environments");

            assert_eq!(results.len(), 100);
            assert!(results.iter().all(|result| {
                result.file_present
                    && result.file_variable_count == 1
                    && result.imported_count == Some(1)
                    && !result.created_empty
            }));
            assert_eq!(get_all_environments(dir.path()).len(), 100);
            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn initialize_environments_from_files_reads_sources_before_locking_the_vault() {
        use std::sync::atomic::Ordering;

        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            let source_path = dir.path().join(".env");
            std::fs::write(&source_path, "KEY=value\n").expect("write dotenv source");
            ENVIRONMENT_SOURCE_READ_LOCK_PROBE.store(1, Ordering::SeqCst);

            initialize_environments_from_files(
                dir.path(),
                &[EnvironmentFileInitialization {
                    environment: "default".to_owned(),
                    source_path,
                    import_if_present: true,
                    create_if_missing: false,
                }],
                false,
            )
            .expect("initialize environment");

            assert_eq!(
                ENVIRONMENT_SOURCE_READ_LOCK_PROBE.swap(0, Ordering::SeqCst),
                2,
                "dotenv source I/O must complete before the global vault transaction lock is acquired",
            );
            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn environment_inventory_and_initialization_decode_unchanged_vault_once() {
        use std::sync::atomic::Ordering;

        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            set_env(dir.path(), "default", &[("EXISTING", "value")])
                .expect("seed existing environment");
            let vault_id = vault_id::read_vault_id(dir.path()).expect("read vault id");
            let source_path = dir.path().join(".env");
            std::fs::write(&source_path, "IMPORTED=value\n").expect("write dotenv source");
            ENVIRONMENT_FULL_DECODE_COUNT.store(0, Ordering::SeqCst);

            let snapshot = capture_environment_initialization_snapshot(Some(&vault_id))
                .expect("inspect environment inventory");
            assert_eq!(snapshot.environment_variable_count("default"), Some(1));
            initialize_environments_from_files_with_snapshot(
                dir.path(),
                &[EnvironmentFileInitialization {
                    environment: "default".to_owned(),
                    source_path,
                    import_if_present: true,
                    create_if_missing: false,
                }],
                false,
                snapshot,
            )
            .expect("initialize environment");

            assert_eq!(
                ENVIRONMENT_FULL_DECODE_COUNT.load(Ordering::SeqCst),
                1,
                "an unchanged vault must reuse its decoded inventory during initialization",
            );
            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn environment_initialization_refreshes_a_snapshot_after_a_concurrent_vault_write() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            set_env(dir.path(), "default", &[("EXISTING", "value")])
                .expect("seed existing environment");
            let vault_id = vault_id::read_vault_id(dir.path()).expect("read vault id");
            let snapshot = capture_environment_initialization_snapshot(Some(&vault_id))
                .expect("capture initialization snapshot");
            set_env(dir.path(), "default", &[("CONCURRENT", "preserved")])
                .expect("write concurrent value");
            let source_path = dir.path().join(".env");
            std::fs::write(&source_path, "IMPORTED=value\n").expect("write dotenv source");

            initialize_environments_from_files_with_snapshot(
                dir.path(),
                &[EnvironmentFileInitialization {
                    environment: "default".to_owned(),
                    source_path,
                    import_if_present: true,
                    create_if_missing: false,
                }],
                false,
                snapshot,
            )
            .expect("initialize environment");

            let environment = get_all_env(dir.path(), "default");
            assert_eq!(
                environment.get("EXISTING").map(String::as_str),
                Some("value")
            );
            assert_eq!(
                environment.get("CONCURRENT").map(String::as_str),
                Some("preserved"),
            );
            assert_eq!(
                environment.get("IMPORTED").map(String::as_str),
                Some("value"),
            );
            cleanup_vault(dir.path());
        });
    }

    #[test]
    fn environment_initialization_bounds_aggregate_source_bytes() {
        let dir = tempfile::tempdir().expect("create project directory");
        let first_path = dir.path().join(".env.first");
        let second_path = dir.path().join(".env.second");
        std::fs::write(&first_path, "FIRST=12345678\n").expect("write first dotenv source");
        std::fs::write(&second_path, "SECOND=12345678\n").expect("write second dotenv source");
        let initializations = [
            EnvironmentFileInitialization {
                environment: "first".to_owned(),
                source_path: first_path,
                import_if_present: true,
                create_if_missing: false,
            },
            EnvironmentFileInitialization {
                environment: "second".to_owned(),
                source_path: second_path,
                import_if_present: true,
                create_if_missing: false,
            },
        ];

        let error = prepare_environment_file_initializations(&initializations, 24)
            .err()
            .expect("aggregate source bytes must be bounded");

        assert_eq!(error, "dotenv sources exceed the 24-byte aggregate limit");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn initialize_environments_from_files_scans_skipped_sources_and_creates_missing_environment() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            set_env(dir.path(), "environment-000", &[("KEY", "original")])
                .expect("seed existing environment");
            let mut initializations = Vec::with_capacity(33);
            for index in 0..32 {
                let environment = format!("environment-{index:03}");
                let source_path = dir.path().join(format!(".env.{environment}"));
                std::fs::write(&source_path, format!("KEY=value-{index}\n"))
                    .expect("write dotenv source");
                initializations.push(EnvironmentFileInitialization {
                    environment,
                    source_path,
                    import_if_present: index != 0,
                    create_if_missing: false,
                });
            }
            initializations.push(EnvironmentFileInitialization {
                environment: "environment-032".to_owned(),
                source_path: dir.path().join(".env.environment-032"),
                import_if_present: true,
                create_if_missing: true,
            });

            let results = initialize_environments_from_files(dir.path(), &initializations, false)
                .expect("initialize environments");

            assert_eq!(results.len(), 33);
            assert!(results[0].file_present);
            assert_eq!(results[0].file_variable_count, 1);
            assert_eq!(results[0].imported_count, None);
            assert!(!results[0].created_empty);
            assert!(results[1..32].iter().all(|result| {
                result.file_present
                    && result.file_variable_count == 1
                    && result.imported_count == Some(1)
            }));
            assert!(!results[32].file_present);
            assert!(results[32].created_empty);
            assert_eq!(
                get_all_env(dir.path(), "environment-000").get("KEY"),
                Some(&"original".to_owned())
            );
            assert_eq!(get_all_environments(dir.path()).len(), 33);
            cleanup_vault(dir.path());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn initialize_environments_from_empty_file_does_not_create_vault_or_gitignore() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            let source_path = dir.path().join(".env");
            std::fs::write(&source_path, "\n# no assignments\n").expect("write empty dotenv");

            let results = initialize_environments_from_files(
                dir.path(),
                &[EnvironmentFileInitialization {
                    environment: "default".to_owned(),
                    source_path,
                    import_if_present: true,
                    create_if_missing: false,
                }],
                false,
            )
            .expect("inspect empty dotenv");

            assert_eq!(results.len(), 1);
            assert!(results[0].file_present);
            assert_eq!(results[0].file_variable_count, 0);
            assert_eq!(results[0].imported_count, Some(0));
            assert!(!results[0].created_empty);
            assert!(vault_id::read_vault_id(dir.path()).is_none());
            assert!(!dir.path().join(".gitignore").exists());
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    fn initialize_environments_from_files_leaves_no_vault_when_later_source_fails() {
        with_forced_file_vault_backend(|| {
            let dir = tempfile::tempdir().expect("create project directory");
            let valid_source = dir.path().join(".env.first");
            let invalid_source = dir.path().join("not-a-file");
            std::fs::write(&valid_source, "KEY=value\n").expect("write valid dotenv");
            std::fs::create_dir(&invalid_source).expect("create invalid source directory");
            let initializations = [
                EnvironmentFileInitialization {
                    environment: "first".to_owned(),
                    source_path: valid_source,
                    import_if_present: true,
                    create_if_missing: false,
                },
                EnvironmentFileInitialization {
                    environment: "second".to_owned(),
                    source_path: invalid_source,
                    import_if_present: true,
                    create_if_missing: false,
                },
            ];

            let error = initialize_environments_from_files(dir.path(), &initializations, false)
                .expect_err("directory source must fail");

            assert!(error.contains("not-a-file"));
            assert!(vault_id::read_vault_id(dir.path()).is_none());
            assert!(!dir.path().join(".gitignore").exists());
        });
    }

    /// Regression: `replace_all_environments` must wipe local-only environments
    /// AND replace (not merge) per-environment secrets, so a `vars pull` after a
    /// stale local edit ends up byte-identical to the cloud snapshot.
    ///
    /// Mirrors `tests/workflows/tests/env_vault.rs::
    /// env_pull_overwrites_local_state_with_remote_environments` at the
    /// storage layer (no subprocess, no mock registry).
    #[cfg(debug_assertions)]
    #[test]
    fn replace_all_environments_drops_local_only_envs_and_overwrites_each_env() {
        let _lock = crate::test_env_lock::acquire_env_lock();

        let temp_home = tempfile::tempdir().expect("create temp HOME");
        let original_home = crate::test_env_lock::HomeEnvSnapshot::set(temp_home.path());
        let original_force_file_vault = std::env::var_os("LPM_FORCE_FILE_VAULT");
        let original_fast_scrypt = std::env::var_os("LPM_TEST_FAST_SCRYPT");

        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            std::env::set_var("LPM_TEST_FAST_SCRYPT", "1");
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let project = tempfile::tempdir().expect("create temp project dir");

            // Seed: stale `default` (with a key the cloud no longer has) plus a
            // local-only `preview` environment that the cloud doesn't know about.
            set_env(
                project.path(),
                "default",
                &[
                    ("STALE_DEFAULT", "old-default"),
                    ("REMOVE_ME", "local-only"),
                ],
            )
            .expect("seed default env");
            set_env(
                project.path(),
                "preview",
                &[
                    ("PREVIEW_ONLY", "stale-preview"),
                    ("SHARED_ENV", "stale-preview"),
                ],
            )
            .expect("seed preview env");

            // Pre-condition sanity: both environments are populated.
            let pre = get_all_environments(project.path());
            assert_eq!(pre.len(), 2, "both seeded envs should be present");
            assert!(
                pre.get("default")
                    .is_some_and(|env| env.contains_key("STALE_DEFAULT"))
            );
            assert!(
                pre.get("preview")
                    .is_some_and(|env| env.contains_key("PREVIEW_ONLY"))
            );

            // Pull payload: brand-new `default` keys + a brand-new `live` env.
            // `preview` is intentionally absent — the bug fix must drop it.
            let mut remote = HashMap::new();
            remote.insert(
                "default".to_string(),
                HashMap::from([
                    ("API_URL".to_string(), "https://api.example.com".to_string()),
                    ("SHARED_ENV".to_string(), "remote-default".to_string()),
                ]),
            );
            remote.insert(
                "live".to_string(),
                HashMap::from([("LIVE_ONLY".to_string(), "remote-live".to_string())]),
            );

            replace_all_environments(project.path(), &remote)
                .expect("replace_all_environments should succeed on file backend");

            // Post-condition: vault is byte-identical to the remote snapshot.
            let post_default = get_all_env(project.path(), "default");
            assert_eq!(
                post_default.len(),
                2,
                "default should contain only the remote keys"
            );
            assert_eq!(
                post_default.get("API_URL").map(String::as_str),
                Some("https://api.example.com")
            );
            assert_eq!(
                post_default.get("SHARED_ENV").map(String::as_str),
                Some("remote-default")
            );
            assert!(
                !post_default.contains_key("STALE_DEFAULT"),
                "stale local key must be removed, not merged"
            );
            assert!(
                !post_default.contains_key("REMOVE_ME"),
                "stale local key must be removed, not merged"
            );

            let post_live = get_all_env(project.path(), "live");
            assert_eq!(post_live.len(), 1);
            assert_eq!(
                post_live.get("LIVE_ONLY").map(String::as_str),
                Some("remote-live")
            );

            let post_preview = get_all_env(project.path(), "preview");
            assert!(
                post_preview.is_empty(),
                "local-only environments must be wiped during pull overwrite, got: {post_preview:?}"
            );

            let post_all = get_all_environments(project.path());
            assert_eq!(post_all.len(), 2, "exactly the remote envs should remain");
            assert!(post_all.contains_key("default"));
            assert!(post_all.contains_key("live"));
            assert!(!post_all.contains_key("preview"));

            cleanup_vault(project.path());
        }));

        unsafe {
            match original_force_file_vault {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
            match original_fast_scrypt {
                Some(value) => std::env::set_var("LPM_TEST_FAST_SCRYPT", value),
                None => std::env::remove_var("LPM_TEST_FAST_SCRYPT"),
            }
        }
        original_home.restore();

        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
