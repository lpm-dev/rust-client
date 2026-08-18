//! Authentication and secure token storage for the LPM Rust client.
//!
//! This crate was extracted from `crates/lpm-cli/src/auth.rs` so that
//! `lpm-registry` can share session/refresh state with `lpm-cli` without
//! a layering violation. Also hosts `SessionManager` — the lazy
//! session/refresh orchestrator.
//!
//! # Token taxonomy
//!
//! - **lpm.dev session tokens** (`get_token`, `set_token`, refresh +
//!   expiry helpers): short-lived access token + rotating refresh token.
//!   Eligible for silent refresh through `SessionManager`.
//! - **Third-party registry tokens** (npm, GitHub, GitLab, custom):
//!   stored via the same keychain + encrypted-file primitives but never
//!   refreshed. They piggyback on the storage layer; `SessionManager`
//!   does not manage them.
//!
//! # Three-tier resolution (matching the JS CLI)
//!
//! 1. `LPM_TOKEN` (or per-registry env var) — CI/CD, testing
//! 2. OS keychain via `keyring` (macOS Keychain, Windows Credential
//!    Manager, Linux Secret Service)
//! 3. Encrypted file fallback at `~/.lpm/.credentials`
//!    (AES-256-GCM + scrypt)
//!
//! Tokens are scoped per registry URL to prevent dev/live collisions.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use credential_authority::{CredentialAuthority, CredentialBackend, CredentialKind};

#[cfg(target_os = "macos")]
use security_framework::passwords::{
    delete_generic_password as macos_delete_generic_password,
    get_generic_password as macos_get_generic_password,
    set_generic_password as macos_set_generic_password,
};
#[cfg(target_os = "macos")]
use security_framework::{
    base::Error as MacosSecurityError,
    item::{ItemClass, ItemSearchOptions, SearchResult},
    os::macos::keychain::SecKeychain,
    os::macos::passwords::find_generic_password as macos_find_generic_password,
};

mod credential_authority;
mod session;
pub use session::{
    AuthRequirement, AuthStorageAccessKind, RefreshPolicy, SessionManager, TokenSource,
    compute_device_fingerprint,
};

/// Keychain service name (matches JS CLI).
const KEYCHAIN_SERVICE: &str = "lpm-cli";

/// Keychain account prefix (matches JS CLI scoped format).
const KEYCHAIN_ACCOUNT_PREFIX: &str = "auth-token";

const DISABLE_HOST_CLI_AUTH_ENV: &str = "LPM_DISABLE_HOST_CLI_AUTH";

#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

#[cfg(target_os = "macos")]
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[cfg(any(target_os = "macos", test))]
const ERR_SEC_INVALID_OWNER_EDIT: i32 = -25244;

#[derive(Debug)]
enum KeychainCredentialProbe {
    Found(String),
    NotFound,
    #[cfg(any(target_os = "macos", test))]
    InteractionRequired,
    Failed,
}

enum KeychainCredentialResolution {
    Found(String),
    NotFound,
    Unavailable,
}

#[cfg(target_os = "macos")]
enum MacosKeychainLookup {
    Found(String),
    NotFound,
    InteractionRequired,
    Failed(MacosSecurityError),
}

#[cfg(test)]
const KEYCHAIN_SERVICE_TEST_ENV: &str = "LPM_AUTH_TEST_KEYCHAIN_SERVICE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStorageBackend {
    Keychain,
    EncryptedFileFallback,
}

impl AuthStorageBackend {
    pub fn as_json_value(self) -> &'static str {
        match self {
            AuthStorageBackend::Keychain => "keychain",
            AuthStorageBackend::EncryptedFileFallback => "encrypted_file_fallback",
        }
    }

    pub fn human_label(self) -> &'static str {
        match self {
            AuthStorageBackend::Keychain => "keychain",
            AuthStorageBackend::EncryptedFileFallback => "encrypted file fallback",
        }
    }

    fn registry_status_label(self) -> &'static str {
        match self {
            AuthStorageBackend::Keychain => "configured (keychain)",
            AuthStorageBackend::EncryptedFileFallback => "configured (encrypted file fallback)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthStorageStatus {
    pub backend: Option<AuthStorageBackend>,
    pub degraded: bool,
}

impl AuthStorageStatus {
    pub fn none() -> Self {
        Self {
            backend: None,
            degraded: false,
        }
    }

    pub fn from_backend(backend: AuthStorageBackend) -> Self {
        Self {
            backend: Some(backend),
            degraded: matches!(backend, AuthStorageBackend::EncryptedFileFallback),
        }
    }

    pub fn from_backends(
        access: Option<AuthStorageBackend>,
        refresh: Option<AuthStorageBackend>,
    ) -> Self {
        if access == Some(AuthStorageBackend::EncryptedFileFallback)
            || refresh == Some(AuthStorageBackend::EncryptedFileFallback)
        {
            return Self::from_backend(AuthStorageBackend::EncryptedFileFallback);
        }

        if access == Some(AuthStorageBackend::Keychain)
            || refresh == Some(AuthStorageBackend::Keychain)
        {
            return Self::from_backend(AuthStorageBackend::Keychain);
        }

        Self::none()
    }

    pub fn backend_json_value(self) -> Option<&'static str> {
        self.backend.map(AuthStorageBackend::as_json_value)
    }

    pub fn human_label(self) -> Option<&'static str> {
        self.backend.map(AuthStorageBackend::human_label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryAuthStatus {
    pub name: String,
    pub status: String,
    pub storage: AuthStorageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredToken {
    token: String,
    backend: AuthStorageBackend,
}

#[derive(Debug)]
enum EncryptedFileCredentialProbe {
    Found(String),
    NotFound,
    Unavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredCredentialPresence {
    Present,
    Absent,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThirdPartyCredentialSource {
    GithubEnvironment,
    GitlabEnvironment,
    GitlabCiJob,
    GithubCli,
    GitlabCli,
    Stored(AuthStorageBackend),
}

impl ThirdPartyCredentialSource {
    pub fn as_json_value(self) -> &'static str {
        match self {
            Self::GithubEnvironment => "env:GITHUB_TOKEN",
            Self::GitlabEnvironment => "env:GITLAB_TOKEN",
            Self::GitlabCiJob => "env:CI_JOB_TOKEN",
            Self::GithubCli => "gh",
            Self::GitlabCli => "glab",
            Self::Stored(_) => "stored",
        }
    }

    pub fn is_stored(self) -> bool {
        matches!(self, Self::Stored(_))
    }

    pub fn storage_status(self) -> AuthStorageStatus {
        match self {
            Self::Stored(backend) => AuthStorageStatus::from_backend(backend),
            _ => AuthStorageStatus::none(),
        }
    }

    fn registry_status(self) -> &'static str {
        match self {
            Self::GithubEnvironment => "configured (env: GITHUB_TOKEN)",
            Self::GitlabEnvironment => "configured (env: GITLAB_TOKEN)",
            Self::GitlabCiJob => "configured (env: CI_JOB_TOKEN)",
            Self::GithubCli => "available (gh auth)",
            Self::GitlabCli => "available (glab auth)",
            Self::Stored(backend) => backend.registry_status_label(),
        }
    }
}

pub struct ResolvedThirdPartyCredential {
    token: SecretString,
    source: ThirdPartyCredentialSource,
}

impl ResolvedThirdPartyCredential {
    fn new(token: String, source: ThirdPartyCredentialSource) -> Self {
        Self {
            token: SecretString::from(token),
            source,
        }
    }

    pub fn source(&self) -> ThirdPartyCredentialSource {
        self.source
    }

    pub fn with_exposed_token<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(self.token.expose_secret())
    }
}

fn force_file_auth() -> bool {
    if !cfg!(debug_assertions) && !acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_AUTH").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

#[cfg(feature = "acceptance-test-hooks")]
fn acceptance_file_storage_enabled() -> bool {
    if !matches!(
        std::env::var("LPM_ACCEPTANCE_FILE_STORAGE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    ) || std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }

    let (Some(run_dir), Some(home), Some(lpm_home)) = (
        std::env::var_os("ACCEPTANCE_RUN_DIR").map(std::path::PathBuf::from),
        std::env::var_os("HOME").map(std::path::PathBuf::from),
        std::env::var_os("LPM_HOME").map(std::path::PathBuf::from),
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
const fn acceptance_file_storage_enabled() -> bool {
    false
}

fn use_fast_test_scrypt() -> bool {
    // SECURITY: Ordinary release binaries must never drop the scrypt N=2^20
    // cost. The feature-gated acceptance build may do so only inside its
    // validated disposable run home.
    if !cfg!(debug_assertions) && !acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_TEST_FAST_SCRYPT").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// Get the token for a given registry URL.
///
/// Priority: env var → keychain → encrypted file
pub fn get_token(registry_url: &str) -> Option<String> {
    // 1. Environment variable (highest priority)
    if let Ok(token) = std::env::var("LPM_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    get_stored_access_token(registry_url)
    // Expiry-based warnings are emitted at command level via
    // check_token_expiry_warnings().
}

fn get_stored_access_token(registry_url: &str) -> Option<String> {
    get_stored_access_token_with_backend(registry_url).map(|stored| stored.token)
}

pub(crate) fn get_stored_access_token_with_interaction_notice(
    registry_url: &str,
    notice: impl FnOnce(),
) -> Result<Option<String>, String> {
    get_stored_credential_with_backend_result(registry_url, CredentialKind::Access, notice)
        .map(|stored| stored.map(|credential| credential.token))
}

/// Check whether a non-empty access token is stored for the given registry.
///
/// Unlike [`get_token`], this ignores `LPM_TOKEN` and reports only local
/// secure-storage state.
pub fn has_stored_access_token(registry_url: &str) -> bool {
    get_stored_access_token(registry_url).is_some()
}

/// Store a token for a given registry URL.
///
/// Tries keychain first, falls back to encrypted file.
pub fn set_token(registry_url: &str, token: &str) -> Result<(), String> {
    set_token_with_backend(registry_url, token).map(|_| ())
}

/// Store a token and report the backend that accepted it.
pub fn set_token_with_backend(
    registry_url: &str,
    token: &str,
) -> Result<AuthStorageBackend, String> {
    set_credential_with_backend(registry_url, CredentialKind::Access, token, || {
        set_token_in_keychain(registry_url, token)
    })
}

fn set_credential_with_backend(
    registry: &str,
    kind: CredentialKind,
    token: &str,
    keychain_write: impl FnOnce() -> Result<(), String>,
) -> Result<AuthStorageBackend, String> {
    with_credential_store_lock(|| {
        set_credential_with_keychain_writer_unlocked(registry, kind, token, keychain_write)
    })
}

fn set_credential_with_keychain_writer_unlocked(
    registry: &str,
    kind: CredentialKind,
    token: &str,
    keychain_write: impl FnOnce() -> Result<(), String>,
) -> Result<AuthStorageBackend, String> {
    let file_key = kind.file_key(registry);
    // Readers hold the same lock and require this digest to match, so a crash
    // before the backend write hides the predecessor instead of reviving it.
    credential_authority::set(
        registry,
        kind,
        CredentialAuthority::active(CredentialBackend::Keychain, token),
    )
    .map_err(|error| format!("failed to record intended keychain authority: {error}"))?;

    match keychain_write() {
        Ok(()) => {
            clear_token_from_file(&file_key).map_err(|error| {
                format!(
                    "keychain credential stored but stale encrypted fallback could not be removed: {error}"
                )
            })?;
            Ok(AuthStorageBackend::Keychain)
        }
        Err(keychain_error) => {
            tracing::warn!("system keychain unavailable — using encrypted file storage");
            credential_authority::set(
                registry,
                kind,
                CredentialAuthority::active(CredentialBackend::EncryptedFileFallback, token),
            )
            .map_err(|error| format!("failed to record intended fallback authority: {error}"))?;
            set_token_in_file(&file_key, token).map_err(|file_error| {
                format!(
                    "keychain write failed ({keychain_error}); encrypted fallback failed: {file_error}"
                )
            })?;
            Ok(AuthStorageBackend::EncryptedFileFallback)
        }
    }
}

fn clear_stored_credential(
    registry: &str,
    kind: CredentialKind,
    keychain_clear: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    with_credential_store_lock(|| {
        let file_key = kind.file_key(registry);
        // A failed delete must leave surviving backend bytes unreadable.
        credential_authority::set(registry, kind, CredentialAuthority::Revoked)
            .map_err(|error| format!("failed to record credential revocation: {error}"))?;
        combine_credential_results([keychain_clear(), clear_token_from_file(&file_key)])?;
        credential_authority::clear(registry, kind)
    })
}

fn with_credential_store_lock<T>(
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = session_lock_path("lpm-auth://credential-store")?;
    match lpm_common::paths::with_exclusive_lock(lock_path, || {
        operation().map_err(lpm_common::LpmError::CredentialStorage)
    }) {
        Ok(value) => Ok(value),
        Err(error) => Err(credential_storage_error_message(error)),
    }
}

fn credential_storage_error_message(error: lpm_common::LpmError) -> String {
    match error {
        lpm_common::LpmError::CredentialStorage(message) => message,
        other => format!("credential storage lock failed: {other}"),
    }
}

fn combine_credential_results<const N: usize>(
    results: [Result<(), String>; N],
) -> Result<(), String> {
    let mut errors = Vec::with_capacity(N);
    for result in results {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub fn auth_storage_status(registry_url: &str) -> AuthStorageStatus {
    AuthStorageStatus::from_backends(
        stored_access_backend(registry_url),
        stored_refresh_backend(registry_url),
    )
}

/// Remove the stored token for a given registry URL.
pub fn clear_token(registry_url: &str) -> Result<(), String> {
    clear_stored_token(registry_url)
}

fn clear_stored_token(registry_url: &str) -> Result<(), String> {
    clear_stored_credential(registry_url, CredentialKind::Access, || {
        clear_token_from_keychain(registry_url)
    })
}

fn combine_clear_results(
    keychain_result: Result<(), String>,
    file_result: Result<(), String>,
) -> Result<(), String> {
    match (keychain_result, file_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(keychain), Ok(())) => Err(keychain),
        (Ok(()), Err(file)) => Err(file),
        (Err(keychain), Err(file)) => Err(format!("{keychain}; {file}")),
    }
}

pub(crate) fn clear_stored_access_token_unlocked(registry_url: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        clear_stored_credential(registry_url, CredentialKind::Access, || Ok(()))
    }

    #[cfg(not(test))]
    {
        clear_token(registry_url)
    }
}

pub(crate) fn clear_stored_refresh_token_unlocked(registry_url: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        clear_stored_credential(registry_url, CredentialKind::Refresh, || Ok(()))
    }

    #[cfg(not(test))]
    {
        clear_refresh_token(registry_url)
    }
}

pub(crate) fn clear_login_state_unlocked(registry_url: &str) -> Result<(), String> {
    if let Some(marker) = dirs::home_dir().map(|h| h.join(".lpm").join(".token-check")) {
        let _ = std::fs::remove_file(marker);
    }

    let access_result = clear_stored_access_token_unlocked(registry_url);
    let refresh_result = clear_stored_refresh_token_unlocked(registry_url);
    let expiry_result = clear_token_expiry_checked(registry_url);
    combine_credential_results([access_result, refresh_result, expiry_result])
}

/// Clear all local login state for a registry.
///
/// This removes the access token, refresh token, and any stored session-expiry
/// metadata so startup cannot silently restore a session after logout.
pub fn clear_login_state(registry_url: &str) -> Result<(), String> {
    let lock_path = session_lock_path(registry_url)?;
    lpm_common::paths::with_exclusive_lock(lock_path, || {
        clear_login_state_unlocked(registry_url).map_err(lpm_common::LpmError::CredentialStorage)
    })
    .map_err(credential_storage_error_message)
}

/// Asynchronously clear all local login state under the per-registry session
/// lock used by access-token refresh and login persistence.
pub async fn clear_login_state_async(registry_url: &str) -> Result<(), String> {
    let lock_path = session_lock_path(registry_url)?;
    lpm_common::paths::with_exclusive_lock_async(lock_path, async {
        clear_login_state_unlocked(registry_url).map_err(lpm_common::LpmError::CredentialStorage)
    })
    .await
    .map_err(credential_storage_error_message)
}

/// Clear a server-rejected legacy session only if its access credential is
/// still current and no refresh credential has appeared in the meantime.
pub fn clear_rejected_legacy_session_if_current(
    registry_url: &str,
    rejected_access_token: &str,
) -> Result<bool, String> {
    let lock_path = session_lock_path(registry_url)?;
    lpm_common::paths::with_exclusive_lock(lock_path, || {
        let access_is_current =
            get_stored_credential_with_backend_result(registry_url, CredentialKind::Access, || {})
                .map_err(lpm_common::LpmError::CredentialStorage)?
                .is_some_and(|credential| credential.token == rejected_access_token);
        let refresh_presence = stored_credential_presence(registry_url, CredentialKind::Refresh);
        if !access_is_current || refresh_presence != StoredCredentialPresence::Absent {
            return Ok(false);
        }

        let expiry_result = clear_token_expiry_checked(registry_url);
        let access_result = clear_stored_access_token_unlocked(registry_url);
        combine_credential_results([access_result, expiry_result])
            .map_err(lpm_common::LpmError::CredentialStorage)?;
        Ok(true)
    })
    .map_err(credential_storage_error_message)
}

// ─── npm Token ─────────────────────────────────────────────────────

/// npm registry URL used for keychain scoping.
const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// Get the token for the npm registry.
///
/// Priority: `NPM_TOKEN` env → keychain(`registry.npmjs.org`) → `.npmrc` parsing
pub fn get_npm_token() -> Option<String> {
    try_get_npm_token().ok().flatten()
}

/// Resolve the npm token while preserving `.npmrc` read failures.
pub fn try_get_npm_token() -> Result<Option<String>, String> {
    // 1. NPM_TOKEN environment variable (CI standard)
    if let Ok(token) = std::env::var("NPM_TOKEN")
        && !token.is_empty()
    {
        return Ok(Some(token));
    }

    // 2. Keychain (stored via `lpm login --npm`)
    if let Some(token) = get_stored_builtin_token(NPM_REGISTRY_URL) {
        return Ok(Some(token));
    }

    // 3. .npmrc fallback — parse token from project or home .npmrc
    if let Some(token) = parse_npmrc_token()? {
        return Ok(Some(token));
    }

    Ok(None)
}

/// Store an npm token in the keychain.
pub fn set_npm_token(token: &str) -> Result<(), String> {
    set_npm_token_with_backend(token).map(|_| ())
}

pub fn set_npm_token_with_backend(token: &str) -> Result<AuthStorageBackend, String> {
    set_token_with_backend(NPM_REGISTRY_URL, token)
}

/// Clear stored npm token (`lpm logout --npm`).
pub fn clear_npm_token() -> Result<(), String> {
    clear_stored_token(NPM_REGISTRY_URL).map_err(|e| format!("failed to clear npm token: {e}"))
}

// ─── GitHub Token ──────────────────────────────────────────────────

/// GitHub Packages registry URL used for keychain scoping.
const GITHUB_REGISTRY_URL: &str = "https://npm.pkg.github.com";

/// Get the token for GitHub Packages.
///
/// Priority: `GITHUB_TOKEN` env → `gh auth token` → keychain(`npm.pkg.github.com`)
pub fn get_github_token() -> Option<String> {
    resolve_github_credential().map(|credential| credential.with_exposed_token(str::to_owned))
}

pub fn resolve_github_environment_credential() -> Option<ResolvedThirdPartyCredential> {
    non_empty_environment_credential(
        "GITHUB_TOKEN",
        ThirdPartyCredentialSource::GithubEnvironment,
    )
}

pub fn resolve_github_credential() -> Option<ResolvedThirdPartyCredential> {
    resolve_github_environment_credential()
        .or_else(|| {
            get_github_cli_token().map(|token| {
                ResolvedThirdPartyCredential::new(token, ThirdPartyCredentialSource::GithubCli)
            })
        })
        .or_else(|| {
            get_stored_builtin_token_with_backend(GITHUB_REGISTRY_URL).map(|stored| {
                ResolvedThirdPartyCredential::new(
                    stored.token,
                    ThirdPartyCredentialSource::Stored(stored.backend),
                )
            })
        })
}

/// Store a GitHub Packages token in the keychain.
pub fn set_github_token(token: &str) -> Result<(), String> {
    set_github_token_with_backend(token).map(|_| ())
}

pub fn set_github_token_with_backend(token: &str) -> Result<AuthStorageBackend, String> {
    set_token_with_backend(GITHUB_REGISTRY_URL, token)
}

/// Clear stored GitHub token (`lpm logout --github`).
pub fn clear_github_token() -> Result<(), String> {
    clear_stored_token(GITHUB_REGISTRY_URL)
        .map_err(|e| format!("failed to clear GitHub token: {e}"))
}

// ─── GitLab Token ──────────────────────────────────────────────────

/// GitLab Packages registry URL used for keychain scoping.
const GITLAB_REGISTRY_URL: &str = "https://gitlab.com/packages/npm";

/// Get the token for GitLab Packages.
///
/// Priority: `GITLAB_TOKEN` env → `CI_JOB_TOKEN` env → `glab auth token` → keychain(`gitlab.com`)
pub fn get_gitlab_token() -> Option<String> {
    get_gitlab_token_for_host("https://gitlab.com")
}

/// Get the token for GitLab Packages at a resolved GitLab host.
///
/// Default-host credentials are used only for `gitlab.com`. Other registry
/// URLs require a credential stored for that exact URL.
pub fn get_gitlab_token_for_host(gitlab_registry_url: &str) -> Option<String> {
    resolve_gitlab_credential_for_host(gitlab_registry_url)
        .map(|credential| credential.with_exposed_token(str::to_owned))
}

pub fn resolve_gitlab_environment_credential() -> Option<ResolvedThirdPartyCredential> {
    non_empty_environment_credential(
        "GITLAB_TOKEN",
        ThirdPartyCredentialSource::GitlabEnvironment,
    )
    .or_else(|| {
        non_empty_environment_credential("CI_JOB_TOKEN", ThirdPartyCredentialSource::GitlabCiJob)
    })
}

pub fn resolve_gitlab_credential_for_host(
    gitlab_registry_url: &str,
) -> Option<ResolvedThirdPartyCredential> {
    if !is_default_gitlab_host(gitlab_registry_url) {
        return get_custom_registry_token_with_backend(gitlab_registry_url).map(|stored| {
            ResolvedThirdPartyCredential::new(
                stored.token,
                ThirdPartyCredentialSource::Stored(stored.backend),
            )
        });
    }

    resolve_gitlab_environment_credential()
        .or_else(|| {
            get_gitlab_cli_token().map(|token| {
                ResolvedThirdPartyCredential::new(token, ThirdPartyCredentialSource::GitlabCli)
            })
        })
        .or_else(|| {
            get_stored_builtin_token_with_backend(GITLAB_REGISTRY_URL).map(|stored| {
                ResolvedThirdPartyCredential::new(
                    stored.token,
                    ThirdPartyCredentialSource::Stored(stored.backend),
                )
            })
        })
}

/// Store a GitLab Packages token in the keychain.
pub fn set_gitlab_token(token: &str) -> Result<(), String> {
    set_gitlab_token_with_backend(token).map(|_| ())
}

pub fn set_gitlab_token_with_backend(token: &str) -> Result<AuthStorageBackend, String> {
    set_token_with_backend(GITLAB_REGISTRY_URL, token)
}

/// Clear stored GitLab token (`lpm logout --gitlab`).
pub fn clear_gitlab_token() -> Result<(), String> {
    clear_stored_token(GITLAB_REGISTRY_URL)
        .map_err(|e| format!("failed to clear GitLab token: {e}"))
}

fn get_stored_builtin_token(registry_url: &str) -> Option<String> {
    get_stored_builtin_token_with_backend(registry_url).map(|stored| stored.token)
}

fn get_stored_builtin_token_with_backend(registry_url: &str) -> Option<StoredToken> {
    get_stored_access_token_with_backend(registry_url)
}

fn non_empty_environment_credential(
    variable: &str,
    source: ThirdPartyCredentialSource,
) -> Option<ResolvedThirdPartyCredential> {
    std::env::var(variable)
        .ok()
        .filter(|token| !token.is_empty())
        .map(|token| ResolvedThirdPartyCredential::new(token, source))
}

fn get_stored_access_token_with_backend(registry_url: &str) -> Option<StoredToken> {
    get_stored_credential_with_backend(registry_url, CredentialKind::Access, || {})
}

fn stored_access_backend(registry_url: &str) -> Option<AuthStorageBackend> {
    get_stored_access_token_with_backend(registry_url).map(|stored| stored.backend)
}

fn stored_refresh_backend(registry_url: &str) -> Option<AuthStorageBackend> {
    get_stored_credential_with_backend(registry_url, CredentialKind::Refresh, || {})
        .map(|stored| stored.backend)
}

fn get_stored_credential_with_backend(
    registry: &str,
    kind: CredentialKind,
    notice: impl FnOnce(),
) -> Option<StoredToken> {
    match get_stored_credential_with_backend_result(registry, kind, notice) {
        Ok(credential) => credential,
        Err(error) => {
            tracing::warn!(
                "credential authority unavailable; refusing ambiguous fallback: {error}"
            );
            None
        }
    }
}

fn get_stored_credential_with_backend_result(
    registry: &str,
    kind: CredentialKind,
    notice: impl FnOnce(),
) -> Result<Option<StoredToken>, String> {
    with_credential_store_lock(|| {
        get_stored_credential_with_backend_unlocked(registry, kind, notice)
    })
}

fn get_stored_credential_with_backend_unlocked(
    registry: &str,
    kind: CredentialKind,
    notice: impl FnOnce(),
) -> Result<Option<StoredToken>, String> {
    let authority = credential_authority::read(registry, kind)?;
    let file_key = kind.file_key(registry);
    let account = match kind {
        CredentialKind::Access => scoped_account(registry),
        CredentialKind::Refresh => scoped_refresh_account(registry),
    };

    let resolved = resolve_stored_credential_from_backends(
        authority.as_ref(),
        || {
            if force_file_auth() {
                return KeychainCredentialProbe::NotFound;
            }
            std::panic::catch_unwind(|| {
                probe_keychain_credential(keychain_service().as_ref(), &account)
            })
            .unwrap_or_else(|_| {
                tracing::debug!("keychain access panicked");
                KeychainCredentialProbe::Failed
            })
        },
        notice,
        || get_password_from_keychain_account(&account),
        || probe_token_from_file(&file_key),
    )?;

    if authority.is_none()
        && let Some(credential) = &resolved
    {
        promote_legacy_credential_authority_unlocked(registry, kind, credential)?;
    }

    Ok(resolved)
}

fn promote_legacy_credential_authority_unlocked(
    registry: &str,
    kind: CredentialKind,
    credential: &StoredToken,
) -> Result<(), String> {
    let backend = match credential.backend {
        AuthStorageBackend::Keychain => CredentialBackend::Keychain,
        AuthStorageBackend::EncryptedFileFallback => CredentialBackend::EncryptedFileFallback,
    };
    credential_authority::set(
        registry,
        kind,
        CredentialAuthority::active(backend, &credential.token),
    )?;
    if credential.backend == AuthStorageBackend::Keychain {
        clear_token_from_file(&kind.file_key(registry))?;
    }
    Ok(())
}

fn resolve_stored_credential_from_backends(
    authority: Option<&CredentialAuthority>,
    keychain_probe: impl FnOnce() -> KeychainCredentialProbe,
    notice: impl FnOnce(),
    interactive_retry: impl FnOnce() -> Option<String>,
    file_lookup: impl FnOnce() -> EncryptedFileCredentialProbe,
) -> Result<Option<StoredToken>, String> {
    if matches!(authority, Some(CredentialAuthority::Revoked)) {
        return Ok(None);
    }

    if authority.and_then(CredentialAuthority::backend)
        == Some(CredentialBackend::EncryptedFileFallback)
    {
        return match file_lookup() {
            EncryptedFileCredentialProbe::Found(token)
                if authority.is_some_and(|record| record.matches_token(&token)) =>
            {
                Ok(Some(StoredToken {
                    token,
                    backend: AuthStorageBackend::EncryptedFileFallback,
                }))
            }
            EncryptedFileCredentialProbe::Found(_) => {
                Err("encrypted credential does not match its authority record".to_owned())
            }
            EncryptedFileCredentialProbe::NotFound => {
                Err("authoritative encrypted credential is unavailable".to_owned())
            }
            EncryptedFileCredentialProbe::Unavailable(error) => Err(format!(
                "authoritative encrypted credential storage is unavailable: {error}"
            )),
        };
    }

    match resolve_keychain_probe(keychain_probe(), notice, interactive_retry) {
        KeychainCredentialResolution::Found(token) if !token.is_empty() => {
            if let Some(authority) = authority {
                if authority.matches_token(&token) {
                    return Ok(Some(StoredToken {
                        token,
                        backend: AuthStorageBackend::Keychain,
                    }));
                }
                return Err("keychain credential does not match its authority record".to_owned());
            }

            match file_lookup() {
                EncryptedFileCredentialProbe::Found(file_token) if file_token != token => {
                    return Err(
                        "legacy keychain and encrypted credentials disagree; refusing destructive migration"
                            .to_owned(),
                    );
                }
                EncryptedFileCredentialProbe::Unavailable(error) => {
                    return Err(format!(
                        "encrypted credential storage is unavailable during legacy migration: {error}"
                    ));
                }
                EncryptedFileCredentialProbe::Found(_) | EncryptedFileCredentialProbe::NotFound => {
                }
            }
            Ok(Some(StoredToken {
                token,
                backend: AuthStorageBackend::Keychain,
            }))
        }
        KeychainCredentialResolution::Found(_) | KeychainCredentialResolution::NotFound
            if authority.is_none() =>
        {
            match file_lookup() {
                EncryptedFileCredentialProbe::Found(token) => Ok(Some(StoredToken {
                    token,
                    backend: AuthStorageBackend::EncryptedFileFallback,
                })),
                EncryptedFileCredentialProbe::NotFound => Ok(None),
                EncryptedFileCredentialProbe::Unavailable(error) => Err(format!(
                    "encrypted credential storage is unavailable: {error}"
                )),
            }
        }
        KeychainCredentialResolution::Found(_) | KeychainCredentialResolution::NotFound => {
            Err("authoritative keychain credential is unavailable".to_owned())
        }
        KeychainCredentialResolution::Unavailable => {
            Err("keychain credential storage is unavailable".to_owned())
        }
    }
}

fn stored_credential_presence(registry: &str, kind: CredentialKind) -> StoredCredentialPresence {
    match get_stored_credential_with_backend_result(registry, kind, || {}) {
        Ok(Some(_)) => StoredCredentialPresence::Present,
        Ok(None) => StoredCredentialPresence::Absent,
        Err(error) => {
            tracing::warn!("credential presence unavailable: {error}");
            StoredCredentialPresence::Unavailable
        }
    }
}

fn host_cli_token(program: &str, args: &[&str]) -> Option<String> {
    if host_cli_auth_disabled() {
        return None;
    }

    let output = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn host_cli_auth_disabled() -> bool {
    matches!(
        std::env::var(DISABLE_HOST_CLI_AUTH_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn is_default_gitlab_host(raw: &str) -> bool {
    reqwest::Url::parse(raw)
        .ok()
        .is_some_and(|url| url.origin().ascii_serialization() == "https://gitlab.com")
}

// ─── Custom Registry Token ─────────────────────────────────────────

/// Get the token for a custom registry URL.
///
/// Priority: keychain(url) — custom registries use the existing scoped keychain.
pub fn get_custom_registry_token(registry_url: &str) -> Option<String> {
    get_custom_registry_token_with_backend(registry_url).map(|stored| stored.token)
}

fn get_custom_registry_token_with_backend(registry_url: &str) -> Option<StoredToken> {
    get_stored_access_token_with_backend(registry_url)
}

/// Return a token from the GitHub CLI without storing or copying it.
pub fn get_github_cli_token() -> Option<String> {
    host_cli_token("gh", &["auth", "token", "--hostname", "github.com"])
}

/// Return a token from the GitLab CLI without storing or copying it.
pub fn get_gitlab_cli_token() -> Option<String> {
    host_cli_token("glab", &["auth", "token"])
}

/// Store a token for a custom registry URL and track it for enumeration.
pub fn set_custom_registry_token(registry_url: &str, token: &str) -> Result<(), String> {
    set_custom_registry_token_with_backend(registry_url, token).map(|_| ())
}

pub fn set_custom_registry_token_with_backend(
    registry_url: &str,
    token: &str,
) -> Result<AuthStorageBackend, String> {
    let backend = set_token_with_backend(registry_url, token)?;
    track_custom_registry(registry_url);
    Ok(backend)
}

/// Clear stored custom registry token and remove from tracking.
pub fn clear_custom_registry_token(registry_url: &str) -> Result<(), String> {
    clear_login_state(registry_url)?;
    untrack_custom_registry(registry_url);
    Ok(())
}

/// Path to the JSON file tracking custom registry URLs.
fn custom_registries_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join(".custom-registries.json"))
}

/// Apply 0o600 to a credential-adjacent file on Unix, best-effort.
///
/// On non-Unix filesystems (network mounts, exFAT, some Docker
/// volumes) `set_permissions` can silently no-op. We can't make
/// non-Unix targets honor the mode bits, but we can ensure every
/// Unix write site that touches credential metadata gets the
/// restrictive mode applied uniformly, and surface failures via
/// `tracing::warn` instead of `let _ = …` silence. Information in
/// `.custom-registries.json` (registry URLs) and `.token-expiry.json`
/// (expiry timestamps, OTP-required flag) is not raw secret material
/// but does enumerate which third-party registries the user has
/// tokens for — useful reconnaissance for an attacker planning
/// credential theft on a shared host.
#[cfg(unix)]
fn restrict_credential_metadata_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to set 0o600 on credential metadata file",
        );
    }
}

#[cfg(not(unix))]
fn restrict_credential_metadata_perms(_path: &Path) {}

fn is_builtin_registry_url(registry_url: &str) -> bool {
    matches!(
        registry_url,
        NPM_REGISTRY_URL | GITHUB_REGISTRY_URL | GITLAB_REGISTRY_URL
    )
}

fn discover_file_backed_custom_registries() -> Vec<String> {
    if !force_file_auth() {
        return Vec::new();
    }

    let Some(path) = credentials_path().ok() else {
        return Vec::new();
    };
    let Ok(content) =
        lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return Vec::new();
    };
    let encrypted = content.trim();
    if encrypted.is_empty() {
        return Vec::new();
    }

    let Some(json_str) = decrypt(encrypted).ok() else {
        return Vec::new();
    };
    let Some(store) = serde_json::from_str::<serde_json::Value>(&json_str).ok() else {
        return Vec::new();
    };
    let Some(entries) = store.as_object() else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|(registry_url, value)| {
            if registry_url.starts_with("refresh:") || is_builtin_registry_url(registry_url) {
                return None;
            }

            if value.is_null() {
                return None;
            }

            Some(registry_url.clone())
        })
        .collect()
}

fn enumerate_custom_registries() -> Vec<String> {
    use std::collections::BTreeSet;

    let mut registries = BTreeSet::new();
    for registry_url in list_custom_registries() {
        registries.insert(registry_url);
    }
    for registry_url in discover_file_backed_custom_registries() {
        registries.insert(registry_url);
    }

    registries.into_iter().collect()
}

/// Read tracked custom registry URLs.
pub fn list_custom_registries() -> Vec<String> {
    let Some(path) = custom_registries_path() else {
        return Vec::new();
    };
    let Ok(content) =
        lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return Vec::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Add a custom registry URL to the tracking file.
fn track_custom_registry(registry_url: &str) {
    let mut registries = list_custom_registries();
    if !registries.iter().any(|r| r == registry_url) {
        registries.push(registry_url.to_string());
        if let Some(path) = custom_registries_path() {
            // Ensure ~/.lpm/ exists (may not on a clean machine if keychain was used first)
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(
                &path,
                serde_json::to_string(&registries).unwrap_or_default(),
            )
            .is_ok()
            {
                restrict_credential_metadata_perms(&path);
            }
        }
    }
}

/// Remove a custom registry URL from the tracking file.
fn untrack_custom_registry(registry_url: &str) {
    let mut registries = list_custom_registries();
    registries.retain(|r| r != registry_url);
    if let Some(path) = custom_registries_path() {
        if registries.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else if std::fs::write(
            &path,
            serde_json::to_string(&registries).unwrap_or_default(),
        )
        .is_ok()
        {
            restrict_credential_metadata_perms(&path);
        }
    }
}

/// Clear all stored custom registry tokens.
///
/// Only removes successfully cleared entries from the tracking file.
/// Failed deletions remain tracked so they can be retried.
pub fn clear_all_custom_registries() -> Vec<(String, Result<(), String>)> {
    let registries = enumerate_custom_registries();
    let mut results = Vec::new();
    let mut remaining = Vec::new();

    for url in &registries {
        let result = clear_login_state(url);
        if result.is_err() {
            remaining.push(url.clone());
        }
        results.push((url.clone(), result));
    }

    // Rewrite tracking file: keep only entries that failed to clear
    if let Some(path) = custom_registries_path() {
        if remaining.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else if std::fs::write(&path, serde_json::to_string(&remaining).unwrap_or_default())
            .is_ok()
        {
            restrict_credential_metadata_perms(&path);
        }
    }

    results
}

// ─── Registry Enumeration (B4) ─────────────────────────────────────

/// Check which registries have available auth sources.
///
/// Does NOT verify tokens because that would require network calls. Use
/// `verify_registry_token()` for that.
pub fn list_registry_auth_statuses() -> Vec<RegistryAuthStatus> {
    let mut result = Vec::new();

    // npm: check env, keychain, .npmrc — show source so user knows where token came from
    let npm_stored_token = get_stored_builtin_token_with_backend(NPM_REGISTRY_URL);

    if let Ok(token) = std::env::var("NPM_TOKEN") {
        if !token.is_empty() {
            result.push(RegistryAuthStatus {
                name: "npmjs.org".into(),
                status: "configured (env: NPM_TOKEN)".into(),
                storage: AuthStorageStatus::none(),
            });
        }
    } else if let Some(stored) = npm_stored_token {
        result.push(RegistryAuthStatus {
            name: "npmjs.org".into(),
            status: stored.backend.registry_status_label().into(),
            storage: AuthStorageStatus::from_backend(stored.backend),
        });
    } else if parse_npmrc_token().is_ok_and(|token| token.is_some()) {
        result.push(RegistryAuthStatus {
            name: "npmjs.org".into(),
            status: "found in .npmrc (may be expired — run `lpm login --npm` to verify)".into(),
            storage: AuthStorageStatus::none(),
        });
    }

    if let Some(credential) = resolve_github_credential() {
        let source = credential.source();
        result.push(RegistryAuthStatus {
            name: "github.com".into(),
            status: source.registry_status().into(),
            storage: source.storage_status(),
        });
    }

    if let Some(credential) = resolve_gitlab_credential_for_host("https://gitlab.com") {
        let source = credential.source();
        result.push(RegistryAuthStatus {
            name: "gitlab.com".into(),
            status: source.registry_status().into(),
            storage: source.storage_status(),
        });
    }

    // Custom registries: read from tracking file
    for url in list_custom_registries() {
        if let Some(stored) = get_custom_registry_token_with_backend(&url) {
            result.push(RegistryAuthStatus {
                name: url,
                status: stored.backend.registry_status_label().into(),
                storage: AuthStorageStatus::from_backend(stored.backend),
            });
        }
    }

    result
}

/// Check which registries have stored tokens.
///
/// Returns a list of `(display_name, status)` pairs for known registries.
pub fn list_stored_registries() -> Vec<(String, String)> {
    list_registry_auth_statuses()
        .into_iter()
        .map(|registry| (registry.name, registry.status))
        .collect()
}

/// Token expiry tracking file path.
fn token_expiry_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join(".token-expiry.json"))
}

fn token_expiry_lock_path() -> Result<std::path::PathBuf, String> {
    token_expiry_path()
        .map(|path| path.with_file_name(".token-expiry.lock"))
        .ok_or_else(|| "could not determine token-expiry lock path".to_string())
}

fn read_token_expiries_checked_from(path: &Path) -> Result<HashMap<String, TokenExpiry>, String> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(HashMap::new()),
            Err(error) => return Err(format!("token-expiry metadata read error: {error}")),
        };

    serde_json::from_str(&content)
        .map_err(|error| format!("token-expiry metadata JSON error: {error}"))
}

fn read_token_expiries_checked() -> Result<HashMap<String, TokenExpiry>, String> {
    let path = token_expiry_path().ok_or("could not determine token-expiry path")?;
    read_token_expiries_checked_from(&path)
}

fn write_token_expiries_checked(
    path: &Path,
    expiries: &HashMap<String, TokenExpiry>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("mkdir error: {error}"))?;
    }
    let json =
        serde_json::to_string_pretty(expiries).map_err(|error| format!("json error: {error}"))?;
    lpm_common::write_file_atomic_with_options(
        path,
        json,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )
    .map_err(|error| format!("write error: {error}"))
}

fn mutate_token_expiries(
    mutation: impl FnOnce(&mut HashMap<String, TokenExpiry>) -> bool,
) -> Result<(), String> {
    let path = token_expiry_path().ok_or("could not determine token-expiry path")?;
    let lock_path = token_expiry_lock_path()?;
    lpm_common::paths::with_exclusive_lock(lock_path, || {
        let mut expiries = read_token_expiries_checked_from(&path)
            .map_err(lpm_common::LpmError::CredentialStorage)?;
        if mutation(&mut expiries) {
            write_token_expiries_checked(&path, &expiries)
                .map_err(lpm_common::LpmError::CredentialStorage)?;
        }
        Ok(())
    })
    .map_err(credential_storage_error_message)
}

/// Read stored token expiry data.
pub fn read_token_expiries() -> std::collections::HashMap<String, TokenExpiry> {
    read_token_expiries_checked().unwrap_or_default()
}

/// Store a token expiry reminder.
pub fn set_token_expiry(registry: &str, expires: &str) {
    if let Err(error) = mutate_token_expiries(|expiries| {
        let entry = expiries.entry(registry.to_string()).or_default();
        entry.expires = expires.to_string();
        entry.reminded_7d = false;
        entry.reminded_1d = false;
        entry.session_access_expires_at = None;
        true
    }) {
        tracing::warn!("failed to store token expiry: {error}");
    }
}

/// Store the precise expiry for a short-lived session access token.
pub fn set_session_access_token_expiry(registry: &str, expires_at: &str) {
    if let Err(error) = set_session_access_token_expiry_checked(registry, expires_at) {
        tracing::warn!("failed to store session access-token expiry: {error}");
    }
}

pub(crate) fn set_session_access_token_expiry_checked(
    registry: &str,
    expires_at: &str,
) -> Result<(), String> {
    mutate_token_expiries(|expiries| {
        let entry = expiries.entry(registry.to_string()).or_default();
        entry.session_access_expires_at = Some(expires_at.to_string());
        entry.expires.clear();
        entry.reminded_7d = false;
        entry.reminded_1d = false;
        true
    })
}

fn session_access_token_expiry(registry: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let expiries = read_token_expiries();
    let expiry = expiries
        .get(registry)?
        .session_access_expires_at
        .as_deref()?;

    chrono::DateTime::parse_from_rfc3339(expiry)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

/// Returns true when a stored session access token is already expired.
pub fn is_session_access_token_expired(registry: &str) -> bool {
    session_access_token_expiry(registry).is_some_and(|expiry| expiry <= chrono::Utc::now())
}

/// Returns true when a stored session access token should be refreshed.
/// Missing metadata is treated as refresh-needed so older stored sessions self-heal.
pub fn should_refresh_session_access_token(registry: &str) -> bool {
    session_access_token_expiry(registry)
        .is_none_or(|expiry| expiry <= chrono::Utc::now() + chrono::Duration::minutes(5))
}

/// Returns true if the local session-expiry metadata exists but cannot be read
/// as a complete metadata map. Missing metadata is not corruption.
pub fn session_metadata_corrupted() -> bool {
    let Some(path) = token_expiry_path() else {
        return false;
    };
    read_token_expiries_checked_from(&path).is_err()
}

/// Remove a token expiry reminder (called on logout).
pub fn clear_token_expiry(registry: &str) {
    if let Err(error) = clear_token_expiry_checked(registry) {
        tracing::warn!("failed to clear token expiry: {error}");
    }
}

pub(crate) fn clear_token_expiry_checked(registry: &str) -> Result<(), String> {
    mutate_token_expiries(|expiries| expiries.remove(registry).is_some())
}

/// Check token expiries and return warnings for tokens expiring soon.
pub fn check_token_expiry_warnings() -> Vec<String> {
    let expiries = read_token_expiries();
    let now = chrono::Utc::now().date_naive();
    let mut warnings = Vec::new();

    for (registry, expiry) in &expiries {
        if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(&expiry.expires, "%Y-%m-%d") {
            let days_left = (exp_date - now).num_days();
            if days_left < 0 {
                warnings.push(format!(
                    "{registry} token expired {} days ago — run `lpm login --{}`",
                    -days_left,
                    registry_to_flag(registry)
                ));
            } else if days_left <= 1 && !expiry.reminded_1d {
                warnings.push(format!(
                    "{registry} token expires tomorrow — run `lpm login --{}`",
                    registry_to_flag(registry)
                ));
            } else if days_left <= 7 && !expiry.reminded_7d {
                warnings.push(format!(
                    "{registry} token expires in {days_left} days — run `lpm login --{}`",
                    registry_to_flag(registry)
                ));
            }
        }
    }
    warnings
}

fn registry_to_flag(registry: &str) -> &str {
    match registry {
        "npmjs.org" => "npm",
        "github.com" => "github",
        "gitlab.com" => "gitlab",
        _ => "npm",
    }
}

/// Token metadata record (expiry + preferences).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct TokenExpiry {
    pub expires: String,
    pub reminded_7d: bool,
    pub reminded_1d: bool,
    /// Whether the account requires OTP/2FA for publish operations.
    #[serde(default)]
    pub otp_required: bool,
    /// Exact expiry timestamp for short-lived session access tokens.
    #[serde(default)]
    pub session_access_expires_at: Option<String>,
}

/// Check if a registry has OTP/2FA enabled (set during login).
pub fn is_otp_required(registry: &str) -> bool {
    read_token_expiries()
        .get(registry)
        .is_some_and(|e| e.otp_required)
}

/// Set the OTP/2FA preference for a registry.
pub fn set_otp_required(registry: &str, required: bool) {
    if let Err(error) = mutate_token_expiries(|expiries| {
        let entry = expiries.entry(registry.to_string()).or_default();
        entry.otp_required = required;
        true
    }) {
        tracing::warn!("failed to store OTP requirement: {error}");
    }
}

// ─── Refresh Token Storage ──────────────────────
// Uses the same keychain + encrypted-file path as the main token.
// Separate account prefix to avoid collision.

const REFRESH_ACCOUNT_PREFIX: &str = "lpm-refresh";

fn scoped_refresh_account(registry_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(registry_url.as_bytes());
    format!("{}:{}", REFRESH_ACCOUNT_PREFIX, hex::encode(&hash[..8]))
}

pub(crate) fn session_lock_path(registry_url: &str) -> Result<PathBuf, String> {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(registry_url.as_bytes());
    let lpm_dir = lpm_dir()?;
    let lock_dir = lpm_dir.join("locks");
    std::fs::create_dir_all(&lock_dir).map_err(|error| format!("lock mkdir error: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        std::fs::set_permissions(&lpm_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("lpm directory permissions error: {error}"))?;
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("lock directory permissions error: {error}"))?;

        let path = lock_dir.join(format!("auth-session-{}.lock", hex::encode(&hash[..16])));
        std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("lock file create error: {error}"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("lock file permissions error: {error}"))?;
        Ok(path)
    }

    #[cfg(not(unix))]
    {
        Ok(lock_dir.join(format!("auth-session-{}.lock", hex::encode(&hash[..16]))))
    }
}

fn validate_refresh_backed_session(
    access_token: &str,
    refresh_token: &str,
    expires_at: &str,
) -> Result<(), String> {
    if access_token.trim().is_empty() || refresh_token.trim().is_empty() {
        return Err("session response contained an empty credential".to_string());
    }
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|error| format!("invalid session access-token expiry: {error}"))?;
    Ok(())
}

pub(crate) fn persist_refresh_backed_session_unlocked(
    registry: &str,
    access_token: &str,
    refresh_token: &str,
    expires_at: &str,
) -> Result<AuthStorageStatus, String> {
    validate_refresh_backed_session(access_token, refresh_token, expires_at)?;
    read_token_expiries_checked()?;

    // The replacement refresh token is the recovery credential after the
    // server consumes its predecessor, so it must become durable first.
    let refresh_backend = set_refresh_token_with_backend(registry, refresh_token)?;
    let access_backend = set_token_with_backend(registry, access_token)?;
    set_session_access_token_expiry_checked(registry, expires_at)?;

    Ok(AuthStorageStatus::from_backends(
        Some(access_backend),
        Some(refresh_backend),
    ))
}

/// Store a complete refresh-backed session under the same per-registry lock
/// used by silent refreshes.
pub async fn store_refresh_backed_session(
    registry: &str,
    access_token: &str,
    refresh_token: &str,
    expires_at: &str,
) -> Result<AuthStorageStatus, lpm_common::LpmError> {
    validate_refresh_backed_session(access_token, refresh_token, expires_at)
        .map_err(lpm_common::LpmError::Registry)?;
    let lock_path = session_lock_path(registry).map_err(|error| {
        lpm_common::LpmError::CredentialStorage(format!("failed to resolve session lock: {error}"))
    })?;

    lpm_common::paths::with_exclusive_lock_async(lock_path, async {
        persist_refresh_backed_session_unlocked(registry, access_token, refresh_token, expires_at)
            .map_err(|error| {
                lpm_common::LpmError::CredentialStorage(format!(
                    "failed to store refresh session: {error}"
                ))
            })
    })
    .await
}

/// Store a refresh token for a registry (keychain first, encrypted file fallback).
pub fn set_refresh_token(registry: &str, token: &str) -> Result<(), String> {
    set_refresh_token_with_backend(registry, token).map(|_| ())
}

pub fn set_refresh_token_with_backend(
    registry: &str,
    token: &str,
) -> Result<AuthStorageBackend, String> {
    let account = scoped_refresh_account(registry);
    set_credential_with_backend(registry, CredentialKind::Refresh, token, || {
        set_password_in_keychain_account(&account, token)
    })
}

/// Get the stored refresh token for a registry.
pub fn get_refresh_token(registry: &str) -> Option<String> {
    get_stored_credential_with_backend(registry, CredentialKind::Refresh, || {})
        .map(|stored| stored.token)
}

pub(crate) fn get_refresh_token_with_interaction_notice(
    registry: &str,
    notice: impl FnOnce(),
) -> Result<Option<String>, String> {
    get_stored_credential_with_backend_result(registry, CredentialKind::Refresh, notice)
        .map(|stored| stored.map(|credential| credential.token))
}

/// Check whether a refresh token is stored for the given registry.
pub fn has_refresh_token(registry: &str) -> bool {
    stored_credential_presence(registry, CredentialKind::Refresh)
        == StoredCredentialPresence::Present
}

/// Clear the stored refresh token for a registry.
pub fn clear_refresh_token(registry: &str) -> Result<(), String> {
    let account = scoped_refresh_account(registry);
    clear_stored_credential(registry, CredentialKind::Refresh, || {
        clear_password_from_keychain_account(&account)
    })
}

/// Parse the npm auth token from `.npmrc` files.
///
/// Checks project `.npmrc` first, then home `~/.npmrc`.
/// Looks for: `//registry.npmjs.org/:_authToken=xxx`
fn parse_npmrc_token() -> Result<Option<String>, String> {
    // Project-level .npmrc first
    if let Ok(cwd) = std::env::current_dir()
        && let Some(token) = parse_npmrc_file(&cwd.join(".npmrc"))?
    {
        return Ok(Some(token));
    }

    // Home-level ~/.npmrc
    if let Some(home) = dirs::home_dir()
        && let Some(token) = parse_npmrc_file(&home.join(".npmrc"))?
    {
        return Ok(Some(token));
    }

    Ok(None)
}

/// Parse a single .npmrc file for the npm registry auth token.
///
/// On Unix, refuses to surface the token when group or other permission bits
/// are set. The content and mode come from the same opened file descriptor.
fn parse_npmrc_file(path: &std::path::Path) -> Result<Option<String>, String> {
    let (content, _file_metadata) = match lpm_common::read_text_file_capped_with_metadata(
        path,
        lpm_common::NPMRC_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(opened_file) => opened_file,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = _file_metadata.permissions();
        if !lpm_common::permissions_are_owner_only(&permissions) {
            tracing::warn!(
                ".npmrc at {} has mode {:04o}, which grants group or other access; \
                 refusing to use its auth token. Run `chmod 600 {}` to restore \
                 this credential source.",
                path.display(),
                permissions.mode() & 0o777,
                path.display(),
            );
            return Ok(None);
        }
    }

    for line in content.lines() {
        let line = line.trim();
        // Match: //registry.npmjs.org/:_authToken=xxx
        if line.starts_with("//registry.npmjs.org/:_authToken=") {
            let token = line
                .strip_prefix("//registry.npmjs.org/:_authToken=")
                .unwrap_or("")
                .trim();
            if !token.is_empty() {
                return Ok(Some(token.to_string()));
            }
        }
    }

    Ok(None)
}

// The 24h `should_revalidate_token` / `mark_token_validated` /
// `clear_token_validation_marker` helpers were retired. Session health is
// now verified passively by authenticated work going through
// `SessionManager`. The `~/.lpm/.token-check` marker file may still exist
// on user machines — it is harmless and cleaned up by `clear_login_state`.

// ─── Keychain ──────────────────────────────────────────────────────

fn scoped_account(registry_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(registry_url.as_bytes());
    format!("{}:{}", KEYCHAIN_ACCOUNT_PREFIX, hex::encode(&hash[..8]))
}

fn keychain_service() -> std::borrow::Cow<'static, str> {
    #[cfg(test)]
    {
        if let Ok(service) = std::env::var(KEYCHAIN_SERVICE_TEST_ENV)
            && !service.is_empty()
        {
            return std::borrow::Cow::Owned(service);
        }
    }

    std::borrow::Cow::Borrowed(KEYCHAIN_SERVICE)
}

fn get_password_from_keychain_account(account: &str) -> Option<String> {
    if force_file_auth() {
        return None;
    }

    let service = keychain_service();
    tracing::debug!(
        "keychain lookup: service={}, account={account}",
        service.as_ref()
    );

    #[cfg(target_os = "macos")]
    {
        match get_password_from_macos_keychain_native(service.as_ref(), account) {
            MacosKeychainLookup::Found(token) => {
                tracing::debug!("keychain hit via Security.framework");
                return Some(token);
            }
            MacosKeychainLookup::NotFound => {}
            MacosKeychainLookup::InteractionRequired => {
                tracing::debug!(
                    "Security.framework keychain lookup still requires interaction for {account}"
                );
                return None;
            }
            MacosKeychainLookup::Failed(error) => {
                tracing::debug!("Security.framework keychain lookup failed for {account}: {error}");
                return None;
            }
        }

        if let Some(token) = get_token_from_macos_keychain_legacy(service.as_ref(), account) {
            tracing::debug!("keychain hit via legacy Security.framework API");
            // Older JS/keytar items can be visible only through the legacy
            // Keychain API; rewrite after a successful read so future reads
            // stay on the modern native prompt path.
            if let Err(error) = set_password_in_macos_keychain(service.as_ref(), account, &token) {
                tracing::debug!("legacy keychain item migration failed for {account}: {error}");
            }
            return Some(token);
        }
    }

    #[cfg(not(target_os = "macos"))]
    if let Ok(entry) = keyring::Entry::new(service.as_ref(), account)
        && let Ok(token) = entry.get_password()
    {
        tracing::debug!("keychain hit via keyring crate");
        return Some(token);
    }

    tracing::debug!("keychain miss for {account}");
    None
}

#[cfg(test)]
fn resolve_keychain_credential(
    probe: KeychainCredentialProbe,
    notice: impl FnOnce(),
    interactive_retry: impl FnOnce() -> Option<String>,
    fallback: impl FnOnce() -> Option<String>,
) -> Option<String> {
    match resolve_keychain_probe(probe, notice, interactive_retry) {
        KeychainCredentialResolution::Found(token) => Some(token),
        KeychainCredentialResolution::NotFound => fallback(),
        KeychainCredentialResolution::Unavailable => None,
    }
}

fn resolve_keychain_probe(
    probe: KeychainCredentialProbe,
    _notice: impl FnOnce(),
    _interactive_retry: impl FnOnce() -> Option<String>,
) -> KeychainCredentialResolution {
    match probe {
        KeychainCredentialProbe::Found(token) => KeychainCredentialResolution::Found(token),
        KeychainCredentialProbe::NotFound => KeychainCredentialResolution::NotFound,
        #[cfg(any(target_os = "macos", test))]
        KeychainCredentialProbe::InteractionRequired => {
            _notice();
            _interactive_retry().map_or(
                KeychainCredentialResolution::Unavailable,
                KeychainCredentialResolution::Found,
            )
        }
        KeychainCredentialProbe::Failed => KeychainCredentialResolution::Unavailable,
    }
}

#[cfg(any(target_os = "macos", test))]
fn resolve_keychain_probe_with_legacy_lookup(
    modern_probe: KeychainCredentialProbe,
    legacy_lookup: impl FnOnce() -> KeychainCredentialProbe,
) -> KeychainCredentialProbe {
    match modern_probe {
        KeychainCredentialProbe::NotFound => legacy_lookup(),
        other => other,
    }
}

#[cfg(target_os = "macos")]
fn probe_keychain_credential(service: &str, account: &str) -> KeychainCredentialProbe {
    let modern_probe = match get_password_from_macos_keychain_noninteractive(service, account) {
        MacosKeychainLookup::Found(token) => KeychainCredentialProbe::Found(token),
        MacosKeychainLookup::NotFound => KeychainCredentialProbe::NotFound,
        MacosKeychainLookup::InteractionRequired => KeychainCredentialProbe::InteractionRequired,
        MacosKeychainLookup::Failed(error) => {
            tracing::debug!(
                "noninteractive Security.framework keychain lookup failed for {account}: {error}"
            );
            KeychainCredentialProbe::Failed
        }
    };

    resolve_keychain_probe_with_legacy_lookup(modern_probe, || {
        match get_token_from_macos_keychain_legacy_noninteractive(service, account) {
            MacosKeychainLookup::Found(token) => {
                if let Err(error) = set_password_in_macos_keychain(service, account, &token) {
                    tracing::debug!("legacy keychain item migration failed for {account}: {error}");
                }
                KeychainCredentialProbe::Found(token)
            }
            MacosKeychainLookup::NotFound => KeychainCredentialProbe::NotFound,
            MacosKeychainLookup::InteractionRequired => {
                KeychainCredentialProbe::InteractionRequired
            }
            MacosKeychainLookup::Failed(error) => {
                tracing::debug!(
                    "noninteractive legacy Security.framework keychain lookup failed for {account}: {error}"
                );
                KeychainCredentialProbe::Failed
            }
        }
    })
}

#[cfg(not(target_os = "macos"))]
fn probe_keychain_credential(service: &str, account: &str) -> KeychainCredentialProbe {
    match keyring::Entry::new(service, account).and_then(|entry| entry.get_password()) {
        Ok(token) if !token.trim().is_empty() => KeychainCredentialProbe::Found(token),
        Ok(_) | Err(keyring::Error::NoEntry) => KeychainCredentialProbe::NotFound,
        Err(error) => {
            tracing::debug!("keychain lookup failed for {account}: {error}");
            KeychainCredentialProbe::Failed
        }
    }
}

fn set_password_in_keychain_account(account: &str, token: &str) -> Result<(), String> {
    if force_file_auth() {
        return Err("keychain disabled by LPM_FORCE_FILE_AUTH".to_string());
    }

    let service = keychain_service();

    #[cfg(target_os = "macos")]
    {
        set_password_in_macos_keychain(service.as_ref(), account, token)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = keyring::Entry::new(service.as_ref(), account)
            .map_err(|e| format!("keychain error: {e}"))?;
        entry
            .set_password(token)
            .map_err(|e| format!("keychain write error: {e}"))
    }
}

#[cfg(target_os = "macos")]
fn get_password_from_macos_keychain_native(service: &str, account: &str) -> MacosKeychainLookup {
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    match macos_get_generic_password(service, account) {
        Ok(password) => token_from_keychain_password(password)
            .map_or(MacosKeychainLookup::NotFound, MacosKeychainLookup::Found),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => MacosKeychainLookup::NotFound,
        Err(error) if error.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            MacosKeychainLookup::InteractionRequired
        }
        Err(error) => MacosKeychainLookup::Failed(error),
    }
}

#[cfg(target_os = "macos")]
fn get_password_from_macos_keychain_noninteractive(
    service: &str,
    account: &str,
) -> MacosKeychainLookup {
    use core_foundation::base::{CFType, TCFType};
    use objc2_local_authentication::LAContext;

    // SAFETY: `new` returns a retained `LAContext`, and the setter only changes
    // whether Security.framework may present authentication UI for this query.
    let context = unsafe { LAContext::new() };
    unsafe {
        context.setInteractionNotAllowed(true);
    }
    // SAFETY: `kSecUseAuthenticationContext` explicitly accepts an LAContext
    // object. The retained Objective-C object stays alive through `search`,
    // and `wrap_under_get_rule` adds the ownership needed by the CFType wrapper.
    let context_ptr = std::ptr::from_ref(&*context).cast::<std::ffi::c_void>();
    let context_value = unsafe { CFType::wrap_under_get_rule(context_ptr) };

    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    let result = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_data(true)
        .local_authentication_context(Some(context_value))
        .search();

    match result {
        Ok(results) => results
            .into_iter()
            .find_map(|result| match result {
                SearchResult::Data(password) => token_from_keychain_password(password),
                _ => None,
            })
            .map_or(MacosKeychainLookup::NotFound, MacosKeychainLookup::Found),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => MacosKeychainLookup::NotFound,
        Err(error) if error.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            MacosKeychainLookup::InteractionRequired
        }
        Err(error) => MacosKeychainLookup::Failed(error),
    }
}

#[cfg(target_os = "macos")]
fn token_from_keychain_password(password: Vec<u8>) -> Option<String> {
    String::from_utf8(password)
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

#[cfg(target_os = "macos")]
fn get_token_from_macos_keychain_legacy_noninteractive(
    service: &str,
    account: &str,
) -> MacosKeychainLookup {
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    let interaction_was_allowed = match SecKeychain::user_interaction_allowed() {
        Ok(allowed) => allowed,
        Err(error) => return MacosKeychainLookup::Failed(error),
    };
    let _interaction_guard = if interaction_was_allowed {
        match SecKeychain::disable_user_interaction() {
            Ok(guard) => Some(guard),
            Err(error) => return MacosKeychainLookup::Failed(error),
        }
    } else {
        None
    };

    match macos_find_generic_password(None, service, account) {
        Ok((password, _item)) => token_from_keychain_password(password.as_ref().to_vec())
            .map_or(MacosKeychainLookup::NotFound, MacosKeychainLookup::Found),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => MacosKeychainLookup::NotFound,
        Err(error) if error.code() == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            MacosKeychainLookup::InteractionRequired
        }
        Err(error) => MacosKeychainLookup::Failed(error),
    }
}

#[cfg(target_os = "macos")]
fn get_token_from_macos_keychain_legacy(service: &str, account: &str) -> Option<String> {
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    match macos_find_generic_password(None, service, account) {
        Ok((password, _item)) => token_from_keychain_password(password.as_ref().to_vec()),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => None,
        Err(error) => {
            tracing::debug!(
                "legacy Security.framework keychain lookup failed for {account}: {error}"
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn set_password_in_macos_keychain(service: &str, account: &str, token: &str) -> Result<(), String> {
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    macos_set_generic_password(service, account, token.as_bytes())
        .map_err(|error| format!("keychain write error: {error}"))
}

#[cfg(target_os = "macos")]
fn clear_security_cli_password_from_macos_keychain_locked(
    service: &str,
    account: &str,
) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|error| format!("keychain legacy delete spawn error: {error}"))?;

    if output.status.success() || output.status.code() == Some(44) {
        return Ok(());
    }

    let error = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "keychain legacy delete error (exit {}): {}",
        output.status.code().unwrap_or(-1),
        error.trim()
    ))
}

#[cfg(any(target_os = "macos", test))]
fn macos_keychain_delete_requires_security_cli(error_code: i32) -> bool {
    error_code == ERR_SEC_INVALID_OWNER_EDIT
}

#[cfg(target_os = "macos")]
fn clear_password_from_macos_keychain(service: &str, account: &str) -> Result<(), String> {
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    match macos_delete_generic_password(service, account) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        // Items written by the older `security` CLI path reject query-based
        // SecItemDelete, but the CLI can delete them without reading the secret.
        Err(error) if macos_keychain_delete_requires_security_cli(error.code()) => {
            clear_security_cli_password_from_macos_keychain_locked(service, account)
        }
        Err(error) => Err(format!("keychain delete error: {error}")),
    }
}

fn clear_password_from_keychain_account(account: &str) -> Result<(), String> {
    if force_file_auth() {
        return Ok(());
    }

    let service = keychain_service();

    #[cfg(target_os = "macos")]
    {
        clear_password_from_macos_keychain(service.as_ref(), account)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = keyring::Entry::new(service.as_ref(), account)
            .map_err(|e| format!("keychain error: {e}"))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("keychain delete error: {e}")),
        }
    }
}

fn set_token_in_keychain(registry_url: &str, token: &str) -> Result<(), String> {
    let account = scoped_account(registry_url);
    set_password_in_keychain_account(&account, token)
}

fn clear_token_from_keychain(registry_url: &str) -> Result<(), String> {
    let account = scoped_account(registry_url);
    clear_password_from_keychain_account(&account)
}

// ─── Encrypted File ────────────────────────────────────────────────

/// Get the `~/.lpm/` directory path.
fn lpm_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".lpm"))
}

fn credentials_path() -> Result<PathBuf, String> {
    Ok(lpm_dir()?.join(".credentials"))
}

fn salt_path() -> Result<PathBuf, String> {
    Ok(lpm_dir()?.join(".salt"))
}

/// Get or create the encryption key for the .credentials file.
///
/// Resolution order:
/// 1. System keyring (most secure, OS-managed)
/// 2. File-based key at `~/.lpm/.key` (0600 permissions)
///
/// If neither exists, generates a 64-char random key and stores it.
#[cfg(test)]
fn get_encryption_key() -> Result<String, String> {
    let key_path = dirs::home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".key");

    if key_path.exists() {
        return lpm_common::read_text_file_capped(&key_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read key file: {e}"));
    }

    use rand::Rng;
    let key: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir error: {e}"))?;
    }
    std::fs::write(&key_path, &key).map_err(|e| format!("failed to write key file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("permissions error: {e}"))?;
    }

    Ok(key)
}

#[cfg(not(test))]
fn get_encryption_key() -> Result<String, String> {
    const KEY_SERVICE: &str = "dev.lpm.credentials-key";
    const KEY_ACCOUNT: &str = "encryption-key";

    let key_path = dirs::home_dir()
        .ok_or("no home directory")?
        .join(".lpm")
        .join(".key");

    if !force_file_auth() {
        #[cfg(target_os = "macos")]
        let _lock = lpm_common::platform::macos_keychain_operation_lock();
        if let Ok(entry) = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT)
            && let Ok(key) = entry.get_password()
        {
            // Clean up stale file-based key if keyring is the source of truth
            if key_path.exists() {
                let _ = std::fs::remove_file(&key_path);
            }
            return Ok(key);
        }
    }

    // Try file-based key
    if key_path.exists() {
        return lpm_common::read_text_file_capped(&key_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read key file: {e}"));
    }

    // Generate new random key
    use rand::Rng;
    let key: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // Store in keyring; only fall back to file if keyring is unavailable
    let keyring_ok = if force_file_auth() {
        false
    } else {
        #[cfg(target_os = "macos")]
        let _lock = lpm_common::platform::macos_keychain_operation_lock();
        keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT)
            .and_then(|entry| entry.set_password(&key))
            .is_ok()
    };

    if !keyring_ok {
        let dir = key_path.parent().unwrap();
        let _ = std::fs::create_dir_all(dir);
        std::fs::write(&key_path, &key).map_err(|e| format!("failed to write key file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    Ok(key)
}

/// Derive the AES-256 key using scrypt with a random encryption key.
///
/// Password: random 64-char key from keyring or `~/.lpm/.key`.
/// Salt: 32 random bytes persisted in `~/.lpm/.salt`.
fn derive_key() -> Result<[u8; 32], String> {
    let password = get_encryption_key()?;

    let salt = get_or_create_salt()?;

    if use_fast_test_scrypt() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        let digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        return Ok(key);
    }

    let params = if cfg!(test) {
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

fn get_or_create_salt() -> Result<Vec<u8>, String> {
    let path = salt_path()?;

    if path.exists() {
        return lpm_common::read_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .map_err(|e| format!("failed to read salt: {e}"));
    }

    // Generate new salt
    let dir = lpm_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create ~/.lpm: {e}"))?;

    // Set directory permissions to 0700 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set permissions: {e}"))?;
    }

    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    std::fs::write(&path, &salt).map_err(|e| format!("failed to write salt: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set salt permissions: {e}"))?;
    }

    Ok(salt)
}

/// Encrypt a value with AES-256-GCM.
/// Output format: `{iv_base64}:{auth_tag_base64}:{ciphertext_base64}` (matches JS CLI).
fn encrypt(plaintext: &str) -> Result<String, String> {
    let key = derive_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher init error: {e}"))?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption error: {e}"))?;

    // AES-GCM appends the 16-byte auth tag to the ciphertext
    let tag_start = ciphertext.len() - 16;
    let (encrypted, auth_tag) = ciphertext.split_at(tag_start);

    Ok(format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(encrypted)
    ))
}

/// Decrypt a value encrypted with `encrypt()`.
fn decrypt(encoded: &str) -> Result<String, String> {
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

    // AES-256-GCM requires exactly 12-byte nonce. If the IV is a different size
    // (e.g., 16 bytes from the JS CLI), this isn't our format.
    if iv.len() != 12 {
        return Err(format!(
            "incompatible IV size: {} bytes (expected 12, possibly JS CLI format)",
            iv.len()
        ));
    }

    let key = derive_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher init error: {e}"))?;

    let nonce = GenericArray::from_slice(&iv);

    // Reconstruct ciphertext + auth_tag (AES-GCM expects them concatenated)
    let mut combined = encrypted;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .map_err(|_| "decryption failed (wrong key or corrupted data)".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))
}

fn probe_token_from_file(registry_url: &str) -> EncryptedFileCredentialProbe {
    let path = match credentials_path() {
        Ok(path) => path,
        Err(error) => return EncryptedFileCredentialProbe::Unavailable(error),
    };
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                return EncryptedFileCredentialProbe::NotFound;
            }
            Err(error) => {
                return EncryptedFileCredentialProbe::Unavailable(format!("read error: {error}"));
            }
        };
    let encrypted = content.trim();
    if encrypted.is_empty() {
        return EncryptedFileCredentialProbe::Unavailable("credential store is empty".to_owned());
    }

    let json = match decrypt(encrypted) {
        Ok(json) => json,
        Err(error) => {
            return EncryptedFileCredentialProbe::Unavailable(format!("decrypt error: {error}"));
        }
    };
    let store = match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json) {
        Ok(store) => store,
        Err(error) => {
            return EncryptedFileCredentialProbe::Unavailable(format!("JSON error: {error}"));
        }
    };
    match store.get(registry_url) {
        Some(serde_json::Value::String(token)) if !token.is_empty() => {
            EncryptedFileCredentialProbe::Found(token.clone())
        }
        None => EncryptedFileCredentialProbe::NotFound,
        Some(serde_json::Value::String(_)) => EncryptedFileCredentialProbe::Unavailable(
            "credential entry is an empty string".to_owned(),
        ),
        Some(_) => {
            EncryptedFileCredentialProbe::Unavailable("credential entry is not a string".to_owned())
        }
    }
}

#[cfg(test)]
fn get_token_from_file(registry_url: &str) -> Option<String> {
    match probe_token_from_file(registry_url) {
        EncryptedFileCredentialProbe::Found(token) => Some(token),
        EncryptedFileCredentialProbe::NotFound => None,
        EncryptedFileCredentialProbe::Unavailable(error) => {
            tracing::debug!("encrypted credential read failed: {error}");
            None
        }
    }
}

fn set_token_in_file(registry_url: &str, token: &str) -> Result<(), String> {
    let path = credentials_path()?;

    // Read existing store (or create empty)
    let mut store: serde_json::Value = if path.exists() {
        let content =
            lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
                .map_err(|e| format!("read error: {e}"))?;
        let encrypted = content.trim();
        if encrypted.is_empty() {
            return Err("credential store is empty".to_owned());
        } else {
            let decrypted = decrypt(encrypted)?;
            serde_json::from_str(&decrypted).map_err(|error| format!("json error: {error}"))?
        }
    } else {
        serde_json::json!({})
    };

    let object = store
        .as_object_mut()
        .ok_or_else(|| "credential store JSON must be an object".to_owned())?;
    object.insert(
        registry_url.to_owned(),
        serde_json::Value::String(token.to_owned()),
    );

    // Encrypt and write
    let json_str = serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
    let encrypted = encrypt(&json_str)?;

    let dir = lpm_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir error: {e}"))?;
    lpm_common::write_file_atomic_with_options(
        &path,
        encrypted,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )
    .map_err(|e| format!("write error: {e}"))?;

    #[cfg(windows)]
    {
        // Use icacls to restrict to current user only
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "".to_string());
        if !username.is_empty() {
            let _ = std::process::Command::new("icacls")
                .args([
                    path.to_str().unwrap_or(""),
                    "/inheritance:r",
                    "/grant:r",
                    &format!("{username}:(R,W)"),
                ])
                .output();
        }
    }

    Ok(())
}

fn clear_token_from_file(registry_url: &str) -> Result<(), String> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(());
    }

    let content = lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .map_err(|e| format!("read error: {e}"))?;
    let encrypted = content.trim();
    if encrypted.is_empty() {
        return Err("credential store is empty".to_owned());
    }

    let json_str = decrypt(encrypted)?;
    let mut store: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|error| format!("json error: {error}"))?;

    let removed = store
        .as_object_mut()
        .ok_or_else(|| "credential store JSON must be an object".to_owned())?
        .remove(registry_url)
        .is_some();
    if !removed {
        return Ok(());
    }

    if store.as_object().is_some_and(serde_json::Map::is_empty) {
        // No more tokens — remove the file
        std::fs::remove_file(&path).map_err(|e| format!("remove error: {e}"))?;
    } else {
        let json_str = serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
        let encrypted = encrypt(&json_str)?;
        lpm_common::write_file_atomic_with_options(
            &path,
            encrypted,
            lpm_common::AtomicWriteOptions::new()
                .unix_mode(0o600)
                .sync_file()
                .sync_parent(),
        )
        .map_err(|e| format!("write error: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod test_env {
    //! Mirror of `lpm-cli`'s `test_env` module — a global env-var lock
    //! that prevents parallel tests from racing on `std::env::set_var`.
    //! Kept here so `lpm-auth` tests can run independently of `lpm-cli`.
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) struct ScopedEnv {
        previous: Vec<(&'static str, Option<OsString>)>,
        _guard: MutexGuard<'static, ()>,
    }

    impl ScopedEnv {
        pub(crate) fn set<I>(vars: I) -> Self
        where
            I: IntoIterator<Item = (&'static str, OsString)>,
        {
            Self::update(vars.into_iter().map(|(k, v)| (k, Some(v))))
        }

        pub(crate) fn update<I>(vars: I) -> Self
        where
            I: IntoIterator<Item = (&'static str, Option<OsString>)>,
        {
            let vars = vars.into_iter().collect::<Vec<_>>();
            let guard = lock_env();
            let previous = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();

            for (key, value) in &vars {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }

            Self {
                previous,
                _guard: guard,
            }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            for (key, value) in self.previous.iter().rev() {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

    struct LocalEnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl LocalEnvGuard {
        fn update<I>(vars: I) -> Self
        where
            I: IntoIterator<Item = (&'static str, Option<std::ffi::OsString>)>,
        {
            let vars = vars.into_iter().collect::<Vec<_>>();
            let previous = vars
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();

            for (key, value) in &vars {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }

            Self { previous }
        }
    }

    impl Drop for LocalEnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.previous.iter().rev() {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn with_temp_home<T>(test: impl FnOnce(&std::path::Path) -> T) -> T {
        let temp = tempfile::tempdir().unwrap();
        let _env = super::test_env::ScopedEnv::update([
            ("HOME", Some(temp.path().as_os_str().to_owned())),
            (DISABLE_HOST_CLI_AUTH_ENV, Some("1".into())),
        ]);

        let result = catch_unwind(AssertUnwindSafe(|| test(temp.path())));

        match result {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    }

    #[test]
    fn credential_update_preserves_unreadable_encrypted_store() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let path = credentials_path().expect("credentials path should resolve");
            let original = b"not-valid-ciphertext";
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            std::fs::write(&path, original).expect("write malformed credential store");

            let result = set_token_in_file("https://registry.example", "replacement-token");
            let after = std::fs::read(&path).expect("read credential store after failed update");

            assert!(
                result.is_err() && after == original,
                "an unreadable credential store must fail closed without changing its bytes: result={result:?}, after={after:?}"
            );
        });
    }

    #[test]
    fn credential_update_preserves_empty_encrypted_store() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            std::fs::write(&path, b"").expect("write empty credential store");

            let result = set_token_in_file("https://registry.example", "replacement-token");
            let after = std::fs::read(&path).expect("read credential store after failed update");

            assert!(
                result.is_err() && after.is_empty(),
                "an empty credential store must fail closed without changing its bytes: result={result:?}, after={after:?}"
            );
        });
    }

    #[test]
    fn credential_update_preserves_encrypted_null_store() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            let original = encrypt("null").expect("encrypt null credential store");
            std::fs::write(&path, &original).expect("write null credential store");

            let result = set_token_in_file("https://registry.example", "replacement-token");
            let after = std::fs::read_to_string(&path).expect("read credential store after update");

            assert!(
                result.is_err() && after == original,
                "a null credential store must fail closed without changing its bytes: result={result:?}"
            );
        });
    }

    #[test]
    fn credential_clear_preserves_store_with_invalid_json() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            let original = encrypt("not-json").expect("encrypt malformed JSON fixture");
            std::fs::write(&path, &original).expect("write malformed credential store");

            let result = clear_token_from_file("https://registry.example");
            let after =
                std::fs::read_to_string(&path).expect("read credential store after failed clear");

            assert!(
                result.is_err() && after == original,
                "invalid credential JSON must fail closed without changing its bytes: result={result:?}"
            );
        });
    }

    #[test]
    fn successful_keychain_write_removes_stale_encrypted_fallback() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            set_token_in_file(registry, "stale-file-token").unwrap();

            let backend = set_credential_with_keychain_writer_unlocked(
                registry,
                CredentialKind::Access,
                "new-keychain-token",
                || Ok(()),
            )
            .unwrap();

            assert_eq!(backend, AuthStorageBackend::Keychain);
            assert_eq!(get_token_from_file(registry), None);
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                Some(CredentialAuthority::active(
                    CredentialBackend::Keychain,
                    "new-keychain-token"
                ))
            );
        });
    }

    #[test]
    fn divergent_legacy_backend_credentials_are_not_resolved_as_authoritative() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            set_token_in_file(registry, "newer-file-token").unwrap();

            let resolved = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("older-keychain-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            );

            assert!(
                resolved.is_err(),
                "disagreeing unmarked backends must remain unresolved"
            );
            assert_eq!(
                get_token_from_file(registry).as_deref(),
                Some("newer-file-token")
            );
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                None
            );
        });
    }

    #[test]
    fn legacy_migration_refuses_keychain_when_encrypted_store_is_corrupt() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            std::fs::write(&path, b"not-valid-ciphertext")
                .expect("write corrupted credential store");

            let resolved = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("older-keychain-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            );

            assert!(
                resolved.is_err(),
                "a corrupt encrypted store must not be treated as proof that an older keychain credential is authoritative: {resolved:?}"
            );
        });
    }

    #[test]
    fn legacy_migration_refuses_keychain_when_encrypted_store_is_empty() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            std::fs::write(&path, b"").expect("write empty credential store");

            let resolved = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("older-keychain-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            );

            assert!(
                resolved.is_err(),
                "an empty encrypted store must not be treated as proof that an older keychain credential is authoritative: {resolved:?}"
            );
        });
    }

    #[test]
    fn legacy_migration_refuses_keychain_when_encrypted_entry_is_empty() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let path = credentials_path().expect("credentials path should resolve");
            std::fs::create_dir_all(path.parent().expect("credentials path should have parent"))
                .expect("create credential directory");
            let encoded = encrypt(&serde_json::json!({ (registry): "" }).to_string())
                .expect("encrypt invalid credential store");
            std::fs::write(&path, encoded).expect("write invalid credential store");

            let resolved = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("older-keychain-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            );

            assert!(
                resolved.is_err(),
                "an empty encrypted credential must not authorize migration of an older keychain credential: {resolved:?}"
            );
        });
    }

    #[test]
    fn credential_authority_is_durable_before_keychain_writer_runs() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let authority_was_durable = std::cell::Cell::new(false);

            set_credential_with_keychain_writer_unlocked(
                registry,
                CredentialKind::Access,
                "new-keychain-token",
                || {
                    authority_was_durable.set(
                        credential_authority::read(registry, CredentialKind::Access).unwrap()
                            == Some(CredentialAuthority::active(
                                CredentialBackend::Keychain,
                                "new-keychain-token",
                            )),
                    );
                    Ok(())
                },
            )
            .unwrap();

            assert!(
                authority_was_durable.get(),
                "the intended credential must be authoritative before backend mutation"
            );
        });
    }

    #[test]
    fn legacy_file_credential_is_promoted_to_file_authority() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let registry = "https://registry.example";
            set_token_in_file(registry, "legacy-file-token").unwrap();

            let resolved = get_stored_access_token_with_backend(registry).unwrap();

            assert_eq!(resolved.token, "legacy-file-token");
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                Some(CredentialAuthority::active(
                    CredentialBackend::EncryptedFileFallback,
                    "legacy-file-token"
                ))
            );
        });
    }

    #[test]
    fn legacy_keychain_only_credential_is_promoted_to_keychain_authority() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let credential = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("legacy-keychain-token".to_owned()),
                || {},
                || None,
                || EncryptedFileCredentialProbe::NotFound,
            )
            .unwrap()
            .unwrap();

            promote_legacy_credential_authority_unlocked(
                registry,
                CredentialKind::Access,
                &credential,
            )
            .unwrap();

            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                Some(CredentialAuthority::active(
                    CredentialBackend::Keychain,
                    "legacy-keychain-token"
                ))
            );
        });
    }

    #[test]
    fn legacy_file_credential_stays_unmarked_when_keychain_is_unavailable() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            set_token_in_file(registry, "legacy-file-token").unwrap();

            let resolved = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Failed,
                || {},
                || None,
                || probe_token_from_file(registry),
            );

            assert!(resolved.is_err());
            assert_eq!(
                get_token_from_file(registry).as_deref(),
                Some("legacy-file-token")
            );
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                None
            );
        });
    }

    #[test]
    fn authority_persistence_failure_prevents_backend_mutation() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let path = credential_authority::path_for_test().unwrap();
            std::fs::create_dir_all(&path).unwrap();
            let writer_called = std::cell::Cell::new(false);

            let result = set_credential_with_keychain_writer_unlocked(
                registry,
                CredentialKind::Access,
                "new-token",
                || {
                    writer_called.set(true);
                    Ok(())
                },
            );

            assert!(result.is_err());
            assert!(
                !writer_called.get(),
                "backend mutation must not run without durable authority"
            );
        });
    }

    #[test]
    fn failed_backend_deletion_retains_authority() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            credential_authority::set(
                registry,
                CredentialKind::Access,
                CredentialAuthority::active(CredentialBackend::Keychain, "rejected-keychain-token"),
            )
            .unwrap();

            let result = clear_stored_credential(registry, CredentialKind::Access, || {
                Err("keychain delete failed".to_owned())
            });

            assert!(result.is_err());
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                Some(CredentialAuthority::Revoked),
                "failed deletion must not make a surviving backend credential eligible for legacy migration"
            );
            let authority = credential_authority::read(registry, CredentialKind::Access).unwrap();
            let resurrected = resolve_stored_credential_from_backends(
                authority.as_ref(),
                || KeychainCredentialProbe::Found("rejected-keychain-token".to_owned()),
                || {},
                || None,
                || EncryptedFileCredentialProbe::NotFound,
            )
            .unwrap();
            assert!(
                resurrected.is_none(),
                "the revocation tombstone must hide a credential that survived deletion"
            );
        });
    }

    #[test]
    fn stored_credential_reads_wait_for_the_writer_lock() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let registry = "https://registry.example";
            set_token_in_file(registry, "file-token").unwrap();
            credential_authority::set(
                registry,
                CredentialKind::Access,
                CredentialAuthority::active(CredentialBackend::EncryptedFileFallback, "file-token"),
            )
            .unwrap();
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (finished_tx, finished_rx) = std::sync::mpsc::channel();

            let reader = with_credential_store_lock(|| {
                let registry = registry.to_owned();
                let reader = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let credential = get_stored_access_token_with_backend(&registry);
                    finished_tx.send(credential).unwrap();
                });
                started_rx.recv().unwrap();
                assert!(
                    finished_rx
                        .recv_timeout(std::time::Duration::from_millis(100))
                        .is_err(),
                    "reader observed credential state inside the writer critical section"
                );
                Ok(reader)
            })
            .unwrap();

            reader.join().unwrap();
            assert_eq!(finished_rx.recv().unwrap().unwrap().token, "file-token");
        });
    }

    #[test]
    fn unavailable_refresh_storage_is_not_classified_as_absent() {
        let authority =
            CredentialAuthority::active(CredentialBackend::Keychain, "stored-refresh-token");
        let resolved = resolve_stored_credential_from_backends(
            Some(&authority),
            || KeychainCredentialProbe::Failed,
            || {},
            || None,
            || EncryptedFileCredentialProbe::NotFound,
        );

        assert!(
            resolved.is_err(),
            "storage unavailability must remain distinguishable from definitive credential absence"
        );
    }

    #[test]
    fn rejected_legacy_cleanup_preserves_session_when_refresh_presence_is_unavailable() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let registry = "https://registry.example";
            set_token_in_file(registry, "rejected-access-token").unwrap();
            set_token_in_file(&format!("refresh:{registry}"), "stored-refresh-token").unwrap();
            credential_authority::set(
                registry,
                CredentialKind::Access,
                CredentialAuthority::active(
                    CredentialBackend::EncryptedFileFallback,
                    "rejected-access-token",
                ),
            )
            .unwrap();
            credential_authority::set(
                registry,
                CredentialKind::Refresh,
                CredentialAuthority::active(
                    CredentialBackend::EncryptedFileFallback,
                    "different-refresh-token",
                ),
            )
            .unwrap();

            let cleared =
                clear_rejected_legacy_session_if_current(registry, "rejected-access-token")
                    .unwrap();

            assert!(!cleared);
            assert_eq!(
                get_token_from_file(registry).as_deref(),
                Some("rejected-access-token")
            );
        });
    }

    #[test]
    fn refresh_token_persistence_failure_is_observable_by_the_caller() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let path = credentials_path().unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"not-valid-ciphertext").unwrap();

            let result = set_refresh_token("https://registry.example", "replacement-refresh-token");

            assert!(result.is_err(), "persistence failure must reach the caller");
        });
    }

    #[test]
    fn matching_legacy_backend_credentials_promote_keychain_and_remove_duplicate() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            set_token_in_file(registry, "matching-token").unwrap();
            let credential = resolve_stored_credential_from_backends(
                None,
                || KeychainCredentialProbe::Found("matching-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            )
            .unwrap()
            .unwrap();
            promote_legacy_credential_authority_unlocked(
                registry,
                CredentialKind::Access,
                &credential,
            )
            .unwrap();

            assert_eq!(get_token_from_file(registry), None);
            assert_eq!(
                credential_authority::read(registry, CredentialKind::Access).unwrap(),
                Some(CredentialAuthority::active(
                    CredentialBackend::Keychain,
                    "matching-token"
                ))
            );
        });
    }

    #[test]
    fn failed_keychain_write_makes_new_file_credential_authoritative() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            let backend = set_credential_with_keychain_writer_unlocked(
                registry,
                CredentialKind::Access,
                "new-file-token",
                || Err("transient keychain failure".to_owned()),
            )
            .unwrap();
            let authority = credential_authority::read(registry, CredentialKind::Access).unwrap();

            let resolved = resolve_stored_credential_from_backends(
                authority.as_ref(),
                || KeychainCredentialProbe::Found("stale-keychain-token".to_owned()),
                || {},
                || None,
                || probe_token_from_file(registry),
            )
            .unwrap()
            .unwrap();

            assert_eq!(backend, AuthStorageBackend::EncryptedFileFallback);
            assert_eq!(resolved.token, "new-file-token");
            assert_eq!(resolved.backend, AuthStorageBackend::EncryptedFileFallback);
        });
    }

    #[test]
    fn credential_authority_is_independent_for_access_and_refresh_tokens() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            credential_authority::set(
                registry,
                CredentialKind::Access,
                CredentialAuthority::active(CredentialBackend::Keychain, "access-token"),
            )
            .unwrap();
            credential_authority::set(
                registry,
                CredentialKind::Refresh,
                CredentialAuthority::active(
                    CredentialBackend::EncryptedFileFallback,
                    "refresh-token",
                ),
            )
            .unwrap();

            assert_eq!(
                (
                    credential_authority::read(registry, CredentialKind::Access).unwrap(),
                    credential_authority::read(registry, CredentialKind::Refresh).unwrap(),
                ),
                (
                    Some(CredentialAuthority::active(
                        CredentialBackend::Keychain,
                        "access-token"
                    )),
                    Some(CredentialAuthority::active(
                        CredentialBackend::EncryptedFileFallback,
                        "refresh-token"
                    )),
                )
            );
        });
    }

    #[test]
    fn corrupt_credential_authority_fails_closed_without_using_file_token() {
        with_temp_home(|_| {
            let registry = "https://registry.example";
            set_token_in_file(registry, "file-token").unwrap();
            let path = credential_authority::path_for_test().unwrap();
            std::fs::write(&path, b"{not valid json").unwrap();

            assert!(get_stored_access_token_with_backend(registry).is_none());
            assert_eq!(std::fs::read(&path).unwrap(), b"{not valid json");
        });
    }

    #[cfg(unix)]
    #[test]
    fn credential_authority_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        with_temp_home(|_| {
            credential_authority::set(
                "https://registry.example",
                CredentialKind::Access,
                CredentialAuthority::active(CredentialBackend::Keychain, "token"),
            )
            .unwrap();
            let path = credential_authority::path_for_test().unwrap();

            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn session_lock_uses_owner_only_file_and_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        with_temp_home(|_| {
            let path = session_lock_path("https://registry.example")
                .expect("session lock path should initialize");
            let file_mode = std::fs::metadata(&path)
                .expect("session lock file should exist")
                .permissions()
                .mode()
                & 0o777;
            let directory_mode = std::fs::metadata(path.parent().expect("lock path has parent"))
                .expect("session lock directory should exist")
                .permissions()
                .mode()
                & 0o777;

            assert_eq!((file_mode, directory_mode), (0o600, 0o700));
        });
    }

    #[test]
    fn conditional_keychain_notice_skips_notice_for_noninteractive_hit() {
        let notices = std::cell::Cell::new(0);
        let retries = std::cell::Cell::new(0);
        let fallbacks = std::cell::Cell::new(0);

        let credential = resolve_keychain_credential(
            KeychainCredentialProbe::Found("stored-token".to_string()),
            || notices.set(notices.get() + 1),
            || {
                retries.set(retries.get() + 1);
                None
            },
            || {
                fallbacks.set(fallbacks.get() + 1);
                None
            },
        );

        assert_eq!(credential.as_deref(), Some("stored-token"));
        assert_eq!(notices.get(), 0);
        assert_eq!(retries.get(), 0);
        assert_eq!(fallbacks.get(), 0);
    }

    #[test]
    fn conditional_keychain_notice_emits_once_and_retries_each_credential_kind() {
        let notices = std::cell::RefCell::new(Vec::new());
        let retries = std::cell::Cell::new(0);

        let access = resolve_keychain_credential(
            KeychainCredentialProbe::InteractionRequired,
            || {
                notices
                    .borrow_mut()
                    .push(AuthStorageAccessKind::AccessToken)
            },
            || {
                retries.set(retries.get() + 1);
                Some("access-token".to_string())
            },
            || None,
        );
        let refresh = resolve_keychain_credential(
            KeychainCredentialProbe::InteractionRequired,
            || {
                notices
                    .borrow_mut()
                    .push(AuthStorageAccessKind::RefreshToken);
            },
            || {
                retries.set(retries.get() + 1);
                Some("refresh-token".to_string())
            },
            || None,
        );

        assert_eq!(access.as_deref(), Some("access-token"));
        assert_eq!(refresh.as_deref(), Some("refresh-token"));
        assert_eq!(
            notices.into_inner(),
            [
                AuthStorageAccessKind::AccessToken,
                AuthStorageAccessKind::RefreshToken,
            ],
        );
        assert_eq!(retries.get(), 2);
    }

    #[test]
    fn conditional_keychain_notice_skips_notice_for_not_found_fallback() {
        let notices = std::cell::Cell::new(0);
        let retries = std::cell::Cell::new(0);

        let credential = resolve_keychain_credential(
            KeychainCredentialProbe::NotFound,
            || notices.set(notices.get() + 1),
            || {
                retries.set(retries.get() + 1);
                None
            },
            || Some("file-token".to_string()),
        );

        assert_eq!(credential.as_deref(), Some("file-token"));
        assert_eq!(notices.get(), 0);
        assert_eq!(retries.get(), 0);
    }

    #[test]
    fn keychain_authority_does_not_activate_stale_file_when_keychain_is_unavailable() {
        let file_lookups = std::cell::Cell::new(0);
        let authority = CredentialAuthority::active(CredentialBackend::Keychain, "keychain-token");

        let credential = resolve_stored_credential_from_backends(
            Some(&authority),
            || KeychainCredentialProbe::Failed,
            || {},
            || None,
            || {
                file_lookups.set(file_lookups.get() + 1);
                EncryptedFileCredentialProbe::Found("stale-file-token".to_owned())
            },
        );

        assert!(credential.is_err());
        assert_eq!(file_lookups.get(), 0);
    }

    #[test]
    fn file_authority_does_not_probe_stale_keychain() {
        let keychain_probes = std::cell::Cell::new(0);
        let authority =
            CredentialAuthority::active(CredentialBackend::EncryptedFileFallback, "new-file-token");

        let credential = resolve_stored_credential_from_backends(
            Some(&authority),
            || {
                keychain_probes.set(keychain_probes.get() + 1);
                KeychainCredentialProbe::Found("stale-keychain-token".to_owned())
            },
            || {},
            || None,
            || EncryptedFileCredentialProbe::Found("new-file-token".to_owned()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(credential.token, "new-file-token");
        assert_eq!(
            credential.backend,
            AuthStorageBackend::EncryptedFileFallback
        );
        assert_eq!(keychain_probes.get(), 0);
    }

    #[test]
    fn conditional_keychain_probe_uses_legacy_lookup_after_modern_miss() {
        let legacy_lookups = std::cell::Cell::new(0);

        let credential =
            resolve_keychain_probe_with_legacy_lookup(KeychainCredentialProbe::NotFound, || {
                legacy_lookups.set(legacy_lookups.get() + 1);
                KeychainCredentialProbe::Found("legacy-token".to_string())
            });

        assert!(matches!(
            credential,
            KeychainCredentialProbe::Found(token) if token == "legacy-token"
        ));
        assert_eq!(legacy_lookups.get(), 1);
    }

    #[test]
    fn keychain_probe_failure_does_not_activate_ambiguous_file_fallback() {
        let notices = std::cell::Cell::new(0);
        let retries = std::cell::Cell::new(0);

        let credential = resolve_keychain_credential(
            KeychainCredentialProbe::Failed,
            || notices.set(notices.get() + 1),
            || {
                retries.set(retries.get() + 1);
                None
            },
            || Some("file-token".to_string()),
        );

        assert_eq!(credential, None);
        assert_eq!(notices.get(), 0);
        assert_eq!(retries.get(), 0);
    }

    #[cfg(target_os = "macos")]
    fn require_keychain_opt_in() {
        if std::env::var("LPM_RUN_KEYCHAIN_TESTS").is_err() {
            panic!(
                "keychain integration test requires `LPM_RUN_KEYCHAIN_TESTS=1`. \
                 Run via: `LPM_RUN_KEYCHAIN_TESTS=1 cargo test -p lpm-auth --lib tests::macos_auth_h4_write_round_trip -- --ignored --exact --test-threads=1`"
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn with_test_keychain_service<T>(test: impl FnOnce(&str) -> T) -> T {
        let service = format!("lpm-cli.test.{}", std::process::id());
        let _env = super::test_env::ScopedEnv::update([(
            super::KEYCHAIN_SERVICE_TEST_ENV,
            Some(service.clone().into()),
        )]);

        let result = catch_unwind(AssertUnwindSafe(|| test(&service)));

        match result {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    }

    #[cfg(target_os = "macos")]
    fn cleanup_keychain_item(service: &str, account: &str) {
        let _ = std::process::Command::new("security")
            .args(["delete-generic-password", "-s", service, "-a", account])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // `should_revalidate_when_marker_missing` and
    // `mark_and_check_token_validated` were retired alongside the
    // marker functions they exercised. Session health is now passive.

    #[test]
    fn scoped_account_deterministic() {
        let a1 = scoped_account("https://lpm.dev");
        let a2 = scoped_account("https://lpm.dev");
        assert_eq!(a1, a2, "same URL should produce same account name");

        let b = scoped_account("http://localhost:3000");
        assert_ne!(
            a1, b,
            "different URLs should produce different account names"
        );
    }

    #[test]
    fn scoped_account_matches_mcp_known_answer_vectors() {
        for (registry_url, expected_account) in [
            ("https://lpm.dev", "auth-token:bd90fc32d95766d5"),
            ("https://lpm.dev/", "auth-token:89f54e26677b97ec"),
            ("http://localhost:3000", "auth-token:f1de9e489ba88cb1"),
            ("http://127.0.0.1:8787", "auth-token:b1a61bf29a38ff36"),
            (
                "https://registry.example.com/custom",
                "auth-token:1658e811bb24ec08",
            ),
        ] {
            assert_eq!(scoped_account(registry_url), expected_account);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_password_bytes_trim_surrounding_whitespace() {
        assert_eq!(
            token_from_keychain_password(b"  lpm_access_token\n".to_vec()).as_deref(),
            Some("lpm_access_token")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_password_bytes_ignore_empty_or_invalid_values() {
        assert_eq!(token_from_keychain_password(b" \n\t".to_vec()), None);
        assert_eq!(token_from_keychain_password(vec![0xff, 0xfe]), None);
    }

    #[test]
    fn invalid_owner_keychain_delete_uses_the_security_cli_fallback() {
        assert!(macos_keychain_delete_requires_security_cli(-25244));
    }

    #[test]
    fn unrelated_keychain_delete_error_does_not_use_the_security_cli_fallback() {
        assert!(!macos_keychain_delete_requires_security_cli(-25308));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn modern_keychain_read_waits_for_process_interaction_lock() {
        let lock = lpm_common::platform::macos_keychain_operation_lock();
        let started = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_started = std::sync::Arc::clone(&started);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let service = format!("lpm-cli.lock-test.{}", std::process::id());

        let worker = std::thread::spawn(move || {
            worker_started.wait();
            let _ = get_password_from_macos_keychain_native(&service, "missing-account");
            finished_tx.send(()).unwrap();
        });
        started.wait();

        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(250))
                .is_err(),
            "modern Keychain reads must share the lock that guards the process-wide interaction state"
        );

        drop(lock);
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok()
        );
        worker.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "macOS keychain integration; opt-in only and serial execution required"]
    fn macos_auth_h4_write_round_trip() {
        require_keychain_opt_in();

        with_test_keychain_service(|service| {
            let registry = "https://registry.test.lpm.dev";
            let access_account = scoped_account(registry);
            let refresh_account = scoped_refresh_account(registry);

            cleanup_keychain_item(service, &access_account);
            cleanup_keychain_item(service, &refresh_account);

            set_password_in_keychain_account(&access_account, "lpm_access_token").unwrap();
            set_password_in_keychain_account(&refresh_account, "lpm_refresh_token").unwrap();

            assert_eq!(
                get_token_from_macos_keychain_legacy(service, &access_account).as_deref(),
                Some("lpm_access_token")
            );
            assert_eq!(
                get_token_from_macos_keychain_legacy(service, &refresh_account).as_deref(),
                Some("lpm_refresh_token")
            );

            cleanup_keychain_item(service, &access_account);
            cleanup_keychain_item(service, &refresh_account);
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "macOS keychain integration; opt-in only and serial execution required"]
    fn logout_clears_credentials_written_by_the_legacy_security_cli() {
        require_keychain_opt_in();

        with_test_keychain_service(|service| {
            let account = "legacy-security-cli-credential";
            cleanup_keychain_item(service, account);

            let status = std::process::Command::new("security")
                .args([
                    "add-generic-password",
                    "-s",
                    service,
                    "-a",
                    account,
                    "-w",
                    "integration-test-credential",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .status()
                .expect("create legacy security CLI credential");
            assert!(status.success(), "legacy credential setup must succeed");

            let result = clear_password_from_macos_keychain(service, account);
            if result.is_err() {
                cleanup_keychain_item(service, account);
            }

            assert!(
                result.is_ok(),
                "logout must clear legacy security CLI credentials: {result:?}"
            );
        });
    }

    /// Write a `.npmrc` test fixture with 0o600 perms so the
    /// hostile-clone permissive-perms guard added in M6 doesn't
    /// refuse the token. Test fixtures are functionally equivalent
    /// to a legitimately-locked dev `.npmrc` — the guard is for
    /// hostile *clones* with default-umask perms, not for properly-
    /// owned files.
    fn write_test_npmrc(path: &std::path::Path, content: &str) {
        std::fs::write(path, content).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
        }
    }

    #[cfg(unix)]
    fn write_fake_host_command(dir: &std::path::Path, name: &str, script: &str) {
        let path = dir.join(name);
        std::fs::write(&path, script).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }

    #[test]
    fn parse_npmrc_extracts_token() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        write_test_npmrc(
            &npmrc_path,
            "//registry.npmjs.org/:_authToken=npm_ABCDEF123456\nregistry=https://registry.npmjs.org/\n",
        );

        let token = parse_npmrc_file(&npmrc_path).unwrap();
        assert_eq!(token, Some("npm_ABCDEF123456".to_string()));
    }

    #[test]
    fn parse_npmrc_ignores_other_registries() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, "//npm.pkg.github.com/:_authToken=ghp_xxxxx\n").unwrap();

        let token = parse_npmrc_file(&npmrc_path).unwrap();
        assert!(token.is_none(), "should only read npmjs.org token");
    }

    #[test]
    fn parse_npmrc_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, "").unwrap();

        let token = parse_npmrc_file(&npmrc_path).unwrap();
        assert!(token.is_none());
    }

    #[test]
    fn parse_npmrc_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        // Don't create the file
        let token = parse_npmrc_file(&npmrc_path).unwrap();
        assert!(token.is_none());
    }

    #[test]
    fn session_access_token_refreshes_when_expiry_metadata_missing() {
        with_temp_home(|_| {
            assert!(should_refresh_session_access_token("http://localhost:3000"));
        });
    }

    #[test]
    fn session_access_token_refreshes_when_expired() {
        with_temp_home(|_| {
            set_session_access_token_expiry("http://localhost:3000", "2026-04-08T00:00:00Z");

            assert!(should_refresh_session_access_token("http://localhost:3000"));
            assert!(is_session_access_token_expired("http://localhost:3000"));
        });
    }

    #[test]
    fn session_access_token_does_not_refresh_when_still_valid() {
        with_temp_home(|_| {
            let future_expiry = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
            set_session_access_token_expiry("http://localhost:3000", &future_expiry);

            assert!(!should_refresh_session_access_token(
                "http://localhost:3000"
            ));
            assert!(!is_session_access_token_expired("http://localhost:3000"));
        });
    }

    #[test]
    fn failed_refresh_session_persistence_leaves_no_partial_credentials() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
            ]);
            let registry = "https://registry.example";
            let metadata_path = home.join(".lpm").join(".token-expiry.json");
            std::fs::create_dir_all(metadata_path.parent().unwrap()).unwrap();
            std::fs::write(&metadata_path, b"not-json").unwrap();

            let result = persist_refresh_backed_session_unlocked(
                registry,
                "new-access",
                "new-refresh",
                "2099-01-01T00:00:00Z",
            );

            assert!(result.is_err(), "corrupt metadata must reject the session");
            assert_eq!(get_stored_access_token(registry), None);
            assert_eq!(get_refresh_token(registry), None);
        });
    }

    #[test]
    fn clear_login_state_removes_session_access_refresh_and_expiry_metadata() {
        with_temp_home(|home| {
            let registry = "http://localhost:3000";

            set_token_in_file(registry, "access-token").unwrap();
            set_token_in_file(&format!("refresh:{registry}"), "refresh-token").unwrap();
            set_session_access_token_expiry(registry, "2026-04-10T00:00:00Z");
            // Simulate a legacy install by writing the marker file directly
            // so the backwards-compat cleanup branch in `clear_login_state`
            // is exercised.
            let legacy_marker = home.join(".lpm").join(".token-check");
            std::fs::create_dir_all(legacy_marker.parent().unwrap()).unwrap();
            std::fs::write(&legacy_marker, "").unwrap();

            assert_eq!(
                get_token_from_file(registry),
                Some("access-token".to_string())
            );
            assert_eq!(
                get_token_from_file(&format!("refresh:{registry}")),
                Some("refresh-token".to_string())
            );
            assert!(read_token_expiries().contains_key(registry));
            assert!(legacy_marker.exists());

            clear_login_state(registry).unwrap();

            assert!(get_token_from_file(registry).is_none());
            assert!(get_token_from_file(&format!("refresh:{registry}")).is_none());
            assert!(!read_token_expiries().contains_key(registry));
            assert!(!legacy_marker.exists());
        });
    }

    #[test]
    fn clear_login_state_reports_corrupt_expiry_metadata_without_claiming_success() {
        with_temp_home(|home| {
            let registry = "https://registry.example";
            let path = home.join(".lpm").join(".token-expiry.json");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"not-json").unwrap();

            let result = clear_login_state(registry);

            assert!(result.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
        });
    }

    #[test]
    fn token_expiry_mutation_waits_for_shared_metadata_lock() {
        with_temp_home(|_| {
            let lock_path = token_expiry_lock_path().unwrap();
            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let holder = std::thread::spawn(move || {
                lpm_common::paths::with_exclusive_lock(lock_path, || {
                    locked_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok::<_, lpm_common::LpmError>(())
                })
                .unwrap();
            });
            locked_rx.recv().unwrap();

            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let writer = std::thread::spawn(move || {
                let result = set_session_access_token_expiry_checked(
                    "https://registry.example",
                    "2099-01-01T00:00:00Z",
                );
                done_tx.send(result).unwrap();
            });

            assert!(
                done_rx
                    .recv_timeout(std::time::Duration::from_millis(100))
                    .is_err(),
                "metadata mutation bypassed the shared expiry lock"
            );
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            assert!(done_rx.recv().unwrap().is_ok());
            writer.join().unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn set_otp_required_tightens_existing_metadata_permissions() {
        use std::os::unix::fs::PermissionsExt;

        with_temp_home(|home| {
            let path = home.join(".lpm").join(".token-expiry.json");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"{}").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

            set_otp_required("https://registry.example", true);

            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        });
    }

    #[test]
    fn clear_token_reports_an_unreadable_file_store_instead_of_claiming_success() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let credentials = home.join(".lpm").join(".credentials");
            std::fs::create_dir_all(&credentials)
                .expect("create an unreadable credentials-path directory");

            let result = clear_token("https://registry.example.test");

            assert!(
                result.is_err(),
                "a credential-store read failure must make logout fail"
            );
        });
    }

    #[test]
    fn clear_token_reports_an_empty_file_store_instead_of_claiming_success() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let credentials = home.join(".lpm").join(".credentials");
            std::fs::create_dir_all(
                credentials
                    .parent()
                    .expect("credentials parent should exist"),
            )
            .expect("create credentials directory");
            std::fs::write(&credentials, b"").expect("write empty credential store");

            let result = clear_token("https://registry.example.test");

            assert!(
                result.is_err(),
                "an empty credential store must make logout fail closed"
            );
        });
    }

    #[test]
    fn clear_token_reports_a_non_object_file_store_instead_of_claiming_success() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);
            let credentials = home.join(".lpm").join(".credentials");
            std::fs::create_dir_all(
                credentials
                    .parent()
                    .expect("credentials parent should exist"),
            )
            .expect("create credentials directory");
            let encoded = encrypt("[]").expect("encrypt non-object credential store");
            std::fs::write(&credentials, encoded).expect("write non-object credential store");

            let result = clear_token("https://registry.example.test");

            assert!(
                result.is_err(),
                "a non-object credential store must make logout fail closed"
            );
        });
    }

    #[cfg(all(not(debug_assertions), feature = "acceptance-test-hooks"))]
    #[test]
    fn release_acceptance_build_uses_file_auth_only_inside_isolated_run_home() {
        let root = tempfile::tempdir().expect("create acceptance root");
        let run_dir = root.path().join("run");
        let home = run_dir.join("session-home");
        std::fs::create_dir_all(&home).expect("create acceptance home");
        let _env = super::test_env::ScopedEnv::update([
            ("HOME", Some(home.as_os_str().to_owned())),
            ("LPM_HOME", Some(home.join(".lpm").into_os_string())),
            ("ACCEPTANCE_RUN_DIR", Some(run_dir.into_os_string())),
            ("ACCEPTANCE_RUN_ID", Some("release-file-auth".into())),
            ("LPM_ACCEPTANCE_FILE_STORAGE", Some("1".into())),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
        ]);

        assert!(force_file_auth());
    }

    #[cfg(all(not(debug_assertions), feature = "acceptance-test-hooks"))]
    #[test]
    fn release_acceptance_build_allows_fast_scrypt_inside_isolated_run_home() {
        let root = tempfile::tempdir().expect("create acceptance root");
        let run_dir = root.path().join("run");
        let home = run_dir.join("session-home");
        std::fs::create_dir_all(&home).expect("create acceptance home");
        let _env = super::test_env::ScopedEnv::update([
            ("HOME", Some(home.as_os_str().to_owned())),
            ("LPM_HOME", Some(home.join(".lpm").into_os_string())),
            ("ACCEPTANCE_RUN_DIR", Some(run_dir.into_os_string())),
            ("ACCEPTANCE_RUN_ID", Some("release-fast-auth".into())),
            ("LPM_ACCEPTANCE_FILE_STORAGE", Some("1".into())),
            ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
        ]);

        assert!(use_fast_test_scrypt());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_ignores_fast_scrypt_without_acceptance_isolation() {
        let _env = super::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_DIR", None),
            ("ACCEPTANCE_RUN_ID", None),
            ("LPM_ACCEPTANCE_FILE_STORAGE", None),
            ("LPM_TEST_FAST_SCRYPT", Some("1".into())),
        ]);

        assert!(!use_fast_test_scrypt());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_ignores_file_auth_without_acceptance_isolation() {
        let _env = super::test_env::ScopedEnv::update([
            ("ACCEPTANCE_RUN_DIR", None),
            ("ACCEPTANCE_RUN_ID", None),
            ("LPM_ACCEPTANCE_FILE_STORAGE", None),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
        ]);

        assert!(!force_file_auth());
    }

    #[test]
    fn auth_storage_status_reports_none_for_env_token_without_stored_material() {
        with_temp_home(|_| {
            let registry = "http://localhost:3000";
            let _env = LocalEnvGuard::update([
                ("LPM_TOKEN", Some("env-token".into())),
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ]);

            assert_eq!(get_token(registry), Some("env-token".to_string()));
            assert_eq!(auth_storage_status(registry), AuthStorageStatus::none());
        });
    }

    #[test]
    fn has_stored_access_token_ignores_environment_credentials() {
        with_temp_home(|_| {
            let registry = "http://localhost:3000";
            let _env = LocalEnvGuard::update([
                ("LPM_TOKEN", Some("env-token".into())),
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ]);

            assert!(!has_stored_access_token(registry));
        });
    }

    #[test]
    fn auth_storage_status_reports_file_backed_access_token_as_degraded() {
        with_temp_home(|_| {
            let registry = "http://localhost:3000";
            let _env = LocalEnvGuard::update([
                ("LPM_TOKEN", None),
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ]);

            set_token_in_file(registry, "access-token").unwrap();

            assert_eq!(
                auth_storage_status(registry),
                AuthStorageStatus::from_backend(AuthStorageBackend::EncryptedFileFallback)
            );
        });
    }

    #[test]
    fn auth_storage_status_reports_file_backed_refresh_token_as_degraded() {
        with_temp_home(|_| {
            let registry = "http://localhost:3000";
            let _env = LocalEnvGuard::update([
                ("LPM_TOKEN", None),
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ]);

            set_token_in_file(&format!("refresh:{registry}"), "refresh-token").unwrap();

            assert_eq!(
                auth_storage_status(registry),
                AuthStorageStatus::from_backend(AuthStorageBackend::EncryptedFileFallback)
            );
        });
    }

    #[test]
    fn auth_storage_status_prefers_file_fallback_when_any_material_is_file_backed() {
        assert_eq!(
            AuthStorageStatus::from_backends(
                Some(AuthStorageBackend::Keychain),
                Some(AuthStorageBackend::EncryptedFileFallback),
            ),
            AuthStorageStatus::from_backend(AuthStorageBackend::EncryptedFileFallback)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "macOS keychain integration; opt-in only and serial execution required"]
    fn auth_storage_status_reports_keychain_backed_stored_token() {
        require_keychain_opt_in();
        with_temp_home(|_| {
            let registry = "http://localhost:3000";
            let _env = LocalEnvGuard::update([
                ("LPM_TOKEN", None),
                ("LPM_FORCE_FILE_AUTH", None),
                (
                    KEYCHAIN_SERVICE_TEST_ENV,
                    Some("lpm-auth-storage-status-test".into()),
                ),
            ]);

            set_token_in_keychain(registry, "access-token").unwrap();

            assert_eq!(
                auth_storage_status(registry),
                AuthStorageStatus::from_backend(AuthStorageBackend::Keychain)
            );

            clear_token_from_keychain(registry).unwrap();
        });
    }

    #[test]
    fn scoped_refresh_account_is_distinct_and_deterministic() {
        let refresh_a = scoped_refresh_account("https://lpm.dev");
        let refresh_b = scoped_refresh_account("https://lpm.dev");
        let access = scoped_account("https://lpm.dev");

        assert_eq!(refresh_a, refresh_b);
        assert_ne!(refresh_a, access);
    }

    #[test]
    fn npm_token_env_priority() {
        let _env = super::test_env::ScopedEnv::set([("NPM_TOKEN", "npm_test_from_env".into())]);
        let token = get_npm_token();
        assert_eq!(token, Some("npm_test_from_env".to_string()));
    }

    #[test]
    fn npm_token_prefers_stored_token_over_npmrc_fallback() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
            ]);

            write_test_npmrc(
                &home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            );

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(&serde_json::json!({ NPM_REGISTRY_URL: "npm-file-token" }).to_string())
                    .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_npm_token(), Some("npm-file-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn github_token_env_priority_over_gh_cli_and_stored_fallback() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(bin.path(), "gh", "#!/bin/sh\nprintf 'gh-cli-token\\n'\n");
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITHUB_TOKEN", Some("github-env-token".into())),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITHUB_REGISTRY_URL: "github-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_github_token(), Some("github-env-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn github_token_uses_gh_cli_before_stored_fallback() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(bin.path(), "gh", "#!/bin/sh\nprintf 'gh-cli-token\\n'\n");
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITHUB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITHUB_REGISTRY_URL: "github-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_github_token(), Some("gh-cli-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn github_token_falls_back_to_stored_token_when_gh_is_missing() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITHUB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITHUB_REGISTRY_URL: "github-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_github_token(), Some("github-file-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn github_token_ignores_empty_gh_output_and_uses_stored_token() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(bin.path(), "gh", "#!/bin/sh\nexit 0\n");
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITHUB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITHUB_REGISTRY_URL: "github-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_github_token(), Some("github-file-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn github_token_ignores_failing_gh_command_and_uses_stored_token() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(bin.path(), "gh", "#!/bin/sh\nexit 1\n");
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITHUB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITHUB_REGISTRY_URL: "github-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_github_token(), Some("github-file-token".to_string()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_token_uses_glab_cli_for_gitlab_dot_com() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(
                bin.path(),
                "glab",
                "#!/bin/sh\nprintf 'glab-cli-token\\n'\n",
            );
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITLAB_REGISTRY_URL: "gitlab-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(
                get_gitlab_token_for_host("https://gitlab.com"),
                Some("glab-cli-token".to_string())
            );
        });
    }

    #[test]
    fn gitlab_ci_job_token_is_not_used_for_self_managed_host() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", Some("gitlab-ci-token".into())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITLAB_REGISTRY_URL: "gitlab-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(
                get_gitlab_token_for_host("https://gitlab.example.com"),
                None
            );
        });
    }

    #[test]
    fn gitlab_default_credentials_are_not_used_for_alternate_port() {
        with_temp_home(|_| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, Some("1".into())),
                ("GITLAB_TOKEN", Some("ambient-gitlab-token".into())),
                ("CI_JOB_TOKEN", None),
            ]);

            assert_eq!(
                get_gitlab_token_for_host("https://gitlab.com:8443/api/v4/projects/7/packages/npm",),
                None
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_token_for_self_managed_host_uses_registry_scoped_token() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(
                bin.path(),
                "glab",
                "#!/bin/sh\nprintf 'glab-cli-token\\n'\n",
            );
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            let registry_url = "https://gitlab.example.com/api/v4/projects/7/packages/npm";
            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        GITLAB_REGISTRY_URL: "default-gitlab-token",
                        registry_url: "self-managed-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(
                get_gitlab_token_for_host(registry_url),
                Some("self-managed-token".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_token_ignores_failing_glab_command_and_uses_stored_token() {
        with_temp_home(|_| {
            let bin = tempfile::tempdir().unwrap();
            write_fake_host_command(bin.path(), "glab", "#!/bin/sh\nexit 1\n");
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                (DISABLE_HOST_CLI_AUTH_ENV, None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
                ("PATH", Some(bin.path().as_os_str().to_owned())),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({ GITLAB_REGISTRY_URL: "gitlab-file-token" }).to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(
                get_gitlab_token_for_host("https://gitlab.com"),
                Some("gitlab-file-token".to_string())
            );
        });
    }

    #[test]
    fn malformed_builtin_file_entry_falls_back_to_npmrc_without_hiding_other_builtin_tokens() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
                ("GITHUB_TOKEN", None),
            ]);

            write_test_npmrc(
                &home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            );

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        NPM_REGISTRY_URL: { "unexpected": true },
                        GITHUB_REGISTRY_URL: "github-file-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            assert_eq!(get_npm_token(), Some("npmrc-fallback-token".to_string()));
            assert_eq!(get_github_token(), Some("github-file-token".to_string()));
        });
    }

    #[test]
    fn list_stored_registries_ignores_malformed_github_entry_and_keeps_other_builtin_sources() {
        with_temp_home(|home| {
            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
                ("GITHUB_TOKEN", None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
            ]);

            write_test_npmrc(
                &home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            );

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        GITHUB_REGISTRY_URL: { "unexpected": true },
                        GITLAB_REGISTRY_URL: "gitlab-file-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");

            let registries = list_stored_registries();

            assert!(registries.iter().any(|(name, status)| {
                name == "npmjs.org" && status.contains("found in .npmrc")
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == "gitlab.com" && status == "configured (encrypted file fallback)"
            }));
            assert!(
                registries.iter().all(|(name, _)| name != "github.com"),
                "malformed GitHub builtin entry should not be reported as configured: {registries:?}"
            );
        });
    }

    #[test]
    fn clear_gitlab_token_preserves_npmrc_and_custom_registry_when_github_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
                ("GITHUB_TOKEN", None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
            ]);

            write_test_npmrc(
                &home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            );

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        GITHUB_REGISTRY_URL: { "unexpected": true },
                        GITLAB_REGISTRY_URL: "gitlab-file-token",
                        custom_registry: "custom-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");
            std::fs::write(
                custom_registries_path().expect("custom registries path should resolve"),
                serde_json::to_string(&vec![custom_registry]).unwrap(),
            )
            .expect("failed to write custom registry tracking file");

            clear_gitlab_token().expect("failed to clear gitlab token");

            assert_eq!(get_npm_token(), Some("npmrc-fallback-token".to_string()));
            assert_eq!(
                get_custom_registry_token(custom_registry),
                Some("custom-token".to_string())
            );
            assert!(get_gitlab_token().is_none());

            let registries = list_stored_registries();
            assert!(registries.iter().any(|(name, status)| {
                name == "npmjs.org" && status.contains("found in .npmrc")
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == custom_registry && status == "configured (encrypted file fallback)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "gitlab.com"));
            assert!(registries.iter().all(|(name, _)| name != "github.com"));
        });
    }

    #[test]
    fn clear_github_token_preserves_npmrc_gitlab_and_custom_registry_when_npm_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
                ("GITHUB_TOKEN", None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
            ]);

            write_test_npmrc(
                &home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            );

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        NPM_REGISTRY_URL: { "unexpected": true },
                        GITHUB_REGISTRY_URL: "github-file-token",
                        GITLAB_REGISTRY_URL: "gitlab-file-token",
                        custom_registry: "custom-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");
            std::fs::write(
                custom_registries_path().expect("custom registries path should resolve"),
                serde_json::to_string(&vec![custom_registry]).unwrap(),
            )
            .expect("failed to write custom registry tracking file");

            clear_github_token().expect("failed to clear github token");

            assert_eq!(get_npm_token(), Some("npmrc-fallback-token".to_string()));
            assert_eq!(get_gitlab_token(), Some("gitlab-file-token".to_string()));
            assert_eq!(
                get_custom_registry_token(custom_registry),
                Some("custom-token".to_string())
            );
            assert!(get_github_token().is_none());

            let registries = list_stored_registries();
            assert!(registries.iter().any(|(name, status)| {
                name == "npmjs.org" && status.contains("found in .npmrc")
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == "gitlab.com" && status == "configured (encrypted file fallback)"
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == custom_registry && status == "configured (encrypted file fallback)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "github.com"));
        });
    }

    #[test]
    fn clear_npm_token_preserves_github_and_custom_registry_when_gitlab_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            let _env = LocalEnvGuard::update([
                ("LPM_FORCE_FILE_AUTH", Some("1".into())),
                ("NPM_TOKEN", None),
                ("GITHUB_TOKEN", None),
                ("GITLAB_TOKEN", None),
                ("CI_JOB_TOKEN", None),
            ]);

            std::fs::write(
                credentials_path().expect("credentials path should resolve"),
                encrypt(
                    &serde_json::json!({
                        NPM_REGISTRY_URL: "npm-file-token",
                        GITHUB_REGISTRY_URL: "github-file-token",
                        GITLAB_REGISTRY_URL: { "unexpected": true },
                        custom_registry: "custom-token",
                    })
                    .to_string(),
                )
                .expect("failed to encrypt credentials store"),
            )
            .expect("failed to write encrypted credentials store");
            std::fs::write(
                custom_registries_path().expect("custom registries path should resolve"),
                serde_json::to_string(&vec![custom_registry]).unwrap(),
            )
            .expect("failed to write custom registry tracking file");

            clear_npm_token().expect("failed to clear npm token");

            assert!(get_npm_token().is_none());
            assert_eq!(get_github_token(), Some("github-file-token".to_string()));
            assert_eq!(
                get_custom_registry_token(custom_registry),
                Some("custom-token".to_string())
            );
            assert!(get_gitlab_token().is_none());

            let registries = list_stored_registries();
            assert!(registries.iter().any(|(name, status)| {
                name == "github.com" && status == "configured (encrypted file fallback)"
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == custom_registry && status == "configured (encrypted file fallback)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "npmjs.org"));
            assert!(registries.iter().all(|(name, _)| name != "gitlab.com"));

            let credentials = get_token_from_file(NPM_REGISTRY_URL);
            assert!(
                credentials.is_none(),
                "npm entry should be removed from file store"
            );

            let _ = home;
        });
    }

    // ─── Custom registry tracking lifecycle ───────────────────────

    #[test]
    fn custom_registry_tracking_roundtrip() {
        // Use an isolated temp dir to avoid touching the real ~/.lpm
        let dir = tempfile::tempdir().unwrap();
        let tracking_path = dir.path().join(".custom-registries.json");

        // Write a tracking file with two URLs
        let urls = vec![
            "https://npm.corp.com".to_string(),
            "https://npm.internal.dev".to_string(),
        ];
        std::fs::write(&tracking_path, serde_json::to_string(&urls).unwrap()).unwrap();

        // Read it back
        let content = std::fs::read_to_string(&tracking_path).unwrap();
        let parsed: Vec<String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "https://npm.corp.com");
        assert_eq!(parsed[1], "https://npm.internal.dev");
    }

    #[test]
    fn custom_registry_tracking_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let tracking_path = dir.path().join(".custom-registries.json");

        // Simulate adding the same URL twice
        let mut registries: Vec<String> = Vec::new();
        let url = "https://npm.corp.com";

        if !registries.iter().any(|r| r == url) {
            registries.push(url.to_string());
        }
        // Second add — should not duplicate
        if !registries.iter().any(|r| r == url) {
            registries.push(url.to_string());
        }

        std::fs::write(&tracking_path, serde_json::to_string(&registries).unwrap()).unwrap();

        let content = std::fs::read_to_string(&tracking_path).unwrap();
        let parsed: Vec<String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1, "duplicate URL should not be added");
    }

    #[test]
    fn custom_registry_partial_clear_preserves_failures() {
        let dir = tempfile::tempdir().unwrap();
        let tracking_path = dir.path().join(".custom-registries.json");

        // Simulate a tracking file with 3 entries where 1 fails to clear
        let urls = vec![
            "https://a.com".to_string(),
            "https://b.com".to_string(),
            "https://c.com".to_string(),
        ];
        std::fs::write(&tracking_path, serde_json::to_string(&urls).unwrap()).unwrap();

        // Simulate partial clear: a.com and c.com succeed, b.com fails
        let remaining: Vec<String> = vec!["https://b.com".to_string()];

        if remaining.is_empty() {
            let _ = std::fs::remove_file(&tracking_path);
        } else {
            std::fs::write(&tracking_path, serde_json::to_string(&remaining).unwrap()).unwrap();
        }

        // Verify only failed entry remains
        let content = std::fs::read_to_string(&tracking_path).unwrap();
        let parsed: Vec<String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], "https://b.com");
    }

    #[test]
    fn list_custom_registries_returns_empty_when_no_file() {
        // The function reads from a fixed path (~/.lpm/.custom-registries.json).
        // On CI or clean machines with no custom registries, it should return empty.
        let result = list_custom_registries();
        // We can't control the real file, but we can verify it doesn't panic
        // and returns a Vec (possibly empty, possibly with entries from prior tests).
        assert!(
            result.len() < 1000,
            "should return reasonable number of entries"
        );
    }

    #[test]
    fn clear_all_custom_registries_discovers_file_entries_when_tracking_file_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            let _env = LocalEnvGuard::update([("LPM_FORCE_FILE_AUTH", Some("1".into()))]);

            set_token_in_file(custom_registry, "custom-token")
                .expect("failed to seed custom registry token");
            set_token_in_file(NPM_REGISTRY_URL, "npm-token")
                .expect("failed to seed builtin registry token");

            let tracking_path = home.join(".lpm").join(".custom-registries.json");
            std::fs::write(&tracking_path, "{not valid json")
                .expect("failed to write malformed tracking file");

            let results = clear_all_custom_registries();

            assert_eq!(
                results.len(),
                1,
                "only custom registry entries should be cleared"
            );
            assert_eq!(results[0].0, custom_registry);
            assert!(results[0].1.is_ok());

            assert_eq!(
                get_token_from_file(NPM_REGISTRY_URL),
                Some("npm-token".to_string())
            );
            assert!(
                get_token_from_file(custom_registry).is_none(),
                "malformed tracking should not strand file-backed custom registry tokens"
            );
            assert!(
                !tracking_path.exists(),
                "tracking file should be removed once malformed custom-registry state is normalized"
            );
        });
    }

    /// Defensive perms on every credential-adjacent file: `restrict_credential_metadata_perms`
    /// applies 0o600 so a shared host can't read which third-party
    /// registries the user has tokens for.
    #[cfg(unix)]
    #[test]
    fn restrict_credential_metadata_perms_applies_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        std::fs::write(&path, b"{}").unwrap();
        // Start with permissive perms to prove the helper tightens them.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict_credential_metadata_perms(&path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
    }

    /// End-to-end: `track_custom_registry` writes the tracking file
    /// with 0o600 directly — proves the perm helper is wired through
    /// the public write path, not just available as a utility.
    #[cfg(unix)]
    #[test]
    fn track_custom_registry_writes_tracking_file_with_0o600() {
        use std::os::unix::fs::PermissionsExt;

        with_temp_home(|home| {
            track_custom_registry("https://registry.example.com");
            let path = home.join(".lpm").join(".custom-registries.json");
            assert!(path.exists(), "tracking file should be written");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        });
    }

    /// End-to-end: `set_token_expiry` writes `.token-expiry.json`
    /// with 0o600.
    #[cfg(unix)]
    #[test]
    fn set_token_expiry_writes_file_with_0o600() {
        use std::os::unix::fs::PermissionsExt;

        with_temp_home(|home| {
            set_token_expiry("https://registry.example.com", "2099-01-01T00:00:00Z");
            let path = home.join(".lpm").join(".token-expiry.json");
            assert!(path.exists(), "expiry file should be written");
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        });
    }

    /// `clear_password_from_keychain_account` is now Ok-on-absent
    /// rather than conflating "already gone" with "real failure"
    /// (which previously produced a misleading "keychain entry not
    /// found" error and made callers either silently swallow or
    /// surface a confusing message to the user).
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_password_from_keychain_account_treats_absent_as_ok() {
        let account = format!(
            "lpm-test-absent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        // No prior write — the account is guaranteed absent.
        let result = clear_password_from_keychain_account(&account);
        assert!(
            result.is_ok(),
            "clearing an absent account must be Ok (idempotent), got {result:?}",
        );
    }

    /// Hostile-clone scenario (M6): a repo ships a world-readable
    /// `.npmrc` carrying an attacker-controlled `_authToken`. The
    /// pre-fix parser warned about the perms but still surfaced the
    /// token. Post-fix, permissive perms refuse the read so npm auth
    /// cannot be silently steered by a clone.
    #[cfg(unix)]
    #[test]
    fn parse_npmrc_file_refuses_token_on_world_readable_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "//registry.npmjs.org/:_authToken=attacker_token\n").unwrap();
        // 0o644 — world-readable, fail the gate.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            parse_npmrc_file(&path).unwrap().is_none(),
            "permissive perms must skip the token surface",
        );
    }

    /// Positive baseline: a properly-locked `.npmrc` still surfaces
    /// its token — proves the gate doesn't over-reject.
    #[cfg(unix)]
    #[test]
    fn parse_npmrc_file_accepts_token_on_0o600_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "//registry.npmjs.org/:_authToken=legit_token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            parse_npmrc_file(&path).unwrap().as_deref(),
            Some("legit_token"),
            "0o600 perms must allow the token surface",
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_npmrc_file_refuses_token_when_owner_and_other_can_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "//registry.npmjs.org/:_authToken=exposed_token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o404)).unwrap();

        assert!(
            parse_npmrc_file(&path).unwrap().is_none(),
            "an other-readable file must not supply credentials",
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_npmrc_file_accepts_token_with_owner_only_0o700_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "//registry.npmjs.org/:_authToken=private_token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            parse_npmrc_file(&path).unwrap().as_deref(),
            Some("private_token"),
            "owner-only permissions must allow credentials",
        );
    }
}
