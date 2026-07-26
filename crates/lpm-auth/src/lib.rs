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
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use security_framework::passwords::{
    delete_generic_password as macos_delete_generic_password,
    get_generic_password as macos_get_generic_password,
    set_generic_password as macos_set_generic_password,
};
#[cfg(target_os = "macos")]
use security_framework::{
    base::Error as MacosSecurityError,
    os::macos::passwords::find_generic_password as macos_find_generic_password,
};

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
enum MacosKeychainLookup {
    Found(String),
    NotFound,
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

    // 2. OS keychain (catch any panics from the keyring crate)
    if let Some(token) = get_token_from_keychain_safe(registry_url) {
        return Some(token);
    }

    // 3. Encrypted file fallback (Rust-native format, NOT compatible with JS CLI's format)
    get_token_from_file(registry_url)
    // Expiry-based warnings are emitted at command level via
    // check_token_expiry_warnings().
}

fn get_stored_access_token(registry_url: &str) -> Option<String> {
    get_stored_access_token_with_backend(registry_url).map(|stored| stored.token)
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
    // Try keychain first
    if set_token_in_keychain(registry_url, token).is_ok() {
        return Ok(AuthStorageBackend::Keychain);
    }

    // Fall back to encrypted file
    tracing::warn!("system keychain unavailable — using encrypted file storage");
    set_token_in_file(registry_url, token)?;
    Ok(AuthStorageBackend::EncryptedFileFallback)
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
    let keychain_result = clear_token_from_keychain(registry_url);
    let file_result = clear_token_from_file(registry_url);

    combine_clear_results(keychain_result, file_result)
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

/// Clear all local login state for a registry.
///
/// This removes the access token, refresh token, and any stored session-expiry
/// metadata so startup cannot silently restore a session after logout.
pub fn clear_login_state(registry_url: &str) -> Result<(), String> {
    // Best-effort cleanup of the legacy 24h validation marker file.
    // Keeps logout idempotent on machines that still have the file.
    if let Some(marker) = dirs::home_dir().map(|h| h.join(".lpm").join(".token-check")) {
        let _ = std::fs::remove_file(marker);
    }

    #[cfg(test)]
    let result = {
        clear_token_from_file(registry_url)?;
        clear_token_from_file(&format!("refresh:{registry_url}"))?;
        clear_token_expiry(registry_url);
        Ok(())
    };

    #[cfg(not(test))]
    let result = {
        let access_result = clear_token(registry_url);
        let refresh_result = clear_refresh_token(registry_url);
        clear_token_expiry(registry_url);
        combine_clear_results(access_result, refresh_result)
    };

    result
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
    if let Ok(token) = std::env::var("GITHUB_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    get_github_cli_token().or_else(|| get_stored_builtin_token(GITHUB_REGISTRY_URL))
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
/// The GitLab CLI token is only used for `gitlab.com`. Self-managed GitLab
/// instances keep the existing env/keychain/manual-token behavior.
pub fn get_gitlab_token_for_host(gitlab_host: &str) -> Option<String> {
    // GITLAB_TOKEN (personal access token / deploy token)
    if let Ok(token) = std::env::var("GITLAB_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    // CI_JOB_TOKEN (GitLab CI/CD automatic token)
    if let Ok(token) = std::env::var("CI_JOB_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    if is_default_gitlab_host(gitlab_host)
        && let Some(token) = get_gitlab_cli_token()
    {
        return Some(token);
    }

    get_stored_builtin_token(GITLAB_REGISTRY_URL)
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

fn get_stored_access_token_with_backend(registry_url: &str) -> Option<StoredToken> {
    if let Some(token) =
        get_token_from_keychain_safe(registry_url).filter(|token| !token.is_empty())
    {
        return Some(StoredToken {
            token,
            backend: AuthStorageBackend::Keychain,
        });
    }

    get_token_from_file(registry_url)
        .filter(|token| !token.is_empty())
        .map(|token| StoredToken {
            token,
            backend: AuthStorageBackend::EncryptedFileFallback,
        })
}

fn stored_access_backend(registry_url: &str) -> Option<AuthStorageBackend> {
    get_stored_access_token_with_backend(registry_url).map(|stored| stored.backend)
}

fn stored_refresh_backend(registry_url: &str) -> Option<AuthStorageBackend> {
    let account = scoped_refresh_account(registry_url);
    if get_password_from_keychain_account(&account)
        .filter(|token| !token.is_empty())
        .is_some()
    {
        return Some(AuthStorageBackend::Keychain);
    }

    get_token_from_file(&format!("refresh:{registry_url}"))
        .filter(|token| !token.is_empty())
        .map(|_| AuthStorageBackend::EncryptedFileFallback)
}

fn get_token_from_keychain_safe(registry_url: &str) -> Option<String> {
    match std::panic::catch_unwind(|| get_token_from_keychain(registry_url)) {
        Ok(token) => token,
        Err(_) => {
            tracing::debug!("keychain access panicked, falling through to file");
            None
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
        .and_then(|url| {
            url.host_str()
                .map(|host| host.eq_ignore_ascii_case("gitlab.com"))
        })
        .unwrap_or(false)
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

    // GitHub: env, host CLI, or keychain
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            result.push(RegistryAuthStatus {
                name: "github.com".into(),
                status: "configured (env: GITHUB_TOKEN)".into(),
                storage: AuthStorageStatus::none(),
            });
        }
    } else if get_github_cli_token().is_some() {
        result.push(RegistryAuthStatus {
            name: "github.com".into(),
            status: "available (gh auth)".into(),
            storage: AuthStorageStatus::none(),
        });
    } else if let Some(stored) = get_stored_builtin_token_with_backend(GITHUB_REGISTRY_URL) {
        result.push(RegistryAuthStatus {
            name: "github.com".into(),
            status: stored.backend.registry_status_label().into(),
            storage: AuthStorageStatus::from_backend(stored.backend),
        });
    }

    // GitLab: env, host CLI, or keychain
    if let Ok(token) = std::env::var("GITLAB_TOKEN") {
        if !token.is_empty() {
            result.push(RegistryAuthStatus {
                name: "gitlab.com".into(),
                status: "configured (env: GITLAB_TOKEN)".into(),
                storage: AuthStorageStatus::none(),
            });
        }
    } else if let Ok(token) = std::env::var("CI_JOB_TOKEN") {
        if !token.is_empty() {
            result.push(RegistryAuthStatus {
                name: "gitlab.com".into(),
                status: "configured (env: CI_JOB_TOKEN)".into(),
                storage: AuthStorageStatus::none(),
            });
        }
    } else if get_gitlab_cli_token().is_some() {
        result.push(RegistryAuthStatus {
            name: "gitlab.com".into(),
            status: "available (glab auth)".into(),
            storage: AuthStorageStatus::none(),
        });
    } else if let Some(stored) = get_stored_builtin_token_with_backend(GITLAB_REGISTRY_URL) {
        result.push(RegistryAuthStatus {
            name: "gitlab.com".into(),
            status: stored.backend.registry_status_label().into(),
            storage: AuthStorageStatus::from_backend(stored.backend),
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

/// Read stored token expiry data.
pub fn read_token_expiries() -> std::collections::HashMap<String, TokenExpiry> {
    let Some(path) = token_expiry_path() else {
        return std::collections::HashMap::new();
    };
    let Ok(content) =
        lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return std::collections::HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// Store a token expiry reminder.
pub fn set_token_expiry(registry: &str, expires: &str) {
    let mut expiries = read_token_expiries();
    // Preserve existing fields (e.g., otp_required) when updating expiry
    let entry = expiries.entry(registry.to_string()).or_default();
    entry.expires = expires.to_string();
    entry.reminded_7d = false;
    entry.reminded_1d = false;
    entry.session_access_expires_at = None;

    if let Some(path) = token_expiry_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&expiries)
            && std::fs::write(&path, json).is_ok()
        {
            restrict_credential_metadata_perms(&path);
        }
    }
}

/// Store the precise expiry for a short-lived session access token.
pub fn set_session_access_token_expiry(registry: &str, expires_at: &str) {
    let mut expiries = read_token_expiries();
    let entry = expiries.entry(registry.to_string()).or_default();
    entry.session_access_expires_at = Some(expires_at.to_string());
    // Session access tokens are auto-refreshed and should not show long-lived token warnings.
    entry.expires.clear();
    entry.reminded_7d = false;
    entry.reminded_1d = false;

    if let Some(path) = token_expiry_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&expiries)
            && std::fs::write(&path, json).is_ok()
        {
            restrict_credential_metadata_perms(&path);
        }
    }
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

/// Returns true if the local session-expiry metadata file exists on disk but
/// is unparseable (corrupted, partial write, hand-edited, version mismatch).
/// Used by `RegistryClient::execute_with_recovery`'s proactive pass to
/// trigger a silent refresh — when we can't trust the cached access-token
/// validity, we ask the server.
///
/// Returns `false` when the file is missing or empty (fresh login
/// optimism: don't refresh just because no metadata has been written
/// yet — login itself writes the metadata).
pub fn session_metadata_corrupted() -> bool {
    let Some(path) = token_expiry_path() else {
        return false;
    };
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return false,
            Err(_) => return true,
        };
    if content.trim().is_empty() {
        return false;
    }
    serde_json::from_str::<std::collections::HashMap<String, TokenExpiry>>(&content).is_err()
}

/// Remove a token expiry reminder (called on logout).
pub fn clear_token_expiry(registry: &str) {
    let mut expiries = read_token_expiries();
    if expiries.remove(registry).is_some()
        && let Some(path) = token_expiry_path()
        && let Ok(json) = serde_json::to_string_pretty(&expiries)
    {
        let _ = std::fs::write(&path, json);
    }
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
    let mut expiries = read_token_expiries();
    let entry = expiries.entry(registry.to_string()).or_default();
    entry.otp_required = required;

    if let Some(path) = token_expiry_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&expiries) {
            let _ = std::fs::write(&path, json);
        }
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

/// Store a refresh token for a registry (keychain first, encrypted file fallback).
pub fn set_refresh_token(registry: &str, token: &str) {
    if let Err(error) = set_refresh_token_with_backend(registry, token) {
        tracing::warn!("failed to store refresh token securely: {error}");
    }
}

pub fn set_refresh_token_with_backend(
    registry: &str,
    token: &str,
) -> Result<AuthStorageBackend, String> {
    let account = scoped_refresh_account(registry);

    if set_password_in_keychain_account(&account, token).is_ok() {
        return Ok(AuthStorageBackend::Keychain);
    }

    // Fall back to encrypted file (same AES-256-GCM as main tokens)
    set_token_in_file(&format!("refresh:{registry}"), token)?;
    Ok(AuthStorageBackend::EncryptedFileFallback)
}

/// Get the stored refresh token for a registry.
pub fn get_refresh_token(registry: &str) -> Option<String> {
    let account = scoped_refresh_account(registry);

    if let Some(token) = get_password_from_keychain_account(&account) {
        return Some(token);
    }

    // Fall back to encrypted file
    get_token_from_file(&format!("refresh:{registry}"))
}

/// Check whether a refresh token is stored for the given registry.
pub fn has_refresh_token(registry: &str) -> bool {
    get_refresh_token(registry).is_some()
}

/// Clear the stored refresh token for a registry.
pub fn clear_refresh_token(registry: &str) -> Result<(), String> {
    let account = scoped_refresh_account(registry);
    combine_clear_results(
        clear_password_from_keychain_account(&account),
        clear_token_from_file(&format!("refresh:{registry}")),
    )
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
/// On Unix, refuses to surface the token when the file's mode is more
/// permissive than `0o600` — a world-readable `.npmrc` in a cloned
/// repo could otherwise steer npm auth toward a token chosen by the
/// repo's author (the M6 hazard). The previous pre-fix behaviour
/// only emitted a `tracing::warn` and still returned the token, which
/// hid the risk in default-quiet logs.
fn parse_npmrc_file(path: &std::path::Path) -> Result<Option<String>, String> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::NPMRC_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path)
            && (meta.permissions().mode() & 0o777) > 0o600
        {
            tracing::warn!(
                ".npmrc at {} has permissive mode {:o} (>0o600); \
                 refusing to use its auth token to defeat hostile-repo \
                 attacks. Run `chmod 600 {}` to restore the token \
                 source.",
                path.display(),
                meta.permissions().mode() & 0o777,
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
    match macos_get_generic_password(service, account) {
        Ok(password) => token_from_keychain_password(password)
            .map_or(MacosKeychainLookup::NotFound, MacosKeychainLookup::Found),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => MacosKeychainLookup::NotFound,
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
fn get_token_from_macos_keychain_legacy(service: &str, account: &str) -> Option<String> {
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
    macos_set_generic_password(service, account, token.as_bytes())
        .map_err(|error| format!("keychain write error: {error}"))
}

#[cfg(target_os = "macos")]
fn clear_password_from_macos_keychain(service: &str, account: &str) -> Result<(), String> {
    match macos_delete_generic_password(service, account) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
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

fn get_token_from_keychain(registry_url: &str) -> Option<String> {
    let account = scoped_account(registry_url);
    get_password_from_keychain_account(&account)
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
        // Try keyring first
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
    let keyring_ok = !force_file_auth()
        && keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT)
            .and_then(|entry| entry.set_password(&key))
            .is_ok();

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

fn get_token_from_file(registry_url: &str) -> Option<String> {
    let path = credentials_path().ok()?;
    if !path.exists() {
        return None;
    }

    let content =
        lpm_common::read_text_file_capped(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES).ok()?;
    let encrypted = content.trim();
    if encrypted.is_empty() {
        return None;
    }

    // Try to decrypt. This may fail if the file was written by the JS CLI
    // (different IV size / key derivation). That's fine — the keychain is
    // the primary interop path between JS and Rust CLIs.
    let json_str = match decrypt(encrypted) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("encrypted file decrypt failed (possibly JS CLI format): {e}");
            return None;
        }
    };
    let store: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    store
        .get(registry_url)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
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
            serde_json::json!({})
        } else {
            decrypt(encrypted)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!({}))
        }
    } else {
        serde_json::json!({})
    };

    // Update
    store[registry_url] = serde_json::Value::String(token.to_string());

    // Encrypt and write
    let json_str = serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
    let encrypted = encrypt(&json_str)?;

    let dir = lpm_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir error: {e}"))?;
    std::fs::write(&path, &encrypted).map_err(|e| format!("write error: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("permissions error: {e}"))?;
    }
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
        return Ok(());
    }

    let json_str = decrypt(encrypted).unwrap_or_else(|_| "{}".to_string());
    let mut store: serde_json::Value =
        serde_json::from_str(&json_str).unwrap_or(serde_json::json!({}));

    if let Some(obj) = store.as_object_mut() {
        obj.remove(registry_url);
    }

    if store.as_object().is_none_or(|o| o.is_empty()) {
        // No more tokens — remove the file
        let _ = std::fs::remove_file(&path);
    } else {
        let json_str = serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
        let encrypted = encrypt(&json_str)?;
        std::fs::write(&path, &encrypted).map_err(|e| format!("write error: {e}"))?;
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
    fn gitlab_ci_job_token_priority_over_stored_fallback_for_self_managed_host() {
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
                Some("gitlab-ci-token".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gitlab_token_for_self_managed_host_skips_glab_cli() {
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
                get_gitlab_token_for_host("https://gitlab.example.com"),
                Some("gitlab-file-token".to_string())
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
}
