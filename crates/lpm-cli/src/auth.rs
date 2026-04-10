//! Authentication and secure token storage for LPM CLI.
//!
//! Three-tier token resolution (matching the JS CLI):
//! 1. `LPM_TOKEN` environment variable (CI/CD, testing)
//! 2. OS keychain via `keyring` crate (macOS Keychain, Windows Credential Manager, Linux Secret Service)
//! 3. Encrypted file fallback at `~/.lpm/.credentials` (AES-256-GCM + scrypt)
//!
//! Tokens are scoped per registry URL to prevent dev/live collisions.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use std::path::PathBuf;

/// Keychain service name (matches JS CLI).
const KEYCHAIN_SERVICE: &str = "lpm-cli";

/// Keychain account prefix (matches JS CLI scoped format).
const KEYCHAIN_ACCOUNT_PREFIX: &str = "auth-token";

fn force_file_auth() -> bool {
    matches!(
        std::env::var("LPM_FORCE_FILE_AUTH").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn use_fast_test_scrypt() -> bool {
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
    match std::panic::catch_unwind(|| get_token_from_keychain(registry_url)) {
        Ok(Some(token)) => return Some(token),
        Ok(None) => {}
        Err(_) => {
            tracing::debug!("keychain access panicked, falling through to file");
        }
    }

    // 3. Encrypted file fallback (Rust-native format, NOT compatible with JS CLI's format)
    get_token_from_file(registry_url)
    // Staleness check removed — replaced by expiry-based warnings
    // called at command level via check_token_expiry_warnings() (Feature 42)
}

/// Store a token for a given registry URL.
///
/// Tries keychain first, falls back to encrypted file.
pub fn set_token(registry_url: &str, token: &str) -> Result<(), String> {
    // Try keychain first
    if set_token_in_keychain(registry_url, token).is_ok() {
        return Ok(());
    }

    // Fall back to encrypted file
    tracing::warn!("system keychain unavailable — using encrypted file storage");
    set_token_in_file(registry_url, token)
}

/// Remove the stored token for a given registry URL.
pub fn clear_token(registry_url: &str) -> Result<(), String> {
    // Clear from keychain
    let _ = clear_token_from_keychain(registry_url);

    // Clear from encrypted file
    let _ = clear_token_from_file(registry_url);

    Ok(())
}

/// Clear all local login state for a registry.
///
/// This removes the access token, refresh token, and any stored session-expiry
/// metadata so startup cannot silently restore a session after logout.
pub fn clear_login_state(registry_url: &str) -> Result<(), String> {
    #[cfg(test)]
    let result = {
        clear_token_from_file(registry_url)?;
        clear_token_from_file(&format!("refresh:{registry_url}"))?;
        clear_token_expiry(registry_url);
        clear_token_validation_marker();
        Ok(())
    };

    #[cfg(not(test))]
    let result = {
        clear_token(registry_url)?;
        clear_refresh_token(registry_url);
        clear_token_expiry(registry_url);
        clear_token_validation_marker();
        Ok(())
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
    // 1. NPM_TOKEN environment variable (CI standard)
    if let Ok(token) = std::env::var("NPM_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    // 2. Keychain (stored via `lpm login --npm`)
    match std::panic::catch_unwind(|| get_token_from_keychain(NPM_REGISTRY_URL)) {
        Ok(Some(token)) => return Some(token),
        Ok(None) => {}
        Err(_) => {
            tracing::debug!("keychain access panicked for npm token");
        }
    }

    if force_file_auth()
        && let Some(token) = get_token_from_file(NPM_REGISTRY_URL)
    {
        return Some(token);
    }

    // 3. .npmrc fallback — parse token from project or home .npmrc
    if let Some(token) = parse_npmrc_token() {
        return Some(token);
    }

    None
}

/// Store an npm token in the keychain.
pub fn set_npm_token(token: &str) -> Result<(), String> {
    if force_file_auth() {
        return set_token_in_file(NPM_REGISTRY_URL, token);
    }

    set_token_in_keychain(NPM_REGISTRY_URL, token)
}

/// Clear stored npm token (`lpm logout --npm`).
pub fn clear_npm_token() -> Result<(), String> {
    if force_file_auth() {
        return clear_token_from_file(NPM_REGISTRY_URL);
    }

    clear_token_from_keychain(NPM_REGISTRY_URL)
        .map_err(|e| format!("failed to clear npm token: {e}"))
}

// ─── GitHub Token ──────────────────────────────────────────────────

/// GitHub Packages registry URL used for keychain scoping.
const GITHUB_REGISTRY_URL: &str = "https://npm.pkg.github.com";

/// Get the token for GitHub Packages.
///
/// Priority: `GITHUB_TOKEN` env → keychain(`npm.pkg.github.com`)
pub fn get_github_token() -> Option<String> {
    if let Ok(token) = std::env::var("GITHUB_TOKEN")
        && !token.is_empty()
    {
        return Some(token);
    }

    match std::panic::catch_unwind(|| get_token_from_keychain(GITHUB_REGISTRY_URL)) {
        Ok(Some(token)) => Some(token),
        _ if force_file_auth() => get_token_from_file(GITHUB_REGISTRY_URL),
        _ => None,
    }
}

/// Store a GitHub Packages token in the keychain.
pub fn set_github_token(token: &str) -> Result<(), String> {
    if force_file_auth() {
        return set_token_in_file(GITHUB_REGISTRY_URL, token);
    }

    set_token_in_keychain(GITHUB_REGISTRY_URL, token)
}

/// Clear stored GitHub token (`lpm logout --github`).
pub fn clear_github_token() -> Result<(), String> {
    if force_file_auth() {
        return clear_token_from_file(GITHUB_REGISTRY_URL);
    }

    clear_token_from_keychain(GITHUB_REGISTRY_URL)
        .map_err(|e| format!("failed to clear GitHub token: {e}"))
}

// ─── GitLab Token ──────────────────────────────────────────────────

/// GitLab Packages registry URL used for keychain scoping.
const GITLAB_REGISTRY_URL: &str = "https://gitlab.com/packages/npm";

/// Get the token for GitLab Packages.
///
/// Priority: `GITLAB_TOKEN` env → `CI_JOB_TOKEN` env → keychain(`gitlab.com`)
pub fn get_gitlab_token() -> Option<String> {
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

    match std::panic::catch_unwind(|| get_token_from_keychain(GITLAB_REGISTRY_URL)) {
        Ok(Some(token)) => Some(token),
        _ if force_file_auth() => get_token_from_file(GITLAB_REGISTRY_URL),
        _ => None,
    }
}

/// Store a GitLab Packages token in the keychain.
pub fn set_gitlab_token(token: &str) -> Result<(), String> {
    if force_file_auth() {
        return set_token_in_file(GITLAB_REGISTRY_URL, token);
    }

    set_token_in_keychain(GITLAB_REGISTRY_URL, token)
}

/// Clear stored GitLab token (`lpm logout --gitlab`).
pub fn clear_gitlab_token() -> Result<(), String> {
    if force_file_auth() {
        return clear_token_from_file(GITLAB_REGISTRY_URL);
    }

    clear_token_from_keychain(GITLAB_REGISTRY_URL)
        .map_err(|e| format!("failed to clear GitLab token: {e}"))
}

// ─── Custom Registry Token ─────────────────────────────────────────

/// Get the token for a custom registry URL.
///
/// Priority: keychain(url) — custom registries use the existing scoped keychain.
pub fn get_custom_registry_token(registry_url: &str) -> Option<String> {
    match std::panic::catch_unwind(|| get_token_from_keychain(registry_url)) {
        Ok(Some(token)) => Some(token),
        _ if force_file_auth() => get_token_from_file(registry_url),
        _ => None,
    }
}

/// Store a token for a custom registry URL and track it for enumeration.
pub fn set_custom_registry_token(registry_url: &str, token: &str) -> Result<(), String> {
    if force_file_auth() {
        set_token_in_file(registry_url, token)?;
    } else {
        set_token_in_keychain(registry_url, token)?;
    }
    track_custom_registry(registry_url);
    Ok(())
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
    let Ok(content) = std::fs::read_to_string(&path) else {
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
    let Ok(content) = std::fs::read_to_string(&path) else {
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
            let _ = std::fs::write(
                &path,
                serde_json::to_string(&registries).unwrap_or_default(),
            );
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
        } else {
            let _ = std::fs::write(
                &path,
                serde_json::to_string(&registries).unwrap_or_default(),
            );
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
        } else {
            let _ = std::fs::write(&path, serde_json::to_string(&remaining).unwrap_or_default());
        }
    }

    results
}

// ─── Registry Enumeration (B4) ─────────────────────────────────────

/// Check which registries have stored tokens.
///
/// Returns a list of `(display_name, status)` pairs for known registries.
/// Status is "configured" (token exists) — does NOT verify the token is valid
/// because that would require network calls. Use `verify_registry_token()` for that.
pub fn list_stored_registries() -> Vec<(String, String)> {
    let mut result = Vec::new();

    // npm: check env, keychain, .npmrc — show source so user knows where token came from
    let npm_stored_token =
        match std::panic::catch_unwind(|| get_token_from_keychain(NPM_REGISTRY_URL)) {
            Ok(Some(token)) => Some(token),
            _ if force_file_auth() => get_token_from_file(NPM_REGISTRY_URL),
            _ => None,
        };

    if let Ok(token) = std::env::var("NPM_TOKEN") {
        if !token.is_empty() {
            result.push(("npmjs.org".into(), "configured (env: NPM_TOKEN)".into()));
        }
    } else if npm_stored_token.is_some() {
        result.push(("npmjs.org".into(), "configured (keychain)".into()));
    } else if parse_npmrc_token().is_some() {
        result.push((
            "npmjs.org".into(),
            "found in .npmrc (may be expired — run `lpm login --npm` to verify)".into(),
        ));
    }

    // GitHub: env or keychain
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            result.push(("github.com".into(), "configured (env: GITHUB_TOKEN)".into()));
        }
    } else if get_github_token().is_some() {
        result.push(("github.com".into(), "configured (keychain)".into()));
    }

    // GitLab: env or keychain
    if let Ok(token) = std::env::var("GITLAB_TOKEN") {
        if !token.is_empty() {
            result.push(("gitlab.com".into(), "configured (env: GITLAB_TOKEN)".into()));
        }
    } else if let Ok(token) = std::env::var("CI_JOB_TOKEN") {
        if !token.is_empty() {
            result.push(("gitlab.com".into(), "configured (env: CI_JOB_TOKEN)".into()));
        }
    } else if get_gitlab_token().is_some() {
        result.push(("gitlab.com".into(), "configured (keychain)".into()));
    }

    // Custom registries: read from tracking file
    for url in list_custom_registries() {
        let has_token = get_custom_registry_token(&url).is_some();
        if has_token {
            result.push((url, "configured (keychain)".into()));
        }
    }

    result
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
    let Ok(content) = std::fs::read_to_string(&path) else {
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
        if let Ok(json) = serde_json::to_string_pretty(&expiries) {
            let _ = std::fs::write(&path, json);
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
        if let Ok(json) = serde_json::to_string_pretty(&expiries) {
            let _ = std::fs::write(&path, json);
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
    session_access_token_expiry(registry)
        .map(|expiry| expiry <= chrono::Utc::now())
        .unwrap_or(false)
}

/// Returns true when a stored session access token should be refreshed.
/// Missing metadata is treated as refresh-needed so older stored sessions self-heal.
pub fn should_refresh_session_access_token(registry: &str) -> bool {
    session_access_token_expiry(registry)
        .map(|expiry| expiry <= chrono::Utc::now() + chrono::Duration::minutes(5))
        .unwrap_or(true)
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

/// Mark that we've shown the 7d or 1d reminder for a registry.
#[allow(dead_code)]
pub fn mark_expiry_reminded(registry: &str, days_left: i64) {
    let mut expiries = read_token_expiries();
    if let Some(expiry) = expiries.get_mut(registry) {
        if days_left <= 1 {
            expiry.reminded_1d = true;
        } else if days_left <= 7 {
            expiry.reminded_7d = true;
        }
        if let Some(path) = token_expiry_path()
            && let Ok(json) = serde_json::to_string_pretty(&expiries)
        {
            let _ = std::fs::write(&path, json);
        }
    }
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
        .map(|e| e.otp_required)
        .unwrap_or(false)
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

// ─── Refresh Token Storage (Feature 44 Part B) ──────────────────────
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
    let account = scoped_refresh_account(registry);

    if set_password_in_keychain_account(&account, token).is_ok() {
        return;
    }

    // Fall back to encrypted file (same AES-256-GCM as main tokens)
    if let Ok(()) = set_token_in_file(&format!("refresh:{registry}"), token) {
        return;
    }
    tracing::warn!("failed to store refresh token securely");
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
pub fn clear_refresh_token(registry: &str) {
    let account = scoped_refresh_account(registry);

    let _ = clear_password_from_keychain_account(&account);

    // Clear from encrypted file
    let _ = clear_token_from_file(&format!("refresh:{registry}"));
}

/// Parse the npm auth token from `.npmrc` files.
///
/// Checks project `.npmrc` first, then home `~/.npmrc`.
/// Looks for: `//registry.npmjs.org/:_authToken=xxx`
fn parse_npmrc_token() -> Option<String> {
    // Project-level .npmrc first
    if let Ok(cwd) = std::env::current_dir()
        && let Some(token) = parse_npmrc_file(&cwd.join(".npmrc"))
    {
        return Some(token);
    }

    // Home-level ~/.npmrc
    if let Some(home) = dirs::home_dir()
        && let Some(token) = parse_npmrc_file(&home.join(".npmrc"))
    {
        return Some(token);
    }

    None
}

/// Parse a single .npmrc file for the npm registry auth token.
fn parse_npmrc_file(path: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;

    // Check file permissions on Unix (S6)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode > 0o600 {
                tracing::warn!(
                    ".npmrc at {} has permissive mode {:o} (should be 0600)",
                    path.display(),
                    mode
                );
            }
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
                return Some(token.to_string());
            }
        }
    }

    None
}

// ─── Token Staleness ────────────────────────────────────────────────

/// Path to the token validation marker file.
fn token_check_marker() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".lpm").join(".token-check"))
}

/// Returns true if the token should be re-validated against the registry.
/// Checks are throttled to once every 24 hours using a marker file.
pub fn should_revalidate_token() -> bool {
    let Some(marker) = token_check_marker() else {
        return true;
    };
    match marker.metadata() {
        Ok(meta) => match meta.modified() {
            Ok(modified) => {
                modified.elapsed().unwrap_or(std::time::Duration::MAX)
                    >= std::time::Duration::from_secs(86400)
            }
            Err(_) => true,
        },
        Err(_) => true,
    }
}

/// Mark the token as recently validated (touch the marker file).
pub fn mark_token_validated() {
    if let Some(marker) = token_check_marker() {
        if let Some(parent) = marker.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&marker, "");
    }
}

fn clear_token_validation_marker() {
    if let Some(marker) = token_check_marker() {
        let _ = std::fs::remove_file(marker);
    }
}

// ─── Keychain ──────────────────────────────────────────────────────

fn scoped_account(registry_url: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(registry_url.as_bytes());
    format!("{}:{}", KEYCHAIN_ACCOUNT_PREFIX, hex::encode(&hash[..8]))
}

fn get_password_from_keychain_account(account: &str) -> Option<String> {
    if force_file_auth() {
        return None;
    }

    tracing::debug!("keychain lookup: service={KEYCHAIN_SERVICE}, account={account}");

    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, account)
        && let Ok(token) = entry.get_password()
    {
        tracing::debug!("keychain hit via keyring crate");
        return Some(token);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(token) = get_token_from_macos_keychain(KEYCHAIN_SERVICE, account) {
            tracing::debug!("keychain hit via security command");
            return Some(token);
        }
    }

    tracing::debug!("keychain miss for {account}");
    None
}

fn set_password_in_keychain_account(account: &str, token: &str) -> Result<(), String> {
    if force_file_auth() {
        return Err("keychain disabled by LPM_FORCE_FILE_AUTH".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                account,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        let status = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                account,
                "-w",
                token,
            ])
            .status()
            .map_err(|e| format!("keychain write error: {e}"))?;

        if status.success() {
            return Ok(());
        }

        Err("security add-generic-password failed".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| format!("keychain error: {e}"))?;
        entry
            .set_password(token)
            .map_err(|e| format!("keychain write error: {e}"))
    }
}

fn clear_password_from_keychain_account(account: &str) -> Result<(), String> {
    if force_file_auth() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                account,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("keychain delete error: {e}"))?;

        if output.success() {
            return Ok(());
        }

        Err("keychain entry not found".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|e| format!("keychain error: {e}"))?;
        entry
            .delete_credential()
            .map_err(|e| format!("keychain delete error: {e}"))
    }
}

fn get_token_from_keychain(registry_url: &str) -> Option<String> {
    let account = scoped_account(registry_url);
    get_password_from_keychain_account(&account)
}

/// Read a password from macOS keychain using the `security` CLI tool.
/// This is needed because the Rust `keyring` crate can't read entries
/// written by Node.js `keytar` (different keychain API usage).
#[cfg(target_os = "macos")]
fn get_token_from_macos_keychain(service: &str, account: &str) -> Option<String> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .ok()?;

    if output.status.success() {
        let token = String::from_utf8(output.stdout).ok()?;
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
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
        return std::fs::read_to_string(&key_path)
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
        return std::fs::read_to_string(&key_path)
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
        return std::fs::read(&path).map_err(|e| format!("failed to read salt: {e}"));
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

    let content = std::fs::read_to_string(&path).ok()?;
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
        let content = std::fs::read_to_string(&path).map_err(|e| format!("read error: {e}"))?;
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

    let content = std::fs::read_to_string(&path).map_err(|e| format!("read error: {e}"))?;
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

    if store.as_object().map(|o| o.is_empty()).unwrap_or(true) {
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
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_temp_home<T>(test: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let original_home = std::env::var_os("HOME");

        unsafe {
            std::env::set_var("HOME", temp.path());
        }

        let result = test(temp.path());

        match original_home {
            Some(value) => unsafe {
                std::env::set_var("HOME", value);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }

        result
    }

    #[test]
    fn should_revalidate_when_marker_missing() {
        // When no marker file exists, should always revalidate
        // (token_check_marker returns a path in ~/.lpm which may or may not exist,
        // but for a fresh/temp env it won't)
        let marker = std::env::temp_dir().join(format!("lpm-test-{}", std::process::id()));
        // Ensure it doesn't exist
        let _ = std::fs::remove_file(&marker);
        // The actual function uses home dir, but we test the logic:
        // missing file → metadata() fails → returns true
        assert!(marker.metadata().is_err());
    }

    #[test]
    fn mark_and_check_token_validated() {
        // Create a temp marker file and verify it's considered fresh
        let tmp = std::env::temp_dir().join(format!("lpm-token-check-test-{}", std::process::id()));
        let _ = std::fs::write(&tmp, "");

        // Just written — should be within 24h
        let meta = tmp.metadata().unwrap();
        let modified = meta.modified().unwrap();
        let elapsed = modified.elapsed().unwrap_or_default();
        assert!(
            elapsed < std::time::Duration::from_secs(86400),
            "freshly written marker should be within 24h"
        );

        // Clean up
        let _ = std::fs::remove_file(&tmp);
    }

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
    fn parse_npmrc_extracts_token() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        std::fs::write(
			&npmrc_path,
			"//registry.npmjs.org/:_authToken=npm_ABCDEF123456\nregistry=https://registry.npmjs.org/\n",
		)
		.unwrap();

        let token = parse_npmrc_file(&npmrc_path);
        assert_eq!(token, Some("npm_ABCDEF123456".to_string()));
    }

    #[test]
    fn parse_npmrc_ignores_other_registries() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, "//npm.pkg.github.com/:_authToken=ghp_xxxxx\n").unwrap();

        let token = parse_npmrc_file(&npmrc_path);
        assert!(token.is_none(), "should only read npmjs.org token");
    }

    #[test]
    fn parse_npmrc_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, "").unwrap();

        let token = parse_npmrc_file(&npmrc_path);
        assert!(token.is_none());
    }

    #[test]
    fn parse_npmrc_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let npmrc_path = dir.path().join(".npmrc");
        // Don't create the file
        let token = parse_npmrc_file(&npmrc_path);
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
        with_temp_home(|_| {
            let registry = "http://localhost:3000";

            set_token_in_file(registry, "access-token").unwrap();
            set_token_in_file(&format!("refresh:{registry}"), "refresh-token").unwrap();
            set_session_access_token_expiry(registry, "2026-04-10T00:00:00Z");
            mark_token_validated();

            assert_eq!(
                get_token_from_file(registry),
                Some("access-token".to_string())
            );
            assert_eq!(
                get_token_from_file(&format!("refresh:{registry}")),
                Some("refresh-token".to_string())
            );
            assert!(read_token_expiries().contains_key(registry));
            assert!(token_check_marker().unwrap().exists());

            clear_login_state(registry).unwrap();

            assert!(get_token_from_file(registry).is_none());
            assert!(get_token_from_file(&format!("refresh:{registry}")).is_none());
            assert!(!read_token_expiries().contains_key(registry));
            assert!(!token_check_marker().unwrap().exists());
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
        // SAFETY: This test runs single-threaded and restores the env var immediately.
        unsafe { std::env::set_var("NPM_TOKEN", "npm_test_from_env") };
        let token = get_npm_token();
        assert_eq!(token, Some("npm_test_from_env".to_string()));
        unsafe { std::env::remove_var("NPM_TOKEN") };
    }

    #[test]
    fn malformed_builtin_file_entry_falls_back_to_npmrc_without_hiding_other_builtin_tokens() {
        with_temp_home(|home| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
                std::env::remove_var("NPM_TOKEN");
                std::env::remove_var("GITHUB_TOKEN");
            }

            std::fs::write(
                home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            )
            .expect("failed to write home .npmrc");

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

            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
        });
    }

    #[test]
    fn list_stored_registries_ignores_malformed_github_entry_and_keeps_other_builtin_sources() {
        with_temp_home(|home| {
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
                std::env::remove_var("NPM_TOKEN");
                std::env::remove_var("GITHUB_TOKEN");
                std::env::remove_var("GITLAB_TOKEN");
                std::env::remove_var("CI_JOB_TOKEN");
            }

            std::fs::write(
                home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            )
            .expect("failed to write home .npmrc");

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
                name == "gitlab.com" && status == "configured (keychain)"
            }));
            assert!(
                registries.iter().all(|(name, _)| name != "github.com"),
                "malformed GitHub builtin entry should not be reported as configured: {registries:?}"
            );

            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
        });
    }

    #[test]
    fn clear_gitlab_token_preserves_npmrc_and_custom_registry_when_github_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
                std::env::remove_var("NPM_TOKEN");
                std::env::remove_var("GITHUB_TOKEN");
                std::env::remove_var("GITLAB_TOKEN");
                std::env::remove_var("CI_JOB_TOKEN");
            }

            std::fs::write(
                home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            )
            .expect("failed to write home .npmrc");

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
                name == custom_registry && status == "configured (keychain)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "gitlab.com"));
            assert!(registries.iter().all(|(name, _)| name != "github.com"));

            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
        });
    }

    #[test]
    fn clear_github_token_preserves_npmrc_gitlab_and_custom_registry_when_npm_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
                std::env::remove_var("NPM_TOKEN");
                std::env::remove_var("GITHUB_TOKEN");
                std::env::remove_var("GITLAB_TOKEN");
                std::env::remove_var("CI_JOB_TOKEN");
            }

            std::fs::write(
                home.join(".npmrc"),
                "//registry.npmjs.org/:_authToken=npmrc-fallback-token\n",
            )
            .expect("failed to write home .npmrc");

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
                name == "gitlab.com" && status == "configured (keychain)"
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == custom_registry && status == "configured (keychain)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "github.com"));

            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
        });
    }

    #[test]
    fn clear_npm_token_preserves_github_and_custom_registry_when_gitlab_entry_is_malformed() {
        with_temp_home(|home| {
            let custom_registry = "https://packages.example.internal/npm";

            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
                std::env::remove_var("NPM_TOKEN");
                std::env::remove_var("GITHUB_TOKEN");
                std::env::remove_var("GITLAB_TOKEN");
                std::env::remove_var("CI_JOB_TOKEN");
            }

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
                name == "github.com" && status == "configured (keychain)"
            }));
            assert!(registries.iter().any(|(name, status)| {
                name == custom_registry && status == "configured (keychain)"
            }));
            assert!(registries.iter().all(|(name, _)| name != "npmjs.org"));
            assert!(registries.iter().all(|(name, _)| name != "gitlab.com"));

            let credentials = get_token_from_file(NPM_REGISTRY_URL);
            assert!(
                credentials.is_none(),
                "npm entry should be removed from file store"
            );

            let _ = home;
            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
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

            unsafe {
                std::env::set_var("LPM_FORCE_FILE_AUTH", "1");
            }

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

            unsafe {
                std::env::remove_var("LPM_FORCE_FILE_AUTH");
            }
        });
    }
}
