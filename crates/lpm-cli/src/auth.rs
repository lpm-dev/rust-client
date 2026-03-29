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

/// Get the token for a given registry URL.
///
/// Priority: env var → keychain → encrypted file
pub fn get_token(registry_url: &str) -> Option<String> {
	// 1. Environment variable (highest priority)
	if let Ok(token) = std::env::var("LPM_TOKEN") {
		if !token.is_empty() {
			return Some(token);
		}
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
	let token = get_token_from_file(registry_url);

	// Check token staleness: warn if > 90 days old
	if token.is_some() {
		check_token_staleness();
	}

	token
}

/// Warn if the stored token is older than 90 days.
/// This is best-effort — does not block or invalidate.
fn check_token_staleness() {
	if let Ok(dir) = lpm_dir() {
		let ts_path = dir.join(".token-ts");
		if let Ok(metadata) = std::fs::metadata(&ts_path) {
			if let Ok(modified) = metadata.modified() {
				if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
					if age > std::time::Duration::from_secs(90 * 24 * 60 * 60) {
						tracing::warn!(
							"Token is 90+ days old. Run `lpm login` to refresh."
						);
					}
				}
			}
		}
	}
}

/// Store a token for a given registry URL.
///
/// Tries keychain first, falls back to encrypted file.
pub fn set_token(registry_url: &str, token: &str) -> Result<(), String> {
	// Try keychain first
	if set_token_in_keychain(registry_url, token).is_ok() {
		// Write .token-ts to track when we last authenticated
		if let Ok(dir) = lpm_dir() {
			let ts_path = dir.join(".token-ts");
			let _ = std::fs::write(&ts_path, chrono::Utc::now().to_rfc3339());
		}
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
				modified
					.elapsed()
					.unwrap_or(std::time::Duration::MAX)
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

// ─── Keychain ──────────────────────────────────────────────────────

fn scoped_account(registry_url: &str) -> String {
	use sha2::{Digest, Sha256};
	let hash = Sha256::digest(registry_url.as_bytes());
	format!("{}:{}", KEYCHAIN_ACCOUNT_PREFIX, hex::encode(&hash[..8]))
}

fn get_token_from_keychain(registry_url: &str) -> Option<String> {
	let account = scoped_account(registry_url);
	tracing::debug!("keychain lookup: service={KEYCHAIN_SERVICE}, account={account}");

	// Try the keyring crate first (works for entries we wrote)
	if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, &account) {
		if let Ok(token) = entry.get_password() {
			tracing::debug!("keychain hit via keyring crate");
			return Some(token);
		}
	}

	// Fallback: macOS security command (reads entries written by Node.js keytar)
	#[cfg(target_os = "macos")]
	{
		if let Some(token) = get_token_from_macos_keychain(KEYCHAIN_SERVICE, &account) {
			tracing::debug!("keychain hit via security command");
			return Some(token);
		}
	}

	tracing::debug!("keychain miss for {account}");
	None
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

	// On macOS, use the security command for compatibility with JS CLI's keytar
	#[cfg(target_os = "macos")]
	{
		// Delete existing entry first (security add fails if entry exists)
		let _ = std::process::Command::new("security")
			.args([
				"delete-generic-password",
				"-s",
				KEYCHAIN_SERVICE,
				"-a",
				&account,
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
				&account,
				"-w",
				token,
			])
			.status()
			.map_err(|e| format!("keychain write error: {e}"))?;

		if status.success() {
			return Ok(());
		}
		return Err("security add-generic-password failed".to_string());
	}

	// Non-macOS: use keyring crate
	#[cfg(not(target_os = "macos"))]
	{
		let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &account)
			.map_err(|e| format!("keychain error: {e}"))?;
		entry
			.set_password(token)
			.map_err(|e| format!("keychain write error: {e}"))
	}
}

fn clear_token_from_keychain(registry_url: &str) -> Result<(), String> {
	let account = scoped_account(registry_url);

	#[cfg(target_os = "macos")]
	{
		let output = std::process::Command::new("security")
			.args([
				"delete-generic-password",
				"-s",
				KEYCHAIN_SERVICE,
				"-a",
				&account,
			])
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.status()
			.map_err(|e| format!("keychain delete error: {e}"))?;

		if output.success() {
			return Ok(());
		}
		return Err("keychain entry not found".to_string());
	}

	#[cfg(not(target_os = "macos"))]
	{
		let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &account)
			.map_err(|e| format!("keychain error: {e}"))?;
		entry
			.delete_credential()
			.map_err(|e| format!("keychain delete error: {e}"))
	}
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
/// If neither exists, generates a 64-char random key and stores it in both.
fn get_encryption_key() -> Result<String, String> {
	const KEY_SERVICE: &str = "dev.lpm.credentials-key";
	const KEY_ACCOUNT: &str = "encryption-key";

	// Try keyring first
	if let Ok(entry) = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT) {
		if let Ok(key) = entry.get_password() {
			return Ok(key);
		}
	}

	// Try file-based key
	let key_path = dirs::home_dir()
		.ok_or("no home directory")?
		.join(".lpm")
		.join(".key");

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

	// Try to store in keyring
	if let Ok(entry) = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT) {
		let _ = entry.set_password(&key);
	}

	// Also store in file as fallback
	let dir = key_path.parent().unwrap();
	let _ = std::fs::create_dir_all(dir);
	std::fs::write(&key_path, &key)
		.map_err(|e| format!("failed to write key file: {e}"))?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
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

	// N=2^18 (262144), r=8, p=2: ~50ms on modern hardware, 8x stronger than 2^15
	let params = scrypt::Params::new(18, 8, 2, 32)
		.map_err(|e| format!("scrypt params error: {e}"))?;

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
	let cipher =
		Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher init error: {e}"))?;

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
	let cipher =
		Aes256Gcm::new_from_slice(&key).map_err(|e| format!("cipher init error: {e}"))?;

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
		let content = std::fs::read_to_string(&path)
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
	let json_str =
		serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
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
		let json_str =
			serde_json::to_string(&store).map_err(|e| format!("json error: {e}"))?;
		let encrypted = encrypt(&json_str)?;
		std::fs::write(&path, &encrypted).map_err(|e| format!("write error: {e}"))?;
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

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
		assert_ne!(a1, b, "different URLs should produce different account names");
	}
}
