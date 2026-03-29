//! Encrypted file fallback for vault secrets on non-macOS platforms.
//!
//! Uses AES-256-GCM + scrypt, same pattern as auth.rs credentials.
//! Vault files stored at `~/.lpm/vaults/{vault-id}.enc`.

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
use std::path::PathBuf;

fn vaults_dir() -> Result<PathBuf, String> {
	let home = dirs::home_dir().ok_or("could not determine home directory")?;
	let dir = home.join(".lpm").join("vaults");
	std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create vaults dir: {e}"))?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
	}

	Ok(dir)
}

fn vault_path(vault_id: &str) -> Result<PathBuf, String> {
	Ok(vaults_dir()?.join(format!("{vault_id}.enc")))
}

fn salt_path() -> Result<PathBuf, String> {
	let home = dirs::home_dir().ok_or("could not determine home directory")?;
	Ok(home.join(".lpm").join(".vault-salt"))
}

fn get_or_create_salt() -> Result<Vec<u8>, String> {
	let path = salt_path()?;
	if path.exists() {
		return std::fs::read(&path).map_err(|e| format!("failed to read vault salt: {e}"));
	}

	let mut salt = vec![0u8; 32];
	rand::thread_rng().fill_bytes(&mut salt);

	std::fs::write(&path, &salt).map_err(|e| format!("failed to write vault salt: {e}"))?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
			tracing::warn!("failed to set permissions on salt file: {e}");
		}
	}

	Ok(salt)
}

fn derive_key() -> Result<[u8; 32], String> {
	let home = dirs::home_dir()
		.ok_or("could not determine home directory")?
		.display()
		.to_string();
	let user = std::env::var("USER")
		.or_else(|_| std::env::var("USERNAME"))
		.unwrap_or_else(|_| "lpm-user".to_string());
	let password = format!("{home}-{user}-vault");

	let salt = get_or_create_salt()?;
	// N=2^18 (262144), r=8, p=2: ~50ms on modern hardware, 8x stronger than 2^15
	let params = scrypt::Params::new(18, 8, 2, 32)
		.map_err(|e| format!("scrypt params error: {e}"))?;

	let mut key = [0u8; 32];
	scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
		.map_err(|e| format!("scrypt error: {e}"))?;

	Ok(key)
}

fn encrypt(plaintext: &str) -> Result<String, String> {
	let key = derive_key()?;
	let cipher = Aes256Gcm::new_from_slice(&key)
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

fn decrypt(encoded: &str) -> Result<String, String> {
	let parts: Vec<&str> = encoded.split(':').collect();
	if parts.len() != 3 {
		return Err("invalid encrypted format".to_string());
	}

	let iv = BASE64.decode(parts[0]).map_err(|e| format!("iv decode: {e}"))?;
	let auth_tag = BASE64.decode(parts[1]).map_err(|e| format!("tag decode: {e}"))?;
	let encrypted = BASE64.decode(parts[2]).map_err(|e| format!("data decode: {e}"))?;

	if iv.len() != 12 {
		return Err(format!("incompatible IV size: {} bytes", iv.len()));
	}

	let key = derive_key()?;
	let cipher = Aes256Gcm::new_from_slice(&key)
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
	environments: HashMap<String, HashMap<String, String>>,
}

/// Read vault secrets for a specific environment.
pub fn read_vault_file_env(vault_id: &str, env: &str) -> Option<HashMap<String, String>> {
	let path = vault_path(vault_id).ok()?;
	if !path.exists() {
		return None;
	}

	let content = std::fs::read_to_string(&path).ok()?;
	let json = decrypt(content.trim()).ok()?;

	// Try new multi-env format first
	if let Ok(data) = serde_json::from_str::<VaultData>(&json) {
		if !data.environments.is_empty() {
			return data.environments.get(env).cloned();
		}
	}

	// Fall back to old flat format (auto-migrate: treat as "default")
	serde_json::from_str(&json).ok()
}

/// Read all environments from encrypted file.
pub fn read_all_environments(vault_id: &str) -> Option<HashMap<String, HashMap<String, String>>> {
	let path = vault_path(vault_id).ok()?;
	if !path.exists() {
		return None;
	}

	let content = std::fs::read_to_string(&path).ok()?;
	let json = decrypt(content.trim()).ok()?;

	// Try new multi-env format
	if let Ok(data) = serde_json::from_str::<VaultData>(&json) {
		if !data.environments.is_empty() {
			return Some(data.environments);
		}
	}

	// Fall back to old flat format → wrap as "default"
	if let Ok(flat) = serde_json::from_str::<HashMap<String, String>>(&json) {
		let mut envs = HashMap::new();
		envs.insert("default".to_string(), flat);
		return Some(envs);
	}

	None
}

/// Write vault secrets to encrypted file (specific environment).
pub fn write_vault_file(
	vault_id: &str,
	secrets: &HashMap<String, String>,
) -> Result<(), String> {
	write_vault_file_env(vault_id, "default", secrets)
}

/// Write vault secrets for a specific environment.
pub fn write_vault_file_env(
	vault_id: &str,
	env: &str,
	secrets: &HashMap<String, String>,
) -> Result<(), String> {
	let path = vault_path(vault_id)?;

	// Read existing environments (if any)
	let mut data = if path.exists() {
		let content = std::fs::read_to_string(&path)
			.map_err(|e| format!("failed to read vault: {e}"))?;
		let json = decrypt(content.trim())?;
		serde_json::from_str::<VaultData>(&json).unwrap_or(VaultData {
			environments: HashMap::new(),
		})
	} else {
		VaultData {
			environments: HashMap::new(),
		}
	};

	// Update the specific environment
	data.environments.insert(env.to_string(), secrets.clone());

	let json = serde_json::to_string(&data)
		.map_err(|e| format!("failed to serialize secrets: {e}"))?;
	let encrypted = encrypt(&json)?;

	std::fs::write(&path, &encrypted).map_err(|e| format!("failed to write vault: {e}"))?;

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
	}

	Ok(())
}

/// Delete encrypted vault file.
pub fn delete_vault_file(vault_id: &str) -> Result<(), String> {
	let path = vault_path(vault_id)?;
	if path.exists() {
		std::fs::remove_file(&path).map_err(|e| format!("failed to delete vault: {e}"))?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	#[ignore] // scrypt key derivation is intentionally slow (~50s in debug builds)
	fn encrypt_decrypt_round_trip() {
		let plaintext = r#"{"DB_HOST": "localhost", "API_KEY": "sk-123"}"#;
		let encrypted = encrypt(plaintext).unwrap();
		let decrypted = decrypt(&encrypted).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	#[ignore] // scrypt key derivation is intentionally slow (~50s in debug builds)
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
}
