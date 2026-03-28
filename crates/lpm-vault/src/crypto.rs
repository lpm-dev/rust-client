//! E2E encryption for vault sync.
//!
//! ## Personal sync (Pro)
//! - Derive wrapping key from `SHA256(auth_token)`
//! - Generate random AES-256 key per vault
//! - Encrypt vault data with AES key
//! - Wrap AES key with token-derived key
//! - Both encrypted blob and wrapped key stored on server
//! - On pull: derive same wrapping key from auth token → unwrap AES key → decrypt
//!
//! ## Org sync
//! - X25519 keypairs per user
//! - AES key per vault, wrapped with each member's X25519 public key (ECIES-like)
//! - Format: `base64(ephemeral_public):base64(iv):base64(ciphertext+tag)`

use aes_gcm::{
	Aes256Gcm, KeyInit,
	aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Derive a wrapping key from the auth token.
/// This key is used to wrap/unwrap the per-vault AES encryption key.
pub fn derive_wrapping_key(auth_token: &str) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(b"lpm-vault-wrap:");
	hasher.update(auth_token.as_bytes());
	let result = hasher.finalize();
	let mut key = [0u8; 32];
	key.copy_from_slice(&result);
	key
}

/// Generate a random 256-bit AES key.
pub fn generate_aes_key() -> [u8; 32] {
	let mut key = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut key);
	key
}

/// Encrypt plaintext with AES-256-GCM.
/// Returns base64-encoded `iv:ciphertext` (IV prepended for self-describing format).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, String> {
	let cipher = Aes256Gcm::new_from_slice(key)
		.map_err(|e| format!("cipher init: {e}"))?;

	let mut iv = [0u8; 12];
	rand::thread_rng().fill_bytes(&mut iv);
	let nonce = GenericArray::from_slice(&iv);

	let ciphertext = cipher
		.encrypt(nonce, plaintext)
		.map_err(|e| format!("encrypt: {e}"))?;

	// Format: base64(iv) + ":" + base64(ciphertext with appended auth tag)
	Ok(format!("{}:{}", BASE64.encode(iv), BASE64.encode(&ciphertext)))
}

/// Decrypt ciphertext produced by `encrypt()`.
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, String> {
	let parts: Vec<&str> = encoded.splitn(2, ':').collect();
	if parts.len() != 2 {
		return Err("invalid encrypted format".to_string());
	}

	let iv = BASE64.decode(parts[0]).map_err(|e| format!("iv decode: {e}"))?;
	let ciphertext = BASE64.decode(parts[1]).map_err(|e| format!("data decode: {e}"))?;

	if iv.len() != 12 {
		return Err(format!("invalid IV size: {}", iv.len()));
	}

	let cipher = Aes256Gcm::new_from_slice(key)
		.map_err(|e| format!("cipher init: {e}"))?;
	let nonce = GenericArray::from_slice(&iv);

	cipher
		.decrypt(nonce, ciphertext.as_slice())
		.map_err(|_| "decryption failed (wrong key or corrupted)".to_string())
}

/// Wrap an AES key with a wrapping key (AES-256-GCM key wrap).
pub fn wrap_key(wrapping_key: &[u8; 32], aes_key: &[u8; 32]) -> Result<String, String> {
	encrypt(wrapping_key, aes_key)
}

/// Unwrap an AES key.
pub fn unwrap_key(wrapping_key: &[u8; 32], wrapped: &str) -> Result<[u8; 32], String> {
	let bytes = decrypt(wrapping_key, wrapped)?;
	if bytes.len() != 32 {
		return Err(format!("unwrapped key is {} bytes, expected 32", bytes.len()));
	}
	let mut key = [0u8; 32];
	key.copy_from_slice(&bytes);
	Ok(key)
}

/// Encrypt vault secrets JSON for sync.
/// Returns (encrypted_blob, wrapped_key) — both base64-encoded strings.
pub fn encrypt_vault_for_sync(
	auth_token: &str,
	secrets_json: &str,
) -> Result<(String, String), String> {
	let aes_key = generate_aes_key();
	let wrapping_key = derive_wrapping_key(auth_token);

	let encrypted_blob = encrypt(&aes_key, secrets_json.as_bytes())?;
	let wrapped_key = wrap_key(&wrapping_key, &aes_key)?;

	Ok((encrypted_blob, wrapped_key))
}

/// Decrypt vault secrets JSON from sync.
pub fn decrypt_vault_from_sync(
	auth_token: &str,
	encrypted_blob: &str,
	wrapped_key: &str,
) -> Result<String, String> {
	let wrapping_key = derive_wrapping_key(auth_token);
	let aes_key = unwrap_key(&wrapping_key, wrapped_key)?;
	let plaintext = decrypt(&aes_key, encrypted_blob)?;

	String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))
}

// ── X25519 Org Sync ───────────────────────────────────────────────

/// Generate a new X25519 keypair. Returns (private_key_bytes, public_key_bytes).
pub fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
	let mut rng_bytes = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut rng_bytes);
	let secret = X25519Secret::from(rng_bytes);
	let public = X25519PublicKey::from(&secret);
	(rng_bytes, public.to_bytes())
}

/// Create an X25519 public key from a private key's raw bytes.
pub fn x25519_public_from_private(private_bytes: &[u8; 32]) -> [u8; 32] {
	let secret = X25519Secret::from(*private_bytes);
	X25519PublicKey::from(&secret).to_bytes()
}

/// Derive a wrapping key from an X25519 shared secret using HKDF-SHA256.
/// Must match Swift CryptoKit's `hkdfDerivedSymmetricKey(using: SHA256, salt: empty, sharedInfo: "lpm-vault-org")`.
fn derive_org_wrapping_key(shared_secret: &[u8; 32]) -> [u8; 32] {
	let hk = Hkdf::<Sha256>::new(Some(&[]), shared_secret);
	let mut okm = [0u8; 32];
	hk.expand(b"lpm-vault-org", &mut okm)
		.expect("HKDF expand failed");
	okm
}

/// Wrap an AES-256 key for a specific recipient using ECIES-like scheme.
///
/// 1. Generate ephemeral X25519 keypair
/// 2. ECDH(ephemeral_private, recipient_public) → shared secret
/// 3. HKDF-SHA256(shared_secret, info="lpm-vault-org") → wrapping key
/// 4. AES-256-GCM encrypt the AES key with wrapping key
///
/// Returns: `base64(ephemeral_public):base64(iv):base64(ciphertext+tag)`
pub fn wrap_key_for_recipient(
	aes_key: &[u8; 32],
	recipient_public: &[u8; 32],
) -> Result<String, String> {
	// Generate ephemeral keypair
	let mut eph_bytes = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut eph_bytes);
	let ephemeral_secret = X25519Secret::from(eph_bytes);
	let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

	// ECDH → shared secret
	let recipient_pk = X25519PublicKey::from(*recipient_public);
	let shared = ephemeral_secret.diffie_hellman(&recipient_pk);

	// Derive wrapping key via HKDF
	let wrapping_key = derive_org_wrapping_key(shared.as_bytes());

	// AES-GCM encrypt the AES key
	let wrapped = encrypt(&wrapping_key, aes_key)?;

	// Prepend ephemeral public key
	Ok(format!(
		"{}:{}",
		BASE64.encode(ephemeral_public.as_bytes()),
		wrapped
	))
}

/// Unwrap an AES-256 key using the recipient's X25519 private key.
///
/// Input format: `base64(ephemeral_public):base64(iv):base64(ciphertext+tag)`
pub fn unwrap_key_from_sender(
	wrapped: &str,
	private_key: &[u8; 32],
) -> Result<[u8; 32], String> {
	// Split: ephemeral_public : iv : ciphertext+tag
	let parts: Vec<&str> = wrapped.splitn(2, ':').collect();
	if parts.len() != 2 {
		return Err("invalid org wrapped key format".to_string());
	}

	let eph_public_bytes = BASE64
		.decode(parts[0])
		.map_err(|e| format!("ephemeral key decode: {e}"))?;
	if eph_public_bytes.len() != 32 {
		return Err(format!(
			"invalid ephemeral key size: {} (expected 32)",
			eph_public_bytes.len()
		));
	}

	let mut eph_pub = [0u8; 32];
	eph_pub.copy_from_slice(&eph_public_bytes);

	// ECDH → shared secret
	let my_secret = X25519Secret::from(*private_key);
	let their_public = X25519PublicKey::from(eph_pub);
	let shared = my_secret.diffie_hellman(&their_public);

	// Derive wrapping key via HKDF
	let wrapping_key = derive_org_wrapping_key(shared.as_bytes());

	// The rest is the standard AES-GCM wrapped key: iv:ciphertext+tag
	let aes_encrypted = parts[1];
	let aes_bytes = decrypt(&wrapping_key, aes_encrypted)?;

	if aes_bytes.len() != 32 {
		return Err(format!(
			"unwrapped key is {} bytes, expected 32",
			aes_bytes.len()
		));
	}
	let mut key = [0u8; 32];
	key.copy_from_slice(&aes_bytes);
	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encrypt_decrypt_round_trip() {
		let key = generate_aes_key();
		let plaintext = b"hello vault secrets";
		let encrypted = encrypt(&key, plaintext).unwrap();
		let decrypted = decrypt(&key, &encrypted).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn different_iv_each_time() {
		let key = generate_aes_key();
		let a = encrypt(&key, b"same").unwrap();
		let b = encrypt(&key, b"same").unwrap();
		assert_ne!(a, b);
	}

	#[test]
	fn wrong_key_fails() {
		let key1 = generate_aes_key();
		let key2 = generate_aes_key();
		let encrypted = encrypt(&key1, b"secret").unwrap();
		assert!(decrypt(&key2, &encrypted).is_err());
	}

	#[test]
	fn wrap_unwrap_round_trip() {
		let wrapping_key = generate_aes_key();
		let aes_key = generate_aes_key();
		let wrapped = wrap_key(&wrapping_key, &aes_key).unwrap();
		let unwrapped = unwrap_key(&wrapping_key, &wrapped).unwrap();
		assert_eq!(unwrapped, aes_key);
	}

	#[test]
	fn wrong_wrapping_key_fails() {
		let key1 = generate_aes_key();
		let key2 = generate_aes_key();
		let aes_key = generate_aes_key();
		let wrapped = wrap_key(&key1, &aes_key).unwrap();
		assert!(unwrap_key(&key2, &wrapped).is_err());
	}

	#[test]
	fn vault_sync_round_trip() {
		let token = "lpm_abc123def456";
		let secrets = r#"{"DB_HOST":"localhost","API_KEY":"sk-123"}"#;

		let (blob, wrapped) = encrypt_vault_for_sync(token, secrets).unwrap();
		let decrypted = decrypt_vault_from_sync(token, &blob, &wrapped).unwrap();

		assert_eq!(decrypted, secrets);
	}

	#[test]
	fn different_token_cannot_decrypt() {
		let (blob, wrapped) =
			encrypt_vault_for_sync("lpm_token1", "secrets").unwrap();
		assert!(decrypt_vault_from_sync("lpm_token2", &blob, &wrapped).is_err());
	}

	#[test]
	fn derive_wrapping_key_deterministic() {
		let a = derive_wrapping_key("lpm_abc");
		let b = derive_wrapping_key("lpm_abc");
		assert_eq!(a, b);
	}

	#[test]
	fn derive_wrapping_key_different_tokens() {
		let a = derive_wrapping_key("lpm_abc");
		let b = derive_wrapping_key("lpm_def");
		assert_ne!(a, b);
	}

	// ── X25519 tests ──

	#[test]
	fn x25519_keypair_generation() {
		let (priv_a, pub_a) = generate_x25519_keypair();
		let (priv_b, pub_b) = generate_x25519_keypair();
		assert_ne!(priv_a, priv_b);
		assert_ne!(pub_a, pub_b);
		// Public key should match private
		assert_eq!(x25519_public_from_private(&priv_a), pub_a);
	}

	#[test]
	fn x25519_wrap_unwrap_round_trip() {
		let aes_key = generate_aes_key();
		let (recipient_priv, recipient_pub) = generate_x25519_keypair();

		let wrapped = wrap_key_for_recipient(&aes_key, &recipient_pub).unwrap();
		let unwrapped = unwrap_key_from_sender(&wrapped, &recipient_priv).unwrap();

		assert_eq!(unwrapped, aes_key);
	}

	#[test]
	fn x25519_wrong_recipient_fails() {
		let aes_key = generate_aes_key();
		let (_, recipient_pub) = generate_x25519_keypair();
		let (wrong_priv, _) = generate_x25519_keypair();

		let wrapped = wrap_key_for_recipient(&aes_key, &recipient_pub).unwrap();
		assert!(unwrap_key_from_sender(&wrapped, &wrong_priv).is_err());
	}

	#[test]
	fn x25519_different_wrap_each_time() {
		let aes_key = generate_aes_key();
		let (_, pub_key) = generate_x25519_keypair();
		let a = wrap_key_for_recipient(&aes_key, &pub_key).unwrap();
		let b = wrap_key_for_recipient(&aes_key, &pub_key).unwrap();
		assert_ne!(a, b); // Different ephemeral keys each time
	}
}
