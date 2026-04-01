//! E2E encryption for vault sync.
//!
//! ## Personal sync (Pro)
//! - Wrapping key stored in system keyring (or `~/.lpm/.vault-key` fallback)
//! - Generate random AES-256 key per vault
//! - Encrypt vault data with AES key
//! - Wrap AES key with wrapping key
//! - Both encrypted blob and wrapped key stored on server
//! - On pull: load wrapping key → unwrap AES key → decrypt
//!
//! ## Legacy migration
//! - Old versions derived wrapping key from `SHA256("lpm-vault-wrap:" + auth_token)`
//! - On decrypt failure with new key, we try the legacy key and re-encrypt if it works
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

/// Keyring service name for the vault wrapping key.
const VAULT_KEY_SERVICE: &str = "dev.lpm.vault-key";

/// Keyring account name for the vault wrapping key.
const VAULT_KEY_ACCOUNT: &str = "wrapping-key";

/// Get or create the vault wrapping key, independent of any auth token.
///
/// Storage priority:
/// 1. System keyring (`dev.lpm.vault-key` / `wrapping-key`)
/// 2. File fallback (`~/.lpm/.vault-key`, 0o600 permissions)
///
/// If neither exists, generates a random 32-byte key and stores in both locations.
pub fn get_or_create_wrapping_key() -> Result<[u8; 32], String> {
    // Try keyring first
    if let Some(key) = read_wrapping_key_from_keyring() {
        return Ok(key);
    }

    // Try file fallback
    if let Some(key) = read_wrapping_key_from_file() {
        // Also store in keyring for next time (best effort)
        let _ = store_wrapping_key_in_keyring(&key);
        return Ok(key);
    }

    // Generate new key
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    // Store in both locations
    let _ = store_wrapping_key_in_keyring(&key);
    store_wrapping_key_in_file(&key)?;

    tracing::debug!("generated new vault wrapping key");
    Ok(key)
}

/// Read the wrapping key from the system keyring.
fn read_wrapping_key_from_keyring() -> Option<[u8; 32]> {
    let entry = keyring::Entry::new(VAULT_KEY_SERVICE, VAULT_KEY_ACCOUNT).ok()?;
    let hex_key = entry.get_password().ok()?;
    let bytes = hex::decode(hex_key.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Store the wrapping key in the system keyring.
fn store_wrapping_key_in_keyring(key: &[u8; 32]) -> Result<(), String> {
    let entry = keyring::Entry::new(VAULT_KEY_SERVICE, VAULT_KEY_ACCOUNT)
        .map_err(|e| format!("keyring entry error: {e}"))?;
    entry
        .set_password(&hex::encode(key))
        .map_err(|e| format!("keyring set error: {e}"))
}

/// Read the wrapping key from the file fallback.
fn read_wrapping_key_from_file() -> Option<[u8; 32]> {
    let key_path = dirs::home_dir()?.join(".lpm").join(".vault-key");
    let hex_key = std::fs::read_to_string(&key_path).ok()?;
    let bytes = hex::decode(hex_key.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Store the wrapping key in the file fallback with restricted permissions.
fn store_wrapping_key_in_file(key: &[u8; 32]) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    let lpm_dir = home.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(|e| format!("failed to create ~/.lpm: {e}"))?;

    let key_path = lpm_dir.join(".vault-key");
    std::fs::write(&key_path, hex::encode(key))
        .map_err(|e| format!("failed to write vault key file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Legacy: derive a wrapping key from the auth token.
///
/// Kept only for migration — old vaults may have keys wrapped with this.
/// New code should use [`get_or_create_wrapping_key`] instead.
pub fn derive_legacy_wrapping_key(auth_token: &str) -> [u8; 32] {
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
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encrypt: {e}"))?;

    // Format: base64(iv) + ":" + base64(ciphertext with appended auth tag)
    Ok(format!(
        "{}:{}",
        BASE64.encode(iv),
        BASE64.encode(&ciphertext)
    ))
}

/// Decrypt ciphertext produced by `encrypt()`.
pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = encoded.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("invalid encrypted format".to_string());
    }

    let iv = BASE64
        .decode(parts[0])
        .map_err(|e| format!("iv decode: {e}"))?;
    let ciphertext = BASE64
        .decode(parts[1])
        .map_err(|e| format!("data decode: {e}"))?;

    if iv.len() != 12 {
        return Err(format!("invalid IV size: {}", iv.len()));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;
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
        return Err(format!(
            "unwrapped key is {} bytes, expected 32",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Encrypt vault secrets JSON for sync.
/// Returns (encrypted_blob, wrapped_key) — both base64-encoded strings.
///
/// Uses the stored wrapping key (keyring or file), independent of auth token.
pub fn encrypt_vault_for_sync(secrets_json: &str) -> Result<(String, String), String> {
    let aes_key = generate_aes_key();
    let wrapping_key = get_or_create_wrapping_key()?;

    let encrypted_blob = encrypt(&aes_key, secrets_json.as_bytes())?;
    let wrapped_key = wrap_key(&wrapping_key, &aes_key)?;

    Ok((encrypted_blob, wrapped_key))
}

/// Decrypt vault secrets JSON from sync.
///
/// Tries the stored wrapping key first. On failure, falls back to the legacy
/// token-derived key for migration. If the legacy key works, returns the
/// decrypted data (the caller should re-encrypt and re-push with the new key).
pub fn decrypt_vault_from_sync(
    auth_token: &str,
    encrypted_blob: &str,
    wrapped_key: &str,
) -> Result<DecryptResult, String> {
    // Try new stored wrapping key first
    if let Ok(wrapping_key) = get_or_create_wrapping_key()
        && let Ok(aes_key) = unwrap_key(&wrapping_key, wrapped_key)
        && let Ok(plaintext) = decrypt(&aes_key, encrypted_blob)
    {
        let text = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;
        return Ok(DecryptResult {
            plaintext: text,
            needs_reencrypt: false,
        });
    }

    // Fall back to legacy token-derived key
    let legacy_key = derive_legacy_wrapping_key(auth_token);
    let aes_key = unwrap_key(&legacy_key, wrapped_key)
        .map_err(|_| "decryption failed with both new and legacy keys".to_string())?;
    let plaintext = decrypt(&aes_key, encrypted_blob)?;
    let text = String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))?;

    tracing::info!(
        "vault decrypted with legacy key — will re-encrypt with stored key on next push"
    );

    Ok(DecryptResult {
        plaintext: text,
        needs_reencrypt: true,
    })
}

/// Result of vault decryption, indicating whether migration is needed.
pub struct DecryptResult {
    /// The decrypted plaintext.
    pub plaintext: String,
    /// If true, the vault was decrypted with the legacy token-derived key
    /// and should be re-encrypted with the new stored key on next push.
    pub needs_reencrypt: bool,
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
pub fn unwrap_key_from_sender(wrapped: &str, private_key: &[u8; 32]) -> Result<[u8; 32], String> {
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

    /// Lock to serialize tests that access the shared wrapping key (keyring + file).
    static WRAPPING_KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn wrapping_key_independent_of_token() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        // The wrapping key comes from keyring/file storage, not from any token.
        // Verify that two different "tokens" don't affect the stored key.
        let key1 = get_or_create_wrapping_key().unwrap();
        let key2 = get_or_create_wrapping_key().unwrap();
        assert_eq!(key1, key2, "wrapping key must be stable across calls");

        // Legacy keys for different tokens should differ (proving independence)
        let legacy_a = derive_legacy_wrapping_key("token_a");
        let legacy_b = derive_legacy_wrapping_key("token_b");
        assert_ne!(legacy_a, legacy_b);

        // The stored key should not equal either legacy key
        assert_ne!(key1, legacy_a);
        assert_ne!(key1, legacy_b);
    }

    #[test]
    fn wrapping_key_roundtrip() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        let wrapping_key = get_or_create_wrapping_key().unwrap();
        let aes_key = generate_aes_key();
        let wrapped = wrap_key(&wrapping_key, &aes_key).unwrap();

        // Get key again — must be same
        let wrapping_key2 = get_or_create_wrapping_key().unwrap();
        assert_eq!(wrapping_key, wrapping_key2);

        let unwrapped = unwrap_key(&wrapping_key2, &wrapped).unwrap();
        assert_eq!(unwrapped, aes_key);
    }

    #[test]
    fn wrapping_key_persists() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        let key1 = get_or_create_wrapping_key().unwrap();
        let key2 = get_or_create_wrapping_key().unwrap();
        assert_eq!(key1, key2, "wrapping key must persist between calls");
    }

    #[test]
    fn vault_sync_round_trip_new_key() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        let secrets = r#"{"DB_HOST":"localhost","API_KEY":"sk-123"}"#;

        let (blob, wrapped) = encrypt_vault_for_sync(secrets).unwrap();
        // auth_token is passed for legacy fallback but shouldn't be needed
        let result = decrypt_vault_from_sync("any_token", &blob, &wrapped).unwrap();

        assert_eq!(result.plaintext, secrets);
        assert!(
            !result.needs_reencrypt,
            "should not need re-encrypt with new key"
        );
    }

    #[test]
    fn vault_sync_legacy_migration() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        // Simulate a vault encrypted with the old token-derived key
        let token = "lpm_old_token_123";
        let secrets = r#"{"LEGACY":"data"}"#;

        let legacy_key = derive_legacy_wrapping_key(token);
        let aes_key = generate_aes_key();
        let encrypted_blob = encrypt(&aes_key, secrets.as_bytes()).unwrap();
        let wrapped_key = wrap_key(&legacy_key, &aes_key).unwrap();

        // Decrypt should fall back to legacy and flag re-encrypt
        let result = decrypt_vault_from_sync(token, &encrypted_blob, &wrapped_key).unwrap();
        assert_eq!(result.plaintext, secrets);
        assert!(
            result.needs_reencrypt,
            "legacy-decrypted vault should need re-encrypt"
        );
    }

    #[test]
    fn vault_sync_token_rotation_does_not_break_new_key() {
        let _lock = WRAPPING_KEY_LOCK.lock().unwrap();

        // Encrypt with new stored key
        let secrets = r#"{"KEY":"value"}"#;
        let (blob, wrapped) = encrypt_vault_for_sync(secrets).unwrap();

        // Decrypt with a completely different "token" — should still work
        // because the new key is token-independent
        let result =
            decrypt_vault_from_sync("completely_different_token", &blob, &wrapped).unwrap();
        assert_eq!(result.plaintext, secrets);
        assert!(!result.needs_reencrypt);
    }

    #[test]
    fn legacy_wrapping_key_deterministic() {
        let a = derive_legacy_wrapping_key("lpm_abc");
        let b = derive_legacy_wrapping_key("lpm_abc");
        assert_eq!(a, b);
    }

    #[test]
    fn legacy_wrapping_key_different_tokens() {
        let a = derive_legacy_wrapping_key("lpm_abc");
        let b = derive_legacy_wrapping_key("lpm_def");
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
