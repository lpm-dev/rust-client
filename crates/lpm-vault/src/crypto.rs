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
//! - On decrypt failure with the stored key, the legacy key is tried as a fallback
//! - If the legacy key works, the caller (`pull` / `pull_raw`) re-encrypts with
//!   the stored key and pushes back on the same call, converging without user action.
//!   Migration push is best-effort: failures are logged and retried on the next pull.
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
    #[cfg(debug_assertions)]
    if let Ok(error) = std::env::var("LPM_TEST_VAULT_WRAPPING_KEY_ERROR") {
        return Err(error);
    }

    if force_file_wrapping_key() {
        if let Some(key) = read_wrapping_key_from_file() {
            return Ok(key);
        }

        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        store_wrapping_key_in_file(&key)?;
        tracing::debug!("generated new vault wrapping key in file-only mode");
        return Ok(key);
    }

    // Try keyring first
    if let Some(key) = read_wrapping_key_from_keyring() {
        // Clean up stale file-based key if keyring is the source of truth
        if let Some(path) = crate::lpm_home_dir().map(|h| h.join(".lpm").join(".vault-key"))
            && path.exists()
        {
            let _ = std::fs::remove_file(&path);
        }
        return Ok(key);
    }

    // Try file fallback
    if let Some(key) = read_wrapping_key_from_file() {
        // Promote to keyring for next time (best effort)
        let _ = store_wrapping_key_in_keyring(&key);
        return Ok(key);
    }

    // Generate new key
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    // Store in keyring; only fall back to file if keyring is unavailable
    if store_wrapping_key_in_keyring(&key).is_err() {
        store_wrapping_key_in_file(&key)?;
    }

    tracing::debug!("generated new vault wrapping key");
    Ok(key)
}

fn force_file_wrapping_key() -> bool {
    if !cfg!(debug_assertions) && !crate::acceptance_file_storage_enabled() {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Read the wrapping key from the system keyring.
fn read_wrapping_key_from_keyring() -> Option<[u8; 32]> {
    #[cfg(target_os = "macos")]
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
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
    #[cfg(target_os = "macos")]
    let _lock = lpm_common::platform::macos_keychain_operation_lock();
    let entry = keyring::Entry::new(VAULT_KEY_SERVICE, VAULT_KEY_ACCOUNT)
        .map_err(|e| format!("keyring entry error: {e}"))?;
    entry
        .set_password(&hex::encode(key))
        .map_err(|e| format!("keyring set error: {e}"))
}

/// Read the wrapping key from the file fallback.
///
/// On Unix, refuses to surface the key when the file's mode is more
/// permissive than 0o600 — the write-side already sets 0o600, but a
/// host that restored the file from a backup or a user who manually
/// `chmod`-ed it could end up with the key world-readable. Refusing
/// at read time forces the user to notice and re-chmod (or force a
/// fresh key by removing the file), rather than silently using a
/// key any local UID could exfiltrate.
fn read_wrapping_key_from_file() -> Option<[u8; 32]> {
    let key_path = crate::lpm_home_dir()?.join(".lpm").join(".vault-key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&key_path)
            && (meta.permissions().mode() & 0o777) > 0o600
        {
            tracing::warn!(
                ".vault-key at {} has permissive mode {:o} (>0o600); refusing to use \
                 the file-fallback wrapping key. Run `chmod 600 {}` to restore the \
                 source, or delete the file to force a fresh key on next write.",
                key_path.display(),
                meta.permissions().mode() & 0o777,
                key_path.display(),
            );
            return None;
        }
    }
    let hex_key =
        lpm_common::read_text_file_capped(&key_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES).ok()?;
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
    let home = crate::lpm_home_dir().ok_or("no home directory")?;
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
///
/// M12: this derivation has no forward secrecy. A stale bearer token
/// captured by any side channel (process argv, log scrape, keychain
/// leak) decrypts every pre-migration vault blob that bearer ever
/// wrapped. The migration path in [`decrypt_vault_from_sync`] re-
/// encrypts under the stored wrapping key on next push, but until
/// that push runs the legacy blob remains decryptable. Operators
/// should rotate any stored bearer that has been observed by other
/// processes and re-push the vault.
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

    // M12: a legacy decryption succeeded — the blob was wrapped with
    // SHA256("lpm-vault-wrap:" + auth_token), which has no forward
    // secrecy. Surface the posture loudly so an operator scanning
    // logs sees the migration window and rotates the bearer if it
    // has been exposed anywhere (process argv pre-H4, CI log leak,
    // backup), in addition to the implicit re-encrypt that happens
    // on the next push.
    tracing::warn!(
        "vault decrypted with legacy token-derived key (no forward secrecy) — re-encrypting under stored key on next push. If the bearer that decrypted this blob has been exposed to other processes / logs / backups, rotate it before any peer can capture the same blob.",
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

// ── P-256 ECDH (Dashboard Device Pairing) ────────────────────────
//
// The dashboard uses Web Crypto API which supports P-256 ECDH natively
// but not X25519. So device pairing uses P-256 for the key exchange,
// while org sync continues to use X25519.

const PAIRING_ENCRYPTION_INFO: &[u8] = b"lpm-dashboard-pair";
const PAIRING_SAS_INFO: &[u8] = b"lpm-pair-sas-v2";

/// Ephemeral P-256 exchange used by the two-phase browser pairing protocol.
/// The same secret stages the public key, derives the displayed SAS, and
/// wraps the key after the user confirms the SAS.
pub struct P256PairingKeyExchange {
    ephemeral_secret: p256::SecretKey,
    browser_public: p256::PublicKey,
    browser_public_bytes: Vec<u8>,
    ephemeral_public_bytes: Vec<u8>,
    ephemeral_public_key_b64: String,
}

impl P256PairingKeyExchange {
    /// Create a fresh exchange bound to the browser's uncompressed SEC1 key.
    pub fn new(browser_public_key_b64: &str) -> Result<Self, String> {
        Self::from_secret(
            browser_public_key_b64,
            p256::SecretKey::random(&mut rand::thread_rng()),
        )
    }

    fn from_secret(
        browser_public_key_b64: &str,
        ephemeral_secret: p256::SecretKey,
    ) -> Result<Self, String> {
        use elliptic_curve::sec1::ToEncodedPoint;

        let browser_public_bytes = BASE64
            .decode(browser_public_key_b64)
            .map_err(|e| format!("browser public key decode: {e}"))?;
        let browser_public = p256::PublicKey::from_sec1_bytes(&browser_public_bytes)
            .map_err(|e| format!("invalid browser P-256 public key: {e}"))?;
        let ephemeral_public_bytes = ephemeral_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let ephemeral_public_key_b64 = BASE64.encode(&ephemeral_public_bytes);

        Ok(Self {
            ephemeral_secret,
            browser_public,
            browser_public_bytes,
            ephemeral_public_bytes,
            ephemeral_public_key_b64,
        })
    }

    /// Public key staged with the server before either side displays the SAS.
    pub fn ephemeral_public_key_b64(&self) -> &str {
        &self.ephemeral_public_key_b64
    }

    fn shared_secret(&self) -> p256::ecdh::SharedSecret {
        p256::ecdh::diffie_hellman(
            self.ephemeral_secret.to_nonzero_scalar(),
            self.browser_public.as_affine(),
        )
    }

    /// Wrap the user's key with a key domain-separated from the SAS output.
    pub fn wrap_key(&self, wrapping_key: &[u8; 32]) -> Result<String, String> {
        let shared_secret = self.shared_secret();
        let hk = Hkdf::<Sha256>::new(Some(&[]), shared_secret.raw_secret_bytes().as_slice());
        let mut derived_key = [0u8; 32];
        hk.expand(PAIRING_ENCRYPTION_INFO, &mut derived_key)
            .expect("32-byte HKDF expansion is valid");
        encrypt(&derived_key, wrapping_key)
    }

    /// Derive the eight-digit SAS from the ECDH secret, pairing code, and
    /// ordered browser/CLI public keys.
    pub fn short_authentication_string(&self, pairing_code: &str) -> String {
        let mut salt = Vec::with_capacity(
            PAIRING_SAS_INFO.len()
                + pairing_code.len()
                + self.browser_public_bytes.len()
                + self.ephemeral_public_bytes.len()
                + 3,
        );
        salt.extend_from_slice(PAIRING_SAS_INFO);
        salt.push(0);
        salt.extend_from_slice(pairing_code.as_bytes());
        salt.push(0);
        salt.extend_from_slice(&self.browser_public_bytes);
        salt.push(0);
        salt.extend_from_slice(&self.ephemeral_public_bytes);

        let shared_secret = self.shared_secret();
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.raw_secret_bytes().as_slice());
        let mut output = [0u8; 4];
        hk.expand(PAIRING_SAS_INFO, &mut output)
            .expect("4-byte HKDF expansion is valid");
        let value = u32::from_be_bytes(output) % 100_000_000;
        format!("{:04} {:04}", value / 10_000, value % 10_000)
    }
}

/// Compatibility wrapper for protocol-v1 servers.
pub fn p256_pair_wrap_key(
    wrapping_key: &[u8; 32],
    browser_public_key_b64: &str,
) -> Result<(String, String), String> {
    let exchange = P256PairingKeyExchange::new(browser_public_key_b64)?;
    let encrypted = exchange.wrap_key(wrapping_key)?;
    Ok((encrypted, exchange.ephemeral_public_key_b64().to_string()))
}

/// Protocol-v1 compatibility SAS used when an older server omits protocol
/// metadata.
pub fn legacy_pairing_match_number(pairing_code: &str, browser_public_key_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-pair-sas:");
    hasher.update(pairing_code.as_bytes());
    hasher.update(b":");
    hasher.update(browser_public_key_b64.as_bytes());
    let digest = hasher.finalize();
    let value = u16::from_be_bytes([digest[0], digest[1]]) % 100;
    format!("{value:02}")
}

/// Short visual fingerprint of the browser's public key, computed from the
/// bytes the CLI is about to wrap for. Returns the first eight bytes of
/// `SHA-256(base64-decoded pubkey)` formatted as `xx:xx:xx:xx:xx:xx:xx:xx`
/// in lowercase hex. If the input fails to decode as base64 the function
/// returns `None` so the caller can surface a clear "could not derive
/// fingerprint" message rather than display a fingerprint of attacker
/// padding.
pub fn browser_key_fingerprint(browser_public_key_b64: &str) -> Option<String> {
    let raw = BASE64.decode(browser_public_key_b64).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&raw);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(23);
    for (i, byte) in digest.iter().take(8).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hermetic test environment for wrapping-key tests.
    ///
    /// Tests that touch [`get_or_create_wrapping_key`] would otherwise hit
    /// the real keyring + the real `~/.lpm/.vault-key`, neither of which
    /// is reliably available on Linux CI runners (no D-Bus / no
    /// secret-service). By forcing file-only mode + an isolated `HOME`
    /// the tests get true isolation: each one starts with a clean key
    /// directory, and there is no chance of cross-test or cross-CI
    /// contamination of the real user keyring/file.
    ///
    /// Construction: takes the shared
    /// [`crate::test_env_lock::ENV_LOCK`] mutex, snapshots `HOME` +
    /// `LPM_FORCE_FILE_VAULT`, points them at a fresh tempdir with the
    /// env var set to `"1"`. Drop restores both env vars and releases
    /// the lock (the tempdir is cleaned up by `tempfile`). Sharing
    /// the lock with `lib.rs::tests::with_forced_file_vault_backend`
    /// is what closes the parallel-cascade where one module's tests
    /// would mutate env while another module's tests were mid-flight.
    #[cfg(debug_assertions)]
    struct IsolatedVaultEnv {
        _tmp: tempfile::TempDir,
        _guard: std::sync::MutexGuard<'static, ()>,
        prior_home: Option<crate::test_env_lock::HomeEnvSnapshot>,
        prior_force_file: Option<std::ffi::OsString>,
    }

    #[cfg(debug_assertions)]
    impl IsolatedVaultEnv {
        fn new() -> Self {
            let guard = crate::test_env_lock::acquire_env_lock();
            let tmp = tempfile::tempdir().expect("tempdir for isolated vault env");
            let prior_home = Some(crate::test_env_lock::HomeEnvSnapshot::set(tmp.path()));
            let prior_force_file = std::env::var_os("LPM_FORCE_FILE_VAULT");
            // SAFETY: the shared env-lock guard ensures we are the only
            // thread mutating these env vars while this struct is alive.
            unsafe {
                std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
            }
            IsolatedVaultEnv {
                _tmp: tmp,
                _guard: guard,
                prior_home,
                prior_force_file,
            }
        }
    }

    #[cfg(debug_assertions)]
    impl Drop for IsolatedVaultEnv {
        fn drop(&mut self) {
            // SAFETY: still holding the shared env-lock via `_guard`.
            unsafe {
                match &self.prior_force_file {
                    Some(v) => std::env::set_var("LPM_FORCE_FILE_VAULT", v),
                    None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
                }
            }
            if let Some(prior_home) = self.prior_home.take() {
                prior_home.restore();
            }
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn force_file_wrapping_key_ignores_env_in_release_builds() {
        let _guard = crate::test_env_lock::acquire_env_lock();
        let prior = std::env::var_os("LPM_FORCE_FILE_VAULT");
        unsafe {
            std::env::set_var("LPM_FORCE_FILE_VAULT", "1");
        }
        let forced = force_file_wrapping_key();
        unsafe {
            match prior {
                Some(value) => std::env::set_var("LPM_FORCE_FILE_VAULT", value),
                None => std::env::remove_var("LPM_FORCE_FILE_VAULT"),
            }
        }

        assert!(!forced);
    }

    #[cfg(all(not(debug_assertions), feature = "acceptance-test-hooks"))]
    #[test]
    fn release_acceptance_build_uses_file_wrapping_key_only_inside_isolated_run_home() {
        let _guard = crate::test_env_lock::acquire_env_lock();
        let root = tempfile::tempdir().expect("create acceptance root");
        let run_dir = root.path().join("run");
        let home = run_dir.join("session-home");
        std::fs::create_dir_all(&home).expect("create acceptance home");
        let variables = [
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_HOME", home.join(".lpm").into_os_string()),
            ("ACCEPTANCE_RUN_DIR", run_dir.into_os_string()),
            ("ACCEPTANCE_RUN_ID", "release-file-vault".into()),
            ("LPM_ACCEPTANCE_FILE_STORAGE", "1".into()),
            ("LPM_FORCE_FILE_VAULT", "1".into()),
        ];
        let previous = variables
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect::<Vec<_>>();
        unsafe {
            for (name, value) in &variables {
                std::env::set_var(name, value);
            }
        }

        let forced = force_file_wrapping_key();

        unsafe {
            for (name, value) in previous.into_iter().rev() {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        assert!(forced);
    }

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

    #[cfg(debug_assertions)]
    #[test]
    fn wrapping_key_independent_of_token() {
        let _env = IsolatedVaultEnv::new();

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

    #[cfg(debug_assertions)]
    #[test]
    fn wrapping_key_roundtrip() {
        let _env = IsolatedVaultEnv::new();

        let wrapping_key = get_or_create_wrapping_key().unwrap();
        let aes_key = generate_aes_key();
        let wrapped = wrap_key(&wrapping_key, &aes_key).unwrap();

        // Get key again — must be same
        let wrapping_key2 = get_or_create_wrapping_key().unwrap();
        assert_eq!(wrapping_key, wrapping_key2);

        let unwrapped = unwrap_key(&wrapping_key2, &wrapped).unwrap();
        assert_eq!(unwrapped, aes_key);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn wrapping_key_persists() {
        let _env = IsolatedVaultEnv::new();

        let key1 = get_or_create_wrapping_key().unwrap();
        let key2 = get_or_create_wrapping_key().unwrap();
        assert_eq!(key1, key2, "wrapping key must persist between calls");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn vault_sync_round_trip_new_key() {
        let _env = IsolatedVaultEnv::new();

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

    #[cfg(debug_assertions)]
    #[test]
    fn vault_sync_legacy_migration() {
        let _env = IsolatedVaultEnv::new();

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

    #[cfg(debug_assertions)]
    #[test]
    fn vault_sync_token_rotation_does_not_break_new_key() {
        let _env = IsolatedVaultEnv::new();

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

    // ── P-256 ECDH tests ──

    #[test]
    fn p256_pair_wrap_produces_valid_output() {
        use p256::SecretKey as P256SecretKey;

        let wrapping_key = generate_aes_key();

        // Simulate browser: generate a P-256 keypair, encode public as uncompressed SEC1
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        let browser_public = browser_secret.public_key();
        use elliptic_curve::sec1::ToEncodedPoint;
        let browser_pub_b64 = BASE64.encode(browser_public.to_encoded_point(false).as_bytes());

        let (encrypted, eph_pub_b64) = p256_pair_wrap_key(&wrapping_key, &browser_pub_b64).unwrap();

        // Verify encrypted format: base64(iv):base64(ciphertext)
        assert!(encrypted.contains(':'));

        // Verify ephemeral public key is valid uncompressed P-256 (65 bytes: 04 || x || y)
        let eph_bytes = BASE64.decode(&eph_pub_b64).unwrap();
        assert_eq!(eph_bytes.len(), 65);
        assert_eq!(eph_bytes[0], 0x04);
    }

    #[test]
    fn p256_pair_wrap_unwrap_round_trip() {
        use p256::SecretKey as P256SecretKey;
        use p256::ecdh::diffie_hellman;

        let wrapping_key = generate_aes_key();

        // Browser generates keypair
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        let browser_public = browser_secret.public_key();
        use elliptic_curve::sec1::ToEncodedPoint;
        let browser_pub_b64 = BASE64.encode(browser_public.to_encoded_point(false).as_bytes());

        // CLI wraps
        let (encrypted, eph_pub_b64) = p256_pair_wrap_key(&wrapping_key, &browser_pub_b64).unwrap();

        // Browser-side: ECDH with ephemeral public key → same shared secret → same derived key
        let eph_bytes = BASE64.decode(&eph_pub_b64).unwrap();
        let eph_pub = p256::PublicKey::from_sec1_bytes(&eph_bytes).unwrap();

        let shared_secret = diffie_hellman(browser_secret.to_nonzero_scalar(), eph_pub.as_affine());

        let hk = Hkdf::<Sha256>::new(Some(&[]), shared_secret.raw_secret_bytes().as_slice());
        let mut derived_key = [0u8; 32];
        hk.expand(b"lpm-dashboard-pair", &mut derived_key).unwrap();

        // Decrypt
        let decrypted = decrypt(&derived_key, &encrypted).unwrap();
        assert_eq!(decrypted.len(), 32);
        assert_eq!(&decrypted[..], &wrapping_key[..]);
    }

    #[test]
    fn p256_pair_different_each_time() {
        use p256::SecretKey as P256SecretKey;

        let wrapping_key = generate_aes_key();
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        use elliptic_curve::sec1::ToEncodedPoint;
        let browser_pub_b64 = BASE64.encode(
            browser_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        let (enc_a, eph_a) = p256_pair_wrap_key(&wrapping_key, &browser_pub_b64).unwrap();
        let (enc_b, eph_b) = p256_pair_wrap_key(&wrapping_key, &browser_pub_b64).unwrap();
        assert_ne!(enc_a, enc_b); // Different ephemeral key each time
        assert_ne!(eph_a, eph_b);
    }

    #[test]
    fn protocol_v2_pairing_sas_is_eight_grouped_digits() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey as P256SecretKey;

        for _ in 0..200 {
            let code: String = (0..6)
                .map(|_| {
                    let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
                    chars
                        .as_bytes()
                        .get(rand::random::<usize>() % chars.len())
                        .map(|b| *b as char)
                        .unwrap()
                })
                .collect();
            let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
            let browser_public = BASE64.encode(
                browser_secret
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            );
            let exchange = P256PairingKeyExchange::new(&browser_public).unwrap();
            let out = exchange.short_authentication_string(&code);
            assert_eq!(
                out.len(),
                9,
                "SAS must render as four digits, a space, and four digits"
            );
            assert_eq!(&out[4..5], " ");
            assert!(
                out.chars()
                    .enumerate()
                    .all(|(index, c)| index == 4 && c == ' ' || c.is_ascii_digit()),
                "SAS must contain only ASCII digits and its grouping space, got {out:?}"
            );
        }
    }

    #[test]
    fn protocol_v2_pairing_sas_is_deterministic_for_same_exchange() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey as P256SecretKey;
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        let browser_public = BASE64.encode(
            browser_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let exchange = P256PairingKeyExchange::new(&browser_public).unwrap();
        let a = exchange.short_authentication_string("ABC123");
        let b = exchange.short_authentication_string("ABC123");
        assert_eq!(a, b);
        assert_eq!(a.len(), 9);
    }

    #[test]
    fn protocol_v2_pairing_sas_matches_browser_web_crypto_vector() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let browser_public = "BHxVGUyrg6Aqn2QCLhpKWxgxAKl8Fzge710Mk4EjOXaWb+2NIrZXsDeew/kaCDoKLvQ74/ux0Jrp4ZdVoFq98Go=";
        let cli_secret_bytes = URL_SAFE_NO_PAD
            .decode("5dN15DKUl326VlUkWjxMwcreiXKehsYwgiuPDDbzr0c")
            .unwrap();
        let cli_secret = p256::SecretKey::from_slice(&cli_secret_bytes).unwrap();
        let exchange = P256PairingKeyExchange::from_secret(browser_public, cli_secret).unwrap();

        assert_eq!(
            exchange.ephemeral_public_key_b64(),
            "BMWROJBAxLxAGItA6oI/47ay4MyHaC8FRvahmthBlzyLNbhic0DB/NZyzCGIgjXhOBsBsPk0WcP2U32il8d2HZE="
        );
        assert_eq!(exchange.short_authentication_string("ABC123"), "9190 5834");
    }

    #[test]
    fn protocol_v2_pairing_sas_changes_with_cli_ephemeral_secret() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey as P256SecretKey;
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        let browser_public = BASE64.encode(
            browser_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let a = P256PairingKeyExchange::new(&browser_public)
            .unwrap()
            .short_authentication_string("ABC123");
        let b = P256PairingKeyExchange::new(&browser_public)
            .unwrap()
            .short_authentication_string("ABC123");
        assert_ne!(a, b);
    }

    #[test]
    fn protocol_v2_pairing_sas_changes_when_code_changes() {
        use elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey as P256SecretKey;
        let browser_secret = P256SecretKey::random(&mut rand::thread_rng());
        let browser_public = BASE64.encode(
            browser_secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let exchange = P256PairingKeyExchange::new(&browser_public).unwrap();
        assert_ne!(
            exchange.short_authentication_string("ABC123"),
            exchange.short_authentication_string("ABC124")
        );
    }

    #[test]
    fn browser_key_fingerprint_renders_first_eight_bytes_as_colon_hex() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty_b64 = BASE64.encode([] as [u8; 0]);
        assert_eq!(
            browser_key_fingerprint(&empty_b64).unwrap(),
            "e3:b0:c4:42:98:fc:1c:14"
        );
    }

    #[test]
    fn browser_key_fingerprint_returns_none_on_malformed_base64() {
        assert!(browser_key_fingerprint("not!valid!base64!!!").is_none());
    }

    #[test]
    fn browser_key_fingerprint_differs_for_one_bit_input_change() {
        let key_a = BASE64.encode([0u8; 65]);
        let mut key_b_bytes = [0u8; 65];
        key_b_bytes[64] = 1;
        let key_b = BASE64.encode(key_b_bytes);
        assert_ne!(
            browser_key_fingerprint(&key_a).unwrap(),
            browser_key_fingerprint(&key_b).unwrap(),
            "a single-bit pubkey flip MUST change the visible fingerprint"
        );
    }
}
