#![allow(dead_code)]

//! Helpers for seeding isolated auth state in workflow tests.
//!
//! These helpers write the same file-backed auth artifacts the CLI reads under
//! the temp HOME used by workflow tests, without touching the developer's real
//! keychain.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use std::path::{Path, PathBuf};

const FIXED_ENCRYPTION_KEY: [u8; 32] = [0x4a; 32];

#[derive(Debug, Clone, Default)]
pub struct SessionSeed<'a> {
    pub registry_url: &'a str,
    pub access_token: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub session_access_expires_at: Option<&'a str>,
}

pub fn seed_sessions(home: &Path, sessions: &[SessionSeed<'_>]) {
    let lpm_dir = lpm_dir(home);
    std::fs::create_dir_all(&lpm_dir).expect("failed to create ~/.lpm test dir");
    write_fixed_key(&lpm_dir);

    let mut credentials = serde_json::Map::new();
    let mut expiries = serde_json::Map::new();

    for session in sessions {
        if let Some(token) = session.access_token {
            credentials.insert(
                session.registry_url.to_string(),
                serde_json::Value::String(token.to_string()),
            );
        }

        if let Some(token) = session.refresh_token {
            credentials.insert(
                format!("refresh:{}", session.registry_url),
                serde_json::Value::String(token.to_string()),
            );
        }

        if let Some(expires_at) = session.session_access_expires_at {
            expiries.insert(
                session.registry_url.to_string(),
                serde_json::json!({
                    "expires": "2099-01-01",
                    "reminded_7d": false,
                    "reminded_1d": false,
                    "otp_required": false,
                    "session_access_expires_at": expires_at,
                }),
            );
        }
    }

    if !credentials.is_empty() {
        let credential_store = serde_json::Value::Object(credentials);
        let encrypted = encrypt_store(&credential_store);
        std::fs::write(credentials_path(home), encrypted).expect("failed to write credentials");
        write_credential_authority(home, &credential_store);
    } else {
        write_credential_authority(home, &serde_json::json!({}));
    }

    if !expiries.is_empty() {
        std::fs::write(
            token_expiry_path(home),
            serde_json::to_vec_pretty(&serde_json::Value::Object(expiries))
                .expect("failed to encode token expiry json"),
        )
        .expect("failed to write token expiry metadata");
    }
}

pub fn mark_recent_token_validation(home: &Path) {
    let path = token_check_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create marker parent");
    }
    std::fs::write(path, []).expect("failed to write token validation marker");
}

pub fn read_credentials(home: &Path) -> serde_json::Value {
    let path = credentials_path(home);
    let encrypted = std::fs::read_to_string(path).expect("failed to read credentials file");
    decrypt_store(encrypted.trim())
}

pub fn write_credentials_store(home: &Path, store: &serde_json::Value) {
    let lpm_dir = lpm_dir(home);
    std::fs::create_dir_all(&lpm_dir).expect("failed to create ~/.lpm test dir");
    write_fixed_key(&lpm_dir);

    let encrypted = encrypt_store(store);
    std::fs::write(credentials_path(home), encrypted).expect("failed to write credentials file");
    write_credential_authority(home, store);
}

pub fn overwrite_credentials_store_preserving_authority(home: &Path, store: &serde_json::Value) {
    let encrypted = encrypt_store(store);
    std::fs::write(credentials_path(home), encrypted)
        .expect("failed to overwrite credentials file");
}

pub fn read_expiry_metadata(home: &Path) -> serde_json::Value {
    let path = token_expiry_path(home);
    let content = std::fs::read_to_string(path).expect("failed to read token expiry file");
    serde_json::from_str(&content).expect("failed to parse token expiry json")
}

pub fn seed_custom_registries(home: &Path, registries: &[&str]) {
    let path = custom_registries_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create custom registry parent");
    }
    std::fs::write(
        path,
        serde_json::to_vec(registries).expect("failed to encode custom registries"),
    )
    .expect("failed to write custom registries");
}

pub fn credentials_path(home: &Path) -> PathBuf {
    lpm_dir(home).join(".credentials")
}

pub fn custom_registries_path(home: &Path) -> PathBuf {
    lpm_dir(home).join(".custom-registries.json")
}

pub fn token_expiry_path(home: &Path) -> PathBuf {
    lpm_dir(home).join(".token-expiry.json")
}

fn token_check_path(home: &Path) -> PathBuf {
    lpm_dir(home).join(".token-check")
}

fn lpm_dir(home: &Path) -> PathBuf {
    home.join(".lpm")
}

fn write_credential_authority(home: &Path, store: &serde_json::Value) {
    use sha2::{Digest, Sha256};

    let mut credentials = serde_json::Map::new();
    if let Some(entries) = store.as_object() {
        for (file_key, value) in entries {
            let Some(token) = value.as_str() else {
                continue;
            };
            let (kind, registry) = file_key
                .strip_prefix("refresh:")
                .map_or(("access", file_key.as_str()), |registry| {
                    ("refresh", registry)
                });
            let mut credential_id = Sha256::new();
            credential_id.update(kind.as_bytes());
            credential_id.update([0]);
            credential_id.update(registry.as_bytes());
            credentials.insert(
                hex::encode(credential_id.finalize()),
                serde_json::json!({
                    "state": "active",
                    "backend": "encrypted_file_fallback",
                    "credential_digest": hex::encode(Sha256::digest(token.as_bytes())),
                    "stale_file_cleanup_pending": false,
                }),
            );
        }
    }
    std::fs::write(
        lpm_dir(home).join(".credential-authority.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "credentials": credentials,
        }))
        .expect("failed to encode credential authority"),
    )
    .expect("failed to write credential authority");
}

fn write_fixed_key(lpm_dir: &Path) {
    std::fs::write(
        lpm_dir.join(".key"),
        format!("raw:{}", hex::encode(FIXED_ENCRYPTION_KEY)),
    )
    .expect("failed to write key");
}

fn derive_key() -> [u8; 32] {
    FIXED_ENCRYPTION_KEY
}

fn encrypt_store(value: &serde_json::Value) -> String {
    let plaintext = serde_json::to_string(value).expect("failed to encode credentials store");
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("failed to init cipher");

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("failed to encrypt credentials store");

    let tag_start = ciphertext.len() - 16;
    let (encrypted, auth_tag) = ciphertext.split_at(tag_start);

    format!(
        "{}:{}:{}",
        BASE64.encode(iv),
        BASE64.encode(auth_tag),
        BASE64.encode(encrypted)
    )
}

fn decrypt_store(encoded: &str) -> serde_json::Value {
    let parts: Vec<&str> = encoded.split(':').collect();
    assert_eq!(parts.len(), 3, "invalid credentials encoding");

    let iv = BASE64.decode(parts[0]).expect("invalid iv");
    let auth_tag = BASE64.decode(parts[1]).expect("invalid auth tag");
    let encrypted = BASE64.decode(parts[2]).expect("invalid encrypted bytes");

    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("failed to init cipher");
    let nonce = GenericArray::from_slice(&iv);

    let mut combined = encrypted;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_slice())
        .expect("failed to decrypt credentials store");

    serde_json::from_slice(&plaintext).expect("invalid decrypted credentials json")
}
