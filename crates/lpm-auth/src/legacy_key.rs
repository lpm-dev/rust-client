use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedKeyCache {
    fingerprint: String,
    key: String,
}

pub(super) fn decode(password: &str, directory: &Path) -> Result<[u8; 32], String> {
    if password.len() != 64 || !password.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("auth data key has an unsupported format".to_owned());
    }
    let salt = lpm_common::read_file_capped(&directory.join(".salt"), 32)
        .map_err(|error| format!("failed to read the existing credential salt: {error}"))?;
    if salt.len() != 32 {
        return Err("existing credential salt must contain 32 bytes".to_owned());
    }
    let credentials = match lpm_common::read_text_file_capped(
        &directory.join(".credentials"),
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(value) => Some(value),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
        Err(error) => return Err(format!("failed to read credential store: {error}")),
    };
    let mut fingerprint = Sha256::new();
    fingerprint.update(password.as_bytes());
    fingerprint.update(&salt);
    let fingerprint = hex::encode(fingerprint.finalize());
    let cache_path = directory.join(".key-derived");
    if cfg!(unix)
        && let Some(key) =
            read_authenticated_cache(&cache_path, &fingerprint, credentials.as_deref())
    {
        return Ok(key);
    }

    // Released file stores use this exact KDF. Keep their key, salt, and
    // ciphertext intact so a rollback can still read the same login.
    let params = scrypt::Params::new(20, 8, 4, 32)
        .map_err(|error| format!("credential key parameters are invalid: {error}"))?;
    let mut key = [0_u8; 32];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|error| format!("credential key derivation failed: {error}"))?;
    if cfg!(unix)
        && let Some(credentials) = credentials
    {
        super::decrypt_with_key(credentials.trim(), &key)?;
        let cache = DerivedKeyCache {
            fingerprint,
            key: super::encode_auth_key(&key),
        };
        if let Ok(encoded) = serde_json::to_string(&cache) {
            // This cache is only for a key already stored in a private file;
            // native keyring keys must never be copied into it.
            let _ = lpm_common::write_file_atomic_with_options(
                &cache_path,
                encoded,
                lpm_common::AtomicWriteOptions::new()
                    .unix_mode(0o600)
                    .sync_file()
                    .sync_parent(),
            );
        }
    }
    Ok(key)
}

fn read_authenticated_cache(
    path: &Path,
    fingerprint: &str,
    credentials: Option<&str>,
) -> Option<[u8; 32]> {
    let credentials = credentials?;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    if !lpm_common::permissions_are_owner_only(&metadata.permissions()) {
        return None;
    }
    let encoded = lpm_common::read_text_file_capped(path, 512).ok()?;
    let cache: DerivedKeyCache = serde_json::from_str(&encoded).ok()?;
    if cache.fingerprint != fingerprint {
        return None;
    }
    let key = super::decode_auth_key(&cache.key).ok()?;
    super::decrypt_with_key(credentials.trim(), &key).ok()?;
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::path::PathBuf;

    fn cache_fixture() -> (tempfile::TempDir, PathBuf, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".key-derived");
        let key = [3_u8; 32];
        let nonce = [4_u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let encrypted = cipher
            .encrypt(GenericArray::from_slice(&nonce), b"{}".as_slice())
            .unwrap();
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
        let credentials = format!(
            "{}:{}:{}",
            STANDARD.encode(nonce),
            STANDARD.encode(tag),
            STANDARD.encode(ciphertext)
        );
        let cache = DerivedKeyCache {
            fingerprint: "expected".to_owned(),
            key: super::super::encode_auth_key(&key),
        };
        lpm_common::write_file_atomic_with_options(
            &path,
            serde_json::to_string(&cache).unwrap(),
            lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
        )
        .unwrap();
        (directory, path, credentials)
    }

    #[test]
    fn derived_cache_requires_matching_material_and_authenticated_ciphertext() {
        let (_directory, path, credentials) = cache_fixture();
        assert_eq!(
            read_authenticated_cache(&path, "expected", Some(&credentials)),
            Some([3; 32])
        );
        assert!(read_authenticated_cache(&path, "different", Some(&credentials)).is_none());
        assert!(read_authenticated_cache(&path, "expected", Some("corrupt")).is_none());
        assert!(read_authenticated_cache(&path, "expected", None).is_none());
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "released scrypt compatibility vector uses 1 GiB"]
    fn released_file_key_recovers_without_rewriting_legacy_state() {
        let directory = tempfile::tempdir().unwrap();
        let password = "a".repeat(64);
        let salt = [11_u8; 32];
        let expected: [u8; 32] =
            hex::decode("990bc575911841568a9b153f67624f0ab393d558eb21d64b1a7896ae089a8b6f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce = [4_u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&expected).unwrap();
        let encrypted = cipher
            .encrypt(GenericArray::from_slice(&nonce), b"{}".as_slice())
            .unwrap();
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
        let credentials = format!(
            "{}:{}:{}",
            STANDARD.encode(nonce),
            STANDARD.encode(tag),
            STANDARD.encode(ciphertext)
        );
        std::fs::write(directory.path().join(".key"), &password).unwrap();
        std::fs::write(directory.path().join(".salt"), salt).unwrap();
        std::fs::write(directory.path().join(".credentials"), &credentials).unwrap();
        let cold = std::time::Instant::now();
        assert_eq!(decode(&password, directory.path()).unwrap(), expected);
        println!("cold recovery: {:?}", cold.elapsed());
        let warm = std::time::Instant::now();
        assert_eq!(decode(&password, directory.path()).unwrap(), expected);
        println!("cached recovery: {:?}", warm.elapsed());
        assert_eq!(
            std::fs::read_to_string(directory.path().join(".key")).unwrap(),
            password
        );
        assert_eq!(std::fs::read(directory.path().join(".salt")).unwrap(), salt);
        assert_eq!(
            std::fs::read_to_string(directory.path().join(".credentials")).unwrap(),
            credentials
        );
        assert!(lpm_common::permissions_are_owner_only(
            &std::fs::metadata(directory.path().join(".key-derived"))
                .unwrap()
                .permissions()
        ));
    }

    #[test]
    fn legacy_recovery_never_generates_a_missing_salt() {
        let directory = tempfile::tempdir().unwrap();
        assert!(decode(&"a".repeat(64), directory.path()).is_err());
        assert!(!directory.path().join(".salt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn derived_cache_rejects_shared_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (directory, path, credentials) = cache_fixture();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_authenticated_cache(&path, "expected", Some(&credentials)).is_none());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link");
        symlink(path, &link).unwrap();
        assert!(read_authenticated_cache(&link, "expected", Some(&credentials)).is_none());
    }
}
