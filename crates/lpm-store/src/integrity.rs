use std::path::Path;

use lpm_common::LpmError;
use sha1::Sha1;
use sha2::{Digest, Sha512};

/// Strict validator for the local-tarball CAS key.
///
/// Local tarballs use raw lowercase-hex SHA-256 (not an SRI string)
/// so the input can be sourced from `sha2::Sha256` digests directly
/// without an Integrity round-trip. Strict shape: exactly 64
/// characters, all `[0-9a-f]`. Case sensitivity is intentional —
/// uppercase hex would fork two store entries for the same content,
/// reintroducing the dedupe gap the CAS layer exists to close.
pub(crate) fn validate_sha256_hex(hex: &str) -> Result<(), LpmError> {
    if hex.len() != 64 {
        return Err(LpmError::InvalidIntegrity(format!(
            "expected 64 lowercase hex chars (SHA-256 digest), got {} chars",
            hex.len()
        )));
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LpmError::InvalidIntegrity(
            "expected 64 lowercase hex chars (SHA-256 digest), got non-hex or uppercase".into(),
        ));
    }
    Ok(())
}

/// Compute an SRI (Subresource Integrity) hash for tarball data.
/// Format: `sha512-<base64>` (matches npm's integrity field format).
pub fn compute_sri_hash(data: &[u8]) -> String {
    use base64::Engine;
    let hash = Sha512::digest(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha512-{b64}")
}

/// Compute a sha256 SRI for tarball data. Paired with
/// [`compute_sri_hash`] so callers can verify against the algorithm
/// declared in an `expected` SRI string instead of silently trusting
/// a computed sha512 when the lockfile declares sha256.
pub fn compute_sri_hash_sha256(data: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha256-{b64}")
}

/// Compute a sha1 SRI for tarball data. npm's legacy `dist.shasum`
/// field is a hex SHA-1 digest; converting it to SRI lets the same
/// verifier cover old registry metadata without falling back to
/// unverified downloads.
pub fn compute_sri_hash_sha1(data: &[u8]) -> String {
    use base64::Engine;
    let hash = Sha1::digest(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha1-{b64}")
}

/// Read the stored `.integrity` file for a package.
/// Returns `None` if the file doesn't exist (package stored before integrity tracking).
pub fn read_stored_integrity(store_dir: &Path) -> Option<String> {
    let integrity_path = store_dir.join(".integrity");
    std::fs::read_to_string(integrity_path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_stored_integrity_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_stored_integrity(dir.path()).is_none());
    }

    #[test]
    fn compute_sri_hash_sha256_known_vector() {
        let sri = compute_sri_hash_sha256(b"");
        assert_eq!(sri, "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn compute_sri_hash_sha1_known_vector() {
        let sri = compute_sri_hash_sha1(b"");
        assert_eq!(sri, "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=");
    }
}
