use crate::error::LpmError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

/// Subresource Integrity (SRI) hash.
///
/// Format: `algorithm-base64hash`
/// Example: `sha512-abc123...`
///
/// Used to verify package tarballs haven't been tampered with.
/// The LPM registry returns integrity hashes in this format for every package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub algorithm: HashAlgorithm,
    /// The raw hash bytes.
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl Integrity {
    /// Parse an SRI string like `sha512-abc123...`
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let (algo_str, hash_b64) = input.split_once('-').ok_or_else(|| {
            LpmError::InvalidIntegrity(format!("{input} missing algorithm prefix (e.g., sha512-)"))
        })?;

        let algorithm = match algo_str {
            "sha256" => HashAlgorithm::Sha256,
            "sha512" => HashAlgorithm::Sha512,
            other => {
                return Err(LpmError::InvalidIntegrity(format!(
                    "unsupported algorithm: {other} (expected sha256 or sha512)"
                )));
            }
        };

        let hash = BASE64.decode(hash_b64).map_err(|e| {
            LpmError::InvalidIntegrity(format!("invalid base64 in integrity hash: {e}"))
        })?;

        Ok(Integrity { algorithm, hash })
    }

    /// Compute integrity hash from raw bytes.
    pub fn from_bytes(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let hash = match algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        };

        Integrity { algorithm, hash }
    }

    /// Verify that the given data matches this integrity hash.
    pub fn verify(&self, data: &[u8]) -> Result<(), LpmError> {
        let computed = Self::from_bytes(self.algorithm, data);
        if self.hash == computed.hash {
            Ok(())
        } else {
            Err(LpmError::IntegrityMismatch {
                expected: self.to_string(),
                actual: computed.to_string(),
            })
        }
    }

    /// Verify a file on disk matches this integrity hash (bounded-memory).
    ///
    /// Reads the file in 64KB chunks — never buffers the full file in memory.
    /// Supports SHA-256 and SHA-512.
    pub fn verify_file(&self, path: &std::path::Path) -> Result<(), LpmError> {
        use std::io::Read;

        let mut file = std::fs::File::open(path).map_err(LpmError::Io)?;
        let mut buf = [0u8; 64 * 1024];

        let computed_hash = match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                loop {
                    let n = file.read(&mut buf).map_err(LpmError::Io)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                loop {
                    let n = file.read(&mut buf).map_err(LpmError::Io)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hasher.finalize().to_vec()
            }
        };

        if self.hash == computed_hash {
            Ok(())
        } else {
            let computed = Integrity {
                algorithm: self.algorithm,
                hash: computed_hash,
            };
            Err(LpmError::IntegrityMismatch {
                expected: self.to_string(),
                actual: computed.to_string(),
            })
        }
    }

    /// Returns the base64-encoded hash string (without algorithm prefix).
    pub fn hash_base64(&self) -> String {
        BASE64.encode(&self.hash)
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algo = match self.algorithm {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        };
        write!(f, "{}-{}", algo, self.hash_base64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha512_integrity() {
        let sri = "sha512-YWJjMTIz"; // "abc123" in base64
        let integrity = Integrity::parse(sri).unwrap();
        assert_eq!(integrity.algorithm, HashAlgorithm::Sha512);
        assert_eq!(integrity.to_string(), sri);
    }

    #[test]
    fn parse_sha256_integrity() {
        let sri = "sha256-YWJjMTIz";
        let integrity = Integrity::parse(sri).unwrap();
        assert_eq!(integrity.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn reject_missing_algorithm() {
        assert!(Integrity::parse("noprefixhere").is_err());
    }

    #[test]
    fn reject_unsupported_algorithm() {
        assert!(Integrity::parse("sha1-YWJjMTIz").is_err());
    }

    #[test]
    fn reject_invalid_base64() {
        assert!(Integrity::parse("sha512-!!!notbase64!!!").is_err());
    }

    #[test]
    fn compute_and_verify_sha512() {
        let data = b"hello world";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        assert!(integrity.verify(data).is_ok());
        assert!(integrity.verify(b"wrong data").is_err());
    }

    #[test]
    fn compute_and_verify_sha256() {
        let data = b"test payload";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha256, data);
        assert!(integrity.verify(data).is_ok());
        assert!(integrity.verify(b"different").is_err());
    }

    #[test]
    fn roundtrip_parse_display() {
        let data = b"roundtrip test";
        let original = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        let serialized = original.to_string();
        let parsed = Integrity::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }
}
