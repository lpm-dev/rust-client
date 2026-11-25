//! TUF metadata documents, their signatures, and the checks every role
//! shares.

use super::TufError;
use super::canonical;
use lpm_common::Timestamp as Time;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// A signed metadata document: the typed `signed` object, the canonical
/// bytes its signatures cover, and those signatures.
#[derive(Debug, Clone)]
pub(super) struct Signed<T> {
    pub(super) signed: T,
    canonical: Vec<u8>,
    signatures: Vec<RawSignature>,
}

#[derive(Deserialize)]
struct RawEnvelope {
    signed: serde_json::Value,
    signatures: Vec<RawSignature>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSignature {
    keyid: String,
    sig: String,
}

/// The fields every top-level role's metadata carries.
pub(super) trait Role: DeserializeOwned {
    const NAME: &'static str;
    fn common(&self) -> &Common;
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Common {
    #[serde(rename = "_type")]
    kind: String,
    spec_version: String,
    pub(super) version: u64,
    expires: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Root {
    #[serde(flatten)]
    pub(super) common: Common,
    keys: BTreeMap<String, Key>,
    roles: BTreeMap<String, RoleKeys>,
    #[serde(default)]
    pub(super) consistent_snapshot: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Timestamp {
    #[serde(flatten)]
    pub(super) common: Common,
    pub(super) meta: BTreeMap<String, MetaFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Snapshot {
    #[serde(flatten)]
    pub(super) common: Common,
    pub(super) meta: BTreeMap<String, MetaFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Targets {
    #[serde(flatten)]
    pub(super) common: Common,
    pub(super) targets: BTreeMap<String, TargetFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct Key {
    keytype: String,
    scheme: String,
    keyval: KeyValue,
}

#[derive(Debug, Clone, Deserialize)]
struct KeyValue {
    public: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RoleKeys {
    keyids: Vec<String>,
    threshold: u32,
}

/// What a snapshot or timestamp records about another metadata file.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct MetaFile {
    pub(super) version: u64,
    pub(super) length: Option<u64>,
    pub(super) hashes: Option<BTreeMap<String, String>>,
}

/// What the targets role records about a target file.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct TargetFile {
    pub(super) length: u64,
    pub(super) hashes: BTreeMap<String, String>,
}

macro_rules! impl_role {
    ($ty:ty, $name:literal) => {
        impl Role for $ty {
            const NAME: &'static str = $name;
            fn common(&self) -> &Common {
                &self.common
            }
        }
    };
}

impl_role!(Root, "root");
impl_role!(Timestamp, "timestamp");
impl_role!(Snapshot, "snapshot");
impl_role!(Targets, "targets");

impl<T: Role> Signed<T> {
    /// Parse a metadata document and check that it is the role it claims
    /// to be, in a TUF 1.x format. Signatures are checked separately with
    /// [`Self::verify_with`].
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, TufError> {
        let malformed = |detail: String| TufError::Malformed {
            role: T::NAME,
            detail,
        };
        let raw: RawEnvelope =
            serde_json::from_slice(bytes).map_err(|error| malformed(error.to_string()))?;
        let mut canonical = Vec::with_capacity(bytes.len());
        canonical::encode(&raw.signed, &mut canonical).map_err(malformed)?;
        let signed = T::deserialize(&raw.signed).map_err(|error| malformed(error.to_string()))?;
        let common = signed.common();
        if common.kind != T::NAME {
            return Err(malformed(format!("its _type is {:?}", common.kind)));
        }
        if common.spec_version.split('.').next() != Some("1") {
            return Err(malformed(format!(
                "it uses TUF specification {}, and this client supports 1.x",
                common.spec_version
            )));
        }
        Ok(Self {
            signed,
            canonical,
            signatures: raw.signatures,
        })
    }

    pub(super) fn version(&self) -> u64 {
        self.signed.common().version
    }

    /// Check that `delegator`'s keys for this role signed the document at
    /// least as many times as the role's threshold requires.
    ///
    /// Each key counts once, however many signatures name it and under
    /// however many key IDs or encodings it is listed.
    pub(super) fn verify_with(&self, delegator: &Root) -> Result<(), TufError> {
        let role = delegator
            .roles
            .get(T::NAME)
            .ok_or_else(|| TufError::Malformed {
                role: Root::NAME,
                detail: format!("it defines no {} role", T::NAME),
            })?;
        if role.threshold == 0 {
            return Err(TufError::Malformed {
                role: Root::NAME,
                detail: format!("the {} role has a threshold of 0", T::NAME),
            });
        }
        let mut counted: Vec<Vec<u8>> = Vec::with_capacity(role.keyids.len());
        for keyid in &role.keyids {
            let Some(key) = delegator.keys.get(keyid) else {
                continue;
            };
            let Some(identity) = key.identity() else {
                continue;
            };
            if counted.contains(&identity) {
                continue;
            }
            let signed_by_key = self
                .signatures
                .iter()
                .filter(|signature| &signature.keyid == keyid)
                .any(|signature| key.verifies(&self.canonical, &signature.sig));
            if signed_by_key {
                counted.push(identity);
            }
        }
        let threshold = role.threshold as usize;
        if counted.len() >= threshold {
            Ok(())
        } else {
            Err(TufError::Threshold {
                role: T::NAME,
                valid: counted.len(),
                threshold,
            })
        }
    }

    /// Refuse metadata whose expiry has passed at `now`.
    pub(super) fn ensure_unexpired(&self, now: SystemTime) -> Result<(), TufError> {
        let expires = &self.signed.common().expires;
        let parsed = Time::parse_rfc3339(expires).map_err(|error| TufError::Malformed {
            role: T::NAME,
            detail: format!("its expiry {expires:?} is not an RFC 3339 time: {error}"),
        })?;
        let now: Time = now.into();
        if now < parsed {
            Ok(())
        } else {
            Err(TufError::Expired {
                role: T::NAME,
                expires: expires.clone(),
            })
        }
    }
}

impl Root {
    /// Whether the keys or threshold for `role` differ between two roots.
    pub(super) fn role_keys_differ(&self, other: &Root, role: &str) -> bool {
        self.role_keys(role) != other.role_keys(role)
    }

    fn role_keys(&self, role: &str) -> Option<(Vec<Vec<u8>>, u32)> {
        self.roles.get(role).map(|keys| {
            let mut identities: Vec<Vec<u8>> = keys
                .keyids
                .iter()
                .filter_map(|keyid| self.keys.get(keyid))
                .filter_map(Key::identity)
                .collect();
            identities.sort_unstable();
            identities.dedup();
            (identities, keys.threshold)
        })
    }
}

impl Key {
    /// The key itself, independent of how the metadata encodes it: the
    /// scheme and the DER public key or raw Ed25519 bytes. `None` for a key
    /// this client can't use.
    fn identity(&self) -> Option<Vec<u8>> {
        use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
        let (tag, bytes) = match (self.keytype.as_str(), self.scheme.as_str()) {
            ("ecdsa" | "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256") => (
                b'1',
                p256::ecdsa::VerifyingKey::from_public_key_pem(&self.keyval.public)
                    .ok()?
                    .to_public_key_der()
                    .ok()?
                    .into_vec(),
            ),
            ("ecdsa" | "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384") => (
                b'3',
                p384::ecdsa::VerifyingKey::from_public_key_pem(&self.keyval.public)
                    .ok()?
                    .to_public_key_der()
                    .ok()?
                    .into_vec(),
            ),
            ("ed25519", "ed25519") => (b'e', hex::decode(&self.keyval.public).ok()?),
            _ => return None,
        };
        let mut identity = Vec::with_capacity(bytes.len() + 1);
        identity.push(tag);
        identity.extend_from_slice(&bytes);
        Some(identity)
    }

    /// Whether `signature_hex` is this key's signature over `message`.
    ///
    /// Supports the key types securesystemslib signs TUF metadata with;
    /// a key of any other type never verifies, so it can't count toward a
    /// threshold.
    fn verifies(&self, message: &[u8], signature_hex: &str) -> bool {
        let Ok(signature) = hex::decode(signature_hex) else {
            return false;
        };
        match (self.keytype.as_str(), self.scheme.as_str()) {
            ("ecdsa" | "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256") => {
                verify_p256(&self.keyval.public, message, &signature)
            }
            ("ecdsa" | "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384") => {
                verify_p384(&self.keyval.public, message, &signature)
            }
            ("ed25519", "ed25519") => verify_ed25519(&self.keyval.public, message, &signature),
            _ => false,
        }
    }
}

fn verify_p256(public_pem: &str, message: &[u8], signature_der: &[u8]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p256::pkcs8::DecodePublicKey;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_pem(public_pem) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_der(signature_der) else {
        return false;
    };
    key.verify_prehash(&Sha256::digest(message), &signature)
        .is_ok()
}

fn verify_p384(public_pem: &str, message: &[u8], signature_der: &[u8]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p384::pkcs8::DecodePublicKey;
    let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_pem(public_pem) else {
        return false;
    };
    let Ok(signature) = p384::ecdsa::Signature::from_der(signature_der) else {
        return false;
    };
    key.verify_prehash(&sha2::Sha384::digest(message), &signature)
        .is_ok()
}

fn verify_ed25519(public_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    let Ok(public) = hex::decode(public_hex) else {
        return false;
    };
    let (Ok(public), Ok(signature)) = (
        <[u8; 32]>::try_from(public.as_slice()),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else {
        return false;
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

/// Check `bytes` against a recorded length and set of hashes.
///
/// Every recorded SHA-256 or SHA-512 hash must match. Hashes in other
/// algorithms are skipped, but at least one hash must be one this client
/// computes when `require_hash` is set.
pub(super) fn check_length_and_hashes(
    bytes: &[u8],
    length: Option<u64>,
    hashes: Option<&BTreeMap<String, String>>,
    require_hash: bool,
    name: &str,
) -> Result<(), TufError> {
    let mismatch = |detail: String| TufError::Mismatch {
        name: name.to_string(),
        detail,
    };
    if let Some(length) = length
        && bytes.len() as u64 != length
    {
        return Err(mismatch(format!(
            "it is {} bytes, and {length} were expected",
            bytes.len()
        )));
    }
    let mut checked = 0usize;
    for (algorithm, expected) in hashes.into_iter().flatten() {
        let actual = match algorithm.as_str() {
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            _ => continue,
        };
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(mismatch(format!("its {algorithm} hash differs")));
        }
        checked += 1;
    }
    if require_hash && checked == 0 {
        return Err(mismatch(
            "no SHA-256 or SHA-512 hash is recorded for it".into(),
        ));
    }
    Ok(())
}
