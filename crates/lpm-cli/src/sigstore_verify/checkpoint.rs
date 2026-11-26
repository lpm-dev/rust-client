//! Transparency log checkpoints: C2SP signed notes (c2sp.org/signed-note)
//! whose text is a tree head (c2sp.org/tlog-checkpoint).
//!
//! A note may carry several signatures, such as witness co-signatures
//! after the log's own. Only the log's signature counts and others are
//! ignored; one from the log that doesn't verify refuses the whole note.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256, Sha384};

use super::RekorKey;
use super::chain::verify_ecdsa_prehash;
use super::der::{self, Reader};

/// More signature lines than any real checkpoint carries; Go's note
/// parser stops at the same bound.
const MAX_SIGNATURES: usize = 100;

const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// How a log signs its checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogStyle {
    /// Rekor v1 signs under a name of its choosing, its host with or
    /// without a port, over an origin naming the shard. Its signature is
    /// the one with the log's key ID, as Rekor's own verifier finds it.
    RekorV1,
    /// Rekor v2 signs under its name, the host of its base URL, which is
    /// also the checkpoint's origin. Its signature is the one with both
    /// that name and the log's key ID.
    RekorV2,
}

/// A checkpoint the log signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Checkpoint {
    pub(super) size: u64,
    pub(super) root_hash: Vec<u8>,
}

/// Verify `envelope`, a signed checkpoint, as the log `log` signed it.
pub(super) fn verify_checkpoint(
    envelope: &str,
    log: &RekorKey,
    style: LogStyle,
) -> Result<Checkpoint, String> {
    let name = log_name(&log.base_url);
    let key = LogKey::from_spki(&log.spki_der)?;
    let key_id = match (&key, &name) {
        (LogKey::Ecdsa { .. }, _) => key.key_id(""),
        (LogKey::Ed25519(_), Some(name)) => key.key_id(name),
        (LogKey::Ed25519(_), None) => return Err(unnamed_log(log)),
    };
    let required_name = match style {
        LogStyle::RekorV1 => None,
        LogStyle::RekorV2 => Some(name.as_deref().ok_or_else(|| unnamed_log(log))?),
    };

    let (text, signatures) = split_note(envelope)?;
    let mut verified = false;
    for (index, line) in signatures.split_terminator('\n').enumerate() {
        if index == MAX_SIGNATURES {
            return Err(format!(
                "the checkpoint carries more than {MAX_SIGNATURES} signatures"
            ));
        }
        let (signer, signature) = parse_signature_line(line)?;
        if signature[..4] != key_id || required_name.is_some_and(|name| signer != name) {
            continue;
        }
        // A repeated signature from the log adds nothing.
        if verified {
            continue;
        }
        key.verify(text.as_bytes(), &signature[4..])
            .map_err(|why| format!("the log's signature on the checkpoint: {why}"))?;
        verified = true;
    }
    if !verified {
        return Err(format!(
            "the checkpoint carries no signature from the log `{}`",
            name.as_deref().unwrap_or(&log.base_url)
        ));
    }

    let checkpoint = parse_checkpoint_text(text)?;
    if let Some(name) = required_name
        && checkpoint.origin != name
    {
        return Err(format!(
            "the checkpoint's origin `{}` is not the log `{name}`",
            checkpoint.origin
        ));
    }
    Ok(Checkpoint {
        size: checkpoint.size,
        root_hash: checkpoint.root_hash,
    })
}

fn unnamed_log(log: &RekorKey) -> String {
    format!(
        "the trust root gives the log no base URL to name it by (`{}`)",
        log.base_url
    )
}

/// The name a Rekor v2 log signs its checkpoints with: the host of its
/// base URL, which may be given without a scheme.
pub(super) fn log_name(base_url: &str) -> Option<String> {
    let parsed = url::Url::parse(base_url)
        .ok()
        .filter(|url| url.has_host())
        .or_else(|| url::Url::parse(&format!("https://{base_url}")).ok())?;
    let host = parsed.host_str()?;
    is_valid_key_name(host).then(|| host.to_string())
}

/// C2SP key names are non-empty, contain no whitespace, and no `+`.
fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(char::is_whitespace) && !name.contains('+')
}

/// Split a signed note into its text, which ends with a newline, and its
/// signature lines.
fn split_note(envelope: &str) -> Result<(&str, &str), String> {
    if envelope.chars().any(|c| (c as u32) < 0x20 && c != '\n') {
        return Err("the checkpoint contains a control character".into());
    }
    let split = envelope.rfind("\n\n").ok_or_else(|| {
        "the checkpoint has no blank line between its text and its signatures".to_string()
    })?;
    let text = &envelope[..=split];
    let signatures = &envelope[split + 2..];
    if signatures.is_empty() || !signatures.ends_with('\n') {
        return Err("the checkpoint's signature lines don't end with a newline".into());
    }
    Ok((text, signatures))
}

/// `— <key name> base64(key ID || signature)`.
fn parse_signature_line(line: &str) -> Result<(&str, Vec<u8>), String> {
    let rest = line
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or_else(|| format!("checkpoint signature line `{line}` doesn't start with `— `"))?;
    let (name, encoded) = rest
        .split_once(' ')
        .ok_or_else(|| format!("checkpoint signature line `{line}` has no signature"))?;
    if !is_valid_key_name(name) {
        return Err(format!(
            "checkpoint signature line `{line}` has an invalid key name"
        ));
    }
    let decoded = BASE64
        .decode(encoded)
        .map_err(|e| format!("checkpoint signature line `{line}` is not base64: {e}"))?;
    if decoded.len() < 5 {
        return Err(format!("checkpoint signature line `{line}` is too short"));
    }
    Ok((name, decoded))
}

struct CheckpointText {
    origin: String,
    size: u64,
    root_hash: Vec<u8>,
}

/// The origin, tree size and root hash lines that open the checkpoint
/// text. Lines after them are extensions and carry nothing verified here.
fn parse_checkpoint_text(text: &str) -> Result<CheckpointText, String> {
    if text.contains('\r') {
        return Err("the checkpoint contains a carriage return".into());
    }
    let mut lines = text.splitn(4, '\n');
    let (Some(origin), Some(size), Some(root_hash), Some(_)) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Err("the checkpoint text has fewer than three lines".into());
    };
    if origin.is_empty() {
        return Err("the checkpoint has an empty origin".into());
    }
    if size.is_empty()
        || (size.len() > 1 && size.starts_with('0'))
        || !size.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("the checkpoint's tree size `{size}` is malformed"));
    }
    let size = size
        .parse::<u64>()
        .map_err(|e| format!("the checkpoint's tree size `{size}` is out of range: {e}"))?;
    let root_hash = BASE64
        .decode(root_hash)
        .map_err(|e| format!("the checkpoint's root hash is not base64: {e}"))?;
    if root_hash.len() != 32 {
        return Err(format!(
            "the checkpoint's root hash is {} bytes where SHA-256 is 32",
            root_hash.len()
        ));
    }
    Ok(CheckpointText {
        origin: origin.to_string(),
        size,
        root_hash,
    })
}

enum LogKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    /// SubjectPublicKeyInfo DER, with the hash its curve signs with.
    Ecdsa {
        spki_der: Vec<u8>,
        sha384: bool,
    },
}

impl LogKey {
    fn from_spki(spki_der: &[u8]) -> Result<Self, String> {
        if let Some(raw) = ed25519_spki_key(spki_der) {
            return ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map(Self::Ed25519)
                .map_err(|e| format!("the log's Ed25519 key is invalid: {e}"));
        }
        use p256::pkcs8::DecodePublicKey;
        if p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).is_ok() {
            return Ok(Self::Ecdsa {
                spki_der: spki_der.to_vec(),
                sha384: false,
            });
        }
        if p384::ecdsa::VerifyingKey::from_public_key_der(spki_der).is_ok() {
            return Ok(Self::Ecdsa {
                spki_der: spki_der.to_vec(),
                sha384: true,
            });
        }
        Err("the log's key is not an Ed25519, ECDSA P-256 or ECDSA P-384 key".into())
    }

    /// The C2SP key ID: for Ed25519, the hash of the key name, a newline,
    /// signature type 0x01 and the raw key; for ECDSA, the hash of the
    /// SubjectPublicKeyInfo, whatever the name.
    fn key_id(&self, name: &str) -> [u8; 4] {
        let digest = match self {
            Self::Ed25519(key) => {
                let mut hasher = Sha256::new();
                hasher.update(name.as_bytes());
                hasher.update([b'\n', 0x01]);
                hasher.update(key.as_bytes());
                hasher.finalize()
            }
            Self::Ecdsa { spki_der, .. } => Sha256::digest(spki_der),
        };
        [digest[0], digest[1], digest[2], digest[3]]
    }

    fn verify(&self, text: &[u8], signature: &[u8]) -> Result<(), String> {
        match self {
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| format!("not an Ed25519 signature: {e}"))?;
                key.verify_strict(text, &signature)
                    .map_err(|e| format!("Ed25519 signature did not verify: {e}"))
            }
            Self::Ecdsa { spki_der, sha384 } => {
                let digest = if *sha384 {
                    Sha384::digest(text).to_vec()
                } else {
                    Sha256::digest(text).to_vec()
                };
                verify_ecdsa_prehash(spki_der, &digest, signature)
            }
        }
    }
}

/// The raw key of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
fn ed25519_spki_key(spki_der: &[u8]) -> Option<[u8; 32]> {
    const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
    let mut outer = Reader::new(spki_der);
    let mut spki = outer
        .nested(der::TAG_SEQUENCE, "SubjectPublicKeyInfo")
        .ok()?;
    outer.finish("SubjectPublicKeyInfo").ok()?;
    let mut algorithm = spki.nested(der::TAG_SEQUENCE, "algorithm").ok()?;
    if algorithm.expect(der::TAG_OID, "algorithm").ok()?.contents != OID_ED25519 {
        return None;
    }
    algorithm.finish("algorithm").ok()?;
    let bits = spki.expect(der::TAG_BIT_STRING, "subjectPublicKey").ok()?;
    spki.finish("SubjectPublicKeyInfo").ok()?;
    match bits.contents {
        [0, key @ ..] => key.try_into().ok(),
        _ => None,
    }
}
