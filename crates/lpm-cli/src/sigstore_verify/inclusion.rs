use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use super::rekor_body::json_value_kind;
use super::rekor_set::{decode_log_id, p256_verifying_key_from_spki, parse_integrated_time};
use super::{RekorKey, VerifyError};

/// Verify the Rekor Merkle inclusion proof attached to `tlog_entry`.
///
/// The inclusion proof is the second offline-verifiable anchor in a
/// Sigstore bundle, alongside the SET. It proves an entry's existence
/// in the transparency log at a specific tree state via the signed
/// checkpoint and the sibling-hash path to the root.
///
/// Merkle walking follows RFC 6962 section 2.1.1:
/// `hash_children(left, right) = sha256(0x01 || left || right)`, and
/// `leaf_hash(data) = sha256(0x00 || data)`.
///
/// Returns `Ok(())` only when every step passes. Returns
/// [`VerifyError::InclusionProofMissing`] if the bundle carries no
/// inclusion proof; the caller decides whether that is fatal per
/// [`super::RekorInclusionProofPolicy`].
pub fn verify_inclusion_proof(
    tlog_entry: &crate::sigstore::TlogEntry,
    rekor_keys: &[RekorKey],
) -> Result<(), VerifyError> {
    let proof = tlog_entry
        .resolved_inclusion_proof()
        .ok_or(VerifyError::InclusionProofMissing)?;

    let integrated_time = parse_integrated_time(&tlog_entry.integrated_time)
        .map_err(|e| VerifyError::InclusionProof(format!("{e}")))?;
    let log_id_bytes = decode_log_id(&tlog_entry.log_id.key_id)
        .map_err(|e| VerifyError::InclusionProof(format!("{e}")))?;
    let rekor_key = rekor_keys
        .iter()
        .find(|k| k.log_id == log_id_bytes && k.valid_for.contains(integrated_time))
        .ok_or_else(|| {
            VerifyError::InclusionProof(format!(
                "no pinned Rekor key for logId={} valid at integratedTime={}",
                tlog_entry.log_id.key_id, tlog_entry.integrated_time,
            ))
        })?;

    let checkpoint_envelope = extract_checkpoint_envelope(&proof.checkpoint)?;
    let trusted = verify_checkpoint_signature(&checkpoint_envelope, rekor_key)?;

    // Consistency: bundle's inclusion-proof fields agree with the
    // signed checkpoint. A bundle that says tree_size=N + root=R but
    // whose signed checkpoint commits to a different tree state is
    // structurally inconsistent — reject before walking the Merkle
    // path so the diagnostic names the mismatch directly.
    if trusted.tree_size != proof.tree_size {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof tree_size={} disagrees with signed checkpoint tree_size={}",
            proof.tree_size, trusted.tree_size,
        )));
    }
    let proof_root_bytes = decode_root_hash_hex_or_base64(&proof.root_hash).map_err(|e| {
        VerifyError::InclusionProof(format!(
            "inclusion proof root_hash is neither valid hex nor base64: {e}"
        ))
    })?;
    if proof_root_bytes != trusted.root_hash {
        return Err(VerifyError::InclusionProof(
            "inclusion proof root_hash disagrees with signed checkpoint root".into(),
        ));
    }

    // The outer `TlogEntry.logIndex` is Rekor's global virtual
    // index across all shards; `inclusionProof.logIndex` is the
    // per-shard tree index. Modern (sharded) Rekor returns
    // different values for the two — they are intentionally not
    // required to agree. The Merkle-proof check only consumes the
    // per-shard index (it walks the per-shard tree), so we keep
    // only the structural sanity checks below.
    if proof.log_index < 0 || proof.tree_size <= 0 {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof has non-positive log_index or tree_size: \
             log_index={}, tree_size={}",
            proof.log_index, proof.tree_size,
        )));
    }
    if (proof.log_index as u64) >= (proof.tree_size as u64) {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof log_index={} is not less than tree_size={}",
            proof.log_index, proof.tree_size,
        )));
    }

    let body_bytes = BASE64
        .decode(tlog_entry.canonicalized_body.as_bytes())
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "canonicalizedBody is not valid base64 — cannot compute leaf hash: {e}"
            ))
        })?;
    let leaf_hash = rfc6962_leaf_hash(&body_bytes);

    let sibling_hashes = proof
        .hashes
        .iter()
        .map(|h| {
            decode_root_hash_hex_or_base64(h).map_err(|e| {
                VerifyError::InclusionProof(format!(
                    "inclusion proof sibling hash is neither hex nor base64: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (i, sibling) in sibling_hashes.iter().enumerate() {
        if sibling.len() != 32 {
            return Err(VerifyError::InclusionProof(format!(
                "inclusion proof sibling hash {i} is {} bytes (expected 32 for sha256)",
                sibling.len()
            )));
        }
    }

    let computed_root = rfc6962_verify_inclusion(
        proof.log_index as u64,
        proof.tree_size as u64,
        &leaf_hash,
        &sibling_hashes,
    )?;
    if computed_root != trusted.root_hash {
        return Err(VerifyError::InclusionProof(format!(
            "Merkle walk root does not match signed checkpoint root: \
             computed={}, signed={}",
            hex::encode(&computed_root),
            hex::encode(&trusted.root_hash),
        )));
    }

    Ok(())
}

/// Pull the checkpoint signed-note string out of an
/// `inclusion_proof.checkpoint` field. The Sigstore Bundle v0.3 spec
/// wraps it as `{ "envelope": "..." }`; some signers / older bundles
/// emit a bare string. Accept both.
fn extract_checkpoint_envelope(value: &serde_json::Value) -> Result<String, VerifyError> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Object(obj) => obj
            .get("envelope")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| {
                VerifyError::InclusionProof(
                    "inclusion proof checkpoint object has no string `envelope` field".into(),
                )
            }),
        other => Err(VerifyError::InclusionProof(format!(
            "inclusion proof checkpoint is {} (expected string or {{\"envelope\":\"...\"}} object)",
            json_value_kind(other)
        ))),
    }
}

/// Parsed and signature-verified checkpoint body. Trusted = the
/// fields below were committed to by the Rekor signing key.
struct TrustedCheckpoint {
    tree_size: i64,
    root_hash: Vec<u8>,
}

/// Verify a C2SP signed-note checkpoint against the pinned Rekor key.
///
/// Format (canonical signed-note):
/// ```text
/// <origin>
/// <tree_size>
/// <root_hash_base64>
/// <... optional extra body lines ...>
///
/// — <name> <base64(key_hint || signature)>
/// ```
///
/// The signed bytes are the body (lines before the empty separator),
/// terminated by `\n`. The signature is DER-encoded ECDSA over
/// `sha256(body_bytes)`. The 4-byte key_hint prefix is informational
/// — we look up the Rekor key by `logId` instead, so a wrong hint
/// doesn't cause a false reject (a wrong signature still does).
fn verify_checkpoint_signature(
    envelope: &str,
    rekor_key: &RekorKey,
) -> Result<TrustedCheckpoint, VerifyError> {
    let (text, sig_block) = envelope.split_once("\n\n").ok_or_else(|| {
        VerifyError::InclusionProof(
            "checkpoint envelope is missing the empty-line separator between body and signatures"
                .into(),
        )
    })?;
    let signed_bytes = format!("{text}\n");

    let mut body_lines = text.lines();
    let _origin = body_lines
        .next()
        .ok_or_else(|| VerifyError::InclusionProof("checkpoint body has no origin line".into()))?;
    let tree_size_str = body_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint body has no tree-size line".into())
    })?;
    let root_hash_b64 = body_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint body has no root-hash line".into())
    })?;

    let tree_size: i64 = tree_size_str.trim().parse().map_err(|e| {
        VerifyError::InclusionProof(format!(
            "checkpoint body tree-size line `{tree_size_str}` is not a valid i64: {e}"
        ))
    })?;
    let root_hash = BASE64
        .decode(root_hash_b64.trim().as_bytes())
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "checkpoint body root-hash line `{root_hash_b64}` is not valid base64: {e}"
            ))
        })?;
    if root_hash.len() != 32 {
        return Err(VerifyError::InclusionProof(format!(
            "checkpoint root hash is {} bytes (expected 32 for sha256)",
            root_hash.len()
        )));
    }

    let mut sig_lines = sig_block.lines().filter(|l| !l.is_empty());
    let sig_line = sig_lines.next().ok_or_else(|| {
        VerifyError::InclusionProof("checkpoint envelope has no signature line".into())
    })?;

    // Per C2SP signed-note: "— <name> <base64>" where the em-dash is
    // U+2014 (UTF-8: E2 80 94). Strip prefix; the name doesn't gate
    // verification (we look the key up by logId), but the base64
    // value is what we need.
    let rest = sig_line
        .strip_prefix("\u{2014} ")
        .or_else(|| sig_line.strip_prefix("- "))
        .ok_or_else(|| {
            VerifyError::InclusionProof(format!(
                "checkpoint signature line does not start with `— ` (em-dash + space): `{sig_line}`"
            ))
        })?;
    let (_name, b64) = rest.split_once(' ').ok_or_else(|| {
        VerifyError::InclusionProof(format!(
            "checkpoint signature line is missing the base64 signature component: `{sig_line}`"
        ))
    })?;
    let key_hint_plus_sig = BASE64.decode(b64.trim().as_bytes()).map_err(|e| {
        VerifyError::InclusionProof(format!("checkpoint signature base64 did not decode: {e}"))
    })?;
    if key_hint_plus_sig.len() < 4 {
        return Err(VerifyError::InclusionProof(format!(
            "checkpoint signature is {} bytes (expected at least 4 for the key-hint prefix)",
            key_hint_plus_sig.len()
        )));
    }
    let sig_bytes = &key_hint_plus_sig[4..];
    let signature = Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::InclusionProof(format!("checkpoint signature is not valid DER ECDSA: {e}"))
    })?;

    let verifying_key = p256_verifying_key_from_spki(&rekor_key.spki_der).map_err(|e| {
        VerifyError::InclusionProof(format!(
            "pinned Rekor key did not decode as ECDSA P-256 SPKI: {e}"
        ))
    })?;
    let digest = Sha256::digest(signed_bytes.as_bytes());
    // Same prehash semantic as the SET verifier — Rekor signs the
    // checkpoint digest via Go's ecdsa.SignASN1 prehash protocol.
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .map_err(|e| {
            VerifyError::InclusionProof(format!(
                "checkpoint signature did not verify under the pinned Rekor key: {e}"
            ))
        })?;

    Ok(TrustedCheckpoint {
        tree_size,
        root_hash,
    })
}

/// Decode a 32-byte sha256 from either hex (Rekor canonical) or
/// base64 (Sigstore Bundle spec). Rekor's HTTP response uses hex for
/// the `rootHash` and `hashes` fields, but some bundle producers
/// re-encode as base64. Accept both to avoid false-rejecting
/// otherwise-valid bundles.
fn decode_root_hash_hex_or_base64(s: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = hex::decode(s) {
        return Ok(bytes);
    }
    BASE64
        .decode(s.as_bytes())
        .map_err(|e| format!("not hex; not base64 ({e})"))
}

/// `MTH({d(0)}) = SHA-256(0x00 || d(0))` per RFC 6962 §2.1.
pub(super) fn rfc6962_leaf_hash(leaf_data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00_u8]);
    hasher.update(leaf_data);
    hasher.finalize().to_vec()
}

/// `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` per
/// RFC 6962 §2.1, hash combination only.
pub(super) fn rfc6962_hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01_u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// RFC 6962 §2.1.1 inclusion proof walker. Mirrors the canonical
/// implementation in `sigstore/sigstore-go`'s `pkg/verify/tlog.go`
/// and Trillian's reference Go code. Returns the computed root hash;
/// the caller compares against the trusted (signed) root.
///
/// Algorithm:
/// - `fn` is the leaf's index inside the tree
/// - `sn` is the rightmost leaf index (`tree_size - 1`)
/// - For each sibling hash in the proof:
///   - If `fn` is odd OR `fn == sn` (i.e. we're a right child OR the
///     "last leaf" at this level), the sibling is on the LEFT.
///     Combine `sibling || current`, then walk up "right edges"
///     until `fn` is no longer the rightmost.
///   - Otherwise the sibling is on the RIGHT. Combine
///     `current || sibling`.
///   - Then halve both `fn` and `sn` (move up a level).
/// - After the walk, expect `sn == 0` (we reached the root) and
///   the proof to have been exactly the right arity.
pub(super) fn rfc6962_verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof: &[Vec<u8>],
) -> Result<Vec<u8>, VerifyError> {
    if leaf_index >= tree_size {
        return Err(VerifyError::InclusionProof(format!(
            "leaf_index={leaf_index} >= tree_size={tree_size}"
        )));
    }
    if tree_size == 1 {
        if !proof.is_empty() {
            return Err(VerifyError::InclusionProof(format!(
                "single-leaf tree expects an empty proof; got {} entries",
                proof.len()
            )));
        }
        return Ok(leaf_hash.to_vec());
    }

    let mut fn_: u64 = leaf_index;
    let mut sn: u64 = tree_size - 1;
    let mut r: Vec<u8> = leaf_hash.to_vec();
    for sibling in proof {
        if sn == 0 {
            return Err(VerifyError::InclusionProof(
                "inclusion proof contains more sibling hashes than the tree depth requires".into(),
            ));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = rfc6962_hash_children(sibling, &r);
            // Walk up the right-edge chain while `fn_` is even and
            // non-zero (we're at a "last leaf" position climbing
            // through multiple right edges).
            while fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = rfc6962_hash_children(&r, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof has too few sibling hashes; reached sn={sn} (expected 0)"
        )));
    }
    Ok(r)
}
