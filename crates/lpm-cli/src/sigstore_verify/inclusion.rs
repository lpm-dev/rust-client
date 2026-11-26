use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

use super::checkpoint::{Checkpoint, LogStyle, verify_checkpoint};
use super::rekor_body::json_value_kind;
use super::rekor_set::{decode_log_id, parse_log_index};
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

    // A checkpoint carries no time to check the log's key against, and
    // without a SET the entry's `integratedTime` is unsigned. The log is
    // found by its ID, as Sigstore's verifiers find it; a SET, when there is
    // one, checks the key at the time it signs.
    let log_id_bytes =
        decode_log_id(&tlog_entry.log_id.key_id).map_err(VerifyError::InclusionProof)?;
    let rekor_key = rekor_keys
        .iter()
        .find(|k| k.log_id == log_id_bytes)
        .ok_or_else(|| VerifyError::MissingTrustMaterial {
            check: "Rekor inclusion proof",
            detail: format!("no pinned Rekor key for logId={}", tlog_entry.log_id.key_id),
        })?;

    let checkpoint_envelope = extract_checkpoint_envelope(&proof.checkpoint)?;
    let trusted = verify_checkpoint(&checkpoint_envelope, rekor_key, LogStyle::RekorV1)
        .map_err(VerifyError::InclusionProof)?;

    // Consistency: bundle's inclusion-proof fields agree with the
    // signed checkpoint. A bundle that says tree_size=N + root=R but
    // whose signed checkpoint commits to a different tree state is
    // structurally inconsistent — reject before walking the Merkle
    // path so the diagnostic names the mismatch directly.
    if u64::try_from(proof.tree_size).ok() != Some(trusted.size) {
        return Err(VerifyError::InclusionProof(format!(
            "inclusion proof tree_size={} disagrees with signed checkpoint tree_size={}",
            proof.tree_size, trusted.size,
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

    verify_leaf_inclusion(tlog_entry, &proof.hashes, proof.log_index as u64, &trusted)
}

/// Verify the inclusion proof of a Rekor v2 entry against the log `log`.
///
/// The checkpoint's origin is the log's name, and the top-level
/// `logIndex` is the leaf's index: Rekor v2 has no shards, and the
/// proof's own index, tree size and root hash repeat values the signed
/// checkpoint and the entry already give.
pub(super) fn verify_rekor_v2_inclusion_proof(
    tlog_entry: &crate::sigstore::TlogEntry,
    log: &RekorKey,
) -> Result<(), VerifyError> {
    let proof = tlog_entry
        .resolved_inclusion_proof()
        .ok_or(VerifyError::InclusionProofMissing)?;
    let checkpoint_envelope = extract_checkpoint_envelope(&proof.checkpoint)?;
    let trusted = verify_checkpoint(&checkpoint_envelope, log, LogStyle::RekorV2)
        .map_err(VerifyError::InclusionProof)?;
    let log_index = parse_log_index(&tlog_entry.log_index)
        .map_err(|e| VerifyError::InclusionProof(e.to_string()))?;
    verify_leaf_inclusion(tlog_entry, &proof.hashes, log_index as u64, &trusted)
}

/// Walk the entry's leaf up to the signed checkpoint's root.
fn verify_leaf_inclusion(
    tlog_entry: &crate::sigstore::TlogEntry,
    hashes: &[String],
    leaf_index: u64,
    trusted: &Checkpoint,
) -> Result<(), VerifyError> {
    if leaf_index >= trusted.size {
        return Err(VerifyError::InclusionProof(format!(
            "the entry's index {leaf_index} is not inside the signed checkpoint's tree of size {}",
            trusted.size
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

    let sibling_hashes = hashes
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

    let computed_root =
        rfc6962_verify_inclusion(leaf_index, trusted.size, &leaf_hash, &sibling_hashes)?;
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
pub(super) fn extract_checkpoint_envelope(
    value: &serde_json::Value,
) -> Result<String, VerifyError> {
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
