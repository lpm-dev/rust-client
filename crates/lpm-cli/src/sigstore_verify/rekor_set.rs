use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

use super::{RekorInclusionProofPolicy, RekorKey, VerifyError};

/// Verify the Rekor SET in `tlog_entry` against the pinned Rekor
/// signing key for the entry's `logID`.
///
/// The SET is Rekor's offline-verifiable promise that a given entry was
/// integrated into the transparency log at `integratedTime`. It signs a
/// canonical JSON payload containing `body`, `integratedTime`, `logID`,
/// and `logIndex`.
///
/// Returns the parsed `integratedTime` as `SystemTime` so the caller can
/// thread it into later validity-window checks as the `at_time` anchor.
pub fn verify_rekor_set(
    tlog_entry: &crate::sigstore::TlogEntry,
    rekor_keys: &[RekorKey],
    policy: RekorInclusionProofPolicy,
) -> Result<SystemTime, VerifyError> {
    let integrated_time = parse_integrated_time(&tlog_entry.integrated_time)?;

    let Some(promise) = tlog_entry.resolved_inclusion_promise() else {
        return if policy.requires_set() {
            Err(VerifyError::RekorSetMissing)
        } else {
            Ok(integrated_time)
        };
    };

    let log_index = parse_log_index(&tlog_entry.log_index)?;
    let log_id_bytes = decode_log_id(&tlog_entry.log_id.key_id)?;

    let rekor_key = rekor_keys
        .iter()
        .find(|k| k.log_id == log_id_bytes && k.valid_for.contains(integrated_time))
        .ok_or_else(|| {
            VerifyError::RekorSet(format!(
                "no pinned Rekor key for logId={} valid at integratedTime={}",
                tlog_entry.log_id.key_id, tlog_entry.integrated_time,
            ))
        })?;

    let verifying_key = p256_verifying_key_from_spki(&rekor_key.spki_der).map_err(|e| {
        VerifyError::RekorSet(format!(
            "pinned Rekor key did not decode as ECDSA P-256 SPKI: {e}"
        ))
    })?;

    let signature_bytes = BASE64
        .decode(promise.signed_entry_timestamp.as_bytes())
        .map_err(|e| VerifyError::RekorSet(format!("signedEntryTimestamp not base64: {e}")))?;
    // Rekor SETs are DER-encoded ECDSA signatures per the Sigstore
    // reference implementation (sigstore/rekor `pkg/util/checkpoint.go`).
    // No raw R||S fallback here — unlike DSSE, Rekor's protocol fixes
    // the encoding.
    let signature = Signature::from_der(&signature_bytes).map_err(|e| {
        VerifyError::RekorSet(format!("signedEntryTimestamp is not valid DER ECDSA: {e}"))
    })?;

    // The SET-signed payload uses the HEX form of log_id (per
    // Rekor's `pkg/util/util.go` — `hex.EncodeToString(LogID)`).
    // Real npm bundles ship base64 on the wire, so re-encode from
    // the decoded bytes rather than using the raw key_id string.
    let log_id_hex = hex::encode(&log_id_bytes);
    let set_input = build_set_input_canonical_json(
        &tlog_entry.canonicalized_body,
        integrated_time_secs(&integrated_time),
        log_index,
        &log_id_hex,
    );
    let digest = Sha256::digest(set_input.as_bytes());

    // Rekor signs the SET via Go's `ecdsa.SignASN1(key, prehash)` —
    // the digest is the signing input, NOT re-hashed by the signer.
    // `verify_prehash` matches that semantic; `verify` would hash
    // the digest a second time and compute the wrong verification
    // input.
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .map_err(|e| {
            VerifyError::RekorSet(format!(
                "SET signature did not verify under the pinned Rekor key for logId={}: {e}",
                tlog_entry.log_id.key_id,
            ))
        })?;

    Ok(integrated_time)
}

/// Parse a stringified i64 seconds-since-epoch into [`SystemTime`].
/// `tlog_entry.integrated_time` is a string per the schema bump
/// in (the publish parser stringifies Rekor's API i64).
pub(super) fn parse_integrated_time(s: &str) -> Result<SystemTime, VerifyError> {
    let secs: i64 = s.parse().map_err(|e| {
        VerifyError::RekorSet(format!(
            "TlogEntry.integratedTime `{s}` is not a valid i64 seconds-since-epoch: {e}"
        ))
    })?;
    if secs < 0 {
        return Err(VerifyError::RekorSet(format!(
            "TlogEntry.integratedTime `{secs}` is negative; expected a unix timestamp"
        )));
    }
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

pub(super) fn parse_log_index(s: &str) -> Result<i64, VerifyError> {
    let log_index = s.parse::<i64>().map_err(|e| {
        VerifyError::RekorSet(format!("TlogEntry.logIndex `{s}` is not a valid i64: {e}"))
    })?;
    if log_index < 0 {
        return Err(VerifyError::RekorSet(format!(
            "TlogEntry.logIndex `{log_index}` is negative"
        )));
    }
    Ok(log_index)
}

fn integrated_time_secs(t: &SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Decode a TlogEntry `logId.keyId` field into raw SHA-256 bytes.
///
/// Two wire encodings appear in the wild:
/// - **Hex** (Rekor's REST API canonical form). LPM's publish path
///   captures this verbatim — see [`crate::sigstore::TlogEntry`] note.
/// - **Base64** (Sigstore Bundle v0.3 spec; protobuf JSON encodes
///   `bytes` fields as standard base64).
///
/// Pinned Rekor keys store the log_id as raw 32-byte SHA-256, so
/// either encoding decodes to the same comparison key. SHA-256 is
/// 32 B → 64 hex chars OR 44 base64 chars (with padding); the
/// length disambiguates the two encodings without false positives
/// because hex characters are a subset of base64 characters.
pub(super) fn decode_log_id(raw: &str) -> Result<Vec<u8>, VerifyError> {
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(raw).map_err(|e| {
            VerifyError::RekorSet(format!(
                "TlogEntry.logId.keyId looked like hex but failed to decode: {e}"
            ))
        });
    }
    BASE64.decode(raw.as_bytes()).map_err(|e| {
        VerifyError::RekorSet(format!(
            "TlogEntry.logId.keyId `{raw}` is neither valid hex (Rekor canonical) \
             nor valid base64 (Sigstore Bundle v0.3 protobuf JSON): {e}"
        ))
    })
}

/// Decode a DER SubjectPublicKeyInfo into a P-256 `VerifyingKey`.
/// Used to consume the `RekorKey.spki_der` material that
/// [`TrustRoot::parse`] base64-decoded out of the trusted_root
/// `publicKey.rawBytes` field.
pub(super) fn p256_verifying_key_from_spki(spki_der: &[u8]) -> Result<VerifyingKey, String> {
    use p256::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_der(spki_der).map_err(|e| e.to_string())
}

/// Build the canonical JSON input the SET is signed over.
///
/// Rekor's SET canonicalization fixes:
/// - Keys in ASCII alphabetical order: `body, integratedTime, logID, logIndex`
/// - No whitespace
/// - `body` is the `canonicalizedBody` base64 string verbatim
///   (Rekor signs over the base64 representation, NOT the decoded bytes)
/// - `integratedTime` and `logIndex` are numeric i64 literals
/// - `logID` is the hex string Rekor returns (NOT base64-decoded)
///
/// Implemented as a `format!()` rather than via `serde_json` because
/// serde's default object output does not guarantee key order — going
/// through a sorted-BTreeMap would also work but is one more hop where
/// a subtle behavioral change could break verification. This is
/// load-bearing for SET verify; pinned via
/// `build_set_input_canonical_json_matches_documented_layout`.
pub(super) fn build_set_input_canonical_json(
    canonicalized_body_b64: &str,
    integrated_time_secs: i64,
    log_index: i64,
    log_id_hex: &str,
) -> String {
    format!(
        r#"{{"body":"{body}","integratedTime":{integrated_time},"logID":"{log_id}","logIndex":{log_index}}}"#,
        body = canonicalized_body_b64,
        integrated_time = integrated_time_secs,
        log_id = log_id_hex,
        log_index = log_index,
    )
}
