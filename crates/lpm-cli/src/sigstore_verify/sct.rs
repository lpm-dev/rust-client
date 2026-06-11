use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use x509_parser::prelude::*;

use super::{CtLogKey, VerifyError};

// Sigstore leaf certificates must carry RFC 6962 SCTs in the
// Precertificate SCT extension. Detached SCTs and RFC 3161 timestamps
// are intentionally not substitutes for this check: a bundle with no
// embedded SCT rejects here instead of silently skipping CT pinning.
/// OID for the "CT Precertificate SCT" extension (RFC 6962 §3.3).
/// Encoded as DER: tag (0x06) + length (0x0A = 10) + 10 OID bytes.
/// We compare the OID bytes directly against x509-parser's
/// `Oid::iter().collect::<Vec<u64>>()`.
pub(super) const SCT_EXTENSION_OID_COMPONENTS: [u64; 10] = [1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

/// CT log key hash size = SHA-256 output. RFC 6962 §3.2.
const CT_LOG_ID_LEN: usize = 32;

/// Minimum serialized SCT length: version(1) + log_id(32) +
/// timestamp(8) + extensions_length(2) + at_least_an_empty_signature(4
/// bytes for the digitally-signed header).
pub(super) const MIN_SCT_LEN: usize = 1 + CT_LOG_ID_LEN + 8 + 2 + 4;

/// Verify the embedded SCT list on a Sigstore-issued leaf cert.
///
/// `leaf_cert_der`: the leaf cert's full DER (NOT the TBS bytes —
/// this function extracts what it needs).
/// `issuer_spki_der`: the DER-encoded SubjectPublicKeyInfo of the
/// leaf's immediate issuer (the Fulcio intermediate or root that
/// signed it). The SCT signed-input includes
/// `sha256(issuer_spki_der)` to bind the SCT to a specific issuer.
/// `ctlog_keys`: trust root's CT log keys, filtered by validity at
/// `at_time` inside this function.
/// `at_time`: typically the Rekor `integratedTime`.
///
/// Returns `Ok(())` when ≥1 SCT in the leaf's extension verifies
/// under one of the pinned CT log keys. A cert with no SCT
/// extension rejects with `VerifyError::Sct` — silent skip would
/// defeat the entire CT pin.
#[allow(dead_code)] // wired into `verify_sigstore_bundle`
pub fn verify_embedded_sct(
    leaf_cert_der: &[u8],
    issuer_spki_der: &[u8],
    ctlog_keys: &[CtLogKey],
    at_time: SystemTime,
) -> Result<(), VerifyError> {
    let (_, leaf) = X509Certificate::from_der(leaf_cert_der)
        .map_err(|e| VerifyError::Sct(format!("leaf cert is not valid DER: {e}")))?;

    // Find the SCT extension on the leaf cert.
    let sct_ext = leaf
        .extensions()
        .iter()
        .find(|e| {
            e.oid
                .iter()
                .map(|it| it.collect::<Vec<u64>>())
                .is_some_and(|v| v.as_slice() == SCT_EXTENSION_OID_COMPONENTS)
        })
        .ok_or_else(|| {
            VerifyError::Sct(
                "no embedded SCT extension on leaf cert (OID 1.3.6.1.4.1.11129.2.4.2); \
                 Sigstore bundles must carry SCTs in the leaf cert extension"
                    .into(),
            )
        })?;

    // The extension's `value` field is the OCTET STRING content bytes
    // per x509-parser; the inner content is itself a DER OCTET STRING
    // wrapping the TLS-encoded SCT list. Unwrap that inner OCTET
    // STRING.
    let inner_tls_bytes = unwrap_octet_string(sct_ext.value).map_err(|e| {
        VerifyError::Sct(format!(
            "SCT extension value is not a DER OCTET STRING: {e}"
        ))
    })?;

    let sct_serialized_list = parse_sct_list_tls(inner_tls_bytes)
        .map_err(|e| VerifyError::Sct(format!("SCT list TLS encoding is malformed: {e}")))?;
    if sct_serialized_list.is_empty() {
        return Err(VerifyError::Sct(
            "SCT list is empty — leaf cert claims to have CT proof but the list is zero-length"
                .into(),
        ));
    }

    // Reconstruct the precertificate TBS: leaf's TBS with the SCT
    // extension removed. This is the byte sequence the CT log signed
    // over (RFC 6962 §3.2).
    let precert_tbs = reconstruct_precert_tbs_without_sct(leaf.tbs_certificate.as_ref())
        .map_err(|e| VerifyError::Sct(format!("precert TBS reconstruction failed: {e}")))?;

    let issuer_key_hash = Sha256::digest(issuer_spki_der).to_vec();
    if issuer_key_hash.len() != CT_LOG_ID_LEN {
        // Unreachable — sha256 output is always 32 bytes — but we
        // assert structurally so the SCT input layout stays correct.
        return Err(VerifyError::Sct(
            "issuer SPKI hash is not 32 bytes (sha256 invariant violated)".into(),
        ));
    }

    // Per-SCT verification. Threshold: ≥1 must verify.
    let mut verified = 0usize;
    let mut last_err: Option<String> = None;
    for (i, serialized) in sct_serialized_list.iter().enumerate() {
        let parsed = match parse_serialized_sct(serialized) {
            Ok(p) => p,
            Err(e) => {
                last_err = Some(format!("sct[{i}] parse: {e}"));
                continue;
            }
        };
        let Some(key) = ctlog_keys
            .iter()
            .find(|k| k.log_id == parsed.log_id && k.valid_for.contains(at_time))
        else {
            last_err = Some(format!(
                "sct[{i}]: no pinned CT log key matches logId={} valid at integratedTime",
                hex::encode(&parsed.log_id)
            ));
            continue;
        };
        if let Err(e) = verify_sct_signature(&parsed, &precert_tbs, &issuer_key_hash, key) {
            last_err = Some(format!("sct[{i}]: {e}"));
            continue;
        }
        verified += 1;
    }
    if verified == 0 {
        return Err(VerifyError::Sct(format!(
            "no SCT in the leaf cert's extension verified under any pinned CT log key (\
             {} candidate(s) in list); last error: {}",
            sct_serialized_list.len(),
            last_err.unwrap_or_else(|| "unknown".into())
        )));
    }
    Ok(())
}

/// Parsed RFC 6962 SCT (the bundle's outer SCT structure, not the
/// signed-input form).
struct ParsedSct<'a> {
    /// Always 0 (v1). Kept on the struct as a parse-trace artifact —
    /// the version byte is asserted == 0 during parse, so the field
    /// itself is informational only at verification time.
    #[allow(dead_code)]
    version: u8,
    /// 32-byte sha256 of the CT log's SPKI.
    log_id: Vec<u8>,
    /// Big-endian millis since unix epoch.
    timestamp_ms: u64,
    /// SCT-extensions — usually empty.
    sct_extensions: &'a [u8],
    /// `digitally-signed` header bytes: hash_algo(1) + sig_algo(1) +
    /// signature length(2).
    sig_hash_algo: u8,
    sig_pk_algo: u8,
    /// DER-encoded ECDSA signature (or whatever the algo says).
    signature_der: &'a [u8],
}

/// Decode the inner OCTET STRING wrapping the SCT list. x509-parser
/// returns the extension `value` as the OCTET STRING content — but
/// that content is ITSELF a DER OCTET STRING (per RFC 6962 §3.3,
/// `extnValue` of the SCT extension contains a DER-encoded OCTET
/// STRING whose content is the TLS-encoded list).
fn unwrap_octet_string(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < 2 {
        return Err(format!("input too short: {} bytes", bytes.len()));
    }
    if bytes[0] != 0x04 {
        return Err(format!(
            "expected OCTET STRING tag (0x04), got 0x{:02x}",
            bytes[0]
        ));
    }
    let (len, consumed) = der_decode_length(&bytes[1..])
        .ok_or_else(|| "OCTET STRING length is malformed".to_string())?;
    let start = 1 + consumed;
    if bytes.len() < start + len {
        return Err(format!(
            "OCTET STRING declares len={len} but only {} content bytes follow",
            bytes.len() - start
        ));
    }
    Ok(&bytes[start..start + len])
}

/// Parse the SignedCertificateTimestampList TLS structure:
/// `u16 total_length || (u16 sct_length || serialized_sct)*`
/// per RFC 6962 §3.3. Returns the list of serialized-SCT byte slices.
fn parse_sct_list_tls(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    if bytes.len() < 2 {
        return Err(format!(
            "input too short for outer u16 length: {} bytes",
            bytes.len()
        ));
    }
    let total_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + total_len {
        return Err(format!(
            "outer length declares {total_len} bytes but {} follow",
            bytes.len() - 2
        ));
    }
    let mut out = Vec::new();
    let mut offset = 2usize;
    let end = 2 + total_len;
    while offset < end {
        if offset + 2 > end {
            return Err(format!("truncated u16 sct_length at offset {offset}"));
        }
        let sct_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + sct_len > end {
            return Err(format!(
                "sct at offset {offset} declares {sct_len} bytes but only {} bytes remain",
                end - offset
            ));
        }
        out.push(&bytes[offset..offset + sct_len]);
        offset += sct_len;
    }
    Ok(out)
}

/// Parse a serialized SCT per RFC 6962 §3.2.
fn parse_serialized_sct(bytes: &[u8]) -> Result<ParsedSct<'_>, String> {
    if bytes.len() < MIN_SCT_LEN {
        return Err(format!(
            "serialized SCT is {} bytes, minimum is {MIN_SCT_LEN}",
            bytes.len()
        ));
    }
    let mut offset = 0usize;
    let version = bytes[offset];
    offset += 1;
    if version != 0 {
        return Err(format!(
            "SCT version is {version} (RFC 6962 requires v1, i.e. version byte 0)"
        ));
    }
    let log_id = bytes[offset..offset + CT_LOG_ID_LEN].to_vec();
    offset += CT_LOG_ID_LEN;
    let timestamp_ms = u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"));
    offset += 8;
    let sct_extensions_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + sct_extensions_len > bytes.len() {
        return Err(format!(
            "SCT extensions declare {sct_extensions_len} bytes but only {} remain",
            bytes.len() - offset
        ));
    }
    let sct_extensions = &bytes[offset..offset + sct_extensions_len];
    offset += sct_extensions_len;

    if offset + 4 > bytes.len() {
        return Err("truncated digitally-signed header (need hash+sig algo+u16 len)".into());
    }
    let sig_hash_algo = bytes[offset];
    let sig_pk_algo = bytes[offset + 1];
    offset += 2;
    let sig_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if offset + sig_len > bytes.len() {
        return Err(format!(
            "digitally-signed declares {sig_len} sig bytes but only {} remain",
            bytes.len() - offset
        ));
    }
    let signature_der = &bytes[offset..offset + sig_len];
    Ok(ParsedSct {
        version,
        log_id,
        timestamp_ms,
        sct_extensions,
        sig_hash_algo,
        sig_pk_algo,
        signature_der,
    })
}

/// SCT signature-input layout for `precert_entry` per RFC 6962 §3.2:
/// ```text
/// uint8  version (0)
/// uint8  signature_type (0 = certificate_timestamp)
/// uint64 timestamp_ms (BE)
/// uint16 entry_type (1 = precert_entry, BE)
/// PreCert {
///     uint8 issuer_key_hash[32]
///     uint24 tbs_length (BE)
///     uint8 tbs_certificate[tbs_length]
/// }
/// uint16 sct_extensions_length (BE)
/// uint8 sct_extensions[sct_extensions_length]
/// ```
fn build_precert_sct_signature_input(
    sct: &ParsedSct<'_>,
    issuer_key_hash: &[u8],
    precert_tbs: &[u8],
) -> Result<Vec<u8>, String> {
    if issuer_key_hash.len() != CT_LOG_ID_LEN {
        return Err("issuer_key_hash must be 32 bytes".into());
    }
    if precert_tbs.len() > 0xFF_FFFF {
        return Err(format!(
            "precert TBS is {} bytes (exceeds u24 max for SCT signed input)",
            precert_tbs.len()
        ));
    }
    let mut out = Vec::with_capacity(45 + precert_tbs.len() + sct.sct_extensions.len());
    out.push(0u8); // version
    out.push(0u8); // signature_type = certificate_timestamp
    out.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // entry_type = precert_entry
    out.extend_from_slice(issuer_key_hash);
    let tbs_len = precert_tbs.len() as u32;
    out.push(((tbs_len >> 16) & 0xFF) as u8);
    out.push(((tbs_len >> 8) & 0xFF) as u8);
    out.push((tbs_len & 0xFF) as u8);
    out.extend_from_slice(precert_tbs);
    out.extend_from_slice(&(sct.sct_extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(sct.sct_extensions);
    Ok(out)
}

/// Verify a single SCT's signature against a pinned CT log key.
fn verify_sct_signature(
    sct: &ParsedSct<'_>,
    precert_tbs: &[u8],
    issuer_key_hash: &[u8],
    ct_log_key: &CtLogKey,
) -> Result<(), String> {
    // Sigstore profile: SCTs use ECDSA P-256 + SHA-256. RFC 6962
    // hash_algorithm = 4 (sha256), signature_algorithm = 3 (ecdsa).
    // A future log that signs with a different algorithm would
    // surface here and be rejected — better visible than silently
    // mis-verified.
    if sct.sig_hash_algo != 4 || sct.sig_pk_algo != 3 {
        return Err(format!(
            "unsupported SCT signature algorithm (hash={}, sig={}); \
             RFC 6962 sha256/ecdsa is (4, 3)",
            sct.sig_hash_algo, sct.sig_pk_algo
        ));
    }
    let signature = Signature::from_der(sct.signature_der)
        .map_err(|e| format!("SCT signature is not valid DER ECDSA: {e}"))?;
    use p256::pkcs8::DecodePublicKey;
    let verifying_key = VerifyingKey::from_public_key_der(&ct_log_key.spki_der)
        .map_err(|e| format!("pinned CT log SPKI did not decode as ECDSA P-256: {e}"))?;
    let signed_input = build_precert_sct_signature_input(sct, issuer_key_hash, precert_tbs)?;
    verifying_key
        .verify(&signed_input, &signature)
        .map_err(|e| format!("signature did not verify: {e}"))
}

/// Strip the embedded SCT extension from a leaf cert's TBS, returning
/// the precert-equivalent TBS bytes (DER-encoded). This is what the
/// CT log actually signed over per RFC 6962 §3.2.
///
/// Approach: walk the TBS SEQUENCE byte-by-byte using a small TLV
/// reader. Extensions appear in the `[3] EXPLICIT Extensions
/// OPTIONAL` tagged field (DER tag `0xA3`). When we hit `[3]`, we
/// dive into the nested SEQUENCE OF Extension, copy non-SCT
/// extensions through, and re-encode the modified extensions list
/// with recomputed lengths.
///
/// We avoid pulling a full DER serde codec for this single
/// surgical edit; the helpers (`der_decode_length`, `der_encode_*`)
/// are small, total-input-bounded, and the TBS shape is fixed by
/// RFC 5280.
pub(super) fn reconstruct_precert_tbs_without_sct(tbs_bytes: &[u8]) -> Result<Vec<u8>, String> {
    // Outer TBS SEQUENCE: tag 0x30 + length.
    if tbs_bytes.is_empty() || tbs_bytes[0] != 0x30 {
        return Err(format!(
            "TBS does not start with SEQUENCE tag 0x30 (got 0x{:02x})",
            tbs_bytes.first().copied().unwrap_or(0)
        ));
    }
    let (tbs_content_len, tbs_len_bytes) =
        der_decode_length(&tbs_bytes[1..]).ok_or_else(|| "malformed TBS length".to_string())?;
    let tbs_content_start = 1 + tbs_len_bytes;
    if tbs_bytes.len() < tbs_content_start + tbs_content_len {
        return Err(format!(
            "TBS bytes too short for declared content length {tbs_content_len}"
        ));
    }
    let tbs_content_end = tbs_content_start + tbs_content_len;

    // Walk TBS children, collecting their raw bytes. Detect the
    // `[3] EXPLICIT Extensions` field (tag 0xA3) and rewrite its
    // content; pass everything else through.
    let mut new_inner = Vec::with_capacity(tbs_content_len);
    let mut found_extensions = false;
    let mut cursor = tbs_content_start;
    while cursor < tbs_content_end {
        let tag = tbs_bytes[cursor];
        let (child_len, len_bytes) = der_decode_length(&tbs_bytes[cursor + 1..])
            .ok_or_else(|| format!("malformed length at TBS offset {cursor}"))?;
        let header_size = 1 + len_bytes;
        let child_total = header_size + child_len;
        if cursor + child_total > tbs_content_end {
            return Err(format!(
                "TBS child at offset {cursor} overruns parent SEQUENCE"
            ));
        }
        let child_bytes = &tbs_bytes[cursor..cursor + child_total];

        if tag == 0xA3 {
            // [3] EXPLICIT Extensions. Recurse: filter out the SCT
            // extension, re-encode.
            found_extensions = true;
            let new_explicit = filter_extensions_remove_sct(child_bytes)?;
            new_inner.extend_from_slice(&new_explicit);
        } else {
            new_inner.extend_from_slice(child_bytes);
        }

        cursor += child_total;
    }
    if !found_extensions {
        return Err(
            "TBS has no `[3] EXPLICIT Extensions` field — cannot have an embedded SCT".into(),
        );
    }

    // Wrap new_inner in the TBS SEQUENCE.
    let mut out = Vec::with_capacity(1 + 9 + new_inner.len());
    out.push(0x30);
    out.extend_from_slice(&der_encode_length(new_inner.len()));
    out.extend_from_slice(&new_inner);
    Ok(out)
}

/// Given the raw bytes of a `[3] EXPLICIT Extensions` TLV (tag
/// `0xA3` followed by length + body), return new bytes representing
/// the same `[3] EXPLICIT` wrapper with the SCT extension removed
/// from the inner `SEQUENCE OF Extension`.
fn filter_extensions_remove_sct(explicit3_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if explicit3_bytes.first() != Some(&0xA3) {
        return Err("expected [3] EXPLICIT tag 0xA3".into());
    }
    let (explicit_content_len, len_bytes) = der_decode_length(&explicit3_bytes[1..])
        .ok_or_else(|| "malformed [3] length".to_string())?;
    let inner_start = 1 + len_bytes;
    if explicit3_bytes.len() < inner_start + explicit_content_len {
        return Err("[3] EXPLICIT bytes overrun".into());
    }
    let inner = &explicit3_bytes[inner_start..inner_start + explicit_content_len];

    // Inner is the Extensions SEQUENCE OF Extension.
    if inner.first() != Some(&0x30) {
        return Err("[3] EXPLICIT content must be SEQUENCE OF Extension".into());
    }
    let (seq_content_len, seq_len_bytes) = der_decode_length(&inner[1..])
        .ok_or_else(|| "malformed Extensions seq length".to_string())?;
    let seq_content_start = 1 + seq_len_bytes;
    if inner.len() < seq_content_start + seq_content_len {
        return Err("Extensions SEQUENCE overrun".into());
    }
    let seq_content = &inner[seq_content_start..seq_content_start + seq_content_len];

    let mut new_seq_content = Vec::with_capacity(seq_content.len());
    let mut cursor = 0usize;
    while cursor < seq_content.len() {
        let ext_start = cursor;
        if seq_content[cursor] != 0x30 {
            return Err(format!(
                "Extensions entry at offset {cursor} is not SEQUENCE"
            ));
        }
        let (ext_len, ext_len_bytes) = der_decode_length(&seq_content[cursor + 1..])
            .ok_or_else(|| format!("malformed extension length at {cursor}"))?;
        let ext_total = 1 + ext_len_bytes + ext_len;
        if cursor + ext_total > seq_content.len() {
            return Err(format!("extension at {cursor} overruns"));
        }
        let ext_bytes = &seq_content[ext_start..ext_start + ext_total];
        if !extension_oid_matches_sct(ext_bytes)? {
            new_seq_content.extend_from_slice(ext_bytes);
        }
        cursor += ext_total;
    }

    // Re-wrap: new SEQUENCE OF Extension, then new [3] EXPLICIT.
    let mut new_seq = Vec::with_capacity(1 + 5 + new_seq_content.len());
    new_seq.push(0x30);
    new_seq.extend_from_slice(&der_encode_length(new_seq_content.len()));
    new_seq.extend_from_slice(&new_seq_content);

    let mut new_explicit = Vec::with_capacity(1 + 5 + new_seq.len());
    new_explicit.push(0xA3);
    new_explicit.extend_from_slice(&der_encode_length(new_seq.len()));
    new_explicit.extend_from_slice(&new_seq);
    Ok(new_explicit)
}

/// Check whether an X509Extension SEQUENCE's first child (the OID)
/// equals the SCT extension OID.
fn extension_oid_matches_sct(ext_bytes: &[u8]) -> Result<bool, String> {
    if ext_bytes.first() != Some(&0x30) {
        return Err("extension is not SEQUENCE".into());
    }
    let (_, len_bytes) = der_decode_length(&ext_bytes[1..])
        .ok_or_else(|| "malformed extension length".to_string())?;
    let content_start = 1 + len_bytes;
    if ext_bytes.len() < content_start + 2 {
        return Err("extension content too short".into());
    }
    // First child: OID (tag 0x06).
    if ext_bytes[content_start] != 0x06 {
        return Err(format!(
            "first child of extension is tag 0x{:02x} (expected OID 0x06)",
            ext_bytes[content_start]
        ));
    }
    let (oid_len, oid_len_bytes) = der_decode_length(&ext_bytes[content_start + 1..])
        .ok_or_else(|| "malformed OID length".to_string())?;
    let oid_start = content_start + 1 + oid_len_bytes;
    if ext_bytes.len() < oid_start + oid_len {
        return Err("OID overruns extension".into());
    }
    let oid_bytes = &ext_bytes[oid_start..oid_start + oid_len];

    // Pre-encoded SCT OID body for byte equality check.
    // OID 1.3.6.1.4.1.11129.2.4.2 encoded as DER content (without
    // tag/length): 0x2B 0x06 0x01 0x04 0x01 0xD6 0x79 0x02 0x04 0x02.
    const SCT_OID_BODY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];
    Ok(oid_bytes == SCT_OID_BODY)
}

/// Decode a DER length. Returns `(length, bytes_consumed)`.
///
/// Short form: single byte < 128.
/// Long form: high bit set, low 7 bits = number of subsequent bytes
/// holding the length (big-endian). `n=0` (indefinite length) is
/// rejected — DER (vs BER) forbids it.
pub(super) fn der_decode_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 8 || bytes.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &bytes[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Encode a DER length in its canonical form (short for <128,
/// minimum-byte long form otherwise).
pub(super) fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let be = (len as u64).to_be_bytes();
    let leading_zeros = be.iter().take_while(|&&b| b == 0).count();
    let nonzero = &be[leading_zeros..];
    let mut out = Vec::with_capacity(1 + nonzero.len());
    out.push(0x80 | nonzero.len() as u8);
    out.extend_from_slice(nonzero);
    out
}
