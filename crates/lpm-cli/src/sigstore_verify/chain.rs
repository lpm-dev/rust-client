use chrono::{DateTime, Utc};
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use std::time::SystemTime;
use x509_parser::prelude::*;

use super::{FulcioRoot, VerifyError};

// AIA fetch is intentionally not implemented. A Sigstore bundle that's
// missing intermediates fails instead of fetching a URL from inside the
// certificate. `at_time` must be Rekor `integratedTime`, not wall-clock,
// so historical bundles verify against the Fulcio chain active when the
// log entry was integrated.
/// Sigstore profile limits cert chains to 3 (leaf + intermediate +
/// root). Caps the depth so a forged chain with attacker-injected
/// "intermediates" can't grow unbounded under-the-radar even if a
/// per-link constraint somehow misfires.
const MAX_CHAIN_LENGTH: usize = 3;

/// Verify an X.509 cert chain from the bundle terminates at one of
/// the pinned Fulcio roots, with every link valid at `at_time` and
/// every cert satisfying its position-appropriate X.509 extension
/// profile.
///
/// `bundle_chain_der`: ordered from leaf upward — `[leaf, intermediates...]`.
/// `fulcio_roots`: filtered by [`TrustRoot::fulcio_roots_at(at_time)`]
/// at the call site; this function further enforces that the chain's
/// final cert byte-equals one of those roots (or is signed by one).
///
/// Returns `Ok(())` only when:
/// 1. `bundle_chain_der.len() <= MAX_CHAIN_LENGTH`.
/// 2. Every cert has `notBefore <= at_time <= notAfter`.
/// 3. The leaf (`chain[0]`) satisfies the Sigstore leaf profile
///    via [`enforce_leaf_constraints`] — not flagged as a CA, no
///    `keyCertSign` if `KeyUsage` is present, `codeSigning` in
///    `ExtendedKeyUsage` if EKU is present.
/// 4. Every issuer (`chain[1..]`) satisfies the issuer profile via
///    [`enforce_issuer_constraints`] — `BasicConstraints` present
///    and critical with `cA = TRUE`, `keyCertSign` set if `KeyUsage`
///    is present, and `pathLenConstraint >= remaining_depth` if set.
/// 5. Every adjacent (child, parent) pair: child's signature
///    verifies under parent's SPKI AND child.issuer == parent.subject.
/// 6. The chain's top cert byte-equals a trust anchor cert, OR its
///    signature verifies under one of the trust anchors (which also
///    must satisfy the issuer profile).
///
/// Without (3) and (4), a Sigstore-issued leaf cert (which any party
/// can obtain via OIDC) could be used as an "intermediate" to sign a
/// forged child leaf with attacker-controlled SAN, bypassing
/// Sigstore's identity binding entirely. The extension enforcement
/// is load-bearing for the verifier's core guarantee.
#[allow(dead_code)] // wired into provenance_fetch
pub fn verify_cert_chain(
    bundle_chain_der: &[&[u8]],
    fulcio_roots: &[&FulcioRoot],
    at_time: SystemTime,
) -> Result<(), VerifyError> {
    if bundle_chain_der.is_empty() {
        return Err(VerifyError::Chain(
            "bundle cert chain is empty (must include at least the leaf)".into(),
        ));
    }
    if bundle_chain_der.len() > MAX_CHAIN_LENGTH {
        return Err(VerifyError::Chain(format!(
            "bundle cert chain has {} certs (Sigstore profile allows at most {})",
            bundle_chain_der.len(),
            MAX_CHAIN_LENGTH
        )));
    }
    if fulcio_roots.is_empty() {
        return Err(VerifyError::Chain(
            "no Fulcio roots active at integratedTime — cannot anchor any chain".into(),
        ));
    }

    let at_time_dt: DateTime<Utc> = at_time.into();

    // Parse every cert in the bundle's chain once up-front. Reject
    // any malformed DER before any signature work runs.
    let mut parsed: Vec<X509Certificate<'_>> = Vec::with_capacity(bundle_chain_der.len());
    for (i, der) in bundle_chain_der.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            VerifyError::Chain(format!(
                "bundle chain cert[{i}] is not valid DER X.509: {e}"
            ))
        })?;
        parsed.push(cert);
    }

    // Step 1: every chain cert must be valid at `at_time`. This is
    // the load-bearing "at_time = integratedTime" check that lets
    // old bundles still verify against retired Fulcio chains.
    for (i, cert) in parsed.iter().enumerate() {
        check_cert_validity_at(cert, at_time_dt, &format!("chain[{i}]"))?;
    }

    // Step 2: position-appropriate X.509 extension profile.
    // Leaf MUST be non-CA; every issuer above the leaf MUST be a CA
    // with keyCertSign authority. This is the defense against the
    // "use a real Sigstore leaf cert as a CA" forgery — closes the
    // identity-binding bypass.
    enforce_leaf_constraints(&parsed[0], "chain[0] (leaf)")?;
    for (i, cert) in parsed.iter().enumerate().skip(1) {
        // "remaining_depth" = number of intermediate CAs that follow
        // this cert on the path to the leaf (exclusive of both this
        // cert and the leaf). For cert at chain index i (i >= 1),
        // that's i - 1.
        let remaining_depth = i - 1;
        enforce_issuer_constraints(cert, remaining_depth, &format!("chain[{i}]"))?;
    }

    // Step 3: every adjacent (child, parent) pair must chain
    // structurally and cryptographically.
    for i in 0..parsed.len().saturating_sub(1) {
        verify_chain_link(
            &parsed[i],
            &parsed[i + 1],
            &format!("chain[{i}] ⇒ chain[{}]", i + 1),
        )?;
    }

    // Step 4: terminate at a trusted anchor. Two valid shapes:
    //   (a) the chain's top cert IS one of the trust anchor certs
    //       (bundle included the Fulcio root).
    //   (b) the chain's top cert is signed by a trust anchor
    //       (bundle stopped at the intermediate).
    let top_der = bundle_chain_der.last().expect("non-empty checked above");
    if anchor_contains_der(fulcio_roots, top_der) {
        return Ok(());
    }

    let top_parsed = parsed.last().expect("non-empty checked above");
    // The anchor in case (b) sits "above" the chain — its
    // remaining_depth equals the number of intermediates already in
    // the chain (`bundle_chain_der.len() - 1`, since chain[0] is the
    // leaf and the leaf doesn't count as an intermediate following
    // the anchor).
    let anchor_remaining_depth = bundle_chain_der.len() - 1;
    for root in fulcio_roots {
        for root_der in &root.cert_chain_der {
            let Ok((_, root_cert)) = X509Certificate::from_der(root_der) else {
                continue;
            };
            // The root's own validity is gated upstream by
            // TrustRoot::fulcio_roots_at; but the cert's intrinsic
            // notBefore/notAfter is still a defense — fail-closed
            // if the trust root's cert itself is out of window.
            if check_cert_validity_at(&root_cert, at_time_dt, "fulcio_root").is_err() {
                continue;
            }
            // The anchor must satisfy the issuer profile too — a
            // misissued or rotated trust-root that lacks cA=TRUE
            // should never anchor a chain.
            if enforce_issuer_constraints(&root_cert, anchor_remaining_depth, "fulcio_root")
                .is_err()
            {
                continue;
            }
            if try_anchor_signature(top_parsed, &root_cert).is_ok() {
                return Ok(());
            }
        }
    }

    Err(VerifyError::Chain(format!(
        "bundle chain's top cert does not match any trusted Fulcio root and \
         is not signed by any trusted Fulcio root \
         ({} candidate root(s) active at integratedTime)",
        fulcio_roots.len()
    )))
}

/// X.509 extension enforcement for a cert acting as a CA — every
/// cert above the leaf in the chain, plus the trust anchor that
/// terminates the chain on the `try_anchor_signature` branch.
///
/// Required:
/// - `BasicConstraints` present, **critical**, `cA = TRUE`. Without
///   this, a real Sigstore leaf cert (which any party can obtain via
///   OIDC) could be used as a forged intermediate to sign an
///   attacker-controlled child cert.
/// - `pathLenConstraint` (when set) `>= remaining_depth`. Sigstore's
///   intermediate has `pathLen = 0`, which means it can sign leaves
///   but not further intermediates — closes "stack arbitrary
///   intermediates between a real cert and a forged leaf."
///
/// If `KeyUsage` is present, require `keyCertSign`. Absent is
/// permissive (real Fulcio CAs always include it, but rcgen-synth
/// CAs may omit it without the strict profile).
pub(super) fn enforce_issuer_constraints(
    cert: &X509Certificate<'_>,
    remaining_depth: usize,
    label: &str,
) -> Result<(), VerifyError> {
    let bc_ext = cert
        .basic_constraints()
        .map_err(|e| VerifyError::Chain(format!("{label}: BasicConstraints parse failed: {e}")))?;
    let bc = bc_ext.ok_or_else(|| {
        VerifyError::Chain(format!(
            "{label}: BasicConstraints extension missing — issuer cert is not authorized to \
             sign other certs (closes 'real Sigstore leaf as CA' forgery)"
        ))
    })?;
    if !bc.critical {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints extension is not marked critical \
             (Sigstore profile requires criticality on issuers)"
        )));
    }
    if !bc.value.ca {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.cA is FALSE — issuer cert is not authorized to sign certs"
        )));
    }
    if let Some(plc) = bc.value.path_len_constraint
        && (plc as usize) < remaining_depth
    {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.pathLenConstraint={plc} < remaining intermediate \
             depth={remaining_depth} (forged chain trying to slip past Sigstore's path-length limit)"
        )));
    }

    let ku_ext = cert
        .key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: KeyUsage parse failed: {e}")))?;
    if let Some(ku) = ku_ext
        && !ku.value.key_cert_sign()
    {
        return Err(VerifyError::Chain(format!(
            "{label}: KeyUsage extension does not include keyCertSign — issuer cert is not \
             authorized to sign other certs"
        )));
    }

    Ok(())
}

/// X.509 extension enforcement for the leaf cert (`chain[0]`).
///
/// Required:
/// - `BasicConstraints` either absent OR `cA = FALSE`. A leaf
///   flagged as a CA is structurally invalid for a Sigstore signing
///   cert.
///
/// If `KeyUsage` is present, require `digitalSignature` AND reject
/// `keyCertSign`. (A leaf that asserts `keyCertSign` is fundamentally
/// abusable.) If `ExtendedKeyUsage` is present, require `codeSigning`
/// per Sigstore's Fulcio leaf profile. Absent extensions are
/// permissive — rcgen test leaves may omit them.
fn enforce_leaf_constraints(cert: &X509Certificate<'_>, label: &str) -> Result<(), VerifyError> {
    let bc_ext = cert
        .basic_constraints()
        .map_err(|e| VerifyError::Chain(format!("{label}: BasicConstraints parse failed: {e}")))?;
    if let Some(bc) = bc_ext
        && bc.value.ca
    {
        return Err(VerifyError::Chain(format!(
            "{label}: BasicConstraints.cA is TRUE — leaf cert must NOT be a CA"
        )));
    }

    let ku_ext = cert
        .key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: KeyUsage parse failed: {e}")))?;
    if let Some(ku) = ku_ext {
        if !ku.value.digital_signature() {
            return Err(VerifyError::Chain(format!(
                "{label}: KeyUsage extension does not include digitalSignature \
                 (Sigstore leaves must be signing-capable)"
            )));
        }
        if ku.value.key_cert_sign() {
            return Err(VerifyError::Chain(format!(
                "{label}: KeyUsage extension includes keyCertSign — leaf cert is fundamentally \
                 abusable as an intermediate"
            )));
        }
    }

    let eku_ext = cert
        .extended_key_usage()
        .map_err(|e| VerifyError::Chain(format!("{label}: ExtendedKeyUsage parse failed: {e}")))?;
    if let Some(eku) = eku_ext
        && !eku.value.code_signing
    {
        return Err(VerifyError::Chain(format!(
            "{label}: ExtendedKeyUsage does not include codeSigning \
             (Sigstore Fulcio leaf profile requires it)"
        )));
    }

    Ok(())
}

fn anchor_contains_der(fulcio_roots: &[&FulcioRoot], top_der: &[u8]) -> bool {
    fulcio_roots
        .iter()
        .flat_map(|r| r.cert_chain_der.iter())
        .any(|d| d.as_slice() == top_der)
}

fn check_cert_validity_at(
    cert: &X509Certificate<'_>,
    at_time: DateTime<Utc>,
    label: &str,
) -> Result<(), VerifyError> {
    let validity = cert.validity();
    let not_before = DateTime::from_timestamp(validity.not_before.timestamp(), 0)
        .ok_or_else(|| VerifyError::Chain(format!("{label} notBefore is unrepresentable")))?;
    let not_after = DateTime::from_timestamp(validity.not_after.timestamp(), 0)
        .ok_or_else(|| VerifyError::Chain(format!("{label} notAfter is unrepresentable")))?;
    if at_time < not_before || at_time > not_after {
        return Err(VerifyError::Chain(format!(
            "{label} validity window [{not_before}, {not_after}] does not contain integratedTime {at_time}"
        )));
    }
    Ok(())
}

fn verify_chain_link(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
    label: &str,
) -> Result<(), VerifyError> {
    // Structural: child.issuer must equal parent.subject. x509-parser
    // exposes DER-equality comparison on `X509Name` via the wrapper's
    // `as_raw()` (the original DER bytes), which we compare byte-wise
    // — that's the strictest form of name equality.
    if child.tbs_certificate.issuer.as_raw() != parent.tbs_certificate.subject.as_raw() {
        return Err(VerifyError::Chain(format!(
            "{label}: child.issuer DN does not equal parent.subject DN"
        )));
    }

    // Cryptographic: child's `tbs_certificate` bytes, hashed under the
    // signature algorithm declared on the cert, must verify under the
    // parent's SPKI bytes.
    let tbs_bytes = child.tbs_certificate.as_ref();
    let sig_bytes = &child.signature_value.data;
    let sig_alg_oid = &child.signature_algorithm.algorithm;
    verify_ecdsa_signature_by_oid(sig_alg_oid, tbs_bytes, sig_bytes, parent, label)
}

fn try_anchor_signature(
    top: &X509Certificate<'_>,
    anchor: &X509Certificate<'_>,
) -> Result<(), VerifyError> {
    if top.tbs_certificate.issuer.as_raw() != anchor.tbs_certificate.subject.as_raw() {
        return Err(VerifyError::Chain(
            "top cert issuer DN does not equal trust anchor subject DN".into(),
        ));
    }
    let tbs = top.tbs_certificate.as_ref();
    let sig = &top.signature_value.data;
    let sig_alg = &top.signature_algorithm.algorithm;
    verify_ecdsa_signature_by_oid(sig_alg, tbs, sig, anchor, "anchor-link")
}

/// ECDSA signature OIDs we accept (Sigstore profile).
/// - 1.2.840.10045.4.3.2 = `ecdsa-with-SHA256` (P-256 leaves)
/// - 1.2.840.10045.4.3.3 = `ecdsa-with-SHA384` (P-384 roots/intermediates)
pub(super) const OID_ECDSA_WITH_SHA256: [u64; 7] = [1, 2, 840, 10045, 4, 3, 2];
pub(super) const OID_ECDSA_WITH_SHA384: [u64; 7] = [1, 2, 840, 10045, 4, 3, 3];

pub(super) fn oid_components_match(
    oid: &x509_parser::der_parser::oid::Oid<'_>,
    expected: &[u64],
) -> bool {
    let components: Vec<u64> = match oid.iter() {
        Some(iter) => iter.collect(),
        None => return false,
    };
    components.as_slice() == expected
}

fn verify_ecdsa_signature_by_oid(
    sig_alg_oid: &x509_parser::der_parser::oid::Oid<'_>,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    parent: &X509Certificate<'_>,
    label: &str,
) -> Result<(), VerifyError> {
    let spki_der = parent.public_key().raw;
    if oid_components_match(sig_alg_oid, &OID_ECDSA_WITH_SHA256) {
        verify_ecdsa_p256_sha256(spki_der, tbs_bytes, sig_bytes, label)
    } else if oid_components_match(sig_alg_oid, &OID_ECDSA_WITH_SHA384) {
        verify_ecdsa_p384_sha384(spki_der, tbs_bytes, sig_bytes, label)
    } else {
        Err(VerifyError::Chain(format!(
            "{label}: unsupported signature algorithm OID {sig_alg_oid} \
             (Sigstore profile accepts only ecdsa-with-SHA256 or ecdsa-with-SHA384)"
        )))
    }
}

fn verify_ecdsa_p256_sha256(
    spki_der: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    label: &str,
) -> Result<(), VerifyError> {
    use p256::pkcs8::DecodePublicKey;
    let verifying_key = VerifyingKey::from_public_key_der(spki_der).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: parent SPKI did not decode as ECDSA P-256: {e}"
        ))
    })?;
    let signature = Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: cert signature is not valid DER ECDSA: {e}"
        ))
    })?;
    // X.509 cert signature: sigma = ECDSA-sign(key, SHA-256(TBS)).
    // p256::ecdsa::VerifyingKey's `Verifier<Signature>::verify` impl
    // hashes the message internally with SHA-256 — exactly the curve's
    // standard hash for ecdsa-with-SHA256 — so passing raw TBS bytes
    // is the right shape. Pre-hashing first would re-hash the digest
    // and produce the wrong verification input.
    verifying_key.verify(tbs_bytes, &signature).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: ECDSA P-256 signature did not verify: {e}"
        ))
    })
}

fn verify_ecdsa_p384_sha384(
    spki_der: &[u8],
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    label: &str,
) -> Result<(), VerifyError> {
    use p384::pkcs8::DecodePublicKey;
    let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: parent SPKI did not decode as ECDSA P-384: {e}"
        ))
    })?;
    let signature = p384::ecdsa::Signature::from_der(sig_bytes).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: cert signature is not valid DER ECDSA: {e}"
        ))
    })?;
    // Same shape as the P-256 case — p384's Verifier hashes with
    // SHA-384, which matches ecdsa-with-SHA384.
    verifying_key.verify(tbs_bytes, &signature).map_err(|e| {
        VerifyError::Chain(format!(
            "{label}: ECDSA P-384 signature did not verify: {e}"
        ))
    })
}
