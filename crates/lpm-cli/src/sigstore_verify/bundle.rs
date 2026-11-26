use crate::sigstore::DsseEnvelope;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use x509_parser::prelude::*;

use super::checkpoint::logs_signing;
use super::inclusion::{extract_checkpoint_envelope, verify_rekor_v2_inclusion_proof};
use super::rekor_body::{RekorEntryVersion, rekor_entry_version, verify_hashedrekord_v002};
use super::rekor_set::{decode_log_id, parse_log_index};
use super::sct::der_decode_length;
use super::timestamp::{MAX_SIGNED_TIMESTAMPS, verify_signed_timestamps};
use super::{
    RekorInclusionProofPolicy, TrustRoot, VerifyError, trust_root, verify_cert_chain, verify_dsse,
    verify_embedded_sct, verify_inclusion_proof, verify_rekor_body, verify_rekor_set,
};

// The composed verifier runs each cryptographic phase to completion
// before trusting output from that phase. All downstream validity-window
// checks use signed times (Rekor v1's `integratedTime` under a SET, an RFC
// 3161 timestamp, or an SCT's own time), not wall-clock time, so
// historical bundles verify against the Fulcio and CT keys active when
// they were signed.
/// Verifier-time options. Currently carries the
/// [`RekorInclusionProofPolicy`] only; future knobs can live here
/// without breaking the public API.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    pub rekor_inclusion_policy: RekorInclusionProofPolicy,
}

impl VerifyOptions {
    /// `RequireBoth` — the strongest assurance posture. Used by
    /// self-update because binary replacement is the highest-trust
    /// operation in LPM.
    #[allow(dead_code)]
    pub fn strict() -> Self {
        Self {
            rekor_inclusion_policy: RekorInclusionProofPolicy::RequireBoth,
        }
    }

    /// `Either` — accept SET-only (v0.1) OR inclusion-proof-only bundles;
    /// the latter, like any bundle without a SET, needs an RFC 3161
    /// timestamp. Used for npm attestations because npm cohorts ship
    /// either form in the wild.
    #[allow(dead_code)]
    pub fn npm_attestation() -> Self {
        Self {
            rekor_inclusion_policy: RekorInclusionProofPolicy::Either,
        }
    }
}

/// Optional caller-supplied pins for the leaf cert's identity.
/// `none()` skips identity checks entirely; a populated instance
/// enforces the relevant pins, such as the self-update release workflow
/// issued under GitHub Actions OIDC.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct IdentityExpectations {
    /// Expected OIDC issuer the Fulcio leaf was minted from, read
    /// from the Fulcio extension at OID `1.3.6.1.4.1.57264.1.1` (or
    /// the v2 OID `1.3.6.1.4.1.57264.1.8`, accepted symmetrically).
    /// Example: `https://token.actions.githubusercontent.com`.
    pub expected_issuer: Option<String>,
    /// Required prefix on the leaf cert's SAN URI. Example:
    /// `https://github.com/lpm-dev/rust-client/`. Off-by-one bug
    /// site (`rust-client` vs `rust-client/`) — always include the
    /// trailing `/` to anchor.
    pub expected_san_uri_prefix: Option<String>,
    /// Required workflow path inside the SAN URI.
    /// Example: `.github/workflows/release.yml`. The full SAN URI
    /// shape is `<prefix><workflow_path>@<ref>`.
    pub expected_workflow_path: Option<String>,
}

impl IdentityExpectations {
    /// Skip all identity checks when per-package identity tracking is
    /// handled outside the verifier.
    #[allow(dead_code)]
    pub fn none() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.expected_issuer.is_none()
            && self.expected_san_uri_prefix.is_none()
            && self.expected_workflow_path.is_none()
    }
}

/// The structured result of a successful bundle verification.
/// `snapshot` carries the per-package identity for the drift gate;
/// the trail of `signed_at`, `leaf_cert_sha256`, `log_id`,
/// and `log_index` becomes verified lockfile evidence. The cache
/// stores the raw bundle so every hit can re-run these checks.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct VerifiedProvenance {
    pub snapshot: lpm_workspace::ProvenanceSnapshot,
    pub build: CertificateBuildClaims,
    pub statement: serde_json::Value,
    /// When the signature was made, as far as signed evidence shows: the
    /// integrated time Rekor v1 signed in the entry's SET, or else the
    /// earliest RFC 3161 timestamp that verifies.
    pub signed_at: SystemTime,
    pub leaf_cert_sha256: String,
    pub log_id: String,
    pub log_index: i64,
}

/// What the Fulcio certificate itself says about the build that signed,
/// from its v2 extensions. Fulcio copies these from the CI provider's
/// OIDC token, so they don't depend on the in-toto statement the build
/// wrote. A field is `None` when the certificate doesn't carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateBuildClaims {
    /// `1.3.6.1.4.1.57264.1.12`, e.g. `https://github.com/lpm-dev/rust-client`.
    pub source_repository_uri: Option<String>,
    /// `1.3.6.1.4.1.57264.1.13`: the commit the build ran from.
    pub source_repository_digest: Option<String>,
    /// `1.3.6.1.4.1.57264.1.14`, e.g. `refs/heads/main`.
    pub source_repository_ref: Option<String>,
    /// `1.3.6.1.4.1.57264.1.20`: the event that started the build.
    pub build_trigger: Option<String>,
    /// `1.3.6.1.4.1.57264.1.11`: `github-hosted` or `self-hosted`.
    pub runner_environment: Option<String>,
}

const FULCIO_SOURCE_REPOSITORY_URI_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 12];
const FULCIO_SOURCE_REPOSITORY_DIGEST_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 13];
const FULCIO_SOURCE_REPOSITORY_REF_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 14];
const FULCIO_BUILD_TRIGGER_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 20];
const FULCIO_RUNNER_ENVIRONMENT_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 11];

/// Read the Fulcio v2 build extensions. Each v2 extension is a DER
/// UTF8String; one that is malformed or appears twice fails the bundle.
pub(super) fn extract_certificate_build_claims(
    leaf: &X509Certificate<'_>,
) -> Result<CertificateBuildClaims, VerifyError> {
    let mut claims = CertificateBuildClaims::default();
    for ext in leaf.extensions() {
        let Some(components) = ext.oid.iter() else {
            continue;
        };
        let components: Vec<u64> = components.collect();
        let (slot, name) = match components.as_slice() {
            oid if oid == FULCIO_SOURCE_REPOSITORY_URI_OID => {
                (&mut claims.source_repository_uri, "source repository URI")
            }
            oid if oid == FULCIO_SOURCE_REPOSITORY_DIGEST_OID => (
                &mut claims.source_repository_digest,
                "source repository digest",
            ),
            oid if oid == FULCIO_SOURCE_REPOSITORY_REF_OID => {
                (&mut claims.source_repository_ref, "source repository ref")
            }
            oid if oid == FULCIO_BUILD_TRIGGER_OID => (&mut claims.build_trigger, "build trigger"),
            oid if oid == FULCIO_RUNNER_ENVIRONMENT_OID => {
                (&mut claims.runner_environment, "runner environment")
            }
            _ => continue,
        };
        let value = decode_der_utf8_string(ext.value).ok_or_else(|| {
            VerifyError::BundleParse(format!("Fulcio {name} extension is not a DER UTF8String"))
        })?;
        if slot.replace(value.to_string()).is_some() {
            return Err(VerifyError::BundleParse(format!(
                "Fulcio {name} extension appears more than once"
            )));
        }
    }
    Ok(claims)
}

/// The whole of `bytes` must be one DER UTF8String (tag 0x0C).
fn decode_der_utf8_string(bytes: &[u8]) -> Option<&str> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x0C {
        return None;
    }
    let (len, consumed) = der_decode_length(rest)?;
    let body = rest.get(consumed..)?;
    if body.len() != len {
        return None;
    }
    std::str::from_utf8(body).ok()
}

/// Verify a Sigstore bundle end-to-end.
///
/// Returns `Ok(VerifiedProvenance)` only when every primitive
/// (DSSE, chain, SCT, Rekor body, SET, inclusion proof) accepts
/// AND the caller-supplied identity expectations match. Any single
/// failure short-circuits with the most-specific `VerifyError`
/// variant so the caller can surface diagnostics without a generic
/// "verification failed" rollup.
#[allow(dead_code)] // wired into provenance_bundle
#[tracing::instrument(skip_all, name = "provenance.verify", level = "debug")]
pub fn verify_sigstore_bundle(
    body: &[u8],
    expectations: &IdentityExpectations,
    options: VerifyOptions,
) -> Result<VerifiedProvenance, VerifyError> {
    let trust = trust_root()?;
    verify_sigstore_bundle_with(body, expectations, options, &trust)
}

/// [`verify_sigstore_bundle`] against a given trust root.
pub(super) fn verify_sigstore_bundle_with(
    body: &[u8],
    expectations: &IdentityExpectations,
    options: VerifyOptions,
    trust: &TrustRoot,
) -> Result<VerifiedProvenance, VerifyError> {
    // Dot-namespaced span names match the existing Tracy integration
    // convention (`linker.prepare`, `linker.one`, etc.) so Tracy
    // captures and `tracing-flame` outputs render the verifier in
    // the same hierarchy as the rest of the install pipeline.
    // Each span is `debug` level — no cost when no subscriber is
    // attached (the `tracing` crate makes unattached spans nearly
    // free), and the inner numbers are only useful when triaging.
    let components = {
        let _span = tracing::debug_span!("provenance.verify.parse").entered();
        parse_bundle_components(body)?
    };
    trust.check_expiry(SystemTime::now())?;

    let log_index = parse_log_index(&components.tlog_entry.log_index)?;
    let entry_version = rekor_entry_version(&components.tlog_entry)?;
    let signature = dsse_signature(&components.dsse_envelope)?;

    // Every RFC 3161 timestamp that verifies is a signed time the
    // signature existed at.
    let timestamps = {
        let _span = tracing::debug_span!("provenance.verify.timestamps").entered();
        verify_signed_timestamps(
            &components.signed_timestamps,
            &signature,
            &trust.timestamp_authorities,
        )?
    };

    // The time the certificate is checked at, which something must have
    // signed: the integrated time in a Rekor v1 entry's SET, else the
    // earliest RFC 3161 timestamp. An inclusion proof shows the entry is in
    // the log, not when it got there, and Rekor v2 records no time at all.
    let integrated_time = match entry_version {
        RekorEntryVersion::V1
            if components
                .tlog_entry
                .resolved_signed_entry_timestamp()
                .is_some() =>
        {
            let _span = tracing::debug_span!("provenance.verify.set").entered();
            Some(verify_rekor_set(
                &components.tlog_entry,
                &trust.rekor_keys,
                options.rekor_inclusion_policy,
            )?)
        }
        RekorEntryVersion::V1 if options.rekor_inclusion_policy.requires_set() => {
            return Err(VerifyError::RekorSetMissing);
        }
        RekorEntryVersion::V1 | RekorEntryVersion::V2 => None,
    };
    let signed_at = match integrated_time.or_else(|| timestamps.earliest()) {
        Some(signed_at) => signed_at,
        None => return Err(timestamps.into_error()),
    };

    // The certificate must have been valid at every signed time. Trust
    // anchors are filtered to those active at each time so a retired root
    // doesn't anchor a fresh bundle.
    let chain_refs: Vec<&[u8]> = components.chain_der.iter().map(|d| d.as_slice()).collect();
    {
        let _span = tracing::debug_span!("provenance.verify.chain").entered();
        verify_cert_chain(&chain_refs, &trust.fulcio_roots_at(signed_at), signed_at)?;
        for timestamp in &timestamps.verified {
            if timestamp.time != signed_at {
                verify_cert_chain(
                    &chain_refs,
                    &trust.fulcio_roots_at(timestamp.time),
                    timestamp.time,
                )?;
            }
        }
    }

    // Parse the leaf cert once for downstream consumers (DSSE,
    // identity, issuer SPKI lookup). The lifetime is tied to
    // `components.leaf_cert_der`.
    let (_, leaf_parsed) = X509Certificate::from_der(&components.leaf_cert_der).map_err(|e| {
        VerifyError::BundleParse(format!("leaf cert DER did not re-parse for DSSE: {e}"))
    })?;

    {
        let _span = tracing::debug_span!("provenance.verify.dsse").entered();
        verify_dsse(&components.dsse_envelope, &leaf_parsed)?;
    }

    // SCT verify — need the immediate issuer's SPKI for the precert
    // signed-input. Search the bundle's chain first (chain[1..]),
    // fall back to the active trust anchors. Chain validation has
    // already cleared the path, so a match is guaranteed.
    let issuer_spki_der =
        find_leaf_issuer_spki(&leaf_parsed, &components.chain_der, trust, signed_at)?;
    {
        let _span = tracing::debug_span!("provenance.verify.sct").entered();
        verify_embedded_sct(
            &components.leaf_cert_der,
            &issuer_spki_der,
            &trust.ctlog_keys,
        )?;
    }

    {
        let _span = tracing::debug_span!("provenance.verify.rekor_body").entered();
        match entry_version {
            RekorEntryVersion::V1 => verify_rekor_body(
                &components.tlog_entry,
                &components.dsse_envelope,
                &components.leaf_cert_der,
            )?,
            RekorEntryVersion::V2 => verify_hashedrekord_v002(
                &components.tlog_entry,
                &components.dsse_envelope,
                &components.leaf_cert_der,
                &signature,
            )?,
        }
    }

    let mut log_id = components.tlog_entry.log_id.key_id.clone();
    {
        let _span = tracing::debug_span!("provenance.verify.inclusion_proof").entered();
        match entry_version {
            RekorEntryVersion::V1 => verify_rekor_v1_inclusion(
                &components.tlog_entry,
                trust,
                options.rekor_inclusion_policy,
                components.inclusion_proof_required,
            )?,
            RekorEntryVersion::V2 => {
                log_id = verify_rekor_v2_inclusion(&components.tlog_entry, trust)?;
            }
        }
    }

    if !expectations.is_empty() {
        check_identity_expectations(&leaf_parsed, expectations)?;
    }

    let leaf_cert_sha256 = format!(
        "sha256-{}",
        hex::encode(Sha256::digest(&components.leaf_cert_der))
    );
    let snapshot = build_provenance_snapshot(&leaf_parsed, &leaf_cert_sha256);
    let build = extract_certificate_build_claims(&leaf_parsed)?;

    Ok(VerifiedProvenance {
        snapshot,
        build,
        statement: components.statement,
        signed_at,
        leaf_cert_sha256,
        log_id,
        log_index,
    })
}

/// A Rekor v1 entry's inclusion proof, as `policy` or the bundle's
/// version requires it. One that is present is verified whatever the
/// policy.
fn verify_rekor_v1_inclusion(
    tlog_entry: &crate::sigstore::TlogEntry,
    trust: &TrustRoot,
    policy: RekorInclusionProofPolicy,
    bundle_requires_proof: bool,
) -> Result<(), VerifyError> {
    let has_inclusion_proof = tlog_entry.resolved_inclusion_proof().is_some();
    if has_inclusion_proof || bundle_requires_proof || policy.requires_inclusion_proof() {
        verify_inclusion_proof(tlog_entry, &trust.rekor_keys)?;
    }
    // `Either` requires a SET or an inclusion proof; the SET check
    // already passed over an absent SET.
    if policy == RekorInclusionProofPolicy::Either
        && tlog_entry.resolved_signed_entry_timestamp().is_none()
        && !has_inclusion_proof
    {
        return Err(VerifyError::RekorSetMissing);
    }
    Ok(())
}

/// A Rekor v2 entry's inclusion proof, which every policy requires: the
/// entry carries no SET. Returns the ID the trust root gives the log,
/// base64-encoded as bundles carry it, however the bundle spells it.
///
/// The log is found by the entry's `logId`, or, since Rekor means to stop
/// sending one, by the checkpoint signature naming a log in the trust
/// root. A checkpoint carries no time to check the log's key against, so
/// the log's window in the trust root isn't consulted, as Sigstore's
/// verifiers don't.
fn verify_rekor_v2_inclusion(
    tlog_entry: &crate::sigstore::TlogEntry,
    trust: &TrustRoot,
) -> Result<String, VerifyError> {
    let missing = |detail: String| VerifyError::MissingTrustMaterial {
        check: "Rekor inclusion proof",
        detail,
    };
    if !tlog_entry.log_id.key_id.is_empty() {
        let log_id =
            decode_log_id(&tlog_entry.log_id.key_id).map_err(VerifyError::InclusionProof)?;
        let log = trust.rekor_log(&log_id).ok_or_else(|| {
            missing(format!(
                "no Rekor log for logId={}",
                tlog_entry.log_id.key_id
            ))
        })?;
        verify_rekor_v2_inclusion_proof(tlog_entry, log)?;
        return Ok(BASE64.encode(&log.log_id));
    }

    // A log in the trust root may also co-sign another log's checkpoints,
    // so every log the checkpoint names is tried.
    let proof = tlog_entry
        .resolved_inclusion_proof()
        .ok_or(VerifyError::InclusionProofMissing)?;
    let envelope = extract_checkpoint_envelope(&proof.checkpoint)?;
    let named = logs_signing(&envelope, &trust.rekor_keys).map_err(VerifyError::InclusionProof)?;
    let mut refused = None;
    for log in named {
        match verify_rekor_v2_inclusion_proof(tlog_entry, log) {
            Ok(()) => return Ok(BASE64.encode(&log.log_id)),
            Err(error) => {
                refused.get_or_insert(error);
            }
        }
    }
    Err(refused
        .unwrap_or_else(|| missing("no Rekor log in the trust root signed its checkpoint".into())))
}

/// Parsed bundle components, with the heavy DER + DSSE work done
/// once up front so downstream verifiers receive typed inputs.
#[derive(Debug)]
pub(super) struct BundleComponents {
    pub(super) dsse_envelope: DsseEnvelope,
    pub(super) statement: serde_json::Value,
    pub(super) leaf_cert_der: Vec<u8>,
    pub(super) chain_der: Vec<Vec<u8>>,
    pub(super) tlog_entry: crate::sigstore::TlogEntry,
    /// DER `TimeStampResp`s from `timestampVerificationData`.
    pub(super) signed_timestamps: Vec<Vec<u8>>,
    /// Whether the bundle's version requires its log entry to carry an
    /// inclusion proof, whatever the caller's policy.
    pub(super) inclusion_proof_required: bool,
}

/// Parse a Sigstore bundle body into [`BundleComponents`]. Handles
/// the three wire shapes the production fetch path already deals
/// with (mirrors the legacy identity-only parser in
/// `crate::provenance_bundle` for cert extraction):
///
/// 1. **Sigstore Bundle v0.2** — chain at
///    `verificationMaterial.x509CertificateChain.certificates[]`.
/// 2. **Sigstore Bundle v0.3** — single leaf at
///    `verificationMaterial.certificate.rawBytes` (chain length 1;
///    the verifier walks the leaf directly against trust anchors).
/// 3. **npm attestations wrapper** —
///    `{ attestations: [{ bundle: <inner> }] }`. npm ships two
///    attestations per package: a publicKey-only publish-time
///    attestation (skip) and a Fulcio-issued provenance
///    attestation (use).
pub(super) fn parse_bundle_components(body: &[u8]) -> Result<BundleComponents, VerifyError> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| VerifyError::BundleParse(format!("bundle is not valid JSON: {e}")))?;

    // npm wrapper case: scan attestations[*].bundle for the first
    // parseable inner bundle.
    if let Some(attestations) = root.get("attestations").and_then(|v| v.as_array()) {
        let mut last_err = None;
        for att in attestations {
            if let Some(inner) = att.get("bundle") {
                match parse_inner_bundle(inner) {
                    Ok(c) => return Ok(c),
                    Err(e) => last_err = Some(e),
                }
            }
        }
        return Err(last_err.unwrap_or_else(|| {
            VerifyError::BundleParse(
                "npm attestations array contained no parseable inner bundle".into(),
            )
        }));
    }

    parse_inner_bundle(&root)
}

fn parse_inner_bundle(bundle: &serde_json::Value) -> Result<BundleComponents, VerifyError> {
    let verification_material = bundle
        .get("verificationMaterial")
        .ok_or_else(|| VerifyError::BundleParse("bundle missing `verificationMaterial`".into()))?;

    // Cert chain — v0.3 single-cert OR v0.2 chain.
    let chain_der: Vec<Vec<u8>> = if let Some(cert) = verification_material.get("certificate") {
        let raw = cert
            .get("rawBytes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VerifyError::BundleParse("v0.3 `certificate` field has no `rawBytes` string".into())
            })?;
        let der = BASE64
            .decode(raw.as_bytes())
            .map_err(|e| VerifyError::BundleParse(format!("leaf cert rawBytes not base64: {e}")))?;
        vec![der]
    } else if let Some(chain) = verification_material.get("x509CertificateChain") {
        let certs = chain
            .get("certificates")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                VerifyError::BundleParse(
                    "v0.2 `x509CertificateChain.certificates` is not an array".into(),
                )
            })?;
        if certs.is_empty() {
            return Err(VerifyError::BundleParse(
                "v0.2 cert chain is empty (must have at least the leaf)".into(),
            ));
        }
        certs
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let raw = c.get("rawBytes").and_then(|v| v.as_str()).ok_or_else(|| {
                    VerifyError::BundleParse(format!(
                        "v0.2 chain cert[{i}] has no `rawBytes` string"
                    ))
                })?;
                BASE64.decode(raw.as_bytes()).map_err(|e| {
                    VerifyError::BundleParse(format!("chain cert[{i}] not base64: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(VerifyError::BundleParse(
            "bundle has neither v0.3 `certificate` nor v0.2 `x509CertificateChain`".into(),
        ));
    };

    let leaf_cert_der = chain_der
        .first()
        .cloned()
        .ok_or_else(|| VerifyError::BundleParse("cert chain has no leaf".into()))?;

    // DSSE envelope — required.
    let dsse_value = bundle
        .get("dsseEnvelope")
        .ok_or_else(|| VerifyError::BundleParse("bundle missing `dsseEnvelope`".into()))?;
    let dsse_envelope: DsseEnvelope = serde_json::from_value(dsse_value.clone())
        .map_err(|e| VerifyError::BundleParse(format!("dsseEnvelope shape: {e}")))?;
    let payload_bytes = BASE64
        .decode(dsse_envelope.payload.as_bytes())
        .map_err(|e| VerifyError::BundleParse(format!("DSSE payload not base64: {e}")))?;
    let statement: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerifyError::BundleParse(format!("DSSE payload not JSON: {e}")))?;

    // Tlog entry — take the first. Sigstore bundles ship one
    // `tlogEntries[0]` for the canonical Rekor entry.
    let tlog_entries = verification_material
        .get("tlogEntries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            VerifyError::BundleParse(
                "bundle `verificationMaterial.tlogEntries` is not an array".into(),
            )
        })?;
    let tlog_value = tlog_entries.first().ok_or_else(|| {
        VerifyError::BundleParse("bundle `verificationMaterial.tlogEntries` is empty".into())
    })?;
    let tlog_entry: crate::sigstore::TlogEntry = serde_json::from_value(tlog_value.clone())
        .map_err(|e| VerifyError::BundleParse(format!("tlogEntries[0] shape: {e}")))?;
    let signed_timestamps = parse_signed_timestamps(verification_material)?;
    let inclusion_proof_required =
        media_type_requires_inclusion_proof(bundle.get("mediaType").and_then(|v| v.as_str()));

    Ok(BundleComponents {
        dsse_envelope,
        statement,
        leaf_cert_der,
        chain_der,
        tlog_entry,
        signed_timestamps,
        inclusion_proof_required,
    })
}

/// Whether a bundle of this media type must carry an inclusion proof.
/// Version 0.1 bundles may rely on a SET alone; every later version
/// requires the proof, so an unknown or absent media type is held to the
/// later rule.
fn media_type_requires_inclusion_proof(media_type: Option<&str>) -> bool {
    !matches!(
        media_type,
        Some(
            "application/vnd.dev.sigstore.bundle+json;version=0.1"
                | "application/vnd.dev.sigstore.bundle.v0.1+json"
        )
    )
}

fn parse_signed_timestamps(
    verification_material: &serde_json::Value,
) -> Result<Vec<Vec<u8>>, VerifyError> {
    let Some(timestamps) = verification_material
        .get("timestampVerificationData")
        .and_then(|data| data.get("rfc3161Timestamps"))
    else {
        return Ok(Vec::new());
    };
    let timestamps = timestamps.as_array().ok_or_else(|| {
        VerifyError::BundleParse(
            "`timestampVerificationData.rfc3161Timestamps` is not an array".into(),
        )
    })?;
    if timestamps.len() > MAX_SIGNED_TIMESTAMPS {
        return Err(VerifyError::BundleParse(format!(
            "the bundle carries {} RFC 3161 timestamps, more than the {MAX_SIGNED_TIMESTAMPS} \
             accepted",
            timestamps.len()
        )));
    }
    timestamps
        .iter()
        .enumerate()
        .map(|(i, timestamp)| {
            let encoded = timestamp
                .get("signedTimestamp")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VerifyError::BundleParse(format!(
                        "rfc3161Timestamps[{i}] has no `signedTimestamp` string"
                    ))
                })?;
            BASE64.decode(encoded.as_bytes()).map_err(|e| {
                VerifyError::BundleParse(format!(
                    "rfc3161Timestamps[{i}].signedTimestamp is not base64: {e}"
                ))
            })
        })
        .collect()
}

/// The bundle's signature, decoded: the one its RFC 3161 timestamps and a
/// Rekor v2 entry name. A Sigstore bundle's envelope carries exactly one,
/// as Sigstore's verifiers require; with a second, a timestamp could date
/// a signature it never saw.
pub(super) fn dsse_signature(envelope: &DsseEnvelope) -> Result<Vec<u8>, VerifyError> {
    let [signature] = envelope.signatures.as_slice() else {
        return Err(VerifyError::DsseSignature(format!(
            "the envelope carries {} signatures where a Sigstore bundle's carries exactly one",
            envelope.signatures.len()
        )));
    };
    BASE64
        .decode(signature.sig.as_bytes())
        .map_err(|e| VerifyError::DsseSignature(format!("signature not valid base64: {e}")))
}

/// Extract `subject[0].name` and `subject[0].digest.sha256` from the
/// in-toto statement carried by the DSSE payload of a Sigstore bundle.
///
/// Pre-condition: the caller has already verified the bundle via
/// [`verify_sigstore_bundle`] — this function parses the wire bytes a
/// second time but adds no new trust decisions. It is purpose-scoped
/// to the standalone self-update path, which needs to bind the bundle
/// to the SHA-256 of the `SHA256SUMS.txt` manifest it just downloaded.
///
/// Returns `(subject_name, subject_sha256)`. Hex digest is lowercase.
pub(crate) fn extract_npm_subject_sha512(body: &[u8]) -> Result<(String, String), VerifyError> {
    extract_in_toto_subject_digest_for_algorithm(body, "sha512", true)
}

fn extract_in_toto_subject_digest_for_algorithm(
    body: &[u8],
    algorithm: &str,
    require_exactly_one_subject: bool,
) -> Result<(String, String), VerifyError> {
    let components = parse_bundle_components(body)?;
    extract_subject_digest_from_statement(
        &components.statement,
        algorithm,
        require_exactly_one_subject,
    )
}

pub(crate) fn extract_subject_digest_from_statement(
    statement: &serde_json::Value,
    algorithm: &str,
    require_exactly_one_subject: bool,
) -> Result<(String, String), VerifyError> {
    let subjects = statement
        .get("subject")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            VerifyError::BundleParse("in-toto statement has no `subject` array".into())
        })?;
    if require_exactly_one_subject && subjects.len() != 1 {
        return Err(VerifyError::BundleParse(format!(
            "in-toto statement must contain exactly one subject, got {}",
            subjects.len()
        )));
    }
    let subject = subjects
        .first()
        .ok_or_else(|| VerifyError::BundleParse("in-toto statement `subject` is empty".into()))?;

    let name = subject
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::BundleParse("in-toto statement subject[0] has no string `name`".into())
        })?
        .to_string();
    let digest = subject
        .get("digest")
        .and_then(|d| d.get(algorithm))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerifyError::BundleParse(format!(
                "in-toto statement subject[0].digest.{algorithm} missing or not a string"
            ))
        })?
        .to_ascii_lowercase();

    Ok((name, digest))
}

/// Find the SPKI DER of the leaf cert's immediate issuer. Tries:
/// 1. Bundle's chain[1..] (the typical case when the bundle ships
///    leaf + intermediate).
/// 2. Active Fulcio trust anchors (when the bundle ships only the
///    leaf and the chain walker traversed the path implicitly).
///
/// Chain validation has already cleared the path, so a match is
/// guaranteed in any valid bundle.
pub(super) fn find_leaf_issuer_spki(
    leaf: &X509Certificate<'_>,
    chain_der: &[Vec<u8>],
    trust: &TrustRoot,
    at_time: SystemTime,
) -> Result<Vec<u8>, VerifyError> {
    let leaf_issuer_dn = leaf.tbs_certificate.issuer.as_raw();
    for der in chain_der.iter().skip(1) {
        if let Ok((_, parsed)) = X509Certificate::from_der(der)
            && parsed.tbs_certificate.subject.as_raw() == leaf_issuer_dn
        {
            return Ok(parsed.tbs_certificate.subject_pki.raw.to_vec());
        }
    }
    for root in trust.fulcio_roots_at(at_time) {
        for der in &root.cert_chain_der {
            if let Ok((_, parsed)) = X509Certificate::from_der(der)
                && parsed.tbs_certificate.subject.as_raw() == leaf_issuer_dn
            {
                return Ok(parsed.tbs_certificate.subject_pki.raw.to_vec());
            }
        }
    }
    Err(VerifyError::Sct(
        "could not locate leaf cert's immediate issuer in the bundle chain or trust root \
         — cannot compute SCT precert input"
            .into(),
    ))
}

/// Fulcio OIDC issuer extension OIDs (RFC-style, dotted-decimal):
/// - `1.3.6.1.4.1.57264.1.1` — original (v1).
/// - `1.3.6.1.4.1.57264.1.8` — v2 (same semantic). Accept either.
pub(super) const FULCIO_OIDC_ISSUER_OID_V1: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 1];
const FULCIO_OIDC_ISSUER_OID_V2: [u64; 9] = [1, 3, 6, 1, 4, 1, 57264, 1, 8];

/// Apply `IdentityExpectations` against the leaf cert. Pre-conditioned
/// by `expectations.is_empty()` at the call site — when populated,
/// every Some field must match or this returns
/// `VerifyError::IdentityMismatch`.
pub(super) fn check_identity_expectations(
    leaf: &X509Certificate<'_>,
    expectations: &IdentityExpectations,
) -> Result<(), VerifyError> {
    if let Some(expected) = &expectations.expected_issuer {
        let actual =
            extract_fulcio_oidc_issuer(leaf)?.ok_or_else(|| VerifyError::IdentityMismatch {
                field: "issuer",
                expected: expected.clone(),
                actual: "<no Fulcio OIDC issuer extension>".into(),
            })?;
        if &actual != expected {
            return Err(VerifyError::IdentityMismatch {
                field: "issuer",
                expected: expected.clone(),
                actual,
            });
        }
    }

    if expectations.expected_san_uri_prefix.is_some()
        || expectations.expected_workflow_path.is_some()
    {
        let san_uri = extract_leaf_san_uri(leaf).ok_or_else(|| VerifyError::IdentityMismatch {
            field: "san_uri",
            expected: expectations
                .expected_san_uri_prefix
                .clone()
                .or_else(|| expectations.expected_workflow_path.clone())
                .unwrap_or_default(),
            actual: "<no SAN URI on leaf cert>".into(),
        })?;
        if let Some(prefix) = &expectations.expected_san_uri_prefix
            && !san_uri.starts_with(prefix)
        {
            return Err(VerifyError::IdentityMismatch {
                field: "san_uri_prefix",
                expected: prefix.clone(),
                actual: san_uri,
            });
        }
        if let Some(expected_workflow) = &expectations.expected_workflow_path {
            let actual_workflow = parse_github_actions_identity(&san_uri)
                .map_or_else(|| san_uri.clone(), |(_, workflow, _)| workflow);
            if &actual_workflow != expected_workflow {
                return Err(VerifyError::IdentityMismatch {
                    field: "workflow_path",
                    expected: expected_workflow.clone(),
                    actual: actual_workflow,
                });
            }
        }
    }

    Ok(())
}

/// Extract the OIDC issuer string from the Fulcio extension at
/// `1.3.6.1.4.1.57264.1.1` (v1) or `.1.8` (v2). The extension's
/// value is a plain UTF-8 string (NOT a DER OCTET STRING in v1; v2
/// uses a DER UTF8String wrapper). We try plain UTF-8 first and
/// fall back to DER-UTF8String parsing for v2.
fn extract_fulcio_oidc_issuer(leaf: &X509Certificate<'_>) -> Result<Option<String>, VerifyError> {
    for ext in leaf.extensions() {
        let components: Vec<u64> = match ext.oid.iter() {
            Some(it) => it.collect(),
            None => continue,
        };
        let is_v1 = components.as_slice() == FULCIO_OIDC_ISSUER_OID_V1;
        let is_v2 = components.as_slice() == FULCIO_OIDC_ISSUER_OID_V2;
        if !is_v1 && !is_v2 {
            continue;
        }
        // v1: raw UTF-8 bytes. v2: DER UTF8String (tag 0x0C + length + content).
        if is_v2 && ext.value.len() >= 2 && ext.value[0] == 0x0C {
            let (len, consumed) = der_decode_length(&ext.value[1..]).ok_or_else(|| {
                VerifyError::BundleParse(
                    "Fulcio OIDC issuer v2 extension has malformed UTF8String length".into(),
                )
            })?;
            let start = 1 + consumed;
            if ext.value.len() < start + len {
                return Err(VerifyError::BundleParse(
                    "Fulcio OIDC issuer v2 UTF8String body truncated".into(),
                ));
            }
            return Ok(Some(
                std::str::from_utf8(&ext.value[start..start + len])
                    .map_err(|e| {
                        VerifyError::BundleParse(format!(
                            "Fulcio OIDC issuer v2 body is not valid UTF-8: {e}"
                        ))
                    })?
                    .to_string(),
            ));
        }
        // v1 plain bytes (or v2 unwrapped fallback).
        return Ok(Some(
            std::str::from_utf8(ext.value)
                .map_err(|e| {
                    VerifyError::BundleParse(format!(
                        "Fulcio OIDC issuer extension body is not valid UTF-8: {e}"
                    ))
                })?
                .to_string(),
        ));
    }
    Ok(None)
}

/// Extract the first URI-shaped SAN from the leaf cert. Sigstore
/// Fulcio leaves carry one URI SAN with the GitHub Actions (or
/// other OIDC-provider) workflow identity.
fn extract_leaf_san_uri(leaf: &X509Certificate<'_>) -> Option<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    for ext in leaf.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    return Some((*uri).to_string());
                }
            }
        }
    }
    None
}

/// Build the `ProvenanceSnapshot` consumed by the drift gate
/// (`lpm_security::provenance::check_provenance_drift`). Reuses
/// the same leaf-cert SAN parsing contract as `provenance_bundle`; this
/// helper exists so the snapshot construction has the same shape
/// regardless of which code path produced the leaf cert.
fn build_provenance_snapshot(
    leaf: &X509Certificate<'_>,
    leaf_cert_sha256: &str,
) -> lpm_workspace::ProvenanceSnapshot {
    let san_uri = extract_leaf_san_uri(leaf);
    let identity = san_uri.as_deref().and_then(parse_github_actions_identity);
    lpm_workspace::ProvenanceSnapshot {
        present: true,
        publisher: identity.as_ref().map(|(p, _, _)| p.clone()),
        workflow_path: identity.as_ref().map(|(_, w, _)| w.clone()),
        workflow_ref: identity.as_ref().map(|(_, _, r)| r.clone()),
        attestation_cert_sha256: Some(leaf_cert_sha256.to_string()),
    }
}

/// Parse a GitHub Actions SAN URI into `(publisher, workflow_path,
/// workflow_ref)`. Mirrors `provenance_bundle`'s GitHub Actions parser
/// — kept inline in the verifier so the orchestrator doesn't reach
/// out into the install-path module; the duplication is small (10
/// lines) and the two stay in sync via the workflow tests that
/// pin the JSON envelope shape.
fn parse_github_actions_identity(uri: &str) -> Option<(String, String, String)> {
    const PREFIX: &str = "https://github.com/";
    const WORKFLOWS_SEG: &str = "/.github/workflows/";
    let after_host = uri.strip_prefix(PREFIX)?;
    let (path, workflow_ref) = after_host.rsplit_once('@')?;
    let (org_repo, wf_tail) = path.split_once(WORKFLOWS_SEG)?;
    let (org, repo) = org_repo.split_once('/')?;
    if org.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    Some((
        format!("github:{org}/{repo}"),
        format!(".github/workflows/{wf_tail}"),
        workflow_ref.to_string(),
    ))
}
