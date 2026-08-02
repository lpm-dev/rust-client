//! Sigstore provenance bundle mechanics for the CLI.
//!
//! This module owns the bounded HTTP fetch, on-disk cache format,
//! cryptographic verification bridge, and legacy identity-only parser used
//! by the operator skip path. Policy composition and install-facing
//! orchestration stay in [`crate::provenance_fetch`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::LpmError;
use lpm_workspace::ProvenanceSnapshot;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 7-day TTL for verified attestation bundles.
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Version 4 stores the original Sigstore bundle instead of derived
/// evidence, so every cache hit is cryptographically reverified and
/// rebound to the current package integrity before use.
const CACHE_MAGIC: &[u8; 8] = b"LPMPRV4\0";
const CACHE_HEADER_BYTES: usize = CACHE_MAGIC.len() + std::mem::size_of::<u64>();

/// Max attestation-bundle response size we'll read. Defends against
/// a hostile / broken registry serving an unbounded body that would
/// OOM the process. 1 MiB is several orders of magnitude above any
/// real Sigstore bundle.
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// HTTP fetch timeout for attestation bundle requests. Kept short
/// because this is an install-path blocker — a slow registry should
/// degrade to "unknown" quickly rather than stall the install.
const FETCH_TIMEOUT_SECS: u64 = 15;

/// Maximum bytes we will read from one on-disk cache entry. A local
/// attacker who can write under `~/.lpm/cache/metadata/attestations/`
/// should not be able to OOM the install by planting a multi-GiB file
const MAX_CACHE_ENTRY_BYTES: u64 = (CACHE_HEADER_BYTES + MAX_BUNDLE_BYTES) as u64;

#[derive(Clone)]
pub(crate) struct ProvenanceHttpClient {
    inner: reqwest::Client,
}

impl ProvenanceHttpClient {
    pub(crate) fn build() -> Result<Self, reqwest::Error> {
        lpm_http::client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|inner| Self { inner })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AttestationUrlPolicy {
    registry_origin: String,
    registry_source: RegistrySourceIdentity,
    allow_loopback_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistrySourceIdentity(String);

impl AttestationUrlPolicy {
    pub(crate) fn for_registry(registry_url: &str) -> Result<Self, LpmError> {
        let mut parsed = reqwest::Url::parse(registry_url).map_err(|error| {
            LpmError::ProvenanceVerification(format!(
                "cannot validate attestation URL against invalid registry URL: {error}"
            ))
        })?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(LpmError::ProvenanceVerification(
                "attestation registry URL must not contain credentials".into(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(LpmError::ProvenanceVerification(
                "attestation registry URL must not contain a fragment".into(),
            ));
        }
        let allow_loopback_http =
            parsed.scheme() == "http" && lpm_registry::is_localhost_url(registry_url);
        if parsed.scheme() != "https" && !allow_loopback_http {
            return Err(LpmError::ProvenanceVerification(
                "attestation registry origin must use HTTPS or loopback HTTP".into(),
            ));
        }
        let normalized_path = parsed.path().trim_end_matches('/').to_string();
        parsed.set_path(if normalized_path.is_empty() {
            "/"
        } else {
            &normalized_path
        });
        Ok(Self {
            registry_origin: parsed.origin().ascii_serialization(),
            registry_source: RegistrySourceIdentity(parsed.to_string()),
            allow_loopback_http,
        })
    }

    pub(crate) fn registry_source(&self) -> &RegistrySourceIdentity {
        &self.registry_source
    }

    pub(crate) fn validate(&self, candidate: &str) -> Result<reqwest::Url, FetchBundleError> {
        let parsed = reqwest::Url::parse(candidate).map_err(|error| {
            FetchBundleError::Policy(format!("attestation URL is invalid: {error}"))
        })?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(FetchBundleError::Policy(
                "attestation URL must not contain credentials".into(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(FetchBundleError::Policy(
                "attestation URL must not contain a fragment".into(),
            ));
        }
        if parsed.origin().ascii_serialization() != self.registry_origin {
            return Err(FetchBundleError::Policy(
                "attestation URL must use the selected registry origin".into(),
            ));
        }
        if parsed.scheme() != "https"
            && !(self.allow_loopback_http
                && parsed.scheme() == "http"
                && lpm_registry::is_localhost_url(parsed.as_str()))
        {
            return Err(FetchBundleError::Policy(
                "attestation URL must use HTTPS or configured loopback HTTP".into(),
            ));
        }
        Ok(parsed)
    }
}

#[derive(Debug)]
pub(crate) enum FetchBundleError {
    Transport,
    Policy(String),
}

// ── Cache primitives ────────────────────────────────────────────

pub(crate) type VerifiedNpmProvenance = lpm_lockfile::LockedProvenance;

fn hash_provenance_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional_provenance_field(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_provenance_field(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn verified_provenance_digest(
    snapshot: &ProvenanceSnapshot,
    subject_name: &str,
    subject_sha512: &str,
    integrated_time_secs: u64,
    log_id: &str,
    log_index: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-verified-provenance-v1\0");
    hasher.update([u8::from(snapshot.present)]);
    hash_optional_provenance_field(&mut hasher, snapshot.publisher.as_deref());
    hash_optional_provenance_field(&mut hasher, snapshot.workflow_path.as_deref());
    hash_optional_provenance_field(&mut hasher, snapshot.workflow_ref.as_deref());
    hash_optional_provenance_field(&mut hasher, snapshot.attestation_cert_sha256.as_deref());
    hash_provenance_field(&mut hasher, subject_name);
    hash_provenance_field(&mut hasher, subject_sha512);
    hasher.update(integrated_time_secs.to_be_bytes());
    hash_provenance_field(&mut hasher, log_id);
    hasher.update(log_index.to_be_bytes());
    format!("sha256-{}", hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmArtifactExpectation {
    subject_name: String,
    subject_sha512: String,
}

impl NpmArtifactExpectation {
    pub(crate) fn from_package(
        name: &str,
        version: &str,
        integrity: Option<&str>,
    ) -> Result<Self, LpmError> {
        let integrity = integrity.ok_or_else(|| {
            LpmError::ProvenanceVerification(format!(
                "cannot bind provenance for {name}@{version}: package metadata has no integrity"
            ))
        })?;
        let parsed = lpm_common::Integrity::parse(integrity).map_err(|error| {
            LpmError::ProvenanceVerification(format!(
                "cannot bind provenance for {name}@{version}: invalid package integrity: {error}"
            ))
        })?;
        if parsed.algorithm != lpm_common::integrity::HashAlgorithm::Sha512 {
            return Err(LpmError::ProvenanceVerification(format!(
                "cannot bind provenance for {name}@{version}: expected sha512 integrity, got {integrity}"
            )));
        }
        Ok(Self {
            subject_name: lpm_common::npm_package_purl(name, version),
            subject_sha512: hex::encode(parsed.hash),
        })
    }

    fn matches(&self, evidence: &VerifiedNpmProvenance) -> bool {
        self.subject_name == evidence.subject_name && self.subject_sha512 == evidence.subject_sha512
    }
}

pub(crate) fn validate_locked_provenance(
    name: &str,
    version: &str,
    integrity: Option<&str>,
    evidence: &VerifiedNpmProvenance,
) -> Result<(), LpmError> {
    let expectation = NpmArtifactExpectation::from_package(name, version, integrity)?;
    if !evidence.snapshot.present {
        return Err(LpmError::ProvenanceVerification(format!(
            "lockfile provenance for {name}@{version} is marked absent"
        )));
    }
    if !expectation.matches(evidence) {
        return Err(LpmError::ProvenanceVerification(format!(
            "lockfile provenance is not bound to {name}@{version} and its package integrity"
        )));
    }
    Ok(())
}

/// Compute the on-disk cache filename for one registry and `name@version`.
///
/// The canonical logical registry source is part of the digest so evidence
/// from one registry can never satisfy another registry's lookup.
fn cache_filename(registry_source: &RegistrySourceIdentity, name: &str, version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(registry_source.0.as_bytes());
    hasher.update(b"\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(version.as_bytes());
    format!("{}.sigstore", hex::encode(hasher.finalize()))
}

fn cache_path(
    cache_root: &Path,
    registry_source: &RegistrySourceIdentity,
    name: &str,
    version: &str,
) -> PathBuf {
    cache_root.join(cache_filename(registry_source, name, version))
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Read and reverify a cached bundle if it exists and is fresh.
///
/// The artifact expectation is mandatory: returning cached provenance
/// without rebinding the signed subject to the current package would turn
/// the user-writable cache into a trust database. Invalid cache contents
/// are misses so the registry gets one opportunity to replace a corrupt
/// local entry.
pub(crate) fn read_cache(
    cache_root: &Path,
    registry_source: &RegistrySourceIdentity,
    name: &str,
    version: &str,
    expectation: &NpmArtifactExpectation,
) -> Result<Option<VerifiedNpmProvenance>, LpmError> {
    use std::io::Read;

    let path = cache_path(cache_root, registry_source, name, version);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LpmError::Io(e)),
    };

    let metadata = file.metadata().map_err(LpmError::Io)?;
    if metadata.len() > MAX_CACHE_ENTRY_BYTES {
        tracing::warn!(
            target: "lpm_cli::provenance_fetch",
            path = %path.display(),
            size_bytes = metadata.len(),
            cap_bytes = MAX_CACHE_ENTRY_BYTES,
            "provenance cache entry exceeds size cap; treating as miss",
        );
        return Ok(None);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::BufReader::new(file)
        .take(MAX_CACHE_ENTRY_BYTES)
        .read_to_end(&mut bytes)
        .map_err(LpmError::Io)?;

    if bytes.len() < CACHE_HEADER_BYTES || &bytes[..CACHE_MAGIC.len()] != CACHE_MAGIC {
        return Ok(None);
    }
    let cached_at_secs = u64::from_le_bytes(
        bytes[CACHE_MAGIC.len()..CACHE_HEADER_BYTES]
            .try_into()
            .map_err(|_| LpmError::Registry("invalid provenance cache header".into()))?,
    );
    if current_epoch_secs().saturating_sub(cached_at_secs) >= CACHE_TTL_SECS {
        return Ok(None);
    }
    let bundle = &bytes[CACHE_HEADER_BYTES..];
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Ok(None);
    }

    match verify_bundle_or_err(bundle, "cached Sigstore bundle", expectation) {
        Ok(evidence) => Ok(Some(evidence)),
        Err(error) => {
            tracing::warn!(
                target: "lpm_cli::provenance_fetch",
                path = %path.display(),
                error = %error,
                "provenance cache bundle failed verification; treating as miss",
            );
            Ok(None)
        }
    }
}

/// Write a verified bundle atomically in the compact binary cache format.
pub(crate) fn write_cache(
    cache_root: &Path,
    registry_source: &RegistrySourceIdentity,
    name: &str,
    version: &str,
    bundle: &[u8],
) -> Result<(), LpmError> {
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(LpmError::Registry(
            "refusing to cache an empty or oversized provenance bundle".into(),
        ));
    }
    std::fs::create_dir_all(cache_root).map_err(LpmError::Io)?;

    let mut bytes = Vec::with_capacity(CACHE_HEADER_BYTES + bundle.len());
    bytes.extend_from_slice(CACHE_MAGIC);
    bytes.extend_from_slice(&current_epoch_secs().to_le_bytes());
    bytes.extend_from_slice(bundle);

    let path = cache_path(cache_root, registry_source, name, version);
    lpm_common::write_file_atomic_with_options(
        &path,
        &bytes,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(LpmError::Io)
}

// ── Fetch + parse ───────────────────────────────────────────────

/// Fetch the Sigstore attestation bundle bytes from `url`.
///
/// Transport errors degrade to [`FetchBundleError::Transport`]; URL-policy
/// violations return [`FetchBundleError::Policy`] and must remain a hard
/// security failure.
///
/// Body-size defense is enforced in two stages:
///
/// 1. **Pre-stream**: if `Content-Length` is declared and exceeds
///    the cap, reject before reading any body bytes. Legitimate
///    servers don't declare lying lengths, so this is a cheap
///    early-out.
/// 2. **Mid-stream**: for chunked / undeclared-length responses,
///    stream chunks via `bytes_stream()` into a bounded `Vec`,
///    checking the accumulator's size on every chunk and aborting
///    (dropping the stream, which closes the connection) the moment
///    it would exceed the cap.
///
/// Together these mean: no matter how the server frames the body, we
/// never allocate more than `MAX_BUNDLE_BYTES + the final pre-limit
/// chunk` bytes before rejecting.
/// HTTP fetch only — pulls the attestation bundle bytes from `url`
/// with the two-stage size-cap defense. All HTTP-stage failure-point
/// tracing (`send`, `status`, `content_length_cap`, `chunk`,
/// `stream_cap`) lives here.
///
/// Keeping this as an HTTP-only helper lets the production path time
/// network and verification separately. Tests that need the legacy
/// identity-only parser go through the [`fetch_and_parse`] wrapper.
pub(crate) async fn fetch_bundle_bytes(
    http: &ProvenanceHttpClient,
    url: reqwest::Url,
    url_policy: &AttestationUrlPolicy,
) -> Result<Vec<u8>, FetchBundleError> {
    use futures::StreamExt;

    let mut current_url = url;
    let mut redirect_count = 0usize;
    let response = loop {
        let response = http
            .inner
            .get(current_url.clone())
            .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
            .send()
            .await
            .map_err(|e| {
                tracing::debug!(
                    target: "lpm_cli::provenance_fetch",
                    error = %lpm_http::display_error(&e),
                    stage = "send",
                    "attestation fetch send/timeout error",
                );
                FetchBundleError::Transport
            })?;
        if !response.status().is_redirection() {
            break response;
        }
        if redirect_count >= lpm_http::DEFAULT_REDIRECT_LIMIT {
            return Err(FetchBundleError::Policy(
                "attestation URL exceeded the redirect limit".into(),
            ));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| {
                FetchBundleError::Policy(
                    "attestation redirect response has no Location header".into(),
                )
            })?
            .to_str()
            .map_err(|_| {
                FetchBundleError::Policy("attestation redirect Location is not valid text".into())
            })?;
        let next = current_url.join(location).map_err(|error| {
            FetchBundleError::Policy(format!("attestation redirect Location is invalid: {error}"))
        })?;
        current_url = url_policy.validate(next.as_str())?;
        redirect_count += 1;
    };

    if !response.status().is_success() {
        let status = response.status();
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            status = status.as_u16(),
            stage = "status",
            "attestation fetch returned non-2xx",
        );
        return Err(FetchBundleError::Transport);
    }

    // Stage 1: early-reject on oversized declared Content-Length.
    // Cheap — server hasn't sent a body byte past the headers yet;
    // dropping the response here closes the connection without
    // reading any body.
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_BUNDLE_BYTES
    {
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            declared_bytes = declared,
            cap_bytes = MAX_BUNDLE_BYTES,
            stage = "content_length_cap",
            "attestation bundle exceeds declared size cap",
        );
        return Err(FetchBundleError::Transport);
    }

    // Stage 2: streaming bound. Initial capacity is generous enough
    // for a typical real bundle (~10-50 KiB) so we don't spend time
    // growing the Vec for the common case, yet far below the cap so
    // we never over-allocate relative to what we'll actually keep.
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                error = %e,
                buffered_bytes = buf.len(),
                stage = "chunk",
                "attestation body chunk read error",
            );
            FetchBundleError::Transport
        })?;
        // Reject BEFORE copying the chunk into `buf`: the check is
        // `buf.len() + chunk.len()` so even a single oversized chunk
        // can't land in our Vec.
        if buf.len().saturating_add(chunk.len()) > MAX_BUNDLE_BYTES {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                buffered_bytes = buf.len(),
                chunk_bytes = chunk.len(),
                cap_bytes = MAX_BUNDLE_BYTES,
                stage = "stream_cap",
                "attestation bundle exceeded streaming size cap",
            );
            return Err(FetchBundleError::Transport);
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

/// Verify — turn the raw bundle bytes into a `ProvenanceSnapshot`
/// AFTER cryptographic verification under [`verify_sigstore_bundle`].
///
/// Failure semantics:
/// - `Ok(evidence)` — bundle verified end-to-end (chain + DSSE +
///   SCT + Rekor body + SET; inclusion proof per policy). The
///   raw bundle is safe to cache for later re-verification, and the
///   returned evidence is safe to record in the lockfile.
/// - `Err(LpmError::ProvenanceVerification(...))` — bundle bytes
///   were structurally present but verification rejected them.
///   The caller MUST surface this as a hard error (NOT degrade to
///   `Ok(None)`). A registry serving signed-but-invalid provenance is
///   an attack signal that the operator deserves to see directly.
///
/// `url` is forwarded only for the outer "verify failed" debug log
/// so the trace stream's "which package failed how" pair stays
/// adjacent.
pub(crate) fn verify_bundle_or_err(
    body: &[u8],
    url: &str,
    expectation: &NpmArtifactExpectation,
) -> Result<VerifiedNpmProvenance, LpmError> {
    use crate::sigstore_verify::{
        IdentityExpectations, VerifyOptions, extract_npm_subject_sha512, verify_sigstore_bundle,
    };
    match verify_sigstore_bundle(
        body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    ) {
        Ok(verified) => {
            let (subject_name, subject_sha512) =
                extract_npm_subject_sha512(body).map_err(|error| {
                    LpmError::ProvenanceVerification(format!(
                        "verified bundle has invalid npm subject: {error}"
                    ))
                })?;
            if subject_name != expectation.subject_name {
                return Err(LpmError::ProvenanceVerification(format!(
                    "attestation subject {subject_name:?} does not match package {:?}",
                    expectation.subject_name
                )));
            }
            if subject_sha512 != expectation.subject_sha512 {
                return Err(LpmError::ProvenanceVerification(format!(
                    "attestation subject digest does not match the package tarball for {}",
                    expectation.subject_name
                )));
            }
            let integrated_time_secs = verified
                .integrated_time
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    LpmError::ProvenanceVerification(format!(
                        "attestation integrated time predates the Unix epoch: {error}"
                    ))
                })?
                .as_secs();
            let bundle_sha256 = verified_provenance_digest(
                &verified.snapshot,
                &subject_name,
                &subject_sha512,
                integrated_time_secs,
                &verified.log_id,
                verified.log_index,
            );
            Ok(VerifiedNpmProvenance {
                snapshot: verified.snapshot,
                subject_name,
                subject_sha512,
                integrated_time_secs,
                log_id: verified.log_id,
                log_index: verified.log_index,
                bundle_sha256,
            })
        }
        Err(verify_err) => {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                url = %url,
                body_bytes = body.len(),
                error = %verify_err,
                stage = "verify",
                "attestation bundle verification rejected",
            );
            Err(LpmError::ProvenanceVerification(format!("{verify_err}")))
        }
    }
}

/// Pre-fused wrapper around the legacy identity-only parser. Used
/// by the wire-shape regression tests below and by the skip-list
/// path in [`fetch_unverified_snapshot`] — production verification
/// still routes through [`fetch_bundle_bytes`] +
/// [`verify_bundle_or_err`] so HTTP and verification can be timed
/// independently.
#[cfg(test)]
async fn fetch_and_parse(
    http: &ProvenanceHttpClient,
    registry_url: &str,
    url: &str,
) -> Result<ProvenanceSnapshot, FetchBundleError> {
    let policy = AttestationUrlPolicy::for_registry(registry_url)
        .map_err(|error| FetchBundleError::Policy(error.to_string()))?;
    let validated_url = policy.validate(url)?;
    let buf = fetch_bundle_bytes(http, validated_url, &policy).await?;
    parse_sigstore_bundle(&buf)
        .map_err(|()| FetchBundleError::Policy("attestation bundle failed to parse".into()))
}

/// Legacy identity-only Sigstore-bundle parser. The production
/// verify path goes through `verify_sigstore_bundle` via
/// [`verify_bundle_or_err`]; this parser remains the live helper
/// for the `--unverified-provenance[-all]` opt-out path, where a
/// skip-listed package needs the SAN identity (so the drift gate
/// can still compare publisher / workflow_path) but explicitly
/// bypasses the cryptographic checks. The result lands on the
/// binding as `ProvenanceStatus::Unverified` — distinct from
/// `Verified` so the audit trail records the operator's downgrade.
///
/// Errors degrade to `Err(())` and the batch caller maps to
/// `TransportDegraded` — even on the skip path, a malformed bundle
/// is "we couldn't observe the identity at all," which is closer to
/// "transport degraded" than to "operator chose to ignore crypto on
/// a structurally-valid identity."
pub(crate) fn parse_sigstore_bundle(body: &[u8]) -> Result<ProvenanceSnapshot, ()> {
    let bundle: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            error = %e,
            body_bytes = body.len(),
            stage = "json_parse",
            "attestation bundle JSON parse failed",
        );
    })?;

    // The Sigstore bundle shape puts the cert chain at
    // `verificationMaterial.x509CertificateChain.certificates[0].rawBytes`
    // (base64-encoded DER). Some bundles (multi-subject responses,
    // e.g., npm's `{ attestations: [...] }` list) wrap the bundle one
    // level deeper; try both shapes.
    let cert_b64 = find_leaf_cert_rawbytes(&bundle).ok_or(()).map_err(|()| {
        // Capture the bundle's top-level keys so a shape drift (e.g.,
        // npm switches to `dsseEnvelope`-only or wraps under a new
        // root) is diagnosable from the log without reproducing the
        // request. Top-level keys aren't sensitive — the cert and
        // signatures sit one or two levels deeper.
        let top_keys: Vec<&str> = bundle
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            stage = "cert_lookup",
            top_level_keys = ?top_keys,
            body_bytes = body.len(),
            "attestation bundle missing leaf cert rawBytes — shape drift?",
        );
    })?;

    let der = BASE64.decode(&cert_b64).map_err(|e| {
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            error = %e,
            cert_b64_len = cert_b64.len(),
            stage = "base64_decode",
            "attestation leaf cert base64 decode failed",
        );
    })?;
    let cert_sha = {
        let mut hasher = Sha256::new();
        hasher.update(&der);
        format!("sha256-{}", hex::encode(hasher.finalize()))
    };

    let identity = extract_san_identity(&der);

    Ok(ProvenanceSnapshot {
        present: true,
        publisher: identity.as_ref().map(|i| i.publisher.clone()),
        workflow_path: identity.as_ref().map(|i| i.workflow_path.clone()),
        workflow_ref: identity.as_ref().map(|i| i.workflow_ref.clone()),
        attestation_cert_sha256: Some(cert_sha),
    })
}

/// Walk a Sigstore bundle JSON looking for the leaf cert's
/// `rawBytes`. Handles three shapes:
///
/// 1. **Sigstore Bundle v0.1 / v0.2** — chain shape:
///    `verificationMaterial.x509CertificateChain.certificates[0].rawBytes`.
///    The original protobuf-specs layout. Still produced by some
///    older signers; the original parser only knew this one.
/// 2. **Sigstore Bundle v0.3** — single-cert shape:
///    `verificationMaterial.certificate.rawBytes`. v0.3 collapsed
///    the cert chain into one leaf field because in practice the
///    chain only ever held one cert. **This is what npm's
///    attestations endpoint serves today** for every Fulcio-issued
///    GitHub Actions provenance attestation, and the absence of
///    this branch in the original parser is what caused the "warm install never caches ~18 packages" bug
///    — every attested URL parsed past the cert-lookup stage and
///    degraded to `Ok(None)`, which is never written to disk.
/// 3. **npm attestations-list wrapper** —
///    `{ attestations: [{ bundle: { <any of the shapes above> } }] }`.
///    npm currently serves TWO attestations per package: the
///    publish-time attestation signed with npm's own keypair (which
///    carries `verificationMaterial.publicKey` and NO leaf cert —
///    that's normal for non-Fulcio attestations), followed by the
///    Fulcio-issued GitHub Actions provenance. The recursive call
///    walks the list in order; the publicKey-only entry returns
///    None and the loop falls through to the cert-bearing entry.
fn find_leaf_cert_rawbytes(v: &serde_json::Value) -> Option<String> {
    // Shape 1: legacy chain.
    if let Some(raw) = v
        .get("verificationMaterial")
        .and_then(|m| m.get("x509CertificateChain"))
        .and_then(|c| c.get("certificates"))
        .and_then(|arr| arr.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("rawBytes"))
        .and_then(|r| r.as_str())
    {
        return Some(raw.to_string());
    }

    // Shape 2: v0.3 single-cert. Checked BEFORE the wrapper recursion
    // so a directly-passed v0.3 bundle (test fixtures, future callers
    // that pass an inner bundle without the npm list wrapper) hits the
    // cheap path without falling through to a list-walk.
    if let Some(raw) = v
        .get("verificationMaterial")
        .and_then(|m| m.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|r| r.as_str())
    {
        return Some(raw.to_string());
    }

    // Shape 3: npm wrapper. Recurse so the inner bundle hits Shape 1
    // or Shape 2 above. Skips publicKey-only entries automatically:
    // those have neither `x509CertificateChain` nor `certificate`, so
    // the recursive call returns None and the loop continues.
    if let Some(list) = v.get("attestations").and_then(|a| a.as_array()) {
        for att in list {
            if let Some(bundle) = att.get("bundle")
                && let Some(raw) = find_leaf_cert_rawbytes(bundle)
            {
                return Some(raw);
            }
        }
    }

    None
}

/// Parsed GitHub Actions OIDC identity from a cert SAN URI.
///
/// The SAN URI carries a single composite `<path>@<ref>` workflow
/// string; we split it at construction so the drift-check comparator
/// (in `lpm-security::provenance`) can compare `workflow_path`
/// cross-release while keeping `workflow_ref` as audit-only data.
/// Motivation: without the split, a legitimate v1.14.0 → v1.14.1
/// release (same repo, same workflow file, necessarily different ref)
/// would register as "identity changed" and block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SanIdentity {
    /// `github:<org>/<repo>` — stable across releases. Part of the
    /// drift-check identity tuple.
    publisher: String,
    /// Workflow PATH — `.github/workflows/<file>`. Stable across
    /// releases from the same workflow. Part of the drift-check
    /// identity tuple.
    workflow_path: String,
    /// Workflow REF — `refs/tags/<tag>`, `refs/heads/<branch>`, etc.
    /// Varies per release. Audit-only, NOT part of the identity
    /// tuple.
    workflow_ref: String,
}

/// Extract the GitHub Actions OIDC identity from a DER-encoded x509
/// certificate's Subject Alternative Name extension.
///
/// GitHub's Fulcio leaf certs include a URI SAN of the shape
/// `https://github.com/<org>/<repo>/.github/workflows/<workflow>@<ref>`.
/// Any other SAN shape (non-GitHub, malformed, no URI SAN at all)
/// returns `None` — the drift check then sees a present-but-unknown
/// snapshot, which is a distinct signal from `present: false`.
///
/// Returns `None` on parse failure rather than `Err` because the
/// calling path has already decided to materialize a snapshot —
/// degraded identity fields still support the drift check's "both
/// sides unknown" branch.
fn extract_san_identity(der: &[u8]) -> Option<SanIdentity> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name
                    && let Some(identity) = parse_github_actions_uri(uri)
                {
                    return Some(identity);
                }
            }
        }
    }
    None
}

/// Parse a GitHub Actions OIDC URI into its `(publisher,
/// workflow_path, workflow_ref)` parts. Returns `None` on any shape
/// mismatch so the caller can decide whether to fall back to a
/// less-specific signal.
///
/// Expected shape:
/// `https://github.com/<org>/<repo>/.github/workflows/<workflow-path>@<ref>`
///
/// - `publisher` → `github:<org>/<repo>` (stable across releases).
/// - `workflow_path` → `.github/workflows/<workflow-path>` (stable
///   across releases from the same workflow).
/// - `workflow_ref` → `<ref>` (e.g. `refs/tags/v1.14.0`, varies per
///   release).
///
/// Non-GitHub hosts, missing `.github/workflows/` segment, or missing
/// `@<ref>` suffix all yield `None`.
///
/// The split at the LAST `@` defends against a hypothetical ref that
/// itself contains `@` — extremely unlikely in practice (GitHub refs
/// don't use `@`), but `rsplit_once` is the correct primitive either
/// way since every legitimate GitHub Actions SAN URI has its ref
/// delimiter as the rightmost `@`.
fn parse_github_actions_uri(uri: &str) -> Option<SanIdentity> {
    const PREFIX: &str = "https://github.com/";
    const WORKFLOWS_SEG: &str = "/.github/workflows/";

    let after_host = uri.strip_prefix(PREFIX)?;
    let (repo_part, workflow_part) = after_host.split_once(WORKFLOWS_SEG)?;

    // `repo_part` must be `<org>/<repo>` — exactly one `/`, non-empty
    // on both sides.
    let (org, repo) = repo_part.split_once('/')?;
    if org.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }

    // Workflow part must carry the `@<ref>` suffix for a Fulcio-issued
    // workflow cert. A bare workflow path with no ref is not a valid
    // GitHub Actions OIDC identity.
    let (workflow_path_tail, workflow_ref) = workflow_part.rsplit_once('@')?;
    if workflow_path_tail.is_empty() || workflow_ref.is_empty() {
        return None;
    }

    // Materialize the FULL workflow path as stored on disk: prepend
    // the `.github/workflows/` segment so `workflow_path` is
    // self-describing (`publish.yml` alone could refer to anything;
    // `.github/workflows/publish.yml` is unambiguous and matches the
    // stored snapshot contract).
    let workflow_path = format!(".github/workflows/{workflow_path_tail}");

    Some(SanIdentity {
        publisher: format!("github:{org}/{repo}"),
        workflow_path,
        workflow_ref: workflow_ref.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance_fetch::{ProvenanceFetchRequest, fetch_provenance_snapshot};
    use lpm_registry::AttestationRef;
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    // ── parse_github_actions_uri ─────────────────────────────────

    #[test]
    fn parse_uri_happy_path() {
        let uri = "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0";
        let parsed = parse_github_actions_uri(uri).unwrap();
        assert_eq!(parsed.publisher, "github:axios/axios");
        assert_eq!(parsed.workflow_path, ".github/workflows/publish.yml");
        assert_eq!(parsed.workflow_ref, "refs/tags/v1.14.0");
    }

    #[test]
    fn parse_uri_handles_nested_workflow_path() {
        // Workflow file can live in a subdirectory.
        let uri = "https://github.com/sigstore/sigstore-js/.github/workflows/ci/publish.yml@refs/heads/main";
        let parsed = parse_github_actions_uri(uri).unwrap();
        assert_eq!(parsed.publisher, "github:sigstore/sigstore-js");
        assert_eq!(parsed.workflow_path, ".github/workflows/ci/publish.yml");
        assert_eq!(parsed.workflow_ref, "refs/heads/main");
    }

    /// Two legitimate releases from the same repo + workflow differ
    /// only in the ref portion of the SAN URI. The parser must produce
    /// the same `workflow_path` for both so the drift comparator's
    /// identity tuple treats them as non-drifting.
    #[test]
    fn parse_uri_release_bump_changes_ref_but_not_path() {
        let v1 = parse_github_actions_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0",
        )
        .unwrap();
        let v2 = parse_github_actions_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.1",
        )
        .unwrap();
        assert_eq!(v1.publisher, v2.publisher);
        assert_eq!(
            v1.workflow_path, v2.workflow_path,
            "same repo + same workflow file MUST produce the same workflow_path across releases",
        );
        assert_ne!(
            v1.workflow_ref, v2.workflow_ref,
            "different release tags MUST produce different workflow_ref",
        );
    }

    #[test]
    fn parse_uri_rejects_non_github_host() {
        assert!(
            parse_github_actions_uri(
                "https://gitlab.com/foo/bar/.github/workflows/publish.yml@refs/tags/v1"
            )
            .is_none()
        );
    }

    #[test]
    fn parse_uri_rejects_missing_workflows_segment() {
        assert!(parse_github_actions_uri("https://github.com/foo/bar/publish.yml@v1").is_none());
    }

    #[test]
    fn parse_uri_rejects_missing_ref_suffix() {
        // No `@<ref>` — not a Fulcio workflow cert.
        assert!(
            parse_github_actions_uri("https://github.com/foo/bar/.github/workflows/publish.yml")
                .is_none()
        );
    }

    #[test]
    fn parse_uri_rejects_missing_repo() {
        // org with no `/repo` segment.
        assert!(
            parse_github_actions_uri("https://github.com/foo/.github/workflows/publish.yml@v1")
                .is_none()
        );
    }

    #[test]
    fn parse_uri_rejects_extra_path_before_workflows() {
        // `<org>/<repo>` must be exactly two segments — no org/group/repo.
        assert!(
            parse_github_actions_uri(
                "https://github.com/org/group/repo/.github/workflows/publish.yml@v1"
            )
            .is_none()
        );
    }

    // ── extract_san_identity (via rcgen-generated certs) ─────────

    fn cert_der_with_san_uri(uri: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    fn cert_der_with_no_san() -> Vec<u8> {
        let params = CertificateParams::default();
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extract_identity_from_github_actions_cert() {
        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0",
        );
        let identity = extract_san_identity(&der).unwrap();
        assert_eq!(identity.publisher, "github:axios/axios");
        assert_eq!(identity.workflow_path, ".github/workflows/publish.yml");
        assert_eq!(identity.workflow_ref, "refs/tags/v1.14.0");
    }

    #[test]
    fn extract_identity_returns_none_for_non_github_san() {
        let der = cert_der_with_san_uri("https://gitlab.com/foo/bar");
        assert!(extract_san_identity(&der).is_none());
    }

    #[test]
    fn extract_identity_returns_none_for_cert_with_no_san() {
        let der = cert_der_with_no_san();
        assert!(extract_san_identity(&der).is_none());
    }

    #[test]
    fn extract_identity_returns_none_for_garbage_bytes() {
        let garbage = vec![0u8; 32];
        assert!(extract_san_identity(&garbage).is_none());
    }

    // ── parse_sigstore_bundle ────────────────────────────────────

    fn sigstore_bundle_with_cert(der: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [
                        { "rawBytes": BASE64.encode(der) }
                    ]
                }
            }
        })
    }

    fn npm_attestations_list_with_cert(der: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "attestations": [
                { "bundle": sigstore_bundle_with_cert(der) }
            ]
        })
    }

    /// **Sigstore Bundle v0.3 fixture** — the single-cert shape that
    /// npm's attestations endpoint serves today for every Fulcio-issued
    /// GitHub Actions provenance attestation. See `find_leaf_cert_rawbytes`
    /// for the full shape rationale.
    fn sigstore_bundle_v3_with_cert(der: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": { "rawBytes": BASE64.encode(der) }
            }
        })
    }

    /// **npm publish-attestation fixture** — mediaType v0.2 with a
    /// `publicKey` reference and NO leaf cert. npm signs this entry
    /// with its own keypair, so there is nothing for the drift-check
    /// to walk into. `find_leaf_cert_rawbytes` must skip this entry
    /// without erroring and continue to the next list item.
    fn sigstore_bundle_publickey_only() -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {
                "publicKey": { "hint": "npm-publisher-keypair" }
            }
        })
    }

    /// **Real-world npm wrapper** — the actual two-element shape served
    /// by `https://registry.npmjs.org/-/npm/v1/attestations/<pkg>` for
    /// any GitHub-Actions-published, attested package. First element
    /// is the npm publish attestation (publicKey-only); second is the
    /// Fulcio-issued GitHub Actions provenance (v0.3 single-cert). Our
    /// parser must walk past the first and pick up the second.
    fn npm_attestations_real_world_shape(der: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "attestations": [
                { "bundle": sigstore_bundle_publickey_only() },
                { "bundle": sigstore_bundle_v3_with_cert(der) }
            ]
        })
    }

    #[test]
    fn parse_bundle_standard_shape_extracts_identity_and_cert_sha() {
        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0",
        );
        let bundle = sigstore_bundle_with_cert(&der);
        let snap = parse_sigstore_bundle(bundle.to_string().as_bytes()).unwrap();

        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
        assert_eq!(
            snap.workflow_path.as_deref(),
            Some(".github/workflows/publish.yml"),
        );
        assert_eq!(snap.workflow_ref.as_deref(), Some("refs/tags/v1.14.0"));

        // Cert SHA must match what an independent hash of the same
        // DER bytes produces — any divergence would indicate the
        // parser is hashing a mis-decoded body.
        let expected_sha = format!("sha256-{}", hex::encode(Sha256::digest(&der)));
        assert_eq!(
            snap.attestation_cert_sha256.as_deref(),
            Some(expected_sha.as_str())
        );
    }

    #[test]
    fn parse_bundle_npm_attestations_list_wrapper_also_works() {
        let der = cert_der_with_san_uri(
            "https://github.com/sigstore/sigstore-js/.github/workflows/publish.yml@refs/tags/v2.0.0",
        );
        let wrapper = npm_attestations_list_with_cert(&der);
        let snap = parse_sigstore_bundle(wrapper.to_string().as_bytes()).unwrap();

        assert!(snap.present);
        assert_eq!(
            snap.publisher.as_deref(),
            Some("github:sigstore/sigstore-js")
        );
    }

    /// Before this test was added, `parse_sigstore_bundle` would fail
    /// on the v0.3 shape (`verificationMaterial.certificate.rawBytes`)
    /// and degrade to `Err(())`, which the install pipeline maps to
    /// `Ok(None)` — never written to cache, so the same bundle re-
    /// fetches on every install. Empirically this affected ~30 of
    /// 254 packages on the bench/fixture-large fixture, costing
    /// ~4.6 s of `prov_sum_ms` on every warm install.
    ///
    /// This test pins the v0.3 shape so any future refactor of
    /// `find_leaf_cert_rawbytes` that drops the v0.3 branch fails
    /// before it ships.
    #[test]
    fn parse_bundle_v3_single_cert_shape_extracts_identity() {
        let der = cert_der_with_san_uri(
            "https://github.com/iamkun/dayjs/.github/workflows/release.yml@refs/tags/1.11.20",
        );
        let bundle = sigstore_bundle_v3_with_cert(&der);
        let snap = parse_sigstore_bundle(bundle.to_string().as_bytes()).unwrap();

        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:iamkun/dayjs"));
        assert_eq!(
            snap.workflow_path.as_deref(),
            Some(".github/workflows/release.yml"),
        );
        assert_eq!(snap.workflow_ref.as_deref(), Some("refs/tags/1.11.20"));
    }

    /// npm currently serves a 2-element list: index 0 is npm's own
    /// publish attestation (publicKey-only, no Fulcio cert), index 1
    /// is the Fulcio-issued GitHub Actions provenance (v0.3 single-
    /// cert). The parser must walk past the publicKey-only entry and
    /// pick up the cert-bearing one. This test encodes the actual
    /// production shape verified by curling
    /// `registry.npmjs.org/-/npm/v1/attestations/<pkg>` on.
    #[test]
    fn parse_bundle_npm_real_world_skips_publickey_falls_through_to_v3_cert() {
        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.15.2",
        );
        let wrapper = npm_attestations_real_world_shape(&der);
        let snap = parse_sigstore_bundle(wrapper.to_string().as_bytes()).unwrap();

        assert!(
            snap.present,
            "real-world npm shape (v0.2 publicKey + v0.3 cert) must \
             produce a present snapshot",
        );
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
        assert_eq!(
            snap.workflow_path.as_deref(),
            Some(".github/workflows/publish.yml"),
        );
        assert_eq!(snap.workflow_ref.as_deref(), Some("refs/tags/v1.15.2"));

        // Cert SHA must hash the v0.3 leaf, not the npm publicKey
        // entry. If the parser accidentally hashed the publicKey-only
        // entry it would fail base64-decoding earlier, but pinning
        // the SHA defends against a future refactor that swaps
        // attestation order.
        let expected_sha = format!("sha256-{}", hex::encode(Sha256::digest(&der)));
        assert_eq!(
            snap.attestation_cert_sha256.as_deref(),
            Some(expected_sha.as_str())
        );
    }

    /// If npm ever ships only a publish attestation (no GitHub Actions
    /// provenance), the wrapper is a single publicKey-only entry. The
    /// parser must reject this — `present: false` is wrong (a publish
    /// attestation IS present, just not a Fulcio one), and `Err(())`
    /// degrades to `Ok(None)` (transient/unknown) which is the
    /// correct semantic per the module-level fetch-failure docs.
    #[test]
    fn parse_bundle_npm_publickey_only_with_no_cert_yields_err() {
        let wrapper = serde_json::json!({
            "attestations": [
                { "bundle": sigstore_bundle_publickey_only() }
            ]
        });
        assert!(
            parse_sigstore_bundle(wrapper.to_string().as_bytes()).is_err(),
            "npm wrapper containing only a publicKey-only attestation \
             (no Fulcio cert) must return Err so the caller treats it \
             as unknown rather than caching a falsely-absent snapshot",
        );
    }

    /// Defensive: ensure the parser doesn't hash a stale v0.2 chain
    /// entry when a v0.3 single-cert entry sits beside it under the
    /// same `verificationMaterial`. Real bundles never put both, but
    /// the lookup order must be stable: v0.2 chain first (legacy
    /// path), then v0.3 single-cert. A future refactor that flips
    /// the order would change the cert-sha output for any package
    /// that grew a v0.3 entry, breaking the drift-check's content-
    /// addressable identity. Pinning the order here makes that
    /// breakage loud.
    #[test]
    fn find_leaf_cert_rawbytes_prefers_v2_chain_when_both_shapes_coexist() {
        let v2_der = b"v2-chain-leaf-fake-der";
        let v3_der = b"v3-single-cert-fake-der";
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [{ "rawBytes": BASE64.encode(v2_der) }]
                },
                "certificate": { "rawBytes": BASE64.encode(v3_der) }
            }
        });
        let got = find_leaf_cert_rawbytes(&bundle).unwrap();
        assert_eq!(
            got,
            BASE64.encode(v2_der),
            "v0.2 chain must take precedence so existing cache keys \
             stay stable; v0.3 single-cert is the fallback",
        );
    }

    #[test]
    fn parse_bundle_with_cert_but_no_extractable_identity_still_present() {
        // A cert with a non-GitHub SAN still produces a `present:
        // true` snapshot (we fetched + parsed a real bundle) but
        // with `publisher: None` — the drift check's "identity
        // unknown" handling.
        let der = cert_der_with_san_uri("https://example.com/opaque");
        let bundle = sigstore_bundle_with_cert(&der);
        let snap = parse_sigstore_bundle(bundle.to_string().as_bytes()).unwrap();

        assert!(snap.present);
        assert!(snap.publisher.is_none());
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());
        // Cert SHA still computed — it's an identity hash, not
        // identity metadata.
        assert!(snap.attestation_cert_sha256.is_some());
    }

    #[test]
    fn parse_bundle_rejects_malformed_json() {
        assert!(parse_sigstore_bundle(b"not json {[").is_err());
    }

    #[test]
    fn parse_bundle_rejects_missing_cert_chain() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "dsseEnvelope": { "payloadType": "foo" }
        });
        assert!(parse_sigstore_bundle(bundle.to_string().as_bytes()).is_err());
    }

    #[test]
    fn parse_bundle_rejects_non_base64_rawbytes() {
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [ { "rawBytes": "not-valid-base64!!!" } ]
                }
            }
        });
        assert!(parse_sigstore_bundle(bundle.to_string().as_bytes()).is_err());
    }

    // ── Cache round-trip ─────────────────────────────────────────

    const AXIOS_INTEGRITY: &str = "sha512-3Y8yrqLSwjuzpXuZ0oIYZ/XGgLwUIBU3uLvbcpb0pidD9ctpShJd43KSlEEkVQg6DS0G9NKyzOvBfUtDKEyHvQ==";
    const TEST_REGISTRY: &str = "https://registry.example.test";

    fn axios_bundle() -> &'static [u8] {
        include_bytes!("../tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json")
    }

    fn test_registry_source() -> RegistrySourceIdentity {
        AttestationUrlPolicy::for_registry(TEST_REGISTRY)
            .unwrap()
            .registry_source
    }

    fn cache_filename(name: &str, version: &str) -> String {
        super::cache_filename(&test_registry_source(), name, version)
    }

    fn read_cache(
        cache_root: &Path,
        name: &str,
        version: &str,
        expectation: &NpmArtifactExpectation,
    ) -> Result<Option<VerifiedNpmProvenance>, LpmError> {
        super::read_cache(
            cache_root,
            &test_registry_source(),
            name,
            version,
            expectation,
        )
    }

    fn write_cache(
        cache_root: &Path,
        name: &str,
        version: &str,
        bundle: &[u8],
    ) -> Result<(), LpmError> {
        super::write_cache(cache_root, &test_registry_source(), name, version, bundle)
    }

    fn axios_expectation() -> NpmArtifactExpectation {
        NpmArtifactExpectation::from_package("axios", "1.14.0", Some(AXIOS_INTEGRITY)).unwrap()
    }

    #[test]
    fn verified_provenance_digest_is_independent_of_json_serialization() {
        let compact = axios_bundle();
        let parsed: serde_json::Value = serde_json::from_slice(compact).unwrap();
        let pretty = serde_json::to_vec_pretty(&parsed).unwrap();
        assert_ne!(compact, pretty.as_slice());

        let expectation = axios_expectation();
        let compact_evidence =
            verify_bundle_or_err(compact, "compact fixture", &expectation).unwrap();
        let pretty_evidence =
            verify_bundle_or_err(&pretty, "pretty fixture", &expectation).unwrap();

        assert_eq!(compact_evidence, pretty_evidence);
    }

    fn pkg_expectation() -> NpmArtifactExpectation {
        NpmArtifactExpectation::from_package(
            "pkg",
            "1.0.0",
            Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
        )
        .unwrap()
    }

    fn raw_cache_entry(cached_at_secs: u64, bundle: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CACHE_HEADER_BYTES + bundle.len());
        bytes.extend_from_slice(CACHE_MAGIC);
        bytes.extend_from_slice(&cached_at_secs.to_le_bytes());
        bytes.extend_from_slice(bundle);
        bytes
    }

    #[test]
    fn cache_write_read_round_trips_within_ttl() {
        let dir = tempfile::tempdir().unwrap();
        write_cache(dir.path(), "axios", "1.14.0", axios_bundle()).unwrap();

        let got = read_cache(dir.path(), "axios", "1.14.0", &axios_expectation()).unwrap();

        assert_eq!(
            got.expect("fresh authentic bundle must hit").subject_name,
            "pkg:npm/axios@1.14.0"
        );
    }

    #[test]
    fn cache_entry_is_missed_when_expected_tarball_digest_changes() {
        let dir = tempfile::tempdir().unwrap();
        write_cache(dir.path(), "axios", "1.14.0", axios_bundle()).unwrap();
        let expectation = NpmArtifactExpectation::from_package(
            "axios",
            "1.14.0",
            Some("sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="),
        )
        .unwrap();

        let got = read_cache(dir.path(), "axios", "1.14.0", &expectation).unwrap();

        assert_eq!(got, None, "cache binding must include the tarball digest");
    }

    #[test]
    fn cache_rejects_locally_forged_verified_evidence() {
        let dir = tempfile::tempdir().unwrap();
        write_cache(dir.path(), "axios", "1.14.0", axios_bundle()).unwrap();
        let path = dir.path().join(cache_filename("axios", "1.14.0"));
        let mut entry = std::fs::read(&path).unwrap();
        let last = entry
            .last_mut()
            .expect("cache entry contains a Sigstore bundle");
        *last ^= 1;
        std::fs::write(&path, entry).unwrap();

        let got = read_cache(dir.path(), "axios", "1.14.0", &axios_expectation()).unwrap();

        assert_eq!(
            got, None,
            "cache evidence must be reverified rather than trusted as derived data"
        );
    }

    #[test]
    fn cache_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let got = read_cache(dir.path(), "missing", "0.0.0", &pkg_expectation()).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn cache_corrupt_file_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            b"not a provenance cache entry",
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0", &pkg_expectation()).unwrap();
        assert_eq!(got, None, "corrupt cache must degrade to miss, not error");
    }

    /// A local attacker who can write into the cache dir should not be
    /// able to OOM the install by dropping a multi-MiB file at a valid
    /// cache path. `read_cache` checks the file size against
    /// `MAX_CACHE_ENTRY_BYTES` before reading and treats anything over
    /// the cap as a miss.
    #[test]
    fn cache_oversized_file_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let path = dir.path().join(cache_filename("pkg", "1.0.0"));
        let payload = vec![b'a'; 2 * 1024 * 1024];
        std::fs::write(&path, &payload).unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0", &pkg_expectation()).unwrap();
        assert_eq!(
            got, None,
            "oversized cache file must degrade to miss, not OOM the install",
        );
        // File still on disk — the next legitimate write_cache will
        // overwrite it via atomic rename; we don't delete from a read
        // path to avoid concurrency footguns.
        assert!(
            path.exists(),
            "read_cache must not delete the oversized file"
        );
    }

    #[test]
    fn cache_legacy_schema_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let bad = serde_json::json!({
            "version": 3,
            "cached_at_secs": current_epoch_secs(),
            "evidence": {
                "subject_name": "pkg:npm/pkg@1.0.0",
                "subject_sha512": "00"
            },
        });
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            bad.to_string(),
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0", &pkg_expectation()).unwrap();
        assert_eq!(
            got, None,
            "derived-evidence cache entries must be treated as misses",
        );
    }

    #[test]
    fn cache_stale_entry_past_ttl_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            dir.path().join(cache_filename("axios", "1.14.0")),
            raw_cache_entry(
                current_epoch_secs().saturating_sub(CACHE_TTL_SECS + 1),
                axios_bundle(),
            ),
        )
        .unwrap();
        let got = read_cache(dir.path(), "axios", "1.14.0", &axios_expectation()).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn cache_write_creates_parent_directory() {
        // Cache root doesn't exist yet — write_cache must create it.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c/attestations");
        write_cache(&nested, "axios", "1.14.0", axios_bundle()).unwrap();
        assert!(nested.exists());
        let got = read_cache(&nested, "axios", "1.14.0", &axios_expectation()).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn cache_filename_is_deterministic_and_collision_resistant() {
        // Same input → same output.
        let a = cache_filename("@scope/pkg", "1.0.0");
        let b = cache_filename("@scope/pkg", "1.0.0");
        assert_eq!(a, b);

        // Different inputs → different outputs (sanity — SHA256
        // makes collisions astronomically unlikely).
        let c = cache_filename("@scope/pkg", "1.0.1");
        assert_ne!(a, c);

        // Scoped-name disambiguation: `@a/b@1` and `@a/b-1` must
        // hash differently. (We hash `{name}@{version}` so the
        // version separator is part of the input; ambiguity would
        // only arise if a name literally contained `@` at the split
        // boundary — not a thing in npm/LPM.)
        let d = cache_filename("@a/b", "1");
        let e = cache_filename("@a/b-1", "");
        assert_ne!(d, e);

        let other_registry =
            AttestationUrlPolicy::for_registry("https://registry.other.test").unwrap();
        let other = super::cache_filename(other_registry.registry_source(), "@scope/pkg", "1.0.0");
        assert_ne!(a, other);
    }

    #[test]
    fn cache_entry_without_artifact_binding_is_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let stale = serde_json::json!({
            "version": 2u32,
            "cached_at_secs": current_epoch_secs(),
            "snapshot": {
                "present": true,
                "publisher": "github:axios/axios"
            },
        });
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            stale.to_string(),
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0", &pkg_expectation()).unwrap();
        assert_eq!(
            got, None,
            "cache entries verified without artifact binding must be invalidated"
        );
    }

    // ── Body-size enforcement ─────────────────

    /// Valid in-bounds response parses end-to-end. This is the
    /// positive baseline for the body-size tests below — if this
    /// fails, the streaming plumbing itself is broken.
    #[tokio::test]
    async fn fetch_and_parse_accepts_bundle_under_size_cap() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0",
        );
        let bundle_bytes = sigstore_bundle_with_cert(&der).to_string().into_bytes();
        assert!(
            bundle_bytes.len() < MAX_BUNDLE_BYTES,
            "test fixture must fit under the cap for this baseline test"
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle_bytes))
            .mount(&server)
            .await;

        let http = ProvenanceHttpClient::build().unwrap();
        let url = format!("{}/att", server.uri());
        let snap = fetch_and_parse(&http, &server.uri(), &url).await.unwrap();
        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
    }

    /// A response whose body exceeds `MAX_BUNDLE_BYTES` must be
    /// rejected before the full body lands in memory. The streaming
    /// cap rejects during accumulation, so even a 10 MiB body never
    /// lives in our process heap.
    ///
    /// wiremock by default sends a truthful `Content-Length`, so
    /// this case exercises the stage-1 pre-stream check. A
    /// chunked-transfer variant would hit stage 2; both stages
    /// reject with the same transport error, so a single test
    /// covers the user-visible contract.
    #[tokio::test]
    async fn fetch_and_parse_rejects_oversized_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 2 MiB of ASCII — well over the 1 MiB cap.
        let oversized = vec![b'a'; 2 * 1024 * 1024];
        assert!(oversized.len() > MAX_BUNDLE_BYTES);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let http = ProvenanceHttpClient::build().unwrap();
        let url = format!("{}/att", server.uri());
        let result = fetch_and_parse(&http, &server.uri(), &url).await;
        assert!(
            result.is_err(),
            "oversized body (2 MiB > 1 MiB cap) must be rejected"
        );
    }

    /// Public-API flavor of the same regression guard: proves the
    /// body-size rejection propagates through `fetch_provenance_snapshot`
    /// as `Ok(None)` (degraded) rather than `Err`, AND that the
    /// oversized response is NOT cached (same "don't poison future
    /// installs" contract as the network-failure case).
    #[tokio::test]
    async fn fetch_returns_none_on_oversized_body_and_does_not_cache() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let oversized = vec![b'a'; 2 * 1024 * 1024];
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let cache = tempfile::tempdir().unwrap();
        let http = ProvenanceHttpClient::build().unwrap();
        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let result = fetch_provenance_snapshot(
            &http,
            cache.path(),
            ProvenanceFetchRequest::new(
                &server.uri(),
                "pkg",
                "1.0.0",
                Some("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
                Some(&att),
            ),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            result, None,
            "oversized body must degrade to unknown (Ok(None))"
        );
        assert!(
            !cache.path().join(cache_filename("pkg", "1.0.0")).exists(),
            "oversized-body rejection must not write a poisoned cache entry"
        );
    }

    /// Stage-1 specificity: a response that DECLARES an oversized
    /// `Content-Length` is rejected even without the server actually
    /// emitting a body. Proves the pre-stream check fires on the
    /// header alone — we drop the response before reading any body
    /// byte.
    ///
    /// Bind a raw TCP socket, write an HTTP/1.1 response with headers
    /// declaring a huge `Content-Length`, then close the connection.
    /// The stage-1 check rejects on the declared header value and drops
    /// the response without ever attempting to read a body byte. The
    /// single-shot accept loop exits after handling one connection.
    #[tokio::test]
    async fn fetch_and_parse_rejects_declared_oversized_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let declared = MAX_BUNDLE_BYTES + 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Single-shot responder: accept one connection, send headers
        // claiming an oversized body, close. We never send a body —
        // the client's stage-1 check bails before reading one.
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Consume the request preamble so the client sees a
                // well-formed turn-taking exchange; we don't parse it.
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Connection: close\r\n\
                     \r\n",
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        let http = ProvenanceHttpClient::build().unwrap();
        let url = format!("http://{addr}/");
        let registry_url = format!("http://{addr}");
        let result = fetch_and_parse(&http, &registry_url, &url).await;
        assert!(
            result.is_err(),
            "declared Content-Length > cap must reject pre-stream",
        );
    }
}
