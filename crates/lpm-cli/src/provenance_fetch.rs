//! Phase 46 P4 Chunk 2 — Sigstore attestation fetch + cache + cert
//! SAN extraction for the CLI's provenance-drift check (§7.1).
//!
//! Pipeline:
//!
//! 1. Caller resolves an `Option<AttestationRef>` from the registry
//!    metadata response. `None` (or `url = None`) means the registry
//!    explicitly did not ship a Sigstore attestation for this
//!    version — this is the axios-case signal when compared against
//!    an approved version that DID have one.
//! 2. [`fetch_provenance_snapshot`] checks the on-disk cache under
//!    `~/.lpm/cache/metadata/attestations/` (7-day TTL). Cache hits
//!    skip the network round-trip.
//! 3. On cache miss, we GET the attestation URL, parse the Sigstore
//!    bundle JSON, extract the leaf certificate (base64 DER), parse
//!    its SAN extension for the GitHub Actions OIDC URI, and return
//!    a populated [`ProvenanceSnapshot`].
//!
//! **Fetch-failure semantics** (plan §11 P4):
//! - `Ok(Some(snapshot))` — a definitive answer (either
//!   `present: true` with identity extracted, or `present: false`
//!   meaning the registry has no attestation for this version).
//! - `Ok(None)` — **degraded / unknown** (network error, malformed
//!   bundle, etc.). The Chunk 3 drift rule interprets this as
//!   "pass, don't drift" per the plan's offline/degrade guarantee.
//!   Never cached, so the next install retries.
//! - `Err(_)` — reserved for genuinely fatal conditions (cache
//!   directory unwritable, I/O errors the caller must surface).
//!
//! **Scope (plan D5):** identity extraction only. No Sigstore
//! signature verification, no Fulcio trust-root checks. Phase 46.1
//! lands full cryptographic verification.
//!
//! **Chunk 2 boundary:** the tests below exercise every item in this
//! module, but the install-time call site is introduced in Chunk 3
//! alongside the drift comparator and install-gate wiring. Until
//! that lands, the binary target treats the module as dead code —
//! the module-level `#![allow(dead_code)]` is a temporary scaffold
//! that comes off atomically when Chunk 3 calls
//! `fetch_provenance_snapshot` from `install.rs`.

#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::LpmError;
use lpm_registry::AttestationRef;
use lpm_workspace::ProvenanceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 7-day TTL per the Phase 46 plan (§11 P4).
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Schema version for the on-disk cache entries. Bump if the parsed
/// `ProvenanceSnapshot` shape changes OR the SAN extractor's
/// behaviour changes in a way that invalidates prior captures. Entries
/// with a mismatched version are treated as misses (re-fetch).
const CACHE_SCHEMA_VERSION: u32 = 1;

/// Max attestation-bundle response size we'll read. Defends against
/// a hostile / broken registry serving an unbounded body that would
/// OOM the process. 1 MiB is several orders of magnitude above any
/// real Sigstore bundle.
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// HTTP fetch timeout for attestation bundle requests. Kept short
/// because this is an install-path blocker — a slow registry should
/// degrade to "unknown" quickly rather than stall the install.
const FETCH_TIMEOUT_SECS: u64 = 15;

// ── Public API ──────────────────────────────────────────────────

/// Fetch (or read from cache) the `ProvenanceSnapshot` for one
/// package version.
///
/// See module docs for the return-value semantics. Never writes a
/// `None` result to cache — those are always transient and the next
/// install should retry.
pub async fn fetch_provenance_snapshot(
    http: &reqwest::Client,
    cache_root: &Path,
    name: &str,
    version: &str,
    attestation_ref: Option<&AttestationRef>,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    // Registry said "no attestation for this version" — that is the
    // axios signal. Return a definitive `present: false` snapshot.
    // We still cache it so repeated installs of the same absent
    // package don't re-examine the registry metadata endlessly (the
    // metadata itself is cached by the resolver, but this makes the
    // absence signal an O(1) disk read for the drift check).
    let url = match attestation_ref.and_then(|a| a.url.as_deref()) {
        Some(u) => u,
        None => {
            let absent = ProvenanceSnapshot {
                present: false,
                publisher: None,
                workflow: None,
                attestation_cert_sha256: None,
            };
            let _ = write_cache(cache_root, name, version, &absent);
            return Ok(Some(absent));
        }
    };

    // Cache hit + fresh → skip the network round-trip.
    if let Some(cached) = read_cache(cache_root, name, version)? {
        return Ok(Some(cached));
    }

    // Cache miss → fetch. Any error from here down degrades to
    // `Ok(None)` and is NOT cached — the next install retries.
    let Ok(snapshot) = fetch_and_parse(http, url).await else {
        return Ok(None);
    };

    // Successful parse — cache it and return. Cache-write failures
    // are logged but not propagated: the snapshot is already
    // computed and usable; future invalidation is at worst one
    // extra fetch.
    if let Err(e) = write_cache(cache_root, name, version, &snapshot) {
        tracing::warn!(
            "provenance cache write failed for {name}@{version}: {e}; \
             continuing with fresh snapshot"
        );
    }
    Ok(Some(snapshot))
}

// ── Cache primitives ────────────────────────────────────────────

/// Cache entry schema on disk.
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    /// Schema version — mismatches are treated as misses.
    version: u32,
    /// Unix timestamp (secs) when the entry was written.
    cached_at_secs: u64,
    /// The extracted provenance snapshot.
    snapshot: ProvenanceSnapshot,
}

/// Compute the on-disk cache filename for one `name@version`.
///
/// Strategy: SHA-256 of the canonical `name@version` string, hex-
/// encoded. Deterministic, filesystem-safe (no `@` or `/` issues on
/// Windows or case-insensitive volumes), collision-resistant, and
/// keeps the cache dir a single flat directory — no per-scope
/// sub-tree walking. The full `name@version` is recorded inside the
/// cache entry's `snapshot` doc comment so a human debugging a bad
/// cache entry can cross-reference by content if needed.
fn cache_filename(name: &str, version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"@");
    hasher.update(version.as_bytes());
    format!("{}.json", hex::encode(hasher.finalize()))
}

fn cache_path(cache_root: &Path, name: &str, version: &str) -> PathBuf {
    cache_root.join(cache_filename(name, version))
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read a cache entry if it exists AND is fresh AND has the expected
/// schema version. Returns `Ok(None)` for every other condition
/// (stale, corrupt, missing, version mismatch). Returns `Err` only
/// for genuine I/O failures the caller would want to surface.
///
/// We deliberately swallow corrupt-file errors (bad JSON, wrong
/// schema) as misses rather than failing the install — a single bad
/// cache entry should not block a build, and the next write overwrites
/// it.
fn read_cache(
    cache_root: &Path,
    name: &str,
    version: &str,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    let path = cache_path(cache_root, name, version);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(LpmError::Io(e)),
    };

    let entry: CacheEntry = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(_) => return Ok(None), // corrupt file → treat as miss
    };

    if entry.version != CACHE_SCHEMA_VERSION {
        return Ok(None); // schema drift → re-fetch
    }
    if current_epoch_secs().saturating_sub(entry.cached_at_secs) >= CACHE_TTL_SECS {
        return Ok(None); // stale → re-fetch
    }

    Ok(Some(entry.snapshot))
}

/// Write a cache entry atomically: serialize to a temp file in the
/// same directory, then `rename`. Creates the cache directory if
/// absent.
fn write_cache(
    cache_root: &Path,
    name: &str,
    version: &str,
    snapshot: &ProvenanceSnapshot,
) -> Result<(), LpmError> {
    std::fs::create_dir_all(cache_root).map_err(LpmError::Io)?;

    let entry = CacheEntry {
        version: CACHE_SCHEMA_VERSION,
        cached_at_secs: current_epoch_secs(),
        snapshot: snapshot.clone(),
    };
    let bytes = serde_json::to_vec(&entry)
        .map_err(|e| LpmError::Registry(format!("failed to serialize provenance cache: {e}")))?;

    let path = cache_path(cache_root, name, version);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, &path).map_err(LpmError::Io)?;
    Ok(())
}

// ── Fetch + parse ───────────────────────────────────────────────

/// Fetch the Sigstore attestation bundle from `url`, parse out the
/// leaf cert, extract its SAN identity, and compute the cert's
/// SHA-256.
///
/// Any error from any stage degrades to `Err(())` — the caller maps
/// that to `Ok(None)` (unknown) so the install proceeds without
/// falsely claiming drift.
async fn fetch_and_parse(http: &reqwest::Client, url: &str) -> Result<ProvenanceSnapshot, ()> {
    let response = http
        .get(url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|_| ())?;

    if !response.status().is_success() {
        return Err(());
    }

    // Bound the body size — a hostile registry should not be able to
    // make the CLI consume unbounded memory on a metadata fetch.
    let bytes = response.bytes().await.map_err(|_| ())?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(());
    }

    parse_sigstore_bundle(&bytes)
}

/// Parse a Sigstore bundle JSON and extract the leaf cert + its SAN
/// identity. Exposed for unit tests; the production path goes
/// through [`fetch_and_parse`].
fn parse_sigstore_bundle(body: &[u8]) -> Result<ProvenanceSnapshot, ()> {
    let bundle: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;

    // The Sigstore bundle shape puts the cert chain at
    // `verificationMaterial.x509CertificateChain.certificates[0].rawBytes`
    // (base64-encoded DER). Some bundles (multi-subject responses,
    // e.g., npm's `{ attestations: [...] }` list) wrap the bundle one
    // level deeper; try both shapes.
    let cert_b64 = find_leaf_cert_rawbytes(&bundle).ok_or(())?;

    let der = BASE64.decode(&cert_b64).map_err(|_| ())?;
    let cert_sha = {
        let mut hasher = Sha256::new();
        hasher.update(&der);
        format!("sha256-{}", hex::encode(hasher.finalize()))
    };

    let identity = extract_san_identity(&der);

    Ok(ProvenanceSnapshot {
        present: true,
        publisher: identity.as_ref().map(|i| i.publisher.clone()),
        workflow: identity.as_ref().map(|i| i.workflow.clone()),
        attestation_cert_sha256: Some(cert_sha),
    })
}

/// Walk a Sigstore bundle JSON looking for the leaf cert's
/// `rawBytes`. Handles both the standard bundle shape and npm's
/// attestations-list wrapper.
fn find_leaf_cert_rawbytes(v: &serde_json::Value) -> Option<String> {
    // Standard bundle:
    //   { verificationMaterial: { x509CertificateChain: { certificates: [{ rawBytes: ... }] } } }
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

    // npm attestations-list wrapper:
    //   { attestations: [{ bundle: { <standard bundle shape> } }] }
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct SanIdentity {
    /// `github:<org>/<repo>` — the publisher key used by the drift
    /// rule's equality check.
    publisher: String,
    /// `<workflow-path>@<ref>` — the exact workflow file + ref that
    /// produced this attestation.
    workflow: String,
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

/// Parse a GitHub Actions OIDC URI into its `(publisher, workflow)`
/// parts. Returns `None` on any shape mismatch so the caller can
/// decide whether to fall back to a less-specific signal.
///
/// Expected shape:
/// `https://github.com/<org>/<repo>/.github/workflows/<workflow-path>@<ref>`
///
/// - `publisher` → `github:<org>/<repo>`
/// - `workflow` → `<workflow-path>@<ref>`
///
/// Non-GitHub hosts, missing `.github/workflows/` segment, or missing
/// `@<ref>` suffix all yield `None`.
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
    if !workflow_part.contains('@') {
        return None;
    }

    Some(SanIdentity {
        publisher: format!("github:{org}/{repo}"),
        workflow: workflow_part.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    // ── parse_github_actions_uri ─────────────────────────────────

    #[test]
    fn parse_uri_happy_path() {
        let uri = "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.0";
        let parsed = parse_github_actions_uri(uri).unwrap();
        assert_eq!(parsed.publisher, "github:axios/axios");
        assert_eq!(parsed.workflow, "publish.yml@refs/tags/v1.14.0");
    }

    #[test]
    fn parse_uri_handles_nested_workflow_path() {
        // Workflow file can live in a subdirectory.
        let uri = "https://github.com/sigstore/sigstore-js/.github/workflows/ci/publish.yml@refs/heads/main";
        let parsed = parse_github_actions_uri(uri).unwrap();
        assert_eq!(parsed.publisher, "github:sigstore/sigstore-js");
        assert_eq!(parsed.workflow, "ci/publish.yml@refs/heads/main");
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
        assert_eq!(identity.workflow, "publish.yml@refs/tags/v1.14.0");
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
            snap.workflow.as_deref(),
            Some("publish.yml@refs/tags/v1.14.0")
        );

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
        assert!(snap.workflow.is_none());
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

    fn fresh_snapshot() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow: Some("publish.yml@refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-abc".into()),
        }
    }

    #[test]
    fn cache_write_read_round_trips_within_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let snap = fresh_snapshot();
        write_cache(dir.path(), "@lpm.dev/acme.widget", "1.0.0", &snap).unwrap();
        let got = read_cache(dir.path(), "@lpm.dev/acme.widget", "1.0.0").unwrap();
        assert_eq!(got, Some(snap));
    }

    #[test]
    fn cache_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let got = read_cache(dir.path(), "missing", "0.0.0").unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn cache_corrupt_file_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            b"not json at all",
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(got, None, "corrupt cache must degrade to miss, not error");
    }

    #[test]
    fn cache_schema_version_mismatch_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let bad = serde_json::json!({
            "version": CACHE_SCHEMA_VERSION + 1,
            "cached_at_secs": current_epoch_secs(),
            "snapshot": fresh_snapshot(),
        });
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            bad.to_string(),
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(
            got, None,
            "future-version cache entries must be treated as misses",
        );
    }

    #[test]
    fn cache_stale_entry_past_ttl_treated_as_miss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // Write an entry whose `cached_at_secs` is older than TTL.
        let stale = CacheEntry {
            version: CACHE_SCHEMA_VERSION,
            cached_at_secs: current_epoch_secs().saturating_sub(CACHE_TTL_SECS + 1),
            snapshot: fresh_snapshot(),
        };
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn cache_write_creates_parent_directory() {
        // Cache root doesn't exist yet — write_cache must create it.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c/attestations");
        write_cache(&nested, "pkg", "1.0.0", &fresh_snapshot()).unwrap();
        assert!(nested.exists());
        let got = read_cache(&nested, "pkg", "1.0.0").unwrap();
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
    }

    // ── fetch_provenance_snapshot (public API) — non-network paths ──

    /// `attestation_ref = None` is the "registry didn't ship an
    /// attestation" signal. Must return `Some(present: false)` and
    /// cache it so repeated installs hit the cache.
    #[tokio::test]
    async fn fetch_returns_absent_snapshot_when_ref_is_none() {
        let cache = tempfile::tempdir().unwrap();
        let http = reqwest::Client::new();
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", None)
            .await
            .unwrap()
            .unwrap();
        assert!(!snap.present);
        assert!(snap.publisher.is_none());
        assert!(snap.workflow.is_none());

        // Cache should now contain the absent marker.
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, Some(snap));
    }

    /// `attestation_ref.url = None` is semantically the same as
    /// `ref = None` — the registry said "no attestation here."
    #[tokio::test]
    async fn fetch_returns_absent_snapshot_when_url_is_none() {
        let cache = tempfile::tempdir().unwrap();
        let http = reqwest::Client::new();
        let att = AttestationRef {
            url: None,
            provenance: None,
        };
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att))
            .await
            .unwrap()
            .unwrap();
        assert!(!snap.present);
    }

    /// A fresh cache entry short-circuits the network entirely.
    /// Driving the test through the public API proves the cache-hit
    /// branch is wired correctly even though the http client in the
    /// test isn't pointed at any real server.
    #[tokio::test]
    async fn fetch_uses_cache_hit_without_network_roundtrip() {
        let cache = tempfile::tempdir().unwrap();
        let pre = fresh_snapshot();
        write_cache(cache.path(), "pkg", "1.0.0", &pre).unwrap();

        let att = AttestationRef {
            url: Some("http://localhost:1/definitely-unreachable".into()),
            provenance: None,
        };
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snap, pre, "cache hit must not perform an HTTP request");
    }

    /// Network failures degrade to `Ok(None)` (unknown) per the
    /// plan's degraded-mode contract. Not caching this result is
    /// critical — a transient failure must not poison future
    /// installs for 7 days.
    #[tokio::test]
    async fn fetch_returns_none_on_network_failure_and_does_not_cache() {
        let cache = tempfile::tempdir().unwrap();
        let att = AttestationRef {
            // Loopback to an unused port — connection refused instantly.
            url: Some("http://127.0.0.1:1/never-listens".into()),
            provenance: None,
        };
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att))
            .await
            .unwrap();
        assert_eq!(
            result, None,
            "network failure must degrade to unknown (Ok(None)) per §11 P4"
        );

        // Most importantly: the failure must not have written a
        // stub entry to cache. The drift-rule contract depends on
        // `None` never being persisted.
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "network failure must not be cached");
    }
}
