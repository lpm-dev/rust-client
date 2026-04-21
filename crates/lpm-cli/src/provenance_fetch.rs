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
//! The install-time call site lives in
//! [`crate::commands::install::run_with_options`]'s drift gate,
//! which fires immediately after the cooldown gate on fresh
//! resolution paths.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::LpmError;
use lpm_registry::AttestationRef;
use lpm_workspace::ProvenanceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// **Phase 46 P4 Chunk 4.** Canonicalized policy for the
/// `--ignore-provenance-drift[-all]` override flags on `lpm install`.
///
/// The two clap args compose per Q2 of the P4 kickoff discussion:
/// `--ignore-provenance-drift-all` supersedes the per-package list,
/// so passing `-all` alongside specific `--ignore-provenance-drift X`
/// is not an error — it just collapses to `IgnoreAll`. This avoids a
/// clap mutual-exclusion rule that would otherwise trip CI scripts
/// that forward both from an orchestrator.
#[derive(Debug, Clone, Default)]
pub enum DriftIgnorePolicy {
    /// No override: enforce §7.2 drift normally.
    #[default]
    EnforceAll,
    /// Opt out of drift enforcement for these specific package names.
    /// Empty set is not constructible — callers use [`Self::from_cli`]
    /// which rewrites an empty per-package list to `EnforceAll`.
    IgnoreNames(HashSet<String>),
    /// Opt out of drift enforcement for every resolved package.
    IgnoreAll,
}

impl DriftIgnorePolicy {
    /// Build the canonical policy from the two raw clap inputs.
    ///
    /// - `ignore_all = true` → `IgnoreAll` (per-package list ignored).
    /// - `ignore_all = false`, non-empty list → `IgnoreNames`.
    /// - Both empty / unset → `EnforceAll`.
    pub fn from_cli(ignore_names: Vec<String>, ignore_all: bool) -> Self {
        if ignore_all {
            return Self::IgnoreAll;
        }
        if ignore_names.is_empty() {
            return Self::EnforceAll;
        }
        Self::IgnoreNames(ignore_names.into_iter().collect())
    }

    /// Whether this policy suppresses drift enforcement universally.
    /// Used by the install gate to short-circuit the entire per-
    /// package loop without any network cost.
    pub fn ignores_all(&self) -> bool {
        matches!(self, Self::IgnoreAll)
    }

    /// Whether drift enforcement is suppressed for one specific name.
    /// `IgnoreAll` returns `true` for every name; `EnforceAll`
    /// returns `false` for every name; `IgnoreNames` consults the
    /// set.
    pub fn ignores_name(&self, name: &str) -> bool {
        match self {
            Self::EnforceAll => false,
            Self::IgnoreNames(set) => set.contains(name),
            Self::IgnoreAll => true,
        }
    }
}

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
                ..Default::default()
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
///
/// **Body-size defense (reviewer finding, Chunk 2 revision):** the
/// original implementation called `response.bytes().await` first and
/// only then compared the buffered length against `MAX_BUNDLE_BYTES`
/// — which meant the 1 MiB "hostile registry" guard was theoretical:
/// we'd already have allocated the full oversized body by the time
/// the check ran. This function now enforces the cap in two stages:
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
async fn fetch_and_parse(http: &reqwest::Client, url: &str) -> Result<ProvenanceSnapshot, ()> {
    use futures::StreamExt;

    let response = http
        .get(url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|_| ())?;

    if !response.status().is_success() {
        return Err(());
    }

    // Stage 1: early-reject on oversized declared Content-Length.
    // Cheap — server hasn't sent a body byte past the headers yet;
    // dropping the response here closes the connection without
    // reading any body.
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_BUNDLE_BYTES
    {
        return Err(());
    }

    // Stage 2: streaming bound. Initial capacity is generous enough
    // for a typical real bundle (~10-50 KiB) so we don't spend time
    // growing the Vec for the common case, yet far below the cap so
    // we never over-allocate relative to what we'll actually keep.
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        // Reject BEFORE copying the chunk into `buf`: the check is
        // `buf.len() + chunk.len()` so even a single oversized chunk
        // can't land in our Vec.
        if buf.len().saturating_add(chunk.len()) > MAX_BUNDLE_BYTES {
            return Err(());
        }
        buf.extend_from_slice(&chunk);
    }

    parse_sigstore_bundle(&buf)
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
        workflow_path: identity.as_ref().map(|i| i.workflow_path.clone()),
        workflow_ref: identity.as_ref().map(|i| i.workflow_ref.clone()),
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
///
/// The SAN URI carries a single composite `<path>@<ref>` workflow
/// string; we split it at construction so the drift-check comparator
/// (in `lpm-security::provenance`) can compare `workflow_path`
/// cross-release while keeping `workflow_ref` as audit-only data.
/// Motivation: without the split, a legitimate v1.14.0 → v1.14.1
/// release (same repo, same workflow file, necessarily different ref)
/// would register as "identity changed" and block. See the reviewer's
/// 2026-04-22 drift-comparator finding for the full trace.
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
    // plan's §6.1 wire spec).
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
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    // ── DriftIgnorePolicy::from_cli ─────────────────────────────

    /// Default state (no flags passed) enforces drift normally. This
    /// is the baseline every non-Install caller relies on via
    /// [`DriftIgnorePolicy::default`].
    #[test]
    fn drift_ignore_policy_no_flags_enforces_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], false);
        assert!(!policy.ignores_all());
        assert!(!policy.ignores_name("axios"));
    }

    /// `--ignore-provenance-drift axios --ignore-provenance-drift lodash`
    /// produces `IgnoreNames`. Other names are still enforced.
    #[test]
    fn drift_ignore_policy_per_package_collapses_into_set() {
        let policy = DriftIgnorePolicy::from_cli(vec!["axios".into(), "lodash".into()], false);
        assert!(!policy.ignores_all());
        assert!(policy.ignores_name("axios"));
        assert!(policy.ignores_name("lodash"));
        assert!(
            !policy.ignores_name("express"),
            "unnamed packages must still enforce drift",
        );
    }

    /// `--ignore-provenance-drift-all` alone → `IgnoreAll`. The
    /// short-circuit drops into the blanket-waive path in the
    /// install gate.
    #[test]
    fn drift_ignore_policy_all_flag_alone_ignores_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], true);
        assert!(policy.ignores_all());
        assert!(policy.ignores_name("any"));
        assert!(policy.ignores_name("package"));
    }

    /// Key behaviour from Q2 of the P4 kickoff: passing both flags is
    /// NOT an error — `-all` supersedes the per-package list. No clap
    /// mutex needed; the combination is unambiguous and the shorter-
    /// text flag wins by the simpler of the two.
    #[test]
    fn drift_ignore_policy_all_flag_supersedes_per_package_list() {
        let policy = DriftIgnorePolicy::from_cli(vec!["axios".into(), "lodash".into()], true);
        // When -all wins, every name is ignored — including names
        // NOT in the per-package list, which is the whole point.
        assert!(policy.ignores_all());
        assert!(policy.ignores_name("axios"));
        assert!(policy.ignores_name("express"));
    }

    /// Empty per-package list + false flag → `EnforceAll`, NOT
    /// `IgnoreNames(empty set)`. The latter would behave identically
    /// but would obscure the "we're enforcing" signal in debug output.
    #[test]
    fn drift_ignore_policy_empty_inputs_canonicalize_to_enforce_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], false);
        assert!(matches!(policy, DriftIgnorePolicy::EnforceAll));
    }

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

    /// **Reviewer finding regression guard — Finding 1.** Two legitimate
    /// releases from the same repo + workflow differ ONLY in the ref
    /// portion of the SAN URI. The parser must produce the SAME
    /// `workflow_path` for both so the drift comparator's identity
    /// tuple treats them as non-drifting. Without the split fix this
    /// test would prove by construction that `.workflow`-full-string
    /// comparison is wrong.
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

    fn fresh_snapshot() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
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
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());

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

    // ── Body-size enforcement (reviewer finding) ─────────────────

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

        let http = reqwest::Client::new();
        let url = format!("{}/att", server.uri());
        let snap = fetch_and_parse(&http, &url).await.unwrap();
        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
    }

    /// **Reviewer finding — primary regression guard.** A response
    /// whose body exceeds `MAX_BUNDLE_BYTES` must be rejected
    /// BEFORE the full body lands in memory. Pre-fix, this case
    /// allocated the entire oversized body then checked size —
    /// defeating the "hostile registry" defense claimed by the
    /// module docs. Post-fix, the streaming cap rejects during
    /// accumulation, so even a 10 MiB body never lives in our
    /// process heap.
    ///
    /// wiremock by default sends a truthful `Content-Length`, so
    /// this case exercises the stage-1 pre-stream check. A
    /// chunked-transfer variant would hit stage 2; both stages
    /// reject with the same `Err(())` sentinel, so a single test
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

        let http = reqwest::Client::new();
        let url = format!("{}/att", server.uri());
        let result = fetch_and_parse(&http, &url).await;
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
        let http = reqwest::Client::new();
        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let result = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att))
            .await
            .unwrap();
        assert_eq!(
            result, None,
            "oversized body must degrade to unknown (Ok(None))"
        );
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(
            cached, None,
            "oversized-body rejection must not write a poisoned cache entry"
        );
    }

    /// Stage-1 specificity: a response that DECLARES an oversized
    /// `Content-Length` is rejected even without the server actually
    /// emitting a body. Proves the pre-stream check fires on the
    /// header alone — we drop the response before reading any body
    /// byte.
    ///
    /// **Reviewer finding (2026-04-22):** an earlier version of this
    /// test used wiremock with an overridden `Content-Length` header
    /// and a small real body. That triggered a hyper framing panic
    /// in the mock-server's response thread ("payload claims
    /// content-length of N, custom content-length header claims M")
    /// — the assertion still returned `Ok` because the client saw
    /// a transport error (which our code maps to `Err(())` anyway),
    /// so the test passed for the wrong reason and left a background
    /// panic in the test run.
    ///
    /// Fix: bypass hyper entirely. Bind a raw TCP socket, write an
    /// HTTP/1.1 response with headers declaring a huge
    /// `Content-Length`, then close the connection. Our code's
    /// stage-1 check rejects on the declared header value and drops
    /// the response without ever attempting to read a body byte, so
    /// the "declared vs actual" framing discrepancy never surfaces
    /// on the client side. Single-shot accept loop — the spawned
    /// task exits after handling one connection, no resource leak.
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

        let http = reqwest::Client::new();
        let url = format!("http://{addr}/");
        let result = fetch_and_parse(&http, &url).await;
        assert!(
            result.is_err(),
            "declared Content-Length > cap must reject pre-stream",
        );
    }
}
