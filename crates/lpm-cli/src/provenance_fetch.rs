//! — Sigstore attestation fetch + cache + cert
//! SAN extraction for the CLI's provenance-drift check.
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
//! **Fetch-failure semantics**:
//! - `Ok(Some(snapshot))` — a definitive answer (either
//!   `present: true` with identity extracted, or `present: false`
//!   meaning the registry has no attestation for this version).
//! - `Ok(None)` — **degraded / unknown** (network error, malformed
//!   bundle, etc.). The drift rule interprets this as
//!   "pass, don't drift" per the plan's offline/degrade guarantee.
//!   Never cached, so the next install retries.
//! - `Err(_)` — reserved for genuinely fatal conditions (cache
//!   directory unwritable, I/O errors the caller must surface).
//!
//! **Scope (plan D5):** identity extraction only. No Sigstore
//! signature verification, no Fulcio trust-root checks. //! lands full cryptographic verification.
//!
//! The install-time call site lives in
//! [`crate::commands::install::run_with_options`]'s drift gate,
//! which fires immediately after the cooldown gate on fresh
//! resolution paths.

// base64 is used by the legacy identity-only parse functions
// (`parse_sigstore_bundle`, `find_leaf_cert_rawbytes`). Pre-Phase
// 2.2.c those were `#[cfg(test)]`-gated; Phase 2.2.c adds the
// `--unverified-provenance[-all]` operator opt-out, which routes
// skip-listed packages through the legacy identity-only parser to
// produce `ProvenanceStatus::Unverified(...)` without running the
// cryptographic verifier. So the parsers are now live in release
// builds as well.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::LpmError;
use lpm_registry::AttestationRef;
use lpm_workspace::{ProvenanceSnapshot, ProvenanceStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Canonicalized policy for the
/// `--ignore-provenance-drift[-all]` override flags on `lpm install`.
///
/// The two clap args compose per Q2 of the kickoff discussion:
/// `--ignore-provenance-drift-all` supersedes the per-package list,
/// so passing `-all` alongside specific `--ignore-provenance-drift X`
/// is not an error — it just collapses to `IgnoreAll`. This avoids a
/// clap mutual-exclusion rule that would otherwise trip CI scripts
/// that forward both from an orchestrator.
#[derive(Debug, Clone, Default)]
pub enum DriftIgnorePolicy {
    /// No override: enforce drift normally.
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

/// Rollout knob for the install-time and approve-time provenance
/// verifier (Phase 2.2.b).
///
/// Read from the `LPM_PROVENANCE_ENFORCE` environment variable.
/// Default is `Deny` (fail-closed). The `Warn` variant exists for
/// the Phase 2.3 two-release rollout window: operators can ship the
/// verifier code in warn mode for one release so a bundle-shape
/// change at the registry surfaces as a loud log line rather than a
/// blocked install, then flip the default to deny on the next
/// release once telemetry confirms no spurious rejections.
///
/// The knob is honored by the **approval-capture path**
/// ([`crate::commands::approve_scripts::snapshot_for_binding_with_mode`]).
/// The install-time drift gate at `commands/install.rs` already
/// propagates `Err(LpmError::ProvenanceVerification)` via `?` and
/// is not gated by this knob — install-time rejection always blocks
/// (the drift gate has its own per-package opt-out via
/// `--ignore-provenance-drift[-all]`). This split matches Phase 2.5
/// where the operator-facing persistent toggle is documented to
/// affect the binding-record posture during approve-scripts.
///
/// Phase 2.5 will promote this enum to the orthogonal
/// `EnforceMode` × `SkipPolicy` shape (with a third `Off` mode and
/// the config + wizard surface). This commit ships only the
/// rollout-knob posture; the persistent operator toggle is a
/// follow-up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnforceMode {
    /// Fail-closed: a verifier rejection refuses the approval.
    /// Production default starting with Phase 2.2.
    #[default]
    Deny,
    /// Rollout-window posture: a verifier rejection logs loudly via
    /// `output::warn` + `tracing::warn` but does not block the
    /// approval. The trust binding's `provenance_at_approval` is
    /// recorded as `None` — same effect as a transport-degraded
    /// fetch during the approval window. Subsequent installs treat
    /// the package as "no provenance reference" until re-approved
    /// under `Deny` mode. Operators who set this MUST monitor the
    /// warn log line and either remediate the registry compromise
    /// or re-approve once the verifier accepts the bundle.
    Warn,
}

impl EnforceMode {
    /// Read the mode from `LPM_PROVENANCE_ENFORCE`.
    ///
    /// Default is `Deny`. Unknown values fall back to `Deny`
    /// (fail-closed) with a `tracing::warn` so a typo in the env
    /// var doesn't silently weaken the posture.
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref())
    }

    /// Pure parser exposed for unit tests so they don't have to
    /// mutate process-global env state. Production callers should
    /// use [`Self::from_env`].
    pub(crate) fn from_env_value(value: Option<&str>) -> Self {
        match value {
            // `unset` is explicitly mapped to `Deny` so a user who
            // never set the var gets the safe default.
            None => Self::Deny,
            Some("warn") => Self::Warn,
            Some("deny") => Self::Deny,
            Some(other) => {
                tracing::warn!(
                    target = "lpm::provenance",
                    value = %other,
                    "ignoring unknown LPM_PROVENANCE_ENFORCE value (expected 'warn' or 'deny'); using fail-closed default"
                );
                Self::Deny
            }
        }
    }
}

/// Per-package opt-out for Sigstore cryptographic verification
/// (Phase 2.2.c). Orthogonal to [`EnforceMode`]: a package excluded
/// here is treated as if the verifier was never run, regardless of
/// the mode. The fetch still happens (we need the bytes to extract
/// the SAN identity) but the verifier is skipped and the resulting
/// snapshot lands on the binding as
/// [`lpm_common::ProvenanceStatus::Unverified`] — explicit "operator
/// accepted the identity without crypto" rather than silently
/// degraded.
///
/// The orthogonal split (rather than collapsing skip into a third
/// `EnforceMode::Off` value) is load-bearing for the composition
/// pinned by the Phase 2.5 ordering audit item: an operator can
/// run `LPM_PROVENANCE_ENFORCE=warn` AND skip a specific package —
/// the env knob still drives the rest of the install (verifier
/// failures warn but don't block) while the skip-listed package
/// produces `Unverified` directly. The wiring composes cleanly only
/// if the two axes are independent.
#[derive(Debug, Clone, Default)]
pub enum SkipPolicy {
    /// Verify every package (default). The verifier runs and its
    /// outcome falls under whatever [`EnforceMode`] is active.
    #[default]
    None,
    /// Skip verification for these specific package names. Empty set
    /// is not constructible — callers use [`Self::from_cli`] which
    /// rewrites an empty per-package list to `None`.
    Names(HashSet<String>),
    /// Skip verification for every resolved package on this
    /// invocation.
    All,
}

impl SkipPolicy {
    /// Build the canonical policy from the two raw clap inputs.
    /// Mirrors [`DriftIgnorePolicy::from_cli`] so the two
    /// `--unverified-provenance{,-all}` and `--ignore-provenance-drift{,-all}`
    /// pairs canonicalize the same way: `-all` supersedes the
    /// per-package list (no clap mutex, just collapse).
    pub fn from_cli(unverified_names: Vec<String>, unverified_all: bool) -> Self {
        if unverified_all {
            return Self::All;
        }
        if unverified_names.is_empty() {
            return Self::None;
        }
        Self::Names(unverified_names.into_iter().collect())
    }

    /// `true` iff this specific package name is skip-listed.
    /// `All` returns `true` for every name; `None` returns `false`
    /// for every name; `Names` consults the set.
    pub fn skips_name(&self, name: &str) -> bool {
        match self {
            Self::None => false,
            Self::Names(set) => set.contains(name),
            Self::All => true,
        }
    }
}

/// Composed verification policy: the (`EnforceMode`, `SkipPolicy`)
/// pair that drives the install- and approve-time provenance gates.
///
/// Held together in one struct so `run_with_options` and the batch
/// caller take a single parameter instead of two. The fields are
/// independent — see [`SkipPolicy`] for why.
#[derive(Debug, Clone, Default)]
pub struct VerifyPolicy {
    pub enforce: EnforceMode,
    pub skip: SkipPolicy,
}

impl VerifyPolicy {
    /// Construct from the install-time CLI inputs + env-resolved
    /// enforce mode. The CLI surface lives on `Commands::Install` in
    /// `main.rs`; this is the single canonicalization point used by
    /// every dispatcher arm that reaches the install pipeline.
    pub fn from_cli(unverified_names: Vec<String>, unverified_all: bool) -> Self {
        Self {
            enforce: EnforceMode::from_env(),
            skip: SkipPolicy::from_cli(unverified_names, unverified_all),
        }
    }
}

/// 7-day TTL per the plan.
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Schema version for the on-disk cache entries. Bump if the parsed
/// `ProvenanceSnapshot` shape changes OR the SAN extractor's
/// behaviour changes in a way that invalidates prior captures, OR
/// the verification posture for cached entries changes. Entries
/// with a mismatched version are treated as misses (re-fetch).
///
/// **Version 2** (Phase 2.1): cache entries are now produced by the
/// FULL cryptographic verifier (Phase 1.8's `verify_sigstore_bundle`),
/// not by identity-only extraction. Every cached snapshot has had
/// chain + DSSE + SCT + Rekor body + SET (and possibly inclusion
/// proof) verified at write time. Schema-1 entries are produced by
/// the legacy `parse_sigstore_bundle` identity-only extractor and
/// MUST NOT be returned by the new code path — they would silently
/// admit unverified attestations into the drift gate. The bump
/// invalidates every legacy entry on first read.
const CACHE_SCHEMA_VERSION: u32 = 2;

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
/// — every legitimate entry is well under 4 KiB and the same 1 MiB
/// bound applies on the fetch side via [`MAX_BUNDLE_BYTES`].
const MAX_CACHE_ENTRY_BYTES: u64 = 1024 * 1024;

/// perf decomposition of [`fetch_provenance_snapshot`].
///
/// Each atomic accumulates time spent in one stage across many
/// concurrent calls. Caller (e.g. `build_blocked_set_metadata`) creates
/// one of these, threads it as `Some(&timings)` into every
/// [`fetch_provenance_snapshot`] call, and emits the breakdown after
/// the surrounding `join_all` settles.
///
/// Stages:
/// - `cache_hit_ns` — time inside [`read_cache`] when it returns
///   `Some`. Cache misses do not contribute here; their downstream
///   fetch is timed under `http_ns`.
/// - `http_ns` — time inside the HTTP fetch from `send` through the
///   final body chunk being buffered. Includes status-check, content-
///   length-cap, and stream-cap rejections.
/// - `parse_ns` — time inside JSON parse + cert lookup + base64
///   decode + SAN extraction. Pure CPU.
///
/// These three cover the dominant cost shapes (warm-cache /
/// cold-fetch / cold-parse). Other paths (no-URL early return, the
/// cache-miss `read_cache` call itself, cache-write) are deliberately
/// not split — they are bounded small and would add report noise
/// without changing what design decision the breakdown informs.
#[derive(Default, Debug)]
pub struct ProvenanceTimings {
    pub cache_hit_ns: AtomicU64,
    pub http_ns: AtomicU64,
    pub parse_ns: AtomicU64,
}

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
    timings: Option<&ProvenanceTimings>,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    // Registry said "no attestation for this version" — that is the
    // axios signal. Return a definitive `present: false` snapshot.
    //
    // W1b: do NOT write an "absent" entry to the cache. The previous
    // implementation wrote this marker "so repeated installs of the
    // same absent package don't re-examine the registry metadata," but
    // analysis of the control flow below reveals two problems:
    //
    //   1. Dead write — the absent cache is never READ for genuinely
    //      absent packages. Every subsequent install sees
    //      `attestation_ref.url = None` in the metadata and takes this
    //      same early-return branch without ever reaching `read_cache`
    //      below (which only runs on the `Some(url)` path).
    //
    //   2. Latent staleness — if a package later publishes an
    //      attestation (URL flips from None → Some), the next install
    //      DOES reach `read_cache` and would return the stale
    //      `present: false` entry, silently defeating provenance drift
    //      detection for that package.
    //
    // The metadata lookup in `build_blocked_set_metadata` is already
    // O(1) from the resolver's 5-min TTL cache, so the "absence signal
    // is O(1) disk read" rationale doesn't hold: re-checking
    // `attestation_ref.is_none()` against cached metadata is O(1) RAM
    // without any disk involvement at all.
    //
    // Measured effect on the 266-pkg fixture (most without attestation
    // URLs): build_blocked_set_metadata wall-clock drops from ~230 ms
    // to ~30 ms. That's ~200 ms of sync fs::write calls serialized
    // through the Tokio runtime worker pool inside a join_all.
    let url = match attestation_ref.and_then(|a| a.url.as_deref()) {
        Some(u) => u,
        None => {
            return Ok(Some(ProvenanceSnapshot {
                present: false,
                ..Default::default()
            }));
        }
    };

    // Cache hit + fresh → skip the network round-trip. Time only the
    // hit case: misses fall through and their downstream fetch is
    // covered by `http_ns`. The `read_cache` call itself on a miss
    // is bounded small and intentionally not split out (see
    // [`ProvenanceTimings`] doc).
    let cache_start = Instant::now();
    if let Some(cached) = read_cache(cache_root, name, version)? {
        if let Some(t) = timings {
            t.cache_hit_ns
                .fetch_add(cache_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        return Ok(Some(cached));
    }

    // Cache miss → fetch (network) + parse (CPU), timed separately so
    // the perf decomposition can attribute cold-install cost. Any
    // error from either stage degrades to `Ok(None)` and is NOT
    // cached — the next install retries.
    let http_start = Instant::now();
    let buf = match fetch_bundle_bytes(http, url).await {
        Ok(b) => b,
        Err(()) => return Ok(None),
    };
    if let Some(t) = timings {
        t.http_ns
            .fetch_add(http_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    // Verification (Phase 2.1): bytes are in hand, run the full
    // verifier. Failure here is NOT degraded to `Ok(None)` because
    // it represents an attack signal (registry served a bundle that
    // claimed signed provenance but failed crypto). Transport-class
    // failures are already absorbed above at `fetch_bundle_bytes`.
    let parse_start = Instant::now();
    let snapshot = verify_bundle_or_err(&buf, url)?;
    if let Some(t) = timings {
        t.parse_ns
            .fetch_add(parse_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

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

/// Map one [`fetch_provenance_snapshot`] outcome to a
/// [`ProvenanceStatus`] for the batch caller.
///
/// Pure mapping (no I/O) so the SILENT-DROP regression is directly
/// testable without mocking the registry-client cascade.
/// Phase 2.2 fix: the prior `.ok().flatten()` collapsed
/// `Err(LpmError::ProvenanceVerification)` into the same `None` as a
/// transport failure, blanking the approval binding and disarming
/// drift on subsequent installs. This helper preserves the four
/// states distinct:
///
/// - `Ok(Some(snap))` with `snap.present == true` → `Verified`
/// - `Ok(Some(snap))` with `snap.present == false` → `Absent`
///   (registry confirmed no attestation — the axios drop signal)
/// - `Ok(None)` → `TransportDegraded`
/// - `Err(LpmError::ProvenanceVerification(reason))` →
///   `VerificationRejected { reason }`
/// - `Err(other)` → `TransportDegraded` (fatal I/O degrades rather
///   than failing the whole batch; the per-package path retains
///   the typed-error contract for install-time `?`-propagation)
fn map_fetch_result_to_status(
    name: &str,
    version: &str,
    result: Result<Option<ProvenanceSnapshot>, LpmError>,
) -> ProvenanceStatus {
    match result {
        Ok(Some(snap)) => {
            if snap.present {
                ProvenanceStatus::Verified(snap)
            } else {
                ProvenanceStatus::Absent
            }
        }
        Ok(None) => ProvenanceStatus::TransportDegraded,
        Err(LpmError::ProvenanceVerification(reason)) => {
            tracing::warn!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                reason = %reason,
                "provenance bundle rejected by verifier; approval will be refused"
            );
            ProvenanceStatus::VerificationRejected { reason }
        }
        Err(other) => {
            tracing::debug!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                err = %other,
                "provenance fetch failed (non-verification error); degrading to transport"
            );
            ProvenanceStatus::TransportDegraded
        }
    }
}

/// Batch-fetch attestation snapshots for many `(name, version)` pairs
/// in parallel. Single source of truth for both the project-level
/// `lpm approve-scripts` write path and the global-scope
/// `lpm approve-scripts --global` write path (P4 parity).
///
/// Returns one [`ProvenanceStatus`] per input pair (never collapses
/// distinct outcomes into a single `None`). Phase 2.2 SILENT-DROP fix:
/// the previous implementation used `.ok().flatten()` here, which made
/// a verifier rejection (`Err(LpmError::ProvenanceVerification)`)
/// indistinguishable from a network failure. Recording the resulting
/// `provenance_at_approval = None` would silently disarm the drift
/// comparator's `(None, _) => NoDrift` arm on every future install,
/// permanently defeating publisher-swap detection after a single
/// attack-window install. The explicit match below preserves the four
/// states end-to-end so the approval-capture path can refuse to
/// record a binding on rejection while still degrading to `NoDrift`
/// on genuine transport failures.
///
/// Phase 2.2.c: `verify_policy.skip` carves a per-package opt-out:
/// for every name listed (or every name when `SkipPolicy::All`), the
/// verifier is bypassed and the bundle is parsed through the legacy
/// identity-only extractor; the result lands as
/// [`ProvenanceStatus::Unverified`] (snapshot present, audit trail
/// records the operator's downgrade). `verify_policy.enforce` only
/// affects the verifier path — when the package is skip-listed there
/// is nothing to enforce against. The two axes are independent on
/// purpose (see [`SkipPolicy`] doc).
///
/// The lpm-vs-npm metadata-fetch dispatch by `@lpm.dev/` name prefix
/// mirrors `install.rs::build_blocked_set_metadata`. The 5-min metadata
/// cache absorbs the typical "install then immediately approve-scripts"
/// case (no network call); the on-disk attestation cache under
/// `~/.lpm/cache/metadata/attestations/` (7-day TTL) covers repeated
/// approvals across runs.
pub async fn fetch_provenance_for_pkgs(
    pkgs: &[(String, String)],
    verify_policy: &VerifyPolicy,
) -> HashMap<(String, String), ProvenanceStatus> {
    let cache_root = match lpm_common::paths::LpmRoot::from_env() {
        Ok(root) => root.cache_metadata_attestations(),
        Err(_) => {
            // Degraded — no cache root. Match the pre-existing install
            // behavior: every package degrades.
            return pkgs
                .iter()
                .map(|p| (p.clone(), ProvenanceStatus::TransportDegraded))
                .collect();
        }
    };
    let http = reqwest::Client::new();
    let registry = lpm_registry::RegistryClient::new();

    let cache_root_ref = &cache_root;
    let http_ref = &http;
    let registry_ref = &registry;
    let skip_ref = &verify_policy.skip;

    let futures = pkgs.iter().map(move |(name, version)| async move {
        // lpm vs npm dispatch by name prefix mirrors
        // `install.rs::build_blocked_set_metadata`.
        let meta = if name.starts_with("@lpm.dev/") {
            match lpm_common::PackageName::parse(name) {
                Ok(pkg_name) => registry_ref.get_package_metadata(&pkg_name).await.ok(),
                Err(_) => None,
            }
        } else {
            registry_ref.get_npm_package_metadata(name).await.ok()
        };
        let attestation_ref = meta
            .as_ref()
            .and_then(|m| m.versions.get(version))
            .and_then(|v| v.dist.as_ref())
            .and_then(|d| d.attestations.clone());

        // Phase 2.2.c skip path: operator opted out of cryptographic
        // verification for this name (or wholesale via `--unverified-
        // provenance-all`). Pull the bytes through the legacy
        // identity-only parser and land the snapshot as `Unverified`
        // so the binding records the operator's downgrade explicitly
        // instead of falsely claiming verification.
        if skip_ref.skips_name(name) {
            let status =
                fetch_unverified_snapshot(http_ref, name, version, attestation_ref.as_ref()).await;
            return ((name.clone(), version.clone()), status);
        }

        let raw = fetch_provenance_snapshot(
            http_ref,
            cache_root_ref,
            name,
            version,
            attestation_ref.as_ref(),
            None,
        )
        .await;
        let status = map_fetch_result_to_status(name, version, raw);
        ((name.clone(), version.clone()), status)
    });
    futures::future::join_all(futures)
        .await
        .into_iter()
        .collect()
}

/// Skip-list fetch: pull the bundle bytes, run the legacy
/// identity-only parser, and emit [`ProvenanceStatus::Unverified`]
/// without engaging the cryptographic verifier. Errors degrade to
/// `TransportDegraded` — even on the skip path, a missing URL or a
/// malformed bundle means we observed nothing; the drift comparator's
/// `(_, None) => NoDrift` arm then absorbs it.
///
/// Cache-bypass on purpose: cached entries are
/// `CACHE_SCHEMA_VERSION = 2` and were written by the verifier path
/// (`Verified` semantics). Reading them on the skip path would
/// silently upgrade an Unverified observation to "the operator opted
/// out, but the cache says it was verified yesterday" — confusing
/// the audit trail. The skip path is rare; the extra fetch is fine.
/// We also do NOT write a cache entry: a future verifier-mode install
/// must not be allowed to short-circuit through an entry that bypassed
/// crypto.
pub async fn fetch_unverified_snapshot(
    http: &reqwest::Client,
    name: &str,
    version: &str,
    attestation_ref: Option<&AttestationRef>,
) -> ProvenanceStatus {
    let url = match attestation_ref.and_then(|a| a.url.as_deref()) {
        Some(u) => u,
        None => {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                pkg = %name,
                version = %version,
                "skip-list package has no attestation URL — recording Absent"
            );
            return ProvenanceStatus::Absent;
        }
    };
    let buf = match fetch_bundle_bytes(http, url).await {
        Ok(b) => b,
        Err(()) => return ProvenanceStatus::TransportDegraded,
    };
    match parse_sigstore_bundle(&buf) {
        Ok(snap) => {
            tracing::warn!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                "operator opted out of cryptographic verification for this package; \
                 recording identity-only snapshot (--unverified-provenance)"
            );
            ProvenanceStatus::Unverified(snap)
        }
        Err(()) => {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                pkg = %name,
                version = %version,
                "skip-list package bundle failed identity-only parse — degrading to transport"
            );
            ProvenanceStatus::TransportDegraded
        }
    }
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
    use std::io::Read;

    let path = cache_path(cache_root, name, version);
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

    let entry: CacheEntry = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                target: "lpm_cli::provenance_fetch",
                path = %path.display(),
                error = %e,
                "provenance cache entry failed to parse; treating as miss",
            );
            return Ok(None);
        }
    };

    if entry.version != CACHE_SCHEMA_VERSION {
        return Ok(None);
    }
    if current_epoch_secs().saturating_sub(entry.cached_at_secs) >= CACHE_TTL_SECS {
        return Ok(None);
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
/// **Body-size defense (reviewer finding, revision):** the
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
/// HTTP fetch only — pulls the attestation bundle bytes from `url`
/// with the two-stage size-cap defense. All HTTP-stage failure-point
/// tracing (`send`, `status`, `content_length_cap`, `chunk`,
/// `stream_cap`) lives here.
///
/// Split out from [`fetch_and_parse`] in W1b so the
/// production path can time HTTP separately from parse. Tests still
/// go through the [`fetch_and_parse`] wrapper.
async fn fetch_bundle_bytes(http: &reqwest::Client, url: &str) -> Result<Vec<u8>, ()> {
    use futures::StreamExt;

    let response = http
        .get(url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| {
            // W1c: surface the failure mode so operators can
            // tell a transient network blip apart from a deterministic
            // bug (URL stale, bundle shape drift, etc.). Caller maps
            // this to Ok(None) and drift-checks proceed in degraded
            // mode — without tracing we have no signal that the cache
            // is silently being bypassed for ~18 of 51 pkgs every
            // warm install.
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                url = %url,
                error = %e,
                stage = "send",
                "attestation fetch send/timeout error",
            );
        })?;

    if !response.status().is_success() {
        let status = response.status();
        tracing::debug!(
            target: "lpm_cli::provenance_fetch",
            url = %url,
            status = status.as_u16(),
            stage = "status",
            "attestation fetch returned non-2xx",
        );
        return Err(());
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
            url = %url,
            declared_bytes = declared,
            cap_bytes = MAX_BUNDLE_BYTES,
            stage = "content_length_cap",
            "attestation bundle exceeds declared size cap",
        );
        return Err(());
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
                url = %url,
                error = %e,
                buffered_bytes = buf.len(),
                stage = "chunk",
                "attestation body chunk read error",
            );
        })?;
        // Reject BEFORE copying the chunk into `buf`: the check is
        // `buf.len() + chunk.len()` so even a single oversized chunk
        // can't land in our Vec.
        if buf.len().saturating_add(chunk.len()) > MAX_BUNDLE_BYTES {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                url = %url,
                buffered_bytes = buf.len(),
                chunk_bytes = chunk.len(),
                cap_bytes = MAX_BUNDLE_BYTES,
                stage = "stream_cap",
                "attestation bundle exceeded streaming size cap",
            );
            return Err(());
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

/// Verify — turn the raw bundle bytes into a `ProvenanceSnapshot`
/// AFTER cryptographic verification under Phase 1.8's
/// `verify_sigstore_bundle`.
///
/// Failure semantics (Phase 2.1):
/// - `Ok(snapshot)` — bundle verified end-to-end (chain + DSSE +
///   SCT + Rekor body + SET; inclusion proof per policy). The
///   returned snapshot is safe to cache and feed into the drift
///   gate.
/// - `Err(LpmError::ProvenanceVerification(...))` — bundle bytes
///   were structurally present but verification rejected them.
///   The caller MUST surface this as a hard error (NOT degrade to
///   `Ok(None)`), per the plan: "The 'degrade to NoDrift' path is
///   reserved for genuine transport failures (per existing module
///   comment at line 20)." A registry serving signed-but-invalid
///   provenance is an attack signal that the operator deserves to
///   see directly.
///
/// `url` is forwarded only for the outer "verify failed" debug log
/// so the trace stream's "which package failed how" pair stays
/// adjacent.
fn verify_bundle_or_err(body: &[u8], url: &str) -> Result<ProvenanceSnapshot, LpmError> {
    use crate::sigstore_verify::{IdentityExpectations, VerifyOptions, verify_sigstore_bundle};
    match verify_sigstore_bundle(
        body,
        &IdentityExpectations::none(),
        VerifyOptions::npm_attestation(),
    ) {
        Ok(verified) => Ok(verified.snapshot),
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
/// by the wire-shape regression tests below and by the Phase 2.2.c
/// skip-list path in [`fetch_unverified_snapshot`] —
/// production verification still routes through
/// [`fetch_bundle_bytes`] + [`verify_bundle_or_err`] so HTTP and
/// verification can be timed independently.
#[cfg(test)]
async fn fetch_and_parse(http: &reqwest::Client, url: &str) -> Result<ProvenanceSnapshot, ()> {
    let buf = fetch_bundle_bytes(http, url).await?;
    let _ = url;
    parse_sigstore_bundle(&buf)
}

/// Legacy identity-only Sigstore-bundle parser. Pre-Phase-2.1 this
/// was the production call site; Phase 2.1 routed the verify path
/// through Phase 1.8's `verify_sigstore_bundle` (see
/// [`verify_bundle_or_err`]). Phase 2.2.c brings it back as a live
/// production helper for the `--unverified-provenance[-all]` opt-out
/// path: a skip-listed package needs the SAN identity (so the drift
/// gate can still compare publisher / workflow_path) but explicitly
/// bypasses the cryptographic checks. The result lands on the
/// binding as [`ProvenanceStatus::Unverified`] — distinct from
/// `Verified` so the audit trail records the operator's downgrade.
///
/// Errors degrade to `Err(())` and the batch caller maps to
/// `TransportDegraded` — even on the skip path, a malformed bundle
/// is "we couldn't observe the identity at all," which is closer to
/// "transport degraded" than to "operator chose to ignore crypto on
/// a structurally-valid identity."
fn parse_sigstore_bundle(body: &[u8]) -> Result<ProvenanceSnapshot, ()> {
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
/// would register as "identity changed" and block. See the reviewer's
/// drift-comparator finding for the full trace.
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
    // plan's wire spec).
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

    /// Key behaviour from Q2 of the kickoff: passing both flags is
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

    // ── SkipPolicy::from_cli (Phase 2.2.c) ──────────────────────
    //
    // Mirrors the DriftIgnorePolicy canonicalization shape so an
    // operator can rely on `--unverified-provenance{,-all}` composing
    // the same way as `--ignore-provenance-drift{,-all}`. Each test
    // pins one specific behavior we expect to survive future refactors.

    #[test]
    fn skip_policy_no_flags_skips_nothing() {
        let policy = SkipPolicy::from_cli(vec![], false);
        assert!(matches!(policy, SkipPolicy::None));
        assert!(
            !policy.skips_name("axios"),
            "default policy must NOT skip verification for any name",
        );
    }

    #[test]
    fn skip_policy_per_package_collapses_into_set() {
        let policy = SkipPolicy::from_cli(vec!["axios".into(), "lodash".into()], false);
        assert!(matches!(policy, SkipPolicy::Names(_)));
        assert!(policy.skips_name("axios"));
        assert!(policy.skips_name("lodash"));
        assert!(
            !policy.skips_name("express"),
            "unnamed packages must still verify",
        );
    }

    #[test]
    fn skip_policy_all_flag_alone_skips_every_name() {
        let policy = SkipPolicy::from_cli(vec![], true);
        assert!(matches!(policy, SkipPolicy::All));
        assert!(policy.skips_name("any"));
        assert!(policy.skips_name("package"));
    }

    /// Same Q2-of-kickoff semantics as DriftIgnorePolicy: `-all`
    /// supersedes the per-package list, no clap mutex needed. Test
    /// pins the contract — collapsing to `SkipPolicy::All` even when
    /// per-package names are listed.
    #[test]
    fn skip_policy_all_flag_supersedes_per_package_list() {
        let policy = SkipPolicy::from_cli(vec!["axios".into(), "lodash".into()], true);
        assert!(matches!(policy, SkipPolicy::All));
        assert!(policy.skips_name("axios"));
        assert!(
            policy.skips_name("express"),
            "All variant must skip every name, including names NOT in the per-package list",
        );
    }

    // ── VerifyPolicy (Phase 2.2.c — composed shape) ─────────────

    /// The composed default `VerifyPolicy` walks the env chain for
    /// `EnforceMode` and lands on `SkipPolicy::None`. With no env var
    /// set the resolved enforce mode is `Deny` (fail-closed) — pin
    /// both axes so a future change to either default surfaces in
    /// review rather than silently weakening the posture.
    #[test]
    fn verify_policy_default_is_deny_and_skip_none() {
        let policy = VerifyPolicy::default();
        // EnforceMode::Deny is the default per `Default` derive.
        assert_eq!(policy.enforce, EnforceMode::Deny);
        assert!(matches!(policy.skip, SkipPolicy::None));
    }

    /// `VerifyPolicy::from_cli` composes the two axes independently:
    /// the env-derived `EnforceMode` is untouched by the per-package
    /// CLI flags, and vice versa. This is the load-bearing
    /// orthogonality the Phase 2.5 ordering audit anchors on — a
    /// future refactor that conflates the two axes would defeat
    /// "LPM_PROVENANCE_ENFORCE=warn + --unverified-provenance foo
    /// composes cleanly" (the test at the workflow tier).
    #[test]
    fn verify_policy_from_cli_composes_skip_independently_of_enforce() {
        let policy = VerifyPolicy::from_cli(vec!["foo".into()], false);
        // The env is unset in this test, so EnforceMode is the default
        // (Deny). The skip-list still carves foo out — both axes are
        // independently resolved.
        assert_eq!(policy.enforce, EnforceMode::Deny);
        assert!(policy.skip.skips_name("foo"));
        assert!(
            !policy.skip.skips_name("bar"),
            "skip-list must NOT spill across to unrelated names",
        );
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
    /// to walk into. The fix's recursive `find_leaf_cert_rawbytes`
    /// must skip this entry without erroring and continue to the next
    /// list item.
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

    ///
    ///
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
    fn parse_bundle_v3_single_cert_shape_extracts_identity_phase_51_regression() {
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

    ///
    ///
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

    ///
    ///
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

    /// **regression — v0.3 cert wins over v0.2 chain when both
    /// are present.**
    ///
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
        // 2 MiB > the 1 MiB cap. The bytes deliberately look like
        // valid JSON prefix to prove the size check fires *before* the
        // parser runs.
        let mut payload = b"{\"version\":1,\"cached_at_secs\":0,\"snapshot\":".to_vec();
        payload.extend(std::iter::repeat_n(b'a', 2 * 1024 * 1024));
        std::fs::write(&path, &payload).unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0").unwrap();
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
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", None, None)
            .await
            .unwrap()
            .unwrap();
        assert!(!snap.present);
        assert!(snap.publisher.is_none());
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());

        // **W1b invariant.** Absent snapshots are returned in-memory
        // only — no cache entry is written. Callers re-derive the
        // absence signal in O(1) from the already-cached
        // `attestation_ref.is_none()` metadata check on the next
        // install. Writing would be both a dead write (never read for
        // always-absent packages) and a latent staleness bug (if the
        // package later publishes an attestation, a cached "absent"
        // would mask it).
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "absent snapshot must not be cached");
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
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
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
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
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
    async fn fetch_returns_provenance_verification_err_on_unverifiable_bundle() {
        // Phase 2.1 behavioral pin: a registry that serves a 200
        // response whose body is structurally a Sigstore bundle but
        // cannot pass cryptographic verification MUST surface as
        // `Err(LpmError::ProvenanceVerification(...))`, NOT degrade
        // to `Ok(None)`. Pre-Phase-2.1 the old identity-only parse
        // would have either returned Ok(snapshot) or Ok(None)
        // depending on whether the JSON was well-formed; neither was
        // an attack signal. Now the verifier's failure IS the
        // signal.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A structurally-valid Sigstore bundle JSON whose contents
        // cannot pass verification — random certs / no real Rekor
        // entry. Verifier rejects at chain parse / DSSE / SET /
        // Rekor body etc. — the SPECIFIC variant doesn't matter
        // here; the contract is "any verify failure → LpmError".
        let der = cert_der_with_san_uri(
            "https://github.com/attacker/forged/.github/workflows/build.yml@refs/tags/v1",
        );
        let bundle_bytes = sigstore_bundle_with_cert(&der).to_string().into_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle_bytes))
            .mount(&server)
            .await;

        let cache = tempfile::tempdir().unwrap();
        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let http = reqwest::Client::new();
        let err = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
            .await
            .expect_err("unverifiable bundle must surface as ProvenanceVerification error");
        match err {
            LpmError::ProvenanceVerification(msg) => {
                // Diagnostic must name a verify-side concern, not a
                // generic JSON parse / network error.
                assert!(
                    !msg.is_empty(),
                    "ProvenanceVerification error must carry a non-empty diagnostic"
                );
            }
            other => panic!(
                "expected LpmError::ProvenanceVerification on unverifiable bundle, got: {other:?}"
            ),
        }

        // Cache MUST stay empty — we do not persist verification
        // failures (registry might be transiently compromised; the
        // next install retries with a fresh fetch).
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "verification failure must not be cached");
    }

    /// **Phase 2.2.c skip-list pin.** `fetch_unverified_snapshot`
    /// must succeed on the same unverifiable-but-structurally-valid
    /// bundle that `fetch_provenance_snapshot` rejects under the
    /// `Verified` path. The legacy identity-only parser extracts the
    /// SAN identity; the verifier is bypassed entirely; the result
    /// lands as `ProvenanceStatus::Unverified(snap)` with the SAN
    /// fields populated. This is the contract the
    /// `--unverified-provenance <name>` flag depends on.
    #[tokio::test]
    async fn fetch_unverified_snapshot_extracts_identity_without_verifier() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.1",
        );
        let bundle_bytes = sigstore_bundle_with_cert(&der).to_string().into_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle_bytes))
            .mount(&server)
            .await;

        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let http = reqwest::Client::new();

        // Same bundle that the verifier rejects via
        // `fetch_provenance_snapshot` (see the test above) — but the
        // skip-list path bypasses the verifier and lands on Unverified
        // with the identity intact.
        let status =
            fetch_unverified_snapshot(&http, "axios", "1.14.1", Some(&att)).await;
        match status {
            ProvenanceStatus::Unverified(snap) => {
                assert!(snap.present, "unverified snapshot must be present:true");
                assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
                assert_eq!(
                    snap.workflow_path.as_deref(),
                    Some(".github/workflows/publish.yml"),
                    "identity-only parser must still extract workflow_path so \
                     the drift comparator has something to compare against",
                );
            }
            other => panic!(
                "skip-list path must produce Unverified on a structurally-valid bundle, got: {other:?}"
            ),
        }
    }

    /// **Phase 2.2.c skip-list edge case.** When the package has no
    /// attestation URL at all (registry returned `dist.attestations:
    /// null` or omitted the field), the skip-list path produces
    /// `Absent` — same signal as the verifier path. No observation
    /// was possible to record, but we don't degrade to
    /// `TransportDegraded` because the registry was definitive about
    /// "no provenance shipped" (the axios drop signal direction).
    #[tokio::test]
    async fn fetch_unverified_snapshot_returns_absent_when_url_missing() {
        let http = reqwest::Client::new();
        let status =
            fetch_unverified_snapshot(&http, "no-prov", "1.0.0", None).await;
        assert!(
            matches!(status, ProvenanceStatus::Absent),
            "skip-list with no attestation URL must record Absent, got: {status:?}",
        );
    }

    #[test]
    fn cache_schema_v1_entry_treated_as_miss_under_v2_verification_posture() {
        // Phase 2.1 schema bump pin: an on-disk entry with the
        // pre-verification schema version (1) must be treated as a
        // miss by the new code, even if the JSON is structurally
        // valid. Without this invalidation, the new verifier would
        // silently return a snapshot produced by the LEGACY
        // identity-only parser — defeating the entire verifier
        // wire-in.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let stale = serde_json::json!({
            "version": 1u32,
            "cached_at_secs": current_epoch_secs(),
            "snapshot": fresh_snapshot(),
        });
        std::fs::write(
            dir.path().join(cache_filename("pkg", "1.0.0")),
            stale.to_string(),
        )
        .unwrap();
        let got = read_cache(dir.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(
            got, None,
            "schema-1 (legacy identity-only) entries must be invalidated under schema-2 \
             (post-verification) — accepting them would defeat the verifier wire-in"
        );
    }

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
        let result =
            fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
                .await
                .unwrap();
        assert_eq!(
            result, None,
            "network failure must degrade to unknown (Ok(None)) per"
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
        let result =
            fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
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
    /// **Reviewer finding :** an earlier version of this
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

    // ── map_fetch_result_to_status (Phase 2.2 SILENT-DROP fix) ──────

    fn snap_present() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-leaf-aaa".into()),
        }
    }

    /// `Ok(Some(snap))` with `present:true` (the verifier returned
    /// a populated, identity-bound snapshot) maps to `Verified`.
    #[test]
    fn batch_maps_verified_snapshot_to_status_verified() {
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(Some(snap_present())));
        match status {
            ProvenanceStatus::Verified(s) => assert!(s.present),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    /// `Ok(Some(snap{present:false}))` (registry returned no
    /// attestation URL) maps to `Absent`. This is the axios drop
    /// signal — it must not collapse with `TransportDegraded`.
    #[test]
    fn batch_maps_present_false_snapshot_to_status_absent() {
        let absent_snap = ProvenanceSnapshot {
            present: false,
            ..Default::default()
        };
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(Some(absent_snap)));
        assert!(
            matches!(status, ProvenanceStatus::Absent),
            "registry-confirmed absence must surface as Absent (the axios drop signal), \
             not collapse with the transport-degrade path",
        );
    }

    /// `Ok(None)` (transient fetch failure, oversized body, etc.)
    /// maps to `TransportDegraded`. Drift comparator's
    /// `(_, None) => NoDrift` arm absorbs this state.
    #[test]
    fn batch_maps_ok_none_to_status_transport_degraded() {
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(None));
        assert!(matches!(status, ProvenanceStatus::TransportDegraded));
    }

    /// **The SILENT-DROP regression guard.** Pre-fix, the batch
    /// caller's `.ok().flatten()` chain collapsed
    /// `Err(LpmError::ProvenanceVerification)` into the same `None`
    /// as a transport failure, blanking the trust binding's
    /// `provenance_at_approval` and disarming the drift comparator's
    /// `(None, _) => NoDrift` arm on every subsequent install.
    /// Post-fix, the verifier rejection MUST surface as
    /// `VerificationRejected { reason }` distinct from
    /// `TransportDegraded`, with the underlying verifier diagnostic
    /// preserved so the approval-capture path can refuse the binding
    /// and the operator can diagnose the failure mode.
    #[test]
    fn batch_preserves_verification_rejected_distinct_from_transport_degraded() {
        let result = Err(LpmError::ProvenanceVerification(
            "DSSE signature mismatch on payload hash".into(),
        ));
        let status = map_fetch_result_to_status("axios", "1.14.1", result);
        match status {
            ProvenanceStatus::VerificationRejected { reason } => {
                assert!(
                    reason.contains("DSSE signature mismatch"),
                    "verifier diagnostic must propagate through the batch caller, got: {reason}",
                );
            }
            ProvenanceStatus::TransportDegraded => panic!(
                "REGRESSION — verification rejection was collapsed back into TransportDegraded. \
                 This is exactly the SILENT-DROP bug the Phase 2.2 fix closes: subsequent \
                 installs would treat this as a benign transient failure and never re-flag the \
                 forged bundle.",
            ),
            other => panic!("expected VerificationRejected, got {other:?}"),
        }
    }

    /// Non-verification `Err` variants (cache I/O, etc.) degrade to
    /// `TransportDegraded` rather than failing the whole batch. The
    /// install-time path's `?`-propagation contract is preserved by
    /// the single-package fetcher; only the batch caller absorbs
    /// these so one bad row doesn't take down N approvals.
    #[test]
    fn batch_maps_other_errors_to_status_transport_degraded() {
        let result: Result<Option<ProvenanceSnapshot>, LpmError> =
            Err(LpmError::Registry("simulated I/O error".into()));
        let status = map_fetch_result_to_status("axios", "1.14.0", result);
        assert!(
            matches!(status, ProvenanceStatus::TransportDegraded),
            "non-verification errors degrade (the typed-error contract is for the single-package \
             fetcher's `?`-propagation path, not the batch caller)",
        );
    }

    // ── EnforceMode env-var parsing (Phase 2.2.b rollout knob) ──────

    /// Unset env → fail-closed default. This is the production
    /// posture for users who never touch `LPM_PROVENANCE_ENFORCE`.
    #[test]
    fn enforce_mode_from_env_unset_is_deny() {
        assert_eq!(EnforceMode::from_env_value(None), EnforceMode::Deny);
    }

    /// `LPM_PROVENANCE_ENFORCE=warn` → `Warn` (the rollout-window
    /// posture). Approval-capture path logs + records None instead
    /// of refusing.
    #[test]
    fn enforce_mode_from_env_warn_is_warn() {
        assert_eq!(EnforceMode::from_env_value(Some("warn")), EnforceMode::Warn);
    }

    /// `LPM_PROVENANCE_ENFORCE=deny` → `Deny` (explicit). Same as
    /// unset, but operators sometimes set this defensively in
    /// CI/CD env so they can `grep` for the policy.
    #[test]
    fn enforce_mode_from_env_explicit_deny_is_deny() {
        assert_eq!(EnforceMode::from_env_value(Some("deny")), EnforceMode::Deny);
    }

    /// Unknown values (typo, future-mode-from-2.5 like `"off"`, etc.)
    /// must fall back to `Deny` so a misconfiguration NEVER silently
    /// weakens the posture. A `tracing::warn` surfaces the
    /// fallback; we don't assert on that here (the tracing
    /// subscriber would need to be wired up), but the fail-closed
    /// behavior is the load-bearing guarantee.
    #[test]
    fn enforce_mode_from_env_unknown_value_falls_back_to_deny() {
        assert_eq!(
            EnforceMode::from_env_value(Some("off")),
            EnforceMode::Deny,
            "unknown values must fail-closed to Deny — never silently weaken the posture",
        );
        assert_eq!(EnforceMode::from_env_value(Some("DENY")), EnforceMode::Deny);
        assert_eq!(EnforceMode::from_env_value(Some("typo")), EnforceMode::Deny);
        assert_eq!(EnforceMode::from_env_value(Some("")), EnforceMode::Deny);
    }
}
