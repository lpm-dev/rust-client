//! Virtual-store-aware linker.
//!
//! Sits next to v1's [`crate::link_packages`] /
//! [`crate::link_packages_hoisted`] and is selected via
//! `LPM_STORE_VERSION=v2`. Instead of materializing per-project
//! wrappers under `<project>/.lpm/wrappers/<segment>/node_modules/<pkg>/`,
//! the v2 linker:
//!
//! 1. Wipes any v1-style project link state
//!    (`<project>/.lpm/wrappers/`, `<project>/.lpm/hoisted/`).
//! 2. Derives a [`GraphKey`] for every [`LinkTarget`] in the install
//!    set so cross-references between targets resolve to stable
//!    graph-key directory names.
//! 3. Calls [`Store::populate_link_entry`] per target, which clonefiles
//!    the package bytes from `objects/<sri>/` into
//!    `links/<graph-key>/node_modules/<name>/` and writes sibling
//!    dep + peer symlinks alongside.
//! 4. Writes project-side `node_modules/<root_link_name>` symlinks
//!    pointing into the materialized link entries.
//! 5. Generates `.bin/` shims by walking the project-side symlinks —
//!    same shape as v1's, but resolving through v2 paths.
//!
//! # Peer-context
//!
//! Each [`LinkTarget`] carries `peers: Vec<(String, String)>`
//! threaded through from the resolver
//! (`ResolvedPackage.peers` → `InstallPackage.peers` →
//! `LinkTarget.peers`). The linker uses these to:
//!
//! - Synthesize peer-edge sibling symlinks INSIDE each link entry
//!   (a peer is `<links/A-key>/node_modules/<peer>` → symlink to
//!   `<links/peer-key>/node_modules/<peer>/`). Without this,
//!   Node's symlink-walk-up from inside the link entry never
//!   reaches the peer.
//! - Fold the peer-context into [`GraphKey`] via
//!   `GraphKeyInputs::with_peers`, so two projects sharing the same
//!   edge graph but different peer pinning produce distinct keys.
//!   Without this, cross-project sharing of `links/<key>/` would be
//!   incorrect for any package whose peer resolution depends on
//!   the consuming project's other packages.
//!
//! Current-schema lockfiles persist `LinkTarget.peers`, including
//! meaningful empty sets for packages without resolved peers. Older
//! callers that arrive with unknown peer context can still fall back
//! to deriving it from the just-extracted `package.json` in
//! `objects/<sri>/` and intersecting with the install-set's `(name,
//! version)` map. That fallback requires the object directory to
//! exist before plan preparation.
//!
//! # Multi-source disambiguation
//!
//! The internal key map keys by `(name, version, wrapper_id)`, not
//! `(name, version)`. Two `LinkTarget`s with the same `(name,
//! version)` but different sources (e.g., one `Source::Registry` +
//! one `Source::Tarball` distinguished by `wrapper_id`) get
//! distinct GraphKeys via `with_root_link_names` + the dep-edge
//! disambiguation that flows from each target's own `wrapper_id`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::LpmError;
use lpm_store::v2::{
    DepLink, ExtractedObject, GraphKey, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag,
    PlatformTuple, Store, VerifiedObjectIntegrity,
};

use crate::validation::is_safe_node_modules_entry_name as is_safe_root_link_name;
use crate::{LinkResult, LinkTarget, LinkerMode, MaterializedPackage};

mod bin_shims;
mod compat_island;
mod keymap;
mod reconcile;

use self::bin_shims::create_bin_links_v2;
pub use self::compat_island::project_compatibility_bins_ready;
use self::compat_island::{create_project_compatibility_links, normalize_compatibility_bin_names};
pub use self::keymap::KeyMap;
use self::keymap::derive_graph_keys;
#[cfg(test)]
use self::reconcile::symlink_points_to;
use self::reconcile::{
    cleanup_v1_state, create_root_symlinks, create_self_ref, ensure_real_dir,
    reconcile_project_node_modules,
};

/// One LinkTarget plus the source SRI needed to resolve its v2 object
/// directory. The install pipeline carries the SRI via
/// [`crate::v2::TargetSource::sri`]; v2 looks it up to compute
/// `<HOME>/.lpm/store/v2/objects/<sri>/`.
#[derive(Debug, Clone)]
pub struct V2Target {
    /// Same identity surface as v1.
    pub target: LinkTarget,
    /// SRI of the source tarball. Required to locate the object dir
    /// at `<HOME>/.lpm/store/v2/objects/<sri>/`.
    pub source_sri: String,
    /// Verified object digest available on warm cache hits.
    pub verified_object_integrity: Option<VerifiedObjectIntegrity>,
    /// Object produced by the extraction path for immediate link-populate.
    /// Warm cache paths cannot construct this value, so they leave it empty
    /// and use populate-time object validation.
    pub fresh_object: Option<ExtractedObject>,
}

/// Pre-computed plan handed across the three-phase v2 link API
/// ([`link_v2_prepare`] → [`link_v2_one`] → [`link_v2_finalize`]).
///
/// **Why three phases.** A single-entry linker would have to wait for
/// the entire fetch barrier before starting any link work. With the
/// plan precomputed once, per-package [`link_v2_one`] tasks can spawn
/// as each object materializes — overlapping link wall-time with the
/// fetch loop instead of accumulating it on the critical path.
///
/// [`link_packages_v2`] drives all three phases internally and stays
/// as the contract for callers (tests, non-event-driven install paths)
/// that don't want to thread per-pkg dispatch.
pub struct LinkPlanV2 {
    /// Targets after [`ensure_peer_context`] resolved any missing
    /// peer-context (lockfile fast-path fallback). The same slice
    /// downstream phases iterate.
    pub augmented_targets: Vec<V2Target>,
    /// `(name, version, wrapper_id) → GraphKey` lookup table populated
    /// by [`derive_graph_keys`]. Read-only for the per-package and
    /// finalize phases.
    pub key_map: KeyMap,
    /// Host platform tuple stamped into every sidecar.
    pub platform: PlatformTuple,
    /// Pre-built `Arc<LinkMetaPlatform>` shared by every [`link_v2_one`]
    /// call. Built once in [`link_v2_prepare`]; cloning is a single atomic
    /// refcount bump instead of 3 string allocations per package.
    pub meta_platform: Arc<LinkMetaPlatform>,
    /// Linker-mode tag — propagates into [`LinkerModeTag`] for
    /// per-target graph-key derivation in case any caller wants to
    /// re-derive a key after prepare (none today, but the plan is
    /// authoritative).
    pub linker_mode: LinkerMode,
    compatibility_bin_names: Vec<String>,
}

impl LinkPlanV2 {
    /// Are all targets ready for the event-driven path? True iff every
    /// `LinkTarget.peers` is already populated (resolver-threaded
    /// greedy-fusion path) and `ensure_peer_context` made no
    /// modifications. This helper cannot distinguish current-schema
    /// lockfiles whose empty peer sets are authoritative from legacy
    /// callers whose empty peer sets are unknown; install.rs therefore
    /// gates those lockfile fast paths with the lockfile schema
    /// version. When peer context is unknown, callers should fall back
    /// to the serial wrapper [`link_packages_v2`] — deriving peers from
    /// `objects/<sri>/package.json` requires the object to be
    /// extracted before [`link_v2_prepare`] runs.
    pub fn all_targets_have_resolver_threaded_peers(targets: &[V2Target]) -> bool {
        // Empty install set is event-driven-safe (zero work to dispatch).
        // Targets with declared peers but resolver-empty peers indicate
        // the lockfile-fast-path; those need ensure_peer_context to
        // read from extracted package.json — incompatible with the
        // pre-fetch prepare phase.
        targets.iter().all(|v2t| {
            // A target has "no peer context required" iff it either
            // has populated peers OR its package declares zero peer
            // dependencies. We can't cheaply prove the latter without
            // reading package.json, so be conservative: only the
            // resolver-threaded shape qualifies.
            !v2t.target.peers.is_empty() || target_declares_no_peers(&v2t.target)
        })
    }
}

/// Heuristic: does this target carry no peer-context information that
/// `ensure_peer_context` would need to discover? Today the only signal
/// available without disk I/O is `peers.is_empty()` plus a "best-effort
/// trust-the-resolver" path. Used by
/// [`LinkPlanV2::all_targets_have_resolver_threaded_peers`] to gate
/// the event-driven dispatch.
fn target_declares_no_peers(_target: &LinkTarget) -> bool {
    // Conservative default: if the resolver didn't thread peers, we
    // can't tell whether the package declares peers without reading
    // its package.json. Return false so the caller falls back to the
    // serial path.
    false
}

/// Materialize the install set under the v2 store layout.
///
/// Returns a [`LinkResult`] in the same shape v1 produces so the
/// install pipeline's reporting / lockfile-write paths don't branch.
/// Counts:
/// - `linked`: number of link entries newly populated this call.
/// - `symlinked`: number of project-side `node_modules/<root>` symlinks created.
/// - `bin_linked`: number of `.bin/<cmd>` shims created.
/// - `self_referenced`: `true` iff a `node_modules/<self_pkg_name>`
///   symlink to the project root was created.
/// - `materialized`: vector of [`MaterializedPackage`] entries.
pub fn link_packages_v2(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    self_package_name: Option<&str>,
) -> Result<LinkResult, LpmError> {
    link_packages_v2_with_compatibility_bin_names(
        project_dir,
        targets,
        store,
        linker_mode,
        self_package_name,
        &[],
    )
}

/// Materialize the v2 install set and project-local compatibility islands
/// for the direct packages that own the requested binary names.
pub fn link_packages_v2_with_compatibility_bin_names(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    self_package_name: Option<&str>,
    compatibility_bin_names: &[String],
) -> Result<LinkResult, LpmError> {
    if targets.is_empty() {
        return Ok(LinkResult {
            linked: 0,
            symlinked: 0,
            bin_linked: 0,
            skipped: 0,
            self_referenced: false,
            materialized: Vec::new(),
        });
    }

    let plan = link_v2_prepare_with_compatibility_bin_names(
        project_dir,
        targets,
        store,
        linker_mode,
        compatibility_bin_names,
    )?;
    let augmented_slice = &plan.augmented_targets[..];

    // Materialize link entries in parallel for installs above the
    // threshold.
    //
    // **Atomicity invariant.** `populate_link_entry` already serializes
    // concurrent writers via atomic-rename — two threads racing on the
    // same graph_key both write into a tmp sibling and one's `rename`
    // wins; the loser observes the completed final dir on its second
    // probe and short-circuits. No external lock needed.
    //
    // **Threshold.** Rayon's global thread pool spin-up cost is
    // measurable (~3-5 ms first call); for small installs the
    // sequential loop is cheaper. 32 is the cross-over point on
    // macOS APFS — below that, the thread-pool overhead exceeds
    // the parallelism gain.
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const PARALLEL_THRESHOLD: usize = 32;

    let linked_count_atomic = AtomicUsize::new(0);
    let materialized_results: Vec<Result<MaterializedPackage, LpmError>> =
        if augmented_slice.len() > PARALLEL_THRESHOLD {
            augmented_slice
                .par_iter()
                .map(|v2t| {
                    let (mat, fresh) = link_v2_one(&plan, v2t, store)?;
                    if fresh {
                        linked_count_atomic.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(mat)
                })
                .collect()
        } else {
            augmented_slice
                .iter()
                .map(|v2t| {
                    let (mat, fresh) = link_v2_one(&plan, v2t, store)?;
                    if fresh {
                        linked_count_atomic.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(mat)
                })
                .collect()
        };
    let materialized: Vec<MaterializedPackage> =
        materialized_results.into_iter().collect::<Result<_, _>>()?;
    let linked_count = linked_count_atomic.into_inner();

    let finalize = link_v2_finalize_inner(project_dir, &plan, store, self_package_name, false)?;

    Ok(LinkResult {
        linked: linked_count,
        symlinked: finalize.symlinked,
        bin_linked: finalize.bin_count,
        skipped: augmented_slice.len().saturating_sub(linked_count),
        self_referenced: finalize.self_referenced,
        materialized,
    })
}

/// Recreate only the project-side v2 wiring for link entries that
/// already exist.
///
/// Used after lifecycle scripts mutate a materialized package. Unlike
/// [`link_packages_v2_with_compatibility_bin_names`], this path never
/// calls `Store::populate_link_entry`, so generated files written by a
/// build step are still present when `.bin` shims are refreshed.
pub fn finalize_existing_link_entries_with_compatibility_bin_names(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    self_package_name: Option<&str>,
    compatibility_bin_names: &[String],
) -> Result<LinkResult, LpmError> {
    if targets.is_empty() {
        return Ok(LinkResult {
            linked: 0,
            symlinked: 0,
            bin_linked: 0,
            skipped: 0,
            self_referenced: false,
            materialized: Vec::new(),
        });
    }

    let plan = link_v2_prepare_with_compatibility_bin_names(
        project_dir,
        targets,
        store,
        linker_mode,
        compatibility_bin_names,
    )?;
    let materialized = existing_link_entry_packages(&plan, store)?;
    let skipped = plan.augmented_targets.len();
    let finalize = link_v2_finalize_inner(project_dir, &plan, store, self_package_name, true)?;

    Ok(LinkResult {
        linked: 0,
        symlinked: finalize.symlinked,
        bin_linked: finalize.bin_count,
        skipped,
        self_referenced: finalize.self_referenced,
        materialized,
    })
}

/// Step 1 of the event-driven v2 link API.
///
/// Runs the post-resolve, pre-fetch sync work that the install pipeline
/// can complete without any object on disk:
/// 1. [`cleanup_v1_state`] — wipes legacy `<project>/.lpm/wrappers/`
///    and `<project>/.lpm/hoisted/` state. Project `node_modules`
///    root entries are reconciled during finalize.
/// 2. [`ensure_peer_context`] — best-effort fill-in for targets whose
///    [`LinkTarget::peers`] arrived empty. Reads `package.json` from
///    extracted `objects/<sri>/`. Pre-fetch callers that already have
///    authoritative peer context should use
///    [`link_v2_prepare_with_authoritative_peer_context`] instead of
///    doing this disk fallback.
/// 3. [`derive_graph_keys`] — computes the
///    `(name, version, wrapper_id) → GraphKey` map. Pure compute over
///    in-memory targets, no I/O. Multi-source-same-coords collisions
///    surface as a hard error here.
///
/// Returns a [`LinkPlanV2`] handed by reference into the per-package
/// and finalize phases.
pub fn link_v2_prepare(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
) -> Result<LinkPlanV2, LpmError> {
    link_v2_prepare_with_compatibility_bin_names(project_dir, targets, store, linker_mode, &[])
}

/// Step 1 of the event-driven v2 link API with requested compatibility
/// roots derived from project script binary names.
pub fn link_v2_prepare_with_compatibility_bin_names(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    compatibility_bin_names: &[String],
) -> Result<LinkPlanV2, LpmError> {
    link_v2_prepare_inner(
        project_dir,
        targets,
        store,
        linker_mode,
        PeerContextMode::DeriveMissing,
        compatibility_bin_names,
    )
}

/// Step 1 of the event-driven v2 link API when the caller has already
/// supplied authoritative per-target peer context.
///
/// This is for current-schema lockfile warm installs: the lockfile
/// records resolved peers for each package, and an empty list means
/// "no resolved peers" rather than "unknown". Skipping
/// [`ensure_peer_context`] avoids reading and pre-scanning
/// `objects/<sri>/package.json` for every no-peer package on the warm
/// path.
pub fn link_v2_prepare_with_authoritative_peer_context(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
) -> Result<LinkPlanV2, LpmError> {
    link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
        project_dir,
        targets,
        store,
        linker_mode,
        &[],
    )
}

/// Step 1 of the event-driven v2 link API with authoritative peer context
/// and requested compatibility roots derived from project script binary names.
pub fn link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    compatibility_bin_names: &[String],
) -> Result<LinkPlanV2, LpmError> {
    link_v2_prepare_inner(
        project_dir,
        targets,
        store,
        linker_mode,
        PeerContextMode::TrustTargets,
        compatibility_bin_names,
    )
}

enum PeerContextMode {
    DeriveMissing,
    TrustTargets,
}

fn link_v2_prepare_inner(
    project_dir: &Path,
    targets: Vec<V2Target>,
    store: &Store,
    linker_mode: LinkerMode,
    peer_context: PeerContextMode,
    compatibility_bin_names: &[String],
) -> Result<LinkPlanV2, LpmError> {
    // Top-level linker-stage span. Visible in Tracy with
    // `--features tracy`; filtered at INFO level so it's essentially
    // free in regular builds.
    let _span = tracing::info_span!("linker.prepare", target_count = targets.len(),).entered();
    cleanup_v1_state(project_dir)?;
    let mut augmented_targets = targets;
    if matches!(peer_context, PeerContextMode::DeriveMissing) {
        ensure_peer_context(&mut augmented_targets, store)?;
    }
    let platform = PlatformTuple::current();
    let linker_tag = match linker_mode {
        LinkerMode::Isolated => LinkerModeTag::Isolated,
        LinkerMode::Hoisted => LinkerModeTag::Hoisted,
    };
    let key_map = derive_graph_keys(&augmented_targets[..], &platform, linker_tag)?;
    let meta_platform = Arc::new(LinkMetaPlatform {
        os: platform.os.clone(),
        cpu: platform.cpu.clone(),
        libc: platform.libc.clone(),
    });
    Ok(LinkPlanV2 {
        augmented_targets,
        key_map,
        platform,
        meta_platform,
        linker_mode,
        compatibility_bin_names: normalize_compatibility_bin_names(compatibility_bin_names),
    })
}

/// Step 2 of the event-driven v2 link API.
///
/// Materializes a single link entry in `~/.lpm/store/v2/links/<key>/`
/// from a precomputed [`LinkPlanV2`]. Idempotent — concurrent calls
/// for the same graph key serialize through the v2 store's
/// atomic-rename machinery.
///
/// Returns `(MaterializedPackage, freshly_populated)` so the caller can
/// distinguish cache hits from new materializations for telemetry.
/// Safe to call from any thread; safe to call concurrently for
/// distinct targets.
///
/// **Object precondition.** `<store>/objects/<source_sri>/` must already
/// be populated by `Store::extract_object_from_bytes` before this
/// function is called for `target`. Calling earlier returns an error
/// from `populate_link_entry`'s clonefile step.
pub fn link_v2_one(
    plan: &LinkPlanV2,
    target: &V2Target,
    store: &Store,
) -> Result<(MaterializedPackage, bool), LpmError> {
    link_v2_one_with_timings(plan, target, store)
        .map(|(materialized, freshly_populated, _)| (materialized, freshly_populated))
}

pub fn link_v2_one_with_timings(
    plan: &LinkPlanV2,
    target: &V2Target,
    store: &Store,
) -> Result<(MaterializedPackage, bool, lpm_store::v2::LinkEntryTimings), LpmError> {
    // Per-package span. Records name+version so Tracy can attribute
    // time to specific slow packages.
    let _span = tracing::info_span!(
        "linker.one",
        name = %target.target.name,
        version = %target.target.version,
    )
    .entered();
    let entry = populate_one(target, store, &plan.key_map, &plan.meta_platform)?;
    let mat = MaterializedPackage {
        name: target.target.name.clone(),
        version: target.target.version.clone(),
        destination: store.paths().link_package_dir(&entry.key),
    };
    Ok((mat, entry.freshly_populated, entry.timings))
}

/// Result handle for [`link_v2_finalize`] — separated from
/// [`LinkResult`] so the caller assembles the final result with its
/// own `linked` / `materialized` counts (which the per-package phase
/// owns).
pub struct LinkV2FinalizeResult {
    /// Number of `<project>/node_modules/<root>` symlinks written.
    pub symlinked: usize,
    /// Number of `<project>/node_modules/.bin/<cmd>` shims written.
    pub bin_count: usize,
    /// Whether `<project>/node_modules/<self_pkg_name>` was created.
    pub self_referenced: bool,
    /// Time spent reconciling stale root entries.
    pub reconcile_ms: u128,
    /// Time spent writing project root symlinks.
    pub root_symlinks_ms: u128,
    /// Time spent preparing compatibility links.
    pub compatibility_ms: u128,
    /// Time spent writing `.bin` shims.
    pub bin_shims_ms: u128,
}

/// Step 3 of the event-driven v2 link API.
///
/// Runs the post-fetch sequential project-side wiring:
/// 1. Project root symlinks (one per `root_link_names` per direct dep).
/// 2. `.bin/` shims — read each direct dep's `package.json` from the
///    materialized link entry, write per-command shims.
/// 3. Self-reference symlink at `<project>/node_modules/<self>` → project
///    root, when `self_package_name` is `Some`.
///
/// Must be called AFTER all [`link_v2_one`] calls for `plan` complete —
/// the bin-shim pass reads `package.json` from inside each link entry,
/// which only exists once `populate_link_entry` finishes.
pub fn link_v2_finalize(
    project_dir: &Path,
    plan: &LinkPlanV2,
    store: &Store,
    self_package_name: Option<&str>,
) -> Result<LinkV2FinalizeResult, LpmError> {
    link_v2_finalize_inner(project_dir, plan, store, self_package_name, false)
}

fn link_v2_finalize_inner(
    project_dir: &Path,
    plan: &LinkPlanV2,
    store: &Store,
    self_package_name: Option<&str>,
    refresh_compatibility_copies: bool,
) -> Result<LinkV2FinalizeResult, LpmError> {
    // Finalize-stage span. Nested sub-stages below split root /
    // bin / self-ref so the Tracy breakdown shows which phase
    // dominates for a given install.
    let _span = tracing::info_span!(
        "linker.finalize",
        target_count = plan.augmented_targets.len(),
    )
    .entered();
    let augmented_slice = &plan.augmented_targets[..];
    let stage_timer = std::time::Instant::now();
    reconcile_project_node_modules(project_dir, augmented_slice, self_package_name, true)?;
    let reconcile_ms = stage_timer.elapsed().as_millis();
    let stage_timer = std::time::Instant::now();
    let symlinked = {
        let _s = tracing::info_span!("linker.finalize.root_symlinks").entered();
        create_root_symlinks(project_dir, augmented_slice, store, &plan.key_map)?
    };
    let root_symlinks_ms = stage_timer.elapsed().as_millis();
    let stage_timer = std::time::Instant::now();
    let compatibility_links = {
        let _s = tracing::info_span!("linker.finalize.compatibility").entered();
        create_project_compatibility_links(
            project_dir,
            augmented_slice,
            store,
            &plan.key_map,
            &plan.compatibility_bin_names,
            refresh_compatibility_copies,
        )?
    };
    let compatibility_ms = stage_timer.elapsed().as_millis();
    let stage_timer = std::time::Instant::now();
    let bin_count = {
        let _s = tracing::info_span!("linker.finalize.bin_shims").entered();
        create_bin_links_v2(
            project_dir,
            augmented_slice,
            store,
            &plan.key_map,
            &compatibility_links,
        )?
    };
    let bin_shims_ms = stage_timer.elapsed().as_millis();
    let self_referenced = if let Some(self_name) = self_package_name {
        create_self_ref(project_dir, self_name)?
    } else {
        false
    };
    Ok(LinkV2FinalizeResult {
        symlinked,
        bin_count,
        self_referenced,
        reconcile_ms,
        root_symlinks_ms,
        compatibility_ms,
        bin_shims_ms,
    })
}

/// Make sure every target in the install set has its
/// `LinkTarget.peers` populated.
///
/// Trust order:
/// - If a target arrives with non-empty `peers`, the resolver
///   already supplied authoritative peer-context — leave it alone.
/// - Otherwise (lockfile fast-path, hand-built test fixtures,
///   migration-state installs), derive peers locally by reading the
///   target's `package.json` from `<store>/objects/<sri>/` and
///   intersecting `peerDependencies` against the install set's
///   resolved versions.
///
/// `peerDependenciesMeta.optional` controls log behavior on a
/// missing peer:
/// - Optional peer not in install set → silent skip (npm-compat).
/// - Required peer not in install set → debug-level trace pointing
///   at the upstream `check_unmet_peers` gap.
///
/// We do NOT close the peer set transitively here. The resolver's
/// per-package peer view already encodes the in-scope set for each
/// consumer; once the v2 linker creates a sibling symlink for each
/// peer, that peer's OWN link entry has its own peer siblings
/// materialized when its turn comes through the loop. Node's
/// symlink-walk-up from inside the consumer's link entry reaches
/// the consumer's siblings, and from inside the peer's package dir
/// (post-symlink-resolve) reaches the peer's own siblings. The
/// transitive closure is encoded in the per-target loop, not in
/// per-target peer edges.
fn ensure_peer_context(targets: &mut [V2Target], store: &Store) -> Result<(), LpmError> {
    // Build a name → version lookup so the fallback derivation can
    // intersect declared peers against the install set. Multi-source
    // same-name disambiguation flows through wrapper_id at the GraphKey
    // level.
    let mut by_name: HashMap<String, String> = HashMap::with_capacity(targets.len());
    for v2t in targets.iter() {
        by_name
            .entry(v2t.target.name.clone())
            .or_insert_with(|| v2t.target.version.clone());
    }

    // Scratch `PathBuf` reused across per-package `package.json`
    // paths — the naïve `object_dir.join("package.json")` allocates
    // per iteration; sharing a single cleared+pushed buffer reuses
    // the underlying capacity.
    let mut pkg_json_path = PathBuf::with_capacity(256);
    for v2t in targets.iter_mut() {
        if !v2t.target.peers.is_empty() {
            // Resolver-threaded — trust it.
            continue;
        }
        let object_dir = store.paths().object_dir(&v2t.source_sri)?;
        pkg_json_path.clear();
        pkg_json_path.push(&object_dir);
        pkg_json_path.push("package.json");

        // Read once; treat I/O failure as "no peer deps" (equivalent to the
        // old `exists()` check but saves one stat(2) syscall per package).
        let content = match std::fs::read(&pkg_json_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: skipping peer derivation for {}@{}: {e}",
                    v2t.target.name,
                    v2t.target.version
                );
                continue;
            }
        };

        // Fast byte pre-scan to avoid serde_json parse (hundreds of
        // allocs) for packages that declare no peer deps — the
        // common case. The needle "peerDependencies" matches both
        // "peerDependencies" and "peerDependenciesMeta", so false
        // negatives are impossible.
        const PEER_KEY: &[u8] = b"peerDependencies";
        if !content.windows(PEER_KEY.len()).any(|w| w == PEER_KEY) {
            continue;
        }

        let (peer_deps, peer_deps_meta) = match lpm_workspace::parse_peer_dependencies(&content) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: failed to parse {}/package.json for peer derivation: {e}",
                    object_dir.display()
                );
                continue;
            }
        };
        if peer_deps.is_empty() {
            continue;
        }
        let mut derived: Vec<(String, String)> = Vec::new();
        for peer_name in peer_deps.keys() {
            let is_optional = peer_deps_meta
                .get(peer_name)
                .is_some_and(|meta| meta.optional);
            match by_name.get(peer_name) {
                Some(ver) => derived.push((peer_name.clone(), ver.clone())),
                None if !is_optional => {
                    tracing::debug!(
                        "v2 linker: REQUIRED peer dep {peer_name} of {}@{} not in install set — \
                         resolver should have caught this in check_unmet_peers",
                        v2t.target.name,
                        v2t.target.version
                    );
                }
                None => {
                    // Optional peer not in install set — silent skip.
                }
            }
        }
        // Sorted for deterministic GraphKey hashing — must match the
        // sort applied by the resolver-threaded path.
        derived.sort_by(|a, b| a.0.cmp(&b.0));
        v2t.target.peers = derived;
    }
    Ok(())
}

/// Result handle for a single populated link entry — keeps the key
/// alongside `freshly_populated` so the caller doesn't have to
/// re-derive it for `materialized` reporting.
struct PopulatedEntry {
    key: Arc<GraphKey>,
    freshly_populated: bool,
    timings: lpm_store::v2::LinkEntryTimings,
}

fn populate_one(
    v2t: &V2Target,
    store: &Store,
    key_map: &KeyMap,
    meta_platform: &Arc<LinkMetaPlatform>,
) -> Result<PopulatedEntry, LpmError> {
    let key = key_map.get_for(&v2t.target).cloned().ok_or_else(|| {
        LpmError::Store(format!(
            "v2 linker: missing graph key for {}@{} (key map pre-pass failed)",
            v2t.target.name, v2t.target.version
        ))
    })?;

    let object_dir = store.paths().object_dir(&v2t.source_sri)?;

    // Dep edges resolve through the alias map (consumer's local name
    // may differ from the canonical target). Peer edges always use
    // the canonical name as the local (peers are never npm-aliased
    // — `peerDependencies` keys ARE the canonical name by spec).
    let mut deps: Vec<DepLink> =
        Vec::with_capacity(v2t.target.dependencies.len() + v2t.target.peers.len());
    for dep in &v2t.target.dependencies {
        if !is_safe_root_link_name(&dep.local) {
            tracing::warn!(
                "v2 linker: skipping unsafe dependency local name {:?} for {}@{}",
                dep.local,
                v2t.target.name,
                v2t.target.version
            );
            continue;
        }
        let dep_key = key_map
            .get_for_dependency(dep)
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: dep {}=>{}@{} of {}@{} has no resolved graph key",
                    dep.local,
                    dep.target_name,
                    dep.graph_key_value(),
                    v2t.target.name,
                    v2t.target.version
                ))
            })?
            .clone();
        deps.push(DepLink {
            local: dep.local.clone(),
            target: dep_key,
        });
    }
    // Peer-edge siblings. Each resolved peer becomes a sibling
    // symlink in the consumer's link entry — without this, Node's
    // walk-up from the consumer's package dir never reaches the
    // peer (v2 link entries are absolute paths into the global
    // store, not the project tree).
    // Skip the HashSet construction entirely when there are no peers —
    // the common case for most packages. For the peer case, build
    // already_local as &str (no clone) then drop before mutating deps.
    if !v2t.target.peers.is_empty() {
        let peer_extras: Vec<DepLink> = {
            let already_local: std::collections::HashSet<&str> =
                deps.iter().map(|d| d.local.as_str()).collect();
            v2t.target
                .peers
                .iter()
                .filter(|(peer_name, _)| {
                    if is_safe_root_link_name(peer_name) {
                        true
                    } else {
                        tracing::warn!(
                            "v2 linker: skipping unsafe peer local name {:?} for {}@{}",
                            peer_name,
                            v2t.target.name,
                            v2t.target.version
                        );
                        false
                    }
                })
                .filter(|(peer_name, _)| !already_local.contains(peer_name.as_str()))
                .filter_map(|(peer_name, peer_ver)| {
                    let peer_key = key_map.get_peer(peer_name, peer_ver)?.clone();
                    Some(DepLink {
                        local: peer_name.clone(),
                        target: peer_key,
                    })
                })
                .collect()
            // already_local (borrows from deps) is dropped here, before
            // deps is mutated by extend below.
        };
        deps.extend(peer_extras);
    }

    let request = LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: v2t.source_sri.clone(),
        object_dir,
        deps,
        platform: Arc::clone(meta_platform),
    };
    let entry = match (
        v2t.fresh_object.as_ref(),
        v2t.verified_object_integrity.as_ref(),
    ) {
        (Some(object), _) => store.populate_link_entry_with_fresh_object(request, object)?,
        (None, Some(digest)) => store.populate_link_entry_with_verified_object(request, digest)?,
        (None, None) => store.populate_link_entry(request)?,
    };
    Ok(PopulatedEntry {
        key,
        freshly_populated: entry.freshly_populated,
        timings: entry.timings,
    })
}

fn existing_link_entry_packages(
    plan: &LinkPlanV2,
    store: &Store,
) -> Result<Vec<MaterializedPackage>, LpmError> {
    let links_root = store.paths().links_root();
    let canonical_links_root = std::fs::canonicalize(&links_root).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to inspect links root at {}: {e}",
            links_root.display()
        ))
    })?;

    let mut materialized = Vec::with_capacity(plan.augmented_targets.len());
    for v2t in &plan.augmented_targets {
        let key = plan.key_map.get_for(&v2t.target).ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: missing graph key for {}@{} during existing-link validation",
                v2t.target.name, v2t.target.version
            ))
        })?;
        let package_dir = store.paths().link_package_dir(key);
        ensure_existing_link_package_dir(
            &package_dir,
            &canonical_links_root,
            &v2t.target.name,
            &v2t.target.version,
        )?;
        materialized.push(MaterializedPackage {
            name: v2t.target.name.clone(),
            version: v2t.target.version.clone(),
            destination: package_dir,
        });
    }
    Ok(materialized)
}

fn ensure_existing_link_package_dir(
    package_dir: &Path,
    canonical_links_root: &Path,
    name: &str,
    version: &str,
) -> Result<(), LpmError> {
    let canonical_package_dir = std::fs::canonicalize(package_dir).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: required link entry for {name}@{version} is missing at {}: {e}",
            package_dir.display()
        ))
    })?;
    if !canonical_package_dir.starts_with(canonical_links_root) {
        return Err(LpmError::Store(format!(
            "v2 linker: refusing existing link entry for {name}@{version} because {} resolves outside {}",
            package_dir.display(),
            canonical_links_root.display()
        )));
    }
    ensure_real_dir(package_dir, "existing link package")?;

    let mut package_json = PathBuf::with_capacity(package_dir.as_os_str().len() + 13);
    package_json.push(package_dir);
    package_json.push("package.json");
    let metadata = std::fs::symlink_metadata(&package_json).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: required package.json for {name}@{version} is missing at {}: {e}",
            package_json.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LpmError::Store(format!(
            "v2 linker: refusing existing link entry for {name}@{version} with non-file package.json at {}",
            package_json.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
