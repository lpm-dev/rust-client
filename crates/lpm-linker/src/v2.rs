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

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::LpmError;
use lpm_common::symlink::create_dir_symlink_or_junction;
use lpm_store::v2::{
    DepLink, GraphKey, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag, PlatformTuple, Store,
};

use crate::materialize::link_dir_recursive;
#[cfg(unix)]
use crate::platform::make_bin_target_executable;
use crate::validation::{
    ensure_real_dir_with_prefix, is_safe_node_modules_entry_name as is_safe_root_link_name,
    validate_bin_target,
};
use crate::{
    LinkDependency, LinkResult, LinkTarget, LinkerMode, MaterializedPackage, validate_bin_name,
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
    Ok((mat, entry.freshly_populated))
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
    reconcile_project_node_modules(
        project_dir,
        augmented_slice,
        self_package_name,
        !plan.compatibility_bin_names.is_empty(),
    )?;
    let symlinked = {
        let _s = tracing::info_span!("linker.finalize.root_symlinks").entered();
        create_root_symlinks(project_dir, augmented_slice, store, &plan.key_map)?
    };
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
    let bin_count = {
        let _s = tracing::info_span!("linker.finalize.bin_shims").entered();
        clear_bin_dir(project_dir)?;
        create_bin_links_v2(
            project_dir,
            augmented_slice,
            store,
            &plan.key_map,
            &compatibility_links,
        )?
    };
    let self_referenced = if let Some(self_name) = self_package_name {
        create_self_ref(project_dir, self_name)?
    } else {
        false
    };
    Ok(LinkV2FinalizeResult {
        symlinked,
        bin_count,
        self_referenced,
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
    let entry = store.populate_link_entry(request)?;
    Ok(PopulatedEntry {
        key,
        freshly_populated: entry.freshly_populated,
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

/// Per-install lookup table from `(name, version, wrapper_id)` to the
/// derived `GraphKey`.
///
/// Built once during [`link_v2_prepare`], stored on [`LinkPlanV2`],
/// consulted by every [`link_v2_one`] / [`link_v2_finalize`] call.
/// Public so callers can hold a reference across spawn boundaries
/// without reaching into linker private API.
///
/// Two lookup indexes plus one duplicate guard:
/// - `by_triple` — full `(name, version, wrapper_id)` identity. Used
///   by `populate_one` to fetch this target's own key and to resolve
///   source-aware dependency edges.
/// - `by_coords` — `(name, version)` only. Used only when the install
///   graph has a single unambiguous package at those coordinates.
/// - `source_identities` — `(name, wrapper_id)` guard so one source
///   identity cannot appear twice with diverging versions.
///
/// Keys are stored as a single `String` using a `\x00`-separated
/// compound key: `"name\x00version"` for `by_coords` and
/// `"name\x00version\x00wrapper_id"` for `by_triple`. Package names
/// and versions never contain null bytes, so there is no collision risk.
/// This lets lookups form the key with a single `format!` call (1 alloc)
/// instead of cloning each field separately (2–3 allocs per lookup).
pub struct KeyMap {
    by_triple: HashMap<String, Arc<GraphKey>>,
    by_coords: HashMap<String, CoordEntry>,
}

enum CoordEntry {
    Single(Arc<GraphKey>),
    Ambiguous,
}

/// Form the `by_coords` key: `"name\x00version"`.
#[inline]
fn coords_key(name: &str, version: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + version.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key
}

/// Form the `by_triple` key: `"name\x00version\x00wrapper_id"`.
#[inline]
fn triple_key(name: &str, version: &str, wrapper_id: Option<&str>) -> String {
    let wid = wrapper_id.unwrap_or("");
    let mut key = String::with_capacity(name.len() + 1 + version.len() + 1 + wid.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key.push('\x00');
    key.push_str(wid);
    key
}

#[inline]
fn name_wrapper_key(name: &str, wrapper_id: &str) -> String {
    let mut key = String::with_capacity(name.len() + 1 + wrapper_id.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(wrapper_id);
    key
}

impl KeyMap {
    fn get_for(&self, target: &LinkTarget) -> Option<&Arc<GraphKey>> {
        self.by_triple.get(&triple_key(
            &target.name,
            &target.version,
            target.wrapper_id.as_deref(),
        ))
    }

    fn get_for_dependency(&self, dep: &LinkDependency) -> Option<&Arc<GraphKey>> {
        self.by_triple
            .get(&triple_key(
                &dep.target_name,
                &dep.target_version,
                dep.target_wrapper_id.as_deref(),
            ))
            .or_else(|| {
                if dep.target_wrapper_id.is_none() {
                    self.get_by_coords_unambiguous(&dep.target_name, &dep.target_version)
                } else {
                    None
                }
            })
    }

    fn get_peer(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        self.by_triple
            .get(&triple_key(name, version, None))
            .or_else(|| self.get_by_coords_unambiguous(name, version))
    }

    fn get_by_coords_unambiguous(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        match self.by_coords.get(&coords_key(name, version)) {
            Some(CoordEntry::Single(gk)) => Some(gk),
            Some(CoordEntry::Ambiguous) | None => None,
        }
    }
}

fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Result<KeyMap, LpmError> {
    let mut by_triple: HashMap<String, Arc<GraphKey>> = HashMap::with_capacity(targets.len());
    let mut source_identities: HashSet<String> = HashSet::with_capacity(targets.len());
    let mut by_coords: HashMap<String, CoordEntry> = HashMap::with_capacity(targets.len());

    for v2t in targets {
        let graph_key_peers: &[(String, String)] = &v2t.target.peers;
        let mut graph_key_deps: Vec<(String, String)> =
            Vec::with_capacity(v2t.target.dependencies.len());
        graph_key_deps.extend(
            v2t.target
                .dependencies
                .iter()
                .map(|dep| (dep.local.clone(), dep.graph_key_value().to_string())),
        );

        let key = Arc::new(GraphKey::derive_raw(
            &v2t.target.name,
            &v2t.target.version,
            platform,
            linker_tag,
            &graph_key_deps,
            &v2t.target.aliases,
            graph_key_peers,
            v2t.target.root_link_names.as_deref(),
            v2t.target.wrapper_id.as_deref(),
            v2t.target.patch_fingerprint.as_deref(),
        ));

        let tkey = triple_key(
            &v2t.target.name,
            &v2t.target.version,
            v2t.target.wrapper_id.as_deref(),
        );
        if by_triple.insert(tkey, key.clone()).is_some() {
            return Err(LpmError::Store(format!(
                "v2 linker: duplicate LinkTarget for {}@{} wrapper_id={:?}",
                v2t.target.name, v2t.target.version, v2t.target.wrapper_id
            )));
        }
        if let Some(wrapper_id) = v2t.target.wrapper_id.as_deref() {
            let wkey = name_wrapper_key(&v2t.target.name, wrapper_id);
            if !source_identities.insert(wkey) {
                return Err(LpmError::Store(format!(
                    "v2 linker: duplicate source identity for {} wrapper_id={wrapper_id:?}",
                    v2t.target.name
                )));
            }
        }

        let ckey = coords_key(&v2t.target.name, &v2t.target.version);
        match by_coords.entry(ckey) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(CoordEntry::Single(key));
            }
            std::collections::hash_map::Entry::Occupied(mut existing) => {
                existing.insert(CoordEntry::Ambiguous);
            }
        }
    }
    Ok(KeyMap {
        by_triple,
        by_coords,
    })
}

/// Wipe legacy project link state so the v2 install starts clean.
fn cleanup_v1_state(project_dir: &Path) -> Result<(), LpmError> {
    // `<project>/.lpm/wrappers/` — the v1 isolated layout.
    let v1_wrappers = project_dir.join(".lpm").join("wrappers");
    if v1_wrappers.exists() {
        std::fs::remove_dir_all(&v1_wrappers).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to wipe legacy v1 wrappers at {}: {e}",
                v1_wrappers.display()
            ))
        })?;
    }
    // `<project>/.lpm/hoisted/` — hoisted layout sidecar.
    let hoisted = project_dir.join(".lpm").join("hoisted");
    if hoisted.exists() {
        std::fs::remove_dir_all(&hoisted).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to wipe legacy hoisted state at {}: {e}",
                hoisted.display()
            ))
        })?;
    }
    Ok(())
}

fn reconcile_project_node_modules(
    project_dir: &Path,
    targets: &[V2Target],
    self_package_name: Option<&str>,
    preserve_internal_lpm_dir: bool,
) -> Result<(), LpmError> {
    let nm = project_dir.join("node_modules");
    if !nm.exists() {
        return Ok(());
    }

    let mut desired = HashSet::new();
    for v2t in targets {
        desired.extend(root_link_names(&v2t.target));
    }
    if let Some(self_name) = self_package_name
        && is_safe_root_link_name(self_name)
    {
        desired.insert(self_name.to_string());
    }

    let entries = std::fs::read_dir(&nm).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read project node_modules at {}: {e}",
            nm.display()
        ))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".bin" {
            continue;
        }
        let is_real_dir = path
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if preserve_internal_lpm_dir && name == ".lpm" && is_real_dir {
            continue;
        }
        if name.starts_with('@') && is_real_dir {
            reconcile_scoped_root_dir(&path, &name, &desired)?;
            if std::fs::read_dir(&path)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(&path);
            }
            continue;
        }
        if !desired.contains(name.as_ref()) {
            remove_node_modules_entry(&path, "stale root entry")?;
        }
    }

    Ok(())
}

fn reconcile_scoped_root_dir(
    scope_dir: &Path,
    scope_name: &str,
    desired: &HashSet<String>,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(scope_dir).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read scoped node_modules dir at {}: {e}",
            scope_dir.display()
        ))
    })?;
    for entry in entries.flatten() {
        let child_path = entry.path();
        let child_name = entry.file_name();
        let full_name = format!("{scope_name}/{}", child_name.to_string_lossy());
        if !desired.contains(&full_name) {
            remove_node_modules_entry(&child_path, "stale scoped root entry")?;
        }
    }
    Ok(())
}

fn clear_bin_dir(project_dir: &Path) -> Result<(), LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    if bin_dir.symlink_metadata().is_err() {
        return Ok(());
    }
    remove_node_modules_entry(&bin_dir, "stale bin directory")
}

fn remove_node_modules_entry(path: &Path, label: &str) -> Result<(), LpmError> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };
    let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to remove {label} at {}: {e}",
            path.display()
        ))
    })
}

/// Create `<project>/node_modules/<root_link_name>` symlinks pointing
/// into the v2 store's link package dirs.
fn create_root_symlinks(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
) -> Result<usize, LpmError> {
    let nm = ensure_node_modules_dir(project_dir)?;

    // Scratch `PathBuf` reused across iterations. The naïve
    // `nm.join(&root_name)` allocates a fresh `PathBuf` per
    // root_name; with a single cleared+pushed buffer the underlying
    // capacity is reused (~100 fewer allocations on a typical install).
    let mut link_path = PathBuf::with_capacity(nm.as_os_str().len() + 64);
    let mut count = 0usize;
    for v2t in targets {
        let names = root_link_names(&v2t.target);
        if names.is_empty() {
            continue;
        }
        let key = key_map.get_for(&v2t.target).ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: missing graph key for {}@{} during root-symlink pass",
                v2t.target.name, v2t.target.version
            ))
        })?;
        let target_path = store.paths().link_package_dir(key);
        for root_name in names {
            link_path.clear();
            link_path.push(&nm);
            link_path.push(&root_name);
            ensure_link_parent_dir(&nm, &link_path, "root symlink")?;
            if symlink_points_to(&link_path, &target_path) {
                count += 1;
                continue;
            }
            // Best-effort cleanup: if a stale symlink/file is at the
            // slot, remove before re-creating. Should be a no-op after
            // `cleanup_v1_state` already wiped node_modules — defensive
            // guard for direct callers.
            //
            // L24: between the cleanup remove and the create, a
            // concurrent install racing on the same project can
            // re-populate the slot, causing create to fail with
            // `AlreadyExists`. Tolerate one retry after a second
            // cleanup pass; if it still fails, escalate. Two
            // concurrent installs on the same project is rare but
            // possible (e.g., editor "watch" mode + CLI run); the
            // retry keeps neither caller from being arbitrarily
            // unlucky.
            for attempt in 0..2u8 {
                if link_path.symlink_metadata().is_ok() {
                    let _ = std::fs::remove_file(&link_path);
                    let _ = std::fs::remove_dir_all(&link_path);
                }
                match create_dir_symlink_or_junction(&target_path, &link_path) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                        // A racing installer re-populated the slot
                        // between our remove and create. Loop once.
                        continue;
                    }
                    Err(e) => {
                        return Err(LpmError::Store(format!(
                            "v2 linker: failed to create root symlink {} → {}: {e}",
                            link_path.display(),
                            target_path.display()
                        )));
                    }
                }
            }
            count += 1;
        }
    }
    Ok(count)
}

const PROJECT_COMPAT_DIR: &str = "compat";
const COMPAT_META_FILENAME: &str = ".lpm-compat-meta";
const COMPAT_META_FORMAT: &str = "lpm-compat-v1";

#[derive(Default)]
struct CompatibilityLinks {
    package_dirs_by_key: HashMap<String, PathBuf>,
}

impl CompatibilityLinks {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            package_dirs_by_key: HashMap::with_capacity(capacity),
        }
    }

    fn insert(&mut self, key: &GraphKey, package_dir: PathBuf) {
        self.package_dirs_by_key
            .insert(key.dir_name().to_string(), package_dir);
    }

    fn package_dir_for_key(&self, key: &GraphKey) -> Option<&Path> {
        self.package_dirs_by_key
            .get(key.dir_name())
            .map(PathBuf::as_path)
    }
}

struct CompatibilityEntry<'a> {
    target: &'a V2Target,
    key: Arc<GraphKey>,
}

#[derive(Clone)]
struct CompatibilitySibling {
    local: String,
    key: Arc<GraphKey>,
}

fn project_compatibility_root(project_dir: &Path) -> PathBuf {
    project_dir
        .join("node_modules")
        .join(".lpm")
        .join(PROJECT_COMPAT_DIR)
}

fn legacy_project_compatibility_root(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(PROJECT_COMPAT_DIR)
}

/// Return true when every requested project `.bin/<name>` resolves into
/// LPM's project-local compatibility area.
pub fn project_compatibility_bins_ready(project_dir: &Path, bin_names: &[String]) -> bool {
    let bin_names = normalize_compatibility_bin_names(bin_names);
    let expected_bin_names = if bin_names.is_empty() {
        match collect_project_direct_bin_names(project_dir) {
            Some(names) => names,
            None => return false,
        }
    } else {
        bin_names.iter().cloned().collect()
    };
    if expected_bin_names.is_empty() {
        return true;
    }
    let Ok(compatibility_root) = project_compatibility_root(project_dir).canonicalize() else {
        return false;
    };
    let bin_dir = project_dir.join("node_modules").join(".bin");
    expected_bin_names.iter().all(|bin_name| {
        bin_dir
            .join(bin_name)
            .canonicalize()
            .is_ok_and(|real| real.starts_with(&compatibility_root))
    })
}

fn collect_project_direct_bin_names(project_dir: &Path) -> Option<HashSet<String>> {
    let nm = project_dir.join("node_modules");
    let entries = match std::fs::read_dir(&nm) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(HashSet::new());
        }
        Err(_) => return None,
    };
    let mut bin_names = HashSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return None,
        };
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".bin" || name == ".lpm" {
            continue;
        }
        if name.starts_with('@') {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => return None,
            };
            if !file_type.is_dir() {
                continue;
            }
            let scoped_entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(_) => return None,
            };
            for scoped_entry in scoped_entries {
                let scoped_entry = match scoped_entry {
                    Ok(entry) => entry,
                    Err(_) => return None,
                };
                let package_name =
                    format!("{}/{}", name, scoped_entry.file_name().to_string_lossy());
                collect_project_package_bin_names(
                    &scoped_entry.path(),
                    &package_name,
                    &mut bin_names,
                )?;
            }
            continue;
        }
        collect_project_package_bin_names(&path, &name, &mut bin_names)?;
    }
    Some(bin_names)
}

fn collect_project_package_bin_names(
    package_dir: &Path,
    fallback_package_name: &str,
    bin_names: &mut HashSet<String>,
) -> Option<()> {
    let package_json = package_dir.join("package.json");
    let content = match std::fs::read(&package_json) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(()),
        Err(_) => return None,
    };
    const BIN_KEY: &[u8] = b"\"bin\"";
    if !content.windows(BIN_KEY.len()).any(|w| w == BIN_KEY) {
        return Some(());
    }
    let bin_config = match lpm_workspace::parse_bin_field(&content) {
        Ok(Some(bin_config)) => bin_config,
        Ok(None) => return Some(()),
        Err(_) => return None,
    };
    let package_name =
        package_name_from_manifest(&content).unwrap_or_else(|| fallback_package_name.to_string());
    bin_names.extend(
        bin_config
            .entries(&package_name)
            .into_iter()
            .map(|(cmd_name, _)| cmd_name),
    );
    Some(())
}

fn package_name_from_manifest(content: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(content).ok()?;
    parsed.get("name")?.as_str().map(str::to_string)
}

fn create_project_compatibility_links(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
    compatibility_bin_names: &[String],
    refresh_package_copies: bool,
) -> Result<CompatibilityLinks, LpmError> {
    let requested_bins = normalize_compatibility_bin_names(compatibility_bin_names);
    let roots = collect_compatibility_roots_for_bins(targets, store, key_map, &requested_bins);

    if roots.is_empty() {
        remove_project_compatibility_root(project_dir)?;
        return Ok(CompatibilityLinks::default());
    }

    let project_context = collect_project_direct_compatibility_siblings(targets, key_map);
    let compatibility_root = ensure_project_compatibility_root(project_dir)?;
    let entries = collect_compatibility_entries(roots, targets, key_map, &project_context)?;
    let desired: HashSet<String> = entries
        .iter()
        .map(|entry| entry.key.dir_name().to_string())
        .collect();
    reconcile_compatibility_root(&compatibility_root, &desired)?;

    let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
    for entry in &entries {
        let package_dir = ensure_compatibility_package_copy(
            &compatibility_root,
            entry,
            store,
            refresh_package_copies,
        )?;
        compatibility_links.insert(&entry.key, package_dir);
    }

    for entry in &entries {
        sync_compatibility_entry_links(
            &compatibility_root,
            entry,
            key_map,
            &compatibility_links,
            &project_context,
        )?;
    }

    for entry in &entries {
        write_compatibility_marker(&compatibility_root, entry)?;
    }

    rewire_project_roots_to_compat(project_dir, targets, key_map, &compatibility_links)?;
    Ok(compatibility_links)
}

fn normalize_compatibility_bin_names(bin_names: &[String]) -> Vec<String> {
    let mut seen = HashSet::with_capacity(bin_names.len());
    let mut normalized = Vec::with_capacity(bin_names.len());
    for name in bin_names {
        if !is_safe_root_link_name(name) {
            tracing::warn!("v2 linker: ignoring unsafe compatibility bin name {name:?}");
            continue;
        }
        if seen.insert(name.clone()) {
            normalized.push(name.clone());
        }
    }
    normalized
}

fn collect_compatibility_roots_for_bins<'a>(
    targets: &'a [V2Target],
    store: &Store,
    key_map: &KeyMap,
    requested_bins: &[String],
) -> Vec<&'a V2Target> {
    let requested: Option<HashSet<&str>> = if requested_bins.is_empty() {
        None
    } else {
        Some(requested_bins.iter().map(String::as_str).collect())
    };
    let mut roots = Vec::new();
    for v2t in targets {
        if !is_direct(&v2t.target) {
            continue;
        }
        let Some(key) = key_map.get_for(&v2t.target) else {
            continue;
        };
        let pkg_json_path = store.paths().link_package_dir(key).join("package.json");
        let content = match std::fs::read(&pkg_json_path) {
            Ok(content) => content,
            Err(error) => {
                tracing::debug!(
                    "v2 linker: skipping compatibility bin scan for {}: failed to read {}: {error}",
                    v2t.target.name,
                    pkg_json_path.display()
                );
                continue;
            }
        };
        const BIN_KEY: &[u8] = b"\"bin\"";
        if !content.windows(BIN_KEY.len()).any(|w| w == BIN_KEY) {
            continue;
        }
        let bin_config = match lpm_workspace::parse_bin_field(&content) {
            Ok(Some(bin_config)) => bin_config,
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(
                    "v2 linker: skipping compatibility bin scan for {}: failed to parse package.json: {error}",
                    v2t.target.name
                );
                continue;
            }
        };
        let entries = bin_config.entries(&v2t.target.name);
        if entries.is_empty() {
            continue;
        }
        match &requested {
            Some(requested) => {
                if entries
                    .iter()
                    .any(|(cmd_name, _)| requested.contains(cmd_name.as_str()))
                {
                    roots.push(v2t);
                }
            }
            None => roots.push(v2t),
        }
    }
    roots
}

fn collect_compatibility_entries<'a>(
    roots: Vec<&'a V2Target>,
    targets: &'a [V2Target],
    key_map: &KeyMap,
    project_context: &[CompatibilitySibling],
) -> Result<Vec<CompatibilityEntry<'a>>, LpmError> {
    let mut targets_by_key_dir: HashMap<String, &V2Target> = HashMap::with_capacity(targets.len());
    for v2t in targets {
        if let Some(key) = key_map.get_for(&v2t.target) {
            targets_by_key_dir.insert(key.dir_name().to_string(), v2t);
        }
    }

    let mut queue: VecDeque<&V2Target> = roots.into();
    for sibling in project_context {
        let Some(target) = targets_by_key_dir.get(sibling.key.dir_name()) else {
            return Err(LpmError::Store(format!(
                "v2 linker: project compatibility dependency {} for root context is missing from install set",
                sibling.key.dir_name()
            )));
        };
        queue.push_back(*target);
    }
    let mut seen: HashSet<String> = HashSet::with_capacity(targets.len());
    let mut entries = Vec::new();
    while let Some(v2t) = queue.pop_front() {
        let key = key_map.get_for(&v2t.target).cloned().ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: missing graph key for compatibility package {}@{}",
                v2t.target.name, v2t.target.version
            ))
        })?;
        if !seen.insert(key.dir_name().to_string()) {
            continue;
        }

        for (_local, dep_key) in compatibility_dependency_links(&v2t.target, key_map)? {
            let dep_target = targets_by_key_dir.get(dep_key.dir_name()).ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: compatibility dependency {} for {}@{} is missing from install set",
                    dep_key.dir_name(),
                    v2t.target.name,
                    v2t.target.version
                ))
            })?;
            queue.push_back(*dep_target);
        }
        entries.push(CompatibilityEntry { target: v2t, key });
    }
    Ok(entries)
}

fn collect_project_direct_compatibility_siblings(
    targets: &[V2Target],
    key_map: &KeyMap,
) -> Vec<CompatibilitySibling> {
    let mut siblings = Vec::new();
    let mut seen_local = HashSet::new();
    for v2t in targets {
        if !v2t.target.is_direct {
            continue;
        }
        let Some(key) = key_map.get_for(&v2t.target) else {
            continue;
        };
        for local in direct_root_link_names(&v2t.target) {
            if seen_local.insert(local.clone()) {
                siblings.push(CompatibilitySibling {
                    local,
                    key: key.clone(),
                });
            }
        }
    }
    siblings
}

fn compatibility_dependency_links(
    target: &LinkTarget,
    key_map: &KeyMap,
) -> Result<Vec<(String, Arc<GraphKey>)>, LpmError> {
    let mut links = Vec::with_capacity(target.dependencies.len() + target.peers.len());
    let mut seen_local: HashSet<String> =
        HashSet::with_capacity(target.dependencies.len() + target.peers.len());

    for dep in &target.dependencies {
        if !is_safe_root_link_name(&dep.local) {
            tracing::warn!(
                "v2 linker: skipping unsafe compatibility dependency local name {:?} for {}@{}",
                dep.local,
                target.name,
                target.version
            );
            continue;
        }
        let dep_key = key_map
            .get_for_dependency(dep)
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: compatibility dep {}=>{}@{} of {}@{} has no resolved graph key",
                    dep.local,
                    dep.target_name,
                    dep.graph_key_value(),
                    target.name,
                    target.version
                ))
            })?
            .clone();
        if seen_local.insert(dep.local.clone()) {
            links.push((dep.local.clone(), dep_key));
        }
    }

    for (peer_name, peer_version) in &target.peers {
        if !is_safe_root_link_name(peer_name) {
            tracing::warn!(
                "v2 linker: skipping unsafe compatibility peer local name {:?} for {}@{}",
                peer_name,
                target.name,
                target.version
            );
            continue;
        }
        if !seen_local.insert(peer_name.clone()) {
            continue;
        }
        if let Some(peer_key) = key_map.get_peer(peer_name, peer_version) {
            links.push((peer_name.clone(), peer_key.clone()));
        }
    }

    Ok(links)
}

fn ensure_project_compatibility_root(project_dir: &Path) -> Result<PathBuf, LpmError> {
    remove_legacy_project_compatibility_root(project_dir)?;
    let node_modules = ensure_node_modules_dir(project_dir)?;
    let lpm_dir = node_modules.join(".lpm");
    ensure_real_dir_or_create(&lpm_dir, "project node_modules/.lpm directory")?;
    let compatibility_root = project_compatibility_root(project_dir);
    ensure_real_dir_or_create(&compatibility_root, "project compatibility directory")?;
    Ok(compatibility_root)
}

fn ensure_real_dir_or_create(path: &Path, label: &str) -> Result<(), LpmError> {
    match path.symlink_metadata() {
        Ok(_) => ensure_real_dir(path, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to create {label} at {}: {e}",
                    path.display()
                ))
            })?;
            ensure_real_dir(path, label)
        }
        Err(error) => Err(LpmError::Store(format!(
            "v2 linker: failed to inspect {label} at {}: {error}",
            path.display()
        ))),
    }
}

fn remove_project_compatibility_root(project_dir: &Path) -> Result<(), LpmError> {
    let lpm_dir = project_dir.join("node_modules").join(".lpm");
    let metadata = match lpm_dir.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            remove_legacy_project_compatibility_root(project_dir)?;
            return Ok(());
        }
        Err(error) => {
            return Err(LpmError::Store(format!(
                "v2 linker: failed to inspect project node_modules/.lpm directory at {}: {error}",
                lpm_dir.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(LpmError::Store(format!(
            "v2 linker: refusing to clean compatibility directory through symlinked node_modules/.lpm at {}",
            lpm_dir.display()
        )));
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let compatibility_root = project_compatibility_root(project_dir);
    if compatibility_root.symlink_metadata().is_ok() {
        remove_node_modules_entry(&compatibility_root, "stale compatibility directory")?;
    }
    if std::fs::read_dir(&lpm_dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir(&lpm_dir);
    }
    remove_legacy_project_compatibility_root(project_dir)?;
    Ok(())
}

fn remove_legacy_project_compatibility_root(project_dir: &Path) -> Result<(), LpmError> {
    let lpm_dir = project_dir.join(".lpm");
    let metadata = match lpm_dir.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(LpmError::Store(format!(
                "v2 linker: failed to inspect legacy project .lpm directory at {}: {error}",
                lpm_dir.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(LpmError::Store(format!(
            "v2 linker: refusing to clean legacy compatibility directory through symlinked .lpm at {}",
            lpm_dir.display()
        )));
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let compatibility_root = legacy_project_compatibility_root(project_dir);
    if compatibility_root.symlink_metadata().is_ok() {
        remove_node_modules_entry(&compatibility_root, "legacy compatibility directory")?;
    }
    Ok(())
}

fn reconcile_compatibility_root(
    compatibility_root: &Path,
    desired: &HashSet<String>,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(compatibility_root).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read compatibility directory at {}: {e}",
            compatibility_root.display()
        ))
    })?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(".tmp.") || desired.contains(&name) {
            continue;
        }
        remove_node_modules_entry(&entry.path(), "stale compatibility entry")?;
    }
    Ok(())
}

fn ensure_compatibility_package_copy(
    compatibility_root: &Path,
    entry: &CompatibilityEntry<'_>,
    store: &Store,
    force_refresh: bool,
) -> Result<PathBuf, LpmError> {
    let final_dir = compatibility_entry_dir(compatibility_root, &entry.key);
    let package_dir = compatibility_package_dir(compatibility_root, &entry.key);
    if !force_refresh && compatibility_entry_reusable(&final_dir, entry) {
        return Ok(package_dir);
    }
    if final_dir.symlink_metadata().is_ok() {
        remove_node_modules_entry(&final_dir, "stale compatibility entry")?;
    }

    let tmp_dir = create_compatibility_tmp_dir(&final_dir)?;
    let tmp_package_dir = tmp_dir.join("node_modules").join(entry.key.name());
    let source_package_dir = store.paths().link_package_dir(&entry.key);
    if !source_package_dir.join("package.json").is_file() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(LpmError::Store(format!(
            "v2 linker: compatibility source package is missing at {}",
            source_package_dir.display()
        )));
    }

    if let Err(error) = link_dir_recursive(&source_package_dir, &tmp_package_dir) {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(error);
    }

    match std::fs::rename(&tmp_dir, &final_dir) {
        Ok(()) => Ok(package_dir),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            Err(LpmError::Store(format!(
                "v2 linker: failed to publish compatibility entry {} -> {}: {error}",
                tmp_dir.display(),
                final_dir.display()
            )))
        }
    }
}

fn create_compatibility_tmp_dir(final_dir: &Path) -> Result<PathBuf, LpmError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COMPAT_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = final_dir.parent().ok_or_else(|| {
        LpmError::Store(format!(
            "v2 linker: compatibility path has no parent: {}",
            final_dir.display()
        ))
    })?;
    let base_name = final_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: compatibility path has invalid final component: {}",
                final_dir.display()
            ))
        })?;
    for _ in 0..16 {
        let suffix = COMPAT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(
            "{}.tmp.{}.{suffix:x}",
            base_name,
            std::process::id()
        ));
        match std::fs::create_dir(&tmp) {
            Ok(()) => return Ok(tmp),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "v2 linker: failed to create compatibility tmp dir at {}: {error}",
                    tmp.display()
                )));
            }
        }
    }
    Err(LpmError::Store(format!(
        "v2 linker: failed to allocate compatibility tmp dir for {}",
        final_dir.display()
    )))
}

fn compatibility_entry_reusable(final_dir: &Path, entry: &CompatibilityEntry<'_>) -> bool {
    let marker = final_dir.join(COMPAT_META_FILENAME);
    let Ok(content) = std::fs::read_to_string(marker) else {
        return false;
    };
    content == compatibility_marker(entry)
        && final_dir
            .join("node_modules")
            .join(entry.key.name())
            .join("package.json")
            .is_file()
}

fn sync_compatibility_entry_links(
    compatibility_root: &Path,
    entry: &CompatibilityEntry<'_>,
    key_map: &KeyMap,
    compatibility_links: &CompatibilityLinks,
    project_context: &[CompatibilitySibling],
) -> Result<(), LpmError> {
    let node_modules = compatibility_node_modules_dir(compatibility_root, &entry.key);
    let mut links = compatibility_dependency_links(&entry.target.target, key_map)?;
    let own_local = entry.key.name();
    links.retain(|(local, _)| local != own_local);
    let mut seen_local: HashSet<String> = HashSet::with_capacity(links.len() + 1);
    seen_local.insert(own_local.to_string());
    seen_local.extend(links.iter().map(|(local, _)| local.clone()));
    for sibling in project_context {
        if seen_local.insert(sibling.local.clone()) {
            links.push((sibling.local.clone(), sibling.key.clone()));
        }
    }
    let mut desired: HashSet<String> = HashSet::with_capacity(links.len() + 1);
    desired.insert(entry.key.name().to_string());
    desired.extend(links.iter().map(|(local, _)| local.clone()));
    reconcile_compatibility_node_modules(&node_modules, &desired)?;

    let own_package_dir = compatibility_package_dir(compatibility_root, &entry.key);
    for (local, dep_key) in links {
        let Some(target_package_dir) = compatibility_links.package_dir_for_key(&dep_key) else {
            return Err(LpmError::Store(format!(
                "v2 linker: compatibility link target {} for {}@{} was not materialized",
                dep_key.dir_name(),
                entry.target.target.name,
                entry.target.target.version
            )));
        };
        if target_package_dir == own_package_dir {
            continue;
        }
        create_compatibility_sibling_link(&node_modules, &local, target_package_dir)?;
    }
    Ok(())
}

fn reconcile_compatibility_node_modules(
    node_modules: &Path,
    desired: &HashSet<String>,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(node_modules).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read compatibility node_modules at {}: {e}",
            node_modules.display()
        ))
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_real_dir = path
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if name.starts_with('@') && is_real_dir {
            reconcile_scoped_root_dir(&path, &name, desired)?;
            if std::fs::read_dir(&path)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(&path);
            }
            continue;
        }
        if !desired.contains(&name) {
            remove_node_modules_entry(&path, "stale compatibility sibling")?;
        }
    }
    Ok(())
}

fn create_compatibility_sibling_link(
    node_modules: &Path,
    local: &str,
    target_package_dir: &Path,
) -> Result<(), LpmError> {
    if !is_safe_root_link_name(local) {
        return Err(LpmError::Store(format!(
            "v2 linker: unsafe compatibility sibling name {local:?}"
        )));
    }
    let link_path = node_modules.join(local);
    ensure_link_parent_dir(node_modules, &link_path, "compatibility sibling")?;
    if symlink_points_to(&link_path, target_package_dir) {
        return Ok(());
    }
    if link_path.symlink_metadata().is_ok() {
        remove_node_modules_entry(&link_path, "stale compatibility sibling")?;
    }
    create_dir_symlink_or_junction(target_package_dir, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create compatibility sibling {} -> {}: {e}",
            link_path.display(),
            target_package_dir.display()
        ))
    })
}

fn write_compatibility_marker(
    compatibility_root: &Path,
    entry: &CompatibilityEntry<'_>,
) -> Result<(), LpmError> {
    let marker_path =
        compatibility_entry_dir(compatibility_root, &entry.key).join(COMPAT_META_FILENAME);
    std::fs::write(&marker_path, compatibility_marker(entry)).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to write compatibility marker at {}: {e}",
            marker_path.display()
        ))
    })
}

fn compatibility_marker(entry: &CompatibilityEntry<'_>) -> String {
    format!(
        "{COMPAT_META_FORMAT}\nkey={}\nsri={}\n",
        entry.key.dir_name(),
        entry.target.source_sri
    )
}

fn rewire_project_roots_to_compat(
    project_dir: &Path,
    targets: &[V2Target],
    key_map: &KeyMap,
    compatibility_links: &CompatibilityLinks,
) -> Result<(), LpmError> {
    let nm = ensure_node_modules_dir(project_dir)?;
    for v2t in targets {
        let Some(key) = key_map.get_for(&v2t.target) else {
            continue;
        };
        let Some(package_dir) = compatibility_links.package_dir_for_key(key) else {
            continue;
        };
        for root_name in root_link_names(&v2t.target) {
            if root_name != v2t.target.name {
                continue;
            }
            let link_path = nm.join(&root_name);
            ensure_link_parent_dir(&nm, &link_path, "compatibility root symlink")?;
            if symlink_points_to(&link_path, package_dir) {
                continue;
            }
            if link_path.symlink_metadata().is_ok() {
                remove_node_modules_entry(&link_path, "store root symlink")?;
            }
            create_dir_symlink_or_junction(package_dir, &link_path).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to rewire project root {} -> {}: {e}",
                    link_path.display(),
                    package_dir.display()
                ))
            })?;
        }
    }
    Ok(())
}

fn compatibility_entry_dir(compatibility_root: &Path, key: &GraphKey) -> PathBuf {
    compatibility_root.join(key.dir_name())
}

fn compatibility_node_modules_dir(compatibility_root: &Path, key: &GraphKey) -> PathBuf {
    compatibility_entry_dir(compatibility_root, key).join("node_modules")
}

fn compatibility_package_dir(compatibility_root: &Path, key: &GraphKey) -> PathBuf {
    compatibility_node_modules_dir(compatibility_root, key).join(key.name())
}

fn symlink_points_to(link_path: &Path, target_path: &Path) -> bool {
    let Ok(existing_target) = std::fs::read_link(link_path) else {
        return false;
    };
    if existing_target == target_path {
        return true;
    }
    if existing_target.is_relative()
        && let Some(parent) = link_path.parent()
    {
        return parent.join(existing_target) == target_path;
    }
    false
}

/// Resolve a target's root-symlink filenames. Mirrors v1's contract
/// (see [`LinkTarget::root_link_names`] docs):
///
/// - `Some([])` — explicit "no root symlinks."
/// - `Some([…])` — explicit list of root names.
/// - `None` + direct dep — single root symlink at `[name]`.
/// - `None` + transitive — empty.
///
/// Filters out any name that contains a path separator or `..`
/// component — a resolver bug (or, worst case, attacker-influenced
/// `root_link_names` data on a future code path) could otherwise
/// land symlink slots outside `<project>/node_modules/`. The root-
/// symlink writer at the call site does `remove_dir_all` on the
/// computed `link_path` before creating the symlink, so a traversal
/// here would `remove_dir_all` an arbitrary path. Refuse-and-warn is
/// the same posture used by the v1 bin emitter and v2's bin loop
/// (see [`crate::validate_bin_name`]).
fn root_link_names(target: &LinkTarget) -> Vec<String> {
    let raw: Vec<String> = if let Some(names) = &target.root_link_names {
        names.clone()
    } else if target.is_direct {
        vec![target.name.clone()]
    } else {
        Vec::new()
    };
    raw.into_iter()
        .filter(|name| {
            if is_safe_root_link_name(name) {
                true
            } else {
                tracing::warn!(
                    "v2 linker: rejecting unsafe root_link_name {name:?} for {}@{} \
                     — contains path separator, traversal, or null byte",
                    target.name,
                    target.version
                );
                false
            }
        })
        .collect()
}

fn direct_root_link_names(target: &LinkTarget) -> Vec<String> {
    if !target.is_direct {
        return Vec::new();
    }
    let raw: Vec<String> = target
        .root_link_names
        .clone()
        .unwrap_or_else(|| vec![target.name.clone()]);
    raw.into_iter()
        .filter(|name| {
            if is_safe_root_link_name(name) {
                true
            } else {
                tracing::warn!(
                    "v2 linker: rejecting unsafe direct root_link_name {name:?} for {}@{}",
                    target.name,
                    target.version
                );
                false
            }
        })
        .collect()
}

/// `.bin/` shim creation for the v2 layout. Walks each direct dep's
/// `package.json` from inside the link entry's package dir
/// (`<store>/links/<graph-key>/node_modules/<name>/package.json`)
/// and emits a relative symlink under `<project>/node_modules/.bin/<cmd>`
/// pointing at the bin script in the link entry.
///
/// Only DIRECT deps get bin shims (matches npm/v1 semantics). Bin
/// shims for transitive deps are unreachable from project scripts
/// without an explicit `npx`/`require.resolve` round-trip, and
/// hoisted-mode v1 only emits direct-dep shims either.
fn create_bin_links_v2(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
    compatibility_links: &CompatibilityLinks,
) -> Result<usize, LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");

    // Scratch `PathBuf`s reused across iterations: the per-iteration
    // paths build into reusable buffers rather than allocating fresh
    // each loop turn (~4×N PathBuf allocations saved for an install
    // with N direct deps × ~2 bin entries each).
    let mut pkg_json_path = PathBuf::with_capacity(256);
    let mut bin_target = PathBuf::with_capacity(256);
    let mut link_path = PathBuf::with_capacity(bin_dir.as_os_str().len() + 64);

    let mut count = 0usize;
    for v2t in targets {
        if !is_direct(&v2t.target) {
            continue;
        }
        let key = match key_map.get_for(&v2t.target) {
            Some(k) => k,
            None => continue,
        };
        let pkg_dir = compatibility_links
            .package_dir_for_key(key)
            .map_or_else(|| store.paths().link_package_dir(key), Path::to_path_buf);
        pkg_json_path.clear();
        pkg_json_path.push(&pkg_dir);
        pkg_json_path.push("package.json");

        // Read once; treat I/O failure as "no bin" (equivalent to the old
        // exists() check but saves one stat(2) syscall per direct dep).
        let content = match std::fs::read(&pkg_json_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Fast byte pre-scan to skip serde_json parse entirely for
        // direct deps that declare no `bin`. The quoted key `"bin"`
        // reliably identifies the JSON field; any false positive (a
        // value containing the 5-byte sequence) is harmless — we just
        // parse and get back None.
        const BIN_KEY: &[u8] = b"\"bin\"";
        if !content.windows(BIN_KEY.len()).any(|w| w == BIN_KEY) {
            continue;
        }

        let bin_config = match lpm_workspace::parse_bin_field(&content) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: skipping bin links for {}: failed to parse package.json: {e}",
                    v2t.target.name
                );
                continue;
            }
        };
        let entries = bin_config.entries(&v2t.target.name);
        if entries.is_empty() {
            continue;
        }
        std::fs::create_dir_all(&bin_dir).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to create .bin/ at {}: {e}",
                bin_dir.display()
            ))
        })?;

        for (cmd_name, bin_rel_path) in entries {
            // Reject bin entries whose key would write outside `.bin/`
            // or shadow path components — same bar as v1's hoisted
            // emitter (lib.rs). Warn-and-skip rather than fail-install
            // so one malformed entry doesn't abort the whole link.
            if let Err(reason) = validate_bin_name(&cmd_name, &v2t.target.name) {
                tracing::warn!(
                    "v2 linker: rejecting bin \"{cmd_name}\" from {}: {reason}",
                    v2t.target.name
                );
                continue;
            }

            // Use validate_bin_target as a *guard only* — the canonical
            // return value is discarded. Downstream `pathdiff::diff_paths`
            // expects bin_target and bin_dir in the same canonical
            // (or same non-canonical) form, and v2's bin_dir is built
            // from the raw project_dir. Mixing forms (canonical target,
            // raw bin_dir) produces malformed symlinks on macOS, where
            // `/var/folders/...` and `/private/var/folders/...` share no
            // prefix until both are canonicalised.
            //
            // The guard call still enforces:
            // - rejection of `..` components in script_path
            // - rejection of bin_rel_path whose canonical resolve
            //   escapes the package dir (e.g. via an in-package symlink
            //   pointing outside)
            // - rejection of missing files (canonicalize fails)
            if let Err(reason) = validate_bin_target(&pkg_dir, &bin_rel_path) {
                tracing::warn!(
                    "v2 linker: rejecting bin {cmd_name} from {}: {reason}",
                    v2t.target.name
                );
                continue;
            }
            bin_target.clear();
            bin_target.push(&pkg_dir);
            bin_target.push(&bin_rel_path);
            #[cfg(unix)]
            if let Err(error) = make_bin_target_executable(&bin_target) {
                tracing::warn!(
                    "v2 linker: skipping bin {cmd_name} from {}: failed to mark target executable: {error}",
                    v2t.target.name
                );
                continue;
            }
            link_path.clear();
            link_path.push(&bin_dir);
            link_path.push(&cmd_name);
            // Best-effort cleanup of a stale shim.
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
            #[cfg(unix)]
            let relative =
                pathdiff::diff_paths(&bin_target, &bin_dir).unwrap_or_else(|| bin_target.clone());
            #[cfg(unix)]
            std::os::unix::fs::symlink(&relative, &link_path).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to create bin shim {} → {}: {e}",
                    link_path.display(),
                    relative.display()
                ))
            })?;
            #[cfg(windows)]
            {
                // Windows: emit a `.cmd` shim that invokes node.exe
                // on the script. Mirrors v1's hoisted/.bin emission.
                // (Junction-style symlinks to script files don't run
                // under cmd.exe; `.cmd` shim is the cross-version
                // path that works on every Windows lpm has shipped
                // on.)
                let target_str = bin_target.to_string_lossy();
                if let Err(reason) = lpm_common::symlink::validate_cmd_path(&target_str) {
                    tracing::warn!("v2 linker: skipping .cmd shim for {cmd_name}: {reason}");
                    continue;
                }
                let cmd_content = format!(
                    "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
                );
                let cmd_path = bin_dir.join(format!("{cmd_name}.cmd"));
                std::fs::write(&cmd_path, cmd_content).map_err(|e| {
                    LpmError::Store(format!(
                        "v2 linker: failed to write .cmd shim at {}: {e}",
                        cmd_path.display()
                    ))
                })?;
            }
            count += 1;
        }
    }
    Ok(count)
}

// Tiny helper called per-target — `#[inline]` so the per-iteration
// call shrinks to a single branch.
#[inline]
fn is_direct(target: &LinkTarget) -> bool {
    if let Some(names) = &target.root_link_names {
        return !names.is_empty();
    }
    target.is_direct
}

/// `<project>/node_modules/<self_name>` → `<project_dir>` symlink.
/// Skipped if the slot is already occupied (a direct dep with the
/// same name took the spot).
fn create_self_ref(project_dir: &Path, self_name: &str) -> Result<bool, LpmError> {
    if !is_safe_root_link_name(self_name) {
        tracing::warn!("v2 linker: skipping self-reference for unsafe package name: {self_name:?}");
        return Ok(false);
    }

    let nm = ensure_node_modules_dir(project_dir)?;
    let link_path = nm.join(self_name);
    if link_path.symlink_metadata().is_ok() {
        return Ok(false);
    }
    ensure_link_parent_dir(&nm, &link_path, "self-reference")?;
    create_dir_symlink_or_junction(project_dir, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create self-ref symlink {} → {}: {e}",
            link_path.display(),
            project_dir.display()
        ))
    })?;
    Ok(true)
}

fn ensure_node_modules_dir(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create project node_modules at {}: {e}",
            nm.display()
        ))
    })?;
    ensure_real_dir(&nm, "project node_modules")?;
    Ok(nm)
}

fn ensure_link_parent_dir(root: &Path, link_path: &Path, label: &str) -> Result<(), LpmError> {
    let Some(parent) = link_path.parent() else {
        return Err(LpmError::Store(format!(
            "v2 linker: {label} path has no parent: {}",
            link_path.display()
        )));
    };
    if parent == root {
        return Ok(());
    }
    match parent.symlink_metadata() {
        Ok(_) => ensure_real_dir(parent, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to create {label} parent at {}: {e}",
                    parent.display()
                ))
            })?;
            ensure_real_dir(parent, label)
        }
        Err(error) => Err(LpmError::Store(format!(
            "v2 linker: failed to inspect {label} parent at {}: {error}",
            parent.display()
        ))),
    }
}

fn ensure_real_dir(path: &Path, label: &str) -> Result<(), LpmError> {
    ensure_real_dir_with_prefix(path, label, "v2 linker: ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_store::v2::Store as V2Store;
    use std::path::PathBuf;

    fn synthetic_sri(seed: &[u8]) -> String {
        lpm_store::compute_sri_hash(seed)
    }

    fn build_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("package/{path}"), &content[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn write_object(store: &V2Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let tarball = build_test_tarball(files);
        store.extract_object(sri, &tarball).unwrap()
    }

    #[cfg(unix)]
    fn write_local_source_object(store: &V2Store, sri: &str, source_dir: &Path) -> PathBuf {
        store
            .populate_object_from_local_source(source_dir, sri)
            .unwrap()
    }

    fn target(name: &str, version: &str, sri: &str, is_direct: bool) -> V2Target {
        V2Target {
            target: LinkTarget {
                name: name.into(),
                version: version.into(),
                store_path: PathBuf::new(), // unused under v2
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                is_direct,
                root_link_names: None,
                wrapper_id: None,
                materialization: crate::Materialization::CasBacked,
                peers: Vec::new(),
                patch_fingerprint: None,
            },
            source_sri: sri.into(),
        }
    }

    #[test]
    fn link_packages_v2_writes_project_root_symlink_for_direct_dep() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"link_packages_v2/single_dep");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
        );

        let result = link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.linked, 1);
        assert_eq!(result.symlinked, 1);
        let link = project.join("node_modules").join("a");
        assert!(
            link.symlink_metadata().unwrap().file_type().is_symlink(),
            "root symlink must be a symlink"
        );
        // Resolves to the package dir inside the link entry.
        assert!(link.join("package.json").is_file());
    }

    #[test]
    fn link_packages_v2_resolves_dep_via_key_map() {
        // Two-package install: consumer depends on lib. The lib's
        // graph key must be reachable when populating consumer's
        // sibling-symlinks.
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let lib_sri = synthetic_sri(b"link_packages_v2/lib");
        write_object(
            &store,
            &lib_sri,
            &[("package.json", b"{\"name\":\"lib\",\"version\":\"1.2.3\"}")],
        );
        let cons_sri = synthetic_sri(b"link_packages_v2/consumer");
        write_object(
            &store,
            &cons_sri,
            &[(
                "package.json",
                b"{\"name\":\"consumer\",\"version\":\"0.1.0\",\"dependencies\":{\"lib\":\"1.2.3\"}}",
            )],
        );

        let mut consumer = target("consumer", "0.1.0", &cons_sri, true);
        consumer.target.dependencies = vec![LinkDependency::registry("lib", "1.2.3")];
        let lib = target("lib", "1.2.3", &lib_sri, false);

        let result = link_packages_v2(
            &project,
            vec![consumer, lib],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.linked, 2);
        // Only `consumer` is direct → exactly one root symlink.
        assert_eq!(result.symlinked, 1);

        let consumer_root = project.join("node_modules").join("consumer");
        assert!(
            consumer_root
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // Sibling symlink lives at `<consumer_link_dir>/node_modules/lib`,
        // not nested inside `consumer/`. From the project, the
        // sibling is reachable via `<consumer_root>/../lib` once
        // Node resolves the symlink — but the v2 contract is that
        // siblings are wrapper-level, so we walk one parent up.
        let consumer_link_pkg = result
            .materialized
            .iter()
            .find(|m| m.name == "consumer")
            .map(|m| m.destination.clone())
            .unwrap();
        let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
        let lib_sibling = consumer_link_dir.join("node_modules").join("lib");
        assert!(
            lib_sibling
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "sibling lib must be a symlink alongside consumer in the same node_modules/"
        );
        // And the symlink target resolves to the lib link entry's
        // package.json.
        assert!(lib_sibling.join("package.json").is_file());
    }

    #[test]
    fn link_packages_v2_materializes_next_compatibility_island_under_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let next_sri = synthetic_sri(b"v2/next-compat/next");
        write_object(
            &store,
            &next_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"next","version":"16.2.4","bin":{"next":"dist/bin/next"},"dependencies":{"@swc/helpers":"0.5.0"},"peerDependencies":{"react":"^19.0.0","react-dom":"^19.0.0"}}"#,
                ),
                ("dist/bin/next", b"#!/usr/bin/env node\n"),
            ],
        );
        let react_sri = synthetic_sri(b"v2/next-compat/react");
        write_object(
            &store,
            &react_sri,
            &[("package.json", br#"{"name":"react","version":"19.2.5"}"#)],
        );
        let react_dom_sri = synthetic_sri(b"v2/next-compat/react-dom");
        write_object(
            &store,
            &react_dom_sri,
            &[(
                "package.json",
                br#"{"name":"react-dom","version":"19.2.5"}"#,
            )],
        );
        let helpers_sri = synthetic_sri(b"v2/next-compat/swc-helpers");
        write_object(
            &store,
            &helpers_sri,
            &[(
                "package.json",
                br#"{"name":"@swc/helpers","version":"0.5.0"}"#,
            )],
        );

        let mut next = target("next", "16.2.4", &next_sri, true);
        next.target.dependencies = vec![LinkDependency::registry("@swc/helpers", "0.5.0")];
        next.target.peers = vec![
            ("react".to_string(), "19.2.5".to_string()),
            ("react-dom".to_string(), "19.2.5".to_string()),
        ];
        let react = target("react", "19.2.5", &react_sri, true);
        let react_dom = target("react-dom", "19.2.5", &react_dom_sri, true);
        let helpers = target("@swc/helpers", "0.5.0", &helpers_sri, false);

        let result = link_packages_v2_with_compatibility_bin_names(
            &project,
            vec![next, react, react_dom, helpers],
            &store,
            LinkerMode::Isolated,
            None,
            &["next".to_string()],
        )
        .unwrap();

        assert_eq!(result.bin_linked, 1, "next's bin shim must still be linked");
        let compat_root = project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .expect("compatibility root should exist");
        assert!(
            !project.join(".lpm").join("compat").exists(),
            "compatibility layout must not sit at project root where framework watchers recurse",
        );
        let store_root = store
            .paths()
            .root()
            .canonicalize()
            .expect("store root should exist");
        let next_root = project.join("node_modules").join("next");
        let next_real = next_root
            .canonicalize()
            .expect("project next root should resolve");
        assert!(
            next_real.starts_with(&compat_root),
            "Next's root realpath must stay under the project compatibility island, got {}",
            next_real.display(),
        );
        assert!(
            !next_real.starts_with(&store_root),
            "Next's root realpath must not point straight into the global v2 store",
        );

        let compat_node_modules = next_real
            .parent()
            .expect("next package dir should live under node_modules");
        for package in ["react", "react-dom", "@swc/helpers"] {
            let package_dir = compat_node_modules.join(package);
            assert!(
                package_dir.join("package.json").is_file(),
                "{package} must be available inside Next's project-local compatibility island",
            );
            let package_real = package_dir
                .canonicalize()
                .unwrap_or_else(|e| panic!("{package} should resolve: {e}"));
            assert!(
                package_real.starts_with(&compat_root),
                "{package} must resolve inside the project compatibility island, got {}",
                package_real.display(),
            );
            assert!(
                !package_real.starts_with(&store_root),
                "{package} must not resolve straight into the global v2 store",
            );
        }

        #[cfg(unix)]
        {
            let shim = project.join("node_modules").join(".bin").join("next");
            let shim_target = std::fs::read_link(&shim).expect("next shim should be a symlink");
            let shim_real = shim
                .parent()
                .unwrap()
                .join(shim_target)
                .canonicalize()
                .expect("next shim target should resolve");
            assert!(
                shim_real.starts_with(&compat_root),
                "next bin shim should execute the project-local compatibility copy, got {}",
                shim_real.display(),
            );
        }
    }

    #[test]
    fn link_packages_v2_compatibility_island_exposes_project_direct_context() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let server_sri = synthetic_sri(b"v2/compat-context/dev-server");
        write_object(
            &store,
            &server_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"dev-server","version":"1.0.0","bin":{"dev-server":"bin/dev-server.js"},"dependencies":{"shared":"1.0.0"}}"#,
                ),
                ("bin/dev-server.js", b"#!/usr/bin/env node\n"),
            ],
        );
        let cli_sri = synthetic_sri(b"v2/compat-context/delegated-cli");
        write_object(
            &store,
            &cli_sri,
            &[(
                "package.json",
                br#"{"name":"delegated-cli","version":"1.0.0"}"#,
            )],
        );
        let shared_dep_sri = synthetic_sri(b"v2/compat-context/shared-1");
        write_object(
            &store,
            &shared_dep_sri,
            &[("package.json", br#"{"name":"shared","version":"1.0.0"}"#)],
        );
        let shared_root_sri = synthetic_sri(b"v2/compat-context/shared-2");
        write_object(
            &store,
            &shared_root_sri,
            &[("package.json", br#"{"name":"shared","version":"2.0.0"}"#)],
        );

        let mut server = target("dev-server", "1.0.0", &server_sri, true);
        server.target.dependencies = vec![LinkDependency::registry("shared", "1.0.0")];
        let delegated_cli = target("delegated-cli", "1.0.0", &cli_sri, true);
        let shared_dep = target("shared", "1.0.0", &shared_dep_sri, false);
        let shared_root = target("shared", "2.0.0", &shared_root_sri, true);

        link_packages_v2_with_compatibility_bin_names(
            &project,
            vec![server, delegated_cli, shared_dep, shared_root],
            &store,
            LinkerMode::Isolated,
            None,
            &["dev-server".to_string()],
        )
        .unwrap();

        let compat_root = project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .expect("compatibility root should exist");
        let server_real = project
            .join("node_modules")
            .join("dev-server")
            .canonicalize()
            .expect("dev-server root should resolve");
        let compat_node_modules = server_real
            .parent()
            .expect("dev-server package dir should live under node_modules");

        let delegated_real = compat_node_modules
            .join("delegated-cli")
            .canonicalize()
            .expect("project direct delegated CLI should resolve inside compat");
        assert!(
            delegated_real.starts_with(&compat_root),
            "delegated CLI should resolve inside compat, got {}",
            delegated_real.display(),
        );

        let shared_package_json = compat_node_modules.join("shared").join("package.json");
        let shared_manifest =
            std::fs::read_to_string(&shared_package_json).expect("shared package.json");
        assert!(
            shared_manifest.contains("\"version\":\"1.0.0\""),
            "package-owned dependency should beat project direct context at {}, got {shared_manifest}",
            shared_package_json.display(),
        );
    }

    #[test]
    fn link_packages_v2_materializes_direct_bins_in_project_compatibility_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/unrequested-bin/tool");
        write_object(
            &store,
            &sri,
            &[
                (
                    "package.json",
                    br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
                ),
                ("bin/tool.js", b"#!/usr/bin/env node\n"),
            ],
        );

        let result = link_packages_v2(
            &project,
            vec![target("tool", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.bin_linked, 1, "tool's bin shim must be linked");
        let compat_root = project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .expect("direct bin should create project compatibility layout");
        assert!(compat_root.is_dir());
        #[cfg(unix)]
        {
            let shim = project.join("node_modules").join(".bin").join("tool");
            let shim_target = std::fs::read_link(&shim).expect("tool shim should be a symlink");
            let shim_real = shim
                .parent()
                .unwrap()
                .join(shim_target)
                .canonicalize()
                .expect("tool shim target should resolve");
            assert!(
                shim_real.starts_with(&compat_root),
                "direct bin shim should execute the project compatibility copy, got {}",
                shim_real.display(),
            );
        }
    }

    #[test]
    fn project_compatibility_bins_ready_accepts_projects_without_direct_bins() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let package_dir = project.join("node_modules").join("library");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            br#"{"name":"library","version":"1.0.0"}"#,
        )
        .unwrap();

        assert!(
            project_compatibility_bins_ready(&project, &[]),
            "projects with no direct package bins do not need a compatibility .bin layout"
        );
    }

    #[test]
    fn project_compatibility_bins_ready_rejects_missing_shim_for_direct_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let package_dir = project.join("node_modules").join("tool");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
        )
        .unwrap();

        assert!(
            !project_compatibility_bins_ready(&project, &[]),
            "a direct package bin requires a .bin shim into the compatibility layout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn finalize_existing_link_entries_refreshes_compatibility_copy_after_generated_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/generated-bin/tool");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                br#"{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}"#,
            )],
        );
        let tool = target("tool", "1.0.0", &sri, true);

        let first = link_packages_v2_with_compatibility_bin_names(
            &project,
            vec![tool.clone()],
            &store,
            LinkerMode::Isolated,
            None,
            &["tool".to_string()],
        )
        .unwrap();
        assert_eq!(
            first.bin_linked, 0,
            "pre-build link must skip a declared bin whose target does not exist yet"
        );

        let link_pkg = store
            .find_link_package_dir("tool", "1.0.0")
            .unwrap()
            .expect("initial link must populate the v2 link entry");
        let generated_bin = link_pkg.join("bin").join("tool.js");
        std::fs::create_dir_all(generated_bin.parent().unwrap()).unwrap();
        std::fs::write(&generated_bin, b"#!/usr/bin/env node\n").unwrap();

        let refreshed = finalize_existing_link_entries_with_compatibility_bin_names(
            &project,
            vec![tool],
            &store,
            LinkerMode::Isolated,
            None,
            &["tool".to_string()],
        )
        .unwrap();
        assert_eq!(
            refreshed.bin_linked, 1,
            "post-build finalize must link the generated bin"
        );

        let compat_root = project
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .expect("compatibility root should exist");
        let shim = project.join("node_modules").join(".bin").join("tool");
        let shim_target = std::fs::read_link(&shim).expect("tool shim should be a symlink");
        let shim_real = shim
            .parent()
            .unwrap()
            .join(shim_target)
            .canonicalize()
            .expect("tool shim target should resolve");
        assert!(
            shim_real.starts_with(&compat_root),
            "generated bin shim should point at the refreshed compatibility copy, got {}",
            shim_real.display(),
        );
    }

    #[test]
    fn link_packages_v2_skips_dependency_local_name_with_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let consumer_sri = synthetic_sri(b"link_packages_v2/unsafe_dep_consumer");
        write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"consumer\",\"version\":\"1.0.0\"}",
            )],
        );
        let dep_sri = synthetic_sri(b"link_packages_v2/unsafe_dep_target");
        write_object(
            &store,
            &dep_sri,
            &[(
                "package.json",
                b"{\"name\":\"debug\",\"version\":\"1.0.0\"}",
            )],
        );

        let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
        consumer.target.dependencies = vec![LinkDependency::new(
            "../../../../escape",
            "debug",
            "1.0.0",
            None,
        )];
        let debug = target("debug", "1.0.0", &dep_sri, false);

        let result = link_packages_v2(
            &project,
            vec![consumer, debug],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.linked, 2);
        assert!(
            project.join("escape").symlink_metadata().is_err(),
            "unsafe dependency local name must not create an entry outside the link entry",
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_packages_v2_supports_local_source_dep_edges() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        let source_dir = tmp.path().join("sources").join("cycle-b");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(
            source_dir.join("package.json"),
            b"{\"name\":\"@smoke/cycle-b\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(source_dir.join("index.js"), b"module.exports = 'before';\n").unwrap();

        let local_sri = synthetic_sri(b"link_packages_v2/local_source_cycle_b");
        write_local_source_object(&store, &local_sri, &source_dir);

        let consumer_sri = synthetic_sri(b"link_packages_v2/external_reentry");
        write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"external-reentry\",\"version\":\"1.0.0\",\"dependencies\":{\"@smoke/cycle-b\":\"1.0.0\"}}",
            )],
        );

        let mut consumer = target("external-reentry", "1.0.0", &consumer_sri, true);
        consumer.target.dependencies = vec![LinkDependency::registry("@smoke/cycle-b", "1.0.0")];

        let mut local = target("@smoke/cycle-b", "1.0.0", &local_sri, false);
        local.target.materialization = crate::Materialization::DirectorySource;

        let result = link_packages_v2(
            &project,
            vec![consumer, local],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        let consumer_link_pkg = result
            .materialized
            .iter()
            .find(|m| m.name == "external-reentry")
            .map(|m| m.destination.clone())
            .unwrap();
        let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
        let local_sibling = consumer_link_dir
            .join("node_modules")
            .join("@smoke/cycle-b");
        assert!(
            local_sibling.join("package.json").is_file(),
            "local-source dep sibling must resolve inside the consumer link entry"
        );

        let local_link_pkg = result
            .materialized
            .iter()
            .find(|m| m.name == "@smoke/cycle-b")
            .map(|m| m.destination.clone())
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(local_link_pkg.join("index.js")).unwrap(),
            "module.exports = 'before';\n"
        );
        assert!(
            !local_link_pkg
                .join("index.js")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "local-source entrypoints must be real files so Node resolves deps from the v2 link entry"
        );
    }

    #[test]
    fn link_packages_v2_wipes_legacy_v1_wrappers() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        let v1_wrappers = project.join(".lpm").join("wrappers").join("stale@1.0.0");
        std::fs::create_dir_all(&v1_wrappers).unwrap();
        std::fs::write(v1_wrappers.join("ghost"), b"left over").unwrap();

        let sri = synthetic_sri(b"link_packages_v2/wipe");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")],
        );

        link_packages_v2(
            &project,
            vec![target("x", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert!(
            !project.join(".lpm").join("wrappers").exists(),
            "v2 linker must wipe legacy v1 wrapper tree"
        );
    }

    #[test]
    fn link_packages_v2_with_explicit_root_link_names() {
        // `root_link_names = Some([])` means "explicitly no root
        // symlinks" — even for an `is_direct = true` target. Mirrors
        // the LinkTarget contract.
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");

        let sri = synthetic_sri(b"link_packages_v2/explicit_empty");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
        );

        let mut t = target("a", "1.0.0", &sri, true);
        t.target.root_link_names = Some(vec![]);
        let result =
            link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap();
        assert_eq!(result.symlinked, 0);
        assert!(!project.join("node_modules").join("a").exists());
    }

    #[test]
    fn link_packages_v2_removes_stale_root_symlinks_without_wiping_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let a_sri = synthetic_sri(b"v2/reconcile/a");
        let b_sri = synthetic_sri(b"v2/reconcile/b");
        write_object(
            &store,
            &a_sri,
            &[("package.json", b"{\"name\":\"a\",\"version\":\"1.0.0\"}")],
        );
        write_object(
            &store,
            &b_sri,
            &[("package.json", b"{\"name\":\"b\",\"version\":\"1.0.0\"}")],
        );

        link_packages_v2(
            &project,
            vec![
                target("a", "1.0.0", &a_sri, true),
                target("b", "1.0.0", &b_sri, true),
            ],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();
        assert!(project.join("node_modules").join("a").exists());
        assert!(project.join("node_modules").join("b").exists());

        link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &a_sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert!(project.join("node_modules").join("a").exists());
        assert!(!project.join("node_modules").join("b").exists());
        assert!(project.join("node_modules").exists());
    }

    #[test]
    fn link_packages_v2_self_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"link_packages_v2/self_ref");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
        );

        let result = link_packages_v2(
            &project,
            vec![target("d", "1.0.0", &sri, false)],
            &store,
            LinkerMode::Isolated,
            Some("self-pkg"),
        )
        .unwrap();

        assert!(result.self_referenced);
        let self_link = project.join("node_modules").join("self-pkg");
        let read = std::fs::read_link(&self_link).unwrap();
        assert_eq!(read, project);
    }

    #[test]
    fn link_packages_v2_skips_self_reference_when_project_name_contains_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"link_packages_v2/self_ref_traversal");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"d\",\"version\":\"1.0.0\"}")],
        );

        let result = link_packages_v2(
            &project,
            vec![target("d", "1.0.0", &sri, false)],
            &store,
            LinkerMode::Isolated,
            Some("../escape"),
        )
        .unwrap();

        assert!(
            !result.self_referenced,
            "unsafe self-reference names must be skipped"
        );
        assert!(
            !project.join("escape").exists(),
            "self-reference must not create an entry outside node_modules",
        );
    }

    #[test]
    fn link_packages_v2_missing_dep_key_surfaces_error() {
        // A LinkTarget references a dep version that wasn't included
        // in the install set — must NOT silently produce a broken
        // sibling symlink.
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");

        let sri = synthetic_sri(b"link_packages_v2/missing_dep");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"c\",\"version\":\"1.0.0\"}")],
        );
        let mut t = target("c", "1.0.0", &sri, true);
        // Dep 'phantom@9.9.9' has no matching LinkTarget in the set.
        t.target.dependencies = vec![LinkDependency::registry("phantom", "9.9.9")];

        let err =
            link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("phantom@9.9.9"),
            "missing-dep error must name the missing edge: {msg}"
        );
    }

    /// **Cross-project peer-divergence invariant.**
    ///
    /// The same consumer package + edge graph but a different
    /// resolved-peer version MUST produce distinct GraphKeys, so two
    /// projects that pin the same peer differently get separate
    /// `links/<key>/` entries instead of silently sharing.
    ///
    /// Setup: two installs, each with consumer `c@1.0.0` declaring
    /// peer `react`. Install 1 has `react@18.0.0` in its install set;
    /// install 2 has `react@19.0.0`. Both call `link_packages_v2` and
    /// the resulting MaterializedPackage destinations for `c@1.0.0`
    /// must differ (because the GraphKey path component differs).
    #[test]
    fn link_packages_v2_distinct_keys_for_peer_divergent_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));

        let c_pkg_json =
            b"{\"name\":\"c\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}";
        let c_sri = synthetic_sri(b"peer_divergent/c");
        write_object(&store, &c_sri, &[("package.json", c_pkg_json)]);

        let r18_sri = synthetic_sri(b"peer_divergent/react@18");
        write_object(
            &store,
            &r18_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
            )],
        );
        let r19_sri = synthetic_sri(b"peer_divergent/react@19");
        write_object(
            &store,
            &r19_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"19.0.0\"}",
            )],
        );

        // Project 1: c + react@18. `LinkTarget.peers` arrives empty
        // here — same shape as the lockfile fast path — so
        // `ensure_peer_context` derives peers by reading c's
        // `package.json` and intersecting with the install set.
        let proj1 = tmp.path().join("project1");
        std::fs::create_dir_all(&proj1).unwrap();
        let result_p1 = link_packages_v2(
            &proj1,
            vec![
                target("c", "1.0.0", &c_sri, true),
                target("react", "18.0.0", &r18_sri, false),
            ],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        // Project 2: c + react@19.
        let proj2 = tmp.path().join("project2");
        std::fs::create_dir_all(&proj2).unwrap();
        let result_p2 = link_packages_v2(
            &proj2,
            vec![
                target("c", "1.0.0", &c_sri, true),
                target("react", "19.0.0", &r19_sri, false),
            ],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        let c_dest_p1 = result_p1
            .materialized
            .iter()
            .find(|m| m.name == "c")
            .map(|m| m.destination.clone())
            .expect("c materialized in project 1");
        let c_dest_p2 = result_p2
            .materialized
            .iter()
            .find(|m| m.name == "c")
            .map(|m| m.destination.clone())
            .expect("c materialized in project 2");
        assert_ne!(
            c_dest_p1, c_dest_p2,
            "peer-divergent installs must produce distinct link entries for c@1.0.0; \
             without peers in the GraphKey they would alias"
        );

        // And each project resolves its peer to the version IT
        // actually has — proj1 sees react@18, proj2 sees react@19.
        // The link entry's sibling symlink targets the version-
        // specific link package dir.
        let r_sibling_p1 = c_dest_p1
            .parent()
            .unwrap()
            .join("react")
            .join("package.json");
        let r_sibling_p2 = c_dest_p2
            .parent()
            .unwrap()
            .join("react")
            .join("package.json");
        let r1_pkg = std::fs::read_to_string(&r_sibling_p1).unwrap();
        let r2_pkg = std::fs::read_to_string(&r_sibling_p2).unwrap();
        assert!(
            r1_pkg.contains("18.0.0"),
            "project 1's c link entry must point at react@18: got {r1_pkg}"
        );
        assert!(
            r2_pkg.contains("19.0.0"),
            "project 2's c link entry must point at react@19: got {r2_pkg}"
        );
    }

    /// Inverse of the divergence test: same consumer + same resolved
    /// peer version across two installs MUST produce the same
    /// GraphKey, so the global v2 store can share `links/<key>/`
    /// across projects. Without this, every project pays a fresh
    /// materialization tax even when the dep + peer graph is
    /// identical — defeating the cross-project sharing the v2
    /// rewrite is supposed to unlock.
    #[test]
    fn link_packages_v2_shares_keys_for_peer_identical_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));

        let c_pkg_json =
            b"{\"name\":\"c\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}";
        let c_sri = synthetic_sri(b"peer_shared/c");
        write_object(&store, &c_sri, &[("package.json", c_pkg_json)]);

        let r_sri = synthetic_sri(b"peer_shared/react");
        write_object(
            &store,
            &r_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
            )],
        );

        let proj1 = tmp.path().join("project1");
        let proj2 = tmp.path().join("project2");
        std::fs::create_dir_all(&proj1).unwrap();
        std::fs::create_dir_all(&proj2).unwrap();

        let result_p1 = link_packages_v2(
            &proj1,
            vec![
                target("c", "1.0.0", &c_sri, true),
                target("react", "18.0.0", &r_sri, false),
            ],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();
        let result_p2 = link_packages_v2(
            &proj2,
            vec![
                target("c", "1.0.0", &c_sri, true),
                target("react", "18.0.0", &r_sri, false),
            ],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        let c_dest_p1 = result_p1
            .materialized
            .iter()
            .find(|m| m.name == "c")
            .map(|m| m.destination.clone())
            .unwrap();
        let c_dest_p2 = result_p2
            .materialized
            .iter()
            .find(|m| m.name == "c")
            .map(|m| m.destination.clone())
            .unwrap();
        assert_eq!(
            c_dest_p1, c_dest_p2,
            "same edge graph + same peer pinning across two projects must share the link entry"
        );
    }

    #[test]
    fn link_packages_v2_hoisted_mode_accepts_targets_with_peer_context() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let consumer_sri = synthetic_sri(b"hoisted_peers/consumer");
        write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"consumer\",\"version\":\"1.0.0\",\"peerDependencies\":{\"react\":\"*\"}}",
            )],
        );

        let react_sri = synthetic_sri(b"hoisted_peers/react");
        write_object(
            &store,
            &react_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.3.1\"}",
            )],
        );

        let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
        consumer.target.peers = vec![("react".into(), "18.3.1".into())];
        let react = target("react", "18.3.1", &react_sri, false);

        let result = link_packages_v2(
            &project,
            vec![consumer, react],
            &store,
            LinkerMode::Hoisted,
            None,
        )
        .unwrap();

        assert_eq!(result.linked, 2);
        assert_eq!(result.symlinked, 1);
        assert!(project.join("node_modules").join("consumer").exists());
    }

    #[test]
    fn link_packages_v2_hoisted_mode_splits_peer_divergent_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));

        let consumer_sri = synthetic_sri(b"hoisted_peer_divergent/consumer");
        write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"consumer\",\"version\":\"1.0.0\"}",
            )],
        );

        let react_18_sri = synthetic_sri(b"hoisted_peer_divergent/react@18");
        write_object(
            &store,
            &react_18_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.3.1\"}",
            )],
        );
        let react_19_sri = synthetic_sri(b"hoisted_peer_divergent/react@19");
        write_object(
            &store,
            &react_19_sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"19.0.0\"}",
            )],
        );

        let project_18 = tmp.path().join("project-18");
        std::fs::create_dir_all(&project_18).unwrap();
        let mut consumer_18 = target("consumer", "1.0.0", &consumer_sri, true);
        consumer_18.target.peers = vec![("react".into(), "18.3.1".into())];
        let result_18 = link_packages_v2(
            &project_18,
            vec![consumer_18, target("react", "18.3.1", &react_18_sri, false)],
            &store,
            LinkerMode::Hoisted,
            None,
        )
        .unwrap();

        let project_19 = tmp.path().join("project-19");
        std::fs::create_dir_all(&project_19).unwrap();
        let mut consumer_19 = target("consumer", "1.0.0", &consumer_sri, true);
        consumer_19.target.peers = vec![("react".into(), "19.0.0".into())];
        let result_19 = link_packages_v2(
            &project_19,
            vec![consumer_19, target("react", "19.0.0", &react_19_sri, false)],
            &store,
            LinkerMode::Hoisted,
            None,
        )
        .unwrap();

        let consumer_dest_18 = result_18
            .materialized
            .iter()
            .find(|m| m.name == "consumer")
            .map(|m| m.destination.clone())
            .expect("consumer materialized with react 18");
        let consumer_dest_19 = result_19
            .materialized
            .iter()
            .find(|m| m.name == "consumer")
            .map(|m| m.destination.clone())
            .expect("consumer materialized with react 19");
        assert_ne!(
            consumer_dest_18, consumer_dest_19,
            "hoisted v2 link entries must include peer pinning when peer siblings are materialized"
        );
    }

    #[test]
    fn link_packages_v2_resolves_multi_source_same_coords_with_source_edges() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let registry_sri = synthetic_sri(b"multi_source/registry");
        let source_sri = synthetic_sri(b"multi_source/source");
        let consumer_sri = synthetic_sri(b"multi_source/consumer");
        write_object(
            &store,
            &registry_sri,
            &[
                ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
                ("index.js", b"module.exports = 'registry';\n"),
            ],
        );
        write_object(
            &store,
            &source_sri,
            &[
                ("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}"),
                ("index.js", b"module.exports = 'source';\n"),
            ],
        );
        write_object(
            &store,
            &consumer_sri,
            &[(
                "package.json",
                b"{\"name\":\"consumer\",\"version\":\"1.0.0\",\"dependencies\":{\"x\":\"1.0.0\"}}",
            )],
        );

        let registry_x = target("x", "1.0.0", &registry_sri, true);
        let mut source_x = target("x", "1.0.0", &source_sri, false);
        source_x.target.wrapper_id = Some("t-bbbbbbbbbbbbbbbb".into());
        let mut consumer = target("consumer", "1.0.0", &consumer_sri, true);
        consumer.target.dependencies = vec![LinkDependency::new(
            "x",
            "x",
            "1.0.0",
            Some("t-bbbbbbbbbbbbbbbb".into()),
        )];

        let result = link_packages_v2(
            &project,
            vec![registry_x, source_x, consumer],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.linked, 3);
        assert!(
            project
                .join("node_modules")
                .join("x")
                .join("index.js")
                .is_file()
        );

        let consumer_link_pkg = result
            .materialized
            .iter()
            .find(|m| m.name == "consumer")
            .map(|m| m.destination.clone())
            .unwrap();
        let consumer_link_dir = consumer_link_pkg.parent().unwrap().parent().unwrap();
        let source_sibling = consumer_link_dir.join("node_modules").join("x");
        assert_eq!(
            std::fs::read_to_string(source_sibling.join("index.js")).unwrap(),
            "module.exports = 'source';\n",
        );
    }

    // ── F1 — patch_fingerprint cross-project isolation ──────────────────
    //
    // **Load-bearing for the patch-engine contract under v2.** Patches
    // are documented as repo-local (`crates/lpm-cli/src/commands/patch.rs:18`):
    // "Patches travel with the repo. The next `lpm install` automatically
    // re-applies them after linking." Under v2's cross-project link
    // sharing, two projects with identical dep graphs
    // resolve to the same `<store>/v2/links/<key>/...` directory by
    // design. Without F1's `patch_fingerprint` dimension, project A's
    // `apply_patch` mutation lands in the shared dir and project B's
    // symlinks resolve through it — silently leaking patched bytes
    // across project boundaries.
    //
    // The fix folds patch identity into the GraphKey so:
    // 1. A patched install lands in its own `links/<key>+<patch-hash>/`
    //    directory, distinct from any unpatched install of the same
    //    coords.
    // 2. Two projects applying byte-identical patches with the same
    //    pinned baseline still share (correct — equivalent
    //    materializations are interchangeable).
    // 3. Edits to the patch text or `originalIntegrity` rotation split
    //    into a fresh entry (old patched bytes can never leak forward).

    #[test]
    fn link_packages_v2_isolates_patched_install_from_unpatched() {
        // Two projects pin lodash@1.0.0 with identical dep graphs.
        // Project A declares a patch (carries `patch_fingerprint`);
        // project B is unpatched. The two installs MUST land at
        // different link-entry directories.
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));

        let sri = synthetic_sri(b"f1_isolation/lodash");
        write_object(
            &store,
            &sri,
            &[
                (
                    "package.json",
                    b"{\"name\":\"lodash\",\"version\":\"1.0.0\"}",
                ),
                ("index.js", b"module.exports = 'orig';\n"),
            ],
        );

        let proj_a = tmp.path().join("project-a-patched");
        let proj_b = tmp.path().join("project-b-unpatched");
        std::fs::create_dir_all(&proj_a).unwrap();
        std::fs::create_dir_all(&proj_b).unwrap();

        let mut t_a = target("lodash", "1.0.0", &sri, true);
        t_a.target.patch_fingerprint = Some("p-aaaaaaaaaaaaaaaa".into());
        let t_b = target("lodash", "1.0.0", &sri, true); // unpatched

        let r_a = link_packages_v2(&proj_a, vec![t_a], &store, LinkerMode::Isolated, None).unwrap();
        let r_b = link_packages_v2(&proj_b, vec![t_b], &store, LinkerMode::Isolated, None).unwrap();

        let dest_a = r_a
            .materialized
            .iter()
            .find(|m| m.name == "lodash")
            .map(|m| m.destination.clone())
            .unwrap();
        let dest_b = r_b
            .materialized
            .iter()
            .find(|m| m.name == "lodash")
            .map(|m| m.destination.clone())
            .unwrap();
        assert_ne!(
            dest_a, dest_b,
            "patched install MUST land in a different link entry than \
             an unpatched install of the same coords — without this, \
             `apply_patch` mutates the dir project B's symlinks resolve \
             through, silently exporting the patch across projects"
        );

        // Byte-isolation cross-check: simulate what `apply_patch` does
        // (`remove_file` + `write` to break inode-share) on project A's
        // destination, then assert project B's bytes are pristine.
        // Combined with the assert_ne above this is the full F1
        // contract: distinct paths + distinct bytes after mutation.
        let a_file = dest_a.join("index.js");
        let b_file = dest_b.join("index.js");
        std::fs::remove_file(&a_file).unwrap();
        std::fs::write(&a_file, b"module.exports = 'PATCHED';\n").unwrap();

        let b_bytes = std::fs::read(&b_file).unwrap();
        assert_eq!(
            b_bytes, b"module.exports = 'orig';\n",
            "project B's bytes MUST remain pristine after project A patches its own link entry"
        );
    }

    #[test]
    fn link_packages_v2_shares_link_entry_for_byte_identical_patches() {
        // Two projects applying byte-identical patches against the
        // same baseline SHOULD share a single link entry — that's the
        // whole point of content-derived patch fingerprinting (the
        // cheap, correct case the F1 design unlocks). Without this,
        // every project would pay a fresh materialization tax even
        // when the patched output is byte-equivalent.
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));

        let sri = synthetic_sri(b"f1_shared_patch/lodash");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"lodash\",\"version\":\"1.0.0\"}",
            )],
        );

        let proj_a = tmp.path().join("project-a");
        let proj_b = tmp.path().join("project-b");
        std::fs::create_dir_all(&proj_a).unwrap();
        std::fs::create_dir_all(&proj_b).unwrap();

        let mut t_a = target("lodash", "1.0.0", &sri, true);
        t_a.target.patch_fingerprint = Some("p-1234567890abcdef".into());
        let mut t_b = target("lodash", "1.0.0", &sri, true);
        t_b.target.patch_fingerprint = Some("p-1234567890abcdef".into());

        let r_a = link_packages_v2(&proj_a, vec![t_a], &store, LinkerMode::Isolated, None).unwrap();
        let r_b = link_packages_v2(&proj_b, vec![t_b], &store, LinkerMode::Isolated, None).unwrap();

        let dest_a = r_a
            .materialized
            .iter()
            .find(|m| m.name == "lodash")
            .map(|m| m.destination.clone())
            .unwrap();
        let dest_b = r_b
            .materialized
            .iter()
            .find(|m| m.name == "lodash")
            .map(|m| m.destination.clone())
            .unwrap();
        assert_eq!(
            dest_a, dest_b,
            "byte-identical patch + identical baseline across two \
             projects MUST share the link entry"
        );
    }

    /// Parallel materialization above `PARALLEL_THRESHOLD = 32` must
    /// produce the same `LinkResult` shape as the sequential path:
    /// every input target gets a populated link entry, materialized
    /// count matches the input length, and `linked` (count of
    /// freshly-populated entries) sums correctly across rayon worker
    /// threads via the atomic counter.
    #[test]
    fn link_packages_v2_parallel_materialization_above_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        // 50 distinct packages — comfortably above the 32-package
        // threshold so the parallel branch fires.
        const N: usize = 50;
        let mut targets = Vec::with_capacity(N);
        for i in 0..N {
            let name = format!("pkg-{i}");
            let sri = synthetic_sri(format!("parallel/{name}").as_bytes());
            let pkg_json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
            write_object(&store, &sri, &[("package.json", pkg_json.as_bytes())]);
            targets.push(target(&name, "1.0.0", &sri, true));
        }

        let result =
            link_packages_v2(&project, targets, &store, LinkerMode::Isolated, None).unwrap();

        // Every package freshly populated: linked counter must match N.
        assert_eq!(
            result.linked, N,
            "atomic counter must sum correctly across rayon workers"
        );
        // Each direct dep gets one root symlink: symlinked must match N.
        assert_eq!(result.symlinked, N);
        // Materialized list preserves one entry per input.
        assert_eq!(result.materialized.len(), N);
        // Every materialized destination resolves to a real package
        // dir — proves the link entry was actually populated, not just
        // counted.
        for m in &result.materialized {
            assert!(
                m.destination.join("package.json").is_file(),
                "package dir {} must contain package.json post-materialization",
                m.destination.display()
            );
        }
        // Every project-side root symlink resolves through to the link
        // entry — confirms the post-parallel `create_root_symlinks`
        // pass saw all `N` graph keys via the key_map.
        for i in 0..N {
            let name = format!("pkg-{i}");
            let link = project.join("node_modules").join(&name);
            assert!(
                link.symlink_metadata().unwrap().file_type().is_symlink(),
                "project-side root symlink for {name} must exist after parallel materialization"
            );
            assert!(link.join("package.json").is_file());
        }
    }

    /// A package whose `bin` map keys a shim with a path-traversal
    /// name must be skipped. v1's hoisted emitter has enforced this
    /// since the validators were introduced; v2 (the default store
    /// version) was the gap a malicious package could exploit to
    /// shadow `/usr/bin` entries via `node_modules/.bin/`.
    #[test]
    fn v2_skips_bin_shim_when_bin_name_contains_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/bin_name_traversal");
        write_object(
            &store,
            &sri,
            &[
                (
                    "package.json",
                    br#"{"name":"a","version":"1.0.0","bin":{"../escape":"index.js"}}"#,
                ),
                ("index.js", b"console.log('a');"),
            ],
        );

        let result = link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(
            result.bin_linked, 0,
            "bin name with `..` must be rejected by validate_bin_name",
        );
        let bin_dir = project.join("node_modules").join(".bin");
        if bin_dir.exists() {
            assert!(
                std::fs::read_dir(&bin_dir).unwrap().next().is_none(),
                ".bin/ must stay empty when the only entry was rejected",
            );
        }
    }

    /// A package whose `bin` value points outside its own dir (the
    /// classic `"bin": {"x": "../../bin/sh"}` shape) must be skipped.
    /// `validate_bin_target` catches the `..` component in the joined
    /// path before any symlink is created.
    #[test]
    fn v2_skips_bin_shim_when_bin_target_escapes_package_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/bin_target_traversal");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                br#"{"name":"a","version":"1.0.0","bin":{"x":"../../../bin/sh"}}"#,
            )],
        );

        let result = link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(
            result.bin_linked, 0,
            "bin target with `..` components must be rejected by validate_bin_target",
        );
        let shim = project.join("node_modules").join(".bin").join("x");
        assert!(
            shim.symlink_metadata().is_err(),
            "no shim should be created for an escaping bin target",
        );
    }

    /// Benign shape still works — proves the new validators don't
    /// over-reject. A well-formed bin entry pointing at an in-package
    /// file produces a `.bin/` symlink.
    #[test]
    fn v2_creates_bin_shim_for_well_formed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/bin_ok");
        write_object(
            &store,
            &sri,
            &[
                (
                    "package.json",
                    br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
                ),
                ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
            ],
        );

        let result = link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert_eq!(result.bin_linked, 1, "well-formed bin entry must be linked");
        #[cfg(unix)]
        {
            let shim = project.join("node_modules").join(".bin").join("a");
            assert!(
                shim.symlink_metadata().unwrap().file_type().is_symlink(),
                "shim must be a symlink",
            );
        }
    }

    #[test]
    fn link_packages_v2_removes_stale_bin_shims_when_bins_disappear() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let with_bin_sri = synthetic_sri(b"v2/stale-bin/with");
        write_object(
            &store,
            &with_bin_sri,
            &[
                (
                    "package.json",
                    br#"{"name":"a","version":"1.0.0","bin":{"a":"cli.js"}}"#,
                ),
                ("cli.js", b"#!/usr/bin/env node\nconsole.log('hi');\n"),
            ],
        );
        link_packages_v2(
            &project,
            vec![target("a", "1.0.0", &with_bin_sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();
        assert!(project.join("node_modules").join(".bin").join("a").exists());

        let without_bin_sri = synthetic_sri(b"v2/stale-bin/without");
        write_object(
            &store,
            &without_bin_sri,
            &[("package.json", b"{\"name\":\"a\",\"version\":\"2.0.0\"}")],
        );
        link_packages_v2(
            &project,
            vec![target("a", "2.0.0", &without_bin_sri, true)],
            &store,
            LinkerMode::Isolated,
            None,
        )
        .unwrap();

        assert!(!project.join("node_modules").join(".bin").join("a").exists());
    }

    /// M16: the root-symlink writer does `remove_dir_all(&link_path)`
    /// before creating the symlink, where `link_path` is
    /// `<project>/node_modules/<root_link_name>`. A `..` in the
    /// name would escape `node_modules/` and delete arbitrary
    /// content. `root_link_names` now filters such names with a
    /// warn-and-continue posture.
    #[test]
    fn root_link_names_rejects_path_traversal_components() {
        let bad = [
            "..",
            "../escape",
            "scope/../escape",
            "deep/../../escape",
            "with\\backslash",
            "with\0null",
            "",
        ];
        for name in bad {
            assert!(
                !is_safe_root_link_name(name),
                "name {name:?} must be rejected as unsafe",
            );
        }
    }

    /// Positive baseline: legitimate names (plain + scoped) are
    /// accepted so the filter doesn't over-reject.
    #[test]
    fn root_link_names_accepts_plain_and_scoped_names() {
        for name in ["react", "lodash", "@scope/foo", "@a/b", "a-package_name"] {
            assert!(
                is_safe_root_link_name(name),
                "name {name:?} must be accepted",
            );
        }
    }

    /// End-to-end through link_packages_v2: a target whose
    /// `root_link_names` contains `..` MUST NOT create a symlink
    /// outside `<project>/node_modules/`. Pre-fix this would have
    /// landed a `remove_dir_all` against the escaped path.
    #[test]
    fn link_packages_v2_skips_root_symlink_when_name_contains_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let sri = synthetic_sri(b"v2/root_link_traversal");
        write_object(
            &store,
            &sri,
            &[("package.json", b"{\"name\":\"safe\",\"version\":\"1.0.0\"}")],
        );

        let mut t = target("safe", "1.0.0", &sri, true);
        t.target.root_link_names = Some(vec!["../escape".into(), "safe".into()]);

        let result =
            link_packages_v2(&project, vec![t], &store, LinkerMode::Isolated, None).unwrap();

        // Only the safe `safe` symlink should land — the `../escape`
        // entry filtered out by root_link_names.
        assert_eq!(
            result.symlinked, 1,
            "exactly one (safe) root symlink should land",
        );
        assert!(
            project
                .join("node_modules")
                .join("safe")
                .symlink_metadata()
                .is_ok(),
            "safe root symlink must exist",
        );
        // The escape path must not have been touched.
        assert!(
            !project.join("escape").exists(),
            "no `escape` entry should be created outside node_modules",
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_v2_finalize_replaces_symlinked_scope_parent_before_root_symlink_write() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let sri = synthetic_sri(b"v2/scope_parent_symlink");
        write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"@scope/pkg\",\"version\":\"1.0.0\"}",
            )],
        );

        let plan = link_v2_prepare(
            &project,
            vec![target("@scope/pkg", "1.0.0", &sri, true)],
            &store,
            LinkerMode::Isolated,
        )
        .unwrap();
        link_v2_one(&plan, &plan.augmented_targets[0], &store).unwrap();

        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        let scope_dir = project.join("node_modules").join("@scope");
        std::os::unix::fs::symlink(&outside, &scope_dir).unwrap();

        let result = link_v2_finalize(&project, &plan, &store, None).unwrap();

        assert_eq!(result.symlinked, 1);
        assert!(
            scope_dir.symlink_metadata().unwrap().file_type().is_dir(),
            "finalize must replace a symlinked scope parent with a real directory",
        );
        assert!(
            !scope_dir
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "scope parent must not remain a symlink",
        );
        assert!(
            !outside.join("pkg").exists(),
            "root symlink must not be created through a symlinked scope parent",
        );
        let root_link = scope_dir.join("pkg");
        assert!(
            root_link
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "scoped root link must be recreated under the real scope directory",
        );
        let key = plan
            .key_map
            .get_for(&plan.augmented_targets[0].target)
            .unwrap();
        assert!(
            symlink_points_to(&root_link, &store.paths().link_package_dir(key)),
            "scoped root link should point at the v2 link package dir",
        );
    }
}
