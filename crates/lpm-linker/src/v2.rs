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
//! When `LinkTarget.peers` is empty (lockfile fast-path doesn't
//! persist peers today), the linker falls back to deriving them
//! from the just-extracted `package.json` in `objects/<sri>/` and
//! intersecting with the install-set's `(name, version)` map. This
//! keeps cold-resolve and warm-fast-path producing the same
//! GraphKeys for the same package.
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
use lpm_common::symlink::create_dir_symlink_or_junction;
use lpm_store::v2::{
    DepLink, GraphKey, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag, PlatformTuple, Store,
};

use crate::{LinkResult, LinkTarget, LinkerMode, MaterializedPackage};

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
}

impl LinkPlanV2 {
    /// Are all targets ready for the event-driven path? True iff every
    /// `LinkTarget.peers` is already populated (resolver-threaded
    /// greedy-fusion path) and `ensure_peer_context` made no
    /// modifications. When false, callers should fall back to the
    /// serial wrapper [`link_packages_v2`] — the lockfile fast-path
    /// reads `package.json` from `objects/<sri>/` to derive peers,
    /// which requires the object to be extracted; calling
    /// `link_v2_prepare` before fetch would silently produce empty
    /// peer-context graph keys.
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

    let plan = link_v2_prepare(project_dir, targets, store, linker_mode)?;
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

    let finalize = link_v2_finalize(project_dir, &plan, store, self_package_name)?;

    Ok(LinkResult {
        linked: linked_count,
        symlinked: finalize.symlinked,
        bin_linked: finalize.bin_count,
        skipped: augmented_slice.len().saturating_sub(linked_count),
        self_referenced: finalize.self_referenced,
        materialized,
    })
}

/// Step 1 of the event-driven v2 link API.
///
/// Runs the post-resolve, pre-fetch sync work that the install pipeline
/// can complete without any object on disk:
/// 1. [`cleanup_v1_state`] — wipes legacy `<project>/.lpm/wrappers/`,
///    `<project>/.lpm/hoisted/`, and `<project>/node_modules/`. v2 always
///    rebuilds the project tree from scratch; per-package
///    [`link_v2_one`] tasks only write under
///    `~/.lpm/store/v2/links/<key>/`, so wiping early frees us to spawn
///    them in parallel with fetch.
/// 2. [`ensure_peer_context`] — best-effort fill-in for targets whose
///    [`LinkTarget::peers`] arrived empty (lockfile fast-path). Reads
///    `package.json` from extracted `objects/<sri>/`. **For
///    pre-fetch event-driven dispatch, callers MUST pre-check
///    [`LinkPlanV2::all_targets_have_resolver_threaded_peers`] and
///    fall back to the serial wrapper if it returns false.** Otherwise
///    peer-context for those targets is silently empty and graph keys
///    diverge from the serial path.
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
    // Top-level linker-stage span. Visible in Tracy with
    // `--features tracy`; filtered at INFO level so it's essentially
    // free in regular builds.
    let _span = tracing::info_span!("linker.prepare", target_count = targets.len(),).entered();
    cleanup_v1_state(project_dir)?;
    let mut augmented_targets = targets;
    ensure_peer_context(&mut augmented_targets, store)?;
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
    // Finalize-stage span. Nested sub-stages below split root /
    // bin / self-ref so the Tracy breakdown shows which phase
    // dominates for a given install.
    let _span = tracing::info_span!(
        "linker.finalize",
        target_count = plan.augmented_targets.len(),
    )
    .entered();
    let augmented_slice = &plan.augmented_targets[..];
    let symlinked = {
        let _s = tracing::info_span!("linker.finalize.root_symlinks").entered();
        create_root_symlinks(project_dir, augmented_slice, store, &plan.key_map)?
    };
    let bin_count = {
        let _s = tracing::info_span!("linker.finalize.bin_shims").entered();
        create_bin_links_v2(project_dir, augmented_slice, store, &plan.key_map)?
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
    // intersect declared peers against the install set. The
    // single-version-per-name shape is correct for the audit-fixture
    // scope; multi-source-same-name disambiguation flows through
    // wrapper_id at the GraphKey level.
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
                .map(|meta| meta.optional)
                .unwrap_or(false);
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
    for (local, ver) in &v2t.target.dependencies {
        let canonical = v2t
            .target
            .aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        let dep_key = key_map
            .get_by_coords(&canonical, ver)
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "v2 linker: dep {local}@{ver} of {}@{} has no resolved graph key",
                    v2t.target.name, v2t.target.version
                ))
            })?
            .clone();
        deps.push(DepLink {
            local: local.clone(),
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
                .filter(|(peer_name, _)| !already_local.contains(peer_name.as_str()))
                .filter_map(|(peer_name, peer_ver)| {
                    let peer_key = key_map.get_by_coords(peer_name, peer_ver)?.clone();
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

/// Per-install lookup table from `(name, version, wrapper_id)` to the
/// derived `GraphKey`.
///
/// Built once during [`link_v2_prepare`], stored on [`LinkPlanV2`],
/// consulted by every [`link_v2_one`] / [`link_v2_finalize`] call.
/// Public so callers can hold a reference across spawn boundaries
/// without reaching into linker private API.
///
/// Two indexes:
/// - `by_triple` — full `(name, version, wrapper_id)` identity. Used
///   by `populate_one` to fetch THIS target's own key.
/// - `by_coords` — `(name, version)` only. Used to resolve dep / peer
///   edges, which carry only `(name, version)` today. Multi-source
///   collisions are detected at construction time and surface a hard
///   error before any link entry materializes.
///
/// Keys are stored as a single `String` using a `\x00`-separated
/// compound key: `"name\x00version"` for `by_coords` and
/// `"name\x00version\x00wrapper_id"` for `by_triple`. Package names
/// and versions never contain null bytes, so there is no collision risk.
/// This lets lookups form the key with a single `format!` call (1 alloc)
/// instead of cloning each field separately (2–3 allocs per lookup).
pub struct KeyMap {
    by_triple: HashMap<String, Arc<GraphKey>>,
    // Value is `(Arc<GraphKey>, first_wrapper_id_seen)`. The wrapper_id
    // component exists solely to surface helpful collision-error messages —
    // it is stripped at lookup time so callers always receive `&Arc<GraphKey>`.
    by_coords: HashMap<String, (Arc<GraphKey>, Option<String>)>,
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

impl KeyMap {
    fn get_for(&self, target: &LinkTarget) -> Option<&Arc<GraphKey>> {
        self.by_triple.get(&triple_key(
            &target.name,
            &target.version,
            target.wrapper_id.as_deref(),
        ))
    }

    fn get_by_coords(&self, name: &str, version: &str) -> Option<&Arc<GraphKey>> {
        self.by_coords
            .get(&coords_key(name, version))
            .map(|(gk, _)| gk)
    }
}

fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Result<KeyMap, LpmError> {
    let mut by_triple: HashMap<String, Arc<GraphKey>> = HashMap::with_capacity(targets.len());
    let mut by_coords: HashMap<String, (Arc<GraphKey>, Option<String>)> =
        HashMap::with_capacity(targets.len());

    for v2t in targets {
        let key = Arc::new(GraphKey::derive_raw(
            &v2t.target.name,
            &v2t.target.version,
            platform,
            linker_tag,
            &v2t.target.dependencies,
            &v2t.target.aliases,
            &v2t.target.peers,
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

        // `ckey` ownership moves into the entry key — no clone needed.
        // The stored `Option<String>` is only used to produce a helpful
        // collision error message; `get_by_coords` strips it at lookup time.
        let ckey = coords_key(&v2t.target.name, &v2t.target.version);
        match by_coords.entry(ckey) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert((key, v2t.target.wrapper_id.clone()));
            }
            std::collections::hash_map::Entry::Occupied(existing) => {
                // Multi-source-same-coords. Dep edges carry only
                // `(name, version)`, so we can't disambiguate which
                // GraphKey a `dep on foo@1.0.0` should point at. Hard
                // error rather than silently aliasing one onto the
                // other; full disambiguation requires wrapper_id-aware
                // dep edges, which is a follow-up.
                return Err(LpmError::Store(format!(
                    "v2 linker: multi-source LinkTarget collision for {}@{} \
                     (existing wrapper_id={:?}, new wrapper_id={:?}). \
                     Multi-source disambiguation requires wrapper_id-aware \
                     dep edges.",
                    v2t.target.name,
                    v2t.target.version,
                    existing.get().1,
                    v2t.target.wrapper_id,
                )));
            }
        }
    }
    Ok(KeyMap {
        by_triple,
        by_coords,
    })
}

/// Wipe v1-style project link state so the v2 install starts clean.
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
    // `<project>/node_modules/` — wipe completely. v2 always rebuilds
    // from scratch; under v1 the linker also wipes stale entries via
    // `cleanup_stale_entries`. Wiping the whole tree is simpler and
    // `.bin/` must be wiped — bin shims regenerate from the active
    // install layout.
    let nm = project_dir.join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to wipe project node_modules at {}: {e}",
                nm.display()
            ))
        })?;
    }
    Ok(())
}

/// Create `<project>/node_modules/<root_link_name>` symlinks pointing
/// into the v2 store's link package dirs.
fn create_root_symlinks(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
) -> Result<usize, LpmError> {
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create project node_modules at {}: {e}",
            nm.display()
        ))
    })?;

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
            // Scoped root names (`@scope/dep`) need their `@scope/`
            // parent directory created.
            if let Some(parent) = link_path.parent()
                && parent != nm
                && !parent.exists()
            {
                std::fs::create_dir_all(parent).map_err(|e| {
                    LpmError::Store(format!(
                        "v2 linker: failed to create scope dir at {}: {e}",
                        parent.display()
                    ))
                })?;
            }
            // Best-effort cleanup: if a stale symlink/file is at the
            // slot, remove before re-creating. Should be a no-op after
            // `cleanup_v1_state` already wiped node_modules — defensive
            // guard for direct callers.
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
                let _ = std::fs::remove_dir_all(&link_path);
            }
            create_dir_symlink_or_junction(&target_path, &link_path).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to create root symlink {} → {}: {e}",
                    link_path.display(),
                    target_path.display()
                ))
            })?;
            count += 1;
        }
    }
    Ok(count)
}

/// Resolve a target's root-symlink filenames. Mirrors v1's contract
/// (see [`LinkTarget::root_link_names`] docs):
///
/// - `Some([])` — explicit "no root symlinks."
/// - `Some([…])` — explicit list of root names.
/// - `None` + direct dep — single root symlink at `[name]`.
/// - `None` + transitive — empty.
fn root_link_names(target: &LinkTarget) -> Vec<String> {
    if let Some(names) = &target.root_link_names {
        names.clone()
    } else if target.is_direct {
        vec![target.name.clone()]
    } else {
        Vec::new()
    }
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
        let pkg_dir = store.paths().link_package_dir(key);
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
            // Strip the conventional `bin/` slash prefix on a sub-path
            // to keep the shim target as the actual file inside the
            // package dir. The v1 helper does the same.
            bin_target.clear();
            bin_target.push(&pkg_dir);
            bin_target.push(&bin_rel_path);
            if !bin_target.exists() {
                tracing::debug!(
                    "v2 linker: bin script {} for {}/{} missing — skipping shim",
                    bin_target.display(),
                    v2t.target.name,
                    cmd_name
                );
                continue;
            }
            // Make the bin file executable (npm tarballs sometimes
            // ship without the +x bit). Same fix as v1.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&bin_target) {
                    let mut perms = meta.permissions();
                    let mode = perms.mode();
                    if mode & 0o111 == 0 {
                        perms.set_mode(mode | 0o111);
                        let _ = std::fs::set_permissions(&bin_target, perms);
                    }
                }
            }
            link_path.clear();
            link_path.push(&bin_dir);
            link_path.push(&cmd_name);
            // Best-effort cleanup of a stale shim.
            if link_path.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&link_path);
            }
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
    let nm = project_dir.join("node_modules");
    let link_path = nm.join(self_name);
    if link_path.symlink_metadata().is_ok() {
        return Ok(false);
    }
    if let Some(parent) = link_path.parent()
        && parent != nm
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to create self-ref scope dir at {}: {e}",
                parent.display()
            ))
        })?;
    }
    create_dir_symlink_or_junction(project_dir, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create self-ref symlink {} → {}: {e}",
            link_path.display(),
            project_dir.display()
        ))
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_store::v2::Store as V2Store;
    use std::path::PathBuf;

    fn synthetic_sri(seed: &[u8]) -> String {
        lpm_store::compute_sri_hash(seed)
    }

    fn write_object(store: &V2Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = store.paths().object_dir(sri).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for (name, contents) in files {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, contents).unwrap();
        }
        // Mark complete (v1-symmetric markers).
        std::fs::write(dir.join(".integrity"), sri).unwrap();
        dir
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
        consumer.target.dependencies = vec![("lib".into(), "1.2.3".into())];
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
        t.target.dependencies = vec![("phantom".into(), "9.9.9".into())];

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

    /// Multi-source-same-coords (two `LinkTarget`s with the same
    /// `(name, version)` but different `wrapper_id`) currently can't
    /// be disambiguated through the dep edges (which carry only
    /// `(name, version)`). Until that's threaded through the resolver,
    /// `derive_graph_keys` MUST surface a hard error rather than
    /// silently aliasing — the audit-fixture suite never exercises
    /// this shape, so the error is reachable only by a malformed
    /// install set.
    #[test]
    fn link_packages_v2_errors_on_multi_source_same_coords() {
        let tmp = tempfile::tempdir().unwrap();
        let store = V2Store::at(tmp.path().join("store"));
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        // Two LinkTargets at the same (name, version) with distinct
        // wrapper_ids.
        let sri_a = synthetic_sri(b"multi_source/a");
        let sri_b = synthetic_sri(b"multi_source/b");
        write_object(
            &store,
            &sri_a,
            &[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")],
        );
        write_object(
            &store,
            &sri_b,
            &[("package.json", b"{\"name\":\"x\",\"version\":\"1.0.0\"}")],
        );

        let mut a = target("x", "1.0.0", &sri_a, true);
        a.target.wrapper_id = Some("t-aaaaaaaaaaaaaaaa".into());
        let mut b = target("x", "1.0.0", &sri_b, true);
        b.target.wrapper_id = Some("t-bbbbbbbbbbbbbbbb".into());

        let err =
            link_packages_v2(&project, vec![a, b], &store, LinkerMode::Isolated, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("multi-source") && msg.contains("x@1.0.0"),
            "multi-source collision error must name the package: {msg}"
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
}
