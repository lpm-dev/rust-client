//! Phase 66 Phase 4b — virtual-store-aware linker.
//!
//! Sits next to v1's [`crate::link_packages`] / [`crate::link_packages_hoisted`]
//! and is selected at the install pipeline by
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
//! # Peer-context (preplan §2.5)
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
//! # Multi-source disambiguation (preplan §2.2)
//!
//! The internal key map keys by `(name, version, wrapper_id)`, not
//! `(name, version)`. Two `LinkTarget`s with the same `(name,
//! version)` but different sources (e.g., one `Source::Registry` +
//! one `Source::Tarball` distinguished by `wrapper_id`) get
//! distinct GraphKeys via `with_root_link_names` + the dep-edge
//! disambiguation that flows from each target's own `wrapper_id`.

use std::collections::HashMap;
use std::path::Path;

use lpm_common::LpmError;
use lpm_common::symlink::create_dir_symlink_or_junction;
use lpm_store::v2::{
    DepEdge, DepLink, GraphKey, GraphKeyInputs, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag,
    PeerEntry, PlatformTuple, Store,
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
    targets: &[V2Target],
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

    let platform = PlatformTuple::current();
    let linker_tag = match linker_mode {
        LinkerMode::Isolated => LinkerModeTag::Isolated,
        LinkerMode::Hoisted => LinkerModeTag::Hoisted,
    };

    // Wipe v1-style project link state. The v2 install always rebuilds
    // `node_modules/` from scratch — under v2 there's no per-project
    // wrapper tree to incrementally update, and stale v1 wrappers
    // would otherwise leave dangling symlinks pointing at `.lpm/`
    // paths the v2 linker never touches.
    cleanup_v1_state(project_dir)?;

    // Peer-context: ensure every target has its peer set populated.
    // For fresh-resolve the resolver already threaded peers through
    // (via `ResolvedPackage.peers` → `InstallPackage.peers` →
    // `LinkTarget.peers`); for the lockfile fast-path the lockfile
    // doesn't persist peers, so `LinkTarget.peers` arrives empty and
    // we derive it here from the just-extracted package.json. Either
    // way, after this call `target.peers` is the authoritative
    // peer-edge set used for both sibling-symlink synthesis and
    // GraphKey derivation.
    let augmented_targets = ensure_peer_context(targets, store)?;
    let augmented_slice = &augmented_targets[..];

    // Pre-pass: every (name, version, wrapper_id) → its GraphKey.
    // The triple disambiguates the rare cross-source same-coords case
    // (Registry + Tarball both at `foo@1.0.0`), which `wrapper_id`
    // already carves apart at the .lpm/segment level under v1; v2
    // mirrors that into the link-entry namespace.
    let key_map = derive_graph_keys(augmented_slice, &platform, linker_tag)?;

    // Materialize each link entry. Phase 4b runs sequentially for
    // simplicity — the v2 store's own atomicity already serializes
    // concurrent writers via atomic-rename, but exercising parallelism
    // here pays for the rayon thread-pool cost on small installs and
    // the audit-fixture set is small. Phase 4d/4f can revisit.
    let mut linked_count = 0usize;
    let mut materialized: Vec<MaterializedPackage> = Vec::with_capacity(augmented_slice.len());
    for v2t in augmented_slice {
        let entry = populate_one(v2t, store, &key_map, &platform)?;
        if entry.freshly_populated {
            linked_count += 1;
        }
        materialized.push(MaterializedPackage {
            name: v2t.target.name.clone(),
            version: v2t.target.version.clone(),
            destination: store.paths().link_package_dir(&entry.key),
        });
    }

    // Project-side root symlinks: one per entry in `root_link_names`
    // (or the default `[name]` for direct deps with `None`).
    let symlinked_count = create_root_symlinks(project_dir, augmented_slice, store, &key_map)?;

    // Bin shims — walk each link entry's package.json directly via
    // the store path. Doesn't need the project-side symlinks to
    // resolve, which keeps the order independent of root-symlink
    // creation timing.
    let bin_count = create_bin_links_v2(project_dir, augmented_slice, store, &key_map)?;

    // Self-reference: project's `node_modules/<self_pkg_name>` →
    // `<project_dir>`. Same shape as v1 (`node_modules/<self>` is a
    // symlink to the project root). Skipped if a direct dep already
    // occupies the slot.
    let self_referenced = if let Some(self_name) = self_package_name {
        create_self_ref(project_dir, self_name)?
    } else {
        false
    };

    Ok(LinkResult {
        linked: linked_count,
        symlinked: symlinked_count,
        bin_linked: bin_count,
        skipped: augmented_slice.len().saturating_sub(linked_count),
        self_referenced,
        materialized,
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
fn ensure_peer_context(targets: &[V2Target], store: &Store) -> Result<Vec<V2Target>, LpmError> {
    // Build a name → version lookup so the fallback derivation can
    // intersect declared peers against the install set. The
    // single-version-per-name shape is correct for the audit-fixture
    // scope; multi-source-same-name disambiguation flows through
    // wrapper_id at the GraphKey level (see preplan §2.2).
    let mut by_name: HashMap<String, String> = HashMap::with_capacity(targets.len());
    for v2t in targets {
        by_name
            .entry(v2t.target.name.clone())
            .or_insert_with(|| v2t.target.version.clone());
    }

    let mut out: Vec<V2Target> = targets.to_vec();
    for v2t in out.iter_mut() {
        if !v2t.target.peers.is_empty() {
            // Resolver-threaded — trust it.
            continue;
        }
        let object_dir = store.paths().object_dir(&v2t.source_sri)?;
        let pkg_json_path = object_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }
        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: failed to parse {}/package.json for peer derivation: {e}",
                    object_dir.display()
                );
                continue;
            }
        };
        if pkg_json.peer_dependencies.is_empty() {
            continue;
        }
        let mut derived: Vec<(String, String)> = Vec::new();
        for peer_name in pkg_json.peer_dependencies.keys() {
            let is_optional = pkg_json
                .peer_dependencies_meta
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
    Ok(out)
}

/// Result handle for a single populated link entry — keeps the key
/// alongside `freshly_populated` so the caller doesn't have to
/// re-derive it for `materialized` reporting.
struct PopulatedEntry {
    key: GraphKey,
    freshly_populated: bool,
}

fn populate_one(
    v2t: &V2Target,
    store: &Store,
    key_map: &KeyMap,
    platform: &PlatformTuple,
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
    let already_local: std::collections::HashSet<String> =
        deps.iter().map(|d| d.local.clone()).collect();
    for (peer_name, peer_ver) in &v2t.target.peers {
        if already_local.contains(peer_name) {
            // Peer is also declared as a regular dep — already
            // covered by the dep-edge pass. Avoids a duplicate
            // sibling symlink (which would conflict at the link
            // entry's `node_modules/<peer>` slot).
            continue;
        }
        let peer_key = match key_map.get_by_coords(peer_name, peer_ver) {
            Some(k) => k.clone(),
            None => {
                // Peer not in install set. ensure_peer_context already
                // distinguished optional from required and emitted
                // the relevant trace; here we silently skip — a
                // missing peer becomes a runtime require failure,
                // mirroring v1's behavior under the same shape.
                continue;
            }
        };
        deps.push(DepLink {
            local: peer_name.clone(),
            target: peer_key,
        });
    }

    let request = LinkEntryRequest {
        graph_key: key.clone(),
        source_sri: v2t.source_sri.clone(),
        object_dir,
        deps,
        platform: link_meta_platform(platform),
    };
    let entry = store.populate_link_entry(request)?;
    Ok(PopulatedEntry {
        key,
        freshly_populated: entry.freshly_populated,
    })
}

fn link_meta_platform(p: &PlatformTuple) -> LinkMetaPlatform {
    LinkMetaPlatform {
        os: p.os.clone(),
        cpu: p.cpu.clone(),
        libc: p.libc.clone(),
    }
}

/// Per-install lookup table from `(name, version, wrapper_id)` to the
/// derived `GraphKey`.
///
/// Two indexes:
/// - `by_triple` — full `(name, version, wrapper_id)` identity. Used
///   by `populate_one` to fetch THIS target's own key.
/// - `by_coords` — `(name, version)` only. Used to resolve dep / peer
///   edges, which carry only `(name, version)` today. Multi-source
///   collisions are detected at construction time and surface a hard
///   error before any link entry materializes.
struct KeyMap {
    by_triple: HashMap<(String, String, Option<String>), GraphKey>,
    by_coords: HashMap<(String, String), GraphKey>,
}

impl KeyMap {
    fn get_for(&self, target: &LinkTarget) -> Option<&GraphKey> {
        self.by_triple.get(&(
            target.name.clone(),
            target.version.clone(),
            target.wrapper_id.clone(),
        ))
    }

    fn get_by_coords(&self, name: &str, version: &str) -> Option<&GraphKey> {
        self.by_coords.get(&(name.to_string(), version.to_string()))
    }
}

fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> Result<KeyMap, LpmError> {
    let mut by_triple: HashMap<(String, String, Option<String>), GraphKey> =
        HashMap::with_capacity(targets.len());
    let mut by_coords: HashMap<(String, String), GraphKey> = HashMap::with_capacity(targets.len());
    let mut coords_seen: HashMap<(String, String), Option<String>> =
        HashMap::with_capacity(targets.len());

    for v2t in targets {
        let inputs = build_inputs(&v2t.target, platform, linker_tag);
        let key = GraphKey::derive(&inputs);
        let triple = (
            v2t.target.name.clone(),
            v2t.target.version.clone(),
            v2t.target.wrapper_id.clone(),
        );
        if by_triple.insert(triple.clone(), key.clone()).is_some() {
            return Err(LpmError::Store(format!(
                "v2 linker: duplicate LinkTarget for {}@{} wrapper_id={:?}",
                v2t.target.name, v2t.target.version, v2t.target.wrapper_id
            )));
        }

        let coords = (v2t.target.name.clone(), v2t.target.version.clone());
        match coords_seen.entry(coords.clone()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(v2t.target.wrapper_id.clone());
                by_coords.insert(coords, key);
            }
            std::collections::hash_map::Entry::Occupied(existing) => {
                // Multi-source-same-coords. Dep edges carry only
                // `(name, version)`, so we can't disambiguate which
                // GraphKey a `dep on foo@1.0.0` should point at. Hard
                // error rather than silently aliasing one onto the
                // other (the audit-fixture suite never exercises this
                // shape today; threading wrapper_id through dep edges
                // is a Phase 4 follow-up that lifts the constraint).
                return Err(LpmError::Store(format!(
                    "v2 linker: multi-source LinkTarget collision for {}@{} \
                     (existing wrapper_id={:?}, new wrapper_id={:?}). \
                     Multi-source disambiguation requires wrapper_id-aware \
                     dep edges (Phase 4 follow-up).",
                    v2t.target.name,
                    v2t.target.version,
                    existing.get(),
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

fn build_inputs(
    target: &LinkTarget,
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> GraphKeyInputs {
    let dep_edges = target.dependencies.iter().map(|(local, ver)| {
        let canonical = target
            .aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        DepEdge {
            local: local.clone(),
            target_name: canonical,
            target_version: ver.clone(),
        }
    });

    let peer_entries = target.peers.iter().map(|(name, ver)| PeerEntry {
        name: name.clone(),
        version: ver.clone(),
    });

    let alias_iter = target.aliases.iter().map(|(k, v)| (k.clone(), v.clone()));

    GraphKeyInputs::new(&target.name, &target.version, platform.clone(), linker_tag)
        .with_peers(peer_entries)
        .with_deps(dep_edges)
        .with_aliases(alias_iter)
        .with_root_link_names(target.root_link_names.clone())
        .with_wrapper_id(target.wrapper_id.clone())
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
    // `<project>/.lpm/hoisted/` — Phase 61.x hoisted layout sidecar.
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
    // matches the migration semantics in preplan §3.2 (".bin/ MUST
    // be wiped — bin shims regenerate from the active install
    // layout").
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
            let link_path = nm.join(&root_name);
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
        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }
        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: skipping bin links for {}: failed to parse package.json: {e}",
                    v2t.target.name
                );
                continue;
            }
        };
        let bin_config = match &pkg_json.bin {
            Some(b) => b,
            None => continue,
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
            let bin_target = pkg_dir.join(&bin_rel_path);
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
            let link_path = bin_dir.join(&cmd_name);
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
            &[target("a", "1.0.0", &sri, true)],
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
            &[consumer, lib],
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
            &[target("x", "1.0.0", &sri, true)],
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
        let result = link_packages_v2(&project, &[t], &store, LinkerMode::Isolated, None).unwrap();
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
            &[target("d", "1.0.0", &sri, false)],
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

        let err = link_packages_v2(&project, &[t], &store, LinkerMode::Isolated, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("phantom@9.9.9"),
            "missing-dep error must name the missing edge: {msg}"
        );
    }

    /// **Cross-project peer-divergence — preplan §2.5 invariant.**
    ///
    /// The same consumer package + edge graph but a different
    /// resolved-peer version MUST produce distinct GraphKeys, so two
    /// projects that pin the same peer differently get separate
    /// `links/<key>/` entries instead of silently sharing. Pre-Phase-66
    /// this was the load-bearing gap behind the empty-peers
    /// `with_peers(Vec::<PeerEntry>::new())` call in `build_inputs`.
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
            &[
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
            &[
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
             pre-Phase-66 they shared a GraphKey because peers were always empty"
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
            &[
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
            &[
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
            link_packages_v2(&project, &[a, b], &store, LinkerMode::Isolated, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("multi-source") && msg.contains("x@1.0.0"),
            "multi-source collision error must name the package: {msg}"
        );
    }
}
