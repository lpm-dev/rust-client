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
//!    dep symlinks alongside.
//! 4. Writes project-side `node_modules/<root_link_name>` symlinks
//!    pointing into the materialized link entries.
//! 5. Generates `.bin/` shims by walking the project-side symlinks —
//!    same shape as v1's, but resolving through v2 paths.
//!
//! # Phase 4b limitations (documented for the dev-only checkpoint)
//!
//! - **Empty peer-context.** [`LinkTarget`] doesn't currently carry
//!   peer-resolution info. v2's preplan §2.5 says isolated graph keys
//!   should fold in peer-context for cross-project sharing. For 4b
//!   we derive keys with empty peers and accept the consequence:
//!   two projects whose `react@18.3.0` resolves the SAME edge graph
//!   but different peer pinning would share the same wrapper
//!   directory. Phase 4 follow-up (post-4b.4) threads peer-context
//!   through the resolver → install → linker chain. Audit-fixtures
//!   gate "v2 mode produces a working install per fixture" — they
//!   don't gate cross-project peer correctness, so 4b acceptance
//!   isn't blocked.
//! - **Single source per (name, version).** The `dep_key_map` is
//!   keyed by `(target_name, target_version)`, so an install with
//!   two LinkTargets sharing `(name, version)` (e.g. one Registry
//!   source + one Tarball source distinguished by `wrapper_id`)
//!   would alias one onto the other. None of the audit fixtures
//!   exercise this; logged as a Phase 4 follow-up.

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

    // Phase 66 Phase 4b: synthesize peer-edge siblings for each
    // target. v1's isolated linker relies on Node's symlink walk-up
    // to reach project-level peers (relative `<project>/.lpm/wrappers/`
    // chain stays inside the project). v2's project-side symlinks
    // jump straight into `<HOME>/.lpm/store/v2/links/<key>/`, so the
    // walk-up never reaches the project's `node_modules/<peer>` — every
    // peer must be present as a sibling INSIDE the consumer's link
    // entry. The resolver doesn't surface resolved peers per-package
    // today (`ResolvedPackage.dependencies` only carries declared
    // `dependencies` / `optionalDependencies`), so the v2 linker
    // derives them from the just-extracted `package.json` files in
    // each `objects/<sri>/` and maps each `peerDependencies` entry to
    // the install-set's matching `(name, version)`. Phase 4 follow-up:
    // thread peers through the resolver so cross-project sharing
    // (where two projects might pin the same peer differently)
    // produces distinct graph keys.
    let augmented_targets = augment_with_peer_edges(targets, store)?;
    let augmented_slice = &augmented_targets[..];

    // Pre-pass: every (name, version) → its GraphKey. Used twice — to
    // build the per-target dep edges (which require the OTHER targets'
    // keys) and to compute symlink targets for project-side root
    // entries.
    let key_map = derive_graph_keys(augmented_slice, &platform, linker_tag);

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

/// Read each target's `package.json` from its v2 object dir, parse
/// out `peerDependencies`, and append edges to the matching
/// install-set entries. Returns a fresh `Vec<V2Target>` with the
/// augmented dep edges; the input is left untouched so callers that
/// still want the pre-augment view (e.g., for diagnostics) can keep it.
///
/// Optional peers (declared in `peerDependenciesMeta` with
/// `optional: true`) are silently skipped when the install set
/// doesn't include the peer's package — matches npm's behavior.
///
/// **Transitive closure.** When package A's peer is B, and B itself
/// declares C as a peer, the v2 isolated layout requires C as a
/// sibling of A (not just of B), because Node's module resolution
/// from inside `<links/A-key>/node_modules/A/` walks up to
/// `<links/A-key>/node_modules/`, then stops — it never reaches B's
/// link entry directly. Without recursive closure, A's
/// `require('react')` (declared by B = rehackt) fails because react
/// isn't a sibling of A's link entry. v1 reaches the project root
/// via the relative `<project>/.lpm/wrappers/` chain and resolves the
/// peer there; v2's absolute store paths break that walk-up.
///
/// We iterate to a fixed point: repeatedly walk every (re-)augmented
/// target's peers and pull in newly-discovered peers, until no
/// target gains a new edge. Bounded by depth-limit to avoid
/// pathological cycles.
fn augment_with_peer_edges(targets: &[V2Target], store: &Store) -> Result<Vec<V2Target>, LpmError> {
    // Build a name → version lookup once. For 4b's single-version-
    // per-name scope this is unambiguous; multi-source-same-name
    // disambiguation is a Phase 4 follow-up.
    let mut by_name: HashMap<String, String> = HashMap::with_capacity(targets.len());
    for v2t in targets {
        by_name
            .entry(v2t.target.name.clone())
            .or_insert_with(|| v2t.target.version.clone());
    }

    // Read every target's `peerDependencies` + `peerDependenciesMeta`
    // once. Cached so the fixed-point loop doesn't re-parse package.json
    // on every pass. Each peer carries an `is_optional` flag, derived
    // from `peerDependenciesMeta.<name>.optional` (npm contract:
    // missing entry = required peer).
    struct PeerInfo {
        name: String,
        is_optional: bool,
    }
    let mut peers_by_name: HashMap<String, Vec<PeerInfo>> = HashMap::with_capacity(targets.len());
    for v2t in targets {
        let object_dir = store.paths().object_dir(&v2t.source_sri)?;
        let pkg_json_path = object_dir.join("package.json");
        if !pkg_json_path.exists() {
            // No package.json — treat as no peers. Should be
            // unreachable for real npm tarballs.
            continue;
        }
        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: failed to parse {}/package.json for peer-edge synthesis: {e}",
                    object_dir.display()
                );
                continue;
            }
        };
        if pkg_json.peer_dependencies.is_empty() {
            continue;
        }
        let infos: Vec<PeerInfo> = pkg_json
            .peer_dependencies
            .keys()
            .map(|name| PeerInfo {
                name: name.clone(),
                is_optional: pkg_json
                    .peer_dependencies_meta
                    .get(name)
                    .map(|meta| meta.optional)
                    .unwrap_or(false),
            })
            .collect();
        peers_by_name.insert(v2t.target.name.clone(), infos);
    }

    let mut out: Vec<V2Target> = targets.to_vec();

    // Bound iterations to avoid cycles. The closure depth is at most
    // the longest peer-chain length in the install set; 64 is two
    // orders of magnitude beyond any real npm graph.
    const MAX_PEER_CLOSURE_PASSES: usize = 64;
    for _ in 0..MAX_PEER_CLOSURE_PASSES {
        let mut changed = false;
        for v2t in out.iter_mut() {
            let peers = match peers_by_name.get(&v2t.target.name) {
                Some(p) => p,
                None => continue,
            };
            let already_declared: std::collections::HashSet<String> = v2t
                .target
                .dependencies
                .iter()
                .map(|(local, _)| local.clone())
                .collect();
            for peer in peers {
                if already_declared.contains(&peer.name) {
                    continue;
                }
                let resolved_version = match by_name.get(&peer.name) {
                    Some(v) => v.clone(),
                    None => {
                        // Peer not in install set. Two distinct cases:
                        //
                        //   1. Optional peer (`peerDependenciesMeta`
                        //      `{ optional: true }`) — npm-compat
                        //      behavior is silent skip. No log; this
                        //      is normal. Example: an apollo plugin
                        //      that optionally integrates with a
                        //      framework the user doesn't have.
                        //
                        //   2. Required peer the resolver missed.
                        //      `check_unmet_peers` is supposed to
                        //      fail resolution upstream; reaching this
                        //      branch means it didn't. Surface a debug
                        //      trace so the gap is visible under
                        //      `RUST_LOG=debug` without spamming the
                        //      default install output. Node will fail
                        //      to resolve at runtime — exactly the
                        //      same end-state as v1's isolated layout
                        //      when a peer is genuinely unresolvable.
                        if !peer.is_optional {
                            tracing::debug!(
                                "v2 linker: REQUIRED peer dep {} of {}@{} not in install set — \
                                 resolver should have caught this in check_unmet_peers",
                                peer.name,
                                v2t.target.name,
                                v2t.target.version
                            );
                        }
                        continue;
                    }
                };
                v2t.target
                    .dependencies
                    .push((peer.name.clone(), resolved_version));
                changed = true;
            }
        }
        if !changed {
            return Ok(out);
        }
    }
    // Hit the depth bound — surface a debug trace and accept the
    // current closure. Real graphs never approach the cap; if they
    // do, return what we have rather than fail the install.
    tracing::debug!(
        "v2 linker: peer-edge closure hit MAX_PEER_CLOSURE_PASSES={MAX_PEER_CLOSURE_PASSES}; \
         possible cycle in peer chain"
    );
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
    key_map: &HashMap<(String, String), GraphKey>,
    platform: &PlatformTuple,
) -> Result<PopulatedEntry, LpmError> {
    let key = key_map
        .get(&(v2t.target.name.clone(), v2t.target.version.clone()))
        .cloned()
        .ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: missing graph key for {}@{} (key map pre-pass failed)",
                v2t.target.name, v2t.target.version
            ))
        })?;

    let object_dir = store.paths().object_dir(&v2t.source_sri)?;

    let deps: Vec<DepLink> = v2t
        .target
        .dependencies
        .iter()
        .map(|(local, ver)| {
            let canonical = v2t
                .target
                .aliases
                .get(local)
                .cloned()
                .unwrap_or_else(|| local.clone());
            let dep_key = key_map.get(&(canonical.clone(), ver.clone())).cloned();
            match dep_key {
                Some(dep_key) => Ok(DepLink {
                    local: local.clone(),
                    target: dep_key,
                }),
                None => Err(LpmError::Store(format!(
                    "v2 linker: dep {local}@{ver} of {}@{} has no resolved graph key",
                    v2t.target.name, v2t.target.version
                ))),
            }
        })
        .collect::<Result<_, _>>()?;

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

fn derive_graph_keys(
    targets: &[V2Target],
    platform: &PlatformTuple,
    linker_tag: LinkerModeTag,
) -> HashMap<(String, String), GraphKey> {
    let mut out = HashMap::with_capacity(targets.len());
    for v2t in targets {
        let inputs = build_inputs(&v2t.target, platform, linker_tag);
        let key = GraphKey::derive(&inputs);
        out.insert((v2t.target.name.clone(), v2t.target.version.clone()), key);
    }
    out
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

    let alias_iter = target.aliases.iter().map(|(k, v)| (k.clone(), v.clone()));

    GraphKeyInputs::new(&target.name, &target.version, platform.clone(), linker_tag)
        // Phase 4b limitation: peers stay empty until peer-context
        // threading lands (preplan §2.5 / module docs above).
        .with_peers(Vec::<PeerEntry>::new())
        .with_deps(dep_edges)
        .with_aliases(alias_iter)
        .with_root_link_names(target.root_link_names.clone())
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
    key_map: &HashMap<(String, String), GraphKey>,
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
        let key = key_map
            .get(&(v2t.target.name.clone(), v2t.target.version.clone()))
            .ok_or_else(|| {
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
    key_map: &HashMap<(String, String), GraphKey>,
) -> Result<usize, LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");

    let mut count = 0usize;
    for v2t in targets {
        if !is_direct(&v2t.target) {
            continue;
        }
        let key = match key_map.get(&(v2t.target.name.clone(), v2t.target.version.clone())) {
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
}
