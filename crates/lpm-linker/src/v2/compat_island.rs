use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::LpmError;
use lpm_common::symlink::{create_dir_symlink_or_junction, is_symlink_or_junction};
#[cfg(target_os = "macos")]
use lpm_store::v2::{COMPAT_ISLAND_COMPLETE_FILENAME, CompatIslandKeyEntry};
use lpm_store::v2::{GraphKey, Store};

use super::V2Target;
use super::keymap::KeyMap;
use super::reconcile::{
    ensure_link_parent_dir, ensure_node_modules_dir, ensure_real_dir, is_direct,
    reconcile_scoped_root_dir, remove_node_modules_entry, root_link_names, symlink_points_to,
};
use crate::materialize::link_dir_recursive;
use crate::validation::is_safe_node_modules_entry_name as is_safe_root_link_name;

const PROJECT_COMPAT_DIR: &str = "compat";
const COMPAT_META_FILENAME: &str = ".lpm-compat-meta";
const COMPAT_META_FORMAT: &str = "lpm-compat-v1";

#[derive(Default)]
pub(super) struct CompatibilityLinks {
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

    pub(super) fn package_dir_for_key(&self, key: &GraphKey) -> Option<&Path> {
        self.package_dirs_by_key
            .get(key.dir_name())
            .map(PathBuf::as_path)
    }
}

struct CompatibilityEntry<'a> {
    target: &'a V2Target,
    key: Arc<GraphKey>,
}

#[cfg(target_os = "macos")]
struct CompatIslandKeySeed<'a> {
    dir_name: &'a str,
    source_sri: &'a str,
    content_integrity: String,
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
    let content =
        match lpm_common::read_file_capped(&package_json, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Some(()),
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
    if manifest_needs_bin_compatibility(&content) {
        bin_names.extend(
            bin_config
                .entries(&package_name)
                .into_iter()
                .map(|(cmd_name, _)| cmd_name),
        );
    }
    Some(())
}

fn package_name_from_manifest(content: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(content).ok()?;
    parsed.get("name")?.as_str().map(str::to_string)
}

pub(super) fn manifest_needs_bin_compatibility(content: &[u8]) -> bool {
    const DEPS_KEY: &[u8] = b"\"dependencies\"";
    const PEERS_KEY: &[u8] = b"\"peerDependencies\"";
    content.windows(DEPS_KEY.len()).any(|w| w == DEPS_KEY)
        || content.windows(PEERS_KEY.len()).any(|w| w == PEERS_KEY)
}

pub(super) fn create_project_compatibility_links(
    project_dir: &Path,
    targets: &[Arc<V2Target>],
    store: &Store,
    key_map: &KeyMap,
    compatibility_bin_names: &[String],
    refresh_package_copies: bool,
) -> Result<CompatibilityLinks, LpmError> {
    let requested_bins = normalize_compatibility_bin_names(compatibility_bin_names);

    if requested_bins.is_empty() {
        return Ok(CompatibilityLinks::default());
    }
    let roots = collect_compatibility_roots_for_bins(targets, store, key_map, &requested_bins);

    if roots.is_empty() {
        remove_project_compatibility_root(project_dir)?;
        return Ok(CompatibilityLinks::default());
    }

    let entries = collect_compatibility_entries(roots, targets, key_map)?;

    // macOS gets the store-cached fast path: build the island once in the
    // global store, then reproduce it in the project with a single recursive
    // `clonefile` (~5x faster than re-copying every package, and it survives
    // `rm -rf node_modules`). Other platforms keep the proven in-place build
    // — without `clonefile` there is no whole-tree clone to amortize, so the
    // store round-trip would only add a copy.
    #[cfg(target_os = "macos")]
    {
        create_project_compatibility_links_store_cached(
            project_dir,
            targets,
            store,
            key_map,
            &entries,
            refresh_package_copies,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        create_project_compatibility_links_in_place(
            project_dir,
            targets,
            store,
            key_map,
            &entries,
            refresh_package_copies,
        )
    }
}

/// Build the island directly under `compatibility_root`: copy each entry's
/// package tree, wire the sibling symlinks, write the per-entry markers.
/// Returns the `key → package dir` map used to rewire project roots.
fn build_compat_island_at(
    compatibility_root: &Path,
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
    key_map: &KeyMap,
    refresh_package_copies: bool,
) -> Result<CompatibilityLinks, LpmError> {
    let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
    for entry in entries {
        let package_dir = ensure_compatibility_package_copy(
            compatibility_root,
            entry,
            store,
            refresh_package_copies,
        )?;
        compatibility_links.insert(&entry.key, package_dir);
    }
    for entry in entries {
        sync_compatibility_entry_links(compatibility_root, entry, key_map, &compatibility_links)?;
    }
    for entry in entries {
        write_compatibility_marker(compatibility_root, entry)?;
    }
    Ok(compatibility_links)
}

/// Non-macOS path: build (and incrementally reconcile) the island directly in
/// the project's `node_modules/.lpm/compat`. This is the original behavior,
/// preserved verbatim where the `clonefile` fast path is unavailable.
#[cfg(not(target_os = "macos"))]
fn create_project_compatibility_links_in_place(
    project_dir: &Path,
    targets: &[Arc<V2Target>],
    store: &Store,
    key_map: &KeyMap,
    entries: &[CompatibilityEntry<'_>],
    refresh_package_copies: bool,
) -> Result<CompatibilityLinks, LpmError> {
    let compatibility_root = ensure_project_compatibility_root(project_dir)?;
    let desired: HashSet<String> = entries
        .iter()
        .map(|entry| entry.key.dir_name().to_string())
        .collect();
    reconcile_compatibility_root(&compatibility_root, &desired)?;
    let compatibility_links = build_compat_island_at(
        &compatibility_root,
        entries,
        store,
        key_map,
        refresh_package_copies,
    )?;
    rewire_project_roots_to_compat(project_dir, targets, key_map, &compatibility_links)?;
    Ok(compatibility_links)
}

// Sentinel written last when building a store-cached island (a crash
// mid-build leaves an island that `store_compat_island_complete` rejects).
// Shared with `lpm cache prune`, which uses its mtime for LRU eviction.
/// macOS path: build the island once in the global store (keyed by its entry
/// set) and reproduce it in the project with a single recursive `clonefile`.
#[cfg(target_os = "macos")]
fn create_project_compatibility_links_store_cached(
    project_dir: &Path,
    targets: &[Arc<V2Target>],
    store: &Store,
    key_map: &KeyMap,
    entries: &[CompatibilityEntry<'_>],
    refresh_package_copies: bool,
) -> Result<CompatibilityLinks, LpmError> {
    let island_key = store_compat_island_key(entries, store)?;
    let store_island = store.paths().compat_island_dir(&island_key);
    ensure_store_compat_island(
        &store_island,
        entries,
        store,
        key_map,
        refresh_package_copies,
    )?;

    let compatibility_root = materialize_island_into_project(project_dir, &store_island)?;

    let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
    for entry in entries {
        compatibility_links.insert(
            &entry.key,
            compatibility_package_dir(&compatibility_root, &entry.key),
        );
    }
    rewire_project_roots_to_compat(project_dir, targets, key_map, &compatibility_links)?;
    Ok(compatibility_links)
}

#[cfg(target_os = "macos")]
fn store_compat_island_key(
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
) -> Result<String, LpmError> {
    let mut seeds = Vec::with_capacity(entries.len());
    for entry in entries {
        seeds.push(CompatIslandKeySeed {
            dir_name: entry.key.dir_name(),
            source_sri: &entry.target.source_sri,
            content_integrity: store.link_entry_content_integrity(&entry.key)?,
        });
    }
    let key_entries: Vec<_> = seeds
        .iter()
        .map(|seed| CompatIslandKeyEntry {
            dir_name: seed.dir_name,
            source_sri: seed.source_sri,
            content_integrity: &seed.content_integrity,
        })
        .collect();
    Ok(lpm_store::v2::compat_island_key(&key_entries))
}

/// Build the content-keyed island in the global store if it isn't already
/// present. Builds into a tmp sibling and atomically renames, so concurrent
/// installs racing on the same key converge on one immutable copy.
#[cfg(target_os = "macos")]
fn ensure_store_compat_island(
    store_island: &Path,
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
    key_map: &KeyMap,
    force_refresh: bool,
) -> Result<(), LpmError> {
    if store_compat_island_complete(store_island) {
        if !force_refresh {
            // Reuse: refresh the sentinel's mtime so `lpm cache prune
            // --max-age` treats an actively-used island as live (the clone
            // that follows only reads the island, so without this an island
            // built once would age out despite daily use). Best-effort — a
            // missed touch only widens prune's view by one install cycle.
            let sentinel = store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME);
            let _ = std::fs::write(&sentinel, COMPAT_META_FORMAT);
            return Ok(());
        }
        remove_node_modules_entry(store_island, "stale store compatibility island")?;
    }
    store.ensure_compat_root_locked()?;

    let tmp = create_store_compatibility_tmp_dir(store_island)?;
    let build = (|| -> Result<(), LpmError> {
        build_compat_island_at(&tmp, entries, store, key_map, true)?;
        // Completion sentinel written last; the atomic rename below only
        // publishes a tmp that reached this point.
        std::fs::write(
            tmp.join(COMPAT_ISLAND_COMPLETE_FILENAME),
            COMPAT_META_FORMAT,
        )
        .map_err(|e| {
            LpmError::Store(format!(
                "virtual-store linker: failed to write island completion sentinel: {e}"
            ))
        })
    })();
    if let Err(error) = build {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(error);
    }

    match std::fs::rename(&tmp, store_island) {
        Ok(()) => Ok(()),
        // Lost a concurrent-build race: another install published a complete
        // island at this key first. Discard ours and reuse theirs.
        Err(_) if store_compat_island_complete(store_island) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(LpmError::Store(format!(
                "virtual-store linker: failed to publish store compatibility island {}: {error}",
                store_island.display()
            )))
        }
    }
}

#[cfg(target_os = "macos")]
fn store_compat_island_complete(store_island: &Path) -> bool {
    store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME).is_file()
}

/// Reproduce the cached store island under the project's
/// `node_modules/.lpm/compat`, returning that root. Replaces any existing
/// project island wholesale; only reached when the install actually links
/// (cold or `node_modules`-removed warm), never on an up-to-date install.
#[cfg(target_os = "macos")]
fn materialize_island_into_project(
    project_dir: &Path,
    store_island: &Path,
) -> Result<PathBuf, LpmError> {
    remove_legacy_project_compatibility_root(project_dir)?;
    let node_modules = ensure_node_modules_dir(project_dir)?;
    ensure_real_dir_or_create(
        &node_modules.join(".lpm"),
        "project node_modules/.lpm directory",
    )?;
    let compatibility_root = project_compatibility_root(project_dir);
    // `clonefile` requires the destination not to exist.
    if compatibility_root.symlink_metadata().is_ok() {
        remove_node_modules_entry(&compatibility_root, "previous project compatibility island")?;
    }
    clone_or_copy_island_tree(store_island, &compatibility_root)?;
    Ok(compatibility_root)
}

/// Recursively reproduce `src` at `dst`. Same-volume APFS: one `clonefile`
/// (CoW). Cross-volume (rare): a symlink-preserving recursive copy.
#[cfg(target_os = "macos")]
fn clone_or_copy_island_tree(src: &Path, dst: &Path) -> Result<(), LpmError> {
    if crate::materialize::try_clonefile(src, dst) {
        return Ok(());
    }
    copy_tree_preserving_symlinks(src, dst)
}

/// Cross-volume fallback: copy a directory tree with independent regular-file
/// inodes and recreate symlinks verbatim so the island's relative sibling
/// edges survive.
#[cfg(target_os = "macos")]
fn copy_tree_preserving_symlinks(src: &Path, dst: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store linker: failed to create island dir {}: {e}",
            dst.display()
        ))
    })?;
    let read = std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store linker: failed to read island {}: {e}",
            src.display()
        ))
    })?;
    for entry in read {
        let entry = entry.map_err(|e| {
            LpmError::Store(format!(
                "virtual-store linker: failed to enumerate island entry: {e}"
            ))
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| {
            LpmError::Store(format!(
                "virtual-store linker: failed to stat island entry {}: {e}",
                src_path.display()
            ))
        })?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(&src_path).map_err(|e| {
                LpmError::Store(format!(
                    "virtual-store linker: failed to read island symlink {}: {e}",
                    src_path.display()
                ))
            })?;
            std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "virtual-store linker: failed to recreate island symlink {}: {e}",
                    dst_path.display()
                ))
            })?;
        } else if file_type.is_dir() {
            copy_tree_preserving_symlinks(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "virtual-store linker: failed to copy island file {}: {e}",
                    src_path.display()
                ))
            })?;
        }
    }
    Ok(())
}

pub(super) fn normalize_compatibility_bin_names(bin_names: &[String]) -> Vec<String> {
    let mut seen = HashSet::with_capacity(bin_names.len());
    let mut normalized = Vec::with_capacity(bin_names.len());
    for name in bin_names {
        if !is_safe_root_link_name(name) {
            tracing::warn!("virtual-store linker: ignoring unsafe compatibility bin name {name:?}");
            continue;
        }
        if seen.insert(name.clone()) {
            normalized.push(name.clone());
        }
    }
    normalized
}

fn collect_compatibility_roots_for_bins<'a>(
    targets: &'a [Arc<V2Target>],
    store: &Store,
    key_map: &KeyMap,
    requested_bins: &[String],
) -> Vec<&'a V2Target> {
    let explicit_request = !requested_bins.is_empty();
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
        let Some(key) = key_map.get_for(v2t) else {
            continue;
        };
        let pkg_json_path = store.paths().link_package_dir(key).join("package.json");
        let content = match lpm_common::read_file_capped(
            &pkg_json_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(error) => {
                tracing::debug!(
                    "virtual-store linker: skipping compatibility bin scan for {}: failed to read {}: {error}",
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
                    "virtual-store linker: skipping compatibility bin scan for {}: failed to parse package.json: {error}",
                    v2t.target.name
                );
                continue;
            }
        };
        let entries = bin_config.entries(&v2t.target.name);
        if entries.is_empty() {
            continue;
        }
        if !explicit_request && v2t.target.dependencies.is_empty() && v2t.target.peers.is_empty() {
            continue;
        }
        match &requested {
            Some(requested) => {
                if entries
                    .iter()
                    .any(|(cmd_name, _)| requested.contains(cmd_name.as_str()))
                {
                    roots.push(v2t.as_ref());
                }
            }
            None => roots.push(v2t.as_ref()),
        }
    }
    roots
}

fn collect_compatibility_entries<'a>(
    roots: Vec<&'a V2Target>,
    targets: &'a [Arc<V2Target>],
    key_map: &KeyMap,
) -> Result<Vec<CompatibilityEntry<'a>>, LpmError> {
    let mut targets_by_key_dir: HashMap<String, &V2Target> = HashMap::with_capacity(targets.len());
    for v2t in targets {
        if let Some(key) = key_map.get_for(v2t) {
            targets_by_key_dir.insert(key.dir_name().to_string(), v2t.as_ref());
        }
    }

    let mut queue: VecDeque<&V2Target> = roots.into();
    let mut seen: HashSet<String> = HashSet::with_capacity(targets.len());
    let mut entries = Vec::new();
    while let Some(v2t) = queue.pop_front() {
        let key = key_map.get_for(v2t).cloned().ok_or_else(|| {
            LpmError::Store(format!(
                "virtual-store linker: missing graph key for compatibility package {}@{}",
                v2t.target.name, v2t.target.version
            ))
        })?;
        if !seen.insert(key.dir_name().to_string()) {
            continue;
        }

        for (_local, dep_key) in compatibility_dependency_links(v2t, key_map)? {
            let dep_target = targets_by_key_dir.get(dep_key.dir_name()).ok_or_else(|| {
                LpmError::Store(format!(
                    "virtual-store linker: compatibility dependency {} for {}@{} is missing from install set",
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

fn compatibility_dependency_links(
    target: &V2Target,
    key_map: &KeyMap,
) -> Result<Vec<(String, Arc<GraphKey>)>, LpmError> {
    let link_target = &target.target;
    let mut links = Vec::with_capacity(link_target.dependencies.len() + link_target.peers.len());
    let mut seen_local: HashSet<String> =
        HashSet::with_capacity(link_target.dependencies.len() + link_target.peers.len());

    for dep in &link_target.dependencies {
        if !is_safe_root_link_name(&dep.local) {
            tracing::warn!(
                "virtual-store linker: skipping unsafe compatibility dependency local name {:?} for {}@{}",
                dep.local,
                link_target.name,
                link_target.version
            );
            continue;
        }
        let dep_key = key_map
            .get_for_dependency(target, dep)
            .ok_or_else(|| {
                LpmError::Store(format!(
                    "virtual-store linker: compatibility dep {}=>{}@{} of {}@{} has no resolved graph key",
                    dep.local,
                    dep.target_name,
                    dep.graph_key_value(),
                    link_target.name,
                    link_target.version
                ))
            })?
            .clone();
        if seen_local.insert(dep.local.clone()) {
            links.push((dep.local.clone(), dep_key));
        }
    }

    for peer in &link_target.peers {
        if !is_safe_root_link_name(&peer.local_name) {
            tracing::warn!(
                "virtual-store linker: skipping unsafe compatibility peer local name {:?} for {}@{}",
                peer.local_name,
                link_target.name,
                link_target.version
            );
            continue;
        }
        if !seen_local.insert(peer.local_name.clone()) {
            continue;
        }
        let peer_key = key_map.get_peer(target, peer).ok_or_else(|| {
            LpmError::Store(format!(
                "virtual-store linker: compatibility peer {}=>{}@{} wrapper_id={:?} of {}@{} has no unambiguous resolved graph key",
                peer.local_name,
                peer.target_name,
                peer.target_version,
                peer.target_wrapper_id,
                link_target.name,
                link_target.version,
            ))
        })?;
        links.push((peer.local_name.clone(), Arc::clone(peer_key)));
    }

    Ok(links)
}

// Only the non-macOS in-place build creates the project compat root directly;
// the macOS store-cache path materializes it via `clonefile` instead.
#[cfg(not(target_os = "macos"))]
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
                    "virtual-store linker: failed to create {label} at {}: {e}",
                    path.display()
                ))
            })?;
            ensure_real_dir(path, label)
        }
        Err(error) => Err(LpmError::Store(format!(
            "virtual-store linker: failed to inspect {label} at {}: {error}",
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
                "virtual-store linker: failed to inspect project node_modules/.lpm directory at {}: {error}",
                lpm_dir.display()
            )));
        }
    };
    if is_symlink_or_junction(&metadata) {
        return Err(LpmError::Store(format!(
            "virtual-store linker: refusing to clean compatibility directory through symlinked node_modules/.lpm at {}",
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
                "virtual-store linker: failed to inspect legacy project .lpm directory at {}: {error}",
                lpm_dir.display()
            )));
        }
    };
    if is_symlink_or_junction(&metadata) {
        return Err(LpmError::Store(format!(
            "virtual-store linker: refusing to clean legacy compatibility directory through symlinked .lpm at {}",
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

// Incremental reconcile only runs on the in-place (non-macOS) build; the
// store-cache path replaces the project island wholesale via `clonefile`.
#[cfg(not(target_os = "macos"))]
fn reconcile_compatibility_root(
    compatibility_root: &Path,
    desired: &HashSet<String>,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(compatibility_root).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store linker: failed to read compatibility directory at {}: {e}",
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
            "virtual-store linker: compatibility source package is missing at {}",
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
                "virtual-store linker: failed to publish compatibility entry {} -> {}: {error}",
                tmp_dir.display(),
                final_dir.display()
            )))
        }
    }
}

#[cfg(target_os = "macos")]
fn create_store_compatibility_tmp_dir(final_dir: &Path) -> Result<PathBuf, LpmError> {
    create_compatibility_tmp_dir_with_mode(final_dir, true)
}

fn create_compatibility_tmp_dir(final_dir: &Path) -> Result<PathBuf, LpmError> {
    create_compatibility_tmp_dir_with_mode(final_dir, false)
}

fn create_compatibility_tmp_dir_with_mode(
    final_dir: &Path,
    locked_mode: bool,
) -> Result<PathBuf, LpmError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COMPAT_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = final_dir.parent().ok_or_else(|| {
        LpmError::Store(format!(
            "virtual-store linker: compatibility path has no parent: {}",
            final_dir.display()
        ))
    })?;
    let base_name = final_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            LpmError::Store(format!(
                "virtual-store linker: compatibility path has invalid final component: {}",
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
        let created = if locked_mode {
            create_dir_0700(&tmp)
        } else {
            std::fs::create_dir(&tmp)
        };
        match created {
            Ok(()) => return Ok(tmp),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "virtual-store linker: failed to create compatibility tmp dir at {}: {error}",
                    tmp.display()
                )));
            }
        }
    }
    Err(LpmError::Store(format!(
        "virtual-store linker: failed to allocate compatibility tmp dir for {}",
        final_dir.display()
    )))
}

fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

fn compatibility_entry_reusable(final_dir: &Path, entry: &CompatibilityEntry<'_>) -> bool {
    let marker = final_dir.join(COMPAT_META_FILENAME);
    let Ok(content) = lpm_common::read_file_capped(&marker, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return false;
    };
    content == compatibility_marker(entry).as_bytes()
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
) -> Result<(), LpmError> {
    let node_modules = compatibility_node_modules_dir(compatibility_root, &entry.key);
    let mut links = compatibility_dependency_links(entry.target, key_map)?;
    let own_local = entry.key.name();
    links.retain(|(local, _)| local != own_local);
    let mut desired: HashSet<String> = HashSet::with_capacity(links.len() + 1);
    desired.insert(entry.key.name().to_string());
    desired.extend(links.iter().map(|(local, _)| local.clone()));
    reconcile_compatibility_node_modules(&node_modules, &desired)?;

    let own_package_dir = compatibility_package_dir(compatibility_root, &entry.key);
    for (local, dep_key) in links {
        let Some(target_package_dir) = compatibility_links.package_dir_for_key(&dep_key) else {
            return Err(LpmError::Store(format!(
                "virtual-store linker: compatibility link target {} for {}@{} was not materialized",
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
            "virtual-store linker: failed to read compatibility node_modules at {}: {e}",
            node_modules.display()
        ))
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_real_dir = path
            .symlink_metadata()
            .map(|metadata| metadata.is_dir() && !is_symlink_or_junction(&metadata))
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
            "virtual-store linker: unsafe compatibility sibling name {local:?}"
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
    // Relative target so the island is position-independent: a whole-tree
    // `clonefile` of the island into a project (warm-install fast path)
    // keeps every sibling edge valid, because the link and its target move
    // together. Same canonicalize-then-`diff_paths` strategy the v1
    // isolated linker uses for store symlinks.
    let relative_target = relative_compat_sibling_target(&link_path, target_package_dir);
    create_dir_symlink_or_junction(&relative_target, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store linker: failed to create compatibility sibling {} -> {}: {e}",
            link_path.display(),
            target_package_dir.display()
        ))
    })
}

/// Relative symlink target for an in-island sibling edge, computed from the
/// link's parent directory. Both paths live under the same compatibility
/// root, so the result is an island-internal relative path (e.g.
/// `../../<dep-key>/node_modules/<dep>`) that survives a whole-island
/// `clonefile` to any destination.
fn relative_compat_sibling_target(link_path: &Path, target_package_dir: &Path) -> PathBuf {
    let Some(link_parent) = link_path.parent() else {
        return target_package_dir.to_path_buf();
    };
    let link_parent_canonical = link_parent
        .canonicalize()
        .unwrap_or_else(|_| link_parent.to_path_buf());
    let target_canonical = target_package_dir
        .canonicalize()
        .unwrap_or_else(|_| target_package_dir.to_path_buf());
    pathdiff::diff_paths(&target_canonical, &link_parent_canonical)
        .unwrap_or_else(|| target_canonical.clone())
}

fn write_compatibility_marker(
    compatibility_root: &Path,
    entry: &CompatibilityEntry<'_>,
) -> Result<(), LpmError> {
    let marker_path =
        compatibility_entry_dir(compatibility_root, &entry.key).join(COMPAT_META_FILENAME);
    std::fs::write(&marker_path, compatibility_marker(entry)).map_err(|e| {
        LpmError::Store(format!(
            "virtual-store linker: failed to write compatibility marker at {}: {e}",
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
    targets: &[Arc<V2Target>],
    key_map: &KeyMap,
    compatibility_links: &CompatibilityLinks,
) -> Result<(), LpmError> {
    let nm = ensure_node_modules_dir(project_dir)?;
    for v2t in targets {
        let Some(key) = key_map.get_for(v2t) else {
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
                    "virtual-store linker: failed to rewire project root {} -> {}: {e}",
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::copy_tree_preserving_symlinks;

    #[test]
    fn compatibility_island_copy_fallback_uses_independent_file_inodes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        let source_file = source.join("package.json");
        std::fs::write(&source_file, b"original").unwrap();

        copy_tree_preserving_symlinks(&source, &destination).unwrap();

        let destination_file = destination.join("package.json");
        assert_ne!(
            std::fs::metadata(&source_file).unwrap().ino(),
            std::fs::metadata(&destination_file).unwrap().ino(),
            "project compatibility files must not hardlink the store cache"
        );
        std::fs::write(destination_file, b"modified").unwrap();
        assert_eq!(std::fs::read(source_file).unwrap(), b"original");
    }
}
