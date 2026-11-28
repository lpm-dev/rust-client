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
    reconcile_scoped_root_dir, remove_node_modules_entry, symlink_points_to,
};
use crate::materialize::copy_dir_recursive;
use crate::validation::is_safe_node_modules_entry_name as is_safe_root_link_name;

const PROJECT_COMPAT_DIR: &str = "compat";
const COMPAT_META_FILENAME: &str = ".lpm-compat-meta";
const COMPAT_META_FORMAT: &str = "lpm-compat-v1";
#[cfg(target_os = "macos")]
const COMPAT_ISLAND_COMPLETE_SCHEMA: u64 = 2;

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
    if !lpm_workspace::manifest_bytes_may_contain_bin(&content) {
        return Some(());
    }
    let (manifest_name, bin_config) = match lpm_workspace::parse_name_and_bin_field(&content) {
        Ok((name, Some(bin_config))) => (name, bin_config),
        Ok((_, None)) => return Some(()),
        Err(_) => return None,
    };
    let package_name = manifest_name.unwrap_or_else(|| fallback_package_name.to_string());
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

pub(super) fn manifest_needs_bin_compatibility(content: &[u8]) -> bool {
    const DEPS_KEY: &[u8] = b"\"dependencies\"";
    const PEERS_KEY: &[u8] = b"\"peerDependencies\"";
    if content.windows(DEPS_KEY.len()).any(|w| w == DEPS_KEY)
        || content.windows(PEERS_KEY.len()).any(|w| w == PEERS_KEY)
    {
        return true;
    }
    if !content.windows(2).any(|w| w == b"\\u") {
        return false;
    }
    let trimmed = content.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(content);
    match serde_json::from_slice::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => {
            map.contains_key("dependencies") || map.contains_key("peerDependencies")
        }
        Ok(_) => false,
        Err(_) => true,
    }
}

pub(super) fn create_project_compatibility_links(
    project_dir: &Path,
    targets: &[Arc<V2Target>],
    store: &Store,
    key_map: &KeyMap,
    compatibility_bin_names: &[String],
    refresh_package_copies: bool,
    warm_link_keys: Option<&HashSet<String>>,
) -> Result<CompatibilityLinks, LpmError> {
    let requested_bins = normalize_compatibility_bin_names(compatibility_bin_names);

    if requested_bins.is_empty() {
        remove_project_compatibility_root(project_dir)?;
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
            store,
            key_map,
            &entries,
            refresh_package_copies,
            warm_link_keys,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        create_project_compatibility_links_in_place(
            project_dir,
            store,
            key_map,
            &entries,
            refresh_package_copies,
            warm_link_keys,
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
    warm_link_keys: Option<&HashSet<String>>,
) -> Result<CompatibilityLinks, LpmError> {
    let is_warm_source =
        |key: &GraphKey| warm_link_keys.is_some_and(|keys| keys.contains(key.dir_name()));
    #[cfg(target_os = "macos")]
    {
        let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
        for entry in entries {
            let package_dir = ensure_compatibility_package_copy(
                compatibility_root,
                entry,
                store,
                refresh_package_copies,
                is_warm_source(&entry.key),
            )?;
            compatibility_links.insert(&entry.key, package_dir);
        }
        for entry in entries {
            sync_compatibility_entry_links(
                compatibility_root,
                entry,
                key_map,
                &compatibility_links,
            )?;
        }
        for entry in entries {
            write_compatibility_marker(compatibility_root, entry)?;
        }
        Ok(compatibility_links)
    }

    #[cfg(not(target_os = "macos"))]
    {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        const PARALLEL_COMPAT_THRESHOLD: usize = 4;
        let max_workers = if store.uses_serialized_volume_metadata() {
            lpm_common::resources::effective_cpu_count().clamp(1, 2)
        } else {
            lpm_common::resources::effective_cpu_count().clamp(1, 8)
        };
        let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
        if entries.len() >= PARALLEL_COMPAT_THRESHOLD && max_workers > 1 {
            let desired_helpers = max_workers.min(entries.len()).saturating_sub(1);
            let next_copy = AtomicUsize::new(0);
            let copy_failed = AtomicBool::new(false);
            let run_copy_worker = || -> Result<Vec<(&GraphKey, PathBuf)>, LpmError> {
                let mut local = Vec::new();
                while !copy_failed.load(Ordering::Relaxed) {
                    let idx = next_copy.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(idx) else {
                        break;
                    };
                    match ensure_compatibility_package_copy(
                        compatibility_root,
                        entry,
                        store,
                        refresh_package_copies,
                        is_warm_source(&entry.key),
                    ) {
                        Ok(package_dir) => local.push((entry.key.as_ref(), package_dir)),
                        Err(error) => {
                            copy_failed.store(true, Ordering::Relaxed);
                            return Err(error);
                        }
                    }
                }
                Ok(local)
            };
            let copied_chunks: Vec<Result<Vec<(&GraphKey, PathBuf)>, LpmError>> =
                std::thread::scope(|scope| {
                    let mut handles = Vec::with_capacity(desired_helpers);
                    for _ in 0..desired_helpers {
                        match std::thread::Builder::new().spawn_scoped(scope, run_copy_worker) {
                            Ok(handle) => handles.push(handle),
                            Err(_) => break,
                        }
                    }
                    let local = run_copy_worker();
                    let mut outputs = Vec::with_capacity(handles.len() + 1);
                    outputs.push(local);
                    for handle in handles {
                        outputs.push(match handle.join() {
                            Ok(result) => result,
                            Err(_) => Err(LpmError::Store(
                                "compatibility island copy worker panicked".into(),
                            )),
                        });
                    }
                    outputs
                });
            for chunk in copied_chunks {
                for (key, package_dir) in chunk? {
                    compatibility_links.insert(key, package_dir);
                }
            }
            let compat_links_ref = &compatibility_links;
            let next_link = AtomicUsize::new(0);
            let link_failed = AtomicBool::new(false);
            let run_link_worker = || -> Result<(), LpmError> {
                while !link_failed.load(Ordering::Relaxed) {
                    let idx = next_link.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(idx) else {
                        break;
                    };
                    if let Err(error) = sync_compatibility_entry_links(
                        compatibility_root,
                        entry,
                        key_map,
                        compat_links_ref,
                    )
                    .and_then(|()| write_compatibility_marker(compatibility_root, entry))
                    {
                        link_failed.store(true, Ordering::Relaxed);
                        return Err(error);
                    }
                }
                Ok(())
            };
            let link_results: Vec<Result<(), LpmError>> = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(desired_helpers);
                for _ in 0..desired_helpers {
                    match std::thread::Builder::new().spawn_scoped(scope, run_link_worker) {
                        Ok(handle) => handles.push(handle),
                        Err(_) => break,
                    }
                }
                let local = run_link_worker();
                let mut outputs = Vec::with_capacity(handles.len() + 1);
                outputs.push(local);
                for handle in handles {
                    outputs.push(match handle.join() {
                        Ok(result) => result,
                        Err(_) => Err(LpmError::Store(
                            "compatibility island link worker panicked".into(),
                        )),
                    });
                }
                outputs
            });
            for result in link_results {
                result?;
            }
        } else {
            for entry in entries {
                let package_dir = ensure_compatibility_package_copy(
                    compatibility_root,
                    entry,
                    store,
                    refresh_package_copies,
                    is_warm_source(&entry.key),
                )?;
                compatibility_links.insert(&entry.key, package_dir);
            }
            for entry in entries {
                sync_compatibility_entry_links(
                    compatibility_root,
                    entry,
                    key_map,
                    &compatibility_links,
                )?;
            }
            for entry in entries {
                write_compatibility_marker(compatibility_root, entry)?;
            }
        }
        Ok(compatibility_links)
    }
}

/// Non-macOS path: build (and incrementally reconcile) the island directly in
/// the project's `node_modules/.lpm/compat`. This is the original behavior,
/// preserved verbatim where the `clonefile` fast path is unavailable.
#[cfg(not(target_os = "macos"))]
fn create_project_compatibility_links_in_place(
    project_dir: &Path,
    store: &Store,
    key_map: &KeyMap,
    entries: &[CompatibilityEntry<'_>],
    refresh_package_copies: bool,
    warm_link_keys: Option<&HashSet<String>>,
) -> Result<CompatibilityLinks, LpmError> {
    let compatibility_root = ensure_project_compatibility_root(project_dir)?;
    let desired: HashSet<String> = entries
        .iter()
        .map(|entry| entry.key.dir_name().to_string())
        .collect();
    reconcile_compatibility_root(&compatibility_root, &desired)?;
    build_compat_island_at(
        &compatibility_root,
        entries,
        store,
        key_map,
        refresh_package_copies,
        warm_link_keys,
    )
}

// Sentinel written last when building a store-cached island (a crash
// mid-build leaves an island that `store_compat_island_complete` rejects).
// Shared with `lpm cache prune`, which uses its mtime for LRU eviction.
/// macOS path: build the island once in the global store (keyed by its entry
/// set) and reproduce it in the project with a single recursive `clonefile`.
#[cfg(target_os = "macos")]
fn create_project_compatibility_links_store_cached(
    project_dir: &Path,
    store: &Store,
    key_map: &KeyMap,
    entries: &[CompatibilityEntry<'_>],
    refresh_package_copies: bool,
    warm_link_keys: Option<&HashSet<String>>,
) -> Result<CompatibilityLinks, LpmError> {
    let island_key = store_compat_island_key(entries, store)?;
    let _island_lock = store.acquire_build_entry_lock(&island_key)?;
    let store_island = store.paths().compat_island_dir(&island_key);
    ensure_store_compat_island(
        &store_island,
        entries,
        store,
        key_map,
        refresh_package_copies,
        warm_link_keys,
    )?;

    let compatibility_root = materialize_island_into_project(project_dir, &store_island)?;

    let mut compatibility_links = CompatibilityLinks::with_capacity(entries.len());
    for entry in entries {
        compatibility_links.insert(
            &entry.key,
            compatibility_package_dir(&compatibility_root, &entry.key),
        );
    }
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
    warm_link_keys: Option<&HashSet<String>>,
) -> Result<(), LpmError> {
    if !force_refresh && store_compat_island_complete(store_island, entries, store, key_map) {
        // Reuse: refresh the sentinel's mtime so `lpm cache prune
        // --max-age` treats an actively-used island as live (the clone
        // that follows only reads the island, so without this an island
        // built once would age out despite daily use). Best-effort — a
        // missed touch only widens prune's view by one install cycle.
        let sentinel = store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME);
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&sentinel) {
            let _ = file.set_modified(std::time::SystemTime::now());
        }
        return Ok(());
    }
    if store_island.symlink_metadata().is_ok() {
        remove_node_modules_entry(store_island, "stale store compatibility island")?;
    }
    store.ensure_compat_root_locked()?;

    let tmp = create_store_compatibility_tmp_dir(store_island)?;
    let build = (|| -> Result<(), LpmError> {
        build_compat_island_at(&tmp, entries, store, key_map, true, warm_link_keys)?;
        // Completion sentinel written last; the atomic rename below only
        // publishes a tmp that reached this point.
        write_store_compat_island_completion(&tmp, entries, store).map_err(|e| {
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
        Err(_) if store_compat_island_complete(store_island, entries, store, key_map) => {
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
const COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS: i128 = 2_000_000_000;

#[cfg(target_os = "macos")]
fn compat_system_time_nanos(time: std::time::SystemTime) -> i128 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    }
}

#[cfg(target_os = "macos")]
struct CompatPackageShallowGuard {
    dir_mtime_nanos: i128,
    dir_ctime_nanos: i128,
    pkg_json_size: u64,
    pkg_json_mtime_nanos: i128,
    pkg_json_ctime_nanos: i128,
}

#[cfg(target_os = "macos")]
fn compat_package_shallow_guard(package_dir: &Path) -> Option<CompatPackageShallowGuard> {
    use std::os::unix::fs::MetadataExt;

    let dir_meta = std::fs::symlink_metadata(package_dir).ok()?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
        return None;
    }
    let dir_mtime_nanos = compat_system_time_nanos(dir_meta.modified().ok()?);
    let dir_ctime_nanos =
        i128::from(dir_meta.ctime()) * 1_000_000_000 + i128::from(dir_meta.ctime_nsec());
    let pkg_json_meta = std::fs::symlink_metadata(package_dir.join("package.json")).ok()?;
    if !pkg_json_meta.is_file() || pkg_json_meta.file_type().is_symlink() {
        return None;
    }
    let pkg_json_mtime_nanos = compat_system_time_nanos(pkg_json_meta.modified().ok()?);
    let pkg_json_ctime_nanos =
        i128::from(pkg_json_meta.ctime()) * 1_000_000_000 + i128::from(pkg_json_meta.ctime_nsec());
    Some(CompatPackageShallowGuard {
        dir_mtime_nanos,
        dir_ctime_nanos,
        pkg_json_size: pkg_json_meta.len(),
        pkg_json_mtime_nanos,
        pkg_json_ctime_nanos,
    })
}

#[cfg(target_os = "macos")]
fn compat_entry_sibling_links_match(
    store_island: &Path,
    entry: &CompatibilityEntry<'_>,
    key_map: &KeyMap,
) -> bool {
    let Ok(mut expected_links) = compatibility_dependency_links(entry.target, key_map) else {
        return false;
    };
    let own_local = entry.key.name();
    expected_links.retain(|(local, _)| local != own_local);
    let node_modules = compatibility_node_modules_dir(store_island, &entry.key);
    let own_package_dir = compatibility_package_dir(store_island, &entry.key);

    let mut expected_slots: HashSet<String> = HashSet::with_capacity(expected_links.len() + 1);
    expected_slots.insert(own_local.to_string());
    for (local, _) in &expected_links {
        expected_slots.insert(local.clone());
    }

    // Verify no unexpected sibling entries were injected into entry/node_modules.
    let Ok(read_dir) = std::fs::read_dir(&node_modules) else {
        return false;
    };
    let mut actual_count = 0usize;
    for item in read_dir {
        let Ok(item) = item else {
            return false;
        };
        let path = item.path();
        let name = item.file_name().to_string_lossy().into_owned();
        let Ok(meta) = path.symlink_metadata() else {
            return false;
        };
        if name.starts_with('@') && meta.is_dir() && !is_symlink_or_junction(&meta) {
            let Ok(scope_entries) = std::fs::read_dir(&path) else {
                return false;
            };
            let mut scope_count = 0usize;
            for scoped in scope_entries {
                let Ok(scoped) = scoped else {
                    return false;
                };
                let full_name = format!("{name}/{}", scoped.file_name().to_string_lossy());
                if !expected_slots.contains(&full_name) {
                    return false;
                }
                scope_count += 1;
            }
            if scope_count == 0 {
                return false;
            }
            actual_count += scope_count;
        } else {
            if !expected_slots.contains(&name) {
                return false;
            }
            actual_count += 1;
        }
    }
    if actual_count != expected_slots.len() {
        return false;
    }

    for (local, dep_key) in expected_links {
        let target_package_dir = compatibility_package_dir(store_island, &dep_key);
        if target_package_dir == own_package_dir {
            continue;
        }
        let link_path = node_modules.join(&local);
        let Ok(meta) = link_path.symlink_metadata() else {
            return false;
        };
        if !meta.file_type().is_symlink() {
            return false;
        }
        let expected_rel = relative_compat_sibling_target(&link_path, &target_package_dir);
        if std::fs::read_link(&link_path).ok().as_deref() != Some(expected_rel.as_path()) {
            return false;
        }
    }
    true
}

#[cfg(target_os = "macos")]
fn store_compat_island_complete(
    store_island: &Path,
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
    key_map: &KeyMap,
) -> bool {
    let sentinel = store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME);
    let Ok(metadata) = sentinel.symlink_metadata() else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    let Ok(content) =
        lpm_common::read_file_capped(&sentinel, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
    else {
        return false;
    };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&content) else {
        return false;
    };
    if manifest.get("schema").and_then(serde_json::Value::as_u64)
        != Some(COMPAT_ISLAND_COMPLETE_SCHEMA)
    {
        return false;
    }
    let Some(recorded_entries) = manifest
        .get("entries")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    if recorded_entries.len() != entries.len() {
        return false;
    }
    let recorded_entries_no_ctime = manifest
        .get("entries_no_ctime")
        .and_then(serde_json::Value::as_object);
    let recorded_guards = manifest
        .get("shallow_guards")
        .and_then(serde_json::Value::as_object);
    let captured_at_nanos = manifest
        .get("captured_at_nanos")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<i128>().ok());
    let trust_restored =
        lpm_store::v2::trust_restored_store_enabled(store.object_integrity_policy());

    let mut any_strict_guard_refresh_needed = false;
    let mut any_restored_only = false;
    let mut refreshed_entries_no_ctime: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut any_no_ctime_backfilled = false;

    for entry in entries {
        let entry_dir = compatibility_entry_dir(store_island, &entry.key);
        let Some(expected) = recorded_entries
            .get(entry.key.dir_name())
            .and_then(serde_json::Value::as_str)
        else {
            return false;
        };
        if !compatibility_entry_reusable(&entry_dir, entry) {
            return false;
        }
        let package_dir = compatibility_package_dir(store_island, &entry.key);
        let entry_source_policy =
            store.source_policy_allows_shallow_guard_for_sri(&entry.target.source_sri);
        let entry_trust_restored = trust_restored && entry_source_policy;
        let shallow_eligible =
            entry_source_policy && package_dir.join(".lpm-built").symlink_metadata().is_err();
        let mut hit_shallow = false;
        if shallow_eligible
            && let Some(captured_at) = captured_at_nanos
            && let Some(guard_val) =
                recorded_guards.and_then(|guards| guards.get(entry.key.dir_name()))
            && let Some(current) = compat_package_shallow_guard(&package_dir)
            && captured_at.saturating_sub(current.dir_mtime_nanos)
                >= COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
            && captured_at.saturating_sub(current.pkg_json_mtime_nanos)
                >= COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
            && guard_val
                .get("dir_mtime_nanos")
                .and_then(serde_json::Value::as_str)
                == Some(current.dir_mtime_nanos.to_string().as_str())
            && guard_val
                .get("dir_ctime_nanos")
                .and_then(serde_json::Value::as_str)
                == Some(current.dir_ctime_nanos.to_string().as_str())
            && guard_val
                .get("pkg_json_size")
                .and_then(serde_json::Value::as_u64)
                == Some(current.pkg_json_size)
            && guard_val
                .get("pkg_json_mtime_nanos")
                .and_then(serde_json::Value::as_str)
                == Some(current.pkg_json_mtime_nanos.to_string().as_str())
            && guard_val
                .get("pkg_json_ctime_nanos")
                .and_then(serde_json::Value::as_str)
                == Some(current.pkg_json_ctime_nanos.to_string().as_str())
            && compat_entry_sibling_links_match(store_island, entry, key_map)
        {
            hit_shallow = true;
        }
        if hit_shallow {
            continue;
        }
        let expected_no_ctime = recorded_entries_no_ctime
            .and_then(|map| map.get(entry.key.dir_name()))
            .and_then(serde_json::Value::as_str);
        if !entry_trust_restored && expected_no_ctime.is_some() {
            let Ok(actual) = store.compat_island_entry_metadata_integrity(&entry_dir) else {
                return false;
            };
            if actual != expected {
                return false;
            }
            if shallow_eligible {
                any_strict_guard_refresh_needed = true;
            }
            continue;
        }
        let Ok((actual, actual_no_ctime)) =
            store.compat_island_entry_metadata_integrities(&entry_dir)
        else {
            return false;
        };
        let matched_strict = actual == expected;
        let matched_restored = !matched_strict
            && entry_trust_restored
            && expected_no_ctime == Some(actual_no_ctime.as_str());
        if !matched_strict && !matched_restored {
            if entry_trust_restored {
                tracing::debug!(
                    entry = %entry.key.dir_name(),
                    "LPM_TRUST_RESTORED_STORE enabled but compat island ctime-free digest missed"
                );
            }
            return false;
        }
        if matched_restored {
            // Never overwrite strict metadata digests or strict shallow guards
            // from a trust-only match so disabling LPM_TRUST_RESTORED_STORE
            // still enforces strict verification on the next run.
            any_restored_only = true;
            continue;
        }
        if shallow_eligible {
            any_strict_guard_refresh_needed = true;
        }
        if expected_no_ctime != Some(actual_no_ctime.as_str()) {
            any_no_ctime_backfilled = true;
            let no_ctime_map = refreshed_entries_no_ctime
                .get_or_insert_with(|| recorded_entries_no_ctime.cloned().unwrap_or_default());
            no_ctime_map.insert(
                entry.key.dir_name().to_string(),
                serde_json::Value::String(actual_no_ctime),
            );
        }
    }

    if !any_restored_only && (any_strict_guard_refresh_needed || any_no_ctime_backfilled) {
        refresh_store_compat_island_completion_best_effort(
            store_island,
            entries,
            store,
            recorded_entries.clone(),
            refreshed_entries_no_ctime
                .unwrap_or_else(|| recorded_entries_no_ctime.cloned().unwrap_or_default()),
            any_no_ctime_backfilled,
        );
    }
    true
}

#[cfg(target_os = "macos")]
fn refresh_store_compat_island_completion_best_effort(
    store_island: &Path,
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
    recorded_entries: serde_json::Map<String, serde_json::Value>,
    recorded_entries_no_ctime: serde_json::Map<String, serde_json::Value>,
    force_write: bool,
) {
    let now_nanos = compat_system_time_nanos(std::time::SystemTime::now());
    let mut shallow_guards = serde_json::Map::new();
    let mut any_eligible = false;
    let mut all_non_racy = true;
    for entry in entries {
        if !store.source_policy_allows_shallow_guard_for_sri(&entry.target.source_sri) {
            continue;
        }
        any_eligible = true;
        let package_dir = compatibility_package_dir(store_island, &entry.key);
        let Some(guard) = compat_package_shallow_guard(&package_dir) else {
            all_non_racy = false;
            continue;
        };
        if now_nanos.saturating_sub(guard.dir_mtime_nanos)
            < COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
            || now_nanos.saturating_sub(guard.pkg_json_mtime_nanos)
                < COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS
        {
            all_non_racy = false;
        }
        shallow_guards.insert(
            entry.key.dir_name().to_string(),
            serde_json::json!({
                "dir_mtime_nanos": guard.dir_mtime_nanos.to_string(),
                "dir_ctime_nanos": guard.dir_ctime_nanos.to_string(),
                "pkg_json_size": guard.pkg_json_size,
                "pkg_json_mtime_nanos": guard.pkg_json_mtime_nanos.to_string(),
                "pkg_json_ctime_nanos": guard.pkg_json_ctime_nanos.to_string(),
            }),
        );
    }
    if !force_write && (!any_eligible || !all_non_racy) {
        return;
    }
    let manifest = serde_json::json!({
        "schema": COMPAT_ISLAND_COMPLETE_SCHEMA,
        "captured_at_nanos": now_nanos.to_string(),
        "entries": recorded_entries,
        "entries_no_ctime": recorded_entries_no_ctime,
        "shallow_guards": shallow_guards,
    });
    if let Ok(content) = serde_json::to_vec(&manifest) {
        let _ = lpm_common::write_file_atomic(
            &store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME),
            content,
        );
    }
}

#[cfg(target_os = "macos")]
fn write_store_compat_island_completion(
    store_island: &Path,
    entries: &[CompatibilityEntry<'_>],
    store: &Store,
) -> Result<(), LpmError> {
    let mut recorded_entries = serde_json::Map::new();
    let mut recorded_entries_no_ctime = serde_json::Map::new();
    let mut shallow_guards = serde_json::Map::new();
    for entry in entries {
        let entry_dir = compatibility_entry_dir(store_island, &entry.key);
        let (integrity, integrity_no_ctime) =
            store.compat_island_entry_metadata_integrities(&entry_dir)?;
        recorded_entries.insert(
            entry.key.dir_name().to_string(),
            serde_json::Value::String(integrity),
        );
        recorded_entries_no_ctime.insert(
            entry.key.dir_name().to_string(),
            serde_json::Value::String(integrity_no_ctime),
        );
        if store.source_policy_allows_shallow_guard_for_sri(&entry.target.source_sri) {
            let package_dir = compatibility_package_dir(store_island, &entry.key);
            if let Some(guard) = compat_package_shallow_guard(&package_dir) {
                shallow_guards.insert(
                    entry.key.dir_name().to_string(),
                    serde_json::json!({
                        "dir_mtime_nanos": guard.dir_mtime_nanos.to_string(),
                        "dir_ctime_nanos": guard.dir_ctime_nanos.to_string(),
                        "pkg_json_size": guard.pkg_json_size,
                        "pkg_json_mtime_nanos": guard.pkg_json_mtime_nanos.to_string(),
                        "pkg_json_ctime_nanos": guard.pkg_json_ctime_nanos.to_string(),
                    }),
                );
            }
        }
    }
    let captured_at_nanos = compat_system_time_nanos(std::time::SystemTime::now()).to_string();
    let manifest = serde_json::json!({
        "schema": COMPAT_ISLAND_COMPLETE_SCHEMA,
        "captured_at_nanos": captured_at_nanos,
        "entries": recorded_entries,
        "entries_no_ctime": recorded_entries_no_ctime,
        "shallow_guards": shallow_guards,
    });
    let content = serde_json::to_vec(&manifest).map_err(|error| {
        LpmError::Store(format!(
            "virtual-store linker: failed to serialize island completion manifest: {error}"
        ))
    })?;
    std::fs::write(store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME), content).map_err(|error| {
        LpmError::Store(format!(
            "virtual-store linker: failed to write island completion manifest: {error}"
        ))
    })
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
        if !lpm_workspace::manifest_bytes_may_contain_bin(&content) {
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
    if std::fs::read_dir(&lpm_dir).is_ok_and(|mut entries| entries.next().is_none()) {
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
    warm_source: bool,
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

    if let Err(error) = copy_dir_recursive(&source_package_dir, &tmp_package_dir, warm_source) {
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
            .is_ok_and(|metadata| metadata.is_dir() && !is_symlink_or_junction(&metadata));
        if name.starts_with('@') && is_real_dir {
            reconcile_scoped_root_dir(&path, &name, desired)?;
            if std::fs::read_dir(&path).is_ok_and(|mut entries| entries.next().is_none()) {
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
/// link's parent directory. Both paths are built under the same compatibility
/// root with no intermediate symlinks, so lexical `diff_paths` computes the
/// island-internal relative path directly without `canonicalize()` syscalls.
fn relative_compat_sibling_target(link_path: &Path, target_package_dir: &Path) -> PathBuf {
    let Some(link_parent) = link_path.parent() else {
        return target_package_dir.to_path_buf();
    };
    if let Some(relative) = pathdiff::diff_paths(target_package_dir, link_parent) {
        return relative;
    }
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

    #[test]
    fn store_compat_island_complete_refreshes_shallow_guard_timestamp_after_racily_clean_window() {
        use super::super::V2Target;
        use super::super::keymap::derive_graph_keys;
        use super::{
            CompatibilityEntry, compatibility_package_dir, ensure_store_compat_island,
            store_compat_island_complete,
        };
        use crate::{LinkTarget, Materialization};
        use lpm_store::v2::{COMPAT_ISLAND_COMPLETE_FILENAME, LinkerModeTag, PlatformTuple, Store};
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let mut tar_builder = tar::Builder::new(Vec::new());
        let pkg_json =
            br#"{"name":"tool","version":"1.0.0","bin":{"tool":"cli.js"},"dependencies":{}}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "package/package.json", &pkg_json[..])
            .unwrap();
        let cli_js = b"#!/usr/bin/env node\nconsole.log('ok');\n";
        let mut cli_header = tar::Header::new_gnu();
        cli_header.set_size(cli_js.len() as u64);
        cli_header.set_mode(0o755);
        cli_header.set_cksum();
        tar_builder
            .append_data(&mut cli_header, "package/cli.js", &cli_js[..])
            .unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
        let tarball = encoder.finish().unwrap();

        let (object_dir, sri, _) = store.extract_object_from_bytes(&tarball, None).unwrap();
        let platform = PlatformTuple::current();
        let v2_target = Arc::new(V2Target {
            instance_id: lpm_common::PackageInstanceId::derive(
                "tool",
                "1.0.0",
                "registry+npm",
                "tool",
            ),
            target: Arc::new(LinkTarget {
                name: "tool".to_string(),
                version: "1.0.0".to_string(),
                store_path: object_dir.clone(),
                dependencies: vec![],
                aliases: std::collections::HashMap::new(),
                is_direct: true,
                root_link_names: None,
                wrapper_id: None,
                materialization: Materialization::CasBacked,
                peers: vec![],
                patch_fingerprint: None,
            }),
            dependency_targets: std::collections::HashMap::new(),
            peer_targets: std::collections::HashMap::new(),
            source_sri: sri.clone(),
            verified_object_integrity: None,
            fresh_object: None,
        });
        let key_map = derive_graph_keys(
            std::slice::from_ref(&v2_target),
            &platform,
            LinkerModeTag::Isolated,
            None,
        )
        .unwrap();
        let derived_key = Arc::clone(key_map.get_for(&v2_target).unwrap());
        store
            .populate_link_entry(lpm_store::v2::LinkEntryRequest {
                graph_key: Arc::clone(&derived_key),
                source_sri: sri,
                object_dir,
                deps: vec![],
                platform: Arc::new(lpm_store::v2::LinkMetaPlatform {
                    os: platform.os,
                    cpu: platform.cpu,
                    libc: platform.libc,
                }),
            })
            .unwrap();

        let store_island = store.paths().compat_island_dir("test-island-refresh");
        let entry = CompatibilityEntry {
            target: &v2_target,
            key: Arc::clone(&derived_key),
        };
        ensure_store_compat_island(
            &store_island,
            std::slice::from_ref(&entry),
            &store,
            &key_map,
            false,
            None,
        )
        .unwrap();

        // Age the island's files and set captured_at_nanos equal to those old mtimes
        // (simulating the racy capture recorded at creation time).
        let pkg_dir = compatibility_package_dir(&store_island, &derived_key);
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        std::fs::set_times(
            pkg_dir.join("package.json"),
            std::fs::FileTimes::new().set_modified(old),
        )
        .unwrap();
        std::fs::set_times(
            pkg_dir.join("cli.js"),
            std::fs::FileTimes::new().set_modified(old),
        )
        .unwrap();
        std::fs::set_times(&pkg_dir, std::fs::FileTimes::new().set_modified(old)).unwrap();
        // Rewrite completion manifest with the current aged metadata AND a racy captured_at_nanos.
        super::write_store_compat_island_completion(
            &store_island,
            std::slice::from_ref(&entry),
            &store,
        )
        .unwrap();
        let sentinel_path = store_island.join(COMPAT_ISLAND_COMPLETE_FILENAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sentinel_path).unwrap()).unwrap();
        let racy_captured = super::compat_system_time_nanos(old).to_string();
        manifest["captured_at_nanos"] = serde_json::Value::String(racy_captured);
        std::fs::write(&sentinel_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        assert!(store_compat_island_complete(
            &store_island,
            std::slice::from_ref(&entry),
            &store,
            &key_map,
        ));
        let refreshed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sentinel_path).unwrap()).unwrap();
        let refreshed_captured = refreshed["captured_at_nanos"]
            .as_str()
            .unwrap()
            .parse::<i128>()
            .unwrap();
        assert!(
            refreshed_captured - super::compat_system_time_nanos(old)
                >= super::COMPAT_SHALLOW_GUARD_RACILY_CLEAN_WINDOW_NANOS,
            "store_compat_island_complete must advance captured_at_nanos once outside the 2s window"
        );

        // Simulate a CI cache restore where ctime shifted on disk (invalidating both
        // the strict shallow guard ctime and the strict full metadata digest while
        // preserving the ctime-free digest). A trust-restored match under Source
        // policy must NOT overwrite strict digests or strict shallow guards.
        let mut stale_strict = refreshed.clone();
        stale_strict["entries"][derived_key.dir_name()] =
            serde_json::Value::String("sha256-stale-strict-digest".to_string());
        stale_strict["shallow_guards"][derived_key.dir_name()]["dir_ctime_nanos"] =
            serde_json::Value::String("0".to_string());
        std::fs::write(&sentinel_path, serde_json::to_vec(&stale_strict).unwrap()).unwrap();
        assert!(
            !store_compat_island_complete(
                &store_island,
                std::slice::from_ref(&entry),
                &store,
                &key_map,
            ),
            "without LPM_TRUST_RESTORED_STORE, stale strict digest must miss"
        );
        #[cfg(debug_assertions)]
        {
            let _trust = lpm_store::v2::override_trust_restored_store_for_test(Some(true));
            assert!(
                store_compat_island_complete(
                    &store_island,
                    std::slice::from_ref(&entry),
                    &store,
                    &key_map,
                ),
                "with LPM_TRUST_RESTORED_STORE under Source policy, matching ctime-free digest must hit"
            );
            let after_trust: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&sentinel_path).unwrap()).unwrap();
            assert_eq!(
                after_trust["entries"][derived_key.dir_name()].as_str(),
                Some("sha256-stale-strict-digest"),
                "trust-restored hit must never overwrite the recorded strict metadata digest"
            );
            assert_eq!(
                after_trust["shallow_guards"][derived_key.dir_name()]["dir_ctime_nanos"].as_str(),
                Some("0"),
                "trust-restored hit must never overwrite the recorded strict shallow guard"
            );

            // Local-source objects enforce Tree integrity even under Source policy,
            // so `LPM_TRUST_RESTORED_STORE` must NOT accept ctime drift for them.
            let local_sentinel = store
                .paths()
                .objects_root()
                .join(".lpm-object-meta")
                .join(
                    store
                        .paths()
                        .object_dir(&entry.target.source_sri)
                        .unwrap()
                        .file_name()
                        .unwrap(),
                )
                .join("local-source");
            std::fs::create_dir_all(local_sentinel.parent().unwrap()).unwrap();
            std::fs::write(&local_sentinel, b"1").unwrap();
            assert!(
                !store_compat_island_complete(
                    &store_island,
                    std::slice::from_ref(&entry),
                    &store,
                    &key_map,
                ),
                "local-source entry using Tree integrity must ignore LPM_TRUST_RESTORED_STORE"
            );
            std::fs::remove_file(&local_sentinel).unwrap();
        }
        assert!(
            !store_compat_island_complete(
                &store_island,
                std::slice::from_ref(&entry),
                &store,
                &key_map,
            ),
            "disabling LPM_TRUST_RESTORED_STORE must immediately re-enforce strict verification"
        );

        // Warm hit on a `.lpm-built` package (shallow-ineligible) must not rewrite `.complete.json`.
        std::fs::write(&sentinel_path, serde_json::to_vec(&refreshed).unwrap()).unwrap();
        std::fs::write(pkg_dir.join(".lpm-built"), b"1").unwrap();
        super::write_store_compat_island_completion(
            &store_island,
            std::slice::from_ref(&entry),
            &store,
        )
        .unwrap();
        std::fs::set_times(&sentinel_path, std::fs::FileTimes::new().set_modified(old)).unwrap();
        assert!(store_compat_island_complete(
            &store_island,
            std::slice::from_ref(&entry),
            &store,
            &key_map,
        ));
        assert_eq!(
            sentinel_path.metadata().unwrap().modified().unwrap(),
            old,
            "warm hit for .lpm-built entry must not rewrite completion sentinel"
        );
    }
}

#[cfg(test)]
mod manifest_tests {
    #[test]
    fn package_name_is_read_from_a_manifest_with_a_byte_order_mark() {
        let (name, bin) =
            lpm_workspace::parse_name_and_bin_field(b"\xEF\xBB\xBF{\"name\":\"marked\"}").unwrap();
        assert_eq!(name.as_deref(), Some("marked"));
        assert!(bin.is_none());
    }

    #[test]
    fn manifest_needs_bin_compatibility_handles_unicode_escaped_dependency_keys() {
        assert!(super::manifest_needs_bin_compatibility(
            br#"{"name":"cli","bin":"./cli.js","dep\u0065ndencies":{"a":"1.0.0"}}"#
        ));
        assert!(super::manifest_needs_bin_compatibility(
            br#"{"name":"cli","bin":"./cli.js","peerDep\u0065ndencies":{"a":"1.0.0"}}"#
        ));
        assert!(!super::manifest_needs_bin_compatibility(
            br#"{"name":"cli","bin":"./cli.js","version":"1.0.0"}"#
        ));
        assert!(!super::manifest_needs_bin_compatibility(
            br#"{"name":"cli","bin":"./cli.js","description":"caf\u00e9"}"#
        ));
    }
}
