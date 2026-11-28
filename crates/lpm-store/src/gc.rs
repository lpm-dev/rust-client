use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher as _, RandomState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use lpm_common::LpmError;

use crate::{PackageStore, STORE_VERSION, is_complete_package_dir};

/// Minimum age before a `.tmp.` staging directory in `store/v1/` is treated as
/// abandoned by a crashed extraction rather than an active concurrent write.
const ABANDONED_TEMP_AGE: Duration = Duration::from_secs(10 * 60);
const RETIRE_RENAME_ATTEMPTS: usize = 16;

static GC_RETIRE_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_retired_path(parent: &Path) -> PathBuf {
    let seq = GC_RETIRE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nonce = RandomState::new().hash_one((std::process::id(), seq, Instant::now()));
    // Bounded basename independent of the package directory name so entries near
    // the 255-byte component limit never fail retirement with ENAMETOOLONG.
    parent.join(format!(".tmp.gc.{}.{nonce:016x}.{seq}", std::process::id()))
}

const ACTIVE_RETIRE_SUFFIX: &str = ".active";

fn retired_active_marker_path(retired: &Path) -> PathBuf {
    let mut marker = retired.as_os_str().to_os_string();
    marker.push(ACTIVE_RETIRE_SUFFIX);
    PathBuf::from(marker)
}

fn has_fresh_active_marker(path: &Path, now: SystemTime) -> bool {
    let marker = retired_active_marker_path(path);
    let Ok(meta) = std::fs::symlink_metadata(&marker) else {
        return false;
    };
    meta.modified()
        .ok()
        .is_some_and(|mtime| is_within_max_age(mtime, now, ABANDONED_TEMP_AGE))
}

fn clear_retired_active_marker(retired: &Path) {
    let _ = std::fs::remove_file(retired_active_marker_path(retired));
}

fn retire_store_entry(path: &Path, _scan_now: SystemTime) -> Result<Option<PathBuf>, LpmError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut last_collision: Option<std::io::Error> = None;

    for _ in 0..RETIRE_RENAME_ATTEMPTS {
        let retired = next_retired_path(parent);
        if std::fs::symlink_metadata(&retired).is_ok() {
            last_collision = Some(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
            continue;
        }
        let marker = retired_active_marker_path(&retired);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(err);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
        match std::fs::rename(path, &retired) {
            Ok(()) => {
                // Capture retirement time now (not the pre-scan clock) and never follow
                // symlinks/junctions when refreshing the retired entry's mtime.
                let retire_now = SystemTime::now();
                if let Ok(meta) = std::fs::symlink_metadata(&retired)
                    && !lpm_common::is_symlink_or_junction(&meta)
                {
                    let _ = std::fs::set_times(
                        &retired,
                        std::fs::FileTimes::new().set_modified(retire_now),
                    );
                }
                return Ok(Some(retired));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let _ = std::fs::remove_file(&marker);
                return Ok(None);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                let _ = std::fs::remove_file(&marker);
                last_collision = Some(err);
            }
            Err(err) => {
                let _ = std::fs::remove_file(&marker);
                return Err(err.into());
            }
        }
    }

    Err(last_collision
        .unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "could not allocate a unique retirement path for {}",
                    path.display()
                ),
            )
        })
        .into())
}

fn is_within_max_age(mtime: SystemTime, now: SystemTime, age_threshold: Duration) -> bool {
    match now.duration_since(mtime) {
        Ok(elapsed) => elapsed < age_threshold,
        Err(_) => true,
    }
}

impl PackageStore {
    /// List all packages in the store.
    pub fn list_packages(&self) -> Result<Vec<(String, String)>, LpmError> {
        let store_dir = self.root().join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(Vec::new());
        }

        let mut packages = Vec::new();
        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if let Some(package) = complete_package_from_dir(&entry.path(), &dir_name) {
                packages.push(package);
            }
        }

        packages.sort();
        Ok(packages)
    }

    /// Garbage collection: remove packages from the store that are not referenced
    /// by any project's lockfile.
    ///
    /// `referenced` is a set of "name@version" strings that should be kept.
    /// Everything else in the store is removed.
    ///
    /// If `max_age` is provided, only unreferenced packages whose directory mtime
    /// is older than `now - max_age` are removed. This allows keeping recently-used
    /// packages even if they're not in the current lockfile.
    pub fn gc(
        &self,
        referenced: &HashSet<String>,
        max_age: Option<&Duration>,
    ) -> Result<GcResult, LpmError> {
        let store_dir = self.root().join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcResult {
                removed: 0,
                kept: 0,
                freed_bytes: 0,
            });
        }

        // Pre-scan `.tmp.` subtrees for recent nested activity outside the publication
        // lock so large abandoned staging trees never block concurrent publishers.
        let pre_scan_now = SystemTime::now();
        let mut abandoned_temp_mtimes: HashMap<String, SystemTime> = HashMap::new();
        if let Ok(read_dir) = std::fs::read_dir(&store_dir) {
            for entry in read_dir.flatten() {
                let dir_name = entry.file_name().to_string_lossy().into_owned();
                if !is_temp_store_dir_name(&dir_name) || dir_name.ends_with(ACTIVE_RETIRE_SUFFIX) {
                    continue;
                }
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if !meta.is_dir() || lpm_common::is_symlink_or_junction(&meta) {
                    continue;
                }
                let Ok(mtime) = meta.modified() else {
                    continue;
                };
                if !is_within_max_age(mtime, pre_scan_now, ABANDONED_TEMP_AGE)
                    && !has_fresh_active_marker(&path, pre_scan_now)
                    && !subtree_has_recent_activity(&path, pre_scan_now, ABANDONED_TEMP_AGE)
                {
                    abandoned_temp_mtimes.insert(dir_name, mtime);
                }
            }
        }

        let mut kept = 0usize;
        let mut retired_packages: Vec<PathBuf> = Vec::new();
        let mut retired_junk: Vec<PathBuf> = Vec::new();

        // Hold the v1 publication lock only while scanning and atomically retiring
        // doomed entries; unlink the retired subtrees outside the lock so slow
        // filesystem deletion does not stall concurrent package publications.
        let retire_result: Result<(), LpmError> = (|| {
            let _publication = self.lock_publication()?;
            #[cfg(all(test, unix))]
            run_gc_after_prescan_hook();
            let now = SystemTime::now();
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&store_dir)? {
                let entry = entry?;
                let dir_name = entry.file_name().to_string_lossy().into_owned();
                entries.push((entry.path(), dir_name));
            }

            for (path, dir_name) in entries {
                if let Some((pkg_name, version)) = complete_package_from_dir(&path, &dir_name) {
                    let key = format!("{pkg_name}@{version}");

                    if referenced.contains(&key) {
                        kept += 1;
                        continue;
                    }

                    if let Some(age_threshold) = max_age
                        && let Ok(meta) = std::fs::symlink_metadata(&path)
                        && let Ok(mtime) = meta.modified()
                        && is_within_max_age(mtime, now, *age_threshold)
                    {
                        kept += 1;
                        continue;
                    }

                    if let Some(retired) = retire_store_entry(&path, now)? {
                        retired_packages.push(retired);
                    }
                    continue;
                }

                if is_junk_store_entry_locked(&path, &dir_name, now, &abandoned_temp_mtimes)
                    && let Some(retired) = retire_store_entry(&path, now)?
                {
                    retired_junk.push(retired);
                }
            }
            Ok(())
        })();

        if let Err(err) = retire_result {
            for path in retired_packages.iter().chain(retired_junk.iter()) {
                let _ = lpm_common::remove_path_entry(path);
                clear_retired_active_marker(path);
            }
            return Err(err);
        }

        let mut removed = 0usize;
        let mut freed_bytes: u64 = 0;
        for retired in retired_packages {
            let remove_result = lpm_common::remove_path_entry_counting_freed_bytes(&retired);
            clear_retired_active_marker(&retired);
            match remove_result {
                Ok(freed) => {
                    freed_bytes = freed_bytes.saturating_add(freed);
                    removed += 1;
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        && matches!(
                            std::fs::symlink_metadata(&retired),
                            Err(meta_err) if meta_err.kind() == std::io::ErrorKind::NotFound
                        ) =>
                {
                    removed += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
        for retired in retired_junk {
            let remove_result = lpm_common::remove_path_entry(&retired);
            clear_retired_active_marker(&retired);
            match remove_result {
                Ok(()) => {}
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        && matches!(
                            std::fs::symlink_metadata(&retired),
                            Err(meta_err) if meta_err.kind() == std::io::ErrorKind::NotFound
                        ) => {}
                Err(err) => return Err(err.into()),
            }
        }

        Ok(GcResult {
            removed,
            kept,
            freed_bytes,
        })
    }

    /// Preview what GC would remove, without actually deleting anything.
    ///
    /// Returns a list of package names and their sizes that would be removed,
    /// plus the count of packages that would be kept.
    pub fn gc_preview(
        &self,
        referenced: &HashSet<String>,
        max_age: Option<&Duration>,
    ) -> Result<GcPreview, LpmError> {
        let store_dir = self.root().join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcPreview {
                would_remove: Vec::new(),
                would_keep: 0,
                would_free_bytes: 0,
            });
        }

        let now = SystemTime::now();
        let mut candidates: Vec<(String, PathBuf)> = Vec::new();
        let mut would_keep = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let path = entry.path();
            let dir_name = entry.file_name().to_string_lossy().into_owned();

            if let Some((pkg_name, version)) = complete_package_from_dir(&path, &dir_name) {
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    would_keep += 1;
                    continue;
                }

                if let Some(age_threshold) = max_age
                    && let Ok(meta) = std::fs::symlink_metadata(&path)
                    && let Ok(mtime) = meta.modified()
                    && is_within_max_age(mtime, now, *age_threshold)
                {
                    would_keep += 1;
                    continue;
                }

                candidates.push((key, path));
            }
        }

        candidates.sort_by(|a, b| a.0.cmp(&b.0));

        let mut seen_links: HashMap<lpm_common::FileIdentity, u64> = HashMap::new();
        let mut would_remove = Vec::with_capacity(candidates.len());
        let mut would_free_bytes: u64 = 0;
        for (key, path) in candidates {
            let size = reclaimable_dir_size(&path, &mut seen_links);
            would_free_bytes = would_free_bytes.saturating_add(size);
            would_remove.push((key, size));
        }

        Ok(GcPreview {
            would_remove,
            would_keep,
            would_free_bytes,
        })
    }

    /// Remove a specific package from the store.
    pub fn remove_package(&self, name: &str, version: &str) -> Result<bool, LpmError> {
        let dir = self.package_dir(name, version);
        if !dir.exists() {
            return Ok(false);
        }
        let retired = {
            let _publication = self.lock_publication()?;
            if std::fs::symlink_metadata(&dir).is_err() {
                return Ok(false);
            }
            let Some(retired) = retire_store_entry(&dir, SystemTime::now())? else {
                return Ok(false);
            };
            retired
        };
        let remove_result = lpm_common::remove_path_entry(&retired);
        clear_retired_active_marker(&retired);
        match remove_result {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(true)
    }
}

fn is_temp_store_dir_name(dir_name: &str) -> bool {
    dir_name.contains(".tmp.")
}

fn complete_package_from_dir(dir: &Path, dir_name: &str) -> Option<(String, String)> {
    if !is_complete_package_dir(dir) || is_temp_store_dir_name(dir_name) {
        return None;
    }

    let at_pos = dir_name.rfind('@')?;
    let pkg_name = dir_name[..at_pos].replace('+', "/");
    let version = dir_name[at_pos + 1..].to_string();
    Some((pkg_name, version))
}

fn is_junk_store_entry_locked(
    path: &Path,
    dir_name: &str,
    now: SystemTime,
    abandoned_temp_mtimes: &HashMap<String, SystemTime>,
) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if lpm_common::is_symlink_or_junction(&meta) {
        return false;
    }
    if dir_name.ends_with(ACTIVE_RETIRE_SUFFIX) && is_temp_store_dir_name(dir_name) {
        return meta.is_file()
            && meta
                .modified()
                .ok()
                .is_some_and(|mtime| !is_within_max_age(mtime, now, ABANDONED_TEMP_AGE));
    }
    if !meta.is_dir() {
        return false;
    }
    if is_temp_store_dir_name(dir_name) {
        let Some(&prescanned_mtime) = abandoned_temp_mtimes.get(dir_name) else {
            return false;
        };
        return meta.modified().ok().is_some_and(|live_mtime| {
            live_mtime == prescanned_mtime
                && !is_within_max_age(live_mtime, now, ABANDONED_TEMP_AGE)
        }) && !has_fresh_active_marker(path, now)
            && !subtree_has_recent_activity(path, now, ABANDONED_TEMP_AGE);
    }
    dir_name.rfind('@').is_some() && !is_complete_package_dir(path)
}

#[cfg(all(test, unix))]
fn is_junk_store_dir(dir: &Path, dir_name: &str, now: SystemTime) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !meta.is_dir() || lpm_common::is_symlink_or_junction(&meta) {
        return false;
    }
    if is_temp_store_dir_name(dir_name) {
        let root_is_abandoned = meta
            .modified()
            .ok()
            .is_some_and(|mtime| !is_within_max_age(mtime, now, ABANDONED_TEMP_AGE));
        return root_is_abandoned
            && !has_fresh_active_marker(dir, now)
            && !subtree_has_recent_activity(dir, now, ABANDONED_TEMP_AGE);
    }
    dir_name.rfind('@').is_some() && !is_complete_package_dir(dir)
}

fn subtree_has_recent_activity(root: &Path, now: SystemTime, threshold: Duration) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return true,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return true;
            };
            let path = entry.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return true,
            };
            if meta
                .modified()
                .ok()
                .is_some_and(|mtime| is_within_max_age(mtime, now, threshold))
            {
                return true;
            }
            if meta.is_dir() && !lpm_common::is_symlink_or_junction(&meta) {
                stack.push(path);
            }
        }
    }
    false
}

/// Result of garbage collection.
#[derive(Debug)]
pub struct GcResult {
    pub removed: usize,
    pub kept: usize,
    pub freed_bytes: u64,
}

/// Preview of what garbage collection would remove (dry-run).
#[derive(Debug)]
pub struct GcPreview {
    /// Packages that would be removed: (name@version, size_bytes).
    pub would_remove: Vec<(String, u64)>,
    /// Number of packages that would be kept.
    pub would_keep: usize,
    /// Total bytes that would be freed.
    pub would_free_bytes: u64,
}

/// Calculate reclaimable regular-file bytes in `root` without following links,
/// matching [`lpm_common::remove_path_entry_counting_freed_bytes`]: a file is
/// counted once when every link to its inode resides within the doomed set.
fn reclaimable_dir_size(
    root: &Path,
    seen_links: &mut HashMap<lpm_common::FileIdentity, u64>,
) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if lpm_common::is_symlink_or_junction(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let len = meta.len();
                match lpm_common::file_link_identity_and_count(&path, &meta) {
                    Some((_, nlink)) if nlink <= 1 => {
                        total = total.saturating_add(len);
                    }
                    Some((identity, nlink)) => {
                        let count = seen_links.entry(identity).or_insert(0);
                        *count = count.saturating_add(1);
                        if *count == nlink {
                            total = total.saturating_add(len);
                        }
                    }
                    None => {
                        total = total.saturating_add(len);
                    }
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::create_test_tarball;

    #[test]
    fn list_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        store.store_package("alpha", "1.0.0", &tarball).unwrap();
        store.store_package("beta", "2.0.0", &tarball).unwrap();

        let list = store.list_packages().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], ("alpha".to_string(), "1.0.0".to_string()));
        assert_eq!(list[1], ("beta".to_string(), "2.0.0".to_string()));
    }

    #[test]
    fn list_packages_ignores_temp_and_incomplete_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        store.store_package("valid", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let stale_tmp = store_v1.join("valid@1.0.0.tmp.stale");
        std::fs::create_dir_all(&stale_tmp).unwrap();
        std::fs::write(stale_tmp.join("package.json"), b"{}").unwrap();
        std::fs::write(stale_tmp.join(".integrity"), b"sha512-stale").unwrap();

        let incomplete = store_v1.join("broken@1.0.0");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("package.json"), b"{}").unwrap();

        let list = store.list_packages().unwrap();

        assert_eq!(list, vec![("valid".to_string(), "1.0.0".to_string())]);
    }
    #[test]
    fn gc_removes_unreferenced_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();
        store.store_package("remove", "1.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("keep@1.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 1);
        assert_eq!(result.kept, 1);
        assert!(result.freed_bytes > 0);
        assert!(store.has_package("keep", "1.0.0"));
        assert!(!store.has_package("remove", "1.0.0"));
    }

    #[test]
    fn gc_keeps_all_referenced_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("a", "1.0.0", &tarball).unwrap();
        store.store_package("b", "2.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("a@1.0.0".to_string());
        referenced.insert("b@2.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(result.kept, 2);
        assert_eq!(result.freed_bytes, 0);
    }

    #[test]
    fn gc_empty_store_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let referenced = std::collections::HashSet::new();
        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(result.kept, 0);
    }

    #[test]
    fn gc_preview_matches_actual_removal() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"pkg\"}"),
            ("index.js", b"module.exports = 1"),
        ]);
        store.store_package("pkg", "1.0.0", &tarball).unwrap();
        store.store_package("pkg", "2.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("pkg@2.0.0".to_string());

        let preview = store.gc_preview(&referenced, None).unwrap();
        assert_eq!(preview.would_remove.len(), 1);
        assert_eq!(preview.would_keep, 1);
        assert!(preview.would_free_bytes > 0);

        // Now actually GC and verify counts match
        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, preview.would_remove.len());
        assert_eq!(result.kept, preview.would_keep);
        assert_eq!(result.freed_bytes, preview.would_free_bytes);
    }

    #[test]
    fn gc_respects_max_age_keeps_recent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("recent", "1.0.0", &tarball).unwrap();

        // Package was just created — mtime is now. With a 30-day threshold,
        // it should be kept even though it's unreferenced.
        let referenced = std::collections::HashSet::new();
        let max_age = std::time::Duration::from_secs(30 * 86400);

        let result = store.gc(&referenced, Some(&max_age)).unwrap();
        assert_eq!(result.removed, 0, "recently created package should be kept");
        assert_eq!(result.kept, 1);
        assert!(store.has_package("recent", "1.0.0"));
    }

    #[test]
    fn gc_scoped_package_name_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store
            .store_package("@scope/pkg", "1.0.0", &tarball)
            .unwrap();

        // Reference with the original scoped name (not the filesystem-safe name)
        let mut referenced = std::collections::HashSet::new();
        referenced.insert("@scope/pkg@1.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(
            result.removed, 0,
            "scoped package should match by original name"
        );
        assert_eq!(result.kept, 1);
    }

    #[test]
    fn gc_preview_doesnt_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("doomed", "1.0.0", &tarball).unwrap();

        let referenced = std::collections::HashSet::new();
        let preview = store.gc_preview(&referenced, None).unwrap();

        assert_eq!(preview.would_remove.len(), 1);
        // But the package should still be there
        assert!(
            store.has_package("doomed", "1.0.0"),
            "preview should not delete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_preview_does_not_count_external_symlink_target_bytes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let package_dir = store.package_dir("linked", "1.0.0");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            br#"{"name":"linked","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_dir.join(".integrity"), b"sha512-linked").unwrap();

        let external_file = dir.path().join("outside.bin");
        let external_size = 32 * 1024;
        std::fs::write(&external_file, vec![b'x'; external_size]).unwrap();
        symlink(&external_file, package_dir.join("external-link")).unwrap();

        let referenced = std::collections::HashSet::new();
        let preview = store.gc_preview(&referenced, None).unwrap();

        assert_eq!(preview.would_remove.len(), 1);
        assert_eq!(preview.would_remove[0].0, "linked@1.0.0");
        assert!(
            preview.would_free_bytes < external_size as u64,
            "gc preview should not count bytes from symlink targets outside the store"
        );
    }

    #[test]
    fn gc_skips_junk_in_preview_and_removes_it_during_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let stale_tmp = store_v1.join("keep@1.0.0.tmp.stale");
        std::fs::create_dir_all(&stale_tmp).unwrap();
        std::fs::write(stale_tmp.join("package.json"), b"{}").unwrap();
        std::fs::write(stale_tmp.join(".integrity"), b"sha512-stale").unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        let old_times = std::fs::FileTimes::new().set_modified(old);
        std::fs::set_times(stale_tmp.join("package.json"), old_times).unwrap();
        std::fs::set_times(stale_tmp.join(".integrity"), old_times).unwrap();
        std::fs::set_times(&stale_tmp, old_times).unwrap();

        let incomplete = store_v1.join("broken@1.0.0");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("package.json"), b"{}").unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("keep@1.0.0".to_string());

        let preview = store.gc_preview(&referenced, None).unwrap();
        assert!(
            preview.would_remove.is_empty(),
            "junk dirs should not appear as removable packages"
        );
        assert_eq!(
            preview.would_keep, 1,
            "only complete referenced packages should count as kept"
        );

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(
            result.removed, 0,
            "junk cleanup should not be counted as package removal"
        );
        assert_eq!(
            result.kept, 1,
            "only complete referenced packages should count as kept"
        );
        assert!(store.has_package("keep", "1.0.0"));
        assert!(
            !stale_tmp.exists(),
            "gc should clean stale temp directories"
        );
        assert!(
            !incomplete.exists(),
            "gc should clean incomplete directories"
        );
    }

    #[test]
    fn gc_preserves_fresh_temp_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let active_tmp = store_v1.join("active@1.0.0.tmp.12345.ThreadId(1)");
        std::fs::create_dir_all(&active_tmp).unwrap();
        std::fs::write(active_tmp.join("package.json"), b"{}").unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("keep@1.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(result.kept, 1);
        assert!(
            active_tmp.exists(),
            "gc must not delete freshly created active temp directories"
        );
    }

    #[test]
    fn gc_waits_for_publication_lock_before_removing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("doomed", "1.0.0", &tarball).unwrap();

        let publication = store.lock_publication().unwrap();
        let store_clone = store.clone();
        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_clone = std::sync::Arc::clone(&started);
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished_clone = std::sync::Arc::clone(&finished);

        let handle = std::thread::spawn(move || {
            started_clone.store(true, Ordering::Release);
            let result = store_clone.gc(&HashSet::new(), None).unwrap();
            finished_clone.store(true, Ordering::Release);
            result
        });

        while !started.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !finished.load(Ordering::Acquire),
            "gc must block until the v1 publication lock is released"
        );
        assert!(
            store.has_package("doomed", "1.0.0"),
            "doomed package must stay intact while publication lock is held"
        );

        drop(publication);
        let result = handle.join().unwrap();
        assert_eq!(result.removed, 1);
        assert!(!store.has_package("doomed", "1.0.0"));
    }

    #[test]
    fn gc_keeps_package_with_mtime_newer_than_cutoff_check() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let pkg_dir = store
            .store_package("future-pkg", "1.0.0", &tarball)
            .unwrap();
        let future = SystemTime::now() + Duration::from_secs(60);
        std::fs::set_times(&pkg_dir, std::fs::FileTimes::new().set_modified(future)).unwrap();

        let max_age = Duration::from_secs(3600);
        let preview = store.gc_preview(&HashSet::new(), Some(&max_age)).unwrap();
        assert_eq!(preview.would_keep, 1);
        assert!(
            preview.would_remove.is_empty(),
            "gc preview must keep packages newer than now"
        );
        let result = store.gc(&HashSet::new(), Some(&max_age)).unwrap();
        assert_eq!(
            result.removed, 0,
            "package newer than now must not be removed"
        );
        assert_eq!(result.kept, 1);
        assert!(store.has_package("future-pkg", "1.0.0"));
    }

    #[test]
    fn gc_preview_and_apply_agree_on_cross_package_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let pkg_a = store.package_dir("pkg-a", "1.0.0");
        let pkg_b = store.package_dir("pkg-b", "1.0.0");
        for pkg in [&pkg_a, &pkg_b] {
            std::fs::create_dir_all(pkg).unwrap();
            std::fs::write(pkg.join("package.json"), b"{}").unwrap();
            std::fs::write(pkg.join(".integrity"), b"sha512-x").unwrap();
        }
        std::fs::write(pkg_a.join("shared.js"), vec![b's'; 64]).unwrap();
        std::fs::hard_link(pkg_a.join("shared.js"), pkg_b.join("shared.js")).unwrap();

        let preview = store.gc_preview(&HashSet::new(), None).unwrap();
        let result = store.gc(&HashSet::new(), None).unwrap();
        assert_eq!(preview.would_remove.len(), 2);
        assert_eq!(result.removed, 2);
        assert_eq!(
            preview.would_free_bytes, result.freed_bytes,
            "hardlink shared strictly between two doomed packages must be counted once"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_retires_entry_at_filesystem_name_limit_without_enametoolong() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        // 249 + "@1.0.0" (6) == 255 bytes (POSIX NAME_MAX).
        let long_name = "a".repeat(249);
        let create_complete_entry = |version: &str| {
            let pkg_dir = store.package_dir(&long_name, version);
            std::fs::create_dir_all(&pkg_dir).unwrap();
            std::fs::write(pkg_dir.join("package.json"), b"{}").unwrap();
            std::fs::write(pkg_dir.join(".integrity"), b"sha512-x").unwrap();
        };

        create_complete_entry("1.0.0");
        let result = store.gc(&HashSet::new(), None).unwrap();
        assert_eq!(result.removed, 1);
        assert!(!store.has_package(&long_name, "1.0.0"));

        create_complete_entry("2.0.0");
        assert!(store.remove_package(&long_name, "2.0.0").unwrap());
        assert!(!store.has_package(&long_name, "2.0.0"));
    }

    #[test]
    fn next_retired_path_uses_bounded_unique_basename_under_parent() {
        let parent = Path::new("/tmp/store/v1");
        let first = next_retired_path(parent);
        let second = next_retired_path(parent);
        assert_eq!(first.parent(), Some(parent));
        assert_ne!(first, second);
        let first_name = first.file_name().unwrap().to_string_lossy();
        assert!(is_temp_store_dir_name(&first_name));
        assert!(
            first_name.len() <= 64,
            "retired basename must stay bounded, got {first_name} ({} bytes)",
            first_name.len()
        );
    }

    #[test]
    fn gc_preserves_staging_dir_with_old_root_mtime_but_recent_nested_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let active_tmp = store_v1.join("slow@1.0.0.tmp.12345.ThreadId(1)");
        let nested = active_tmp.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        std::fs::set_times(&active_tmp, std::fs::FileTimes::new().set_modified(old)).unwrap();
        std::fs::write(nested.join("fresh.js"), b"active").unwrap();

        let mut referenced = HashSet::new();
        referenced.insert("keep@1.0.0".to_string());
        let _ = store.gc(&referenced, None).unwrap();
        assert!(
            active_tmp.exists(),
            "staging dir with recent nested file writes must not be treated as abandoned"
        );
    }

    #[test]
    fn gc_preview_and_apply_agree_on_freed_bytes_for_internal_and_external_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let pkg_dir = store.package_dir("hardlinked", "1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("package.json"), b"{}").unwrap();
        std::fs::write(pkg_dir.join(".integrity"), b"sha512-x").unwrap();
        std::fs::write(pkg_dir.join("unique.js"), b"0123456789").unwrap();
        std::fs::write(pkg_dir.join("internal-a.js"), b"01234567890123456789").unwrap();
        std::fs::hard_link(pkg_dir.join("internal-a.js"), pkg_dir.join("internal-b.js")).unwrap();
        let external = dir.path().join("external.js");
        std::fs::write(&external, vec![b'z'; 40]).unwrap();
        std::fs::hard_link(&external, pkg_dir.join("shared-outside.js")).unwrap();

        let preview = store.gc_preview(&HashSet::new(), None).unwrap();
        let result = store.gc(&HashSet::new(), None).unwrap();
        assert_eq!(
            preview.would_free_bytes, result.freed_bytes,
            "gc preview and gc apply must agree on hardlink-reclaimed bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_retire_does_not_follow_symlink_entry_for_mtime_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("external-target");
        std::fs::create_dir(&external).unwrap();
        let old = SystemTime::now() - Duration::from_secs(7200);
        std::fs::set_times(&external, std::fs::FileTimes::new().set_modified(old)).unwrap();
        let before_mtime = std::fs::metadata(&external).unwrap().modified().unwrap();

        let store_v1 = dir.path().join("v1");
        std::fs::create_dir_all(&store_v1).unwrap();
        let link_entry = store_v1.join("sneaky@1.0.0");
        std::os::unix::fs::symlink(&external, &link_entry).unwrap();

        let retired = retire_store_entry(&link_entry, SystemTime::now())
            .unwrap()
            .expect("symlink entry should retire");
        assert!(std::fs::symlink_metadata(&retired).unwrap().is_symlink());
        let after_mtime = std::fs::metadata(&external).unwrap().modified().unwrap();
        assert_eq!(
            after_mtime, before_mtime,
            "retiring a symlink entry must never follow it to modify the external target's mtime"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_retirement_protects_entry_from_concurrent_sweep_when_scan_exceeds_threshold_or_set_times_fails()
     {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let store_v1 = dir.path().join("v1");
        std::fs::create_dir_all(&store_v1).unwrap();
        let old_pkg = store_v1.join("ancient@1.0.0");
        std::fs::create_dir(&old_pkg).unwrap();
        std::fs::write(old_pkg.join("index.js"), b"old").unwrap();
        let very_old = SystemTime::now() - Duration::from_secs(3600);
        std::fs::set_times(&old_pkg, std::fs::FileTimes::new().set_modified(very_old)).unwrap();

        // Case 1: passing a stale pre-scan timestamp older than ABANDONED_TEMP_AGE must
        // not leave the freshly retired entry immediately eligible for a concurrent sweep.
        let stale_scan_start = SystemTime::now() - (ABANDONED_TEMP_AGE + Duration::from_secs(120));
        let retired = retire_store_entry(&old_pkg, stale_scan_start)
            .unwrap()
            .expect("old package should retire");
        let retired_name = retired.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !is_junk_store_dir(&retired, &retired_name, SystemTime::now()),
            "freshly retired tombstone must not appear abandoned when scan start was older than ABANDONED_TEMP_AGE"
        );
        let _ = std::fs::remove_dir_all(&retired);

        // Case 2: even when the retired directory itself cannot have its mtime updated,
        // a concurrent collector must still see it as actively retired rather than abandoned.
        let ro_pkg = store_v1.join("readonly-ancient@1.0.0");
        std::fs::create_dir(&ro_pkg).unwrap();
        std::fs::set_times(&ro_pkg, std::fs::FileTimes::new().set_modified(very_old)).unwrap();
        std::fs::set_permissions(&ro_pkg, std::fs::Permissions::from_mode(0o555)).unwrap();
        let retired_ro = retire_store_entry(&ro_pkg, stale_scan_start)
            .unwrap()
            .expect("readonly package should retire");
        let retired_ro_name = retired_ro
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // Force the directory mtime back to very_old to simulate set_times failure on unowned dirs.
        let _ = std::fs::set_permissions(&retired_ro, std::fs::Permissions::from_mode(0o755));
        std::fs::set_times(
            &retired_ro,
            std::fs::FileTimes::new().set_modified(very_old),
        )
        .unwrap();
        assert!(
            !is_junk_store_dir(&retired_ro, &retired_ro_name, SystemTime::now()),
            "freshly retired tombstone must be protected by its active lease even if set_times failed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_does_not_retire_temp_dir_that_resumed_nested_writes_after_prescan() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let store_v1 = dir.path().join("v1");
        let tmp_dir = store_v1.join(".tmp.resumed-staging");
        let nested_dir = tmp_dir.join("lib");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let nested_file = nested_dir.join("index.js");
        std::fs::write(&nested_file, b"initial").unwrap();
        let very_old = SystemTime::now() - Duration::from_secs(3600);
        for p in [&nested_file, &nested_dir, &tmp_dir] {
            std::fs::set_times(p, std::fs::FileTimes::new().set_modified(very_old)).unwrap();
        }

        let file_to_touch = nested_file.clone();
        let _guard = GcAfterPrescanHookGuard::install(move || {
            // Writing an existing nested file bumps its mtime without touching tmp_dir's mtime.
            std::fs::write(&file_to_touch, b"resumed-write").unwrap();
        });

        let result = store.gc(&HashSet::new(), None).unwrap();
        assert_eq!(
            result.removed, 0,
            "temp dir that resumed nested writes after prescan must not be retired"
        );
        assert!(
            tmp_dir.is_dir() && nested_file.is_file(),
            "resumed staging temp directory must remain intact"
        );
    }
}

#[cfg(all(test, unix))]
type GcAfterPrescanHookFn = Box<dyn FnMut()>;

#[cfg(all(test, unix))]
thread_local! {
    static GC_AFTER_PRESCAN_HOOK: std::cell::RefCell<Option<GcAfterPrescanHookFn>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
struct GcAfterPrescanHookGuard;

#[cfg(all(test, unix))]
impl GcAfterPrescanHookGuard {
    fn install(hook: impl FnMut() + 'static) -> Self {
        GC_AFTER_PRESCAN_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        Self
    }
}

#[cfg(all(test, unix))]
impl Drop for GcAfterPrescanHookGuard {
    fn drop(&mut self) {
        GC_AFTER_PRESCAN_HOOK.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[cfg(all(test, unix))]
fn run_gc_after_prescan_hook() {
    GC_AFTER_PRESCAN_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook();
        }
    });
}
