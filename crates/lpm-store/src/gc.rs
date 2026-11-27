use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use lpm_common::LpmError;

use crate::{PackageStore, STORE_VERSION, is_complete_package_dir};

/// Minimum age before a `.tmp.` staging directory in `store/v1/` is treated as
/// abandoned by a crashed extraction rather than an active concurrent write.
const ABANDONED_TEMP_AGE: Duration = Duration::from_secs(10 * 60);

static GC_RETIRE_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_retired_path(dir: &Path) -> PathBuf {
    let seq = GC_RETIRE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = dir.as_os_str().to_owned();
    name.push(format!(".tmp.gc.{}.{seq}", std::process::id()));
    PathBuf::from(name)
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

        let now = SystemTime::now();
        let mut kept = 0usize;
        let mut retired_packages: Vec<PathBuf> = Vec::new();
        let mut retired_junk: Vec<PathBuf> = Vec::new();

        // Hold the v1 publication lock only while scanning and atomically retiring
        // doomed entries; unlink the retired subtrees outside the lock so slow
        // filesystem deletion does not stall concurrent package publications.
        let retire_result: Result<(), LpmError> = (|| {
            let _publication = self.lock_publication()?;
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
                        && let Ok(elapsed) = now.duration_since(mtime)
                        && elapsed < *age_threshold
                    {
                        kept += 1;
                        continue;
                    }

                    let retired = next_retired_path(&path);
                    match std::fs::rename(&path, &retired) {
                        Ok(()) => retired_packages.push(retired),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                    continue;
                }

                if is_junk_store_dir(&path, &dir_name, now) {
                    let retired = next_retired_path(&path);
                    match std::fs::rename(&path, &retired) {
                        Ok(()) => retired_junk.push(retired),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            Ok(())
        })();

        if let Err(err) = retire_result {
            for path in retired_packages.iter().chain(retired_junk.iter()) {
                let _ = lpm_common::remove_path_entry(path);
            }
            return Err(err);
        }

        let mut removed = 0usize;
        let mut freed_bytes: u64 = 0;
        for retired in retired_packages {
            let freed = lpm_common::remove_path_entry_counting_freed_bytes(&retired)?;
            freed_bytes = freed_bytes.saturating_add(freed);
            removed += 1;
        }
        for retired in retired_junk {
            lpm_common::remove_path_entry(&retired)?;
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
        let mut would_remove = Vec::new();
        let mut would_keep = 0;
        let mut would_free_bytes: u64 = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();

            if let Some((pkg_name, version)) = complete_package_from_dir(&entry.path(), &dir_name) {
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    would_keep += 1;
                    continue;
                }

                // Check age filter
                if let Some(age_threshold) = max_age
                    && let Ok(meta) = entry.metadata()
                    && let Ok(mtime) = meta.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                    && elapsed < *age_threshold
                {
                    would_keep += 1;
                    continue;
                }

                let size = dir_size(&entry.path());
                would_free_bytes = would_free_bytes.saturating_add(size);
                would_remove.push((key, size));
            }
        }

        would_remove.sort_by(|a, b| a.0.cmp(&b.0));

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
            let retired = next_retired_path(&dir);
            match std::fs::rename(&dir, &retired) {
                Ok(()) => retired,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(err) => return Err(err.into()),
            }
        };
        lpm_common::remove_path_entry(&retired)?;
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

fn is_junk_store_dir(dir: &Path, dir_name: &str, now: SystemTime) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !meta.is_dir() || lpm_common::is_symlink_or_junction(&meta) {
        return false;
    }
    if is_temp_store_dir_name(dir_name) {
        return meta
            .modified()
            .ok()
            .and_then(|mtime| now.duration_since(mtime).ok())
            .is_some_and(|age| age >= ABANDONED_TEMP_AGE);
    }
    dir_name.rfind('@').is_some() && !is_complete_package_dir(dir)
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

/// Calculate the total regular-file size of a directory iteratively so deep
/// trees keep a single `ReadDir` handle open at a time and never follow links.
fn dir_size(root: &Path) -> u64 {
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
                total = total.saturating_add(meta.len());
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
        std::fs::set_times(&stale_tmp, std::fs::FileTimes::new().set_modified(old)).unwrap();

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
}
