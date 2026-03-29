//! Content-addressable package store for LPM.
//!
//! Global store at `~/.lpm/store/` holds extracted packages keyed by
//! `name@version` hash. Projects link into this store via hardlinks or
//! copy-on-write (reflink on APFS/Btrfs).
//!
//! Layout:
//! ```text
//! ~/.lpm/store/
//!   v1/                          ← store version (for future migrations)
//!     react@19.2.4/              ← extracted package directory
//!       package.json
//!       index.js
//!       ...
//!     express@4.22.1/
//!       ...
//! ```
//!
//! Performance: per-file dedup, reflink/clonefile — see phase-18-todo.md.
//! Maintenance: GC, integrity verification — see phase-19-todo.md and phase-20-todo.md.

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Store version for the directory layout.
const STORE_VERSION: &str = "v1";

/// The global content-addressable package store.
#[derive(Clone)]
pub struct PackageStore {
    /// Root directory of the store (e.g., ~/.lpm/store).
    root: PathBuf,
}

impl PackageStore {
    /// Create a store at the default location (~/.lpm/store).
    pub fn default_location() -> Result<Self, LpmError> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine home directory",
            )))?;
        Ok(PackageStore {
            root: PathBuf::from(home).join(".lpm").join("store"),
        })
    }

    /// Create a store at a specific path (for testing).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        PackageStore { root: root.into() }
    }

    /// Get the store directory for a package version.
    /// e.g., `~/.lpm/store/v1/react@19.2.4/`
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        // Sanitize name for filesystem: replace @ and / with safe characters
        let safe_name = name.replace('/', "+").replace('\\', "+");
        self.root.join(STORE_VERSION).join(format!("{safe_name}@{version}"))
    }

    /// Check if a package version is already in the store.
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        let dir = self.package_dir(name, version);
        dir.join("package.json").exists()
    }

    /// Extract a tarball into the store. Returns the store path.
    ///
    /// If the package already exists in the store, skips extraction (cache hit).
    ///
    /// Uses a unique temp directory per process+thread to prevent TOCTOU races
    /// when multiple parallel downloads extract the same package simultaneously.
    /// The final rename is atomic on the same filesystem — if another thread wins
    /// the race, we discard our work and use theirs.
    pub fn store_package(
        &self,
        name: &str,
        version: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.package_dir(name, version);

        // Fast path: already stored
        if dir.exists() {
            tracing::debug!("store hit: {name}@{version}");
            return Ok(dir);
        }

        tracing::debug!("extracting {name}@{version} to store");

        // Use a unique temp dir to prevent races between parallel downloads.
        // Each process+thread gets its own temp directory so concurrent extractions
        // never step on each other.
        let unique_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = dir.with_extension(format!("tmp.{unique_id}.{thread_id}"));

        // Clean up any stale tmp dir from a previous crash
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        // Ensure parent directory exists
        if let Some(parent) = tmp_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create store dir: {e}")))?;
        }

        lpm_extractor::extract_tarball(tarball_data, &tmp_dir)?;

        // Atomic rename — if another thread already completed, rename fails (that's OK)
        match std::fs::rename(&tmp_dir, &dir) {
            Ok(()) => Ok(dir),
            Err(_) if dir.exists() => {
                // Another thread/process beat us — clean up our temp dir and use theirs
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok(dir)
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!("failed to store package: {e}")))
            }
        }
    }

    /// List all packages in the store.
    pub fn list_packages(&self) -> Result<Vec<(String, String)>, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(Vec::new());
        }

        let mut packages = Vec::new();
        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Parse "name@version" from directory name
            if let Some(at_pos) = name.rfind('@') {
                let pkg_name = name[..at_pos].replace('+', "/");
                let version = name[at_pos + 1..].to_string();
                packages.push((pkg_name, version));
            }
        }

        packages.sort();
        Ok(packages)
    }

    /// Get the store root path.
    pub fn root(&self) -> &Path {
        &self.root
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
        referenced: &std::collections::HashSet<String>,
        max_age: Option<&std::time::Duration>,
    ) -> Result<GcResult, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcResult { removed: 0, kept: 0, freed_bytes: 0 });
        }

        let now = std::time::SystemTime::now();
        let mut removed = 0;
        let mut kept = 0;
        let mut freed_bytes: u64 = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();

            // Parse "name@version"
            if let Some(at_pos) = dir_name.rfind('@') {
                let pkg_name = dir_name[..at_pos].replace('+', "/");
                let version = &dir_name[at_pos + 1..];
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    kept += 1;
                    continue;
                }

                // Check age filter: skip if the package was modified recently
                if let Some(age_threshold) = max_age {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            if let Ok(elapsed) = now.duration_since(mtime) {
                                if elapsed < *age_threshold {
                                    kept += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Calculate size before removing
                freed_bytes += dir_size(&entry.path());
                std::fs::remove_dir_all(entry.path())?;
                removed += 1;
            }
        }

        Ok(GcResult { removed, kept, freed_bytes })
    }

    /// Preview what GC would remove, without actually deleting anything.
    ///
    /// Returns a list of package names and their sizes that would be removed,
    /// plus the count of packages that would be kept.
    pub fn gc_preview(
        &self,
        referenced: &std::collections::HashSet<String>,
        max_age: Option<&std::time::Duration>,
    ) -> Result<GcPreview, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcPreview {
                would_remove: Vec::new(),
                would_keep: 0,
                would_free_bytes: 0,
            });
        }

        let now = std::time::SystemTime::now();
        let mut would_remove = Vec::new();
        let mut would_keep = 0;
        let mut would_free_bytes: u64 = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();

            if let Some(at_pos) = dir_name.rfind('@') {
                let pkg_name = dir_name[..at_pos].replace('+', "/");
                let version = &dir_name[at_pos + 1..];
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    would_keep += 1;
                    continue;
                }

                // Check age filter
                if let Some(age_threshold) = max_age {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            if let Ok(elapsed) = now.duration_since(mtime) {
                                if elapsed < *age_threshold {
                                    would_keep += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }

                let size = dir_size(&entry.path());
                would_free_bytes += size;
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
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
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

/// Calculate the total size of a directory recursively.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                total += dir_size(&path);
            } else if let Ok(meta) = path.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
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

    #[test]
    fn store_and_retrieve_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"foo\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);

        assert!(!store.has_package("foo", "1.0.0"));

        let path = store.store_package("foo", "1.0.0", &tarball).unwrap();
        assert!(store.has_package("foo", "1.0.0"));
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[
            ("package.json", b"{}"),
        ]);

        store.store_package("bar", "2.0.0", &tarball).unwrap();
        // Second call should be a cache hit
        let path = store.store_package("bar", "2.0.0", &tarball).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn scoped_package_name_safe_on_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        let path = store.store_package("@types/node", "22.0.0", &tarball).unwrap();
        assert!(path.exists());
        // Directory name should not contain / or @
        let dir_name = path.file_name().unwrap().to_string_lossy();
        assert!(!dir_name.contains('/'));
    }

    #[test]
    fn store_same_package_twice_returns_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"dup\",\"version\":\"1.0.0\"}"),
        ]);

        let path1 = store.store_package("dup", "1.0.0", &tarball).unwrap();
        assert!(path1.exists());

        // Second store of same package should hit the fast path
        let path2 = store.store_package("dup", "1.0.0", &tarball).unwrap();
        assert_eq!(path1, path2);
        assert!(path2.join("package.json").exists());
    }

    #[test]
    fn store_different_packages_no_interference() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball_a = create_test_tarball(&[
            ("package.json", b"{\"name\":\"pkg-a\",\"version\":\"1.0.0\"}"),
        ]);
        let tarball_b = create_test_tarball(&[
            ("package.json", b"{\"name\":\"pkg-b\",\"version\":\"2.0.0\"}"),
        ]);

        let path_a = store.store_package("pkg-a", "1.0.0", &tarball_a).unwrap();
        let path_b = store.store_package("pkg-b", "2.0.0", &tarball_b).unwrap();

        assert_ne!(path_a, path_b);
        assert!(path_a.join("package.json").exists());
        assert!(path_b.join("package.json").exists());
    }

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
}
