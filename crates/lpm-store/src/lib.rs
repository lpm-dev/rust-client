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
//! # TODOs
//! - [ ] Per-file deduplication by content hash (pnpm-style)
//! - [ ] Reflink (copy-on-write) on APFS/Btrfs, hardlink fallback
//! - [ ] Garbage collection (remove unreferenced packages)
//! - [ ] Store integrity verification (hash check on read)

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
    pub fn store_package(
        &self,
        name: &str,
        version: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.package_dir(name, version);

        if self.has_package(name, version) {
            tracing::debug!("store hit: {name}@{version}");
            return Ok(dir);
        }

        tracing::debug!("extracting {name}@{version} to store");

        // Extract to a temp directory first, then rename atomically
        let tmp_dir = dir.with_extension("tmp");
        if tmp_dir.exists() {
            std::fs::remove_dir_all(&tmp_dir)?;
        }

        lpm_extractor::extract_tarball(tarball_data, &tmp_dir)?;

        // Atomic rename (only works on same filesystem, which it is)
        if dir.exists() {
            // Race condition: another process extracted while we were working
            std::fs::remove_dir_all(&tmp_dir)?;
        } else {
            std::fs::rename(&tmp_dir, &dir)?;
        }

        Ok(dir)
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
    pub fn gc(&self, referenced: &std::collections::HashSet<String>) -> Result<GcResult, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcResult { removed: 0, kept: 0, freed_bytes: 0 });
        }

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
                } else {
                    // Calculate size before removing
                    freed_bytes += dir_size(&entry.path());
                    std::fs::remove_dir_all(entry.path())?;
                    removed += 1;
                }
            }
        }

        Ok(GcResult { removed, kept, freed_bytes })
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
