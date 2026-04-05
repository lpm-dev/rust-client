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
//! Performance: package-level dedup (skip extraction on store hit), clonefile/reflink on macOS.
//! Maintenance: GC with age filtering, integrity verification (SRI hashes).

use lpm_common::LpmError;
use sha2::{Digest, Sha512};
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
            .map_err(|_| {
                LpmError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "could not determine home directory",
                ))
            })?;
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
        let safe_name = name.replace(['/', '\\'], "+");
        self.root
            .join(STORE_VERSION)
            .join(format!("{safe_name}@{version}"))
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

        // Write SRI integrity hash of the original tarball for later verification.
        // This allows `store verify --deep` to detect post-extraction tampering.
        let sri = compute_sri_hash(tarball_data);
        std::fs::write(tmp_dir.join(".integrity"), &sri)
            .map_err(|e| LpmError::Store(format!("failed to write .integrity: {e}")))?;

        // Run behavioral security analysis and write .lpm-security.json.
        // Done BEFORE the atomic rename so the analysis result is included
        // atomically — when the package dir becomes visible, the security
        // cache is already present. Analysis failure is non-fatal (warn only).
        let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
        if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
            tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
        } else {
            tracing::debug!(
                "security analysis: {name}@{version} — {} files scanned, {} bytes",
                analysis.meta.files_scanned,
                analysis.meta.bytes_scanned
            );
        }

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

    /// Extract a tarball from a file into the store. Returns the store path.
    ///
    /// Bounded-memory variant of `store_package()` — reads the tarball from disk
    /// in chunks rather than requiring it in memory. The SRI hash is provided by
    /// the caller (computed during download).
    ///
    /// Same atomicity guarantees as `store_package()`: unique temp dir per
    /// process+thread, atomic rename into final location.
    pub fn store_package_from_file(
        &self,
        name: &str,
        version: &str,
        tarball_path: &std::path::Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        let dir = self.package_dir(name, version);

        // Fast path: already stored
        if dir.exists() {
            tracing::debug!("store hit: {name}@{version}");
            return Ok(dir);
        }

        tracing::debug!("extracting {name}@{version} to store (from file)");

        let unique_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = dir.with_extension(format!("tmp.{unique_id}.{thread_id}"));

        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        if let Some(parent) = tmp_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create store dir: {e}")))?;
        }

        // Extract from file — bounded memory, no full tarball in heap
        lpm_extractor::extract_tarball_from_file(tarball_path, &tmp_dir)?;

        // Write pre-computed SRI hash (no second pass needed)
        std::fs::write(tmp_dir.join(".integrity"), sri)
            .map_err(|e| LpmError::Store(format!("failed to write .integrity: {e}")))?;

        // Security analysis (same as store_package)
        let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
        if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
            tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
        } else {
            tracing::debug!(
                "security analysis: {name}@{version} — {} files scanned, {} bytes",
                analysis.meta.files_scanned,
                analysis.meta.bytes_scanned
            );
        }

        // Atomic rename
        match std::fs::rename(&tmp_dir, &dir) {
            Ok(()) => Ok(dir),
            Err(_) if dir.exists() => {
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
            return Ok(GcResult {
                removed: 0,
                kept: 0,
                freed_bytes: 0,
            });
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
                if let Some(age_threshold) = max_age
                    && let Ok(meta) = entry.metadata()
                    && let Ok(mtime) = meta.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                    && elapsed < *age_threshold
                {
                    kept += 1;
                    continue;
                }

                // Calculate size before removing
                freed_bytes += dir_size(&entry.path());
                std::fs::remove_dir_all(entry.path())?;
                removed += 1;
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

/// Compute an SRI (Subresource Integrity) hash for tarball data.
/// Format: `sha512-<base64>` (matches npm's integrity field format).
pub fn compute_sri_hash(data: &[u8]) -> String {
    use base64::Engine;
    let hash = Sha512::digest(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha512-{b64}")
}

/// Read the stored `.integrity` file for a package.
/// Returns `None` if the file doesn't exist (package stored before integrity tracking).
pub fn read_stored_integrity(store_dir: &Path) -> Option<String> {
    let integrity_path = store_dir.join(".integrity");
    std::fs::read_to_string(integrity_path).ok()
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

        let tarball = create_test_tarball(&[("package.json", b"{}")]);

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

        let path = store
            .store_package("@types/node", "22.0.0", &tarball)
            .unwrap();
        assert!(path.exists());
        // Directory name should not contain / or @
        let dir_name = path.file_name().unwrap().to_string_lossy();
        assert!(!dir_name.contains('/'));
    }

    #[test]
    fn store_same_package_twice_returns_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball =
            create_test_tarball(&[("package.json", b"{\"name\":\"dup\",\"version\":\"1.0.0\"}")]);

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

        let tarball_a = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"pkg-a\",\"version\":\"1.0.0\"}",
        )]);
        let tarball_b = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"pkg-b\",\"version\":\"2.0.0\"}",
        )]);

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

    #[test]
    fn store_writes_integrity_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"integ\",\"version\":\"1.0.0\"}",
        )]);

        let path = store.store_package("integ", "1.0.0", &tarball).unwrap();

        // .integrity file should exist
        let integrity_path = path.join(".integrity");
        assert!(integrity_path.exists(), ".integrity file must be written");

        let stored = std::fs::read_to_string(&integrity_path).unwrap();
        assert!(
            stored.starts_with("sha512-"),
            "integrity must be SRI format"
        );

        // Verify it matches a fresh computation
        let expected = compute_sri_hash(&tarball);
        assert_eq!(stored, expected);
    }

    #[test]
    fn read_stored_integrity_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_stored_integrity(dir.path()).is_none());
    }

    #[test]
    fn store_writes_security_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"sec-test\",\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            ),
            ("index.js", b"const fs = require('fs'); eval('code')"),
        ]);

        let path = store.store_package("sec-test", "1.0.0", &tarball).unwrap();

        // .lpm-security.json should exist
        let security_path = path.join(".lpm-security.json");
        assert!(
            security_path.exists(),
            ".lpm-security.json must be written during extraction"
        );

        // Parse and verify contents
        let content = std::fs::read_to_string(&security_path).unwrap();
        let analysis: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            analysis["version"],
            lpm_security::behavioral::SCHEMA_VERSION
        );
        assert_eq!(analysis["source"]["filesystem"], true);
        assert_eq!(analysis["source"]["eval"], true);
        assert_eq!(analysis["source"]["network"], false);
        assert_eq!(analysis["manifest"]["copyleftLicense"], false);
        assert_eq!(analysis["manifest"]["noLicense"], false);
    }

    #[test]
    fn store_security_analysis_detects_gpl() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"gpl-pkg\",\"version\":\"1.0.0\",\"license\":\"GPL-3.0\"}",
            ),
            ("index.js", b"module.exports = 42"),
        ]);

        let path = store.store_package("gpl-pkg", "1.0.0", &tarball).unwrap();
        let content = std::fs::read_to_string(path.join(".lpm-security.json")).unwrap();
        let analysis: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(analysis["manifest"]["copyleftLicense"], true);
    }

    #[test]
    fn store_cache_hit_preserves_security_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"cached\",\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            ),
            ("index.js", b"eval('test')"),
        ]);

        // First store — writes analysis
        let path1 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path1.join(".lpm-security.json").exists());

        // Second store — cache hit, should still have the file
        let path2 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path2.join(".lpm-security.json").exists());

        // Verify analysis is readable via the public API
        let analysis = lpm_security::behavioral::read_cached_analysis(&path2);
        assert!(analysis.is_some(), "cached analysis should be readable");
        assert!(analysis.unwrap().source.eval);
    }

    #[test]
    fn integrity_mismatch_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"tamper\",\"version\":\"1.0.0\"}",
        )]);

        let path = store.store_package("tamper", "1.0.0", &tarball).unwrap();

        // Tamper with the integrity file
        std::fs::write(path.join(".integrity"), "sha512-TAMPERED").unwrap();

        let stored = read_stored_integrity(&path).unwrap();
        let expected = compute_sri_hash(&tarball);
        assert_ne!(stored, expected, "tampered integrity should not match");
    }

    #[test]
    fn store_concurrent_same_package_no_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"race\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = PackageStore::at(dir.path());
                let tarball = tarball.clone();
                std::thread::spawn(move || store.store_package("race", "1.0.0", &tarball))
            })
            .collect();

        for handle in handles {
            let result = handle.join().expect("thread panicked");
            assert!(result.is_ok(), "store_package failed: {:?}", result.err());
        }

        // Final directory must be valid
        let store = PackageStore::at(dir.path());
        assert!(store.has_package("race", "1.0.0"));
        let pkg_dir = store.package_dir("race", "1.0.0");
        assert!(pkg_dir.join("package.json").exists());
        assert!(pkg_dir.join("index.js").exists());

        // No stale .tmp directories should remain
        let v1_dir = dir.path().join("v1");
        if v1_dir.exists() {
            for entry in std::fs::read_dir(&v1_dir).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                assert!(
                    !name.contains(".tmp."),
                    "stale temp directory found: {name}"
                );
            }
        }
    }

    // ─── Garbage collection tests ──────────────────────────────────────

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
        assert_eq!(result.removed, 0, "scoped package should match by original name");
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

    // ─── File-based store tests ──────────────────────────────────────

    #[test]
    fn store_from_file_creates_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"file-test","version":"1.0.0"}"#),
            ("index.js", b"exports.run = () => 'file-based'"),
        ]);

        // Write tarball to a temp file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();

        let sri = "sha512-test-hash";
        let path = store
            .store_package_from_file("file-test", "1.0.0", temp.path(), sri)
            .unwrap();

        assert!(store.has_package("file-test", "1.0.0"));
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());

        // Verify .integrity was written with the provided SRI
        let stored_sri = std::fs::read_to_string(path.join(".integrity")).unwrap();
        assert_eq!(stored_sri, sri);
    }

    #[test]
    fn store_from_file_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"cached","version":"1.0.0"}"#),
        ]);

        // First store via memory path
        store.store_package("cached", "1.0.0", &tgz).unwrap();
        assert!(store.has_package("cached", "1.0.0"));

        // Second store via file path — should hit cache
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();
        let path = store
            .store_package_from_file("cached", "1.0.0", temp.path(), "sha512-x")
            .unwrap();

        assert!(path.join("package.json").exists());
    }

    #[test]
    fn store_from_file_concurrent_same_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(PackageStore::at(dir.path()));
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"race","version":"1.0.0"}"#),
            ("index.js", b"module.exports = 'race'"),
        ]);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                let data = tgz.clone();
                std::thread::spawn(move || {
                    let mut temp = tempfile::NamedTempFile::new().unwrap();
                    std::io::Write::write_all(&mut temp, &data).unwrap();
                    s.store_package_from_file("race", "1.0.0", temp.path(), "sha512-race")
                })
            })
            .collect();

        for h in handles {
            let result: Result<PathBuf, _> = h.join().unwrap();
            assert!(result.is_ok(), "concurrent store_from_file should not fail");
        }

        assert!(store.has_package("race", "1.0.0"));
        // No stale temp dirs left
        let store_v1 = store.root.join("v1");
        if store_v1.exists() {
            for entry in std::fs::read_dir(&store_v1).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                assert!(
                    !name.contains(".tmp."),
                    "stale temp dir found: {name}"
                );
            }
        }
    }
}
