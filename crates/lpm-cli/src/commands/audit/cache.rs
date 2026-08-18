//! Project-level audit cache (`.lpm/audit-cache.json`).
//!
//! Stores behavioral analysis results per package instance so that
//! subsequent `lpm audit` runs are near-instant when nothing changed.
//!
//! Cache invalidation:
//! - Global: `cache_version` or `behavioral_schema_version` mismatch → full re-scan
//! - Per-entry: `integrity` hash mismatch → re-scan that package only
//! - Quick check: lockfile mtime vs cache mtime (skip all comparisons if lockfile is older)

use lpm_security::behavioral::PackageAnalysis;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Current cache format version. Bump when the cache structure changes.
/// v2: added `dependencies` field to CacheEntry for dependency edge graph.
/// v3: added a per-entry timestamp that newer readers ignore because advisory
/// freshness is enforced independently of source-analysis reuse.
const CACHE_VERSION: u32 = 3;

/// Project audit cache, stored at `.lpm/audit-cache.json`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectAuditCache {
    pub cache_version: u32,
    pub behavioral_schema_version: u32,
    pub manager: String,
    /// Keyed by package path (e.g., "node_modules/react").
    pub entries: HashMap<String, CacheEntry>,
}

/// A single cached analysis entry.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    pub name: String,
    pub version: String,
    pub integrity: Option<String>,
    pub analysis: PackageAnalysis,
    /// Direct dependencies: (name, exact_version).
    /// Used by `lpm query` for `>` combinator traversal without re-parsing the lockfile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<(String, String)>,
}

impl ProjectAuditCache {
    /// Create a new empty cache.
    pub fn new(manager: &str) -> Self {
        Self {
            cache_version: CACHE_VERSION,
            behavioral_schema_version: lpm_security::behavioral::SCHEMA_VERSION,
            manager: manager.to_string(),
            entries: HashMap::new(),
        }
    }

    /// Read cache from disk. Returns None if missing, corrupt, or stale.
    pub fn read(project_root: &Path) -> Option<Self> {
        let path = cache_path(project_root);
        let content =
            lpm_common::read_capped_state_file(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
                .ok()??;
        let cache: Self = serde_json::from_slice(&content).ok()?;

        // Check versions — stale cache requires full re-scan
        if cache.cache_version != CACHE_VERSION {
            tracing::debug!(
                "cache version {} != current {CACHE_VERSION}, discarding",
                cache.cache_version
            );
            return None;
        }
        if cache.behavioral_schema_version != lpm_security::behavioral::SCHEMA_VERSION {
            tracing::debug!(
                "behavioral schema version {} != current {}, discarding",
                cache.behavioral_schema_version,
                lpm_security::behavioral::SCHEMA_VERSION
            );
            return None;
        }

        Some(cache)
    }

    /// Write cache to disk. Creates `.lpm/` directory if needed.
    pub fn write(&self, project_root: &Path) -> Result<(), std::io::Error> {
        let path = cache_path(project_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        lpm_common::write_file_atomic_with(&path, lpm_common::AtomicWriteOptions::new(), |file| {
            let mut writer = CappedWriter::new(
                file,
                lpm_common::STATE_FILE_SIZE_CAP_BYTES,
                "audit cache exceeds the state-file size limit",
            );
            serde_json::to_writer_pretty(&mut writer, self).map_err(|error| {
                io::Error::new(
                    error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
                    error,
                )
            })
        })
    }

    /// Look up a cached entry. Returns the analysis if the integrity matches.
    ///
    /// M61: cache hits REQUIRE matching integrity on both sides. The
    /// pre-fix degraded mode (any side missing integrity → "trust the
    /// cache") allowed a malicious repo to ship a committed
    /// `.lpm/audit-cache.json` alongside packages whose lockfile entries
    /// were scrubbed of SRI. Any arm with `None` on either side
    /// returns `None` (cache miss).
    ///
    pub fn get(&self, path: &str, integrity: Option<&str>) -> Option<&PackageAnalysis> {
        let entry = self.entries.get(path)?;

        match (integrity, &entry.integrity) {
            (Some(new), Some(cached)) if new == cached => {}
            _ => return None,
        }

        Some(&entry.analysis)
    }

    /// Insert or update a cache entry.
    pub fn insert(
        &mut self,
        path: String,
        name: String,
        version: String,
        integrity: Option<String>,
        analysis: PackageAnalysis,
        dependencies: Vec<(String, String)>,
    ) {
        self.entries.insert(
            path,
            CacheEntry {
                name,
                version,
                integrity,
                analysis,
                dependencies,
            },
        );
    }
}

struct CappedWriter<'a> {
    inner: &'a mut std::fs::File,
    remaining: u64,
    limit_error: &'static str,
}

impl<'a> CappedWriter<'a> {
    fn new(inner: &'a mut std::fs::File, limit: u64, limit_error: &'static str) -> Self {
        Self {
            inner,
            remaining: limit,
            limit_error,
        }
    }
}

impl Write for CappedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(buffer.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "write buffer length overflow")
        })?;
        if length > self.remaining {
            return Err(io::Error::new(io::ErrorKind::InvalidData, self.limit_error));
        }
        let written = self.inner.write(buffer)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn cache_path(project_root: &Path) -> PathBuf {
    project_root.join(".lpm").join("audit-cache.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::behavioral::PackageAnalysis;

    fn empty_analysis() -> PackageAnalysis {
        // Build the cheapest possible PackageAnalysis for the cache-
        // lookup tests. Substruct defaults are derived; the parent
        // struct is not, so we name the fields explicitly.
        PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "1970-01-01T00:00:00Z".into(),
            source: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            meta: Default::default(),
        }
    }

    /// Both integrity hashes present and matching → cache hit.
    #[test]
    fn get_returns_entry_on_integrity_match() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        assert!(
            cache
                .get("node_modules/react", Some("sha512-cachehash"))
                .is_some()
        );
    }

    /// Both integrity hashes present but different → re-scan.
    #[test]
    fn get_returns_none_on_integrity_mismatch() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        assert!(
            cache
                .get("node_modules/react", Some("sha512-different"))
                .is_none()
        );
    }

    /// M61: discovered-side missing integrity (lockfile scrubbed of
    /// SRI / node_modules fallback) MUST refuse the cached entry.
    /// Pre-fix this returned `Some(analysis)` from the cache, letting
    /// a hostile committed cache short-circuit fresh behavioral
    /// scanning for packages whose integrity was deliberately omitted.
    #[test]
    fn get_returns_none_when_discovered_integrity_missing() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        assert!(
            cache.get("node_modules/react", None).is_none(),
            "discovered-side None must NOT trust the cache — that was the M61 hole"
        );
    }

    /// Cached-side missing integrity (entry written under an older
    /// release that didn't record SRI) is also treated as miss. Forces
    /// a re-scan that re-populates the entry with the new SRI field.
    #[test]
    fn get_returns_none_when_cached_integrity_missing() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            None,
            empty_analysis(),
            vec![],
        );
        assert!(
            cache
                .get("node_modules/react", Some("sha512-discovered"))
                .is_none()
        );
    }

    /// Both sides None — also a miss. Symmetric with the other arms;
    /// pre-fix this also collapsed to "trust the cache".
    #[test]
    fn get_returns_none_when_both_integrities_missing() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            None,
            empty_analysis(),
            vec![],
        );
        assert!(cache.get("node_modules/react", None).is_none());
    }

    #[test]
    fn matching_integrity_reuses_analysis_despite_legacy_timestamp() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        let mut serialized = serde_json::to_value(cache).unwrap();
        serialized["entries"]["node_modules/react"]["cachedAtUnixSecs"] = 0.into();
        let cache: ProjectAuditCache = serde_json::from_value(serialized).unwrap();

        assert!(
            cache
                .get("node_modules/react", Some("sha512-cachehash"))
                .is_some(),
            "advisory freshness must not expire integrity-keyed source analysis"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_replaces_destination_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"sentinel").unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let cache_path = cache_path(project.path());
        symlink(outside.path(), &cache_path).unwrap();

        ProjectAuditCache::new("npm").write(project.path()).unwrap();

        assert_eq!(
            (
                std::fs::read(outside.path()).unwrap(),
                std::fs::symlink_metadata(cache_path)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
            ),
            (b"sentinel".to_vec(), false),
            "cache replacement must not follow a destination symlink"
        );
    }

    #[test]
    fn oversized_write_preserves_previous_readable_cache() {
        let project = tempfile::tempdir().unwrap();
        let previous = ProjectAuditCache::new("npm");
        previous.write(project.path()).unwrap();
        let cache_path = cache_path(project.path());
        let previous_bytes = std::fs::read(&cache_path).unwrap();

        let mut oversized = ProjectAuditCache::new("npm");
        let mut analysis = empty_analysis();
        analysis.analyzed_at = "x".repeat(lpm_common::STATE_FILE_SIZE_CAP_BYTES as usize);
        oversized.insert(
            "node_modules/oversized".into(),
            "oversized".into(),
            "1.0.0".into(),
            Some("sha512-cachehash".into()),
            analysis,
            vec![],
        );

        let result = oversized.write(project.path());
        let previous_preserved = std::fs::read(cache_path).unwrap() == previous_bytes;

        assert_eq!(
            (result.is_err(), previous_preserved),
            (true, true),
            "an over-cap cache must fail before replacing the prior cache"
        );
    }
}
