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
use std::path::{Path, PathBuf};

/// Current cache format version. Bump when the cache structure changes.
/// v2: added `dependencies` field to CacheEntry for dependency edge graph.
/// v3: added `cached_at_unix_secs` for the M14 advisory-corpus freshness gate.
const CACHE_VERSION: u32 = 3;

/// M14: max age of a cache entry before it's treated as a miss, in
/// seconds. The audit cache currently has no signal that lets it
/// invalidate when the advisory corpus (OSV) ships a new CVE for an
/// already-scanned package; a 24-hour TTL bounds the freshness gap
/// without forcing a re-scan on every install.
///
/// 24 hours is the same cadence operators set their `lpm audit`
/// cron jobs at; a TTL longer than that defeats the purpose, a TTL
/// shorter than that re-scans every install for no benefit. Tuneable
/// via `LPM_AUDIT_CACHE_MAX_AGE_SECS` for tests and high-frequency
/// operators.
const AUDIT_CACHE_ENTRY_MAX_AGE_SECS: u64 = 24 * 60 * 60;

fn audit_cache_max_age_secs() -> u64 {
    std::env::var("LPM_AUDIT_CACHE_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(AUDIT_CACHE_ENTRY_MAX_AGE_SECS)
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

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
    /// M14: unix seconds at which this entry was last refreshed.
    /// Entries older than [`AUDIT_CACHE_ENTRY_MAX_AGE_SECS`] are
    /// treated as misses so a post-publication CVE from the
    /// advisory corpus surfaces within a day.
    /// `#[serde(default)]` keeps v2 caches readable; a missing
    /// field is treated as age `0` (epoch), which triggers a
    /// guaranteed miss on the first read after upgrade.
    #[serde(default)]
    pub cached_at_unix_secs: u64,
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
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, json)
    }

    /// Look up a cached entry. Returns the analysis if the integrity
    /// matches AND the cached entry is within the advisory-corpus
    /// freshness window.
    ///
    /// M61: cache hits REQUIRE matching integrity on both sides. The
    /// pre-fix degraded mode (any side missing integrity → "trust the
    /// cache") allowed a malicious repo to ship a committed
    /// `.lpm/audit-cache.json` alongside packages whose lockfile entries
    /// were scrubbed of SRI. Any arm with `None` on either side
    /// returns `None` (cache miss).
    ///
    /// M14: the cache previously had no signal that lets a fresh CVE
    /// publication invalidate stale "no findings" verdicts for an
    /// already-scanned (name, version, integrity) tuple. The
    /// `cached_at_unix_secs` field on each entry gives a hard 24-hour
    /// TTL — entries past the cap collapse to `None` so the next
    /// `lpm audit` re-runs the behavioral analyzer (which is what
    /// surfaces post-publication CVEs from the advisory corpus).
    pub fn get(&self, path: &str, integrity: Option<&str>) -> Option<&PackageAnalysis> {
        let entry = self.entries.get(path)?;

        // M61 integrity gate first — a stale cache that fails the
        // integrity check shouldn't waste time on the TTL check.
        match (integrity, &entry.integrity) {
            (Some(new), Some(cached)) if new == cached => {}
            _ => return None,
        }

        // M14 freshness gate. An entry written more than
        // `audit_cache_max_age_secs()` ago collapses to miss; the
        // caller re-runs analysis and re-stamps the entry.
        let now = now_unix_secs();
        let max_age = audit_cache_max_age_secs();
        if now.saturating_sub(entry.cached_at_unix_secs) > max_age {
            return None;
        }

        Some(&entry.analysis)
    }

    /// Insert or update a cache entry. The `cached_at_unix_secs`
    /// field is stamped here so every fresh write re-establishes the
    /// M14 freshness window.
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
                cached_at_unix_secs: now_unix_secs(),
            },
        );
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

    /// M14: an entry stamped now is within the TTL — cache hit.
    #[test]
    fn get_returns_entry_when_cached_age_under_ttl() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        // insert() stamps cached_at_unix_secs to now, so the entry is
        // within TTL and the lookup hits.
        assert!(
            cache
                .get("node_modules/react", Some("sha512-cachehash"))
                .is_some(),
            "fresh cache entry must hit"
        );
    }

    /// M14: an entry stamped at unix epoch (i.e. older than any TTL
    /// reasonable) collapses to miss — the next `lpm audit` re-runs
    /// behavioral analysis and re-stamps the entry, surfacing any
    /// post-publication CVEs that landed in the corpus.
    #[test]
    fn get_returns_none_when_cached_entry_is_stale() {
        let mut cache = ProjectAuditCache::new("npm");
        cache.entries.insert(
            "node_modules/react".into(),
            CacheEntry {
                name: "react".into(),
                version: "18.0.0".into(),
                integrity: Some("sha512-cachehash".into()),
                analysis: empty_analysis(),
                dependencies: vec![],
                // 0 = unix epoch; guaranteed to be past any TTL.
                cached_at_unix_secs: 0,
            },
        );
        assert!(
            cache
                .get("node_modules/react", Some("sha512-cachehash"))
                .is_none(),
            "stale cache entry must collapse to miss (M14 freshness gate)"
        );
    }

    /// M14: entries written by an older lpm release (no
    /// `cached_at_unix_secs` field) deserialize with the serde
    /// default of `0`, which the freshness gate treats as stale.
    /// First read after upgrade re-runs analysis once for each
    /// entry, then subsequent reads hit the cache normally.
    #[test]
    fn get_returns_none_for_legacy_entry_without_cached_at_field() {
        let mut cache = ProjectAuditCache::new("npm");
        // Simulate a v2-shape entry (serde_json::from_str path that
        // wouldn't have populated the new field) by overwriting the
        // field to 0 after insert().
        cache.insert(
            "node_modules/legacy".into(),
            "legacy".into(),
            "1.0.0".into(),
            Some("sha512-legacy".into()),
            empty_analysis(),
            vec![],
        );
        cache
            .entries
            .get_mut("node_modules/legacy")
            .unwrap()
            .cached_at_unix_secs = 0;
        assert!(
            cache
                .get("node_modules/legacy", Some("sha512-legacy"))
                .is_none(),
            "legacy entry missing the freshness field must collapse to miss after upgrade"
        );
    }

    /// M14: `LPM_AUDIT_CACHE_MAX_AGE_SECS` env override lets tests
    /// and high-frequency operators tighten the gate.
    #[test]
    fn freshness_gate_honours_env_override() {
        let _g = crate::test_env::ScopedEnv::set([("LPM_AUDIT_CACHE_MAX_AGE_SECS", "1".into())]);
        let mut cache = ProjectAuditCache::new("npm");
        cache.insert(
            "node_modules/react".into(),
            "react".into(),
            "18.0.0".into(),
            Some("sha512-cachehash".into()),
            empty_analysis(),
            vec![],
        );
        // Backdate the entry by 10 seconds — past the 1-second env-overridden TTL.
        let now = now_unix_secs();
        cache
            .entries
            .get_mut("node_modules/react")
            .unwrap()
            .cached_at_unix_secs = now.saturating_sub(10);
        assert!(
            cache
                .get("node_modules/react", Some("sha512-cachehash"))
                .is_none(),
            "env-overridden 1s TTL must invalidate a 10s-old entry"
        );
    }
}
