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
const CACHE_VERSION: u32 = 1;

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
		let content = std::fs::read_to_string(&path).ok()?;
		let cache: Self = serde_json::from_str(&content).ok()?;

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

	/// Look up a cached entry. Returns the analysis if the integrity matches.
	pub fn get(&self, path: &str, integrity: Option<&str>) -> Option<&PackageAnalysis> {
		let entry = self.entries.get(path)?;

		// If both have integrity hashes, compare them
		match (integrity, &entry.integrity) {
			(Some(new), Some(cached)) if new == cached => Some(&entry.analysis),
			(Some(_), Some(_)) => None, // integrity mismatch → stale
			// No integrity to compare (degraded mode) — trust the cache
			_ => Some(&entry.analysis),
		}
	}

	/// Insert or update a cache entry.
	pub fn insert(
		&mut self,
		path: String,
		name: String,
		version: String,
		integrity: Option<String>,
		analysis: PackageAnalysis,
	) {
		self.entries.insert(
			path,
			CacheEntry {
				name,
				version,
				integrity,
				analysis,
			},
		);
	}
}

fn cache_path(project_root: &Path) -> PathBuf {
	project_root.join(".lpm").join("audit-cache.json")
}
