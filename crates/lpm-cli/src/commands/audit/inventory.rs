//! Shared package inventory for `audit` and `query` commands.
//!
//! Provides a single entry point that discovers packages, loads behavioral
//! analysis from the appropriate cache, and builds the data structures
//! needed for both auditing and querying.

use super::cache::ProjectAuditCache;
use super::discovery::{self, DiscoveredPackage, DiscoveryResult, ManagerKind, ScanMode};
use lpm_security::behavioral::PackageAnalysis;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;

pub(crate) fn build_project_v2_baseline_index(
    project_dir: &Path,
    lpm_root: &lpm_common::LpmRoot,
) -> Option<lpm_store::V2BaselineIndex> {
    if lpm_store::StoreVersion::from_env() != lpm_store::StoreVersion::V2 {
        return Some(lpm_store::V2BaselineIndex::default());
    }
    match lpm_store::V2BaselineIndex::for_project(project_dir, lpm_root) {
        Ok(index) => Some(index),
        Err(e) => {
            tracing::debug!("failed to build v2 baseline index: {e}");
            None
        }
    }
}

pub(crate) fn find_project_baseline(
    index: Option<&lpm_store::V2BaselineIndex>,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<lpm_store::InstalledPackageBaseline> {
    if let Some(index) = index {
        return lpm_store::find_installed_package_baseline_indexed(index, lpm_root, name, version);
    }
    lpm_store::find_installed_package_baseline(lpm_root, name, version)
        .ok()
        .flatten()
}

/// A fully loaded package inventory ready for audit or query consumption.
///
/// Contains discovered packages with their behavioral analysis loaded
/// from the appropriate cache (LPM store or project audit cache).
pub struct PackageInventory {
    /// Discovery result (manager, lockfile, packages, etc.)
    pub discovery: DiscoveryResult,
    /// Behavioral analysis keyed by package path.
    /// For LPM store packages: keyed by name (backward compat).
    /// For npm projects: keyed by node_modules path.
    pub analyses: HashMap<String, PackageAnalysis>,
}

struct LoadedAnalysis {
    key: String,
    analysis: PackageAnalysis,
    cache_update: Option<CacheUpdate>,
}

struct CacheUpdate {
    path: String,
    name: String,
    version: String,
    integrity: Option<String>,
    analysis: PackageAnalysis,
    dependencies: Vec<(String, String)>,
}

impl PackageInventory {
    /// Build a package inventory from a project directory.
    ///
    /// Discovers packages from any lockfile format, then loads behavioral
    /// analysis from the appropriate cache:
    /// - LPM store (`.lpm-security.json`) for LPM-managed packages
    /// - Project audit cache (`.lpm/audit-cache.json`) for npm/pnpm/yarn/bun
    /// - Fresh scan on `node_modules/` as fallback
    ///
    /// Also writes back to the project audit cache when new scans are performed.
    /// Cheap pre-discovery: read the project's lockfile and return the
    /// resulting [`DiscoveryResult`] without loading any behavioral
    /// analyses. Does NOT touch the LPM store.
    ///
    /// Callers that need to take the store lock around the
    /// store-touching part of inventory load should call this first to
    /// learn `discovery.manager`, then conditionally lock and call
    /// [`PackageInventory::from_discovery`].
    pub fn discover(
        project_dir: &Path,
    ) -> Result<discovery::DiscoveryResult, lpm_common::LpmError> {
        discovery::discover_packages(project_dir)
    }

    /// Build the full inventory from a pre-computed
    /// [`DiscoveryResult`]. For LPM-managed projects this reads
    /// behavioral-analysis caches from the LPM store
    /// (`.lpm-security.json` per package dir) — callers must hold the
    /// shared store lock around this call to avoid racing
    /// `lpm cache prune --apply` / `lpm store clean`.
    pub fn from_discovery(discovery: discovery::DiscoveryResult) -> Self {
        let mut analyses: HashMap<String, PackageAnalysis> = HashMap::new();

        // Scannable packages: those with source on disk
        let scannable: Vec<&DiscoveredPackage> = discovery
            .packages
            .iter()
            .filter(|p| {
                matches!(
                    p.scan_mode,
                    ScanMode::FullLocal | ScanMode::RegistryAndStore
                )
            })
            .collect();

        if scannable.is_empty() {
            return Self {
                discovery,
                analyses,
            };
        }

        // Load project-level audit cache
        let mut project_cache = ProjectAuditCache::read(&discovery.project_root);

        let lpm_root = lpm_common::LpmRoot::from_env().ok();
        let baseline_index = lpm_root
            .as_ref()
            .and_then(|root| build_project_v2_baseline_index(&discovery.project_root, root));

        let project_cache_ref = project_cache.as_ref();
        let loaded: Vec<LoadedAnalysis> = scannable
            .par_iter()
            .filter_map(|pkg| {
                let cached_analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
                    lpm_root
                        .as_ref()
                        .and_then(|root| {
                            find_project_baseline(
                                baseline_index.as_ref(),
                                root,
                                &pkg.name,
                                &pkg.version,
                            )
                        })
                        .and_then(|baseline| {
                            lpm_security::behavioral::read_cached_analysis(&baseline.package_dir)
                        })
                        .or_else(|| {
                            project_cache_ref
                                .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                                .cloned()
                        })
                } else {
                    project_cache_ref
                        .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                        .cloned()
                };

                let abs_path = discovery.project_root.join(&pkg.path);
                let (analysis, cache_update) = if let Some(analysis) = cached_analysis {
                    (analysis, None)
                } else if abs_path.is_dir() {
                    let analysis = lpm_security::behavioral::analyze_package(&abs_path);
                    let cache_update = CacheUpdate {
                        path: pkg.path.clone(),
                        name: pkg.name.clone(),
                        version: pkg.version.clone(),
                        integrity: pkg.integrity.clone(),
                        analysis: analysis.clone(),
                        dependencies: pkg.dependencies.clone(),
                    };
                    (analysis, Some(cache_update))
                } else {
                    return None;
                };

                let key = if discovery.manager == ManagerKind::Lpm {
                    pkg.name.clone()
                } else {
                    pkg.path.clone()
                };
                Some(LoadedAnalysis {
                    key,
                    analysis,
                    cache_update,
                })
            })
            .collect();

        for loaded in loaded {
            if let Some(update) = loaded.cache_update {
                if project_cache.is_none() {
                    project_cache = Some(ProjectAuditCache::new(&discovery.manager.to_string()));
                }
                if let Some(ref mut cache) = project_cache {
                    cache.insert(
                        update.path,
                        update.name,
                        update.version,
                        update.integrity,
                        update.analysis,
                        update.dependencies,
                    );
                }
            }
            analyses.insert(loaded.key, loaded.analysis);
        }

        // Write cache back to disk
        if let Some(ref cache) = project_cache
            && let Err(e) = cache.write(&discovery.project_root)
        {
            tracing::debug!("failed to write audit cache: {e}");
        }

        Self {
            discovery,
            analyses,
        }
    }

    /// Get all non-@lpm.dev packages as `(name, version)` pairs for OSV queries.
    pub fn npm_package_pairs(&self) -> Vec<(String, String)> {
        self.discovery
            .packages
            .iter()
            .filter(|p| !p.name.starts_with("@lpm.dev/"))
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect()
    }
}
