//! Shared package inventory for `audit` and `query` commands.
//!
//! Provides a single entry point that discovers packages, loads behavioral
//! analysis from the appropriate cache, and builds the data structures
//! needed for both auditing and querying.

use super::cache::ProjectAuditCache;
use super::discovery::{self, DiscoveredPackage, DiscoveryResult, ManagerKind, ScanMode};
use lpm_security::behavioral::PackageAnalysis;
use std::collections::HashMap;
use std::path::Path;

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
    pub fn load(project_dir: &Path) -> Result<Self, lpm_common::LpmError> {
        let discovery = discovery::discover_packages(project_dir)?;
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
            return Ok(Self {
                discovery,
                analyses,
            });
        }

        // Load project-level audit cache
        let mut project_cache = ProjectAuditCache::read(&discovery.project_root);

        // Try LPM store for store-backed packages
        let lpm_store = lpm_store::PackageStore::default_location().ok();

        for pkg in &scannable {
            let analysis = if pkg.scan_mode == ScanMode::RegistryAndStore {
                // LPM store: try store cache first, then project cache
                lpm_store
                    .as_ref()
                    .and_then(|store| {
                        let pkg_dir = store.package_dir(&pkg.name, &pkg.version);
                        lpm_security::behavioral::read_cached_analysis(&pkg_dir)
                    })
                    .or_else(|| {
                        project_cache
                            .as_ref()
                            .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                            .cloned()
                    })
            } else {
                // Non-store: check project cache
                project_cache
                    .as_ref()
                    .and_then(|c| c.get(&pkg.path, pkg.integrity.as_deref()))
                    .cloned()
            };

            // Fallback: scan node_modules directly
            let analysis = analysis.or_else(|| {
                let abs_path = discovery.project_root.join(&pkg.path);
                if abs_path.is_dir() {
                    let analysis = lpm_security::behavioral::analyze_package(&abs_path);
                    if project_cache.is_none() {
                        project_cache =
                            Some(ProjectAuditCache::new(&discovery.manager.to_string()));
                    }
                    if let Some(ref mut cache) = project_cache {
                        cache.insert(
                            pkg.path.clone(),
                            pkg.name.clone(),
                            pkg.version.clone(),
                            pkg.integrity.clone(),
                            analysis.clone(),
                            pkg.dependencies.clone(),
                        );
                    }
                    Some(analysis)
                } else {
                    None
                }
            });

            if let Some(analysis) = analysis {
                // Key by path for npm projects, by name for LPM (backward compat)
                let key = if discovery.manager == ManagerKind::Lpm {
                    pkg.name.clone()
                } else {
                    pkg.path.clone()
                };
                analyses.insert(key, analysis);
            }
        }

        // Write cache back to disk
        if let Some(ref cache) = project_cache
            && let Err(e) = cache.write(&discovery.project_root)
        {
            tracing::debug!("failed to write audit cache: {e}");
        }

        Ok(Self {
            discovery,
            analyses,
        })
    }

    /// Whether this is an LPM-managed project (uses `lpm.lock`).
    pub fn is_lpm_project(&self) -> bool {
        self.discovery.manager == ManagerKind::Lpm
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
