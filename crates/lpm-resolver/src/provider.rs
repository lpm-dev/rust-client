//! PubGrub DependencyProvider implementation for LPM.
//!
//! Bridges PubGrub's resolution algorithm with the LPM/npm registries.
//!
//! # TODOs
//! - [ ] peerDependencies handling (inject as direct deps of the parent)
//! - [ ] optionalDependencies (try/catch — skip if resolution fails)
//! - [ ] overrides/resolutions (inject as hard constraints)
//! - [ ] workspace:* protocol (resolve to local packages)
//! - [ ] Platform filtering (os/cpu)
//! - [ ] Multi-version splitting (when flat resolution fails)
//! - [ ] npm upstream registry support (currently npm packages are leaf nodes)

use crate::npm_version::NpmVersion;
use crate::package::ResolverPackage;
use crate::ranges::NpmRange;
use lpm_registry::RegistryClient;
use pubgrub::{Dependencies, DependencyProvider, PackageResolutionStatistics};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::runtime::Handle;
use version_ranges::Ranges;

/// Cached info about a package: available versions and their dependency maps.
#[derive(Debug, Clone)]
pub struct CachedPackageInfo {
    /// Available versions, sorted descending (newest first).
    pub versions: Vec<NpmVersion>,
    /// Regular dependencies for each version: version_string → { dep_name → range_string }.
    pub deps: HashMap<String, HashMap<String, String>>,
    /// Peer dependencies for each version: version_string → { dep_name → range_string }.
    /// These get propagated to the parent that depends on this package.
    pub peer_deps: HashMap<String, HashMap<String, String>>,
    /// Optional dependency names (per version). Included in deps but resolution failure
    /// for these is non-fatal.
    pub optional_dep_names: HashMap<String, HashSet<String>>,
}

/// The DependencyProvider that bridges PubGrub with LPM's registry.
pub struct LpmDependencyProvider {
    client: Arc<RegistryClient>,
    rt: Handle,
    cache: RefCell<HashMap<ResolverPackage, CachedPackageInfo>>,
    root_deps: HashMap<String, String>,
    /// Packages that should be split into per-parent identities.
    split_packages: HashSet<String>,
    /// Version overrides: package_name → forced_version.
    /// Applied as hard constraints — the resolver MUST use these versions.
    overrides: HashMap<String, String>,
}

impl LpmDependencyProvider {
    pub fn new(
        client: Arc<RegistryClient>,
        rt: Handle,
        root_deps: HashMap<String, String>,
    ) -> Self {
        LpmDependencyProvider {
            client,
            rt,
            cache: RefCell::new(HashMap::new()),
            root_deps,
            split_packages: HashSet::new(),
            overrides: HashMap::new(),
        }
    }

    /// Create a provider with multi-version splitting for specific packages.
    pub fn new_with_splits(
        client: Arc<RegistryClient>,
        rt: Handle,
        root_deps: HashMap<String, String>,
        splits: HashSet<String>,
    ) -> Self {
        LpmDependencyProvider {
            client,
            rt,
            cache: RefCell::new(HashMap::new()),
            root_deps,
            split_packages: splits,
            overrides: HashMap::new(),
        }
    }

    /// Set version overrides (from package.json `overrides` or `resolutions`).
    pub fn with_overrides(mut self, overrides: HashMap<String, String>) -> Self {
        self.overrides = overrides;
        self
    }

    /// Ensure package metadata is cached. Fetches from registry if needed.
    ///
    /// For split packages (with context), we first check if the canonical
    /// (contextless) version is cached, then copy its data under the split key.
    fn ensure_cached(&self, package: &ResolverPackage) -> Result<(), ProviderError> {
        if package.is_root() || self.cache.borrow().contains_key(package) {
            return Ok(());
        }

        // For split packages, try to reuse the canonical package's cache
        if package.is_split() {
            let canonical = match package {
                ResolverPackage::Lpm { owner, name, .. } => ResolverPackage::lpm(owner, name),
                ResolverPackage::Npm { name, .. } => ResolverPackage::npm(name),
                _ => unreachable!(),
            };
            self.ensure_cached(&canonical)?;
            // Separate borrow/borrow_mut to avoid RefCell conflict
            let info = self.cache.borrow().get(&canonical).cloned();
            if let Some(info) = info {
                self.cache.borrow_mut().insert(package.clone(), info);
            }
            return Ok(());
        }

        match package {
            ResolverPackage::Root => Ok(()),
            ResolverPackage::Lpm { owner, name, .. } => {
                let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                    .map_err(|e| ProviderError::Registry(e.to_string()))?;

                let metadata = self
                    .rt
                    .block_on(self.client.get_package_metadata(&pkg_name))
                    .map_err(|e| ProviderError::Registry(e.to_string()))?;

                let mut versions: Vec<NpmVersion> = Vec::new();
                let mut deps: HashMap<String, HashMap<String, String>> = HashMap::new();
                let mut peer_deps: HashMap<String, HashMap<String, String>> = HashMap::new();
                let mut optional_dep_names: HashMap<String, HashSet<String>> = HashMap::new();

                for (ver_str, ver_meta) in &metadata.versions {
                    if let Ok(v) = NpmVersion::parse(ver_str) {
                        let mut ver_deps = HashMap::new();
                        for (dep_name, dep_range) in &ver_meta.dependencies {
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                        }

                        // Include optional deps in the deps map but track their names
                        let mut opt_names = HashSet::new();
                        for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                            opt_names.insert(dep_name.clone());
                        }
                        if !opt_names.is_empty() {
                            optional_dep_names.insert(ver_str.clone(), opt_names);
                        }

                        deps.insert(ver_str.clone(), ver_deps);

                        // Store peer deps separately for propagation
                        if !ver_meta.peer_dependencies.is_empty() {
                            let mut ver_peers = HashMap::new();
                            for (dep_name, dep_range) in &ver_meta.peer_dependencies {
                                ver_peers.insert(dep_name.clone(), dep_range.clone());
                            }
                            peer_deps.insert(ver_str.clone(), ver_peers);
                        }

                        versions.push(v);
                    }
                }

                versions.sort();
                versions.reverse(); // Newest first

                self.cache.borrow_mut().insert(
                    package.clone(),
                    CachedPackageInfo { versions, deps, peer_deps, optional_dep_names },
                );
                Ok(())
            }
            ResolverPackage::Npm { name, .. } => {
                let metadata = self
                    .rt
                    .block_on(self.client.get_npm_package_metadata(name))
                    .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;

                let mut versions: Vec<NpmVersion> = Vec::new();
                let mut deps: HashMap<String, HashMap<String, String>> = HashMap::new();
                let mut peer_deps: HashMap<String, HashMap<String, String>> = HashMap::new();
                let mut optional_dep_names: HashMap<String, HashSet<String>> = HashMap::new();

                for (ver_str, ver_meta) in &metadata.versions {
                    if let Ok(v) = NpmVersion::parse(ver_str) {
                        // Skip pre-release versions for npm packages by default
                        if v.is_prerelease() {
                            continue;
                        }

                        let mut ver_deps = HashMap::new();
                        for (dep_name, dep_range) in &ver_meta.dependencies {
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                        }

                        // Include optional deps but track them
                        let mut opt_names = HashSet::new();
                        for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                            opt_names.insert(dep_name.clone());
                        }
                        if !opt_names.is_empty() {
                            optional_dep_names.insert(ver_str.clone(), opt_names);
                        }

                        deps.insert(ver_str.clone(), ver_deps);

                        // Store peer deps separately
                        if !ver_meta.peer_dependencies.is_empty() {
                            let mut ver_peers = HashMap::new();
                            for (dep_name, dep_range) in &ver_meta.peer_dependencies {
                                ver_peers.insert(dep_name.clone(), dep_range.clone());
                            }
                            peer_deps.insert(ver_str.clone(), ver_peers);
                        }

                        versions.push(v);
                    }
                }

                versions.sort();
                versions.reverse(); // Newest first

                tracing::debug!("npm package {name}: {} versions", versions.len());

                self.cache.borrow_mut().insert(
                    package.clone(),
                    CachedPackageInfo { versions, deps, peer_deps, optional_dep_names },
                );
                Ok(())
            }
        }
    }

    /// Get the list of available versions for a package (from cache).
    fn available_versions(&self, package: &ResolverPackage) -> Vec<NpmVersion> {
        self.cache
            .borrow()
            .get(package)
            .map(|c| c.versions.clone())
            .unwrap_or_default()
    }

    /// Extract the metadata cache. Call after resolution to get dependency info
    /// for building the install plan (linker needs to know each package's deps).
    pub fn into_cache(self) -> HashMap<ResolverPackage, CachedPackageInfo> {
        self.cache.into_inner()
    }
}

impl DependencyProvider for LpmDependencyProvider {
    type P = ResolverPackage;
    type V = NpmVersion;
    type VS = Ranges<NpmVersion>;
    type Priority = ResolverPriority;
    type M = String;
    type Err = ProviderError;

    fn prioritize(
        &self,
        package: &Self::P,
        _range: &Self::VS,
        stats: &PackageResolutionStatistics,
    ) -> Self::Priority {
        let conflict_count = stats.conflict_count();
        let version_count = self
            .cache
            .borrow()
            .get(package)
            .map(|c| c.versions.len())
            .unwrap_or(100) as u32;

        ResolverPriority {
            conflict_count,
            inverse_version_count: u32::MAX - version_count,
        }
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        if package.is_root() {
            return Ok(Some(NpmVersion::new(0, 0, 0)));
        }

        self.ensure_cached(package)?;

        // Check for version override
        let canonical = package.canonical_name();
        if let Some(forced_ver) = self.overrides.get(&canonical) {
            if let Ok(v) = NpmVersion::parse(forced_ver) {
                if range.contains(&v) {
                    tracing::debug!("override: {canonical} forced to {forced_ver}");
                    return Ok(Some(v));
                }
            }
        }

        let cache = self.cache.borrow();
        let info = match cache.get(package) {
            Some(info) => info,
            None => return Ok(None),
        };

        // Return newest version that satisfies the range (versions are newest-first)
        Ok(info.versions.iter().find(|v| range.contains(v)).cloned())
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        if package.is_root() {
            let mut constraints = pubgrub::Map::default();
            for (dep_name, dep_range_str) in &self.root_deps {
                let pkg = ResolverPackage::from_dep_name(dep_name);

                // Ensure dep is cached so we know its versions
                self.ensure_cached(&pkg)?;
                let available = self.available_versions(&pkg);

                let npm_range = NpmRange::parse(dep_range_str)
                    .map_err(|e| ProviderError::InvalidRange(e))?;

                let range = if available.is_empty() {
                    npm_range.to_pubgrub_ranges_heuristic()
                } else {
                    npm_range.to_pubgrub_ranges(&available)
                };

                constraints.insert(pkg, range);
            }
            return Ok(Dependencies::Available(constraints));
        }

        self.ensure_cached(package)?;

        let ver_str = version.to_string();
        let (ver_deps, optional_names) = {
            let cache = self.cache.borrow();
            let info = match cache.get(package) {
                Some(info) => info,
                None => {
                    return Ok(Dependencies::Unavailable(format!(
                        "no metadata for {package}"
                    )));
                }
            };
            let deps = match info.deps.get(&ver_str) {
                Some(deps) => deps.clone(),
                None => return Ok(Dependencies::Available(pubgrub::Map::default())),
            };
            let opt = info
                .optional_dep_names
                .get(&ver_str)
                .cloned()
                .unwrap_or_default();
            (deps, opt)
        };

        let parent_name = package.canonical_name();
        let mut constraints = pubgrub::Map::default();

        // Collect dep names we add so we can check for peer dep conflicts
        let mut added_deps = HashSet::new();

        for (dep_name, dep_range_str) in &ver_deps {
            let base_pkg = ResolverPackage::from_dep_name(dep_name);

            // If this dep is in the split set, create a scoped identity
            // so PubGrub treats each consumer's version independently.
            let pkg = if self.split_packages.contains(dep_name) {
                base_pkg.with_context(&parent_name)
            } else {
                base_pkg
            };

            let is_optional = optional_names.contains(dep_name);

            // Ensure dep is cached — skip optional deps that fail to fetch
            match self.ensure_cached(&pkg) {
                Ok(()) => {}
                Err(e) => {
                    if is_optional {
                        tracing::debug!("skipping optional dep {dep_name}: {e}");
                        continue;
                    }
                    return Err(e);
                }
            }
            let available = self.available_versions(&pkg);

            // Skip optional deps with no available versions (platform-specific packages)
            if is_optional && available.is_empty() {
                tracing::debug!("skipping optional dep {dep_name}: no versions available");
                continue;
            }

            match NpmRange::parse(dep_range_str) {
                Ok(npm_range) => {
                    let range = if available.is_empty() {
                        npm_range.to_pubgrub_ranges_heuristic()
                    } else {
                        npm_range.to_pubgrub_ranges(&available)
                    };
                    constraints.insert(pkg, range);
                    added_deps.insert(dep_name.clone());
                }
                Err(e) => {
                    if is_optional {
                        tracing::debug!("skipping optional dep {dep_name}@{dep_range_str}: {e}");
                    } else {
                        tracing::warn!("skipping dep {dep_name}@{dep_range_str}: {e}");
                    }
                }
            }
        }

        // Peer dependency propagation: for each dep, if it has peerDependencies,
        // add those as constraints of THIS package (the parent provides peers).
        // This is how npm/pnpm handle peers — the consumer must also install them.
        let peer_constraints: Vec<(String, String)> = {
            let cache = self.cache.borrow();
            ver_deps
                .keys()
                .filter_map(|dep_name| {
                    let dep_pkg = ResolverPackage::from_dep_name(dep_name);
                    let info = cache.get(&dep_pkg)?;
                    // Find the version of this dep that would be selected
                    // For peer propagation, use the latest matching version's peers
                    let latest_ver = info.versions.first()?;
                    let ver_str = latest_ver.to_string();
                    info.peer_deps.get(&ver_str).map(|peers| {
                        peers
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<Vec<_>>()
                    })
                })
                .flatten()
                .collect()
        };

        for (peer_name, peer_range_str) in &peer_constraints {
            // Don't add peer dep if it's already a regular dep
            if added_deps.contains(peer_name) {
                continue;
            }

            let peer_pkg = ResolverPackage::from_dep_name(peer_name);
            self.ensure_cached(&peer_pkg)?;
            let available = self.available_versions(&peer_pkg);

            match NpmRange::parse(peer_range_str) {
                Ok(npm_range) => {
                    let range = if available.is_empty() {
                        npm_range.to_pubgrub_ranges_heuristic()
                    } else {
                        npm_range.to_pubgrub_ranges(&available)
                    };
                    // Only add if not already constrained (first peer wins)
                    if !constraints.contains_key(&peer_pkg) {
                        constraints.insert(peer_pkg, range);
                        tracing::debug!(
                            "peer dep propagated: {parent_name} → {peer_name}@{peer_range_str}"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!("skipping peer dep {peer_name}@{peer_range_str}: {e}");
                }
            }
        }

        Ok(Dependencies::Available(constraints))
    }
}

/// Priority for the resolver. Higher = resolved first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverPriority {
    conflict_count: u32,
    inverse_version_count: u32,
}

impl Ord for ResolverPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.conflict_count
            .cmp(&other.conflict_count)
            .then(self.inverse_version_count.cmp(&other.inverse_version_count))
    }
}

impl PartialOrd for ResolverPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Errors during dependency resolution.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("registry error: {0}")]
    Registry(String),

    #[error("invalid version range: {0}")]
    InvalidRange(String),

    #[error("resolution cancelled")]
    Cancelled,
}
