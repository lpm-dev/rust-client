//! PubGrub DependencyProvider implementation for LPM.
//!
//! Bridges PubGrub's resolution algorithm with the LPM/npm registries.
//!
//! Resolver compatibility: peerDeps, optionalDeps, overrides, workspace:*, platform filtering.
//! See phase-17-todo.md.

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
    /// Platform restrictions per version: version_string → PlatformMeta.
    /// Only populated for versions that declare os/cpu restrictions.
    pub platform: HashMap<String, PlatformMeta>,
    /// Cached aggregated peer deps (union across all versions, newest-first priority).
    /// Computed lazily on first access.
    pub aggregated_peers: Option<HashMap<String, String>>,
}

/// Platform restriction metadata for a specific package version.
#[derive(Debug, Clone, Default)]
pub struct PlatformMeta {
    /// OS restrictions: e.g., ["darwin", "linux"] or ["!win32"].
    pub os: Vec<String>,
    /// CPU restrictions: e.g., ["x64", "arm64"] or ["!ia32"].
    pub cpu: Vec<String>,
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
                let mut platform: HashMap<String, PlatformMeta> = HashMap::new();

                for (ver_str, ver_meta) in &metadata.versions {
                    if !is_valid_version_string(ver_str) {
                        tracing::warn!("skipping invalid version string: {ver_str:?}");
                        continue;
                    }
                    if let Ok(v) = NpmVersion::parse(ver_str) {
                        let mut ver_deps = HashMap::new();
                        for (dep_name, dep_range) in &ver_meta.dependencies {
                            if !is_valid_dep_name(dep_name) {
                                tracing::warn!("skipping invalid dep name: {dep_name:?}");
                                continue;
                            }
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                        }

                        // Include optional deps in the deps map but track their names
                        let mut opt_names = HashSet::new();
                        for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                            if !is_valid_dep_name(dep_name) {
                                tracing::warn!("skipping invalid optional dep name: {dep_name:?}");
                                continue;
                            }
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
                                if !is_valid_dep_name(dep_name) {
                                    tracing::warn!("skipping invalid peer dep name: {dep_name:?}");
                                    continue;
                                }
                                ver_peers.insert(dep_name.clone(), dep_range.clone());
                            }
                            peer_deps.insert(ver_str.clone(), ver_peers);
                        }

                        // Store platform restrictions
                        if !ver_meta.os.is_empty() || !ver_meta.cpu.is_empty() {
                            platform.insert(
                                ver_str.clone(),
                                PlatformMeta {
                                    os: ver_meta.os.clone(),
                                    cpu: ver_meta.cpu.clone(),
                                },
                            );
                        }

                        versions.push(v);
                    }
                }

                versions.sort();
                versions.reverse(); // Newest first

                self.cache.borrow_mut().insert(
                    package.clone(),
                    CachedPackageInfo {
                        versions,
                        deps,
                        peer_deps,
                        optional_dep_names,
                        platform,
                        aggregated_peers: None,
                    },
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
                let mut platform: HashMap<String, PlatformMeta> = HashMap::new();

                for (ver_str, ver_meta) in &metadata.versions {
                    if !is_valid_version_string(ver_str) {
                        tracing::warn!("skipping invalid npm version string: {ver_str:?}");
                        continue;
                    }
                    if let Ok(v) = NpmVersion::parse(ver_str) {
                        // Skip pre-release versions for npm packages by default
                        if v.is_prerelease() {
                            continue;
                        }

                        let mut ver_deps = HashMap::new();
                        for (dep_name, dep_range) in &ver_meta.dependencies {
                            if !is_valid_dep_name(dep_name) {
                                tracing::warn!("skipping invalid npm dep name: {dep_name:?}");
                                continue;
                            }
                            ver_deps.insert(dep_name.clone(), dep_range.clone());
                        }

                        // Include optional deps but track them
                        let mut opt_names = HashSet::new();
                        for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                            if !is_valid_dep_name(dep_name) {
                                tracing::warn!(
                                    "skipping invalid npm optional dep name: {dep_name:?}"
                                );
                                continue;
                            }
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
                                if !is_valid_dep_name(dep_name) {
                                    tracing::warn!(
                                        "skipping invalid npm peer dep name: {dep_name:?}"
                                    );
                                    continue;
                                }
                                ver_peers.insert(dep_name.clone(), dep_range.clone());
                            }
                            peer_deps.insert(ver_str.clone(), ver_peers);
                        }

                        // Store platform restrictions
                        if !ver_meta.os.is_empty() || !ver_meta.cpu.is_empty() {
                            platform.insert(
                                ver_str.clone(),
                                PlatformMeta {
                                    os: ver_meta.os.clone(),
                                    cpu: ver_meta.cpu.clone(),
                                },
                            );
                        }

                        versions.push(v);
                    }
                }

                versions.sort();
                versions.reverse(); // Newest first

                tracing::debug!("npm package {name}: {} versions", versions.len());

                self.cache.borrow_mut().insert(
                    package.clone(),
                    CachedPackageInfo {
                        versions,
                        deps,
                        peer_deps,
                        optional_dep_names,
                        platform,
                        aggregated_peers: None,
                    },
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

    /// Get or compute the aggregated peer deps for a package.
    /// Uses newest-version-first priority for deterministic results, and caches
    /// the result so subsequent calls are O(1).
    fn get_aggregated_peers(&self, package: &ResolverPackage) -> HashMap<String, String> {
        // Check if already cached
        {
            let cache = self.cache.borrow();
            if let Some(info) = cache.get(package)
                && let Some(ref cached) = info.aggregated_peers
            {
                return cached.clone();
            }
        }

        // Compute: sort versions descending so newest wins
        let aggregated = {
            let cache = self.cache.borrow();
            let Some(info) = cache.get(package) else {
                return HashMap::new();
            };

            let mut sorted_versions: Vec<&String> = info.peer_deps.keys().collect();
            sorted_versions.sort_unstable_by(|a, b| {
                // Parse as NpmVersion for proper semver comparison, fall back to string
                match (NpmVersion::parse(a), NpmVersion::parse(b)) {
                    (Ok(va), Ok(vb)) => vb.cmp(&va), // newest first
                    _ => b.cmp(a),
                }
            });

            let mut peers: HashMap<String, String> = HashMap::new();
            for ver_str in sorted_versions {
                if let Some(ver_peers) = info.peer_deps.get(ver_str) {
                    for (peer_name, peer_range) in ver_peers {
                        peers
                            .entry(peer_name.clone())
                            .or_insert_with(|| peer_range.clone());
                    }
                }
            }
            peers
        };

        // Cache the result
        {
            let mut cache = self.cache.borrow_mut();
            if let Some(info) = cache.get_mut(package) {
                info.aggregated_peers = Some(aggregated.clone());
            }
        }

        aggregated
    }
}

/// Validate a dependency name from registry metadata.
/// Rejects path traversal, null bytes, excessive length, and invalid formats.
fn is_valid_dep_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    if name.contains('\0') || name.contains("..") {
        return false;
    }
    // Scoped packages: @scope/name
    if name.starts_with('@') {
        let Some(slash_pos) = name.find('/') else {
            return false;
        };
        let scope = &name[1..slash_pos]; // strip the leading '@'
        let pkg = &name[slash_pos + 1..];
        return !scope.is_empty() && !pkg.is_empty() && !pkg.contains('/') && !pkg.contains('\\');
    }
    // Unscoped: no path separators
    !name.contains('/') && !name.contains('\\')
}

/// Validate a version string from registry metadata.
/// Must contain only semver-compatible characters.
fn is_valid_version_string(v: &str) -> bool {
    if v.is_empty() || v.len() > 256 {
        return false;
    }
    v.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// Compile-time platform detection for the current build target.
///
/// NOTE: Platform detection uses compile-time cfg!() macros.
/// This resolves for the current build target only.
/// To support cross-platform resolution (e.g., `lpm install --platform=linux-x64`),
/// this would need to be changed to runtime detection with an overridable parameter.
/// See: https://docs.npmjs.com/cli/v9/commands/npm-install#os
pub(crate) struct Platform {
    pub os: &'static str,
    pub cpu: &'static str,
}

impl Platform {
    pub fn current() -> Self {
        Self {
            os: if cfg!(target_os = "macos") {
                "darwin"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "windows") {
                "win32"
            } else if cfg!(target_os = "freebsd") {
                "freebsd"
            } else {
                "unknown"
            },
            cpu: if cfg!(target_arch = "x86_64") {
                "x64"
            } else if cfg!(target_arch = "aarch64") {
                "arm64"
            } else if cfg!(target_arch = "x86") {
                "ia32"
            } else if cfg!(target_arch = "arm") {
                "arm"
            } else {
                "unknown"
            },
        }
    }
}

/// Check if a platform filter matches, following npm's semantics.
///
/// Platform filtering follows npm's semantics:
/// - If ANY entry starts with '!', the filter is treated as exclusion-only
///   e.g., `["darwin", "!win32"]` → exclusion mode → only "!win32" matters, "darwin" is ignored
/// - If no entries start with '!', the filter is treated as inclusion
///   e.g., `["darwin", "linux"]` → only these platforms are allowed
///
/// This matches npm's behavior: <https://docs.npmjs.com/cli/v9/configuring-npm/package-json#os>
fn check_platform_filter(entries: &[String], current: &str, field_name: &str) -> bool {
    if entries.is_empty() {
        return true;
    }

    let has_exclusions = entries.iter().any(|e| e.starts_with('!'));
    let has_inclusions = entries.iter().any(|e| !e.starts_with('!'));

    if has_exclusions && has_inclusions {
        tracing::debug!(
            "mixed include/exclude in {field_name} filter: {entries:?} — using exclusion mode (positive entries ignored)"
        );
    }

    if has_exclusions {
        // Exclusion mode: ALL exclusions must not match
        entries.iter().all(|e| {
            if let Some(stripped) = e.strip_prefix('!') {
                stripped != current
            } else {
                true
            }
        })
    } else {
        // Inclusion mode: at least one must match
        entries.iter().any(|e| e == current)
    }
}

/// Check if a package version is compatible with the current platform.
/// Empty os/cpu means no restriction (compatible with all platforms).
/// Entries starting with `!` are exclusions (e.g., `!win32` = all except win32).
fn is_platform_compatible(meta: &PlatformMeta) -> bool {
    let platform = Platform::current();
    let os_ok = check_platform_filter(&meta.os, platform.os, "os");
    let cpu_ok = check_platform_filter(&meta.cpu, platform.cpu, "cpu");
    os_ok && cpu_ok
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
        if let Some(forced_ver) = self.overrides.get(&canonical)
            && let Ok(v) = NpmVersion::parse(forced_ver)
            && range.contains(&v)
        {
            tracing::debug!("override: {canonical} forced to {forced_ver}");
            return Ok(Some(v));
        }

        let cache = self.cache.borrow();
        let info = match cache.get(package) {
            Some(info) => info,
            None => return Ok(None),
        };

        // Return newest version that satisfies the range AND is platform-compatible
        // (versions are newest-first)
        for version in &info.versions {
            if !range.contains(version) {
                continue;
            }

            // Skip versions incompatible with the current platform
            if let Some(platform_meta) = info.platform.get(&version.to_string())
                && !is_platform_compatible(platform_meta)
            {
                tracing::debug!(
                    "skipping {}@{}: platform incompatible (os: {:?}, cpu: {:?})",
                    package.canonical_name(),
                    version,
                    platform_meta.os,
                    platform_meta.cpu
                );
                continue;
            }

            return Ok(Some(version.clone()));
        }
        Ok(None)
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

                let npm_range =
                    NpmRange::parse(dep_range_str).map_err(ProviderError::InvalidRange)?;

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
        //
        // We take the UNION of peer deps across ALL versions of each dependency,
        // sorted newest-first for deterministic tiebreaking. Result is cached per package.
        let peer_constraints: Vec<(String, String)> = ver_deps
            .keys()
            .flat_map(|dep_name| {
                let dep_pkg = ResolverPackage::from_dep_name(dep_name);
                let peers = self.get_aggregated_peers(&dep_pkg);
                peers.into_iter().collect::<Vec<_>>()
            })
            .collect();

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
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        constraints.entry(peer_pkg)
                    {
                        e.insert(range);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Finding #2: Validation tests ===

    #[test]
    fn valid_dep_names() {
        assert!(is_valid_dep_name("express"));
        assert!(is_valid_dep_name("@scope/name"));
        assert!(is_valid_dep_name("lodash"));
        assert!(is_valid_dep_name("@lpm.dev/neo.highlight"));
        assert!(is_valid_dep_name("my-package"));
        assert!(is_valid_dep_name("a"));
    }

    #[test]
    fn invalid_dep_names() {
        assert!(!is_valid_dep_name(""));
        assert!(!is_valid_dep_name("../../../etc"));
        assert!(!is_valid_dep_name("a\0b"));
        assert!(!is_valid_dep_name(&"a".repeat(300)));
        assert!(!is_valid_dep_name("foo/bar")); // unscoped with slash
        assert!(!is_valid_dep_name("foo\\bar"));
        assert!(!is_valid_dep_name("@scope")); // missing /name
        assert!(!is_valid_dep_name("@/name")); // empty scope
        assert!(!is_valid_dep_name("@scope/")); // empty name
        assert!(!is_valid_dep_name("foo..bar")); // contains ..
    }

    #[test]
    fn valid_version_strings() {
        assert!(is_valid_version_string("1.0.0"));
        assert!(is_valid_version_string("1.0.0-beta.1"));
        assert!(is_valid_version_string("1.0.0+build.123"));
    }

    #[test]
    fn invalid_version_strings() {
        assert!(!is_valid_version_string(""));
        assert!(!is_valid_version_string(&"1".repeat(300)));
        assert!(!is_valid_version_string("1.0.0; rm -rf /"));
        assert!(!is_valid_version_string("1.0.0\0"));
    }

    // === Finding #1 & #3: Deterministic peer dep aggregation + caching ===

    #[test]
    fn aggregated_peers_newest_version_wins() {
        // Create a CachedPackageInfo with two versions having different peer ranges
        let mut peer_deps = HashMap::new();
        let mut v1_peers = HashMap::new();
        v1_peers.insert("react".to_string(), "^16".to_string());
        peer_deps.insert("1.0.0".to_string(), v1_peers);

        let mut v2_peers = HashMap::new();
        v2_peers.insert("react".to_string(), "^18".to_string());
        peer_deps.insert("2.0.0".to_string(), v2_peers);

        let info = CachedPackageInfo {
            versions: vec![
                NpmVersion::parse("2.0.0").unwrap(),
                NpmVersion::parse("1.0.0").unwrap(),
            ],
            deps: HashMap::new(),
            peer_deps,
            optional_dep_names: HashMap::new(),
            platform: HashMap::new(),
            aggregated_peers: None,
        };

        let pkg = ResolverPackage::npm("test-pkg");
        // Build a minimal provider with this info pre-cached
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
        provider.cache.borrow_mut().insert(pkg.clone(), info);

        // First call computes
        let peers = provider.get_aggregated_peers(&pkg);
        assert_eq!(
            peers.get("react").unwrap(),
            "^18",
            "newest version (2.0.0) should win"
        );

        // Second call should use cache (verify it's populated)
        {
            let cache = provider.cache.borrow();
            let cached_info = cache.get(&pkg).unwrap();
            assert!(
                cached_info.aggregated_peers.is_some(),
                "should be cached after first call"
            );
        }

        // Run again — deterministic
        let peers2 = provider.get_aggregated_peers(&pkg);
        assert_eq!(peers, peers2, "must be deterministic across calls");
    }

    // === Finding #7: Mixed include/exclude in os/cpu ===

    #[test]
    fn platform_filter_inclusion_only() {
        let entries = vec!["darwin".to_string(), "linux".to_string()];
        assert!(check_platform_filter(&entries, "darwin", "os"));
        assert!(check_platform_filter(&entries, "linux", "os"));
        assert!(!check_platform_filter(&entries, "win32", "os"));
    }

    #[test]
    fn platform_filter_exclusion_only() {
        let entries = vec!["!win32".to_string()];
        assert!(check_platform_filter(&entries, "darwin", "os"));
        assert!(check_platform_filter(&entries, "linux", "os"));
        assert!(!check_platform_filter(&entries, "win32", "os"));
    }

    /// Finding #7: Mixed include/exclude entries enter exclusion mode (npm behavior).
    /// The positive "darwin" entry is IGNORED — only "!win32" matters.
    /// On macOS this is compatible because the current OS is not excluded by "!win32".
    #[test]
    fn platform_filter_mixed_uses_exclusion_mode() {
        let entries = vec!["darwin".to_string(), "!win32".to_string()];
        // Exclusion mode: "darwin" positive entry is ignored, only "!win32" matters
        assert!(
            check_platform_filter(&entries, "darwin", "os"),
            "darwin not excluded by !win32"
        );
        assert!(
            check_platform_filter(&entries, "linux", "os"),
            "linux not excluded by !win32"
        );
        assert!(
            !check_platform_filter(&entries, "win32", "os"),
            "win32 excluded by !win32"
        );
    }

    #[test]
    fn platform_filter_empty_allows_all() {
        let entries: Vec<String> = vec![];
        assert!(check_platform_filter(&entries, "anything", "os"));
    }

    #[test]
    fn platform_compatible_no_restrictions() {
        let meta = PlatformMeta {
            os: vec![],
            cpu: vec![],
        };
        assert!(is_platform_compatible(&meta));
    }

    // === Finding #8: Platform struct returns known values ===

    #[test]
    fn platform_current_returns_known_values() {
        let p = Platform::current();
        let known_os = ["darwin", "linux", "win32", "freebsd"];
        let known_cpu = ["x64", "arm64", "ia32", "arm"];
        // On CI/dev machines, we should always get a known value (not "unknown")
        assert!(known_os.contains(&p.os), "expected known OS, got: {}", p.os);
        assert!(
            known_cpu.contains(&p.cpu),
            "expected known CPU, got: {}",
            p.cpu
        );
    }
}
