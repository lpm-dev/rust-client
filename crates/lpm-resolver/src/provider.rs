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

/// Distribution info for a specific version: tarball URL and integrity hash.
/// Extracted from registry metadata so the download phase doesn't need to
/// re-fetch metadata just to get the URL.
#[derive(Debug, Clone, Default)]
pub struct CachedDistInfo {
    pub tarball_url: Option<String>,
    pub integrity: Option<String>,
}

/// Cached info about a package: available versions and their dependency maps.
#[derive(Debug, Clone)]
pub struct CachedPackageInfo {
    /// Available versions, sorted descending (newest first).
    pub versions: Vec<NpmVersion>,
    /// Regular dependencies for each version: version_string → { dep_name → range_string }.
    pub deps: HashMap<String, HashMap<String, String>>,
    /// Peer dependencies for each version: version_string → { dep_name → range_string }.
    /// Checked post-resolution against the actual resolved tree (not during resolution).
    pub peer_deps: HashMap<String, HashMap<String, String>>,
    /// Optional dependency names (per version). Included in deps but resolution failure
    /// for these is non-fatal.
    pub optional_dep_names: HashMap<String, HashSet<String>>,
    /// Platform restrictions per version: version_string → PlatformMeta.
    /// Only populated for versions that declare os/cpu restrictions.
    pub platform: HashMap<String, PlatformMeta>,
    /// Distribution info per version: tarball URL and integrity hash.
    /// Carried through to the download phase to avoid re-fetching metadata.
    pub dist: HashMap<String, CachedDistInfo>,
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

    /// Pre-populate the in-memory cache from a previous resolver run.
    /// Used to carry Phase 1's metadata into Phase 2 (split resolution),
    /// avoiding redundant disk reads and metadata parsing.
    pub fn with_cache(mut self, cache: HashMap<ResolverPackage, CachedPackageInfo>) -> Self {
        self.cache = RefCell::new(cache);
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
                let mut dist_info: HashMap<String, CachedDistInfo> = HashMap::new();

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

                        // Store dist info for download phase
                        dist_info.insert(
                            ver_str.clone(),
                            CachedDistInfo {
                                tarball_url: ver_meta.tarball_url().map(str::to_string),
                                integrity: ver_meta.integrity().map(str::to_string),
                            },
                        );

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

                        dist: dist_info,
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
                let mut dist_info: HashMap<String, CachedDistInfo> = HashMap::new();

                for (ver_str, ver_meta) in &metadata.versions {
                    if !is_valid_version_string(ver_str) {
                        tracing::warn!("skipping invalid npm version string: {ver_str:?}");
                        continue;
                    }
                    if let Ok(v) = NpmVersion::parse(ver_str) {
                        // Skip pre-release versions for npm packages by default.
                        //
                        // Design decision: LPM packages include prereleases because
                        // authors publish them intentionally (e.g., 1.0.0-beta.1).
                        // npm packages skip prereleases because the npm upstream has
                        // many noisy prereleases that would pollute resolution and
                        // cause unexpected version selection.
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

                        // Store dist info for download phase
                        dist_info.insert(
                            ver_str.clone(),
                            CachedDistInfo {
                                tarball_url: ver_meta.tarball_url().map(str::to_string),
                                integrity: ver_meta.integrity().map(str::to_string),
                            },
                        );

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

                        dist: dist_info,
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
        if let Some(forced_ver) = self.overrides.get(&canonical) {
            match NpmVersion::parse(forced_ver) {
                Ok(v) if range.contains(&v) => {
                    tracing::debug!("override: {canonical} forced to {forced_ver}");
                    return Ok(Some(v));
                }
                Ok(_) => {
                    tracing::warn!(
                        "override {canonical}@{forced_ver} does not satisfy requested range — override ignored"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "override {canonical}@{forced_ver} has invalid version: {e} — override ignored"
                    );
                }
            }
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
            // Batch-prefetch root deps missing from BOTH in-memory and disk cache.
            // The initial batch_metadata_deep in install.rs covers most deps, so
            // this only fires when there are genuine cache misses (e.g., initial
            // batch failed or was incomplete).
            {
                let cache = self.cache.borrow();
                let uncached: Vec<String> = self
                    .root_deps
                    .keys()
                    .filter(|name| {
                        let pkg = ResolverPackage::from_dep_name(name);
                        !cache.contains_key(&pkg) && !self.client.is_metadata_fresh(name)
                    })
                    .cloned()
                    .collect();
                drop(cache);

                if uncached.len() > 1 {
                    match self.rt.block_on(self.client.batch_metadata(&uncached)) {
                        Ok(batch) => {
                            tracing::debug!(
                                "root batch prefetch: {} uncached → {} fetched",
                                uncached.len(),
                                batch.len()
                            );
                        }
                        Err(e) => {
                            tracing::debug!("root batch prefetch failed (non-fatal): {e}");
                        }
                    }
                }
            }

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

        // Batch-prefetch deps missing from BOTH in-memory and disk cache.
        // Checks disk freshness via stat() (microseconds) to avoid redundant HTTP
        // requests for packages the initial batch_metadata_deep already cached.
        // Only fires when 2+ deps are genuine network misses.
        {
            let cache = self.cache.borrow();
            let uncached: Vec<String> = ver_deps
                .keys()
                .filter(|name| {
                    let pkg = ResolverPackage::from_dep_name(name);
                    !cache.contains_key(&pkg) && !self.client.is_metadata_fresh(name)
                })
                .cloned()
                .collect();
            drop(cache); // Release borrow before block_on

            if uncached.len() > 1 {
                match self.rt.block_on(self.client.batch_metadata(&uncached)) {
                    Ok(batch) => {
                        tracing::debug!(
                            "dep batch prefetch for {parent_name}: {} uncached → {} fetched",
                            uncached.len(),
                            batch.len()
                        );
                    }
                    Err(e) => {
                        // Non-fatal: loop below falls back to individual ensure_cached() calls
                        tracing::debug!("dep batch prefetch failed (non-fatal): {e}");
                    }
                }
            }
        }

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

        // Peer dependencies are NOT propagated as constraints during resolution.
        // Instead, they are checked post-resolution against the actual resolved tree.
        // This avoids the over-constraint problem where union-across-all-versions
        // peer deps could force incompatible requirements (e.g., styled-components@5
        // peers react@^16 but styled-components@6 peers react@^18 — union would
        // force react@^18, breaking projects using v5).
        //
        // See resolve.rs: check_unmet_peers() for the post-resolution check.

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

    // === Peer deps are stored per-version in cache for post-resolution checking ===

    #[test]
    fn peer_deps_stored_per_version() {
        // Verify that peer deps are stored separately per version in CachedPackageInfo,
        // so post-resolution check_unmet_peers() can look up the exact version's peers.
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
            dist: HashMap::new(),
        };

        // Version 1.0.0 peers on react@^16
        let v1_peers = info.peer_deps.get("1.0.0").unwrap();
        assert_eq!(v1_peers.get("react").unwrap(), "^16");

        // Version 2.0.0 peers on react@^18
        let v2_peers = info.peer_deps.get("2.0.0").unwrap();
        assert_eq!(v2_peers.get("react").unwrap(), "^18");

        // They are independent — no union, no aggregation
        assert_ne!(
            v1_peers.get("react").unwrap(),
            v2_peers.get("react").unwrap(),
            "per-version peers must not be merged"
        );
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

    // === Helper: build a provider with pre-populated cache (no network) ===

    fn make_provider_with_cache(
        root_deps: HashMap<String, String>,
        cache_entries: Vec<(ResolverPackage, CachedPackageInfo)>,
    ) -> LpmDependencyProvider {
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), root_deps);
        for (pkg, info) in cache_entries {
            provider.cache.borrow_mut().insert(pkg, info);
        }
        provider
    }

    fn make_info(
        versions: &[&str],
        deps: Vec<(&str, Vec<(&str, &str)>)>,
        optional_names: Vec<(&str, Vec<&str>)>,
        platform: Vec<(&str, Vec<&str>, Vec<&str>)>,
    ) -> CachedPackageInfo {
        CachedPackageInfo {
            versions: versions
                .iter()
                .filter_map(|v| NpmVersion::parse(v).ok())
                .collect(),
            deps: deps
                .into_iter()
                .map(|(v, d)| {
                    (
                        v.to_string(),
                        d.into_iter()
                            .map(|(k, r)| (k.to_string(), r.to_string()))
                            .collect(),
                    )
                })
                .collect(),
            peer_deps: HashMap::new(),
            optional_dep_names: optional_names
                .into_iter()
                .map(|(v, names)| {
                    (
                        v.to_string(),
                        names.into_iter().map(|n| n.to_string()).collect(),
                    )
                })
                .collect(),
            platform: platform
                .into_iter()
                .map(|(v, os, cpu)| {
                    (
                        v.to_string(),
                        PlatformMeta {
                            os: os.into_iter().map(|s| s.to_string()).collect(),
                            cpu: cpu.into_iter().map(|s| s.to_string()).collect(),
                        },
                    )
                })
                .collect(),
            dist: HashMap::new(),
        }
    }

    // === choose_version: override warning behavior ===

    #[test]
    fn choose_version_override_in_range_applies() {
        let pkg = ResolverPackage::npm("lodash");
        let info = make_info(&["4.17.21", "4.17.20", "4.17.19"], vec![], vec![], vec![]);

        let mut overrides = HashMap::new();
        overrides.insert("lodash".to_string(), "4.17.20".to_string());

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(overrides);
        provider.cache.borrow_mut().insert(pkg.clone(), info);

        // Range ^4.17.0 — override 4.17.20 is in range → should be selected
        let range = NpmRange::parse("^4.17.0")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));
        let chosen = provider.choose_version(&pkg, &range).unwrap();
        assert_eq!(
            chosen.map(|v| v.to_string()),
            Some("4.17.20".to_string()),
            "override 4.17.20 should be selected over newest 4.17.21"
        );
    }

    #[test]
    fn choose_version_override_out_of_range_ignored() {
        // Override specifies 3.0.0 but range requires ^4.0.0 → override ignored,
        // newest matching version selected instead
        let pkg = ResolverPackage::npm("lodash");
        let info = make_info(&["4.17.21", "4.17.20", "3.0.0"], vec![], vec![], vec![]);

        let mut overrides = HashMap::new();
        overrides.insert("lodash".to_string(), "3.0.0".to_string());

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(overrides);
        provider.cache.borrow_mut().insert(pkg.clone(), info);

        let range = NpmRange::parse("^4.17.0")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));
        let chosen = provider.choose_version(&pkg, &range).unwrap();
        assert_eq!(
            chosen.map(|v| v.to_string()),
            Some("4.17.21".to_string()),
            "out-of-range override should be ignored, newest matching version selected"
        );
    }

    // === choose_version: platform filtering skips incompatible, selects next ===

    #[test]
    fn choose_version_skips_incompatible_platform_selects_next() {
        // 3 versions: 1.3.0 (win32-only), 1.2.0 (no restriction), 1.1.0 (no restriction)
        // On non-win32: should skip 1.3.0 and select 1.2.0
        let pkg = ResolverPackage::npm("win-pkg");
        let info = make_info(
            &["1.3.0", "1.2.0", "1.1.0"],
            vec![],
            vec![],
            vec![("1.3.0", vec!["win32"], vec![])],
        );

        let provider = make_provider_with_cache(HashMap::new(), vec![(pkg.clone(), info)]);
        let range = NpmRange::parse("^1.0.0")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));

        let chosen = provider.choose_version(&pkg, &range).unwrap();
        let current_os = Platform::current().os;

        if current_os == "win32" {
            assert_eq!(
                chosen.map(|v| v.to_string()),
                Some("1.3.0".to_string()),
                "on win32, 1.3.0 should be compatible and selected"
            );
        } else {
            assert_eq!(
                chosen.map(|v| v.to_string()),
                Some("1.2.0".to_string()),
                "on non-win32, 1.3.0 should be skipped, 1.2.0 selected"
            );
        }
    }

    #[test]
    fn choose_version_all_incompatible_returns_none() {
        // All versions are win32-only → on non-win32, should return None
        let pkg = ResolverPackage::npm("win-only");
        let info = make_info(
            &["2.0.0", "1.0.0"],
            vec![],
            vec![],
            vec![
                ("2.0.0", vec!["win32"], vec![]),
                ("1.0.0", vec!["win32"], vec![]),
            ],
        );

        let provider = make_provider_with_cache(HashMap::new(), vec![(pkg.clone(), info)]);
        let range = NpmRange::parse("*")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));

        let chosen = provider.choose_version(&pkg, &range).unwrap();
        let current_os = Platform::current().os;

        if current_os != "win32" {
            assert!(
                chosen.is_none(),
                "on non-win32, all win32-only versions should be skipped"
            );
        }
    }

    // === get_dependencies: optional deps skip on failure ===

    #[test]
    fn get_dependencies_includes_optional_deps_when_cached() {
        // Package with both regular and optional deps — both present in cache
        let pkg = ResolverPackage::npm("my-app");
        let opt_dep = ResolverPackage::npm("fsevents");
        let reg_dep = ResolverPackage::npm("express");

        let pkg_info = make_info(
            &["1.0.0"],
            vec![("1.0.0", vec![("express", "^4.0.0"), ("fsevents", "^2.0.0")])],
            vec![("1.0.0", vec!["fsevents"])],
            vec![],
        );
        let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
        let fsevents_info = make_info(&["2.3.0"], vec![], vec![], vec![]);

        let provider = make_provider_with_cache(
            HashMap::new(),
            vec![
                (pkg.clone(), pkg_info),
                (reg_dep, express_info),
                (opt_dep, fsevents_info),
            ],
        );

        let deps = provider
            .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
            .unwrap();

        match deps {
            Dependencies::Available(map) => {
                assert!(
                    map.contains_key(&ResolverPackage::npm("express")),
                    "regular dep should be present"
                );
                assert!(
                    map.contains_key(&ResolverPackage::npm("fsevents")),
                    "optional dep should be present when available in cache"
                );
            }
            _ => panic!("expected Available dependencies"),
        }
    }

    #[test]
    fn get_dependencies_skips_optional_with_no_versions() {
        // Package has optional dep "fsevents" but fsevents has no compatible versions
        // (e.g., all versions are platform-incompatible → empty version list)
        let pkg = ResolverPackage::npm("my-app");
        let opt_dep = ResolverPackage::npm("fsevents");
        let reg_dep = ResolverPackage::npm("express");

        let pkg_info = make_info(
            &["1.0.0"],
            vec![("1.0.0", vec![("express", "^4.0.0"), ("fsevents", "^2.0.0")])],
            vec![("1.0.0", vec!["fsevents"])],
            vec![],
        );
        let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
        // fsevents has NO versions (simulates platform-filtered-out)
        let fsevents_info = make_info(&[], vec![], vec![], vec![]);

        let provider = make_provider_with_cache(
            HashMap::new(),
            vec![
                (pkg.clone(), pkg_info),
                (reg_dep, express_info),
                (opt_dep, fsevents_info),
            ],
        );

        let deps = provider
            .get_dependencies(&pkg, &NpmVersion::parse("1.0.0").unwrap())
            .unwrap();

        match deps {
            Dependencies::Available(map) => {
                assert!(
                    map.contains_key(&ResolverPackage::npm("express")),
                    "regular dep should be present"
                );
                assert!(
                    !map.contains_key(&ResolverPackage::npm("fsevents")),
                    "optional dep with no versions should be silently skipped"
                );
            }
            _ => panic!("expected Available dependencies"),
        }
    }
}
