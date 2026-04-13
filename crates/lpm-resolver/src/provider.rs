//! PubGrub DependencyProvider implementation for LPM.
//!
//! Bridges PubGrub's resolution algorithm with the LPM/npm registries.
//!
//! Resolver compatibility: peerDeps, optionalDeps, overrides, workspace:*, platform filtering.
//! See phase-17-todo.md.

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
use crate::package::ResolverPackage;
use crate::ranges::NpmRange;
use crate::streaming::StreamingPrefetch;
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
    /// Phase 32 Phase 5 — fully-parsed override IR. Records every applied
    /// override into its internal `RefCell<Vec<OverrideHit>>` so callers
    /// can drain the trace after `pubgrub::resolve` returns. Always
    /// present (defaults to `OverrideSet::empty()` when no overrides
    /// are declared in `package.json`).
    overrides: OverrideSet,
    /// Phase 34.5: set after the first batch_metadata call fails (e.g., 401).
    /// Prevents repeated guaranteed-failing batch requests during resolution.
    /// Individual ensure_cached calls still work as fallback.
    batch_disabled: RefCell<bool>,
    /// Phase 36: install-path streaming prefetch. Populated concurrently by
    /// the batch producer in install.rs. `None` for non-install callers.
    streaming: Option<Arc<StreamingPrefetch>>,
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
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            streaming: None,
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
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            streaming: None,
        }
    }

    /// Phase 32 Phase 5 — install the fully-parsed override set. The set
    /// is owned by the provider for the duration of resolution; the
    /// resolver records every applied override into its internal hits
    /// buffer.
    ///
    /// **Important**: any package targeted by a path-selector override
    /// MUST also be in the `split_packages` set so PubGrub creates the
    /// per-parent identities the lookup expects. Callers can use
    /// [`OverrideSet::split_targets`] to seed the split set, then call
    /// `with_overrides` here. The two-step is intentional — keeping the
    /// split set passed at construction time preserves the existing
    /// API surface used by the two-phase resolver.
    pub fn with_overrides(mut self, overrides: OverrideSet) -> Self {
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

    /// Phase 36: attach a streaming prefetch cache for install-path
    /// batch/resolve overlap. The streaming cache is populated concurrently
    /// by the install orchestrator while the resolver runs. Non-install
    /// callers should not call this — provider batching at lines 705/790
    /// serves as the generic fallback.
    pub fn with_streaming_prefetch(mut self, streaming: Arc<StreamingPrefetch>) -> Self {
        self.streaming = Some(streaming);
        self
    }

    /// Pre-seed the in-memory cache from batch-prefetched metadata.
    ///
    /// Phase 34.5 #1: the batch prefetch in `install.rs` returns
    /// `HashMap<String, PackageMetadata>`. Passing it here avoids 52+
    /// disk reads during resolution — the provider checks in-memory first.
    pub fn with_prefetched_metadata(
        self,
        batch: &HashMap<String, lpm_registry::PackageMetadata>,
    ) -> Self {
        let mut cache = self.cache.into_inner();
        for (name, metadata) in batch {
            let package = ResolverPackage::from_dep_name(name);
            if cache.contains_key(&package) {
                continue; // Don't overwrite existing cache entries
            }
            let is_npm = !name.starts_with("@lpm.dev/");
            let info = parse_metadata_to_cache_info(metadata, is_npm);
            cache.insert(package, info);
        }
        Self {
            cache: RefCell::new(cache),
            ..self
        }
    }

    /// Ensure package metadata is cached. Fetches from registry if needed.
    ///
    /// For split packages (with context), we first check if the canonical
    /// (contextless) version is cached, then copy its data under the split key.
    fn ensure_cached(&self, package: &ResolverPackage) -> Result<(), ProviderError> {
        if package.is_root() || self.cache.borrow().contains_key(package) {
            return Ok(());
        }

        // Phase 36: non-blocking check against the streaming prefetch cache.
        // Catches the singleton case where uncached.len() == 1 and the
        // batch-decision blocks above were skipped, but the streaming
        // producer has already delivered this package.
        if let Some(ref streaming) = self.streaming {
            let canonical_name = package.canonical_name();
            if let Some(info) = streaming.get(&canonical_name) {
                self.cache.borrow_mut().insert(package.clone(), info);
                return Ok(());
            }
        }

        let _span = tracing::debug_span!("ensure_cached", pkg = %package).entered();
        let _prof = crate::profile::ensure_cached::start();

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

                // Phase 34.5: use shared parser (LPM packages include prereleases)
                let info = parse_metadata_to_cache_info(&metadata, false);
                self.cache.borrow_mut().insert(package.clone(), info);
                Ok(())
            }
            ResolverPackage::Npm { name, .. } => {
                let metadata = self
                    .rt
                    .block_on(self.client.get_npm_package_metadata(name))
                    .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;

                // Phase 34.5: use shared parser (npm packages skip prereleases)
                let info = parse_metadata_to_cache_info(&metadata, true);
                tracing::debug!("npm package {name}: {} versions", info.versions.len());
                self.cache.borrow_mut().insert(package.clone(), info);
                Ok(())
            }
        }
    }

    /// Get the list of available versions for a package (from cache).
    fn available_versions(&self, package: &ResolverPackage) -> Vec<NpmVersion> {
        let _span = tracing::debug_span!("available_versions", pkg = %package).entered();
        let _prof = crate::profile::available_versions::start();
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

    /// Phase 32 Phase 5 — extract the override hits AND the metadata
    /// cache in one shot. The two-stage `take_override_hits()` /
    /// `into_cache()` API is also available for callers that need only
    /// one of the two.
    pub fn into_parts(
        self,
    ) -> (
        HashMap<ResolverPackage, CachedPackageInfo>,
        Vec<OverrideHit>,
    ) {
        let hits = self.overrides.take_hits();
        (self.cache.into_inner(), hits)
    }

    /// Phase 32 Phase 5 — pick the version the resolver would choose
    /// WITHOUT any override applied. Returns the newest version in the
    /// consumer's declared range that is platform-compatible.
    ///
    /// Factored out of [`Self::choose_version`] so the override path
    /// can compute `from_version` for the apply trace AND fall back to
    /// this same value when no override matches.
    fn pick_natural_version(
        &self,
        package: &ResolverPackage,
        range: &Ranges<NpmVersion>,
    ) -> Option<NpmVersion> {
        let cache = self.cache.borrow();
        let info = cache.get(package)?;

        // Versions are sorted newest-first; first match wins.
        for version in &info.versions {
            if !range.contains(version) {
                continue;
            }

            if let Some(platform_meta) = info.platform.get(&version.to_string())
                && !is_platform_compatible(platform_meta)
            {
                tracing::debug!(
                    "pick_natural_version skipping {}@{}: platform incompatible (os: {:?}, cpu: {:?})",
                    package.canonical_name(),
                    version,
                    platform_meta.os,
                    platform_meta.cpu
                );
                continue;
            }

            return Some(version.clone());
        }
        None
    }

    /// Phase 32 Phase 5 — apply an [`OverrideTarget`] against the
    /// consumer's PubGrub `range` to produce a final forced version.
    ///
    /// - `PinnedVersion` returns the pinned version verbatim, but ONLY
    ///   if it satisfies the consumer's declared range. The Phase 5
    ///   contract is that we never pick a version the consumer didn't
    ///   ask for and silently pretend it works — out-of-range pinned
    ///   targets return `None` so [`Self::choose_version`] surfaces
    ///   them as a debug-level warning today.
    /// - `Range` intersects the override range with the consumer range
    ///   (via the cache's available versions list for THIS package)
    ///   and picks the newest match. The intersect-then-pick semantics
    ///   matches pnpm's range-target behavior: a `^2.0.0` override
    ///   means "use the newest 2.x", not "force `2.0.0`".
    fn apply_override_target(
        &self,
        package: &ResolverPackage,
        target: &OverrideTarget,
        range: &Ranges<NpmVersion>,
    ) -> Option<NpmVersion> {
        match target {
            OverrideTarget::PinnedVersion { version, .. } => {
                if range.contains(version) {
                    Some(version.clone())
                } else {
                    None
                }
            }
            OverrideTarget::Range {
                range: target_range,
                ..
            } => {
                // Walk THIS package's cached versions only — the cache
                // is keyed by ResolverPackage so we look up by identity.
                // For each candidate version in the consumer's range,
                // check the override range and platform constraints.
                let cache = self.cache.borrow();
                let info = cache.get(package)?;
                for v in &info.versions {
                    // versions are sorted newest-first, so the first
                    // match is the newest match.
                    if !range.contains(v) {
                        continue;
                    }
                    if !target_range.satisfies(v) {
                        continue;
                    }
                    if let Some(platform_meta) = info.platform.get(&v.to_string())
                        && !is_platform_compatible(platform_meta)
                    {
                        continue;
                    }
                    return Some(v.clone());
                }
                None
            }
        }
    }
}

/// Phase 34.5: shared metadata → CachedPackageInfo parser.
///
/// Extracts versions, deps, peer_deps, optional_deps, platform, and dist
/// from a `PackageMetadata` response. Used by `ensure_cached` (for
/// single-package fetches), `with_prefetched_metadata` (for batch), and
/// Phase 36 streaming prefetch (called from `lpm-cli` install orchestrator).
///
/// `skip_prerelease`: true for npm packages (noisy prereleases), false for LPM.
pub fn parse_metadata_to_cache_info(
    metadata: &lpm_registry::PackageMetadata,
    skip_prerelease: bool,
) -> CachedPackageInfo {
    let version_count = metadata.versions.len();
    let mut versions: Vec<NpmVersion> = Vec::with_capacity(version_count);
    let mut deps: HashMap<String, HashMap<String, String>> = HashMap::with_capacity(version_count);
    let mut peer_deps: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut optional_dep_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut platform: HashMap<String, PlatformMeta> = HashMap::new();
    let mut dist_info: HashMap<String, CachedDistInfo> = HashMap::with_capacity(version_count);

    for (ver_str, ver_meta) in &metadata.versions {
        if !is_valid_version_string(ver_str) {
            tracing::warn!("skipping invalid version string: {ver_str:?}");
            continue;
        }
        if let Ok(v) = NpmVersion::parse(ver_str) {
            if skip_prerelease && v.is_prerelease() {
                continue;
            }

            let mut ver_deps = HashMap::new();
            for (dep_name, dep_range) in &ver_meta.dependencies {
                if !is_valid_dep_name(dep_name) {
                    tracing::warn!("skipping invalid dep name: {dep_name:?}");
                    continue;
                }
                ver_deps.insert(dep_name.clone(), dep_range.clone());
            }

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

            if !ver_meta.os.is_empty() || !ver_meta.cpu.is_empty() {
                platform.insert(
                    ver_str.clone(),
                    PlatformMeta {
                        os: ver_meta.os.clone(),
                        cpu: ver_meta.cpu.clone(),
                    },
                );
            }

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

    CachedPackageInfo {
        versions,
        deps,
        peer_deps,
        optional_dep_names,
        platform,
        dist: dist_info,
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

        let _span = tracing::debug_span!("choose_version", pkg = %package).entered();
        let _prof = crate::profile::choose_version::start();
        self.ensure_cached(package)?;

        let canonical = package.canonical_name();

        // Step 1 — compute the *natural* version: the newest version
        // satisfying the consumer's declared range, ignoring overrides.
        // The natural version is what the resolver WOULD pick without
        // any override; we capture it so the override summary can show
        // `from → to` (e.g. `foo 1.5.3 → 2.1.0`).
        let natural = self.pick_natural_version(package, range);

        // Step 2 — Phase 32 Phase 5 override lookup. We need a natural
        // version to evaluate the NameRange and Path range filters
        // against. If there's no natural match (range satisfies nothing
        // in the cache), the override can't apply — fall through to the
        // unconstrained newest-in-range pass below for whatever the
        // resolver wants to do (usually return None and surface a
        // NoSolution).
        if let Some(natural_ver) = natural.as_ref() {
            let parent_ctx = package.context();
            if let Some(entry) = self
                .overrides
                .find_match(&canonical, natural_ver, parent_ctx)
            {
                // Apply the override target to produce the forced version.
                if let Some(forced) = self.apply_override_target(package, &entry.target, range) {
                    let hit = OverrideHit {
                        raw_key: entry.raw_key.clone(),
                        source: entry.source,
                        package: canonical.clone(),
                        from_version: natural_ver.to_string(),
                        to_version: forced.to_string(),
                        via_parent: parent_ctx.map(str::to_string),
                    };
                    tracing::debug!(
                        "override applied: {} {} → {} (via {})",
                        hit.package,
                        hit.from_version,
                        hit.to_version,
                        hit.source_display()
                    );
                    self.overrides.record_hit(hit);
                    return Ok(Some(forced));
                } else {
                    // The override target didn't satisfy the consumer's
                    // declared range. This is the "irreconcilable
                    // override" case — we leave the consumer's natural
                    // version in place and let any downstream peer/SAT
                    // checks surface the situation. We do NOT silently
                    // pretend the override applied (fail-loud at debug
                    // level for now; future Phase 5.x will turn this
                    // into a hard error gated on a flag).
                    tracing::warn!(
                        "override {} could not be satisfied: target {} is outside consumer range for {}",
                        entry.raw_key,
                        entry.target.raw(),
                        canonical
                    );
                }
            }
        }

        // Step 3 — no override applied. Return the natural version
        // (computed above so we don't re-traverse the cache).
        Ok(natural)
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        let _span =
            tracing::debug_span!("get_dependencies", pkg = %package, ver = %version).entered();
        let _prof = crate::profile::get_dependencies::start();
        if package.is_root() {
            // Phase 36: drain streaming prefetch into provider cache before
            // counting uncached deps. This reduces the uncached set so the
            // provider's own batch (below) fires with fewer or zero packages.
            if let Some(ref streaming) = self.streaming {
                let mut cache = self.cache.borrow_mut();
                for dep_name in self.root_deps.keys() {
                    let pkg = ResolverPackage::from_dep_name(dep_name);
                    if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(pkg)
                        && let Some(info) = streaming.get(dep_name)
                    {
                        e.insert(info);
                    }
                }
            }

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

                if uncached.len() > 1 && !*self.batch_disabled.borrow() {
                    match self.rt.block_on(self.client.batch_metadata(&uncached)) {
                        Ok(batch) => {
                            tracing::debug!(
                                "root batch prefetch: {} uncached → {} fetched",
                                uncached.len(),
                                batch.len()
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                "root batch prefetch failed, disabling batching for this run: {e}"
                            );
                            *self.batch_disabled.borrow_mut() = true;
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

        // Phase 36: drain streaming prefetch into provider cache for this
        // package's deps, same pattern as the root-deps block above.
        if let Some(ref streaming) = self.streaming {
            let mut cache = self.cache.borrow_mut();
            for dep_name in ver_deps.keys() {
                let pkg = ResolverPackage::from_dep_name(dep_name);
                if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(pkg)
                    && let Some(info) = streaming.get(dep_name)
                {
                    e.insert(info);
                }
            }
        }

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

            if uncached.len() > 1 && !*self.batch_disabled.borrow() {
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
                        tracing::debug!(
                            "dep batch prefetch failed, disabling batching for this run: {e}"
                        );
                        *self.batch_disabled.borrow_mut() = true;
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

    /// Build an OverrideSet from a single `lpm.overrides` entry. Test
    /// helper that mirrors the `OverrideSet::parse` call site in
    /// install.rs without dragging the full `package.json` schema in.
    fn override_set_with(key: &str, target: &str) -> OverrideSet {
        let mut lpm = HashMap::new();
        lpm.insert(key.to_string(), target.to_string());
        OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new()).unwrap()
    }

    #[test]
    fn choose_version_override_in_range_applies() {
        let pkg = ResolverPackage::npm("lodash");
        let info = make_info(&["4.17.21", "4.17.20", "4.17.19"], vec![], vec![], vec![]);

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(override_set_with("lodash", "4.17.20"));
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

        // **Phase 32 Phase 5** — verify the apply trace was recorded.
        let hits = provider.overrides.take_hits();
        assert_eq!(hits.len(), 1, "exactly one override hit should be recorded");
        assert_eq!(hits[0].package, "lodash");
        assert_eq!(hits[0].from_version, "4.17.21");
        assert_eq!(hits[0].to_version, "4.17.20");
        assert_eq!(hits[0].via_parent, None);
    }

    #[test]
    fn choose_version_override_out_of_range_ignored() {
        // Override specifies 3.0.0 but range requires ^4.0.0 → override ignored,
        // newest matching version selected instead
        let pkg = ResolverPackage::npm("lodash");
        let info = make_info(&["4.17.21", "4.17.20", "3.0.0"], vec![], vec![], vec![]);

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(override_set_with("lodash", "3.0.0"));
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

        // No override hit should be recorded for an out-of-range pinned target.
        let hits = provider.overrides.take_hits();
        assert!(
            hits.is_empty(),
            "no hit should be recorded for out-of-range override"
        );
    }

    #[test]
    fn choose_version_override_range_target_picks_newest_in_intersection() {
        // **Phase 32 Phase 5** — `^2.0.0` override target should pick the
        // newest 2.x in the consumer's range, not force a single version.
        let pkg = ResolverPackage::npm("foo");
        let info = make_info(
            &["2.5.0", "2.4.0", "2.0.0", "1.0.0"],
            vec![],
            vec![],
            vec![],
        );

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(override_set_with("foo", "^2.0.0"));
        provider.cache.borrow_mut().insert(pkg.clone(), info);

        // Consumer asks for `*` (any version). Without override → 2.5.0.
        // With override `^2.0.0` → still 2.5.0 (newest in 2.x).
        let range = NpmRange::parse("*")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));
        let chosen = provider.choose_version(&pkg, &range).unwrap();
        assert_eq!(chosen.map(|v| v.to_string()), Some("2.5.0".to_string()));

        // The hit should still be recorded — `from_version` and
        // `to_version` are the same here because the override and the
        // natural choice agree on 2.5.0, but the resolver still
        // intersected with the override range.
        let hits = provider.overrides.take_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].to_version, "2.5.0");
    }

    #[test]
    fn choose_version_override_range_target_excludes_non_matching() {
        // Consumer asks for `*` but override range `^2.0.0` excludes 3.x.
        let pkg = ResolverPackage::npm("foo");
        let info = make_info(&["3.0.0", "2.5.0", "2.0.0"], vec![], vec![], vec![]);

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_overrides(override_set_with("foo", "^2.0.0"));
        provider.cache.borrow_mut().insert(pkg.clone(), info);

        let range = NpmRange::parse("*")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&pkg));
        let chosen = provider.choose_version(&pkg, &range).unwrap();
        // 3.0.0 is the natural choice but the override range constrains
        // to 2.x — 2.5.0 wins.
        assert_eq!(chosen.map(|v| v.to_string()), Some("2.5.0".to_string()));

        let hits = provider.overrides.take_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].from_version, "3.0.0");
        assert_eq!(hits[0].to_version, "2.5.0");
    }

    #[test]
    fn choose_version_path_selector_only_applies_to_matching_parent() {
        // **Phase 32 Phase 5** — path selector `baz>qar@1` should ONLY
        // apply when `qar` is reached through `baz` AND the natural
        // version satisfies `^1.0.0`. The split mechanism gives us
        // per-parent identities (`qar[baz]` vs `qar[other]`), so the
        // resolver looks up overrides with the right parent context.
        //
        // Available qar versions: 2.0.0, 1.2.0, 1.1.0.
        // Consumer range: `^1.0.0` → natural pick is 1.2.0 (newest 1.x).
        // Path selector range filter: `1` (= ^1.0.0) → matches 1.2.0.
        // Target: `2.0.0` → forced because it's in `*`-target-range, but
        // we need the consumer range to ALSO include 2.0.0 for the
        // pinned target to apply. So consumer range must be `*`.
        //
        // Result design: consumer range `*`, override range filter
        // narrows to 1.x. Natural is 2.0.0; selector filter `1`
        // requires natural to satisfy `^1.0.0` — 2.0.0 doesn't, so the
        // override is SKIPPED. To exercise the path selector path,
        // shrink the available versions so the natural is in 1.x.
        let qar_baz = ResolverPackage::npm("qar").with_context("baz");
        let qar_other = ResolverPackage::npm("qar").with_context("other");
        let info = make_info(&["1.5.0", "1.2.0", "1.1.0"], vec![], vec![], vec![]);

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut splits = HashSet::new();
        splits.insert("qar".to_string());
        let provider = LpmDependencyProvider::new_with_splits(
            client,
            rt.handle().clone(),
            HashMap::new(),
            splits,
        )
        .with_overrides(override_set_with("baz>qar@1", "1.1.0"));
        provider
            .cache
            .borrow_mut()
            .insert(qar_baz.clone(), info.clone());
        provider.cache.borrow_mut().insert(qar_other.clone(), info);

        let consumer_range = NpmRange::parse("^1.0.0")
            .unwrap()
            .to_pubgrub_ranges(&provider.available_versions(&qar_baz));

        // Through `baz`: natural is 1.5.0; selector range filter `1`
        // (= ^1.0.0) matches 1.5.0 → override forces 1.1.0.
        let chosen_baz = provider.choose_version(&qar_baz, &consumer_range).unwrap();
        assert_eq!(
            chosen_baz.map(|v| v.to_string()),
            Some("1.1.0".to_string()),
            "qar via baz should be forced to the override target 1.1.0"
        );

        // Through `other`: path selector does not match (wrong parent).
        // Natural pick wins.
        let chosen_other = provider
            .choose_version(&qar_other, &consumer_range)
            .unwrap();
        assert_eq!(
            chosen_other.map(|v| v.to_string()),
            Some("1.5.0".to_string()),
            "qar via other should get the natural newest (1.5.0) — path selector skipped"
        );

        // Drain the apply trace — only the baz hit should be recorded.
        let hits = provider.overrides.take_hits();
        assert_eq!(hits.len(), 1, "only the baz path should record a hit");
        assert_eq!(hits[0].package, "qar");
        assert_eq!(hits[0].via_parent, Some("baz".to_string()));
        assert_eq!(hits[0].from_version, "1.5.0");
        assert_eq!(hits[0].to_version, "1.1.0");
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

    // === Phase 36: streaming prefetch integration ===

    #[test]
    fn streaming_prefetch_populates_provider_cache_at_batch_decision() {
        // Simulates the install-path overlap: the streaming cache has a
        // package that the provider's in-memory cache doesn't. The provider
        // should drain it at the batch-decision point in get_dependencies(),
        // avoiding both a provider-internal batch and an individual fetch.
        let streaming = Arc::new(StreamingPrefetch::new());

        let lodash_info = make_info(&["4.17.21"], vec![], vec![], vec![]);
        streaming.insert("lodash".to_string(), lodash_info);
        streaming.mark_done();

        let mut root_deps = HashMap::new();
        root_deps.insert("lodash".to_string(), "^4.0.0".to_string());

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), root_deps)
            .with_streaming_prefetch(streaming);

        // Provider cache should be empty before get_dependencies
        assert!(
            !provider
                .cache
                .borrow()
                .contains_key(&ResolverPackage::npm("lodash")),
            "lodash should not be in provider cache yet"
        );

        // get_dependencies for Root triggers the streaming drain
        let deps = provider.get_dependencies(&ResolverPackage::Root, &NpmVersion::new(0, 0, 0));
        assert!(deps.is_ok(), "get_dependencies should succeed");

        // Now lodash should be in the provider cache (drained from streaming)
        assert!(
            provider
                .cache
                .borrow()
                .contains_key(&ResolverPackage::npm("lodash")),
            "lodash should have been drained from streaming cache into provider cache"
        );
    }

    #[test]
    fn streaming_prefetch_singleton_ensure_cached() {
        // Simulates the singleton case: uncached.len() == 1 so the provider
        // skips its batch path and goes to ensure_cached(). The streaming
        // cache should catch it there.
        let streaming = Arc::new(StreamingPrefetch::new());

        let express_info = make_info(&["4.18.0"], vec![], vec![], vec![]);
        streaming.insert("express".to_string(), express_info);
        streaming.mark_done();

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new())
            .with_streaming_prefetch(streaming);

        let pkg = ResolverPackage::npm("express");
        assert!(!provider.cache.borrow().contains_key(&pkg));

        // ensure_cached should find it in the streaming cache
        let result = provider.ensure_cached(&pkg);
        assert!(
            result.is_ok(),
            "ensure_cached should succeed via streaming cache"
        );
        assert!(
            provider.cache.borrow().contains_key(&pkg),
            "express should be in provider cache after ensure_cached"
        );
    }

    #[test]
    fn no_streaming_prefetch_leaves_existing_behavior() {
        // Non-install callers pass None for streaming. Verify the provider
        // still works normally without it.
        let mut root_deps = HashMap::new();
        root_deps.insert("lodash".to_string(), "^4.0.0".to_string());

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), root_deps);

        // No streaming prefetch — streaming field is None
        assert!(provider.streaming.is_none());

        // Provider cache is empty, no streaming to drain from.
        // get_dependencies would try provider batching / individual fetch
        // (which would fail with no real server), but the point is it
        // doesn't panic or NPE from a missing streaming ref.
        assert!(
            !provider
                .cache
                .borrow()
                .contains_key(&ResolverPackage::npm("lodash"))
        );
    }
}
