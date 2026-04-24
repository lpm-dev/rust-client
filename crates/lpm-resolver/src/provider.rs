//! PubGrub DependencyProvider implementation for LPM.
//!
//! Bridges PubGrub's resolution algorithm with the LPM/npm registries.
//!
//! Resolver compatibility: peerDeps, optionalDeps, overrides, workspace:*, platform filtering.
//! See phase-17-todo.md.

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
use crate::package::{CanonicalKey, ResolverPackage};
use crate::ranges::NpmRange;
use dashmap::DashMap;
use lpm_registry::{RegistryClient, RouteMode, UpstreamRoute};
use pubgrub::{Dependencies, DependencyProvider, PackageResolutionStatistics};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use version_ranges::Ranges;

/// Shared metadata cache for the Phase 49 streaming BFS resolver.
///
/// Keyed by [`CanonicalKey`] — split-retry identities of the same canonical
/// package share a single entry. The walker inserts under canonical names;
/// the provider canonicalizes at every read so split contexts hit the
/// same cell. Changing this to a context-bearing key re-introduces the
/// silent notify-miss bug documented in the Phase 49 preplan §4.2.
pub type SharedCache = Arc<DashMap<CanonicalKey, CachedPackageInfo>>;

/// Per-canonical-key waker map. The walker fires `notify_waiters()` after
/// inserting each manifest; the provider's `ensure_cached` wait-loop
/// awaits on the same handle. See preplan §5.1 for the granularity
/// rationale (per-package vs. global `Notify`).
pub type NotifyMap = Arc<DashMap<CanonicalKey, Arc<Notify>>>;

/// Phase 49 provider-side observability for `timing.resolve.streaming_bfs`.
///
/// Three atomic counters, share across split-retry passes via the
/// inner `Arc<AtomicU64>`s. Install.rs creates a single instance,
/// hands it to the resolver, and reads the snapshot after resolution
/// completes for JSON output.
///
/// Healthy values on a cold install with walker plumbed:
/// - `cache_waits ≈ total_packages` — every PubGrub read hit the
///   wait-loop and was served by the walker's insert.
/// - `cache_wait_timeouts == 0` — no walker gap forced a timeout.
/// - `escape_hatch_fetches == 0` — no direct fetch was needed.
///
/// Non-zero `cache_wait_timeouts` or `escape_hatch_fetches` signals
/// a walker gap (the walker didn't reach a package PubGrub needed).
/// Zero `cache_waits` with non-zero `escape_hatch_fetches` signals
/// the walker wasn't attached (pre-§5 provider shape with
/// `fetch_wait_timeout == ZERO`).
#[derive(Debug, Clone, Default)]
pub struct StreamingBfsMetrics {
    cache_waits: Arc<AtomicU64>,
    cache_wait_timeouts: Arc<AtomicU64>,
    escape_hatch_fetches: Arc<AtomicU64>,
}

impl StreamingBfsMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cache_waits(&self) -> u64 {
        self.cache_waits.load(Ordering::Relaxed)
    }

    pub fn cache_wait_timeouts(&self) -> u64 {
        self.cache_wait_timeouts.load(Ordering::Relaxed)
    }

    pub fn escape_hatch_fetches(&self) -> u64 {
        self.escape_hatch_fetches.load(Ordering::Relaxed)
    }

    fn incr_cache_wait(&self) {
        self.cache_waits.fetch_add(1, Ordering::Relaxed);
    }

    fn incr_cache_wait_timeout(&self) {
        self.cache_wait_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn incr_escape_hatch_fetch(&self) {
        self.escape_hatch_fetches.fetch_add(1, Ordering::Relaxed);
    }
}

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
    /// **Phase 40 P2** — npm-alias dep edges per version. Shape:
    /// `version_string → { local_name → target_canonical_name }`.
    /// Only populated for versions whose declared deps include the
    /// `npm:<target>@<range>` alias syntax. Used by the resolver to
    /// (a) resolve each aliased dep under its target identity in
    /// PubGrub, and (b) populate `ResolvedPackage.aliases` so the
    /// linker can build `node_modules/<local>/` → store entry for
    /// `<target>@<version>`.
    pub aliases: HashMap<String, HashMap<String, String>>,
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
    /// Phase 49: canonical-keyed, concurrent metadata cache. See
    /// [`SharedCache`] for the invariant rationale. When a walker is
    /// plumbed (Phase 49 §5), the same `Arc` is handed to the walker so
    /// inserts become visible to the provider without a copy.
    cache: SharedCache,
    /// Phase 49: per-canonical-key waker map. Populated on-demand by the
    /// wait-loop inside `ensure_cached`; walker calls
    /// `notify_waiters()` on the matching entry after insert.
    notify_map: NotifyMap,
    /// Phase 49: routing policy for escape-hatch fetches. Default
    /// [`RouteMode::Direct`] per preplan §3. LPM packages still go via
    /// the Worker regardless (see `RouteMode::route_for_package`).
    route_mode: RouteMode,
    /// Phase 49: how long `ensure_cached`'s wait-loop is willing to
    /// block on a walker insert before falling through to the direct
    /// fetch escape hatch.
    ///
    /// Defaults to [`Duration::ZERO`] so the provider stays fetch-on-
    /// miss (identical to today's behavior) when no walker is attached.
    /// Phase 49 §5 will bump this to ~5s once `install.rs` shares the
    /// walker-populated `SharedCache` with the provider, making the
    /// wait-loop the hot path and the direct fetch the rare escape
    /// hatch.
    fetch_wait_timeout: Duration,
    /// Phase 49 §6: streaming-BFS observability counters. Shared Arc
    /// across split-retry passes; install.rs reads the snapshot after
    /// resolution for `timing.resolve.streaming_bfs` JSON output.
    metrics: StreamingBfsMetrics,
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
    /// Phase 40 P1 — count of optional deps skipped because no
    /// platform-compatible version satisfies the declared range on the
    /// current OS/CPU. Cumulative across all calls to `get_dependencies`
    /// within a single provider instance. Drained via
    /// [`Self::platform_skipped_count`] (or [`Self::into_parts`] bundled
    /// with cache + override hits) after `pubgrub::resolve` returns so the
    /// resolver can expose it in `ResolveResult.platform_skipped`, which
    /// the install CLI surfaces as `timing.resolve.platform_skipped` in
    /// `--json` output.
    platform_skipped: RefCell<usize>,
    /// **Phase 40 P2** — root-level npm-alias edges accumulated as
    /// `get_dependencies(Root)` walks `self.root_deps`. Shape:
    /// `local_name → target_canonical_name`. Surfaced via
    /// `into_parts()` so `ResolveResult.root_aliases` carries the map
    /// into the install pipeline, which feeds it to the linker so
    /// `node_modules/<local>/` is created pointing at the aliased
    /// target's `.lpm/<target>@<version>/` store entry.
    root_aliases: RefCell<HashMap<String, String>>,
    /// **Phase 42 P2** — memoize `(ResolverPackage, raw_range) →
    /// Ranges<NpmVersion>` so repeated PubGrub `get_dependencies`
    /// queries for the same edge skip the O(N-versions) conversion
    /// inside `NpmRange::to_pubgrub_ranges`. Phase 41 measured this
    /// uncached conversion at ~962 ms of `pubgrub_core_ms` when the
    /// metadata cache grew by 9 packages; the uncached O(queries × N)
    /// cost is what made the resolver look "sensitive to metadata
    /// bloat."
    ///
    /// Correctness. Safe to memoize for the lifetime of a single
    /// provider instance because `available_versions(pkg)` is fixed
    /// once `ensure_cached(pkg)` runs: the metadata cache is append-
    /// only during a resolve pass and platform filtering is a pure
    /// function of the cached platform map, which is also fixed.
    /// Keyed on `ResolverPackage` (not bare canonical name) so split
    /// contexts stay in distinct cells — cheaper than teaching the
    /// cache to reason about split equivalence, and safe by
    /// construction.
    ///
    /// NOT transferred across provider instances by `with_cache` /
    /// `with_prefetched_metadata`. The metadata cache transfers; the
    /// range cache is re-built on the next pass. Keeps the
    /// invariant local: anything that changes how `available_versions`
    /// resolves (e.g. a future per-split platform override) can't
    /// accidentally read stale memoized Ranges from a prior pass.
    range_cache: RefCell<HashMap<(ResolverPackage, String), Ranges<NpmVersion>>>,
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
            cache: Arc::new(DashMap::new()),
            notify_map: Arc::new(DashMap::new()),
            // Phase 49 §3: keep provider's default at Proxy to preserve
            // pre-49 three-tier npm fetch semantics for existing callers.
            // `install.rs` in §5 explicitly switches via
            // `with_route_mode(RouteMode::from_env_or_default())` once
            // the walker is plumbed. Keeps §3 behavior-preserving.
            route_mode: RouteMode::Proxy,
            fetch_wait_timeout: Duration::ZERO,
            metrics: StreamingBfsMetrics::new(),
            root_deps,
            split_packages: HashSet::new(),
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            platform_skipped: RefCell::new(0),
            root_aliases: RefCell::new(HashMap::new()),
            range_cache: RefCell::new(HashMap::new()),
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
            cache: Arc::new(DashMap::new()),
            notify_map: Arc::new(DashMap::new()),
            // Phase 49 §3: keep provider's default at Proxy to preserve
            // pre-49 three-tier npm fetch semantics for existing callers.
            // `install.rs` in §5 explicitly switches via
            // `with_route_mode(RouteMode::from_env_or_default())` once
            // the walker is plumbed. Keeps §3 behavior-preserving.
            route_mode: RouteMode::Proxy,
            fetch_wait_timeout: Duration::ZERO,
            metrics: StreamingBfsMetrics::new(),
            root_deps,
            split_packages: splits,
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            platform_skipped: RefCell::new(0),
            root_aliases: RefCell::new(HashMap::new()),
            range_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Phase 49: attach an externally-owned shared cache + notify map
    /// (e.g. the one the BFS walker is populating concurrently). Also
    /// sets the `fetch_wait_timeout` so `ensure_cached`'s wait-loop
    /// actually waits instead of falling straight to the escape hatch.
    ///
    /// This constructor is intended for the Phase 49 §5 install.rs
    /// orchestration where the walker + provider share state; pre-49
    /// callers stick with [`Self::new`] / [`Self::new_with_splits`]
    /// (which create their own Arcs with zero timeout).
    #[allow(dead_code)] // wired by install.rs in §5
    pub fn with_shared_cache(
        mut self,
        cache: SharedCache,
        notify_map: NotifyMap,
        fetch_wait_timeout: Duration,
    ) -> Self {
        self.cache = cache;
        self.notify_map = notify_map;
        self.fetch_wait_timeout = fetch_wait_timeout;
        self
    }

    /// Phase 49: set the escape-hatch route mode. Applies to both the
    /// provider's own miss-path fetches AND any walker attached via
    /// [`Self::with_shared_cache`] (the walker is constructed with the
    /// same mode by the install.rs orchestration).
    #[allow(dead_code)] // wired by install.rs in §5
    pub fn with_route_mode(mut self, mode: RouteMode) -> Self {
        self.route_mode = mode;
        self
    }

    /// Phase 49 §6: attach an externally-owned metrics object so the
    /// same counters accumulate across split-retry passes (each pass
    /// creates a new provider instance; the shared `Arc<AtomicU64>`
    /// inside `StreamingBfsMetrics` survives). Install.rs reads the
    /// snapshot after resolution completes for JSON output.
    pub fn with_streaming_metrics(mut self, metrics: StreamingBfsMetrics) -> Self {
        self.metrics = metrics;
        self
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
    /// API surface used by the split-retry resolver.
    pub fn with_overrides(mut self, overrides: OverrideSet) -> Self {
        self.overrides = overrides;
        self
    }

    /// Ensure package metadata is cached. Fetches from registry on miss.
    ///
    /// Phase 49 shape (preplan §5.1):
    ///
    /// 1. **Canonicalize first.** `ResolverPackage` carries a `context`
    ///    field in its `Hash + Eq` (split-retry identities); the cache
    ///    is keyed by [`CanonicalKey`] which strips that context. Every
    ///    cache interaction MUST go through canonicalization or split
    ///    retries silently miss walker-inserted entries and fall through
    ///    to escape-hatch fetches — a silent perf cliff rather than a
    ///    correctness bug, but exactly the thing preplan §4.2 cautions
    ///    against. Do not change the order of operations in this
    ///    function without re-reading that section.
    ///
    /// 2. **Fast path:** cache hit → return immediately.
    ///
    /// 3. **Wait-loop** (only when `fetch_wait_timeout > 0`): subscribe
    ///    to this key's per-canonical [`Notify`], re-check the cache
    ///    under the subscription, then `block_on(timeout(notified))`.
    ///    Each wake re-checks the cache (the per-canonical Notify only
    ///    fires when THIS key lands, so one wake ≈ one insert for us).
    ///    On timeout, fall to step 4.
    ///
    /// 4. **Escape-hatch fetch:** direct fetch via
    ///    [`Self::direct_fetch_and_cache`], which honors the same
    ///    `route_for_package` policy the walker uses. LPM packages stay
    ///    on the Worker; npm packages go direct in
    ///    [`RouteMode::Direct`], proxy in [`RouteMode::Proxy`].
    ///
    /// Pre-49 callers with no walker attached get `fetch_wait_timeout ==
    /// Duration::ZERO`, so step 3 falls immediately through to step 4 —
    /// behavior indistinguishable from today's fetch-on-miss path.
    fn ensure_cached(&self, package: &ResolverPackage) -> Result<(), ProviderError> {
        if package.is_root() {
            return Ok(());
        }
        let key = CanonicalKey::from(package);
        // Fast path (step 2).
        if self.cache.contains_key(&key) {
            return Ok(());
        }

        let _span = tracing::debug_span!("ensure_cached", pkg = %package).entered();
        let _prof = crate::profile::ensure_cached::start();

        // Wait-loop (step 3). Only active when a walker is attached and
        // the caller has set a non-zero fetch_wait_timeout; otherwise
        // the loop's first iteration falls straight to step 4.
        if !self.fetch_wait_timeout.is_zero() {
            // Count every PubGrub callback that hit the wait-loop on a
            // cache miss — the healthy Phase 49 cold-install shape has
            // `cache_waits ≈ total_packages` (every miss served by the
            // walker's insert, no fetches).
            self.metrics.incr_cache_wait();
            let notify = self
                .notify_map
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone();
            let start = Instant::now();
            loop {
                // Subscribe BEFORE re-checking the cache. If the walker
                // inserts between the check and the await, `notified()`
                // will return immediately — this is tokio::sync::Notify's
                // missed-wakeup defense.
                let notified = notify.notified();
                if self.cache.contains_key(&key) {
                    return Ok(());
                }
                let remaining = self.fetch_wait_timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    self.metrics.incr_cache_wait_timeout();
                    break; // escape to step 4
                }
                match self
                    .rt
                    .block_on(async { tokio::time::timeout(remaining, notified).await })
                {
                    Ok(_) => continue, // walker inserted our key; recheck
                    Err(_) => {
                        self.metrics.incr_cache_wait_timeout();
                        break; // timed out; escape to step 4
                    }
                }
            }
        }

        // Escape-hatch fetch (step 4).
        self.direct_fetch_and_cache(package)
    }

    /// Phase 49: synchronous fetch of a single package, keyed + cached
    /// under its canonical form. Routing honors [`Self::route_mode`]:
    /// LPM → Worker unconditionally; npm → per `RouteMode`.
    ///
    /// Called by [`Self::ensure_cached`] as the escape-hatch when the
    /// walker either isn't attached or didn't reach this package within
    /// `fetch_wait_timeout`.
    fn direct_fetch_and_cache(&self, package: &ResolverPackage) -> Result<(), ProviderError> {
        let key = CanonicalKey::from(package);
        // Phase 49 §6: count every fetch that falls through to the
        // escape hatch. Root returns early without triggering a
        // registry fetch, so it doesn't count against the metric.
        if !package.is_root() {
            self.metrics.incr_escape_hatch_fetch();
        }
        match package {
            ResolverPackage::Root => Ok(()),
            ResolverPackage::Lpm { owner, name, .. } => {
                let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                    .map_err(|e| ProviderError::Registry(e.to_string()))?;

                let metadata = self
                    .rt
                    .block_on(self.client.get_package_metadata(&pkg_name))
                    .map_err(classify_registry_error)?;

                // Phase 34.5: use shared parser (LPM packages include prereleases)
                let info = parse_metadata_to_cache_info(&metadata, false);
                self.insert_and_notify(key, info);
                Ok(())
            }
            ResolverPackage::Npm { name, .. } => {
                // Phase 49: npm fetches honor the route_mode. In Direct
                // (shipped default) this skips the Worker hop entirely;
                // in Proxy it goes through the Worker with npm fallback.
                // @lpm.dev/* can't land here — it's handled by the Lpm
                // arm above — but `route_for_package` still enforces the
                // policy symmetrically for the walker's sake.
                let route = self.route_mode.route_for_package(name);
                let metadata = match route {
                    UpstreamRoute::LpmWorker => {
                        self.rt.block_on(self.client.get_npm_package_metadata(name))
                    }
                    UpstreamRoute::NpmDirect => {
                        self.rt.block_on(self.client.get_npm_metadata_direct(name))
                    }
                }
                .map_err(|e| ProviderError::Registry(format!("npm:{name}: {e}")))?;

                // Phase 34.5: use shared parser (npm packages skip prereleases)
                let info = parse_metadata_to_cache_info(&metadata, true);
                tracing::debug!("npm package {name}: {} versions", info.versions.len());
                self.insert_and_notify(key, info);
                Ok(())
            }
        }
    }

    /// Phase 49: insert a freshly-parsed `CachedPackageInfo` and fire any
    /// waiters on its canonical key. Ordering is load-bearing per preplan
    /// §5.5: insert → notify. Do NOT reorder. A future refactor that
    /// notifies before inserting would race the provider's re-check and
    /// cause spurious wait-loop iterations.
    fn insert_and_notify(&self, key: CanonicalKey, info: CachedPackageInfo) {
        self.cache.insert(key.clone(), info);
        if let Some(n) = self.notify_map.get(&key) {
            n.notify_waiters();
        }
    }

    /// Get the list of versions for a package that are available on the
    /// current platform.
    ///
    /// Phase 49: canonicalizes before cache lookup — split-retry
    /// identities of the same canonical package share one cache entry.
    fn available_versions(&self, package: &ResolverPackage) -> Vec<NpmVersion> {
        let _span = tracing::debug_span!("available_versions", pkg = %package).entered();
        let _prof = crate::profile::available_versions::start();
        let key = CanonicalKey::from(package);
        self.cache
            .get(&key)
            .map(|c| {
                c.versions
                    .iter()
                    .filter(|version| {
                        c.platform
                            .get(&version.to_string())
                            .is_none_or(is_platform_compatible)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// **Phase 42 P2** — memoized wrapper around
    /// [`NpmRange::to_pubgrub_ranges`]. First call for a given
    /// `(package, raw_range)` pair computes the O(N-versions)
    /// conversion and caches the result; subsequent calls return a
    /// clone of the cached `Ranges`. See the doc on
    /// [`Self::range_cache`] for the correctness argument.
    ///
    /// Callers MUST pass the same `available` slice they'd have passed
    /// to the uncached call (i.e. the output of
    /// `available_versions(pkg)` at the moment of the call). The cache
    /// doesn't re-derive `available` on hits — it just returns what it
    /// recorded. Because `available_versions(pkg)` is fixed for the
    /// lifetime of one provider (metadata cache is append-only per
    /// pass), this is safe; calling with a stale `available` is a
    /// caller bug that would be wrong uncached too.
    fn to_pubgrub_ranges_cached(
        &self,
        pkg: &ResolverPackage,
        npm_range: &NpmRange,
        available: &[NpmVersion],
    ) -> Ranges<NpmVersion> {
        let key = (pkg.clone(), npm_range.raw().to_string());
        if let Some(cached) = self.range_cache.borrow().get(&key) {
            return cached.clone();
        }
        let computed = npm_range.to_pubgrub_ranges(available);
        self.range_cache.borrow_mut().insert(key, computed.clone());
        computed
    }

    /// Phase 32 Phase 5 — extract the override hits AND the metadata
    /// cache in one shot. The two-stage `take_override_hits()` /
    /// `into_cache()` API is also available for callers that need only
    /// one of the two.
    ///
    /// Phase 40 P1 also surfaces the `platform_skipped` count so the
    /// resolver can accumulate it across split-retry passes without a
    /// separate borrow.
    ///
    /// Phase 40 P2 surfaces the `root_aliases` map so the install
    /// pipeline knows which root node_modules entries need alias
    /// symlinks instead of the default `<canonical_name> → store`
    /// wiring.
    pub fn into_parts(
        self,
    ) -> (
        HashMap<CanonicalKey, CachedPackageInfo>,
        Vec<OverrideHit>,
        usize,
        HashMap<String, String>,
    ) {
        let hits = self.overrides.take_hits();
        let platform_skipped = *self.platform_skipped.borrow();
        let root_aliases = self.root_aliases.into_inner();
        let cache = match Arc::try_unwrap(self.cache) {
            Ok(dm) => dm.into_iter().collect::<HashMap<_, _>>(),
            Err(arc) => arc
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
        };
        (cache, hits, platform_skipped, root_aliases)
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
        let key = CanonicalKey::from(package);
        let info = self.cache.get(&key)?;

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
                // Walk THIS package's cached versions only. Phase 49:
                // cache is canonical-keyed, so split-context variants
                // of the same canonical package share one entry — the
                // override check is over the canonical version list.
                let key = CanonicalKey::from(package);
                let info = self.cache.get(&key)?;
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
/// from a `PackageMetadata` response. Used by both `ensure_cached` (for
/// single-package fetches) and `with_prefetched_metadata` (for batch).
///
/// `skip_prerelease`: true for npm packages (noisy prereleases), false for LPM.
pub(crate) fn parse_metadata_to_cache_info(
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
    // Phase 40 P2 — per-version alias map: local_name → target_canonical_name.
    // Only populated when the version declares at least one `npm:<target>@<range>`
    // dep. The `deps` map above stores local_name → INNER range (range after
    // the `npm:<target>@` prefix) so downstream range parsing is identical to
    // the non-aliased path. Lookup is the single source of truth for
    // "is this local name an alias and if so, what's the target".
    let mut aliases: HashMap<String, HashMap<String, String>> = HashMap::new();

    // Helper: normalize a `(local_name, raw_range)` dep declaration through
    // the alias rewrite. Returns `(inner_range_string, target_name_if_alias)`.
    // The inner range string is always safe to hand to `NpmRange::parse`;
    // the target is recorded in the per-version aliases map when present.
    fn split_alias(raw_range: &str) -> (String, Option<String>) {
        match crate::ranges::parse_npm_alias(raw_range) {
            Some(alias) => (alias.range, Some(alias.target)),
            None => (raw_range.to_string(), None),
        }
    }

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
            let mut ver_aliases: HashMap<String, String> = HashMap::new();

            for (dep_name, dep_range) in &ver_meta.dependencies {
                if !is_valid_dep_name(dep_name) {
                    tracing::warn!("skipping invalid dep name: {dep_name:?}");
                    continue;
                }
                let (inner_range, target) = split_alias(dep_range);
                if let Some(target) = target {
                    if !is_valid_dep_name(&target) {
                        tracing::warn!(
                            "skipping alias dep {dep_name:?}: invalid target name {target:?}"
                        );
                        continue;
                    }
                    ver_aliases.insert(dep_name.clone(), target);
                }
                ver_deps.insert(dep_name.clone(), inner_range);
            }

            let mut opt_names = HashSet::new();
            for (dep_name, dep_range) in &ver_meta.optional_dependencies {
                if !is_valid_dep_name(dep_name) {
                    tracing::warn!("skipping invalid optional dep name: {dep_name:?}");
                    continue;
                }
                let (inner_range, target) = split_alias(dep_range);
                if let Some(target) = target {
                    if !is_valid_dep_name(&target) {
                        tracing::warn!(
                            "skipping optional alias dep {dep_name:?}: invalid target name {target:?}"
                        );
                        continue;
                    }
                    ver_aliases.insert(dep_name.clone(), target);
                }
                ver_deps.insert(dep_name.clone(), inner_range);
                opt_names.insert(dep_name.clone());
            }
            if !opt_names.is_empty() {
                optional_dep_names.insert(ver_str.clone(), opt_names);
            }
            if !ver_aliases.is_empty() {
                aliases.insert(ver_str.clone(), ver_aliases);
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
        aliases,
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

/// Phase 40 P3c — should the resolver's follow-up batch calls use
/// the deep variant (worker recursively resolves transitives) rather
/// than the shallow variant (just the named packages)?
///
/// Default ON. `LPM_DEEP_FOLLOWUP=0` (or any value starting with `0`)
/// flips it off. Any other value — including empty — keeps it on, so
/// `LPM_DEEP_FOLLOWUP=1`, `=true`, `=yes`, unset all behave the same.
///
/// Measured win on cold installs (see commit for Phase 40 P3c):
/// - 58-dep fixture: −24.4 s resolve_ms (−39 %)
/// - 280-pkg fixture: −3.5 s resolve_ms (−28 %)
///
/// The escape hatch is for bisecting future regressions, not
/// operational use.
fn deep_followup_enabled() -> bool {
    match std::env::var("LPM_DEEP_FOLLOWUP") {
        Ok(v) => !v.starts_with('0'),
        Err(_) => true,
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
        let key = CanonicalKey::from(package);
        let version_count = self
            .cache
            .get(&key)
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
            // Batch-prefetch root deps missing from BOTH in-memory and disk cache.
            // The initial batch_metadata_deep in install.rs covers most deps, so
            // this only fires when there are genuine cache misses (e.g., initial
            // batch failed or was incomplete).
            //
            // Phase 40 P2 — the prefetch list uses TARGET names for
            // aliased root deps. Keeping the alias syntax here would
            // turn into a failed metadata fetch for a bogus name.
            {
                let uncached: Vec<String> = self
                    .root_deps
                    .iter()
                    .map(|(local, range)| {
                        crate::ranges::parse_npm_alias(range)
                            .map(|a| a.target)
                            .unwrap_or_else(|| local.clone())
                    })
                    .filter(|target| {
                        let key = CanonicalKey::from_dep_name(target);
                        !self.cache.contains_key(&key) && !self.client.is_metadata_fresh(target)
                    })
                    .collect();

                if uncached.len() > 1 && !*self.batch_disabled.borrow() {
                    // Phase 40 P3c — root-level follow-up (only fires when
                    // install.rs's pre-resolve batch was absent or
                    // incomplete) also uses the deep variant so the
                    // first pubgrub walk starts with a pre-populated
                    // transitive cache instead of serially fetching
                    // dep-of-deps inside the tree walk. Same
                    // `LPM_DEEP_FOLLOWUP` escape hatch as the per-
                    // package path below.
                    let deep_followup = deep_followup_enabled();
                    let fetch = async {
                        if deep_followup {
                            self.client.batch_metadata_deep(&uncached).await
                        } else {
                            self.client.batch_metadata(&uncached).await
                        }
                    };
                    match self.rt.block_on(fetch) {
                        Ok(batch) => {
                            tracing::debug!(
                                "root batch prefetch (deep={}): {} uncached → {} fetched",
                                deep_followup,
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
                // Phase 40 P2 — root-level alias rewrite. If the
                // consumer's package.json declares `"local": "npm:target@range"`,
                // the resolver must key the PubGrub constraint on
                // `target` (the real registry identity) while the
                // install pipeline remembers `local → target` for the
                // linker to build `node_modules/<local>/`. The alias
                // is recorded in `self.root_aliases` (RefCell,
                // accumulated as we walk each root dep).
                let (target_name, range_str) = match crate::ranges::parse_npm_alias(dep_range_str) {
                    Some(alias) => {
                        self.root_aliases
                            .borrow_mut()
                            .insert(dep_name.clone(), alias.target.clone());
                        (alias.target, alias.range)
                    }
                    None => (dep_name.clone(), dep_range_str.clone()),
                };

                let pkg = ResolverPackage::from_dep_name(&target_name);

                // Ensure dep is cached so we know its versions
                self.ensure_cached(&pkg)?;
                let available = self.available_versions(&pkg);

                let npm_range = NpmRange::parse(&range_str).map_err(ProviderError::InvalidRange)?;

                let range = if available.is_empty() {
                    npm_range.to_pubgrub_ranges_heuristic()
                } else {
                    // Phase 42 P2 — memoized. See Self::range_cache doc.
                    self.to_pubgrub_ranges_cached(&pkg, &npm_range, &available)
                };

                constraints.insert(pkg, range);
            }
            return Ok(Dependencies::Available(constraints));
        }

        self.ensure_cached(package)?;

        let ver_str = version.to_string();
        let key = CanonicalKey::from(package);
        let (ver_deps, optional_names, ver_aliases) = {
            let info = match self.cache.get(&key) {
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
            // Phase 40 P2 — local_name → target_name. Empty for most
            // packages (bare-identity deps).
            let aliases = info.aliases.get(&ver_str).cloned().unwrap_or_default();
            (deps, opt, aliases)
        };

        // Phase 40 P4 — scope key for a child of a split parent must
        // include the parent's OWN split context, not just its canonical
        // name. Otherwise, grandchildren of two already-split parents
        // (e.g. `ajv[<root>]@8` and `ajv[eslint]@6`, both children of
        // different node_modules branches) collapse back into a single
        // pubgrub identity when they each declare a dep on, say,
        // `json-schema-traverse`. Using the parent's full Display form
        // propagates the split downward: grandchildren get
        // `[ajv[<root>]]` vs `[ajv[eslint]]` and resolve independently,
        // matching the nested-node_modules shape npm / bun produce.
        let parent_name = package.to_string();
        let mut constraints = pubgrub::Map::default();

        // Batch-prefetch deps missing from BOTH in-memory and disk cache.
        // Checks disk freshness via stat() (microseconds) to avoid redundant HTTP
        // requests for packages the initial batch_metadata_deep already cached.
        // Only fires when 2+ deps are genuine network misses.
        //
        // Phase 40 P3c — the follow-up batch is issued with `deep=true`
        // so the worker recurses from each uncached name and returns
        // its transitives in the same RPC. This is the client-side
        // companion to P3b (server-side deep-walk depth): every parent
        // in the walk that hits the follow-up path pre-populates the
        // disk cache for its descendants, collapsing what would
        // otherwise be N serial round-trips into 1. Gated by
        // `LPM_DEEP_FOLLOWUP` (default on). Setting `=0` reverts to
        // shallow `batch_metadata`, matching the pre-P3c behavior for
        // comparison / bisection.
        let deep_followup = deep_followup_enabled();
        {
            let uncached: Vec<String> = ver_deps
                .keys()
                .filter(|name| {
                    let k = CanonicalKey::from_dep_name(name);
                    !self.cache.contains_key(&k) && !self.client.is_metadata_fresh(name)
                })
                .cloned()
                .collect();

            if uncached.len() > 1 && !*self.batch_disabled.borrow() {
                let fetch = async {
                    if deep_followup {
                        self.client.batch_metadata_deep(&uncached).await
                    } else {
                        self.client.batch_metadata(&uncached).await
                    }
                };
                match self.rt.block_on(fetch) {
                    Ok(batch) => {
                        tracing::debug!(
                            "dep batch prefetch for {parent_name} (deep={}): {} uncached → {} fetched",
                            deep_followup,
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
            // Phase 40 P2 — resolve alias edges under the TARGET identity.
            //
            // For non-aliased deps the local name == target name, so
            // `target_name` is simply `dep_name`. For aliases declared as
            // `"local": "npm:target@range"` (e.g., Radix UI's
            // `strip-ansi-cjs → npm:strip-ansi@^6.0.1`), we key the
            // ResolverPackage on `target_name` so PubGrub dedup + metadata
            // fetch target the real registry identity. `dep_name` (the
            // local) is still used everywhere that records "how did the
            // parent refer to this dep" (split set, is_optional flag),
            // and in `format_solution` it becomes the edge key on
            // `ResolvedPackage.dependencies`.
            let target_name: &str = ver_aliases
                .get(dep_name)
                .map(String::as_str)
                .unwrap_or(dep_name.as_str());
            let base_pkg = ResolverPackage::from_dep_name(target_name);

            // If this dep is in the split set, create a scoped identity
            // so PubGrub treats each consumer's version independently.
            // Match against the TARGET name — split decisions are about
            // the canonical registry identity, not the parent-specific
            // alias label.
            let pkg = if self.split_packages.contains(target_name) {
                base_pkg.with_context(&parent_name)
            } else {
                base_pkg
            };

            let is_optional = optional_names.contains(dep_name);

            // Ensure dep is cached — skip optional deps that fail to fetch.
            //
            // Phase 35 §10.3: an optional `@lpm.dev` dep that hits an
            // auth/entitlement error must surface as a user-visible
            // warning, not a silent debug skip. Pre-fix this site
            // swallowed the error via `tracing::debug!`, which made
            // gated-dep omission indistinguishable from the legitimate
            // "fsevents on linux" platform-skip pattern.
            //
            // Other failure shapes (network blips, npm registry 5xx,
            // platform-incompatible) keep the silent debug behavior —
            // they're expected and noisy.
            match self.ensure_cached(&pkg) {
                Ok(()) => {}
                Err(e) => {
                    if is_optional {
                        let is_lpm = matches!(pkg, ResolverPackage::Lpm { .. });
                        let is_auth = matches!(e, ProviderError::AuthRequired(_));
                        if is_lpm && is_auth {
                            tracing::warn!(
                                "optional dep {dep_name} skipped: requires LPM authentication \
                                 (run `lpm login` to install this package)"
                            );
                        } else {
                            tracing::debug!("skipping optional dep {dep_name}: {e}");
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
            let available = self.available_versions(&pkg);

            // Phase 40 P1 — unified platform-gate for optional deps.
            //
            // The PRE-P1 check was `is_optional && available.is_empty()`,
            // which only covered packages where ALL versions are
            // platform-incompatible. It missed the bug shape where one
            // old version has an ERRONEOUS os/cpu declaration (e.g.,
            // `@next/swc-linux-x64-musl@12.0.0` ships with
            // `os: ["darwin"]` — a Next.js packaging bug from 2021).
            // In that case `available.is_empty()` was false, the range
            // intersection was empty (12.0.0 doesn't satisfy ^15), and
            // PubGrub surfaced a NoSolution that bun/npm never hit.
            //
            // The fix: parse the range FIRST, then check whether any
            // platform-compatible version actually satisfies it. If not,
            // skip the optional dep and bump the `platform_skipped`
            // counter for `--json` observability. Required deps still
            // fall through to pubgrub with an empty `Ranges`, producing
            // the same loud error as before (see
            // `resolve_regular_dep_with_no_platform_compatible_version_still_fails`
            // in resolve.rs tests).
            let npm_range = match NpmRange::parse(dep_range_str) {
                Ok(r) => r,
                Err(e) => {
                    if is_optional {
                        tracing::debug!("skipping optional dep {dep_name}@{dep_range_str}: {e}");
                    } else {
                        tracing::warn!("skipping dep {dep_name}@{dep_range_str}: {e}");
                    }
                    continue;
                }
            };

            if is_optional {
                let any_satisfies = available.iter().any(|v| npm_range.satisfies(v));
                if !any_satisfies {
                    tracing::debug!(
                        "skipping optional dep {dep_name}@{dep_range_str}: \
                         no platform-compatible version satisfies range \
                         (available={}, os={}, cpu={})",
                        available.len(),
                        Platform::current().os,
                        Platform::current().cpu,
                    );
                    *self.platform_skipped.borrow_mut() += 1;
                    continue;
                }
            }

            let range = if available.is_empty() {
                npm_range.to_pubgrub_ranges_heuristic()
            } else {
                // Phase 42 P2 — memoized. See Self::range_cache doc.
                self.to_pubgrub_ranges_cached(&pkg, &npm_range, &available)
            };
            constraints.insert(pkg, range);
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

    /// Phase 35 audit fix #3 + plan §10.3.
    /// Carries auth/entitlement failures across the
    /// `LpmError` → `ProviderError` boundary so the optional-dep skip
    /// path can distinguish "auth needed" (user-visible warn) from
    /// "platform-incompatible" or "registry transient" (silent debug).
    #[error("auth required: {0}")]
    AuthRequired(String),

    #[error("invalid version range: {0}")]
    InvalidRange(String),
}

/// Phase 35 audit fix #3: classify a registry error as
/// auth/entitlement vs everything else, preserving the message.
fn classify_registry_error(e: lpm_common::LpmError) -> ProviderError {
    match e {
        lpm_common::LpmError::AuthRequired
        | lpm_common::LpmError::SessionExpired
        | lpm_common::LpmError::Forbidden(_) => ProviderError::AuthRequired(e.to_string()),
        other => ProviderError::Registry(other.to_string()),
    }
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
            aliases: HashMap::new(),
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

    // === Phase 40 P3c — deep follow-up env-var contract ===
    //
    // These tests mutate `LPM_DEEP_FOLLOWUP` via `SafeScopedEnv`, a
    // tiny RAII guard that restores the original value on drop. We
    // deliberately avoid `set_var` without a guard: tests run in
    // parallel and another test could observe a half-set variable.
    // The guard takes a module-local `Mutex` so the env mutations
    // are serialized against each other (but not against unrelated
    // tests that don't touch `LPM_DEEP_FOLLOWUP`).

    struct ScopedEnv {
        key: &'static str,
        original: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ScopedEnv {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            // SAFETY: the lock serializes `LPM_DEEP_FOLLOWUP`
            // mutations across tests in this module; unrelated
            // tests don't touch this variable.
            let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let original = std::env::var(key).ok();
            // SAFETY: `set_var`/`remove_var` are unsafe in Rust
            // 2024; we hold the module lock, so concurrent reads
            // in other threads of this process are the caller's
            // responsibility (see LOCK above).
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
            Self {
                key,
                original,
                _lock: guard,
            }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            // SAFETY: see `set`.
            unsafe {
                match &self.original {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn deep_followup_default_is_on() {
        let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", None);
        assert!(
            deep_followup_enabled(),
            "default must be ON so cold installs get the in-loop deep-batch win"
        );
    }

    #[test]
    fn deep_followup_zero_disables() {
        let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("0"));
        assert!(
            !deep_followup_enabled(),
            "LPM_DEEP_FOLLOWUP=0 must flip off, matching the rollback escape hatch"
        );
    }

    #[test]
    fn deep_followup_one_stays_on() {
        let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("1"));
        assert!(deep_followup_enabled());
    }

    #[test]
    fn deep_followup_arbitrary_string_stays_on() {
        // Future-proof: any non-"0" value must keep it on so a
        // stray `=true` or `=yes` doesn't accidentally disable the
        // fast path.
        let _g = ScopedEnv::set("LPM_DEEP_FOLLOWUP", Some("true"));
        assert!(deep_followup_enabled());
    }

    // === Helper: build a provider with pre-populated cache (no network) ===

    fn make_provider_with_cache(
        root_deps: HashMap<String, String>,
        cache_entries: Vec<(ResolverPackage, CachedPackageInfo)>,
    ) -> LpmDependencyProvider {
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), root_deps);
        // Phase 49: canonicalize at the test-helper boundary so existing
        // tests keep working unchanged — they still pass `ResolverPackage`
        // values (with or without context), we stash them under their
        // canonical keys, which is what the provider now reads.
        for (pkg, info) in cache_entries {
            provider.cache.insert(CanonicalKey::from(&pkg), info);
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
            aliases: HashMap::new(),
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
        provider.cache.insert(CanonicalKey::from(&pkg), info);

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
        provider.cache.insert(CanonicalKey::from(&pkg), info);

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
        provider.cache.insert(CanonicalKey::from(&pkg), info);

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
        provider.cache.insert(CanonicalKey::from(&pkg), info);

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
            .insert(CanonicalKey::from(&qar_baz), info.clone());
        provider.cache.insert(CanonicalKey::from(&qar_other), info);

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

    #[test]
    fn get_dependencies_skips_optional_with_only_platform_incompatible_versions() {
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
        let fsevents_info = make_info(
            &["2.3.0"],
            vec![],
            vec![],
            vec![("2.3.0", vec!["definitely-not-this-os"], vec![])],
        );

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
                    "optional dep with only platform-incompatible versions should be silently skipped"
                );
            }
            _ => panic!("expected Available dependencies"),
        }
    }

    // Phase 35 §10.3 / audit fix #3: classifier round-trip.
    //
    // The optional-dep-skip path differentiates auth/entitlement
    // failures from everything else by matching on
    // `ProviderError::AuthRequired`. These tests pin the
    // `LpmError → ProviderError` translation so future refactors
    // can't accidentally swallow auth signals back into
    // `Registry(String)`.

    #[test]
    fn classify_registry_error_auth_required_maps_to_auth_required() {
        let p = classify_registry_error(lpm_common::LpmError::AuthRequired);
        assert!(
            matches!(p, ProviderError::AuthRequired(_)),
            "AuthRequired must round-trip to ProviderError::AuthRequired so the \
             optional-dep skip path can warn-and-skip"
        );
    }

    #[test]
    fn classify_registry_error_session_expired_maps_to_auth_required() {
        let p = classify_registry_error(lpm_common::LpmError::SessionExpired);
        assert!(matches!(p, ProviderError::AuthRequired(_)));
    }

    #[test]
    fn classify_registry_error_forbidden_maps_to_auth_required() {
        let p = classify_registry_error(lpm_common::LpmError::Forbidden("nope".into()));
        assert!(matches!(p, ProviderError::AuthRequired(_)));
    }

    #[test]
    fn classify_registry_error_network_maps_to_registry() {
        let p = classify_registry_error(lpm_common::LpmError::Network("ETIMEDOUT".into()));
        assert!(
            matches!(p, ProviderError::Registry(_)),
            "non-auth failures must stay as Registry so they remain silent debug skips"
        );
    }

    #[test]
    fn classify_registry_error_not_found_maps_to_registry() {
        let p = classify_registry_error(lpm_common::LpmError::NotFound("missing".into()));
        assert!(matches!(p, ProviderError::Registry(_)));
    }

    // ─── Phase 42 P2: range memoization ──────────────────────────
    //
    // `NpmRange::to_pubgrub_ranges(&available_versions)` is O(N) in the
    // version count for a given package. PubGrub backtracking calls
    // `get_dependencies` multiple times per package during a single
    // resolve pass, each call re-evaluating every declared dep's range
    // against the same `available_versions` list. On the decision-gate
    // fixture Phase 41 measured this uncached cost at ~962 ms of
    // `pubgrub_core_ms` when 9 extra packages entered the metadata
    // cache.
    //
    // The contract: `(package, raw_range_str) → Ranges<NpmVersion>`
    // must produce identical output on repeated calls within a single
    // provider instance, and the second call MUST hit the cache
    // instead of recomputing. `available_versions` is fixed for a
    // given `ResolverPackage` once `ensure_cached` has run, so there's
    // no staleness concern within a resolve pass.

    #[test]
    fn to_pubgrub_ranges_cached_hits_on_repeated_query() {
        let pkg = ResolverPackage::npm("lodash");
        let info = make_info(
            &["4.17.21", "4.17.20", "4.17.19", "4.16.0", "3.10.1"],
            vec![],
            vec![],
            vec![],
        );

        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
        provider.cache.insert(CanonicalKey::from(&pkg), info);

        let npm_range = NpmRange::parse("^4.17.0").unwrap();
        let available = provider.available_versions(&pkg);

        // Miss path — first call computes + caches.
        let r1 = provider.to_pubgrub_ranges_cached(&pkg, &npm_range, &available);
        assert_eq!(
            provider.range_cache.borrow().len(),
            1,
            "first call must populate exactly one entry"
        );

        // Hit path — second call returns the SAME Ranges without a
        // recompute. We assert structural equality (Ranges<V>: Eq)
        // plus that no new cache entry appeared.
        let r2 = provider.to_pubgrub_ranges_cached(&pkg, &npm_range, &available);
        assert_eq!(
            r1, r2,
            "memoized Ranges must equal the freshly-computed Ranges"
        );
        assert_eq!(
            provider.range_cache.borrow().len(),
            1,
            "repeated query with identical (pkg, range) must NOT add a second cache entry"
        );

        // Different range → separate entry.
        let npm_range2 = NpmRange::parse("~4.17.0").unwrap();
        provider.to_pubgrub_ranges_cached(&pkg, &npm_range2, &available);
        assert_eq!(
            provider.range_cache.borrow().len(),
            2,
            "different raw-range string must key a new entry"
        );
    }

    #[test]
    fn to_pubgrub_ranges_cached_distinguishes_split_packages() {
        // Split packages (same canonical name, different `context`) are
        // distinct `ResolverPackage` identities. Their `available_versions`
        // SET is typically the same (splits copy from canonical via
        // `ensure_cached`), but the cache keys are distinct because the
        // linker and PubGrub treat them as separate identities. Ensure
        // the cache honors that: a hit for `ajv[eslint]` must NOT serve
        // a query for `ajv` (bare), even at the same raw range string —
        // because future changes might introduce per-split platform
        // differences and silently serving across contexts would mask
        // that. Keep keys distinct.
        let pkg_plain = ResolverPackage::npm("ajv");
        let pkg_split = ResolverPackage::npm("ajv").with_context("eslint");
        assert_ne!(pkg_plain, pkg_split, "split and plain are distinct keys");

        let info = make_info(&["8.18.0", "7.2.4", "6.14.0"], vec![], vec![], vec![]);
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());
        provider
            .cache
            .insert(CanonicalKey::from(&pkg_plain), info.clone());
        provider.cache.insert(CanonicalKey::from(&pkg_split), info);

        let npm_range = NpmRange::parse("^6.0.0").unwrap();
        let available_plain = provider.available_versions(&pkg_plain);
        let available_split = provider.available_versions(&pkg_split);

        provider.to_pubgrub_ranges_cached(&pkg_plain, &npm_range, &available_plain);
        provider.to_pubgrub_ranges_cached(&pkg_split, &npm_range, &available_split);
        assert_eq!(
            provider.range_cache.borrow().len(),
            2,
            "split and plain keys must live in separate cache entries"
        );
    }

    // ─── Phase 49 — canonical-keyed cache regressions ──────────────────

    /// Boundary test for preplan §4.2 / §8.1: when `ensure_cached` is
    /// asked for a split-retry identity (`ajv[eslint]`), it MUST hit the
    /// canonical cache entry (`ajv`) the walker inserted — not time out
    /// and fall through to the escape-hatch fetch.
    ///
    /// Before Phase 49 the cache was keyed by `ResolverPackage` including
    /// context, and the old `ensure_cached` had an explicit `is_split()`
    /// branch that recursively fetched the canonical form and copied its
    /// info into the split cell. Phase 49 replaces both mechanisms with
    /// canonicalization at the cache boundary: one entry per canonical
    /// name, reads canonicalize `ResolverPackage → CanonicalKey` first.
    ///
    /// If anyone ever regresses this — e.g. re-introducing a context-
    /// bearing key on the cache or skipping canonicalization in
    /// `ensure_cached` — this test times out 0 s (no walker attached,
    /// fetch_wait_timeout is ZERO) and then fails trying to fetch from
    /// a dummy `RegistryClient`. The network-dependent failure mode is
    /// intentional: a pure in-memory assertion could mask the exact
    /// bug the invariant prevents.
    #[test]
    fn ensure_cached_split_retry_hits_canonical_entry() {
        let info = make_info(&["4.17.21"], vec![], vec![], vec![]);
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());

        // Simulate a walker having inserted under the canonical key.
        provider.cache.insert(CanonicalKey::npm("lodash"), info);

        // Ask `ensure_cached` for a split-context version of lodash —
        // this is what PubGrub does on multi-version retries. The
        // canonical-keyed cache MUST serve this from the existing
        // entry via CanonicalKey::from(&split) collapsing to the same
        // cell as the walker's insert.
        let split = ResolverPackage::npm("lodash").with_context("eslint");
        assert!(
            provider.cache.contains_key(&CanonicalKey::from(&split)),
            "canonicalization must map the split identity to the walker-inserted key"
        );

        // Call ensure_cached: must return Ok without touching the
        // network. If canonicalization regressed, this would fall to
        // direct_fetch_and_cache and blow up on the default (unconfigured)
        // RegistryClient because the pool isn't wired to a live server.
        provider
            .ensure_cached(&split)
            .expect("ensure_cached must resolve via the canonical cache entry without fetching");

        // available_versions must also see the canonical entry via the
        // split identity — this is the load-bearing downstream
        // consequence that `format_solution` and `check_unmet_peers`
        // depend on.
        let avail = provider.available_versions(&split);
        assert_eq!(
            avail.len(),
            1,
            "split identity must see canonical versions through canonicalization"
        );
    }

    /// Second boundary test: the same invariant from the other direction —
    /// a `ResolverPackage::npm("lodash")` (canonical) lookup must hit an
    /// entry inserted under a `ResolverPackage::npm("lodash").with_context(...)`
    /// identity. Both sides of the canonicalization must agree.
    #[test]
    fn ensure_cached_canonical_hits_split_insertion_symmetric() {
        let info = make_info(&["4.17.21"], vec![], vec![], vec![]);
        let client = Arc::new(RegistryClient::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = LpmDependencyProvider::new(client, rt.handle().clone(), HashMap::new());

        // Insert from the SPLIT side (as a test helper might). Note:
        // the walker in production only ever inserts canonical keys,
        // but the test helper canonicalizes at its boundary, so both
        // directions are functionally equivalent.
        let split = ResolverPackage::npm("lodash").with_context("eslint");
        provider.cache.insert(CanonicalKey::from(&split), info);

        // Canonical lookup — must hit.
        let canonical = ResolverPackage::npm("lodash");
        provider
            .ensure_cached(&canonical)
            .expect("canonical lookup must resolve via the split-inserted canonical key");
    }
}
