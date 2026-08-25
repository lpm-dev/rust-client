use super::manifest_core::CachedPackageInfo;
use super::prelude::*;

/// Shared metadata cache for the streaming BFS resolver.
///
/// Keyed by [`CanonicalKey`] — split-retry identities of the same canonical
/// package share a single entry. The walker inserts under canonical names;
/// the provider canonicalizes at every read so split contexts hit the
/// same cell. Changing this to a context-bearing key re-introduces a
/// silent notify-miss bug (split contexts silently miss walker-inserted
/// entries and fall through to escape-hatch fetches).
///
/// Values are wrapped in `Arc` so `.value().clone()` is a refcount bump,
/// not a deep clone of 7 nested HashMaps. The greedy resolver's
/// `ensure_manifest` was hitting ~5 sec of allocator churn cloning
/// popular packuments per edge (lodash + react + eslint transitives have
/// hundreds of versions × dozens of deps each); with Arc the per-edge
/// cost drops to nanoseconds.
pub type SharedCache = Arc<DashMap<CanonicalKey, Arc<CachedPackageInfo>>>;

/// Per-canonical-key waker map. The walker fires `notify_waiters()` after
/// inserting each manifest; the provider's `ensure_cached` wait-loop
/// awaits on the same handle. Per-package granularity (vs. a global
/// `Notify`) avoids spurious wakes that would stall unrelated waiters.
pub type NotifyMap = Arc<DashMap<CanonicalKey, Arc<Notify>>>;

/// Walker-done flag, shared between [`crate::BfsWalker`] and the
/// provider's `ensure_cached` wait-loop.
///
/// The walker stores `true` (Release) when [`crate::BfsWalker::run`] is
/// about to return, *immediately before* broadcasting `notify_waiters()`
/// across every entry in the [`NotifyMap`]. Once the flag flips, no
/// further `shared_cache` inserts will happen — any wait-loop sleeping
/// on a key the walker decided not to fetch (e.g. an older-version
/// transitive missed by newest-only expansion) would otherwise burn the
/// full `fetch_wait_timeout` for nothing. The wait-loop checks the flag
/// after `Notified::enable()` and short-circuits to the escape-hatch
/// fetch when set.
///
/// Defaults to `Arc::new(AtomicBool::new(false))` for callers with no
/// walker attached — `fetch_wait_timeout == ZERO` skips the wait-loop
/// wholesale, so the flag is consulted only when the loop runs.
pub type WalkerDone = Arc<AtomicBool>;

/// Provider-side observability for `timing.resolve.streaming_bfs`.
///
/// Three atomic counters, share across split-retry passes via the
/// inner `Arc<AtomicU64>`s. Install.rs creates a single instance,
/// hands it to the resolver, and reads the snapshot after resolution
/// completes for JSON output.
///
/// Counter semantics (qualitative — exact values depend on walker
/// timing vs. PubGrub scheduling, split-retry reentrancy, and how
/// often `ensure_cached` is called per package):
///
/// - `cache_waits` — incremented only on `ensure_cached` misses
///   with a non-zero `fetch_wait_timeout`. Fast-path cache hits do
///   not count. `ensure_cached` may be invoked multiple times per
///   package across split-retry passes, so this is NOT equal to the
///   installed package count; treat it as "how many times PubGrub
///   had to wait on the walker." Walker-keeps-up runs have far
///   fewer cache_waits than installed packages.
///
/// - `cache_wait_timeouts` — incremented when a wait-loop iteration
///   exits by timeout. Healthy 0.
///
/// - `escape_hatch_fetches` — incremented on every non-root
///   `direct_fetch_and_cache` call. Healthy 0 when the walker is
///   attached and keeps ahead of PubGrub. Non-zero signals either
///   (a) a walker gap (walker didn't reach a package PubGrub needed)
///   or (b) no walker attached (`fetch_wait_timeout == ZERO`, where
///   every miss routes through the escape hatch).
///
/// - `cache_wait_walker_done_shortcuts` — incremented when the wait-loop
///   exited early because the walker had already finished and the key
///   was confirmed not cached. The healthy outcome of the walker-done
///   broadcast: missed transitives route to the escape-hatch in
///   microseconds instead of burning the full `fetch_wait_timeout`.
///   This counter + `escape_hatch_fetches` is the canary for "walker
///   had a gap, but it was cheap to recover".
#[derive(Debug, Clone, Default)]
pub struct StreamingBfsMetrics {
    pub(super) cache_waits: Arc<AtomicU64>,
    pub(super) cache_wait_timeouts: Arc<AtomicU64>,
    pub(super) escape_hatch_fetches: Arc<AtomicU64>,
    pub(super) cache_wait_walker_done_shortcuts: Arc<AtomicU64>,
}

#[derive(Debug)]
pub(crate) enum SkippedDependencyReason {
    Fetch { detail: String, warn_auth: bool },
    InvalidRange { detail: String },
    NoMatchingVersion { detail: String },
}

impl SkippedDependencyReason {
    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Fetch { detail, .. }
            | Self::InvalidRange { detail }
            | Self::NoMatchingVersion { detail } => detail,
        }
    }

    pub(crate) fn warns_about_auth(&self) -> bool {
        matches!(
            self,
            Self::Fetch {
                warn_auth: true,
                ..
            }
        )
    }

    pub(crate) fn counts_as_platform_skip(&self) -> bool {
        matches!(self, Self::NoMatchingVersion { .. })
    }
}

#[derive(Debug)]
pub(crate) struct SkippedDependency {
    pub(crate) parent: ResolverPackage,
    pub(crate) parent_version: String,
    pub(crate) child: ResolverPackage,
    pub(crate) local_name: String,
    pub(crate) requested: String,
    pub(crate) edge_is_optional: bool,
    pub(crate) reason: SkippedDependencyReason,
}

impl SkippedDependency {
    pub(super) fn new(
        parent: &ResolverPackage,
        parent_version: &NpmVersion,
        child: &ResolverPackage,
        local_name: &str,
        requested: &str,
        edge_is_optional: bool,
        reason: SkippedDependencyReason,
    ) -> Self {
        Self {
            parent: parent.clone(),
            parent_version: parent_version.to_string(),
            child: child.clone(),
            local_name: local_name.to_string(),
            requested: requested.to_string(),
            edge_is_optional,
            reason,
        }
    }
}

/// The DependencyProvider that bridges PubGrub with LPM's registry.
pub struct LpmDependencyProvider {
    pub(super) client: Arc<RegistryClient>,
    pub(super) rt: Handle,
    /// Canonical-keyed, concurrent metadata cache. When a walker is
    /// attached, the same `Arc` is handed to the walker so inserts become
    /// visible to the provider without a copy.
    pub(super) cache: SharedCache,
    /// Per-canonical-key waker map. Populated on-demand by the wait-loop
    /// inside `ensure_cached`; walker calls `notify_waiters()` on the
    /// matching entry after insert.
    pub(super) notify_map: NotifyMap,
    /// Routing policy for escape-hatch fetches. LPM packages still go via
    /// the Worker regardless (see [`RouteTable::route_for_package`]).
    /// When `.npmrc` is parsed, this is a full [`RouteTable`] so
    /// custom registries can produce [`UpstreamRoute::Custom`].
    pub(super) route_table: RouteTable,
    /// How long `ensure_cached`'s wait-loop is willing to block on a
    /// walker insert before falling through to the direct fetch escape hatch.
    ///
    /// Defaults to [`Duration::ZERO`] so the provider stays fetch-on-miss
    /// when no walker is attached.
    pub(super) fetch_wait_timeout: Duration,
    /// Wait-loop early-exit signal. See [`WalkerDone`] for the
    /// shutdown-handshake rationale. Default `Arc::new(AtomicBool::new(false))`
    /// for callers with no walker — the wait-loop never runs
    /// (`fetch_wait_timeout == ZERO`), so the flag is unobserved. The
    /// orchestration layer shares the *same* Arc with the walker so the
    /// walker's terminal store is visible here without a re-allocation.
    pub(super) walker_done: WalkerDone,
    /// Streaming-BFS observability counters. Shared Arc across split-retry
    /// passes; install.rs reads the snapshot after resolution for
    /// `timing.resolve.streaming_bfs` JSON output.
    pub(super) metrics: StreamingBfsMetrics,
    pub(super) root_dependencies: RootDependencies,
    /// Packages that should be split into per-parent identities.
    pub(super) split_packages: HashSet<String>,
    /// Fully-parsed override IR. Records every applied override so callers
    /// can drain the trace after `pubgrub::resolve` returns. Always present
    /// (defaults to `OverrideSet::empty()` when no overrides are declared).
    pub(super) overrides: OverrideSet,
    /// Set after the first batch_metadata call fails (e.g., 401).
    /// Prevents repeated guaranteed-failing batch requests during resolution.
    /// Individual ensure_cached calls still work as fallback.
    pub(super) batch_disabled: Mutex<bool>,
    pub(super) policy: ResolverPolicy,
    /// Root-level npm-alias edges accumulated as `get_dependencies(Root)`
    /// walks `self.root_dependencies`. Shape: `local_name → target_canonical_name`.
    /// Surfaced via `into_parts()` so `ResolveResult.root_aliases` carries
    /// the map into the install pipeline, which feeds it to the linker.
    pub(super) root_aliases: Mutex<HashMap<String, String>>,
    /// Dependency edges provisionally omitted while PubGrub explores versions.
    /// Their effective optionality is decided from the final selected graph.
    pub(super) skipped_dependencies:
        Mutex<HashMap<(ResolverPackage, String, ResolverPackage, String), SkippedDependency>>,
    /// Memoize `(ResolverPackage, raw_range) → Ranges<NpmVersion>` so
    /// repeated PubGrub `get_dependencies` queries for the same edge skip
    /// the O(N-versions) conversion inside `NpmRange::to_pubgrub_ranges`.
    /// The uncached conversion measured at ~962 ms of `pubgrub_core_ms`
    /// when the metadata cache grew by 9 packages; the uncached O(queries
    /// × N) cost is what made the resolver look "sensitive to metadata bloat."
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
    /// NOT transferred across provider instances. The `SharedCache`
    /// Arc carries metadata across split-retry passes;
    /// this range cache is re-built per pass. Keeps the invariant
    /// local: anything that changes how `available_versions` resolves
    /// (e.g. a future per-split platform override) can't accidentally
    /// read stale memoized Ranges from a prior pass.
    pub(super) range_cache: Mutex<HashMap<(ResolverPackage, String), Ranges<NpmVersion>>>,
    pub(super) available_versions_cache: Mutex<HashMap<ResolverPackage, Arc<[NpmVersion]>>>,
    pub(super) include_optional_dependencies: bool,
}
