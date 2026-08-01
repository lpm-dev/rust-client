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

/// Distribution info for a specific version.
///
/// Extracted from registry metadata so the download phase doesn't need to
/// re-fetch metadata for tarball URL, integrity, or registry signatures.
#[derive(Debug, Clone, Default)]
pub struct CachedDistInfo {
    pub tarball_url: Option<String>,
    pub integrity: Option<String>,
    pub signatures: Vec<lpm_registry::RegistrySignature>,
    pub published_at: Option<String>,
    pub published_at_unix: Option<i64>,
    pub trust_evidence: Option<TrustEvidence>,
}

/// Cached info about a package: available versions and their dependency maps.
#[derive(Debug, Clone)]
pub struct CachedPackageInfo {
    /// Package-level `modified` timestamp from npm metadata. Abbreviated
    /// packuments often omit per-version `time` but keep this upper bound.
    pub modified: Option<String>,
    pub modified_unix: Option<i64>,
    /// True when this cache entry came from a full packument fetch, so
    /// missing trust evidence can be treated as genuinely absent rather
    /// than "not present in abbreviated metadata."
    pub trust_metadata_complete: bool,
    /// True when `versions` represents the complete available version set.
    /// Range-aware Worker responses intentionally carry only selected
    /// versions, so broad ranges must refetch before choosing a version.
    pub versions_complete: bool,
    /// Range strings for which an incomplete `versions` set is known to be
    /// Worker-selected. Empty for normal complete packuments.
    pub covered_ranges: HashSet<String>,
    /// Versions sourced from local workspace manifests rather than registry
    /// packuments. A satisfying local version is preferred, while a range
    /// that matches none of these versions must be allowed to fetch registry
    /// metadata for the same package name.
    pub workspace_versions: HashSet<NpmVersion>,
    /// True when the registry response included full per-version platform
    /// fields. npm abbreviated packuments retain `os` and `cpu` but omit
    /// `libc`, so a non-empty platform map is not necessarily complete.
    pub platform_metadata_complete: bool,
    /// Parsed target of the registry's authoritative `latest` dist-tag.
    pub latest_version: Option<NpmVersion>,
    /// Available versions, sorted descending (newest first).
    pub versions: Vec<NpmVersion>,
    /// Regular dependencies for each version: version_string → { dep_name → range_string }.
    pub deps: HashMap<String, HashMap<String, String>>,
    /// Peer dependencies for each version: version_string → { dep_name → range_string }.
    /// A same-named regular or optional dependency takes precedence and is omitted here.
    /// Checked post-resolution against the actual resolved tree (not during resolution).
    pub peer_deps: HashMap<String, HashMap<String, String>>,
    /// Optional dependency names (per version). Included in deps but resolution failure
    /// for these is non-fatal.
    pub optional_dep_names: HashMap<String, HashSet<String>>,
    /// `peerDependenciesMeta.optional`
    /// flags per version: `version_string → { peer_name }` for peers
    /// the manifest marked optional. Consumed by [`crate::check_unmet_peers`]
    /// to suppress the missing-peer warning (an opt-out the manifest
    /// author requested). Optional peers that ARE present but at the
    /// wrong version still produce a warning — the user opted into
    /// having a peer, just at an incompatible version.
    pub optional_peer_names: HashMap<String, HashSet<String>>,
    /// `engines.node` constraints keyed by version string. Versions without
    /// a Node.js constraint are absent from the map.
    pub node_engines: HashMap<String, String>,
    /// `bundleDependencies` /
    /// `bundledDependencies` names per version. Per-version because
    /// the same package's bundling intent can change across releases
    /// (e.g., a maintainer drops bundling between major versions).
    /// The resolver skips enqueueing these names as separate installs
    /// — they're already provided by the parent's tarball. The
    /// extractor preserves the in-tarball `node_modules/<bundled>/`
    /// subtree implicitly; without bundled-dependency filtering the resolver also fetches a
    /// registry copy of the bundled name, which the linker may then
    /// shadow over the bundled copy depending on hoisting precedence.
    pub bundled_dep_names: HashMap<String, HashSet<String>>,
    /// Platform restrictions per version: version_string → PlatformMeta.
    /// Only populated for versions that declare os/cpu/libc restrictions.
    pub platform: HashMap<String, PlatformMeta>,
    /// Distribution info per version: tarball URL and integrity hash.
    /// Carried through to the download phase to avoid re-fetching metadata.
    pub dist: HashMap<String, CachedDistInfo>,
    /// npm-alias dep edges per version. Shape:
    /// `version_string → { local_name → target_canonical_name }`.
    /// Only populated for versions whose declared deps include the
    /// `npm:<target>@<range>` alias syntax. Used by the resolver to
    /// (a) resolve each aliased dep under its target identity in
    /// PubGrub, and (b) populate `ResolvedPackage.aliases` so the
    /// linker can build `node_modules/<local>/` → store entry for
    /// `<target>@<version>`.
    pub aliases: HashMap<String, HashMap<String, String>>,
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

impl CachedPackageInfo {
    pub(super) fn remove_shadowed_peer_requirements(&mut self) {
        let deps = &self.deps;
        self.peer_deps.retain(|version, peers| {
            if let Some(regular) = deps.get(version) {
                peers.retain(|name, _| !regular.contains_key(name));
            }
            !peers.is_empty()
        });
        self.optional_peer_names.retain(|version, peers| {
            if let Some(regular) = deps.get(version) {
                peers.retain(|name| !regular.contains_key(name));
            }
            !peers.is_empty()
        });
    }

    pub fn needs_metadata_for_range(&self, range: &NpmRange) -> bool {
        if self.versions_complete || self.workspace_version_satisfies(range) {
            return false;
        }
        if let Some(exact) = range.exact_version() {
            return !self.versions.contains(&exact);
        }
        !self.covered_ranges.contains(range.raw())
            || !self.versions.iter().any(|version| {
                range.satisfies_with_latest_bound(version, self.latest_version.as_ref())
            })
    }

    pub fn workspace_version_satisfies(&self, range: &NpmRange) -> bool {
        self.workspace_versions
            .iter()
            .any(|version| range.satisfies_with_latest_bound(version, self.latest_version.as_ref()))
    }

    pub fn needs_trust_metadata(&self, policy: &ResolverPolicy) -> bool {
        policy.requires_trust_history() && !self.trust_metadata_complete
    }

    pub fn needs_release_time_metadata(
        &self,
        package: &CanonicalKey,
        policy: &ResolverPolicy,
    ) -> bool {
        if !policy.release_age_active() || policy.release_age_excluded(package) {
            return false;
        }
        let missing_version_time = self.versions.iter().any(|version| {
            self.dist
                .get(&version.to_string())
                .and_then(|dist| dist.published_at.as_deref())
                .is_none()
        });
        missing_version_time
            && policy.metadata_modified_after_cutoff_for_package(
                package,
                self.modified.as_deref(),
                self.modified_unix,
            )
    }

    pub fn needs_policy_metadata(&self, package: &CanonicalKey, policy: &ResolverPolicy) -> bool {
        self.needs_trust_metadata(policy) || self.needs_release_time_metadata(package, policy)
    }

    pub fn needs_platform_metadata(&self) -> bool {
        !self.platform_metadata_complete
            && self.platform.values().any(|platform| {
                platform.libc.is_empty()
                    && (!platform.os.is_empty() || !platform.cpu.is_empty())
                    && platform_may_target_linux(&platform.os)
            })
    }

    pub fn needs_supplemental_metadata(
        &self,
        package: &CanonicalKey,
        policy: &ResolverPolicy,
    ) -> bool {
        self.needs_policy_metadata(package, policy) || self.needs_platform_metadata()
    }
}

fn platform_may_target_linux(os: &[String]) -> bool {
    if os.is_empty() {
        return true;
    }
    if os.iter().any(|entry| entry.starts_with('!')) {
        return !os.iter().any(|entry| entry == "!linux");
    }
    os.iter().any(|entry| entry == "linux")
}

/// Platform restriction metadata for a specific package version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformMeta {
    /// OS restrictions: e.g., ["darwin", "linux"] or ["!win32"].
    pub os: Vec<String>,
    /// CPU restrictions: e.g., ["x64", "arm64"] or ["!ia32"].
    pub cpu: Vec<String>,
    /// Linux libc restrictions: e.g., ["musl"], ["glibc"], or ["!glibc"].
    /// Same inclusion / exclusion semantics as `os` / `cpu`, per the npm
    /// spec at <https://docs.npmjs.com/cli/v9/configuring-npm/package-json#libc>.
    /// Empty when the manifest declares no libc restriction.
    pub libc: Vec<String>,
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
    /// Fully-parsed override IR. Records every applied override into its
    /// internal `RefCell<Vec<OverrideHit>>` so callers can drain the trace
    /// after `pubgrub::resolve` returns. Always present (defaults to
    /// `OverrideSet::empty()` when no overrides are declared).
    pub(super) overrides: OverrideSet,
    /// Set after the first batch_metadata call fails (e.g., 401).
    /// Prevents repeated guaranteed-failing batch requests during resolution.
    /// Individual ensure_cached calls still work as fallback.
    pub(super) batch_disabled: RefCell<bool>,
    pub(super) policy: ResolverPolicy,
    /// Root-level npm-alias edges accumulated as `get_dependencies(Root)`
    /// walks `self.root_dependencies`. Shape: `local_name → target_canonical_name`.
    /// Surfaced via `into_parts()` so `ResolveResult.root_aliases` carries
    /// the map into the install pipeline, which feeds it to the linker.
    pub(super) root_aliases: RefCell<HashMap<String, String>>,
    /// Dependency edges provisionally omitted while PubGrub explores versions.
    /// Their effective optionality is decided from the final selected graph.
    pub(super) skipped_dependencies:
        RefCell<HashMap<(ResolverPackage, String, ResolverPackage, String), SkippedDependency>>,
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
    pub(super) range_cache: RefCell<HashMap<(ResolverPackage, String), Ranges<NpmVersion>>>,
    pub(super) available_versions_cache: RefCell<HashMap<ResolverPackage, Vec<NpmVersion>>>,
    pub(super) include_optional_dependencies: bool,
}
