//! High-level resolution entry point.
//!
//! Iterative split-retry approach:
//! 1. Try flat resolution (one version per package) — works for ~90% of real trees
//! 2. On conflict, identify packages needing multiple versions and retry with splits
//! 3. Keep adding new split candidates until resolution succeeds or no new candidates remain

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet};
use crate::package::{CanonicalKey, ResolverPackage};
use crate::policy::ResolverPolicy;
use crate::provider::{
    CachedPackageInfo, LpmDependencyProvider, NotifyMap, PlatformMeta, SharedCache,
    StreamingBfsMetrics,
};
use crate::ranges::NpmRange;
use lpm_registry::{RegistryClient, RouteMode, RouteTable};
use pubgrub::{DefaultStringReporter, Reporter};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;

/// A resolved package: name + selected version + its dependencies.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub package: ResolverPackage,
    pub version: NpmVersion,
    /// Dependencies of this package: (dep_name_in_parent, resolved_version_string).
    ///
    /// `dep_name_in_parent` is the LOCAL name used in THIS package's
    /// `dependencies` / `optionalDependencies` map. For non-aliased
    /// deps this equals the child's canonical registry name; for
    /// npm-alias deps (e.g., `"strip-ansi-cjs": "npm:strip-ansi@^6"`)
    /// it is the alias key, and the `aliases` map below records the
    /// alias's canonical target name. Keeping the local name as the
    /// edge key means the linker can build `node_modules/<local>/`
    /// directly from the edge without a second lookup.
    pub dependencies: Vec<(String, String)>,
    /// npm-alias edges. Key = `dep_name_in_parent`
    /// from the `dependencies` vec; value = target canonical package
    /// name (what to fetch from the registry + how the `.lpm/` store
    /// entry is keyed). Empty for packages that declare no aliased
    /// deps (the common case). Non-aliased edges are NOT present —
    /// callers compute `aliases.get(local).unwrap_or(local)` to get
    /// the target.
    pub aliases: HashMap<String, String>,
    /// Resolved peers that ARE in scope for this consumer in the
    /// install set. Shape: `(peer_name, resolved_version)` — same
    /// edge shape as `dependencies`, but read from
    /// `peerDependencies` / `peerDependenciesMeta` and intersected
    /// against the install set's resolved versions.
    ///
    /// Sorted by peer_name for deterministic lockfile / GraphKey
    /// hashing. Empty when this package declares no peers OR when
    /// every declared peer is missing from the install set
    /// (`check_unmet_peers` surfaces those as `PeerWarning`s).
    ///
    /// The v2 GraphKey folds these in so two projects sharing the
    /// same edge graph but different peer pinning produce distinct
    /// keys. Without this field, v2's `links/<key>/` entries silently
    /// shared across peer-divergent installs.
    pub peers: Vec<(String, String)>,
    /// Tarball download URL from registry metadata.
    /// Carried from resolution → download to avoid re-fetching metadata.
    pub tarball_url: Option<String>,
    /// SRI integrity hash (e.g. "sha512-...") from registry metadata.
    pub integrity: Option<String>,
    /// Platform restrictions declared by the selected package version.
    pub platform: Option<PlatformMeta>,
    /// True when this package is reachable only through optional dependency
    /// edges. Install-time platform filtering skips incompatible optional
    /// packages while failing required ones.
    pub optional: bool,
}

/// Internal type for PubGrub result + provider (to extract cache).
type PubGrubResult = Result<
    (
        pubgrub::SelectedDependencies<LpmDependencyProvider>,
        LpmDependencyProvider,
    ),
    Box<(
        pubgrub::PubGrubError<LpmDependencyProvider>,
        LpmDependencyProvider,
    )>,
>;

/// Result of dependency resolution: resolved packages + metadata cache
/// + override apply trace.
///
/// The cache is returned so callers can run post-resolution checks
/// (e.g., `check_unmet_peers`) against the actual resolved tree. The
/// `applied_overrides` vec is the override apply trace — every override
/// the resolver honored, in `(package, raw_key)` order.
pub struct ResolveResult {
    /// Resolved packages with dependency edges.
    pub packages: Vec<ResolvedPackage>,
    /// Metadata cache from resolution. Contains peer_deps, platform info, etc.
    /// Used by `check_unmet_peers()` for post-resolution peer checking.
    ///
    /// Values are `Arc<CachedPackageInfo>` so the resolver's
    /// end-of-resolve materialization is an `Arc::clone` per entry
    /// (refcount bump) rather than a deep-clone of seven nested
    /// HashMaps. Consumers that need an owned `CachedPackageInfo` can
    /// `(*arc).clone()` at their use site; everything in the codebase
    /// today reads fields through `&Arc<CachedPackageInfo>` (auto-deref).
    pub cache: HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    /// Override apply trace. Empty when no
    /// `lpm.overrides` / `overrides` / `resolutions` were declared OR
    /// when none of them matched any resolved package. Sorted by
    /// `(package, raw_key)` for deterministic output.
    pub applied_overrides: Vec<OverrideHit>,
    /// Count of optional deps skipped because no platform-compatible
    /// version satisfies the declared range on the current OS/CPU.
    /// Surfaced in install `--json` output as
    /// `timing.resolve.platform_skipped` for observability. Taken from
    /// the FINAL successful pass — retry passes share the same fixture
    /// so the count is deterministic.
    pub platform_skipped: usize,
    /// Root-level npm-alias edges the resolver saw on
    /// the consumer's `package.json` deps. Shape:
    /// `local_name → target_canonical_name`. Empty when no root dep
    /// uses `npm:<target>@<range>` syntax. The install pipeline uses
    /// this to (a) drive root `node_modules/<local>/` symlinks and (b)
    /// persist aliases in the lockfile for deterministic re-install.
    pub root_aliases: HashMap<String, String>,
    /// Ambient installs synthesized by the eager peer-drain pass.
    /// Shape: each entry is the canonical name of a package the
    /// resolver auto-installed because some consumer declared it as a
    /// required peer that wasn't otherwise in the resolved tree.
    /// Sorted alphabetically for deterministic output.
    ///
    /// Why this exists as a separate field: the install pipeline's
    /// `resolved_to_install_packages` derives "is this a top-level
    /// node_modules entry?" from `pkg.dependencies` (the user's
    /// `package.json`). An ambient peer install is NOT in
    /// `package.json` — it was synthesized at resolve-time — so
    /// without this field the install pipeline would extract the
    /// package into the store but never surface it at
    /// `node_modules/<name>/`. Install-side merges this set with
    /// `pkg.dependencies` when computing top-level link names +
    /// direct-dep flags.
    ///
    /// Empty when no peers needed synthesis OR when
    /// `auto_install_peers` was false.
    pub ambient_peer_installs: Vec<String>,
    /// Best-effort peer-conflict reports. Each entry is one peer
    /// canonical whose required consumer ranges were pairwise-
    /// incompatible: lpm picked the version satisfying the most
    /// consumers and recorded the unsatisfied ones here. Mirrors npm
    /// v7+ / pnpm hoisted-mode behavior — pick one peer top-level,
    /// warn the rest. The install pipeline prints a single warning
    /// block per entry after the install summary.
    ///
    /// Sorted alphabetically by `canonical` for deterministic warning
    /// order. Empty when the resolved peer graph is clean.
    pub peer_conflicts: Vec<crate::greedy::PeerConflictReport>,
    /// Substage breakdown of cold-resolve wall-clock.
    /// Observability-only; the fields and their overlap contract are
    /// documented on [`StageTiming`].
    pub stage_timing: StageTiming,
}

/// Per-substage wall-clock breakdown emitted by
/// [`resolve_with_shared_cache`].
///
/// Scope: the counters are reset at the start of every
/// `resolve_with_shared_cache` call and snapshot at the end, so they
/// capture work done by the RESOLVER — not install.rs's walker
/// roots-ready wait. install.rs measures that separately
/// (`timing.resolve.initial_batch_ms`) and combines both numbers
/// before surfacing to `--json`.
///
/// Field contract:
/// - `followup_rpc_ms` + `followup_rpc_count` are the follow-up
///   metadata fetches fired from inside the provider's callbacks
///   (follow-up depth/fanout lever). On a fully-cached warm install
///   they're both zero; on a cold install with a shallow worker
///   deep-walk they dominate `resolve_ms`.
/// - `parse_ndjson_ms` is serde_json CPU time for follow-up batches
///   only. The initial batch's parse time is folded into
///   install.rs's `initial_batch_ms` wall-clock.
/// - `pubgrub_ms` covers every pass of the `spawn_blocking` that
///   runs `pubgrub::resolve()` — sum across split-retries. Includes
///   any provider callback time, so `pubgrub_ms - followup_rpc_ms`
///   approximates pubgrub-core work (backtracking, selection).
#[derive(Debug, Clone, Default, Copy)]
pub struct StageTiming {
    /// Wall-clock spent in follow-up metadata RPCs triggered from
    /// inside the resolver's PubGrub callbacks. Does NOT include
    /// install.rs's pre-resolve initial batch. Reset + snapshot
    /// boundaries ensure this number is zero when the resolver is
    /// called on a warm cache with no cache misses.
    pub followup_rpc_ms: u64,
    /// Total number of metadata RPCs that went to the network during
    /// this resolve pass. Equals
    /// `walker_rpc_count + escape_hatch_rpc_count`. Previously this
    /// field conflated walker fetches and provider escape-hatch
    /// fetches; now the two are reported separately on
    /// `walker_rpc_count` / `escape_hatch_rpc_count` below. This
    /// total stays for backward compatibility with `--json` consumers.
    pub followup_rpc_count: u32,
    /// NDJSON deserialization CPU time for follow-up batches. Grows
    /// with the total number of VERSIONS across those batches, so
    /// it's a direct signal for the P3d "slim the batch response"
    /// lever. Initial batch parse time is folded into
    /// `initial_batch_ms` on the install side.
    pub parse_ndjson_ms: u64,
    /// Wall-clock spent inside the `spawn_blocking` that hosts
    /// `pubgrub::resolve()`. Summed across split-retry passes. On
    /// the happy path (no retries) this equals the resolver's
    /// total work.
    pub pubgrub_ms: u64,
    /// Number of metadata RPCs the walker fired. Each parallel-fetch
    /// per-package GET counts once; each `batch_metadata` call counts
    /// once regardless of name count. High walker_rpc + low
    /// escape_hatch = walker working well. Low walker_rpc + high
    /// escape_hatch = walker depth/fanout undersized.
    ///
    /// Zero under the fused dispatcher (`LPM_GREEDY_FUSION=1`) since
    /// the walker is bypassed entirely. Use `dispatcher_rpc_count`
    /// instead for the fusion arm.
    pub walker_rpc_count: u32,
    /// Number of metadata RPCs the provider's escape hatch fired
    /// (manifests not produced by the walker before
    /// `fetch_wait_timeout` expired). The actionable signal — see
    /// `walker_rpc_count` for tuning levers.
    ///
    /// Zero under the fused dispatcher — there is no escape-hatch
    /// path because there is no walker to be missed.
    pub escape_hatch_rpc_count: u32,
    /// Total metadata RPCs the fused dispatcher fired
    /// during this resolve pass. Replaces
    /// `walker_rpc_count + escape_hatch_rpc_count` under fusion: each
    /// per-canonical fetch counts once whether driven by a root edge
    /// or a transitive child completion. Zero on the walker arm.
    /// Equality `dispatcher_rpc_count == walker_rpc_count +
    /// escape_hatch_rpc_count` (modulo arm) is a sanity check on the
    /// instrumentation.
    pub dispatcher_rpc_count: u64,
    /// Peak `metadata_jobs.len()` observed at any Phase A→C
    /// transition of the fused dispatcher loop. Confirms the metadata
    /// semaphore is the binding constraint when this approaches the
    /// configured fanout; if it sits well below, the binding
    /// constraint is something upstream (h2 single-connection flow
    /// control, h1-pool socket count, or a serialization in
    /// `process_edge`).
    pub dispatcher_inflight_high_water: u64,
    /// `max(parked.values().map(|v| v.len()))` over the
    /// life of the fused dispatcher loop. Catches pathological
    /// parking — e.g., every edge in the tree blocked on one slow
    /// canonical's manifest. Healthy values are O(distinct version
    /// requests for the same canonical from sibling parents); any
    /// reading in the hundreds is a signal the registry is stalling
    /// on one specific package.
    pub parked_max_depth: u32,
    /// Count of selected-version metadata frames emitted to an optional
    /// install-side tarball speculation channel. Zero on the walker arm
    /// and on fusion callers that do not pass a speculation channel.
    pub tarball_dispatched_count: u64,
    /// Count of speculative peer-manifest fetches the fused dispatcher
    /// dispatched concurrent with the regular dep walk. Each prefetch
    /// corresponds to one `peerDependencies` requirement that (at the
    /// moment Phase A drained) was: non-optional, not yet satisfied
    /// by the resolved tree, not yet in the shared cache, and not yet
    /// in flight from a sibling dispatch.
    ///
    /// **What this counter means observability-wise:**
    /// - `0` — no required peers were missing at any point during the
    ///   resolve, OR `auto_install_peers` was off.
    /// - `> 0` — peer fetches that would have run SERIALLY in the
    ///   post-loop drain pass instead ran concurrently with the
    ///   regular dep dispatch. Each prefetch saves one network
    ///   round-trip from the critical path.
    /// - The counter MAY be lower than `len(ambient_peer_installs)`:
    ///   a peer canonical that gets pulled in as a regular transitive
    ///   AFTER the prefetch dispatched is still counted; but a peer
    ///   canonical pulled in BEFORE the prefetch evaluated (cache hit
    ///   at picker time) will NOT bump this counter. The counter
    ///   measures "prefetches we issued," not "peers that ultimately
    ///   landed."
    ///
    /// Zero on the walker arm (speculative prefetch is fused-only —
    /// the walker arm is the legacy opt-out and not a performance
    /// target).
    pub peer_prefetch_count: u64,
}

/// Resolve dependencies for a project.
///
/// Uses an iterative split-retry approach:
/// 1. Start with flat resolution using PubGrub (one version per package)
/// 2. On each `NoSolution`, extract conflicting packages and add them to the split set
/// 3. Retry until resolution succeeds or the conflict report yields no new split candidates
///
/// Returns resolved packages with their dependency edges populated from
/// the resolver's metadata cache.
pub async fn resolve_dependencies(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
) -> Result<ResolveResult, ResolveError> {
    // Default: eager peer auto-install ON. Callers that need warn-only
    // semantics use `resolve_with_shared_cache` directly with
    // `auto_install_peers = false`.
    resolve_dependencies_with_overrides(client, dependencies, OverrideSet::empty()).await
}

pub async fn resolve_dependencies_routed(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    route_table: RouteTable,
) -> Result<ResolveResult, ResolveError> {
    resolve_dependencies_with_overrides_routed(
        client,
        dependencies,
        OverrideSet::empty(),
        route_table,
    )
    .await
}

/// Resolve with a fully-parsed [`OverrideSet`].
///
/// **Path-selector wiring.** If the override set declares any path
/// selectors, the canonical names of their targets are added to the
/// resolver's split set before resolution starts. This guarantees that
/// path selectors work in flat resolution — the resolver doesn't have to
/// fall through to split-on-conflict retries for an override to take
/// effect. Every retry inherits the same set so conflict-driven splits
/// union with the override-driven ones.
pub async fn resolve_dependencies_with_overrides(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
) -> Result<ResolveResult, ResolveError> {
    resolve_dependencies_with_overrides_routed(
        client,
        dependencies,
        overrides,
        RouteTable::from_mode_only(RouteMode::Proxy),
    )
    .await
}

pub async fn resolve_dependencies_with_overrides_routed(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
) -> Result<ResolveResult, ResolveError> {
    // When no walker is wired, the caller gets a fresh empty shared
    // cache + zero wait-timeout. The provider's `ensure_cached`
    // wait-loop short-circuits on ZERO timeout and goes straight to
    // its escape-hatch fetch.
    use crate::provider::WalkerDone;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicBool;
    let shared_cache: SharedCache = Arc::new(DashMap::new());
    let notify_map: NotifyMap = Arc::new(DashMap::new());
    // Pre-49 callers don't run a walker, so this flag never flips. The
    // wait-loop is gated by `fetch_wait_timeout == ZERO` (set below)
    // and stays disabled regardless.
    let walker_done: WalkerDone = Arc::new(AtomicBool::new(false));
    resolve_with_shared_cache(
        client,
        dependencies,
        overrides,
        shared_cache,
        notify_map,
        walker_done,
        Duration::ZERO,
        route_table,
        StreamingBfsMetrics::new(),
        true, // default: auto-install peers ON.
    )
    .await
}

/// Resolve against a shared cache + notify map concurrently populated
/// by the [`BfsWalker`](crate::BfsWalker). The provider's wait-loop in
/// `ensure_cached` awaits on the per-canonical `Notify` for up to
/// `fetch_wait_timeout`; on timeout, its escape-hatch fetch runs via
/// `route_mode`.
///
/// Replaces the old `resolve_with_prefetch(..., prefetched: Option<HashMap<..>>)`
/// shape. `SharedCache` IS the prefetch now — whatever the walker (or
/// anyone else) has inserted before this function is called is already
/// visible, and anything still in flight comes in via `Notify`.
#[allow(clippy::too_many_arguments)] // design-level: orchestration surface for the shared-cache resolver entry point
pub async fn resolve_with_shared_cache(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: crate::provider::WalkerDone,
    fetch_wait_timeout: Duration,
    route_table: RouteTable,
    metrics: StreamingBfsMetrics,
    auto_install_peers: bool,
) -> Result<ResolveResult, ResolveError> {
    resolve_with_shared_cache_options(
        client,
        dependencies,
        overrides,
        shared_cache,
        notify_map,
        walker_done,
        fetch_wait_timeout,
        route_table,
        metrics,
        auto_install_peers,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_with_shared_cache_options(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: crate::provider::WalkerDone,
    fetch_wait_timeout: Duration,
    route_table: RouteTable,
    metrics: StreamingBfsMetrics,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
) -> Result<ResolveResult, ResolveError> {
    resolve_with_shared_cache_options_and_policy(
        client,
        dependencies,
        overrides,
        shared_cache,
        notify_map,
        walker_done,
        fetch_wait_timeout,
        route_table,
        metrics,
        auto_install_peers,
        include_optional_dependencies,
        ResolverPolicy::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_with_shared_cache_options_and_policy(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: crate::provider::WalkerDone,
    fetch_wait_timeout: Duration,
    route_table: RouteTable,
    metrics: StreamingBfsMetrics,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    policy: ResolverPolicy,
) -> Result<ResolveResult, ResolveError> {
    // Greedy is the default; users opt out to the legacy
    // PubGrub-with-split-retry resolver via `LPM_RESOLVER=pubgrub`.
    // The flag dispatches at the public entry-point so every caller —
    // install.rs, audit, tests — switches together.
    //
    // This function is the LEGACY WALKER ARM. install.rs now
    // short-circuits to `resolve_greedy_fused` (the fused dispatcher)
    // unless `LPM_RESOLVER=pubgrub` or `LPM_GREEDY_FUSION=0` is set.
    // See install.rs `fusion_enabled_local` for the resolver-dispatch
    // matrix.
    if std::env::var("LPM_RESOLVER").as_deref() != Ok("pubgrub") {
        return crate::greedy::resolve_greedy_with_options_and_policy(
            client,
            dependencies,
            overrides,
            shared_cache,
            notify_map,
            walker_done,
            fetch_wait_timeout,
            route_table,
            metrics,
            auto_install_peers,
            include_optional_dependencies,
            policy,
        )
        .await;
    }

    let _span = tracing::debug_span!("resolve", n_deps = dependencies.len()).entered();
    let rt = Handle::current();

    // Reset profiling accumulators once before resolution starts.
    // Counters accumulate across all retry passes so the final summary
    // reflects the total resolver work, not just the last pass.
    crate::profile::reset_all();

    // Reset the registry-side metadata/parse accumulators so
    // `snapshot()` at the end of this call reports only work done
    // since entry. Safe to call even when the caller already warmed
    // the metadata cache via install.rs's initial batch — that
    // contribution is captured separately by the install-side timer.
    lpm_registry::timing::reset();

    // Pre-compute the split set from path selectors. Empty when no
    // path-selector overrides are declared, which keeps the no-overrides
    // path on the existing zero-allocation hot loop.
    let mut split_packages: HashSet<String> = overrides.split_targets().clone();
    let mut attempt = 0usize;

    // Accumulate pubgrub wall-clock across split-retry passes. The
    // `spawn_blocking` hosting `pubgrub::resolve()` is the innermost
    // correct boundary; anything outside (queueing, Tokio task
    // switching) is background noise that shouldn't be lumped in.
    let mut pubgrub_ms_total: u128 = 0;

    let final_result = loop {
        let deps_for_pass = dependencies.clone();
        let client_for_pass = client.clone();
        let rt_for_pass = rt.clone();
        let overrides_for_pass = overrides.clone();
        let split_packages_for_pass = split_packages.clone();
        let route_table_for_pass = route_table.clone();
        let policy_for_pass = policy.clone();
        // Same Arc shared across retry passes. The walker's Arc is the
        // same Arc as the provider's Arc on every pass, so any
        // metadata already fetched is immediately visible without a
        // into_cache/with_cache round-trip.
        let shared_cache_for_pass = shared_cache.clone();
        let notify_map_for_pass = notify_map.clone();
        // Same Arc<AtomicBool> across all split-retry passes. Once
        // the walker flips it, every subsequent pass's wait-loop
        // short-circuits the same way.
        let walker_done_for_pass = walker_done.clone();
        // Same metrics Arc across passes so split-retry counts
        // accumulate into the same counter set.
        let metrics_for_pass = metrics.clone();
        let include_optional_dependencies_for_pass = include_optional_dependencies;

        let pass_start = std::time::Instant::now();
        let result: PubGrubResult = tokio::task::spawn_blocking(move || {
            let provider = if split_packages_for_pass.is_empty() {
                LpmDependencyProvider::new(client_for_pass, rt_for_pass, deps_for_pass)
            } else {
                LpmDependencyProvider::new_with_splits(
                    client_for_pass,
                    rt_for_pass,
                    deps_for_pass,
                    split_packages_for_pass,
                )
            }
            .with_overrides(overrides_for_pass)
            .with_shared_cache(
                shared_cache_for_pass,
                notify_map_for_pass,
                walker_done_for_pass,
                fetch_wait_timeout,
            )
            .with_route_table(route_table_for_pass)
            .with_streaming_metrics(metrics_for_pass)
            .with_include_optional_dependencies(include_optional_dependencies_for_pass)
            .with_policy(policy_for_pass);

            match pubgrub::resolve(&provider, ResolverPackage::Root, NpmVersion::new(0, 0, 0)) {
                Ok(solution) => Ok((solution, provider)),
                Err(e) => Err(Box::new((e, provider))),
            }
        })
        .await
        .map_err(|e| ResolveError::Internal(format!("resolver task panicked: {e}")))?;
        // Accumulate this pass's pubgrub wall-clock. Split-retry
        // passes each add to the total, matching how `metadata_rpc_ms`
        // accumulates at the registry layer.
        pubgrub_ms_total = pubgrub_ms_total.saturating_add(pass_start.elapsed().as_millis());

        match result {
            Ok((solution, provider)) => {
                let (cache, applied_overrides, platform_skipped, root_aliases, root_deps) =
                    provider.into_parts();
                let packages = format_solution(solution, &cache, &root_deps, &root_aliases);
                // Snapshot substage counters at the tail of the happy
                // path. The registry-side atomics were reset at the
                // top of this call, so they now reflect only follow-up
                // RPCs (the walker's measurement is surfaced separately
                // by install.rs).
                let snap = lpm_registry::timing::snapshot();
                // Dispatcher fields stay at default 0 on the
                // PubGrub/walker path; populated only by the fused
                // dispatcher in `resolve_greedy_fused`.
                let stage_timing = StageTiming {
                    followup_rpc_ms: snap.metadata_rpc.as_millis() as u64,
                    followup_rpc_count: snap.metadata_rpc_count,
                    parse_ndjson_ms: snap.parse_ndjson.as_millis() as u64,
                    pubgrub_ms: pubgrub_ms_total as u64,
                    walker_rpc_count: snap.walker_rpc_count,
                    escape_hatch_rpc_count: snap.escape_hatch_rpc_count,
                    ..StageTiming::default()
                };
                break Ok(ResolveResult {
                    packages,
                    cache,
                    applied_overrides,
                    platform_skipped,
                    root_aliases,
                    // The PubGrub/walker arm doesn't implement eager
                    // peer auto-install (legacy correctness opt-out via
                    // `LPM_RESOLVER=pubgrub`). Users who pin to pubgrub
                    // get warn-only peer semantics, same as
                    // `auto_install_peers = false`.
                    ambient_peer_installs: Vec::new(),
                    peer_conflicts: Vec::new(),
                    stage_timing,
                });
            }
            Err(err) if matches!(err.0, pubgrub::PubGrubError::NoSolution(_)) => {
                let (pubgrub::PubGrubError::NoSolution(mut derivation_tree), provider) = *err
                else {
                    unreachable!()
                };
                derivation_tree.collapse_no_versions();
                let report = DefaultStringReporter::report(&derivation_tree);

                let conflicting = extract_conflicting_packages(&report);
                if conflicting.is_empty() {
                    break Err(ResolveError::NoSolution(report));
                }

                let mut new_splits: Vec<String> = conflicting
                    .into_iter()
                    .filter(|pkg| !split_packages.contains(pkg))
                    .collect();
                if new_splits.is_empty() {
                    break Err(ResolveError::NoSolution(report));
                }

                new_splits.sort();
                split_packages.extend(new_splits.iter().cloned());
                // The shared cache persists across retry passes via the
                // `Arc` held in `shared_cache_for_pass`. Drop provider
                // without `into_cache()` — the `Arc<DashMap>` stays
                // live because the next pass re-clones the outer Arc.
                drop(provider);
                attempt += 1;

                if attempt == 1 {
                    tracing::info!(
                        "flat resolution failed, splitting {} package(s): {}",
                        split_packages.len(),
                        split_packages
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                } else {
                    tracing::info!(
                        "split pass {} failed, adding {} more split package(s): {}",
                        attempt,
                        new_splits.len(),
                        new_splits.join(", ")
                    );
                }
            }
            Err(err) => break Err(map_pubgrub_error(err.0)),
        }
    };

    // Dump cumulative resolver profile after all passes complete.
    // Counters accumulate across all split-retry passes.
    tracing::debug!(
        "resolver profile (all passes):\n{}",
        crate::profile::summary()
    );

    final_result
}

/// Convert PubGrub solution + cached metadata into `ResolvedPackage` list
/// with dependency edges populated.
fn format_solution(
    solution: pubgrub::SelectedDependencies<LpmDependencyProvider>,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
) -> Vec<ResolvedPackage> {
    // Build a lookup: canonical_name → resolved_version for cross-referencing deps
    let resolved_versions: HashMap<String, String> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(pkg, ver)| (pkg.canonical_name(), ver.to_string()))
        .collect();
    let resolved_peer_versions: HashMap<String, Vec<(Option<String>, String)>> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .fold(HashMap::new(), |mut acc, (pkg, ver)| {
            acc.entry(pkg.canonical_name())
                .or_default()
                .push((pkg.context().map(str::to_string), ver.to_string()));
            acc
        });

    let mut resolved: Vec<ResolvedPackage> = solution
        .into_iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(package, version)| {
            let ver_str = version.to_string();
            // Cache is canonical-keyed. Split-retry identities of the
            // same canonical package share one entry, so every lookup
            // canonicalizes.
            let key = CanonicalKey::from(&package);

            // Pull the per-version alias map from the cache so we can
            // (a) redirect edge-lookup to the aliased target's resolved
            // version and (b) surface the alias map on the resolved
            // package for the linker.
            let cached_aliases: HashMap<String, String> = cache
                .get(&key)
                .and_then(|info| info.aliases.get(&ver_str))
                .cloned()
                .unwrap_or_default();

            // Look up this package's declared deps from the provider
            // cache. `ver_deps` is keyed by the LOCAL dep name (what
            // appears in the parent's `dependencies` map). To look up
            // the resolved version in `resolved_versions` (keyed by
            // the child's canonical registry name) we redirect through
            // the per-version alias map.
            let dependencies = cache
                .get(&key)
                .and_then(|info| info.deps.get(&ver_str))
                .map(|ver_deps| {
                    ver_deps
                        .keys()
                        .filter_map(|local_name| {
                            let target_name = cached_aliases
                                .get(local_name)
                                .map_or(local_name.as_str(), String::as_str);
                            resolved_versions
                                .get(target_name)
                                .map(|resolved_ver| (local_name.clone(), resolved_ver.clone()))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Only surface aliases that actually survived resolution —
            // an optional aliased dep skipped by the platform filter is
            // not in `dependencies`, so carrying its alias entry would
            // be dead weight for the linker.
            let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
            let aliases: HashMap<String, String> = cached_aliases
                .iter()
                .filter(|(local, _)| alive_locals.contains(local))
                .map(|(l, t)| (l.clone(), t.clone()))
                .collect();

            // Extract tarball URL and integrity from cached dist info
            let (tarball_url, integrity) = cache
                .get(&key)
                .and_then(|info| info.dist.get(&ver_str))
                .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                .unwrap_or_default();
            let platform = cache
                .get(&key)
                .and_then(|info| info.platform.get(&ver_str))
                .cloned();

            // Surface resolved peers per package. The resolver already
            // proved each peer's range was satisfied (or surfaced a
            // `PeerWarning` for the gap); here we just intersect the
            // declared peers against the install set's resolved-
            // versions lookup. Missing peers simply don't appear in
            // the output Vec — the linker / GraphKey only cares about
            // peers that ARE present.
            let peers = compute_resolved_peers(&package, &ver_str, cache, &resolved_peer_versions);

            ResolvedPackage {
                package,
                version,
                dependencies,
                aliases,
                peers,
                tarball_url,
                integrity,
                platform,
                optional: false,
            }
        })
        .collect();
    mark_optional_reachability(&mut resolved, cache, root_deps, root_aliases);
    dedupe_peer_superset_packages(&mut resolved);
    resolved.sort_by_key(|a| a.package.to_string());
    resolved
}

fn mark_optional_reachability(
    packages: &mut [ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
) {
    if packages.is_empty() {
        return;
    }

    let mut by_name: HashMap<String, Vec<usize>> = HashMap::with_capacity(packages.len());
    let mut by_name_version: HashMap<(String, String), Vec<usize>> =
        HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        let name = package.package.canonical_name();
        let version = package.version.to_string();
        by_name.entry(name.clone()).or_default().push(idx);
        by_name_version
            .entry((name, version))
            .or_default()
            .push(idx);
    }

    let mut required = vec![false; packages.len()];
    let mut queue = VecDeque::new();
    for local_name in root_deps.keys() {
        let target = root_aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        if let Some(indices) = by_name.get(target) {
            for &idx in indices {
                if !required[idx] {
                    required[idx] = true;
                    queue.push_back(idx);
                }
            }
        }
    }

    while let Some(idx) = queue.pop_front() {
        let package = &packages[idx];
        let key = CanonicalKey::from(&package.package);
        let version = package.version.to_string();
        let optional_names = cache
            .get(&key)
            .and_then(|info| info.optional_dep_names.get(&version));

        for (local_name, dep_version) in &package.dependencies {
            if optional_names.is_some_and(|names| names.contains(local_name)) {
                continue;
            }
            let target = package
                .aliases
                .get(local_name)
                .map_or(local_name.as_str(), String::as_str);
            if let Some(indices) = by_name_version.get(&(target.to_string(), dep_version.clone())) {
                for &next_idx in indices {
                    if !required[next_idx] {
                        required[next_idx] = true;
                        queue.push_back(next_idx);
                    }
                }
            }
        }
    }

    for (package, is_required) in packages.iter_mut().zip(required) {
        package.optional = !is_required;
    }
}

/// Collapse same-package/same-version rows when one materialization graph can
/// safely stand in for another.
///
/// The resolver can temporarily produce multiple rows for the same canonical
/// package and version when peer-bound contexts differ. A row whose dependency
/// edges, alias edges, and resolved peer bindings are all subsets of another
/// row is interchangeable with that larger wrapper: the larger wrapper exposes
/// everything the smaller one needs. Non-comparable peer contexts stay distinct.
pub(crate) fn dedupe_peer_superset_packages(packages: &mut Vec<ResolvedPackage>) {
    if packages.len() < 2 {
        return;
    }

    let mut groups: HashMap<String, Vec<usize>> = HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        groups
            .entry(resolved_package_identity_key(package))
            .or_default()
            .push(idx);
    }

    let mut dominated = vec![false; packages.len()];
    for indices in groups.values().filter(|indices| indices.len() > 1) {
        for &idx in indices {
            for &candidate_idx in indices {
                if idx == candidate_idx {
                    continue;
                }
                let package = &packages[idx];
                let candidate = &packages[candidate_idx];
                if !resolved_package_can_replace(candidate, package) {
                    continue;
                }
                if resolved_package_is_strict_superset(candidate, package) || candidate_idx < idx {
                    dominated[idx] = true;
                    break;
                }
            }
        }
    }

    let mut idx = 0usize;
    packages.retain(|_| {
        let keep = !dominated[idx];
        idx += 1;
        keep
    });
}

fn resolved_package_identity_key(package: &ResolvedPackage) -> String {
    let name = package.package.canonical_name();
    let version = package.version.to_string();
    let mut key = String::with_capacity(name.len() + 1 + version.len());
    key.push_str(&name);
    key.push('\0');
    key.push_str(&version);
    key
}

fn resolved_package_can_replace(candidate: &ResolvedPackage, package: &ResolvedPackage) -> bool {
    candidate.tarball_url == package.tarball_url
        && candidate.integrity == package.integrity
        && entries_are_superset(&candidate.dependencies, &package.dependencies)
        && aliases_are_superset(&candidate.aliases, &package.aliases)
        && entries_are_superset(&candidate.peers, &package.peers)
}

fn resolved_package_is_strict_superset(
    candidate: &ResolvedPackage,
    package: &ResolvedPackage,
) -> bool {
    candidate.dependencies.len() > package.dependencies.len()
        || candidate.aliases.len() > package.aliases.len()
        || candidate.peers.len() > package.peers.len()
}

fn entries_are_superset(candidate: &[(String, String)], package: &[(String, String)]) -> bool {
    package.iter().all(|entry| {
        candidate
            .iter()
            .any(|candidate_entry| candidate_entry == entry)
    })
}

fn aliases_are_superset(
    candidate: &HashMap<String, String>,
    package: &HashMap<String, String>,
) -> bool {
    package
        .iter()
        .all(|(local, target)| candidate.get(local) == Some(target))
}

/// Intersect a consumer's declared `peerDependencies` against the
/// install set's resolved-versions lookup. Returns
/// `(peer_name, resolved_version)` pairs sorted by peer_name (stable
/// for GraphKey hashing).
///
/// **What "resolved" means here.** The pubgrub / greedy arms have
/// already finished resolution by the time we reach this helper, so
/// the install set is fixed. Peer resolution at this stage is just a
/// lookup: for each declared peer, does the install set contain a
/// version of that package? If yes, that version IS the resolved
/// peer (peer-dep ranges don't multi-select — a peer is whatever
/// version of the named package is in scope).
///
/// **What's NOT here.** Split-aware peer resolution (consumer in
/// context X picks peer in context X first, falling back to
/// unsplit). The upstream `check_unmet_peers` does this for warning
/// generation. For the v2 GraphKey we use the simpler lookup because
/// the audit-fixture scope doesn't exercise splits, and a
/// pessimistic (slightly over-binding) GraphKey is acceptable —
/// worst case is fewer cross-project sharing hits, never an
/// incorrect share. When split-aware resolution becomes load-bearing
/// (once cross-project benchmarks make it load-bearing), this helper grows the
/// `unsplit_versions` parameter the same way `resolve_peer_version`
/// already does.
fn compute_resolved_peers(
    consumer: &ResolverPackage,
    consumer_version: &str,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    resolved_versions: &HashMap<String, Vec<(Option<String>, String)>>,
) -> Vec<(String, String)> {
    let key = CanonicalKey::from(consumer);
    let Some(peer_deps) = cache
        .get(&key)
        .and_then(|info| info.peer_deps.get(consumer_version))
    else {
        return Vec::new();
    };
    let mut peers: Vec<(String, String)> = peer_deps
        .iter()
        .filter_map(|peer_name| {
            let (peer_name, peer_range) = peer_name;
            let parsed_range = NpmRange::parse(peer_range).ok();
            resolve_peer_binding_version(
                consumer,
                peer_name,
                parsed_range.as_ref(),
                resolved_versions,
            )
            .map(|(version, _)| (peer_name.clone(), version.clone()))
        })
        .collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    peers
}

pub(crate) fn resolve_peer_binding_version<'a>(
    consumer: &ResolverPackage,
    peer_name: &str,
    peer_range: Option<&NpmRange>,
    resolved_versions: &'a HashMap<String, Vec<(Option<String>, String)>>,
) -> Option<(&'a String, bool)> {
    let candidates = resolved_versions.get(peer_name)?;

    if let Some(context) = consumer.context() {
        let same_context: Vec<&(Option<String>, String)> = candidates
            .iter()
            .filter(|(candidate_context, _)| candidate_context.as_deref() == Some(context))
            .collect();
        if let Some(selected) = select_peer_candidate(&same_context, peer_range) {
            return Some(selected);
        }
    }

    let unsplit: Vec<&(Option<String>, String)> = candidates
        .iter()
        .filter(|(candidate_context, _)| candidate_context.is_none())
        .collect();
    if let Some(selected) = select_peer_candidate(&unsplit, peer_range) {
        return Some(selected);
    }

    let all_candidates: Vec<&(Option<String>, String)> = candidates.iter().collect();
    select_peer_candidate(&all_candidates, peer_range)
}

fn select_peer_candidate<'a>(
    candidates: &[&'a (Option<String>, String)],
    peer_range: Option<&NpmRange>,
) -> Option<(&'a String, bool)> {
    match candidates {
        [] => None,
        [(_, version)] => Some((version, peer_version_satisfies(version, peer_range))),
        _ => {
            let mut satisfying = candidates.iter().filter_map(|(_, version)| {
                peer_version_satisfies(version, peer_range).then_some(version)
            });
            let first = satisfying.next()?;
            if satisfying.next().is_none() {
                Some((first, true))
            } else {
                None
            }
        }
    }
}

fn peer_version_satisfies(version: &str, peer_range: Option<&NpmRange>) -> bool {
    peer_range.is_none_or(|range| {
        NpmVersion::parse(version)
            .ok()
            .is_some_and(|parsed| range.satisfies(&parsed))
    })
}

/// A warning about an unmet peer dependency.
///
/// Peer deps are checked post-resolution against the actual resolved tree,
/// not during resolution. This avoids over-constraining (union-across-all-versions)
/// and matches npm/pnpm behavior.
#[derive(Debug, Clone)]
pub struct PeerWarning {
    /// The package that declares the peer dependency.
    pub package: String,
    /// The version of the package that declares the peer.
    pub version: String,
    /// The peer dependency name.
    pub peer: String,
    /// The required peer version range.
    pub required_range: String,
    /// The version actually resolved in the tree (None if peer is completely missing).
    pub resolved_version: Option<String>,
}

impl std::fmt::Display for PeerWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.resolved_version {
            Some(v) => write!(
                f,
                "{}@{} requires peer {} ({}), but {}@{} was resolved",
                self.package, self.version, self.peer, self.required_range, self.peer, v
            ),
            None => write!(
                f,
                "{}@{} requires peer {} ({}), but it is not installed",
                self.package, self.version, self.peer, self.required_range
            ),
        }
    }
}

/// Pre-compiled peer-dependency rules consumed by [`check_unmet_peers`].
///
/// Mirrors the on-disk shape of `package.json > lpm.peerDependencyRules`
/// (and pnpm's identical `pnpm.peerDependencyRules`) but with patterns
/// pre-split, selector keys parsed, and version ranges pre-parsed so
/// the post-resolution peer-warning loop never re-parses on the hot
/// path.
///
/// Build with [`CompiledPeerRules::compile`] from raw string inputs.
/// Compile is **fail-closed**: any unparseable selector key or version
/// range in `allowed_versions` returns an `Err`. The install path
/// propagates this as `LpmError::Script`, matching the
/// [`crate::OverrideSet`] fail-closed posture for `lpm.overrides` —
/// silent typos in hand-authored manifest config are more dangerous
/// than a hard install error. Pass [`CompiledPeerRules::default`]
/// when no rules apply.
///
/// The three sub-fields are independent and combined per pnpm's
/// documented semantics:
///
/// - `ignore_missing` suppresses missing-peer warnings (peer is not in
///   the tree at all).
/// - `allowed_versions` widens the accepted range when the peer is in
///   the tree but at a non-satisfying version.
/// - `allow_any` suppresses version-mismatch warnings entirely when
///   the peer is in the tree (any version goes).
///
/// **Selector grammar (mirrors `lpm.overrides`)** for
/// `allowed_versions` keys:
///
/// - `"react"` — any peer named `react`, regardless of consumer
/// - `"@scope/foo"` — scoped peer, any consumer
/// - `"foo>react"` — `react` peer of `foo` (any version of foo)
/// - `"foo@^2>react"` — `react` peer of `foo` whose version
///   satisfies `^2`
/// - `"@scope/foo@^2>react"` — same shape with scoped parent
///
/// Multi-segment paths (`a>b>c`) and standalone version qualifiers
/// on a bare peer name (`"foo@2"` without `>`) are rejected at
/// compile time — same fail-closed posture as `lpm.overrides`.
///
/// Glob patterns (`*`, `@scope/*`, `*-suffix`, etc.) are supported by
/// `ignore_missing` and `allow_any`; `allowed_versions` uses the
/// structured selector grammar above instead.
#[derive(Debug, Clone, Default)]
pub struct CompiledPeerRules {
    ignore_missing: Vec<GlobPattern>,
    allowed_versions: Vec<AllowedVersionsRule>,
    allow_any: Vec<GlobPattern>,
}

/// One pre-parsed `lpm.peerDependencyRules.allowedVersions` entry.
///
/// `selector` decides which (consumer, peer) pairs the rule applies
/// to; `widened_range` is the user's accepted range for the peer's
/// resolved version. Multiple rules may match a given (consumer, peer)
/// — `check_unmet_peers` accepts the resolved version if **any**
/// matching rule's range is satisfied (union semantics).
#[derive(Debug, Clone)]
struct AllowedVersionsRule {
    selector: AllowedVersionsSelector,
    widened_range: crate::ranges::NpmRange,
}

/// Parsed selector key for an `allowedVersions` rule. Mirrors the
/// `lpm.overrides` selector grammar — bare peer name, or
/// `parent>peer` with optional `@range` on the parent half.
#[derive(Debug, Clone)]
struct AllowedVersionsSelector {
    /// Optional consumer constraint. `None` matches any consumer.
    parent: Option<ParentSelector>,
    /// Exact peer name. No version qualifier permitted on this side
    /// (the rule's value is the widened range).
    peer: String,
}

/// Parent half of an `allowedVersions` selector.
#[derive(Debug, Clone)]
struct ParentSelector {
    name: String,
    /// Optional version range on the consumer. `None` matches any
    /// version of `name`.
    range: Option<crate::ranges::NpmRange>,
}

impl AllowedVersionsSelector {
    /// Parse a raw `allowedVersions` key. Fails closed on:
    /// - empty input
    /// - multi-segment paths (`a>b>c`)
    /// - empty parent or peer halves (`"foo>"`, `">react"`, `">"`)
    /// - bare keys carrying a version qualifier (`"foo@2"` without `>`)
    /// - peer half carrying a version qualifier (`"foo>react@2"`)
    /// - invalid npm names on either side
    /// - unparseable parent version range
    fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty allowedVersions selector".into());
        }
        let parts: Vec<&str> = trimmed.split('>').collect();
        match parts.len() {
            1 => {
                // Bare peer name. Reject `foo@version` forms — too
                // ambiguous (could mean "scope by peer required range"
                // or "scope by peer resolved version"). pnpm's own
                // examples don't use this shape.
                let name = parts[0];
                if has_version_qualifier(name) {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: peer name cannot \
                         carry a version qualifier; use `<consumer>{}<peer>` to \
                         scope the rule by consumer",
                        '>'
                    ));
                }
                validate_selector_name(name, "peer name")?;
                Ok(AllowedVersionsSelector {
                    parent: None,
                    peer: name.to_string(),
                })
            }
            2 => {
                let parent_raw = parts[0];
                let peer = parts[1];
                if peer.is_empty() {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: empty peer name \
                         after `>`"
                    ));
                }
                if has_version_qualifier(peer) {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: peer half cannot \
                         carry a version qualifier (the rule's value is the \
                         widened range)"
                    ));
                }
                validate_selector_name(peer, "peer name")?;
                let parent = parse_parent_selector(parent_raw)?;
                Ok(AllowedVersionsSelector {
                    parent: Some(parent),
                    peer: peer.to_string(),
                })
            }
            _ => Err(format!(
                "invalid allowedVersions selector {raw:?}: multi-segment paths \
                 (`a>b>c`) are not supported"
            )),
        }
    }

    /// Match against a (consumer, consumer_version, peer) triple from
    /// the resolved tree. Returns true iff every component of the
    /// selector matches.
    fn matches(&self, consumer: &str, consumer_version: &NpmVersion, peer: &str) -> bool {
        if self.peer != peer {
            return false;
        }
        let Some(parent) = &self.parent else {
            return true;
        };
        if parent.name != consumer {
            return false;
        }
        if let Some(range) = &parent.range
            && !range.satisfies(consumer_version)
        {
            return false;
        }
        true
    }
}

/// Parse the parent half of `parent>peer`. Accepts:
/// - `"foo"` — bare name
/// - `"@scope/foo"` — scoped name
/// - `"foo@^2"` — name + version range
/// - `"@scope/foo@^2"` — scoped name + version range
fn parse_parent_selector(raw: &str) -> Result<ParentSelector, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty parent name in allowedVersions selector".into());
    }
    // For `@scope/foo@^2`, the version-separating `@` is the rightmost
    // one at position > 0 (the leading `@` is part of the scope).
    let at_idx = trimmed
        .rmatch_indices('@')
        .find(|(i, _)| *i > 0)
        .map(|(i, _)| i);
    match at_idx {
        Some(i) => {
            let name = &trimmed[..i];
            let range_str = &trimmed[i + 1..];
            if range_str.is_empty() {
                return Err(format!(
                    "empty version range after `@` in allowedVersions parent selector \
                     {trimmed:?}"
                ));
            }
            validate_selector_name(name, "parent name")?;
            let range = crate::ranges::NpmRange::parse(range_str)
                .map_err(|e| format!("unparseable parent version range in {trimmed:?}: {e}"))?;
            Ok(ParentSelector {
                name: name.to_string(),
                range: Some(range),
            })
        }
        None => {
            validate_selector_name(trimmed, "parent name")?;
            Ok(ParentSelector {
                name: trimmed.to_string(),
                range: None,
            })
        }
    }
}

/// `true` iff `name` appears to carry a version qualifier (a `@`
/// past the optional leading scope `@`).
fn has_version_qualifier(name: &str) -> bool {
    if let Some(stripped) = name.strip_prefix('@') {
        stripped.contains('@')
    } else {
        name.contains('@')
    }
}

/// Validate a name appearing in an `allowedVersions` selector.
///
/// Returns `Ok(())` for a valid npm package name; `Err(msg)` with a
/// position-aware error message otherwise. `position` is interpolated
/// into the error (e.g. `"peer name"`, `"parent name"`) so the user
/// sees which half of the selector is malformed.
///
/// **Why not just use [`crate::provider::is_valid_dep_name`]?** That
/// helper is a registry-data hygiene check — its job is to catch
/// path traversal and null bytes in tarball metadata, not to enforce
/// npm's full naming spec. It accepts `"foo bar"` (spaces),
/// `"FooBar"` (uppercase), `".hidden"` / `"_private"` (npm-forbidden
/// leading chars), and `"*"` (glob wildcards) as "valid names" —
/// any of which would silently no-op at runtime against a resolved
/// tree that uses real npm names.
///
/// This validator enforces the actual npm naming contract:
/// 1–214 ASCII characters, lowercase letters / digits /
/// `- _ . ~`, cannot start with `.` or `_`, scoped form
/// `@scope/name` with both halves following the same rules.
/// Glob wildcards (`*`) are explicitly classified separately so the
/// error message can point at `ignoreMissing` / `allowAny`.
///
/// `ignoreMissing` and `allowAny` keep using the unrestricted
/// `GlobPattern` parser — wildcards (and other relaxed shapes) are
/// first-class there.
fn validate_selector_name(name: &str, position: &str) -> Result<(), String> {
    if name.contains('*') {
        return Err(format!(
            "invalid {position} {name:?} in allowedVersions selector \
             (glob wildcards like `*` are not accepted here — use \
             `ignoreMissing` or `allowAny` for pattern-based rules)"
        ));
    }
    if !is_real_npm_package_name(name) {
        return Err(format!(
            "invalid {position} {name:?} in allowedVersions selector \
             (must be a valid npm package name: lowercase letters, digits, \
             `- _ . ~`, cannot start with `.` or `_`; scoped form is \
             `@scope/name`)"
        ));
    }
    Ok(())
}

/// Real npm package-name validator (the contract `npm publish`
/// enforces, not the permissive registry-hygiene fallback).
///
/// Accepts:
/// - 1..=214 ASCII characters
/// - Unscoped: starts with a lowercase letter, digit, `-`, or `~`;
///   body may also include `_`, `.`
/// - Scoped: `@scope/name` where the **scope** follows the unscoped
///   leading-char rules, and the **package half** is a body-only
///   match (leading `.` or `_` is permitted there — npm's
///   `validate-npm-package-name` enforces the leading-char check
///   against the WHOLE name string, which for a scoped name starts
///   with `@`, so `@scope/_internal` and `@scope/.config` are valid
///   per the npm spec).
///
/// Rejects:
/// - Empty / over-length names
/// - Uppercase letters anywhere
/// - Leading `.` or `_` on the unscoped form (or on the scope half
///   of a scoped form)
/// - Any character outside the allowed set (spaces, punctuation, etc.)
fn is_real_npm_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    if let Some(rest) = name.strip_prefix('@') {
        let Some(slash_pos) = rest.find('/') else {
            return false;
        };
        let scope = &rest[..slash_pos];
        let pkg = &rest[slash_pos + 1..];
        // Scope: full unscoped rules — including the leading-`.`/`_`
        // restriction. Package half: body-only — leading `.`/`_` is
        // allowed because npm's leading-char check fires against the
        // whole name (which starts with `@`), not the package half.
        return is_valid_unscoped_npm_name(scope) && is_valid_npm_name_body(pkg);
    }
    is_valid_unscoped_npm_name(name)
}

/// Full unscoped npm-name validator. Used for the unscoped form and
/// for the scope half of a scoped form. Enforces both the leading-
/// char rule and the body charset.
fn is_valid_unscoped_npm_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let first = bytes[0];
    // Cannot start with `.` or `_` per npm's own validator (when
    // applied to the WHOLE name; for scoped names this rule is
    // satisfied by the leading `@` and the scope half running
    // through here, not by the package half — see
    // [`is_valid_npm_name_body`]).
    if !(first.is_ascii_lowercase() || first.is_ascii_digit() || first == b'-' || first == b'~') {
        return false;
    }
    is_valid_npm_name_body(s)
}

/// Body-only npm-name validator: charset matches
/// [`is_valid_unscoped_npm_name`] but the leading-char restriction
/// is dropped. Used for the package half of a scoped name —
/// `@scope/_internal` and `@scope/.config` are valid per npm because
/// the leading-`.`/`_` check fires against the whole `name` string,
/// which starts with `@`.
fn is_valid_npm_name_body(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.as_bytes().iter().all(|&b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~'
    })
}

/// Validate an `lpm.peerDependencyRules.allowedVersions` selector key
/// without compiling the full ruleset. Used by the migrate planner to
/// surface bad pnpm-side selector keys up-front before any disk
/// mutation. The migrate planner wraps the error message into its
/// structured `allowed_versions_parse_errors` list so the user sees
/// every bad entry at once.
pub fn validate_allowed_versions_selector(raw_key: &str) -> Result<(), String> {
    AllowedVersionsSelector::parse(raw_key).map(|_| ())
}

/// Validate the widened-range value of an
/// `lpm.peerDependencyRules.allowedVersions` entry against the same
/// parser the resolver uses at install time
/// ([`crate::ranges::NpmRange`]). Exposed so the migrate planner can
/// validate pnpm-side ranges with the exact parser the resolver
/// runs against `lpm.peerDependencyRules` — no parser drift between
/// the two surfaces.
///
/// This explicitly does NOT use `lpm_semver::VersionReq::parse`,
/// which is a stricter strict-semver parser; `NpmRange` accepts the
/// fuller npm-compat range grammar (unions via `||`, `>=1 <2`, etc.)
/// that the install path honors. A range that migrates clean must
/// also compile clean.
pub fn validate_allowed_versions_range(raw_range: &str) -> Result<(), String> {
    crate::ranges::NpmRange::parse(raw_range).map(|_| ())
}

impl CompiledPeerRules {
    /// Compile raw peer-rule inputs from `package.json`.
    ///
    /// **Fail-closed.** Any unparseable selector key or version range
    /// in `allowed_versions` returns an `Err` carrying a human-readable
    /// message naming the offending entry. The install path propagates
    /// this as `LpmError::Script`, matching the [`crate::OverrideSet`]
    /// fail-closed posture for `lpm.overrides`. A silent typo in
    /// hand-authored manifest config is more dangerous than a hard
    /// install error.
    ///
    /// `ignore_missing` and `allow_any` patterns never fail to compile
    /// (they're plain glob fragments — any string is a valid pattern).
    pub fn compile(
        ignore_missing: &[String],
        allowed_versions: &HashMap<String, String>,
        allow_any: &[String],
    ) -> Result<Self, String> {
        let ignore_missing = ignore_missing
            .iter()
            .map(|s| GlobPattern::compile(s))
            .collect();

        let mut allowed_versions_compiled: Vec<AllowedVersionsRule> =
            Vec::with_capacity(allowed_versions.len());
        for (raw_key, raw_range) in allowed_versions {
            let selector = AllowedVersionsSelector::parse(raw_key).map_err(|e| {
                format!("`lpm.peerDependencyRules.allowedVersions[{raw_key:?}]`: {e}")
            })?;
            let widened_range = crate::ranges::NpmRange::parse(raw_range).map_err(|e| {
                format!(
                    "`lpm.peerDependencyRules.allowedVersions[{raw_key:?}] = \
                     {raw_range:?}`: unparseable version range: {e}"
                )
            })?;
            allowed_versions_compiled.push(AllowedVersionsRule {
                selector,
                widened_range,
            });
        }

        let allow_any = allow_any.iter().map(|s| GlobPattern::compile(s)).collect();

        Ok(Self {
            ignore_missing,
            allowed_versions: allowed_versions_compiled,
            allow_any,
        })
    }

    /// `true` iff every list/map is empty — the no-op rule set.
    /// `check_unmet_peers` short-circuits on this for the common case.
    pub fn is_empty(&self) -> bool {
        self.ignore_missing.is_empty()
            && self.allowed_versions.is_empty()
            && self.allow_any.is_empty()
    }

    /// `true` iff a missing-peer warning for `name` should be
    /// suppressed. Tested on every peer-not-in-tree case.
    pub fn ignore_missing_matches(&self, name: &str) -> bool {
        self.ignore_missing.iter().any(|p| p.matches(name))
    }

    /// `true` iff at least one `allowedVersions` rule applies to the
    /// given (consumer, consumer_version, peer) triple AND the
    /// resolved peer version satisfies that rule's widened range.
    /// Multiple matching rules combine with union semantics — any
    /// match suppresses the warning.
    ///
    /// `consumer` is the canonical name of the package declaring the
    /// peer; `consumer_version` is its actual resolved version.
    /// Together they let `parent>peer` and `parent@range>peer`
    /// selectors filter precisely.
    pub fn allowed_versions_satisfies(
        &self,
        consumer: &str,
        consumer_version: &NpmVersion,
        peer: &str,
        resolved_peer_version: &NpmVersion,
    ) -> bool {
        self.allowed_versions.iter().any(|rule| {
            rule.selector.matches(consumer, consumer_version, peer)
                && rule.widened_range.satisfies(resolved_peer_version)
        })
    }

    /// `true` iff a version-mismatch warning for `name` should be
    /// suppressed. Only consulted when the peer IS in the tree.
    pub fn allow_any_matches(&self, name: &str) -> bool {
        self.allow_any.iter().any(|p| p.matches(name))
    }
}

/// Pre-compiled glob pattern.
///
/// Supports the pnpm-compatible subset: literal names, `*` as a
/// wildcard standing in for zero-or-more characters, anywhere in the
/// pattern. Exactly the surface the migrate path translates verbatim.
///
/// Implementation: split on `*`, then walk segments. Empty leading /
/// trailing segments mean "no anchor on that side." Compiled once;
/// matched many times.
#[derive(Debug, Clone)]
struct GlobPattern {
    segments: Vec<String>,
    has_wildcard: bool,
}

impl GlobPattern {
    fn compile(pattern: &str) -> Self {
        let has_wildcard = pattern.contains('*');
        let segments: Vec<String> = if has_wildcard {
            pattern.split('*').map(str::to_string).collect()
        } else {
            vec![pattern.to_string()]
        };
        Self {
            segments,
            has_wildcard,
        }
    }

    fn matches(&self, name: &str) -> bool {
        if !self.has_wildcard {
            return self.segments.first().map(String::as_str) == Some(name);
        }
        let mut idx: usize = 0;
        let last = self.segments.len().saturating_sub(1);
        for (i, seg) in self.segments.iter().enumerate() {
            if seg.is_empty() {
                // Empty segment = wildcard adjacent to a `*`. Leading
                // empty unanchors the prefix, trailing empty unanchors
                // the suffix; an empty middle is impossible to produce
                // via `split('*')` unless there's a `**` (rare; treated
                // as another unanchored gap, harmless).
                continue;
            }
            if i == 0 {
                // First non-empty segment must anchor the prefix.
                if !name[idx..].starts_with(seg.as_str()) {
                    return false;
                }
                idx += seg.len();
            } else if i == last {
                // Last non-empty segment must anchor the suffix at
                // or after the current `idx`.
                let tail = &name[idx..];
                if tail.len() < seg.len() || !tail.ends_with(seg.as_str()) {
                    return false;
                }
                // No idx update — done after the last segment.
            } else {
                // Middle segment: find anywhere in the remainder.
                let tail = &name[idx..];
                match tail.find(seg.as_str()) {
                    Some(p) => idx += p + seg.len(),
                    None => return false,
                }
            }
        }
        true
    }
}

/// Check the resolved tree for unmet peer dependencies.
///
/// For each resolved package, looks up its *actual selected version's* peer deps
/// from the cached metadata, then checks whether the resolved tree satisfies them.
///
/// `peer_rules` is the user-declared peer-dependency rule set from
/// `package.json > lpm.peerDependencyRules` (mirrored from
/// `pnpm.peerDependencyRules` by `lpm migrate`). Three filters apply:
/// `ignore_missing` suppresses missing-peer warnings; `allow_any`
/// suppresses version-mismatch warnings when the peer is present;
/// `allowed_versions` widens the accepted range for matched names.
/// Pass [`CompiledPeerRules::default`] when no rules apply — the
/// helper short-circuits the empty case.
///
/// Returns a list of warnings for unmet peers. This is intentionally warnings-only
/// (not errors) to match npm's default peer behavior. Strict mode enforcement
/// is the caller's responsibility.
pub fn check_unmet_peers(
    resolved: &[ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    peer_rules: &CompiledPeerRules,
) -> Vec<PeerWarning> {
    use crate::ranges::NpmRange;

    // Build lookup: canonical_name → all resolved instances for that package.
    // Split packages may legitimately appear multiple times with different contexts.
    let resolved_versions: HashMap<String, Vec<(Option<String>, String)>> =
        resolved.iter().fold(HashMap::new(), |mut acc, package| {
            acc.entry(package.package.canonical_name())
                .or_default()
                .push((
                    package.package.context().map(str::to_string),
                    package.version.to_string(),
                ));
            acc
        });

    let mut warnings = Vec::new();

    for resolved_pkg in resolved {
        let ver_str = resolved_pkg.version.to_string();
        let canonical = resolved_pkg.package.canonical_name();

        // Look up this package's peer deps for its actual resolved
        // version. Canonicalize — split-retry variants share a single
        // cache entry under the canonical key.
        let key = CanonicalKey::from(&resolved_pkg.package);
        let info = cache.get(&key);
        let peer_deps = info.and_then(|i| i.peer_deps.get(&ver_str));

        let Some(peer_deps) = peer_deps else {
            continue;
        };

        // Set of peer names this version marked optional via
        // `peerDependenciesMeta.optional`. Empty for the common case.
        // Used below to suppress the missing-peer warning ONLY — an
        // optional peer that's present but at the wrong version still
        // warrants a warning (the user opted into having a peer, just
        // at an incompatible version).
        let optional_peers = info.and_then(|i| i.optional_peer_names.get(&ver_str));

        for (peer_name, peer_range_str) in peer_deps {
            let parsed_range = NpmRange::parse(peer_range_str).ok();
            let resolved_peer_ver = resolve_peer_binding_version(
                &resolved_pkg.package,
                peer_name,
                parsed_range.as_ref(),
                &resolved_versions,
            );

            match resolved_peer_ver {
                Some((resolved_ver, satisfies)) => {
                    // Peer is in the tree — check if the resolved version satisfies the range
                    let parsed_resolved = NpmVersion::parse(resolved_ver).ok();

                    if !satisfies {
                        // peerDependencyRules filter: allow_any
                        // suppresses every version-mismatch warning
                        // for matched names. allowed_versions tries
                        // a user-widened range as a fallback, with
                        // selector-aware matching against the consumer
                        // (the package declaring the peer) so
                        // `foo@^2>react` only fires for foo@^2.
                        if peer_rules.allow_any_matches(peer_name) {
                            continue;
                        }
                        if let Some(v) = parsed_resolved.as_ref()
                            && peer_rules.allowed_versions_satisfies(
                                &canonical,
                                &resolved_pkg.version,
                                peer_name,
                                v,
                            )
                        {
                            continue;
                        }
                        warnings.push(PeerWarning {
                            package: canonical.clone(),
                            version: ver_str.clone(),
                            peer: peer_name.clone(),
                            required_range: peer_range_str.clone(),
                            resolved_version: Some(resolved_ver.clone()),
                        });
                    }
                }
                None => {
                    // Peer is completely missing from the resolved
                    // tree. peerDependencyRules.ignoreMissing can
                    // suppress the warning entirely.
                    if peer_rules.ignore_missing_matches(peer_name) {
                        continue;
                    }
                    // `peerDependenciesMeta.optional: true` is the
                    // manifest author's explicit "this peer is
                    // optional; no warning if it's missing." pnpm,
                    // yarn, and npm v7+ all honor this. Gates ONLY
                    // the missing-peer branch — version-mismatch
                    // above still warrants a warning.
                    if optional_peers.is_some_and(|set| set.contains(peer_name)) {
                        continue;
                    }
                    warnings.push(PeerWarning {
                        package: canonical.clone(),
                        version: ver_str.clone(),
                        peer: peer_name.clone(),
                        required_range: peer_range_str.clone(),
                        resolved_version: None,
                    });
                }
            }
        }
    }

    // Sort for deterministic output
    warnings.sort_by(|a, b| a.package.cmp(&b.package).then(a.peer.cmp(&b.peer)));
    warnings
}

fn map_pubgrub_error(e: pubgrub::PubGrubError<LpmDependencyProvider>) -> ResolveError {
    match e {
        pubgrub::PubGrubError::NoSolution(mut dt) => {
            dt.collapse_no_versions();
            ResolveError::NoSolution(DefaultStringReporter::report(&dt))
        }
        pubgrub::PubGrubError::ErrorRetrievingDependencies {
            package,
            version,
            source,
        } => ResolveError::DependencyFetch {
            package: package.to_string(),
            version: version.to_string(),
            detail: source.to_string(),
        },
        pubgrub::PubGrubError::ErrorChoosingVersion { package, source } => {
            ResolveError::VersionChoice {
                package: package.to_string(),
                detail: source.to_string(),
            }
        }
        pubgrub::PubGrubError::ErrorInShouldCancel(e) => ResolveError::Cancelled(e.to_string()),
    }
}

/// Extract package names that appear in conflicts from PubGrub's error report.
///
/// Primary strategy: parse "X depends on PKG VERSION1 and Y depends on PKG VERSION2"
/// patterns. Fallback: extract all package-like names mentioned multiple times.
fn extract_conflicting_packages(report: &str) -> HashSet<String> {
    let conflicts = extract_conflicts_primary(report);
    if !conflicts.is_empty() {
        return conflicts;
    }

    // Fallback: primary extraction found nothing — PubGrub format may have changed
    tracing::warn!(
        "primary conflict extraction found no packages; falling back to broad extraction"
    );
    extract_conflicts_fallback(report)
}

/// Primary extraction: looks for "depends on PKG VERSION" patterns where PKG
/// appears with 2+ different version constraints.
fn extract_conflicts_primary(report: &str) -> HashSet<String> {
    let mut package_versions: HashMap<String, HashSet<String>> = HashMap::new();

    for line in report.lines() {
        let line = line.trim();
        let parts: Vec<&str> = line.split("depends on ").collect();
        for part in parts.iter().skip(1) {
            let tokens: Vec<&str> = part.split_whitespace().collect();
            if tokens.len() >= 2 {
                let pkg_name = tokens[0].trim_matches(',');
                let version = tokens[1].trim_matches(',');
                if !pkg_name.is_empty()
                    && !pkg_name.starts_with('<')
                    && version.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    package_versions
                        .entry(pkg_name.to_string())
                        .or_default()
                        .insert(version.to_string());
                }
            }
        }
    }

    package_versions
        .into_iter()
        .filter(|(_, versions)| versions.len() >= 2)
        .map(|(name, _)| name)
        .collect()
}

/// Fallback extraction: find all tokens that look like package names
/// (contain only valid npm name chars) mentioned alongside version-like tokens.
/// Returns any package name that appears 2+ times in different contexts.
fn extract_conflicts_fallback(report: &str) -> HashSet<String> {
    let mut name_occurrences: HashMap<String, usize> = HashMap::new();

    for line in report.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for window in tokens.windows(2) {
            let candidate = window[0].trim_matches(|c: char| {
                !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-' && c != '_'
            });
            let next = window[1].trim_matches(',');
            // candidate looks like a package name, next looks like a version
            if !candidate.is_empty()
                && !candidate.starts_with('<')
                && !candidate.starts_with('>')
                && next.chars().next().is_some_and(|c| c.is_ascii_digit())
                && candidate
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_'))
            {
                *name_occurrences.entry(candidate.to_string()).or_default() += 1;
            }
        }
    }

    // Return packages mentioned 2+ times as likely conflict participants
    name_occurrences
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(name, _)| name)
        .collect()
}

/// Errors from the resolution process.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no solution found:\n{0}")]
    NoSolution(String),

    #[error("failed to fetch dependencies for {package}@{version}: {detail}")]
    DependencyFetch {
        package: String,
        version: String,
        detail: String,
    },

    #[error("failed to choose version for {package}: {detail}")]
    VersionChoice { package: String, detail: String },

    #[error("resolution cancelled: {0}")]
    Cancelled(String),

    #[error("internal error: {0}")]
    Internal(String),

    /// Two or more consumers in the install set declare
    /// `peerDependencies` for `canonical` whose ranges have no version
    /// in common, AND at least one of those consumers is non-optional.
    /// The auto-install path can't pick a single version that satisfies
    /// every required consumer's range.
    ///
    /// `requirements` lists every contributing consumer with its
    /// declared range so the user can act on the conflict (typically:
    /// pin a version of one of the consumers, or use
    /// `lpm.overrides` to force a peer version).
    ///
    /// **Why this is an error and not a warning:** the alternative
    /// (warn-only post-resolve) leaves the install in a half-broken
    /// state where one consumer silently gets a peer that doesn't
    /// satisfy its declared range. An unsatisfiable peer with at least
    /// one required consumer has the same shape as
    /// [`Self::NoSolution`] for regular deps.
    #[error(
        "peer dependency conflict for `{canonical}`: {} consumer(s) declare incompatible ranges. \
         Consumers: {}",
        requirements.len(),
        format_peer_conflict_consumers(requirements)
    )]
    PeerConflict {
        /// Registry identity of the conflicted peer.
        canonical: String,
        /// One entry per contributing consumer:
        /// `(consumer_canonical, declared_range, optional)`.
        requirements: Vec<(String, String, bool)>,
    },
}

/// Format the `requirements` list on a [`ResolveError::PeerConflict`]
/// for the `Display` impl. Sorted deterministically by `(consumer
/// name, range)` so two failing runs produce byte-identical error
/// messages regardless of `HashMap` iteration order.
fn format_peer_conflict_consumers(reqs: &[(String, String, bool)]) -> String {
    let mut sorted: Vec<&(String, String, bool)> = reqs.iter().collect();
    sorted.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    sorted
        .iter()
        .map(|(consumer, range, optional)| {
            if *optional {
                format!("{consumer} → {range} (optional)")
            } else {
                format!("{consumer} → {range}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Platform;
    use lpm_registry::{PackageMetadata, VersionMetadata};
    use std::sync::OnceLock;
    use tokio::sync::Mutex as TokioMutex;

    /// Process-global env-mutation lock for tests in this module.
    ///
    /// `resolve_with_shared_cache` defaults to greedy unless
    /// `LPM_RESOLVER=pubgrub` is set. Tests that exercise PubGrub-arm-
    /// specific features (split-retry, npm-alias range parsing) must
    /// temporarily set the env var, which is process-global. Serialise
    /// mutation across async tests.
    ///
    /// Uses `tokio::sync::Mutex` (async-aware) because the resolver
    /// tests `.await` while holding the guard — `std::sync::Mutex`
    /// triggers clippy's `await_holding_lock` lint.
    fn env_lock() -> &'static TokioMutex<()> {
        static LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TokioMutex::new(()))
    }

    /// Pin the resolver to PubGrub for the duration of a test.
    ///
    /// Snapshots `LPM_RESOLVER`, sets it to `"pubgrub"`, and restores
    /// the prior value on drop. Caller MUST already hold `env_lock()`
    /// — this guard does not acquire it because `set_var` is unsafe in
    /// Rust 2024 and we want the lock-acquire to be visible at the
    /// callsite.
    struct PubgrubEnvGuard {
        prior: Option<std::ffi::OsString>,
    }
    impl PubgrubEnvGuard {
        fn new() -> Self {
            let prior = std::env::var_os("LPM_RESOLVER");
            // SAFETY: caller holds env_lock() — env-var mutation is
            // serialised across this module's tests.
            unsafe { std::env::set_var("LPM_RESOLVER", "pubgrub") };
            Self { prior }
        }
    }
    impl Drop for PubgrubEnvGuard {
        fn drop(&mut self) {
            // SAFETY: still inside the env_lock-protected section.
            unsafe {
                match &self.prior {
                    Some(v) => std::env::set_var("LPM_RESOLVER", v),
                    None => std::env::remove_var("LPM_RESOLVER"),
                }
            }
        }
    }

    /// Test-only adapter: converts a raw `HashMap<String, PackageMetadata>`
    /// into a pre-seeded `SharedCache` and delegates to
    /// `resolve_with_shared_cache`. Not exported — tests only.
    async fn resolve_with_prefetch(
        client: Arc<RegistryClient>,
        dependencies: HashMap<String, String>,
        overrides: OverrideSet,
        prefetched: Option<HashMap<String, PackageMetadata>>,
    ) -> Result<ResolveResult, ResolveError> {
        use crate::provider::WalkerDone;
        use dashmap::DashMap;
        use std::sync::atomic::AtomicBool;
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let walker_done: WalkerDone = Arc::new(AtomicBool::new(false));
        if let Some(batch) = prefetched {
            for (name, metadata) in batch {
                let key = CanonicalKey::from_dep_name(&name);
                let info = crate::provider::parse_metadata_to_cache_info(&metadata);
                shared_cache.insert(key, Arc::new(info));
            }
        }
        resolve_with_shared_cache(
            client,
            dependencies,
            overrides,
            shared_cache,
            notify_map,
            walker_done,
            Duration::ZERO,
            RouteTable::from_mode_only(RouteMode::Proxy),
            StreamingBfsMetrics::new(),
            true, // tests default to auto-install on; tests exercising
                  // warn-only behavior pass false explicitly.
        )
        .await
    }

    #[test]
    fn resolver_package_types_work() {
        let root = ResolverPackage::Root;
        assert!(root.is_root());

        let lpm = ResolverPackage::from_dep_name("@lpm.dev/neo.highlight");
        assert!(lpm.is_lpm());

        let npm = ResolverPackage::from_dep_name("react");
        assert!(npm.is_npm());
    }

    #[test]
    fn extract_conflicts_from_report() {
        let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
        let conflicts = extract_conflicting_packages(report);
        assert!(conflicts.contains("ms"));
    }

    #[test]
    fn no_conflicts_in_primary_for_single_version() {
        // Primary extraction should NOT flag foo — it only appears with one version (1.0.0)
        let report = "Because root depends on foo 1.0.0 and foo 1.0.0 is not available.";
        let conflicts = extract_conflicts_primary(report);
        assert!(
            !conflicts.contains("foo"),
            "same version twice is not a conflict"
        );
    }

    #[test]
    fn primary_extraction_works() {
        let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
        let conflicts = extract_conflicts_primary(report);
        assert!(conflicts.contains("ms"));
    }

    #[test]
    fn fallback_extraction_on_garbled_format() {
        // A format that doesn't use "depends on" but still mentions packages with versions
        let report = r#"
ms 2.1.3 is required by send 0.19.0
ms 2.0.0 is required by debug 2.6.9
these are incompatible
"#;
        // Primary should fail
        let primary = extract_conflicts_primary(report);
        assert!(
            primary.is_empty(),
            "primary should not find conflicts in non-standard format"
        );

        // Fallback should find ms (appears twice with different versions)
        let fallback = extract_conflicts_fallback(report);
        assert!(
            fallback.contains("ms"),
            "fallback should find 'ms' mentioned with 2+ versions"
        );
    }

    #[test]
    fn fallback_returns_nonempty_for_repeated_packages() {
        let report = "foo 1.0.0 conflicts with foo 2.0.0";
        let fallback = extract_conflicts_fallback(report);
        assert!(!fallback.is_empty(), "fallback should find something");
        assert!(fallback.contains("foo"));
    }

    fn resolved_pkg_with_graph(
        name: &str,
        version: &str,
        context: Option<&str>,
        dependencies: &[(&str, &str)],
        peers: &[(&str, &str)],
    ) -> ResolvedPackage {
        let package = match context {
            Some(context) => ResolverPackage::npm(name).with_context(context),
            None => ResolverPackage::npm(name),
        };
        ResolvedPackage {
            package,
            version: NpmVersion::parse(version).unwrap(),
            dependencies: dependencies
                .iter()
                .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
                .collect(),
            aliases: HashMap::new(),
            peers: peers
                .iter()
                .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
                .collect(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }
    }

    #[test]
    fn peer_superset_dedup_prefers_row_with_superset_edges_and_peers() {
        let mut packages = vec![
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("react"),
                &[("shared", "1.0.0")],
                &[("react", "18.2.0")],
            ),
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("react-dom"),
                &[("shared", "1.0.0"), ("extra", "1.0.0")],
                &[("react", "18.2.0"), ("react-dom", "18.2.0")],
            ),
        ];

        dedupe_peer_superset_packages(&mut packages);

        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].dependencies,
            vec![
                ("shared".to_string(), "1.0.0".to_string()),
                ("extra".to_string(), "1.0.0".to_string())
            ],
            "the retained row must be the graph superset"
        );
        assert_eq!(
            packages[0].peers,
            vec![
                ("react".to_string(), "18.2.0".to_string()),
                ("react-dom".to_string(), "18.2.0".to_string())
            ]
        );
    }

    #[test]
    fn peer_superset_dedup_collapses_identical_split_contexts() {
        let mut packages = vec![
            resolved_pkg_with_graph(
                "cross-spawn",
                "7.0.6",
                Some("parent-a"),
                &[("path-key", "3.1.1")],
                &[],
            ),
            resolved_pkg_with_graph(
                "cross-spawn",
                "7.0.6",
                Some("parent-b"),
                &[("path-key", "3.1.1")],
                &[],
            ),
        ];

        dedupe_peer_superset_packages(&mut packages);

        assert_eq!(
            packages.len(),
            1,
            "identical same-version split contexts must collapse before install conversion"
        );
    }

    #[test]
    fn peer_superset_dedup_keeps_non_comparable_peer_contexts() {
        let mut packages = vec![
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("react-17"),
                &[("shared", "1.0.0")],
                &[("react", "17.0.2")],
            ),
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("react-18"),
                &[("shared", "1.0.0")],
                &[("react", "18.2.0")],
            ),
        ];

        dedupe_peer_superset_packages(&mut packages);

        assert_eq!(
            packages.len(),
            2,
            "same package/version rows with different peer bindings are not interchangeable"
        );
    }

    #[test]
    fn peer_superset_dedup_keeps_non_comparable_dependency_edges() {
        let mut packages = vec![
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("left"),
                &[("left-only", "1.0.0")],
                &[("react", "18.2.0")],
            ),
            resolved_pkg_with_graph(
                "plugin",
                "1.0.0",
                Some("right"),
                &[("right-only", "1.0.0")],
                &[("react", "18.2.0"), ("react-dom", "18.2.0")],
            ),
        ];

        dedupe_peer_superset_packages(&mut packages);

        assert_eq!(
            packages.len(),
            2,
            "peer supersets cannot replace rows with unrelated dependency edges"
        );
    }

    // === Post-resolution peer dependency checking ===

    /// Helper to build a CachedPackageInfo for tests.
    fn make_cached_info(
        versions: &[&str],
        deps: Vec<(&str, Vec<(&str, &str)>)>,
        peer_deps: Vec<(&str, Vec<(&str, &str)>)>,
    ) -> std::sync::Arc<CachedPackageInfo> {
        // A3: post-A3 the public `ResolveResult.cache` and
        // `check_unmet_peers` take `Arc<CachedPackageInfo>` values, so
        // the test helper wraps once at construction time. Tests insert
        // the returned Arc directly with no further changes.
        std::sync::Arc::new(CachedPackageInfo {
            modified: None,
            trust_metadata_complete: false,
            versions: versions
                .iter()
                .map(|v| NpmVersion::parse(v).unwrap())
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
            peer_deps: peer_deps
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
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: HashMap::new(),
            aliases: HashMap::new(),
        })
    }

    fn make_version_metadata(
        name: &str,
        version: &str,
        dependencies: Vec<(&str, &str)>,
        optional_dependencies: Vec<(&str, &str)>,
        os: Vec<&str>,
        cpu: Vec<&str>,
    ) -> VersionMetadata {
        VersionMetadata {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: dependencies
                .into_iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            optional_dependencies: optional_dependencies
                .into_iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            os: os.into_iter().map(str::to_string).collect(),
            cpu: cpu.into_iter().map(str::to_string).collect(),
            ..VersionMetadata::default()
        }
    }

    fn make_package_metadata(name: &str, versions: Vec<VersionMetadata>) -> PackageMetadata {
        let latest_version = versions
            .last()
            .map(|version| version.version.clone())
            .expect("package metadata test fixture needs at least one version");

        PackageMetadata {
            name: name.to_string(),
            description: None,
            dist_tags: HashMap::from([("latest".to_string(), latest_version.clone())]),
            versions: versions
                .into_iter()
                .map(|version| (version.version.clone(), version))
                .collect(),
            time: HashMap::new(),
            modified: None,
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: Some(latest_version),
            ecosystem: None,
        }
    }

    #[tokio::test]
    async fn resolve_with_prefetch_preserves_platform_incompatible_optional_registry_metadata() {
        let platform = Platform::current();
        let compatible_optional = format!("@esbuild/{}-{}", platform.os, platform.cpu);
        let (incompatible_optional, incompatible_os, incompatible_cpu) = if platform.os == "darwin"
        {
            ("@esbuild/linux-x64".to_string(), "linux", "x64")
        } else {
            ("@esbuild/darwin-arm64".to_string(), "darwin", "arm64")
        };

        let prefetched = HashMap::from([
            (
                "esbuild".to_string(),
                make_package_metadata(
                    "esbuild",
                    vec![make_version_metadata(
                        "esbuild",
                        "0.28.0",
                        vec![],
                        vec![
                            (compatible_optional.as_str(), "0.28.0"),
                            (incompatible_optional.as_str(), "0.28.0"),
                        ],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                compatible_optional.clone(),
                make_package_metadata(
                    &compatible_optional,
                    vec![make_version_metadata(
                        &compatible_optional,
                        "0.28.0",
                        vec![],
                        vec![],
                        vec![platform.os],
                        vec![platform.cpu],
                    )],
                ),
            ),
            (
                incompatible_optional.clone(),
                make_package_metadata(
                    &incompatible_optional,
                    vec![make_version_metadata(
                        &incompatible_optional,
                        "0.28.0",
                        vec![],
                        vec![],
                        vec![incompatible_os],
                        vec![incompatible_cpu],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("esbuild".to_string(), "0.28.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("prefetched esbuild-style metadata should resolve on the current platform");

        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|package| package.package.to_string())
            .collect();
        assert!(resolved_names.contains("esbuild"));
        assert!(resolved_names.contains(&compatible_optional));
        assert!(resolved_names.contains(&incompatible_optional));

        let esbuild = result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == "esbuild")
            .expect("esbuild should be in the resolved tree");
        assert!(
            esbuild
                .dependencies
                .contains(&(compatible_optional, "0.28.0".to_string()))
        );
        assert!(
            esbuild
                .dependencies
                .contains(&(incompatible_optional.clone(), "0.28.0".to_string()))
        );

        let incompatible = result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == incompatible_optional)
            .expect("incompatible optional should remain in the resolver output");
        assert!(incompatible.optional);
        assert_eq!(
            incompatible.platform,
            Some(PlatformMeta {
                os: vec![incompatible_os.to_string()],
                cpu: vec![incompatible_cpu.to_string()],
                libc: vec![],
            })
        );
    }

    /// `StageTiming` contract: `resolve_with_prefetch` populates the
    /// field on `ResolveResult` and the resolver flows that value
    /// through the happy path to the caller.
    ///
    /// NOTE: The underlying counters live in `lpm_registry::timing`
    /// as process-global atomics (see that module's docs for why
    /// thread-locals can't work with `spawn_blocking`). Concurrent
    /// tests that trigger RPCs — even failing ones — will race on
    /// those atomics, so this test intentionally does NOT assert
    /// strict zeros on follow-up fields. The install-pipeline
    /// fixture run serves as the end-to-end contract check for
    /// non-zero values; here we validate only that the shape is
    /// wired through and that the `pubgrub_ms` accumulator ran
    /// (it's bounded by a single resolution pass, so not subject to
    /// cross-test contamination).
    #[tokio::test]
    async fn resolve_with_prefetch_emits_stage_timing_shape() {
        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![("left", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "left".to_string(),
                make_package_metadata(
                    "left",
                    vec![make_version_metadata(
                        "left",
                        "1.0.0",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("fully-prefetched resolution must succeed");

        let t = result.stage_timing;
        // `pubgrub_ms` is a per-pass wall-clock accumulator, not a
        // process-global, so it's race-free. Even on the fastest
        // machines a non-trivial resolution is at least 1 instant
        // apart; but we tolerate 0 in case of sub-millisecond
        // resolution (the type is unsigned, so only assert upper
        // sanity bound).
        assert!(
            t.pubgrub_ms < 60_000,
            "pubgrub_ms of {} indicates runaway resolution or leaked wall-clock",
            t.pubgrub_ms
        );
        // Shape is accessible; follow-up fields exist and are read
        // without panic. The actual values are validated end-to-end
        // against a real install fixture.
        let _ = t.followup_rpc_ms;
        let _ = t.followup_rpc_count;
        let _ = t.parse_ndjson_ms;
    }

    /// Regression: a platform-gated optional dep has one old version with
    /// an erroneous `os`/`cpu` declaration that makes it look compatible,
    /// but that version doesn't satisfy the declared range. Resolution must
    /// still pick the newest satisfying version and carry platform metadata
    /// forward so install-time filtering can skip it.
    #[tokio::test]
    async fn resolve_with_prefetch_selects_newest_optional_when_platform_match_is_out_of_range() {
        let platform = Platform::current();
        let incompatible_optional = if platform.os == "darwin" {
            "@next/swc-linux-x64-musl".to_string()
        } else {
            "@next/swc-darwin-arm64".to_string()
        };

        // `next@15.5.15` declares `incompatible_optional: 15.5.15` as OPTIONAL.
        // The dep has two versions in the registry:
        //   - 15.5.15: declares the correct (incompatible) platform
        //   - 12.0.0: declares the current platform erroneously (Next.js packaging bug)
        let prefetched = HashMap::from([
            (
                "next".to_string(),
                make_package_metadata(
                    "next",
                    vec![make_version_metadata(
                        "next",
                        "15.5.15",
                        vec![],
                        vec![(incompatible_optional.as_str(), "15.5.15")],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                incompatible_optional.clone(),
                make_package_metadata(
                    &incompatible_optional,
                    vec![
                        // Correctly tagged for the OTHER platform — would be
                        // filtered by platform check.
                        make_version_metadata(
                            &incompatible_optional,
                            "15.5.15",
                            vec![],
                            vec![],
                            if platform.os == "darwin" {
                                vec!["linux"]
                            } else {
                                vec!["darwin"]
                            },
                            if platform.os == "darwin" {
                                vec!["x64"]
                            } else {
                                vec!["arm64"]
                            },
                        ),
                        // Erroneously tagged for the CURRENT platform — passes
                        // platform filter, but doesn't satisfy the declared
                        // range on `next@15.5.15` (which is `15.5.15` exactly).
                        make_version_metadata(
                            &incompatible_optional,
                            "12.0.0",
                            vec![],
                            vec![],
                            vec![platform.os],
                            vec![platform.cpu],
                        ),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("next".to_string(), "15.5.15".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect(
            "resolver must pick the newest satisfying optional dep and defer platform filtering",
        );

        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|package| package.package.to_string())
            .collect();
        assert!(
            resolved_names.contains("next"),
            "root dep `next` must be resolved"
        );
        assert!(
            resolved_names.contains(&incompatible_optional),
            "platform-gated optional dep must be present for install-time filtering"
        );

        let optional = result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == incompatible_optional)
            .expect("platform-gated optional dep should resolve");
        assert_eq!(optional.version.to_string(), "15.5.15");
        assert!(optional.optional);
    }

    /// npm-alias root dep: the consumer declares
    /// `"strip-ansi-cjs": "npm:strip-ansi@^6.0.1"`, and the resolver
    /// must (a) fetch `strip-ansi` metadata (not `strip-ansi-cjs`),
    /// (b) resolve the alias target's version against the inner range,
    /// and (c) surface the `local → target` mapping via
    /// `ResolveResult.root_aliases` so the install pipeline can build
    /// `node_modules/strip-ansi-cjs/` → `.lpm/strip-ansi@6.0.1/...`.
    #[tokio::test]
    async fn resolve_with_prefetch_handles_root_npm_alias() {
        // PubGrub-arm-specific: npm-alias range parsing
        // (`"strip-ansi-cjs": "npm:strip-ansi@^6.0.1"`). Greedy doesn't
        // accept this range form, so pin to PubGrub.
        let _env = env_lock().lock().await;
        let _guard = PubgrubEnvGuard::new();

        let prefetched = HashMap::from([(
            "strip-ansi".to_string(),
            make_package_metadata(
                "strip-ansi",
                vec![make_version_metadata(
                    "strip-ansi",
                    "6.0.1",
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        )]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([(
                "strip-ansi-cjs".to_string(),
                "npm:strip-ansi@^6.0.1".to_string(),
            )]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("root npm-alias must resolve against the target identity");

        // The resolved tree contains the TARGET (`strip-ansi`), not the
        // alias key.
        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|p| p.package.to_string())
            .collect();
        assert!(
            resolved_names.contains("strip-ansi"),
            "alias target must be in resolved tree"
        );
        assert!(
            !resolved_names.contains("strip-ansi-cjs"),
            "alias key must not pollute resolver identities"
        );

        // Root alias is surfaced for the install pipeline.
        assert_eq!(
            result.root_aliases.get("strip-ansi-cjs"),
            Some(&"strip-ansi".to_string()),
            "root_aliases must record local → target"
        );
    }

    /// npm-alias transitive dep: a parent package's registry metadata
    /// declares
    /// `"strip-ansi-cjs": "npm:strip-ansi@^6"` in its own
    /// `dependencies`. The resolver must treat the alias the same way
    /// at any depth — the parent's resolved edge list records the
    /// local name (`strip-ansi-cjs`), the resolved child is keyed on
    /// `strip-ansi`, and the parent's `aliases` map carries the
    /// `local → target` pair so the linker can build
    /// `.lpm/parent@1.0.0/node_modules/strip-ansi-cjs/` →
    /// `../../strip-ansi@6.0.1/node_modules/strip-ansi/`.
    #[tokio::test]
    async fn resolve_with_prefetch_handles_transitive_npm_alias() {
        let prefetched = HashMap::from([
            (
                "parent".to_string(),
                make_package_metadata(
                    "parent",
                    vec![make_version_metadata(
                        "parent",
                        "1.0.0",
                        vec![("strip-ansi-cjs", "npm:strip-ansi@^6")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "strip-ansi".to_string(),
                make_package_metadata(
                    "strip-ansi",
                    vec![make_version_metadata(
                        "strip-ansi",
                        "6.0.1",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("parent".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("transitive npm-alias must resolve through the target identity");

        // Parent and aliased target (strip-ansi) are in the tree; the
        // alias key itself is NOT a distinct ResolverPackage.
        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|p| p.package.to_string())
            .collect();
        assert!(resolved_names.contains("parent"));
        assert!(resolved_names.contains("strip-ansi"));
        assert!(!resolved_names.contains("strip-ansi-cjs"));

        // Parent's dep edge carries the LOCAL name + resolved version.
        let parent = result
            .packages
            .iter()
            .find(|p| p.package.canonical_name() == "parent")
            .unwrap();
        assert_eq!(
            parent.dependencies,
            vec![("strip-ansi-cjs".to_string(), "6.0.1".to_string())],
            "edge key is the local alias name, version is the target's"
        );
        assert_eq!(
            parent.aliases.get("strip-ansi-cjs"),
            Some(&"strip-ansi".to_string()),
            "parent's aliases map records local → target"
        );

        // Transitive aliases are NOT root aliases.
        assert!(
            result.root_aliases.is_empty(),
            "transitive alias must not leak into the root alias map"
        );
    }

    /// Regression: a non-optional dep with no compatible platform version
    /// still resolves so install-time filtering can produce the required
    /// hard platform error instead of hiding the selected package from the
    /// lockfile.
    #[tokio::test]
    async fn resolve_regular_dep_with_no_platform_compatible_version_still_resolves() {
        let platform = Platform::current();
        let incompatible_dep = if platform.os == "darwin" {
            "some-linux-only-dep".to_string()
        } else {
            "some-darwin-only-dep".to_string()
        };

        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![(incompatible_dep.as_str(), "1.0.0")], // REQUIRED dep
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                incompatible_dep.clone(),
                make_package_metadata(
                    &incompatible_dep,
                    vec![make_version_metadata(
                        &incompatible_dep,
                        "1.0.0",
                        vec![],
                        vec![],
                        if platform.os == "darwin" {
                            vec!["linux"]
                        } else {
                            vec!["darwin"]
                        },
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("resolver must defer required platform errors to install-time filtering");

        let dep = result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == incompatible_dep)
            .expect("required incompatible dep should be present in resolver output");
        assert!(!dep.optional);
        assert!(dep.platform.is_some());
    }

    #[tokio::test]
    async fn resolve_with_prefetch_retries_until_all_conflicts_are_split() {
        // PubGrub-arm-specific: split-retry conflict resolution.
        let _env = env_lock().lock().await;
        let _guard = PubgrubEnvGuard::new();

        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "a".to_string(),
                make_package_metadata(
                    "a",
                    vec![make_version_metadata(
                        "a",
                        "1.0.0",
                        vec![("x", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "b".to_string(),
                make_package_metadata(
                    "b",
                    vec![make_version_metadata(
                        "b",
                        "1.0.0",
                        vec![("x", "2.0.0"), ("y", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "c".to_string(),
                make_package_metadata(
                    "c",
                    vec![make_version_metadata(
                        "c",
                        "1.0.0",
                        vec![("y", "2.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "x".to_string(),
                make_package_metadata(
                    "x",
                    vec![
                        make_version_metadata("x", "1.0.0", vec![], vec![], vec![], vec![]),
                        make_version_metadata("x", "2.0.0", vec![], vec![], vec![], vec![]),
                    ],
                ),
            ),
            (
                "y".to_string(),
                make_package_metadata(
                    "y",
                    vec![
                        make_version_metadata("y", "1.0.0", vec![], vec![], vec![], vec![]),
                        make_version_metadata("y", "2.0.0", vec![], vec![], vec![], vec![]),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("resolver should keep splitting until both x and y conflicts are scoped");

        let resolved_versions: HashMap<String, String> = result
            .packages
            .iter()
            .map(|package| (package.package.to_string(), package.version.to_string()))
            .collect();

        assert_eq!(
            resolved_versions.get("x[a]").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            resolved_versions.get("x[b]").map(String::as_str),
            Some("2.0.0")
        );
        assert_eq!(
            resolved_versions.get("y[b]").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            resolved_versions.get("y[c]").map(String::as_str),
            Some("2.0.0")
        );
    }

    /// Nested-scope propagation.
    ///
    /// Minimal reproduction of the real-world eslint + ajv conflict:
    /// root depends on ajv@^8 + eslint@^9; eslint@9 transitively requires
    /// ajv@^6; ajv@8 and ajv@6 each declare DIFFERENT json-schema-traverse
    /// version ranges.
    ///
    /// bun resolves this fine — two ajv's coexist in node_modules (top-
    /// level ajv@8 + nested eslint/node_modules/ajv@6), each with its own
    /// json-schema-traverse.
    ///
    /// Before the fix, lpm's pubgrub concluded NoSolution because the
    /// split-retry logic could split `ajv` into `ajv[<root>]` vs
    /// `ajv[eslint]`, but when enumerating the split ajv's deps the scope
    /// key for the grandchild was built from
    /// `parent.canonical_name()` — which strips the parent's context.
    /// Both ajv's produced a child scope-key of `[ajv]`, unifying the two
    /// json-schema-traverse requests back into a single pubgrub identity
    /// whose version ranges collided.
    ///
    /// After the fix, the grandchild scope key is derived from the
    /// parent's full display identity, so `ajv[<root>]`'s child gets
    /// `json-schema-traverse[ajv[<root>]]` and `ajv[eslint]`'s child gets
    /// `json-schema-traverse[ajv[eslint]]` — distinct pubgrub packages,
    /// each able to satisfy its own range.
    #[tokio::test]
    async fn resolve_with_prefetch_propagates_parent_context_to_grandchild_splits() {
        // PubGrub-arm-specific: split-retry context propagation to
        // grandchildren of split nodes.
        let _env = env_lock().lock().await;
        let _guard = PubgrubEnvGuard::new();

        let prefetched = HashMap::from([
            (
                "root_app".to_string(),
                make_package_metadata(
                    "root_app",
                    vec![make_version_metadata(
                        "root_app",
                        "1.0.0",
                        vec![("ajv", "^8.0.0"), ("eslint", "^9.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "eslint".to_string(),
                make_package_metadata(
                    "eslint",
                    vec![make_version_metadata(
                        "eslint",
                        "9.0.0",
                        vec![("ajv", "^6.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "ajv".to_string(),
                make_package_metadata(
                    "ajv",
                    vec![
                        make_version_metadata(
                            "ajv",
                            "6.14.0",
                            vec![("json-schema-traverse", "^0.4.0")],
                            vec![],
                            vec![],
                            vec![],
                        ),
                        make_version_metadata(
                            "ajv",
                            "8.18.0",
                            vec![("json-schema-traverse", "^1.0.0")],
                            vec![],
                            vec![],
                            vec![],
                        ),
                    ],
                ),
            ),
            (
                "json-schema-traverse".to_string(),
                make_package_metadata(
                    "json-schema-traverse",
                    vec![
                        make_version_metadata(
                            "json-schema-traverse",
                            "0.4.1",
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                        ),
                        make_version_metadata(
                            "json-schema-traverse",
                            "1.0.0",
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                        ),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("root_app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect(
            "resolver must handle eslint+ajv nested duplicates — bun and npm both resolve this \
             without dropping deps",
        );

        let resolved_versions: HashMap<String, String> = result
            .packages
            .iter()
            .map(|package| (package.package.to_string(), package.version.to_string()))
            .collect();

        // Two ajv's must coexist.
        let ajv_8_key = resolved_versions
            .iter()
            .find(|(_, v)| v.as_str() == "8.18.0")
            .map(|(k, _)| k.clone())
            .expect("ajv@8 should be chosen for the root's direct ^8 range");
        let ajv_6_key = resolved_versions
            .iter()
            .find(|(_, v)| v.as_str() == "6.14.0")
            .map(|(k, _)| k.clone())
            .expect("ajv@6 should be chosen for eslint's transitive ^6 range");
        assert!(
            ajv_8_key.starts_with("ajv"),
            "ajv@8 key should be an ajv identity, got {ajv_8_key}"
        );
        assert!(
            ajv_6_key.starts_with("ajv"),
            "ajv@6 key should be an ajv identity, got {ajv_6_key}"
        );
        assert_ne!(
            ajv_8_key, ajv_6_key,
            "ajv@8 and ajv@6 must be distinct pubgrub identities, both got {ajv_8_key}"
        );

        // And both json-schema-traverse versions must coexist, one per ajv.
        let mut jst_versions: Vec<&str> = resolved_versions
            .iter()
            .filter(|(k, _)| k.starts_with("json-schema-traverse"))
            .map(|(_, v)| v.as_str())
            .collect();
        jst_versions.sort();
        assert_eq!(
            jst_versions,
            vec!["0.4.1", "1.0.0"],
            "exactly one json-schema-traverse@0.4.1 and one @1.0.0 must resolve — got {:?}",
            resolved_versions
        );
    }

    #[test]
    fn peer_check_satisfied_peer_no_warning() {
        // styled-components@5.0.0 peers on react@^16||^17
        // react@17.0.2 is in the tree → satisfied, no warning
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["5.0.0"],
                vec![],
                vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(
            warnings.is_empty(),
            "peer should be satisfied: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_wrong_version_produces_warning() {
        // styled-components@6.0.0 peers on react@^18
        // react@17.0.2 is in the tree → version mismatch warning
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("6.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["6.0.0"],
                vec![],
                vec![("6.0.0", vec![("react", "^18.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].peer, "react");
        assert_eq!(warnings[0].required_range, "^18.0.0");
        assert_eq!(warnings[0].resolved_version.as_deref(), Some("17.0.2"));
    }

    /// `peerDependenciesMeta.optional` suppresses the missing-peer
    /// warning. Real-world example: `react-redux@9` declares optional
    /// peer for older React; users who don't install those see noisy
    /// warnings without this gate.
    #[test]
    fn peer_check_optional_peer_missing_no_warning() {
        let pkg = ResolverPackage::npm("react-redux");

        let resolved = vec![ResolvedPackage {
            package: pkg.clone(),
            version: NpmVersion::parse("9.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }];

        let mut cache = HashMap::new();
        let mut info = (*make_cached_info(
            &["9.0.0"],
            vec![],
            vec![("9.0.0", vec![("react", "^18 || ^19")])],
        ))
        .clone();
        // Mark `react` as optional via peerDependenciesMeta — the
        // missing-peer warning must be suppressed.
        let mut opt_peers = HashSet::new();
        opt_peers.insert("react".to_string());
        info.optional_peer_names
            .insert("9.0.0".to_string(), opt_peers);
        cache.insert(CanonicalKey::from(&pkg), std::sync::Arc::new(info));

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(
            warnings.is_empty(),
            "optional missing peer must NOT produce a warning: {warnings:?}"
        );
    }

    /// Optional peers that ARE present but at the wrong version still
    /// produce a warning. An optional flag is opt-out for the missing
    /// case only; if the user opted into having the peer, the
    /// version-mismatch contract still applies.
    #[test]
    fn peer_check_optional_peer_wrong_version_still_warns() {
        let pkg = ResolverPackage::npm("react-redux");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: pkg.clone(),
                version: NpmVersion::parse("9.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        let mut info = (*make_cached_info(
            &["9.0.0"],
            vec![],
            vec![("9.0.0", vec![("react", "^18 || ^19")])],
        ))
        .clone();
        let mut opt_peers = HashSet::new();
        opt_peers.insert("react".to_string());
        info.optional_peer_names
            .insert("9.0.0".to_string(), opt_peers);
        cache.insert(CanonicalKey::from(&pkg), std::sync::Arc::new(info));
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].peer, "react");
        assert_eq!(
            warnings[0].resolved_version.as_deref(),
            Some("17.0.2"),
            "warning is for the version mismatch, not for missing"
        );
    }

    #[test]
    fn peer_check_missing_peer_produces_warning() {
        // styled-components@5.0.0 peers on react@^16||^17
        // react is NOT in the tree → missing peer warning
        let sc_pkg = ResolverPackage::npm("styled-components");

        let resolved = vec![ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["5.0.0"],
                vec![],
                vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
            ),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].peer, "react");
        assert!(
            warnings[0].resolved_version.is_none(),
            "peer is missing from tree"
        );
    }

    #[test]
    fn peer_check_version_specific_no_cross_contamination() {
        // Key test: styled-components has different peers per version.
        // Only the SELECTED version's peers should be checked.
        //
        // v5.0.0 peers on react@^16||^17
        // v6.0.0 peers on react@^18
        //
        // If v5.0.0 is selected and react@17.0.2 is in tree:
        //   → NO warning (^16||^17 satisfied by 17.0.2)
        //
        // The old union approach would have forced react@^18 (newest wins),
        // which would incorrectly fail.
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        // Both versions are in cache, but only v5's peers should matter
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["6.0.0", "5.0.0"],
                vec![],
                vec![
                    ("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")]),
                    ("6.0.0", vec![("react", "^18.0.0")]),
                ],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(
            warnings.is_empty(),
            "v5's peer react@^16||^17 is satisfied by 17.0.2, v6's peers should not apply: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_prefers_same_split_context_peer_version() {
        let plugin_pkg = ResolverPackage::npm("plugin").with_context("host-a");
        let react_host_a = ResolverPackage::npm("react").with_context("host-a");
        let react_host_b = ResolverPackage::npm("react").with_context("host-b");

        let resolved = vec![
            ResolvedPackage {
                package: plugin_pkg.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_host_a.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_host_b.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&plugin_pkg),
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^17.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_host_a),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );
        cache.insert(
            CanonicalKey::from(&react_host_b),
            make_cached_info(&["18.2.0"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(
            warnings.is_empty(),
            "split package should use peer version from the same context before falling back globally: {warnings:?}"
        );
    }

    #[test]
    fn peer_binding_uses_declared_range_when_multiple_unsplit_versions_exist() {
        let plugin_pkg = ResolverPackage::npm("plugin");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: plugin_pkg.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&plugin_pkg),
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^17.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["18.2.0", "17.0.2"], vec![], vec![]),
        );

        let peer_candidates: HashMap<String, Vec<(Option<String>, String)>> =
            resolved.iter().fold(HashMap::new(), |mut acc, pkg| {
                acc.entry(pkg.package.canonical_name()).or_default().push((
                    pkg.package.context().map(str::to_string),
                    pkg.version.to_string(),
                ));
                acc
            });
        let bound_peers = compute_resolved_peers(&plugin_pkg, "1.0.0", &cache, &peer_candidates);
        assert_eq!(
            bound_peers,
            vec![("react".to_string(), "17.0.2".to_string())],
            "graph/link peer binding must choose the version satisfying the consumer range"
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(
            warnings.is_empty(),
            "warning path and graph binding should agree that react@17 satisfies plugin: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_multiple_packages_multiple_peers() {
        // Two packages with different peers
        let pkg_a = ResolverPackage::npm("pkg-a");
        let pkg_b = ResolverPackage::npm("pkg-b");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: pkg_a.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: pkg_b.clone(),
                version: NpmVersion::parse("2.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        // pkg-a peers on react@^18 (satisfied) and vue@^3 (missing)
        cache.insert(
            CanonicalKey::from(&pkg_a),
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^18.0.0"), ("vue", "^3.0.0")])],
            ),
        );
        // pkg-b peers on react@^17 (wrong version)
        cache.insert(
            CanonicalKey::from(&pkg_b),
            make_cached_info(
                &["2.0.0"],
                vec![],
                vec![("2.0.0", vec![("react", "^17.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["18.2.0"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        // Should have 2 warnings: vue missing + react wrong version for pkg-b
        assert_eq!(warnings.len(), 2, "expected 2 warnings: {warnings:?}");

        // Sorted by package then peer
        assert_eq!(warnings[0].package, "pkg-a");
        assert_eq!(warnings[0].peer, "vue");
        assert!(warnings[0].resolved_version.is_none());

        assert_eq!(warnings[1].package, "pkg-b");
        assert_eq!(warnings[1].peer, "react");
        assert_eq!(warnings[1].resolved_version.as_deref(), Some("18.2.0"));
    }

    #[test]
    fn peer_check_no_peers_no_warnings() {
        // Package with no peer deps → no warnings
        let pkg = ResolverPackage::npm("lodash");

        let resolved = vec![ResolvedPackage {
            package: pkg.clone(),
            version: NpmVersion::parse("4.17.21").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&pkg),
            make_cached_info(&["4.17.21"], vec![], vec![]),
        );

        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert!(warnings.is_empty());
    }

    #[test]
    fn peer_warning_display_format() {
        let w_missing = PeerWarning {
            package: "styled-components".to_string(),
            version: "5.0.0".to_string(),
            peer: "react".to_string(),
            required_range: "^16.8.0".to_string(),
            resolved_version: None,
        };
        assert!(w_missing.to_string().contains("is not installed"));

        let w_wrong = PeerWarning {
            package: "styled-components".to_string(),
            version: "6.0.0".to_string(),
            peer: "react".to_string(),
            required_range: "^18.0.0".to_string(),
            resolved_version: Some("17.0.2".to_string()),
        };
        assert!(w_wrong.to_string().contains("17.0.2 was resolved"));
    }

    // ─── peer-dependency rules — glob matcher ─────────────────────────

    /// Patterns without `*` match exactly; nothing else.
    #[test]
    fn glob_pattern_exact_match_no_wildcard() {
        let p = GlobPattern::compile("react");
        assert!(p.matches("react"));
        assert!(!p.matches("react-dom"));
        assert!(!p.matches("preact"));
        assert!(!p.matches(""));
    }

    /// Bare `*` matches every name including the empty string.
    #[test]
    fn glob_pattern_bare_star_matches_anything() {
        let p = GlobPattern::compile("*");
        assert!(p.matches("react"));
        assert!(p.matches("@scope/anything"));
        assert!(p.matches(""));
    }

    /// Trailing `*` is a prefix match.
    #[test]
    fn glob_pattern_trailing_star_is_prefix_match() {
        let p = GlobPattern::compile("@babel/*");
        assert!(p.matches("@babel/core"));
        assert!(p.matches("@babel/runtime"));
        assert!(p.matches("@babel/")); // empty suffix allowed
        assert!(!p.matches("@babels/core"));
        assert!(!p.matches("babel/core"));
    }

    /// Leading `*` is a suffix match.
    #[test]
    fn glob_pattern_leading_star_is_suffix_match() {
        let p = GlobPattern::compile("*-eslint-plugin");
        assert!(p.matches("vue-eslint-plugin"));
        assert!(p.matches("react-eslint-plugin"));
        assert!(p.matches("-eslint-plugin")); // empty prefix allowed
        assert!(!p.matches("eslint-plugin")); // missing the leading hyphen
        assert!(!p.matches("eslint-plugin-vue"));
    }

    /// Middle `*` requires both anchors.
    #[test]
    fn glob_pattern_middle_star_requires_both_anchors() {
        let p = GlobPattern::compile("react-*-helper");
        assert!(p.matches("react-something-helper"));
        assert!(p.matches("react--helper")); // empty middle allowed
        assert!(!p.matches("react-helper")); // missing the second hyphen
        assert!(!p.matches("react-something-helpers"));
        assert!(!p.matches("preact-something-helper"));
    }

    /// Multiple wildcards: "a*b*c" requires ordered substring match.
    #[test]
    fn glob_pattern_multiple_wildcards() {
        let p = GlobPattern::compile("@scope/*-*-tools");
        assert!(p.matches("@scope/foo-bar-tools"));
        assert!(p.matches("@scope/--tools"));
        assert!(!p.matches("@scope/foo-tools")); // only one hyphen
        assert!(!p.matches("@scope/foo-bar")); // missing -tools suffix
    }

    // ─── peer-dependency rules — apply during check_unmet_peers ───────

    /// `ignoreMissing` matches → no missing-peer warning fires for
    /// the matched name.
    #[test]
    fn peer_rules_ignore_missing_suppresses_missing_warning() {
        let sc_pkg = ResolverPackage::npm("styled-components");

        let resolved = vec![ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["5.0.0"],
                vec![],
                vec![("5.0.0", vec![("react", "^16.8.0")])],
            ),
        );

        // Without rules: warning fires.
        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(warnings.len(), 1);

        // With ignoreMissing on react: warning suppressed.
        let rules = CompiledPeerRules::compile(&["react".into()], &HashMap::new(), &[]).unwrap();
        let warnings = check_unmet_peers(&resolved, &cache, &rules);
        assert!(
            warnings.is_empty(),
            "ignoreMissing(react) must suppress missing-peer warning"
        );

        // Pattern form: scope wildcard catches multiple names.
        let rules = CompiledPeerRules::compile(&["*".into()], &HashMap::new(), &[]).unwrap();
        let warnings = check_unmet_peers(&resolved, &cache, &rules);
        assert!(
            warnings.is_empty(),
            "ignoreMissing(*) must suppress everything"
        );
    }

    /// `allowedVersions` widens the accepted range when the peer is
    /// in the tree but at a non-satisfying version.
    #[test]
    fn peer_rules_allowed_versions_widens_match() {
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![("react".into(), "17.0.2".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["5.0.0"],
                vec![],
                // Consumer wants react ^16, but 17 was resolved.
                vec![("5.0.0", vec![("react", "^16.8.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.2"], vec![], vec![]),
        );

        // Without rules: version-mismatch warning.
        let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].resolved_version.is_some());

        // Widen the range to "16 || 17": warning suppressed.
        let mut allowed = HashMap::new();
        allowed.insert("react".to_string(), "16 || 17".to_string());
        let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();
        let warnings = check_unmet_peers(&resolved, &cache, &rules);
        assert!(
            warnings.is_empty(),
            "allowedVersions(react=16||17) must accept react@17.0.2"
        );

        // allowedVersions does NOT support glob patterns; the
        // structured selector grammar is the only accepted shape.
        // Compile must FAIL CLOSED on a wildcard key — silently
        // accepting `"*"` and matching nothing would contradict the
        // documented contract and silently no-op the rule.
        let mut allowed = HashMap::new();
        allowed.insert("*".to_string(), "16 || 17".to_string());
        let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
        assert!(err.contains("\"*\""), "error must name the bad key: {err}");
        assert!(
            err.contains("wildcard") || err.contains("glob"),
            "error must explain why `*` is rejected: {err}"
        );
    }

    /// `allowAny` matches → version-mismatch warning suppressed,
    /// but the peer must still be present (does not suppress
    /// missing-peer warnings).
    #[test]
    fn peer_rules_allow_any_suppresses_version_mismatch_only() {
        let sc_pkg = ResolverPackage::npm("styled-components");
        let babel_pkg = ResolverPackage::npm("@babel/core");

        // Variant A: peer in tree at wrong version.
        let resolved_present = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![("@babel/core".into(), "7.5.0".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: babel_pkg.clone(),
                version: NpmVersion::parse("7.5.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        // Variant B: peer not in tree at all.
        let resolved_missing = vec![ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        }];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&sc_pkg),
            make_cached_info(
                &["5.0.0"],
                vec![],
                // Consumer wants babel ^7.20, got 7.5 — mismatch.
                vec![("5.0.0", vec![("@babel/core", "^7.20.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&babel_pkg),
            make_cached_info(&["7.5.0"], vec![], vec![]),
        );

        // allowAny pattern — covers @babel/* — suppresses present-
        // but-mismatched warning.
        let rules = CompiledPeerRules::compile(&[], &HashMap::new(), &["@babel/*".into()]).unwrap();
        let warnings = check_unmet_peers(&resolved_present, &cache, &rules);
        assert!(
            warnings.is_empty(),
            "allowAny(@babel/*) must suppress version-mismatch when peer is in tree"
        );

        // Same rule does NOT suppress the missing-peer case — the
        // user must combine with ignoreMissing for that.
        let warnings = check_unmet_peers(&resolved_missing, &cache, &rules);
        assert_eq!(
            warnings.len(),
            1,
            "allowAny must NOT suppress missing-peer warnings — that's ignoreMissing's job"
        );
        assert!(warnings[0].resolved_version.is_none());
    }

    // ─── allowedVersions selector grammar (full pnpm parity) ─────────

    /// Bare peer name selectors match any consumer for that peer.
    #[test]
    fn allowed_versions_selector_bare_name_matches_any_consumer() {
        let s = AllowedVersionsSelector::parse("react").unwrap();
        assert!(s.parent.is_none());
        assert_eq!(s.peer, "react");

        let v1 = NpmVersion::parse("1.0.0").unwrap();
        assert!(s.matches("anything", &v1, "react"));
        assert!(s.matches("@scope/anything", &v1, "react"));
        assert!(!s.matches("anything", &v1, "react-dom"));
    }

    /// Scoped peer name selectors are bare keys with a leading `@`.
    #[test]
    fn allowed_versions_selector_scoped_bare_name() {
        let s = AllowedVersionsSelector::parse("@scope/foo").unwrap();
        assert!(s.parent.is_none());
        assert_eq!(s.peer, "@scope/foo");
    }

    /// `parent>peer` selector matches only when the consumer name
    /// matches the parent half. Parent version is unconstrained.
    #[test]
    fn allowed_versions_selector_parent_no_range_filters_by_consumer_name() {
        let s = AllowedVersionsSelector::parse("foo>react").unwrap();
        let parent = s.parent.as_ref().unwrap();
        assert_eq!(parent.name, "foo");
        assert!(parent.range.is_none());
        assert_eq!(s.peer, "react");

        let v1 = NpmVersion::parse("1.0.0").unwrap();
        assert!(s.matches("foo", &v1, "react"));
        assert!(!s.matches("bar", &v1, "react")); // different consumer
        assert!(!s.matches("foo", &v1, "vue")); // different peer
    }

    /// `parent@range>peer` filters by both consumer name AND consumer
    /// version satisfying the range — the central correctness fix
    /// the user flagged.
    #[test]
    fn allowed_versions_selector_parent_with_range_filters_by_consumer_version() {
        let s = AllowedVersionsSelector::parse("foo@^2>react").unwrap();
        let parent = s.parent.as_ref().unwrap();
        assert_eq!(parent.name, "foo");
        assert!(parent.range.is_some());
        assert_eq!(s.peer, "react");

        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("2.5.0").unwrap();
        let v3 = NpmVersion::parse("3.0.0").unwrap();
        assert!(!s.matches("foo", &v1, "react")); // v1 outside ^2
        assert!(s.matches("foo", &v2, "react")); // v2 satisfies ^2
        assert!(!s.matches("foo", &v3, "react")); // v3 outside ^2
        assert!(!s.matches("bar", &v2, "react")); // wrong consumer name
    }

    /// Scoped parent + version range. The leading `@` of the scope is
    /// distinguished from the version-separating `@`.
    #[test]
    fn allowed_versions_selector_scoped_parent_with_range() {
        let s = AllowedVersionsSelector::parse("@scope/foo@^2>react").unwrap();
        let parent = s.parent.as_ref().unwrap();
        assert_eq!(parent.name, "@scope/foo");
        assert!(parent.range.is_some());
        assert_eq!(s.peer, "react");

        let v2 = NpmVersion::parse("2.0.0").unwrap();
        assert!(s.matches("@scope/foo", &v2, "react"));
        assert!(!s.matches("scope/foo", &v2, "react")); // missing scope @
    }

    /// Multi-segment paths are rejected as a hard error — same posture
    /// as `lpm.overrides`.
    #[test]
    fn allowed_versions_selector_rejects_multi_segment_paths() {
        let err = AllowedVersionsSelector::parse("a>b>c").unwrap_err();
        assert!(err.contains("multi-segment"), "got: {err}");
    }

    /// Bare key with version qualifier is ambiguous and rejected.
    #[test]
    fn allowed_versions_selector_rejects_bare_name_with_version_qualifier() {
        let err = AllowedVersionsSelector::parse("foo@2").unwrap_err();
        assert!(err.contains("version qualifier"), "got: {err}");
    }

    /// Peer half (after `>`) carrying a version qualifier is rejected
    /// — the rule's value is the widened range; putting one on the
    /// peer side too is ambiguous.
    #[test]
    fn allowed_versions_selector_rejects_peer_with_version_qualifier() {
        let err = AllowedVersionsSelector::parse("foo>react@2").unwrap_err();
        assert!(err.contains("peer half"), "got: {err}");
    }

    /// Empty halves are rejected.
    #[test]
    fn allowed_versions_selector_rejects_empty_halves() {
        assert!(AllowedVersionsSelector::parse("foo>").is_err());
        assert!(AllowedVersionsSelector::parse(">react").is_err());
        assert!(AllowedVersionsSelector::parse(">").is_err());
        assert!(AllowedVersionsSelector::parse("").is_err());
    }

    /// Unparseable parent version range is rejected.
    #[test]
    fn allowed_versions_selector_rejects_unparseable_parent_range() {
        let err = AllowedVersionsSelector::parse("foo@~~not-a-range>react").unwrap_err();
        assert!(err.contains("range"), "got: {err}");
    }

    // ─── parent-context-aware allowedVersions in check_unmet_peers ────

    /// The high-finding case: `parent>peer` selectors actually filter
    /// at runtime. A pnpm-style `card>react` rule must NOT silence
    /// `button>react` peer warnings.
    #[test]
    fn peer_rules_allowed_versions_parent_selector_only_matches_named_consumer() {
        // Two consumers (button + card) each peer-dep on react@^18.
        // Resolver lands react@17 — both warn without rules.
        // With `card>react: 17`, only card's warning silences;
        // button's warning still fires.
        let button_pkg = ResolverPackage::npm("button");
        let card_pkg = ResolverPackage::npm("card");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: button_pkg.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![("react".into(), "17.0.0".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: card_pkg.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![("react".into(), "17.0.0".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&button_pkg),
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^18.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&card_pkg),
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^18.0.0")])],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.0"], vec![], vec![]),
        );

        // Without rules: BOTH consumers warn (2 warnings).
        let baseline = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
        assert_eq!(baseline.len(), 2, "baseline: both consumers warn");

        // With `card>react: 17`, only card's warning silences.
        let mut allowed = HashMap::new();
        allowed.insert("card>react".into(), "17".into());
        let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();
        let warnings = check_unmet_peers(&resolved, &cache, &rules);
        assert_eq!(
            warnings.len(),
            1,
            "card>react must silence ONLY card's warning, not button's"
        );
        assert_eq!(warnings[0].package, "button");
    }

    /// `parent@range>peer` only fires when the consumer's resolved
    /// version satisfies the range.
    #[test]
    fn peer_rules_allowed_versions_parent_range_filters_consumer_version() {
        // Consumer foo declares react@^18 peer; foo's installed
        // version varies. Rule is `foo@^2>react: 17`.
        let foo_pkg = ResolverPackage::npm("foo");
        let react_pkg = ResolverPackage::npm("react");

        // Variant A: foo@2.5 (in range) → rule matches → no warning.
        let resolved_in_range = vec![
            ResolvedPackage {
                package: foo_pkg.clone(),
                version: NpmVersion::parse("2.5.0").unwrap(),
                dependencies: vec![("react".into(), "17.0.0".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];
        // Variant B: foo@1.5 (out of range) → rule doesn't apply → warning.
        let resolved_out_of_range = vec![
            ResolvedPackage {
                package: foo_pkg.clone(),
                version: NpmVersion::parse("1.5.0").unwrap(),
                dependencies: vec![("react".into(), "17.0.0".into())],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                peers: Vec::new(),
                tarball_url: None,
                integrity: None,
                platform: None,
                optional: false,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::from(&foo_pkg),
            make_cached_info(
                &["2.5.0", "1.5.0"],
                vec![],
                vec![
                    ("2.5.0", vec![("react", "^18.0.0")]),
                    ("1.5.0", vec![("react", "^18.0.0")]),
                ],
            ),
        );
        cache.insert(
            CanonicalKey::from(&react_pkg),
            make_cached_info(&["17.0.0"], vec![], vec![]),
        );

        let mut allowed = HashMap::new();
        allowed.insert("foo@^2>react".into(), "17".into());
        let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();

        let in_range = check_unmet_peers(&resolved_in_range, &cache, &rules);
        assert!(
            in_range.is_empty(),
            "foo@2.5 satisfies ^2 → rule applies → no warning"
        );
        let out_of_range = check_unmet_peers(&resolved_out_of_range, &cache, &rules);
        assert_eq!(
            out_of_range.len(),
            1,
            "foo@1.5 outside ^2 → rule doesn't apply → warning"
        );
    }

    // ─── fail-closed compile (Medium-finding fix) ────────────────────

    /// Unparseable selector key fails compile with a named-error.
    #[test]
    fn compile_rejects_unparseable_selector_key() {
        let mut allowed = HashMap::new();
        allowed.insert("a>b>c".into(), "1".into());
        let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
        assert!(
            err.contains("a>b>c"),
            "error must name the offending key: {err}"
        );
        assert!(err.contains("multi-segment"), "got: {err}");
    }

    /// Unparseable widened range fails compile with a named-error.
    /// Mirrors the OverrideSet fail-closed posture for hand-authored
    /// `lpm.overrides` typos.
    #[test]
    fn compile_rejects_unparseable_range() {
        let mut allowed = HashMap::new();
        allowed.insert("react".into(), "~~not-a-range".into());
        let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
        assert!(
            err.contains("react"),
            "error must name the offending key: {err}"
        );
        assert!(err.contains("range"), "got: {err}");
    }

    /// validate_allowed_versions_selector exposes the same parser to
    /// the migrate planner — same errors, same shapes accepted.
    #[test]
    fn validate_allowed_versions_selector_exposes_same_parser() {
        // Same valid forms compile.
        for valid in [
            "react",
            "@scope/foo",
            "foo>react",
            "foo@^2>react",
            "@scope/foo@^2>react",
        ] {
            assert!(
                validate_allowed_versions_selector(valid).is_ok(),
                "expected {valid} to validate",
            );
        }
        // Same invalid forms reject — including every glob-wildcard
        // shape across every selector position.
        for invalid in [
            "",
            "a>b>c",
            "foo@2",
            "foo>react@2",
            ">react",
            "foo>",
            // bare wildcard
            "*",
            // scope wildcard
            "@scope/*",
            // suffix wildcard
            "*-eslint-plugin",
            // peer-half wildcard (after `>`)
            "foo>*",
            // parent-half wildcard
            "*>react",
            // wildcard inside scoped name
            "@*/foo>react",
        ] {
            assert!(
                validate_allowed_versions_selector(invalid).is_err(),
                "expected {invalid:?} to fail",
            );
        }
    }

    // ─── glob wildcards rejected at every selector position ──────────

    /// Bare wildcard keys (`"*"`, `"@scope/*"`, `"*-suffix"`) are
    /// rejected at compile time — `allowedVersions` uses the
    /// structured selector grammar, not glob patterns. The
    /// permissive registry-data validator [`is_valid_dep_name`]
    /// would otherwise accept these (it only blocks path traversal
    /// and null bytes) and let them silently no-op at runtime.
    #[test]
    fn allowed_versions_selector_rejects_bare_wildcard() {
        for bad in ["*", "@scope/*", "*-eslint-plugin"] {
            let err = AllowedVersionsSelector::parse(bad).unwrap_err();
            assert!(
                err.contains("wildcard") || err.contains("glob"),
                "expected wildcard rejection for {bad:?}, got: {err}"
            );
        }
    }

    /// Wildcards in the peer half of `parent>peer` are rejected.
    #[test]
    fn allowed_versions_selector_rejects_wildcard_in_peer_half() {
        let err = AllowedVersionsSelector::parse("foo>*").unwrap_err();
        assert!(
            err.contains("wildcard") || err.contains("glob"),
            "got: {err}"
        );
    }

    /// Wildcards in the parent half (with or without scope) are
    /// rejected.
    #[test]
    fn allowed_versions_selector_rejects_wildcard_in_parent_half() {
        for bad in ["*>react", "@*/foo>react", "@scope/*>react"] {
            let err = AllowedVersionsSelector::parse(bad).unwrap_err();
            assert!(
                err.contains("wildcard") || err.contains("glob"),
                "expected wildcard rejection for {bad:?}, got: {err}"
            );
        }
    }

    /// Compile fails closed on a wildcard key — the `"*"` test that
    /// previously locked in the fail-open behavior is now explicit
    /// fail-closed. Documented contract honored on the wire.
    #[test]
    fn compile_rejects_wildcard_allowed_versions_keys() {
        let mut allowed = HashMap::new();
        allowed.insert("*".to_string(), "16 || 17".to_string());
        let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
        assert!(err.contains("\"*\""));
        assert!(err.contains("wildcard") || err.contains("glob"));
    }

    // ─── stricter selector-name predicate (real npm naming rules) ───

    /// Malformed non-wildcard selector keys are rejected at compile
    /// time. The previous `is_valid_selector_name` only added
    /// wildcard rejection on top of the registry-hygiene helper,
    /// which silently accepted spaces, uppercase letters, leading
    /// `.`/`_`, and other npm-forbidden characters — those entries
    /// would compile cleanly but never match anything at runtime
    /// (silent no-op). Each name shape below would have slipped
    /// through pre-fix; all must now error with a useful message.
    #[test]
    fn allowed_versions_selector_rejects_malformed_non_wildcard_names() {
        // (raw_key, expected_error_position_hint)
        let cases: &[(&str, &str)] = &[
            // Spaces are not valid in npm names.
            ("foo bar", "peer name"),
            // Uppercase is rejected (npm requires lowercase).
            ("FooBar", "peer name"),
            ("@Scope/Foo", "peer name"),
            // Leading `.` and `_` are forbidden by npm.
            (".hidden", "peer name"),
            ("_private", "peer name"),
            // Special characters outside the allowed set.
            ("foo!bar", "peer name"),
            ("foo(bar)", "peer name"),
            ("foo'bar", "peer name"),
            ("foo+bar", "peer name"),
            // Same set of restrictions on the parent half of
            // `parent>peer` selectors.
            ("foo bar>react", "parent name"),
            ("FooBar>react", "parent name"),
            (".hidden>react", "parent name"),
            ("_private>react", "parent name"),
            // And on the peer half too.
            ("foo>react dom", "peer name"),
            ("foo>React", "peer name"),
            ("foo>.private", "peer name"),
        ];

        for (raw, expected_position) in cases {
            let err = AllowedVersionsSelector::parse(raw).unwrap_err();
            assert!(
                err.contains(expected_position),
                "expected {raw:?} error to mention {expected_position:?}, got: {err}"
            );
            assert!(
                err.contains("npm package name") || err.contains("must be a valid"),
                "expected {raw:?} error to point at the npm-naming contract, got: {err}"
            );
        }
    }

    /// Compile must error on malformed non-wildcard keys with a
    /// named error — same fail-closed posture as the wildcard case.
    /// Pins the contract so this class can't drift back into a
    /// silent no-op.
    #[test]
    fn compile_rejects_malformed_non_wildcard_allowed_versions_keys() {
        let mut allowed = HashMap::new();
        allowed.insert("foo bar".to_string(), "1".to_string());
        let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
        assert!(err.contains("\"foo bar\""), "must name the bad key: {err}");
        assert!(
            err.contains("npm package name") || err.contains("must be a valid"),
            "must point at the npm-naming contract: {err}"
        );
    }

    /// Real npm names accept the standard charset — verifies the new
    /// predicate doesn't over-reject valid packages.
    #[test]
    fn allowed_versions_selector_accepts_realistic_npm_names() {
        for valid in [
            "react",
            "react-dom",
            "react.js",
            "react_dom",
            "react-router-dom",
            "lodash.debounce",
            "0auth",
            "@scope/foo",
            "@scope/foo-bar.baz_qux",
            // parent>peer with both sides standard names
            "foo>react",
            "@scope/foo>react",
            "@scope/foo@^2>react-dom",
        ] {
            assert!(
                AllowedVersionsSelector::parse(valid).is_ok(),
                "expected {valid:?} to compile as a valid selector"
            );
        }
    }

    /// Scoped package names whose package half starts with `.` or
    /// `_` are valid per npm's spec — `validate-npm-package-name`
    /// runs the leading-`.`/`_` check against the WHOLE name, which
    /// for `@scope/_internal` starts with `@`. Must accept these
    /// across every selector position they can appear in: bare
    /// peer, peer half of `parent>peer`, parent name (with or
    /// without version range).
    #[test]
    fn allowed_versions_selector_accepts_scoped_names_with_dot_or_underscore_prefix() {
        for valid in [
            // Bare peer — package half starts with `_` / `.`
            "@scope/_internal",
            "@scope/.config",
            "@types/_helpers",
            // parent>peer with the leading-char form on each half
            "@scope/_internal>react",
            "@scope/.config>react",
            "foo>@scope/_internal",
            "foo>@scope/.config",
            // parent@range>peer with the leading-char form on the
            // parent's package half
            "@scope/_internal@^2>react",
            "@scope/.config@^1>react",
            // Both halves of parent>peer using scoped leading-char
            "@scope/_internal>@types/_helpers",
        ] {
            assert!(
                AllowedVersionsSelector::parse(valid).is_ok(),
                "expected {valid:?} to compile (npm allows scoped package half \
                 to start with `.` or `_`)"
            );
        }
    }

    /// Unscoped names with leading `.` or `_` MUST still reject —
    /// the loosening only applies to the package half of a scoped
    /// name. This pins the asymmetry so it can't drift back to a
    /// uniform restriction (or, worse, get flipped to uniform
    /// permissiveness).
    #[test]
    fn allowed_versions_selector_still_rejects_unscoped_dot_or_underscore_prefix() {
        for invalid in [
            // Bare unscoped names — leading `.` / `_` rejected.
            ".hidden",
            "_private",
            // Same in the parent half of `parent>peer`.
            ".hidden>react",
            "_private>react",
            // Same in the peer half of `parent>peer`.
            "foo>.private",
            "foo>_private",
            // Scope itself rejects leading `.`/`_` (only the
            // package half is permissive).
            "@.bad/foo",
            "@_bad/foo",
            "@.bad/foo>react",
        ] {
            let err = AllowedVersionsSelector::parse(invalid).unwrap_err();
            assert!(
                err.contains("npm package name") || err.contains("must be a valid"),
                "expected {invalid:?} to fail with a name-contract error, got: {err}"
            );
        }
    }

    /// `validate_allowed_versions_range` exposes `NpmRange::parse`
    /// to the migrate planner. Same parser the resolver uses at
    /// install time — a range that migrates clean must compile clean.
    #[test]
    fn validate_allowed_versions_range_uses_npm_range_grammar() {
        // NpmRange honors the broader npm-compat grammar — unions,
        // hyphen ranges, x-ranges, the empty / `*` "any version"
        // shorthand, etc. A range that migrates clean must compile
        // clean, so the surface is intentionally permissive.
        for valid in [
            "16 || 17 || 18",
            ">=16 <19",
            "^4.17.21",
            "1.x",
            "*",
            "16 - 18",
        ] {
            assert!(
                validate_allowed_versions_range(valid).is_ok(),
                "expected {valid:?} to validate as a widened range"
            );
        }
        // Genuinely malformed inputs reject. The npm grammar is
        // lenient, so the rejection surface is small — but it's not
        // empty, and it must report the typo with a useful error.
        for invalid in ["~~not-a-range", "not-a-version"] {
            let err_result = validate_allowed_versions_range(invalid);
            assert!(
                err_result.is_err(),
                "expected {invalid:?} to fail as a widened range, got: {err_result:?}"
            );
        }
    }
}
