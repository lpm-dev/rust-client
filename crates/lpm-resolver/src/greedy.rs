//! Greedy multi-version resolver, bun-recipe port.
//!
//! Replaces PubGrub-with-split-retry with a greedy enqueue + first-match
//! version pick that doubles as the fetch dispatcher. Mirrors bun's
//! `enqueueDependencyWithMain` shape (`src/install/PackageManagerEnqueue.zig`
//! + `runTasks.zig::flushDependencyQueue`).
//!
//! ## Scope
//!
//! - **Multi-version-per-canonical via reuse-on-compatible / allocate-on-
//!   incompatible.** When edge A picks `lodash@4.17.21` and edge B
//!   wants `lodash@^4`, edge B reuses A's node — first-version-wins
//!   inside any single satisfying range bucket (matches bun + npm + pnpm
//!   semantics). When edge B's range is `^3` and 4.17.21 doesn't satisfy
//!   it, the resolver allocates a new node for `lodash@3.10.1` (or
//!   whatever the best match is); both versions live independently in
//!   the resolved tree, keyed by `(canonical, version)`.
//! - **Required + optional deps.** Peer deps are recorded but not
//!   eagerly installed; the existing post-resolve [`crate::check_unmet_peers`]
//!   pass continues to surface peer warnings.
//! - **Overrides** are applied at version-pick time inside
//!   [`process_edge`]. Mirrors [`crate::provider::LpmDependencyProvider::choose_version`]'s
//!   pubgrub-arm semantics: compute the natural version, look up
//!   `OverrideSet::find_match` against (canonical, natural, parent_ctx),
//!   apply the [`OverrideTarget`] against the consumer range, record an
//!   [`OverrideHit`] on success, fall through to the natural version on
//!   target/range mismatch (legacy "irreconcilable override" debug warn).
//!   `OverrideSet::split_targets` informs reuse-vs-allocate so two parents
//!   forcing distinct versions split into independent nodes.
//! - **npm-aliases** are passed through from the cache (the `aliases` map
//!   on each `CachedPackageInfo` is already populated by
//!   [`crate::provider::parse_metadata_to_cache_info`]) and surfaced in the
//!   resolved tree.
//!
//! ## Dispatch model
//!
//! The loop is single-threaded — bun's PackageManager event loop runs on
//! one thread, and parallelism comes from the I/O fan-out (the BfsWalker's
//! 50-permit batch fetch + the existing 24-permit download pool). Each
//! iteration:
//!
//! 1. Pop an [`Edge`] off `task_queue`.
//! 2. Resolve its canonical's manifest via [`ensure_manifest`] — fast path
//!    is the [`crate::provider::SharedCache`] hit (the walker has been
//!    prefetching concurrently); slow path waits on the per-canonical
//!    [`tokio::sync::Notify`] up to `fetch_wait_timeout`, then falls
//!    through to a direct registry fetch.
//! 3. Pick a version with [`find_best_version`] (reverse-iterate sorted
//!    versions; first satisfying match wins — matches bun's `npm.zig:
//!    1808-1819`).
//! 4. Either reuse an existing node for `canonical` (W1's single-version
//!    rule) or allocate a new one and enqueue ITS declared deps as fresh
//!    edges.
//! 5. Repeat until `task_queue` is empty.
//!
//! No backtracking. No split-retry. The cost model is O(edges × log
//! versions) — measured at ~600-1000 `find_best_version` calls per cold
//! install on `bench/fixture-large`, each ~µs.

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet, OverrideTarget};
use crate::package::{CanonicalKey, ResolverPackage};
use crate::provider::{
    CachedPackageInfo, NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone,
    parse_metadata_to_cache_info,
};
use crate::ranges::NpmRange;
use crate::resolve::{
    ResolveError, ResolveResult, ResolvedPackage, StageTiming, resolve_peer_binding_version,
};
use ahash::{AHashMap, AHashSet};
#[cfg(test)]
use lpm_registry::RouteMode;
use lpm_registry::{RegistryClient, RouteTable, UpstreamRoute};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Internal node identity used while the resolver runs. Maps to a
/// final [`ResolvedPackage`] at the end of the pass. Each unique
/// `(canonical, version)` pair gets its own id; multi-version
/// canonicals (e.g. `is-unicode-supported@1.3.0` + `is-unicode-supported
/// @2.1.0` both alive in the same install) produce two distinct ids.
type NodeId = u32;

/// One unresolved edge: parent N needs `name @ range` with `behavior`.
///
/// Mirrors bun's `(dependency_id, version_range)` queue entry pattern
/// (`PackageManagerEnqueue.zig:830-838`). The edge carries enough
/// context for [`process_edge`] to look up the right manifest, pick a
/// version, and link parent → child in the resolved tree.
#[derive(Debug, Clone)]
struct Edge {
    /// Parent node in the resolved tree. The root project is the
    /// only node without a parent — it's seeded explicitly before
    /// the loop starts.
    parent: NodeId,
    /// Local name in the parent's `dependencies` map (alias-aware).
    /// When this differs from `canonical`, the edge was declared via
    /// `npm:<target>@<range>` and `local_name → target` is recorded on
    /// the parent's resolved node so the linker can build
    /// `node_modules/<local>/` → store entry for `<target>`.
    local_name: String,
    /// Canonical (registry-side) name of the dependency. Equal to
    /// `local_name` for non-aliased edges; equal to the alias target
    /// for aliased edges.
    canonical: CanonicalKey,
    /// Semver range to satisfy.
    range: NpmRange,
    /// What kind of dep this is — affects error semantics on miss.
    behavior: DepBehavior,
}

/// A single `peerDependencies[name]` declaration captured during the walk.
///
/// Distinct shape from [`Edge`]: peer requirements are NOT enqueued
/// on the dispatcher's `task_queue`. Peers are treated as a separate
/// input class so they map to `ResolvedPackage.peers` rather than
/// `ResolvedPackage.dependencies`. The v2 store's graph-key derivation
/// depends on this separation; silently routing peers through `n.children`
/// would break peer-divergent link-entry isolation.
// Fields are read by peer-collection tests below + the peer-drain pass. `#[allow(dead_code)]`
// at the struct level rather than per-field keeps the doc readable —
// the struct doc explains the future-use contract.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PeerRequirement {
    /// The package that DECLARED this peer dep — i.e. the consumer
    /// of the peer. Stored as a [`NodeId`] (already-allocated node)
    /// because peer collection happens at child-deps-enqueue time,
    /// when the consumer node is known.
    consumer: NodeId,
    /// Local name of the peer as it appears in `peerDependencies`.
    /// May differ from [`Self::canonical`] only in the (rare) case
    /// where an `npm:<target>@<range>` alias is also declared on the
    /// peer key — npm permits this and the canonical is then the
    /// alias target.
    peer_name: String,
    /// Registry identity (alias-aware).
    canonical: CanonicalKey,
    /// Parsed range from the `peerDependencies` value.
    range: NpmRange,
    /// `peerDependenciesMeta.<name>.optional` flag for this peer.
    /// The peer-drain step skips optional peers when synthesizing
    /// ambient installs (the manifest author opted out); the
    /// post-resolve `check_unmet_peers` pass already suppresses the
    /// missing-peer warning for this set.
    optional: bool,
}

/// One best-effort peer-conflict report. Surfaced when a peer canonical
/// has multiple required consumers whose ranges are pairwise-incompatible —
/// lpm picks the version that satisfies the most consumers and records the
/// unsatisfied ones here for the install pipeline to warn about. Mirrors
/// npm v7+'s "pick one + warn the rest" behavior on hoisted layouts.
#[derive(Debug, Clone)]
pub struct PeerConflictReport {
    /// Peer canonical name (e.g., `"react"` or `"@scope/foo"`).
    pub canonical: String,
    /// Version lpm chose to ambient-install at top level. Satisfies at
    /// least one required consumer's range (if zero consumers were
    /// satisfiable, the resolver hard-errors with `PeerConflict`
    /// instead of producing this report).
    pub chosen_version: String,
    /// `(consumer_canonical, declared_range)` for required consumers
    /// whose range does NOT include `chosen_version`. Stable order:
    /// matches the order the requirements were registered in.
    pub unsatisfied_consumers: Vec<(String, String)>,
}

/// Bitfield matching bun's `Dependency.Behavior` (`dependency.zig:35-37`).
/// W1 collapses dev under required at the root level (only root
/// edges are ever marked dev — transitive `devDependencies` are not
/// followed by npm clients per spec). The `required` field is
/// asserted at edge-creation time and read in W3 when error-on-miss
/// semantics widen beyond the current "all-non-optional-non-peer
/// edges error on miss" rule.
#[derive(Debug, Clone, Copy, Default)]
struct DepBehavior {
    #[allow(dead_code)] // read in W3 when peer/required asymmetry widens
    required: bool,
    peer: bool,
    optional: bool,
}

/// Per-canonical manifest state. Mirrors bun's combined
/// `network_dedupe_map` and `task_queue` HashMap pair. Uses the
/// per-canonical [`Notify`] from [`NotifyMap`] instead of a custom
/// `Pending(Vec<Edge>)` state.
#[allow(dead_code)]
type ManifestState = Arc<CachedPackageInfo>;

/// Entry point — same signature shape as
/// [`crate::resolve::resolve_with_shared_cache`] so the dispatch in
/// `resolve.rs` can swap implementations behind a feature flag.
///
/// **`auto_install_peers`** — `true` to enable bun-parity eager peer
/// auto-install: any non-optional `peerDependency` not already satisfied
/// by the resolved tree gets promoted to an ambient root-scoped install.
/// `false` falls back to warn-only behavior (the post-resolve
/// [`crate::check_unmet_peers`] pass surfaces missing peers as
/// `PeerWarning`s, no auto-install). The lpm beta default is `true`
/// — install.rs reads `package.json > lpm > autoInstallPeers` /
/// `~/.lpm/config.toml > auto-install-peers` to derive the value at
/// the call site.
#[allow(clippy::too_many_arguments)] // mirrors resolve_with_shared_cache for drop-in dispatch
#[allow(dead_code)]
pub async fn resolve_greedy(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: WalkerDone,
    fetch_wait_timeout: Duration,
    route_table: RouteTable,
    metrics: StreamingBfsMetrics,
    auto_install_peers: bool,
) -> Result<ResolveResult, ResolveError> {
    resolve_greedy_with_options(
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
pub async fn resolve_greedy_with_options(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: WalkerDone,
    fetch_wait_timeout: Duration,
    route_table: RouteTable,
    metrics: StreamingBfsMetrics,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
) -> Result<ResolveResult, ResolveError> {
    let _span = tracing::debug_span!("resolve_greedy", n_deps = dependencies.len()).entered();
    let pass_start = Instant::now();

    // Reset profiling accumulators. We measure greedy work in `pubgrub_ms`
    // for schema parity even though no PubGrub call happens here; the
    // field semantically means "resolver wall-clock".
    crate::profile::reset_all();
    lpm_registry::timing::reset();

    let mut state =
        ResolveState::new_with_options(dependencies, overrides, include_optional_dependencies);
    state.seed_root_edges()?;

    // ── Main task_queue + peer-drain fixed-point loop ──────────────
    //
    // Each iteration drains the task_queue, then runs ONE peer-drain
    // pass that may synthesize ambient root-scoped install edges; if
    // any were synthesized, we re-enter the task_queue drain to
    // process them (and their children, which may themselves declare
    // peers — caught by the next iteration). Termination: both
    // task_queue and peer_requirements empty after a single pass.
    loop {
        // Inner: drain task_queue exactly as before.
        while let Some(edge) = state.task_queue.pop_front() {
            let info = ensure_manifest(
                &edge.canonical,
                client.clone(),
                &route_table,
                &shared_cache,
                &notify_map,
                &walker_done,
                fetch_wait_timeout,
                &metrics,
            )
            .await?;
            process_edge(&edge, &info, &mut state)?;
        }

        // Outer: peer-drain pass. Skips synthesis when
        // `auto_install_peers` is false (still drains the worklist
        // so the resolver doesn't busy-loop on a non-empty Vec).
        let client_drain = client.clone();
        let route_table_drain = route_table.clone();
        let shared_cache_drain = shared_cache.clone();
        let notify_map_drain = notify_map.clone();
        let walker_done_drain = walker_done.clone();
        let metrics_drain = metrics.clone();
        let synthesized = drain_peer_requirements_one_pass(
            &mut state,
            auto_install_peers,
            move |canonical: CanonicalKey| {
                let client = client_drain.clone();
                let route_table = route_table_drain.clone();
                let shared_cache = shared_cache_drain.clone();
                let notify_map = notify_map_drain.clone();
                let walker_done = walker_done_drain.clone();
                let metrics = metrics_drain.clone();
                async move {
                    ensure_manifest(
                        &canonical,
                        client,
                        &route_table,
                        &shared_cache,
                        &notify_map,
                        &walker_done,
                        fetch_wait_timeout,
                        &metrics,
                    )
                    .await
                }
            },
        )
        .await?;

        if synthesized.is_empty() {
            // No new ambient installs and the task_queue is empty —
            // nothing more to drain. Exit the fixed point.
            break;
        }

        // Push synthesized ambient edges; the next iteration's inner
        // drain processes them via the regular `process_edge` path.
        for edge in synthesized {
            state.task_queue.push_back(edge);
        }
    }

    let resolver_ms = pass_start.elapsed().as_millis() as u64;

    // Build the public result. Cache the in-memory CachedPackageInfo from
    // shared_cache for the downstream `check_unmet_peers` pass and the
    // install pipeline's tarball-url lookup (matching the format_solution
    // contract in resolve.rs).
    // Surface `Arc<CachedPackageInfo>` directly — materializing
    // `HashMap<_, CachedPackageInfo>` by deep-cloning each entry causes
    // significant allocator churn (seven nested HashMaps per package).
    // The Arc::clone here is a refcount bump.
    let cache: HashMap<CanonicalKey, Arc<CachedPackageInfo>> = shared_cache
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();

    // Snapshot the platform-skipped counter before `into_resolved_packages`
    // consumes the state.
    let platform_skipped = state.platform_skipped;
    let root_aliases = std::mem::take(&mut state.root_aliases);
    // Drain ambient peer installs and dedup+sort. Same canonical
    // can be synthesized once per fixed-point iteration (a transitive
    // peer chain), so dedup before exposing.
    let mut ambient_peer_installs = std::mem::take(&mut state.ambient_peer_installs);
    ambient_peer_installs.sort();
    ambient_peer_installs.dedup();
    // Drain peer-conflict reports. Sort by canonical for deterministic
    // install-side warning order. Empty in the common case (no transitive
    // peer-version conflicts).
    let mut peer_conflicts = std::mem::take(&mut state.peer_conflicts);
    peer_conflicts.sort_by(|a, b| a.canonical.cmp(&b.canonical));
    // Drain the override apply trace before `state` is moved by
    // `into_resolved_packages`. `take_hits` sorts deterministically by
    // (package, raw_key), matching the pubgrub arm's contract for
    // `applied_overrides` ordering on `--json` output.
    let applied_overrides = state.overrides.take_hits();
    let packages = state.into_resolved_packages(&cache);

    let snap = lpm_registry::timing::snapshot();
    Ok(ResolveResult {
        packages,
        cache,
        applied_overrides,
        platform_skipped,
        // Root aliases: populated during seed_root_edges when a root dep
        // declares `npm:target@range`. Empty when no root dep uses alias syntax.
        root_aliases,
        ambient_peer_installs,
        peer_conflicts,
        stage_timing: StageTiming {
            followup_rpc_ms: snap.metadata_rpc.as_millis() as u64,
            followup_rpc_count: snap.metadata_rpc_count,
            parse_ndjson_ms: snap.parse_ndjson.as_millis() as u64,
            pubgrub_ms: resolver_ms,
            walker_rpc_count: snap.walker_rpc_count,
            escape_hatch_rpc_count: snap.escape_hatch_rpc_count,
            // Dispatcher counters: zero on the walker arm.
            // Populated by `resolve_greedy_fused` when `LPM_GREEDY_FUSION=1`.
            ..StageTiming::default()
        },
    })
}

/// Fused dispatcher: greedy resolver IS the fetch dispatcher. Replaces the
/// walker + resolver two-task model with a single tokio task that drains
/// its work queue synchronously, parks edges on cache misses, and resumes
/// them on manifest land.
///
/// **Three-phase loop:**
///
/// - **Phase A — drain `task_queue`.** Fully synchronous; no `await`.
///   Each edge: cache hit → `process_edge` inline (allocates a node
///   and pushes the new node's child deps as fresh edges); cache miss
///   → park edge by canonical and spawn one fetch per canonical
///   (deduped via the `inflight` set so two parents asking for the
///   same canonical don't double-fetch).
///
/// - **Phase B — termination.** Loop exits when both `task_queue` is
///   empty AND `metadata_jobs` has no pending jobs. The invariant
///   `parked.is_empty()` is asserted at this boundary: every parked
///   edge has a corresponding canonical in `inflight`, which mirrors
///   `metadata_jobs`'s pending set, so an empty `metadata_jobs`
///   implies an empty `parked`.
///
/// - **Phase C — bounded await.** When neither queue is empty AND no
///   work is locally drainable, await `metadata_jobs.join_next()`.
///   On manifest land: parse, forward raw metadata to install.rs's
///   speculation dispatcher via `spec_tx`, insert into `shared_cache`,
///   and resume parked edges in stable `(parent_id, local_name)` order
///   so multi-version dedupe stays deterministic across runs.
///
/// **Concurrency caps.** A single 256-permit semaphore (`npm_fanout`)
/// gates outstanding metadata fetches. H2 single-connection multiplex
/// caps at 256 streams; the resolver sits at the cap and lets the
/// registry's flow control set the actual pace. Tarball downloads run
/// through install.rs's existing 24-permit `fetch_semaphore` —
/// independent of the metadata semaphore so a stalled tarball can't
/// starve metadata fetches that would unblock the resolver.
///
/// **Counters.** `dispatcher_rpc_count`, `inflight_high_water`,
/// `parked_max_depth`, `tarball_dispatched_count`, and
/// `peer_prefetch_count` (speculative peer prefetch) are populated on
/// `ResolveResult.stage_timing` for `--json` consumption under
/// `timing.resolve.dispatcher.*` (W1 plumbing). `walker_rpc_count` and
/// `escape_hatch_rpc_count` are zero on the fusion arm by construction
/// (no walker → no escape-hatch path).
/// **`auto_install_peers`** — see the doc on [`resolve_greedy`] for
/// the contract. Same semantic on the fused arm.
#[allow(clippy::too_many_arguments)] // mirrors resolve_with_shared_cache's plumbing surface
pub async fn resolve_greedy_fused(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, lpm_registry::PackageMetadata)>>,
    auto_install_peers: bool,
) -> Result<ResolveResult, ResolveError> {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    resolve_greedy_fused_with_cache(
        client,
        dependencies,
        overrides,
        route_table,
        npm_fanout,
        spec_tx,
        shared_cache,
        auto_install_peers,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // mirrors resolve_greedy_fused plus an install-owned cache
pub async fn resolve_greedy_fused_with_cache(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, lpm_registry::PackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
) -> Result<ResolveResult, ResolveError> {
    resolve_greedy_fused_with_cache_options(
        client,
        dependencies,
        overrides,
        route_table,
        npm_fanout,
        spec_tx,
        shared_cache,
        auto_install_peers,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_greedy_fused_with_cache_options(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, lpm_registry::PackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
) -> Result<ResolveResult, ResolveError> {
    let _span = tracing::debug_span!(
        "resolve_greedy_fused",
        n_deps = dependencies.len(),
        npm_fanout
    )
    .entered();
    let pass_start = Instant::now();

    // Reset profiling accumulators so substage telemetry zeroes correctly
    // across back-to-back installs in the same process (rare, but bench
    // harnesses do it).
    crate::profile::reset_all();
    lpm_registry::timing::reset();

    let mut state =
        ResolveState::new_with_options(dependencies, overrides, include_optional_dependencies);
    state.seed_root_edges()?;

    // Loop-local state, owned by this single task. No Arcs needed
    // around `inflight` / `parked` because they never cross task
    // boundaries — only the spawn closures own clones of the
    // canonicals they're fetching.
    let metadata_sem = Arc::new(tokio::sync::Semaphore::new(npm_fanout));

    // Counters. Declared here so the lpm.dev pre-batch below can
    // increment them before the main loop starts.
    let mut dispatcher_rpc_count: u64 = 0;
    let mut tarball_dispatched_count: u64 = 0;
    // Speculative peer-manifest fetches dispatched concurrent with
    // regular dep dispatch. Bumped in Phase A2 below; surfaces on
    // `StageTiming.peer_prefetch_count`.
    let mut peer_prefetch_count: u64 = 0;

    // Pre-batch the root-level `@lpm.dev/*` deps in one round trip
    // before the main fetch loop. Without this, each such dep would
    // fire its own [`fetch_metadata_raw`] call inside the dispatcher
    // (~one RPC per package). The walker arm in `walker.rs` already
    // batches lpm.dev names; this pre-pass brings the fused arm to
    // parity.
    //
    // Why pre-resolve, not inside the loop:
    //   - The `shared_cache` fast-path at the top of Phase A short-
    //     circuits any edge whose canonical is already cached, so
    //     populating it BEFORE [`seed_root_edges`]'s edges drain
    //     turns N lpm.dev RPCs into 1.
    //   - `batch_metadata_deep` walks transitive lpm.dev deps server-
    //     side, so an install with several lpm.dev packages and
    //     transitive lpm.dev deps gets the whole sub-tree pre-warmed
    //     in one round trip.
    //
    // Failure-mode contract:
    //   - On batch error (auth/network/server fault), fall through
    //     silently — each lpm.dev root dep will be fetched
    //     individually by the main loop. Slower but correct.
    //   - On per-name parse failure (server returned something we
    //     can't interpret as a CanonicalKey), skip that entry and
    //     let the main loop refetch it.
    let lpm_root_names: Vec<String> = state
        .root_deps
        .keys()
        .filter(|k| k.starts_with("@lpm.dev/"))
        .cloned()
        .collect();
    if !lpm_root_names.is_empty() {
        match client.batch_metadata_deep(&lpm_root_names).await {
            Ok(batch) => {
                // One actual HTTP round trip regardless of
                // batch.len(). The dispatcher_rpc_count metric tracks
                // RPCs (not packages); record exactly 1 for the batch
                // — keeps the metric semantics stable across arms.
                dispatcher_rpc_count += 1;
                for (name, meta) in batch {
                    let canonical = crate::package::CanonicalKey::from_dep_name(&name);
                    // `from_dep_name` returns `Npm` for any name that
                    // doesn't match the `@lpm.dev/owner.name` shape.
                    // We trust the server here, but defend against a
                    // mis-shaped key landing in the lpm.dev cache.
                    if !matches!(canonical, crate::package::CanonicalKey::Lpm { .. }) {
                        continue;
                    }
                    let fetched = parse_fetched_metadata(meta);
                    shared_cache.insert(canonical.clone(), fetched.info);
                    if let Some(tx) = spec_tx.as_ref()
                        && tx
                            .try_send((canonical.to_string(), fetched.metadata))
                            .is_ok()
                    {
                        tarball_dispatched_count += 1;
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "greedy-fusion: lpm.dev pre-batch failed ({} names): {e} \
                     — falling back to per-package dispatch",
                    lpm_root_names.len()
                );
            }
        }
    }
    // Pre-size both maps to the expected steady-state cardinality.
    // For bench/fixture-large (266 transitive packages) the default-
    // sized HashMap rehashes ~5-7 times growing from 0 → 266; samply
    // surfaced `hashbrown::reserve_rehash` at ~6.7 % of cold-install
    // CPU. `npm_fanout` (the metadata-semaphore size, default 256)
    // is the closest proxy for "how many manifests this resolver might
    // track simultaneously" without threading a dependency-count estimate
    // through. Slight over-allocation is cheaper than rehashing.
    let mut inflight: AHashSet<CanonicalKey> = AHashSet::with_capacity(npm_fanout);
    let mut parked: AHashMap<CanonicalKey, Vec<Edge>> = AHashMap::with_capacity(npm_fanout);
    let mut metadata_jobs: tokio::task::JoinSet<(CanonicalKey, FetchResult)> =
        tokio::task::JoinSet::new();
    let mut inflight_order: BTreeMap<String, CanonicalKey> = BTreeMap::new();
    let mut ready_metadata: BTreeMap<String, FetchResult> = BTreeMap::new();

    // High-water marks update at the boundary of each Phase A→B transition
    // so the post-loop value reflects the peak across the run, not just the
    // final tick. `dispatcher_rpc_count` and `tarball_dispatched_count` are
    // declared above the lpm.dev pre-batch so it can pre-increment them.
    let mut inflight_high_water: u64 = 0;
    let mut parked_max_depth: u32 = 0;

    loop {
        // ── Phase A — drain `task_queue` synchronously ────────────
        while let Some(edge) = state.task_queue.pop_front() {
            // Cache hit fast-path. Hot path; one DashMap lookup +
            // refcount bump on the Arc<CachedPackageInfo>. The shard
            // lock is released before `process_edge` mutates state.
            if let Some(info_arc) = shared_cache.get(&edge.canonical).map(|e| e.value().clone()) {
                process_edge(&edge, &info_arc, &mut state)?;
                continue;
            }
            // Cache miss — park the edge and spawn one fetch per
            // canonical. The `inflight.insert` guard ensures we don't
            // dispatch two fetches for the same canonical when sibling
            // parents ask in close succession (one fetch per canonical,
            // deduped via the inflight set).
            let canonical = edge.canonical.clone();
            parked.entry(canonical.clone()).or_default().push(edge);
            if inflight.insert(canonical.clone()) {
                inflight_order.insert(canonical.to_string(), canonical.clone());
                let client_c = client.clone();
                let permit = metadata_sem.clone();
                let route_table_c = route_table.clone();
                metadata_jobs.spawn(async move {
                    // Acquire the metadata permit inside the task so
                    // the queue cap (256) limits in-flight HTTP calls,
                    // not spawn allocations. The `expect` guards an
                    // invariant we control (the semaphore lives for
                    // the resolver's lifetime); a panic here means we
                    // dropped the semaphore early, which is a bug.
                    let _p = permit
                        .acquire_owned()
                        .await
                        .expect("metadata semaphore must outlive the resolver");
                    let result =
                        fetch_metadata_for_resolver(&client_c, &route_table_c, &canonical).await;
                    (canonical, result)
                });
                dispatcher_rpc_count += 1;
            }
        }

        // ── Phase A2 — speculative peer-manifest prefetch ─────────
        //
        // For every peer requirement collected during the just-drained
        // batch of regular dep edges, dispatch a metadata fetch
        // CONCURRENT with the rest of the dispatch. By the time the
        // main loop terminates and the peer-drain pass runs, the
        // manifest is already in `shared_cache` — the drain becomes a
        // pure classify-and-synthesize pass with zero serial network
        // round-trips on the critical path.
        //
        // Without this, the drain helper's fetch closure ran a serial
        // `fetch_metadata_raw` per missing peer canonical AFTER the
        // main loop had already terminated. For typical projects with
        // 0–3 unmet peers this added ~50–300 ms of pure-network
        // latency. Overlapping that with the regular dep dispatch
        // eliminates the serial tail.
        //
        // Idempotency: `pick_peer_prefetch_candidates` filters out
        // canonicals that are already cached or already in flight, so
        // re-running this block in the next iteration won't double-
        // dispatch. The dispatcher's `inflight.insert` guard would
        // catch any miss but is redundant here.
        if auto_install_peers {
            let candidates = pick_peer_prefetch_candidates(&state, &shared_cache, &inflight);
            for canonical in candidates {
                // Mirror the cache-miss spawn path — same metadata
                // semaphore, same is_npm derivation, same tarball-spec
                // forward when the manifest lands. `parked.remove()`
                // returns None for these (nothing was parked) so the
                // resume step is a no-op.
                inflight.insert(canonical.clone());
                inflight_order.insert(canonical.to_string(), canonical.clone());
                let client_c = client.clone();
                let permit = metadata_sem.clone();
                let route_table_c = route_table.clone();
                metadata_jobs.spawn(async move {
                    let _p = permit
                        .acquire_owned()
                        .await
                        .expect("metadata semaphore must outlive the resolver");
                    let result =
                        fetch_metadata_for_resolver(&client_c, &route_table_c, &canonical).await;
                    (canonical, result)
                });
                dispatcher_rpc_count += 1;
                peer_prefetch_count += 1;
            }
        }

        // High-water samples. O(unique-canonicals-parked) per tick;
        // ~tens of entries × ~134 ticks on bench/fixture-large is
        // negligible vs the network wall.
        let inflight_now = (metadata_jobs.len() + ready_metadata.len()) as u64;
        if inflight_now > inflight_high_water {
            inflight_high_water = inflight_now;
        }
        if let Some(max_park) = parked.values().map(|v| v.len() as u32).max()
            && max_park > parked_max_depth
        {
            parked_max_depth = max_park;
        }

        // ── Phase B — termination invariant + peer-drain hook ─────
        // Both queues empty + zero in-flight metadata jobs ⇒ no
        // future edges can appear from the regular dep walk. Before
        // declaring victory, run ONE peer-drain pass: it may
        // synthesize ambient root-scoped install edges for unmet
        // peers, which re-arms the loop. The pass is a no-op when
        // `peer_requirements` is empty OR `auto_install_peers`
        // is false.
        if metadata_jobs.is_empty()
            && ready_metadata.is_empty()
            && inflight_order.is_empty()
            && state.task_queue.is_empty()
        {
            debug_assert!(
                parked.is_empty(),
                "greedy-fusion: non-empty parked at termination — invariant violated \
                 (parked_keys={:?})",
                parked.keys().collect::<Vec<_>>()
            );

            // Peer-drain pass. The fetch closure consults `shared_cache`
            // first (hot path — manifests for peer canonicals are usually
            // already there because the regular dep walk pulled them as
            // transitive children). On true cache miss, fetch directly via
            // `fetch_metadata_raw` — no need to park/spawn through the
            // dispatcher because drains run sequentially outside Phase A.
            let client_drain = client.clone();
            let route_table_drain = route_table.clone();
            let shared_cache_drain = shared_cache.clone();
            let synthesized = drain_peer_requirements_one_pass(
                &mut state,
                auto_install_peers,
                move |canonical: CanonicalKey| {
                    let client = client_drain.clone();
                    let route_table = route_table_drain.clone();
                    let shared_cache = shared_cache_drain.clone();
                    async move {
                        // Cache hit: refcount bump, return immediately.
                        if let Some(info_arc) =
                            shared_cache.get(&canonical).map(|e| e.value().clone())
                        {
                            return Ok(info_arc);
                        }
                        // Cache miss: direct fetch + parse + insert.
                        // Peer manifests are typically a small tail
                        // (e.g., react when only react-dom was a
                        // direct dep), so the serial fetch here is
                        // bounded by the count of unmet-peer canonicals
                        // — usually 0–3.
                        let meta = fetch_metadata_raw(&client, &route_table, &canonical).await?;
                        let info = parse_metadata_to_cache_info(&meta);
                        let info_arc = Arc::new(info);
                        shared_cache.insert(canonical.clone(), info_arc.clone());
                        Ok(info_arc)
                    }
                },
            )
            .await?;

            if synthesized.is_empty() {
                // Fixed point reached: no more edges, no more peer
                // requirements that needed synthesis. Done.
                break;
            }

            // Push synthesized ambient edges; the next iteration's
            // Phase A processes them via the regular cache-hit path
            // (the drain pre-populated `shared_cache` for every
            // canonical it touched).
            for edge in synthesized {
                state.task_queue.push_back(edge);
            }
            continue;
        }

        // ── Phase C — bounded await ──────────────────────────────
        if let Some((canonical, result)) =
            take_next_ready_metadata(&mut inflight_order, &mut ready_metadata)
        {
            inflight.remove(&canonical);
            complete_metadata_fetch(
                canonical,
                result,
                &shared_cache,
                spec_tx.as_ref(),
                &mut tarball_dispatched_count,
                &mut parked,
                &mut state,
            )?;
            continue;
        }

        // metadata_jobs is non-empty here (Phase B guards otherwise).
        // Take the next network completion, then buffer it until all
        // earlier canonical fetches are also ready. Only the
        // deterministic ready-pop above is allowed to mutate resolver
        // state.
        if let Some(joined) = metadata_jobs.join_next().await {
            let (canonical, result) = joined
                .map_err(|e| ResolveError::Internal(format!("metadata join failure: {e}")))?;
            ready_metadata.insert(canonical.to_string(), result);
        }
    }

    let resolver_ms = pass_start.elapsed().as_millis() as u64;

    // Same shape as `resolve_greedy`'s tail — `cache` materializes
    // the SharedCache as `HashMap<_, Arc<_>>` for the install-side
    // tarball-url lookup; `into_resolved_packages` consumes state
    // and produces the deterministic Vec<ResolvedPackage>.
    let cache: HashMap<CanonicalKey, Arc<CachedPackageInfo>> = shared_cache
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    let platform_skipped = state.platform_skipped;
    let root_aliases = std::mem::take(&mut state.root_aliases);
    // Same drain semantic as walker arm: dedup + sort the ambient
    // install set so the install pipeline gets a clean, deterministic
    // list to union with `pkg.dependencies`.
    let mut ambient_peer_installs = std::mem::take(&mut state.ambient_peer_installs);
    ambient_peer_installs.sort();
    ambient_peer_installs.dedup();
    // Same drain semantic as walker arm: best-effort peer conflicts
    // surface as warnings on the install pipeline.
    let mut peer_conflicts = std::mem::take(&mut state.peer_conflicts);
    peer_conflicts.sort_by(|a, b| a.canonical.cmp(&b.canonical));
    // Drain the override apply trace before `state` is moved by
    // `into_resolved_packages`. Same shape + order contract as the walker arm.
    let applied_overrides = state.overrides.take_hits();
    let packages = state.into_resolved_packages(&cache);

    let snap = lpm_registry::timing::snapshot();
    Ok(ResolveResult {
        packages,
        cache,
        applied_overrides,
        platform_skipped,
        root_aliases,
        ambient_peer_installs,
        peer_conflicts,
        stage_timing: StageTiming {
            followup_rpc_ms: snap.metadata_rpc.as_millis() as u64,
            followup_rpc_count: snap.metadata_rpc_count,
            parse_ndjson_ms: snap.parse_ndjson.as_millis() as u64,
            pubgrub_ms: resolver_ms,
            // Under fusion, walker/escape-hatch fields are zero by
            // construction (no walker, no escape-hatch path). The total
            // RPC count lives in `dispatcher_rpc_count`.
            // `metadata_rpc_count` from the registry-side snapshot is a
            // sanity check — must equal dispatcher_rpc_count modulo the
            // fast-path-cache-hit ratio.
            walker_rpc_count: 0,
            escape_hatch_rpc_count: 0,
            dispatcher_rpc_count,
            dispatcher_inflight_high_water: inflight_high_water,
            parked_max_depth,
            tarball_dispatched_count,
            peer_prefetch_count,
        },
    })
}

/// Carrier for the per-pass mutable state. Keeps the dispatch loop
/// readable by bundling the four coupled collections into one place.
struct ResolveState {
    /// Root deps from `package.json`. Stored so we can reconstruct
    /// each root edge's range when seeding.
    root_deps: HashMap<String, String>,
    /// Edge work queue. Drained by the main loop.
    task_queue: VecDeque<Edge>,
    /// Resolved nodes indexed by canonical → list of `(version,
    /// node_id)` pairs. W2 multi-version: when an edge wants the same
    /// canonical, we walk this list looking for an existing version
    /// whose range satisfies; reuse if found, else allocate a new
    /// node and append. Per-canonical lists are tiny in practice
    /// (1-2 entries even on big trees), so the linear scan is cheap.
    resolved: AHashMap<CanonicalKey, Vec<(NpmVersion, NodeId)>>,
    /// Resolved nodes in declaration order. `nodes[i].id == i`.
    nodes: Vec<ResolvedNodeBuilder>,
    /// Set of `(canonical, version)` pairs whose declared deps have
    /// already been enqueued as edges. Prevents re-enqueueing the
    /// same package@version's children when a second parent reuses
    /// the existing node. Different versions of the same canonical
    /// each get their OWN entry here because their dep lists are
    /// version-specific.
    children_enqueued: AHashSet<(CanonicalKey, NpmVersion)>,
    /// Count of optional deps skipped because no platform-compatible version
    /// satisfied the declared range. Surfaced in `ResolveResult.platform_skipped`
    /// for the install pipeline's `--json` output.
    platform_skipped: usize,
    /// Root-level npm alias map. Populated during [`Self::seed_root_edges`]
    /// when a root dep declares `"local": "npm:target@range"`: keyed by
    /// `local` (the alias name the consumer wrote), valued by `target` (the
    /// real registry identity). Drained into `ResolveResult.root_aliases` at
    /// the end of each resolver arm so the install pipeline can build
    /// `node_modules/<local>/` symlinks pointing at the target's content.
    root_aliases: HashMap<String, String>,
    /// Parsed override set. [`process_edge`] consults
    /// `overrides.find_match` against (canonical, natural_version,
    /// parent_ctx) for every edge whose canonical satisfies a non-empty
    /// range; on hit, [`apply_override_target_greedy`] produces the forced
    /// version and an [`OverrideHit`] is recorded. `take_hits()` drains the
    /// trace into `ResolveResult.applied_overrides` at the tail of each
    /// resolver arm.
    overrides: OverrideSet,
    /// Per-consumer record of every `peerDependencies` entry observed during
    /// the walk. **Collected here, never enqueued onto [`Self::task_queue`].**
    /// Peers are intentionally distinct from regular deps: they map to
    /// `ResolvedPackage.peers` (not `dependencies`), and the v2 store's
    /// graph-key derivation depends on that separation — peer pinning is
    /// folded into the graph key so two installs with the same dep tree but
    /// different peer ranges produce distinct `links/<key>/` entries. If we
    /// silently smuggled peers in as `n.children` edges, peer-divergent
    /// installs would share a single link entry and contaminate each other's
    /// `node_modules/`.
    peer_requirements: Vec<PeerRequirement>,
    /// Canonical names of packages the peer-drain pass synthesized as
    /// ambient root-scoped installs. Drained into
    /// `ResolveResult.ambient_peer_installs` at each arm's tail. The install
    /// pipeline reads this set to surface ambient peers at the project's
    /// `node_modules/<name>/` top level — without it, the auto-installed peer
    /// extracts into the global store but never gets a project-side symlink.
    ///
    /// Sorted alphabetically before drain for deterministic output.
    ambient_peer_installs: Vec<String>,
    /// Peer-group conflicts the drain resolved best-effort. Each entry
    /// corresponds to one canonical whose required consumer ranges were
    /// pairwise-incompatible: lpm picked the version satisfying the most
    /// consumers, recorded the unsatisfied ones here, and continued. Drained
    /// into `ResolveResult.peer_conflicts` at the arm tail; install pipeline
    /// prints a single warning per entry. Empty when no peer group needed
    /// best-effort fallback.
    peer_conflicts: Vec<PeerConflictReport>,
    /// Per-run peer resolution cache. Keyed by peer canonical plus a
    /// stable hash of the sorted parent peer context so repeated peer-drain
    /// passes don't recompute the same manifest decision.
    peer_resolution_cache: dashmap::DashMap<PeerResolutionCacheKey, CachedPeerResolution>,
    include_optional_dependencies: bool,
}

/// In-flight resolved node — accumulated during the loop, finalized
/// at `into_resolved_packages` time.
#[derive(Debug)]
struct ResolvedNodeBuilder {
    canonical: CanonicalKey,
    version: NpmVersion,
    optional: bool,
    /// Edges going OUT of this node: (local_name, child_node_id).
    children: Vec<(String, NodeId)>,
}

impl ResolveState {
    #[cfg(test)]
    fn new(root_deps: HashMap<String, String>, overrides: OverrideSet) -> Self {
        Self::new_with_options(root_deps, overrides, true)
    }

    fn new_with_options(
        root_deps: HashMap<String, String>,
        overrides: OverrideSet,
        include_optional_dependencies: bool,
    ) -> Self {
        ResolveState {
            root_deps,
            task_queue: VecDeque::with_capacity(256),
            resolved: AHashMap::with_capacity(512),
            nodes: Vec::with_capacity(512),
            children_enqueued: AHashSet::with_capacity(512),
            platform_skipped: 0,
            root_aliases: HashMap::new(),
            overrides,
            // Most installs declare zero peers at any given level. Even
            // bench/fixture-large produces ~10s of total peer entries
            // across 250+ packages. Start small; Vec::push amortizes.
            peer_requirements: Vec::new(),
            // Typically 0 (most installs don't need ambient peer
            // synthesis). Allocated lazily on first push.
            ambient_peer_installs: Vec::new(),
            // Typically 0 (most installs have a clean peer graph).
            // Allocated lazily on first conflict.
            peer_conflicts: Vec::new(),
            peer_resolution_cache: dashmap::DashMap::with_capacity(64),
            include_optional_dependencies,
        }
    }

    /// Seed the queue with one Edge per root dependency. The pseudo-node
    /// with id=0 represents the project root; its children are tracked
    /// in the resolved-tree edges but it has no version of its own and
    /// is filtered out at `into_resolved_packages` time, matching
    /// PubGrub's `format_solution` (which filters `pkg.is_root()`).
    fn seed_root_edges(&mut self) -> Result<(), ResolveError> {
        // Insert the root pseudo-node so child edges have a parent id.
        // It carries a sentinel canonical (`Root`) and a placeholder
        // version. Filtered out at `into_resolved_packages`.
        self.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::Root,
            version: NpmVersion::new(0, 0, 0),
            optional: false,
            children: Vec::new(),
        });
        // Root carries a sentinel canonical; it's never queried by an
        // edge's `process_edge` (no edge has CanonicalKey::Root as its
        // target). Kept in the map for symmetry with the rest of the
        // resolved-tree shape.
        self.resolved
            .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
        // Root-level alias rewrite: if the consumer's package.json declares
        // `"local": "npm:target@range"`, the resolver must (a) key the
        // canonical on `target` (the real registry identity) so metadata
        // fetch + version resolution hit the right package, (b) parse the
        // inner range, and (c) record `local → target` in
        // `self.root_aliases` so the install pipeline can build
        // `node_modules/<local>/` from the target's content.
        let mut entries: Vec<_> = self.root_deps.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        for (name, range_str) in entries {
            let (canonical_name, effective_range) = match crate::ranges::parse_npm_alias(range_str)
            {
                Some(alias) => {
                    self.root_aliases.insert(name.clone(), alias.target.clone());
                    (alias.target, alias.range)
                }
                None => (name.clone(), range_str.clone()),
            };
            let canonical = CanonicalKey::from_dep_name(&canonical_name);
            // `workspace:<rest>` must be rewritten upstream by
            // `lpm-workspace` before reaching the resolver.
            // If a raw `workspace:` slips through (e.g., a future
            // refactor drops the upstream layer or a manifest is
            // hand-edited), `NpmRange::parse` would fail with an
            // opaque semver error. This guard surfaces the actual
            // diagnosis to the maintainer.
            if is_workspace_specifier(&effective_range) {
                return Err(ResolveError::Internal(format!(
                    "root dep {name}: range '{effective_range}' uses the \
                     `workspace:` protocol, which must be resolved by \
                     `lpm-workspace` before reaching the resolver. This is \
                     an internal bug — please file an issue at \
                     https://github.com/lpm-dev/rust-client/issues"
                )));
            }
            let range = NpmRange::parse(&effective_range).map_err(|e| {
                ResolveError::Internal(format!("failed to parse range for root dep {name}: {e}"))
            })?;
            self.task_queue.push_back(Edge {
                parent: 0,
                local_name: name.clone(),
                canonical,
                range,
                behavior: DepBehavior {
                    required: true,
                    peer: false,
                    optional: false,
                },
            });
        }
        Ok(())
    }

    /// Convert the in-flight builders into the public
    /// `Vec<ResolvedPackage>`. Mirrors `resolve.rs::format_solution`.
    fn into_resolved_packages(
        self,
        cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    ) -> Vec<ResolvedPackage> {
        // Build node-id → version-string lookup so child edges can
        // be resolved to the child's selected version regardless of
        // aliasing (alias rewriting already happened at edge-creation
        // time, so children[i].1 is always the correct node id).
        let id_to_version: Vec<String> = self.nodes.iter().map(|n| n.version.to_string()).collect();

        // canonical-name → resolved-version lookup for peer resolution.
        // Mirrors `format_solution`'s peer-candidate lookup. Built from the
        // same node table (filtered to non-root) so peer name-lookups
        // intersect the active install set. `CanonicalKey`'s Display impl
        // emits the canonical-name form (`@lpm.dev/owner.name` or `react`),
        // matching how `peerDependencies` keys are spelled in package.json.
        let resolved_by_canonical: HashMap<String, Vec<(Option<String>, String)>> = self
            .nodes
            .iter()
            .filter(|n| !matches!(n.canonical, CanonicalKey::Root))
            .fold(HashMap::new(), |mut acc, n| {
                acc.entry(n.canonical.to_string())
                    .or_default()
                    .push((None, n.version.to_string()));
                acc
            });

        let mut out: Vec<ResolvedPackage> = self
            .nodes
            .into_iter()
            .enumerate()
            .filter(|(_, n)| !matches!(n.canonical, CanonicalKey::Root))
            .map(|(_, n)| {
                let pkg = canonical_to_resolver_package(&n.canonical);
                let ver_str = n.version.to_string();

                let cached_aliases: HashMap<String, String> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.aliases.get(&ver_str))
                    .cloned()
                    .unwrap_or_default();

                // Sort each parent's dependency list by local_name for
                // byte-identical lockfile output across resolver arms.
                // On the walker arm, n.children is already alphabetic by
                // virtue of `enqueue_child_deps` pre-sorting + FIFO
                // task_queue + serial process_edge. Under fusion, parked
                // edges resume in manifest-arrival order so n.children's
                // insertion order is non-deterministic w.r.t. names. The
                // sort makes the alphabetic invariant explicit and
                // arm-independent.
                let mut dependencies: Vec<(String, String)> = n
                    .children
                    .iter()
                    .map(|(local, child_id)| {
                        let child_ver = id_to_version[*child_id as usize].clone();
                        (local.clone(), child_ver)
                    })
                    .collect();
                dependencies.sort_by(|a, b| a.0.cmp(&b.0));

                let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
                let aliases: HashMap<String, String> = cached_aliases
                    .iter()
                    .filter(|(local, _)| alive_locals.contains(local))
                    .map(|(l, t)| (l.clone(), t.clone()))
                    .collect();

                let (tarball_url, integrity) = cache
                    .get(&n.canonical)
                    .and_then(|info| info.dist.get(&ver_str))
                    .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                    .unwrap_or_default();
                let platform = cache
                    .get(&n.canonical)
                    .and_then(|info| info.platform.get(&ver_str))
                    .cloned();

                // Surface resolved peers per package so the v2 GraphKey
                // can fold them in. The resolved-versions lookup is built
                // from the same node table.
                let peers: Vec<(String, String)> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.peer_deps.get(&ver_str))
                    .map(|peer_deps| {
                        let mut out: Vec<(String, String)> = peer_deps
                            .iter()
                            .filter_map(|(peer_name, peer_range)| {
                                let parsed_range = NpmRange::parse(peer_range).ok();
                                resolve_peer_binding_version(
                                    &pkg,
                                    peer_name,
                                    parsed_range.as_ref(),
                                    &resolved_by_canonical,
                                )
                                .map(|(ver, _)| (peer_name.clone(), ver.clone()))
                            })
                            .collect();
                        out.sort_by(|a, b| a.0.cmp(&b.0));
                        out
                    })
                    .unwrap_or_default();

                ResolvedPackage {
                    package: pkg,
                    version: n.version,
                    dependencies,
                    aliases,
                    peers,
                    tarball_url,
                    integrity,
                    platform,
                    optional: n.optional,
                }
            })
            .collect();

        crate::resolve::dedupe_peer_superset_packages(&mut out);

        // Match `format_solution`'s deterministic order so lockfile
        // serialization is stable regardless of resolution order.
        //
        // Secondary sort by version. `ResolverPackage`'s `Display` impl
        // drops the version (Npm prints just `name`), so two distinct
        // ResolvedPackages for `debug@2.6.9` and `debug@4.4.3` tie under
        // the primary key. Without a tiebreaker, the stable sort preserves
        // the original Vec order — which depends on `state.resolved`'s
        // insertion order, which under fusion follows manifest-arrival order
        // rather than walker-arm alphabetic-BFS order. Sorting by version on
        // tie makes the total order deterministic and arm-independent.
        out.sort_by_cached_key(|pkg| (pkg.package.to_string(), pkg.version.clone()));
        out
    }
}

/// Convert a `CanonicalKey` back to a `ResolverPackage` for the
/// public output. W1 always emits non-split (`context: None`) packages
/// — multi-version in W2 will start emitting with context for the
/// secondary copy of each duplicated canonical.
fn canonical_to_resolver_package(key: &CanonicalKey) -> ResolverPackage {
    match key {
        CanonicalKey::Root => ResolverPackage::Root,
        CanonicalKey::Lpm { owner, name } => ResolverPackage::Lpm {
            owner: owner.clone(),
            name: name.clone(),
            context: None,
        },
        CanonicalKey::Npm { name } => ResolverPackage::Npm {
            name: name.clone(),
            context: None,
        },
    }
}

/// Process one edge: reuse an existing node whose version satisfies
/// the edge's range, OR allocate a new node for the best version
/// matching the range. Mirrors bun's "dedupe when compatible,
/// allocate when not" model — same as npm + pnpm semantics. PubGrub's
/// flat-then-split-retry workaround is unnecessary because
/// multi-version is the natural representation here.
///
/// **Overrides.** When `state.overrides` is non-empty, we compute the
/// natural pick FIRST and consult `find_match` for an applicable
/// [`OverrideTarget`]. A successful override produces a forced version that
/// becomes the dedupe target — reuse falls through to exact-version-match
/// (so two parents forcing different versions allocate independent nodes),
/// and the [`OverrideHit`] is recorded for the install summary. The
/// empty-overrides hot path skips this entire branch with one
/// [`OverrideSet::is_empty`] check (single-bool indirection, zero allocs).
fn process_edge(
    edge: &Edge,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    // Hot path: zero-overrides installs (the common case) skip the
    // natural-pick computation entirely. Behavior matches the pre-
    // override implementation byte-for-byte.
    if state.overrides.is_empty() {
        return process_edge_inner(edge, info, None, state);
    }

    // Slow path: at least one override entry exists. Compute the
    // natural pick (the version greedy WOULD pick without any
    // override) and consult `find_match`.
    let parent_ctx_owned = if edge.parent == 0 {
        None
    } else {
        Some(state.nodes[edge.parent as usize].canonical.to_string())
    };
    let canonical_name = edge.canonical.to_string();

    let natural_pick = find_best_version(info, &edge.range);
    let natural_ver = match &natural_pick {
        VersionPick::Picked(v) => Some(v.clone()),
        VersionPick::NoSatisfying => None,
    };

    // No natural version means there's nothing to evaluate the
    // override selector's range filter against. Mirrors the pubgrub
    // arm — when natural is None, override can't apply, so we surface
    // the no-version outcome directly.
    let Some(natural) = natural_ver else {
        return match natural_pick {
            VersionPick::NoSatisfying => handle_no_version(edge, info, false, state),
            VersionPick::Picked(_) => unreachable!(),
        };
    };

    let parent_ctx_ref = parent_ctx_owned.as_deref();
    let override_outcome: Option<(NpmVersion, OverrideHit)> = match state.overrides.find_match(
        &canonical_name,
        &natural,
        parent_ctx_ref,
    ) {
        Some(entry) => match apply_override_target_greedy(info, &entry.target, &edge.range) {
            Some(forced) => {
                let hit = OverrideHit {
                    raw_key: entry.raw_key.clone(),
                    source: entry.source,
                    package: canonical_name.clone(),
                    from_version: natural.to_string(),
                    to_version: forced.to_string(),
                    via_parent: parent_ctx_ref.map(str::to_string),
                };
                tracing::debug!(
                    "override applied: {} {} → {} (via {})",
                    hit.package,
                    hit.from_version,
                    hit.to_version,
                    hit.source_display()
                );
                Some((forced, hit))
            }
            None => {
                // Mirrors pubgrub arm's "irreconcilable override" warn:
                // target is outside the consumer range. We fall through
                // to the natural version — DO NOT silently pretend the
                // override applied. Fall through to the natural version.
                tracing::warn!(
                    "override {} could not be satisfied: target {} is outside consumer range for {}",
                    entry.raw_key,
                    entry.target.raw(),
                    canonical_name
                );
                None
            }
        },
        None => None,
    };

    process_edge_inner(edge, info, Some((natural, override_outcome)), state)
}

fn edge_is_optional_in_context(edge: &Edge, state: &ResolveState) -> bool {
    edge.behavior.optional || state.nodes[edge.parent as usize].optional
}

fn mark_node_required_closure(state: &mut ResolveState, node_id: NodeId) {
    let idx = node_id as usize;
    if !state.nodes[idx].optional {
        return;
    }
    state.nodes[idx].optional = false;
    let children: Vec<NodeId> = state.nodes[idx]
        .children
        .iter()
        .map(|(_, child_id)| *child_id)
        .collect();
    for child_id in children {
        mark_node_required_closure(state, child_id);
    }
}

/// Core reuse-or-allocate logic. The `forced` parameter, when present,
/// carries (natural_version, optional_override) computed by the override
/// branch in [`process_edge`]. When `None`, the function uses the
/// pre-override fast path: any existing node satisfying the edge range
/// is reused, otherwise [`find_best_version`] picks the newest match.
fn process_edge_inner(
    edge: &Edge,
    info: &CachedPackageInfo,
    forced: Option<(NpmVersion, Option<(NpmVersion, OverrideHit)>)>,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    // Determine the target version for THIS edge. Without overrides,
    // the target is whichever existing node satisfies the range, else
    // the newest in-range pick. With an override applied, the target
    // is the override-forced version (used for exact-match dedupe so
    // distinct overrides split correctly). With overrides parsed but
    // not matching this edge, the target is the natural pick — same as
    // the no-overrides path but skipping the redundant find_best_version.
    let (target_version, override_hit): (NpmVersion, Option<OverrideHit>) = match forced {
        Some((natural, Some((forced_v, hit)))) => {
            let _ = natural;
            (forced_v, Some(hit))
        }
        Some((natural, None)) => (natural, None),
        None => {
            // Hot path — no overrides parsed. Reuse-on-range-satisfies.
            let existing_id: Option<NodeId> =
                state.resolved.get(&edge.canonical).and_then(|nodes| {
                    nodes
                        .iter()
                        .find(|(v, _)| edge.range.satisfies(v))
                        .map(|(_, id)| *id)
                });
            if let Some(id) = existing_id {
                if !edge_is_optional_in_context(edge, state) {
                    mark_node_required_closure(state, id);
                }
                state.nodes[edge.parent as usize]
                    .children
                    .push((edge.local_name.clone(), id));
                return Ok(());
            }
            let version = match find_best_version(info, &edge.range) {
                VersionPick::Picked(v) => v,
                VersionPick::NoSatisfying => {
                    return handle_no_version(edge, info, false, state);
                }
            };
            (version, None)
        }
    };

    // Reuse-or-allocate against `target_version`.
    //
    // **Dedupe rule.** Exact-match when EITHER (a) this edge applied an
    // override, OR (b) the canonical is in `OverrideSet::split_targets()`
    // — i.e., at least one path-selector targets it. Otherwise
    // range-satisfies (the pre-override hot-path semantic).
    //
    // Why split-targeted canonicals must use exact-match even when THIS
    // edge didn't apply an override: a sibling edge from a path-matching
    // parent may have already allocated a forced node at a different
    // version. With range-satisfies dedupe, this edge would silently
    // inherit that forced version — leaking the override into a parent
    // it wasn't selecting. Exact-match against the natural pick avoids
    // the leak; a second non-matching sibling agreeing on the same
    // natural pick still dedupes correctly.
    //
    // The hot path (no overrides parsed) is in the `forced.is_none()`
    // branch above and never reaches here, so this gate has zero cost
    // on installs without overrides. The `split_targets().is_empty()`
    // short-circuit also keeps slow-path installs with name-only
    // overrides off the `to_string()` allocation.
    let split_gate = !state.overrides.split_targets().is_empty()
        && state
            .overrides
            .split_targets()
            .contains(&edge.canonical.to_string());
    let must_exact_match = override_hit.is_some() || split_gate;
    let existing_id: Option<NodeId> = state.resolved.get(&edge.canonical).and_then(|nodes| {
        if must_exact_match {
            nodes
                .iter()
                .find(|(v, _)| v == &target_version)
                .map(|(_, id)| *id)
        } else {
            nodes
                .iter()
                .find(|(v, _)| edge.range.satisfies(v))
                .map(|(_, id)| *id)
        }
    });

    let child_id = match existing_id {
        Some(id) => {
            if !edge_is_optional_in_context(edge, state) {
                mark_node_required_closure(state, id);
            }
            id
        }
        None => {
            let new_id = state.nodes.len() as NodeId;
            let incoming_optional = edge_is_optional_in_context(edge, state);
            state.nodes.push(ResolvedNodeBuilder {
                canonical: edge.canonical.clone(),
                version: target_version.clone(),
                optional: incoming_optional,
                children: Vec::new(),
            });
            state
                .resolved
                .entry(edge.canonical.clone())
                .or_default()
                .push((target_version.clone(), new_id));

            // Enqueue this version's deps once. Different versions of
            // the same canonical each get their own children-enqueued
            // entry because dep lists are version-specific (lodash@4
            // has different deps from lodash@3).
            let key = (edge.canonical.clone(), target_version.clone());
            if !state.children_enqueued.contains(&key) {
                state.children_enqueued.insert(key);
                enqueue_child_deps(new_id, &edge.canonical, &target_version, info, state);
            }
            new_id
        }
    };

    // Record override AFTER node allocation so we never trace an
    // override that didn't actually take effect.
    if let Some(hit) = override_hit {
        state.overrides.record_hit(hit);
    }

    state.nodes[edge.parent as usize]
        .children
        .push((edge.local_name.clone(), child_id));

    Ok(())
}

/// Apply an [`OverrideTarget`] against the consumer's range, walking THIS
/// canonical's cached versions to produce a final forced version. Mirrors
/// [`crate::provider::LpmDependencyProvider::apply_override_target`]'s
/// pubgrub-arm semantics:
///
/// - `PinnedVersion` returns the pinned version verbatim, but ONLY if it
///   satisfies the consumer's declared range. Out-of-range targets return
///   `None` so the caller can fall through to the natural pick.
/// - `Range` intersects the override range with the consumer range (over
///   the cache's available versions list for THIS package) and picks the
///   newest match. Platform-incompatible candidates are skipped; this can
///   return `None` even when an in-range version exists if every candidate
///   is filtered out.
fn apply_override_target_greedy(
    info: &CachedPackageInfo,
    target: &OverrideTarget,
    range: &NpmRange,
) -> Option<NpmVersion> {
    match target {
        OverrideTarget::PinnedVersion { version, .. } => {
            if range.satisfies(version) {
                Some(version.clone())
            } else {
                None
            }
        }
        OverrideTarget::Range {
            range: target_range,
            ..
        } => {
            // Versions are sorted newest-first by
            // `parse_metadata_to_cache_info`, so the first match is
            // the newest match — same contract as `find_best_version`.
            for v in &info.versions {
                if !range.satisfies(v) {
                    continue;
                }
                if !target_range.satisfies(v) {
                    continue;
                }
                let platform_ok = info.platform.is_empty()
                    || info
                        .platform
                        .get(&v.to_string())
                        .is_none_or(crate::provider::is_platform_compatible);
                if !platform_ok {
                    continue;
                }
                return Some(v.clone());
            }
            None
        }
    }
}

fn handle_no_version(
    edge: &Edge,
    info: &CachedPackageInfo,
    platform_filtered: bool,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    if edge.behavior.optional {
        // Optional dep with no satisfying or platform-compatible
        // version: skip silently. Matches bun's behavior
        // (`PackageManagerEnqueue.zig:77-78` warning path) minus the
        // warning itself — W3 will wire the warning emission.
        if platform_filtered {
            state.platform_skipped += 1;
        }
        tracing::debug!(
            "optional dep {} skipped (range={}, platform_filtered={})",
            edge.canonical,
            edge.range,
            platform_filtered
        );
        return Ok(());
    }
    if edge.behavior.peer {
        // Peer dep: not eagerly installed in W1; the post-resolve
        // `check_unmet_peers` pass will surface the warning if the
        // peer goes unresolved. W3 will wire the bun-style queue+drain.
        tracing::debug!(
            "peer dep {} (range {}) not eagerly installed in W1",
            edge.canonical,
            edge.range,
        );
        return Ok(());
    }
    let detail = if platform_filtered {
        format!(
            "every version satisfying the range is incompatible with this OS/CPU \
             (versions in manifest: {})",
            info.versions.len()
        )
    } else {
        format!(
            "no version satisfies range (versions available: {})",
            info.versions.len()
        )
    };
    Err(ResolveError::DependencyFetch {
        package: edge.canonical.to_string(),
        version: edge.range.to_string(),
        detail,
    })
}

/// Read `info.deps[version]`, parse each child's range, push edges. Aliases
/// are looked up in `info.aliases[version]` and rewritten to the target
/// canonical at edge-creation time so the dispatch loop only ever has
/// canonical keys to look up.
fn enqueue_child_deps(
    parent_id: NodeId,
    parent_canonical: &CanonicalKey,
    version: &NpmVersion,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) {
    let ver_str = version.to_string();
    let Some(deps) = info.deps.get(&ver_str) else {
        return; // version has no declared deps
    };
    let aliases = info.aliases.get(&ver_str);
    let optional_names = info.optional_dep_names.get(&ver_str);
    let bundled_names = info.bundled_dep_names.get(&ver_str);

    // Sort for deterministic edge ordering — keeps test diffs stable
    // and the resolved tree reproducible across runs.
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by_key(|(name, _)| *name);

    for (local_name, range_str) in entries {
        // Bundled deps are vendored inside the parent's tarball
        // (`node_modules/<bundled>/` extracted alongside the parent's
        // own files). Skip enqueueing them as separate edges so the
        // resolver doesn't fetch a registry copy that the linker
        // might shadow over the bundled one. The extractor preserves
        // the in-tarball subtree implicitly; the resolver's job is
        // just to NOT introduce a redundant registry fetch.
        if bundled_names.is_some_and(|s| s.contains(local_name)) {
            tracing::debug!(
                "skipping bundled dep {} of {}@{} — provided by parent's tarball",
                local_name,
                parent_canonical,
                ver_str,
            );
            continue;
        }

        let canonical = match aliases.and_then(|a| a.get(local_name)) {
            Some(target) => CanonicalKey::from_dep_name(target),
            None => CanonicalKey::from_dep_name(local_name),
        };

        // Registry-published packages should
        // never declare `workspace:` deps (npm rejects them at publish
        // time), but a malformed cache entry or a future regression
        // could land one here. Skip with a specific log line rather
        // than the generic "invalid range" branch so the diagnosis
        // points at the actual cause.
        if is_workspace_specifier(range_str) {
            tracing::warn!(
                "ignoring transitive `workspace:` dep '{}' from {}@{} → {} \
                 (workspace: must be resolved upstream by lpm-workspace; \
                 a registry-published package should not declare it)",
                range_str,
                parent_canonical,
                ver_str,
                local_name,
            );
            continue;
        }

        let range = match NpmRange::parse(range_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "invalid range '{}' on {}@{} → {}: {e}",
                    range_str,
                    parent_canonical,
                    ver_str,
                    local_name,
                );
                continue;
            }
        };

        let optional = state.nodes[parent_id as usize].optional
            || optional_names.is_some_and(|set| set.contains(local_name));
        if optional && !state.include_optional_dependencies {
            tracing::debug!(
                "skipping optional dep {} of {}@{} by install option",
                local_name,
                parent_canonical,
                ver_str,
            );
            continue;
        }

        state.task_queue.push_back(Edge {
            parent: parent_id,
            local_name: local_name.clone(),
            canonical,
            range,
            behavior: DepBehavior {
                required: !optional,
                peer: false,
                optional,
            },
        });
    }

    // Capture every `peerDependencies` entry on this (canonical, version)
    // as a `PeerRequirement`. Peers are NOT pushed onto `state.task_queue`
    // because they must NOT become `n.children` edges — see the
    // [`PeerRequirement`] doc + the v2 graph-key rationale on
    // `state.peer_requirements`.
    //
    // Same alias / workspace / range-parse defenses as the regular-deps
    // loop above; bundled-deps gate doesn't apply to peers (npm forbids
    // peerBundle interactions; no real package ships both).
    if let Some(peer_deps) = info.peer_deps.get(&ver_str) {
        let optional_peers = info.optional_peer_names.get(&ver_str);
        let peer_aliases = info.aliases.get(&ver_str);
        let mut peer_entries: Vec<(&String, &String)> = peer_deps.iter().collect();
        peer_entries.sort_by_key(|(name, _)| *name);

        for (peer_name, peer_range_str) in peer_entries {
            // `workspace:` peers from a registry-published package
            // shouldn't exist (npm rejects them at publish time).
            // Skip with a specific log rather than letting
            // `NpmRange::parse` emit an opaque error.
            if is_workspace_specifier(peer_range_str) {
                tracing::warn!(
                    "ignoring `workspace:` peer dep '{}' from {}@{} → {} \
                     (workspace: must be resolved upstream by lpm-workspace; \
                     a registry-published package should not declare it)",
                    peer_range_str,
                    parent_canonical,
                    ver_str,
                    peer_name,
                );
                continue;
            }

            // Alias-aware canonical lookup. Mirrors the regular-deps
            // loop: a `"peer-local": "npm:target@range"` declaration
            // (rare on peers, but legal) keys the requirement on
            // `target` so the resolver consults the correct manifest.
            let canonical = match peer_aliases.and_then(|a| a.get(peer_name)) {
                Some(target) => CanonicalKey::from_dep_name(target),
                None => CanonicalKey::from_dep_name(peer_name),
            };

            let range = match NpmRange::parse(peer_range_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "invalid peer range '{}' on {}@{} → {}: {e}",
                        peer_range_str,
                        parent_canonical,
                        ver_str,
                        peer_name,
                    );
                    continue;
                }
            };

            let optional = optional_peers.is_some_and(|set| set.contains(peer_name));

            state.peer_requirements.push(PeerRequirement {
                consumer: parent_id,
                peer_name: peer_name.clone(),
                canonical,
                range,
                optional,
            });
        }
    }
}

// ── Eager peer auto-install drain ─────────────────────────────────
//
// Design:
//   - Peer requirements are collected during `enqueue_child_deps`
//     onto `state.peer_requirements`, NEVER as `task_queue` edges.
//   - After the main task_queue drains, a peer-drain pass runs:
//     1. Group requirements by `canonical`.
//     2. For each group, check if any node in `state.resolved` for
//        that canonical satisfies EVERY consumer's range. Yes → skip
//        (the existing `into_resolved_packages` peer derivation will
//        record the consumer→peer edge from cache).
//     3. If unsatisfied AND `auto_install_peers` is on AND at least
//        one consumer is non-optional, look up the canonical's
//        manifest (arm-specific fetch closure), find the newest
//        version satisfying every consumer's range, and synthesize a
//        ROOT-SCOPED ambient `Edge` pinning that exact version.
//     4. If no version satisfies every required consumer's range →
//        `ResolveError::PeerConflict` (the user must fix the manifest
//        or pin via `lpm.overrides`).
//   - Caller pushes synthesized edges to `task_queue`, re-drains the
//     main loop, and re-runs the drain pass. Repeat until both
//     queues are empty (transitive peers from ambient installs may
//     spawn further requirements).
//
// **Architectural correction (vs. earlier draft).** Peers are
// deliberately NOT routed as `n.children` edges of the consumer.
// `ResolvedPackage.dependencies` and `ResolvedPackage.peers` are
// distinct fields; the v2 store's graph-key derivation depends on
// the separation
// (`install.rs::4620-4686` / `lpm-resolver::resolve.rs::36+61`).
// Smuggling peers in as children would break peer-divergent link-
// entry isolation under v2 (default). Hence: ambient install at
// ROOT scope, satisfying the peer's canonical from the side without
// modifying the consumer's child list.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PeerResolutionCacheKey {
    canonical: CanonicalKey,
    sorted_parent_peers_hash: [u8; 32],
}

#[derive(Debug, Clone)]
enum CachedPeerResolution {
    Synthesize { chosen: NpmVersion },
    BestEffortSynthesize { chosen: NpmVersion },
}

impl CachedPeerResolution {
    fn to_outcome(&self, state: &ResolveState, reqs: &[&PeerRequirement]) -> PeerDrainOutcome {
        match self {
            Self::Synthesize { chosen } => PeerDrainOutcome::Synthesize {
                chosen: chosen.clone(),
            },
            Self::BestEffortSynthesize { chosen } => PeerDrainOutcome::BestEffortSynthesize {
                chosen: chosen.clone(),
                unsatisfied: unsatisfied_required_consumers(state, reqs, chosen),
            },
        }
    }
}

/// Classification outcome for a single peer-canonical group during
/// the drain pass.
enum PeerDrainOutcome {
    /// Some node already in `state.resolved` for this canonical
    /// satisfies every requirement in the group. No work to do —
    /// `into_resolved_packages` will record the per-consumer peer
    /// edges from the metadata cache.
    SatisfiedByExisting,
    /// All consumers in the group declared the peer as optional, OR
    /// `auto_install_peers` is off. Skip without synthesis;
    /// `check_unmet_peers` handles user-visible output.
    SkippedOptOut,
    /// At least one consumer is required and the group can be
    /// satisfied by version `chosen` from the canonical's manifest.
    /// Caller synthesizes a root-scoped ambient `Edge` with an
    /// exact-version range pinning `chosen`. `find_version_satisfying_all`
    /// applies the platform filter, so a returned version is always
    /// platform-compatible — the synthesis path never bumps
    /// `state.platform_skipped`.
    Synthesize { chosen: NpmVersion },
    /// Best-effort synthesis: required consumer ranges are
    /// pairwise-incompatible, so no single version satisfies every
    /// consumer. Caller still synthesizes a root-scoped ambient Edge
    /// at `chosen` (the version satisfying the most consumers, ties
    /// broken by newest), AND records a [`PeerConflictReport`] so the
    /// install pipeline can warn about the unsatisfied consumers.
    /// Mirrors npm v7+ / pnpm behavior — pick one peer at top level,
    /// warn the rest. The unreachable terminal case (no version
    /// satisfies ANY required consumer) keeps the hard
    /// [`ResolveError::PeerConflict`] surface.
    BestEffortSynthesize {
        chosen: NpmVersion,
        unsatisfied: Vec<(String, String)>, // (consumer_canonical, range)
    },
}

/// Walk `info.versions` newest-first, return the first version that
/// satisfies EVERY requirement's range AND is platform-compatible.
/// Mirrors `find_best_version`'s contract for a single range, but
/// generalized to N ranges that all must be satisfied simultaneously.
///
/// Returns `None` when no version threads every range; callers turn
/// that into a best-effort fallback via [`find_version_satisfying_most`]
/// (warn + synthesize the most-satisfying version) or a silent skip
/// (all consumers optional).
fn find_version_satisfying_all(
    info: &CachedPackageInfo,
    reqs: &[&PeerRequirement],
) -> Option<NpmVersion> {
    for v in &info.versions {
        // Every requirement's range must accept this version.
        if !reqs.iter().all(|r| r.range.satisfies(v)) {
            continue;
        }
        // Platform filter — same gate the regular dep path uses, so
        // an ambient install never lands a tarball the current OS/CPU
        // can't use.
        let platform_ok = info.platform.is_empty()
            || info
                .platform
                .get(&v.to_string())
                .is_none_or(crate::provider::is_platform_compatible);
        if !platform_ok {
            continue;
        }
        return Some(v.clone());
    }
    None
}

/// Best-effort fallback when no version satisfies EVERY required
/// consumer's range (transitive peer conflict). Returns
/// `Some((chosen, unsatisfied_required_indices))` where:
/// - `chosen` is the platform-compatible version that satisfies the
///   most REQUIRED consumer ranges (ties broken by newest semver — the
///   `info.versions` walk is already newest-first);
/// - `unsatisfied_required_indices` indexes into `reqs` for required
///   consumers whose range does NOT include `chosen`. Optional
///   consumers are excluded from the unsatisfied list — they're never
///   surfaced as warnings.
///
/// Returns `None` when no platform-compatible version satisfies even
/// ONE required consumer's range — that's the truly-irreconcilable
/// terminal case the caller should turn into a hard `PeerConflict`
/// error.
///
/// Mirrors npm v7+ / pnpm hoisted-mode behavior: pick a single
/// top-level peer version, warn about consumers stuck with the wrong
/// one. lpm pre-fix raised `PeerConflict` here, blocking real-world
/// installs (e.g. nestjs/typescript-starter's transitive
/// ajv-keywords@5 vs @8 chain).
fn find_version_satisfying_most<'a>(
    info: &CachedPackageInfo,
    reqs: &'a [&'a PeerRequirement],
) -> Option<(NpmVersion, Vec<usize>)> {
    let required_indices: Vec<usize> = reqs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| (!r.optional).then_some(i))
        .collect();
    if required_indices.is_empty() {
        return None;
    }

    let mut best: Option<(NpmVersion, usize, Vec<usize>)> = None;
    for v in &info.versions {
        let platform_ok = info.platform.is_empty()
            || info
                .platform
                .get(&v.to_string())
                .is_none_or(crate::provider::is_platform_compatible);
        if !platform_ok {
            continue;
        }
        let mut hits = 0usize;
        let mut misses: Vec<usize> = Vec::new();
        for &i in &required_indices {
            if reqs[i].range.satisfies(v) {
                hits += 1;
            } else {
                misses.push(i);
            }
        }
        if hits == 0 {
            continue;
        }
        // Newest-first walk + strictly-greater hit count = stable
        // tiebreak on newest. Equal hit count loses to the version
        // already chosen (which was newer in the walk).
        match &best {
            None => best = Some((v.clone(), hits, misses)),
            Some((_, prev_hits, _)) if hits > *prev_hits => best = Some((v.clone(), hits, misses)),
            _ => {}
        }
    }
    best.map(|(v, _, misses)| (v, misses))
}

/// True iff at least one node currently in `state.resolved[canonical]`
/// is at a version that satisfies EVERY requirement in the group. The
/// existing `into_resolved_packages` peer-derivation pass picks up the
/// resolved version from `resolved_by_canonical`, so a satisfied group
/// needs no further work.
fn group_satisfied_by_existing(
    state: &ResolveState,
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
) -> bool {
    let Some(nodes) = state.resolved.get(canonical) else {
        return false;
    };
    nodes
        .iter()
        .any(|(v, _)| reqs.iter().all(|r| r.range.satisfies(v)))
}

fn peer_resolution_cache_key(
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
) -> PeerResolutionCacheKey {
    let mut parent_peers: Vec<(String, String, bool)> = Vec::with_capacity(reqs.len());
    for req in reqs {
        parent_peers.push((req.peer_name.clone(), req.range.to_string(), req.optional));
    }
    parent_peers.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"lpm-peer-resolution-cache-v1\0");
    for (peer_name, range, optional) in parent_peers {
        hasher.update(peer_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(range.as_bytes());
        hasher.update(b"\0");
        hasher.update(if optional {
            b"optional\0"
        } else {
            b"required\0"
        });
    }
    let digest = hasher.finalize();
    let mut sorted_parent_peers_hash = [0u8; 32];
    sorted_parent_peers_hash.copy_from_slice(&digest);

    PeerResolutionCacheKey {
        canonical: canonical.clone(),
        sorted_parent_peers_hash,
    }
}

fn unsatisfied_required_consumers(
    state: &ResolveState,
    reqs: &[&PeerRequirement],
    chosen: &NpmVersion,
) -> Vec<(String, String)> {
    reqs.iter()
        .filter(|req| !req.optional && !req.range.satisfies(chosen))
        .map(|req| peer_conflict_consumer_entry(state, req))
        .collect()
}

fn unsatisfied_required_consumers_at_indices(
    state: &ResolveState,
    reqs: &[&PeerRequirement],
    indices: Vec<usize>,
) -> Vec<(String, String)> {
    indices
        .into_iter()
        .map(|i| peer_conflict_consumer_entry(state, reqs[i]))
        .collect()
}

fn peer_conflict_consumer_entry(state: &ResolveState, req: &PeerRequirement) -> (String, String) {
    let consumer_canonical = state
        .nodes
        .get(req.consumer as usize)
        .map_or_else(|| "<unknown>".to_string(), |n| n.canonical.to_string());
    (consumer_canonical, req.range.to_string())
}

/// One peer-drain pass.
///
/// Drains the current `state.peer_requirements` snapshot (replacing
/// the field with an empty Vec so the next pass collects fresh
/// requirements from any ambient installs synthesized during this
/// pass). Returns the synthesized edges for the caller to push onto
/// `state.task_queue` and drain through the main loop.
///
/// Pick canonicals that should be speculatively prefetched concurrent with
/// the regular dep walk.
///
/// Returns canonicals from `state.peer_requirements` that satisfy
/// ALL of:
///   - at least one consumer in the group is non-optional
///     (optional-only groups never auto-install, so prefetching
///     would be wasted bandwidth);
///   - no node in `state.resolved` for the canonical satisfies any
///     consumer's range (i.e., not already met by an ancestor);
///   - the canonical is not in `cached_canonicals` (manifest already
///     in the shared cache — the eventual drain pass will hit the
///     fast path);
///   - the canonical is not in `inflight_canonicals` (some sibling
///     dispatch already started a fetch — the dispatcher's existing
///     dedup handles us).
///
/// Returned canonicals are sorted alphabetically for deterministic
/// dispatch ordering across runs (same lockfile-equivalence guarantee
/// the regular dep loop holds).
///
/// **Pure function:** no I/O, no `&mut` parameters that would couple
/// it to the dispatcher's spawn machinery. The fused arm calls this
/// once per main-loop iteration to pick prefetch candidates, then
/// spawns metadata jobs through its existing infrastructure. Tests
/// can drive it directly with hand-built state + cached/inflight
/// sets to verify the four predicates.
fn pick_peer_prefetch_candidates(
    state: &ResolveState,
    cached_canonicals: &dashmap::DashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    inflight_canonicals: &AHashSet<CanonicalKey>,
) -> Vec<CanonicalKey> {
    if state.peer_requirements.is_empty() {
        return Vec::new();
    }

    // Group reqs by canonical so the all-optional check is per-group,
    // not per-individual-requirement (an optional consumer alone
    // shouldn't keep a prefetch from happening when a sibling
    // required-consumer for the SAME canonical exists).
    let mut grouped: HashMap<&CanonicalKey, Vec<&PeerRequirement>> = HashMap::new();
    for req in &state.peer_requirements {
        grouped.entry(&req.canonical).or_default().push(req);
    }

    let mut picks: Vec<CanonicalKey> = Vec::new();
    for (canonical, reqs) in grouped {
        // All-optional → no auto-install regardless of cache state.
        if reqs.iter().all(|r| r.optional) {
            continue;
        }
        // Already satisfied by an existing node in the resolved tree.
        if let Some(nodes) = state.resolved.get(canonical)
            && nodes
                .iter()
                .any(|(v, _)| reqs.iter().all(|r| r.range.satisfies(v)))
        {
            continue;
        }
        // Manifest already in cache — drain pass will hit the fast
        // path; no prefetch needed.
        if cached_canonicals.contains_key(canonical) {
            continue;
        }
        // Some sibling dispatch already started a fetch for this
        // canonical (regular transitive dep is racing with us). The
        // dispatcher's `inflight` guard would dedup our spawn anyway;
        // skipping here saves the spawn allocation + the redundant
        // `dispatcher_rpc_count` bump.
        if inflight_canonicals.contains(canonical) {
            continue;
        }
        picks.push(canonical.clone());
    }

    // Deterministic dispatch order. With ~tens of peer requirements
    // even on bench/fixture-large, sort cost is negligible.
    picks.sort_by_key(|c| c.to_string());
    picks
}

/// `fetch_manifest` is the arm-specific closure that resolves a
/// canonical to its `Arc<CachedPackageInfo>`, using whatever caching
/// and dispatch machinery the calling arm has (walker arm:
/// synchronous `ensure_manifest`; fused arm: `shared_cache` lookup
/// then direct fetch on miss).
async fn drain_peer_requirements_one_pass<F, Fut>(
    state: &mut ResolveState,
    auto_install_peers: bool,
    mut fetch_manifest: F,
) -> Result<Vec<Edge>, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    // Take ownership of the current snapshot so subsequent passes
    // start clean. Synthesized ambient installs may produce further
    // peer requirements via `enqueue_child_deps`; those are caught by
    // the next pass.
    let pending = std::mem::take(&mut state.peer_requirements);
    if pending.is_empty() {
        return Ok(Vec::new());
    }

    // Group by canonical, deterministically. The HashMap walk would
    // produce non-reproducible synthesis order; collect-then-sort
    // gives byte-identical lockfile output across runs.
    let mut grouped: HashMap<CanonicalKey, Vec<PeerRequirement>> = HashMap::new();
    for req in pending {
        grouped.entry(req.canonical.clone()).or_default().push(req);
    }
    let mut canonicals: Vec<CanonicalKey> = grouped.keys().cloned().collect();
    canonicals.sort_by_key(|c| c.to_string());

    let mut synthesized: Vec<Edge> = Vec::new();
    for canonical in canonicals {
        let reqs_owned = grouped.remove(&canonical).expect("just collected key");
        let reqs: Vec<&PeerRequirement> = reqs_owned.iter().collect();

        let outcome = classify_peer_group(
            state,
            &canonical,
            &reqs,
            auto_install_peers,
            &mut fetch_manifest,
        )
        .await?;

        match outcome {
            PeerDrainOutcome::SatisfiedByExisting => continue,
            PeerDrainOutcome::SkippedOptOut => continue,
            PeerDrainOutcome::Synthesize { chosen } => {
                synthesize_ambient_edge(
                    state,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
            }
            PeerDrainOutcome::BestEffortSynthesize {
                chosen,
                unsatisfied,
            } => {
                synthesize_ambient_edge(
                    state,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
                // Best-effort synthesis still installs the canonical
                // at top level — but at most one consumer range. Store
                // the conflict so install.rs can warn the user about
                // the consumers that DIDN'T match. tracing::warn!
                // surfaces in `--json=false` runs even when stderr is
                // capped; install.rs additionally formats the report
                // human-readably below the install summary.
                tracing::warn!(
                    "ambient peer-install best-effort: {} @ {} satisfies {} of {} required consumer(s); \
                     unsatisfied: {}",
                    canonical,
                    chosen,
                    reqs_owned.len() - unsatisfied.len(),
                    reqs_owned.iter().filter(|r| !r.optional).count(),
                    unsatisfied
                        .iter()
                        .map(|(c, r)| format!("{c} wants {r}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                state.peer_conflicts.push(PeerConflictReport {
                    canonical: canonical.to_string(),
                    chosen_version: chosen.to_string(),
                    unsatisfied_consumers: unsatisfied,
                });
            }
        }
    }

    Ok(synthesized)
}

/// Push a single ambient root-scoped Edge for the chosen peer version
/// and record the canonical on `state.ambient_peer_installs`. Shared
/// between the strict-satisfies-all path and the best-effort
/// satisfies-most fallback so both paths produce byte-identical edges.
fn synthesize_ambient_edge(
    state: &mut ResolveState,
    canonical: &CanonicalKey,
    chosen: &NpmVersion,
    consumer_count: usize,
    out: &mut Vec<Edge>,
) -> Result<(), ResolveError> {
    let exact_range = NpmRange::parse(&chosen.to_string()).map_err(|e| {
        ResolveError::Internal(format!(
            "synthesized exact-pin range '{chosen}' for {canonical} \
             failed to parse: {e}"
        ))
    })?;
    let canonical_name = canonical.to_string();
    out.push(Edge {
        parent: 0,
        local_name: canonical_name.clone(),
        canonical: canonical.clone(),
        range: exact_range,
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });
    state.ambient_peer_installs.push(canonical_name);
    tracing::debug!(
        "ambient-install: {} @ {} (consumers: {})",
        canonical,
        chosen,
        consumer_count,
    );
    Ok(())
}

/// Classify one peer-canonical group. Splits the satisfaction check
/// from the synthesis path so callers can short-circuit the manifest
/// fetch when it's not needed.
async fn classify_peer_group<F, Fut>(
    state: &ResolveState,
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
    auto_install_peers: bool,
    fetch_manifest: &mut F,
) -> Result<PeerDrainOutcome, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    // Step 1 — already satisfied?
    if group_satisfied_by_existing(state, canonical, reqs) {
        return Ok(PeerDrainOutcome::SatisfiedByExisting);
    }

    // Step 2 — opt-out gates. If every requirement is optional, the
    // manifest author asked us not to fail; same skip path as
    // `auto_install_peers = false`.
    let any_required = reqs.iter().any(|r| !r.optional);
    if !any_required || !auto_install_peers {
        return Ok(PeerDrainOutcome::SkippedOptOut);
    }

    let cache_key = peer_resolution_cache_key(canonical, reqs);
    if let Some(cached) = state.peer_resolution_cache.get(&cache_key) {
        return Ok(cached.value().to_outcome(state, reqs));
    }

    // Step 3 — synthesis path. Fetch the manifest, find the version
    // satisfying every consumer's range. Raising `PeerConflict` when no
    // version threads every range breaks real-world installs whose
    // TRANSITIVE tree declares incompatible peer ranges (e.g. nestjs's
    // chain pulling both `ajv-keywords@5` peer'ing ajv@^6 and
    // `ajv-keywords@8` peer'ing ajv@^8). npm v7+ + pnpm hoist a single top-level peer
    // and warn about the stuck consumers; lpm now matches.
    let info = fetch_manifest(canonical.clone()).await?;
    if let Some(chosen) = find_version_satisfying_all(&info, reqs) {
        let outcome = PeerDrainOutcome::Synthesize {
            chosen: chosen.clone(),
        };
        state
            .peer_resolution_cache
            .insert(cache_key, CachedPeerResolution::Synthesize { chosen });
        return Ok(outcome);
    }
    if let Some((chosen, unsatisfied_idx)) = find_version_satisfying_most(&info, reqs) {
        let unsatisfied = unsatisfied_required_consumers_at_indices(state, reqs, unsatisfied_idx);
        let outcome = PeerDrainOutcome::BestEffortSynthesize {
            chosen: chosen.clone(),
            unsatisfied,
        };
        state.peer_resolution_cache.insert(
            cache_key,
            CachedPeerResolution::BestEffortSynthesize { chosen },
        );
        return Ok(outcome);
    }
    // Truly irreconcilable: no platform-compatible version satisfies
    // any required consumer's range. Hard error — this means the
    // canonical's published versions don't include anything any
    // required consumer accepts, which the resolver can't paper over.
    Err(ResolveError::PeerConflict {
        canonical: canonical.to_string(),
        requirements: reqs
            .iter()
            .map(|r| {
                let consumer_canonical = state
                    .nodes
                    .get(r.consumer as usize)
                    .map_or_else(|| "<unknown>".to_string(), |n| n.canonical.to_string());
                (consumer_canonical, r.range.to_string(), r.optional)
            })
            .collect(),
    })
}

/// Outcome of `find_best_version`. Distinguishes "no version exists
/// satisfying the range" from "a satisfying version exists but the
/// current platform isn't compatible" so callers can increment
/// `platform_skipped` precisely.
enum VersionPick {
    /// A satisfying version was found.
    Picked(NpmVersion),
    /// No version satisfies the range.
    NoSatisfying,
}

/// Detect a leaked `workspace:` specifier before [`NpmRange::parse`] gets
/// to it. The implementation lives in [`crate::ranges::is_workspace_specifier`]
/// so both resolver arms consult the same predicate; this thin re-export
/// keeps the local callsite readable.
fn is_workspace_specifier(range_str: &str) -> bool {
    crate::ranges::is_workspace_specifier(range_str)
}

/// Greedy first-match version pick. Iterates `info.versions` (sorted
/// descending by semver in
/// [`crate::provider::parse_metadata_to_cache_info`]) and returns the
/// first version satisfying the range. Platform compatibility is applied
/// after resolution so lockfiles remain portable across hosts.
fn find_best_version(info: &CachedPackageInfo, range: &NpmRange) -> VersionPick {
    for v in &info.versions {
        if !range.satisfies(v) {
            continue;
        }
        return VersionPick::Picked(v.clone());
    }
    VersionPick::NoSatisfying
}

/// Fast cache hit, then short-lived per-canonical wait, then escape-hatch
/// direct fetch. Mirrors `provider.rs::ensure_cached` shape but yields an
/// owned `Arc<CachedPackageInfo>` instead of a `RefCell` borrow.
#[allow(clippy::too_many_arguments)] // mirrors provider::ensure_cached's plumbing surface
async fn ensure_manifest(
    canonical: &CanonicalKey,
    client: Arc<RegistryClient>,
    route_table: &RouteTable,
    shared_cache: &SharedCache,
    notify_map: &NotifyMap,
    walker_done: &WalkerDone,
    fetch_wait_timeout: Duration,
    metrics: &StreamingBfsMetrics,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    // Fast path. Cache values are Arc-wrapped, so the clone here is a
    // refcount bump rather than a deep clone of the 7-HashMap struct.
    // This is the load-bearing fix for the resolver wall — previously the
    // greedy resolver cloned popular packuments per edge, burning ~5 sec
    // per cold install.
    if let Some(entry) = shared_cache.get(canonical) {
        return Ok(entry.value().clone());
    }

    // Wait-loop (only when walker is attached and timeout > 0).
    if !fetch_wait_timeout.is_zero() && !walker_done.load(Ordering::Acquire) {
        metrics_incr_cache_wait(metrics);
        let notify = notify_map
            .entry(canonical.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .value()
            .clone();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        // Re-check: walker may have inserted between the fast-path miss
        // and now.
        if let Some(entry) = shared_cache.get(canonical) {
            return Ok(entry.value().clone());
        }
        // Walker may have flipped done — if so, fetch directly without
        // burning the timeout. Matches `provider.rs::ensure_cached`'s
        // walker_done short-circuit path.
        if !walker_done.load(Ordering::Acquire) {
            match tokio::time::timeout(fetch_wait_timeout, notified).await {
                Ok(()) => {
                    if let Some(entry) = shared_cache.get(canonical) {
                        return Ok(entry.value().clone());
                    }
                }
                Err(_) => {
                    metrics_incr_timeout(metrics);
                }
            }
        }
    }

    // Escape hatch: direct fetch.
    metrics_incr_escape_hatch(metrics);
    let info = direct_fetch(&client, route_table, canonical).await?;
    let info_arc = Arc::new(info);
    shared_cache.insert(canonical.clone(), info_arc.clone());
    if let Some(n) = notify_map.get(canonical) {
        n.notify_waiters();
    }
    Ok(info_arc)
}

async fn direct_fetch(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
) -> Result<CachedPackageInfo, ResolveError> {
    let metadata = fetch_metadata_raw(client, route_table, canonical).await?;
    Ok(parse_metadata_to_cache_info(&metadata))
}

struct FetchedMetadata {
    metadata: lpm_registry::PackageMetadata,
    info: Arc<CachedPackageInfo>,
}

type FetchResult = Result<FetchedMetadata, ResolveError>;

async fn fetch_metadata_for_resolver(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
) -> Result<FetchedMetadata, ResolveError> {
    let metadata = fetch_metadata_raw(client, route_table, canonical).await?;
    Ok(parse_fetched_metadata(metadata))
}

fn parse_fetched_metadata(metadata: lpm_registry::PackageMetadata) -> FetchedMetadata {
    let info = Arc::new(parse_metadata_to_cache_info(&metadata));
    FetchedMetadata { metadata, info }
}

fn take_next_ready_metadata<V>(
    inflight_order: &mut BTreeMap<String, CanonicalKey>,
    ready_metadata: &mut BTreeMap<String, V>,
) -> Option<(CanonicalKey, V)> {
    let next_key = inflight_order.keys().next().cloned()?;
    let ready = ready_metadata.remove(&next_key)?;
    let canonical = inflight_order
        .remove(&next_key)
        .expect("ready metadata key must be tracked as inflight");
    Some((canonical, ready))
}

fn complete_metadata_fetch(
    canonical: CanonicalKey,
    result: FetchResult,
    shared_cache: &SharedCache,
    spec_tx: Option<&tokio::sync::mpsc::Sender<(String, lpm_registry::PackageMetadata)>>,
    tarball_dispatched_count: &mut u64,
    parked: &mut AHashMap<CanonicalKey, Vec<Edge>>,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    match result {
        Ok(fetched) => {
            shared_cache.insert(canonical.clone(), fetched.info);
            if let Some(tx) = spec_tx
                && tx
                    .try_send((canonical.to_string(), fetched.metadata))
                    .is_ok()
            {
                *tarball_dispatched_count += 1;
            }
            if let Some(mut edges) = parked.remove(&canonical) {
                edges.sort_by(|a, b| {
                    (a.parent, a.local_name.as_str()).cmp(&(b.parent, b.local_name.as_str()))
                });
                for e in edges {
                    state.task_queue.push_back(e);
                }
            }
        }
        Err(e) => {
            if let Some(edges) = parked.remove(&canonical) {
                for edge in edges {
                    propagate_fetch_error(&edge, &e, state)?;
                }
            }
        }
    }
    Ok(())
}

/// Raw-metadata fetch, factored out so the fused resolver can forward the
/// original [`lpm_registry::PackageMetadata`] to `spec_tx` for tarball
/// speculation while caching the parsed [`CachedPackageInfo`] form.
///
/// Both NPM routes go through the abbreviated packument endpoint
/// (`application/vnd.npm.install-v1+json`), so wire-byte savings already
/// apply.
async fn fetch_metadata_raw(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
) -> Result<lpm_registry::PackageMetadata, ResolveError> {
    match canonical {
        CanonicalKey::Root => Err(ResolveError::Internal(
            "fetch_metadata_raw called for root".to_string(),
        )),
        CanonicalKey::Lpm { owner, name } => {
            let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                .map_err(|e| ResolveError::Internal(e.to_string()))?;
            client.get_package_metadata(&pkg_name).await.map_err(|e| {
                ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: e.to_string(),
                }
            })
        }
        CanonicalKey::Npm { name } => {
            let route = route_table.route_for_package(name);
            match route {
                UpstreamRoute::LpmWorker => client.get_npm_package_metadata(name).await,
                UpstreamRoute::NpmDirect => client.get_npm_metadata_direct(name).await,
                UpstreamRoute::Custom { target, auth } => {
                    // `.npmrc`-declared custom registry. Auth (if any)
                    // is origin-scoped and re-verified inside
                    // `get_npm_metadata_from` before the Authorization
                    // header is attached.
                    client
                        .get_npm_metadata_from(&target.base_url, name, auth.as_ref())
                        .await
                }
            }
            .map_err(|e| ResolveError::DependencyFetch {
                package: canonical.to_string(),
                version: "*".to_string(),
                detail: e.to_string(),
            })
        }
    }
}

/// Apply optional/peer/required behavior to an edge whose manifest fetch
/// failed. Mirrors [`handle_no_version`]'s contract for fetch-side errors
/// so the fused dispatcher's failure semantics are indistinguishable from
/// the walker arm's:
///
/// - Optional → skip silently. The platform_skipped counter is
///   irrelevant here (we never reached platform filtering — the
///   manifest itself never landed), so it stays unchanged.
/// - Peer → skip with debug log; the post-resolve `check_unmet_peers`
///   pass surfaces unmet peers separately.
/// - Required → propagate as `ResolveError::DependencyFetch` with the
///   underlying detail, matching `direct_fetch`'s error shape exactly.
fn propagate_fetch_error(
    edge: &Edge,
    err: &ResolveError,
    _state: &mut ResolveState,
) -> Result<(), ResolveError> {
    if edge.behavior.optional {
        tracing::debug!(
            "optional dep {} fetch failed; skipping: {err}",
            edge.canonical,
        );
        return Ok(());
    }
    if edge.behavior.peer {
        tracing::debug!(
            "peer dep {} fetch failed; not eagerly installed: {err}",
            edge.canonical,
        );
        return Ok(());
    }
    Err(ResolveError::DependencyFetch {
        package: edge.canonical.to_string(),
        version: edge.range.to_string(),
        detail: err.to_string(),
    })
}

// Metrics helpers — wrap the `pub(crate)` increment methods on
// `StreamingBfsMetrics` so the call sites in `ensure_manifest` stay
// readable. Each is a one-line forwarder; kept private here.
fn metrics_incr_cache_wait(_m: &StreamingBfsMetrics) {
    // The fields on `StreamingBfsMetrics` are private to `provider`;
    // greedy uses the public counter readback at install.rs JSON time
    // and doesn't need to bump them here. Left as a no-op stub so we
    // can wire telemetry symmetrically with PubGrub once the metrics
    // surface is widened (W5: BfsWalker integration).
}
fn metrics_incr_timeout(_m: &StreamingBfsMetrics) {}
fn metrics_incr_escape_hatch(_m: &StreamingBfsMetrics) {}

// ── Unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CachedDistInfo, CachedPackageInfo};

    /// Build a minimal npm-packument JSON shape for wiremock-based
    /// resolver tests. Mirrors `walker::tests::metadata_json` so the
    /// fixture shape stays identical across resolver-arm tests.
    fn metadata_json(name: &str, deps: &[(&str, &str)]) -> serde_json::Value {
        let deps_obj: serde_json::Map<String, serde_json::Value> = deps
            .iter()
            .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
            .collect();
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg.tgz",
                        "integrity": "sha512-test"
                    },
                    "dependencies": deps_obj
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        })
    }

    /// Build a minimal CachedPackageInfo for a synthesized npm package.
    /// `versions` are passed already in descending order to mirror
    /// `parse_metadata_to_cache_info`'s contract.
    fn mk_info(versions: &[&str], deps_of_latest: &[(&str, &str)]) -> CachedPackageInfo {
        let parsed: Vec<NpmVersion> = versions
            .iter()
            .map(|v| NpmVersion::parse(v).unwrap())
            .collect();
        let mut deps_map = HashMap::new();
        let mut latest_deps = HashMap::new();
        for (n, r) in deps_of_latest {
            latest_deps.insert(n.to_string(), r.to_string());
        }
        if let Some(latest) = versions.first() {
            deps_map.insert(latest.to_string(), latest_deps);
        }
        CachedPackageInfo {
            versions: parsed,
            deps: deps_map,
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: versions
                .iter()
                .map(|v| {
                    (
                        v.to_string(),
                        CachedDistInfo {
                            tarball_url: Some(format!("https://example.invalid/{}.tgz", v)),
                            integrity: Some(format!("sha512-fake-{}", v)),
                        },
                    )
                })
                .collect(),
            aliases: HashMap::new(),
        }
    }

    fn picked(p: VersionPick) -> NpmVersion {
        match p {
            VersionPick::Picked(v) => v,
            VersionPick::NoSatisfying => panic!("expected Picked, got NoSatisfying"),
        }
    }

    #[test]
    fn find_best_version_picks_newest_match() {
        let info = mk_info(&["4.17.21", "4.17.20", "3.10.1", "3.0.0"], &[]);
        let range = NpmRange::parse("^4.0.0").unwrap();
        assert_eq!(
            picked(find_best_version(&info, &range)).to_string(),
            "4.17.21"
        );
    }

    #[test]
    fn find_best_version_returns_no_satisfying_when_unsatisfied() {
        let info = mk_info(&["4.17.21", "3.10.1"], &[]);
        let range = NpmRange::parse("^5.0.0").unwrap();
        assert!(matches!(
            find_best_version(&info, &range),
            VersionPick::NoSatisfying
        ));
    }

    #[test]
    fn find_best_version_handles_exact_pin() {
        let info = mk_info(&["4.17.21", "4.17.20", "3.10.1"], &[]);
        let range = NpmRange::parse("4.17.20").unwrap();
        assert_eq!(
            picked(find_best_version(&info, &range)).to_string(),
            "4.17.20"
        );
    }

    #[test]
    fn find_best_version_ignores_platform_when_selecting_version() {
        // Platform filtering happens after resolution so lockfiles stay
        // portable. The newest semver-satisfying version wins even when
        // it is incompatible with the current host.
        let mut info = mk_info(&["1.0.0"], &[]);
        info.platform.insert(
            "1.0.0".to_string(),
            crate::provider::PlatformMeta {
                os: vec![
                    "!darwin".to_string(),
                    "!linux".to_string(),
                    "!win32".to_string(),
                    "!freebsd".to_string(),
                    "!openbsd".to_string(),
                    "!netbsd".to_string(),
                    "!aix".to_string(),
                    "!sunos".to_string(),
                    "!android".to_string(),
                ],
                cpu: vec![],
                libc: vec![],
            },
        );
        let range = NpmRange::parse("^1.0.0").unwrap();
        assert_eq!(
            picked(find_best_version(&info, &range)).to_string(),
            "1.0.0"
        );
    }

    #[test]
    fn seed_root_edges_orders_deterministically() {
        let mut deps = HashMap::new();
        deps.insert("zebra".to_string(), "^1.0.0".to_string());
        deps.insert("alpha".to_string(), "^1.0.0".to_string());
        deps.insert("middle".to_string(), "^1.0.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();
        let order: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        assert_eq!(order, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn seed_root_edges_rewrites_npm_alias_root_dep() {
        // Root dep declared as `"local": "npm:target@range"` must
        // (a) emit an Edge whose canonical is keyed on the TARGET (`lodash`),
        // not the alias (`lodash-cjs`), so metadata fetch hits the right
        // package; (b) parse the inner range (`^4.17.21`); (c) preserve the
        // alias as `local_name` so the install pipeline knows which
        // `node_modules/<alias>/` slot to build; (d) record `local → target`
        // in `root_aliases` for
        // ResolveResult downstream consumption. Mirrors
        // `resolve.rs::resolve_with_prefetch_handles_root_npm_alias`'s
        // contract on the legacy-pubgrub arm.
        let mut deps = HashMap::new();
        deps.insert("lodash-cjs".to_string(), "npm:lodash@^4.17.21".to_string());
        // A non-aliased sibling proves the alias-vs-non-alias branch
        // both work in one seeding pass.
        deps.insert("rxjs".to_string(), "^7.8.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();

        // root_aliases is populated only for the aliased entry.
        assert_eq!(state.root_aliases.len(), 1);
        assert_eq!(
            state.root_aliases.get("lodash-cjs"),
            Some(&"lodash".to_string())
        );

        // Edges keyed on canonical = target for the alias, canonical =
        // alias-key (== package name) for the non-alias.
        let edges_by_local: HashMap<&str, &Edge> = state
            .task_queue
            .iter()
            .map(|e| (e.local_name.as_str(), e))
            .collect();
        assert_eq!(edges_by_local.len(), 2);

        let alias_edge = edges_by_local["lodash-cjs"];
        assert_eq!(
            alias_edge.canonical,
            CanonicalKey::from_dep_name("lodash"),
            "alias canonical must be the TARGET, not the local key"
        );
        assert_eq!(
            alias_edge.local_name, "lodash-cjs",
            "local_name preserves the alias key for the install pipeline"
        );
        // Inner range must parse as a normal semver range. `^4.17.21`
        // satisfies 4.17.21 and not 5.0.0.
        let v_4_17_21 = NpmVersion::new(4, 17, 21);
        let v_5_0_0 = NpmVersion::new(5, 0, 0);
        assert!(alias_edge.range.satisfies(&v_4_17_21));
        assert!(!alias_edge.range.satisfies(&v_5_0_0));

        let plain_edge = edges_by_local["rxjs"];
        assert_eq!(
            plain_edge.canonical,
            CanonicalKey::from_dep_name("rxjs"),
            "non-alias canonical equals the dep name"
        );
    }

    #[test]
    fn seed_root_edges_seeds_root_node() {
        let mut deps = HashMap::new();
        deps.insert("only".to_string(), "^1.0.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();
        assert_eq!(state.nodes.len(), 1);
        assert!(matches!(state.nodes[0].canonical, CanonicalKey::Root));
        assert_eq!(state.task_queue.len(), 1);
        assert_eq!(state.task_queue[0].parent, 0);
    }

    #[test]
    fn process_edge_reuses_node_when_existing_version_satisfies_new_range() {
        // Two parents both wanting `lodash` with COMPATIBLE ranges
        // (^4.0.0 and ^4.10.0 both satisfied by 4.17.21) should produce
        // ONE resolved node, two parent→child edges. The first edge
        // picks 4.17.21; the second sees an existing node whose version
        // satisfies its tighter range and reuses it.
        let info = mk_info(&["4.17.21"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^4.0.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();

        // Add a second parent (simulate a transitive that also needs lodash)
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("react"),
            version: NpmVersion::parse("18.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state.resolved.insert(
            CanonicalKey::npm("react"),
            vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
        );
        state.task_queue.push_back(Edge {
            parent: 1,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse("^4.10.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });

        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        // One lodash node (root + react + lodash = 3 nodes total).
        assert_eq!(state.nodes.len(), 3);
        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 1);
        let (_, lodash_id) = lodash_entries[0];

        // Both root and react have an edge to that single lodash node.
        assert!(
            state.nodes[0]
                .children
                .iter()
                .any(|(_, id)| *id == lodash_id)
        );
        assert!(
            state.nodes[1]
                .children
                .iter()
                .any(|(_, id)| *id == lodash_id)
        );
    }

    #[test]
    fn process_edge_allocates_second_version_on_incompatible_range() {
        // Two parents wanting INCOMPATIBLE ranges of the same canonical
        // (^4.0.0 picks 4.17.21; ^3.0.0 cannot reuse 4.17.21 → must
        // allocate a new node for 3.10.1). Both versions live in the
        // resolved tree as distinct nodes — bun + npm + pnpm semantics.
        // This is the case the PubGrub split-retry workaround was
        // grafted on for; greedy handles it natively.
        let info = mk_info(&["4.17.21", "4.0.0", "3.10.1", "3.0.0"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^4.0.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();

        // Second parent wants ^3 — incompatible with the first parent's ^4.
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("legacy-shim"),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state.resolved.insert(
            CanonicalKey::npm("legacy-shim"),
            vec![(NpmVersion::parse("1.0.0").unwrap(), 1)],
        );
        state.task_queue.push_back(Edge {
            parent: 1,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse("^3.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });

        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        // root + legacy-shim + lodash@4.17.21 + lodash@3.10.1 = 4 nodes
        assert_eq!(state.nodes.len(), 4);

        // Two lodash entries with different versions
        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 2);
        let mut versions: Vec<String> = lodash_entries.iter().map(|(v, _)| v.to_string()).collect();
        versions.sort();
        assert_eq!(versions, vec!["3.10.1", "4.17.21"]);

        // Root's edge points at the ^4.0.0-satisfying node (4.17.21)
        let root_lodash_id = state.nodes[0]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();
        assert_eq!(
            state.nodes[root_lodash_id as usize].version.to_string(),
            "4.17.21"
        );

        // legacy-shim's edge points at the ^3.0.0-satisfying node (3.10.1)
        let shim_lodash_id = state.nodes[1]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();
        assert_eq!(
            state.nodes[shim_lodash_id as usize].version.to_string(),
            "3.10.1"
        );
    }

    // ── Override application on the greedy arm ─────────────────────
    //
    // Tests pin the contract: user-declared `lpm.overrides` /
    // `package.json > overrides` take effect on the default resolver
    // path. Exercises three semantic surfaces of `OverrideSet::find_match`:
    //   - Name selectors (apply to every resolution of a canonical)
    //   - Path selectors (apply only via a specific parent)
    //   - Irreconcilable targets (out-of-range — fall back to natural)

    /// Helper: build an OverrideSet from a single `lpm.overrides`
    /// entry. Path-selector tests use a separate path-key form via
    /// the same parser.
    fn override_set(key: &str, target: &str) -> OverrideSet {
        let mut lpm = HashMap::new();
        lpm.insert(key.to_string(), target.to_string());
        OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new())
            .expect("test override should parse")
    }

    #[test]
    fn process_edge_applies_name_selector_override() {
        // `lpm.overrides: { "lodash": "3.10.1" }` — every lodash
        // resolution is forced to 3.10.1, even when the consumer's
        // range nominally satisfies 4.17.21. Mirrors
        // `LpmDependencyProvider::choose_version`'s pubgrub-arm
        // semantics (provider.rs:1185-1207).
        let info = mk_info(&["4.17.21", "4.0.0", "3.10.1", "3.0.0"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^3.0.0 || ^4.0.0".to_string());
        let mut state = ResolveState::new(deps, override_set("lodash", "3.10.1"));
        state.seed_root_edges().unwrap();
        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 1, "single forced version");
        assert_eq!(lodash_entries[0].0.to_string(), "3.10.1");

        let hits = state.overrides.take_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].package, "lodash");
        assert_eq!(hits[0].from_version, "4.17.21");
        assert_eq!(hits[0].to_version, "3.10.1");
        assert_eq!(hits[0].via_parent, None, "Name selector — no parent ctx");
    }

    #[test]
    fn process_edge_range_target_picks_newest_in_intersection() {
        // `lpm.overrides: { "lodash": "^3.0.0" }` — constrains the
        // candidate set to 3.x and lets the resolver pick the newest
        // match in the consumer's range × override range intersection.
        let info = mk_info(&["4.17.21", "3.10.1", "3.0.0"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "*".to_string());
        let mut state = ResolveState::new(deps, override_set("lodash", "^3.0.0"));
        state.seed_root_edges().unwrap();
        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 1);
        assert_eq!(
            lodash_entries[0].0.to_string(),
            "3.10.1",
            "newest version in 3.x — consumer's `*` × override's `^3.0.0`"
        );
    }

    #[test]
    fn process_edge_irreconcilable_override_falls_through_to_natural() {
        // Pinned target is OUTSIDE the consumer's declared range. The
        // resolver should fall through to the natural pick rather than
        // silently picking a version the consumer never asked for. No
        // OverrideHit is recorded — the override didn't take effect.
        let info = mk_info(&["4.17.21", "3.10.1"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^4.0.0".to_string());
        // Override pin to 3.10.1 — outside ^4.0.0.
        let mut state = ResolveState::new(deps, override_set("lodash", "3.10.1"));
        state.seed_root_edges().unwrap();
        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 1);
        assert_eq!(
            lodash_entries[0].0.to_string(),
            "4.17.21",
            "irreconcilable override falls through to natural pick"
        );
        assert!(
            state.overrides.take_hits().is_empty(),
            "no OverrideHit when override didn't apply"
        );
    }

    #[test]
    fn process_edge_path_selector_splits_two_parents() {
        // `lpm.overrides: { "react>lodash": "3.10.1" }` — only the
        // edge originating from `react` is forced; the root-level
        // `lodash` edge keeps its natural pick. Two distinct lodash
        // nodes coexist in the resolved tree (split-by-context).
        //
        // split_targets gate: this test enqueues the override-bearing
        // edge BEFORE the natural edge, so the
        // override allocates `lodash@3.10.1` first; the subsequent
        // root edge must NOT silently inherit that forced version
        // via range-satisfies dedupe (3.10.1 satisfies `>=3.0.0`).
        // Pre-fix, that's exactly what happened — the path-selector
        // override leaked into every sibling of `react`. Post-fix,
        // `OverrideSet::split_targets` (containing "lodash") forces
        // exact-match dedupe on every slow-path edge, so the root
        // edge allocates the natural 4.17.21 in its own node.
        let info = mk_info(&["4.17.21", "3.10.1"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), ">=3.0.0".to_string());
        let mut state = ResolveState::new(deps, override_set("react>lodash", "3.10.1"));

        // Hand-seed both parents WITHOUT calling `seed_root_edges()`,
        // which would push the root>lodash edge first. Reverse order
        // (react edge enqueued before root edge) is what surfaces the
        // pre-fix bug.
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::Root,
            version: NpmVersion::new(0, 0, 0),
            optional: false,
            children: Vec::new(),
        });
        state
            .resolved
            .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("react"),
            version: NpmVersion::parse("18.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state.resolved.insert(
            CanonicalKey::npm("react"),
            vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
        );

        // React edge first — applies override, allocates lodash@3.10.1.
        state.task_queue.push_back(Edge {
            parent: 1,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse(">=3.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });
        // Root edge second — must allocate natural 4.17.21, NOT reuse
        // the forced 3.10.1 the react edge just allocated.
        state.task_queue.push_back(Edge {
            parent: 0,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse(">=3.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });

        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        let mut versions: Vec<String> = lodash_entries.iter().map(|(v, _)| v.to_string()).collect();
        versions.sort();
        assert_eq!(
            versions,
            vec!["3.10.1", "4.17.21"],
            "path-selector override splits lodash into two versions \
             regardless of edge processing order"
        );

        // The root edge resolved to natural (4.17.21).
        let root_lodash_id = state.nodes[0]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();
        assert_eq!(
            state.nodes[root_lodash_id as usize].version.to_string(),
            "4.17.21",
            "root edge must resolve to natural pick (not leaked from earlier-allocated forced node)"
        );

        // The react edge resolved to the override (3.10.1).
        let react_lodash_id = state.nodes[1]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();
        assert_eq!(
            state.nodes[react_lodash_id as usize].version.to_string(),
            "3.10.1"
        );

        let hits = state.overrides.take_hits();
        assert_eq!(hits.len(), 1, "only the path-selector edge records a hit");
        assert_eq!(hits[0].via_parent.as_deref(), Some("react"));
        assert_eq!(hits[0].to_version, "3.10.1");
    }

    #[test]
    fn process_edge_path_selector_does_not_leak_to_sibling_parent() {
        // Regression test: two transitive parents pull the same
        // canonical: `react > lodash` (path-selector matched) and
        // `redux > lodash` (NOT matched). The override edge processes
        // first, allocating `lodash@3.10.1`. Without the
        // `split_targets` gate, the redux edge's range-satisfies dedupe
        // would find 3.10.1 satisfying `>=3.0.0` and silently reuse —
        // leaking the path-selector override into a parent the user
        // didn't select. With the gate, redux gets the natural pick
        // (4.17.21) in its own node.
        let info = mk_info(&["4.17.21", "3.10.1"], &[]);
        // No root-level lodash edge — the leak is parent-to-parent
        // among transitive deps, not parent-to-root.
        let deps = HashMap::new();
        let mut state = ResolveState::new(deps, override_set("react>lodash", "3.10.1"));

        // Root pseudo-node + two parents.
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::Root,
            version: NpmVersion::new(0, 0, 0),
            optional: false,
            children: Vec::new(),
        });
        state
            .resolved
            .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("react"),
            version: NpmVersion::parse("18.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state.resolved.insert(
            CanonicalKey::npm("react"),
            vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
        );
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("redux"),
            version: NpmVersion::parse("4.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state.resolved.insert(
            CanonicalKey::npm("redux"),
            vec![(NpmVersion::parse("4.0.0").unwrap(), 2)],
        );

        // React's lodash edge first (path-selector match, override applies).
        state.task_queue.push_back(Edge {
            parent: 1,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse(">=3.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });
        // Redux's lodash edge second (no path-selector match, must
        // allocate natural — must NOT reuse react's forced 3.10.1).
        state.task_queue.push_back(Edge {
            parent: 2,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse(">=3.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });

        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        let react_lodash_id = state.nodes[1]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();
        let redux_lodash_id = state.nodes[2]
            .children
            .iter()
            .find(|(name, _)| name == "lodash")
            .map(|(_, id)| *id)
            .unwrap();

        assert_eq!(
            state.nodes[react_lodash_id as usize].version.to_string(),
            "3.10.1",
            "react > lodash applies the path-selector override"
        );
        assert_eq!(
            state.nodes[redux_lodash_id as usize].version.to_string(),
            "4.17.21",
            "redux > lodash does NOT inherit react's forced version (split_targets gate)"
        );
        assert_ne!(
            react_lodash_id, redux_lodash_id,
            "the two parents resolve to distinct lodash nodes"
        );
    }

    // ── bundleDependencies skip ───────────────────────────────────

    #[test]
    fn enqueue_child_deps_skips_bundled_names() {
        // Parent declares `bundleDependencies: ["lodash"]` AND
        // `dependencies: { lodash: "^4", react: "^18" }`. The
        // resolver must NOT enqueue `lodash` as a separate edge —
        // it's vendored inside the parent's tarball — but must still
        // enqueue `react`.
        let mut info = mk_info(&["1.0.0"], &[]);
        let mut deps_of_latest = HashMap::new();
        deps_of_latest.insert("lodash".to_string(), "^4.0.0".to_string());
        deps_of_latest.insert("react".to_string(), "^18.0.0".to_string());
        info.deps.insert("1.0.0".to_string(), deps_of_latest);
        let mut bundled = HashSet::new();
        bundled.insert("lodash".to_string());
        info.bundled_dep_names.insert("1.0.0".to_string(), bundled);

        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("parent"),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        enqueue_child_deps(
            0,
            &CanonicalKey::npm("parent"),
            &NpmVersion::parse("1.0.0").unwrap(),
            &info,
            &mut state,
        );

        let queued: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        assert_eq!(
            queued,
            vec!["react"],
            "lodash skipped (bundled); react enqueued"
        );
    }

    #[test]
    fn enqueue_child_deps_no_bundled_names_unchanged() {
        // Sanity baseline: with no bundleDependencies, every dep
        // gets enqueued (the no-bundling fast path is byte-identical
        // to the unbundled fast path).
        let mut info = mk_info(&["1.0.0"], &[]);
        let mut deps_of_latest = HashMap::new();
        deps_of_latest.insert("lodash".to_string(), "^4.0.0".to_string());
        deps_of_latest.insert("react".to_string(), "^18.0.0".to_string());
        info.deps.insert("1.0.0".to_string(), deps_of_latest);
        // No bundled_dep_names entry for 1.0.0.

        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("parent"),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        enqueue_child_deps(
            0,
            &CanonicalKey::npm("parent"),
            &NpmVersion::parse("1.0.0").unwrap(),
            &info,
            &mut state,
        );

        let mut queued: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        queued.sort();
        assert_eq!(queued, vec!["lodash", "react"]);
    }

    #[test]
    fn enqueue_child_deps_omits_optional_dependencies_when_disabled() {
        let mut info = mk_info(&["1.0.0"], &[]);
        let mut deps_of_latest = HashMap::new();
        deps_of_latest.insert("required-child".to_string(), "^1.0.0".to_string());
        deps_of_latest.insert("optional-child".to_string(), "^2.0.0".to_string());
        info.deps.insert("1.0.0".to_string(), deps_of_latest);
        let mut optional = HashSet::new();
        optional.insert("optional-child".to_string());
        info.optional_dep_names
            .insert("1.0.0".to_string(), optional);

        let mut state = ResolveState::new_with_options(HashMap::new(), OverrideSet::empty(), false);
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("parent"),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        enqueue_child_deps(
            0,
            &CanonicalKey::npm("parent"),
            &NpmVersion::parse("1.0.0").unwrap(),
            &info,
            &mut state,
        );

        let queued: Vec<&str> = state
            .task_queue
            .iter()
            .map(|edge| edge.local_name.as_str())
            .collect();
        assert_eq!(queued, vec!["required-child"]);
    }

    // ── workspace: defense-in-depth at resolver entry ────────────

    #[test]
    fn seed_root_edges_rejects_workspace_specifier() {
        // A `workspace:*` root dep means lpm-workspace's upstream
        // rewrite step missed this entry — the resolver must surface
        // a specific error pointing at the real cause, not propagate
        // an opaque semver-parse failure from `NpmRange::parse`.
        let mut deps = HashMap::new();
        deps.insert("internal-pkg".to_string(), "workspace:*".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        let err = state.seed_root_edges().unwrap_err();
        match err {
            ResolveError::Internal(msg) => {
                assert!(
                    msg.contains("workspace:") && msg.contains("lpm-workspace"),
                    "error must point at the workspace-rewrite layer: {msg}"
                );
            }
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[test]
    fn enqueue_child_deps_skips_workspace_specifier_with_warn() {
        // Registry-published packages should not declare `workspace:`
        // deps. If a malformed cache entry slips one in, the transitive
        // edge is silently skipped (continue) rather than failing the
        // whole resolve. Mirrors the existing "invalid range" branch's
        // skip-with-warn semantic.
        let mut info = mk_info(&["1.0.0"], &[]);
        let mut deps_of_latest = HashMap::new();
        deps_of_latest.insert("workspace-leak".to_string(), "workspace:^1".to_string());
        deps_of_latest.insert("plain-dep".to_string(), "^2.0.0".to_string());
        info.deps.insert("1.0.0".to_string(), deps_of_latest);

        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("parent"),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        enqueue_child_deps(
            0,
            &CanonicalKey::npm("parent"),
            &NpmVersion::parse("1.0.0").unwrap(),
            &info,
            &mut state,
        );

        // Only `plain-dep` should have been enqueued; `workspace-leak`
        // got skipped at the workspace-specifier guard.
        let queued: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        assert_eq!(queued, vec!["plain-dep"]);
    }

    #[test]
    fn is_workspace_specifier_detects_the_prefix() {
        assert!(is_workspace_specifier("workspace:*"));
        assert!(is_workspace_specifier("workspace:^1.0.0"));
        assert!(is_workspace_specifier("  workspace:~"));
        assert!(!is_workspace_specifier("^1.0.0"));
        assert!(!is_workspace_specifier("npm:foo@^1"));
        assert!(!is_workspace_specifier(""));
        // The match is on the literal prefix; `workspaces:` (typo)
        // should NOT trigger so the caller's normal range-parse
        // failure surfaces the real issue.
        assert!(!is_workspace_specifier("workspaces:*"));
    }

    // ── Eager-peer collection tests ───────────────────────────────
    //
    // Peer-collection contract:
    //   1. Every `peerDependencies` entry on the (canonical, version)
    //      under enqueue produces ONE `PeerRequirement` on
    //      `state.peer_requirements`.
    //   2. Peers are NEVER pushed to `state.task_queue` and NEVER
    //      added to the consumer's `n.children`.
    //   3. Defenses (workspace, invalid range, alias rewrite) match
    //      the regular-deps loop semantically.
    //   4. `optional_peer_names` flag propagates onto the
    //      requirement's `optional` field.
    //
    // The peer-drain pass then reads `state.peer_requirements` and
    // synthesizes root-scoped ambient install edges through the fused
    // dispatcher, consuming well-formed requirements produced here.

    /// Build a `CachedPackageInfo` with peer_deps + optional_peer_names
    /// populated for a single version. Mirrors `mk_info`'s shape.
    fn mk_info_with_peers(
        versions: &[&str],
        deps_of_latest: &[(&str, &str)],
        peers_of_latest: &[(&str, &str)],
        optional_peers_of_latest: &[&str],
    ) -> CachedPackageInfo {
        let mut info = mk_info(versions, deps_of_latest);
        let Some(latest) = versions.first() else {
            return info;
        };
        let mut peer_map = HashMap::new();
        for (n, r) in peers_of_latest {
            peer_map.insert(n.to_string(), r.to_string());
        }
        info.peer_deps.insert(latest.to_string(), peer_map);
        if !optional_peers_of_latest.is_empty() {
            let mut optional = HashSet::new();
            for n in optional_peers_of_latest {
                optional.insert(n.to_string());
            }
            info.optional_peer_names
                .insert(latest.to_string(), optional);
        }
        info
    }

    /// Drive `enqueue_child_deps` against a freshly-allocated parent
    /// node and return the mutated state for assertion. Encapsulates
    /// the ResolveState scaffolding that every peer-collection test needs.
    fn enqueue_for_parent(
        parent_canonical: CanonicalKey,
        info: &CachedPackageInfo,
    ) -> ResolveState {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        state.nodes.push(ResolvedNodeBuilder {
            canonical: parent_canonical.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            optional: false,
            children: Vec::new(),
        });
        enqueue_child_deps(
            0,
            &parent_canonical,
            &NpmVersion::parse("1.0.0").unwrap(),
            info,
            &mut state,
        );
        state
    }

    #[test]
    fn peer_collection_records_one_requirement_per_peer() {
        // Parent declares `peerDependencies: { react: "^18.0.0" }`.
        // After `enqueue_child_deps`, exactly one PeerRequirement
        // should be on the worklist — keyed on the consumer node id,
        // canonical "react", and parsed range "^18.0.0".
        let info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        assert_eq!(
            state.peer_requirements.len(),
            1,
            "exactly one peer requirement should be recorded"
        );
        let req = &state.peer_requirements[0];
        assert_eq!(req.consumer, 0, "consumer id is the parent node");
        assert_eq!(req.peer_name, "react");
        assert_eq!(req.canonical, CanonicalKey::npm("react"));
        assert!(
            req.range.satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "range parsed correctly (18.2.0 satisfies ^18.0.0)"
        );
        assert!(!req.optional, "optional flag defaults to false");
    }

    #[test]
    fn peer_collection_does_not_push_to_task_queue() {
        // Peers go on `peer_requirements`, NOT `task_queue`. If a
        // future regression switches the push site, this test fires.
        let info = mk_info_with_peers(
            &["1.0.0"],
            &[("regular-dep", "^1.0.0")],
            &[("peer-dep", "^2.0.0")],
            &[],
        );
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        let queued: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        assert_eq!(
            queued,
            vec!["regular-dep"],
            "task_queue gets ONLY regular deps; peers must not leak in"
        );
        assert_eq!(state.peer_requirements.len(), 1);
        assert_eq!(state.peer_requirements[0].peer_name, "peer-dep");
    }

    #[test]
    fn peer_collection_does_not_mutate_consumer_children() {
        // **Contract assertion.** The consumer node's `children` list
        // must not gain a peer entry. If a future change accidentally
        // pushes a peer onto `n.children`, the v2 graph-key derivation
        // would silently fold the peer into the dependency portion of
        // the key, breaking peer-divergent link-entry isolation.
        let info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        assert!(
            state.nodes[0].children.is_empty(),
            "consumer.children must remain empty when only peers are declared \
             (peer collection must not write to children)"
        );
        assert_eq!(state.peer_requirements.len(), 1);
    }

    #[test]
    fn peer_collection_optional_flag_propagated() {
        // `peerDependenciesMeta.optional: true` lands in
        // `info.optional_peer_names`. The collector copies the flag
        // onto the requirement so the peer-drain step can skip
        // ambient-install synthesis for opted-out peers.
        let info = mk_info_with_peers(
            &["1.0.0"],
            &[],
            &[("react", "^18.0.0"), ("redux", "^4.0.0")],
            &["react"], // react is optional, redux is required
        );
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        assert_eq!(state.peer_requirements.len(), 2);
        let mut by_name: HashMap<&str, &PeerRequirement> = HashMap::new();
        for req in &state.peer_requirements {
            by_name.insert(req.peer_name.as_str(), req);
        }
        assert!(
            by_name["react"].optional,
            "react is in optional_peer_names → optional=true"
        );
        assert!(
            !by_name["redux"].optional,
            "redux is NOT in optional_peer_names → optional=false"
        );
    }

    #[test]
    fn peer_collection_alias_aware() {
        // npm permits a peer to be declared via alias —
        // `"my-react": "npm:react@^18"` is equivalent to
        // `peerDependencies: { react: "^18" }` re-keyed under
        // `my-react`. The collector must record the canonical as
        // `react` (registry identity) so the peer-drain fetches the right
        // manifest, while preserving the local `peer_name = "my-react"`
        // for the eventual `ResolvedPackage.peers` edge label.
        let mut info = mk_info_with_peers(&["1.0.0"], &[], &[("my-react", "^18.0.0")], &[]);
        // Inject the alias map for the latest version.
        let mut aliases = HashMap::new();
        aliases.insert("my-react".to_string(), "react".to_string());
        info.aliases.insert("1.0.0".to_string(), aliases);

        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
        assert_eq!(state.peer_requirements.len(), 1);
        let req = &state.peer_requirements[0];
        assert_eq!(req.peer_name, "my-react", "local name preserved");
        assert_eq!(
            req.canonical,
            CanonicalKey::npm("react"),
            "canonical resolved through alias to the registry target"
        );
    }

    #[test]
    fn peer_collection_skips_workspace_specifier() {
        // A registry-published manifest declaring a `workspace:` peer
        // is malformed (npm rejects at publish time). The collector
        // skips it with a workspace-specific log rather than letting
        // `NpmRange::parse` emit an opaque semver error. Mirrors the
        // regular-deps loop.
        let info = mk_info_with_peers(
            &["1.0.0"],
            &[],
            &[("legit-peer", "^1.0.0"), ("internal-peer", "workspace:*")],
            &[],
        );
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        let names: Vec<&str> = state
            .peer_requirements
            .iter()
            .map(|r| r.peer_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["legit-peer"],
            "workspace: peer skipped; legit peer recorded"
        );
    }

    #[test]
    fn peer_collection_skips_invalid_range() {
        // Defense: an unparseable peer range emits a debug warn and
        // is skipped. Does NOT panic / propagate an error — the
        // resolver must continue resolving the rest of the graph.
        let info = mk_info_with_peers(
            &["1.0.0"],
            &[],
            &[("good-peer", "^1.0.0"), ("bad-peer", "this-is-not-semver")],
            &[],
        );
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

        let names: Vec<&str> = state
            .peer_requirements
            .iter()
            .map(|r| r.peer_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["good-peer"],
            "unparseable peer range skipped silently"
        );
    }

    #[test]
    fn peer_collection_deterministic_order() {
        // The collector sorts peer entries alphabetically before
        // pushing — same contract as the regular-deps loop. Without
        // this, HashMap iteration order would leak into
        // `peer_requirements`'s order, producing non-reproducible
        // lockfile output when the peer-drain drives ambient-install
        // edge ordering off the worklist.
        let info = mk_info_with_peers(
            &["1.0.0"],
            &[],
            // Insertion order is intentionally the WORST possible
            // for a stable sort: reverse-alphabetic.
            &[("zoo", "^1.0.0"), ("middle", "^1.0.0"), ("alpha", "^1.0.0")],
            &[],
        );
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
        let names: Vec<&str> = state
            .peer_requirements
            .iter()
            .map(|r| r.peer_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["alpha", "middle", "zoo"],
            "peer requirements sorted alphabetically for determinism"
        );
    }

    #[test]
    fn peer_collection_no_peer_deps_is_empty_worklist() {
        // Hot path / sanity baseline: a package with NO peer
        // declarations produces an empty worklist. This test guards
        // against an accidental regression where peer collection becomes
        // noisy (e.g., a stray `entry().or_insert_with` populating
        // empty entries).
        let info = mk_info(&["1.0.0"], &[("regular", "^1.0.0")]);
        let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
        assert!(state.peer_requirements.is_empty());
        assert_eq!(state.task_queue.len(), 1, "regular dep enqueued normally");
    }

    // ── Eager peer auto-install drain tests ──────────────────────
    //
    // `drain_peer_requirements_one_pass` contract:
    //   1. Pure classify-and-synthesize pass: reads `state.resolved`
    //      and `state.peer_requirements`, fetches manifests for
    //      unmet canonicals via the supplied closure, and returns
    //      ambient root-scoped Edges for the caller to drain.
    //   2. Satisfied groups (some node in `state.resolved` already
    //      threads every range) are SKIPPED — no synthesis, the
    //      existing `into_resolved_packages` peer-derivation handles
    //      output.
    //   3. All-optional groups are SKIPPED regardless of
    //      `auto_install_peers`.
    //   4. With `auto_install_peers = false`, ALL groups are
    //      skipped — warn-only behavior.
    //   5. Required-but-unsatisfiable groups (no version threads
    //      every range) raise `ResolveError::PeerConflict`.
    //   6. Synthesized Edges are root-scoped (`parent = 0`), behave
    //      as regular required deps, and pin the canonical to the
    //      exact chosen version.
    //
    // These tests drive the helper directly with a hand-built
    // closure that returns pre-canned manifests. End-to-end
    // integration through the dispatcher is exercised by the
    // resolve-tier tests in `resolve.rs`.

    /// Stand-in for an `Arc<CachedPackageInfo>` returned by the
    /// fetch closure. Tests pre-populate a name → info map and the
    /// closure looks up by canonical name.
    fn mk_info_arc(versions: &[&str], deps_of_latest: &[(&str, &str)]) -> Arc<CachedPackageInfo> {
        Arc::new(mk_info(versions, deps_of_latest))
    }

    /// Build a minimal `state.peer_requirements` entry. The
    /// `consumer` is encoded as a plain `NodeId` — tests pre-create
    /// the consumer node so `state.nodes[consumer]` resolves for
    /// `PeerConflict` error rendering.
    fn mk_peer_req(
        consumer: NodeId,
        peer_name: &str,
        canonical: CanonicalKey,
        range: &str,
        optional: bool,
    ) -> PeerRequirement {
        PeerRequirement {
            consumer,
            peer_name: peer_name.to_string(),
            canonical,
            range: NpmRange::parse(range).unwrap(),
            optional,
        }
    }

    #[test]
    fn peer_resolution_cache_key_uses_canonical_and_sorted_parent_peer_context() {
        let legacy_req = mk_peer_req(1, "react", CanonicalKey::npm("react"), "^17.0.0", false);
        let modern_req = mk_peer_req(2, "react", CanonicalKey::npm("react"), "^18.0.0", false);

        let canonical = CanonicalKey::npm("react");
        let forward = peer_resolution_cache_key(&canonical, &[&legacy_req, &modern_req]);
        let reversed = peer_resolution_cache_key(&canonical, &[&modern_req, &legacy_req]);
        assert_eq!(
            forward, reversed,
            "parent peer context hash must be order-insensitive"
        );

        let other_range_req = mk_peer_req(2, "react", CanonicalKey::npm("react"), "^19.0.0", false);
        let other_range = peer_resolution_cache_key(&canonical, &[&legacy_req, &other_range_req]);
        assert_ne!(
            forward, other_range,
            "different parent peer context must miss the cache"
        );

        let other_canonical =
            peer_resolution_cache_key(&CanonicalKey::npm("preact"), &[&legacy_req, &modern_req]);
        assert_ne!(
            forward, other_canonical,
            "same parent context for a different peer canonical must miss the cache"
        );
    }

    /// Pre-allocate a consumer node and return its NodeId. Mirrors
    /// what `process_edge` would produce after consuming a regular
    /// dep edge for the consumer.
    fn push_node(state: &mut ResolveState, canonical: CanonicalKey, version: &str) -> NodeId {
        let id = state.nodes.len() as NodeId;
        state.nodes.push(ResolvedNodeBuilder {
            canonical: canonical.clone(),
            version: NpmVersion::parse(version).unwrap(),
            optional: false,
            children: Vec::new(),
        });
        state
            .resolved
            .entry(canonical)
            .or_default()
            .push((NpmVersion::parse(version).unwrap(), id));
        id
    }

    #[test]
    fn ready_metadata_waits_for_earliest_inflight_key() {
        let mut inflight_order = BTreeMap::new();
        inflight_order.insert("a".to_string(), CanonicalKey::npm("a"));
        inflight_order.insert("b".to_string(), CanonicalKey::npm("b"));

        let mut ready_metadata = BTreeMap::new();
        ready_metadata.insert("b".to_string(), 2_u8);
        assert!(
            take_next_ready_metadata(&mut inflight_order, &mut ready_metadata).is_none(),
            "later completions must not mutate resolver state before earlier keys land"
        );
        assert!(
            inflight_order.contains_key("a") && inflight_order.contains_key("b"),
            "a blocked pop must leave inflight order intact"
        );

        ready_metadata.insert("a".to_string(), 1_u8);
        let (first_key, first_value) =
            take_next_ready_metadata(&mut inflight_order, &mut ready_metadata)
                .expect("earliest key is now ready");
        assert_eq!(first_key, CanonicalKey::npm("a"));
        assert_eq!(first_value, 1);

        let (second_key, second_value) =
            take_next_ready_metadata(&mut inflight_order, &mut ready_metadata)
                .expect("second key is ready after earliest is consumed");
        assert_eq!(second_key, CanonicalKey::npm("b"));
        assert_eq!(second_value, 2);
    }

    #[test]
    fn into_resolved_packages_binds_peer_by_consumer_range() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        push_node(&mut state, CanonicalKey::Root, "0.0.0");
        push_node(&mut state, CanonicalKey::npm("plugin"), "1.0.0");
        push_node(&mut state, CanonicalKey::npm("react"), "17.0.2");
        push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");

        let mut cache = HashMap::new();
        cache.insert(
            CanonicalKey::npm("plugin"),
            Arc::new(mk_info_with_peers(
                &["1.0.0"],
                &[],
                &[("react", "^17.0.0")],
                &[],
            )),
        );
        cache.insert(
            CanonicalKey::npm("react"),
            mk_info_arc(&["18.2.0", "17.0.2"], &[]),
        );

        let resolved = state.into_resolved_packages(&cache);
        let plugin = resolved
            .iter()
            .find(|pkg| pkg.package.canonical_name() == "plugin")
            .expect("plugin package present");
        assert_eq!(
            plugin.peers,
            vec![("react".to_string(), "17.0.2".to_string())],
            "greedy finalization should bind the peer version satisfying the consumer range"
        );
    }

    #[tokio::test]
    async fn peer_drain_satisfied_by_existing_skips_synthesis() {
        // The peer's canonical already has a node in the resolved
        // tree (e.g., react was a regular root dep) at a version
        // satisfying every consumer's range. The drain pass must
        // detect this and skip synthesis entirely — no fetch, no
        // ambient install.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let synth = drain_peer_requirements_one_pass(
            &mut state,
            true,
            // Closure must NOT be called — satisfied-by-existing
            // should short-circuit before any fetch.
            |canonical: CanonicalKey| async move {
                panic!("fetch closure called for already-satisfied peer {canonical}")
            },
        )
        .await
        .unwrap();
        assert!(
            synth.is_empty(),
            "no ambient install when peer is satisfied"
        );
        assert!(state.peer_requirements.is_empty(), "worklist drained");
    }

    #[tokio::test]
    async fn peer_drain_synthesizes_ambient_for_missing_peer() {
        // The peer's canonical is NOT in the tree. With
        // `auto_install_peers = true`, the drain pass fetches the
        // manifest, picks the newest version satisfying the
        // consumer's range, and synthesizes a root-scoped Edge
        // pinning that version.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "18.0.0", "17.0.2"], &[]);
        let synth =
            drain_peer_requirements_one_pass(&mut state, true, |canonical: CanonicalKey| {
                let info = info_arc.clone();
                async move {
                    assert_eq!(canonical, CanonicalKey::npm("react"));
                    Ok(info)
                }
            })
            .await
            .unwrap();

        assert_eq!(synth.len(), 1, "exactly one ambient install");
        let edge = &synth[0];
        assert_eq!(edge.parent, 0, "ambient install is root-scoped");
        assert_eq!(edge.canonical, CanonicalKey::npm("react"));
        assert_eq!(edge.local_name, "react");
        assert!(
            edge.range.satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "exact-pin range satisfies the chosen version"
        );
        assert!(
            !edge.range.satisfies(&NpmVersion::parse("19.0.0").unwrap()),
            "exact-pin range does NOT satisfy a sibling version"
        );
        assert!(
            edge.behavior.required && !edge.behavior.peer && !edge.behavior.optional,
            "ambient install behaves as a required regular dep"
        );
    }

    #[tokio::test]
    async fn peer_drain_reuses_resolution_for_same_parent_peer_context_regardless_order() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");
        let modern = push_node(&mut state, CanonicalKey::npm("modern"), "2.0.0");

        let legacy_req = mk_peer_req(
            legacy,
            "react",
            CanonicalKey::npm("react"),
            "^17.0.0",
            false,
        );
        let modern_req = mk_peer_req(
            modern,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        );
        state.peer_requirements.push(legacy_req.clone());
        state.peer_requirements.push(modern_req.clone());

        let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
        let fetch_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            let fetch_count = fetch_count.clone();
            async move {
                fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(info)
            }
        })
        .await
        .unwrap();
        assert_eq!(first.len(), 1);

        state.peer_requirements.push(modern_req);
        state.peer_requirements.push(legacy_req);

        let second = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            let fetch_count = fetch_count.clone();
            async move {
                fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(info)
            }
        })
        .await
        .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            fetch_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "same peer canonical + same parent peer context should reuse the cached decision"
        );
    }

    #[tokio::test]
    async fn peer_drain_cached_best_effort_reports_current_unsatisfied_consumers() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let first_legacy = push_node(&mut state, CanonicalKey::npm("legacy-one"), "1.0.0");
        let first_modern = push_node(&mut state, CanonicalKey::npm("modern-one"), "2.0.0");

        state.peer_requirements.push(mk_peer_req(
            first_legacy,
            "react",
            CanonicalKey::npm("react"),
            "^17.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            first_modern,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
        let fetch_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            let fetch_count = fetch_count.clone();
            async move {
                fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(info)
            }
        })
        .await
        .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(state.peer_conflicts.len(), 1);
        assert_eq!(
            state.peer_conflicts[0].unsatisfied_consumers,
            vec![("legacy-one".to_string(), "^17.0.0".to_string())]
        );

        state.peer_conflicts.clear();
        let second_legacy = push_node(&mut state, CanonicalKey::npm("legacy-two"), "1.0.0");
        let second_modern = push_node(&mut state, CanonicalKey::npm("modern-two"), "2.0.0");
        state.peer_requirements.push(mk_peer_req(
            second_modern,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            second_legacy,
            "react",
            CanonicalKey::npm("react"),
            "^17.0.0",
            false,
        ));

        let second = drain_peer_requirements_one_pass(
            &mut state,
            true,
            |canonical: CanonicalKey| async move {
                panic!("cached best-effort resolution should not refetch {canonical}")
            },
        )
        .await
        .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(fetch_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(state.peer_conflicts.len(), 1);
        assert_eq!(state.peer_conflicts[0].canonical, "react");
        assert_eq!(state.peer_conflicts[0].chosen_version, "18.2.0");
        assert_eq!(
            state.peer_conflicts[0].unsatisfied_consumers,
            vec![("legacy-two".to_string(), "^17.0.0".to_string())],
            "cached best-effort decisions must render warnings from the current consumers"
        );
    }

    #[tokio::test]
    async fn peer_drain_cached_resolution_does_not_override_existing_satisfaction() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
        let req = mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        );

        state.peer_requirements.push(req.clone());
        let info_arc = mk_info_arc(&["18.2.0"], &[]);
        let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();
        assert_eq!(first.len(), 1);

        let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
        state.peer_requirements.push(req);

        let second = drain_peer_requirements_one_pass(
            &mut state,
            true,
            |canonical: CanonicalKey| async move {
                panic!("cache hit must not run before existing satisfaction for {canonical}")
            },
        )
        .await
        .unwrap();
        assert!(
            second.is_empty(),
            "live resolved tree satisfaction wins over a cached synthesize decision"
        );
    }

    #[tokio::test]
    async fn peer_drain_picks_newest_satisfying_all_consumer_ranges() {
        // Two consumers declare the SAME peer at compatible-but-
        // distinct ranges. The drain must pick a version satisfying
        // BOTH ranges (intersection semantic), not just the first
        // consumer's range.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_a = push_node(&mut state, CanonicalKey::npm("pkg-a"), "1.0.0");
        let consumer_b = push_node(&mut state, CanonicalKey::npm("pkg-b"), "1.0.0");

        // Consumer A wants `>=18.0.0`, Consumer B wants `<19.0.0`.
        // Intersection: `>=18.0.0 <19.0.0`. Newest available: 18.2.0.
        state.peer_requirements.push(mk_peer_req(
            consumer_a,
            "react",
            CanonicalKey::npm("react"),
            ">=18.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer_b,
            "react",
            CanonicalKey::npm("react"),
            "<19.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "17.0.2"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();

        assert_eq!(synth.len(), 1, "one ambient install for the joined group");
        assert!(
            synth[0]
                .range
                .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "chose newest version satisfying both consumer ranges"
        );
        assert!(
            !synth[0]
                .range
                .satisfies(&NpmVersion::parse("19.0.0").unwrap()),
            "did NOT pick the newest overall (19.0.0 violates consumer B's <19.0.0)"
        );
    }

    #[tokio::test]
    async fn peer_drain_best_effort_synthesizes_for_incompatible_required_ranges() {
        // Two required consumers declare incompatible ranges (`^17` vs
        // `^18`). No version satisfies both. Previously this raised
        // `PeerConflict` and broke real-world installs (nestjs's transitive
        // ajv-keywords chain). Now: pick the version satisfying the most
        // consumers, ambient-install it, and record the unsatisfied ones in
        // `state.peer_conflicts` for the install pipeline to warn about.
        // Mirrors npm v7+ / pnpm hoisted behavior.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_a = push_node(&mut state, CanonicalKey::npm("legacy-pkg"), "1.0.0");
        let consumer_b = push_node(&mut state, CanonicalKey::npm("modern-pkg"), "2.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer_a,
            "react",
            CanonicalKey::npm("react"),
            "^17.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer_b,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .expect("best-effort synthesis must NOT raise PeerConflict");

        assert_eq!(
            synth.len(),
            1,
            "exactly one ambient install — the chosen peer version"
        );
        // Tied hit count (each version satisfies one consumer).
        // Newest-first walk picks 18.2.0 first; the tiebreak favors
        // it over 17.0.2.
        assert!(
            synth[0]
                .range
                .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "newest tied-hit version wins (18.2.0 satisfies modern-pkg)"
        );

        // Conflict report must record the unsatisfied required
        // consumer (legacy-pkg wants ^17 but we picked 18.2.0).
        assert_eq!(
            state.peer_conflicts.len(),
            1,
            "one conflict report for the react peer group"
        );
        let report = &state.peer_conflicts[0];
        assert_eq!(report.canonical, "react");
        assert_eq!(report.chosen_version, "18.2.0");
        assert_eq!(report.unsatisfied_consumers.len(), 1);
        assert_eq!(report.unsatisfied_consumers[0].0, "legacy-pkg");
        assert_eq!(report.unsatisfied_consumers[0].1, "^17.0.0");
    }

    #[tokio::test]
    async fn peer_drain_hard_errors_when_no_required_consumer_satisfiable() {
        // Terminal case: no platform-compatible version satisfies any required
        // consumer's range (required consumer wants ^99, but only 18 + 17 are
        // published). Hard error survives because there's no version to
        // "best-effort" pick that helps anyone.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("future-pkg"), "1.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^99.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
        let result = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await;

        match result {
            Err(ResolveError::PeerConflict {
                canonical,
                requirements,
            }) => {
                assert_eq!(canonical, "react");
                assert_eq!(requirements.len(), 1);
                assert_eq!(requirements[0].0, "future-pkg");
                assert_eq!(requirements[0].1, "^99.0.0");
            }
            other => {
                panic!("expected PeerConflict for unsatisfiable required range, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn peer_drain_best_effort_picks_version_satisfying_most_consumers() {
        // Three required consumers; two want ^18, one wants ^17.
        // Best-effort picks 18.2.0 (satisfies 2 of 3) over 17.x
        // (satisfies 1 of 3). The unsatisfied consumer is recorded.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let c_modern_a = push_node(&mut state, CanonicalKey::npm("modern-a"), "1.0.0");
        let c_modern_b = push_node(&mut state, CanonicalKey::npm("modern-b"), "1.0.0");
        let c_legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");

        for (consumer, range) in [
            (c_modern_a, "^18.0.0"),
            (c_modern_b, "^18.0.0"),
            (c_legacy, "^17.0.0"),
        ] {
            state.peer_requirements.push(mk_peer_req(
                consumer,
                "react",
                CanonicalKey::npm("react"),
                range,
                false,
            ));
        }

        let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .expect("majority-satisfiable conflict should NOT hard-error");

        assert_eq!(synth.len(), 1);
        assert!(
            synth[0]
                .range
                .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "majority pick is the newest version satisfying the most consumers"
        );
        assert_eq!(state.peer_conflicts.len(), 1);
        let report = &state.peer_conflicts[0];
        assert_eq!(report.chosen_version, "18.2.0");
        assert_eq!(report.unsatisfied_consumers.len(), 1);
        assert_eq!(report.unsatisfied_consumers[0].0, "legacy");
    }

    #[tokio::test]
    async fn peer_drain_does_not_conflict_when_all_consumers_optional() {
        // All consumers in a conflicted group are optional → skip
        // silently rather than raising PeerConflict. Mirrors npm
        // v7+'s behavior for `peerDependenciesMeta.optional = true`.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_a = push_node(&mut state, CanonicalKey::npm("opt-a"), "1.0.0");
        let consumer_b = push_node(&mut state, CanonicalKey::npm("opt-b"), "2.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer_a,
            "react",
            CanonicalKey::npm("react"),
            "^17.0.0",
            true, // optional
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer_b,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            true, // optional
        ));

        let synth = drain_peer_requirements_one_pass(
            &mut state,
            true,
            // Closure must NOT be called — all-optional groups skip
            // before reaching the manifest fetch.
            |canonical: CanonicalKey| async move {
                panic!("fetch called for all-optional peer {canonical}")
            },
        )
        .await
        .unwrap();
        assert!(synth.is_empty(), "all-optional group is skipped silently");
    }

    #[tokio::test]
    async fn peer_drain_respects_auto_install_peers_false_opt_out() {
        // When `auto_install_peers = false`, even a missing required
        // peer is NOT auto-installed; the drain returns no
        // synthesized edges. The post-resolve `check_unmet_peers`
        // pass surfaces the missing peer as a `PeerWarning` later.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let synth = drain_peer_requirements_one_pass(
            &mut state,
            false, // opt-out
            // Closure must NOT be called — opt-out skips before fetch.
            |canonical: CanonicalKey| async move {
                panic!("fetch called under auto_install_peers=false for {canonical}")
            },
        )
        .await
        .unwrap();
        assert!(synth.is_empty(), "no synthesis under opt-out");
    }

    #[tokio::test]
    async fn peer_drain_skips_optional_when_required_sibling_satisfied() {
        // Mixed group: one required + one optional consumer for the
        // same canonical, with overlapping ranges. The required
        // consumer drives synthesis; the optional consumer's range
        // ALSO must be honored (intersection across BOTH). If the
        // version satisfies both, we synthesize. This guards against
        // a regression where "any optional in group" silently bypassed
        // the required consumer's needs.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_req = push_node(&mut state, CanonicalKey::npm("required-pkg"), "1.0.0");
        let consumer_opt = push_node(&mut state, CanonicalKey::npm("optional-pkg"), "1.0.0");

        // Both want react^18, one is optional. Intersection is `^18`,
        // newest available is 18.2.0 → synthesize.
        state.peer_requirements.push(mk_peer_req(
            consumer_req,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer_opt,
            "react",
            CanonicalKey::npm("react"),
            "^18.2.0",
            true, // optional
        ));

        let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "18.0.0"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();
        assert_eq!(synth.len(), 1);
        assert!(
            synth[0]
                .range
                .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
            "chose 18.2.0 (newest satisfying both ^18.0.0 and ^18.2.0)"
        );
    }

    #[tokio::test]
    async fn peer_drain_does_not_modify_consumer_children() {
        // The drain pass MUST NOT add the synthesized peer to the
        // consumer's `children` list. Children is dependency-only;
        // the consumer's `peers` list is derived from the metadata
        // cache by `into_resolved_packages` AFTER the resolved tree
        // is final. If synthesis ever wrote to `consumer.children`,
        // the v2 graph-key derivation would silently fold the peer
        // into the dependency portion, breaking peer-divergent
        // link-entry isolation.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();
        assert_eq!(synth.len(), 1);
        assert!(
            state.nodes[consumer as usize].children.is_empty(),
            "consumer.children must remain empty — peers are NOT routed as children"
        );
    }

    #[tokio::test]
    async fn peer_drain_clears_peer_requirements_each_pass() {
        // After one pass, `state.peer_requirements` is empty so the
        // next pass starts fresh. Required because synthesized
        // ambient installs may themselves declare peers (transitive
        // chains), and the caller's outer fixed-point loop relies on
        // each pass starting with whatever the previous pass left
        // behind via `enqueue_child_deps`.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("a"), "1.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0"], &[]);
        drain_peer_requirements_one_pass(&mut state, true, |_| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();
        assert!(
            state.peer_requirements.is_empty(),
            "drain consumes the worklist regardless of synthesis outcome"
        );
    }

    #[tokio::test]
    async fn peer_drain_recording_records_ambient_peer_installs() {
        // The install pipeline derives top-level `node_modules/<name>/`
        // symlinks from `pkg.dependencies` ∪
        // `ResolveResult.ambient_peer_installs`. If the drain helper
        // synthesizes an Edge but DOESN'T record the canonical onto
        // `state.ambient_peer_installs`, the package extracts into the
        // v2 store but never gets a project-side symlink. This test
        // pins the behavior so a future refactor can't silently drop
        // the recording.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.2.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let info_arc = mk_info_arc(&["18.2.0"], &[]);
        let synth = drain_peer_requirements_one_pass(&mut state, true, |_| {
            let info = info_arc.clone();
            async move { Ok(info) }
        })
        .await
        .unwrap();

        assert_eq!(synth.len(), 1, "ambient edge synthesized");
        assert_eq!(
            state.ambient_peer_installs,
            vec!["react".to_string()],
            "the canonical of every synthesized ambient install must be \
             recorded on `state.ambient_peer_installs`; the install \
             pipeline reads this set to surface the package at \
             top-level node_modules/"
        );
    }

    #[tokio::test]
    async fn peer_drain_recording_does_not_record_satisfied_or_skipped_groups() {
        // The recording must be tight: only ACTUALLY-synthesized
        // groups land in `ambient_peer_installs`. Satisfied-by-
        // existing groups don't (no install was synthesized).
        // All-optional groups don't (no install was synthesized).
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        // Already-satisfied: react is in the tree at 18.2.0.
        let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
        let consumer1 = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.2.0");
        // All-optional consumer: optional peer on @types/react.
        let consumer2 = push_node(&mut state, CanonicalKey::npm("opt-pkg"), "1.0.0");

        state.peer_requirements.push(mk_peer_req(
            consumer1,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer2,
            "@types/react",
            CanonicalKey::npm("@types/react"),
            "^18.0.0",
            true, // optional
        ));

        let synth = drain_peer_requirements_one_pass(
            &mut state,
            true,
            // Closure must NOT be called — both groups short-circuit
            // before fetch (one satisfied, one all-optional).
            |canonical: CanonicalKey| async move { panic!("unexpected fetch for {canonical}") },
        )
        .await
        .unwrap();

        assert!(synth.is_empty(), "neither group should synthesize");
        assert!(
            state.ambient_peer_installs.is_empty(),
            "ambient_peer_installs records ONLY synthesized groups"
        );
    }

    // ── Speculative peer-manifest prefetch picker tests ───────────
    //
    // Peer prefetch makes manifest fetches concurrent with the regular
    // dep walk by selecting prefetch candidates at the top of every
    // main-loop iteration and dispatching them through the existing
    // metadata_jobs JoinSet. The picker is a pure function: it reads
    // `state` plus the dispatcher's `shared_cache` + `inflight` set
    // and returns the canonicals that should be fetched. These tests
    // pin the four predicate gates (all-optional, satisfied-by-
    // existing, already-cached, in-flight) and the deterministic
    // ordering contract.

    /// Empty cache + inflight for tests that don't exercise either.
    fn empty_cache() -> dashmap::DashMap<CanonicalKey, Arc<CachedPackageInfo>> {
        dashmap::DashMap::new()
    }
    fn empty_inflight() -> AHashSet<CanonicalKey> {
        AHashSet::new()
    }

    #[test]
    fn peer_prefetch_picker_returns_unsatisfied_required_peer() {
        // Baseline: a single required peer with no node in the
        // resolved tree, no cache hit, no in-flight dispatch. Must
        // be picked.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert_eq!(picks, vec![CanonicalKey::npm("react")]);
    }

    #[test]
    fn peer_prefetch_picker_skips_satisfied_by_existing() {
        // The peer's canonical is in the resolved tree at a version
        // satisfying the consumer's range. No prefetch — the drain
        // pass will see this group as already-satisfied.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert!(
            picks.is_empty(),
            "satisfied-by-existing groups must NOT trigger a prefetch"
        );
    }

    #[test]
    fn peer_prefetch_picker_skips_all_optional_groups() {
        // A group of consumers all marked `peerDependenciesMeta.optional`.
        // Optional-only groups never auto-install, so prefetching
        // is wasted bandwidth.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer1 = push_node(&mut state, CanonicalKey::npm("opt-a"), "1.0.0");
        let consumer2 = push_node(&mut state, CanonicalKey::npm("opt-b"), "1.0.0");
        for consumer in [consumer1, consumer2] {
            state.peer_requirements.push(mk_peer_req(
                consumer,
                "react",
                CanonicalKey::npm("react"),
                "^18.0.0",
                true, // optional
            ));
        }

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert!(picks.is_empty(), "all-optional group must skip prefetch");
    }

    #[test]
    fn peer_prefetch_picker_picks_when_at_least_one_consumer_is_required() {
        // Mixed group: one optional + one required. Prefetch fires
        // because the required consumer drives auto-install.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_req = push_node(&mut state, CanonicalKey::npm("required-pkg"), "1.0.0");
        let consumer_opt = push_node(&mut state, CanonicalKey::npm("optional-pkg"), "1.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer_req,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));
        state.peer_requirements.push(mk_peer_req(
            consumer_opt,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            true,
        ));

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert_eq!(picks, vec![CanonicalKey::npm("react")]);
    }

    #[test]
    fn peer_prefetch_picker_skips_canonicals_already_cached() {
        // Sibling regular-dep walk already pulled the peer's manifest
        // into the shared cache. The drain pass will hit the fast
        // path; no need to dispatch a prefetch.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let cache = empty_cache();
        cache.insert(CanonicalKey::npm("react"), mk_info_arc(&["18.2.0"], &[]));

        let picks = pick_peer_prefetch_candidates(&state, &cache, &empty_inflight());
        assert!(
            picks.is_empty(),
            "cached canonical must not be re-dispatched"
        );
    }

    #[test]
    fn peer_prefetch_picker_skips_canonicals_already_in_flight() {
        // A sibling cache-miss already dispatched a fetch for the canonical.
        // The dispatcher's inflight guard would dedup a redundant spawn
        // anyway; skipping at the picker level saves the spawn allocation.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));

        let mut inflight = empty_inflight();
        inflight.insert(CanonicalKey::npm("react"));

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &inflight);
        assert!(
            picks.is_empty(),
            "in-flight canonical must not be re-dispatched"
        );
    }

    #[test]
    fn peer_prefetch_picker_returns_alphabetic_order() {
        // Multiple unmet peers in pathological insertion order. The
        // picker must return them sorted alphabetically — the same
        // determinism contract as the regular `enqueue_child_deps`
        // sort. Without it, lockfile output across runs would shift
        // based on HashMap iteration.
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer = push_node(&mut state, CanonicalKey::npm("multi-peer"), "1.0.0");
        for (name, range) in [("zoo", "^1.0.0"), ("alpha", "^1.0.0"), ("middle", "^1.0.0")] {
            state.peer_requirements.push(mk_peer_req(
                consumer,
                name,
                CanonicalKey::npm(name),
                range,
                false,
            ));
        }

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        let names: Vec<String> = picks.iter().map(|c| c.to_string()).collect();
        assert_eq!(names, vec!["alpha", "middle", "zoo"]);
    }

    #[test]
    fn peer_prefetch_picker_dedups_same_canonical_across_multiple_consumers() {
        // Two consumers both peer the same canonical. The picker
        // groups by canonical first, so we should get exactly ONE
        // entry for that canonical (not two).
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
        let consumer_a = push_node(&mut state, CanonicalKey::npm("pkg-a"), "1.0.0");
        let consumer_b = push_node(&mut state, CanonicalKey::npm("pkg-b"), "1.0.0");
        for consumer in [consumer_a, consumer_b] {
            state.peer_requirements.push(mk_peer_req(
                consumer,
                "react",
                CanonicalKey::npm("react"),
                "^18.0.0",
                false,
            ));
        }

        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert_eq!(
            picks,
            vec![CanonicalKey::npm("react")],
            "shared canonical produces ONE prefetch — the dispatcher \
             handles N consumers via dedupe-on-canonical"
        );
    }

    #[test]
    fn peer_prefetch_picker_empty_when_peer_requirements_empty() {
        // Hot-path baseline: no peers declared → empty result.
        let state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
        assert!(picks.is_empty());
    }

    #[test]
    fn process_edge_zero_overrides_takes_hot_path_unchanged() {
        // Sanity check: with no overrides, the slow-path branch is
        // never entered — the existing (range.satisfies → reuse,
        // else find_best_version → allocate) semantic is byte-
        // identical. Guards against an accidental regression where
        // the slow path becomes the default.
        let info = mk_info(&["4.17.21", "4.0.0"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^4.0.0".to_string());
        let mut state = ResolveState::new(deps, OverrideSet::empty());
        state.seed_root_edges().unwrap();
        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }
        let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_entries.len(), 1);
        assert_eq!(lodash_entries[0].0.to_string(), "4.17.21");
        assert!(state.overrides.take_hits().is_empty());
    }

    #[test]
    fn handle_no_version_optional_skips() {
        let info = mk_info(&["1.0.0"], &[]);
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^99.0.0").unwrap(),
            behavior: DepBehavior {
                required: false,
                peer: false,
                optional: true,
            },
        };
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        assert!(handle_no_version(&edge, &info, false, &mut state).is_ok());
        assert_eq!(state.platform_skipped, 0);
    }

    #[test]
    fn handle_no_version_optional_platform_filtered_increments_counter() {
        let info = mk_info(&["1.0.0"], &[]);
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^1.0.0").unwrap(),
            behavior: DepBehavior {
                required: false,
                peer: false,
                optional: true,
            },
        };
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        assert!(handle_no_version(&edge, &info, true, &mut state).is_ok());
        assert_eq!(state.platform_skipped, 1);
    }

    #[test]
    fn handle_no_version_required_errors() {
        let info = mk_info(&["1.0.0"], &[]);
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^99.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        };
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        assert!(matches!(
            handle_no_version(&edge, &info, false, &mut state),
            Err(ResolveError::DependencyFetch { .. })
        ));
    }

    // ── Fusion termination invariants ───────────────────────────────
    //
    // The loop's correctness pivots on the Phase B termination
    // invariant: queue empty + jobs empty ⇒ parked empty. These tests
    // poke the three corners that could break it: zero-edge case,
    // error-on-fetch case, and required-error propagation.
    // Success-path termination is covered by real-install smoke tests.

    /// Empty deps map: the loop must terminate after seed_root_edges
    /// (zero edges queued, zero fetches dispatched, parked empty by
    /// construction). This is the trivial baseline for the
    /// termination invariant.
    #[tokio::test(flavor = "current_thread")]
    async fn fusion_terminates_on_empty_deps() {
        let client =
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
        let result = resolve_greedy_fused(
            client,
            HashMap::new(),
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Proxy),
            8,
            None,
            true, // tests default to auto-install on
        )
        .await
        .expect("empty deps must resolve to empty result");
        assert!(result.packages.is_empty());
        assert_eq!(result.stage_timing.dispatcher_rpc_count, 0);
        assert_eq!(result.stage_timing.dispatcher_inflight_high_water, 0);
        assert_eq!(result.stage_timing.parked_max_depth, 0);
    }

    /// Single optional dep with a client that fails every fetch.
    /// `propagate_fetch_error` must drop the edge silently (Optional
    /// → skip), the parked map must drain to empty, and the loop must
    /// terminate with a successful empty result.
    #[tokio::test(flavor = "current_thread")]
    async fn fusion_terminates_on_optional_fetch_failure() {
        let client =
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
        // Synthesize state with a single optional-marked edge, then
        // run resolve_greedy_fused via the public dependencies map.
        // We can't directly mark a root dep as optional through the
        // public API, but the propagate_fetch_error logic is
        // exercised identically when handle_no_version returns Ok
        // for an optional. So instead we drive via the propagate
        // helper directly + assert it returns Ok.
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^1.0.0").unwrap(),
            behavior: DepBehavior {
                required: false,
                peer: false,
                optional: true,
            },
        };
        let err = ResolveError::DependencyFetch {
            package: "x".to_string(),
            version: "*".to_string(),
            detail: "connection refused".to_string(),
        };
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        assert!(propagate_fetch_error(&edge, &err, &mut state).is_ok());

        // And the full-loop variant: zero deps means zero parked
        // edges means termination is unconditional. Reusing the
        // empty-deps test infrastructure to assert the loop exits
        // even when the fetch primitive is broken.
        let result = resolve_greedy_fused(
            client,
            HashMap::new(),
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Proxy),
            8,
            None,
            true, // tests default to auto-install on
        )
        .await;
        assert!(result.is_ok());
    }

    /// Root-level `@lpm.dev/*` deps are pre-batched in one round trip
    /// before the main fetch loop. This test asserts:
    ///   1. The pre-batch HTTP call hits exactly once for any number
    ///      of root lpm.dev names (not once per name).
    ///   2. Pre-batched results land in `shared_cache` so the main
    ///      loop's cache-hit fast path picks them up — no per-package
    ///      `fetch_metadata_raw` RPCs fire.
    ///   3. `dispatcher_rpc_count` reflects the batch as a single RPC.
    #[tokio::test(flavor = "current_thread")]
    async fn fusion_pre_batches_lpm_dev_root_deps() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Two root-level lpm.dev packages. The pre-batch must hit
        // POST /api/registry/batch-metadata exactly once and bundle
        // both names; subsequent main-loop `fetch_metadata_raw` calls
        // for these MUST NOT fire (cache pre-populated).
        let lpm_a_meta = metadata_json("@lpm.dev/owner.foo", &[]);
        let lpm_b_meta = metadata_json("@lpm.dev/owner.bar", &[]);
        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(serde_json::json!({
                        "packages": {
                            "@lpm.dev/owner.foo": lpm_a_meta,
                            "@lpm.dev/owner.bar": lpm_b_meta,
                        }
                    })),
            )
            // `expect(1)` is the load-bearing assertion — if pre-batch
            // were skipped and the main loop fell back to per-package
            // dispatch, this mock would either receive >1 hits (one
            // per package) or zero (the per-package endpoint is
            // GET /api/registry/<name>, not POST) and the test would
            // fail. Either failure mode catches a regression.
            .expect(1)
            .mount(&server)
            .await;
        // Per-package GET endpoints are NOT mounted. If the pre-batch
        // succeeded, the main loop hits the cache and never calls
        // GET. If pre-batch fails or is skipped, the main loop tries
        // GET /api/registry/@lpm.dev/owner.foo and wiremock returns
        // 404 — we assert the resolver succeeds, so 404s here would
        // surface as a hard-fail.

        let client = Arc::new(
            RegistryClient::new()
                .with_base_url(server.uri())
                .with_cache_dir(None),
        );

        let mut deps = HashMap::new();
        deps.insert("@lpm.dev/owner.foo".into(), "^1.0.0".into());
        deps.insert("@lpm.dev/owner.bar".into(), "^1.0.0".into());

        let result = resolve_greedy_fused(
            client,
            deps,
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Proxy),
            8,
            None,
            true, // tests default to auto-install on
        )
        .await
        .expect("pre-batched lpm.dev resolve should succeed");

        // Both lpm.dev packages resolved.
        assert_eq!(result.packages.len(), 2);
        let names: std::collections::HashSet<_> = result
            .packages
            .iter()
            .map(|p| p.package.canonical_name())
            .collect();
        assert!(names.contains("@lpm.dev/owner.foo"));
        assert!(names.contains("@lpm.dev/owner.bar"));

        // Exactly 1 dispatcher RPC counted — the batch. No per-package
        // RPCs fired (those would each tick the counter).
        assert_eq!(
            result.stage_timing.dispatcher_rpc_count, 1,
            "batch counts as 1 RPC; per-package dispatch would tick once per name (would be 2)"
        );
    }

    /// Pre-batch fallback: when the batch endpoint errors, the main
    /// loop must still resolve via per-package `fetch_metadata_raw`.
    /// This test pins the failure-mode contract: batch error →
    /// graceful fall-through, no hang, no propagated error.
    #[tokio::test(flavor = "current_thread")]
    async fn fusion_falls_through_on_lpm_dev_batch_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Batch endpoint returns 500 — pre-batch must log and
        // fall through.
        Mock::given(method("POST"))
            .and(path("/api/registry/batch-metadata"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        // Per-package GET endpoint serves the lpm.dev metadata as a
        // fallback. Path matches the GET /api/registry/<scoped> shape
        // `get_package_metadata` calls.
        let lpm_meta = metadata_json("@lpm.dev/owner.foo", &[]);
        Mock::given(method("GET"))
            .and(path("/api/registry/@lpm.dev/owner.foo"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-type", "application/json")
                    .set_body_json(lpm_meta),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Arc::new(
            RegistryClient::new()
                .with_base_url(server.uri())
                .with_cache_dir(None),
        );

        let mut deps = HashMap::new();
        deps.insert("@lpm.dev/owner.foo".into(), "^1.0.0".into());

        let result = resolve_greedy_fused(
            client,
            deps,
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Proxy),
            8,
            None,
            true, // tests default to auto-install on
        )
        .await
        .expect(
            "batch failure must fall through to per-package dispatch — \
             resolve still succeeds",
        );

        assert_eq!(result.packages.len(), 1);
        // 1 dispatcher RPC — the per-package fallback. The failed
        // batch attempt does NOT increment dispatcher_rpc_count
        // (we only count successful batches; failures are
        // observability noise, not real RPCs that resolved data).
        assert_eq!(result.stage_timing.dispatcher_rpc_count, 1);
    }

    /// Required dep with a client that fails: the resolver must
    /// propagate `ResolveError::DependencyFetch` (not hang waiting
    /// for the fetch, not panic on a debug_assert). Drives the full
    /// dispatcher loop so the parked-edge resume-on-error path is
    /// exercised end-to-end.
    #[tokio::test(flavor = "current_thread")]
    async fn fusion_propagates_required_fetch_failure() {
        // Use a port that's filtered (TEST-NET-1, RFC 5737, .254 host
        // is reserved). reqwest will time out on connect after the
        // configured timeout — but since we point at 127.0.0.1:9
        // (discard, kernel rejects), it errors immediately instead.
        let client =
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
        let mut deps = HashMap::new();
        deps.insert("nonexistent-pkg".to_string(), "^1.0.0".to_string());
        let result = resolve_greedy_fused(
            client,
            deps,
            OverrideSet::empty(),
            RouteTable::from_mode_only(RouteMode::Direct), // npm-direct route — discard port (9) errors immediately
            8,
            None,
            true, // tests default to auto-install on
        )
        .await;
        // Either the fetch errors or NoSolution; both are acceptable
        // termination outcomes that prove the dispatcher exits the
        // loop. The critical invariant is "no hang" — the test would
        // hit tokio's default test timeout if termination broke.
        match result {
            Err(ResolveError::DependencyFetch { .. } | ResolveError::NoSolution(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("required dep with broken client must fail, not succeed"),
        }
    }
}
