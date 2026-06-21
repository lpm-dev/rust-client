use super::edge::process_edge_with_preferred;
use super::manifest::{
    FetchResult, FetchedMetadata, complete_metadata_fetch,
    ensure_policy_metadata_for_cached_manifest, fetch_metadata_for_resolver_with_trace_detail,
    parse_fetched_metadata,
};
use super::peer::{drain_peer_requirements_one_pass, pick_peer_prefetch_candidates};
use super::prelude::*;
use super::state::ResolveState;
use super::tree_policy::{TreeManifestProvider, preferred_tree_compatible_version};
use super::types::Edge;
use crate::resolve::SelectedPackageEvent;
use std::cell::Cell;

struct FusedTreeProvider<'a> {
    client: &'a Arc<RegistryClient>,
    route_table: &'a RouteTable,
    shared_cache: &'a SharedCache,
    policy: &'a ResolverPolicy,
    spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    dispatcher_rpc_count: Cell<u64>,
    tarball_dispatched_count: Cell<u64>,
    worker_batch_disabled: &'a Cell<bool>,
    trace_metadata_fetches: bool,
}

struct MetadataFetchDispatch<'a> {
    metadata_sem: &'a Arc<tokio::sync::Semaphore>,
    client: &'a Arc<RegistryClient>,
    route_table: &'a RouteTable,
    policy: &'a ResolverPolicy,
    trace_metadata_fetches: bool,
}

impl TreeManifestProvider for FusedTreeProvider<'_> {
    fn cached_manifest(&self, canonical: &CanonicalKey) -> Option<Arc<CachedPackageInfo>> {
        self.shared_cache
            .get(canonical)
            .map(|entry| entry.value().clone())
    }

    fn ensure_manifest<'a>(
        &'a self,
        canonical: &'a CanonicalKey,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>> + 'a>,
    > {
        Box::pin(async move {
            if let Some(info_arc) = self
                .shared_cache
                .get(canonical)
                .map(|entry| entry.value().clone())
            {
                return ensure_policy_metadata_for_cached_manifest(
                    canonical,
                    info_arc,
                    self.client,
                    self.route_table,
                    self.shared_cache,
                    self.policy,
                    self.trace_metadata_fetches,
                )
                .await;
            }

            let fetched = fetch_metadata_for_resolver_with_trace_detail(
                self.client,
                self.route_table,
                canonical,
                self.policy,
                self.spec_tx.is_some(),
                self.trace_metadata_fetches,
            )
            .await?;
            let FetchedMetadata {
                speculation,
                info: info_arc,
            } = fetched;
            self.shared_cache
                .insert(canonical.clone(), info_arc.clone());
            self.dispatcher_rpc_count
                .set(self.dispatcher_rpc_count.get() + 1);
            if let (Some(tx), Some(speculation)) = (self.spec_tx, speculation)
                && tx.try_send((canonical.to_string(), speculation)).is_ok()
            {
                self.tarball_dispatched_count
                    .set(self.tarball_dispatched_count.get() + 1);
            }
            Ok(info_arc)
        })
    }

    fn prefetch_manifests<'a>(
        &'a self,
        canonicals: &'a [CanonicalKey],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            if self.worker_batch_disabled.get() || canonicals.is_empty() {
                return;
            }

            let mut seen = AHashSet::with_capacity(canonicals.len());
            let mut names = Vec::with_capacity(canonicals.len());
            for canonical in canonicals {
                if self.shared_cache.contains_key(canonical) {
                    continue;
                }
                let CanonicalKey::Npm { name } = canonical else {
                    continue;
                };
                if !matches!(
                    self.route_table.route_for_package(name),
                    UpstreamRoute::LpmWorker
                ) {
                    continue;
                }
                if seen.insert(canonical.clone()) {
                    names.push(name.clone());
                }
            }
            if names.is_empty() {
                return;
            }

            match self.client.batch_metadata_deep(&names).await {
                Ok(batch) => {
                    self.dispatcher_rpc_count
                        .set(self.dispatcher_rpc_count.get() + 1);
                    for (name, meta) in batch {
                        let canonical = crate::package::CanonicalKey::from_dep_name(&name);
                        if matches!(canonical, crate::package::CanonicalKey::Root) {
                            continue;
                        }
                        if !matches!(
                            self.route_table.route_for_package(&name),
                            UpstreamRoute::LpmWorker
                        ) {
                            continue;
                        }
                        let fetched = parse_fetched_metadata(meta, self.spec_tx.is_some());
                        let FetchedMetadata { speculation, info } = fetched;
                        self.shared_cache.insert(canonical.clone(), info);
                        if let (Some(tx), Some(speculation)) = (self.spec_tx, speculation)
                            && tx.try_send((canonical.to_string(), speculation)).is_ok()
                        {
                            self.tarball_dispatched_count
                                .set(self.tarball_dispatched_count.get() + 1);
                        }
                    }
                }
                Err(e) => {
                    self.worker_batch_disabled.set(true);
                    tracing::debug!(
                        "greedy-fusion: Worker tree prefetch batch failed ({} names): {e} \
                         — falling back to per-package dispatch",
                        names.len()
                    );
                }
            }
        })
    }
}

fn spawn_metadata_fetch_job(
    metadata_jobs: &mut tokio::task::JoinSet<(CanonicalKey, FetchResult)>,
    dispatch: &MetadataFetchDispatch<'_>,
    canonical: CanonicalKey,
    include_speculation: bool,
) {
    let client_c = dispatch.client.clone();
    let permit = Arc::clone(dispatch.metadata_sem);
    let route_table_c = dispatch.route_table.clone();
    let policy_c = dispatch.policy.clone();
    let trace_metadata_fetches = dispatch.trace_metadata_fetches;
    metadata_jobs.spawn(async move {
        let _p = permit
            .acquire_owned()
            .await
            .expect("metadata semaphore must outlive the resolver");
        let result = fetch_metadata_for_resolver_with_trace_detail(
            &client_c,
            &route_table_c,
            &canonical,
            &policy_c,
            include_speculation,
            trace_metadata_fetches,
        )
        .await;
        (canonical, result)
    });
}

/// Fused dispatcher: greedy resolver IS the fetch dispatcher. Replaces the
/// walker + resolver two-task model with a single tokio task that drains
/// its work queue synchronously, parks edges on cache misses, and resumes
/// them on manifest land.
///
/// **Three-step loop:**
///
/// - **Queue drain.** Fully synchronous; no `await`.
///   Each edge: cache hit → `process_edge` inline (allocates a node
///   and pushes the new node's child deps as fresh edges); cache miss
///   → park edge by canonical and spawn one fetch per canonical
///   (deduped via the `inflight` set so two parents asking for the
///   same canonical don't double-fetch).
///
/// - **Termination.** Loop exits when both `task_queue` is
///   empty AND `metadata_jobs` has no pending jobs. The invariant
///   `parked.is_empty()` is asserted at this boundary: every parked
///   edge has a corresponding canonical in `inflight`, which mirrors
///   `metadata_jobs`'s pending set, so an empty `metadata_jobs`
///   implies an empty `parked`.
///
/// - **Bounded await.** When neither queue is empty AND no
///   work is locally drainable, await `metadata_jobs.join_next()`.
///   On manifest land: parse, forward raw metadata to install.rs's
///   speculation dispatcher via `spec_tx`, insert into `shared_cache`,
///   and resume parked edges in stable `(parent_id, local_name)` order
///   so multi-version dedupe stays deterministic across runs.
///
/// **Concurrency caps.** A single `npm_fanout` semaphore gates
/// outstanding metadata fetches. Callers tune the fanout for their
/// registry/network regime; tarball downloads run later in install.rs
/// unless a caller explicitly supplies a speculation channel.
///
/// **Counters.** `dispatcher_rpc_count`, `inflight_high_water`,
/// `parked_max_depth`, `tarball_dispatched_count`, and
/// `peer_prefetch_count` (speculative peer prefetch) are populated on
/// `ResolveResult.stage_timing` for `--json` consumption under
/// `timing.resolve.dispatcher.*`. `walker_rpc_count` and
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
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
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
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
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
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
) -> Result<ResolveResult, ResolveError> {
    resolve_greedy_fused_with_cache_options_and_policy(
        client,
        dependencies,
        overrides,
        route_table,
        npm_fanout,
        spec_tx,
        shared_cache,
        auto_install_peers,
        include_optional_dependencies,
        ResolverPolicy::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_greedy_fused_with_cache_options_and_policy(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    policy: ResolverPolicy,
) -> Result<ResolveResult, ResolveError> {
    resolve_greedy_fused_with_cache_options_policy_and_selected_events(
        client,
        dependencies,
        overrides,
        route_table,
        npm_fanout,
        spec_tx,
        shared_cache,
        auto_install_peers,
        include_optional_dependencies,
        policy,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_greedy_fused_with_cache_options_policy_and_selected_events(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    policy: ResolverPolicy,
    selected_package_tx: Option<tokio::sync::mpsc::UnboundedSender<SelectedPackageEvent>>,
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
    let trace_metadata_fetches = lpm_registry::timing::metadata_fetch_detail_enabled();

    let mut state = ResolveState::new_with_options_and_policy(
        dependencies,
        overrides,
        include_optional_dependencies,
        policy.clone(),
    );
    state.set_selected_package_tx(selected_package_tx);
    state.seed_root_edges()?;
    let worker_batch_disabled = Cell::new(false);
    let tree_provider = FusedTreeProvider {
        client: &client,
        route_table: &route_table,
        shared_cache: &shared_cache,
        policy: &policy,
        spec_tx: spec_tx.as_ref(),
        dispatcher_rpc_count: Cell::new(0),
        tarball_dispatched_count: Cell::new(0),
        worker_batch_disabled: &worker_batch_disabled,
        trace_metadata_fetches,
    };
    let tree_status_cache = super::tree_policy::TreeStatusCache::default();

    // Loop-local state, owned by this single task. No Arcs needed
    // around `inflight` / `parked` because they never cross task
    // boundaries — only the spawn closures own clones of the
    // canonicals they're fetching.
    let metadata_sem = Arc::new(tokio::sync::Semaphore::new(npm_fanout));
    let metadata_dispatch = MetadataFetchDispatch {
        metadata_sem: &metadata_sem,
        client: &client,
        route_table: &route_table,
        policy: &policy,
        trace_metadata_fetches,
    };

    // Counters. Declared here so the lpm.dev pre-batch below can
    // increment them before the main loop starts.
    let mut dispatcher_rpc_count: u64 = 0;
    let mut tarball_dispatched_count: u64 = 0;
    // Speculative peer-manifest fetches dispatched concurrent with
    // regular dep dispatch. Bumped by the peer-prefetch step; surfaces on
    // `StageTiming.peer_prefetch_count`.
    let mut peer_prefetch_count: u64 = 0;

    // Pre-batch root deps routed through the LPM Worker in one round trip
    // before the main fetch loop. Without this, each such dep would
    // fire its own [`fetch_metadata_raw`] call inside the dispatcher
    // (~one RPC per package). The walker arm in `walker.rs` already
    // batches Worker-routed names; this pre-pass brings the fused arm to
    // parity and gives Worker-routed npm roots the same metadata fast path.
    //
    // Why pre-resolve, not inside the loop:
    //   - The `shared_cache` fast-path at the top of the queue-drain step short-
    //     circuits any edge whose canonical is already cached, so
    //     populating it BEFORE [`seed_root_edges`]'s edges drain
    //     turns N Worker RPCs into 1.
    //   - `batch_metadata_deep` can return transitive metadata too, so
    //     returned manifests are cached even when they were not direct
    //     roots.
    //
    // Failure-mode contract:
    //   - On batch error (auth/network/server fault), fall through
    //     silently — each root dep will be fetched
    //     individually by the main loop. Slower but correct.
    //   - On per-name parse failure (server returned something we
    //     can't interpret as a CanonicalKey), skip that entry and
    //     let the main loop refetch it.
    let worker_root_names: Vec<String> = state
        .root_deps
        .keys()
        .filter(|name| {
            matches!(
                route_table.route_for_package(name),
                UpstreamRoute::LpmWorker
            )
        })
        .cloned()
        .collect();
    if !worker_root_names.is_empty() {
        match client.batch_metadata_deep(&worker_root_names).await {
            Ok(batch) => {
                // One actual HTTP round trip regardless of
                // batch.len(). The dispatcher_rpc_count metric tracks
                // RPCs (not packages); record exactly 1 for the batch
                // — keeps the metric semantics stable across arms.
                dispatcher_rpc_count += 1;
                for (name, meta) in batch {
                    let canonical = crate::package::CanonicalKey::from_dep_name(&name);
                    if matches!(canonical, crate::package::CanonicalKey::Root) {
                        continue;
                    }
                    if !matches!(
                        route_table.route_for_package(&name),
                        UpstreamRoute::LpmWorker
                    ) {
                        continue;
                    }
                    let fetched = parse_fetched_metadata(meta, spec_tx.is_some());
                    let FetchedMetadata { speculation, info } = fetched;
                    shared_cache.insert(canonical.clone(), info);
                    if let (Some(tx), Some(speculation)) = (spec_tx.as_ref(), speculation)
                        && tx.try_send((canonical.to_string(), speculation)).is_ok()
                    {
                        tarball_dispatched_count += 1;
                    }
                }
            }
            Err(e) => {
                worker_batch_disabled.set(true);
                tracing::debug!(
                    "greedy-fusion: Worker pre-batch failed ({} names): {e} \
                     — falling back to per-package dispatch",
                    worker_root_names.len()
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

    // High-water marks update after each queue-drain pass
    // so the post-loop value reflects the peak across the run, not just the
    // final tick. `dispatcher_rpc_count` and `tarball_dispatched_count` are
    // declared above the lpm.dev pre-batch so it can pre-increment them.
    let mut inflight_high_water: u64 = 0;
    let mut parked_max_depth: u32 = 0;

    loop {
        let mut worker_batch_candidates: Vec<(CanonicalKey, String)> = Vec::new();

        // ── Drain `task_queue` synchronously ─────────────────────
        while let Some(edge) = state.task_queue.pop_front() {
            // Cache hit fast-path. Hot path; one DashMap lookup +
            // refcount bump on the Arc<CachedPackageInfo>. The shard
            // lock is released before `process_edge` mutates state.
            if let Some(info_arc) = shared_cache.get(&edge.canonical).map(|e| e.value().clone()) {
                let info_arc = ensure_policy_metadata_for_cached_manifest(
                    &edge.canonical,
                    info_arc,
                    &client,
                    &route_table,
                    &shared_cache,
                    &policy,
                    trace_metadata_fetches,
                )
                .await?;
                let preferred = preferred_tree_compatible_version(
                    &edge,
                    &info_arc,
                    &policy,
                    &tree_provider,
                    &tree_status_cache,
                )
                .await;
                process_edge_with_preferred(&edge, &info_arc, preferred, &mut state)?;
                continue;
            }
            // Cache miss — park the edge and dispatch one fetch per
            // canonical. Worker-routed npm misses discovered in this
            // drain are grouped into one batch below; direct/custom
            // routes keep the existing per-package fetch path.
            let canonical = edge.canonical.clone();
            parked.entry(canonical.clone()).or_default().push(edge);
            if inflight.insert(canonical.clone()) {
                let include_speculation = spec_tx.is_some();
                let worker_name = match &canonical {
                    CanonicalKey::Npm { name }
                        if !worker_batch_disabled.get()
                            && matches!(
                                route_table.route_for_package(name),
                                UpstreamRoute::LpmWorker
                            ) =>
                    {
                        Some(name.clone())
                    }
                    _ => None,
                };
                if let Some(name) = worker_name {
                    worker_batch_candidates.push((canonical, name));
                } else {
                    spawn_metadata_fetch_job(
                        &mut metadata_jobs,
                        &metadata_dispatch,
                        canonical,
                        include_speculation,
                    );
                    dispatcher_rpc_count += 1;
                }
            }
        }

        if !worker_batch_candidates.is_empty() {
            let worker_names: Vec<String> = worker_batch_candidates
                .iter()
                .map(|(_, name)| name.clone())
                .collect();
            match client.batch_metadata_deep(&worker_names).await {
                Ok(batch) => {
                    dispatcher_rpc_count += 1;
                    let mut returned = AHashSet::with_capacity(batch.len());
                    for (name, meta) in batch {
                        let canonical = crate::package::CanonicalKey::from_dep_name(&name);
                        if matches!(canonical, crate::package::CanonicalKey::Root) {
                            continue;
                        }
                        if !matches!(
                            route_table.route_for_package(&name),
                            UpstreamRoute::LpmWorker
                        ) {
                            continue;
                        }
                        returned.insert(canonical.clone());
                        inflight.remove(&canonical);
                        let fetched = parse_fetched_metadata(meta, spec_tx.is_some());
                        complete_metadata_fetch(
                            canonical,
                            Ok(fetched),
                            &shared_cache,
                            spec_tx.as_ref(),
                            &mut tarball_dispatched_count,
                            &mut parked,
                            &mut state,
                        )?;
                    }

                    for (canonical, _) in worker_batch_candidates {
                        if returned.contains(&canonical) {
                            continue;
                        }
                        spawn_metadata_fetch_job(
                            &mut metadata_jobs,
                            &metadata_dispatch,
                            canonical,
                            spec_tx.is_some(),
                        );
                        dispatcher_rpc_count += 1;
                    }
                    continue;
                }
                Err(e) => {
                    worker_batch_disabled.set(true);
                    tracing::debug!(
                        "greedy-fusion: Worker tail batch failed ({} names): {e} \
                         — falling back to per-package dispatch",
                        worker_batch_candidates.len()
                    );
                    for (canonical, _) in worker_batch_candidates {
                        spawn_metadata_fetch_job(
                            &mut metadata_jobs,
                            &metadata_dispatch,
                            canonical,
                            spec_tx.is_some(),
                        );
                        dispatcher_rpc_count += 1;
                    }
                }
            }
        }

        // ── Speculative peer-manifest prefetch ───────────────────
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
                let include_speculation = spec_tx.is_some();
                spawn_metadata_fetch_job(
                    &mut metadata_jobs,
                    &metadata_dispatch,
                    canonical,
                    include_speculation,
                );
                dispatcher_rpc_count += 1;
                peer_prefetch_count += 1;
            }
        }

        // High-water samples. O(unique-canonicals-parked) per tick;
        // ~tens of entries × ~134 ticks on bench/fixture-large is
        // negligible vs the network wall.
        let inflight_now = inflight.len() as u64;
        if inflight_now > inflight_high_water {
            inflight_high_water = inflight_now;
        }
        if let Some(max_park) = parked.values().map(|v| v.len() as u32).max()
            && max_park > parked_max_depth
        {
            parked_max_depth = max_park;
        }

        // ── Termination invariant + peer-drain hook ──────────────
        // Both queues empty + zero in-flight metadata jobs ⇒ no
        // future edges can appear from the regular dep walk. Before
        // declaring victory, run ONE peer-drain pass: it may
        // synthesize ambient root-scoped install edges for unmet
        // peers, which re-arms the loop. The pass is a no-op when
        // `peer_requirements` is empty OR `auto_install_peers`
        // is false.
        if metadata_jobs.is_empty() && state.task_queue.is_empty() {
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
            // dispatcher because drains run sequentially outside the queue drain.
            let client_drain = client.clone();
            let route_table_drain = route_table.clone();
            let shared_cache_drain = shared_cache.clone();
            let policy_drain = policy.clone();
            let synthesized = drain_peer_requirements_one_pass(
                &mut state,
                auto_install_peers,
                move |canonical: CanonicalKey| {
                    let client = client_drain.clone();
                    let route_table = route_table_drain.clone();
                    let shared_cache = shared_cache_drain.clone();
                    let policy = policy_drain.clone();
                    async move {
                        // Cache hit: refcount bump, return immediately.
                        if let Some(info_arc) =
                            shared_cache.get(&canonical).map(|e| e.value().clone())
                        {
                            return ensure_policy_metadata_for_cached_manifest(
                                &canonical,
                                info_arc,
                                &client,
                                &route_table,
                                &shared_cache,
                                &policy,
                                trace_metadata_fetches,
                            )
                            .await;
                        }
                        // Cache miss: direct fetch + parse + insert.
                        // Peer manifests are typically a small tail
                        // (e.g., react when only react-dom was a
                        // direct dep), so the serial fetch here is
                        // bounded by the count of unmet-peer canonicals
                        // — usually 0–3.
                        let fetched = fetch_metadata_for_resolver_with_trace_detail(
                            &client,
                            &route_table,
                            &canonical,
                            &policy,
                            false,
                            trace_metadata_fetches,
                        )
                        .await?;
                        let info_arc = fetched.info;
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
            // The next drain processes them via the regular cache-hit path
            // (the drain pre-populated `shared_cache` for every
            // canonical it touched).
            for edge in synthesized {
                state.task_queue.push_back(edge);
            }
            continue;
        }

        // ── Bounded await ───────────────────────────────────────
        // metadata_jobs is non-empty here (the termination guard handles the empty case).
        // Take the next completion; deterministic reuse is enforced in
        // process_edge, so the network loop can keep completion-order
        // throughput without making lockfiles arrival-order-dependent.
        if let Some(joined) = metadata_jobs.join_next().await {
            let (canonical, result) = joined
                .map_err(|e| ResolveError::Internal(format!("metadata join failure: {e}")))?;
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
    let policy_snap = crate::profile::policy_summary();
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
            dispatcher_rpc_count: dispatcher_rpc_count + tree_provider.dispatcher_rpc_count.get(),
            dispatcher_inflight_high_water: inflight_high_water,
            parked_max_depth,
            tarball_dispatched_count: tarball_dispatched_count
                + tree_provider.tarball_dispatched_count.get(),
            peer_prefetch_count,
            policy_release_age_ms: policy_snap.release_age.elapsed.as_millis() as u64,
            policy_release_age_checked_count: policy_snap.release_age.checked_count,
            policy_release_age_rejected_count: policy_snap.release_age.rejected_count,
            policy_release_age_missing_count: policy_snap.release_age.missing_count,
            policy_trust_ms: policy_snap.trust_policy.elapsed.as_millis() as u64,
            policy_trust_checked_count: policy_snap.trust_policy.checked_count,
            policy_trust_rejected_count: policy_snap.trust_policy.rejected_count,
        },
    })
}
