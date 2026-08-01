use super::edge::process_edge_with_preferred;
use super::manifest::{
    FetchResult, FetchedMetadata, MetadataFetchCompletion, complete_metadata_fetch,
    ensure_policy_metadata_for_cached_manifest, fetch_metadata_for_resolver_with_trace_detail,
    parse_fetched_metadata, parse_partial_fetched_metadata,
};
use super::peer::{drain_peer_requirements_one_pass, pick_peer_prefetch_candidates};
use super::prelude::*;
use super::state::{PendingRootConstraints, ResolveState, selected_package_cardinality};
use super::tree_policy::{TreeManifestProvider, preferred_tree_compatible_version};
use super::types::{Edge, PeerRequirement};
use crate::resolve::SelectedPackageEvent;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

struct FusedTreeProvider<'a> {
    client: &'a Arc<RegistryClient>,
    route_table: &'a RouteTable,
    shared_cache: &'a SharedCache,
    policy: &'a ResolverPolicy,
    spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    dispatcher_rpc_count: Cell<u64>,
    tarball_dispatched_count: Cell<u64>,
    worker_batch_disabled: &'a Cell<bool>,
    release_age_package_names: &'a [String],
    release_age_all_packages: bool,
    trace_metadata_fetches: bool,
}

struct MetadataFetchDispatch<'a> {
    metadata_sem: &'a Arc<tokio::sync::Semaphore>,
    telemetry: &'a Arc<MetadataFetchTelemetry>,
    client: &'a Arc<RegistryClient>,
    route_table: &'a RouteTable,
    policy: &'a ResolverPolicy,
    trace_metadata_fetches: bool,
}

#[derive(Default)]
struct MetadataFetchTelemetry {
    active: AtomicU64,
    active_high_water: AtomicU64,
    semaphore_wait_count: AtomicU64,
    semaphore_wait_ns: AtomicU64,
}

impl MetadataFetchTelemetry {
    fn enter(self: &Arc<Self>) -> ActiveMetadataFetch {
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.active_high_water.fetch_max(active, Ordering::Relaxed);
        ActiveMetadataFetch {
            telemetry: Arc::clone(self),
        }
    }

    fn record_wait_duration(&self, elapsed: std::time::Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let _ =
            self.semaphore_wait_ns
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(elapsed_ns))
                });
    }
}

struct ActiveMetadataFetch {
    telemetry: Arc<MetadataFetchTelemetry>,
}

impl Drop for ActiveMetadataFetch {
    fn drop(&mut self) {
        self.telemetry.active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn record_pending_high_water(high_water: &mut u64, pending: usize) {
    *high_water = (*high_water).max(u64::try_from(pending).unwrap_or(u64::MAX));
}

struct OrderedMetadataFetches {
    inflight: AHashSet<CanonicalKey>,
    committed: AHashSet<CanonicalKey>,
    sequences: AHashMap<CanonicalKey, u64>,
    ready: BTreeMap<u64, (CanonicalKey, FetchResult, MetadataCompletionSource)>,
    next_dispatch_sequence: u64,
    next_commit_sequence: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MetadataCompletionSource {
    Cached,
    Fetched,
}

impl OrderedMetadataFetches {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            inflight: AHashSet::with_capacity(capacity),
            committed: AHashSet::with_capacity(capacity),
            sequences: AHashMap::with_capacity(capacity),
            ready: BTreeMap::new(),
            next_dispatch_sequence: 0,
            next_commit_sequence: 0,
        }
    }

    fn start(&mut self, canonical: &CanonicalKey) -> Result<bool, ResolveError> {
        if !self.inflight.insert(canonical.clone()) {
            return Ok(false);
        }
        let sequence = self.next_dispatch_sequence;
        self.next_dispatch_sequence = self
            .next_dispatch_sequence
            .checked_add(1)
            .ok_or_else(|| ResolveError::Internal("metadata dispatch sequence overflow".into()))?;
        let previous = self.sequences.insert(canonical.clone(), sequence);
        debug_assert!(previous.is_none());
        Ok(true)
    }

    fn queue_if_tracked(
        &mut self,
        canonical: CanonicalKey,
        result: FetchResult,
    ) -> Result<Option<FetchResult>, ResolveError> {
        self.queue_if_tracked_from(canonical, result, MetadataCompletionSource::Fetched)
    }

    fn queue_if_tracked_from(
        &mut self,
        canonical: CanonicalKey,
        result: FetchResult,
        source: MetadataCompletionSource,
    ) -> Result<Option<FetchResult>, ResolveError> {
        let Some(sequence) = self.sequences.get(&canonical).copied() else {
            return Ok(Some(result));
        };
        if let Some((_, _, existing_source)) = self.ready.get(&sequence) {
            if *existing_source == MetadataCompletionSource::Cached {
                return Ok(None);
            }
            if source == MetadataCompletionSource::Cached {
                self.ready.insert(sequence, (canonical, result, source));
                return Ok(None);
            }
            return Err(ResolveError::Internal(format!(
                "duplicate metadata completion for {canonical}"
            )));
        }
        self.ready.insert(sequence, (canonical, result, source));
        Ok(None)
    }

    fn queue_tracked(
        &mut self,
        canonical: CanonicalKey,
        result: FetchResult,
    ) -> Result<(), ResolveError> {
        match self.queue_if_tracked(canonical.clone(), result)? {
            None => Ok(()),
            Some(_) => Err(ResolveError::Internal(format!(
                "metadata completion without a dispatch sequence for {canonical}"
            ))),
        }
    }

    fn queue_cached_tracked(
        &mut self,
        canonical: CanonicalKey,
        result: FetchResult,
    ) -> Result<(), ResolveError> {
        match self.queue_if_tracked_from(
            canonical.clone(),
            result,
            MetadataCompletionSource::Cached,
        )? {
            None => Ok(()),
            Some(_) => Err(ResolveError::Internal(format!(
                "cached metadata completion without a dispatch sequence for {canonical}"
            ))),
        }
    }

    fn commit_ready(
        &mut self,
        completion: &mut MetadataFetchCompletion<'_>,
    ) -> Result<(), ResolveError> {
        while let Some((canonical, result, _)) = self.ready.remove(&self.next_commit_sequence) {
            let sequence = self.sequences.remove(&canonical);
            debug_assert_eq!(sequence, Some(self.next_commit_sequence));
            let removed = self.inflight.remove(&canonical);
            debug_assert!(removed);
            self.next_commit_sequence =
                self.next_commit_sequence.checked_add(1).ok_or_else(|| {
                    ResolveError::Internal("metadata commit sequence overflow".into())
                })?;
            let succeeded = complete_metadata_fetch(canonical.clone(), result, completion)?;
            if succeeded {
                self.committed.insert(canonical);
            }
        }
        Ok(())
    }

    fn has_committed(&self, canonical: &CanonicalKey) -> bool {
        self.committed.contains(canonical)
    }

    fn inflight(&self) -> &AHashSet<CanonicalKey> {
        &self.inflight
    }

    fn len(&self) -> usize {
        self.inflight.len()
    }

    fn is_empty(&self) -> bool {
        self.inflight.is_empty() && self.sequences.is_empty() && self.ready.is_empty()
    }
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
                ..
            } = fetched;
            insert_or_merge_cached_package_info(
                self.shared_cache,
                canonical.clone(),
                info_arc.clone(),
            );
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

            match self
                .client
                .batch_metadata_deep_with_release_age_packages(
                    &names,
                    self.release_age_package_names,
                    self.release_age_all_packages,
                )
                .await
            {
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
                        let fetched = parse_fetched_metadata(
                            meta,
                            self.spec_tx.is_some(),
                            self.trace_metadata_fetches,
                        );
                        let FetchedMetadata {
                            speculation, info, ..
                        } = fetched;
                        insert_or_merge_cached_package_info(
                            self.shared_cache,
                            canonical.clone(),
                            info,
                        );
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
    let telemetry = Arc::clone(dispatch.telemetry);
    metadata_jobs.spawn(async move {
        let _permit = match Arc::clone(&permit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                telemetry
                    .semaphore_wait_count
                    .fetch_add(1, Ordering::Relaxed);
                let wait_started = Instant::now();
                let permit = permit
                    .acquire_owned()
                    .await
                    .expect("metadata semaphore must outlive the resolver");
                telemetry.record_wait_duration(wait_started.elapsed());
                permit
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                panic!("metadata semaphore must outlive the resolver")
            }
        };
        let _active_fetch = telemetry.enter();
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

fn release_age_names_from_root_deps(
    root_deps: &HashMap<String, String>,
    policy: &ResolverPolicy,
) -> Vec<String> {
    if !policy.release_age_active() {
        return Vec::new();
    }
    let mut names: Vec<String> = root_deps
        .iter()
        .filter_map(|(name, range)| {
            let candidate = crate::ranges::parse_npm_alias(range)
                .map_or_else(|| name.clone(), |alias| alias.target);
            let canonical = CanonicalKey::from_dep_name(&candidate);
            if matches!(&canonical, CanonicalKey::Npm { .. })
                && policy.release_age_applies_to_package(&canonical)
            {
                Some(candidate)
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn worker_range_aware_batch_enabled() -> bool {
    std::env::var("LPM_WORKER_RANGE_AWARE_BATCH").as_deref() == Ok("1")
}

fn worker_streaming_batch_enabled() -> bool {
    std::env::var("LPM_WORKER_STREAMING_BATCH").as_deref() == Ok("1")
}

fn worker_package_specs_from_root_deps(
    root_deps: &HashMap<String, String>,
    route_table: &RouteTable,
) -> Vec<(String, String)> {
    let mut seen = AHashSet::with_capacity(root_deps.len());
    let mut specs = Vec::with_capacity(root_deps.len());
    for (name, range) in root_deps {
        let (package_name, package_range) = crate::ranges::parse_npm_alias(range).map_or_else(
            || (name.clone(), range.clone()),
            |alias| (alias.target, alias.range),
        );
        if !matches!(
            CanonicalKey::from_dep_name(&package_name),
            CanonicalKey::Npm { .. }
        ) {
            continue;
        }
        if !matches!(
            route_table.route_for_package(&package_name),
            UpstreamRoute::LpmWorker
        ) {
            continue;
        }
        if seen.insert((package_name.clone(), package_range.clone())) {
            specs.push((package_name, package_range));
        }
    }
    specs.sort();
    specs
}

fn worker_package_names_from_specs(package_specs: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = package_specs.iter().map(|(name, _)| name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

fn covered_ranges_for_name(package_specs: &[(String, String)], name: &str) -> Vec<String> {
    package_specs
        .iter()
        .filter(|(spec_name, _)| spec_name == name)
        .map(|(_, range)| range.clone())
        .collect()
}

fn extend_covered_ranges_from_metadata(
    package_specs: &mut Vec<(String, String)>,
    metadata: &lpm_registry::PackageMetadata,
) {
    for version in metadata.versions.values() {
        for (name, range) in &version.dependencies {
            push_covered_range(package_specs, name, range);
        }
        for (name, range) in &version.optional_dependencies {
            push_covered_range(package_specs, name, range);
        }
    }
}

fn push_covered_range(package_specs: &mut Vec<(String, String)>, name: &str, range: &str) {
    let (package_name, package_range) = crate::ranges::parse_npm_alias(range).map_or_else(
        || (name.to_string(), range.to_string()),
        |alias| (alias.target, alias.range),
    );
    if !matches!(
        CanonicalKey::from_dep_name(&package_name),
        CanonicalKey::Npm { .. }
    ) {
        return;
    }
    if package_specs.iter().any(|(existing_name, existing_range)| {
        existing_name == &package_name && existing_range == &package_range
    }) {
        return;
    }
    package_specs.push((package_name, package_range));
}

fn worker_package_specs_from_parked_edges(
    candidates: &[(CanonicalKey, String)],
    parked: &AHashMap<CanonicalKey, Vec<Edge>>,
) -> Vec<(String, String)> {
    let mut seen = AHashSet::with_capacity(candidates.len());
    let mut specs = Vec::with_capacity(candidates.len());
    for (canonical, name) in candidates {
        let Some(edges) = parked.get(canonical) else {
            continue;
        };
        for edge in edges {
            let range = edge.range.raw().to_string();
            if seen.insert((name.clone(), range.clone())) {
                specs.push((name.clone(), range));
            }
        }
    }
    specs
}

async fn hydrate_partial_worker_peer_cache(
    client: &RegistryClient,
    route_table: &RouteTable,
    shared_cache: &SharedCache,
    policy: &ResolverPolicy,
    peer_requirements: &[PeerRequirement],
    trace_metadata_fetches: bool,
) -> Result<u64, ResolveError> {
    if peer_requirements.is_empty() {
        return Ok(0);
    }

    let mut grouped: AHashMap<CanonicalKey, Vec<&PeerRequirement>> = AHashMap::new();
    for req in peer_requirements {
        grouped.entry(req.canonical.clone()).or_default().push(req);
    }
    let mut canonicals: Vec<CanonicalKey> = grouped.keys().cloned().collect();
    canonicals.sort_by_key(|canonical| canonical.to_string());

    let mut fetched_count = 0;
    for canonical in canonicals {
        let CanonicalKey::Npm { name } = &canonical else {
            continue;
        };
        if !matches!(
            route_table.route_for_package(name),
            UpstreamRoute::LpmWorker
        ) {
            continue;
        }
        let Some(info) = shared_cache
            .get(&canonical)
            .map(|entry| entry.value().clone())
        else {
            continue;
        };
        let Some(reqs) = grouped.get(&canonical) else {
            continue;
        };
        if cached_info_satisfies_peer_requirements(&info, reqs) {
            continue;
        }
        let fetched = fetch_metadata_for_resolver_with_trace_detail(
            client,
            route_table,
            &canonical,
            policy,
            false,
            trace_metadata_fetches,
        )
        .await?;
        shared_cache.insert(canonical, fetched.info);
        fetched_count += 1;
    }
    Ok(fetched_count)
}

fn cached_info_satisfies_peer_requirements(
    info: &CachedPackageInfo,
    reqs: &[&PeerRequirement],
) -> bool {
    info.versions.iter().any(|version| {
        reqs.iter().all(|req| {
            req.range
                .satisfies_with_latest_bound(version, info.latest_version.as_ref())
        }) && (info.platform.is_empty()
            || info
                .platform
                .get(&version.to_string())
                .is_none_or(crate::provider::is_platform_compatible))
    })
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
pub async fn resolve_greedy_fused_with_cache_options_and_policy_roots(
    client: Arc<RegistryClient>,
    root_dependencies: crate::resolve::RootDependencies,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    spec_tx: Option<tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    policy: ResolverPolicy,
) -> Result<ResolveResult, ResolveError> {
    resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
        client,
        root_dependencies,
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
    resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
        client,
        crate::resolve::RootDependencies::required(dependencies),
        overrides,
        route_table,
        npm_fanout,
        spec_tx,
        shared_cache,
        auto_install_peers,
        include_optional_dependencies,
        policy,
        selected_package_tx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
    client: Arc<RegistryClient>,
    root_dependencies: crate::resolve::RootDependencies,
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
        n_deps = root_dependencies.dependencies.len(),
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
    let range_aware_worker_batch = worker_range_aware_batch_enabled();

    let mut state = ResolveState::new_with_root_dependencies_and_policy(
        root_dependencies,
        overrides,
        include_optional_dependencies,
        policy.clone(),
    );
    state.set_selected_package_tx(selected_package_tx);
    state.seed_root_edges()?;
    let mut pending_root_constraints = PendingRootConstraints::from_task_queue(&state.task_queue);
    let worker_batch_disabled = Cell::new(false);
    let release_age_all_packages = policy.release_age_checks_all_packages();
    let release_age_package_names = if release_age_all_packages {
        Vec::new()
    } else {
        release_age_names_from_root_deps(&state.root_deps, &policy)
    };
    let release_age_cutoff_unix = policy.release_age_cutoff_unix();
    let tree_provider = FusedTreeProvider {
        client: &client,
        route_table: &route_table,
        shared_cache: &shared_cache,
        policy: &policy,
        spec_tx: spec_tx.as_ref(),
        dispatcher_rpc_count: Cell::new(0),
        tarball_dispatched_count: Cell::new(0),
        worker_batch_disabled: &worker_batch_disabled,
        release_age_package_names: &release_age_package_names,
        release_age_all_packages,
        trace_metadata_fetches,
    };
    let tree_status_cache = super::tree_policy::TreeStatusCache::default();

    // Loop-local state, owned by this single task. No Arcs needed
    // around `inflight` / `parked` because they never cross task
    // boundaries — only the spawn closures own clones of the
    // canonicals they're fetching.
    let metadata_sem = Arc::new(tokio::sync::Semaphore::new(npm_fanout));
    let metadata_fetch_telemetry = Arc::new(MetadataFetchTelemetry::default());
    let metadata_dispatch = MetadataFetchDispatch {
        metadata_sem: &metadata_sem,
        telemetry: &metadata_fetch_telemetry,
        client: &client,
        route_table: &route_table,
        policy: &policy,
        trace_metadata_fetches,
    };

    // Counters. Declared here so the Worker root pre-batch below can
    // update them before the main loop starts.
    let mut dispatcher_rpc_count: u64 = 0;
    let mut pending_high_water: u64 = 0;
    let mut tarball_dispatched_count: u64 = 0;
    let mut parked_max_depth: u32 = 0;
    // Speculative peer-manifest fetches dispatched concurrent with
    // regular dep dispatch. Bumped by the peer-prefetch step; surfaces on
    // `StageTiming.peer_prefetch_count`.
    let mut peer_prefetch_count: u64 = 0;

    // Pre-size both maps to the expected steady-state cardinality.
    // For bench/fixture-large (266 transitive packages) the default-
    // sized HashMap rehashes ~5-7 times growing from 0 → 266; samply
    // surfaced `hashbrown::reserve_rehash` at ~6.7 % of cold-install
    // CPU. `npm_fanout` (the metadata-semaphore size) is the closest
    // proxy for "how many manifests this resolver might
    // track simultaneously" without threading a dependency-count estimate
    // through. Slight over-allocation is cheaper than rehashing.
    let mut ordered_metadata = OrderedMetadataFetches::with_capacity(npm_fanout);
    let mut parked: AHashMap<CanonicalKey, Vec<Edge>> = AHashMap::with_capacity(npm_fanout);
    let mut counted_metadata_edge_misses =
        trace_metadata_fetches.then(|| AHashSet::with_capacity(npm_fanout));
    let mut metadata_jobs: tokio::task::JoinSet<(CanonicalKey, FetchResult)> =
        tokio::task::JoinSet::new();
    let mut worker_batch_stream = None;
    let mut worker_batch_stream_package_specs: Vec<(String, String)> = Vec::new();
    let mut worker_stream_can_batch_waiting = false;
    let mut worker_stream_waiting: AHashSet<CanonicalKey> = AHashSet::with_capacity(npm_fanout);

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
    let worker_root_package_specs = if range_aware_worker_batch {
        worker_package_specs_from_root_deps(&state.root_deps, &route_table)
            .into_iter()
            .filter(|(name, _)| !shared_cache.contains_key(&CanonicalKey::from_dep_name(name)))
            .collect()
    } else {
        Vec::new()
    };
    let worker_root_names: Vec<String> = if range_aware_worker_batch {
        worker_package_names_from_specs(&worker_root_package_specs)
    } else {
        state
            .root_deps
            .keys()
            .filter(|name| {
                !shared_cache.contains_key(&CanonicalKey::from_dep_name(name))
                    && matches!(
                        route_table.route_for_package(name),
                        UpstreamRoute::LpmWorker
                    )
            })
            .cloned()
            .collect()
    };
    let streaming_worker_batch = range_aware_worker_batch
        && worker_streaming_batch_enabled()
        && !worker_root_package_specs.is_empty();
    if !worker_root_names.is_empty() {
        record_pending_high_water(&mut pending_high_water, worker_root_names.len());
        if streaming_worker_batch {
            match client
                .batch_metadata_deep_with_release_age_packages_and_package_specs_stream(
                    &worker_root_names,
                    &release_age_package_names,
                    release_age_all_packages,
                    &worker_root_package_specs,
                    release_age_cutoff_unix,
                )
                .await
            {
                Ok(stream) => {
                    dispatcher_rpc_count += 1;
                    worker_batch_stream = Some(stream);
                    worker_batch_stream_package_specs = worker_root_package_specs.clone();
                    worker_stream_can_batch_waiting = true;
                }
                Err(e) => {
                    worker_batch_disabled.set(true);
                    tracing::debug!(
                        "greedy-fusion: streaming Worker pre-batch failed to open ({} names): {e} \
                         — falling back to per-package dispatch",
                        worker_root_names.len()
                    );
                }
            }
        } else {
            let batch_result = if worker_root_package_specs.is_empty() {
                client
                    .batch_metadata_deep_with_release_age_packages(
                        &worker_root_names,
                        &release_age_package_names,
                        release_age_all_packages,
                    )
                    .await
            } else {
                client
                    .batch_metadata_deep_with_release_age_packages_and_package_specs(
                        &worker_root_names,
                        &release_age_package_names,
                        release_age_all_packages,
                        &worker_root_package_specs,
                        release_age_cutoff_unix,
                    )
                    .await
            };
            match batch_result {
                Ok(batch) => {
                    // One actual HTTP round trip regardless of
                    // batch.len(). The dispatcher_rpc_count metric tracks
                    // RPCs (not packages); record exactly 1 for the batch
                    // — keeps the metric semantics stable across arms.
                    dispatcher_rpc_count += 1;
                    let mut batch_package_specs = worker_root_package_specs.clone();
                    for meta in batch.values() {
                        extend_covered_ranges_from_metadata(&mut batch_package_specs, meta);
                    }
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
                        let fetched = if worker_root_package_specs.is_empty() {
                            parse_fetched_metadata(meta, spec_tx.is_some(), trace_metadata_fetches)
                        } else {
                            parse_partial_fetched_metadata(
                                meta,
                                spec_tx.is_some(),
                                trace_metadata_fetches,
                                covered_ranges_for_name(&batch_package_specs, &name),
                            )
                        };
                        let FetchedMetadata {
                            speculation, info, ..
                        } = fetched;
                        insert_or_merge_cached_package_info(&shared_cache, canonical.clone(), info);
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
    }
    loop {
        let mut worker_batch_candidates: Vec<(CanonicalKey, String)> = Vec::new();

        // ── Drain `task_queue` synchronously ─────────────────────
        while let Some(edge) = state.task_queue.pop_front() {
            let Some(edge) = pending_root_constraints.defer_if_root_pending(edge) else {
                continue;
            };
            // Cache hit fast-path. Hot path; one DashMap lookup +
            // refcount bump on the Arc<CachedPackageInfo>. The shard
            // lock is released before `process_edge` mutates state.
            if let Some(info_arc) = shared_cache.get(&edge.canonical).map(|e| e.value().clone()) {
                if info_arc.needs_metadata_for_range(&edge.range) {
                    let canonical = edge.canonical.clone();
                    let new_fetch = ordered_metadata.start(&canonical)?;
                    if new_fetch && trace_metadata_fetches {
                        state.work_stats.record_metadata_edge_miss(
                            &canonical,
                            &edge.range,
                            &route_table,
                        );
                        if let Some(counted_metadata_edge_misses) =
                            counted_metadata_edge_misses.as_mut()
                        {
                            counted_metadata_edge_misses.insert(canonical.clone());
                        }
                    }
                    parked.entry(canonical.clone()).or_default().push(edge);
                    let worker_name = match &canonical {
                        CanonicalKey::Npm { name }
                            if range_aware_worker_batch
                                && !worker_batch_disabled.get()
                                && matches!(
                                    route_table.route_for_package(name),
                                    UpstreamRoute::LpmWorker
                                ) =>
                        {
                            Some(name.clone())
                        }
                        _ => None,
                    };
                    if let Some(worker_name) = worker_name {
                        if worker_batch_stream.is_some() {
                            worker_stream_waiting.insert(canonical);
                        } else if new_fetch {
                            worker_batch_candidates.push((canonical, worker_name));
                        }
                    } else if new_fetch {
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
                if !ordered_metadata.has_committed(&edge.canonical) {
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
                    let canonical = edge.canonical.clone();
                    let new_completion = ordered_metadata.start(&canonical)?;
                    parked.entry(canonical.clone()).or_default().push(edge);
                    if new_completion {
                        ordered_metadata.queue_cached_tracked(
                            canonical,
                            Ok(FetchedMetadata {
                                speculation: None,
                                latest_version: info_arc.latest_version.clone(),
                                info: info_arc,
                            }),
                        )?;
                        let mut completion = MetadataFetchCompletion {
                            shared_cache: &shared_cache,
                            route_table: &route_table,
                            counted_metadata_edge_misses: counted_metadata_edge_misses.as_mut(),
                            trace_metadata_fetches,
                            spec_tx: spec_tx.as_ref(),
                            tarball_dispatched_count: &mut tarball_dispatched_count,
                            parked: &mut parked,
                            state: &mut state,
                            pending_root_constraints: &mut pending_root_constraints,
                        };
                        ordered_metadata.commit_ready(&mut completion)?;
                    }
                    continue;
                }
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
                pending_root_constraints.complete_root_edge(&edge, &mut state.task_queue);
                continue;
            }
            // Cache miss — park the edge and dispatch one fetch per
            // canonical. Worker-routed npm misses discovered in this
            // drain are grouped into one batch below; direct/custom
            // routes keep the existing per-package fetch path.
            let canonical = edge.canonical.clone();
            let new_fetch = ordered_metadata.start(&canonical)?;
            if new_fetch && trace_metadata_fetches {
                state
                    .work_stats
                    .record_metadata_edge_miss(&canonical, &edge.range, &route_table);
                if let Some(counted_metadata_edge_misses) = counted_metadata_edge_misses.as_mut() {
                    counted_metadata_edge_misses.insert(canonical.clone());
                }
            }
            parked.entry(canonical.clone()).or_default().push(edge);
            if new_fetch {
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
                    if worker_batch_stream.is_some() {
                        worker_stream_waiting.insert(canonical);
                    } else {
                        worker_batch_candidates.push((canonical, name));
                    }
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
            let worker_package_specs = if range_aware_worker_batch {
                worker_package_specs_from_parked_edges(&worker_batch_candidates, &parked)
            } else {
                Vec::new()
            };
            record_pending_high_water(&mut pending_high_water, ordered_metadata.len());
            if streaming_worker_batch && !worker_package_specs.is_empty() {
                match client
                    .batch_metadata_deep_with_release_age_packages_and_package_specs_stream(
                        &worker_names,
                        &release_age_package_names,
                        release_age_all_packages,
                        &worker_package_specs,
                        release_age_cutoff_unix,
                    )
                    .await
                {
                    Ok(stream) => {
                        dispatcher_rpc_count += 1;
                        worker_batch_stream = Some(stream);
                        worker_batch_stream_package_specs = worker_package_specs.clone();
                        worker_stream_can_batch_waiting = false;
                        worker_stream_waiting.extend(
                            worker_batch_candidates
                                .into_iter()
                                .map(|(canonical, _)| canonical),
                        );
                        continue;
                    }
                    Err(e) => {
                        worker_batch_disabled.set(true);
                        tracing::debug!(
                            "greedy-fusion: streaming Worker tail batch failed to open ({} names): {e} \
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
            } else {
                let batch_result = if worker_package_specs.is_empty() {
                    client
                        .batch_metadata_deep_with_release_age_packages(
                            &worker_names,
                            &release_age_package_names,
                            release_age_all_packages,
                        )
                        .await
                } else {
                    client
                        .batch_metadata_deep_with_release_age_packages_and_package_specs(
                            &worker_names,
                            &release_age_package_names,
                            release_age_all_packages,
                            &worker_package_specs,
                            release_age_cutoff_unix,
                        )
                        .await
                };
                match batch_result {
                    Ok(batch) => {
                        dispatcher_rpc_count += 1;
                        let mut returned = AHashSet::with_capacity(batch.len());
                        let mut batch_package_specs = worker_package_specs.clone();
                        for meta in batch.values() {
                            extend_covered_ranges_from_metadata(&mut batch_package_specs, meta);
                        }
                        let mut batch_entries: Vec<_> = batch.into_iter().collect();
                        batch_entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                        for (name, meta) in batch_entries {
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
                            let fetched = if worker_package_specs.is_empty() {
                                parse_fetched_metadata(
                                    meta,
                                    spec_tx.is_some(),
                                    trace_metadata_fetches,
                                )
                            } else {
                                parse_partial_fetched_metadata(
                                    meta,
                                    spec_tx.is_some(),
                                    trace_metadata_fetches,
                                    covered_ranges_for_name(&batch_package_specs, &name),
                                )
                            };
                            if let Some(result) =
                                ordered_metadata.queue_if_tracked(canonical.clone(), Ok(fetched))?
                            {
                                let mut completion = MetadataFetchCompletion {
                                    shared_cache: &shared_cache,
                                    route_table: &route_table,
                                    counted_metadata_edge_misses: counted_metadata_edge_misses
                                        .as_mut(),
                                    trace_metadata_fetches,
                                    spec_tx: spec_tx.as_ref(),
                                    tarball_dispatched_count: &mut tarball_dispatched_count,
                                    parked: &mut parked,
                                    state: &mut state,
                                    pending_root_constraints: &mut pending_root_constraints,
                                };
                                complete_metadata_fetch(canonical, result, &mut completion)?;
                            }
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
                        let mut completion = MetadataFetchCompletion {
                            shared_cache: &shared_cache,
                            route_table: &route_table,
                            counted_metadata_edge_misses: counted_metadata_edge_misses.as_mut(),
                            trace_metadata_fetches,
                            spec_tx: spec_tx.as_ref(),
                            tarball_dispatched_count: &mut tarball_dispatched_count,
                            parked: &mut parked,
                            state: &mut state,
                            pending_root_constraints: &mut pending_root_constraints,
                        };
                        ordered_metadata.commit_ready(&mut completion)?;
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
            let candidates =
                pick_peer_prefetch_candidates(&state, &shared_cache, ordered_metadata.inflight());
            for canonical in candidates {
                // Mirror the cache-miss spawn path — same metadata
                // semaphore, same is_npm derivation, same tarball-spec
                // forward when the manifest lands. `parked.remove()`
                // returns None for these (nothing was parked) so the
                // resume step is a no-op.
                if !ordered_metadata.start(&canonical)? {
                    continue;
                }
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
        record_pending_high_water(&mut pending_high_water, ordered_metadata.len());
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
            let mut worker_stream_finished = false;
            if let Some(stream) = worker_batch_stream.as_mut() {
                match stream.next().await {
                    Ok(Some((name, meta))) => {
                        let canonical = crate::package::CanonicalKey::from_dep_name(&name);
                        if !matches!(canonical, crate::package::CanonicalKey::Root)
                            && matches!(
                                route_table.route_for_package(&name),
                                UpstreamRoute::LpmWorker
                            )
                        {
                            worker_stream_waiting.remove(&canonical);
                            let covered_ranges =
                                covered_ranges_for_name(&worker_batch_stream_package_specs, &name);
                            extend_covered_ranges_from_metadata(
                                &mut worker_batch_stream_package_specs,
                                &meta,
                            );
                            let fetched = parse_partial_fetched_metadata(
                                meta,
                                spec_tx.is_some(),
                                trace_metadata_fetches,
                                covered_ranges,
                            );
                            if let Some(result) =
                                ordered_metadata.queue_if_tracked(canonical.clone(), Ok(fetched))?
                            {
                                let mut completion = MetadataFetchCompletion {
                                    shared_cache: &shared_cache,
                                    route_table: &route_table,
                                    counted_metadata_edge_misses: counted_metadata_edge_misses
                                        .as_mut(),
                                    trace_metadata_fetches,
                                    spec_tx: spec_tx.as_ref(),
                                    tarball_dispatched_count: &mut tarball_dispatched_count,
                                    parked: &mut parked,
                                    state: &mut state,
                                    pending_root_constraints: &mut pending_root_constraints,
                                };
                                complete_metadata_fetch(canonical, result, &mut completion)?;
                            }
                            let mut completion = MetadataFetchCompletion {
                                shared_cache: &shared_cache,
                                route_table: &route_table,
                                counted_metadata_edge_misses: counted_metadata_edge_misses.as_mut(),
                                trace_metadata_fetches,
                                spec_tx: spec_tx.as_ref(),
                                tarball_dispatched_count: &mut tarball_dispatched_count,
                                parked: &mut parked,
                                state: &mut state,
                                pending_root_constraints: &mut pending_root_constraints,
                            };
                            ordered_metadata.commit_ready(&mut completion)?;
                        }
                        continue;
                    }
                    Ok(None) => {
                        worker_stream_finished = true;
                    }
                    Err(e) => {
                        worker_stream_finished = true;
                        worker_batch_disabled.set(true);
                        tracing::debug!(
                            "greedy-fusion: streaming Worker batch failed mid-body: {e} \
                             — falling back to per-package dispatch for pending names"
                        );
                    }
                }
            }

            if worker_stream_finished {
                worker_batch_stream = None;
                worker_batch_stream_package_specs.clear();
                if !worker_stream_waiting.is_empty() {
                    let waiting_candidates: Vec<(CanonicalKey, String)> = worker_stream_waiting
                        .iter()
                        .filter_map(|canonical| match canonical {
                            CanonicalKey::Npm { name } => Some((canonical.clone(), name.clone())),
                            CanonicalKey::Root | CanonicalKey::Lpm { .. } => None,
                        })
                        .collect();
                    if worker_stream_can_batch_waiting && !waiting_candidates.is_empty() {
                        let worker_names: Vec<String> = waiting_candidates
                            .iter()
                            .map(|(_, name)| name.clone())
                            .collect();
                        let worker_package_specs =
                            worker_package_specs_from_parked_edges(&waiting_candidates, &parked);
                        if !worker_package_specs.is_empty() {
                            record_pending_high_water(
                                &mut pending_high_water,
                                ordered_metadata.len(),
                            );
                            match client
                                .batch_metadata_deep_with_release_age_packages_and_package_specs_stream(
                                    &worker_names,
                                    &release_age_package_names,
                                    release_age_all_packages,
                                    &worker_package_specs,
                                    release_age_cutoff_unix,
                                )
                                .await
                            {
                                Ok(stream) => {
                                    dispatcher_rpc_count += 1;
                                    worker_batch_stream = Some(stream);
                                    worker_batch_stream_package_specs = worker_package_specs;
                                    worker_stream_can_batch_waiting = false;
                                    continue;
                                }
                                Err(e) => {
                                    worker_batch_disabled.set(true);
                                    tracing::debug!(
                                        "greedy-fusion: streaming Worker follow-up batch failed to open ({} names): {e} \
                                         — falling back to per-package dispatch",
                                        waiting_candidates.len()
                                    );
                                }
                            }
                        }
                    }

                    worker_stream_can_batch_waiting = false;
                    for canonical in worker_stream_waiting.drain() {
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
                worker_stream_can_batch_waiting = false;
            }

            debug_assert!(
                parked.is_empty(),
                "greedy-fusion: non-empty parked at termination — invariant violated \
                 (parked_keys={:?})",
                parked.keys().collect::<Vec<_>>()
            );
            if !ordered_metadata.is_empty() {
                return Err(ResolveError::Internal(
                    "metadata completions are blocked without a pending source".into(),
                ));
            }
            if !pending_root_constraints.is_empty() {
                return Err(ResolveError::Internal(
                    "root constraints are blocked without pending metadata".into(),
                ));
            }

            if range_aware_worker_batch {
                dispatcher_rpc_count += hydrate_partial_worker_peer_cache(
                    &client,
                    &route_table,
                    &shared_cache,
                    &policy,
                    &state.peer_requirements,
                    trace_metadata_fetches,
                )
                .await?;
            }

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
                        Ok(insert_or_merge_cached_package_info(
                            &shared_cache,
                            canonical.clone(),
                            info_arc,
                        ))
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
        // Fetches finish concurrently, while graph mutations commit in
        // deterministic dispatch order.
        if let Some(joined) = metadata_jobs.join_next().await {
            let (canonical, result) = joined
                .map_err(|e| ResolveError::Internal(format!("metadata join failure: {e}")))?;
            ordered_metadata.queue_tracked(canonical, result)?;
            let mut completion = MetadataFetchCompletion {
                shared_cache: &shared_cache,
                route_table: &route_table,
                counted_metadata_edge_misses: counted_metadata_edge_misses.as_mut(),
                trace_metadata_fetches,
                spec_tx: spec_tx.as_ref(),
                tarball_dispatched_count: &mut tarball_dispatched_count,
                parked: &mut parked,
                state: &mut state,
                pending_root_constraints: &mut pending_root_constraints,
            };
            ordered_metadata.commit_ready(&mut completion)?;
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
    let work_stats = state.work_stats;
    let root_resolutions = state.root_resolutions();
    let packages = state.into_resolved_packages(&cache, &root_aliases);
    let (
        selected_package_count,
        selected_unique_canonical_count,
        selected_duplicate_canonical_count,
    ) = selected_package_cardinality(&packages);

    let snap = lpm_registry::timing::snapshot();
    let policy_snap = crate::profile::policy_summary();
    Ok(ResolveResult {
        packages,
        cache,
        applied_overrides,
        platform_skipped,
        root_aliases,
        root_resolutions,
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
            dispatcher_configured_fanout: u64::try_from(npm_fanout).unwrap_or(u64::MAX),
            dispatcher_inflight_high_water: metadata_fetch_telemetry
                .active_high_water
                .load(Ordering::Relaxed),
            dispatcher_pending_high_water: pending_high_water,
            dispatcher_semaphore_wait_count: metadata_fetch_telemetry
                .semaphore_wait_count
                .load(Ordering::Relaxed),
            dispatcher_semaphore_wait_ns: metadata_fetch_telemetry
                .semaphore_wait_ns
                .load(Ordering::Relaxed),
            parked_max_depth,
            tarball_dispatched_count: tarball_dispatched_count
                + tree_provider.tarball_dispatched_count.get(),
            peer_prefetch_count,
            work_edge_process_count: work_stats.edge_process_count,
            work_edge_reuse_count: work_stats.edge_reuse_count,
            work_edge_reuse_range_count: work_stats.edge_reuse_range_count,
            work_edge_reuse_exact_count: work_stats.edge_reuse_exact_count,
            work_node_allocated_count: work_stats.node_allocated_count,
            work_child_edge_enqueued_count: work_stats.child_edge_enqueued_count,
            work_peer_requirement_count: work_stats.peer_requirement_count,
            work_metadata_edge_miss_count: work_stats.metadata_edge_miss_count,
            work_metadata_edge_miss_direct_count: work_stats.metadata_edge_miss_direct_count,
            work_metadata_edge_miss_latest_known_count: work_stats
                .metadata_edge_miss_latest_known_count,
            work_metadata_edge_miss_latest_known_direct_count: work_stats
                .metadata_edge_miss_latest_known_direct_count,
            work_metadata_edge_miss_latest_satisfies_count: work_stats
                .metadata_edge_miss_latest_satisfies_count,
            work_metadata_edge_miss_latest_satisfies_direct_count: work_stats
                .metadata_edge_miss_latest_satisfies_direct_count,
            work_metadata_edge_miss_latest_matches_pick_count: work_stats
                .metadata_edge_miss_latest_matches_pick_count,
            work_metadata_edge_miss_latest_matches_pick_direct_count: work_stats
                .metadata_edge_miss_latest_matches_pick_direct_count,
            work_metadata_edge_miss_version_doc_policy_eligible_count: work_stats
                .metadata_edge_miss_version_doc_policy_eligible_count,
            work_metadata_edge_miss_version_doc_policy_eligible_direct_count: work_stats
                .metadata_edge_miss_version_doc_policy_eligible_direct_count,
            work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count:
                work_stats.metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count,
            work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count:
                work_stats
                    .metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count,
            work_metadata_edge_miss_exact_count: work_stats.metadata_edge_miss_exact_count,
            work_metadata_edge_miss_star_count: work_stats.metadata_edge_miss_star_count,
            work_metadata_edge_miss_caret_count: work_stats.metadata_edge_miss_caret_count,
            work_metadata_edge_miss_tilde_count: work_stats.metadata_edge_miss_tilde_count,
            work_metadata_edge_miss_comparator_count: work_stats
                .metadata_edge_miss_comparator_count,
            work_metadata_edge_miss_complex_count: work_stats.metadata_edge_miss_complex_count,
            work_metadata_edge_miss_other_count: work_stats.metadata_edge_miss_other_count,
            selected_package_count,
            selected_unique_canonical_count,
            selected_duplicate_canonical_count,
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

#[cfg(test)]
mod release_age_hint_tests {
    use super::*;
    use crate::policy::TrustPolicyMode;

    #[test]
    fn release_age_names_from_root_deps_returns_direct_npm_targets_only() {
        let root_deps = HashMap::from_iter([
            ("plain".to_string(), "^1.0.0".to_string()),
            (
                "alias-local".to_string(),
                "npm:@scope/real@^2.0.0".to_string(),
            ),
            (
                "lpm".to_string(),
                "npm:@lpm.dev/acme.widget@^3.0.0".to_string(),
            ),
            ("unlisted".to_string(), "^4.0.0".to_string()),
        ]);
        let policy = ResolverPolicy::with_cutoff_unix_and_release_age_packages(
            86_400,
            1_735_776_000,
            TrustPolicyMode::Off,
            [
                CanonicalKey::npm("plain"),
                CanonicalKey::npm("@scope/real"),
                CanonicalKey::lpm("acme", "widget"),
            ],
        );

        let names = release_age_names_from_root_deps(&root_deps, &policy);

        assert_eq!(names, vec!["@scope/real".to_string(), "plain".to_string()]);
    }

    #[test]
    fn release_age_names_from_root_deps_returns_empty_when_release_age_is_off() {
        let root_deps = HashMap::from_iter([("plain".to_string(), "^1.0.0".to_string())]);
        let policy = ResolverPolicy::new(0, TrustPolicyMode::Off);

        let names = release_age_names_from_root_deps(&root_deps, &policy);

        assert!(names.is_empty());
    }
}

#[cfg(test)]
mod range_aware_worker_batch_tests {
    use super::*;

    #[test]
    fn worker_package_specs_from_root_deps_keeps_proxy_routed_npm_specs() {
        let root_deps = HashMap::from_iter([
            ("plain".to_string(), "^1.0.0".to_string()),
            (
                "alias-local".to_string(),
                "npm:@scope/real@^2.0.0".to_string(),
            ),
            (
                "lpm".to_string(),
                "npm:@lpm.dev/acme.widget@^3.0.0".to_string(),
            ),
        ]);
        let route_table = RouteTable::from_mode_only(RouteMode::Proxy);

        let specs = worker_package_specs_from_root_deps(&root_deps, &route_table);

        assert_eq!(
            specs,
            vec![
                ("@scope/real".to_string(), "^2.0.0".to_string()),
                ("plain".to_string(), "^1.0.0".to_string()),
            ]
        );
    }

    #[test]
    fn worker_package_specs_from_root_deps_skips_direct_npm_routes() {
        let root_deps = HashMap::from_iter([("plain".to_string(), "^1.0.0".to_string())]);
        let route_table = RouteTable::from_mode_only(RouteMode::Direct);

        let specs = worker_package_specs_from_root_deps(&root_deps, &route_table);

        assert!(specs.is_empty());
    }

    #[test]
    fn worker_package_names_from_specs_dedupes_duplicate_package_ranges() {
        let specs = vec![
            ("shared".to_string(), "^1.0.0".to_string()),
            ("shared".to_string(), "^2.0.0".to_string()),
            ("other".to_string(), "*".to_string()),
        ];

        let names = worker_package_names_from_specs(&specs);

        assert_eq!(names, vec!["other".to_string(), "shared".to_string()]);
    }

    #[test]
    fn worker_package_specs_from_parked_edges_preserves_distinct_ranges() {
        let canonical = CanonicalKey::npm("shared");
        let mut parked = AHashMap::new();
        parked.insert(
            canonical.clone(),
            vec![
                Edge {
                    parent: 0,
                    local_name: "shared".to_string(),
                    canonical: canonical.clone(),
                    range: NpmRange::parse("^1.0.0").expect("valid range"),
                    behavior: Default::default(),
                },
                Edge {
                    parent: 1,
                    local_name: "shared".to_string(),
                    canonical: canonical.clone(),
                    range: NpmRange::parse("^2.0.0").expect("valid range"),
                    behavior: Default::default(),
                },
                Edge {
                    parent: 2,
                    local_name: "shared".to_string(),
                    canonical: canonical.clone(),
                    range: NpmRange::parse("^1.0.0").expect("valid range"),
                    behavior: Default::default(),
                },
            ],
        );
        let candidates = vec![(canonical, "shared".to_string())];

        let specs = worker_package_specs_from_parked_edges(&candidates, &parked);

        assert_eq!(
            specs,
            vec![
                ("shared".to_string(), "^1.0.0".to_string()),
                ("shared".to_string(), "^2.0.0".to_string()),
            ]
        );
    }
}
