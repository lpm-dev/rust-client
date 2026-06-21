use super::ExperimentalMetadataFetchTimings;
use super::metrics::{metrics_incr_cache_wait, metrics_incr_escape_hatch, metrics_incr_timeout};
use super::prelude::*;
use super::state::ResolveState;
use super::types::Edge;

/// Fast cache hit, then short-lived per-canonical wait, then escape-hatch
/// direct fetch. Mirrors `LpmDependencyProvider::ensure_cached` but yields an
/// owned `Arc<CachedPackageInfo>` instead of a `RefCell` borrow.
#[allow(clippy::too_many_arguments)] // mirrors provider::ensure_cached's plumbing surface
pub(super) async fn ensure_manifest(
    canonical: &CanonicalKey,
    client: Arc<RegistryClient>,
    route_table: &RouteTable,
    shared_cache: &SharedCache,
    notify_map: &NotifyMap,
    walker_done: &WalkerDone,
    fetch_wait_timeout: Duration,
    metrics: &StreamingBfsMetrics,
    policy: &ResolverPolicy,
    trace_metadata_fetches: bool,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    // Fast path. Cache values are Arc-wrapped, so the clone here is a
    // refcount bump rather than a deep clone of the 7-HashMap struct.
    // This is the load-bearing fix for the resolver wall — previously the
    // greedy resolver cloned popular packuments per edge, burning ~5 sec
    // per cold install.
    if let Some(entry) = shared_cache.get(canonical) {
        return ensure_policy_metadata_for_cached_manifest(
            canonical,
            entry.value().clone(),
            &client,
            route_table,
            shared_cache,
            policy,
            trace_metadata_fetches,
        )
        .await;
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
            return ensure_policy_metadata_for_cached_manifest(
                canonical,
                entry.value().clone(),
                &client,
                route_table,
                shared_cache,
                policy,
                trace_metadata_fetches,
            )
            .await;
        }
        // Walker may have flipped done — if so, fetch directly without
        // burning the timeout. Matches `LpmDependencyProvider::ensure_cached`'s
        // walker_done short-circuit path.
        if !walker_done.load(Ordering::Acquire) {
            match tokio::time::timeout(fetch_wait_timeout, notified).await {
                Ok(()) => {
                    if let Some(entry) = shared_cache.get(canonical) {
                        return ensure_policy_metadata_for_cached_manifest(
                            canonical,
                            entry.value().clone(),
                            &client,
                            route_table,
                            shared_cache,
                            policy,
                            trace_metadata_fetches,
                        )
                        .await;
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
    let info_arc = direct_fetch(
        &client,
        route_table,
        canonical,
        policy,
        trace_metadata_fetches,
    )
    .await?;
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
    policy: &ResolverPolicy,
    trace_metadata_fetches: bool,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    let fetched = fetch_metadata_for_resolver_with_trace_detail(
        client,
        route_table,
        canonical,
        policy,
        false,
        trace_metadata_fetches,
    )
    .await?;
    Ok(fetched.info)
}

pub(super) struct FetchedMetadata {
    pub(super) speculation: Option<SpeculativePackageMetadata>,
    pub(super) info: Arc<CachedPackageInfo>,
    pub(super) latest_version: Option<NpmVersion>,
}

pub(super) type FetchResult = Result<FetchedMetadata, ResolveError>;

pub(super) async fn fetch_metadata_for_resolver(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Result<FetchedMetadata, ResolveError> {
    let metadata = fetch_metadata_raw(client, route_table, canonical).await?;
    let latest_version = latest_version_from_metadata(&metadata);
    let dist_tags = metadata.dist_tags.clone();
    let mut info = parse_metadata_to_cache_info(&metadata);
    if info.needs_trust_metadata(policy) {
        return fetch_full_metadata_for_policy(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
        )
        .await;
    }
    if info.needs_release_time_metadata(canonical, policy) {
        fetch_release_times_for_policy(client, route_table, canonical, &mut info).await?;
    }
    Ok(fetched_metadata_from_info(
        latest_version,
        dist_tags,
        info,
        include_speculation,
    ))
}

pub(super) async fn fetch_metadata_for_resolver_with_timings(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Result<(FetchedMetadata, ExperimentalMetadataFetchTimings), ResolveError> {
    let total_start = Instant::now();
    let mut timings = ExperimentalMetadataFetchTimings {
        package: canonical.to_string(),
        ..ExperimentalMetadataFetchTimings::default()
    };
    let raw_start = Instant::now();
    let raw = fetch_metadata_raw_with_timings(client, route_table, canonical).await?;
    timings.raw_fetch_ms = raw_start.elapsed().as_millis();
    timings.route = raw.route;
    timings.version_count = raw.metadata.versions.len() as u64;
    let latest_version = latest_version_from_metadata(&raw.metadata);
    if let Some(registry) = raw.registry_timings {
        timings.cache_hit = registry.cache_hit;
        timings.not_modified = registry.not_modified;
        timings.cache_read_ms = registry.cache_read_ms;
        timings.validator_read_ms = registry.validator_read_ms;
        timings.http_ms = registry.http_ms;
        timings.body_read_ms = registry.body_read_ms;
        timings.json_decode_ms = registry.json_decode_ms;
        timings.cache_after_304_ms = registry.cache_after_304_ms;
        timings.cache_write_dispatch_ms = registry.cache_write_dispatch_ms;
        timings.body_bytes = registry.body_bytes;
    }

    let dist_tags = raw.metadata.dist_tags.clone();
    let parse_start = Instant::now();
    let mut info = parse_metadata_to_cache_info(&raw.metadata);
    timings.cache_info_parse_ms = parse_start.elapsed().as_millis();
    if info.needs_trust_metadata(policy) {
        let policy_start = Instant::now();
        let fetched = fetch_full_metadata_for_policy(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
        )
        .await?;
        timings.policy_full_metadata_ms = policy_start.elapsed().as_millis();
        timings.total_ms = total_start.elapsed().as_millis();
        return Ok((fetched, timings));
    }
    if info.needs_release_time_metadata(canonical, policy) {
        let policy_start = Instant::now();
        fetch_release_times_for_policy(client, route_table, canonical, &mut info).await?;
        timings.policy_release_time_ms = policy_start.elapsed().as_millis();
    }
    let fetched = fetched_metadata_from_info(latest_version, dist_tags, info, include_speculation);
    timings.total_ms = total_start.elapsed().as_millis();
    Ok((fetched, timings))
}

pub(super) async fn fetch_metadata_for_resolver_with_trace_detail(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
    trace_metadata_fetches: bool,
) -> Result<FetchedMetadata, ResolveError> {
    if !trace_metadata_fetches {
        return fetch_metadata_for_resolver(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
        )
        .await;
    }

    let (fetched, timings) = fetch_metadata_for_resolver_with_timings(
        client,
        route_table,
        canonical,
        policy,
        include_speculation,
    )
    .await?;
    lpm_registry::timing::record_metadata_fetch_detail(metadata_fetch_detail_record(timings));
    Ok(fetched)
}

fn metadata_fetch_detail_record(
    timings: ExperimentalMetadataFetchTimings,
) -> lpm_registry::timing::MetadataFetchDetailRecord {
    lpm_registry::timing::MetadataFetchDetailRecord {
        package: timings.package,
        route: timings.route,
        total_ms: timings.total_ms,
        raw_fetch_ms: timings.raw_fetch_ms,
        cache_read_ms: timings.cache_read_ms,
        validator_read_ms: timings.validator_read_ms,
        http_ms: timings.http_ms,
        body_read_ms: timings.body_read_ms,
        json_decode_ms: timings.json_decode_ms,
        cache_after_304_ms: timings.cache_after_304_ms,
        cache_write_dispatch_ms: timings.cache_write_dispatch_ms,
        cache_info_parse_ms: timings.cache_info_parse_ms,
        policy_release_time_ms: timings.policy_release_time_ms,
        policy_full_metadata_ms: timings.policy_full_metadata_ms,
        body_bytes: timings.body_bytes,
        version_count: timings.version_count,
        cache_hit: timings.cache_hit,
        not_modified: timings.not_modified,
    }
}

pub(super) fn parse_fetched_metadata(
    metadata: lpm_registry::PackageMetadata,
    include_speculation: bool,
) -> FetchedMetadata {
    let latest_version = latest_version_from_metadata(&metadata);
    let info = Arc::new(parse_metadata_to_cache_info(&metadata));
    let speculation = include_speculation.then(|| {
        SpeculativePackageMetadata::from_dist_tags_and_info(metadata.dist_tags, info.clone())
    });
    FetchedMetadata {
        speculation,
        info,
        latest_version,
    }
}

pub(super) fn parse_full_fetched_metadata(
    metadata: lpm_registry::PackageMetadata,
    include_speculation: bool,
) -> FetchedMetadata {
    fetched_metadata_from_info(
        latest_version_from_metadata(&metadata),
        metadata.dist_tags.clone(),
        parse_full_metadata_to_cache_info(&metadata),
        include_speculation,
    )
}

fn fetched_metadata_from_info(
    latest_version: Option<NpmVersion>,
    dist_tags: HashMap<String, String>,
    info: CachedPackageInfo,
    include_speculation: bool,
) -> FetchedMetadata {
    let info = Arc::new(info);
    let speculation = include_speculation
        .then(|| SpeculativePackageMetadata::from_dist_tags_and_info(dist_tags, info.clone()));
    FetchedMetadata {
        speculation,
        info,
        latest_version,
    }
}

fn latest_version_from_metadata(metadata: &lpm_registry::PackageMetadata) -> Option<NpmVersion> {
    metadata
        .latest_version_tag()
        .and_then(|version| NpmVersion::parse(version).ok())
}

pub(super) async fn ensure_policy_metadata_for_cached_manifest(
    canonical: &CanonicalKey,
    info: Arc<CachedPackageInfo>,
    client: &RegistryClient,
    route_table: &RouteTable,
    shared_cache: &SharedCache,
    policy: &ResolverPolicy,
    trace_metadata_fetches: bool,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    if !info.needs_policy_metadata(canonical, policy) {
        return Ok(info);
    }
    if !matches!(canonical, CanonicalKey::Npm { .. }) {
        return Ok(info);
    }
    if !info.needs_trust_metadata(policy) && info.needs_release_time_metadata(canonical, policy) {
        let mut merged = (*info).clone();
        let policy_start = trace_metadata_fetches.then(Instant::now);
        fetch_release_times_for_policy(client, route_table, canonical, &mut merged).await?;
        if let Some(start) = policy_start {
            let elapsed = start.elapsed().as_millis();
            lpm_registry::timing::record_metadata_fetch_detail(
                cached_policy_metadata_fetch_detail_record(
                    canonical,
                    route_table,
                    elapsed,
                    elapsed,
                    0,
                    merged.versions.len() as u64,
                ),
            );
        }
        let merged = Arc::new(merged);
        shared_cache.insert(canonical.clone(), merged.clone());
        return Ok(merged);
    }
    let policy_start = trace_metadata_fetches.then(Instant::now);
    let fetched =
        fetch_full_metadata_for_policy(client, route_table, canonical, policy, false).await?;
    let full_info = fetched.info;
    if let Some(start) = policy_start {
        let elapsed = start.elapsed().as_millis();
        lpm_registry::timing::record_metadata_fetch_detail(
            cached_policy_metadata_fetch_detail_record(
                canonical,
                route_table,
                elapsed,
                0,
                elapsed,
                full_info.versions.len() as u64,
            ),
        );
    }
    shared_cache.insert(canonical.clone(), full_info.clone());
    Ok(full_info)
}

fn cached_policy_metadata_fetch_detail_record(
    canonical: &CanonicalKey,
    route_table: &RouteTable,
    total_ms: u128,
    policy_release_time_ms: u128,
    policy_full_metadata_ms: u128,
    version_count: u64,
) -> lpm_registry::timing::MetadataFetchDetailRecord {
    lpm_registry::timing::MetadataFetchDetailRecord {
        package: canonical.to_string(),
        route: route_label_for_canonical(route_table, canonical),
        total_ms,
        policy_release_time_ms,
        policy_full_metadata_ms,
        version_count,
        ..lpm_registry::timing::MetadataFetchDetailRecord::default()
    }
}

fn route_label_for_canonical(route_table: &RouteTable, canonical: &CanonicalKey) -> &'static str {
    match canonical {
        CanonicalKey::Root => "unknown",
        CanonicalKey::Lpm { .. } => "lpm",
        CanonicalKey::Npm { name } => match route_table.route_for_package(name) {
            UpstreamRoute::NpmDirect => "npm_direct",
            UpstreamRoute::LpmWorker => "lpm_worker",
            UpstreamRoute::Custom { .. } => "custom",
        },
    }
}

async fn fetch_release_times_for_policy(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    info: &mut CachedPackageInfo,
) -> Result<(), ResolveError> {
    let CanonicalKey::Npm { name } = canonical else {
        return Ok(());
    };
    let route = route_table.route_for_package(name);
    let release_times = client
        .get_npm_release_times_routed_full(name, route)
        .await
        .map_err(|e| ResolveError::DependencyFetch {
            package: canonical.to_string(),
            version: "*".to_string(),
            detail: e.to_string(),
        })?;
    merge_release_times_into_cache_info(info, &release_times);
    Ok(())
}

async fn fetch_full_metadata_for_policy(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Result<FetchedMetadata, ResolveError> {
    let full = fetch_full_metadata_raw(client, route_table, canonical).await?;
    let fetched = parse_full_fetched_metadata(full, include_speculation);
    if !fetched.info.needs_policy_metadata(canonical, policy) {
        return Ok(fetched);
    }

    let CanonicalKey::Npm { name } = canonical else {
        return Ok(fetched);
    };
    if !matches!(
        route_table.route_for_package(name),
        UpstreamRoute::LpmWorker
    ) {
        return Ok(fetched);
    }

    tracing::debug!(
        "Worker full metadata for {name} omitted policy fields; falling back to direct npm full metadata"
    );
    let direct_full = client
        .refetch_npm_metadata_direct_full(name)
        .await
        .map_err(|e| ResolveError::DependencyFetch {
            package: canonical.to_string(),
            version: "*".to_string(),
            detail: e.to_string(),
        })?;
    Ok(parse_full_fetched_metadata(
        direct_full,
        include_speculation,
    ))
}

pub(super) struct MetadataFetchCompletion<'a> {
    pub(super) shared_cache: &'a SharedCache,
    pub(super) route_table: &'a RouteTable,
    pub(super) counted_metadata_misses: &'a mut AHashSet<CanonicalKey>,
    spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    pub(super) tarball_dispatched_count: &'a mut u64,
    pub(super) parked: &'a mut AHashMap<CanonicalKey, Vec<Edge>>,
    pub(super) state: &'a mut ResolveState,
}

impl<'a> MetadataFetchCompletion<'a> {
    pub(super) fn new(
        shared_cache: &'a SharedCache,
        route_table: &'a RouteTable,
        counted_metadata_misses: &'a mut AHashSet<CanonicalKey>,
        spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
        tarball_dispatched_count: &'a mut u64,
        parked: &'a mut AHashMap<CanonicalKey, Vec<Edge>>,
        state: &'a mut ResolveState,
    ) -> Self {
        Self {
            shared_cache,
            route_table,
            counted_metadata_misses,
            spec_tx,
            tarball_dispatched_count,
            parked,
            state,
        }
    }
}

pub(super) fn complete_metadata_fetch(
    canonical: CanonicalKey,
    result: FetchResult,
    completion: &mut MetadataFetchCompletion<'_>,
) -> Result<(), ResolveError> {
    let count_latest_for_miss = completion.counted_metadata_misses.remove(&canonical);
    match result {
        Ok(fetched) => {
            let FetchedMetadata {
                speculation,
                info,
                latest_version,
            } = fetched;
            if let (Some(tx), Some(speculation)) = (completion.spec_tx, speculation)
                && tx.try_send((canonical.to_string(), speculation)).is_ok()
            {
                *completion.tarball_dispatched_count += 1;
            }
            if let Some(mut edges) = completion.parked.remove(&canonical) {
                if count_latest_for_miss && let Some(edge) = edges.first() {
                    completion.state.work_stats.record_metadata_miss_latest(
                        &canonical,
                        &edge.range,
                        &info,
                        latest_version.as_ref(),
                        completion.route_table,
                        &completion.state.policy,
                    );
                }
                edges.sort_by(|a, b| {
                    (a.parent, a.local_name.as_str()).cmp(&(b.parent, b.local_name.as_str()))
                });
                for e in edges {
                    completion.state.task_queue.push_back(e);
                }
            }
            completion.shared_cache.insert(canonical, info);
        }
        Err(e) => {
            if let Some(edges) = completion.parked.remove(&canonical) {
                for edge in edges {
                    propagate_fetch_error(&edge, &e, completion.state)?;
                }
            }
        }
    }
    Ok(())
}

/// Raw-metadata fetch, factored out so the fused resolver can cache the
/// parsed [`CachedPackageInfo`] form and derive the slim speculation hint.
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

struct RawMetadataWithTimings {
    metadata: lpm_registry::PackageMetadata,
    route: &'static str,
    registry_timings: Option<lpm_registry::PackageMetadataFetchTimings>,
}

async fn fetch_metadata_raw_with_timings(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
) -> Result<RawMetadataWithTimings, ResolveError> {
    match canonical {
        CanonicalKey::Root => Err(ResolveError::Internal(
            "fetch_metadata_raw called for root".to_string(),
        )),
        CanonicalKey::Lpm { owner, name } => {
            let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                .map_err(|e| ResolveError::Internal(e.to_string()))?;
            client
                .get_package_metadata(&pkg_name)
                .await
                .map(|metadata| RawMetadataWithTimings {
                    metadata,
                    route: "lpm",
                    registry_timings: None,
                })
                .map_err(|e| ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: e.to_string(),
                })
        }
        CanonicalKey::Npm { name } => {
            let route = route_table.route_for_package(name);
            match route {
                UpstreamRoute::NpmDirect => client
                    .get_npm_metadata_direct_with_timings(name)
                    .await
                    .map(|timed| RawMetadataWithTimings {
                        metadata: timed.metadata,
                        route: "npm_direct",
                        registry_timings: Some(timed.timings),
                    }),
                UpstreamRoute::LpmWorker => {
                    client.get_npm_package_metadata(name).await.map(|metadata| {
                        RawMetadataWithTimings {
                            metadata,
                            route: "lpm_worker",
                            registry_timings: None,
                        }
                    })
                }
                UpstreamRoute::Custom { target, auth } => client
                    .get_npm_metadata_from(&target.base_url, name, auth.as_ref())
                    .await
                    .map(|metadata| RawMetadataWithTimings {
                        metadata,
                        route: "custom",
                        registry_timings: None,
                    }),
            }
            .map_err(|e| ResolveError::DependencyFetch {
                package: canonical.to_string(),
                version: "*".to_string(),
                detail: e.to_string(),
            })
        }
    }
}

async fn fetch_full_metadata_raw(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
) -> Result<lpm_registry::PackageMetadata, ResolveError> {
    match canonical {
        CanonicalKey::Root => Err(ResolveError::Internal(
            "fetch_full_metadata_raw called for root".to_string(),
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
            client
                .get_npm_metadata_routed_full(name, route)
                .await
                .map_err(|e| ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: e.to_string(),
                })
        }
    }
}

/// Apply optional/peer/required behavior to an edge whose manifest fetch
/// failed. Required fetch failures keep the failed dependency edge attached
/// so CLI diagnostics can name the requester.
///
/// - Optional → skip silently. The platform_skipped counter is
///   irrelevant here (we never reached platform filtering — the
///   manifest itself never landed), so it stays unchanged.
/// - Peer → skip with debug log; the post-resolve `check_unmet_peers`
///   pass surfaces unmet peers separately.
/// - Required → propagate as a structured resolver failure with the
///   underlying fetch detail.
pub(super) fn propagate_fetch_error(
    edge: &Edge,
    err: &ResolveError,
    state: &mut ResolveState,
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
    let detail = match err {
        ResolveError::DependencyFetch { detail, .. } => detail.clone(),
        ResolveError::Resolution(context) => context.reason.clone(),
        other => other.to_string(),
    };
    Err(ResolveError::Resolution(Box::new(
        state.edge_resolution_context(edge, ResolutionFailureKind::FetchFailed, detail, None, None),
    )))
}
