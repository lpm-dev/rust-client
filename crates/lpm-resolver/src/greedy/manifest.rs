use super::ExperimentalMetadataFetchTimings;
use super::metrics::{metrics_incr_cache_wait, metrics_incr_escape_hatch, metrics_incr_timeout};
use super::prelude::*;
use super::state::{MetadataEdgeMissLatest, ResolveState};
use super::types::Edge;
use crate::provider::CachedDistInfo;

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
    let dist_tags = metadata.dist_tags.clone();
    let mut info = parse_metadata_to_cache_info(&metadata);
    if info.needs_trust_metadata(policy) {
        return fetch_full_metadata_for_policy(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
            false,
        )
        .await;
    }
    if info.needs_release_time_metadata(canonical, policy) {
        fetch_release_times_for_policy(client, route_table, canonical, &mut info, false).await?;
    }
    Ok(fetched_metadata_from_info(
        None,
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
            true,
        )
        .await?;
        timings.policy_full_metadata_ms = policy_start.elapsed().as_millis();
        timings.total_ms = total_start.elapsed().as_millis();
        return Ok((fetched, timings));
    }
    if info.needs_release_time_metadata(canonical, policy) {
        let policy_start = Instant::now();
        if let Some(detail) =
            fetch_release_times_for_policy(client, route_table, canonical, &mut info, true).await?
        {
            timings.policy_release_time_fetch_ms = detail.total_ms;
            timings.policy_release_time_fetch = Some(detail.timings);
            timings.policy_release_time_version_count = detail.version_count;
        }
        timings.policy_release_time_ms = policy_start.elapsed().as_millis();
    }
    let fetched = fetched_metadata_from_info(latest_version, dist_tags, info, include_speculation);
    timings.total_ms = total_start.elapsed().as_millis();
    Ok((fetched, timings))
}

pub(super) async fn fetch_exact_metadata_for_resolver_with_timings(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    version: &str,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Result<(FetchedMetadata, ExperimentalMetadataFetchTimings), ResolveError> {
    let CanonicalKey::Npm { name } = canonical else {
        return fetch_metadata_for_resolver_with_timings(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
        )
        .await;
    };
    if !matches!(
        route_table.route_for_package(name),
        UpstreamRoute::NpmDirect
    ) {
        return fetch_metadata_for_resolver_with_timings(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
        )
        .await;
    }

    let total_start = Instant::now();
    let mut timings = ExperimentalMetadataFetchTimings {
        package: canonical.to_string(),
        route: "npm_direct_version_doc",
        ..ExperimentalMetadataFetchTimings::default()
    };
    let raw_start = Instant::now();
    let raw = client
        .get_npm_version_metadata_direct_with_timings(name, version)
        .await
        .map_err(|e| ResolveError::DependencyFetch {
            package: canonical.to_string(),
            version: version.to_string(),
            detail: e.to_string(),
        })?;
    timings.raw_fetch_ms = raw_start.elapsed().as_millis();
    timings.version_count = raw.metadata.versions.len() as u64;
    timings.cache_hit = raw.timings.cache_hit;
    timings.not_modified = raw.timings.not_modified;
    timings.cache_read_ms = raw.timings.cache_read_ms;
    timings.validator_read_ms = raw.timings.validator_read_ms;
    timings.http_ms = raw.timings.http_ms;
    timings.body_read_ms = raw.timings.body_read_ms;
    timings.json_decode_ms = raw.timings.json_decode_ms;
    timings.cache_after_304_ms = raw.timings.cache_after_304_ms;
    timings.cache_write_dispatch_ms = raw.timings.cache_write_dispatch_ms;
    timings.body_bytes = raw.timings.body_bytes;

    let parse_start = Instant::now();
    let info = parse_partial_metadata_to_cache_info(&raw.metadata);
    timings.cache_info_parse_ms = parse_start.elapsed().as_millis();
    if info.needs_policy_metadata(canonical, policy) {
        let policy_start = Instant::now();
        let fetched = fetch_metadata_for_resolver(
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

    let fetched =
        fetched_metadata_from_info(None, raw.metadata.dist_tags, info, include_speculation);
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
        policy_release_time_fetch_ms: timings.policy_release_time_fetch_ms,
        policy_release_time_cache_read_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.cache_read_ms),
        policy_release_time_validator_read_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.validator_read_ms),
        policy_release_time_http_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.http_ms),
        policy_release_time_body_read_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.body_read_ms),
        policy_release_time_json_decode_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.json_decode_ms),
        policy_release_time_cache_after_304_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.cache_after_304_ms),
        policy_release_time_cache_write_dispatch_ms: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.cache_write_dispatch_ms),
        policy_release_time_body_bytes: timings
            .policy_release_time_fetch
            .map_or(0, |fetch| fetch.body_bytes),
        policy_release_time_version_count: timings.policy_release_time_version_count,
        policy_release_time_cache_hit: timings
            .policy_release_time_fetch
            .is_some_and(|fetch| fetch.cache_hit),
        policy_release_time_not_modified: timings
            .policy_release_time_fetch
            .is_some_and(|fetch| fetch.not_modified),
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
    include_latest_version: bool,
) -> FetchedMetadata {
    parse_fetched_metadata_with_cache_completeness(
        metadata,
        include_speculation,
        include_latest_version,
        true,
        std::iter::empty(),
    )
}

pub(super) fn parse_partial_fetched_metadata(
    metadata: lpm_registry::PackageMetadata,
    include_speculation: bool,
    include_latest_version: bool,
    covered_ranges: impl IntoIterator<Item = String>,
) -> FetchedMetadata {
    parse_fetched_metadata_with_cache_completeness(
        metadata,
        include_speculation,
        include_latest_version,
        false,
        covered_ranges,
    )
}

fn parse_fetched_metadata_with_cache_completeness(
    metadata: lpm_registry::PackageMetadata,
    include_speculation: bool,
    include_latest_version: bool,
    versions_complete: bool,
    covered_ranges: impl IntoIterator<Item = String>,
) -> FetchedMetadata {
    let latest_version = include_latest_version
        .then(|| latest_version_from_metadata(&metadata))
        .flatten();
    let mut info = if versions_complete {
        parse_metadata_to_cache_info(&metadata)
    } else {
        parse_partial_metadata_to_cache_info(&metadata)
    };
    info.covered_ranges.extend(covered_ranges);
    let info = Arc::new(info);
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
    include_latest_version: bool,
) -> FetchedMetadata {
    fetched_metadata_from_info(
        include_latest_version
            .then(|| latest_version_from_metadata(&metadata))
            .flatten(),
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
        let detail = fetch_release_times_for_policy(
            client,
            route_table,
            canonical,
            &mut merged,
            trace_metadata_fetches,
        )
        .await?;
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
                    detail,
                ),
            );
        }
        let merged = Arc::new(merged);
        shared_cache.insert(canonical.clone(), merged.clone());
        return Ok(merged);
    }
    let policy_start = trace_metadata_fetches.then(Instant::now);
    let fetched =
        fetch_full_metadata_for_policy(client, route_table, canonical, policy, false, false)
            .await?;
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
                None,
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
    release_time_detail: Option<ReleaseTimeFetchDetail>,
) -> lpm_registry::timing::MetadataFetchDetailRecord {
    let release_time_fetch = release_time_detail.as_ref().map(|detail| detail.timings);
    lpm_registry::timing::MetadataFetchDetailRecord {
        package: canonical.to_string(),
        route: route_label_for_canonical(route_table, canonical),
        total_ms,
        policy_release_time_ms,
        policy_release_time_fetch_ms: release_time_detail
            .as_ref()
            .map_or(0, |detail| detail.total_ms),
        policy_release_time_cache_read_ms: release_time_fetch
            .map_or(0, |fetch| fetch.cache_read_ms),
        policy_release_time_validator_read_ms: release_time_fetch
            .map_or(0, |fetch| fetch.validator_read_ms),
        policy_release_time_http_ms: release_time_fetch.map_or(0, |fetch| fetch.http_ms),
        policy_release_time_body_read_ms: release_time_fetch.map_or(0, |fetch| fetch.body_read_ms),
        policy_release_time_json_decode_ms: release_time_fetch
            .map_or(0, |fetch| fetch.json_decode_ms),
        policy_release_time_cache_after_304_ms: release_time_fetch
            .map_or(0, |fetch| fetch.cache_after_304_ms),
        policy_release_time_cache_write_dispatch_ms: release_time_fetch
            .map_or(0, |fetch| fetch.cache_write_dispatch_ms),
        policy_release_time_body_bytes: release_time_fetch.map_or(0, |fetch| fetch.body_bytes),
        policy_release_time_version_count: release_time_detail
            .as_ref()
            .map_or(0, |detail| detail.version_count),
        policy_release_time_cache_hit: release_time_fetch.is_some_and(|fetch| fetch.cache_hit),
        policy_release_time_not_modified: release_time_fetch
            .is_some_and(|fetch| fetch.not_modified),
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
    capture_timings: bool,
) -> Result<Option<ReleaseTimeFetchDetail>, ResolveError> {
    let CanonicalKey::Npm { name } = canonical else {
        return Ok(None);
    };
    let route = route_table.route_for_package(name);
    let release_times = if capture_timings {
        let start = Instant::now();
        let timed = client
            .get_npm_release_times_routed_full_with_timings(name, route)
            .await
            .map_err(|e| ResolveError::DependencyFetch {
                package: canonical.to_string(),
                version: "*".to_string(),
                detail: e.to_string(),
            })?;
        let detail = ReleaseTimeFetchDetail {
            total_ms: start.elapsed().as_millis(),
            timings: timed.timings,
            version_count: timed.metadata.time.len() as u64,
        };
        merge_release_times_into_cache_info(info, &timed.metadata);
        return Ok(Some(detail));
    } else {
        client
            .get_npm_release_times_routed_full(name, route)
            .await
            .map_err(|e| ResolveError::DependencyFetch {
                package: canonical.to_string(),
                version: "*".to_string(),
                detail: e.to_string(),
            })?
    };
    merge_release_times_into_cache_info(info, &release_times);
    Ok(None)
}

#[derive(Clone, Copy)]
struct ReleaseTimeFetchDetail {
    total_ms: u128,
    timings: lpm_registry::PackageMetadataFetchTimings,
    version_count: u64,
}

async fn fetch_full_metadata_for_policy(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
    include_latest_version: bool,
) -> Result<FetchedMetadata, ResolveError> {
    let full = fetch_full_metadata_raw(client, route_table, canonical).await?;
    let fetched = parse_full_fetched_metadata(full, include_speculation, include_latest_version);
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
        include_latest_version,
    ))
}

pub(super) struct MetadataFetchCompletion<'a> {
    pub(super) shared_cache: &'a SharedCache,
    pub(super) route_table: &'a RouteTable,
    pub(super) counted_metadata_edge_misses: Option<&'a mut AHashSet<CanonicalKey>>,
    pub(super) trace_metadata_fetches: bool,
    pub(super) spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    pub(super) tarball_dispatched_count: &'a mut u64,
    pub(super) parked: &'a mut AHashMap<CanonicalKey, Vec<Edge>>,
    pub(super) state: &'a mut ResolveState,
}

pub(super) fn insert_or_merge_cached_package_info(
    shared_cache: &SharedCache,
    canonical: CanonicalKey,
    incoming: Arc<CachedPackageInfo>,
) -> Arc<CachedPackageInfo> {
    if incoming.versions_complete {
        shared_cache.insert(canonical, incoming.clone());
        return incoming;
    }

    let Some(existing) = shared_cache
        .get(&canonical)
        .map(|entry| Arc::clone(entry.value()))
    else {
        shared_cache.insert(canonical, incoming.clone());
        return incoming;
    };

    let merged = Arc::new(merge_cached_package_info(&existing, &incoming));
    shared_cache.insert(canonical, merged.clone());
    merged
}

fn merge_cached_package_info(
    existing: &CachedPackageInfo,
    incoming: &CachedPackageInfo,
) -> CachedPackageInfo {
    let mut versions = Vec::with_capacity(existing.versions.len() + incoming.versions.len());
    versions.extend(existing.versions.iter().cloned());
    versions.extend(incoming.versions.iter().cloned());
    versions.sort_by(|a, b| b.cmp(a));
    versions.dedup();

    let mut dist = existing.dist.clone();
    for (version, incoming_dist) in &incoming.dist {
        dist.entry(version.clone())
            .and_modify(|existing_dist| {
                *existing_dist = merge_cached_dist_info(existing_dist, incoming_dist);
            })
            .or_insert_with(|| incoming_dist.clone());
    }

    let mut deps = existing.deps.clone();
    deps.extend(incoming.deps.clone());
    let mut peer_deps = existing.peer_deps.clone();
    peer_deps.extend(incoming.peer_deps.clone());
    let mut optional_dep_names = existing.optional_dep_names.clone();
    optional_dep_names.extend(incoming.optional_dep_names.clone());
    let mut optional_peer_names = existing.optional_peer_names.clone();
    optional_peer_names.extend(incoming.optional_peer_names.clone());
    let mut bundled_dep_names = existing.bundled_dep_names.clone();
    bundled_dep_names.extend(incoming.bundled_dep_names.clone());
    let mut platform = existing.platform.clone();
    platform.extend(incoming.platform.clone());
    let mut aliases = existing.aliases.clone();
    aliases.extend(incoming.aliases.clone());
    let mut covered_ranges = existing.covered_ranges.clone();
    covered_ranges.extend(incoming.covered_ranges.iter().cloned());
    let incoming_adds_versions = incoming
        .versions
        .iter()
        .any(|version| !existing.versions.contains(version));
    let versions_complete = existing.versions_complete && !incoming_adds_versions;

    CachedPackageInfo {
        modified: incoming
            .modified
            .clone()
            .or_else(|| existing.modified.clone()),
        modified_unix: incoming.modified_unix.or(existing.modified_unix),
        trust_metadata_complete: versions_complete
            && (existing.trust_metadata_complete || incoming.trust_metadata_complete),
        versions_complete,
        covered_ranges,
        versions,
        deps,
        peer_deps,
        optional_dep_names,
        optional_peer_names,
        bundled_dep_names,
        platform,
        dist,
        aliases,
    }
}

fn merge_cached_dist_info(existing: &CachedDistInfo, incoming: &CachedDistInfo) -> CachedDistInfo {
    CachedDistInfo {
        tarball_url: incoming
            .tarball_url
            .clone()
            .or_else(|| existing.tarball_url.clone()),
        integrity: incoming
            .integrity
            .clone()
            .or_else(|| existing.integrity.clone()),
        signatures: if incoming.signatures.is_empty() {
            existing.signatures.clone()
        } else {
            incoming.signatures.clone()
        },
        published_at: incoming
            .published_at
            .clone()
            .or_else(|| existing.published_at.clone()),
        published_at_unix: incoming.published_at_unix.or(existing.published_at_unix),
        trust_evidence: incoming.trust_evidence.or(existing.trust_evidence),
    }
}

pub(super) fn complete_metadata_fetch(
    canonical: CanonicalKey,
    result: FetchResult,
    completion: &mut MetadataFetchCompletion<'_>,
) -> Result<(), ResolveError> {
    let count_latest_for_miss = match completion.counted_metadata_edge_misses.as_mut() {
        Some(misses) => misses.remove(&canonical),
        None => false,
    };
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
            let info = insert_or_merge_cached_package_info(
                completion.shared_cache,
                canonical.clone(),
                info,
            );
            if let Some(mut edges) = completion.parked.remove(&canonical) {
                if count_latest_for_miss && let Some(edge) = edges.first() {
                    completion
                        .state
                        .work_stats
                        .record_metadata_edge_miss_latest(MetadataEdgeMissLatest {
                            canonical: &canonical,
                            range: &edge.range,
                            info: &info,
                            latest_version: latest_version.as_ref(),
                            route_table: completion.route_table,
                            policy: &completion.state.policy,
                            compare_policy_pick: completion.trace_metadata_fetches,
                        });
                }
                edges.sort_by(|a, b| {
                    (a.parent, a.local_name.as_str()).cmp(&(b.parent, b.local_name.as_str()))
                });
                for e in edges {
                    completion.state.task_queue.push_back(e);
                }
            }
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
