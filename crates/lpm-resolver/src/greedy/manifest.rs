use super::ExperimentalMetadataFetchTimings;
use super::metrics::{metrics_incr_cache_wait, metrics_incr_escape_hatch, metrics_incr_timeout};
use super::prelude::*;
use super::state::{MetadataEdgeMissLatest, PendingRootConstraints, ResolveState};
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
    pub(super) shared_fact: Option<Arc<CachedPackageInfo>>,
    pub(super) latest_version: Option<NpmVersion>,
}

pub(super) type FetchResult = Result<FetchedMetadata, ResolveError>;

pub(super) fn parse_cached_metadata_for_resolver(
    metadata: &lpm_registry::PackageMetadata,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Option<FetchedMetadata> {
    let base_fact = Arc::new(parse_metadata_to_cache_info(metadata));
    if base_fact.needs_supplemental_metadata(canonical, policy) {
        return None;
    }
    let mut fetched = fetched_metadata_from_arc(
        None,
        metadata.dist_tags.clone(),
        Arc::clone(&base_fact),
        include_speculation,
    );
    fetched.shared_fact = Some(base_fact);
    Some(fetched)
}

pub(super) async fn fetch_metadata_for_resolver(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
    include_speculation: bool,
) -> Result<FetchedMetadata, ResolveError> {
    let metadata = fetch_metadata_raw(client, route_table, canonical).await?;
    let dist_tags = metadata.dist_tags.clone();
    let base_fact = Arc::new(parse_metadata_to_cache_info(&metadata));
    if base_fact.needs_trust_metadata(policy) {
        let mut fetched = fetch_full_metadata_for_policy(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
            false,
        )
        .await?;
        fetched.shared_fact = Some(base_fact);
        return Ok(fetched);
    }
    let needs_release_time = base_fact.needs_release_time_metadata(canonical, policy);
    let needs_platform = base_fact.needs_platform_metadata();
    if !needs_release_time && !needs_platform {
        let mut fetched =
            fetched_metadata_from_arc(None, dist_tags, Arc::clone(&base_fact), include_speculation);
        fetched.shared_fact = Some(base_fact);
        return Ok(fetched);
    }
    let mut info = (*base_fact).clone();
    if needs_release_time {
        fetch_release_times_for_policy(client, route_table, canonical, &mut info, false).await?;
    }
    if needs_platform {
        fetch_platform_metadata(client, route_table, canonical, &mut info, false).await?;
    }
    let mut fetched = fetched_metadata_from_info(None, dist_tags, info, include_speculation);
    fetched.shared_fact = Some(base_fact);
    Ok(fetched)
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
    let base_fact = Arc::new(parse_metadata_to_cache_info(&raw.metadata));
    timings.cache_info_parse_ms = parse_start.elapsed().as_millis();
    if base_fact.needs_trust_metadata(policy) {
        let policy_start = Instant::now();
        let mut fetched = fetch_full_metadata_for_policy(
            client,
            route_table,
            canonical,
            policy,
            include_speculation,
            true,
        )
        .await?;
        fetched.shared_fact = Some(base_fact);
        timings.policy_full_metadata_ms = policy_start.elapsed().as_millis();
        timings.total_ms = total_start.elapsed().as_millis();
        return Ok((fetched, timings));
    }
    let needs_release_time = base_fact.needs_release_time_metadata(canonical, policy);
    let needs_platform = base_fact.needs_platform_metadata();
    if !needs_release_time && !needs_platform {
        let mut fetched = fetched_metadata_from_arc(
            latest_version,
            dist_tags,
            Arc::clone(&base_fact),
            include_speculation,
        );
        fetched.shared_fact = Some(base_fact);
        timings.total_ms = total_start.elapsed().as_millis();
        return Ok((fetched, timings));
    }
    let mut info = (*base_fact).clone();
    if needs_release_time {
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
    if needs_platform {
        fetch_platform_metadata(client, route_table, canonical, &mut info, true).await?;
    }
    let mut fetched =
        fetched_metadata_from_info(latest_version, dist_tags, info, include_speculation);
    fetched.shared_fact = Some(base_fact);
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
    let mut info = parse_partial_metadata_to_cache_info(&raw.metadata);
    info.platform_metadata_complete = true;
    timings.cache_info_parse_ms = parse_start.elapsed().as_millis();
    if info.needs_supplemental_metadata(canonical, policy) {
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
        shared_fact: Some(Arc::clone(&info)),
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
    fetched_metadata_from_arc(latest_version, dist_tags, info, include_speculation)
}

fn fetched_metadata_from_arc(
    latest_version: Option<NpmVersion>,
    dist_tags: HashMap<String, String>,
    info: Arc<CachedPackageInfo>,
    include_speculation: bool,
) -> FetchedMetadata {
    let speculation = include_speculation
        .then(|| SpeculativePackageMetadata::from_dist_tags_and_info(dist_tags, info.clone()));
    FetchedMetadata {
        speculation,
        info,
        shared_fact: None,
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
    if !info.needs_supplemental_metadata(canonical, policy) {
        return Ok(info);
    }
    if !matches!(canonical, CanonicalKey::Npm { .. }) {
        return Ok(info);
    }
    if !info.needs_trust_metadata(policy) {
        let mut merged = (*info).clone();
        let supplemental_start = trace_metadata_fetches.then(Instant::now);
        let (detail, policy_release_time_ms) =
            if merged.needs_release_time_metadata(canonical, policy) {
                let release_time_start = trace_metadata_fetches.then(Instant::now);
                let detail = fetch_release_times_for_policy(
                    client,
                    route_table,
                    canonical,
                    &mut merged,
                    trace_metadata_fetches,
                )
                .await?;
                (
                    detail,
                    release_time_start.map_or(0, |start| start.elapsed().as_millis()),
                )
            } else {
                (None, 0)
            };
        if merged.needs_platform_metadata() {
            fetch_platform_metadata(
                client,
                route_table,
                canonical,
                &mut merged,
                trace_metadata_fetches,
            )
            .await?;
        }
        if let Some(start) = supplemental_start {
            let elapsed = start.elapsed().as_millis();
            lpm_registry::timing::record_metadata_fetch_detail(
                cached_policy_metadata_fetch_detail_record(
                    canonical,
                    route_table,
                    elapsed,
                    policy_release_time_ms,
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

async fn fetch_platform_metadata(
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
    let detail = fetch_platform_metadata_from_route(
        client,
        canonical,
        name,
        route.clone(),
        info,
        capture_timings,
    )
    .await?;
    if !info.needs_platform_metadata() {
        return Ok(detail);
    }
    if matches!(route, UpstreamRoute::LpmWorker) {
        let direct_detail = fetch_platform_metadata_from_route(
            client,
            canonical,
            name,
            UpstreamRoute::NpmDirect,
            info,
            capture_timings,
        )
        .await?;
        if !info.needs_platform_metadata() {
            return Ok(direct_detail.or(detail));
        }
    }
    Err(ResolveError::DependencyFetch {
        package: canonical.to_string(),
        version: "*".to_string(),
        detail: "full registry metadata omitted the versions map required to recover platform restrictions"
            .to_string(),
    })
}

async fn fetch_platform_metadata_from_route(
    client: &RegistryClient,
    canonical: &CanonicalKey,
    name: &str,
    route: UpstreamRoute,
    info: &mut CachedPackageInfo,
    capture_timings: bool,
) -> Result<Option<ReleaseTimeFetchDetail>, ResolveError> {
    let fetch = async {
        if capture_timings {
            let start = Instant::now();
            let timed = client
                .get_npm_platform_metadata_routed_full_with_timings(name, route)
                .await
                .map_err(|error| ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: error.to_string(),
                })?;
            let detail = ReleaseTimeFetchDetail {
                total_ms: start.elapsed().as_millis(),
                timings: timed.timings,
                version_count: timed
                    .metadata
                    .versions
                    .as_ref()
                    .map_or(0, |versions| versions.len() as u64),
            };
            merge_release_times_into_cache_info(info, &timed.metadata);
            Ok(Some(detail))
        } else {
            let metadata = client
                .get_npm_platform_metadata_routed_full(name, route)
                .await
                .map_err(|error| ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: error.to_string(),
                })?;
            merge_release_times_into_cache_info(info, &metadata);
            Ok(None)
        }
    };
    lpm_registry::timing::with_metadata_purpose(
        lpm_registry::timing::MetadataPurpose::PlatformHydration,
        fetch,
    )
    .await
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
    if !fetched.info.needs_supplemental_metadata(canonical, policy) {
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
    pub(super) shared_fact_cache: Option<&'a SharedCache>,
    pub(super) route_table: &'a RouteTable,
    pub(super) counted_metadata_edge_misses: Option<&'a mut AHashSet<CanonicalKey>>,
    pub(super) trace_metadata_fetches: bool,
    pub(super) spec_tx: Option<&'a tokio::sync::mpsc::Sender<(String, SpeculativePackageMetadata)>>,
    pub(super) tarball_dispatched_count: &'a mut u64,
    pub(super) parked: &'a mut AHashMap<CanonicalKey, Vec<Edge>>,
    pub(super) state: &'a mut ResolveState,
    pub(super) pending_root_constraints: &'a mut PendingRootConstraints,
}

pub(super) fn cached_manifest_from_importer_or_facts(
    importer_cache: &SharedCache,
    shared_fact_cache: Option<&SharedCache>,
    canonical: &CanonicalKey,
) -> Option<Arc<CachedPackageInfo>> {
    if let Some(info) = importer_cache
        .get(canonical)
        .map(|entry| Arc::clone(entry.value()))
    {
        return Some(info);
    }

    let fact = shared_fact_cache?
        .get(canonical)
        .map(|entry| Arc::clone(entry.value()))?;
    Some(insert_or_merge_cached_package_info(
        importer_cache,
        canonical.clone(),
        fact,
    ))
}

pub(super) fn publish_direct_base_fact(
    shared_fact_cache: Option<&SharedCache>,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    fact: Option<Arc<CachedPackageInfo>>,
) {
    let (Some(shared_fact_cache), Some(fact), CanonicalKey::Npm { name }) =
        (shared_fact_cache, fact, canonical)
    else {
        return;
    };
    if !matches!(
        route_table.route_for_package(name),
        UpstreamRoute::NpmDirect
    ) {
        return;
    }
    insert_or_merge_cached_package_info(shared_fact_cache, canonical.clone(), fact);
}

pub(super) fn complete_metadata_fetch(
    canonical: CanonicalKey,
    result: FetchResult,
    completion: &mut MetadataFetchCompletion<'_>,
) -> Result<bool, ResolveError> {
    let count_latest_for_miss = match completion.counted_metadata_edge_misses.as_mut() {
        Some(misses) => misses.remove(&canonical),
        None => false,
    };
    match result {
        Ok(fetched) => {
            let FetchedMetadata {
                speculation,
                info,
                shared_fact,
                latest_version,
            } = fetched;
            publish_direct_base_fact(
                completion.shared_fact_cache,
                completion.route_table,
                &canonical,
                shared_fact,
            );
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
            Ok(true)
        }
        Err(error)
            if matches!(error, ResolveError::PackageNotFound { .. })
                && activate_workspace_fallback(completion.shared_cache, &canonical).is_some() =>
        {
            if let Some(mut edges) = completion.parked.remove(&canonical) {
                edges.sort_by(|left, right| {
                    (left.parent, left.local_name.as_str())
                        .cmp(&(right.parent, right.local_name.as_str()))
                });
                for edge in edges {
                    completion.state.task_queue.push_back(edge);
                }
            }
            Ok(true)
        }
        Err(error) => {
            if let Some(edges) = completion.parked.remove(&canonical) {
                for edge in edges {
                    propagate_fetch_error(&edge, &error, completion.state)?;
                    completion
                        .pending_root_constraints
                        .complete_root_edge(&edge, &mut completion.state.task_queue);
                }
            }
            Ok(false)
        }
    }
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
            client
                .get_package_metadata(&pkg_name)
                .await
                .map_err(|error| metadata_fetch_error(canonical, error))
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
            .map_err(|error| metadata_fetch_error(canonical, error))
        }
    }
}

fn metadata_fetch_error(canonical: &CanonicalKey, error: lpm_common::LpmError) -> ResolveError {
    match error {
        lpm_common::LpmError::NotFound(detail) => ResolveError::PackageNotFound {
            package: canonical.to_string(),
            detail,
        },
        other => ResolveError::DependencyFetch {
            package: canonical.to_string(),
            version: "*".to_string(),
            detail: other.to_string(),
        },
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
                .map_err(|error| metadata_fetch_error(canonical, error))
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
            .map_err(|error| metadata_fetch_error(canonical, error))
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
            client
                .get_package_metadata(&pkg_name)
                .await
                .map_err(|error| metadata_fetch_error(canonical, error))
        }
        CanonicalKey::Npm { name } => {
            let route = route_table.route_for_package(name);
            client
                .get_npm_metadata_routed_full(name, route)
                .await
                .map_err(|error| metadata_fetch_error(canonical, error))
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
        ResolveError::DependencyFetch { detail, .. }
        | ResolveError::PackageNotFound { detail, .. } => detail.clone(),
        ResolveError::Resolution(context) => context.reason.clone(),
        other => other.to_string(),
    };
    Err(ResolveError::Resolution(Box::new(
        state.edge_resolution_context(edge, ResolutionFailureKind::FetchFailed, detail, None, None),
    )))
}
