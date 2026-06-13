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
    let info_arc = direct_fetch(&client, route_table, canonical, policy).await?;
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
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    let fetched = fetch_metadata_for_resolver(client, route_table, canonical, policy).await?;
    Ok(fetched.info)
}

pub(super) struct FetchedMetadata {
    pub(super) metadata: lpm_registry::PackageMetadata,
    pub(super) info: Arc<CachedPackageInfo>,
}

pub(super) type FetchResult = Result<FetchedMetadata, ResolveError>;

pub(super) async fn fetch_metadata_for_resolver(
    client: &RegistryClient,
    route_table: &RouteTable,
    canonical: &CanonicalKey,
    policy: &ResolverPolicy,
) -> Result<FetchedMetadata, ResolveError> {
    let metadata = fetch_metadata_raw(client, route_table, canonical).await?;
    let fetched = parse_fetched_metadata(metadata);
    if !fetched.info.needs_policy_metadata(policy) {
        return Ok(fetched);
    }
    let full = fetch_full_metadata_raw(client, route_table, canonical).await?;
    Ok(parse_full_fetched_metadata(full))
}

pub(super) fn parse_fetched_metadata(metadata: lpm_registry::PackageMetadata) -> FetchedMetadata {
    let info = Arc::new(parse_metadata_to_cache_info(&metadata));
    FetchedMetadata { metadata, info }
}

pub(super) fn parse_full_fetched_metadata(
    metadata: lpm_registry::PackageMetadata,
) -> FetchedMetadata {
    let info = Arc::new(parse_full_metadata_to_cache_info(&metadata));
    FetchedMetadata { metadata, info }
}

pub(super) async fn ensure_policy_metadata_for_cached_manifest(
    canonical: &CanonicalKey,
    info: Arc<CachedPackageInfo>,
    client: &RegistryClient,
    route_table: &RouteTable,
    shared_cache: &SharedCache,
    policy: &ResolverPolicy,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    if !info.needs_policy_metadata(policy) {
        return Ok(info);
    }
    if !matches!(canonical, CanonicalKey::Npm { .. }) {
        return Ok(info);
    }
    let full = fetch_full_metadata_raw(client, route_table, canonical).await?;
    let full_info = Arc::new(parse_full_metadata_to_cache_info(&full));
    shared_cache.insert(canonical.clone(), full_info.clone());
    Ok(full_info)
}

pub(super) fn complete_metadata_fetch(
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
