use super::prelude::*;

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
    // Callers that don't run a walker never flip this flag. The
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
    resolve_with_shared_cache_options_and_policy_roots(
        client,
        RootDependencies::required(dependencies),
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
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_with_shared_cache_options_and_policy_roots(
    client: Arc<RegistryClient>,
    root_dependencies: RootDependencies,
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
        return crate::greedy::resolve_greedy_with_root_dependencies_options_and_policy(
            client,
            root_dependencies,
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

    let _span =
        tracing::debug_span!("resolve", n_deps = root_dependencies.dependencies.len()).entered();
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
        let root_dependencies_for_pass = root_dependencies.clone();
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
                LpmDependencyProvider::new_with_root_dependencies(
                    client_for_pass,
                    rt_for_pass,
                    root_dependencies_for_pass,
                )
            } else {
                LpmDependencyProvider::new_with_root_dependencies_and_splits(
                    client_for_pass,
                    rt_for_pass,
                    root_dependencies_for_pass,
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
                let (
                    cache,
                    applied_overrides,
                    skipped_dependencies,
                    root_aliases,
                    root_dependencies,
                ) = provider.into_parts();
                let root_resolutions =
                    root_resolutions_from_solution(&solution, &root_dependencies, &root_aliases);
                let (packages, platform_skipped) = match format_solution(
                    solution,
                    &cache,
                    &root_dependencies,
                    &root_aliases,
                    skipped_dependencies,
                ) {
                    Ok(formatted) => formatted,
                    Err(error) => break Err(error),
                };
                // Snapshot substage counters at the tail of the happy
                // path. The registry-side atomics were reset at the
                // top of this call, so they now reflect only follow-up
                // RPCs (the walker's measurement is surfaced separately
                // by install.rs).
                let snap = lpm_registry::timing::snapshot();
                let policy_snap = crate::profile::policy_summary();
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
                    policy_release_age_ms: policy_snap.release_age.elapsed.as_millis() as u64,
                    policy_release_age_checked_count: policy_snap.release_age.checked_count,
                    policy_release_age_rejected_count: policy_snap.release_age.rejected_count,
                    policy_release_age_missing_count: policy_snap.release_age.missing_count,
                    policy_trust_ms: policy_snap.trust_policy.elapsed.as_millis() as u64,
                    policy_trust_checked_count: policy_snap.trust_policy.checked_count,
                    policy_trust_rejected_count: policy_snap.trust_policy.rejected_count,
                    ..StageTiming::default()
                };
                break Ok(ResolveResult {
                    packages,
                    cache,
                    applied_overrides,
                    platform_skipped,
                    root_aliases,
                    root_resolutions,
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
                    break Err(no_solution_error(report));
                }

                let mut new_splits: Vec<String> = conflicting
                    .into_iter()
                    .filter(|pkg| !split_packages.contains(pkg))
                    .collect();
                if new_splits.is_empty() {
                    break Err(no_solution_error(report));
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
