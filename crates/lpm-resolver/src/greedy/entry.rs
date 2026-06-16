use super::edge::process_edge_with_preferred;
use super::manifest::{ensure_manifest, propagate_fetch_error};
use super::peer::drain_peer_requirements_one_pass;
use super::prelude::*;
use super::state::ResolveState;
use super::tree_policy::{TreeManifestProvider, preferred_tree_compatible_version};

struct WalkerTreeProvider<'a> {
    client: &'a Arc<RegistryClient>,
    route_table: &'a RouteTable,
    shared_cache: &'a SharedCache,
    notify_map: &'a NotifyMap,
    walker_done: &'a WalkerDone,
    fetch_wait_timeout: Duration,
    metrics: &'a StreamingBfsMetrics,
    policy: &'a ResolverPolicy,
}

impl TreeManifestProvider for WalkerTreeProvider<'_> {
    fn ensure_manifest<'a>(
        &'a self,
        canonical: &'a CanonicalKey,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>> + 'a>,
    > {
        Box::pin(async move {
            ensure_manifest(
                canonical,
                self.client.clone(),
                self.route_table,
                self.shared_cache,
                self.notify_map,
                self.walker_done,
                self.fetch_wait_timeout,
                self.metrics,
                self.policy,
            )
            .await
        })
    }
}

/// Entry point — same signature shape as
/// [`crate::resolve::resolve_with_shared_cache`] so the dispatch in
/// [`crate::resolve`] can swap implementations behind a feature flag.
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
    resolve_greedy_with_options_and_policy(
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
pub async fn resolve_greedy_with_options_and_policy(
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
    policy: ResolverPolicy,
) -> Result<ResolveResult, ResolveError> {
    let _span = tracing::debug_span!("resolve_greedy", n_deps = dependencies.len()).entered();
    let pass_start = Instant::now();

    // Reset profiling accumulators. We measure greedy work in `pubgrub_ms`
    // for schema parity even though no PubGrub call happens here; the
    // field semantically means "resolver wall-clock".
    crate::profile::reset_all();
    lpm_registry::timing::reset();

    let mut state = ResolveState::new_with_options_and_policy(
        dependencies,
        overrides,
        include_optional_dependencies,
        policy.clone(),
    );
    state.seed_root_edges()?;
    let tree_provider = WalkerTreeProvider {
        client: &client,
        route_table: &route_table,
        shared_cache: &shared_cache,
        notify_map: &notify_map,
        walker_done: &walker_done,
        fetch_wait_timeout,
        metrics: &metrics,
        policy: &policy,
    };

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
            let info = match ensure_manifest(
                &edge.canonical,
                client.clone(),
                &route_table,
                &shared_cache,
                &notify_map,
                &walker_done,
                fetch_wait_timeout,
                &metrics,
                &policy,
            )
            .await
            {
                Ok(info) => info,
                Err(err) => {
                    propagate_fetch_error(&edge, &err, &mut state)?;
                    continue;
                }
            };
            let preferred =
                preferred_tree_compatible_version(&edge, &info, &policy, &tree_provider).await;
            process_edge_with_preferred(&edge, &info, preferred, &mut state)?;
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
        let policy_drain = policy.clone();
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
                let policy = policy_drain.clone();
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
                        &policy,
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
    // contract in `format_solution`).
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
