use super::super::*;

pub(in crate::commands::install) struct OnlineResolutionPhaseInput<'a> {
    pub(in crate::commands::install) start: Instant,
    pub(in crate::commands::install) lockfile_result: Option<LockfileFastPath>,
    pub(in crate::commands::install) arc_client: Arc<RegistryClient>,
    pub(in crate::commands::install) route_table: RouteTable,
    pub(in crate::commands::install) project_dir: &'a Path,
    pub(in crate::commands::install) deps: &'a mut HashMap<String, String>,
    pub(in crate::commands::install) pkg: &'a lpm_workspace::PackageJson,
    pub(in crate::commands::install) requested_add_count: Option<usize>,
    pub(in crate::commands::install) json_output: bool,
    pub(in crate::commands::install) requested_v2_mode: bool,
    pub(in crate::commands::install) v2_workspace_root_pre_resolve:
        &'a V2WorkspaceRootPreResolveResult,
    pub(in crate::commands::install) workspace_member_deps: &'a mut Vec<WorkspaceMemberLink>,
    pub(in crate::commands::install) all_workspace_members: &'a [WorkspaceMemberLink],
    pub(in crate::commands::install) store: PackageStore,
    pub(in crate::commands::install) store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    pub(in crate::commands::install) fetch_semaphore: Arc<Semaphore>,
    pub(in crate::commands::install) fetch_extract_limiter: FetchExtractLimiter,
    pub(in crate::commands::install) fetch_coord: Arc<FetchCoordinator>,
    pub(in crate::commands::install) gate_stats: Arc<GateStats>,
    pub(in crate::commands::install) npm_firewall_mode: crate::npm_firewall_config::NpmFirewallMode,
    pub(in crate::commands::install) npm_firewall_lookup_mode: NpmFirewallLookupMode,
    pub(in crate::commands::install) npm_firewall_policy_profile:
        lpm_registry::client::NpmFirewallPolicyProfile,
    pub(in crate::commands::install) npm_firewall_chunk_size: usize,
    pub(in crate::commands::install) policy_extension_configs:
        &'a [policy_extensions::PolicyExtensionConfig],
    pub(in crate::commands::install) force: bool,
    pub(in crate::commands::install) offline: bool,
    pub(in crate::commands::install) omit_policy: InstallOmitPolicy,
    pub(in crate::commands::install) production_dependency_names: &'a HashSet<String>,
    pub(in crate::commands::install) pubgrub_opt_out: bool,
    pub(in crate::commands::install) auto_install_peers: bool,
    pub(in crate::commands::install) resolver_policy: lpm_resolver::ResolverPolicy,
    pub(in crate::commands::install) resolver_min_age_secs: u64,
    pub(in crate::commands::install) override_set: OverrideSet,
    pub(in crate::commands::install) strict_peer_dependencies: bool,
    pub(in crate::commands::install) peer_conflict_auto_isolation_allowed: bool,
    pub(in crate::commands::install) configured_linker_mode: lpm_linker::LinkerMode,
    pub(in crate::commands::install) auto_isolated_peer_conflicts: bool,
    pub(in crate::commands::install) linker_mode: lpm_linker::LinkerMode,
    pub(in crate::commands::install) strict_integrity: bool,
    pub(in crate::commands::install) streaming_fetch: bool,
}

pub(in crate::commands::install) struct OnlineResolutionPhaseResult {
    pub(in crate::commands::install) packages: Vec<InstallPackage>,
    pub(in crate::commands::install) packages_for_lockfile: Vec<InstallPackage>,
    pub(in crate::commands::install) resolve_ms: u128,
    pub(in crate::commands::install) used_lockfile: bool,
    pub(in crate::commands::install) platform_skipped: usize,
    pub(in crate::commands::install) latest_stable_versions: HashMap<String, String>,
    pub(in crate::commands::install) applied_overrides: Vec<OverrideHit>,
    pub(in crate::commands::install) peer_conflicts: Vec<lpm_resolver::PeerConflictReport>,
    pub(in crate::commands::install) peer_warnings: Vec<PeerWarning>,
    pub(in crate::commands::install) ambient_peer_installs_for_lockfile: Vec<String>,
    pub(in crate::commands::install) spec_tracker: SpeculativeKeyTracker,
    pub(in crate::commands::install) speculation_join: Option<SpeculationJoin>,
    pub(in crate::commands::install) fetch_overlap_join: Option<FetchOverlapJoin>,
    pub(in crate::commands::install) npm_firewall_preflight_join: Option<NpmFirewallPreflightJoin>,
    pub(in crate::commands::install) post_firewall_fetch_overlap_allowed: bool,
    pub(in crate::commands::install) resolved_with: &'static str,
    pub(in crate::commands::install) streaming_metrics: lpm_resolver::StreamingBfsMetrics,
    pub(in crate::commands::install) initial_batch_ms: u128,
    pub(in crate::commands::install) resolver_stage_timing: lpm_resolver::StageTiming,
    pub(in crate::commands::install) fast_path_lockfile: Option<lpm_lockfile::Lockfile>,
    pub(in crate::commands::install) lockfile_peer_context_authoritative: bool,
    pub(in crate::commands::install) needs_binary_upgrade: bool,
    pub(in crate::commands::install) wf_setup_ms: u128,
    pub(in crate::commands::install) wf_resolve_end_ms: u128,
    pub(in crate::commands::install) auto_isolated_peer_conflicts: bool,
    pub(in crate::commands::install) linker_mode: lpm_linker::LinkerMode,
}

pub(in crate::commands::install) async fn run_online_resolution_phase(
    input: OnlineResolutionPhaseInput<'_>,
) -> Result<OnlineResolutionPhaseResult, LpmError> {
    let OnlineResolutionPhaseInput {
        start,
        lockfile_result,
        arc_client,
        route_table,
        project_dir,
        deps,
        pkg,
        requested_add_count,
        json_output,
        requested_v2_mode,
        v2_workspace_root_pre_resolve,
        workspace_member_deps,
        all_workspace_members,
        store,
        store_v2_handle,
        fetch_semaphore,
        fetch_extract_limiter,
        fetch_coord,
        gate_stats,
        npm_firewall_mode,
        npm_firewall_lookup_mode,
        npm_firewall_policy_profile,
        npm_firewall_chunk_size,
        policy_extension_configs,
        force,
        offline,
        omit_policy,
        production_dependency_names,
        pubgrub_opt_out,
        auto_install_peers,
        resolver_policy,
        resolver_min_age_secs,
        override_set,
        strict_peer_dependencies,
        peer_conflict_auto_isolation_allowed,
        configured_linker_mode,
        auto_isolated_peer_conflicts,
        linker_mode,
        strict_integrity,
        streaming_fetch,
    } = input;

    let NonRegistryPreResolveResult {
        install_pkgs: tarball_url_install_pkgs,
        source_deps: non_registry_source_deps,
        additional_workspace_links,
    } = pre_resolve_non_registry_deps(
        &arc_client,
        &store,
        project_dir,
        deps,
        json_output,
        strict_integrity,
        all_workspace_members,
    )
    .await?;

    merge_workspace_member_links(
        workspace_member_deps,
        additional_workspace_links.into_iter().chain(
            v2_workspace_root_pre_resolve
                .additional_workspace_links
                .iter()
                .cloned(),
        ),
    );
    expand_workspace_member_deps_with_transitives(workspace_member_deps, all_workspace_members)?;

    let spec_tracker = SpeculativeKeyTracker::default();
    let fetch_coord: Arc<FetchCoordinator> = fetch_coord;
    let mut speculation_join: Option<SpeculationJoin> = None;
    let mut fetch_overlap_join: Option<FetchOverlapJoin> = None;
    let mut npm_firewall_preflight_join: Option<NpmFirewallPreflightJoin> = None;
    let mut post_firewall_fetch_overlap_allowed = false;
    let mut resolved_with: &'static str = "greedy-fusion";
    let streaming_metrics = lpm_resolver::StreamingBfsMetrics::new();
    let mut initial_batch_ms: u128 = 0;
    let mut resolver_stage_timing = lpm_resolver::StageTiming::default();
    let mut fast_path_lockfile: Option<lpm_lockfile::Lockfile> = None;
    let mut lockfile_peer_context_authoritative = false;
    let mut needs_binary_upgrade = false;
    let wf_setup_ms = start.elapsed().as_millis();
    let mut applied_overrides: Vec<OverrideHit> = Vec::new();
    let mut peer_conflicts: Vec<lpm_resolver::PeerConflictReport> = Vec::new();
    let mut peer_warnings: Vec<PeerWarning> = Vec::new();
    let mut ambient_peer_installs_for_lockfile: Vec<String> = Vec::new();
    let mut auto_isolated_peer_conflicts = auto_isolated_peer_conflicts;
    let mut linker_mode = linker_mode;

    let (mut packages, resolve_ms, used_lockfile, mut platform_skipped, latest_stable_versions) =
        match lockfile_result {
            Some(fast_path) => {
                if !json_output {
                    output::info(&format!(
                        "Using lockfile ({} packages)",
                        fast_path.packages.len().to_string().bold()
                    ));
                }
                lockfile_peer_context_authoritative = fast_path.lockfile.metadata.lockfile_version
                    >= MIN_LOCKFILE_VERSION_WITH_AUTHORITATIVE_PEER_STATE;
                fast_path_lockfile = Some(fast_path.lockfile);
                needs_binary_upgrade = fast_path.needs_binary_upgrade;
                (fast_path.packages, 0u128, true, 0usize, HashMap::new())
            }
            None => {
                let resolve_start = Instant::now();
                let fusion_disabled = std::env::var("LPM_GREEDY_FUSION").as_deref() == Ok("0");
                let fusion_enabled_local = !pubgrub_opt_out && !fusion_disabled;

                resolved_with = if pubgrub_opt_out {
                    "pubgrub"
                } else if fusion_disabled {
                    "greedy"
                } else {
                    "greedy-fusion"
                };
                let speculation_deps: HashMap<String, String> = if omit_policy.dev {
                    deps.iter()
                        .filter(|(name, _)| production_dependency_names.contains(*name))
                        .map(|(name, range)| (name.clone(), range.clone()))
                        .collect()
                } else {
                    deps.clone()
                };

                let (resolve_res, initial_batch_ms_measured): (
                    Result<lpm_resolver::ResolveResult, LpmError>,
                    u128,
                ) = if fusion_enabled_local {
                    let fetch_overlap_allowed_local =
                        fetch_overlap_enabled(fusion_enabled_local, force, omit_policy.dev);
                    let preflight_disables_tarball_prefetch = npm_firewall_mode
                        .disables_tarball_prefetch()
                        || policy_extensions_disable_tarball_prefetch(policy_extension_configs);
                    let fetch_overlap_downloads_during_resolve =
                        fetch_overlap_allowed_local && !preflight_disables_tarball_prefetch;
                    if preflight_disables_tarball_prefetch && fetch_overlap_allowed_local {
                        post_firewall_fetch_overlap_allowed = true;
                    }
                    let npm_fanout = positive_usize_env_or_default(
                        "LPM_NPM_FANOUT",
                        default_fusion_npm_fanout(
                            fetch_overlap_downloads_during_resolve,
                            resolver_min_age_secs,
                        ),
                    );
                    let speculation_permits = positive_usize_env_or_default(
                        ENV_FUSION_SPECULATION_PERMITS,
                        DEFAULT_FUSION_SPECULATION_PERMITS,
                    );

                    let shared_cache: lpm_resolver::SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, all_workspace_members)?;
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        Some(Arc::new(Semaphore::new(speculation_permits))),
                        fetch_coord.clone(),
                        if npm_firewall_mode.disables_tarball_prefetch()
                            || policy_extensions_disable_tarball_prefetch(policy_extension_configs)
                        {
                            HashMap::new()
                        } else {
                            speculation_deps
                        },
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );
                    let selected_package_fetch_overlap_allowed = fetch_overlap_allowed_local
                        && !policy_extensions_disable_tarball_prefetch(policy_extension_configs);
                    let selected_package_tx = if selected_package_fetch_overlap_allowed {
                        if npm_firewall_mode.is_enabled() {
                            let (selected_tx, selected_rx) = tokio::sync::mpsc::unbounded_channel();
                            let (fetch_tx, fetch_rx) = tokio::sync::mpsc::unbounded_channel();
                            fetch_overlap_join = Some(spawn_fetch_overlap_dispatcher(
                                fetch_rx,
                                arc_client.clone(),
                                route_table.clone(),
                                store.clone(),
                                store_v2_handle.clone(),
                                fetch_semaphore.clone(),
                                fetch_coord.clone(),
                                project_dir.to_path_buf(),
                                gate_stats.clone(),
                                fetch_extract_limiter.clone(),
                                streaming_fetch,
                                1,
                            ));
                            npm_firewall_preflight_join =
                                Some(spawn_chunked_npm_firewall_preflight(
                                    selected_rx,
                                    fetch_tx,
                                    arc_client.clone(),
                                    NpmFirewallChunkedPreflightConfig {
                                        route_table: route_table.clone(),
                                        mode: npm_firewall_mode,
                                        lookup_mode: npm_firewall_lookup_mode,
                                        policy_profile: npm_firewall_policy_profile,
                                        offline,
                                        chunk_size: npm_firewall_chunk_size,
                                    },
                                ));
                            Some(selected_tx)
                        } else {
                            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                            fetch_overlap_join = Some(spawn_fetch_overlap_dispatcher(
                                rx,
                                arc_client.clone(),
                                route_table.clone(),
                                store.clone(),
                                store_v2_handle.clone(),
                                fetch_semaphore.clone(),
                                fetch_coord.clone(),
                                project_dir.to_path_buf(),
                                gate_stats.clone(),
                                fetch_extract_limiter.clone(),
                                streaming_fetch,
                                fetch_overlap_min_selected(),
                            ));
                            Some(tx)
                        }
                    } else {
                        None
                    };
                    let res = lpm_resolver::resolve_greedy_fused_with_cache_options_policy_and_selected_events(
                        arc_client.clone(),
                        deps.clone(),
                        override_set.clone(),
                        route_table.clone(),
                        npm_fanout,
                        Some(spec_tx),
                        shared_cache,
                        auto_install_peers,
                        !omit_policy.optional,
                        resolver_policy.clone(),
                        selected_package_tx,
                    )
                    .await
                    .map_err(crate::resolver_error::resolver_error_to_lpm);

                    speculation_join = Some(SpeculationJoin {
                        producer: None,
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });
                    (res, 0u128)
                } else {
                    let dep_names: Vec<String> = deps.keys().cloned().collect();
                    use lpm_resolver::{BfsWalker, NotifyMap, SharedCache, WalkerDone};
                    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
                    seed_workspace_resolver_cache(&shared_cache, all_workspace_members)?;
                    let notify_map: NotifyMap = Arc::new(dashmap::DashMap::new());
                    let walker_done: WalkerDone =
                        Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (spec_tx, spec_rx) =
                        tokio::sync::mpsc::channel::<(String, SpeculativePackageMetadata)>(512);
                    let (roots_ready_tx, roots_ready_rx) = tokio::sync::oneshot::channel::<()>();

                    let batch_start = Instant::now();
                    let walker_handle = if dep_names.is_empty() {
                        let _ = roots_ready_tx.send(());
                        walker_done.store(true, std::sync::atomic::Ordering::Release);
                        tokio::spawn(async { Ok(lpm_resolver::WalkerSummary::default()) })
                    } else {
                        tokio::spawn(
                            BfsWalker::new(
                                arc_client.clone(),
                                shared_cache.clone(),
                                notify_map.clone(),
                                walker_done.clone(),
                                spec_tx,
                                roots_ready_tx,
                                dep_names.clone(),
                                route_table.clone(),
                            )
                            .run(),
                        )
                    };

                    let (dispatcher_handle, dispatcher_counters) = spawn_speculation_dispatcher(
                        spec_rx,
                        arc_client.clone(),
                        route_table.clone(),
                        store.clone(),
                        fetch_semaphore.clone(),
                        None,
                        fetch_coord.clone(),
                        if npm_firewall_mode.disables_tarball_prefetch()
                            || policy_extensions_disable_tarball_prefetch(policy_extension_configs)
                        {
                            HashMap::new()
                        } else {
                            speculation_deps
                        },
                        spec_tracker.clone(),
                        store_v2_handle.clone(),
                        fetch_extract_limiter.clone(),
                    );

                    let resolve_client = arc_client.clone();
                    let resolve_deps = deps.clone();
                    let resolve_overrides = override_set.clone();
                    let shared_cache_for_resolve = shared_cache.clone();
                    let notify_map_for_resolve = notify_map.clone();
                    let walker_done_for_resolve = walker_done.clone();
                    let streaming_metrics_for_resolve = streaming_metrics.clone();
                    let (resolve_res_legacy, batch_ms): (
                        Result<lpm_resolver::ResolveResult, LpmError>,
                        u128,
                    ) = async {
                        let _ = roots_ready_rx.await;
                        let roots_ready_at = batch_start.elapsed().as_millis();
                        let w2_resolve_start = Instant::now();
                        let result = lpm_resolver::resolve_with_shared_cache_options_and_policy(
                            resolve_client,
                            resolve_deps,
                            resolve_overrides,
                            shared_cache_for_resolve,
                            notify_map_for_resolve,
                            walker_done_for_resolve,
                            std::time::Duration::from_secs(5),
                            route_table.clone(),
                            streaming_metrics_for_resolve,
                            auto_install_peers,
                            !omit_policy.optional,
                            resolver_policy.clone(),
                        )
                        .await
                        .map_err(crate::resolver_error::resolver_error_to_lpm);
                        tracing::debug!(
                            "perf.w2_resolve_after_roots ms={}",
                            w2_resolve_start.elapsed().as_millis()
                        );
                        (result, roots_ready_at)
                    }
                    .await;

                    speculation_join = Some(SpeculationJoin {
                        producer: Some(walker_handle),
                        dispatcher: dispatcher_handle,
                        dispatched: dispatcher_counters.dispatched,
                        completed: dispatcher_counters.completed,
                        task_ms_sum: dispatcher_counters.task_ms_sum,
                        transitive_dispatched: dispatcher_counters.transitive_dispatched,
                        max_depth_reached: dispatcher_counters.max_depth_reached,
                        no_version_match: dispatcher_counters.no_version_match,
                        unresolved_parked: dispatcher_counters.unresolved_parked,
                        failed: dispatcher_counters.failed,
                        skipped_no_permit: dispatcher_counters.skipped_no_permit,
                        skipped_auth: dispatcher_counters.skipped_auth,
                    });

                    (resolve_res_legacy, batch_ms)
                };
                initial_batch_ms = initial_batch_ms_measured;

                let resolve_result = resolve_res?;
                let ms = resolve_start.elapsed().as_millis();

                let peer_rules_cfg = pkg.lpm.as_ref().map(|l| &l.peer_dependency_rules);
                let compiled_peer_rules = match peer_rules_cfg {
                    Some(r) => CompiledPeerRules::compile(
                        &r.ignore_missing,
                        &r.allowed_versions,
                        &r.allow_any,
                    )
                    .map_err(|e| {
                        LpmError::Script(format!("invalid lpm.peerDependencyRules: {e}"))
                    })?,
                    None => CompiledPeerRules::default(),
                };
                peer_warnings = check_unmet_peers(
                    &resolve_result.packages,
                    &resolve_result.cache,
                    &compiled_peer_rules,
                );
                if !peer_warnings.is_empty() && !json_output {
                    for w in &peer_warnings {
                        output::warn(&format!("peer dep: {w}"));
                    }
                }

                applied_overrides = resolve_result.applied_overrides.clone();
                peer_conflicts = resolve_result.peer_conflicts.clone();

                if strict_peer_dependencies
                    && let Some(err) = strict_peer_dependency_error(&peer_warnings, &peer_conflicts)
                {
                    return Err(err);
                }

                if peer_conflict_auto_isolation_allowed {
                    auto_isolated_peer_conflicts = !peer_conflicts.is_empty();
                    linker_mode = if auto_isolated_peer_conflicts {
                        if matches!(configured_linker_mode, lpm_linker::LinkerMode::Hoisted)
                            && !json_output
                        {
                            output::info(
                                "Peer conflicts detected; using isolated linker for this install.",
                            );
                        }
                        lpm_linker::LinkerMode::Isolated
                    } else {
                        configured_linker_mode
                    };
                }

                let platform_skipped = resolve_result.platform_skipped;
                resolver_stage_timing = resolve_result.stage_timing;
                ambient_peer_installs_for_lockfile = resolve_result.ambient_peer_installs.clone();

                let mut packages = resolved_to_install_packages_with_workspace_members(
                    &resolve_result.packages,
                    deps,
                    &resolve_result.root_aliases,
                    &resolve_result.ambient_peer_installs,
                    &resolve_result.cache,
                    &route_table,
                    all_workspace_members,
                    project_dir,
                );
                let latest_stable = build_latest_stable_versions(&resolve_result.cache);
                packages.extend(tarball_url_install_pkgs.iter().cloned());
                apply_post_resolve_directory_link_fixup(&mut packages, &non_registry_source_deps);
                enforce_registry_integrity_policy(&packages, strict_integrity, json_output)?;

                if !json_output {
                    let reported_install_count = requested_add_count.unwrap_or(packages.len());
                    let firewall_active = npm_firewall_mode.is_enabled()
                        && npm_firewall_has_packages(
                            &packages,
                            &route_table,
                            arc_client.as_ref(),
                            npm_firewall_lookup_mode,
                        );
                    let install_message = format!(
                        "Installing {} {}",
                        reported_install_count.to_string().bold(),
                        install_ui::packages_word(reported_install_count),
                    );
                    install_ui::phase(&install_ui::with_firewall_badge(
                        install_message,
                        firewall_active,
                    ));
                    for report in &resolve_result.peer_conflicts {
                        let unsatisfied_str = report
                            .unsatisfied_consumers
                            .iter()
                            .map(|(c, r)| format!("{c} wants {r}"))
                            .collect::<Vec<_>>()
                            .join("; ");
                        output::warn(&format!(
                            "peer {} pinned to {} but {} unsatisfied consumer(s): {}",
                            report.canonical.bold(),
                            report.chosen_version,
                            report.unsatisfied_consumers.len(),
                            unsatisfied_str,
                        ));
                    }
                }
                (packages, ms, false, platform_skipped, latest_stable)
            }
        };
    let wf_resolve_end_ms = start.elapsed().as_millis();

    if requested_v2_mode && !v2_workspace_root_pre_resolve.install_pkgs.is_empty() {
        packages.extend(v2_workspace_root_pre_resolve.install_pkgs.iter().cloned());
        apply_post_resolve_directory_link_fixup(
            &mut packages,
            &v2_workspace_root_pre_resolve.source_deps,
        );
    }
    dedupe_install_packages_by_identity(&mut packages);

    let packages_for_lockfile = packages.clone();
    if omit_policy.dev {
        filter_dev_packages(&mut packages, production_dependency_names);
    }
    platform_skipped += filter_platform_packages(&mut packages)?;

    Ok(OnlineResolutionPhaseResult {
        packages,
        packages_for_lockfile,
        resolve_ms,
        used_lockfile,
        platform_skipped,
        latest_stable_versions,
        applied_overrides,
        peer_conflicts,
        peer_warnings,
        ambient_peer_installs_for_lockfile,
        spec_tracker,
        speculation_join,
        fetch_overlap_join,
        npm_firewall_preflight_join,
        post_firewall_fetch_overlap_allowed,
        resolved_with,
        streaming_metrics,
        initial_batch_ms,
        resolver_stage_timing,
        fast_path_lockfile,
        lockfile_peer_context_authoritative,
        needs_binary_upgrade,
        wf_setup_ms,
        wf_resolve_end_ms,
        auto_isolated_peer_conflicts,
        linker_mode,
    })
}
