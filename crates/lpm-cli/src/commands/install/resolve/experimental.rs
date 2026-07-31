use super::super::*;
use super::fetch_schedule::{
    FetchHandle, lockfile_fetch_schedule, maybe_spawn_fetch, spawn_fetches_for_packages,
    spawn_missing_fetches_for_drafts,
};
use super::graph::{
    NodeResolution, PackageDraft, ResolveFuture, attach_dependency_edge, enqueue_dependencies,
    ensure_package_can_materialize, load_lockfile_graph_packages, mark_required_closure,
    merge_node_into_packages, normalize_draft_optional_reachability,
    normalize_install_package_optional_reachability, optional_dependency_names_from_resolver_cache,
    package_should_materialize, resolve_node, root_resolve_requests, select_or_reuse_node,
};
use super::peer::{attach_peer_edges_to_drafts, drain_ambient_peer_installs};
use super::{
    ExperimentalResolverParity, ExperimentalResolverParityMode, ExperimentalResolverStageTimings,
    ExperimentalResolverStats, MetadataCaches, MetadataStats, PackageIdentity,
    compare_package_parity_with_baseline,
};
use futures::stream::{FuturesUnordered, StreamExt};
use lpm_linker::LinkResult;

const ENV_EXPERIMENTAL_RESOLVER: &str = "LPM_EXPERIMENTAL_INSTALLER_SPIKE";
const ENV_EXPERIMENTAL_RESOLVER_FETCH_CONCURRENCY: &str = "LPM_INSTALLER_SPIKE_CONCURRENCY";
const ENV_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY: &str =
    "LPM_INSTALLER_SPIKE_METADATA_CONCURRENCY";
const ENV_EXPERIMENTAL_RESOLVER_GRAPH: &str = "LPM_INSTALLER_SPIKE_GRAPH";
const ENV_EXPERIMENTAL_RESOLVER_BENCHMARK_ONLY: &str = "LPM_INSTALLER_SPIKE_BENCHMARK_ONLY";
const DEFAULT_EXPERIMENTAL_RESOLVER_FETCH_CONCURRENCY: usize = 64;
pub(super) const DEFAULT_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY: usize = 192;

pub(in crate::commands::install) fn enabled() -> bool {
    std::env::var(ENV_EXPERIMENTAL_RESOLVER).as_deref() == Ok("1")
}

#[derive(Debug, Clone, Copy)]
pub(in crate::commands::install) struct ExperimentalResolverAdmission {
    pub(in crate::commands::install) json_output: bool,
    pub(in crate::commands::install) frozen_lockfile_active: bool,
    pub(in crate::commands::install) omit_policy: InstallOmitPolicy,
    pub(in crate::commands::install) has_workspace_member_deps: bool,
    pub(in crate::commands::install) has_v2_workspace_member_deps: bool,
    pub(in crate::commands::install) has_tarball_source_deps: bool,
    pub(in crate::commands::install) verify_registry_signatures: bool,
    pub(in crate::commands::install) strict_integrity: bool,
    pub(in crate::commands::install) force_security_floor: bool,
    pub(in crate::commands::install) npm_firewall_enabled: bool,
    pub(in crate::commands::install) policy_extensions_enabled: bool,
    pub(in crate::commands::install) auto_build: bool,
    pub(in crate::commands::install) script_policy_override:
        Option<crate::script_policy_config::ScriptPolicy>,
    pub(in crate::commands::install) script_policy_is_default: bool,
    pub(in crate::commands::install) has_trusted_dependencies: bool,
    pub(in crate::commands::install) strict_release_age_replay: bool,
    pub(in crate::commands::install) allow_new: bool,
    pub(in crate::commands::install) is_add_invocation: bool,
    pub(in crate::commands::install) has_direct_versions_out: bool,
    pub(in crate::commands::install) has_target_set: bool,
    pub(in crate::commands::install) audit_after_install: bool,
    pub(in crate::commands::install) no_skills: bool,
    pub(in crate::commands::install) no_security_summary: bool,
    pub(in crate::commands::install) verbose: bool,
    pub(in crate::commands::install) drift_ignore_policy_is_default: bool,
    pub(in crate::commands::install) verify_policy_is_default: bool,
}

pub(in crate::commands::install) fn should_run(
    admission: ExperimentalResolverAdmission,
) -> Result<bool, LpmError> {
    if !enabled() {
        return Ok(false);
    }
    let benchmark_only =
        std::env::var(ENV_EXPERIMENTAL_RESOLVER_BENCHMARK_ONLY).as_deref() == Ok("1");
    let reasons = unsupported_admission_reasons(
        admission,
        ExperimentalResolverGraphSource::from_env(),
        ExperimentalResolverParityMode::from_env(),
        benchmark_only,
    );
    if reasons.is_empty() {
        return Ok(true);
    }
    Err(LpmError::Registry(format!(
        "experimental installer spike is limited to benchmark installs; unsupported for this invocation: {}",
        reasons.join("; ")
    )))
}

pub(super) fn unsupported_admission_reasons(
    admission: ExperimentalResolverAdmission,
    graph_source: ExperimentalResolverGraphSource,
    parity_mode: ExperimentalResolverParityMode,
    benchmark_only: bool,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if graph_source == ExperimentalResolverGraphSource::Invalid {
        reasons.push("set LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist or lockfile");
    }
    if !benchmark_only {
        reasons.push("set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1");
    }
    let lockfile_graph = graph_source.uses_lockfile();
    if lockfile_graph
        && matches!(
            parity_mode,
            ExperimentalResolverParityMode::FreshResolve { .. }
        )
    {
        reasons.push("use lockfile parity or disable parity");
    }
    if lockfile_graph && !admission.frozen_lockfile_active {
        reasons.push("use a frozen lockfile install");
    }
    if graph_source == ExperimentalResolverGraphSource::ResolveWorklist
        && admission.frozen_lockfile_active
    {
        reasons.push("set LPM_INSTALLER_SPIKE_GRAPH=lockfile for frozen installs");
    }
    if graph_source == ExperimentalResolverGraphSource::ResolveWorklist
        && parity_mode != (ExperimentalResolverParityMode::FreshResolve { deny: true })
    {
        reasons.push("set LPM_INSTALLER_SPIKE_PARITY=deny for live graph parity");
    }
    if !admission.json_output {
        reasons.push("use --json");
    }
    if !admission.no_security_summary {
        reasons.push("use --no-security-summary");
    }
    if !admission.no_skills {
        reasons.push("use --no-skills");
    }
    if admission.omit_policy.dev {
        reasons.push("--prod/--omit=dev is not supported");
    }
    if admission.omit_policy.optional {
        reasons.push("--omit=optional is not supported");
    }
    if (admission.has_workspace_member_deps || admission.has_v2_workspace_member_deps)
        && graph_source != ExperimentalResolverGraphSource::ResolveWorklist
    {
        reasons.push("workspace member links require resolve-worklist graph mode");
    }
    if admission.has_tarball_source_deps {
        reasons.push("tarball source deps are not supported");
    }
    if admission.verify_registry_signatures {
        reasons.push("registry signature verification is not supported");
    }
    if admission.strict_integrity {
        reasons.push("strict integrity mode is not supported");
    }
    if admission.force_security_floor {
        reasons.push("force-security-floor is not supported");
    }
    if admission.npm_firewall_enabled {
        reasons.push("npm firewall is not supported");
    }
    if admission.policy_extensions_enabled {
        reasons.push("policy extensions are not supported");
    }
    if admission.auto_build
        || admission.script_policy_override.is_some()
        || !admission.script_policy_is_default
        || admission.has_trusted_dependencies
    {
        reasons.push("script policy/build execution options are not supported");
    }
    if admission.strict_release_age_replay {
        reasons.push("strict minimumReleaseAge lockfile replay is not supported");
    }
    if admission.allow_new {
        reasons.push("--allow-new is not supported");
    }
    if admission.is_add_invocation || admission.has_direct_versions_out {
        reasons.push("add-style installs are not supported");
    }
    if admission.has_target_set {
        reasons.push("workspace filtered installs are not supported");
    }
    if admission.audit_after_install {
        reasons.push("audit-after-install is not supported");
    }
    if admission.verbose {
        reasons.push("--verbose is not supported");
    }
    if !admission.drift_ignore_policy_is_default {
        reasons.push("provenance drift waivers are not supported");
    }
    if !admission.verify_policy_is_default {
        reasons.push("provenance verification policy overrides are not supported");
    }
    reasons
}

struct LinkOutcomeWithTimings {
    result: LinkResult,
    task_await_ms: u128,
    finalize_ms: u128,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::commands::install) async fn run(
    client: Arc<RegistryClient>,
    project_dir: &Path,
    deps: &HashMap<String, String>,
    pkg: &lpm_workspace::PackageJson,
    route_table: RouteTable,
    json_output: bool,
    start: Instant,
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    lpm_root: &lpm_common::LpmRoot,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    compatibility_bin_names: &[String],
    override_set: OverrideSet,
    resolver_policy: lpm_resolver::ResolverPolicy,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    optional_registry_roots: &HashSet<String>,
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
    workspace_member_deps: &[WorkspaceMemberLink],
    all_workspace_members: &[WorkspaceMemberLink],
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    current_patches: &HashMap<String, PatchedDependencyEntry>,
    prior_patch_state: &Option<patch_state::PatchState>,
    current_patch_fingerprint: &str,
    dependency_engine_policy: &crate::engine_check::DependencyEnginePolicy,
    install_accounting: ManagedInstallAccounting,
    emit_install_report: bool,
) -> Result<(), LpmError> {
    if !json_output {
        output::info("using experimental resolver path");
    }

    let fetch_concurrency = experimental_resolver_fetch_concurrency();
    let metadata_concurrency = experimental_resolver_metadata_concurrency();
    let graph_source = ExperimentalResolverGraphSource::from_env();
    let timing_detail_mode = TimingDetailMode::from_env();
    let fetch_queue = Arc::new(Semaphore::new(fetch_concurrency));
    let fetch_extract_limiter = configured_fetch_extract_limiter(store_v2_handle.is_some());
    let metadata_queue = Arc::new(Semaphore::new(metadata_concurrency));
    let metadata_caches = MetadataCaches::new();
    let store = PackageStore::from_root(lpm_root);
    let patch_fingerprints = compute_patch_fingerprints(current_patches, project_dir)?;
    let gate_stats = Arc::new(GateStats::default());

    let setup_ms = start.elapsed().as_millis();
    let resolve_start = Instant::now();
    let metadata_stats = Arc::new(MetadataStats::new(resolve_start));
    let mut stats = ExperimentalResolverStats::default();
    let mut stage_timings = ExperimentalResolverStageTimings::default();
    let mut fetch_handles: HashMap<String, FetchHandle> = HashMap::new();
    let mut install_packages = match graph_source {
        ExperimentalResolverGraphSource::ResolveWorklist => {
            let mut pending: FuturesUnordered<ResolveFuture> = FuturesUnordered::new();
            let mut packages: HashMap<PackageIdentity, PackageDraft> =
                HashMap::with_capacity(deps.len().saturating_mul(4).max(32));
            let root_requests = root_resolve_requests(deps, optional_registry_roots);
            stats.root_requests = root_requests.len() as u64;

            for request in root_requests {
                pending.push(Box::pin(resolve_node(
                    request,
                    Arc::clone(&client),
                    route_table.clone(),
                    metadata_caches.clone(),
                    Arc::clone(&metadata_queue),
                    Arc::clone(&metadata_stats),
                    resolver_policy.clone(),
                )));
            }

            while let Some(result) = pending.next().await {
                match result? {
                    NodeResolution::SkippedOptionalMetadata => {
                        stats.skipped_optional += 1;
                    }
                    NodeResolution::Metadata { request, info } => {
                        let Some(node) = select_or_reuse_node(
                            request,
                            Arc::clone(&info),
                            &mut packages,
                            &override_set,
                            &resolver_policy,
                        )?
                        else {
                            stats.skipped_optional += 1;
                            continue;
                        };
                        stats.selected_nodes += 1;
                        if node.reused_existing {
                            stats.reused_existing_versions += 1;
                        }
                        let identity = (node.request.target_name.clone(), node.version.clone());
                        let merge = merge_node_into_packages(
                            &mut packages,
                            &node,
                            &route_table,
                            client.as_ref(),
                            &store,
                            project_dir,
                        );
                        if merge.became_required {
                            let draft = packages.get(&identity).ok_or_else(|| {
                                LpmError::Registry(format!(
                                    "experimental resolver lost package {}@{} during required promotion",
                                    identity.0, identity.1
                                ))
                            })?;
                            ensure_package_can_materialize(&draft.package)?;
                            mark_required_closure(&mut packages, &identity);
                        }

                        if let Some(parent) = node.request.parent.as_ref() {
                            attach_dependency_edge(&mut packages, parent, &node)?;
                        }

                        if merge.inserted {
                            stats.inserted_nodes += 1;
                            let package = packages
                                .get(&identity)
                                .map(|draft| draft.package.clone())
                                .ok_or_else(|| {
                                    LpmError::Registry(format!(
                                        "experimental resolver lost package {}@{} during insertion",
                                        identity.0, identity.1
                                    ))
                                })?;
                            if package_should_materialize(&package)? {
                                maybe_spawn_fetch(
                                    package,
                                    &store,
                                    store_v2_handle.clone(),
                                    project_dir,
                                    Arc::clone(&client),
                                    route_table.clone(),
                                    Arc::clone(&fetch_queue),
                                    Arc::clone(&gate_stats),
                                    force,
                                    fetch_extract_limiter.clone(),
                                    install_accounting,
                                    ArtifactSelection::FreshResolution,
                                    &mut fetch_handles,
                                    &mut stats,
                                );
                            } else {
                                stats.platform_pre_skipped += 1;
                            }
                            enqueue_dependencies(
                                &node,
                                &mut packages,
                                &mut pending,
                                &client,
                                &route_table,
                                &metadata_caches,
                                &metadata_queue,
                                &metadata_stats,
                                &resolver_policy,
                                include_optional_dependencies,
                                &mut stats,
                            )?;
                        } else {
                            stats.duplicate_nodes += 1;
                        }
                    }
                }
            }
            stage_timings.resolve_worklist_ms = resolve_start.elapsed().as_millis();

            let peer_drain_start = Instant::now();
            drain_ambient_peer_installs(
                &mut packages,
                &client,
                &route_table,
                &metadata_caches,
                &metadata_queue,
                &fetch_queue,
                &metadata_stats,
                &resolver_policy,
                include_optional_dependencies,
                auto_install_peers,
                &override_set,
                &store,
                project_dir,
                &mut fetch_handles,
                &mut stats,
                store_v2_handle.clone(),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                install_accounting,
            )
            .await?;
            stage_timings.peer_drain_ms = peer_drain_start.elapsed().as_millis();
            stats.metadata_requests = metadata_caches.request_count() as u64;
            stats.metadata_cache_hits = metadata_stats.ready_hit_count();

            let package_graph_start = Instant::now();
            normalize_draft_optional_reachability(&mut packages);
            spawn_missing_fetches_for_drafts(
                &packages,
                &store,
                store_v2_handle.clone(),
                project_dir,
                &client,
                &route_table,
                &fetch_queue,
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                install_accounting,
                &mut fetch_handles,
                &mut stats,
            )?;
            attach_peer_edges_to_drafts(&mut packages);
            let mut install_packages: Vec<InstallPackage> =
                packages.into_values().map(|draft| draft.package).collect();
            install_packages
                .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
            dedupe_install_packages_by_identity(&mut install_packages);
            stage_timings.package_graph_ms = package_graph_start.elapsed().as_millis();
            merge_pre_resolved_packages(
                &mut install_packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            spawn_fetches_for_packages(
                pre_resolved_install_pkgs,
                &store,
                store_v2_handle.clone(),
                project_dir,
                &client,
                &route_table,
                &fetch_queue,
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                install_accounting,
                ArtifactSelection::FreshResolution,
                &mut fetch_handles,
                &mut stats,
            )?;
            install_packages
        }
        ExperimentalResolverGraphSource::Lockfile => {
            let package_graph_start = Instant::now();
            let mut install_packages = load_lockfile_graph_packages(
                project_dir,
                deps,
                catalog_resolutions,
                client.as_ref(),
                gate_stats.as_ref(),
                auto_install_peers,
            )?;
            dedupe_install_packages_by_identity(&mut install_packages);
            install_packages
                .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
            stage_timings.package_graph_ms = package_graph_start.elapsed().as_millis();
            stage_timings.resolve_worklist_ms = resolve_start.elapsed().as_millis();
            stats.root_requests = deps.len() as u64;
            stats.selected_nodes = install_packages.len() as u64;
            stats.inserted_nodes = install_packages.len() as u64;
            merge_pre_resolved_packages(
                &mut install_packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            install_packages
        }
        ExperimentalResolverGraphSource::Invalid => {
            return Err(LpmError::Registry(
                "invalid experimental resolver graph".to_string(),
            ));
        }
    };
    filter_dependency_engine_packages(&mut install_packages, dependency_engine_policy)?;
    let mut platform_skipped = filter_platform_packages(&mut install_packages)?;
    if graph_source == ExperimentalResolverGraphSource::Lockfile {
        let fetch_packages = lockfile_fetch_schedule(&install_packages);
        spawn_fetches_for_packages(
            &fetch_packages,
            &store,
            store_v2_handle.clone(),
            project_dir,
            &client,
            &route_table,
            &fetch_queue,
            Arc::clone(&gate_stats),
            force,
            fetch_extract_limiter.clone(),
            install_accounting,
            ArtifactSelection::LockfileReplay,
            &mut fetch_handles,
            &mut stats,
        )?;
        platform_skipped += stats.platform_pre_skipped as usize;
    }
    let resolve_ms = resolve_start.elapsed().as_millis();

    let pre_fetch_start = Instant::now();
    let parity_start = Instant::now();
    let parity = compute_parity_if_requested(
        Arc::clone(&client),
        deps,
        override_set,
        route_table.clone(),
        resolver_policy,
        auto_install_peers,
        include_optional_dependencies,
        optional_registry_roots,
        all_workspace_members,
        catalog_resolutions,
        pre_resolved_install_pkgs,
        pre_resolved_source_deps,
        project_dir,
        &install_packages,
        json_output,
        dependency_engine_policy,
    )
    .await?;
    stage_timings.parity_ms = parity_start.elapsed().as_millis();

    let link_targets_start = Instant::now();
    let link_targets = build_experimental_link_targets(
        project_dir,
        &store,
        &install_packages,
        &patch_fingerprints,
    )?;
    stage_timings.link_targets_ms = link_targets_start.elapsed().as_millis();
    let v2_event_plan = match store_v2_handle.as_ref() {
        Some(store_v2) => {
            populate_v2_local_source_objects(&link_targets, store_v2)?;
            let v2_targets_start = Instant::now();
            let v2_targets = build_v2_targets(&install_packages, &link_targets)?;
            stage_timings.v2_targets_ms = v2_targets_start.elapsed().as_millis();
            let v2_prepare_start = Instant::now();
            let plan =
                lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
                    project_dir,
                    v2_targets.clone(),
                    store_v2,
                    linker_mode,
                    compatibility_bin_names,
                )?;
            stage_timings.v2_prepare_ms = v2_prepare_start.elapsed().as_millis();
            let v2_index_start = Instant::now();
            let target_by_key: HashMap<String, lpm_linker::v2::V2Target> = install_packages
                .iter()
                .zip(v2_targets)
                .map(|(package, target)| (install_pkg_key(package), target))
                .collect();
            stage_timings.v2_index_ms = v2_index_start.elapsed().as_millis();
            Some((Arc::new(plan), target_by_key))
        }
        None => None,
    };
    stage_timings.pre_fetch_overlap_ms = pre_fetch_start.elapsed().as_millis();

    let fetch_start = Instant::now();
    let mut fetch_breakdown = FetchBreakdown::default();
    let mut slow_package_timings = SlowPackageTimings::default();
    let mut downloaded = 0usize;
    let mut cached = 0usize;
    let mut fetch_join_set: FuturesUnordered<FetchHandle> = fetch_handles.into_values().collect();
    let v2_link_task_semaphore = Arc::new(Semaphore::new(v2_link_task_concurrency(
        install_packages.len(),
    )));
    let mut v2_link_handles: Vec<V2LinkHandle> = Vec::new();
    while let Some(handle_result) = fetch_join_set.next().await {
        let outcome = handle_result
            .map_err(|e| LpmError::Registry(format!("experimental fetch task panicked: {e}")))??;
        if outcome.cached {
            cached += 1;
        } else {
            downloaded += 1;
        }
        if let Some(timings) = outcome.timings {
            if timing_detail_mode.trace() {
                slow_package_timings.record_fetch(&outcome.package_display, timings);
            }
            fetch_breakdown.record(timings);
        }
        if let Some(computed_sri) = outcome.computed_sri {
            let mut parts = outcome.key.split('\0');
            let name = parts.next().unwrap_or_default();
            let version = parts.next().unwrap_or_default();
            if let Some(package) = install_packages
                .iter_mut()
                .find(|package| package.name == name && package.version == version)
            {
                package.integrity = Some(computed_sri);
            }
        }
        if let (Some((plan, target_by_key)), Some(store_v2)) =
            (v2_event_plan.as_ref(), store_v2_handle.as_ref())
            && let Some(target) = target_by_key.get(&outcome.key).cloned()
        {
            v2_link_handles.push(spawn_v2_link_task(
                Arc::clone(plan),
                target,
                Arc::clone(store_v2),
                Arc::clone(&v2_link_task_semaphore),
            ));
        }
    }
    let fetch_ms = fetch_start.elapsed().as_millis();
    stage_timings.fetch_join_ms = fetch_ms;

    let link_start = Instant::now();
    let link_outcome = if let (Some((plan, _)), Some(store_v2)) =
        (v2_event_plan.as_ref(), store_v2_handle.as_deref())
    {
        finish_v2_event_driven_link(
            project_dir,
            plan,
            store_v2,
            v2_link_handles,
            pkg.name.as_deref(),
            timing_detail_mode,
            &mut slow_package_timings,
        )
        .await?
    } else {
        let result = link_experimental_targets(
            project_dir,
            store_v2_handle.as_deref(),
            &install_packages,
            &link_targets,
            linker_mode,
            force,
            pkg.name.as_deref(),
            compatibility_bin_names,
        )?;
        LinkOutcomeWithTimings {
            result,
            task_await_ms: 0,
            finalize_ms: link_start.elapsed().as_millis(),
        }
    };
    stage_timings.link_task_await_ms = link_outcome.task_await_ms;
    stage_timings.link_finalize_ms = link_outcome.finalize_ms;
    let link_result = link_outcome.result;
    let workspace_links_created = link_workspace_members(project_dir, workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info_line(crate::install_ui::terminal_line!(
            "Linked {} workspace member(s)",
            install_ui::bold(&workspace_links_created.to_string())
        ));
    }
    let applied_patches = apply_patches_for_install(
        current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;
    persist_patch_state(
        project_dir,
        current_patches,
        prior_patch_state,
        &applied_patches,
    );
    let link_ms = link_start.elapsed().as_millis();
    let total_ms = start.elapsed().as_millis();

    report_pool_install_attribution(&client, &install_packages, install_accounting).await?;

    if emit_install_report && json_output {
        let package_json: Vec<serde_json::Value> = install_packages
            .iter()
            .map(|package| {
                serde_json::json!({
                    "name": package.name,
                    "version": package.version,
                    "source": package.source,
                    "direct": package.is_direct,
                })
            })
            .collect();
        let waterfall_json = serde_json::json!({
            "setup_ms": setup_ms,
            "resolve_ms": resolve_ms,
            "materialization_wait_ms": 0u128,
            "commit_wait_ms": 0u128,
            "post_resolve_work_ms": stage_timings.pre_fetch_overlap_ms,
            "pre_fetch_ms": stage_timings.pre_fetch_overlap_ms,
            "fetch_ms": fetch_ms,
            "pre_link_ms": 0u128,
            "link_ms": link_ms,
            "link_await_ms": stage_timings.link_task_await_ms,
            "link_finalize_ms": stage_timings.link_finalize_ms,
            "tail_ms": total_ms.saturating_sub(setup_ms.saturating_add(resolve_ms).saturating_add(stage_timings.pre_fetch_overlap_ms).saturating_add(fetch_ms).saturating_add(link_ms)),
            "total_ms": total_ms,
        });
        let mut experimental_json = serde_json::json!({
            "concurrency": fetch_concurrency,
            "metadata_concurrency": metadata_concurrency,
            "graph_source": graph_source.as_str(),
            "metadata_requests": stats.metadata_requests,
            "metadata_cache_hits": stats.metadata_cache_hits,
            "metadata": metadata_stats.to_json(TimingDetailMode::from_env().trace()),
            "root_requests": stats.root_requests,
            "dependency_requests_enqueued": stats.dependency_requests_enqueued,
            "peer_requests_enqueued": stats.peer_requests_enqueued,
            "selected_nodes": stats.selected_nodes,
            "inserted_nodes": stats.inserted_nodes,
            "duplicate_nodes": stats.duplicate_nodes,
            "reused_existing_versions": stats.reused_existing_versions,
            "inline_reused_edges": stats.inline_reused_edges,
            "inline_reuse_deferred_promotions": stats.inline_reuse_deferred_promotions,
            "skipped_optional": stats.skipped_optional,
            "platform_pre_skipped": stats.platform_pre_skipped,
            "fetch_dispatched": stats.fetch_dispatched,
            "platform_skipped": platform_skipped,
            "stages": stage_timings.to_json(),
            "parity": parity.to_json(),
            "tarball_url_gate": gate_stats.to_json(),
        });
        if timing_detail_mode.trace()
            && let serde_json::Value::Object(experimental) = &mut experimental_json
        {
            experimental.insert("slow_packages".to_string(), slow_package_timings.to_json());
        }
        let timing_json = serde_json::json!({
            "resolve_ms": resolve_ms,
            "fetch_ms": fetch_ms,
            "link_ms": link_ms,
            "total_ms": total_ms,
            "waterfall": waterfall_json,
            "fetch_breakdown": fetch_breakdown.to_json(),
            "experimental_installer_spike": experimental_json,
        });
        let mut json = serde_json::json!({
            "success": true,
            "experimental": "installer-spike",
            "packages": package_json,
            "count": install_packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": graph_source.uses_lockfile(),
            "duration_ms": total_ms as u64,
            "timing": timing_json,
            "warnings": [],
            "errors": [],
        });
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|patch| patch.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            fingerprint_json_value(current_patches.len(), current_patch_fingerprint);
        crate::security_floor::attach_security_posture(&mut json, false);
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if emit_install_report {
        output::success_line(crate::install_ui::terminal_line!(
            "{} packages installed in {}s",
            install_ui::bold(&install_packages.len().to_string()),
            format!("{:.1}", total_ms as f64 / 1000.0)
        ));
    }

    Ok(())
}

fn experimental_resolver_fetch_concurrency() -> usize {
    std::env::var(ENV_EXPERIMENTAL_RESOLVER_FETCH_CONCURRENCY)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| (1..=256).contains(value))
        .unwrap_or(DEFAULT_EXPERIMENTAL_RESOLVER_FETCH_CONCURRENCY)
}

fn experimental_resolver_metadata_concurrency() -> usize {
    std::env::var(ENV_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| (1..=256).contains(value))
        .unwrap_or(DEFAULT_EXPERIMENTAL_RESOLVER_METADATA_CONCURRENCY)
}

pub(in crate::commands::install) fn has_tarball_source_deps(
    project_dir: &Path,
    deps: &HashMap<String, String>,
) -> bool {
    deps.values()
        .any(|raw| match lpm_resolver::Specifier::parse(raw) {
            Ok(lpm_resolver::Specifier::Tarball { .. }) => true,
            Ok(lpm_resolver::Specifier::File { path }) => {
                std::fs::metadata(project_dir.join(path)).is_ok_and(|meta| meta.is_file())
            }
            _ => false,
        })
}

fn merge_pre_resolved_packages(
    packages: &mut Vec<InstallPackage>,
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
) {
    if !pre_resolved_install_pkgs.is_empty() {
        packages.extend(pre_resolved_install_pkgs.iter().cloned());
    }
    if !pre_resolved_source_deps.is_empty() {
        apply_post_resolve_directory_link_fixup(packages, pre_resolved_source_deps);
    }
    dedupe_install_packages_by_identity(packages);
}

fn populate_v2_local_source_objects(
    link_targets: &[LinkTarget],
    store_v2: &lpm_store::v2::Store,
) -> Result<(), LpmError> {
    for target in link_targets {
        if matches!(
            target.materialization,
            lpm_linker::Materialization::DirectorySource
        ) {
            let sri = local_source_sri_for_target(target);
            store_v2.populate_object_from_local_source(&target.store_path, &sri)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ExperimentalResolverGraphSource {
    ResolveWorklist,
    Lockfile,
    Invalid,
}

impl ExperimentalResolverGraphSource {
    fn from_env() -> Self {
        Self::from_value(
            std::env::var(ENV_EXPERIMENTAL_RESOLVER_GRAPH)
                .ok()
                .as_deref(),
        )
    }

    pub(super) fn from_value(value: Option<&str>) -> Self {
        match value {
            None => Self::ResolveWorklist,
            Some("resolve" | "resolve-worklist" | "live" | "live-resolve") => Self::ResolveWorklist,
            Some("lock" | "lockfile" | "seed-lock") => Self::Lockfile,
            Some(_) => Self::Invalid,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ResolveWorklist => "resolve-worklist",
            Self::Lockfile => "lockfile",
            Self::Invalid => "invalid",
        }
    }

    fn uses_lockfile(self) -> bool {
        matches!(self, Self::Lockfile)
    }
}

#[allow(clippy::too_many_arguments)]
async fn compute_parity_if_requested(
    client: Arc<RegistryClient>,
    deps: &HashMap<String, String>,
    override_set: OverrideSet,
    route_table: RouteTable,
    resolver_policy: lpm_resolver::ResolverPolicy,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    optional_registry_roots: &HashSet<String>,
    all_workspace_members: &[WorkspaceMemberLink],
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
    project_dir: &Path,
    candidate_packages: &[InstallPackage],
    json_output: bool,
    dependency_engine_policy: &crate::engine_check::DependencyEnginePolicy,
) -> Result<ExperimentalResolverParity, LpmError> {
    let mode = ExperimentalResolverParityMode::from_env();
    if !mode.enabled() {
        return Ok(ExperimentalResolverParity::disabled());
    }

    let mut baseline_packages = match mode {
        ExperimentalResolverParityMode::Disabled => unreachable!(),
        ExperimentalResolverParityMode::FreshResolve { .. } => {
            let shared_cache: lpm_resolver::SharedCache = Arc::new(dashmap::DashMap::new());
            seed_workspace_resolver_cache(&shared_cache, all_workspace_members)?;
            let npm_fanout = positive_usize_env_or_default(
                "LPM_NPM_FANOUT",
                default_fusion_npm_fanout(false, 0),
            );
            let root_dependencies = lpm_resolver::RootDependencies::with_optional_names(
                deps.clone(),
                optional_registry_roots.clone(),
            );
            let resolve_result =
                lpm_resolver::resolve_greedy_fused_with_cache_options_and_policy_roots(
                    Arc::clone(&client),
                    root_dependencies,
                    override_set,
                    route_table.clone(),
                    npm_fanout,
                    None,
                    shared_cache,
                    auto_install_peers,
                    include_optional_dependencies,
                    resolver_policy,
                )
                .await
                .map_err(crate::resolver_error::resolver_error_to_lpm)?;

            let mut packages = resolved_to_install_packages_with_workspace_members(
                &resolve_result.packages,
                deps,
                &resolve_result.root_aliases,
                &resolve_result.ambient_peer_installs,
                &resolve_result.cache,
                &route_table,
                client.as_ref(),
                all_workspace_members,
                project_dir,
            );
            let optional_dependency_names =
                optional_dependency_names_from_resolver_cache(&packages, &resolve_result.cache);
            normalize_install_package_optional_reachability(
                &mut packages,
                &optional_dependency_names,
            );
            merge_pre_resolved_packages(
                &mut packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            packages
        }
        ExperimentalResolverParityMode::Lockfile { .. } => {
            let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
            let gate_stats = GateStats::default();
            try_lockfile_fast_path(
                &lockfile_path,
                deps,
                catalog_resolutions,
                client.as_ref(),
                &gate_stats,
                true,
            )
            .map(|fast| fast.packages)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "experimental resolver lockfile parity requires a readable seed {} matching the current manifest",
                    lockfile_path.display()
                ))
            })?
        }
    };
    dedupe_install_packages_by_identity(&mut baseline_packages);
    filter_dependency_engine_packages(&mut baseline_packages, dependency_engine_policy)?;
    let _ = filter_platform_packages(&mut baseline_packages)?;

    let parity = compare_package_parity_with_baseline(
        candidate_packages,
        &baseline_packages,
        mode.baseline(),
    );
    if !parity.matches && !json_output {
        output::warn(&format!(
            "experimental resolver parity mismatch against {}: candidate={} baseline={} extra={} missing={} graph-mismatches={}",
            parity.baseline,
            parity.candidate_count,
            parity.baseline_count,
            parity.extra_count,
            parity.missing_count,
            parity.fingerprint_mismatch_count,
        ));
    }
    if !parity.matches && mode.deny() {
        return Err(LpmError::Registry(format!(
            "experimental resolver parity mismatch against {}: candidate={} baseline={} extra={} missing={} graph-mismatches={}",
            parity.baseline,
            parity.candidate_count,
            parity.baseline_count,
            parity.extra_count,
            parity.missing_count,
            parity.fingerprint_mismatch_count,
        )));
    }

    Ok(parity)
}

fn build_experimental_link_targets(
    project_dir: &Path,
    store: &PackageStore,
    packages: &[InstallPackage],
    patch_fingerprints: &HashMap<(String, String), String>,
) -> Result<Vec<LinkTarget>, LpmError> {
    let source_index = source_dependency_index(packages);
    packages
        .iter()
        .map(|package| -> Result<LinkTarget, LpmError> {
            Ok(LinkTarget {
                name: package.name.clone(),
                version: package.version.clone(),
                store_path: package.store_path_or_err(store, project_dir, None)?,
                dependencies: link_dependencies_for_package(package, &source_index)?,
                aliases: package.aliases.clone(),
                is_direct: package.is_direct,
                root_link_names: package.root_link_names.clone(),
                wrapper_id: package.wrapper_id_for_source(),
                materialization: package.materialization_for_source(),
                peers: package.peers.clone(),
                patch_fingerprint: patch_fingerprints
                    .get(&(package.name.clone(), package.version.clone()))
                    .cloned(),
            })
        })
        .collect::<Result<_, _>>()
}

#[allow(clippy::too_many_arguments)]
fn link_experimental_targets(
    project_dir: &Path,
    store_v2: Option<&lpm_store::v2::Store>,
    packages: &[InstallPackage],
    link_targets: &[LinkTarget],
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    self_package_name: Option<&str>,
    compatibility_bin_names: &[String],
) -> Result<LinkResult, LpmError> {
    if let Some(store_v2) = store_v2 {
        let v2_targets = build_v2_targets(packages, link_targets)?;
        return lpm_linker::v2::link_packages_v2_with_compatibility_bin_names(
            project_dir,
            v2_targets,
            store_v2,
            linker_mode,
            self_package_name,
            compatibility_bin_names,
        );
    }

    match linker_mode {
        lpm_linker::LinkerMode::Hoisted => {
            lpm_linker::link_packages_hoisted(project_dir, link_targets, force, self_package_name)
        }
        lpm_linker::LinkerMode::Isolated => {
            lpm_linker::link_packages(project_dir, link_targets, force, self_package_name)
        }
    }
}

async fn finish_v2_event_driven_link(
    project_dir: &Path,
    plan: &Arc<lpm_linker::v2::LinkPlanV2>,
    store_v2: &lpm_store::v2::Store,
    mut v2_link_handles: Vec<V2LinkHandle>,
    self_package_name: Option<&str>,
    timing_detail_mode: TimingDetailMode,
    slow_package_timings: &mut SlowPackageTimings,
) -> Result<LinkOutcomeWithTimings, LpmError> {
    let await_start = Instant::now();
    let mut materialized = Vec::with_capacity(v2_link_handles.len());
    let mut linked = 0usize;
    for handle in v2_link_handles.drain(..) {
        let task = handle.await.map_err(|e| {
            LpmError::Registry(format!("experimental v2 link task panicked: {e}"))
        })??;
        if timing_detail_mode.trace() {
            let package_display =
                format!("{}@{}", task.materialized.name, task.materialized.version);
            slow_package_timings.record_link_v2_one(&package_display, task.ms, task.timings);
        }
        if task.freshly_populated {
            linked += 1;
        }
        materialized.push(task.materialized);
    }
    let task_await_ms = await_start.elapsed().as_millis();
    let finalize_start = Instant::now();
    let finalize =
        lpm_linker::v2::link_v2_finalize(project_dir, plan, store_v2, self_package_name)?;
    let finalize_ms = finalize_start.elapsed().as_millis();
    Ok(LinkOutcomeWithTimings {
        result: LinkResult {
            linked,
            symlinked: finalize.symlinked,
            bin_linked: finalize.bin_count,
            skipped: plan.augmented_targets.len().saturating_sub(linked),
            self_referenced: finalize.self_referenced,
            materialized,
        },
        task_await_ms,
        finalize_ms,
    })
}
