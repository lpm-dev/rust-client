use super::*;
use lpm_task::graph::WorkspaceGraph;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::task::JoinSet;

const ENV_WORKSPACE_CONCURRENCY: &str = "LPM_WORKSPACE_CONCURRENCY";
const WORKSPACE_INSTALL_DEFAULT_CONCURRENCY: usize = 1;
const WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY: usize = 3;

pub(crate) struct RecursiveInstallOptions {
    pub(crate) json_output: bool,
    pub(crate) offline: bool,
    pub(crate) frozen_lockfile: FrozenLockfileMode,
    pub(crate) force: bool,
    pub(crate) allow_new: bool,
    pub(crate) strict_integrity: bool,
    pub(crate) no_engine_strict: bool,
    pub(crate) strict_peer_dependencies_override: Option<bool>,
    pub(crate) linker_override: Option<lpm_linker::LinkerMode>,
    pub(crate) lpm_skills_preference: crate::lpm_skills_config::LpmSkillsPreference,
    pub(crate) no_editor_setup: bool,
    pub(crate) no_security_summary: bool,
    pub(crate) auto_build: bool,
    pub(crate) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(crate) advisor_override: Option<String>,
    pub(crate) min_release_age_override: Option<u64>,
    pub(crate) min_release_age_exclude: Vec<String>,
    pub(crate) drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    pub(crate) verify_policy: crate::provenance_fetch::VerifyPolicy,
    pub(crate) omit_policy: InstallOmitPolicy,
    pub(crate) strict_sandbox: bool,
    pub(crate) no_sandbox: bool,
    pub(crate) verbose: bool,
    pub(crate) audit_after_install: bool,
    pub(crate) timing: bool,
    pub(crate) workspace_concurrency: Option<NonZeroUsize>,
}

struct WorkspaceInstallTarget {
    name: String,
    path: PathBuf,
    kind: &'static str,
    lifecycle: crate::commands::root_lifecycle::RootProjectLifecycle,
    resolve_ahead_eligible: bool,
    // Indices of targets that must complete before this one starts:
    // workspace dependency edges, the sequential chain between
    // script-bearing targets, and (for the root) every member.
    schedule_after: Vec<usize>,
}

struct WorkspaceInstallOutcome {
    name: String,
    path: PathBuf,
    kind: &'static str,
    duration_ms: u64,
    report: Option<serde_json::Value>,
}

struct TargetTaskResult {
    report: Option<serde_json::Value>,
    // Present when the target ran a `pnpm:devPreinstall` script and
    // reloaded its manifest: later-scheduled targets build on this view.
    refreshed_workspace: Option<Arc<lpm_workspace::Workspace>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_recursive_workspace_install(
    client: &RegistryClient,
    cwd: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    fail_if_no_match: bool,
    options: RecursiveInstallOptions,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(cwd)
        .map_err(|error| LpmError::Script(format!("workspace discovery failed: {error}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "`--recursive` requires a workspace. Run `lpm install` without `--recursive` \
                 for a standalone project."
                    .into(),
            )
        })?;
    let mut targets = select_workspace_install_targets(
        &workspace,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
    )?;

    if targets.is_empty() {
        if fail_if_no_match {
            return Err(LpmError::Script(
                "no workspace packages matched the filter (--fail-if-no-match)".into(),
            ));
        }
        emit_workspace_install_report(&workspace.root, &[], options.json_output, 0);
        return Ok(());
    }

    let targets_need_materialization = workspace_targets_need_materialization(&targets);
    let lockfile_replay_ready = targets_need_materialization
        && workspace_targets_are_lockfile_replay_ready(&workspace, &targets, &options);
    let share_local_source_populations =
        targets.iter().all(|target| !target.lifecycle.has_scripts());
    let automatic_parallel_replay =
        explicit_workspace_install_concurrency(options.workspace_concurrency).is_none()
            && lockfile_replay_ready;
    let resolve_ahead = targets_need_materialization
        && !lockfile_replay_ready
        && !options.offline
        && !options.force
        && explicit_workspace_install_concurrency(options.workspace_concurrency).is_none()
        && targets.len() > 1
        && targets
            .iter()
            .all(|target| !target.lifecycle.has_scripts() && target.resolve_ahead_eligible);
    let concurrency = resolve_workspace_install_concurrency(
        options.workspace_concurrency,
        targets.len(),
        automatic_parallel_replay,
    );
    let resolution_concurrency = automatic_workspace_resolution_concurrency(
        targets.len(),
        std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(WORKSPACE_INSTALL_DEFAULT_CONCURRENCY),
    );
    tracing::debug!(
        concurrency,
        resolution_concurrency,
        resolve_ahead,
        lockfile_replay_ready,
        share_local_source_populations,
        automatic_parallel_replay,
        "selected recursive workspace install concurrency"
    );
    let materialization_coordinator = targets_need_materialization.then(|| {
        Arc::new(
            workspace_materialization::WorkspaceMaterializationCoordinator::new(
                lockfile_replay_ready,
                share_local_source_populations,
            ),
        )
    });
    let resolution_coordinator = resolve_ahead.then(|| {
        Arc::new(workspace_resolution::WorkspaceResolutionCoordinator::new(
            targets.len(),
            resolution_concurrency,
        ))
    });
    let workspace_client = resolution_coordinator
        .as_ref()
        .map(|_| client.clone_with_metadata_memory_cache());
    let client = workspace_client.as_ref().unwrap_or(client);
    let workspace_root = workspace.root.clone();
    let workspace_lock = lpm_common::project_install_lock(&workspace_root);
    let started = Instant::now();
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let options = Arc::new(options);
    // The install pipeline future is !Send (the fused resolver keeps
    // single-threaded caches), so concurrent targets run on a LocalSet.
    // Downloads, extraction, and link tasks are spawned onto the
    // multi-thread pool from inside each pipeline, so the heavy work
    // still fans out across cores; only per-target orchestration and
    // resolver CPU share this thread.
    let local_tasks = tokio::task::LocalSet::new();
    let scheduler = local_tasks.run_until(async {
        let mut active_workspace = Arc::new(workspace);
        let target_count = targets.len();
        let scheduling_order =
            workspace_target_scheduling_order(&targets, resolution_coordinator.is_some());
        let mut plans: Vec<Option<WorkspaceInstallTarget>> = targets.drain(..).map(Some).collect();
        let mut done = vec![false; target_count];
        let mut started_at = vec![None::<Instant>; target_count];
        let mut outcomes: Vec<Option<WorkspaceInstallOutcome>> =
            (0..target_count).map(|_| None).collect();
        let mut in_flight: JoinSet<(usize, Result<TargetTaskResult, LpmError>)> = JoinSet::new();
        let mut first_error: Option<LpmError> = None;

        loop {
            if first_error.is_none() {
                for &index in &scheduling_order {
                    let scheduler_limit = if resolution_coordinator.is_some() {
                        target_count
                    } else {
                        concurrency
                    };
                    if in_flight.len() >= scheduler_limit {
                        break;
                    }
                    let ready = plans[index].as_ref().is_some_and(|plan| {
                        resolution_coordinator.is_some()
                            || plan.schedule_after.iter().all(|dep| done[*dep])
                    });
                    if !ready {
                        continue;
                    }
                    let plan = plans[index].take().expect("ready target plan present");
                    started_at[index] = Some(Instant::now());
                    spawn_workspace_target_install(
                        &mut in_flight,
                        index,
                        plan,
                        client,
                        &lpm_root,
                        Arc::clone(&active_workspace),
                        Arc::clone(&options),
                        materialization_coordinator.as_ref().map(Arc::clone),
                        resolution_coordinator.as_ref().map(Arc::clone),
                        &mut outcomes,
                    );
                }
            }

            let Some(joined) = in_flight.join_next().await else {
                break;
            };
            match joined {
                Ok((index, Ok(result))) => {
                    done[index] = true;
                    if let Some(refreshed) = result.refreshed_workspace {
                        active_workspace = refreshed;
                    }
                    let outcome = outcomes[index]
                        .as_mut()
                        .expect("outcome slot initialized at spawn");
                    outcome.duration_ms = started_at[index]
                        .map(|start| duration_ms(start.elapsed()))
                        .unwrap_or_default();
                    outcome.report = result.report;
                }
                Ok((index, Err(error))) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    outcomes[index] = None;
                    if resolution_coordinator.is_some() {
                        in_flight.abort_all();
                    }
                }
                Err(join_error) => {
                    if first_error.is_none() && !join_error.is_cancelled() {
                        first_error = Some(LpmError::Script(format!(
                            "workspace install worker failed: {join_error}"
                        )));
                    }
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(outcomes.into_iter().flatten().collect::<Vec<_>>()),
        }
    });
    let outcomes = lpm_common::with_exclusive_lock_async(workspace_lock, scheduler).await?;

    emit_workspace_install_report(
        &workspace_root,
        &outcomes,
        options.json_output,
        duration_ms(started.elapsed()),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_workspace_target_install(
    in_flight: &mut JoinSet<(usize, Result<TargetTaskResult, LpmError>)>,
    index: usize,
    plan: WorkspaceInstallTarget,
    client: &RegistryClient,
    lpm_root: &lpm_common::LpmRoot,
    base_workspace: Arc<lpm_workspace::Workspace>,
    options: Arc<RecursiveInstallOptions>,
    materialization_coordinator: Option<
        Arc<workspace_materialization::WorkspaceMaterializationCoordinator>,
    >,
    resolution_coordinator: Option<Arc<workspace_resolution::WorkspaceResolutionCoordinator>>,
    outcomes: &mut [Option<WorkspaceInstallOutcome>],
) {
    outcomes[index] = Some(WorkspaceInstallOutcome {
        name: plan.name.clone(),
        path: plan.path.clone(),
        kind: plan.kind,
        duration_ms: 0,
        report: None,
    });
    let client = client.clone_with_config();
    let lpm_root = lpm_root.clone();
    in_flight.spawn_local(async move {
        let install = run_workspace_target_install(plan, client, lpm_root, base_workspace, options);
        let install = async {
            match materialization_coordinator {
                Some(coordinator) => workspace_materialization::scope(coordinator, install).await,
                None => install.await,
            }
        };
        let result = match resolution_coordinator {
            Some(coordinator) => workspace_resolution::scope(coordinator, index, install).await,
            None => install.await,
        };
        (index, result)
    });
}

async fn run_workspace_target_install(
    plan: WorkspaceInstallTarget,
    client: RegistryClient,
    lpm_root: lpm_common::LpmRoot,
    base_workspace: Arc<lpm_workspace::Workspace>,
    options: Arc<RecursiveInstallOptions>,
) -> Result<TargetTaskResult, LpmError> {
    plan.lifecycle
        .run_dev_preinstall(&plan.path, options.json_output)?;

    // `pnpm:devPreinstall` may edit the target manifest, and the root
    // install must see current root configuration; both re-read from
    // disk into a private workspace view. Scriptless members reuse the
    // shared view — their manifests cannot have changed since discovery.
    let needs_refresh = plan.lifecycle.has_dev_preinstall() || plan.kind == "root";
    let scoped_workspace = if needs_refresh {
        let mut refreshed = (*base_workspace).clone();
        crate::workspace_discovery_cache::refresh_target(&mut refreshed, &plan.path).map_err(
            |error| {
                LpmError::Script(format!(
                    "failed to refresh workspace package {}: {error}",
                    plan.path.display()
                ))
            },
        )?;
        Arc::new(refreshed)
    } else {
        base_workspace
    };

    let capture = options.json_output.then(report_capture::new_capture);
    let install = run_with_options_with_lpm_root(
        &client,
        &plan.path,
        options.json_output,
        options.offline,
        options.frozen_lockfile,
        options.force,
        options.allow_new,
        options.strict_integrity,
        options.no_engine_strict,
        options.strict_peer_dependencies_override,
        options.linker_override,
        options.lpm_skills_preference,
        options.no_editor_setup,
        options.no_security_summary,
        options.auto_build,
        None,
        None,
        None,
        options.script_policy_override,
        options.advisor_override.clone(),
        options.min_release_age_override,
        &options.min_release_age_exclude,
        options.drift_ignore_policy.clone(),
        options.verify_policy.clone(),
        options.omit_policy,
        options.strict_sandbox,
        options.no_sandbox,
        options.verbose,
        options.audit_after_install,
        options.timing,
        &[],
        options.json_output,
        false,
        lpm_root,
    );
    match &capture {
        Some(capture) => {
            crate::workspace_discovery_cache::scope(
                Arc::clone(&scoped_workspace),
                report_capture::scope(Arc::clone(capture), install),
            )
            .await?;
        }
        None => {
            crate::workspace_discovery_cache::scope(Arc::clone(&scoped_workspace), install).await?;
        }
    }

    plan.lifecycle
        .run_after_successful_install(&plan.path, options.json_output)?;

    Ok(TargetTaskResult {
        report: capture.as_ref().and_then(report_capture::take),
        refreshed_workspace: plan
            .lifecycle
            .has_dev_preinstall()
            .then_some(scoped_workspace),
    })
}

fn resolve_workspace_install_concurrency(
    cli_override: Option<NonZeroUsize>,
    target_count: usize,
    lockfile_replay_ready: bool,
) -> usize {
    let configured = explicit_workspace_install_concurrency(cli_override);
    let limit = configured.unwrap_or_else(|| {
        let available_parallelism = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(WORKSPACE_INSTALL_DEFAULT_CONCURRENCY);
        automatic_workspace_install_concurrency(
            target_count,
            lockfile_replay_ready,
            available_parallelism,
        )
    });
    limit.min(target_count.max(1))
}

fn explicit_workspace_install_concurrency(cli_override: Option<NonZeroUsize>) -> Option<usize> {
    cli_override.map(NonZeroUsize::get).or_else(|| {
        std::env::var(ENV_WORKSPACE_CONCURRENCY)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
    })
}

fn automatic_workspace_install_concurrency(
    target_count: usize,
    lockfile_replay_ready: bool,
    available_parallelism: usize,
) -> usize {
    if !lockfile_replay_ready {
        return WORKSPACE_INSTALL_DEFAULT_CONCURRENCY;
    }
    available_parallelism
        .clamp(1, WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY)
        .min(target_count.max(1))
}

fn automatic_workspace_resolution_concurrency(
    target_count: usize,
    available_parallelism: usize,
) -> usize {
    available_parallelism
        .clamp(1, WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY)
        .min(target_count.max(1))
}

fn workspace_target_scheduling_order(
    targets: &[WorkspaceInstallTarget],
    resolve_ahead: bool,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..targets.len()).collect();
    if resolve_ahead
        && let Some(root_position) = targets.iter().position(|target| target.kind == "root")
    {
        let root_index = order.remove(root_position);
        order.insert(0, root_index);
    }
    order
}

fn dependency_specifier_allows_resolution_ahead(raw: &str) -> bool {
    matches!(
        lpm_resolver::Specifier::parse(raw),
        Ok(lpm_resolver::Specifier::SemverRange(_)
            | lpm_resolver::Specifier::NpmAlias { .. }
            | lpm_resolver::Specifier::Workspace(_))
    )
}

fn package_allows_resolution_ahead(package: &lpm_workspace::PackageJson) -> bool {
    package
        .dependencies
        .values()
        .chain(package.dev_dependencies.values())
        .chain(package.optional_dependencies.values())
        .chain(package.peer_dependencies.values())
        .all(|specifier| dependency_specifier_allows_resolution_ahead(specifier))
}

fn workspace_targets_need_materialization(targets: &[WorkspaceInstallTarget]) -> bool {
    targets
        .iter()
        .any(|target| !target.path.join("node_modules").is_dir())
}

fn workspace_targets_are_lockfile_replay_ready(
    workspace: &lpm_workspace::Workspace,
    targets: &[WorkspaceInstallTarget],
    options: &RecursiveInstallOptions,
) -> bool {
    if options.force
        || options.offline
        || targets
            .iter()
            .any(|target| target.lifecycle.has_dev_preinstall())
    {
        return false;
    }

    let Ok(global_config) = crate::commands::config::GlobalConfig::load_checked() else {
        return false;
    };
    let global_auto_install_peers = global_config.get_bool("auto-install-peers");

    let mut packages_by_path = HashMap::with_capacity(workspace.members.len() + 1);
    packages_by_path.insert(workspace.root.as_path(), &workspace.root_package);
    for member in &workspace.members {
        packages_by_path.insert(member.path.as_path(), &member.package);
    }

    targets.iter().all(|target| {
        let Some(package) = packages_by_path.get(target.path.as_path()).copied() else {
            return false;
        };
        target_lockfile_is_replay_ready(workspace, &target.path, package, global_auto_install_peers)
    })
}

fn target_lockfile_is_replay_ready(
    workspace: &lpm_workspace::Workspace,
    project_dir: &Path,
    package: &lpm_workspace::PackageJson,
    global_auto_install_peers: Option<bool>,
) -> bool {
    if package
        .lpm
        .as_ref()
        .is_some_and(|lpm| !lpm.patched_dependencies.is_empty())
    {
        return false;
    }

    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let Ok(lockfile) = lpm_lockfile::Lockfile::read_fast(&lockfile_path) else {
        return false;
    };
    let auto_install_peers = package
        .lpm
        .as_ref()
        .and_then(|lpm| lpm.auto_install_peers)
        .or(global_auto_install_peers)
        .unwrap_or(true);
    if lockfile_needs_peer_state_repair(&lockfile, auto_install_peers)
        || lockfile_needs_dependency_engine_repair(&lockfile)
    {
        return false;
    }

    let mut deps = manifest_install_deps(package);
    if normalize_jsr_manifest_deps(&mut deps).is_err()
        || deps
            .values()
            .any(|specifier| specifier.starts_with("file:") || specifier.starts_with("link:"))
        || extract_workspace_protocol_deps(&mut deps, workspace).is_err()
    {
        return false;
    }
    let catalogs = &workspace.root_package.catalogs;
    let Ok(mut catalog_resolutions) = lpm_workspace::resolve_catalog_protocol(&mut deps, catalogs)
    else {
        return false;
    };
    let Ok(overrides) = prepare_override_resolution_state(OverrideResolutionInput {
        package,
        workspace: Some(workspace),
        catalog_resolutions: &mut catalog_resolutions,
    }) else {
        return false;
    };
    let current_importer = validation::importer_snapshot_for_current_manifest(
        package,
        &overrides.lpm_overrides,
        overrides.overrides.as_ref(),
        overrides.resolutions.as_ref(),
        overrides.override_catalogs,
        None,
        auto_install_peers,
    );
    if lockfile.importers.get(".") != Some(&current_importer) {
        return false;
    }

    lockfile_satisfies_fast_path(&lockfile, &deps, &catalog_resolutions, false, false)
}

fn select_workspace_install_targets(
    workspace: &lpm_workspace::Workspace,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
) -> Result<Vec<WorkspaceInstallTarget>, LpmError> {
    let graph = WorkspaceGraph::from_workspace(workspace);
    let filtered = !filters.is_empty() || !filter_prod.is_empty();
    let mut selected = HashSet::new();

    if filters.is_empty() && filter_prod.is_empty() {
        selected.extend(0..graph.len());
    } else {
        let selected_with_all_edges = if filters.is_empty() {
            HashSet::new()
        } else {
            crate::workspace_select::select_workspace_target_set(
                &graph,
                &workspace.root,
                filters,
                &[],
                changed_files_ignore_pattern,
                test_pattern,
                false,
                "main",
            )?
        };
        let dependencies: HashSet<usize> = selected_with_all_edges
            .iter()
            .flat_map(|&id| graph.transitive_dependencies(id))
            .collect();
        selected.extend(selected_with_all_edges);
        selected.extend(dependencies);

        let selected_with_prod_edges = if filter_prod.is_empty() {
            HashSet::new()
        } else {
            crate::workspace_select::select_workspace_target_set(
                &graph,
                &workspace.root,
                &[],
                filter_prod,
                changed_files_ignore_pattern,
                test_pattern,
                false,
                "main",
            )?
        };
        let production_dependencies: HashSet<usize> = selected_with_prod_edges
            .iter()
            .flat_map(|&id| graph.transitive_prod_dependencies(id))
            .collect();
        selected.extend(selected_with_prod_edges);
        selected.extend(production_dependencies);
    }

    let (ordered_ids, workspace_edges_usable) = match graph.topological_sort() {
        Ok(ids) => (ids, true),
        Err(error) => {
            tracing::warn!(
                "workspace dependency graph is cyclic; using deterministic path order: {error}"
            );
            let mut ids: Vec<_> = (0..graph.len()).collect();
            ids.sort_unstable_by(|left, right| {
                workspace.members[*left]
                    .path
                    .cmp(&workspace.members[*right].path)
            });
            (ids, false)
        }
    };

    let root_capacity = usize::from(!filtered);
    let mut targets = Vec::with_capacity(selected.len() + root_capacity);
    let mut target_index_by_graph_id = vec![None::<usize>; graph.len()];
    for id in ordered_ids {
        if !selected.contains(&id) {
            continue;
        }
        let member = &workspace.members[id];
        target_index_by_graph_id[id] = Some(targets.len());
        targets.push(WorkspaceInstallTarget {
            name: member
                .package
                .name
                .clone()
                .unwrap_or_else(|| graph.members[id].name.clone()),
            path: member.path.clone(),
            kind: "member",
            lifecycle: crate::commands::root_lifecycle::RootProjectLifecycle::from_package(
                &member.package,
            ),
            resolve_ahead_eligible: package_allows_resolution_ahead(&member.package),
            schedule_after: if workspace_edges_usable {
                graph.edges[id]
                    .iter()
                    .filter_map(|dep| target_index_by_graph_id.get(*dep).copied().flatten())
                    .collect()
            } else {
                // Cyclic workspace graph: chain every target so
                // execution stays sequential in the deterministic
                // path order instead of deadlocking on cyclic edges.
                targets.len().checked_sub(1).into_iter().collect()
            },
        });
    }

    // Script-bearing targets stay sequential relative to each other so
    // their lifecycle scripts observe the same deterministic order the
    // one-at-a-time orchestration guaranteed.
    let mut last_script_target = None::<usize>;
    for (index, target) in targets.iter_mut().enumerate() {
        if !target.lifecycle.has_scripts() {
            continue;
        }
        if let Some(previous) = last_script_target
            && !target.schedule_after.contains(&previous)
        {
            target.schedule_after.push(previous);
        }
        last_script_target = Some(index);
    }

    if !filtered {
        let schedule_after = (0..targets.len()).collect();
        targets.push(WorkspaceInstallTarget {
            name: workspace
                .root_package
                .name
                .clone()
                .unwrap_or_else(|| "(workspace root)".into()),
            path: workspace.root.clone(),
            kind: "root",
            lifecycle: crate::commands::root_lifecycle::RootProjectLifecycle::from_package(
                &workspace.root_package,
            ),
            resolve_ahead_eligible: package_allows_resolution_ahead(&workspace.root_package),
            schedule_after,
        });
    }

    Ok(targets)
}

const TARGET_REPORT_FIELDS: &[&str] = &[
    "up_to_date",
    "no_dependencies",
    "count",
    "downloaded",
    "cached",
    "linked",
    "symlinked",
    "used_lockfile",
    "timing",
    "security",
    "audit_summary",
];

fn emit_workspace_install_report(
    workspace_root: &Path,
    outcomes: &[WorkspaceInstallOutcome],
    json_output: bool,
    duration_ms: u64,
) {
    if json_output {
        let targets: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|outcome| {
                let mut target = serde_json::json!({
                    "name": outcome.name,
                    "path": outcome.path.display().to_string(),
                    "kind": outcome.kind,
                    "status": "success",
                    "duration_ms": outcome.duration_ms,
                });
                if let Some(report) = &outcome.report {
                    for field in TARGET_REPORT_FIELDS {
                        if let Some(value) = report.get(field) {
                            target[*field] = value.clone();
                        }
                    }
                }
                target
            })
            .collect();
        let mut report = serde_json::json!({
            "schema_version": crate::json_contract::INSTALL_JSON_SCHEMA_VERSION,
            "success": true,
            "recursive": true,
            "workspace_root": workspace_root.display().to_string(),
            "duration_ms": duration_ms,
            "targets": targets,
            "summary": {
                "total": outcomes.len(),
                "succeeded": outcomes.len(),
                "failed": 0,
            },
        });
        attach_aggregate_telemetry(&mut report, duration_ms);
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        output::success(&format!(
            "Installed {} workspace package{} in {duration_ms}ms",
            outcomes.len(),
            if outcomes.len() == 1 { "" } else { "s" },
        ));
    }
}

/// Roll per-target counters and phase timings up to the envelope root
/// so consumers keep the single-project field surface. Phase sums are
/// attribution across targets — under concurrent execution they can
/// exceed the wall-clock `total_ms`.
fn attach_aggregate_telemetry(report: &mut serde_json::Value, wall_ms: u64) {
    let Some(targets) = report.get("targets").and_then(serde_json::Value::as_array) else {
        return;
    };

    let sum = |field: &str| -> Option<u64> {
        let mut total = 0u64;
        let mut present = false;
        for target in targets {
            if let Some(value) = target.get(field).and_then(serde_json::Value::as_u64) {
                total = total.saturating_add(value);
                present = true;
            }
        }
        present.then_some(total)
    };
    let counters: Vec<(&str, Option<u64>)> = vec![
        ("count", sum("count")),
        ("downloaded", sum("downloaded")),
        ("cached", sum("cached")),
        ("linked", sum("linked")),
    ];

    let all_up_to_date = !targets.is_empty()
        && targets.iter().all(|target| {
            target
                .get("up_to_date")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        });

    let timing_sum = |field: &str| -> u64 {
        targets
            .iter()
            .filter_map(|target| {
                target
                    .get("timing")
                    .and_then(|timing| timing.get(field))
                    .and_then(serde_json::Value::as_u64)
            })
            .fold(0u64, u64::saturating_add)
    };
    let any_timing = targets.iter().any(|target| target.get("timing").is_some());
    let resolve_ms = timing_sum("resolve_ms");
    let fetch_ms = timing_sum("fetch_ms");
    let link_ms = timing_sum("link_ms");

    for (field, value) in counters {
        if let Some(value) = value {
            report[field] = serde_json::json!(value);
        }
    }
    if all_up_to_date {
        report["up_to_date"] = serde_json::json!(true);
    }
    if any_timing {
        report["timing"] = serde_json::json!({
            "resolve_ms": resolve_ms,
            "fetch_ms": fetch_ms,
            "link_ms": link_ms,
            "total_ms": wall_ms,
        });
    }
}

fn duration_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_workspace_install_defaults_to_sequential_execution() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            None::<std::ffi::OsString>,
        )]);

        assert_eq!(resolve_workspace_install_concurrency(None, 4, false), 1);
    }

    #[test]
    fn recursive_workspace_install_parallelizes_proven_lockfile_replays() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            None::<std::ffi::OsString>,
        )]);

        assert_eq!(automatic_workspace_install_concurrency(8, true, 8), 3);
    }

    #[test]
    fn recursive_workspace_install_bounds_fresh_resolution_parallelism() {
        assert_eq!(automatic_workspace_resolution_concurrency(8, 8), 3);
        assert_eq!(automatic_workspace_resolution_concurrency(2, 8), 2);
        assert_eq!(automatic_workspace_resolution_concurrency(8, 1), 1);
    }

    #[test]
    fn recursive_workspace_install_starts_root_resolution_first_without_reordering_commits() {
        let package = replay_ready_package();
        let member_a = workspace_target("member-a", "member", &package);
        let member_b = workspace_target("member-b", "member", &package);
        let root = workspace_target("root", "root", &package);

        assert_eq!(
            workspace_target_scheduling_order(&[member_a, member_b, root], true),
            vec![2, 0, 1],
        );
    }

    #[test]
    fn recursive_workspace_resolution_accepts_registry_alias_and_workspace_specifiers() {
        for specifier in [
            "^1.2.3",
            "latest",
            "npm:lodash@^4.17.0",
            "jsr:@std/path@^1.0.0",
            "workspace:*",
        ] {
            assert!(
                dependency_specifier_allows_resolution_ahead(specifier),
                "{specifier} should be eligible for resolve-ahead"
            );
        }
    }

    #[test]
    fn recursive_workspace_resolution_rejects_source_and_malformed_specifiers() {
        for specifier in [
            "file:../local-package",
            "link:../local-package",
            "git+https://github.com/example/package.git",
            "github:example/package",
            "https://example.com/package.tgz",
            "unsupported:package",
        ] {
            assert!(
                !dependency_specifier_allows_resolution_ahead(specifier),
                "{specifier} must stay on the dependency-ordered path"
            );
        }
    }

    #[test]
    fn recursive_workspace_install_caps_automatic_parallelism_by_target_count() {
        assert_eq!(automatic_workspace_install_concurrency(2, true, 8), 2);
    }

    #[test]
    fn recursive_workspace_install_keeps_automatic_parallelism_within_available_cpus() {
        assert_eq!(automatic_workspace_install_concurrency(8, true, 2), 2);
    }

    #[test]
    fn recursive_workspace_install_cli_concurrency_overrides_automatic_policy() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            Some(std::ffi::OsString::from("2")),
        )]);

        assert_eq!(
            resolve_workspace_install_concurrency(NonZeroUsize::new(3), 8, false),
            3,
        );
    }

    #[test]
    fn recursive_workspace_install_env_concurrency_overrides_automatic_policy() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            Some(std::ffi::OsString::from("3")),
        )]);

        assert_eq!(resolve_workspace_install_concurrency(None, 8, false), 3);
    }

    #[test]
    fn recursive_workspace_install_rejects_missing_lockfile_for_automatic_parallelism() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        let package = replay_ready_package();
        let workspace = replay_ready_workspace(directory.path(), package.clone());

        assert!(!target_lockfile_is_replay_ready(
            &workspace,
            directory.path(),
            &package,
            None,
        ));
    }

    #[test]
    fn recursive_workspace_install_rejects_malformed_lockfile_for_automatic_parallelism() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        let package = replay_ready_package();
        let workspace = replay_ready_workspace(directory.path(), package.clone());
        std::fs::write(
            directory.path().join(lpm_lockfile::LOCKFILE_NAME),
            "not a lockfile\n",
        )
        .expect("write malformed lockfile");

        assert!(!target_lockfile_is_replay_ready(
            &workspace,
            directory.path(),
            &package,
            None,
        ));
    }

    #[test]
    fn recursive_workspace_install_rejects_stale_importer_for_automatic_parallelism() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        let package = replay_ready_package();
        let workspace = replay_ready_workspace(directory.path(), package.clone());
        write_replay_ready_lockfile(directory.path(), &package, "^4.16.0");

        assert!(!target_lockfile_is_replay_ready(
            &workspace,
            directory.path(),
            &package,
            None,
        ));
    }

    #[test]
    fn recursive_workspace_install_accepts_current_lockfile_for_automatic_parallelism() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        let package = replay_ready_package();
        let workspace = replay_ready_workspace(directory.path(), package.clone());
        write_replay_ready_lockfile(directory.path(), &package, "^4.17.0");

        assert!(target_lockfile_is_replay_ready(
            &workspace,
            directory.path(),
            &package,
            None,
        ));
    }

    #[test]
    fn recursive_workspace_install_skips_lockfile_preflight_when_targets_are_materialized() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        std::fs::create_dir(directory.path().join("node_modules"))
            .expect("create materialized node_modules");
        let package = replay_ready_package();
        let targets = vec![replay_ready_target(directory.path(), &package)];

        assert!(!workspace_targets_need_materialization(&targets));
    }

    #[test]
    fn recursive_workspace_install_checks_lockfiles_when_a_target_needs_materialization() {
        let directory = tempfile::tempdir().expect("create workspace temp directory");
        let package = replay_ready_package();
        let targets = vec![replay_ready_target(directory.path(), &package)];

        assert!(workspace_targets_need_materialization(&targets));
    }

    fn replay_ready_target(
        path: &Path,
        package: &lpm_workspace::PackageJson,
    ) -> WorkspaceInstallTarget {
        WorkspaceInstallTarget {
            name: "replay-ready".to_string(),
            path: path.to_path_buf(),
            kind: "root",
            lifecycle: crate::commands::root_lifecycle::RootProjectLifecycle::from_package(package),
            resolve_ahead_eligible: package_allows_resolution_ahead(package),
            schedule_after: Vec::new(),
        }
    }

    fn workspace_target(
        path: &str,
        kind: &'static str,
        package: &lpm_workspace::PackageJson,
    ) -> WorkspaceInstallTarget {
        WorkspaceInstallTarget {
            name: path.to_string(),
            path: PathBuf::from(path),
            kind,
            lifecycle: crate::commands::root_lifecycle::RootProjectLifecycle::from_package(package),
            resolve_ahead_eligible: package_allows_resolution_ahead(package),
            schedule_after: Vec::new(),
        }
    }

    fn replay_ready_package() -> lpm_workspace::PackageJson {
        let mut package = lpm_workspace::PackageJson {
            name: Some("replay-ready".to_string()),
            version: Some("1.0.0".to_string()),
            ..lpm_workspace::PackageJson::default()
        };
        package
            .dependencies
            .insert("lodash".to_string(), "^4.17.0".to_string());
        package
    }

    fn replay_ready_workspace(
        root: &Path,
        package: lpm_workspace::PackageJson,
    ) -> lpm_workspace::Workspace {
        lpm_workspace::Workspace {
            root: root.to_path_buf(),
            root_package: package,
            members: Vec::new(),
        }
    }

    fn write_replay_ready_lockfile(
        project_dir: &Path,
        package: &lpm_workspace::PackageJson,
        importer_spec: &str,
    ) {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        let mut importer = validation::importer_snapshot_for_current_manifest(
            package,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            None,
            true,
        );
        importer
            .dependencies
            .insert("lodash".to_string(), importer_spec.to_string());
        lockfile.importers.insert(".".to_string(), importer);
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: Vec::new(),
            alias_dependencies: Vec::new(),
            peers: Vec::new(),
            tarball: None,
        });
        lockfile
            .write_to_file(&project_dir.join(lpm_lockfile::LOCKFILE_NAME))
            .expect("write replay-ready lockfile");
    }
}
