use super::*;
use lpm_task::graph::WorkspaceGraph;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::task::JoinSet;

const ENV_WORKSPACE_CONCURRENCY: &str = "LPM_WORKSPACE_CONCURRENCY";
const WORKSPACE_INSTALL_DEFAULT_CONCURRENCY: usize = 1;
const WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY: usize = 3;
const WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY: usize = 6;
const WORKSPACE_INSTALL_FRESH_WORK_UNITS_PER_LANE: usize = 256;

#[derive(Clone, Copy)]
struct AutomaticWorkspaceInstallPolicy {
    target_count: usize,
    dependency_count: usize,
    targets_need_materialization: bool,
    lockfile_replay_ready: bool,
    offline: bool,
    force: bool,
    explicit_concurrency: bool,
    share_local_source_populations: bool,
    root_resolve_ahead_eligible: bool,
}

impl AutomaticWorkspaceInstallPolicy {
    fn parallel_replay(self) -> bool {
        self.targets_need_materialization
            && !self.explicit_concurrency
            && self.lockfile_replay_ready
    }

    fn parallel_fresh(self) -> bool {
        self.fresh_concurrency() > WORKSPACE_INSTALL_DEFAULT_CONCURRENCY
    }

    fn fresh_concurrency(self) -> usize {
        let eligible = self.targets_need_materialization
            && !self.lockfile_replay_ready
            && !self.offline
            && !self.force
            && !self.explicit_concurrency
            && self.share_local_source_populations
            && self.root_resolve_ahead_eligible;
        if !eligible {
            return WORKSPACE_INSTALL_DEFAULT_CONCURRENCY;
        }

        self.target_count
            .saturating_add(self.dependency_count)
            .div_ceil(WORKSPACE_INSTALL_FRESH_WORK_UNITS_PER_LANE)
            .clamp(
                WORKSPACE_INSTALL_DEFAULT_CONCURRENCY,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            )
            .min(self.target_count.max(1))
    }
}

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
    dependency_count: usize,
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
    let timing_detail_mode = TimingDetailMode::from_env();
    let _registry_timing_scope = if options.timing {
        Some(lpm_registry::timing::command_scope().await)
    } else {
        None
    };
    let _resolver_profile_scope = if options.timing {
        Some(lpm_resolver::profile::command_scope().await)
    } else {
        None
    };

    if targets.is_empty() {
        if fail_if_no_match {
            return Err(LpmError::Script(
                "no workspace packages matched the filter (--fail-if-no-match)".into(),
            ));
        }
        emit_workspace_install_report(
            &workspace.root,
            &[],
            options.json_output,
            options.timing,
            timing_detail_mode,
            0,
        );
        return Ok(());
    }

    let root_target_index = targets.iter().position(|target| target.kind == "root");
    let root_provider_fingerprint = root_target_index
        .and_then(|_| {
            workspace_resolution::root_provider_fingerprint_from_lockfile(&workspace.root)
        })
        .map(Arc::<str>::from);
    let targets_need_materialization = workspace_targets_need_materialization(&targets);
    let lockfile_replay_ready = workspace_targets_are_lockfile_replay_ready(
        &workspace,
        &targets,
        &options,
        root_provider_fingerprint.as_deref(),
    );
    let share_local_source_populations = workspace_allows_shared_local_source_populations(&targets);
    let explicit_concurrency =
        explicit_workspace_install_concurrency(options.workspace_concurrency).is_some();
    let automatic_policy = AutomaticWorkspaceInstallPolicy {
        target_count: targets.len(),
        dependency_count: targets.iter().fold(0usize, |total, target| {
            total.saturating_add(target.dependency_count)
        }),
        targets_need_materialization,
        lockfile_replay_ready,
        offline: options.offline,
        force: options.force,
        explicit_concurrency,
        share_local_source_populations,
        root_resolve_ahead_eligible: root_target_index
            .is_some_and(|index| targets[index].resolve_ahead_eligible),
    };
    let automatic_parallel_replay = automatic_policy.parallel_replay();
    let automatic_parallel_fresh = automatic_policy.parallel_fresh();
    let automatic_fresh_concurrency = automatic_policy.fresh_concurrency();
    let resolve_ahead = !lockfile_replay_ready
        && !options.offline
        && !options.force
        && !explicit_concurrency
        && !automatic_parallel_fresh
        && targets.len() > 1
        && targets
            .iter()
            .all(|target| !target.lifecycle.has_scripts() && target.resolve_ahead_eligible);
    let release_age_reference_unix = workspace_resolution::current_unix_timestamp();
    let root_provider_coordinator = root_target_index
        .filter(|index| {
            !resolve_ahead
                && !lockfile_replay_ready
                && !options.offline
                && share_local_source_populations
                && !targets[*index].lifecycle.has_scripts()
                && targets[*index].resolve_ahead_eligible
        })
        .map(|_| {
            Arc::new(
                workspace_resolution::WorkspaceRootProviderCoordinator::new_at_unix(
                    release_age_reference_unix,
                ),
            )
        });
    let concurrency = resolve_workspace_install_concurrency(
        options.workspace_concurrency,
        targets.len(),
        automatic_parallel_replay || automatic_parallel_fresh,
        if automatic_parallel_fresh {
            automatic_fresh_concurrency
        } else {
            WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY
        },
    );
    let resolution_concurrency = automatic_workspace_resolution_concurrency(
        targets.len(),
        std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(WORKSPACE_INSTALL_DEFAULT_CONCURRENCY),
    );
    tracing::debug!(
        concurrency,
        effective_resolution_concurrency = if resolve_ahead {
            resolution_concurrency
        } else {
            0
        },
        resolve_ahead,
        root_provider_serialized = root_provider_coordinator.is_some(),
        lockfile_replay_ready,
        share_object_validations = targets_need_materialization,
        share_local_source_populations,
        workspace_resource_pools = true,
        automatic_parallel_replay,
        automatic_parallel_fresh,
        "selected recursive workspace install concurrency"
    );
    let materialization_coordinator = Arc::new(
        workspace_materialization::WorkspaceMaterializationCoordinator::new(
            share_local_source_populations,
        ),
    );
    let resolution_coordinator = resolve_ahead.then(|| {
        Arc::new(match root_target_index {
            Some(root_index) => {
                workspace_resolution::WorkspaceResolutionCoordinator::new_with_root_at_unix(
                    targets.len(),
                    resolution_concurrency,
                    root_index,
                    release_age_reference_unix,
                )
            }
            None => workspace_resolution::WorkspaceResolutionCoordinator::new_at_unix(
                targets.len(),
                resolution_concurrency,
                release_age_reference_unix,
            ),
        })
    });
    let workspace_client =
        (!options.offline && targets.len() > 1).then(|| client.clone_with_metadata_memory_cache());
    let client = workspace_client.as_ref().unwrap_or(client);
    let workspace_root = workspace.root.clone();
    let workspace_lock = lpm_common::project_install_lock(&workspace_root);
    let started = Instant::now();
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let options = Arc::new(options);
    let workspace_freshness_cache =
        Arc::new(crate::workspace_discovery_cache::WorkspaceFreshnessCache::default());
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
        let scheduling_order = workspace_target_scheduling_order(
            &targets,
            resolution_coordinator.is_some() || root_provider_coordinator.is_some(),
        );
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
                    let root_provider_pending = root_provider_coordinator.is_some()
                        && root_target_index.is_some_and(|root_index| !done[root_index]);
                    let scheduler_limit = if root_provider_pending {
                        1
                    } else if resolution_coordinator.is_some() {
                        target_count
                    } else {
                        concurrency
                    };
                    if in_flight.len() >= scheduler_limit {
                        break;
                    }
                    let ready = plans[index].as_ref().is_some_and(|plan| {
                        if root_provider_pending {
                            root_target_index == Some(index)
                        } else {
                            resolution_coordinator.is_some()
                                || plan.schedule_after.iter().all(|dep| done[*dep])
                        }
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
                        Arc::clone(&materialization_coordinator),
                        resolution_coordinator.as_ref().map(Arc::clone),
                        root_provider_coordinator.as_ref().map(Arc::clone),
                        Arc::clone(&workspace_freshness_cache),
                        root_provider_fingerprint.as_ref().map(Arc::clone),
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
        options.timing,
        timing_detail_mode,
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
    materialization_coordinator: Arc<
        workspace_materialization::WorkspaceMaterializationCoordinator,
    >,
    resolution_coordinator: Option<Arc<workspace_resolution::WorkspaceResolutionCoordinator>>,
    root_provider_coordinator: Option<Arc<workspace_resolution::WorkspaceRootProviderCoordinator>>,
    workspace_freshness_cache: Arc<crate::workspace_discovery_cache::WorkspaceFreshnessCache>,
    root_provider_fingerprint: Option<Arc<str>>,
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
        let is_root = plan.kind == "root";
        let install = run_workspace_target_install(
            plan,
            client,
            lpm_root,
            base_workspace,
            options,
            workspace_freshness_cache,
            root_provider_fingerprint,
        );
        let install = async {
            match root_provider_coordinator {
                Some(coordinator) => {
                    workspace_resolution::root_provider_scope(coordinator, is_root, install).await
                }
                None => install.await,
            }
        };
        let install = workspace_materialization::scope(materialization_coordinator, install);
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
    workspace_freshness_cache: Arc<crate::workspace_discovery_cache::WorkspaceFreshnessCache>,
    root_provider_fingerprint: Option<Arc<str>>,
) -> Result<TargetTaskResult, LpmError> {
    plan.lifecycle
        .run_dev_preinstall(&plan.path, options.json_output)?;
    if plan.lifecycle.has_dev_preinstall() {
        workspace_freshness_cache.invalidate();
    }

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
                root_provider_fingerprint.as_ref().map(Arc::clone),
                Arc::clone(&workspace_freshness_cache),
                report_capture::scope(Arc::clone(capture), install),
            )
            .await?;
        }
        None => {
            crate::workspace_discovery_cache::scope(
                Arc::clone(&scoped_workspace),
                root_provider_fingerprint,
                Arc::clone(&workspace_freshness_cache),
                install,
            )
            .await?;
        }
    }

    plan.lifecycle
        .run_after_successful_install(&plan.path, options.json_output)?;
    if plan.lifecycle.has_scripts() {
        workspace_freshness_cache.invalidate();
    }

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
    automatic_parallel: bool,
    automatic_max_concurrency: usize,
) -> usize {
    let configured = explicit_workspace_install_concurrency(cli_override);
    let limit = configured.unwrap_or_else(|| {
        let available_parallelism = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(WORKSPACE_INSTALL_DEFAULT_CONCURRENCY);
        automatic_workspace_install_concurrency(
            target_count,
            automatic_parallel,
            available_parallelism,
            automatic_max_concurrency,
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
    automatic_parallel: bool,
    available_parallelism: usize,
    automatic_max_concurrency: usize,
) -> usize {
    if !automatic_parallel {
        return WORKSPACE_INSTALL_DEFAULT_CONCURRENCY;
    }
    available_parallelism
        .clamp(1, automatic_max_concurrency.max(1))
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

fn package_allows_resolution_ahead(
    package: &lpm_workspace::PackageJson,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> bool {
    [
        &package.dependencies,
        &package.dev_dependencies,
        &package.optional_dependencies,
        &package.peer_dependencies,
    ]
    .into_iter()
    .all(|dependencies| {
        let mut resolved = dependencies.clone();
        lpm_workspace::resolve_catalog_protocol(&mut resolved, catalogs).is_ok()
            && resolved
                .values()
                .all(|specifier| dependency_specifier_allows_resolution_ahead(specifier))
    })
}

fn workspace_targets_need_materialization(targets: &[WorkspaceInstallTarget]) -> bool {
    targets
        .iter()
        .any(|target| !target.path.join("node_modules").is_dir())
}

fn workspace_allows_shared_local_source_populations(targets: &[WorkspaceInstallTarget]) -> bool {
    targets
        .iter()
        .all(|target| target.kind == "root" || !target.lifecycle.has_scripts())
}

fn package_install_dependency_count(package: &lpm_workspace::PackageJson) -> usize {
    package
        .dependencies
        .len()
        .saturating_add(package.dev_dependencies.len())
        .saturating_add(package.optional_dependencies.len())
        .saturating_add(package.peer_dependencies.len())
}

fn workspace_targets_are_lockfile_replay_ready(
    workspace: &lpm_workspace::Workspace,
    targets: &[WorkspaceInstallTarget],
    options: &RecursiveInstallOptions,
    root_provider_fingerprint: Option<&str>,
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
        target_lockfile_is_replay_ready(
            workspace,
            &target.path,
            package,
            global_auto_install_peers,
            root_provider_fingerprint,
        )
    })
}

fn target_lockfile_is_replay_ready(
    workspace: &lpm_workspace::Workspace,
    project_dir: &Path,
    package: &lpm_workspace::PackageJson,
    global_auto_install_peers: Option<bool>,
    root_provider_fingerprint: Option<&str>,
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
    let mut current_importer = validation::importer_snapshot_for_current_manifest(
        package,
        &overrides.lpm_overrides,
        overrides.overrides.as_ref(),
        overrides.resolutions.as_ref(),
        overrides.override_catalogs,
        None,
        auto_install_peers,
    );
    let locked_uses_root_providers = lockfile
        .importers
        .get(".")
        .and_then(|importer| {
            importer
                .workspace_root_peer_providers_fingerprint
                .as_deref()
        })
        .is_some();
    if project_dir != workspace.root && locked_uses_root_providers {
        current_importer.workspace_root_peer_providers_fingerprint =
            root_provider_fingerprint.map(str::to_string);
    }
    if lockfile.importers.get(".") != Some(&current_importer) {
        return false;
    }

    lockfile_satisfies_fast_path(
        &lockfile,
        project_dir,
        &deps,
        &catalog_resolutions,
        Some(workspace),
        false,
        false,
    )
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
            dependency_count: package_install_dependency_count(&member.package),
            resolve_ahead_eligible: package_allows_resolution_ahead(
                &member.package,
                &workspace.root_package.catalogs,
            ),
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
            dependency_count: package_install_dependency_count(&workspace.root_package),
            resolve_ahead_eligible: package_allows_resolution_ahead(
                &workspace.root_package,
                &workspace.root_package.catalogs,
            ),
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
    "counts",
    "used_lockfile",
    "timing",
    "security",
    "audit_summary",
];

fn emit_workspace_install_report(
    workspace_root: &Path,
    outcomes: &[WorkspaceInstallOutcome],
    json_output: bool,
    emit_timing: bool,
    timing_detail_mode: TimingDetailMode,
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
                            target[*field] = if *field == "timing" {
                                recursive_target_timing(value)
                            } else {
                                value.clone()
                            };
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
        attach_aggregate_telemetry(&mut report, duration_ms, emit_timing, timing_detail_mode);
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        output::success(&format!(
            "Installed {} workspace package{} in {duration_ms}ms",
            outcomes.len(),
            if outcomes.len() == 1 { "" } else { "s" },
        ));
    }
}

fn recursive_target_timing(source: &serde_json::Value) -> serde_json::Value {
    let mut timing = source.clone();
    attach_target_timing_semantics(&mut timing);
    timing["process_global_metrics"] = serde_json::json!({
        "scope": "recursive_command",
        "reported_at": "timing.process",
    });

    if let Some(resolve) = timing
        .get_mut("resolve")
        .and_then(serde_json::Value::as_object_mut)
    {
        for field in [
            "followup_rpc_ms",
            "followup_rpc_count",
            "walker_rpc_count",
            "escape_hatch_rpc_count",
            "parse_ndjson_ms",
            "metadata_http_versions",
        ] {
            resolve.remove(field);
        }
    }

    if let Some(detail) = timing
        .get_mut("detail")
        .and_then(serde_json::Value::as_object_mut)
    {
        detail.remove("metadata");
        if let Some(resolve) = detail
            .get_mut("resolve")
            .and_then(serde_json::Value::as_object_mut)
        {
            resolve.remove("metadata");
            resolve.remove("metadata_fetch");
            resolve.remove("policy");
            if let Some(scheduler) = resolve
                .get_mut("scheduler")
                .and_then(serde_json::Value::as_object_mut)
            {
                for field in [
                    "followup_rpc_ms",
                    "followup_rpc_count",
                    "walker_rpc_count",
                    "escape_hatch_rpc_count",
                ] {
                    scheduler.remove(field);
                }
            }
            if let Some(cpu) = resolve
                .get_mut("cpu")
                .and_then(serde_json::Value::as_object_mut)
            {
                cpu.remove("parse_ndjson_ms");
                cpu.remove("pubgrub_core_estimate_ms");
            }
        }
    }

    timing
}

fn recursive_process_timing(timing_detail_mode: TimingDetailMode) -> serde_json::Value {
    let registry = lpm_registry::timing::snapshot();
    let http_versions = lpm_registry::timing::snapshot_metadata_http_versions();
    let policy = lpm_resolver::profile::policy_summary();
    let mut process = serde_json::json!({
        "scope": "recursive_command",
        "registry": {
            "metadata_rpc_sum_ms": registry.metadata_rpc.as_millis(),
            "metadata_rpc_count": registry.metadata_rpc_count,
            "parse_ndjson_sum_ms": registry.parse_ndjson.as_millis(),
            "walker_rpc_count": registry.walker_rpc_count,
            "escape_hatch_rpc_count": registry.escape_hatch_rpc_count,
            "metadata_http_versions": {
                "http_09": http_versions.http_09,
                "http_10": http_versions.http_10,
                "http_11": http_versions.http_11,
                "http_2": http_versions.http_2,
                "http_3": http_versions.http_3,
                "unknown": http_versions.unknown,
            },
        },
        "resolver_policy": {
            "release_age": {
                "sum_ms": policy.release_age.elapsed.as_millis(),
                "checked_count": policy.release_age.checked_count,
                "rejected_count": policy.release_age.rejected_count,
                "missing_count": policy.release_age.missing_count,
            },
            "trust": {
                "sum_ms": policy.trust_policy.elapsed.as_millis(),
                "checked_count": policy.trust_policy.checked_count,
                "rejected_count": policy.trust_policy.rejected_count,
            },
        },
    });
    if timing_detail_mode.enabled() {
        let metadata = metadata_detail_snapshots();
        process["metadata"] = metadata_detail_json_from_snapshots(&metadata, timing_detail_mode);
    }
    if timing_detail_mode.trace() {
        let metadata_fetch = lpm_registry::timing::snapshot_metadata_fetch_detail();
        process["metadata_fetch"] =
            metadata_fetch_detail_json_from_snapshot(&metadata_fetch, timing_detail_mode);
    }
    process
}

/// Roll per-target counters and phase timings up to the envelope root.
/// Target phase values are work sums and can exceed command wall time.
fn attach_aggregate_telemetry(
    report: &mut serde_json::Value,
    wall_ms: u64,
    emit_timing: bool,
    timing_detail_mode: TimingDetailMode,
) {
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
    let sum_count = |field: &str| -> u64 {
        targets
            .iter()
            .filter_map(|target| {
                target
                    .get("counts")
                    .and_then(|counts| counts.get(field))
                    .and_then(serde_json::Value::as_u64)
            })
            .fold(0u64, u64::saturating_add)
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
    let waterfall_sum = |field: &str| -> u64 {
        targets
            .iter()
            .filter_map(|target| {
                target
                    .get("timing")
                    .and_then(|timing| timing.get("waterfall"))
                    .and_then(|waterfall| waterfall.get(field))
                    .and_then(serde_json::Value::as_u64)
            })
            .fold(0u64, u64::saturating_add)
    };
    let resolver_substage_sum = |field: &str| -> f64 {
        targets
            .iter()
            .filter_map(|target| {
                target
                    .get("timing")
                    .and_then(|timing| timing.get("detail"))
                    .and_then(|detail| detail.get("resolve"))
                    .and_then(|resolve| resolve.get("substages"))
                    .and_then(|substages| substages.get(field))
                    .and_then(serde_json::Value::as_f64)
            })
            .sum()
    };
    let resolve_ms = timing_sum("resolve_ms");
    let fetch_ms = timing_sum("fetch_ms");
    let link_ms = timing_sum("link_ms");
    let materialization_wait_ms = waterfall_sum("materialization_wait_ms");
    let commit_wait_ms = waterfall_sum("commit_wait_ms");
    let post_resolve_work_ms = waterfall_sum("post_resolve_work_ms");
    let resolver_substage_sums = timing_detail_mode.trace().then(|| {
        serde_json::json!({
            "scope": "recursive_command",
            "aggregation": "sum_of_resolver_pass_work",
            "work_is_cumulative": true,
            "tree_policy_ms": resolver_substage_sum("tree_policy_ms"),
            "policy_hydration_ms": resolver_substage_sum("policy_hydration_ms"),
            "manifest_wait_ms": resolver_substage_sum("manifest_wait_ms"),
            "edge_expansion_ms": resolver_substage_sum("edge_expansion_ms"),
            "graph_finalization_ms": resolver_substage_sum("graph_finalization_ms"),
        })
    });
    let aggregate_counts = serde_json::json!({
        "scope": "recursive_command",
        "aggregation": "sum_of_target_observations",
        "work_is_cumulative": true,
        "resolved_package_row_count": sum_count("resolved_package_row_count"),
        "authoritative_fetch_candidate_count":
            sum_count("authoritative_fetch_candidate_count"),
        "store_reuse_observation_count": sum_count("store_reuse_observation_count"),
        "store_reuse_may_include_same_command_population": true,
        "linker_entry_created_count": sum_count("linker_entry_created_count"),
        "linker_entry_reused_count": sum_count("linker_entry_reused_count"),
        "project_root_symlink_created_count":
            sum_count("project_root_symlink_created_count"),
        "bin_link_created_count": sum_count("bin_link_created_count"),
    });

    for (field, value) in counters {
        if let Some(value) = value {
            report[field] = serde_json::json!(value);
        }
    }
    if all_up_to_date {
        report["up_to_date"] = serde_json::json!(true);
    }
    report["counts"] = aggregate_counts;
    if emit_timing {
        report["timing"] = serde_json::json!({
            "scope": "recursive_command",
            "work_is_cumulative": true,
            "phase_aggregation": "sum_of_target_wall_clock",
            "resolve_ms": resolve_ms,
            "fetch_ms": fetch_ms,
            "link_ms": link_ms,
            "total_ms": wall_ms,
            "waterfall": {
                "total_ms": wall_ms,
            },
            "wait": {
                "aggregation": "sum_of_target_wall_clock",
                "target_materialization_sum_ms": materialization_wait_ms,
                "target_commit_sum_ms": commit_wait_ms,
            },
            "work": {
                "target_resolve_sum_ms": resolve_ms,
                "target_post_resolve_sum_ms": post_resolve_work_ms,
                "target_fetch_sum_ms": fetch_ms,
                "target_link_sum_ms": link_ms,
            },
            "process": recursive_process_timing(timing_detail_mode),
        });
        if let Some(resolver_substage_sums) = resolver_substage_sums {
            report["timing"]["work"]["resolver_substage_sums"] = resolver_substage_sums;
        }
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

        assert_eq!(
            resolve_workspace_install_concurrency(
                None,
                4,
                false,
                WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY,
            ),
            1,
        );
    }

    #[test]
    fn recursive_workspace_install_parallelizes_proven_lockfile_replays() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            None::<std::ffi::OsString>,
        )]);

        assert_eq!(
            automatic_workspace_install_concurrency(
                8,
                true,
                8,
                WORKSPACE_INSTALL_AUTOMATIC_MAX_CONCURRENCY,
            ),
            3,
        );
    }

    #[test]
    fn recursive_workspace_install_parallelizes_large_safe_fresh_workspaces() {
        let policy = large_fresh_workspace_policy();

        assert!(policy.parallel_fresh());
        assert_eq!(
            automatic_workspace_install_concurrency(
                78,
                true,
                8,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            6,
        );
    }

    #[test]
    fn recursive_workspace_install_keeps_small_fresh_workspaces_sequential() {
        let policy = AutomaticWorkspaceInstallPolicy {
            target_count: 4,
            dependency_count: 0,
            ..large_fresh_workspace_policy()
        };

        assert!(!policy.parallel_fresh());
        assert_eq!(
            automatic_workspace_install_concurrency(
                4,
                false,
                8,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            1,
        );
    }

    #[test]
    fn recursive_workspace_install_parallelizes_smaller_dependency_heavy_workspaces() {
        let policy = AutomaticWorkspaceInstallPolicy {
            target_count: 30,
            dependency_count: 500,
            ..large_fresh_workspace_policy()
        };

        assert!(policy.parallel_fresh());
        assert_eq!(policy.fresh_concurrency(), 3);
    }

    #[test]
    fn recursive_workspace_install_keeps_large_dependency_free_workspaces_sequential() {
        let policy = AutomaticWorkspaceInstallPolicy {
            target_count: 240,
            dependency_count: 0,
            ..large_fresh_workspace_policy()
        };

        assert!(!policy.parallel_fresh());
        assert_eq!(policy.fresh_concurrency(), 1);
    }

    #[test]
    fn recursive_workspace_install_keeps_uncoordinated_fresh_workspaces_sequential() {
        let policy = AutomaticWorkspaceInstallPolicy {
            root_resolve_ahead_eligible: false,
            ..large_fresh_workspace_policy()
        };

        assert!(!policy.parallel_fresh());
    }

    #[test]
    fn recursive_workspace_install_keeps_script_bearing_fresh_workspaces_sequential() {
        let policy = AutomaticWorkspaceInstallPolicy {
            share_local_source_populations: false,
            ..large_fresh_workspace_policy()
        };

        assert!(!policy.parallel_fresh());
    }

    #[test]
    fn recursive_workspace_install_allows_parallel_members_before_scripted_root() {
        let package = replay_ready_package();
        let mut scripted_root_package = package.clone();
        scripted_root_package
            .scripts
            .insert("prepare".to_string(), "node prepare.js".to_string());
        let member = workspace_target("member", "member", &package);
        let root = workspace_target("root", "root", &scripted_root_package);
        let targets = [member, root];
        let policy = AutomaticWorkspaceInstallPolicy {
            share_local_source_populations: workspace_allows_shared_local_source_populations(
                &targets,
            ),
            ..large_fresh_workspace_policy()
        };

        assert!(policy.parallel_fresh());
        assert_eq!(
            workspace_target_scheduling_order(&targets, false),
            vec![0, 1]
        );
    }

    #[test]
    fn recursive_workspace_install_keeps_offline_and_forced_fresh_workspaces_sequential() {
        let offline = AutomaticWorkspaceInstallPolicy {
            offline: true,
            ..large_fresh_workspace_policy()
        };
        let forced = AutomaticWorkspaceInstallPolicy {
            force: true,
            ..large_fresh_workspace_policy()
        };

        assert!(!offline.parallel_fresh());
        assert!(!forced.parallel_fresh());
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
    fn recursive_workspace_resolution_rejects_catalog_entry_resolving_to_local_source() {
        let mut package = lpm_workspace::PackageJson::default();
        package
            .dependencies
            .insert("local-package".to_string(), "catalog:".to_string());
        package.catalogs.insert(
            "default".to_string(),
            HashMap::from([(
                "local-package".to_string(),
                "file:../local-package".to_string(),
            )]),
        );

        assert!(!package_allows_resolution_ahead(
            &package,
            &package.catalogs,
        ));
    }

    #[test]
    fn recursive_workspace_install_caps_automatic_parallelism_by_target_count() {
        assert_eq!(
            automatic_workspace_install_concurrency(
                2,
                true,
                8,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            2,
        );
    }

    #[test]
    fn recursive_workspace_install_keeps_automatic_parallelism_within_available_cpus() {
        assert_eq!(
            automatic_workspace_install_concurrency(
                8,
                true,
                2,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            2,
        );
    }

    #[test]
    fn recursive_workspace_install_cli_concurrency_overrides_automatic_policy() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            Some(std::ffi::OsString::from("2")),
        )]);

        assert_eq!(
            resolve_workspace_install_concurrency(
                NonZeroUsize::new(3),
                8,
                false,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            3,
        );
    }

    #[test]
    fn recursive_workspace_install_env_concurrency_overrides_automatic_policy() {
        let _env = crate::test_env::ScopedEnv::update([(
            ENV_WORKSPACE_CONCURRENCY,
            Some(std::ffi::OsString::from("3")),
        )]);

        assert_eq!(
            resolve_workspace_install_concurrency(
                None,
                8,
                false,
                WORKSPACE_INSTALL_FRESH_MAX_CONCURRENCY,
            ),
            3,
        );
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

    fn large_fresh_workspace_policy() -> AutomaticWorkspaceInstallPolicy {
        AutomaticWorkspaceInstallPolicy {
            target_count: 78,
            dependency_count: 2_022,
            targets_need_materialization: true,
            lockfile_replay_ready: false,
            offline: false,
            force: false,
            explicit_concurrency: false,
            share_local_source_populations: true,
            root_resolve_ahead_eligible: true,
        }
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
            dependency_count: package_install_dependency_count(package),
            resolve_ahead_eligible: package_allows_resolution_ahead(package, &package.catalogs),
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
            dependency_count: package_install_dependency_count(package),
            resolve_ahead_eligible: package_allows_resolution_ahead(package, &package.catalogs),
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
