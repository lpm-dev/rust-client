use super::cache::{
    CompletedTaskCacheIdentity, TaskDependencyIdentity, WorkspaceCacheContract,
    WorkspaceDependencyIdentities, is_task_cached_with_config,
};
use super::format::{
    TaskResult, TaskRunReport, format_run_failure_detail, format_workspace_member_scripts_header,
};
use super::parallel::run_tasks_parallel;
use super::runtime::{ensure_runtime, validate_runtime_requirements_with_cache};
use super::sequential::run_tasks_sequential;
use super::task::{is_meta_task, reject_direct_hidden_scripts, run_task};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct WorkspaceMemberTaskConfig {
    package_scripts: HashMap<String, String>,
    lpm_config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct WorkspaceTaskRef {
    member_idx: usize,
    task_name: String,
}

struct WorkspaceMemberTaskPlan {
    config: WorkspaceMemberTaskConfig,
    requested_tasks: Vec<String>,
    task_levels: Vec<Vec<String>>,
    sequential_tasks: Vec<String>,
    direct_workspace_task_dependencies: HashMap<String, Vec<WorkspaceTaskRef>>,
}

impl WorkspaceMemberTaskConfig {
    fn tasks(&self) -> &HashMap<String, lpm_runner::lpm_json::TaskConfig> {
        match &self.lpm_config {
            Some(config) => &config.tasks,
            None => empty_task_config(),
        }
    }

    fn has_task(&self, name: &str) -> bool {
        self.package_scripts.contains_key(name)
            || self
                .tasks()
                .get(name)
                .is_some_and(|task| task.command.is_some() || !task.depends_on.is_empty())
    }
}

fn empty_task_config() -> &'static HashMap<String, lpm_runner::lpm_json::TaskConfig> {
    static EMPTY: std::sync::OnceLock<HashMap<String, lpm_runner::lpm_json::TaskConfig>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(HashMap::new)
}

fn load_workspace_member_task_config(
    member_dir: &Path,
    package_scripts: HashMap<String, String>,
) -> Result<WorkspaceMemberTaskConfig, LpmError> {
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(member_dir).map_err(|error| {
        LpmError::Script(format!(
            "failed to read {}: {error}",
            member_dir.join("lpm.json").display()
        ))
    })?;
    Ok(WorkspaceMemberTaskConfig {
        package_scripts,
        lpm_config,
    })
}

fn ensure_workspace_member_task_config(
    member_idx: usize,
    workspace_graph: &lpm_task::graph::WorkspaceGraph,
    package_scripts: &mut [Option<HashMap<String, String>>],
    configs: &mut [Option<WorkspaceMemberTaskConfig>],
) -> Result<(), LpmError> {
    if configs[member_idx].is_none() {
        let member_scripts = package_scripts[member_idx].take().ok_or_else(|| {
            LpmError::Script(format!(
                "internal package scripts missing for workspace member '{}'",
                workspace_graph.members[member_idx].name
            ))
        })?;
        configs[member_idx] = Some(load_workspace_member_task_config(
            &workspace_graph.members[member_idx].path,
            member_scripts,
        )?);
    }
    Ok(())
}

fn sort_direct_workspace_task_dependencies(
    direct_dependencies: HashMap<String, HashSet<WorkspaceTaskRef>>,
) -> HashMap<String, Vec<WorkspaceTaskRef>> {
    direct_dependencies
        .into_iter()
        .map(|(task_name, dependencies)| {
            let mut dependencies: Vec<_> = dependencies.into_iter().collect();
            dependencies.sort_unstable();
            (task_name, dependencies)
        })
        .collect()
}

fn build_workspace_task_schedule(
    workspace_graph: &lpm_task::graph::WorkspaceGraph,
    package_scripts: Vec<HashMap<String, String>>,
    target_set: &HashSet<usize>,
    requested_tasks: &[String],
) -> Result<Vec<Option<Arc<WorkspaceMemberTaskPlan>>>, LpmError> {
    let member_count = workspace_graph.members.len();
    let mut package_scripts: Vec<_> = package_scripts.into_iter().map(Some).collect();
    let mut configs: Vec<Option<WorkspaceMemberTaskConfig>> =
        (0..member_count).map(|_| None).collect();
    let mut scheduled_tasks = vec![Vec::new(); member_count];
    let mut scheduled_names: Vec<HashSet<String>> =
        (0..member_count).map(|_| HashSet::new()).collect();
    let mut direct_upstream_task_dependencies: Vec<HashMap<String, HashSet<WorkspaceTaskRef>>> =
        (0..member_count).map(|_| HashMap::new()).collect();
    let mut pending = VecDeque::new();

    let mut targets: Vec<usize> = target_set.iter().copied().collect();
    targets.sort_unstable();
    for member_idx in targets {
        ensure_workspace_member_task_config(
            member_idx,
            workspace_graph,
            &mut package_scripts,
            &mut configs,
        )?;
        let config = configs[member_idx].as_ref().ok_or_else(|| {
            LpmError::Script(format!(
                "internal task config missing for workspace member '{}'",
                workspace_graph.members[member_idx].name
            ))
        })?;
        if !requested_tasks.iter().any(|task| config.has_task(task)) {
            continue;
        }
        for task in requested_tasks {
            if scheduled_names[member_idx].insert(task.clone()) {
                scheduled_tasks[member_idx].push(task.clone());
                pending.push_back((member_idx, task.clone()));
            }
        }
    }

    let mut expanded = HashSet::new();
    let mut expanded_upstream = HashSet::new();
    while let Some((member_idx, task_name)) = pending.pop_front() {
        if !expanded.insert((member_idx, task_name.clone())) {
            continue;
        }
        ensure_workspace_member_task_config(
            member_idx,
            workspace_graph,
            &mut package_scripts,
            &mut configs,
        )?;
        let dependencies = {
            let config = configs[member_idx].as_ref().ok_or_else(|| {
                LpmError::Script(format!(
                    "internal task config missing for workspace member '{}'",
                    workspace_graph.members[member_idx].name
                ))
            })?;
            if !config.has_task(&task_name) {
                return Err(LpmError::Script(format!(
                    "workspace member '{}' does not define requested task '{task_name}'",
                    workspace_graph.members[member_idx].name
                )));
            }
            config
                .tasks()
                .get(&task_name)
                .map(|task| task.depends_on.clone())
                .unwrap_or_default()
        };
        for dependency in dependencies {
            if let Some(upstream_task) = dependency.strip_prefix('^') {
                if upstream_task.is_empty() || upstream_task.starts_with('^') {
                    return Err(LpmError::Script(format!(
                        "task '{}:{task_name}' has invalid upstream dependency '{dependency}'",
                        workspace_graph.members[member_idx].name
                    )));
                }
                let mut upstream_edges: VecDeque<_> = workspace_graph.edges[member_idx]
                    .iter()
                    .map(|&upstream_idx| (member_idx, task_name.clone(), upstream_idx))
                    .collect();
                while let Some((dependent_idx, dependent_task, upstream_idx)) =
                    upstream_edges.pop_front()
                {
                    direct_upstream_task_dependencies[dependent_idx]
                        .entry(dependent_task.clone())
                        .or_default()
                        .insert(WorkspaceTaskRef {
                            member_idx: upstream_idx,
                            task_name: upstream_task.to_string(),
                        });
                    if !expanded_upstream.insert((upstream_idx, upstream_task.to_string())) {
                        continue;
                    }
                    ensure_workspace_member_task_config(
                        upstream_idx,
                        workspace_graph,
                        &mut package_scripts,
                        &mut configs,
                    )?;
                    let upstream_config = configs[upstream_idx].as_ref().ok_or_else(|| {
                        LpmError::Script(format!(
                            "internal task config missing for workspace member '{}'",
                            workspace_graph.members[upstream_idx].name
                        ))
                    })?;
                    if !upstream_config.has_task(upstream_task) {
                        return Err(LpmError::Script(format!(
                            "task '{}:{dependent_task}' requires '^{upstream_task}', but workspace dependency '{}' does not define task '{upstream_task}'",
                            workspace_graph.members[dependent_idx].name,
                            workspace_graph.members[upstream_idx].name
                        )));
                    }
                    if scheduled_names[upstream_idx].insert(upstream_task.to_string()) {
                        scheduled_tasks[upstream_idx].push(upstream_task.to_string());
                        pending.push_back((upstream_idx, upstream_task.to_string()));
                    }
                    upstream_edges.extend(workspace_graph.edges[upstream_idx].iter().map(
                        |&transitive_idx| (upstream_idx, upstream_task.to_string(), transitive_idx),
                    ));
                }
            } else {
                let config = configs[member_idx].as_ref().ok_or_else(|| {
                    LpmError::Script(format!(
                        "internal task config missing for workspace member '{}'",
                        workspace_graph.members[member_idx].name
                    ))
                })?;
                if !config.has_task(&dependency) {
                    return Err(LpmError::Script(format!(
                        "task '{}:{task_name}' depends on '{dependency}', but that task is not defined",
                        workspace_graph.members[member_idx].name
                    )));
                }
                pending.push_back((member_idx, dependency));
            }
        }
    }

    let mut plans = Vec::with_capacity(member_count);
    for (member_idx, requested_tasks) in scheduled_tasks.into_iter().enumerate() {
        if requested_tasks.is_empty() {
            plans.push(None);
            continue;
        }
        let config = configs[member_idx].take().ok_or_else(|| {
            LpmError::Script(format!(
                "internal task config missing for workspace member '{}'",
                workspace_graph.members[member_idx].name
            ))
        })?;
        let lpm_runner::task_graph::TaskSchedule {
            levels: task_levels,
            sequential: sequential_tasks,
        } = lpm_runner::task_graph::task_schedule(
            &config.package_scripts,
            config.tasks(),
            &requested_tasks,
        )
        .map_err(|error| {
            LpmError::Script(format!(
                "task graph for workspace member '{}': {error}",
                workspace_graph.members[member_idx].name
            ))
        })?;
        let direct_workspace_task_dependencies = sort_direct_workspace_task_dependencies(
            std::mem::take(&mut direct_upstream_task_dependencies[member_idx]),
        );
        plans.push(Some(Arc::new(WorkspaceMemberTaskPlan {
            config,
            requested_tasks,
            task_levels,
            sequential_tasks,
            direct_workspace_task_dependencies,
        })));
    }

    Ok(plans)
}

fn resolve_workspace_dependency_identities(
    member_task_plan: &WorkspaceMemberTaskPlan,
    workspace_graph: &lpm_task::graph::WorkspaceGraph,
    completed_task_identities: &[Option<HashMap<String, Arc<CompletedTaskCacheIdentity>>>],
) -> WorkspaceDependencyIdentities {
    let mut resolved =
        HashMap::with_capacity(member_task_plan.direct_workspace_task_dependencies.len());
    for (task_name, dependencies) in &member_task_plan.direct_workspace_task_dependencies {
        let mut identities = dependencies
            .iter()
            .map(|dependency| {
                completed_task_identities
                    .get(dependency.member_idx)
                    .and_then(Option::as_ref)
                    .and_then(|identities| identities.get(&dependency.task_name))
                    .map(|identity| TaskDependencyIdentity {
                        label: format!(
                            "workspace:{}#{}",
                            workspace_graph.members[dependency.member_idx].name,
                            dependency.task_name
                        ),
                        node: Arc::clone(identity),
                    })
            })
            .collect::<Option<Vec<_>>>();
        if let Some(identities) = &mut identities {
            identities.sort_unstable_by(|left, right| left.label.cmp(&right.label));
        }
        resolved.insert(task_name.clone(), identities);
    }
    resolved
}

fn blocked_workspace_tasks(
    member_task_plan: &WorkspaceMemberTaskPlan,
    completed_task_states: &[Option<HashMap<String, bool>>],
) -> HashSet<String> {
    member_task_plan
        .direct_workspace_task_dependencies
        .iter()
        .filter(|(_, dependencies)| {
            dependencies.iter().any(|dependency| {
                !completed_task_states
                    .get(dependency.member_idx)
                    .and_then(Option::as_ref)
                    .and_then(|states| states.get(&dependency.task_name))
                    .copied()
                    .unwrap_or(false)
            })
        })
        .map(|(task_name, _)| task_name.clone())
        .collect()
}

fn required_cache_identities(
    task_report: &TaskRunReport,
    required_tasks: &HashSet<String>,
) -> HashMap<String, Arc<CompletedTaskCacheIdentity>> {
    required_tasks
        .iter()
        .filter_map(|task_name| {
            task_report
                .task_cache_identity(task_name)
                .map(|identity| (task_name.clone(), Arc::clone(identity)))
        })
        .collect()
}

/// Run scripts across workspace packages with task-graph-aware execution.
///
/// For each package in workspace topological order:
/// 1. Build a task dependency graph from the package's lpm.json
/// 2. Expand requested scripts into their full dependency chain
/// 3. Execute the expanded task set (parallel or sequential based on flags)
///
/// This delivers the "packages × tasks" execution matrix.
///
/// Filter selection goes through the shared `lpm_task::filter::FilterEngine`
/// with explicit glob grammar. Bare names no longer substring-match; users must
/// write explicit globs (`*foo*`, `foo-*`, etc.).
#[allow(clippy::too_many_arguments)]
pub async fn run_workspace(
    project_dir: &Path,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    filters: &[String],
    filter_prod: &[String],
    affected: bool,
    base_ref: &str,
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    fail_if_no_match: bool,
    no_cache: bool,
    parallel: bool,
    continue_on_error: bool,
    workspace_concurrency: Option<NonZeroUsize>,
    stream: bool,
    json_output: bool,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    reject_direct_hidden_scripts(scripts)?;

    // Capture the root hint so members without their own version pin can
    // inherit it; members with local pins still resolve themselves.
    let root_hint = Arc::new(ensure_runtime(project_dir).await?);

    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "no workspace found. --all/--filter/--affected require a monorepo".into(),
            )
        })?;

    let ws_graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
    let levels = ws_graph
        .topological_levels()
        .map_err(|e| LpmError::Script(e.to_string()))?;
    let workspace_concurrency = crate::workspace_concurrency_config::resolve_workspace_concurrency(
        &workspace.root,
        workspace_concurrency,
    )?
    .get();

    let target_set = crate::workspace_select::select_workspace_target_set(
        &ws_graph,
        &workspace.root,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        affected,
        base_ref,
    )?;

    if target_set.is_empty() {
        // Surface the bare-filter migration hint when a name-like filter
        // would have matched under the old substring behavior.
        let hint = crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);

        if fail_if_no_match {
            let base_msg = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base_msg}\n\n{h}"),
                None => base_msg.to_string(),
            }));
        }

        if json_output {
            let json = serde_json::json!({
                "success": true,
                "packages": 0,
                "succeeded": 0,
                "duration_ms": 0,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            return Ok(());
        }

        install_ui::warn("No packages matched");
        if let Some(h) = hint {
            install_ui::detail("");
            for line in h.lines() {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {}",
                    install_ui::dim(line)
                ));
            }
            install_ui::detail("");
        }
        return Ok(());
    }

    let engine_strict =
        crate::engine_strict_config::resolve_for_root(false, &workspace.root_package);
    let member_engine_requirements: Vec<_> = workspace
        .members
        .iter()
        .map(|member| {
            crate::engine_check::workspace_node_engine_requirements(
                &workspace.root_package,
                Some(&member.package),
                engine_strict,
            )
        })
        .collect();
    let package_scripts: Vec<HashMap<String, String>> = workspace
        .members
        .into_iter()
        .map(|member| member.package.scripts)
        .collect();
    let member_task_plans =
        build_workspace_task_schedule(&ws_graph, package_scripts, &target_set, scripts)?;
    let mut no_cache = no_cache;
    let caches_a_task = member_task_plans.iter().flatten().any(|plan| {
        plan.task_levels
            .iter()
            .flatten()
            .any(|task| is_task_cached_with_config(task, plan.config.lpm_config.as_ref()))
    });
    let workspace_contract = if no_cache || !caches_a_task {
        None
    } else {
        WorkspaceCacheContract::for_cached_run(&workspace.root, &mut no_cache)
    };
    let mut required_task_identities: Vec<HashSet<String>> = (0..ws_graph.members.len())
        .map(|_| HashSet::new())
        .collect();
    for member_task_plan in member_task_plans.iter().flatten() {
        for dependency in member_task_plan
            .direct_workspace_task_dependencies
            .values()
            .flatten()
        {
            required_task_identities[dependency.member_idx].insert(dependency.task_name.clone());
        }
    }
    let runnable_members: Vec<bool> = member_task_plans.iter().map(Option::is_some).collect();
    let mut member_runtime_hints = vec![Arc::clone(&root_hint); ws_graph.members.len()];
    let mut node_versions = crate::engine_check::path_node_versions();
    for idx in levels
        .iter()
        .flatten()
        .copied()
        .filter(|idx| runnable_members[*idx])
    {
        let member_dir = &ws_graph.members[idx].path;
        let member_selectors = lpm_runtime::detect::detect_runtime_versions(member_dir)?;
        if !member_selectors.is_empty() {
            let member_hint = ensure_runtime(member_dir).await?;
            let selected_runtimes: Vec<_> = member_selectors
                .iter()
                .map(|selector| selector.runtime)
                .collect();
            member_runtime_hints[idx] = Arc::new(
                member_hint.inherit_unselected_from(root_hint.as_ref(), &selected_runtimes),
            );
            validate_runtime_requirements_with_cache(
                member_dir,
                member_runtime_hints[idx].as_ref(),
                json_output,
                &mut node_versions,
                &member_engine_requirements[idx],
            )?;
        } else {
            validate_runtime_requirements_with_cache(
                member_dir,
                root_hint.as_ref(),
                json_output,
                &mut node_versions,
                &member_engine_requirements[idx],
            )?;
        }
    }

    let total = runnable_members
        .iter()
        .filter(|runnable| **runnable)
        .count();
    let start = std::time::Instant::now();
    let succeeded = AtomicUsize::new(0);
    let failed_flag = AtomicBool::new(false);
    let mut completed_task_identities: Vec<
        Option<HashMap<String, Arc<CompletedTaskCacheIdentity>>>,
    > = (0..ws_graph.members.len()).map(|_| None).collect();
    let mut completed_task_states: Vec<Option<HashMap<String, bool>>> =
        (0..ws_graph.members.len()).map(|_| None).collect();

    let env_access = lpm_runner::env_access::EnvAccessScope::current_or_new();

    if total > 0 {
        let runnable_dag = (workspace_concurrency > 1)
            .then(|| RunnableWorkspaceDag::from_graph(&ws_graph, &runnable_members));
        if runnable_dag
            .as_ref()
            .is_none_or(RunnableWorkspaceDag::is_linear_chain)
        {
            for idx in levels
                .iter()
                .flatten()
                .copied()
                .filter(|idx| runnable_members[*idx])
            {
                if !continue_on_error && failed_flag.load(Ordering::Relaxed) {
                    break;
                }
                let member_task_plan = member_task_plans[idx].as_ref().ok_or_else(|| {
                    LpmError::Script(format!(
                        "internal task plan missing for workspace member '{}'",
                        ws_graph.members[idx].name
                    ))
                })?;
                let workspace_dependency_identities = resolve_workspace_dependency_identities(
                    member_task_plan,
                    &ws_graph,
                    &completed_task_identities,
                );
                let initially_failed_tasks =
                    blocked_workspace_tasks(member_task_plan, &completed_task_states);
                let report = env_access.run(|| {
                    run_workspace_package(
                        &ws_graph.members[idx].path,
                        workspace_contract.as_ref(),
                        &ws_graph.members[idx].name,
                        extra_args,
                        env_mode,
                        no_cache,
                        parallel,
                        continue_on_error,
                        stream,
                        json_output,
                        member_runtime_hints[idx].as_ref(),
                        member_task_plan,
                        &workspace_dependency_identities,
                        &initially_failed_tasks,
                        session.clone(),
                    )
                })?;
                if !no_cache {
                    completed_task_identities[idx] = Some(required_cache_identities(
                        &report,
                        &required_task_identities[idx],
                    ));
                }
                completed_task_states[idx] = Some(report.task_states());
                if report.is_successful() {
                    succeeded.fetch_add(1, Ordering::Relaxed);
                } else {
                    failed_flag.store(true, Ordering::Relaxed);
                }
            }
        } else {
            let runnable_dag = runnable_dag.expect("DAG constructed for workspace_concurrency > 1");
            let mut dag_state = (&mut completed_task_identities, &mut completed_task_states);
            runnable_dag.execute_parallel(
                workspace_concurrency,
                continue_on_error,
                &ws_graph.members,
                &mut dag_state,
                |idx, isolated, (completed_identities, completed_states)| {
                    // Concurrent members need prefixed, piped output so their
                    // logs do not interleave; an isolated member (nothing else
                    // running or ready) keeps inherited stdio unless --stream
                    // was requested.
                    let member_stream = stream || (!isolated && !json_output);
                    let member_name = ws_graph.members[idx].name.clone();
                    let member_task_plan =
                        member_task_plans[idx].as_ref().cloned().ok_or_else(|| {
                            LpmError::Script(format!(
                                "internal task plan missing for workspace member '{member_name}'"
                            ))
                        })?;
                    let workspace_dependency_identities = resolve_workspace_dependency_identities(
                        member_task_plan.as_ref(),
                        &ws_graph,
                        completed_identities,
                    );
                    let initially_failed_tasks =
                        blocked_workspace_tasks(member_task_plan.as_ref(), completed_states);
                    let member_dir = ws_graph.members[idx].path.clone();
                    let args_owned = extra_args.to_vec();
                    let mode_owned = env_mode.map(str::to_owned);
                    let workspace_contract = workspace_contract.clone();
                    let session = session.clone();
                    let member_runtime_hint = Arc::clone(&member_runtime_hints[idx]);
                    let required_task_identities = required_task_identities[idx].clone();
                    let worker_env_access = env_access.clone();
                    Ok(move || {
                        worker_env_access.run(|| {
                            let report = run_workspace_package(
                                &member_dir,
                                workspace_contract.as_ref(),
                                &member_name,
                                &args_owned,
                                mode_owned.as_deref(),
                                no_cache,
                                parallel,
                                continue_on_error,
                                member_stream,
                                json_output,
                                member_runtime_hint.as_ref(),
                                member_task_plan.as_ref(),
                                &workspace_dependency_identities,
                                &initially_failed_tasks,
                                session,
                            )?;
                            let identities = if !no_cache {
                                Some(required_cache_identities(
                                    &report,
                                    &required_task_identities,
                                ))
                            } else {
                                None
                            };
                            Ok((report, identities))
                        })
                    })
                },
                |idx, (report, identities), (completed_identities, completed_states)| {
                    completed_identities[idx] = identities;
                    completed_states[idx] = Some(report.task_states());
                    if report.is_successful() {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                        true
                    } else {
                        failed_flag.store(true, Ordering::Relaxed);
                        false
                    }
                },
            )?;
        }
    }

    let elapsed = start.elapsed();
    let total_succeeded = succeeded.load(Ordering::Relaxed);
    let has_failed = failed_flag.load(Ordering::Relaxed);
    if json_output {
        let json = serde_json::json!({
            "success": !has_failed,
            "packages": total,
            "succeeded": total_succeeded,
            "duration_ms": elapsed.as_millis() as u64,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done_untrusted(&format!(
            "{total} packages, {total_succeeded} succeeded ({:.1}s)",
            elapsed.as_secs_f64()
        ));
    }

    if has_failed {
        Err(LpmError::ExitCode(1))
    } else {
        Ok(())
    }
}

/// Execute scripts in a single workspace package with task-graph awareness.
///
/// This is the per-package workhorse called from `run_workspace()`.
/// It runs synchronously so it can be spawned in threads for package-level
/// parallelism.
#[allow(clippy::too_many_arguments)]
fn run_workspace_package(
    member_dir: &Path,
    workspace_contract: Option<&WorkspaceCacheContract>,
    member_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    json_output: bool,
    bin_hint: &ManagedRuntimeHint,
    member_task_plan: &WorkspaceMemberTaskPlan,
    workspace_dependency_identities: &WorkspaceDependencyIdentities,
    initially_failed_tasks: &HashSet<String>,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<TaskRunReport, LpmError> {
    let member_task_config = &member_task_plan.config;
    let scripts = &member_task_plan.requested_tasks;
    let tasks = member_task_config.tasks();
    let lpm_config = member_task_config.lpm_config.as_ref();

    install_ui::detail("");
    install_ui::detail_line(format_workspace_member_scripts_header(member_name, scripts));

    let task_count: usize = member_task_plan.task_levels.iter().map(Vec::len).sum();

    // Single task, no deps → simple run
    if !json_output
        && !stream
        && task_count == 1
        && scripts.len() == 1
        && !initially_failed_tasks.contains(&scripts[0])
        && (no_cache || !is_task_cached_with_config(&scripts[0], lpm_config))
        && !is_meta_task(
            &scripts[0],
            tasks,
            Some(&member_task_config.package_scripts),
        )
    {
        let start = std::time::Instant::now();
        let success = match run_task(
            member_dir,
            &scripts[0],
            extra_args,
            env_mode,
            tasks,
            bin_hint,
            lpm_config,
        ) {
            Ok(()) => true,
            Err(e) => {
                install_ui::detail_line(format_run_failure_detail(member_name, e));
                false
            }
        };
        return Ok(TaskRunReport::new(vec![TaskResult {
            name: scripts[0].clone(),
            success,
            exit_code: None,
            phase: None,
            duration: start.elapsed(),
            cached: false,
            skipped: false,
        }]));
    }

    if parallel || stream {
        let serial_levels;
        let execution_levels = if parallel {
            &member_task_plan.task_levels
        } else {
            serial_levels = member_task_plan
                .sequential_tasks
                .iter()
                .cloned()
                .map(|task| vec![task])
                .collect::<Vec<_>>();
            &serial_levels
        };
        run_tasks_parallel(
            member_dir,
            workspace_contract,
            workspace_dependency_identities,
            execution_levels,
            extra_args,
            env_mode,
            continue_on_error,
            stream,
            no_cache,
            tasks,
            lpm_config,
            super::format::TaskOutputPolicy::nested(json_output),
            bin_hint,
            Some(&member_task_config.package_scripts),
            initially_failed_tasks,
            session,
            Some(member_name),
        )
    } else {
        let topo_order = &member_task_plan.sequential_tasks;
        run_tasks_sequential(
            member_dir,
            workspace_contract,
            workspace_dependency_identities,
            topo_order,
            extra_args,
            env_mode,
            continue_on_error,
            no_cache,
            tasks,
            lpm_config,
            super::format::TaskOutputPolicy::nested(json_output),
            bin_hint,
            Some(&member_task_config.package_scripts),
            initially_failed_tasks,
            session,
        )
    }
}

/// Effective dependency DAG across workspace members.
///
/// Stores the original O(V + E) graph and propagates readiness immediately
/// through non-runnable intermediate members so a runnable member starts as
/// soon as its own runnable ancestors finish without expanding transitive
/// bridges into quadratic edge lists.
struct RunnableWorkspaceDag {
    runnable: Vec<bool>,
    remaining_deps: Vec<usize>,
    dependents: Vec<Vec<usize>>,
}

impl RunnableWorkspaceDag {
    fn from_graph(ws_graph: &lpm_task::graph::WorkspaceGraph, runnable: &[bool]) -> Self {
        Self::from_edges(&ws_graph.edges, runnable)
    }

    fn from_edges(edges: &[Vec<usize>], runnable: &[bool]) -> Self {
        let count = edges.len();
        let mut remaining_deps = vec![0usize; count];
        let mut dependents = vec![Vec::new(); count];
        let mut seen_epoch = vec![0u32; count];
        let mut epoch = 0u32;
        for (member_idx, deps) in edges.iter().enumerate() {
            epoch = epoch.wrapping_add(1);
            if epoch == 0 {
                seen_epoch.fill(0);
                epoch = 1;
            }
            for &dep_idx in deps {
                if dep_idx < count && seen_epoch[dep_idx] != epoch {
                    seen_epoch[dep_idx] = epoch;
                    remaining_deps[member_idx] += 1;
                    dependents[dep_idx].push(member_idx);
                }
            }
        }
        Self {
            runnable: runnable.to_vec(),
            remaining_deps,
            dependents,
        }
    }

    fn release_node(
        &self,
        idx: usize,
        remaining: &mut [usize],
        ready_runnable: &mut std::collections::BTreeSet<usize>,
    ) {
        let mut zero_work_queue = vec![idx];
        while let Some(completed_idx) = zero_work_queue.pop() {
            for &dep_idx in &self.dependents[completed_idx] {
                remaining[dep_idx] -= 1;
                if remaining[dep_idx] == 0 {
                    if self.runnable[dep_idx] {
                        ready_runnable.insert(dep_idx);
                    } else {
                        zero_work_queue.push(dep_idx);
                    }
                }
            }
        }
    }

    fn initial_ready(&self, remaining: &mut [usize]) -> std::collections::BTreeSet<usize> {
        let mut ready_runnable = std::collections::BTreeSet::new();
        let mut zero_work_roots = Vec::new();
        for (idx, &is_runnable) in self.runnable.iter().enumerate() {
            if remaining[idx] == 0 {
                if is_runnable {
                    ready_runnable.insert(idx);
                } else {
                    zero_work_roots.push(idx);
                }
            }
        }
        for root in zero_work_roots {
            self.release_node(root, remaining, &mut ready_runnable);
        }
        ready_runnable
    }

    fn is_linear_chain(&self) -> bool {
        let mut remaining = self.remaining_deps.clone();
        let mut ready = self.initial_ready(&mut remaining);
        while let Some(idx) = ready.pop_first() {
            if !ready.is_empty() {
                return false;
            }
            self.release_node(idx, &mut remaining, &mut ready);
        }
        true
    }

    fn execute_parallel<S, T, F, Prep, Done>(
        &self,
        workspace_concurrency: usize,
        continue_on_error: bool,
        members: &[lpm_task::graph::GraphNode],
        state: &mut S,
        mut prepare: Prep,
        mut on_complete: Done,
    ) -> Result<(), LpmError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, LpmError> + Send + 'static,
        Prep: FnMut(usize, bool, &S) -> Result<F, LpmError>,
        Done: FnMut(usize, T, &mut S) -> bool,
    {
        let concurrency = workspace_concurrency.max(1);
        let mut remaining = self.remaining_deps.clone();
        let mut ready = self.initial_ready(&mut remaining);
        // Hard errors (env denial, worker error, panic) stop unstarted members
        // even under --no-bail while waiting for already-started members to finish.
        let stop_requested = Arc::new(AtomicBool::new(false));
        let mut failed = false;
        let mut first_error: Option<LpmError> = None;

        std::thread::scope(|scope| {
            let (tx, rx) =
                std::sync::mpsc::channel::<(usize, std::thread::Result<Result<T, LpmError>>)>();
            let mut handles: HashMap<usize, std::thread::ScopedJoinHandle<'_, ()>> = HashMap::new();

            loop {
                while !stop_requested.load(Ordering::Acquire)
                    && (continue_on_error || !failed)
                    && handles.len() < concurrency
                    && let Some(idx) = ready.pop_first()
                {
                    let isolated = handles.is_empty() && ready.is_empty();
                    let job = match prepare(idx, isolated, state) {
                        Ok(job) => job,
                        Err(error) => {
                            stop_requested.store(true, Ordering::Release);
                            first_error.get_or_insert(error);
                            break;
                        }
                    };
                    let tx = tx.clone();
                    let worker_stop = Arc::clone(&stop_requested);
                    let handle = scope.spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                        if !matches!(&result, Ok(Ok(_))) {
                            worker_stop.store(true, Ordering::Release);
                        }
                        let _ = tx.send((idx, result));
                    });
                    handles.insert(idx, handle);
                }

                if handles.is_empty() {
                    break;
                }

                let Ok(first_completion) = rx.recv() else {
                    break;
                };
                // Drain every already-queued completion before refilling slots
                // so a queued hard error stops pending dependents even when a
                // success message was queued just ahead of it.
                let mut completions = vec![first_completion];
                while let Ok(next) = rx.try_recv() {
                    completions.push(next);
                }

                for (idx, worker_result) in completions {
                    if let Some(handle) = handles.remove(&idx) {
                        let _ = handle.join();
                    }
                    match worker_result {
                        Ok(Ok(value)) => {
                            let succeeded = on_complete(idx, value, state);
                            if !succeeded {
                                failed = true;
                            }
                            if !stop_requested.load(Ordering::Acquire)
                                && (continue_on_error || !failed)
                            {
                                self.release_node(idx, &mut remaining, &mut ready);
                            }
                        }
                        Ok(Err(error)) => {
                            stop_requested.store(true, Ordering::Release);
                            first_error.get_or_insert(error);
                        }
                        Err(_) => {
                            stop_requested.store(true, Ordering::Release);
                            first_error.get_or_insert_with(|| {
                                LpmError::Task(format!(
                                    "workspace task thread panicked for '{}'",
                                    members[idx].name
                                ))
                            });
                        }
                    }
                }
            }
        });

        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_members(names: &[&str]) -> Vec<lpm_task::graph::GraphNode> {
        names
            .iter()
            .map(|name| lpm_task::graph::GraphNode {
                name: (*name).to_string(),
                path: std::path::PathBuf::from(name),
            })
            .collect()
    }

    #[test]
    fn dag_scheduler_starts_dependent_before_unrelated_slow_peer_finishes() {
        // Graph: 0 (fast-lib), 1 (slow-lib), 2 (app -> depends on 0 only).
        let edges = vec![vec![], vec![], vec![0]];
        let runnable = vec![true, true, true];
        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        assert!(!dag.is_linear_chain());

        let members = test_members(&["fast-lib", "slow-lib", "app"]);
        let (slow_started_tx, slow_started_rx) = std::sync::mpsc::channel();
        let slow_started_rx = Arc::new(std::sync::Mutex::new(slow_started_rx));
        let (app_done_tx, app_done_rx) = std::sync::mpsc::channel();
        let app_done_rx = Arc::new(std::sync::Mutex::new(app_done_rx));
        let finished = Arc::new(std::sync::Mutex::new(Vec::new()));
        let peak = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicUsize::new(0));

        dag.execute_parallel(
            2,
            false,
            &members,
            &mut (),
            |idx, isolated, ()| {
                assert!(!isolated || idx == 2);
                let slow_started_tx = slow_started_tx.clone();
                let slow_started_rx = Arc::clone(&slow_started_rx);
                let app_done_tx = app_done_tx.clone();
                let app_done_rx = Arc::clone(&app_done_rx);
                let finished = Arc::clone(&finished);
                let peak = Arc::clone(&peak);
                let running = Arc::clone(&running);
                Ok(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    if idx == 1 {
                        slow_started_tx.send(()).unwrap();
                        app_done_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .expect("app must complete while slow-lib is still running");
                    } else if idx == 0 {
                        slow_started_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .expect("slow-lib must start concurrently with fast-lib");
                    }
                    finished.lock().unwrap().push(idx);
                    running.fetch_sub(1, Ordering::SeqCst);
                    if idx == 2 {
                        app_done_tx.send(()).unwrap();
                    }
                    Ok(idx)
                })
            },
            |_idx, _val, ()| true,
        )
        .unwrap();

        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(*finished.lock().unwrap(), vec![0, 2, 1]);
    }

    #[test]
    fn dag_scheduler_preserves_transitive_order_through_non_runnable_member() {
        // Graph: 0 (runnable) <- 1 (non-runnable) <- 2 (runnable)
        let edges = vec![vec![], vec![0], vec![1]];
        let runnable = vec![true, false, true];
        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        assert!(dag.is_linear_chain());
        let members = test_members(&["lib", "skip", "app"]);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        dag.execute_parallel(
            2,
            false,
            &members,
            &mut (),
            |idx, isolated, ()| {
                assert!(isolated, "linear chain member {idx} must be isolated");
                let order = Arc::clone(&order);
                Ok(move || {
                    order.lock().unwrap().push(idx);
                    Ok(idx)
                })
            },
            |_idx, _val, ()| true,
        )
        .unwrap();
        assert_eq!(*order.lock().unwrap(), vec![0, 2]);
    }

    #[test]
    fn dag_scheduler_keeps_linear_edge_storage_for_shared_non_runnable_bridge() {
        // 100 producers -> 1 non-runnable bridge -> 100 consumers (200 edges, not 10,000).
        let producers = 100usize;
        let bridge = producers;
        let consumers = 100usize;
        let total = producers + 1 + consumers;
        let mut edges = vec![Vec::new(); total];
        edges[bridge] = (0..producers).collect();
        for edge in &mut edges[(bridge + 1)..total] {
            *edge = vec![bridge];
        }
        let mut runnable = vec![true; total];
        runnable[bridge] = false;

        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        let stored_edges: usize = dag.dependents.iter().map(Vec::len).sum();
        assert_eq!(stored_edges, producers + consumers);
    }

    #[test]
    fn dag_scheduler_marks_fan_in_final_member_as_isolated() {
        // 0 (a), 1 (b), 2 (app depends on 0 and 1).
        let edges = vec![vec![], vec![], vec![0, 1]];
        let runnable = vec![true, true, true];
        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        let members = test_members(&["a", "b", "app"]);
        let isolated_seen = Arc::new(std::sync::Mutex::new(HashMap::new()));

        dag.execute_parallel(
            2,
            false,
            &members,
            &mut (),
            |idx, isolated, ()| {
                isolated_seen.lock().unwrap().insert(idx, isolated);
                Ok(move || Ok(idx))
            },
            |_idx, _val, ()| true,
        )
        .unwrap();

        let map = isolated_seen.lock().unwrap();
        assert_eq!(map.get(&0), Some(&false));
        assert_eq!(map.get(&2), Some(&true));
    }

    #[test]
    fn dag_scheduler_stops_pending_dependents_on_queued_hard_error_even_with_no_bail() {
        // 0 (succeeds), 1 (hard Err), 2 (depends on 0).
        let edges = vec![vec![], vec![], vec![0]];
        let runnable = vec![true, true, true];
        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        let members = test_members(&["ok", "fatal", "dep"]);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let started = Arc::new(std::sync::Mutex::new(Vec::new()));

        let err = dag
            .execute_parallel(
                2,
                true, // --no-bail
                &members,
                &mut (),
                |idx, _isolated, ()| {
                    started.lock().unwrap().push(idx);
                    let barrier = Arc::clone(&barrier);
                    Ok(move || {
                        if idx == 0 {
                            barrier.wait();
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            Ok(idx)
                        } else if idx == 1 {
                            barrier.wait();
                            Err(LpmError::Task("fatal env error".into()))
                        } else {
                            Ok(idx)
                        }
                    })
                },
                |_idx, _val, ()| true,
            )
            .unwrap_err();

        assert!(err.to_string().contains("fatal env error"));
        assert!(!started.lock().unwrap().contains(&2));
    }

    #[test]
    fn dag_scheduler_starts_ready_members_in_workspace_order_with_concurrency_one() {
        let edges = vec![vec![], vec![], vec![], vec![]];
        let runnable = vec![true, true, true, true];
        let dag = RunnableWorkspaceDag::from_edges(&edges, &runnable);
        let members = test_members(&["a", "b", "c", "d"]);
        let started = Arc::new(std::sync::Mutex::new(Vec::new()));

        dag.execute_parallel(
            1,
            false,
            &members,
            &mut (),
            |idx, _isolated, ()| {
                let started = Arc::clone(&started);
                Ok(move || {
                    started.lock().unwrap().push(idx);
                    Ok(idx)
                })
            },
            |_idx, _val, ()| true,
        )
        .unwrap();

        assert_eq!(*started.lock().unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn workspace_plan_retains_only_direct_upstream_task_references() {
        let upstream = WorkspaceTaskRef {
            member_idx: 2,
            task_name: "build".into(),
        };
        let direct = HashMap::from([("build".into(), HashSet::from([upstream.clone()]))]);

        let dependencies = sort_direct_workspace_task_dependencies(direct);

        assert_eq!(dependencies.get("build"), Some(&vec![upstream]));
        assert!(!dependencies.contains_key("deploy"));
    }
}
