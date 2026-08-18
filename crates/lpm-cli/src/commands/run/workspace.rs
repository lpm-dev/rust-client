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
                let mut expanded_edges = HashSet::new();
                while let Some((dependent_idx, dependent_task, upstream_idx)) =
                    upstream_edges.pop_front()
                {
                    if !expanded_edges.insert((dependent_idx, upstream_idx)) {
                        continue;
                    }
                    direct_upstream_task_dependencies[dependent_idx]
                        .entry(dependent_task.clone())
                        .or_default()
                        .insert(WorkspaceTaskRef {
                            member_idx: upstream_idx,
                            task_name: upstream_task.to_string(),
                        });
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
                    }
                    pending.push_back((upstream_idx, upstream_task.to_string()));
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
        let task_levels = lpm_runner::task_graph::task_levels(
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

    let workspace_contract = if no_cache {
        None
    } else {
        Some(WorkspaceCacheContract::capture(&workspace.root)?)
    };
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
    let mut node_versions = lpm_runtime::effective::PathNodeVersionCache::default();
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

    // Run workspace levels sequentially (respects inter-package deps),
    // packages within each level in parallel.
    for level in &levels {
        let scheduled_level_targets: Vec<usize> = level
            .iter()
            .filter(|i| runnable_members[**i])
            .copied()
            .collect();

        if scheduled_level_targets.is_empty() {
            continue;
        }

        if !continue_on_error && failed_flag.load(Ordering::Relaxed) {
            break;
        }

        let level_targets = scheduled_level_targets;

        // Single package in level → no thread overhead
        if level_targets.len() == 1 {
            let idx = level_targets[0];
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
            let report = run_workspace_package(
                &ws_graph.members[idx].path,
                workspace_contract.as_ref(),
                &ws_graph.members[idx].name,
                extra_args,
                env_mode,
                no_cache,
                parallel,
                continue_on_error,
                stream,
                member_runtime_hints[idx].as_ref(),
                member_task_plan,
                &workspace_dependency_identities,
                &initially_failed_tasks,
                session.clone(),
            )?;
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
        } else {
            // Multiple packages in this level — run in parallel
            for chunk in level_targets.chunks(workspace_concurrency) {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&idx| -> Result<_, LpmError> {
                        let member_dir = ws_graph.members[idx].path.clone();
                        let member_name = ws_graph.members[idx].name.clone();
                        let args_owned: Vec<String> = extra_args.to_vec();
                        let mode_owned = env_mode.map(|s| s.to_string());
                        let workspace_contract = workspace_contract.clone();
                        let session = session.clone();
                        let member_runtime_hint = Arc::clone(&member_runtime_hints[idx]);
                        let required_task_identities = required_task_identities[idx].clone();
                        let member_task_plan = member_task_plans[idx]
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| {
                                LpmError::Script(format!(
                                    "internal task plan missing for workspace member '{member_name}'"
                                ))
                            })?;
                        let workspace_dependency_identities =
                            resolve_workspace_dependency_identities(
                                member_task_plan.as_ref(),
                                &ws_graph,
                                &completed_task_identities,
                            );
                        let initially_failed_tasks = blocked_workspace_tasks(
                            member_task_plan.as_ref(),
                            &completed_task_states,
                        );

                        Ok((idx, std::thread::spawn(move || -> Result<_, LpmError> {
                            let report = run_workspace_package(
                                &member_dir,
                                workspace_contract.as_ref(),
                                &member_name,
                                &args_owned,
                                mode_owned.as_deref(),
                                no_cache,
                                parallel,
                                continue_on_error,
                                stream,
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
                        })))
                    })
                    .collect::<Result<_, _>>()?;

                for (idx, handle) in handles {
                    match handle.join() {
                        Ok(Ok((report, identities))) => {
                            completed_task_identities[idx] = identities;
                            completed_task_states[idx] = Some(report.task_states());
                            if report.is_successful() {
                                succeeded.fetch_add(1, Ordering::Relaxed);
                            } else {
                                failed_flag.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {
                            return Err(LpmError::Task(format!(
                                "workspace task thread panicked for '{}'",
                                ws_graph.members[idx].name
                            )));
                        }
                    }
                }

                if !continue_on_error && failed_flag.load(Ordering::Relaxed) {
                    break;
                }
            }
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
    if task_count == 1
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
            duration: start.elapsed(),
            cached: false,
            skipped: false,
        }]));
    }

    if parallel {
        run_tasks_parallel(
            member_dir,
            workspace_contract,
            workspace_dependency_identities,
            &member_task_plan.task_levels,
            extra_args,
            env_mode,
            continue_on_error,
            stream,
            no_cache,
            tasks,
            lpm_config,
            false,
            bin_hint,
            Some(&member_task_config.package_scripts),
            initially_failed_tasks,
            session,
        )
    } else {
        let topo_order: Vec<String> = member_task_plan
            .task_levels
            .iter()
            .flatten()
            .cloned()
            .collect();
        run_tasks_sequential(
            member_dir,
            workspace_contract,
            workspace_dependency_identities,
            &topo_order,
            extra_args,
            env_mode,
            continue_on_error,
            no_cache,
            tasks,
            lpm_config,
            false,
            bin_hint,
            Some(&member_task_config.package_scripts),
            initially_failed_tasks,
            session,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
