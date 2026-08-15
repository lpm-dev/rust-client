use super::format::{format_run_failure_detail, format_workspace_member_scripts_header};
use super::parallel::run_tasks_parallel;
use super::runtime::{ensure_runtime, validate_runtime_with_cache};
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

struct WorkspaceMemberTaskPlan {
    config: WorkspaceMemberTaskConfig,
    requested_tasks: Vec<String>,
    task_levels: Vec<Vec<String>>,
    upstream_member_dependencies: Vec<usize>,
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
    let mut upstream_member_dependencies: Vec<HashSet<usize>> =
        (0..member_count).map(|_| HashSet::new()).collect();
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
                for &upstream_idx in &workspace_graph.edges[member_idx] {
                    upstream_member_dependencies[member_idx].insert(upstream_idx);
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
                            "task '{}:{task_name}' requires '^{upstream_task}', but workspace dependency '{}' does not define task '{upstream_task}'",
                            workspace_graph.members[member_idx].name,
                            workspace_graph.members[upstream_idx].name
                        )));
                    }
                    if scheduled_names[upstream_idx].insert(upstream_task.to_string()) {
                        scheduled_tasks[upstream_idx].push(upstream_task.to_string());
                    }
                    pending.push_back((upstream_idx, upstream_task.to_string()));
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
        let mut upstream_member_dependencies: Vec<_> =
            upstream_member_dependencies[member_idx].drain().collect();
        upstream_member_dependencies.sort_unstable();
        plans.push(Some(Arc::new(WorkspaceMemberTaskPlan {
            config,
            requested_tasks,
            task_levels,
            upstream_member_dependencies,
        })));
    }

    Ok(plans)
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

    let package_scripts: Vec<HashMap<String, String>> = workspace
        .members
        .into_iter()
        .map(|member| member.package.scripts)
        .collect();
    let member_task_plans =
        build_workspace_task_schedule(&ws_graph, package_scripts, &target_set, scripts)?;
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
            validate_runtime_with_cache(
                member_dir,
                member_runtime_hints[idx].as_ref(),
                json_output,
                &mut node_versions,
            )?;
        } else {
            validate_runtime_with_cache(
                member_dir,
                root_hint.as_ref(),
                json_output,
                &mut node_versions,
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
    let mut failed_members = HashSet::new();

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

        let mut level_targets = Vec::with_capacity(scheduled_level_targets.len());
        for idx in scheduled_level_targets {
            let member_task_plan = member_task_plans[idx].as_ref().ok_or_else(|| {
                LpmError::Script(format!(
                    "internal task plan missing for workspace member '{}'",
                    ws_graph.members[idx].name
                ))
            })?;
            if member_task_plan
                .upstream_member_dependencies
                .iter()
                .any(|dependency| failed_members.contains(dependency))
            {
                failed_members.insert(idx);
                install_ui::detail_line(format_run_failure_detail(
                    &ws_graph.members[idx].name,
                    "skipped because an upstream task dependency failed",
                ));
            } else {
                level_targets.push(idx);
            }
        }
        if level_targets.is_empty() {
            continue;
        }

        // Single package in level → no thread overhead
        if level_targets.len() == 1 {
            let idx = level_targets[0];
            let member_task_plan = member_task_plans[idx].as_ref().ok_or_else(|| {
                LpmError::Script(format!(
                    "internal task plan missing for workspace member '{}'",
                    ws_graph.members[idx].name
                ))
            })?;
            let ok = run_workspace_package(
                &ws_graph.members[idx].path,
                &ws_graph.members[idx].name,
                extra_args,
                env_mode,
                no_cache,
                parallel,
                continue_on_error,
                stream,
                member_runtime_hints[idx].as_ref(),
                member_task_plan,
            );
            if ok {
                succeeded.fetch_add(1, Ordering::Relaxed);
            } else {
                failed_members.insert(idx);
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
                        let member_runtime_hint = Arc::clone(&member_runtime_hints[idx]);
                        let member_task_plan = member_task_plans[idx]
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| {
                                LpmError::Script(format!(
                                    "internal task plan missing for workspace member '{member_name}'"
                                ))
                            })?;

                        Ok((idx, std::thread::spawn(move || {
                            run_workspace_package(
                                &member_dir,
                                &member_name,
                                &args_owned,
                                mode_owned.as_deref(),
                                no_cache,
                                parallel,
                                continue_on_error,
                                stream,
                                member_runtime_hint.as_ref(),
                                member_task_plan.as_ref(),
                            )
                        })))
                    })
                    .collect::<Result<_, _>>()?;

                for (idx, handle) in handles {
                    match handle.join() {
                        Ok(true) => {
                            succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {
                            failed_members.insert(idx);
                            failed_flag.store(true, Ordering::Relaxed);
                        }
                        Err(_) => {
                            install_ui::detail_line(format_run_failure_detail(
                                "workspace task",
                                "panicked",
                            ));
                            failed_members.insert(idx);
                            failed_flag.store(true, Ordering::Relaxed);
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
    member_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    bin_hint: &ManagedRuntimeHint,
    member_task_plan: &WorkspaceMemberTaskPlan,
) -> bool {
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
        && !is_meta_task(
            &scripts[0],
            tasks,
            Some(&member_task_config.package_scripts),
        )
    {
        return match run_task(
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
    }

    let result = if parallel {
        run_tasks_parallel(
            member_dir,
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
        )
    };

    result.is_ok()
}
