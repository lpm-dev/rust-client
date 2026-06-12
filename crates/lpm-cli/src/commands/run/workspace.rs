use super::format::{format_run_failure_detail, format_workspace_member_scripts_header};
use super::parallel::run_tasks_parallel;
use super::runtime::ensure_runtime;
use super::sequential::run_tasks_sequential;
use super::task::{reject_direct_hidden_scripts, run_task};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
/// with pnpm-parity grammar. Bare names no longer substring-match; users must
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
    let root_hint = Arc::new(ensure_runtime(project_dir).await);

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
                install_ui::detail(&format!("  {}", install_ui::dim(line)));
            }
            install_ui::detail("");
        }
        return Ok(());
    }

    let total = target_set.len();
    let start = std::time::Instant::now();
    let succeeded = AtomicUsize::new(0);
    let failed_flag = AtomicBool::new(false);

    // Run workspace levels sequentially (respects inter-package deps),
    // packages within each level in parallel.
    for level in &levels {
        let level_targets: Vec<usize> = level
            .iter()
            .filter(|i| target_set.contains(i))
            .copied()
            .collect();

        if level_targets.is_empty() {
            continue;
        }

        if !continue_on_error && failed_flag.load(Ordering::Relaxed) {
            break;
        }

        // Single package in level → no thread overhead
        if level_targets.len() == 1 {
            let idx = level_targets[0];
            let ok = run_workspace_package(
                &ws_graph.members[idx].path,
                &ws_graph.members[idx].name,
                scripts,
                extra_args,
                env_mode,
                no_cache,
                parallel,
                continue_on_error,
                stream,
                &root_hint,
            );
            match ok {
                Some(true) => {
                    succeeded.fetch_add(1, Ordering::Relaxed);
                }
                Some(false) => {
                    failed_flag.store(true, Ordering::Relaxed);
                }
                None => {} // skipped (no scripts for this package)
            }
        } else {
            // Multiple packages in this level — run in parallel
            for chunk in level_targets.chunks(workspace_concurrency) {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&idx| {
                        let member_dir = ws_graph.members[idx].path.clone();
                        let member_name = ws_graph.members[idx].name.clone();
                        let scripts_owned: Vec<String> = scripts.to_vec();
                        let args_owned: Vec<String> = extra_args.to_vec();
                        let mode_owned = env_mode.map(|s| s.to_string());
                        let root_hint_clone = Arc::clone(&root_hint);

                        std::thread::spawn(move || {
                            run_workspace_package(
                                &member_dir,
                                &member_name,
                                &scripts_owned,
                                &args_owned,
                                mode_owned.as_deref(),
                                no_cache,
                                parallel,
                                continue_on_error,
                                stream,
                                &root_hint_clone,
                            )
                        })
                    })
                    .collect();

                for handle in handles {
                    match handle.join() {
                        Ok(Some(true)) => {
                            succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Some(false)) => {
                            failed_flag.store(true, Ordering::Relaxed);
                        }
                        Ok(None) => {} // skipped
                        Err(_) => {
                            install_ui::detail(&format_run_failure_detail(
                                "workspace task",
                                "panicked",
                            ));
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
        install_ui::done(&format!(
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
/// Returns `Some(true)` on success, `Some(false)` on failure, `None` if
/// the package was skipped (no matching scripts/tasks).
///
/// This is the per-package workhorse called from `run_workspace()`.
/// It runs synchronously so it can be spawned in threads for package-level
/// parallelism.
#[allow(clippy::too_many_arguments)]
fn run_workspace_package(
    member_dir: &Path,
    member_name: &str,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    root_hint: &ManagedRuntimeHint,
) -> Option<bool> {
    let pkg_json_path = member_dir.join("package.json");
    if !pkg_json_path.exists() {
        return None;
    }

    let pkg = match lpm_workspace::read_package_json(&pkg_json_path) {
        Ok(p) => p,
        Err(e) => {
            install_ui::detail(&format_run_failure_detail(member_name, e));
            return Some(false);
        }
    };

    // Check if any requested scripts exist (as scripts, commands, or meta-tasks)
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(member_dir)
        .ok()
        .flatten();
    let tasks = lpm_config
        .as_ref()
        .map(|c| c.tasks.clone())
        .unwrap_or_default();

    let has_any = scripts.iter().any(|s| {
        pkg.scripts.contains_key(s)
            || tasks
                .get(s)
                .is_some_and(|tc| tc.command.is_some() || !tc.depends_on.is_empty())
    });
    if !has_any {
        return None;
    }

    install_ui::detail("");
    install_ui::detail(&format_workspace_member_scripts_header(
        member_name,
        scripts,
    ));

    // Build per-package task graph
    let task_levels = match lpm_runner::task_graph::task_levels(&pkg.scripts, &tasks, scripts) {
        Ok(l) => l,
        Err(e) => {
            install_ui::detail(&format_run_failure_detail(member_name, e));
            return Some(false);
        }
    };

    let task_count: usize = task_levels.iter().map(|l| l.len()).sum();

    // If the member has its own Node.js version pin, let silent detection
    // resolve at the member level. Otherwise inherit the workspace-root hint.
    let bin_hint = if lpm_runtime::detect::detect_node_version(member_dir).is_some() {
        ManagedRuntimeHint::Unknown
    } else {
        root_hint.clone()
    };

    // Single task, no deps → simple run
    if task_count == 1 && scripts.len() == 1 {
        return match run_task(
            member_dir,
            &scripts[0],
            extra_args,
            env_mode,
            &tasks,
            &bin_hint,
        ) {
            Ok(()) => Some(true),
            Err(e) => {
                install_ui::detail(&format_run_failure_detail(member_name, e));
                Some(false)
            }
        };
    }

    // Use a tokio runtime for the async task executors (they're async in
    // signature but internally use OS threads for actual parallelism).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = if parallel {
        rt.block_on(run_tasks_parallel(
            member_dir,
            &task_levels,
            extra_args,
            env_mode,
            continue_on_error,
            stream,
            no_cache,
            &tasks,
            lpm_config.as_ref(),
            false,
            &bin_hint,
            Some(&pkg.scripts),
        ))
    } else {
        let topo_order: Vec<String> = task_levels.into_iter().flatten().collect();
        rt.block_on(run_tasks_sequential(
            member_dir,
            &topo_order,
            extra_args,
            env_mode,
            continue_on_error,
            no_cache,
            &tasks,
            lpm_config.as_ref(),
            false,
            &bin_hint,
            Some(&pkg.scripts),
        ))
    };

    Some(result.is_ok())
}
