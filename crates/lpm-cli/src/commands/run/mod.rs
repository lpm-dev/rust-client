mod cache;
mod dlx;
mod dlx_policy;
mod format;
mod parallel;
mod runtime;
mod sequential;
mod single;
pub(crate) use single::run_with_reserved_stdout;
mod task;
mod workspace;

use lpm_common::LpmError;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::install_ui;

pub use dlx::{DlxOptions, dlx, managed_dlx};
pub(crate) use runtime::validate_runtime_with_cache;
pub use runtime::{ensure_detected_runtimes, ensure_runtime, prepare_runtime};
pub use single::{exec, run, run_file, run_file_watch, run_watch};
pub use workspace::run_workspace;

use parallel::run_tasks_parallel;
use sequential::run_tasks_sequential;
use task::reject_direct_hidden_scripts;

/// Run scripts in a single package, with task dependency enforcement.
///
/// Always builds a task dependency graph from lpm.json, expanding `dependsOn`
/// prerequisites even for single-script invocations. When `parallel` is true,
/// independent tasks run concurrently; otherwise they run in topological order.
///
/// Supports `--no-bail` to keep running after failures, `--stream` for
/// interleaved output with task prefixes, and
/// `--no-cache` to skip task caching.
#[allow(clippy::too_many_arguments)]
pub async fn run_multi(
    project_dir: &Path,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    no_cache: bool,
    json_output: bool,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    let bin_hint = prepare_runtime(project_dir, json_output).await?;

    if scripts.is_empty() {
        install_ui::warn("No scripts specified. Usage: lpm run <script> [scripts...]");
        return Ok(());
    }
    reject_direct_hidden_scripts(scripts)?;

    let plan = prepare_single_package_task_plan(project_dir, scripts)?;
    let tasks = plan.tasks();
    let levels = &plan.levels;

    let total_tasks: usize = levels.iter().map(|l| l.len()).sum();

    // Fast path: single task with no dependencies — delegate to simple runner
    let has_lpm_task_command = scripts.first().is_some_and(|script| {
        tasks
            .get(script)
            .and_then(|task| task.command.as_ref())
            .is_some()
    });
    if total_tasks == 1 && scripts.len() == 1 && !json_output && !stream && !has_lpm_task_command {
        return run(
            project_dir,
            &scripts[0],
            extra_args,
            env_mode,
            no_cache,
            &bin_hint,
            session,
        )
        .await;
    }

    let report = execute_single_package_task_plan(
        project_dir,
        &plan,
        extra_args,
        env_mode,
        TaskExecutionOptions {
            parallel,
            continue_on_error,
            stream,
            no_cache,
            json_output,
        },
        &bin_hint,
        session,
    )?;
    if total_tasks == 1 && scripts.len() == 1 {
        report.into_single_result()
    } else {
        report.into_result()
    }
}

struct SinglePackageTaskPlan {
    config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
    package_scripts: Option<HashMap<String, String>>,
    levels: Vec<Vec<String>>,
}

impl SinglePackageTaskPlan {
    fn tasks(&self) -> &HashMap<String, lpm_runner::lpm_json::TaskConfig> {
        static EMPTY: std::sync::OnceLock<HashMap<String, lpm_runner::lpm_json::TaskConfig>> =
            std::sync::OnceLock::new();
        self.config
            .as_ref()
            .map_or_else(|| EMPTY.get_or_init(HashMap::new), |config| &config.tasks)
    }
}

fn prepare_single_package_task_plan(
    project_dir: &Path,
    scripts: &[String],
) -> Result<SinglePackageTaskPlan, LpmError> {
    reject_direct_hidden_scripts(scripts)?;
    // Read lpm.json for task dependencies
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    let empty_tasks = HashMap::new();
    let tasks = lpm_config
        .as_ref()
        .map_or(&empty_tasks, |config| &config.tasks);

    // Collect all known scripts: package.json scripts + lpm.json task commands.
    // This supports pure lpm.json projects without package.json.
    //
    // `pkg_scripts` is kept separately so `is_meta_task` can distinguish
    // package.json scripts from lpm.json commands without re-reading
    // package.json per task.
    let pkg_scripts: Option<HashMap<String, String>> = {
        let pkg_json_path = project_dir.join("package.json");
        if pkg_json_path.exists() {
            lpm_workspace::read_package_json(&pkg_json_path)
                .ok()
                .map(|p| p.scripts)
        } else {
            None
        }
    };

    let mut all_scripts: HashMap<String, String> = pkg_scripts.clone().unwrap_or_default();

    // Add lpm.json task commands (don't override package.json scripts)
    for (name, task) in tasks {
        if let Some(cmd) = &task.command {
            all_scripts
                .entry(name.clone())
                .or_insert_with(|| cmd.clone());
        }
    }

    // Always build task graph — expand dependsOn for all scripts, even single ones.
    // This is the core contract: `lpm run test` auto-runs `check` if
    // test.dependsOn includes "check".
    let levels = lpm_runner::task_graph::task_levels(&all_scripts, tasks, scripts)
        .map_err(LpmError::Script)?;
    for name in levels.iter().flatten() {
        if let Some(task) = tasks.get(name)
            && let Some(dependency) = task.depends_on.iter().find(|dep| dep.starts_with('^'))
        {
            return Err(LpmError::Script(format!(
                "task '{name}' requires workspace dependency '{dependency}'; use --filter or --all to select workspace tasks"
            )));
        }
    }

    Ok(SinglePackageTaskPlan {
        config: lpm_config,
        package_scripts: pkg_scripts,
        levels,
    })
}

#[derive(Clone, Copy)]
struct TaskExecutionOptions {
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    no_cache: bool,
    json_output: bool,
}

fn execute_single_package_task_plan(
    project_dir: &Path,
    plan: &SinglePackageTaskPlan,
    extra_args: &[String],
    env_mode: Option<&str>,
    options: TaskExecutionOptions,
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<format::TaskRunReport, LpmError> {
    let TaskExecutionOptions {
        parallel,
        continue_on_error,
        stream,
        no_cache,
        json_output,
    } = options;
    let tasks = plan.tasks();
    let lpm_config = plan.config.as_ref();
    let pkg_scripts = plan.package_scripts.as_ref();
    let levels = &plan.levels;
    let workspace_dependency_identities = HashMap::new();
    let initially_failed_tasks = HashSet::new();
    let report = if parallel || stream {
        let serial_levels;
        let execution_levels = if parallel {
            levels
        } else {
            serial_levels = levels
                .iter()
                .flatten()
                .cloned()
                .map(|task| vec![task])
                .collect::<Vec<_>>();
            &serial_levels
        };
        // Parallel: run independent tasks concurrently within each level
        run_tasks_parallel(
            project_dir,
            None,
            &workspace_dependency_identities,
            execution_levels,
            extra_args,
            env_mode,
            continue_on_error,
            stream,
            no_cache,
            tasks,
            lpm_config,
            format::TaskOutputPolicy::standalone(json_output),
            bin_hint,
            pkg_scripts,
            &initially_failed_tasks,
            session,
        )
    } else {
        // Sequential: run tasks in topological order (deps before dependents)
        let topo_order: Vec<String> = levels.iter().flatten().cloned().collect();
        run_tasks_sequential(
            project_dir,
            None,
            &workspace_dependency_identities,
            &topo_order,
            extra_args,
            env_mode,
            continue_on_error,
            no_cache,
            tasks,
            lpm_config,
            format::TaskOutputPolicy::standalone(json_output),
            bin_hint,
            pkg_scripts,
            &initially_failed_tasks,
            session,
        )
    }?;
    Ok(report)
}

/// Run an unknown top-level command as a script/task shortcut, then as a
/// project-local binary shorthand when no script/task surface exists.
pub async fn run_external_shortcut(
    project_dir: &Path,
    args: &[String],
    json_output: bool,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    let Some(command_name) = args.first() else {
        return Ok(());
    };
    let extra_args = if args.len() > 1 { &args[1..] } else { &[] };

    if script_or_task_exists(project_dir, command_name)? {
        return run_multi(
            project_dir,
            std::slice::from_ref(command_name),
            extra_args,
            None,
            false,
            false,
            false,
            false,
            json_output,
            session,
        )
        .await;
    }

    if !lpm_runner::script::local_bin_exists(project_dir, command_name) {
        return Err(missing_external_shortcut_error(command_name));
    }

    let bin_hint = prepare_runtime(project_dir, json_output).await?;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Executing {}",
        install_ui::yellow(command_name)
    ));
    let start = std::time::Instant::now();
    lpm_runner::script::run_local_bin(
        project_dir,
        command_name,
        extra_args,
        None,
        false,
        &bin_hint,
    )?;
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · exited 0 in {}",
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

fn script_or_task_exists(project_dir: &Path, name: &str) -> Result<bool, LpmError> {
    let pkg_scripts = {
        let pkg_json_path = project_dir.join("package.json");
        if pkg_json_path.exists() {
            Some(
                lpm_workspace::read_package_json(&pkg_json_path)
                    .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?
                    .scripts,
            )
        } else {
            None
        }
    };
    if pkg_scripts
        .as_ref()
        .is_some_and(|scripts| scripts.contains_key(name))
    {
        return Ok(true);
    }

    let Some(config) =
        lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?
    else {
        return Ok(false);
    };
    let Some(task) = config.tasks.get(name) else {
        return Ok(false);
    };

    Ok(task.command.is_some() || !task.depends_on.is_empty())
}

fn missing_external_shortcut_error(command_name: &str) -> LpmError {
    LpmError::Script(format!(
        "command '{command_name}' was not found as a package.json script, lpm.json task, or project-local binary in node_modules/.bin"
    ))
}

#[cfg(test)]
mod tests;
