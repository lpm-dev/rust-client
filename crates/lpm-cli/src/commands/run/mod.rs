mod cache;
mod format;
mod parallel;
mod runtime;
mod sequential;
mod single;
mod task;
mod workspace;

use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::Path;

use crate::install_ui;

pub use runtime::ensure_runtime;
pub use single::{dlx, exec, run, run_watch};
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
) -> Result<(), LpmError> {
    let bin_hint = ensure_runtime(project_dir).await;

    if scripts.is_empty() {
        install_ui::warn("No scripts specified. Usage: lpm run <script> [scripts...]");
        return Ok(());
    }
    reject_direct_hidden_scripts(scripts)?;

    // Read lpm.json for task dependencies
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let tasks = lpm_config
        .as_ref()
        .map(|c| c.tasks.clone())
        .unwrap_or_default();

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
    for (name, task) in &tasks {
        if let Some(cmd) = &task.command {
            all_scripts
                .entry(name.clone())
                .or_insert_with(|| cmd.clone());
        }
    }

    // Always build task graph — expand dependsOn for all scripts, even single ones.
    // This is the core contract: `lpm run test` auto-runs `check` if
    // test.dependsOn includes "check".
    let levels = lpm_runner::task_graph::task_levels(&all_scripts, &tasks, scripts)
        .map_err(LpmError::Script)?;

    let total_tasks: usize = levels.iter().map(|l| l.len()).sum();

    // Fast path: single task with no dependencies — delegate to simple runner
    if total_tasks == 1 && scripts.len() == 1 && !json_output {
        return run(
            project_dir,
            &scripts[0],
            extra_args,
            env_mode,
            no_cache,
            &bin_hint,
        )
        .await;
    }

    if parallel {
        // Parallel: run independent tasks concurrently within each level
        run_tasks_parallel(
            project_dir,
            &levels,
            extra_args,
            env_mode,
            continue_on_error,
            stream,
            no_cache,
            &tasks,
            lpm_config.as_ref(),
            json_output,
            &bin_hint,
            pkg_scripts.as_ref(),
        )
        .await
    } else {
        // Sequential: run tasks in topological order (deps before dependents)
        let topo_order: Vec<String> = levels.into_iter().flatten().collect();
        run_tasks_sequential(
            project_dir,
            &topo_order,
            extra_args,
            env_mode,
            continue_on_error,
            no_cache,
            &tasks,
            lpm_config.as_ref(),
            json_output,
            &bin_hint,
            pkg_scripts.as_ref(),
        )
        .await
    }
}

#[cfg(test)]
mod tests;
