use super::cache::{
    CacheStoreRequest, is_task_cached_with_config, try_cache_hit_with_config,
    try_cache_store_with_output_and_config,
};
use super::format::{
    TaskResult, print_captured_stderr, print_captured_stdout, print_json_summary,
    print_results_summary, print_task_result,
};
use super::task::{is_meta_task, run_task, run_task_captured};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub(super) fn run_tasks_sequential(
    project_dir: &Path,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    continue_on_error: bool,
    no_cache: bool,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    json_output: bool,
    bin_hint: &ManagedRuntimeHint,
    pkg_scripts: Option<&HashMap<String, String>>,
) -> Result<(), LpmError> {
    let mut results: Vec<TaskResult> = Vec::with_capacity(scripts.len());
    let total_start = std::time::Instant::now();
    let mut failed_tasks: HashSet<String> = HashSet::new();

    for (idx, script) in scripts.iter().enumerate() {
        // Skip tasks whose dependencies failed (topological order means deps
        // were already processed)
        let deps_failed = if let Some(tc) = tasks.get(script.as_str()) {
            tc.depends_on
                .iter()
                .filter(|d| !d.starts_with('^'))
                .any(|d| failed_tasks.contains(d.as_str()))
        } else {
            false
        };

        if deps_failed {
            results.push(TaskResult {
                name: script.clone(),
                success: false,
                duration: std::time::Duration::ZERO,
                cached: false,
                skipped: true,
            });
            print_task_result(results.last().unwrap());
            failed_tasks.insert(script.clone());
            continue;
        }

        // Meta-task: has dependsOn but no command and no package.json script.
        // All deps completed successfully (checked above), so the meta-task succeeds.
        let is_meta_task = is_meta_task(script, tasks, pkg_scripts);
        if is_meta_task {
            let start = std::time::Instant::now();
            results.push(TaskResult {
                name: script.clone(),
                success: true,
                duration: start.elapsed(),
                cached: false,
                skipped: false,
            });
            print_task_result(results.last().unwrap());
            continue;
        }

        let start = std::time::Instant::now();

        // Check cache
        if !no_cache
            && let Ok(Some(hit)) = try_cache_hit_with_config(
                project_dir,
                script,
                env_mode,
                extra_args,
                bin_hint,
                lpm_config,
            )
        {
            if !hit.stdout.is_empty() {
                print_captured_stdout(&hit.stdout);
            }
            if !hit.stderr.is_empty() {
                print_captured_stderr(&hit.stderr);
            }
            results.push(TaskResult {
                name: script.clone(),
                success: true,
                duration: start.elapsed(),
                cached: true,
                skipped: false,
            });
            print_task_result(results.last().unwrap());
            continue;
        }

        install_ui::phase_untrusted(&format!(
            "Running {}",
            lpm_common::sanitize_terminal_inline(script)
        ));

        let caching_enabled = !no_cache && is_task_cached_with_config(script, lpm_config);
        let task_start = std::time::Instant::now();

        // Resolve command: lpm.json task command > package.json script
        let run_result = if caching_enabled {
            match run_task_captured(project_dir, script, extra_args, env_mode, tasks, bin_hint) {
                Ok(captured) => {
                    let duration_ms = task_start.elapsed().as_millis() as u64;
                    let _ = try_cache_store_with_output_and_config(CacheStoreRequest {
                        project_dir,
                        script_name: script,
                        env_mode,
                        extra_args,
                        bin_hint,
                        duration_ms,
                        stdout: &captured.stdout,
                        stderr: &captured.stderr,
                        lpm_config,
                    });
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            run_task(project_dir, script, extra_args, env_mode, tasks, bin_hint)
        };

        match run_result {
            Ok(()) => {
                results.push(TaskResult {
                    name: script.clone(),
                    success: true,
                    duration: start.elapsed(),
                    cached: false,
                    skipped: false,
                });
                print_task_result(results.last().unwrap());
            }
            Err(_) => {
                results.push(TaskResult {
                    name: script.clone(),
                    success: false,
                    duration: start.elapsed(),
                    cached: false,
                    skipped: false,
                });
                print_task_result(results.last().unwrap());
                failed_tasks.insert(script.clone());

                if !continue_on_error {
                    // Mark remaining scripts as skipped
                    for remaining in &scripts[idx + 1..] {
                        results.push(TaskResult {
                            name: remaining.clone(),
                            success: false,
                            duration: std::time::Duration::ZERO,
                            cached: false,
                            skipped: true,
                        });
                        print_task_result(results.last().unwrap());
                    }
                    // Don't early-return with the raw script error — fall
                    // through to the aggregate failure-count exit path so
                    // the exit code reflects the task-runner contract.
                    break;
                }
            }
        }
    }

    print_results_summary(&results, total_start.elapsed());

    let failure_count = results.iter().filter(|r| !r.success && !r.skipped).count();
    if failure_count > 0 {
        if json_output {
            print_json_summary(&results, total_start.elapsed());
        }
        Err(LpmError::ExitCode(failure_count as i32))
    } else {
        if json_output {
            print_json_summary(&results, total_start.elapsed());
        }
        Ok(())
    }
}
