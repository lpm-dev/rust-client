use super::cache::{
    CacheStoreRequest, is_task_cached_with_config, try_cache_hit_with_config,
    try_cache_store_with_output_and_config,
};
use super::format::{
    TaskResult, format_failed_task_output_footer, format_failed_task_output_header,
    format_run_failure_detail, print_captured_stderr, print_captured_stdout, print_json_summary,
    print_results_summary, print_task_result,
};
use super::task::{is_meta_task, run_task, run_task_captured};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

pub(super) const MAX_CAPTURED_OUTPUT: usize = 10 * 1024 * 1024;

/// Truncate captured output if it exceeds `MAX_CAPTURED_OUTPUT`, cutting at
/// the last newline boundary to avoid splitting a line.
pub(super) fn truncate_output(output: String) -> String {
    if output.len() > MAX_CAPTURED_OUTPUT {
        let truncated = &output[..MAX_CAPTURED_OUTPUT];
        let end = truncated.rfind('\n').unwrap_or(MAX_CAPTURED_OUTPUT);
        format!(
            "{}...\n\n[output truncated at {}MB]",
            &output[..end],
            MAX_CAPTURED_OUTPUT / (1024 * 1024),
        )
    } else {
        output
    }
}

/// ANSI color codes for task prefixes in streaming mode.
const TASK_COLORS: &[&str] = &["36", "33", "35", "32", "34", "31"];

#[allow(clippy::too_many_arguments)]
pub(super) fn run_tasks_parallel(
    project_dir: &Path,
    levels: &[Vec<String>],
    extra_args: &[String],
    env_mode: Option<&str>,
    continue_on_error: bool,
    stream: bool,
    no_cache: bool,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    json_output: bool,
    bin_hint: &ManagedRuntimeHint,
    pkg_scripts: Option<&HashMap<String, String>>,
) -> Result<(), LpmError> {
    let total_start = std::time::Instant::now();
    let mut all_results: Vec<TaskResult> = Vec::new();
    let mut failed_tasks: HashSet<String> = HashSet::new();

    // Show execution plan when there's parallelism
    let total_tasks: usize = levels.iter().map(|l| l.len()).sum();
    if levels.len() > 1 || levels.first().map_or(0, |l| l.len()) > 1 {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Running {} tasks {}",
            install_ui::yellow(&total_tasks.to_string()),
            install_ui::dim(&format!("({} parallel groups)", levels.len()))
        ));
        install_ui::detail("");
    }

    // Shared per-call state is allocated once and cloned into workers with
    // cheap refcount bumps instead of deep HashMap/config clones.
    let hint_arc = Arc::new(bin_hint.clone());
    let tasks_arc = Arc::new(tasks.clone());
    let config_arc = lpm_config.cloned().map(Arc::new);
    let pkg_scripts_arc = pkg_scripts.cloned().map(Arc::new);

    let mut color_idx = 0usize;

    for level in levels {
        // Filter out tasks whose dependencies have failed
        let runnable: Vec<&String> = level
            .iter()
            .filter(|task| {
                if let Some(tc) = tasks.get(task.as_str()) {
                    let deps_failed = tc
                        .depends_on
                        .iter()
                        .filter(|d| !d.starts_with('^'))
                        .any(|d| failed_tasks.contains(d));
                    !deps_failed
                } else {
                    !failed_tasks.contains(task.as_str())
                }
            })
            .collect();

        // Mark non-runnable tasks as skipped AND add to failed_tasks
        // so that transitive dependents are also skipped.
        for task in level {
            if !runnable.contains(&task) {
                all_results.push(TaskResult {
                    name: task.clone(),
                    success: false,
                    duration: std::time::Duration::ZERO,
                    cached: false,
                    skipped: true,
                });
                print_task_result(all_results.last().unwrap());
                failed_tasks.insert(task.clone());
            }
        }

        if runnable.is_empty() {
            continue;
        }

        if runnable.len() == 1 {
            // Single task in this level — run directly (no thread overhead)
            let task_name = runnable[0];
            let start = std::time::Instant::now();

            // Meta-task: no command, no script — just a dependency group
            if is_meta_task(task_name, tasks, pkg_scripts) {
                all_results.push(TaskResult {
                    name: task_name.clone(),
                    success: true,
                    duration: start.elapsed(),
                    cached: false,
                    skipped: false,
                });
                print_task_result(all_results.last().unwrap());
                continue;
            }

            // Check cache
            if !no_cache
                && let Ok(Some(hit)) = try_cache_hit_with_config(
                    project_dir,
                    task_name,
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
                all_results.push(TaskResult {
                    name: task_name.clone(),
                    success: true,
                    duration: start.elapsed(),
                    cached: true,
                    skipped: false,
                });
                print_task_result(all_results.last().unwrap());
                continue;
            }

            install_ui::phase_untrusted(&format!(
                "Running {}",
                lpm_common::sanitize_terminal_inline(task_name)
            ));

            // Use captured execution when caching is enabled.
            let caching_enabled = !no_cache && is_task_cached_with_config(task_name, lpm_config);

            if caching_enabled {
                match run_task_captured(
                    project_dir,
                    task_name,
                    extra_args,
                    env_mode,
                    tasks,
                    bin_hint,
                ) {
                    Ok(output) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        let _ = try_cache_store_with_output_and_config(CacheStoreRequest {
                            project_dir,
                            script_name: task_name,
                            env_mode,
                            extra_args,
                            bin_hint,
                            duration_ms,
                            stdout: &output.stdout,
                            stderr: &output.stderr,
                            lpm_config,
                        });
                        all_results.push(TaskResult {
                            name: task_name.clone(),
                            success: true,
                            duration: start.elapsed(),
                            cached: false,
                            skipped: false,
                        });
                        print_task_result(all_results.last().unwrap());
                    }
                    Err(_) => {
                        all_results.push(TaskResult {
                            name: task_name.clone(),
                            success: false,
                            duration: start.elapsed(),
                            cached: false,
                            skipped: false,
                        });
                        print_task_result(all_results.last().unwrap());
                        failed_tasks.insert(task_name.clone());
                    }
                }
            } else {
                match run_task(
                    project_dir,
                    task_name,
                    extra_args,
                    env_mode,
                    tasks,
                    bin_hint,
                ) {
                    Ok(()) => {
                        all_results.push(TaskResult {
                            name: task_name.clone(),
                            success: true,
                            duration: start.elapsed(),
                            cached: false,
                            skipped: false,
                        });
                        print_task_result(all_results.last().unwrap());
                    }
                    Err(_) => {
                        all_results.push(TaskResult {
                            name: task_name.clone(),
                            success: false,
                            duration: start.elapsed(),
                            cached: false,
                            skipped: false,
                        });
                        print_task_result(all_results.last().unwrap());
                        failed_tasks.insert(task_name.clone());
                    }
                }
            }
        } else {
            // Multi-task level: spawn threads with correct output mode
            let max_threads = std::thread::available_parallelism().map_or(4, |n| n.get());

            for chunk in runnable.chunks(max_threads) {
                let chunk_names: Vec<String> = chunk.iter().map(|t| (*t).clone()).collect();
                // Assign color per task for streaming mode
                let chunk_colors: Vec<String> = chunk
                    .iter()
                    .map(|_| {
                        let c = TASK_COLORS[color_idx % TASK_COLORS.len()].to_string();
                        color_idx += 1;
                        c
                    })
                    .collect();

                let handles: Vec<_> = chunk
                    .iter()
                    .enumerate()
                    .map(|(ci, &task_name)| {
                        let dir = project_dir.to_path_buf();
                        let name = task_name.clone();
                        let args = extra_args.to_vec();
                        let mode = env_mode.map(|s| s.to_string());
                        // Arc::clone avoids copying the task maps and runtime hint per worker.
                        let hint_clone = Arc::clone(&hint_arc);
                        let tasks_clone = Arc::clone(&tasks_arc);
                        let config_clone = config_arc.clone();
                        let pkg_scripts_clone = pkg_scripts_arc.clone();
                        let is_stream = stream;
                        let color = chunk_colors[ci].clone();

                        std::thread::spawn(move || -> (TaskResult, String, String) {
                            let start = std::time::Instant::now();

                            // Meta-task — skip execution
                            if is_meta_task(&name, &tasks_clone, pkg_scripts_clone.as_deref()) {
                                return (
                                    TaskResult {
                                        name,
                                        success: true,
                                        duration: start.elapsed(),
                                        cached: false,
                                        skipped: false,
                                    },
                                    String::new(),
                                    String::new(),
                                );
                            }

                            // Check cache
                            if !no_cache
                                && let Ok(Some(hit)) = try_cache_hit_with_config(
                                    &dir,
                                    &name,
                                    mode.as_deref(),
                                    &args,
                                    &hint_clone,
                                    config_clone.as_deref(),
                                )
                            {
                                return (
                                    TaskResult {
                                        name,
                                        success: true,
                                        duration: start.elapsed(),
                                        cached: true,
                                        skipped: false,
                                    },
                                    hit.stdout,
                                    hit.stderr,
                                );
                            }

                            // Resolve command from lpm.json or package.json
                            let command_override =
                                tasks_clone.get(&name).and_then(|tc| tc.command.clone());

                            let result = if is_stream {
                                // Streaming: prefixed live output, no double-print
                                if let Some(cmd) = &command_override {
                                    lpm_runner::script::run_task_command_prefixed(
                                        &dir,
                                        &name,
                                        cmd,
                                        &args,
                                        mode.as_deref(),
                                        &name,
                                        &color,
                                        &hint_clone,
                                    )
                                } else {
                                    lpm_runner::script::run_script_prefixed(
                                        &dir,
                                        &name,
                                        &args,
                                        mode.as_deref(),
                                        &name,
                                        &color,
                                        &hint_clone,
                                    )
                                }
                            } else {
                                // Buffered: capture silently, print after completion
                                if let Some(cmd) = &command_override {
                                    lpm_runner::script::run_task_command_buffered(
                                        &dir,
                                        &name,
                                        cmd,
                                        &args,
                                        mode.as_deref(),
                                        &hint_clone,
                                    )
                                } else {
                                    lpm_runner::script::run_script_buffered(
                                        &dir,
                                        &name,
                                        &args,
                                        mode.as_deref(),
                                        &hint_clone,
                                    )
                                }
                            };

                            match result {
                                Ok(output) => {
                                    // Store cache
                                    if !no_cache {
                                        let duration_ms = start.elapsed().as_millis() as u64;
                                        let _ = try_cache_store_with_output_and_config(
                                            CacheStoreRequest {
                                                project_dir: &dir,
                                                script_name: &name,
                                                env_mode: mode.as_deref(),
                                                extra_args: &args,
                                                bin_hint: &hint_clone,
                                                duration_ms,
                                                stdout: &output.stdout,
                                                stderr: &output.stderr,
                                                lpm_config: config_clone.as_deref(),
                                            },
                                        );
                                    }
                                    (
                                        TaskResult {
                                            name,
                                            success: true,
                                            duration: start.elapsed(),
                                            cached: false,
                                            skipped: false,
                                        },
                                        truncate_output(output.stdout),
                                        truncate_output(output.stderr),
                                    )
                                }
                                Err(LpmError::ScriptWithOutput { stdout, stderr, .. }) => (
                                    TaskResult {
                                        name,
                                        success: false,
                                        duration: start.elapsed(),
                                        cached: false,
                                        skipped: false,
                                    },
                                    truncate_output(stdout),
                                    truncate_output(stderr),
                                ),
                                Err(_) => (
                                    TaskResult {
                                        name,
                                        success: false,
                                        duration: start.elapsed(),
                                        cached: false,
                                        skipped: false,
                                    },
                                    String::new(),
                                    String::new(),
                                ),
                            }
                        })
                    })
                    .collect();

                // Collect results — failed tasks dump stderr after summary
                let mut failed_outputs: Vec<(String, String)> = Vec::new();

                for (i, handle) in handles.into_iter().enumerate() {
                    match handle.join() {
                        Ok((result, stdout, stderr)) => {
                            if !stream {
                                // Buffered mode: print captured output now
                                if !stdout.is_empty() {
                                    print_captured_stdout(&stdout);
                                }
                                if !stderr.is_empty() && result.success {
                                    print_captured_stderr(&stderr);
                                }
                            }
                            // Streaming mode: output was already printed with prefixes

                            if !result.success {
                                if !stderr.is_empty() {
                                    failed_outputs.push((result.name.clone(), stderr));
                                }
                                failed_tasks.insert(result.name.clone());
                            }
                            print_task_result(&result);
                            all_results.push(result);
                        }
                        Err(_) => {
                            let name = chunk_names[i].clone();
                            install_ui::detail_line(format_run_failure_detail(
                                &name,
                                "thread panicked",
                            ));
                            failed_tasks.insert(name.clone());
                            all_results.push(TaskResult {
                                name,
                                success: false,
                                cached: false,
                                duration: std::time::Duration::ZERO,
                                skipped: false,
                            });
                        }
                    }
                }

                // Dump failed task output after the level completes
                for (name, stderr) in &failed_outputs {
                    install_ui::detail("");
                    install_ui::detail_line(format_failed_task_output_header(name));
                    print_captured_stderr(stderr);
                    install_ui::detail_line(format_failed_task_output_footer());
                }
            }
        }

        if !continue_on_error && !failed_tasks.is_empty() {
            break;
        }
    }

    // If we broke out early, mark remaining tasks as skipped
    if !continue_on_error && !failed_tasks.is_empty() {
        let already_processed: HashSet<String> =
            all_results.iter().map(|r| r.name.clone()).collect();
        for level in levels {
            for task in level {
                if !already_processed.contains(task) {
                    all_results.push(TaskResult {
                        name: task.clone(),
                        success: false,
                        duration: std::time::Duration::ZERO,
                        cached: false,
                        skipped: true,
                    });
                    print_task_result(all_results.last().unwrap());
                }
            }
        }
    }

    print_results_summary(&all_results, total_start.elapsed());

    if json_output {
        print_json_summary(&all_results, total_start.elapsed());
    }

    let failure_count = all_results
        .iter()
        .filter(|r| !r.success && !r.skipped)
        .count();
    if failure_count > 0 {
        Err(LpmError::ExitCode(failure_count as i32))
    } else {
        Ok(())
    }
}
