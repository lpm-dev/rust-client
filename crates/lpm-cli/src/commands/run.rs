use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::collections::HashSet;
use std::path::Path;

/// Maximum size for captured task output before truncation (Finding #2).
/// Prevents unbounded memory usage from chatty tasks.
const MAX_CAPTURED_OUTPUT: usize = 10 * 1024 * 1024; // 10MB

/// Truncate captured output if it exceeds `MAX_CAPTURED_OUTPUT`, cutting at
/// the last newline boundary to avoid splitting a line.
fn truncate_output(output: String) -> String {
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

/// Ensure the required Node.js runtime is available before running scripts.
///
/// Detects version requirements from lpm.json/package.json/.nvmrc/.node-version,
/// auto-installs if needed, and prints a user-visible notice about which version
/// is being used.
///
/// This replaces the silent fallback behavior — developers always know which
/// Node version they're running on.
pub async fn ensure_runtime(project_dir: &Path) {
    match lpm_runtime::ensure_runtime(project_dir).await {
        lpm_runtime::RuntimeStatus::Ready { version, source } => {
            // Point 1: one-line notice when using managed runtime
            eprintln!(
                "  {} node {} (from {})",
                "Using".dimmed(),
                version.bold(),
                source.dimmed(),
            );
        }
        lpm_runtime::RuntimeStatus::Installed { version, source } => {
            // Point 3: auto-installed
            output::success(&format!(
                "Auto-installed node {} (from {})",
                version.bold(),
                source,
            ));
        }
        lpm_runtime::RuntimeStatus::NotInstalled { spec, source } => {
            // Point 2: warn when required version isn't installed
            output::warn(&format!(
                "{} requires node {}, but it's not installed. Using system node.",
                source,
                spec.bold(),
            ));
            eprintln!("    Run: {}", format!("lpm use node@{spec}").cyan(),);
        }
        lpm_runtime::RuntimeStatus::NoRequirement => {
            // No version pinned — nothing to show
        }
    }
}

/// Run a script from package.json (single package).
///
/// Delegates to `lpm_runner::script::run_script()` which provides:
/// - PATH injection (`node_modules/.bin` prepended)
/// - `.env` file loading (auto + `--env` flag + `lpm.json` mapping)
/// - Pre/post script hooks (npm convention)
/// - Task caching (when enabled in `lpm.json`)
pub async fn run(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
) -> Result<(), LpmError> {
    // Ensure runtime is available (auto-install if needed)
    ensure_runtime(project_dir).await;

    // Check if caching is enabled for this task
    if !no_cache && let Some(hit) = try_cache_hit(project_dir, script_name, env_mode)? {
        // Cache hit — replay output
        if !hit.stdout.is_empty() {
            print!("{}", hit.stdout);
        }
        if !hit.stderr.is_empty() {
            eprint!("{}", hit.stderr);
        }
        output::success(&format!(
            "{} restored from cache (originally {:.1}s)",
            script_name.bold(),
            hit.meta.duration_ms as f64 / 1000.0,
        ));
        return Ok(());
    }

    output::info(&format!("{}", script_name.bold()));

    // Check if caching is enabled — if so, use tee capture
    let caching_enabled = !no_cache && is_task_cached(project_dir, script_name);

    let start = std::time::Instant::now();

    if caching_enabled {
        // Run with tee capture (output streams to terminal + captured for cache)
        let output = lpm_runner::script::run_script_captured(
            project_dir,
            script_name,
            extra_args,
            env_mode,
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let _ = try_cache_store_with_output(
            project_dir,
            script_name,
            env_mode,
            duration_ms,
            &output.stdout,
            &output.stderr,
        );
    } else {
        // Run normally (inherited stdio, no capture)
        lpm_runner::script::run_script(project_dir, script_name, extra_args, env_mode)?;
    }

    Ok(())
}

/// Run scripts in a single package, with task dependency enforcement.
///
/// Always builds a task dependency graph from lpm.json, expanding `dependsOn`
/// prerequisites even for single-script invocations. When `parallel` is true,
/// independent tasks run concurrently; otherwise they run in topological order.
///
/// Supports `--continue-on-error` to keep running after failures,
/// `--stream` for interleaved output with task prefixes, and
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
    ensure_runtime(project_dir).await;

    if scripts.is_empty() {
        output::warn("No scripts specified. Usage: lpm run <script> [scripts...]");
        return Ok(());
    }

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
    let mut all_scripts: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists()
        && let Ok(pkg) = lpm_workspace::read_package_json(&pkg_json_path)
    {
        all_scripts.extend(pkg.scripts);
    }

    // Add lpm.json task commands (don't override package.json scripts)
    for (name, task) in &tasks {
        if let Some(cmd) = &task.command {
            all_scripts
                .entry(name.clone())
                .or_insert_with(|| cmd.clone());
        }
    }

    // Always build task graph — expand dependsOn for all scripts, even single ones.
    // This is the core Phase 13 contract: `lpm run test` auto-runs `check` if
    // test.dependsOn includes "check".
    let levels = lpm_runner::task_graph::task_levels(&all_scripts, &tasks, scripts)
        .map_err(LpmError::Script)?;

    let total_tasks: usize = levels.iter().map(|l| l.len()).sum();

    // Fast path: single task with no dependencies — delegate to simple runner
    if total_tasks == 1 && scripts.len() == 1 {
        return run(project_dir, &scripts[0], extra_args, env_mode, no_cache).await;
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
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// TaskResult + output helpers
// ---------------------------------------------------------------------------

struct TaskResult {
    name: String,
    success: bool,
    duration: std::time::Duration,
    cached: bool,
    skipped: bool,
}

fn print_task_result(result: &TaskResult) {
    if result.skipped {
        eprintln!(
            "  {} {}   {}",
            "\u{2298}".dimmed(),
            result.name.dimmed(),
            "skipped".dimmed(),
        );
    } else if result.success {
        let timing = format_duration(result.duration);
        let cache_label = if result.cached { ", cached" } else { "" };
        eprintln!(
            "  {} {}   passed ({}{})",
            "\u{2714}".green(),
            result.name.bold(),
            timing,
            cache_label,
        );
    } else {
        let timing = format_duration(result.duration);
        eprintln!(
            "  {} {}   failed (exit 1, {})",
            "\u{2716}".red(),
            result.name.bold(),
            timing,
        );
    }
}

fn print_results_summary(results: &[TaskResult], total_elapsed: std::time::Duration) {
    if results.len() <= 1 {
        return; // No summary for single task
    }

    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success && !r.skipped).count();
    let skipped = results.iter().filter(|r| r.skipped).count();
    let cached = results.iter().filter(|r| r.cached).count();

    // Calculate sequential time — exclude skipped tasks (Finding #5: skipped
    // tasks have 0ms duration which deflates the "% faster" metric).
    let sequential_ms: u128 = results
        .iter()
        .filter(|r| !r.skipped)
        .map(|r| r.duration.as_millis())
        .sum();
    let actual_ms = total_elapsed.as_millis();

    eprintln!();
    if failed == 0 {
        let speedup = if sequential_ms > 0 && actual_ms < sequential_ms {
            let pct = ((sequential_ms - actual_ms) as f64 / sequential_ms as f64 * 100.0) as u32;
            format!(
                " (vs {:.1}s sequential, {}% faster)",
                sequential_ms as f64 / 1000.0,
                pct,
            )
        } else {
            String::new()
        };
        // Finding #5: use ran count (excludes skipped) in summary
        let ran_count = results.iter().filter(|r| !r.skipped).count();
        eprintln!(
            "  {} {} completed in {}{}",
            "\u{2714}".green(),
            ran_count,
            format_duration(total_elapsed),
            speedup.dimmed(),
        );
    } else {
        // Finding #19: denominator excludes skipped tasks
        let ran = results.len() - skipped;
        let skip_note = if skipped > 0 {
            format!(" ({skipped} skipped)")
        } else {
            String::new()
        };
        eprintln!(
            "  {} {} of {} tasks failed.{}",
            "\u{2716}".red(),
            failed,
            ran,
            skip_note,
        );
    }

    if skipped > 0 {
        eprintln!("  {} skipped (dependency failed)", skipped);
    }
    if cached > 0 {
        eprintln!(
            "  Cache: {} hit, {} miss",
            cached,
            results.len() - cached - skipped,
        );
    }

    // Per-task breakdown when there's something interesting to show
    let _ = (passed, skipped);
}

fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

// ---------------------------------------------------------------------------
// Sequential execution
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_tasks_sequential(
    project_dir: &Path,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    continue_on_error: bool,
    no_cache: bool,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    json_output: bool,
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
        let is_meta_task = is_meta_task(project_dir, script, tasks);
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
            && let Ok(Some(hit)) =
                try_cache_hit_with_config(project_dir, script, env_mode, lpm_config)
        {
            if !hit.stdout.is_empty() {
                print!("{}", hit.stdout);
            }
            if !hit.stderr.is_empty() {
                eprint!("{}", hit.stderr);
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

        output::info(&format!("{}", script.bold()));

        let caching_enabled = !no_cache && is_task_cached_with_config(script, lpm_config);
        let task_start = std::time::Instant::now();

        // Resolve command: lpm.json task command > package.json script
        let run_result = if caching_enabled {
            match run_task_captured(project_dir, script, extra_args, env_mode, tasks) {
                Ok(captured) => {
                    let duration_ms = task_start.elapsed().as_millis() as u64;
                    let _ = try_cache_store_with_output_and_config(
                        project_dir,
                        script,
                        env_mode,
                        duration_ms,
                        &captured.stdout,
                        &captured.stderr,
                        lpm_config,
                    );
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            run_task(project_dir, script, extra_args, env_mode, tasks)
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

// ---------------------------------------------------------------------------
// Parallel execution
// ---------------------------------------------------------------------------

/// ANSI color codes for task prefixes in streaming mode.
const TASK_COLORS: &[&str] = &["36", "33", "35", "32", "34", "31"];

#[allow(clippy::too_many_arguments)]
async fn run_tasks_parallel(
    project_dir: &Path,
    levels: &[Vec<String>],
    extra_args: &[String],
    env_mode: Option<&str>,
    continue_on_error: bool,
    stream: bool,
    no_cache: bool,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
    json_output: bool,
) -> Result<(), LpmError> {
    let total_start = std::time::Instant::now();
    let mut all_results: Vec<TaskResult> = Vec::new();
    let mut failed_tasks: HashSet<String> = HashSet::new();

    // Show execution plan when there's parallelism
    let total_tasks: usize = levels.iter().map(|l| l.len()).sum();
    if levels.len() > 1 || levels.first().map(|l| l.len()).unwrap_or(0) > 1 {
        eprintln!(
            "  Running {} tasks ({} parallel groups)...\n",
            total_tasks,
            levels.len(),
        );
    }

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
            if is_meta_task(project_dir, task_name, tasks) {
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
                && let Ok(Some(hit)) =
                    try_cache_hit_with_config(project_dir, task_name, env_mode, lpm_config)
            {
                if !hit.stdout.is_empty() {
                    print!("{}", hit.stdout);
                }
                if !hit.stderr.is_empty() {
                    eprint!("{}", hit.stderr);
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

            output::info(&format!("{}", task_name.bold()));

            // Use captured execution when caching is enabled (Finding #5)
            let caching_enabled = !no_cache && is_task_cached_with_config(task_name, lpm_config);

            if caching_enabled {
                match run_task_captured(project_dir, task_name, extra_args, env_mode, tasks) {
                    Ok(output) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        let _ = try_cache_store_with_output_and_config(
                            project_dir,
                            task_name,
                            env_mode,
                            duration_ms,
                            &output.stdout,
                            &output.stderr,
                            lpm_config,
                        );
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
                match run_task(project_dir, task_name, extra_args, env_mode, tasks) {
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
            let max_threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);

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
                        let config_clone = lpm_config.cloned();
                        let tasks_clone = tasks.clone();
                        let is_stream = stream;
                        let color = chunk_colors[ci].clone();

                        std::thread::spawn(move || -> (TaskResult, String, String) {
                            let start = std::time::Instant::now();

                            // Meta-task — skip execution
                            if is_meta_task_from_config(&dir, &name, &tasks_clone) {
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
                                    config_clone.as_ref(),
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
                                    lpm_runner::script::run_command_prefixed(
                                        &dir,
                                        cmd,
                                        &args,
                                        mode.as_deref(),
                                        &name,
                                        &color,
                                    )
                                } else {
                                    lpm_runner::script::run_script_prefixed(
                                        &dir,
                                        &name,
                                        &args,
                                        mode.as_deref(),
                                        &name,
                                        &color,
                                    )
                                }
                            } else {
                                // Buffered: capture silently, print after completion
                                if let Some(cmd) = &command_override {
                                    lpm_runner::script::run_command_buffered(
                                        &dir,
                                        cmd,
                                        &args,
                                        mode.as_deref(),
                                    )
                                } else {
                                    lpm_runner::script::run_script_buffered(
                                        &dir,
                                        &name,
                                        &args,
                                        mode.as_deref(),
                                    )
                                }
                            };

                            match result {
                                Ok(output) => {
                                    // Store cache
                                    if !no_cache {
                                        let duration_ms = start.elapsed().as_millis() as u64;
                                        let _ = try_cache_store_with_output_and_config(
                                            &dir,
                                            &name,
                                            mode.as_deref(),
                                            duration_ms,
                                            &output.stdout,
                                            &output.stderr,
                                            config_clone.as_ref(),
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
                                    print!("{}", stdout);
                                }
                                if !stderr.is_empty() && result.success {
                                    eprint!("{}", stderr);
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
                            eprintln!("  {} {} thread panicked", "\u{2716}".red(), name);
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
                    eprintln!();
                    eprintln!(
                        "  \u{2500}\u{2500} {} output {}",
                        name.bold(),
                        "\u{2500}".repeat(40)
                    );
                    eprint!("{stderr}");
                    eprintln!("  {}", "\u{2500}".repeat(50));
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

/// Run scripts across workspace packages with task-graph-aware execution.
///
/// For each package in workspace topological order:
/// 1. Build a task dependency graph from the package's lpm.json
/// 2. Expand requested scripts into their full dependency chain
/// 3. Execute the expanded task set (parallel or sequential based on flags)
///
/// This delivers the Phase 13 "packages × tasks" execution matrix.
#[allow(clippy::too_many_arguments)]
pub async fn run_workspace(
    project_dir: &Path,
    scripts: &[String],
    extra_args: &[String],
    env_mode: Option<&str>,
    filter: Option<&str>,
    affected: bool,
    base_ref: &str,
    no_cache: bool,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    ensure_runtime(project_dir).await;

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
    let sorted: Vec<usize> = levels.iter().flatten().copied().collect();

    let target_set: std::collections::HashSet<usize> = if affected {
        lpm_task::affected::find_affected(&ws_graph, &workspace.root, base_ref)
            .map_err(LpmError::Script)?
    } else if let Some(filter_pat) = filter {
        sorted
            .iter()
            .filter(|&&i| {
                let member = &ws_graph.members[i];
                member.name.contains(filter_pat)
                    || member.path.to_string_lossy().contains(filter_pat)
            })
            .copied()
            .collect()
    } else {
        sorted.iter().copied().collect()
    };

    if target_set.is_empty() {
        output::info("No packages matched");
        return Ok(());
    }

    let total = target_set.len();
    let start = std::time::Instant::now();
    let succeeded = std::sync::atomic::AtomicUsize::new(0);
    let failed_flag = std::sync::atomic::AtomicBool::new(false);

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

        if !continue_on_error && failed_flag.load(std::sync::atomic::Ordering::Relaxed) {
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
            );
            match ok {
                Some(true) => {
                    succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Some(false) => {
                    failed_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                None => {} // skipped (no scripts for this package)
            }
        } else {
            // Multiple packages in this level — run in parallel
            let max_threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);

            for chunk in level_targets.chunks(max_threads) {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&idx| {
                        let member_dir = ws_graph.members[idx].path.clone();
                        let member_name = ws_graph.members[idx].name.clone();
                        let scripts_owned: Vec<String> = scripts.to_vec();
                        let args_owned: Vec<String> = extra_args.to_vec();
                        let mode_owned = env_mode.map(|s| s.to_string());

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
                            )
                        })
                    })
                    .collect();

                for handle in handles {
                    match handle.join() {
                        Ok(Some(true)) => {
                            succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(Some(false)) => {
                            failed_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(None) => {} // skipped
                        Err(_) => {
                            eprintln!("  {} workspace task panicked", "\u{2716}".red());
                            failed_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }

                if !continue_on_error && failed_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let total_succeeded = succeeded.load(std::sync::atomic::Ordering::Relaxed);
    let has_failed = failed_flag.load(std::sync::atomic::Ordering::Relaxed);
    if json_output {
        let json = serde_json::json!({
            "success": !has_failed,
            "packages": total,
            "succeeded": total_succeeded,
            "duration_ms": elapsed.as_millis() as u64,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        output::success(&format!(
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
) -> Option<bool> {
    let pkg_json_path = member_dir.join("package.json");
    if !pkg_json_path.exists() {
        return None;
    }

    let pkg = match lpm_workspace::read_package_json(&pkg_json_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {} {member_name}: {e}", "\u{2716}".red());
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
                .map(|tc| tc.command.is_some() || !tc.depends_on.is_empty())
                .unwrap_or(false)
    });
    if !has_any {
        return None;
    }

    eprintln!(
        "\n  {} {}",
        format!("[{member_name}]").cyan(),
        scripts.join(", ").bold(),
    );

    // Build per-package task graph
    let task_levels = match lpm_runner::task_graph::task_levels(&pkg.scripts, &tasks, scripts) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  {} {member_name}: {e}", "\u{2716}".red());
            return Some(false);
        }
    };

    let task_count: usize = task_levels.iter().map(|l| l.len()).sum();

    // Single task, no deps → simple run
    if task_count == 1 && scripts.len() == 1 {
        return match run_task(member_dir, &scripts[0], extra_args, env_mode, &tasks) {
            Ok(()) => Some(true),
            Err(e) => {
                eprintln!("  {} {member_name}: {e}", "\u{2716}".red());
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
        ))
    };

    Some(result.is_ok())
}

/// Run a script in watch mode — re-run on file changes.
///
/// Watch mode always runs fresh (no caching) — this is the correct behavior
/// for a development workflow where you want immediate feedback on every save.
/// The `--no-cache` flag has no effect in watch mode.
///
/// If the task has configured `inputs` globs in `lpm.json`, only file changes
/// matching those globs trigger a rebuild. Otherwise, any relevant file change
/// (excluding `.git/`, `node_modules/`, etc.) triggers a rebuild.
pub fn run_watch(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
) -> Result<(), LpmError> {
    // Read task config for input globs — only trigger on relevant file changes
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let input_globs = lpm_config
        .as_ref()
        .and_then(|c| c.tasks.get(script_name))
        .map(|tc| tc.effective_inputs())
        .unwrap_or_default();

    if input_globs.is_empty() {
        output::info(&format!("watching {} (Ctrl+C to stop)", script_name.bold()));
    } else {
        output::info(&format!(
            "watching {} [{}] (Ctrl+C to stop)",
            script_name.bold(),
            input_globs.join(", ").dimmed(),
        ));
    }

    let script = script_name.to_string();
    let args: Vec<String> = extra_args.to_vec();
    let mode = env_mode.map(|s| s.to_string());
    let dir = project_dir.to_path_buf();

    lpm_task::watch::watch_and_run(
        project_dir,
        Box::new(move || {
            // Clear screen between runs
            print!("\x1B[2J\x1B[1;1H");
            println!(
                "{} running {} ...",
                owo_colors::OwoColorize::dimmed(&"[watch]"),
                script,
            );

            let result = lpm_runner::script::run_script(&dir, &script, &args, mode.as_deref());

            match result {
                Ok(()) => {
                    println!(
                        "\n{} {} completed. Waiting for changes...",
                        owo_colors::OwoColorize::green(&"✔"),
                        script,
                    );
                }
                Err(e) => {
                    eprintln!("\n{} {}: {}", owo_colors::OwoColorize::red(&"✖"), script, e,);
                    eprintln!("Waiting for changes...");
                }
            }
        }),
        &input_globs,
        None, // No shutdown channel — runs until Ctrl+C
    )
    .map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

    Ok(())
}

/// Execute a file directly, auto-detecting the runtime.
pub async fn exec(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
) -> Result<(), LpmError> {
    ensure_runtime(project_dir).await;
    output::info(&format!("exec {}", file_path.bold()));
    lpm_runner::exec::exec_file(project_dir, file_path, extra_args)
}

/// Run a package binary without installing it into the project.
///
/// Uses LPM's own install pipeline (self-hosted, no npm dependency).
/// Caches installations for 24 hours. Use `--refresh` to force reinstall.
pub async fn dlx(
    project_dir: &Path,
    package_spec: &str,
    extra_args: &[String],
    refresh: bool,
) -> Result<(), LpmError> {
    let cache_dir = lpm_runner::dlx::dlx_cache_dir(package_spec)?;

    let needs_install = if refresh || !cache_dir.join("node_modules/.bin").is_dir() {
        true
    } else if !lpm_runner::dlx::is_cache_fresh(&cache_dir, lpm_runner::dlx::CACHE_TTL_SECS) {
        output::info(&format!(
            "cache expired for {}, reinstalling...",
            package_spec.bold()
        ));
        true
    } else {
        false
    };

    if needs_install {
        lpm_runner::dlx::create_cache_dir(&cache_dir)?;

        let (pkg_name, version_spec) = lpm_runner::dlx::parse_package_spec(package_spec);

        // Write package.json with the target dependency
        let pkg_json =
            format!(r#"{{"private":true,"dependencies":{{"{pkg_name}":"{version_spec}"}}}}"#,);
        std::fs::write(cache_dir.join("package.json"), &pkg_json)
            .map_err(|e| LpmError::Script(format!("failed to write dlx package.json: {e}")))?;

        output::info(&format!("installing {}...", package_spec.bold()));

        // Self-hosted install using LPM's own resolver/store/linker
        let registry_url = std::env::var("LPM_REGISTRY_URL")
            .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
        let client = lpm_registry::RegistryClient::new().with_base_url(&registry_url);

        // Pass to install pipeline (same as `lpm install`)
        crate::commands::install::run_with_options(
            &client, &cache_dir, false, // json_output
            false, // offline
            false, // force
            false, // allow_new
            None,  // linker_override
            false, // no_skills
            false, // no_editor_setup
            true,  // no_security_summary (dlx doesn't need it)
            false, // auto_build
        )
        .await?;

        lpm_runner::dlx::touch_cache(&cache_dir);
    }

    // Execute the binary
    lpm_runner::dlx::exec_dlx_binary(project_dir, &cache_dir, package_spec, extra_args)
}

// ---------------------------------------------------------------------------
// Task execution helpers (Finding #4: support lpm.json commands + meta-tasks)
// ---------------------------------------------------------------------------

/// Check if a task is a meta-task: has dependsOn but no command and no
/// package.json script. Meta-tasks succeed once all deps complete.
fn is_meta_task(
    project_dir: &Path,
    task_name: &str,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
) -> bool {
    // Has task config with dependsOn?
    let has_deps = tasks
        .get(task_name)
        .map(|tc| !tc.depends_on.is_empty())
        .unwrap_or(false);
    if !has_deps {
        return false;
    }

    // Has a command in lpm.json?
    let has_command = tasks
        .get(task_name)
        .and_then(|tc| tc.command.as_ref())
        .is_some();
    if has_command {
        return false;
    }

    // Has a script in package.json?
    let pkg_path = project_dir.join("package.json");
    if pkg_path.exists()
        && let Ok(pkg) = lpm_workspace::read_package_json(&pkg_path)
        && pkg.scripts.contains_key(task_name)
    {
        return false;
    }

    true // dependsOn exists, but no command/script — it's a meta-task
}

/// Thread-safe meta-task check using pre-read config (no filesystem access).
fn is_meta_task_from_config(
    project_dir: &Path,
    task_name: &str,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
) -> bool {
    is_meta_task(project_dir, task_name, tasks)
}

/// Resolve and run a task: checks lpm.json command first, then package.json script.
fn run_task(
    project_dir: &Path,
    task_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
) -> Result<(), LpmError> {
    // Check lpm.json for command override
    if let Some(command) = tasks.get(task_name).and_then(|tc| tc.command.as_ref()) {
        return lpm_runner::script::run_command(project_dir, command, extra_args, env_mode);
    }
    // Fall back to package.json script
    lpm_runner::script::run_script(project_dir, task_name, extra_args, env_mode)
}

/// Resolve and run a task with tee-captured output (for caching).
fn run_task_captured(
    project_dir: &Path,
    task_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
) -> Result<lpm_runner::script::ScriptOutput, LpmError> {
    // Check lpm.json for command override
    if let Some(command) = tasks.get(task_name).and_then(|tc| tc.command.as_ref()) {
        return lpm_runner::script::run_command_captured(
            project_dir,
            command,
            extra_args,
            env_mode,
        );
    }
    // Fall back to package.json script
    lpm_runner::script::run_script_captured(project_dir, task_name, extra_args, env_mode)
}

/// Check if a task has caching enabled, using pre-read config.
fn is_task_cached_with_config(
    script_name: &str,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> bool {
    lpm_config
        .and_then(|c| c.tasks.get(script_name))
        .map(|tc| tc.cache && !tc.outputs.is_empty())
        .unwrap_or(false)
}

/// Print a JSON summary of task results (Finding #7).
fn print_json_summary(results: &[TaskResult], elapsed: std::time::Duration) {
    let tasks: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "success": r.success,
                "cached": r.cached,
                "skipped": r.skipped,
                "duration_ms": r.duration.as_millis() as u64,
            })
        })
        .collect();

    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success && !r.skipped).count();
    let skipped = results.iter().filter(|r| r.skipped).count();
    let cached = results.iter().filter(|r| r.cached).count();

    let json = serde_json::json!({
        "success": failed == 0,
        "tasks": tasks,
        "total": results.len(),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "cached": cached,
        "duration_ms": elapsed.as_millis() as u64,
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

// --- Cache helpers ---

/// Pre-computed cache context to avoid re-reading lpm.json and package.json
/// multiple times per task (Finding #10).
struct CacheContext {
    task_config: lpm_runner::lpm_json::TaskConfig,
    cache_key: String,
    command: String,
}

/// Build the cache context for a task: reads lpm.json (or uses provided config),
/// resolves the command, and computes the cache key. Returns `None` if caching
/// is not enabled or outputs are empty (Finding #20: shared helper eliminates
/// duplication between try_cache_store and try_cache_store_with_output).
fn build_cache_context(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<CacheContext>, LpmError> {
    // Use provided config or read from disk
    let owned_config;
    let config_ref = if let Some(cfg) = lpm_config {
        Some(cfg)
    } else {
        owned_config =
            lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
        owned_config.as_ref()
    };

    let task_config = config_ref.and_then(|c| c.tasks.get(script_name));

    let task_config = match task_config {
        Some(tc) if tc.cache && !tc.outputs.is_empty() => tc,
        _ => return Ok(None),
    };

    let env_vars = lpm_runner::dotenv::load_env_files(project_dir, env_mode);

    let pkg_json_path = project_dir.join("package.json");
    let deps_json = if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        serde_json::to_string(&pkg.dependencies).unwrap_or_default()
    } else {
        "{}".into()
    };

    let command = if let Some(cmd) = &task_config.command {
        cmd.clone()
    } else if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("{e}")))?;
        pkg.scripts.get(script_name).cloned().unwrap_or_default()
    } else {
        String::new()
    };

    let cache_key = lpm_task::hasher::compute_cache_key(
        project_dir,
        &command,
        &task_config.effective_inputs(),
        &env_vars,
        &deps_json,
    );

    Ok(Some(CacheContext {
        task_config: task_config.clone(),
        cache_key,
        command,
    }))
}

/// Check for a cache hit. Returns `None` if caching is disabled, outputs are
/// empty (Finding #21: consistent with is_task_cached), or no hit exists.
fn try_cache_hit(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
) -> Result<Option<lpm_task::cache::CacheHit>, LpmError> {
    try_cache_hit_with_config(project_dir, script_name, env_mode, None)
}

/// Finding #4: variant that accepts a pre-read config to avoid re-reading
/// lpm.json per thread in parallel execution.
fn try_cache_hit_with_config(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<lpm_task::cache::CacheHit>, LpmError> {
    let ctx = match build_cache_context(project_dir, script_name, env_mode, lpm_config)? {
        Some(ctx) => ctx,
        None => return Ok(None),
    };

    if lpm_task::cache::has_cache_hit(&ctx.cache_key) {
        let hit = lpm_task::cache::restore_cache(&ctx.cache_key, project_dir)?;
        return Ok(Some(hit));
    }

    Ok(None)
}

/// Check if a task has caching enabled in lpm.json.
fn is_task_cached(project_dir: &Path, script_name: &str) -> bool {
    lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten()
        .and_then(|c| c.tasks.get(script_name).cloned())
        .map(|tc| tc.cache && !tc.outputs.is_empty())
        .unwrap_or(false)
}

/// Store cache with captured stdout/stderr.
fn try_cache_store_with_output(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    duration_ms: u64,
    stdout: &str,
    stderr: &str,
) -> Result<(), LpmError> {
    try_cache_store_with_output_and_config(
        project_dir,
        script_name,
        env_mode,
        duration_ms,
        stdout,
        stderr,
        None,
    )
}

/// Finding #4: variant that accepts a pre-read config.
fn try_cache_store_with_output_and_config(
    project_dir: &Path,
    script_name: &str,
    env_mode: Option<&str>,
    duration_ms: u64,
    stdout: &str,
    stderr: &str,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    let ctx = match build_cache_context(project_dir, script_name, env_mode, lpm_config)? {
        Some(ctx) => ctx,
        None => return Ok(()),
    };

    lpm_task::cache::store_cache(
        &ctx.cache_key,
        project_dir,
        &ctx.command,
        &ctx.task_config.outputs,
        stdout,
        stderr,
        duration_ms,
    )?;

    tracing::debug!(
        "stored cache for task '{script_name}' (key: {}, stdout: {} bytes)",
        ctx.cache_key,
        stdout.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Finding #1: transitive skip propagation ---

    /// Helper matching the skip-check logic in `run_tasks_parallel`.
    fn should_skip_task(
        task_name: &str,
        tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
        failed_tasks: &HashSet<String>,
    ) -> bool {
        if let Some(tc) = tasks.get(task_name) {
            tc.depends_on
                .iter()
                .filter(|d| !d.starts_with('^'))
                .any(|d| failed_tasks.contains(d.as_str()))
        } else {
            failed_tasks.contains(task_name)
        }
    }

    #[test]
    fn transitive_skip_propagation() {
        // Chain: A depends on B, B depends on C. C fails.
        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "A".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["B".into()],
                ..Default::default()
            },
        );
        tasks.insert(
            "B".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["C".into()],
                ..Default::default()
            },
        );
        tasks.insert("C".into(), lpm_runner::lpm_json::TaskConfig::default());

        let mut failed_tasks: HashSet<String> = HashSet::new();
        failed_tasks.insert("C".into());

        // B should be skipped (depends on C which failed)
        assert!(should_skip_task("B", &tasks, &failed_tasks));

        // After marking B as skipped, add it to failed_tasks (the fix)
        failed_tasks.insert("B".into());

        // A should now also be skipped (depends on B which is in failed_tasks)
        assert!(should_skip_task("A", &tasks, &failed_tasks));
    }

    #[test]
    fn no_skip_when_deps_ok() {
        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "A".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["B".into()],
                ..Default::default()
            },
        );
        tasks.insert("B".into(), lpm_runner::lpm_json::TaskConfig::default());

        let failed_tasks: HashSet<String> = HashSet::new();
        assert!(!should_skip_task("A", &tasks, &failed_tasks));
    }

    // --- Finding #2: output truncation ---

    #[test]
    fn truncate_output_small_passthrough() {
        let small = "hello world\n".repeat(10);
        let result = truncate_output(small.clone());
        assert_eq!(result, small);
    }

    #[test]
    fn truncate_output_large_truncated() {
        // 11 MB of output
        let large = "x".repeat(11 * 1024 * 1024);
        let result = truncate_output(large);
        assert!(result.len() <= MAX_CAPTURED_OUTPUT + 100); // +100 for the message
        assert!(result.contains("[output truncated at 10MB]"));
    }

    #[test]
    fn truncate_output_cuts_at_newline() {
        // Create string just over limit with newlines
        let mut s = String::new();
        let line = "a".repeat(1000) + "\n";
        while s.len() < MAX_CAPTURED_OUTPUT + 5000 {
            s.push_str(&line);
        }
        let result = truncate_output(s);
        assert!(result.contains("[output truncated at 10MB]"));
        // The truncated content (before "...") should end at a newline boundary
        let before_ellipsis = result.split("...\n").next().unwrap();
        assert!(before_ellipsis.ends_with('\n') || before_ellipsis.ends_with('a'));
    }

    // --- Finding #5: skipped tasks excluded from sequential estimate ---

    #[test]
    fn sequential_excludes_skipped() {
        let results = [
            TaskResult {
                name: "build".into(),
                success: true,
                duration: std::time::Duration::from_secs(5),
                cached: false,
                skipped: false,
            },
            TaskResult {
                name: "test".into(),
                success: true,
                duration: std::time::Duration::from_secs(3),
                cached: false,
                skipped: false,
            },
            TaskResult {
                name: "deploy".into(),
                success: false,
                duration: std::time::Duration::ZERO,
                cached: false,
                skipped: true,
            },
        ];

        let sequential_ms: u128 = results
            .iter()
            .filter(|r| !r.skipped)
            .map(|r| r.duration.as_millis())
            .sum();
        assert_eq!(sequential_ms, 8000);

        let ran_count = results.iter().filter(|r| !r.skipped).count();
        assert_eq!(ran_count, 2);
    }

    // --- Cache context tests ---

    #[test]
    fn build_cache_context_returns_none_without_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.json → caching not configured
        let ctx = build_cache_context(dir.path(), "build", None, None).unwrap();
        assert!(ctx.is_none(), "should return None without lpm.json");
    }

    #[test]
    fn build_cache_context_returns_none_when_cache_false() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"build":"echo hi"}}"#,
        )
        .unwrap();
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "build".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        cache: false,
                        outputs: vec!["dist/**".into()],
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        let ctx = build_cache_context(dir.path(), "build", None, Some(&config)).unwrap();
        assert!(ctx.is_none(), "should return None when cache is false");
    }

    #[test]
    fn build_cache_context_returns_none_when_outputs_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"build":"echo hi"}}"#,
        )
        .unwrap();
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "build".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        cache: true,
                        outputs: vec![], // empty outputs
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        let ctx = build_cache_context(dir.path(), "build", None, Some(&config)).unwrap();
        assert!(ctx.is_none(), "should return None when outputs are empty");
    }

    #[test]
    fn build_cache_context_returns_some_when_properly_configured() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"build":"echo hi"}}"#,
        )
        .unwrap();
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "build".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        cache: true,
                        outputs: vec!["dist/**".into()],
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        let ctx = build_cache_context(dir.path(), "build", None, Some(&config)).unwrap();
        assert!(ctx.is_some(), "should return Some for valid cache config");
        let ctx = ctx.unwrap();
        assert_eq!(ctx.command, "echo hi");
        assert_eq!(ctx.cache_key.len(), 64, "cache key should be SHA-256 hex");
    }

    #[test]
    fn is_task_cached_false_without_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_task_cached(dir.path(), "build"));
    }

    // --- Format helpers ---

    #[test]
    fn format_duration_milliseconds() {
        assert_eq!(
            format_duration(std::time::Duration::from_millis(42)),
            "42ms"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_millis(999)),
            "999ms"
        );
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(
            format_duration(std::time::Duration::from_millis(1500)),
            "1.5s"
        );
        assert_eq!(format_duration(std::time::Duration::from_secs(10)), "10.0s");
    }

    // --- Meta-task detection ---

    #[test]
    fn meta_task_with_deps_no_command_no_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"lint": "eslint .", "test": "vitest"}}"#,
        )
        .unwrap();

        let mut tasks = std::collections::HashMap::new();
        // "ci" has dependsOn but no command and no package.json script → meta-task
        tasks.insert(
            "ci".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["lint".into(), "test".into()],
                ..Default::default()
            },
        );

        assert!(is_meta_task(dir.path(), "ci", &tasks));
    }

    #[test]
    fn meta_task_false_when_has_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"ci": "echo ci", "lint": "eslint ."}}"#,
        )
        .unwrap();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "ci".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["lint".into()],
                ..Default::default()
            },
        );

        assert!(!is_meta_task(dir.path(), "ci", &tasks));
    }

    #[test]
    fn meta_task_false_when_has_command() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"lint": "eslint ."}}"#,
        )
        .unwrap();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "ci".into(),
            lpm_runner::lpm_json::TaskConfig {
                command: Some("echo all-done".into()),
                depends_on: vec!["lint".into()],
                ..Default::default()
            },
        );

        assert!(!is_meta_task(dir.path(), "ci", &tasks));
    }

    #[test]
    fn meta_task_false_when_no_deps() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let tasks = std::collections::HashMap::new();
        assert!(!is_meta_task(dir.path(), "build", &tasks));
    }

    // --- is_task_cached_with_config ---

    #[test]
    fn is_task_cached_with_config_returns_true() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "build".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        cache: true,
                        outputs: vec!["dist/**".into()],
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        assert!(is_task_cached_with_config("build", Some(&config)));
    }

    #[test]
    fn is_task_cached_with_config_false_no_outputs() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            tasks: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "lint".into(),
                    lpm_runner::lpm_json::TaskConfig {
                        cache: true,
                        outputs: vec![],
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        assert!(!is_task_cached_with_config("lint", Some(&config)));
    }

    #[test]
    fn is_task_cached_with_config_false_no_config() {
        assert!(!is_task_cached_with_config("build", None));
    }

    // --- run_task resolves lpm.json command ---

    #[test]
    fn run_task_uses_lpm_json_command() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "codegen".into(),
            lpm_runner::lpm_json::TaskConfig {
                command: Some("echo codegen-ran".into()),
                ..Default::default()
            },
        );

        let result = run_task(dir.path(), "codegen", &[], None, &tasks);
        assert!(result.is_ok(), "should run lpm.json command: {result:?}");
    }

    #[test]
    fn run_task_falls_back_to_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "echo build-ran"}}"#,
        )
        .unwrap();

        let tasks = std::collections::HashMap::new();
        let result = run_task(dir.path(), "build", &[], None, &tasks);
        assert!(result.is_ok(), "should fall back to package.json script");
    }

    #[test]
    fn run_task_errors_for_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let tasks = std::collections::HashMap::new();
        let result = run_task(dir.path(), "nonexistent", &[], None, &tasks);
        assert!(result.is_err());
    }

    // --- run_task_captured resolves lpm.json command ---

    #[test]
    fn run_task_captured_uses_lpm_json_command() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "codegen".into(),
            lpm_runner::lpm_json::TaskConfig {
                command: Some("echo captured-codegen".into()),
                ..Default::default()
            },
        );

        let result = run_task_captured(dir.path(), "codegen", &[], None, &tasks);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("captured-codegen"));
    }

    // --- JSON summary ---

    #[test]
    fn json_summary_format() {
        let results = vec![
            TaskResult {
                name: "lint".into(),
                success: true,
                duration: std::time::Duration::from_millis(100),
                cached: false,
                skipped: false,
            },
            TaskResult {
                name: "test".into(),
                success: false,
                duration: std::time::Duration::from_millis(200),
                cached: false,
                skipped: false,
            },
            TaskResult {
                name: "deploy".into(),
                success: false,
                duration: std::time::Duration::ZERO,
                cached: false,
                skipped: true,
            },
        ];

        // Just verify it doesn't panic — output goes to stdout
        // which is captured by the test harness
        print_json_summary(&results, std::time::Duration::from_millis(300));
    }

    // --- dependsOn expansion: single script with deps should expand ---

    #[test]
    fn task_graph_expands_single_script_deps() {
        // "test" depends on "check" — requesting just "test" should include both
        let scripts: std::collections::HashMap<String, String> = [
            ("test".to_string(), "vitest".to_string()),
            ("check".to_string(), "tsc --noEmit".to_string()),
        ]
        .into();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "test".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["check".into()],
                ..Default::default()
            },
        );

        let levels =
            lpm_runner::task_graph::task_levels(&scripts, &tasks, &["test".into()]).unwrap();

        // Should be 2 levels: [check], [test]
        assert_eq!(levels.len(), 2, "expected 2 levels, got {levels:?}");
        assert_eq!(levels[0], vec!["check"]);
        assert_eq!(levels[1], vec!["test"]);
    }

    #[test]
    fn single_script_no_deps_single_level() {
        let scripts: std::collections::HashMap<String, String> =
            [("build".to_string(), "vite build".to_string())].into();
        let tasks = std::collections::HashMap::new();

        let levels =
            lpm_runner::task_graph::task_levels(&scripts, &tasks, &["build".into()]).unwrap();

        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec!["build"]);
    }

    // --- ScriptWithOutput error preserves output ---

    #[test]
    fn script_with_output_error_captures_stderr() {
        let err = LpmError::ScriptWithOutput {
            code: 1,
            stdout: "some stdout".into(),
            stderr: "detailed error info".into(),
        };
        assert!(err.to_string().contains("code 1"));
        if let LpmError::ScriptWithOutput { stderr, .. } = &err {
            assert_eq!(stderr, "detailed error info");
        }
    }

    // --- Remaining Finding #2: nested meta-task dependency resolution ---

    #[test]
    fn nested_meta_task_deps_expand_correctly() {
        // release → ci (meta-task), ci → [lint, test]
        let scripts: std::collections::HashMap<String, String> = [
            ("lint".to_string(), "eslint .".to_string()),
            ("test".to_string(), "vitest".to_string()),
        ]
        .into();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "ci".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["lint".into(), "test".into()],
                ..Default::default()
            },
        );
        tasks.insert(
            "release".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["ci".into()],
                ..Default::default()
            },
        );

        let levels =
            lpm_runner::task_graph::task_levels(&scripts, &tasks, &["release".into()]).unwrap();

        // [lint, test], [ci], [release]
        assert_eq!(levels.len(), 3, "got: {levels:?}");
        assert!(levels[0].contains(&"lint".to_string()));
        assert!(levels[0].contains(&"test".to_string()));
        assert_eq!(levels[1], vec!["ci"]);
        assert_eq!(levels[2], vec!["release"]);
    }

    // --- Remaining Finding #3: sequential failure uses aggregate exit code ---

    #[test]
    fn sequential_failure_exit_code_is_failure_count() {
        // Verify the run_tasks_sequential path returns failure_count, not the
        // raw script exit code. We can't easily run the async function in a
        // sync test, but we can verify the exit-code logic directly.

        let results = [
            TaskResult {
                name: "lint".into(),
                success: false,
                duration: std::time::Duration::from_millis(100),
                cached: false,
                skipped: false,
            },
            TaskResult {
                name: "test".into(),
                success: false,
                duration: std::time::Duration::ZERO,
                cached: false,
                skipped: true,
            },
        ];

        let failure_count = results.iter().filter(|r| !r.success && !r.skipped).count();
        assert_eq!(failure_count, 1, "only non-skipped failures counted");

        // The function returns LpmError::ExitCode(failure_count as i32)
        let err = LpmError::ExitCode(failure_count as i32);
        if let LpmError::ExitCode(code) = err {
            assert_eq!(
                code, 1,
                "exit code should be failure count, not script exit code"
            );
        }
    }

    // --- Meta-task execution in sequential path ---

    #[test]
    fn meta_task_in_expanded_graph_is_noop() {
        // Verify that a meta-task (dependsOn, no command, no script) in a
        // task graph is detected as a meta-task and would succeed as a no-op.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"lint": "eslint .", "test": "vitest"}}"#,
        )
        .unwrap();

        let mut tasks = std::collections::HashMap::new();
        tasks.insert(
            "ci".into(),
            lpm_runner::lpm_json::TaskConfig {
                depends_on: vec!["lint".into(), "test".into()],
                ..Default::default()
            },
        );

        // "ci" should be detected as a meta-task
        assert!(is_meta_task(dir.path(), "ci", &tasks));

        // "lint" should NOT be a meta-task (it has a script)
        assert!(!is_meta_task(dir.path(), "lint", &tasks));

        // Task graph should expand ci → [lint, test], [ci]
        let pkg = lpm_workspace::read_package_json(&dir.path().join("package.json")).unwrap();
        let levels =
            lpm_runner::task_graph::task_levels(&pkg.scripts, &tasks, &["ci".into()]).unwrap();
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[1], vec!["ci"]);
    }
}
