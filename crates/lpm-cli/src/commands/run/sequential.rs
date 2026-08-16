use super::cache::{
    CacheStoreRequest, CompletedTaskCacheIdentity, WorkspaceCacheContract,
    WorkspaceDependencyIdentities, complete_task_cache_identity, prepare_cache_context_with_config,
    resolve_task_dependency_identities, try_cache_hit_with_context, try_cache_store_with_context,
};
use super::format::{
    TaskResult, TaskRunReport, print_captured_stderr, print_captured_stdout, print_json_summary,
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
    workspace_contract: Option<&WorkspaceCacheContract>,
    workspace_dependency_identities: &WorkspaceDependencyIdentities,
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
    initially_failed_tasks: &HashSet<String>,
) -> Result<TaskRunReport, LpmError> {
    let mut results: Vec<TaskResult> = Vec::with_capacity(scripts.len());
    let total_start = std::time::Instant::now();
    let mut failed_tasks = initially_failed_tasks.clone();
    let mut cache_identities = HashMap::new();

    for (idx, script) in scripts.iter().enumerate() {
        // Skip tasks whose dependencies failed (topological order means deps
        // were already processed)
        let deps_failed = failed_tasks.contains(script)
            || tasks.get(script.as_str()).is_some_and(|task| {
                task.depends_on
                    .iter()
                    .filter(|dependency| !dependency.starts_with('^'))
                    .any(|dependency| failed_tasks.contains(dependency.as_str()))
            });

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

        let start = std::time::Instant::now();
        let dependency_identities = (!no_cache).then(|| {
            resolve_task_dependency_identities(
                script,
                tasks,
                workspace_dependency_identities,
                &cache_identities,
            )
        });
        let dependency_identities = dependency_identities.flatten();

        // Meta-task: has dependsOn but no command and no package.json script.
        // All deps completed successfully (checked above), so the meta-task succeeds.
        if is_meta_task(script, tasks, pkg_scripts) {
            if let Some(dependency_identities) = &dependency_identities {
                cache_identities.insert(
                    script.clone(),
                    CompletedTaskCacheIdentity::meta(dependency_identities),
                );
            }
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

        let cache_context = match dependency_identities.as_deref() {
            Some(dependency_identities) => prepare_cache_context_with_config(
                project_dir,
                workspace_contract,
                dependency_identities,
                script,
                env_mode,
                extra_args,
                bin_hint,
                lpm_config,
            )?,
            None => None,
        };
        let cache_hit = cache_context
            .as_ref()
            .map(|context| try_cache_hit_with_context(project_dir, context))
            .transpose()?
            .flatten();
        if let Some(hit) = cache_hit {
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
            let context = cache_context.as_ref().ok_or_else(|| {
                LpmError::Task(format!("cache context missing for task '{script}'"))
            })?;
            if let Some(identity) = complete_task_cache_identity(project_dir, script, context) {
                cache_identities.insert(script.clone(), identity);
            }
            print_task_result(results.last().unwrap());
            continue;
        }

        install_ui::phase_untrusted(&format!(
            "Running {}",
            lpm_common::sanitize_terminal_inline(script)
        ));

        let caching_enabled = cache_context.is_some();
        let task_start = std::time::Instant::now();

        // Resolve command: lpm.json task command > package.json script
        let run_result = if caching_enabled {
            match run_task_captured(project_dir, script, extra_args, env_mode, tasks, bin_hint) {
                Ok(captured) => {
                    let duration_ms = task_start.elapsed().as_millis() as u64;
                    let context = cache_context.as_ref().ok_or_else(|| {
                        LpmError::Task(format!("cache context missing for task '{script}'"))
                    })?;
                    if try_cache_store_with_context(
                        CacheStoreRequest {
                            project_dir,
                            workspace_contract,
                            script_name: script,
                            env_mode,
                            extra_args,
                            bin_hint,
                            duration_ms,
                            stdout: &captured.stdout,
                            stderr: &captured.stderr,
                        },
                        context,
                    ) && let Some(identity) =
                        complete_task_cache_identity(project_dir, script, context)
                    {
                        cache_identities.insert(script.clone(), identity);
                    }
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

    if json_output {
        print_json_summary(&results, total_start.elapsed());
    }
    Ok(TaskRunReport::with_cache_identities(
        results,
        cache_identities,
    ))
}
