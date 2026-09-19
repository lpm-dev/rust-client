use super::cache::{
    CacheStoreRequest, prepare_package_script_cache_context, try_cache_hit_with_context,
    try_cache_store_with_context,
};
use super::format::{print_captured_stderr, print_captured_stdout};
use super::runtime::prepare_runtime;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::sync::Arc;

fn script_command_for_display(
    project_dir: &Path,
    script_name: &str,
    lpm_config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<Option<String>, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        if let Some(command) = pkg.scripts.get(script_name) {
            return Ok(Some(command.clone()));
        }
    }

    Ok(lpm_config
        .and_then(|config| config.tasks.get(script_name))
        .and_then(|task| task.command.clone()))
}

fn print_run_metadata(cache_status: &str, command: Option<&str>) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{:<8}", "cache")),
        cache_status,
    ));
    if let Some(command) = command {
        let command = lpm_common::sanitize_terminal_inline(command);
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<8}", "command")),
            command,
        ));
    }
    install_ui::detail("");
}

/// Run a script from package.json (single package).
///
/// Delegates to `lpm_runner::script::run_script()` which provides:
/// - PATH injection (`node_modules/.bin` prepended)
/// - `.env` file loading (auto + `--env` flag + `lpm.json` mapping)
/// - Pre/post script hooks (npm convention)
/// - Task caching (when enabled in `lpm.json`)
///
/// **Caller contract:** invoke [`ensure_runtime`] first and pass its return
/// value as `bin_hint`; doing so surfaces the runtime notice, performs
/// auto-install when needed, and avoids re-probing the runtime for the script.
pub async fn run(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    bin_hint: &ManagedRuntimeHint,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    run_with_reserved_stdout(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        no_cache,
        bin_hint,
        session,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_with_reserved_stdout(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_cache: bool,
    bin_hint: &ManagedRuntimeHint,
    session: Option<Arc<lpm_auth::SessionManager>>,
    reserve_stdout: bool,
) -> Result<(), LpmError> {
    // Read lpm.json once so the cache lookup and task predicate share the same config.
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    let command = script_command_for_display(project_dir, script_name, lpm_config.as_ref())?;
    let cache_context = if no_cache {
        None
    } else {
        prepare_package_script_cache_context(
            project_dir,
            script_name,
            env_mode,
            extra_args,
            bin_hint,
            lpm_config.as_ref(),
            session,
        )?
    };
    let caching_enabled = cache_context.is_some();

    if let Some(hit) = cache_context
        .as_ref()
        .map(|context| try_cache_hit_with_context(project_dir, context))
        .transpose()?
        .flatten()
    {
        // Cache hit — replay output
        if !hit.stdout.is_empty() {
            if reserve_stdout {
                print_captured_stderr(&hit.stdout);
            } else {
                print_captured_stdout(&hit.stdout);
            }
        }
        if !hit.stderr.is_empty() {
            print_captured_stderr(&hit.stderr);
        }
        install_ui::done_line(crate::install_ui::terminal_line!(
            "{} · restored from {} (originally {})",
            install_ui::yellow(script_name),
            install_ui::dim("cache"),
            install_ui::green(&install_ui::format_duration(
                std::time::Duration::from_millis(hit.meta.duration_ms)
            )),
        ));
        return Ok(());
    }

    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Running {}",
        install_ui::yellow(script_name)
    ));
    let cache_status = if no_cache {
        "disabled"
    } else if caching_enabled {
        "miss"
    } else {
        "disabled"
    };
    print_run_metadata(cache_status, command.as_deref());

    let start = std::time::Instant::now();

    if caching_enabled || reserve_stdout {
        // Run with tee capture (output streams to terminal + captured for cache)
        let output = lpm_runner::script::run_script_captured_with_reserved_stdout(
            project_dir,
            script_name,
            extra_args,
            env_mode,
            bin_hint,
            reserve_stdout,
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;
        if let Some(context) = cache_context.as_ref() {
            let _ = try_cache_store_with_context(
                CacheStoreRequest {
                    project_dir,
                    workspace_contract: None,
                    script_name,
                    env_mode,
                    extra_args,
                    bin_hint,
                    duration_ms,
                    stdout: &output.stdout,
                    stderr: &output.stderr,
                },
                context,
            );
        }
    } else {
        // Run normally (inherited stdio, no capture)
        lpm_runner::script::run_script(project_dir, script_name, extra_args, env_mode, bin_hint)?;
    }

    install_ui::done_line(crate::install_ui::terminal_line!(
        "{} · success in {}",
        install_ui::yellow(script_name),
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));

    Ok(())
}

/// Rerun a finite task graph after its inputs change, bypassing caches.
#[allow(clippy::too_many_arguments)]
pub fn run_watch(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: ManagedRuntimeHint,
    parallel: bool,
    continue_on_error: bool,
    stream: bool,
) -> Result<(), LpmError> {
    let script = script_name.to_string();
    let plan = super::prepare_single_package_task_plan(project_dir, std::slice::from_ref(&script))?;
    let filter = lpm_task::watch::WatchFilterHandle::new(task_watch_filter(project_dir, &plan)?);
    let cycle_filter = filter.clone();
    install_ui::phase_untrusted(&format!(
        "Watching {} (Ctrl+C to stop)",
        lpm_common::sanitize_terminal_inline(&script)
    ));
    let args = extra_args.to_vec();
    let mode = env_mode.map(str::to_string);
    let dir = project_dir.to_path_buf();
    lpm_task::watch::watch_and_run_with_filter(
        project_dir,
        Box::new(move || {
            let mut stderr = std::io::stderr();
            if stderr.is_terminal() {
                let _ = write!(stderr, "\x1B[2J\x1B[1;1H");
                let _ = stderr.flush();
            }
            let result = (|| {
                let plan =
                    super::prepare_single_package_task_plan(&dir, std::slice::from_ref(&script))?;
                cycle_filter.replace(task_watch_filter(&dir, &plan)?);
                super::execute_single_package_task_plan(
                    &dir,
                    &plan,
                    &args,
                    mode.as_deref(),
                    super::TaskExecutionOptions {
                        parallel,
                        continue_on_error,
                        stream,
                        no_cache: true,
                        json_output: false,
                    },
                    &bin_hint,
                    None,
                )?
                .into_result()
            })();
            match result {
                Ok(()) => install_ui::done_line(crate::install_ui::terminal_line!(
                    "{} completed. Waiting for changes...",
                    install_ui::yellow(&script)
                )),
                Err(error) => {
                    install_ui::failed_line(crate::install_ui::terminal_line!(
                        "{}: {}",
                        install_ui::yellow(&script),
                        lpm_common::sanitize_for_terminal(&error.to_string())
                    ));
                    install_ui::detail("  Waiting for changes...");
                }
            }
        }),
        filter,
        None,
    )
    .map_err(|error| LpmError::Script(format!("watch error: {error}")))
}

fn task_watch_filter(
    project_dir: &Path,
    plan: &super::SinglePackageTaskPlan,
) -> Result<lpm_task::watch::WatchFilter, LpmError> {
    let mut inputs = std::collections::BTreeSet::new();
    let mut outputs = std::collections::BTreeSet::new();
    let mut all_inputs = false;
    for task_name in plan.levels.iter().flatten() {
        let task = plan.tasks().get(task_name);
        if let Some(task) = task {
            outputs.extend(task.outputs.iter().cloned());
        }
        if super::task::is_meta_task(task_name, plan.tasks(), plan.package_scripts.as_ref()) {
            continue;
        }
        if let Some(task) = task {
            inputs.extend(task.effective_inputs());
        } else {
            all_inputs = true;
        }
    }
    let inputs = if all_inputs {
        Vec::new()
    } else {
        inputs.into_iter().collect::<Vec<_>>()
    };
    lpm_task::watch::WatchFilter::new(
        project_dir,
        &inputs,
        &outputs.into_iter().collect::<Vec<_>>(),
    )
    .map(lpm_task::watch::WatchFilter::with_config_files)
    .map_err(LpmError::Script)
}

/// Run a project-local binary from node_modules/.bin.
pub async fn exec(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
) -> Result<(), LpmError> {
    let bin_hint = prepare_runtime(project_dir, false).await?;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Executing {}",
        install_ui::yellow(command_name)
    ));
    let start = std::time::Instant::now();
    lpm_runner::script::run_local_bin(
        project_dir,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        &bin_hint,
    )?;
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · exited 0 in {}",
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

/// Execute a source file directly, auto-detecting the runtime.
pub async fn run_file(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
) -> Result<(), LpmError> {
    let bin_hint = prepare_runtime(project_dir, false).await?;
    let options = exec_options(env_mode, no_env_check, plain_node, bin_hint);
    exec_once(project_dir, file_path, extra_args, &options)
}

fn exec_once(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    options: &lpm_runner::exec::ExecOptions,
) -> Result<(), LpmError> {
    let plan = lpm_runner::exec::build_exec_plan(project_dir, file_path, extra_args, options)?;
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Executing {} with {}",
        lpm_common::sanitize_terminal_inline(file_path),
        install_ui::yellow(&plan.runtime_label())
    ));
    let start = std::time::Instant::now();
    lpm_runner::exec::execute_exec_plan(project_dir, &plan)?;
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · exited 0 in {}",
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

pub async fn run_file_watch(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
) -> Result<(), LpmError> {
    let bin_hint = prepare_runtime(project_dir, false).await?;
    let options = exec_options(env_mode, no_env_check, plain_node, bin_hint);
    let plan = lpm_runner::exec::build_exec_plan(project_dir, file_path, extra_args, &options)?;
    let signals = Arc::new(lpm_runner::execution::ExecutionSignals::new()?);
    let run_signals = Arc::clone(&signals);

    install_ui::phase_untrusted(&format!(
        "Watching {} (Ctrl+C to stop)",
        lpm_common::sanitize_terminal_inline(file_path)
    ));

    let dir = project_dir.to_path_buf();
    let file = file_path.to_string();
    let watched_file = plan.resolved_path.clone();
    let plan_for_watch = plan;

    lpm_task::watch::watch_file_and_run(
        &watched_file,
        Box::new(move || {
            let mut stderr = std::io::stderr();
            if stderr.is_terminal() {
                let _ = write!(stderr, "\x1B[2J\x1B[1;1H");
                let _ = stderr.flush();
            }

            install_ui::phase_line(crate::install_ui::terminal_line!(
                "watch executing {} with {}",
                install_ui::yellow(&file),
                install_ui::yellow(&plan_for_watch.runtime_label())
            ));
            let start = std::time::Instant::now();

            match lpm_runner::exec::execute_exec_plan_with_signals(
                &dir,
                &plan_for_watch,
                &run_signals,
            ) {
                Ok(()) => {
                    install_ui::done_line(crate::install_ui::terminal_line!(
                        "{} completed in {}. Waiting for changes...",
                        install_ui::yellow(&file),
                        install_ui::green(&install_ui::format_duration(start.elapsed())),
                    ));
                }
                Err(e) => {
                    install_ui::failed_line(crate::install_ui::terminal_line!(
                        "{}: {}",
                        install_ui::yellow(&file),
                        lpm_common::sanitize_for_terminal(&e.to_string())
                    ));
                    install_ui::detail("  Waiting for changes...");
                }
            }
        }),
        || signals.is_stopped(),
    )
    .map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

    signals.check()
}

fn exec_options(
    env_mode: Option<&str>,
    no_env_check: bool,
    plain_node: bool,
    managed_runtime_hint: lpm_runner::bin_path::ManagedRuntimeHint,
) -> lpm_runner::exec::ExecOptions {
    lpm_runner::exec::ExecOptions {
        env_mode: env_mode.map(str::to_string),
        no_env_check,
        managed_runtime_hint,
        plain_node,
        runtime_cache_root: None,
    }
}
