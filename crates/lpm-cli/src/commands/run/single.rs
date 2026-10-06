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

#[derive(Default)]
struct FileWatchConfig {
    captured: Option<Result<Option<lpm_runner::lpm_json::LpmJsonConfig>, String>>,
    paths: Vec<String>,
    root_digest: Option<[u8; 32]>,
}

impl FileWatchConfig {
    fn paths(&mut self, project_dir: &Path) -> Vec<String> {
        use sha2::{Digest, Sha256};
        let root = match lpm_common::read_text_file_capped(
            &project_dir.join("lpm.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => Ok(Some(content)),
            Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(None),
            Err(error) => Err(format!("failed to read lpm.json: {error}")),
        };
        let digest = root
            .as_ref()
            .ok()
            .and_then(|content| content.as_ref())
            .map(|content| Sha256::digest(content.as_bytes()).into());
        let reusable = root.is_ok()
            && digest == self.root_digest
            && self.captured.as_ref().is_some_and(|config| match config {
                Ok(config) => config
                    .as_ref()
                    .and_then(|config| config.env_schema_resolution.as_ref())
                    .is_none_or(|snapshot| snapshot.verify_dependencies().is_ok()),
                Err(_) => false,
            });
        if !reusable {
            let config = root
                .map_err(|message| (message, Vec::new()))
                .and_then(|content| {
                    content
                        .map(|content| {
                            lpm_runner::lpm_json::parse_lpm_json_in_detailed(project_dir, &content)
                        })
                        .transpose()
                        .map_err(|error| {
                            let paths = match &error {
                                lpm_runner::lpm_json::ConfigReadError::Schema { error, .. } => {
                                    error.requested_paths.clone()
                                }
                                _ => Vec::new(),
                            };
                            (error.to_string(), paths)
                        })
                });
            self.paths = match &config {
                Ok(config) => config
                    .as_ref()
                    .and_then(|config| config.env_schema_resolution.as_ref())
                    .map(|snapshot| {
                        snapshot
                            .dependencies
                            .iter()
                            .map(|dependency| dependency.path.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                Err((_, paths)) => paths.clone(),
            };
            let config = config.map_err(|(message, _)| message);
            self.root_digest = digest;
            self.captured = Some(config);
        }
        self.paths.clone()
    }
}

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
    let env_access = lpm_runner::env_access::EnvAccessScope::current_or_new();
    let _env_access_binding = env_access.bind();
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
        env_access.check()?;
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
        let output = lpm_runner::script::run_script_captured_with_config(
            project_dir,
            script_name,
            extra_args,
            env_mode,
            bin_hint,
            reserve_stdout,
            lpm_config.as_ref(),
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
        lpm_runner::script::run_script_with_config(
            project_dir,
            script_name,
            extra_args,
            env_mode,
            bin_hint,
            lpm_config.as_ref(),
        )?;
    }

    env_access.check()?;
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
    let filter = match lpm_runner::lpm_json::read_lpm_json_detailed(project_dir) {
        Ok(config) => {
            let plan = super::prepare_single_package_task_plan_with_config(
                project_dir,
                std::slice::from_ref(&script),
                config,
            )?;
            task_watch_filter(project_dir, &plan)?
        }
        Err(lpm_runner::lpm_json::ConfigReadError::Schema { error, config }) => {
            let plan = super::prepare_single_package_task_plan_with_config(
                project_dir,
                std::slice::from_ref(&script),
                Some(*config),
            )?;
            task_watch_filter(project_dir, &plan)?.with_config_dependencies(&error.requested_paths)
        }
        Err(error) => return Err(LpmError::Script(error.to_string())),
    };
    let filter = lpm_task::watch::WatchFilterHandle::new(filter);
    let cycle_filter = filter.clone();
    install_ui::phase_untrusted(&format!(
        "Watching {} (Ctrl+C to stop)",
        lpm_common::sanitize_terminal_inline(&script)
    ));
    let args = extra_args.to_vec();
    let mode = env_mode.map(str::to_string);
    let dir = project_dir.to_path_buf();
    let env_access = lpm_runner::env_access::EnvAccessScope::default();
    let cycle_env_access = env_access.clone();
    lpm_task::watch::watch_and_run_until(
        project_dir,
        Box::new(move || {
            let mut stderr = std::io::stderr();
            if stderr.is_terminal() {
                let _ = write!(stderr, "\x1B[2J\x1B[1;1H");
                let _ = stderr.flush();
            }
            let result = cycle_env_access.run(|| {
                let config = match lpm_runner::lpm_json::read_lpm_json_detailed(&dir) {
                    Ok(config) => config,
                    Err(error) => {
                        if let lpm_runner::lpm_json::ConfigReadError::Schema { error, .. } = &error
                        {
                            cycle_filter.replace_config_dependencies(&error.requested_paths);
                        }
                        return Err(LpmError::Script(error.to_string()));
                    }
                };
                let plan = super::prepare_single_package_task_plan_with_config(
                    &dir,
                    std::slice::from_ref(&script),
                    config,
                )?;
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
            });
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
        || env_access.check().is_err(),
    )
    .map_err(|error| LpmError::Script(format!("watch error: {error}")))?;
    env_access.check()
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
    .map(|filter| {
        let paths: Vec<_> = plan
            .config
            .as_ref()
            .and_then(|config| config.env_schema_resolution.as_ref())
            .map(|snapshot| {
                snapshot
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.path.clone())
                    .collect()
            })
            .unwrap_or_default();
        filter.with_config_files().with_config_dependencies(&paths)
    })
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
    let env_access = lpm_runner::env_access::EnvAccessScope::default();
    let cycle_env_access = env_access.clone();

    let watch_dir = project_dir.to_path_buf();
    let cycle_config = Arc::new(std::sync::Mutex::new(FileWatchConfig::default()));
    let capture_config = Arc::clone(&cycle_config);
    lpm_task::watch::watch_file_and_run_with_config(
        &watched_file,
        project_dir,
        Box::new(move || {
            let mut cycle = capture_config
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            cycle.paths(&watch_dir)
        }),
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

            match cycle_env_access.run(|| {
                let config = cycle_config
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .captured
                    .take()
                    .ok_or_else(|| {
                        LpmError::Script("missing file watch configuration snapshot".into())
                    })?
                    .map_err(LpmError::Script)?;
                lpm_runner::exec::execute_exec_plan_with_config_and_signals(
                    &dir,
                    &plan_for_watch,
                    config.as_ref(),
                    &run_signals,
                )
            }) {
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
        || signals.is_stopped() || env_access.check().is_err(),
    )
    .map_err(|e| LpmError::Script(format!("watch error: {e}")))?;

    env_access.check()?;
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
        recorded_node_versions: crate::engine_check::recorded_node_versions(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn file_watch_initial_execution_reloads_sources_changed_during_registration() {
        for scenario in ["root", "fragment", "missing-import", "missing-root"] {
            let project = tempfile::tempdir().expect("project");
            let root = project.path().join("lpm.json");
            let fragment = project.path().join("base.json");
            if scenario != "missing-root" {
                let content = if scenario == "root" {
                    r#"{"envSchema":{"vars":{}}}"#
                } else {
                    r#"{"envSchema":{"extends":["base.json"]}}"#
                };
                std::fs::write(&root, content).expect("root");
            }
            if scenario == "fragment" {
                std::fs::write(&fragment, r#"{"vars":{"VALUE":{"default":"before"}}}"#)
                    .expect("fragment");
            }
            let entry = project.path().join("entry.cjs");
            std::fs::write(&entry, "").expect("entry");
            let captured = Arc::new(std::sync::Mutex::new(FileWatchConfig::default()));
            let capture = Arc::clone(&captured);
            let dir = project.path().to_path_buf();
            let stop = Arc::new(AtomicBool::new(false));
            let finished = Arc::clone(&stop);
            let mut first = true;
            lpm_task::watch::watch_file_and_run_with_config(
                &entry,
                project.path(),
                Box::new(move || {
                    let paths = capture.lock().expect("capture").paths(&dir);
                    if first {
                        first = false;
                        if scenario == "root" || scenario == "missing-root" {
                            std::fs::write(
                                &root,
                                r#"{"envSchema":{"vars":{"VALUE":{"default":"after!"}}}}"#,
                            )
                            .expect("replace root");
                        } else {
                            std::fs::write(&fragment, r#"{"vars":{"VALUE":{"default":"after!"}}}"#)
                                .expect("replace fragment");
                        }
                    }
                    paths
                }),
                Box::new(move || {
                    let config = captured
                        .lock()
                        .expect("capture")
                        .captured
                        .take()
                        .expect("captured")
                        .expect("repaired config")
                        .expect("root config");
                    let schema = config.env_schema.expect("schema");
                    assert_eq!(
                        schema.vars["VALUE"].default.as_deref(),
                        Some("after!"),
                        "{scenario}"
                    );
                    finished.store(true, Ordering::SeqCst);
                }),
                || stop.load(Ordering::SeqCst),
            )
            .expect("watch registration");
        }
    }

    #[test]
    fn file_watch_unchanged_initial_capture_reuses_the_resolved_graph() {
        let project = tempfile::tempdir().expect("project");
        std::fs::write(
            project.path().join("lpm.json"),
            r#"{"envSchema":{"vars":{}}}"#,
        )
        .expect("root");
        let mut cycle = FileWatchConfig::default();
        cycle.paths(project.path());
        let snapshot = Arc::clone(
            cycle
                .captured
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .env_schema_resolution
                .as_ref()
                .unwrap(),
        );
        cycle.paths(project.path());
        let current = cycle
            .captured
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .env_schema_resolution
            .as_ref()
            .unwrap();
        assert!(Arc::ptr_eq(&snapshot, current));
    }
}
