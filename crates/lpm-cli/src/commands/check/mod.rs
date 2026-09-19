mod arguments;

use self::arguments::Arguments;
use super::tool_execution::{
    StdioMode, ToolOutcome, emit_envelope, finish_single_tool, member_result,
    selected_schedule_state,
};
use super::tool_runtime::InstalledRuntimes;
use crate::{CheckEngine, install_ui};
use futures::stream::{FuturesUnordered, StreamExt};
use lpm_common::LpmError;
use lpm_runner::execution::ExecutionSignals;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

struct Prepared {
    entry: PathBuf,
    path: Option<String>,
    arguments: Arguments,
}

fn preflight(cwd: &Path, args: &[String]) -> Result<(), LpmError> {
    if args.is_empty()
        && !cwd
            .ancestors()
            .any(|dir| dir.join("tsconfig.json").is_file())
    {
        return Err(LpmError::Script(format!(
            "no tsconfig.json found in {} or its ancestors. Add one or pass `-p <path>`",
            cwd.display()
        )));
    }
    Ok(())
}

fn prepare_tsc(
    cwd: &Path,
    boundary: &Path,
    runtimes: &InstalledRuntimes,
    arguments: Arguments,
) -> Result<Prepared, LpmError> {
    let status = crate::tsc_status::TscStatus::probe_bounded(cwd, boundary);
    let entry = status.local_bin.or(status.system_bin).ok_or_else(|| {
        LpmError::Script(if status.in_deps {
            "typescript declared in package.json but not installed. Run: lpm install".into()
        } else {
            "typescript not installed. Run: lpm install -D typescript".into()
        })
    })?;
    Ok(Prepared {
        entry,
        path: Some(runtimes.path_for(cwd)?),
        arguments,
    })
}

async fn run(
    cwd: &Path,
    task: &Prepared,
    stdio: StdioMode,
    signals: Arc<ExecutionSignals>,
) -> ToolOutcome {
    let mut command = Command::new(&task.entry);
    command.args(&task.arguments.values).current_dir(cwd);
    if let Some(path) = &task.path {
        command.env("PATH", path);
    }
    super::tool_execution::run(command, stdio, signals).await
}

pub async fn check(
    cwd: &Path,
    args: &[String],
    engine: CheckEngine,
    json_output: bool,
) -> Result<(), LpmError> {
    preflight(cwd, args)?;
    let arguments = Arguments::prepare(cwd, args, engine)?;
    validate_watch(arguments.watch, 1, json_output)?;
    let task = match engine {
        CheckEngine::Tsc => {
            let boundary = super::tool_runtime::boundary(cwd)?;
            prepare_tsc(
                cwd,
                &boundary,
                &InstalledRuntimes::new(&boundary)?,
                arguments,
            )?
        }
        CheckEngine::Tsgo => Prepared {
            entry: lpm_plugin::ensure_engine("tsgo", None, json_output).await?,
            path: None,
            arguments,
        },
    };
    if !json_output {
        super::tools_ui::using_check_engine(match engine {
            CheckEngine::Tsc => "tsc",
            CheckEngine::Tsgo => "tsgo",
        });
    }
    let signals = Arc::new(ExecutionSignals::new()?);
    let start = std::time::Instant::now();
    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };
    let outcome = run(cwd, &task, stdio, Arc::clone(&signals)).await;
    if json_output {
        return finish_single_tool(cwd, outcome, start.elapsed(), &signals);
    }
    signals.check()?;
    if let Some(code) = outcome.exit_code
        && code != 0
    {
        super::tools_ui::failed("typecheck", code);
    }
    outcome.into_result()?;
    super::tools_ui::done_typecheck(start.elapsed());
    Ok(())
}

fn validate_watch(watch: bool, selected: usize, json: bool) -> Result<(), LpmError> {
    if watch && json {
        return Err(LpmError::Script(
            "--watch cannot be combined with --json for lpm check".into(),
        ));
    }
    if watch && selected != 1 {
        return Err(LpmError::Script(format!(
            "check watch mode requires exactly one selected workspace member (selected {selected})"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn workspace(
    cwd: &Path,
    args: &[String],
    engine: CheckEngine,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    affected_base: Option<&str>,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(cwd)
        .map_err(|error| LpmError::Script(format!("workspace error: {error}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "no workspace found. --all/--filter/--affected require a monorepo".into(),
            )
        })?;
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
    let targets = crate::workspace_select::select_workspace_target_set(
        &graph,
        &workspace.root,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        affected_base.is_some(),
        affected_base.unwrap_or("main"),
    )?;
    if targets.is_empty() {
        let arguments = Arguments::prepare(cwd, args, engine)?;
        validate_watch(arguments.watch, 0, json_output)?;
        if fail_if_no_match {
            return Err(LpmError::Script(
                "no workspace packages matched the filter (--fail-if-no-match)".into(),
            ));
        }
        if json_output {
            emit_envelope(
                &[],
                0,
                0,
                0,
                std::time::Duration::ZERO,
                &ExecutionSignals::new()?,
            )?;
        } else {
            install_ui::warn("No packages matched");
            if let Some(hint) = super::filter::format_no_match_hint_for_sets(filters, filter_prod) {
                eprintln!("\n{hint}\n");
            }
        }
        return Ok(());
    }
    let (mut unmet, mut ready) = selected_schedule_state(&graph, &targets)?;
    let mut arguments = Vec::with_capacity(graph.len());
    for (index, member) in graph.members.iter().enumerate() {
        if !targets.contains(&index) {
            arguments.push(Err("member not selected".to_string()));
            continue;
        }
        let value = Arguments::prepare(&member.path, args, engine);
        if let Ok(value) = &value {
            validate_watch(value.watch, targets.len(), json_output)?;
        }
        arguments.push(value.map_err(|error| error.to_string()));
    }
    let any_valid = arguments.iter().any(Result::is_ok);
    let native = if any_valid && matches!(engine, CheckEngine::Tsgo) {
        Some(
            lpm_plugin::ensure_engine("tsgo", None, json_output)
                .await
                .map_err(|error| error.to_string()),
        )
    } else {
        None
    };
    let runtimes = if any_valid && matches!(engine, CheckEngine::Tsc) {
        Some(InstalledRuntimes::new(&workspace.root)?)
    } else {
        None
    };
    let tasks = graph
        .members
        .iter()
        .zip(arguments)
        .map(|(member, arguments)| {
            arguments.and_then(|arguments| match &native {
                Some(entry) => entry.clone().map(|entry| Prepared {
                    entry,
                    path: None,
                    arguments,
                }),
                None => runtimes
                    .as_ref()
                    .ok_or_else(|| "runtime selection is unavailable".to_string())
                    .and_then(|runtimes| {
                        prepare_tsc(&member.path, &workspace.root, runtimes, arguments)
                            .map_err(|error| error.to_string())
                    }),
            })
        })
        .collect::<Vec<_>>();
    let signals = Arc::new(ExecutionSignals::new()?);
    let start = std::time::Instant::now();
    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };
    let limit = std::thread::available_parallelism().map_or(4, |count| count.get());
    let mut running = FuturesUnordered::new();
    let mut results = Vec::with_capacity(targets.len());
    loop {
        while running.len() < limit {
            let Some(index) = ready.pop_front() else {
                break;
            };
            let member = &graph.members[index];
            let task = &tasks[index];
            let signals = Arc::clone(&signals);
            running.push(async move {
                let started = std::time::Instant::now();
                if !json_output {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "  {} check",
                        install_ui::bold(&format!("[{}]", member.name))
                    ));
                }
                let outcome = match task {
                    Ok(task) => run(&member.path, task, stdio, signals).await,
                    Err(error) => ToolOutcome {
                        error: Some(error.clone()),
                        ..Default::default()
                    },
                };
                (
                    index,
                    member_result(member.name.clone(), outcome, started.elapsed()),
                )
            });
        }
        let Some((index, result)) = running.next().await else {
            break;
        };
        results.push((index, result));
        for &dependent in &graph.reverse_edges[index] {
            if targets.contains(&dependent) {
                unmet[dependent] -= 1;
                if unmet[dependent] == 0 {
                    ready.push_back(dependent);
                }
            }
        }
    }
    results.sort_unstable_by_key(|(index, _)| *index);
    let results = results
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    let succeeded = results.iter().filter(|result| result.success).count();
    let failed = results.len() - succeeded;
    if json_output {
        emit_envelope(
            &results,
            results.len(),
            succeeded,
            failed,
            start.elapsed(),
            &signals,
        )?;
    } else {
        for result in &results {
            if let Some(error) = &result.error {
                install_ui::failed_untrusted(&format!("{}: {error}", result.name));
            }
        }
        if failed == 0 {
            install_ui::done_untrusted(&format!("Typecheck complete: {succeeded} packages passed"));
        } else {
            install_ui::failed_untrusted(&format!(
                "Typecheck failed: {failed} of {} packages failed",
                results.len()
            ));
        }
    }
    signals.check()?;
    if failed > 0 {
        return Err(LpmError::ExitCode(1));
    }
    Ok(())
}
