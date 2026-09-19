use super::tool_execution::{
    StdioMode, ToolOutcome, emit_envelope, finish_single_tool, member_result,
    selected_schedule_state,
};
use super::tool_runtime::InstalledRuntimes;
use crate::{BundleFormat, BundlePlatform, install_ui};
use futures::stream::{FuturesUnordered, StreamExt};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_runner::execution::ExecutionSignals;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct BundleOptions {
    pub entry: Option<String>,
    pub out_dir: Option<String>,
    pub config: Option<String>,
    pub format: Option<BundleFormat>,
    pub platform: Option<BundlePlatform>,
    pub minify: bool,
    pub sourcemap: bool,
    pub args: Vec<String>,
}

impl BundleOptions {
    fn rolldown_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(config) = &self.config {
            args.push("--config".to_string());
            args.push(config.clone());
        }
        if let Some(entry) = &self.entry {
            args.push("--input".to_string());
            args.push(entry.clone());
        }
        if let Some(out_dir) = &self.out_dir {
            args.push("--dir".to_string());
            args.push(out_dir.clone());
        }
        if let Some(format) = self.format {
            args.push("--format".to_string());
            args.push(format.as_cli_value().to_string());
        }
        if let Some(platform) = self.platform {
            args.push("--platform".to_string());
            args.push(platform.as_cli_value().to_string());
        }
        if self.minify {
            args.push("--minify".to_string());
        }
        if self.sourcemap {
            args.push("--sourcemap".to_string());
        }

        args.extend(self.args.iter().cloned());
        args
    }
}

impl BundleFormat {
    fn as_cli_value(self) -> &'static str {
        match self {
            Self::Esm => "esm",
            Self::Cjs => "cjs",
            Self::Iife => "iife",
        }
    }
}

impl BundlePlatform {
    fn as_cli_value(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Browser => "browser",
            Self::Neutral => "neutral",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    project_dir: &Path,
    options: &BundleOptions,
    all: bool,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    affected: bool,
    base_ref: &str,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if args_imply_watch(&options.args) && json_output {
        return Err(LpmError::Script(
            "--watch cannot be combined with --json for lpm bundle".into(),
        ));
    }
    if all || affected || !filters.is_empty() || !filter_prod.is_empty() {
        bundle_workspace(
            project_dir,
            options,
            filters,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            if affected { Some(base_ref) } else { None },
            fail_if_no_match,
            json_output,
        )
        .await
    } else {
        bundle(project_dir, options, json_output).await
    }
}

pub async fn bundle(
    project_dir: &Path,
    options: &BundleOptions,
    json_output: bool,
) -> Result<(), LpmError> {
    if args_imply_watch(&options.args) && json_output {
        return Err(LpmError::Script(
            "--watch cannot be combined with --json for lpm bundle".into(),
        ));
    }
    let pin = super::tools::effective_tool_version(project_dir, "rolldown")?;
    let version =
        lpm_plugin::resolve_engine_version_for_current_platform("rolldown", pin.as_deref())?;
    let runtimes = InstalledRuntimes::new(&super::tool_runtime::boundary(project_dir)?)?;
    let path = runtimes.path_for(project_dir)?;
    let entry = lpm_plugin::ensure_engine("rolldown", pin.as_deref(), json_output).await?;
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Bundling with {} {}",
            install_ui::yellow("Rolldown"),
            version
        ));
    }
    let start = std::time::Instant::now();
    let signals = Arc::new(ExecutionSignals::new()?);
    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };
    let outcome = run_bundle_process(
        project_dir,
        &entry,
        &path,
        options,
        stdio,
        Arc::clone(&signals),
    )
    .await;
    if json_output {
        return finish_single_tool(project_dir, outcome, start.elapsed(), &signals);
    }
    if outcome.success() {
        let duration = install_ui::format_duration(start.elapsed());
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · bundled in {}",
            install_ui::green(&duration)
        ));
    } else if let Some(code) = outcome.exit_code {
        install_ui::failed_untrusted(&format!("bundle failed · exit code {code}"));
    }
    signals.check()?;
    outcome.into_result()
}

async fn run_bundle_process(
    project_dir: &Path,
    entry: &Path,
    path: &str,
    options: &BundleOptions,
    stdio: StdioMode,
    signals: Arc<ExecutionSignals>,
) -> ToolOutcome {
    let mut command = Command::new("node");
    command
        .arg(entry)
        .args(options.rolldown_args())
        .current_dir(project_dir)
        .env("PATH", path);
    let mut outcome = super::tool_execution::run(command, stdio, signals).await;
    if let Some(error) = &mut outcome.error {
        error.push_str(". Install Node via `lpm use node@22` or ensure `node` is on PATH");
    }
    outcome
}

fn args_imply_watch(args: &[String]) -> bool {
    let mut args = args.iter().peekable();
    let mut selected_alias = None;
    let mut watching = false;
    // CAC keeps each spelling separately, then copies the first alias over the others.
    // Repeated values of that spelling use the last value, including short clusters.
    let mut record = |alias, value| {
        if *selected_alias.get_or_insert(alias) == alias {
            watching = value;
        }
    };
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        let name = arg.trim_start_matches('-');
        let dashes = arg.len() - name.len();
        if dashes == 0 {
            continue;
        }
        if let Some(negated) = name.strip_prefix("no-") {
            match negated {
                "watch" => record("watch", false),
                "w" => record("w", false),
                _ => {}
            }
            continue;
        }
        let (name, assigned) = name.split_once('=').unwrap_or((name, ""));
        let value = if !assigned.is_empty() {
            assigned
        } else if args.peek().is_some_and(|next| !next.starts_with('-')) {
            args.next().map_or("true", String::as_str)
        } else {
            "true"
        };
        if dashes == 2 {
            match name {
                "watch" => record("watch", !value.is_empty() && value != "false"),
                "w" => record("w", !value.is_empty() && value != "false"),
                _ => {}
            }
        } else {
            let mut chars = name.chars().peekable();
            while let Some(short) = chars.next() {
                if short == 'w' {
                    record(
                        "w",
                        chars.peek().is_some() || !value.is_empty() && value != "false",
                    );
                }
            }
        }
    }
    watching
}

#[allow(clippy::too_many_arguments)]
async fn bundle_workspace(
    project_dir: &Path,
    options: &BundleOptions,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    affected_base: Option<&str>,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
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
    if args_imply_watch(&options.args) && targets.len() != 1 {
        return Err(LpmError::Script(format!(
            "bundle watch mode requires exactly one selected workspace member (selected {})",
            targets.len()
        )));
    }
    if targets.is_empty() {
        let affected_only = filters.is_empty() && filter_prod.is_empty() && affected_base.is_some();
        if fail_if_no_match {
            let message = if affected_only {
                format!(
                    "no workspace packages affected vs {} (--fail-if-no-match)",
                    affected_base.unwrap_or("main")
                )
            } else {
                let base = "no workspace packages matched the filter (--fail-if-no-match)";
                crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod)
                    .map_or_else(|| base.into(), |hint| format!("{base}\n\n{hint}"))
            };
            return Err(LpmError::Script(message));
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
        } else if affected_only {
            install_ui::done_untrusted(&format!(
                "no packages affected vs {} — nothing to bundle",
                affected_base.unwrap_or("main")
            ));
        } else {
            install_ui::warn("No packages matched");
            if let Some(hint) =
                crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod)
            {
                eprintln!("\n{hint}\n");
            }
        }
        return Ok(());
    }
    let (mut unmet, mut ready) = selected_schedule_state(&graph, &targets)?;
    let root_pin = super::tools::read_tool_version(&workspace.root, "rolldown")?;
    let runtimes = InstalledRuntimes::new(&workspace.root)?;
    let mut engines = HashMap::new();
    let mut prepared = Vec::with_capacity(graph.len());
    for (index, member) in graph.members.iter().enumerate() {
        if !targets.contains(&index) {
            prepared.push(Err("member not selected".into()));
            continue;
        }
        let result = async {
            let pin = super::tools::read_tool_version(&member.path, "rolldown")?
                .or_else(|| root_pin.clone());
            let path = runtimes.path_for(&member.path)?;
            if !engines.contains_key(&pin) {
                let entry = lpm_plugin::ensure_engine("rolldown", pin.as_deref(), json_output)
                    .await
                    .map_err(|error| error.to_string());
                engines.insert(pin.clone(), entry);
            }
            let entry = engines[&pin].clone().map_err(LpmError::Script)?;
            Ok::<_, LpmError>((entry, path))
        }
        .await
        .map_err(|error| error.to_string());
        prepared.push(result);
    }
    let start = std::time::Instant::now();
    let signals = Arc::new(ExecutionSignals::new()?);
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
            let task = &prepared[index];
            let task_signals = Arc::clone(&signals);
            running.push(async move {
                let started = std::time::Instant::now();
                if !json_output {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "  {} bundle",
                        install_ui::bold(&format!("[{}]", member.name))
                    ));
                }
                let outcome = match task {
                    Ok((entry, path)) => {
                        run_bundle_process(&member.path, entry, path, options, stdio, task_signals)
                            .await
                    }
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
        emit_human_summary(
            "bundle",
            results.len(),
            succeeded,
            failed,
            targets.len(),
            start.elapsed(),
        );
    }
    signals.check()?;
    if failed > 0 {
        Err(LpmError::ExitCode(1))
    } else {
        Ok(())
    }
}

fn emit_human_summary(
    tool: &str,
    total: usize,
    succeeded: usize,
    failed: usize,
    targeted: usize,
    elapsed: std::time::Duration,
) {
    if failed == 0 {
        let duration = install_ui::format_duration(elapsed);
        install_ui::done_line(crate::install_ui::terminal_line!(
            "{} passed in {} {} in {}",
            tool,
            install_ui::bold(&total.to_string()),
            install_ui::packages_word(total),
            install_ui::green(&duration)
        ));
        if targeted > total {
            eprintln!(
                "  {} {} targeted",
                "·".dimmed(),
                format!("{targeted} packages").dimmed(),
            );
        }
    } else {
        let duration = install_ui::format_duration(elapsed);
        install_ui::failed_untrusted(&format!(
            "{tool}: {succeeded} passed, {failed} failed out of {total} packages in {duration}"
        ));
    }
}
