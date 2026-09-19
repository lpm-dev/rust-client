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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct PackOptions {
    pub entry: Option<String>,
    pub out_dir: Option<String>,
    pub config: Option<String>,
    pub tsconfig: Option<String>,
    pub target: Option<String>,
    pub format: Option<BundleFormat>,
    pub platform: Option<BundlePlatform>,
    pub dts: bool,
    pub minify: bool,
    pub sourcemap: bool,
    pub args: Vec<String>,
}

impl PackOptions {
    fn tsdown_args(&self, force_finite: bool) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(config) = &self.config {
            push_option_value(&mut args, "--config", config);
        }
        if let Some(tsconfig) = &self.tsconfig {
            push_option_value(&mut args, "--tsconfig", tsconfig);
        }
        if let Some(target) = &self.target {
            push_option_value(&mut args, "--target", target);
        }
        if let Some(entry) = &self.entry {
            args.push(if entry.starts_with('-') {
                format!("./{entry}")
            } else {
                entry.clone()
            });
        }
        if let Some(out_dir) = &self.out_dir {
            push_option_value(&mut args, "--out-dir", out_dir);
        }
        if let Some(format) = self.format {
            args.push("--format".to_string());
            args.push(bundle_format_cli_value(format).to_string());
        }
        if let Some(platform) = self.platform {
            args.push("--platform".to_string());
            args.push(bundle_platform_cli_value(platform).to_string());
        }
        if self.dts {
            args.push("--dts".to_string());
        }
        if self.minify {
            args.push("--minify".to_string());
        }
        if self.sourcemap {
            args.push("--sourcemap".to_string());
        }

        args.extend(self.args.iter().cloned());
        if force_finite {
            let delimiter = args
                .iter()
                .position(|arg| arg == "--")
                .unwrap_or(args.len());
            args.insert(delimiter, "--no-watch".into());
        }
        args
    }
}

fn push_option_value(args: &mut Vec<String>, option: &str, value: &str) {
    if value.starts_with('-') {
        args.push(format!("{option}={value}"));
    } else {
        args.push(option.into());
        args.push(value.into());
    }
}

fn bundle_format_cli_value(format: BundleFormat) -> &'static str {
    match format {
        BundleFormat::Esm => "esm",
        BundleFormat::Cjs => "cjs",
        BundleFormat::Iife => "iife",
    }
}

fn bundle_platform_cli_value(platform: BundlePlatform) -> &'static str {
    match platform {
        BundlePlatform::Node => "node",
        BundlePlatform::Browser => "browser",
        BundlePlatform::Neutral => "neutral",
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    project_dir: &Path,
    options: &PackOptions,
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
            "--watch cannot be combined with --json for lpm pack".into(),
        ));
    }
    if all || affected || !filters.is_empty() || !filter_prod.is_empty() {
        pack_workspace(
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
        pack(project_dir, options, json_output).await
    }
}

pub async fn pack(
    project_dir: &Path,
    options: &PackOptions,
    json_output: bool,
) -> Result<(), LpmError> {
    if args_imply_watch(&options.args) && json_output {
        return Err(LpmError::Script(
            "--watch cannot be combined with --json for lpm pack".into(),
        ));
    }
    let boundary = super::tool_runtime::boundary(project_dir)?;
    let runtimes = InstalledRuntimes::new(&boundary)?;
    let path = runtimes.path_for(project_dir)?;
    let entry = resolve_local_pack_binary(project_dir, &boundary)?;
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Using local {}",
            install_ui::yellow("tsdown")
        ));
    }
    let start = std::time::Instant::now();
    let signals = Arc::new(ExecutionSignals::new()?);
    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };
    let outcome = run_pack_process(
        project_dir,
        &entry,
        &path,
        options,
        json_output,
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
            "Done · package build complete in {}",
            install_ui::green(&duration)
        ));
    } else if let Some(code) = outcome.exit_code {
        install_ui::failed_untrusted(&format!("pack failed · exit code {code}"));
    }
    signals.check()?;
    outcome.into_result()
}

async fn run_pack_process(
    project_dir: &Path,
    entry: &Path,
    path: &str,
    options: &PackOptions,
    force_finite: bool,
    stdio: StdioMode,
    signals: Arc<ExecutionSignals>,
) -> ToolOutcome {
    let mut command = Command::new(entry);
    command
        .args(options.tsdown_args(force_finite && !args_imply_watch(&options.args)))
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
    let mut had_value = false;
    // CAC keeps aliases separately. Repeated watch paths form a truthy array;
    // a negated option replaces that array with false.
    let mut record = |alias: &'static str, value: bool, negated: bool| {
        if *selected_alias.get_or_insert(alias) == alias {
            watching = if had_value && !negated { true } else { value };
            had_value = true;
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
                "watch" => record("watch", false, true),
                "w" => record("w", false, true),
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
                "watch" => record("watch", watch_path_is_truthy(value), false),
                "w" => record("w", watch_path_is_truthy(value), false),
                _ => {}
            }
        } else {
            let mut chars = name.chars().peekable();
            while let Some(short) = chars.next() {
                if short == 'w' {
                    record(
                        "w",
                        chars.peek().is_some() || watch_path_is_truthy(value),
                        false,
                    );
                }
            }
        }
    }
    watching
}

fn watch_path_is_truthy(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if let Ok(number) = value.parse::<f64>() {
        return number != 0.0;
    }
    for prefix in ["0x", "0X", "0b", "0B", "0o", "0O"] {
        if let Some(digits) = value.strip_prefix(prefix) {
            return digits.is_empty() || digits.bytes().any(|byte| byte != b'0');
        }
    }
    true
}

fn resolve_local_pack_binary(project_dir: &Path, boundary: &Path) -> Result<PathBuf, LpmError> {
    lpm_runner::script::resolve_local_bin_path_bounded(project_dir, boundary, "tsdown").map_err(
        |error| {
            LpmError::Script(format!(
                "{error}. Install tsdown with `lpm install -D tsdown`"
            ))
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn pack_workspace(
    project_dir: &Path,
    options: &PackOptions,
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
            "pack watch mode requires exactly one selected workspace member (selected {})",
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
                "no packages affected vs {} — nothing to pack",
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
    let mut result_order = vec![0; graph.len()];
    for (order, index) in graph
        .topological_levels()
        .map_err(|error| LpmError::Script(error.to_string()))?
        .into_iter()
        .flatten()
        .enumerate()
    {
        result_order[index] = order;
    }
    let runtimes = InstalledRuntimes::new(&workspace.root)?;
    let mut prepared = Vec::with_capacity(graph.len());
    for (index, member) in graph.members.iter().enumerate() {
        if !targets.contains(&index) {
            prepared.push(Err("member not selected".into()));
            continue;
        }
        let result = (|| {
            let path = runtimes.path_for(&member.path)?;
            let entry = resolve_local_pack_binary(&member.path, &workspace.root)?;
            Ok::<_, LpmError>((entry, path))
        })()
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
                        "  {} pack",
                        install_ui::bold(&format!("[{}]", member.name))
                    ));
                }
                let outcome = match task {
                    Ok((entry, path)) => {
                        run_pack_process(
                            &member.path,
                            entry,
                            path,
                            options,
                            true,
                            stdio,
                            task_signals,
                        )
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
    results.sort_unstable_by_key(|(index, _)| result_order[*index]);
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
            "pack",
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
