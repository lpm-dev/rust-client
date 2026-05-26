use crate::{BundleFormat, BundlePlatform, output};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_CAPTURED_OUTPUT: usize = 10 * 1024 * 1024;

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
    fn tsdown_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(config) = &self.config {
            args.push("--config".to_string());
            args.push(config.clone());
        }
        if let Some(tsconfig) = &self.tsconfig {
            args.push("--tsconfig".to_string());
            args.push(tsconfig.clone());
        }
        if let Some(target) = &self.target {
            args.push("--target".to_string());
            args.push(target.clone());
        }
        if let Some(entry) = &self.entry {
            args.push(entry.clone());
        }
        if let Some(out_dir) = &self.out_dir {
            args.push("--out-dir".to_string());
            args.push(out_dir.clone());
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
        args
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StdioMode {
    Inherit,
    Capture,
}

#[derive(Default)]
struct Captured {
    stdout: String,
    stderr: String,
}

#[derive(Default)]
struct ToolOutcome {
    exit_code: Option<i32>,
    captured: Captured,
    error: Option<String>,
}

impl ToolOutcome {
    fn success(&self) -> bool {
        matches!(self.exit_code, Some(0)) && self.error.is_none()
    }

    fn into_result(self) -> Result<(), LpmError> {
        if let Some(error) = self.error {
            return Err(LpmError::Script(error));
        }

        match self.exit_code {
            Some(0) => Ok(()),
            Some(code) => Err(LpmError::ExitCode(code)),
            None => Err(LpmError::Script(
                "pack exited without an exit code".to_string(),
            )),
        }
    }
}

struct MemberResult {
    name: String,
    success: bool,
    exit_code: Option<i32>,
    duration_ms: u64,
    captured: Captured,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    project_dir: &Path,
    options: &PackOptions,
    all: bool,
    filters: &[String],
    affected: bool,
    base_ref: &str,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace_mode = all || affected || !filters.is_empty();

    if workspace_mode && args_imply_watch(&options.args) {
        let workspace = lpm_workspace::discover_workspace(project_dir)
            .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
            .ok_or_else(|| {
                LpmError::Script(
                    "no workspace found. --all/--filter/--affected require a monorepo".into(),
                )
            })?;
        let ws_graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);
        let target_set = crate::workspace_select::select_workspace_target_set(
            &ws_graph,
            &workspace.root,
            filters,
            affected,
            base_ref,
        )?;

        match target_set.len() {
            0 => {
                return Err(LpmError::Script(
                    "no workspace member matched the selection — nothing to watch with `lpm pack --watch`."
                        .into(),
                ));
            }
            1 => {
                let idx = *target_set.iter().next().expect("len == 1");
                return pack(&ws_graph.members[idx].path, options, json_output).await;
            }
            n => {
                return Err(LpmError::Script(format!(
                    "--watch is not supported when the selection resolves to {n} members for `lpm pack` \
                     (would start one watcher per member). Narrow the selection so it resolves to exactly \
                     one member, e.g. `lpm pack --filter <single-name> -- --watch`, or run from the member's \
                     directory with `cd <member> && lpm pack -- --watch`."
                )));
            }
        }
    }

    if workspace_mode {
        pack_workspace(
            project_dir,
            options,
            filters,
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
    if !json_output {
        output::info("pack (tsdown)");
    }

    let outcome = run_pack_process(project_dir, options, StdioMode::Inherit)?;
    outcome.into_result()
}

fn run_pack_process(
    project_dir: &Path,
    options: &PackOptions,
    stdio: StdioMode,
) -> Result<ToolOutcome, LpmError> {
    let pack_bin = resolve_local_pack_binary(project_dir).ok_or_else(|| {
        LpmError::Script("tsdown not installed. Run: lpm install -D tsdown".to_string())
    })?;
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let mut cmd = Command::new(&pack_bin);
    cmd.args(options.tsdown_args())
        .current_dir(project_dir)
        .env("PATH", &path);

    apply_stdio(&mut cmd, stdio);

    let mut outcome = ToolOutcome::default();
    let spawn_hint = "Install Node via `lpm use node@22` or ensure `node` is on PATH";

    match stdio {
        StdioMode::Inherit => {
            let status = cmd.status().map_err(|e| {
                LpmError::Script(format!(
                    "failed to run {}: {e}. {spawn_hint}",
                    pack_bin.display(),
                ))
            })?;
            outcome.exit_code = Some(status.code().unwrap_or(1));
        }
        StdioMode::Capture => match cmd.output() {
            Ok(output) => {
                outcome.captured = Captured {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                };
                outcome.exit_code = Some(output.status.code().unwrap_or(1));
            }
            Err(e) => {
                outcome.error = Some(format!(
                    "failed to run {}: {e}. {spawn_hint}",
                    pack_bin.display(),
                ));
            }
        },
    }

    Ok(outcome)
}

fn resolve_local_pack_binary(project_dir: &Path) -> Option<PathBuf> {
    for bin_dir in lpm_runner::bin_path::find_bin_dirs(project_dir) {
        for candidate_name in tool_candidates("tsdown") {
            let candidate = bin_dir.join(candidate_name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(windows)]
fn tool_candidates(name: &str) -> Vec<String> {
    let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut candidates = vec![name.to_string()];
    candidates.extend(
        raw.split(';')
            .filter(|ext| !ext.is_empty())
            .map(|ext| format!("{name}{ext}")),
    );
    candidates
}

#[cfg(not(windows))]
fn tool_candidates(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn apply_stdio(cmd: &mut Command, stdio: StdioMode) {
    match stdio {
        StdioMode::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
        StdioMode::Capture => {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
    }
}

fn args_imply_watch(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg == "--watch" || arg.starts_with("--watch=") || arg == "-w")
}

async fn pack_workspace(
    project_dir: &Path,
    options: &PackOptions,
    filters: &[String],
    affected_base: Option<&str>,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
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
    let target_set = crate::workspace_select::select_workspace_target_set(
        &ws_graph,
        &workspace.root,
        filters,
        affected_base.is_some(),
        affected_base.unwrap_or("main"),
    )?;

    if target_set.is_empty() {
        let affected_only = filters.is_empty() && affected_base.is_some();
        if fail_if_no_match {
            let msg = if affected_only {
                format!(
                    "no workspace packages affected vs {} (--fail-if-no-match)",
                    affected_base.unwrap_or("main"),
                )
            } else {
                let hint = crate::commands::filter::format_no_match_hint(filters);
                let base = "no workspace packages matched the filter (--fail-if-no-match)";
                match hint {
                    Some(h) => format!("{base}\n\n{h}"),
                    None => base.to_string(),
                }
            };
            return Err(LpmError::Script(msg));
        }

        if json_output {
            let envelope = serde_json::json!({
                "success": true,
                "packages": 0,
                "succeeded": 0,
                "failed": 0,
                "duration_ms": 0,
                "members": [],
            });
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        } else if affected_only {
            output::success(&format!(
                "no packages affected vs {} — nothing to pack",
                affected_base.unwrap_or("main"),
            ));
        } else {
            let hint = crate::commands::filter::format_no_match_hint(filters);
            output::warn("No packages matched");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    let stdio = if json_output {
        StdioMode::Capture
    } else {
        StdioMode::Inherit
    };

    let start = std::time::Instant::now();
    let mut member_results = Vec::with_capacity(target_set.len());

    for level in &levels {
        let level_targets: Vec<usize> = level
            .iter()
            .filter(|idx| target_set.contains(idx))
            .copied()
            .collect();
        if level_targets.is_empty() {
            continue;
        }

        member_results.extend(run_level(&ws_graph, &level_targets, options, stdio).await);
    }

    let elapsed = start.elapsed();
    let succeeded = member_results
        .iter()
        .filter(|result| result.success)
        .count();
    let failed = member_results.len() - succeeded;

    if json_output {
        emit_envelope(
            &member_results,
            member_results.len(),
            succeeded,
            failed,
            elapsed,
        );
    } else {
        emit_human_summary(
            "pack",
            member_results.len(),
            succeeded,
            failed,
            target_set.len(),
            elapsed,
        );
    }

    if failed > 0 {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

async fn run_level(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    level_targets: &[usize],
    options: &PackOptions,
    stdio: StdioMode,
) -> Vec<MemberResult> {
    if level_targets.len() == 1 {
        let idx = level_targets[0];
        return vec![
            run_one_member(
                &ws_graph.members[idx].path,
                &ws_graph.members[idx].name,
                options,
                stdio,
            )
            .await,
        ];
    }

    let max_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let mut all_results = Vec::with_capacity(level_targets.len());

    for chunk in level_targets.chunks(max_threads) {
        let mut chunk_futs = Vec::with_capacity(chunk.len());
        for &idx in chunk {
            let member_dir = ws_graph.members[idx].path.clone();
            let member_name = ws_graph.members[idx].name.clone();
            let pack_options = options.clone();

            chunk_futs.push(tokio::spawn(async move {
                run_one_member(&member_dir, &member_name, &pack_options, stdio).await
            }));
        }

        for fut in chunk_futs {
            match fut.await {
                Ok(result) => all_results.push(result),
                Err(join_err) => all_results.push(MemberResult {
                    name: "<unknown>".into(),
                    success: false,
                    exit_code: None,
                    duration_ms: 0,
                    captured: Captured::default(),
                    error: Some(format!("workspace task panicked: {join_err}")),
                }),
            }
        }
    }

    all_results
}

async fn run_one_member(
    member_dir: &Path,
    member_name: &str,
    options: &PackOptions,
    stdio: StdioMode,
) -> MemberResult {
    let start = std::time::Instant::now();

    if matches!(stdio, StdioMode::Inherit) {
        eprintln!("  {} pack", format!("[{member_name}]").bold());
    }

    let outcome = run_pack_process(member_dir, options, stdio).unwrap_or_else(|e| ToolOutcome {
        error: Some(e.to_string()),
        ..Default::default()
    });
    let success = outcome.success();
    let exit_code = outcome.exit_code;
    let captured = outcome.captured;
    let error = outcome.error;
    let duration_ms = start.elapsed().as_millis() as u64;

    if matches!(stdio, StdioMode::Inherit) && !success {
        if let Some(code) = exit_code {
            eprintln!(
                "  {} {member_name}: exit {code}",
                "\u{2716}".to_string().red()
            );
        } else if let Some(ref msg) = error {
            eprintln!("  {} {member_name}: {msg}", "\u{2716}".to_string().red());
        }
    }

    MemberResult {
        name: member_name.to_string(),
        success,
        exit_code,
        duration_ms,
        captured,
        error,
    }
}

fn truncate_output(text: &str) -> String {
    if text.len() > MAX_CAPTURED_OUTPUT {
        let truncated = &text[..MAX_CAPTURED_OUTPUT];
        let end = truncated.rfind('\n').unwrap_or(MAX_CAPTURED_OUTPUT);
        format!(
            "{}...\n\n[output truncated at {}MB]",
            &text[..end],
            MAX_CAPTURED_OUTPUT / (1024 * 1024),
        )
    } else {
        text.to_string()
    }
}

fn emit_envelope(
    results: &[MemberResult],
    total: usize,
    succeeded: usize,
    failed: usize,
    elapsed: std::time::Duration,
) {
    let members: Vec<serde_json::Value> = results
        .iter()
        .map(|result| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "name".into(),
                serde_json::Value::String(result.name.clone()),
            );
            obj.insert("success".into(), serde_json::Value::Bool(result.success));
            obj.insert(
                "exit_code".into(),
                match result.exit_code {
                    Some(code) => serde_json::Value::Number(code.into()),
                    None => serde_json::Value::Null,
                },
            );
            obj.insert(
                "duration_ms".into(),
                serde_json::Value::Number(result.duration_ms.into()),
            );

            if !result.success {
                if let Some(ref error) = result.error {
                    obj.insert("error".into(), serde_json::Value::String(error.clone()));
                }
                if !result.captured.stdout.is_empty() {
                    obj.insert(
                        "stdout".into(),
                        serde_json::Value::String(truncate_output(&result.captured.stdout)),
                    );
                }
                if !result.captured.stderr.is_empty() {
                    obj.insert(
                        "stderr".into(),
                        serde_json::Value::String(truncate_output(&result.captured.stderr)),
                    );
                }
            }

            serde_json::Value::Object(obj)
        })
        .collect();

    let envelope = serde_json::json!({
        "success": failed == 0,
        "packages": total,
        "succeeded": succeeded,
        "failed": failed,
        "duration_ms": elapsed.as_millis() as u64,
        "members": members,
    });

    println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
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
        output::success(&format!(
            "{tool} passed in {total} packages ({:.1}s)",
            elapsed.as_secs_f64()
        ));
        if targeted > total {
            eprintln!(
                "  {} {} targeted",
                "·".dimmed(),
                format!("{targeted} packages").dimmed(),
            );
        }
    } else {
        output::warn(&format!(
            "{tool}: {succeeded} passed, {failed} failed out of {total} packages ({:.1}s)",
            elapsed.as_secs_f64()
        ));
    }
}
