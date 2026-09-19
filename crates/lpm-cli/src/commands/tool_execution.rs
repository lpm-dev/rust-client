mod process;
use lpm_common::LpmError;
pub(super) use process::{run, write_json};
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::process::{Command, Stdio};

/// Maximum size for captured workspace stdout/stderr before truncation.
/// Mirrors the `MAX_CAPTURED_OUTPUT` constant in `commands::run` so chatty
/// failing members don't unbound the JSON envelope.
const MAX_CAPTURED_OUTPUT: usize = 10 * 1024 * 1024; // 10 MB

/// Truncate captured output if it exceeds `MAX_CAPTURED_OUTPUT`, cutting at
/// the last newline boundary to avoid splitting a line.
fn truncate_output(text: &str) -> String {
    if text.len() > MAX_CAPTURED_OUTPUT {
        let mut end = MAX_CAPTURED_OUTPUT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let end = text[..end].rfind('\n').unwrap_or(end);
        format!(
            "{}...\n\n[output truncated at {}MB]",
            &text[..end],
            MAX_CAPTURED_OUTPUT / (1024 * 1024),
        )
    } else {
        text.to_string()
    }
}

/// How a tool subprocess should connect its stdio to the parent.
///
/// `Inherit` is the default — single-package mode and human-mode workspace
/// runs both stream child output directly to the user's terminal.
///
/// `Capture` is used for workspace + `--json` mode: child stdout/stderr is
/// piped into in-memory buffers so the orchestrator can emit a single, valid
/// JSON envelope on the parent's stdout. Without `Capture`, child writes to
/// stdout would interleave with the envelope and produce un-parsable output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioMode {
    Inherit,
    Capture,
}

/// Captured stdio from a single tool invocation.
#[derive(Default)]
pub(super) struct Captured {
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) fn runner_error(error: LpmError) -> ToolOutcome {
    match error {
        LpmError::ExitCode(code) => ToolOutcome {
            exit_code: Some(code),
            ..Default::default()
        },
        LpmError::ScriptPhase {
            phase,
            code,
            stdout,
            stderr,
        } => ToolOutcome {
            exit_code: Some(code),
            captured: Captured { stdout, stderr },
            error: if matches!(phase.as_str(), "test" | "bench") {
                None
            } else {
                Some(format!("script '{phase}' failed with exit code {code}"))
            },
        },
        error => ToolOutcome {
            error: Some(error.to_string()),
            ..Default::default()
        },
    }
}

pub(super) fn finish_single_tool(
    project_dir: &Path,
    outcome: ToolOutcome,
    elapsed: std::time::Duration,
    signals: &lpm_runner::execution::ExecutionSignals,
) -> Result<(), LpmError> {
    let code = outcome.exit_code.unwrap_or(1);
    let success = outcome.success();
    let name = lpm_workspace::read_package_json(&project_dir.join("package.json"))
        .ok()
        .and_then(|package| package.name)
        .unwrap_or_else(|| {
            project_dir.file_name().map_or_else(
                || "<project>".into(),
                |name| name.to_string_lossy().into_owned(),
            )
        });
    let member = member_result(name, outcome, elapsed);
    emit_envelope(
        std::slice::from_ref(&member),
        1,
        usize::from(success),
        usize::from(!success),
        elapsed,
        signals,
    )?;
    if success {
        Ok(())
    } else {
        Err(LpmError::ExitCode(code))
    }
}

/// Outcome of a single tool invocation: either it ran (with an exit code) or
/// LPM couldn't even launch it (spawn / config / plugin failure).
#[derive(Default)]
pub(super) struct ToolOutcome {
    pub(super) exit_code: Option<i32>,
    pub(super) captured: Captured,
    /// Set when LPM itself failed to launch — distinguishes from "ran and
    /// exited non-zero." Surfaces in the JSON envelope as `error` with a
    /// `null` exit_code.
    pub(super) error: Option<String>,
}

impl ToolOutcome {
    pub(super) fn success(&self) -> bool {
        matches!(self.exit_code, Some(0)) && self.error.is_none()
    }

    pub(super) fn as_result(&self) -> Result<(), LpmError> {
        match self.exit_code {
            Some(0) if self.error.is_none() => Ok(()),
            Some(code) if code != 0 => Err(LpmError::ExitCode(code)),
            _ => {
                Err(LpmError::Script(self.error.clone().unwrap_or_else(|| {
                    "tool exited without an exit code".into()
                })))
            }
        }
    }

    /// Convert into a `Result` for single-package callers that just want the
    /// exit-code propagated.
    pub(super) fn into_result(self) -> Result<(), LpmError> {
        self.as_result()
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

/// Per-member result captured by the workspace orchestrator.
pub(super) struct MemberResult {
    pub(super) name: String,
    pub(super) success: bool,
    /// `Some(code)` when the subprocess ran. `None` for spawn/config/plugin
    /// failures — paired with `error` in the envelope.
    pub(super) exit_code: Option<i32>,
    pub(super) duration_ms: u64,
    pub(super) captured: Captured,
    pub(super) error: Option<String>,
}

pub(super) fn member_result(
    name: String,
    outcome: ToolOutcome,
    elapsed: std::time::Duration,
) -> MemberResult {
    let success = outcome.success();
    MemberResult {
        name,
        success,
        exit_code: outcome.exit_code,
        duration_ms: elapsed.as_millis() as u64,
        captured: if success {
            Captured::default()
        } else {
            outcome.captured
        },
        error: outcome.error,
    }
}

pub(super) fn selected_schedule_state(
    ws_graph: &lpm_task::graph::WorkspaceGraph,
    target_set: &HashSet<usize>,
) -> Result<(Vec<usize>, VecDeque<usize>), LpmError> {
    let mut initial_unmet = vec![0; ws_graph.len()];
    let mut ready = VecDeque::new();
    for &index in target_set {
        initial_unmet[index] = ws_graph.edges[index]
            .iter()
            .filter(|dependency| target_set.contains(dependency))
            .count();
        if initial_unmet[index] == 0 {
            ready.push_back(index);
        }
    }

    let mut remaining = initial_unmet.clone();
    let mut preflight = ready.clone();
    let mut processed = 0;
    while let Some(index) = preflight.pop_front() {
        processed += 1;
        for &dependent in &ws_graph.reverse_edges[index] {
            if !target_set.contains(&dependent) {
                continue;
            }
            remaining[dependent] -= 1;
            if remaining[dependent] == 0 {
                preflight.push_back(dependent);
            }
        }
    }
    if processed != target_set.len() {
        let mut blocked = target_set
            .iter()
            .filter(|index| remaining[**index] > 0)
            .map(|index| ws_graph.members[*index].name.as_str())
            .collect::<Vec<_>>();
        blocked.sort_unstable();
        return Err(LpmError::Script(format!(
            "dependency cycle detected in selected workspace packages: {}",
            blocked.join(", ")
        )));
    }

    let mut ready = ready.into_iter().collect::<Vec<_>>();
    ready.sort_unstable();
    Ok((initial_unmet, ready.into()))
}

/// Emit the workspace JSON envelope. Stdout/stderr surface ONLY for failed
/// members and are truncated at the 10MB ceiling.
pub(super) fn emit_envelope(
    results: &[MemberResult],
    total: usize,
    succeeded: usize,
    failed: usize,
    elapsed: std::time::Duration,
    signals: &lpm_runner::execution::ExecutionSignals,
) -> Result<(), LpmError> {
    let members: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), serde_json::Value::String(r.name.clone()));
            obj.insert("success".into(), serde_json::Value::Bool(r.success));
            obj.insert(
                "exit_code".into(),
                match r.exit_code {
                    Some(code) => serde_json::Value::Number(code.into()),
                    None => serde_json::Value::Null,
                },
            );
            obj.insert(
                "duration_ms".into(),
                serde_json::Value::Number(r.duration_ms.into()),
            );

            if !r.success {
                if let Some(ref msg) = r.error {
                    obj.insert("error".into(), serde_json::Value::String(msg.clone()));
                }
                if !r.captured.stdout.is_empty() {
                    obj.insert(
                        "stdout".into(),
                        serde_json::Value::String(truncate_output(&r.captured.stdout)),
                    );
                }
                if !r.captured.stderr.is_empty() {
                    obj.insert(
                        "stderr".into(),
                        serde_json::Value::String(truncate_output(&r.captured.stderr)),
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

    write_json(&envelope, signals)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_outcome_into_result_distinguishes_exit_from_error() {
        let exit_failure = ToolOutcome {
            exit_code: Some(2),
            ..Default::default()
        };
        match exit_failure.into_result() {
            Err(LpmError::ExitCode(code)) => assert_eq!(code, 2),
            other => panic!("expected ExitCode error, got: {other:?}"),
        }

        let spawn_failure = ToolOutcome {
            error: Some("spawn failed".into()),
            ..Default::default()
        };
        match spawn_failure.into_result() {
            Err(LpmError::Script(msg)) => assert_eq!(msg, "spawn failed"),
            other => panic!("expected Script error, got: {other:?}"),
        }
    }

    // --- truncate_output ---

    #[test]
    fn truncate_output_small_passthrough() {
        let small = "hello world\n".repeat(10);
        let result = truncate_output(&small);
        assert_eq!(result, small);
    }

    #[test]
    fn truncate_output_large_truncated() {
        let huge = "x".repeat(MAX_CAPTURED_OUTPUT + 2_000);
        let result = truncate_output(&huge);
        assert!(
            result.ends_with("[output truncated at 10MB]"),
            "expected truncation marker, got tail: {:?}",
            &result[result.len().saturating_sub(60)..]
        );
        assert!(result.len() <= MAX_CAPTURED_OUTPUT + 100);
    }
}
