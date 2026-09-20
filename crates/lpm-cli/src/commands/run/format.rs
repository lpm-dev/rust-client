use crate::install_ui;
use lpm_common::LpmError;
use std::collections::HashMap;
use std::sync::Arc;

use super::cache::CompletedTaskCacheIdentity;

pub(super) fn print_captured_stdout(output: &str) {
    print!("{}", lpm_common::sanitize_terminal_multiline(output));
}

pub(super) fn print_captured_stderr(output: &str) {
    eprint!("{}", lpm_common::sanitize_terminal_multiline(output));
}

pub(super) struct TaskResult {
    pub(super) name: String,
    pub(super) success: bool,
    pub(super) exit_code: Option<i32>,
    pub(super) phase: Option<String>,
    pub(super) duration: std::time::Duration,
    pub(super) cached: bool,
    pub(super) skipped: bool,
}

pub(super) struct TaskRunReport {
    results: Vec<TaskResult>,
    cache_identities: HashMap<String, Arc<CompletedTaskCacheIdentity>>,
}

impl TaskRunReport {
    pub(super) fn new(results: Vec<TaskResult>) -> Self {
        Self {
            results,
            cache_identities: HashMap::new(),
        }
    }

    pub(super) fn with_cache_identities(
        results: Vec<TaskResult>,
        cache_identities: HashMap<String, Arc<CompletedTaskCacheIdentity>>,
    ) -> Self {
        Self {
            results,
            cache_identities,
        }
    }

    pub(super) fn is_successful(&self) -> bool {
        self.results.iter().all(|result| result.success)
    }

    pub(super) fn task_states(&self) -> HashMap<String, bool> {
        self.results
            .iter()
            .map(|result| (result.name.clone(), result.success))
            .collect()
    }

    pub(super) fn task_cache_identity(
        &self,
        task_name: &str,
    ) -> Option<&Arc<CompletedTaskCacheIdentity>> {
        self.cache_identities.get(task_name)
    }

    pub(super) fn into_single_result(self) -> Result<(), LpmError> {
        if let Some(result) = self.results.iter().find(|r| !r.success && !r.skipped) {
            Err(LpmError::ExitCode(result.exit_code.unwrap_or(1)))
        } else {
            Ok(())
        }
    }

    pub(super) fn into_result(self) -> Result<(), LpmError> {
        let failure_count = self
            .results
            .iter()
            .filter(|result| !result.success && !result.skipped)
            .count();
        if failure_count == 0 {
            Ok(())
        } else {
            Err(LpmError::ExitCode(
                failure_count.min(u8::MAX as usize) as i32
            ))
        }
    }
}

pub(super) fn print_task_result(result: &TaskResult) {
    let name = lpm_common::sanitize_terminal_inline(&result.name);
    if result.skipped {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}   {}",
            install_ui::dim("⊘"),
            install_ui::dim(&name),
            install_ui::dim("skipped"),
        ));
    } else if result.success {
        let timing = format_duration(result.duration);
        let cache_label = if result.cached { ", cached" } else { "" };
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}   passed ({}{})",
            install_ui::status_ok("✓"),
            install_ui::yellow(&name),
            timing,
            cache_label,
        ));
    } else {
        let timing = format_duration(result.duration);
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}   failed (exit {}, {}{})",
            install_ui::red("✗"),
            install_ui::yellow(&name),
            result.exit_code.unwrap_or(1),
            result
                .phase
                .as_ref()
                .map(|phase| format!("{}, ", lpm_common::sanitize_terminal_inline(phase)))
                .unwrap_or_default(),
            timing,
        ));
    }
}

pub(super) fn format_run_failure_detail(
    subject: &str,
    reason: impl std::fmt::Display,
) -> install_ui::TerminalLine {
    let reason = reason.to_string();
    crate::install_ui::terminal_line!(
        "  {} {}: {}",
        install_ui::red("✗"),
        install_ui::yellow(subject),
        reason
    )
}

pub(super) fn format_failed_task_output_header(name: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "  {} {} output {}",
        install_ui::dim("──"),
        install_ui::yellow(name),
        install_ui::dim(&"─".repeat(40))
    )
}

pub(super) fn format_failed_task_output_footer() -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("  {}", install_ui::dim(&"─".repeat(50)))
}

pub(super) fn format_cache_summary(cached: usize, missed: usize) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "  {} {} hit, {} miss",
        install_ui::dim("Cache:"),
        install_ui::status_ok(&cached.to_string()),
        missed
    )
}

pub(super) fn format_workspace_member_scripts_header(
    member_name: &str,
    scripts: &[String],
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::cyan(&format!("[{member_name}]")),
        install_ui::yellow(&scripts.join(", "))
    )
}

pub(super) fn print_results_summary(results: &[TaskResult], total_elapsed: std::time::Duration) {
    if results.len() <= 1 {
        return; // No summary for single task
    }

    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success && !r.skipped).count();
    let skipped = results.iter().filter(|r| r.skipped).count();
    let cached = results.iter().filter(|r| r.cached).count();

    // Calculate sequential time — exclude skipped tasks (skipped
    // tasks have 0ms duration which deflates the "% faster" metric).
    let sequential_ms: u128 = results
        .iter()
        .filter(|r| !r.skipped)
        .map(|r| r.duration.as_millis())
        .sum();
    let actual_ms = total_elapsed.as_millis();

    install_ui::detail("");
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
        // use ran count (excludes skipped) in summary
        let ran_count = results.iter().filter(|r| !r.skipped).count();
        install_ui::done_line(crate::install_ui::terminal_line!(
            "{} completed in {}{}",
            ran_count,
            format_duration(total_elapsed),
            install_ui::dim(&speedup),
        ));
    } else {
        // denominator excludes skipped tasks
        let ran = results.len() - skipped;
        let skip_note = if skipped > 0 {
            format!(" ({skipped} skipped)")
        } else {
            String::new()
        };
        install_ui::failed_untrusted(&format!("{failed} of {ran} tasks failed.{skip_note}"));
    }

    if skipped > 0 {
        install_ui::detail_untrusted(&format!("  {} skipped (dependency failed)", skipped));
    }
    if cached > 0 {
        install_ui::detail_line(format_cache_summary(
            cached,
            results.len() - cached - skipped,
        ));
    }

    // Per-task breakdown when there's something interesting to show
    let _ = (passed, skipped);
}

pub(super) fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// Print a JSON summary of task results.
pub(super) fn print_json_summary(results: &[TaskResult], elapsed: std::time::Duration) {
    let tasks: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let mut task = serde_json::json!({
                "name": r.name,
                "success": r.success,
                "cached": r.cached,
                "skipped": r.skipped,
                "duration_ms": r.duration.as_millis() as u64,
            });
            if let Some(code) = r.exit_code {
                task["exit_code"] = code.into();
            }
            if let Some(phase) = &r.phase {
                task["phase"] = phase.clone().into();
            }
            task
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

pub(super) fn task_failure(error: &LpmError) -> (Option<i32>, Option<String>) {
    match error {
        LpmError::ExitCode(code) | LpmError::ScriptWithOutput { code, .. } => (Some(*code), None),
        LpmError::ScriptPhase { code, phase, .. } => (Some(*code), Some(phase.clone())),
        _ => (Some(1), None),
    }
}

pub(super) fn print_task_stdout(output: &str, json_output: bool) {
    if json_output {
        print_captured_stderr(output);
    } else {
        print_captured_stdout(output);
    }
}

#[derive(Clone, Copy)]
pub(super) struct TaskOutputPolicy {
    pub(super) reserve_stdout: bool,
    pub(super) report_json: bool,
}

impl TaskOutputPolicy {
    pub(super) fn standalone(json: bool) -> Self {
        Self {
            reserve_stdout: json,
            report_json: json,
        }
    }
    pub(super) fn nested(json: bool) -> Self {
        Self {
            reserve_stdout: json,
            report_json: false,
        }
    }
}
