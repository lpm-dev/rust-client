use crate::install_ui;

pub(super) fn print_captured_stdout(output: &str) {
    print!("{}", lpm_common::sanitize_terminal_multiline(output));
}

pub(super) fn print_captured_stderr(output: &str) {
    eprint!("{}", lpm_common::sanitize_terminal_multiline(output));
}

pub(super) struct TaskResult {
    pub(super) name: String,
    pub(super) success: bool,
    pub(super) duration: std::time::Duration,
    pub(super) cached: bool,
    pub(super) skipped: bool,
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
            "  {} {}   failed (exit 1, {})",
            install_ui::red("✗"),
            install_ui::yellow(&name),
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
