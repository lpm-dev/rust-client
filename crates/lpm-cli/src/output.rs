//! Terminal output helpers using cliclack for consistent, styled output.

use lpm_common::color::Painted;

/// Suppress stdout for nested command execution when the outer command
/// owns the machine-readable stdout contract.
pub fn suppress_stdout(enabled: bool) -> Result<Option<gag::Gag>, String> {
    if !enabled {
        return Ok(None);
    }

    gag::Gag::stdout()
        .map(Some)
        .map_err(|error| format!("failed to suppress stdout: {error}"))
}

/// Suppress stderr for nested command execution when the outer command
/// owns the human-readable stderr contract.
pub fn suppress_stderr(enabled: bool) -> Result<Option<gag::Gag>, String> {
    if !enabled {
        return Ok(None);
    }

    gag::Gag::stderr()
        .map(Some)
        .map_err(|error| format!("failed to suppress stderr: {error}"))
}

/// Print a success message.
pub fn success(msg: &str) {
    let _ = cliclack::log::success(msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    let _ = cliclack::log::warning(msg);
}

/// Print an info message.
pub fn info(msg: &str) {
    let _ = cliclack::log::info(msg);
}

/// Print a label: value pair with the label dimmed.
pub fn field(label: &str, value: &str) {
    println!("  {}: {value}", label.dimmed());
}

/// Print a section header.
pub fn header(title: &str) {
    println!();
    println!("  {}", title.bold());
}

/// Format a quality tier with appropriate color.
pub fn tier_colored(tier: &str) -> String {
    match tier.to_lowercase().as_str() {
        "gold" => tier.yellow().bold(),
        "silver" => tier.white().bold(),
        "bronze" => tier.red(),
        _ => tier.dimmed(),
    }
}

/// Format a quality score with color based on value.
pub fn score_colored(score: u32, max: u32) -> String {
    let pct = (score * 100).checked_div(max).unwrap_or(0);
    let text = format!("{score}/{max}");
    if pct >= 80 {
        text.green()
    } else if pct >= 50 {
        text.yellow()
    } else {
        text.red()
    }
}

/// Format a distribution mode badge.
pub fn mode_badge(mode: &str) -> String {
    match mode {
        "pool" => "pool".cyan(),
        "marketplace" => "marketplace".magenta(),
        "private" => "private".yellow(),
        _ => mode.dimmed(),
    }
}
