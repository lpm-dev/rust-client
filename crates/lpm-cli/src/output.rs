//! Terminal output helpers using cliclack for consistent, styled output.

use owo_colors::OwoColorize;

/// Print the LPM header banner using cliclack intro style.
pub fn print_header() {
    let _ = cliclack::intro("LPM — Licensed Package Manager");
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

/// Print a success field (green checkmark + label + value).
pub fn success_inline(label: &str, value: &str) {
    println!("  {} {}: {value}", "✔".green(), label.dimmed());
}

/// Print a section header.
pub fn header(title: &str) {
    println!();
    println!("  {}", title.bold());
}

/// Format a quality tier with appropriate color.
pub fn tier_colored(tier: &str) -> String {
    match tier.to_lowercase().as_str() {
        "gold" => tier.yellow().bold().to_string(),
        "silver" => tier.white().bold().to_string(),
        "bronze" => tier.red().to_string(),
        _ => tier.dimmed().to_string(),
    }
}

/// Format a quality score with color based on value.
pub fn score_colored(score: u32, max: u32) -> String {
    let pct = if max > 0 { score * 100 / max } else { 0 };
    let text = format!("{score}/{max}");
    if pct >= 80 {
        text.green().to_string()
    } else if pct >= 50 {
        text.yellow().to_string()
    } else {
        text.red().to_string()
    }
}

/// Format a distribution mode badge.
pub fn mode_badge(mode: &str) -> String {
    match mode {
        "pool" => "pool".cyan().to_string(),
        "marketplace" => "marketplace".magenta().to_string(),
        "private" => "private".yellow().to_string(),
        _ => mode.dimmed().to_string(),
    }
}
