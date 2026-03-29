//! Terminal output helpers with color support.

use owo_colors::OwoColorize;

/// Print the LPM header banner. Called at the start of user-facing commands.
/// Dimmed/opaque to stay subtle — focus should be on the command output, not the banner.
pub fn print_header() {
    eprintln!();
    eprintln!("  {}", "LPM — Licensed Package Manager".dimmed());
    eprintln!();
}

/// Print a success message with a green checkmark.
pub fn success(msg: &str) {
    println!("{} {msg}", "✔".green());
}

/// Print a warning message with a yellow marker.
pub fn warn(msg: &str) {
    println!("{} {msg}", "⚠".yellow());
}

/// Print an info message with a blue marker.
pub fn info(msg: &str) {
    println!("{} {msg}", "ℹ".blue());
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
