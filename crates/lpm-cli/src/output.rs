//! Slim terminal output helpers for non-interactive status lines.

use crate::install_ui;
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
    install_ui::done(msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    install_ui::warn(msg);
}

/// Print an info message.
pub fn info(msg: &str) {
    install_ui::phase(msg);
}

/// Print a label: value pair with the label dimmed.
pub fn field(label: &str, value: &str) {
    let label = format!("{label}:");
    eprintln!("    {} {value}", format!("{label:<24}").dimmed());
}
