//! Slim terminal output helpers for non-interactive status lines.

use crate::install_ui;
use lpm_common::color::Painted;
use serde_json::Value;
use std::io::IsTerminal;
use std::sync::{Mutex, OnceLock};

struct StdoutSuppressionState {
    active_leases: usize,
    gag: Option<gag::Gag>,
}

fn stdout_suppression_state() -> &'static Mutex<StdoutSuppressionState> {
    static STATE: OnceLock<Mutex<StdoutSuppressionState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(StdoutSuppressionState {
            active_leases: 0,
            gag: None,
        })
    })
}

pub struct StdoutSuppressionLease {
    _private: (),
}

impl Drop for StdoutSuppressionLease {
    fn drop(&mut self) {
        let mut state = stdout_suppression_state()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_leases -= 1;
        if state.active_leases == 0 {
            state.gag.take();
        }
    }
}

/// Suppress stdout for nested command execution when the outer command
/// owns the machine-readable stdout contract.
pub fn suppress_stdout(enabled: bool) -> Result<Option<StdoutSuppressionLease>, String> {
    if !enabled {
        return Ok(None);
    }

    let mut state = stdout_suppression_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.active_leases == 0 {
        state.gag = Some(
            gag::Gag::stdout().map_err(|error| format!("failed to suppress stdout: {error}"))?,
        );
    }
    state.active_leases += 1;
    Ok(Some(StdoutSuppressionLease { _private: () }))
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
    install_ui::done_untrusted(msg);
}

pub fn success_line(msg: install_ui::TerminalLine) {
    install_ui::done_line(msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    install_ui::warn_untrusted(msg);
}

pub fn warn_line(msg: install_ui::TerminalLine) {
    install_ui::warn_line(msg);
}

/// Print an info message.
pub fn info(msg: &str) {
    install_ui::phase_untrusted(msg);
}

pub fn info_line(msg: install_ui::TerminalLine) {
    install_ui::phase_line(msg);
}

/// Print a label: value pair with the label dimmed.
pub fn field(label: &'static str, value: &str) {
    let label = format!("{label}:");
    let value = lpm_common::sanitize_terminal_inline(value);
    eprintln!("    {} {value}", format!("{label:<24}").dimmed());
}

/// Format a JSON stdout answer with syntax color only for interactive terminals.
pub fn format_json_answer(value: &Value) -> Result<String, serde_json::Error> {
    format_json_answer_for_stdout(value, std::io::stdout().is_terminal())
}

fn format_json_answer_for_stdout(
    value: &Value,
    stdout_is_terminal: bool,
) -> Result<String, serde_json::Error> {
    if stdout_is_terminal && lpm_common::color::enabled() {
        Ok(format_colorized_json(value))
    } else {
        serde_json::to_string_pretty(value)
    }
}

fn format_colorized_json(value: &Value) -> String {
    let capacity = serde_json::to_string(value)
        .map(|compact| compact.len().saturating_mul(2))
        .unwrap_or(128);
    let mut out = String::with_capacity(capacity);
    push_colorized_json(value, 0, &mut out);
    out
}

fn push_colorized_json(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => out.push_str(&ansi_yellow(&json_string(value))),
        Value::Array(values) => push_colorized_array(values, indent, out),
        Value::Object(entries) => push_colorized_object(entries, indent, out),
    }
}

fn push_colorized_array(values: &[Value], indent: usize, out: &mut String) {
    if values.is_empty() {
        out.push_str(&ansi_dim("[]"));
        return;
    }

    out.push_str(&ansi_dim("["));
    out.push('\n');
    for (index, value) in values.iter().enumerate() {
        push_indent(indent + 2, out);
        push_colorized_json(value, indent + 2, out);
        if index + 1 != values.len() {
            out.push_str(&ansi_dim(","));
        }
        out.push('\n');
    }
    push_indent(indent, out);
    out.push_str(&ansi_dim("]"));
}

fn push_colorized_object(
    entries: &serde_json::Map<String, Value>,
    indent: usize,
    out: &mut String,
) {
    if entries.is_empty() {
        out.push_str(&ansi_dim("{}"));
        return;
    }

    out.push_str(&ansi_dim("{"));
    out.push('\n');
    let len = entries.len();
    for (index, (key, value)) in entries.iter().enumerate() {
        push_indent(indent + 2, out);
        out.push_str(&ansi_cyan(&json_string(key)));
        out.push_str(&ansi_dim(":"));
        out.push(' ');
        push_colorized_json(value, indent + 2, out);
        if index + 1 != len {
            out.push_str(&ansi_dim(","));
        }
        out.push('\n');
    }
    push_indent(indent, out);
    out.push_str(&ansi_dim("}"));
}

fn push_indent(indent: usize, out: &mut String) {
    out.extend(std::iter::repeat_n(' ', indent));
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn ansi_cyan(value: &str) -> String {
    format!("\x1b[36m{value}\x1b[39m")
}

fn ansi_yellow(value: &str) -> String {
    format!("\x1b[33m{value}\x1b[39m")
}

fn ansi_dim(value: &str) -> String {
    format!("\x1b[2m{value}\x1b[22m")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_stdout_suppression_leases_share_one_redirect() {
        let first = suppress_stdout(true).expect("first suppression starts");
        let second = suppress_stdout(true).expect("overlapping suppression shares redirect");

        drop(first);
        assert_eq!(
            stdout_suppression_state()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active_leases,
            1
        );
        drop(second);

        let state = stdout_suppression_state()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.active_leases, 0);
        assert!(state.gag.is_none());
    }

    #[test]
    fn json_answer_non_tty_matches_serde_pretty_bytes() {
        let value = serde_json::json!({
            "name": "demo",
            "nested": {
                "enabled": true,
                "count": 2
            },
            "items": ["one", "two"]
        });

        let expected = serde_json::to_string_pretty(&value).expect("json serializes");
        let actual = format_json_answer_for_stdout(&value, false).expect("json answer formats");

        assert_eq!(actual, expected);
    }

    #[test]
    fn colorized_json_styles_keys_string_values_and_punctuation() {
        let value = serde_json::json!({
            "name": "demo",
            "count": 2
        });

        let formatted = format_colorized_json(&value);

        assert!(
            formatted.contains("\x1b[36m\"name\"\x1b[39m"),
            "keys must be cyan: {formatted:?}"
        );
        assert!(
            formatted.contains("\x1b[33m\"demo\"\x1b[39m"),
            "string values must be yellow/gold: {formatted:?}"
        );
        assert!(
            formatted.contains("\x1b[2m{\x1b[22m"),
            "punctuation must be dimmed: {formatted:?}"
        );
    }
}
