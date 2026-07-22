use crate::install_ui;
use std::time::Duration;

pub fn blank_line() {
    eprintln!();
}

pub fn phase(msg: &str) {
    install_ui::phase(msg);
}

/// Emits a detail row assembled from trusted text and field-role helpers.
pub fn trusted_detail(label: &str, value: &str) {
    install_ui::detail(&format_detail_line(label, value, None));
}

/// Emits a trusted detail row while sanitizing the untrusted hint field.
pub fn trusted_detail_with_hint(label: &str, value: &str, hint: &str) {
    install_ui::detail(&format_detail_line(label, value, Some(hint)));
}

pub fn readiness(label: &str, value: &str) {
    eprintln!("{}", format_readiness_line(label, value, None));
}

pub fn readiness_with_hint(label: &str, value: &str, hint: &str) {
    eprintln!("{}", format_readiness_line(label, value, Some(hint)));
}

fn format_readiness_line(label: &str, value: &str, hint: Option<&str>) -> String {
    let suffix = hint.map_or_else(String::new, |hint| format!(" {}", install_ui::dim(hint)));
    let label = lpm_common::sanitize_terminal_inline(label);
    let value = lpm_common::sanitize_terminal_inline(value);
    format!(
        "  {} {:<7} {value}{suffix}",
        install_ui::bullet(true),
        label
    )
}

fn format_detail_line(label: &str, value: &str, hint: Option<&str>) -> String {
    let suffix = hint.map_or_else(String::new, |hint| format!(" {}", install_ui::dim(hint)));
    format!("  {} {value}{suffix}", install_ui::dim(label))
}

pub fn done(msg: &str) {
    install_ui::done(msg);
}

pub fn done_ready(subject: &str, duration: Duration) {
    let duration_str = install_ui::format_duration(duration);
    install_ui::done(&format!(
        "{} ready ({})",
        lpm_common::sanitize_terminal_inline(subject),
        install_ui::green(&duration_str),
    ));
}

pub fn warn(msg: &str) {
    install_ui::warn(&lpm_common::sanitize_terminal_inline(msg));
}

pub fn hint_line(msg: &str) {
    eprintln!("  {}", install_ui::dim(msg));
}

/// Emits a hint assembled only from LPM-owned text and field-level style helpers.
pub fn trusted_hint_line(msg: &str) {
    eprintln!("  {msg}");
}

/// Emits an LPM-generated terminal block verbatim; untrusted text must use a
/// field or readiness renderer instead.
pub fn raw_block(block: &str) {
    eprint!("{block}");
    if !block.ends_with('\n') {
        eprintln!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_line_uses_status_bullet_without_phase_glyph() {
        let line = format_readiness_line("Node", "v22.12.0", Some("(.nvmrc)"));

        assert!(
            line.contains('●'),
            "readiness line must use a status bullet: {line:?}"
        );
        assert!(
            !line.contains('›'),
            "readiness line must not use a phase glyph: {line:?}"
        );
        assert!(
            line.contains("Node") && line.contains("v22.12.0") && line.contains("(.nvmrc)"),
            "readiness line must include label, value, and hint: {line:?}"
        );
    }

    #[test]
    fn detail_line_uses_label_row_without_phase_glyph() {
        let line = format_detail_line("Local", "http://localhost:3000", None);
        let plain = console::strip_ansi_codes(&line);

        assert!(
            !plain.contains('›') && plain.starts_with("  Local "),
            "detail line must be a slim detail row, got: {plain:?}"
        );
    }
}
