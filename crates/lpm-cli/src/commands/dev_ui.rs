use crate::install_ui;
use std::time::Duration;

pub fn blank_line() {
    eprintln!();
}

pub fn phase(msg: &str) {
    install_ui::phase_untrusted(msg);
}

/// Emits a detail row assembled from trusted text and field-role helpers.
pub fn trusted_detail(label: &'static str, value: &install_ui::TerminalFragment) {
    install_ui::detail_line(format_detail_line(label, value, None));
}

pub fn trusted_detail_line(label: &'static str, value: install_ui::TerminalLine) {
    install_ui::detail_line(install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim(label),
        value,
    ));
}

/// Emits a trusted detail row while sanitizing the untrusted hint field.
pub fn trusted_detail_with_hint(
    label: &'static str,
    value: &install_ui::TerminalFragment,
    hint: &str,
) {
    install_ui::detail_line(format_detail_line(label, value, Some(hint)));
}

pub fn readiness(label: &str, value: &str) {
    install_ui::detail_line(format_readiness_line(label, value, None));
}

pub fn readiness_with_hint(label: &str, value: &str, hint: &str) {
    install_ui::detail_line(format_readiness_line(label, value, Some(hint)));
}

fn format_readiness_line(label: &str, value: &str, hint: Option<&str>) -> install_ui::TerminalLine {
    let suffix = hint.map_or_else(
        || install_ui::TerminalLine::new(""),
        |hint| install_ui::terminal_line!(" {}", install_ui::dim(hint)),
    );
    install_ui::terminal_line!(
        "  {} {:<7} {}{}",
        install_ui::bullet(true),
        label,
        value,
        suffix,
    )
}

fn format_detail_line(
    label: &'static str,
    value: &install_ui::TerminalFragment,
    hint: Option<&str>,
) -> install_ui::TerminalLine {
    let suffix = hint.map_or_else(
        || install_ui::TerminalLine::new(""),
        |hint| install_ui::terminal_line!(" {}", install_ui::dim(hint)),
    );
    install_ui::terminal_line!("  {} {}{}", install_ui::dim(label), value, suffix)
}

pub fn done(msg: &str) {
    install_ui::done_untrusted(msg);
}

pub fn done_ready(subject: &str, duration: Duration) {
    let duration_str = install_ui::format_duration(duration);
    install_ui::done_line(crate::install_ui::terminal_line!(
        "{} ready ({})",
        lpm_common::sanitize_terminal_inline(subject),
        install_ui::green(&duration_str),
    ));
}

pub fn warn(msg: &str) {
    install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(msg));
}

pub fn hint_line(msg: &str) {
    install_ui::detail_line(install_ui::terminal_line!("  {}", install_ui::dim(msg)));
}

/// Emits a hint assembled only from LPM-owned text and field-level style helpers.
pub fn trusted_hint_line(msg: install_ui::TerminalLine) {
    install_ui::detail_line(install_ui::terminal_line!("  {}", msg));
}

pub fn untrusted_block(block: &str) {
    let safe = lpm_common::sanitize_terminal_multiline(block);
    eprint!("{safe}");
    if !safe.ends_with('\n') {
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
        let value = install_ui::url("http://localhost:3000");
        let line = format_detail_line("Local", &value, None);
        let plain = console::strip_ansi_codes(&line);

        assert!(
            !plain.contains('›') && plain.starts_with("  Local "),
            "detail line must be a slim detail row, got: {plain:?}"
        );
    }
}
