use crate::install_ui;
use std::time::Duration;

pub fn blank_line() {
    eprintln!();
}

pub fn phase(msg: &str) {
    install_ui::phase(msg);
}

pub fn detail(label: &str, value: &str) {
    install_ui::phase(&format!("{label} {value}"));
}

pub fn detail_with_hint(label: &str, value: &str, hint: &str) {
    install_ui::phase(&format!("{label} {value} {}", install_ui::dim(hint)));
}

pub fn readiness(label: &str, value: &str) {
    eprintln!("{}", format_readiness_line(label, value, None));
}

pub fn readiness_with_hint(label: &str, value: &str, hint: &str) {
    eprintln!("{}", format_readiness_line(label, value, Some(hint)));
}

fn format_readiness_line(label: &str, value: &str, hint: Option<&str>) -> String {
    let suffix = hint.map_or_else(String::new, |hint| format!(" {}", install_ui::dim(hint)));
    format!(
        "  {} {:<7} {value}{suffix}",
        install_ui::bullet(true),
        label
    )
}

pub fn done(msg: &str) {
    install_ui::done(msg);
}

pub fn done_ready(subject: &str, duration: Duration) {
    let duration_str = install_ui::format_duration(duration);
    install_ui::done(&format!(
        "{subject} ready ({})",
        install_ui::green(&duration_str),
    ));
}

pub fn warn(msg: &str) {
    install_ui::warn(msg);
}

pub fn hint_line(msg: &str) {
    eprintln!("  {}", install_ui::dim(msg));
}

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
}
