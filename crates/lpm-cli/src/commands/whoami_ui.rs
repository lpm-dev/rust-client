use crate::install_ui;
use lpm_common::color::Painted;

pub fn blank_line() {
    eprintln!();
}

pub fn done(message: &str) {
    install_ui::done(message);
}

pub fn phase(message: &str) {
    install_ui::phase(message);
}

pub fn warn(message: &str) {
    install_ui::warn(message);
}

pub fn detail(label: &str, value: &str) {
    eprintln!("  {} {value}", format!("{label:<14}").dimmed());
}

pub fn section(message: &str) {
    eprintln!("  {}", install_ui::section(message));
}

pub fn registry(name: &str, status: &str, active: bool) {
    let name = lpm_common::sanitize_terminal_inline(name);
    let status = if active {
        install_ui::status_ok(status)
    } else {
        install_ui::dim(status)
    };
    eprintln!("  {} {name} {status}", install_ui::bullet(active));
}

pub fn list_item(message: &str) {
    eprintln!("  {message}");
}
