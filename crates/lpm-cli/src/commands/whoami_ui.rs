use crate::install_ui;

pub fn blank_line() {
    eprintln!();
}

pub fn done(message: &'static str) {
    install_ui::done(message);
}

pub fn phase_line(message: install_ui::TerminalLine) {
    install_ui::phase_line(message);
}

pub fn warn(message: &'static str) {
    install_ui::warn(message);
}

pub fn warn_untrusted(message: &str) {
    install_ui::warn_untrusted(message);
}

pub fn warn_line(message: install_ui::TerminalLine) {
    install_ui::warn_line(message);
}

pub fn detail<T: install_ui::TerminalValue>(label: &'static str, value: T) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim(&format!("{label:<14}")),
        value
    ));
}

pub fn section(message: &'static str) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {}",
        install_ui::section(message)
    ));
}

pub fn registry(name: &str, status: &str, active: bool) {
    let status = if active {
        install_ui::status_ok(status)
    } else {
        install_ui::dim(status)
    };
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} {} {}",
        install_ui::bullet(active),
        name,
        status
    ));
}

pub fn list_item(message: install_ui::TerminalLine) {
    install_ui::detail_line(crate::install_ui::terminal_line!("  {}", message));
}
