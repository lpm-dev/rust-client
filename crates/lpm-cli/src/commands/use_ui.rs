use crate::install_ui;

pub fn phase(msg: &str) {
    install_ui::phase_untrusted(msg);
}

pub fn phase_line(msg: install_ui::TerminalLine) {
    install_ui::phase_line(msg);
}

pub fn done(msg: &str) {
    install_ui::done_untrusted(msg);
}

pub fn done_line(msg: install_ui::TerminalLine) {
    install_ui::done_line(msg);
}

pub fn warn(msg: &str) {
    install_ui::warn_untrusted(msg);
}

pub fn hint_line(msg: &str) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {}",
        install_ui::dim(msg)
    ));
}

pub fn list_item(msg: &str) {
    install_ui::detail_line(crate::install_ui::terminal_line!("  {}", msg));
}
