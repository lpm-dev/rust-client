use crate::install_ui;

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
    install_ui::phase(&format!("{label} {value}"));
}

pub fn list_item(message: &str) {
    eprintln!("  {message}");
}
