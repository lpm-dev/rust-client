use crate::install_ui;

pub fn phase(msg: &str) {
    install_ui::phase(msg);
}

pub fn done(msg: &str) {
    install_ui::done(msg);
}

pub fn warn(msg: &str) {
    install_ui::warn(msg);
}

pub fn hint_line(msg: &str) {
    eprintln!("  {}", install_ui::dim(msg));
}

pub fn list_item(msg: &str) {
    eprintln!("  {msg}");
}
