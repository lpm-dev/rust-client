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
