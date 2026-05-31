use crate::install_ui;
use std::time::Duration;

pub fn phase_resolving_graph(package_count: usize) {
    install_ui::phase(&format!(
        "Resolving dependency graph ({} {})",
        install_ui::bold(&package_count.to_string()),
        install_ui::packages_word(package_count),
    ));
}

pub fn minus_package(name: &str, version: Option<&str>) {
    install_ui::minus_target(name, version, None);
}

pub fn minus_command(name: &str) {
    install_ui::minus(name, None, Some("(command)"));
}

pub fn minus_alias(name: &str) {
    install_ui::minus(name, None, Some("(alias)"));
}

pub fn warn_no_filter_match() {
    install_ui::warn("No packages matched the filter; nothing to uninstall.");
}

pub fn warn_no_packages_removed() {
    install_ui::warn("No packages were removed (not found in any target manifest)");
}

pub fn warn_not_found(names: &[String]) {
    install_ui::warn(&format!(
        "Not found in any targeted manifest: {}",
        names.join(", ")
    ));
}

pub fn done_removed(removed_count: usize, elapsed: Duration) {
    let duration_str = install_ui::format_duration(elapsed);
    install_ui::done(&format!(
        "Done · removed {} {} in {}",
        install_ui::bold(&removed_count.to_string()),
        install_ui::packages_word(removed_count),
        install_ui::green(&duration_str),
    ));
}

pub fn done_global(package: &str, version: &str) {
    install_ui::done(&format!(
        "Done · uninstalled {}{}",
        install_ui::bold(package),
        install_ui::dim(&format!("@{version}")),
    ));
}

pub fn warn_pruned_trust_entries(trust_entries_pruned: usize) {
    install_ui::warn(&format!(
        "Pruned {} host-global trust entr{} reachable only through this install.",
        trust_entries_pruned,
        if trust_entries_pruned == 1 {
            "y"
        } else {
            "ies"
        },
    ));
}
