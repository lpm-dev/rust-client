//! Validate `lpm.json > tools` keys against the plugin-backed set.
//!
//! `lpm.json` accepts an arbitrary `tools` map by serde shape, but
//! only `oxlint` and `biome` are plugin-backed and respect the pin.
//! A user-pinned `typescript` (or any other tool) is silently dropped
//! today — this helper surfaces the gap once per process invocation
//! so the warning fires once even when workspace mode runs the same
//! tool command across N members.
//!
//! The plugin set is small enough to inline. If a future plugin gets
//! added, both [`lpm_plugin::registry::PLUGINS`] and this list need
//! updating; the unit test pins the inventory.

use crate::install_ui;
use std::path::Path;
use std::sync::OnceLock;

const PLUGIN_BACKED_TOOLS: &[&str] = &["oxlint", "biome"];

static WARNED: OnceLock<()> = OnceLock::new();

/// Read `<project_dir>/lpm.json` once per process and warn for every
/// `tools.<key>` whose pin is silently dropped because no plugin
/// backs that key. Subsequent calls in the same process are no-ops —
/// workspace mode would otherwise repeat the warning per member.
pub fn warn_unsupported_tool_pins_once(project_dir: &Path) {
    if WARNED.get().is_some() {
        return;
    }

    let unsupported = match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(Some(config)) => collect_unsupported(&config.tools),
        _ => Vec::new(),
    };

    let _ = WARNED.set(());

    if unsupported.is_empty() {
        return;
    }

    emit_warning(&unsupported);
}

fn collect_unsupported(tools: &std::collections::HashMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = tools
        .keys()
        .filter(|k| !PLUGIN_BACKED_TOOLS.contains(&k.as_str()))
        .cloned()
        .collect();
    out.sort();
    out
}

fn emit_warning(unsupported: &[String]) {
    install_ui::warn(&format_warning(unsupported));
}

fn format_warning(unsupported: &[String]) -> String {
    let names = unsupported
        .iter()
        .map(|n| install_ui::cyan(&format!("tools.{n}")))
        .collect::<Vec<_>>()
        .join(", ");
    let supported = PLUGIN_BACKED_TOOLS
        .iter()
        .map(|tool| install_ui::yellow(tool))
        .collect::<Vec<_>>()
        .join(" and ");
    format!(
        "{}: {names} ignored — only {supported} are plugin-backed today",
        install_ui::cyan("lpm.json")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn collect_unsupported_filters_plugin_backed_keys() {
        let mut tools = HashMap::new();
        tools.insert("oxlint".to_string(), "1.58.0".to_string());
        tools.insert("biome".to_string(), "2.4.10".to_string());
        tools.insert("typescript".to_string(), "5.4.0".to_string());
        tools.insert("eslint".to_string(), "9.0.0".to_string());

        let unsupported = collect_unsupported(&tools);
        assert_eq!(unsupported, vec!["eslint", "typescript"]);
    }

    #[test]
    fn collect_unsupported_returns_empty_for_only_plugin_backed_keys() {
        let mut tools = HashMap::new();
        tools.insert("oxlint".to_string(), "1.58.0".to_string());
        tools.insert("biome".to_string(), "2.4.10".to_string());

        assert!(collect_unsupported(&tools).is_empty());
    }

    #[test]
    fn collect_unsupported_handles_empty_map() {
        assert!(collect_unsupported(&HashMap::new()).is_empty());
    }

    #[test]
    fn collect_unsupported_sorts_for_deterministic_output() {
        let mut tools = HashMap::new();
        tools.insert("zzz".to_string(), "1".to_string());
        tools.insert("aaa".to_string(), "1".to_string());
        tools.insert("mmm".to_string(), "1".to_string());

        let unsupported = collect_unsupported(&tools);
        assert_eq!(unsupported, vec!["aaa", "mmm", "zzz"]);
    }

    #[test]
    fn unsupported_tool_pin_warning_uses_slim_body_roles() {
        let warning = console::strip_ansi_codes(&format_warning(&[
            "typescript".to_string(),
            "eslint".to_string(),
        ]))
        .into_owned();

        assert_eq!(
            warning,
            "lpm.json: tools.typescript, tools.eslint ignored — only oxlint and biome are plugin-backed today"
        );
    }
}
