use crate::install_ui;
use lpm_common::LpmError;

use super::super::global_config::GlobalConfig;
use super::super::io::{read_config, update_config};

pub(in crate::commands::config) const SCRIPT_POLICY_KEY: &str = "script-policy";
pub(in crate::commands::config) const TRIAGE_ADVISOR_KEY: &str = "triage-advisor";
pub(in crate::commands::config) const SIGNATURES_KEY: &str = "signatures";

pub(in crate::commands::config) const SCRIPT_POLICY_VALUES: &[&str] = &["deny", "triage", "allow"];
pub(in crate::commands::config) const TRIAGE_ADVISOR_VALUES: &[&str] =
    &["none", "claude-cli", "codex", "ollama"];

pub(in crate::commands::config) fn parse_config_bool(input: &str) -> Result<bool, &'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "enabled" => Ok(true),
        "false" | "0" | "no" | "off" | "disabled" => Ok(false),
        _ => Err("must be true or false"),
    }
}

pub(in crate::commands::config) fn read_bool_value(
    config_path: &std::path::Path,
    key: &str,
) -> Result<Option<bool>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_bool(key))
}

pub(in crate::commands::config) async fn persist_bool(
    config_path: &std::path::Path,
    key: &str,
    value: bool,
) -> Result<(), LpmError> {
    update_config(config_path, |config| {
        let table = config.table_mut();
        table.insert(key.to_string(), toml::Value::Boolean(value));
        Ok(((), true))
    })
    .await
}

pub(in crate::commands::config) fn format_bool_enabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

pub(in crate::commands::config) fn announce_bool_set(key: &str, value: bool, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                key: value,
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set {} = {}",
            key,
            install_ui::bold(format_bool_enabled(value)),
        ));
    }
}

pub(in crate::commands::config) fn read_string_value(
    config_path: &std::path::Path,
    key: &str,
) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg.get(key).and_then(|v| v.as_str()).map(String::from))
}

pub(in crate::commands::config) async fn persist_string(
    config_path: &std::path::Path,
    key: &str,
    value: &str,
) -> Result<(), LpmError> {
    update_config(config_path, |config| {
        let table = config.table_mut();
        table.insert(key.to_string(), toml::Value::String(value.to_string()));
        Ok(((), true))
    })
    .await
}

pub(in crate::commands::config) fn announce_set(key: &str, value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                key: value,
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · {} = {}",
            key,
            install_ui::section(&format!("\"{value}\""))
        ));
    }
}
