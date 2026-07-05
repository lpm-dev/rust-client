use super::prelude::*;

pub(in crate::commands::config) const FIREWALL_GUIDED_MENU_LABEL: &str = "Firewall for npm";
pub(in crate::commands::config) const FIREWALL_WIZARD_PROMPT: &str =
    "How should LPM handle firewall verdicts for npm packages?";
pub(in crate::commands::config) const FIREWALL_OFF_HINT: &str =
    "default; use direct npm metadata and tarballs only";
pub(in crate::commands::config) const FIREWALL_REPORT_HINT: &str = "warn without blocking install";
pub(in crate::commands::config) const FIREWALL_ENFORCE_HINT: &str =
    "block packages marked malicious by firewall.lpm.dev";

pub(in crate::commands::config) async fn run_firewall_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let selection = if let Some(value) = set {
        parse_firewall_mode_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config firewall requires a TTY; use `--set off|report|enforce` instead"
                    .to_string(),
            ));
        }

        let current = read_firewall_mode(config_path)?.unwrap_or_default();
        println!();
        println!(
            "  current: {}",
            format_current_firewall_mode(Some(current)).cyan()
        );
        let new_value: &str = cliclack::select(FIREWALL_WIZARD_PROMPT)
            .item("off", "off", FIREWALL_OFF_HINT)
            .item("report", "report", FIREWALL_REPORT_HINT)
            .item("enforce", "enforce", FIREWALL_ENFORCE_HINT)
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;
        parse_firewall_mode_selection(new_value)?
    };

    if set.is_none() && selection.loosens(read_firewall_mode(config_path)?.unwrap_or_default()) {
        println!();
        println!(
            "  {}: setting firewall mode to {} weakens npm firewall checks for every \
             install on this machine.",
            "warning".yellow(),
            selection.as_str().yellow().bold(),
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want to weaken npm firewall checks for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    let existing_cfg = read_config(config_path)?;
    crate::security_floor::reject_looser_firewall_mode_write(
        &global_config_view_from_value(&existing_cfg),
        selection,
    )?;
    crate::security_approval::authorize_persistent_npm_firewall_mode(
        selection,
        json_output,
        &format!("lpm config firewall --set {}", selection.as_str()),
    )?;
    persist_firewall_mode(config_path, selection)?;
    announce_firewall_mode_set(selection, json_output);
    Ok(())
}

pub(in crate::commands::config) fn parse_firewall_mode_selection(
    input: &str,
) -> Result<NpmFirewallMode, LpmError> {
    NpmFirewallMode::parse(input).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid firewall mode '{input}'; must be one of: off | report | enforce"
        ))
    })
}

pub(in crate::commands::config) fn read_firewall_mode(
    config_path: &std::path::Path,
) -> Result<Option<NpmFirewallMode>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    crate::npm_firewall_config::config_mode(&GlobalConfig { table })
}

pub(in crate::commands::config) fn persist_firewall_mode(
    config_path: &std::path::Path,
    mode: NpmFirewallMode,
) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    persist_firewall_mode_in_config_value(&mut cfg, mode)?;
    write_config(config_path, &cfg)
}

pub(in crate::commands::config) fn persist_firewall_mode_in_config_value(
    cfg: &mut toml::Value,
    mode: NpmFirewallMode,
) -> Result<(), LpmError> {
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let firewall_section = top
        .entry(FIREWALL_CONFIG_SECTION.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let firewall_table = firewall_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "`{FIREWALL_CONFIG_SECTION}` is not a TOML table — refusing to clobber"
        ))
    })?;
    firewall_table.insert(
        FIREWALL_CONFIG_MODE_KEY.to_string(),
        toml::Value::String(mode.as_str().to_string()),
    );
    Ok(())
}

pub(in crate::commands::config) fn format_current_firewall_mode(
    current: Option<NpmFirewallMode>,
) -> String {
    current.unwrap_or_default().as_str().to_string()
}

pub(in crate::commands::config) fn announce_firewall_mode_set(
    mode: NpmFirewallMode,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "firewall": { "mode": mode.as_str() },
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Set {FIREWALL_CONFIG_PATH} = {}",
            mode.as_str().bold()
        ));
    }
}
