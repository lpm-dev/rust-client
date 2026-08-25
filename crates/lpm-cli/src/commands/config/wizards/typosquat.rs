use super::prelude::*;

pub(crate) const TYPOSQUAT_GUARD_KEY: &str = "typosquat-guard";
pub(in crate::commands::config) const TYPOSQUAT_GUARD_VALUES: &[&str] = &["default", "on", "off"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TyposquatGuardSelection {
    Default,
    On,
    Off,
}

impl TyposquatGuardSelection {
    pub(crate) fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "default" => Some(Self::Default),
            "on" | "true" | "1" | "yes" | "enabled" => Some(Self::On),
            "off" | "false" | "0" | "no" | "disabled" => Some(Self::Off),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    pub(crate) fn disables_guard(self) -> bool {
        matches!(self, Self::Off)
    }

    pub(crate) fn loosens(self, floor: Self) -> bool {
        self.rank() < floor.rank()
    }

    fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Default => 1,
            Self::On => 2,
        }
    }
}

pub(in crate::commands::config) async fn run_typosquat_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let selection = if let Some(value) = set {
        parse_typosquat_guard_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config typosquat requires a TTY; use `--set default|on|off` instead"
                    .to_string(),
            ));
        }

        let current =
            read_typosquat_guard_override(config_path)?.unwrap_or(TyposquatGuardSelection::Default);
        println!();
        println!(
            "  current: {}",
            format_current_typosquat_guard(Some(current)).cyan()
        );
        let new_value: &str = cliclack::select("How should LPM handle suspicious package names?")
            .item(
                "default",
                "default — enabled unless the product default changes",
                "recommended",
            )
            .item(
                "on",
                "on — always run the guard",
                "ignores diagnostic env opt-outs",
            )
            .item("off", "off — skip typosquat analysis", "NOT recommended")
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;
        parse_typosquat_guard_selection(new_value)?
    };

    if set.is_none() && selection.disables_guard() {
        println!();
        println!(
            "  {}: setting typosquat-guard = {} disables suspicious-name checks for every \
             install on this machine. Prefer project allow-list entries for intentional \
             false positives.",
            "warning".yellow(),
            "off".yellow().bold(),
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want typosquat-guard = off for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    update_config(config_path, |config| {
        reject_looser_typosquat_guard_write(config, selection)?;
        crate::security_approval::authorize_persistent_typosquat_guard(
            selection,
            json_output,
            &format!("lpm config typosquat --set {}", selection.as_str()),
        )?;
        let top = config.table_mut();
        if selection == TyposquatGuardSelection::Default {
            top.remove(TYPOSQUAT_GUARD_KEY);
        } else {
            top.insert(
                TYPOSQUAT_GUARD_KEY.to_string(),
                toml::Value::String(selection.as_str().to_string()),
            );
        }
        Ok(((), true))
    })
    .await?;
    announce_typosquat_guard_set(selection, json_output);
    Ok(())
}

pub(in crate::commands::config) fn parse_typosquat_guard_selection(
    input: &str,
) -> Result<TyposquatGuardSelection, LpmError> {
    TyposquatGuardSelection::parse(input).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid typosquat-guard '{input}'; must be one of: {}",
            TYPOSQUAT_GUARD_VALUES.join(" | ")
        ))
    })
}

pub(in crate::commands::config) fn read_typosquat_guard_override(
    config_path: &std::path::Path,
) -> Result<Option<TyposquatGuardSelection>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_typosquat_guard_mode())
}

pub(in crate::commands::config) fn reject_looser_typosquat_guard_write(
    global: &GlobalConfig,
    requested: TyposquatGuardSelection,
) -> Result<(), LpmError> {
    if !crate::security_floor::force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = global
        .get_typosquat_guard_mode()
        .unwrap_or(TyposquatGuardSelection::Default);
    if !requested.loosens(floor) {
        return Ok(());
    }
    Err(crate::security_floor::security_floor_write_error(
        TYPOSQUAT_GUARD_KEY,
        requested.as_str(),
        floor.as_str(),
    ))
}

pub(in crate::commands::config) fn format_current_typosquat_guard(
    current: Option<TyposquatGuardSelection>,
) -> String {
    match current {
        None | Some(TyposquatGuardSelection::Default) => "default (enabled)".to_string(),
        Some(selection) => selection.as_str().to_string(),
    }
}

pub(in crate::commands::config) fn announce_typosquat_guard_set(
    selection: TyposquatGuardSelection,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                TYPOSQUAT_GUARD_KEY: selection.as_str(),
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set typosquat-guard = {}",
            install_ui::bold(&format_current_typosquat_guard(Some(selection))),
        ));
    }
}
