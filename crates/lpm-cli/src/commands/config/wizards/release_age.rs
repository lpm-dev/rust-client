use super::prelude::*;

pub(in crate::commands::config) const RELEASE_AGE_KEY: &str = "minimum-release-age-secs";
pub(in crate::commands::config) const RELEASE_AGE_POLICY_KEY: &str =
    crate::release_age_config::GLOBAL_POLICY_KEY;
pub(in crate::commands::config) const DEFAULT_RELEASE_AGE_SECS: u64 =
    crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS;
pub(in crate::commands::config) const CAUTIOUS_RELEASE_AGE_SECS: u64 = 3 * DEFAULT_RELEASE_AGE_SECS;

#[derive(Clone, Copy)]
enum ReleaseAgeSelection {
    Default,
    Seconds(u64),
}

pub(in crate::commands::config) async fn run_release_age_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let selection = if let Some(value) = set {
        parse_release_age_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config release-age requires a TTY; use `--set default|off|0|<N>h|<N>d` instead"
                    .to_string(),
            ));
        }

        let current = read_release_age_override(config_path)?;
        println!();
        println!("  current: {}", format_current_release_age(current).cyan());
        let preset: &str =
            cliclack::select("How long should LPM wait before allowing newly published packages?")
                .item("default", "Default (1 day)", "recommended")
                .item("cautious", "Cautious (3 days)", "stricter")
                .item("off", "Off", "NOT recommended — disables the cooldown")
                .item("custom", "Custom", "enter 12h / 7d / 0")
                .initial_value(release_age_initial_choice(current))
                .interact()
                .map_err(prompt_err)?;

        match preset {
            "default" => ReleaseAgeSelection::Default,
            "cautious" => ReleaseAgeSelection::Seconds(CAUTIOUS_RELEASE_AGE_SECS),
            "off" => ReleaseAgeSelection::Seconds(0),
            "custom" => {
                let default_input =
                    current.map_or_else(|| "1d".to_string(), format_release_age_cli_value);
                let duration: String = cliclack::input("Minimum release age")
                    .default_input(&default_input)
                    .placeholder("1d, 12h, 0")
                    .validate(|input: &String| {
                        crate::release_age_config::parse_duration(input)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                    .interact()
                    .map_err(prompt_err)?;
                ReleaseAgeSelection::Seconds(crate::release_age_config::parse_duration(&duration)?)
            }
            _ => unreachable!("release-age select returned unexpected preset"),
        }
    };

    let requested_secs = match selection {
        ReleaseAgeSelection::Default => DEFAULT_RELEASE_AGE_SECS,
        ReleaseAgeSelection::Seconds(secs) => secs,
    };
    let requested_policy = if set.is_none() && requested_secs > 0 {
        Some(prompt_release_age_policy(config_path)?)
    } else {
        None
    };
    let command_hint = match selection {
        ReleaseAgeSelection::Default => "lpm config release-age --set default".to_string(),
        ReleaseAgeSelection::Seconds(0) => "lpm config release-age --set 0".to_string(),
        ReleaseAgeSelection::Seconds(secs) => {
            format!(
                "lpm config release-age --set {}",
                format_release_age_cli_value(secs)
            )
        }
    };
    let persisted = persist_release_age_selection(
        config_path,
        selection,
        requested_secs,
        requested_policy,
        json_output,
        &command_hint,
    )
    .await?;
    announce_release_age_set(persisted, json_output);
    Ok(())
}

fn parse_release_age_selection(input: &str) -> Result<ReleaseAgeSelection, LpmError> {
    match input {
        "default" => Ok(ReleaseAgeSelection::Default),
        "off" => Ok(ReleaseAgeSelection::Seconds(0)),
        other => crate::release_age_config::parse_duration(other).map(ReleaseAgeSelection::Seconds),
    }
}

pub(in crate::commands::config) fn read_release_age_override(
    config_path: &std::path::Path,
) -> Result<Option<u64>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_u64(RELEASE_AGE_KEY))
}

pub(in crate::commands::config) fn read_release_age_policy_override(
    config_path: &std::path::Path,
) -> Result<Option<crate::release_age_config::ReleaseAgePolicy>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    let Some(raw) = table.get(RELEASE_AGE_POLICY_KEY).and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    Ok(Some(crate::release_age_config::ReleaseAgePolicy::parse(
        RELEASE_AGE_POLICY_KEY,
        raw,
    )?))
}

pub(in crate::commands::config) fn prompt_release_age_policy(
    config_path: &std::path::Path,
) -> Result<crate::release_age_config::ReleaseAgePolicy, LpmError> {
    let current = read_release_age_policy_override(config_path)?.unwrap_or_default();
    let choice: &str = cliclack::select("Apply the release-age cooldown to which dependencies?")
        .item(
            "direct",
            "direct dependencies",
            "default; fastest normal installs",
        )
        .item(
            "strict",
            "direct and transitive dependencies",
            "stricter supply-chain posture",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;
    crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, choice)
}

async fn persist_release_age_selection(
    config_path: &std::path::Path,
    selection: ReleaseAgeSelection,
    requested_secs: u64,
    requested_policy: Option<crate::release_age_config::ReleaseAgePolicy>,
    json_output: bool,
    command_hint: &str,
) -> Result<Option<u64>, LpmError> {
    update_config(config_path, |config| {
        crate::security_floor::reject_looser_release_age_write(config, requested_secs)?;
        crate::security_approval::authorize_persistent_release_age(
            requested_secs,
            json_output,
            command_hint,
        )?;
        if let Some(policy) = requested_policy {
            crate::security_floor::reject_looser_release_age_policy_write(config, policy)?;
            crate::security_approval::authorize_persistent_release_age_policy(
                policy,
                json_output,
                &format!("lpm config release-age-policy --set {}", policy.as_str()),
            )?;
        }

        let top = config.table_mut();
        let persisted = match selection {
            ReleaseAgeSelection::Default => {
                top.remove(RELEASE_AGE_KEY);
                None
            }
            ReleaseAgeSelection::Seconds(secs) => {
                top.insert(
                    RELEASE_AGE_KEY.to_string(),
                    toml::Value::String(secs.to_string()),
                );
                Some(secs)
            }
        };
        if let Some(policy) = requested_policy {
            top.insert(
                RELEASE_AGE_POLICY_KEY.to_string(),
                toml::Value::String(policy.as_str().to_string()),
            );
        }
        Ok((persisted, true))
    })
    .await
}

pub(in crate::commands::config) async fn run_release_age_policy_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let policy = if let Some(value) = set {
        crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config release-age-policy requires a TTY; use `--set direct|strict` instead"
                    .to_string(),
            ));
        }
        prompt_release_age_policy(config_path)?
    };

    update_config(config_path, |config| {
        crate::security_floor::reject_looser_release_age_policy_write(config, policy)?;
        crate::security_approval::authorize_persistent_release_age_policy(
            policy,
            json_output,
            &format!("lpm config release-age-policy --set {}", policy.as_str()),
        )?;
        let table = config.table_mut();
        table.insert(
            RELEASE_AGE_POLICY_KEY.to_string(),
            toml::Value::String(policy.as_str().to_string()),
        );
        Ok(((), true))
    })
    .await?;
    announce_release_age_policy_set(policy, json_output);
    Ok(())
}

pub(in crate::commands::config) fn format_release_age_cli_value(secs: u64) -> String {
    if secs == 0 {
        return "0".to_string();
    }
    if secs.is_multiple_of(86400) {
        return format!("{}d", secs / 86400);
    }
    if secs.is_multiple_of(3600) {
        return format!("{}h", secs / 3600);
    }
    secs.to_string()
}

pub(in crate::commands::config) fn format_current_release_age(current: Option<u64>) -> String {
    match current {
        None => "default (1d)".to_string(),
        Some(0) => "off".to_string(),
        Some(secs) if secs == DEFAULT_RELEASE_AGE_SECS => "1d (explicit override)".to_string(),
        Some(secs) => format_release_age_cli_value(secs),
    }
}

pub(in crate::commands::config) fn release_age_initial_choice(
    current: Option<u64>,
) -> &'static str {
    match current {
        None => "default",
        Some(0) => "off",
        Some(secs) if secs == CAUTIOUS_RELEASE_AGE_SECS => "cautious",
        Some(_) => "custom",
    }
}

pub(in crate::commands::config) fn announce_release_age_set(value: Option<u64>, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                RELEASE_AGE_KEY: value,
            }))
            .unwrap()
        );
        return;
    }

    match value {
        None => install_ui::done("Using default minimum release age (1d)"),
        Some(0) => install_ui::done("Set minimum release age = off"),
        Some(secs) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Set minimum release age = {}",
            install_ui::bold(&format_release_age_cli_value(secs)),
        )),
    }
}

pub(in crate::commands::config) fn announce_release_age_policy_set(
    policy: crate::release_age_config::ReleaseAgePolicy,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                RELEASE_AGE_POLICY_KEY: policy.as_str(),
            }))
            .unwrap()
        );
        return;
    }
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Set release-age-policy = {}",
        install_ui::bold(policy.as_str()),
    ));
}
