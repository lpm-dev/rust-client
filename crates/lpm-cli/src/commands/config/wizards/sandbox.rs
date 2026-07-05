use super::prelude::*;

pub(in crate::commands::config) const SANDBOX_MODE_VALUES: &[&str] = &["default", "strict", "none"];

pub(in crate::commands::config) async fn run_sandbox_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(v) = set {
        if !SANDBOX_MODE_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid sandbox mode '{v}'; must be one of: {}",
                SANDBOX_MODE_VALUES.join(" | ")
            )));
        }
        let requested = ResolvedSandboxMode::parse_for_security_floor(v)
            .ok_or_else(|| LpmError::Registry(format!("invalid sandbox mode '{v}'")))?;
        crate::security_floor::reject_looser_sandbox_mode_write(&global, requested)?;
        crate::security_approval::authorize_persistent_sandbox_mode(
            requested,
            json_output,
            &format!("lpm config sandbox --set {v}"),
        )?;
        persist_sandbox_mode(config_path, v)?;
        announce_sandbox_set(v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config sandbox requires a TTY; use `--set default|strict|none` instead"
                .to_string(),
        ));
    }

    let current = read_sandbox_mode(config_path)?.unwrap_or_else(|| "default".to_string());
    println!();
    println!("  current: {}", current.cyan());
    let new_value: &str = cliclack::select("How strict should the install-time sandbox be?")
        .item(
            "default",
            "default — filesystem + env containment, outbound network allowed",
            "recommended",
        )
        .item(
            "strict",
            "strict  — + outbound network denied",
            "paranoid / CI / enterprise",
        )
        .item(
            "none",
            "none    — sandbox off",
            "NOT recommended — full host access for every script",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;

    // DX redline: confirm when the user picks `none` in
    // the interactive wizard. The `--set none` form trusts the
    // operator (no TTY check); only the wizard prompts.
    if new_value == "none" {
        println!();
        println!(
            "  {}: setting sandbox mode to {} means every lifecycle script that runs \
             gets full host access — filesystem open, full env (credentials), network. \
             This is the npm-default shape; LPM does not recommend it as a persistent \
             posture.",
            "warning".yellow(),
            "none".yellow().bold()
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want sandbox = none for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    let requested = ResolvedSandboxMode::parse_for_security_floor(new_value)
        .ok_or_else(|| LpmError::Registry(format!("invalid sandbox mode '{new_value}'")))?;
    crate::security_floor::reject_looser_sandbox_mode_write(&global, requested)?;
    crate::security_approval::authorize_persistent_sandbox_mode(
        requested,
        json_output,
        &format!("lpm config sandbox --set {new_value}"),
    )?;
    persist_sandbox_mode(config_path, new_value)?;
    announce_sandbox_set(new_value, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_sandbox_mode(
    config_path: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg
        .get("sandbox")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("mode"))
        .and_then(|v| v.as_str())
        .map(String::from))
}

pub(in crate::commands::config) fn persist_sandbox_mode(
    config_path: &std::path::Path,
    value: &str,
) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let sandbox_section = top
        .entry("sandbox".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let sandbox_table = sandbox_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `[sandbox]` is not a TOML table — refusing to clobber",
            config_path.display(),
        ))
    })?;
    sandbox_table.insert("mode".to_string(), toml::Value::String(value.to_string()));
    write_config(config_path, &cfg)
}

pub(in crate::commands::config) fn announce_sandbox_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "sandbox": { "mode": value },
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!("Set [sandbox] mode = {}", value.bold()));
    }
}
