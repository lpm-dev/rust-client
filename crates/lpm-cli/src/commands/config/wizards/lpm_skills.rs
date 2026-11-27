use super::prelude::*;
use crate::lpm_skills_config::{
    AUTO_INSTALL_LPM_SKILLS_KEY, LPM_DEV_PACKAGES_SETTING, LpmSkillsPreference,
};

pub(in crate::commands::config) async fn run_lpm_skills_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{LPM_DEV_PACKAGES_SETTING}` {message}"))
        })?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config lpm-skills requires a TTY; use `--set true|false` instead".to_string(),
            ));
        }

        let current = read_auto_install_lpm_skills(config_path)?;
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let new_value: &str = cliclack::select(
            "Install the reviewed skills of @lpm.dev/* packages and link them for agents?",
        )
        .item(
            "true",
            "enabled",
            "default; installs fetch LPM.dev package skills and link them",
        )
        .item(
            "false",
            "disabled",
            "skip skill fetches and remove LPM's links; fetched files are kept",
        )
        .initial_value(if current { "true" } else { "false" })
        .interact()
        .map_err(prompt_err)?;
        parse_config_bool(new_value).map_err(|message| {
            LpmError::Registry(format!("`{LPM_DEV_PACKAGES_SETTING}` {message}"))
        })?
    };

    persist_auto_install_lpm_skills(config_path, enabled).await?;
    if json_output {
        // Earlier releases printed only the legacy key; scripts may still read it.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                LPM_DEV_PACKAGES_SETTING: enabled,
                AUTO_INSTALL_LPM_SKILLS_KEY: enabled,
            }))?
        );
    } else {
        announce_bool_set(LPM_DEV_PACKAGES_SETTING, enabled, false);
    }
    Ok(())
}

pub(in crate::commands::config) fn read_auto_install_lpm_skills(
    config_path: &std::path::Path,
) -> Result<bool, LpmError> {
    let config = read_config(config_path)?;
    LpmSkillsPreference::Config.resolve(&GlobalConfig::from_value(config)?)
}

async fn persist_auto_install_lpm_skills(
    config_path: &std::path::Path,
    enabled: bool,
) -> Result<(), LpmError> {
    super::persist_skill_settings(config_path, Some(enabled), None).await
}
