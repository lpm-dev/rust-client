use super::prelude::*;
use crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY;

pub(in crate::commands::config) async fn run_source_analysis_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{INSTALL_TIME_SOURCE_ANALYSIS_KEY}` {message}"))
        })?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config source-analysis requires a TTY; use `--set true|false` instead"
                    .to_string(),
            ));
        }
        let current = read_install_time_source_analysis(config_path)?;
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let selected: &str = cliclack::select("Analyze package source while installing?")
            .item(
                "true",
                "enabled",
                "default; analyze extracted package bytes and maintain the local cache",
            )
            .item(
                "false",
                "disabled",
                "defer behavioral source analysis until `lpm audit`",
            )
            .initial_value(if current { "true" } else { "false" })
            .interact()
            .map_err(prompt_err)?;
        parse_config_bool(selected).map_err(|message| {
            LpmError::Registry(format!("`{INSTALL_TIME_SOURCE_ANALYSIS_KEY}` {message}"))
        })?
    };

    let existing_config = read_config(config_path)?;
    if !enabled
        && crate::security_floor::force_security_floor_enabled(&global_config_view_from_value(
            &existing_config,
        ))
    {
        return Err(crate::security_floor::security_floor_write_error(
            INSTALL_TIME_SOURCE_ANALYSIS_KEY,
            "false",
            "true",
        ));
    }
    crate::security_approval::authorize_persistent_install_time_source_analysis(
        enabled,
        json_output,
        &format!("lpm config source-analysis --set {enabled}"),
    )?;
    persist_bool(config_path, INSTALL_TIME_SOURCE_ANALYSIS_KEY, enabled)?;
    announce_bool_set(INSTALL_TIME_SOURCE_ANALYSIS_KEY, enabled, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_install_time_source_analysis(
    config_path: &std::path::Path,
) -> Result<bool, LpmError> {
    let config = read_config(config_path)?;
    crate::source_analysis_config::read_install_time_source_analysis(
        &global_config_view_from_value(&config),
    )
}
