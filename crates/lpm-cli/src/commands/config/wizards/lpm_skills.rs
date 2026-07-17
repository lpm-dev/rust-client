use super::prelude::*;
use crate::lpm_skills_config::{
    AUTO_INSTALL_LPM_SKILLS_KEY, LEGACY_NO_SKILLS_KEY, LpmSkillsPreference,
};

pub(in crate::commands::config) async fn run_lpm_skills_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{AUTO_INSTALL_LPM_SKILLS_KEY}` {message}"))
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
        let new_value: &str =
            cliclack::select("Auto-install package-published skills from @lpm.dev/* packages?")
                .item(
                    "true",
                    "enabled",
                    "default; reconcile LPM.dev package skills during installs",
                )
                .item(
                    "false",
                    "disabled",
                    "skip automatic skill fetches; existing files are kept",
                )
                .initial_value(if current { "true" } else { "false" })
                .interact()
                .map_err(prompt_err)?;
        parse_config_bool(new_value).map_err(|message| {
            LpmError::Registry(format!("`{AUTO_INSTALL_LPM_SKILLS_KEY}` {message}"))
        })?
    };

    persist_auto_install_lpm_skills(config_path, enabled)?;
    announce_bool_set(AUTO_INSTALL_LPM_SKILLS_KEY, enabled, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_auto_install_lpm_skills(
    config_path: &std::path::Path,
) -> Result<bool, LpmError> {
    let config = read_config(config_path)?;
    LpmSkillsPreference::Config.resolve(&global_config_view_from_value(&config))
}

pub(in crate::commands::config) fn format_current_lpm_skills(enabled: bool) -> &'static str {
    if enabled {
        "enabled (default)"
    } else {
        "disabled"
    }
}

fn persist_auto_install_lpm_skills(
    config_path: &std::path::Path,
    enabled: bool,
) -> Result<(), LpmError> {
    let mut config = read_config(config_path)?;
    let table = config.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    table.remove(LEGACY_NO_SKILLS_KEY);
    table.insert(
        AUTO_INSTALL_LPM_SKILLS_KEY.to_string(),
        toml::Value::Boolean(enabled),
    );
    write_config(config_path, &config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_false_persists_canonical_boolean_and_removes_legacy_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "registry = \"https://example.test\"\nnoSkills = false\n",
        )
        .unwrap();

        run_lpm_skills_wizard(&path, Some("false"), true)
            .await
            .unwrap();

        let config = read_config(&path).unwrap();
        assert_eq!(
            config.get(AUTO_INSTALL_LPM_SKILLS_KEY),
            Some(&toml::Value::Boolean(false))
        );
        assert!(config.get(LEGACY_NO_SKILLS_KEY).is_none());
        assert_eq!(
            config.get("registry").and_then(toml::Value::as_str),
            Some("https://example.test")
        );
    }

    #[tokio::test]
    async fn invalid_set_value_is_rejected_without_creating_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");

        let error = run_lpm_skills_wizard(&path, Some("sometimes"), true)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("must be true or false"));
        assert!(!path.exists());
    }
}
