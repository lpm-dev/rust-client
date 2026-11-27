use super::prelude::*;
use crate::lpm_insights_config::FETCH_LPM_SECURITY_INSIGHTS_KEY;
use crate::lpm_skills_config::LpmSkillsPreference;
#[cfg(test)]
use crate::lpm_skills_config::{
    AUTO_INSTALL_LPM_SKILLS_KEY, LEGACY_NO_SKILLS_KEY, LPM_DEV_PACKAGES_KEY, SKILLS_TABLE,
};
use console::Term;
use std::io;

const LPM_DEV_EDITOR_PROMPT: &str = "LPM.dev settings";
const LPM_DEV_EDITOR_HELP: &str = "Use ↑/↓ to move, ←/→ to change, Enter to save, Esc to cancel.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LpmDevSettings {
    package_skills: bool,
    security_insights: bool,
}

pub(in crate::commands::config) async fn run_lpm_dev_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if set.is_some() {
        return Err(LpmError::Registry(
            "lpm config lpm-dev is a combined interactive editor; use `lpm config lpm-skills --set true|false` or `lpm config lpm-insights --set true|false` for scripts"
                .to_string(),
        ));
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config lpm-dev requires a TTY; use the focused `lpm-skills` or `lpm-insights` setters instead"
                .to_string(),
        ));
    }

    let initial = read_lpm_dev_settings(config_path)?;
    let mut term = Term::stderr();
    let selected = run_lpm_dev_editor(&mut term, initial).map_err(prompt_err)?;
    persist_lpm_dev_settings(config_path, selected).await?;
    install_ui::done("Saved LPM.dev settings");
    Ok(())
}

pub(in crate::commands::config) async fn run_lpm_insights_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{FETCH_LPM_SECURITY_INSIGHTS_KEY}` {message}"))
        })?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config lpm-insights requires a TTY; use `--set true|false` instead"
                    .to_string(),
            ));
        }
        let current = read_fetch_lpm_security_insights(config_path)?;
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let selected: &str = cliclack::select(
            "Fetch install-time LPM.dev security insights for @lpm.dev/* packages?",
        )
        .item(
            "true",
            "enabled",
            "default; enrich the install summary with server-side findings",
        )
        .item(
            "false",
            "disabled",
            "show local analysis only; do not fetch summary enrichment",
        )
        .initial_value(if current { "true" } else { "false" })
        .interact()
        .map_err(prompt_err)?;
        parse_config_bool(selected).map_err(|message| {
            LpmError::Registry(format!("`{FETCH_LPM_SECURITY_INSIGHTS_KEY}` {message}"))
        })?
    };

    persist_bool(config_path, FETCH_LPM_SECURITY_INSIGHTS_KEY, enabled).await?;
    announce_bool_set(FETCH_LPM_SECURITY_INSIGHTS_KEY, enabled, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_fetch_lpm_security_insights(
    config_path: &std::path::Path,
) -> Result<bool, LpmError> {
    let config = read_config(config_path)?;
    crate::lpm_insights_config::read_fetch_lpm_security_insights(&GlobalConfig::from_value(config)?)
}

fn read_lpm_dev_settings(config_path: &std::path::Path) -> Result<LpmDevSettings, LpmError> {
    let config = read_config(config_path)?;
    let global = GlobalConfig::from_value(config)?;
    Ok(LpmDevSettings {
        package_skills: LpmSkillsPreference::Config.resolve(&global)?,
        security_insights: crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)?,
    })
}

async fn persist_lpm_dev_settings(
    config_path: &std::path::Path,
    settings: LpmDevSettings,
) -> Result<(), LpmError> {
    update_config(config_path, |config| {
        let table = config.table_mut();
        crate::lpm_skills_config::write_skill_settings(table, Some(settings.package_skills), None)?;
        table.insert(
            FETCH_LPM_SECURITY_INSIGHTS_KEY.to_string(),
            toml::Value::Boolean(settings.security_insights),
        );
        Ok(((), true))
    })
    .await
}

fn lpm_dev_toggles(settings: LpmDevSettings) -> Vec<super::editor::Toggle> {
    vec![
        super::editor::Toggle {
            title: "LPM.dev package skills",
            detail: "Install the reviewed skills of @lpm.dev/* dependencies and link them for agents?",
            enabled: settings.package_skills,
        },
        super::editor::Toggle {
            title: "Fetch LPM Registry Insights",
            detail: "At install time, use registry behavioral tags and lifecycle-script data. Audits add AI findings.",
            enabled: settings.security_insights,
        },
    ]
}

fn run_lpm_dev_editor(term: &mut Term, initial: LpmDevSettings) -> io::Result<LpmDevSettings> {
    let toggles = super::editor::run_toggles(
        term,
        LPM_DEV_EDITOR_PROMPT,
        LPM_DEV_EDITOR_HELP,
        lpm_dev_toggles(initial),
    )?;
    Ok(LpmDevSettings {
        package_skills: toggles[0].enabled,
        security_insights: toggles[1].enabled,
    })
}

#[cfg(test)]
fn format_lpm_dev_editor_frame(settings: LpmDevSettings, cursor: usize) -> String {
    super::editor::format_toggle_frame(
        LPM_DEV_EDITOR_PROMPT,
        LPM_DEV_EDITOR_HELP,
        &lpm_dev_toggles(settings),
        cursor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_editor_frame_contains_both_lpm_dev_controls() {
        let frame = format_lpm_dev_editor_frame(
            LpmDevSettings {
                package_skills: true,
                security_insights: false,
            },
            0,
        );
        let plain = console::strip_ansi_codes(&frame);
        assert!(plain.contains("LPM.dev package skills"));
        assert!(plain.contains("Fetch LPM Registry Insights"));
        assert!(plain.contains("Audits add AI findings."));
        assert!(!plain.contains("vulnerabilities"));
        assert!(plain.contains("● Enabled"));
        assert!(plain.contains("● Disabled"));
    }

    #[tokio::test]
    async fn grouped_save_writes_both_booleans_and_removes_legacy_skills_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "noSkills = true\nregistry = \"https://example.test\"\n",
        )
        .unwrap();

        persist_lpm_dev_settings(
            &path,
            LpmDevSettings {
                package_skills: true,
                security_insights: false,
            },
        )
        .await
        .unwrap();

        let config = read_config(&path).unwrap();
        assert_eq!(
            config
                .get(SKILLS_TABLE)
                .and_then(|skills| skills.get(LPM_DEV_PACKAGES_KEY)),
            Some(&toml::Value::Boolean(true))
        );
        assert!(config.get(AUTO_INSTALL_LPM_SKILLS_KEY).is_none());
        assert_eq!(
            config.get(FETCH_LPM_SECURITY_INSIGHTS_KEY),
            Some(&toml::Value::Boolean(false))
        );
        assert!(config.get(LEGACY_NO_SKILLS_KEY).is_none());
        assert_eq!(
            config.get("registry").and_then(toml::Value::as_str),
            Some("https://example.test")
        );
    }
}
