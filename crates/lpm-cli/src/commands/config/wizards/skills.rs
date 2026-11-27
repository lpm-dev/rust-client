use super::prelude::*;
use crate::lpm_skills_config::{
    LPM_DEV_PACKAGES_SETTING, LpmSkillsPreference, OTHER_PACKAGES_SETTING,
    SECURITY_PROVIDER_SETTING, SecurityProvider, other_package_skills_enabled, security_provider,
    write_security_provider, write_skill_settings,
};
use console::Term;

const SKILLS_EDITOR_PROMPT: &str = "Skill settings";
const SKILLS_EDITOR_HELP: &str = "Use ↑/↓ to move, ←/→ to change, Enter to save, Esc to cancel.";

/// The user's skill settings in `[skills]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::commands::config) struct SkillSettings {
    pub(in crate::commands::config) lpm_dev_packages: bool,
    pub(in crate::commands::config) other_packages: bool,
    pub(in crate::commands::config) security_provider: SecurityProvider,
}

pub(in crate::commands::config) async fn run_skills_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if set.is_some() {
        return Err(LpmError::Registry(
            "lpm config skills is an interactive editor; use `lpm config lpm-skills --set true|false` or `lpm config npm-skills --set true|false` for scripts"
                .to_string(),
        ));
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config skills requires a TTY; use the focused `lpm-skills` or `npm-skills` setters instead"
                .to_string(),
        ));
    }
    let initial = read_skill_settings(config_path)?;
    let mut term = Term::stderr();
    let toggles = super::editor::run_toggles(
        &mut term,
        SKILLS_EDITOR_PROMPT,
        SKILLS_EDITOR_HELP,
        toggles(initial),
    )
    .map_err(prompt_err)?;
    let selected = SkillSettings {
        lpm_dev_packages: toggles[0].enabled,
        other_packages: toggles[1].enabled,
        security_provider: if toggles[2].enabled {
            SecurityProvider::Socket
        } else {
            SecurityProvider::None
        },
    };
    update_config(config_path, |config| {
        write_skill_settings(
            config.table_mut(),
            Some(selected.lpm_dev_packages),
            Some(selected.other_packages),
        )?;
        write_security_provider(config.table_mut(), selected.security_provider)?;
        Ok(((), true))
    })
    .await?;
    install_ui::done("Saved skill settings");
    if selected.security_provider == SecurityProvider::Socket
        && lpm_auth::resolve_socket_credential().is_none()
    {
        install_ui::warn(
            "Socket checks need a Socket API token: run `lpm login --socket`, or set SOCKET_CLI_API_TOKEN",
        );
    }
    Ok(())
}

/// `lpm config set skills.security-provider <none|socket>`.
pub(in crate::commands::config) async fn persist_security_provider(
    config_path: &std::path::Path,
    value: &str,
) -> Result<SecurityProvider, LpmError> {
    let provider = SecurityProvider::parse(value).ok_or_else(|| {
        LpmError::Registry(format!(
            "`{SECURITY_PROVIDER_SETTING}` must be \"none\" or \"socket\""
        ))
    })?;
    update_config(config_path, |config| {
        write_security_provider(config.table_mut(), provider)?;
        Ok(((), true))
    })
    .await?;
    Ok(provider)
}

pub(in crate::commands::config) async fn run_npm_skills_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{OTHER_PACKAGES_SETTING}` {message}"))
        })?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config npm-skills requires a TTY; use `--set true|false` instead".to_string(),
            ));
        }
        let current = read_skill_settings(config_path)?.other_packages;
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let selected: &str =
            cliclack::select("Link the skills of npm and other packages that a project allows?")
                .item(
                    "true",
                    "enabled",
                    "default; follow each project's `package.json > lpm > skills`",
                )
                .item(
                    "false",
                    "disabled",
                    "never link them for you; links LPM made are removed at the next install",
                )
                .initial_value(if current { "true" } else { "false" })
                .interact()
                .map_err(prompt_err)?;
        parse_config_bool(selected).map_err(|message| {
            LpmError::Registry(format!("`{OTHER_PACKAGES_SETTING}` {message}"))
        })?
    };
    persist_skill_settings(config_path, None, Some(enabled)).await?;
    announce_bool_set(OTHER_PACKAGES_SETTING, enabled, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_skill_settings(
    config_path: &std::path::Path,
) -> Result<SkillSettings, LpmError> {
    let global = GlobalConfig::from_value(read_config(config_path)?)?;
    Ok(SkillSettings {
        lpm_dev_packages: LpmSkillsPreference::Config.resolve(&global)?,
        other_packages: other_package_skills_enabled(&global)?,
        security_provider: security_provider(&global)?,
    })
}

pub(in crate::commands::config) async fn persist_skill_settings(
    config_path: &std::path::Path,
    lpm_dev_packages: Option<bool>,
    other_packages: Option<bool>,
) -> Result<(), LpmError> {
    update_config(config_path, |config| {
        write_skill_settings(config.table_mut(), lpm_dev_packages, other_packages)?;
        Ok(((), true))
    })
    .await
}

pub(in crate::commands::config) fn format_current_skill_settings(
    settings: SkillSettings,
) -> String {
    format!(
        "lpm.dev={}, npm={}, check={}",
        format_bool_enabled(settings.lpm_dev_packages),
        format_bool_enabled(settings.other_packages),
        settings.security_provider.as_str()
    )
}

/// The `lpm config set` names of the two settings, for the generic setter.
pub(in crate::commands::config) const SKILL_SETTINGS: [&str; 2] =
    [LPM_DEV_PACKAGES_SETTING, OTHER_PACKAGES_SETTING];

fn toggles(settings: SkillSettings) -> Vec<super::editor::Toggle> {
    vec![
        super::editor::Toggle {
            title: "LPM.dev package skills",
            detail: "Install the reviewed skills of @lpm.dev/* dependencies and link them for agents.",
            enabled: settings.lpm_dev_packages,
        },
        super::editor::Toggle {
            title: "npm and other package skills",
            detail: "Link the skills of npm and other dependencies that a project's package.json allows.",
            enabled: settings.other_packages,
        },
        super::editor::Toggle {
            title: "Socket security check",
            detail: "Before linking them, check those skills' packages with Socket (needs `lpm login --socket`).",
            enabled: settings.security_provider == SecurityProvider::Socket,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_editor_frame_shows_every_skill_setting() {
        let frame = super::super::editor::format_toggle_frame(
            SKILLS_EDITOR_PROMPT,
            SKILLS_EDITOR_HELP,
            &toggles(SkillSettings {
                lpm_dev_packages: true,
                other_packages: false,
                security_provider: SecurityProvider::None,
            }),
            1,
        );
        let plain = console::strip_ansi_codes(&frame);
        assert!(plain.contains("Skill settings"));
        assert!(plain.contains("LPM.dev package skills"));
        assert!(plain.contains("npm and other package skills"));
        assert!(plain.contains("Socket security check"));
        assert!(plain.contains("● Enabled"));
        assert!(plain.contains("● Disabled"));
    }

    #[tokio::test]
    async fn saving_writes_the_skills_table_and_keeps_other_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "auto-install-lpm-skills = true\nregistry = \"https://example.test\"\n",
        )
        .unwrap();

        persist_skill_settings(&path, Some(false), Some(false))
            .await
            .unwrap();

        let settings = read_skill_settings(&path).unwrap();
        assert_eq!(
            settings,
            SkillSettings {
                lpm_dev_packages: false,
                other_packages: false,
                security_provider: SecurityProvider::None,
            }
        );
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains("auto-install-lpm-skills"), "{written}");
        assert!(written.contains("registry = \"https://example.test\""));
    }

    #[tokio::test]
    async fn the_security_provider_is_saved_by_name_and_unknown_names_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "").unwrap();

        assert_eq!(
            persist_security_provider(&path, "Socket").await.unwrap(),
            SecurityProvider::Socket
        );
        assert_eq!(
            read_skill_settings(&path).unwrap().security_provider,
            SecurityProvider::Socket
        );
        assert!(
            persist_security_provider(&path, "virustotal")
                .await
                .is_err()
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("security-provider = \"socket\"")
        );
    }
}
