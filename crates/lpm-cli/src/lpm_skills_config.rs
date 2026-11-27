use lpm_common::LpmError;

use crate::commands::config::GlobalConfig;

pub(crate) const AUTO_INSTALL_LPM_SKILLS_KEY: &str = "auto-install-lpm-skills";
pub(crate) const LEGACY_NO_SKILLS_KEY: &str = "noSkills";
/// The `[skills]` table in `~/.lpm/config.toml`.
pub(crate) const SKILLS_TABLE: &str = "skills";
/// `[skills] lpm-dev-packages`: install the reviewed skills of `@lpm.dev/*`
/// dependencies and link them for agents. Replaces the top-level
/// `auto-install-lpm-skills`, which is still read when this key is absent,
/// and `noSkills` before it.
pub(crate) const LPM_DEV_PACKAGES_KEY: &str = "lpm-dev-packages";
/// `[skills] other-packages`: link the skills of npm and other non-LPM.dev
/// dependencies that a project allows.
pub(crate) const OTHER_PACKAGES_KEY: &str = "other-packages";
/// The dotted names `lpm config` uses for the two settings.
pub(crate) const LPM_DEV_PACKAGES_SETTING: &str = "skills.lpm-dev-packages";
pub(crate) const OTHER_PACKAGES_SETTING: &str = "skills.other-packages";

/// Where the LPM.dev package-skills setting came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LpmDevSkillsSource {
    Skills,
    LegacyAutoInstall,
    LegacyNoSkills,
    Default,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum LpmSkillsPreference {
    #[default]
    Config,
    Enabled,
    Disabled,
}

impl LpmSkillsPreference {
    pub(crate) fn from_cli(skills: bool, no_skills: bool) -> Self {
        match (skills, no_skills) {
            (true, false) => Self::Enabled,
            (false, true) => Self::Disabled,
            _ => Self::Config,
        }
    }

    pub(crate) fn resolve(self, config: &GlobalConfig) -> Result<bool, LpmError> {
        match self {
            Self::Enabled => Ok(true),
            Self::Disabled => Ok(false),
            Self::Config => resolve_from_config(config),
        }
    }
}

fn resolve_from_config(config: &GlobalConfig) -> Result<bool, LpmError> {
    if let Some(value) = skills_table(config)?.and_then(|table| table.get(LPM_DEV_PACKAGES_KEY)) {
        return parse_bool(value).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{LPM_DEV_PACKAGES_SETTING}` in ~/.lpm/config.toml; must be true or false"
            ))
        });
    }
    if let Some(value) = config.get_value(AUTO_INSTALL_LPM_SKILLS_KEY) {
        return parse_bool(value).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{AUTO_INSTALL_LPM_SKILLS_KEY}` in ~/.lpm/config.toml; must be true or false"
            ))
        });
    }

    Ok(!config.get_bool(LEGACY_NO_SKILLS_KEY).unwrap_or(false))
}

/// Whether the user lets projects link the skills of npm and other
/// non-LPM.dev dependencies: `[skills] other-packages`, on by default. A
/// project still has to allow each one.
pub(crate) fn other_package_skills_enabled(config: &GlobalConfig) -> Result<bool, LpmError> {
    let Some(table) = skills_table(config)? else {
        return Ok(true);
    };
    match table.get(OTHER_PACKAGES_KEY) {
        None => Ok(true),
        Some(value) => parse_bool(value).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{SKILLS_TABLE}.{OTHER_PACKAGES_KEY}` in ~/.lpm/config.toml; must be true or false"
            ))
        }),
    }
}

/// Where the LPM.dev package-skills setting comes from in `config`.
pub(crate) fn lpm_dev_skills_source(config: &GlobalConfig) -> LpmDevSkillsSource {
    if skills_table(config)
        .ok()
        .flatten()
        .is_some_and(|table| table.contains_key(LPM_DEV_PACKAGES_KEY))
    {
        LpmDevSkillsSource::Skills
    } else if config.get_value(AUTO_INSTALL_LPM_SKILLS_KEY).is_some() {
        LpmDevSkillsSource::LegacyAutoInstall
    } else if config.get_value(LEGACY_NO_SKILLS_KEY).is_some() {
        LpmDevSkillsSource::LegacyNoSkills
    } else {
        LpmDevSkillsSource::Default
    }
}

/// Writes the skill settings given into `table`, the whole user config, under
/// `[skills]`. Writing the LPM.dev one removes the legacy keys it replaces.
pub(crate) fn write_skill_settings(
    table: &mut toml::map::Map<String, toml::Value>,
    lpm_dev_packages: Option<bool>,
    other_packages: Option<bool>,
) -> Result<(), LpmError> {
    let skills = table
        .entry(SKILLS_TABLE)
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "`{SKILLS_TABLE}` in ~/.lpm/config.toml is not a table; fix it before changing skill settings"
            ))
        })?;
    if let Some(enabled) = lpm_dev_packages {
        skills.insert(LPM_DEV_PACKAGES_KEY.into(), toml::Value::Boolean(enabled));
    }
    if let Some(enabled) = other_packages {
        skills.insert(OTHER_PACKAGES_KEY.into(), toml::Value::Boolean(enabled));
    }
    if lpm_dev_packages.is_some() {
        table.remove(AUTO_INSTALL_LPM_SKILLS_KEY);
        table.remove(LEGACY_NO_SKILLS_KEY);
    }
    Ok(())
}

fn skills_table(config: &GlobalConfig) -> Result<Option<&toml::value::Table>, LpmError> {
    match config.get_value(SKILLS_TABLE) {
        None => Ok(None),
        Some(value) => value.as_table().map(Some).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{SKILLS_TABLE}` in ~/.lpm/config.toml; must be a table"
            ))
        }),
    }
}

fn parse_bool(value: &toml::Value) -> Option<bool> {
    match value {
        toml::Value::Boolean(value) => Some(*value),
        toml::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" | "enabled" => Some(true),
            "false" | "0" | "no" | "off" | "disabled" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(contents: &str) -> GlobalConfig {
        let value: toml::Value = toml::from_str(contents).unwrap();
        GlobalConfig::from_table(value.as_table().unwrap().clone())
    }

    #[test]
    fn absent_config_enables_lpm_package_skills() {
        assert!(
            LpmSkillsPreference::Config
                .resolve(&GlobalConfig::empty())
                .unwrap()
        );
    }

    #[test]
    fn canonical_config_disables_lpm_package_skills() {
        assert!(
            !LpmSkillsPreference::Config
                .resolve(&config("auto-install-lpm-skills = false"))
                .unwrap()
        );
    }

    #[test]
    fn the_skills_table_wins_over_both_legacy_keys() {
        let config = config(
            "auto-install-lpm-skills = true\nnoSkills = false\n[skills]\nlpm-dev-packages = false",
        );
        assert!(!LpmSkillsPreference::Config.resolve(&config).unwrap());
        assert_eq!(lpm_dev_skills_source(&config), LpmDevSkillsSource::Skills);
    }

    #[test]
    fn writing_the_lpm_dev_setting_migrates_the_legacy_keys() {
        let value: toml::Value =
            toml::from_str("auto-install-lpm-skills = false\nnoSkills = true\nregistry = \"x\"")
                .unwrap();
        let mut table = value.as_table().unwrap().clone();
        write_skill_settings(&mut table, Some(true), None).unwrap();

        let config = GlobalConfig::from_table(table.clone());
        assert!(LpmSkillsPreference::Config.resolve(&config).unwrap());
        assert!(!table.contains_key(AUTO_INSTALL_LPM_SKILLS_KEY));
        assert!(!table.contains_key(LEGACY_NO_SKILLS_KEY));
        assert_eq!(table["registry"].as_str(), Some("x"));
        assert!(other_package_skills_enabled(&config).unwrap());

        write_skill_settings(&mut table, None, Some(false)).unwrap();
        let config = GlobalConfig::from_table(table);
        assert!(!other_package_skills_enabled(&config).unwrap());
        assert!(LpmSkillsPreference::Config.resolve(&config).unwrap());
    }

    #[test]
    fn a_non_table_skills_entry_is_refused_rather_than_overwritten() {
        let value: toml::Value = toml::from_str("skills = true").unwrap();
        let mut table = value.as_table().unwrap().clone();
        assert!(write_skill_settings(&mut table, Some(true), None).is_err());
        assert!(
            LpmSkillsPreference::Config
                .resolve(&GlobalConfig::from_table(table))
                .is_err()
        );
    }

    #[test]
    fn canonical_config_wins_over_legacy_no_skills() {
        let config = config("auto-install-lpm-skills = true\nnoSkills = true");

        assert!(LpmSkillsPreference::Config.resolve(&config).unwrap());
    }

    #[test]
    fn legacy_no_skills_remains_a_compatibility_fallback() {
        assert!(
            !LpmSkillsPreference::Config
                .resolve(&config("noSkills = true"))
                .unwrap()
        );
    }

    #[test]
    fn explicit_enable_overrides_disabled_config() {
        assert!(
            LpmSkillsPreference::Enabled
                .resolve(&config("auto-install-lpm-skills = false"))
                .unwrap()
        );
    }

    #[test]
    fn explicit_disable_overrides_enabled_config() {
        assert!(
            !LpmSkillsPreference::Disabled
                .resolve(&config("auto-install-lpm-skills = true"))
                .unwrap()
        );
    }

    #[test]
    fn other_package_skills_default_on_and_follow_the_skills_table() {
        assert!(other_package_skills_enabled(&GlobalConfig::empty()).unwrap());
        assert!(
            !other_package_skills_enabled(&config("[skills]\nother-packages = false")).unwrap()
        );
        assert!(
            other_package_skills_enabled(&config("[skills]\nother-packages = \"on\"")).unwrap()
        );
        assert!(other_package_skills_enabled(&config("[skills]\nother-packages = 3")).is_err());
        assert!(other_package_skills_enabled(&config("skills = true")).is_err());
    }

    #[test]
    fn malformed_canonical_config_fails_instead_of_enabling_skills() {
        let error = LpmSkillsPreference::Config
            .resolve(&config("auto-install-lpm-skills = 1"))
            .unwrap_err();

        assert!(error.to_string().contains(AUTO_INSTALL_LPM_SKILLS_KEY));
    }
}
