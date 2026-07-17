use lpm_common::LpmError;

use crate::commands::config::GlobalConfig;

pub(crate) const AUTO_INSTALL_LPM_SKILLS_KEY: &str = "auto-install-lpm-skills";
pub(crate) const LEGACY_NO_SKILLS_KEY: &str = "noSkills";

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

    pub(crate) fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
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
    if let Some(value) = config.get_value(AUTO_INSTALL_LPM_SKILLS_KEY) {
        return parse_bool(value).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{AUTO_INSTALL_LPM_SKILLS_KEY}` in ~/.lpm/config.toml; must be true or false"
            ))
        });
    }

    Ok(!config.get_bool(LEGACY_NO_SKILLS_KEY).unwrap_or(false))
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
    fn malformed_canonical_config_fails_instead_of_enabling_skills() {
        let error = LpmSkillsPreference::Config
            .resolve(&config("auto-install-lpm-skills = 1"))
            .unwrap_err();

        assert!(error.to_string().contains(AUTO_INSTALL_LPM_SKILLS_KEY));
    }
}
