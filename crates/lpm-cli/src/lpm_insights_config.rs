use lpm_common::LpmError;

use crate::commands::config::GlobalConfig;

pub(crate) const FETCH_LPM_SECURITY_INSIGHTS_KEY: &str = "fetch-lpm-security-insights";

pub(crate) fn read_fetch_lpm_security_insights(config: &GlobalConfig) -> Result<bool, LpmError> {
    let Some(_) = config.get_value(FETCH_LPM_SECURITY_INSIGHTS_KEY) else {
        return Ok(true);
    };
    config.get_bool(FETCH_LPM_SECURITY_INSIGHTS_KEY).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{FETCH_LPM_SECURITY_INSIGHTS_KEY}` in ~/.lpm/config.toml; must be true or false"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(contents: &str) -> GlobalConfig {
        let value: toml::Value = toml::from_str(contents).unwrap();
        GlobalConfig::from_table(value.as_table().unwrap().clone())
    }

    #[test]
    fn lpm_security_insights_are_enabled_when_config_is_absent() {
        assert!(read_fetch_lpm_security_insights(&GlobalConfig::empty()).unwrap());
    }

    #[test]
    fn lpm_security_insights_read_explicit_boolean() {
        assert!(
            !read_fetch_lpm_security_insights(&config("fetch-lpm-security-insights = false"))
                .unwrap()
        );
    }

    #[test]
    fn lpm_security_insights_read_legacy_boolean_string() {
        assert!(
            !read_fetch_lpm_security_insights(&config("fetch-lpm-security-insights = \"false\""))
                .unwrap()
        );
    }

    #[test]
    fn lpm_security_insights_reject_non_boolean_config() {
        let error = read_fetch_lpm_security_insights(&config(
            "fetch-lpm-security-insights = \"sometimes\"",
        ))
        .unwrap_err();
        assert!(error.to_string().contains("must be true or false"));
    }
}
