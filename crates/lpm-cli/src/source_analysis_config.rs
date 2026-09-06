use lpm_common::LpmError;

use crate::commands::config::GlobalConfig;

pub(crate) const INSTALL_TIME_SOURCE_ANALYSIS_KEY: &str = "install-time-source-analysis";
pub(crate) const DEFAULT_SECURITY_ANALYSIS_POLICY: lpm_store::SecurityAnalysisPolicy =
    lpm_store::SecurityAnalysisPolicy::Disabled;
pub(crate) const DEFAULT_INSTALL_TIME_SOURCE_ANALYSIS: bool =
    DEFAULT_SECURITY_ANALYSIS_POLICY.is_enabled();

pub(crate) fn read_install_time_source_analysis(config: &GlobalConfig) -> Result<bool, LpmError> {
    let Some(_) = config.get_value(INSTALL_TIME_SOURCE_ANALYSIS_KEY) else {
        return Ok(DEFAULT_INSTALL_TIME_SOURCE_ANALYSIS);
    };
    config.get_bool(INSTALL_TIME_SOURCE_ANALYSIS_KEY).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{INSTALL_TIME_SOURCE_ANALYSIS_KEY}` in ~/.lpm/config.toml; must be true or false"
        ))
    })
}

pub(crate) fn resolve_install_time_source_analysis(
    config: &GlobalConfig,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<bool, LpmError> {
    let enabled = read_install_time_source_analysis(config)?;
    crate::security_approval::ensure_runtime_install_time_source_analysis_authorized(
        project_dir,
        json_output,
        enabled,
    )?;
    Ok(enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(contents: &str) -> GlobalConfig {
        let value: toml::Value = toml::from_str(contents).unwrap();
        GlobalConfig::from_table(value.as_table().unwrap().clone())
    }

    #[test]
    fn source_analysis_is_disabled_when_config_is_absent() {
        assert!(!read_install_time_source_analysis(&GlobalConfig::empty()).unwrap());
    }

    #[test]
    fn source_analysis_reads_explicit_boolean() {
        assert!(
            !read_install_time_source_analysis(&config("install-time-source-analysis = false"))
                .unwrap()
        );
    }

    #[test]
    fn source_analysis_reads_legacy_boolean_string() {
        assert!(
            !read_install_time_source_analysis(&config("install-time-source-analysis = \"false\""))
                .unwrap()
        );
    }

    #[test]
    fn source_analysis_rejects_non_boolean_config() {
        let error = read_install_time_source_analysis(&config(
            "install-time-source-analysis = \"sometimes\"",
        ))
        .unwrap_err();
        assert!(error.to_string().contains("must be true or false"));
    }
}
