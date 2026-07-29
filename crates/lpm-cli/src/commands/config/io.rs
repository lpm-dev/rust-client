use crate::sandbox_config::ResolvedSandboxMode;
use crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY;
use lpm_common::LpmError;

use super::global_config::global_config_view_from_value;
use super::wizards::{
    RELEASE_AGE_KEY, RELEASE_AGE_POLICY_KEY, SCRIPT_POLICY_KEY, TYPOSQUAT_GUARD_KEY,
    TyposquatGuardSelection, parse_config_bool, reject_looser_typosquat_guard_write,
};

pub(super) fn read_config(path: &std::path::Path) -> Result<toml::Value, LpmError> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                return Ok(toml::Value::Table(toml::map::Map::new()));
            }
            Err(error) => return Err(LpmError::Registry(error.to_string())),
        };
    toml::from_str(&content).map_err(|e| LpmError::Registry(format!("config parse error: {e}")))
}

pub(super) fn write_config(path: &std::path::Path, config: &toml::Value) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)
        .map_err(|e| LpmError::Registry(format!("config serialize error: {e}")))?;
    std::fs::write(path, content)?;
    Ok(())
}

pub(super) fn config_value_to_json(value: &toml::Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

pub(super) fn config_value_for_display(value: &toml::Value) -> String {
    match value {
        toml::Value::Boolean(value) => value.to_string(),
        toml::Value::Integer(value) => value.to_string(),
        toml::Value::Float(value) => value.to_string(),
        toml::Value::Datetime(value) => value.to_string(),
        _ => value.to_string(),
    }
}

pub(super) fn guard_generic_set_against_force_floor(
    config: &toml::Value,
    key: &str,
    value: &str,
) -> Result<(), LpmError> {
    let global = global_config_view_from_value(config);
    match key {
        "force-security-floor"
            if crate::security_floor::force_security_floor_enabled(&global)
                && !matches!(value, "true" | "1" | "yes") =>
        {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                value,
                "true",
            ));
        }
        SCRIPT_POLICY_KEY => {
            if let Ok(requested) = crate::script_policy_config::ScriptPolicy::parse(value) {
                crate::security_floor::reject_looser_script_policy_write(&global, requested)?;
            }
        }
        RELEASE_AGE_KEY => {
            if let Some(requested_secs) = crate::release_age_config::parse_strict_u64_string(value)
            {
                crate::security_floor::reject_looser_release_age_write(&global, requested_secs)?;
            }
        }
        RELEASE_AGE_POLICY_KEY => {
            if let Ok(requested) = crate::release_age_config::ReleaseAgePolicy::parse(key, value) {
                crate::security_floor::reject_looser_release_age_policy_write(&global, requested)?;
            }
        }
        TYPOSQUAT_GUARD_KEY => {
            if let Some(requested) = TyposquatGuardSelection::parse(value) {
                reject_looser_typosquat_guard_write(&global, requested)?;
            }
        }
        INSTALL_TIME_SOURCE_ANALYSIS_KEY
            if crate::security_floor::force_security_floor_enabled(&global)
                && matches!(parse_config_bool(value), Ok(false)) =>
        {
            return Err(crate::security_floor::security_floor_write_error(
                INSTALL_TIME_SOURCE_ANALYSIS_KEY,
                value,
                "true",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn guard_generic_delete_against_force_floor(
    config: &toml::Value,
    key: &str,
) -> Result<(), LpmError> {
    let global = global_config_view_from_value(config);
    match key {
        RELEASE_AGE_KEY => crate::security_floor::reject_looser_release_age_write(
            &global,
            crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
        )?,
        RELEASE_AGE_POLICY_KEY => crate::security_floor::reject_looser_release_age_policy_write(
            &global,
            crate::release_age_config::ReleaseAgePolicy::Direct,
        )?,
        "sandbox" => crate::security_floor::reject_looser_sandbox_mode_write(
            &global,
            ResolvedSandboxMode::Default,
        )?,
        TYPOSQUAT_GUARD_KEY => {
            reject_looser_typosquat_guard_write(&global, TyposquatGuardSelection::Default)?
        }
        "force-security-floor" if crate::security_floor::force_security_floor_enabled(&global) => {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                "unset",
                "true",
            ));
        }
        _ => {}
    }
    Ok(())
}
