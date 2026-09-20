use lpm_common::LpmError;

pub(super) fn validate_scalar(key: &str, value: &str) -> Result<(), LpmError> {
    let valid = match key {
        "" => false,
        "script-read-allow" | "max-sandbox-write-roots" => {
            return Err(LpmError::Registry(format!(
                "`{key}` requires a TOML array; edit ~/.lpm/config.toml instead"
            )));
        }
        "save-prefix" => crate::save_spec::SavePrefix::parse(value).is_ok(),
        "save-exact" => {
            crate::save_config::coerce_bool(&toml::Value::String(value.to_string())).is_some()
        }
        "engine-strict"
        | "strict-peer-dependencies"
        | "auto-install-peers"
        | "audit-after-install"
        | "force-security-floor"
        | "allowNew"
        | "noSkills" => super::global_config::parse_user_bool(value).is_some(),
        "workspace-concurrency" => {
            crate::workspace_concurrency_config::parse_workspace_concurrency(value).is_ok()
        }
        "linker" => matches!(value, "hoisted" | "isolated"),
        "triage-advisor" => super::TRIAGE_ADVISOR_VALUES.contains(&value),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "invalid value for configuration key `{key}`"
        )))
    }
}
