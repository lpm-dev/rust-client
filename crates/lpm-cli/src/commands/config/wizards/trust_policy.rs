use super::prelude::*;

pub(crate) const TRUST_POLICY_KEY: &str = "trust-policy";
pub(in crate::commands::config) const TRUST_POLICY_VALUES: &[&str] = &["off", "no-downgrade"];

pub(in crate::commands::config) async fn run_trust_policy_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let value = if let Some(value) = set {
        validate_trust_policy_value(value)?;
        value.to_string()
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config trust-policy requires a TTY; use `--set off|no-downgrade` instead"
                    .to_string(),
            ));
        }

        let current = read_string_value(config_path, TRUST_POLICY_KEY)?
            .filter(|v| TRUST_POLICY_VALUES.contains(&v.as_str()))
            .unwrap_or_else(|| "off".to_string());
        println!();
        println!("  current: {}", current.cyan());
        cliclack::select("How should LPM handle npm trust downgrades?")
            .item("off", "off", "default")
            .item(
                "no-downgrade",
                "no-downgrade",
                "block versions that drop publisher/provenance trust",
            )
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?
            .to_string()
    };

    persist_string(config_path, TRUST_POLICY_KEY, &value)?;
    announce_trust_policy_set(&value, json_output);
    Ok(())
}

pub(in crate::commands::config) fn validate_trust_policy_value(
    value: &str,
) -> Result<(), LpmError> {
    if TRUST_POLICY_VALUES.contains(&value) {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "invalid trust-policy '{value}'; must be one of: {}",
            TRUST_POLICY_VALUES.join(" | ")
        )))
    }
}

pub(in crate::commands::config) fn announce_trust_policy_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                TRUST_POLICY_KEY: value,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!("Set trust-policy = {}", value.bold()));
    }
}
