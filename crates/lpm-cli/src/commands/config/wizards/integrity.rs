use super::prelude::*;

pub(in crate::commands::config) const INTEGRITY_KEY: &str = "integrity";
pub(in crate::commands::config) const INTEGRITY_VALUES: [&str; 2] = ["source", "tree"];
pub(in crate::commands::config) const INTEGRITY_GUIDED_MENU_LABEL: &str = "Store integrity";
pub(in crate::commands::config) const INTEGRITY_WIZARD_PROMPT: &str =
    "How should LPM verify reused package store objects?";
pub(in crate::commands::config) const INTEGRITY_SOURCE_HINT: &str =
    "default; verify source identity without rehashing expanded files";
pub(in crate::commands::config) const INTEGRITY_TREE_HINT: &str =
    "stricter; rehash expanded files to detect local store tampering/corruption";

pub(in crate::commands::config) fn parse_integrity_policy_selection(
    input: &str,
) -> Result<lpm_store::v2::ObjectIntegrityPolicy, LpmError> {
    lpm_store::v2::ObjectIntegrityPolicy::parse(input).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid integrity mode '{input}'; must be one of: {}",
            INTEGRITY_VALUES.join(" | ")
        ))
    })
}

pub(in crate::commands::config) async fn run_integrity_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let policy = if let Some(value) = set {
        parse_integrity_policy_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config integrity requires a TTY; use `--set source|tree` instead".to_string(),
            ));
        }

        let current = read_integrity_policy(config_path)?
            .unwrap_or(lpm_store::v2::ObjectIntegrityPolicy::Source);
        println!();
        println!("  current: {}", current.as_str().cyan());
        let new_value: &str = cliclack::select(INTEGRITY_WIZARD_PROMPT)
            .item("source", "source", INTEGRITY_SOURCE_HINT)
            .item("tree", "tree", INTEGRITY_TREE_HINT)
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;
        parse_integrity_policy_selection(new_value)?
    };

    persist_integrity_policy(config_path, policy).await?;
    announce_integrity_policy_set(policy, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_integrity_policy(
    config_path: &std::path::Path,
) -> Result<Option<lpm_store::v2::ObjectIntegrityPolicy>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    GlobalConfig { table }.get_integrity_policy()
}

pub(crate) fn resolve_object_integrity_policy(
    global: &GlobalConfig,
) -> Result<lpm_store::v2::ObjectIntegrityPolicy, LpmError> {
    if let Ok(value) = std::env::var(lpm_store::v2::ENV_V2_OBJECT_INTEGRITY) {
        return Ok(lpm_store::v2::ObjectIntegrityPolicy::from_env_value(Some(
            value.as_str(),
        )));
    }
    Ok(global
        .get_integrity_policy()?
        .unwrap_or(lpm_store::v2::ObjectIntegrityPolicy::Source))
}

pub(in crate::commands::config) async fn persist_integrity_policy(
    config_path: &std::path::Path,
    policy: lpm_store::v2::ObjectIntegrityPolicy,
) -> Result<(), LpmError> {
    persist_string(config_path, INTEGRITY_KEY, policy.as_str()).await
}

pub(in crate::commands::config) fn format_current_integrity_policy(
    current: Option<lpm_store::v2::ObjectIntegrityPolicy>,
) -> String {
    current
        .unwrap_or(lpm_store::v2::ObjectIntegrityPolicy::Source)
        .as_str()
        .to_string()
}

pub(in crate::commands::config) fn announce_integrity_policy_set(
    policy: lpm_store::v2::ObjectIntegrityPolicy,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                INTEGRITY_KEY: policy.as_str(),
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set {} = {}",
            INTEGRITY_KEY,
            install_ui::bold(policy.as_str()),
        ));
    }
}
