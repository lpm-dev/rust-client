use super::prelude::*;

pub(in crate::commands::config) async fn run_scripts_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(v) = set {
        if !SCRIPT_POLICY_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid script-policy '{v}'; must be one of: {}",
                SCRIPT_POLICY_VALUES.join(" | ")
            )));
        }
        persist_script_policy(config_path, v, json_output).await?;
        announce_set(SCRIPT_POLICY_KEY, v, json_output);
        if v == "triage" {
            print_triage_policy_followup(json_output);
        }
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config scripts requires a TTY; use `--set deny|triage|allow` instead".to_string(),
        ));
    }

    let current =
        read_string_value(config_path, SCRIPT_POLICY_KEY)?.unwrap_or_else(|| "deny".to_string());
    println!();
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  current: {}",
        install_ui::cyan(&current)
    ));
    let new_value: &str = cliclack::select("How should lpm treat package lifecycle scripts?")
        .item(
            "deny",
            "deny — never auto-run lifecycle scripts",
            "default; most restrictive",
        )
        .item(
            "triage",
            "triage — Layers 1-3 always; advisor only if configured",
            "recommended",
        )
        .item(
            "allow",
            "allow — run every script",
            "npm-classic; least restrictive",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;
    persist_script_policy(config_path, new_value, json_output).await?;
    announce_set(SCRIPT_POLICY_KEY, new_value, json_output);

    if new_value == "triage" {
        print_triage_policy_followup(json_output);
    }
    Ok(())
}

pub(in crate::commands::config) async fn persist_script_policy(
    config_path: &std::path::Path,
    value: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let requested = crate::script_policy_config::ScriptPolicy::parse(value)
        .map_err(|e| LpmError::Registry(e.to_string()))?;
    update_config(config_path, |config| {
        let global = global_config_view_from_value(config);
        crate::security_floor::reject_looser_script_policy_write(&global, requested)?;
        crate::security_approval::authorize_persistent_script_policy(
            requested,
            json_output,
            &format!("lpm config scripts --set {value}"),
        )?;
        let table = config.as_table_mut().ok_or_else(|| {
            LpmError::Registry("config.toml must be a TOML table at the top level".into())
        })?;
        table.insert(
            SCRIPT_POLICY_KEY.to_string(),
            toml::Value::String(value.to_string()),
        );
        Ok(((), true))
    })
    .await
}

pub(in crate::commands::config) fn print_triage_policy_followup(json_output: bool) {
    if json_output {
        return;
    }
    println!();
    println!(
        "  {}: triage runs Layers 1-3 on every install. Run `lpm config \
         triage` to pick an optional advisor (claude-cli / codex / \
         ollama) that can promote some amber packages to auto-run \
         this install. The advisor is consulted only for amber; \
         green and hard-blocked paths are unchanged.",
        "tip".cyan()
    );
}
