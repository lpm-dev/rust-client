use super::prelude::*;

pub(in crate::commands::config) const SIGSTORE_VERIFY_VALUES: &[&str] = &["deny", "warn", "off"];

pub(in crate::commands::config) async fn run_sigstore_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(v) = set {
        if !SIGSTORE_VERIFY_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid sigstore verify mode '{v}'; must be one of: {}",
                SIGSTORE_VERIFY_VALUES.join(" | ")
            )));
        }
        let requested = parse_sigstore_enforce_mode(v)?;
        crate::security_floor::reject_looser_sigstore_write(&global, requested)?;
        crate::security_approval::authorize_persistent_sigstore(
            requested,
            json_output,
            &format!("lpm config sigstore --set {v}"),
        )?;
        persist_sigstore_verify(config_path, v)?;
        announce_sigstore_set(v, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config sigstore requires a TTY; use `--set deny|warn|off` instead".to_string(),
        ));
    }

    let current = read_sigstore_verify(config_path)?.unwrap_or_else(|| "deny".to_string());
    println!();
    println!("  current: {}", current.cyan());
    let new_value: &str =
        cliclack::select("How should LPM handle Sigstore provenance verification?")
            .item(
                "deny",
                "deny — verify every attestation, fail-closed on errors",
                "recommended",
            )
            .item("warn", "warn — verify, but only log on failure", "degraded")
            .item(
                "off",
                "off  — skip verification entirely",
                "NOT recommended",
            )
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;

    // Confirm when the user picks `off` in the interactive wizard.
    // The `--set off` form trusts the operator (no TTY check); only
    // the wizard prompts. Matches the sandbox=none confirm shape.
    if new_value == "off" {
        println!();
        println!(
            "  {}: setting sigstore.verify = {} means every Sigstore attestation \
             your registry ships will be IGNORED. Provenance drift detection \
             still runs against unverified identity data, but a malicious or \
             compromised registry can lie about who built a package and the \
             install will accept it. LPM does not recommend disabled verification \
             as a persistent setting.",
            "warning".yellow(),
            "off".yellow().bold(),
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want sigstore.verify = off for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    let requested = parse_sigstore_enforce_mode(new_value)?;
    crate::security_floor::reject_looser_sigstore_write(&global, requested)?;
    crate::security_approval::authorize_persistent_sigstore(
        requested,
        json_output,
        &format!("lpm config sigstore --set {new_value}"),
    )?;
    persist_sigstore_verify(config_path, new_value)?;
    announce_sigstore_set(new_value, json_output);
    Ok(())
}

pub(in crate::commands::config) fn parse_sigstore_enforce_mode(
    raw: &str,
) -> Result<EnforceMode, LpmError> {
    match raw {
        "deny" => Ok(EnforceMode::Deny),
        "warn" => Ok(EnforceMode::Warn),
        "off" => Ok(EnforceMode::Off),
        other => Err(LpmError::Registry(format!(
            "invalid sigstore verify mode '{other}'"
        ))),
    }
}

pub(in crate::commands::config) fn read_sigstore_verify(
    config_path: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg
        .get("sigstore")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("verify"))
        .and_then(|v| v.as_str())
        .map(String::from))
}

pub(in crate::commands::config) fn persist_sigstore_verify(
    config_path: &std::path::Path,
    value: &str,
) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let sigstore_section = top
        .entry("sigstore".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let sigstore_table = sigstore_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `[sigstore]` is not a TOML table — refusing to clobber",
            config_path.display(),
        ))
    })?;
    sigstore_table.insert("verify".to_string(), toml::Value::String(value.to_string()));
    write_config(config_path, &cfg)
}

pub(in crate::commands::config) fn announce_sigstore_set(value: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "sigstore": { "verify": value },
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set [sigstore] verify = {}",
            install_ui::bold(value),
        ));
    }
}
