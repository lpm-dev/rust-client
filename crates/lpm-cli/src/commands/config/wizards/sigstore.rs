use super::prelude::*;

pub(in crate::commands::config) const SIGSTORE_VERIFY_VALUES: &[&str] = &["deny", "warn", "off"];
pub(in crate::commands::config) const SIGSTORE_SCOPE_VALUES: &[&str] = &["approved", "all"];
pub(in crate::commands::config) const SIGSTORE_AVAILABILITY_VALUES: &[&str] =
    &["best-effort", "strict"];

#[derive(Clone, Copy)]
pub(in crate::commands::config) enum SigstoreSetting {
    Verify,
    Scope,
    Availability,
}

impl SigstoreSetting {
    pub(in crate::commands::config) fn key(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Scope => "scope",
            Self::Availability => "availability",
        }
    }

    fn values(self) -> &'static [&'static str] {
        match self {
            Self::Verify => SIGSTORE_VERIFY_VALUES,
            Self::Scope => SIGSTORE_SCOPE_VALUES,
            Self::Availability => SIGSTORE_AVAILABILITY_VALUES,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::commands::config) struct SigstoreAssignment<'a> {
    pub(in crate::commands::config) setting: SigstoreSetting,
    pub(in crate::commands::config) value: &'a str,
}

pub(in crate::commands::config) async fn run_sigstore_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let existing_cfg = read_config(config_path)?;
    let global = global_config_view_from_value(&existing_cfg);
    if let Some(raw) = set {
        let assignment = parse_sigstore_assignment(raw)?;
        apply_sigstore_assignment(
            config_path,
            &global,
            assignment,
            json_output,
            &format!("lpm config sigstore --set {raw}"),
        )?;
        announce_sigstore_set(assignment.setting.key(), assignment.value, json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config sigstore requires a TTY; use `--set deny|warn|off`, \
             `--set scope=approved|all`, or \
             `--set availability=best-effort|strict` instead"
                .to_string(),
        ));
    }

    let current_verify = read_sigstore_verify(config_path)?.unwrap_or_else(|| "deny".to_string());
    let current_scope = read_sigstore_scope(config_path)?.unwrap_or_else(|| "approved".to_string());
    let current_availability =
        read_sigstore_availability(config_path)?.unwrap_or_else(|| "best-effort".to_string());
    println!();
    println!(
        "  current: verify={}, scope={}, availability={}",
        current_verify.cyan(),
        current_scope.cyan(),
        current_availability.cyan(),
    );
    let setting = match cliclack::select("Which Sigstore setting do you want to change?")
        .item("verify", "Verification failures", current_verify.as_str())
        .item("scope", "Packages to verify", current_scope.as_str())
        .item(
            "availability",
            "Missing or unreachable attestations",
            current_availability.as_str(),
        )
        .interact()
        .map_err(prompt_err)?
    {
        "verify" => SigstoreSetting::Verify,
        "scope" => SigstoreSetting::Scope,
        "availability" => SigstoreSetting::Availability,
        _ => unreachable!("sigstore setting selector returned an unknown value"),
    };

    let new_value = select_sigstore_value(
        setting,
        &current_verify,
        &current_scope,
        &current_availability,
    )?;
    if matches!(setting, SigstoreSetting::Verify) && new_value == "off" {
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

    let assignment = SigstoreAssignment {
        setting,
        value: new_value,
    };
    let proposed_value = if matches!(setting, SigstoreSetting::Verify) {
        new_value.to_string()
    } else {
        format!("{}={new_value}", setting.key())
    };
    apply_sigstore_assignment(
        config_path,
        &global,
        assignment,
        json_output,
        &format!("lpm config sigstore --set {proposed_value}"),
    )?;
    announce_sigstore_set(setting.key(), new_value, json_output);
    Ok(())
}

fn select_sigstore_value<'a>(
    setting: SigstoreSetting,
    current_verify: &'a str,
    current_scope: &'a str,
    current_availability: &'a str,
) -> Result<&'a str, LpmError> {
    match setting {
        SigstoreSetting::Verify => {
            cliclack::select("How should LPM handle Sigstore verification failures?")
                .item(
                    "deny",
                    "deny — reject attestations that fail verification",
                    "recommended",
                )
                .item("warn", "warn — log verification failures", "degraded")
                .item("off", "off — skip verification entirely", "NOT recommended")
                .initial_value(current_verify)
                .interact()
                .map_err(prompt_err)
        }
        SigstoreSetting::Scope => cliclack::select("Which packages should LPM verify?")
            .item(
                "approved",
                "approved — packages with an existing rich-trust binding",
                "default",
            )
            .item("all", "all — every registry package", "stricter opt-in")
            .initial_value(current_scope)
            .interact()
            .map_err(prompt_err),
        SigstoreSetting::Availability => {
            cliclack::select("How should unavailable attestations be handled?")
                .item(
                    "best-effort",
                    "best-effort — tolerate missing or unreachable attestations",
                    "default",
                )
                .item(
                    "strict",
                    "strict — require attestation evidence in the selected scope",
                    "stricter opt-in",
                )
                .initial_value(current_availability)
                .interact()
                .map_err(prompt_err)
        }
    }
}

pub(in crate::commands::config) fn parse_sigstore_assignment(
    raw: &str,
) -> Result<SigstoreAssignment<'_>, LpmError> {
    let (setting, value) = match raw.split_once('=') {
        Some(("verify", value)) => (SigstoreSetting::Verify, value),
        Some(("scope", value)) => (SigstoreSetting::Scope, value),
        Some(("availability", value)) => (SigstoreSetting::Availability, value),
        Some((key, _)) => {
            return Err(LpmError::Registry(format!(
                "invalid sigstore setting '{key}'; expected verify, scope, or availability"
            )));
        }
        None => (SigstoreSetting::Verify, raw),
    };
    if !setting.values().contains(&value) {
        return Err(LpmError::Registry(format!(
            "invalid sigstore {} mode '{value}'; must be one of: {}",
            setting.key(),
            setting.values().join(" | ")
        )));
    }
    Ok(SigstoreAssignment { setting, value })
}

pub(in crate::commands::config) fn apply_sigstore_assignment(
    config_path: &std::path::Path,
    global: &GlobalConfig,
    assignment: SigstoreAssignment<'_>,
    json_output: bool,
    proposed_command: &str,
) -> Result<(), LpmError> {
    if matches!(assignment.setting, SigstoreSetting::Verify) {
        let requested = parse_sigstore_enforce_mode(assignment.value)?;
        crate::security_floor::reject_looser_sigstore_write(global, requested)?;
        crate::security_approval::authorize_persistent_sigstore(
            requested,
            json_output,
            proposed_command,
        )?;
    }
    persist_sigstore_value(config_path, assignment.setting.key(), assignment.value)
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

fn read_sigstore_value(
    config_path: &std::path::Path,
    key: &str,
) -> Result<Option<String>, LpmError> {
    let cfg = read_config(config_path)?;
    Ok(cfg
        .get("sigstore")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(key))
        .and_then(toml::Value::as_str)
        .map(String::from))
}

pub(in crate::commands::config) fn read_sigstore_verify(
    config_path: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    read_sigstore_value(config_path, "verify")
}

pub(in crate::commands::config) fn read_sigstore_scope(
    config_path: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    read_sigstore_value(config_path, "scope")
}

pub(in crate::commands::config) fn read_sigstore_availability(
    config_path: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    read_sigstore_value(config_path, "availability")
}

fn persist_sigstore_value(
    config_path: &std::path::Path,
    key: &str,
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
    sigstore_table.insert(key.to_string(), toml::Value::String(value.to_string()));
    write_config(config_path, &cfg)
}

pub(in crate::commands::config) fn announce_sigstore_set(
    key: &str,
    value: &str,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "sigstore": { (key): value },
            }))
            .unwrap()
        );
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set [sigstore] {} = {}",
            key,
            install_ui::bold(value),
        ));
    }
}
