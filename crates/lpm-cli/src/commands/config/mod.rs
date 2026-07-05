mod global_config;
mod io;
mod wizards;

#[cfg(test)]
mod tests;

use crate::install_ui;
use crate::npm_firewall_config::{FIREWALL_CONFIG_SECTION, NpmFirewallMode};
use crate::prompt::prompt_err;
use crate::sandbox_config::ResolvedSandboxMode;
use lpm_common::color::Painted;
use lpm_common::{LpmError, LpmRoot};
use std::io::IsTerminal;

pub use global_config::GlobalConfig;
pub(crate) use wizards::{
    TRUST_POLICY_KEY, TYPOSQUAT_GUARD_KEY, TyposquatGuardSelection, resolve_object_integrity_policy,
};

use global_config::global_config_view_from_value;
use io::{
    config_value_for_display, config_value_to_json, guard_generic_delete_against_force_floor,
    guard_generic_set_against_force_floor, read_config, write_config,
};
use wizards::{
    FIREWALL_GUIDED_MENU_LABEL, INTEGRITY_GUIDED_MENU_LABEL, INTEGRITY_KEY, RELEASE_AGE_KEY,
    RELEASE_AGE_POLICY_KEY, SANDBOX_MODE_VALUES, SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES,
    SIGNATURES_KEY, SIGSTORE_VERIFY_VALUES, TRIAGE_ADVISOR_KEY, TRIAGE_ADVISOR_VALUES,
    TRUST_POLICY_VALUES, format_bool_enabled, format_current_firewall_mode,
    format_current_integrity_policy, format_current_release_age, format_current_typosquat_guard,
    parse_config_bool, parse_firewall_mode_selection, parse_integrity_policy_selection,
    parse_typosquat_guard_selection, persist_firewall_mode_in_config_value, read_bool_value,
    read_firewall_mode, read_integrity_policy, read_release_age_override,
    read_release_age_policy_override, read_sandbox_mode, read_sigstore_verify, read_string_value,
    read_typosquat_guard_override, reject_looser_typosquat_guard_write, run_firewall_wizard,
    run_integrity_wizard, run_release_age_policy_wizard, run_release_age_wizard,
    run_sandbox_wizard, run_scripts_wizard, run_signatures_wizard, run_sigstore_wizard,
    run_triage_wizard, run_trust_policy_wizard, run_typosquat_wizard, validate_trust_policy_value,
};

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
///
/// Bare `lpm config` opens a guided editor that routes into the focused
/// wizards below. The direct forms stay available for scripts and deep links.
///
/// Beyond `get`/`set`/`delete`/`list`, eleven focused wizards live here:
/// - `lpm config scripts` owns `script-policy = deny | triage | allow`.
/// - `lpm config triage` owns `triage-advisor = none | claude-cli | codex | ollama`.
/// - `lpm config sandbox` owns `[sandbox] mode = default | strict | none`.
/// - `lpm config sigstore` owns `[sigstore] verify = deny | warn | off`
///   (operator persistent toggle for Sigstore provenance verification).
/// - `lpm config signatures` owns `signatures = true | false`
///   (operator persistent toggle for npm registry package signatures).
/// - `lpm config trust-policy` owns `trust-policy = off | no-downgrade`
///   (operator persistent toggle for npm publisher/provenance downgrade checks).
/// - `lpm config typosquat` owns `typosquat-guard = default | on | off`
///   (operator persistent toggle for suspicious package-name analysis).
/// - `lpm config firewall` owns `[firewall] mode = off | report | enforce`
///   (operator persistent toggle for npm package firewall verdict checks).
/// - `lpm config integrity` owns `integrity = source | tree`
///   (operator preference for v2 expanded-store object validation).
/// - `lpm config release-age` owns `minimum-release-age-secs = <seconds>`
///   via human-friendly duration inputs.
/// - `lpm config release-age-policy` owns `release-age-policy = direct | strict`.
///
/// All eleven default to interactive in a TTY; `--set <value>` is the
/// non-interactive setter required for CI / scripted setup.
pub async fn run(
    action: Option<&str>,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config_path = LpmRoot::from_env()?.root().join("config.toml");

    let Some(action) = action else {
        return run_guided_config_menu(&config_path, key, value, set, json_output).await;
    };

    if action == "scripts" {
        return run_scripts_wizard(&config_path, set, json_output).await;
    }
    if action == "triage" {
        return run_triage_wizard(&config_path, set, json_output).await;
    }
    if action == "sandbox" {
        return run_sandbox_wizard(&config_path, set, json_output).await;
    }
    if action == "sigstore" {
        return run_sigstore_wizard(&config_path, set, json_output).await;
    }
    if action == "signatures" {
        return run_signatures_wizard(&config_path, set, json_output).await;
    }
    if action == "trust-policy" {
        return run_trust_policy_wizard(&config_path, set, json_output).await;
    }
    if action == "typosquat" {
        return run_typosquat_wizard(&config_path, set, json_output).await;
    }
    if action == "firewall" {
        return run_firewall_wizard(&config_path, set, json_output).await;
    }
    if action == "integrity" {
        return run_integrity_wizard(&config_path, set, json_output).await;
    }
    if action == "release-age" {
        return run_release_age_wizard(&config_path, set, json_output).await;
    }
    if action == "release-age-policy" {
        return run_release_age_policy_wizard(&config_path, set, json_output).await;
    }

    match action {
        "get" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let config = read_config(&config_path)?;
            if let Some(val) = config.get(key) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "success": true,
                            key: config_value_to_json(val),
                        }))
                        .unwrap()
                    );
                } else if let Some(raw) = val.as_str() {
                    println!("{raw}");
                } else {
                    println!("{}", config_value_for_display(val));
                }
            } else if !json_output {
                install_ui::warn(&format!("{key} is not set"));
            }
        }
        "set" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let value = value.ok_or_else(|| LpmError::Registry("missing value".into()))?;
            let mut config = read_config(&config_path)?;
            guard_generic_set_against_force_floor(&config, key, value)?;
            match key {
                SCRIPT_POLICY_KEY => {
                    let requested = crate::script_policy_config::ScriptPolicy::parse(value)
                        .map_err(|e| LpmError::Registry(e.to_string()))?;
                    crate::security_approval::authorize_persistent_script_policy(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )?;
                }
                RELEASE_AGE_KEY => {
                    let requested_secs = crate::release_age_config::parse_strict_u64_string(value)
                        .ok_or_else(|| {
                            LpmError::Registry(format!(
                                "`{RELEASE_AGE_KEY}` must be a non-negative integer second count"
                            ))
                        })?;
                    crate::security_approval::authorize_persistent_release_age(
                        requested_secs,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )?;
                }
                RELEASE_AGE_POLICY_KEY => {
                    let requested = crate::release_age_config::ReleaseAgePolicy::parse(key, value)?;
                    crate::security_floor::reject_looser_release_age_policy_write(
                        &global_config_view_from_value(&config),
                        requested,
                    )?;
                    crate::security_approval::authorize_persistent_release_age_policy(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {}", requested.as_str()),
                    )?;
                }
                SIGNATURES_KEY => {
                    parse_config_bool(value).map_err(|message| {
                        LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                    })?;
                }
                TRUST_POLICY_KEY => validate_trust_policy_value(value)?,
                INTEGRITY_KEY => {
                    parse_integrity_policy_selection(value)?;
                }
                TYPOSQUAT_GUARD_KEY => {
                    let requested = parse_typosquat_guard_selection(value)?;
                    let global = global_config_view_from_value(&config);
                    reject_looser_typosquat_guard_write(&global, requested)?;
                    crate::security_approval::authorize_persistent_typosquat_guard(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {}", requested.as_str()),
                    )?;
                }
                FIREWALL_CONFIG_SECTION => {
                    let requested = parse_firewall_mode_selection(value)?;
                    crate::security_floor::reject_looser_firewall_mode_write(
                        &global_config_view_from_value(&config),
                        requested,
                    )?;
                    crate::security_approval::authorize_persistent_npm_firewall_mode(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {}", requested.as_str()),
                    )?;
                }
                _ => {}
            }
            if key == FIREWALL_CONFIG_SECTION {
                persist_firewall_mode_in_config_value(
                    &mut config,
                    parse_firewall_mode_selection(value)?,
                )?;
            } else if let Some(table) = config.as_table_mut() {
                if key == TYPOSQUAT_GUARD_KEY
                    && parse_typosquat_guard_selection(value)? == TyposquatGuardSelection::Default
                {
                    table.remove(key);
                } else {
                    let value = if key == SIGNATURES_KEY {
                        toml::Value::Boolean(parse_config_bool(value).map_err(|message| {
                            LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                        })?)
                    } else if key == RELEASE_AGE_POLICY_KEY {
                        toml::Value::String(
                            crate::release_age_config::ReleaseAgePolicy::parse(key, value)?
                                .as_str()
                                .to_string(),
                        )
                    } else if key == INTEGRITY_KEY {
                        toml::Value::String(
                            parse_integrity_policy_selection(value)?
                                .as_str()
                                .to_string(),
                        )
                    } else if key == TYPOSQUAT_GUARD_KEY {
                        toml::Value::String(
                            parse_typosquat_guard_selection(value)?.as_str().to_string(),
                        )
                    } else {
                        toml::Value::String(value.to_string())
                    };
                    table.insert(key.to_string(), value);
                }
            }
            write_config(&config_path, &config)?;
            if json_output {
                let value = if key == SIGNATURES_KEY {
                    serde_json::Value::Bool(parse_config_bool(value).map_err(|message| {
                        LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}"))
                    })?)
                } else if key == RELEASE_AGE_POLICY_KEY {
                    serde_json::Value::String(
                        crate::release_age_config::ReleaseAgePolicy::parse(key, value)?
                            .as_str()
                            .to_string(),
                    )
                } else if key == INTEGRITY_KEY {
                    serde_json::Value::String(
                        parse_integrity_policy_selection(value)?
                            .as_str()
                            .to_string(),
                    )
                } else if key == TYPOSQUAT_GUARD_KEY {
                    serde_json::Value::String(
                        parse_typosquat_guard_selection(value)?.as_str().to_string(),
                    )
                } else if key == FIREWALL_CONFIG_SECTION {
                    serde_json::json!({
                        "mode": parse_firewall_mode_selection(value)?.as_str(),
                    })
                } else {
                    serde_json::Value::String(value.to_string())
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "action": "set",
                        "key": key,
                        "value": value,
                    })
                );
            } else {
                install_ui::done(&format!(
                    "Done · {key} = {}",
                    install_ui::section(&format!("\"{value}\""))
                ));
            }
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let mut config = read_config(&config_path)?;
            guard_generic_delete_against_force_floor(&config, key)?;
            match key {
                SCRIPT_POLICY_KEY => crate::security_approval::authorize_persistent_script_policy(
                    crate::script_policy_config::ScriptPolicy::Deny,
                    json_output,
                    &format!("lpm config delete {key}"),
                )?,
                RELEASE_AGE_KEY => crate::security_approval::authorize_persistent_release_age(
                    crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
                    json_output,
                    &format!("lpm config delete {key}"),
                )?,
                RELEASE_AGE_POLICY_KEY => {
                    crate::security_floor::reject_looser_release_age_policy_write(
                        &global_config_view_from_value(&config),
                        crate::release_age_config::ReleaseAgePolicy::Direct,
                    )?;
                    crate::security_approval::authorize_persistent_release_age_policy(
                        crate::release_age_config::ReleaseAgePolicy::Direct,
                        json_output,
                        &format!("lpm config delete {key}"),
                    )?;
                }
                "sandbox" => crate::security_approval::authorize_persistent_sandbox_mode(
                    ResolvedSandboxMode::Default,
                    json_output,
                    "lpm config delete sandbox",
                )?,
                TYPOSQUAT_GUARD_KEY => {
                    crate::security_approval::authorize_persistent_typosquat_guard(
                        TyposquatGuardSelection::Default,
                        json_output,
                        &format!("lpm config delete {key}"),
                    )?;
                }
                FIREWALL_CONFIG_SECTION => {
                    crate::security_floor::reject_looser_firewall_mode_write(
                        &global_config_view_from_value(&config),
                        NpmFirewallMode::Off,
                    )?;
                    crate::security_approval::authorize_persistent_npm_firewall_mode(
                        NpmFirewallMode::Off,
                        json_output,
                        &format!("lpm config delete {key}"),
                    )?;
                }
                _ => {}
            }
            let existed = config.as_table_mut().and_then(|t| t.remove(key)).is_some();
            write_config(&config_path, &config)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "action": "delete",
                        "key": key,
                        "existed": existed,
                    })
                );
            } else {
                install_ui::done(&format!("Deleted {}", key.bold()));
            }
        }
        "list" | "ls" => {
            let config = read_config(&config_path)?;
            if json_output {
                let mut json = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("success".to_string(), serde_json::Value::Bool(true));
                }
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                if let Some(table) = config.as_table() {
                    if table.is_empty() {
                        install_ui::warn("No configuration set");
                    } else {
                        for (k, v) in table {
                            println!("  {k:<24} {v}");
                        }
                    }
                }
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown config action: {action}. \
                 Use: get, set, delete (alias: unset), list (alias: ls), \
                 scripts, triage, sandbox, sigstore, signatures, trust-policy, typosquat, firewall, integrity, release-age, release-age-policy"
            )));
        }
    }

    Ok(())
}

async fn run_guided_config_menu(
    config_path: &std::path::Path,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if key.is_some() || value.is_some() || set.is_some() {
        return Err(LpmError::Registry(
            "lpm config needs a setting before --set; use `lpm config scripts --set triage` or run `lpm config` interactively".into(),
        ));
    }
    if json_output {
        return Err(LpmError::Registry(
            "lpm config requires an interactive terminal; use `lpm config list --json` for machine-readable config".into(),
        ));
    }
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config requires an interactive terminal; use `lpm config list` or `lpm config <setting> --set <value>` instead".into(),
        ));
    }

    loop {
        let summary = read_guided_config_summary(config_path)?;
        println!();
        let choice: &str = cliclack::select("What do you want to configure?")
            .item(
                "scripts",
                "Lifecycle scripts",
                format!("current: {}", summary.script_policy),
            )
            .item(
                "triage",
                "Triage advisor",
                format!("current: {}", summary.triage_advisor),
            )
            .item(
                "sandbox",
                "Sandbox mode",
                format!("current: {}", summary.sandbox_mode),
            )
            .item(
                "sigstore",
                "Sigstore provenance",
                format!("current: {}", summary.sigstore_verify),
            )
            .item(
                "signatures",
                "Registry signatures",
                format!("current: {}", summary.signatures),
            )
            .item(
                "trust-policy",
                "Trust downgrade policy",
                format!("current: {}", summary.trust_policy),
            )
            .item(
                "typosquat",
                "Typosquat guard",
                format!("current: {}", summary.typosquat_guard),
            )
            .item(
                "firewall",
                FIREWALL_GUIDED_MENU_LABEL,
                format!("current: {}", summary.firewall_mode),
            )
            .item(
                "integrity",
                INTEGRITY_GUIDED_MENU_LABEL,
                format!("current: {}", summary.integrity_mode),
            )
            .item(
                "release-age",
                "Minimum release age",
                format!("current: {}", summary.release_age),
            )
            .item(
                "release-age-policy",
                "Release-age scope",
                format!("current: {}", summary.release_age_policy),
            )
            .item("done", "Done", "exit")
            .interact()
            .map_err(prompt_err)?;

        match choice {
            "scripts" => {
                run_scripts_wizard(config_path, None, false).await?;
                maybe_offer_triage_advisor(config_path).await?;
            }
            "triage" => run_triage_wizard(config_path, None, false).await?,
            "sandbox" => run_sandbox_wizard(config_path, None, false).await?,
            "sigstore" => run_sigstore_wizard(config_path, None, false).await?,
            "signatures" => run_signatures_wizard(config_path, None, false).await?,
            "trust-policy" => run_trust_policy_wizard(config_path, None, false).await?,
            "typosquat" => run_typosquat_wizard(config_path, None, false).await?,
            "firewall" => run_firewall_wizard(config_path, None, false).await?,
            "integrity" => run_integrity_wizard(config_path, None, false).await?,
            "release-age" => run_release_age_wizard(config_path, None, false).await?,
            "release-age-policy" => run_release_age_policy_wizard(config_path, None, false).await?,
            "done" => return Ok(()),
            _ => unreachable!("guided config select returned unexpected setting"),
        }
    }
}

async fn maybe_offer_triage_advisor(config_path: &std::path::Path) -> Result<(), LpmError> {
    if read_string_value(config_path, SCRIPT_POLICY_KEY)?.as_deref() != Some("triage") {
        return Ok(());
    }

    let configure = cliclack::confirm("Configure the triage advisor now?")
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
    if configure {
        run_triage_wizard(config_path, None, false).await?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct GuidedConfigSummary {
    script_policy: String,
    triage_advisor: String,
    sandbox_mode: String,
    sigstore_verify: String,
    signatures: &'static str,
    trust_policy: String,
    typosquat_guard: String,
    firewall_mode: String,
    integrity_mode: String,
    release_age: String,
    release_age_policy: String,
}

fn read_guided_config_summary(
    config_path: &std::path::Path,
) -> Result<GuidedConfigSummary, LpmError> {
    Ok(GuidedConfigSummary {
        script_policy: read_string_value(config_path, SCRIPT_POLICY_KEY)?
            .filter(|value| SCRIPT_POLICY_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "deny".to_string()),
        triage_advisor: read_string_value(config_path, TRIAGE_ADVISOR_KEY)?
            .filter(|value| TRIAGE_ADVISOR_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "none".to_string()),
        sandbox_mode: read_sandbox_mode(config_path)?
            .filter(|value| SANDBOX_MODE_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "default".to_string()),
        sigstore_verify: read_sigstore_verify(config_path)?
            .filter(|value| SIGSTORE_VERIFY_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "deny".to_string()),
        signatures: format_bool_enabled(
            read_bool_value(config_path, SIGNATURES_KEY)?.unwrap_or(false),
        ),
        trust_policy: read_string_value(config_path, TRUST_POLICY_KEY)?
            .filter(|value| TRUST_POLICY_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "off".to_string()),
        typosquat_guard: format_current_typosquat_guard(read_typosquat_guard_override(
            config_path,
        )?),
        firewall_mode: format_current_firewall_mode(read_firewall_mode(config_path)?),
        integrity_mode: format_current_integrity_policy(read_integrity_policy(config_path)?),
        release_age: format_current_release_age(read_release_age_override(config_path)?),
        release_age_policy: read_release_age_policy_override(config_path)?
            .unwrap_or_default()
            .as_str()
            .to_string(),
    })
}
