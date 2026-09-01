mod effective;
mod global_config;
mod io;
mod wizards;

#[cfg(test)]
mod tests;

use crate::install_ui;
use crate::lpm_insights_config::FETCH_LPM_SECURITY_INSIGHTS_KEY;
use crate::lpm_skills_config::{AUTO_INSTALL_LPM_SKILLS_KEY, LEGACY_NO_SKILLS_KEY};
use crate::npm_firewall_config::{FIREWALL_CONFIG_SECTION, NpmFirewallMode};
use crate::prompt::prompt_err;
use crate::sandbox_config::ResolvedSandboxMode;
use crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY;
use lpm_common::{LpmError, LpmRoot};
use std::io::IsTerminal;

pub use global_config::GlobalConfig;
pub(crate) use wizards::{
    TRUST_POLICY_KEY, TYPOSQUAT_GUARD_KEY, TyposquatGuardSelection, resolve_object_integrity_policy,
};

use effective::EffectiveConfig;
pub(crate) use io::update_config;
use io::{
    config_value_at_path, config_value_for_display, config_value_to_json,
    guard_generic_delete_against_force_floor, guard_generic_set_against_force_floor, read_config,
    redact_config_json_value, remove_config_value_at_path,
};
use wizards::{
    FIREWALL_GUIDED_MENU_LABEL, INTEGRITY_GUIDED_MENU_LABEL, INTEGRITY_KEY,
    RELEASE_AGE_GUIDED_MENU_LABEL, RELEASE_AGE_KEY, RELEASE_AGE_POLICY_KEY, SANDBOX_MODE_VALUES,
    SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES, SIGNATURES_KEY, SIGSTORE_AVAILABILITY_VALUES,
    SIGSTORE_SCOPE_VALUES, SIGSTORE_VERIFY_VALUES, TRIAGE_ADVISOR_KEY, TRIAGE_ADVISOR_VALUES,
    TRUST_POLICY_VALUES, apply_firewall_mode, apply_sandbox_mode, apply_sigstore_assignment,
    format_bool_enabled, format_current_firewall_mode, format_current_integrity_policy,
    format_current_lpm_skills, format_current_release_age, format_current_typosquat_guard,
    parse_config_bool, parse_firewall_mode_selection, parse_integrity_policy_selection,
    parse_sigstore_assignment, parse_typosquat_guard_selection, read_string_value,
    reject_looser_typosquat_guard_write, run_firewall_wizard, run_integrity_wizard,
    run_lpm_dev_wizard, run_lpm_insights_wizard, run_lpm_skills_wizard,
    run_release_age_configuration_wizard, run_release_age_policy_wizard, run_release_age_wizard,
    run_sandbox_wizard, run_scripts_wizard, run_signatures_wizard, run_sigstore_wizard,
    run_source_analysis_wizard, run_triage_wizard, run_trust_policy_wizard, run_typosquat_wizard,
    validate_trust_policy_value,
};

const NESTED_CONFIG_SECTIONS: [&str; 5] = ["sandbox", "sigstore", "firewall", "policy", "tunnel"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericSetTarget {
    Scalar,
    ReleaseAgeExcludeList,
    Sandbox,
    Sigstore,
    Firewall,
    UnsupportedNested,
}

fn generic_set_target(key: &str) -> GenericSetTarget {
    match key {
        crate::commands::release_age_exclude::USER_KEY => GenericSetTarget::ReleaseAgeExcludeList,
        "sandbox" => GenericSetTarget::Sandbox,
        "sigstore" => GenericSetTarget::Sigstore,
        "firewall" => GenericSetTarget::Firewall,
        "policy" | "tunnel" => GenericSetTarget::UnsupportedNested,
        _ if NESTED_CONFIG_SECTIONS.iter().any(|section| {
            key.strip_prefix(section)
                .is_some_and(|suffix| suffix.starts_with('.'))
        }) =>
        {
            GenericSetTarget::UnsupportedNested
        }
        _ => GenericSetTarget::Scalar,
    }
}

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
///
/// Bare `lpm config` opens a guided editor that routes into the focused
/// wizards below. The direct forms stay available for scripts and deep links.
///
/// Beyond `get`/`set`/`delete`/`list`, focused wizards live here:
/// - `lpm config scripts` owns `script-policy = deny | triage | allow`.
/// - `lpm config triage` owns `triage-advisor = none | claude-cli | codex | ollama`.
/// - `lpm config sandbox` owns `[sandbox] mode = default | strict | none`.
/// - `lpm config sigstore` owns verification, package scope, and
///   attestation-availability policy under `[sigstore]`.
/// - `lpm config signatures` owns `signatures = true | false`
///   (operator persistent toggle for npm registry package signatures).
/// - `lpm config trust-policy` owns `trust-policy = off | no-downgrade`
///   (operator persistent toggle for npm publisher/provenance downgrade checks).
/// - `lpm config typosquat` owns `typosquat-guard = default | on | off`
///   (operator persistent toggle for suspicious package-name analysis).
/// - `lpm config firewall` owns `[firewall] mode = off | monitor | enforce`
///   (operator persistent toggle for npm package firewall verdict checks).
/// - `lpm config integrity` owns `integrity = source | tree`
///   (operator preference for v2 expanded-store object validation).
/// - `lpm config release-age` owns `minimum-release-age-secs = <seconds>`
///   via human-friendly duration inputs.
/// - `lpm config release-age-policy` owns `release-age-policy = direct | strict`.
///   Bare `lpm config` groups both settings in one editor.
/// - `lpm config release-age-exclude` owns the user-wide package exclusion list.
/// - `lpm config lpm-skills` owns `auto-install-lpm-skills = true | false`
///   for package-published skills from `@lpm.dev/*` packages.
/// - `lpm config source-analysis` owns
///   `install-time-source-analysis = true | false`.
/// - `lpm config lpm-insights` owns
///   `fetch-lpm-security-insights = true | false`.
/// - `lpm config lpm-dev` groups the two LPM.dev preferences.
///
/// Focused settings default to interactive in a TTY; `--set <value>` is the
/// non-interactive setter required for CI / scripted setup.
pub async fn run(
    action: Option<&str>,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    validate_action_arguments(action, key, value, set)?;
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
    if action == "release-age-exclude" {
        let operation =
            crate::commands::release_age_exclude::parse_config_operation(key, value, set)?;
        return crate::commands::release_age_exclude::run_user(
            &config_path,
            operation,
            json_output,
        )
        .await;
    }
    if action == "lpm-skills" {
        return run_lpm_skills_wizard(&config_path, set, json_output).await;
    }
    if action == "lpm-dev" {
        return run_lpm_dev_wizard(&config_path, set, json_output).await;
    }
    if action == "lpm-insights" {
        return run_lpm_insights_wizard(&config_path, set, json_output).await;
    }
    if action == "source-analysis" {
        return run_source_analysis_wizard(&config_path, set, json_output).await;
    }

    match action {
        "get" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let config = read_config(&config_path)?;
            let value = config
                .as_table()
                .and_then(|table| config_value_at_path(table, key));
            if json_output {
                let envelope = serde_json::json!({
                    "success": true,
                    "action": "get",
                    "key": key,
                    "value": value.map_or(serde_json::Value::Null, config_value_to_json),
                    "found": value.is_some(),
                });
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else if let Some(value) = value {
                if let Some(raw) = value.as_str() {
                    println!("{}", lpm_common::sanitize_terminal_inline(raw));
                } else {
                    println!(
                        "{}",
                        lpm_common::sanitize_terminal_inline(&config_value_for_display(value))
                    );
                }
            } else {
                install_ui::warn_untrusted(&format!("{key} is not set"));
            }
        }
        "set" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let value = value.ok_or_else(|| LpmError::Registry("missing value".into()))?;
            match generic_set_target(key) {
                GenericSetTarget::ReleaseAgeExcludeList => {
                    return Err(LpmError::Registry(format!(
                        "`lpm config set {key} {value}` cannot write an array setting. Use `lpm config release-age-exclude add {value}` instead"
                    )));
                }
                GenericSetTarget::Sandbox => {
                    apply_sandbox_mode(
                        &config_path,
                        value,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )
                    .await?;
                    announce_generic_set(
                        key,
                        value,
                        serde_json::json!({ "mode": value }),
                        json_output,
                    );
                    return Ok(());
                }
                GenericSetTarget::Sigstore => {
                    let assignment = parse_sigstore_assignment(value)?;
                    apply_sigstore_assignment(
                        &config_path,
                        assignment,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )
                    .await?;
                    announce_generic_set(
                        key,
                        value,
                        serde_json::json!({
                            (assignment.setting.key()): assignment.value,
                        }),
                        json_output,
                    );
                    return Ok(());
                }
                GenericSetTarget::Firewall => {
                    let mode = parse_firewall_mode_selection(value)?;
                    apply_firewall_mode(
                        &config_path,
                        mode,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )
                    .await?;
                    announce_generic_set(
                        key,
                        value,
                        serde_json::json!({ "mode": mode.as_str() }),
                        json_output,
                    );
                    return Ok(());
                }
                GenericSetTarget::UnsupportedNested => {
                    return Err(LpmError::Registry(format!(
                        "`lpm config set` cannot write nested section `{key}` from one value. Edit `~/.lpm/config.toml` instead."
                    )));
                }
                GenericSetTarget::Scalar => {}
            }
            let json_value = update_config(&config_path, |config| {
                guard_generic_set_against_force_floor(config, key, value)?;
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
                        let requested_secs = crate::release_age_config::parse_strict_u64_string(
                            value,
                        )
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
                        let requested =
                            crate::release_age_config::ReleaseAgePolicy::parse(key, value)?;
                        crate::security_floor::reject_looser_release_age_policy_write(
                            config, requested,
                        )?;
                        crate::security_approval::authorize_persistent_release_age_policy(
                            requested,
                            json_output,
                            &format!("lpm config set {key} {}", requested.as_str()),
                        )?;
                    }
                    SIGNATURES_KEY
                    | AUTO_INSTALL_LPM_SKILLS_KEY
                    | FETCH_LPM_SECURITY_INSIGHTS_KEY => {
                        parse_config_bool(value)
                            .map_err(|message| LpmError::Registry(format!("`{key}` {message}")))?;
                    }
                    INSTALL_TIME_SOURCE_ANALYSIS_KEY => {
                        let requested = parse_config_bool(value)
                            .map_err(|message| LpmError::Registry(format!("`{key}` {message}")))?;
                        crate::security_approval::authorize_persistent_install_time_source_analysis(
                        requested,
                        json_output,
                        &format!("lpm config set {key} {value}"),
                    )?;
                    }
                    TRUST_POLICY_KEY => validate_trust_policy_value(value)?,
                    INTEGRITY_KEY => {
                        parse_integrity_policy_selection(value)?;
                    }
                    TYPOSQUAT_GUARD_KEY => {
                        let requested = parse_typosquat_guard_selection(value)?;
                        reject_looser_typosquat_guard_write(config, requested)?;
                        crate::security_approval::authorize_persistent_typosquat_guard(
                            requested,
                            json_output,
                            &format!("lpm config set {key} {}", requested.as_str()),
                        )?;
                    }
                    _ => {}
                }
                {
                    let table = config.table_mut();
                    if key == AUTO_INSTALL_LPM_SKILLS_KEY {
                        table.remove(LEGACY_NO_SKILLS_KEY);
                    }
                    if key == TYPOSQUAT_GUARD_KEY
                        && parse_typosquat_guard_selection(value)?
                            == TyposquatGuardSelection::Default
                    {
                        table.remove(key);
                    } else {
                        let value = if matches!(
                            key,
                            SIGNATURES_KEY
                                | AUTO_INSTALL_LPM_SKILLS_KEY
                                | FETCH_LPM_SECURITY_INSIGHTS_KEY
                                | INSTALL_TIME_SOURCE_ANALYSIS_KEY
                        ) {
                            toml::Value::Boolean(parse_config_bool(value).map_err(|message| {
                                LpmError::Registry(format!("`{key}` {message}"))
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
                let json_value = if matches!(
                    key,
                    SIGNATURES_KEY
                        | AUTO_INSTALL_LPM_SKILLS_KEY
                        | FETCH_LPM_SECURITY_INSIGHTS_KEY
                        | INSTALL_TIME_SOURCE_ANALYSIS_KEY
                ) {
                    serde_json::Value::Bool(
                        parse_config_bool(value)
                            .map_err(|message| LpmError::Registry(format!("`{key}` {message}")))?,
                    )
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
                } else {
                    serde_json::Value::String(value.to_string())
                };
                Ok((json_value, true))
            })
            .await?;
            announce_generic_set(key, value, json_value, json_output);
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let existed = update_config(&config_path, |config| {
                if config_value_at_path(config.table(), key).is_none() {
                    return Ok((false, false));
                }
                guard_generic_delete_against_force_floor(config, key)?;
                match key {
                    SCRIPT_POLICY_KEY => {
                        crate::security_approval::authorize_persistent_script_policy(
                            crate::script_policy_config::ScriptPolicy::Deny,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?
                    }
                    RELEASE_AGE_KEY => crate::security_approval::authorize_persistent_release_age(
                        crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
                        json_output,
                        &format!("lpm config delete {key}"),
                    )?,
                    RELEASE_AGE_POLICY_KEY => {
                        crate::security_floor::reject_looser_release_age_policy_write(
                            config,
                            crate::release_age_config::ReleaseAgePolicy::Direct,
                        )?;
                        crate::security_approval::authorize_persistent_release_age_policy(
                            crate::release_age_config::ReleaseAgePolicy::Direct,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?;
                    }
                    "sandbox" | "sandbox.mode" => {
                        crate::security_approval::authorize_persistent_sandbox_mode(
                            ResolvedSandboxMode::Default,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?
                    }
                    "sigstore" | "sigstore.verify" => {
                        crate::security_approval::authorize_persistent_sigstore(
                            crate::provenance_fetch::EnforceMode::Deny,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?;
                    }
                    TYPOSQUAT_GUARD_KEY => {
                        crate::security_approval::authorize_persistent_typosquat_guard(
                            TyposquatGuardSelection::Default,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?;
                    }
                    FIREWALL_CONFIG_SECTION | "firewall.mode" => {
                        crate::security_floor::reject_looser_firewall_mode_write(
                            config,
                            NpmFirewallMode::Off,
                        )?;
                        crate::security_approval::authorize_persistent_npm_firewall_mode(
                            NpmFirewallMode::Off,
                            json_output,
                            &format!("lpm config delete {key}"),
                        )?;
                    }
                    INSTALL_TIME_SOURCE_ANALYSIS_KEY => {
                        crate::security_approval::authorize_persistent_install_time_source_analysis(
                        true,
                        json_output,
                        &format!("lpm config delete {key}"),
                    )?;
                    }
                    _ => {}
                }
                let existed = remove_config_value_at_path(config.table_mut(), key);
                Ok((existed, existed))
            })
            .await?;
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
                if existed {
                    install_ui::done_line(crate::install_ui::terminal_line!(
                        "Deleted {}",
                        install_ui::bold(key)
                    ));
                } else {
                    install_ui::warn_untrusted(&format!("{key} was not set"));
                }
            }
        }
        "list" | "ls" => {
            let current_dir = std::env::current_dir()?;
            let config = EffectiveConfig::load(&current_dir)?;
            if json_output {
                config.print_json()?;
            } else {
                config.print_human();
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown config action: {action}. \
                 Use: get, set, delete (alias: unset), list (alias: ls), \
                 scripts, triage, sandbox, sigstore, signatures, trust-policy, typosquat, firewall, integrity, release-age, release-age-policy, release-age-exclude, source-analysis, lpm-dev, lpm-skills, lpm-insights"
            )));
        }
    }

    Ok(())
}

fn announce_generic_set(
    key: &str,
    display_value: &str,
    json_value: serde_json::Value,
    json_output: bool,
) {
    let json_value = redact_config_json_value(key, json_value);
    let display_value = match &json_value {
        serde_json::Value::String(value) => value.as_str(),
        _ => display_value,
    };
    if json_output {
        let envelope = serde_json::json!({
            "success": true,
            "action": "set",
            "key": key,
            "value": json_value,
        });
        println!("{envelope}");
    } else {
        let key = lpm_common::sanitize_terminal_inline(key);
        let display_value = lpm_common::sanitize_terminal_inline(display_value);
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · {} = {}",
            key,
            install_ui::section(&format!("\"{display_value}\""))
        ));
    }
}

fn validate_action_arguments(
    action: Option<&str>,
    key: Option<&str>,
    value: Option<&str>,
    set: Option<&str>,
) -> Result<(), LpmError> {
    let invalid = match action {
        None => key.is_some() || value.is_some() || set.is_some(),
        Some("get" | "delete" | "unset") => key.is_none() || value.is_some() || set.is_some(),
        Some("set") => key.is_none() || value.is_none() || set.is_some(),
        Some("list" | "ls") => key.is_some() || value.is_some() || set.is_some(),
        Some("release-age-exclude") => false,
        Some(
            "scripts" | "triage" | "sandbox" | "sigstore" | "signatures" | "trust-policy"
            | "typosquat" | "firewall" | "integrity" | "release-age" | "release-age-policy"
            | "source-analysis" | "lpm-dev" | "lpm-skills" | "lpm-insights",
        ) => key.is_some() || value.is_some(),
        Some(_) => false,
    };
    if invalid {
        let action = action.unwrap_or("guided editor");
        return Err(LpmError::Registry(format!(
            "invalid arguments for `lpm config {action}`; run `lpm config --help` for the supported command shape"
        )));
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
                format!(
                    "verify={}, scope={}, availability={}",
                    summary.sigstore_verify, summary.sigstore_scope, summary.sigstore_availability,
                ),
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
                "release-age-configuration",
                RELEASE_AGE_GUIDED_MENU_LABEL,
                format!(
                    "scope={}, minimum={}",
                    summary.release_age_policy, summary.release_age
                ),
            )
            .item(
                "source-analysis",
                "Install-time source analysis",
                format!("current: {}", summary.source_analysis),
            )
            .item(
                "lpm-dev",
                "LPM.dev settings",
                format!(
                    "skills={}, insights={}",
                    summary.lpm_skills, summary.lpm_insights
                ),
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
            "release-age-configuration" => {
                run_release_age_configuration_wizard(config_path).await?
            }
            "source-analysis" => run_source_analysis_wizard(config_path, None, false).await?,
            "lpm-dev" => run_lpm_dev_wizard(config_path, None, false).await?,
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
    sigstore_scope: String,
    sigstore_availability: String,
    signatures: &'static str,
    trust_policy: String,
    typosquat_guard: String,
    firewall_mode: String,
    integrity_mode: String,
    release_age: String,
    release_age_policy: String,
    source_analysis: &'static str,
    lpm_skills: &'static str,
    lpm_insights: &'static str,
}

fn read_guided_config_summary(
    config_path: &std::path::Path,
) -> Result<GuidedConfigSummary, LpmError> {
    let global = GlobalConfig::from_value(read_config(config_path)?)?;
    let sandbox_mode = global
        .get_table("sandbox")
        .and_then(|table| table.get("mode"))
        .and_then(toml::Value::as_str);
    let sigstore_value = |key: &str| {
        global
            .get_table("sigstore")
            .and_then(|table| table.get(key))
            .and_then(toml::Value::as_str)
    };
    let release_age_policy = global
        .get_str(RELEASE_AGE_POLICY_KEY)
        .map(|raw| crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, raw))
        .transpose()?;
    Ok(GuidedConfigSummary {
        script_policy: global
            .get_str(SCRIPT_POLICY_KEY)
            .map(str::to_string)
            .filter(|value| SCRIPT_POLICY_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "deny".to_string()),
        triage_advisor: global
            .get_str(TRIAGE_ADVISOR_KEY)
            .map(str::to_string)
            .filter(|value| TRIAGE_ADVISOR_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "none".to_string()),
        sandbox_mode: sandbox_mode
            .filter(|value| SANDBOX_MODE_VALUES.contains(value))
            .map_or_else(|| "default".to_string(), str::to_string),
        sigstore_verify: sigstore_value("verify")
            .filter(|value| SIGSTORE_VERIFY_VALUES.contains(value))
            .map_or_else(|| "deny".to_string(), str::to_string),
        sigstore_scope: sigstore_value("scope")
            .filter(|value| SIGSTORE_SCOPE_VALUES.contains(value))
            .map_or_else(|| "approved".to_string(), str::to_string),
        sigstore_availability: sigstore_value("availability")
            .filter(|value| SIGSTORE_AVAILABILITY_VALUES.contains(value))
            .map_or_else(|| "best-effort".to_string(), str::to_string),
        signatures: format_bool_enabled(global.get_bool(SIGNATURES_KEY).unwrap_or(false)),
        trust_policy: global
            .get_str(TRUST_POLICY_KEY)
            .map(str::to_string)
            .filter(|value| TRUST_POLICY_VALUES.contains(&value.as_str()))
            .unwrap_or_else(|| "off".to_string()),
        typosquat_guard: format_current_typosquat_guard(global.get_typosquat_guard_mode()),
        firewall_mode: format_current_firewall_mode(crate::npm_firewall_config::config_mode(
            &global,
        )?),
        integrity_mode: format_current_integrity_policy(global.get_integrity_policy()?),
        release_age: format_current_release_age(global.get_u64(RELEASE_AGE_KEY)),
        release_age_policy: release_age_policy.unwrap_or_default().as_str().to_string(),
        source_analysis: format_bool_enabled(
            crate::source_analysis_config::read_install_time_source_analysis(&global)?,
        ),
        lpm_skills: format_current_lpm_skills(
            crate::lpm_skills_config::LpmSkillsPreference::Config.resolve(&global)?,
        ),
        lpm_insights: format_bool_enabled(
            crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)?,
        ),
    })
}
