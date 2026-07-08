use super::prelude::*;
use lpm_registry::client::{NpmFirewallPolicyAction, NpmFirewallPolicyProfile};

pub(in crate::commands::config) const FIREWALL_GUIDED_MENU_LABEL: &str = "Firewall for npm";
pub(in crate::commands::config) const FIREWALL_WIZARD_PROMPT: &str =
    "How should LPM handle firewall verdicts for npm packages?";
pub(in crate::commands::config) const FIREWALL_OFF_HINT: &str =
    "default; use direct npm metadata and tarballs only";
pub(in crate::commands::config) const FIREWALL_MONITOR_HINT: &str =
    "show what would be blocked without stopping install";
pub(in crate::commands::config) const FIREWALL_ENFORCE_HINT: &str =
    "recommended policy profile; block high-confidence firewall verdicts";
pub(in crate::commands::config) const FIREWALL_CUSTOMIZE_HINT: &str =
    "choose which firewall policy groups block, warn, or allow";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirewallWizardSelection {
    Mode(NpmFirewallMode),
    CustomEnforce(NpmFirewallPolicyProfile),
}

impl FirewallWizardSelection {
    fn mode(self) -> NpmFirewallMode {
        match self {
            Self::Mode(mode) => mode,
            Self::CustomEnforce(_) => NpmFirewallMode::Enforce,
        }
    }

    fn policy_profile(self) -> Option<NpmFirewallPolicyProfile> {
        match self {
            Self::Mode(_) => None,
            Self::CustomEnforce(profile) => Some(profile),
        }
    }
}

pub(in crate::commands::config) async fn run_firewall_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let selection = if let Some(value) = set {
        FirewallWizardSelection::Mode(parse_firewall_mode_selection(value)?)
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config firewall requires a TTY; use `--set off|monitor|enforce` instead"
                    .to_string(),
            ));
        }

        let current = read_firewall_mode(config_path)?.unwrap_or_default();
        println!();
        println!(
            "  current: {}",
            format_current_firewall_mode(Some(current)).cyan()
        );
        let new_value: &str = cliclack::select(FIREWALL_WIZARD_PROMPT)
            .item("off", "off", FIREWALL_OFF_HINT)
            .item("monitor", "monitor", FIREWALL_MONITOR_HINT)
            .item("enforce", "enforce recommended", FIREWALL_ENFORCE_HINT)
            .item("custom", "customize enforcement", FIREWALL_CUSTOMIZE_HINT)
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;
        if new_value == "custom" {
            FirewallWizardSelection::CustomEnforce(prompt_firewall_policy_profile()?)
        } else {
            FirewallWizardSelection::Mode(parse_firewall_mode_selection(new_value)?)
        }
    };
    let mode = selection.mode();

    if set.is_none() && mode.loosens(read_firewall_mode(config_path)?.unwrap_or_default()) {
        println!();
        println!(
            "  {}: setting firewall mode to {} weakens npm firewall checks for every \
             install on this machine.",
            "warning".yellow(),
            mode.as_str().yellow().bold(),
        );
        let confirmed = cliclack::confirm(
            "Are you sure you want to weaken npm firewall checks for every install on this machine?",
        )
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            println!("  Aborted. No config change.");
            return Ok(());
        }
    }

    let existing_cfg = read_config(config_path)?;
    crate::security_floor::reject_looser_firewall_mode_write(
        &global_config_view_from_value(&existing_cfg),
        mode,
    )?;
    crate::security_approval::authorize_persistent_npm_firewall_mode(
        mode,
        json_output,
        &format!("lpm config firewall --set {}", mode.as_str()),
    )?;
    persist_firewall_selection(config_path, selection)?;
    announce_firewall_selection_set(selection, json_output);
    Ok(())
}

pub(in crate::commands::config) fn parse_firewall_mode_selection(
    input: &str,
) -> Result<NpmFirewallMode, LpmError> {
    NpmFirewallMode::parse(input).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid firewall mode '{input}'; must be one of: off | monitor | enforce (`report` is accepted as a legacy alias)"
        ))
    })
}

pub(in crate::commands::config) fn read_firewall_mode(
    config_path: &std::path::Path,
) -> Result<Option<NpmFirewallMode>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    crate::npm_firewall_config::config_mode(&GlobalConfig { table })
}

fn persist_firewall_selection(
    config_path: &std::path::Path,
    selection: FirewallWizardSelection,
) -> Result<(), LpmError> {
    let mut cfg = read_config(config_path)?;
    persist_firewall_mode_in_config_value(&mut cfg, selection.mode())?;
    if let Some(profile) = selection.policy_profile() {
        persist_firewall_policy_profile_in_config_value(&mut cfg, profile)?;
    }
    write_config(config_path, &cfg)
}

pub(in crate::commands::config) fn persist_firewall_mode_in_config_value(
    cfg: &mut toml::Value,
    mode: NpmFirewallMode,
) -> Result<(), LpmError> {
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let firewall_section = top
        .entry(FIREWALL_CONFIG_SECTION.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let firewall_table = firewall_section.as_table_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "`{FIREWALL_CONFIG_SECTION}` is not a TOML table — refusing to clobber"
        ))
    })?;
    firewall_table.insert(
        FIREWALL_CONFIG_MODE_KEY.to_string(),
        toml::Value::String(mode.as_str().to_string()),
    );
    Ok(())
}

pub(in crate::commands::config) fn persist_firewall_policy_profile_in_config_value(
    cfg: &mut toml::Value,
    profile: NpmFirewallPolicyProfile,
) -> Result<(), LpmError> {
    let top = cfg.as_table_mut().ok_or_else(|| {
        LpmError::Registry("config.toml must be a TOML table at the top level".into())
    })?;
    let firewall_table = top
        .entry(FIREWALL_CONFIG_SECTION.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "`{FIREWALL_CONFIG_SECTION}` is not a TOML table — refusing to clobber"
            ))
        })?;
    let npm_table = firewall_table
        .entry(crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| LpmError::Registry("`firewall.npm` is not a TOML table".to_string()))?;
    let policies_table = npm_table
        .entry(crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            LpmError::Registry("`firewall.npm.policies` is not a TOML table".to_string())
        })?;
    policies_table.insert(
        crate::npm_firewall_config::TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY.to_string(),
        policy_action_value(profile.trusted_public_malicious_advisories),
    );
    policies_table.insert(
        crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY.to_string(),
        policy_action_value(profile.lpm_ai_confirmed_malware),
    );
    policies_table.insert(
        crate::npm_firewall_config::LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY.to_string(),
        policy_action_value(profile.lpm_ai_agent_control_surface),
    );
    policies_table.insert(
        crate::npm_firewall_config::CRITICAL_VULNERABILITY_POLICY_KEY.to_string(),
        policy_action_value(profile.critical_vulnerability),
    );
    policies_table.insert(
        crate::npm_firewall_config::STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
        policy_action_value(profile.static_only_suspicious),
    );
    Ok(())
}

pub(in crate::commands::config) fn format_current_firewall_mode(
    current: Option<NpmFirewallMode>,
) -> String {
    current.unwrap_or_default().as_str().to_string()
}

fn announce_firewall_selection_set(selection: FirewallWizardSelection, json_output: bool) {
    let mode = selection.mode();
    if json_output {
        let mut firewall = serde_json::json!({ "mode": mode.as_str() });
        if let Some(profile) = selection.policy_profile() {
            firewall["npm"] = serde_json::json!({
                "policies": policy_profile_json(profile),
            });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "firewall": firewall,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Set {FIREWALL_CONFIG_PATH} = {}",
            mode.as_str().bold()
        ));
    }
}

fn prompt_firewall_policy_profile() -> Result<NpmFirewallPolicyProfile, LpmError> {
    Ok(NpmFirewallPolicyProfile {
        trusted_public_malicious_advisories: prompt_block_warn_allow_policy_action(
            "Trusted public malicious advisories (OSV/OpenSSF/GHSA)",
            NpmFirewallPolicyAction::Block,
        )?,
        lpm_ai_confirmed_malware: prompt_block_warn_allow_policy_action(
            "LPM AI-confirmed malware",
            NpmFirewallPolicyAction::Block,
        )?,
        lpm_ai_agent_control_surface: prompt_block_warn_allow_policy_action(
            "LPM AI-agent control-surface policy",
            NpmFirewallPolicyAction::Block,
        )?,
        critical_vulnerability: prompt_warn_allow_policy_action(
            "Critical vulnerabilities",
            NpmFirewallPolicyAction::Warn,
        )?,
        static_only_suspicious: prompt_warn_allow_policy_action(
            "Static-only suspicious signals",
            NpmFirewallPolicyAction::Warn,
        )?,
    })
}

fn prompt_block_warn_allow_policy_action(
    prompt: &str,
    initial: NpmFirewallPolicyAction,
) -> Result<NpmFirewallPolicyAction, LpmError> {
    let value: &str = cliclack::select(prompt)
        .item("block", "block", "stop install")
        .item("warn", "warn only", "show warning and continue")
        .item("allow", "allow", "ignore this policy group")
        .initial_value(initial.as_str())
        .interact()
        .map_err(prompt_err)?;
    parse_policy_action(value)
}

fn prompt_warn_allow_policy_action(
    prompt: &str,
    initial: NpmFirewallPolicyAction,
) -> Result<NpmFirewallPolicyAction, LpmError> {
    let value: &str = cliclack::select(prompt)
        .item("warn", "warn only", "show warning and continue")
        .item("allow", "allow", "ignore this policy group")
        .initial_value(initial.as_str())
        .interact()
        .map_err(prompt_err)?;
    parse_policy_action(value)
}

fn parse_policy_action(value: &str) -> Result<NpmFirewallPolicyAction, LpmError> {
    NpmFirewallPolicyAction::parse(value)
        .ok_or_else(|| LpmError::Registry(format!("invalid firewall policy action '{value}'")))
}

fn policy_action_value(action: NpmFirewallPolicyAction) -> toml::Value {
    toml::Value::String(action.as_str().to_string())
}

fn policy_profile_json(profile: NpmFirewallPolicyProfile) -> serde_json::Value {
    let mut policies = serde_json::Map::new();
    policies.insert(
        crate::npm_firewall_config::TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY.to_string(),
        serde_json::Value::String(
            profile
                .trusted_public_malicious_advisories
                .as_str()
                .to_string(),
        ),
    );
    policies.insert(
        crate::npm_firewall_config::LPM_AI_CONFIRMED_MALWARE_POLICY_KEY.to_string(),
        serde_json::Value::String(profile.lpm_ai_confirmed_malware.as_str().to_string()),
    );
    policies.insert(
        crate::npm_firewall_config::LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY.to_string(),
        serde_json::Value::String(profile.lpm_ai_agent_control_surface.as_str().to_string()),
    );
    policies.insert(
        crate::npm_firewall_config::CRITICAL_VULNERABILITY_POLICY_KEY.to_string(),
        serde_json::Value::String(profile.critical_vulnerability.as_str().to_string()),
    );
    policies.insert(
        crate::npm_firewall_config::STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
        serde_json::Value::String(profile.static_only_suspicious.as_str().to_string()),
    );
    serde_json::Value::Object(policies)
}
