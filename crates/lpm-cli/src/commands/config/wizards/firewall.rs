use super::prelude::*;
use console::{Key, Term};
use lpm_registry::client::{NpmFirewallPolicyAction, NpmFirewallPolicyProfile};
use std::io;

pub(in crate::commands::config) const FIREWALL_GUIDED_MENU_LABEL: &str = "Firewall for npm";
pub(in crate::commands::config) const FIREWALL_WIZARD_PROMPT: &str =
    "How should LPM CLI handle LPM Firewall verdicts for npm packages?";
pub(in crate::commands::config) const FIREWALL_OFF_HINT: &str =
    "default; use direct npm metadata and tarballs only";
pub(in crate::commands::config) const FIREWALL_MONITOR_HINT: &str =
    "show what would be blocked without stopping install";
pub(in crate::commands::config) const FIREWALL_ENFORCE_HINT: &str =
    "review recommended policy profile before saving";
const FIREWALL_POLICY_EDITOR_PROMPT: &str = "Review npm firewall enforcement policy";
const FIREWALL_POLICY_EDITOR_HELP: &str =
    "Use ↑/↓ to move, ←/→ to change, Enter to save, Esc to cancel.";
const BLOCK_WARN_ALLOW_ACTIONS: [NpmFirewallPolicyAction; 3] = [
    NpmFirewallPolicyAction::Block,
    NpmFirewallPolicyAction::Warn,
    NpmFirewallPolicyAction::Allow,
];
const WARN_ALLOW_ACTIONS: [NpmFirewallPolicyAction; 2] = [
    NpmFirewallPolicyAction::Warn,
    NpmFirewallPolicyAction::Allow,
];

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
            .item("enforce", "enforce", FIREWALL_ENFORCE_HINT)
            .initial_value(current.as_str())
            .interact()
            .map_err(prompt_err)?;
        if new_value == "enforce" {
            let initial_profile = read_firewall_policy_profile(config_path)?;
            let profile = prompt_firewall_policy_profile(initial_profile)?;
            let existing_cfg = read_config(config_path)?;
            if should_persist_firewall_policy_profile(&existing_cfg, profile) {
                FirewallWizardSelection::CustomEnforce(profile)
            } else {
                FirewallWizardSelection::Mode(NpmFirewallMode::Enforce)
            }
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

    apply_firewall_selection(
        config_path,
        selection,
        json_output,
        &format!("lpm config firewall --set {}", mode.as_str()),
    )
    .await?;
    announce_firewall_selection_set(selection, json_output);
    Ok(())
}

pub(in crate::commands::config) async fn apply_firewall_mode(
    config_path: &std::path::Path,
    mode: NpmFirewallMode,
    json_output: bool,
    proposed_command: &str,
) -> Result<(), LpmError> {
    apply_firewall_selection(
        config_path,
        FirewallWizardSelection::Mode(mode),
        json_output,
        proposed_command,
    )
    .await
}

async fn apply_firewall_selection(
    config_path: &std::path::Path,
    selection: FirewallWizardSelection,
    json_output: bool,
    proposed_command: &str,
) -> Result<(), LpmError> {
    let mode = selection.mode();
    update_config(config_path, |config| {
        validate_firewall_selection_target(config, selection)?;
        crate::security_floor::reject_looser_firewall_mode_write(config, mode)?;
        crate::security_approval::authorize_persistent_npm_firewall_mode(
            mode,
            json_output,
            proposed_command,
        )?;
        persist_firewall_mode_in_config_value(config, mode)?;
        if let Some(profile) = selection.policy_profile() {
            persist_firewall_policy_profile_in_config_value(config, profile)?;
        }
        Ok(((), true))
    })
    .await
}

fn validate_firewall_selection_target(
    config: &GlobalConfig,
    selection: FirewallWizardSelection,
) -> Result<(), LpmError> {
    let Some(firewall) = config.get_value(FIREWALL_CONFIG_SECTION) else {
        return Ok(());
    };
    let firewall = firewall.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "`{FIREWALL_CONFIG_SECTION}` is not a TOML table — refusing to clobber"
        ))
    })?;
    if selection.policy_profile().is_none() {
        return Ok(());
    }
    let Some(npm) = firewall.get(crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION) else {
        return Ok(());
    };
    let npm = npm
        .as_table()
        .ok_or_else(|| LpmError::Registry("`firewall.npm` is not a TOML table".to_string()))?;
    if npm
        .get(crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION)
        .is_some_and(|policies| !policies.is_table())
    {
        return Err(LpmError::Registry(
            "`firewall.npm.policies` is not a TOML table".to_string(),
        ));
    }
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

pub(in crate::commands::config) fn persist_firewall_mode_in_config_value(
    cfg: &mut GlobalConfig,
    mode: NpmFirewallMode,
) -> Result<(), LpmError> {
    let top = cfg.table_mut();
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
    cfg: &mut GlobalConfig,
    profile: NpmFirewallPolicyProfile,
) -> Result<(), LpmError> {
    let top = cfg.table_mut();
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
    policies_table.remove(crate::npm_firewall_config::LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY);
    policies_table.insert(
        crate::npm_firewall_config::LPM_AI_SUSPICIOUS_POLICY_KEY.to_string(),
        policy_action_value(profile.lpm_ai_suspicious),
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
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Set {} = {}",
            FIREWALL_CONFIG_PATH,
            install_ui::bold(mode.as_str()),
        ));
    }
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
        crate::npm_firewall_config::LPM_AI_SUSPICIOUS_POLICY_KEY.to_string(),
        serde_json::Value::String(profile.lpm_ai_suspicious.as_str().to_string()),
    );
    serde_json::Value::Object(policies)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirewallPolicyField {
    TrustedPublicMaliciousAdvisories,
    LpmAiConfirmedMalware,
    LpmAiAgentControlSurface,
    CriticalVulnerability,
    LpmAiSuspicious,
}

impl FirewallPolicyField {
    fn action(self, profile: NpmFirewallPolicyProfile) -> NpmFirewallPolicyAction {
        match self {
            Self::TrustedPublicMaliciousAdvisories => profile.trusted_public_malicious_advisories,
            Self::LpmAiConfirmedMalware => profile.lpm_ai_confirmed_malware,
            Self::LpmAiAgentControlSurface => profile.lpm_ai_agent_control_surface,
            Self::CriticalVulnerability => profile.critical_vulnerability,
            Self::LpmAiSuspicious => profile.lpm_ai_suspicious,
        }
    }

    fn set_action(self, profile: &mut NpmFirewallPolicyProfile, action: NpmFirewallPolicyAction) {
        match self {
            Self::TrustedPublicMaliciousAdvisories => {
                profile.trusted_public_malicious_advisories = action;
            }
            Self::LpmAiConfirmedMalware => profile.lpm_ai_confirmed_malware = action,
            Self::LpmAiAgentControlSurface => profile.lpm_ai_agent_control_surface = action,
            Self::CriticalVulnerability => profile.critical_vulnerability = action,
            Self::LpmAiSuspicious => profile.lpm_ai_suspicious = action,
        }
    }

    fn default_actions(self) -> &'static [NpmFirewallPolicyAction] {
        match self {
            Self::TrustedPublicMaliciousAdvisories
            | Self::LpmAiConfirmedMalware
            | Self::LpmAiAgentControlSurface
            | Self::CriticalVulnerability => &BLOCK_WARN_ALLOW_ACTIONS,
            Self::LpmAiSuspicious => &WARN_ALLOW_ACTIONS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FirewallPolicyGroup {
    field: FirewallPolicyField,
    title: &'static str,
    detail: &'static str,
}

const FIREWALL_POLICY_GROUPS: [FirewallPolicyGroup; 5] = [
    FirewallPolicyGroup {
        field: FirewallPolicyField::TrustedPublicMaliciousAdvisories,
        title: "Trusted public malicious advisories",
        detail: "OSV / OpenSSF / GHSA",
    },
    FirewallPolicyGroup {
        field: FirewallPolicyField::LpmAiConfirmedMalware,
        title: "LPM Firewall AI-confirmed malware",
        detail: "Credential/data exfiltration, RCE, remote payload execution, persistence, dependency confusion",
    },
    FirewallPolicyGroup {
        field: FirewallPolicyField::LpmAiAgentControlSurface,
        title: "LPM Firewall AI-agent control-surface policy",
        detail: "Silent install-lifecycle writes into foreign or broad AI-agent control surfaces",
    },
    FirewallPolicyGroup {
        field: FirewallPolicyField::CriticalVulnerability,
        title: "Critical vulnerabilities",
        detail: "Legitimate package risk without malicious author intent",
    },
    FirewallPolicyGroup {
        field: FirewallPolicyField::LpmAiSuspicious,
        title: "LPM Firewall AI-suspicious findings",
        detail: "AI-reviewed suspicious findings without confirmed malware intent",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct FirewallPolicyEditorRow {
    group: FirewallPolicyGroup,
    action: NpmFirewallPolicyAction,
    actions: Vec<NpmFirewallPolicyAction>,
}

impl FirewallPolicyEditorRow {
    fn new(group: FirewallPolicyGroup, action: NpmFirewallPolicyAction) -> Self {
        let default_actions = group.field.default_actions();
        let mut actions = Vec::with_capacity(default_actions.len() + 1);
        actions.extend_from_slice(default_actions);
        if !actions.contains(&action) {
            insert_missing_policy_action(&mut actions, action);
        }
        Self {
            group,
            action,
            actions,
        }
    }

    fn step_action(&mut self, step: PolicyActionStep) {
        let Some(current_index) = self
            .actions
            .iter()
            .position(|candidate| *candidate == self.action)
        else {
            return;
        };
        let next_index = match step {
            PolicyActionStep::Previous => {
                if current_index == 0 {
                    self.actions.len() - 1
                } else {
                    current_index - 1
                }
            }
            PolicyActionStep::Next => {
                let next = current_index + 1;
                if next == self.actions.len() { 0 } else { next }
            }
        };
        self.action = self.actions[next_index];
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyActionStep {
    Previous,
    Next,
}

fn insert_missing_policy_action(
    actions: &mut Vec<NpmFirewallPolicyAction>,
    action: NpmFirewallPolicyAction,
) {
    let index = match action {
        NpmFirewallPolicyAction::Warn => 0,
        NpmFirewallPolicyAction::Block => actions
            .iter()
            .position(|candidate| *candidate == NpmFirewallPolicyAction::Allow)
            .unwrap_or(actions.len()),
        NpmFirewallPolicyAction::Allow => actions.len(),
    };
    actions.insert(index, action);
}

fn read_firewall_policy_profile(
    config_path: &std::path::Path,
) -> Result<NpmFirewallPolicyProfile, LpmError> {
    let cfg = read_config(config_path)?;
    crate::npm_firewall_config::config_policy_profile(&GlobalConfig::from_value(cfg)?)
}

fn should_persist_firewall_policy_profile(
    cfg: &toml::Value,
    profile: NpmFirewallPolicyProfile,
) -> bool {
    profile != NpmFirewallPolicyProfile::default() || firewall_policy_table_exists(cfg)
}

fn firewall_policy_table_exists(cfg: &toml::Value) -> bool {
    cfg.get(FIREWALL_CONFIG_SECTION)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION))
        .and_then(toml::Value::as_table)
        .and_then(|table| {
            table.get(crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION)
        })
        .is_some()
}

fn prompt_firewall_policy_profile(
    initial_profile: NpmFirewallPolicyProfile,
) -> Result<NpmFirewallPolicyProfile, LpmError> {
    let mut term = Term::stderr();
    run_firewall_policy_editor(&mut term, initial_profile).map_err(prompt_err)
}

fn run_firewall_policy_editor(
    term: &mut Term,
    initial_profile: NpmFirewallPolicyProfile,
) -> io::Result<NpmFirewallPolicyProfile> {
    super::editor::run(term, |term| {
        interact_firewall_policy_editor(term, initial_profile)
    })
}

fn interact_firewall_policy_editor(
    term: &mut Term,
    initial_profile: NpmFirewallPolicyProfile,
) -> io::Result<NpmFirewallPolicyProfile> {
    let mut rows = firewall_policy_rows_from_profile(initial_profile);
    let mut cursor = 0;
    let mut previous_line_count = 0;

    loop {
        let frame = format_firewall_policy_editor_frame(&rows, cursor);
        super::editor::draw_frame(term, &frame, &mut previous_line_count)?;

        match term.read_key()? {
            Key::ArrowUp | Key::Char('k') => {
                cursor = if cursor == 0 {
                    rows.len() - 1
                } else {
                    cursor - 1
                };
            }
            Key::ArrowDown | Key::Char('j') => {
                cursor += 1;
                if cursor == rows.len() {
                    cursor = 0;
                }
            }
            Key::ArrowLeft | Key::Char('h') => {
                rows[cursor].step_action(PolicyActionStep::Previous);
            }
            Key::ArrowRight | Key::Char('l') | Key::Char(' ') => {
                rows[cursor].step_action(PolicyActionStep::Next);
            }
            Key::Enter => return Ok(firewall_policy_profile_from_rows(&rows)),
            Key::Escape | Key::CtrlC => return Err(io::ErrorKind::Interrupted.into()),
            _ => {}
        }
    }
}

fn firewall_policy_rows_from_profile(
    profile: NpmFirewallPolicyProfile,
) -> Vec<FirewallPolicyEditorRow> {
    let mut rows = Vec::with_capacity(FIREWALL_POLICY_GROUPS.len());
    for group in FIREWALL_POLICY_GROUPS {
        rows.push(FirewallPolicyEditorRow::new(
            group,
            group.field.action(profile),
        ));
    }
    rows
}

fn firewall_policy_profile_from_rows(rows: &[FirewallPolicyEditorRow]) -> NpmFirewallPolicyProfile {
    let mut profile = NpmFirewallPolicyProfile::default();
    for row in rows {
        row.group.field.set_action(&mut profile, row.action);
    }
    profile
}

fn format_firewall_policy_editor_frame(rows: &[FirewallPolicyEditorRow], cursor: usize) -> String {
    let mut frame = String::with_capacity(1_200);
    frame.push_str(&format!(
        "◆  {}\n",
        FIREWALL_POLICY_EDITOR_PROMPT.cyan().bold()
    ));
    frame.push_str(&format!("│  {}\n", FIREWALL_POLICY_EDITOR_HELP.dimmed()));
    frame.push_str("│\n");
    for (index, row) in rows.iter().enumerate() {
        let active = index == cursor;
        let title = if active {
            row.group.title.bold()
        } else {
            row.group.title.to_string()
        };
        let marker = if active {
            "›".cyan().bold()
        } else {
            " ".to_string()
        };
        frame.push_str(&format!("│  {marker} {title}\n"));
        frame.push_str(&format!("│    {}\n", row.group.detail.dimmed()));
        frame.push_str(&format!("│    {}\n", format_policy_action_options(row)));
        if index + 1 < rows.len() {
            frame.push_str("│\n");
        }
    }
    frame.push_str("└\n");
    frame
}

fn format_policy_action_options(row: &FirewallPolicyEditorRow) -> String {
    let mut rendered = String::with_capacity(48);
    for (index, action) in row.actions.iter().enumerate() {
        if index > 0 {
            rendered.push_str("  ");
        }
        let selected = *action == row.action;
        let symbol = if selected { "●" } else { "○" };
        let label = policy_action_label(*action);
        if selected {
            rendered.push_str(&format!("{} {}", symbol.cyan(), label.bold()));
        } else {
            rendered.push_str(&format!("{symbol} {label}"));
        }
    }
    rendered
}

fn policy_action_label(action: NpmFirewallPolicyAction) -> &'static str {
    match action {
        NpmFirewallPolicyAction::Block => "Block",
        NpmFirewallPolicyAction::Warn => "Warn only",
        NpmFirewallPolicyAction::Allow => "Allow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_policy_editor_frame_shows_every_policy_group_on_one_prompt() {
        let rows = firewall_policy_rows_from_profile(NpmFirewallPolicyProfile::default());

        let frame = format_firewall_policy_editor_frame(&rows, 0);
        let plain = console::strip_ansi_codes(&frame);

        assert!(plain.contains("Trusted public malicious advisories"));
        assert!(plain.contains("LPM Firewall AI-confirmed malware"));
        assert!(plain.contains("LPM Firewall AI-agent control-surface policy"));
        assert!(plain.contains("Critical vulnerabilities"));
        assert!(plain.contains("LPM Firewall AI-suspicious findings"));
    }

    #[test]
    fn firewall_policy_editor_orders_critical_vulnerability_actions_like_blocking_groups() {
        let rows = firewall_policy_rows_from_profile(NpmFirewallPolicyProfile::default());
        let critical = rows
            .iter()
            .find(|row| row.group.field == FirewallPolicyField::CriticalVulnerability)
            .expect("critical vulnerability row must exist");

        assert_eq!(
            critical.actions,
            [
                NpmFirewallPolicyAction::Block,
                NpmFirewallPolicyAction::Warn,
                NpmFirewallPolicyAction::Allow,
            ]
        );
        assert_eq!(critical.action, NpmFirewallPolicyAction::Warn);
    }

    #[test]
    fn firewall_policy_editor_defaults_ai_agent_control_surface_to_warn() {
        let rows = firewall_policy_rows_from_profile(NpmFirewallPolicyProfile::default());
        let ai_agent = rows
            .iter()
            .find(|row| row.group.field == FirewallPolicyField::LpmAiAgentControlSurface)
            .expect("AI-agent control-surface row must exist");

        assert_eq!(
            ai_agent.actions,
            [
                NpmFirewallPolicyAction::Block,
                NpmFirewallPolicyAction::Warn,
                NpmFirewallPolicyAction::Allow,
            ]
        );
        assert_eq!(ai_agent.action, NpmFirewallPolicyAction::Warn);
    }

    #[test]
    fn firewall_policy_editor_preserves_manual_ai_suspicious_block_action() {
        let rows = firewall_policy_rows_from_profile(NpmFirewallPolicyProfile {
            lpm_ai_suspicious: NpmFirewallPolicyAction::Block,
            ..NpmFirewallPolicyProfile::default()
        });
        let ai_suspicious = rows
            .iter()
            .find(|row| row.group.field == FirewallPolicyField::LpmAiSuspicious)
            .expect("AI-suspicious row must exist");

        assert_eq!(ai_suspicious.action, NpmFirewallPolicyAction::Block);
        assert!(
            ai_suspicious
                .actions
                .contains(&NpmFirewallPolicyAction::Block)
        );
    }

    #[test]
    fn default_enforce_policy_without_existing_policy_table_does_not_persist_custom_table() {
        let cfg = toml::Value::Table(toml::map::Map::new());

        assert!(!should_persist_firewall_policy_profile(
            &cfg,
            NpmFirewallPolicyProfile::default()
        ));
    }

    #[test]
    fn default_enforce_policy_with_existing_policy_table_persists_to_reset_custom_values() {
        let mut policies = toml::map::Map::new();
        policies.insert(
            crate::npm_firewall_config::LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("allow".to_string()),
        );
        let mut npm = toml::map::Map::new();
        npm.insert(
            crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
            toml::Value::Table(policies),
        );
        let mut firewall = toml::map::Map::new();
        firewall.insert(
            crate::npm_firewall_config::FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
        let mut top = toml::map::Map::new();
        top.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        let cfg = toml::Value::Table(top);

        assert!(should_persist_firewall_policy_profile(
            &cfg,
            NpmFirewallPolicyProfile::default()
        ));
    }
}
