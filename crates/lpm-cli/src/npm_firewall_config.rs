use crate::commands::config::GlobalConfig;
use lpm_common::LpmError;
use lpm_registry::client::{NpmFirewallPolicyAction, NpmFirewallPolicyProfile};
use std::path::Path;

pub(crate) const FIREWALL_CONFIG_SECTION: &str = "firewall";
pub(crate) const FIREWALL_CONFIG_MODE_KEY: &str = "mode";
pub(crate) const FIREWALL_CONFIG_PATH: &str = "[firewall].mode";
pub(crate) const FIREWALL_NPM_CONFIG_SECTION: &str = "npm";
pub(crate) const FIREWALL_NPM_POLICIES_CONFIG_SECTION: &str = "policies";
pub(crate) const FIREWALL_NPM_POLICIES_CONFIG_PATH: &str = "[firewall.npm.policies]";

pub(crate) const TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY: &str =
    "trusted_public_malicious_advisories";
pub(crate) const LPM_AI_CONFIRMED_MALWARE_POLICY_KEY: &str = "lpm_ai_confirmed_malware";
pub(crate) const LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY: &str = "lpm_ai_dependency_script_policy";
pub(crate) const LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY: &str = "lpm_ai_agent_control_surface";
pub(crate) const LPM_AI_TELEMETRY_POLICY_KEY: &str = "lpm_ai_telemetry";
pub(crate) const LPM_AI_SUSPICIOUS_POLICY_KEY: &str = "lpm_ai_suspicious";
pub(crate) const CRITICAL_VULNERABILITY_POLICY_KEY: &str = "critical_vulnerability";
pub(crate) const LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY: &str = "static_only_suspicious";

const ENV_NPM_FIREWALL: &str = "LPM_NPM_FIREWALL";
const ENV_EXPERIMENT_NPM_FIREWALL: &str = "LPM_EXPERIMENT_NPM_FIREWALL";

/// Where the effective `lpm_ai_telemetry` action comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TelemetryPolicyOrigin {
    Default,
    Config,
    /// Telemetry warnings used to be part of `lpm_ai_suspicious`, so a policy
    /// table that predates `lpm_ai_telemetry` keeps applying its AI-suspicious
    /// action (or the legacy `static_only_suspicious` one) to telemetry.
    InheritedFromAiSuspicious,
}

pub(crate) fn telemetry_policy_origin(policies: Option<&toml::Table>) -> TelemetryPolicyOrigin {
    let Some(policies) = policies else {
        return TelemetryPolicyOrigin::Default;
    };
    if policies.contains_key(LPM_AI_TELEMETRY_POLICY_KEY) {
        TelemetryPolicyOrigin::Config
    } else if policies.contains_key(LPM_AI_SUSPICIOUS_POLICY_KEY)
        || policies.contains_key(LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY)
    {
        TelemetryPolicyOrigin::InheritedFromAiSuspicious
    } else {
        TelemetryPolicyOrigin::Default
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum NpmFirewallMode {
    #[default]
    Off,
    Monitor,
    Enforce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NpmFirewallModeRequest {
    mode: NpmFirewallMode,
    source: NpmFirewallModeRequestSource,
}

impl NpmFirewallModeRequest {
    #[cfg(test)]
    pub(crate) fn from_config(mode: NpmFirewallMode) -> Self {
        Self {
            mode,
            source: NpmFirewallModeRequestSource::Config,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_env(mode: NpmFirewallMode) -> Self {
        Self {
            mode,
            source: NpmFirewallModeRequestSource::Env,
        }
    }

    pub(crate) fn mode(self) -> NpmFirewallMode {
        self.mode
    }

    pub(crate) fn source_label(self) -> &'static str {
        match self.source {
            NpmFirewallModeRequestSource::Config => "~/.lpm/config.toml [firewall].mode",
            NpmFirewallModeRequestSource::Env => "environment",
            NpmFirewallModeRequestSource::ConfigAndEnv => {
                "~/.lpm/config.toml [firewall].mode + environment"
            }
        }
    }

    pub(crate) fn approval_source(self) -> crate::security_approval::ApprovalSource {
        match self.source {
            NpmFirewallModeRequestSource::Config => {
                crate::security_approval::ApprovalSource::GlobalConfig
            }
            NpmFirewallModeRequestSource::Env => crate::security_approval::ApprovalSource::EnvVar,
            NpmFirewallModeRequestSource::ConfigAndEnv => {
                crate::security_approval::ApprovalSource::ConfigAndEnv
            }
        }
    }

    pub(crate) fn downgrade_message(self) -> &'static str {
        match self.source {
            NpmFirewallModeRequestSource::Config => {
                "The persisted global [firewall].mode setting weakens npm firewall checks for this project."
            }
            NpmFirewallModeRequestSource::Env => {
                "The environment npm firewall setting weakens npm firewall checks for this project."
            }
            NpmFirewallModeRequestSource::ConfigAndEnv => {
                "The combined persisted global [firewall].mode and environment npm firewall settings weaken npm firewall checks for this project."
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NpmFirewallModeRequestSource {
    Config,
    Env,
    ConfigAndEnv,
}

impl NpmFirewallMode {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "no" | "disabled" => Some(Self::Off),
            "monitor" | "report" | "warn" => Some(Self::Monitor),
            "enforce" | "deny" | "block" | "true" | "1" | "yes" | "enabled" | "on" => {
                Some(Self::Enforce)
            }
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Monitor => "monitor",
            Self::Enforce => "enforce",
        }
    }

    pub(crate) fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Only enforcement has to see a verdict before package bytes arrive;
    /// monitor mode reports verdicts without changing the install.
    pub(crate) fn disables_tarball_prefetch(self) -> bool {
        matches!(self, Self::Enforce)
    }

    pub(crate) fn loosens(self, floor: Self) -> bool {
        self.rank() < floor.rank()
    }

    pub(crate) fn stricter(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Monitor => 1,
            Self::Enforce => 2,
        }
    }
}

pub(crate) fn config_mode(global: &GlobalConfig) -> Result<Option<NpmFirewallMode>, LpmError> {
    let Some(section) = global.get_value(FIREWALL_CONFIG_SECTION) else {
        return Ok(None);
    };
    let table = section.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[{FIREWALL_CONFIG_SECTION}]` must be a TOML table"
        ))
    })?;
    let Some(value) = table.get(FIREWALL_CONFIG_MODE_KEY) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        LpmError::Registry(format!(
            "`{FIREWALL_CONFIG_PATH}` must be a string: off | monitor | enforce"
        ))
    })?;
    NpmFirewallMode::parse(raw).map(Some).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `{FIREWALL_CONFIG_PATH}` value `{raw}`; must be one of: off | monitor | enforce (`report` is accepted as a legacy alias)"
        ))
    })
}

pub(crate) fn config_policy_profile(
    global: &GlobalConfig,
) -> Result<NpmFirewallPolicyProfile, LpmError> {
    Ok(config_policy_request(global)?.unwrap_or_default())
}

/// The profile `~/.lpm/config.toml` asks for, with the built-in default for
/// each group its table leaves out, or `None` without a table or with an
/// empty one.
pub(crate) fn config_policy_request(
    global: &GlobalConfig,
) -> Result<Option<NpmFirewallPolicyProfile>, LpmError> {
    policy_request_over(global, NpmFirewallPolicyProfile::default(), None)
}

/// What an approved profile makes of the groups a `[firewall.npm.policies]`
/// table in `~/.lpm/config.toml` leaves out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyTableBase {
    /// What installs run for a group the table leaves out.
    pub(crate) tableless: NpmFirewallPolicyProfile,
    /// The approved telemetry action, which telemetry following
    /// `lpm_ai_suspicious` never goes below, or `None` where the approved
    /// firewall is off and so binds no action.
    pub(crate) approved_telemetry: Option<NpmFirewallPolicyAction>,
}

impl PolicyTableBase {
    /// The base an `approved` profile gives under `approved_mode`; a managed
    /// profile applies as written.
    pub(crate) fn of(
        approved: NpmFirewallPolicyProfile,
        approved_mode: NpmFirewallMode,
        managed: bool,
    ) -> Self {
        Self {
            tableless: tableless_policy_profile(approved, managed),
            approved_telemetry: (approved_mode != NpmFirewallMode::Off)
                .then_some(approved.lpm_ai_telemetry),
        }
    }

    pub(crate) fn of_posture(
        effective: &crate::security_approval::EffectiveAuthorizedPosture,
    ) -> Self {
        Self::of(
            effective.posture.firewall_policy_profile(),
            effective.posture.firewall_mode(),
            matches!(
                effective.sources.firewall_policies,
                crate::security_approval::PostureSourceKind::ManagedPolicy
            ),
        )
    }
}

/// The profile `~/.lpm/config.toml` asks for over `base`: each group its
/// `[firewall.npm.policies]` table names, and what installs run without a
/// table for the rest, or `None` without a table or with an empty one.
pub(crate) fn config_policy_request_over(
    global: &GlobalConfig,
    base: PolicyTableBase,
) -> Result<Option<NpmFirewallPolicyProfile>, LpmError> {
    policy_request_over(global, base.tableless, base.approved_telemetry)
}

fn policy_request_over(
    global: &GlobalConfig,
    base: NpmFirewallPolicyProfile,
    telemetry_floor: Option<NpmFirewallPolicyAction>,
) -> Result<Option<NpmFirewallPolicyProfile>, LpmError> {
    firewall_policy_table(global.table())
        .and_then(|policies| {
            policies
                .filter(|policies| !policies.is_empty())
                .map(|policies| parse_policy_table_over(policies, base, telemetry_floor))
                .transpose()
        })
        .map_err(LpmError::Registry)
}

/// What a command asks for: the groups `~/.lpm/config.toml` names, and for
/// the rest what it runs without a table, so leaving a group out never asks
/// for less than the approved profile allows.
pub(crate) fn runtime_policy_request(
    global: &GlobalConfig,
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
) -> Result<Option<NpmFirewallPolicyProfile>, LpmError> {
    config_policy_request_over(global, PolicyTableBase::of_posture(effective))
}

/// The `[firewall.npm.policies]` table under a config-shaped TOML table, as
/// both `~/.lpm/config.toml` and the managed security policy lay it out.
pub(crate) fn firewall_policy_table(top: &toml::Table) -> Result<Option<&toml::Table>, String> {
    let Some(section) = top.get(FIREWALL_CONFIG_SECTION) else {
        return Ok(None);
    };
    let table = section
        .as_table()
        .ok_or_else(|| format!("`[{FIREWALL_CONFIG_SECTION}]` must be a TOML table"))?;
    let Some(npm) = table.get(FIREWALL_NPM_CONFIG_SECTION) else {
        return Ok(None);
    };
    let npm_table = npm
        .as_table()
        .ok_or_else(|| "`[firewall.npm]` must be a TOML table".to_string())?;
    let Some(policies) = npm_table.get(FIREWALL_NPM_POLICIES_CONFIG_SECTION) else {
        return Ok(None);
    };
    policies
        .as_table()
        .map(Some)
        .ok_or_else(|| format!("`{FIREWALL_NPM_POLICIES_CONFIG_PATH}` must be a TOML table"))
}

pub(crate) fn parse_policy_table(
    policies: &toml::Table,
) -> Result<NpmFirewallPolicyProfile, String> {
    parse_policy_table_over(policies, NpmFirewallPolicyProfile::default(), None)
}

/// The table's actions over `base`: a group the table leaves out keeps its
/// `base` action, except that telemetry follows `lpm_ai_suspicious` when only
/// that is set, though never below `telemetry_floor`.
fn parse_policy_table_over(
    policies: &toml::Table,
    base: NpmFirewallPolicyProfile,
    telemetry_floor: Option<NpmFirewallPolicyAction>,
) -> Result<NpmFirewallPolicyProfile, String> {
    let mut profile = base;
    let has_canonical_ai_suspicious = policies.contains_key(LPM_AI_SUSPICIOUS_POLICY_KEY);
    for (key, value) in policies {
        if key == LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY && has_canonical_ai_suspicious {
            continue;
        }
        let raw = value.as_str().ok_or_else(|| {
            format!(
                "`{FIREWALL_NPM_POLICIES_CONFIG_PATH}.{key}` must be a string: allow | warn | block"
            )
        })?;
        let action = NpmFirewallPolicyAction::parse(raw).ok_or_else(|| {
            format!(
                "invalid `{FIREWALL_NPM_POLICIES_CONFIG_PATH}.{key}` value `{raw}`; must be one of: allow | warn | block"
            )
        })?;
        let canonical_key = if key == LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY {
            LPM_AI_SUSPICIOUS_POLICY_KEY
        } else {
            key.as_str()
        };
        let Some(slot) = policy_action_mut(&mut profile, canonical_key) else {
            return Err(format!(
                "unknown `{FIREWALL_NPM_POLICIES_CONFIG_PATH}` key `{key}`"
            ));
        };
        *slot = action;
    }
    if telemetry_policy_origin(Some(policies)) == TelemetryPolicyOrigin::InheritedFromAiSuspicious {
        // Leaving the telemetry key out never asks for less than the approved
        // telemetry action, so dropping it can't make installs refuse.
        let enforce = NpmFirewallMode::Enforce;
        profile.lpm_ai_telemetry = match telemetry_floor {
            Some(floor)
                if enforced_rank(enforce, floor)
                    > enforced_rank(enforce, profile.lpm_ai_suspicious) =>
            {
                floor
            }
            _ => profile.lpm_ai_suspicious,
        };
    }
    Ok(profile)
}

/// Every policy group the profile decides, in the order LPM shows them.
pub(crate) const POLICY_KEYS: [&str; 7] = [
    TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY,
    LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
    LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY,
    LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY,
    LPM_AI_TELEMETRY_POLICY_KEY,
    LPM_AI_SUSPICIOUS_POLICY_KEY,
    CRITICAL_VULNERABILITY_POLICY_KEY,
];

pub(crate) fn policy_action(
    profile: &NpmFirewallPolicyProfile,
    key: &str,
) -> Option<NpmFirewallPolicyAction> {
    Some(match key {
        TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY => {
            profile.trusted_public_malicious_advisories
        }
        LPM_AI_CONFIRMED_MALWARE_POLICY_KEY => profile.lpm_ai_confirmed_malware,
        LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY => profile.lpm_ai_dependency_script_policy,
        LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY => profile.lpm_ai_agent_control_surface,
        LPM_AI_TELEMETRY_POLICY_KEY => profile.lpm_ai_telemetry,
        LPM_AI_SUSPICIOUS_POLICY_KEY => profile.lpm_ai_suspicious,
        CRITICAL_VULNERABILITY_POLICY_KEY => profile.critical_vulnerability,
        _ => return None,
    })
}

pub(crate) fn policy_action_mut<'a>(
    profile: &'a mut NpmFirewallPolicyProfile,
    key: &str,
) -> Option<&'a mut NpmFirewallPolicyAction> {
    Some(match key {
        TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY => {
            &mut profile.trusted_public_malicious_advisories
        }
        LPM_AI_CONFIRMED_MALWARE_POLICY_KEY => &mut profile.lpm_ai_confirmed_malware,
        LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY => &mut profile.lpm_ai_dependency_script_policy,
        LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY => &mut profile.lpm_ai_agent_control_surface,
        LPM_AI_TELEMETRY_POLICY_KEY => &mut profile.lpm_ai_telemetry,
        LPM_AI_SUSPICIOUS_POLICY_KEY => &mut profile.lpm_ai_suspicious,
        CRITICAL_VULNERABILITY_POLICY_KEY => &mut profile.critical_vulnerability,
        _ => return None,
    })
}

/// The policy groups whose action differs from the default profile, as the
/// signed posture and the managed policy store them.
pub(crate) fn policy_profile_overrides(
    profile: &NpmFirewallPolicyProfile,
) -> std::collections::BTreeMap<String, String> {
    let default = NpmFirewallPolicyProfile::default();
    POLICY_KEYS
        .iter()
        .filter_map(|key| {
            let action = policy_action(profile, key)?;
            (Some(action) != policy_action(&default, key))
                .then(|| ((*key).to_string(), action.as_str().to_string()))
        })
        .collect()
}

/// Rebuilds a profile from [`policy_profile_overrides`]. Keys a newer LPM
/// wrote and actions it can't read keep their default, so an unreadable
/// entry never allows more than the default profile does.
pub(crate) fn policy_profile_from_overrides(
    overrides: &std::collections::BTreeMap<String, String>,
) -> NpmFirewallPolicyProfile {
    let mut profile = NpmFirewallPolicyProfile::default();
    for (key, raw) in overrides {
        if let (Some(slot), Some(action)) = (
            policy_action_mut(&mut profile, key),
            NpmFirewallPolicyAction::parse(raw),
        ) {
            *slot = action;
        }
    }
    profile
}

/// Every policy group with its action, for status views.
pub(crate) fn policy_profile_entries(
    profile: &NpmFirewallPolicyProfile,
) -> std::collections::BTreeMap<String, String> {
    POLICY_KEYS
        .iter()
        .filter_map(|key| {
            policy_action(profile, key)
                .map(|action| ((*key).to_string(), action.as_str().to_string()))
        })
        .collect()
}

/// A policy group the requested firewall settings handle more leniently than
/// the approved ones do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoosenedFirewallPolicy {
    pub(crate) key: &'static str,
    pub(crate) requested: NpmFirewallPolicyAction,
    pub(crate) approved: NpmFirewallPolicyAction,
}

/// The policy groups where the requested mode and profile stop or report
/// less than the approved mode and profile. With the firewall off nothing is
/// checked, and monitor mode reports a block without stopping the command,
/// so a profile only weakens what the approved mode actually enforced.
pub(crate) fn loosened_firewall_policies(
    requested_mode: NpmFirewallMode,
    requested: &NpmFirewallPolicyProfile,
    approved_mode: NpmFirewallMode,
    approved: &NpmFirewallPolicyProfile,
) -> Vec<LoosenedFirewallPolicy> {
    POLICY_KEYS
        .iter()
        .filter_map(|key| {
            let requested_action = policy_action(requested, key)?;
            let approved_action = policy_action(approved, key)?;
            policy_action_loosens(
                requested_mode,
                requested_action,
                approved_mode,
                approved_action,
            )
            .then_some(LoosenedFirewallPolicy {
                key,
                requested: requested_action,
                approved: approved_action,
            })
        })
        .collect()
}

/// Whether `requested_action` under `requested_mode` stops or reports less
/// than `approved_action` under `approved_mode`.
pub(crate) fn policy_action_loosens(
    requested_mode: NpmFirewallMode,
    requested_action: NpmFirewallPolicyAction,
    approved_mode: NpmFirewallMode,
    approved_action: NpmFirewallPolicyAction,
) -> bool {
    enforced_rank(requested_mode, requested_action) < enforced_rank(approved_mode, approved_action)
}

fn enforced_rank(mode: NpmFirewallMode, action: NpmFirewallPolicyAction) -> u8 {
    let action_rank = match action {
        NpmFirewallPolicyAction::Allow => 0,
        NpmFirewallPolicyAction::Warn => 1,
        NpmFirewallPolicyAction::Block => 2,
    };
    match mode {
        NpmFirewallMode::Off => 0,
        NpmFirewallMode::Monitor => action_rank.min(1),
        NpmFirewallMode::Enforce => action_rank,
    }
}

/// The modes a requested profile and the approved one are compared at. A
/// managed profile binds whenever the firewall runs, so both sides use the
/// requested mode. When the mode itself loosens, that is the mode check's to
/// report, so both sides use the approved mode. Otherwise each side uses its
/// own mode.
pub(crate) fn policy_comparison_modes(
    requested_mode: NpmFirewallMode,
    approved_mode: NpmFirewallMode,
    policies_managed: bool,
) -> (NpmFirewallMode, NpmFirewallMode) {
    if policies_managed {
        (requested_mode, requested_mode)
    } else if requested_mode.loosens(approved_mode) {
        (approved_mode, approved_mode)
    } else {
        (requested_mode, approved_mode)
    }
}

/// The profile a command runs with: the `config.toml` table when there is
/// one, else the default raised to the approved profile wherever that is
/// stricter. An approved looser action is a permission the table has to ask
/// for; a managed profile applies as written.
pub(crate) fn runtime_policy_profile(
    request: Option<NpmFirewallPolicyProfile>,
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
) -> NpmFirewallPolicyProfile {
    request.unwrap_or_else(|| PolicyTableBase::of_posture(effective).tableless)
}

fn tableless_policy_profile(
    approved: NpmFirewallPolicyProfile,
    managed: bool,
) -> NpmFirewallPolicyProfile {
    if managed {
        approved
    } else {
        stricter_policy_profile(&NpmFirewallPolicyProfile::default(), &approved)
    }
}

/// The profile that is at least as strict as both `current` and `proposed` in
/// every group, so adopting it never loosens anything.
pub(crate) fn stricter_policy_profile(
    current: &NpmFirewallPolicyProfile,
    proposed: &NpmFirewallPolicyProfile,
) -> NpmFirewallPolicyProfile {
    let mut stricter = *current;
    for key in POLICY_KEYS {
        if let (Some(slot), Some(proposed_action)) = (
            policy_action_mut(&mut stricter, key),
            policy_action(proposed, key),
        ) && enforced_rank(NpmFirewallMode::Enforce, proposed_action)
            > enforced_rank(NpmFirewallMode::Enforce, *slot)
        {
            *slot = proposed_action;
        }
    }
    stricter
}

/// The profile installs enforce: what they run, with each group they would
/// refuse as looser than the approved profile held at its approved action.
pub(crate) fn enforced_policy_profile(
    global: &GlobalConfig,
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
) -> Result<NpmFirewallPolicyProfile, LpmError> {
    let mut profile = runtime_policy_profile(runtime_policy_request(global, effective)?, effective);
    let approved = effective.posture.firewall_policy_profile();
    let approved_mode = effective.posture.firewall_mode();
    let requested_mode =
        runtime_request_mode(global)?.map_or(approved_mode, |request| request.mode());
    let (requested_mode, approved_mode) = policy_comparison_modes(
        requested_mode,
        approved_mode,
        matches!(
            effective.sources.firewall_policies,
            crate::security_approval::PostureSourceKind::ManagedPolicy
        ),
    );
    for loosened in loosened_firewall_policies(requested_mode, &profile, approved_mode, &approved) {
        if let Some(slot) = policy_action_mut(&mut profile, loosened.key) {
            *slot = loosened.approved;
        }
    }
    Ok(profile)
}

pub(crate) fn describe_loosened_policies(loosened: &[LoosenedFirewallPolicy]) -> String {
    let mut text = String::with_capacity(loosened.len() * 48);
    for (index, entry) in loosened.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(entry.key);
        text.push_str(" = ");
        text.push_str(entry.requested.as_str());
        text.push_str(" (approved: ");
        text.push_str(entry.approved.as_str());
        text.push(')');
    }
    text
}

pub(crate) fn env_mode() -> Result<Option<NpmFirewallMode>, LpmError> {
    if let Some(mode) = parse_env_mode(ENV_NPM_FIREWALL)? {
        return Ok(Some(mode));
    }
    parse_env_mode(ENV_EXPERIMENT_NPM_FIREWALL)
}

fn parse_env_mode(key: &str) -> Result<Option<NpmFirewallMode>, LpmError> {
    match std::env::var(key) {
        Ok(raw) => NpmFirewallMode::parse(&raw).map(Some).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{key}` value `{raw}`; must be one of: off | monitor | enforce (`report` is accepted as a legacy alias)"
            ))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(LpmError::Registry(format!(
            "`{key}` must be valid UTF-8: off | monitor | enforce"
        ))),
    }
}

pub(crate) fn runtime_request_mode(
    global: &GlobalConfig,
) -> Result<Option<NpmFirewallModeRequest>, LpmError> {
    let config = config_mode(global)?;
    let env = env_mode()?;
    let request = match (config, env) {
        (Some(config), Some(env)) => Some(NpmFirewallModeRequest {
            mode: config.stricter(env),
            source: NpmFirewallModeRequestSource::ConfigAndEnv,
        }),
        (Some(config), None) => Some(NpmFirewallModeRequest {
            mode: config,
            source: NpmFirewallModeRequestSource::Config,
        }),
        (None, Some(env)) => Some(NpmFirewallModeRequest {
            mode: env,
            source: NpmFirewallModeRequestSource::Env,
        }),
        (None, None) => None,
    };
    Ok(request)
}

/// The firewall mode and policy profile a command runs with, after checking
/// that neither is weaker than the approved posture allows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeFirewall {
    pub(crate) mode: NpmFirewallMode,
    pub(crate) policy_profile: NpmFirewallPolicyProfile,
}

pub(crate) fn resolve_runtime_firewall(
    global: &GlobalConfig,
    project_dir: &Path,
    json_output: bool,
) -> Result<RuntimeFirewall, LpmError> {
    let effective = crate::security_approval::load_effective_authorized_posture()?;
    let mode_request = runtime_request_mode(global)?;
    let policy_request = runtime_policy_request(global, &effective)?;
    crate::security_approval::ensure_runtime_npm_firewall_config_authorized_with_effective(
        &effective,
        project_dir,
        json_output,
        mode_request,
        policy_request.as_ref(),
    )?;
    Ok(RuntimeFirewall {
        mode: mode_request.map_or_else(|| effective.posture.firewall_mode(), |r| r.mode()),
        policy_profile: runtime_policy_profile(policy_request, &effective),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_firewall_mode_parses_product_values_and_aliases() {
        assert_eq!(NpmFirewallMode::parse("off"), Some(NpmFirewallMode::Off));
        assert_eq!(
            NpmFirewallMode::parse(" Monitor "),
            Some(NpmFirewallMode::Monitor)
        );
        assert_eq!(
            NpmFirewallMode::parse(" Report "),
            Some(NpmFirewallMode::Monitor)
        );
        assert_eq!(
            NpmFirewallMode::parse("TRUE"),
            Some(NpmFirewallMode::Enforce)
        );
    }

    #[test]
    fn npm_firewall_mode_rejects_unknown_values() {
        assert_eq!(NpmFirewallMode::parse("maybe"), None);
    }

    #[test]
    fn npm_firewall_mode_can_only_tighten_when_resolving_env_override() {
        assert_eq!(
            NpmFirewallMode::Enforce.stricter(NpmFirewallMode::Off),
            NpmFirewallMode::Enforce
        );
        assert_eq!(
            NpmFirewallMode::Monitor.stricter(NpmFirewallMode::Enforce),
            NpmFirewallMode::Enforce
        );
    }

    #[test]
    fn npm_firewall_config_policy_profile_uses_defaults_without_policy_table() {
        let global = GlobalConfig::empty();

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(
            profile.trusted_public_malicious_advisories,
            NpmFirewallPolicyAction::Block
        );
        assert_eq!(
            profile.lpm_ai_agent_control_surface,
            NpmFirewallPolicyAction::Warn
        );
        assert_eq!(
            profile.critical_vulnerability,
            NpmFirewallPolicyAction::Warn
        );
        assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Warn);
        assert_eq!(profile.lpm_ai_telemetry, NpmFirewallPolicyAction::Warn);
        assert_eq!(
            profile.lpm_ai_dependency_script_policy,
            NpmFirewallPolicyAction::Block
        );
    }

    fn global_with_policies(entries: &[(&str, &str)]) -> GlobalConfig {
        let policies: toml::Table = entries
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    toml::Value::String((*value).to_string()),
                )
            })
            .collect();
        let mut npm = toml::Table::new();
        npm.insert(
            FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
            toml::Value::Table(policies),
        );
        let mut firewall = toml::Table::new();
        firewall.insert(
            FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
        let mut table = toml::Table::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        GlobalConfig::from_table(table)
    }

    #[test]
    fn npm_firewall_config_policy_profile_parses_explicit_telemetry_actions() {
        for (raw, expected) in [
            ("allow", NpmFirewallPolicyAction::Allow),
            ("warn", NpmFirewallPolicyAction::Warn),
            ("block", NpmFirewallPolicyAction::Block),
        ] {
            let global = global_with_policies(&[(LPM_AI_TELEMETRY_POLICY_KEY, raw)]);

            let profile = config_policy_profile(&global).unwrap();

            assert_eq!(
                profile.lpm_ai_telemetry, expected,
                "lpm_ai_telemetry = {raw}"
            );
            assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Warn);
        }
    }

    #[test]
    fn npm_firewall_config_telemetry_inherits_ai_suspicious_action_when_unset() {
        let global = global_with_policies(&[(LPM_AI_SUSPICIOUS_POLICY_KEY, "block")]);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(profile.lpm_ai_telemetry, NpmFirewallPolicyAction::Block);
    }

    #[test]
    fn npm_firewall_config_telemetry_inherits_legacy_static_only_suspicious_action() {
        let global = global_with_policies(&[(LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY, "allow")]);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(profile.lpm_ai_telemetry, NpmFirewallPolicyAction::Allow);
    }

    #[test]
    fn npm_firewall_config_explicit_telemetry_action_wins_over_ai_suspicious() {
        let global = global_with_policies(&[
            (LPM_AI_SUSPICIOUS_POLICY_KEY, "block"),
            (LPM_AI_TELEMETRY_POLICY_KEY, "allow"),
        ]);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(profile.lpm_ai_telemetry, NpmFirewallPolicyAction::Allow);
        assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Block);
    }

    #[test]
    fn npm_firewall_config_rejects_invalid_telemetry_action() {
        let global = global_with_policies(&[(LPM_AI_TELEMETRY_POLICY_KEY, "deny")]);

        let err = config_policy_profile(&global).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid `[firewall.npm.policies].lpm_ai_telemetry` value `deny`"),
            "{err}"
        );
    }

    #[test]
    fn npm_firewall_config_telemetry_origin_reports_config_inherited_or_default() {
        let explicit = toml::Table::from_iter([(
            LPM_AI_TELEMETRY_POLICY_KEY.to_string(),
            toml::Value::String("warn".to_string()),
        )]);
        let inherited = toml::Table::from_iter([(
            LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("warn".to_string()),
        )]);
        let unrelated = toml::Table::from_iter([(
            CRITICAL_VULNERABILITY_POLICY_KEY.to_string(),
            toml::Value::String("block".to_string()),
        )]);

        assert_eq!(
            telemetry_policy_origin(Some(&explicit)),
            TelemetryPolicyOrigin::Config
        );
        assert_eq!(
            telemetry_policy_origin(Some(&inherited)),
            TelemetryPolicyOrigin::InheritedFromAiSuspicious
        );
        assert_eq!(
            telemetry_policy_origin(Some(&unrelated)),
            TelemetryPolicyOrigin::Default
        );
        assert_eq!(
            telemetry_policy_origin(None),
            TelemetryPolicyOrigin::Default
        );
    }

    #[test]
    fn npm_firewall_config_policy_profile_parses_dependency_script_policy_actions() {
        for (raw, expected) in [
            ("allow", NpmFirewallPolicyAction::Allow),
            ("warn", NpmFirewallPolicyAction::Warn),
            ("block", NpmFirewallPolicyAction::Block),
        ] {
            let global = global_with_policies(&[(LPM_AI_DEPENDENCY_SCRIPT_POLICY_KEY, raw)]);

            let profile = config_policy_profile(&global).unwrap();

            assert_eq!(
                profile.lpm_ai_dependency_script_policy, expected,
                "lpm_ai_dependency_script_policy = {raw}"
            );
        }
    }

    #[test]
    fn npm_firewall_config_dependency_script_policy_does_not_inherit_confirmed_malware_action() {
        let global = global_with_policies(&[(LPM_AI_CONFIRMED_MALWARE_POLICY_KEY, "warn")]);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(
            profile.lpm_ai_dependency_script_policy,
            NpmFirewallPolicyAction::Block
        );
    }

    #[test]
    fn npm_firewall_config_policy_profile_parses_custom_actions() {
        let mut policies = toml::map::Map::new();
        policies.insert(
            LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY.to_string(),
            toml::Value::String("warn".to_string()),
        );
        policies.insert(
            TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY.to_string(),
            toml::Value::String("block".to_string()),
        );
        policies.insert(
            LPM_AI_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("allow".to_string()),
        );
        let mut npm = toml::map::Map::new();
        npm.insert(
            FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
            toml::Value::Table(policies),
        );
        let mut firewall = toml::map::Map::new();
        firewall.insert(
            FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
        let mut table = toml::map::Map::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        let global = GlobalConfig::from_table(table);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(
            profile.lpm_ai_agent_control_surface,
            NpmFirewallPolicyAction::Warn
        );
        assert_eq!(
            profile.trusted_public_malicious_advisories,
            NpmFirewallPolicyAction::Block
        );
        assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Allow);
    }

    #[test]
    fn npm_firewall_config_policy_profile_accepts_legacy_static_only_suspicious_key() {
        let mut policies = toml::map::Map::new();
        policies.insert(
            LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("allow".to_string()),
        );
        let mut npm = toml::map::Map::new();
        npm.insert(
            FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
            toml::Value::Table(policies),
        );
        let mut firewall = toml::map::Map::new();
        firewall.insert(
            FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
        let mut table = toml::map::Map::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        let global = GlobalConfig::from_table(table);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Allow);
    }

    #[test]
    fn npm_firewall_config_policy_profile_prefers_canonical_ai_suspicious_key() {
        let mut policies = toml::map::Map::new();
        policies.insert(
            LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("allow".to_string()),
        );
        policies.insert(
            LPM_AI_SUSPICIOUS_POLICY_KEY.to_string(),
            toml::Value::String("warn".to_string()),
        );
        let mut npm = toml::map::Map::new();
        npm.insert(
            FIREWALL_NPM_POLICIES_CONFIG_SECTION.to_string(),
            toml::Value::Table(policies),
        );
        let mut firewall = toml::map::Map::new();
        firewall.insert(
            FIREWALL_NPM_CONFIG_SECTION.to_string(),
            toml::Value::Table(npm),
        );
        let mut table = toml::map::Map::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        let global = GlobalConfig::from_table(table);

        let profile = config_policy_profile(&global).unwrap();

        assert_eq!(profile.lpm_ai_suspicious, NpmFirewallPolicyAction::Warn);
    }

    #[test]
    fn npm_firewall_env_rejects_invalid_product_value() {
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_NPM_FIREWALL", Some(std::ffi::OsString::from("enfore"))),
            ("LPM_EXPERIMENT_NPM_FIREWALL", None),
        ]);

        let err = env_mode().unwrap_err();

        assert!(err.to_string().contains("invalid `LPM_NPM_FIREWALL`"));
    }

    #[test]
    fn npm_firewall_env_rejects_invalid_legacy_value() {
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_NPM_FIREWALL", None),
            (
                "LPM_EXPERIMENT_NPM_FIREWALL",
                Some(std::ffi::OsString::from("enfore")),
            ),
        ]);

        let err = env_mode().unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid `LPM_EXPERIMENT_NPM_FIREWALL`")
        );
    }

    #[test]
    fn npm_firewall_config_rejects_unknown_mode() {
        let mut firewall = toml::map::Map::new();
        firewall.insert(
            FIREWALL_CONFIG_MODE_KEY.to_string(),
            toml::Value::String("enfore".to_string()),
        );
        let mut table = toml::map::Map::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::Table(firewall),
        );
        let global = GlobalConfig::from_table(table);

        let err = config_mode(&global).unwrap_err();

        assert!(err.to_string().contains("invalid `[firewall].mode`"));
    }

    #[test]
    fn npm_firewall_config_rejects_non_table_section() {
        let mut table = toml::map::Map::new();
        table.insert(
            FIREWALL_CONFIG_SECTION.to_string(),
            toml::Value::String("enforce".to_string()),
        );
        let global = GlobalConfig::from_table(table);

        let err = config_mode(&global).unwrap_err();

        assert!(
            err.to_string()
                .contains("`[firewall]` must be a TOML table")
        );
    }

    fn profile_with(key: &str, action: NpmFirewallPolicyAction) -> NpmFirewallPolicyProfile {
        let mut profile = NpmFirewallPolicyProfile::default();
        *policy_action_mut(&mut profile, key).unwrap() = action;
        profile
    }

    #[test]
    fn loosened_policies_name_groups_the_request_handles_more_leniently() {
        let requested = profile_with(
            LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            NpmFirewallPolicyAction::Allow,
        );

        let loosened = loosened_firewall_policies(
            NpmFirewallMode::Enforce,
            &requested,
            NpmFirewallMode::Enforce,
            &NpmFirewallPolicyProfile::default(),
        );

        assert_eq!(
            loosened,
            vec![LoosenedFirewallPolicy {
                key: LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
                requested: NpmFirewallPolicyAction::Allow,
                approved: NpmFirewallPolicyAction::Block,
            }]
        );
    }

    #[test]
    fn loosened_policies_ignore_stricter_groups() {
        let requested = profile_with(LPM_AI_TELEMETRY_POLICY_KEY, NpmFirewallPolicyAction::Block);

        assert!(
            loosened_firewall_policies(
                NpmFirewallMode::Enforce,
                &requested,
                NpmFirewallMode::Enforce,
                &NpmFirewallPolicyProfile::default(),
            )
            .is_empty()
        );
    }

    #[test]
    fn no_policy_loosens_an_approved_firewall_that_is_off() {
        let requested = profile_with(
            LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            NpmFirewallPolicyAction::Allow,
        );

        assert!(
            loosened_firewall_policies(
                NpmFirewallMode::Enforce,
                &requested,
                NpmFirewallMode::Off,
                &NpmFirewallPolicyProfile::default(),
            )
            .is_empty()
        );
    }

    #[test]
    fn allowing_a_group_monitor_mode_reports_is_a_loosening() {
        let requested = profile_with(
            LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            NpmFirewallPolicyAction::Allow,
        );

        let loosened = loosened_firewall_policies(
            NpmFirewallMode::Monitor,
            &requested,
            NpmFirewallMode::Monitor,
            &NpmFirewallPolicyProfile::default(),
        );

        assert_eq!(loosened.len(), 1);
        assert_eq!(loosened[0].key, LPM_AI_CONFIRMED_MALWARE_POLICY_KEY);
    }

    #[test]
    fn warn_and_block_are_equivalent_in_monitor_mode() {
        let requested = profile_with(
            LPM_AI_CONFIRMED_MALWARE_POLICY_KEY,
            NpmFirewallPolicyAction::Warn,
        );

        assert!(
            loosened_firewall_policies(
                NpmFirewallMode::Monitor,
                &requested,
                NpmFirewallMode::Monitor,
                &NpmFirewallPolicyProfile::default(),
            )
            .is_empty()
        );
    }

    #[test]
    fn policy_overrides_round_trip_and_omit_default_actions() {
        let profile = profile_with(
            LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY,
            NpmFirewallPolicyAction::Block,
        );

        let overrides = policy_profile_overrides(&profile);

        assert_eq!(
            overrides,
            std::collections::BTreeMap::from([(
                LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY.to_string(),
                "block".to_string()
            )])
        );
        assert_eq!(policy_profile_from_overrides(&overrides), profile);
        assert!(policy_profile_overrides(&NpmFirewallPolicyProfile::default()).is_empty());
    }

    #[test]
    fn unreadable_policy_overrides_keep_the_default_action() {
        let overrides = std::collections::BTreeMap::from([
            ("lpm_ai_future_group".to_string(), "allow".to_string()),
            (
                LPM_AI_CONFIRMED_MALWARE_POLICY_KEY.to_string(),
                "permit".to_string(),
            ),
        ]);

        assert_eq!(
            policy_profile_from_overrides(&overrides),
            NpmFirewallPolicyProfile::default()
        );
    }

    #[test]
    fn without_a_table_an_approved_looser_action_waits_for_a_request() {
        let approved = NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: NpmFirewallPolicyAction::Allow,
            lpm_ai_agent_control_surface: NpmFirewallPolicyAction::Block,
            ..NpmFirewallPolicyProfile::default()
        };

        let runtime = tableless_policy_profile(approved, false);

        assert_eq!(
            runtime.lpm_ai_confirmed_malware,
            NpmFirewallPolicyAction::Block
        );
        assert_eq!(
            runtime.lpm_ai_agent_control_surface,
            NpmFirewallPolicyAction::Block
        );
        assert_eq!(tableless_policy_profile(approved, true), approved);
    }

    #[test]
    fn telemetry_follows_suspicious_but_not_below_an_approved_stricter_action() {
        let global = global_with_policies(&[(LPM_AI_SUSPICIOUS_POLICY_KEY, "allow")]);
        let strict_base = NpmFirewallPolicyProfile {
            lpm_ai_telemetry: NpmFirewallPolicyAction::Block,
            ..NpmFirewallPolicyProfile::default()
        };

        let inherited = config_policy_request(&global).unwrap().unwrap();
        let held = config_policy_request_over(
            &global,
            PolicyTableBase::of(strict_base, NpmFirewallMode::Enforce, false),
        )
        .unwrap()
        .unwrap();

        assert_eq!(inherited.lpm_ai_telemetry, NpmFirewallPolicyAction::Allow);
        assert_eq!(held.lpm_ai_telemetry, NpmFirewallPolicyAction::Block);
        assert_eq!(held.lpm_ai_suspicious, NpmFirewallPolicyAction::Allow);
    }

    #[test]
    fn telemetry_follows_suspicious_but_never_below_any_approved_action() {
        let global = global_with_policies(&[(LPM_AI_SUSPICIOUS_POLICY_KEY, "allow")]);
        let approved_at = |telemetry| {
            let approved = NpmFirewallPolicyProfile {
                lpm_ai_suspicious: NpmFirewallPolicyAction::Allow,
                lpm_ai_telemetry: telemetry,
                ..NpmFirewallPolicyProfile::default()
            };
            config_policy_request_over(
                &global,
                PolicyTableBase::of(approved, NpmFirewallMode::Enforce, false),
            )
            .unwrap()
            .unwrap()
            .lpm_ai_telemetry
        };

        assert_eq!(
            approved_at(NpmFirewallPolicyAction::Warn),
            NpmFirewallPolicyAction::Warn
        );
        assert_eq!(
            approved_at(NpmFirewallPolicyAction::Allow),
            NpmFirewallPolicyAction::Allow
        );
    }

    #[test]
    fn telemetry_follows_suspicious_freely_where_the_approved_firewall_is_off() {
        let global = global_with_policies(&[(LPM_AI_SUSPICIOUS_POLICY_KEY, "allow")]);
        let base = PolicyTableBase::of(
            NpmFirewallPolicyProfile::default(),
            NpmFirewallMode::Off,
            false,
        );

        let request = config_policy_request_over(&global, base).unwrap().unwrap();

        assert_eq!(request.lpm_ai_telemetry, NpmFirewallPolicyAction::Allow);
    }

    #[test]
    fn an_empty_policy_table_requests_nothing() {
        let global = global_with_policies(&[]);

        assert_eq!(config_policy_request(&global).unwrap(), None);
    }

    #[test]
    fn a_partial_table_requests_only_the_groups_it_names() {
        let base = NpmFirewallPolicyProfile {
            lpm_ai_agent_control_surface: NpmFirewallPolicyAction::Block,
            ..NpmFirewallPolicyProfile::default()
        };
        let global = global_with_policies(&[(LPM_AI_SUSPICIOUS_POLICY_KEY, "block")]);

        let request = config_policy_request_over(
            &global,
            PolicyTableBase::of(base, NpmFirewallMode::Enforce, false),
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            request.lpm_ai_agent_control_surface,
            NpmFirewallPolicyAction::Block
        );
        assert_eq!(request.lpm_ai_suspicious, NpmFirewallPolicyAction::Block);
        assert_eq!(request.lpm_ai_telemetry, NpmFirewallPolicyAction::Block);
    }

    #[test]
    fn config_policy_request_is_absent_without_a_policy_table() {
        assert_eq!(config_policy_request(&GlobalConfig::empty()).unwrap(), None);
        let global = global_with_policies(&[(LPM_AI_TELEMETRY_POLICY_KEY, "block")]);
        assert_eq!(
            config_policy_request(&global)
                .unwrap()
                .unwrap()
                .lpm_ai_telemetry,
            NpmFirewallPolicyAction::Block
        );
    }
}
