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
pub(crate) const LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY: &str = "lpm_ai_agent_control_surface";
pub(crate) const LPM_AI_SUSPICIOUS_POLICY_KEY: &str = "lpm_ai_suspicious";
pub(crate) const CRITICAL_VULNERABILITY_POLICY_KEY: &str = "critical_vulnerability";
pub(crate) const LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY: &str = "static_only_suspicious";

const ENV_NPM_FIREWALL: &str = "LPM_NPM_FIREWALL";
const ENV_EXPERIMENT_NPM_FIREWALL: &str = "LPM_EXPERIMENT_NPM_FIREWALL";

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

    pub(crate) fn disables_tarball_prefetch(self) -> bool {
        self.is_enabled()
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
    let Some(section) = global.get_value(FIREWALL_CONFIG_SECTION) else {
        return Ok(NpmFirewallPolicyProfile::default());
    };
    let table = section.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[{FIREWALL_CONFIG_SECTION}]` must be a TOML table"
        ))
    })?;
    let Some(npm) = table.get(FIREWALL_NPM_CONFIG_SECTION) else {
        return Ok(NpmFirewallPolicyProfile::default());
    };
    let npm_table = npm
        .as_table()
        .ok_or_else(|| LpmError::Registry("`[firewall.npm]` must be a TOML table".to_string()))?;
    let Some(policies) = npm_table.get(FIREWALL_NPM_POLICIES_CONFIG_SECTION) else {
        return Ok(NpmFirewallPolicyProfile::default());
    };
    let policies = policies.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "`{FIREWALL_NPM_POLICIES_CONFIG_PATH}` must be a TOML table"
        ))
    })?;
    let mut profile = NpmFirewallPolicyProfile::default();
    let has_canonical_ai_suspicious = policies.contains_key(LPM_AI_SUSPICIOUS_POLICY_KEY);
    for (key, value) in policies {
        if key == LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY && has_canonical_ai_suspicious {
            continue;
        }
        let raw = value.as_str().ok_or_else(|| {
            LpmError::Registry(format!(
                "`{FIREWALL_NPM_POLICIES_CONFIG_PATH}.{key}` must be a string: allow | warn | block"
            ))
        })?;
        let action = NpmFirewallPolicyAction::parse(raw).ok_or_else(|| {
            LpmError::Registry(format!(
                "invalid `{FIREWALL_NPM_POLICIES_CONFIG_PATH}.{key}` value `{raw}`; must be one of: allow | warn | block"
            ))
        })?;
        match key.as_str() {
            TRUSTED_PUBLIC_MALICIOUS_ADVISORIES_POLICY_KEY => {
                profile.trusted_public_malicious_advisories = action;
            }
            LPM_AI_CONFIRMED_MALWARE_POLICY_KEY => {
                profile.lpm_ai_confirmed_malware = action;
            }
            LPM_AI_AGENT_CONTROL_SURFACE_POLICY_KEY => {
                profile.lpm_ai_agent_control_surface = action;
            }
            LPM_AI_SUSPICIOUS_POLICY_KEY => {
                profile.lpm_ai_suspicious = action;
            }
            CRITICAL_VULNERABILITY_POLICY_KEY => {
                profile.critical_vulnerability = action;
            }
            LEGACY_STATIC_ONLY_SUSPICIOUS_POLICY_KEY if !has_canonical_ai_suspicious => {
                profile.lpm_ai_suspicious = action;
            }
            _ => {
                return Err(LpmError::Registry(format!(
                    "unknown `{FIREWALL_NPM_POLICIES_CONFIG_PATH}` key `{key}`"
                )));
            }
        }
    }
    Ok(profile)
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

pub(crate) fn resolve_runtime_mode(
    global: &GlobalConfig,
    project_dir: &Path,
    json_output: bool,
) -> Result<NpmFirewallMode, LpmError> {
    let effective = crate::security_approval::load_effective_authorized_posture()?;
    let Some(request) = runtime_request_mode(global)? else {
        return Ok(effective.posture.firewall_mode());
    };
    crate::security_approval::ensure_runtime_npm_firewall_config_authorized_with_effective(
        &effective,
        project_dir,
        json_output,
        request,
    )?;
    Ok(request.mode())
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
}
