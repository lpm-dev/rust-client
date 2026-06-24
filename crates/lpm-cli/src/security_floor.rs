//! Shared force-security-floor guard helpers.
//!
//! Phase 1 intentionally extends the existing `force-security-floor`
//! kill-switch beyond `script-policy` while preserving its "soft floor"
//! posture for command execution:
//!
//! - CLI / project loosening requests are suppressed to the current
//!   machine floor and surfaced as warnings.
//! - Global config writes that would lower the current machine floor are
//!   refused while the flag is enabled.
//! - JSON-mode callers can inspect the suppression list via the
//!   `security_posture` envelope rather than scraping stderr.

use crate::commands::config::GlobalConfig;
use crate::output;
use crate::precedence::PurePolicyKnob;
use crate::provenance_fetch::EnforceMode;
use crate::release_age_config::{DEFAULT_MIN_RELEASE_AGE_SECS, ReleaseAgePolicy};
use crate::sandbox_config::ResolvedSandboxMode;
use crate::script_policy_config::ScriptPolicy;
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedControl {
    CooldownWindow,
    ProvenanceDriftWaiver,
    UnverifiedProvenance,
    SandboxMode,
    SandboxAllowDegraded,
    ScriptPolicy,
    #[allow(dead_code)]
    SigstoreVerify,
    #[allow(dead_code)]
    FirewallMode,
}

impl GuardedControl {
    fn as_str(self) -> &'static str {
        match self {
            Self::CooldownWindow => "cooldown_window",
            Self::ProvenanceDriftWaiver => "provenance_drift_waiver",
            Self::UnverifiedProvenance => "unverified_provenance",
            Self::SandboxMode => "sandbox_mode",
            Self::SandboxAllowDegraded => "sandbox_allow_degraded",
            Self::ScriptPolicy => "script_policy",
            Self::SigstoreVerify => "sigstore_verify",
            Self::FirewallMode => "firewall_mode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionSource {
    Cli,
    Project,
}

impl SuppressionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressionRecord {
    pub control: GuardedControl,
    pub source: SuppressionSource,
    pub requested: String,
    pub enforced: String,
}

impl SuppressionRecord {
    pub fn new(
        control: GuardedControl,
        source: SuppressionSource,
        requested: impl Into<String>,
        enforced: impl Into<String>,
    ) -> Self {
        Self {
            control,
            source,
            requested: requested.into(),
            enforced: enforced.into(),
        }
    }

    fn warning_line(&self) -> String {
        format!(
            "warning: {} {} request ignored — `force-security-floor = true` keeps `{}` at `{}` (requested `{}`).",
            self.source.as_str(),
            self.control.as_str(),
            self.control.as_str(),
            self.enforced,
            self.requested,
        )
    }
}

#[derive(Default)]
struct SuppressionState {
    seen: HashSet<(GuardedControl, SuppressionSource, String, String)>,
    records: Vec<SuppressionRecord>,
}

fn suppression_state() -> &'static Mutex<SuppressionState> {
    static STATE: OnceLock<Mutex<SuppressionState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(SuppressionState::default()))
}

pub fn record_suppression(record: SuppressionRecord, json_output: bool) {
    let key = (
        record.control,
        record.source,
        record.requested.clone(),
        record.enforced.clone(),
    );
    let mut state = suppression_state()
        .lock()
        .expect("security-floor suppression state mutex poisoned");
    if state.seen.insert(key) {
        if !json_output {
            output::warn(&record.warning_line());
        }
        state.records.push(record);
    }
}

#[cfg(test)]
pub fn recorded_suppressions() -> Vec<SuppressionRecord> {
    suppression_state()
        .lock()
        .expect("security-floor suppression state mutex poisoned")
        .records
        .clone()
}

pub fn clear_recorded_suppressions() {
    let mut state = suppression_state()
        .lock()
        .expect("security-floor suppression state mutex poisoned");
    state.records.clear();
    state.seen.clear();
}

pub fn take_recorded_suppressions() -> Vec<SuppressionRecord> {
    let mut state = suppression_state()
        .lock()
        .expect("security-floor suppression state mutex poisoned");
    let records = std::mem::take(&mut state.records);
    state.seen.clear();
    records
}

pub fn attach_security_posture(json: &mut serde_json::Value, force_security_floor: bool) {
    let suppressions = take_recorded_suppressions();
    if !force_security_floor && suppressions.is_empty() {
        return;
    }
    json["security_posture"] = serde_json::json!({
        "force_security_floor": force_security_floor,
        "suppressed_overrides": suppressions,
    });
}

#[cfg(test)]
pub fn clear_recorded_suppressions_for_tests() {
    clear_recorded_suppressions();
}

pub fn force_security_floor_enabled(global: &GlobalConfig) -> bool {
    global.get_bool("force-security-floor").unwrap_or(false)
}

pub fn current_release_age_floor_secs(global: &GlobalConfig) -> u64 {
    global
        .get_u64("minimum-release-age-secs")
        .unwrap_or(DEFAULT_MIN_RELEASE_AGE_SECS)
}

pub fn current_release_age_policy_floor(global: &GlobalConfig) -> ReleaseAgePolicy {
    global
        .get_str(crate::release_age_config::GLOBAL_POLICY_KEY)
        .and_then(|raw| ReleaseAgePolicy::parse("release-age-policy", raw).ok())
        .unwrap_or_default()
}

pub fn current_script_policy_floor(global: &GlobalConfig) -> ScriptPolicy {
    global
        .get_str("script-policy")
        .and_then(|raw| ScriptPolicy::parse(raw).ok())
        .unwrap_or_default()
}

pub fn current_sigstore_floor(global: &GlobalConfig) -> EnforceMode {
    let env_value = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    let (mode, _) =
        EnforceMode::resolve_from_chain(env_value.as_deref(), || global.get_sigstore_verify());
    mode
}

pub fn reject_looser_script_policy_write(
    global: &GlobalConfig,
    requested: ScriptPolicy,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_script_policy_floor(global);
    if requested.loosens(floor) {
        return Err(security_floor_write_error(
            "script-policy",
            requested.as_str(),
            floor.as_str(),
        ));
    }
    Ok(())
}

pub fn reject_looser_release_age_write(
    global: &GlobalConfig,
    requested_secs: u64,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_release_age_floor_secs(global);
    if requested_secs < floor {
        return Err(security_floor_write_error(
            "minimum-release-age-secs",
            requested_secs.to_string(),
            floor.to_string(),
        ));
    }
    Ok(())
}

pub fn reject_looser_release_age_policy_write(
    global: &GlobalConfig,
    requested: ReleaseAgePolicy,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_release_age_policy_floor(global);
    if requested.loosens(floor) {
        return Err(security_floor_write_error(
            crate::release_age_config::GLOBAL_POLICY_KEY,
            requested.as_str(),
            floor.as_str(),
        ));
    }
    Ok(())
}

pub fn reject_looser_sigstore_write(
    global: &GlobalConfig,
    requested: EnforceMode,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_sigstore_floor(global);
    if sigstore_loosens(requested, floor) {
        return Err(security_floor_write_error(
            "[sigstore].verify",
            sigstore_mode_name(requested),
            sigstore_mode_name(floor),
        ));
    }
    Ok(())
}

pub fn current_firewall_floor(
    global: &GlobalConfig,
) -> Result<crate::npm_firewall_config::NpmFirewallMode, LpmError> {
    Ok(crate::npm_firewall_config::config_mode(global)?.unwrap_or_default())
}

pub fn reject_looser_firewall_mode_write(
    global: &GlobalConfig,
    requested: crate::npm_firewall_config::NpmFirewallMode,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_firewall_floor(global)?;
    if requested.loosens(floor) {
        return Err(security_floor_write_error(
            crate::npm_firewall_config::FIREWALL_CONFIG_PATH,
            requested.as_str(),
            floor.as_str(),
        ));
    }
    Ok(())
}

pub fn current_sandbox_floor_mode(global: &GlobalConfig) -> ResolvedSandboxMode {
    global
        .get_table("sandbox")
        .and_then(|table| table.get("mode"))
        .and_then(|value| value.as_str())
        .and_then(ResolvedSandboxMode::parse_for_security_floor)
        .unwrap_or(ResolvedSandboxMode::Default)
}

pub fn reject_looser_sandbox_mode_write(
    global: &GlobalConfig,
    requested: ResolvedSandboxMode,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let floor = current_sandbox_floor_mode(global);
    if requested.loosens(floor) {
        return Err(security_floor_write_error(
            "[sandbox].mode",
            requested.as_str(),
            floor.as_str(),
        ));
    }
    Ok(())
}

pub fn security_floor_write_error(
    knob: &str,
    requested: impl AsRef<str>,
    enforced: impl AsRef<str>,
) -> LpmError {
    LpmError::SecurityFloor(format!(
        "setting `{knob}` to `{}` would loosen the current machine floor `{}` while \
         `force-security-floor = true` is active. Lower the floor intentionally in \
         ~/.lpm/config.toml before retrying.",
        requested.as_ref(),
        enforced.as_ref(),
    ))
}

pub fn sigstore_mode_name(mode: EnforceMode) -> &'static str {
    match mode {
        EnforceMode::Deny => "deny",
        EnforceMode::Warn => "warn",
        EnforceMode::Off => "off",
    }
}

pub fn sigstore_loosens(requested: EnforceMode, floor: EnforceMode) -> bool {
    sigstore_rank(requested) < sigstore_rank(floor)
}

fn sigstore_rank(mode: EnforceMode) -> u8 {
    match mode {
        EnforceMode::Off => 0,
        EnforceMode::Warn => 1,
        EnforceMode::Deny => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_cfg(script_policy: Option<&str>, min_age: Option<&str>, force: bool) -> GlobalConfig {
        let mut table = toml::map::Map::new();
        if let Some(policy) = script_policy {
            table.insert(
                "script-policy".to_string(),
                toml::Value::String(policy.to_string()),
            );
        }
        if let Some(age) = min_age {
            table.insert(
                "minimum-release-age-secs".to_string(),
                toml::Value::String(age.to_string()),
            );
        }
        table.insert(
            "force-security-floor".to_string(),
            toml::Value::Boolean(force),
        );
        GlobalConfig::from_table(table)
    }

    #[test]
    fn release_age_floor_defaults_to_builtin_when_absent() {
        let cfg = global_cfg(None, None, false);
        assert_eq!(
            current_release_age_floor_secs(&cfg),
            DEFAULT_MIN_RELEASE_AGE_SECS
        );
    }

    #[test]
    fn reject_looser_release_age_write_blocks_lower_value_when_force_enabled() {
        let cfg = global_cfg(None, Some("259200"), true);
        let err = reject_looser_release_age_write(&cfg, 0).unwrap_err();
        assert_eq!(err.error_code(), "security_floor");
        assert!(err.to_string().contains("minimum-release-age-secs"));
    }

    #[test]
    fn reject_looser_script_policy_write_allows_tightening() {
        let cfg = global_cfg(Some("allow"), None, true);
        reject_looser_script_policy_write(&cfg, ScriptPolicy::Triage).unwrap();
    }

    #[test]
    fn suppressions_are_deduped() {
        clear_recorded_suppressions_for_tests();
        let record = SuppressionRecord::new(
            GuardedControl::CooldownWindow,
            SuppressionSource::Cli,
            "0",
            "floor=86400",
        );
        record_suppression(record.clone(), true);
        record_suppression(record, true);
        let got = recorded_suppressions();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].control, GuardedControl::CooldownWindow);
        clear_recorded_suppressions_for_tests();
    }
}
