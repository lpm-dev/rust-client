//! Shared force-security-floor guard helpers.
//!
//! The `force-security-floor` kill-switch applies beyond `script-policy`
//! while preserving its "soft floor" posture for command execution:
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
use crate::security_approval::PersistentSecuritySetting;
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
    defer_warnings: bool,
    deferred_warnings: Vec<SuppressionRecord>,
}

fn suppression_state() -> &'static Mutex<SuppressionState> {
    static STATE: OnceLock<Mutex<SuppressionState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(SuppressionState::default()))
}

pub struct DeferredSuppressionWarningsGuard {
    committed: bool,
}

impl DeferredSuppressionWarningsGuard {
    pub fn flush(mut self, json_output: bool) {
        self.committed = true;
        let warnings = {
            let mut state = suppression_state()
                .lock()
                .expect("security-floor suppression state mutex poisoned");
            state.defer_warnings = false;
            std::mem::take(&mut state.deferred_warnings)
        };
        if !json_output {
            for record in warnings {
                output::warn(&record.warning_line());
            }
        }
    }
}

impl Drop for DeferredSuppressionWarningsGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut state = suppression_state()
            .lock()
            .expect("security-floor suppression state mutex poisoned");
        state.defer_warnings = false;
        let discarded = std::mem::take(&mut state.deferred_warnings);
        for record in discarded {
            let key = (
                record.control,
                record.source,
                record.requested.clone(),
                record.enforced.clone(),
            );
            state.seen.remove(&key);
            state.records.retain(|existing| existing != &record);
        }
    }
}

pub fn defer_suppression_warnings() -> DeferredSuppressionWarningsGuard {
    let mut state = suppression_state()
        .lock()
        .expect("security-floor suppression state mutex poisoned");
    state.defer_warnings = true;
    state.deferred_warnings.clear();
    DeferredSuppressionWarningsGuard { committed: false }
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
        if state.defer_warnings {
            state.deferred_warnings.push(record.clone());
        } else if !json_output {
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

/// Refuses saving `settings` together while `force-security-floor = true` is
/// active. Every setting is first put to a managed security policy, all of
/// them before any floor, so a floor refusal never stands in for the
/// policy's; then each is held to the machine floor `config.toml` sets.
pub fn reject_looser_writes(
    global: &GlobalConfig,
    settings: &[PersistentSecuritySetting],
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    crate::security_approval::reject_saves_a_managed_policy_holds(settings)?;
    settings
        .iter()
        .try_for_each(|setting| reject_below_floor(global, *setting))
}

/// Refuses `setting` when it loosens the machine floor `config.toml` sets.
fn reject_below_floor(
    global: &GlobalConfig,
    setting: PersistentSecuritySetting,
) -> Result<(), LpmError> {
    use PersistentSecuritySetting as Setting;
    let (knob, requested, floor) = match setting {
        Setting::ScriptPolicy(requested) => {
            let floor = current_script_policy_floor(global);
            if !requested.loosens(floor) {
                return Ok(());
            }
            (
                "script-policy",
                requested.as_str(),
                floor.as_str().to_owned(),
            )
        }
        Setting::MinimumReleaseAgeSecs(requested) => {
            let floor = current_release_age_floor_secs(global);
            if requested >= floor {
                return Ok(());
            }
            return Err(security_floor_write_error(
                "minimum-release-age-secs",
                requested.to_string(),
                floor.to_string(),
            ));
        }
        Setting::ReleaseAgePolicy(requested) => {
            let floor = current_release_age_policy_floor(global);
            if !requested.loosens(floor) {
                return Ok(());
            }
            (
                crate::release_age_config::GLOBAL_POLICY_KEY,
                requested.as_str(),
                floor.as_str().to_owned(),
            )
        }
        Setting::SandboxMode(requested) => {
            let floor = current_sandbox_floor_mode(global);
            if !requested.loosens(floor) {
                return Ok(());
            }
            (
                "[sandbox].mode",
                requested.as_str(),
                floor.as_str().to_owned(),
            )
        }
        Setting::SigstoreVerify(requested) => {
            let floor = current_sigstore_floor(global);
            if !sigstore_loosens(requested, floor) {
                return Ok(());
            }
            (
                "[sigstore].verify",
                sigstore_mode_name(requested),
                sigstore_mode_name(floor).to_owned(),
            )
        }
        Setting::TyposquatGuard(requested) => {
            let floor = global
                .get_typosquat_guard_mode()
                .unwrap_or(crate::commands::config::TyposquatGuardSelection::Default);
            if !requested.loosens(floor) {
                return Ok(());
            }
            (
                crate::commands::config::TYPOSQUAT_GUARD_KEY,
                requested.as_str(),
                floor.as_str().to_owned(),
            )
        }
        Setting::FirewallMode(requested) => {
            let floor = current_firewall_floor(global)?;
            if !requested.loosens(floor) {
                return Ok(());
            }
            (
                crate::npm_firewall_config::FIREWALL_CONFIG_PATH,
                requested.as_str(),
                floor.as_str().to_owned(),
            )
        }
        Setting::InstallTimeSourceAnalysis(requested) => {
            if requested
                || !crate::source_analysis_config::read_install_time_source_analysis(global)?
            {
                return Ok(());
            }
            (
                crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY,
                "false",
                "true".to_owned(),
            )
        }
    };
    Err(security_floor_write_error(knob, requested, floor))
}

pub fn reject_looser_typosquat_guard_write(
    global: &GlobalConfig,
    requested: crate::commands::config::TyposquatGuardSelection,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::TyposquatGuard(requested)],
    )
}

pub fn reject_looser_script_policy_write(
    global: &GlobalConfig,
    requested: ScriptPolicy,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::ScriptPolicy(requested)],
    )
}

pub fn reject_looser_release_age_write(
    global: &GlobalConfig,
    requested_secs: u64,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::MinimumReleaseAgeSecs(
            requested_secs,
        )],
    )
}

pub fn reject_looser_release_age_policy_write(
    global: &GlobalConfig,
    requested: ReleaseAgePolicy,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::ReleaseAgePolicy(requested)],
    )
}

pub fn reject_looser_sigstore_write(
    global: &GlobalConfig,
    requested: EnforceMode,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::SigstoreVerify(requested)],
    )
}

pub fn reject_looser_install_time_source_analysis_write(
    global: &GlobalConfig,
    requested: bool,
) -> Result<(), LpmError> {
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::InstallTimeSourceAnalysis(
            requested,
        )],
    )
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
    reject_looser_writes(
        global,
        &[PersistentSecuritySetting::FirewallMode(requested)],
    )
}

/// Refuses an editor save of `requested` that a managed security policy or
/// the forced floor doesn't allow. The managed check comes first, so a save
/// that loosens what the policy holds is refused naming the policy and is
/// recorded, and the floor's advice then always passes the policy.
pub fn reject_firewall_policy_save(
    global: &GlobalConfig,
    requested: &lpm_registry::client::NpmFirewallPolicyProfile,
) -> Result<(), LpmError> {
    crate::security_approval::reject_firewall_policies_a_managed_policy_holds(requested)?;
    reject_looser_firewall_policy_write(global, requested)
}

/// Refuses a `[firewall.npm.policies]` profile the firewall editor saves, and
/// signs into the approved posture, when it handles any policy group more
/// leniently than installs enforce now, or than the local posture it rewrites,
/// while `force-security-floor = true` is active. Every group counts, a group
/// left loose by hand included, since the save signs them all; the local
/// posture counts because it binds again once a managed policy goes away.
pub fn reject_looser_firewall_policy_write(
    global: &GlobalConfig,
    requested: &lpm_registry::client::NpmFirewallPolicyProfile,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let effective = crate::security_approval::load_effective_authorized_posture()?;
    let enforced = crate::npm_firewall_config::enforced_policy_profile(global, &effective)?;
    // An editor save also sets `enforce`, so its profile takes effect at once
    // and is measured against what installs do now, at the mode they run.
    let installs_mode = installs_firewall_mode(global, &effective)?;
    let local = crate::security_approval::load_authorized_posture()?;
    let local_profile = local.firewall_policy_profile();
    reject_policy_below_floors(
        crate::npm_firewall_config::NpmFirewallMode::Enforce,
        requested,
        &[
            PolicyFloor {
                mode: installs_mode,
                profile: &enforced,
                source: PolicyFloorSource::Enforced,
            },
            PolicyFloor {
                mode: local.firewall_mode(),
                profile: &local_profile,
                source: PolicyFloorSource::ApprovedPosture,
            },
        ],
    )
}

/// Refuses deleting a `config.toml` key when the profile installs would run
/// afterwards handles a group the delete changes more leniently than installs
/// enforce now, while `force-security-floor = true` is active. A delete only
/// ever tightens what is signed, so a group it leaves as it was is not its
/// doing, and restoring one group never waits on another that is still loose.
pub fn reject_looser_firewall_policy_delete(
    global: &GlobalConfig,
    after: &lpm_registry::client::NpmFirewallPolicyProfile,
) -> Result<(), LpmError> {
    if !force_security_floor_enabled(global) {
        return Ok(());
    }
    let effective = crate::security_approval::load_effective_authorized_posture()?;
    let current = crate::npm_firewall_config::runtime_policy_profile(
        crate::npm_firewall_config::runtime_policy_request(global, &effective)?,
        &effective,
    );
    let floor = crate::npm_firewall_config::enforced_policy_profile(global, &effective)?;
    let installs_mode = installs_firewall_mode(global, &effective)?;
    let mut changed = floor;
    for key in crate::npm_firewall_config::POLICY_KEYS {
        let after_action = crate::npm_firewall_config::policy_action(after, key);
        if after_action != crate::npm_firewall_config::policy_action(&current, key)
            && let (Some(slot), Some(action)) = (
                crate::npm_firewall_config::policy_action_mut(&mut changed, key),
                after_action,
            )
        {
            *slot = action;
        }
    }
    reject_policy_below_floors(
        installs_mode,
        &changed,
        &[PolicyFloor {
            mode: installs_mode,
            profile: &floor,
            source: PolicyFloorSource::Enforced,
        }],
    )
}

/// The firewall mode installs run at now: the config or environment request,
/// never below the effective approved mode.
fn installs_firewall_mode(
    global: &GlobalConfig,
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
) -> Result<crate::npm_firewall_config::NpmFirewallMode, LpmError> {
    Ok(crate::npm_firewall_config::runtime_request_mode(global)?
        .map_or_else(
            || effective.posture.firewall_mode(),
            |request| request.mode(),
        )
        .stricter(effective.posture.firewall_mode()))
}

/// Where a policy floor comes from, as its error names it.
#[derive(Clone, Copy, Debug)]
enum PolicyFloorSource {
    /// What installs enforce now.
    Enforced,
    /// The local approved posture a save rewrites.
    ApprovedPosture,
}

impl PolicyFloorSource {
    fn describe(self) -> &'static str {
        match self {
            Self::Enforced => "LPM CLI enforces",
            Self::ApprovedPosture => "your approved posture holds",
        }
    }
}

/// A profile a policy write may not drop below while `force-security-floor =
/// true` is active, and the mode its actions are measured at.
struct PolicyFloor<'a> {
    mode: crate::npm_firewall_config::NpmFirewallMode,
    profile: &'a lpm_registry::client::NpmFirewallPolicyProfile,
    source: PolicyFloorSource,
}

/// Refuses `requested`, run at `requested_mode`, when it handles a group more
/// leniently than any of `floors`. A floor is a signed or enforced action
/// rather than a `config.toml` value, so the advice is the weakest action that
/// passes every floor, named with the floor that needs it, or to lift the
/// forced floor.
fn reject_policy_below_floors(
    requested_mode: crate::npm_firewall_config::NpmFirewallMode,
    requested: &lpm_registry::client::NpmFirewallPolicyProfile,
    floors: &[PolicyFloor<'_>],
) -> Result<(), LpmError> {
    use crate::npm_firewall_config::{
        action_strictness, loosest_action_meeting, policy_action, policy_action_loosens,
    };
    use lpm_registry::client::NpmFirewallPolicyAction;
    for key in crate::npm_firewall_config::POLICY_KEYS {
        let Some(requested_action) = policy_action(requested, key) else {
            continue;
        };
        let mut binding: Option<(
            &PolicyFloor<'_>,
            NpmFirewallPolicyAction,
            NpmFirewallPolicyAction,
        )> = None;
        for floor in floors {
            let Some(floor_action) = policy_action(floor.profile, key) else {
                continue;
            };
            let passing = loosest_action_meeting(requested_mode, floor.mode, floor_action);
            if binding.is_none_or(|(_, _, strictest)| {
                action_strictness(passing) > action_strictness(strictest)
            }) {
                binding = Some((floor, floor_action, passing));
            }
        }
        let Some((floor, floor_action, passing)) = binding else {
            continue;
        };
        if !policy_action_loosens(requested_mode, requested_action, floor.mode, floor_action) {
            continue;
        }
        return Err(LpmError::SecurityFloor(format!(
            "setting `{}.{}` to `{}` would loosen the `{}` {} for it while \
             `force-security-floor = true` is active. Keep it at `{}` or stricter, or remove \
             `force-security-floor` first.",
            crate::npm_firewall_config::FIREWALL_NPM_POLICIES_CONFIG_PATH,
            key,
            requested_action.as_str(),
            floor_action.as_str(),
            floor.source.describe(),
            passing.as_str(),
        )));
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
    reject_looser_writes(global, &[PersistentSecuritySetting::SandboxMode(requested)])
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
        let temp = tempfile::tempdir().unwrap();
        crate::security_approval::test_support::with_test_env(temp.path(), || {
            let cfg = global_cfg(None, Some("259200"), true);
            let err = reject_looser_release_age_write(&cfg, 0).unwrap_err();
            assert_eq!(err.error_code(), "security_floor");
            assert!(err.to_string().contains("minimum-release-age-secs"));
        });
    }

    #[test]
    fn a_floor_check_without_a_managed_policy_leaves_the_signed_posture_unread() {
        let temp = tempfile::tempdir().unwrap();
        crate::security_approval::test_support::with_test_env(temp.path(), || {
            std::fs::write(
                temp.path().join("approved-posture.json"),
                "not a signed posture",
            )
            .unwrap();
            let cfg = global_cfg(None, Some("259200"), true);

            let err = reject_looser_release_age_write(&cfg, 0).unwrap_err();

            assert!(
                err.to_string()
                    .contains("would loosen the current machine floor `259200`"),
                "{err}"
            );
        });
    }

    #[test]
    fn reject_looser_script_policy_write_allows_tightening() {
        let temp = tempfile::tempdir().unwrap();
        crate::security_approval::test_support::with_test_env(temp.path(), || {
            let cfg = global_cfg(Some("allow"), None, true);
            reject_looser_script_policy_write(&cfg, ScriptPolicy::Triage).unwrap();
        });
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

    #[test]
    fn deferred_suppression_warnings_discard_on_drop_and_keep_on_flush() {
        clear_recorded_suppressions_for_tests();
        let record = SuppressionRecord::new(
            GuardedControl::CooldownWindow,
            SuppressionSource::Cli,
            "0",
            "86400",
        );
        {
            let _guard = defer_suppression_warnings();
            record_suppression(record.clone(), true);
            assert_eq!(recorded_suppressions().len(), 1);
        }
        assert!(
            recorded_suppressions().is_empty(),
            "dropped deferred guard must discard unsent suppression records"
        );

        let guard = defer_suppression_warnings();
        record_suppression(record, true);
        guard.flush(true);
        assert_eq!(recorded_suppressions().len(), 1);
        clear_recorded_suppressions_for_tests();
    }

    fn malware_floor(
        action: lpm_registry::client::NpmFirewallPolicyAction,
    ) -> lpm_registry::client::NpmFirewallPolicyProfile {
        lpm_registry::client::NpmFirewallPolicyProfile {
            lpm_ai_confirmed_malware: action,
            ..lpm_registry::client::NpmFirewallPolicyProfile::default()
        }
    }

    #[test]
    fn forced_floor_refuses_a_looser_firewall_policy_write() {
        let requested = malware_floor(lpm_registry::client::NpmFirewallPolicyAction::Allow);

        let err = reject_policy_below_floors(
            crate::npm_firewall_config::NpmFirewallMode::Enforce,
            &requested,
            &[PolicyFloor {
                mode: crate::npm_firewall_config::NpmFirewallMode::Enforce,
                profile: &malware_floor(lpm_registry::client::NpmFirewallPolicyAction::Block),
                source: PolicyFloorSource::Enforced,
            }],
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("[firewall.npm.policies].lpm_ai_confirmed_malware"),
            "{err}"
        );
        let unforced: toml::Table = toml::from_str("force-security-floor = false\n").unwrap();
        assert!(
            reject_looser_firewall_policy_write(&GlobalConfig::from_table(unforced), &requested)
                .is_ok()
        );
    }

    #[test]
    fn forced_floor_names_the_weakest_action_that_passes_at_the_floor_mode() {
        let err = reject_policy_below_floors(
            crate::npm_firewall_config::NpmFirewallMode::Enforce,
            &malware_floor(lpm_registry::client::NpmFirewallPolicyAction::Allow),
            &[PolicyFloor {
                mode: crate::npm_firewall_config::NpmFirewallMode::Monitor,
                profile: &malware_floor(lpm_registry::client::NpmFirewallPolicyAction::Block),
                source: PolicyFloorSource::ApprovedPosture,
            }],
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("Keep it at `warn` or stricter"),
            "{message}"
        );
        assert!(message.contains("approved"), "{message}");
    }

    #[test]
    fn forced_floor_accepts_a_stricter_firewall_policy_write() {
        let requested = lpm_registry::client::NpmFirewallPolicyProfile::default();

        assert!(
            reject_policy_below_floors(
                crate::npm_firewall_config::NpmFirewallMode::Enforce,
                &requested,
                &[PolicyFloor {
                    mode: crate::npm_firewall_config::NpmFirewallMode::Enforce,
                    profile: &malware_floor(lpm_registry::client::NpmFirewallPolicyAction::Warn),
                    source: PolicyFloorSource::Enforced,
                }],
            )
            .is_ok()
        );
    }
}
