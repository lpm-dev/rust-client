mod common;
mod editor;
mod firewall;
mod integrity;
mod lpm_dev;
mod lpm_skills;
mod release_age;
mod sandbox;
mod scripts;
mod signatures;
mod sigstore;
mod source_analysis;
mod triage;
mod trust_policy;
mod typosquat;

mod prelude {
    pub(in crate::commands::config) use crate::install_ui;
    pub(in crate::commands::config) use crate::npm_firewall_config::{
        FIREWALL_CONFIG_MODE_KEY, FIREWALL_CONFIG_PATH, FIREWALL_CONFIG_SECTION, NpmFirewallMode,
    };
    pub(in crate::commands::config) use crate::prompt::prompt_err;
    pub(in crate::commands::config) use crate::provenance_fetch::EnforceMode;
    pub(in crate::commands::config) use crate::sandbox_config::ResolvedSandboxMode;
    pub(in crate::commands::config) use lpm_common::LpmError;
    pub(in crate::commands::config) use lpm_common::color::Painted;
    pub(in crate::commands::config) use std::io::IsTerminal;

    pub(in crate::commands::config) use super::super::global_config::GlobalConfig;
    pub(in crate::commands::config) use super::super::io::{read_config, update_config};
    pub(in crate::commands::config) use super::common::{
        SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES, SIGNATURES_KEY, TRIAGE_ADVISOR_KEY,
        TRIAGE_ADVISOR_VALUES, announce_bool_set, announce_set, format_bool_enabled,
        parse_config_bool, persist_bool, persist_string, read_bool_value, read_string_value,
    };
}

pub(in crate::commands::config) use common::{
    SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES, SIGNATURES_KEY, TRIAGE_ADVISOR_KEY,
    TRIAGE_ADVISOR_VALUES, format_bool_enabled, parse_config_bool, read_string_value,
};
#[cfg(test)]
pub(in crate::commands::config) use firewall::persist_firewall_policy_profile_in_config_value;
#[cfg(test)]
pub(in crate::commands::config) use firewall::read_firewall_mode;
#[cfg(test)]
pub(in crate::commands::config) use firewall::{
    FIREWALL_ENFORCE_HINT, FIREWALL_MONITOR_HINT, FIREWALL_OFF_HINT, FIREWALL_WIZARD_PROMPT,
};
pub(in crate::commands::config) use firewall::{
    FIREWALL_GUIDED_MENU_LABEL, apply_firewall_mode, format_current_firewall_mode,
    parse_firewall_mode_selection, run_firewall_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use integrity::read_integrity_policy;
pub(crate) use integrity::resolve_object_integrity_policy;
pub(in crate::commands::config) use integrity::{
    INTEGRITY_GUIDED_MENU_LABEL, INTEGRITY_KEY, INTEGRITY_VALUES, format_current_integrity_policy,
    parse_integrity_policy_selection, run_integrity_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use integrity::{
    INTEGRITY_SOURCE_HINT, INTEGRITY_TREE_HINT, INTEGRITY_WIZARD_PROMPT,
};
pub(in crate::commands::config) use lpm_dev::{run_lpm_dev_wizard, run_lpm_insights_wizard};
pub(in crate::commands::config) use lpm_skills::{
    format_current_lpm_skills, run_lpm_skills_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use release_age::read_release_age_override;
#[cfg(test)]
pub(in crate::commands::config) use release_age::{
    CAUTIOUS_RELEASE_AGE_SECS, DEFAULT_RELEASE_AGE_SECS, ReleaseAgeSelection,
    persist_release_age_selection, release_age_initial_choice,
};
pub(in crate::commands::config) use release_age::{
    RELEASE_AGE_GUIDED_MENU_LABEL, RELEASE_AGE_KEY, RELEASE_AGE_POLICY_KEY,
    format_current_release_age, run_release_age_configuration_wizard,
    run_release_age_policy_wizard, run_release_age_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use sandbox::read_sandbox_mode;
pub(in crate::commands::config) use sandbox::{
    SANDBOX_MODE_VALUES, apply_sandbox_mode, run_sandbox_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use scripts::persist_script_policy;
pub(in crate::commands::config) use scripts::run_scripts_wizard;
pub(in crate::commands::config) use signatures::run_signatures_wizard;
pub(in crate::commands::config) use sigstore::{
    SIGSTORE_AVAILABILITY_VALUES, SIGSTORE_SCOPE_VALUES, SIGSTORE_VERIFY_VALUES,
    apply_sigstore_assignment, parse_sigstore_assignment, run_sigstore_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use sigstore::{
    read_sigstore_availability, read_sigstore_scope, read_sigstore_verify,
};
pub(in crate::commands::config) use source_analysis::run_source_analysis_wizard;
pub(in crate::commands::config) use triage::run_triage_wizard;
pub(crate) use trust_policy::TRUST_POLICY_KEY;
pub(in crate::commands::config) use trust_policy::{
    TRUST_POLICY_VALUES, run_trust_policy_wizard, validate_trust_policy_value,
};
#[cfg(test)]
pub(in crate::commands::config) use typosquat::read_typosquat_guard_override;
pub(crate) use typosquat::{TYPOSQUAT_GUARD_KEY, TyposquatGuardSelection};
pub(in crate::commands::config) use typosquat::{
    format_current_typosquat_guard, parse_typosquat_guard_selection,
    reject_looser_typosquat_guard_write, run_typosquat_wizard,
};
