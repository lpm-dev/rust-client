mod common;
mod firewall;
mod integrity;
mod lpm_skills;
mod release_age;
mod sandbox;
mod scripts;
mod signatures;
mod sigstore;
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

    pub(in crate::commands::config) use super::super::global_config::{
        GlobalConfig, global_config_view_from_value,
    };
    pub(in crate::commands::config) use super::super::io::{read_config, write_config};
    pub(in crate::commands::config) use super::common::{
        SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES, SIGNATURES_KEY, TRIAGE_ADVISOR_KEY,
        TRIAGE_ADVISOR_VALUES, announce_bool_set, announce_set, format_bool_enabled,
        parse_config_bool, persist_bool, persist_string, read_bool_value, read_string_value,
    };
}

pub(in crate::commands::config) use common::{
    SCRIPT_POLICY_KEY, SCRIPT_POLICY_VALUES, SIGNATURES_KEY, TRIAGE_ADVISOR_KEY,
    TRIAGE_ADVISOR_VALUES, format_bool_enabled, parse_config_bool, read_bool_value,
    read_string_value,
};
#[cfg(test)]
pub(in crate::commands::config) use firewall::persist_firewall_policy_profile_in_config_value;
#[cfg(test)]
pub(in crate::commands::config) use firewall::{
    FIREWALL_ENFORCE_HINT, FIREWALL_MONITOR_HINT, FIREWALL_OFF_HINT, FIREWALL_WIZARD_PROMPT,
};
pub(in crate::commands::config) use firewall::{
    FIREWALL_GUIDED_MENU_LABEL, format_current_firewall_mode, parse_firewall_mode_selection,
    persist_firewall_mode_in_config_value, read_firewall_mode, run_firewall_wizard,
};
pub(crate) use integrity::resolve_object_integrity_policy;
pub(in crate::commands::config) use integrity::{
    INTEGRITY_GUIDED_MENU_LABEL, INTEGRITY_KEY, INTEGRITY_VALUES, format_current_integrity_policy,
    parse_integrity_policy_selection, read_integrity_policy, run_integrity_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use integrity::{
    INTEGRITY_SOURCE_HINT, INTEGRITY_TREE_HINT, INTEGRITY_WIZARD_PROMPT,
};
pub(in crate::commands::config) use lpm_skills::{
    format_current_lpm_skills, read_auto_install_lpm_skills, run_lpm_skills_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use release_age::{
    CAUTIOUS_RELEASE_AGE_SECS, DEFAULT_RELEASE_AGE_SECS, release_age_initial_choice,
};
pub(in crate::commands::config) use release_age::{
    RELEASE_AGE_KEY, RELEASE_AGE_POLICY_KEY, format_current_release_age, read_release_age_override,
    read_release_age_policy_override, run_release_age_policy_wizard, run_release_age_wizard,
};
pub(in crate::commands::config) use sandbox::{
    SANDBOX_MODE_VALUES, read_sandbox_mode, run_sandbox_wizard,
};
#[cfg(test)]
pub(in crate::commands::config) use scripts::persist_script_policy;
pub(in crate::commands::config) use scripts::run_scripts_wizard;
pub(in crate::commands::config) use signatures::run_signatures_wizard;
pub(in crate::commands::config) use sigstore::{
    SIGSTORE_AVAILABILITY_VALUES, SIGSTORE_SCOPE_VALUES, SIGSTORE_VERIFY_VALUES,
    read_sigstore_availability, read_sigstore_scope, read_sigstore_verify, run_sigstore_wizard,
};
pub(in crate::commands::config) use triage::run_triage_wizard;
pub(crate) use trust_policy::TRUST_POLICY_KEY;
pub(in crate::commands::config) use trust_policy::{
    TRUST_POLICY_VALUES, run_trust_policy_wizard, validate_trust_policy_value,
};
pub(crate) use typosquat::{TYPOSQUAT_GUARD_KEY, TyposquatGuardSelection};
pub(in crate::commands::config) use typosquat::{
    format_current_typosquat_guard, parse_typosquat_guard_selection, read_typosquat_guard_override,
    reject_looser_typosquat_guard_write, run_typosquat_wizard,
};
