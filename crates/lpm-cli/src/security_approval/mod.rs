//! Signed security approvals for guarded posture changes.
//!
//! The signed approved machine posture and short-lived unlock grants
//! are the authority for guarded weakeners. `package.json`, `lpm.toml`,
//! and `~/.lpm/config.toml` remain proposal layers; this module decides
//! whether a weaker proposal is already authorized, needs interactive
//! approval, or must fail closed for automation.

mod approval;
mod audit;
mod helpers;
mod managed_policy;
mod native_auth;
mod paths;
mod posture;
mod project_state;
mod signed_store;
#[cfg(test)]
mod tests;
mod types;
mod unlocks;

pub(crate) use approval::record_project_trust_candidate_authorized_from_managed_flow;
pub use approval::{
    approval_required_error, authorize_persistent_release_age,
    authorize_persistent_release_age_policy, authorize_persistent_sandbox_mode,
    authorize_persistent_script_policy, authorize_persistent_sigstore,
    ensure_global_trust_authorized, ensure_global_trust_candidate_authorized_from_trust,
    ensure_project_policy_authorized, ensure_project_trust_candidate_authorized,
    ensure_runtime_sigstore_posture, ensure_runtime_sigstore_posture_for_global,
};
pub use helpers::format_unlock_duration;
#[allow(unused_imports)]
pub use paths::security_dir;
#[allow(unused_imports)]
pub use posture::{
    load_authorized_posture, load_effective_authorized_posture, load_security_status,
    persist_authorized_posture,
};
pub use project_state::authorized_capability_user_bound;
pub use signed_store::repair_security_state;
#[allow(unused_imports)]
pub use types::{
    ApprovalScope, ApprovalSource, AuthorizedPosture, AuthorizedPostureView,
    EffectiveAuthorizedPosture, EffectivePostureSources, ManagedPolicyStatus, PostureSourceKind,
    QuarantinedSecurityState, RuntimeOverride, SecurityRepairReport, SecurityStatus, UnlockGrant,
    UnlockLimits, UnlockRevocation, UnlockTargetKind,
};
#[allow(unused_imports)]
pub use unlocks::{
    approve_project_runtime_override, ensure_global_unlock, ensure_project_unlock,
    has_active_project_unlock, list_active_global_unlocks, list_active_project_unlocks,
    list_active_unlocks, lock_global_scopes_command, lock_project_scopes_command,
    unlock_global_scopes_command, unlock_scopes_command,
};

const SIGNING_SECRET_BYTES: usize = 32;
const APPROVED_POSTURE_SCHEMA_VERSION: u32 = 1;
const UNLOCK_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_UNLOCK_TTL_SECS: u64 = 10 * 60;
pub const MAX_UNLOCK_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const KEYRING_SERVICE: &str = "dev.lpm.security-approval";
const KEYRING_ACCOUNT: &str = "signing-secret-v1";
#[cfg(test)]
const SECURITY_DIR_ENV: &str = "LPM_SECURITY_DIR";
#[cfg(not(windows))]
const DEFAULT_SECURITY_POLICY_PATH: &str = "/etc/lpm/security-policy.toml";
#[cfg(windows)]
const DEFAULT_SECURITY_POLICY_PATH: &str = r"C:\ProgramData\lpm\security-policy.toml";
const APPROVED_PROJECT_STATE_SCHEMA_VERSION: u32 = 1;
const APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION: u32 = 1;
const AUDIT_EVENT_SCHEMA_VERSION: u32 = 1;
const AUDIT_HEAD_SCHEMA_VERSION: u32 = 1;

#[cfg(debug_assertions)]
const SECURITY_POLICY_PATH_ENV: &str = "LPM_SECURITY_POLICY_PATH";
#[cfg(test)]
const TEST_SECRET_ENV: &str = "LPM_TEST_SECURITY_SECRET_HEX";
#[cfg(test)]
const TEST_AUTH_RESULT_ENV: &str = "LPM_TEST_SECURITY_AUTH_RESULT";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

fn force_file_audit_head_backend() -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[cfg(test)]
fn test_secret_override() -> Option<String> {
    std::env::var(TEST_SECRET_ENV)
        .ok()
        .filter(|raw| !raw.trim().is_empty())
}

#[cfg(not(test))]
fn test_secret_override() -> Option<String> {
    None
}

#[cfg(test)]
fn test_native_auth_override() -> Option<String> {
    std::env::var(TEST_AUTH_RESULT_ENV).ok()
}

#[cfg(not(test))]
fn test_native_auth_override() -> Option<String> {
    None
}

#[cfg(not(test))]
fn keyring_account(base: &str) -> Result<String, lpm_common::LpmError> {
    use sha2::Digest;

    if std::env::var_os("LPM_HOME").is_none() {
        return Ok(base.to_string());
    }
    let root = lpm_common::LpmRoot::from_env()?;
    let digest = hex::encode(sha2::Sha256::digest(
        root.root().display().to_string().as_bytes(),
    ));
    Ok(format!("{base}:{}", &digest[..16]))
}

#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "test build keeps the same fallible account helper signature"
)]
fn keyring_account(base: &str) -> Result<String, lpm_common::LpmError> {
    Ok(base.to_string())
}

#[allow(unused_imports)]
mod prelude {
    #[cfg(debug_assertions)]
    pub(super) use super::SECURITY_POLICY_PATH_ENV;
    pub(super) use super::{
        APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION, APPROVED_POSTURE_SCHEMA_VERSION,
        APPROVED_PROJECT_STATE_SCHEMA_VERSION, AUDIT_EVENT_SCHEMA_VERSION,
        AUDIT_HEAD_SCHEMA_VERSION, DEFAULT_SECURITY_POLICY_PATH, DEFAULT_UNLOCK_TTL_SECS,
        HmacSha256, KEYRING_ACCOUNT, KEYRING_SERVICE, MAX_UNLOCK_TTL_SECS, SIGNING_SECRET_BYTES,
        UNLOCK_SCHEMA_VERSION, force_file_audit_head_backend, keyring_account,
        test_native_auth_override, test_secret_override,
    };
    #[cfg(test)]
    pub(super) use super::{SECURITY_DIR_ENV, TEST_AUTH_RESULT_ENV, TEST_SECRET_ENV};

    pub(super) use super::approval::{
        approval_required_error, managed_policy_blocks_scope, managed_policy_blocks_scope_direct,
    };
    pub(super) use super::audit::{
        AuditRecord, append_audit_event, audit_signature_payload, hash_json_value,
        read_audit_log_tail, record_audit_event,
    };
    pub(super) use super::helpers::{
        canonical_global_root, canonical_project_root, format_scope_list, format_unlock_duration,
        is_automation, normalized_packages, normalized_scopes, project_dir_is_global_install,
        scope_names, suggested_unlock_command,
    };
    pub(super) use super::managed_policy::{load_managed_policy, managed_policy_error};
    pub(super) use super::native_auth::request_native_approval;
    pub(super) use super::paths::{
        approved_global_trust_path, approved_posture_path, approved_projects_dir, audit_head_path,
        audit_lock_path, audit_log_path, security_dir, signing_secret_path, unlocks_dir,
    };
    pub(super) use super::posture::{
        load_authorized_posture, load_effective_authorized_posture, persist_authorized_posture,
    };
    pub(super) use super::project_state::{
        authorized_capability_user_bound, candidate_global_trust_state,
        candidate_project_policy_state, current_global_trust_state, current_project_policy_state,
        global_trust_widened, load_approved_global_trust_state, load_approved_project_policy_state,
        persist_global_trust_state, persist_project_policy_state, project_policy_required_scopes,
        same_global_trust_shape, same_project_policy_shape, unlock_grant_covers_packages,
    };
    pub(super) use super::signed_store::{
        read_signed_json, sign_payload_value, verify_payload_value, write_signed_json,
    };
    pub(super) use super::types::{
        ApprovalScope, ApprovalSource, ApprovedGlobalTrustState, ApprovedProjectPolicyState,
        AuditEvent, AuditHead, AuthorizedPosture, AuthorizedPostureView,
        EffectiveAuthorizedPosture, EffectivePostureSources, ManagedPolicy, ManagedPolicyStatus,
        PostureSourceKind, QuarantinedSecurityState, RuntimeOverride, SecurityRepairReport,
        SecurityStatus, SignedAuditEnvelope, SignedEnvelope, StoredUnlockGrant, UnlockGrant,
        UnlockLimits, UnlockRevocation, UnlockTargetKind,
    };
    pub(super) use super::unlocks::{
        create_global_unlock_grant, create_global_unlock_grant_for_scopes, create_unlock_grant,
        create_unlock_grant_for_scopes, ensure_global_unlock, ensure_project_unlock,
        find_active_project_unlock, has_active_project_unlock, list_active_global_unlocks,
        list_active_project_unlocks, list_active_unlocks, persist_unlock_grant, prompt_for_unlock,
        read_active_unlocks,
    };

    pub(super) use crate::precedence::PurePolicyKnob;
    pub(super) use crate::provenance_fetch::EnforceMode;
    pub(super) use crate::release_age_config::{DEFAULT_MIN_RELEASE_AGE_SECS, ReleaseAgePolicy};
    pub(super) use crate::sandbox_config::ResolvedSandboxMode;
    pub(super) use crate::script_policy_config::ScriptPolicy;
    pub(super) use chrono::{DateTime, Utc};
    pub(super) use hmac::Mac;
    pub(super) use lpm_common::LpmError;
    pub(super) use rand::RngCore;
    pub(super) use serde::{Deserialize, Serialize};
    pub(super) use sha2::{Digest, Sha256};
    pub(super) use std::collections::{BTreeMap, BTreeSet};
    pub(super) use std::io::{IsTerminal, Write};
    pub(super) use std::path::{Path, PathBuf};
    pub(super) use std::process::Command;
}
