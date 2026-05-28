//! Signed security approvals for guarded posture changes.
//!
//! Phase 2 moves the *authoritative* approved machine posture out of
//! ordinary config files and adds short-lived signed unlock grants for
//! project-scoped weakeners. `package.json`, `lpm.toml`, and
//! `~/.lpm/config.toml` remain the proposal layers; this module
//! decides whether a weaker proposal is already authorized, needs an
//! interactive approval, or must fail closed for automation.

use crate::precedence::PurePolicyKnob;
use crate::provenance_fetch::EnforceMode;
use crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS;
use crate::sandbox_config::ResolvedSandboxMode;
use crate::script_policy_config::ScriptPolicy;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use lpm_common::LpmError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

type HmacSha256 = Hmac<Sha256>;

const APPROVED_POSTURE_SCHEMA_VERSION: u32 = 1;
const UNLOCK_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_UNLOCK_TTL_SECS: u64 = 10 * 60;
pub const MAX_UNLOCK_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const KEYRING_SERVICE: &str = "dev.lpm.security-approval";
const KEYRING_ACCOUNT: &str = "signing-secret-v1";
#[cfg(not(test))]
const KEYRING_AUDIT_HEAD_ACCOUNT: &str = "audit-head-v1";
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

#[cfg(test)]
const SECURITY_POLICY_PATH_ENV: &str = "LPM_SECURITY_POLICY_PATH";
#[cfg(test)]
const TEST_SECRET_ENV: &str = "LPM_TEST_SECURITY_SECRET_HEX";
#[cfg(test)]
const TEST_AUTH_RESULT_ENV: &str = "LPM_TEST_SECURITY_AUTH_RESULT";

fn force_file_audit_head_backend() -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    matches!(
        std::env::var("LPM_FORCE_FILE_VAULT").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalScope {
    CooldownBypass,
    CooldownWindow,
    ProvenanceIgnoreDrift,
    ProvenanceUnverified,
    ScriptsTriage,
    ScriptsAllow,
    TrustBulkApprove,
    TrustScopeWiden,
    SandboxDefault,
    SandboxNone,
    SandboxAllowDegraded,
    CapabilityWiden,
    FloorEdit,
}

const ALL_APPROVAL_SCOPES: [ApprovalScope; 13] = [
    ApprovalScope::CooldownBypass,
    ApprovalScope::CooldownWindow,
    ApprovalScope::ProvenanceIgnoreDrift,
    ApprovalScope::ProvenanceUnverified,
    ApprovalScope::ScriptsTriage,
    ApprovalScope::ScriptsAllow,
    ApprovalScope::TrustBulkApprove,
    ApprovalScope::TrustScopeWiden,
    ApprovalScope::SandboxDefault,
    ApprovalScope::SandboxNone,
    ApprovalScope::SandboxAllowDegraded,
    ApprovalScope::CapabilityWiden,
    ApprovalScope::FloorEdit,
];

const DEFAULT_UNLOCK_SCOPES: [ApprovalScope; 9] = [
    ApprovalScope::CooldownBypass,
    ApprovalScope::CooldownWindow,
    ApprovalScope::ProvenanceIgnoreDrift,
    ApprovalScope::ProvenanceUnverified,
    ApprovalScope::ScriptsTriage,
    ApprovalScope::ScriptsAllow,
    ApprovalScope::SandboxDefault,
    ApprovalScope::SandboxNone,
    ApprovalScope::SandboxAllowDegraded,
];

impl ApprovalScope {
    pub fn all_scopes() -> &'static [Self] {
        &ALL_APPROVAL_SCOPES
    }

    pub fn default_unlock_scopes() -> &'static [Self] {
        &DEFAULT_UNLOCK_SCOPES
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CooldownBypass => "cooldown-bypass",
            Self::CooldownWindow => "cooldown-window",
            Self::ProvenanceIgnoreDrift => "provenance-ignore-drift",
            Self::ProvenanceUnverified => "provenance-unverified",
            Self::ScriptsTriage => "scripts-triage",
            Self::ScriptsAllow => "scripts-allow",
            Self::TrustBulkApprove => "trust-bulk-approve",
            Self::TrustScopeWiden => "trust-scope-widen",
            Self::SandboxDefault => "sandbox-default",
            Self::SandboxNone => "sandbox-none",
            Self::SandboxAllowDegraded => "sandbox-allow-degraded",
            Self::CapabilityWiden => "capability-widen",
            Self::FloorEdit => "floor-edit",
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalSource {
    CliFlag,
    EnvVar,
    ProjectConfig,
    GlobalConfig,
    ConfigMutation,
    SecurityCommand,
}

impl ApprovalSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::CliFlag => "cli-flag",
            Self::EnvVar => "env-var",
            Self::ProjectConfig => "project-config",
            Self::GlobalConfig => "global-config",
            Self::ConfigMutation => "config-mutation",
            Self::SecurityCommand => "security-command",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedPosture {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub script_policy: String,
    pub minimum_release_age_secs: u64,
    pub sandbox_mode: String,
    pub sandbox_allow_degraded: bool,
    pub sigstore_verify: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizedPostureView {
    pub script_policy: String,
    pub minimum_release_age_secs: u64,
    pub sandbox_mode: String,
    pub sandbox_allow_degraded: bool,
    pub sigstore_verify: String,
}

impl Default for AuthorizedPosture {
    fn default() -> Self {
        Self {
            schema_version: APPROVED_POSTURE_SCHEMA_VERSION,
            updated_at: Utc::now(),
            script_policy: ScriptPolicy::default().as_str().to_string(),
            minimum_release_age_secs: DEFAULT_MIN_RELEASE_AGE_SECS,
            sandbox_mode: ResolvedSandboxMode::Default.as_str().to_string(),
            sandbox_allow_degraded: false,
            sigstore_verify: "deny".to_string(),
        }
    }
}

impl AuthorizedPosture {
    pub fn script_policy(&self) -> ScriptPolicy {
        ScriptPolicy::parse(&self.script_policy).unwrap_or_default()
    }

    pub fn minimum_release_age_secs(&self) -> u64 {
        self.minimum_release_age_secs
    }

    pub fn sandbox_mode(&self) -> ResolvedSandboxMode {
        ResolvedSandboxMode::parse_for_security_floor(&self.sandbox_mode)
            .unwrap_or(ResolvedSandboxMode::Default)
    }

    pub fn sandbox_allow_degraded(&self) -> bool {
        self.sandbox_allow_degraded
    }

    pub fn sigstore_verify(&self) -> EnforceMode {
        match self.sigstore_verify.as_str() {
            "off" => EnforceMode::Off,
            "warn" => EnforceMode::Warn,
            _ => EnforceMode::Deny,
        }
    }

    pub fn to_view(&self) -> AuthorizedPostureView {
        AuthorizedPostureView {
            script_policy: self.script_policy.clone(),
            minimum_release_age_secs: self.minimum_release_age_secs,
            sandbox_mode: self.sandbox_mode.clone(),
            sandbox_allow_degraded: self.sandbox_allow_degraded,
            sigstore_verify: self.sigstore_verify.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostureSourceKind {
    BuiltinDefault,
    ApprovedStore,
    ManagedPolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EffectivePostureSources {
    pub script_policy: PostureSourceKind,
    pub minimum_release_age_secs: PostureSourceKind,
    pub sandbox_mode: PostureSourceKind,
    pub sandbox_allow_degraded: PostureSourceKind,
    pub sigstore_verify: PostureSourceKind,
}

impl EffectivePostureSources {
    fn new(base: PostureSourceKind) -> Self {
        Self {
            script_policy: base,
            minimum_release_age_secs: base,
            sandbox_mode: base,
            sandbox_allow_degraded: base,
            sigstore_verify: base,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManagedPolicyStatus {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enforced_controls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EffectiveAuthorizedPosture {
    pub posture: AuthorizedPosture,
    pub sources: EffectivePostureSources,
    pub approved_posture_path: String,
    pub approved_posture_source: PostureSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_policy: Option<ManagedPolicyStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityStatus {
    pub target: UnlockTargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub effective_floor: AuthorizedPostureView,
    pub floor_sources: EffectivePostureSources,
    pub approved_posture_path: String,
    pub approved_posture_source: PostureSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_policy: Option<ManagedPolicyStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_runtime_overrides: Vec<RuntimeOverride>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_unlocks: Vec<UnlockGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedPolicy {
    status: ManagedPolicyStatus,
    script_policy: Option<ScriptPolicy>,
    minimum_release_age_secs: Option<u64>,
    sandbox_mode: Option<ResolvedSandboxMode>,
    sandbox_allow_degraded: Option<bool>,
    sigstore_verify: Option<EnforceMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UnlockLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_release_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockTargetKind {
    #[default]
    Project,
    Global,
}

impl UnlockTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockGrant {
    pub schema_version: u32,
    pub id: String,
    #[serde(default)]
    pub target: UnlockTargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub scopes: Vec<ApprovalScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    #[serde(default)]
    pub limits: UnlockLimits,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnlockRevocation {
    pub id: String,
    pub target: UnlockTargetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_scopes: Vec<ApprovalScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining_scopes: Vec<ApprovalScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct StoredUnlockGrant {
    path: PathBuf,
    grant: UnlockGrant,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeOverride {
    pub control: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ApprovedProjectPolicyState {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub project_root: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted_dependencies: BTreeMap<String, crate::trust_snapshot::SnapshotEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_request_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ApprovedGlobalTrustState {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted_dependencies: BTreeMap<String, lpm_global::TrustedDependencyBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AuditEvent {
    pub schema_version: u32,
    pub occurred_at: DateTime<Utc>,
    pub event: String,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AuditHead {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub last_entry_hash: String,
    pub entry_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedAuditEnvelope {
    payload: AuditEvent,
    previous_entry_hash: Option<String>,
    entry_hash: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedEnvelope<T> {
    payload: T,
    signature: String,
}

pub fn security_dir() -> Result<PathBuf, LpmError> {
    #[cfg(test)]
    if let Ok(path) = std::env::var(SECURITY_DIR_ENV)
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    Ok(lpm_common::LpmRoot::from_env()?.root().join("security"))
}

fn approved_posture_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("approved-posture.json"))
}

fn unlocks_dir() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("unlocks"))
}

fn approved_projects_dir() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("projects"))
}

fn approved_global_trust_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("approved-global-trust.json"))
}

fn audit_log_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("audit.jsonl"))
}

fn signing_secret_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("signing-secret.hex"))
}

fn audit_head_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("audit-head.json"))
}

#[cfg(test)]
fn managed_policy_path_override() -> Option<PathBuf> {
    std::env::var(SECURITY_POLICY_PATH_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

#[cfg(not(test))]
fn managed_policy_path_override() -> Option<PathBuf> {
    None
}

fn managed_policy_path() -> PathBuf {
    if let Some(path) = managed_policy_path_override() {
        return path;
    }
    PathBuf::from(DEFAULT_SECURITY_POLICY_PATH)
}

fn managed_policy_error(path: &Path, message: impl Into<String>) -> LpmError {
    LpmError::Registry(format!(
        "managed security policy {} {}",
        path.display(),
        message.into()
    ))
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
fn keyring_account(base: &str) -> Result<String, LpmError> {
    if std::env::var_os("LPM_HOME").is_none() {
        return Ok(base.to_string());
    }
    let root = lpm_common::LpmRoot::from_env()?;
    let digest = hex::encode(Sha256::digest(root.root().display().to_string().as_bytes()));
    Ok(format!("{base}:{}", &digest[..16]))
}

#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "test build keeps the same fallible account helper signature"
)]
fn keyring_account(base: &str) -> Result<String, LpmError> {
    Ok(base.to_string())
}

#[cfg_attr(test, allow(dead_code))]
#[cfg(unix)]
fn validate_root_owned_path(path: &Path, expect_dir: bool) -> Result<(), LpmError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(managed_policy_error(
            path,
            "must not be a symlink-backed path",
        ));
    }
    if expect_dir && !metadata.is_dir() {
        return Err(managed_policy_error(path, "must be a directory"));
    }
    if !expect_dir && !metadata.is_file() {
        return Err(managed_policy_error(path, "must be a regular file"));
    }
    if metadata.uid() != 0 {
        return Err(managed_policy_error(path, "must be owned by root"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(managed_policy_error(
            path,
            "must not be group- or world-writable",
        ));
    }
    if metadata.file_type().is_socket()
        || metadata.file_type().is_fifo()
        || metadata.file_type().is_block_device()
        || metadata.file_type().is_char_device()
    {
        return Err(managed_policy_error(
            path,
            "must not be a special device path",
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(test)))]
fn validate_managed_policy_authority(path: &Path) -> Result<(), LpmError> {
    let canonical = std::fs::canonicalize(path)?;
    if canonical != Path::new(DEFAULT_SECURITY_POLICY_PATH) {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", DEFAULT_SECURITY_POLICY_PATH),
        ));
    }

    validate_root_owned_path(path, false)?;
    let mut current = path.parent();
    while let Some(dir) = current {
        validate_root_owned_path(dir, true)?;
        if dir == Path::new("/etc") {
            break;
        }
        current = dir.parent();
    }
    Ok(())
}

#[cfg(all(windows, not(test)))]
fn validate_windows_admin_owned_path(path: &Path, expect_dir: bool) -> Result<(), LpmError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const WRITE_MASK: u32 = 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000 // GENERIC_WRITE
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x0000_0010 // FILE_WRITE_EA
        | 0x0000_0100; // FILE_WRITE_ATTRIBUTES

    struct LocalAlloc(*mut c_void);
    impl Drop for LocalAlloc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    fn wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn sid_from_sddl(sddl: &[u16]) -> Result<LocalAlloc, LpmError> {
        let mut sid: PSID = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(sddl.as_ptr(), &mut sid) };
        if ok == 0 || sid.is_null() {
            return Err(LpmError::Registry(
                "failed to initialize Windows managed-policy authority SID".into(),
            ));
        }
        Ok(LocalAlloc(sid.cast()))
    }

    fn sid_matches(sid: PSID, trusted: &[LocalAlloc]) -> bool {
        trusted
            .iter()
            .any(|trusted_sid| unsafe { EqualSid(sid, trusted_sid.0.cast()) != 0 })
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(managed_policy_error(
            path,
            "must not be a reparse-point-backed path",
        ));
    }
    if expect_dir && !metadata.is_dir() {
        return Err(managed_policy_error(path, "must be a directory"));
    }
    if !expect_dir && !metadata.is_file() {
        return Err(managed_policy_error(path, "must be a regular file"));
    }

    let system_sid = sid_from_sddl(&[
        b'S' as u16,
        b'-' as u16,
        b'1' as u16,
        b'-' as u16,
        b'5' as u16,
        b'-' as u16,
        b'1' as u16,
        b'8' as u16,
        0,
    ])?;
    let admins_sid = sid_from_sddl(&[
        b'S' as u16,
        b'-' as u16,
        b'1' as u16,
        b'-' as u16,
        b'5' as u16,
        b'-' as u16,
        b'3' as u16,
        b'2' as u16,
        b'-' as u16,
        b'5' as u16,
        b'4' as u16,
        b'4' as u16,
        0,
    ])?;
    let trusted_sids = [system_sid, admins_sid];

    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let path_wide = wide_null(path);
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(managed_policy_error(
            path,
            format!("could not read Windows security descriptor: error {status}"),
        ));
    }
    let _descriptor_guard = LocalAlloc(descriptor.cast());

    if owner.is_null() || !sid_matches(owner, &trusted_sids) {
        return Err(managed_policy_error(
            path,
            "must be owned by SYSTEM or Administrators",
        ));
    }

    let mut owner_from_descriptor: PSID = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner_from_descriptor, &mut owner_defaulted)
    } == 0
        || owner_from_descriptor.is_null()
        || !sid_matches(owner_from_descriptor, &trusted_sids)
    {
        return Err(managed_policy_error(
            path,
            "must have a valid SYSTEM or Administrators owner",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(managed_policy_error(path, "must have a readable DACL"));
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(managed_policy_error(path, "must not have a null DACL"));
    }

    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..ace_count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 || ace.is_null() {
            return Err(managed_policy_error(path, "has an unreadable DACL entry"));
        }
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        if allowed.Mask & WRITE_MASK == 0 {
            continue;
        }
        let sid = std::ptr::addr_of!(allowed.SidStart).cast::<c_void>() as PSID;
        if !sid_matches(sid, &trusted_sids) {
            return Err(managed_policy_error(
                path,
                "must not grant write access to non-administrator principals",
            ));
        }
    }

    Ok(())
}

#[cfg(all(windows, not(test)))]
fn validate_managed_policy_authority(path: &Path) -> Result<(), LpmError> {
    let canonical = std::fs::canonicalize(path)?;
    let default_path = PathBuf::from(DEFAULT_SECURITY_POLICY_PATH);
    let canonical_default = std::fs::canonicalize(&default_path)?;
    if !canonical
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(canonical_default.as_os_str().to_string_lossy().as_ref())
    {
        return Err(managed_policy_error(
            path,
            format!("must resolve to {}", DEFAULT_SECURITY_POLICY_PATH),
        ));
    }

    validate_windows_admin_owned_path(path, false)?;
    let Some(parent) = path.parent() else {
        return Err(managed_policy_error(
            path,
            "must have a managed parent directory",
        ));
    };
    validate_windows_admin_owned_path(parent, true)?;
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "test stub must preserve the fallible production signature"
)]
fn validate_managed_policy_authority(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

fn parse_policy_u64(path: &Path, key: &str, value: &toml::Value) -> Result<Option<u64>, LpmError> {
    match value {
        toml::Value::Integer(raw) => u64::try_from(*raw)
            .map(Some)
            .map_err(|_| managed_policy_error(path, format!("has invalid `{key}` value `{raw}`"))),
        toml::Value::String(raw) => crate::release_age_config::parse_strict_u64_string(raw)
            .map(Some)
            .ok_or_else(|| {
                managed_policy_error(path, format!("has invalid `{key}` value `{raw}`"))
            }),
        _ => Err(managed_policy_error(
            path,
            format!("must set `{key}` to a non-negative integer second count"),
        )),
    }
}

fn parse_policy_sigstore(path: &Path, raw: &str) -> Result<EnforceMode, LpmError> {
    match raw {
        "deny" => Ok(EnforceMode::Deny),
        "warn" => Ok(EnforceMode::Warn),
        "off" => Ok(EnforceMode::Off),
        _ => Err(managed_policy_error(
            path,
            format!("has invalid `[sigstore].verify` value `{raw}`"),
        )),
    }
}

fn load_managed_policy() -> Result<Option<ManagedPolicy>, LpmError> {
    let path = managed_policy_path();
    if !path.exists() {
        return Ok(None);
    }
    validate_managed_policy_authority(&path)?;

    let content = std::fs::read_to_string(&path)?;
    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|e| managed_policy_error(&path, format!("parse error: {e}")))?;
    let table = parsed
        .as_table()
        .ok_or_else(|| managed_policy_error(&path, "must be a TOML table at the top level"))?;

    let policy_meta = table.get("policy").and_then(|value| value.as_table());
    let name = policy_meta
        .and_then(|meta| meta.get("name"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let source = policy_meta
        .and_then(|meta| meta.get("source"))
        .and_then(|value| value.as_str())
        .map(str::to_string);

    let script_policy = table
        .get("script-policy")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| managed_policy_error(&path, "must set `script-policy` to a string"))
        })
        .transpose()?
        .map(|raw| ScriptPolicy::parse(raw).map_err(|e| managed_policy_error(&path, e.to_string())))
        .transpose()?;

    let minimum_release_age_secs = table
        .get("minimum-release-age-secs")
        .map(|value| parse_policy_u64(&path, "minimum-release-age-secs", value))
        .transpose()?
        .flatten();

    let sandbox = table.get("sandbox").and_then(|value| value.as_table());
    let sandbox_mode = sandbox
        .and_then(|tbl| tbl.get("mode"))
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| managed_policy_error(&path, "must set `[sandbox].mode` to a string"))
        })
        .transpose()?
        .map(|raw| {
            ResolvedSandboxMode::parse_for_security_floor(raw).ok_or_else(|| {
                managed_policy_error(&path, format!("has invalid `[sandbox].mode` value `{raw}`"))
            })
        })
        .transpose()?;
    let sandbox_allow_degraded = sandbox
        .and_then(|tbl| tbl.get("allow-degraded"))
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                managed_policy_error(&path, "must set `[sandbox].allow-degraded` to a boolean")
            })
        })
        .transpose()?;

    let sigstore = table.get("sigstore").and_then(|value| value.as_table());
    let sigstore_verify = sigstore
        .and_then(|tbl| tbl.get("verify"))
        .map(|value| {
            value.as_str().ok_or_else(|| {
                managed_policy_error(&path, "must set `[sigstore].verify` to a string")
            })
        })
        .transpose()?
        .map(|raw| parse_policy_sigstore(&path, raw))
        .transpose()?;

    let mut enforced_controls = Vec::new();
    if script_policy.is_some() {
        enforced_controls.push("script-policy".to_string());
    }
    if minimum_release_age_secs.is_some() {
        enforced_controls.push("minimum-release-age-secs".to_string());
    }
    if sandbox_mode.is_some() {
        enforced_controls.push("sandbox.mode".to_string());
    }
    if sandbox_allow_degraded.is_some() {
        enforced_controls.push("sandbox.allow-degraded".to_string());
    }
    if sigstore_verify.is_some() {
        enforced_controls.push("sigstore.verify".to_string());
    }

    Ok(Some(ManagedPolicy {
        status: ManagedPolicyStatus {
            path: path.display().to_string(),
            name,
            source,
            enforced_controls,
        },
        script_policy,
        minimum_release_age_secs,
        sandbox_mode,
        sandbox_allow_degraded,
        sigstore_verify,
    }))
}

fn signing_secret() -> Result<Vec<u8>, LpmError> {
    if let Some(raw) = test_secret_override() {
        return hex::decode(raw.trim()).map_err(|e| {
            LpmError::Registry(format!(
                "test security secret override must be valid hex: {e}"
            ))
        });
    }

    if force_file_audit_head_backend() {
        let path = signing_secret_path()?;
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            return hex::decode(raw.trim()).map_err(|e| {
                LpmError::Registry(format!(
                    "security approval file secret is corrupt; remove it and retry: {e}"
                ))
            });
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        std::fs::write(&path, format!("{}\n", hex::encode(secret)))?;
        return Ok(secret.to_vec());
    }

    let account = keyring_account(KEYRING_ACCOUNT)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| LpmError::Registry(format!("security approval keyring error: {e}")))?;

    if let Ok(existing) = entry.get_password() {
        return hex::decode(existing.trim()).map_err(|e| {
            LpmError::Registry(format!(
                "security approval keyring entry is corrupt; remove it and retry: {e}"
            ))
        });
    }

    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| LpmError::Registry(format!("security approval keyring write error: {e}")))?;
    Ok(secret.to_vec())
}

fn sign_payload_value(payload: &serde_json::Value) -> Result<String, LpmError> {
    let secret = signing_secret()?;
    let bytes = serde_json::to_vec(payload)?;
    let mut mac = HmacSha256::new_from_slice(&secret)
        .map_err(|e| LpmError::Registry(format!("security approval signer init failed: {e}")))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_payload_value(payload: &serde_json::Value, signature: &str) -> Result<bool, LpmError> {
    let secret = signing_secret()?;
    let expected = match hex::decode(signature.trim()) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let bytes = serde_json::to_vec(payload)?;
    let mut mac = HmacSha256::new_from_slice(&secret)
        .map_err(|e| LpmError::Registry(format!("security approval signer init failed: {e}")))?;
    mac.update(&bytes);
    Ok(mac.verify_slice(&expected).is_ok())
}

fn write_signed_json<T: Serialize + Clone>(path: &Path, payload: &T) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let payload_value = serde_json::to_value(payload)?;
    let envelope = SignedEnvelope {
        payload: payload.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    let body = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(path, body)?;
    Ok(())
}

fn read_signed_json<T>(path: &Path) -> Result<Option<T>, LpmError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path)?;
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| LpmError::Registry(format!("security approval file parse error: {e}")))?;
    let signature = parsed
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "security approval file {} is missing a signature",
                path.display()
            ))
        })?;
    let payload = parsed.get("payload").cloned().ok_or_else(|| {
        LpmError::Registry(format!(
            "security approval file {} is missing a payload",
            path.display()
        ))
    })?;
    if !verify_payload_value(&payload, signature)? {
        return Err(LpmError::Registry(format!(
            "security approval file {} failed signature verification",
            path.display()
        )));
    }
    let envelope: SignedEnvelope<T> = serde_json::from_value(parsed)
        .map_err(|e| LpmError::Registry(format!("security approval file parse error: {e}")))?;
    Ok(Some(envelope.payload))
}

pub fn load_authorized_posture() -> Result<AuthorizedPosture, LpmError> {
    Ok(read_signed_json(&approved_posture_path()?)?.unwrap_or_default())
}

pub fn load_effective_authorized_posture() -> Result<EffectiveAuthorizedPosture, LpmError> {
    let approved_path = approved_posture_path()?;
    let approved_posture_source = if approved_path.exists() {
        PostureSourceKind::ApprovedStore
    } else {
        PostureSourceKind::BuiltinDefault
    };
    let mut posture = load_authorized_posture()?;
    let mut sources = EffectivePostureSources::new(approved_posture_source);
    let managed_policy = load_managed_policy()?;

    if let Some(policy) = managed_policy.as_ref() {
        if let Some(script_policy) = policy.script_policy {
            posture.script_policy = script_policy.as_str().to_string();
            sources.script_policy = PostureSourceKind::ManagedPolicy;
        }
        if let Some(minimum_release_age_secs) = policy.minimum_release_age_secs {
            posture.minimum_release_age_secs = minimum_release_age_secs;
            sources.minimum_release_age_secs = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sandbox_mode) = policy.sandbox_mode {
            posture.sandbox_mode = sandbox_mode.as_str().to_string();
            sources.sandbox_mode = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sandbox_allow_degraded) = policy.sandbox_allow_degraded {
            posture.sandbox_allow_degraded = sandbox_allow_degraded;
            sources.sandbox_allow_degraded = PostureSourceKind::ManagedPolicy;
        }
        if let Some(sigstore_verify) = policy.sigstore_verify {
            posture.sigstore_verify =
                crate::security_floor::sigstore_mode_name(sigstore_verify).to_string();
            sources.sigstore_verify = PostureSourceKind::ManagedPolicy;
        }
    }

    Ok(EffectiveAuthorizedPosture {
        posture,
        sources,
        approved_posture_path: approved_path.display().to_string(),
        approved_posture_source,
        managed_policy: managed_policy.map(|policy| policy.status),
    })
}

pub fn persist_authorized_posture(posture: &AuthorizedPosture) -> Result<(), LpmError> {
    let mut normalized = posture.clone();
    normalized.schema_version = APPROVED_POSTURE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    write_signed_json(&approved_posture_path()?, &normalized)
}

pub fn is_automation(json_output: bool) -> bool {
    if test_native_auth_override().is_some() {
        return false;
    }
    json_output
        || !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || matches!(
            std::env::var("CI").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
        )
}

fn canonical_project_root(project_dir: &Path) -> String {
    std::fs::canonicalize(project_dir)
        .unwrap_or_else(|_| project_dir.to_path_buf())
        .display()
        .to_string()
}

fn canonical_global_root() -> Result<String, LpmError> {
    Ok(canonical_project_root(
        &lpm_common::LpmRoot::from_env()?.global_root(),
    ))
}

fn project_dir_is_global_install(project_dir: &Path) -> bool {
    let Ok(root) = lpm_common::LpmRoot::from_env() else {
        return false;
    };
    let global_installs = root.global_installs();
    let canonical_global_installs =
        std::fs::canonicalize(&global_installs).unwrap_or(global_installs);
    let canonical_project =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    canonical_project.starts_with(canonical_global_installs)
}

fn normalized_packages(packages: &[String]) -> Vec<String> {
    let mut values: Vec<_> = packages
        .iter()
        .map(|pkg| pkg.trim())
        .filter(|pkg| !pkg.is_empty())
        .map(str::to_string)
        .collect();
    values.sort();
    values.dedup();
    values
}

fn scope_rank(scope: ApprovalScope) -> usize {
    ApprovalScope::all_scopes()
        .iter()
        .position(|candidate| *candidate == scope)
        .unwrap_or(usize::MAX)
}

fn normalized_scopes(scopes: &[ApprovalScope]) -> Vec<ApprovalScope> {
    let mut values = scopes.to_vec();
    values.sort_by_key(|scope| scope_rank(*scope));
    values.dedup();
    values
}

fn scope_names(scopes: &[ApprovalScope]) -> Vec<String> {
    normalized_scopes(scopes)
        .into_iter()
        .map(|scope| scope.as_str().to_string())
        .collect()
}

fn format_scope_list(scopes: &[ApprovalScope]) -> String {
    scope_names(scopes).join(", ")
}

pub fn format_unlock_duration(ttl_secs: u64) -> String {
    if ttl_secs.is_multiple_of(86_400) {
        return format!("{}d", ttl_secs / 86_400);
    }
    if ttl_secs.is_multiple_of(3_600) {
        return format!("{}h", ttl_secs / 3_600);
    }
    if ttl_secs.is_multiple_of(60) {
        return format!("{}m", ttl_secs / 60);
    }
    format!("{ttl_secs}s")
}

fn suggested_unlock_command(scope: &str, target: UnlockTargetKind, packages: &[String]) -> String {
    let mut command = match target {
        UnlockTargetKind::Project => {
            format!("lpm security unlock {scope} --project . --ttl 10m")
        }
        UnlockTargetKind::Global => {
            format!("lpm security unlock {scope} --global --ttl 10m")
        }
    };
    for package in normalized_packages(packages) {
        command.push_str(&format!(" --package {package}"));
    }
    command
}

fn project_policy_state_path(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let root = canonical_project_root(project_dir);
    let id = hex::encode(Sha256::digest(root.as_bytes()));
    Ok(approved_projects_dir()?.join(format!("{id}.json")))
}

fn read_project_trusted_dependencies(
    project_dir: &Path,
) -> Result<lpm_workspace::TrustedDependencies, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Ok(lpm_workspace::TrustedDependencies::default());
    }
    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    Ok(pkg
        .lpm
        .map(|lpm| lpm.trusted_dependencies)
        .unwrap_or_default())
}

fn trusted_dependencies_snapshot(
    trusted: &lpm_workspace::TrustedDependencies,
) -> BTreeMap<String, crate::trust_snapshot::SnapshotEntry> {
    crate::trust_snapshot::TrustSnapshot::capture_current(trusted).bindings
}

fn current_trusted_scopes(project_dir: &Path) -> BTreeSet<String> {
    crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir)
        .trusted_scopes
        .into_iter()
        .collect()
}

pub fn authorized_capability_user_bound() -> crate::capability::UserBound {
    // Raw `[sandbox.limits]` in `~/.lpm/config.toml` is only a proposal layer.
    // Until LPM has an authenticated write path for capability ceilings, runtime
    // capability enforcement must fail closed rather than trust hand-edited user config.
    crate::capability::UserBound::default()
}

fn current_capability_request_hash(project_dir: &Path) -> Result<Option<String>, LpmError> {
    let user_bound = authorized_capability_user_bound();
    let capability_set =
        crate::capability::CapabilitySet::from_package_json(&project_dir.join("package.json"))
            .map_err(|e| LpmError::Registry(format!("{e}")))?;
    Ok(if capability_set.loosens_beyond(&user_bound) {
        Some(capability_set.canonical_hash())
    } else {
        None
    })
}

fn current_project_policy_state(
    project_dir: &Path,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    let trusted = read_project_trusted_dependencies(project_dir)?;
    candidate_project_policy_state(project_dir, &trusted)
}

fn candidate_project_policy_state(
    project_dir: &Path,
    trusted: &lpm_workspace::TrustedDependencies,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    let mut trusted_scopes: Vec<_> = current_trusted_scopes(project_dir).into_iter().collect();
    trusted_scopes.sort();
    Ok(ApprovedProjectPolicyState {
        schema_version: APPROVED_PROJECT_STATE_SCHEMA_VERSION,
        updated_at: Utc::now(),
        project_root: canonical_project_root(project_dir),
        trusted_dependencies: trusted_dependencies_snapshot(trusted),
        trusted_scopes,
        capability_request_hash: current_capability_request_hash(project_dir)?,
    })
}

fn load_approved_project_policy_state(
    project_dir: &Path,
) -> Result<ApprovedProjectPolicyState, LpmError> {
    Ok(
        read_signed_json(&project_policy_state_path(project_dir)?)?.unwrap_or_else(|| {
            ApprovedProjectPolicyState {
                schema_version: APPROVED_PROJECT_STATE_SCHEMA_VERSION,
                updated_at: Utc::now(),
                project_root: canonical_project_root(project_dir),
                trusted_dependencies: BTreeMap::new(),
                trusted_scopes: Vec::new(),
                capability_request_hash: None,
            }
        }),
    )
}

fn persist_project_policy_state(
    project_dir: &Path,
    state: &ApprovedProjectPolicyState,
) -> Result<(), LpmError> {
    let mut normalized = state.clone();
    normalized.schema_version = APPROVED_PROJECT_STATE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    normalized.project_root = canonical_project_root(project_dir);
    normalized.trusted_scopes.sort();
    normalized.trusted_scopes.dedup();
    write_signed_json(&project_policy_state_path(project_dir)?, &normalized)
}

fn current_global_trust_state(
    root: &lpm_common::LpmRoot,
) -> Result<ApprovedGlobalTrustState, LpmError> {
    let trust = lpm_global::trusted_deps::read_for(root)?;
    Ok(candidate_global_trust_state(&trust))
}

fn candidate_global_trust_state(
    trust: &lpm_global::GlobalTrustedDependencies,
) -> ApprovedGlobalTrustState {
    ApprovedGlobalTrustState {
        schema_version: APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION,
        updated_at: Utc::now(),
        trusted_dependencies: trust.trusted.clone(),
    }
}

fn load_approved_global_trust_state() -> Result<ApprovedGlobalTrustState, LpmError> {
    Ok(
        read_signed_json(&approved_global_trust_path()?)?.unwrap_or(ApprovedGlobalTrustState {
            schema_version: APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION,
            updated_at: Utc::now(),
            trusted_dependencies: BTreeMap::new(),
        }),
    )
}

fn persist_global_trust_state(state: &ApprovedGlobalTrustState) -> Result<(), LpmError> {
    let mut normalized = state.clone();
    normalized.schema_version = APPROVED_GLOBAL_TRUST_STATE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    write_signed_json(&approved_global_trust_path()?, &normalized)
}

fn audit_signature_payload(
    event: &AuditEvent,
    previous_entry_hash: &Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "payload": event,
        "previous_entry_hash": previous_entry_hash,
    })
}

fn hash_json_value(value: &serde_json::Value) -> Result<String, LpmError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn verify_audit_envelope(
    envelope: &SignedAuditEnvelope,
    expected_previous: &Option<String>,
) -> Result<(), LpmError> {
    if &envelope.previous_entry_hash != expected_previous {
        return Err(LpmError::Registry(
            "security audit log hash chain is broken; possible tampering".into(),
        ));
    }
    let payload_value = audit_signature_payload(&envelope.payload, &envelope.previous_entry_hash);
    if hash_json_value(&payload_value)? != envelope.entry_hash {
        return Err(LpmError::Registry(
            "security audit log entry hash does not match payload; possible tampering".into(),
        ));
    }
    if !verify_payload_value(&payload_value, &envelope.signature)? {
        return Err(LpmError::Registry(
            "security audit log entry failed signature verification; possible tampering".into(),
        ));
    }
    Ok(())
}

fn legacy_audit_entry_hash(parsed: &serde_json::Value) -> Result<String, LpmError> {
    let signature = parsed
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("legacy security audit log entry is missing a signature".into())
        })?;
    let payload = parsed.get("payload").cloned().ok_or_else(|| {
        LpmError::Registry("legacy security audit log entry is missing a payload".into())
    })?;
    if !verify_payload_value(&payload, signature)? {
        return Err(LpmError::Registry(
            "legacy security audit log entry failed signature verification; possible tampering"
                .into(),
        ));
    }
    let _: SignedEnvelope<AuditEvent> = serde_json::from_value(parsed.clone()).map_err(|e| {
        LpmError::Registry(format!("legacy security audit log entry parse error: {e}"))
    })?;
    hash_json_value(parsed)
}

fn read_audit_log_tail(path: &Path) -> Result<(Option<String>, u64), LpmError> {
    if !path.exists() {
        return Ok((None, 0));
    }
    let body = std::fs::read_to_string(path)?;
    let mut previous = None;
    let mut count = 0;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let parsed: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            LpmError::Registry(format!("security audit log entry parse error: {e}"))
        })?;
        if parsed.get("entry_hash").is_some() || parsed.get("previous_entry_hash").is_some() {
            let envelope: SignedAuditEnvelope = serde_json::from_value(parsed).map_err(|e| {
                LpmError::Registry(format!("security audit log entry parse error: {e}"))
            })?;
            verify_audit_envelope(&envelope, &previous)?;
            previous = Some(envelope.entry_hash);
        } else {
            previous = Some(legacy_audit_entry_hash(&parsed)?);
        }
        count += 1;
    }
    Ok((previous, count))
}

#[cfg(test)]
fn load_audit_head() -> Result<Option<AuditHead>, LpmError> {
    read_signed_json(&audit_head_path()?)
}

#[cfg(test)]
fn persist_audit_head(head: &AuditHead) -> Result<(), LpmError> {
    write_signed_json(&audit_head_path()?, head)
}

#[cfg(not(test))]
fn load_audit_head() -> Result<Option<AuditHead>, LpmError> {
    if force_file_audit_head_backend() {
        return read_signed_json(&audit_head_path()?);
    }

    let account = keyring_account(KEYRING_AUDIT_HEAD_ACCOUNT)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| LpmError::Registry(format!("security audit keyring error: {e}")))?;
    let raw = match entry.get_password() {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => {
            return Err(LpmError::Registry(format!(
                "security audit keyring read error: {e}"
            )));
        }
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("security audit head parse error: {e}")))?;
    let signature = parsed
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("security audit head is missing a signature".into()))?;
    let payload = parsed
        .get("payload")
        .cloned()
        .ok_or_else(|| LpmError::Registry("security audit head is missing a payload".into()))?;
    if !verify_payload_value(&payload, signature)? {
        return Err(LpmError::Registry(
            "security audit head failed signature verification; possible tampering".into(),
        ));
    }
    let envelope: SignedEnvelope<AuditHead> = serde_json::from_value(parsed)
        .map_err(|e| LpmError::Registry(format!("security audit head parse error: {e}")))?;
    Ok(Some(envelope.payload))
}

#[cfg(not(test))]
fn persist_audit_head(head: &AuditHead) -> Result<(), LpmError> {
    if force_file_audit_head_backend() {
        return write_signed_json(&audit_head_path()?, head);
    }

    let payload_value = serde_json::to_value(head)?;
    let envelope = SignedEnvelope {
        payload: head.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    let body = serde_json::to_string(&envelope)?;
    let account = keyring_account(KEYRING_AUDIT_HEAD_ACCOUNT)?;
    keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| LpmError::Registry(format!("security audit keyring error: {e}")))?
        .set_password(&body)
        .map_err(|e| LpmError::Registry(format!("security audit keyring write error: {e}")))?;
    Ok(())
}

fn append_audit_event(event: &AuditEvent) -> Result<(), LpmError> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (previous_entry_hash, entry_count) = read_audit_log_tail(&path)?;
    if let Some(head) = load_audit_head()?
        && (head.last_entry_hash != previous_entry_hash.as_deref().unwrap_or_default()
            || head.entry_count != entry_count)
    {
        return Err(LpmError::Registry(
            "security audit log does not match the signed audit head; possible tampering".into(),
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let payload_value = audit_signature_payload(event, &previous_entry_hash);
    let entry_hash = hash_json_value(&payload_value)?;
    let envelope = SignedAuditEnvelope {
        payload: event.clone(),
        previous_entry_hash,
        entry_hash: entry_hash.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    writeln!(file, "{}", serde_json::to_string(&envelope)?)?;
    persist_audit_head(&AuditHead {
        schema_version: AUDIT_HEAD_SCHEMA_VERSION,
        updated_at: Utc::now(),
        last_entry_hash: entry_hash,
        entry_count: entry_count + 1,
    })?;
    Ok(())
}

struct AuditRecord {
    event: String,
    allowed: bool,
    scopes: Vec<String>,
    project_root: Option<String>,
    packages: Vec<String>,
    source: Option<String>,
    unlock_id: Option<String>,
    detail: Option<String>,
}

impl AuditRecord {
    fn new(event: impl Into<String>, allowed: bool, scopes: Vec<String>) -> Self {
        Self {
            event: event.into(),
            allowed,
            scopes,
            project_root: None,
            packages: Vec::new(),
            source: None,
            unlock_id: None,
            detail: None,
        }
    }

    fn project_root(mut self, project_root: impl Into<String>) -> Self {
        self.project_root = Some(project_root.into());
        self
    }

    fn packages(mut self, packages: Vec<String>) -> Self {
        self.packages = packages;
        self
    }

    fn source(mut self, source: ApprovalSource) -> Self {
        self.source = Some(source.as_str().to_string());
        self
    }

    fn unlock_id(mut self, unlock_id: String) -> Self {
        self.unlock_id = Some(unlock_id);
        self
    }

    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

fn record_audit_event(record: AuditRecord) {
    let event = AuditEvent {
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        occurred_at: Utc::now(),
        event: record.event,
        allowed: record.allowed,
        scopes: record.scopes,
        project_root: record.project_root,
        packages: normalized_packages(&record.packages),
        source: record.source,
        unlock_id: record.unlock_id,
        detail: record.detail,
    };
    if let Err(err) = append_audit_event(&event) {
        tracing::warn!("failed to append security audit event: {err}");
    }
}

fn managed_policy_write_error(
    managed_policy: &ManagedPolicyStatus,
    knob: &str,
    requested: impl AsRef<str>,
    enforced: impl AsRef<str>,
) -> LpmError {
    LpmError::SecurityFloor(format!(
        "managed security policy `{}` keeps `{knob}` at `{}`. Update that higher-authority policy before setting `{knob}` to `{}` here.",
        managed_policy.path,
        enforced.as_ref(),
        requested.as_ref(),
    ))
}

fn managed_policy_scope_error(
    managed_policy: &ManagedPolicyStatus,
    scope: ApprovalScope,
    control: &str,
) -> LpmError {
    LpmError::SecurityFloor(format!(
        "managed security policy `{}` owns `{control}`, so `{}` cannot be unlocked here. Update that higher-authority policy before weakening this control.",
        managed_policy.path,
        scope.as_str(),
    ))
}

fn managed_policy_blocks_scope(
    effective: &EffectiveAuthorizedPosture,
    scope: ApprovalScope,
) -> Option<LpmError> {
    let managed_policy = effective.managed_policy.as_ref()?;
    let blocked_control = match scope {
        ApprovalScope::ScriptsAllow | ApprovalScope::ScriptsTriage
            if matches!(
                effective.sources.script_policy,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("script-policy")
        }
        ApprovalScope::CooldownBypass | ApprovalScope::CooldownWindow
            if matches!(
                effective.sources.minimum_release_age_secs,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("minimum-release-age-secs")
        }
        ApprovalScope::SandboxDefault | ApprovalScope::SandboxNone
            if matches!(
                effective.sources.sandbox_mode,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sandbox.mode")
        }
        ApprovalScope::SandboxAllowDegraded
            if matches!(
                effective.sources.sandbox_allow_degraded,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sandbox.allow-degraded")
        }
        ApprovalScope::ProvenanceUnverified | ApprovalScope::ProvenanceIgnoreDrift
            if matches!(
                effective.sources.sigstore_verify,
                PostureSourceKind::ManagedPolicy
            ) =>
        {
            Some("sigstore.verify")
        }
        _ => None,
    }?;
    Some(managed_policy_scope_error(
        managed_policy,
        scope,
        blocked_control,
    ))
}

fn approval_source_for_enforce_source(
    source: crate::provenance_fetch::EnforceModeSource,
) -> ApprovalSource {
    match source {
        crate::provenance_fetch::EnforceModeSource::Env => ApprovalSource::EnvVar,
        crate::provenance_fetch::EnforceModeSource::Config => ApprovalSource::GlobalConfig,
        crate::provenance_fetch::EnforceModeSource::Default => ApprovalSource::SecurityCommand,
    }
}

pub fn approval_required_error(
    message: impl Into<String>,
    requested_scopes: Vec<String>,
    project_root: Option<String>,
    suggested_command: Option<String>,
) -> LpmError {
    LpmError::SecurityApprovalRequired {
        message: message.into(),
        requested_scopes,
        project_root,
        suggested_command,
    }
}

fn create_unlock_grant_for_scopes(
    scopes: &[ApprovalScope],
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> UnlockGrant {
    let now = Utc::now();
    UnlockGrant {
        schema_version: UNLOCK_SCHEMA_VERSION,
        id: format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        target: UnlockTargetKind::Project,
        project_root: Some(canonical_project_root(project_dir)),
        scopes: normalized_scopes(scopes),
        packages: normalized_packages(packages),
        limits: UnlockLimits {
            min_release_age_secs,
        },
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        issuer: "user-presence".to_string(),
    }
}

fn create_unlock_grant(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> UnlockGrant {
    create_unlock_grant_for_scopes(
        &[scope],
        project_dir,
        ttl_secs,
        min_release_age_secs,
        packages,
    )
}

fn create_global_unlock_grant_for_scopes(
    scopes: &[ApprovalScope],
    ttl_secs: u64,
    packages: &[String],
) -> UnlockGrant {
    let now = Utc::now();
    UnlockGrant {
        schema_version: UNLOCK_SCHEMA_VERSION,
        id: format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        target: UnlockTargetKind::Global,
        project_root: None,
        scopes: normalized_scopes(scopes),
        packages: normalized_packages(packages),
        limits: UnlockLimits::default(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        issuer: "user-presence".to_string(),
    }
}

fn create_global_unlock_grant(
    scope: ApprovalScope,
    ttl_secs: u64,
    packages: &[String],
) -> UnlockGrant {
    create_global_unlock_grant_for_scopes(&[scope], ttl_secs, packages)
}

fn persist_unlock_grant(grant: &UnlockGrant) -> Result<(), LpmError> {
    let path = unlocks_dir()?.join(format!("{}.json", grant.id));
    write_signed_json(&path, grant)
}

fn read_active_unlock_entries() -> Result<Vec<StoredUnlockGrant>, LpmError> {
    let dir = unlocks_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut grants = Vec::new();
    let now = Utc::now();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        match read_signed_json::<UnlockGrant>(&path) {
            Ok(Some(grant)) if grant.expires_at > now => {
                grants.push(StoredUnlockGrant { path, grant })
            }
            Ok(Some(_expired)) => {
                let _ = std::fs::remove_file(&path);
            }
            Ok(None) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(grants)
}

fn read_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    Ok(read_active_unlock_entries()?
        .into_iter()
        .map(|entry| entry.grant)
        .collect())
}

pub fn list_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    let mut grants = read_active_unlocks()?;
    grants.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
    Ok(grants)
}

pub fn list_active_global_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    let mut grants: Vec<_> = read_active_unlocks()?
        .into_iter()
        .filter(|grant| grant.target == UnlockTargetKind::Global)
        .collect();
    grants.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
    Ok(grants)
}

pub fn list_active_project_unlocks(project_dir: &Path) -> Result<Vec<UnlockGrant>, LpmError> {
    let root = canonical_project_root(project_dir);
    let mut grants: Vec<_> = read_active_unlocks()?
        .into_iter()
        .filter(|grant| {
            grant.target == UnlockTargetKind::Project
                && grant.project_root.as_deref() == Some(root.as_str())
        })
        .collect();
    grants.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
    Ok(grants)
}

fn active_runtime_overrides(effective: &EffectiveAuthorizedPosture) -> Vec<RuntimeOverride> {
    let env_value = std::env::var("LPM_PROVENANCE_ENFORCE").ok();
    let global = crate::commands::config::GlobalConfig::load();
    let (mode, source) =
        EnforceMode::resolve_from_chain(env_value.as_deref(), || global.get_sigstore_verify());
    let effective_mode = effective.posture.sigstore_verify();
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) && mode != effective_mode
    {
        return vec![RuntimeOverride {
            control: "sigstore.verify".to_string(),
            value: crate::security_floor::sigstore_mode_name(mode).to_string(),
            source: match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "LPM_PROVENANCE_ENFORCE".to_string()
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "~/.lpm/config.toml [sigstore].verify".to_string()
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
        }];
    }
    Vec::new()
}

pub fn load_security_status(
    project_dir: Option<&Path>,
    global: bool,
) -> Result<SecurityStatus, LpmError> {
    let effective = load_effective_authorized_posture()?;
    let active_runtime_overrides = active_runtime_overrides(&effective);
    let (target, project_root, active_unlocks) = if global {
        (
            UnlockTargetKind::Global,
            Some(canonical_global_root()?),
            list_active_global_unlocks()?,
        )
    } else {
        match project_dir {
            Some(dir) => (
                UnlockTargetKind::Project,
                Some(canonical_project_root(dir)),
                list_active_project_unlocks(dir)?,
            ),
            None => (UnlockTargetKind::Project, None, list_active_unlocks()?),
        }
    };

    Ok(SecurityStatus {
        target,
        project_root,
        effective_floor: effective.posture.to_view(),
        floor_sources: effective.sources,
        approved_posture_path: effective.approved_posture_path,
        approved_posture_source: effective.approved_posture_source,
        managed_policy: effective.managed_policy,
        active_runtime_overrides,
        active_unlocks,
    })
}

fn grant_matches_lock_request(
    grant: &UnlockGrant,
    target: UnlockTargetKind,
    project_root: Option<&str>,
    scopes: &[ApprovalScope],
    packages: &[String],
) -> bool {
    if grant.target != target {
        return false;
    }
    if target == UnlockTargetKind::Project && grant.project_root.as_deref() != project_root {
        return false;
    }
    if !grant.scopes.iter().any(|scope| scopes.contains(scope)) {
        return false;
    }
    packages.is_empty() || grant.packages == packages
}

fn revoke_unlocks(
    selector: &str,
    target: UnlockTargetKind,
    project_root: Option<&Path>,
    scopes: &[ApprovalScope],
    packages: &[String],
) -> Result<Vec<UnlockRevocation>, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }

    let requested_packages = normalized_packages(packages);
    let project_root = project_root.map(canonical_project_root);
    let mut revocations = Vec::new();

    for entry in read_active_unlock_entries()? {
        if !grant_matches_lock_request(
            &entry.grant,
            target,
            project_root.as_deref(),
            &requested_scopes,
            &requested_packages,
        ) {
            continue;
        }

        let revoked_scopes: Vec<_> = entry
            .grant
            .scopes
            .iter()
            .copied()
            .filter(|scope| requested_scopes.contains(scope))
            .collect();
        let remaining_scopes: Vec<_> = entry
            .grant
            .scopes
            .iter()
            .copied()
            .filter(|scope| !requested_scopes.contains(scope))
            .collect();
        let revoked_scopes = normalized_scopes(&revoked_scopes);
        let remaining_scopes = normalized_scopes(&remaining_scopes);

        if remaining_scopes.is_empty() {
            std::fs::remove_file(&entry.path)?;
        } else {
            let mut updated = entry.grant.clone();
            updated.scopes = remaining_scopes.clone();
            write_signed_json(&entry.path, &updated)?;
        }

        let mut audit = AuditRecord::new("unlock-revoked", true, scope_names(&revoked_scopes))
            .packages(entry.grant.packages.clone())
            .source(ApprovalSource::SecurityCommand)
            .unlock_id(entry.grant.id.clone());
        if let Some(root) = entry.grant.project_root.clone() {
            audit = audit.project_root(root);
        }
        let detail = if remaining_scopes.is_empty() {
            format!("temporary unlock revoked for {selector}")
        } else {
            format!(
                "temporary unlock narrowed for {selector}; remaining scopes: {}",
                format_scope_list(&remaining_scopes)
            )
        };
        record_audit_event(audit.detail(detail));

        revocations.push(UnlockRevocation {
            id: entry.grant.id,
            target: entry.grant.target,
            project_root: entry.grant.project_root,
            revoked_scopes,
            remaining_scopes,
            packages: entry.grant.packages,
            expires_at: entry.grant.expires_at,
        });
    }

    Ok(revocations)
}

pub fn lock_project_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    project_dir: &Path,
    packages: &[String],
) -> Result<Vec<UnlockRevocation>, LpmError> {
    revoke_unlocks(
        selector,
        UnlockTargetKind::Project,
        Some(project_dir),
        scopes,
        packages,
    )
}

pub fn lock_global_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    packages: &[String],
) -> Result<Vec<UnlockRevocation>, LpmError> {
    revoke_unlocks(selector, UnlockTargetKind::Global, None, scopes, packages)
}

fn trusted_dependencies_widened(
    current: &BTreeMap<String, crate::trust_snapshot::SnapshotEntry>,
    approved: &BTreeMap<String, crate::trust_snapshot::SnapshotEntry>,
) -> bool {
    current
        .iter()
        .any(|(key, value)| approved.get(key) != Some(value))
}

fn trusted_scopes_widened(current: &[String], approved: &[String]) -> bool {
    let approved_set: BTreeSet<_> = approved.iter().map(String::as_str).collect();
    current
        .iter()
        .any(|scope| !approved_set.contains(scope.as_str()))
}

fn capability_request_widened(current: Option<&String>, approved: Option<&String>) -> bool {
    match current {
        Some(hash) => approved != Some(hash),
        None => false,
    }
}

fn project_policy_required_scopes(
    current: &ApprovedProjectPolicyState,
    approved: &ApprovedProjectPolicyState,
) -> Vec<ApprovalScope> {
    let mut scopes = Vec::new();
    if trusted_dependencies_widened(
        &current.trusted_dependencies,
        &approved.trusted_dependencies,
    ) {
        scopes.push(ApprovalScope::TrustBulkApprove);
    }
    if trusted_scopes_widened(&current.trusted_scopes, &approved.trusted_scopes) {
        scopes.push(ApprovalScope::TrustScopeWiden);
    }
    if capability_request_widened(
        current.capability_request_hash.as_ref(),
        approved.capability_request_hash.as_ref(),
    ) {
        scopes.push(ApprovalScope::CapabilityWiden);
    }
    scopes
}

fn same_project_policy_shape(
    current: &ApprovedProjectPolicyState,
    approved: &ApprovedProjectPolicyState,
) -> bool {
    current.project_root == approved.project_root
        && current.trusted_dependencies == approved.trusted_dependencies
        && current.trusted_scopes == approved.trusted_scopes
        && current.capability_request_hash == approved.capability_request_hash
}

fn global_trust_widened(
    current: &BTreeMap<String, lpm_global::TrustedDependencyBinding>,
    approved: &BTreeMap<String, lpm_global::TrustedDependencyBinding>,
) -> bool {
    current
        .iter()
        .any(|(key, value)| approved.get(key) != Some(value))
}

fn unlock_grant_covers_packages(grant: &UnlockGrant, packages: &[String]) -> bool {
    let requested_packages = normalized_packages(packages);
    match (grant.packages.is_empty(), requested_packages.is_empty()) {
        (true, _) => true,
        (false, true) => false,
        (false, false) => {
            let granted: BTreeSet<_> = grant.packages.iter().map(String::as_str).collect();
            requested_packages
                .iter()
                .all(|package| granted.contains(package.as_str()))
        }
    }
}

fn same_global_trust_shape(
    current: &ApprovedGlobalTrustState,
    approved: &ApprovedGlobalTrustState,
) -> bool {
    current.trusted_dependencies == approved.trusted_dependencies
}

fn approval_required_for_scopes(
    message: impl Into<String>,
    scopes: &[ApprovalScope],
    project_root: Option<String>,
) -> LpmError {
    let requested_scopes: Vec<_> = scopes
        .iter()
        .map(|scope| scope.as_str().to_string())
        .collect();
    let suggested_command = scopes
        .first()
        .map(|scope| suggested_unlock_command(scope.as_str(), UnlockTargetKind::Project, &[]));
    approval_required_error(message, requested_scopes, project_root, suggested_command)
}

fn ensure_project_policy_candidate_authorized(
    project_dir: &Path,
    current: &ApprovedProjectPolicyState,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let approved = load_approved_project_policy_state(project_dir)?;
    let required_scopes = project_policy_required_scopes(current, &approved);
    if required_scopes.is_empty() {
        if !same_project_policy_shape(current, &approved) {
            persist_project_policy_state(project_dir, current)?;
        }
        return Ok(());
    }

    let mut missing_scopes = Vec::new();
    for scope in &required_scopes {
        if !has_active_project_unlock(*scope, project_dir, None, &[])? {
            missing_scopes.push(*scope);
        }
    }
    if !missing_scopes.is_empty() {
        let message =
            "project trust or capability state changed outside an LPM-managed approval flow";
        record_audit_event(
            AuditRecord::new(
                "guarded-attempt",
                false,
                missing_scopes
                    .iter()
                    .map(|scope| scope.as_str().to_string())
                    .collect(),
            )
            .project_root(canonical_project_root(project_dir))
            .source(source)
            .detail(message),
        );
        if matches!(source, ApprovalSource::CliFlag) && !is_automation(json_output) {
            for scope in &missing_scopes {
                prompt_for_unlock(
                    *scope,
                    project_dir,
                    DEFAULT_UNLOCK_TTL_SECS,
                    None,
                    &[],
                    message,
                )?;
            }
        } else {
            return Err(approval_required_for_scopes(
                message,
                &missing_scopes,
                Some(canonical_project_root(project_dir)),
            ));
        }
    }

    persist_project_policy_state(project_dir, current)?;
    record_audit_event(
        AuditRecord::new(
            "project-policy-authorized",
            true,
            required_scopes
                .iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
        )
        .project_root(canonical_project_root(project_dir))
        .source(source)
        .detail("persisted approved project trust/capability state"),
    );
    Ok(())
}

pub fn ensure_project_policy_authorized(
    project_dir: &Path,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = current_project_policy_state(project_dir)?;
    ensure_project_policy_candidate_authorized(project_dir, &current, json_output, source)
}

pub fn ensure_project_trust_candidate_authorized(
    project_dir: &Path,
    trusted: &lpm_workspace::TrustedDependencies,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = candidate_project_policy_state(project_dir, trusted)?;
    ensure_project_policy_candidate_authorized(project_dir, &current, json_output, source)
}

pub fn ensure_global_trust_authorized(
    root: &lpm_common::LpmRoot,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = current_global_trust_state(root)?;
    ensure_global_trust_candidate_authorized(&current, json_output, source)
}

fn ensure_global_trust_candidate_authorized(
    current: &ApprovedGlobalTrustState,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let approved = load_approved_global_trust_state()?;
    if !global_trust_widened(
        &current.trusted_dependencies,
        &approved.trusted_dependencies,
    ) {
        if !same_global_trust_shape(current, &approved) {
            persist_global_trust_state(current)?;
        }
        return Ok(());
    }

    ensure_global_unlock(
        ApprovalScope::TrustBulkApprove,
        json_output,
        source,
        "global trust approvals changed outside an LPM-managed approval flow",
        &[],
    )?;
    persist_global_trust_state(current)?;
    record_audit_event(
        AuditRecord::new(
            "global-trust-authorized",
            true,
            vec![ApprovalScope::TrustBulkApprove.as_str().to_string()],
        )
        .source(source)
        .detail("persisted approved global trust state"),
    );
    Ok(())
}

pub fn ensure_global_trust_candidate_authorized_from_trust(
    root: &lpm_common::LpmRoot,
    trust: &lpm_global::GlobalTrustedDependencies,
    json_output: bool,
    source: ApprovalSource,
) -> Result<(), LpmError> {
    let current = candidate_global_trust_state(trust);
    let _ = root;
    ensure_global_trust_candidate_authorized(&current, json_output, source)
}

fn find_active_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<Option<UnlockGrant>, LpmError> {
    let root = canonical_project_root(project_dir);
    for grant in read_active_unlocks()? {
        if grant.target != UnlockTargetKind::Project {
            continue;
        }
        if grant.project_root.as_deref() != Some(root.as_str()) {
            continue;
        }
        if !grant.scopes.contains(&scope) {
            continue;
        }
        if let Some(requested_secs) = min_release_age_secs
            && let Some(limit) = grant.limits.min_release_age_secs
            && requested_secs < limit
        {
            continue;
        }
        if !unlock_grant_covers_packages(&grant, packages) {
            continue;
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

pub fn has_active_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<bool, LpmError> {
    Ok(find_active_project_unlock(scope, project_dir, min_release_age_secs, packages)?.is_some())
}

fn find_active_global_unlock(
    scope: ApprovalScope,
    packages: &[String],
) -> Result<Option<UnlockGrant>, LpmError> {
    for grant in read_active_unlocks()? {
        if grant.target != UnlockTargetKind::Global {
            continue;
        }
        if !grant.scopes.contains(&scope) {
            continue;
        }
        if !unlock_grant_covers_packages(&grant, packages) {
            continue;
        }
        return Ok(Some(grant));
    }
    Ok(None)
}

fn run_native_auth_command(mut command: Command) -> Result<bool, LpmError> {
    match command.status() {
        Ok(status) => Ok(status.success()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(LpmError::Registry(
            "native security approval is unavailable on this machine; use managed policy or install a supported desktop auth backend".into(),
        )),
        Err(err) => Err(LpmError::Registry(format!(
            "native security approval failed to launch: {err}"
        ))),
    }
}

#[allow(unused_variables)]
fn request_native_approval(prompt: &str) -> Result<bool, LpmError> {
    if let Some(result) = test_native_auth_override() {
        return match result.as_str() {
            "approve" => Ok(true),
            "deny" => Ok(false),
            "error" => Err(LpmError::Registry(
                "test native security approval backend forced an error".into(),
            )),
            other => Err(LpmError::Registry(format!(
                "test native security approval override must be one of: approve | deny | error (got `{other}`)"
            ))),
        };
    }

    #[cfg(target_os = "macos")]
    {
        fn escape_applescript(value: &str) -> String {
            value.replace('\\', "\\\\").replace('"', "\\\"")
        }

        let script = format!(
            "do shell script \"/usr/bin/true\" with administrator privileges with prompt \"{}\"",
            escape_applescript(prompt)
        );
        return run_native_auth_command({
            let mut command = Command::new("osascript");
            command.arg("-e").arg(script);
            command
        });
    }

    #[cfg(target_os = "linux")]
    {
        return run_native_auth_command({
            let mut command = Command::new("pkexec");
            command.arg("/bin/true");
            command
        });
    }

    #[cfg(target_os = "windows")]
    {
        return run_native_auth_command({
            let mut command = Command::new("powershell");
            command.args([
                "-NoProfile",
                "-Command",
                "Start-Process -FilePath powershell -ArgumentList '-NoProfile -Command exit 0' -Verb RunAs -Wait",
            ]);
            command
        });
    }

    #[allow(unreachable_code)]
    Err(LpmError::Registry(format!(
        "native security approval is not implemented for this platform; prompt was: {prompt}"
    )))
}

fn prompt_for_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    packages: &[String],
    message: &str,
) -> Result<(), LpmError> {
    crate::output::warn(message);
    let prompt = format!(
        "Approve {} for this project for {}?",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    );
    let confirmed = request_native_approval(&prompt)?;

    if !confirmed {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(ApprovalSource::CliFlag)
                .detail(format!("user declined {}", scope.as_str())),
        );
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                scope.as_str(),
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }

    let grant = create_unlock_grant(scope, project_dir, ttl_secs, min_release_age_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, vec![scope.as_str().to_string()])
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(ApprovalSource::CliFlag)
            .unlock_id(grant.id)
            .detail(format!("temporary unlock granted for {}", scope.as_str())),
    );
    crate::output::success(&format!(
        "Approved {} for this project for {}.",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    ));
    Ok(())
}

pub fn ensure_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    json_output: bool,
    source: ApprovalSource,
    message: &str,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(err) = managed_policy_blocks_scope(&effective, scope) {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(source)
                .detail(message),
        );
        return Err(err);
    }
    if project_dir_is_global_install(project_dir) {
        return ensure_global_unlock(scope, json_output, source, message, packages);
    }
    if let Some(grant) =
        find_active_project_unlock(scope, project_dir, min_release_age_secs, packages)?
    {
        record_audit_event(
            AuditRecord::new("guarded-attempt", true, vec![scope.as_str().to_string()])
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(source)
                .unlock_id(grant.id)
                .detail(message),
        );
        return Ok(());
    }

    if matches!(source, ApprovalSource::CliFlag | ApprovalSource::EnvVar)
        && !is_automation(json_output)
    {
        return prompt_for_unlock(
            scope,
            project_dir,
            DEFAULT_UNLOCK_TTL_SECS,
            min_release_age_secs,
            packages,
            message,
        );
    }

    record_audit_event(
        AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(source)
            .detail(message),
    );
    Err(approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        Some(canonical_project_root(project_dir)),
        Some(suggested_unlock_command(
            scope.as_str(),
            UnlockTargetKind::Project,
            packages,
        )),
    ))
}

fn prompt_for_global_unlock(
    scope: ApprovalScope,
    ttl_secs: u64,
    packages: &[String],
    message: &str,
) -> Result<(), LpmError> {
    crate::output::warn(message);
    let prompt = format!(
        "Approve {} globally for {}?",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    );
    let confirmed = request_native_approval(&prompt)?;

    if !confirmed {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(ApprovalSource::CliFlag)
                .detail(format!("user declined {}", scope.as_str())),
        );
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            None,
            Some(suggested_unlock_command(
                scope.as_str(),
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }

    let grant = create_global_unlock_grant(scope, ttl_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, vec![scope.as_str().to_string()])
            .packages(packages.to_vec())
            .source(ApprovalSource::CliFlag)
            .unlock_id(grant.id)
            .detail(format!(
                "temporary global unlock granted for {}",
                scope.as_str()
            )),
    );
    crate::output::success(&format!(
        "Approved {} globally for {}.",
        scope.as_str(),
        format_unlock_duration(ttl_secs),
    ));
    Ok(())
}

pub fn ensure_global_unlock(
    scope: ApprovalScope,
    json_output: bool,
    source: ApprovalSource,
    message: &str,
    packages: &[String],
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(err) = managed_policy_blocks_scope(&effective, scope) {
        record_audit_event(
            AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(source)
                .detail(message),
        );
        return Err(err);
    }
    if let Some(grant) = find_active_global_unlock(scope, packages)? {
        record_audit_event(
            AuditRecord::new("guarded-attempt", true, vec![scope.as_str().to_string()])
                .packages(packages.to_vec())
                .source(source)
                .unlock_id(grant.id)
                .detail(message),
        );
        return Ok(());
    }

    if matches!(source, ApprovalSource::CliFlag | ApprovalSource::EnvVar)
        && !is_automation(json_output)
    {
        return prompt_for_global_unlock(scope, DEFAULT_UNLOCK_TTL_SECS, packages, message);
    }

    record_audit_event(
        AuditRecord::new("guarded-attempt", false, vec![scope.as_str().to_string()])
            .packages(packages.to_vec())
            .source(source)
            .detail(message),
    );
    Err(approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        None,
        Some(suggested_unlock_command(
            scope.as_str(),
            UnlockTargetKind::Global,
            packages,
        )),
    ))
}

fn confirm_persistent_weakening(
    scope: ApprovalScope,
    json_output: bool,
    command_hint: &str,
    message: &str,
) -> Result<(), LpmError> {
    if is_automation(json_output) {
        record_persistent_guarded_attempt(scope, false, message);
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }

    crate::output::warn(message);
    let confirmed =
        request_native_approval("Approve this persistent machine-level security change now?")?;
    if !confirmed {
        record_persistent_guarded_attempt(scope, false, message);
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }
    record_persistent_guarded_attempt(scope, true, message);
    Ok(())
}

fn record_persistent_guarded_attempt(scope: ApprovalScope, allowed: bool, detail: &str) {
    record_audit_event(
        AuditRecord::new(
            "persistent-guarded-attempt",
            allowed,
            vec![scope.as_str().to_string()],
        )
        .source(ApprovalSource::ConfigMutation)
        .detail(detail),
    );
}

fn approval_scope_for_script_policy(requested: ScriptPolicy) -> ApprovalScope {
    match requested {
        ScriptPolicy::Allow => ApprovalScope::ScriptsAllow,
        ScriptPolicy::Triage | ScriptPolicy::Deny => ApprovalScope::ScriptsTriage,
    }
}

fn approval_scope_for_sandbox_mode(requested: ResolvedSandboxMode) -> ApprovalScope {
    match requested {
        ResolvedSandboxMode::None => ApprovalScope::SandboxNone,
        ResolvedSandboxMode::Default | ResolvedSandboxMode::Strict => ApprovalScope::SandboxDefault,
    }
}

pub fn authorize_persistent_script_policy(
    requested: ScriptPolicy,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.script_policy();
    let weakens_current = requested.loosens(current);
    if requested.loosens(current)
        && matches!(
            effective.sources.script_policy,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "script-policy",
            requested.as_str(),
            current.as_str(),
        );
        record_persistent_guarded_attempt(
            approval_scope_for_script_policy(requested),
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            approval_scope_for_script_policy(requested),
            json_output,
            command_hint,
            &format!(
                "Persisting `script-policy = {}` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.script_policy();
        if requested == approved || requested.loosens(approved) {
            return Ok(());
        }
    }
    posture.script_policy = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_release_age(
    requested_secs: u64,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.minimum_release_age_secs();
    let weakens_current = requested_secs < current;
    if requested_secs < current
        && matches!(
            effective.sources.minimum_release_age_secs,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "minimum-release-age-secs",
            requested_secs.to_string(),
            current.to_string(),
        );
        record_persistent_guarded_attempt(ApprovalScope::CooldownBypass, false, &err.to_string());
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            ApprovalScope::CooldownBypass,
            json_output,
            command_hint,
            &format!(
                "Persisting `minimum-release-age-secs = {requested_secs}` weakens the approved machine posture."
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.minimum_release_age_secs();
        if requested_secs <= approved {
            return Ok(());
        }
    }
    posture.minimum_release_age_secs = requested_secs;
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sandbox_mode(
    requested: ResolvedSandboxMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sandbox_mode();
    let weakens_current = requested.loosens(current);
    if requested.loosens(current)
        && matches!(
            effective.sources.sandbox_mode,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "[sandbox].mode",
            requested.as_str(),
            current.as_str(),
        );
        record_persistent_guarded_attempt(
            approval_scope_for_sandbox_mode(requested),
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            approval_scope_for_sandbox_mode(requested),
            json_output,
            command_hint,
            &format!(
                "Persisting `[sandbox] mode = \"{}\"` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.sandbox_mode();
        if requested == approved || requested.loosens(approved) {
            return Ok(());
        }
    }
    posture.sandbox_mode = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sigstore(
    requested: EnforceMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sigstore_verify();
    let weakens_current = crate::security_floor::sigstore_loosens(requested, current);
    if weakens_current
        && matches!(
            effective.sources.sigstore_verify,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        let err = managed_policy_write_error(
            managed_policy,
            "[sigstore].verify",
            crate::security_floor::sigstore_mode_name(requested),
            crate::security_floor::sigstore_mode_name(current),
        );
        record_persistent_guarded_attempt(
            ApprovalScope::ProvenanceUnverified,
            false,
            &err.to_string(),
        );
        return Err(err);
    }

    let mut posture = load_authorized_posture()?;
    if weakens_current {
        confirm_persistent_weakening(
            ApprovalScope::ProvenanceUnverified,
            json_output,
            command_hint,
            &format!(
                "Persisting `[sigstore] verify = \"{}\"` weakens the approved machine posture.",
                crate::security_floor::sigstore_mode_name(requested)
            ),
        )?;
    } else if !matches!(
        effective.approved_posture_source,
        PostureSourceKind::ApprovedStore
    ) {
        return Ok(());
    } else {
        let approved = posture.sigstore_verify();
        if requested == approved || crate::security_floor::sigstore_loosens(requested, approved) {
            return Ok(());
        }
    }
    posture.sigstore_verify = crate::security_floor::sigstore_mode_name(requested).to_string();
    persist_authorized_posture(&posture)
}

pub fn ensure_runtime_sigstore_posture(
    project_dir: &Path,
    json_output: bool,
    requested: EnforceMode,
    source: crate::provenance_fetch::EnforceModeSource,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let approved = effective.posture.sigstore_verify();
    if !crate::security_floor::sigstore_loosens(requested, approved) {
        return Ok(());
    }
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) {
        if let Some(err) =
            managed_policy_blocks_scope(&effective, ApprovalScope::ProvenanceUnverified)
        {
            record_audit_event(
                AuditRecord::new(
                    "guarded-attempt",
                    false,
                    vec![ApprovalScope::ProvenanceUnverified.as_str().to_string()],
                )
                .project_root(canonical_project_root(project_dir))
                .source(approval_source_for_enforce_source(source))
                .detail(
                    "runtime Sigstore verification posture is weaker than managed policy"
                        .to_string(),
                ),
            );
            return Err(err);
        }
        ensure_project_unlock(
            ApprovalScope::ProvenanceUnverified,
            project_dir,
            json_output,
            approval_source_for_enforce_source(source),
            match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "This command weakens Sigstore verification via LPM_PROVENANCE_ENFORCE for this project."
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "The persisted global [sigstore].verify setting weakens Sigstore verification for this project."
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
            None,
            &[],
        )?;
    }
    Ok(())
}

pub fn ensure_runtime_sigstore_posture_for_global(
    json_output: bool,
    requested: EnforceMode,
    source: crate::provenance_fetch::EnforceModeSource,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    let approved = effective.posture.sigstore_verify();
    if !crate::security_floor::sigstore_loosens(requested, approved) {
        return Ok(());
    }
    if matches!(
        source,
        crate::provenance_fetch::EnforceModeSource::Env
            | crate::provenance_fetch::EnforceModeSource::Config
    ) {
        if let Some(err) =
            managed_policy_blocks_scope(&effective, ApprovalScope::ProvenanceUnverified)
        {
            record_audit_event(
                AuditRecord::new(
                    "guarded-attempt",
                    false,
                    vec![ApprovalScope::ProvenanceUnverified.as_str().to_string()],
                )
                .source(approval_source_for_enforce_source(source))
                .detail(
                    "runtime Sigstore verification posture is weaker than managed policy"
                        .to_string(),
                ),
            );
            return Err(err);
        }
        ensure_global_unlock(
            ApprovalScope::ProvenanceUnverified,
            json_output,
            approval_source_for_enforce_source(source),
            match source {
                crate::provenance_fetch::EnforceModeSource::Env => {
                    "This command weakens Sigstore verification via LPM_PROVENANCE_ENFORCE globally."
                }
                crate::provenance_fetch::EnforceModeSource::Config => {
                    "The persisted global [sigstore].verify setting weakens Sigstore verification globally."
                }
                crate::provenance_fetch::EnforceModeSource::Default => unreachable!(),
            },
            &[],
        )?;
    }
    Ok(())
}

pub fn unlock_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    project_dir: &Path,
    ttl_secs: u64,
    json_output: bool,
    min_release_age_secs: Option<u64>,
    packages: &[String],
) -> Result<UnlockGrant, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }
    if !(1..=MAX_UNLOCK_TTL_SECS).contains(&ttl_secs) {
        return Err(LpmError::Registry(format!(
            "unlock ttl must be between 1 and {MAX_UNLOCK_TTL_SECS} seconds"
        )));
    }
    let effective = load_effective_authorized_posture()?;
    for scope in &requested_scopes {
        if let Some(err) = managed_policy_blocks_scope(&effective, *scope) {
            return Err(err);
        }
    }
    if is_automation(json_output) {
        return Err(approval_required_error(
            format!("{selector} requires an interactive approval terminal"),
            scope_names(&requested_scopes),
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }

    crate::output::warn(&format!(
        "{selector} will be allowed for this project for {} if you approve.",
        format_unlock_duration(ttl_secs),
    ));
    let confirmed = request_native_approval("Approve this temporary security unlock now?")?;
    if !confirmed {
        record_audit_event(
            AuditRecord::new("unlock-granted", false, scope_names(&requested_scopes))
                .project_root(canonical_project_root(project_dir))
                .packages(packages.to_vec())
                .source(ApprovalSource::SecurityCommand)
                .detail(format!("user declined {selector}")),
        );
        return Err(approval_required_error(
            format!("{selector} requires explicit approval"),
            scope_names(&requested_scopes),
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Project,
                packages,
            )),
        ));
    }
    let grant = create_unlock_grant_for_scopes(
        &requested_scopes,
        project_dir,
        ttl_secs,
        min_release_age_secs,
        packages,
    );
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, scope_names(&requested_scopes))
            .project_root(canonical_project_root(project_dir))
            .packages(packages.to_vec())
            .source(ApprovalSource::SecurityCommand)
            .unlock_id(grant.id.clone())
            .detail(format!("temporary unlock granted for {selector}")),
    );
    Ok(grant)
}

pub fn unlock_global_scopes_command(
    selector: &str,
    scopes: &[ApprovalScope],
    ttl_secs: u64,
    json_output: bool,
    packages: &[String],
) -> Result<UnlockGrant, LpmError> {
    let requested_scopes = normalized_scopes(scopes);
    if requested_scopes.is_empty() {
        return Err(LpmError::Registry(
            "at least one unlock scope is required".into(),
        ));
    }
    if !(1..=MAX_UNLOCK_TTL_SECS).contains(&ttl_secs) {
        return Err(LpmError::Registry(format!(
            "unlock ttl must be between 1 and {MAX_UNLOCK_TTL_SECS} seconds"
        )));
    }
    let effective = load_effective_authorized_posture()?;
    for scope in &requested_scopes {
        if let Some(err) = managed_policy_blocks_scope(&effective, *scope) {
            return Err(err);
        }
    }
    if is_automation(json_output) {
        return Err(approval_required_error(
            format!("{selector} requires an interactive approval terminal"),
            scope_names(&requested_scopes),
            None,
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }

    crate::output::warn(&format!(
        "{selector} will be allowed globally for {} if you approve.",
        format_unlock_duration(ttl_secs),
    ));
    let confirmed = request_native_approval("Approve this temporary global security unlock now?")?;
    if !confirmed {
        record_audit_event(
            AuditRecord::new("unlock-granted", false, scope_names(&requested_scopes))
                .packages(packages.to_vec())
                .source(ApprovalSource::SecurityCommand)
                .detail(format!("user declined {selector}")),
        );
        return Err(approval_required_error(
            format!("{selector} requires explicit approval"),
            scope_names(&requested_scopes),
            None,
            Some(suggested_unlock_command(
                selector,
                UnlockTargetKind::Global,
                packages,
            )),
        ));
    }
    let grant = create_global_unlock_grant_for_scopes(&requested_scopes, ttl_secs, packages);
    persist_unlock_grant(&grant)?;
    record_audit_event(
        AuditRecord::new("unlock-granted", true, scope_names(&requested_scopes))
            .packages(packages.to_vec())
            .source(ApprovalSource::SecurityCommand)
            .unlock_id(grant.id.clone())
            .detail(format!("temporary global unlock granted for {selector}")),
    );
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn with_test_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        struct EnvRestore {
            original_dir: Option<std::ffi::OsString>,
            original_policy: Option<std::ffi::OsString>,
            original_secret: Option<std::ffi::OsString>,
            original_auth: Option<std::ffi::OsString>,
        }
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                match self.original_dir.take() {
                    Some(value) => unsafe { std::env::set_var(SECURITY_DIR_ENV, value) },
                    None => unsafe { std::env::remove_var(SECURITY_DIR_ENV) },
                }
                match self.original_policy.take() {
                    Some(value) => unsafe { std::env::set_var(SECURITY_POLICY_PATH_ENV, value) },
                    None => unsafe { std::env::remove_var(SECURITY_POLICY_PATH_ENV) },
                }
                match self.original_secret.take() {
                    Some(value) => unsafe { std::env::set_var(TEST_SECRET_ENV, value) },
                    None => unsafe { std::env::remove_var(TEST_SECRET_ENV) },
                }
                match self.original_auth.take() {
                    Some(value) => unsafe { std::env::set_var(TEST_AUTH_RESULT_ENV, value) },
                    None => unsafe { std::env::remove_var(TEST_AUTH_RESULT_ENV) },
                }
            }
        }
        let _restore = EnvRestore {
            original_dir: std::env::var_os(SECURITY_DIR_ENV),
            original_policy: std::env::var_os(SECURITY_POLICY_PATH_ENV),
            original_secret: std::env::var_os(TEST_SECRET_ENV),
            original_auth: std::env::var_os(TEST_AUTH_RESULT_ENV),
        };
        let policy_path = dir.join("managed-security-policy.toml");
        // Test-only env mutation is isolated to this helper and
        // restored before returning.
        unsafe {
            std::env::set_var(SECURITY_DIR_ENV, dir);
            std::env::set_var(SECURITY_POLICY_PATH_ENV, &policy_path);
            std::env::set_var(
                TEST_SECRET_ENV,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
            std::env::set_var(TEST_AUTH_RESULT_ENV, "approve");
        }
        f()
    }

    fn write_managed_policy(dir: &Path, body: &str) {
        let policy_path = dir.join("managed-security-policy.toml");
        std::fs::write(policy_path, body).unwrap();
    }

    #[test]
    fn authorized_posture_round_trips_through_signed_store() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            let posture = AuthorizedPosture {
                script_policy: "allow".into(),
                minimum_release_age_secs: 0,
                sandbox_mode: "none".into(),
                ..AuthorizedPosture::default()
            };
            persist_authorized_posture(&posture).unwrap();
            let loaded = load_authorized_posture().unwrap();
            assert_eq!(loaded.script_policy(), ScriptPolicy::Allow);
            assert_eq!(loaded.minimum_release_age_secs(), 0);
            assert_eq!(loaded.sandbox_mode(), ResolvedSandboxMode::None);
        });
    }

    #[test]
    fn unlock_grant_round_trips_and_matches_project_scope() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        with_test_env(temp.path(), || {
            let grant = create_unlock_grant(
                ApprovalScope::SandboxNone,
                &project,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &[],
            );
            persist_unlock_grant(&grant).unwrap();
            assert!(
                has_active_project_unlock(ApprovalScope::SandboxNone, &project, None, &[]).unwrap()
            );
        });
    }

    #[test]
    fn unlock_duration_formats_compact_units() {
        assert_eq!(format_unlock_duration(600), "10m");
        assert_eq!(format_unlock_duration(3_600), "1h");
        assert_eq!(format_unlock_duration(365 * 24 * 60 * 60), "365d");
        assert_eq!(format_unlock_duration(45), "45s");
    }

    #[test]
    fn default_unlock_bundle_excludes_trust_capability_and_floor_scopes() {
        let scopes = ApprovalScope::default_unlock_scopes();
        assert!(scopes.contains(&ApprovalScope::CooldownBypass));
        assert!(scopes.contains(&ApprovalScope::SandboxNone));
        assert!(!scopes.contains(&ApprovalScope::TrustBulkApprove));
        assert!(!scopes.contains(&ApprovalScope::TrustScopeWiden));
        assert!(!scopes.contains(&ApprovalScope::CapabilityWiden));
        assert!(!scopes.contains(&ApprovalScope::FloorEdit));
    }

    #[test]
    fn unlock_scopes_command_accepts_year_long_ttl() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let grant = unlock_scopes_command(
                "default",
                ApprovalScope::default_unlock_scopes(),
                &project,
                MAX_UNLOCK_TTL_SECS,
                false,
                None,
                &[],
            )
            .unwrap();

            assert_eq!(grant.scopes, ApprovalScope::default_unlock_scopes());
            assert_eq!(
                (grant.expires_at - grant.issued_at).num_seconds(),
                MAX_UNLOCK_TTL_SECS as i64
            );
        });
    }

    #[test]
    fn lock_global_scopes_command_revokes_only_requested_scopes() {
        let temp = tempdir().unwrap();

        with_test_env(temp.path(), || {
            let grant = create_global_unlock_grant_for_scopes(
                &[
                    ApprovalScope::CooldownBypass,
                    ApprovalScope::TrustBulkApprove,
                ],
                DEFAULT_UNLOCK_TTL_SECS,
                &[],
            );
            persist_unlock_grant(&grant).unwrap();

            let revocations =
                lock_global_scopes_command("default", ApprovalScope::default_unlock_scopes(), &[])
                    .unwrap();

            assert_eq!(revocations.len(), 1);
            assert_eq!(
                revocations[0].revoked_scopes,
                vec![ApprovalScope::CooldownBypass]
            );
            assert_eq!(
                revocations[0].remaining_scopes,
                vec![ApprovalScope::TrustBulkApprove]
            );

            let grants = list_active_global_unlocks().unwrap();
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].id, grant.id);
            assert_eq!(grants[0].scopes, vec![ApprovalScope::TrustBulkApprove]);
        });
    }

    #[test]
    fn lock_project_scopes_command_matches_exact_package_sets() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let grant = create_unlock_grant_for_scopes(
                &[ApprovalScope::ProvenanceUnverified],
                &project,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &["esbuild".to_string(), "sharp".to_string()],
            );
            persist_unlock_grant(&grant).unwrap();

            let revocations = lock_project_scopes_command(
                "provenance-unverified",
                &[ApprovalScope::ProvenanceUnverified],
                &project,
                &["esbuild".to_string()],
            )
            .unwrap();

            assert!(revocations.is_empty());
            assert!(
                has_active_project_unlock(
                    ApprovalScope::ProvenanceUnverified,
                    &project,
                    None,
                    &["esbuild".to_string(), "sharp".to_string()],
                )
                .unwrap()
            );
        });
    }

    #[test]
    fn managed_policy_overrides_selected_floor_controls() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            let posture = AuthorizedPosture {
                script_policy: "deny".into(),
                minimum_release_age_secs: DEFAULT_MIN_RELEASE_AGE_SECS,
                sandbox_mode: "default".into(),
                sandbox_allow_degraded: false,
                sigstore_verify: "deny".into(),
                ..AuthorizedPosture::default()
            };
            persist_authorized_posture(&posture).unwrap();
            write_managed_policy(
                temp.path(),
                r#"
script-policy = "allow"
minimum-release-age-secs = "0"

[policy]
name = "ci"
source = "test"
"#,
            );

            let effective = load_effective_authorized_posture().unwrap();
            assert_eq!(effective.posture.script_policy(), ScriptPolicy::Allow);
            assert_eq!(effective.posture.minimum_release_age_secs(), 0);
            assert_eq!(
                effective.sources.script_policy,
                PostureSourceKind::ManagedPolicy
            );
            assert_eq!(
                effective.sources.minimum_release_age_secs,
                PostureSourceKind::ManagedPolicy
            );
            assert_eq!(
                effective.sources.sandbox_mode,
                PostureSourceKind::ApprovedStore
            );
            assert_eq!(
                effective
                    .managed_policy
                    .as_ref()
                    .and_then(|policy| policy.name.as_deref()),
                Some("ci")
            );
        });
    }

    #[test]
    fn persistent_weakening_rejects_when_managed_policy_owns_that_floor() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            write_managed_policy(
                temp.path(),
                r#"
script-policy = "deny"
"#,
            );

            let err = authorize_persistent_script_policy(
                ScriptPolicy::Allow,
                true,
                "lpm config scripts --set allow",
            )
            .unwrap_err();
            assert_eq!(err.error_code(), "security_floor");
            assert!(err.to_string().contains("managed security policy"));
        });
    }

    #[test]
    fn persistent_strict_sigstore_write_from_builtin_default_skips_signed_store() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            let posture_path = approved_posture_path().unwrap();
            assert!(!posture_path.exists());

            authorize_persistent_sigstore(
                EnforceMode::Deny,
                true,
                "lpm config sigstore --set deny",
            )
            .unwrap();

            assert!(
                !posture_path.exists(),
                "strict/equal writes from the builtin floor must not require native secure storage",
            );
        });
    }

    #[test]
    fn persistent_strict_sigstore_write_revokes_existing_weaker_approval() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            let posture = AuthorizedPosture {
                sigstore_verify: "off".into(),
                ..AuthorizedPosture::default()
            };
            persist_authorized_posture(&posture).unwrap();

            authorize_persistent_sigstore(
                EnforceMode::Deny,
                true,
                "lpm config sigstore --set deny",
            )
            .unwrap();

            let loaded = load_authorized_posture().unwrap();
            assert_eq!(loaded.sigstore_verify(), EnforceMode::Deny);
        });
    }

    #[test]
    fn persistent_default_release_age_from_builtin_default_skips_signed_store() {
        let temp = tempdir().unwrap();
        with_test_env(temp.path(), || {
            let posture_path = approved_posture_path().unwrap();
            assert!(!posture_path.exists());

            authorize_persistent_release_age(
                DEFAULT_MIN_RELEASE_AGE_SECS,
                true,
                "lpm config release-age --set default",
            )
            .unwrap();

            assert!(
                !posture_path.exists(),
                "default release-age writes must not create a signed posture record",
            );
        });
    }

    #[test]
    fn security_status_filters_unlocks_to_the_requested_project() {
        let temp = tempdir().unwrap();
        let project_a = temp.path().join("project-a");
        let project_b = temp.path().join("project-b");
        std::fs::create_dir_all(&project_a).unwrap();
        std::fs::create_dir_all(&project_b).unwrap();
        with_test_env(temp.path(), || {
            persist_unlock_grant(&create_unlock_grant(
                ApprovalScope::SandboxNone,
                &project_a,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &[],
            ))
            .unwrap();
            persist_unlock_grant(&create_unlock_grant(
                ApprovalScope::CooldownBypass,
                &project_b,
                DEFAULT_UNLOCK_TTL_SECS,
                Some(0),
                &[],
            ))
            .unwrap();

            let status = load_security_status(Some(&project_a), false).unwrap();
            let expected_root = canonical_project_root(&project_a);
            assert_eq!(status.target, UnlockTargetKind::Project);
            assert_eq!(status.project_root.as_deref(), Some(expected_root.as_str()));
            assert_eq!(status.active_unlocks.len(), 1);
            assert_eq!(
                status.active_unlocks[0].scopes,
                vec![ApprovalScope::SandboxNone]
            );
        });
    }

    #[test]
    fn automation_mode_includes_json() {
        assert!(is_automation(true));
    }

    #[test]
    fn project_trust_widening_requires_approval_at_runtime() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "trustedDependencies": {
      "esbuild@0.25.1": {
        "integrity": "sha512-demo",
        "scriptHash": "sha256-demo"
      }
    }
  }
}"#,
        )
        .unwrap();

        with_test_env(temp.path(), || {
            let err =
                ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
                    .unwrap_err();
            assert_eq!(err.error_code(), "security_approval_required");
            assert!(
                err.to_string()
                    .contains("project trust or capability state changed")
            );
        });
    }

    #[test]
    fn project_trusted_scope_widening_requires_approval_at_runtime() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "trustedScopes": ["@myorg/*"]
    }
  }
}"#,
        )
        .unwrap();

        with_test_env(temp.path(), || {
            let err =
                ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
                    .unwrap_err();
            assert_eq!(err.error_code(), "security_approval_required");
            assert!(
                err.to_string()
                    .contains("project trust or capability state changed")
            );
        });
    }

    #[test]
    fn project_capability_widening_requires_approval_at_runtime() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "readProject": "full",
      "passEnv": ["SSH_AUTH_SOCK"]
    }
  }
}"#,
        )
        .unwrap();

        with_test_env(temp.path(), || {
            let err =
                ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
                    .unwrap_err();
            assert_eq!(err.error_code(), "security_approval_required");
            assert!(
                err.to_string()
                    .contains("project trust or capability state changed")
            );
        });
    }

    #[test]
    fn blocked_runtime_attempt_is_written_to_audit_log() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "demo",
  "version": "1.0.0",
  "lpm": {
    "scripts": {
      "trustedScopes": ["@myorg/*"]
    }
  }
}"#,
        )
        .unwrap();

        with_test_env(temp.path(), || {
            let err =
                ensure_project_policy_authorized(&project, true, ApprovalSource::ProjectConfig)
                    .unwrap_err();
            assert_eq!(err.error_code(), "security_approval_required");

            let audit_path = audit_log_path().unwrap();
            let content = std::fs::read_to_string(audit_path).unwrap();
            assert!(content.contains("\"event\":\"guarded-attempt\""));
            assert!(content.contains("trust-scope-widen"));
            assert!(content.contains(&canonical_project_root(&project)));
        });
    }

    #[test]
    fn cli_trust_authorization_persists_candidate_state() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"demo","version":"1.0.0"}"#,
        )
        .unwrap();

        with_test_env(temp.path(), || {
            let mut bindings = std::collections::HashMap::new();
            bindings.insert(
                "esbuild@0.25.1".to_string(),
                lpm_workspace::TrustedDependencyBinding {
                    integrity: Some("sha512-demo".to_string()),
                    script_hash: Some("sha256-demo".to_string()),
                    ..Default::default()
                },
            );
            let trusted = lpm_workspace::TrustedDependencies::Rich(bindings);
            ensure_project_trust_candidate_authorized(
                &project,
                &trusted,
                false,
                ApprovalSource::CliFlag,
            )
            .unwrap();

            let approved = load_approved_project_policy_state(&project).unwrap();
            assert!(approved.trusted_dependencies.contains_key("esbuild@0.25.1"));
        });
    }

    #[test]
    fn package_scoped_unlock_only_matches_granted_packages() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let grant = create_unlock_grant(
                ApprovalScope::ProvenanceUnverified,
                &project,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &["esbuild".to_string()],
            );
            persist_unlock_grant(&grant).unwrap();
            assert!(
                has_active_project_unlock(
                    ApprovalScope::ProvenanceUnverified,
                    &project,
                    None,
                    &["esbuild".to_string()],
                )
                .unwrap()
            );
            assert!(
                !has_active_project_unlock(
                    ApprovalScope::ProvenanceUnverified,
                    &project,
                    None,
                    &["sharp".to_string()],
                )
                .unwrap()
            );
            assert!(
                !has_active_project_unlock(
                    ApprovalScope::ProvenanceUnverified,
                    &project,
                    None,
                    &[],
                )
                .unwrap()
            );
        });
    }

    #[test]
    fn security_status_reports_runtime_sigstore_env_override() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let original = std::env::var_os("LPM_PROVENANCE_ENFORCE");
            unsafe {
                std::env::set_var("LPM_PROVENANCE_ENFORCE", "warn");
            }
            let status = load_security_status(Some(&project), false).unwrap();
            assert_eq!(status.active_runtime_overrides.len(), 1);
            assert_eq!(
                status.active_runtime_overrides[0].control,
                "sigstore.verify"
            );
            assert_eq!(status.active_runtime_overrides[0].value, "warn");
            match original {
                Some(value) => unsafe { std::env::set_var("LPM_PROVENANCE_ENFORCE", value) },
                None => unsafe { std::env::remove_var("LPM_PROVENANCE_ENFORCE") },
            }
        });
    }

    #[test]
    fn global_status_only_lists_global_unlocks() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            persist_unlock_grant(&create_unlock_grant(
                ApprovalScope::SandboxNone,
                &project,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &[],
            ))
            .unwrap();
            persist_unlock_grant(&create_global_unlock_grant(
                ApprovalScope::TrustBulkApprove,
                DEFAULT_UNLOCK_TTL_SECS,
                &[],
            ))
            .unwrap();

            let status = load_security_status(None, true).unwrap();
            assert_eq!(status.target, UnlockTargetKind::Global);
            assert_eq!(status.active_unlocks.len(), 1);
            assert_eq!(status.active_unlocks[0].target, UnlockTargetKind::Global);
        });
    }

    #[test]
    fn runtime_sigstore_config_downgrade_requires_project_unlock() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let err = ensure_runtime_sigstore_posture(
                &project,
                true,
                EnforceMode::Warn,
                crate::provenance_fetch::EnforceModeSource::Config,
            )
            .unwrap_err();
            assert_eq!(err.error_code(), "security_approval_required");
            assert!(err.to_string().contains("provenance-unverified"));
        });
    }

    #[test]
    fn runtime_sigstore_config_downgrade_uses_active_project_unlock() {
        let temp = tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        with_test_env(temp.path(), || {
            let grant = create_unlock_grant(
                ApprovalScope::ProvenanceUnverified,
                &project,
                DEFAULT_UNLOCK_TTL_SECS,
                None,
                &[],
            );
            persist_unlock_grant(&grant).unwrap();
            ensure_runtime_sigstore_posture(
                &project,
                true,
                EnforceMode::Warn,
                crate::provenance_fetch::EnforceModeSource::Config,
            )
            .unwrap();
        });
    }

    #[test]
    fn persistent_automation_refusal_is_written_to_audit_log() {
        let temp = tempdir().unwrap();

        with_test_env(temp.path(), || {
            let original_auth = std::env::var_os(TEST_AUTH_RESULT_ENV);
            unsafe {
                std::env::remove_var(TEST_AUTH_RESULT_ENV);
            }
            let err = authorize_persistent_script_policy(
                ScriptPolicy::Allow,
                true,
                "lpm config scripts --set allow",
            )
            .unwrap_err();
            match original_auth {
                Some(value) => unsafe { std::env::set_var(TEST_AUTH_RESULT_ENV, value) },
                None => unsafe { std::env::remove_var(TEST_AUTH_RESULT_ENV) },
            }
            assert_eq!(err.error_code(), "security_approval_required");

            let content = std::fs::read_to_string(audit_log_path().unwrap()).unwrap();
            assert!(content.contains("\"event\":\"persistent-guarded-attempt\""));
            assert!(content.contains("\"allowed\":false"));
            assert!(content.contains("scripts-allow"));
        });
    }

    #[test]
    fn audit_log_truncation_is_detected_by_signed_head() {
        let temp = tempdir().unwrap();

        with_test_env(temp.path(), || {
            let event = AuditEvent {
                schema_version: AUDIT_EVENT_SCHEMA_VERSION,
                occurred_at: Utc::now(),
                event: "guarded-attempt".into(),
                allowed: false,
                scopes: vec![ApprovalScope::SandboxNone.as_str().to_string()],
                project_root: None,
                packages: Vec::new(),
                source: Some(ApprovalSource::CliFlag.as_str().to_string()),
                unlock_id: None,
                detail: Some("test".into()),
            };
            append_audit_event(&event).unwrap();
            std::fs::write(audit_log_path().unwrap(), "").unwrap();

            let err = append_audit_event(&event).unwrap_err();
            assert!(err.to_string().contains("signed audit head"));
        });
    }

    #[test]
    fn audit_log_appends_after_legacy_signed_entries() {
        let temp = tempdir().unwrap();

        with_test_env(temp.path(), || {
            let event = AuditEvent {
                schema_version: AUDIT_EVENT_SCHEMA_VERSION,
                occurred_at: Utc::now(),
                event: "guarded-attempt".into(),
                allowed: false,
                scopes: vec![ApprovalScope::SandboxNone.as_str().to_string()],
                project_root: None,
                packages: Vec::new(),
                source: Some(ApprovalSource::CliFlag.as_str().to_string()),
                unlock_id: None,
                detail: Some("legacy".into()),
            };
            let payload = serde_json::to_value(&event).unwrap();
            let legacy = SignedEnvelope {
                payload: event.clone(),
                signature: sign_payload_value(&payload).unwrap(),
            };
            let legacy_value = serde_json::to_value(&legacy).unwrap();
            let legacy_hash = hash_json_value(&legacy_value).unwrap();
            let log_path = audit_log_path().unwrap();
            std::fs::write(
                &log_path,
                format!("{}\n", serde_json::to_string(&legacy).unwrap()),
            )
            .unwrap();

            append_audit_event(&event).unwrap();

            let (tail, count) = read_audit_log_tail(&log_path).unwrap();
            assert!(tail.is_some());
            assert_eq!(count, 2);
            let content = std::fs::read_to_string(&log_path).unwrap();
            assert!(content.contains(&legacy_hash));
        });
    }
}
