//! Signed security approvals for guarded posture changes.
//!
//! Phase 2 moves the *authoritative* approved machine posture out of
//! ordinary config files and adds short-lived signed unlock grants for
//! project-scoped weakeners. `package.json`, `lpm.toml`, and
//! `~/.lpm/config.toml` remain the proposal layers; this module
//! decides whether a weaker proposal is already authorized, needs an
//! interactive approval, or must fail closed for automation.

use crate::provenance_fetch::EnforceMode;
use crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS;
use crate::sandbox_config::ResolvedSandboxMode;
use crate::script_policy_config::ScriptPolicy;
use crate::precedence::PurePolicyKnob;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use lpm_common::LpmError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

const APPROVED_POSTURE_SCHEMA_VERSION: u32 = 1;
const UNLOCK_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_UNLOCK_TTL_SECS: u64 = 10 * 60;
pub const MAX_UNLOCK_TTL_SECS: u64 = 30 * 60;
const KEYRING_SERVICE: &str = "dev.lpm.security-approval";
const KEYRING_ACCOUNT: &str = "signing-secret-v1";
const SECURITY_DIR_ENV: &str = "LPM_SECURITY_DIR";
const TEST_SECRET_ENV: &str = "LPM_TEST_SECURITY_SECRET_HEX";

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

impl ApprovalScope {
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
    ProjectConfig,
    GlobalConfig,
    ConfigMutation,
    SecurityCommand,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UnlockLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_release_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockGrant {
    pub schema_version: u32,
    pub id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedEnvelope<T> {
    payload: T,
    signature: String,
}

pub fn security_dir() -> Result<PathBuf, LpmError> {
    if let Ok(path) = std::env::var(SECURITY_DIR_ENV)
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| LpmError::Registry("could not determine home dir".into()))?;
    Ok(home.join(".lpm").join("security"))
}

fn approved_posture_path() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("approved-posture.json"))
}

fn unlocks_dir() -> Result<PathBuf, LpmError> {
    Ok(security_dir()?.join("unlocks"))
}

fn signing_secret() -> Result<Vec<u8>, LpmError> {
    if let Ok(raw) = std::env::var(TEST_SECRET_ENV)
        && !raw.trim().is_empty()
    {
        return hex::decode(raw.trim()).map_err(|e| {
            LpmError::Registry(format!(
                "{TEST_SECRET_ENV} must be valid hex-encoded bytes: {e}"
            ))
        });
    }

    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
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

pub fn persist_authorized_posture(posture: &AuthorizedPosture) -> Result<(), LpmError> {
    let mut normalized = posture.clone();
    normalized.schema_version = APPROVED_POSTURE_SCHEMA_VERSION;
    normalized.updated_at = Utc::now();
    write_signed_json(&approved_posture_path()?, &normalized)
}

pub fn is_automation(json_output: bool) -> bool {
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

fn suggested_unlock_command(scope: ApprovalScope) -> String {
    format!(
        "lpm security unlock {} --project . --ttl 10m",
        scope.as_str()
    )
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

fn create_unlock_grant(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
) -> UnlockGrant {
    let now = Utc::now();
    UnlockGrant {
        schema_version: UNLOCK_SCHEMA_VERSION,
        id: format!("unl_{}", now.timestamp_nanos_opt().unwrap_or_default()),
        project_root: Some(canonical_project_root(project_dir)),
        scopes: vec![scope],
        packages: Vec::new(),
        limits: UnlockLimits {
            min_release_age_secs,
        },
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
        issuer: "interactive-confirmation".to_string(),
    }
}

fn persist_unlock_grant(grant: &UnlockGrant) -> Result<(), LpmError> {
    let path = unlocks_dir()?.join(format!("{}.json", grant.id));
    write_signed_json(&path, grant)
}

fn read_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
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
            Ok(Some(grant)) if grant.expires_at > now => grants.push(grant),
            Ok(Some(_expired)) => {
                let _ = std::fs::remove_file(&path);
            }
            Ok(None) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(grants)
}

pub fn has_active_project_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    min_release_age_secs: Option<u64>,
) -> Result<bool, LpmError> {
    let root = canonical_project_root(project_dir);
    for grant in read_active_unlocks()? {
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
        return Ok(true);
    }
    Ok(false)
}

fn prompt_for_unlock(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    min_release_age_secs: Option<u64>,
    message: &str,
) -> Result<(), LpmError> {
    crate::output::warn(message);
    let confirmed = cliclack::confirm(format!(
        "Approve {} for this project for {} minute{}?",
        scope.as_str(),
        ttl_secs / 60,
        if ttl_secs / 60 == 1 { "" } else { "s" }
    ))
    .initial_value(false)
    .interact()
    .map_err(|e| LpmError::Registry(format!("security approval prompt failed: {e}")))?;

    if !confirmed {
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(scope)),
        ));
    }

    let grant = create_unlock_grant(scope, project_dir, ttl_secs, min_release_age_secs);
    persist_unlock_grant(&grant)?;
    crate::output::success(&format!(
        "Approved {} for this project for {} minute{}.",
        scope.as_str(),
        ttl_secs / 60,
        if ttl_secs / 60 == 1 { "" } else { "s" }
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
) -> Result<(), LpmError> {
    if has_active_project_unlock(scope, project_dir, min_release_age_secs)? {
        return Ok(());
    }

    if matches!(source, ApprovalSource::CliFlag) && !is_automation(json_output) {
        return prompt_for_unlock(
            scope,
            project_dir,
            DEFAULT_UNLOCK_TTL_SECS,
            min_release_age_secs,
            message,
        );
    }

    Err(approval_required_error(
        format!("{} requires explicit approval", scope.as_str()),
        vec![scope.as_str().to_string()],
        Some(canonical_project_root(project_dir)),
        Some(suggested_unlock_command(scope)),
    ))
}

fn confirm_persistent_weakening(
    scope: ApprovalScope,
    json_output: bool,
    command_hint: &str,
    message: &str,
) -> Result<(), LpmError> {
    if is_automation(json_output) {
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }

    crate::output::warn(message);
    let confirmed = cliclack::confirm("Approve this persistent machine-level security change now?")
        .initial_value(false)
        .interact()
        .map_err(|e| LpmError::Registry(format!("security approval prompt failed: {e}")))?;
    if !confirmed {
        return Err(approval_required_error(
            message,
            vec![scope.as_str().to_string()],
            None,
            Some(command_hint.to_string()),
        ));
    }
    Ok(())
}

pub fn authorize_persistent_script_policy(
    requested: ScriptPolicy,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let mut posture = load_authorized_posture()?;
    let current = posture.script_policy();
    if requested.loosens(current) {
        confirm_persistent_weakening(
            match requested {
                ScriptPolicy::Allow => ApprovalScope::ScriptsAllow,
                ScriptPolicy::Triage => ApprovalScope::ScriptsTriage,
                ScriptPolicy::Deny => ApprovalScope::ScriptsTriage,
            },
            json_output,
            command_hint,
            &format!(
                "Persisting `script-policy = {}` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    }
    posture.script_policy = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_release_age(
    requested_secs: u64,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let mut posture = load_authorized_posture()?;
    let current = posture.minimum_release_age_secs();
    if requested_secs < current {
        confirm_persistent_weakening(
            ApprovalScope::CooldownBypass,
            json_output,
            command_hint,
            &format!(
                "Persisting `minimum-release-age-secs = {requested_secs}` weakens the approved machine posture."
            ),
        )?;
    }
    posture.minimum_release_age_secs = requested_secs;
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sandbox_mode(
    requested: ResolvedSandboxMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let mut posture = load_authorized_posture()?;
    let current = posture.sandbox_mode();
    if requested.loosens(current) {
        confirm_persistent_weakening(
            match requested {
                ResolvedSandboxMode::None => ApprovalScope::SandboxNone,
                ResolvedSandboxMode::Default => ApprovalScope::SandboxDefault,
                ResolvedSandboxMode::Strict => ApprovalScope::SandboxDefault,
            },
            json_output,
            command_hint,
            &format!(
                "Persisting `[sandbox] mode = \"{}\"` weakens the approved machine posture.",
                requested.as_str()
            ),
        )?;
    }
    posture.sandbox_mode = requested.as_str().to_string();
    persist_authorized_posture(&posture)
}

pub fn authorize_persistent_sigstore(
    requested: EnforceMode,
    json_output: bool,
    command_hint: &str,
) -> Result<(), LpmError> {
    let mut posture = load_authorized_posture()?;
    let current = posture.sigstore_verify();
    if crate::security_floor::sigstore_loosens(requested, current) {
        confirm_persistent_weakening(
            ApprovalScope::ProvenanceUnverified,
            json_output,
            command_hint,
            &format!(
                "Persisting `[sigstore] verify = \"{}\"` weakens the approved machine posture.",
                crate::security_floor::sigstore_mode_name(requested)
            ),
        )?;
    }
    posture.sigstore_verify = crate::security_floor::sigstore_mode_name(requested).to_string();
    persist_authorized_posture(&posture)
}

pub fn unlock_scope_command(
    scope: ApprovalScope,
    project_dir: &Path,
    ttl_secs: u64,
    json_output: bool,
    min_release_age_secs: Option<u64>,
) -> Result<UnlockGrant, LpmError> {
    if !(1..=MAX_UNLOCK_TTL_SECS).contains(&ttl_secs) {
        return Err(LpmError::Registry(format!(
            "unlock ttl must be between 1 and {MAX_UNLOCK_TTL_SECS} seconds"
        )));
    }
    if is_automation(json_output) {
        return Err(approval_required_error(
            format!("{} requires an interactive approval terminal", scope.as_str()),
            vec![scope.as_str().to_string()],
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(scope)),
        ));
    }

    crate::output::warn(&format!(
        "{} will be allowed for this project for {} minute{} if you approve.",
        scope.as_str(),
        ttl_secs / 60,
        if ttl_secs / 60 == 1 { "" } else { "s" }
    ));
    let confirmed = cliclack::confirm("Approve this temporary security unlock now?")
        .initial_value(false)
        .interact()
        .map_err(|e| LpmError::Registry(format!("security approval prompt failed: {e}")))?;
    if !confirmed {
        return Err(approval_required_error(
            format!("{} requires explicit approval", scope.as_str()),
            vec![scope.as_str().to_string()],
            Some(canonical_project_root(project_dir)),
            Some(suggested_unlock_command(scope)),
        ));
    }
    let grant = create_unlock_grant(scope, project_dir, ttl_secs, min_release_age_secs);
    persist_unlock_grant(&grant)?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::sync::{Mutex, OnceLock};

    fn with_test_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("security approval test env mutex poisoned");
        let original_dir = std::env::var_os(SECURITY_DIR_ENV);
        let original_secret = std::env::var_os(TEST_SECRET_ENV);
        // Test-only env mutation is isolated to this helper and
        // restored before returning.
        unsafe {
            std::env::set_var(SECURITY_DIR_ENV, dir);
            std::env::set_var(
                TEST_SECRET_ENV,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
        }
        let out = f();
        match original_dir {
            Some(value) => unsafe { std::env::set_var(SECURITY_DIR_ENV, value) },
            None => unsafe { std::env::remove_var(SECURITY_DIR_ENV) },
        }
        match original_secret {
            Some(value) => unsafe { std::env::set_var(TEST_SECRET_ENV, value) },
            None => unsafe { std::env::remove_var(TEST_SECRET_ENV) },
        }
        out
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
            );
            persist_unlock_grant(&grant).unwrap();
            assert!(has_active_project_unlock(
                ApprovalScope::SandboxNone,
                &project,
                None
            )
            .unwrap());
        });
    }

    #[test]
    fn automation_mode_includes_json() {
        assert!(is_automation(true));
    }
}
