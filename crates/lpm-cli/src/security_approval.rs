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
const SECURITY_POLICY_PATH_ENV: &str = "LPM_SECURITY_POLICY_PATH";
const TEST_SECRET_ENV: &str = "LPM_TEST_SECURITY_SECRET_HEX";
const DEFAULT_SECURITY_POLICY_PATH: &str = "/etc/lpm/security-policy.toml";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub effective_floor: AuthorizedPostureView,
    pub floor_sources: EffectivePostureSources,
    pub approved_posture_path: String,
    pub approved_posture_source: PostureSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_policy: Option<ManagedPolicyStatus>,
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

fn managed_policy_path() -> PathBuf {
    if let Ok(path) = std::env::var(SECURITY_POLICY_PATH_ENV)
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
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

pub fn list_active_unlocks() -> Result<Vec<UnlockGrant>, LpmError> {
    let mut grants = read_active_unlocks()?;
    grants.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
    Ok(grants)
}

pub fn list_active_project_unlocks(project_dir: &Path) -> Result<Vec<UnlockGrant>, LpmError> {
    let root = canonical_project_root(project_dir);
    let mut grants: Vec<_> = read_active_unlocks()?
        .into_iter()
        .filter(|grant| grant.project_root.as_deref() == Some(root.as_str()))
        .collect();
    grants.sort_by(|left, right| left.expires_at.cmp(&right.expires_at));
    Ok(grants)
}

pub fn load_security_status(project_dir: Option<&Path>) -> Result<SecurityStatus, LpmError> {
    let effective = load_effective_authorized_posture()?;
    let (project_root, active_unlocks) = match project_dir {
        Some(dir) => (
            Some(canonical_project_root(dir)),
            list_active_project_unlocks(dir)?,
        ),
        None => (None, list_active_unlocks()?),
    };

    Ok(SecurityStatus {
        project_root,
        effective_floor: effective.posture.to_view(),
        floor_sources: effective.sources,
        approved_posture_path: effective.approved_posture_path,
        approved_posture_source: effective.approved_posture_source,
        managed_policy: effective.managed_policy,
        active_unlocks,
    })
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
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.script_policy();
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
        return Err(managed_policy_write_error(
            managed_policy,
            "script-policy",
            requested.as_str(),
            current.as_str(),
        ));
    }

    let mut posture = load_authorized_posture()?;
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
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.minimum_release_age_secs();
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
        return Err(managed_policy_write_error(
            managed_policy,
            "minimum-release-age-secs",
            requested_secs.to_string(),
            current.to_string(),
        ));
    }

    let mut posture = load_authorized_posture()?;
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
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sandbox_mode();
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
        return Err(managed_policy_write_error(
            managed_policy,
            "[sandbox].mode",
            requested.as_str(),
            current.as_str(),
        ));
    }

    let mut posture = load_authorized_posture()?;
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
    let effective = load_effective_authorized_posture()?;
    let current = effective.posture.sigstore_verify();
    if crate::security_floor::sigstore_loosens(requested, current)
        && matches!(
            effective.sources.sigstore_verify,
            PostureSourceKind::ManagedPolicy
        )
    {
        let managed_policy = effective
            .managed_policy
            .as_ref()
            .expect("managed policy source must include status metadata");
        return Err(managed_policy_write_error(
            managed_policy,
            "[sigstore].verify",
            crate::security_floor::sigstore_mode_name(requested),
            crate::security_floor::sigstore_mode_name(current),
        ));
    }

    let mut posture = load_authorized_posture()?;
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
            format!(
                "{} requires an interactive approval terminal",
                scope.as_str()
            ),
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
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn with_test_env<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("security approval test env mutex poisoned");
        let original_dir = std::env::var_os(SECURITY_DIR_ENV);
        let original_policy = std::env::var_os(SECURITY_POLICY_PATH_ENV);
        let original_secret = std::env::var_os(TEST_SECRET_ENV);
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
        }
        let out = f();
        match original_dir {
            Some(value) => unsafe { std::env::set_var(SECURITY_DIR_ENV, value) },
            None => unsafe { std::env::remove_var(SECURITY_DIR_ENV) },
        }
        match original_policy {
            Some(value) => unsafe { std::env::set_var(SECURITY_POLICY_PATH_ENV, value) },
            None => unsafe { std::env::remove_var(SECURITY_POLICY_PATH_ENV) },
        }
        match original_secret {
            Some(value) => unsafe { std::env::set_var(TEST_SECRET_ENV, value) },
            None => unsafe { std::env::remove_var(TEST_SECRET_ENV) },
        }
        out
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
            );
            persist_unlock_grant(&grant).unwrap();
            assert!(has_active_project_unlock(ApprovalScope::SandboxNone, &project, None).unwrap());
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
            ))
            .unwrap();
            persist_unlock_grant(&create_unlock_grant(
                ApprovalScope::CooldownBypass,
                &project_b,
                DEFAULT_UNLOCK_TTL_SECS,
                Some(0),
            ))
            .unwrap();

            let status = load_security_status(Some(&project_a)).unwrap();
            let expected_root = canonical_project_root(&project_a);
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
}
