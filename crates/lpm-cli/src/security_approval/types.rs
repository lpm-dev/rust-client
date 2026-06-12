use super::prelude::*;

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
    ApproveScripts,
}

impl ApprovalSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::CliFlag => "cli-flag",
            Self::EnvVar => "env-var",
            Self::ProjectConfig => "project-config",
            Self::GlobalConfig => "global-config",
            Self::ConfigMutation => "config-mutation",
            Self::SecurityCommand => "security-command",
            Self::ApproveScripts => "approve-scripts",
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
    pub(super) fn new(base: PostureSourceKind) -> Self {
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QuarantinedSecurityState {
    pub original_path: String,
    pub quarantine_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityRepairReport {
    pub security_dir: String,
    pub quarantined: Vec<QuarantinedSecurityState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManagedPolicy {
    pub(super) status: ManagedPolicyStatus,
    pub(super) script_policy: Option<ScriptPolicy>,
    pub(super) minimum_release_age_secs: Option<u64>,
    pub(super) sandbox_mode: Option<ResolvedSandboxMode>,
    pub(super) sandbox_allow_degraded: Option<bool>,
    pub(super) sigstore_verify: Option<EnforceMode>,
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
pub(super) struct StoredUnlockGrant {
    pub(super) path: PathBuf,
    pub(super) grant: UnlockGrant,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeOverride {
    pub control: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ApprovedProjectPolicyState {
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
pub(super) struct ApprovedGlobalTrustState {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted_dependencies: BTreeMap<String, lpm_global::TrustedDependencyBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct AuditEvent {
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
pub(super) struct AuditHead {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub last_entry_hash: String,
    pub entry_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SignedAuditEnvelope {
    pub(super) payload: AuditEvent,
    pub(super) previous_entry_hash: Option<String>,
    pub(super) entry_hash: String,
    pub(super) signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SignedEnvelope<T> {
    pub(super) payload: T,
    pub(super) signature: String,
}
