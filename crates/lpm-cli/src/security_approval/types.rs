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
    TyposquatDisable,
    FirewallDisable,
    SourceAnalysisDisable,
    FloorEdit,
}

const ALL_APPROVAL_SCOPES: [ApprovalScope; 16] = [
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
    ApprovalScope::TyposquatDisable,
    ApprovalScope::FirewallDisable,
    ApprovalScope::SourceAnalysisDisable,
    ApprovalScope::FloorEdit,
];

const DEFAULT_UNLOCK_SCOPES: [ApprovalScope; 12] = [
    ApprovalScope::CooldownBypass,
    ApprovalScope::CooldownWindow,
    ApprovalScope::ProvenanceIgnoreDrift,
    ApprovalScope::ProvenanceUnverified,
    ApprovalScope::ScriptsTriage,
    ApprovalScope::ScriptsAllow,
    ApprovalScope::SandboxDefault,
    ApprovalScope::SandboxNone,
    ApprovalScope::SandboxAllowDegraded,
    ApprovalScope::TyposquatDisable,
    ApprovalScope::FirewallDisable,
    ApprovalScope::SourceAnalysisDisable,
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
            Self::TyposquatDisable => "typosquat-disable",
            Self::FirewallDisable => "firewall-disable",
            Self::SourceAnalysisDisable => "source-analysis-disable",
            Self::FloorEdit => "floor-edit",
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalSource {
    CliFlag,
    EnvVar,
    ConfigAndEnv,
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
            Self::ConfigAndEnv => "config-and-env",
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
    pub updated_at: Timestamp,
    pub script_policy: String,
    pub minimum_release_age_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub minimum_release_age_exclude: Vec<String>,
    #[serde(default = "default_release_age_policy_string")]
    pub release_age_policy: String,
    pub sandbox_mode: String,
    pub sandbox_allow_degraded: bool,
    pub sigstore_verify: String,
    #[serde(default = "default_typosquat_guard_string")]
    pub typosquat_guard: String,
    #[serde(default = "default_firewall_mode_string")]
    pub firewall_mode: String,
    /// Approved `[firewall.npm.policies]` actions that differ from the default
    /// profile, keyed by policy group.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub firewall_policies: BTreeMap<String, String>,
    #[serde(default = "default_install_time_source_analysis")]
    pub install_time_source_analysis: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizedPostureView {
    pub script_policy: String,
    pub minimum_release_age_secs: u64,
    pub release_age_policy: String,
    pub sandbox_mode: String,
    pub sandbox_allow_degraded: bool,
    pub sigstore_verify: String,
    pub typosquat_guard: String,
    pub firewall_mode: String,
    pub firewall_policies: BTreeMap<String, String>,
    pub install_time_source_analysis: bool,
}

fn default_release_age_policy_string() -> String {
    ReleaseAgePolicy::Direct.as_str().to_string()
}

fn default_typosquat_guard_string() -> String {
    crate::commands::config::TyposquatGuardSelection::Default
        .as_str()
        .to_string()
}

fn default_firewall_mode_string() -> String {
    crate::npm_firewall_config::NpmFirewallMode::Off
        .as_str()
        .to_string()
}

fn default_install_time_source_analysis() -> bool {
    crate::source_analysis_config::DEFAULT_INSTALL_TIME_SOURCE_ANALYSIS
}

impl Default for AuthorizedPosture {
    fn default() -> Self {
        Self {
            schema_version: APPROVED_POSTURE_SCHEMA_VERSION,
            updated_at: Timestamp::now(),
            script_policy: ScriptPolicy::default().as_str().to_string(),
            minimum_release_age_secs: DEFAULT_MIN_RELEASE_AGE_SECS,
            minimum_release_age_exclude: Vec::new(),
            release_age_policy: default_release_age_policy_string(),
            sandbox_mode: ResolvedSandboxMode::Default.as_str().to_string(),
            sandbox_allow_degraded: false,
            sigstore_verify: "deny".to_string(),
            typosquat_guard: default_typosquat_guard_string(),
            firewall_mode: default_firewall_mode_string(),
            firewall_policies: BTreeMap::new(),
            install_time_source_analysis: default_install_time_source_analysis(),
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

    pub fn release_age_policy(&self) -> ReleaseAgePolicy {
        ReleaseAgePolicy::parse("approved release-age-policy", &self.release_age_policy)
            .unwrap_or_default()
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

    pub fn typosquat_guard(&self) -> crate::commands::config::TyposquatGuardSelection {
        crate::commands::config::TyposquatGuardSelection::parse(&self.typosquat_guard)
            .unwrap_or(crate::commands::config::TyposquatGuardSelection::Default)
    }

    pub fn firewall_mode(&self) -> crate::npm_firewall_config::NpmFirewallMode {
        crate::npm_firewall_config::NpmFirewallMode::parse(&self.firewall_mode).unwrap_or_default()
    }

    pub fn firewall_policy_profile(&self) -> lpm_registry::client::NpmFirewallPolicyProfile {
        crate::npm_firewall_config::policy_profile_from_overrides(&self.firewall_policies)
    }

    pub fn install_time_source_analysis(&self) -> bool {
        self.install_time_source_analysis
    }

    pub fn to_view(&self) -> AuthorizedPostureView {
        AuthorizedPostureView {
            script_policy: self.script_policy.clone(),
            minimum_release_age_secs: self.minimum_release_age_secs,
            release_age_policy: self.release_age_policy.clone(),
            sandbox_mode: self.sandbox_mode.clone(),
            sandbox_allow_degraded: self.sandbox_allow_degraded,
            sigstore_verify: self.sigstore_verify.clone(),
            typosquat_guard: self.typosquat_guard().as_str().to_string(),
            firewall_mode: self.firewall_mode().as_str().to_string(),
            firewall_policies: crate::npm_firewall_config::policy_profile_entries(
                &self.firewall_policy_profile(),
            ),
            install_time_source_analysis: self.install_time_source_analysis,
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
    pub release_age_policy: PostureSourceKind,
    pub sandbox_mode: PostureSourceKind,
    pub sandbox_allow_degraded: PostureSourceKind,
    pub sigstore_verify: PostureSourceKind,
    pub typosquat_guard: PostureSourceKind,
    pub firewall_mode: PostureSourceKind,
    pub firewall_policies: PostureSourceKind,
    pub install_time_source_analysis: PostureSourceKind,
}

impl EffectivePostureSources {
    pub(super) fn new(base: PostureSourceKind) -> Self {
        Self {
            script_policy: base,
            minimum_release_age_secs: base,
            release_age_policy: base,
            sandbox_mode: base,
            sandbox_allow_degraded: base,
            sigstore_verify: base,
            typosquat_guard: base,
            firewall_mode: base,
            firewall_policies: base,
            install_time_source_analysis: base,
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
pub struct ManagedProtectionStatus {
    pub path: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_policy: Option<ManagedPolicyStatus>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedProtectionChange {
    Enabled,
    Disabled,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum ManagedProtectionAction {
    EnableMonitor,
    EnableEnforce,
    Disable,
}

impl ManagedProtectionAction {
    #[cfg(any(unix, windows))]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EnableMonitor => "enable-monitor",
            Self::EnableEnforce => "enable-enforce",
            Self::Disable => "disable",
        }
    }
}

impl ManagedProtectionChange {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManagedProtectionReport {
    pub change: ManagedProtectionChange,
    pub status: ManagedProtectionStatus,
    /// Where a policy, or its directory, that LPM never applied was moved
    /// to make way (on Windows, where any user can make one first).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub set_aside: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EffectiveAuthorizedPosture {
    pub posture: AuthorizedPosture,
    pub sources: EffectivePostureSources,
    pub approved_posture_path: String,
    pub approved_posture_source: PostureSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_policy: Option<ManagedPolicyStatus>,
    /// The managed policy's `[firewall].bypass` and `bypass-malware` lists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub managed_firewall_bypass: Vec<ManagedFirewallBypass>,
}

/// One entry of the managed policy's `[firewall].bypass` or
/// `[firewall].bypass-malware` list.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManagedFirewallBypass {
    pub spec: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub covers_malware: bool,
}

/// The LPM Firewall bypass rules `lpm security status` reports.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FirewallBypassStatus {
    /// Whether rules added with `lpm firewall bypass add` apply here.
    pub local_rules_apply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive_reason: Option<String>,
    /// The unexpired local rules that apply to the status target: those for
    /// every project, and the project's own.
    #[serde(serialize_with = "crate::firewall_bypass::serialize_rules")]
    pub rules: Vec<crate::firewall_bypass::FirewallBypassRule>,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "crate::firewall_bypass::serialize_managed_rules"
    )]
    pub managed_rules: Vec<ManagedFirewallBypass>,
    /// Why the local rule store couldn't be read, when it couldn't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    pub firewall_bypass: FirewallBypassStatus,
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
    pub(super) release_age_policy: Option<ReleaseAgePolicy>,
    pub(super) sandbox_mode: Option<ResolvedSandboxMode>,
    pub(super) sandbox_allow_degraded: Option<bool>,
    pub(super) sigstore_verify: Option<EnforceMode>,
    pub(super) typosquat_guard: Option<crate::commands::config::TyposquatGuardSelection>,
    pub(super) firewall_mode: Option<crate::npm_firewall_config::NpmFirewallMode>,
    pub(super) firewall_policies: Option<lpm_registry::client::NpmFirewallPolicyProfile>,
    pub(super) firewall_bypass: Vec<ManagedFirewallBypass>,
    pub(super) install_time_source_analysis: Option<bool>,
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
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
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
    pub expires_at: Timestamp,
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
    pub updated_at: Timestamp,
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
    pub updated_at: Timestamp,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted_dependencies: BTreeMap<String, lpm_global::TrustedDependencyBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct AuditEvent {
    pub schema_version: u32,
    pub occurred_at: Timestamp,
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
    pub updated_at: Timestamp,
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
