use super::*;
use lpm_registry::client::{
    AuthPosture, NpmFirewallAction, NpmFirewallBatchPackage, NpmFirewallBatchResponse,
    NpmFirewallCacheDirective, NpmFirewallClientTiming, NpmFirewallDecision,
    NpmFirewallDiagnostics, NpmFirewallFlaggedPackageIndexDiagnostics, NpmFirewallPolicyProfile,
};

use crate::firewall_bypass::{AppliedRule, BlockClass, FirewallBypassRules, bypass_add_command};
pub(super) use crate::npm_firewall_config::NpmFirewallMode;

const ENV_EXPERIMENT_NPM_FIREWALL_LOOKUP: &str = "LPM_EXPERIMENT_NPM_FIREWALL_LOOKUP";
const ENV_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE: &str = "LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE";
const ENV_NPM_FIREWALL_CACHE: &str = "LPM_NPM_FIREWALL_CACHE";
const DEFAULT_MONITOR_VERDICT_CACHE_TTL_SECS: u64 = 300;
const MAX_MONITOR_VERDICT_CACHE_ENTRIES: usize = 10_000;
const MAX_MONITOR_VERDICT_CACHE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FIREWALL_BATCH_PACKAGES: usize = 512;
pub(super) const DEFAULT_NPM_FIREWALL_CHUNK_SIZE: usize = 64;
const NPM_FIREWALL_OFFLINE_HINT: &str = "npm firewall verdict preflight requires network access; set [firewall].mode = \"off\" or run online";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NpmFirewallMaterializationPackage {
    name: String,
    version: String,
    integrity: Option<String>,
    published_at: Option<String>,
}

impl NpmFirewallMaterializationPackage {
    pub(crate) fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        integrity: Option<&str>,
        published_at: Option<&str>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            integrity: integrity.map(str::to_string),
            published_at: published_at.map(str::to_string),
        }
    }

    fn to_batch_package(&self, lookup_mode: NpmFirewallLookupMode) -> NpmFirewallBatchPackage {
        NpmFirewallBatchPackage {
            name: self.name.clone(),
            version: self.version.clone(),
            integrity: lookup_mode
                .include_integrity()
                .then(|| self.integrity.clone())
                .flatten(),
            published_at: self.published_at.clone(),
        }
    }
}

pub(crate) type NpmFirewallMaterializationJson = Option<serde_json::Value>;

pub(crate) struct NpmFirewallMaterializationPreflight {
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    policy_profile: NpmFirewallPolicyProfile,
    bypass: FirewallBypassRules,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
}

impl NpmFirewallMaterializationPreflight {
    pub(crate) fn is_active(&self) -> bool {
        self.mode.is_enabled() && !self.verdict_packages.is_empty()
    }
}

#[derive(Clone)]
struct NpmFirewallPreflightClient {
    base: Arc<RegistryClient>,
    ci_oidc: Arc<tokio::sync::OnceCell<Arc<RegistryClient>>>,
}

impl NpmFirewallPreflightClient {
    fn new(base: Arc<RegistryClient>) -> Self {
        Self {
            base,
            ci_oidc: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    async fn batch_verdicts(
        &self,
        mode: NpmFirewallMode,
        policy_profile: NpmFirewallPolicyProfile,
        packages: &[NpmFirewallBatchPackage],
    ) -> Result<NpmFirewallBatchResponse, LpmError> {
        let (effective_client, _) = self.for_mode(mode).await?;
        effective_client
            .npm_firewall_batch_verdicts_with_posture_and_policy(
                packages,
                mode.auth_posture(),
                Some(policy_profile),
            )
            .await
    }

    async fn for_mode(
        &self,
        mode: NpmFirewallMode,
    ) -> Result<(Arc<RegistryClient>, bool), LpmError> {
        let posture = mode.auth_posture();
        if !mode.is_enabled()
            || self.base.has_bearer_for_posture(posture)?
            || !crate::oidc::registry_exchange_jwt_available()
        {
            return Ok((Arc::clone(&self.base), false));
        }

        let client = self
            .ci_oidc
            .get_or_try_init(|| async {
                let oidc_token = crate::oidc::exchange_oidc_token(
                    &self.base,
                    self.base.base_url(),
                    None,
                    "read",
                )
                .await?;
                Ok::<Arc<RegistryClient>, LpmError>(Arc::new(
                    self.base
                        .clone_with_config()
                        .with_token_override(oidc_token.token),
                ))
            })
            .await?;
        Ok((Arc::clone(client), true))
    }
}

impl NpmFirewallMode {
    pub(super) fn auth_posture(self) -> AuthPosture {
        match self {
            Self::Off => AuthPosture::AnonymousPreferred,
            Self::Monitor | Self::Enforce => AuthPosture::AuthRequired,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum NpmFirewallLookupMode {
    PackageAndIntegrity,
    #[default]
    PackageOnly,
}

impl NpmFirewallLookupMode {
    pub(super) fn from_env() -> Self {
        Self::from_env_value(
            std::env::var(ENV_EXPERIMENT_NPM_FIREWALL_LOOKUP)
                .ok()
                .as_deref(),
        )
    }

    pub(super) fn from_env_value(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            Some(value)
                if value.eq_ignore_ascii_case("package")
                    || value.eq_ignore_ascii_case("package-only")
                    || value.eq_ignore_ascii_case("package_only")
                    || value.eq_ignore_ascii_case("package-version")
                    || value.eq_ignore_ascii_case("package_version") =>
            {
                Self::PackageOnly
            }
            Some(value)
                if value.eq_ignore_ascii_case("package-and-integrity")
                    || value.eq_ignore_ascii_case("package_and_integrity")
                    || value.eq_ignore_ascii_case("integrity")
                    || value.eq_ignore_ascii_case("strict") =>
            {
                Self::PackageAndIntegrity
            }
            _ => Self::PackageOnly,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::PackageAndIntegrity => "package_and_integrity",
            Self::PackageOnly => "package_only",
        }
    }

    fn include_integrity(self) -> bool {
        matches!(self, Self::PackageAndIntegrity)
    }
}

pub(super) fn npm_firewall_chunk_size_from_env() -> usize {
    std::env::var(ENV_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE)
        .ok()
        .as_deref()
        .map_or(DEFAULT_NPM_FIREWALL_CHUNK_SIZE, npm_firewall_chunk_size)
}

pub(super) fn npm_firewall_chunk_size(raw: &str) -> usize {
    raw.trim()
        .parse::<usize>()
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(DEFAULT_NPM_FIREWALL_CHUNK_SIZE)
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct NpmFirewallPreflightStats {
    pub(super) mode: NpmFirewallMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) checked_count: u64,
    pub(super) batch_ms: u128,
    pub(super) chunk_count: u64,
    pub(super) chunk_sum_ms: u128,
    pub(super) chunk_max_ms: u128,
    pub(super) allow_count: u64,
    pub(super) warn_count: u64,
    pub(super) block_count: u64,
    /// Blocks a verdict summary counted beyond the decision rows it returned,
    /// so no package can be named for them.
    pub(super) unattributed_block_count: u64,
    /// Why some packages went unchecked after a block was already found. The
    /// command fails on the block either way; this keeps the failure that
    /// names it from being replaced by the later request error.
    pub(super) unchecked_reason: Option<String>,
    /// Blocked versions that bypass rules lifted; once a verdict request
    /// fails, only those already released to download.
    pub(super) bypassed: Vec<BypassedVerdict>,
    /// Why the bypass rules couldn't be read, when a block needed them.
    pub(super) bypass_error: Option<String>,
    /// Whether rules saved with `lpm firewall bypass add` apply here.
    pub(super) local_bypass_available: bool,
    /// Whether `lpm firewall bypass add` would accept a new rule here.
    pub(super) bypass_additions_allowed: bool,
    /// The managed security policy that keeps local bypass rules from
    /// applying, when one does.
    pub(super) managed_policy_path: Option<String>,
    pub(super) unknown_count: u64,
    pub(super) matched_count: u64,
    pub(super) cache_hit_count: u64,
    pub(super) rpc_failed: bool,
    pub(super) offline_skipped: bool,
    pub(super) worker_diagnostics: Option<NpmFirewallDiagnostics>,
    pub(super) client_timing: Option<NpmFirewallClientTiming>,
}

impl NpmFirewallPreflightStats {
    fn for_mode(mode: NpmFirewallMode, lookup_mode: NpmFirewallLookupMode) -> Self {
        Self {
            mode,
            lookup_mode,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn record_summary(&mut self, summary: lpm_registry::client::NpmFirewallSummary) {
        self.allow_count = summary.allow;
        self.warn_count = summary.warn;
        self.block_count = summary.block;
        self.unknown_count = summary.unknown;
        self.matched_count = summary.matched;
    }

    fn add_summary(&mut self, summary: lpm_registry::client::NpmFirewallSummary) {
        self.allow_count = self.allow_count.saturating_add(summary.allow);
        self.warn_count = self.warn_count.saturating_add(summary.warn);
        self.block_count = self.block_count.saturating_add(summary.block);
        self.unknown_count = self.unknown_count.saturating_add(summary.unknown);
        self.matched_count = self.matched_count.saturating_add(summary.matched);
    }

    #[cfg(test)]
    pub(super) fn record_worker_diagnostics(
        &mut self,
        diagnostics: Option<NpmFirewallDiagnostics>,
    ) {
        self.worker_diagnostics = diagnostics;
    }

    #[cfg(test)]
    pub(super) fn record_client_timing(&mut self, timing: Option<NpmFirewallClientTiming>) {
        self.client_timing = timing;
    }

    fn record_response(&mut self, response: &NpmFirewallBatchResponse, elapsed_ms: u128) {
        self.chunk_count = self.chunk_count.saturating_add(1);
        self.chunk_sum_ms = self.chunk_sum_ms.saturating_add(elapsed_ms);
        self.chunk_max_ms = self.chunk_max_ms.max(elapsed_ms);
        self.add_summary(response.summary);
        add_worker_diagnostics(&mut self.worker_diagnostics, response.diagnostics.clone());
        add_client_timing(&mut self.client_timing, response.client_timing);
    }

    /// Adds one classified response and returns its decision rows.
    fn record_classified(&mut self, classified: ClassifiedVerdicts) -> Vec<NpmFirewallDecision> {
        self.unattributed_block_count = self
            .unattributed_block_count
            .saturating_add(classified.unattributed);
        self.bypassed.extend(classified.bypassed);
        if self.bypass_error.is_none() {
            self.bypass_error = classified.bypass_error;
        }
        classified.decisions
    }

    fn note_bypass_rules(&mut self, bypass: &FirewallBypassRules) {
        self.local_bypass_available = bypass.local_rules_apply();
        self.bypass_additions_allowed = bypass.additions_allowed();
        self.managed_policy_path = bypass.managed_policy_path().map(str::to_string);
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "enabled": self.mode.is_enabled(),
            "mode": self.mode.as_str(),
            "lookup_mode": self.lookup_mode.as_str(),
            "checked_count": self.checked_count,
            "batch_ms": self.batch_ms,
            "chunk_count": self.chunk_count,
            "chunk_sum_ms": self.chunk_sum_ms,
            "chunk_max_ms": self.chunk_max_ms,
            "allow_count": self.allow_count,
            "warn_count": self.warn_count,
            "block_count": self.block_count,
            "unknown_count": self.unknown_count,
            "matched_count": self.matched_count,
            "rpc_failed": self.rpc_failed,
            "offline_skipped": self.offline_skipped,
        });
        if self.mode.is_enabled() || self.cache_hit_count > 0 {
            json["cache_hit_count"] = serde_json::json!(self.cache_hit_count);
        }
        if self.mode.is_enabled() {
            json["unattributed_block_count"] = serde_json::json!(self.unattributed_block_count);
            json["bypassed_count"] = serde_json::json!(self.bypassed.len());
        }
        if let Some(diagnostics) = &self.worker_diagnostics {
            json["worker"] = serde_json::to_value(diagnostics).unwrap_or(serde_json::Value::Null);
        }
        if let Some(timing) = &self.client_timing {
            json["client"] = serde_json::to_value(timing).unwrap_or(serde_json::Value::Null);
        }
        json
    }
}

impl NpmFirewallPreflightStats {
    /// [`Self::to_json`] plus each version a bypass rule let through, for the
    /// `security.firewall` report; timing sections keep the counts alone.
    pub(super) fn to_security_json(&self) -> serde_json::Value {
        let mut json = self.to_json();
        if !self.bypassed.is_empty() {
            json["bypassed"] = serde_json::Value::Array(
                self.bypassed.iter().map(BypassedVerdict::to_json).collect(),
            );
        }
        json
    }
}

/// A blocked version a bypass rule let through, and the rule.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct BypassedVerdict {
    pub(super) decision: NpmFirewallDecision,
    pub(super) rule: AppliedRule,
}

impl BypassedVerdict {
    pub(super) fn to_json(&self) -> serde_json::Value {
        let mut json = npm_firewall_decision_json(&self.decision);
        json["rule"] = self.rule.to_json();
        json
    }
}

/// One verdict response, checked against the packages it asked about.
struct ClassifiedVerdicts {
    /// Rows no bypass rule lifted.
    decisions: Vec<NpmFirewallDecision>,
    bypassed: Vec<BypassedVerdict>,
    /// Blocks the summary counted without a decision row.
    unattributed: u64,
    bypass_error: Option<String>,
}

impl ClassifiedVerdicts {
    fn blocks(&self) -> bool {
        self.unattributed > 0
            || self
                .decisions
                .iter()
                .any(|decision| decision.action == NpmFirewallAction::Block)
    }
}

/// Splits a response's blocks into those a bypass rule lifts and those that
/// stand. Each block row is matched to one version this request asked about,
/// as many times as it was asked; a row beyond that, or for a version it never
/// asked about, names nothing and is dropped but still counts as an unnamed
/// block, as does a block the summary counts without a row. Only matched rows
/// can be lifted, and only by a rule whose kind may cover the block.
async fn classify_verdicts(
    response: NpmFirewallBatchResponse,
    requested: &[NpmFirewallBatchPackage],
    bypass: &FirewallBypassRules,
) -> ClassifiedVerdicts {
    let mut requested_counts: HashMap<&str, Vec<(&str, u32)>> =
        HashMap::with_capacity(requested.len());
    for package in requested {
        let versions = requested_counts.entry(package.name.as_str()).or_default();
        match versions
            .iter_mut()
            .find(|(version, _)| *version == package.version)
        {
            Some((_, count)) => *count += 1,
            None => versions.push((package.version.as_str(), 1)),
        }
    }
    let mut decisions = Vec::with_capacity(response.decisions.len());
    let mut block_rows: u64 = 0;
    let mut group_of: HashMap<(String, String), usize> = HashMap::new();
    let mut groups: Vec<((String, String), Vec<NpmFirewallDecision>)> = Vec::new();
    for decision in response.decisions {
        if decision.action != NpmFirewallAction::Block {
            decisions.push(decision);
            continue;
        }
        block_rows += 1;
        let key = (decision.name.clone(), decision.version.clone());
        match group_of.get(&key) {
            Some(&index) => groups[index].1.push(decision),
            None => {
                group_of.insert(key.clone(), groups.len());
                groups.push((key, vec![decision]));
            }
        }
    }
    // Each version keeps its hardest rows, as many as it was requested, so an
    // excess row never hides a block a rule can't lift.
    let mut matched_blocks = Vec::with_capacity(groups.len());
    for ((name, version), mut rows) in groups {
        let requested_count = requested_counts
            .get(name.as_str())
            .and_then(|versions| versions.iter().find(|(requested, _)| *requested == version))
            .map_or(0, |(_, count)| *count as usize);
        if requested_count == 0 {
            continue;
        }
        rows.sort_by_key(|row| std::cmp::Reverse(decision_block_class(row).lift_difficulty()));
        rows.truncate(requested_count);
        matched_blocks.extend(rows);
    }
    let mut classified = ClassifiedVerdicts {
        decisions,
        bypassed: Vec::new(),
        unattributed: response
            .summary
            .block
            .max(block_rows)
            .saturating_sub(matched_blocks.len() as u64),
        bypass_error: None,
    };
    if matched_blocks.is_empty() || bypass.is_empty() {
        classified.decisions.extend(matched_blocks);
        return classified;
    }
    let (rules, local_error) = bypass.load().await;
    classified.bypass_error = local_error.map(str::to_string);
    let now = lpm_common::Timestamp::now();
    for decision in matched_blocks {
        let applied = rules
            .find(
                &decision.name,
                &decision.version,
                decision_block_class(&decision),
                now,
            )
            .cloned();
        match applied {
            Some(rule) => classified.bypassed.push(BypassedVerdict { decision, rule }),
            None => classified.decisions.push(decision),
        }
    }
    classified
}

fn decision_block_class(decision: &NpmFirewallDecision) -> BlockClass {
    BlockClass::of(
        &decision.verdict,
        decision.policy.as_ref().map(|policy| policy.group.as_str()),
    )
}

fn add_client_timing(
    aggregate: &mut Option<NpmFirewallClientTiming>,
    timing: Option<NpmFirewallClientTiming>,
) {
    let Some(timing) = timing else {
        return;
    };
    let total = aggregate.get_or_insert_with(NpmFirewallClientTiming::default);
    total.request_ms = total.request_ms.saturating_add(timing.request_ms);
    total.body_read_ms = total.body_read_ms.saturating_add(timing.body_read_ms);
    total.json_parse_ms = total.json_parse_ms.saturating_add(timing.json_parse_ms);
    total.total_ms = total.total_ms.saturating_add(timing.total_ms);
    total.request_body_bytes = total
        .request_body_bytes
        .saturating_add(timing.request_body_bytes);
    total.response_body_bytes = total
        .response_body_bytes
        .saturating_add(timing.response_body_bytes);
}

fn add_worker_diagnostics(
    aggregate: &mut Option<NpmFirewallDiagnostics>,
    diagnostics: Option<NpmFirewallDiagnostics>,
) {
    let Some(diagnostics) = diagnostics else {
        return;
    };
    let total = aggregate.get_or_insert_with(NpmFirewallDiagnostics::default);
    total.package_count = total
        .package_count
        .saturating_add(diagnostics.package_count);
    total.lookup_concurrency = total.lookup_concurrency.max(diagnostics.lookup_concurrency);
    total.kv_read_count = total
        .kv_read_count
        .saturating_add(diagnostics.kv_read_count);
    total.kv_lookup_ms += diagnostics.kv_lookup_ms;
    total.entitlement_ms += diagnostics.entitlement_ms;
    total.parse_ms += diagnostics.parse_ms;
    total.total_ms += diagnostics.total_ms;
    total.matched_count = total
        .matched_count
        .saturating_add(diagnostics.matched_count);
    total.decision_detail = total
        .decision_detail
        .take()
        .or(diagnostics.decision_detail.clone());
    total.returned_decision_count = total
        .returned_decision_count
        .saturating_add(diagnostics.returned_decision_count);
    total.kv_namespace_label = total
        .kv_namespace_label
        .take()
        .or(diagnostics.kv_namespace_label.clone());
    add_flagged_index_diagnostics(
        &mut total.flagged_package_index,
        diagnostics.flagged_package_index,
    );
    total.match_sources.integrity = total
        .match_sources
        .integrity
        .saturating_add(diagnostics.match_sources.integrity);
    total.match_sources.package = total
        .match_sources
        .package
        .saturating_add(diagnostics.match_sources.package);
    total.match_sources.none = total
        .match_sources
        .none
        .saturating_add(diagnostics.match_sources.none);
    total.lookup_duration.count = total
        .lookup_duration
        .count
        .saturating_add(diagnostics.lookup_duration.count);
    total.lookup_duration.sum_ms += diagnostics.lookup_duration.sum_ms;
    total.lookup_duration.max_ms = total
        .lookup_duration
        .max_ms
        .max(diagnostics.lookup_duration.max_ms);
    total.lookup_duration.p50_ms = total
        .lookup_duration
        .p50_ms
        .max(diagnostics.lookup_duration.p50_ms);
    total.lookup_duration.p95_ms = total
        .lookup_duration
        .p95_ms
        .max(diagnostics.lookup_duration.p95_ms);
}

fn add_flagged_index_diagnostics(
    aggregate: &mut Option<NpmFirewallFlaggedPackageIndexDiagnostics>,
    diagnostics: Option<NpmFirewallFlaggedPackageIndexDiagnostics>,
) {
    let Some(diagnostics) = diagnostics else {
        return;
    };
    let total = aggregate.get_or_insert_with(NpmFirewallFlaggedPackageIndexDiagnostics::default);
    total.enabled |= diagnostics.enabled;
    total.used |= diagnostics.used;
    total.status = total.status.take().or(diagnostics.status);
    total.cache_status = total.cache_status.take().or(diagnostics.cache_status);
    total.key = total.key.take().or(diagnostics.key);
    total.read_ms += diagnostics.read_ms;
    total.package_key_count = total.package_key_count.max(diagnostics.package_key_count);
    total.candidate_count = total
        .candidate_count
        .saturating_add(diagnostics.candidate_count);
    total.detail_read_count = total
        .detail_read_count
        .saturating_add(diagnostics.detail_read_count);
    total.skipped_package_lookup_count = total
        .skipped_package_lookup_count
        .saturating_add(diagnostics.skipped_package_lookup_count);
    total.generated_at = total.generated_at.take().or(diagnostics.generated_at);
}

#[derive(Debug)]
pub(super) struct NpmFirewallPreflightResult {
    pub(super) stats: NpmFirewallPreflightStats,
    pub(super) decisions: Vec<NpmFirewallDecision>,
    pub(super) report_error: Option<String>,
    /// An enforce-mode verdict request that failed with nothing blocked,
    /// which ends the install once what the other requests found is
    /// reported.
    pub(super) failure: Option<LpmError>,
}

impl NpmFirewallPreflightResult {
    fn empty(mode: NpmFirewallMode, lookup_mode: NpmFirewallLookupMode) -> Self {
        Self {
            stats: NpmFirewallPreflightStats::for_mode(mode, lookup_mode),
            decisions: Vec::new(),
            report_error: None,
            failure: None,
        }
    }
}

pub(super) struct NpmFirewallPreflightJoin {
    handle: Option<tokio::task::JoinHandle<Result<NpmFirewallPreflightResult, LpmError>>>,
}

impl NpmFirewallPreflightJoin {
    pub(super) async fn drain(mut self) -> Result<NpmFirewallPreflightResult, LpmError> {
        let handle = self.handle.as_mut().ok_or_else(|| {
            LpmError::Registry("npm firewall preflight task was already drained".into())
        })?;
        handle.await.map_err(|error| {
            LpmError::Registry(format!("npm firewall preflight task panicked: {error}"))
        })?
    }
}

impl Drop for NpmFirewallPreflightJoin {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

struct FirewallSelectedChunk {
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
}

impl FirewallSelectedChunk {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            verdict_packages: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.events.len().max(self.verdict_packages.len())
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty() && self.verdict_packages.is_empty()
    }

    fn clear(&mut self) {
        self.events.clear();
        self.verdict_packages.clear();
    }
}

struct FirewallChunkResult {
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
    response: Option<NpmFirewallBatchResponse>,
    elapsed_ms: u128,
    report_error: Option<String>,
}

pub(super) struct NpmFirewallChunkedPreflightConfig {
    pub(super) route_table: RouteTable,
    pub(super) mode: NpmFirewallMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) policy_profile: NpmFirewallPolicyProfile,
    pub(super) offline: bool,
    pub(super) chunk_size: usize,
    pub(super) bypass: FirewallBypassRules,
    /// Where each version a rule lifts is kept once its chunk is released to
    /// download, so the install can report it if it fails before this check
    /// reports.
    pub(super) released_bypasses: Arc<super::ReleasedFirewallBypasses>,
}

pub(super) fn spawn_chunked_npm_firewall_preflight(
    mut selected_rx: tokio::sync::mpsc::Receiver<lpm_resolver::SelectedPackageEvent>,
    fetch_tx: tokio::sync::mpsc::Sender<lpm_resolver::SelectedPackageEvent>,
    client: Arc<RegistryClient>,
    config: NpmFirewallChunkedPreflightConfig,
) -> NpmFirewallPreflightJoin {
    let handle = tokio::spawn(async move {
        let NpmFirewallChunkedPreflightConfig {
            route_table,
            mode,
            lookup_mode,
            policy_profile,
            offline,
            chunk_size,
            bypass,
            released_bypasses,
        } = config;

        if !mode.is_enabled() {
            while let Some(event) = selected_rx.recv().await {
                if fetch_tx.send(event).await.is_err() {
                    break;
                }
            }
            return Ok(NpmFirewallPreflightResult::empty(mode, lookup_mode));
        }
        let chunk_size = chunk_size.max(1);
        let mut stats = NpmFirewallPreflightStats::for_mode(mode, lookup_mode);
        stats.note_bypass_rules(&bypass);
        let mut decisions = Vec::new();
        let mut report_error = None;
        let total_started = Instant::now();

        if offline {
            if matches!(mode, NpmFirewallMode::Enforce) {
                return Err(LpmError::Registry(NPM_FIREWALL_OFFLINE_HINT.to_string()));
            }
            stats.offline_skipped = true;
            while let Some(event) = selected_rx.recv().await {
                if npm_firewall_package_from_selected_event(
                    &event,
                    &route_table,
                    client.as_ref(),
                    lookup_mode,
                )
                .is_some()
                {
                    stats.checked_count = stats.checked_count.saturating_add(1);
                }
                if fetch_tx.send(event).await.is_err() {
                    break;
                }
            }
            report_error = Some(format!(
                "{NPM_FIREWALL_OFFLINE_HINT}; continuing because monitor mode is active"
            ));
            stats.batch_ms = total_started.elapsed().as_millis();
            return Ok(NpmFirewallPreflightResult {
                failure: None,
                stats,
                decisions,
                report_error,
            });
        }

        let preflight_client = NpmFirewallPreflightClient::new(Arc::clone(&client));
        let dispatch = FirewallChunkDispatch {
            fetch_tx: &fetch_tx,
            client: &preflight_client,
            mode,
            policy_profile,
            bypass: &bypass,
            released_bypasses: &released_bypasses,
        };
        let mut chunk = FirewallSelectedChunk::with_capacity(chunk_size);
        let mut receiver_closed = false;
        let mut tasks = tokio::task::JoinSet::new();
        // After an enforced block, or a failed request, the install fails, so
        // later chunks are still checked to name every blocked package, but
        // nothing more downloads.
        let mut blocked = false;
        let mut failure: Option<LpmError> = None;
        // What rules lifted in chunks held back from download.
        let mut held_bypassed = Vec::new();

        loop {
            tokio::select! {
                event = selected_rx.recv(), if !receiver_closed => {
                    match event {
                        Some(event) => {
                            if let Some(released) = push_firewall_chunk_event(
                                &mut chunk,
                                event,
                                &route_table,
                                client.as_ref(),
                                lookup_mode,
                                mode.disables_tarball_prefetch(),
                            ) {
                                let _ = fetch_tx.send(released).await;
                            }
                            if chunk.len() >= chunk_size {
                                spawn_or_release_firewall_chunk(
                                    &mut chunk,
                                    &dispatch,
                                    blocked || failure.is_some(),
                                    &mut stats,
                                    &mut tasks,
                                )
                                .await;
                            }
                        }
                        None => {
                            receiver_closed = true;
                            spawn_or_release_firewall_chunk(
                                &mut chunk,
                                &dispatch,
                                blocked || failure.is_some(),
                                &mut stats,
                                &mut tasks,
                            )
                            .await;
                        }
                    }
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let chunk_result = match joined
                        .ok_or_else(|| LpmError::Registry("npm firewall chunk task ended unexpectedly".into()))?
                        .map_err(|error| LpmError::Registry(format!("npm firewall chunk task panicked: {error}")))?
                    {
                        Ok(chunk_result) => chunk_result,
                        Err(error) => {
                            failure.get_or_insert(error);
                            continue;
                        }
                    };
                    let applied = apply_firewall_chunk_result(
                        chunk_result,
                        &dispatch,
                        blocked || failure.is_some(),
                        &mut stats,
                        &mut decisions,
                        &mut held_bypassed,
                        &mut report_error,
                    )
                    .await;
                    blocked |= applied.blocks;
                    if applied.lifted_version_not_handed_off {
                        failure.get_or_insert_with(|| {
                            LpmError::Registry(
                                "npm firewall preflight couldn't hand a version a bypass rule let through to the download, which has stopped".into(),
                            )
                        });
                    }
                }
                else => {
                    if receiver_closed && tasks.is_empty() {
                        break;
                    }
                }
            }
        }

        let failure = match failure {
            Some(error) if blocked => {
                stats.unchecked_reason = Some(error.to_string());
                None
            }
            failure => failure,
        };
        // A block names every version a rule lifted, downloaded or not;
        // otherwise only what was released to download was let through.
        if blocked {
            stats.bypassed.append(&mut held_bypassed);
        }
        stats.batch_ms = total_started.elapsed().as_millis();
        Ok(NpmFirewallPreflightResult {
            stats,
            decisions,
            report_error,
            failure,
        })
    });
    NpmFirewallPreflightJoin {
        handle: Some(handle),
    }
}

/// Adds the event's verdict request to the chunk. An event that must wait for
/// the verdict stays in the chunk; otherwise it is returned for immediate
/// release.
fn push_firewall_chunk_event(
    chunk: &mut FirewallSelectedChunk,
    event: lpm_resolver::SelectedPackageEvent,
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
    hold_for_verdict: bool,
) -> Option<lpm_resolver::SelectedPackageEvent> {
    if let Some(verdict_package) =
        npm_firewall_package_from_selected_event(&event, route_table, client, lookup_mode)
        && !chunk
            .verdict_packages
            .iter()
            .any(|requested| same_verdict_request(requested, &verdict_package))
    {
        chunk.verdict_packages.push(verdict_package);
    }
    if hold_for_verdict {
        chunk.events.push(event);
        None
    } else {
        Some(event)
    }
}

/// What every chunk of one streaming preflight shares.
struct FirewallChunkDispatch<'a> {
    fetch_tx: &'a tokio::sync::mpsc::Sender<lpm_resolver::SelectedPackageEvent>,
    client: &'a NpmFirewallPreflightClient,
    mode: NpmFirewallMode,
    policy_profile: NpmFirewallPolicyProfile,
    bypass: &'a FirewallBypassRules,
    released_bypasses: &'a super::ReleasedFirewallBypasses,
}

async fn spawn_or_release_firewall_chunk(
    chunk: &mut FirewallSelectedChunk,
    dispatch: &FirewallChunkDispatch<'_>,
    blocked: bool,
    stats: &mut NpmFirewallPreflightStats,
    tasks: &mut tokio::task::JoinSet<Result<FirewallChunkResult, LpmError>>,
) {
    let FirewallChunkDispatch {
        fetch_tx,
        client,
        mode,
        policy_profile,
        bypass: _,
        released_bypasses: _,
    } = *dispatch;
    if chunk.is_empty() {
        return;
    }
    if chunk.verdict_packages.is_empty() {
        if !blocked {
            release_firewall_events(fetch_tx, chunk.events.drain(..)).await;
        }
        chunk.clear();
        return;
    }

    stats.checked_count = stats
        .checked_count
        .saturating_add(chunk.verdict_packages.len() as u64);
    let events = std::mem::take(&mut chunk.events);
    let verdict_packages = std::mem::take(&mut chunk.verdict_packages);
    let client = client.clone();
    tasks.spawn(async move {
        request_firewall_chunk(client, mode, policy_profile, events, verdict_packages).await
    });
}

async fn request_firewall_chunk(
    client: NpmFirewallPreflightClient,
    mode: NpmFirewallMode,
    policy_profile: NpmFirewallPolicyProfile,
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
) -> Result<FirewallChunkResult, LpmError> {
    let started = Instant::now();
    let response = match client
        .batch_verdicts(mode, policy_profile, &verdict_packages)
        .await
    {
        Ok(response) => response,
        Err(error) if matches!(mode, NpmFirewallMode::Monitor) => {
            return Ok(FirewallChunkResult {
                events,
                verdict_packages,
                response: None,
                elapsed_ms: started.elapsed().as_millis(),
                report_error: Some(npm_firewall_preflight_report_error(error)),
            });
        }
        Err(error) => {
            return Err(npm_firewall_preflight_enforce_error(error));
        }
    };
    Ok(FirewallChunkResult {
        events,
        verdict_packages,
        response: Some(response),
        elapsed_ms: started.elapsed().as_millis(),
        report_error: None,
    })
}

fn npm_firewall_preflight_report_error(error: LpmError) -> String {
    let error = normalize_npm_firewall_preflight_error(error);
    let recovery = if matches!(error, LpmError::EnvTokenRejected) {
        ". Replace LPM_TOKEN with a valid token, or unset LPM_TOKEN to use your saved login."
    } else {
        ""
    };
    format!("npm firewall verdict preflight failed in monitor mode: {error}{recovery}")
}

fn npm_firewall_preflight_enforce_error(error: LpmError) -> LpmError {
    match normalize_npm_firewall_preflight_error(error) {
        error @ (LpmError::AuthRequired
        | LpmError::EnvTokenRejected
        | LpmError::SessionExpired
        | LpmError::NpmFirewallEntitlementRequired { .. }) => error,
        error if error.is_credential_storage_failure() => error,
        error => LpmError::Registry(format!("npm firewall verdict preflight failed: {error}")),
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn enforced_preflight_preserves_environment_token_recovery() {
        assert!(matches!(
            npm_firewall_preflight_enforce_error(LpmError::EnvTokenRejected),
            LpmError::EnvTokenRejected
        ));
    }

    #[test]
    fn enforced_preflight_keeps_local_credential_storage_error_codes() {
        for (error, code) in [
            (
                LpmError::CredentialStorage("failed to read stored access credential".into()),
                "credential_storage",
            ),
            (
                LpmError::CredentialStorageLocked("failed to read stored access credential".into()),
                "credential_storage_locked",
            ),
        ] {
            let error = npm_firewall_preflight_enforce_error(error);

            assert_eq!(error.error_code(), code, "{error}");
        }
    }

    #[test]
    fn monitored_preflight_explains_environment_token_recovery() {
        let warning = npm_firewall_preflight_report_error(LpmError::EnvTokenRejected);
        assert!(warning.contains("unset LPM_TOKEN"), "{warning}");
        assert!(!warning.contains("lpm login"), "{warning}");
    }
}

fn normalize_npm_firewall_preflight_error(error: LpmError) -> LpmError {
    match error {
        LpmError::UpstreamProxyEntitlementRequired {
            message,
            reason,
            entitlement_source,
        } => LpmError::NpmFirewallEntitlementRequired {
            message,
            reason,
            entitlement_source,
        },
        error => error,
    }
}

/// Records a finished chunk and releases its events for download unless the
/// chunk, or an earlier one, blocks in enforce mode. Returns whether this
/// chunk blocks.
/// What applying one chunk's verdicts found.
#[derive(Default)]
struct AppliedChunk {
    /// An enforced block the install fails on.
    blocks: bool,
    /// A version a rule lifted whose events never reached the downloader:
    /// the install can't go on to download it unreported, so the check fails.
    lifted_version_not_handed_off: bool,
}

async fn apply_firewall_chunk_result(
    chunk_result: FirewallChunkResult,
    dispatch: &FirewallChunkDispatch<'_>,
    earlier_block: bool,
    stats: &mut NpmFirewallPreflightStats,
    decisions: &mut Vec<NpmFirewallDecision>,
    held_bypassed: &mut Vec<BypassedVerdict>,
    report_error: &mut Option<String>,
) -> AppliedChunk {
    let fetch_tx = dispatch.fetch_tx;
    let mode = dispatch.mode;
    if let Some(error) = chunk_result.report_error {
        stats.rpc_failed = true;
        stats.chunk_count = stats.chunk_count.saturating_add(1);
        stats.chunk_sum_ms = stats.chunk_sum_ms.saturating_add(chunk_result.elapsed_ms);
        stats.chunk_max_ms = stats.chunk_max_ms.max(chunk_result.elapsed_ms);
        if report_error.is_none() {
            *report_error = Some(error);
        }
        release_firewall_events(fetch_tx, chunk_result.events).await;
        return AppliedChunk::default();
    }

    let Some(response) = chunk_result.response else {
        release_firewall_events(fetch_tx, chunk_result.events).await;
        return AppliedChunk::default();
    };

    stats.record_response(&response, chunk_result.elapsed_ms);
    tracing::debug!(
        target = "lpm::firewall",
        package_count = response.summary.total,
        matched = response.summary.matched,
        warn = response.summary.warn,
        block = response.summary.block,
        elapsed_ms = chunk_result.elapsed_ms,
        request_id = %response.request_id,
        policy_mode = %response.policy_mode,
        "npm firewall verdict chunk completed",
    );
    let mut classified =
        classify_verdicts(response, &chunk_result.verdict_packages, dispatch.bypass).await;
    let chunk_has_block = classified.blocks();
    let enforce = matches!(mode, NpmFirewallMode::Enforce);
    let release = !(enforce && (chunk_has_block || earlier_block));
    let mut lifted_version_not_handed_off = false;
    if !release {
        held_bypassed.append(&mut classified.bypassed);
    } else if enforce {
        let delivered = hand_off_firewall_events(
            fetch_tx,
            chunk_result.events,
            &classified.bypassed,
            mode,
            dispatch.released_bypasses,
        )
        .await;
        // A version none of whose events reached the downloader was let
        // through by nothing, so it stays with the held ones.
        let lifted = std::mem::take(&mut classified.bypassed);
        for (verdict, delivered) in lifted.into_iter().zip(delivered) {
            if delivered {
                classified.bypassed.push(verdict);
            } else {
                lifted_version_not_handed_off = true;
                held_bypassed.push(verdict);
            }
        }
    } else {
        release_firewall_events(fetch_tx, chunk_result.events).await;
    }
    decisions.extend(stats.record_classified(classified));
    AppliedChunk {
        blocks: enforce && chunk_has_block,
        lifted_version_not_handed_off,
    }
}

/// Sends each of `events` to the downloader together with the lifted
/// versions it carries, so the install's record of `released` names exactly
/// what reached the downloader, and stops once the install closes it or the
/// downloader stops. Returns, for each of `lifted`, whether an event carrying
/// it was sent.
async fn hand_off_firewall_events(
    fetch_tx: &tokio::sync::mpsc::Sender<lpm_resolver::SelectedPackageEvent>,
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    lifted: &[BypassedVerdict],
    mode: NpmFirewallMode,
    released: &super::ReleasedFirewallBypasses,
) -> Vec<bool> {
    let mut delivered = vec![false; lifted.len()];
    for event in events {
        let Ok(permit) = fetch_tx.reserve().await else {
            break;
        };
        let carried: Vec<usize> = lifted
            .iter()
            .enumerate()
            .filter(|(_, verdict)| {
                verdict.decision.name == event.name && verdict.decision.version == event.version
            })
            .map(|(index, _)| index)
            .collect();
        if !released.hand_off(
            mode,
            carried.iter().map(|&index| &lifted[index]),
            permit,
            event,
            fetch_tx,
        ) {
            break;
        }
        for index in carried {
            delivered[index] = true;
        }
    }
    delivered
}

async fn release_firewall_events(
    fetch_tx: &tokio::sync::mpsc::Sender<lpm_resolver::SelectedPackageEvent>,
    events: impl IntoIterator<Item = lpm_resolver::SelectedPackageEvent>,
) {
    for event in events {
        if fetch_tx.send(event).await.is_err() {
            break;
        }
    }
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
struct MonitorVerdictCacheEntry {
    expires_at: u64,
    #[serde(default)]
    unknown: bool,
    #[serde(default)]
    matched: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MonitorVerdictCacheFile {
    version: u8,
    entries: HashMap<String, MonitorVerdictCacheEntry>,
}

const MONITOR_VERDICT_CACHE_VERSION: u8 = 3;
const MONITOR_VERDICT_SUBDIR: &str = "firewall-verdicts";

fn monitor_verdict_cache_enabled_with_env(
    mode: NpmFirewallMode,
    force: bool,
    offline: bool,
    env_value: Option<&str>,
) -> bool {
    if !matches!(mode, NpmFirewallMode::Monitor) || force || offline {
        return false;
    }
    !env_value.is_some_and(|raw| {
        let trimmed = raw.trim();
        trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("0")
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("no")
    })
}

fn monitor_verdict_cache_enabled(mode: NpmFirewallMode, force: bool, offline: bool) -> bool {
    let env_value = std::env::var(ENV_NPM_FIREWALL_CACHE).ok();
    monitor_verdict_cache_enabled_with_env(mode, force, offline, env_value.as_deref())
}

#[derive(Clone)]
struct MonitorVerdictCacheTarget {
    cache_root: PathBuf,
    filename: String,
}

fn monitor_verdict_cache_target(
    client: &RegistryClient,
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    policy_profile: NpmFirewallPolicyProfile,
) -> Result<Option<MonitorVerdictCacheTarget>, LpmError> {
    use sha2::Digest as _;

    let Some(cache_root) = client.cache_dir() else {
        return Ok(None);
    };
    let Some(auth_fp) = client.firewall_cache_identity_fingerprint(mode.auth_posture())? else {
        return Ok(None);
    };
    let policy_bytes = serde_json::to_vec(&policy_profile).unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"lpm-firewall-verdict-cache-v3\0");
    hasher.update(client.base_url().as_bytes());
    hasher.update(b"\0");
    hasher.update(lookup_mode.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(auth_fp.as_bytes());
    hasher.update(b"\0");
    hasher.update(&policy_bytes);
    let digest = hasher.finalize();
    let mut filename = String::with_capacity(37);
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        let _ = write!(&mut filename, "{byte:02x}");
    }
    filename.push_str(".json");
    Ok(Some(MonitorVerdictCacheTarget {
        cache_root: cache_root.to_path_buf(),
        filename,
    }))
}

fn monitor_verdict_entry_key(
    pkg: &NpmFirewallBatchPackage,
    lookup_mode: NpmFirewallLookupMode,
) -> String {
    match lookup_mode {
        NpmFirewallLookupMode::PackageOnly => {
            let mut key = String::with_capacity(pkg.name.len() + 1 + pkg.version.len());
            key.push_str(&pkg.name);
            key.push('\0');
            key.push_str(&pkg.version);
            key
        }
        NpmFirewallLookupMode::PackageAndIntegrity => {
            let integrity = pkg.integrity.as_deref().unwrap_or("");
            let mut key =
                String::with_capacity(pkg.name.len() + 2 + pkg.version.len() + integrity.len());
            key.push_str(&pkg.name);
            key.push('\0');
            key.push_str(&pkg.version);
            key.push('\0');
            key.push_str(integrity);
            key
        }
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn is_valid_monitor_verdict_expiry(expires_at: u64, now_secs: u64) -> bool {
    let max_expiry = now_secs.saturating_add(DEFAULT_MONITOR_VERDICT_CACHE_TTL_SECS);
    expires_at > now_secs && expires_at <= max_expiry
}

struct OpenedMonitorVerdictDir {
    dir: cap_std::fs::Dir,
    was_previously_untrusted: bool,
}

#[cfg(unix)]
fn is_trusted_verdict_file_unix(file_uid: u32, euid: u32, mode: u32) -> bool {
    file_uid == euid && (mode & 0o077) == 0
}

fn open_monitor_verdict_cache_dir_nofollow(
    cache_root: &Path,
    create: bool,
) -> Option<OpenedMonitorVerdictDir> {
    // Reject a symlinked or non-directory cache root before mutating permissions
    // so pathname-based `chmod` can never follow a link to an unrelated target.
    match std::fs::symlink_metadata(cache_root) {
        Ok(root_meta) => {
            if !root_meta.is_dir() || lpm_common::is_symlink_or_junction(&root_meta) {
                return None;
            }
        }
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(cache_root).ok()?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(cache_root).ok()?;
            }
        }
        Err(_) => return None,
    }

    #[cfg(unix)]
    let (root_dir, root_was_writable) = {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let euid = unsafe { libc::geteuid() };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(cache_root)
            .ok()?;
        let opened_meta = file.metadata().ok()?;
        if !opened_meta.is_dir() || opened_meta.uid() != euid {
            return None;
        }
        let mode = opened_meta.permissions().mode() & 0o777;
        let was_writable = (mode & 0o022) != 0;
        if create {
            if mode != 0o700 {
                // SAFETY: `file` is a valid open directory descriptor pinned without following symlinks.
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
                    return None;
                }
            }
        } else if was_writable {
            return None;
        }
        (cap_std::fs::Dir::from_std_file(file), was_writable)
    };
    #[cfg(not(unix))]
    let (root_dir, root_was_writable) = {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
                FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
                FILE_TRAVERSE,
            };

            let file = std::fs::OpenOptions::new()
                .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(cache_root)
                .ok()?;
            let opened_meta = file.metadata().ok()?;
            if !opened_meta.is_dir() || lpm_common::is_symlink_or_junction(&opened_meta) {
                return None;
            }
            (cap_std::fs::Dir::from_std_file(file), false)
        }
        #[cfg(not(windows))]
        {
            let root_meta = std::fs::symlink_metadata(cache_root).ok()?;
            if !root_meta.is_dir() || lpm_common::is_symlink_or_junction(&root_meta) {
                return None;
            }
            (
                cap_std::fs::Dir::open_ambient_dir(cache_root, cap_std::ambient_authority())
                    .ok()?,
                false,
            )
        }
    };

    #[cfg(unix)]
    let (sub_dir, sub_was_writable) = {
        use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let euid = unsafe { libc::geteuid() };
        let root_fd = root_dir.as_fd().as_raw_fd();
        let subdir_cstr = std::ffi::CString::new(MONITOR_VERDICT_SUBDIR).ok()?;
        if create {
            // SAFETY: `root_fd` is a valid open directory descriptor and `subdir_cstr` is NUL-terminated.
            let rc = unsafe { libc::mkdirat(root_fd, subdir_cstr.as_ptr(), 0o700) };
            if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return None;
            }
        }
        // Open with `O_RDONLY` rather than `cap_std`'s Linux `O_PATH` so `fchmod`
        // succeeds on the pinned descriptor even when the process umask widens mode bits.
        // SAFETY: `root_fd` is a valid open directory descriptor and `subdir_cstr` is NUL-terminated.
        let sub_fd = unsafe {
            libc::openat(
                root_fd,
                subdir_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if sub_fd < 0 {
            return None;
        }
        // SAFETY: `sub_fd` was just returned by `openat` and is exclusively owned here.
        let sub_file = unsafe { std::fs::File::from_raw_fd(sub_fd) };
        let sub_meta = sub_file.metadata().ok()?;
        if !sub_meta.is_dir() || sub_meta.uid() != euid {
            return None;
        }
        let sub_mode = sub_meta.permissions().mode() & 0o777;
        let was_writable = (sub_mode & 0o022) != 0;
        if create {
            if sub_mode != 0o700 {
                // SAFETY: `sub_file` is a real `O_RDONLY` directory descriptor opened with `O_NOFOLLOW`.
                if unsafe { libc::fchmod(sub_file.as_raw_fd(), 0o700) } != 0 {
                    return None;
                }
            }
        } else if was_writable {
            return None;
        }
        (cap_std::fs::Dir::from_std_file(sub_file), was_writable)
    };
    #[cfg(not(unix))]
    let (sub_dir, sub_was_writable) = {
        use cap_fs_ext::DirExt as _;

        if create {
            match root_dir.create_dir(MONITOR_VERDICT_SUBDIR) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
        }
        let sub_dir = root_dir.open_dir_nofollow(MONITOR_VERDICT_SUBDIR).ok()?;
        let sub_meta = sub_dir.dir_metadata().ok()?;
        if !sub_meta.is_dir() {
            return None;
        }
        (sub_dir, false)
    };
    Some(OpenedMonitorVerdictDir {
        dir: sub_dir,
        was_previously_untrusted: root_was_writable || sub_was_writable,
    })
}

fn read_monitor_verdict_cache_from_dir(
    dir: &cap_std::fs::Dir,
    filename: &str,
    now_secs: u64,
) -> HashMap<String, MonitorVerdictCacheEntry> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
    use std::io::Read as _;

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let Ok(file) = dir.open_with(filename, &options) else {
        return HashMap::new();
    };
    let Ok(metadata) = file.metadata() else {
        return HashMap::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_MONITOR_VERDICT_CACHE_FILE_BYTES {
        return HashMap::new();
    }
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        let euid = unsafe { libc::geteuid() };
        if !is_trusted_verdict_file_unix(metadata.uid(), euid, metadata.permissions().mode()) {
            return HashMap::new();
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = file
        .into_std()
        .take(MAX_MONITOR_VERDICT_CACHE_FILE_BYTES.saturating_add(1));
    if limited.read_to_end(&mut bytes).is_err()
        || bytes.len() as u64 > MAX_MONITOR_VERDICT_CACHE_FILE_BYTES
    {
        return HashMap::new();
    }
    let Ok(mut parsed) = serde_json::from_slice::<MonitorVerdictCacheFile>(&bytes) else {
        return HashMap::new();
    };
    if parsed.version != MONITOR_VERDICT_CACHE_VERSION {
        return HashMap::new();
    }
    parsed
        .entries
        .retain(|_, entry| is_valid_monitor_verdict_expiry(entry.expires_at, now_secs));
    parsed.entries
}

fn read_monitor_verdict_cache(
    target: &MonitorVerdictCacheTarget,
    now_secs: u64,
) -> HashMap<String, MonitorVerdictCacheEntry> {
    let Some(opened) = open_monitor_verdict_cache_dir_nofollow(&target.cache_root, false) else {
        return HashMap::new();
    };
    read_monitor_verdict_cache_from_dir(&opened.dir, &target.filename, now_secs)
}

fn effective_monitor_verdict_ttl_secs(directive: NpmFirewallCacheDirective) -> Option<u64> {
    match directive {
        NpmFirewallCacheDirective::NoStore => None,
        NpmFirewallCacheDirective::Store { max_age_secs: 0 } => None,
        NpmFirewallCacheDirective::Store { max_age_secs } => {
            Some(max_age_secs.min(DEFAULT_MONITOR_VERDICT_CACHE_TTL_SECS))
        }
        NpmFirewallCacheDirective::Unspecified => Some(DEFAULT_MONITOR_VERDICT_CACHE_TTL_SECS),
    }
}

fn sweep_expired_monitor_verdict_files(dir: &cap_std::fs::Dir, active_filename: &str) {
    let Ok(entries) = dir.entries() else {
        return;
    };
    let max_age = std::time::Duration::from_secs(DEFAULT_MONITOR_VERDICT_CACHE_TTL_SECS);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == active_filename || !name_str.ends_with(".json") {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
            && let Ok(modified) = meta.modified()
            && let Ok(elapsed) = modified.into_std().elapsed()
            && elapsed > max_age
        {
            let _ = dir.remove_file(name_str);
        }
    }
}

fn serialize_bounded_monitor_verdict_cache(
    mut entries: HashMap<String, MonitorVerdictCacheEntry>,
    now_secs: u64,
) -> Option<Vec<u8>> {
    entries.retain(|_, entry| is_valid_monitor_verdict_expiry(entry.expires_at, now_secs));
    let mut by_expiry: Vec<(u64, String, MonitorVerdictCacheEntry)> = entries
        .into_iter()
        .map(|(key, entry)| (entry.expires_at, key, entry))
        .collect();
    if by_expiry.len() > MAX_MONITOR_VERDICT_CACHE_ENTRIES {
        by_expiry.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));
        by_expiry.truncate(MAX_MONITOR_VERDICT_CACHE_ENTRIES);
    }
    loop {
        let map: HashMap<String, MonitorVerdictCacheEntry> = by_expiry
            .iter()
            .map(|(_, key, entry)| (key.clone(), *entry))
            .collect();
        let payload = MonitorVerdictCacheFile {
            version: MONITOR_VERDICT_CACHE_VERSION,
            entries: map,
        };
        let bytes = serde_json::to_vec(&payload).ok()?;
        if bytes.len() as u64 <= MAX_MONITOR_VERDICT_CACHE_FILE_BYTES {
            return Some(bytes);
        }
        if by_expiry.len() <= 1 {
            return None;
        }
        by_expiry.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));
        by_expiry.truncate(by_expiry.len() / 2);
    }
}

fn update_monitor_verdict_cache(
    target: &MonitorVerdictCacheTarget,
    additions: Vec<(String, MonitorVerdictCacheEntry)>,
    removals: Vec<String>,
    now_secs: u64,
) {
    use std::io::Write as _;

    if additions.is_empty() && removals.is_empty() {
        return;
    }
    let create = !additions.is_empty();
    let Some(opened) = open_monitor_verdict_cache_dir_nofollow(&target.cache_root, create) else {
        return;
    };
    let dir = opened.dir;
    // If the directory failed the trust check before being healed to 0700, discard
    // any pre-existing file instead of laundering potentially planted entries.
    let mut entries = if opened.was_previously_untrusted {
        HashMap::new()
    } else {
        read_monitor_verdict_cache_from_dir(&dir, &target.filename, now_secs)
    };
    let mut changed = opened.was_previously_untrusted;
    for key in removals {
        if entries.remove(&key).is_some() {
            changed = true;
        }
    }
    for (key, entry) in additions {
        if is_valid_monitor_verdict_expiry(entry.expires_at, now_secs) {
            entries.insert(key, entry);
            changed = true;
        }
    }
    if !changed {
        return;
    }
    if entries.is_empty() && opened.was_previously_untrusted {
        let _ = dir.remove_file(&target.filename);
        return;
    }
    let Some(bytes) = serialize_bounded_monitor_verdict_cache(entries, now_secs) else {
        return;
    };
    let options = lpm_common::atomic_write::AtomicWriteOptions::new().owner_only();
    if let Err(error) = lpm_common::atomic_write::write_file_atomic_in_dir_with_options(
        &dir,
        std::ffi::OsStr::new(&target.filename),
        options,
        |file| file.write_all(&bytes),
    ) {
        tracing::debug!(%error, "failed to persist firewall monitor verdict cache");
        return;
    }
    sweep_expired_monitor_verdict_files(&dir, &target.filename);
}

fn collect_monitor_cache_updates(
    uncached: &[NpmFirewallBatchPackage],
    response: &NpmFirewallBatchResponse,
    lookup_mode: NpmFirewallLookupMode,
    now_secs: u64,
    allow_insertions: bool,
    additions: &mut Vec<(String, MonitorVerdictCacheEntry)>,
    removals: &mut Vec<String>,
) {
    let non_allow: HashSet<(&str, &str)> = response
        .decisions
        .iter()
        .filter(|decision| decision.action != NpmFirewallAction::Allow)
        .map(|decision| (decision.name.as_str(), decision.version.as_str()))
        .collect();
    for package in uncached {
        if non_allow.contains(&(package.name.as_str(), package.version.as_str())) {
            removals.push(monitor_verdict_entry_key(package, lookup_mode));
        }
    }
    if !allow_insertions {
        return;
    }
    let Some(ttl_secs) = effective_monitor_verdict_ttl_secs(response.cache_directive) else {
        return;
    };
    let flagged_summary = response.summary.warn.saturating_add(response.summary.block);
    if response.summary.allow == 0
        || response.summary.total != uncached.len() as u64
        || response.summary.allow.saturating_add(flagged_summary) != response.summary.total
    {
        return;
    }
    // Fail closed unless every reported warn/block decision matches an exact
    // requested package and accounts for the full flagged summary count.
    let matched_non_allow_packages: Vec<&NpmFirewallBatchPackage> = uncached
        .iter()
        .filter(|pkg| non_allow.contains(&(pkg.name.as_str(), pkg.version.as_str())))
        .collect();
    let matched_non_allow_coords: HashSet<(&str, &str)> = matched_non_allow_packages
        .iter()
        .map(|pkg| (pkg.name.as_str(), pkg.version.as_str()))
        .collect();
    if matched_non_allow_packages.len() as u64 != flagged_summary
        || matched_non_allow_coords.len() != non_allow.len()
    {
        return;
    }

    // Only cache unambiguous batches where every Allow verdict has an exact
    // `(unknown, matched)` classification so warm hits preserve JSON counts.
    let (allow_unknown, allow_matched) = if response.summary.unknown == response.summary.allow
        && response.summary.matched == flagged_summary
    {
        (true, false)
    } else if response.summary.unknown == 0 && response.summary.matched == response.summary.total {
        (false, true)
    } else if response.summary.unknown == 0 && response.summary.matched == flagged_summary {
        (false, false)
    } else {
        return;
    };

    let expires_at = now_secs.saturating_add(ttl_secs);
    for package in uncached {
        if non_allow.contains(&(package.name.as_str(), package.version.as_str())) {
            continue;
        }
        additions.push((
            monitor_verdict_entry_key(package, lookup_mode),
            MonitorVerdictCacheEntry {
                expires_at,
                unknown: allow_unknown,
                matched: allow_matched,
            },
        ));
    }
}

#[cfg(test)]
pub(super) async fn request_npm_firewall_preflight(
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    policy_profile: NpmFirewallPolicyProfile,
    client: Arc<RegistryClient>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
    offline: bool,
) -> Result<NpmFirewallPreflightResult, LpmError> {
    request_npm_firewall_preflight_with_force(
        mode,
        lookup_mode,
        policy_profile,
        client,
        verdict_packages,
        offline,
        false,
    )
    .await
}

#[cfg(test)]
pub(super) async fn request_npm_firewall_preflight_with_force(
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    policy_profile: NpmFirewallPolicyProfile,
    client: Arc<RegistryClient>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
    offline: bool,
    force: bool,
) -> Result<NpmFirewallPreflightResult, LpmError> {
    request_npm_firewall_preflight_with_bypass(
        PreflightSettings {
            mode,
            lookup_mode,
            policy_profile,
            offline,
            force,
            bypass: FirewallBypassRules::none(),
        },
        client,
        verdict_packages,
    )
    .await
}

/// How one verdict preflight runs.
pub(super) struct PreflightSettings {
    pub(super) mode: NpmFirewallMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) policy_profile: NpmFirewallPolicyProfile,
    pub(super) offline: bool,
    pub(super) force: bool,
    pub(super) bypass: FirewallBypassRules,
}

pub(super) async fn request_npm_firewall_preflight_with_bypass(
    settings: PreflightSettings,
    client: Arc<RegistryClient>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
) -> Result<NpmFirewallPreflightResult, LpmError> {
    let PreflightSettings {
        mode,
        lookup_mode,
        policy_profile,
        offline,
        force,
        bypass,
    } = settings;
    let mut stats = NpmFirewallPreflightStats::for_mode(mode, lookup_mode);
    stats.note_bypass_rules(&bypass);
    if !mode.is_enabled() {
        return Ok(NpmFirewallPreflightResult::empty(mode, lookup_mode));
    }

    stats.checked_count = verdict_packages.len() as u64;
    if verdict_packages.is_empty() {
        return Ok(NpmFirewallPreflightResult {
            failure: None,
            stats,
            decisions: Vec::new(),
            report_error: None,
        });
    }

    if offline {
        stats.offline_skipped = true;
        let message = NPM_FIREWALL_OFFLINE_HINT.to_string();
        if matches!(mode, NpmFirewallMode::Monitor) {
            return Ok(NpmFirewallPreflightResult {
                failure: None,
                stats,
                decisions: Vec::new(),
                report_error: Some(format!(
                    "{message}; continuing because monitor mode is active"
                )),
            });
        }
        return Err(LpmError::Registry(message));
    }

    let client = NpmFirewallPreflightClient::new(client);
    let started = Instant::now();
    let (effective_client, ephemeral_oidc) = match client.for_mode(mode).await {
        Ok(resolved) => resolved,
        Err(error) if matches!(mode, NpmFirewallMode::Monitor) => {
            stats.batch_ms = started.elapsed().as_millis();
            stats.rpc_failed = true;
            return Ok(NpmFirewallPreflightResult {
                failure: None,
                stats,
                decisions: Vec::new(),
                report_error: Some(npm_firewall_preflight_report_error(error)),
            });
        }
        Err(error) => {
            return Err(npm_firewall_preflight_enforce_error(error));
        }
    };
    let cache_feature_on = !ephemeral_oidc && monitor_verdict_cache_enabled(mode, false, offline);
    let use_cache_read = !ephemeral_oidc && monitor_verdict_cache_enabled(mode, force, offline);
    let now_secs = if cache_feature_on {
        current_unix_secs()
    } else {
        0
    };
    let packages_to_check: Vec<NpmFirewallBatchPackage> = if use_cache_read {
        let read_target =
            monitor_verdict_cache_target(&effective_client, mode, lookup_mode, policy_profile)
                .ok()
                .flatten();
        if let Some(target) = read_target {
            let entries =
                tokio::task::spawn_blocking(move || read_monitor_verdict_cache(&target, now_secs))
                    .await
                    .unwrap_or_default();
            let mut uncached = Vec::new();
            let mut hits = 0u64;
            let mut unknown_hits = 0u64;
            let mut matched_hits = 0u64;
            for package in verdict_packages {
                let key = monitor_verdict_entry_key(&package, lookup_mode);
                if let Some(entry) = entries
                    .get(&key)
                    .filter(|entry| is_valid_monitor_verdict_expiry(entry.expires_at, now_secs))
                {
                    hits = hits.saturating_add(1);
                    if entry.unknown {
                        unknown_hits = unknown_hits.saturating_add(1);
                    }
                    if entry.matched {
                        matched_hits = matched_hits.saturating_add(1);
                    }
                } else {
                    uncached.push(package);
                }
            }
            stats.cache_hit_count = hits;
            stats.allow_count = stats.allow_count.saturating_add(hits);
            stats.unknown_count = stats.unknown_count.saturating_add(unknown_hits);
            stats.matched_count = stats.matched_count.saturating_add(matched_hits);
            uncached
        } else {
            verdict_packages
        }
    } else {
        verdict_packages
    };

    if packages_to_check.is_empty() {
        stats.batch_ms = started.elapsed().as_millis();
        return Ok(NpmFirewallPreflightResult {
            failure: None,
            stats,
            decisions: Vec::new(),
            report_error: None,
        });
    }

    let mut all_decisions = Vec::new();
    let mut cache_additions = Vec::new();
    let mut cache_removals = Vec::new();
    let mut total_checked_live = 0u64;
    let mut total_matched_live = 0u64;
    let mut total_warn_live = 0u64;
    let mut total_block_live = 0u64;
    let mut last_request_id = String::new();
    let mut last_policy_mode = String::new();
    // In enforce mode a failed batch doesn't stop the others: a block they
    // find is what the install reports, with this failure as unchecked.
    let mut first_failure = None;

    for chunk in packages_to_check.chunks(MAX_FIREWALL_BATCH_PACKAGES) {
        let chunk_started = Instant::now();
        let response = match effective_client
            .npm_firewall_batch_verdicts_with_posture_and_policy(
                chunk,
                mode.auth_posture(),
                Some(policy_profile),
            )
            .await
        {
            Ok(response) => response,
            Err(error) if matches!(mode, NpmFirewallMode::Monitor) => {
                stats.batch_ms = started.elapsed().as_millis();
                stats.rpc_failed = true;
                return Ok(NpmFirewallPreflightResult {
                    failure: None,
                    stats,
                    decisions: all_decisions,
                    report_error: Some(npm_firewall_preflight_report_error(error)),
                });
            }
            Err(error) => {
                first_failure.get_or_insert(error);
                continue;
            }
        };
        let chunk_ms = chunk_started.elapsed().as_millis();
        stats.record_response(&response, chunk_ms);
        total_checked_live = total_checked_live.saturating_add(response.summary.total);
        total_matched_live = total_matched_live.saturating_add(response.summary.matched);
        total_warn_live = total_warn_live.saturating_add(response.summary.warn);
        total_block_live = total_block_live.saturating_add(response.summary.block);
        last_request_id = response.request_id.clone();
        last_policy_mode = response.policy_mode.clone();

        if cache_feature_on {
            collect_monitor_cache_updates(
                chunk,
                &response,
                lookup_mode,
                now_secs,
                use_cache_read,
                &mut cache_additions,
                &mut cache_removals,
            );
        }
        let classified = classify_verdicts(response, chunk, &bypass).await;
        all_decisions.extend(stats.record_classified(classified));
    }
    if let Some(error) = first_failure.map(npm_firewall_preflight_enforce_error) {
        if !stats_have_block(&stats, &all_decisions) {
            // Nothing downloads until every batch settles, so a failed one
            // lets nothing through.
            stats.bypassed.clear();
            stats.batch_ms = started.elapsed().as_millis();
            return Ok(NpmFirewallPreflightResult {
                stats,
                decisions: all_decisions,
                report_error: None,
                failure: Some(error),
            });
        }
        stats.unchecked_reason = Some(error.to_string());
    }
    stats.batch_ms = started.elapsed().as_millis();

    // Compute the write target AFTER the live RPC succeeds so a refresh-only
    // session stores verdicts under the refreshed account's real bearer.
    if cache_feature_on
        && (!cache_additions.is_empty() || !cache_removals.is_empty())
        && let Ok(Some(write_target)) =
            monitor_verdict_cache_target(&effective_client, mode, lookup_mode, policy_profile)
    {
        let write_now = current_unix_secs();
        let _ = tokio::task::spawn_blocking(move || {
            update_monitor_verdict_cache(&write_target, cache_additions, cache_removals, write_now);
        })
        .await;
    }

    tracing::debug!(
        target = "lpm::firewall",
        package_count = total_checked_live,
        matched = total_matched_live,
        warn = total_warn_live,
        block = total_block_live,
        cache_hits = stats.cache_hit_count,
        elapsed_ms = stats.batch_ms,
        request_id = %last_request_id,
        policy_mode = %last_policy_mode,
        "npm firewall verdict preflight completed",
    );
    Ok(NpmFirewallPreflightResult {
        failure: None,
        stats,
        decisions: all_decisions,
        report_error: None,
    })
}

/// A firewall verdict that is either settled or still being requested in the
/// background, as it is in monitor mode.
pub(super) enum NpmFirewallOutcome {
    Settled(Box<NpmFirewallPreflightStats>),
    Pending(NpmFirewallPreflightJoin),
}

impl NpmFirewallOutcome {
    pub(super) async fn settle(
        self,
        json_output: bool,
    ) -> Result<NpmFirewallPreflightStats, LpmError> {
        match self {
            Self::Settled(stats) => Ok(*stats),
            Self::Pending(join) => finish_npm_firewall_preflight(join.drain().await?, json_output),
        }
    }
}

/// Requests verdicts for `request.packages` on a background task.
pub(super) fn spawn_npm_firewall_preflight(
    request: NpmFirewallPreflightRequest<'_>,
) -> NpmFirewallPreflightJoin {
    let NpmFirewallPreflightRequest {
        mode,
        lookup_mode,
        policy_profile,
        bypass,
        client,
        route_table,
        packages,
        offline,
        force,
        json_output: _,
        firewall_bypass_report: _,
        released_bypasses: _,
    } = request;
    let verdict_packages =
        npm_firewall_packages(packages, route_table, client.as_ref(), lookup_mode);
    let client = Arc::clone(client);
    NpmFirewallPreflightJoin {
        handle: Some(tokio::spawn(request_npm_firewall_preflight_with_bypass(
            PreflightSettings {
                mode,
                lookup_mode,
                policy_profile,
                offline,
                force,
                bypass: bypass.clone(),
            },
            client,
            verdict_packages,
        ))),
    }
}

/// Settles `result` for an install whose command keeps `report`. A request
/// failure ends the install as an error, so what a rule let through before it
/// is handed to the report first.
pub(super) fn finish_npm_firewall_preflight_into(
    result: NpmFirewallPreflightResult,
    json_output: bool,
    report: Option<&super::FirewallBypassReport>,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    if result.failure.is_some()
        && let Some(report) = report
    {
        report.record(&result.stats);
    }
    finish_npm_firewall_preflight(result, json_output)
}

pub(super) fn finish_npm_firewall_preflight(
    result: NpmFirewallPreflightResult,
    json_output: bool,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let stats = report_npm_firewall_preflight(result, json_output)?;
    super::PROCESS_FIREWALL_BYPASSES.record(&stats);
    Ok(stats)
}

fn report_npm_firewall_preflight(
    result: NpmFirewallPreflightResult,
    json_output: bool,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let mut stats = result.stats;
    let mut seen_bypassed = HashSet::with_capacity(stats.bypassed.len());
    stats.bypassed.retain(|bypassed| {
        seen_bypassed.insert((
            bypassed.decision.name.clone(),
            bypassed.decision.version.clone(),
        ))
    });
    if let Some(failure) = result.failure {
        // Only versions released to download before the failure remain.
        if !json_output {
            print_bypassed_verdicts(&stats.bypassed, false);
        }
        super::PROCESS_FIREWALL_BYPASSES.record(&stats);
        return Err(failure);
    }
    // A failed request in monitor mode still leaves what the requests before
    // it found, which is reported below.
    if let Some(error) = &result.report_error
        && !json_output
    {
        output::warn(&lpm_common::sanitize_terminal_inline(error));
    }

    let blocked = distinct_decisions(&result.decisions, NpmFirewallAction::Block);
    let warned = distinct_decisions(&result.decisions, NpmFirewallAction::Warn);
    let blocked_count = blocked
        .len()
        .saturating_add(usize::try_from(stats.unattributed_block_count).unwrap_or(usize::MAX));
    let warned_count = warned.len().max(stats.warn_count as usize);

    if matches!(stats.mode, NpmFirewallMode::Monitor) {
        if !json_output && (blocked_count > 0 || warned_count > 0 || !stats.bypassed.is_empty()) {
            output::warn(&format!(
                "LPM Firewall monitor: {} would-block, {} warned; command continues because monitor mode is active.",
                blocked_count, warned_count
            ));
            print_firewall_decisions(&blocked);
            print_firewall_decisions(&warned);
            print_bypassed_verdicts(&stats.bypassed, true);
        }
        return Ok(stats);
    }

    if !json_output {
        print_bypassed_verdicts(&stats.bypassed, false);
    }

    if warned_count > 0 && !json_output {
        output::warn(&format!(
            "LPM Firewall warned for {} {}:",
            warned_count,
            install_ui::packages_word(warned_count),
        ));
        print_firewall_decisions(&warned);
    }

    if blocked_count == 0 {
        return Ok(stats);
    }

    if !json_output {
        output::warn(&format!(
            "LPM Firewall blocked {} {}:",
            blocked_count,
            install_ui::packages_word(blocked_count),
        ));
        print_firewall_decisions(&blocked);
    }
    let additions_usable = stats.bypass_additions_allowed && stats.bypass_error.is_none();
    let packages: Vec<_> = blocked
        .iter()
        .map(|decision| blocked_package(decision, additions_usable))
        .collect();
    // The command is offered only when running it lets the command finish:
    // every block is named and liftable by an exact rule, every version was
    // checked, and a shell reads every coordinate unchanged.
    let bypass_command = (!packages.is_empty()
        && packages.iter().all(|package| {
            package.bypassable && crate::firewall_bypass::spec_shell_safe(&package.coordinate())
        })
        && stats.unattributed_block_count == 0
        && stats.unchecked_reason.is_none())
    .then(|| {
        let coordinates: Vec<String> = packages
            .iter()
            .map(lpm_common::NpmFirewallBlockedPackage::coordinate)
            .collect();
        bypass_add_command(coordinates.iter().map(String::as_str))
    });
    let has_malware = packages
        .iter()
        .any(|package| package.block_class.as_deref() == Some(BlockClass::Malware.as_str()));
    // A hold for LPM review lifts for no rule, so no note points at rules.
    let some_rule_could_lift = packages
        .iter()
        .any(|package| package.block_class.as_deref() != Some(BlockClass::ServerReview.as_str()));
    let bypass_unavailable_reason = stats
        .bypass_error
        .as_ref()
        .filter(|_| some_rule_could_lift)
        .map(|error| {
            // The store's error already names its remedy: repair, or update
            // LPM CLI for a newer file.
            format!("your bypass rules couldn't be read: {error}")
        })
        .or_else(|| {
            (some_rule_could_lift && !stats.local_bypass_available).then(|| {
                format!(
                    "{} manages the npm firewall here; ask its administrator to list the version in its `[firewall].{}`",
                    stats
                        .managed_policy_path
                        .as_deref()
                        .unwrap_or("a managed security policy"),
                    if has_malware { "bypass-malware" } else { "bypass" },
                )
            })
        })
        .or_else(|| {
            (some_rule_could_lift && !stats.bypass_additions_allowed).then(|| {
                "`force-security-floor = true` keeps the npm firewall at enforce, so `lpm firewall bypass add` refuses new rules".to_string()
            })
        });
    Err(LpmError::NpmFirewallBlocked(Box::new(
        lpm_common::NpmFirewallBlockedErrorContext {
            source: lpm_common::NpmFirewallBlockSource::Preflight,
            packages,
            unattributed_count: stats.unattributed_block_count,
            unchecked_reason: stats.unchecked_reason,
            bypassed: stats
                .bypassed
                .iter()
                .map(|bypassed| lpm_common::NpmFirewallBypassedPackage {
                    name: bypassed.decision.name.clone(),
                    version: bypassed.decision.version.clone(),
                    rule: bypassed.rule.spec.clone(),
                })
                .collect(),
            bypass_command,
            bypass_unavailable_reason,
        },
    )))
}

/// Whether the verdicts gathered so far already block the command.
fn stats_have_block(stats: &NpmFirewallPreflightStats, decisions: &[NpmFirewallDecision]) -> bool {
    stats.unattributed_block_count > 0
        || decisions
            .iter()
            .any(|decision| decision.action == NpmFirewallAction::Block)
}

/// The decisions with `action`, once per package version: peer-context
/// instances of one version can each come back from a separate chunk. A
/// version blocked more than once, say once per integrity, keeps the block
/// that is hardest to lift, so the report and its hint answer for every one.
fn distinct_decisions(
    decisions: &[NpmFirewallDecision],
    action: NpmFirewallAction,
) -> Vec<&NpmFirewallDecision> {
    let mut position: HashMap<(&str, &str), usize> = HashMap::with_capacity(decisions.len());
    let mut distinct: Vec<&NpmFirewallDecision> = Vec::with_capacity(decisions.len());
    for decision in decisions
        .iter()
        .filter(|decision| decision.action == action)
    {
        match position.entry((decision.name.as_str(), decision.version.as_str())) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(distinct.len());
                distinct.push(decision);
            }
            std::collections::hash_map::Entry::Occupied(slot) => {
                let kept = &mut distinct[*slot.get()];
                if action == NpmFirewallAction::Block
                    && decision_block_class(decision).lift_difficulty()
                        > decision_block_class(kept).lift_difficulty()
                {
                    *kept = decision;
                }
            }
        }
    }
    distinct
}

fn blocked_package(
    decision: &NpmFirewallDecision,
    additions_usable: bool,
) -> lpm_common::NpmFirewallBlockedPackage {
    let display = decision.display.as_ref();
    let class = decision_block_class(decision);
    lpm_common::NpmFirewallBlockedPackage {
        name: decision.name.clone(),
        version: Some(decision.version.clone()),
        verdict: decision.verdict.clone(),
        reason: decision.reason.clone(),
        decision_id: Some(decision.decision_id.clone()),
        match_source: Some(decision.match_source.clone()),
        policy_group: decision.policy.as_ref().map(|policy| policy.group.clone()),
        summary: display
            .and_then(|display| non_empty_display_text(display.summary.as_deref()))
            .map(str::to_string),
        report_url: display
            .and_then(|display| non_empty_display_text(display.report_url.as_deref()))
            .map(str::to_string),
        block_class: Some(class.as_str().to_string()),
        bypassable: additions_usable
            && crate::firewall_bypass::FirewallBypassSpec::parse(&format!(
                "{}@{}",
                decision.name, decision.version
            ))
            .is_ok_and(|spec| spec.kind() == crate::firewall_bypass::BypassKind::Exact)
            && class.coverable_by(crate::firewall_bypass::BypassKind::Exact, false),
    }
}

/// Prints the blocked versions bypass rules let through, each with its rule.
pub(super) fn print_bypassed_verdicts(bypassed: &[BypassedVerdict], monitor: bool) {
    if bypassed.is_empty() {
        return;
    }
    super::FIREWALL_BYPASS_NOTICES.show(bypassed, |bypassed| {
        write_bypassed_verdicts(bypassed, monitor);
    });
}

/// Writes the notice [`print_bypassed_verdicts`] prints.
pub(super) fn write_bypassed_verdicts(bypassed: &[BypassedVerdict], monitor: bool) {
    if bypassed.is_empty() {
        return;
    }
    let count = bypassed.len();
    output::warn(&if monitor {
        format!(
            "LPM Firewall monitor: your bypass rules would allow {count} blocked {}:",
            install_ui::packages_word(count)
        )
    } else {
        format!(
            "LPM Firewall allowed {count} blocked {} because of your bypass rules:",
            install_ui::packages_word(count)
        )
    });
    for verdict in bypassed {
        for line in firewall_decision_lines(&verdict.decision) {
            install_ui::detail_line(line);
        }
        install_ui::detail_line(install_ui::terminal_line!(
            "    {} {} {}",
            install_ui::dim("rule:"),
            install_ui::field(&verdict.rule.spec),
            install_ui::dim(&format!("({})", verdict.rule.scope_text())),
        ));
    }
}

pub(super) async fn run_npm_firewall_preflight(
    request: NpmFirewallPreflightRequest<'_>,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let NpmFirewallPreflightRequest {
        mode,
        lookup_mode,
        policy_profile,
        bypass,
        client,
        route_table,
        packages,
        offline,
        force,
        json_output,
        firewall_bypass_report,
        released_bypasses,
    } = request;
    let verdict_packages =
        npm_firewall_packages(packages, route_table, client.as_ref(), lookup_mode);
    let result = request_npm_firewall_preflight_with_bypass(
        PreflightSettings {
            mode,
            lookup_mode,
            policy_profile,
            offline,
            force,
            bypass: bypass.clone(),
        },
        Arc::clone(client),
        verdict_packages,
    )
    .await?;
    if let Some(released) = released_bypasses
        && npm_firewall_preflight_lets_through(&result)
    {
        super::settle_released_firewall_bypasses(released, &result.stats)?;
    }
    finish_npm_firewall_preflight_into(result, json_output, firewall_bypass_report)
}

pub(super) struct NpmFirewallPreflightRequest<'a> {
    pub(super) mode: NpmFirewallMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) policy_profile: NpmFirewallPolicyProfile,
    pub(super) bypass: &'a FirewallBypassRules,
    pub(super) client: &'a Arc<RegistryClient>,
    pub(super) route_table: &'a RouteTable,
    pub(super) packages: &'a [InstallPackage],
    pub(super) offline: bool,
    pub(super) force: bool,
    pub(super) json_output: bool,
    /// Where the command keeps what bypass rules let through.
    pub(super) firewall_bypass_report: Option<&'a super::FirewallBypassReport>,
    /// The install's record of what it let through, settled before the check
    /// reports a clean result, so an exiting command stops the install first.
    pub(super) released_bypasses: Option<&'a super::ReleasedFirewallBypasses>,
}

/// Whether `result` lets the install go on to download: no request failed and
/// nothing is blocked, or monitor mode, which blocks nothing.
pub(super) fn npm_firewall_preflight_lets_through(result: &NpmFirewallPreflightResult) -> bool {
    matches!(result.stats.mode, NpmFirewallMode::Monitor)
        || (result.failure.is_none() && !stats_have_block(&result.stats, &result.decisions))
}

pub(super) fn npm_firewall_packages(
    packages: &[InstallPackage],
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) -> Vec<NpmFirewallBatchPackage> {
    let mut verdict_packages = Vec::with_capacity(packages.len());
    let mut requested = HashSet::with_capacity(packages.len());
    for package in packages {
        let key = (
            package.name.as_str(),
            package.version.as_str(),
            lookup_mode
                .include_integrity()
                .then_some(package.integrity.as_deref())
                .flatten(),
        );
        if requested.contains(&key) {
            continue;
        }
        if let Some(verdict_package) =
            npm_firewall_package(package, route_table, client, lookup_mode)
        {
            requested.insert(key);
            verdict_packages.push(verdict_package);
        }
    }
    verdict_packages
}

/// Peer-context instances of one package share a coordinate, and one verdict
/// answers for all of them.
fn same_verdict_request(left: &NpmFirewallBatchPackage, right: &NpmFirewallBatchPackage) -> bool {
    left.name == right.name && left.version == right.version && left.integrity == right.integrity
}

pub(super) fn npm_firewall_has_packages(
    packages: &[InstallPackage],
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) -> bool {
    packages
        .iter()
        .any(|package| npm_firewall_package(package, route_table, client, lookup_mode).is_some())
}

pub(super) fn npm_firewall_package_from_selected_event(
    event: &lpm_resolver::SelectedPackageEvent,
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) -> Option<NpmFirewallBatchPackage> {
    if event.is_lpm {
        return None;
    }
    if event
        .platform
        .as_ref()
        .is_some_and(|platform| !lpm_resolver::is_platform_compatible(platform))
    {
        return None;
    }
    if !route_is_public_npm(route_table, client, &event.name) {
        return None;
    }
    Some(NpmFirewallBatchPackage {
        name: event.name.clone(),
        version: event.version.clone(),
        integrity: lookup_mode
            .include_integrity()
            .then(|| event.integrity.clone())
            .flatten(),
        published_at: None,
    })
}

pub(super) fn npm_firewall_package(
    package: &InstallPackage,
    _route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) -> Option<NpmFirewallBatchPackage> {
    if package.is_lpm || lpm_common::package_name::is_lpm_package(&package.name) {
        return None;
    }
    if !package_platform_compatible(package) {
        return None;
    }
    let Ok(lpm_lockfile::Source::Registry { url }) = package.source_kind() else {
        return None;
    };
    if !crate::npm_public_source::is_public_npm_origin(&url)
        && !crate::npm_public_source::is_lpm_registry_origin(&url, client)
    {
        return None;
    }
    Some(NpmFirewallBatchPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        integrity: lookup_mode
            .include_integrity()
            .then(|| package.integrity.clone())
            .flatten(),
        published_at: package.registry_published_at.clone(),
    })
}

fn route_is_public_npm(route_table: &RouteTable, client: &RegistryClient, name: &str) -> bool {
    if lpm_common::package_name::is_lpm_package(name) {
        return false;
    }
    match route_table.route_for_package(name) {
        UpstreamRoute::NpmDirect | UpstreamRoute::LpmWorker => true,
        UpstreamRoute::Custom { target, .. } => {
            crate::npm_public_source::is_public_npm_origin(&target.base_url)
                || crate::npm_public_source::is_lpm_registry_origin(&target.base_url, client)
        }
    }
}

pub(crate) fn registry_materialization_route_is_public_npm(
    route_table: &RouteTable,
    client: &RegistryClient,
    name: &str,
) -> bool {
    if lpm_common::package_name::is_lpm_package(name) {
        return false;
    }
    match route_table.route_for_package(name) {
        UpstreamRoute::NpmDirect | UpstreamRoute::LpmWorker => true,
        UpstreamRoute::Custom { target, .. } => {
            crate::npm_public_source::is_public_npm_origin(&target.base_url)
                || crate::npm_public_source::is_lpm_registry_origin(&target.base_url, client)
        }
    }
}

/// One verdict request per artifact. The integrity is part of the key when
/// the lookup sends it, so each artifact of one version keeps its own verdict.
pub(super) fn materialization_verdict_packages(
    packages: &[NpmFirewallMaterializationPackage],
    lookup_mode: NpmFirewallLookupMode,
) -> Vec<NpmFirewallBatchPackage> {
    let include_integrity = lookup_mode.include_integrity();
    let mut seen = HashSet::with_capacity(packages.len());
    packages
        .iter()
        .filter(|package| {
            seen.insert((
                package.name.as_str(),
                package.version.as_str(),
                include_integrity
                    .then_some(package.integrity.as_deref())
                    .flatten(),
            ))
        })
        .map(|package| package.to_batch_package(lookup_mode))
        .collect()
}

pub(crate) fn prepare_npm_firewall_materialization_preflight(
    project_dir: &Path,
    packages: &[NpmFirewallMaterializationPackage],
    json_output: bool,
) -> Result<NpmFirewallMaterializationPreflight, LpmError> {
    let global_config = crate::commands::config::GlobalConfig::load_checked()?;
    let crate::npm_firewall_config::RuntimeFirewall {
        mode,
        policy_profile,
        bypass,
    } = crate::npm_firewall_config::resolve_runtime_firewall(
        &global_config,
        project_dir,
        json_output,
        crate::npm_firewall_config::BypassRuleScope::ProjectAndGlobal(project_dir),
    )?;
    let lookup_mode = NpmFirewallLookupMode::from_env();
    let verdict_packages = materialization_verdict_packages(packages, lookup_mode);
    Ok(NpmFirewallMaterializationPreflight {
        mode,
        lookup_mode,
        policy_profile,
        bypass,
        verdict_packages,
    })
}

/// A materialization verdict that has settled, or that monitor mode is still
/// requesting while the package downloads.
pub(crate) struct NpmFirewallMaterializationVerdict(MaterializationVerdictState);

enum MaterializationVerdictState {
    Settled(Box<SettledMaterialization>),
    Pending(NpmFirewallPreflightJoin),
}

struct SettledMaterialization {
    json: NpmFirewallMaterializationJson,
    stats: NpmFirewallPreflightStats,
}

impl NpmFirewallMaterializationVerdict {
    /// Waits for a pending verdict and reports it.
    pub(crate) async fn settle(
        self,
        json_output: bool,
    ) -> Result<NpmFirewallMaterializationJson, LpmError> {
        Ok(self.settled(json_output).await?.json)
    }

    /// [`Self::settle`], also handing what bypass rules let through to the
    /// command's `report`, as `lpm add` reports its source package with the
    /// installs it runs.
    pub(crate) async fn settle_into(
        self,
        json_output: bool,
        report: &super::FirewallBypassReport,
    ) -> Result<NpmFirewallMaterializationJson, LpmError> {
        let settled = self.settled(json_output).await?;
        report.record(&settled.stats);
        Ok(settled.json)
    }

    async fn settled(self, json_output: bool) -> Result<SettledMaterialization, LpmError> {
        match self.0 {
            MaterializationVerdictState::Settled(settled) => Ok(*settled),
            MaterializationVerdictState::Pending(join) => {
                finish_npm_firewall_materialization(join.drain().await?, json_output)
            }
        }
    }
}

/// Starts the verdict request for a materialization. Enforce mode waits for
/// the verdict here, before any package bytes are downloaded; monitor mode
/// requests it in the background.
pub(crate) async fn begin_prepared_npm_firewall_materialization_preflight(
    client: &RegistryClient,
    preflight: NpmFirewallMaterializationPreflight,
    json_output: bool,
) -> Result<NpmFirewallMaterializationVerdict, LpmError> {
    let request = request_npm_firewall_preflight_with_bypass(
        PreflightSettings {
            mode: preflight.mode,
            lookup_mode: preflight.lookup_mode,
            policy_profile: preflight.policy_profile,
            offline: false,
            force: false,
            bypass: preflight.bypass,
        },
        Arc::new(client.clone_with_config()),
        preflight.verdict_packages,
    );
    let state = if matches!(preflight.mode, NpmFirewallMode::Monitor) {
        MaterializationVerdictState::Pending(NpmFirewallPreflightJoin {
            handle: Some(tokio::spawn(request)),
        })
    } else {
        MaterializationVerdictState::Settled(Box::new(finish_npm_firewall_materialization(
            request.await?,
            json_output,
        )?))
    };
    Ok(NpmFirewallMaterializationVerdict(state))
}

fn finish_npm_firewall_materialization(
    result: NpmFirewallPreflightResult,
    json_output: bool,
) -> Result<SettledMaterialization, LpmError> {
    let json = npm_firewall_materialization_json(&result);
    finish_npm_firewall_preflight(result, json_output)
        .map(|stats| SettledMaterialization { json, stats })
}

fn npm_firewall_materialization_json(
    result: &NpmFirewallPreflightResult,
) -> NpmFirewallMaterializationJson {
    if !result.stats.mode.is_enabled() {
        return None;
    }

    let mut json = result.stats.to_security_json();
    if let Some(report_error) = &result.report_error {
        json["monitor_error"] = serde_json::Value::String(report_error.clone());
    }
    if !result.decisions.is_empty() {
        json["decisions"] = serde_json::Value::Array(
            result
                .decisions
                .iter()
                .map(npm_firewall_decision_json)
                .collect(),
        );
    }
    Some(json)
}

fn npm_firewall_decision_json(decision: &NpmFirewallDecision) -> serde_json::Value {
    let mut json = serde_json::json!({
        "decision_id": &decision.decision_id,
        "name": &decision.name,
        "version": &decision.version,
        "action": decision.action.as_str(),
        "verdict": &decision.verdict,
        "reason": &decision.reason,
        "match_source": &decision.match_source,
        "matched_key": &decision.matched_key,
        "policy_mode": &decision.policy_mode,
        "enqueue_scan": decision.enqueue_scan,
        "scanned_at": &decision.scanned_at,
        "scan_run_id": &decision.scan_run_id,
        "report_path": &decision.report_path,
        "confidence": decision.confidence,
    });
    if let Some(policy) = &decision.policy {
        json["policy"] = serde_json::json!({
            "group": &policy.group,
            "key": &policy.key,
            "intent": &policy.intent,
            "default_action": policy.default_action.map(|action| action.as_str()),
        });
    }
    if let Some(authority) = &decision.authority {
        json["authority"] = serde_json::json!({
            "source": &authority.source,
            "source_type": &authority.source_type,
            "external_intel": authority.external_intel,
        });
    }
    if let Some(display) = &decision.display {
        json["display"] = serde_json::json!({
            "summary": &display.summary,
            "report_url": &display.report_url,
        });
    }
    json
}

pub(crate) fn print_npm_firewall_decisions(decisions: &[&NpmFirewallDecision]) {
    print_firewall_decisions(decisions);
}

fn print_firewall_decisions(decisions: &[&NpmFirewallDecision]) {
    for decision in decisions {
        for line in firewall_decision_lines(decision) {
            install_ui::detail_line(line);
        }
    }
}

fn firewall_decision_lines(decision: &NpmFirewallDecision) -> Vec<install_ui::TerminalLine> {
    let package = format!("{}@{}", decision.name, decision.version);
    let row = install_ui::terminal_line!(
        "  {} {} - ",
        firewall_action_field(decision.action, "›"),
        firewall_action_field(decision.action, &package),
    );
    let summary = decision
        .display
        .as_ref()
        .and_then(|display| non_empty_display_text(display.summary.as_deref()));
    let row = if let Some(summary) = summary {
        install_ui::terminal_line!(
            "{}{}: {}",
            row,
            firewall_action_field(decision.action, decision.action.as_str()),
            summary,
        )
    } else {
        install_ui::terminal_line!(
            "{}{}: {}{}",
            row,
            firewall_action_field(decision.action, &decision.verdict),
            decision.reason,
            firewall_decision_context(decision),
        )
    };
    let mut lines = Vec::with_capacity(2);
    lines.push(row);
    if let Some(report_url) = decision
        .display
        .as_ref()
        .and_then(|display| non_empty_display_text(display.report_url.as_deref()))
    {
        lines.push(install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim("report:"),
            install_ui::hyperlink(report_url),
        ));
    }
    lines
}

fn firewall_action_field(action: NpmFirewallAction, text: &str) -> install_ui::TerminalFragment {
    match action {
        NpmFirewallAction::Block => install_ui::red(text),
        NpmFirewallAction::Warn => install_ui::yellow(text),
        NpmFirewallAction::Allow => install_ui::green(text),
    }
}

fn non_empty_display_text(value: Option<&str>) -> Option<&str> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn firewall_decision_context(decision: &NpmFirewallDecision) -> String {
    let policy = decision.policy.as_ref().map(|policy| {
        format!(
            "policy {}",
            lpm_common::sanitize_for_terminal(firewall_policy_group_label(&policy.group))
        )
    });
    let authority = decision.authority.as_ref().map(|authority| {
        format!(
            "source {}",
            lpm_common::sanitize_for_terminal(&authority.source)
        )
    });
    match (policy, authority) {
        (Some(policy), Some(authority)) => format!(" ({policy}, {authority})"),
        (Some(policy), None) => format!(" ({policy})"),
        (None, Some(authority)) => format!(" ({authority})"),
        (None, None) => String::new(),
    }
}

fn firewall_policy_group_label(group: &str) -> &str {
    if group == "static_only_suspicious" {
        "lpm_ai_suspicious"
    } else {
        group
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_firewall_preflight_drain_aborts_its_pending_task() {
        let cancelled = tokio_util::sync::CancellationToken::new();
        let guard = cancelled.clone().drop_guard();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let _ = started_tx.send(());
            futures::future::pending().await
        });
        let abort = handle.abort_handle();
        let join = NpmFirewallPreflightJoin {
            handle: Some(handle),
        };
        started_rx.await.unwrap();
        let mut drain = Box::pin(join.drain());
        assert!(futures::poll!(drain.as_mut()).is_pending());
        drop(drain);
        let stopped =
            tokio::time::timeout(std::time::Duration::from_secs(1), cancelled.cancelled())
                .await
                .is_ok();
        abort.abort();
        assert!(stopped, "cancelling drain must retain abort ownership");
    }

    use lpm_registry::client::{
        NpmFirewallDecisionAuthority, NpmFirewallDecisionDisplay, NpmFirewallDecisionPolicy,
    };

    fn firewall_decision_with_display(summary: &str, report_url: &str) -> NpmFirewallDecision {
        NpmFirewallDecision {
            decision_id: "decision-1".to_string(),
            name: "moi-computer".to_string(),
            version: "0.1.0".to_string(),
            action: NpmFirewallAction::Warn,
            verdict: "suspicious".to_string(),
            reason: "client policy maps lpm_ai_suspicious to warn".to_string(),
            match_source: "package".to_string(),
            matched_key: None,
            policy_mode: "product_default".to_string(),
            enqueue_scan: false,
            scanned_at: None,
            scan_run_id: None,
            report_path: None,
            confidence: None,
            policy: None,
            authority: None,
            display: Some(NpmFirewallDecisionDisplay {
                summary: Some(summary.to_string()),
                report_url: Some(report_url.to_string()),
            }),
        }
    }

    #[test]
    fn firewall_decision_context_renders_legacy_static_only_group_as_ai_suspicious() {
        let decision = NpmFirewallDecision {
            decision_id: "decision-1".to_string(),
            name: "legacy-ai-warning".to_string(),
            version: "1.0.0".to_string(),
            action: NpmFirewallAction::Warn,
            verdict: "suspicious".to_string(),
            reason: "client policy maps lpm_ai_suspicious to warn".to_string(),
            match_source: "package".to_string(),
            matched_key: None,
            policy_mode: "product_default".to_string(),
            enqueue_scan: false,
            scanned_at: None,
            scan_run_id: None,
            report_path: None,
            confidence: None,
            policy: Some(NpmFirewallDecisionPolicy {
                group: "static_only_suspicious".to_string(),
                key: None,
                intent: None,
                default_action: None,
            }),
            authority: Some(NpmFirewallDecisionAuthority {
                source: "lpm_ai".to_string(),
                source_type: Some("lpm".to_string()),
                external_intel: Some(false),
            }),
            display: None,
        };

        assert_eq!(
            firewall_decision_context(&decision),
            " (policy lpm_ai_suspicious, source lpm_ai)"
        );
    }

    fn plain_firewall_decision_lines(decision: &NpmFirewallDecision) -> Vec<String> {
        firewall_decision_lines(decision)
            .iter()
            .map(|line| console::strip_ansi_codes(line.as_ref()).into_owned())
            .collect()
    }

    #[test]
    fn firewall_decision_lines_prefer_display_summary_and_report_url() {
        let decision = firewall_decision_with_display(
            "May alter local Git configuration and add or overwrite package-owned agent skills in selected workspaces.",
            "https://firewall.lpm.dev/npm/moi-computer/v/0.1.0",
        );

        assert_eq!(
            plain_firewall_decision_lines(&decision),
            vec![
                "  › moi-computer@0.1.0 - warn: May alter local Git configuration and add or overwrite package-owned agent skills in selected workspaces.".to_string(),
                "    report: https://firewall.lpm.dev/npm/moi-computer/v/0.1.0".to_string(),
            ]
        );
    }

    #[test]
    fn firewall_decision_lines_neutralize_terminal_controls_in_display_fields() {
        let decision = firewall_decision_with_display(
            "summary\x1b]52;c;c3VtbWFyeQ==\x07bell\x07line\nreturn\rback\x08end",
            "https://firewall.lpm.dev/\x1b]52;c;cmVwb3J0\x07bell\x07line\nreturn\rback\x08end",
        );

        assert_eq!(
            plain_firewall_decision_lines(&decision),
            vec![
                "  › moi-computer@0.1.0 - warn: summarybell?line?return?back?end".to_string(),
                "    report: https://firewall.lpm.dev/bell?line?return?back?end".to_string(),
            ]
        );
    }

    #[test]
    fn firewall_decision_lines_retain_fallback_verdict_reason_and_context() {
        let mut decision = firewall_decision_with_display(
            "  ",
            "https://firewall.lpm.dev/npm/moi-computer/v/0.1.0",
        );
        decision.policy = Some(NpmFirewallDecisionPolicy {
            group: "lpm_ai_suspicious".to_string(),
            key: None,
            intent: None,
            default_action: None,
        });
        decision.authority = Some(NpmFirewallDecisionAuthority {
            source: "lpm_ai".to_string(),
            source_type: None,
            external_intel: None,
        });

        assert_eq!(
            plain_firewall_decision_lines(&decision),
            vec![
                "  › moi-computer@0.1.0 - suspicious: client policy maps lpm_ai_suspicious to warn (policy lpm_ai_suspicious, source lpm_ai)",
                "    report: https://firewall.lpm.dev/npm/moi-computer/v/0.1.0",
            ]
        );
    }

    #[test]
    fn firewall_decision_lines_name_telemetry_and_dependency_script_policy_groups() {
        for (group, reason) in [
            (
                "lpm_ai_telemetry",
                "client policy maps lpm_ai_suspicious to warn (telemetry)",
            ),
            (
                "lpm_ai_dependency_script_policy",
                "client policy maps lpm_ai_dependency_script_policy to warn",
            ),
        ] {
            let mut decision = firewall_decision_with_display(
                "",
                "https://firewall.lpm.dev/npm/moi-computer/v/0.1.0",
            );
            decision.reason = reason.to_string();
            decision.policy = Some(NpmFirewallDecisionPolicy {
                group: group.to_string(),
                key: None,
                intent: None,
                default_action: Some(lpm_registry::client::NpmFirewallPolicyAction::Warn),
            });
            decision.authority = Some(NpmFirewallDecisionAuthority {
                source: "lpm_ai".to_string(),
                source_type: None,
                external_intel: None,
            });

            assert_eq!(
                plain_firewall_decision_lines(&decision)[0],
                format!(
                    "  › moi-computer@0.1.0 - suspicious: {reason} (policy {group}, source lpm_ai)"
                ),
            );
        }
    }

    #[test]
    fn firewall_decision_lines_sanitize_fallback_package_and_verdict_fields() {
        let mut decision = firewall_decision_with_display("", "");
        decision.name = "package\nforged".to_string();
        decision.version = "1.0.0\x1b[2J".to_string();
        decision.verdict = "malicious\x1b]52;c;AAAA\x07".to_string();
        decision.reason = "reason\rforged".to_string();
        decision.policy = None;
        decision.authority = None;

        assert_eq!(
            plain_firewall_decision_lines(&decision),
            vec!["  › package?forged@1.0.0 - malicious: reason?forged"],
        );
    }

    #[test]
    fn npm_firewall_decision_json_includes_display_metadata() {
        let decision = NpmFirewallDecision {
            decision_id: "decision-1".to_string(),
            name: "n8n-nodes-pwn".to_string(),
            version: "1.0.1".to_string(),
            action: NpmFirewallAction::Block,
            verdict: "malicious".to_string(),
            reason: "client policy maps lpm_ai_confirmed_malware to block".to_string(),
            match_source: "package".to_string(),
            matched_key: None,
            policy_mode: "product_default".to_string(),
            enqueue_scan: false,
            scanned_at: None,
            scan_run_id: None,
            report_path: None,
            confidence: Some(0.99),
            policy: None,
            authority: None,
            display: Some(NpmFirewallDecisionDisplay {
                summary: Some(
                    "Host and potentially sensitive root-readable file contents are sent to a hard-coded external host."
                        .to_string(),
                ),
                report_url: Some("https://firewall.lpm.dev/npm/n8n-nodes-pwn/v/1.0.1".to_string()),
            }),
        };

        let json = npm_firewall_decision_json(&decision);
        assert_eq!(
            json["display"],
            serde_json::json!({
                "summary": "Host and potentially sensitive root-readable file contents are sent to a hard-coded external host.",
                "report_url": "https://firewall.lpm.dev/npm/n8n-nodes-pwn/v/1.0.1",
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_monitor_verdict_cache_dir_tightens_existing_cache_root_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let cache_root = root.path().join("metadata-cache");
        std::fs::create_dir(&cache_root).unwrap();
        std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let dir = open_monitor_verdict_cache_dir_nofollow(&cache_root, true)
            .expect("cache dir should open");
        drop(dir);

        let root_mode = std::fs::symlink_metadata(&cache_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            root_mode, 0o700,
            "existing cache root must be tightened to owner-only 0o700"
        );
        let subdir_mode = std::fs::symlink_metadata(cache_root.join(MONITOR_VERDICT_SUBDIR))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            subdir_mode, 0o700,
            "monitor verdict subdir must be owner-only 0o700"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_monitor_verdict_cache_dir_refuses_symlink_without_changing_target_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("real-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let symlink_cache = root.path().join("linked-cache");
        std::os::unix::fs::symlink(&target, &symlink_cache).unwrap();

        assert!(
            open_monitor_verdict_cache_dir_nofollow(&symlink_cache, true).is_none(),
            "symlinked cache root must be refused"
        );
        let target_mode = std::fs::symlink_metadata(&target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            target_mode, 0o755,
            "refusing a symlinked cache root must not chmod its target directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_monitor_verdict_cache_dir_read_mode_rejects_group_or_world_writable_directories() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let cache_root = root.path().join("metadata-cache");
        let subdir = cache_root.join(MONITOR_VERDICT_SUBDIR);
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&subdir, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert!(
            open_monitor_verdict_cache_dir_nofollow(&cache_root, false).is_none(),
            "read-only verdict cache open must reject world-writable monitor-verdicts directory"
        );

        std::fs::set_permissions(&subdir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            open_monitor_verdict_cache_dir_nofollow(&cache_root, false).is_none(),
            "read-only verdict cache open must reject group-writable cache root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_monitor_verdict_cache_discards_entries_from_previously_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let cache_root = root.path().join("metadata-cache");
        let subdir = cache_root.join(MONITOR_VERDICT_SUBDIR);
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&subdir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let target = MonitorVerdictCacheTarget {
            cache_root,
            filename: "verdicts.json".to_string(),
        };
        let now_secs = 1_700_000_000;
        let planted_file = subdir.join(&target.filename);
        let planted_payload = serde_json::json!({
            "version": MONITOR_VERDICT_CACHE_VERSION,
            "entries": {
                "planted-pkg@1.0.0": {
                    "expires_at": now_secs + 120
                }
            }
        });
        std::fs::write(&planted_file, planted_payload.to_string()).unwrap();
        std::fs::set_permissions(&planted_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Read-only lookup rejects the world-writable directory.
        assert!(read_monitor_verdict_cache(&target, now_secs).is_empty());

        // Writing a fresh verdict heals permissions and must discard planted entries.
        update_monitor_verdict_cache(
            &target,
            vec![(
                "fresh-pkg@1.0.0".to_string(),
                MonitorVerdictCacheEntry {
                    expires_at: now_secs + 120,
                    unknown: false,
                    matched: false,
                },
            )],
            Vec::new(),
            now_secs,
        );

        let after = read_monitor_verdict_cache(&target, now_secs);
        assert!(
            !after.contains_key("planted-pkg@1.0.0"),
            "healing a previously world-writable verdict cache directory must not launder planted entries"
        );
        assert!(
            after.contains_key("fresh-pkg@1.0.0"),
            "fresh addition written during heal must be persisted"
        );
        assert!(!is_trusted_verdict_file_unix(1001, 1000, 0o600));
        assert!(!is_trusted_verdict_file_unix(1000, 1000, 0o640));
        assert!(is_trusted_verdict_file_unix(1000, 1000, 0o600));
    }
}
