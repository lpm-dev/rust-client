use super::*;
use lpm_registry::client::{
    AuthPosture, NpmFirewallAction, NpmFirewallBatchPackage, NpmFirewallBatchResponse,
    NpmFirewallClientTiming, NpmFirewallDecision, NpmFirewallDiagnostics,
    NpmFirewallFlaggedPackageIndexDiagnostics,
};

pub(super) use crate::npm_firewall_config::NpmFirewallMode;

const ENV_EXPERIMENT_NPM_FIREWALL_LOOKUP: &str = "LPM_EXPERIMENT_NPM_FIREWALL_LOOKUP";
const ENV_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE: &str = "LPM_EXPERIMENT_NPM_FIREWALL_CHUNK_SIZE";
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
    verdict_packages: Vec<NpmFirewallBatchPackage>,
}

impl NpmFirewallMaterializationPreflight {
    pub(crate) fn is_active(&self) -> bool {
        self.mode.is_enabled() && !self.verdict_packages.is_empty()
    }
}

impl NpmFirewallMode {
    pub(super) fn auth_posture(self) -> AuthPosture {
        match self {
            Self::Off | Self::Report => AuthPosture::AnonymousPreferred,
            Self::Enforce => AuthPosture::AuthRequired,
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
    pub(super) unknown_count: u64,
    pub(super) matched_count: u64,
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
        if let Some(diagnostics) = &self.worker_diagnostics {
            json["worker"] = serde_json::to_value(diagnostics).unwrap_or(serde_json::Value::Null);
        }
        if let Some(timing) = &self.client_timing {
            json["client"] = serde_json::to_value(timing).unwrap_or(serde_json::Value::Null);
        }
        json
    }
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
}

impl NpmFirewallPreflightResult {
    fn empty(mode: NpmFirewallMode, lookup_mode: NpmFirewallLookupMode) -> Self {
        Self {
            stats: NpmFirewallPreflightStats::for_mode(mode, lookup_mode),
            decisions: Vec::new(),
            report_error: None,
        }
    }
}

pub(super) struct NpmFirewallPreflightJoin {
    handle: Option<tokio::task::JoinHandle<Result<NpmFirewallPreflightResult, LpmError>>>,
}

impl NpmFirewallPreflightJoin {
    pub(super) async fn drain(mut self) -> Result<NpmFirewallPreflightResult, LpmError> {
        let handle = self.handle.take().ok_or_else(|| {
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
        self.events.len()
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn clear(&mut self) {
        self.events.clear();
        self.verdict_packages.clear();
    }
}

struct FirewallChunkResult {
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    response: Option<NpmFirewallBatchResponse>,
    elapsed_ms: u128,
    report_error: Option<String>,
}

pub(super) struct NpmFirewallChunkedPreflightConfig {
    pub(super) route_table: RouteTable,
    pub(super) mode: NpmFirewallMode,
    pub(super) lookup_mode: NpmFirewallLookupMode,
    pub(super) offline: bool,
    pub(super) chunk_size: usize,
}

pub(super) fn spawn_chunked_npm_firewall_preflight(
    mut selected_rx: tokio::sync::mpsc::UnboundedReceiver<lpm_resolver::SelectedPackageEvent>,
    fetch_tx: tokio::sync::mpsc::UnboundedSender<lpm_resolver::SelectedPackageEvent>,
    client: Arc<RegistryClient>,
    config: NpmFirewallChunkedPreflightConfig,
) -> NpmFirewallPreflightJoin {
    let handle = tokio::spawn(async move {
        let NpmFirewallChunkedPreflightConfig {
            route_table,
            mode,
            lookup_mode,
            offline,
            chunk_size,
        } = config;

        if !mode.is_enabled() {
            while let Some(event) = selected_rx.recv().await {
                let _ = fetch_tx.send(event);
            }
            return Ok(NpmFirewallPreflightResult::empty(mode, lookup_mode));
        }

        let chunk_size = chunk_size.max(1);
        let mut stats = NpmFirewallPreflightStats::for_mode(mode, lookup_mode);
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
                let _ = fetch_tx.send(event);
            }
            report_error = Some(format!(
                "{NPM_FIREWALL_OFFLINE_HINT}; continuing because report mode is active"
            ));
            stats.batch_ms = total_started.elapsed().as_millis();
            return Ok(NpmFirewallPreflightResult {
                stats,
                decisions,
                report_error,
            });
        }

        let mut chunk = FirewallSelectedChunk::with_capacity(chunk_size);
        let mut receiver_closed = false;
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                event = selected_rx.recv(), if !receiver_closed => {
                    match event {
                        Some(event) => {
                            push_firewall_chunk_event(
                                &mut chunk,
                                event,
                                &route_table,
                                client.as_ref(),
                                lookup_mode,
                            );
                            if chunk.len() >= chunk_size {
                                spawn_or_release_firewall_chunk(
                                    &mut chunk,
                                    &fetch_tx,
                                    &client,
                                    mode,
                                    &mut stats,
                                    &mut tasks,
                                );
                            }
                        }
                        None => {
                            receiver_closed = true;
                            spawn_or_release_firewall_chunk(
                                &mut chunk,
                                &fetch_tx,
                                &client,
                                mode,
                                &mut stats,
                                &mut tasks,
                            );
                        }
                    }
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let chunk_result = joined
                        .ok_or_else(|| LpmError::Registry("npm firewall chunk task ended unexpectedly".into()))?
                        .map_err(|error| LpmError::Registry(format!("npm firewall chunk task panicked: {error}")))??;
                    apply_firewall_chunk_result(
                        chunk_result,
                        &fetch_tx,
                        mode,
                        &mut stats,
                        &mut decisions,
                        &mut report_error,
                    );
                    if matches!(mode, NpmFirewallMode::Enforce) && stats.block_count > 0 {
                        tasks.abort_all();
                        stats.batch_ms = total_started.elapsed().as_millis();
                        return Ok(NpmFirewallPreflightResult {
                            stats,
                            decisions,
                            report_error,
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

        stats.batch_ms = total_started.elapsed().as_millis();
        Ok(NpmFirewallPreflightResult {
            stats,
            decisions,
            report_error,
        })
    });
    NpmFirewallPreflightJoin {
        handle: Some(handle),
    }
}

fn push_firewall_chunk_event(
    chunk: &mut FirewallSelectedChunk,
    event: lpm_resolver::SelectedPackageEvent,
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) {
    if let Some(verdict_package) =
        npm_firewall_package_from_selected_event(&event, route_table, client, lookup_mode)
    {
        chunk.verdict_packages.push(verdict_package);
    }
    chunk.events.push(event);
}

fn spawn_or_release_firewall_chunk(
    chunk: &mut FirewallSelectedChunk,
    fetch_tx: &tokio::sync::mpsc::UnboundedSender<lpm_resolver::SelectedPackageEvent>,
    client: &Arc<RegistryClient>,
    mode: NpmFirewallMode,
    stats: &mut NpmFirewallPreflightStats,
    tasks: &mut tokio::task::JoinSet<Result<FirewallChunkResult, LpmError>>,
) {
    if chunk.is_empty() {
        return;
    }
    if chunk.verdict_packages.is_empty() {
        release_firewall_events(fetch_tx, chunk.events.drain(..));
        chunk.clear();
        return;
    }

    stats.checked_count = stats
        .checked_count
        .saturating_add(chunk.verdict_packages.len() as u64);
    let events = std::mem::take(&mut chunk.events);
    let verdict_packages = std::mem::take(&mut chunk.verdict_packages);
    let client = Arc::clone(client);
    tasks
        .spawn(async move { request_firewall_chunk(client, mode, events, verdict_packages).await });
}

async fn request_firewall_chunk(
    client: Arc<RegistryClient>,
    mode: NpmFirewallMode,
    events: Vec<lpm_resolver::SelectedPackageEvent>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
) -> Result<FirewallChunkResult, LpmError> {
    let started = Instant::now();
    let response = match client
        .npm_firewall_batch_verdicts_with_posture(&verdict_packages, mode.auth_posture())
        .await
    {
        Ok(response) => response,
        Err(error) if matches!(mode, NpmFirewallMode::Report) => {
            return Ok(FirewallChunkResult {
                events,
                response: None,
                elapsed_ms: started.elapsed().as_millis(),
                report_error: Some(format!(
                    "npm firewall verdict preflight failed in report mode: {error}"
                )),
            });
        }
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "npm firewall verdict preflight failed: {error}"
            )));
        }
    };
    Ok(FirewallChunkResult {
        events,
        response: Some(response),
        elapsed_ms: started.elapsed().as_millis(),
        report_error: None,
    })
}

fn apply_firewall_chunk_result(
    chunk_result: FirewallChunkResult,
    fetch_tx: &tokio::sync::mpsc::UnboundedSender<lpm_resolver::SelectedPackageEvent>,
    mode: NpmFirewallMode,
    stats: &mut NpmFirewallPreflightStats,
    decisions: &mut Vec<NpmFirewallDecision>,
    report_error: &mut Option<String>,
) {
    if let Some(error) = chunk_result.report_error {
        stats.rpc_failed = true;
        stats.chunk_count = stats.chunk_count.saturating_add(1);
        stats.chunk_sum_ms = stats.chunk_sum_ms.saturating_add(chunk_result.elapsed_ms);
        stats.chunk_max_ms = stats.chunk_max_ms.max(chunk_result.elapsed_ms);
        if report_error.is_none() {
            *report_error = Some(error);
        }
        release_firewall_events(fetch_tx, chunk_result.events);
        return;
    }

    let Some(response) = chunk_result.response else {
        release_firewall_events(fetch_tx, chunk_result.events);
        return;
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

    let chunk_has_block = response.summary.block > 0
        || response
            .decisions
            .iter()
            .any(|decision| decision.action == NpmFirewallAction::Block);
    decisions.extend(response.decisions);
    if matches!(mode, NpmFirewallMode::Report) || !chunk_has_block {
        release_firewall_events(fetch_tx, chunk_result.events);
    }
}

fn release_firewall_events(
    fetch_tx: &tokio::sync::mpsc::UnboundedSender<lpm_resolver::SelectedPackageEvent>,
    events: impl IntoIterator<Item = lpm_resolver::SelectedPackageEvent>,
) {
    for event in events {
        let _ = fetch_tx.send(event);
    }
}

pub(super) async fn request_npm_firewall_preflight(
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    client: Arc<RegistryClient>,
    verdict_packages: Vec<NpmFirewallBatchPackage>,
    offline: bool,
) -> Result<NpmFirewallPreflightResult, LpmError> {
    let mut stats = NpmFirewallPreflightStats::for_mode(mode, lookup_mode);
    if !mode.is_enabled() {
        return Ok(NpmFirewallPreflightResult::empty(mode, lookup_mode));
    }

    stats.checked_count = verdict_packages.len() as u64;
    if verdict_packages.is_empty() {
        return Ok(NpmFirewallPreflightResult {
            stats,
            decisions: Vec::new(),
            report_error: None,
        });
    }

    if offline {
        stats.offline_skipped = true;
        let message = NPM_FIREWALL_OFFLINE_HINT.to_string();
        if matches!(mode, NpmFirewallMode::Report) {
            return Ok(NpmFirewallPreflightResult {
                stats,
                decisions: Vec::new(),
                report_error: Some(format!(
                    "{message}; continuing because report mode is active"
                )),
            });
        }
        return Err(LpmError::Registry(message));
    }

    let started = Instant::now();
    let response = match client
        .npm_firewall_batch_verdicts_with_posture(&verdict_packages, mode.auth_posture())
        .await
    {
        Ok(response) => response,
        Err(error) if matches!(mode, NpmFirewallMode::Report) => {
            stats.batch_ms = started.elapsed().as_millis();
            stats.rpc_failed = true;
            return Ok(NpmFirewallPreflightResult {
                stats,
                decisions: Vec::new(),
                report_error: Some(format!(
                    "npm firewall verdict preflight failed in report mode: {error}"
                )),
            });
        }
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "npm firewall verdict preflight failed: {error}"
            )));
        }
    };
    stats.batch_ms = started.elapsed().as_millis();
    stats.record_response(&response, stats.batch_ms);
    tracing::debug!(
        target = "lpm::firewall",
        package_count = response.summary.total,
        matched = response.summary.matched,
        warn = response.summary.warn,
        block = response.summary.block,
        elapsed_ms = stats.batch_ms,
        request_id = %response.request_id,
        policy_mode = %response.policy_mode,
        "npm firewall verdict preflight completed",
    );
    Ok(NpmFirewallPreflightResult {
        stats,
        decisions: response.decisions,
        report_error: None,
    })
}

pub(super) fn finish_npm_firewall_preflight(
    result: NpmFirewallPreflightResult,
    json_output: bool,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let stats = result.stats;
    if let Some(error) = result.report_error {
        if !json_output {
            output::warn(&error);
        }
        return Ok(stats);
    }

    let blocked: Vec<_> = result
        .decisions
        .iter()
        .filter(|decision| decision.action == NpmFirewallAction::Block)
        .collect();
    let warned: Vec<_> = result
        .decisions
        .iter()
        .filter(|decision| decision.action == NpmFirewallAction::Warn)
        .collect();
    let blocked_count = blocked.len().max(stats.block_count as usize);
    let warned_count = warned.len().max(stats.warn_count as usize);

    if matches!(stats.mode, NpmFirewallMode::Report) {
        if !json_output && (blocked_count > 0 || warned_count > 0) {
            output::warn(&format!(
                "npm firewall report found {} blocked and {} warned package(s); command continues because report mode is active.",
                blocked_count, warned_count
            ));
            print_firewall_decisions(&blocked);
            print_firewall_decisions(&warned);
        }
        return Ok(stats);
    }

    if warned_count > 0 && !json_output {
        output::warn(&format!(
            "npm firewall warned for {} package(s):",
            warned_count
        ));
        print_firewall_decisions(&warned);
    }

    if blocked_count == 0 {
        return Ok(stats);
    }

    if !json_output {
        output::warn(&format!(
            "npm firewall blocked {} package(s):",
            blocked_count
        ));
        print_firewall_decisions(&blocked);
    }
    Err(LpmError::Registry(format!(
        "{} package(s) blocked by LPM npm firewall",
        blocked_count
    )))
}

pub(super) async fn run_npm_firewall_preflight(
    mode: NpmFirewallMode,
    lookup_mode: NpmFirewallLookupMode,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    packages: &[InstallPackage],
    offline: bool,
    json_output: bool,
) -> Result<NpmFirewallPreflightStats, LpmError> {
    let verdict_packages =
        npm_firewall_packages(packages, route_table, client.as_ref(), lookup_mode);
    let result = request_npm_firewall_preflight(
        mode,
        lookup_mode,
        Arc::clone(client),
        verdict_packages,
        offline,
    )
    .await?;
    finish_npm_firewall_preflight(result, json_output)
}

pub(super) fn npm_firewall_packages(
    packages: &[InstallPackage],
    route_table: &RouteTable,
    client: &RegistryClient,
    lookup_mode: NpmFirewallLookupMode,
) -> Vec<NpmFirewallBatchPackage> {
    let mut verdict_packages = Vec::with_capacity(packages.len());
    for package in packages {
        if let Some(verdict_package) =
            npm_firewall_package(package, route_table, client, lookup_mode)
        {
            verdict_packages.push(verdict_package);
        }
    }
    verdict_packages
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

pub(crate) fn prepare_npm_firewall_materialization_preflight(
    project_dir: &Path,
    packages: &[NpmFirewallMaterializationPackage],
    json_output: bool,
) -> Result<NpmFirewallMaterializationPreflight, LpmError> {
    let global_config = crate::commands::config::GlobalConfig::load_checked()?;
    let mode =
        crate::npm_firewall_config::resolve_runtime_mode(&global_config, project_dir, json_output)?;
    let lookup_mode = NpmFirewallLookupMode::from_env();
    let mut verdict_packages = Vec::with_capacity(packages.len());
    for package in packages {
        verdict_packages.push(package.to_batch_package(lookup_mode));
    }
    Ok(NpmFirewallMaterializationPreflight {
        mode,
        lookup_mode,
        verdict_packages,
    })
}

pub(crate) async fn run_prepared_npm_firewall_materialization_preflight(
    client: &RegistryClient,
    preflight: NpmFirewallMaterializationPreflight,
    json_output: bool,
) -> Result<NpmFirewallMaterializationJson, LpmError> {
    let result = request_npm_firewall_preflight(
        preflight.mode,
        preflight.lookup_mode,
        Arc::new(client.clone_with_config()),
        preflight.verdict_packages,
        false,
    )
    .await?;
    let firewall_json = npm_firewall_materialization_json(&result);
    finish_npm_firewall_preflight(result, json_output).map(|_| firewall_json)
}

fn npm_firewall_materialization_json(
    result: &NpmFirewallPreflightResult,
) -> NpmFirewallMaterializationJson {
    if !result.stats.mode.is_enabled() {
        return None;
    }

    let mut json = result.stats.to_json();
    if let Some(report_error) = &result.report_error {
        json["report_error"] = serde_json::Value::String(report_error.clone());
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
    serde_json::json!({
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
    })
}

fn print_firewall_decisions(decisions: &[&NpmFirewallDecision]) {
    for decision in decisions {
        let name = lpm_common::sanitize_for_terminal(&decision.name);
        let version = lpm_common::sanitize_for_terminal(&decision.version);
        let verdict = lpm_common::sanitize_for_terminal(&decision.verdict);
        let reason = lpm_common::sanitize_for_terminal(&decision.reason);
        eprintln!("    {name}@{version} - {verdict}: {reason}");
    }
}
