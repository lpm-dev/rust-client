use super::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::OnceCell;

const ENV_EXPERIMENTAL_INSTALLER_SPIKE: &str = "LPM_EXPERIMENTAL_INSTALLER_SPIKE";
const ENV_INSTALLER_SPIKE_CONCURRENCY: &str = "LPM_INSTALLER_SPIKE_CONCURRENCY";
const ENV_INSTALLER_SPIKE_METADATA_CONCURRENCY: &str = "LPM_INSTALLER_SPIKE_METADATA_CONCURRENCY";
const ENV_INSTALLER_SPIKE_GRAPH: &str = "LPM_INSTALLER_SPIKE_GRAPH";
const ENV_INSTALLER_SPIKE_PARITY: &str = "LPM_INSTALLER_SPIKE_PARITY";
const ENV_INSTALLER_SPIKE_BENCHMARK_ONLY: &str = "LPM_INSTALLER_SPIKE_BENCHMARK_ONLY";
const ENV_INSTALLER_SPIKE_EXACT_DOC: &str = "LPM_INSTALLER_SPIKE_EXACT_DOC";
const DEFAULT_INSTALLER_SPIKE_CONCURRENCY: usize = 64;
const DEFAULT_INSTALLER_SPIKE_METADATA_CONCURRENCY: usize = 192;
const PARITY_SAMPLE_LIMIT: usize = 25;

pub(super) fn enabled() -> bool {
    std::env::var(ENV_EXPERIMENTAL_INSTALLER_SPIKE).as_deref() == Ok("1")
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InstallerSpikeAdmission {
    pub(super) json_output: bool,
    pub(super) frozen_lockfile_active: bool,
    pub(super) omit_policy: InstallOmitPolicy,
    pub(super) has_workspace_member_deps: bool,
    pub(super) has_v2_workspace_member_deps: bool,
    pub(super) has_tarball_source_deps: bool,
    pub(super) verify_registry_signatures: bool,
    pub(super) strict_integrity: bool,
    pub(super) force_security_floor: bool,
    pub(super) npm_firewall_enabled: bool,
    pub(super) policy_extensions_enabled: bool,
    pub(super) auto_build: bool,
    pub(super) script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    pub(super) script_policy_is_default: bool,
    pub(super) has_trusted_dependencies: bool,
    pub(super) strict_release_age_replay: bool,
    pub(super) allow_new: bool,
    pub(super) is_add_invocation: bool,
    pub(super) has_direct_versions_out: bool,
    pub(super) has_target_set: bool,
    pub(super) audit_after_install: bool,
    pub(super) no_skills: bool,
    pub(super) no_security_summary: bool,
    pub(super) verbose: bool,
    pub(super) drift_ignore_policy_is_default: bool,
    pub(super) verify_policy_is_default: bool,
}

pub(super) fn should_run(admission: InstallerSpikeAdmission) -> Result<bool, LpmError> {
    if !enabled() {
        return Ok(false);
    }
    let benchmark_only = std::env::var(ENV_INSTALLER_SPIKE_BENCHMARK_ONLY).as_deref() == Ok("1");
    let reasons = unsupported_admission_reasons(
        admission,
        InstallerSpikeGraphSource::from_env(),
        InstallerSpikeParityMode::from_env(),
        benchmark_only,
    );
    if reasons.is_empty() {
        return Ok(true);
    }
    Err(LpmError::Registry(format!(
        "experimental installer spike is limited to benchmark installs; unsupported for this invocation: {}",
        reasons.join("; ")
    )))
}

fn unsupported_admission_reasons(
    admission: InstallerSpikeAdmission,
    graph_source: InstallerSpikeGraphSource,
    parity_mode: InstallerSpikeParityMode,
    benchmark_only: bool,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if graph_source == InstallerSpikeGraphSource::Invalid {
        reasons.push("set LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist or lockfile");
    }
    if !benchmark_only {
        reasons.push("set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1");
    }
    let lockfile_graph = graph_source.uses_lockfile();
    if lockfile_graph && matches!(parity_mode, InstallerSpikeParityMode::FreshResolve { .. }) {
        reasons.push("use lockfile parity or disable parity");
    }
    if lockfile_graph && !admission.frozen_lockfile_active {
        reasons.push("use a frozen lockfile install");
    }
    if graph_source == InstallerSpikeGraphSource::ResolveWorklist
        && admission.frozen_lockfile_active
    {
        reasons.push("set LPM_INSTALLER_SPIKE_GRAPH=lockfile for frozen installs");
    }
    if graph_source == InstallerSpikeGraphSource::ResolveWorklist
        && parity_mode != (InstallerSpikeParityMode::FreshResolve { deny: true })
    {
        reasons.push("set LPM_INSTALLER_SPIKE_PARITY=deny for live graph parity");
    }
    if !admission.json_output {
        reasons.push("use --json");
    }
    if !admission.no_security_summary {
        reasons.push("use --no-security-summary");
    }
    if !admission.no_skills {
        reasons.push("use --no-skills");
    }
    if admission.omit_policy.dev {
        reasons.push("--prod/--omit=dev is not supported");
    }
    if admission.omit_policy.optional {
        reasons.push("--omit=optional is not supported");
    }
    if (admission.has_workspace_member_deps || admission.has_v2_workspace_member_deps)
        && graph_source != InstallerSpikeGraphSource::ResolveWorklist
    {
        reasons.push("workspace member links require resolve-worklist graph mode");
    }
    if admission.has_tarball_source_deps {
        reasons.push("tarball source deps are not supported");
    }
    if admission.verify_registry_signatures {
        reasons.push("registry signature verification is not supported");
    }
    if admission.strict_integrity {
        reasons.push("strict integrity mode is not supported");
    }
    if admission.force_security_floor {
        reasons.push("force-security-floor is not supported");
    }
    if admission.npm_firewall_enabled {
        reasons.push("npm firewall is not supported");
    }
    if admission.policy_extensions_enabled {
        reasons.push("policy extensions are not supported");
    }
    if admission.auto_build
        || admission.script_policy_override.is_some()
        || !admission.script_policy_is_default
        || admission.has_trusted_dependencies
    {
        reasons.push("script policy/build execution options are not supported");
    }
    if admission.strict_release_age_replay {
        reasons.push("strict minimumReleaseAge lockfile replay is not supported");
    }
    if admission.allow_new {
        reasons.push("--allow-new is not supported");
    }
    if admission.is_add_invocation || admission.has_direct_versions_out {
        reasons.push("add-style installs are not supported");
    }
    if admission.has_target_set {
        reasons.push("workspace filtered installs are not supported");
    }
    if admission.audit_after_install {
        reasons.push("audit-after-install is not supported");
    }
    if admission.verbose {
        reasons.push("--verbose is not supported");
    }
    if !admission.drift_ignore_policy_is_default {
        reasons.push("provenance drift waivers are not supported");
    }
    if !admission.verify_policy_is_default {
        reasons.push("provenance verification policy overrides are not supported");
    }
    reasons
}

type MetadataCell = Arc<OnceCell<Arc<lpm_resolver::CachedPackageInfo>>>;
type MetadataCache = Arc<dashmap::DashMap<String, MetadataCell>>;
type ExactVersionMetadataCache = Arc<dashmap::DashMap<ExactVersionMetadataKey, MetadataCell>>;
type PackageIdentity = (String, String);
type SelectedVersion = (
    String,
    Option<lpm_resolver::PlatformMeta>,
    Option<lpm_resolver::OverrideHit>,
);
type FetchHandle = tokio::task::JoinHandle<Result<FetchOutcome, LpmError>>;
type ResolveFuture = Pin<Box<dyn Future<Output = Result<NodeResolution, LpmError>> + Send>>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct ExactVersionMetadataKey {
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
struct MetadataCaches {
    full: MetadataCache,
    exact_version: ExactVersionMetadataCache,
}

impl MetadataCaches {
    fn new() -> Self {
        Self {
            full: Arc::new(dashmap::DashMap::new()),
            exact_version: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn request_count(&self) -> usize {
        self.full.len().saturating_add(self.exact_version.len())
    }
}

#[derive(Debug, Clone)]
struct ResolveRequest {
    local_name: String,
    target_name: String,
    range: String,
    parent: Option<PackageIdentity>,
    root_ancestor: String,
    depth: u16,
    optional: bool,
    root: bool,
    direct: bool,
}

#[derive(Debug, Clone)]
struct MetadataRequestContext {
    package: String,
    range: Option<String>,
    range_shape: MetadataRangeShape,
    version_doc_eligible: bool,
    parent: Option<String>,
    root_ancestor: String,
    depth: u16,
    optional: bool,
    direct: bool,
    root: bool,
    reason: &'static str,
}

impl MetadataRequestContext {
    fn from_request(request: &ResolveRequest) -> Self {
        let range_shape = MetadataRangeShape::from_range(Some(&request.range));
        Self {
            package: request.target_name.clone(),
            range: Some(request.range.clone()),
            range_shape,
            version_doc_eligible: false,
            parent: request
                .parent
                .as_ref()
                .map(|(name, version)| format!("{name}@{version}")),
            root_ancestor: request.root_ancestor.clone(),
            depth: request.depth,
            optional: request.optional,
            direct: request.direct,
            root: request.root,
            reason: "resolve",
        }
    }

    fn peer_plan(package: &str) -> Self {
        Self {
            package: package.to_string(),
            range: None,
            range_shape: MetadataRangeShape::Unknown,
            version_doc_eligible: false,
            parent: None,
            root_ancestor: package.to_string(),
            depth: 0,
            optional: false,
            direct: false,
            root: true,
            reason: "peer-plan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataRangeShape {
    Exact,
    Star,
    Caret,
    Tilde,
    Comparator,
    Complex,
    Other,
    Unknown,
}

impl MetadataRangeShape {
    fn from_range(range: Option<&str>) -> Self {
        let Some(raw) = range.map(str::trim) else {
            return Self::Unknown;
        };
        if raw.is_empty() || raw == "*" || raw == "latest" {
            return Self::Star;
        }
        if exact_pin_version(raw).is_some() {
            return Self::Exact;
        }
        if raw.contains("||") || raw.contains(" - ") || raw.contains(' ') || raw.contains(',') {
            return Self::Complex;
        }
        if raw.starts_with('^') {
            return Self::Caret;
        }
        if raw.starts_with('~') {
            return Self::Tilde;
        }
        if raw.starts_with('<') || raw.starts_with('>') || raw.starts_with('=') {
            return Self::Comparator;
        }
        Self::Other
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Star => "star",
            Self::Caret => "caret",
            Self::Tilde => "tilde",
            Self::Comparator => "comparator",
            Self::Complex => "complex",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

fn exact_pin_version(range: &str) -> Option<String> {
    let raw = range.trim();
    let raw = raw.strip_prefix('=').unwrap_or(raw).trim();
    if lpm_resolver::NpmVersion::parse(raw).is_ok() {
        Some(raw.to_string())
    } else {
        None
    }
}

#[derive(Debug, Default)]
struct MetadataRangeShapeCounters {
    exact: AtomicU64,
    star: AtomicU64,
    caret: AtomicU64,
    tilde: AtomicU64,
    comparator: AtomicU64,
    complex: AtomicU64,
    other: AtomicU64,
    unknown: AtomicU64,
}

impl MetadataRangeShapeCounters {
    fn record(&self, shape: MetadataRangeShape) {
        match shape {
            MetadataRangeShape::Exact => &self.exact,
            MetadataRangeShape::Star => &self.star,
            MetadataRangeShape::Caret => &self.caret,
            MetadataRangeShape::Tilde => &self.tilde,
            MetadataRangeShape::Comparator => &self.comparator,
            MetadataRangeShape::Complex => &self.complex,
            MetadataRangeShape::Other => &self.other,
            MetadataRangeShape::Unknown => &self.unknown,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "exact": self.exact.load(Ordering::Relaxed),
            "star": self.star.load(Ordering::Relaxed),
            "caret": self.caret.load(Ordering::Relaxed),
            "tilde": self.tilde.load(Ordering::Relaxed),
            "comparator": self.comparator.load(Ordering::Relaxed),
            "complex": self.complex.load(Ordering::Relaxed),
            "other": self.other.load(Ordering::Relaxed),
            "unknown": self.unknown.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Default)]
struct MetadataPackageRangeStats {
    calls: u64,
    exact_calls: u64,
    version_doc_eligible_exact_calls: u64,
    exact_versions: BTreeSet<String>,
}

impl MetadataPackageRangeStats {
    fn record(&mut self, context: &MetadataRequestContext) {
        self.calls = self.calls.saturating_add(1);
        if context.range_shape != MetadataRangeShape::Exact {
            return;
        }
        self.exact_calls = self.exact_calls.saturating_add(1);
        if context.version_doc_eligible {
            self.version_doc_eligible_exact_calls =
                self.version_doc_eligible_exact_calls.saturating_add(1);
        }
        if let Some(version) = context.range.as_deref().and_then(exact_pin_version) {
            self.exact_versions.insert(version);
        }
    }

    fn has_exact_and_non_exact(&self) -> bool {
        self.exact_calls > 0 && self.exact_calls < self.calls
    }

    fn exact_only(&self) -> bool {
        self.calls > 0 && self.exact_calls == self.calls
    }

    fn version_doc_eligible_exact_only(&self) -> bool {
        self.calls > 0 && self.version_doc_eligible_exact_calls == self.calls
    }
}

#[derive(Debug, Default)]
struct MetadataPackageRangeSummary {
    seen: u64,
    exact_only: u64,
    exact_only_single_version: u64,
    exact_only_multiple_versions: u64,
    mixed_exact_and_non_exact: u64,
    non_exact_only: u64,
    version_doc_eligible_exact_only: u64,
    version_doc_eligible_exact_only_single_version: u64,
    version_doc_eligible_exact_only_multiple_versions: u64,
}

impl MetadataPackageRangeSummary {
    fn record(&mut self, stats: &MetadataPackageRangeStats) {
        self.seen = self.seen.saturating_add(1);
        if stats.exact_only() {
            self.exact_only = self.exact_only.saturating_add(1);
            match stats.exact_versions.len() {
                0 | 1 => {
                    self.exact_only_single_version =
                        self.exact_only_single_version.saturating_add(1);
                }
                _ => {
                    self.exact_only_multiple_versions =
                        self.exact_only_multiple_versions.saturating_add(1);
                }
            }
        } else if stats.has_exact_and_non_exact() {
            self.mixed_exact_and_non_exact = self.mixed_exact_and_non_exact.saturating_add(1);
        } else {
            self.non_exact_only = self.non_exact_only.saturating_add(1);
        }

        if stats.version_doc_eligible_exact_only() {
            self.version_doc_eligible_exact_only =
                self.version_doc_eligible_exact_only.saturating_add(1);
            match stats.exact_versions.len() {
                0 | 1 => {
                    self.version_doc_eligible_exact_only_single_version = self
                        .version_doc_eligible_exact_only_single_version
                        .saturating_add(1);
                }
                _ => {
                    self.version_doc_eligible_exact_only_multiple_versions = self
                        .version_doc_eligible_exact_only_multiple_versions
                        .saturating_add(1);
                }
            }
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "seen": self.seen,
            "exact_only": self.exact_only,
            "exact_only_single_version": self.exact_only_single_version,
            "exact_only_multiple_versions": self.exact_only_multiple_versions,
            "mixed_exact_and_non_exact": self.mixed_exact_and_non_exact,
            "non_exact_only": self.non_exact_only,
            "version_doc_eligible_exact_only": self.version_doc_eligible_exact_only,
            "version_doc_eligible_exact_only_single_version": self.version_doc_eligible_exact_only_single_version,
            "version_doc_eligible_exact_only_multiple_versions": self.version_doc_eligible_exact_only_multiple_versions,
        })
    }
}

#[derive(Debug, Clone)]
struct ResolvedNode {
    request: ResolveRequest,
    version: String,
    info: Arc<lpm_resolver::CachedPackageInfo>,
    platform: Option<lpm_resolver::PlatformMeta>,
    reused_existing: bool,
}

#[derive(Debug)]
enum NodeResolution {
    Metadata {
        request: ResolveRequest,
        info: Arc<lpm_resolver::CachedPackageInfo>,
    },
}

#[derive(Debug, Clone)]
struct PackageDraft {
    package: InstallPackage,
    info: Arc<lpm_resolver::CachedPackageInfo>,
}

#[derive(Debug, Clone, Copy)]
struct MergeOutcome {
    inserted: bool,
    became_required: bool,
}

#[derive(Debug, Clone)]
struct PeerRequirement {
    target_name: String,
    range: lpm_resolver::NpmRange,
    optional: bool,
}

#[derive(Debug, Clone)]
struct AmbientPeerPlan {
    target_name: String,
    version: String,
}

#[derive(Debug)]
struct FetchOutcome {
    key: String,
    package_display: String,
    computed_sri: Option<String>,
    timings: Option<TaskTimings>,
    cached: bool,
}

#[derive(Debug, Default)]
struct InstallerSpikeStats {
    metadata_requests: u64,
    metadata_cache_hits: u64,
    root_requests: u64,
    dependency_requests_enqueued: u64,
    peer_requests_enqueued: u64,
    selected_nodes: u64,
    inserted_nodes: u64,
    duplicate_nodes: u64,
    reused_existing_versions: u64,
    inline_reused_edges: u64,
    inline_reuse_deferred_promotions: u64,
    skipped_optional: u64,
    platform_pre_skipped: u64,
    fetch_dispatched: u64,
}

#[derive(Debug, Clone)]
struct MetadataTraceRecord {
    context: MetadataRequestContext,
    timings: lpm_resolver::ExperimentalMetadataFetchTimings,
    queued_at_ms: u128,
    completed_at_ms: u128,
}

#[derive(Debug, Default)]
struct MetadataWaveStats {
    initial_fetches: u64,
    fetch_sum_ms: u64,
    fetch_max_ms: u64,
    completed_max_ms: u64,
    body_bytes: u64,
}

#[derive(Debug)]
struct MetadataStats {
    started_at: Instant,
    calls: AtomicU64,
    ready_hits: AtomicU64,
    initial_fetches: AtomicU64,
    queue_wait_sum_ms: AtomicU64,
    queue_wait_max_ms: AtomicU64,
    fetch_sum_ms: AtomicU64,
    fetch_max_ms: AtomicU64,
    raw_fetch_sum_ms: AtomicU64,
    raw_fetch_max_ms: AtomicU64,
    cache_read_sum_ms: AtomicU64,
    validator_read_sum_ms: AtomicU64,
    http_sum_ms: AtomicU64,
    body_read_sum_ms: AtomicU64,
    json_decode_sum_ms: AtomicU64,
    cache_after_304_sum_ms: AtomicU64,
    cache_write_dispatch_sum_ms: AtomicU64,
    cache_info_parse_sum_ms: AtomicU64,
    policy_release_time_sum_ms: AtomicU64,
    policy_full_metadata_sum_ms: AtomicU64,
    body_bytes_sum: AtomicU64,
    version_count_sum: AtomicU64,
    registry_cache_hits: AtomicU64,
    registry_not_modified: AtomicU64,
    range_shape_calls: MetadataRangeShapeCounters,
    range_shape_initial_fetches: MetadataRangeShapeCounters,
    version_doc_eligible_calls: AtomicU64,
    version_doc_eligible_initial_fetches: AtomicU64,
    version_doc_attempts: AtomicU64,
    version_doc_hits: AtomicU64,
    version_doc_fallbacks: AtomicU64,
    range_shapes_by_package: std::sync::Mutex<BTreeMap<String, MetadataPackageRangeStats>>,
    route_npm_direct: AtomicU64,
    route_npm_direct_version_doc: AtomicU64,
    route_lpm_worker: AtomicU64,
    route_custom: AtomicU64,
    route_lpm: AtomicU64,
    waves_by_depth: std::sync::Mutex<BTreeMap<u16, MetadataWaveStats>>,
    slow_metadata_by_total: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_completed_at: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_raw_fetch: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_cache_read: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_http: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_body_read: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_json_decode: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_cache_write: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_cache_info_parse: std::sync::Mutex<Vec<MetadataTraceRecord>>,
    slow_metadata_by_policy_release_time: std::sync::Mutex<Vec<MetadataTraceRecord>>,
}

impl MetadataStats {
    fn new(started_at: Instant) -> Self {
        Self {
            started_at,
            calls: AtomicU64::new(0),
            ready_hits: AtomicU64::new(0),
            initial_fetches: AtomicU64::new(0),
            queue_wait_sum_ms: AtomicU64::new(0),
            queue_wait_max_ms: AtomicU64::new(0),
            fetch_sum_ms: AtomicU64::new(0),
            fetch_max_ms: AtomicU64::new(0),
            raw_fetch_sum_ms: AtomicU64::new(0),
            raw_fetch_max_ms: AtomicU64::new(0),
            cache_read_sum_ms: AtomicU64::new(0),
            validator_read_sum_ms: AtomicU64::new(0),
            http_sum_ms: AtomicU64::new(0),
            body_read_sum_ms: AtomicU64::new(0),
            json_decode_sum_ms: AtomicU64::new(0),
            cache_after_304_sum_ms: AtomicU64::new(0),
            cache_write_dispatch_sum_ms: AtomicU64::new(0),
            cache_info_parse_sum_ms: AtomicU64::new(0),
            policy_release_time_sum_ms: AtomicU64::new(0),
            policy_full_metadata_sum_ms: AtomicU64::new(0),
            body_bytes_sum: AtomicU64::new(0),
            version_count_sum: AtomicU64::new(0),
            registry_cache_hits: AtomicU64::new(0),
            registry_not_modified: AtomicU64::new(0),
            range_shape_calls: MetadataRangeShapeCounters::default(),
            range_shape_initial_fetches: MetadataRangeShapeCounters::default(),
            version_doc_eligible_calls: AtomicU64::new(0),
            version_doc_eligible_initial_fetches: AtomicU64::new(0),
            version_doc_attempts: AtomicU64::new(0),
            version_doc_hits: AtomicU64::new(0),
            version_doc_fallbacks: AtomicU64::new(0),
            range_shapes_by_package: std::sync::Mutex::new(BTreeMap::new()),
            route_npm_direct: AtomicU64::new(0),
            route_npm_direct_version_doc: AtomicU64::new(0),
            route_lpm_worker: AtomicU64::new(0),
            route_custom: AtomicU64::new(0),
            route_lpm: AtomicU64::new(0),
            waves_by_depth: std::sync::Mutex::new(BTreeMap::new()),
            slow_metadata_by_total: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_completed_at: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_raw_fetch: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_cache_read: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_http: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_body_read: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_json_decode: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_cache_write: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_cache_info_parse: std::sync::Mutex::new(Vec::new()),
            slow_metadata_by_policy_release_time: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn elapsed_ms(&self) -> u128 {
        self.started_at.elapsed().as_millis()
    }

    fn record_queue_wait(&self, ms: u128) {
        let ms = u128_to_u64_saturating(ms);
        self.queue_wait_sum_ms.fetch_add(ms, Ordering::Relaxed);
        atomic_max(&self.queue_wait_max_ms, ms);
    }

    fn record_fetch(&self, ms: u128) {
        let ms = u128_to_u64_saturating(ms);
        self.fetch_sum_ms.fetch_add(ms, Ordering::Relaxed);
        atomic_max(&self.fetch_max_ms, ms);
    }

    fn record_range_call(&self, context: &MetadataRequestContext) {
        self.range_shape_calls.record(context.range_shape);
        if context.version_doc_eligible {
            self.version_doc_eligible_calls
                .fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut packages) = self.range_shapes_by_package.lock() {
            packages
                .entry(context.package.clone())
                .or_default()
                .record(context);
        }
    }

    fn record_range_initial_fetch(&self, context: &MetadataRequestContext) {
        self.range_shape_initial_fetches.record(context.range_shape);
        if context.version_doc_eligible {
            self.version_doc_eligible_initial_fetches
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_version_doc_attempt(&self) {
        self.version_doc_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_version_doc_hit(&self) {
        self.version_doc_hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_version_doc_fallback(&self) {
        self.version_doc_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    fn record_detail(
        &self,
        context: MetadataRequestContext,
        timings: lpm_resolver::ExperimentalMetadataFetchTimings,
        queued_at_ms: u128,
        completed_at_ms: u128,
        trace: bool,
    ) {
        self.raw_fetch_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.raw_fetch_ms),
            Ordering::Relaxed,
        );
        atomic_max(
            &self.raw_fetch_max_ms,
            u128_to_u64_saturating(timings.raw_fetch_ms),
        );
        self.cache_read_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.cache_read_ms),
            Ordering::Relaxed,
        );
        self.validator_read_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.validator_read_ms),
            Ordering::Relaxed,
        );
        self.http_sum_ms
            .fetch_add(u128_to_u64_saturating(timings.http_ms), Ordering::Relaxed);
        self.body_read_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.body_read_ms),
            Ordering::Relaxed,
        );
        self.json_decode_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.json_decode_ms),
            Ordering::Relaxed,
        );
        self.cache_after_304_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.cache_after_304_ms),
            Ordering::Relaxed,
        );
        self.cache_write_dispatch_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.cache_write_dispatch_ms),
            Ordering::Relaxed,
        );
        self.cache_info_parse_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.cache_info_parse_ms),
            Ordering::Relaxed,
        );
        self.policy_release_time_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.policy_release_time_ms),
            Ordering::Relaxed,
        );
        self.policy_full_metadata_sum_ms.fetch_add(
            u128_to_u64_saturating(timings.policy_full_metadata_ms),
            Ordering::Relaxed,
        );
        self.body_bytes_sum
            .fetch_add(timings.body_bytes, Ordering::Relaxed);
        self.version_count_sum
            .fetch_add(timings.version_count, Ordering::Relaxed);
        if timings.cache_hit {
            self.registry_cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        if timings.not_modified {
            self.registry_not_modified.fetch_add(1, Ordering::Relaxed);
        }
        match timings.route {
            "npm_direct" => self.route_npm_direct.fetch_add(1, Ordering::Relaxed),
            "npm_direct_version_doc" => self
                .route_npm_direct_version_doc
                .fetch_add(1, Ordering::Relaxed),
            "lpm_worker" => self.route_lpm_worker.fetch_add(1, Ordering::Relaxed),
            "custom" => self.route_custom.fetch_add(1, Ordering::Relaxed),
            "lpm" => self.route_lpm.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };

        if trace {
            self.record_wave(&context, &timings, completed_at_ms);
            let record = MetadataTraceRecord {
                context,
                timings,
                queued_at_ms,
                completed_at_ms,
            };
            Self::record_slow_metadata(&self.slow_metadata_by_total, &record, |entry| {
                entry.timings.total_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_completed_at, &record, |entry| {
                entry.completed_at_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_raw_fetch, &record, |entry| {
                entry.timings.raw_fetch_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_cache_read, &record, |entry| {
                entry.timings.cache_read_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_http, &record, |entry| {
                entry.timings.http_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_body_read, &record, |entry| {
                entry.timings.body_read_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_json_decode, &record, |entry| {
                entry.timings.json_decode_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_cache_write, &record, |entry| {
                entry.timings.cache_write_dispatch_ms
            });
            Self::record_slow_metadata(&self.slow_metadata_by_cache_info_parse, &record, |entry| {
                entry.timings.cache_info_parse_ms
            });
            Self::record_slow_metadata(
                &self.slow_metadata_by_policy_release_time,
                &record,
                |entry| entry.timings.policy_release_time_ms,
            );
        }
    }

    fn record_wave(
        &self,
        context: &MetadataRequestContext,
        timings: &lpm_resolver::ExperimentalMetadataFetchTimings,
        completed_at_ms: u128,
    ) {
        let Ok(mut waves) = self.waves_by_depth.lock() else {
            return;
        };
        let wave = waves.entry(context.depth).or_default();
        wave.initial_fetches = wave.initial_fetches.saturating_add(1);
        wave.fetch_sum_ms = wave
            .fetch_sum_ms
            .saturating_add(u128_to_u64_saturating(timings.total_ms));
        wave.fetch_max_ms = wave
            .fetch_max_ms
            .max(u128_to_u64_saturating(timings.total_ms));
        wave.completed_max_ms = wave
            .completed_max_ms
            .max(u128_to_u64_saturating(completed_at_ms));
        wave.body_bytes = wave.body_bytes.saturating_add(timings.body_bytes);
    }

    fn record_slow_metadata(
        bucket: &std::sync::Mutex<Vec<MetadataTraceRecord>>,
        record: &MetadataTraceRecord,
        rank_ms: impl Fn(&MetadataTraceRecord) -> u128 + Copy,
    ) {
        if rank_ms(record) == 0 {
            return;
        }
        let Ok(mut bucket) = bucket.lock() else {
            return;
        };
        bucket.push(record.clone());
        bucket.sort_unstable_by(|a, b| {
            rank_ms(b)
                .cmp(&rank_ms(a))
                .then_with(|| a.timings.package.cmp(&b.timings.package))
        });
        bucket.truncate(10);
    }

    fn to_json(&self, trace: bool) -> serde_json::Value {
        let calls = self.calls.load(Ordering::Relaxed);
        let ready_hits = self.ready_hits.load(Ordering::Relaxed);
        let initial_fetches = self.initial_fetches.load(Ordering::Relaxed);
        let mut json = serde_json::json!({
            "calls": calls,
            "ready_hits": ready_hits,
            "initial_fetches": initial_fetches,
            "shared_waiters": calls.saturating_sub(ready_hits).saturating_sub(initial_fetches),
            "queue_wait": {
                "sum_ms": self.queue_wait_sum_ms.load(Ordering::Relaxed),
                "max_ms": self.queue_wait_max_ms.load(Ordering::Relaxed),
            },
            "fetch": {
                "sum_ms": self.fetch_sum_ms.load(Ordering::Relaxed),
                "max_ms": self.fetch_max_ms.load(Ordering::Relaxed),
            },
            "attribution": {
                "raw_fetch_sum_ms": self.raw_fetch_sum_ms.load(Ordering::Relaxed),
                "raw_fetch_max_ms": self.raw_fetch_max_ms.load(Ordering::Relaxed),
                "cache_read_sum_ms": self.cache_read_sum_ms.load(Ordering::Relaxed),
                "validator_read_sum_ms": self.validator_read_sum_ms.load(Ordering::Relaxed),
                "http_sum_ms": self.http_sum_ms.load(Ordering::Relaxed),
                "body_read_sum_ms": self.body_read_sum_ms.load(Ordering::Relaxed),
                "json_decode_sum_ms": self.json_decode_sum_ms.load(Ordering::Relaxed),
                "cache_after_304_sum_ms": self.cache_after_304_sum_ms.load(Ordering::Relaxed),
                "cache_write_dispatch_sum_ms": self.cache_write_dispatch_sum_ms.load(Ordering::Relaxed),
                "cache_info_parse_sum_ms": self.cache_info_parse_sum_ms.load(Ordering::Relaxed),
                "policy_release_time_sum_ms": self.policy_release_time_sum_ms.load(Ordering::Relaxed),
                "policy_full_metadata_sum_ms": self.policy_full_metadata_sum_ms.load(Ordering::Relaxed),
                "body_bytes_sum": self.body_bytes_sum.load(Ordering::Relaxed),
                "version_count_sum": self.version_count_sum.load(Ordering::Relaxed),
                "registry_cache_hit_count": self.registry_cache_hits.load(Ordering::Relaxed),
                "registry_not_modified_count": self.registry_not_modified.load(Ordering::Relaxed),
                "range_shapes": {
                    "calls": self.range_shape_calls.to_json(),
                    "package_first_fetches": self.range_shape_initial_fetches.to_json(),
                    "version_doc_eligible_calls": self.version_doc_eligible_calls.load(Ordering::Relaxed),
                    "version_doc_eligible_package_first_fetches": self.version_doc_eligible_initial_fetches.load(Ordering::Relaxed),
                    "packages": self.range_shape_package_summary_json(),
                },
                "version_docs": {
                    "attempts": self.version_doc_attempts.load(Ordering::Relaxed),
                    "hits": self.version_doc_hits.load(Ordering::Relaxed),
                    "fallbacks": self.version_doc_fallbacks.load(Ordering::Relaxed),
                },
                "routes": {
                    "npm_direct": self.route_npm_direct.load(Ordering::Relaxed),
                    "npm_direct_version_doc": self.route_npm_direct_version_doc.load(Ordering::Relaxed),
                    "lpm_worker": self.route_lpm_worker.load(Ordering::Relaxed),
                    "custom": self.route_custom.load(Ordering::Relaxed),
                    "lpm": self.route_lpm.load(Ordering::Relaxed),
                },
            },
        });
        if trace {
            json["waves_by_depth"] = Self::waves_json(&self.waves_by_depth);
            json["slow_metadata"] = serde_json::json!({
                "by_total": Self::slow_metadata_json(&self.slow_metadata_by_total),
                "by_completed_at": Self::slow_metadata_json(&self.slow_metadata_by_completed_at),
                "by_raw_fetch": Self::slow_metadata_json(&self.slow_metadata_by_raw_fetch),
                "by_cache_read": Self::slow_metadata_json(&self.slow_metadata_by_cache_read),
                "by_http": Self::slow_metadata_json(&self.slow_metadata_by_http),
                "by_body_read": Self::slow_metadata_json(&self.slow_metadata_by_body_read),
                "by_json_decode": Self::slow_metadata_json(&self.slow_metadata_by_json_decode),
                "by_cache_write_dispatch": Self::slow_metadata_json(&self.slow_metadata_by_cache_write),
                "by_cache_info_parse": Self::slow_metadata_json(&self.slow_metadata_by_cache_info_parse),
                "by_policy_release_time": Self::slow_metadata_json(&self.slow_metadata_by_policy_release_time),
            });
        }
        json
    }

    fn waves_json(
        bucket: &std::sync::Mutex<BTreeMap<u16, MetadataWaveStats>>,
    ) -> serde_json::Value {
        let Ok(bucket) = bucket.lock() else {
            return serde_json::Value::Array(Vec::new());
        };
        serde_json::Value::Array(
            bucket
                .iter()
                .map(|(depth, stats)| {
                    serde_json::json!({
                        "depth": depth,
                        "initial_fetches": stats.initial_fetches,
                        "fetch_sum_ms": stats.fetch_sum_ms,
                        "fetch_max_ms": stats.fetch_max_ms,
                        "completed_max_ms": stats.completed_max_ms,
                        "body_bytes": stats.body_bytes,
                    })
                })
                .collect(),
        )
    }

    fn range_shape_package_summary_json(&self) -> serde_json::Value {
        let Ok(packages) = self.range_shapes_by_package.lock() else {
            return serde_json::Value::Object(serde_json::Map::new());
        };
        let mut summary = MetadataPackageRangeSummary::default();
        for stats in packages.values() {
            summary.record(stats);
        }
        summary.to_json()
    }

    fn slow_metadata_json(
        bucket: &std::sync::Mutex<Vec<MetadataTraceRecord>>,
    ) -> serde_json::Value {
        let Ok(bucket) = bucket.lock() else {
            return serde_json::Value::Array(Vec::new());
        };
        serde_json::Value::Array(
            bucket
                .iter()
                .map(|entry| {
                    let timings = &entry.timings;
                    serde_json::json!({
                        "package": timings.package,
                        "route": timings.route,
                        "total_ms": timings.total_ms,
                        "raw_fetch_ms": timings.raw_fetch_ms,
                        "cache_read_ms": timings.cache_read_ms,
                        "validator_read_ms": timings.validator_read_ms,
                        "http_ms": timings.http_ms,
                        "body_read_ms": timings.body_read_ms,
                        "json_decode_ms": timings.json_decode_ms,
                        "cache_after_304_ms": timings.cache_after_304_ms,
                        "cache_write_dispatch_ms": timings.cache_write_dispatch_ms,
                        "cache_info_parse_ms": timings.cache_info_parse_ms,
                        "policy_release_time_ms": timings.policy_release_time_ms,
                        "policy_full_metadata_ms": timings.policy_full_metadata_ms,
                        "body_bytes": timings.body_bytes,
                        "version_count": timings.version_count,
                        "cache_hit": timings.cache_hit,
                        "not_modified": timings.not_modified,
                        "queued_at_ms": entry.queued_at_ms,
                        "completed_at_ms": entry.completed_at_ms,
                        "depth": entry.context.depth,
                        "root_ancestor": entry.context.root_ancestor,
                        "range": entry.context.range,
                        "range_shape": entry.context.range_shape.as_str(),
                        "version_doc_eligible": entry.context.version_doc_eligible,
                        "parent": entry.context.parent,
                        "optional": entry.context.optional,
                        "direct": entry.context.direct,
                        "root": entry.context.root,
                        "reason": entry.context.reason,
                    })
                })
                .collect(),
        )
    }
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    value.min(u128::from(u64::MAX)) as u64
}

fn atomic_max(cell: &AtomicU64, value: u64) {
    let mut current = cell.load(Ordering::Relaxed);
    while value > current {
        match cell.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => current = next,
        }
    }
}

#[derive(Debug, Default)]
struct InstallerSpikeStageTimings {
    resolve_worklist_ms: u128,
    peer_drain_ms: u128,
    package_graph_ms: u128,
    parity_ms: u128,
    link_targets_ms: u128,
    v2_targets_ms: u128,
    v2_prepare_ms: u128,
    v2_index_ms: u128,
    pre_fetch_overlap_ms: u128,
    fetch_join_ms: u128,
    link_task_await_ms: u128,
    link_finalize_ms: u128,
}

impl InstallerSpikeStageTimings {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "resolve_worklist_ms": self.resolve_worklist_ms,
            "peer_drain_ms": self.peer_drain_ms,
            "package_graph_ms": self.package_graph_ms,
            "parity_ms": self.parity_ms,
            "link_targets_ms": self.link_targets_ms,
            "v2_targets_ms": self.v2_targets_ms,
            "v2_prepare_ms": self.v2_prepare_ms,
            "v2_index_ms": self.v2_index_ms,
            "pre_fetch_overlap_ms": self.pre_fetch_overlap_ms,
            "fetch_join_ms": self.fetch_join_ms,
            "link_task_await_ms": self.link_task_await_ms,
            "link_finalize_ms": self.link_finalize_ms,
        })
    }
}

struct LinkOutcomeWithTimings {
    result: LinkResult,
    task_await_ms: u128,
    finalize_ms: u128,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PackageFingerprint {
    dependencies: Vec<(String, String)>,
    aliases: Vec<(String, String)>,
    peers: Vec<(String, String)>,
    root_link_names: Vec<String>,
    is_direct: bool,
    optional: bool,
}

#[derive(Debug, Clone)]
struct PackageFingerprintMismatch {
    package: String,
    candidate: PackageFingerprint,
    baseline: PackageFingerprint,
}

#[derive(Debug, Clone)]
struct InstallerSpikeParity {
    enabled: bool,
    matches: bool,
    baseline: &'static str,
    candidate_count: usize,
    baseline_count: usize,
    count_delta: isize,
    extra_count: usize,
    missing_count: usize,
    fingerprint_mismatch_count: usize,
    extra: Vec<String>,
    missing: Vec<String>,
    fingerprint_mismatches: Vec<PackageFingerprintMismatch>,
}

impl InstallerSpikeParity {
    fn disabled() -> Self {
        Self {
            enabled: false,
            matches: true,
            baseline: "disabled",
            candidate_count: 0,
            baseline_count: 0,
            count_delta: 0,
            extra_count: 0,
            missing_count: 0,
            fingerprint_mismatch_count: 0,
            extra: Vec::new(),
            missing: Vec::new(),
            fingerprint_mismatches: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "matches": self.matches,
            "baseline": self.baseline,
            "candidate_count": self.candidate_count,
            "baseline_count": self.baseline_count,
            "count_delta": self.count_delta,
            "extra_count": self.extra_count,
            "missing_count": self.missing_count,
            "fingerprint_mismatch_count": self.fingerprint_mismatch_count,
            "extra": &self.extra,
            "missing": &self.missing,
            "fingerprint_mismatches": self.fingerprint_mismatches.iter().map(|mismatch| {
                serde_json::json!({
                    "package": &mismatch.package,
                    "candidate": package_fingerprint_json(&mismatch.candidate),
                    "baseline": package_fingerprint_json(&mismatch.baseline),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    client: Arc<RegistryClient>,
    project_dir: &Path,
    deps: &HashMap<String, String>,
    pkg: &lpm_workspace::PackageJson,
    route_table: RouteTable,
    json_output: bool,
    start: Instant,
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    lpm_root: &lpm_common::LpmRoot,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    compatibility_bin_names: &[String],
    override_set: OverrideSet,
    resolver_policy: lpm_resolver::ResolverPolicy,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
    workspace_member_deps: &[WorkspaceMemberLink],
    all_workspace_members: &[WorkspaceMemberLink],
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    current_patches: &HashMap<String, PatchedDependencyEntry>,
    prior_patch_state: &Option<patch_state::PatchState>,
    current_patch_fingerprint: &str,
) -> Result<(), LpmError> {
    if !json_output {
        output::info("using experimental installer spike path");
    }

    let fetch_concurrency = installer_spike_concurrency();
    let metadata_concurrency = installer_spike_metadata_concurrency();
    let graph_source = InstallerSpikeGraphSource::from_env();
    let timing_detail_mode = TimingDetailMode::from_env();
    let fetch_queue = Arc::new(Semaphore::new(fetch_concurrency));
    let fetch_extract_limiter = configured_fetch_extract_limiter(store_v2_handle.is_some());
    let metadata_queue = Arc::new(Semaphore::new(metadata_concurrency));
    let metadata_caches = MetadataCaches::new();
    let store = PackageStore::from_root(lpm_root);
    let patch_fingerprints = compute_patch_fingerprints(current_patches, project_dir)?;
    let gate_stats = Arc::new(GateStats::default());

    let setup_ms = start.elapsed().as_millis();
    let resolve_start = Instant::now();
    let metadata_stats = Arc::new(MetadataStats::new(resolve_start));
    let mut stats = InstallerSpikeStats::default();
    let mut stage_timings = InstallerSpikeStageTimings::default();
    let mut fetch_handles: HashMap<String, FetchHandle> = HashMap::new();
    let mut install_packages = match graph_source {
        InstallerSpikeGraphSource::ResolveWorklist => {
            let mut pending: FuturesUnordered<ResolveFuture> = FuturesUnordered::new();
            let mut packages: HashMap<PackageIdentity, PackageDraft> =
                HashMap::with_capacity(deps.len().saturating_mul(4).max(32));
            let root_requests = root_resolve_requests(deps);
            stats.root_requests = root_requests.len() as u64;

            for request in root_requests {
                pending.push(Box::pin(resolve_node(
                    request,
                    Arc::clone(&client),
                    route_table.clone(),
                    metadata_caches.clone(),
                    Arc::clone(&metadata_queue),
                    Arc::clone(&metadata_stats),
                    resolver_policy.clone(),
                )));
            }

            while let Some(result) = pending.next().await {
                match result? {
                    NodeResolution::Metadata { request, info } => {
                        let Some(node) = select_or_reuse_node(
                            request,
                            Arc::clone(&info),
                            &mut packages,
                            &override_set,
                            &resolver_policy,
                        )?
                        else {
                            stats.skipped_optional += 1;
                            continue;
                        };
                        stats.selected_nodes += 1;
                        if node.reused_existing {
                            stats.reused_existing_versions += 1;
                        }
                        let identity = (node.request.target_name.clone(), node.version.clone());
                        let merge = merge_node_into_packages(
                            &mut packages,
                            &node,
                            &route_table,
                            &store,
                            project_dir,
                        );
                        if merge.became_required {
                            let draft = packages.get(&identity).ok_or_else(|| {
                                LpmError::Registry(format!(
                                    "experimental installer lost package {}@{} during required promotion",
                                    identity.0, identity.1
                                ))
                            })?;
                            ensure_package_can_materialize(&draft.package)?;
                            mark_required_closure(&mut packages, &identity);
                        }

                        if let Some(parent) = node.request.parent.as_ref() {
                            attach_dependency_edge(&mut packages, parent, &node)?;
                        }

                        if merge.inserted {
                            stats.inserted_nodes += 1;
                            let package =
                                packages.get(&identity).map(|draft| draft.package.clone()).ok_or_else(
                                    || {
                                        LpmError::Registry(format!(
                                            "experimental installer lost package {}@{} during insertion",
                                            identity.0, identity.1
                                        ))
                                    },
                                )?;
                            if package_should_materialize(&package)? {
                                maybe_spawn_fetch(
                                    package,
                                    &store,
                                    store_v2_handle.clone(),
                                    project_dir,
                                    Arc::clone(&client),
                                    route_table.clone(),
                                    Arc::clone(&fetch_queue),
                                    Arc::clone(&gate_stats),
                                    force,
                                    fetch_extract_limiter.clone(),
                                    &mut fetch_handles,
                                    &mut stats,
                                );
                            } else {
                                stats.platform_pre_skipped += 1;
                            }
                            enqueue_dependencies(
                                &node,
                                &mut packages,
                                &mut pending,
                                &client,
                                &route_table,
                                &metadata_caches,
                                &metadata_queue,
                                &metadata_stats,
                                &resolver_policy,
                                include_optional_dependencies,
                                &mut stats,
                            )?;
                        } else {
                            stats.duplicate_nodes += 1;
                        }
                    }
                }
            }
            stage_timings.resolve_worklist_ms = resolve_start.elapsed().as_millis();

            let peer_drain_start = Instant::now();
            drain_ambient_peer_installs(
                &mut packages,
                &client,
                &route_table,
                &metadata_caches,
                &metadata_queue,
                &fetch_queue,
                &metadata_stats,
                &resolver_policy,
                include_optional_dependencies,
                auto_install_peers,
                &override_set,
                &store,
                project_dir,
                &mut fetch_handles,
                &mut stats,
                store_v2_handle.clone(),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
            )
            .await?;
            stage_timings.peer_drain_ms = peer_drain_start.elapsed().as_millis();
            stats.metadata_requests = metadata_caches.request_count() as u64;
            stats.metadata_cache_hits = metadata_stats.ready_hits.load(Ordering::Relaxed);

            let package_graph_start = Instant::now();
            normalize_draft_optional_reachability(&mut packages);
            spawn_missing_fetches_for_drafts(
                &packages,
                &store,
                store_v2_handle.clone(),
                project_dir,
                &client,
                &route_table,
                &fetch_queue,
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                &mut fetch_handles,
                &mut stats,
            )?;
            attach_peer_edges_to_drafts(&mut packages);
            let mut install_packages: Vec<InstallPackage> =
                packages.into_values().map(|draft| draft.package).collect();
            install_packages
                .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
            dedupe_install_packages_by_identity(&mut install_packages);
            stage_timings.package_graph_ms = package_graph_start.elapsed().as_millis();
            merge_pre_resolved_packages(
                &mut install_packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            spawn_fetches_for_packages(
                pre_resolved_install_pkgs,
                &store,
                store_v2_handle.clone(),
                project_dir,
                &client,
                &route_table,
                &fetch_queue,
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                &mut fetch_handles,
                &mut stats,
            )?;
            install_packages
        }
        InstallerSpikeGraphSource::Lockfile => {
            let package_graph_start = Instant::now();
            let mut install_packages = load_lockfile_graph_packages(
                project_dir,
                deps,
                catalog_resolutions,
                client.as_ref(),
                gate_stats.as_ref(),
                auto_install_peers,
            )?;
            dedupe_install_packages_by_identity(&mut install_packages);
            install_packages
                .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
            stage_timings.package_graph_ms = package_graph_start.elapsed().as_millis();
            stage_timings.resolve_worklist_ms = resolve_start.elapsed().as_millis();
            stats.root_requests = deps.len() as u64;
            stats.selected_nodes = install_packages.len() as u64;
            stats.inserted_nodes = install_packages.len() as u64;
            merge_pre_resolved_packages(
                &mut install_packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            install_packages
        }
        InstallerSpikeGraphSource::Invalid => {
            return Err(LpmError::Registry(
                "invalid experimental installer spike graph".to_string(),
            ));
        }
    };
    let mut platform_skipped = filter_platform_packages(&mut install_packages)?;
    if graph_source == InstallerSpikeGraphSource::Lockfile {
        let fetch_packages = lockfile_fetch_schedule(&install_packages);
        spawn_fetches_for_packages(
            &fetch_packages,
            &store,
            store_v2_handle.clone(),
            project_dir,
            &client,
            &route_table,
            &fetch_queue,
            Arc::clone(&gate_stats),
            force,
            fetch_extract_limiter.clone(),
            &mut fetch_handles,
            &mut stats,
        )?;
        platform_skipped += stats.platform_pre_skipped as usize;
    }
    let resolve_ms = resolve_start.elapsed().as_millis();

    let pre_fetch_start = Instant::now();
    let parity_start = Instant::now();
    let parity = compute_parity_if_requested(
        Arc::clone(&client),
        deps,
        override_set,
        route_table.clone(),
        resolver_policy,
        auto_install_peers,
        include_optional_dependencies,
        all_workspace_members,
        catalog_resolutions,
        pre_resolved_install_pkgs,
        pre_resolved_source_deps,
        project_dir,
        &install_packages,
        json_output,
    )
    .await?;
    stage_timings.parity_ms = parity_start.elapsed().as_millis();

    let link_targets_start = Instant::now();
    let link_targets = build_experimental_link_targets(
        project_dir,
        &store,
        &install_packages,
        &patch_fingerprints,
    )?;
    stage_timings.link_targets_ms = link_targets_start.elapsed().as_millis();
    let v2_event_plan = match store_v2_handle.as_ref() {
        Some(store_v2) => {
            populate_v2_local_source_objects(&link_targets, store_v2)?;
            let v2_targets_start = Instant::now();
            let v2_targets = build_v2_targets(&install_packages, &link_targets)?;
            stage_timings.v2_targets_ms = v2_targets_start.elapsed().as_millis();
            let v2_prepare_start = Instant::now();
            let plan =
                lpm_linker::v2::link_v2_prepare_with_authoritative_peer_context_and_compatibility_bin_names(
                    project_dir,
                    v2_targets.clone(),
                    store_v2,
                    linker_mode,
                    compatibility_bin_names,
                )?;
            stage_timings.v2_prepare_ms = v2_prepare_start.elapsed().as_millis();
            let v2_index_start = Instant::now();
            let target_by_key: HashMap<String, lpm_linker::v2::V2Target> = install_packages
                .iter()
                .zip(v2_targets)
                .map(|(package, target)| (install_pkg_key(package), target))
                .collect();
            stage_timings.v2_index_ms = v2_index_start.elapsed().as_millis();
            Some((Arc::new(plan), target_by_key))
        }
        None => None,
    };
    stage_timings.pre_fetch_overlap_ms = pre_fetch_start.elapsed().as_millis();

    let fetch_start = Instant::now();
    let mut fetch_breakdown = FetchBreakdown::default();
    let mut slow_package_timings = SlowPackageTimings::default();
    let mut downloaded = 0usize;
    let mut cached = 0usize;
    let mut fetch_join_set: FuturesUnordered<FetchHandle> = fetch_handles.into_values().collect();
    let v2_link_task_semaphore = Arc::new(Semaphore::new(v2_link_task_concurrency(
        install_packages.len(),
    )));
    let mut v2_link_handles: Vec<V2LinkHandle> = Vec::new();
    while let Some(handle_result) = fetch_join_set.next().await {
        let outcome = handle_result
            .map_err(|e| LpmError::Registry(format!("experimental fetch task panicked: {e}")))??;
        if outcome.cached {
            cached += 1;
        } else {
            downloaded += 1;
        }
        if let Some(timings) = outcome.timings {
            if timing_detail_mode.trace() {
                slow_package_timings.record_fetch(&outcome.package_display, timings);
            }
            fetch_breakdown.record(timings);
        }
        if let Some(computed_sri) = outcome.computed_sri {
            let mut parts = outcome.key.split('\0');
            let name = parts.next().unwrap_or_default();
            let version = parts.next().unwrap_or_default();
            if let Some(package) = install_packages
                .iter_mut()
                .find(|package| package.name == name && package.version == version)
            {
                package.integrity = Some(computed_sri);
            }
        }
        if let (Some((plan, target_by_key)), Some(store_v2)) =
            (v2_event_plan.as_ref(), store_v2_handle.as_ref())
            && let Some(target) = target_by_key.get(&outcome.key).cloned()
        {
            v2_link_handles.push(spawn_v2_link_task(
                Arc::clone(plan),
                target,
                Arc::clone(store_v2),
                Arc::clone(&v2_link_task_semaphore),
            ));
        }
    }
    let fetch_ms = fetch_start.elapsed().as_millis();
    stage_timings.fetch_join_ms = fetch_ms;

    let link_start = Instant::now();
    let link_outcome = if let (Some((plan, _)), Some(store_v2)) =
        (v2_event_plan.as_ref(), store_v2_handle.as_deref())
    {
        finish_v2_event_driven_link(
            project_dir,
            plan,
            store_v2,
            v2_link_handles,
            pkg.name.as_deref(),
            timing_detail_mode,
            &mut slow_package_timings,
        )
        .await?
    } else {
        let result = link_experimental_targets(
            project_dir,
            store_v2_handle.as_deref(),
            &install_packages,
            &link_targets,
            linker_mode,
            force,
            pkg.name.as_deref(),
            compatibility_bin_names,
        )?;
        LinkOutcomeWithTimings {
            result,
            task_await_ms: 0,
            finalize_ms: link_start.elapsed().as_millis(),
        }
    };
    stage_timings.link_task_await_ms = link_outcome.task_await_ms;
    stage_timings.link_finalize_ms = link_outcome.finalize_ms;
    let link_result = link_outcome.result;
    let workspace_links_created = link_workspace_members(project_dir, workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }
    let applied_patches = apply_patches_for_install(
        current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;
    persist_patch_state(
        project_dir,
        current_patches,
        prior_patch_state,
        &applied_patches,
    );
    let link_ms = link_start.elapsed().as_millis();
    let total_ms = start.elapsed().as_millis();

    if json_output {
        let package_json: Vec<serde_json::Value> = install_packages
            .iter()
            .map(|package| {
                serde_json::json!({
                    "name": package.name,
                    "version": package.version,
                    "source": package.source,
                    "direct": package.is_direct,
                })
            })
            .collect();
        let waterfall_json = serde_json::json!({
            "setup_ms": setup_ms,
            "resolve_ms": resolve_ms,
            "pre_fetch_ms": stage_timings.pre_fetch_overlap_ms,
            "fetch_ms": fetch_ms,
            "pre_link_ms": 0u128,
            "link_ms": link_ms,
            "link_await_ms": stage_timings.link_task_await_ms,
            "link_finalize_ms": stage_timings.link_finalize_ms,
            "tail_ms": total_ms.saturating_sub(setup_ms.saturating_add(resolve_ms).saturating_add(stage_timings.pre_fetch_overlap_ms).saturating_add(fetch_ms).saturating_add(link_ms)),
            "total_ms": total_ms,
        });
        let mut experimental_json = serde_json::json!({
            "concurrency": fetch_concurrency,
            "metadata_concurrency": metadata_concurrency,
            "graph_source": graph_source.as_str(),
            "metadata_requests": stats.metadata_requests,
            "metadata_cache_hits": stats.metadata_cache_hits,
            "metadata": metadata_stats.to_json(TimingDetailMode::from_env().trace()),
            "root_requests": stats.root_requests,
            "dependency_requests_enqueued": stats.dependency_requests_enqueued,
            "peer_requests_enqueued": stats.peer_requests_enqueued,
            "selected_nodes": stats.selected_nodes,
            "inserted_nodes": stats.inserted_nodes,
            "duplicate_nodes": stats.duplicate_nodes,
            "reused_existing_versions": stats.reused_existing_versions,
            "inline_reused_edges": stats.inline_reused_edges,
            "inline_reuse_deferred_promotions": stats.inline_reuse_deferred_promotions,
            "skipped_optional": stats.skipped_optional,
            "platform_pre_skipped": stats.platform_pre_skipped,
            "fetch_dispatched": stats.fetch_dispatched,
            "platform_skipped": platform_skipped,
            "stages": stage_timings.to_json(),
            "parity": parity.to_json(),
            "tarball_url_gate": gate_stats.to_json(),
        });
        if timing_detail_mode.trace()
            && let serde_json::Value::Object(experimental) = &mut experimental_json
        {
            experimental.insert("slow_packages".to_string(), slow_package_timings.to_json());
        }
        let timing_json = serde_json::json!({
            "resolve_ms": resolve_ms,
            "fetch_ms": fetch_ms,
            "link_ms": link_ms,
            "total_ms": total_ms,
            "waterfall": waterfall_json,
            "fetch_breakdown": fetch_breakdown.to_json(),
            "experimental_installer_spike": experimental_json,
        });
        let mut json = serde_json::json!({
            "success": true,
            "experimental": "installer-spike",
            "packages": package_json,
            "count": install_packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": graph_source.uses_lockfile(),
            "duration_ms": total_ms as u64,
            "timing": timing_json,
            "warnings": [],
            "errors": [],
        });
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|patch| patch.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            fingerprint_json_value(current_patches.len(), current_patch_fingerprint);
        crate::security_floor::attach_security_posture(&mut json, false);
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        output::success(&format!(
            "{} packages installed in {:.1}s",
            install_packages.len().to_string().bold(),
            total_ms as f64 / 1000.0
        ));
    }

    Ok(())
}

fn installer_spike_concurrency() -> usize {
    std::env::var(ENV_INSTALLER_SPIKE_CONCURRENCY)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| (1..=256).contains(value))
        .unwrap_or(DEFAULT_INSTALLER_SPIKE_CONCURRENCY)
}

fn installer_spike_metadata_concurrency() -> usize {
    std::env::var(ENV_INSTALLER_SPIKE_METADATA_CONCURRENCY)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| (1..=256).contains(value))
        .unwrap_or(DEFAULT_INSTALLER_SPIKE_METADATA_CONCURRENCY)
}

fn installer_spike_exact_doc_enabled() -> bool {
    std::env::var(ENV_INSTALLER_SPIKE_EXACT_DOC).as_deref() == Ok("1")
}

pub(super) fn has_tarball_source_deps(project_dir: &Path, deps: &HashMap<String, String>) -> bool {
    deps.values()
        .any(|raw| match lpm_resolver::Specifier::parse(raw) {
            Ok(lpm_resolver::Specifier::Tarball { .. }) => true,
            Ok(lpm_resolver::Specifier::File { path }) => {
                std::fs::metadata(project_dir.join(path)).is_ok_and(|meta| meta.is_file())
            }
            _ => false,
        })
}

fn merge_pre_resolved_packages(
    packages: &mut Vec<InstallPackage>,
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
) {
    if !pre_resolved_install_pkgs.is_empty() {
        packages.extend(pre_resolved_install_pkgs.iter().cloned());
    }
    if !pre_resolved_source_deps.is_empty() {
        apply_post_resolve_directory_link_fixup(packages, pre_resolved_source_deps);
    }
    dedupe_install_packages_by_identity(packages);
}

fn populate_v2_local_source_objects(
    link_targets: &[LinkTarget],
    store_v2: &lpm_store::v2::Store,
) -> Result<(), LpmError> {
    for target in link_targets {
        if matches!(
            target.materialization,
            lpm_linker::Materialization::DirectorySource
        ) {
            let sri = local_source_sri_for_target(target);
            store_v2.populate_object_from_local_source(&target.store_path, &sri)?;
        }
    }
    Ok(())
}

fn is_local_source_package(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
    )
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum InstallerSpikeGraphSource {
    ResolveWorklist,
    Lockfile,
    Invalid,
}

impl InstallerSpikeGraphSource {
    fn from_env() -> Self {
        Self::from_value(std::env::var(ENV_INSTALLER_SPIKE_GRAPH).ok().as_deref())
    }

    fn from_value(value: Option<&str>) -> Self {
        match value {
            None => Self::ResolveWorklist,
            Some("resolve" | "resolve-worklist" | "live" | "live-resolve") => Self::ResolveWorklist,
            Some("lock" | "lockfile" | "seed-lock") => Self::Lockfile,
            Some(_) => Self::Invalid,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ResolveWorklist => "resolve-worklist",
            Self::Lockfile => "lockfile",
            Self::Invalid => "invalid",
        }
    }

    fn uses_lockfile(self) -> bool {
        matches!(self, Self::Lockfile)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum InstallerSpikeParityMode {
    Disabled,
    FreshResolve { deny: bool },
    Lockfile { deny: bool },
}

impl InstallerSpikeParityMode {
    fn from_env() -> Self {
        Self::from_value(std::env::var(ENV_INSTALLER_SPIKE_PARITY).ok().as_deref())
    }

    fn from_value(value: Option<&str>) -> Self {
        match value {
            Some("1" | "true" | "warn") => Self::FreshResolve { deny: false },
            Some("deny") => Self::FreshResolve { deny: true },
            Some("lock" | "lockfile" | "seed-lock") => Self::Lockfile { deny: false },
            Some("lock-deny" | "lockfile-deny" | "seed-lock-deny") => Self::Lockfile { deny: true },
            Some(_) | None => Self::Disabled,
        }
    }

    fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn deny(self) -> bool {
        matches!(
            self,
            Self::FreshResolve { deny: true } | Self::Lockfile { deny: true }
        )
    }

    fn baseline(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FreshResolve { .. } => "fresh-greedy",
            Self::Lockfile { .. } => "lockfile",
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn compute_parity_if_requested(
    client: Arc<RegistryClient>,
    deps: &HashMap<String, String>,
    override_set: OverrideSet,
    route_table: RouteTable,
    resolver_policy: lpm_resolver::ResolverPolicy,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    all_workspace_members: &[WorkspaceMemberLink],
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    pre_resolved_install_pkgs: &[InstallPackage],
    pre_resolved_source_deps: &HashMap<String, Vec<SourceDep>>,
    project_dir: &Path,
    candidate_packages: &[InstallPackage],
    json_output: bool,
) -> Result<InstallerSpikeParity, LpmError> {
    let mode = InstallerSpikeParityMode::from_env();
    if !mode.enabled() {
        return Ok(InstallerSpikeParity::disabled());
    }

    let mut baseline_packages = match mode {
        InstallerSpikeParityMode::Disabled => unreachable!(),
        InstallerSpikeParityMode::FreshResolve { .. } => {
            let shared_cache: lpm_resolver::SharedCache = Arc::new(dashmap::DashMap::new());
            seed_workspace_resolver_cache(&shared_cache, all_workspace_members)?;
            let npm_fanout = positive_usize_env_or_default(
                "LPM_NPM_FANOUT",
                default_fusion_npm_fanout(false, 0),
            );
            let resolve_result = lpm_resolver::resolve_greedy_fused_with_cache_options_and_policy(
                client,
                deps.clone(),
                override_set,
                route_table.clone(),
                npm_fanout,
                None,
                shared_cache,
                auto_install_peers,
                include_optional_dependencies,
                resolver_policy,
            )
            .await
            .map_err(crate::resolver_error::resolver_error_to_lpm)?;

            let mut packages = resolved_to_install_packages_with_workspace_members(
                &resolve_result.packages,
                deps,
                &resolve_result.root_aliases,
                &resolve_result.ambient_peer_installs,
                &resolve_result.cache,
                &route_table,
                all_workspace_members,
                project_dir,
            );
            let optional_dependency_names =
                optional_dependency_names_from_resolver_cache(&packages, &resolve_result.cache);
            normalize_install_package_optional_reachability(
                &mut packages,
                &optional_dependency_names,
            );
            merge_pre_resolved_packages(
                &mut packages,
                pre_resolved_install_pkgs,
                pre_resolved_source_deps,
            );
            packages
        }
        InstallerSpikeParityMode::Lockfile { .. } => {
            let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
            let gate_stats = GateStats::default();
            try_lockfile_fast_path(
                &lockfile_path,
                deps,
                catalog_resolutions,
                client.as_ref(),
                &gate_stats,
                true,
            )
            .map(|fast| fast.packages)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "experimental installer spike lockfile parity requires a readable seed {} matching the current manifest",
                    lockfile_path.display()
                ))
            })?
        }
    };
    dedupe_install_packages_by_identity(&mut baseline_packages);
    let _ = filter_platform_packages(&mut baseline_packages)?;

    let parity = compare_package_parity_with_baseline(
        candidate_packages,
        &baseline_packages,
        mode.baseline(),
    );
    if !parity.matches && !json_output {
        output::warn(&format!(
            "experimental installer spike parity mismatch against {}: candidate={} baseline={} extra={} missing={} graph-mismatches={}",
            parity.baseline,
            parity.candidate_count,
            parity.baseline_count,
            parity.extra_count,
            parity.missing_count,
            parity.fingerprint_mismatch_count,
        ));
    }
    if !parity.matches && mode.deny() {
        return Err(LpmError::Registry(format!(
            "experimental installer spike parity mismatch against {}: candidate={} baseline={} extra={} missing={} graph-mismatches={}",
            parity.baseline,
            parity.candidate_count,
            parity.baseline_count,
            parity.extra_count,
            parity.missing_count,
            parity.fingerprint_mismatch_count,
        )));
    }

    Ok(parity)
}

fn compare_package_parity_with_baseline(
    candidate_packages: &[InstallPackage],
    baseline_packages: &[InstallPackage],
    baseline_name: &'static str,
) -> InstallerSpikeParity {
    let candidate = package_parity_index(candidate_packages);
    let baseline = package_parity_index(baseline_packages);

    let mut extra = Vec::new();
    for (key, (display, _)) in &candidate {
        if !baseline.contains_key(key) {
            extra.push(display.clone());
        }
    }

    let mut missing = Vec::new();
    for (key, (display, _)) in &baseline {
        if !candidate.contains_key(key) {
            missing.push(display.clone());
        }
    }

    let mut fingerprint_mismatches = Vec::new();
    for (key, (display, candidate_fp)) in &candidate {
        let Some((_, baseline_fp)) = baseline.get(key) else {
            continue;
        };
        if candidate_fp != baseline_fp {
            fingerprint_mismatches.push(PackageFingerprintMismatch {
                package: display.clone(),
                candidate: candidate_fp.clone(),
                baseline: baseline_fp.clone(),
            });
        }
    }

    let extra_count = extra.len();
    let missing_count = missing.len();
    let fingerprint_mismatch_count = fingerprint_mismatches.len();
    extra.truncate(PARITY_SAMPLE_LIMIT);
    missing.truncate(PARITY_SAMPLE_LIMIT);
    fingerprint_mismatches.truncate(PARITY_SAMPLE_LIMIT);
    let matches = extra_count == 0 && missing_count == 0 && fingerprint_mismatch_count == 0;

    InstallerSpikeParity {
        enabled: true,
        matches,
        baseline: baseline_name,
        candidate_count: candidate_packages.len(),
        baseline_count: baseline_packages.len(),
        count_delta: candidate_packages.len() as isize - baseline_packages.len() as isize,
        extra_count,
        missing_count,
        fingerprint_mismatch_count,
        extra,
        missing,
        fingerprint_mismatches,
    }
}

fn package_parity_index(
    packages: &[InstallPackage],
) -> BTreeMap<String, (String, PackageFingerprint)> {
    packages
        .iter()
        .map(|package| {
            (
                install_pkg_key(package),
                (
                    format!("{}@{} {}", package.name, package.version, package.source),
                    package_fingerprint(package),
                ),
            )
        })
        .collect()
}

fn package_fingerprint(package: &InstallPackage) -> PackageFingerprint {
    let mut dependencies = package.dependencies.clone();
    dependencies.sort();
    let mut aliases: Vec<_> = package
        .aliases
        .iter()
        .map(|(alias, target)| (alias.clone(), target.clone()))
        .collect();
    aliases.sort();
    let mut peers = package.peers.clone();
    peers.sort();
    let mut root_link_names = package.root_link_names.clone().unwrap_or_default();
    root_link_names.sort();
    PackageFingerprint {
        dependencies,
        aliases,
        peers,
        root_link_names,
        is_direct: package.is_direct,
        optional: package.optional,
    }
}

fn package_fingerprint_json(fingerprint: &PackageFingerprint) -> serde_json::Value {
    serde_json::json!({
        "dependencies": &fingerprint.dependencies,
        "aliases": &fingerprint.aliases,
        "peers": &fingerprint.peers,
        "root_link_names": &fingerprint.root_link_names,
        "direct": fingerprint.is_direct,
        "optional": fingerprint.optional,
    })
}

fn load_lockfile_graph_packages(
    project_dir: &Path,
    deps: &HashMap<String, String>,
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    client: &RegistryClient,
    gate_stats: &GateStats,
    auto_install_peers: bool,
) -> Result<Vec<InstallPackage>, LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let fast = try_lockfile_fast_path(
        &lockfile_path,
        deps,
        catalog_resolutions,
        client,
        gate_stats,
        false,
    )
    .ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental installer lockfile graph mode requires a readable {} matching the current manifest",
            lockfile_path.display()
        ))
    })?;
    if lockfile_needs_peer_state_repair(&fast.lockfile, auto_install_peers) {
        return Err(LpmError::Registry(format!(
            "experimental installer lockfile graph mode requires an upgraded v{} lockfile; found v{}",
            lpm_lockfile::LOCKFILE_VERSION,
            fast.lockfile.metadata.lockfile_version
        )));
    }
    Ok(fast.packages)
}

fn root_resolve_requests(deps: &HashMap<String, String>) -> Vec<ResolveRequest> {
    let mut requests = Vec::with_capacity(deps.len());
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (local_name, range) in entries {
        let (target_name, range) = parse_alias_target(local_name, range);
        requests.push(ResolveRequest {
            local_name: local_name.clone(),
            root_ancestor: target_name.clone(),
            target_name,
            range,
            parent: None,
            depth: 0,
            optional: false,
            root: true,
            direct: true,
        });
    }
    requests
}

fn parse_alias_target(local_name: &str, range: &str) -> (String, String) {
    lpm_resolver::ranges::parse_npm_alias(range).map_or_else(
        || (local_name.to_string(), range.to_string()),
        |alias| (alias.target, alias.range),
    )
}

async fn resolve_node(
    request: ResolveRequest,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    metadata_caches: MetadataCaches,
    metadata_queue: Arc<Semaphore>,
    metadata_stats: Arc<MetadataStats>,
    resolver_policy: lpm_resolver::ResolverPolicy,
) -> Result<NodeResolution, LpmError> {
    let context = MetadataRequestContext::from_request(&request);
    let info = metadata_for_package(
        context,
        client,
        route_table,
        metadata_caches,
        metadata_queue,
        metadata_stats,
        resolver_policy,
    )
    .await?;
    Ok(NodeResolution::Metadata { request, info })
}

async fn metadata_for_package(
    mut context: MetadataRequestContext,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    metadata_caches: MetadataCaches,
    metadata_queue: Arc<Semaphore>,
    metadata_stats: Arc<MetadataStats>,
    resolver_policy: lpm_resolver::ResolverPolicy,
) -> Result<Arc<lpm_resolver::CachedPackageInfo>, LpmError> {
    metadata_stats.calls.fetch_add(1, Ordering::Relaxed);
    let queued_at_ms = metadata_stats.elapsed_ms();
    let name = context.package.clone();
    let canonical = lpm_resolver::CanonicalKey::from_dep_name(&name);
    let version_doc_policy_eligible = !resolver_policy.release_age_applies_to_package(&canonical)
        && !resolver_policy.requires_trust_history();
    let version_doc_eligible = matches!(
        route_table.route_for_package(&name),
        lpm_registry::UpstreamRoute::NpmDirect
    ) && matches!(context.range_shape, MetadataRangeShape::Exact)
        && version_doc_policy_eligible;
    context.version_doc_eligible = version_doc_eligible;
    metadata_stats.record_range_call(&context);

    if installer_spike_exact_doc_enabled()
        && version_doc_eligible
        && !metadata_caches.full.contains_key(&name)
        && let Some(version) = context.range.as_deref().and_then(exact_pin_version)
    {
        return metadata_for_exact_version(
            context,
            name,
            version,
            client,
            route_table,
            metadata_caches,
            metadata_queue,
            metadata_stats,
            resolver_policy,
            queued_at_ms,
        )
        .await;
    }

    metadata_for_full_package(
        context,
        name,
        client,
        route_table,
        metadata_caches,
        metadata_queue,
        metadata_stats,
        resolver_policy,
        queued_at_ms,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn metadata_for_full_package(
    context: MetadataRequestContext,
    name: String,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    metadata_caches: MetadataCaches,
    metadata_queue: Arc<Semaphore>,
    metadata_stats: Arc<MetadataStats>,
    resolver_policy: lpm_resolver::ResolverPolicy,
    queued_at_ms: u128,
) -> Result<Arc<lpm_resolver::CachedPackageInfo>, LpmError> {
    let cell = metadata_caches
        .full
        .entry(name.clone())
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();
    if cell.get().is_some() {
        metadata_stats.ready_hits.fetch_add(1, Ordering::Relaxed);
    }
    let metadata_stats_for_init = Arc::clone(&metadata_stats);
    let trace = TimingDetailMode::from_env().trace();
    cell.get_or_try_init(|| async move {
        metadata_stats_for_init
            .initial_fetches
            .fetch_add(1, Ordering::Relaxed);
        metadata_stats_for_init.record_range_initial_fetch(&context);
        let queue_start = Instant::now();
        let _permit = metadata_queue
            .acquire()
            .await
            .map_err(|_| LpmError::Registry("experimental installer queue closed".into()))?;
        metadata_stats_for_init.record_queue_wait(queue_start.elapsed().as_millis());
        let fetch_start = Instant::now();
        let canonical = lpm_resolver::CanonicalKey::from_dep_name(&name);
        let (info, timings) =
            lpm_resolver::experimental_fetch_cached_package_info_with_policy_and_timings(
                &client,
                &route_table,
                &canonical,
                &resolver_policy,
            )
            .await
            .map_err(crate::resolver_error::resolver_error_to_lpm)?;
        metadata_stats_for_init.record_fetch(fetch_start.elapsed().as_millis());
        let completed_at_ms = metadata_stats_for_init.elapsed_ms();
        metadata_stats_for_init.record_detail(
            context,
            timings,
            queued_at_ms,
            completed_at_ms,
            trace,
        );
        Ok(info)
    })
    .await
    .cloned()
}

#[allow(clippy::too_many_arguments)]
async fn metadata_for_exact_version(
    context: MetadataRequestContext,
    name: String,
    version: String,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    metadata_caches: MetadataCaches,
    metadata_queue: Arc<Semaphore>,
    metadata_stats: Arc<MetadataStats>,
    resolver_policy: lpm_resolver::ResolverPolicy,
    queued_at_ms: u128,
) -> Result<Arc<lpm_resolver::CachedPackageInfo>, LpmError> {
    let key = ExactVersionMetadataKey {
        name: name.clone(),
        version: version.clone(),
    };
    let cell = metadata_caches
        .exact_version
        .entry(key)
        .or_insert_with(|| Arc::new(OnceCell::new()))
        .clone();
    if cell.get().is_some() {
        metadata_stats.ready_hits.fetch_add(1, Ordering::Relaxed);
    }
    let metadata_stats_for_init = Arc::clone(&metadata_stats);
    let trace = TimingDetailMode::from_env().trace();
    cell.get_or_try_init(|| async move {
        metadata_stats_for_init
            .initial_fetches
            .fetch_add(1, Ordering::Relaxed);
        metadata_stats_for_init.record_range_initial_fetch(&context);
        metadata_stats_for_init.record_version_doc_attempt();
        let queue_start = Instant::now();
        let permit = metadata_queue
            .acquire()
            .await
            .map_err(|_| LpmError::Registry("experimental installer queue closed".into()))?;
        metadata_stats_for_init.record_queue_wait(queue_start.elapsed().as_millis());
        let fetch_start = Instant::now();
        let canonical = lpm_resolver::CanonicalKey::from_dep_name(&name);
        let exact_result =
            lpm_resolver::experimental_fetch_exact_cached_package_info_with_policy_and_timings(
                &client,
                &route_table,
                &canonical,
                &version,
                &resolver_policy,
            )
            .await;
        metadata_stats_for_init.record_fetch(fetch_start.elapsed().as_millis());
        drop(permit);
        match exact_result {
            Ok((info, timings)) => {
                metadata_stats_for_init.record_version_doc_hit();
                let completed_at_ms = metadata_stats_for_init.elapsed_ms();
                metadata_stats_for_init.record_detail(
                    context,
                    timings,
                    queued_at_ms,
                    completed_at_ms,
                    trace,
                );
                Ok(info)
            }
            Err(_) => {
                metadata_stats_for_init.record_version_doc_fallback();
                metadata_for_full_package(
                    context,
                    name,
                    client,
                    route_table,
                    metadata_caches,
                    metadata_queue,
                    metadata_stats_for_init,
                    resolver_policy,
                    queued_at_ms,
                )
                .await
            }
        }
    })
    .await
    .cloned()
}

fn select_or_reuse_node(
    request: ResolveRequest,
    info: Arc<lpm_resolver::CachedPackageInfo>,
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    override_set: &OverrideSet,
    resolver_policy: &lpm_resolver::ResolverPolicy,
) -> Result<Option<ResolvedNode>, LpmError> {
    if override_set.is_empty()
        && let Some(version) = reusable_existing_version(&request, packages)?
    {
        let platform = info.platform.get(&version).cloned();
        return Ok(Some(ResolvedNode {
            request,
            version,
            info,
            platform,
            reused_existing: true,
        }));
    }

    let split_target = !override_set.split_targets().is_empty()
        && override_set.split_targets().contains(&request.target_name);
    let Some((version, platform, override_hit)) =
        select_version_from_info(&request, &info, override_set, resolver_policy)?
    else {
        return Ok(None);
    };
    let override_applied = override_hit.is_some();
    if let Some(hit) = override_hit {
        override_set.record_hit(hit);
    }
    if !request.root {
        if override_applied || split_target {
            if package_version_exists(packages, &request.target_name, &version) {
                return Ok(Some(ResolvedNode {
                    request,
                    version,
                    info,
                    platform,
                    reused_existing: true,
                }));
            }
        } else if let Some(version) = reusable_existing_version(&request, packages)? {
            let platform = info.platform.get(&version).cloned();
            return Ok(Some(ResolvedNode {
                request,
                version,
                info,
                platform,
                reused_existing: true,
            }));
        }
    }
    Ok(Some(ResolvedNode {
        request,
        version,
        info,
        platform,
        reused_existing: false,
    }))
}

fn reusable_existing_version(
    request: &ResolveRequest,
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> Result<Option<String>, LpmError> {
    if request.root {
        return Ok(None);
    }
    let range = lpm_resolver::NpmRange::parse(&request.range).map_err(|e| {
        LpmError::Registry(format!(
            "experimental installer: invalid range {}@{}: {e}",
            request.target_name, request.range
        ))
    })?;
    let mut selected: Option<(lpm_resolver::NpmVersion, String)> = None;
    for (name, version) in packages.keys() {
        if name != &request.target_name {
            continue;
        }
        let Ok(parsed) = lpm_resolver::NpmVersion::parse(version) else {
            continue;
        };
        if !range.satisfies(&parsed) {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(current, _)| parsed > *current)
        {
            selected = Some((parsed, version.clone()));
        }
    }
    Ok(selected.map(|(_, version)| version))
}

fn package_version_exists(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    target_name: &str,
    version: &str,
) -> bool {
    packages.contains_key(&(target_name.to_string(), version.to_string()))
}

fn select_version_from_info(
    request: &ResolveRequest,
    info: &lpm_resolver::CachedPackageInfo,
    override_set: &OverrideSet,
    resolver_policy: &lpm_resolver::ResolverPolicy,
) -> Result<Option<SelectedVersion>, LpmError> {
    let range = lpm_resolver::NpmRange::parse(&request.range).map_err(|e| {
        LpmError::Registry(format!(
            "experimental installer: invalid range {}@{}: {e}",
            request.target_name, request.range
        ))
    })?;
    let canonical = lpm_resolver::CanonicalKey::from_dep_name(&request.target_name);
    let parent_canonical = request.parent.as_ref().map(|(name, _)| name.as_str());
    let (selection, override_hit) =
        lpm_resolver::experimental_select_version_with_policy_and_overrides(
            &canonical,
            info,
            &range,
            resolver_policy,
            override_set,
            parent_canonical,
        );
    match selection {
        lpm_resolver::ExperimentalVersionSelection::Picked(version) => {
            let version = version.to_string();
            let platform = info.platform.get(&version).cloned();
            Ok(Some((version, platform, override_hit)))
        }
        lpm_resolver::ExperimentalVersionSelection::NoSatisfying => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental installer: no version of {} satisfies {}",
                    request.target_name, request.range
                )))
            }
        }
        lpm_resolver::ExperimentalVersionSelection::BlockedByReleaseAge {
            version,
            remaining_secs,
            minimum_secs,
        } => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental installer: {}@{} published too recently for minimumReleaseAge; {}s remaining (minimumReleaseAge={}s)",
                    request.target_name, version, remaining_secs, minimum_secs
                )))
            }
        }
        lpm_resolver::ExperimentalVersionSelection::BlockedByTrustPolicy { version, reason } => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental installer: {}@{} blocked by trust-policy no-downgrade: {}",
                    request.target_name, version, reason
                )))
            }
        }
    }
}

fn merge_node_into_packages(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    node: &ResolvedNode,
    route_table: &RouteTable,
    store: &PackageStore,
    project_dir: &Path,
) -> MergeOutcome {
    let identity = (node.request.target_name.clone(), node.version.clone());
    let mut outcome = MergeOutcome {
        inserted: false,
        became_required: false,
    };
    match packages.entry(identity) {
        Entry::Occupied(mut occupied) => {
            let package = &mut occupied.get_mut().package;
            let was_optional = package.optional;
            package.optional &= node.request.optional;
            outcome.became_required = was_optional && !package.optional;
            if node.request.direct {
                package.is_direct = true;
            }
            if node.request.root {
                append_root_link(package, &node.request.local_name);
            }
        }
        Entry::Vacant(vacant) => {
            outcome.inserted = true;
            let name = node.request.target_name.clone();
            let version = node.version.clone();
            let registry_url = registry_source_url_for(&name, route_table);
            let source = format!("registry+{registry_url}");
            let is_lpm = name.starts_with("@lpm.dev/");
            let dist = node.info.dist.get(&version);
            let mut package = InstallPackage {
                name,
                version: version.clone(),
                source,
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                root_link_names: None,
                is_direct: node.request.direct,
                is_lpm,
                peers: Vec::new(),
                integrity: dist.and_then(|dist| dist.integrity.clone()),
                registry_signatures: dist.map(|dist| dist.signatures.clone()).unwrap_or_default(),
                registry_published_at: dist.and_then(|dist| dist.published_at.clone()),
                platform: node.platform.clone(),
                optional: node.request.optional,
                tarball_url: dist.and_then(|dist| dist.tarball_url.clone()),
                metadata_checked_for_tarball: true,
            };
            if node.request.root {
                append_root_link(&mut package, &node.request.local_name);
            }
            let _ = package.store_path_source_aware(store, project_dir, None);
            vacant.insert(PackageDraft {
                package,
                info: Arc::clone(&node.info),
            });
        }
    }
    outcome
}

fn append_root_link(package: &mut InstallPackage, local_name: &str) {
    let names = package.root_link_names.get_or_insert_with(Vec::new);
    if !names.iter().any(|name| name == local_name) {
        names.push(local_name.to_string());
        names.sort();
    }
}

fn mark_required_closure(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    identity: &PackageIdentity,
) {
    let mut stack = vec![identity.clone()];
    let mut seen = HashSet::new();
    while let Some(identity) = stack.pop() {
        if !seen.insert(identity.clone()) {
            continue;
        }
        let Some(draft) = packages.get_mut(&identity) else {
            continue;
        };
        draft.package.optional = false;
        let dependencies = draft.package.dependencies.clone();
        let aliases = draft.package.aliases.clone();
        for (local_name, version) in dependencies {
            let target_name = aliases.get(&local_name).unwrap_or(&local_name).clone();
            stack.push((target_name, version));
        }
    }
}

fn attach_dependency_edge(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    parent: &PackageIdentity,
    node: &ResolvedNode,
) -> Result<(), LpmError> {
    let parent = packages.get_mut(parent).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental installer: parent package {}@{} was not recorded",
            parent.0, parent.1
        ))
    })?;
    upsert_dependency(
        &mut parent.package.dependencies,
        node.request.local_name.clone(),
        node.version.clone(),
    );
    if node.request.local_name != node.request.target_name {
        parent
            .package
            .aliases
            .entry(node.request.local_name.clone())
            .or_insert_with(|| node.request.target_name.clone());
    }
    Ok(())
}

fn upsert_dependency(
    dependencies: &mut Vec<(String, String)>,
    local_name: String,
    version: String,
) {
    if let Some((_, existing)) = dependencies
        .iter_mut()
        .find(|(existing_name, _)| existing_name == &local_name)
    {
        *existing = version;
    } else {
        dependencies.push((local_name, version));
    }
}

#[allow(clippy::too_many_arguments)]
fn enqueue_dependencies(
    node: &ResolvedNode,
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    pending: &mut FuturesUnordered<ResolveFuture>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    include_optional_dependencies: bool,
    stats: &mut InstallerSpikeStats,
) -> Result<(), LpmError> {
    let parent = Some((node.request.target_name.clone(), node.version.clone()));
    let aliases = node.info.aliases.get(&node.version);
    let optional_names = node.info.optional_dep_names.get(&node.version);
    let bundled_names = node.info.bundled_dep_names.get(&node.version);
    let Some(deps) = node.info.deps.get(&node.version) else {
        return Ok(());
    };
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (local_name, range) in entries {
        if bundled_names.is_some_and(|names| names.contains(local_name)) {
            continue;
        }
        let target_name = aliases
            .and_then(|aliases| aliases.get(local_name))
            .cloned()
            .unwrap_or_else(|| local_name.clone());
        let optional =
            node.request.optional || optional_names.is_some_and(|names| names.contains(local_name));
        if optional && !include_optional_dependencies {
            continue;
        }
        let request = ResolveRequest {
            local_name: local_name.clone(),
            root_ancestor: node.request.root_ancestor.clone(),
            target_name,
            range: range.clone(),
            parent: parent.clone(),
            depth: node.request.depth.saturating_add(1),
            optional,
            root: false,
            direct: false,
        };
        if let Some(version) = reusable_existing_version(&request, packages)? {
            if inline_reuse_can_preserve_optional_state(packages, &request, &version)? {
                attach_reused_dependency_edge(packages, &request, &version)?;
                stats.inline_reused_edges += 1;
                stats.reused_existing_versions += 1;
                continue;
            }
            stats.inline_reuse_deferred_promotions += 1;
        }
        stats.dependency_requests_enqueued += 1;
        pending.push(Box::pin(resolve_node(
            request,
            Arc::clone(client),
            route_table.clone(),
            metadata_caches.clone(),
            Arc::clone(metadata_queue),
            Arc::clone(metadata_stats),
            resolver_policy.clone(),
        )));
    }
    Ok(())
}

fn attach_reused_dependency_edge(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    request: &ResolveRequest,
    version: &str,
) -> Result<(), LpmError> {
    let identity = (request.target_name.clone(), version.to_string());
    let became_required = {
        let draft = packages.get_mut(&identity).ok_or_else(|| {
            LpmError::Registry(format!(
                "experimental installer could not reuse missing package {}@{}",
                identity.0, identity.1
            ))
        })?;
        let was_optional = draft.package.optional;
        draft.package.optional &= request.optional;
        let became_required = was_optional && !draft.package.optional;
        if became_required {
            ensure_package_can_materialize(&draft.package)?;
        }
        became_required
    };

    if let Some(parent) = request.parent.as_ref() {
        attach_dependency_edge_from_request(packages, parent, request, version)?;
    }
    if became_required {
        mark_required_closure(packages, &identity);
    }
    Ok(())
}

fn inline_reuse_can_preserve_optional_state(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    request: &ResolveRequest,
    version: &str,
) -> Result<bool, LpmError> {
    let identity = (request.target_name.clone(), version.to_string());
    let draft = packages.get(&identity).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental installer could not inspect reusable package {}@{}",
            identity.0, identity.1
        ))
    })?;
    Ok(!draft.package.optional || request.optional)
}

fn attach_dependency_edge_from_request(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    parent: &PackageIdentity,
    request: &ResolveRequest,
    version: &str,
) -> Result<(), LpmError> {
    let parent = packages.get_mut(parent).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental installer: parent package {}@{} was not recorded",
            parent.0, parent.1
        ))
    })?;
    upsert_dependency(
        &mut parent.package.dependencies,
        request.local_name.clone(),
        version.to_string(),
    );
    if request.local_name != request.target_name {
        parent
            .package
            .aliases
            .entry(request.local_name.clone())
            .or_insert_with(|| request.target_name.clone());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drain_ambient_peer_installs(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    fetch_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    include_optional_dependencies: bool,
    auto_install_peers: bool,
    override_set: &OverrideSet,
    store: &PackageStore,
    project_dir: &Path,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut InstallerSpikeStats,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
) -> Result<(), LpmError> {
    if !auto_install_peers {
        return Ok(());
    }

    let mut ambient_done = HashSet::new();
    loop {
        let plans = ambient_peer_plans(
            packages,
            client,
            route_table,
            metadata_caches,
            metadata_queue,
            metadata_stats,
            resolver_policy,
            &ambient_done,
        )
        .await?;
        if plans.is_empty() {
            return Ok(());
        }

        let mut pending: FuturesUnordered<ResolveFuture> = FuturesUnordered::new();
        for plan in plans {
            stats.peer_requests_enqueued += 1;
            ambient_done.insert(plan.target_name.clone());
            pending.push(Box::pin(resolve_node(
                ResolveRequest {
                    local_name: plan.target_name.clone(),
                    root_ancestor: plan.target_name.clone(),
                    target_name: plan.target_name,
                    range: plan.version,
                    parent: None,
                    depth: 0,
                    optional: false,
                    root: true,
                    direct: false,
                },
                Arc::clone(client),
                route_table.clone(),
                metadata_caches.clone(),
                Arc::clone(metadata_queue),
                Arc::clone(metadata_stats),
                resolver_policy.clone(),
            )));
        }

        while let Some(result) = pending.next().await {
            let NodeResolution::Metadata { request, info } = result?;
            let Some(node) = select_or_reuse_node(
                request,
                Arc::clone(&info),
                packages,
                override_set,
                resolver_policy,
            )?
            else {
                stats.skipped_optional += 1;
                continue;
            };
            stats.selected_nodes += 1;
            if node.reused_existing {
                stats.reused_existing_versions += 1;
            }
            let identity = (node.request.target_name.clone(), node.version.clone());
            let merge = merge_node_into_packages(packages, &node, route_table, store, project_dir);
            if merge.became_required {
                let draft = packages.get(&identity).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "experimental installer lost package {}@{} during peer required promotion",
                        identity.0, identity.1
                    ))
                })?;
                ensure_package_can_materialize(&draft.package)?;
                mark_required_closure(packages, &identity);
            }
            if let Some(parent) = node.request.parent.as_ref() {
                attach_dependency_edge(packages, parent, &node)?;
            }
            if merge.inserted {
                stats.inserted_nodes += 1;
                let package = packages
                    .get(&identity)
                    .map(|draft| draft.package.clone())
                    .ok_or_else(|| {
                        LpmError::Registry(format!(
                            "experimental installer lost package {}@{} during peer insertion",
                            identity.0, identity.1
                        ))
                    })?;
                if package_should_materialize(&package)? {
                    maybe_spawn_fetch(
                        package,
                        store,
                        store_v2_handle.clone(),
                        project_dir,
                        Arc::clone(client),
                        route_table.clone(),
                        Arc::clone(fetch_queue),
                        Arc::clone(&gate_stats),
                        force,
                        fetch_extract_limiter.clone(),
                        fetch_handles,
                        stats,
                    );
                } else {
                    stats.platform_pre_skipped += 1;
                }
                enqueue_dependencies(
                    &node,
                    packages,
                    &mut pending,
                    client,
                    route_table,
                    metadata_caches,
                    metadata_queue,
                    metadata_stats,
                    resolver_policy,
                    include_optional_dependencies,
                    stats,
                )?;
            } else {
                stats.duplicate_nodes += 1;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ambient_peer_plans(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    ambient_done: &HashSet<String>,
) -> Result<Vec<AmbientPeerPlan>, LpmError> {
    let mut grouped: BTreeMap<String, Vec<PeerRequirement>> = BTreeMap::new();
    for requirement in collect_peer_requirements(packages) {
        grouped
            .entry(requirement.target_name.clone())
            .or_default()
            .push(requirement);
    }

    let mut plans = Vec::new();
    for (target_name, reqs) in grouped {
        if ambient_done.contains(&target_name)
            || reqs.iter().all(|req| req.optional)
            || peer_group_satisfied_by_existing(packages, &target_name, &reqs)
        {
            continue;
        }
        let info = metadata_for_package(
            MetadataRequestContext::peer_plan(&target_name),
            Arc::clone(client),
            route_table.clone(),
            metadata_caches.clone(),
            Arc::clone(metadata_queue),
            Arc::clone(metadata_stats),
            resolver_policy.clone(),
        )
        .await?;
        let Some(version) = peer_version_satisfying_all(&info, &reqs)
            .or_else(|| peer_version_satisfying_most(&info, &reqs))
        else {
            return Err(LpmError::Registry(format!(
                "experimental installer: no version of {target_name} satisfies required peer ranges"
            )));
        };
        plans.push(AmbientPeerPlan {
            target_name,
            version: version.to_string(),
        });
    }
    Ok(plans)
}

fn collect_peer_requirements(
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> Vec<PeerRequirement> {
    let mut requirements = Vec::new();
    for draft in packages.values() {
        let version = &draft.package.version;
        let Some(peer_deps) = draft.info.peer_deps.get(version) else {
            continue;
        };
        let aliases = draft.info.aliases.get(version);
        let optional_peers = draft.info.optional_peer_names.get(version);
        for (peer_name, peer_range) in peer_deps {
            let Ok(range) = lpm_resolver::NpmRange::parse(peer_range) else {
                continue;
            };
            let target_name = aliases
                .and_then(|aliases| aliases.get(peer_name))
                .cloned()
                .unwrap_or_else(|| peer_name.clone());
            requirements.push(PeerRequirement {
                target_name,
                range,
                optional: optional_peers.is_some_and(|peers| peers.contains(peer_name)),
            });
        }
    }
    requirements
}

fn peer_group_satisfied_by_existing(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    target_name: &str,
    reqs: &[PeerRequirement],
) -> bool {
    packages.keys().any(|(name, version)| {
        if name != target_name {
            return false;
        }
        let Ok(version) = lpm_resolver::NpmVersion::parse(version) else {
            return false;
        };
        reqs.iter().all(|req| req.range.satisfies(&version))
    })
}

fn peer_version_satisfying_all(
    info: &lpm_resolver::CachedPackageInfo,
    reqs: &[PeerRequirement],
) -> Option<lpm_resolver::NpmVersion> {
    info.versions
        .iter()
        .find(|version| {
            reqs.iter().all(|req| req.range.satisfies(version))
                && platform_allows_peer_version(info, version)
        })
        .cloned()
}

fn peer_version_satisfying_most(
    info: &lpm_resolver::CachedPackageInfo,
    reqs: &[PeerRequirement],
) -> Option<lpm_resolver::NpmVersion> {
    let mut best: Option<(lpm_resolver::NpmVersion, usize)> = None;
    for version in &info.versions {
        if !platform_allows_peer_version(info, version) {
            continue;
        }
        let hits = reqs
            .iter()
            .filter(|req| !req.optional && req.range.satisfies(version))
            .count();
        if hits == 0 {
            continue;
        }
        if best.as_ref().is_none_or(|(_, best_hits)| hits > *best_hits) {
            best = Some((version.clone(), hits));
        }
    }
    best.map(|(version, _)| version)
}

fn platform_allows_peer_version(
    info: &lpm_resolver::CachedPackageInfo,
    version: &lpm_resolver::NpmVersion,
) -> bool {
    info.platform
        .get(&version.to_string())
        .is_none_or(lpm_resolver::is_platform_compatible)
}

fn package_should_materialize(package: &InstallPackage) -> Result<bool, LpmError> {
    if package_platform_compatible(package) {
        return Ok(true);
    }
    if package.optional {
        return Ok(false);
    }
    ensure_package_can_materialize(package)?;
    Ok(true)
}

fn ensure_package_can_materialize(package: &InstallPackage) -> Result<(), LpmError> {
    if package_platform_compatible(package) {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "{}@{} is incompatible with this platform",
        package.name, package.version
    )))
}

fn normalize_draft_optional_reachability(packages: &mut HashMap<PackageIdentity, PackageDraft>) {
    if packages.is_empty() {
        return;
    }

    let optional_dependency_names = optional_dependency_names_from_drafts(packages);
    let mut install_packages: Vec<InstallPackage> = packages
        .values()
        .map(|draft| draft.package.clone())
        .collect();
    normalize_install_package_optional_reachability(
        &mut install_packages,
        &optional_dependency_names,
    );
    for package in install_packages {
        let identity = (package.name.clone(), package.version.clone());
        if let Some(draft) = packages.get_mut(&identity) {
            draft.package.optional = package.optional;
        }
    }
}

fn optional_dependency_names_from_drafts(
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> HashMap<PackageIdentity, HashSet<String>> {
    packages
        .iter()
        .filter_map(|(identity, draft)| {
            draft
                .info
                .optional_dep_names
                .get(&draft.package.version)
                .cloned()
                .map(|names| (identity.clone(), names))
        })
        .collect()
}

fn optional_dependency_names_from_resolver_cache(
    packages: &[InstallPackage],
    resolver_cache: &HashMap<lpm_resolver::CanonicalKey, Arc<lpm_resolver::CachedPackageInfo>>,
) -> HashMap<PackageIdentity, HashSet<String>> {
    packages
        .iter()
        .filter_map(|package| {
            let canonical = lpm_resolver::CanonicalKey::from_dep_name(&package.name);
            resolver_cache
                .get(&canonical)
                .and_then(|info| info.optional_dep_names.get(&package.version))
                .cloned()
                .map(|names| ((package.name.clone(), package.version.clone()), names))
        })
        .collect()
}

fn normalize_install_package_optional_reachability(
    packages: &mut [InstallPackage],
    optional_dependency_names: &HashMap<PackageIdentity, HashSet<String>>,
) {
    if packages.is_empty() {
        return;
    }

    let mut by_identity: HashMap<PackageIdentity, Vec<usize>> =
        HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        by_identity
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(idx);
    }

    let mut required: HashSet<PackageIdentity> = HashSet::new();
    let mut queue = VecDeque::new();
    for package in packages.iter() {
        if package.root_link_names.is_some() || package.is_direct {
            let identity = (package.name.clone(), package.version.clone());
            required.insert(identity.clone());
            queue.push_back(identity);
        }
    }

    while let Some(identity) = queue.pop_front() {
        if let Some(indices) = by_identity.get(&identity) {
            for &idx in indices {
                let package = &packages[idx];
                let optional_names = optional_dependency_names.get(&identity);
                for (local_name, version) in &package.dependencies {
                    if optional_names.is_some_and(|names| names.contains(local_name)) {
                        continue;
                    }
                    let target_name = package
                        .aliases
                        .get(local_name)
                        .unwrap_or(local_name)
                        .clone();
                    let next = (target_name, version.clone());
                    if by_identity.contains_key(&next) && required.insert(next.clone()) {
                        queue.push_back(next);
                    }
                }
            }
        }
    }

    for package in packages {
        package.optional = !required.contains(&(package.name.clone(), package.version.clone()));
    }
}

fn lockfile_fetch_schedule(packages: &[InstallPackage]) -> Vec<InstallPackage> {
    let mut scheduled = packages.to_vec();
    scheduled.sort_by(|a, b| {
        b.is_direct
            .cmp(&a.is_direct)
            .then_with(|| b.dependencies.len().cmp(&a.dependencies.len()))
            .then_with(|| b.peers.len().cmp(&a.peers.len()))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
    scheduled
}

#[allow(clippy::too_many_arguments)]
fn spawn_missing_fetches_for_drafts(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut InstallerSpikeStats,
) -> Result<(), LpmError> {
    for draft in packages.values() {
        let package = &draft.package;
        if fetch_handles.contains_key(&install_pkg_key(package)) {
            continue;
        }
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                fetch_handles,
                stats,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_fetches_for_packages(
    packages: &[InstallPackage],
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    fetch_queue: &Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut InstallerSpikeStats,
) -> Result<(), LpmError> {
    for package in packages {
        if package_should_materialize(package)? {
            maybe_spawn_fetch(
                package.clone(),
                store,
                store_v2_handle.clone(),
                project_dir,
                Arc::clone(client),
                route_table.clone(),
                Arc::clone(fetch_queue),
                Arc::clone(&gate_stats),
                force,
                fetch_extract_limiter.clone(),
                fetch_handles,
                stats,
            );
        } else {
            stats.platform_pre_skipped += 1;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn maybe_spawn_fetch(
    package: InstallPackage,
    store: &PackageStore,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    project_dir: &Path,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    fetch_queue: Arc<Semaphore>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut InstallerSpikeStats,
) {
    let key = install_pkg_key(&package);
    if fetch_handles.contains_key(&key) {
        return;
    }
    let insert_key = key.clone();
    let package_display = format!("{}@{}", package.name, package.version);
    stats.fetch_dispatched += 1;
    let store = store.clone();
    let project_dir = project_dir.to_path_buf();
    let handle = tokio::spawn(async move {
        if is_local_source_package(&package) {
            if package.store_has_source_aware(&store, &project_dir) {
                return Ok(FetchOutcome {
                    key,
                    package_display,
                    computed_sri: package.integrity.clone(),
                    timings: None,
                    cached: true,
                });
            }
            package.store_path_or_err(&store, &project_dir, None)?;
            return Err(LpmError::Registry(format!(
                "local source package {}@{} is missing package.json",
                package.name, package.version
            )));
        }

        if !force
            && package.store_has_for_install_layout(
                &store,
                store_v2_handle.as_deref(),
                &project_dir,
            )
        {
            return Ok(FetchOutcome {
                key,
                package_display,
                computed_sri: package.integrity.clone(),
                timings: None,
                cached: true,
            });
        }

        let queue_start = Instant::now();
        let permit = fetch_queue
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LpmError::Registry("experimental installer queue closed".into()))?;
        let queue_wait_ms = queue_start.elapsed().as_millis();
        let (computed_sri, timings, _, _) = fetch_and_store_streaming(
            &client,
            &route_table,
            &store,
            store_v2_handle.as_deref(),
            &package,
            queue_wait_ms,
            &project_dir,
            TarballNotFoundRecovery::DeleteProjectLockfiles,
            &gate_stats,
            permit,
            &fetch_extract_limiter,
        )
        .await?;
        Ok(FetchOutcome {
            key,
            package_display,
            computed_sri: Some(computed_sri),
            timings: Some(timings),
            cached: false,
        })
    });
    fetch_handles.insert(insert_key, handle);
}

fn attach_peer_edges_to_drafts(packages: &mut HashMap<PackageIdentity, PackageDraft>) {
    let available: HashMap<String, Vec<(lpm_resolver::NpmVersion, String)>> = packages
        .values()
        .filter_map(|package| {
            let parsed = lpm_resolver::NpmVersion::parse(&package.package.version).ok()?;
            Some((
                package.package.name.clone(),
                (parsed, package.package.version.clone()),
            ))
        })
        .fold(HashMap::new(), |mut acc, (name, version)| {
            acc.entry(name).or_default().push(version);
            acc
        });

    for draft in packages.values_mut() {
        let Some(peer_deps) = draft.info.peer_deps.get(&draft.package.version) else {
            draft.package.peers.clear();
            continue;
        };
        let mut peers = Vec::with_capacity(peer_deps.len());
        for (peer_name, peer_range) in peer_deps {
            let Some(candidates) = available.get(peer_name) else {
                continue;
            };
            let Ok(range) = lpm_resolver::NpmRange::parse(peer_range) else {
                continue;
            };
            if let Some((_, version)) = candidates
                .iter()
                .filter(|(version, _)| range.satisfies(version))
                .max_by(|(left, _), (right, _)| left.cmp(right))
            {
                peers.push((peer_name.clone(), version.clone()));
            }
        }
        peers.sort();
        draft.package.peers = peers;
    }
}

fn build_experimental_link_targets(
    project_dir: &Path,
    store: &PackageStore,
    packages: &[InstallPackage],
    patch_fingerprints: &HashMap<(String, String), String>,
) -> Result<Vec<LinkTarget>, LpmError> {
    let source_index = source_dependency_index(packages);
    packages
        .iter()
        .map(|package| -> Result<LinkTarget, LpmError> {
            Ok(LinkTarget {
                name: package.name.clone(),
                version: package.version.clone(),
                store_path: package.store_path_or_err(store, project_dir, None)?,
                dependencies: link_dependencies_for_package(package, &source_index)?,
                aliases: package.aliases.clone(),
                is_direct: package.is_direct,
                root_link_names: package.root_link_names.clone(),
                wrapper_id: package.wrapper_id_for_source(),
                materialization: package.materialization_for_source(),
                peers: package.peers.clone(),
                patch_fingerprint: patch_fingerprints
                    .get(&(package.name.clone(), package.version.clone()))
                    .cloned(),
            })
        })
        .collect::<Result<_, _>>()
}

#[allow(clippy::too_many_arguments)]
fn link_experimental_targets(
    project_dir: &Path,
    store_v2: Option<&lpm_store::v2::Store>,
    packages: &[InstallPackage],
    link_targets: &[LinkTarget],
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    self_package_name: Option<&str>,
    compatibility_bin_names: &[String],
) -> Result<LinkResult, LpmError> {
    if let Some(store_v2) = store_v2 {
        let v2_targets = build_v2_targets(packages, link_targets)?;
        return lpm_linker::v2::link_packages_v2_with_compatibility_bin_names(
            project_dir,
            v2_targets,
            store_v2,
            linker_mode,
            self_package_name,
            compatibility_bin_names,
        );
    }

    match linker_mode {
        lpm_linker::LinkerMode::Hoisted => {
            lpm_linker::link_packages_hoisted(project_dir, link_targets, force, self_package_name)
        }
        lpm_linker::LinkerMode::Isolated => {
            lpm_linker::link_packages(project_dir, link_targets, force, self_package_name)
        }
    }
}

async fn finish_v2_event_driven_link(
    project_dir: &Path,
    plan: &Arc<lpm_linker::v2::LinkPlanV2>,
    store_v2: &lpm_store::v2::Store,
    mut v2_link_handles: Vec<V2LinkHandle>,
    self_package_name: Option<&str>,
    timing_detail_mode: TimingDetailMode,
    slow_package_timings: &mut SlowPackageTimings,
) -> Result<LinkOutcomeWithTimings, LpmError> {
    let await_start = Instant::now();
    let mut materialized = Vec::with_capacity(v2_link_handles.len());
    let mut linked = 0usize;
    for handle in v2_link_handles.drain(..) {
        let task = handle.await.map_err(|e| {
            LpmError::Registry(format!("experimental v2 link task panicked: {e}"))
        })??;
        if timing_detail_mode.trace() {
            let package_display =
                format!("{}@{}", task.materialized.name, task.materialized.version);
            slow_package_timings.record_link_v2_one(&package_display, task.ms, task.timings);
        }
        if task.freshly_populated {
            linked += 1;
        }
        materialized.push(task.materialized);
    }
    let task_await_ms = await_start.elapsed().as_millis();
    let finalize_start = Instant::now();
    let finalize =
        lpm_linker::v2::link_v2_finalize(project_dir, plan, store_v2, self_package_name)?;
    let finalize_ms = finalize_start.elapsed().as_millis();
    Ok(LinkOutcomeWithTimings {
        result: LinkResult {
            linked,
            symlinked: finalize.symlinked,
            bin_linked: finalize.bin_count,
            skipped: plan.augmented_targets.len().saturating_sub(linked),
            self_referenced: finalize.self_referenced,
            materialized,
        },
        task_await_ms,
        finalize_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benchmark_admission() -> InstallerSpikeAdmission {
        InstallerSpikeAdmission {
            json_output: true,
            frozen_lockfile_active: true,
            omit_policy: InstallOmitPolicy::default(),
            has_workspace_member_deps: false,
            has_v2_workspace_member_deps: false,
            has_tarball_source_deps: false,
            verify_registry_signatures: false,
            strict_integrity: false,
            force_security_floor: false,
            npm_firewall_enabled: false,
            policy_extensions_enabled: false,
            auto_build: false,
            script_policy_override: None,
            script_policy_is_default: true,
            has_trusted_dependencies: false,
            strict_release_age_replay: false,
            allow_new: false,
            is_add_invocation: false,
            has_direct_versions_out: false,
            has_target_set: false,
            audit_after_install: false,
            no_skills: true,
            no_security_summary: true,
            verbose: false,
            drift_ignore_policy_is_default: true,
            verify_policy_is_default: true,
        }
    }

    fn fake_package(name: &str, version: &str, deps: &[(&str, &str)]) -> InstallPackage {
        InstallPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: deps
                .iter()
                .map(|(name, version)| (name.to_string(), version.to_string()))
                .collect(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct: false,
            is_lpm: false,
            peers: Vec::new(),
            integrity: Some(format!("sha512-{name}-{version}")),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            optional: false,
            tarball_url: Some(format!(
                "https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
            )),
            metadata_checked_for_tarball: true,
        }
    }

    #[test]
    fn package_materialization_skips_optional_platform_incompatible_package() {
        let mut package = fake_package("platform-leaf", "1.0.0", &[]);
        package.optional = true;
        package.platform = Some(lpm_resolver::PlatformMeta {
            os: vec!["definitely-not-this-os".to_string()],
            cpu: Vec::new(),
            libc: Vec::new(),
        });

        assert!(!package_should_materialize(&package).unwrap());
    }

    #[test]
    fn metadata_concurrency_default_uses_measured_stable_value() {
        assert_eq!(DEFAULT_INSTALLER_SPIKE_METADATA_CONCURRENCY, 192);
    }

    #[test]
    fn parity_mode_parses_lockfile_deny_without_environment_mutation() {
        assert_eq!(
            InstallerSpikeParityMode::from_value(Some("lockfile-deny")),
            InstallerSpikeParityMode::Lockfile { deny: true }
        );
    }

    #[test]
    fn graph_source_parses_lockfile_without_environment_mutation() {
        assert_eq!(
            InstallerSpikeGraphSource::from_value(Some("lockfile")),
            InstallerSpikeGraphSource::Lockfile
        );
    }

    #[test]
    fn graph_source_defaults_to_resolve_worklist_when_unset() {
        assert_eq!(
            InstallerSpikeGraphSource::from_value(None),
            InstallerSpikeGraphSource::ResolveWorklist
        );
    }

    #[test]
    fn graph_source_parses_explicit_resolve_worklist_without_environment_mutation() {
        assert_eq!(
            InstallerSpikeGraphSource::from_value(Some("resolve-worklist")),
            InstallerSpikeGraphSource::ResolveWorklist
        );
    }

    #[test]
    fn graph_source_rejects_unknown_explicit_value() {
        assert_eq!(
            InstallerSpikeGraphSource::from_value(Some("unexpected")),
            InstallerSpikeGraphSource::Invalid
        );
    }

    #[test]
    fn admission_accepts_frozen_lockfile_benchmark_shape() {
        let reasons = unsupported_admission_reasons(
            benchmark_admission(),
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::Disabled,
            true,
        );

        assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
    }

    #[test]
    fn admission_accepts_live_resolve_worklist_benchmark_shape() {
        let mut admission = benchmark_admission();
        admission.frozen_lockfile_active = false;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::ResolveWorklist,
            InstallerSpikeParityMode::FreshResolve { deny: true },
            true,
        );

        assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
    }

    #[test]
    fn admission_rejects_live_resolve_worklist_without_deny_parity() {
        let mut admission = benchmark_admission();
        admission.frozen_lockfile_active = false;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::ResolveWorklist,
            InstallerSpikeParityMode::Disabled,
            true,
        );

        assert_eq!(
            reasons,
            vec!["set LPM_INSTALLER_SPIKE_PARITY=deny for live graph parity"]
        );
    }

    #[test]
    fn admission_rejects_unknown_explicit_graph_value() {
        let reasons = unsupported_admission_reasons(
            benchmark_admission(),
            InstallerSpikeGraphSource::Invalid,
            InstallerSpikeParityMode::FreshResolve { deny: true },
            true,
        );

        assert_eq!(
            reasons,
            vec!["set LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist or lockfile"]
        );
    }

    #[test]
    fn admission_rejects_live_resolve_worklist_for_frozen_installs() {
        let reasons = unsupported_admission_reasons(
            benchmark_admission(),
            InstallerSpikeGraphSource::ResolveWorklist,
            InstallerSpikeParityMode::FreshResolve { deny: true },
            true,
        );

        assert_eq!(
            reasons,
            vec!["set LPM_INSTALLER_SPIKE_GRAPH=lockfile for frozen installs"]
        );
    }

    #[test]
    fn admission_requires_benchmark_ack_and_frozen_lockfile_for_lockfile_graph() {
        let mut admission = benchmark_admission();
        admission.frozen_lockfile_active = false;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::FreshResolve { deny: false },
            false,
        );

        assert!(reasons.contains(&"set LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1"));
        assert!(reasons.contains(&"use lockfile parity or disable parity"));
        assert!(reasons.contains(&"use a frozen lockfile install"));
    }

    #[test]
    fn admission_rejects_install_contracts_spike_does_not_implement() {
        let mut admission = benchmark_admission();
        admission.omit_policy.dev = true;
        admission.has_workspace_member_deps = true;
        admission.verify_registry_signatures = true;
        admission.npm_firewall_enabled = true;
        admission.audit_after_install = true;
        admission.script_policy_is_default = false;
        admission.has_trusted_dependencies = true;
        admission.strict_release_age_replay = true;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::Lockfile { deny: true },
            true,
        );

        assert!(reasons.contains(&"--prod/--omit=dev is not supported"));
        assert!(reasons.contains(&"workspace member links require resolve-worklist graph mode"));
        assert!(!reasons.contains(&"overrides are not supported"));
        assert!(!reasons.contains(&"patches are not supported"));
        assert!(reasons.contains(&"registry signature verification is not supported"));
        assert!(reasons.contains(&"npm firewall is not supported"));
        assert!(reasons.contains(&"audit-after-install is not supported"));
        assert!(reasons.contains(&"script policy/build execution options are not supported"));
        assert!(reasons.contains(&"strict minimumReleaseAge lockfile replay is not supported"));
    }

    #[test]
    fn admission_accepts_workspace_member_links_for_live_resolve_worklist() {
        let mut admission = benchmark_admission();
        admission.frozen_lockfile_active = false;
        admission.has_workspace_member_deps = true;
        admission.has_v2_workspace_member_deps = true;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::ResolveWorklist,
            InstallerSpikeParityMode::FreshResolve { deny: true },
            true,
        );

        assert!(reasons.is_empty(), "unexpected reasons: {reasons:?}");
    }

    #[test]
    fn admission_rejects_tarball_source_deps() {
        let mut admission = benchmark_admission();
        admission.has_tarball_source_deps = true;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::Disabled,
            true,
        );

        assert_eq!(reasons, vec!["tarball source deps are not supported"]);
    }

    #[test]
    fn admission_rejects_policy_extensions() {
        let mut admission = benchmark_admission();
        admission.policy_extensions_enabled = true;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::Disabled,
            true,
        );

        assert_eq!(reasons, vec!["policy extensions are not supported"]);
    }

    #[test]
    fn admission_rejects_trusted_dependencies_without_other_script_policy_changes() {
        let mut admission = benchmark_admission();
        admission.has_trusted_dependencies = true;

        let reasons = unsupported_admission_reasons(
            admission,
            InstallerSpikeGraphSource::Lockfile,
            InstallerSpikeParityMode::Disabled,
            true,
        );

        assert_eq!(
            reasons,
            vec!["script policy/build execution options are not supported"]
        );
    }

    #[test]
    fn lockfile_fetch_schedule_prioritizes_direct_roots_then_fanout() {
        let mut direct = fake_package("direct-root", "1.0.0", &[]);
        direct.is_direct = true;
        let high_fanout = fake_package(
            "high-fanout",
            "1.0.0",
            &[("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
        );
        let low_fanout = fake_package("low-fanout", "1.0.0", &[("a", "1.0.0")]);

        let scheduled = lockfile_fetch_schedule(&[low_fanout, high_fanout, direct]);
        let names: Vec<_> = scheduled
            .iter()
            .map(|package| package.name.as_str())
            .collect();

        assert_eq!(names, vec!["direct-root", "high-fanout", "low-fanout"]);
    }

    fn empty_info_value() -> lpm_resolver::CachedPackageInfo {
        lpm_resolver::CachedPackageInfo {
            modified: None,
            modified_unix: None,
            trust_metadata_complete: false,
            versions_complete: true,
            covered_ranges: HashSet::new(),
            versions: Vec::new(),
            deps: HashMap::new(),
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    fn empty_info() -> Arc<lpm_resolver::CachedPackageInfo> {
        Arc::new(empty_info_value())
    }

    fn fake_draft(name: &str, version: &str, deps: &[(&str, &str)]) -> PackageDraft {
        PackageDraft {
            package: fake_package(name, version, deps),
            info: empty_info(),
        }
    }

    fn resolve_request_for_test(
        name: &str,
        range: &str,
        parent: Option<PackageIdentity>,
        root: bool,
        direct: bool,
    ) -> ResolveRequest {
        let depth = if root { 0 } else { 1 };
        let root_ancestor = parent
            .as_ref()
            .map_or_else(|| name.to_string(), |(name, _)| name.clone());
        ResolveRequest {
            local_name: name.to_string(),
            target_name: name.to_string(),
            range: range.to_string(),
            parent,
            root_ancestor,
            depth,
            optional: false,
            root,
            direct,
        }
    }

    fn package_set_for_completion_order(
        requests: Vec<ResolveRequest>,
        info: Arc<lpm_resolver::CachedPackageInfo>,
    ) -> Vec<InstallPackage> {
        let mut packages = HashMap::new();
        for request in requests {
            let node = select_or_reuse_node(
                request,
                Arc::clone(&info),
                &mut packages,
                &OverrideSet::empty(),
                &lpm_resolver::ResolverPolicy::default(),
            )
            .unwrap()
            .unwrap();
            if node.reused_existing {
                continue;
            }
            packages.insert(
                (node.request.target_name.clone(), node.version.clone()),
                fake_draft(&node.request.target_name, &node.version, &[]),
            );
        }
        let mut packages: Vec<_> = packages.into_values().map(|draft| draft.package).collect();
        packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
        packages
    }

    fn info_with_versions(versions: &[&str]) -> lpm_resolver::CachedPackageInfo {
        let mut info = empty_info_value();
        info.versions = versions
            .iter()
            .map(|version| {
                lpm_resolver::NpmVersion::parse(version).expect("test version should parse")
            })
            .collect();
        info
    }

    fn override_set(key: &str, target: &str) -> OverrideSet {
        let lpm = HashMap::from([(key.to_string(), target.to_string())]);
        OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new())
            .expect("test override should parse")
    }

    fn fake_metadata_timing(
        package: &str,
        total_ms: u128,
        raw_fetch_ms: u128,
        http_ms: u128,
        json_decode_ms: u128,
        cache_info_parse_ms: u128,
    ) -> lpm_resolver::ExperimentalMetadataFetchTimings {
        lpm_resolver::ExperimentalMetadataFetchTimings {
            package: package.to_string(),
            route: "npm_direct",
            total_ms,
            raw_fetch_ms,
            cache_read_ms: 1,
            validator_read_ms: 2,
            http_ms,
            body_read_ms: 3,
            json_decode_ms,
            cache_write_dispatch_ms: 4,
            cache_info_parse_ms,
            body_bytes: 1024,
            version_count: 7,
            cache_hit: false,
            not_modified: false,
            ..lpm_resolver::ExperimentalMetadataFetchTimings::default()
        }
    }

    #[test]
    fn metadata_stats_reports_attribution_sums_and_trace_rows() {
        let stats = MetadataStats::new(Instant::now());
        let first_request = resolve_request_for_test("fast", "^1.0.0", None, true, true);
        let first_context = MetadataRequestContext::from_request(&first_request);
        stats.record_range_call(&first_context);
        stats.record_range_initial_fetch(&first_context);
        stats.record_detail(
            first_context,
            fake_metadata_timing("fast", 10, 8, 5, 1, 2),
            1,
            11,
            true,
        );
        let second_request = resolve_request_for_test("slow", "2.0.0", None, true, true);
        let mut second_context = MetadataRequestContext::from_request(&second_request);
        second_context.version_doc_eligible = true;
        stats.record_range_call(&second_context);
        stats.record_range_initial_fetch(&second_context);
        stats.record_detail(
            second_context,
            fake_metadata_timing("slow", 40, 30, 20, 7, 11),
            12,
            55,
            true,
        );

        let json = stats.to_json(true);

        assert_eq!(json["attribution"]["raw_fetch_sum_ms"].as_u64(), Some(38));
        assert_eq!(json["attribution"]["http_sum_ms"].as_u64(), Some(25));
        assert_eq!(
            json["attribution"]["cache_info_parse_sum_ms"].as_u64(),
            Some(13)
        );
        assert_eq!(
            json["attribution"]["routes"]["npm_direct"].as_u64(),
            Some(2)
        );
        assert_eq!(
            json["attribution"]["range_shapes"]["package_first_fetches"]["caret"].as_u64(),
            Some(1)
        );
        assert_eq!(
            json["attribution"]["range_shapes"]["package_first_fetches"]["exact"].as_u64(),
            Some(1)
        );
        assert_eq!(
            json["attribution"]["range_shapes"]["version_doc_eligible_package_first_fetches"]
                .as_u64(),
            Some(1)
        );
        assert_eq!(
            json["attribution"]["range_shapes"]["packages"]["seen"].as_u64(),
            Some(2)
        );
        assert_eq!(
            json["attribution"]["range_shapes"]["packages"]["version_doc_eligible_exact_only"]
                .as_u64(),
            Some(1)
        );
        assert_eq!(
            json["slow_metadata"]["by_total"][0]["package"].as_str(),
            Some("slow")
        );
        assert_eq!(
            json["slow_metadata"]["by_completed_at"][0]["completed_at_ms"].as_u64(),
            Some(55)
        );
        assert_eq!(
            json["slow_metadata"]["by_total"][0]["root_ancestor"].as_str(),
            Some("slow")
        );
        assert_eq!(
            json["slow_metadata"]["by_cache_info_parse"][0]["package"].as_str(),
            Some("slow")
        );
        assert_eq!(
            json["slow_metadata"]["by_cache_read"][0]["route"].as_str(),
            Some("npm_direct")
        );
        assert_eq!(
            json["slow_metadata"]["by_total"][0]["range"].as_str(),
            Some("2.0.0")
        );
        assert_eq!(
            json["slow_metadata"]["by_total"][0]["range_shape"].as_str(),
            Some("exact")
        );
        assert_eq!(
            json["slow_metadata"]["by_total"][0]["version_doc_eligible"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn metadata_stats_omits_slow_rows_without_trace() {
        let stats = MetadataStats::new(Instant::now());
        stats.record_detail(
            MetadataRequestContext::peer_plan("slow"),
            fake_metadata_timing("slow", 40, 30, 20, 7, 11),
            0,
            40,
            false,
        );

        let json = stats.to_json(false);

        assert!(json.get("slow_metadata").is_none());
        assert!(json.get("waves_by_depth").is_none());
        assert_eq!(json["attribution"]["raw_fetch_sum_ms"].as_u64(), Some(30));
    }

    #[test]
    fn metadata_range_shape_classifies_common_npm_ranges() {
        assert_eq!(
            MetadataRangeShape::from_range(Some("1.2.3")),
            MetadataRangeShape::Exact
        );
        assert_eq!(
            MetadataRangeShape::from_range(Some("=1.2.3")),
            MetadataRangeShape::Exact
        );
        assert_eq!(
            MetadataRangeShape::from_range(Some("^1.2.3")),
            MetadataRangeShape::Caret
        );
        assert_eq!(
            MetadataRangeShape::from_range(Some("~1.2.3")),
            MetadataRangeShape::Tilde
        );
        assert_eq!(
            MetadataRangeShape::from_range(Some(">=1.2.3")),
            MetadataRangeShape::Comparator
        );
        assert_eq!(
            MetadataRangeShape::from_range(Some("^1.0.0 || ^2.0.0")),
            MetadataRangeShape::Complex
        );
        assert_eq!(
            MetadataRangeShape::from_range(None),
            MetadataRangeShape::Unknown
        );
    }

    #[test]
    fn metadata_package_range_summary_separates_mixed_exact_and_broad_packages() {
        let stats = MetadataStats::new(Instant::now());

        let mut exact_only = MetadataRequestContext::from_request(&resolve_request_for_test(
            "exact-only",
            "=1.2.3",
            None,
            true,
            true,
        ));
        exact_only.version_doc_eligible = true;
        stats.record_range_call(&exact_only);

        let mut mixed_exact = MetadataRequestContext::from_request(&resolve_request_for_test(
            "mixed", "2.0.0", None, true, true,
        ));
        mixed_exact.version_doc_eligible = true;
        stats.record_range_call(&mixed_exact);
        let mixed_broad = MetadataRequestContext::from_request(&resolve_request_for_test(
            "mixed", "^2.0.0", None, true, true,
        ));
        stats.record_range_call(&mixed_broad);

        let packages = &stats.to_json(false)["attribution"]["range_shapes"]["packages"];

        assert_eq!(packages["seen"].as_u64(), Some(2));
        assert_eq!(
            packages["version_doc_eligible_exact_only_single_version"].as_u64(),
            Some(1)
        );
        assert_eq!(packages["mixed_exact_and_non_exact"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn exact_version_metadata_cache_does_not_satisfy_broad_request() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let name = "cache-split";

        Mock::given(method("GET"))
            .and(path(format!("/{name}/1.0.0")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/cache-split-1.0.0.tgz",
                    "integrity": "sha512-one"
                },
                "dependencies": {}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": "https://example.com/cache-split-1.0.0.tgz",
                            "integrity": "sha512-one"
                        },
                        "dependencies": {}
                    },
                    "2.0.0": {
                        "name": name,
                        "version": "2.0.0",
                        "dist": {
                            "tarball": "https://example.com/cache-split-2.0.0.tgz",
                            "integrity": "sha512-two"
                        },
                        "dependencies": {}
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let registry = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(tmp.path().to_path_buf()));
        let client = Arc::new(registry);
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let caches = MetadataCaches::new();
        let queue = Arc::new(Semaphore::new(4));
        let stats = Arc::new(MetadataStats::new(Instant::now()));
        let policy = lpm_resolver::ResolverPolicy::default();

        let mut exact_context = MetadataRequestContext::from_request(&resolve_request_for_test(
            name, "1.0.0", None, true, true,
        ));
        exact_context.version_doc_eligible = true;
        let exact_info = metadata_for_exact_version(
            exact_context,
            name.to_string(),
            "1.0.0".to_string(),
            Arc::clone(&client),
            route_table.clone(),
            caches.clone(),
            Arc::clone(&queue),
            Arc::clone(&stats),
            policy.clone(),
            0,
        )
        .await
        .expect("exact version metadata should resolve");

        let full_info = metadata_for_full_package(
            MetadataRequestContext::from_request(&resolve_request_for_test(
                name, "^1.0.0", None, true, true,
            )),
            name.to_string(),
            client,
            route_table,
            caches.clone(),
            queue,
            stats,
            policy,
            0,
        )
        .await
        .expect("broad metadata should resolve through full packument cache");

        assert_eq!(exact_info.versions.len(), 1);
        assert_eq!(full_info.versions.len(), 2);
        assert_eq!(caches.exact_version.len(), 1);
        assert_eq!(caches.full.len(), 1);
    }

    #[tokio::test]
    async fn exact_version_metadata_fallback_populates_full_cache() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = crate::test_env::ScopedEnv::set([(
            ENV_INSTALLER_SPIKE_EXACT_DOC,
            std::ffi::OsString::from("1"),
        )]);
        let server = MockServer::start().await;
        let name = "cache-fallback";

        Mock::given(method("GET"))
            .and(path(format!("/{name}/1.0.0")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "wrong-package",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/wrong-package-1.0.0.tgz",
                    "integrity": "sha512-wrong"
                },
                "dependencies": {}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": name,
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": name,
                        "version": "1.0.0",
                        "dist": {
                            "tarball": "https://example.com/cache-fallback-1.0.0.tgz",
                            "integrity": "sha512-one"
                        },
                        "dependencies": {}
                    },
                    "2.0.0": {
                        "name": name,
                        "version": "2.0.0",
                        "dist": {
                            "tarball": "https://example.com/cache-fallback-2.0.0.tgz",
                            "integrity": "sha512-two"
                        },
                        "dependencies": {}
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let registry = RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(tmp.path().to_path_buf()));
        let client = Arc::new(registry);
        let route_table = lpm_registry::RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let caches = MetadataCaches::new();
        let queue = Arc::new(Semaphore::new(1));
        let stats = Arc::new(MetadataStats::new(Instant::now()));
        let policy = lpm_resolver::ResolverPolicy::default();

        let exact_info = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            metadata_for_package(
                MetadataRequestContext::from_request(&resolve_request_for_test(
                    name, "1.0.0", None, true, true,
                )),
                Arc::clone(&client),
                route_table.clone(),
                caches.clone(),
                Arc::clone(&queue),
                Arc::clone(&stats),
                policy.clone(),
            ),
        )
        .await
        .expect("fallback must not deadlock while metadata concurrency is one")
        .expect("exact-doc fallback should resolve through full metadata");
        let broad_info = metadata_for_package(
            MetadataRequestContext::from_request(&resolve_request_for_test(
                name, "^1.0.0", None, true, true,
            )),
            client,
            route_table,
            caches.clone(),
            queue,
            Arc::clone(&stats),
            policy,
        )
        .await
        .expect("broad request should reuse the populated full cache");

        assert_eq!(exact_info.versions.len(), 2);
        assert_eq!(broad_info.versions.len(), 2);
        assert_eq!(caches.exact_version.len(), 1);
        assert_eq!(caches.full.len(), 1);
        let json = stats.to_json(false);
        assert_eq!(
            json["attribution"]["version_docs"]["attempts"].as_u64(),
            Some(1)
        );
        assert_eq!(
            json["attribution"]["version_docs"]["fallbacks"].as_u64(),
            Some(1)
        );
        assert_eq!(
            json["attribution"]["version_docs"]["hits"].as_u64(),
            Some(0)
        );
    }

    #[test]
    fn reused_dependency_edge_attaches_parent_without_resolving_again() {
        let mut packages = HashMap::new();
        packages.insert(
            ("parent".to_string(), "1.0.0".to_string()),
            fake_draft("parent", "1.0.0", &[]),
        );
        packages.insert(
            ("child".to_string(), "1.2.3".to_string()),
            fake_draft("child", "1.2.3", &[]),
        );
        let request = resolve_request_for_test(
            "child",
            "^1.0.0",
            Some(("parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );

        attach_reused_dependency_edge(&mut packages, &request, "1.2.3").unwrap();

        assert_eq!(
            packages
                .get(&("parent".to_string(), "1.0.0".to_string()))
                .unwrap()
                .package
                .dependencies,
            vec![("child".to_string(), "1.2.3".to_string())]
        );
    }

    #[test]
    fn inline_reuse_defers_optional_to_required_promotion() {
        let mut packages = HashMap::new();
        let mut child = fake_draft("child", "1.2.3", &[]);
        child.package.optional = true;
        packages.insert(("child".to_string(), "1.2.3".to_string()), child);
        let request = resolve_request_for_test(
            "child",
            "^1.0.0",
            Some(("parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );

        assert!(!inline_reuse_can_preserve_optional_state(&packages, &request, "1.2.3").unwrap());
    }

    #[test]
    fn optional_reachability_marks_reused_optional_descendants_required() {
        let mut packages = HashMap::new();
        let mut required_parent = fake_draft("required-parent", "1.0.0", &[("shared", "1.0.0")]);
        required_parent.package.root_link_names = Some(vec!["required-parent".to_string()]);

        let mut optional_parent = fake_draft("optional-parent", "1.0.0", &[("shared", "1.0.0")]);
        optional_parent.package.root_link_names = Some(vec!["optional-parent".to_string()]);
        let mut optional_parent_info = empty_info_value();
        optional_parent_info
            .optional_dep_names
            .insert("1.0.0".to_string(), HashSet::from(["shared".to_string()]));
        optional_parent.info = Arc::new(optional_parent_info);

        let mut shared = fake_draft("shared", "1.0.0", &[("leaf", "1.0.0")]);
        shared.package.optional = true;
        let mut leaf = fake_draft("leaf", "1.0.0", &[]);
        leaf.package.optional = true;

        packages.insert(
            ("required-parent".to_string(), "1.0.0".to_string()),
            required_parent,
        );
        packages.insert(
            ("optional-parent".to_string(), "1.0.0".to_string()),
            optional_parent,
        );
        packages.insert(("shared".to_string(), "1.0.0".to_string()), shared);
        packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

        normalize_draft_optional_reachability(&mut packages);

        assert!(
            !packages
                .get(&("shared".to_string(), "1.0.0".to_string()))
                .unwrap()
                .package
                .optional
        );
        assert!(
            !packages
                .get(&("leaf".to_string(), "1.0.0".to_string()))
                .unwrap()
                .package
                .optional
        );
    }

    #[test]
    fn optional_reachability_keeps_optional_only_subtree_optional() {
        let mut packages = HashMap::new();
        let mut parent = fake_draft("parent", "1.0.0", &[("child", "1.0.0")]);
        parent.package.root_link_names = Some(vec!["parent".to_string()]);
        let mut parent_info = empty_info_value();
        parent_info
            .optional_dep_names
            .insert("1.0.0".to_string(), HashSet::from(["child".to_string()]));
        parent.info = Arc::new(parent_info);

        let mut child = fake_draft("child", "1.0.0", &[("leaf", "1.0.0")]);
        child.package.optional = false;
        let mut leaf = fake_draft("leaf", "1.0.0", &[]);
        leaf.package.optional = false;

        packages.insert(("parent".to_string(), "1.0.0".to_string()), parent);
        packages.insert(("child".to_string(), "1.0.0".to_string()), child);
        packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

        normalize_draft_optional_reachability(&mut packages);

        assert!(
            packages
                .get(&("child".to_string(), "1.0.0".to_string()))
                .unwrap()
                .package
                .optional
        );
        assert!(
            packages
                .get(&("leaf".to_string(), "1.0.0".to_string()))
                .unwrap()
                .package
                .optional
        );
    }

    #[test]
    fn package_parity_reports_extra_and_missing_packages() {
        let candidate = vec![
            fake_package("shared", "1.0.0", &[]),
            fake_package("candidate-only", "1.0.0", &[]),
        ];
        let baseline = vec![
            fake_package("shared", "1.0.0", &[]),
            fake_package("baseline-only", "1.0.0", &[]),
        ];

        let parity =
            compare_package_parity_with_baseline(&candidate, &baseline, "install-packages");

        assert!(!parity.matches);
        assert_eq!(parity.candidate_count, 2);
        assert_eq!(parity.baseline_count, 2);
        assert_eq!(parity.count_delta, 0);
        assert_eq!(parity.extra_count, 1);
        assert_eq!(parity.missing_count, 1);
        assert!(parity.extra[0].contains("candidate-only@1.0.0"));
        assert!(parity.missing[0].contains("baseline-only@1.0.0"));
    }

    #[test]
    fn package_parity_reports_dependency_fingerprint_mismatch() {
        let candidate = vec![fake_package("shared", "1.0.0", &[("left", "1.0.0")])];
        let baseline = vec![fake_package("shared", "1.0.0", &[("right", "1.0.0")])];

        let parity =
            compare_package_parity_with_baseline(&candidate, &baseline, "install-packages");

        assert!(!parity.matches);
        assert_eq!(parity.extra_count, 0);
        assert_eq!(parity.missing_count, 0);
        assert_eq!(parity.fingerprint_mismatch_count, 1);
        assert_eq!(
            parity.fingerprint_mismatches[0].candidate.dependencies,
            vec![("left".to_string(), "1.0.0".to_string())]
        );
        assert_eq!(
            parity.fingerprint_mismatches[0].baseline.dependencies,
            vec![("right".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn package_parity_catches_completion_order_dependent_reuse() {
        let info = Arc::new(info_with_versions(&["1.9.0", "1.0.5", "1.0.0"]));
        let narrow = resolve_request_for_test(
            "shared",
            "~1.0.0",
            Some(("narrow-parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );
        let broad = resolve_request_for_test(
            "shared",
            "^1.0.0",
            Some(("broad-parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );

        let narrow_first = package_set_for_completion_order(
            vec![narrow.clone(), broad.clone()],
            Arc::clone(&info),
        );
        let broad_first = package_set_for_completion_order(vec![broad, narrow], info);

        let parity =
            compare_package_parity_with_baseline(&narrow_first, &broad_first, "completion-order");

        assert!(!parity.matches);
        assert_eq!(parity.candidate_count, 1);
        assert_eq!(parity.baseline_count, 2);
        assert_eq!(parity.missing_count, 1);
        assert!(parity.missing[0].contains("shared@1.9.0"));
    }

    #[test]
    fn reusable_existing_version_prefers_newest_satisfying_non_root_package() {
        let mut packages = HashMap::new();
        packages.insert(
            ("dep".to_string(), "1.0.0".to_string()),
            fake_draft("dep", "1.0.0", &[]),
        );
        packages.insert(
            ("dep".to_string(), "1.5.0".to_string()),
            fake_draft("dep", "1.5.0", &[]),
        );
        packages.insert(
            ("dep".to_string(), "2.0.0".to_string()),
            fake_draft("dep", "2.0.0", &[]),
        );
        let request = resolve_request_for_test(
            "dep",
            "^1.0.0",
            Some(("parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );

        let selected = reusable_existing_version(&request, &packages).unwrap();

        assert_eq!(selected.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn reusable_existing_version_does_not_reuse_for_root_package() {
        let mut packages = HashMap::new();
        packages.insert(
            ("dep".to_string(), "1.0.0".to_string()),
            fake_draft("dep", "1.0.0", &[]),
        );
        let request = resolve_request_for_test("dep", "^1.0.0", None, true, true);

        let selected = reusable_existing_version(&request, &packages).unwrap();

        assert_eq!(selected, None);
    }

    #[test]
    fn select_or_reuse_node_honors_name_override_before_range_reuse() {
        let mut packages = HashMap::new();
        packages.insert(
            ("dep".to_string(), "1.0.0".to_string()),
            fake_draft("dep", "1.0.0", &[]),
        );
        packages.insert(
            ("dep".to_string(), "1.5.0".to_string()),
            fake_draft("dep", "1.5.0", &[]),
        );
        let request = resolve_request_for_test(
            "dep",
            "^1.0.0",
            Some(("parent".to_string(), "1.0.0".to_string())),
            false,
            false,
        );
        let info = Arc::new(info_with_versions(&["1.5.0", "1.0.0"]));
        let overrides = override_set("dep", "1.5.0");

        let node = select_or_reuse_node(
            request,
            info,
            &mut packages,
            &overrides,
            &lpm_resolver::ResolverPolicy::default(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(node.version, "1.5.0");
        assert!(node.reused_existing);
        assert_eq!(overrides.take_hits().len(), 1);
    }

    #[test]
    fn select_or_reuse_node_honors_path_override_before_satisfying_reuse() {
        let mut packages = HashMap::new();
        packages.insert(
            ("ajv".to_string(), "8.20.0".to_string()),
            fake_draft("ajv", "8.20.0", &[]),
        );
        let request = resolve_request_for_test(
            "ajv",
            "^8.0.0",
            Some(("schema-utils".to_string(), "4.3.3".to_string())),
            false,
            false,
        );
        let info = Arc::new(info_with_versions(&["8.20.0", "8.18.0"]));
        let overrides = override_set("schema-utils>ajv", "8.18.0");

        let node = select_or_reuse_node(
            request,
            info,
            &mut packages,
            &overrides,
            &lpm_resolver::ResolverPolicy::default(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(node.version, "8.18.0");
        assert!(!node.reused_existing);
        assert_eq!(overrides.take_hits().len(), 1);
    }

    #[test]
    fn mark_required_closure_marks_existing_optional_descendants_required() {
        let mut packages = HashMap::new();
        let mut parent = fake_draft("parent", "1.0.0", &[("child", "1.0.0")]);
        parent.package.optional = true;
        let mut child = fake_draft("child", "1.0.0", &[("leaf", "1.0.0")]);
        child.package.optional = true;
        let mut leaf = fake_draft("leaf", "1.0.0", &[]);
        leaf.package.optional = true;
        packages.insert(("parent".to_string(), "1.0.0".to_string()), parent);
        packages.insert(("child".to_string(), "1.0.0".to_string()), child);
        packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

        mark_required_closure(&mut packages, &("parent".to_string(), "1.0.0".to_string()));

        assert!(packages.values().all(|draft| !draft.package.optional));
    }
}
