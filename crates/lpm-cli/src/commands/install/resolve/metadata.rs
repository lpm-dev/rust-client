use super::super::*;
use super::ResolveRequest;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::OnceCell;

const ENV_INSTALLER_SPIKE_EXACT_DOC: &str = "LPM_INSTALLER_SPIKE_EXACT_DOC";

type MetadataCell = Arc<OnceCell<Arc<lpm_resolver::CachedPackageInfo>>>;
type MetadataCache = Arc<dashmap::DashMap<String, MetadataCell>>;
type ExactVersionMetadataCache = Arc<dashmap::DashMap<ExactVersionMetadataKey, MetadataCell>>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct ExactVersionMetadataKey {
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
pub(in crate::commands::install) struct MetadataCaches {
    full: MetadataCache,
    exact_version: ExactVersionMetadataCache,
}

impl MetadataCaches {
    pub(in crate::commands::install) fn new() -> Self {
        Self {
            full: Arc::new(dashmap::DashMap::new()),
            exact_version: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub(in crate::commands::install) fn request_count(&self) -> usize {
        self.full.len().saturating_add(self.exact_version.len())
    }
}

#[derive(Debug, Clone)]
pub(in crate::commands::install) struct MetadataRequestContext {
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
    pub(in crate::commands::install) fn from_request(request: &ResolveRequest) -> Self {
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

    pub(in crate::commands::install) fn peer_plan(package: &str) -> Self {
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
pub(in crate::commands::install) struct MetadataStats {
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
    pub(in crate::commands::install) fn new(started_at: Instant) -> Self {
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

    pub(in crate::commands::install) fn ready_hit_count(&self) -> u64 {
        self.ready_hits.load(Ordering::Relaxed)
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

    pub(in crate::commands::install) fn to_json(&self, trace: bool) -> serde_json::Value {
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

pub(in crate::commands::install) async fn metadata_for_package(
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

fn installer_spike_exact_doc_enabled() -> bool {
    std::env::var(ENV_INSTALLER_SPIKE_EXACT_DOC).as_deref() == Ok("1")
}

#[cfg(test)]
mod tests {
    use super::super::PackageIdentity;
    use super::*;

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
}
