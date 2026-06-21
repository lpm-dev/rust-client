//! Process-global timing accumulators for metadata RPC work.
//!
//! The resolver needs to know how much of `resolve_ms` was spent on
//! HTTP round-trips vs NDJSON parsing vs pubgrub backtracking so the
//! right optimization lever can be pulled. Process globals let
//! `lpm-registry` report numbers up to `lpm-resolver` without reshaping
//! every `RegistryClient` signature. Contention is a non-issue because
//! the resolver is the only consumer and the cold-resolve path is
//! effectively serial.
//!
//! Contract:
//!   1. `reset()` at the start of each resolution pass (idempotent).
//!   2. The registry client records time and counts as it works —
//!      every successful batch or per-package metadata call
//!      contributes to the rpc counters; every NDJSON parse
//!      contributes to the parse counter.
//!   3. `snapshot()` reads the accumulated numbers AFTER resolution
//!      completes, without clearing them.
//!
//! NOT thread-local: `spawn_blocking` in the resolver runs on a
//! different thread than the async context, so thread-locals would
//! drop work. `AtomicU64` is contention-free for the single-writer
//! case (the cold-resolve path is effectively serial).

use std::cell::Cell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

static METADATA_RPC_NS: AtomicU64 = AtomicU64::new(0);
static METADATA_RPC_COUNT: AtomicU32 = AtomicU32::new(0);
static PARSE_NDJSON_NS: AtomicU64 = AtomicU64::new(0);
static METADATA_HTTP_09_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_HTTP_10_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_HTTP_11_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_HTTP_2_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_HTTP_3_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_HTTP_UNKNOWN_COUNT: AtomicU32 = AtomicU32::new(0);
static METADATA_FETCH_DETAIL: OnceLock<MetadataFetchDetailCounters> = OnceLock::new();
#[cfg(test)]
static METADATA_FETCH_DETAIL_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
const TOP_METADATA_FETCH_DETAIL_LIMIT: usize = 10;

tokio::task_local! {
    static METADATA_PURPOSE: Cell<MetadataPurpose>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum MetadataPurpose {
    Resolve,
    BlockedSet,
    SignatureHydration,
    ProvenanceDrift,
    TarballUrlLookup,
}

impl MetadataPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::BlockedSet => "blocked_set",
            Self::SignatureHydration => "signature_hydration",
            Self::ProvenanceDrift => "provenance_drift",
            Self::TarballUrlLookup => "tarball_url_lookup",
        }
    }
}

const METADATA_PURPOSES: [MetadataPurpose; 5] = [
    MetadataPurpose::Resolve,
    MetadataPurpose::BlockedSet,
    MetadataPurpose::SignatureHydration,
    MetadataPurpose::ProvenanceDrift,
    MetadataPurpose::TarballUrlLookup,
];

#[derive(Default)]
struct PurposeCounters {
    rpc_ns: AtomicU64,
    rpc_count: AtomicU64,
    cache_hit_count: AtomicU64,
    cache_miss_count: AtomicU64,
    request_count: AtomicU64,
}

static RESOLVE_COUNTERS: PurposeCounters = PurposeCounters::new();
static BLOCKED_SET_COUNTERS: PurposeCounters = PurposeCounters::new();
static SIGNATURE_HYDRATION_COUNTERS: PurposeCounters = PurposeCounters::new();
static PROVENANCE_DRIFT_COUNTERS: PurposeCounters = PurposeCounters::new();
static TARBALL_URL_LOOKUP_COUNTERS: PurposeCounters = PurposeCounters::new();

impl PurposeCounters {
    const fn new() -> Self {
        Self {
            rpc_ns: AtomicU64::new(0),
            rpc_count: AtomicU64::new(0),
            cache_hit_count: AtomicU64::new(0),
            cache_miss_count: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.rpc_ns.store(0, Ordering::Relaxed);
        self.rpc_count.store(0, Ordering::Relaxed);
        self.cache_hit_count.store(0, Ordering::Relaxed);
        self.cache_miss_count.store(0, Ordering::Relaxed);
        self.request_count.store(0, Ordering::Relaxed);
    }
}

fn purpose_counters(purpose: MetadataPurpose) -> &'static PurposeCounters {
    match purpose {
        MetadataPurpose::Resolve => &RESOLVE_COUNTERS,
        MetadataPurpose::BlockedSet => &BLOCKED_SET_COUNTERS,
        MetadataPurpose::SignatureHydration => &SIGNATURE_HYDRATION_COUNTERS,
        MetadataPurpose::ProvenanceDrift => &PROVENANCE_DRIFT_COUNTERS,
        MetadataPurpose::TarballUrlLookup => &TARBALL_URL_LOOKUP_COUNTERS,
    }
}

fn metadata_request_counts() -> &'static Mutex<HashMap<(MetadataPurpose, String), u64>> {
    static COUNTS: OnceLock<Mutex<HashMap<(MetadataPurpose, String), u64>>> = OnceLock::new();
    COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn metadata_fetch_detail() -> &'static MetadataFetchDetailCounters {
    METADATA_FETCH_DETAIL.get_or_init(MetadataFetchDetailCounters::default)
}

#[cfg(test)]
pub(crate) fn metadata_fetch_detail_test_lock() -> &'static tokio::sync::Mutex<()> {
    METADATA_FETCH_DETAIL_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn current_metadata_purpose() -> MetadataPurpose {
    METADATA_PURPOSE
        .try_with(Cell::get)
        .unwrap_or(MetadataPurpose::Resolve)
}

pub async fn with_metadata_purpose<T>(
    purpose: MetadataPurpose,
    future: impl Future<Output = T>,
) -> T {
    METADATA_PURPOSE.scope(Cell::new(purpose), future).await
}

/// Split `metadata_rpc_count` into walker-driven and provider-escape-hatch
/// buckets. Walker code paths call [`record_walker_rpcs`] with the count
/// of manifests they fetched; every metadata round-trip bumps
/// `METADATA_RPC_COUNT` via [`record_rpc`]. The escape-hatch count is
/// `METADATA_RPC_COUNT - WALKER_RPC_COUNT` at snapshot time.
///
/// The walker calls the same `RegistryClient` methods as the escape-hatch,
/// so per-RPC instrumentation inside the client can't distinguish them.
/// Post-counting deltas at the walker's two call sites
/// (`parallel_fetch_npm_manifests` + `batch_metadata`) is cheaper than
/// `task_local!` scoping and equivalent.
static WALKER_RPC_COUNT: AtomicU32 = AtomicU32::new(0);

/// Reset all counters to zero. Idempotent. Call once before resolution
/// starts so `snapshot()` at the end reflects only work from THIS
/// resolution pass.
pub fn reset() {
    METADATA_RPC_NS.store(0, Ordering::Relaxed);
    METADATA_RPC_COUNT.store(0, Ordering::Relaxed);
    PARSE_NDJSON_NS.store(0, Ordering::Relaxed);
    WALKER_RPC_COUNT.store(0, Ordering::Relaxed);
    if metadata_fetch_detail_enabled()
        && let Some(detail) = METADATA_FETCH_DETAIL.get()
    {
        detail.reset();
    }
}

pub fn reset_metadata_detail() {
    for purpose in METADATA_PURPOSES {
        purpose_counters(purpose).reset();
    }
    if let Ok(mut counts) = metadata_request_counts().lock() {
        counts.clear();
    }
    if let Some(detail) = METADATA_FETCH_DETAIL.get() {
        detail.reset();
    }
}

/// Reset install-scoped metadata response protocol counters.
pub fn reset_metadata_http_versions() {
    METADATA_HTTP_09_COUNT.store(0, Ordering::Relaxed);
    METADATA_HTTP_10_COUNT.store(0, Ordering::Relaxed);
    METADATA_HTTP_11_COUNT.store(0, Ordering::Relaxed);
    METADATA_HTTP_2_COUNT.store(0, Ordering::Relaxed);
    METADATA_HTTP_3_COUNT.store(0, Ordering::Relaxed);
    METADATA_HTTP_UNKNOWN_COUNT.store(0, Ordering::Relaxed);
}

/// Record wall-clock time spent in a single metadata RPC. Covers
/// batch fetches (`/api/registry/batch-metadata`) and per-package
/// fetches (`/api/registry/<name>` + the upstream npm fallback).
///
/// One call site records per HTTP request; the same request can
/// parse N packages, so `rpc_count` grows by 1 but
/// `metadata_packages_parsed` (implicit in the parse side) grows by
/// N. Keeping them on separate counters makes the signal-to-noise
/// ratio readable at the JSON output.
pub fn record_rpc(duration: Duration) {
    METADATA_RPC_NS.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    METADATA_RPC_COUNT.fetch_add(1, Ordering::Relaxed);
    let counters = purpose_counters(current_metadata_purpose());
    counters
        .rpc_ns
        .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    counters.rpc_count.fetch_add(1, Ordering::Relaxed);
}

/// Record CPU time spent parsing an NDJSON line (serde_json ->
/// `PackageMetadata`). The NDJSON batch parser already tracks this
/// locally for its debug log; the accumulator lets the resolver
/// surface it in `--json`.
pub fn record_parse(duration: Duration) {
    PARSE_NDJSON_NS.fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
}

/// Record `n` RPCs as walker-driven. Called by the walker after each
/// batch / parallel-fetch returns so the walker vs escape-hatch split
/// can be reported in `--json` without the client knowing its caller.
/// `record_rpc` continues to bump the total; this moves the bucketing.
pub fn record_walker_rpcs(n: u32) {
    WALKER_RPC_COUNT.fetch_add(n, Ordering::Relaxed);
}

/// Record the negotiated protocol version for one package-metadata response.
pub fn record_metadata_http_version(version: reqwest::Version) {
    if version == reqwest::Version::HTTP_09 {
        METADATA_HTTP_09_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if version == reqwest::Version::HTTP_10 {
        METADATA_HTTP_10_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if version == reqwest::Version::HTTP_11 {
        METADATA_HTTP_11_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if version == reqwest::Version::HTTP_2 {
        METADATA_HTTP_2_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if version == reqwest::Version::HTTP_3 {
        METADATA_HTTP_3_COUNT.fetch_add(1, Ordering::Relaxed);
    } else {
        METADATA_HTTP_UNKNOWN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_metadata_request(package_name: &str) {
    let purpose = current_metadata_purpose();
    purpose_counters(purpose)
        .request_count
        .fetch_add(1, Ordering::Relaxed);
    if let Ok(mut counts) = metadata_request_counts().lock() {
        let key = (purpose, package_name.to_string());
        *counts.entry(key).or_insert(0) += 1;
    }
}

pub fn record_metadata_cache_hit() {
    purpose_counters(current_metadata_purpose())
        .cache_hit_count
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_metadata_cache_miss() {
    purpose_counters(current_metadata_purpose())
        .cache_miss_count
        .fetch_add(1, Ordering::Relaxed);
}

pub fn metadata_fetch_detail_enabled() -> bool {
    std::env::var("LPM_TIMING_DETAIL")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("trace"))
}

pub fn record_metadata_fetch_detail(record: MetadataFetchDetailRecord) {
    metadata_fetch_detail().record(record);
}

pub fn record_metadata_cache_info_parse_detail(
    package: impl Into<String>,
    route: &'static str,
    cache_info_parse_ms: u128,
    version_count: u64,
) {
    if cache_info_parse_ms == 0 {
        return;
    }
    metadata_fetch_detail().record_cache_info_parse(MetadataFetchDetailRecord {
        package: package.into(),
        route,
        cache_info_parse_ms,
        version_count,
        ..MetadataFetchDetailRecord::default()
    });
}

/// Snapshot package-metadata response protocol counters.
pub fn snapshot_metadata_http_versions() -> HttpVersionCounts {
    HttpVersionCounts {
        http_09: METADATA_HTTP_09_COUNT.load(Ordering::Relaxed),
        http_10: METADATA_HTTP_10_COUNT.load(Ordering::Relaxed),
        http_11: METADATA_HTTP_11_COUNT.load(Ordering::Relaxed),
        http_2: METADATA_HTTP_2_COUNT.load(Ordering::Relaxed),
        http_3: METADATA_HTTP_3_COUNT.load(Ordering::Relaxed),
        unknown: METADATA_HTTP_UNKNOWN_COUNT.load(Ordering::Relaxed),
    }
}

/// Snapshot the accumulators without clearing them.
pub fn snapshot() -> Snapshot {
    let total = METADATA_RPC_COUNT.load(Ordering::Relaxed);
    let walker = WALKER_RPC_COUNT.load(Ordering::Relaxed);
    Snapshot {
        metadata_rpc: Duration::from_nanos(METADATA_RPC_NS.load(Ordering::Relaxed)),
        metadata_rpc_count: total,
        parse_ndjson: Duration::from_nanos(PARSE_NDJSON_NS.load(Ordering::Relaxed)),
        walker_rpc_count: walker,
        // Saturating sub guards the (rare) ordering window where a
        // walker post-record raced past the matching `record_rpc`.
        escape_hatch_rpc_count: total.saturating_sub(walker),
    }
}

/// Snapshot of metadata-RPC substage timers. See field docs for the
/// exact contract each represents.
#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    /// Total wall-clock time spent in metadata HTTP calls since the
    /// last `reset()`. Covers every batch + per-package call, whether
    /// it terminated in success, 404, or retry. Network dominates on
    /// cold installs.
    pub metadata_rpc: Duration,
    /// Count of metadata HTTP calls. Includes calls that returned
    /// nothing useful (e.g., 404s on missing packages). Equals
    /// `walker_rpc_count + escape_hatch_rpc_count`.
    pub metadata_rpc_count: u32,
    /// CPU time spent in the NDJSON serde_json deserializer. Subset
    /// of `metadata_rpc` by wall-clock (the parser runs while the
    /// network stream is still active), but reported separately so
    /// the "slim the batch response" optimization can be evaluated on
    /// its own.
    pub parse_ndjson: Duration,
    /// Count of metadata HTTP calls fired by the walker (`BfsWalker` /
    /// streaming walker). Each parallel-fetch GET counts as one; each
    /// batch_metadata call also counts as one regardless of package count.
    /// Walker post-records the delta after each batch / parallel fetch.
    pub walker_rpc_count: u32,
    /// Count of metadata HTTP calls fired by the resolver provider's
    /// escape-hatch path (manifests the walker didn't pre-fetch within
    /// `fetch_wait_timeout`). High values indicate the walker's depth or
    /// fanout is undersized. `escape_hatch + walker == metadata_rpc_count`.
    pub escape_hatch_rpc_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataPurposeSnapshot {
    pub purpose: &'static str,
    pub rpc: Duration,
    pub rpc_count: u64,
    pub cache_hit_count: u64,
    pub cache_miss_count: u64,
    pub request_count: u64,
    pub unique_package_count: u64,
    pub duplicate_request_count: u64,
    pub top_duplicate_packages: Vec<MetadataDuplicatePackage>,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataDuplicatePackage {
    pub package: String,
    pub request_count: u64,
    pub duplicate_count: u64,
}

pub fn snapshot_metadata_detail() -> Vec<MetadataPurposeSnapshot> {
    let request_counts = metadata_request_counts().lock().ok();
    METADATA_PURPOSES
        .iter()
        .map(|&purpose| {
            let counters = purpose_counters(purpose);
            let (unique_package_count, duplicate_request_count) =
                request_counts.as_ref().map_or((0, 0), |counts| {
                    counts.iter().filter(|((p, _), _)| *p == purpose).fold(
                        (0u64, 0u64),
                        |(unique, duplicate), (_, count)| {
                            (unique + 1, duplicate + count.saturating_sub(1))
                        },
                    )
                });
            let mut top_duplicate_packages: Vec<MetadataDuplicatePackage> =
                request_counts.as_ref().map_or_else(Vec::new, |counts| {
                    counts
                        .iter()
                        .filter(|((p, _), count)| *p == purpose && **count > 1)
                        .map(|((_, package), count)| MetadataDuplicatePackage {
                            package: package.clone(),
                            request_count: *count,
                            duplicate_count: count.saturating_sub(1),
                        })
                        .collect()
                });
            top_duplicate_packages.sort_unstable_by(|a, b| {
                b.duplicate_count
                    .cmp(&a.duplicate_count)
                    .then_with(|| b.request_count.cmp(&a.request_count))
                    .then_with(|| a.package.cmp(&b.package))
            });
            top_duplicate_packages.truncate(10);
            MetadataPurposeSnapshot {
                purpose: purpose.as_str(),
                rpc: Duration::from_nanos(counters.rpc_ns.load(Ordering::Relaxed)),
                rpc_count: counters.rpc_count.load(Ordering::Relaxed),
                cache_hit_count: counters.cache_hit_count.load(Ordering::Relaxed),
                cache_miss_count: counters.cache_miss_count.load(Ordering::Relaxed),
                request_count: counters.request_count.load(Ordering::Relaxed),
                unique_package_count,
                duplicate_request_count,
                top_duplicate_packages,
            }
        })
        .collect()
}

pub fn snapshot_metadata_fetch_detail() -> MetadataFetchDetailSnapshot {
    metadata_fetch_detail().snapshot()
}

#[derive(Debug, Clone, Default)]
pub struct MetadataFetchDetailRecord {
    pub package: String,
    pub route: &'static str,
    pub total_ms: u128,
    pub raw_fetch_ms: u128,
    pub cache_read_ms: u128,
    pub validator_read_ms: u128,
    pub http_ms: u128,
    pub body_read_ms: u128,
    pub json_decode_ms: u128,
    pub cache_after_304_ms: u128,
    pub cache_write_dispatch_ms: u128,
    pub cache_info_parse_ms: u128,
    pub policy_release_time_ms: u128,
    pub policy_full_metadata_ms: u128,
    pub body_bytes: u64,
    pub version_count: u64,
    pub cache_hit: bool,
    pub not_modified: bool,
}

#[derive(Default)]
struct MetadataFetchDetailCounters {
    calls: AtomicU64,
    cache_hit_count: AtomicU64,
    not_modified_count: AtomicU64,
    body_bytes_sum: AtomicU64,
    version_count_sum: AtomicU64,
    route_npm_direct_count: AtomicU64,
    route_lpm_worker_count: AtomicU64,
    route_custom_count: AtomicU64,
    route_lpm_count: AtomicU64,
    route_unknown_count: AtomicU64,
    total_sum_ms: AtomicU64,
    total_max_ms: AtomicU64,
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
    slow_by_total: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_raw_fetch: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_http: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_body_read: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_json_decode: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_cache_info_parse: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_policy_release_time: Mutex<Vec<MetadataFetchDetailRecord>>,
    slow_by_policy_full_metadata: Mutex<Vec<MetadataFetchDetailRecord>>,
}

impl MetadataFetchDetailCounters {
    fn reset(&self) {
        self.calls.store(0, Ordering::Relaxed);
        self.cache_hit_count.store(0, Ordering::Relaxed);
        self.not_modified_count.store(0, Ordering::Relaxed);
        self.body_bytes_sum.store(0, Ordering::Relaxed);
        self.version_count_sum.store(0, Ordering::Relaxed);
        self.route_npm_direct_count.store(0, Ordering::Relaxed);
        self.route_lpm_worker_count.store(0, Ordering::Relaxed);
        self.route_custom_count.store(0, Ordering::Relaxed);
        self.route_lpm_count.store(0, Ordering::Relaxed);
        self.route_unknown_count.store(0, Ordering::Relaxed);
        self.total_sum_ms.store(0, Ordering::Relaxed);
        self.total_max_ms.store(0, Ordering::Relaxed);
        self.raw_fetch_sum_ms.store(0, Ordering::Relaxed);
        self.raw_fetch_max_ms.store(0, Ordering::Relaxed);
        self.cache_read_sum_ms.store(0, Ordering::Relaxed);
        self.validator_read_sum_ms.store(0, Ordering::Relaxed);
        self.http_sum_ms.store(0, Ordering::Relaxed);
        self.body_read_sum_ms.store(0, Ordering::Relaxed);
        self.json_decode_sum_ms.store(0, Ordering::Relaxed);
        self.cache_after_304_sum_ms.store(0, Ordering::Relaxed);
        self.cache_write_dispatch_sum_ms.store(0, Ordering::Relaxed);
        self.cache_info_parse_sum_ms.store(0, Ordering::Relaxed);
        self.policy_release_time_sum_ms.store(0, Ordering::Relaxed);
        self.policy_full_metadata_sum_ms.store(0, Ordering::Relaxed);
        Self::clear_bucket(&self.slow_by_total);
        Self::clear_bucket(&self.slow_by_raw_fetch);
        Self::clear_bucket(&self.slow_by_http);
        Self::clear_bucket(&self.slow_by_body_read);
        Self::clear_bucket(&self.slow_by_json_decode);
        Self::clear_bucket(&self.slow_by_cache_info_parse);
        Self::clear_bucket(&self.slow_by_policy_release_time);
        Self::clear_bucket(&self.slow_by_policy_full_metadata);
    }

    fn clear_bucket(bucket: &Mutex<Vec<MetadataFetchDetailRecord>>) {
        if let Ok(mut bucket) = bucket.lock() {
            bucket.clear();
        }
    }

    fn record(&self, record: MetadataFetchDetailRecord) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if record.cache_hit {
            self.cache_hit_count.fetch_add(1, Ordering::Relaxed);
        }
        if record.not_modified {
            self.not_modified_count.fetch_add(1, Ordering::Relaxed);
        }
        self.body_bytes_sum
            .fetch_add(record.body_bytes, Ordering::Relaxed);
        self.version_count_sum
            .fetch_add(record.version_count, Ordering::Relaxed);
        match record.route {
            "npm_direct" => &self.route_npm_direct_count,
            "lpm_worker" => &self.route_lpm_worker_count,
            "custom" => &self.route_custom_count,
            "lpm" => &self.route_lpm_count,
            _ => &self.route_unknown_count,
        }
        .fetch_add(1, Ordering::Relaxed);

        Self::record_sum_max(&self.total_sum_ms, &self.total_max_ms, record.total_ms);
        Self::record_sum_max(
            &self.raw_fetch_sum_ms,
            &self.raw_fetch_max_ms,
            record.raw_fetch_ms,
        );
        self.cache_read_sum_ms.fetch_add(
            u128_to_u64_saturating(record.cache_read_ms),
            Ordering::Relaxed,
        );
        self.validator_read_sum_ms.fetch_add(
            u128_to_u64_saturating(record.validator_read_ms),
            Ordering::Relaxed,
        );
        self.http_sum_ms
            .fetch_add(u128_to_u64_saturating(record.http_ms), Ordering::Relaxed);
        self.body_read_sum_ms.fetch_add(
            u128_to_u64_saturating(record.body_read_ms),
            Ordering::Relaxed,
        );
        self.json_decode_sum_ms.fetch_add(
            u128_to_u64_saturating(record.json_decode_ms),
            Ordering::Relaxed,
        );
        self.cache_after_304_sum_ms.fetch_add(
            u128_to_u64_saturating(record.cache_after_304_ms),
            Ordering::Relaxed,
        );
        self.cache_write_dispatch_sum_ms.fetch_add(
            u128_to_u64_saturating(record.cache_write_dispatch_ms),
            Ordering::Relaxed,
        );
        self.cache_info_parse_sum_ms.fetch_add(
            u128_to_u64_saturating(record.cache_info_parse_ms),
            Ordering::Relaxed,
        );
        self.policy_release_time_sum_ms.fetch_add(
            u128_to_u64_saturating(record.policy_release_time_ms),
            Ordering::Relaxed,
        );
        self.policy_full_metadata_sum_ms.fetch_add(
            u128_to_u64_saturating(record.policy_full_metadata_ms),
            Ordering::Relaxed,
        );

        Self::record_slow(&self.slow_by_total, &record, |entry| entry.total_ms);
        Self::record_slow(&self.slow_by_raw_fetch, &record, |entry| entry.raw_fetch_ms);
        Self::record_slow(&self.slow_by_http, &record, |entry| entry.http_ms);
        Self::record_slow(&self.slow_by_body_read, &record, |entry| entry.body_read_ms);
        Self::record_slow(&self.slow_by_json_decode, &record, |entry| {
            entry.json_decode_ms
        });
        Self::record_slow(&self.slow_by_cache_info_parse, &record, |entry| {
            entry.cache_info_parse_ms
        });
        Self::record_slow(&self.slow_by_policy_release_time, &record, |entry| {
            entry.policy_release_time_ms
        });
        Self::record_slow(&self.slow_by_policy_full_metadata, &record, |entry| {
            entry.policy_full_metadata_ms
        });
    }

    fn record_cache_info_parse(&self, record: MetadataFetchDetailRecord) {
        self.cache_info_parse_sum_ms.fetch_add(
            u128_to_u64_saturating(record.cache_info_parse_ms),
            Ordering::Relaxed,
        );
        Self::record_slow(&self.slow_by_cache_info_parse, &record, |entry| {
            entry.cache_info_parse_ms
        });
    }

    fn record_sum_max(sum: &AtomicU64, max: &AtomicU64, ms: u128) {
        let ms = u128_to_u64_saturating(ms);
        sum.fetch_add(ms, Ordering::Relaxed);
        max.fetch_max(ms, Ordering::Relaxed);
    }

    fn record_slow(
        bucket: &Mutex<Vec<MetadataFetchDetailRecord>>,
        record: &MetadataFetchDetailRecord,
        rank_ms: impl Fn(&MetadataFetchDetailRecord) -> u128 + Copy,
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
                .then_with(|| a.package.cmp(&b.package))
        });
        bucket.truncate(TOP_METADATA_FETCH_DETAIL_LIMIT);
    }

    fn snapshot(&self) -> MetadataFetchDetailSnapshot {
        MetadataFetchDetailSnapshot {
            calls: self.calls.load(Ordering::Relaxed),
            cache_hit_count: self.cache_hit_count.load(Ordering::Relaxed),
            not_modified_count: self.not_modified_count.load(Ordering::Relaxed),
            body_bytes_sum: self.body_bytes_sum.load(Ordering::Relaxed),
            version_count_sum: self.version_count_sum.load(Ordering::Relaxed),
            route_npm_direct_count: self.route_npm_direct_count.load(Ordering::Relaxed),
            route_lpm_worker_count: self.route_lpm_worker_count.load(Ordering::Relaxed),
            route_custom_count: self.route_custom_count.load(Ordering::Relaxed),
            route_lpm_count: self.route_lpm_count.load(Ordering::Relaxed),
            route_unknown_count: self.route_unknown_count.load(Ordering::Relaxed),
            attribution: MetadataFetchAttributionSnapshot {
                total_sum_ms: self.total_sum_ms.load(Ordering::Relaxed),
                total_max_ms: self.total_max_ms.load(Ordering::Relaxed),
                raw_fetch_sum_ms: self.raw_fetch_sum_ms.load(Ordering::Relaxed),
                raw_fetch_max_ms: self.raw_fetch_max_ms.load(Ordering::Relaxed),
                cache_read_sum_ms: self.cache_read_sum_ms.load(Ordering::Relaxed),
                validator_read_sum_ms: self.validator_read_sum_ms.load(Ordering::Relaxed),
                http_sum_ms: self.http_sum_ms.load(Ordering::Relaxed),
                body_read_sum_ms: self.body_read_sum_ms.load(Ordering::Relaxed),
                json_decode_sum_ms: self.json_decode_sum_ms.load(Ordering::Relaxed),
                cache_after_304_sum_ms: self.cache_after_304_sum_ms.load(Ordering::Relaxed),
                cache_write_dispatch_sum_ms: self
                    .cache_write_dispatch_sum_ms
                    .load(Ordering::Relaxed),
                cache_info_parse_sum_ms: self.cache_info_parse_sum_ms.load(Ordering::Relaxed),
                policy_release_time_sum_ms: self.policy_release_time_sum_ms.load(Ordering::Relaxed),
                policy_full_metadata_sum_ms: self
                    .policy_full_metadata_sum_ms
                    .load(Ordering::Relaxed),
            },
            top_slow_packages: MetadataFetchSlowSnapshot {
                by_total: Self::snapshot_bucket(&self.slow_by_total),
                by_raw_fetch: Self::snapshot_bucket(&self.slow_by_raw_fetch),
                by_http: Self::snapshot_bucket(&self.slow_by_http),
                by_body_read: Self::snapshot_bucket(&self.slow_by_body_read),
                by_json_decode: Self::snapshot_bucket(&self.slow_by_json_decode),
                by_cache_info_parse: Self::snapshot_bucket(&self.slow_by_cache_info_parse),
                by_policy_release_time: Self::snapshot_bucket(&self.slow_by_policy_release_time),
                by_policy_full_metadata: Self::snapshot_bucket(&self.slow_by_policy_full_metadata),
            },
        }
    }

    fn snapshot_bucket(
        bucket: &Mutex<Vec<MetadataFetchDetailRecord>>,
    ) -> Vec<MetadataFetchDetailRecord> {
        bucket
            .lock()
            .map_or_else(|_| Vec::new(), |bucket| bucket.clone())
    }
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Default)]
pub struct MetadataFetchDetailSnapshot {
    pub calls: u64,
    pub cache_hit_count: u64,
    pub not_modified_count: u64,
    pub body_bytes_sum: u64,
    pub version_count_sum: u64,
    pub route_npm_direct_count: u64,
    pub route_lpm_worker_count: u64,
    pub route_custom_count: u64,
    pub route_lpm_count: u64,
    pub route_unknown_count: u64,
    pub attribution: MetadataFetchAttributionSnapshot,
    pub top_slow_packages: MetadataFetchSlowSnapshot,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataFetchAttributionSnapshot {
    pub total_sum_ms: u64,
    pub total_max_ms: u64,
    pub raw_fetch_sum_ms: u64,
    pub raw_fetch_max_ms: u64,
    pub cache_read_sum_ms: u64,
    pub validator_read_sum_ms: u64,
    pub http_sum_ms: u64,
    pub body_read_sum_ms: u64,
    pub json_decode_sum_ms: u64,
    pub cache_after_304_sum_ms: u64,
    pub cache_write_dispatch_sum_ms: u64,
    pub cache_info_parse_sum_ms: u64,
    pub policy_release_time_sum_ms: u64,
    pub policy_full_metadata_sum_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataFetchSlowSnapshot {
    pub by_total: Vec<MetadataFetchDetailRecord>,
    pub by_raw_fetch: Vec<MetadataFetchDetailRecord>,
    pub by_http: Vec<MetadataFetchDetailRecord>,
    pub by_body_read: Vec<MetadataFetchDetailRecord>,
    pub by_json_decode: Vec<MetadataFetchDetailRecord>,
    pub by_cache_info_parse: Vec<MetadataFetchDetailRecord>,
    pub by_policy_release_time: Vec<MetadataFetchDetailRecord>,
    pub by_policy_full_metadata: Vec<MetadataFetchDetailRecord>,
}

/// Counts of package-metadata HTTP responses by negotiated protocol version.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct HttpVersionCounts {
    pub http_09: u32,
    pub http_10: u32,
    pub http_11: u32,
    pub http_2: u32,
    pub http_3: u32,
    pub unknown: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScopedEnv {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl ScopedEnv {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: timing tests that mutate process env are serialized by
            // `metadata_fetch_detail_test_lock`.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: timing tests that mutate process env are serialized by
            // `metadata_fetch_detail_test_lock`.
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            // SAFETY: timing tests that mutate process env are serialized by
            // `metadata_fetch_detail_test_lock`.
            unsafe {
                if let Some(previous) = &self.previous {
                    std::env::set_var(self.key, previous);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn metadata_fetch_detail_counters_rank_slow_packages_and_reset() {
        let _guard = metadata_fetch_detail_test_lock().lock().await;
        let counters = MetadataFetchDetailCounters::default();

        counters.record(MetadataFetchDetailRecord {
            package: "fast".to_string(),
            route: "npm_direct",
            total_ms: 5,
            raw_fetch_ms: 4,
            http_ms: 2,
            body_bytes: 100,
            version_count: 3,
            ..MetadataFetchDetailRecord::default()
        });
        counters.record(MetadataFetchDetailRecord {
            package: "slow".to_string(),
            route: "npm_direct",
            total_ms: 12,
            raw_fetch_ms: 10,
            http_ms: 9,
            body_read_ms: 6,
            json_decode_ms: 4,
            cache_info_parse_ms: 3,
            body_bytes: 900,
            version_count: 7,
            cache_hit: true,
            ..MetadataFetchDetailRecord::default()
        });

        let snapshot = counters.snapshot();

        assert_eq!(snapshot.calls, 2);
        assert_eq!(snapshot.cache_hit_count, 1);
        assert_eq!(snapshot.route_npm_direct_count, 2);
        assert_eq!(snapshot.body_bytes_sum, 1000);
        assert_eq!(snapshot.version_count_sum, 10);
        assert_eq!(snapshot.attribution.total_sum_ms, 17);
        assert_eq!(snapshot.attribution.total_max_ms, 12);
        assert_eq!(snapshot.attribution.http_sum_ms, 11);
        assert_eq!(snapshot.top_slow_packages.by_total[0].package, "slow");
        assert_eq!(snapshot.top_slow_packages.by_http[0].package, "slow");

        counters.reset();
        let snapshot = counters.snapshot();

        assert_eq!(snapshot.calls, 0);
        assert!(snapshot.top_slow_packages.by_total.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_clears_existing_metadata_fetch_detail_collector() {
        let _guard = metadata_fetch_detail_test_lock().lock().await;
        let _env = ScopedEnv::set("LPM_TIMING_DETAIL", "trace");
        reset_metadata_detail();
        record_metadata_fetch_detail(MetadataFetchDetailRecord {
            package: "stale".to_string(),
            route: "npm_direct",
            total_ms: 9,
            ..MetadataFetchDetailRecord::default()
        });
        assert_eq!(snapshot_metadata_fetch_detail().calls, 1);

        reset();

        assert_eq!(snapshot_metadata_fetch_detail().calls, 0);
        assert!(
            snapshot_metadata_fetch_detail()
                .top_slow_packages
                .by_total
                .is_empty()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_info_parse_detail_does_not_increment_fetch_call_count() {
        let _guard = metadata_fetch_detail_test_lock().lock().await;
        let _env = ScopedEnv::set("LPM_TIMING_DETAIL", "trace");
        reset_metadata_detail();

        record_metadata_cache_info_parse_detail("parse-heavy", "npm_direct", 11, 123);
        let snapshot = snapshot_metadata_fetch_detail();

        assert_eq!(snapshot.calls, 0);
        assert_eq!(snapshot.attribution.cache_info_parse_sum_ms, 11);
        assert_eq!(
            snapshot.top_slow_packages.by_cache_info_parse[0].package,
            "parse-heavy"
        );
        assert_eq!(
            snapshot.top_slow_packages.by_cache_info_parse[0].version_count,
            123
        );
        reset_metadata_detail();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_preserves_metadata_fetch_detail_collector_when_trace_disabled() {
        let _guard = metadata_fetch_detail_test_lock().lock().await;
        let _env = ScopedEnv::remove("LPM_TIMING_DETAIL");
        reset_metadata_detail();
        record_metadata_fetch_detail(MetadataFetchDetailRecord {
            package: "trace-only".to_string(),
            route: "npm_direct",
            total_ms: 9,
            ..MetadataFetchDetailRecord::default()
        });

        reset();

        assert_eq!(snapshot_metadata_fetch_detail().calls, 1);
        reset_metadata_detail();
    }
}
