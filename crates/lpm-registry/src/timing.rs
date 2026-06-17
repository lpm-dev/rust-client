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

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
