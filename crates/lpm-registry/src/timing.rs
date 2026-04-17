//! Phase 40 P3a — process-global timing accumulators for metadata RPC
//! work.
//!
//! The resolver needs to know how much of `resolve_ms` was spent on
//! HTTP round-trips vs NDJSON parsing vs pubgrub's own backtracking
//! before we can pick which lever to pull (P3b worker-walk depth, P3c
//! parallel follow-up fetches, or P3d slimmer batch response). Process
//! globals are the simplest way to let `lpm-registry` report numbers
//! up to `lpm-resolver` without reshaping every `RegistryClient`
//! signature — the resolver sits between install.rs and the client
//! and is the only consumer, so contention is a non-issue in practice.
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

/// Reset all counters to zero. Idempotent. Call once before resolution
/// starts so `snapshot()` at the end reflects only work from THIS
/// resolution pass.
pub fn reset() {
    METADATA_RPC_NS.store(0, Ordering::Relaxed);
    METADATA_RPC_COUNT.store(0, Ordering::Relaxed);
    PARSE_NDJSON_NS.store(0, Ordering::Relaxed);
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

/// Snapshot the accumulators without clearing them. Returns
/// `(metadata_rpc_ms, metadata_rpc_count, parse_ndjson_ms)` — the
/// three Phase 40 P3a numbers the resolver surfaces to its callers.
pub fn snapshot() -> Snapshot {
    Snapshot {
        metadata_rpc: Duration::from_nanos(METADATA_RPC_NS.load(Ordering::Relaxed)),
        metadata_rpc_count: METADATA_RPC_COUNT.load(Ordering::Relaxed),
        parse_ndjson: Duration::from_nanos(PARSE_NDJSON_NS.load(Ordering::Relaxed)),
    }
}

/// Snapshot of Phase 40 P3a substage timers. See the field docs for
/// the exact contract each represents.
#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    /// Total wall-clock time spent in metadata HTTP calls since the
    /// last `reset()`. Covers every batch + per-package call, whether
    /// it terminated in success, 404, or retry. Network dominates on
    /// cold installs.
    pub metadata_rpc: Duration,
    /// Count of metadata HTTP calls. Includes calls that returned
    /// nothing useful (e.g., 404s on missing packages).
    pub metadata_rpc_count: u32,
    /// CPU time spent in the NDJSON serde_json deserializer. Subset
    /// of `metadata_rpc` by wall-clock (the parser runs while the
    /// network stream is still active), but reported separately so
    /// the P3d "slim the batch response" lever can be evaluated on
    /// its own.
    pub parse_ndjson: Duration,
}
