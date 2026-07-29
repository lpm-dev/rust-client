use super::*;

/// Per-package fetch-stage timings collected inside one download task.
///
/// Populated by the parallel download loop and folded into a
/// [`FetchBreakdown`] aggregate so `lpm install --json` can surface the
/// real sub-stage costs instead of the single lumpy `fetch_ms` number.
/// All values are whole milliseconds.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct TaskTimings {
    /// Time from tokio spawn to successful semaphore acquire. High values
    /// indicate download concurrency (the configured permit pool, default
    /// 24, overridable via `LPM_CONCURRENT_DOWNLOADS`) is the bottleneck —
    /// tasks are queued waiting for a slot rather than running I/O.
    pub(super) queue_wait_ms: u128,
    /// — time spent resolving the tarball URL (registry
    /// metadata round-trip when the lockfile didn't have a usable
    /// cached URL; near-zero otherwise). Measured around the
    /// `resolve_tarball_url` call in BOTH legacy and streaming
    /// fetch paths so the direct win is visible on either
    /// path. Carved out of `download_ms` (legacy) and previously
    /// untimed in streaming.
    pub(super) url_lookup_ms: u128,
    /// Time in `client.download_tarball_to_file` — the HTTP GET +
    /// on-disk temp spool + SHA-512 streaming hash. ** /// note:** URL resolution is now carved out into
    /// `url_lookup_ms` on both paths; `download_ms` covers GET +
    /// temp-file write only (legacy path; streaming collapses
    /// into `extract_ms`).
    pub(super) download_ms: u128,
    /// Time spent verifying the computed SRI against the expected hash.
    /// Near-zero in the common `sha512` matched case (string compare);
    /// non-trivial only when `integrity.algo` differs from sha512, in
    /// which case the tarball is re-read in 64 KB chunks.
    pub(super) integrity_ms: u128,
    pub(super) extract_permit_wait_ms: u128,
    /// Time in `extract_tarball_from_file` (gzip decompress, tar walk,
    /// and write-to-staging). Mirrors [`lpm_store::StageTimings::extract_ms`].
    pub(super) extract_ms: u128,
    /// Post-extraction security finalization and cache-write time. On
    /// two-pass extraction paths this also contains the source scan.
    /// Mirrors [`lpm_store::StageTimings::security_ms`].
    pub(super) security_ms: u128,
    /// Source-analysis attribution nested inside extraction on fused paths
    /// and security time on two-pass paths. Kept in nanoseconds so small
    /// packages do not round to zero.
    pub(super) source_scan_ns: u128,
    /// Time in `.integrity` write + atomic rename into the store path.
    /// Mirrors [`lpm_store::StageTimings::finalize_ms`].
    pub(super) finalize_ms: u128,
    pub(super) finalize_permit_wait_ms: u128,
    pub(super) finalize_tree_integrity_ms: u128,
    pub(super) finalize_integrity_write_ms: u128,
    pub(super) finalize_rename_ms: u128,
    pub(super) finalize_collision_recovery_ms: u128,
    pub(super) file_count: u64,
    pub(super) dir_count: u64,
    pub(super) symlink_count: u64,
    pub(super) unpacked_bytes: u64,
}

impl TaskTimings {
    pub(super) fn from_stage(
        queue_wait_ms: u128,
        url_lookup_ms: u128,
        download_ms: u128,
        integrity_ms: u128,
        extract_permit_wait_ms: u128,
        stage: lpm_store::StageTimings,
    ) -> Self {
        Self {
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            integrity_ms,
            extract_permit_wait_ms,
            extract_ms: stage.extract_ms,
            security_ms: stage.security_ms,
            source_scan_ns: stage.source_scan_ns,
            finalize_ms: stage.finalize_ms,
            finalize_permit_wait_ms: stage.finalize_permit_wait_ms,
            finalize_tree_integrity_ms: stage.finalize_tree_integrity_ms,
            finalize_integrity_write_ms: stage.finalize_integrity_write_ms,
            finalize_rename_ms: stage.finalize_rename_ms,
            finalize_collision_recovery_ms: stage.finalize_collision_recovery_ms,
            file_count: stage.file_count,
            dir_count: stage.dir_count,
            symlink_count: stage.symlink_count,
            unpacked_bytes: stage.unpacked_bytes,
        }
    }

    pub(super) fn total_ms(self) -> u128 {
        self.queue_wait_ms
            .saturating_add(self.url_lookup_ms)
            .saturating_add(self.download_ms)
            .saturating_add(self.integrity_ms)
            .saturating_add(self.extract_permit_wait_ms)
            .saturating_add(self.extract_ms)
            .saturating_add(self.security_ms)
            .saturating_add(self.finalize_permit_wait_ms)
            .saturating_add(self.finalize_ms)
    }
}

/// Aggregate fetch-stage breakdown across the entire parallel download pool.
///
/// Sum fields give total wall-clock spent in each stage across all tasks
/// (useful for CPU/IO attribution). Max fields give the single slowest
/// package's cost (useful for tail-latency analysis). `task_count` is the
/// number of non-cached packages actually downloaded.
///
/// Emitted under `timing.fetch_breakdown` in `lpm install --json`. Both
/// sum- and max- variants are reported so future optimizations can be
/// measured against the stage profile most relevant to the change:
/// stream-to-staging () moves mass out of `extract_sum_ms`; the
/// fused-scan follow-up () should zero out `security_sum_ms`.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FetchBreakdown {
    /// Number of tasks whose timings were folded in (== `downloaded`).
    pub(super) task_count: u64,
    pub(super) task_sum_ms: u128,
    pub(super) task_max_ms: u128,
    pub(super) queue_wait_sum_ms: u128,
    pub(super) queue_wait_max_ms: u128,
    /// — sum/max of per-task URL-lookup time. Primary
    /// projection target: drops from ~15–25 s to near-0
    /// on fresh-CI installs once stored URLs are reused. Visible
    /// on both legacy and streaming paths by construction.
    pub(super) url_lookup_sum_ms: u128,
    pub(super) url_lookup_max_ms: u128,
    pub(super) download_sum_ms: u128,
    pub(super) download_max_ms: u128,
    pub(super) integrity_sum_ms: u128,
    pub(super) integrity_max_ms: u128,
    pub(super) extract_permit_wait_sum_ms: u128,
    pub(super) extract_permit_wait_max_ms: u128,
    pub(super) extract_sum_ms: u128,
    pub(super) extract_max_ms: u128,
    pub(super) security_sum_ms: u128,
    pub(super) security_max_ms: u128,
    pub(super) source_scan_sum_ns: u128,
    pub(super) source_scan_max_ns: u128,
    pub(super) finalize_permit_wait_sum_ms: u128,
    pub(super) finalize_permit_wait_max_ms: u128,
    pub(super) finalize_sum_ms: u128,
    pub(super) finalize_max_ms: u128,
}

/// speculative-fetch counters.
///
/// Populated by the walker+dispatcher orchestration. Zero
/// across the board on the lockfile-fast-path (walker never runs) or
/// when every root is already in the store before the metadata RPC
/// starts. Surfaced in `timing.fetch_breakdown.speculative` so
/// benchmarks can attribute the wall-clock delta to actual speculation
/// outcomes.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SpeculativeStats {
    /// wall-clock of the walker's metadata-producer window,
    /// measured inside the walker task from `BfsWalker::run()` entry
    /// to its return (see `WalkerSummary::walker_wall_ms`). Reported
    /// here so pre/post-49 benches stay comparable at the contract
    /// layer, even though the underlying producer changed from the
    /// Worker's NDJSON batch stream to a client-side BFS walker.
    /// Excludes the dispatcher's tarball-download tail, which overlaps
    /// with the real fetch loop and is reported in `fetch_ms`.
    pub(super) streaming_batch_ms: u128,
    /// Total packages the dispatcher started a tarball download for.
    /// Pre-this capped at root count; now includes
    /// transitives reachable via `dispatched_root → dep_range → matching
    /// version` expansion. Excludes store hits, unparseable ranges, and
    /// packages with no range-satisfying version in the arrived manifest.
    pub(super) dispatched: u64,
    /// Number of dispatched downloads that completed successfully (or
    /// no-op'd because another concurrent task raced us to the store).
    /// Below `dispatched` when a tarball network error or integrity
    /// mismatch caused the spec download to drop.
    pub(super) completed: u64,
    /// Cumulative wall-clock across all dispatched speculative tasks.
    /// Divide by `completed` for average per-task cost.
    pub(super) task_ms_sum: u128,
    /// Subset of `dispatched` that came from transitive
    /// expansion (i.e. a dep of an already-speculated package). Equal to
    /// `dispatched - roots_dispatched`; reported separately so benchmarks
    /// can confirm transitive reach on larger fixtures.
    pub(super) transitive_dispatched: u64,
    /// Maximum depth reached during transitive expansion
    /// on this install. `1` for root-only installs; climbs with deeper
    /// trees. Capped at [`SPECULATION_MAX_DEPTH`].
    pub(super) max_depth_reached: u64,
    /// Packages whose manifest arrived but whose range
    /// had no matching version — tracked separately from dispatched
    /// misses because a naive user might read the gap between
    /// `dispatched` and `resolve-output` as wastage.
    pub(super) no_version_match: u64,
    /// Packages whose manifest never arrived during
    /// speculation (parked but the parent's deep-walk didn't cover
    /// them). Usually indicates the worker's deep-walk hit its own cap.
    pub(super) unresolved_parked: u64,
    /// Dispatched speculative tasks that returned an error.
    pub(super) failed: u64,
    /// Dispatched tasks that did not start network work because all
    /// speculative permits or shared download permits were already busy.
    pub(super) skipped_no_permit: u64,
    /// Dispatched packages skipped because their route carried custom-registry
    /// auth; the authoritative fetch path remains the only credentialed actor.
    pub(super) skipped_auth: u64,
    /// Completed before the authoritative fetch loop started. This is the
    /// clearest "was speculation early enough?" signal.
    pub(super) completed_before_fetch: u64,
    /// Final-graph packages whose authoritative fetch was skipped because a
    /// speculative tarball had already materialized the same source-aware key.
    pub(super) consumed_by_fetch: u64,
    /// Final-graph packages where speculation failed and the authoritative
    /// fetch still had to download the same source-aware key.
    pub(super) duplicated_with_fetch: u64,
    /// Completed speculative downloads that were not present in the final
    /// resolved graph.
    pub(super) wasted: u64,
}

impl SpeculativeStats {
    pub(super) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "streaming_batch_ms": self.streaming_batch_ms,
            "dispatched": self.dispatched,
            "completed": self.completed,
            "task_ms_sum": self.task_ms_sum,
            "transitive_dispatched": self.transitive_dispatched,
            "max_depth_reached": self.max_depth_reached,
            "no_version_match": self.no_version_match,
            "unresolved_parked": self.unresolved_parked,
            "failed": self.failed,
            "skipped_no_permit": self.skipped_no_permit,
            "skipped_auth": self.skipped_auth,
            "completed_before_fetch": self.completed_before_fetch,
            "consumed_by_fetch": self.consumed_by_fetch,
            "duplicated_with_fetch": self.duplicated_with_fetch,
            "wasted": self.wasted,
        })
    }
}

#[derive(Clone, Default)]
pub(super) struct SpeculativeKeyTracker {
    completed_keys: std::sync::Arc<dashmap::DashSet<String>>,
    failed_keys: std::sync::Arc<dashmap::DashSet<String>>,
    consumed_keys: std::sync::Arc<dashmap::DashSet<String>>,
    duplicated_keys: std::sync::Arc<dashmap::DashSet<String>>,
}

impl SpeculativeKeyTracker {
    pub(super) fn record_completed(&self, key: String) {
        self.completed_keys.insert(key);
    }

    pub(super) fn record_failed(&self, key: String) {
        self.failed_keys.insert(key);
    }

    pub(super) fn mark_consumed_if_completed(&self, key: &str) {
        if self.completed_keys.contains(key) {
            self.consumed_keys.insert(key.to_string());
        }
    }

    pub(super) fn mark_duplicated_if_failed(&self, key: &str) {
        if self.failed_keys.contains(key) {
            self.duplicated_keys.insert(key.to_string());
        }
    }

    pub(super) fn completed_count(&self) -> u64 {
        self.completed_keys.len() as u64
    }

    pub(super) fn consumed_count(&self) -> u64 {
        self.consumed_keys.len() as u64
    }

    pub(super) fn duplicated_count(&self) -> u64 {
        self.duplicated_keys.len() as u64
    }

    pub(super) fn failed_count(&self) -> u64 {
        self.failed_keys.len() as u64
    }

    pub(super) fn wasted_count(&self, final_graph_keys: &HashSet<String>) -> u64 {
        self.completed_keys
            .iter()
            .filter(|key| !final_graph_keys.contains(key.as_str()))
            .count() as u64
    }
}

/// Cap on transitive-speculation depth. Prevents
/// unbounded fan-out on pathological trees (e.g. circular deps, or
/// very deep single-chains). Matches the worker's own deep-walk cap so
/// speculation doesn't ask for manifests the worker won't send.
pub(super) const SPECULATION_MAX_DEPTH: u32 = 5;
pub(super) const DEFAULT_FUSION_NPM_FANOUT: usize = lpm_resolver::DEFAULT_NPM_FANOUT;
pub(super) const DEFAULT_FUSION_OVERLAP_NPM_FANOUT: usize = 32;
pub(super) const DEFAULT_FUSION_SPECULATION_PERMITS: usize = DEFAULT_MAX_CONCURRENT_DOWNLOADS;
pub(super) const ENV_FUSION_SPECULATION_PERMITS: &str = "LPM_FUSION_SPECULATION_PERMITS";
pub(super) const ENV_VERIFY_REGISTRY_SIGNATURES: &str = "LPM_VERIFY_REGISTRY_SIGNATURES";

pub(super) fn default_fusion_npm_fanout(
    fetch_overlap_enabled: bool,
    _minimum_release_age_secs: u64,
) -> usize {
    if fetch_overlap_enabled {
        DEFAULT_FUSION_OVERLAP_NPM_FANOUT
    } else {
        DEFAULT_FUSION_NPM_FANOUT
    }
}

pub(super) fn parse_positive_usize_or_default(value: &str, default: usize) -> usize {
    value
        .parse::<usize>()
        .ok()
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

pub(super) fn positive_usize_env_or_default(name: &str, default: usize) -> usize {
    std::env::var(name).ok().map_or(default, |value| {
        parse_positive_usize_or_default(&value, default)
    })
}

pub(super) fn parse_bool_env_value(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

pub(super) fn registry_signature_verification_enabled(
    global_config: &crate::commands::config::GlobalConfig,
) -> bool {
    std::env::var(ENV_VERIFY_REGISTRY_SIGNATURES)
        .ok()
        .map_or_else(
            || global_config.get_bool("signatures").unwrap_or(false),
            |value| parse_bool_env_value(&value, false),
        )
}

impl FetchBreakdown {
    /// Fold one task's timings into the running aggregate.
    pub(super) fn record(&mut self, t: TaskTimings) {
        self.task_count += 1;
        let task_ms = t.total_ms();
        self.task_sum_ms = self.task_sum_ms.saturating_add(task_ms);
        self.task_max_ms = self.task_max_ms.max(task_ms);
        self.queue_wait_sum_ms += t.queue_wait_ms;
        self.queue_wait_max_ms = self.queue_wait_max_ms.max(t.queue_wait_ms);
        self.url_lookup_sum_ms += t.url_lookup_ms;
        self.url_lookup_max_ms = self.url_lookup_max_ms.max(t.url_lookup_ms);
        self.download_sum_ms += t.download_ms;
        self.download_max_ms = self.download_max_ms.max(t.download_ms);
        self.integrity_sum_ms += t.integrity_ms;
        self.integrity_max_ms = self.integrity_max_ms.max(t.integrity_ms);
        self.extract_permit_wait_sum_ms += t.extract_permit_wait_ms;
        self.extract_permit_wait_max_ms = self
            .extract_permit_wait_max_ms
            .max(t.extract_permit_wait_ms);
        self.extract_sum_ms += t.extract_ms;
        self.extract_max_ms = self.extract_max_ms.max(t.extract_ms);
        self.security_sum_ms += t.security_ms;
        self.security_max_ms = self.security_max_ms.max(t.security_ms);
        self.source_scan_sum_ns = self.source_scan_sum_ns.saturating_add(t.source_scan_ns);
        self.source_scan_max_ns = self.source_scan_max_ns.max(t.source_scan_ns);
        self.finalize_permit_wait_sum_ms += t.finalize_permit_wait_ms;
        self.finalize_permit_wait_max_ms = self
            .finalize_permit_wait_max_ms
            .max(t.finalize_permit_wait_ms);
        self.finalize_sum_ms += t.finalize_ms;
        self.finalize_max_ms = self.finalize_max_ms.max(t.finalize_ms);
    }

    /// Serialize as a JSON object for `lpm install --json` output.
    pub(super) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "task_count": self.task_count,
            "task_sum_ms": self.task_sum_ms,
            "task_max_ms": self.task_max_ms,
            "queue_wait":  { "sum_ms": self.queue_wait_sum_ms,  "max_ms": self.queue_wait_max_ms  },
            "url_lookup":  { "sum_ms": self.url_lookup_sum_ms,  "max_ms": self.url_lookup_max_ms  },
            "download":    { "sum_ms": self.download_sum_ms,    "max_ms": self.download_max_ms    },
            "integrity":   { "sum_ms": self.integrity_sum_ms,   "max_ms": self.integrity_max_ms   },
            "extract_permit_wait": { "sum_ms": self.extract_permit_wait_sum_ms, "max_ms": self.extract_permit_wait_max_ms },
            "extract":     { "sum_ms": self.extract_sum_ms,     "max_ms": self.extract_max_ms     },
            "security":    { "sum_ms": self.security_sum_ms,    "max_ms": self.security_max_ms    },
            "source_scan": { "sum_ns": self.source_scan_sum_ns, "max_ns": self.source_scan_max_ns },
            "finalize_permit_wait": { "sum_ms": self.finalize_permit_wait_sum_ms, "max_ms": self.finalize_permit_wait_max_ms },
            "finalize":    { "sum_ms": self.finalize_sum_ms,    "max_ms": self.finalize_max_ms    },
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FetchOverlapStats {
    pub(super) selected_count: u64,
    pub(super) dispatched_count: u64,
    pub(super) completed_count: u64,
    pub(super) cache_hit_count: u64,
    pub(super) failed_count: u64,
    pub(super) skipped_platform_count: u64,
    pub(super) skipped_auth_count: u64,
    pub(super) skipped_optional_count: u64,
    pub(super) skipped_engine_count: u64,
    pub(super) buffered_count: u64,
    pub(super) buffered_dispatch_count: u64,
    pub(super) buffer_wait_sum_ms: u128,
    pub(super) buffer_wait_max_ms: u128,
    pub(super) breakdown: FetchBreakdown,
    pub(super) drain_ms: u128,
}

impl FetchOverlapStats {
    pub(super) fn record_buffered_event(&mut self) {
        self.buffered_count = self.buffered_count.saturating_add(1);
    }

    pub(super) fn record_buffered_dispatch(&mut self, wait_ms: u128) {
        self.buffered_dispatch_count = self.buffered_dispatch_count.saturating_add(1);
        self.buffer_wait_sum_ms = self.buffer_wait_sum_ms.saturating_add(wait_ms);
        self.buffer_wait_max_ms = self.buffer_wait_max_ms.max(wait_ms);
    }

    pub(super) fn record_task(&mut self, timings: TaskTimings) {
        self.breakdown.record(timings);
    }

    pub(super) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "selected_count": self.selected_count,
            "dispatched_count": self.dispatched_count,
            "completed_count": self.completed_count,
            "cache_hit_count": self.cache_hit_count,
            "failed_count": self.failed_count,
            "skipped_platform_count": self.skipped_platform_count,
            "skipped_auth_count": self.skipped_auth_count,
            "skipped_optional_count": self.skipped_optional_count,
            "skipped_engine_count": self.skipped_engine_count,
            "buffered_count": self.buffered_count,
            "buffered_dispatch_count": self.buffered_dispatch_count,
            "buffered_undispatched_count": self.buffered_count.saturating_sub(self.buffered_dispatch_count),
            "buffer_wait": {
                "sum_ms": self.buffer_wait_sum_ms,
                "max_ms": self.buffer_wait_max_ms,
            },
            "task_sum_ms": self.breakdown.task_sum_ms,
            "task_max_ms": self.breakdown.task_max_ms,
            "breakdown": self.breakdown.to_json(),
            "drain_ms": self.drain_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct V2ReusableValidationTimings {
    pub(super) checked_count: u64,
    pub(super) hit_count: u64,
    pub(super) miss_count: u64,
    pub(super) total_ms: u128,
    pub(super) max_check_ms: u128,
    pub(super) missing_count: u64,
    pub(super) complete_check_ms: u128,
    pub(super) object_sidecar_read_count: u64,
    pub(super) object_sidecar_read_ms: u128,
    pub(super) snapshot_read_count: u64,
    pub(super) snapshot_read_ms: u128,
    pub(super) snapshot_hit_count: u64,
    pub(super) snapshot_miss_count: u64,
    pub(super) metadata_hash_count: u64,
    pub(super) metadata_hash_ms: u128,
    pub(super) full_hash_count: u64,
    pub(super) full_hash_ms: u128,
    pub(super) removed_count: u64,
    pub(super) remove_ms: u128,
}

impl V2ReusableValidationTimings {
    pub(super) fn record(&mut self, timings: lpm_store::v2::ReusableObjectCheckTimings, hit: bool) {
        self.checked_count = self.checked_count.saturating_add(1);
        if hit {
            self.hit_count = self.hit_count.saturating_add(1);
        } else {
            self.miss_count = self.miss_count.saturating_add(1);
        }
        self.total_ms = self.total_ms.saturating_add(timings.total_ms);
        self.max_check_ms = self.max_check_ms.max(timings.total_ms);
        self.missing_count = self.missing_count.saturating_add(timings.missing_count);
        self.complete_check_ms = self
            .complete_check_ms
            .saturating_add(timings.complete_check_ms);
        self.object_sidecar_read_count = self
            .object_sidecar_read_count
            .saturating_add(timings.object_sidecar_read_count);
        self.object_sidecar_read_ms = self
            .object_sidecar_read_ms
            .saturating_add(timings.object_sidecar_read_ms);
        self.snapshot_read_count = self
            .snapshot_read_count
            .saturating_add(timings.snapshot_read_count);
        self.snapshot_read_ms = self
            .snapshot_read_ms
            .saturating_add(timings.snapshot_read_ms);
        self.snapshot_hit_count = self
            .snapshot_hit_count
            .saturating_add(timings.snapshot_hit_count);
        self.snapshot_miss_count = self
            .snapshot_miss_count
            .saturating_add(timings.snapshot_miss_count);
        self.metadata_hash_count = self
            .metadata_hash_count
            .saturating_add(timings.metadata_hash_count);
        self.metadata_hash_ms = self
            .metadata_hash_ms
            .saturating_add(timings.metadata_hash_ms);
        self.full_hash_count = self.full_hash_count.saturating_add(timings.full_hash_count);
        self.full_hash_ms = self.full_hash_ms.saturating_add(timings.full_hash_ms);
        self.removed_count = self.removed_count.saturating_add(timings.removed_count);
        self.remove_ms = self.remove_ms.saturating_add(timings.remove_ms);
    }

    pub(super) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "checked_count": self.checked_count,
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "total_ms": self.total_ms,
            "max_check_ms": self.max_check_ms,
            "missing_count": self.missing_count,
            "complete_check_ms": self.complete_check_ms,
            "object_sidecar_read_count": self.object_sidecar_read_count,
            "object_sidecar_read_ms": self.object_sidecar_read_ms,
            "snapshot_read_count": self.snapshot_read_count,
            "snapshot_read_ms": self.snapshot_read_ms,
            "snapshot_hit_count": self.snapshot_hit_count,
            "snapshot_miss_count": self.snapshot_miss_count,
            "metadata_hash_count": self.metadata_hash_count,
            "metadata_hash_ms": self.metadata_hash_ms,
            "full_hash_count": self.full_hash_count,
            "full_hash_ms": self.full_hash_ms,
            "removed_count": self.removed_count,
            "remove_ms": self.remove_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct V2LinkTaskTimings {
    pub(super) task_count: u64,
    pub(super) freshly_populated_count: u64,
    pub(super) task_sum_ms: u128,
    pub(super) task_max_ms: u128,
}

impl V2LinkTaskTimings {
    pub(super) fn record(&mut self, ms: u128, freshly_populated: bool) {
        self.task_count = self.task_count.saturating_add(1);
        if freshly_populated {
            self.freshly_populated_count = self.freshly_populated_count.saturating_add(1);
        }
        self.task_sum_ms = self.task_sum_ms.saturating_add(ms);
        self.task_max_ms = self.task_max_ms.max(ms);
    }

    pub(super) fn to_json(self, await_ms: u128) -> serde_json::Value {
        serde_json::json!({
            "task_count": self.task_count,
            "freshly_populated_count": self.freshly_populated_count,
            "reused_entry_count": self.task_count.saturating_sub(self.freshly_populated_count),
            "task_sum_ms": self.task_sum_ms,
            "task_max_ms": self.task_max_ms,
            "await_ms": await_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FetchStageTimings {
    pub(super) plan_ms: u128,
    pub(super) v2_reusable_prevalidate_ms: u128,
    pub(super) cache_classify_ms: u128,
    pub(super) cache_classify_local_source_ms: u128,
    pub(super) cache_classify_v2_reusable_hit_ms: u128,
    pub(super) cache_classify_v1_to_v2_translate_ms: u128,
    pub(super) cache_classify_v1_cache_hit_ms: u128,
    pub(super) cache_classify_download_candidate_ms: u128,
    pub(super) cache_classify_link_dispatch_ms: u128,
    pub(super) policy_gate_ms: u128,
    pub(super) download_wall_ms: u128,
    pub(super) v2_reusable_candidate_count: u64,
    pub(super) v2_reusable_concurrency: u64,
    pub(super) local_source_count: u64,
    pub(super) v2_reusable_hit_count: u64,
    pub(super) v1_to_v2_translate_count: u64,
    pub(super) v1_to_v2_translate_failure_count: u64,
    pub(super) v1_cache_hit_count: u64,
    pub(super) link_dispatch_count: u64,
    pub(super) v2_reusable_validation: V2ReusableValidationTimings,
    pub(super) overlap: FetchOverlapStats,
}

impl FetchStageTimings {
    pub(super) fn to_json(
        self,
        fetch_wall_ms: u128,
        package_count: usize,
        cached_count: usize,
        download_candidate_count: usize,
        breakdown: FetchBreakdown,
    ) -> serde_json::Value {
        serde_json::json!({
            "stage": {
                "wall_ms": fetch_wall_ms,
                "plan_ms": self.plan_ms,
                "v2_reusable_prevalidate_ms": self.v2_reusable_prevalidate_ms,
                "cache_classify_ms": self.cache_classify_ms,
                "policy_gate_ms": self.policy_gate_ms,
                "download_wall_ms": self.download_wall_ms,
                "other_ms": fetch_wall_ms
                    .saturating_sub(self.plan_ms)
                    .saturating_sub(self.v2_reusable_prevalidate_ms)
                    .saturating_sub(self.cache_classify_ms)
                    .saturating_sub(self.policy_gate_ms)
                    .saturating_sub(self.download_wall_ms),
            },
            "classification": {
                "wall_ms": self.cache_classify_ms,
                "local_source_ms": self.cache_classify_local_source_ms,
                "v2_reusable_hit_ms": self.cache_classify_v2_reusable_hit_ms,
                "v1_to_v2_translate_ms": self.cache_classify_v1_to_v2_translate_ms,
                "v1_cache_hit_ms": self.cache_classify_v1_cache_hit_ms,
                "download_candidate_ms": self.cache_classify_download_candidate_ms,
                "link_dispatch_ms": self.cache_classify_link_dispatch_ms,
                "other_ms": self.cache_classify_ms
                    .saturating_sub(self.cache_classify_local_source_ms)
                    .saturating_sub(self.cache_classify_v2_reusable_hit_ms)
                    .saturating_sub(self.cache_classify_v1_to_v2_translate_ms)
                    .saturating_sub(self.cache_classify_v1_cache_hit_ms)
                    .saturating_sub(self.cache_classify_download_candidate_ms),
            },
            "counts": {
                "package_count": package_count as u64,
                "cached_count": cached_count as u64,
                "download_candidate_count": download_candidate_count as u64,
                "v2_reusable_candidate_count": self.v2_reusable_candidate_count,
                "v2_reusable_hit_count": self.v2_reusable_hit_count,
                "v2_reusable_concurrency": self.v2_reusable_concurrency,
                "local_source_count": self.local_source_count,
                "v1_cache_hit_count": self.v1_cache_hit_count,
                "v1_to_v2_translate_count": self.v1_to_v2_translate_count,
                "v1_to_v2_translate_failure_count": self.v1_to_v2_translate_failure_count,
                "link_dispatch_count": self.link_dispatch_count,
            },
            "v2_reusable_validation": self.v2_reusable_validation.to_json(),
            "overlap": self.overlap.to_json(),
            "breakdown": breakdown.to_json(),
        })
    }
}

///
///
/// Shared across every fetch task (must be atomic because 24
/// concurrent permit-holders may increment these). Surfaces on
/// `timing.fetch_breakdown` at install-end so an A/B bench can tell
/// whether stored URLs are actually being reused or the gate is
/// incorrectly rejecting them.
///
/// `shape_mismatch > 0` is a BUG signal — the writer should never
/// emit a gate-rejectable URL. `origin_mismatch > 0` is expected
/// after `LPM_REGISTRY_URL` switches (stored origins rebased out).
#[derive(Default, Debug)]
pub(super) struct GateStats {
    /// Origin-mismatch rejections (cached URL doesn't match current
    /// `{base_url, npm_registry_url}`). Expected non-zero after a
    /// registry switch; drops back to 0 once the writeback trigger
    /// ( Change 3, landing in a follow-up commit) persists the
    /// rebased URLs.
    pub(super) origin_mismatch: std::sync::atomic::AtomicU64,
    /// Shape-mismatch rejections (URL path doesn't contain `/-/`
    /// or doesn't end in `.tgz`). Should always be 0 — a writer
    /// regression or a tampered lockfile otherwise.
    pub(super) shape_mismatch: std::sync::atomic::AtomicU64,
    /// Scheme-mismatch rejections (neither HTTPS nor
    /// `http://localhost`). Same invariant as `shape_mismatch`:
    /// the writer never emits a scheme-unsafe URL, so a non-zero
    /// counter is a corrupt-lockfile signal.
    pub(super) scheme_mismatch: std::sync::atomic::AtomicU64,
    /// Stored URL 404'd and the same-run retry (refresh metadata
    /// → fetch fresh URL) succeeded. Expected near-zero in steady
    /// state once the writeback trigger lands; persistent non-zero
    /// = stored URLs keep going stale faster than writeback can
    /// refresh them.
    pub(super) stale_recovery: std::sync::atomic::AtomicU64,
    /// Stored URL 404'd AND the same-run retry also failed (or
    /// the fresh URL matched the stale one, indicating metadata
    /// itself is stuck). Package really isn't reachable — lockfile
    /// gets deleted, user re-resolves.
    pub(super) stale_hard_fail: std::sync::atomic::AtomicU64,
}

impl GateStats {
    pub(super) fn to_json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        serde_json::json!({
            "origin_mismatch_count":  self.origin_mismatch.load(Ordering::Relaxed),
            "shape_mismatch_count":   self.shape_mismatch.load(Ordering::Relaxed),
            "scheme_mismatch_count":  self.scheme_mismatch.load(Ordering::Relaxed),
            "stale_recovery_count":   self.stale_recovery.load(Ordering::Relaxed),
            "stale_hard_fail_count":  self.stale_hard_fail.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum TimingDetailMode {
    Off,
    Detail,
    Trace,
}

impl TimingDetailMode {
    pub(super) fn from_env() -> Self {
        std::env::var("LPM_TIMING_DETAIL")
            .ok()
            .map_or(Self::Off, |value| {
                if value.eq_ignore_ascii_case("trace") {
                    Self::Trace
                } else {
                    Self::Detail
                }
            })
    }

    pub(super) fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub(super) fn trace(self) -> bool {
        matches!(self, Self::Trace)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct SlowPackageTimings {
    tarball_http: Vec<PackageTiming>,
    extract: Vec<PackageTiming>,
    security: Vec<PackageTiming>,
    finalize: Vec<PackageTiming>,
    fetch_tasks_by_total: Vec<FetchTaskTiming>,
    fetch_tasks_by_extract: Vec<FetchTaskTiming>,
    fetch_tasks_by_security: Vec<FetchTaskTiming>,
    fetch_tasks_by_finalize: Vec<FetchTaskTiming>,
    link_v2_one: Vec<LinkV2OneTiming>,
}

#[derive(Debug, Clone)]
struct PackageTiming {
    package: String,
    ms: u128,
}

#[derive(Debug, Clone)]
struct FetchTaskTiming {
    package: String,
    timings: TaskTimings,
    task_total_ms: u128,
}

#[derive(Debug, Clone)]
struct LinkV2OneTiming {
    package: String,
    ms: u128,
    timings: lpm_store::v2::LinkEntryTimings,
}

impl SlowPackageTimings {
    pub(super) fn record_fetch(&mut self, package: &str, timings: TaskTimings) {
        Self::record(&mut self.tarball_http, package, timings.download_ms);
        Self::record(&mut self.extract, package, timings.extract_ms);
        Self::record(&mut self.security, package, timings.security_ms);
        Self::record(&mut self.finalize, package, timings.finalize_ms);
        let row = FetchTaskTiming {
            package: package.to_string(),
            timings,
            task_total_ms: timings.total_ms(),
        };
        Self::record_fetch_task(&mut self.fetch_tasks_by_total, &row, |entry| {
            entry.task_total_ms
        });
        Self::record_fetch_task(&mut self.fetch_tasks_by_extract, &row, |entry| {
            entry.timings.extract_ms
        });
        Self::record_fetch_task(&mut self.fetch_tasks_by_security, &row, |entry| {
            entry.timings.security_ms
        });
        Self::record_fetch_task(&mut self.fetch_tasks_by_finalize, &row, |entry| {
            entry.timings.finalize_ms
        });
    }

    pub(super) fn record_link_v2_one(
        &mut self,
        package: &str,
        ms: u128,
        timings: lpm_store::v2::LinkEntryTimings,
    ) {
        if ms == 0 {
            return;
        }
        self.link_v2_one.push(LinkV2OneTiming {
            package: package.to_string(),
            ms,
            timings,
        });
        self.link_v2_one
            .sort_unstable_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.package.cmp(&b.package)));
        self.link_v2_one.truncate(10);
    }

    fn record(bucket: &mut Vec<PackageTiming>, package: &str, ms: u128) {
        if ms == 0 {
            return;
        }
        bucket.push(PackageTiming {
            package: package.to_string(),
            ms,
        });
        bucket.sort_unstable_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.package.cmp(&b.package)));
        bucket.truncate(10);
    }

    fn record_fetch_task(
        bucket: &mut Vec<FetchTaskTiming>,
        row: &FetchTaskTiming,
        rank_ms: impl Fn(&FetchTaskTiming) -> u128 + Copy,
    ) {
        if rank_ms(row) == 0 {
            return;
        }
        bucket.push(row.clone());
        bucket.sort_unstable_by(|a, b| {
            rank_ms(b)
                .cmp(&rank_ms(a))
                .then_with(|| a.package.cmp(&b.package))
        });
        bucket.truncate(10);
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tarball_http": Self::bucket_json(&self.tarball_http),
            "extract": Self::bucket_json(&self.extract),
            "security": Self::bucket_json(&self.security),
            "finalize": Self::bucket_json(&self.finalize),
            "fetch_tasks": {
                "by_total": Self::fetch_task_bucket_json(&self.fetch_tasks_by_total),
                "by_extract": Self::fetch_task_bucket_json(&self.fetch_tasks_by_extract),
                "by_security": Self::fetch_task_bucket_json(&self.fetch_tasks_by_security),
                "by_finalize": Self::fetch_task_bucket_json(&self.fetch_tasks_by_finalize),
            },
            "link_v2_one": Self::link_v2_one_bucket_json(&self.link_v2_one),
        })
    }

    fn bucket_json(bucket: &[PackageTiming]) -> serde_json::Value {
        serde_json::Value::Array(
            bucket
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "package": entry.package,
                        "ms": entry.ms,
                    })
                })
                .collect(),
        )
    }

    fn fetch_task_bucket_json(bucket: &[FetchTaskTiming]) -> serde_json::Value {
        serde_json::Value::Array(
            bucket
                .iter()
                .map(|entry| {
                    let timings = entry.timings;
                    serde_json::json!({
                        "package": entry.package,
                        "task_total_ms": entry.task_total_ms,
                        "queue_wait_ms": timings.queue_wait_ms,
                        "url_lookup_ms": timings.url_lookup_ms,
                        "download_ms": timings.download_ms,
                        "integrity_ms": timings.integrity_ms,
                        "extract_permit_wait_ms": timings.extract_permit_wait_ms,
                        "extract_ms": timings.extract_ms,
                        "security_ms": timings.security_ms,
                        "source_scan_ns": timings.source_scan_ns,
                        "finalize_permit_wait_ms": timings.finalize_permit_wait_ms,
                        "finalize_ms": timings.finalize_ms,
                        "finalize_tree_integrity_ms": timings.finalize_tree_integrity_ms,
                        "finalize_integrity_write_ms": timings.finalize_integrity_write_ms,
                        "finalize_rename_ms": timings.finalize_rename_ms,
                        "finalize_collision_recovery_ms": timings.finalize_collision_recovery_ms,
                        "file_count": timings.file_count,
                        "dir_count": timings.dir_count,
                        "symlink_count": timings.symlink_count,
                        "unpacked_bytes": timings.unpacked_bytes,
                    })
                })
                .collect(),
        )
    }

    fn link_v2_one_bucket_json(bucket: &[LinkV2OneTiming]) -> serde_json::Value {
        serde_json::Value::Array(
            bucket
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "package": entry.package,
                        "ms": entry.ms,
                        "reuse_check_ms": entry.timings.reuse_check_ms,
                        "object_integrity_ms": entry.timings.object_integrity_ms,
                        "materialize_ms": entry.timings.materialize_ms,
                        "snapshot_ms": entry.timings.snapshot_ms,
                        "symlink_ms": entry.timings.symlink_ms,
                        "sidecar_ms": entry.timings.sidecar_ms,
                        "rename_ms": entry.timings.rename_ms,
                        "collision_recovery_ms": entry.timings.collision_recovery_ms,
                    })
                })
                .collect(),
        )
    }
}

pub(super) fn setup_only_timing_detail_json(
    mode: TimingDetailMode,
    setup_total_ms: u128,
    install_state_ms: u128,
    route_table_ms: u128,
) -> serde_json::Value {
    let metadata = metadata_detail_snapshots();
    let mut detail = serde_json::json!({
        "setup": {
            "install_state_ms": install_state_ms,
            "route_table_ms": route_table_ms,
            "other_ms": setup_total_ms.saturating_sub(
                install_state_ms.saturating_add(route_table_ms),
            ),
        },
        "metadata": metadata_detail_json_from_snapshots(&metadata, mode),
        "resolve": resolve_detail_json(
            0,
            0,
            &lpm_resolver::StageTiming::default(),
            &metadata,
            mode,
        ),
        "fetch": FetchStageTimings::default().to_json(0, 0, 0, 0, FetchBreakdown::default()),
        "security": {
            "registry_signatures": serde_json::Value::Null,
            "provenance": serde_json::Value::Null,
        },
        "link": {
            "reconcile_ms": 0u128,
            "root_symlinks_ms": 0u128,
            "compatibility_ms": 0u128,
            "bin_shims_ms": 0u128,
            "v2_one": V2LinkTaskTimings::default().to_json(0),
        },
        "tail": {
            "blocked_metadata_ms": 0u128,
            "trust_snapshot_ms": 0u128,
            "lockfile_write_ms": 0u128,
            "lockfile_write_count": 0u64,
            "build_state_write_ms": 0u64,
            "build_state_write_count": 0u64,
            "audit_after_install_ms": 0u128,
            "other_ms": 0u128,
        },
    });
    if mode.trace() {
        let mut slow_packages = SlowPackageTimings::default().to_json();
        if let serde_json::Value::Object(slow_packages) = &mut slow_packages {
            slow_packages.insert(
                "provenance_verify".to_string(),
                serde_json::Value::Array(Vec::new()),
            );
        }
        detail["trace"] = serde_json::json!({
            "slow_packages": slow_packages,
        });
    }
    detail
}

pub(super) fn metadata_detail_snapshots() -> Vec<lpm_registry::timing::MetadataPurposeSnapshot> {
    lpm_registry::timing::snapshot_metadata_detail()
}

pub(super) fn metadata_detail_json_from_snapshots(
    snapshots: &[lpm_registry::timing::MetadataPurposeSnapshot],
    mode: TimingDetailMode,
) -> serde_json::Value {
    serde_json::Value::Array(
        snapshots
            .iter()
            .map(|snapshot| {
                let mut entry = serde_json::json!({
                    "purpose": snapshot.purpose,
                    "rpc_ms": snapshot.rpc.as_millis(),
                    "rpc_count": snapshot.rpc_count,
                    "cache_hit_count": snapshot.cache_hit_count,
                    "cache_miss_count": snapshot.cache_miss_count,
                    "request_count": snapshot.request_count,
                    "unique_package_count": snapshot.unique_package_count,
                    "duplicate_request_count": snapshot.duplicate_request_count,
                });
                if mode.trace() {
                    entry["top_duplicate_packages"] = serde_json::Value::Array(
                        snapshot
                            .top_duplicate_packages
                            .iter()
                            .map(|package| {
                                serde_json::json!({
                                    "package": package.package.as_str(),
                                    "request_count": package.request_count,
                                    "duplicate_count": package.duplicate_count,
                                })
                            })
                            .collect(),
                    );
                }
                entry
            })
            .collect(),
    )
}

fn metadata_fetch_detail_json_from_snapshot(
    snapshot: &lpm_registry::timing::MetadataFetchDetailSnapshot,
    mode: TimingDetailMode,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "scope": "per_package_metadata_fetches",
        "batch_fetches_included": false,
        "calls": snapshot.calls,
        "cache_hit_count": snapshot.cache_hit_count,
        "not_modified_count": snapshot.not_modified_count,
        "body_bytes_sum": snapshot.body_bytes_sum,
        "version_count_sum": snapshot.version_count_sum,
        "routes": {
            "npm_direct": snapshot.route_npm_direct_count,
            "lpm_worker": snapshot.route_lpm_worker_count,
            "custom": snapshot.route_custom_count,
            "lpm": snapshot.route_lpm_count,
            "unknown": snapshot.route_unknown_count,
        },
        "attribution": {
            "total_sum_ms": snapshot.attribution.total_sum_ms,
            "total_max_ms": snapshot.attribution.total_max_ms,
            "raw_fetch_sum_ms": snapshot.attribution.raw_fetch_sum_ms,
            "raw_fetch_max_ms": snapshot.attribution.raw_fetch_max_ms,
            "cache_read_sum_ms": snapshot.attribution.cache_read_sum_ms,
            "validator_read_sum_ms": snapshot.attribution.validator_read_sum_ms,
            "http_sum_ms": snapshot.attribution.http_sum_ms,
            "body_read_sum_ms": snapshot.attribution.body_read_sum_ms,
            "json_decode_sum_ms": snapshot.attribution.json_decode_sum_ms,
            "cache_after_304_sum_ms": snapshot.attribution.cache_after_304_sum_ms,
            "cache_write_dispatch_sum_ms": snapshot.attribution.cache_write_dispatch_sum_ms,
            "cache_info_parse_sum_ms": snapshot.attribution.cache_info_parse_sum_ms,
            "policy_release_time_sum_ms": snapshot.attribution.policy_release_time_sum_ms,
            "policy_release_time_fetch": {
                "total_sum_ms": snapshot.attribution.policy_release_time_fetch_sum_ms,
                "cache_read_sum_ms": snapshot.attribution.policy_release_time_cache_read_sum_ms,
                "validator_read_sum_ms": snapshot
                    .attribution
                    .policy_release_time_validator_read_sum_ms,
                "http_sum_ms": snapshot.attribution.policy_release_time_http_sum_ms,
                "body_read_sum_ms": snapshot.attribution.policy_release_time_body_read_sum_ms,
                "json_decode_sum_ms": snapshot
                    .attribution
                    .policy_release_time_json_decode_sum_ms,
                "cache_after_304_sum_ms": snapshot
                    .attribution
                    .policy_release_time_cache_after_304_sum_ms,
                "cache_write_dispatch_sum_ms": snapshot
                    .attribution
                    .policy_release_time_cache_write_dispatch_sum_ms,
                "body_bytes_sum": snapshot.attribution.policy_release_time_body_bytes_sum,
                "version_count_sum": snapshot.attribution.policy_release_time_version_count_sum,
                "cache_hit_count": snapshot.attribution.policy_release_time_cache_hit_count,
                "not_modified_count": snapshot
                    .attribution
                    .policy_release_time_not_modified_count,
            },
            "policy_full_metadata_sum_ms": snapshot.attribution.policy_full_metadata_sum_ms,
        },
    });
    if mode.trace() {
        json["top_slow_packages"] = serde_json::json!({
            "by_total": metadata_fetch_bucket_json(&snapshot.top_slow_packages.by_total),
            "by_raw_fetch": metadata_fetch_bucket_json(&snapshot.top_slow_packages.by_raw_fetch),
            "by_http": metadata_fetch_bucket_json(&snapshot.top_slow_packages.by_http),
            "by_body_read": metadata_fetch_bucket_json(&snapshot.top_slow_packages.by_body_read),
            "by_body_bytes": metadata_fetch_bucket_json(&snapshot.top_slow_packages.by_body_bytes),
            "by_json_decode": metadata_fetch_bucket_json(
                &snapshot.top_slow_packages.by_json_decode,
            ),
            "by_cache_info_parse": metadata_fetch_bucket_json(
                &snapshot.top_slow_packages.by_cache_info_parse,
            ),
            "by_policy_release_time": metadata_fetch_bucket_json(
                &snapshot.top_slow_packages.by_policy_release_time,
            ),
            "by_policy_release_time_fetch": metadata_fetch_bucket_json(
                &snapshot.top_slow_packages.by_policy_release_time_fetch,
            ),
            "by_policy_full_metadata": metadata_fetch_bucket_json(
                &snapshot.top_slow_packages.by_policy_full_metadata,
            ),
        });
        json["top_direct_packuments"] = serde_json::json!({
            "by_http": metadata_fetch_bucket_json(&snapshot.top_direct_packuments.by_http),
            "by_body_bytes": metadata_fetch_bucket_json(
                &snapshot.top_direct_packuments.by_body_bytes,
            ),
            "by_policy_release_time_fetch": metadata_fetch_bucket_json(
                &snapshot.top_direct_packuments.by_policy_release_time_fetch,
            ),
            "by_policy_release_time_body_bytes": metadata_fetch_bucket_json(
                &snapshot
                    .top_direct_packuments
                    .by_policy_release_time_body_bytes,
            ),
        });
    }
    json
}

fn metadata_fetch_bucket_json(
    bucket: &[lpm_registry::timing::MetadataFetchDetailRecord],
) -> serde_json::Value {
    serde_json::Value::Array(
        bucket
            .iter()
            .map(|record| {
                serde_json::json!({
                    "package": record.package,
                    "route": record.route,
                    "total_ms": record.total_ms,
                    "raw_fetch_ms": record.raw_fetch_ms,
                    "cache_read_ms": record.cache_read_ms,
                    "validator_read_ms": record.validator_read_ms,
                    "http_ms": record.http_ms,
                    "body_read_ms": record.body_read_ms,
                    "json_decode_ms": record.json_decode_ms,
                    "cache_after_304_ms": record.cache_after_304_ms,
                    "cache_write_dispatch_ms": record.cache_write_dispatch_ms,
                    "cache_info_parse_ms": record.cache_info_parse_ms,
                    "policy_release_time_ms": record.policy_release_time_ms,
                    "policy_release_time_fetch": {
                        "total_ms": record.policy_release_time_fetch_ms,
                        "cache_read_ms": record.policy_release_time_cache_read_ms,
                        "validator_read_ms": record.policy_release_time_validator_read_ms,
                        "http_ms": record.policy_release_time_http_ms,
                        "body_read_ms": record.policy_release_time_body_read_ms,
                        "json_decode_ms": record.policy_release_time_json_decode_ms,
                        "cache_after_304_ms": record.policy_release_time_cache_after_304_ms,
                        "cache_write_dispatch_ms": record
                            .policy_release_time_cache_write_dispatch_ms,
                        "body_bytes": record.policy_release_time_body_bytes,
                        "version_count": record.policy_release_time_version_count,
                        "cache_hit": record.policy_release_time_cache_hit,
                        "not_modified": record.policy_release_time_not_modified,
                    },
                    "policy_full_metadata_ms": record.policy_full_metadata_ms,
                    "body_bytes": record.body_bytes,
                    "version_count": record.version_count,
                    "cache_hit": record.cache_hit,
                    "not_modified": record.not_modified,
                })
            })
            .collect(),
    )
}

pub(super) fn resolve_detail_json(
    resolve_wall_ms: u128,
    initial_batch_ms: u128,
    stage: &lpm_resolver::StageTiming,
    metadata_snapshots: &[lpm_registry::timing::MetadataPurposeSnapshot],
    mode: TimingDetailMode,
) -> serde_json::Value {
    let default_metadata = lpm_registry::timing::MetadataPurposeSnapshot::default();
    let resolve_metadata = metadata_snapshots
        .iter()
        .find(|snapshot| snapshot.purpose == "resolve")
        .unwrap_or(&default_metadata);
    let pubgrub_core_estimate_ms = stage.pubgrub_ms.saturating_sub(stage.followup_rpc_ms);
    let mut json = serde_json::json!({
        "wall_ms": resolve_wall_ms,
        "initial_batch_ms": initial_batch_ms,
        "metadata": {
            "rpc_sum_ms": resolve_metadata.rpc.as_millis(),
            "rpc_count": resolve_metadata.rpc_count,
            "cache_hit_count": resolve_metadata.cache_hit_count,
            "cache_miss_count": resolve_metadata.cache_miss_count,
            "request_count": resolve_metadata.request_count,
            "unique_package_count": resolve_metadata.unique_package_count,
            "duplicate_request_count": resolve_metadata.duplicate_request_count,
        },
        "scheduler": {
            "followup_rpc_ms": stage.followup_rpc_ms,
            "followup_rpc_count": stage.followup_rpc_count,
            "walker_rpc_count": stage.walker_rpc_count,
            "escape_hatch_rpc_count": stage.escape_hatch_rpc_count,
            "dispatcher": {
                "rpc_count": stage.dispatcher_rpc_count,
                "inflight_high_water": stage.dispatcher_inflight_high_water,
                "parked_max_depth": stage.parked_max_depth,
                "tarball_dispatched": stage.tarball_dispatched_count,
                "peer_prefetch_count": stage.peer_prefetch_count,
            },
        },
        "cpu": {
            "parse_ndjson_ms": stage.parse_ndjson_ms,
            "pubgrub_ms": stage.pubgrub_ms,
            "pubgrub_core_estimate_ms": pubgrub_core_estimate_ms,
        },
        "work": {
            "edge_process_count": stage.work_edge_process_count,
            "edge_reuse_count": stage.work_edge_reuse_count,
            "edge_reuse_range_count": stage.work_edge_reuse_range_count,
            "edge_reuse_exact_count": stage.work_edge_reuse_exact_count,
            "edge_non_reuse_count": stage.work_edge_process_count
                .saturating_sub(stage.work_edge_reuse_count),
            "node_allocated_count": stage.work_node_allocated_count,
            "child_edge_enqueued_count": stage.work_child_edge_enqueued_count,
            "peer_requirement_count": stage.work_peer_requirement_count,
            "metadata_edge_miss_count": stage.work_metadata_edge_miss_count,
            "metadata_edge_miss_direct_count": stage.work_metadata_edge_miss_direct_count,
            "metadata_edge_miss_latest_known_count": stage.work_metadata_edge_miss_latest_known_count,
            "metadata_edge_miss_latest_known_direct_count": stage
                .work_metadata_edge_miss_latest_known_direct_count,
            "metadata_edge_miss_latest_satisfies_count": stage
                .work_metadata_edge_miss_latest_satisfies_count,
            "metadata_edge_miss_latest_satisfies_direct_count": stage
                .work_metadata_edge_miss_latest_satisfies_direct_count,
            "metadata_edge_miss_latest_matches_pick_count": stage
                .work_metadata_edge_miss_latest_matches_pick_count,
            "metadata_edge_miss_latest_matches_pick_direct_count": stage
                .work_metadata_edge_miss_latest_matches_pick_direct_count,
            "metadata_edge_miss_version_doc_policy_eligible_count": stage
                .work_metadata_edge_miss_version_doc_policy_eligible_count,
            "metadata_edge_miss_version_doc_policy_eligible_direct_count": stage
                .work_metadata_edge_miss_version_doc_policy_eligible_direct_count,
            "metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count": stage
                .work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count,
            "metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count": stage
                .work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count,
            "metadata_edge_miss_range_shapes": {
                "exact": stage.work_metadata_edge_miss_exact_count,
                "star": stage.work_metadata_edge_miss_star_count,
                "caret": stage.work_metadata_edge_miss_caret_count,
                "tilde": stage.work_metadata_edge_miss_tilde_count,
                "comparator": stage.work_metadata_edge_miss_comparator_count,
                "complex": stage.work_metadata_edge_miss_complex_count,
                "other": stage.work_metadata_edge_miss_other_count,
            },
            "selected_package_count": stage.selected_package_count,
            "selected_unique_canonical_count": stage.selected_unique_canonical_count,
            "selected_duplicate_canonical_count": stage.selected_duplicate_canonical_count,
        },
        "policy": {
            "release_age": {
                "ms": stage.policy_release_age_ms,
                "checked_count": stage.policy_release_age_checked_count,
                "rejected_count": stage.policy_release_age_rejected_count,
                "missing_count": stage.policy_release_age_missing_count,
            },
            "trust": {
                "ms": stage.policy_trust_ms,
                "checked_count": stage.policy_trust_checked_count,
                "rejected_count": stage.policy_trust_rejected_count,
            },
        },
        "other_ms": resolve_wall_ms
            .saturating_sub(initial_batch_ms)
            .saturating_sub(stage.pubgrub_ms as u128),
    });
    if mode.trace() {
        let metadata_fetch_detail = lpm_registry::timing::snapshot_metadata_fetch_detail();
        json["metadata_fetch"] =
            metadata_fetch_detail_json_from_snapshot(&metadata_fetch_detail, mode);
    }
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fusion_npm_fanout_uses_overlap_scheduling_cap_when_overlap_enabled() {
        assert_eq!(default_fusion_npm_fanout(true, 0), 32);
    }

    #[test]
    fn default_fusion_npm_fanout_uses_overlap_scheduling_cap_with_release_age() {
        assert_eq!(default_fusion_npm_fanout(true, 86_400), 32);
    }

    #[test]
    fn default_fusion_npm_fanout_uses_wide_default_when_overlap_disabled() {
        assert_eq!(
            default_fusion_npm_fanout(false, 0),
            DEFAULT_FUSION_NPM_FANOUT
        );
    }

    #[test]
    fn default_fusion_npm_fanout_uses_wide_default_when_release_age_overlap_disabled() {
        assert_eq!(
            default_fusion_npm_fanout(false, 86_400),
            DEFAULT_FUSION_NPM_FANOUT
        );
    }

    #[test]
    fn fetch_stage_timings_reports_link_dispatch_as_classification_subset() {
        let timings = FetchStageTimings {
            cache_classify_ms: 10,
            cache_classify_v2_reusable_hit_ms: 6,
            cache_classify_download_candidate_ms: 2,
            cache_classify_link_dispatch_ms: 4,
            ..FetchStageTimings::default()
        };

        let json = timings.to_json(10, 1, 1, 0, FetchBreakdown::default());

        assert_eq!(json["classification"]["other_ms"], 2);
        assert_eq!(json["classification"]["link_dispatch_ms"], 4);
    }

    #[test]
    fn fetch_stage_timings_reports_v2_reusable_validation_counters() {
        let mut validation = V2ReusableValidationTimings::default();
        validation.record(
            lpm_store::v2::ReusableObjectCheckTimings {
                total_ms: 7,
                snapshot_hit_count: 1,
                metadata_hash_count: 1,
                ..lpm_store::v2::ReusableObjectCheckTimings::default()
            },
            true,
        );
        let timings = FetchStageTimings {
            v2_reusable_validation: validation,
            ..FetchStageTimings::default()
        };

        let json = timings.to_json(7, 1, 1, 0, FetchBreakdown::default());

        assert_eq!(json["v2_reusable_validation"]["checked_count"], 1);
        assert_eq!(json["v2_reusable_validation"]["hit_count"], 1);
        assert_eq!(json["v2_reusable_validation"]["snapshot_hit_count"], 1);
        assert_eq!(json["v2_reusable_validation"]["metadata_hash_count"], 1);
        assert_eq!(json["v2_reusable_validation"]["total_ms"], 7);
    }

    #[test]
    fn fetch_breakdown_reports_task_sum_and_max() {
        let mut breakdown = FetchBreakdown::default();
        breakdown.record(TaskTimings {
            queue_wait_ms: 1,
            url_lookup_ms: 2,
            download_ms: 3,
            integrity_ms: 4,
            extract_permit_wait_ms: 9,
            extract_ms: 5,
            security_ms: 6,
            finalize_permit_wait_ms: 8,
            finalize_ms: 7,
            ..TaskTimings::default()
        });
        breakdown.record(TaskTimings {
            queue_wait_ms: 2,
            download_ms: 3,
            extract_permit_wait_ms: 6,
            finalize_permit_wait_ms: 5,
            finalize_ms: 4,
            ..TaskTimings::default()
        });

        let json = breakdown.to_json();

        assert_eq!(json["task_count"], 2);
        assert_eq!(json["task_sum_ms"], 65);
        assert_eq!(json["task_max_ms"], 45);
        assert_eq!(json["extract_permit_wait"]["sum_ms"], 15);
        assert_eq!(json["extract_permit_wait"]["max_ms"], 9);
        assert_eq!(json["finalize_permit_wait"]["sum_ms"], 13);
        assert_eq!(json["finalize_permit_wait"]["max_ms"], 8);
    }

    #[test]
    fn slow_package_trace_reports_fetch_task_attribution_rows() {
        let mut slow_packages = SlowPackageTimings::default();

        slow_packages.record_fetch(
            "pkg@1.0.0",
            TaskTimings {
                queue_wait_ms: 1,
                url_lookup_ms: 2,
                download_ms: 3,
                integrity_ms: 4,
                extract_permit_wait_ms: 9,
                extract_ms: 5,
                security_ms: 6,
                source_scan_ns: 6_500_000,
                finalize_permit_wait_ms: 7,
                finalize_ms: 8,
                finalize_tree_integrity_ms: 9,
                finalize_integrity_write_ms: 10,
                finalize_rename_ms: 11,
                finalize_collision_recovery_ms: 12,
                file_count: 13,
                dir_count: 14,
                symlink_count: 15,
                unpacked_bytes: 16,
            },
        );

        let json = slow_packages.to_json();
        let row = &json["fetch_tasks"]["by_total"][0];

        assert_eq!(row["package"], "pkg@1.0.0");
        assert_eq!(row["task_total_ms"], 45);
        assert_eq!(row["queue_wait_ms"], 1);
        assert_eq!(row["url_lookup_ms"], 2);
        assert_eq!(row["download_ms"], 3);
        assert_eq!(row["integrity_ms"], 4);
        assert_eq!(row["extract_permit_wait_ms"], 9);
        assert_eq!(row["extract_ms"], 5);
        assert_eq!(row["security_ms"], 6);
        assert_eq!(row["source_scan_ns"], 6_500_000u64);
        assert_eq!(row["finalize_permit_wait_ms"], 7);
        assert_eq!(row["finalize_ms"], 8);
        assert_eq!(row["finalize_tree_integrity_ms"], 9);
        assert_eq!(row["finalize_integrity_write_ms"], 10);
        assert_eq!(row["finalize_rename_ms"], 11);
        assert_eq!(row["finalize_collision_recovery_ms"], 12);
        assert_eq!(row["file_count"], 13);
        assert_eq!(row["dir_count"], 14);
        assert_eq!(row["symlink_count"], 15);
        assert_eq!(row["unpacked_bytes"], 16);
    }

    #[test]
    fn slow_package_trace_reports_v2_link_task_rows() {
        let mut slow_packages = SlowPackageTimings::default();

        slow_packages.record_link_v2_one(
            "slow@1.0.0",
            23,
            lpm_store::v2::LinkEntryTimings {
                materialize_ms: 11,
                snapshot_ms: 7,
                sidecar_ms: 2,
                collision_recovery_ms: 5,
                ..lpm_store::v2::LinkEntryTimings::default()
            },
        );
        slow_packages.record_link_v2_one(
            "fast@1.0.0",
            3,
            lpm_store::v2::LinkEntryTimings {
                materialize_ms: 1,
                snapshot_ms: 1,
                ..lpm_store::v2::LinkEntryTimings::default()
            },
        );

        let json = slow_packages.to_json();

        assert_eq!(json["link_v2_one"][0]["package"], "slow@1.0.0");
        assert_eq!(json["link_v2_one"][0]["ms"], 23);
        assert_eq!(json["link_v2_one"][0]["materialize_ms"], 11);
        assert_eq!(json["link_v2_one"][0]["snapshot_ms"], 7);
        assert_eq!(json["link_v2_one"][0]["sidecar_ms"], 2);
        assert_eq!(json["link_v2_one"][0]["collision_recovery_ms"], 5);
        assert_eq!(json["link_v2_one"][1]["package"], "fast@1.0.0");
        assert_eq!(json["link_v2_one"][1]["ms"], 3);
    }

    #[test]
    fn metadata_fetch_trace_reports_slow_package_attribution_rows() {
        let record = lpm_registry::timing::MetadataFetchDetailRecord {
            package: "left-pad".to_string(),
            route: "npm_direct",
            total_ms: 21,
            raw_fetch_ms: 18,
            cache_read_ms: 1,
            validator_read_ms: 2,
            http_ms: 12,
            body_read_ms: 3,
            json_decode_ms: 4,
            cache_after_304_ms: 5,
            cache_write_dispatch_ms: 6,
            cache_info_parse_ms: 7,
            policy_release_time_ms: 8,
            policy_release_time_fetch_ms: 10,
            policy_release_time_cache_read_ms: 11,
            policy_release_time_validator_read_ms: 12,
            policy_release_time_http_ms: 13,
            policy_release_time_body_read_ms: 14,
            policy_release_time_json_decode_ms: 15,
            policy_release_time_cache_after_304_ms: 16,
            policy_release_time_cache_write_dispatch_ms: 17,
            policy_release_time_body_bytes: 2048,
            policy_release_time_version_count: 43,
            policy_release_time_cache_hit: true,
            policy_release_time_not_modified: true,
            policy_full_metadata_ms: 9,
            body_bytes: 1024,
            version_count: 42,
            cache_hit: true,
            not_modified: true,
        };
        let snapshot = lpm_registry::timing::MetadataFetchDetailSnapshot {
            calls: 1,
            cache_hit_count: 1,
            not_modified_count: 1,
            body_bytes_sum: 1024,
            version_count_sum: 42,
            route_npm_direct_count: 1,
            attribution: lpm_registry::timing::MetadataFetchAttributionSnapshot {
                total_sum_ms: 21,
                total_max_ms: 21,
                raw_fetch_sum_ms: 18,
                raw_fetch_max_ms: 18,
                cache_read_sum_ms: 1,
                validator_read_sum_ms: 2,
                http_sum_ms: 12,
                body_read_sum_ms: 3,
                json_decode_sum_ms: 4,
                cache_after_304_sum_ms: 5,
                cache_write_dispatch_sum_ms: 6,
                cache_info_parse_sum_ms: 7,
                policy_release_time_sum_ms: 8,
                policy_release_time_fetch_sum_ms: 10,
                policy_release_time_cache_read_sum_ms: 11,
                policy_release_time_validator_read_sum_ms: 12,
                policy_release_time_http_sum_ms: 13,
                policy_release_time_body_read_sum_ms: 14,
                policy_release_time_json_decode_sum_ms: 15,
                policy_release_time_cache_after_304_sum_ms: 16,
                policy_release_time_cache_write_dispatch_sum_ms: 17,
                policy_release_time_body_bytes_sum: 2048,
                policy_release_time_version_count_sum: 43,
                policy_release_time_cache_hit_count: 1,
                policy_release_time_not_modified_count: 1,
                policy_full_metadata_sum_ms: 9,
            },
            top_slow_packages: lpm_registry::timing::MetadataFetchSlowSnapshot {
                by_total: vec![record.clone()],
                by_body_bytes: vec![record.clone()],
                ..lpm_registry::timing::MetadataFetchSlowSnapshot::default()
            },
            top_direct_packuments: lpm_registry::timing::MetadataFetchDirectPackumentSnapshot {
                by_http: vec![record.clone()],
                by_body_bytes: vec![record],
                ..lpm_registry::timing::MetadataFetchDirectPackumentSnapshot::default()
            },
            ..lpm_registry::timing::MetadataFetchDetailSnapshot::default()
        };

        let json = metadata_fetch_detail_json_from_snapshot(&snapshot, TimingDetailMode::Trace);
        let row = &json["top_slow_packages"]["by_total"][0];
        let direct_row = &json["top_direct_packuments"]["by_body_bytes"][0];

        assert_eq!(json["calls"], 1);
        assert_eq!(json["scope"], "per_package_metadata_fetches");
        assert_eq!(json["batch_fetches_included"], false);
        assert_eq!(json["routes"]["npm_direct"], 1);
        assert_eq!(json["attribution"]["http_sum_ms"], 12);
        assert_eq!(
            json["attribution"]["policy_release_time_fetch"]["total_sum_ms"],
            10
        );
        assert_eq!(
            json["attribution"]["policy_release_time_fetch"]["body_bytes_sum"],
            2048
        );
        assert_eq!(
            json["attribution"]["policy_release_time_fetch"]["version_count_sum"],
            43
        );
        assert_eq!(
            json["attribution"]["policy_release_time_fetch"]["cache_hit_count"],
            1
        );
        assert_eq!(row["package"], "left-pad");
        assert_eq!(row["route"], "npm_direct");
        assert_eq!(row["total_ms"], 21);
        assert_eq!(row["raw_fetch_ms"], 18);
        assert_eq!(row["cache_read_ms"], 1);
        assert_eq!(row["validator_read_ms"], 2);
        assert_eq!(row["http_ms"], 12);
        assert_eq!(row["body_read_ms"], 3);
        assert_eq!(row["json_decode_ms"], 4);
        assert_eq!(row["cache_after_304_ms"], 5);
        assert_eq!(row["cache_write_dispatch_ms"], 6);
        assert_eq!(row["cache_info_parse_ms"], 7);
        assert_eq!(row["policy_release_time_ms"], 8);
        assert_eq!(row["policy_release_time_fetch"]["total_ms"], 10);
        assert_eq!(row["policy_release_time_fetch"]["cache_read_ms"], 11);
        assert_eq!(row["policy_release_time_fetch"]["validator_read_ms"], 12);
        assert_eq!(row["policy_release_time_fetch"]["http_ms"], 13);
        assert_eq!(row["policy_release_time_fetch"]["body_read_ms"], 14);
        assert_eq!(row["policy_release_time_fetch"]["json_decode_ms"], 15);
        assert_eq!(row["policy_release_time_fetch"]["cache_after_304_ms"], 16);
        assert_eq!(
            row["policy_release_time_fetch"]["cache_write_dispatch_ms"],
            17
        );
        assert_eq!(row["policy_release_time_fetch"]["body_bytes"], 2048);
        assert_eq!(row["policy_release_time_fetch"]["version_count"], 43);
        assert!(
            row["policy_release_time_fetch"]["cache_hit"]
                .as_bool()
                .unwrap_or(false)
        );
        assert!(
            row["policy_release_time_fetch"]["not_modified"]
                .as_bool()
                .unwrap_or(false)
        );
        assert_eq!(row["policy_full_metadata_ms"], 9);
        assert_eq!(row["body_bytes"], 1024);
        assert_eq!(row["version_count"], 42);
        assert!(row["cache_hit"].as_bool().unwrap_or(false));
        assert!(row["not_modified"].as_bool().unwrap_or(false));
        assert_eq!(
            json["top_slow_packages"]["by_body_bytes"][0]["package"],
            "left-pad"
        );
        assert_eq!(
            json["top_direct_packuments"]["by_http"][0]["package"],
            "left-pad"
        );
        assert_eq!(direct_row["package"], "left-pad");
        assert_eq!(direct_row["body_bytes"], 1024);
    }

    #[test]
    fn resolve_detail_reports_greedy_work_counters() {
        let stage = lpm_resolver::StageTiming {
            work_edge_process_count: 9,
            work_edge_reuse_count: 4,
            work_edge_reuse_range_count: 3,
            work_edge_reuse_exact_count: 1,
            work_node_allocated_count: 5,
            work_child_edge_enqueued_count: 8,
            work_peer_requirement_count: 2,
            work_metadata_edge_miss_count: 7,
            work_metadata_edge_miss_direct_count: 6,
            work_metadata_edge_miss_latest_known_count: 5,
            work_metadata_edge_miss_latest_known_direct_count: 4,
            work_metadata_edge_miss_latest_satisfies_count: 3,
            work_metadata_edge_miss_latest_satisfies_direct_count: 2,
            work_metadata_edge_miss_latest_matches_pick_count: 2,
            work_metadata_edge_miss_latest_matches_pick_direct_count: 1,
            work_metadata_edge_miss_version_doc_policy_eligible_count: 4,
            work_metadata_edge_miss_version_doc_policy_eligible_direct_count: 3,
            work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count: 2,
            work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count: 1,
            work_metadata_edge_miss_exact_count: 1,
            work_metadata_edge_miss_star_count: 2,
            work_metadata_edge_miss_caret_count: 3,
            work_metadata_edge_miss_tilde_count: 4,
            work_metadata_edge_miss_comparator_count: 5,
            work_metadata_edge_miss_complex_count: 6,
            work_metadata_edge_miss_other_count: 7,
            selected_package_count: 6,
            selected_unique_canonical_count: 5,
            selected_duplicate_canonical_count: 1,
            ..lpm_resolver::StageTiming::default()
        };

        let json = resolve_detail_json(10, 1, &stage, &[], TimingDetailMode::Detail);

        assert_eq!(json["work"]["edge_process_count"], 9);
        assert_eq!(json["work"]["edge_reuse_count"], 4);
        assert_eq!(json["work"]["edge_reuse_range_count"], 3);
        assert_eq!(json["work"]["edge_reuse_exact_count"], 1);
        assert_eq!(json["work"]["edge_non_reuse_count"], 5);
        assert_eq!(json["work"]["node_allocated_count"], 5);
        assert_eq!(json["work"]["child_edge_enqueued_count"], 8);
        assert_eq!(json["work"]["peer_requirement_count"], 2);
        assert_eq!(json["work"]["metadata_edge_miss_count"], 7);
        assert_eq!(json["work"]["metadata_edge_miss_direct_count"], 6);
        assert_eq!(json["work"]["metadata_edge_miss_latest_known_count"], 5);
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_known_direct_count"],
            4
        );
        assert_eq!(json["work"]["metadata_edge_miss_latest_satisfies_count"], 3);
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_satisfies_direct_count"],
            2
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_matches_pick_count"],
            2
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_matches_pick_direct_count"],
            1
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_version_doc_policy_eligible_count"],
            4
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_version_doc_policy_eligible_direct_count"],
            3
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count"],
            2
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count"],
            1
        );
        assert_eq!(json["work"]["metadata_edge_miss_range_shapes"]["exact"], 1);
        assert_eq!(json["work"]["metadata_edge_miss_range_shapes"]["star"], 2);
        assert_eq!(json["work"]["metadata_edge_miss_range_shapes"]["caret"], 3);
        assert_eq!(json["work"]["metadata_edge_miss_range_shapes"]["tilde"], 4);
        assert_eq!(
            json["work"]["metadata_edge_miss_range_shapes"]["comparator"],
            5
        );
        assert_eq!(
            json["work"]["metadata_edge_miss_range_shapes"]["complex"],
            6
        );
        assert_eq!(json["work"]["metadata_edge_miss_range_shapes"]["other"], 7);
        assert_eq!(json["work"]["selected_package_count"], 6);
        assert_eq!(json["work"]["selected_unique_canonical_count"], 5);
        assert_eq!(json["work"]["selected_duplicate_canonical_count"], 1);
    }

    #[test]
    fn v2_link_task_timings_reports_reused_entries() {
        let mut timings = V2LinkTaskTimings::default();
        timings.record(5, false);
        timings.record(8, true);

        let json = timings.to_json(3);

        assert_eq!(json["task_count"], 2);
        assert_eq!(json["freshly_populated_count"], 1);
        assert_eq!(json["reused_entry_count"], 1);
        assert_eq!(json["task_sum_ms"], 13);
        assert_eq!(json["task_max_ms"], 8);
        assert_eq!(json["await_ms"], 3);
    }

    #[test]
    fn speculative_stats_json_reports_usefulness_counters() {
        let stats = SpeculativeStats {
            completed_before_fetch: 3,
            consumed_by_fetch: 2,
            duplicated_with_fetch: 1,
            failed: 4,
            wasted: 5,
            ..SpeculativeStats::default()
        };

        let json = stats.to_json();

        assert_eq!(json["completed_before_fetch"], 3);
        assert_eq!(json["consumed_by_fetch"], 2);
        assert_eq!(json["duplicated_with_fetch"], 1);
        assert_eq!(json["failed"], 4);
        assert_eq!(json["wasted"], 5);
    }

    #[test]
    fn fetch_overlap_stats_json_reports_buffer_wait_before_dispatch() {
        let mut stats = FetchOverlapStats::default();
        stats.record_buffered_event();
        stats.record_buffered_event();
        stats.record_buffered_dispatch(7);
        stats.skipped_optional_count = 3;
        stats.skipped_engine_count = 2;

        let json = stats.to_json();

        assert_eq!(json["buffered_count"], 2);
        assert_eq!(json["buffered_dispatch_count"], 1);
        assert_eq!(json["buffered_undispatched_count"], 1);
        assert_eq!(json["buffer_wait"]["sum_ms"], 7);
        assert_eq!(json["buffer_wait"]["max_ms"], 7);
        assert_eq!(json["skipped_optional_count"], 3);
        assert_eq!(json["skipped_engine_count"], 2);
    }

    #[test]
    fn speculative_key_tracker_counts_consumed_duplicates_and_wasted_completed_downloads() {
        let tracker = SpeculativeKeyTracker::default();
        tracker.record_completed("used".to_string());
        tracker.record_completed("wasted".to_string());
        tracker.record_failed("failed".to_string());

        tracker.mark_consumed_if_completed("used");
        tracker.mark_duplicated_if_failed("failed");
        let final_keys = HashSet::from(["used".to_string(), "failed".to_string()]);

        assert_eq!(tracker.completed_count(), 2);
        assert_eq!(tracker.consumed_count(), 1);
        assert_eq!(tracker.duplicated_count(), 1);
        assert_eq!(tracker.failed_count(), 1);
        assert_eq!(tracker.wasted_count(&final_keys), 1);
    }
}
