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
    /// Time in `extract_tarball_from_file` (gzip decompress, tar walk,
    /// and write-to-staging). Mirrors [`lpm_store::StageTimings::extract_ms`].
    pub(super) extract_ms: u128,
    /// Time in the behavioral security scan + `.lpm-security.json` cache
    /// write. The second-filesystem-pass cost that targets.
    /// Mirrors [`lpm_store::StageTimings::security_ms`].
    pub(super) security_ms: u128,
    /// Time in `.integrity` write + atomic rename into the store path.
    /// Mirrors [`lpm_store::StageTimings::finalize_ms`].
    pub(super) finalize_ms: u128,
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
    pub(super) extract_sum_ms: u128,
    pub(super) extract_max_ms: u128,
    pub(super) security_sum_ms: u128,
    pub(super) security_max_ms: u128,
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
        })
    }
}

/// Cap on transitive-speculation depth. Prevents
/// unbounded fan-out on pathological trees (e.g. circular deps, or
/// very deep single-chains). Matches the worker's own deep-walk cap so
/// speculation doesn't ask for manifests the worker won't send.
pub(super) const SPECULATION_MAX_DEPTH: u32 = 5;
pub(super) const DEFAULT_FUSION_NPM_FANOUT: usize = lpm_resolver::DEFAULT_NPM_FANOUT;
pub(super) const DEFAULT_FUSION_SPECULATION_PERMITS: usize = DEFAULT_MAX_CONCURRENT_DOWNLOADS;
pub(super) const ENV_FUSION_SPECULATION_PERMITS: &str = "LPM_FUSION_SPECULATION_PERMITS";
pub(super) const ENV_VERIFY_REGISTRY_SIGNATURES: &str = "LPM_VERIFY_REGISTRY_SIGNATURES";

pub(super) fn default_fusion_npm_fanout_for_policy(_minimum_release_age_secs: u64) -> usize {
    DEFAULT_FUSION_NPM_FANOUT
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
        self.queue_wait_sum_ms += t.queue_wait_ms;
        self.queue_wait_max_ms = self.queue_wait_max_ms.max(t.queue_wait_ms);
        self.url_lookup_sum_ms += t.url_lookup_ms;
        self.url_lookup_max_ms = self.url_lookup_max_ms.max(t.url_lookup_ms);
        self.download_sum_ms += t.download_ms;
        self.download_max_ms = self.download_max_ms.max(t.download_ms);
        self.integrity_sum_ms += t.integrity_ms;
        self.integrity_max_ms = self.integrity_max_ms.max(t.integrity_ms);
        self.extract_sum_ms += t.extract_ms;
        self.extract_max_ms = self.extract_max_ms.max(t.extract_ms);
        self.security_sum_ms += t.security_ms;
        self.security_max_ms = self.security_max_ms.max(t.security_ms);
        self.finalize_sum_ms += t.finalize_ms;
        self.finalize_max_ms = self.finalize_max_ms.max(t.finalize_ms);
    }

    /// Serialize as a JSON object for `lpm install --json` output.
    pub(super) fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "task_count": self.task_count,
            "queue_wait":  { "sum_ms": self.queue_wait_sum_ms,  "max_ms": self.queue_wait_max_ms  },
            "url_lookup":  { "sum_ms": self.url_lookup_sum_ms,  "max_ms": self.url_lookup_max_ms  },
            "download":    { "sum_ms": self.download_sum_ms,    "max_ms": self.download_max_ms    },
            "integrity":   { "sum_ms": self.integrity_sum_ms,   "max_ms": self.integrity_max_ms   },
            "extract":     { "sum_ms": self.extract_sum_ms,     "max_ms": self.extract_max_ms     },
            "security":    { "sum_ms": self.security_sum_ms,    "max_ms": self.security_max_ms    },
            "finalize":    { "sum_ms": self.finalize_sum_ms,    "max_ms": self.finalize_max_ms    },
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
}

#[derive(Debug, Clone)]
struct PackageTiming {
    package: String,
    ms: u128,
}

impl SlowPackageTimings {
    pub(super) fn record_fetch(&mut self, package: &str, timings: TaskTimings) {
        Self::record(&mut self.tarball_http, package, timings.download_ms);
        Self::record(&mut self.extract, package, timings.extract_ms);
        Self::record(&mut self.security, package, timings.security_ms);
        Self::record(&mut self.finalize, package, timings.finalize_ms);
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

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tarball_http": Self::bucket_json(&self.tarball_http),
            "extract": Self::bucket_json(&self.extract),
            "security": Self::bucket_json(&self.security),
            "finalize": Self::bucket_json(&self.finalize),
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
}

pub(super) fn setup_only_timing_detail_json(
    mode: TimingDetailMode,
    setup_total_ms: u128,
    install_state_ms: u128,
    route_table_ms: u128,
) -> serde_json::Value {
    let mut detail = serde_json::json!({
        "setup": {
            "install_state_ms": install_state_ms,
            "route_table_ms": route_table_ms,
            "other_ms": setup_total_ms.saturating_sub(
                install_state_ms.saturating_add(route_table_ms),
            ),
        },
        "metadata": metadata_detail_json(),
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

pub(super) fn metadata_detail_json() -> serde_json::Value {
    serde_json::Value::Array(
        lpm_registry::timing::snapshot_metadata_detail()
            .into_iter()
            .map(|snapshot| {
                serde_json::json!({
                    "purpose": snapshot.purpose,
                    "rpc_ms": snapshot.rpc.as_millis(),
                    "rpc_count": snapshot.rpc_count,
                    "cache_hit_count": snapshot.cache_hit_count,
                    "cache_miss_count": snapshot.cache_miss_count,
                    "request_count": snapshot.request_count,
                    "unique_package_count": snapshot.unique_package_count,
                    "duplicate_request_count": snapshot.duplicate_request_count,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fusion_npm_fanout_for_policy_keeps_abbreviated_fast_path_wide() {
        assert_eq!(
            default_fusion_npm_fanout_for_policy(0),
            DEFAULT_FUSION_NPM_FANOUT
        );
    }

    #[test]
    fn default_fusion_npm_fanout_for_policy_keeps_release_age_fast_path_wide() {
        assert_eq!(
            default_fusion_npm_fanout_for_policy(86_400),
            DEFAULT_FUSION_NPM_FANOUT
        );
    }
}
