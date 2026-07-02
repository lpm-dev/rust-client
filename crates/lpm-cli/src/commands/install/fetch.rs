use super::*;

pub(super) type FetchLock = Arc<AsyncMutex<()>>;
pub(super) type FetchExtractLimiter = Option<Arc<tokio::sync::Semaphore>>;

const ENV_FETCH_EXTRACT_PERMITS: &str = "LPM_FETCH_EXTRACT_PERMITS";
const ENV_EXPERIMENTAL_INSTALLER_SPIKE: &str = "LPM_EXPERIMENTAL_INSTALLER_SPIKE";
const DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS: usize = 10;

#[derive(Clone, Copy)]
pub(super) enum TarballNotFoundRecovery {
    DeleteProjectLockfiles,
    PreserveProjectLockfiles,
}

#[derive(Default)]
pub(super) struct FetchCoordinator {
    pub(super) locks: AsyncMutex<HashMap<String, FetchLock>>,
}

impl FetchCoordinator {
    pub(super) async fn lock_for(&self, key: String) -> FetchLock {
        let mut map = self.locks.lock().await;
        map.entry(key)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}

/// Default concurrent-tarball-download pool size. Overridable per-invocation
/// via `LPM_CONCURRENT_DOWNLOADS=N` for future network-condition A/B.
///
/// Default bumped 16 → 24 on after the concurrency
/// A/B matrix (/ × 16/24/32 permits, 11-run medians each). Key finding:
/// root-only speculation + 16 permits forced transitive downloads to
/// queue behind the speculation drain. 24 permits keeps the tail
/// parallel without HTTP/1.1 connection thrash. 32 went backwards
/// (CDN-side contention or local socket overhead). See install-source plan
/// doc for the full matrix.
pub(super) const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 24;

/// Read `LPM_CONCURRENT_DOWNLOADS` from the environment. Valid values are
/// integers in `1..=256`. Anything else (unparseable, zero, > 256) falls back
/// to `DEFAULT_MAX_CONCURRENT_DOWNLOADS` AFTER emitting a stderr warning so
/// users notice their override silently didn't apply. Unset → default,
/// silently.
pub(super) fn max_concurrent_downloads() -> usize {
    let Some(raw) = std::env::var("LPM_CONCURRENT_DOWNLOADS").ok() else {
        return DEFAULT_MAX_CONCURRENT_DOWNLOADS;
    };
    match raw.parse::<usize>() {
        Ok(n) if n > 0 && n <= 256 => n,
        _ => {
            crate::output::warn(&format!(
                "LPM_CONCURRENT_DOWNLOADS={raw:?} is not a valid integer in 1..=256 \
                 — falling back to default ({DEFAULT_MAX_CONCURRENT_DOWNLOADS})"
            ));
            DEFAULT_MAX_CONCURRENT_DOWNLOADS
        }
    }
}

fn parse_fetch_extract_permits(value: &str) -> Option<usize> {
    value.trim().parse::<usize>().ok().filter(|&n| n > 0)
}

fn configured_fetch_extract_permits(
    explicit_permits: Option<&str>,
    experimental_installer_spike: Option<&str>,
    v2_store_active: bool,
) -> Option<usize> {
    match explicit_permits {
        Some(value) => parse_fetch_extract_permits(value),
        None if experimental_installer_spike == Some("1") => {
            Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
        }
        None => platform_default_fetch_extract_permits(v2_store_active, cfg!(target_os = "macos")),
    }
}

fn platform_default_fetch_extract_permits(
    v2_store_active: bool,
    target_is_macos: bool,
) -> Option<usize> {
    (target_is_macos && v2_store_active).then_some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
}

pub(super) fn configured_fetch_extract_limiter(v2_store_active: bool) -> FetchExtractLimiter {
    let explicit_permits = std::env::var(ENV_FETCH_EXTRACT_PERMITS).ok();
    let experimental_installer_spike = std::env::var(ENV_EXPERIMENTAL_INSTALLER_SPIKE).ok();
    configured_fetch_extract_permits(
        explicit_permits.as_deref(),
        experimental_installer_spike.as_deref(),
        v2_store_active,
    )
    .map(tokio::sync::Semaphore::new)
    .map(Arc::new)
}

async fn acquire_fetch_extract_permit(
    limiter: &FetchExtractLimiter,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, LpmError> {
    match limiter {
        Some(limiter) => Ok(Some(limiter.clone().acquire_owned().await.map_err(
            |_| LpmError::Registry("fetch extract limiter closed unexpectedly".into()),
        )?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fetch_extract_permits_accepts_only_positive_integers() {
        assert_eq!(parse_fetch_extract_permits("4"), Some(4));
        assert_eq!(parse_fetch_extract_permits(" 2 "), Some(2));
        assert_eq!(parse_fetch_extract_permits("0"), None);
        assert_eq!(parse_fetch_extract_permits(""), None);
        assert_eq!(parse_fetch_extract_permits("nope"), None);
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_when_unset_without_experimental_installer() {
        assert_eq!(configured_fetch_extract_permits(None, None, false), None);
    }

    #[test]
    fn fetch_extract_permits_default_to_bounded_value_for_experimental_installer() {
        assert_eq!(
            configured_fetch_extract_permits(None, Some("1"), false),
            Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
        );
    }

    #[test]
    fn fetch_extract_permits_explicit_value_overrides_experimental_default() {
        assert_eq!(
            configured_fetch_extract_permits(Some("8"), Some("1"), true),
            Some(8)
        );
    }

    #[test]
    fn fetch_extract_permits_invalid_explicit_value_keeps_existing_unbounded_escape_hatch() {
        assert_eq!(
            configured_fetch_extract_permits(Some("0"), Some("1"), true),
            None
        );
    }

    #[test]
    fn fetch_extract_permits_default_to_bounded_value_for_macos_v2_installs() {
        assert_eq!(
            platform_default_fetch_extract_permits(true, true),
            Some(DEFAULT_BOUNDED_FETCH_EXTRACT_PERMITS)
        );
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_for_macos_v1_installs() {
        assert_eq!(platform_default_fetch_extract_permits(false, true), None);
    }

    #[test]
    fn fetch_extract_permits_stay_unbounded_for_non_macos_v2_installs() {
        assert_eq!(platform_default_fetch_extract_permits(true, false), None);
    }
}

/// Pick the highest version in a slim speculation packument that
/// satisfies the given npm range string. Returns the concrete
/// `(version, tarball_url, integrity)` tuple so the caller can dispatch
/// a speculative download without waiting for PubGrub.
///
/// This is the lightweight analog of what PubGrub does in the conflict-
/// free case: pick the newest range-satisfying version. Mismatches with
/// PubGrub's final pick (~5% of real-world trees, higher in workspaces
/// with tight peer constraints) produce a wasted tarball in the store
/// — cheap to absorb, GC reclaims later.
///
/// npm dist-tags (e.g. `range = "latest"`) resolve via `dist-tags` first,
/// short-circuiting range parsing. Invalid ranges return `None` and the
/// dispatcher skips the package.
pub(super) fn pick_speculative_version(
    meta: &SpeculativePackageMetadata,
    range_str: &str,
) -> Option<(String, String, Option<String>)> {
    // dist-tag path (e.g. "latest", "next", "beta")
    if let Some(pinned) = meta.dist_tags.get(range_str)
        && let Some(dist) = meta.info.dist.get(pinned)
        && let Some(url) = dist.tarball_url.as_deref()
    {
        return Some((pinned.clone(), url.to_string(), dist.integrity.clone()));
    }

    let range = lpm_resolver::NpmRange::parse(range_str).ok()?;
    let version = meta
        .info
        .versions
        .iter()
        .find(|version| range.satisfies(version))?;
    let v_str = version.to_string();
    let dist = meta.info.dist.get(&v_str)?;
    let url = dist.tarball_url.clone()?;
    let integrity = dist.integrity.clone();
    Some((v_str, url, integrity))
}

pub(super) fn push_regular_speculative_dependencies(
    meta: &SpeculativePackageMetadata,
    version: &str,
    next_depth: u32,
    work_queue: &mut Vec<(String, String, u32, bool)>,
) {
    let Some(deps) = meta.info.deps.get(version) else {
        return;
    };
    let optional = meta.info.optional_dep_names.get(version);
    let aliases = meta.info.aliases.get(version);
    for (dep_name, dep_range) in deps {
        if optional.is_some_and(|names| names.contains(dep_name)) {
            continue;
        }
        let target_name = aliases
            .and_then(|map| map.get(dep_name))
            .map_or(dep_name.as_str(), String::as_str);
        work_queue.push((
            target_name.to_string(),
            dep_range.clone(),
            next_depth,
            false,
        ));
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum SpeculativeFetchOutcome {
    Stored,
    AlreadyPresent,
    SkippedNoPermit,
}

pub(super) fn registry_install_pkg_key(
    name: &str,
    version: &str,
    route_table: &RouteTable,
) -> String {
    let registry_url = registry_source_url_for(name, route_table);
    let source = format!("registry+{registry_url}");
    let mut key = String::with_capacity(name.len() + 1 + version.len() + 1 + source.len());
    key.push_str(name);
    key.push('\x00');
    key.push_str(version);
    key.push('\x00');
    key.push_str(&source);
    key
}

/// /: stream metadata AND dispatch speculative
/// downloads in parallel with NDJSON arrival. Returns the same complete
/// metadata `HashMap` that `batch_metadata_deep` would — callers are
/// semantically identical to the non-speculative path.
///
/// Dispatched downloads write directly into the real package store, so
/// the post-resolve real-fetch loop sees them as plain
/// `store.has_package()` hits. Mismatches (resolver picks a different
/// version than our naive range-match) cost one wasted tarball each;
/// the wrong version sits in the store until GC reclaims it.
///
/// transitive speculation. Roots seed a
/// work queue; as each package's manifest arrives, its chosen version's
/// dependencies are expanded onto the queue (capped at
/// [`SPECULATION_MAX_DEPTH`]). Conflict-free trees (95%+ of real-world
/// shape per npm data) see every downloaded package match what PubGrub
/// ultimately picks. Pathological cases that mismatch still converge
/// correctly via the real fetch loop.
/// Bundles the still-live metadata producer, dispatcher `JoinHandle`,
/// and dispatcher's atomic counters so `drain` at the post-fetch point
/// folds speculation stats into the report shape.
///
/// Invariant: all handles are unawaited at construction. Awaiting any
/// before `drain()` consumes the handle and makes the post-fetch drain
/// a no-op.
pub(super) struct SpeculationJoin {
    pub(super) producer: Option<
        tokio::task::JoinHandle<Result<lpm_resolver::WalkerSummary, lpm_resolver::WalkerError>>,
    >,
    pub(super) dispatcher: tokio::task::JoinHandle<()>,
    pub(super) dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) completed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) task_ms_sum: Arc<std::sync::atomic::AtomicU64>,
    pub(super) transitive_dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) max_depth_reached: Arc<std::sync::atomic::AtomicU64>,
    pub(super) no_version_match: Arc<std::sync::atomic::AtomicU64>,
    pub(super) unresolved_parked: Arc<std::sync::atomic::AtomicU64>,
    pub(super) failed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_no_permit: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_auth: Arc<std::sync::atomic::AtomicU64>,
}

impl SpeculationJoin {
    /// Await producer + dispatcher tails and fold dispatcher counters
    /// into `stats`. Consumes `self` so the handles can only be
    /// drained once.
    ///
    /// `stats.streaming_batch_ms` is read from the walker's
    /// own self-measured `walker_wall_ms` (captured inside the walker
    /// task from `run()` entry to its return). Using `started_at.elapsed()`
    /// at drain-call time measures "spawn → drain," which includes
    /// any post-walker fetch-overlap tail — not the metadata-producer
    /// window the field is documented as. The walker-owned measurement
    /// is invariant to when the caller chooses to `.await` the handle.
    /// Fusion has no separate walker, so it reports the default summary
    /// while still folding dispatcher counters.
    pub(super) async fn drain(self, stats: &mut SpeculativeStats) -> lpm_resolver::WalkerSummary {
        use std::sync::atomic::Ordering::Relaxed;
        let producer_res = match self.producer {
            Some(producer) => Some(producer.await),
            None => None,
        };
        let _dispatcher_res = self.dispatcher.await;
        stats.dispatched = self.dispatched.load(Relaxed);
        stats.completed = self.completed.load(Relaxed);
        stats.task_ms_sum = self.task_ms_sum.load(Relaxed) as u128;
        stats.transitive_dispatched = self.transitive_dispatched.load(Relaxed);
        stats.max_depth_reached = self.max_depth_reached.load(Relaxed);
        stats.no_version_match = self.no_version_match.load(Relaxed);
        stats.unresolved_parked = self.unresolved_parked.load(Relaxed);
        stats.failed = self.failed.load(Relaxed);
        stats.skipped_no_permit = self.skipped_no_permit.load(Relaxed);
        stats.skipped_auth = self.skipped_auth.load(Relaxed);
        let summary = match producer_res {
            Some(Ok(Ok(summary))) => summary,
            Some(Ok(Err(e))) => {
                tracing::warn!("metadata producer finished with error: {e}");
                lpm_resolver::WalkerSummary::default()
            }
            Some(Err(join_err)) => {
                tracing::warn!("metadata producer task join failed: {join_err}");
                lpm_resolver::WalkerSummary::default()
            }
            None => lpm_resolver::WalkerSummary::default(),
        };
        stats.streaming_batch_ms = summary.walker_wall_ms;
        summary
    }
}

/// Bundle of dispatcher atomic counters. split-out: the walker
/// owns roots-ready signalling; the dispatcher owns speculation counters.
pub(super) struct DispatcherCounters {
    pub(super) dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) completed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) task_ms_sum: Arc<std::sync::atomic::AtomicU64>,
    pub(super) transitive_dispatched: Arc<std::sync::atomic::AtomicU64>,
    pub(super) max_depth_reached: Arc<std::sync::atomic::AtomicU64>,
    pub(super) no_version_match: Arc<std::sync::atomic::AtomicU64>,
    pub(super) unresolved_parked: Arc<std::sync::atomic::AtomicU64>,
    pub(super) failed: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_no_permit: Arc<std::sync::atomic::AtomicU64>,
    pub(super) skipped_auth: Arc<std::sync::atomic::AtomicU64>,
}

/// spawn the speculation dispatcher as a standalone task.
/// Consumes `(name, SpeculativePackageMetadata)` frames from `rx` (fed by the
/// walker) and issues tarball prefetches against the work queue + root
/// range set. Extraction is refactor-only vs pre-49
/// `run_deep_batch_with_speculation` — the dispatcher body is
/// unchanged except that the `roots_ready_tx` logic is gone (walker
/// fires roots-ready now; the dispatcher is just a pure consumer).
#[allow(clippy::too_many_arguments)] // design-level: dispatcher takes the full per-install state
pub(super) fn spawn_speculation_dispatcher(
    rx: tokio::sync::mpsc::Receiver<(String, SpeculativePackageMetadata)>,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    store: PackageStore,
    semaphore: Arc<Semaphore>,
    speculation_semaphore: Option<Arc<Semaphore>>,
    coord: Arc<FetchCoordinator>,
    deps: HashMap<String, String>,
    spec_tracker: SpeculativeKeyTracker,
    // — under v2 mode the dispatcher routes downloaded
    // bytes through `v2::Store::extract_object_from_bytes` instead of
    // v1's per-`(name, version)` slot. `None` keeps the legacy v1 path
    // for callers running with the env var unset (and for the migration-
    // window code paths that still write v1 alongside).
    store_v2: Option<Arc<lpm_store::v2::Store>>,
    fetch_extract_limiter: FetchExtractLimiter,
) -> (tokio::task::JoinHandle<()>, DispatcherCounters) {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    let deps_for_spec = deps;
    let client_spec = client;
    let route_table_spec = route_table;
    let store_spec = store;
    let sem_spec = semaphore;
    let speculation_sem_spec = speculation_semaphore;
    let coord_spec = coord;
    let spec_tracker_spec = spec_tracker;
    let store_v2_spec = store_v2;
    let fetch_extract_limiter_spec = fetch_extract_limiter;

    let dispatched = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let task_ms_sum = Arc::new(AtomicU64::new(0));
    let transitive_dispatched = Arc::new(AtomicU64::new(0));
    let max_depth_reached = Arc::new(AtomicU64::new(0));
    let no_version_match = Arc::new(AtomicU64::new(0));
    let unresolved_parked = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let skipped_no_permit = Arc::new(AtomicU64::new(0));
    let skipped_auth = Arc::new(AtomicU64::new(0));

    let dispatched_c = dispatched.clone();
    let completed_c = completed.clone();
    let task_ms_c = task_ms_sum.clone();
    let transitive_c = transitive_dispatched.clone();
    let max_depth_c = max_depth_reached.clone();
    let no_match_c = no_version_match.clone();
    let parked_c = unresolved_parked.clone();
    let failed_c = failed.clone();
    let skipped_no_permit_c = skipped_no_permit.clone();
    let skipped_auth_c = skipped_auth.clone();

    let mut rx = rx;
    let handle = tokio::spawn(async move {
        // — under v2 mode the dispatcher writes to
        // v2's `objects/<sri>/` via `extract_object_from_bytes`. The
        // store handle threads through `speculative_download_and_store`
        // below; when `store_v2_spec` is `Some`, the spec download
        // collects bytes (rather than streaming straight to disk) and
        // hands them to the v2 store's idempotent extract. The legacy
        // v1 path runs when `store_v2_spec` is `None`.
        //
        // Pre-this branch drained the channel as a no-op,
        // forcing the real fetch loop to do all download work — v2
        // installs paid full per-package fetch latency on the hot
        // path. With this wired, v2 cold installs match v1's
        // pipelined-fetch shape.

        // Work queue items: (package_name, range_string, depth, is_root).
        // Depth is 1 for roots, N+1 for each transitive hop. Capped at
        // SPECULATION_MAX_DEPTH.
        let mut work_queue: Vec<(String, String, u32, bool)> = Vec::new();
        // Packages whose manifest has arrived.
        let mut metadata: HashMap<String, SpeculativePackageMetadata> = HashMap::new();
        // Ranges waiting on a specific package's manifest to arrive.
        // Keyed by package name; values are (range, depth, is_root).
        let mut parked: HashMap<String, Vec<(String, u32, bool)>> = HashMap::new();
        // "name@version" that have already been dispatched; dedups
        // re-asks for the same pinned version from multiple parents.
        let mut already_dispatched: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut spec_tasks = Vec::new();

        // Seed roots.
        for (name, range) in &deps_for_spec {
            work_queue.push((name.clone(), range.clone(), 1, true));
        }

        // Process-one-item helper. Inlined so it can mutate the
        // dispatcher-local state without awkward borrow splits.
        let process_item =
            |name: String,
             range: String,
             depth: u32,
             is_root: bool,
             metadata: &HashMap<String, SpeculativePackageMetadata>,
             parked: &mut HashMap<String, Vec<(String, u32, bool)>>,
             already_dispatched: &mut std::collections::HashSet<String>,
             work_queue: &mut Vec<(String, String, u32, bool)>,
             spec_tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
                let Some(meta) = metadata.get(&name) else {
                    parked
                        .entry(name)
                        .or_default()
                        .push((range, depth, is_root));
                    return;
                };

                let Some((version, url, integrity)) = pick_speculative_version(meta, &range) else {
                    // Range didn't match any arrived version — count it so we
                    // can tell "dispatcher worked but range was too tight"
                    // apart from "dispatcher never saw this package".
                    no_match_c.fetch_add(1, Relaxed);
                    return;
                };

                let key = format!("{name}@{version}");
                if !already_dispatched.insert(key) {
                    return;
                }
                let package_key = registry_install_pkg_key(&name, &version, &route_table_spec);

                let skip_auth_bearing_custom_speculation = matches!(
                    route_table_spec.route_for_package(&name),
                    UpstreamRoute::Custom { auth: Some(_), .. }
                );

                let already_present = if let (Some(store_v2), Some(sri)) =
                    (store_v2_spec.as_deref(), integrity.as_deref())
                {
                    store_v2
                        .reusable_object_dir(sri)
                        .is_ok_and(|object_dir| object_dir.is_some())
                } else {
                    store_spec.has_package(&name, &version)
                };
                if already_present {
                    return;
                }

                // Record depth high-water mark + transitive flag.
                let current_max = max_depth_c.load(Relaxed);
                if depth as u64 > current_max {
                    max_depth_c.store(depth as u64, Relaxed);
                }
                dispatched_c.fetch_add(1, Relaxed);
                if !is_root {
                    transitive_c.fetch_add(1, Relaxed);
                }

                // Expand transitive deps onto the work queue (bounded by
                // SPECULATION_MAX_DEPTH). Speculation follows regular deps
                // only; optional deps are left to the authoritative fetch
                // path, matching the previous raw-manifest payload.
                if depth < SPECULATION_MAX_DEPTH {
                    push_regular_speculative_dependencies(meta, &version, depth + 1, work_queue);
                }

                // Skip tarball speculation for auth-bearing custom
                // registries. The real fetch loop already owns
                // correctness and user-facing failures; speculative
                // requests here only duplicate authenticated traffic
                // against private mirrors.
                if skip_auth_bearing_custom_speculation {
                    skipped_auth_c.fetch_add(1, Relaxed);
                    return;
                }

                // Spawn the download.
                let c = client_spec.clone();
                let rt = route_table_spec.clone();
                let s = store_spec.clone();
                let sem = sem_spec.clone();
                let spec_sem = speculation_sem_spec.clone();
                let coord = coord_spec.clone();
                let completed_task = completed_c.clone();
                let task_ms_task = task_ms_c.clone();
                let failed_task = failed_c.clone();
                let skipped_no_permit_task = skipped_no_permit_c.clone();
                let spec_tracker_task = spec_tracker_spec.clone();
                let store_v2_task = store_v2_spec.clone();
                let fetch_extract_limiter_task = fetch_extract_limiter_spec.clone();
                spec_tasks.push(tokio::spawn(async move {
                    let task_start = std::time::Instant::now();
                    match speculative_download_and_store(
                        &c,
                        &rt,
                        &s,
                        store_v2_task.as_deref(),
                        &sem,
                        spec_sem.as_ref(),
                        &coord,
                        &name,
                        &version,
                        &url,
                        integrity.as_deref(),
                        &fetch_extract_limiter_task,
                    )
                    .await
                    {
                        Ok(SpeculativeFetchOutcome::Stored) => {
                            completed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_completed(package_key);
                        }
                        Ok(SpeculativeFetchOutcome::AlreadyPresent) => {
                            completed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_completed(package_key);
                        }
                        Ok(SpeculativeFetchOutcome::SkippedNoPermit) => {
                            skipped_no_permit_task.fetch_add(1, Relaxed);
                        }
                        Err(e) => {
                            failed_task.fetch_add(1, Relaxed);
                            spec_tracker_task.record_failed(package_key);
                            tracing::debug!(
                                "speculative download {name}@{version} failed (real fetch remains authoritative): {e}"
                            );
                        }
                    }
                    task_ms_task.fetch_add(task_start.elapsed().as_millis() as u64, Relaxed);
                }));
            };

        // Main interleave loop: drain the work queue, then wait for the
        // next manifest, unpark any pending ranges that were keyed on
        // it, and repeat.
        loop {
            while let Some((name, range, depth, is_root)) = work_queue.pop() {
                process_item(
                    name,
                    range,
                    depth,
                    is_root,
                    &metadata,
                    &mut parked,
                    &mut already_dispatched,
                    &mut work_queue,
                    &mut spec_tasks,
                );
            }

            match rx.recv().await {
                Some((name, meta)) => {
                    metadata.insert(name.clone(), meta);
                    // the roots-ready signal is owned by
                    // the walker now — the dispatcher is a pure
                    // consumer of `(name, SpeculativePackageMetadata)` frames.
                    if let Some(pending) = parked.remove(&name) {
                        for (range, depth, is_root) in pending {
                            work_queue.push((name.clone(), range, depth, is_root));
                        }
                    }
                }
                None => break, // sender dropped → walker complete
            }
        }

        // Drain any remaining work (possible if a manifest arrived
        // immediately before the sender dropped).
        while let Some((name, range, depth, is_root)) = work_queue.pop() {
            process_item(
                name,
                range,
                depth,
                is_root,
                &metadata,
                &mut parked,
                &mut already_dispatched,
                &mut work_queue,
                &mut spec_tasks,
            );
        }

        // Packages still parked here were expected by some parent but
        // their manifest never arrived in the batch — the worker's
        // deep-walk didn't reach them. Report so we can tune the
        // server-side cap if this becomes common.
        let orphan_count: u64 = parked.values().map(|v| v.len() as u64).sum();
        parked_c.fetch_add(orphan_count, Relaxed);

        // Wait for all dispatched speculations to either complete or
        // drop — ensures store visibility for the real fetch loop's
        // `has_package` check. Losing a race to the real loop is fine:
        // the store's atomic-rename protects against corruption.
        futures::future::join_all(spec_tasks).await;
    });

    // caller owns the tx side of the mpsc channel and the
    // walker task; we return the dispatcher's `JoinHandle` +
    // counters. The dispatcher's `rx.recv()` loop exits when the
    // walker drops its `tx` sender — same channel-close termination
    // shape the pre-49 streaming batch path used.
    (
        handle,
        DispatcherCounters {
            dispatched,
            completed,
            task_ms_sum,
            transitive_dispatched,
            max_depth_reached,
            no_version_match,
            unresolved_parked,
            failed,
            skipped_no_permit,
            skipped_auth,
        },
    )
}

///: one speculative download — stream tarball → store,
/// identical to `fetch_and_store_streaming` but without the
/// `InstallPackage`-shaped plumbing or `TaskTimings` accounting. Errors
/// are swallowed by the dispatcher (best-effort speculation); the real
/// fetch loop remains the authority.
#[allow(clippy::too_many_arguments)]
pub(super) async fn speculative_download_and_store(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — when `Some`, route the downloaded bytes through
    // v2's `extract_object_from_bytes` (idempotent on object hits)
    // instead of v1's `stream_and_store_package`. Each spec task
    // gets its own clone of the `Arc<Store>`.
    store_v2: Option<&lpm_store::v2::Store>,
    semaphore: &Arc<Semaphore>,
    speculation_semaphore: Option<&Arc<Semaphore>>,
    coord: &Arc<FetchCoordinator>,
    name: &str,
    version: &str,
    url: &str,
    integrity: Option<&str>,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<SpeculativeFetchOutcome, LpmError> {
    use futures::stream::TryStreamExt;
    use tokio_util::io::{StreamReader, SyncIoBridge};

    // + ( completion) — per-key
    // fetch lock keyed by `(name, version, source_id)`. Speculation
    // only fires for registry-source packages, so we derive the
    // registry URL through the same route table the install
    // pipeline uses (`registry_source_url_for`). That keeps the
    // speculation lock and the real fetch loop's lock for the SAME
    // registry package matching even when `.npmrc` redirects the
    // package to a private mirror. Tarball-URL packages have a
    // different source_id and naturally don't share locks with
    // speculation — that's correct (speculation never targets them).
    let speculation_key = registry_install_pkg_key(name, version, route_table);
    let key_lock = coord.lock_for(speculation_key).await;
    let _key_guard = key_lock.lock().await;

    // — store-hit short-circuit, layout-aware. Under v2
    // mode the SRI determines the object dir; if the SRI is
    // unavailable (TOFU resolution path) we fall back to v1's
    // `(name, version)` check, which is harmless under v2 (it just
    // misses an opportunity to skip).
    let already_present = if let Some(v2) = store_v2 {
        match integrity {
            Some(sri) => v2
                .reusable_object_dir(sri)
                .is_ok_and(|object_dir| object_dir.is_some()),
            None => store.has_package(name, version),
        }
    } else {
        store.has_package(name, version)
    };
    if already_present {
        return Ok(SpeculativeFetchOutcome::AlreadyPresent);
    }

    let _speculation_permit = match speculation_semaphore {
        Some(limiter) => match limiter.try_acquire() {
            Ok(permit) => Some(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Ok(SpeculativeFetchOutcome::SkippedNoPermit);
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(LpmError::Registry(
                    "speculation limiter semaphore closed".into(),
                ));
            }
        },
        None => None,
    };

    // Speculation must never queue ahead of the authoritative fetch loop.
    // If all shared download permits are busy, skip this best-effort
    // prefetch and let the real fetch path own the network slot.
    let permit = match semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return Ok(SpeculativeFetchOutcome::SkippedNoPermit);
        }
        Err(tokio::sync::TryAcquireError::Closed) => {
            return Err(LpmError::Registry("spec semaphore closed".into()));
        }
    };

    // Keep speculative downloads on the auth-aware route so custom registries
    // use the same credentials and origin checks as authoritative fetches.
    let response = client
        .download_tarball_streaming_routed(route_table, name, url)
        .await?;

    if let Some(v2) = store_v2 {
        // v2 path: collect bytes, extract via v2 store. Streaming-to-
        // disk into v2 is a future optimization; for
        // speculation the in-memory shape is fine because spec sets
        // are bounded (a few hundred packages parallel, each typically
        // <500 KB compressed). The semaphore upstream caps the
        // concurrent allocator pressure.
        let body = response.bytes().await.map_err(|e| {
            LpmError::Registry(format!("spec body fetch failed for {name}@{version}: {e}"))
        })?;
        drop(permit);
        let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
        let v2_clone = v2.clone();
        let bytes = body.to_vec();
        let integrity_c = integrity.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            v2_clone
                .extract_object_from_bytes(&bytes, integrity_c.as_deref())
                .map(|_| ())
        })
        .await
        .map_err(|e| LpmError::Registry(format!("spec v2 blocking task: {e}")))??;
        return Ok(SpeculativeFetchOutcome::Stored);
    }

    // v1 path: streaming straight to the per-`(name, version)` slot.
    let byte_stream = response.bytes_stream().map_err(std::io::Error::other);
    let async_reader = StreamReader::new(byte_stream);
    let name_c = name.to_string();
    let version_c = version.to_string();
    let integrity_c = integrity.map(|s| s.to_string());
    let store_owned = store.clone();

    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    tokio::task::spawn_blocking(move || {
        let sync_reader = SyncIoBridge::new(async_reader);
        store_owned
            .stream_and_store_package(
                &name_c,
                &version_c,
                sync_reader,
                integrity_c.as_deref(),
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
            )
            .map(|_| ())
    })
    .await
    .map_err(|e| LpmError::Registry(format!("spec blocking task: {e}")))??;
    Ok(SpeculativeFetchOutcome::Stored)
}

pub(super) struct ResolvedRegistryTarballUrl {
    pub(super) url: String,
}

fn tarball_file_prefix(name: &str) -> Option<&str> {
    name.rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

fn npm_compatible_canonical_tarball_url(
    registry_base_url: &str,
    name: &str,
    version: &str,
) -> Option<String> {
    let file_prefix = tarball_file_prefix(name)?;
    let registry_base_url = registry_base_url.trim_end_matches('/');
    let mut url = String::with_capacity(
        registry_base_url.len() + 1 + name.len() + 3 + file_prefix.len() + 1 + version.len() + 4,
    );
    url.push_str(registry_base_url);
    url.push('/');
    url.push_str(name);
    url.push_str("/-/");
    url.push_str(file_prefix);
    url.push('-');
    url.push_str(version);
    url.push_str(".tgz");
    Some(url)
}

fn lpm_canonical_tarball_url(base_url: &str, name: &str, version: &str) -> Option<String> {
    let package = lpm_common::PackageName::parse(name).ok()?;
    let base_url = base_url.trim_end_matches('/');
    let api_prefix = "/api/registry/";
    let lpm_scope = "@lpm.dev/";
    let mut url = String::with_capacity(
        base_url.len()
            + api_prefix.len()
            + lpm_scope.len()
            + package.owner.len()
            + 1
            + package.name.len()
            + 3
            + package.name.len()
            + 1
            + version.len()
            + 4,
    );
    url.push_str(base_url);
    url.push_str(api_prefix);
    url.push_str(lpm_scope);
    url.push_str(&package.owner);
    url.push('.');
    url.push_str(&package.name);
    url.push_str("/-/");
    url.push_str(&package.name);
    url.push('-');
    url.push_str(version);
    url.push_str(".tgz");
    Some(url)
}

pub(super) fn canonical_cached_registry_tarball_url(
    client: &RegistryClient,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
) -> Option<String> {
    if is_lpm {
        return lpm_canonical_tarball_url(client.base_url(), name, version);
    }

    match route_table.route_for_package(name) {
        UpstreamRoute::Custom { target, .. } => {
            npm_compatible_canonical_tarball_url(&target.base_url, name, version)
        }
        UpstreamRoute::NpmDirect | UpstreamRoute::LpmWorker => {
            npm_compatible_canonical_tarball_url(client.npm_registry_url(), name, version)
        }
    }
}

pub(super) async fn metadata_tarball_url_for_package(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
) -> Result<(String, lpm_registry::PackageMetadata), LpmError> {
    let metadata = if is_lpm {
        let pkg =
            lpm_common::PackageName::parse(name).map_err(|e| LpmError::Registry(e.to_string()))?;
        client.get_package_metadata(&pkg).await?
    } else {
        let route = route_table.route_for_package(name);
        client.get_npm_metadata_routed(name, route).await?
    };
    let ver_meta = metadata
        .version(version)
        .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
    let url = ver_meta
        .tarball_url()
        .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
        .to_string();
    Ok((url, metadata))
}

/// Resolve the tarball URL for a registry package. Lockfile-provided
/// registry tarball hints are cache hints: use the route's canonical tarball
/// URL without a metadata round trip when it matches, otherwise bind the hint
/// back to the package version's current registry metadata.
///
/// Non-LPM metadata lookups route through `route_table`, so custom registry
/// hints are validated against the same registry that resolved them.
pub(super) async fn resolve_tarball_url(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
    is_lpm: bool,
    cached_url: Option<&str>,
    metadata_checked_for_tarball: bool,
) -> Result<ResolvedRegistryTarballUrl, LpmError> {
    if let Some(url) = cached_url {
        if metadata_checked_for_tarball {
            return Ok(ResolvedRegistryTarballUrl {
                url: url.to_string(),
            });
        }
        if canonical_cached_registry_tarball_url(client, route_table, name, version, is_lpm)
            .as_deref()
            == Some(url)
        {
            return Ok(ResolvedRegistryTarballUrl {
                url: url.to_string(),
            });
        }
        let (metadata_url, _metadata) = lpm_registry::timing::with_metadata_purpose(
            lpm_registry::timing::MetadataPurpose::TarballUrlLookup,
            metadata_tarball_url_for_package(client, route_table, name, version, is_lpm),
        )
        .await?;
        if url != metadata_url {
            return Err(LpmError::Registry(format!(
                "registry lockfile tarball for {name}@{version} does not match registry metadata \
                 dist.tarball; refusing lockfile hint"
            )));
        }
        return Ok(ResolvedRegistryTarballUrl {
            url: url.to_string(),
        });
    }
    if metadata_checked_for_tarball {
        return Err(LpmError::NotFound(format!(
            "no tarball URL for {name}@{version}"
        )));
    }
    let (url, _metadata) = lpm_registry::timing::with_metadata_purpose(
        lpm_registry::timing::MetadataPurpose::TarballUrlLookup,
        metadata_tarball_url_for_package(client, route_table, name, version, is_lpm),
    )
    .await?;
    Ok(ResolvedRegistryTarballUrl { url })
}

/// Invalidate metadata cache for a package, routing through the
/// custom-registry-aware path when the package is served from a
/// `.npmrc`-declared registry. added
/// [`RegistryClient::invalidate_custom_metadata_cache`]; this helper
/// is the install-path consumer that the route-table invariant requires
/// was missing.
pub(super) fn invalidate_metadata_routed(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    name: &str,
    version: &str,
) {
    match route_table.route_for_package(name) {
        UpstreamRoute::Custom { target, auth } => {
            client.invalidate_custom_metadata_cache(&target.base_url, name, auth.as_ref());
        }
        _ => {
            client.invalidate_metadata_cache(name);
            client.invalidate_npm_version_metadata_cache(name, version);
        }
    }
}

/// Shared 404-handling: invalidate stale metadata and return the user-facing
/// error message the caller should surface. Authoritative fetches also remove
/// lockfiles so the next `lpm install` re-resolves; best-effort overlap fetches
/// preserve project state.
///
/// `project_dir` is the project root, not necessarily the current process CWD.
pub(super) fn handle_tarball_not_found_with_recovery(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    project_dir: &Path,
    recovery: TarballNotFoundRecovery,
) -> LpmError {
    client.invalidate_metadata_cache(name);
    client.invalidate_npm_version_metadata_cache(name, version);
    if matches!(recovery, TarballNotFoundRecovery::DeleteProjectLockfiles) {
        let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
        if lock_path.exists() {
            let _ = std::fs::remove_file(&lock_path);
        }
        let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
        if lockb_path.exists() {
            let _ = std::fs::remove_file(&lockb_path);
        }
    }
    LpmError::NotFound(format!(
        "{name}@{version} tarball not found (possibly unpublished). \
         Cache cleared — run `lpm install` again to re-resolve."
    ))
}

/// Legacy fetch path — download to temp file, reopen, extract. Returns
/// `(computed_sri, TaskTimings)`. Called from the per-task closure under
/// a held download semaphore permit. Kept as the default while the
/// streaming path is validated.
///
/// `project_dir` + `gate_stats` are threaded in
/// for the CWD-safe `handle_tarball_not_found` (which deletes
/// lockfiles relative to the project root, not CWD) and the
/// stale-URL same-run retry telemetry. See the design doc §
/// Change 2 for the full retry semantics.
// See the docs on `fetch_and_store_streaming` for why the permit drop
// happens between download and extract. Same shape applies on the legacy
// spool path.
#[allow(clippy::too_many_arguments)] // design-level: install-fetch orchestration takes the full surface
pub(super) async fn fetch_and_store_legacy(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — see [`fetch_and_store_streaming`] for the
    // contract. None → v1 (default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    not_found_recovery: TarballNotFoundRecovery,
    gate_stats: &Arc<GateStats>,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    use std::sync::atomic::Ordering;

    // — explicit URL resolution + download so we can
    // distinguish a metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cached URL, try
    // recovery). Return tuple's final `String` is the URL that
    // served bytes (equal to `initial_url` on the happy path, the
    // retry's `fresh_url` on stale-URL recovery). Driver post-
    // aggregates any divergence from `p.tarball_url` into the
    // writeback `fresh_urls` map.
    let url_lookup_start = std::time::Instant::now();
    let initial_resolution = match resolve_tarball_url(
        client,
        route_table,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
        p.metadata_checked_for_tarball,
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            // Metadata 404 — package/version genuinely gone.
            // Nothing to retry.
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let initial_url = initial_resolution.url.clone();
    let mut final_url = initial_url.clone();

    let download_start = std::time::Instant::now();
    let downloaded = match client
        .download_tarball_routed(route_table, &p.name, &initial_url)
        .await
    {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL went stale — package was republished, or
            // upstream migrated paths. Invalidate metadata + retry
            // ONCE with a freshly-resolved URL.
            invalidate_metadata_routed(client, route_table, &p.name, &p.version);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_resolution = match resolve_tarball_url(
                client,
                route_table,
                &p.name,
                &p.version,
                p.is_lpm,
                None,
                false,
            )
            .await
            {
                Ok(u) => u,
                Err(_) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
            };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            let fresh_url = fresh_resolution.url.clone();
            if fresh_url == initial_url {
                // Loop guard — metadata still points at the same
                // stale URL. Tarball is really gone, not just moved.
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found_with_recovery(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                    not_found_recovery,
                ));
            }
            match client
                .download_tarball_routed(route_table, &p.name, &fresh_url)
                .await
            {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            // On-demand path (no stored URL) 404 — really gone.
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    // — `download_ms` measures just the GET + temp-file
    // write. URL-lookup costs (initial + optional retry) are
    // accumulated into `url_lookup_ms` above.
    let download_ms = download_start.elapsed().as_millis();

    // Drop the permit now that bytes are on disk.
    // Integrity verification + extract that follow are CPU+I/O bound
    // and don't need the download throttle; sibling downloads can
    // proceed while this task finishes its post-download work.
    drop(permit);

    let computed_sri = downloaded.sri.clone();

    // Verify integrity before storing. SHA-512 is the common case: computed
    // during download, so match is a string compare. Non-sha512 expected
    // values stream-verify from the temp file in 64 KB chunks.
    let integrity_start = std::time::Instant::now();
    if let Some(ref integrity) = p.integrity {
        if computed_sri != *integrity
            && let Err(e) = lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
        {
            return Err(LpmError::Registry(format!(
                "integrity verification failed for {}@{}: {e}",
                p.name, p.version
            )));
        }
    } else {
        tracing::warn!(
            "no integrity hash for {}@{} — skipping verification",
            p.name,
            p.version
        );
    }
    let integrity_ms = integrity_start.elapsed().as_millis();

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    let (stage, fresh_object, result_sri) = if let Some(store_v2) = store_v2 {
        // — v2 path. Read the on-disk tarball into
        // memory and route through `extract_object_from_bytes`. The
        // legacy fetch path's whole point is to spool the download
        // to a temp file (vs the streaming path's in-memory body), so
        // we incur the read-to-bytes cost here rather than refactor
        // the streaming abstraction; the perf delta is bounded by
        // tarball size which already passed the size limit upstream.
        let bytes = std::fs::read(downloaded.file.path()).map_err(|e| {
            LpmError::Registry(format!(
                "v2 store: failed to re-read downloaded tarball at {}: {e}",
                downloaded.file.path().display()
            ))
        })?;
        let (object, sri, timings) = store_v2
            .extract_object_from_bytes_with_fresh_integrity(&bytes, p.integrity.as_deref())?;
        (timings, Some(object), sri)
    } else {
        let (_, stage) = store.store_package_from_file_timed(
            &p.name,
            &p.version,
            downloaded.file.path(),
            &computed_sri,
        )?;
        (stage, None, computed_sri)
    };

    Ok((
        result_sri,
        TaskTimings::from_stage(
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            integrity_ms,
            extract_permit_wait_ms,
            stage,
        ),
        final_url,
        fresh_object,
    ))
}

/// fetch + store path for
/// `Source::Tarball` packages.
///
/// Distinct from [`fetch_and_store_legacy`] / [`fetch_and_store_streaming`]
/// in three structural ways:
/// 1. **No URL resolution.** The tarball URL is the dep specifier;
///    it's already in `p.tarball_url`. No registry metadata
///    round-trip, no `route_table` lookup, no `resolve_tarball_url`.
/// 2. **No registry-routed download.** Uses
///    [`RegistryClient::download_tarball_with_integrity`] which
///    fetches an arbitrary URL and verifies an optional pre-declared
///    SRI. Trust-on-first-use when `p.integrity` is `None`; hard
///    error on mismatch when `Some`.
/// 3. **Content-addressable store path.** Extraction lands at
///    [`PackageStore::store_tarball_at_cas_path`] (keyed by the
///    computed SRI), NOT the `(name, version)`-keyed
///    [`PackageStore::package_dir`]. identity: the URL +
///    integrity is the source identity, distinct from any registry
///    package that happens to share the same `name@version`.
///
/// Returns `(computed_sri, task_timings, final_url)` matching the
/// other fetch paths' shape so the install loop can aggregate the
/// three uniformly.
pub(super) async fn fetch_and_store_tarball_url(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    // — see [`fetch_and_store_streaming`] for the
    // contract. None → v1 (default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    // The dispatch site only routes here when source_kind() returned
    // Source::Tarball, so this unwrap is contract-protected. A
    // missing URL at this point is a programmer error in the
    // resolver's InstallPackage construction, not a runtime input
    // bug.
    let url = p.tarball_url.as_deref().ok_or_else(|| {
        LpmError::Registry(format!(
            "install-source internal error: Source::Tarball install package {:?}@{} has no tarball_url",
            p.name, p.version,
        ))
    })?;

    let download_start = std::time::Instant::now();
    let (data, computed_sri) = client
        .download_tarball_with_integrity(url, p.integrity.as_deref())
        .await?;
    let download_ms = download_start.elapsed().as_millis();
    drop(permit);

    // download_tarball_with_integrity already verified the SRI when
    // p.integrity was Some; on trust-on-first-use it returned the
    // computed SRI we need to record. integrity_ms folds into
    // download_ms because the verify is a single string compare.
    let integrity_ms = 0;

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    let (stage, fresh_object, result_sri) = if let Some(store_v2) = store_v2 {
        // — v2 path. The Source::Tarball case
        // already has bytes + SRI in hand; route them straight into
        // `extract_object_from_bytes`. The downloader returns the
        // declaration's algorithm when one was supplied, while v2
        // objects are keyed by the extractor's canonical sha512 SRI.
        let (object, sri, stage) =
            store_v2.extract_object_from_bytes_with_fresh_integrity(&data, Some(&computed_sri))?;
        (stage, Some(object), sri)
    } else {
        let extract_start = std::time::Instant::now();
        let _store_path = store.store_tarball_at_cas_path(&computed_sri, &data)?;
        (
            lpm_store::StageTimings {
                extract_ms: extract_start.elapsed().as_millis(),
                ..Default::default()
            },
            None,
            computed_sri,
        )
    };

    let timings = TaskTimings::from_stage(
        queue_wait_ms,
        0, // No registry metadata round-trip.
        download_ms,
        integrity_ms,
        extract_permit_wait_ms,
        stage,
    );

    Ok((result_sri, timings, url.to_string(), fresh_object))
}

/// streaming fetch path — bytes flow from reqwest directly
/// into the store's extractor via `StreamReader` + `SyncIoBridge`. No
/// temp file spool, no re-read. Hash computed inline as bytes flow.
///
/// Because download + decode + extract + hash happen in one interleaved
/// pipeline, `download_ms` and `integrity_ms` collapse into
/// `extract_ms` — the breakdown stays shape-compatible with the legacy
/// path but pushes mass into one bucket. That's the whole point of:
/// eliminate the temp-file hop that today forces sequential download →
/// reopen → extract.
#[allow(clippy::too_many_arguments)] // design-level: install-fetch orchestration takes the full surface
pub(super) async fn fetch_and_store_streaming(
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    store: &PackageStore,
    // — when `Some`, the install pipeline is running
    // under `LPM_STORE_VERSION=v2`. Bytes flow into the v2
    // `objects/<sri>/` path instead of v1's `<name>@<version>/`. None
    // → v1 path (today's default + every release).
    store_v2: Option<&lpm_store::v2::Store>,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    not_found_recovery: TarballNotFoundRecovery,
    gate_stats: &Arc<GateStats>,
    permit: tokio::sync::OwnedSemaphorePermit,
    fetch_extract_limiter: &FetchExtractLimiter,
) -> Result<
    (
        String,
        TaskTimings,
        String,
        Option<lpm_store::v2::ExtractedObject>,
    ),
    LpmError,
> {
    use std::sync::atomic::Ordering;

    // URL resolution — times this into `url_lookup_ms` and
    // distinguishes metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cache, try recovery).
    let url_lookup_start = std::time::Instant::now();
    let initial_resolution = match resolve_tarball_url(
        client,
        route_table,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
        p.metadata_checked_for_tarball,
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let initial_url = initial_resolution.url.clone();
    let mut final_url = initial_url.clone();

    let response = match client
        .download_tarball_streaming_routed(route_table, &p.name, &initial_url)
        .await
    {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL stale — retry ONCE with fresh metadata.
            // See `fetch_and_store_legacy` for the full semantics;
            // this branch mirrors that retry logic byte-for-byte
            // (minus the streaming-specific response handling).
            invalidate_metadata_routed(client, route_table, &p.name, &p.version);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_resolution = match resolve_tarball_url(
                client,
                route_table,
                &p.name,
                &p.version,
                p.is_lpm,
                None,
                false,
            )
            .await
            {
                Ok(u) => u,
                Err(_) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
            };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            let fresh_url = fresh_resolution.url.clone();
            if fresh_url == initial_url {
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found_with_recovery(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                    not_found_recovery,
                ));
            }
            match client
                .download_tarball_streaming_routed(route_table, &p.name, &fresh_url)
                .await
            {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found_with_recovery(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                        not_found_recovery,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found_with_recovery(
                client,
                &p.name,
                &p.version,
                project_dir,
                not_found_recovery,
            ));
        }
        Err(e) => return Err(e),
    };

    // Collect the entire compressed tarball into memory
    // BEFORE releasing the download permit, then release the permit
    // BEFORE the spawn_blocking extract. When the permit covers
    // download + extract end-to-end, long extract tails serialize
    // sibling download permit hand-off. Releasing it here lets the next
    // download start as soon as bytes are on the heap; extract no
    // longer holds a download slot and can be coordinated separately.
    //
    // Bounded memory: `download_tarball_streaming` already enforces
    // `MAX_COMPRESSED_TARBALL_SIZE` (500 MB) via `Content-Length`, and
    // `Bytes::clone` is a refcount bump so the move into spawn_blocking
    // doesn't realloc. Average tarball on fixture-large is ~50-500 KB;
    // 24-permit peak is ~12 MB resident.
    let download_start = std::time::Instant::now();
    let body = response
        .bytes()
        .await
        .map_err(|e| LpmError::Network(format!("tarball stream failed: {e}")))?;
    let download_ms = download_start.elapsed().as_millis();
    drop(permit); // release for sibling downloads before extract starts.

    let name = p.name.clone();
    let version = p.version.clone();
    let expected_integrity = p.integrity.clone();
    let store_owned = store.clone();
    // — capture the Optional v2 handle into the
    // blocking task. Cloning an `Option<Store>` is cheap (the inner
    // `Store` derives Clone over a single PathBuf), and `None` keeps
    // the existing v1 path byte-for-byte.
    let store_v2_owned = store_v2.cloned();

    let extract_permit_wait_start = std::time::Instant::now();
    let _extract_permit = acquire_fetch_extract_permit(fetch_extract_limiter).await?;
    let extract_permit_wait_ms = extract_permit_wait_start.elapsed().as_millis();

    // Everything below runs on the blocking pool — frees the tokio async
    // workers to keep driving network reads. No download permit is held.
    let extract_start = std::time::Instant::now();
    let (computed_sri, stage, fresh_object) = tokio::task::spawn_blocking(
        move || -> Result<
            (
                String,
                lpm_store::StageTimings,
                Option<lpm_store::v2::ExtractedObject>,
            ),
            LpmError,
        > {
            if let Some(store_v2) = store_v2_owned {
                // — v2 path. Bytes flow through
                // `extract_object_from_bytes`: SHA-512 hash → integrity
                // verify → extract into `objects/<sri>/` → security
                // analysis → atomic rename. SizeLimit is enforced
                // upstream by `download_tarball_streaming`'s
                // Content-Length check (same as the v1 streaming path's
                // `SizeLimitedReader`), so the buffered `body` is
                // already bounded.
                let (object, sri, timings) = store_v2
                    .extract_object_from_bytes_with_fresh_integrity(
                        &body,
                        expected_integrity.as_deref(),
                    )?;
                Ok((sri, timings, Some(object)))
            } else {
                let cursor = std::io::Cursor::new(body);
                store_owned
                    .stream_and_store_package(
                        &name,
                        &version,
                        cursor,
                        expected_integrity.as_deref(),
                        lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
                    )
                    .map(|(_path, sri, timings)| (sri, timings, None))
            }
        },
    )
    .await
    .map_err(|e| LpmError::Registry(format!("streaming extract task panicked: {e}")))??;
    let pipeline_ms = extract_start.elapsed().as_millis();

    // `pipeline_ms` is the spawn_blocking wall-clock; we prefer the
    // store's inner `stage.extract_ms` for the breakdown because it
    // excludes join overhead.
    let _ = pipeline_ms;

    Ok((
        computed_sri,
        TaskTimings::from_stage(
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            0,
            extract_permit_wait_ms,
            stage,
        ),
        final_url,
        fresh_object,
    ))
}
