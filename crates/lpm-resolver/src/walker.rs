//! Phase 49 client-side streaming BFS walker.
//!
//! The walker discovers transitive dependencies breadth-first from a root
//! set, fetches metadata for each canonical package name, populates the
//! shared cache (and per-canonical `Notify` waiters), and emits
//! `(name, PackageMetadata)` frames on the speculation channel the
//! existing dispatcher (`spawn_speculation_dispatcher` in
//! `lpm-cli/src/commands/install.rs`, extracted from the pre-49
//! `run_deep_batch_with_speculation`) consumes. The walker is the
//! metadata producer for both the resolver (via `SharedCache` insert)
//! and the dispatcher (via the mpsc channel), keeping the dispatcher
//! body itself untouched (preplan §5.5).
//!
//! # Location rationale
//!
//! Preplan §5.5 initially placed the walker in `lpm-registry`, but that
//! would require moving [`crate::CanonicalKey`], [`crate::provider::SharedCache`]
//! and [`crate::provider::NotifyMap`] to `lpm-common` or duplicating them —
//! neither is a good fit. The walker lives here instead; the circular
//! dep is avoided because `lpm-resolver` already depends on `lpm-registry`
//! (for `RegistryClient`, `PackageMetadata`, `RouteMode`, etc.) and
//! nothing in `lpm-registry` needs to know the walker exists.
//!
//! # Ordering invariant (preplan §5.5)
//!
//! Per manifest, steps MUST run in this order (do not permute):
//!   1. `shared_cache.insert(canonical_key, cached_info)`
//!   2. `notify_map[canonical_key].notify_waiters()`
//!   3. fire `roots_ready` oneshot iff this completes the root set
//!   4. `spec_tx.send((name, metadata)).await` — the only step that
//!      can `.await` on backpressure
//!
//! Step 4 is last so resolver visibility is never gated on dispatcher
//! throughput. A refactor that moves the send earlier would silently
//! reintroduce the very bottleneck W4 previously hit; the comment block
//! above the per-manifest helper enforces the invariant at code-read
//! time.

use crate::package::CanonicalKey;
use crate::provider::{
    CachedPackageInfo, NotifyMap, SharedCache, WalkerDone, parse_metadata_to_cache_info,
};
use lpm_registry::{PackageMetadata, RegistryClient, RouteMode, UpstreamRoute};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

/// Server-side deep walk cap in the Worker's old BFS endpoint; we
/// mirror it client-side to prevent runaway walks on malformed
/// manifests. Preplan §5.5.
const MAX_WALK_DEPTH: u32 = 16;

/// Default npm fan-out for [`RegistryClient::parallel_fetch_npm_manifests`]
/// (BFS walker) and the per-`run_stream` Semaphore permit count (stream
/// walker). Callers can override via [`BfsWalker::with_npm_fanout`] or the
/// `LPM_NPM_FANOUT` env var (read in [`BfsWalker::run`]).
///
/// **Phase 54 W3 Option C empirical bump (was 50):** n=10 cold-equal-
/// footing on `bench/fixture-large`, stream walker + greedy resolver:
///
///   fanout= 50  median=4816 ms  stdev= 972 ms  ← prior default
///   fanout=128  median=4403 ms  stdev=1578 ms  (noisy, t=0.59 not sig.)
///   fanout=256  median=4124 ms  stdev= 253 ms  (t=3.49 SIGNIFICANT)
///
/// Bumping to 256 on the same single HTTP/2 connection saves ~700 ms
/// median wall (-14.4 %) AND collapses stdev by ~74 % (972 → 253). No
/// server-side rejection at 256 streams on a single npmjs.org h2
/// connection — the registry doesn't enforce the "most CDNs cap at
/// 100" limit some hypotheses warned about.
///
/// The remaining 4-sec gap to bun's 765 ms is per-connection flow
/// control on the single h2 multiplex socket; bun uses 64 separate
/// HTTP/1.1 sockets to bypass that. Pursued in Phase 55 Option B
/// (h1-pool transport).
pub const DEFAULT_NPM_FANOUT: usize = 256;

/// Per-walk statistics, folded into the `timing.resolve.streaming_bfs`
/// JSON sub-object by the install.rs orchestration (preplan §5.6).
#[derive(Debug, Clone, Default)]
pub struct WalkerSummary {
    /// Number of manifests the walker inserted into `shared_cache`.
    pub manifests_fetched: usize,
    /// Names skipped because `shared_cache` already held the entry
    /// (e.g., a prior walker pass or the caller pre-seeded roots).
    pub cache_hits: usize,
    /// Deepest BFS level reached (0 = roots).
    pub max_depth: u32,
    /// Cumulative wall-clock the walker spent blocked on
    /// `spec_tx.send().await`. The canary for dispatcher backpressure
    /// per preplan §5.6 — healthy value is 0/near-zero on F1/F2.
    pub spec_tx_send_wait_ms: u128,
    /// Wall-clock of the walker's entire `run()` lifetime — from entry
    /// to the point it returns the summary. The metadata-producer
    /// window. Downstream reporters use this for
    /// `timing.fetch_breakdown.speculative.streaming_batch_ms` so the
    /// metric reflects only the walker's producing phase, NOT any
    /// dispatcher/fetch-overlap tail that continues after the walker
    /// drops `spec_tx`.
    pub walker_wall_ms: u128,
    /// **Phase 54 W1** — per-BFS-level timing breakdown. One entry per
    /// level the walker iterates (level 0 = roots, level N = N-th
    /// transitive expansion). Each entry attributes that level's wall
    /// to its three phases — `setup` (partition + cache-hit handling),
    /// `fetch` (`tokio::join!` of the npm + lpm halves), `commit`
    /// (the per-result `commit_manifest` + `expand_deps_from_info`
    /// loop). Sum of `total_ms` across levels approximates
    /// `walker_wall_ms`; the gap (if any) is pre/post-loop overhead.
    /// Surfaced through `timing.resolve.streaming_bfs.levels` in
    /// `--json` output so Phase 54 W3's bench can quantify per-level
    /// dead time across the BFS.
    pub levels: Vec<LevelTiming>,
}

/// **Phase 54 W1** — one BFS level's three-phase wall breakdown.
///
/// The level loop in [`BfsWalker::run`] does, in order:
///   1. **Setup**: drain `current_level`, partition by route, look up
///      cached entries, expand cache hits' deps into `next_level`.
///   2. **Fetch**: `tokio::join!(npm_fut, lpm_fut)` — concurrent
///      manifest fetches for the two halves.
///   3. **Commit**: for each landed manifest, run
///      `commit_manifest` (cache insert + notify + spec_tx send) +
///      `expand_deps_from_info` (seed `next_level` with declared deps).
///
/// `total_ms` is the wall of the whole iteration (start of setup to
/// end of commit). `total_ms − fetch_ms` is the **inter-fetch dead
/// time** that Phase 54 W2's continuous-stream walker eliminates.
#[derive(Debug, Clone, Default)]
pub struct LevelTiming {
    /// Zero-indexed BFS depth. Level 0 = root deps from `package.json`.
    pub depth: u32,
    /// Number of names entering this level (after dedupe via `seen`).
    pub seeded_count: usize,
    /// Names whose canonical was already in `shared_cache` when this
    /// level started — skipped fetching, but still expanded for the
    /// next level's seeds.
    pub cache_hit_count: usize,
    /// Names routed to the npm-direct fetcher this level.
    pub npm_fetch_count: usize,
    /// Names routed to the lpm-worker batch fetcher this level.
    pub lpm_fetch_count: usize,
    /// Wall of the partition + cache-hit-expansion phase, before any
    /// network is hit.
    pub setup_ms: u128,
    /// Wall of `tokio::join!(npm_fut, lpm_fut)` — the concurrent
    /// manifest fetch for both halves of this level. This is what
    /// the BFS barrier waits on before any of next-level's fetches
    /// can start.
    pub fetch_ms: u128,
    /// Wall of the per-result `commit_manifest` + `expand_deps_from_info`
    /// loop. Holds the spec_tx backpressure cost (see
    /// `WalkerSummary::spec_tx_send_wait_ms` for the cumulative-across-
    /// levels figure).
    pub commit_ms: u128,
    /// Wall of the entire level iteration, start of setup → end of
    /// commit. `setup_ms + fetch_ms + commit_ms` ≈ `total_ms`.
    pub total_ms: u128,
}

/// Walker errors. Per-package fetch errors are logged at debug and do
/// not surface here (preplan §7.1); only wholesale shutdowns do.
#[derive(Debug, thiserror::Error)]
pub enum WalkerError {
    /// A network or infrastructure failure the walker can't recover from.
    /// Install.rs orchestration (§5) surfaces this via `WalkerJoin::drain`.
    #[error("walker failed: {0}")]
    Fatal(String),
}

/// RAII guard that fires the wait-loop shutdown handshake from
/// [`BfsWalker::run`].
///
/// On drop — whether `run()` returns normally, returns
/// [`WalkerError`], or panics mid-walk — this guard:
///
/// 1. Stores `walker_done = true` (Release).
/// 2. Iterates every entry in `notify_map` and calls
///    `notify_waiters()`.
///
/// The order is load-bearing. The provider's `ensure_cached` wait-loop
/// pins `Notified::enable()` and re-checks (cache, then
/// `walker_done`); either ordering outcome wakes a sleeper in
/// microseconds: flag observed first → wait-loop short-circuits to the
/// escape-hatch fetch; notify observed first → wait-loop wakes,
/// re-checks the cache (still miss), re-checks the flag (now true),
/// short-circuits.
///
/// Without this guard a panic mid-walk would strand every sleeper for
/// the full `fetch_wait_timeout` (the 5s × N misses pathology that
/// turned a 60-dep `express` install into 40s of wall-clock).
struct WalkerShutdownGuard {
    walker_done: WalkerDone,
    notify_map: NotifyMap,
}

impl Drop for WalkerShutdownGuard {
    fn drop(&mut self) {
        self.walker_done.store(true, Ordering::Release);
        for entry in self.notify_map.iter() {
            entry.value().notify_waiters();
        }
    }
}

/// Client-side streaming BFS walker.
///
/// Construct via [`BfsWalker::new`] and drive with [`BfsWalker::run`]
/// (consuming). The walker is level-by-level — each level partitions
/// names by route (`LpmWorker` vs `NpmDirect`), fetches the two halves
/// concurrently, then expands each landed manifest into the next
/// level's deps. Dedup via a local `seen` set keyed by
/// [`CanonicalKey`].
pub struct BfsWalker {
    client: Arc<RegistryClient>,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    /// Phase 49 wait-loop early-exit signal. Set to `true` (Release) at
    /// the very end of [`Self::run`], immediately before broadcasting
    /// `notify_waiters()` across every entry in `notify_map`. The
    /// provider's wait-loop in `ensure_cached` checks this flag after
    /// `Notified::enable()` and short-circuits to the escape-hatch
    /// fetch, avoiding a 5s sleep per missed transitive when the walker
    /// terminates without inserting a particular key (e.g. an
    /// older-version dep that newest-only expansion didn't enqueue).
    /// Owned by install.rs and shared with the provider via the same
    /// Arc.
    walker_done: WalkerDone,
    spec_tx: mpsc::Sender<(String, PackageMetadata)>,
    roots_ready_tx: Option<oneshot::Sender<()>>,
    dep_names: Vec<String>,
    route_mode: RouteMode,
    npm_fanout: usize,
}

impl BfsWalker {
    #[allow(clippy::too_many_arguments)] // design-level: orchestration constructor for the Phase 49 streaming walker
    pub fn new(
        client: Arc<RegistryClient>,
        shared_cache: SharedCache,
        notify_map: NotifyMap,
        walker_done: WalkerDone,
        spec_tx: mpsc::Sender<(String, PackageMetadata)>,
        roots_ready_tx: oneshot::Sender<()>,
        dep_names: Vec<String>,
        route_mode: RouteMode,
    ) -> Self {
        Self {
            client,
            shared_cache,
            notify_map,
            walker_done,
            spec_tx,
            roots_ready_tx: Some(roots_ready_tx),
            dep_names,
            route_mode,
            npm_fanout: DEFAULT_NPM_FANOUT,
        }
    }

    /// Override the npm parallel-fetch concurrency (default 50).
    pub fn with_npm_fanout(mut self, fanout: usize) -> Self {
        self.npm_fanout = fanout;
        self
    }

    /// Run the walker to termination. Returns a [`WalkerSummary`] on
    /// normal exit; [`WalkerError::Fatal`] on unrecoverable errors.
    ///
    /// Per-package fetch failures are logged at debug and the walk
    /// continues — matches bun/pnpm semantics (preplan §7.1). The
    /// provider's escape-hatch path will handle any package the walker
    /// skipped.
    ///
    /// **Phase 54 dispatch:** the env var `LPM_WALKER` picks between
    /// the level-step BFS implementation and the continuous-stream
    /// implementation introduced in Phase 54 W2. Default is BFS until
    /// W3's bench validates the stream walker; users opting into
    /// `LPM_WALKER=stream` get the continuous-stream path. See
    /// `DOCS/new-features/37-rust-client-RUNNER-VISION-phase54-continuous-stream-walker-preplan.md`.
    pub async fn run(mut self) -> Result<WalkerSummary, WalkerError> {
        // **Phase 54 W3 follow-up — Option C probe:** allow overriding
        // the npm fan-out at runtime via `LPM_NPM_FANOUT`. Default stays
        // [`DEFAULT_NPM_FANOUT`] (50). Empirically tests whether the
        // registry server's `max_concurrent_streams` setting is the cap
        // (most CDNs hard-cap HTTP/2 streams at 100); if bumping past
        // the default doesn't move the wall, the bottleneck is per-
        // connection flow control, not stream concurrency.
        if let Ok(s) = std::env::var("LPM_NPM_FANOUT")
            && let Ok(n) = s.parse::<usize>()
            && n > 0
        {
            self.npm_fanout = n;
        }
        if std::env::var("LPM_WALKER").as_deref() == Ok("stream") {
            self.run_stream().await
        } else {
            self.run_bfs().await
        }
    }

    /// Phase 49 level-step BFS walker (the original implementation).
    /// Each level partitions names by route, fetches the two halves
    /// concurrently via `tokio::join!`, then expands each landed
    /// manifest into the next level's seeds — a stop-the-world
    /// barrier per level. Phase 54 W1 instrumentation in this body
    /// quantifies the per-level wall breakdown.
    async fn run_bfs(mut self) -> Result<WalkerSummary, WalkerError> {
        // Capture the walker's own wall-clock. Measured INSIDE the
        // walker task so `summary.walker_wall_ms` reflects the exact
        // producer-window duration regardless of when the caller
        // eventually `.await`s the JoinHandle. Without this, the
        // downstream `streaming_batch_ms` reporter would measure
        // "drain call time − spawn time" and include any post-walker
        // fetch overlap — breaking the metadata-producer-window
        // contract.
        let run_start = Instant::now();

        // Phase 49 wait-loop shutdown handshake (preplan §5.1 fix).
        // Held for the lifetime of `run()`; fires `notify_waiters()`
        // across every `notify_map` entry on drop. Whether `run()`
        // exits normally, returns an error, or panics mid-walk, every
        // waiter sleeping on a key the walker decided not to fetch
        // gets woken — and the provider's wait-loop sees
        // `walker_done == true` on its post-wake re-check, breaking
        // to the escape-hatch fetch in microseconds. Without this
        // backstop a walker panic stranded sleepers for the full
        // `fetch_wait_timeout` (the 5s × N misses pathology).
        let _shutdown_guard = WalkerShutdownGuard {
            walker_done: self.walker_done.clone(),
            notify_map: self.notify_map.clone(),
        };
        let mut summary = WalkerSummary::default();
        let mut seen: HashSet<CanonicalKey> = HashSet::new();

        let root_keys: HashSet<CanonicalKey> = self
            .dep_names
            .iter()
            .map(|n| CanonicalKey::from_dep_name(n))
            .collect();
        let mut roots_inserted: HashSet<CanonicalKey> = HashSet::new();

        // Seed level 0 with the roots, deduplicated by canonical key.
        let mut current_level: Vec<String> = Vec::new();
        for name in &self.dep_names {
            let key = CanonicalKey::from_dep_name(name);
            if seen.insert(key) {
                current_level.push(name.clone());
            }
        }

        let mut depth: u32 = 0;
        while !current_level.is_empty() && depth < MAX_WALK_DEPTH {
            summary.max_depth = depth;

            // Phase 54 W1 — per-level timing capture.
            let level_start = Instant::now();
            let setup_start = level_start;
            let seeded_count = current_level.len();
            let mut cache_hit_count: usize = 0;

            // Partition names into (already-cached, need-fetch-npm,
            // need-fetch-lpm). A cache hit still has to seed the next
            // BFS level — we read the cached `CachedPackageInfo`'s
            // newest-version deps and enqueue them. Skipping transitive
            // expansion on cache hits (the pre-fix behavior) truncated
            // the walk exactly at pre-seeded / previously-fetched roots
            // — the reviewer caught this on the shared-cache seam §5
            // is about to wire into.
            //
            // Cached entries do NOT re-emit on `spec_tx`: the manifest
            // was already produced by whoever seeded the cache, and the
            // dispatcher dedupes internally anyway. Re-emitting would
            // just waste channel capacity.
            let mut next_level: Vec<String> = Vec::new();
            let (mut npm_names, mut lpm_names): (Vec<String>, Vec<String>) =
                (Vec::new(), Vec::new());
            for name in current_level.drain(..) {
                let key = CanonicalKey::from_dep_name(&name);
                // Clone the cached info out of the DashMap guard and let
                // the guard drop at the `;` — holding it across the
                // subsequent `&mut self` call on `maybe_fire_roots_ready`
                // triggers an E0502 borrow conflict (DashMap `Ref`
                // carries a shard read lock, not just a data reference).
                let cached = self.shared_cache.get(&key).map(|r| r.value().clone());
                if let Some(info) = cached {
                    summary.cache_hits += 1;
                    cache_hit_count += 1;
                    expand_deps_from_info(&info, &mut seen, &mut next_level);
                    if root_keys.contains(&key) {
                        roots_inserted.insert(key);
                        self.maybe_fire_roots_ready(&roots_inserted, &root_keys);
                    }
                    continue;
                }
                match self.route_mode.route_for_package(&name) {
                    UpstreamRoute::NpmDirect => npm_names.push(name),
                    UpstreamRoute::LpmWorker => lpm_names.push(name),
                }
            }

            // Phase 54 W1 — capture partition counts before the futures
            // move `npm_names` / `lpm_names`, and snapshot setup wall.
            let npm_fetch_count = npm_names.len();
            let lpm_fetch_count = lpm_names.len();
            let setup_ms = setup_start.elapsed().as_millis();

            // Fetch npm and LPM halves concurrently.
            let npm_fanout = self.npm_fanout;
            let client_npm = self.client.clone();
            let client_lpm = self.client.clone();
            let mode = self.route_mode;
            let npm_fut = async move {
                if npm_names.is_empty() {
                    Vec::new()
                } else {
                    // In Proxy mode the npm partition is empty (route_for_package
                    // routes all non-`@lpm.dev` to LpmWorker); the npm_names list
                    // only has entries when we're in Direct mode. Using the
                    // direct-tier fan-out is therefore correct without a mode
                    // branch here.
                    let _ = mode;
                    let n = npm_names.len() as u32;
                    let (results, _stats) = client_npm
                        .parallel_fetch_npm_manifests(&npm_names, npm_fanout)
                        .await;
                    // Phase 53 A1 — `parallel_fetch_npm_manifests` fans out
                    // one HTTP call per name; tag them as walker-driven so
                    // the resolver's `walker_rpc_count` snapshot matches.
                    lpm_registry::timing::record_walker_rpcs(n);
                    results
                }
            };
            let lpm_fut = async move {
                if lpm_names.is_empty() {
                    Vec::new()
                } else {
                    // Phase 53 A1 — one batch RPC fired regardless of names.len().
                    lpm_registry::timing::record_walker_rpcs(1);
                    match client_lpm.batch_metadata(&lpm_names).await {
                        Ok(map) => map.into_iter().map(|(n, m)| (n, Ok(m))).collect(),
                        Err(e) => {
                            tracing::debug!("walker: lpm batch failed: {e}");
                            // Non-fatal: walker continues; provider's
                            // escape-hatch fetches individual misses.
                            Vec::new()
                        }
                    }
                }
            };
            // Phase 54 W1 — fetch wall is the wall of `tokio::join!` itself.
            let fetch_start = Instant::now();
            let (npm_results, lpm_results) = tokio::join!(npm_fut, lpm_fut);
            let fetch_ms = fetch_start.elapsed().as_millis();

            // Merge. Each entry is `(name, Result<PackageMetadata, LpmError>)`.
            // Phase 54 W1 — commit wall is the per-result loop time.
            let commit_start = Instant::now();
            for (name, res) in npm_results.into_iter().chain(lpm_results) {
                match res {
                    Ok(meta) => {
                        let is_npm = !name.starts_with("@lpm.dev/");
                        // `commit_manifest` returns the `CachedPackageInfo`
                        // it parsed + inserted so we can expand deps
                        // from it without re-parsing. Expansion uses the
                        // parsed info (not raw metadata) so the cache-hit
                        // path and the fresh-fetch path share one
                        // dep-discovery primitive.
                        let info = self
                            .commit_manifest(
                                &name,
                                &meta,
                                is_npm,
                                &root_keys,
                                &mut roots_inserted,
                                &mut summary,
                            )
                            .await;
                        expand_deps_from_info(&info, &mut seen, &mut next_level);
                    }
                    Err(e) => {
                        tracing::debug!("walker: fetch failed for {name}: {e}");
                    }
                }
            }
            let commit_ms = commit_start.elapsed().as_millis();

            // Phase 54 W1 — record this level's three-phase wall + counts.
            let total_ms = level_start.elapsed().as_millis();
            tracing::info!(
                target: "lpm_resolver::walker",
                "walker level {} seeded={} cache_hits={} npm_fetch={} lpm_fetch={} setup_ms={} fetch_ms={} commit_ms={} total_ms={}",
                depth,
                seeded_count,
                cache_hit_count,
                npm_fetch_count,
                lpm_fetch_count,
                setup_ms,
                fetch_ms,
                commit_ms,
                total_ms,
            );
            summary.levels.push(LevelTiming {
                depth,
                seeded_count,
                cache_hit_count,
                npm_fetch_count,
                lpm_fetch_count,
                setup_ms,
                fetch_ms,
                commit_ms,
                total_ms,
            });

            current_level = next_level;
            depth += 1;
        }

        // Drop the spec_tx sender by consuming self — the dispatcher's
        // `rx.recv()` then observes `None` and exits its loop, matching
        // the channel-close termination contract of the pre-49 streaming
        // batch path.
        drop(self.spec_tx);

        // Roots-ready is never held past the end: if the walker exits
        // without all roots fetched (e.g. they all 404'd), fire the
        // signal anyway so the caller doesn't deadlock awaiting it.
        // The resolver will then either find what it needs in the
        // cache or hit its escape-hatch path.
        if let Some(tx) = self.roots_ready_tx.take() {
            let _ = tx.send(());
        }

        summary.walker_wall_ms = run_start.elapsed().as_millis();
        // The shutdown guard fires here on its way out of scope and
        // performs the walker_done store + notify_waiters broadcast.
        Ok(summary)
    }

    /// **Phase 54 W2** — continuous-stream walker. Bun-style "fetch on
    /// manifest parse": no level barrier; the moment a parent's
    /// manifest body lands and reveals its `dependencies` map, each
    /// child is enqueued for fetching independently. Concurrency is
    /// bounded by a single `Semaphore(npm_fanout)` instead of per-level
    /// batching, so the throughput cap is global, not per-level.
    ///
    /// Mirrors the same SharedCache + NotifyMap + spec_tx contract as
    /// `run_bfs` (preplan §5.5 ordering: insert → notify → roots_ready →
    /// spec_tx send), so callers see no behavioral change beyond
    /// timing. Both PubGrub's `LpmDependencyProvider::ensure_cached`
    /// wait-loop and the greedy resolver's `ensure_manifest` continue
    /// to work unchanged because the cache + notify state shape is
    /// identical.
    ///
    /// **Termination:** the loop owns the only `tx` for the dependency
    /// channel. When `in_flight` is empty AND `rx` is empty, no more
    /// children can ever appear, so `tx` is dropped; the next `rx.recv()`
    /// returns `None`, both `select!` arms are unmatched, and the
    /// `else` arm fires `break`.
    ///
    /// **Per-fetch permit acquisition:** each fetch task acquires its
    /// own permit from the shared `Semaphore` *inside* the spawned
    /// future. The dispatch loop itself never blocks on permit
    /// acquisition — it just spawns the task into a `JoinSet` and
    /// continues. Tasks waiting on permits sit parked in the runtime;
    /// the semaphore caps actual concurrent network I/O.
    async fn run_stream(mut self) -> Result<WalkerSummary, WalkerError> {
        let run_start = Instant::now();
        let _shutdown_guard = WalkerShutdownGuard {
            walker_done: self.walker_done.clone(),
            notify_map: self.notify_map.clone(),
        };
        let mut summary = WalkerSummary::default();
        let mut seen: HashSet<CanonicalKey> = HashSet::new();

        let root_keys: HashSet<CanonicalKey> = self
            .dep_names
            .iter()
            .map(|n| CanonicalKey::from_dep_name(n))
            .collect();
        let mut roots_inserted: HashSet<CanonicalKey> = HashSet::new();

        // Channel of (name, depth) pairs. Depth 0 = root deps; each
        // child sent with parent's depth + 1. Caller checks
        // `depth < MAX_WALK_DEPTH` before sending.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
        let mut tx: Option<tokio::sync::mpsc::UnboundedSender<(String, u32)>> = Some(tx);

        // Global concurrency cap. Tasks acquire a permit before
        // hitting the network; the dispatch loop itself never waits
        // on the semaphore.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.npm_fanout));

        // In-flight fetches. tokio::task::JoinSet is the tokio-native
        // equivalent of FuturesUnordered<JoinHandle> — same shape, no
        // futures crate dep.
        let mut in_flight: tokio::task::JoinSet<(
            String,
            u32,
            Result<lpm_registry::PackageMetadata, lpm_common::LpmError>,
        )> = tokio::task::JoinSet::new();

        // Seed roots at depth 0, deduplicated by canonical key.
        for name in &self.dep_names {
            let key = CanonicalKey::from_dep_name(name);
            if seen.insert(key)
                && let Some(t) = tx.as_ref()
            {
                let _ = t.send((name.clone(), 0));
            }
        }

        loop {
            // Termination check (BEFORE the select!): drop the only
            // sender once nothing more can land. With in_flight empty
            // and rx drained, no future child can appear; closing tx
            // makes the next rx.recv() return None and the else arm
            // fires `break`.
            if tx.is_some() && in_flight.is_empty() && rx.is_empty() {
                tx = None;
            }

            tokio::select! {
                biased;
                // Higher priority: drain a settled fetch first so
                // permits free up and children get discovered.
                Some(joined) = in_flight.join_next(), if !in_flight.is_empty() => {
                    let (name, depth, result) = joined.map_err(|e| {
                        WalkerError::Fatal(format!("walker fetch task join: {e}"))
                    })?;
                    if depth > summary.max_depth {
                        summary.max_depth = depth;
                    }
                    match result {
                        Ok(meta) => {
                            let is_npm = !name.starts_with("@lpm.dev/");
                            let info = self
                                .commit_manifest(
                                    &name, &meta, is_npm,
                                    &root_keys, &mut roots_inserted, &mut summary,
                                )
                                .await;
                            if depth + 1 < MAX_WALK_DEPTH {
                                let mut next: Vec<String> = Vec::new();
                                expand_deps_from_info(&info, &mut seen, &mut next);
                                if let Some(t) = tx.as_ref() {
                                    for child in next {
                                        let _ = t.send((child, depth + 1));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("walker stream: fetch failed for {name}: {e}");
                        }
                    }
                }
                Some((name, depth)) = rx.recv() => {
                    let key = CanonicalKey::from_dep_name(&name);
                    // Drop the DashMap guard before any &mut self call
                    // (matches run_bfs's E0502 mitigation).
                    let cached = self.shared_cache.get(&key).map(|r| r.value().clone());
                    if let Some(info) = cached {
                        summary.cache_hits += 1;
                        if root_keys.contains(&key) {
                            roots_inserted.insert(key);
                            self.maybe_fire_roots_ready(&roots_inserted, &root_keys);
                        }
                        if depth + 1 < MAX_WALK_DEPTH {
                            let mut next: Vec<String> = Vec::new();
                            expand_deps_from_info(&info, &mut seen, &mut next);
                            if let Some(t) = tx.as_ref() {
                                for child in next {
                                    let _ = t.send((child, depth + 1));
                                }
                            }
                        }
                        if depth > summary.max_depth {
                            summary.max_depth = depth;
                        }
                        continue;
                    }

                    // Spawn fetch — permit acquisition happens inside
                    // the spawned future so the dispatch loop never
                    // blocks on the semaphore.
                    let route = self.route_mode.route_for_package(&name);
                    let client = self.client.clone();
                    let sem = semaphore.clone();
                    let name_owned = name;
                    in_flight.spawn(async move {
                        let _permit = match sem.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                // Semaphore closed (shouldn't happen —
                                // we hold an Arc); surface as a registry
                                // error so the result handler logs and
                                // moves on.
                                return (
                                    name_owned,
                                    depth,
                                    Err(lpm_common::LpmError::Registry(
                                        "walker semaphore closed".to_string(),
                                    )),
                                );
                            }
                        };
                        let result = match route {
                            UpstreamRoute::NpmDirect => {
                                client.get_npm_metadata_direct(&name_owned).await
                            }
                            UpstreamRoute::LpmWorker => {
                                if name_owned.starts_with("@lpm.dev/") {
                                    match lpm_common::PackageName::parse(&name_owned) {
                                        Ok(pkg_name) => {
                                            client.get_package_metadata(&pkg_name).await
                                        }
                                        Err(e) => Err(lpm_common::LpmError::Registry(
                                            format!("invalid lpm name {name_owned}: {e}"),
                                        )),
                                    }
                                } else {
                                    client.get_npm_package_metadata(&name_owned).await
                                }
                            }
                        };
                        // Phase 53 A1 — count this fetch as walker-driven
                        // regardless of success/error. The Phase 49 stream
                        // walker fans out one HTTP call per package (no
                        // batch_metadata path here, unlike `run_bfs`), so
                        // each completion is exactly one RPC. TTL cache
                        // hits inside the client short-circuit before
                        // `record_rpc` fires, so they correctly do NOT
                        // contribute to either bucket.
                        lpm_registry::timing::record_walker_rpcs(1);
                        (name_owned, depth, result)
                    });
                }
                else => break,
            }
        }

        drop(self.spec_tx);

        if let Some(tx) = self.roots_ready_tx.take() {
            let _ = tx.send(());
        }

        summary.walker_wall_ms = run_start.elapsed().as_millis();
        Ok(summary)
    }

    /// Per-manifest commit. Enforces the preplan §5.5 ordering invariant:
    /// (1) shared_cache insert, (2) notify_waiters, (3) roots_ready
    /// signal if applicable, (4) spec_tx.send — the only awaiting step.
    /// Do NOT permute. See module-level doc for rationale.
    async fn commit_manifest(
        &mut self,
        name: &str,
        meta: &PackageMetadata,
        is_npm: bool,
        root_keys: &HashSet<CanonicalKey>,
        roots_inserted: &mut HashSet<CanonicalKey>,
        summary: &mut WalkerSummary,
    ) -> CachedPackageInfo {
        let key = CanonicalKey::from_dep_name(name);

        // (1) Insert into shared cache. Keep a clone to return so the
        // caller can drive dep expansion without re-parsing or looking
        // the entry back out of the DashMap.
        let info = parse_metadata_to_cache_info(meta, is_npm);
        // Phase 55 W4: cache stores Arc<CachedPackageInfo> so per-edge
        // resolver lookups are refcount bumps. The clone here happens
        // once per fetch (this function), not per edge.
        self.shared_cache
            .insert(key.clone(), Arc::new(info.clone()));

        // (2) Fire per-canonical waiters.
        if let Some(n) = self.notify_map.get(&key) {
            n.notify_waiters();
        }

        // (3) Roots-ready.
        if root_keys.contains(&key) {
            roots_inserted.insert(key.clone());
            self.maybe_fire_roots_ready(roots_inserted, root_keys);
        }

        summary.manifests_fetched += 1;

        // (4) Speculation hint. May block on dispatcher backpressure;
        // we measure the wait so `timing.resolve.streaming_bfs.spec_tx_send_wait_ms`
        // surfaces the cost if it ever matters (preplan §5.6 canary).
        let send_start = Instant::now();
        let _ = self.spec_tx.send((name.to_string(), meta.clone())).await;
        summary.spec_tx_send_wait_ms += send_start.elapsed().as_millis();

        info
    }

    fn maybe_fire_roots_ready(
        &mut self,
        roots_inserted: &HashSet<CanonicalKey>,
        root_keys: &HashSet<CanonicalKey>,
    ) {
        if roots_inserted.len() == root_keys.len()
            && let Some(tx) = self.roots_ready_tx.take()
        {
            let _ = tx.send(());
        }
    }
}

/// Expand a cached-info entry's deps into the next BFS level's name
/// list.
///
/// Discovery picks the **semver-newest version**
/// (`info.versions[0]`, kept sorted newest-first by
/// `parse_metadata_to_cache_info`) and enqueues that version's deps
/// with alias resolution: a `"local": "npm:target@range"` declaration
/// enqueues `target`, not the local label (the local label isn't a
/// registry identity and would 404).
///
/// # Why newest-only and not union-across-versions
///
/// Two earlier strategies were measured and abandoned:
///
/// 1. **Full union (§11):** walk every version's dep set. Caused
///    recursive over-fetch — each package's full-history dep set
///    pulls in historical packages whose own histories pull in more,
///    exploding through the BFS. Express with `^4.18.0` measured at
///    7,146 manifests / 31.8 s walker wall-clock vs the install's
///    actual 60-package footprint.
///
/// 2. **Bounded union by major (top-K=4 buckets):** still amplifies.
///    Express: 845 manifests / 7.6 s walker, then pubgrub spent 11 s
///    chewing through the inflated cache. The cap helps in isolation
///    but the chain of older transitives still compounds through BFS
///    levels.
///
/// Newest-only on the same fixture: 68 manifests / 72 ms walker,
/// 6 escape-hatch fetches in microseconds (covered by the §12
/// `walker_done` broadcast) — total resolve <1 s. The escape-hatch
/// being cheap is the load-bearing change: when a name the walker
/// missed comes up in the solve, [`super::LpmDependencyProvider::ensure_cached`]
/// short-circuits via `walker_done` in microseconds and a single
/// direct fetch (nearly always disk-cache-warm) lands the manifest.
/// Walking proactively to avoid those fetches is a net loss.
///
/// # The older-version-pick case
///
/// PubGrub may still pick a non-semver-newest version (e.g. a
/// consumer pinned to `^1.0.0` while the package's tip is 4.x). The
/// walker won't have that version's transitives in cache, so
/// `get_dependencies` will call `ensure_cached` on names the walker
/// never enqueued. After §12 those calls short-circuit through the
/// `walker_done` broadcast and complete in microseconds via
/// `direct_fetch_and_cache`. The
/// `cache_wait_walker_done_shortcuts` JSON counter measures exactly
/// these recoveries; on healthy installs it should track the count
/// of older-version picks (typically <10 even on big trees).
///
/// Caller dedupes via the `seen` set keyed by `CanonicalKey`, so a
/// dep name only enqueues once.
fn expand_deps_from_info(
    info: &CachedPackageInfo,
    seen: &mut HashSet<CanonicalKey>,
    next_level: &mut Vec<String>,
) {
    let Some(newest) = info.versions.first() else {
        return;
    };
    // `info.versions` round-trips through `NpmVersion::parse` →
    // `Display`; the same string was used as the `info.deps` /
    // `info.aliases` key in `parse_metadata_to_cache_info`.
    let ver_str = newest.to_string();
    let Some(deps) = info.deps.get(&ver_str) else {
        return;
    };
    let ver_aliases = info.aliases.get(&ver_str);
    for dep_name in deps.keys() {
        // Alias rewrite: if this version declares `dep_name` as a
        // `npm:<target>@<range>` alias, enqueue the target.
        let target_name: &str = ver_aliases
            .and_then(|m| m.get(dep_name))
            .map(String::as_str)
            .unwrap_or(dep_name.as_str());
        let dep_key = CanonicalKey::from_dep_name(target_name);
        if seen.insert(dep_key) {
            next_level.push(target_name.to_string());
        }
    }
}

#[cfg(test)]
async fn mount_with_delay(
    server: &wiremock::MockServer,
    name: &str,
    deps: &[(&str, &str)],
    delays: &[(&'static str, u64)],
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let deps_obj: serde_json::Map<String, serde_json::Value> = deps
        .iter()
        .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
        .collect();
    let body = serde_json::json!({
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg.tgz",
                    "integrity": "sha512-test"
                },
                "dependencies": deps_obj
            }
        },
        "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
    });
    let delay_ms = delays
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, d)| *d)
        .unwrap_or(0);
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(body)
                .set_delay(std::time::Duration::from_millis(delay_ms)),
        )
        .mount(server)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicBool;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Default-false [`WalkerDone`] for tests. The walker flips it to
    /// `true` at the end of `run()` regardless of which test calls it,
    /// so tests that need to inspect post-run state can clone this and
    /// `.load(Ordering::Acquire)` after `run().await`.
    fn make_walker_done() -> WalkerDone {
        Arc::new(AtomicBool::new(false))
    }

    fn metadata_json(name: &str, deps: &[(&str, &str)]) -> serde_json::Value {
        let deps_obj: serde_json::Map<String, serde_json::Value> = deps
            .iter()
            .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
            .collect();
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.com/pkg.tgz",
                        "integrity": "sha512-test"
                    },
                    "dependencies": deps_obj
                }
            },
            "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
        })
    }

    async fn mount(server: &MockServer, name: &str, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// Build one entry of an npm packument's `versions` map.
    /// Convenience for multi-version fixtures (`§13` bounded-union
    /// tests) so the test body stays readable.
    fn dist_with_deps(name: &str, version: &str, deps: &[(&str, &str)]) -> serde_json::Value {
        let deps_obj: serde_json::Map<String, serde_json::Value> = deps
            .iter()
            .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
            .collect();
        serde_json::json!({
            "name": name,
            "version": version,
            "dist": {
                "tarball": "https://example.com/pkg.tgz",
                "integrity": "sha512-test"
            },
            "dependencies": deps_obj,
        })
    }

    fn client_direct_to(npm_server: &MockServer) -> Arc<RegistryClient> {
        // Disable the disk cache entirely for walker tests. The
        // default `~/.lpm/cache/metadata/` is shared across every
        // test in the process AND persists between test runs, so
        // any test that writes a package's metadata there bleeds
        // into later tests that reuse the same name. Disabling the
        // cache keeps each walker test hermetic.
        Arc::new(
            RegistryClient::new()
                .with_base_url("http://127.0.0.1:1") // unused in direct mode
                .with_npm_registry_url(npm_server.uri())
                .with_cache_dir(None),
        )
    }

    /// Happy-path end-to-end: 2 roots with 1 transitive each. Asserts
    /// (a) all 4 manifests land in shared_cache, (b) roots_ready fires
    /// exactly once, (c) spec_tx receives all 4 frames, (d) summary
    /// reflects the walk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_end_to_end_discovery_and_signals() {
        let server = MockServer::start().await;
        mount(
            &server,
            "root-a",
            metadata_json("root-a", &[("leaf-a", "^1.0.0")]),
        )
        .await;
        mount(
            &server,
            "root-b",
            metadata_json("root-b", &[("leaf-b", "^1.0.0")]),
        )
        .await;
        mount(&server, "leaf-a", metadata_json("leaf-a", &[])).await;
        mount(&server, "leaf-b", metadata_json("leaf-b", &[])).await;

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let (spec_tx, mut spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["root-a".into(), "root-b".into()],
            RouteMode::Direct,
        );

        let summary = walker.run().await.expect("walker should succeed");

        // (a) All 4 manifests present.
        let keys: Vec<String> = shared_cache.iter().map(|e| e.key().to_string()).collect();
        assert_eq!(
            shared_cache.len(),
            4,
            "cache should hold 4 manifests, got: {keys:?}"
        );
        assert!(shared_cache.contains_key(&CanonicalKey::npm("root-a")));
        assert!(shared_cache.contains_key(&CanonicalKey::npm("root-b")));
        assert!(shared_cache.contains_key(&CanonicalKey::npm("leaf-a")));
        assert!(shared_cache.contains_key(&CanonicalKey::npm("leaf-b")));

        // (b) roots_ready fired.
        roots_ready_rx
            .await
            .expect("roots_ready oneshot must fire when both roots are in the cache");

        // (c) spec_tx received all frames.
        let mut frames = Vec::new();
        while let Some(frame) = spec_rx.recv().await {
            frames.push(frame.0);
        }
        assert_eq!(frames.len(), 4, "dispatcher must see 4 emitted frames");

        // (d) Summary.
        assert_eq!(summary.manifests_fetched, 4);
        assert_eq!(summary.cache_hits, 0);
        assert!(
            summary.max_depth >= 1,
            "walker walked at least one transitive level"
        );
    }

    /// Split-context lookup through the shared cache uses canonical keys —
    /// a walker insert under `leaf` MUST be visible to a lookup for
    /// `leaf[parent]` via `CanonicalKey::from(&ResolverPackage)`. This is
    /// the same invariant the provider's `ensure_cached` regression
    /// tests pin, retested end-to-end through the walker path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_inserts_under_canonical_key_not_context_bearing() {
        let server = MockServer::start().await;
        mount(&server, "lodash", metadata_json("lodash", &[])).await;

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let (spec_tx, _spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["lodash".into()],
            RouteMode::Direct,
        );
        walker.run().await.expect("walker succeeds");

        // A split-context ResolverPackage's canonicalization must hit
        // the walker's canonical insertion. If this ever fails, the
        // walker is inserting under something other than the canonical
        // key and provider split-retry lookups would silently miss.
        let split = crate::package::ResolverPackage::npm("lodash").with_context("parent");
        assert!(
            shared_cache.contains_key(&CanonicalKey::from(&split)),
            "walker insert must be visible under CanonicalKey::from(&split)"
        );
    }

    /// Respect MAX_WALK_DEPTH. Chain 20 packages; walker should stop
    /// at depth 16 and not walk the deepest 4.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_caps_at_max_walk_depth() {
        let server = MockServer::start().await;
        // Chain: pkg-0 → pkg-1 → … → pkg-19
        for i in 0..20 {
            let name = format!("pkg-{i}");
            let body = if i + 1 < 20 {
                let dep_name = format!("pkg-{}", i + 1);
                serde_json::json!({
                    "name": name,
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": name,
                            "version": "1.0.0",
                            "dist": { "tarball": "https://example.com/x.tgz", "integrity": "sha512-test" },
                            "dependencies": { dep_name: "^1.0.0" }
                        }
                    },
                    "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
                })
            } else {
                metadata_json(&name, &[])
            };
            mount(&server, &name, body).await;
        }

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let (spec_tx, _spec_rx) = mpsc::channel(64);
        let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["pkg-0".into()],
            RouteMode::Direct,
        );
        let summary = walker.run().await.expect("walker succeeds");

        // depth 0 = pkg-0; MAX_WALK_DEPTH=16 means levels 0..=15 are
        // walked (16 total). Fetched count caps there.
        assert_eq!(
            shared_cache.len() as u32,
            MAX_WALK_DEPTH,
            "walker must cap at MAX_WALK_DEPTH ({} levels)",
            MAX_WALK_DEPTH
        );
        assert_eq!(summary.max_depth, MAX_WALK_DEPTH - 1);
    }

    /// Regression for reviewer finding 1: a pre-seeded (cache-hit) root
    /// MUST still seed the next BFS level via its cached deps. Before
    /// the fix, the cache-hit branch `continue`d without reading the
    /// cached manifest back, truncating the walk exactly at any
    /// already-seeded node — exactly the shape §5 depends on.
    ///
    /// Setup: pre-seed `root-cached` in the shared cache with a dep on
    /// `leaf-x` (not mocked in the walker's fetch path, but retrievable
    /// via a mock GET). Mount `leaf-x`. Walker with root = `root-cached`
    /// should skip the root fetch BUT still walk `leaf-x`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_cache_hit_still_expands_transitive_deps() {
        let server = MockServer::start().await;
        mount(&server, "leaf-x", metadata_json("leaf-x", &[])).await;

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());

        // Pre-seed the root with a dep on `leaf-x` (bypassing the
        // walker's fetch path for `root-cached`). Build a
        // PackageMetadata → parse → insert under canonical key.
        let root_meta: PackageMetadata =
            serde_json::from_value(metadata_json("root-cached", &[("leaf-x", "^1.0.0")]))
                .expect("parse root fixture");
        let root_info = parse_metadata_to_cache_info(&root_meta, true);
        shared_cache.insert(CanonicalKey::npm("root-cached"), Arc::new(root_info));

        let (spec_tx, mut spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["root-cached".into()],
            RouteMode::Direct,
        );
        let summary = walker.run().await.expect("walker succeeds");

        // Root was cached → cache_hit counted, not a fetch.
        assert_eq!(
            summary.cache_hits, 1,
            "cached root must count as a cache hit"
        );
        // Transitive must have been walked + fetched.
        assert_eq!(
            summary.manifests_fetched, 1,
            "transitive `leaf-x` must be fetched via the expanded cache-hit path"
        );
        assert!(
            shared_cache.contains_key(&CanonicalKey::npm("leaf-x")),
            "leaf-x must be in the cache after walker completes"
        );

        // Roots_ready must still fire even though the only root was cached.
        roots_ready_rx
            .await
            .expect("roots_ready must fire for cached root");

        // spec_tx must see the transitive frame only (cached roots do
        // NOT re-emit — the frame was already produced when whoever
        // seeded the cache ran).
        let mut frames: Vec<String> = Vec::new();
        while let Some(frame) = spec_rx.recv().await {
            frames.push(frame.0);
        }
        assert_eq!(frames, vec!["leaf-x".to_string()]);
    }

    /// Phase 49 §8 — walker completion timing must not change the
    /// final shared-cache state. Runs the same walker twice against
    /// the same tree but with artificially asymmetric per-manifest
    /// latencies: pass A has slow roots + fast leaves, pass B is
    /// inverted. Both runs must produce the same set of
    /// `CanonicalKey`s in the shared cache and the same summary
    /// shape (modulo wall-clock counters).
    ///
    /// Preplan §8.1 lists "order-independence: same final solve
    /// result regardless of walker speed" as a walker test. The
    /// walker itself doesn't solve, but asserting its completion
    /// state is independent of fetch-order timing is the same
    /// invariant at the metadata-production layer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_result_independent_of_per_manifest_timing() {
        // Package names are namespaced with `ord-` so this test's
        // disk-cache writes (shared `~/.lpm/cache/metadata/` across
        // all tests in the process) don't contaminate other walker
        // tests that use generic names like `root-a`. The walker
        // dedupes via CanonicalKey so prefix-unique names are an
        // effective isolation mechanism without plumbing a new
        // test-only cache-dir setter.
        let run_once = |delays: Vec<(&'static str, u64)>| async move {
            let server = MockServer::start().await;
            // 2 roots → 2 leaves each (4 leaves total + 2 roots = 6 packages).
            mount_with_delay(
                &server,
                "ord-root-a",
                &[("ord-leaf-a1", "^1.0.0"), ("ord-leaf-a2", "^1.0.0")],
                &delays,
            )
            .await;
            mount_with_delay(
                &server,
                "ord-root-b",
                &[("ord-leaf-b1", "^1.0.0"), ("ord-leaf-b2", "^1.0.0")],
                &delays,
            )
            .await;
            for leaf in ["ord-leaf-a1", "ord-leaf-a2", "ord-leaf-b1", "ord-leaf-b2"] {
                mount_with_delay(&server, leaf, &[], &delays).await;
            }

            let client = client_direct_to(&server);
            let shared_cache: SharedCache = Arc::new(DashMap::new());
            let notify_map: NotifyMap = Arc::new(DashMap::new());
            let (spec_tx, _spec_rx) = mpsc::channel(32);
            let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();

            let walker = BfsWalker::new(
                client,
                shared_cache.clone(),
                notify_map,
                make_walker_done(),
                spec_tx,
                roots_ready_tx,
                vec!["ord-root-a".into(), "ord-root-b".into()],
                RouteMode::Direct,
            );
            let summary = walker.run().await.expect("walker ok");
            let keys: std::collections::BTreeSet<String> =
                shared_cache.iter().map(|e| e.key().to_string()).collect();
            (keys, summary.manifests_fetched, summary.max_depth)
        };

        // Pass A: slow roots, fast leaves.
        let (keys_a, fetched_a, depth_a) = run_once(vec![
            ("ord-root-a", 120),
            ("ord-root-b", 120),
            ("ord-leaf-a1", 10),
            ("ord-leaf-a2", 10),
            ("ord-leaf-b1", 10),
            ("ord-leaf-b2", 10),
        ])
        .await;

        // Pass B: inverted — fast roots, slow leaves.
        let (keys_b, fetched_b, depth_b) = run_once(vec![
            ("ord-root-a", 10),
            ("ord-root-b", 10),
            ("ord-leaf-a1", 120),
            ("ord-leaf-a2", 120),
            ("ord-leaf-b1", 120),
            ("ord-leaf-b2", 120),
        ])
        .await;

        // Final cache state MUST be identical across the two runs.
        assert_eq!(
            keys_a, keys_b,
            "walker's final shared-cache keyset must not depend on per-manifest timing"
        );
        assert_eq!(
            fetched_a, fetched_b,
            "manifests_fetched must not depend on timing"
        );
        assert_eq!(depth_a, depth_b, "max_depth must not depend on timing");
        assert_eq!(keys_a.len(), 6, "all 6 packages must be in the cache");
    }

    /// §13 walker contract: discovery walks **only the semver-newest
    /// version's** deps. Older-version deps are not pre-fetched by
    /// the walker — they reach the shared cache via the §12
    /// `walker_done` broadcast + escape-hatch path on the (rare) call
    /// where PubGrub picks a non-newest version.
    ///
    /// This test pins both halves of the §13 contract on a fixture
    /// with two majors carrying disjoint dep names:
    ///
    ///   `multi-ver` v1.0.0 → `old-dep`
    ///   `multi-ver` v2.0.0 → `new-dep`
    ///
    /// Walker run alone (no resolver, no escape-hatch consumer):
    /// `new-dep` MUST be cached, `old-dep` MUST NOT — proving the
    /// walker stays disciplined on newest-only and doesn't regress
    /// to the §11 full-union shape that turned a 60-dep `express`
    /// install into 7,146 manifests / 31.8 s walker wall-clock.
    ///
    /// Coverage of the older-version pick at the resolver level is
    /// covered by [`walker_done_broadcast_wakes_sleepers_for_unfetched_keys`]
    /// (provider-side) and the express integration bench (end-to-end:
    /// `cache_wait_walker_done_shortcuts > 0` while wall-clock <1 s).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_expands_only_newest_version_deps() {
        let server = MockServer::start().await;
        let multi_ver_body = serde_json::json!({
            "name": "multi-ver",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": dist_with_deps("multi-ver", "1.0.0", &[("old-dep", "^1.0.0")]),
                "2.0.0": dist_with_deps("multi-ver", "2.0.0", &[("new-dep", "^1.0.0")]),
            },
            "time": {
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "2.0.0": "2025-01-01T00:00:00.000Z"
            }
        });
        mount(&server, "multi-ver", multi_ver_body).await;
        mount(&server, "old-dep", metadata_json("old-dep", &[])).await;
        mount(&server, "new-dep", metadata_json("new-dep", &[])).await;

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let (spec_tx, _spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["multi-ver".into()],
            RouteMode::Direct,
        );
        walker.run().await.expect("walker succeeds");

        assert!(
            shared_cache.contains_key(&CanonicalKey::npm("new-dep")),
            "walker must fetch the newest version's deps"
        );
        assert!(
            !shared_cache.contains_key(&CanonicalKey::npm("old-dep")),
            "walker must NOT pre-fetch older versions' deps — \
             over-fetching them caused the §11 full-union 7,146-manifest \
             explosion. PubGrub's older-version pick is covered cheaply \
             by the §12 walker_done broadcast + escape-hatch path."
        );
    }

    /// §11 (post-ship-gate bench fix): walker must resolve
    /// `npm:<target>@<range>` alias declarations to the TARGET name
    /// before enqueueing. The local label isn't a registry identity
    /// and would 404; pre-fix, the walker enqueued the local label,
    /// emitted a debug-level fetch failure, and the aliased target
    /// was silently missing from the shared cache.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_resolves_npm_aliases_to_target_name() {
        let server = MockServer::start().await;
        // Root declares `strip-ansi-cjs` as an alias for `strip-ansi`.
        // Walker must fetch `strip-ansi`, not `strip-ansi-cjs`.
        mount(
            &server,
            "alias-root",
            metadata_json("alias-root", &[("strip-ansi-cjs", "npm:strip-ansi@^6.0.1")]),
        )
        .await;
        mount(&server, "strip-ansi", metadata_json("strip-ansi", &[])).await;

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let (spec_tx, _spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
            make_walker_done(),
            spec_tx,
            roots_ready_tx,
            vec!["alias-root".into()],
            RouteMode::Direct,
        );
        walker.run().await.expect("walker succeeds");

        assert!(
            shared_cache.contains_key(&CanonicalKey::npm("strip-ansi")),
            "walker must fetch the alias target, not the local label"
        );
        assert!(
            !shared_cache.contains_key(&CanonicalKey::npm("strip-ansi-cjs")),
            "walker must not insert a cache entry under the local alias label"
        );
    }

    /// Regression test for the wait-loop shutdown handshake (preplan
    /// §5.1 fix). Reproduces the original symptom — a 60-dep `express`
    /// install spending 30s of pure wall-clock in 6 × 5s wait-loop
    /// timeouts because the walker terminated without inserting keys
    /// PubGrub later asked for, and the wait-loop had no way to learn
    /// the walker had given up.
    ///
    /// Setup: walker fetches `present-pkg` only. A pre-installed
    /// per-canonical Notify entry stands in for a sleeper subscribed to
    /// `missing-pkg` (which the walker never enqueues). After
    /// `walker.run()` returns:
    ///
    /// - `walker_done` MUST be `true` (broadcast actually fired).
    /// - The Notify entry for `missing-pkg` MUST have received
    ///   `notify_waiters()` so a real sleeper would have woken — the
    ///   provider's wait-loop in [`super::ensure_cached`] would then
    ///   re-check the cache (still miss), observe the flag, and break
    ///   to its escape-hatch fetch in microseconds.
    ///
    /// We assert "received notify" by registering a `Notified` BEFORE
    /// the walker runs and `try_wait`-style polling it after. Tokio's
    /// `Notify` only stores wakeups for currently-pinned `Notified`
    /// futures (via `notify_waiters()`), which is precisely the
    /// invariant the wait-loop's `Notified::enable()` upholds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn walker_done_broadcast_wakes_sleepers_for_unfetched_keys() {
        let server = MockServer::start().await;
        mount(&server, "present-pkg", metadata_json("present-pkg", &[])).await;
        // Note: NO mock for `missing-pkg`. The walker isn't asked to
        // fetch it; the Notify is pre-registered to simulate a
        // resolver-side sleeper.

        let client = client_direct_to(&server);
        let shared_cache: SharedCache = Arc::new(DashMap::new());
        let notify_map: NotifyMap = Arc::new(DashMap::new());
        let walker_done: WalkerDone = Arc::new(AtomicBool::new(false));

        // Pre-register a Notify for `missing-pkg`, mirroring what
        // `ensure_cached` does when it enters the wait-loop on a miss.
        let missing_key = CanonicalKey::npm("missing-pkg");
        let missing_notify = Arc::new(tokio::sync::Notify::new());
        notify_map.insert(missing_key.clone(), missing_notify.clone());

        // Pin a Notified future BEFORE the walker runs. `enable()`
        // commits the subscription so any later `notify_waiters()` on
        // this Notify wakes us, even if we never re-poll until after.
        let mut sleeper = Box::pin(missing_notify.notified());
        sleeper.as_mut().enable();

        let (spec_tx, _spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, _roots_ready_rx) = oneshot::channel();
        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map.clone(),
            walker_done.clone(),
            spec_tx,
            roots_ready_tx,
            vec!["present-pkg".into()],
            RouteMode::Direct,
        );
        walker.run().await.expect("walker succeeds");

        // Invariant 1: walker flipped the flag to `true`.
        assert!(
            walker_done.load(Ordering::Acquire),
            "walker.run() must store walker_done = true at exit so the \
             provider wait-loop can short-circuit on missed keys"
        );

        // Invariant 2: the missing-pkg Notify received notify_waiters()
        // even though the walker never inserted that key. The walker
        // has already returned, so the broadcast must already be
        // pending on our enabled `Notified`. Awaiting under a tiny
        // timeout proves it: a healthy broadcast wakes us in
        // microseconds; a missing broadcast hangs the future and the
        // timeout fires.
        tokio::time::timeout(std::time::Duration::from_millis(100), sleeper)
            .await
            .expect(
                "walker exit must broadcast notify_waiters() to every \
                 notify_map entry — without this, a wait-loop sleeper \
                 on a key the walker decided not to fetch burns the \
                 full fetch_wait_timeout (the express-install 30s stall \
                 symptom).",
            );
    }
}
