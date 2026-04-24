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
use crate::provider::{CachedPackageInfo, NotifyMap, SharedCache, parse_metadata_to_cache_info};
use lpm_registry::{PackageMetadata, RegistryClient, RouteMode, UpstreamRoute};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

/// Server-side deep walk cap in the Worker's old BFS endpoint; we
/// mirror it client-side to prevent runaway walks on malformed
/// manifests. Preplan §5.5.
const MAX_WALK_DEPTH: u32 = 16;

/// Default npm fan-out for [`RegistryClient::parallel_fetch_npm_manifests`].
/// Matches the preplan §5.5 ceiling (bumped from W4's 32). Callers can
/// override via [`BfsWalker::with_npm_fanout`].
pub const DEFAULT_NPM_FANOUT: usize = 50;

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
    spec_tx: mpsc::Sender<(String, PackageMetadata)>,
    roots_ready_tx: Option<oneshot::Sender<()>>,
    dep_names: Vec<String>,
    route_mode: RouteMode,
    npm_fanout: usize,
}

impl BfsWalker {
    pub fn new(
        client: Arc<RegistryClient>,
        shared_cache: SharedCache,
        notify_map: NotifyMap,
        spec_tx: mpsc::Sender<(String, PackageMetadata)>,
        roots_ready_tx: oneshot::Sender<()>,
        dep_names: Vec<String>,
        route_mode: RouteMode,
    ) -> Self {
        Self {
            client,
            shared_cache,
            notify_map,
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
    pub async fn run(mut self) -> Result<WalkerSummary, WalkerError> {
        // Capture the walker's own wall-clock. Measured INSIDE the
        // walker task so `summary.walker_wall_ms` reflects the exact
        // producer-window duration regardless of when the caller
        // eventually `.await`s the JoinHandle. Without this, the
        // downstream `streaming_batch_ms` reporter would measure
        // "drain call time − spawn time" and include any post-walker
        // fetch overlap — breaking the metadata-producer-window
        // contract.
        let run_start = Instant::now();
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
                    let (results, _stats) = client_npm
                        .parallel_fetch_npm_manifests(&npm_names, npm_fanout)
                        .await;
                    results
                }
            };
            let lpm_fut = async move {
                if lpm_names.is_empty() {
                    Vec::new()
                } else {
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
            let (npm_results, lpm_results) = tokio::join!(npm_fut, lpm_fut);

            // Merge. Each entry is `(name, Result<PackageMetadata, LpmError>)`.
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
        self.shared_cache.insert(key.clone(), info.clone());

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
/// Discovery picks the **semver-newest version** in `info.versions`
/// (which `parse_metadata_to_cache_info` keeps sorted newest-first and
/// prerelease-filtered for npm packages). Reading from the parsed info
/// rather than the raw `PackageMetadata` (a) lets the cache-hit path
/// and the fresh-fetch path share one dep-discovery primitive, and
/// (b) avoids the earlier bug where the raw-metadata fallback
/// (`versions.keys().next()`) was arbitrary `HashMap` iteration order
/// instead of a real semver max.
///
/// Walker's version pick does not consult the consumer's range — we
/// can't, multiple parents may have different ranges on the same dep.
/// The dispatcher's `pick_speculative_version` uses a range; the
/// walker's job is best-effort discovery, and mis-speculation is
/// handled by the provider's escape-hatch path.
fn expand_deps_from_info(
    info: &CachedPackageInfo,
    seen: &mut HashSet<CanonicalKey>,
    next_level: &mut Vec<String>,
) {
    // `info.versions` is sorted newest-first by the parser; take
    // version 0 as the discovery pick.
    let Some(newest) = info.versions.first() else {
        return;
    };
    let ver_str = newest.to_string();
    let Some(deps) = info.deps.get(&ver_str) else {
        return;
    };
    for dep_name in deps.keys() {
        let dep_key = CanonicalKey::from_dep_name(dep_name);
        if seen.insert(dep_key) {
            next_level.push(dep_name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        shared_cache.insert(CanonicalKey::npm("root-cached"), root_info);

        let (spec_tx, mut spec_rx) = mpsc::channel(16);
        let (roots_ready_tx, roots_ready_rx) = oneshot::channel();

        let walker = BfsWalker::new(
            client,
            shared_cache.clone(),
            notify_map,
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
