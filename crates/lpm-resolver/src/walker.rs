//! Phase 49 client-side streaming BFS walker.
//!
//! The walker discovers transitive dependencies breadth-first from a root
//! set, fetches metadata for each canonical package name, populates the
//! shared cache (and per-canonical `Notify` waiters), and emits
//! `(name, PackageMetadata)` frames on the speculation channel the
//! existing dispatcher (`run_deep_batch_with_speculation` in
//! `lpm-cli/src/commands/install.rs`) consumes. The walker thus
//! replaces today's `batch_metadata_deep_streaming` as the producer of
//! metadata frames, keeping the dispatcher untouched (preplan §5.5).
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
use crate::provider::{NotifyMap, SharedCache, parse_metadata_to_cache_info};
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

            // Skip names already in the shared cache (walker may share
            // state with a prior pass, or the caller pre-seeded roots).
            let (mut npm_names, mut lpm_names): (Vec<String>, Vec<String>) =
                (Vec::new(), Vec::new());
            for name in current_level.drain(..) {
                let key = CanonicalKey::from_dep_name(&name);
                if self.shared_cache.contains_key(&key) {
                    summary.cache_hits += 1;
                    // Still propagate roots_ready if this was a root.
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
            let mut next_level: Vec<String> = Vec::new();
            for (name, res) in npm_results.into_iter().chain(lpm_results) {
                match res {
                    Ok(meta) => {
                        let is_npm = !name.starts_with("@lpm.dev/");
                        self.commit_manifest(
                            &name,
                            &meta,
                            is_npm,
                            &root_keys,
                            &mut roots_inserted,
                            &mut summary,
                        )
                        .await;
                        expand_deps_into(&meta, &mut seen, &mut next_level);
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
        // today's `batch_metadata_deep_streaming` termination contract.
        drop(self.spec_tx);

        // Roots-ready is never held past the end: if the walker exits
        // without all roots fetched (e.g. they all 404'd), fire the
        // signal anyway so the caller doesn't deadlock awaiting it.
        // The resolver will then either find what it needs in the
        // cache or hit its escape-hatch path.
        if let Some(tx) = self.roots_ready_tx.take() {
            let _ = tx.send(());
        }

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
    ) {
        let key = CanonicalKey::from_dep_name(name);

        // (1) Insert into shared cache.
        let info = parse_metadata_to_cache_info(meta, is_npm);
        self.shared_cache.insert(key.clone(), info);

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

/// Expand a landed manifest's deps into the next BFS level's name list.
///
/// Discovery picks **the `dist-tags.latest` version**'s production deps,
/// falling back to the highest version key if `latest` is absent. This
/// mirrors the dispatcher's `pick_speculative_version` shape — we walk
/// the version the resolver is most likely to pick. Ranges other than
/// `^latest` may cause mis-speculation; the provider's escape-hatch
/// handles the miss. See preplan §5.5 / §12 (post-49 walker-dispatcher
/// unification note).
fn expand_deps_into(
    meta: &PackageMetadata,
    seen: &mut HashSet<CanonicalKey>,
    next_level: &mut Vec<String>,
) {
    let Some(version_key) = meta
        .dist_tags
        .get("latest")
        .cloned()
        .or_else(|| meta.versions.keys().next().cloned())
    else {
        return;
    };
    let Some(vm) = meta.versions.get(&version_key) else {
        return;
    };
    for dep_name in vm.dependencies.keys() {
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
        let tmp = tempfile::tempdir().expect("tmp");
        // cache_dir is set to a temp path via a private setter in the
        // registry crate's test harness; for walker tests we rely on
        // `get_npm_metadata_direct`'s Tier-1 read returning None when
        // no cache has been pre-seeded, which is the default behavior
        // of RegistryClient::new() (`cache_dir: None`).
        let _ = tmp; // keep tempdir alive
        Arc::new(
            RegistryClient::new()
                .with_base_url("http://127.0.0.1:1") // unused in direct mode
                .with_npm_registry_url(npm_server.uri()),
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
        assert_eq!(shared_cache.len(), 4, "cache should hold 4 manifests");
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
}
