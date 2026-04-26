//! Phase 53 W1 — greedy multi-version resolver, bun-recipe port.
//!
//! Replaces PubGrub-with-split-retry with a greedy enqueue + first-match
//! version pick that doubles as the fetch dispatcher. Mirrors bun's
//! `enqueueDependencyWithMain` shape (`src/install/PackageManagerEnqueue.zig`
//! + `runTasks.zig::flushDependencyQueue`).
//!
//! ## W1 scope (this commit)
//!
//! - **Single-version-per-canonical** as a starting point. When two parents
//!   need different versions, the first one wins. Multi-version (each
//!   `(canonical, version)` is its own node) lands in W2; the data
//!   structures here already support it (see [`ResolvedNodeKey`]).
//! - **Required + optional deps only.** Peer deps are recorded but not
//!   eagerly installed; the existing post-resolve [`crate::check_unmet_peers`]
//!   pass continues to surface peer warnings. W3 will add bun's "queue peer
//!   edge, drain after main pass" semantics.
//! - **Phase 32 P5 path-selector overrides** are surfaced through
//!   `OverrideSet::split_targets` but NOT applied at version-pick time.
//!   W4 wires that.
//! - **Phase 40 P2 npm-aliases** are passed through from the cache (the
//!   `aliases` map on each `CachedPackageInfo` is already populated by
//!   [`crate::provider::parse_metadata_to_cache_info`]) and surfaced in the
//!   resolved tree.
//!
//! ## Dispatch model
//!
//! The loop is single-threaded — bun's PackageManager event loop runs on
//! one thread, and parallelism comes from the I/O fan-out (the BfsWalker's
//! 50-permit batch fetch + the existing 24-permit download pool). Each
//! iteration:
//!
//! 1. Pop an [`Edge`] off `task_queue`.
//! 2. Resolve its canonical's manifest via [`ensure_manifest`] — fast path
//!    is the [`crate::provider::SharedCache`] hit (the walker has been
//!    prefetching concurrently); slow path waits on the per-canonical
//!    [`tokio::sync::Notify`] up to `fetch_wait_timeout`, then falls
//!    through to a direct registry fetch.
//! 3. Pick a version with [`find_best_version`] (reverse-iterate sorted
//!    versions; first satisfying match wins — matches bun's `npm.zig:
//!    1808-1819`).
//! 4. Either reuse an existing node for `canonical` (W1's single-version
//!    rule) or allocate a new one and enqueue ITS declared deps as fresh
//!    edges.
//! 5. Repeat until `task_queue` is empty.
//!
//! No backtracking. No split-retry. The cost model is O(edges × log
//! versions) — measured at ~600-1000 `find_best_version` calls per cold
//! install on `bench/fixture-large`, each ~µs.

use crate::npm_version::NpmVersion;
use crate::overrides::OverrideSet;
use crate::package::{CanonicalKey, ResolverPackage};
use crate::provider::{
    CachedPackageInfo, NotifyMap, SharedCache, StreamingBfsMetrics, WalkerDone,
    parse_metadata_to_cache_info,
};
use crate::ranges::NpmRange;
use crate::resolve::{ResolveError, ResolveResult, ResolvedPackage, StageTiming};
use lpm_registry::{RegistryClient, RouteMode, UpstreamRoute};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Internal node identity used while the resolver runs. Maps to a
/// final [`ResolvedPackage`] at the end of the pass. W1 collapses all
/// nodes for one canonical into a single id; W2 will key by
/// `(canonical, version)` to enable multi-version naturally.
type NodeId = u32;

/// Logical key for the dedupe map of resolved nodes.
///
/// W1: just `CanonicalKey` — first version wins per canonical.
/// W2 will swap this to `(CanonicalKey, NpmVersion)` so the same
/// canonical can have multiple resolved versions in the same install.
type ResolvedNodeKey = CanonicalKey;

/// One unresolved edge: parent N needs `name @ range` with `behavior`.
///
/// Mirrors bun's `(dependency_id, version_range)` queue entry pattern
/// (`PackageManagerEnqueue.zig:830-838`). The edge carries enough
/// context for [`process_edge`] to look up the right manifest, pick a
/// version, and link parent → child in the resolved tree.
#[derive(Debug, Clone)]
struct Edge {
    /// Parent node in the resolved tree. The root project is the
    /// only node without a parent — it's seeded explicitly before
    /// the loop starts.
    parent: NodeId,
    /// Local name in the parent's `dependencies` map (alias-aware).
    /// Phase 40 P2: when this differs from `canonical`, the edge was
    /// declared via `npm:<target>@<range>` and `local_name → target`
    /// is recorded on the parent's resolved node so the linker can
    /// build `node_modules/<local>/` → store entry for `<target>`.
    local_name: String,
    /// Canonical (registry-side) name of the dependency. Equal to
    /// `local_name` for non-aliased edges; equal to the alias target
    /// for aliased edges.
    canonical: CanonicalKey,
    /// Semver range to satisfy.
    range: NpmRange,
    /// What kind of dep this is — affects error semantics on miss.
    behavior: DepBehavior,
}

/// Bitfield matching bun's `Dependency.Behavior` (`dependency.zig:35-37`).
/// W1 collapses dev under required at the root level (only root
/// edges are ever marked dev — transitive `devDependencies` are not
/// followed by npm clients per spec). The `required` field is
/// asserted at edge-creation time and read in W3 when error-on-miss
/// semantics widen beyond the current "all-non-optional-non-peer
/// edges error on miss" rule.
#[derive(Debug, Clone, Copy, Default)]
struct DepBehavior {
    #[allow(dead_code)] // read in W3 when peer/required asymmetry widens
    required: bool,
    peer: bool,
    optional: bool,
}

/// Per-canonical manifest state. Mirrors bun's combined
/// `network_dedupe_map` and `task_queue` HashMap pair. W1 uses the
/// per-canonical [`Notify`] from [`NotifyMap`] (already plumbed for
/// Phase 49's wait-loop) instead of a custom `Pending(Vec<Edge>)`
/// state, so this alias just names the per-canonical body type for
/// callers and W5.
#[allow(dead_code)] // referenced by W5's BfsWalker integration
type ManifestState = Arc<CachedPackageInfo>;

/// Entry point — same signature shape as
/// [`crate::resolve::resolve_with_shared_cache`] so the dispatch in
/// `resolve.rs` can swap implementations behind a feature flag.
#[allow(clippy::too_many_arguments)] // mirrors resolve_with_shared_cache for drop-in dispatch
pub async fn resolve_greedy(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    _overrides: OverrideSet,
    shared_cache: SharedCache,
    notify_map: NotifyMap,
    walker_done: WalkerDone,
    fetch_wait_timeout: Duration,
    route_mode: RouteMode,
    metrics: StreamingBfsMetrics,
) -> Result<ResolveResult, ResolveError> {
    let _span = tracing::debug_span!("resolve_greedy", n_deps = dependencies.len()).entered();
    let pass_start = Instant::now();

    // Phase 49 §6 reset — see resolve_with_shared_cache for the
    // accumulator contract. We measure greedy work in `pubgrub_ms` for
    // schema parity even though no PubGrub call happens here; the field
    // semantically means "resolver wall-clock".
    crate::profile::reset_all();
    lpm_registry::timing::reset();

    let mut state = ResolveState::new(dependencies);
    state.seed_root_edges()?;

    while let Some(edge) = state.task_queue.pop_front() {
        let info = ensure_manifest(
            &edge.canonical,
            client.clone(),
            route_mode,
            &shared_cache,
            &notify_map,
            &walker_done,
            fetch_wait_timeout,
            &metrics,
        )
        .await?;
        process_edge(&edge, &info, &mut state)?;
    }

    let resolver_ms = pass_start.elapsed().as_millis() as u64;

    // Build the public result. Cache the in-memory CachedPackageInfo from
    // shared_cache for the downstream `check_unmet_peers` pass and the
    // install pipeline's tarball-url lookup (matching the format_solution
    // contract in resolve.rs).
    let cache: HashMap<CanonicalKey, CachedPackageInfo> = shared_cache
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect();

    let packages = state.into_resolved_packages(&cache);

    let snap = lpm_registry::timing::snapshot();
    Ok(ResolveResult {
        packages,
        cache,
        // Phase 32 P5 overrides: not yet applied in W1 (see module docs).
        applied_overrides: Vec::new(),
        platform_skipped: state_platform_skipped(),
        // Phase 40 P2 root aliases: walker / metadata-parser already
        // populates aliases on each `CachedPackageInfo`; the per-package
        // alias edges flow through `into_resolved_packages`. Root aliases
        // (the resolved-result's `root_aliases` field) require detecting
        // `npm:<target>@<range>` in the *root* `package.json`. W4 wires
        // that. For now: empty map — the bench/project fixture has no
        // root aliases.
        root_aliases: HashMap::new(),
        stage_timing: StageTiming {
            followup_rpc_ms: snap.metadata_rpc.as_millis() as u64,
            followup_rpc_count: snap.metadata_rpc_count,
            parse_ndjson_ms: snap.parse_ndjson.as_millis() as u64,
            pubgrub_ms: resolver_ms,
        },
    })
}

/// Carrier for the per-pass mutable state. Keeps the dispatch loop
/// readable by bundling the four coupled collections into one place.
struct ResolveState {
    /// Root deps from `package.json`. Stored so we can reconstruct
    /// each root edge's range when seeding.
    root_deps: HashMap<String, String>,
    /// Edge work queue. Drained by the main loop.
    task_queue: VecDeque<Edge>,
    /// Resolved nodes by their lookup key. W1 keys by canonical alone
    /// (single-version); W2 will switch to (canonical, version).
    resolved: HashMap<ResolvedNodeKey, NodeId>,
    /// Resolved nodes in declaration order. `nodes[i].id == i`.
    nodes: Vec<ResolvedNodeBuilder>,
    /// Set of canonicals for which we've already enqueued children.
    /// Prevents re-enqueueing the same package's deps when it's
    /// referenced by a second parent (W1 single-version: the version
    /// won't change, so its deps don't change either).
    children_enqueued: HashSet<CanonicalKey>,
}

/// In-flight resolved node — accumulated during the loop, finalized
/// at `into_resolved_packages` time.
#[derive(Debug)]
struct ResolvedNodeBuilder {
    canonical: CanonicalKey,
    version: NpmVersion,
    /// Edges going OUT of this node: (local_name, child_node_id).
    children: Vec<(String, NodeId)>,
}

impl ResolveState {
    fn new(root_deps: HashMap<String, String>) -> Self {
        ResolveState {
            root_deps,
            task_queue: VecDeque::with_capacity(256),
            resolved: HashMap::with_capacity(512),
            nodes: Vec::with_capacity(512),
            children_enqueued: HashSet::with_capacity(512),
        }
    }

    /// Seed the queue with one Edge per root dependency. The pseudo-node
    /// with id=0 represents the project root; its children are tracked
    /// in the resolved-tree edges but it has no version of its own and
    /// is filtered out at `into_resolved_packages` time, matching
    /// PubGrub's `format_solution` (which filters `pkg.is_root()`).
    fn seed_root_edges(&mut self) -> Result<(), ResolveError> {
        // Insert the root pseudo-node so child edges have a parent id.
        // It carries a sentinel canonical (`Root`) and a placeholder
        // version. Filtered out at `into_resolved_packages`.
        self.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::Root,
            version: NpmVersion::new(0, 0, 0),
            children: Vec::new(),
        });
        self.resolved.insert(CanonicalKey::Root, 0);
        // Phase 40 P2 alias rewriting on root edges happens in W4;
        // here we just take the package.json declaration verbatim.
        let mut entries: Vec<_> = self.root_deps.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (name, range_str) in entries {
            let canonical = CanonicalKey::from_dep_name(name);
            let range = NpmRange::parse(range_str).map_err(|e| {
                ResolveError::Internal(format!("failed to parse range for root dep {name}: {e}"))
            })?;
            self.task_queue.push_back(Edge {
                parent: 0,
                local_name: name.clone(),
                canonical,
                range,
                behavior: DepBehavior {
                    required: true,
                    peer: false,
                    optional: false,
                },
            });
        }
        Ok(())
    }

    /// Convert the in-flight builders into the public
    /// `Vec<ResolvedPackage>`. Mirrors `resolve.rs::format_solution`.
    fn into_resolved_packages(
        self,
        cache: &HashMap<CanonicalKey, CachedPackageInfo>,
    ) -> Vec<ResolvedPackage> {
        // Build node-id → version-string lookup so child edges can
        // be resolved to the child's selected version regardless of
        // aliasing (alias rewriting already happened at edge-creation
        // time, so children[i].1 is always the correct node id).
        let id_to_version: Vec<String> = self.nodes.iter().map(|n| n.version.to_string()).collect();

        let mut out: Vec<ResolvedPackage> = self
            .nodes
            .into_iter()
            .enumerate()
            .filter(|(_, n)| !matches!(n.canonical, CanonicalKey::Root))
            .map(|(_, n)| {
                let pkg = canonical_to_resolver_package(&n.canonical);
                let ver_str = n.version.to_string();

                let cached_aliases: HashMap<String, String> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.aliases.get(&ver_str))
                    .cloned()
                    .unwrap_or_default();

                let dependencies: Vec<(String, String)> = n
                    .children
                    .iter()
                    .map(|(local, child_id)| {
                        let child_ver = id_to_version[*child_id as usize].clone();
                        (local.clone(), child_ver)
                    })
                    .collect();

                let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
                let aliases: HashMap<String, String> = cached_aliases
                    .iter()
                    .filter(|(local, _)| alive_locals.contains(local))
                    .map(|(l, t)| (l.clone(), t.clone()))
                    .collect();

                let (tarball_url, integrity) = cache
                    .get(&n.canonical)
                    .and_then(|info| info.dist.get(&ver_str))
                    .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                    .unwrap_or_default();

                ResolvedPackage {
                    package: pkg,
                    version: n.version,
                    dependencies,
                    aliases,
                    tarball_url,
                    integrity,
                }
            })
            .collect();

        // Match `format_solution`'s deterministic order so lockfile
        // serialization is stable regardless of resolution order.
        out.sort_by(|a, b| a.package.to_string().cmp(&b.package.to_string()));
        out
    }
}

/// Convert a `CanonicalKey` back to a `ResolverPackage` for the
/// public output. W1 always emits non-split (`context: None`) packages
/// — multi-version in W2 will start emitting with context for the
/// secondary copy of each duplicated canonical.
fn canonical_to_resolver_package(key: &CanonicalKey) -> ResolverPackage {
    match key {
        CanonicalKey::Root => ResolverPackage::Root,
        CanonicalKey::Lpm { owner, name } => ResolverPackage::Lpm {
            owner: owner.clone(),
            name: name.clone(),
            context: None,
        },
        CanonicalKey::Npm { name } => ResolverPackage::Npm {
            name: name.clone(),
            context: None,
        },
    }
}

/// W1: `state.platform_skipped` isn't tracked yet (greedy doesn't have a
/// `RefCell<usize>` like the PubGrub provider; the count gets surfaced
/// when we wire optional platform filtering in a follow-up). Always
/// returns 0 for now; install.rs's JSON output reports
/// `timing.resolve.platform_skipped: 0` for greedy until then. Bench
/// schema parity is unaffected.
fn state_platform_skipped() -> usize {
    0
}

/// Process one edge: pick a version, link parent → child, enqueue the
/// child's own deps if this is the first time we've seen the canonical.
fn process_edge(
    edge: &Edge,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    let chosen = find_best_version(info, &edge.range);
    let Some(version) = chosen else {
        return handle_no_version(edge, info);
    };

    // W1 single-version: dedupe by canonical alone. If we've already
    // resolved this canonical, reuse — even if the existing version
    // doesn't satisfy the current edge's range. This matches PubGrub
    // flat-resolution behavior and lets W1 reproduce identical trees on
    // no-conflict fixtures. W2 swaps the dedupe key to (canonical,
    // version) so two different ranges naturally produce two nodes.
    let child_id = if let Some(&existing) = state.resolved.get(&edge.canonical) {
        existing
    } else {
        let new_id = state.nodes.len() as NodeId;
        state.nodes.push(ResolvedNodeBuilder {
            canonical: edge.canonical.clone(),
            version: version.clone(),
            children: Vec::new(),
        });
        state.resolved.insert(edge.canonical.clone(), new_id);
        new_id
    };

    // Record the parent → child edge on the parent's children list.
    state.nodes[edge.parent as usize]
        .children
        .push((edge.local_name.clone(), child_id));

    // First-time-seen canonical: enqueue its own deps as new edges.
    if !state.children_enqueued.contains(&edge.canonical) {
        state.children_enqueued.insert(edge.canonical.clone());
        enqueue_child_deps(child_id, &edge.canonical, &version, info, state)?;
    }

    Ok(())
}

fn handle_no_version(edge: &Edge, info: &CachedPackageInfo) -> Result<(), ResolveError> {
    if edge.behavior.optional {
        // Optional dep with no satisfying version: skip silently. Matches
        // bun's behavior (`PackageManagerEnqueue.zig:77-78` warning path)
        // minus the warning itself — W3 will wire the warning emission.
        tracing::debug!(
            "optional dep {} has no version satisfying {} (versions tried: {})",
            edge.canonical,
            edge.range,
            info.versions.len()
        );
        return Ok(());
    }
    if edge.behavior.peer {
        // Peer dep: not eagerly installed in W1; the post-resolve
        // `check_unmet_peers` pass will surface the warning if the
        // peer goes unresolved. W3 will wire the bun-style queue+drain.
        tracing::debug!(
            "peer dep {} (range {}) not eagerly installed in W1",
            edge.canonical,
            edge.range,
        );
        return Ok(());
    }
    Err(ResolveError::DependencyFetch {
        package: edge.canonical.to_string(),
        version: edge.range.to_string(),
        detail: format!(
            "no version satisfies range (versions available: {})",
            info.versions.len()
        ),
    })
}

/// Read `info.deps[version]`, parse each child's range, push edges. Aliases
/// are looked up in `info.aliases[version]` and rewritten to the target
/// canonical at edge-creation time so the dispatch loop only ever has
/// canonical keys to look up.
fn enqueue_child_deps(
    parent_id: NodeId,
    parent_canonical: &CanonicalKey,
    version: &NpmVersion,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    let ver_str = version.to_string();
    let Some(deps) = info.deps.get(&ver_str) else {
        return Ok(()); // version has no declared deps
    };
    let aliases = info.aliases.get(&ver_str);
    let optional_names = info.optional_dep_names.get(&ver_str);

    // Sort for deterministic edge ordering — keeps test diffs stable
    // and the resolved tree reproducible across runs.
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (local_name, range_str) in entries {
        let canonical = match aliases.and_then(|a| a.get(local_name)) {
            Some(target) => CanonicalKey::from_dep_name(target),
            None => CanonicalKey::from_dep_name(local_name),
        };

        let range = match NpmRange::parse(range_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "invalid range '{}' on {}@{} → {}: {e}",
                    range_str,
                    parent_canonical,
                    ver_str,
                    local_name,
                );
                continue;
            }
        };

        let optional = optional_names
            .map(|set| set.contains(local_name))
            .unwrap_or(false);

        state.task_queue.push_back(Edge {
            parent: parent_id,
            local_name: local_name.clone(),
            canonical,
            range,
            behavior: DepBehavior {
                required: !optional,
                peer: false,
                optional,
            },
        });
    }
    Ok(())
}

/// Greedy first-match version pick. Reverse-iterates `info.versions`
/// (sorted descending by semver in
/// [`crate::provider::parse_metadata_to_cache_info`]) and returns the
/// first version that satisfies the range. Mirrors bun's
/// `npm.zig:1808-1819`. O(n_versions); typically <100 versions per
/// popular package, so per-call cost is microseconds.
///
/// W1: no dist-tag fast path, no override application, no platform
/// filtering. Each lands in a follow-up commit (dist-tags rarely
/// matter on common semver inputs; overrides are W4; platform
/// filtering is straightforward but adds a `is_platform_compatible`
/// dependency from `provider`).
fn find_best_version(info: &CachedPackageInfo, range: &NpmRange) -> Option<NpmVersion> {
    info.versions.iter().find(|v| range.satisfies(v)).cloned()
}

/// Phase 49 wait-or-fetch: fast cache hit, then short-lived
/// per-canonical wait, then escape-hatch direct fetch. Mirrors
/// `provider.rs::ensure_cached` shape but yields an owned
/// `Arc<CachedPackageInfo>` instead of a `RefCell` borrow.
#[allow(clippy::too_many_arguments)] // mirrors provider::ensure_cached's plumbing surface
async fn ensure_manifest(
    canonical: &CanonicalKey,
    client: Arc<RegistryClient>,
    route_mode: RouteMode,
    shared_cache: &SharedCache,
    notify_map: &NotifyMap,
    walker_done: &WalkerDone,
    fetch_wait_timeout: Duration,
    metrics: &StreamingBfsMetrics,
) -> Result<Arc<CachedPackageInfo>, ResolveError> {
    // Fast path
    if let Some(entry) = shared_cache.get(canonical) {
        return Ok(Arc::new(entry.clone()));
    }

    // Wait-loop (only when walker is attached and timeout > 0).
    if !fetch_wait_timeout.is_zero() && !walker_done.load(Ordering::Acquire) {
        metrics_incr_cache_wait(metrics);
        let notify = notify_map
            .entry(canonical.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .value()
            .clone();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        // Re-check: walker may have inserted between the fast-path miss
        // and now.
        if let Some(entry) = shared_cache.get(canonical) {
            return Ok(Arc::new(entry.clone()));
        }
        // Walker may have flipped done — if so, fetch directly without
        // burning the timeout. Matches `provider.rs::ensure_cached`'s
        // walker_done short-circuit path.
        if !walker_done.load(Ordering::Acquire) {
            match tokio::time::timeout(fetch_wait_timeout, notified).await {
                Ok(()) => {
                    if let Some(entry) = shared_cache.get(canonical) {
                        return Ok(Arc::new(entry.clone()));
                    }
                }
                Err(_) => {
                    metrics_incr_timeout(metrics);
                }
            }
        }
    }

    // Escape hatch: direct fetch.
    metrics_incr_escape_hatch(metrics);
    let info = direct_fetch(&client, route_mode, canonical).await?;
    shared_cache.insert(canonical.clone(), info.clone());
    if let Some(n) = notify_map.get(canonical) {
        n.notify_waiters();
    }
    Ok(Arc::new(info))
}

async fn direct_fetch(
    client: &RegistryClient,
    route_mode: RouteMode,
    canonical: &CanonicalKey,
) -> Result<CachedPackageInfo, ResolveError> {
    match canonical {
        CanonicalKey::Root => Err(ResolveError::Internal(
            "direct_fetch called for root".to_string(),
        )),
        CanonicalKey::Lpm { owner, name } => {
            let pkg_name = lpm_common::PackageName::parse(&format!("@lpm.dev/{owner}.{name}"))
                .map_err(|e| ResolveError::Internal(e.to_string()))?;
            let metadata = client.get_package_metadata(&pkg_name).await.map_err(|e| {
                ResolveError::DependencyFetch {
                    package: canonical.to_string(),
                    version: "*".to_string(),
                    detail: e.to_string(),
                }
            })?;
            Ok(parse_metadata_to_cache_info(&metadata, false))
        }
        CanonicalKey::Npm { name } => {
            let route = route_mode.route_for_package(name);
            let metadata = match route {
                UpstreamRoute::LpmWorker => client.get_npm_package_metadata(name).await,
                UpstreamRoute::NpmDirect => client.get_npm_metadata_direct(name).await,
            }
            .map_err(|e| ResolveError::DependencyFetch {
                package: canonical.to_string(),
                version: "*".to_string(),
                detail: e.to_string(),
            })?;
            Ok(parse_metadata_to_cache_info(&metadata, true))
        }
    }
}

// Metrics helpers — wrap the `pub(crate)` increment methods on
// `StreamingBfsMetrics` so the call sites in `ensure_manifest` stay
// readable. Each is a one-line forwarder; kept private here.
fn metrics_incr_cache_wait(_m: &StreamingBfsMetrics) {
    // The fields on `StreamingBfsMetrics` are private to `provider`;
    // greedy uses the public counter readback at install.rs JSON time
    // and doesn't need to bump them here. Left as a no-op stub so we
    // can wire telemetry symmetrically with PubGrub once the metrics
    // surface is widened (W5: BfsWalker integration).
}
fn metrics_incr_timeout(_m: &StreamingBfsMetrics) {}
fn metrics_incr_escape_hatch(_m: &StreamingBfsMetrics) {}

// ── Unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CachedDistInfo, CachedPackageInfo};

    /// Build a minimal CachedPackageInfo for a synthesized npm package.
    /// `versions` are passed already in descending order to mirror
    /// `parse_metadata_to_cache_info`'s contract.
    fn mk_info(versions: &[&str], deps_of_latest: &[(&str, &str)]) -> CachedPackageInfo {
        let parsed: Vec<NpmVersion> = versions
            .iter()
            .map(|v| NpmVersion::parse(v).unwrap())
            .collect();
        let mut deps_map = HashMap::new();
        let mut latest_deps = HashMap::new();
        for (n, r) in deps_of_latest {
            latest_deps.insert(n.to_string(), r.to_string());
        }
        if let Some(latest) = versions.first() {
            deps_map.insert(latest.to_string(), latest_deps);
        }
        CachedPackageInfo {
            versions: parsed,
            deps: deps_map,
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: versions
                .iter()
                .map(|v| {
                    (
                        v.to_string(),
                        CachedDistInfo {
                            tarball_url: Some(format!("https://example.invalid/{}.tgz", v)),
                            integrity: Some(format!("sha512-fake-{}", v)),
                        },
                    )
                })
                .collect(),
            aliases: HashMap::new(),
        }
    }

    #[test]
    fn find_best_version_picks_newest_match() {
        let info = mk_info(&["4.17.21", "4.17.20", "3.10.1", "3.0.0"], &[]);
        let range = NpmRange::parse("^4.0.0").unwrap();
        assert_eq!(
            find_best_version(&info, &range).unwrap().to_string(),
            "4.17.21"
        );
    }

    #[test]
    fn find_best_version_returns_none_when_unsatisfied() {
        let info = mk_info(&["4.17.21", "3.10.1"], &[]);
        let range = NpmRange::parse("^5.0.0").unwrap();
        assert!(find_best_version(&info, &range).is_none());
    }

    #[test]
    fn find_best_version_handles_exact_pin() {
        let info = mk_info(&["4.17.21", "4.17.20", "3.10.1"], &[]);
        let range = NpmRange::parse("4.17.20").unwrap();
        assert_eq!(
            find_best_version(&info, &range).unwrap().to_string(),
            "4.17.20"
        );
    }

    #[test]
    fn seed_root_edges_orders_deterministically() {
        let mut deps = HashMap::new();
        deps.insert("zebra".to_string(), "^1.0.0".to_string());
        deps.insert("alpha".to_string(), "^1.0.0".to_string());
        deps.insert("middle".to_string(), "^1.0.0".to_string());
        let mut state = ResolveState::new(deps);
        state.seed_root_edges().unwrap();
        let order: Vec<&str> = state
            .task_queue
            .iter()
            .map(|e| e.local_name.as_str())
            .collect();
        assert_eq!(order, vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn seed_root_edges_seeds_root_node() {
        let mut deps = HashMap::new();
        deps.insert("only".to_string(), "^1.0.0".to_string());
        let mut state = ResolveState::new(deps);
        state.seed_root_edges().unwrap();
        assert_eq!(state.nodes.len(), 1);
        assert!(matches!(state.nodes[0].canonical, CanonicalKey::Root));
        assert_eq!(state.task_queue.len(), 1);
        assert_eq!(state.task_queue[0].parent, 0);
    }

    #[test]
    fn process_edge_dedupes_same_canonical() {
        // Two parents both wanting `lodash@^4` should produce one resolved
        // node, two parent→child edges. W1 single-version contract.
        let info = mk_info(&["4.17.21"], &[]);
        let mut deps = HashMap::new();
        deps.insert("lodash".to_string(), "^4.0.0".to_string());
        let mut state = ResolveState::new(deps);
        state.seed_root_edges().unwrap();

        // Add a second parent (simulate a transitive that also needs lodash)
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("react"),
            version: NpmVersion::parse("18.0.0").unwrap(),
            children: Vec::new(),
        });
        state.resolved.insert(CanonicalKey::npm("react"), 1);
        state.task_queue.push_back(Edge {
            parent: 1,
            local_name: "lodash".to_string(),
            canonical: CanonicalKey::npm("lodash"),
            range: NpmRange::parse("^4.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        });

        // Drain both edges
        while let Some(edge) = state.task_queue.pop_front() {
            process_edge(&edge, &info, &mut state).unwrap();
        }

        // One unique resolved node for lodash (count = root + react + lodash)
        assert_eq!(state.nodes.len(), 3);
        let lodash_id = state.resolved[&CanonicalKey::npm("lodash")];
        assert_eq!(lodash_id, 2);

        // Both root and react have an edge to lodash
        assert!(
            state.nodes[0]
                .children
                .iter()
                .any(|(_, id)| *id == lodash_id)
        );
        assert!(
            state.nodes[1]
                .children
                .iter()
                .any(|(_, id)| *id == lodash_id)
        );
    }

    #[test]
    fn handle_no_version_optional_skips() {
        let info = mk_info(&["1.0.0"], &[]);
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^99.0.0").unwrap(),
            behavior: DepBehavior {
                required: false,
                peer: false,
                optional: true,
            },
        };
        assert!(handle_no_version(&edge, &info).is_ok());
    }

    #[test]
    fn handle_no_version_required_errors() {
        let info = mk_info(&["1.0.0"], &[]);
        let edge = Edge {
            parent: 0,
            local_name: "x".to_string(),
            canonical: CanonicalKey::npm("x"),
            range: NpmRange::parse("^99.0.0").unwrap(),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        };
        assert!(matches!(
            handle_no_version(&edge, &info),
            Err(ResolveError::DependencyFetch { .. })
        ));
    }
}
