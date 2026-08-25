//! Criterion benchmarks for the greedy dependency resolver.
//!
//! ## What this measures
//!
//! The resolver's CPU-only work: HashMap operations (inflight/parked/resolved),
//! find_best_version scans, process_edge dispatch. Network is eliminated by
//! pre-populating SharedCache with all packages before each benchmark group
//! starts (ensure_manifest always fast-paths on the first cache check).
//!
//! ## How to run
//!
//!   cargo bench -p lpm-resolver
//!   # HTML report: target/criterion/greedy_resolver/report/index.html
//!
//! ## Corpus sizes
//!
//!   n=50   — smoke (fast, ~1 ms per iter)
//!   n=266  — fixture-large parity (21 direct → ~266 transitive, matches bench/fixture-large)
//!   n=500  — resolver stress (more HashMap pressure, clearer hasher signal)
//!   n=1000 — upper bound (rare in practice; isolates O(n) growth curve)
//!
//! ## Graph shape
//!
//! Each package has N_VERSIONS versions (descending). The highest version
//! depends on up to 3 packages with lower indices, creating a diamond-heavy
//! graph with realistic reuse semantics. Lower versions have no deps
//! (so find_best_version always picks the top version immediately).
//!
//! ## Baseline workflow
//!
//! 1. Run once on main to establish baseline: save output to bench/perf-results/resolver-baseline.txt
//! 2. Apply optimization (e.g., ahash swap in greedy.rs)
//! 3. Run again: criterion compares vs baseline automatically (via saved .json in target/criterion/)
//! 4. Report: "greedy_resolver/packages/266  time: [X ms Y ms Z ms]  change: [-8.3% -7.1% -5.9%]"

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dashmap::DashMap;
use lpm_registry::{NpmrcConfig, RegistryClient, RouteMode, RouteTable};
use lpm_resolver::{
    CachedDistInfo, CachedPackageInfo, CanonicalKey, ManifestDependency, ManifestVersion,
    NotifyMap, NpmVersion, OverrideSet, SharedCache, StreamingBfsMetrics, WalkerDone,
    resolve_with_shared_cache,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Number of available versions per synthetic package.
///
/// Higher → more work in find_best_version (reverse-scan until satisfying match).
/// 8 is realistic: popular packages (lodash, zod, react) often have 50-200 published
/// versions but the resolver only needs to scan until it finds the best-matching one
/// for a `^major.0.0` range — typically 1-3 steps. 8 gives measurable scan work
/// without over-stressing version storage.
const N_VERSIONS: u64 = 8;

/// Build a synthetic package graph of `n` packages and return the pre-populated
/// SharedCache and a root-level dependency map.
///
/// Cache invariant: every package name that can appear as a dep target is present.
/// ensure_manifest will always fast-path on the first `shared_cache.get()` check,
/// so the bench measures pure resolver algorithm, not I/O.
fn make_graph(n: usize) -> (SharedCache, HashMap<String, String>) {
    let cache: SharedCache = Arc::new(DashMap::with_capacity(n));

    for i in 0..n {
        let name = format!("pkg-{i}");
        let canonical = CanonicalKey::Npm { name };

        // Versions descending: N_VERSIONS.0.0 → 1.0.0 (resolver picks highest-first)
        let manifests = (1..=N_VERSIONS)
            .rev()
            .map(|major| ManifestVersion {
                version: NpmVersion::new(major, 0, 0),
                dependencies: if major == N_VERSIONS {
                    // Highest version depends on up to 3 packages with lower indices.
                    // Creates diamond deps: pkg-10 and pkg-11 both depend on pkg-8,
                    // which the resolver resolves once and reuses (realistic graph pressure).
                    (i.saturating_sub(3)..i)
                        .map(|j| ManifestDependency {
                            name: format!("pkg-{j}"),
                            range: format!("^{N_VERSIONS}.0.0"),
                            alias: None,
                            optional: false,
                            bundled: false,
                        })
                        .collect()
                } else {
                    Vec::new()
                },
                peer_dependencies: Vec::new(),
                node_engine: None,
                platform: None,
                dist: CachedDistInfo::default(),
            })
            .collect();

        let info = CachedPackageInfo::from_manifest_versions(
            None,
            false,
            true,
            HashSet::new(),
            HashSet::new(),
            true,
            None,
            manifests,
        );

        cache.insert(canonical, Arc::new(info));
    }

    // Root depends on the last `direct` packages at `^{N_VERSIONS}.0.0`.
    // Capped at 20 to match fixture-large's 21-direct-dep shape.
    let direct = n.min(20);
    let root_deps: HashMap<String, String> = (n.saturating_sub(direct)..n)
        .map(|i| (format!("pkg-{i}"), format!("^{N_VERSIONS}.0.0")))
        .collect();

    (cache, root_deps)
}

fn bench_greedy_resolver(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Built once — never called in the bench (all packages pre-cached).
    // RegistryClient::new() touches ~/.lpm/cache/metadata/ for fs setup;
    // that happens once here, not per iteration.
    let client = Arc::new(RegistryClient::new());

    let route_table = RouteTable::new(RouteMode::Direct, NpmrcConfig::default())
        .expect("RouteTable::new should not fail with default NpmrcConfig");

    // Empty override set — no lpm.overrides in the synthetic fixture.
    let overrides = OverrideSet::empty();

    // walker_done=true: ensure_manifest fast-path returns immediately on cache hit
    // without entering the notify wait-loop (which would need a real walker).
    let walker_done: WalkerDone = Arc::new(AtomicBool::new(true));

    // fetch_wait_timeout=ZERO: belt-and-suspenders with walker_done=true.
    // Even if a cache miss somehow occurs, the wait loop is skipped and the
    // bench fails fast (no silent 30s hang from a stray network call).
    let fetch_wait_timeout = Duration::ZERO;

    let metrics = StreamingBfsMetrics::new();

    let mut group = c.benchmark_group("greedy_resolver");
    group.sample_size(50); // 50 samples → stable median + tight CI

    for n in [50usize, 266, 500, 1000] {
        let (shared_cache, root_deps) = make_graph(n);
        // Fresh notify_map per corpus size — not shared across iterations
        // (resolver doesn't insert into it when cache always hits, but
        // keeping it size-matched to the corpus avoids misleading DashMap
        // resize amortisation in the first few samples).
        let notify_map: NotifyMap = Arc::new(DashMap::with_capacity(n));

        group.bench_with_input(BenchmarkId::new("packages", n), &n, |b, _| {
            b.iter(|| {
                // block_on is zero-overhead here: the resolver's async
                // machinery (tokio::select!, Notify::notified()) is never
                // reached because walker_done=true + all packages cached.
                // The future resolves synchronously on the first poll.
                rt.block_on(resolve_with_shared_cache(
                    client.clone(),
                    root_deps.clone(),
                    overrides.clone(),
                    shared_cache.clone(),
                    notify_map.clone(),
                    walker_done.clone(),
                    fetch_wait_timeout,
                    route_table.clone(),
                    metrics.clone(),
                    false, // auto_install_peers
                ))
                .expect("synthetic graph resolution must not fail")
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_greedy_resolver);
criterion_main!(benches);
