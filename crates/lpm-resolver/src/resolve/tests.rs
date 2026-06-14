use super::prelude::*;
use super::*;
use crate::provider::Platform;
use lpm_registry::{PackageMetadata, VersionMetadata};
use std::sync::OnceLock;
use tokio::sync::Mutex as TokioMutex;

/// Process-global env-mutation lock for tests in this module.
///
/// `resolve_with_shared_cache` defaults to greedy unless
/// `LPM_RESOLVER=pubgrub` is set. Tests that exercise PubGrub-arm-
/// specific features (split-retry, npm-alias range parsing) must
/// temporarily set the env var, which is process-global. Serialise
/// mutation across async tests.
///
/// Uses `tokio::sync::Mutex` (async-aware) because the resolver
/// tests `.await` while holding the guard — `std::sync::Mutex`
/// triggers clippy's `await_holding_lock` lint.
fn env_lock() -> &'static TokioMutex<()> {
    static LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| TokioMutex::new(()))
}

/// Pin the resolver to PubGrub for the duration of a test.
///
/// Snapshots `LPM_RESOLVER`, sets it to `"pubgrub"`, and restores
/// the prior value on drop. Caller MUST already hold `env_lock()`
/// — this guard does not acquire it because `set_var` is unsafe in
/// Rust 2024 and we want the lock-acquire to be visible at the
/// callsite.
struct PubgrubEnvGuard {
    prior: Option<std::ffi::OsString>,
}
impl PubgrubEnvGuard {
    fn new() -> Self {
        let prior = std::env::var_os("LPM_RESOLVER");
        // SAFETY: caller holds env_lock() — env-var mutation is
        // serialised across this module's tests.
        unsafe { std::env::set_var("LPM_RESOLVER", "pubgrub") };
        Self { prior }
    }
}
impl Drop for PubgrubEnvGuard {
    fn drop(&mut self) {
        // SAFETY: still inside the env_lock-protected section.
        unsafe {
            match &self.prior {
                Some(v) => std::env::set_var("LPM_RESOLVER", v),
                None => std::env::remove_var("LPM_RESOLVER"),
            }
        }
    }
}

/// Test-only adapter: converts a raw `HashMap<String, PackageMetadata>`
/// into a pre-seeded `SharedCache` and delegates to
/// `resolve_with_shared_cache`. Not exported — tests only.
async fn resolve_with_prefetch(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    prefetched: Option<HashMap<String, PackageMetadata>>,
) -> Result<ResolveResult, ResolveError> {
    use crate::provider::WalkerDone;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicBool;
    let shared_cache: SharedCache = Arc::new(DashMap::new());
    let notify_map: NotifyMap = Arc::new(DashMap::new());
    let walker_done: WalkerDone = Arc::new(AtomicBool::new(false));
    if let Some(batch) = prefetched {
        for (name, metadata) in batch {
            let key = CanonicalKey::from_dep_name(&name);
            let info = crate::provider::parse_metadata_to_cache_info(&metadata);
            shared_cache.insert(key, Arc::new(info));
        }
    }
    resolve_with_shared_cache(
        client,
        dependencies,
        overrides,
        shared_cache,
        notify_map,
        walker_done,
        Duration::ZERO,
        RouteTable::from_mode_only(RouteMode::Proxy),
        StreamingBfsMetrics::new(),
        true, // tests default to auto-install on; tests exercising
              // warn-only behavior pass false explicitly.
    )
    .await
}

#[test]
fn resolver_package_types_work() {
    let root = ResolverPackage::Root;
    assert!(root.is_root());

    let lpm = ResolverPackage::from_dep_name("@lpm.dev/neo.highlight");
    assert!(lpm.is_lpm());

    let npm = ResolverPackage::from_dep_name("react");
    assert!(npm.is_npm());
}

#[test]
fn extract_conflicts_from_report() {
    let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
    let conflicts = extract_conflicting_packages(report);
    assert!(conflicts.contains("ms"));
}

#[test]
fn no_conflicts_in_primary_for_single_version() {
    // Primary extraction should NOT flag foo — it only appears with one version (1.0.0)
    let report = "Because root depends on foo 1.0.0 and foo 1.0.0 is not available.";
    let conflicts = extract_conflicts_primary(report);
    assert!(
        !conflicts.contains("foo"),
        "same version twice is not a conflict"
    );
}

#[test]
fn primary_extraction_works() {
    let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
    let conflicts = extract_conflicts_primary(report);
    assert!(conflicts.contains("ms"));
}

#[test]
fn fallback_extraction_on_garbled_format() {
    // A format that doesn't use "depends on" but still mentions packages with versions
    let report = r#"
ms 2.1.3 is required by send 0.19.0
ms 2.0.0 is required by debug 2.6.9
these are incompatible
"#;
    // Primary should fail
    let primary = extract_conflicts_primary(report);
    assert!(
        primary.is_empty(),
        "primary should not find conflicts in non-standard format"
    );

    // Fallback should find ms (appears twice with different versions)
    let fallback = extract_conflicts_fallback(report);
    assert!(
        fallback.contains("ms"),
        "fallback should find 'ms' mentioned with 2+ versions"
    );
}

#[test]
fn fallback_returns_nonempty_for_repeated_packages() {
    let report = "foo 1.0.0 conflicts with foo 2.0.0";
    let fallback = extract_conflicts_fallback(report);
    assert!(!fallback.is_empty(), "fallback should find something");
    assert!(fallback.contains("foo"));
}

fn resolved_pkg_with_graph(
    name: &str,
    version: &str,
    context: Option<&str>,
    dependencies: &[(&str, &str)],
    peers: &[(&str, &str)],
) -> ResolvedPackage {
    let package = match context {
        Some(context) => ResolverPackage::npm(name).with_context(context),
        None => ResolverPackage::npm(name),
    };
    ResolvedPackage {
        package,
        version: NpmVersion::parse(version).unwrap(),
        dependencies: dependencies
            .iter()
            .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
            .collect(),
        aliases: HashMap::new(),
        peers: peers
            .iter()
            .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
            .collect(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }
}

#[test]
fn peer_superset_dedup_prefers_row_with_superset_edges_and_peers() {
    let mut packages = vec![
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("react"),
            &[("shared", "1.0.0")],
            &[("react", "18.2.0")],
        ),
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("react-dom"),
            &[("shared", "1.0.0"), ("extra", "1.0.0")],
            &[("react", "18.2.0"), ("react-dom", "18.2.0")],
        ),
    ];

    dedupe_peer_superset_packages(&mut packages);

    assert_eq!(packages.len(), 1);
    assert_eq!(
        packages[0].dependencies,
        vec![
            ("shared".to_string(), "1.0.0".to_string()),
            ("extra".to_string(), "1.0.0".to_string())
        ],
        "the retained row must be the graph superset"
    );
    assert_eq!(
        packages[0].peers,
        vec![
            ("react".to_string(), "18.2.0".to_string()),
            ("react-dom".to_string(), "18.2.0".to_string())
        ]
    );
}

#[test]
fn peer_superset_dedup_collapses_identical_split_contexts() {
    let mut packages = vec![
        resolved_pkg_with_graph(
            "cross-spawn",
            "7.0.6",
            Some("parent-a"),
            &[("path-key", "3.1.1")],
            &[],
        ),
        resolved_pkg_with_graph(
            "cross-spawn",
            "7.0.6",
            Some("parent-b"),
            &[("path-key", "3.1.1")],
            &[],
        ),
    ];

    dedupe_peer_superset_packages(&mut packages);

    assert_eq!(
        packages.len(),
        1,
        "identical same-version split contexts must collapse before install conversion"
    );
}

#[test]
fn peer_superset_dedup_keeps_non_comparable_peer_contexts() {
    let mut packages = vec![
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("react-17"),
            &[("shared", "1.0.0")],
            &[("react", "17.0.2")],
        ),
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("react-18"),
            &[("shared", "1.0.0")],
            &[("react", "18.2.0")],
        ),
    ];

    dedupe_peer_superset_packages(&mut packages);

    assert_eq!(
        packages.len(),
        2,
        "same package/version rows with different peer bindings are not interchangeable"
    );
}

#[test]
fn peer_superset_dedup_keeps_non_comparable_dependency_edges() {
    let mut packages = vec![
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("left"),
            &[("left-only", "1.0.0")],
            &[("react", "18.2.0")],
        ),
        resolved_pkg_with_graph(
            "plugin",
            "1.0.0",
            Some("right"),
            &[("right-only", "1.0.0")],
            &[("react", "18.2.0"), ("react-dom", "18.2.0")],
        ),
    ];

    dedupe_peer_superset_packages(&mut packages);

    assert_eq!(
        packages.len(),
        2,
        "peer supersets cannot replace rows with unrelated dependency edges"
    );
}

// === Post-resolution peer dependency checking ===

/// Helper to build a CachedPackageInfo for tests.
fn make_cached_info(
    versions: &[&str],
    deps: Vec<(&str, Vec<(&str, &str)>)>,
    peer_deps: Vec<(&str, Vec<(&str, &str)>)>,
) -> std::sync::Arc<CachedPackageInfo> {
    // The public `ResolveResult.cache` and `check_unmet_peers` take
    // `Arc<CachedPackageInfo>` values, so the test helper wraps once at
    // construction time. Tests insert the returned Arc directly with no
    // further changes.
    std::sync::Arc::new(CachedPackageInfo {
        modified: None,
        trust_metadata_complete: false,
        versions: versions
            .iter()
            .map(|v| NpmVersion::parse(v).unwrap())
            .collect(),
        deps: deps
            .into_iter()
            .map(|(v, d)| {
                (
                    v.to_string(),
                    d.into_iter()
                        .map(|(k, r)| (k.to_string(), r.to_string()))
                        .collect(),
                )
            })
            .collect(),
        peer_deps: peer_deps
            .into_iter()
            .map(|(v, d)| {
                (
                    v.to_string(),
                    d.into_iter()
                        .map(|(k, r)| (k.to_string(), r.to_string()))
                        .collect(),
                )
            })
            .collect(),
        optional_dep_names: HashMap::new(),
        optional_peer_names: HashMap::new(),
        bundled_dep_names: HashMap::new(),
        platform: HashMap::new(),
        dist: HashMap::new(),
        aliases: HashMap::new(),
    })
}

fn make_version_metadata(
    name: &str,
    version: &str,
    dependencies: Vec<(&str, &str)>,
    optional_dependencies: Vec<(&str, &str)>,
    os: Vec<&str>,
    cpu: Vec<&str>,
) -> VersionMetadata {
    VersionMetadata {
        name: name.to_string(),
        version: version.to_string(),
        dependencies: dependencies
            .into_iter()
            .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
            .collect(),
        optional_dependencies: optional_dependencies
            .into_iter()
            .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
            .collect(),
        os: os.into_iter().map(str::to_string).collect(),
        cpu: cpu.into_iter().map(str::to_string).collect(),
        ..VersionMetadata::default()
    }
}

fn make_package_metadata(name: &str, versions: Vec<VersionMetadata>) -> PackageMetadata {
    let latest_version = versions
        .last()
        .map(|version| version.version.clone())
        .expect("package metadata test fixture needs at least one version");

    PackageMetadata {
        name: name.to_string(),
        description: None,
        dist_tags: HashMap::from([("latest".to_string(), latest_version.clone())]),
        versions: versions
            .into_iter()
            .map(|version| (version.version.clone(), version))
            .collect(),
        time: HashMap::new(),
        modified: None,
        downloads: None,
        distribution_mode: None,
        package_type: None,
        latest_version: Some(latest_version),
        ecosystem: None,
    }
}

#[tokio::test]
async fn resolve_with_prefetch_preserves_platform_incompatible_optional_registry_metadata() {
    let platform = Platform::current();
    let compatible_optional = format!("@esbuild/{}-{}", platform.os, platform.cpu);
    let (incompatible_optional, incompatible_os, incompatible_cpu) = if platform.os == "darwin" {
        ("@esbuild/linux-x64".to_string(), "linux", "x64")
    } else {
        ("@esbuild/darwin-arm64".to_string(), "darwin", "arm64")
    };

    let prefetched = HashMap::from([
        (
            "esbuild".to_string(),
            make_package_metadata(
                "esbuild",
                vec![make_version_metadata(
                    "esbuild",
                    "0.28.0",
                    vec![],
                    vec![
                        (compatible_optional.as_str(), "0.28.0"),
                        (incompatible_optional.as_str(), "0.28.0"),
                    ],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            compatible_optional.clone(),
            make_package_metadata(
                &compatible_optional,
                vec![make_version_metadata(
                    &compatible_optional,
                    "0.28.0",
                    vec![],
                    vec![],
                    vec![platform.os],
                    vec![platform.cpu],
                )],
            ),
        ),
        (
            incompatible_optional.clone(),
            make_package_metadata(
                &incompatible_optional,
                vec![make_version_metadata(
                    &incompatible_optional,
                    "0.28.0",
                    vec![],
                    vec![],
                    vec![incompatible_os],
                    vec![incompatible_cpu],
                )],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("esbuild".to_string(), "0.28.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("prefetched esbuild-style metadata should resolve on the current platform");

    let resolved_names: HashSet<String> = result
        .packages
        .iter()
        .map(|package| package.package.to_string())
        .collect();
    assert!(resolved_names.contains("esbuild"));
    assert!(resolved_names.contains(&compatible_optional));
    assert!(resolved_names.contains(&incompatible_optional));

    let esbuild = result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == "esbuild")
        .expect("esbuild should be in the resolved tree");
    assert!(
        esbuild
            .dependencies
            .contains(&(compatible_optional, "0.28.0".to_string()))
    );
    assert!(
        esbuild
            .dependencies
            .contains(&(incompatible_optional.clone(), "0.28.0".to_string()))
    );

    let incompatible = result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == incompatible_optional)
        .expect("incompatible optional should remain in the resolver output");
    assert!(incompatible.optional);
    assert_eq!(
        incompatible.platform,
        Some(PlatformMeta {
            os: vec![incompatible_os.to_string()],
            cpu: vec![incompatible_cpu.to_string()],
            libc: vec![],
        })
    );
}

/// `StageTiming` contract: `resolve_with_prefetch` populates the
/// field on `ResolveResult` and the resolver flows that value
/// through the happy path to the caller.
///
/// NOTE: The underlying counters live in `lpm_registry::timing`
/// as process-global atomics (see that module's docs for why
/// thread-locals can't work with `spawn_blocking`). Concurrent
/// tests that trigger RPCs — even failing ones — will race on
/// those atomics, so this test intentionally does NOT assert
/// strict zeros on follow-up fields. The install-pipeline
/// fixture run serves as the end-to-end contract check for
/// non-zero values; here we validate only that the shape is
/// wired through and that the `pubgrub_ms` accumulator ran
/// (it's bounded by a single resolution pass, so not subject to
/// cross-test contamination).
#[tokio::test]
async fn resolve_with_prefetch_emits_stage_timing_shape() {
    let prefetched = HashMap::from([
        (
            "app".to_string(),
            make_package_metadata(
                "app",
                vec![make_version_metadata(
                    "app",
                    "1.0.0",
                    vec![("left", "1.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "left".to_string(),
            make_package_metadata(
                "left",
                vec![make_version_metadata(
                    "left",
                    "1.0.0",
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("app".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("fully-prefetched resolution must succeed");

    let t = result.stage_timing;
    // `pubgrub_ms` is a per-pass wall-clock accumulator, not a
    // process-global, so it's race-free. Even on the fastest
    // machines a non-trivial resolution is at least 1 instant
    // apart; but we tolerate 0 in case of sub-millisecond
    // resolution (the type is unsigned, so only assert upper
    // sanity bound).
    assert!(
        t.pubgrub_ms < 60_000,
        "pubgrub_ms of {} indicates runaway resolution or leaked wall-clock",
        t.pubgrub_ms
    );
    // Shape is accessible; follow-up fields exist and are read
    // without panic. The actual values are validated end-to-end
    // against a real install fixture.
    let _ = t.followup_rpc_ms;
    let _ = t.followup_rpc_count;
    let _ = t.parse_ndjson_ms;
}

/// Regression: a platform-gated optional dep has one old version with
/// an erroneous `os`/`cpu` declaration that makes it look compatible,
/// but that version doesn't satisfy the declared range. Resolution must
/// still pick the newest satisfying version and carry platform metadata
/// forward so install-time filtering can skip it.
#[tokio::test]
async fn resolve_with_prefetch_selects_newest_optional_when_platform_match_is_out_of_range() {
    let platform = Platform::current();
    let incompatible_optional = if platform.os == "darwin" {
        "@next/swc-linux-x64-musl".to_string()
    } else {
        "@next/swc-darwin-arm64".to_string()
    };

    // `next@15.5.15` declares `incompatible_optional: 15.5.15` as OPTIONAL.
    // The dep has two versions in the registry:
    //   - 15.5.15: declares the correct (incompatible) platform
    //   - 12.0.0: declares the current platform erroneously (Next.js packaging bug)
    let prefetched = HashMap::from([
        (
            "next".to_string(),
            make_package_metadata(
                "next",
                vec![make_version_metadata(
                    "next",
                    "15.5.15",
                    vec![],
                    vec![(incompatible_optional.as_str(), "15.5.15")],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            incompatible_optional.clone(),
            make_package_metadata(
                &incompatible_optional,
                vec![
                    // Correctly tagged for the OTHER platform — would be
                    // filtered by platform check.
                    make_version_metadata(
                        &incompatible_optional,
                        "15.5.15",
                        vec![],
                        vec![],
                        if platform.os == "darwin" {
                            vec!["linux"]
                        } else {
                            vec!["darwin"]
                        },
                        if platform.os == "darwin" {
                            vec!["x64"]
                        } else {
                            vec!["arm64"]
                        },
                    ),
                    // Erroneously tagged for the CURRENT platform — passes
                    // platform filter, but doesn't satisfy the declared
                    // range on `next@15.5.15` (which is `15.5.15` exactly).
                    make_version_metadata(
                        &incompatible_optional,
                        "12.0.0",
                        vec![],
                        vec![],
                        vec![platform.os],
                        vec![platform.cpu],
                    ),
                ],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("next".to_string(), "15.5.15".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("resolver must pick the newest satisfying optional dep and defer platform filtering");

    let resolved_names: HashSet<String> = result
        .packages
        .iter()
        .map(|package| package.package.to_string())
        .collect();
    assert!(
        resolved_names.contains("next"),
        "root dep `next` must be resolved"
    );
    assert!(
        resolved_names.contains(&incompatible_optional),
        "platform-gated optional dep must be present for install-time filtering"
    );

    let optional = result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == incompatible_optional)
        .expect("platform-gated optional dep should resolve");
    assert_eq!(optional.version.to_string(), "15.5.15");
    assert!(optional.optional);
}

/// npm-alias root dep: the consumer declares
/// `"strip-ansi-cjs": "npm:strip-ansi@^6.0.1"`, and the resolver
/// must (a) fetch `strip-ansi` metadata (not `strip-ansi-cjs`),
/// (b) resolve the alias target's version against the inner range,
/// and (c) surface the `local → target` mapping via
/// `ResolveResult.root_aliases` so the install pipeline can build
/// `node_modules/strip-ansi-cjs/` → `.lpm/strip-ansi@6.0.1/...`.
#[tokio::test]
async fn resolve_with_prefetch_handles_root_npm_alias() {
    // PubGrub-arm-specific: npm-alias range parsing
    // (`"strip-ansi-cjs": "npm:strip-ansi@^6.0.1"`). Greedy doesn't
    // accept this range form, so pin to PubGrub.
    let _env = env_lock().lock().await;
    let _guard = PubgrubEnvGuard::new();

    let prefetched = HashMap::from([(
        "strip-ansi".to_string(),
        make_package_metadata(
            "strip-ansi",
            vec![make_version_metadata(
                "strip-ansi",
                "6.0.1",
                vec![],
                vec![],
                vec![],
                vec![],
            )],
        ),
    )]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([(
            "strip-ansi-cjs".to_string(),
            "npm:strip-ansi@^6.0.1".to_string(),
        )]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("root npm-alias must resolve against the target identity");

    // The resolved tree contains the TARGET (`strip-ansi`), not the
    // alias key.
    let resolved_names: HashSet<String> = result
        .packages
        .iter()
        .map(|p| p.package.to_string())
        .collect();
    assert!(
        resolved_names.contains("strip-ansi"),
        "alias target must be in resolved tree"
    );
    assert!(
        !resolved_names.contains("strip-ansi-cjs"),
        "alias key must not pollute resolver identities"
    );

    // Root alias is surfaced for the install pipeline.
    assert_eq!(
        result.root_aliases.get("strip-ansi-cjs"),
        Some(&"strip-ansi".to_string()),
        "root_aliases must record local → target"
    );
}

/// npm-alias transitive dep: a parent package's registry metadata
/// declares
/// `"strip-ansi-cjs": "npm:strip-ansi@^6"` in its own
/// `dependencies`. The resolver must treat the alias the same way
/// at any depth — the parent's resolved edge list records the
/// local name (`strip-ansi-cjs`), the resolved child is keyed on
/// `strip-ansi`, and the parent's `aliases` map carries the
/// `local → target` pair so the linker can build
/// `.lpm/parent@1.0.0/node_modules/strip-ansi-cjs/` →
/// `../../strip-ansi@6.0.1/node_modules/strip-ansi/`.
#[tokio::test]
async fn resolve_with_prefetch_handles_transitive_npm_alias() {
    let prefetched = HashMap::from([
        (
            "parent".to_string(),
            make_package_metadata(
                "parent",
                vec![make_version_metadata(
                    "parent",
                    "1.0.0",
                    vec![("strip-ansi-cjs", "npm:strip-ansi@^6")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "strip-ansi".to_string(),
            make_package_metadata(
                "strip-ansi",
                vec![make_version_metadata(
                    "strip-ansi",
                    "6.0.1",
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("parent".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("transitive npm-alias must resolve through the target identity");

    // Parent and aliased target (strip-ansi) are in the tree; the
    // alias key itself is NOT a distinct ResolverPackage.
    let resolved_names: HashSet<String> = result
        .packages
        .iter()
        .map(|p| p.package.to_string())
        .collect();
    assert!(resolved_names.contains("parent"));
    assert!(resolved_names.contains("strip-ansi"));
    assert!(!resolved_names.contains("strip-ansi-cjs"));

    // Parent's dep edge carries the LOCAL name + resolved version.
    let parent = result
        .packages
        .iter()
        .find(|p| p.package.canonical_name() == "parent")
        .unwrap();
    assert_eq!(
        parent.dependencies,
        vec![("strip-ansi-cjs".to_string(), "6.0.1".to_string())],
        "edge key is the local alias name, version is the target's"
    );
    assert_eq!(
        parent.aliases.get("strip-ansi-cjs"),
        Some(&"strip-ansi".to_string()),
        "parent's aliases map records local → target"
    );

    // Transitive aliases are NOT root aliases.
    assert!(
        result.root_aliases.is_empty(),
        "transitive alias must not leak into the root alias map"
    );
}

/// Regression: a non-optional dep with no compatible platform version
/// still resolves so install-time filtering can produce the required
/// hard platform error instead of hiding the selected package from the
/// lockfile.
#[tokio::test]
async fn resolve_regular_dep_with_no_platform_compatible_version_still_resolves() {
    let platform = Platform::current();
    let incompatible_dep = if platform.os == "darwin" {
        "some-linux-only-dep".to_string()
    } else {
        "some-darwin-only-dep".to_string()
    };

    let prefetched = HashMap::from([
        (
            "app".to_string(),
            make_package_metadata(
                "app",
                vec![make_version_metadata(
                    "app",
                    "1.0.0",
                    vec![(incompatible_dep.as_str(), "1.0.0")], // REQUIRED dep
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            incompatible_dep.clone(),
            make_package_metadata(
                &incompatible_dep,
                vec![make_version_metadata(
                    &incompatible_dep,
                    "1.0.0",
                    vec![],
                    vec![],
                    if platform.os == "darwin" {
                        vec!["linux"]
                    } else {
                        vec!["darwin"]
                    },
                    vec![],
                )],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("app".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("resolver must defer required platform errors to install-time filtering");

    let dep = result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == incompatible_dep)
        .expect("required incompatible dep should be present in resolver output");
    assert!(!dep.optional);
    assert!(dep.platform.is_some());
}

#[tokio::test]
async fn resolve_with_prefetch_retries_until_all_conflicts_are_split() {
    // PubGrub-arm-specific: split-retry conflict resolution.
    let _env = env_lock().lock().await;
    let _guard = PubgrubEnvGuard::new();

    let prefetched = HashMap::from([
        (
            "app".to_string(),
            make_package_metadata(
                "app",
                vec![make_version_metadata(
                    "app",
                    "1.0.0",
                    vec![("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "a".to_string(),
            make_package_metadata(
                "a",
                vec![make_version_metadata(
                    "a",
                    "1.0.0",
                    vec![("x", "1.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "b".to_string(),
            make_package_metadata(
                "b",
                vec![make_version_metadata(
                    "b",
                    "1.0.0",
                    vec![("x", "2.0.0"), ("y", "1.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "c".to_string(),
            make_package_metadata(
                "c",
                vec![make_version_metadata(
                    "c",
                    "1.0.0",
                    vec![("y", "2.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "x".to_string(),
            make_package_metadata(
                "x",
                vec![
                    make_version_metadata("x", "1.0.0", vec![], vec![], vec![], vec![]),
                    make_version_metadata("x", "2.0.0", vec![], vec![], vec![], vec![]),
                ],
            ),
        ),
        (
            "y".to_string(),
            make_package_metadata(
                "y",
                vec![
                    make_version_metadata("y", "1.0.0", vec![], vec![], vec![], vec![]),
                    make_version_metadata("y", "2.0.0", vec![], vec![], vec![], vec![]),
                ],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("app".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect("resolver should keep splitting until both x and y conflicts are scoped");

    let resolved_versions: HashMap<String, String> = result
        .packages
        .iter()
        .map(|package| (package.package.to_string(), package.version.to_string()))
        .collect();

    assert_eq!(
        resolved_versions.get("x[a]").map(String::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        resolved_versions.get("x[b]").map(String::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        resolved_versions.get("y[b]").map(String::as_str),
        Some("1.0.0")
    );
    assert_eq!(
        resolved_versions.get("y[c]").map(String::as_str),
        Some("2.0.0")
    );
}

/// Nested-scope propagation.
///
/// Minimal reproduction of the real-world eslint + ajv conflict:
/// root depends on ajv@^8 + eslint@^9; eslint@9 transitively requires
/// ajv@^6; ajv@8 and ajv@6 each declare DIFFERENT json-schema-traverse
/// version ranges.
///
/// bun resolves this fine — two ajv's coexist in node_modules (top-
/// level ajv@8 + nested eslint/node_modules/ajv@6), each with its own
/// json-schema-traverse.
///
/// Before the fix, lpm's pubgrub concluded NoSolution because the
/// split-retry logic could split `ajv` into `ajv[<root>]` vs
/// `ajv[eslint]`, but when enumerating the split ajv's deps the scope
/// key for the grandchild was built from
/// `parent.canonical_name()` — which strips the parent's context.
/// Both ajv's produced a child scope-key of `[ajv]`, unifying the two
/// json-schema-traverse requests back into a single pubgrub identity
/// whose version ranges collided.
///
/// After the fix, the grandchild scope key is derived from the
/// parent's full display identity, so `ajv[<root>]`'s child gets
/// `json-schema-traverse[ajv[<root>]]` and `ajv[eslint]`'s child gets
/// `json-schema-traverse[ajv[eslint]]` — distinct pubgrub packages,
/// each able to satisfy its own range.
#[tokio::test]
async fn resolve_with_prefetch_propagates_parent_context_to_grandchild_splits() {
    // PubGrub-arm-specific: split-retry context propagation to
    // grandchildren of split nodes.
    let _env = env_lock().lock().await;
    let _guard = PubgrubEnvGuard::new();

    let prefetched = HashMap::from([
        (
            "root_app".to_string(),
            make_package_metadata(
                "root_app",
                vec![make_version_metadata(
                    "root_app",
                    "1.0.0",
                    vec![("ajv", "^8.0.0"), ("eslint", "^9.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "eslint".to_string(),
            make_package_metadata(
                "eslint",
                vec![make_version_metadata(
                    "eslint",
                    "9.0.0",
                    vec![("ajv", "^6.0.0")],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        ),
        (
            "ajv".to_string(),
            make_package_metadata(
                "ajv",
                vec![
                    make_version_metadata(
                        "ajv",
                        "6.14.0",
                        vec![("json-schema-traverse", "^0.4.0")],
                        vec![],
                        vec![],
                        vec![],
                    ),
                    make_version_metadata(
                        "ajv",
                        "8.18.0",
                        vec![("json-schema-traverse", "^1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    ),
                ],
            ),
        ),
        (
            "json-schema-traverse".to_string(),
            make_package_metadata(
                "json-schema-traverse",
                vec![
                    make_version_metadata(
                        "json-schema-traverse",
                        "0.4.1",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    ),
                    make_version_metadata(
                        "json-schema-traverse",
                        "1.0.0",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    ),
                ],
            ),
        ),
    ]);

    let result = resolve_with_prefetch(
        Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
        HashMap::from([("root_app".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
        Some(prefetched),
    )
    .await
    .expect(
        "resolver must handle eslint+ajv nested duplicates — bun and npm both resolve this \
             without dropping deps",
    );

    let resolved_versions: HashMap<String, String> = result
        .packages
        .iter()
        .map(|package| (package.package.to_string(), package.version.to_string()))
        .collect();

    // Two ajv's must coexist.
    let ajv_8_key = resolved_versions
        .iter()
        .find(|(_, v)| v.as_str() == "8.18.0")
        .map(|(k, _)| k.clone())
        .expect("ajv@8 should be chosen for the root's direct ^8 range");
    let ajv_6_key = resolved_versions
        .iter()
        .find(|(_, v)| v.as_str() == "6.14.0")
        .map(|(k, _)| k.clone())
        .expect("ajv@6 should be chosen for eslint's transitive ^6 range");
    assert!(
        ajv_8_key.starts_with("ajv"),
        "ajv@8 key should be an ajv identity, got {ajv_8_key}"
    );
    assert!(
        ajv_6_key.starts_with("ajv"),
        "ajv@6 key should be an ajv identity, got {ajv_6_key}"
    );
    assert_ne!(
        ajv_8_key, ajv_6_key,
        "ajv@8 and ajv@6 must be distinct pubgrub identities, both got {ajv_8_key}"
    );

    // And both json-schema-traverse versions must coexist, one per ajv.
    let mut jst_versions: Vec<&str> = resolved_versions
        .iter()
        .filter(|(k, _)| k.starts_with("json-schema-traverse"))
        .map(|(_, v)| v.as_str())
        .collect();
    jst_versions.sort();
    assert_eq!(
        jst_versions,
        vec!["0.4.1", "1.0.0"],
        "exactly one json-schema-traverse@0.4.1 and one @1.0.0 must resolve — got {:?}",
        resolved_versions
    );
}

#[test]
fn peer_check_satisfied_peer_no_warning() {
    // styled-components@5.0.0 peers on react@^16||^17
    // react@17.0.2 is in the tree → satisfied, no warning
    let sc_pkg = ResolverPackage::npm("styled-components");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["5.0.0"],
            vec![],
            vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "peer should be satisfied: {warnings:?}"
    );
}

#[test]
fn peer_check_wrong_version_produces_warning() {
    // styled-components@6.0.0 peers on react@^18
    // react@17.0.2 is in the tree → version mismatch warning
    let sc_pkg = ResolverPackage::npm("styled-components");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("6.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["6.0.0"],
            vec![],
            vec![("6.0.0", vec![("react", "^18.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].peer, "react");
    assert_eq!(warnings[0].required_range, "^18.0.0");
    assert_eq!(warnings[0].resolved_version.as_deref(), Some("17.0.2"));
}

#[test]
fn peer_check_multiple_satisfying_versions_do_not_report_peer_missing() {
    let plugin_pkg = ResolverPackage::npm("esbuild-plugins-node-modules-polyfill");
    let esbuild_nested_a = ResolverPackage::npm("esbuild").with_context("vite");
    let esbuild_nested_b = ResolverPackage::npm("esbuild").with_context("@remix-run/dev");

    let resolved = vec![
        ResolvedPackage {
            package: plugin_pkg.clone(),
            version: NpmVersion::parse("1.8.1").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: esbuild_nested_a.clone(),
            version: NpmVersion::parse("0.25.12").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: esbuild_nested_b.clone(),
            version: NpmVersion::parse("0.17.6").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&plugin_pkg),
        make_cached_info(
            &["1.8.1"],
            vec![],
            vec![("1.8.1", vec![("esbuild", ">=0.14.0 <=0.27.x")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&esbuild_nested_a),
        make_cached_info(&["0.25.12", "0.17.6"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "any satisfying esbuild instance should satisfy the peer instead of reporting it missing: {warnings:?}"
    );
}

/// `peerDependenciesMeta.optional` suppresses the missing-peer
/// warning. Real-world example: `react-redux@9` declares optional
/// peer for older React; users who don't install those see noisy
/// warnings without this gate.
#[test]
fn peer_check_optional_peer_missing_no_warning() {
    let pkg = ResolverPackage::npm("react-redux");

    let resolved = vec![ResolvedPackage {
        package: pkg.clone(),
        version: NpmVersion::parse("9.0.0").unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }];

    let mut cache = HashMap::new();
    let mut info = (*make_cached_info(
        &["9.0.0"],
        vec![],
        vec![("9.0.0", vec![("react", "^18 || ^19")])],
    ))
    .clone();
    // Mark `react` as optional via peerDependenciesMeta — the
    // missing-peer warning must be suppressed.
    let mut opt_peers = HashSet::new();
    opt_peers.insert("react".to_string());
    info.optional_peer_names
        .insert("9.0.0".to_string(), opt_peers);
    cache.insert(CanonicalKey::from(&pkg), std::sync::Arc::new(info));

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "optional missing peer must NOT produce a warning: {warnings:?}"
    );
}

/// Optional peers that ARE present but at the wrong version still
/// produce a warning. An optional flag is opt-out for the missing
/// case only; if the user opted into having the peer, the
/// version-mismatch contract still applies.
#[test]
fn peer_check_optional_peer_wrong_version_still_warns() {
    let pkg = ResolverPackage::npm("react-redux");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: pkg.clone(),
            version: NpmVersion::parse("9.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    let mut info = (*make_cached_info(
        &["9.0.0"],
        vec![],
        vec![("9.0.0", vec![("react", "^18 || ^19")])],
    ))
    .clone();
    let mut opt_peers = HashSet::new();
    opt_peers.insert("react".to_string());
    info.optional_peer_names
        .insert("9.0.0".to_string(), opt_peers);
    cache.insert(CanonicalKey::from(&pkg), std::sync::Arc::new(info));
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].peer, "react");
    assert_eq!(
        warnings[0].resolved_version.as_deref(),
        Some("17.0.2"),
        "warning is for the version mismatch, not for missing"
    );
}

#[test]
fn peer_check_missing_peer_produces_warning() {
    // styled-components@5.0.0 peers on react@^16||^17
    // react is NOT in the tree → missing peer warning
    let sc_pkg = ResolverPackage::npm("styled-components");

    let resolved = vec![ResolvedPackage {
        package: sc_pkg.clone(),
        version: NpmVersion::parse("5.0.0").unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["5.0.0"],
            vec![],
            vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
        ),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].peer, "react");
    assert!(
        warnings[0].resolved_version.is_none(),
        "peer is missing from tree"
    );
}

#[test]
fn peer_check_version_specific_no_cross_contamination() {
    // Key test: styled-components has different peers per version.
    // Only the SELECTED version's peers should be checked.
    //
    // v5.0.0 peers on react@^16||^17
    // v6.0.0 peers on react@^18
    //
    // If v5.0.0 is selected and react@17.0.2 is in tree:
    //   → NO warning (^16||^17 satisfied by 17.0.2)
    //
    // The old union approach would have forced react@^18 (newest wins),
    // which would incorrectly fail.
    let sc_pkg = ResolverPackage::npm("styled-components");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    // Both versions are in cache, but only v5's peers should matter
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["6.0.0", "5.0.0"],
            vec![],
            vec![
                ("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")]),
                ("6.0.0", vec![("react", "^18.0.0")]),
            ],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "v5's peer react@^16||^17 is satisfied by 17.0.2, v6's peers should not apply: {warnings:?}"
    );
}

#[test]
fn peer_check_prefers_same_split_context_peer_version() {
    let plugin_pkg = ResolverPackage::npm("plugin").with_context("host-a");
    let react_host_a = ResolverPackage::npm("react").with_context("host-a");
    let react_host_b = ResolverPackage::npm("react").with_context("host-b");

    let resolved = vec![
        ResolvedPackage {
            package: plugin_pkg.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_host_a.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_host_b.clone(),
            version: NpmVersion::parse("18.2.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&plugin_pkg),
        make_cached_info(
            &["1.0.0"],
            vec![],
            vec![("1.0.0", vec![("react", "^17.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_host_a),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );
    cache.insert(
        CanonicalKey::from(&react_host_b),
        make_cached_info(&["18.2.0"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "split package should use peer version from the same context before falling back globally: {warnings:?}"
    );
}

#[test]
fn peer_binding_uses_declared_range_when_multiple_unsplit_versions_exist() {
    let plugin_pkg = ResolverPackage::npm("plugin");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: plugin_pkg.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("18.2.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&plugin_pkg),
        make_cached_info(
            &["1.0.0"],
            vec![],
            vec![("1.0.0", vec![("react", "^17.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["18.2.0", "17.0.2"], vec![], vec![]),
    );

    let peer_candidates: HashMap<String, Vec<(Option<String>, String)>> =
        resolved.iter().fold(HashMap::new(), |mut acc, pkg| {
            acc.entry(pkg.package.canonical_name()).or_default().push((
                pkg.package.context().map(str::to_string),
                pkg.version.to_string(),
            ));
            acc
        });
    let bound_peers = compute_resolved_peers(&plugin_pkg, "1.0.0", &cache, &peer_candidates);
    assert_eq!(
        bound_peers,
        vec![("react".to_string(), "17.0.2".to_string())],
        "graph/link peer binding must choose the version satisfying the consumer range"
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(
        warnings.is_empty(),
        "warning path and graph binding should agree that react@17 satisfies plugin: {warnings:?}"
    );
}

#[test]
fn peer_check_multiple_packages_multiple_peers() {
    // Two packages with different peers
    let pkg_a = ResolverPackage::npm("pkg-a");
    let pkg_b = ResolverPackage::npm("pkg-b");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: pkg_a.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: pkg_b.clone(),
            version: NpmVersion::parse("2.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("18.2.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    // pkg-a peers on react@^18 (satisfied) and vue@^3 (missing)
    cache.insert(
        CanonicalKey::from(&pkg_a),
        make_cached_info(
            &["1.0.0"],
            vec![],
            vec![("1.0.0", vec![("react", "^18.0.0"), ("vue", "^3.0.0")])],
        ),
    );
    // pkg-b peers on react@^17 (wrong version)
    cache.insert(
        CanonicalKey::from(&pkg_b),
        make_cached_info(
            &["2.0.0"],
            vec![],
            vec![("2.0.0", vec![("react", "^17.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["18.2.0"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    // Should have 2 warnings: vue missing + react wrong version for pkg-b
    assert_eq!(warnings.len(), 2, "expected 2 warnings: {warnings:?}");

    // Sorted by package then peer
    assert_eq!(warnings[0].package, "pkg-a");
    assert_eq!(warnings[0].peer, "vue");
    assert!(warnings[0].resolved_version.is_none());

    assert_eq!(warnings[1].package, "pkg-b");
    assert_eq!(warnings[1].peer, "react");
    assert_eq!(warnings[1].resolved_version.as_deref(), Some("18.2.0"));
}

#[test]
fn peer_check_no_peers_no_warnings() {
    // Package with no peer deps → no warnings
    let pkg = ResolverPackage::npm("lodash");

    let resolved = vec![ResolvedPackage {
        package: pkg.clone(),
        version: NpmVersion::parse("4.17.21").unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&pkg),
        make_cached_info(&["4.17.21"], vec![], vec![]),
    );

    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert!(warnings.is_empty());
}

#[test]
fn peer_warning_display_format() {
    let w_missing = PeerWarning {
        package: "styled-components".to_string(),
        version: "5.0.0".to_string(),
        peer: "react".to_string(),
        required_range: "^16.8.0".to_string(),
        resolved_version: None,
    };
    assert!(w_missing.to_string().contains("is not installed"));

    let w_wrong = PeerWarning {
        package: "styled-components".to_string(),
        version: "6.0.0".to_string(),
        peer: "react".to_string(),
        required_range: "^18.0.0".to_string(),
        resolved_version: Some("17.0.2".to_string()),
    };
    assert!(w_wrong.to_string().contains("17.0.2 was resolved"));
}

// ─── peer-dependency rules — glob matcher ─────────────────────────

/// Patterns without `*` match exactly; nothing else.
#[test]
fn glob_pattern_exact_match_no_wildcard() {
    let p = GlobPattern::compile("react");
    assert!(p.matches("react"));
    assert!(!p.matches("react-dom"));
    assert!(!p.matches("preact"));
    assert!(!p.matches(""));
}

/// Bare `*` matches every name including the empty string.
#[test]
fn glob_pattern_bare_star_matches_anything() {
    let p = GlobPattern::compile("*");
    assert!(p.matches("react"));
    assert!(p.matches("@scope/anything"));
    assert!(p.matches(""));
}

/// Trailing `*` is a prefix match.
#[test]
fn glob_pattern_trailing_star_is_prefix_match() {
    let p = GlobPattern::compile("@babel/*");
    assert!(p.matches("@babel/core"));
    assert!(p.matches("@babel/runtime"));
    assert!(p.matches("@babel/")); // empty suffix allowed
    assert!(!p.matches("@babels/core"));
    assert!(!p.matches("babel/core"));
}

/// Leading `*` is a suffix match.
#[test]
fn glob_pattern_leading_star_is_suffix_match() {
    let p = GlobPattern::compile("*-eslint-plugin");
    assert!(p.matches("vue-eslint-plugin"));
    assert!(p.matches("react-eslint-plugin"));
    assert!(p.matches("-eslint-plugin")); // empty prefix allowed
    assert!(!p.matches("eslint-plugin")); // missing the leading hyphen
    assert!(!p.matches("eslint-plugin-vue"));
}

/// Middle `*` requires both anchors.
#[test]
fn glob_pattern_middle_star_requires_both_anchors() {
    let p = GlobPattern::compile("react-*-helper");
    assert!(p.matches("react-something-helper"));
    assert!(p.matches("react--helper")); // empty middle allowed
    assert!(!p.matches("react-helper")); // missing the second hyphen
    assert!(!p.matches("react-something-helpers"));
    assert!(!p.matches("preact-something-helper"));
}

/// Multiple wildcards: "a*b*c" requires ordered substring match.
#[test]
fn glob_pattern_multiple_wildcards() {
    let p = GlobPattern::compile("@scope/*-*-tools");
    assert!(p.matches("@scope/foo-bar-tools"));
    assert!(p.matches("@scope/--tools"));
    assert!(!p.matches("@scope/foo-tools")); // only one hyphen
    assert!(!p.matches("@scope/foo-bar")); // missing -tools suffix
}

// ─── peer-dependency rules — apply during check_unmet_peers ───────

/// `ignoreMissing` matches → no missing-peer warning fires for
/// the matched name.
#[test]
fn peer_rules_ignore_missing_suppresses_missing_warning() {
    let sc_pkg = ResolverPackage::npm("styled-components");

    let resolved = vec![ResolvedPackage {
        package: sc_pkg.clone(),
        version: NpmVersion::parse("5.0.0").unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["5.0.0"],
            vec![],
            vec![("5.0.0", vec![("react", "^16.8.0")])],
        ),
    );

    // Without rules: warning fires.
    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(warnings.len(), 1);

    // With ignoreMissing on react: warning suppressed.
    let rules = CompiledPeerRules::compile(&["react".into()], &HashMap::new(), &[]).unwrap();
    let warnings = check_unmet_peers(&resolved, &cache, &rules);
    assert!(
        warnings.is_empty(),
        "ignoreMissing(react) must suppress missing-peer warning"
    );

    // Pattern form: scope wildcard catches multiple names.
    let rules = CompiledPeerRules::compile(&["*".into()], &HashMap::new(), &[]).unwrap();
    let warnings = check_unmet_peers(&resolved, &cache, &rules);
    assert!(
        warnings.is_empty(),
        "ignoreMissing(*) must suppress everything"
    );
}

/// `allowedVersions` widens the accepted range when the peer is
/// in the tree but at a non-satisfying version.
#[test]
fn peer_rules_allowed_versions_widens_match() {
    let sc_pkg = ResolverPackage::npm("styled-components");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![("react".into(), "17.0.2".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.2").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["5.0.0"],
            vec![],
            // Consumer wants react ^16, but 17 was resolved.
            vec![("5.0.0", vec![("react", "^16.8.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.2"], vec![], vec![]),
    );

    // Without rules: version-mismatch warning.
    let warnings = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].resolved_version.is_some());

    // Widen the range to "16 || 17": warning suppressed.
    let mut allowed = HashMap::new();
    allowed.insert("react".to_string(), "16 || 17".to_string());
    let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();
    let warnings = check_unmet_peers(&resolved, &cache, &rules);
    assert!(
        warnings.is_empty(),
        "allowedVersions(react=16||17) must accept react@17.0.2"
    );

    // allowedVersions does NOT support glob patterns; the
    // structured selector grammar is the only accepted shape.
    // Compile must FAIL CLOSED on a wildcard key — silently
    // accepting `"*"` and matching nothing would contradict the
    // documented contract and silently no-op the rule.
    let mut allowed = HashMap::new();
    allowed.insert("*".to_string(), "16 || 17".to_string());
    let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
    assert!(err.contains("\"*\""), "error must name the bad key: {err}");
    assert!(
        err.contains("wildcard") || err.contains("glob"),
        "error must explain why `*` is rejected: {err}"
    );
}

/// `allowAny` matches → version-mismatch warning suppressed,
/// but the peer must still be present (does not suppress
/// missing-peer warnings).
#[test]
fn peer_rules_allow_any_suppresses_version_mismatch_only() {
    let sc_pkg = ResolverPackage::npm("styled-components");
    let babel_pkg = ResolverPackage::npm("@babel/core");

    // Variant A: peer in tree at wrong version.
    let resolved_present = vec![
        ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![("@babel/core".into(), "7.5.0".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: babel_pkg.clone(),
            version: NpmVersion::parse("7.5.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    // Variant B: peer not in tree at all.
    let resolved_missing = vec![ResolvedPackage {
        package: sc_pkg.clone(),
        version: NpmVersion::parse("5.0.0").unwrap(),
        dependencies: vec![],
        aliases: HashMap::new(),
        peers: Vec::new(),
        tarball_url: None,
        integrity: None,
        platform: None,
        optional: false,
    }];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&sc_pkg),
        make_cached_info(
            &["5.0.0"],
            vec![],
            // Consumer wants babel ^7.20, got 7.5 — mismatch.
            vec![("5.0.0", vec![("@babel/core", "^7.20.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&babel_pkg),
        make_cached_info(&["7.5.0"], vec![], vec![]),
    );

    // allowAny pattern — covers @babel/* — suppresses present-
    // but-mismatched warning.
    let rules = CompiledPeerRules::compile(&[], &HashMap::new(), &["@babel/*".into()]).unwrap();
    let warnings = check_unmet_peers(&resolved_present, &cache, &rules);
    assert!(
        warnings.is_empty(),
        "allowAny(@babel/*) must suppress version-mismatch when peer is in tree"
    );

    // Same rule does NOT suppress the missing-peer case — the
    // user must combine with ignoreMissing for that.
    let warnings = check_unmet_peers(&resolved_missing, &cache, &rules);
    assert_eq!(
        warnings.len(),
        1,
        "allowAny must NOT suppress missing-peer warnings — that's ignoreMissing's job"
    );
    assert!(warnings[0].resolved_version.is_none());
}

// ─── allowedVersions selector grammar (full pnpm parity) ─────────

/// Bare peer name selectors match any consumer for that peer.
#[test]
fn allowed_versions_selector_bare_name_matches_any_consumer() {
    let s = AllowedVersionsSelector::parse("react").unwrap();
    assert!(s.parent.is_none());
    assert_eq!(s.peer, "react");

    let v1 = NpmVersion::parse("1.0.0").unwrap();
    assert!(s.matches("anything", &v1, "react"));
    assert!(s.matches("@scope/anything", &v1, "react"));
    assert!(!s.matches("anything", &v1, "react-dom"));
}

/// Scoped peer name selectors are bare keys with a leading `@`.
#[test]
fn allowed_versions_selector_scoped_bare_name() {
    let s = AllowedVersionsSelector::parse("@scope/foo").unwrap();
    assert!(s.parent.is_none());
    assert_eq!(s.peer, "@scope/foo");
}

/// `parent>peer` selector matches only when the consumer name
/// matches the parent half. Parent version is unconstrained.
#[test]
fn allowed_versions_selector_parent_no_range_filters_by_consumer_name() {
    let s = AllowedVersionsSelector::parse("foo>react").unwrap();
    let parent = s.parent.as_ref().unwrap();
    assert_eq!(parent.name, "foo");
    assert!(parent.range.is_none());
    assert_eq!(s.peer, "react");

    let v1 = NpmVersion::parse("1.0.0").unwrap();
    assert!(s.matches("foo", &v1, "react"));
    assert!(!s.matches("bar", &v1, "react")); // different consumer
    assert!(!s.matches("foo", &v1, "vue")); // different peer
}

/// `parent@range>peer` filters by both consumer name AND consumer
/// version satisfying the range — the central correctness fix
/// the user flagged.
#[test]
fn allowed_versions_selector_parent_with_range_filters_by_consumer_version() {
    let s = AllowedVersionsSelector::parse("foo@^2>react").unwrap();
    let parent = s.parent.as_ref().unwrap();
    assert_eq!(parent.name, "foo");
    assert!(parent.range.is_some());
    assert_eq!(s.peer, "react");

    let v1 = NpmVersion::parse("1.0.0").unwrap();
    let v2 = NpmVersion::parse("2.5.0").unwrap();
    let v3 = NpmVersion::parse("3.0.0").unwrap();
    assert!(!s.matches("foo", &v1, "react")); // v1 outside ^2
    assert!(s.matches("foo", &v2, "react")); // v2 satisfies ^2
    assert!(!s.matches("foo", &v3, "react")); // v3 outside ^2
    assert!(!s.matches("bar", &v2, "react")); // wrong consumer name
}

/// Scoped parent + version range. The leading `@` of the scope is
/// distinguished from the version-separating `@`.
#[test]
fn allowed_versions_selector_scoped_parent_with_range() {
    let s = AllowedVersionsSelector::parse("@scope/foo@^2>react").unwrap();
    let parent = s.parent.as_ref().unwrap();
    assert_eq!(parent.name, "@scope/foo");
    assert!(parent.range.is_some());
    assert_eq!(s.peer, "react");

    let v2 = NpmVersion::parse("2.0.0").unwrap();
    assert!(s.matches("@scope/foo", &v2, "react"));
    assert!(!s.matches("scope/foo", &v2, "react")); // missing scope @
}

/// Multi-segment paths are rejected as a hard error — same posture
/// as `lpm.overrides`.
#[test]
fn allowed_versions_selector_rejects_multi_segment_paths() {
    let err = AllowedVersionsSelector::parse("a>b>c").unwrap_err();
    assert!(err.contains("multi-segment"), "got: {err}");
}

/// Bare key with version qualifier is ambiguous and rejected.
#[test]
fn allowed_versions_selector_rejects_bare_name_with_version_qualifier() {
    let err = AllowedVersionsSelector::parse("foo@2").unwrap_err();
    assert!(err.contains("version qualifier"), "got: {err}");
}

/// Peer half (after `>`) carrying a version qualifier is rejected
/// — the rule's value is the widened range; putting one on the
/// peer side too is ambiguous.
#[test]
fn allowed_versions_selector_rejects_peer_with_version_qualifier() {
    let err = AllowedVersionsSelector::parse("foo>react@2").unwrap_err();
    assert!(err.contains("peer half"), "got: {err}");
}

/// Empty halves are rejected.
#[test]
fn allowed_versions_selector_rejects_empty_halves() {
    assert!(AllowedVersionsSelector::parse("foo>").is_err());
    assert!(AllowedVersionsSelector::parse(">react").is_err());
    assert!(AllowedVersionsSelector::parse(">").is_err());
    assert!(AllowedVersionsSelector::parse("").is_err());
}

/// Unparseable parent version range is rejected.
#[test]
fn allowed_versions_selector_rejects_unparseable_parent_range() {
    let err = AllowedVersionsSelector::parse("foo@~~not-a-range>react").unwrap_err();
    assert!(err.contains("range"), "got: {err}");
}

// ─── parent-context-aware allowedVersions in check_unmet_peers ────

/// High-signal case: `parent>peer` selectors actually filter
/// at runtime. A pnpm-style `card>react` rule must NOT silence
/// `button>react` peer warnings.
#[test]
fn peer_rules_allowed_versions_parent_selector_only_matches_named_consumer() {
    // Two consumers (button + card) each peer-dep on react@^18.
    // Resolver lands react@17 — both warn without rules.
    // With `card>react: 17`, only card's warning silences;
    // button's warning still fires.
    let button_pkg = ResolverPackage::npm("button");
    let card_pkg = ResolverPackage::npm("card");
    let react_pkg = ResolverPackage::npm("react");

    let resolved = vec![
        ResolvedPackage {
            package: button_pkg.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: vec![("react".into(), "17.0.0".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: card_pkg.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: vec![("react".into(), "17.0.0".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&button_pkg),
        make_cached_info(
            &["1.0.0"],
            vec![],
            vec![("1.0.0", vec![("react", "^18.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&card_pkg),
        make_cached_info(
            &["1.0.0"],
            vec![],
            vec![("1.0.0", vec![("react", "^18.0.0")])],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.0"], vec![], vec![]),
    );

    // Without rules: BOTH consumers warn (2 warnings).
    let baseline = check_unmet_peers(&resolved, &cache, &CompiledPeerRules::default());
    assert_eq!(baseline.len(), 2, "baseline: both consumers warn");

    // With `card>react: 17`, only card's warning silences.
    let mut allowed = HashMap::new();
    allowed.insert("card>react".into(), "17".into());
    let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();
    let warnings = check_unmet_peers(&resolved, &cache, &rules);
    assert_eq!(
        warnings.len(),
        1,
        "card>react must silence ONLY card's warning, not button's"
    );
    assert_eq!(warnings[0].package, "button");
}

/// `parent@range>peer` only fires when the consumer's resolved
/// version satisfies the range.
#[test]
fn peer_rules_allowed_versions_parent_range_filters_consumer_version() {
    // Consumer foo declares react@^18 peer; foo's installed
    // version varies. Rule is `foo@^2>react: 17`.
    let foo_pkg = ResolverPackage::npm("foo");
    let react_pkg = ResolverPackage::npm("react");

    // Variant A: foo@2.5 (in range) → rule matches → no warning.
    let resolved_in_range = vec![
        ResolvedPackage {
            package: foo_pkg.clone(),
            version: NpmVersion::parse("2.5.0").unwrap(),
            dependencies: vec![("react".into(), "17.0.0".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];
    // Variant B: foo@1.5 (out of range) → rule doesn't apply → warning.
    let resolved_out_of_range = vec![
        ResolvedPackage {
            package: foo_pkg.clone(),
            version: NpmVersion::parse("1.5.0").unwrap(),
            dependencies: vec![("react".into(), "17.0.0".into())],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
        ResolvedPackage {
            package: react_pkg.clone(),
            version: NpmVersion::parse("17.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            optional: false,
        },
    ];

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::from(&foo_pkg),
        make_cached_info(
            &["2.5.0", "1.5.0"],
            vec![],
            vec![
                ("2.5.0", vec![("react", "^18.0.0")]),
                ("1.5.0", vec![("react", "^18.0.0")]),
            ],
        ),
    );
    cache.insert(
        CanonicalKey::from(&react_pkg),
        make_cached_info(&["17.0.0"], vec![], vec![]),
    );

    let mut allowed = HashMap::new();
    allowed.insert("foo@^2>react".into(), "17".into());
    let rules = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap();

    let in_range = check_unmet_peers(&resolved_in_range, &cache, &rules);
    assert!(
        in_range.is_empty(),
        "foo@2.5 satisfies ^2 → rule applies → no warning"
    );
    let out_of_range = check_unmet_peers(&resolved_out_of_range, &cache, &rules);
    assert_eq!(
        out_of_range.len(),
        1,
        "foo@1.5 outside ^2 → rule doesn't apply → warning"
    );
}

// ─── fail-closed compile ────────────────────

/// Unparseable selector key fails compile with a named-error.
#[test]
fn compile_rejects_unparseable_selector_key() {
    let mut allowed = HashMap::new();
    allowed.insert("a>b>c".into(), "1".into());
    let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
    assert!(
        err.contains("a>b>c"),
        "error must name the offending key: {err}"
    );
    assert!(err.contains("multi-segment"), "got: {err}");
}

/// Unparseable widened range fails compile with a named-error.
/// Mirrors the OverrideSet fail-closed posture for hand-authored
/// `lpm.overrides` typos.
#[test]
fn compile_rejects_unparseable_range() {
    let mut allowed = HashMap::new();
    allowed.insert("react".into(), "~~not-a-range".into());
    let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
    assert!(
        err.contains("react"),
        "error must name the offending key: {err}"
    );
    assert!(err.contains("range"), "got: {err}");
}

/// validate_allowed_versions_selector exposes the same parser to
/// the migrate planner — same errors, same shapes accepted.
#[test]
fn validate_allowed_versions_selector_exposes_same_parser() {
    // Same valid forms compile.
    for valid in [
        "react",
        "@scope/foo",
        "foo>react",
        "foo@^2>react",
        "@scope/foo@^2>react",
    ] {
        assert!(
            validate_allowed_versions_selector(valid).is_ok(),
            "expected {valid} to validate",
        );
    }
    // Same invalid forms reject — including every glob-wildcard
    // shape across every selector position.
    for invalid in [
        "",
        "a>b>c",
        "foo@2",
        "foo>react@2",
        ">react",
        "foo>",
        // bare wildcard
        "*",
        // scope wildcard
        "@scope/*",
        // suffix wildcard
        "*-eslint-plugin",
        // peer-half wildcard (after `>`)
        "foo>*",
        // parent-half wildcard
        "*>react",
        // wildcard inside scoped name
        "@*/foo>react",
    ] {
        assert!(
            validate_allowed_versions_selector(invalid).is_err(),
            "expected {invalid:?} to fail",
        );
    }
}

// ─── glob wildcards rejected at every selector position ──────────

/// Bare wildcard keys (`"*"`, `"@scope/*"`, `"*-suffix"`) are
/// rejected at compile time — `allowedVersions` uses the
/// structured selector grammar, not glob patterns. The
/// permissive registry-data validator [`is_valid_dep_name`]
/// would otherwise accept these (it only blocks path traversal
/// and null bytes) and let them silently no-op at runtime.
#[test]
fn allowed_versions_selector_rejects_bare_wildcard() {
    for bad in ["*", "@scope/*", "*-eslint-plugin"] {
        let err = AllowedVersionsSelector::parse(bad).unwrap_err();
        assert!(
            err.contains("wildcard") || err.contains("glob"),
            "expected wildcard rejection for {bad:?}, got: {err}"
        );
    }
}

/// Wildcards in the peer half of `parent>peer` are rejected.
#[test]
fn allowed_versions_selector_rejects_wildcard_in_peer_half() {
    let err = AllowedVersionsSelector::parse("foo>*").unwrap_err();
    assert!(
        err.contains("wildcard") || err.contains("glob"),
        "got: {err}"
    );
}

/// Wildcards in the parent half (with or without scope) are
/// rejected.
#[test]
fn allowed_versions_selector_rejects_wildcard_in_parent_half() {
    for bad in ["*>react", "@*/foo>react", "@scope/*>react"] {
        let err = AllowedVersionsSelector::parse(bad).unwrap_err();
        assert!(
            err.contains("wildcard") || err.contains("glob"),
            "expected wildcard rejection for {bad:?}, got: {err}"
        );
    }
}

/// Compile fails closed on a wildcard key — the `"*"` test that
/// previously locked in the fail-open behavior is now explicit
/// fail-closed. Documented contract honored on the wire.
#[test]
fn compile_rejects_wildcard_allowed_versions_keys() {
    let mut allowed = HashMap::new();
    allowed.insert("*".to_string(), "16 || 17".to_string());
    let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
    assert!(err.contains("\"*\""));
    assert!(err.contains("wildcard") || err.contains("glob"));
}

// ─── stricter selector-name predicate (real npm naming rules) ───

/// Malformed non-wildcard selector keys are rejected at compile
/// time. The previous `is_valid_selector_name` only added
/// wildcard rejection on top of the registry-hygiene helper,
/// which silently accepted spaces, uppercase letters, leading
/// `.`/`_`, and other npm-forbidden characters — those entries
/// would compile cleanly but never match anything at runtime
/// (silent no-op). Each name shape below must now error with a useful
/// message.
#[test]
fn allowed_versions_selector_rejects_malformed_non_wildcard_names() {
    // (raw_key, expected_error_position_hint)
    let cases: &[(&str, &str)] = &[
        // Spaces are not valid in npm names.
        ("foo bar", "peer name"),
        // Uppercase is rejected (npm requires lowercase).
        ("FooBar", "peer name"),
        ("@Scope/Foo", "peer name"),
        // Leading `.` and `_` are forbidden by npm.
        (".hidden", "peer name"),
        ("_private", "peer name"),
        // Special characters outside the allowed set.
        ("foo!bar", "peer name"),
        ("foo(bar)", "peer name"),
        ("foo'bar", "peer name"),
        ("foo+bar", "peer name"),
        // Same set of restrictions on the parent half of
        // `parent>peer` selectors.
        ("foo bar>react", "parent name"),
        ("FooBar>react", "parent name"),
        (".hidden>react", "parent name"),
        ("_private>react", "parent name"),
        // And on the peer half too.
        ("foo>react dom", "peer name"),
        ("foo>React", "peer name"),
        ("foo>.private", "peer name"),
    ];

    for (raw, expected_position) in cases {
        let err = AllowedVersionsSelector::parse(raw).unwrap_err();
        assert!(
            err.contains(expected_position),
            "expected {raw:?} error to mention {expected_position:?}, got: {err}"
        );
        assert!(
            err.contains("npm package name") || err.contains("must be a valid"),
            "expected {raw:?} error to point at the npm-naming contract, got: {err}"
        );
    }
}

/// Compile must error on malformed non-wildcard keys with a
/// named error — same fail-closed posture as the wildcard case.
/// Pins the contract so this class can't drift back into a
/// silent no-op.
#[test]
fn compile_rejects_malformed_non_wildcard_allowed_versions_keys() {
    let mut allowed = HashMap::new();
    allowed.insert("foo bar".to_string(), "1".to_string());
    let err = CompiledPeerRules::compile(&[], &allowed, &[]).unwrap_err();
    assert!(err.contains("\"foo bar\""), "must name the bad key: {err}");
    assert!(
        err.contains("npm package name") || err.contains("must be a valid"),
        "must point at the npm-naming contract: {err}"
    );
}

/// Real npm names accept the standard charset — verifies the new
/// predicate doesn't over-reject valid packages.
#[test]
fn allowed_versions_selector_accepts_realistic_npm_names() {
    for valid in [
        "react",
        "react-dom",
        "react.js",
        "react_dom",
        "react-router-dom",
        "lodash.debounce",
        "0auth",
        "@scope/foo",
        "@scope/foo-bar.baz_qux",
        // parent>peer with both sides standard names
        "foo>react",
        "@scope/foo>react",
        "@scope/foo@^2>react-dom",
    ] {
        assert!(
            AllowedVersionsSelector::parse(valid).is_ok(),
            "expected {valid:?} to compile as a valid selector"
        );
    }
}

/// Scoped package names whose package half starts with `.` or
/// `_` are valid per npm's spec — `validate-npm-package-name`
/// runs the leading-`.`/`_` check against the WHOLE name, which
/// for `@scope/_internal` starts with `@`. Must accept these
/// across every selector position they can appear in: bare
/// peer, peer half of `parent>peer`, parent name (with or
/// without version range).
#[test]
fn allowed_versions_selector_accepts_scoped_names_with_dot_or_underscore_prefix() {
    for valid in [
        // Bare peer — package half starts with `_` / `.`
        "@scope/_internal",
        "@scope/.config",
        "@types/_helpers",
        // parent>peer with the leading-char form on each half
        "@scope/_internal>react",
        "@scope/.config>react",
        "foo>@scope/_internal",
        "foo>@scope/.config",
        // parent@range>peer with the leading-char form on the
        // parent's package half
        "@scope/_internal@^2>react",
        "@scope/.config@^1>react",
        // Both halves of parent>peer using scoped leading-char
        "@scope/_internal>@types/_helpers",
    ] {
        assert!(
            AllowedVersionsSelector::parse(valid).is_ok(),
            "expected {valid:?} to compile (npm allows scoped package half \
                 to start with `.` or `_`)"
        );
    }
}

/// Unscoped names with leading `.` or `_` MUST still reject —
/// the loosening only applies to the package half of a scoped
/// name. This pins the asymmetry so it can't drift back to a
/// uniform restriction (or, worse, get flipped to uniform
/// permissiveness).
#[test]
fn allowed_versions_selector_still_rejects_unscoped_dot_or_underscore_prefix() {
    for invalid in [
        // Bare unscoped names — leading `.` / `_` rejected.
        ".hidden",
        "_private",
        // Same in the parent half of `parent>peer`.
        ".hidden>react",
        "_private>react",
        // Same in the peer half of `parent>peer`.
        "foo>.private",
        "foo>_private",
        // Scope itself rejects leading `.`/`_` (only the
        // package half is permissive).
        "@.bad/foo",
        "@_bad/foo",
        "@.bad/foo>react",
    ] {
        let err = AllowedVersionsSelector::parse(invalid).unwrap_err();
        assert!(
            err.contains("npm package name") || err.contains("must be a valid"),
            "expected {invalid:?} to fail with a name-contract error, got: {err}"
        );
    }
}

/// `validate_allowed_versions_range` exposes `NpmRange::parse`
/// to the migrate planner. Same parser the resolver uses at
/// install time — a range that migrates clean must compile clean.
#[test]
fn validate_allowed_versions_range_uses_npm_range_grammar() {
    // NpmRange honors the broader npm-compat grammar — unions,
    // hyphen ranges, x-ranges, the empty / `*` "any version"
    // shorthand, etc. A range that migrates clean must compile
    // clean, so the surface is intentionally permissive.
    for valid in [
        "16 || 17 || 18",
        ">=16 <19",
        "^4.17.21",
        "1.x",
        "*",
        "16 - 18",
    ] {
        assert!(
            validate_allowed_versions_range(valid).is_ok(),
            "expected {valid:?} to validate as a widened range"
        );
    }
    // Genuinely malformed inputs reject. The npm grammar is
    // lenient, so the rejection surface is small — but it's not
    // empty, and it must report the typo with a useful error.
    for invalid in ["~~not-a-range", "not-a-version"] {
        let err_result = validate_allowed_versions_range(invalid);
        assert!(
            err_result.is_err(),
            "expected {invalid:?} to fail as a widened range, got: {err_result:?}"
        );
    }
}
