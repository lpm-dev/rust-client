use super::deps::*;
use super::edge::*;
use super::fused::*;
use super::manifest::*;
use super::peer::*;
use super::policy::*;
use super::prelude::*;
use super::state::*;
use super::tree_policy::{
    TreeManifestProvider, TreeStatusCache, preferred_tree_compatible_version,
};
use super::types::*;
use super::version::*;
use crate::policy::{TrustPolicyMode, parse_npm_time_unix};
use crate::provider::{CachedDistInfo, CachedPackageInfo};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct ScopedEnvVars {
    originals: Vec<(&'static str, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ScopedEnvVars {
    fn set(vars: &[(&'static str, &'static str)]) -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let originals = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect();
        // SAFETY: the module-local lock serializes mutations of these
        // test-scoped environment variables.
        unsafe {
            for (key, value) in vars {
                std::env::set_var(key, value);
            }
        }
        Self {
            originals,
            _lock: guard,
        }
    }
}

impl Drop for ScopedEnvVars {
    fn drop(&mut self) {
        // SAFETY: see `ScopedEnvVars::set`.
        unsafe {
            for (key, value) in &self.originals {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// Build a minimal npm-packument JSON shape for wiremock-based
/// resolver tests. Mirrors `walker::tests::metadata_json` so the
/// fixture shape stays identical across resolver-arm tests.
fn metadata_json(name: &str, deps: &[(&str, &str)]) -> serde_json::Value {
    metadata_json_version(name, "1.0.0", deps)
}

fn metadata_json_version(name: &str, version: &str, deps: &[(&str, &str)]) -> serde_json::Value {
    let deps_obj: serde_json::Map<String, serde_json::Value> = deps
        .iter()
        .map(|(n, r)| (n.to_string(), serde_json::Value::String(r.to_string())))
        .collect();
    let mut versions = serde_json::Map::new();
    versions.insert(
        version.to_string(),
        serde_json::json!({
            "name": name,
            "version": version,
            "dist": {
                "tarball": "https://example.com/pkg.tgz",
                "integrity": "sha512-test"
            },
            "dependencies": deps_obj
        }),
    );
    let mut time = serde_json::Map::new();
    time.insert(
        version.to_string(),
        serde_json::Value::String("2025-01-01T00:00:00.000Z".to_string()),
    );
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": versions,
        "time": time
    })
}

fn version_document_json(name: &str, version: &str, deps: &[(&str, &str)]) -> serde_json::Value {
    let dependencies: serde_json::Map<String, serde_json::Value> = deps
        .iter()
        .map(|(name, range)| {
            (
                name.to_string(),
                serde_json::Value::String(range.to_string()),
            )
        })
        .collect();
    serde_json::json!({
        "name": name,
        "version": version,
        "dist": {
            "tarball": format!("https://example.invalid/{name}-{version}.tgz"),
            "integrity": format!("sha512-{name}-{version}")
        },
        "dependencies": dependencies
    })
}

/// Build a minimal CachedPackageInfo for a synthesized npm package.
/// `versions` are passed already in descending order to mirror
/// `parse_metadata_to_cache_info`'s contract.
fn mk_info(versions: &[&str], deps_of_latest: &[(&str, &str)]) -> CachedPackageInfo {
    let mut manifests: Vec<crate::provider::ManifestVersion> = versions
        .iter()
        .map(|version| crate::provider::ManifestVersion {
            version: NpmVersion::parse(version).unwrap(),
            dependencies: Vec::new(),
            peer_dependencies: Vec::new(),
            node_engine: None,
            platform: None,
            dist: CachedDistInfo {
                tarball_url: Some(format!("https://example.invalid/{version}.tgz")),
                integrity: Some(format!("sha512-fake-{version}")),
                ..CachedDistInfo::default()
            },
        })
        .collect();
    if let Some(latest) = manifests.first_mut() {
        latest.dependencies = deps_of_latest
            .iter()
            .map(|(name, range)| crate::provider::ManifestDependency {
                name: (*name).to_owned(),
                range: (*range).to_owned(),
                alias: None,
                optional: false,
                bundled: false,
            })
            .collect();
    }
    CachedPackageInfo::from_manifest_versions(
        None,
        false,
        true,
        HashSet::new(),
        HashSet::new(),
        true,
        None,
        manifests,
    )
}

fn edge_for_range(name: &str, range: &str) -> Edge {
    Edge {
        parent: 0,
        local_name: name.to_string(),
        canonical: CanonicalKey::npm(name),
        range: NpmRange::parse(range).expect("valid range"),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    }
}

#[test]
fn partial_worker_cache_refetches_for_uncovered_overlapping_range() {
    let mut info = mk_info(&["4.1.2"], &[]);
    info.versions_complete = false;
    info.covered_ranges.insert("^4.0.0".to_string());

    assert!(info.needs_metadata_for_range(&edge_for_range("shared", "*").range));
}

#[test]
fn partial_worker_cache_serves_worker_covered_range() {
    let mut info = mk_info(&["4.1.2"], &[]);
    info.versions_complete = false;
    info.covered_ranges.insert("^4.0.0".to_string());

    assert!(!info.needs_metadata_for_range(&edge_for_range("shared", "^4.0.0").range));
}

#[test]
fn workspace_cache_probes_the_registry_before_using_a_satisfying_local_version() {
    let mut info = mk_info(&["2.0.0"], &[]);
    info.versions_complete = false;
    info.workspace_versions
        .insert(NpmVersion::parse("2.0.0").expect("valid workspace version"));

    assert!(info.needs_metadata_for_range(&NpmRange::parse("^2.0.0").expect("valid range")));
}

#[test]
fn workspace_cache_requests_registry_metadata_for_a_nonmatching_range() {
    let mut info = mk_info(&["2.0.0"], &[]);
    info.versions_complete = false;
    info.workspace_versions
        .insert(NpmVersion::parse("2.0.0").expect("valid workspace version"));

    assert!(info.needs_metadata_for_range(&NpmRange::parse("^1.0.0").expect("valid range")));
}

#[test]
fn registry_not_found_activates_the_workspace_cache_as_authoritative() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("workspace-fallback");
    let mut workspace = mk_info(&["2.0.0"], &[]);
    workspace.versions_complete = false;
    workspace
        .workspace_versions
        .insert(NpmVersion::parse("2.0.0").expect("valid workspace version"));
    shared_cache.insert(canonical.clone(), Arc::new(workspace));

    let fallback = activate_workspace_fallback(&shared_cache, &canonical)
        .expect("workspace metadata should be available as a fallback");

    assert!(fallback.versions_complete);
    assert!(!fallback.needs_metadata_for_range(&NpmRange::parse("^2.0.0").unwrap()));
}

#[test]
fn successful_registry_metadata_replaces_same_version_workspace_metadata() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("source-boundary");
    let mut workspace = mk_info(&["1.0.0"], &[("local-child", "1.0.0")]);
    workspace.versions_complete = false;
    workspace
        .workspace_versions
        .insert(NpmVersion::parse("1.0.0").expect("valid workspace version"));
    shared_cache.insert(canonical.clone(), Arc::new(workspace));

    let registry = mk_info(&["1.0.0"], &[("registry-child", "1.0.0")]);
    let selected =
        insert_or_merge_cached_package_info(&shared_cache, canonical, Arc::new(registry));

    assert!(selected.workspace_versions.is_empty());
    assert!(selected.dependency("1.0.0", "registry-child").is_some());
    assert!(selected.dependency("1.0.0", "local-child").is_none());
}

#[test]
fn merging_partial_versions_drops_package_level_completeness() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("merge-me");

    let mut full = mk_info(&["2.0.0"], &[]);
    full.trust_metadata_complete = true;
    insert_or_merge_cached_package_info(&shared_cache, canonical.clone(), Arc::new(full));

    let mut partial = mk_info(&["3.0.0"], &[]);
    partial.versions_complete = false;
    partial.covered_ranges.insert("^3.0.0".to_string());
    let merged = insert_or_merge_cached_package_info(&shared_cache, canonical, Arc::new(partial));

    assert!(!merged.versions_complete);
    assert!(!merged.trust_metadata_complete);
    assert!(merged.covered_ranges.contains("^3.0.0"));
    assert!(
        merged
            .versions
            .iter()
            .any(|version| version.to_string() == "2.0.0")
    );
    assert!(
        merged
            .versions
            .iter()
            .any(|version| version.to_string() == "3.0.0")
    );
}

#[test]
fn complete_base_metadata_does_not_discard_existing_policy_hydration() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("policy-hydrated");
    let mut hydrated = mk_info(&["1.0.0"], &[]);
    hydrated.trust_metadata_complete = true;
    set_published_at(&mut hydrated, "1.0.0", "2026-07-20T17:38:38.286Z");
    insert_or_merge_cached_package_info(&shared_cache, canonical.clone(), Arc::new(hydrated));

    let base = mk_info(&["1.0.0"], &[]);
    let merged = insert_or_merge_cached_package_info(&shared_cache, canonical, Arc::new(base));

    assert_eq!(
        merged.published_at("1.0.0"),
        Some("2026-07-20T17:38:38.286Z")
    );
    assert!(merged.trust_metadata_complete);
}

#[test]
fn merging_cached_metadata_regular_dependency_shadows_same_named_peer_requirement() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("dual-role-dependency");
    let regular = mk_info(&["1.0.0"], &[("zod", "^4.3.6")]);
    insert_or_merge_cached_package_info(&shared_cache, canonical.clone(), Arc::new(regular));

    let mut peer_fragment = mk_info_with_peers(&["1.0.0"], &[], &[("zod", "^4.0.0")], &[]);
    peer_fragment.versions_complete = false;
    let merged =
        insert_or_merge_cached_package_info(&shared_cache, canonical, Arc::new(peer_fragment));

    assert!(
        merged.peer_dependency("1.0.0", "zod").is_none(),
        "a partial metadata merge must preserve regular-dependency precedence"
    );
}

#[test]
fn reinserting_identical_cached_metadata_reuses_the_existing_arc() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let canonical = CanonicalKey::npm("same-metadata");
    let info = Arc::new(mk_info(&["1.0.0"], &[]));
    shared_cache.insert(canonical.clone(), Arc::clone(&info));

    let reinserted =
        insert_or_merge_cached_package_info(&shared_cache, canonical, Arc::clone(&info));

    assert!(Arc::ptr_eq(&reinserted, &info));
}

#[test]
fn parse_fetched_metadata_omits_speculation_when_disabled() {
    let metadata = serde_json::from_value(metadata_json("spec-skip", &[("left-pad", "^1.0.0")]))
        .expect("fixture metadata should parse");

    let fetched = parse_fetched_metadata(metadata, false, false);

    assert!(fetched.speculation.is_none());
    assert_eq!(fetched.info.versions.len(), 1);
    assert!(
        fetched
            .shared_fact
            .as_ref()
            .is_some_and(|fact| Arc::ptr_eq(fact, &fetched.info))
    );
}

#[test]
fn full_policy_metadata_is_not_published_as_a_shared_base_fact() {
    let metadata = serde_json::from_value(metadata_json("policy-full", &[]))
        .expect("fixture metadata should parse");

    let fetched = parse_full_fetched_metadata(metadata, false, false);

    assert!(fetched.shared_fact.is_none());
}

#[test]
fn importer_policy_hydration_does_not_mutate_the_shared_base_fact() {
    let importer_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let shared_facts: SharedCache = Arc::new(dashmap::DashMap::new());
    let route_table = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
    let canonical = CanonicalKey::npm("policy-isolated");
    let base = Arc::new(mk_info(&["1.0.0"], &[]));
    publish_direct_base_fact(
        Some(&shared_facts),
        &route_table,
        &canonical,
        Some(Arc::clone(&base)),
    );

    let importer =
        cached_manifest_from_importer_or_facts(&importer_cache, Some(&shared_facts), &canonical)
            .expect("the importer should read the shared base fact");
    assert!(Arc::ptr_eq(&importer, &base));

    let mut hydrated = (*importer).clone();
    set_published_at(&mut hydrated, "1.0.0", "2025-01-01T00:00:00.000Z");
    importer_cache.insert(canonical.clone(), Arc::new(hydrated));

    assert!(
        shared_facts
            .get(&canonical)
            .is_some_and(|fact| fact.published_at("1.0.0").is_none())
    );
}

#[test]
fn parse_fetched_metadata_preserves_speculation_when_enabled() {
    let metadata = serde_json::from_value(metadata_json("spec-keep", &[("left-pad", "^1.0.0")]))
        .expect("fixture metadata should parse");

    let fetched = parse_fetched_metadata(metadata, true, false);

    let speculation = fetched
        .speculation
        .expect("speculation should be built when requested");
    assert_eq!(
        speculation
            .info
            .dependency("1.0.0", "left-pad")
            .map(|dependency| dependency.range),
        Some("^1.0.0")
    );
}

fn picked(p: VersionPick) -> NpmVersion {
    match p {
        VersionPick::Picked(v) => v,
        VersionPick::NoSatisfying => panic!("expected Picked, got NoSatisfying"),
        VersionPick::BlockedByReleaseAge { version, .. } => {
            panic!("expected Picked, got release-age block for {version}")
        }
        VersionPick::BlockedByTrustPolicy { version, reason } => {
            panic!("expected Picked, got trust-policy block for {version}: {reason}")
        }
    }
}

#[test]
fn find_best_version_picks_newest_match() {
    let info = mk_info(&["4.17.21", "4.17.20", "3.10.1", "3.0.0"], &[]);
    let range = NpmRange::parse("^4.0.0").unwrap();
    assert_eq!(
        picked(find_best_version(&info, &range)).to_string(),
        "4.17.21"
    );
}

#[test]
fn find_best_version_prefers_satisfying_latest_dist_tag() {
    let mut info = mk_info(&["1.0.0-next.28", "1.0.0-next.25"], &[]);
    info.latest_version = Some(NpmVersion::parse("1.0.0-next.25").unwrap());
    let range = NpmRange::parse("^1.0.0-next.25").unwrap();

    assert_eq!(
        picked(find_best_version(&info, &range)).to_string(),
        "1.0.0-next.25"
    );
}

#[test]
fn find_best_version_returns_no_satisfying_when_unsatisfied() {
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    let range = NpmRange::parse("^5.0.0").unwrap();
    assert!(matches!(
        find_best_version(&info, &range),
        VersionPick::NoSatisfying
    ));
}

#[test]
fn find_best_version_handles_exact_pin() {
    let info = mk_info(&["4.17.21", "4.17.20", "3.10.1"], &[]);
    let range = NpmRange::parse("4.17.20").unwrap();
    assert_eq!(
        picked(find_best_version(&info, &range)).to_string(),
        "4.17.20"
    );
}

fn set_published_at(info: &mut CachedPackageInfo, version: &str, published_at: &str) {
    assert!(info.update_manifest_version(version, |manifest| {
        manifest.dist.published_at = Some(published_at.to_string());
        manifest.dist.published_at_unix = parse_npm_time_unix(published_at);
    }));
}

fn set_trust_evidence(
    info: &mut CachedPackageInfo,
    version: &str,
    evidence: crate::policy::TrustEvidence,
) {
    assert!(info.update_manifest_version(version, |manifest| {
        manifest.dist.trust_evidence = Some(evidence);
    }));
}

#[test]
fn find_best_version_skips_too_fresh_latest_when_release_age_is_active() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.1.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let range = NpmRange::parse("^1.0.0").unwrap();

    assert_eq!(
        picked(find_best_version_with_policy(
            &CanonicalKey::npm("release-age-target"),
            &info,
            &range,
            &policy,
        ))
        .to_string(),
        "1.0.0"
    );
}

#[test]
fn find_best_version_latest_fallback_never_exceeds_dist_tag_target() {
    let mut info = mk_info(&["4.0.0", "3.1.0", "3.0.0"], &[]);
    info.latest_version = Some(NpmVersion::parse("3.1.0").unwrap());
    set_published_at(&mut info, "4.0.0", "2025-01-01T00:00:00.000Z");
    set_published_at(&mut info, "3.1.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut info, "3.0.0", "2025-01-01T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let range = NpmRange::parse("latest").unwrap();

    assert_eq!(
        picked(find_best_version_with_policy(
            &CanonicalKey::npm("release-age-target"),
            &info,
            &range,
            &policy,
        ))
        .to_string(),
        "3.0.0"
    );
}

#[test]
fn find_best_version_release_age_exclude_allows_latest_for_canonical_package() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.1.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix_and_release_age_excludes(
        86_400,
        1_735_776_000,
        Default::default(),
        [CanonicalKey::npm("release-age-target")],
    );
    let range = NpmRange::parse("^1.0.0").unwrap();

    assert_eq!(
        picked(find_best_version_with_policy(
            &CanonicalKey::npm("release-age-target"),
            &info,
            &range,
            &policy,
        ))
        .to_string(),
        "1.1.0"
    );
}

struct CountingTreeProvider {
    manifests: AHashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    cached: Mutex<AHashSet<CanonicalKey>>,
    ensure_calls: AtomicUsize,
}

impl TreeManifestProvider for CountingTreeProvider {
    fn cached_manifest(&self, canonical: &CanonicalKey) -> Option<Arc<CachedPackageInfo>> {
        self.cached
            .lock()
            .expect("cached manifests mutex poisoned")
            .contains(canonical)
            .then(|| self.manifests.get(canonical).cloned())
            .flatten()
    }

    fn ensure_manifest<'a>(
        &'a self,
        canonical: &'a CanonicalKey,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>> + Send + 'a>>
    {
        self.ensure_calls.fetch_add(1, Ordering::Relaxed);
        let result = self
            .manifests
            .get(canonical)
            .cloned()
            .ok_or_else(|| ResolveError::Internal(format!("missing manifest for {canonical}")));
        Box::pin(async move {
            let info = result?;
            self.cached
                .lock()
                .expect("cached manifests mutex poisoned")
                .insert(canonical.clone());
            Ok(info)
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn preferred_tree_compatible_version_reuses_cached_subtree_status_for_trust_policy() {
    let parent = CanonicalKey::npm("parent");
    let child = CanonicalKey::npm("child");
    let parent_info = mk_info(&["1.0.0"], &[("child", "^1.0.0")]);
    let child_info = Arc::new(mk_info(&["1.0.0"], &[]));
    let edge = Edge {
        parent: 0,
        local_name: "parent".to_string(),
        canonical: parent.clone(),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let policy = ResolverPolicy::new(0, TrustPolicyMode::NoDowngrade);
    let provider = CountingTreeProvider {
        manifests: AHashMap::from_iter([(child, child_info)]),
        cached: Mutex::new(AHashSet::new()),
        ensure_calls: AtomicUsize::new(0),
    };
    let mut cache = TreeStatusCache::default();

    let first =
        preferred_tree_compatible_version(&edge, &parent_info, &policy, &provider, &mut cache)
            .await;
    let second =
        preferred_tree_compatible_version(&edge, &parent_info, &policy, &provider, &mut cache)
            .await;

    assert_eq!(first, Some(NpmVersion::parse("1.0.0").unwrap()));
    assert_eq!(second, Some(NpmVersion::parse("1.0.0").unwrap()));
    assert_eq!(provider.ensure_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn preferred_tree_compatible_version_skips_subtree_walk_for_scoped_release_age() {
    let parent = CanonicalKey::npm("parent");
    let child = CanonicalKey::npm("child");
    let parent_info = mk_info(&["1.0.0"], &[("child", "^1.0.0")]);
    let child_info = Arc::new(mk_info(&["1.0.0"], &[]));
    let edge = Edge {
        parent: 0,
        local_name: "parent".to_string(),
        canonical: parent.clone(),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let policy = ResolverPolicy::with_cutoff_unix_and_release_age_packages(
        86_400,
        1_735_776_000,
        Default::default(),
        [parent],
    );
    let provider = CountingTreeProvider {
        manifests: AHashMap::from_iter([(child, child_info)]),
        cached: Mutex::new(AHashSet::new()),
        ensure_calls: AtomicUsize::new(0),
    };
    let mut cache = TreeStatusCache::default();

    let preferred =
        preferred_tree_compatible_version(&edge, &parent_info, &policy, &provider, &mut cache)
            .await;

    assert!(preferred.is_none());
    assert_eq!(provider.ensure_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn preferred_tree_compatible_version_skips_subtree_walk_for_transitive_edges() {
    let parent = CanonicalKey::npm("parent");
    let child = CanonicalKey::npm("child");
    let parent_info = mk_info(&["1.0.0"], &[("child", "^1.0.0")]);
    let child_info = Arc::new(mk_info(&["1.0.0"], &[]));
    let edge = Edge {
        parent: 1,
        local_name: "parent".to_string(),
        canonical: parent,
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let provider = CountingTreeProvider {
        manifests: AHashMap::from_iter([(child, child_info)]),
        cached: Mutex::new(AHashSet::new()),
        ensure_calls: AtomicUsize::new(0),
    };
    let mut cache = TreeStatusCache::default();

    let preferred =
        preferred_tree_compatible_version(&edge, &parent_info, &policy, &provider, &mut cache)
            .await;

    assert!(preferred.is_none());
    assert_eq!(provider.ensure_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn preferred_tree_compatible_version_uses_bounded_release_age_lookahead() {
    let parent = CanonicalKey::npm("parent");
    let child = CanonicalKey::npm("child");
    let mut parent_info = mk_info(&["1.1.0", "1.0.0"], &[("child", "^2.0.0")]);
    assert!(parent_info.update_manifest_version("1.0.0", |manifest| {
        manifest.dependencies = vec![crate::provider::ManifestDependency {
            name: "child".to_string(),
            range: "^1.0.0".to_string(),
            alias: None,
            optional: false,
            bundled: false,
        }];
    }));
    set_published_at(&mut parent_info, "1.1.0", "2025-01-01T00:00:00.000Z");
    set_published_at(&mut parent_info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let mut child_info = mk_info(&["2.0.0", "1.0.0"], &[]);
    set_published_at(&mut child_info, "2.0.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut child_info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let edge = Edge {
        parent: 0,
        local_name: "parent".to_string(),
        canonical: parent.clone(),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, TrustPolicyMode::Off);
    let provider = CountingTreeProvider {
        manifests: AHashMap::from_iter([(child, Arc::new(child_info))]),
        cached: Mutex::new(AHashSet::new()),
        ensure_calls: AtomicUsize::new(0),
    };
    let mut cache = TreeStatusCache::default();

    let preferred =
        preferred_tree_compatible_version(&edge, &parent_info, &policy, &provider, &mut cache)
            .await;

    assert_eq!(preferred, Some(NpmVersion::parse("1.0.0").unwrap()));
    assert_eq!(provider.ensure_calls.load(Ordering::Relaxed), 1);
    assert_eq!(cache.release_age_lookahead_fetches(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_metadata_refetches_full_packument_when_release_age_needs_publish_time() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(tmp.path().to_path_buf()));

    let abbreviated = serde_json::json!({
        "name": "release-age-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "release-age-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/release-age-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        }
    });
    let full = serde_json::json!({
        "name": "release-age-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "release-age-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/release-age-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z"
        }
    });

    Mock::given(method("GET"))
        .and(path("/release-age-fixture"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(abbreviated))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/release-age-fixture"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full))
        .expect(1)
        .mount(&server)
        .await;

    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("release-age-fixture");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());

    let fetched = fetch_metadata_for_resolver(&client, &route_table, &canonical, &policy, false)
        .await
        .expect("policy fetch should escalate to full metadata");

    assert_eq!(
        fetched.info.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_metadata_skips_release_times_when_package_modified_before_cutoff() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(tmp.path().to_path_buf()));

    let abbreviated = serde_json::json!({
        "name": "old-release-age-fixture",
        "modified": "2025-01-01T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "old-release-age-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/old-release-age-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/old-release-age-fixture"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(abbreviated))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/old-release-age-fixture"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("old-release-age-fixture");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());

    let fetched = fetch_metadata_for_resolver(&client, &route_table, &canonical, &policy, false)
        .await
        .expect("old modified timestamp should satisfy release-age without full metadata");

    assert_eq!(fetched.info.published_at("1.0.0"), None);
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_metadata_skips_release_times_for_unlisted_release_age_package_scope() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(tmp.path().to_path_buf()));

    let abbreviated = serde_json::json!({
        "name": "transitive-release-age-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "transitive-release-age-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/transitive-release-age-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/transitive-release-age-fixture"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(abbreviated))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/transitive-release-age-fixture"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("transitive-release-age-fixture");
    let policy = ResolverPolicy::with_cutoff_unix_and_release_age_packages(
        86_400,
        1_735_776_000,
        Default::default(),
        [CanonicalKey::npm("direct-release-age-fixture")],
    );

    fetch_metadata_for_resolver(&client, &route_table, &canonical, &policy, false)
        .await
        .expect("unlisted transitive package should not fetch release-time metadata");
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_metadata_merges_release_times_without_rehydrating_versions() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(Some(tmp.path().to_path_buf()));

    let abbreviated = serde_json::json!({
        "name": "release-time-merge-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "release-time-merge-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/release-time-merge-fixture.tgz",
                    "integrity": "sha512-release-time"
                },
                "dependencies": { "child": "^2.0.0" }
            }
        }
    });
    let release_times_only = serde_json::json!({
        "name": "release-time-merge-fixture",
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z"
        }
    });

    Mock::given(method("GET"))
        .and(path("/release-time-merge-fixture"))
        .and(header("Accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(abbreviated))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/release-time-merge-fixture"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(release_times_only))
        .expect(1)
        .mount(&server)
        .await;

    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("release-time-merge-fixture");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());

    let fetched = fetch_metadata_for_resolver(&client, &route_table, &canonical, &policy, false)
        .await
        .expect("policy fetch should merge release times into abbreviated metadata");

    assert_eq!(
        fetched
            .info
            .dependency("1.0.0", "child")
            .map(|dependency| dependency.range),
        Some("^2.0.0")
    );
    assert_eq!(
        fetched.info.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_metadata_uses_direct_full_when_worker_full_omits_release_time() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("cache temp dir");
    let client = RegistryClient::new()
        .with_base_url(proxy_server.uri())
        .with_npm_registry_url(npm_server.uri())
        .with_cache_dir(Some(tmp.path().to_path_buf()));

    let worker_missing_time = serde_json::json!({
        "name": "release-age-worker-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "release-age-worker-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/release-age-worker-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        }
    });
    let direct_full = serde_json::json!({
        "name": "release-age-worker-fixture",
        "modified": "2025-01-03T00:00:00.000Z",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "release-age-worker-fixture",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/release-age-worker-fixture.tgz",
                    "integrity": "sha512-release-age"
                },
                "dependencies": {}
            }
        },
        "time": {
            "1.0.0": "2025-01-01T00:00:00.000Z"
        }
    });

    let worker_requests = Arc::new(AtomicUsize::new(0));
    let worker_requests_for_responder = Arc::clone(&worker_requests);
    Mock::given(method("GET"))
        .and(path("/api/registry/release-age-worker-fixture"))
        .respond_with(move |request: &wiremock::Request| {
            let attempt = worker_requests_for_responder.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                assert_ne!(
                    request
                        .headers
                        .get("accept")
                        .and_then(|value| value.to_str().ok()),
                    Some("application/json")
                );
            } else {
                assert_eq!(
                    request
                        .headers
                        .get("accept")
                        .and_then(|value| value.to_str().ok()),
                    Some("application/json")
                );
            }
            ResponseTemplate::new(200).set_body_json(worker_missing_time.clone())
        })
        .expect(2)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/release-age-worker-fixture"))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(direct_full))
        .expect(1)
        .mount(&npm_server)
        .await;

    let route_table = RouteTable::from_mode_only(RouteMode::Proxy);
    let canonical = CanonicalKey::npm("release-age-worker-fixture");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());

    let fetched = fetch_metadata_for_resolver(&client, &route_table, &canonical, &policy, false)
        .await
        .expect("policy fetch should recover direct full metadata when Worker omits time");

    assert_eq!(worker_requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        fetched.info.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn find_best_version_ignores_platform_when_selecting_version() {
    // Platform filtering happens after resolution so lockfiles stay
    // portable. The newest semver-satisfying version wins even when
    // it is incompatible with the current host.
    let mut info = mk_info(&["1.0.0"], &[]);
    assert!(info.update_manifest_version("1.0.0", |manifest| {
        manifest.platform = Some(crate::provider::PlatformMeta {
            os: vec![
                "!darwin".to_string(),
                "!linux".to_string(),
                "!win32".to_string(),
                "!freebsd".to_string(),
                "!openbsd".to_string(),
                "!netbsd".to_string(),
                "!aix".to_string(),
                "!sunos".to_string(),
                "!android".to_string(),
            ],
            cpu: vec![],
            libc: vec![],
        });
    }));
    let range = NpmRange::parse("^1.0.0").unwrap();
    assert_eq!(
        picked(find_best_version(&info, &range)).to_string(),
        "1.0.0"
    );
}

#[test]
fn find_best_version_skips_trust_downgrade_when_older_candidate_satisfies_range() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    set_trust_evidence(
        &mut info,
        "1.0.0",
        crate::policy::TrustEvidence::TrustedPublisher,
    );
    set_published_at(&mut info, "1.1.0", "2025-01-02T00:00:00.000Z");
    let policy = ResolverPolicy::new(0, crate::policy::TrustPolicyMode::NoDowngrade);
    let range = NpmRange::parse("^1.0.0").unwrap();

    assert_eq!(
        picked(find_best_version_with_policy(
            &CanonicalKey::Root,
            &info,
            &range,
            &policy
        ))
        .to_string(),
        "1.0.0"
    );
}

#[test]
fn find_best_version_blocks_exact_trust_downgrade() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    set_trust_evidence(
        &mut info,
        "1.0.0",
        crate::policy::TrustEvidence::TrustedPublisher,
    );
    set_published_at(&mut info, "1.1.0", "2025-01-02T00:00:00.000Z");
    let policy = ResolverPolicy::new(0, crate::policy::TrustPolicyMode::NoDowngrade);
    let range = NpmRange::parse("1.1.0").unwrap();

    assert!(matches!(
        find_best_version_with_policy(&CanonicalKey::Root, &info, &range, &policy),
        VersionPick::BlockedByTrustPolicy { .. }
    ));
}

#[test]
fn find_best_version_unprofiled_does_not_record_policy_checks() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    set_trust_evidence(
        &mut info,
        "1.0.0",
        crate::policy::TrustEvidence::TrustedPublisher,
    );
    set_published_at(&mut info, "1.1.0", "2025-01-02T00:00:00.000Z");
    let policy = ResolverPolicy::new(0, crate::policy::TrustPolicyMode::NoDowngrade);
    let range = NpmRange::parse("1.1.0").unwrap();

    crate::profile::reset_all();

    assert!(matches!(
        find_best_version_with_policy_unprofiled(&CanonicalKey::Root, &info, &range, &policy),
        VersionPick::BlockedByTrustPolicy { .. }
    ));
    let policy_summary = crate::profile::policy_summary();
    assert_eq!(policy_summary.release_age.checked_count, 0);
    assert_eq!(policy_summary.trust_policy.checked_count, 0);
}

#[test]
fn seed_root_edges_orders_deterministically() {
    let mut deps = HashMap::new();
    deps.insert("zebra".to_string(), "^1.0.0".to_string());
    deps.insert("alpha".to_string(), "^1.0.0".to_string());
    deps.insert("middle".to_string(), "^1.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();
    let order: Vec<&str> = state
        .task_queue
        .iter()
        .map(|e| e.local_name.as_str())
        .collect();
    assert_eq!(order, vec!["alpha", "middle", "zebra"]);
}

#[test]
fn seed_root_edges_rewrites_npm_alias_root_dep() {
    // Root dep declared as `"local": "npm:target@range"` must
    // (a) emit an Edge whose canonical is keyed on the TARGET (`lodash`),
    // not the alias (`lodash-cjs`), so metadata fetch hits the right
    // package; (b) parse the inner range (`^4.17.21`); (c) preserve the
    // alias as `local_name` so the install pipeline knows which
    // `node_modules/<alias>/` slot to build; (d) record `local → target`
    // in `root_aliases` for
    // ResolveResult downstream consumption. Mirrors
    // `resolve_with_prefetch_handles_root_npm_alias`'s
    // contract on the legacy-pubgrub arm.
    let mut deps = HashMap::new();
    deps.insert("lodash-cjs".to_string(), "npm:lodash@^4.17.21".to_string());
    // A non-aliased sibling proves the alias-vs-non-alias branch
    // both work in one seeding pass.
    deps.insert("rxjs".to_string(), "^7.8.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();

    // root_aliases is populated only for the aliased entry.
    assert_eq!(state.root_aliases.len(), 1);
    assert_eq!(
        state.root_aliases.get("lodash-cjs"),
        Some(&"lodash".to_string())
    );

    // Edges keyed on canonical = target for the alias, canonical =
    // alias-key (== package name) for the non-alias.
    let edges_by_local: HashMap<&str, &Edge> = state
        .task_queue
        .iter()
        .map(|e| (e.local_name.as_str(), e))
        .collect();
    assert_eq!(edges_by_local.len(), 2);

    let alias_edge = edges_by_local["lodash-cjs"];
    assert_eq!(
        alias_edge.canonical,
        CanonicalKey::from_dep_name("lodash"),
        "alias canonical must be the TARGET, not the local key"
    );
    assert_eq!(
        alias_edge.local_name, "lodash-cjs",
        "local_name preserves the alias key for the install pipeline"
    );
    // Inner range must parse as a normal semver range. `^4.17.21`
    // satisfies 4.17.21 and not 5.0.0.
    let v_4_17_21 = NpmVersion::new(4, 17, 21);
    let v_5_0_0 = NpmVersion::new(5, 0, 0);
    assert!(alias_edge.range.satisfies(&v_4_17_21));
    assert!(!alias_edge.range.satisfies(&v_5_0_0));

    let plain_edge = edges_by_local["rxjs"];
    assert_eq!(
        plain_edge.canonical,
        CanonicalKey::from_dep_name("rxjs"),
        "non-alias canonical equals the dep name"
    );
}

#[test]
fn seed_root_edges_seeds_root_node() {
    let mut deps = HashMap::new();
    deps.insert("only".to_string(), "^1.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();
    assert_eq!(state.nodes.len(), 1);
    assert!(matches!(state.nodes[0].canonical, CanonicalKey::Root));
    assert_eq!(state.task_queue.len(), 1);
    assert_eq!(state.task_queue[0].parent, 0);
}

#[test]
fn process_edge_reuses_node_when_edges_select_the_same_version() {
    // Both compatible ranges naturally select 4.17.21, so their exact
    // selected package identity is shared by both parent edges.
    let info = mk_info(&["4.17.21"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();

    // Add a second parent (simulate a transitive that also needs lodash)
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("react"),
        version: NpmVersion::parse("18.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("react"),
        vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
    );
    state.task_queue.push_back(Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse("^4.10.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });

    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    // One lodash node (root + react + lodash = 3 nodes total).
    assert_eq!(state.nodes.len(), 3);
    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1);
    let (_, lodash_id) = lodash_entries[0];

    // Both root and react have an edge to that single lodash node.
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
fn transitive_edge_prefers_a_satisfying_root_selection_over_its_newer_natural_target() {
    let info = mk_info(&["1.1.0", "1.0.0"], &[]);
    let mut state = ResolveState::new(
        HashMap::from([("shared".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
    );
    state.seed_root_edges().unwrap();
    let root_edge = state.task_queue.pop_front().unwrap();
    process_edge(&root_edge, &info, &mut state).unwrap();
    let root_shared_id = state.nodes[0].children[0].1;
    let parent_id = push_node(&mut state, CanonicalKey::npm("range-parent"), "1.0.0");
    let transitive = Edge {
        parent: parent_id,
        local_name: "shared".to_string(),
        canonical: CanonicalKey::npm("shared"),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };

    process_edge(&transitive, &info, &mut state).unwrap();

    assert_eq!(
        state.nodes[parent_id as usize].children[0].1,
        root_shared_id
    );
    assert_eq!(state.resolved[&CanonicalKey::npm("shared")].len(), 1);
    assert_eq!(state.work_stats.edge_reuse_range_count, 1);
}

#[test]
fn unchanged_override_selection_does_not_reuse_a_different_satisfying_root_version() {
    let info = mk_info(&["1.1.0", "1.0.0"], &[]);
    let mut state = ResolveState::new(
        HashMap::from([("shared".to_string(), "1.1.0".to_string())]),
        OverrideSet::empty(),
    );
    state.seed_root_edges().unwrap();
    let root_edge = state.task_queue.pop_front().unwrap();
    process_edge(&root_edge, &info, &mut state).unwrap();
    let root_shared_id = state.nodes[0].children[0].1;

    state.overrides = override_set("shared", "1.0.0");
    let parent_id = push_node(&mut state, CanonicalKey::npm("range-parent"), "1.0.0");
    let transitive = Edge {
        parent: parent_id,
        local_name: "shared".to_string(),
        canonical: CanonicalKey::npm("shared"),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };

    process_edge_with_preferred(
        &transitive,
        &info,
        Some(NpmVersion::parse("1.0.0").unwrap()),
        &mut state,
    )
    .unwrap();

    let selected_id = state.nodes[parent_id as usize].children[0].1;
    assert_ne!(selected_id, root_shared_id);
    assert_eq!(
        state.nodes[selected_id as usize].version.to_string(),
        "1.0.0"
    );
    assert_eq!(state.resolved[&CanonicalKey::npm("shared")].len(), 2);
    assert!(state.overrides.take_hits().is_empty());
}

fn overlapping_range_targets(broad_first: bool) -> (String, String) {
    let info = mk_info(&["2.0.3", "1.0.1"], &[]);
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let narrow_parent = push_node(&mut state, CanonicalKey::npm("narrow-parent"), "1.0.0");
    let broad_parent = push_node(&mut state, CanonicalKey::npm("broad-parent"), "1.0.0");
    let narrow = Edge {
        parent: narrow_parent,
        local_name: "shared".to_string(),
        canonical: CanonicalKey::npm("shared"),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let broad = Edge {
        parent: broad_parent,
        local_name: "shared".to_string(),
        canonical: CanonicalKey::npm("shared"),
        range: NpmRange::parse("1 - 2").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let edges = if broad_first {
        [broad, narrow]
    } else {
        [narrow, broad]
    };
    for edge in edges {
        process_edge(&edge, &info, &mut state).unwrap();
    }
    let selected = |parent: NodeId| {
        let child = state.nodes[parent as usize].children[0].1;
        state.nodes[child as usize].version.to_string()
    };
    (selected(narrow_parent), selected(broad_parent))
}

#[test]
fn process_edge_overlapping_range_targets_are_independent_of_edge_order() {
    let narrow_first = overlapping_range_targets(false);
    let broad_first = overlapping_range_targets(true);

    assert_eq!(narrow_first, broad_first);
    assert_eq!(narrow_first, ("1.0.1".to_string(), "2.0.3".to_string()));
}

#[test]
fn process_edge_records_work_stats_for_allocation_and_reuse() {
    let info = mk_info(&["4.17.21"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();

    let root_edge = state.task_queue.pop_front().unwrap();
    process_edge(&root_edge, &info, &mut state).unwrap();

    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("react"),
        version: NpmVersion::parse("18.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("react"),
        vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
    );
    let reuse_edge = Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse("^4.10.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    process_edge(&reuse_edge, &info, &mut state).unwrap();

    assert_eq!(state.work_stats.edge_process_count, 2);
    assert_eq!(state.work_stats.node_allocated_count, 1);
    assert_eq!(state.work_stats.edge_reuse_count, 1);
    assert_eq!(state.work_stats.edge_reuse_range_count, 0);
    assert_eq!(state.work_stats.edge_reuse_exact_count, 1);
}

#[test]
fn process_edge_counts_override_path_no_version_attempt() {
    let info = mk_info(&["4.17.21"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^99.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("lodash", "4.17.21"));
    state.seed_root_edges().unwrap();

    let root_edge = state.task_queue.pop_front().unwrap();
    let result = process_edge(&root_edge, &info, &mut state);

    assert!(result.is_err());
    assert_eq!(state.work_stats.edge_process_count, 1);
    assert_eq!(state.work_stats.node_allocated_count, 0);
    assert_eq!(state.work_stats.edge_reuse_count, 0);
}

#[test]
fn selected_package_cardinality_counts_duplicate_canonicals() {
    let packages = vec![
        ResolvedPackage {
            resolution_id: lpm_common::ResolutionNodeId::UNASSIGNED,
            dependency_targets: HashMap::new(),
            optional_dependencies: HashSet::new(),
            peer_targets: HashMap::new(),
            package: ResolverPackage::Npm {
                name: "debug".to_string(),
                context: None,
            },
            version: NpmVersion::parse("2.6.9").unwrap(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            node_engine: None,
            optional: false,
        },
        ResolvedPackage {
            resolution_id: lpm_common::ResolutionNodeId::UNASSIGNED,
            dependency_targets: HashMap::new(),
            optional_dependencies: HashSet::new(),
            peer_targets: HashMap::new(),
            package: ResolverPackage::Npm {
                name: "debug".to_string(),
                context: None,
            },
            version: NpmVersion::parse("4.4.3").unwrap(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            node_engine: None,
            optional: false,
        },
        ResolvedPackage {
            resolution_id: lpm_common::ResolutionNodeId::UNASSIGNED,
            dependency_targets: HashMap::new(),
            optional_dependencies: HashSet::new(),
            peer_targets: HashMap::new(),
            package: ResolverPackage::Npm {
                name: "ms".to_string(),
                context: None,
            },
            version: NpmVersion::parse("2.1.3").unwrap(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            node_engine: None,
            optional: false,
        },
    ];

    assert_eq!(selected_package_cardinality(&packages), (3, 2, 1));
}

#[test]
fn process_edge_emits_selected_package_event_only_for_new_nodes() {
    let info = mk_info(&["4.17.21"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    state.set_selected_package_tx(Some(tx));
    state.seed_root_edges().unwrap();

    let root_edge = state.task_queue.pop_front().unwrap();
    process_edge(&root_edge, &info, &mut state).unwrap();

    let event = rx.try_recv().expect("new node should emit selection event");
    assert_eq!(event.name, "lodash");
    assert_eq!(event.version, "4.17.21");
    assert_eq!(
        event.tarball_url.as_deref(),
        Some("https://example.invalid/4.17.21.tgz")
    );
    assert_eq!(event.integrity.as_deref(), Some("sha512-fake-4.17.21"));

    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("react"),
        version: NpmVersion::parse("18.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("react"),
        vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
    );
    let reuse_edge = Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse("^4.10.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    process_edge(&reuse_edge, &info, &mut state).unwrap();

    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn process_edge_allocates_second_version_on_incompatible_range() {
    // Two parents wanting INCOMPATIBLE ranges of the same canonical
    // (^4.0.0 picks 4.17.21; ^3.0.0 cannot reuse 4.17.21 → must
    // allocate a new node for 3.10.1). Both versions live in the
    // resolved tree as distinct nodes.
    // This is the case the PubGrub split-retry workaround was
    // grafted on for; greedy handles it natively.
    let info = mk_info(&["4.17.21", "4.0.0", "3.10.1", "3.0.0"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();

    // Second parent wants ^3 — incompatible with the first parent's ^4.
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("legacy-shim"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("legacy-shim"),
        vec![(NpmVersion::parse("1.0.0").unwrap(), 1)],
    );
    state.task_queue.push_back(Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse("^3.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });

    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    // root + legacy-shim + lodash@4.17.21 + lodash@3.10.1 = 4 nodes
    assert_eq!(state.nodes.len(), 4);

    // Two lodash entries with different versions
    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 2);
    let mut versions: Vec<String> = lodash_entries.iter().map(|(v, _)| v.to_string()).collect();
    versions.sort();
    assert_eq!(versions, vec!["3.10.1", "4.17.21"]);

    // Root's edge points at the ^4.0.0-satisfying node (4.17.21)
    let root_lodash_id = state.nodes[0]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();
    assert_eq!(
        state.nodes[root_lodash_id as usize].version.to_string(),
        "4.17.21"
    );

    // legacy-shim's edge points at the ^3.0.0-satisfying node (3.10.1)
    let shim_lodash_id = state.nodes[1]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();
    assert_eq!(
        state.nodes[shim_lodash_id as usize].version.to_string(),
        "3.10.1"
    );
}

// ── Override application on the greedy arm ─────────────────────
//
// Tests pin the contract: user-declared `lpm.overrides` /
// `package.json > overrides` take effect on the default resolver
// path. Exercises three semantic surfaces of `OverrideSet::find_match`:
//   - Name selectors (apply to every resolution of a canonical)
//   - Path selectors (apply only via a specific parent)
//   - Targets outside a consumer range (force the override target)

/// Helper: build an OverrideSet from a single `lpm.overrides`
/// entry. Path-selector tests use a separate path-key form via
/// the same parser.
fn override_set(key: &str, target: &str) -> OverrideSet {
    let mut lpm = HashMap::new();
    lpm.insert(key.to_string(), target.to_string());
    OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new()).expect("test override should parse")
}

#[test]
fn apply_override_target_greedy_rejects_release_age_blocked_target() {
    let canonical = CanonicalKey::npm("release-age-override-target");
    let mut info = mk_info(&["2.0.0", "1.0.0"], &[]);
    set_published_at(&mut info, "2.0.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let target = OverrideTarget::PinnedVersion {
        raw: "2.0.0".to_string(),
        version: NpmVersion::parse("2.0.0").unwrap(),
    };

    assert!(apply_override_target_greedy(&canonical, &info, &target, &policy).is_none());
}

#[test]
fn process_edge_applies_name_selector_override() {
    // `lpm.overrides: { "lodash": "3.10.1" }` — every lodash
    // resolution is forced to 3.10.1, even when the consumer's
    // range nominally satisfies 4.17.21. Mirrors
    // `LpmDependencyProvider::choose_version` semantics.
    let info = mk_info(&["4.17.21", "4.0.0", "3.10.1", "3.0.0"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^3.0.0 || ^4.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("lodash", "3.10.1"));
    state.seed_root_edges().unwrap();
    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1, "single forced version");
    assert_eq!(lodash_entries[0].0.to_string(), "3.10.1");

    let hits = state.overrides.take_hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].package, "lodash");
    assert_eq!(hits[0].from_version, "4.17.21");
    assert_eq!(hits[0].to_version, "3.10.1");
    assert_eq!(hits[0].via_parent, None, "Name selector — no parent ctx");
}

#[test]
fn process_edge_range_target_replaces_consumer_range() {
    // The override range replaces the consumer range, then selects the
    // newest published version that satisfies the override.
    let info = mk_info(&["4.17.21", "3.10.1", "3.0.0"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("lodash", "^3.0.0"));
    state.seed_root_edges().unwrap();
    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1);
    assert_eq!(
        lodash_entries[0].0.to_string(),
        "3.10.1",
        "newest version in the override's 3.x range"
    );
}

#[test]
fn process_edge_pinned_override_replaces_consumer_range() {
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("lodash", "3.10.1"));
    state.seed_root_edges().unwrap();
    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1);
    assert_eq!(
        lodash_entries[0].0.to_string(),
        "3.10.1",
        "the pinned override replaces the consumer's declared range"
    );
    let hits = state.overrides.take_hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].from_version, "4.17.21");
    assert_eq!(hits[0].to_version, "3.10.1");
}

#[test]
fn process_edge_unpublished_override_target_falls_back_to_natural_version() {
    let info = mk_info(&["4.17.21"], &[]);
    let mut state = ResolveState::new(
        HashMap::from([("lodash".to_string(), "^4.0.0".to_string())]),
        override_set("lodash", "99.0.0"),
    );
    state.seed_root_edges().unwrap();

    let edge = state.task_queue.pop_front().unwrap();
    process_edge(&edge, &info, &mut state).unwrap();

    assert_eq!(
        state.resolved[&CanonicalKey::npm("lodash")][0]
            .0
            .to_string(),
        "4.17.21"
    );
    assert!(state.overrides.take_hits().is_empty());
}

#[test]
fn process_edge_path_selector_splits_two_parents() {
    // `lpm.overrides: { "react>lodash": "3.10.1" }` — only the
    // edge originating from `react` is forced; the root-level
    // `lodash` edge keeps its natural pick. Two distinct lodash
    // nodes coexist in the resolved tree (split-by-context).
    //
    // split_targets gate: this test enqueues the override-bearing
    // edge BEFORE the natural edge, so the
    // override allocates `lodash@3.10.1` first; the subsequent
    // root edge must NOT silently inherit that forced version
    // via range-satisfies dedupe (3.10.1 satisfies `>=3.0.0`).
    // The regression was a path-selector override leaking into every
    // sibling of `react`. `OverrideSet::split_targets` (containing
    // "lodash") forces exact-match dedupe on every slow-path edge, so
    // the root edge allocates the natural 4.17.21 in its own node.
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), ">=3.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("react>lodash", "3.10.1"));

    // Hand-seed both parents WITHOUT calling `seed_root_edges()`,
    // which would push the root>lodash edge first. Reverse order
    // (react edge enqueued before root edge) is what surfaces the
    // override-leak regression.
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::Root,
        version: NpmVersion::new(0, 0, 0),
        optional: false,
        children: Vec::new(),
    });
    state
        .resolved
        .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("react"),
        version: NpmVersion::parse("18.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("react"),
        vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
    );

    // React edge first — applies override, allocates lodash@3.10.1.
    state.task_queue.push_back(Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse(">=3.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });
    // Root edge second — must allocate natural 4.17.21, NOT reuse
    // the forced 3.10.1 the react edge just allocated.
    state.task_queue.push_back(Edge {
        parent: 0,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse(">=3.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });

    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    let mut versions: Vec<String> = lodash_entries.iter().map(|(v, _)| v.to_string()).collect();
    versions.sort();
    assert_eq!(
        versions,
        vec!["3.10.1", "4.17.21"],
        "path-selector override splits lodash into two versions \
         regardless of edge processing order"
    );

    // The root edge resolved to natural (4.17.21).
    let root_lodash_id = state.nodes[0]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();
    assert_eq!(
        state.nodes[root_lodash_id as usize].version.to_string(),
        "4.17.21",
        "root edge must resolve to natural pick (not leaked from earlier-allocated forced node)"
    );

    // The react edge resolved to the override (3.10.1).
    let react_lodash_id = state.nodes[1]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();
    assert_eq!(
        state.nodes[react_lodash_id as usize].version.to_string(),
        "3.10.1"
    );

    let hits = state.overrides.take_hits();
    assert_eq!(hits.len(), 1, "only the path-selector edge records a hit");
    assert_eq!(hits[0].via_parent.as_deref(), Some("react"));
    assert_eq!(hits[0].to_version, "3.10.1");
}

#[test]
fn process_edge_path_selector_does_not_leak_to_sibling_parent() {
    // Regression test: two transitive parents pull the same
    // canonical: `react > lodash` (path-selector matched) and
    // `redux > lodash` (NOT matched). The override edge processes
    // first, allocating `lodash@3.10.1`. Without the
    // `split_targets` gate, the redux edge's range-satisfies dedupe
    // would find 3.10.1 satisfying `>=3.0.0` and silently reuse —
    // leaking the path-selector override into a parent the user
    // didn't select. With the gate, redux gets the natural pick
    // (4.17.21) in its own node.
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    // No root-level lodash edge — the leak is parent-to-parent
    // among transitive deps, not parent-to-root.
    let deps = HashMap::new();
    let mut state = ResolveState::new(deps, override_set("react>lodash", "3.10.1"));

    // Root pseudo-node + two parents.
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::Root,
        version: NpmVersion::new(0, 0, 0),
        optional: false,
        children: Vec::new(),
    });
    state
        .resolved
        .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("react"),
        version: NpmVersion::parse("18.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("react"),
        vec![(NpmVersion::parse("18.0.0").unwrap(), 1)],
    );
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("redux"),
        version: NpmVersion::parse("4.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state.resolved.insert(
        CanonicalKey::npm("redux"),
        vec![(NpmVersion::parse("4.0.0").unwrap(), 2)],
    );

    // React's lodash edge first (path-selector match, override applies).
    state.task_queue.push_back(Edge {
        parent: 1,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse(">=3.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });
    // Redux's lodash edge second (no path-selector match, must
    // allocate natural — must NOT reuse react's forced 3.10.1).
    state.task_queue.push_back(Edge {
        parent: 2,
        local_name: "lodash".to_string(),
        canonical: CanonicalKey::npm("lodash"),
        range: NpmRange::parse(">=3.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });

    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let react_lodash_id = state.nodes[1]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();
    let redux_lodash_id = state.nodes[2]
        .children
        .iter()
        .find(|(name, _)| name == "lodash")
        .map(|(_, id)| *id)
        .unwrap();

    assert_eq!(
        state.nodes[react_lodash_id as usize].version.to_string(),
        "3.10.1",
        "react > lodash applies the path-selector override"
    );
    assert_eq!(
        state.nodes[redux_lodash_id as usize].version.to_string(),
        "4.17.21",
        "redux > lodash does NOT inherit react's forced version (split_targets gate)"
    );
    assert_ne!(
        react_lodash_id, redux_lodash_id,
        "the two parents resolve to distinct lodash nodes"
    );
}

// ── bundleDependencies skip ───────────────────────────────────

#[test]
fn enqueue_child_deps_skips_bundled_names() {
    // Parent declares `bundleDependencies: ["lodash"]` AND
    // `dependencies: { lodash: "^4", react: "^18" }`. The
    // resolver must NOT enqueue `lodash` as a separate edge —
    // it's vendored inside the parent's tarball — but must still
    // enqueue `react`.
    let mut info = mk_info(&["1.0.0"], &[("lodash", "^4.0.0"), ("react", "^18.0.0")]);
    assert!(info.update_manifest_version("1.0.0", |manifest| {
        manifest
            .dependencies
            .iter_mut()
            .find(|dependency| dependency.name == "lodash")
            .expect("lodash fixture dependency")
            .bundled = true;
    }));

    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .unwrap();

    let queued: Vec<&str> = state
        .task_queue
        .iter()
        .map(|e| e.local_name.as_str())
        .collect();
    assert_eq!(
        queued,
        vec!["react"],
        "lodash skipped (bundled); react enqueued"
    );
}

#[test]
fn enqueue_child_deps_no_bundled_names_unchanged() {
    // Sanity baseline: with no bundleDependencies, every dep
    // gets enqueued (the no-bundling fast path is byte-identical
    // to the unbundled fast path).
    let info = mk_info(&["1.0.0"], &[("lodash", "^4.0.0"), ("react", "^18.0.0")]);
    // No bundled_dep_names entry for 1.0.0.

    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .unwrap();

    let mut queued: Vec<&str> = state
        .task_queue
        .iter()
        .map(|e| e.local_name.as_str())
        .collect();
    queued.sort();
    assert_eq!(queued, vec!["lodash", "react"]);
}

#[test]
fn enqueue_child_deps_omits_optional_dependencies_when_disabled() {
    let mut info = mk_info(
        &["1.0.0"],
        &[("required-child", "^1.0.0"), ("optional-child", "^2.0.0")],
    );
    assert!(info.update_manifest_version("1.0.0", |manifest| {
        manifest
            .dependencies
            .iter_mut()
            .find(|dependency| dependency.name == "optional-child")
            .expect("optional-child fixture dependency")
            .optional = true;
    }));

    let mut state = ResolveState::new_with_options(HashMap::new(), OverrideSet::empty(), false);
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .unwrap();

    let queued: Vec<&str> = state
        .task_queue
        .iter()
        .map(|edge| edge.local_name.as_str())
        .collect();
    assert_eq!(queued, vec!["required-child"]);
}

// ── workspace: defense-in-depth at resolver entry ────────────

#[test]
fn seed_root_edges_rejects_workspace_specifier() {
    // A `workspace:*` root dep means lpm-workspace's upstream
    // rewrite step missed this entry — the resolver must surface
    // a specific error pointing at the real cause, not propagate
    // an opaque semver-parse failure from `NpmRange::parse`.
    let mut deps = HashMap::new();
    deps.insert("internal-pkg".to_string(), "workspace:*".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    let err = state.seed_root_edges().unwrap_err();
    match err {
        ResolveError::Internal(msg) => {
            assert!(
                msg.contains("workspace:") && msg.contains("lpm-workspace"),
                "error must point at the workspace-rewrite layer: {msg}"
            );
        }
        other => panic!("expected Internal error, got {other:?}"),
    }
}

#[test]
fn enqueue_child_deps_rejects_required_workspace_specifier() {
    let info = mk_info(
        &["1.0.0"],
        &[("workspace-leak", "workspace:^1"), ("plain-dep", "^2.0.0")],
    );

    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    let error = enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .expect_err("required workspace dependency must fail");

    assert!(error.to_string().contains("workspace-leak"));
}

#[test]
fn enqueue_child_deps_skips_workspace_edge_for_selected_workspace_version() {
    let mut info = mk_info(
        &["1.0.0"],
        &[
            ("registry-child", "^2.0.0"),
            ("workspace-child", "workspace:*"),
        ],
    );
    info.workspace_versions
        .insert(NpmVersion::parse("1.0.0").unwrap());
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("workspace-parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });

    enqueue_child_deps(
        0,
        &CanonicalKey::npm("workspace-parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .unwrap();

    assert_eq!(state.task_queue.len(), 1);
    assert_eq!(state.task_queue[0].local_name, "registry-child");
}

#[test]
fn enqueue_child_deps_rejects_workspace_edge_for_unmarked_selected_version() {
    let mut info = mk_info(&["2.0.0"], &[("workspace-child", "workspace:*")]);
    info.workspace_versions
        .insert(NpmVersion::parse("1.0.0").unwrap());
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("registry-parent"),
        version: NpmVersion::parse("2.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });

    let error = enqueue_child_deps(
        0,
        &CanonicalKey::npm("registry-parent"),
        &NpmVersion::parse("2.0.0").unwrap(),
        &info,
        &mut state,
    )
    .expect_err("workspace marker for another version must not exempt registry metadata");

    assert!(error.to_string().contains("workspace-child"));
}

#[test]
fn enqueue_child_deps_rejects_invalid_required_range() {
    let info = mk_info(&[("1.0.0")], &[("malformed-child", "~X0^.00")]);
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });

    let error = enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .expect_err("invalid required range must fail");

    let message = error.to_string();
    assert!(message.contains("parent@1.0.0"));
    assert!(message.contains("malformed-child"));
    assert!(message.contains("~X0^.00"));
}

#[test]
fn is_workspace_specifier_detects_the_prefix() {
    assert!(is_workspace_specifier("workspace:*"));
    assert!(is_workspace_specifier("workspace:^1.0.0"));
    assert!(is_workspace_specifier("  workspace:~"));
    assert!(!is_workspace_specifier("^1.0.0"));
    assert!(!is_workspace_specifier("npm:foo@^1"));
    assert!(!is_workspace_specifier(""));
    // The match is on the literal prefix; `workspaces:` (typo)
    // should NOT trigger so the caller's normal range-parse
    // failure surfaces the real issue.
    assert!(!is_workspace_specifier("workspaces:*"));
}

// ── Eager-peer collection tests ───────────────────────────────
//
// Peer-collection contract:
//   1. Every `peerDependencies` entry on the (canonical, version)
//      under enqueue produces ONE `PeerRequirement` on
//      `state.peer_requirements`.
//   2. Peers are NEVER pushed to `state.task_queue` and NEVER
//      added to the consumer's `n.children`.
//   3. Defenses (workspace, invalid range, alias rewrite) match
//      the regular-deps loop semantically.
//   4. `optional_peer_names` flag propagates onto the
//      requirement's `optional` field.
//
// The peer-drain pass then reads `state.peer_requirements` and
// synthesizes root-scoped ambient install edges through the fused
// dispatcher, consuming well-formed requirements produced here.

/// Build a `CachedPackageInfo` with peer_deps + optional_peer_names
/// populated for a single version. Mirrors `mk_info`'s shape.
fn mk_info_with_peers(
    versions: &[&str],
    deps_of_latest: &[(&str, &str)],
    peers_of_latest: &[(&str, &str)],
    optional_peers_of_latest: &[&str],
) -> CachedPackageInfo {
    let mut info = mk_info(versions, deps_of_latest);
    let Some(latest) = versions.first() else {
        return info;
    };
    let optional_peers = optional_peers_of_latest
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    assert!(info.update_manifest_version(latest, |manifest| {
        manifest.peer_dependencies = peers_of_latest
            .iter()
            .map(|(name, range)| crate::provider::ManifestPeerDependency {
                name: (*name).to_owned(),
                range: (*range).to_owned(),
                alias: None,
                optional: optional_peers.contains(name),
            })
            .collect();
    }));
    info
}

/// Drive `enqueue_child_deps` against a freshly-allocated parent
/// node and return the mutated state for assertion. Encapsulates
/// the ResolveState scaffolding that every peer-collection test needs.
fn enqueue_for_parent(parent_canonical: CanonicalKey, info: &CachedPackageInfo) -> ResolveState {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: parent_canonical.clone(),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    enqueue_child_deps(
        0,
        &parent_canonical,
        &NpmVersion::parse("1.0.0").unwrap(),
        info,
        &mut state,
    )
    .unwrap();
    state
}

#[test]
fn peer_collection_records_one_requirement_per_peer() {
    // Parent declares `peerDependencies: { react: "^18.0.0" }`.
    // After `enqueue_child_deps`, exactly one PeerRequirement
    // should be on the worklist — keyed on the consumer node id,
    // canonical "react", and parsed range "^18.0.0".
    let info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    assert_eq!(
        state.peer_requirements.len(),
        1,
        "exactly one peer requirement should be recorded"
    );
    let req = &state.peer_requirements[0];
    assert_eq!(req.consumer, 0, "consumer id is the parent node");
    assert_eq!(req.peer_name, "react");
    assert_eq!(req.canonical, CanonicalKey::npm("react"));
    assert!(
        req.range.satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "range parsed correctly (18.2.0 satisfies ^18.0.0)"
    );
    assert!(!req.optional, "optional flag defaults to false");
}

#[test]
fn peer_collection_runs_when_sparse_cache_omits_empty_dependency_entry() {
    let info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);

    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    assert_eq!(state.task_queue.len(), 0);
    assert_eq!(state.peer_requirements.len(), 1);
    assert_eq!(state.peer_requirements[0].peer_name, "react");
}

#[test]
fn peer_collection_does_not_push_to_task_queue() {
    // Peers go on `peer_requirements`, NOT `task_queue`. If a
    // future regression switches the push site, this test fires.
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[("regular-dep", "^1.0.0")],
        &[("peer-dep", "^2.0.0")],
        &[],
    );
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    let queued: Vec<&str> = state
        .task_queue
        .iter()
        .map(|e| e.local_name.as_str())
        .collect();
    assert_eq!(
        queued,
        vec!["regular-dep"],
        "task_queue gets ONLY regular deps; peers must not leak in"
    );
    assert_eq!(state.peer_requirements.len(), 1);
    assert_eq!(state.peer_requirements[0].peer_name, "peer-dep");
}

#[test]
fn peer_collection_regular_dependency_shadows_same_named_peer_requirement() {
    let info = mk_info_with_peers(&["1.0.0"], &[("zod", "^4.3.6")], &[("zod", "^4.0.0")], &[]);
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    assert_eq!(state.task_queue.len(), 1);
    assert_eq!(state.task_queue[0].local_name, "zod");
    assert!(
        state.peer_requirements.is_empty(),
        "a regular dependency must not also create peer context for the same local name"
    );
}

#[test]
fn peer_collection_does_not_mutate_consumer_children() {
    // **Contract assertion.** The consumer node's `children` list
    // must not gain a peer entry. If a future change accidentally
    // pushes a peer onto `n.children`, the v2 graph-key derivation
    // would silently fold the peer into the dependency portion of
    // the key, breaking peer-divergent link-entry isolation.
    let info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    assert!(
        state.nodes[0].children.is_empty(),
        "consumer.children must remain empty when only peers are declared \
         (peer collection must not write to children)"
    );
    assert_eq!(state.peer_requirements.len(), 1);
}

#[test]
fn peer_collection_optional_flag_propagated() {
    // `peerDependenciesMeta.optional: true` lands in
    // `info.optional_peer_names`. The collector copies the flag
    // onto the requirement so the peer-drain step can skip
    // ambient-install synthesis for opted-out peers.
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[("react", "^18.0.0"), ("redux", "^4.0.0")],
        &["react"], // react is optional, redux is required
    );
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);

    assert_eq!(state.peer_requirements.len(), 2);
    let mut by_name: HashMap<&str, &PeerRequirement> = HashMap::new();
    for req in &state.peer_requirements {
        by_name.insert(req.peer_name.as_str(), req);
    }
    assert!(
        by_name["react"].optional,
        "react is in optional_peer_names → optional=true"
    );
    assert!(
        !by_name["redux"].optional,
        "redux is NOT in optional_peer_names → optional=false"
    );
}

#[test]
fn peer_collection_alias_aware() {
    // npm permits a peer to be declared via alias —
    // `"my-react": "npm:react@^18"` is equivalent to
    // `peerDependencies: { react: "^18" }` re-keyed under
    // `my-react`. The collector must record the canonical as
    // `react` (registry identity) so the peer-drain fetches the right
    // manifest, while preserving the local `peer_name = "my-react"`
    // for the eventual `ResolvedPackage.peers` edge label.
    let mut info = mk_info_with_peers(&["1.0.0"], &[], &[("my-react", "^18.0.0")], &[]);
    assert!(info.update_manifest_version("1.0.0", |manifest| {
        manifest
            .peer_dependencies
            .first_mut()
            .expect("peer alias fixture")
            .alias = Some("react".to_string());
    }));

    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
    assert_eq!(state.peer_requirements.len(), 1);
    let req = &state.peer_requirements[0];
    assert_eq!(req.peer_name, "my-react", "local name preserved");
    assert_eq!(
        req.canonical,
        CanonicalKey::npm("react"),
        "canonical resolved through alias to the registry target"
    );
}

#[test]
fn peer_collection_rejects_required_workspace_specifier() {
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[("legit-peer", "^1.0.0"), ("internal-peer", "workspace:*")],
        &[],
    );
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    let error = enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .expect_err("required workspace peer must fail");
    assert!(error.to_string().contains("internal-peer"));
}

#[test]
fn peer_collection_skips_workspace_peer_for_selected_workspace_version() {
    let mut info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[
            ("registry-peer", "^1.0.0"),
            ("workspace-peer", "workspace:*"),
        ],
        &[],
    );
    info.workspace_versions
        .insert(NpmVersion::parse("1.0.0").unwrap());
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("workspace-parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });

    enqueue_child_deps(
        0,
        &CanonicalKey::npm("workspace-parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .unwrap();

    assert_eq!(state.peer_requirements.len(), 1);
    assert_eq!(state.peer_requirements[0].peer_name, "registry-peer");
}

#[test]
fn peer_collection_rejects_invalid_required_range() {
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[("good-peer", "^1.0.0"), ("bad-peer", "~X0^.00")],
        &[],
    );
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("parent"),
        version: NpmVersion::parse("1.0.0").unwrap(),
        optional: false,
        children: Vec::new(),
    });
    let error = enqueue_child_deps(
        0,
        &CanonicalKey::npm("parent"),
        &NpmVersion::parse("1.0.0").unwrap(),
        &info,
        &mut state,
    )
    .expect_err("invalid required peer range must fail");
    assert!(error.to_string().contains("bad-peer"));
}

#[test]
fn peer_collection_skips_invalid_optional_range() {
    let info = mk_info_with_peers(&["1.0.0"], &[], &[("bad-peer", "~X0^.00")], &["bad-peer"]);
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
    assert!(state.peer_requirements.is_empty());
}

#[test]
fn peer_collection_deterministic_order() {
    // The collector sorts peer entries alphabetically before
    // pushing — same contract as the regular-deps loop. Without
    // this, HashMap iteration order would leak into
    // `peer_requirements`'s order, producing non-reproducible
    // lockfile output when the peer-drain drives ambient-install
    // edge ordering off the worklist.
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        // Insertion order is intentionally the WORST possible
        // for a stable sort: reverse-alphabetic.
        &[("zoo", "^1.0.0"), ("middle", "^1.0.0"), ("alpha", "^1.0.0")],
        &[],
    );
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
    let names: Vec<&str> = state
        .peer_requirements
        .iter()
        .map(|r| r.peer_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["alpha", "middle", "zoo"],
        "peer requirements sorted alphabetically for determinism"
    );
}

#[test]
fn peer_collection_no_peer_deps_is_empty_worklist() {
    // Hot path / sanity baseline: a package with NO peer
    // declarations produces an empty worklist. This test guards
    // against an accidental regression where peer collection becomes
    // noisy (e.g., a stray `entry().or_insert_with` populating
    // empty entries).
    let info = mk_info(&["1.0.0"], &[("regular", "^1.0.0")]);
    let state = enqueue_for_parent(CanonicalKey::npm("parent"), &info);
    assert!(state.peer_requirements.is_empty());
    assert_eq!(state.task_queue.len(), 1, "regular dep enqueued normally");
}

// ── Eager peer auto-install drain tests ──────────────────────
//
// `drain_peer_requirements_one_pass` contract:
//   1. Pure classify-and-synthesize pass: reads `state.resolved`
//      and `state.peer_requirements`, fetches manifests for
//      unmet canonicals via the supplied closure, and returns
//      ambient root-scoped Edges for the caller to drain.
//   2. Satisfied groups (some node in `state.resolved` already
//      threads every range) are SKIPPED — no synthesis, the
//      existing `into_resolved_packages` peer-derivation handles
//      output.
//   3. All-optional groups are SKIPPED regardless of
//      `auto_install_peers`.
//   4. With `auto_install_peers = false`, ALL groups are
//      skipped — warn-only behavior.
//   5. Required-but-unsatisfiable groups (no version threads
//      every range) raise `ResolveError::PeerConflict`.
//   6. Synthesized Edges are root-scoped (`parent = 0`), behave
//      as regular required deps, and pin the canonical to the
//      exact chosen version.
//
// These tests drive the helper directly with a hand-built
// closure that returns pre-canned manifests. End-to-end
// integration through the dispatcher is exercised by the
// resolve-tier tests in `resolve::tests`.

/// Stand-in for an `Arc<CachedPackageInfo>` returned by the
/// fetch closure. Tests pre-populate a name → info map and the
/// closure looks up by canonical name.
fn mk_info_arc(versions: &[&str], deps_of_latest: &[(&str, &str)]) -> Arc<CachedPackageInfo> {
    Arc::new(mk_info(versions, deps_of_latest))
}

/// Build a minimal `state.peer_requirements` entry. The
/// `consumer` is encoded as a plain `NodeId` — tests pre-create
/// the consumer node so `state.nodes[consumer]` resolves for
/// `PeerConflict` error rendering.
fn mk_peer_req(
    consumer: NodeId,
    peer_name: &str,
    canonical: CanonicalKey,
    range: &str,
    optional: bool,
) -> PeerRequirement {
    PeerRequirement {
        consumer,
        peer_name: peer_name.to_string(),
        canonical,
        range: NpmRange::parse(range).unwrap(),
        optional,
    }
}

#[test]
fn peer_resolution_cache_key_uses_canonical_and_sorted_parent_peer_context() {
    let legacy_req = mk_peer_req(1, "react", CanonicalKey::npm("react"), "^17.0.0", false);
    let modern_req = mk_peer_req(2, "react", CanonicalKey::npm("react"), "^18.0.0", false);

    let canonical = CanonicalKey::npm("react");
    let forward = peer_resolution_cache_key(&canonical, &[&legacy_req, &modern_req]);
    let reversed = peer_resolution_cache_key(&canonical, &[&modern_req, &legacy_req]);
    assert_eq!(
        forward, reversed,
        "parent peer context hash must be order-insensitive"
    );

    let other_range_req = mk_peer_req(2, "react", CanonicalKey::npm("react"), "^19.0.0", false);
    let other_range = peer_resolution_cache_key(&canonical, &[&legacy_req, &other_range_req]);
    assert_ne!(
        forward, other_range,
        "different parent peer context must miss the cache"
    );

    let other_canonical =
        peer_resolution_cache_key(&CanonicalKey::npm("preact"), &[&legacy_req, &modern_req]);
    assert_ne!(
        forward, other_canonical,
        "same parent context for a different peer canonical must miss the cache"
    );
}

/// Pre-allocate a consumer node and return its NodeId. Mirrors
/// what `process_edge` would produce after consuming a regular
/// dep edge for the consumer.
fn push_node(state: &mut ResolveState, canonical: CanonicalKey, version: &str) -> NodeId {
    let id = state.nodes.len() as NodeId;
    state.nodes.push(ResolvedNodeBuilder {
        canonical: canonical.clone(),
        version: NpmVersion::parse(version).unwrap(),
        optional: false,
        children: Vec::new(),
    });
    state
        .resolved
        .entry(canonical)
        .or_default()
        .push((NpmVersion::parse(version).unwrap(), id));
    id
}

#[test]
fn process_edge_reuses_existing_node_for_the_natural_target_version() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let shared = CanonicalKey::npm("shared");
    let older = push_node(&mut state, shared.clone(), "1.2.0");
    let newer = push_node(&mut state, shared.clone(), "1.9.0");

    state.resolved.insert(
        shared.clone(),
        vec![
            (NpmVersion::parse("1.2.0").unwrap(), older),
            (NpmVersion::parse("1.9.0").unwrap(), newer),
        ],
    );

    let edge = Edge {
        parent: 0,
        local_name: "shared".to_string(),
        canonical: shared,
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let info = mk_info(&["1.9.0", "1.2.0"], &[]);

    process_edge(&edge, &info, &mut state).unwrap();

    assert_eq!(
        state.nodes[0].children,
        vec![("shared".to_string(), newer)],
        "reuse must target the edge's natural selection"
    );
}

#[test]
fn root_edge_allocates_best_version_when_only_lower_existing_version_satisfies_range() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let shared = CanonicalKey::npm("shared");
    push_node(&mut state, shared.clone(), "1.2.0");

    let edge = Edge {
        parent: 0,
        local_name: "shared".to_string(),
        canonical: shared.clone(),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    };
    let info = mk_info(&["1.9.0", "1.2.0"], &[]);

    process_edge(&edge, &info, &mut state).unwrap();

    let root_shared_id = state.nodes[0]
        .children
        .iter()
        .find(|(name, _)| name == "shared")
        .map(|(_, id)| *id)
        .unwrap();
    assert_eq!(
        state.nodes[root_shared_id as usize].version.to_string(),
        "1.9.0",
        "root dependency edges must pick their natural best version, not a lower transitive version that already satisfies the range"
    );
    let mut versions: Vec<String> = state.resolved[&shared]
        .iter()
        .map(|(version, _)| version.to_string())
        .collect();
    versions.sort();
    assert_eq!(versions, vec!["1.2.0", "1.9.0"]);
}

#[test]
fn into_resolved_packages_binds_peer_by_consumer_range() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let plugin_id = push_node(&mut state, CanonicalKey::npm("plugin"), "1.0.0");
    let react_17_id = push_node(&mut state, CanonicalKey::npm("react"), "17.0.2");
    push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    state.record_exact_peer_binding(plugin_id, "react".to_string(), react_17_id);

    let mut cache = HashMap::new();
    cache.insert(
        CanonicalKey::npm("plugin"),
        Arc::new(mk_info_with_peers(
            &["1.0.0"],
            &[],
            &[("react", "^17.0.0")],
            &[],
        )),
    );
    cache.insert(
        CanonicalKey::npm("react"),
        mk_info_arc(&["18.2.0", "17.0.2"], &[]),
    );

    let resolved = state.into_resolved_packages(&cache, &HashMap::new());
    let plugin = resolved
        .iter()
        .find(|pkg| pkg.package.canonical_name() == "plugin")
        .expect("plugin package present");
    assert_eq!(
        plugin.peers,
        vec![lpm_common::PeerEdge::registry("react", "react", "17.0.2")],
        "greedy finalization should preserve the peer selected for this exact consumer"
    );
    assert_eq!(
        plugin.peer_targets.get("react"),
        Some(&lpm_common::ResolutionNodeId::new(react_17_id)),
    );
}

#[test]
fn into_resolved_packages_recomputes_required_reachability_from_the_final_graph() {
    let mut state = ResolveState::new(
        HashMap::from([("required-parent".to_string(), "1.0.0".to_string())]),
        OverrideSet::empty(),
    );
    state.seed_root_edges().expect("seed required root");
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("required-parent"),
        version: NpmVersion::parse("1.0.0").expect("valid parent version"),
        optional: false,
        children: vec![("required-child".to_string(), 2)],
    });
    state.nodes.push(ResolvedNodeBuilder {
        canonical: CanonicalKey::npm("required-child"),
        version: NpmVersion::parse("1.0.0").expect("valid child version"),
        optional: true,
        children: Vec::new(),
    });
    state.nodes[0].children = vec![("required-parent".to_string(), 1)];
    let cache = HashMap::from([
        (
            CanonicalKey::npm("required-parent"),
            Arc::new(mk_info(&["1.0.0"], &[("required-child", "1.0.0")])),
        ),
        (
            CanonicalKey::npm("required-child"),
            Arc::new(mk_info(&["1.0.0"], &[])),
        ),
    ]);

    let packages = state.into_resolved_packages(&cache, &HashMap::new());
    let child = packages
        .iter()
        .find(|package| package.package.canonical_name() == "required-child")
        .expect("required child should be resolved");

    assert!(!child.optional);
}

#[tokio::test]
async fn peer_drain_satisfied_by_existing_skips_synthesis() {
    // The peer's canonical already has a node in the resolved
    // tree (e.g., react was a regular root dep) at a version
    // satisfying every consumer's range. The drain pass must
    // detect this and skip synthesis entirely — no fetch, no
    // ambient install.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let synth = drain_peer_requirements_one_pass(
        &mut state,
        true,
        // Closure must NOT be called — satisfied-by-existing
        // should short-circuit before any fetch.
        |canonical: CanonicalKey| async move {
            panic!("fetch closure called for already-satisfied peer {canonical}")
        },
    )
    .await
    .unwrap();
    assert!(
        synth.is_empty(),
        "no ambient install when peer is satisfied"
    );
    assert!(state.peer_requirements.is_empty(), "worklist drained");
}

#[tokio::test]
async fn peer_drain_synthesizes_ambient_for_missing_peer() {
    // The peer's canonical is NOT in the tree. With
    // `auto_install_peers = true`, the drain pass fetches the
    // manifest, picks the newest version satisfying the
    // consumer's range, and synthesizes a root-scoped Edge
    // pinning that version.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "18.0.0", "17.0.2"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |canonical: CanonicalKey| {
        let info = info_arc.clone();
        async move {
            assert_eq!(canonical, CanonicalKey::npm("react"));
            Ok(info)
        }
    })
    .await
    .unwrap();

    assert_eq!(synth.len(), 1, "exactly one ambient install");
    let edge = &synth[0];
    assert_eq!(edge.parent, 0, "ambient install is root-scoped");
    assert_eq!(edge.canonical, CanonicalKey::npm("react"));
    assert_eq!(edge.local_name, "react");
    assert!(
        edge.range.satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "exact-pin range satisfies the chosen version"
    );
    assert!(
        !edge.range.satisfies(&NpmVersion::parse("19.0.0").unwrap()),
        "exact-pin range does NOT satisfy a sibling version"
    );
    assert!(
        edge.behavior.required && !edge.behavior.peer && !edge.behavior.optional,
        "ambient install behaves as a required regular dep"
    );
}

#[tokio::test]
async fn peer_drain_skips_a_too_new_version_when_release_age_is_active() {
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());
    let mut state = ResolveState::new_with_options_and_policy(
        HashMap::new(),
        OverrideSet::empty(),
        true,
        policy,
    );
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("peer-consumer"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "peer-host",
        CanonicalKey::npm("peer-host"),
        "^1.0.0",
        false,
    ));
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.1.0", "2025-01-03T00:00:00.000Z");
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    let info = Arc::new(info);

    let synthesized = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = Arc::clone(&info);
        async move { Ok(info) }
    })
    .await
    .expect("an older policy-compliant peer version should be selected");

    assert_eq!(synthesized.len(), 1);
    assert!(
        synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("1.0.0").unwrap())
    );
    assert!(
        !synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("1.1.0").unwrap())
    );
}

#[tokio::test]
async fn peer_drain_latest_never_selects_above_the_dist_tag_target() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("peer-consumer"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "peer-host",
        CanonicalKey::npm("peer-host"),
        "latest",
        false,
    ));
    let mut info = mk_info(&["4.0.0", "3.1.0", "3.0.0"], &[]);
    info.latest_version = Some(NpmVersion::parse("3.1.0").unwrap());
    let info = Arc::new(info);

    let synthesized = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = Arc::clone(&info);
        async move { Ok(info) }
    })
    .await
    .expect("the latest peer tag should synthesize an ambient provider");

    assert_eq!(synthesized.len(), 1);
    assert!(
        synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("3.1.0").unwrap())
    );
    assert!(
        !synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("4.0.0").unwrap())
    );
}

#[tokio::test]
async fn peer_drain_latest_does_not_bind_an_existing_version_above_the_dist_tag() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    push_node(&mut state, CanonicalKey::npm("peer-host"), "4.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("peer-consumer"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "peer-host",
        CanonicalKey::npm("peer-host"),
        "latest",
        false,
    ));
    let mut info = mk_info(&["4.0.0", "3.1.0"], &[]);
    info.latest_version = Some(NpmVersion::parse("3.1.0").unwrap());
    let info = Arc::new(info);

    let synthesized = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = Arc::clone(&info);
        async move { Ok(info) }
    })
    .await
    .expect("latest must synthesize the dist-tag target instead of binding 4.0.0");

    assert_eq!(synthesized.len(), 1);
    assert!(
        synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("3.1.0").unwrap())
    );
}

#[tokio::test]
async fn peer_drain_reuses_resolution_for_same_parent_peer_context_regardless_order() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");
    let modern = push_node(&mut state, CanonicalKey::npm("modern"), "2.0.0");

    let legacy_req = mk_peer_req(
        legacy,
        "react",
        CanonicalKey::npm("react"),
        "^17.0.0",
        false,
    );
    let modern_req = mk_peer_req(
        modern,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    );
    state.peer_requirements.push(legacy_req.clone());
    state.peer_requirements.push(modern_req.clone());

    let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
    let fetch_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        let fetch_count = fetch_count.clone();
        async move {
            fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(info)
        }
    })
    .await
    .unwrap();
    assert_eq!(first.len(), 1);

    state.peer_requirements.push(modern_req);
    state.peer_requirements.push(legacy_req);

    let second = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        let fetch_count = fetch_count.clone();
        async move {
            fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(info)
        }
    })
    .await
    .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(
        fetch_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "same peer canonical + same parent peer context should reuse the cached decision"
    );
}

#[tokio::test]
async fn peer_drain_telemetry_distinguishes_repeated_cached_and_satisfied_work() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    let react_consumer = push_node(&mut state, CanonicalKey::npm("react-user"), "1.0.0");
    let vue_consumer = push_node(&mut state, CanonicalKey::npm("vue-user"), "1.0.0");
    let optional_consumer = push_node(&mut state, CanonicalKey::npm("optional-user"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        react_consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));
    let vue_requirement = mk_peer_req(
        vue_consumer,
        "vue",
        CanonicalKey::npm("vue"),
        "^3.0.0",
        false,
    );
    state.peer_requirements.push(vue_requirement.clone());
    state.peer_requirements.push(mk_peer_req(
        optional_consumer,
        "optional-peer",
        CanonicalKey::npm("optional-peer"),
        "^1.0.0",
        true,
    ));

    let vue_info = mk_info_arc(&["3.5.0"], &[]);
    let first = drain_peer_requirements_one_pass(&mut state, true, |canonical| {
        let vue_info = vue_info.clone();
        async move {
            assert_eq!(canonical, CanonicalKey::npm("vue"));
            Ok(vue_info)
        }
    })
    .await
    .expect("first peer drain should resolve the missing required peer");
    assert_eq!(first.len(), 1);

    state.peer_requirements.push(vue_requirement);
    let second = drain_peer_requirements_one_pass(&mut state, true, |canonical| async move {
        panic!("cached peer decision should not refetch {canonical}")
    })
    .await
    .expect("second peer drain should reuse the cached decision");
    assert_eq!(second.len(), 1);

    let snapshot = state.peer_work_stats.snapshot();
    assert_eq!(
        (
            snapshot.non_empty_pass_count,
            snapshot.requirement_count,
            snapshot.unique_requirement_count,
            snapshot.group_count,
            snapshot.already_satisfied_group_count,
            snapshot.classified_group_count,
            snapshot.skipped_opt_out_group_count,
            snapshot.resolution_cache_hit_count,
            snapshot.resolution_cache_miss_count,
            snapshot.manifest_lookup_count,
            snapshot.synthesized_edge_count,
        ),
        (2, 4, 3, 4, 1, 3, 1, 1, 1, 1, 2)
    );
}

#[tokio::test]
async fn required_peer_binding_promotes_an_existing_optional_provider() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let provider = push_node(&mut state, CanonicalKey::npm("peer-host"), "1.0.0");
    state.nodes[provider as usize].optional = true;
    let consumer = push_node(&mut state, CanonicalKey::npm("peer-consumer"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "peer-host",
        CanonicalKey::npm("peer-host"),
        "^1.0.0",
        false,
    ));

    let synthesized = drain_peer_requirements_one_pass(&mut state, true, |canonical| async move {
        panic!("existing peer provider must not fetch {canonical}")
    })
    .await
    .expect("bind existing peer provider");

    assert!(synthesized.is_empty());
    assert!(!state.nodes[provider as usize].optional);
}

#[tokio::test]
async fn peer_drain_cached_best_effort_reports_current_unsatisfied_consumers() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let first_legacy = push_node(&mut state, CanonicalKey::npm("legacy-one"), "1.0.0");
    let first_modern = push_node(&mut state, CanonicalKey::npm("modern-one"), "2.0.0");

    state.peer_requirements.push(mk_peer_req(
        first_legacy,
        "react",
        CanonicalKey::npm("react"),
        "^17.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        first_modern,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
    let fetch_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        let fetch_count = fetch_count.clone();
        async move {
            fetch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(info)
        }
    })
    .await
    .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(state.peer_conflicts.len(), 1);
    assert_eq!(
        state.peer_conflicts[0].unsatisfied_consumers,
        vec![("legacy-one".to_string(), "^17.0.0".to_string())]
    );

    state.peer_conflicts.clear();
    let second_legacy = push_node(&mut state, CanonicalKey::npm("legacy-two"), "1.0.0");
    let second_modern = push_node(&mut state, CanonicalKey::npm("modern-two"), "2.0.0");
    state.peer_requirements.push(mk_peer_req(
        second_modern,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        second_legacy,
        "react",
        CanonicalKey::npm("react"),
        "^17.0.0",
        false,
    ));

    let second =
        drain_peer_requirements_one_pass(&mut state, true, |canonical: CanonicalKey| async move {
            panic!("cached best-effort resolution should not refetch {canonical}")
        })
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(fetch_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(state.peer_conflicts.len(), 1);
    assert_eq!(state.peer_conflicts[0].canonical, "react");
    assert_eq!(state.peer_conflicts[0].chosen_version, "18.2.0");
    assert_eq!(
        state.peer_conflicts[0].unsatisfied_consumers,
        vec![("legacy-two".to_string(), "^17.0.0".to_string())],
        "cached best-effort decisions must render warnings from the current consumers"
    );
}

#[tokio::test]
async fn peer_drain_cached_resolution_does_not_override_existing_satisfaction() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    let req = mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    );

    state.peer_requirements.push(req.clone());
    let info_arc = mk_info_arc(&["18.2.0"], &[]);
    let first = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();
    assert_eq!(first.len(), 1);

    let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    state.peer_requirements.push(req);

    let second =
        drain_peer_requirements_one_pass(&mut state, true, |canonical: CanonicalKey| async move {
            panic!("cache hit must not run before existing satisfaction for {canonical}")
        })
        .await
        .unwrap();
    assert!(
        second.is_empty(),
        "live resolved tree satisfaction wins over a cached synthesize decision"
    );
}

#[tokio::test]
async fn peer_drain_picks_newest_satisfying_all_consumer_ranges() {
    // Two consumers declare the SAME peer at compatible-but-
    // distinct ranges. The drain must pick a version satisfying
    // BOTH ranges (intersection semantic), not just the first
    // consumer's range.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_a = push_node(&mut state, CanonicalKey::npm("pkg-a"), "1.0.0");
    let consumer_b = push_node(&mut state, CanonicalKey::npm("pkg-b"), "1.0.0");

    // Consumer A wants `>=18.0.0`, Consumer B wants `<19.0.0`.
    // Intersection: `>=18.0.0 <19.0.0`. Newest available: 18.2.0.
    state.peer_requirements.push(mk_peer_req(
        consumer_a,
        "react",
        CanonicalKey::npm("react"),
        ">=18.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer_b,
        "react",
        CanonicalKey::npm("react"),
        "<19.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "17.0.2"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();

    assert_eq!(synth.len(), 1, "one ambient install for the joined group");
    assert!(
        synth[0]
            .range
            .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "chose newest version satisfying both consumer ranges"
    );
    assert!(
        !synth[0]
            .range
            .satisfies(&NpmVersion::parse("19.0.0").unwrap()),
        "did NOT pick the newest overall (19.0.0 violates consumer B's <19.0.0)"
    );
}

#[tokio::test]
async fn peer_drain_best_effort_synthesizes_for_incompatible_required_ranges() {
    // Two required consumers declare incompatible ranges (`^17` vs
    // `^18`). No version satisfies both. Previously this raised
    // `PeerConflict` and broke real-world installs (nestjs's transitive
    // ajv-keywords chain). Now: pick the version satisfying the most
    // consumers, ambient-install it, and record the unsatisfied ones in
    // `state.peer_conflicts` for the install pipeline to warn about.
    // Mirrors hoisted peer-resolution behavior.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_a = push_node(&mut state, CanonicalKey::npm("legacy-pkg"), "1.0.0");
    let consumer_b = push_node(&mut state, CanonicalKey::npm("modern-pkg"), "2.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer_a,
        "react",
        CanonicalKey::npm("react"),
        "^17.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer_b,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .expect("best-effort synthesis must NOT raise PeerConflict");

    assert_eq!(
        synth.len(),
        1,
        "exactly one ambient install — the chosen peer version"
    );
    // Tied hit count (each version satisfies one consumer).
    // Newest-first walk picks 18.2.0 first; the tiebreak favors
    // it over 17.0.2.
    assert!(
        synth[0]
            .range
            .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "newest tied-hit version wins (18.2.0 satisfies modern-pkg)"
    );

    // Conflict report must record the unsatisfied required
    // consumer (legacy-pkg wants ^17 but we picked 18.2.0).
    assert_eq!(
        state.peer_conflicts.len(),
        1,
        "one conflict report for the react peer group"
    );
    let report = &state.peer_conflicts[0];
    assert_eq!(report.canonical, "react");
    assert_eq!(report.chosen_version, "18.2.0");
    assert_eq!(report.unsatisfied_consumers.len(), 1);
    assert_eq!(report.unsatisfied_consumers[0].0, "legacy-pkg");
    assert_eq!(report.unsatisfied_consumers[0].1, "^17.0.0");
}

#[tokio::test]
async fn peer_drain_best_effort_skips_a_trust_downgrade_candidate() {
    let policy = ResolverPolicy::new(0, TrustPolicyMode::NoDowngrade);
    let mut state = ResolveState::new_with_options_and_policy(
        HashMap::new(),
        OverrideSet::empty(),
        true,
        policy,
    );
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let modern_a = push_node(&mut state, CanonicalKey::npm("modern-a"), "1.0.0");
    let modern_b = push_node(&mut state, CanonicalKey::npm("modern-b"), "1.0.0");
    let legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");

    for (consumer, range) in [
        (modern_a, "^2.0.0"),
        (modern_b, "^2.0.0"),
        (legacy, "^1.0.0"),
    ] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "peer",
            CanonicalKey::npm("peer"),
            range,
            false,
        ));
    }

    let mut info = mk_info(&["2.0.0", "1.0.0"], &[]);
    set_published_at(&mut info, "1.0.0", "2025-01-01T00:00:00.000Z");
    set_trust_evidence(
        &mut info,
        "1.0.0",
        crate::policy::TrustEvidence::TrustedPublisher,
    );
    set_published_at(&mut info, "2.0.0", "2025-01-02T00:00:00.000Z");
    let info = Arc::new(info);

    let synthesized = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = Arc::clone(&info);
        async move { Ok(info) }
    })
    .await
    .expect("an allowed best-effort peer candidate remains available");

    assert_eq!(synthesized.len(), 1);
    assert!(
        synthesized[0]
            .range
            .satisfies(&NpmVersion::parse("1.0.0").unwrap()),
        "trust-policy no-downgrade must reject the untrusted majority candidate"
    );
    assert_eq!(state.peer_conflicts[0].chosen_version, "1.0.0");
}

#[test]
fn best_effort_consumer_counts_exclude_optional_requirements() {
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");
    let modern = push_node(&mut state, CanonicalKey::npm("modern"), "1.0.0");
    let optional_a = push_node(&mut state, CanonicalKey::npm("optional-a"), "1.0.0");
    let optional_b = push_node(&mut state, CanonicalKey::npm("optional-b"), "1.0.0");

    for (consumer, range, optional) in [
        (legacy, "^17.0.0", false),
        (modern, "^18.0.0", false),
        (optional_a, "^18.0.0", true),
        (optional_b, "^99.0.0", true),
    ] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            range,
            optional,
        ));
    }

    let requirements = state.peer_requirements.iter().collect::<Vec<_>>();
    let chosen = NpmVersion::parse("18.2.0").unwrap();

    assert_eq!(
        required_peer_consumer_counts(&requirements, &chosen),
        (1, 2)
    );
}

#[tokio::test]
async fn peer_drain_hard_errors_when_no_required_consumer_satisfiable() {
    // Terminal case: no platform-compatible version satisfies any required
    // consumer's range (required consumer wants ^99, but only 18 + 17 are
    // published). Hard error survives because there's no version to
    // "best-effort" pick that helps anyone.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("future-pkg"), "1.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^99.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
    let result = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await;

    match result {
        Err(ResolveError::PeerConflict {
            canonical,
            requirements,
        }) => {
            assert_eq!(canonical, "react");
            assert_eq!(requirements.len(), 1);
            assert_eq!(requirements[0].0, "future-pkg");
            assert_eq!(requirements[0].1, "^99.0.0");
        }
        other => {
            panic!("expected PeerConflict for unsatisfiable required range, got {other:?}")
        }
    }
}

#[tokio::test]
async fn peer_drain_best_effort_picks_version_satisfying_most_consumers() {
    // Three required consumers; two want ^18, one wants ^17.
    // Best-effort picks 18.2.0 (satisfies 2 of 3) over 17.x
    // (satisfies 1 of 3). The unsatisfied consumer is recorded.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let c_modern_a = push_node(&mut state, CanonicalKey::npm("modern-a"), "1.0.0");
    let c_modern_b = push_node(&mut state, CanonicalKey::npm("modern-b"), "1.0.0");
    let c_legacy = push_node(&mut state, CanonicalKey::npm("legacy"), "1.0.0");

    for (consumer, range) in [
        (c_modern_a, "^18.0.0"),
        (c_modern_b, "^18.0.0"),
        (c_legacy, "^17.0.0"),
    ] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            range,
            false,
        ));
    }

    let info_arc = mk_info_arc(&["18.2.0", "17.0.2"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .expect("majority-satisfiable conflict should NOT hard-error");

    assert_eq!(synth.len(), 1);
    assert!(
        synth[0]
            .range
            .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "majority pick is the newest version satisfying the most consumers"
    );
    assert_eq!(state.peer_conflicts.len(), 1);
    let report = &state.peer_conflicts[0];
    assert_eq!(report.chosen_version, "18.2.0");
    assert_eq!(report.unsatisfied_consumers.len(), 1);
    assert_eq!(report.unsatisfied_consumers[0].0, "legacy");
}

#[tokio::test]
async fn peer_drain_does_not_conflict_when_all_consumers_optional() {
    // All consumers in a conflicted group are optional → skip
    // silently rather than raising PeerConflict. Mirrors npm
    // v7+'s behavior for `peerDependenciesMeta.optional = true`.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_a = push_node(&mut state, CanonicalKey::npm("opt-a"), "1.0.0");
    let consumer_b = push_node(&mut state, CanonicalKey::npm("opt-b"), "2.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer_a,
        "react",
        CanonicalKey::npm("react"),
        "^17.0.0",
        true, // optional
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer_b,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        true, // optional
    ));

    let synth = drain_peer_requirements_one_pass(
        &mut state,
        true,
        // Closure must NOT be called — all-optional groups skip
        // before reaching the manifest fetch.
        |canonical: CanonicalKey| async move {
            panic!("fetch called for all-optional peer {canonical}")
        },
    )
    .await
    .unwrap();
    assert!(synth.is_empty(), "all-optional group is skipped silently");
}

#[tokio::test]
async fn peer_drain_respects_auto_install_peers_false_opt_out() {
    // When `auto_install_peers = false`, even a missing required
    // peer is NOT auto-installed; the drain returns no
    // synthesized edges. The post-resolve `check_unmet_peers`
    // pass surfaces the missing peer as a `PeerWarning` later.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let synth = drain_peer_requirements_one_pass(
        &mut state,
        false, // opt-out
        // Closure must NOT be called — opt-out skips before fetch.
        |canonical: CanonicalKey| async move {
            panic!("fetch called under auto_install_peers=false for {canonical}")
        },
    )
    .await
    .unwrap();
    assert!(synth.is_empty(), "no synthesis under opt-out");
}

#[tokio::test]
async fn peer_drain_unrelated_override_does_not_lookup_opted_out_peer_manifest() {
    let mut state = ResolveState::new(HashMap::new(), override_set("unrelated-package", "2.0.0"));
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let synthesized =
        drain_peer_requirements_one_pass(&mut state, false, |canonical: CanonicalKey| async move {
            panic!("unrelated override must not trigger a manifest lookup for {canonical}")
        })
        .await
        .expect("peer auto-install opt-out should finish without synthesis");

    assert!(synthesized.is_empty());
}

#[tokio::test]
async fn peer_drain_skips_optional_when_required_sibling_satisfied() {
    // Mixed group: one required + one optional consumer for the
    // same canonical, with overlapping ranges. The required
    // consumer drives synthesis; the optional consumer's range
    // ALSO must be honored (intersection across BOTH). If the
    // version satisfies both, we synthesize. This guards against
    // a regression where "any optional in group" silently bypassed
    // the required consumer's needs.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_req = push_node(&mut state, CanonicalKey::npm("required-pkg"), "1.0.0");
    let consumer_opt = push_node(&mut state, CanonicalKey::npm("optional-pkg"), "1.0.0");

    // Both want react^18, one is optional. Intersection is `^18`,
    // newest available is 18.2.0 → synthesize.
    state.peer_requirements.push(mk_peer_req(
        consumer_req,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer_opt,
        "react",
        CanonicalKey::npm("react"),
        "^18.2.0",
        true, // optional
    ));

    let info_arc = mk_info_arc(&["19.0.0", "18.2.0", "18.0.0"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();
    assert_eq!(synth.len(), 1);
    assert!(
        synth[0]
            .range
            .satisfies(&NpmVersion::parse("18.2.0").unwrap()),
        "chose 18.2.0 (newest satisfying both ^18.0.0 and ^18.2.0)"
    );
}

#[tokio::test]
async fn peer_drain_does_not_modify_consumer_children() {
    // The drain pass MUST NOT add the synthesized peer to the
    // consumer's `children` list. Children is dependency-only;
    // the consumer's `peers` list is derived from the metadata
    // cache by `into_resolved_packages` AFTER the resolved tree
    // is final. If synthesis ever wrote to `consumer.children`,
    // the v2 graph-key derivation would silently fold the peer
    // into the dependency portion, breaking peer-divergent
    // link-entry isolation.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_canonical| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();
    assert_eq!(synth.len(), 1);
    assert!(
        state.nodes[consumer as usize].children.is_empty(),
        "consumer.children must remain empty — peers are NOT routed as children"
    );
}

#[tokio::test]
async fn peer_drain_clears_peer_requirements_each_pass() {
    // After one pass, `state.peer_requirements` is empty so the
    // next pass starts fresh. Required because synthesized
    // ambient installs may themselves declare peers (transitive
    // chains), and the caller's outer fixed-point loop relies on
    // each pass starting with whatever the previous pass left
    // behind via `enqueue_child_deps`.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("a"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0"], &[]);
    drain_peer_requirements_one_pass(&mut state, true, |_| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();
    assert!(
        state.peer_requirements.is_empty(),
        "drain consumes the worklist regardless of synthesis outcome"
    );
}

#[tokio::test]
async fn peer_drain_recording_records_ambient_peer_installs() {
    // The install pipeline derives top-level `node_modules/<name>/`
    // symlinks from `pkg.dependencies` ∪
    // `ResolveResult.ambient_peer_installs`. If the drain helper
    // synthesizes an Edge but DOESN'T record the canonical onto
    // `state.ambient_peer_installs`, the package extracts into the
    // v2 store but never gets a project-side symlink. This test
    // pins the behavior so a future refactor can't silently drop
    // the recording.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.2.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let info_arc = mk_info_arc(&["18.2.0"], &[]);
    let synth = drain_peer_requirements_one_pass(&mut state, true, |_| {
        let info = info_arc.clone();
        async move { Ok(info) }
    })
    .await
    .unwrap();

    assert_eq!(synth.len(), 1, "ambient edge synthesized");
    assert_eq!(
        state.ambient_peer_installs,
        vec!["react".to_string()],
        "the canonical of every synthesized ambient install must be \
         recorded on `state.ambient_peer_installs`; the install \
         pipeline reads this set to surface the package at \
         top-level node_modules/"
    );
}

#[tokio::test]
async fn peer_drain_recording_does_not_record_satisfied_or_skipped_groups() {
    // The recording must be tight: only ACTUALLY-synthesized
    // groups land in `ambient_peer_installs`. Satisfied-by-
    // existing groups don't (no install was synthesized).
    // All-optional groups don't (no install was synthesized).
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    // Already-satisfied: react is in the tree at 18.2.0.
    let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    let consumer1 = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.2.0");
    // All-optional consumer: optional peer on @types/react.
    let consumer2 = push_node(&mut state, CanonicalKey::npm("opt-pkg"), "1.0.0");

    state.peer_requirements.push(mk_peer_req(
        consumer1,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer2,
        "@types/react",
        CanonicalKey::npm("@types/react"),
        "^18.0.0",
        true, // optional
    ));

    let synth = drain_peer_requirements_one_pass(
        &mut state,
        true,
        // Closure must NOT be called — both groups short-circuit
        // before fetch (one satisfied, one all-optional).
        |canonical: CanonicalKey| async move { panic!("unexpected fetch for {canonical}") },
    )
    .await
    .unwrap();

    assert!(synth.is_empty(), "neither group should synthesize");
    assert!(
        state.ambient_peer_installs.is_empty(),
        "ambient_peer_installs records ONLY synthesized groups"
    );
}

// ── Speculative peer-manifest prefetch picker tests ───────────
//
// Peer prefetch makes manifest fetches concurrent with the regular
// dep walk by selecting prefetch candidates at the top of every
// main-loop iteration and dispatching them through the existing
// metadata_jobs JoinSet. The picker is a pure function: it reads
// `state` plus the dispatcher's `shared_cache` + `inflight` set
// and returns the canonicals that should be fetched. These tests
// pin the four predicate gates (all-optional, satisfied-by-
// existing, already-cached, in-flight) and the deterministic
// ordering contract.

/// Empty cache + inflight for tests that don't exercise either.
fn empty_cache() -> dashmap::DashMap<CanonicalKey, Arc<CachedPackageInfo>> {
    dashmap::DashMap::new()
}
fn empty_inflight() -> AHashSet<CanonicalKey> {
    AHashSet::new()
}

#[test]
fn peer_prefetch_picker_returns_unsatisfied_required_peer() {
    // Baseline: a single required peer with no node in the
    // resolved tree, no cache hit, no in-flight dispatch. Must
    // be picked.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert_eq!(picks, vec![CanonicalKey::npm("react")]);
}

#[test]
fn peer_prefetch_picker_skips_satisfied_by_existing() {
    // The peer's canonical is in the resolved tree at a version
    // satisfying the consumer's range. No prefetch — the drain
    // pass will see this group as already-satisfied.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let _react = push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert!(
        picks.is_empty(),
        "satisfied-by-existing groups must NOT trigger a prefetch"
    );
}

#[test]
fn peer_prefetch_picker_skips_all_optional_groups() {
    // A group of consumers all marked `peerDependenciesMeta.optional`.
    // Optional-only groups never auto-install, so prefetching
    // is wasted bandwidth.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer1 = push_node(&mut state, CanonicalKey::npm("opt-a"), "1.0.0");
    let consumer2 = push_node(&mut state, CanonicalKey::npm("opt-b"), "1.0.0");
    for consumer in [consumer1, consumer2] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            true, // optional
        ));
    }

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert!(picks.is_empty(), "all-optional group must skip prefetch");
}

#[test]
fn peer_prefetch_picker_picks_when_at_least_one_consumer_is_required() {
    // Mixed group: one optional + one required. Prefetch fires
    // because the required consumer drives auto-install.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_req = push_node(&mut state, CanonicalKey::npm("required-pkg"), "1.0.0");
    let consumer_opt = push_node(&mut state, CanonicalKey::npm("optional-pkg"), "1.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer_req,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));
    state.peer_requirements.push(mk_peer_req(
        consumer_opt,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        true,
    ));

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert_eq!(picks, vec![CanonicalKey::npm("react")]);
}

#[test]
fn peer_prefetch_picker_skips_canonicals_already_cached() {
    // Sibling regular-dep walk already pulled the peer's manifest
    // into the shared cache. The drain pass will hit the fast
    // path; no need to dispatch a prefetch.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let cache = empty_cache();
    cache.insert(CanonicalKey::npm("react"), mk_info_arc(&["18.2.0"], &[]));

    let picks = pick_peer_prefetch_candidates(&state, &cache, &empty_inflight());
    assert!(
        picks.is_empty(),
        "cached canonical must not be re-dispatched"
    );
}

#[test]
fn peer_prefetch_picker_skips_canonicals_already_in_flight() {
    // A sibling cache-miss already dispatched a fetch for the canonical.
    // The dispatcher's inflight guard would dedup a redundant spawn
    // anyway; skipping at the picker level saves the spawn allocation.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("react-redux"), "9.0.0");
    state.peer_requirements.push(mk_peer_req(
        consumer,
        "react",
        CanonicalKey::npm("react"),
        "^18.0.0",
        false,
    ));

    let mut inflight = empty_inflight();
    inflight.insert(CanonicalKey::npm("react"));

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &inflight);
    assert!(
        picks.is_empty(),
        "in-flight canonical must not be re-dispatched"
    );
}

#[test]
fn peer_prefetch_picker_returns_alphabetic_order() {
    // Multiple unmet peers in pathological insertion order. The
    // picker must return them sorted alphabetically — the same
    // determinism contract as the regular `enqueue_child_deps`
    // sort. Without it, lockfile output across runs would shift
    // based on HashMap iteration.
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer = push_node(&mut state, CanonicalKey::npm("multi-peer"), "1.0.0");
    for (name, range) in [("zoo", "^1.0.0"), ("alpha", "^1.0.0"), ("middle", "^1.0.0")] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            name,
            CanonicalKey::npm(name),
            range,
            false,
        ));
    }

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    let names: Vec<String> = picks.iter().map(|c| c.to_string()).collect();
    assert_eq!(names, vec!["alpha", "middle", "zoo"]);
}

#[test]
fn peer_prefetch_picker_dedups_same_canonical_across_multiple_consumers() {
    // Two consumers both peer the same canonical. The picker
    // groups by canonical first, so we should get exactly ONE
    // entry for that canonical (not two).
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let _root = push_node(&mut state, CanonicalKey::Root, "0.0.0");
    let consumer_a = push_node(&mut state, CanonicalKey::npm("pkg-a"), "1.0.0");
    let consumer_b = push_node(&mut state, CanonicalKey::npm("pkg-b"), "1.0.0");
    for consumer in [consumer_a, consumer_b] {
        state.peer_requirements.push(mk_peer_req(
            consumer,
            "react",
            CanonicalKey::npm("react"),
            "^18.0.0",
            false,
        ));
    }

    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert_eq!(
        picks,
        vec![CanonicalKey::npm("react")],
        "shared canonical produces ONE prefetch — the dispatcher \
         handles N consumers via dedupe-on-canonical"
    );
}

#[test]
fn peer_prefetch_picker_empty_when_peer_requirements_empty() {
    // Hot-path baseline: no peers declared → empty result.
    let state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    let picks = pick_peer_prefetch_candidates(&state, &empty_cache(), &empty_inflight());
    assert!(picks.is_empty());
}

#[test]
fn process_edge_without_overrides_selects_natural_version() {
    let info = mk_info(&["4.17.21", "4.0.0"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    let mut state = ResolveState::new(deps, OverrideSet::empty());
    state.seed_root_edges().unwrap();
    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }
    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1);
    assert_eq!(lodash_entries[0].0.to_string(), "4.17.21");
    assert!(state.overrides.take_hits().is_empty());
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
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    assert!(handle_no_version(&edge, &info, false, &mut state).is_ok());
    assert_eq!(state.platform_skipped, 0);
}

#[test]
fn handle_no_version_optional_platform_filtered_increments_counter() {
    let info = mk_info(&["1.0.0"], &[]);
    let edge = Edge {
        parent: 0,
        local_name: "x".to_string(),
        canonical: CanonicalKey::npm("x"),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: false,
            peer: false,
            optional: true,
        },
    };
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    assert!(handle_no_version(&edge, &info, true, &mut state).is_ok());
    assert_eq!(state.platform_skipped, 1);
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
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    match handle_no_version(&edge, &info, false, &mut state) {
        Err(ResolveError::Resolution(context)) => {
            assert_eq!(context.package, "x");
            assert_eq!(context.requested, "^99.0.0");
            assert_eq!(context.required_by.as_deref(), None);
            assert_eq!(context.kind, ResolutionFailureKind::NoMatchingVersion);
            assert_eq!(context.available_versions, Some(1));
            assert_eq!(context.newest_version.as_deref(), Some("1.0.0"));
        }
        other => panic!("expected structured resolution failure, got {other:?}"),
    }
}

// ── Fusion termination invariants ───────────────────────────────
//
// The loop's correctness pivots on the termination
// invariant: queue empty + jobs empty ⇒ parked empty. These tests
// poke the three corners that could break it: zero-edge case,
// error-on-fetch case, and required-error propagation.
// Success-path termination is covered by real-install smoke tests.

/// Empty deps map: the loop must terminate after seed_root_edges
/// (zero edges queued, zero fetches dispatched, parked empty by
/// construction). This is the trivial baseline for the
/// termination invariant.
#[tokio::test(flavor = "current_thread")]
async fn fusion_terminates_on_empty_deps() {
    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
    let result = resolve_greedy_fused(
        client,
        HashMap::new(),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true, // tests default to auto-install on
    )
    .await
    .expect("empty deps must resolve to empty result");
    assert!(result.packages.is_empty());
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 0);
    assert_eq!(result.stage_timing.dispatcher_inflight_high_water, 0);
    assert_eq!(result.stage_timing.parked_max_depth, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_exact_npm_range_fetches_only_the_version_document() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exact-root/1.2.3"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "exact-root",
            "version": "1.2.3",
            "dist": {
                "tarball": "https://example.invalid/exact-root-1.2.3.tgz",
                "integrity": "sha512-exact-root"
            },
            "dependencies": {}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let result = resolve_greedy_fused(
        client,
        HashMap::from([("exact-root".to_string(), "1.2.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an exact npm range should resolve from its version document");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_broad_npm_range_keeps_using_the_packument() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/broad-root"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json_version(
                "broad-root",
                "1.2.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let result = resolve_greedy_fused(
        client,
        HashMap::from([("broad-root".to_string(), "^1.0.0".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("a broad npm range should continue to resolve from a packument");

    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_invalid_exact_version_document_falls_back_to_the_packument() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fallback-root/1.2.3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "wrong-package",
            "version": "1.2.3",
            "dist": {
                "tarball": "https://example.invalid/wrong-package-1.2.3.tgz",
                "integrity": "sha512-wrong-package"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fallback-root"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json_version(
                "fallback-root",
                "1.2.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let result = resolve_greedy_fused(
        client,
        HashMap::from([("fallback-root".to_string(), "1.2.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an invalid exact version document should fall back to the packument");

    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_exact_prerelease_fetches_the_prerelease_version_document() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/prerelease-root/2.0.0-beta.3"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(version_document_json(
                "prerelease-root",
                "2.0.0-beta.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([("prerelease-root".to_string(), "2.0.0-beta.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an exact prerelease should resolve from its version document");

    assert_eq!(result.packages[0].version.to_string(), "2.0.0-beta.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_exact_npm_alias_fetches_the_target_version_document() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/alias-target/1.2.3"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(version_document_json(
                "alias-target",
                "1.2.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([(
            "local-alias".to_string(),
            "npm:alias-target@1.2.3".to_string(),
        )]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an exact npm alias should resolve from the target version document");

    assert_eq!(
        result.root_aliases.get("local-alias").map(String::as_str),
        Some("alias-target")
    );
    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_exact_document_without_distribution_falls_back_to_the_packument() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing-dist/1.2.3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "missing-dist",
            "version": "1.2.3",
            "dependencies": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/missing-dist"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json_version(
                "missing-dist",
                "1.2.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([("missing-dist".to_string(), "1.2.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an incomplete version document should fall back to the packument");

    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_release_age_policy_skips_the_exact_document_and_uses_complete_metadata() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/policy-root/1.2.3"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/policy-root"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "policy-root",
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": version_document_json("policy-root", "1.2.3", &[])
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/policy-root"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "policy-root",
            "time": { "1.2.3": "2025-01-01T00:00:00.000Z" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = resolve_greedy_fused_with_cache_options_and_policy(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([("policy-root".to_string(), "1.2.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        Arc::new(dashmap::DashMap::new()),
        true,
        true,
        ResolverPolicy::with_cutoff_unix(86_400, 1_750_000_000, TrustPolicyMode::Off),
    )
    .await
    .expect("release-age policy should resolve from complete metadata");

    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_broad_range_after_an_exact_document_refetches_the_packument() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-range/1.0.0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(version_document_json(
                "shared-range",
                "1.0.0",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/shared-range"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "shared-range",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": version_document_json("shared-range", "1.0.0", &[]),
                "2.0.0": version_document_json("shared-range", "2.0.0", &[])
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("a-exact".to_string(), "npm:shared-range@1.0.0".to_string()),
            ("z-broad".to_string(), "npm:shared-range@^2.0.0".to_string()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("an uncovered broad range should refetch complete metadata");

    let versions: HashSet<_> = result
        .packages
        .iter()
        .map(|package| package.version.to_string())
        .collect();
    assert_eq!(
        versions,
        HashSet::from(["1.0.0".to_string(), "2.0.0".to_string()])
    );
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_multiple_exact_versions_merge_without_fetching_a_packument() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for version in ["1.0.0", "2.0.0"] {
        Mock::given(method("GET"))
            .and(path(format!("/shared-exact/{version}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(version_document_json(
                    "shared-exact",
                    version,
                    &[],
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
    }

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("a-one".to_string(), "npm:shared-exact@1.0.0".to_string()),
            ("z-two".to_string(), "npm:shared-exact@2.0.0".to_string()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("multiple exact versions should merge as partial metadata");

    let versions: HashSet<_> = result
        .packages
        .iter()
        .map(|package| package.version.to_string())
        .collect();
    assert_eq!(
        versions,
        HashSet::from(["1.0.0".to_string(), "2.0.0".to_string()])
    );
    assert!(!result.cache[&CanonicalKey::npm("shared-exact")].versions_complete);
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_custom_registry_exact_range_keeps_using_the_packument() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/custom-exact/1.2.3"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/custom-exact"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json_version(
                "custom-exact",
                "1.2.3",
                &[],
            )),
        )
        .expect(1)
        .mount(&server)
        .await;
    let npmrc =
        lpm_registry::NpmrcConfig::parse(&format!("registry={}\n", server.uri()), "test", &|_| {
            None
        });

    let result = resolve_greedy_fused(
        Arc::new(RegistryClient::new().with_cache_dir(None)),
        HashMap::from([("custom-exact".to_string(), "1.2.3".to_string())]),
        OverrideSet::empty(),
        RouteTable::new(RouteMode::Direct, npmrc).expect("valid custom registry"),
        8,
        None,
        true,
    )
    .await
    .expect("custom registry exact ranges should keep the existing path");

    assert_eq!(result.packages[0].version.to_string(), "1.2.3");
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_inflight_high_water_never_exceeds_metadata_fanout() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PACKAGE_COUNT: usize = 6;
    const FANOUT: usize = 2;

    let server = MockServer::start().await;
    let mut deps = HashMap::with_capacity(PACKAGE_COUNT);
    for index in 0..PACKAGE_COUNT {
        let name = format!("fanout-{index}");
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(metadata_json(&name, &[])),
            )
            .expect(1)
            .mount(&server)
            .await;
        deps.insert(name, "^1.0.0".to_string());
    }

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        FANOUT,
        None,
        true,
    )
    .await
    .expect("direct metadata fanout fixture should resolve");

    assert!(
        result.stage_timing.dispatcher_inflight_high_water <= FANOUT as u64,
        "active metadata fetch high-water {} exceeded configured fanout {FANOUT}",
        result.stage_timing.dispatcher_inflight_high_water,
    );
    assert_eq!(
        result.stage_timing.dispatcher_configured_fanout,
        FANOUT as u64
    );
    assert_eq!(result.stage_timing.dispatcher_exact_document_fanout, 8);
    assert_eq!(result.stage_timing.dispatcher_inflight_high_water, 2);
    assert_eq!(
        result.stage_timing.dispatcher_pending_high_water,
        PACKAGE_COUNT as u64
    );
    assert_eq!(
        result.stage_timing.dispatcher_semaphore_wait_count,
        (PACKAGE_COUNT - FANOUT) as u64
    );
    assert!(result.stage_timing.dispatcher_semaphore_wait_ns > 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_exact_documents_use_the_wider_bounded_fanout() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PACKAGE_COUNT: usize = 6;
    const PACKUMENT_FANOUT: usize = 2;

    let server = MockServer::start().await;
    let mut deps = HashMap::with_capacity(PACKAGE_COUNT);
    for index in 0..PACKAGE_COUNT {
        let name = format!("exact-fanout-{index}");
        Mock::given(method("GET"))
            .and(path(format!("/{name}/1.0.0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(version_document_json(&name, "1.0.0", &[])),
            )
            .expect(1)
            .mount(&server)
            .await;
        deps.insert(name, "1.0.0".to_string());
    }

    let result = resolve_greedy_fused(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        PACKUMENT_FANOUT,
        None,
        true,
    )
    .await
    .expect("exact version documents should resolve through the wider lane");

    assert_eq!(result.stage_timing.dispatcher_configured_fanout, 2);
    assert_eq!(result.stage_timing.dispatcher_exact_document_fanout, 8);
    assert_eq!(
        result.stage_timing.dispatcher_inflight_high_water,
        PACKAGE_COUNT as u64
    );
    assert_eq!(result.stage_timing.dispatcher_semaphore_wait_count, 0);
    server.verify().await;
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_trace_attributes_edge_expansion_and_graph_finalization() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _timing_guard = crate::metadata_fetch_detail_test_lock().lock().await;
    let _env = ScopedEnvVars::set(&[("LPM_TIMING_DETAIL", "trace")]);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/timed-root"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(5))
                .set_body_json(metadata_json("timed-root", &[])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let result = resolve_greedy_fused(
        client,
        HashMap::from_iter([("timed-root".to_string(), "^1.0.0".to_string())]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("trace timing fixture should resolve");

    assert!(result.stage_timing.edge_expansion_ns > 0);
    assert!(result.stage_timing.graph_finalization_ns > 0);
    assert!(result.stage_timing.manifest_wait_ns >= 1_000_000);
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_reuses_direct_base_facts_across_importer_local_caches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shared-package"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json("shared-package", &[])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let shared_facts: SharedCache = Arc::new(dashmap::DashMap::new());
    let dependencies = crate::RootDependencies::required(HashMap::from([(
        "shared-package".to_string(),
        "^1.0.0".to_string(),
    )]));
    let resolve = || {
        resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
            Arc::clone(&client),
            dependencies.clone(),
            OverrideSet::empty(),
            route_table.clone(),
            8,
            None,
            Arc::new(dashmap::DashMap::new()),
            true,
            true,
            ResolverPolicy::default(),
            None,
            Some(Arc::clone(&shared_facts)),
            None,
        )
    };

    let first = resolve().await.expect("first importer should resolve");
    let second = resolve().await.expect("second importer should resolve");

    let identities = |result: &ResolveResult| {
        result
            .packages
            .iter()
            .map(|package| {
                (
                    package.package.canonical_name(),
                    package.version.to_string(),
                    package.dependencies.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(identities(&first), identities(&second));
    assert!(shared_facts.contains_key(&CanonicalKey::npm("shared-package")));
}

async fn resolve_overlapping_range_with_parent_delay(
    exact_parent_delay_ms: u64,
    range_parent_delay_ms: u64,
) -> String {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for (name, dependency_range, delay_ms) in [
        ("exact-parent", "1.0.0", exact_parent_delay_ms),
        ("range-parent", "^1.0.0", range_parent_delay_ms),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(delay_ms))
                    .set_body_json(metadata_json(name, &[("shared-child", dependency_range)])),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/shared-child"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "shared-child",
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": {
                    "name": "shared-child",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://example.invalid/shared-child-1.0.0.tgz",
                        "integrity": "sha512-shared-100"
                    }
                },
                "1.1.0": {
                    "name": "shared-child",
                    "version": "1.1.0",
                    "dist": {
                        "tarball": "https://example.invalid/shared-child-1.1.0.tgz",
                        "integrity": "sha512-shared-110"
                    }
                }
            },
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "1.1.0": "2025-01-02T00:00:00.000Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(None),
    );
    let dependencies = HashMap::from([
        ("exact-parent".to_string(), "^1.0.0".to_string()),
        ("range-parent".to_string(), "^1.0.0".to_string()),
    ]);
    let result = resolve_greedy_fused(
        client,
        dependencies,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("overlapping range fixture should resolve");

    result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == "range-parent")
        .and_then(|package| {
            package
                .dependencies
                .iter()
                .find(|(name, _)| name == "shared-child")
        })
        .map(|(_, version)| version.clone())
        .expect("range parent should retain its shared-child edge")
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_overlapping_range_selection_is_independent_of_metadata_arrival_order() {
    let exact_first = resolve_overlapping_range_with_parent_delay(0, 100).await;
    let range_first = resolve_overlapping_range_with_parent_delay(100, 0).await;

    assert_eq!(exact_first, "1.1.0");
    assert_eq!(
        exact_first, range_first,
        "metadata response order must not change the selected dependency graph"
    );
}

async fn resolve_direct_and_transitive_overlap_with_seeded_cache(
    seed_parent: bool,
    seed_shared: bool,
) -> String {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let parent_metadata = metadata_json("range-parent", &[("shared-child", "*")]);
    let shared_metadata = serde_json::json!({
        "name": "shared-child",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": {
                "name": "shared-child",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.0.0.tgz",
                    "integrity": "sha512-shared-100"
                }
            },
            "1.1.0": {
                "name": "shared-child",
                "version": "1.1.0",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.1.0.tgz",
                    "integrity": "sha512-shared-110"
                }
            }
        }
    });
    Mock::given(method("GET"))
        .and(path("/range-parent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_metadata.clone()))
        .expect(u64::from(!seed_parent))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/shared-child"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shared_metadata.clone()))
        .expect(u64::from(!seed_shared))
        .mount(&server)
        .await;

    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    if seed_parent {
        let metadata = serde_json::from_value(parent_metadata).expect("parent metadata fixture");
        shared_cache.insert(
            CanonicalKey::npm("range-parent"),
            Arc::new(parse_metadata_to_cache_info(&metadata)),
        );
    }
    if seed_shared {
        let metadata = serde_json::from_value(shared_metadata).expect("shared metadata fixture");
        shared_cache.insert(
            CanonicalKey::npm("shared-child"),
            Arc::new(parse_metadata_to_cache_info(&metadata)),
        );
    }

    let result = resolve_greedy_fused_with_cache_options(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        HashMap::from([
            ("range-parent".to_string(), "*".to_string()),
            ("shared-child".to_string(), "1.0.0".to_string()),
        ]),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        shared_cache,
        true,
        true,
    )
    .await
    .expect("direct and transitive overlap fixture should resolve");

    result
        .packages
        .iter()
        .find(|package| package.package.canonical_name() == "range-parent")
        .and_then(|package| {
            package
                .dependencies
                .iter()
                .find(|(name, _)| name == "shared-child")
        })
        .map(|(_, version)| version.clone())
        .expect("range parent should retain its shared-child edge")
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_overlapping_range_selection_is_independent_of_shared_cache_warmth() {
    let cold = resolve_direct_and_transitive_overlap_with_seeded_cache(false, false).await;
    let parent_warm = resolve_direct_and_transitive_overlap_with_seeded_cache(true, false).await;
    let shared_warm = resolve_direct_and_transitive_overlap_with_seeded_cache(false, true).await;
    let fully_warm = resolve_direct_and_transitive_overlap_with_seeded_cache(true, true).await;

    assert_eq!(cold, "1.0.0");
    assert_eq!(
        [parent_warm, shared_warm, fully_warm],
        [cold.clone(), cold.clone(), cold],
        "shared-cache warmth must not change the selected dependency graph"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct CacheWarmOverlapResult {
    required_parent_child: String,
    optional_parent_child: String,
    shared_versions: Vec<(String, bool)>,
}

#[derive(Clone, Copy)]
enum CacheWarmFixtureSeed {
    Cold,
    RequiredChain,
    Complete,
}

async fn resolve_deep_required_and_shallow_optional_overlap(
    seed: CacheWarmFixtureSeed,
) -> CacheWarmOverlapResult {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let required_parent = metadata_json("a-required-parent", &[("middle", "*")]);
    let optional_parent = metadata_json("b-optional-parent", &[("shared-child", "^1.1.1")]);
    let middle = metadata_json("middle", &[("shared-child", "~1.1.1")]);
    let shared_child = serde_json::json!({
        "name": "shared-child",
        "dist-tags": { "latest": "1.3.0" },
        "versions": {
            "1.1.1": {
                "name": "shared-child",
                "version": "1.1.1",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.1.1.tgz",
                    "integrity": "sha512-shared-111"
                }
            },
            "1.3.0": {
                "name": "shared-child",
                "version": "1.3.0",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.3.0.tgz",
                    "integrity": "sha512-shared-130"
                }
            }
        }
    });
    let required_chain_seeded = matches!(
        seed,
        CacheWarmFixtureSeed::RequiredChain | CacheWarmFixtureSeed::Complete
    );
    let fully_seeded = matches!(seed, CacheWarmFixtureSeed::Complete);
    for (name, metadata, seeded) in [
        (
            "a-required-parent",
            required_parent.clone(),
            required_chain_seeded,
        ),
        ("b-optional-parent", optional_parent.clone(), fully_seeded),
        ("middle", middle.clone(), required_chain_seeded),
        ("shared-child", shared_child.clone(), fully_seeded),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .expect(u64::from(!seeded))
            .mount(&server)
            .await;
    }

    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    if required_chain_seeded {
        for (name, metadata) in [("a-required-parent", required_parent), ("middle", middle)] {
            let metadata = serde_json::from_value(metadata).expect("seeded metadata fixture");
            shared_cache.insert(
                CanonicalKey::npm(name),
                Arc::new(parse_metadata_to_cache_info(&metadata)),
            );
        }
    }
    if fully_seeded {
        for (name, metadata) in [
            ("b-optional-parent", optional_parent),
            ("shared-child", shared_child),
        ] {
            let metadata = serde_json::from_value(metadata).expect("seeded metadata fixture");
            shared_cache.insert(
                CanonicalKey::npm(name),
                Arc::new(parse_metadata_to_cache_info(&metadata)),
            );
        }
    }

    let roots = crate::resolve::RootDependencies::with_optional_names(
        HashMap::from([
            ("a-required-parent".to_string(), "*".to_string()),
            ("b-optional-parent".to_string(), "*".to_string()),
        ]),
        HashSet::from(["b-optional-parent".to_string()]),
    );
    let result = resolve_greedy_fused_with_cache_options_and_policy_roots(
        Arc::new(
            RegistryClient::new()
                .with_npm_registry_url(server.uri())
                .with_cache_dir(None),
        ),
        roots,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        shared_cache,
        true,
        true,
        ResolverPolicy::default(),
    )
    .await
    .expect("deep required and shallow optional overlap should resolve");

    let dependency_version = |parent: &str, child: &str| {
        result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == parent)
            .and_then(|package| package.dependencies.iter().find(|(name, _)| name == child))
            .map_or_else(
                || panic!("{parent} should retain its {child} edge"),
                |(_, version)| version.clone(),
            )
    };
    let mut shared_versions: Vec<_> = result
        .packages
        .iter()
        .filter(|package| package.package.canonical_name() == "shared-child")
        .map(|package| (package.version.to_string(), package.optional))
        .collect();
    shared_versions.sort_unstable();

    CacheWarmOverlapResult {
        required_parent_child: dependency_version("middle", "shared-child"),
        optional_parent_child: dependency_version("b-optional-parent", "shared-child"),
        shared_versions,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_deep_overlap_selection_is_independent_of_shared_cache_warmth() {
    let cold = resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::Cold).await;
    let partially_seeded =
        resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::RequiredChain)
            .await;
    let fully_seeded =
        resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::Complete).await;

    assert_eq!(
        [
            (
                partially_seeded.required_parent_child,
                partially_seeded.optional_parent_child,
            ),
            (
                fully_seeded.required_parent_child,
                fully_seeded.optional_parent_child,
            ),
        ],
        [
            (
                cold.required_parent_child.clone(),
                cold.optional_parent_child.clone(),
            ),
            (cold.required_parent_child, cold.optional_parent_child),
        ],
        "shared-cache warmth must not change overlapping transitive selections"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_required_reachability_is_independent_of_shared_cache_warmth() {
    let cold = resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::Cold).await;
    let partially_seeded =
        resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::RequiredChain)
            .await;
    let fully_seeded =
        resolve_deep_required_and_shallow_optional_overlap(CacheWarmFixtureSeed::Complete).await;

    assert_eq!(
        [
            partially_seeded.shared_versions,
            fully_seeded.shared_versions
        ],
        [cold.shared_versions.clone(), cold.shared_versions],
        "shared-cache warmth must not change required versus optional reachability"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_strict_release_age_selection_is_independent_of_persistent_cache_warmth() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let mut parent_abbreviated = metadata_json("range-parent", &[("shared-child", "*")]);
    let parent_object = parent_abbreviated
        .as_object_mut()
        .expect("parent metadata object");
    parent_object.remove("time");
    parent_object.insert(
        "modified".to_string(),
        serde_json::Value::String("2026-07-31T12:00:00.000Z".to_string()),
    );
    let shared_abbreviated = serde_json::json!({
        "name": "shared-child",
        "modified": "2026-07-31T12:00:00.000Z",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": {
                "name": "shared-child",
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.0.0.tgz",
                    "integrity": "sha512-shared-100"
                }
            },
            "1.1.0": {
                "name": "shared-child",
                "version": "1.1.0",
                "dist": {
                    "tarball": "https://example.invalid/shared-child-1.1.0.tgz",
                    "integrity": "sha512-shared-110"
                }
            }
        }
    });
    for (name, abbreviated, release_times) in [
        (
            "range-parent",
            parent_abbreviated,
            serde_json::json!({
                "name": "range-parent",
                "time": { "1.0.0": "2025-01-01T00:00:00.000Z" }
            }),
        ),
        (
            "shared-child",
            shared_abbreviated,
            serde_json::json!({
                "name": "shared-child",
                "time": {
                    "1.0.0": "2025-01-01T00:00:00.000Z",
                    "1.1.0": "2025-02-01T00:00:00.000Z"
                }
            }),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .and(header("Accept", "application/vnd.npm.install-v1+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(abbreviated))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(release_times))
            .expect(1)
            .mount(&server)
            .await;
    }

    let cache_dir = tempfile::tempdir().expect("metadata cache temp dir");
    let client = Arc::new(
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache_dir.path().to_path_buf())),
    );
    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_775_001_600, Default::default());
    let resolve = |dependencies| {
        resolve_greedy_fused_with_cache_options_and_policy(
            Arc::clone(&client),
            dependencies,
            OverrideSet::empty(),
            route_table.clone(),
            8,
            None,
            Arc::new(dashmap::DashMap::new()),
            true,
            true,
            policy.clone(),
        )
    };

    resolve(HashMap::from([(
        "shared-child".to_string(),
        "*".to_string(),
    )]))
    .await
    .expect("member pre-resolution should warm shared metadata");
    client.flush_pending_cache_writes().await;

    let partially_warm = resolve(HashMap::from([
        ("range-parent".to_string(), "*".to_string()),
        ("shared-child".to_string(), "1.0.0".to_string()),
    ]))
    .await
    .expect("partially warm root should resolve");
    client.flush_pending_cache_writes().await;
    let fully_warm = resolve(HashMap::from([
        ("range-parent".to_string(), "*".to_string()),
        ("shared-child".to_string(), "1.0.0".to_string()),
    ]))
    .await
    .expect("fully warm root should resolve");

    let selected_child = |result: &ResolveResult| {
        result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == "range-parent")
            .and_then(|package| {
                package
                    .dependencies
                    .iter()
                    .find(|(name, _)| name == "shared-child")
            })
            .map(|(_, version)| version.clone())
            .expect("range parent should retain its shared-child edge")
    };
    let partially_warm_child = selected_child(&partially_warm);
    let fully_warm_child = selected_child(&fully_warm);
    assert_eq!(partially_warm_child, "1.0.0");
    assert_eq!(
        partially_warm_child, fully_warm_child,
        "persistent metadata cache warmth must not change strict-policy selection"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_auto_installs_peer_when_sparse_cache_omits_empty_dependency_entry() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());

    let peer_host = mk_info_with_peers(&["1.0.0"], &[], &[("ghost-peer", "^1.0.0")], &[]);
    shared_cache.insert(CanonicalKey::npm("peer-host"), Arc::new(peer_host));
    shared_cache.insert(
        CanonicalKey::npm("ghost-peer"),
        Arc::new(mk_info(&["1.0.0"], &[])),
    );

    let mut deps = HashMap::new();
    deps.insert("peer-host".to_string(), "^1.0.0".to_string());

    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
    let result = resolve_greedy_fused_with_cache(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        shared_cache,
        true,
    )
    .await
    .expect("cache-only peer auto-install resolve should succeed");

    let names: HashSet<String> = result
        .packages
        .iter()
        .map(|pkg| pkg.package.canonical_name())
        .collect();
    assert!(names.contains("peer-host"));
    assert!(names.contains("ghost-peer"));
    assert_eq!(result.ambient_peer_installs, vec!["ghost-peer"]);
}

/// Single optional dep with a client that fails every fetch.
/// `propagate_fetch_error` must drop the edge silently (Optional
/// → skip), the parked map must drain to empty, and the loop must
/// terminate with a successful empty result.
#[tokio::test(flavor = "current_thread")]
async fn fusion_terminates_on_optional_fetch_failure() {
    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
    // Synthesize state with a single optional-marked edge, then
    // run resolve_greedy_fused via the public dependencies map.
    // We can't directly mark a root dep as optional through the
    // public API, but the propagate_fetch_error logic is
    // exercised identically when handle_no_version returns Ok
    // for an optional. So instead we drive via the propagate
    // helper directly + assert it returns Ok.
    let edge = Edge {
        parent: 0,
        local_name: "x".to_string(),
        canonical: CanonicalKey::npm("x"),
        range: NpmRange::parse("^1.0.0").unwrap(),
        behavior: DepBehavior {
            required: false,
            peer: false,
            optional: true,
        },
    };
    let err = ResolveError::DependencyFetch {
        package: "x".to_string(),
        version: "*".to_string(),
        detail: "connection refused".to_string(),
    };
    let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
    assert!(propagate_fetch_error(&edge, &err, &mut state).is_ok());

    // And the full-loop variant: zero deps means zero parked
    // edges means termination is unconditional. Reusing the
    // empty-deps test infrastructure to assert the loop exits
    // even when the fetch primitive is broken.
    let result = resolve_greedy_fused(
        client,
        HashMap::new(),
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true, // tests default to auto-install on
    )
    .await;
    assert!(result.is_ok());
}

/// Root-level `@lpm.dev/*` deps are pre-batched in one round trip
/// before the main fetch loop. This test asserts:
///   1. The pre-batch HTTP call hits exactly once for any number
///      of root lpm.dev names (not once per name).
///   2. Pre-batched results land in `shared_cache` so the main
///      loop's cache-hit fast path picks them up — no per-package
///      `fetch_metadata_raw` RPCs fire.
///   3. `dispatcher_rpc_count` reflects the batch as a single RPC.
#[tokio::test(flavor = "current_thread")]
async fn fusion_pre_batches_lpm_dev_root_deps() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Two root-level lpm.dev packages. The pre-batch must hit
    // POST /api/registry/batch-metadata exactly once and bundle
    // both names; subsequent main-loop `fetch_metadata_raw` calls
    // for these MUST NOT fire (cache pre-populated).
    let lpm_a_meta = metadata_json("@lpm.dev/owner.foo", &[]);
    let lpm_b_meta = metadata_json("@lpm.dev/owner.bar", &[]);
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "@lpm.dev/owner.foo": lpm_a_meta,
                        "@lpm.dev/owner.bar": lpm_b_meta,
                    }
                })),
        )
        // `expect(1)` is the load-bearing assertion — if pre-batch
        // were skipped and the main loop fell back to per-package
        // dispatch, this mock would either receive >1 hits (one
        // per package) or zero (the per-package endpoint is
        // GET /api/registry/<name>, not POST) and the test would
        // fail. Either failure mode catches a regression.
        .expect(1)
        .mount(&server)
        .await;
    // Per-package GET endpoints are NOT mounted. If the pre-batch
    // succeeded, the main loop hits the cache and never calls
    // GET. If pre-batch fails or is skipped, the main loop tries
    // GET /api/registry/@lpm.dev/owner.foo and wiremock returns
    // 404 — we assert the resolver succeeds, so 404s here would
    // surface as a hard-fail.

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("@lpm.dev/owner.foo".into(), "^1.0.0".into());
    deps.insert("@lpm.dev/owner.bar".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true, // tests default to auto-install on
    )
    .await
    .expect("pre-batched lpm.dev resolve should succeed");

    // Both lpm.dev packages resolved.
    assert_eq!(result.packages.len(), 2);
    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|p| p.package.canonical_name())
        .collect();
    assert!(names.contains("@lpm.dev/owner.foo"));
    assert!(names.contains("@lpm.dev/owner.bar"));

    // Exactly 1 dispatcher RPC counted — the batch. No per-package
    // RPCs fired (those would each tick the counter).
    assert_eq!(
        result.stage_timing.dispatcher_rpc_count, 1,
        "batch counts as 1 RPC; per-package dispatch would tick once per name (would be 2)"
    );
}

/// Root-level npm deps routed through the LPM Worker should use the
/// same deep batch endpoint as lpm.dev packages. One metadata RPC can
/// hydrate all routed root manifests, while direct mode and npmrc custom
/// registries stay off the Worker.
#[tokio::test(flavor = "current_thread")]
async fn fusion_pre_batches_worker_routed_npm_root_deps() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let npm_a_meta = metadata_json("proxy-root-a", &[]);
    let npm_b_meta = metadata_json("proxy-root-b", &[]);

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"proxy-root-a\""))
        .and(body_string_contains("\"proxy-root-b\""))
        .and(body_string_contains("\"deep\":true"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "proxy-root-a": npm_a_meta,
                        "proxy-root-b": npm_b_meta,
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("proxy-root-a".into(), "^1.0.0".into());
    deps.insert("proxy-root-b".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true,
    )
    .await
    .expect("Worker-routed npm roots should resolve from one metadata batch");

    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|p| p.package.canonical_name())
        .collect();
    assert!(names.contains("proxy-root-a"));
    assert!(names.contains("proxy-root-b"));
    assert_eq!(
        result.stage_timing.dispatcher_rpc_count, 1,
        "Worker-routed npm root metadata should batch into one dispatcher RPC"
    );
    assert_eq!(
        result.stage_timing.dispatcher_pending_high_water, 2,
        "both Worker-routed root metadata requests should count as pending"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_streaming_worker_batch_emits_selected_root_before_tail_metadata_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep, timeout};

    let _env = ScopedEnvVars::set(&[
        ("LPM_WORKER_RANGE_AWARE_BATCH", "1"),
        ("LPM_WORKER_STREAMING_BATCH", "1"),
    ]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let _ = stream.read(&mut request).await.unwrap();

        let root_line = serde_json::json!({
            "name": "proxy-stream-root",
            "metadata": metadata_json("proxy-stream-root", &[("proxy-stream-tail", "^1.0.0")]),
        })
        .to_string()
            + "\n";
        let tail_line = serde_json::json!({
            "name": "proxy-stream-tail",
            "metadata": metadata_json("proxy-stream-tail", &[]),
        })
        .to_string()
            + "\n";

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let root_header = format!("{:X}\r\n", root_line.len());
        stream.write_all(root_header.as_bytes()).await.unwrap();
        stream.write_all(root_line.as_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
        stream.flush().await.unwrap();

        sleep(Duration::from_millis(900)).await;

        let tail_header = format!("{:X}\r\n", tail_line.len());
        stream.write_all(tail_header.as_bytes()).await.unwrap();
        stream.write_all(tail_line.as_bytes()).await.unwrap();
        stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(format!("http://{address}"))
            .with_cache_dir(None),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut deps = HashMap::new();
    deps.insert("proxy-stream-root".into(), "^1.0.0".into());
    let resolver = resolve_greedy_fused_with_cache_options_policy_and_selected_events(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        Arc::new(dashmap::DashMap::new()),
        true,
        true,
        ResolverPolicy::default(),
        Some(tx),
    );
    tokio::pin!(resolver);

    let event = timeout(Duration::from_millis(500), async {
        tokio::select! {
            event = rx.recv() => {
                event.expect("selected-package channel should remain open")
            }
            _ = &mut resolver => {
                panic!("resolver finished before root selected-package event");
            }
        }
    })
    .await
    .expect("root selection should arrive before delayed tail metadata");
    assert_eq!(event.name, "proxy-stream-root");
    assert_eq!(event.version, "1.0.0");

    let result = resolver.await.expect("streaming resolve should succeed");
    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|p| p.package.canonical_name())
        .collect();
    assert!(names.contains("proxy-stream-root"));
    assert!(names.contains("proxy-stream-tail"));
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 1);

    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_streaming_worker_batch_waits_when_partial_cache_misses_edge_range() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};

    let _env = ScopedEnvVars::set(&[
        ("LPM_WORKER_RANGE_AWARE_BATCH", "1"),
        ("LPM_WORKER_STREAMING_BATCH", "1"),
    ]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let _ = stream.read(&mut request).await.unwrap();

        let lines = [
            serde_json::json!({
                "name": "proxy-partial-root",
                "metadata": metadata_json("proxy-partial-root", &[
                    ("aaa-first", "^1.0.0"),
                    ("zzz-second", "^1.0.0"),
                ]),
            })
            .to_string()
                + "\n",
            serde_json::json!({
                "name": "aaa-first",
                "metadata": metadata_json("aaa-first", &[("chalk", "^5.0.0")]),
            })
            .to_string()
                + "\n",
            serde_json::json!({
                "name": "chalk",
                "metadata": metadata_json_version("chalk", "5.6.2", &[]),
            })
            .to_string()
                + "\n",
            serde_json::json!({
                "name": "zzz-second",
                "metadata": metadata_json("zzz-second", &[("chalk", "^4.0.0")]),
            })
            .to_string()
                + "\n",
            serde_json::json!({
                "name": "chalk",
                "metadata": metadata_json_version("chalk", "4.1.2", &[]),
            })
            .to_string()
                + "\n",
        ];

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for (index, line) in lines.iter().enumerate() {
            if index == lines.len() - 1 {
                sleep(Duration::from_millis(100)).await;
            }
            let header = format!("{:X}\r\n", line.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(line.as_bytes()).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(format!("http://{address}"))
            .with_cache_dir(None),
    );
    let mut deps = HashMap::new();
    deps.insert("proxy-partial-root".into(), "^1.0.0".into());

    let result = resolve_greedy_fused_with_cache_options_policy_and_selected_events(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        Arc::new(dashmap::DashMap::new()),
        true,
        true,
        ResolverPolicy::default(),
        None,
    )
    .await
    .expect("partial streamed metadata should wait for a satisfying later entry");

    let chalk_versions: std::collections::HashSet<_> = result
        .packages
        .iter()
        .filter(|package| package.package.canonical_name() == "chalk")
        .map(|package| package.version.to_string())
        .collect();
    assert!(chalk_versions.contains("5.6.2"));
    assert!(chalk_versions.contains("4.1.2"));
    for version in ["5.6.2", "4.1.2"] {
        let package = result
            .packages
            .iter()
            .find(|package| {
                package.package.canonical_name() == "chalk"
                    && package.version.to_string() == version
            })
            .expect("chalk version should be resolved");
        assert!(
            package.tarball_url.is_some(),
            "chalk@{version} should keep tarball URL after merging partial metadata"
        );
        assert!(
            package.integrity.is_some(),
            "chalk@{version} should keep integrity after merging partial metadata"
        );
    }
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 1);

    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_streaming_worker_batch_refetches_full_metadata_for_late_peer_range() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let _env = ScopedEnvVars::set(&[
        ("LPM_WORKER_RANGE_AWARE_BATCH", "1"),
        ("LPM_WORKER_STREAMING_BATCH", "1"),
    ]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut root_meta = metadata_json(
        "proxy-peer-root",
        &[("shared-peer-v5", "npm:shared-peer@^5.0.0")],
    );
    root_meta["versions"]["1.0.0"]["peerDependencies"] =
        serde_json::json!({ "shared-peer": "^4.0.0" });
    let streamed_shared = metadata_json_version("shared-peer", "5.0.0", &[]);
    let mut full_shared = metadata_json_version("shared-peer", "5.0.0", &[]);
    let shared_v4 = metadata_json_version("shared-peer", "4.0.0", &[]);
    full_shared["versions"]["4.0.0"] = shared_v4["versions"]["4.0.0"].clone();
    full_shared["time"]["4.0.0"] = shared_v4["time"]["4.0.0"].clone();
    let body = [
        serde_json::json!({
            "name": "proxy-peer-root",
            "metadata": root_meta,
        })
        .to_string(),
        serde_json::json!({
            "name": "shared-peer",
            "metadata": streamed_shared,
        })
        .to_string(),
    ]
    .join("\n")
        + "\n";
    let full_shared_body = full_shared.to_string();
    let server = tokio::spawn(async move {
        for request_index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 8192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            if request_index == 0 {
                assert!(request.starts_with("POST /api/registry/batch-metadata "));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let header = format!("{:X}\r\n", body.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
                stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
            } else {
                assert!(request.starts_with("GET /api/registry/shared-peer "));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    full_shared_body.len(),
                    full_shared_body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(format!("http://{address}"))
            .with_cache_dir(None),
    );
    let mut deps = HashMap::new();
    deps.insert("proxy-peer-root".into(), "^1.0.0".into());

    let result = resolve_greedy_fused_with_cache_options_policy_and_selected_events(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        Arc::new(dashmap::DashMap::new()),
        true,
        true,
        ResolverPolicy::default(),
        None,
    )
    .await
    .expect(
        "late peer range should refetch full metadata instead of trusting a pruned cache entry",
    );

    let shared_versions: std::collections::HashSet<_> = result
        .packages
        .iter()
        .filter(|package| package.package.canonical_name() == "shared-peer")
        .map(|package| package.version.to_string())
        .collect();
    assert!(shared_versions.contains("5.0.0"));
    assert!(shared_versions.contains("4.0.0"));
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 2);

    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_streaming_worker_batch_streams_follow_up_tail_batch() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep, timeout};

    let _env = ScopedEnvVars::set(&[
        ("LPM_WORKER_RANGE_AWARE_BATCH", "1"),
        ("LPM_WORKER_STREAMING_BATCH", "1"),
    ]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for request_index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 8192];
            let _ = stream.read(&mut request).await.unwrap();

            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();

            if request_index == 0 {
                let root_line = serde_json::json!({
                    "name": "proxy-tail-stream-root",
                    "metadata": metadata_json("proxy-tail-stream-root", &[
                        ("proxy-tail-stream-a", "^1.0.0"),
                        ("proxy-tail-stream-b", "^1.0.0"),
                    ]),
                })
                .to_string()
                    + "\n";
                let header = format!("{:X}\r\n", root_line.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(root_line.as_bytes()).await.unwrap();
                stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
                continue;
            }

            let tail_a = serde_json::json!({
                "name": "proxy-tail-stream-a",
                "metadata": metadata_json("proxy-tail-stream-a", &[]),
            })
            .to_string()
                + "\n";
            let tail_b = serde_json::json!({
                "name": "proxy-tail-stream-b",
                "metadata": metadata_json("proxy-tail-stream-b", &[]),
            })
            .to_string()
                + "\n";

            let tail_a_header = format!("{:X}\r\n", tail_a.len());
            stream.write_all(tail_a_header.as_bytes()).await.unwrap();
            stream.write_all(tail_a.as_bytes()).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();

            sleep(Duration::from_millis(900)).await;

            let tail_b_header = format!("{:X}\r\n", tail_b.len());
            stream.write_all(tail_b_header.as_bytes()).await.unwrap();
            stream.write_all(tail_b.as_bytes()).await.unwrap();
            stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            stream.flush().await.unwrap();
        }
    });

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(format!("http://{address}"))
            .with_cache_dir(None),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut deps = HashMap::new();
    deps.insert("proxy-tail-stream-root".into(), "^1.0.0".into());
    let resolver = resolve_greedy_fused_with_cache_options_policy_and_selected_events(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        Arc::new(dashmap::DashMap::new()),
        true,
        true,
        ResolverPolicy::default(),
        Some(tx),
    );
    tokio::pin!(resolver);

    let tail_event = timeout(Duration::from_millis(700), async {
        loop {
            tokio::select! {
                event = rx.recv() => {
                    let event = event.expect("selected-package channel should remain open");
                    if event.name == "proxy-tail-stream-a" {
                        break event;
                    }
                }
                _ = &mut resolver => {
                    panic!("resolver finished before streamed tail selected-package event");
                }
            }
        }
    })
    .await
    .expect("tail selection should arrive before delayed second tail metadata");
    assert_eq!(tail_event.version, "1.0.0");

    let result = resolver
        .await
        .expect("follow-up tail stream resolve should succeed");
    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|package| package.package.canonical_name())
        .collect();
    assert!(names.contains("proxy-tail-stream-root"));
    assert!(names.contains("proxy-tail-stream-a"));
    assert!(names.contains("proxy-tail-stream-b"));
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 2);
    assert_eq!(
        result.stage_timing.dispatcher_pending_high_water, 2,
        "both requests in the streaming Worker tail batch should count as pending"
    );

    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_batches_worker_routed_tail_misses_after_root_batch() {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let root_meta = metadata_json(
        "proxy-root-with-tail",
        &[("proxy-tail-a", "^1.0.0"), ("proxy-tail-b", "^1.0.0")],
    );
    let tail_a_meta = metadata_json("proxy-tail-a", &[]);
    let tail_b_meta = metadata_json("proxy-tail-b", &[]);

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"proxy-root-with-tail\""))
        .and(body_string_contains("\"deep\":true"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "proxy-root-with-tail": root_meta,
                    }
                })),
        )
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"proxy-tail-a\""))
        .and(body_string_contains("\"proxy-tail-b\""))
        .and(body_string_contains("\"deep\":true"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "proxy-tail-a": tail_a_meta,
                        "proxy-tail-b": tail_b_meta,
                    }
                })),
        )
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/registry/proxy-tail-a"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&proxy_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/proxy-tail-b"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&proxy_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy-tail-a"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy-tail-b"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&npm_server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("proxy-root-with-tail".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true,
    )
    .await
    .expect("Worker-routed tail misses should resolve from one follow-up batch");

    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|p| p.package.canonical_name())
        .collect();
    assert!(names.contains("proxy-root-with-tail"));
    assert!(names.contains("proxy-tail-a"));
    assert!(names.contains("proxy-tail-b"));
    assert_eq!(
        result.stage_timing.dispatcher_rpc_count, 2,
        "root batch plus one tail batch should replace two per-package tail fetches"
    );
    assert_eq!(
        result.stage_timing.dispatcher_pending_high_water, 2,
        "both requests in the synchronous Worker tail batch should count as pending"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_batches_worker_routed_tree_policy_prefetch_misses() {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;
    let root_meta = metadata_json("proxy-policy-root", &[("proxy-policy-parent", "^1.0.0")]);
    let parent_meta = metadata_json(
        "proxy-policy-parent",
        &[
            ("proxy-policy-tail-a", "^1.0.0"),
            ("proxy-policy-tail-b", "^1.0.0"),
        ],
    );
    let tail_a_meta = metadata_json("proxy-policy-tail-a", &[]);
    let tail_b_meta = metadata_json("proxy-policy-tail-b", &[]);

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"proxy-policy-root\""))
        .and(body_string_contains("\"deep\":true"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "proxy-policy-root": root_meta,
                        "proxy-policy-parent": parent_meta,
                    }
                })),
        )
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .and(body_string_contains("\"proxy-policy-tail-a\""))
        .and(body_string_contains("\"proxy-policy-tail-b\""))
        .and(body_string_contains("\"deep\":true"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "packages": {
                        "proxy-policy-tail-a": tail_a_meta,
                        "proxy-policy-tail-b": tail_b_meta,
                    }
                })),
        )
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/registry/proxy-policy-tail-a"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&proxy_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/registry/proxy-policy-tail-b"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&proxy_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy-policy-tail-a"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&npm_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/proxy-policy-tail-b"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&npm_server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("proxy-policy-root".into(), "^1.0.0".into());
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, Default::default());

    let result = resolve_greedy_fused_with_cache_options_and_policy(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        shared_cache,
        true,
        true,
        policy,
    )
    .await
    .expect("release-age tree prefetch should batch Worker-routed missing children");

    let names: std::collections::HashSet<_> = result
        .packages
        .iter()
        .map(|p| p.package.canonical_name())
        .collect();
    assert!(names.contains("proxy-policy-root"));
    assert!(names.contains("proxy-policy-parent"));
    assert!(names.contains("proxy-policy-tail-a"));
    assert!(names.contains("proxy-policy-tail-b"));
    assert_eq!(
        result.stage_timing.dispatcher_rpc_count, 2,
        "root batch plus one release-age tree prefetch batch should avoid per-package tail fetches"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_direct_mode_does_not_batch_npm_root_deps() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let lpm_server = MockServer::start().await;
    let npm_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": {}
        })))
        .expect(0)
        .mount(&lpm_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/direct-root"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_json("direct-root", &[])))
        .expect(1)
        .mount(&npm_server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(lpm_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("direct-root".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct),
        8,
        None,
        true,
    )
    .await
    .expect("direct npm roots should resolve from the npm registry");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(result.packages[0].package.canonical_name(), "direct-root");
}

#[tokio::test(flavor = "current_thread")]
async fn trace_metadata_fetch_records_direct_npm_timing_attribution() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _timing_guard = crate::metadata_fetch_detail_test_lock().lock().await;
    lpm_registry::timing::reset_metadata_detail();

    let npm_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/direct-trace"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(5))
                .set_body_json(metadata_json("direct-trace", &[])),
        )
        .expect(1)
        .mount(&npm_server)
        .await;

    let client = RegistryClient::new()
        .with_npm_registry_url(npm_server.uri())
        .with_cache_dir(None);
    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("direct-trace");

    let fetched = fetch_metadata_for_resolver_with_trace_detail(
        &client,
        &route_table,
        &canonical,
        &ResolverPolicy::default(),
        false,
        true,
    )
    .await
    .expect("direct npm metadata fetch should succeed");

    assert_eq!(fetched.info.versions.len(), 1);
    let snapshot = lpm_registry::timing::snapshot_metadata_fetch_detail();
    assert_eq!(snapshot.calls, 1);
    assert_eq!(snapshot.route_npm_direct_count, 1);
    assert!(
        snapshot.attribution.raw_fetch_sum_ms > 0,
        "delayed direct fetch should populate raw fetch timing; got {snapshot:#?}"
    );
    let row = snapshot
        .top_slow_packages
        .by_total
        .first()
        .unwrap_or_else(|| {
            panic!("delayed direct fetch should rank a slow row; got {snapshot:#?}")
        });
    assert_eq!(row.package, "direct-trace");
    assert_eq!(row.route, "npm_direct");
    assert!(row.body_bytes > 0);
    assert_eq!(row.version_count, 1);

    lpm_registry::timing::reset_metadata_detail();
}

#[tokio::test(flavor = "current_thread")]
async fn trace_metadata_fetch_records_cached_release_time_policy_followup() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _timing_guard = crate::metadata_fetch_detail_test_lock().lock().await;
    lpm_registry::timing::reset_metadata_detail();

    let npm_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cached-policy-trace"))
        .and(header("accept", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(5))
                .set_body_json(metadata_json("cached-policy-trace", &[])),
        )
        .expect(1)
        .mount(&npm_server)
        .await;

    let client = RegistryClient::new()
        .with_npm_registry_url(npm_server.uri())
        .with_cache_dir(None);
    let route_table = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("cached-policy-trace");
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());
    let mut cached_info = mk_info(&["1.0.0"], &[]);
    cached_info.modified = Some("2025-01-03T00:00:00.000Z".to_string());
    cached_info.modified_unix = parse_npm_time_unix("2025-01-03T00:00:00.000Z");
    let policy = ResolverPolicy::with_cutoff_unix(86_400, 1_735_776_000, TrustPolicyMode::Off);

    let hydrated = ensure_policy_metadata_for_cached_manifest(
        &canonical,
        Arc::new(cached_info),
        &client,
        &route_table,
        &shared_cache,
        &policy,
        true,
    )
    .await
    .expect("cached release-age policy follow-up should hydrate publish times");

    assert_eq!(
        hydrated.published_at("1.0.0"),
        Some("2025-01-01T00:00:00.000Z")
    );
    let snapshot = lpm_registry::timing::snapshot_metadata_fetch_detail();
    assert_eq!(snapshot.calls, 1);
    assert_eq!(snapshot.route_npm_direct_count, 1);
    assert!(
        snapshot.attribution.policy_release_time_sum_ms > 0,
        "delayed policy fetch should populate release-time attribution; got {snapshot:#?}"
    );
    let row = snapshot
        .top_slow_packages
        .by_policy_release_time
        .first()
        .unwrap_or_else(|| {
            panic!("delayed policy fetch should rank a release-time row; got {snapshot:#?}")
        });
    assert_eq!(row.package, "cached-policy-trace");
    assert_eq!(row.route, "npm_direct");
    assert_eq!(row.version_count, 1);

    lpm_registry::timing::reset_metadata_detail();
}

#[tokio::test(flavor = "current_thread")]
async fn fusion_falls_back_to_direct_npm_when_worker_batch_denies_access() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let proxy_server = MockServer::start().await;
    let npm_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "upstream_proxy_entitlement_required",
            "message": "upstream proxy access required"
        })))
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/registry/proxy-access-fallback"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "upstream_proxy_entitlement_required",
            "message": "upstream proxy access required"
        })))
        .expect(1)
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/proxy-access-fallback"))
        .and(header("accept", "application/vnd.npm.install-v1+json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_json("proxy-access-fallback", &[])),
        )
        .expect(1)
        .mount(&npm_server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(proxy_server.uri())
            .with_npm_registry_url(npm_server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("proxy-access-fallback".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true,
    )
    .await
    .expect("Worker access denial should fall back to direct npm metadata");

    assert_eq!(result.packages.len(), 1);
    assert_eq!(
        result.packages[0].package.canonical_name(),
        "proxy-access-fallback"
    );
    assert_eq!(
        result.stage_timing.dispatcher_rpc_count, 1,
        "failed proxy batch is not a resolved-data RPC; direct fallback fetch is"
    );
}

/// Pre-batch fallback: when the batch endpoint errors, the main
/// loop must still resolve via per-package `fetch_metadata_raw`.
/// This test pins the failure-mode contract: batch error →
/// graceful fall-through, no hang, no propagated error.
#[tokio::test(flavor = "current_thread")]
async fn fusion_falls_through_on_lpm_dev_batch_failure() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Batch endpoint returns 500 — pre-batch must log and
    // fall through.
    Mock::given(method("POST"))
        .and(path("/api/registry/batch-metadata"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    // Per-package GET endpoint serves the lpm.dev metadata as a
    // fallback. Path matches the GET /api/registry/<scoped> shape
    // `get_package_metadata` calls.
    let lpm_meta = metadata_json("@lpm.dev/owner.foo", &[]);
    Mock::given(method("GET"))
        .and(path("/api/registry/@lpm.dev/owner.foo"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(lpm_meta),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Arc::new(
        RegistryClient::new()
            .with_base_url(server.uri())
            .with_cache_dir(None),
    );

    let mut deps = HashMap::new();
    deps.insert("@lpm.dev/owner.foo".into(), "^1.0.0".into());

    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Proxy),
        8,
        None,
        true, // tests default to auto-install on
    )
    .await
    .expect(
        "batch failure must fall through to per-package dispatch — \
         resolve still succeeds",
    );

    assert_eq!(result.packages.len(), 1);
    // 1 dispatcher RPC — the per-package fallback. The failed
    // batch attempt does NOT increment dispatcher_rpc_count
    // (we only count successful batches; failures are
    // observability noise, not real RPCs that resolved data).
    assert_eq!(result.stage_timing.dispatcher_rpc_count, 1);
}

/// Required dep with a client that fails: the resolver must
/// propagate `ResolveError::DependencyFetch` (not hang waiting
/// for the fetch, not panic on a debug_assert). Drives the full
/// dispatcher loop so the parked-edge resume-on-error path is
/// exercised end-to-end.
#[tokio::test(flavor = "current_thread")]
async fn fusion_propagates_required_fetch_failure() {
    // Use a port that's filtered (TEST-NET-1, RFC 5737, .254 host
    // is reserved). reqwest will time out on connect after the
    // configured timeout — but since we point at 127.0.0.1:9
    // (discard, kernel rejects), it errors immediately instead.
    let client = Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9"));
    let mut deps = HashMap::new();
    deps.insert("nonexistent-pkg".to_string(), "^1.0.0".to_string());
    let result = resolve_greedy_fused(
        client,
        deps,
        OverrideSet::empty(),
        RouteTable::from_mode_only(RouteMode::Direct), // npm-direct route — discard port (9) errors immediately
        8,
        None,
        true, // tests default to auto-install on
    )
    .await;
    // Either the fetch errors or NoSolution; both are acceptable
    // termination outcomes that prove the dispatcher exits the
    // loop. The critical invariant is "no hang" — the test would
    // hit tokio's default test timeout if termination broke.
    match result {
        Err(
            ResolveError::Resolution(_)
            | ResolveError::DependencyFetch { .. }
            | ResolveError::NoSolution(_),
        ) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
        Ok(_) => panic!("required dep with broken client must fail, not succeed"),
    }
}
