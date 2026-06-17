use super::deps::*;
use super::edge::*;
use super::fused::*;
use super::manifest::*;
use super::peer::*;
use super::policy::*;
use super::prelude::*;
use super::state::*;
use super::types::*;
use super::version::*;
use crate::provider::{CachedDistInfo, CachedPackageInfo};

/// Build a minimal npm-packument JSON shape for wiremock-based
/// resolver tests. Mirrors `walker::tests::metadata_json` so the
/// fixture shape stays identical across resolver-arm tests.
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
        modified: None,
        trust_metadata_complete: false,
        versions: parsed,
        deps: deps_map,
        peer_deps: HashMap::new(),
        optional_dep_names: HashMap::new(),
        optional_peer_names: HashMap::new(),
        bundled_dep_names: HashMap::new(),
        platform: HashMap::new(),
        dist: versions
            .iter()
            .map(|v| {
                (
                    v.to_string(),
                    CachedDistInfo {
                        tarball_url: Some(format!("https://example.invalid/{}.tgz", v)),
                        integrity: Some(format!("sha512-fake-{}", v)),
                        signatures: Vec::new(),
                        published_at: None,
                        trust_evidence: None,
                    },
                )
            })
            .collect(),
        aliases: HashMap::new(),
    }
}

#[test]
fn parse_fetched_metadata_omits_speculation_when_disabled() {
    let metadata = serde_json::from_value(metadata_json("spec-skip", &[("left-pad", "^1.0.0")]))
        .expect("fixture metadata should parse");

    let fetched = parse_fetched_metadata(metadata, false);

    assert!(fetched.speculation.is_none());
    assert_eq!(fetched.info.versions.len(), 1);
}

#[test]
fn parse_fetched_metadata_preserves_speculation_when_enabled() {
    let metadata = serde_json::from_value(metadata_json("spec-keep", &[("left-pad", "^1.0.0")]))
        .expect("fixture metadata should parse");

    let fetched = parse_fetched_metadata(metadata, true);

    let speculation = fetched
        .speculation
        .expect("speculation should be built when requested");
    assert_eq!(
        speculation
            .info
            .deps
            .get("1.0.0")
            .and_then(|dependencies| dependencies.get("left-pad"))
            .map(String::as_str),
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
    info.dist.get_mut(version).unwrap().published_at = Some(published_at.to_string());
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
        fetched
            .info
            .dist
            .get("1.0.0")
            .and_then(|dist| dist.published_at.as_deref()),
        Some("2025-01-01T00:00:00.000Z")
    );
}

#[test]
fn find_best_version_ignores_platform_when_selecting_version() {
    // Platform filtering happens after resolution so lockfiles stay
    // portable. The newest semver-satisfying version wins even when
    // it is incompatible with the current host.
    let mut info = mk_info(&["1.0.0"], &[]);
    info.platform.insert(
        "1.0.0".to_string(),
        crate::provider::PlatformMeta {
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
        },
    );
    let range = NpmRange::parse("^1.0.0").unwrap();
    assert_eq!(
        picked(find_best_version(&info, &range)).to_string(),
        "1.0.0"
    );
}

#[test]
fn find_best_version_skips_trust_downgrade_when_older_candidate_satisfies_range() {
    let mut info = mk_info(&["1.1.0", "1.0.0"], &[]);
    info.dist.get_mut("1.0.0").unwrap().published_at = Some("2025-01-01T00:00:00.000Z".to_string());
    info.dist.get_mut("1.0.0").unwrap().trust_evidence =
        Some(crate::policy::TrustEvidence::TrustedPublisher);
    info.dist.get_mut("1.1.0").unwrap().published_at = Some("2025-01-02T00:00:00.000Z".to_string());
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
    info.dist.get_mut("1.0.0").unwrap().published_at = Some("2025-01-01T00:00:00.000Z".to_string());
    info.dist.get_mut("1.0.0").unwrap().trust_evidence =
        Some(crate::policy::TrustEvidence::TrustedPublisher);
    info.dist.get_mut("1.1.0").unwrap().published_at = Some("2025-01-02T00:00:00.000Z".to_string());
    let policy = ResolverPolicy::new(0, crate::policy::TrustPolicyMode::NoDowngrade);
    let range = NpmRange::parse("1.1.0").unwrap();

    assert!(matches!(
        find_best_version_with_policy(&CanonicalKey::Root, &info, &range, &policy),
        VersionPick::BlockedByTrustPolicy { .. }
    ));
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
fn process_edge_reuses_node_when_existing_version_satisfies_new_range() {
    // Two parents both wanting `lodash` with COMPATIBLE ranges
    // (^4.0.0 and ^4.10.0 both satisfied by 4.17.21) should produce
    // ONE resolved node, two parent→child edges. The first edge
    // picks 4.17.21; the second sees an existing node whose version
    // satisfies its tighter range and reuses it.
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
fn process_edge_allocates_second_version_on_incompatible_range() {
    // Two parents wanting INCOMPATIBLE ranges of the same canonical
    // (^4.0.0 picks 4.17.21; ^3.0.0 cannot reuse 4.17.21 → must
    // allocate a new node for 3.10.1). Both versions live in the
    // resolved tree as distinct nodes — bun + npm + pnpm semantics.
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
//   - Irreconcilable targets (out-of-range — fall back to natural)

/// Helper: build an OverrideSet from a single `lpm.overrides`
/// entry. Path-selector tests use a separate path-key form via
/// the same parser.
fn override_set(key: &str, target: &str) -> OverrideSet {
    let mut lpm = HashMap::new();
    lpm.insert(key.to_string(), target.to_string());
    OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new()).expect("test override should parse")
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
fn process_edge_range_target_picks_newest_in_intersection() {
    // `lpm.overrides: { "lodash": "^3.0.0" }` — constrains the
    // candidate set to 3.x and lets the resolver pick the newest
    // match in the consumer's range × override range intersection.
    let info = mk_info(&["4.17.21", "3.10.1", "3.0.0"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "*".to_string());
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
        "newest version in 3.x — consumer's `*` × override's `^3.0.0`"
    );
}

#[test]
fn process_edge_irreconcilable_override_falls_through_to_natural() {
    // Pinned target is OUTSIDE the consumer's declared range. The
    // resolver should fall through to the natural pick rather than
    // silently picking a version the consumer never asked for. No
    // OverrideHit is recorded — the override didn't take effect.
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), "^4.0.0".to_string());
    // Override pin to 3.10.1 — outside ^4.0.0.
    let mut state = ResolveState::new(deps, override_set("lodash", "3.10.1"));
    state.seed_root_edges().unwrap();
    while let Some(edge) = state.task_queue.pop_front() {
        process_edge(&edge, &info, &mut state).unwrap();
    }

    let lodash_entries = &state.resolved[&CanonicalKey::npm("lodash")];
    assert_eq!(lodash_entries.len(), 1);
    assert_eq!(
        lodash_entries[0].0.to_string(),
        "4.17.21",
        "irreconcilable override falls through to natural pick"
    );
    assert!(
        state.overrides.take_hits().is_empty(),
        "no OverrideHit when override didn't apply"
    );
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
    // Pre-fix, that's exactly what happened — the path-selector
    // override leaked into every sibling of `react`. Post-fix,
    // `OverrideSet::split_targets` (containing "lodash") forces
    // exact-match dedupe on every slow-path edge, so the root
    // edge allocates the natural 4.17.21 in its own node.
    let info = mk_info(&["4.17.21", "3.10.1"], &[]);
    let mut deps = HashMap::new();
    deps.insert("lodash".to_string(), ">=3.0.0".to_string());
    let mut state = ResolveState::new(deps, override_set("react>lodash", "3.10.1"));

    // Hand-seed both parents WITHOUT calling `seed_root_edges()`,
    // which would push the root>lodash edge first. Reverse order
    // (react edge enqueued before root edge) is what surfaces the
    // pre-fix bug.
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
    let mut info = mk_info(&["1.0.0"], &[]);
    let mut deps_of_latest = HashMap::new();
    deps_of_latest.insert("lodash".to_string(), "^4.0.0".to_string());
    deps_of_latest.insert("react".to_string(), "^18.0.0".to_string());
    info.deps.insert("1.0.0".to_string(), deps_of_latest);
    let mut bundled = HashSet::new();
    bundled.insert("lodash".to_string());
    info.bundled_dep_names.insert("1.0.0".to_string(), bundled);

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
    );

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
    let mut info = mk_info(&["1.0.0"], &[]);
    let mut deps_of_latest = HashMap::new();
    deps_of_latest.insert("lodash".to_string(), "^4.0.0".to_string());
    deps_of_latest.insert("react".to_string(), "^18.0.0".to_string());
    info.deps.insert("1.0.0".to_string(), deps_of_latest);
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
    );

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
    let mut info = mk_info(&["1.0.0"], &[]);
    let mut deps_of_latest = HashMap::new();
    deps_of_latest.insert("required-child".to_string(), "^1.0.0".to_string());
    deps_of_latest.insert("optional-child".to_string(), "^2.0.0".to_string());
    info.deps.insert("1.0.0".to_string(), deps_of_latest);
    let mut optional = HashSet::new();
    optional.insert("optional-child".to_string());
    info.optional_dep_names
        .insert("1.0.0".to_string(), optional);

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
    );

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
fn enqueue_child_deps_skips_workspace_specifier_with_warn() {
    // Registry-published packages should not declare `workspace:`
    // deps. If a malformed cache entry slips one in, the transitive
    // edge is silently skipped (continue) rather than failing the
    // whole resolve. Mirrors the existing "invalid range" branch's
    // skip-with-warn semantic.
    let mut info = mk_info(&["1.0.0"], &[]);
    let mut deps_of_latest = HashMap::new();
    deps_of_latest.insert("workspace-leak".to_string(), "workspace:^1".to_string());
    deps_of_latest.insert("plain-dep".to_string(), "^2.0.0".to_string());
    info.deps.insert("1.0.0".to_string(), deps_of_latest);

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
    );

    // Only `plain-dep` should have been enqueued; `workspace-leak`
    // got skipped at the workspace-specifier guard.
    let queued: Vec<&str> = state
        .task_queue
        .iter()
        .map(|e| e.local_name.as_str())
        .collect();
    assert_eq!(queued, vec!["plain-dep"]);
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
    let mut peer_map = HashMap::new();
    for (n, r) in peers_of_latest {
        peer_map.insert(n.to_string(), r.to_string());
    }
    info.peer_deps.insert(latest.to_string(), peer_map);
    if !optional_peers_of_latest.is_empty() {
        let mut optional = HashSet::new();
        for n in optional_peers_of_latest {
            optional.insert(n.to_string());
        }
        info.optional_peer_names
            .insert(latest.to_string(), optional);
    }
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
    );
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
    let mut info = mk_info_with_peers(&["1.0.0"], &[], &[("react", "^18.0.0")], &[]);
    info.deps.remove("1.0.0");

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
    // Inject the alias map for the latest version.
    let mut aliases = HashMap::new();
    aliases.insert("my-react".to_string(), "react".to_string());
    info.aliases.insert("1.0.0".to_string(), aliases);

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
fn peer_collection_skips_workspace_specifier() {
    // A registry-published manifest declaring a `workspace:` peer
    // is malformed (npm rejects at publish time). The collector
    // skips it with a workspace-specific log rather than letting
    // `NpmRange::parse` emit an opaque semver error. Mirrors the
    // regular-deps loop.
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[("legit-peer", "^1.0.0"), ("internal-peer", "workspace:*")],
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
        vec!["legit-peer"],
        "workspace: peer skipped; legit peer recorded"
    );
}

#[test]
fn peer_collection_skips_invalid_range() {
    // Defense: an unparseable peer range emits a debug warn and
    // is skipped. Does NOT panic / propagate an error — the
    // resolver must continue resolving the rest of the graph.
    let info = mk_info_with_peers(
        &["1.0.0"],
        &[],
        &[("good-peer", "^1.0.0"), ("bad-peer", "this-is-not-semver")],
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
        vec!["good-peer"],
        "unparseable peer range skipped silently"
    );
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
fn process_edge_reuses_newest_existing_version_when_multiple_satisfy_range() {
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
        "reuse must be independent of the order compatible nodes were allocated"
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
    push_node(&mut state, CanonicalKey::npm("plugin"), "1.0.0");
    push_node(&mut state, CanonicalKey::npm("react"), "17.0.2");
    push_node(&mut state, CanonicalKey::npm("react"), "18.2.0");

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

    let resolved = state.into_resolved_packages(&cache);
    let plugin = resolved
        .iter()
        .find(|pkg| pkg.package.canonical_name() == "plugin")
        .expect("plugin package present");
    assert_eq!(
        plugin.peers,
        vec![("react".to_string(), "17.0.2".to_string())],
        "greedy finalization should bind the peer version satisfying the consumer range"
    );
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
    // Mirrors npm v7+ / pnpm hoisted behavior.
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
fn process_edge_zero_overrides_takes_hot_path_unchanged() {
    // Sanity check: with no overrides, the slow-path branch is
    // never entered — the existing (range.satisfies → reuse,
    // else find_best_version → allocate) semantic is byte-
    // identical. Guards against an accidental regression where
    // the slow path becomes the default.
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
async fn fusion_auto_installs_peer_when_sparse_cache_omits_empty_dependency_entry() {
    let shared_cache: SharedCache = Arc::new(dashmap::DashMap::new());

    let mut peer_host = mk_info_with_peers(&["1.0.0"], &[], &[("ghost-peer", "^1.0.0")], &[]);
    peer_host.deps.remove("1.0.0");
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
