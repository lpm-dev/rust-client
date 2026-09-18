use super::*;

fn provider(entries: &[(&str, &str)]) -> LpmDependencyProvider {
    make_provider_with_cache(
        HashMap::new(),
        vec![(
            ResolverPackage::npm("target"),
            make_info(&["3.0.0", "2.0.0"], vec![], vec![], vec![]),
        )],
    )
    .with_overrides(
        OverrideSet::parse(
            &entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap(),
    )
}

fn effective(provider: &LpmDependencyProvider, parent: &str, raw: &str) -> Ranges<NpmVersion> {
    let child = ResolverPackage::npm("target");
    let range = NpmRange::parse(raw)
        .unwrap()
        .to_pubgrub_ranges(&provider.available_versions(&child));
    provider.effective_dependency_range(
        &ResolverPackage::npm(parent),
        &NpmVersion::new(1, 0, 0),
        "target",
        &child,
        range,
    )
}

#[test]
fn range_qualified_selectors_do_not_rescue_a_missing_natural_candidate() {
    for key in ["target@1", "parent>target@1"] {
        let provider = provider(&[(key, "2.0.0")]);
        assert!(effective(&provider, "parent", "^1").is_empty());
    }
}

#[test]
fn rescue_does_not_reapply_a_qualified_selector_to_the_target() {
    let provider = provider(&[("target", "2.0.0"), ("target@2", "3.0.0")]);
    let range = effective(&provider, "parent", "^1");
    let chosen = provider
        .choose_version(&ResolverPackage::npm("target"), &range)
        .unwrap();
    assert_eq!(chosen, Some(NpmVersion::new(2, 0, 0)));
    let natural_range = effective(&provider, "other", "^2");
    assert_eq!(natural_range, Ranges::singleton(NpmVersion::new(3, 0, 0)));
}

#[test]
fn rejected_rescue_retains_the_empty_constraint() {
    let provider = provider(&[("target", "99.0.0")]);
    assert!(effective(&provider, "parent", "^1").is_empty());
}

#[test]
fn unchanged_override_still_restricts_the_solver_constraint() {
    let provider = provider(&[("target", "3.0.0")]);
    let range = effective(&provider, "parent", ">=2");
    assert_eq!(range, Ranges::singleton(NpmVersion::new(3, 0, 0)));
    assert!(provider.override_edges.lock().is_empty());
}

#[test]
fn override_trace_excludes_discarded_parent_versions() {
    let provider = provider(&[("target", "2.0.0")]);
    effective(&provider, "parent", "^1");
    let mut solution = pubgrub::Map::default();
    solution.insert(ResolverPackage::npm("parent"), NpmVersion::new(2, 0, 0));
    solution.insert(ResolverPackage::npm("target"), NpmVersion::new(2, 0, 0));
    assert!(provider.selected_override_hits(&solution).is_empty());
}

#[test]
fn solver_callback_never_returns_a_version_outside_its_constraint() {
    let provider = provider(&[("target", "2.0.0")]);
    let constraint = Ranges::singleton(NpmVersion::new(3, 0, 0));
    assert_eq!(
        provider
            .choose_version(&ResolverPackage::npm("target"), &constraint)
            .unwrap(),
        Some(NpmVersion::new(3, 0, 0))
    );
}

#[test]
fn aliased_self_cycle_reuses_the_same_dependency_identity() {
    let parent = ResolverPackage::npm("self-cycle");
    let info = parse_metadata_to_cache_info(&serde_json::from_value(serde_json::json!({
        "name":"self-cycle", "versions": {"1.0.0": {
            "name":"self-cycle", "version":"1.0.0", "dependencies": {"self-alias":"npm:self-cycle@1.0.0"}
        }}
    })).unwrap());
    let provider = make_provider_with_cache(HashMap::new(), vec![(parent.clone(), info)]);
    let version = NpmVersion::new(1, 0, 0);
    let Dependencies::Available(first) = provider.get_dependencies(&parent, &version).unwrap()
    else {
        panic!("dependencies unavailable")
    };
    let child = first.keys().next().unwrap();
    let Dependencies::Available(second) = provider.get_dependencies(child, &version).unwrap()
    else {
        panic!("dependencies unavailable")
    };
    assert_eq!(
        first.keys().collect::<Vec<_>>(),
        second.keys().collect::<Vec<_>>()
    );
}

#[test]
fn alias_identity_keeps_distinct_parent_versions() {
    let parent = ResolverPackage::npm("parent");
    let first = ResolverPackage::from_transitive_dependency(
        &parent,
        &NpmVersion::new(1, 0, 0),
        "alias",
        "target",
        false,
    );
    let second = ResolverPackage::from_transitive_dependency(
        &parent,
        &NpmVersion::new(2, 0, 0),
        "alias",
        "target",
        false,
    );
    assert_ne!(first, second);
}

#[test]
fn two_package_alias_cycle_has_finite_identities() {
    let version = NpmVersion::new(1, 0, 0);
    let a = ResolverPackage::npm("a");
    let b = ResolverPackage::from_transitive_dependency(&a, &version, "b-alias", "b", false);
    let next_a = ResolverPackage::from_transitive_dependency(&b, &version, "a-alias", "a", false);
    let next_b =
        ResolverPackage::from_transitive_dependency(&next_a, &version, "b-alias", "b", false);
    assert_eq!(b, next_b);
}

#[test]
fn experimental_greedy_rescue_preserves_selector_and_policy_checks() {
    use crate::greedy::{
        ExperimentalVersionSelection, experimental_select_version_with_policy_and_overrides_outcome,
    };
    let canonical = CanonicalKey::npm("target");
    let info = make_info(&["2.0.0"], vec![], vec![], vec![]);
    let range = NpmRange::parse("^1").unwrap();
    for (selector, target, rescued) in [
        ("target", "2.0.0", true),
        ("parent>target", "2.0.0", true),
        ("target@1", "2.0.0", false),
        ("parent>target@1", "2.0.0", false),
        ("target", "99.0.0", false),
    ] {
        let outcome = experimental_select_version_with_policy_and_overrides_outcome(
            &canonical,
            &info,
            &range,
            &ResolverPolicy::default(),
            &override_set_with(selector, target),
            Some("parent"),
        );
        assert_eq!(
            matches!(outcome.selection, ExperimentalVersionSelection::Picked(_)),
            rescued,
            "{selector} → {target}"
        );
        if rescued {
            assert!(outcome.override_hit.unwrap().from_version.is_none());
        }
    }
}
