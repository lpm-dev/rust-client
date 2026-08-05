use super::super::graph::{
    attach_reused_dependency_edge, inline_reuse_can_preserve_optional_state, mark_required_closure,
    normalize_draft_optional_reachability, package_should_materialize, reusable_existing_version,
    select_or_reuse_node,
};
use super::common::{
    empty_info_value, fake_draft, fake_package, info_with_versions, override_set,
    resolve_request_for_test,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[test]
fn package_materialization_skips_optional_platform_incompatible_package() {
    let mut package = fake_package("platform-leaf", "1.0.0", &[]);
    package.optional = true;
    package.platform = Some(lpm_resolver::PlatformMeta {
        os: vec!["definitely-not-this-os".to_string()],
        cpu: Vec::new(),
        libc: Vec::new(),
    });

    assert!(!package_should_materialize(&package).unwrap());
}

#[test]
fn reused_dependency_edge_attaches_parent_without_resolving_again() {
    let mut packages = HashMap::new();
    packages.insert(
        ("parent".to_string(), "1.0.0".to_string()),
        fake_draft("parent", "1.0.0", &[]),
    );
    packages.insert(
        ("child".to_string(), "1.2.3".to_string()),
        fake_draft("child", "1.2.3", &[]),
    );
    let request = resolve_request_for_test(
        "child",
        "^1.0.0",
        Some(("parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );

    attach_reused_dependency_edge(&mut packages, &request, "1.2.3").unwrap();

    assert_eq!(
        packages
            .get(&("parent".to_string(), "1.0.0".to_string()))
            .unwrap()
            .package
            .dependencies,
        vec![("child".to_string(), "1.2.3".to_string())]
    );
}

#[test]
fn inline_reuse_defers_optional_to_required_promotion() {
    let mut packages = HashMap::new();
    let mut child = fake_draft("child", "1.2.3", &[]);
    child.package.optional = true;
    packages.insert(("child".to_string(), "1.2.3".to_string()), child);
    let request = resolve_request_for_test(
        "child",
        "^1.0.0",
        Some(("parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );

    assert!(!inline_reuse_can_preserve_optional_state(&packages, &request, "1.2.3").unwrap());
}

#[test]
fn optional_reachability_marks_reused_optional_descendants_required() {
    let mut packages = HashMap::new();
    let mut required_parent = fake_draft("required-parent", "1.0.0", &[("shared", "1.0.0")]);
    required_parent.package.root_link_names = Some(vec!["required-parent".to_string()]);

    let mut optional_parent = fake_draft("optional-parent", "1.0.0", &[("shared", "1.0.0")]);
    optional_parent.package.root_link_names = Some(vec!["optional-parent".to_string()]);
    let mut optional_parent_info = empty_info_value();
    optional_parent_info
        .optional_dep_names
        .insert("1.0.0".to_string(), HashSet::from(["shared".to_string()]));
    optional_parent.info = Arc::new(optional_parent_info);

    let mut shared = fake_draft("shared", "1.0.0", &[("leaf", "1.0.0")]);
    shared.package.optional = true;
    let mut leaf = fake_draft("leaf", "1.0.0", &[]);
    leaf.package.optional = true;

    packages.insert(
        ("required-parent".to_string(), "1.0.0".to_string()),
        required_parent,
    );
    packages.insert(
        ("optional-parent".to_string(), "1.0.0".to_string()),
        optional_parent,
    );
    packages.insert(("shared".to_string(), "1.0.0".to_string()), shared);
    packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

    normalize_draft_optional_reachability(&mut packages);

    assert!(
        !packages
            .get(&("shared".to_string(), "1.0.0".to_string()))
            .unwrap()
            .package
            .optional
    );
    assert!(
        !packages
            .get(&("leaf".to_string(), "1.0.0".to_string()))
            .unwrap()
            .package
            .optional
    );
}

#[test]
fn optional_reachability_keeps_optional_only_subtree_optional() {
    let mut packages = HashMap::new();
    let mut parent = fake_draft("parent", "1.0.0", &[("child", "1.0.0")]);
    parent.package.root_link_names = Some(vec!["parent".to_string()]);
    let mut parent_info = empty_info_value();
    parent_info
        .optional_dep_names
        .insert("1.0.0".to_string(), HashSet::from(["child".to_string()]));
    parent.info = Arc::new(parent_info);

    let mut child = fake_draft("child", "1.0.0", &[("leaf", "1.0.0")]);
    child.package.optional = false;
    let mut leaf = fake_draft("leaf", "1.0.0", &[]);
    leaf.package.optional = false;

    packages.insert(("parent".to_string(), "1.0.0".to_string()), parent);
    packages.insert(("child".to_string(), "1.0.0".to_string()), child);
    packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

    normalize_draft_optional_reachability(&mut packages);

    assert!(
        packages
            .get(&("child".to_string(), "1.0.0".to_string()))
            .unwrap()
            .package
            .optional
    );
    assert!(
        packages
            .get(&("leaf".to_string(), "1.0.0".to_string()))
            .unwrap()
            .package
            .optional
    );
}

#[test]
fn reusable_existing_version_prefers_newest_satisfying_non_root_package() {
    let mut packages = HashMap::new();
    packages.insert(
        ("dep".to_string(), "1.0.0".to_string()),
        fake_draft("dep", "1.0.0", &[]),
    );
    packages.insert(
        ("dep".to_string(), "1.5.0".to_string()),
        fake_draft("dep", "1.5.0", &[]),
    );
    packages.insert(
        ("dep".to_string(), "2.0.0".to_string()),
        fake_draft("dep", "2.0.0", &[]),
    );
    let request = resolve_request_for_test(
        "dep",
        "^1.0.0",
        Some(("parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );

    let selected = reusable_existing_version(&request, &packages).unwrap();

    assert_eq!(selected.as_deref(), Some("1.5.0"));
}

#[test]
fn reusable_existing_version_does_not_reuse_for_root_package() {
    let mut packages = HashMap::new();
    packages.insert(
        ("dep".to_string(), "1.0.0".to_string()),
        fake_draft("dep", "1.0.0", &[]),
    );
    let request = resolve_request_for_test("dep", "^1.0.0", None, true, true);

    let selected = reusable_existing_version(&request, &packages).unwrap();

    assert_eq!(selected, None);
}

#[test]
fn select_or_reuse_node_keeps_unchanged_name_override_exact_before_range_reuse() {
    let mut packages = HashMap::new();
    packages.insert(
        ("dep".to_string(), "1.0.0".to_string()),
        fake_draft("dep", "1.0.0", &[]),
    );
    let request = resolve_request_for_test(
        "dep",
        "^1.0.0",
        Some(("parent".to_string(), "1.0.0".to_string())),
        false,
        false,
    );
    let info = Arc::new(info_with_versions(&["1.5.0", "1.0.0"]));
    let overrides = override_set("dep", "1.5.0");

    let node = select_or_reuse_node(
        request,
        info,
        &mut packages,
        &overrides,
        &lpm_resolver::ResolverPolicy::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(node.version, "1.5.0");
    assert!(!node.reused_existing);
    assert!(overrides.take_hits().is_empty());
}

#[test]
fn select_or_reuse_node_honors_path_override_before_satisfying_reuse() {
    let mut packages = HashMap::new();
    packages.insert(
        ("ajv".to_string(), "8.20.0".to_string()),
        fake_draft("ajv", "8.20.0", &[]),
    );
    let request = resolve_request_for_test(
        "ajv",
        "^8.0.0",
        Some(("schema-utils".to_string(), "4.3.3".to_string())),
        false,
        false,
    );
    let info = Arc::new(info_with_versions(&["8.20.0", "8.18.0"]));
    let overrides = override_set("schema-utils>ajv", "8.18.0");

    let node = select_or_reuse_node(
        request,
        info,
        &mut packages,
        &overrides,
        &lpm_resolver::ResolverPolicy::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(node.version, "8.18.0");
    assert!(!node.reused_existing);
    assert_eq!(overrides.take_hits().len(), 1);
}

#[test]
fn mark_required_closure_marks_existing_optional_descendants_required() {
    let mut packages = HashMap::new();
    let mut parent = fake_draft("parent", "1.0.0", &[("child", "1.0.0")]);
    parent.package.optional = true;
    let mut child = fake_draft("child", "1.0.0", &[("leaf", "1.0.0")]);
    child.package.optional = true;
    let mut leaf = fake_draft("leaf", "1.0.0", &[]);
    leaf.package.optional = true;
    packages.insert(("parent".to_string(), "1.0.0".to_string()), parent);
    packages.insert(("child".to_string(), "1.0.0".to_string()), child);
    packages.insert(("leaf".to_string(), "1.0.0".to_string()), leaf);

    mark_required_closure(&mut packages, &("parent".to_string(), "1.0.0".to_string()));

    assert!(packages.values().all(|draft| !draft.package.optional));
}
