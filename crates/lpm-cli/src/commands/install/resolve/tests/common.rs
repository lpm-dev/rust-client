use super::super::super::*;
use super::super::graph::{PackageDraft, select_or_reuse_node};
use super::super::{PackageIdentity, ResolveRequest};

pub(super) fn fake_package(name: &str, version: &str, deps: &[(&str, &str)]) -> InstallPackage {
    InstallPackage {
        instance_id: None,
        dependency_targets: HashMap::new(),
        peer_targets: HashMap::new(),
        name: name.to_string(),
        version: version.to_string(),
        source: "registry+https://registry.npmjs.org".to_string(),
        dependencies: deps
            .iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect(),
        aliases: HashMap::new(),
        root_link_names: None,
        is_direct: false,
        is_lpm: false,
        peers: Vec::new(),
        integrity: Some(format!("sha512-{name}-{version}")),
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine: None,
        optional: false,
        tarball_url: Some(format!(
            "https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
        )),
        metadata_checked_for_tarball: true,
        manifest_fingerprint: None,
    }
}

pub(super) fn empty_info_value() -> lpm_resolver::CachedPackageInfo {
    lpm_resolver::CachedPackageInfo {
        modified: None,
        modified_unix: None,
        trust_metadata_complete: false,
        versions_complete: true,
        covered_ranges: HashSet::new(),
        workspace_versions: HashSet::new(),
        platform_metadata_complete: true,
        latest_version: None,
        versions: Vec::new(),
        deps: HashMap::new(),
        peer_deps: HashMap::new(),
        peer_aliases: HashMap::new(),
        optional_dep_names: HashMap::new(),
        optional_peer_names: HashMap::new(),
        node_engines: HashMap::new(),
        bundled_dep_names: HashMap::new(),
        platform: HashMap::new(),
        dist: HashMap::new(),
        aliases: HashMap::new(),
    }
}

pub(super) fn empty_info() -> Arc<lpm_resolver::CachedPackageInfo> {
    Arc::new(empty_info_value())
}

pub(super) fn fake_draft(name: &str, version: &str, deps: &[(&str, &str)]) -> PackageDraft {
    PackageDraft {
        package: fake_package(name, version, deps),
        info: empty_info(),
    }
}

pub(super) fn resolve_request_for_test(
    name: &str,
    range: &str,
    parent: Option<PackageIdentity>,
    root: bool,
    direct: bool,
) -> ResolveRequest {
    let depth = if root { 0 } else { 1 };
    let root_ancestor = parent
        .as_ref()
        .map_or_else(|| name.to_string(), |(name, _)| name.clone());
    ResolveRequest {
        local_name: name.to_string(),
        target_name: name.to_string(),
        range: range.to_string(),
        parent,
        root_ancestor,
        depth,
        optional: false,
        root,
        direct,
    }
}

pub(super) fn info_with_versions(versions: &[&str]) -> lpm_resolver::CachedPackageInfo {
    let mut info = empty_info_value();
    info.versions = versions
        .iter()
        .map(|version| lpm_resolver::NpmVersion::parse(version).expect("test version should parse"))
        .collect();
    info
}

pub(super) fn override_set(key: &str, target: &str) -> OverrideSet {
    let lpm = HashMap::from([(key.to_string(), target.to_string())]);
    OverrideSet::parse(&lpm, &HashMap::new(), &HashMap::new()).expect("test override should parse")
}

pub(super) fn package_set_for_completion_order(
    requests: Vec<ResolveRequest>,
    info: Arc<lpm_resolver::CachedPackageInfo>,
) -> Vec<InstallPackage> {
    let mut packages = HashMap::new();
    for request in requests {
        let node = select_or_reuse_node(
            request,
            Arc::clone(&info),
            &mut packages,
            &OverrideSet::empty(),
            &lpm_resolver::ResolverPolicy::default(),
        )
        .unwrap()
        .unwrap();
        if node.reused_existing {
            continue;
        }
        packages.insert(
            (node.request.target_name.clone(), node.version.clone()),
            fake_draft(&node.request.target_name, &node.version, &[]),
        );
    }
    let mut packages: Vec<_> = packages.into_values().map(|draft| draft.package).collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    packages
}
