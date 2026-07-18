use super::super::*;
use super::{
    ExperimentalResolverStats, MetadataCaches, MetadataRequestContext, MetadataStats,
    PackageIdentity, ResolveRequest, metadata_for_package,
};
use futures::stream::FuturesUnordered;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::pin::Pin;

type SelectedVersion = (
    String,
    Option<lpm_resolver::PlatformMeta>,
    Option<lpm_resolver::OverrideHit>,
);

pub(super) type ResolveFuture =
    Pin<Box<dyn Future<Output = Result<NodeResolution, LpmError>> + Send>>;

#[derive(Debug, Clone)]
pub(super) struct ResolvedNode {
    pub(super) request: ResolveRequest,
    pub(super) version: String,
    pub(super) info: Arc<lpm_resolver::CachedPackageInfo>,
    pub(super) platform: Option<lpm_resolver::PlatformMeta>,
    pub(super) reused_existing: bool,
}

#[derive(Debug)]
pub(super) enum NodeResolution {
    Metadata {
        request: ResolveRequest,
        info: Arc<lpm_resolver::CachedPackageInfo>,
    },
    SkippedOptionalMetadata,
}

#[derive(Debug, Clone)]
pub(super) struct PackageDraft {
    pub(super) package: InstallPackage,
    pub(super) info: Arc<lpm_resolver::CachedPackageInfo>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MergeOutcome {
    pub(super) inserted: bool,
    pub(super) became_required: bool,
}

pub(super) fn load_lockfile_graph_packages(
    project_dir: &Path,
    deps: &HashMap<String, String>,
    current_importer_snapshot: &lpm_lockfile::ImporterSnapshot,
    catalog_resolutions: &[lpm_workspace::CatalogProtocolResolution],
    client: &RegistryClient,
    gate_stats: &GateStats,
    auto_install_peers: bool,
) -> Result<Vec<InstallPackage>, LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let fast = try_lockfile_fast_path(
        &lockfile_path,
        deps,
        Some(current_importer_snapshot),
        catalog_resolutions,
        client,
        gate_stats,
        false,
    )
    .ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental resolver lockfile graph mode requires a readable {} matching the current manifest",
            lockfile_path.display()
        ))
    })?;
    if lockfile_needs_peer_state_repair(&fast.lockfile, auto_install_peers) {
        return Err(LpmError::Registry(format!(
            "experimental resolver lockfile graph mode requires an upgraded v{} lockfile; found v{}",
            lpm_lockfile::LOCKFILE_VERSION,
            fast.lockfile.metadata.lockfile_version
        )));
    }
    if lockfile_needs_dependency_engine_repair(&fast.lockfile) {
        return Err(LpmError::Registry(format!(
            "experimental resolver lockfile graph mode requires an upgraded v{} lockfile; found v{}",
            lpm_lockfile::LOCKFILE_VERSION_WITH_DEPENDENCY_ENGINES,
            fast.lockfile.metadata.lockfile_version
        )));
    }
    Ok(fast.packages)
}

pub(super) fn root_resolve_requests(
    deps: &HashMap<String, String>,
    optional_names: &HashSet<String>,
) -> Vec<ResolveRequest> {
    let mut requests = Vec::with_capacity(deps.len());
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (local_name, range) in entries {
        let (target_name, range) = parse_alias_target(local_name, range);
        requests.push(ResolveRequest {
            local_name: local_name.clone(),
            root_ancestor: target_name.clone(),
            target_name,
            range,
            parent: None,
            depth: 0,
            optional: optional_names.contains(local_name),
            root: true,
            direct: true,
        });
    }
    requests
}

fn parse_alias_target(local_name: &str, range: &str) -> (String, String) {
    lpm_resolver::ranges::parse_npm_alias(range).map_or_else(
        || (local_name.to_string(), range.to_string()),
        |alias| (alias.target, alias.range),
    )
}

pub(super) async fn resolve_node(
    request: ResolveRequest,
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    metadata_caches: MetadataCaches,
    metadata_queue: Arc<Semaphore>,
    metadata_stats: Arc<MetadataStats>,
    resolver_policy: lpm_resolver::ResolverPolicy,
) -> Result<NodeResolution, LpmError> {
    let context = MetadataRequestContext::from_request(&request);
    let result = metadata_for_package(
        context,
        client,
        route_table,
        metadata_caches,
        metadata_queue,
        metadata_stats,
        resolver_policy,
    )
    .await;
    let info = match result {
        Ok(info) => info,
        Err(err) if request.optional => {
            tracing::debug!(
                "skipping optional metadata failure for {}@{}: {err}",
                request.target_name,
                request.range,
            );
            return Ok(NodeResolution::SkippedOptionalMetadata);
        }
        Err(err) => return Err(err),
    };
    Ok(NodeResolution::Metadata { request, info })
}

pub(super) fn select_or_reuse_node(
    request: ResolveRequest,
    info: Arc<lpm_resolver::CachedPackageInfo>,
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    override_set: &OverrideSet,
    resolver_policy: &lpm_resolver::ResolverPolicy,
) -> Result<Option<ResolvedNode>, LpmError> {
    if override_set.is_empty()
        && let Some(version) = reusable_existing_version(&request, packages)?
    {
        let platform = info.platform.get(&version).cloned();
        return Ok(Some(ResolvedNode {
            request,
            version,
            info,
            platform,
            reused_existing: true,
        }));
    }

    let split_target = !override_set.split_targets().is_empty()
        && override_set.split_targets().contains(&request.target_name);
    let Some((version, platform, override_hit)) =
        select_version_from_info(&request, &info, override_set, resolver_policy)?
    else {
        return Ok(None);
    };
    let override_applied = override_hit.is_some();
    if let Some(hit) = override_hit {
        override_set.record_hit(hit);
    }
    if !request.root {
        if override_applied || split_target {
            if package_version_exists(packages, &request.target_name, &version) {
                return Ok(Some(ResolvedNode {
                    request,
                    version,
                    info,
                    platform,
                    reused_existing: true,
                }));
            }
        } else if let Some(version) = reusable_existing_version(&request, packages)? {
            let platform = info.platform.get(&version).cloned();
            return Ok(Some(ResolvedNode {
                request,
                version,
                info,
                platform,
                reused_existing: true,
            }));
        }
    }
    Ok(Some(ResolvedNode {
        request,
        version,
        info,
        platform,
        reused_existing: false,
    }))
}

pub(super) fn reusable_existing_version(
    request: &ResolveRequest,
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> Result<Option<String>, LpmError> {
    if request.root {
        return Ok(None);
    }
    let range = lpm_resolver::NpmRange::parse(&request.range).map_err(|e| {
        LpmError::Registry(format!(
            "experimental resolver: invalid range {}@{}: {e}",
            request.target_name, request.range
        ))
    })?;
    let mut selected: Option<(lpm_resolver::NpmVersion, String)> = None;
    for (name, version) in packages.keys() {
        if name != &request.target_name {
            continue;
        }
        let Ok(parsed) = lpm_resolver::NpmVersion::parse(version) else {
            continue;
        };
        if !range.satisfies(&parsed) {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(current, _)| parsed > *current)
        {
            selected = Some((parsed, version.clone()));
        }
    }
    Ok(selected.map(|(_, version)| version))
}

fn package_version_exists(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    target_name: &str,
    version: &str,
) -> bool {
    packages.contains_key(&(target_name.to_string(), version.to_string()))
}

fn select_version_from_info(
    request: &ResolveRequest,
    info: &lpm_resolver::CachedPackageInfo,
    override_set: &OverrideSet,
    resolver_policy: &lpm_resolver::ResolverPolicy,
) -> Result<Option<SelectedVersion>, LpmError> {
    let range = lpm_resolver::NpmRange::parse(&request.range).map_err(|e| {
        LpmError::Registry(format!(
            "experimental resolver: invalid range {}@{}: {e}",
            request.target_name, request.range
        ))
    })?;
    let canonical = lpm_resolver::CanonicalKey::from_dep_name(&request.target_name);
    let parent_canonical = request.parent.as_ref().map(|(name, _)| name.as_str());
    let (selection, override_hit) =
        lpm_resolver::experimental_select_version_with_policy_and_overrides(
            &canonical,
            info,
            &range,
            resolver_policy,
            override_set,
            parent_canonical,
        );
    match selection {
        lpm_resolver::ExperimentalVersionSelection::Picked(version) => {
            let version = version.to_string();
            let platform = info.platform.get(&version).cloned();
            Ok(Some((version, platform, override_hit)))
        }
        lpm_resolver::ExperimentalVersionSelection::NoSatisfying => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental resolver: no version of {} satisfies {}",
                    request.target_name, request.range
                )))
            }
        }
        lpm_resolver::ExperimentalVersionSelection::BlockedByReleaseAge {
            version,
            remaining_secs,
            minimum_secs,
        } => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental resolver: {}@{} published too recently for minimumReleaseAge; {}s remaining (minimumReleaseAge={}s)",
                    request.target_name, version, remaining_secs, minimum_secs
                )))
            }
        }
        lpm_resolver::ExperimentalVersionSelection::BlockedByTrustPolicy { version, reason } => {
            if request.optional {
                Ok(None)
            } else {
                Err(LpmError::Registry(format!(
                    "experimental resolver: {}@{} blocked by trust-policy no-downgrade: {}",
                    request.target_name, version, reason
                )))
            }
        }
    }
}

pub(super) fn merge_node_into_packages(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    node: &ResolvedNode,
    route_table: &RouteTable,
    store: &PackageStore,
    project_dir: &Path,
) -> MergeOutcome {
    let identity = (node.request.target_name.clone(), node.version.clone());
    let mut outcome = MergeOutcome {
        inserted: false,
        became_required: false,
    };
    match packages.entry(identity) {
        Entry::Occupied(mut occupied) => {
            let package = &mut occupied.get_mut().package;
            let was_optional = package.optional;
            package.optional &= node.request.optional;
            outcome.became_required = was_optional && !package.optional;
            if node.request.direct {
                package.is_direct = true;
            }
            if node.request.root {
                append_root_link(package, &node.request.local_name);
            }
        }
        Entry::Vacant(vacant) => {
            outcome.inserted = true;
            let name = node.request.target_name.clone();
            let version = node.version.clone();
            let registry_url = registry_source_url_for(&name, route_table);
            let source = format!("registry+{registry_url}");
            let is_lpm = name.starts_with("@lpm.dev/");
            let dist = node.info.dist.get(&version);
            let mut package = InstallPackage {
                name,
                version: version.clone(),
                source,
                dependencies: Vec::new(),
                aliases: HashMap::new(),
                root_link_names: None,
                is_direct: node.request.direct,
                is_lpm,
                peers: Vec::new(),
                integrity: dist.and_then(|dist| dist.integrity.clone()),
                registry_signatures: dist.map(|dist| dist.signatures.clone()).unwrap_or_default(),
                registry_published_at: dist.and_then(|dist| dist.published_at.clone()),
                platform: node.platform.clone(),
                node_engine: node.info.node_engines.get(&version).cloned(),
                optional: node.request.optional,
                tarball_url: dist.and_then(|dist| dist.tarball_url.clone()),
                metadata_checked_for_tarball: true,
            };
            if node.request.root {
                append_root_link(&mut package, &node.request.local_name);
            }
            let _ = package.store_path_source_aware(store, project_dir, None);
            vacant.insert(PackageDraft {
                package,
                info: Arc::clone(&node.info),
            });
        }
    }
    outcome
}

fn append_root_link(package: &mut InstallPackage, local_name: &str) {
    let names = package.root_link_names.get_or_insert_with(Vec::new);
    if !names.iter().any(|name| name == local_name) {
        names.push(local_name.to_string());
        names.sort();
    }
}

pub(super) fn mark_required_closure(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    identity: &PackageIdentity,
) {
    let mut stack = vec![identity.clone()];
    let mut seen = HashSet::new();
    while let Some(identity) = stack.pop() {
        if !seen.insert(identity.clone()) {
            continue;
        }
        let Some(draft) = packages.get_mut(&identity) else {
            continue;
        };
        draft.package.optional = false;
        let dependencies = draft.package.dependencies.clone();
        let aliases = draft.package.aliases.clone();
        for (local_name, version) in dependencies {
            let target_name = aliases.get(&local_name).unwrap_or(&local_name).clone();
            stack.push((target_name, version));
        }
    }
}

pub(super) fn attach_dependency_edge(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    parent: &PackageIdentity,
    node: &ResolvedNode,
) -> Result<(), LpmError> {
    let parent = packages.get_mut(parent).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental resolver: parent package {}@{} was not recorded",
            parent.0, parent.1
        ))
    })?;
    upsert_dependency(
        &mut parent.package.dependencies,
        node.request.local_name.clone(),
        node.version.clone(),
    );
    if node.request.local_name != node.request.target_name {
        parent
            .package
            .aliases
            .entry(node.request.local_name.clone())
            .or_insert_with(|| node.request.target_name.clone());
    }
    Ok(())
}

fn upsert_dependency(
    dependencies: &mut Vec<(String, String)>,
    local_name: String,
    version: String,
) {
    if let Some((_, existing)) = dependencies
        .iter_mut()
        .find(|(existing_name, _)| existing_name == &local_name)
    {
        *existing = version;
    } else {
        dependencies.push((local_name, version));
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_dependencies(
    node: &ResolvedNode,
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    pending: &mut FuturesUnordered<ResolveFuture>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    include_optional_dependencies: bool,
    stats: &mut ExperimentalResolverStats,
) -> Result<(), LpmError> {
    let parent = Some((node.request.target_name.clone(), node.version.clone()));
    let aliases = node.info.aliases.get(&node.version);
    let optional_names = node.info.optional_dep_names.get(&node.version);
    let bundled_names = node.info.bundled_dep_names.get(&node.version);
    let Some(deps) = node.info.deps.get(&node.version) else {
        return Ok(());
    };
    let mut entries: Vec<(&String, &String)> = deps.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (local_name, range) in entries {
        if bundled_names.is_some_and(|names| names.contains(local_name)) {
            continue;
        }
        let target_name = aliases
            .and_then(|aliases| aliases.get(local_name))
            .cloned()
            .unwrap_or_else(|| local_name.clone());
        let optional =
            node.request.optional || optional_names.is_some_and(|names| names.contains(local_name));
        if optional && !include_optional_dependencies {
            continue;
        }
        let request = ResolveRequest {
            local_name: local_name.clone(),
            root_ancestor: node.request.root_ancestor.clone(),
            target_name,
            range: range.clone(),
            parent: parent.clone(),
            depth: node.request.depth.saturating_add(1),
            optional,
            root: false,
            direct: false,
        };
        if let Some(version) = reusable_existing_version(&request, packages)? {
            if inline_reuse_can_preserve_optional_state(packages, &request, &version)? {
                attach_reused_dependency_edge(packages, &request, &version)?;
                stats.inline_reused_edges += 1;
                stats.reused_existing_versions += 1;
                continue;
            }
            stats.inline_reuse_deferred_promotions += 1;
        }
        stats.dependency_requests_enqueued += 1;
        pending.push(Box::pin(resolve_node(
            request,
            Arc::clone(client),
            route_table.clone(),
            metadata_caches.clone(),
            Arc::clone(metadata_queue),
            Arc::clone(metadata_stats),
            resolver_policy.clone(),
        )));
    }
    Ok(())
}

pub(super) fn attach_reused_dependency_edge(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    request: &ResolveRequest,
    version: &str,
) -> Result<(), LpmError> {
    let identity = (request.target_name.clone(), version.to_string());
    let became_required = {
        let draft = packages.get_mut(&identity).ok_or_else(|| {
            LpmError::Registry(format!(
                "experimental resolver could not reuse missing package {}@{}",
                identity.0, identity.1
            ))
        })?;
        let was_optional = draft.package.optional;
        draft.package.optional &= request.optional;
        let became_required = was_optional && !draft.package.optional;
        if became_required {
            ensure_package_can_materialize(&draft.package)?;
        }
        became_required
    };

    if let Some(parent) = request.parent.as_ref() {
        attach_dependency_edge_from_request(packages, parent, request, version)?;
    }
    if became_required {
        mark_required_closure(packages, &identity);
    }
    Ok(())
}

pub(super) fn inline_reuse_can_preserve_optional_state(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    request: &ResolveRequest,
    version: &str,
) -> Result<bool, LpmError> {
    let identity = (request.target_name.clone(), version.to_string());
    let draft = packages.get(&identity).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental resolver could not inspect reusable package {}@{}",
            identity.0, identity.1
        ))
    })?;
    Ok(!draft.package.optional || request.optional)
}

fn attach_dependency_edge_from_request(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    parent: &PackageIdentity,
    request: &ResolveRequest,
    version: &str,
) -> Result<(), LpmError> {
    let parent = packages.get_mut(parent).ok_or_else(|| {
        LpmError::Registry(format!(
            "experimental resolver: parent package {}@{} was not recorded",
            parent.0, parent.1
        ))
    })?;
    upsert_dependency(
        &mut parent.package.dependencies,
        request.local_name.clone(),
        version.to_string(),
    );
    if request.local_name != request.target_name {
        parent
            .package
            .aliases
            .entry(request.local_name.clone())
            .or_insert_with(|| request.target_name.clone());
    }
    Ok(())
}

pub(super) fn package_should_materialize(package: &InstallPackage) -> Result<bool, LpmError> {
    if package_platform_compatible(package) {
        return Ok(true);
    }
    if package.optional {
        return Ok(false);
    }
    ensure_package_can_materialize(package)?;
    Ok(true)
}

pub(super) fn ensure_package_can_materialize(package: &InstallPackage) -> Result<(), LpmError> {
    if package_platform_compatible(package) {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "{}@{} is incompatible with this platform",
        package.name, package.version
    )))
}

pub(super) fn normalize_draft_optional_reachability(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
) {
    if packages.is_empty() {
        return;
    }

    let optional_dependency_names = optional_dependency_names_from_drafts(packages);
    let mut install_packages: Vec<InstallPackage> = packages
        .values()
        .map(|draft| draft.package.clone())
        .collect();
    normalize_install_package_optional_reachability(
        &mut install_packages,
        &optional_dependency_names,
    );
    for package in install_packages {
        let identity = (package.name.clone(), package.version.clone());
        if let Some(draft) = packages.get_mut(&identity) {
            draft.package.optional = package.optional;
        }
    }
}

fn optional_dependency_names_from_drafts(
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> HashMap<PackageIdentity, HashSet<String>> {
    packages
        .iter()
        .filter_map(|(identity, draft)| {
            draft
                .info
                .optional_dep_names
                .get(&draft.package.version)
                .cloned()
                .map(|names| (identity.clone(), names))
        })
        .collect()
}

pub(super) fn optional_dependency_names_from_resolver_cache(
    packages: &[InstallPackage],
    resolver_cache: &HashMap<lpm_resolver::CanonicalKey, Arc<lpm_resolver::CachedPackageInfo>>,
) -> HashMap<PackageIdentity, HashSet<String>> {
    packages
        .iter()
        .filter_map(|package| {
            let canonical = lpm_resolver::CanonicalKey::from_dep_name(&package.name);
            resolver_cache
                .get(&canonical)
                .and_then(|info| info.optional_dep_names.get(&package.version))
                .cloned()
                .map(|names| ((package.name.clone(), package.version.clone()), names))
        })
        .collect()
}

pub(super) fn normalize_install_package_optional_reachability(
    packages: &mut [InstallPackage],
    optional_dependency_names: &HashMap<PackageIdentity, HashSet<String>>,
) {
    if packages.is_empty() {
        return;
    }

    let mut by_identity: HashMap<PackageIdentity, Vec<usize>> =
        HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        by_identity
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(idx);
    }

    let mut required: HashSet<PackageIdentity> = HashSet::new();
    let mut queue = VecDeque::new();
    for package in packages.iter() {
        if package.root_link_names.is_some() || package.is_direct {
            let identity = (package.name.clone(), package.version.clone());
            required.insert(identity.clone());
            queue.push_back(identity);
        }
    }

    while let Some(identity) = queue.pop_front() {
        if let Some(indices) = by_identity.get(&identity) {
            for &idx in indices {
                let package = &packages[idx];
                let optional_names = optional_dependency_names.get(&identity);
                for (local_name, version) in &package.dependencies {
                    if optional_names.is_some_and(|names| names.contains(local_name)) {
                        continue;
                    }
                    let target_name = package
                        .aliases
                        .get(local_name)
                        .unwrap_or(local_name)
                        .clone();
                    let next = (target_name, version.clone());
                    if by_identity.contains_key(&next) && required.insert(next.clone()) {
                        queue.push_back(next);
                    }
                }
            }
        }
    }

    for package in packages {
        package.optional = !required.contains(&(package.name.clone(), package.version.clone()));
    }
}
