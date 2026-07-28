use super::super::*;
use super::fetch_schedule::{FetchHandle, maybe_spawn_fetch};
use super::graph::{
    NodeResolution, PackageDraft, ResolveFuture, attach_dependency_edge, enqueue_dependencies,
    mark_required_closure, merge_node_into_packages, package_should_materialize, resolve_node,
    select_or_reuse_node,
};
use super::{
    ExperimentalResolverStats, MetadataCaches, MetadataRequestContext, MetadataStats,
    PackageIdentity, ResolveRequest, metadata_for_package,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
struct PeerRequirement {
    target_name: String,
    range: lpm_resolver::NpmRange,
    optional: bool,
}

#[derive(Debug, Clone)]
struct AmbientPeerPlan {
    target_name: String,
    version: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_ambient_peer_installs(
    packages: &mut HashMap<PackageIdentity, PackageDraft>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    fetch_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    include_optional_dependencies: bool,
    auto_install_peers: bool,
    override_set: &OverrideSet,
    store: &PackageStore,
    project_dir: &Path,
    fetch_handles: &mut HashMap<String, FetchHandle>,
    stats: &mut ExperimentalResolverStats,
    store_v2_handle: Option<Arc<lpm_store::v2::Store>>,
    gate_stats: Arc<GateStats>,
    force: bool,
    fetch_extract_limiter: FetchExtractLimiter,
    install_accounting: ManagedInstallAccounting,
) -> Result<(), LpmError> {
    if !auto_install_peers {
        return Ok(());
    }

    let mut ambient_done = HashSet::new();
    loop {
        let plans = ambient_peer_plans(
            packages,
            client,
            route_table,
            metadata_caches,
            metadata_queue,
            metadata_stats,
            resolver_policy,
            &ambient_done,
        )
        .await?;
        if plans.is_empty() {
            return Ok(());
        }

        let mut pending: FuturesUnordered<ResolveFuture> = FuturesUnordered::new();
        for plan in plans {
            stats.peer_requests_enqueued += 1;
            ambient_done.insert(plan.target_name.clone());
            pending.push(Box::pin(resolve_node(
                ResolveRequest {
                    local_name: plan.target_name.clone(),
                    root_ancestor: plan.target_name.clone(),
                    target_name: plan.target_name,
                    range: plan.version,
                    parent: None,
                    depth: 0,
                    optional: false,
                    root: true,
                    direct: false,
                },
                Arc::clone(client),
                route_table.clone(),
                metadata_caches.clone(),
                Arc::clone(metadata_queue),
                Arc::clone(metadata_stats),
                resolver_policy.clone(),
            )));
        }

        while let Some(result) = pending.next().await {
            let NodeResolution::Metadata { request, info } = result? else {
                stats.skipped_optional += 1;
                continue;
            };
            let Some(node) = select_or_reuse_node(
                request,
                Arc::clone(&info),
                packages,
                override_set,
                resolver_policy,
            )?
            else {
                stats.skipped_optional += 1;
                continue;
            };
            stats.selected_nodes += 1;
            if node.reused_existing {
                stats.reused_existing_versions += 1;
            }
            let identity = (node.request.target_name.clone(), node.version.clone());
            let merge = merge_node_into_packages(
                packages,
                &node,
                route_table,
                client.as_ref(),
                store,
                project_dir,
            );
            if merge.became_required {
                let draft = packages.get(&identity).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "experimental resolver lost package {}@{} during peer required promotion",
                        identity.0, identity.1
                    ))
                })?;
                super::graph::ensure_package_can_materialize(&draft.package)?;
                mark_required_closure(packages, &identity);
            }
            if let Some(parent) = node.request.parent.as_ref() {
                attach_dependency_edge(packages, parent, &node)?;
            }
            if merge.inserted {
                stats.inserted_nodes += 1;
                let package = packages
                    .get(&identity)
                    .map(|draft| draft.package.clone())
                    .ok_or_else(|| {
                        LpmError::Registry(format!(
                            "experimental resolver lost package {}@{} during peer insertion",
                            identity.0, identity.1
                        ))
                    })?;
                if package_should_materialize(&package)? {
                    maybe_spawn_fetch(
                        package,
                        store,
                        store_v2_handle.clone(),
                        project_dir,
                        Arc::clone(client),
                        route_table.clone(),
                        Arc::clone(fetch_queue),
                        Arc::clone(&gate_stats),
                        force,
                        fetch_extract_limiter.clone(),
                        install_accounting,
                        ArtifactSelection::FreshResolution,
                        fetch_handles,
                        stats,
                    );
                } else {
                    stats.platform_pre_skipped += 1;
                }
                enqueue_dependencies(
                    &node,
                    packages,
                    &mut pending,
                    client,
                    route_table,
                    metadata_caches,
                    metadata_queue,
                    metadata_stats,
                    resolver_policy,
                    include_optional_dependencies,
                    stats,
                )?;
            } else {
                stats.duplicate_nodes += 1;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ambient_peer_plans(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    client: &Arc<RegistryClient>,
    route_table: &RouteTable,
    metadata_caches: &MetadataCaches,
    metadata_queue: &Arc<Semaphore>,
    metadata_stats: &Arc<MetadataStats>,
    resolver_policy: &lpm_resolver::ResolverPolicy,
    ambient_done: &HashSet<String>,
) -> Result<Vec<AmbientPeerPlan>, LpmError> {
    let mut grouped: BTreeMap<String, Vec<PeerRequirement>> = BTreeMap::new();
    for requirement in collect_peer_requirements(packages) {
        grouped
            .entry(requirement.target_name.clone())
            .or_default()
            .push(requirement);
    }

    let mut plans = Vec::new();
    for (target_name, reqs) in grouped {
        if ambient_done.contains(&target_name)
            || reqs.iter().all(|req| req.optional)
            || peer_group_satisfied_by_existing(packages, &target_name, &reqs)
        {
            continue;
        }
        let info = metadata_for_package(
            MetadataRequestContext::peer_plan(&target_name),
            Arc::clone(client),
            route_table.clone(),
            metadata_caches.clone(),
            Arc::clone(metadata_queue),
            Arc::clone(metadata_stats),
            resolver_policy.clone(),
        )
        .await?;
        let Some(version) = peer_version_satisfying_all(&info, &reqs)
            .or_else(|| peer_version_satisfying_most(&info, &reqs))
        else {
            return Err(LpmError::Registry(format!(
                "experimental resolver: no version of {target_name} satisfies required peer ranges"
            )));
        };
        plans.push(AmbientPeerPlan {
            target_name,
            version: version.to_string(),
        });
    }
    Ok(plans)
}

fn collect_peer_requirements(
    packages: &HashMap<PackageIdentity, PackageDraft>,
) -> Vec<PeerRequirement> {
    let mut requirements = Vec::new();
    for draft in packages.values() {
        let version = &draft.package.version;
        let Some(peer_deps) = draft.info.peer_deps.get(version) else {
            continue;
        };
        let aliases = draft.info.aliases.get(version);
        let optional_peers = draft.info.optional_peer_names.get(version);
        for (peer_name, peer_range) in peer_deps {
            let Ok(range) = lpm_resolver::NpmRange::parse(peer_range) else {
                continue;
            };
            let target_name = aliases
                .and_then(|aliases| aliases.get(peer_name))
                .cloned()
                .unwrap_or_else(|| peer_name.clone());
            requirements.push(PeerRequirement {
                target_name,
                range,
                optional: optional_peers.is_some_and(|peers| peers.contains(peer_name)),
            });
        }
    }
    requirements
}

fn peer_group_satisfied_by_existing(
    packages: &HashMap<PackageIdentity, PackageDraft>,
    target_name: &str,
    reqs: &[PeerRequirement],
) -> bool {
    packages.keys().any(|(name, version)| {
        if name != target_name {
            return false;
        }
        let Ok(version) = lpm_resolver::NpmVersion::parse(version) else {
            return false;
        };
        reqs.iter().all(|req| req.range.satisfies(&version))
    })
}

fn peer_version_satisfying_all(
    info: &lpm_resolver::CachedPackageInfo,
    reqs: &[PeerRequirement],
) -> Option<lpm_resolver::NpmVersion> {
    info.versions
        .iter()
        .find(|version| {
            reqs.iter().all(|req| req.range.satisfies(version))
                && platform_allows_peer_version(info, version)
        })
        .cloned()
}

fn peer_version_satisfying_most(
    info: &lpm_resolver::CachedPackageInfo,
    reqs: &[PeerRequirement],
) -> Option<lpm_resolver::NpmVersion> {
    let mut best: Option<(lpm_resolver::NpmVersion, usize)> = None;
    for version in &info.versions {
        if !platform_allows_peer_version(info, version) {
            continue;
        }
        let hits = reqs
            .iter()
            .filter(|req| !req.optional && req.range.satisfies(version))
            .count();
        if hits == 0 {
            continue;
        }
        if best.as_ref().is_none_or(|(_, best_hits)| hits > *best_hits) {
            best = Some((version.clone(), hits));
        }
    }
    best.map(|(version, _)| version)
}

fn platform_allows_peer_version(
    info: &lpm_resolver::CachedPackageInfo,
    version: &lpm_resolver::NpmVersion,
) -> bool {
    info.platform
        .get(&version.to_string())
        .is_none_or(lpm_resolver::is_platform_compatible)
}

pub(super) fn attach_peer_edges_to_drafts(packages: &mut HashMap<PackageIdentity, PackageDraft>) {
    let available: HashMap<String, Vec<(lpm_resolver::NpmVersion, String)>> = packages
        .values()
        .filter_map(|package| {
            let parsed = lpm_resolver::NpmVersion::parse(&package.package.version).ok()?;
            Some((
                package.package.name.clone(),
                (parsed, package.package.version.clone()),
            ))
        })
        .fold(HashMap::new(), |mut acc, (name, version)| {
            acc.entry(name).or_default().push(version);
            acc
        });

    for draft in packages.values_mut() {
        let Some(peer_deps) = draft.info.peer_deps.get(&draft.package.version) else {
            draft.package.peers.clear();
            continue;
        };
        let mut peers = Vec::with_capacity(peer_deps.len());
        for (peer_name, peer_range) in peer_deps {
            let Some(candidates) = available.get(peer_name) else {
                continue;
            };
            let Ok(range) = lpm_resolver::NpmRange::parse(peer_range) else {
                continue;
            };
            if let Some((_, version)) = candidates
                .iter()
                .filter(|(version, _)| range.satisfies(version))
                .max_by(|(left, _), (right, _)| left.cmp(right))
            {
                peers.push((peer_name.clone(), version.clone()));
            }
        }
        peers.sort();
        draft.package.peers = peers;
    }
}
