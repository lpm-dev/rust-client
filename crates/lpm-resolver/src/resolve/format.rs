use super::prelude::*;

pub(super) fn root_resolutions_from_solution(
    solution: &pubgrub::SelectedDependencies<LpmDependencyProvider>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
) -> HashMap<String, RootResolution> {
    let resolution_ids = resolution_ids_from_solution(solution);
    let mut resolutions = HashMap::with_capacity(root_dependencies.dependencies.len());
    for local_name in root_dependencies.dependencies.keys() {
        let target = root_aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        let root_package = ResolverPackage::from_dep_name(target);
        let Some((package, version)) = solution
            .iter()
            .find(|(package, _)| package == &&root_package)
        else {
            continue;
        };
        resolutions.insert(
            local_name.clone(),
            RootResolution {
                target: resolution_ids[package],
                package: package.canonical_name(),
                version: version.to_string(),
            },
        );
    }
    resolutions
}

fn resolution_ids_from_solution(
    solution: &pubgrub::SelectedDependencies<LpmDependencyProvider>,
) -> HashMap<ResolverPackage, lpm_common::ResolutionNodeId> {
    let mut packages = solution
        .keys()
        .filter(|package| !package.is_root())
        .cloned()
        .collect::<Vec<_>>();
    packages.sort_by_key(ResolverPackage::to_string);
    packages
        .into_iter()
        .enumerate()
        .map(|(index, package)| {
            let id = u32::try_from(index).unwrap_or(u32::MAX);
            (package, lpm_common::ResolutionNodeId::new(id))
        })
        .collect()
}

/// Convert PubGrub solution + cached metadata into `ResolvedPackage` list
/// with dependency edges populated.
pub(super) fn format_solution(
    solution: pubgrub::SelectedDependencies<LpmDependencyProvider>,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
    skipped_dependencies: Vec<SkippedDependency>,
) -> Result<(Vec<ResolvedPackage>, usize), ResolveError> {
    let resolution_ids = resolution_ids_from_solution(&solution);
    let resolved_versions: HashMap<ResolverPackage, String> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(pkg, ver)| (pkg.clone(), ver.to_string()))
        .collect();
    let resolved_peer_versions: HashMap<String, Vec<(ResolverPackage, String)>> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .fold(HashMap::new(), |mut acc, (pkg, ver)| {
            acc.entry(pkg.canonical_name())
                .or_default()
                .push((pkg.clone(), ver.to_string()));
            acc
        });

    let mut resolved: Vec<ResolvedPackage> = solution
        .into_iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(package, version)| {
            let ver_str = version.to_string();
            let parent_identity = package.to_string();
            // Cache is canonical-keyed. Split-retry identities of the
            // same canonical package share one entry, so every lookup
            // canonicalizes.
            let key = CanonicalKey::from(&package);

            // Pull the per-version alias map from the cache so we can
            // (a) redirect edge-lookup to the aliased target's resolved
            // version and (b) surface the alias map on the resolved
            // package for the linker.
            let cached_aliases: HashMap<String, String> = cache
                .get(&key)
                .and_then(|info| info.aliases.get(&ver_str))
                .cloned()
                .unwrap_or_default();

            // Look up this package's declared deps from the provider
            // cache. `ver_deps` is keyed by the LOCAL dep name (what
            // appears in the parent's `dependencies` map). Alias targets
            // and split children must use the same resolver identity that
            // the provider constructed for this parent.
            let resolved_dependencies = cache
                .get(&key)
                .and_then(|info| info.deps.get(&ver_str))
                .map(|ver_deps| {
                    ver_deps
                        .keys()
                        .filter_map(|local_name| {
                            let target_name = cached_aliases
                                .get(local_name)
                                .map_or(local_name.as_str(), String::as_str);
                            let target = ResolverPackage::from_dep_name(target_name);
                            let split_target = target.with_context(&parent_identity);
                            resolved_versions
                                .get(&split_target)
                                .or_else(|| resolved_versions.get(&target))
                                .map(|resolved_ver| {
                                    let exact_target =
                                        if resolved_versions.contains_key(&split_target) {
                                            split_target
                                        } else {
                                            target
                                        };
                                    (
                                        local_name.clone(),
                                        resolved_ver.clone(),
                                        resolution_ids[&exact_target],
                                    )
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let dependencies = resolved_dependencies
                .iter()
                .map(|(local, version, _)| (local.clone(), version.clone()))
                .collect::<Vec<_>>();
            let dependency_targets = resolved_dependencies
                .iter()
                .map(|(local, _, target)| (local.clone(), *target))
                .collect::<HashMap<_, _>>();
            let optional_dependencies = cache
                .get(&key)
                .and_then(|info| info.optional_dep_names.get(&ver_str))
                .cloned()
                .unwrap_or_default();

            // Only surface aliases that actually survived resolution —
            // an optional aliased dep skipped by the platform filter is
            // not in `dependencies`, so carrying its alias entry would
            // be dead weight for the linker.
            let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
            let aliases: HashMap<String, String> = cached_aliases
                .iter()
                .filter(|(local, _)| alive_locals.contains(local))
                .map(|(l, t)| (l.clone(), t.clone()))
                .collect();

            // Extract tarball URL and integrity from cached dist info
            let (tarball_url, integrity) = cache
                .get(&key)
                .and_then(|info| info.dist.get(&ver_str))
                .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                .unwrap_or_default();
            let platform = cache
                .get(&key)
                .and_then(|info| info.platform.get(&ver_str))
                .cloned();
            let node_engine = cache
                .get(&key)
                .and_then(|info| info.node_engines.get(&ver_str))
                .cloned();

            // Surface resolved peers per package. The resolver already
            // proved each peer's range was satisfied (or surfaced a
            // `PeerWarning` for the gap); here we just intersect the
            // declared peers against the install set's resolved-
            // versions lookup. Missing peers simply don't appear in
            // the output Vec — the linker / GraphKey only cares about
            // peers that ARE present.
            let peer_bindings =
                compute_resolved_peers(&package, &ver_str, cache, &resolved_peer_versions)?;
            let peer_targets = peer_bindings
                .iter()
                .filter_map(|(peer, provider)| {
                    resolution_ids
                        .get(provider)
                        .copied()
                        .map(|target| (peer.local_name.clone(), target))
                })
                .collect();
            let peers = peer_bindings.into_iter().map(|(peer, _)| peer).collect();

            Ok(ResolvedPackage {
                resolution_id: resolution_ids[&package],
                package,
                version,
                dependencies,
                dependency_targets,
                optional_dependencies,
                aliases,
                peers,
                peer_targets,
                tarball_url,
                integrity,
                platform,
                node_engine,
                optional: false,
            })
        })
        .collect::<Result<_, ResolveError>>()?;
    let root_resolutions =
        root_resolutions_from_solution_for_ids(&resolved, root_dependencies, root_aliases);
    mark_optional_reachability(&mut resolved, root_dependencies, &root_resolutions);
    let platform_skipped =
        validate_selected_dependency_skips(&resolved, cache, skipped_dependencies)?;
    resolved.sort_by_key(|a| a.package.to_string());
    Ok((resolved, platform_skipped))
}

fn validate_selected_dependency_skips(
    packages: &[ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    skipped_dependencies: Vec<SkippedDependency>,
) -> Result<usize, ResolveError> {
    if skipped_dependencies.is_empty() {
        return Ok(0);
    }

    let selected: HashMap<ResolverPackage, &ResolvedPackage> = packages
        .iter()
        .map(|package| (package.package.clone(), package))
        .collect();
    let mut platform_skipped = 0;

    for skipped in skipped_dependencies {
        let Some(parent) = selected.get(&skipped.parent) else {
            continue;
        };
        if parent.version.to_string() != skipped.parent_version {
            continue;
        }

        let recovered = selected.get(&skipped.child).is_some_and(|child| {
            let Ok(range) = NpmRange::parse(&skipped.requested) else {
                return false;
            };
            let latest = cache
                .get(&CanonicalKey::from(&skipped.child))
                .and_then(|info| info.latest_version.as_ref());
            range.satisfies_with_latest_bound(&child.version, latest)
        });
        if recovered {
            continue;
        }

        if parent.optional || skipped.edge_is_optional {
            if skipped.reason.warns_about_auth() {
                tracing::warn!(
                    "optional dep {} skipped: requires LPM authentication \
                     (run `lpm login` to install this package)",
                    skipped.local_name,
                );
            } else {
                tracing::debug!(
                    "optional dep {} skipped: {}",
                    skipped.local_name,
                    skipped.reason.detail(),
                );
            }
            platform_skipped += usize::from(skipped.reason.counts_as_platform_skip());
            continue;
        }

        return Err(ResolveError::DependencyFetch {
            package: parent.package.to_string(),
            version: parent.version.to_string(),
            detail: skipped.reason.detail().to_string(),
        });
    }

    Ok(platform_skipped)
}

fn root_resolutions_from_solution_for_ids(
    packages: &[ResolvedPackage],
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
) -> HashMap<String, RootResolution> {
    let mut roots = HashMap::with_capacity(root_dependencies.dependencies.len());
    for local in root_dependencies.dependencies.keys() {
        let target = root_aliases
            .get(local)
            .map_or(local.as_str(), String::as_str);
        if let Some(package) = packages.iter().find(|package| {
            package.package.canonical_name() == target && package.package.context().is_none()
        }) {
            roots.insert(
                local.clone(),
                RootResolution {
                    target: package.resolution_id,
                    package: target.to_string(),
                    version: package.version.to_string(),
                },
            );
        }
    }
    roots
}

pub(crate) fn mark_optional_reachability(
    packages: &mut [ResolvedPackage],
    root_dependencies: &RootDependencies,
    root_resolutions: &HashMap<String, RootResolution>,
) {
    if packages.is_empty() {
        return;
    }

    let mut by_id = HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        by_id.insert(package.resolution_id, idx);
    }

    let mut required = vec![false; packages.len()];
    let mut queue = VecDeque::new();
    for local_name in root_dependencies.dependencies.keys() {
        if root_dependencies.is_optional(local_name) {
            continue;
        }
        if let Some(root) = root_resolutions.get(local_name)
            && let Some(&idx) = by_id.get(&root.target)
            && !required[idx]
        {
            required[idx] = true;
            queue.push_back(idx);
        }
    }

    while let Some(idx) = queue.pop_front() {
        let package = &packages[idx];
        for (local_name, _) in &package.dependencies {
            if package.optional_dependencies.contains(local_name) {
                continue;
            }
            let Some(&target) = package.dependency_targets.get(local_name) else {
                continue;
            };
            if let Some(&next_idx) = by_id.get(&target)
                && !required[next_idx]
            {
                required[next_idx] = true;
                queue.push_back(next_idx);
            }
        }
    }

    for (package, is_required) in packages.iter_mut().zip(required) {
        package.optional = !is_required;
    }
}

/// Retain every exact resolver node until stable package-instance identities
/// have been assigned. Artifact-coordinate supersets are not interchangeable:
/// their incoming edges and peer environments can be different.
#[cfg(test)]
pub(crate) fn dedupe_peer_superset_packages(_packages: &mut Vec<ResolvedPackage>) {}

#[cfg(test)]
mod skipped_dependency_tests {
    use super::*;
    use crate::provider::SkippedDependencyReason;

    #[test]
    fn skipped_dependency_from_discarded_parent_version_does_not_affect_solution() {
        let parent = ResolverPackage::npm("parent");
        let packages = vec![ResolvedPackage {
            resolution_id: lpm_common::ResolutionNodeId::new(1),
            dependency_targets: HashMap::new(),
            optional_dependencies: HashSet::new(),
            peer_targets: HashMap::new(),
            package: parent.clone(),
            version: NpmVersion::parse("1.0.0").unwrap(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            peers: Vec::new(),
            tarball_url: None,
            integrity: None,
            platform: None,
            node_engine: None,
            optional: false,
        }];
        let skipped = SkippedDependency {
            parent,
            parent_version: "2.0.0".to_string(),
            child: ResolverPackage::npm("missing-child"),
            local_name: "missing-child".to_string(),
            requested: "1.0.0".to_string(),
            edge_is_optional: false,
            reason: SkippedDependencyReason::NoMatchingVersion {
                detail: "no matching version".to_string(),
            },
        };

        assert_eq!(
            validate_selected_dependency_skips(&packages, &HashMap::new(), vec![skipped]).unwrap(),
            0,
        );
    }
}

#[cfg(test)]
mod root_resolution_tests {
    use super::*;

    #[test]
    fn pubgrub_root_resolution_uses_unscoped_selection_when_split_version_also_exists() {
        let package = ResolverPackage::npm("peer-host");
        let mut solution: pubgrub::SelectedDependencies<LpmDependencyProvider> =
            pubgrub::Map::default();
        solution.insert(
            package.with_context("peer-consumer"),
            NpmVersion::parse("1.1.0").expect("valid split version"),
        );
        solution.insert(
            package,
            NpmVersion::parse("1.0.0").expect("valid root version"),
        );
        let root_dependencies = RootDependencies::required(HashMap::from([(
            "peer-host".to_string(),
            "^1.0.0".to_string(),
        )]));

        let resolutions =
            root_resolutions_from_solution(&solution, &root_dependencies, &HashMap::new());

        assert_eq!(
            resolutions.get("peer-host"),
            Some(&RootResolution {
                target: lpm_common::ResolutionNodeId::new(0),
                package: "peer-host".to_string(),
                version: "1.0.0".to_string(),
            })
        );
    }
}
