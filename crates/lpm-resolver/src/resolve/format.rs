use super::prelude::*;

#[cfg(test)]
pub(super) fn root_resolutions_from_solution(
    solution: &PubGrubSolution,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
) -> HashMap<String, RootResolution> {
    let resolution_ids = resolution_ids_from_solution(solution);
    root_resolutions_from_solution_with_ids(
        solution,
        &resolution_ids,
        root_dependencies,
        root_aliases,
    )
}

fn root_resolutions_from_solution_with_ids(
    solution: &PubGrubSolution,
    resolution_ids: &HashMap<ResolverPackage, lpm_common::ResolutionNodeId>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
) -> HashMap<String, RootResolution> {
    let mut resolutions = HashMap::with_capacity(root_dependencies.dependencies.len());
    for local_name in root_dependencies.dependencies.keys() {
        let target = root_aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        let root_package = ResolverPackage::from_root_dependency(local_name, target);
        let Some(version) = solution.get(&root_package) else {
            continue;
        };
        resolutions.insert(
            local_name.clone(),
            RootResolution {
                target: resolution_ids[&root_package],
                package: root_package.canonical_name(),
                version: version.to_string(),
            },
        );
    }
    resolutions
}

fn resolution_ids_from_solution(
    solution: &PubGrubSolution,
) -> HashMap<ResolverPackage, lpm_common::ResolutionNodeId> {
    let mut packages = solution
        .iter()
        .map(|(package, _)| package)
        .filter(|package| !package.is_root())
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.cmp_display(right));
    packages
        .into_iter()
        .enumerate()
        .map(|(index, package)| {
            let id = u32::try_from(index).unwrap_or(u32::MAX);
            (package.clone(), lpm_common::ResolutionNodeId::new(id))
        })
        .collect()
}

/// Why a PubGrub solution can't be installed.
#[derive(Debug)]
pub(super) struct RejectedSolution {
    pub(super) error: Box<ResolveError>,
    /// Selected packages with a version no resolution can use. Solving again
    /// without those versions may succeed.
    pub(super) unusable_packages: Vec<CanonicalKey>,
}

impl From<ResolveError> for RejectedSolution {
    fn from(error: ResolveError) -> Self {
        Self {
            error: Box::new(error),
            unusable_packages: Vec::new(),
        }
    }
}

pub(super) struct FormattedSolution {
    pub(super) packages: Vec<ResolvedPackage>,
    pub(super) root_resolutions: HashMap<String, RootResolution>,
    pub(super) platform_skipped: usize,
}

/// Convert PubGrub solution + cached metadata into `ResolvedPackage` list,
/// root resolution handles, and platform-skip count.
pub(super) fn format_solution(
    solution: PubGrubSolution,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
    skipped_dependencies: Vec<SkippedDependency>,
) -> Result<FormattedSolution, RejectedSolution> {
    let resolution_ids = resolution_ids_from_solution(&solution);
    let root_resolutions = root_resolutions_from_solution_with_ids(
        &solution,
        &resolution_ids,
        root_dependencies,
        root_aliases,
    );
    let mut resolved_versions = HashMap::with_capacity(resolution_ids.len());
    let mut resolved_peer_versions: HashMap<String, Vec<(ResolverPackage, String)>> =
        HashMap::with_capacity(resolution_ids.len());
    for (pkg, ver) in solution.iter() {
        if pkg.is_root() {
            continue;
        }
        let ver_str = ver.to_string();
        resolved_peer_versions
            .entry(pkg.canonical_name())
            .or_default()
            .push((pkg.clone(), ver_str.clone()));
        resolved_versions.insert(pkg.clone(), ver_str);
    }

    let mut resolved: Vec<ResolvedPackage> = solution
        .into_iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(package, version)| {
            let ver_str = resolved_versions
                .get(&package)
                .map_or_else(|| version.to_string(), String::clone);
            let key = CanonicalKey::from(&package);
            let version_view = cache.get(&key).and_then(|info| info.version_view(&ver_str));

            let mut dependencies = Vec::new();
            let mut dependency_targets = HashMap::new();
            let mut optional_dependencies = HashSet::new();
            let mut aliases = HashMap::new();

            if let Some(view) = version_view {
                for dependency in view.dependencies() {
                    if dependency.optional {
                        optional_dependencies.insert(dependency.name.to_owned());
                    }
                    if dependency.bundled {
                        continue;
                    }
                    let local_name = dependency.name;
                    let target_name = dependency.alias.unwrap_or(local_name);
                    let split_target = ResolverPackage::from_transitive_dependency(
                        &package,
                        &version,
                        local_name,
                        target_name,
                        true,
                    );
                    let resolved_edge =
                        if let Some(resolved_ver) = resolved_versions.get(&split_target) {
                            Some((resolved_ver, resolution_ids[&split_target]))
                        } else if local_name == target_name {
                            let target = ResolverPackage::from_dep_name(target_name);
                            resolved_versions
                                .get(&target)
                                .map(|resolved_ver| (resolved_ver, resolution_ids[&target]))
                        } else {
                            None
                        };
                    if let Some((resolved_ver, target_id)) = resolved_edge {
                        let local_owned = local_name.to_owned();
                        if let Some(alias) = dependency.alias {
                            aliases.insert(local_owned.clone(), alias.to_owned());
                        }
                        dependency_targets.insert(local_owned.clone(), target_id);
                        dependencies.push((local_owned, resolved_ver.clone()));
                    }
                }
            }

            let (tarball_url, integrity, platform, node_engine) = match version_view {
                Some(view) => (
                    view.tarball_url().map(str::to_owned),
                    view.integrity().map(str::to_owned),
                    view.platform(),
                    view.node_engine().map(str::to_owned),
                ),
                None => (None, None, None, None),
            };

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
    mark_optional_reachability(&mut resolved, root_dependencies, &root_resolutions);
    let platform_skipped =
        validate_selected_dependency_skips(&resolved, cache, skipped_dependencies)?;
    resolved.sort_by(|left, right| left.package.cmp_display(&right.package));
    Ok(FormattedSolution {
        packages: resolved,
        root_resolutions,
        platform_skipped,
    })
}

fn validate_selected_dependency_skips(
    packages: &[ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    skipped_dependencies: Vec<SkippedDependency>,
) -> Result<usize, RejectedSolution> {
    if skipped_dependencies.is_empty() {
        return Ok(0);
    }

    let selected: HashMap<ResolverPackage, &ResolvedPackage> = packages
        .iter()
        .map(|package| (package.package.clone(), package))
        .collect();
    let mut tolerated = Vec::new();
    let mut error = None;
    let mut unusable_packages = Vec::new();

    for skipped in skipped_dependencies {
        let Some(parent) = selected.get(&skipped.parent) else {
            continue;
        };
        if parent.version.to_string() != skipped.parent_version {
            continue;
        }

        let recovered = selected.get(&skipped.child).is_some_and(|child| {
            let Ok(range) = NpmRange::parse_registry_spec(&skipped.requested) else {
                return false;
            };
            cache
                .get(&CanonicalKey::from(&skipped.child))
                .is_some_and(|info| info.range_satisfies(&range, &child.version))
        });
        if recovered {
            continue;
        }

        if parent.optional || skipped.edge_is_optional {
            tolerated.push(skipped);
            continue;
        }

        if skipped.reason.makes_parent_version_unusable() {
            let package = CanonicalKey::from(&parent.package);
            if !unusable_packages.contains(&package) {
                unusable_packages.push(package);
            }
        }
        error.get_or_insert_with(|| ResolveError::DependencyFetch {
            package: parent.package.to_string(),
            version: parent.version.to_string(),
            detail: skipped.reason.detail().to_string(),
        });
    }

    if let Some(error) = error {
        return Err(RejectedSolution {
            error: Box::new(error),
            unusable_packages,
        });
    }

    let mut platform_skipped = 0;
    for skipped in tolerated {
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
    }
    Ok(platform_skipped)
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
        let solution: PubGrubSolution = [
            (
                package.with_context("peer-consumer"),
                NpmVersion::parse("1.1.0").expect("valid split version"),
            ),
            (
                package,
                NpmVersion::parse("1.0.0").expect("valid root version"),
            ),
        ]
        .into_iter()
        .collect();
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

    #[test]
    fn pubgrub_format_solution_omits_bundled_dependency_edges_even_when_resolved_elsewhere() {
        let parent_meta: lpm_registry::PackageMetadata =
            serde_json::from_value(serde_json::json!({
                "name": "parent-pkg",
                "versions": {
                    "1.0.0": {
                        "name": "parent-pkg",
                        "version": "1.0.0",
                        "dependencies": {
                            "shared-dep": "^1.0.0",
                            "external-dep": "^1.0.0"
                        },
                        "bundleDependencies": ["shared-dep"]
                    }
                }
            }))
            .expect("parse parent metadata");
        let shared_meta: lpm_registry::PackageMetadata =
            serde_json::from_value(serde_json::json!({
                "name": "shared-dep",
                "versions": {
                    "1.0.0": { "name": "shared-dep", "version": "1.0.0" }
                }
            }))
            .expect("parse shared metadata");
        let external_meta: lpm_registry::PackageMetadata =
            serde_json::from_value(serde_json::json!({
                "name": "external-dep",
                "versions": {
                    "1.0.0": { "name": "external-dep", "version": "1.0.0" }
                }
            }))
            .expect("parse external metadata");

        let cache = HashMap::from([
            (
                CanonicalKey::npm("parent-pkg"),
                std::sync::Arc::new(crate::provider::parse_metadata_to_cache_info(&parent_meta)),
            ),
            (
                CanonicalKey::npm("shared-dep"),
                std::sync::Arc::new(crate::provider::parse_metadata_to_cache_info(&shared_meta)),
            ),
            (
                CanonicalKey::npm("external-dep"),
                std::sync::Arc::new(crate::provider::parse_metadata_to_cache_info(
                    &external_meta,
                )),
            ),
        ]);
        let solution: PubGrubSolution = [
            (
                ResolverPackage::npm("parent-pkg"),
                NpmVersion::parse("1.0.0").unwrap(),
            ),
            (
                ResolverPackage::npm("shared-dep"),
                NpmVersion::parse("1.0.0").unwrap(),
            ),
            (
                ResolverPackage::npm("external-dep"),
                NpmVersion::parse("1.0.0").unwrap(),
            ),
        ]
        .into_iter()
        .collect();
        let root_deps = RootDependencies::required(HashMap::from([
            ("parent-pkg".to_string(), "^1.0.0".to_string()),
            ("shared-dep".to_string(), "^1.0.0".to_string()),
        ]));

        let FormattedSolution { packages, .. } =
            format_solution(solution, &cache, &root_deps, &HashMap::new(), Vec::new())
                .expect("format solution");
        let parent = packages
            .iter()
            .find(|pkg| pkg.package.canonical_name() == "parent-pkg")
            .expect("parent-pkg present");
        assert!(
            !parent
                .dependencies
                .iter()
                .any(|(name, _)| name == "shared-dep"),
            "bundled dependency must not be linked to an external shared copy: {:?}",
            parent.dependencies
        );
        assert_eq!(
            parent.dependencies,
            vec![("external-dep".to_string(), "1.0.0".to_string())]
        );
    }
}
