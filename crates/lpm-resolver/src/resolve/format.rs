use super::prelude::*;

/// Convert PubGrub solution + cached metadata into `ResolvedPackage` list
/// with dependency edges populated.
pub(super) fn format_solution(
    solution: pubgrub::SelectedDependencies<LpmDependencyProvider>,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
    skipped_dependencies: Vec<SkippedDependency>,
) -> Result<(Vec<ResolvedPackage>, usize), ResolveError> {
    for (package, version) in solution.iter().filter(|(package, _)| !package.is_root()) {
        let version = version.to_string();
        let key = CanonicalKey::from(package);
        let Some(peer_dependencies) = cache
            .get(&key)
            .and_then(|info| info.peer_deps.get(&version))
        else {
            continue;
        };
        for (peer_name, peer_dependency) in peer_dependencies {
            if let Err(error) = peer_dependency.parsed() {
                return Err(ResolveError::InvalidPeerSpecifier {
                    consumer: package.canonical_name(),
                    version: version.clone(),
                    peer: peer_name.clone(),
                    specifier: peer_dependency.raw().to_string(),
                    detail: error.to_string(),
                });
            }
        }
    }

    // Build a lookup: canonical_name → resolved_version for cross-referencing deps
    let resolved_versions: HashMap<String, String> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(pkg, ver)| (pkg.canonical_name(), ver.to_string()))
        .collect();
    let resolved_peer_versions: HashMap<String, Vec<(Option<String>, String)>> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .fold(HashMap::new(), |mut acc, (pkg, ver)| {
            acc.entry(pkg.canonical_name())
                .or_default()
                .push((pkg.context().map(str::to_string), ver.to_string()));
            acc
        });

    let mut resolved: Vec<ResolvedPackage> = solution
        .into_iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(package, version)| {
            let ver_str = version.to_string();
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
            // appears in the parent's `dependencies` map). To look up
            // the resolved version in `resolved_versions` (keyed by
            // the child's canonical registry name) we redirect through
            // the per-version alias map.
            let dependencies = cache
                .get(&key)
                .and_then(|info| info.deps.get(&ver_str))
                .map(|ver_deps| {
                    ver_deps
                        .keys()
                        .filter_map(|local_name| {
                            let target_name = cached_aliases
                                .get(local_name)
                                .map_or(local_name.as_str(), String::as_str);
                            resolved_versions
                                .get(target_name)
                                .map(|resolved_ver| (local_name.clone(), resolved_ver.clone()))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Only surface aliases that actually survived resolution —
            // an optional aliased dep skipped by the platform filter is
            // not in `dependencies`, so carrying its alias entry would
            // be dead weight for the linker.
            let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
            let mut aliases: HashMap<String, String> = cached_aliases
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
            let peers = compute_resolved_peers(
                &package,
                &ver_str,
                cache,
                &resolved_peer_versions,
                &root_dependencies.explicit_peer_providers,
            );
            if let Some(peer_deps) = cache
                .get(&key)
                .and_then(|info| info.peer_deps.get(&ver_str))
            {
                for (peer_name, _) in &peers {
                    let Some(peer_dependency) = peer_deps.get(peer_name) else {
                        continue;
                    };
                    let specifier = peer_dependency
                        .parsed()
                        .expect("selected peer specifiers were validated before formatting");
                    if specifier.target() != peer_name {
                        aliases.insert(peer_name.clone(), specifier.target().to_string());
                    }
                }
            }

            ResolvedPackage {
                package,
                version,
                dependencies,
                aliases,
                peers,
                tarball_url,
                integrity,
                platform,
                node_engine,
                optional: false,
            }
        })
        .collect();
    mark_optional_reachability(&mut resolved, cache, root_dependencies, root_aliases);
    let platform_skipped =
        validate_selected_dependency_skips(&resolved, cache, skipped_dependencies)?;
    dedupe_peer_superset_packages(&mut resolved);
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

pub(super) fn mark_optional_reachability(
    packages: &mut [ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    root_dependencies: &RootDependencies,
    root_aliases: &HashMap<String, String>,
) {
    if packages.is_empty() {
        return;
    }

    let mut by_name: HashMap<String, Vec<usize>> = HashMap::with_capacity(packages.len());
    let mut by_name_version: HashMap<(String, String), Vec<usize>> =
        HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        let name = package.package.canonical_name();
        let version = package.version.to_string();
        by_name.entry(name.clone()).or_default().push(idx);
        by_name_version
            .entry((name, version))
            .or_default()
            .push(idx);
    }

    let mut required = vec![false; packages.len()];
    let mut queue = VecDeque::new();
    for local_name in root_dependencies.dependencies.keys() {
        if root_dependencies.is_optional(local_name) {
            continue;
        }
        let target = root_aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        if let Some(indices) = by_name.get(target) {
            for &idx in indices {
                if !required[idx] {
                    required[idx] = true;
                    queue.push_back(idx);
                }
            }
        }
    }

    while let Some(idx) = queue.pop_front() {
        let package = &packages[idx];
        let key = CanonicalKey::from(&package.package);
        let version = package.version.to_string();
        let optional_names = cache
            .get(&key)
            .and_then(|info| info.optional_dep_names.get(&version));

        for (local_name, dep_version) in &package.dependencies {
            if optional_names.is_some_and(|names| names.contains(local_name)) {
                continue;
            }
            let target = package
                .aliases
                .get(local_name)
                .map_or(local_name.as_str(), String::as_str);
            if let Some(indices) = by_name_version.get(&(target.to_string(), dep_version.clone())) {
                for &next_idx in indices {
                    if !required[next_idx] {
                        required[next_idx] = true;
                        queue.push_back(next_idx);
                    }
                }
            }
        }
    }

    for (package, is_required) in packages.iter_mut().zip(required) {
        package.optional = !is_required;
    }
}

/// Collapse same-package/same-version rows when one materialization graph can
/// safely stand in for another.
///
/// The resolver can temporarily produce multiple rows for the same canonical
/// package and version when peer-bound contexts differ. A row whose dependency
/// edges, alias edges, and resolved peer bindings are all subsets of another
/// row is interchangeable with that larger wrapper: the larger wrapper exposes
/// everything the smaller one needs. Non-comparable peer contexts stay distinct.
pub(crate) fn dedupe_peer_superset_packages(packages: &mut Vec<ResolvedPackage>) {
    if packages.len() < 2 {
        return;
    }

    let mut groups: HashMap<String, Vec<usize>> = HashMap::with_capacity(packages.len());
    for (idx, package) in packages.iter().enumerate() {
        groups
            .entry(resolved_package_identity_key(package))
            .or_default()
            .push(idx);
    }

    let mut dominated = vec![false; packages.len()];
    for indices in groups.values().filter(|indices| indices.len() > 1) {
        for &idx in indices {
            for &candidate_idx in indices {
                if idx == candidate_idx {
                    continue;
                }
                let package = &packages[idx];
                let candidate = &packages[candidate_idx];
                if !resolved_package_can_replace(candidate, package) {
                    continue;
                }
                if resolved_package_is_strict_superset(candidate, package) || candidate_idx < idx {
                    dominated[idx] = true;
                    break;
                }
            }
        }
    }

    let mut idx = 0usize;
    packages.retain(|_| {
        let keep = !dominated[idx];
        idx += 1;
        keep
    });
}

pub(super) fn resolved_package_identity_key(package: &ResolvedPackage) -> String {
    let name = package.package.canonical_name();
    let version = package.version.to_string();
    let mut key = String::with_capacity(name.len() + 1 + version.len());
    key.push_str(&name);
    key.push('\0');
    key.push_str(&version);
    key
}

pub(super) fn resolved_package_can_replace(
    candidate: &ResolvedPackage,
    package: &ResolvedPackage,
) -> bool {
    candidate.tarball_url == package.tarball_url
        && candidate.integrity == package.integrity
        && candidate.node_engine == package.node_engine
        && entries_are_superset(&candidate.dependencies, &package.dependencies)
        && aliases_are_superset(&candidate.aliases, &package.aliases)
        && entries_are_superset(&candidate.peers, &package.peers)
}

pub(super) fn resolved_package_is_strict_superset(
    candidate: &ResolvedPackage,
    package: &ResolvedPackage,
) -> bool {
    candidate.dependencies.len() > package.dependencies.len()
        || candidate.aliases.len() > package.aliases.len()
        || candidate.peers.len() > package.peers.len()
}

pub(super) fn entries_are_superset(
    candidate: &[(String, String)],
    package: &[(String, String)],
) -> bool {
    package.iter().all(|entry| {
        candidate
            .iter()
            .any(|candidate_entry| candidate_entry == entry)
    })
}

pub(super) fn aliases_are_superset(
    candidate: &HashMap<String, String>,
    package: &HashMap<String, String>,
) -> bool {
    package
        .iter()
        .all(|(local, target)| candidate.get(local) == Some(target))
}

#[cfg(test)]
mod skipped_dependency_tests {
    use super::*;
    use crate::provider::SkippedDependencyReason;

    #[test]
    fn skipped_dependency_from_discarded_parent_version_does_not_affect_solution() {
        let parent = ResolverPackage::npm("parent");
        let packages = vec![ResolvedPackage {
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
