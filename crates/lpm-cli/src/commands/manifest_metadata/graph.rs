use crate::commands::install::requested_range_for_locked_lookup;
use lpm_common::PackageInstanceId;
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_resolver::specifier::Specifier;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum PackageScope {
    Excluded,
    Optional,
    Required,
}

impl PackageScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Excluded => "excluded",
        }
    }

    fn child_scope(self, child: &LockedPackage) -> Self {
        match self {
            Self::Excluded => Self::Excluded,
            Self::Optional => Self::Optional,
            Self::Required if child.optional => Self::Optional,
            Self::Required => Self::Required,
        }
    }
}

pub(crate) fn package_scopes_by_lockfile_index(
    root_json: &Value,
    lockfile: &Lockfile,
) -> Vec<Option<PackageScope>> {
    let indexes = PackageIndexes::new(&lockfile.packages);
    let adjacency = package_adjacency(&lockfile.packages, &indexes);
    let mut scopes = vec![None; lockfile.packages.len()];
    let mut queue = VecDeque::new();
    for (_, package_index, scope) in selected_roots(root_json, lockfile, &indexes) {
        if set_package_scope(&mut scopes, package_index, scope) {
            queue.push_back((package_index, scope));
        }
    }

    while let Some((package_index, scope)) = queue.pop_front() {
        for &child_index in &adjacency[package_index] {
            let child_scope = scope.child_scope(&lockfile.packages[child_index]);
            if set_package_scope(&mut scopes, child_index, child_scope) {
                queue.push_back((child_index, child_scope));
            }
        }
    }

    scopes
}

fn set_package_scope(
    scopes: &mut [Option<PackageScope>],
    package_index: usize,
    scope: PackageScope,
) -> bool {
    let slot = &mut scopes[package_index];
    if slot.is_none_or(|existing| scope > existing) {
        *slot = Some(scope);
        return true;
    }
    false
}

pub(crate) struct PackageIndexes<'a> {
    packages: &'a [LockedPackage],
    pub(super) by_instance: HashMap<PackageInstanceId, usize>,
    by_name: HashMap<&'a str, Vec<usize>>,
    pub(super) by_pin: HashMap<(&'a str, &'a str), Vec<usize>>,
}

impl<'a> PackageIndexes<'a> {
    pub(crate) fn new(packages: &'a [LockedPackage]) -> Self {
        let mut by_instance = HashMap::with_capacity(packages.len());
        let mut by_name = HashMap::with_capacity(packages.len());
        let mut by_pin = HashMap::with_capacity(packages.len());
        for (index, package) in packages.iter().enumerate() {
            if let Some(instance_id) = package.instance_id {
                by_instance.insert(instance_id, index);
            }
            by_name
                .entry(package.name.as_str())
                .or_insert_with(Vec::new)
                .push(index);
            by_pin
                .entry((package.name.as_str(), package.version.as_str()))
                .or_insert_with(Vec::new)
                .push(index);
        }
        Self {
            packages,
            by_instance,
            by_name,
            by_pin,
        }
    }

    pub(super) fn select_legacy(&self, target: &str, requested_spec: &str) -> Option<usize> {
        let candidates = self.by_name.get(target)?;
        let requested_range = requested_range_for_locked_lookup(requested_spec)
            .and_then(|range| lpm_resolver::NpmRange::parse(&range).ok());
        let mut best_satisfying = None;
        let mut best_any = None;

        for &index in candidates {
            let version_text = &self.packages[index].version;
            let Ok(version) = lpm_resolver::NpmVersion::parse(version_text) else {
                continue;
            };
            if best_any
                .as_ref()
                .is_none_or(|(best, _): &(lpm_resolver::NpmVersion, usize)| version > *best)
            {
                best_any = Some((version.clone(), index));
            }
            if requested_range
                .as_ref()
                .is_some_and(|range| range.satisfies(&version))
                && best_satisfying
                    .as_ref()
                    .is_none_or(|(best, _): &(lpm_resolver::NpmVersion, usize)| version > *best)
            {
                best_satisfying = Some((version, index));
            }
        }

        best_satisfying
            .map(|(_, index)| index)
            .or_else(|| best_any.map(|(_, index)| index))
            .or_else(|| candidates.first().copied())
    }
}

pub(crate) fn package_adjacency(
    packages: &[LockedPackage],
    indexes: &PackageIndexes<'_>,
) -> Vec<Vec<usize>> {
    packages
        .iter()
        .map(|package| {
            package_targets(package, indexes)
                .into_iter()
                .map(|(_, index)| index)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .collect()
}

pub(super) fn package_targets<'a>(
    package: &'a LockedPackage,
    indexes: &PackageIndexes<'_>,
) -> Vec<(&'a str, usize)> {
    let mut targets = Vec::new();
    for (pins, exact, structured_peers) in [
        (&package.dependencies, &package.dependency_targets, false),
        (&package.peers, &package.peer_targets, true),
    ] {
        if !exact.is_empty() {
            targets.extend(exact.iter().filter_map(|(local, id)| {
                indexes
                    .by_instance
                    .get(id)
                    .map(|index| (local.as_str(), *index))
            }));
        } else if structured_peers && !package.peer_edges.is_empty() {
            for peer in &package.peer_edges {
                if let Some(indices) = indexes
                    .by_pin
                    .get(&(peer.target_name.as_str(), peer.target_version.as_str()))
                {
                    for &index in indices {
                        let wrapper = match indexes.packages[index].source_kind() {
                            Some(Ok(lpm_lockfile::Source::Registry { .. })) | None => None,
                            Some(Ok(source)) => Some(source.source_id()),
                            Some(Err(_)) => continue,
                        };
                        if wrapper.as_deref() == peer.target_wrapper_id.as_deref() {
                            targets.push((peer.local_name.as_str(), index));
                        }
                    }
                }
            }
        } else {
            for pin in pins {
                let Some((local, version)) = split_dependency_pin(pin) else {
                    continue;
                };
                let name = package
                    .alias_dependencies
                    .iter()
                    .find(|[alias, _]| alias == local)
                    .map_or(local, |[_, target]| target);
                if let Some(indices) = indexes.by_pin.get(&(name, version)) {
                    targets.extend(indices.iter().map(|index| (local, *index)));
                }
            }
        }
    }
    targets
}

fn root_dependency_seeds(root_json: &Value) -> BTreeMap<String, (String, PackageScope)> {
    let mut seeds = BTreeMap::new();
    collect_root_dependency_seeds(
        root_json,
        "dependencies",
        PackageScope::Required,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "peerDependencies",
        PackageScope::Required,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "optionalDependencies",
        PackageScope::Optional,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "devDependencies",
        PackageScope::Excluded,
        &mut seeds,
    );
    seeds
}

fn collect_root_dependency_seeds(
    root_json: &Value,
    section: &str,
    scope: PackageScope,
    seeds: &mut BTreeMap<String, (String, PackageScope)>,
) {
    let Some(deps) = root_json.get(section).and_then(Value::as_object) else {
        return;
    };
    for (name, spec) in deps {
        let spec = spec.as_str().unwrap_or_default().to_string();
        let entry = seeds.entry(name.clone()).or_insert((spec.clone(), scope));
        if scope > entry.1 {
            *entry = (spec, scope);
        }
    }
}

fn root_dependency_target_name(local_name: &str, spec: &str, lockfile: &Lockfile) -> String {
    if let Some(target) = lockfile.root_aliases.get(local_name) {
        return target.clone();
    }
    if spec.trim_start().starts_with("npm:")
        && let Ok(Specifier::NpmAlias { target, .. }) = Specifier::parse(spec)
    {
        return target;
    }
    local_name.to_string()
}

fn split_dependency_pin(input: &str) -> Option<(&str, &str)> {
    let at = input.rfind('@')?;
    if at == 0 || at + 1 >= input.len() {
        return None;
    }
    Some((&input[..at], &input[at + 1..]))
}

pub(crate) fn selected_roots(
    root_json: &Value,
    lockfile: &Lockfile,
    indexes: &PackageIndexes<'_>,
) -> Vec<(String, usize, PackageScope)> {
    let root_seeds = root_dependency_seeds(root_json);
    let exact_roots = lockfile
        .root_resolutions
        .values()
        .any(|resolution| resolution.instance_id.is_some());
    let mut selected = Vec::with_capacity(root_seeds.len());
    for (local_name, (spec, scope)) in root_seeds {
        let target_name = root_dependency_target_name(&local_name, &spec, lockfile);
        let package_index = if let Some(resolution) = lockfile.root_resolutions.get(&local_name) {
            resolution
                .instance_id
                .and_then(|id| indexes.by_instance.get(&id).copied())
                .or_else(|| {
                    if resolution.instance_id.is_some() {
                        return None;
                    }
                    indexes
                        .by_pin
                        .get(&(resolution.package.as_str(), resolution.version.as_str()))?
                        .iter()
                        .copied()
                        .find(|&index| lockfile.packages[index].source == resolution.source)
                })
        } else if exact_roots {
            None
        } else {
            indexes.select_legacy(&target_name, &spec)
        };
        let Some(package_index) = package_index else {
            continue;
        };
        selected.push((local_name, package_index, scope));
    }
    selected
}
