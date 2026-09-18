use crate::commands::install::requested_range_for_locked_lookup;
use lpm_common::PackageInstanceId;
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_resolver::specifier::Specifier;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::OnceLock;

#[cfg(test)]
mod legacy_peer_tests {
    use super::*;

    #[test]
    fn ordinary_alias_does_not_rewrite_a_legacy_peer_pin() {
        let packages = vec![
            LockedPackage {
                name: "plugin".into(),
                version: "1.0.0".into(),
                dependencies: vec!["slot@1.0.0".into()],
                alias_dependencies: vec![["slot".into(), "actual-dep".into()]],
                peers: vec!["slot@2.0.0".into()],
                ..Default::default()
            },
            LockedPackage {
                name: "actual-dep".into(),
                version: "1.0.0".into(),
                ..Default::default()
            },
            LockedPackage {
                name: "slot".into(),
                version: "2.0.0".into(),
                ..Default::default()
            },
        ];
        let indexes = PackageIndexes::new(&packages);
        assert_eq!(package_adjacency(&packages, &indexes)[0], [1, 2]);
    }

    #[test]
    fn candidate_visitation_stops_at_the_first_ambiguous_pin() {
        let parent = LockedPackage {
            name: "parent".into(),
            version: "1.0.0".into(),
            dependencies: vec!["target@1.0.0".into(); 128],
            ..Default::default()
        };
        let packages: Vec<_> = (0..128)
            .map(|index| LockedPackage {
                name: "target".into(),
                version: "1.0.0".into(),
                source: Some(format!("registry+https://source{index}.example.test")),
                ..Default::default()
            })
            .collect();
        let indexes = PackageIndexes::new(&packages);
        assert_eq!(
            unique_package_targets_for_kind(&parent, &indexes, false),
            Err("target")
        );
        let mut visited = 0;
        let result = visit_package_targets(&parent, &indexes, false, |_, _| {
            visited += 1;
            if visited == 2 {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        });
        assert_eq!(result, std::ops::ControlFlow::Break(()));
        assert_eq!(visited, 2);
    }
}

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
    legacy_peers: OnceLock<HashMap<(&'a str, &'a str), LegacyPeerCandidates>>,
}

#[derive(Default)]
struct LegacyPeerCandidates {
    registry: Vec<usize>,
    wrappers: HashMap<String, Vec<usize>>,
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
            legacy_peers: OnceLock::new(),
        }
    }

    fn legacy_peer_targets<'b>(&'b self, peer: &'b lpm_common::PeerEdge) -> &'b [usize] {
        let by_pin = self.legacy_peers.get_or_init(|| {
            let mut by_pin = HashMap::<_, LegacyPeerCandidates>::with_capacity(self.by_pin.len());
            for (index, package) in self.packages.iter().enumerate() {
                let wrapper = match package.source_kind() {
                    Some(Ok(lpm_lockfile::Source::Registry { .. })) | None => None,
                    Some(Ok(source)) => Some(source.source_id()),
                    Some(Err(_)) => continue,
                };
                let candidates = by_pin
                    .entry((package.name.as_str(), package.version.as_str()))
                    .or_default();
                if let Some(wrapper) = wrapper {
                    candidates.wrappers.entry(wrapper).or_default().push(index);
                } else {
                    candidates.registry.push(index);
                }
            }
            by_pin
        });
        let Some(candidates) =
            by_pin.get(&(peer.target_name.as_str(), peer.target_version.as_str()))
        else {
            return &[];
        };
        match &peer.target_wrapper_id {
            Some(wrapper) => candidates.wrappers.get(wrapper).map_or(&[], Vec::as_slice),
            None => &candidates.registry,
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
    for peers in [false, true] {
        let _ = visit_package_targets(package, indexes, peers, |local, index| {
            targets.push((local, index));
            std::ops::ControlFlow::<std::convert::Infallible>::Continue(())
        });
    }
    targets
}

pub(crate) fn unique_package_targets_for_kind<'a>(
    package: &'a LockedPackage,
    indexes: &PackageIndexes<'_>,
    peers: bool,
) -> Result<Vec<usize>, &'a str> {
    let mut selected = HashMap::new();
    let mut targets = Vec::new();
    let result = visit_package_targets(package, indexes, peers, |local, index| {
        match selected.insert(local, index) {
            Some(prior) if prior != index => return std::ops::ControlFlow::Break(local),
            Some(_) => {}
            None => targets.push(index),
        }
        std::ops::ControlFlow::Continue(())
    });
    match result {
        std::ops::ControlFlow::Break(local) => Err(local),
        std::ops::ControlFlow::Continue(()) => Ok(targets),
    }
}

fn visit_package_targets<'a, E>(
    package: &'a LockedPackage,
    indexes: &PackageIndexes<'_>,
    structured_peers: bool,
    mut visit: impl FnMut(&'a str, usize) -> std::ops::ControlFlow<E>,
) -> std::ops::ControlFlow<E> {
    let (pins, exact) = if structured_peers {
        (&package.peers, &package.peer_targets)
    } else {
        (&package.dependencies, &package.dependency_targets)
    };
    if !exact.is_empty() {
        for (local, id) in exact {
            if let Some(&index) = indexes.by_instance.get(id) {
                visit(local, index)?;
            }
        }
    } else if structured_peers && !package.peer_edges.is_empty() {
        for peer in &package.peer_edges {
            for &index in indexes.legacy_peer_targets(peer) {
                visit(&peer.local_name, index)?;
            }
        }
    } else {
        let aliases: HashMap<&str, &str> = if structured_peers {
            HashMap::new()
        } else {
            package
                .alias_dependencies
                .iter()
                .map(|[local, target]| (local.as_str(), target.as_str()))
                .collect()
        };
        for pin in pins {
            let Some((local, version)) = split_dependency_pin(pin) else {
                continue;
            };
            let name = aliases.get(local).copied().unwrap_or(local);
            if let Some(indices) = indexes.by_pin.get(&(name, version)) {
                for &index in indices {
                    visit(local, index)?;
                }
            }
        }
    }
    std::ops::ControlFlow::Continue(())
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
