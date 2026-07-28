use super::*;
use lpm_registry::{PoolInstallRoot, RegistryClient};

pub(super) fn select_pool_install_roots(packages: &[InstallPackage]) -> Vec<PoolInstallRoot> {
    let mut indices: Vec<usize> = (0..packages.len()).collect();
    indices.sort_unstable_by(|left, right| {
        install_pkg_key(&packages[*left]).cmp(&install_pkg_key(&packages[*right]))
    });

    let mut package_by_identity: HashMap<(&str, &str), usize> =
        HashMap::with_capacity(packages.len());
    for index in indices.iter().copied() {
        let package = &packages[index];
        package_by_identity
            .entry((&package.name, &package.version))
            .or_insert(index);
    }

    let mut pending = VecDeque::new();
    let mut direct_pool_roots = BTreeSet::new();
    for index in indices
        .iter()
        .copied()
        .filter(|index| packages[*index].is_direct)
    {
        let package = &packages[index];
        if package.is_lpm {
            direct_pool_roots.insert((package.name.as_str(), package.version.as_str()));
        }
        pending.push_back((index, false));
    }

    let mut visited = HashSet::with_capacity(packages.len());
    let mut roots = BTreeSet::new();
    let mut covered_pool_packages = BTreeSet::new();
    while let Some((index, covered_by_lpm)) = pending.pop_front() {
        if !visited.insert((index, covered_by_lpm)) {
            continue;
        }

        let package = &packages[index];
        let identity = (package.name.as_str(), package.version.as_str());
        if package.is_lpm && covered_by_lpm {
            covered_pool_packages.insert(identity);
        }
        if package.is_lpm && (!covered_by_lpm || package.is_direct) {
            roots.insert(identity);
        }
        let descendants_covered = covered_by_lpm || package.is_lpm;

        for (local_name, version) in &package.dependencies {
            if looks_like_source_dependency_key(version) {
                continue;
            }
            let canonical_name = package
                .aliases
                .get(local_name)
                .map_or(local_name.as_str(), String::as_str);
            if let Some(child_index) = package_by_identity
                .get(&(canonical_name, version.as_str()))
                .copied()
            {
                pending.push_back((child_index, descendants_covered));
            }
        }
    }

    roots.retain(|identity| {
        direct_pool_roots.contains(identity) || !covered_pool_packages.contains(identity)
    });
    roots
        .into_iter()
        .map(|(name, version)| PoolInstallRoot::new(name, version))
        .collect()
}

pub(super) async fn report_pool_install_attribution(
    client: &RegistryClient,
    packages: &[InstallPackage],
    accounting: ManagedInstallAccounting,
) -> Result<(), LpmError> {
    let roots = select_pool_install_roots(packages);
    client
        .report_managed_pool_install(&roots, accounting)
        .await
        .map_err(|error| LpmError::PoolAttributionUnconfirmed {
            reason: error.to_string(),
        })
}
