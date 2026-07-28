use super::*;
use lpm_registry::{ManagedInstallRoot, RegistryClient};

pub(super) fn select_lpm_install_roots(packages: &[InstallPackage]) -> Vec<ManagedInstallRoot> {
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
    for index in indices
        .iter()
        .copied()
        .filter(|index| packages[*index].is_direct)
    {
        pending.push_back((index, false));
    }

    let mut visited = HashSet::with_capacity(packages.len());
    let mut roots = BTreeSet::new();
    while let Some((index, covered_by_lpm)) = pending.pop_front() {
        if !visited.insert((index, covered_by_lpm)) {
            continue;
        }

        let package = &packages[index];
        let identity = (package.name.as_str(), package.version.as_str());
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

    roots
        .into_iter()
        .map(|(name, version)| ManagedInstallRoot::new(name, version))
        .collect()
}

pub(super) async fn report_pool_install_attribution(
    client: &RegistryClient,
    packages: &[InstallPackage],
    accounting: ManagedInstallAccounting,
) -> Result<(), LpmError> {
    let roots = select_lpm_install_roots(packages);
    client
        .report_managed_pool_install(&roots, accounting)
        .await
        .map_err(|error| LpmError::PoolAttributionUnconfirmed {
            reason: error.to_string(),
        })
}
