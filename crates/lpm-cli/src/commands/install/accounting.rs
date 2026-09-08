use super::*;
use lpm_registry::{ManagedInstallRoot, RegistryClient};

pub(super) fn build_managed_install_graph(
    packages: &[InstallPackage],
) -> lpm_registry::ManagedInstallGraph {
    use lpm_registry::{ManagedInstallGraph, ManagedInstallNode};
    let registry_lpm = |package: &InstallPackage| {
        lpm_common::package_name::is_lpm_package(&package.name)
            && matches!(
                package.source_kind(),
                Ok(lpm_lockfile::Source::Registry { .. })
            )
    };
    if !packages.iter().any(registry_lpm) {
        return ManagedInstallGraph::default();
    }
    let traversal = PackageTraversalIndex::new(packages);
    let mut edges = Vec::with_capacity(packages.len());
    let mut parents = vec![Vec::new(); packages.len()];
    for (index, package) in packages.iter().enumerate() {
        let mut children = Vec::with_capacity(package.dependencies.len() + package.peers.len());
        for (name, version) in &package.dependencies {
            if let Some(child) = traversal.dependency(package, name, version) {
                children.push(child);
            }
        }
        for peer in &package.peers {
            if let Some(child) = traversal.peer(package, peer) {
                children.push(child);
            }
        }
        children.sort_unstable();
        children.dedup();
        for &child in &children {
            parents[child].push(index);
        }
        edges.push(children);
    }
    let direct: Vec<_> = packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| package.is_direct.then_some(index))
        .collect();
    let mut reachable = vec![false; packages.len()];
    let mut pending = direct.clone();
    while let Some(index) = pending.pop() {
        if reachable[index] {
            continue;
        }
        reachable[index] = true;
        pending.extend(edges[index].iter().copied());
    }
    let mut relevant = vec![false; packages.len()];
    pending.extend(packages.iter().enumerate().filter_map(|(index, package)| {
        (reachable[index] && registry_lpm(package)).then_some(index)
    }));
    while let Some(index) = pending.pop() {
        if relevant[index] || !reachable[index] {
            continue;
        }
        relevant[index] = true;
        pending.extend(parents[index].iter().copied());
    }
    let mut ordered: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(index, _)| relevant[*index])
        .map(|(index, package)| (install_pkg_key(package), index))
        .collect();
    ordered.sort_unstable();
    let mut translated = vec![None; packages.len()];
    for (new_index, (_, original)) in ordered.iter().enumerate() {
        translated[*original] = Some(new_index);
    }
    let nodes = ordered
        .iter()
        .map(|(_, original)| {
            let package = &packages[*original];
            let mut dependencies: Vec<_> = edges[*original]
                .iter()
                .filter_map(|index| translated[*index])
                .collect();
            dependencies.sort_unstable();
            ManagedInstallNode {
                name: if matches!(
                    package.source_kind(),
                    Ok(lpm_lockfile::Source::Registry { .. })
                ) {
                    package.name.clone()
                } else {
                    format!("source:{}", translated[*original].unwrap_or_default())
                },
                version: package.version.clone(),
                dependencies,
            }
        })
        .collect();
    let mut roots: Vec<_> = direct
        .into_iter()
        .filter_map(|index| translated[index])
        .collect();
    roots.sort_unstable();
    roots.dedup();
    ManagedInstallGraph { nodes, roots }
}

pub(super) async fn report_pool_install_attribution(
    client: &RegistryClient,
    packages: &[InstallPackage],
    accounting: ManagedInstallAccounting,
) -> Result<(), LpmError> {
    let graph = build_managed_install_graph(packages);
    client
        .report_managed_pool_install(&graph, accounting)
        .await
        .map_err(|error| LpmError::PoolAttributionUnconfirmed {
            reason: error.to_string(),
        })
}

pub(super) async fn verify_lpm_install_access(
    client: &RegistryClient,
    packages: &[InstallPackage],
    json_output: bool,
) -> Result<Vec<String>, LpmError> {
    let exact: Vec<_> = packages
        .iter()
        .filter(|package| {
            lpm_common::package_name::is_lpm_package(&package.name)
                && matches!(
                    package.source_kind(),
                    Ok(lpm_lockfile::Source::Registry { .. })
                )
        })
        .map(|package| ManagedInstallRoot::new(&package.name, &package.version))
        .collect();
    let warnings = client.check_install_access(&exact).await?;
    if !json_output {
        for warning in &warnings {
            output::warn(warning);
        }
    }
    Ok(warnings)
}
