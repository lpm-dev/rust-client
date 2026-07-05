use lpm_common::LpmError;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::DEPLOY_WORKSPACE_DIR;
use super::manifest_rewrite::read_manifest_value;

pub(in crate::commands::deploy) fn write_pruned_deploy_lockfile_if_possible(
    source_cwd: &Path,
    output_dir: &Path,
) -> Result<Option<usize>, LpmError> {
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;
    let source_lockfile_path = workspace.root.join(lpm_lockfile::LOCKFILE_NAME);
    if !source_lockfile_path.exists() {
        return Ok(None);
    }

    let root_specs = match collect_registry_specs_from_deploy_manifests(output_dir)? {
        Some(specs) => specs,
        None => return Ok(None),
    };
    let source_lockfile =
        lpm_lockfile::Lockfile::read_from_file(&source_lockfile_path).map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read source lockfile {source_lockfile_path:?}: {e}"
            ))
        })?;

    let mut queue = VecDeque::new();
    for (name, spec) in &root_specs {
        let Some(package) = select_locked_package_for_spec(&source_lockfile, name, spec) else {
            return Ok(None);
        };
        queue.push_back(package.clone());
    }

    let mut selected = HashSet::new();
    while let Some(package) = queue.pop_front() {
        let key = locked_package_key(&package);
        if !selected.insert(key) {
            continue;
        }
        let alias_targets: HashMap<&str, &str> = package
            .alias_dependencies
            .iter()
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();
        for edge in package.dependencies.iter().chain(package.peers.iter()) {
            let Some((local_name, version)) = split_locked_edge(edge) else {
                continue;
            };
            let target = alias_targets.get(local_name).copied().unwrap_or(local_name);
            if let Some(child) = find_locked_package_exact(&source_lockfile, target, version) {
                queue.push_back(child.clone());
            }
        }
    }

    let mut pruned = lpm_lockfile::Lockfile::new();
    pruned.metadata = source_lockfile.metadata.clone();
    pruned.catalogs = source_lockfile.catalogs.clone();
    pruned.packages = source_lockfile
        .packages
        .into_iter()
        .filter(|package| selected.contains(&locked_package_key(package)))
        .collect();
    pruned.root_aliases = source_lockfile
        .root_aliases
        .into_iter()
        .filter(|(local, _)| root_specs.contains_key(local))
        .collect();
    pruned.ambient_peer_installs = source_lockfile
        .ambient_peer_installs
        .into_iter()
        .filter(|name| pruned.packages.iter().any(|package| &package.name == name))
        .collect();
    let package_count = pruned.packages.len();
    pruned
        .write_all(&output_dir.join(lpm_lockfile::LOCKFILE_NAME))
        .map_err(|e| LpmError::Script(format!("deploy: failed to write pruned lockfile: {e}")))?;

    Ok(Some(package_count))
}

fn collect_registry_specs_from_deploy_manifests(
    output_dir: &Path,
) -> Result<Option<HashMap<String, String>>, LpmError> {
    let mut specs = HashMap::new();
    let mut manifests = vec![output_dir.join("package.json")];
    let deploy_workspace = output_dir.join(DEPLOY_WORKSPACE_DIR);
    if deploy_workspace.exists() {
        collect_package_manifests_recursive(&deploy_workspace, &mut manifests)?;
    }

    for manifest in manifests {
        let doc = read_manifest_value(&manifest)?;
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(deps) = doc.get(section).and_then(|value| value.as_object()) else {
                continue;
            };
            for (name, value) in deps {
                let Some(spec) = value.as_str() else {
                    return Ok(None);
                };
                if spec.starts_with("workspace:")
                    || spec.starts_with("file:")
                    || spec.starts_with("link:")
                    || spec.starts_with("portal:")
                {
                    continue;
                }
                if spec.starts_with("catalog:") {
                    return Ok(None);
                }
                specs
                    .entry(name.clone())
                    .or_insert_with(|| spec.to_string());
            }
        }
    }

    Ok(Some(specs))
}

fn collect_package_manifests_recursive(
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| LpmError::Script(format!("deploy: failed to read {dir:?}: {e}")))?
    {
        let entry = entry
            .map_err(|e| LpmError::Script(format!("deploy: failed to read dir entry: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("deploy: failed to stat {path:?}: {e}")))?;
        if file_type.is_dir() {
            let manifest = path.join("package.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
            collect_package_manifests_recursive(&path, manifests)?;
        }
    }
    Ok(())
}

fn select_locked_package_for_spec<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    local_name: &str,
    spec: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    let (target, range_spec) = match lpm_resolver::ranges::parse_npm_alias(spec) {
        Some(alias) => (alias.target, alias.range),
        None => (local_name.to_string(), spec.to_string()),
    };
    let range = lpm_resolver::NpmRange::parse(&range_spec).ok()?;
    lockfile
        .packages
        .iter()
        .filter_map(|package| {
            if package.name != target {
                return None;
            }
            let version = lpm_resolver::NpmVersion::parse(&package.version).ok()?;
            range.satisfies(&version).then_some((version, package))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, package)| package)
}

fn find_locked_package_exact<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    name: &str,
    version: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    lockfile
        .packages
        .iter()
        .find(|package| package.name == name && package.version == version)
}

fn split_locked_edge(edge: &str) -> Option<(&str, &str)> {
    edge.rfind('@')
        .map(|at| (&edge[..at], &edge[at + 1..]))
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
}

fn locked_package_key(package: &lpm_lockfile::LockedPackage) -> (String, String, Option<String>) {
    (
        package.name.clone(),
        package.version.clone(),
        package.source.clone(),
    )
}
