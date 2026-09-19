pub(crate) mod graph;

use lpm_common::{BoundedReadError, LpmError, LpmRoot, with_shared_lock};
use lpm_lockfile::{LockedPackage, Lockfile};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub(crate) struct ManifestMetadata {
    pub(crate) description: Option<String>,
    pub(crate) licenses: Vec<String>,
    pub(crate) homepage: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) author: Option<String>,
}

impl ManifestMetadata {
    pub(crate) fn merge_missing(&mut self, other: ManifestMetadata) {
        if self.description.is_none() {
            self.description = other.description;
        }
        if self.homepage.is_none() {
            self.homepage = other.homepage;
        }
        if self.repository.is_none() {
            self.repository = other.repository;
        }
        if self.author.is_none() {
            self.author = other.author;
        }
        if self.licenses.is_empty() {
            self.licenses = other.licenses;
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstalledManifestInventory {
    metadata_by_package: BTreeMap<String, ManifestMetadata>,
    platform_skipped_packages: BTreeSet<String>,
}

impl InstalledManifestInventory {
    pub(crate) fn get(&self, package: &LockedPackage) -> Option<&ManifestMetadata> {
        self.metadata_by_package.get(&package_metadata_key(package))
    }

    pub(crate) fn is_platform_skipped(&self, package: &LockedPackage) -> bool {
        self.platform_skipped_packages
            .contains(&package_metadata_key(package))
    }
}

pub(crate) fn read_json_file(path: &Path) -> Result<Value, LpmError> {
    let (content, _) = lpm_common::read_text_regular_file_capped_with_metadata(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    let object: serde_json::Map<String, Value> =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).map_err(|e| {
            LpmError::Registry(format!("failed to parse JSON from {}: {e}", path.display()))
        })?;
    Ok(Value::Object(object))
}

pub(crate) fn extract_manifest_metadata(value: &Value) -> ManifestMetadata {
    let description = value
        .get("description")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let homepage = value
        .get("homepage")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let repository = value.get("repository").and_then(extract_urlish);
    let author = value.get("author").and_then(extract_author);
    let mut licenses = Vec::new();
    if let Some(license) = value.get("license") {
        collect_licenses(license, &mut licenses);
    }
    if let Some(license) = value.get("licenses") {
        collect_licenses(license, &mut licenses);
    }
    licenses.sort();
    licenses.dedup();
    ManifestMetadata {
        description,
        licenses,
        homepage,
        repository,
        author,
    }
}

pub(crate) fn read_installed_manifest_metadata(
    project_dir: &Path,
    lockfile: &Lockfile,
    root_json: &Value,
) -> Result<InstalledManifestInventory, LpmError> {
    let root = LpmRoot::from_env()?;
    let lock_path = root.store_lock();
    let root_for_lock = root;
    with_shared_lock(lock_path, || {
        let baseline_index = lpm_store::V2BaselineIndex::for_project(project_dir, &root_for_lock);
        let store_version = lpm_store::StoreVersion::from_env();
        let packages = &lockfile.packages;
        let indexes = graph::PackageIndexes::new(packages);
        let roots = graph::selected_roots(root_json, lockfile, &indexes);
        let platform_skipped_candidates = platform_skipped_package_keys(lockfile, &indexes, &roots);
        let instance_baselines = super::audit::inventory::build_instance_baselines(
            project_dir,
            &baseline_index,
            lockfile,
        );
        let installed_paths = installed_package_paths(project_dir, lockfile, &indexes, &roots)?;
        let mut metadata_by_package = BTreeMap::new();
        let mut platform_skipped_packages = BTreeSet::new();
        for package in packages {
            let package_key = package_metadata_key(package);
            if let Some(path) = installed_paths.get(&package_key) {
                if let Some(baseline) = baseline_index.lookup_by_package_dir(path)
                    && package
                        .integrity
                        .as_deref()
                        .is_some_and(|expected| expected != baseline.integrity)
                {
                    return Err(LpmError::Store(format!(
                        "installed package {}@{} has a different integrity than lpm.lock. Run `lpm install` to repair this project's dependencies",
                        package.name, package.version
                    )));
                }
                let manifest = path.join("package.json");
                match read_matching_manifest_metadata(&manifest, package)? {
                    ManifestProbe::Match(metadata) => {
                        metadata_by_package.insert(package_key, metadata);
                        continue;
                    }
                    ManifestProbe::Missing | ManifestProbe::DifferentPackage { .. } => {
                        if store_version.uses_virtual_store() {
                            return Err(missing_installed_manifest(package, Some(&manifest)));
                        }
                    }
                }
            }
            let virtual_baseline = package
                .instance_id
                .and_then(|id| instance_baselines.get(&id).map(std::sync::Arc::as_ref))
                .or_else(|| {
                    if package.instance_id.is_some() {
                        return None;
                    }
                    match package.integrity.as_deref() {
                        Some(integrity) => baseline_index.lookup_by_integrity(integrity),
                        None => baseline_index.lookup(&package.name, &package.version),
                    }
                });
            if let Some(baseline) = virtual_baseline {
                let manifest_path = baseline.package_dir.join("package.json");
                let metadata = read_required_manifest_metadata(&manifest_path, package)?;
                metadata_by_package.insert(package_key, metadata);
                continue;
            }

            if package.instance_id.is_some() && store_version.uses_virtual_store() {
                if platform_skipped_candidates.contains(&package_key) {
                    platform_skipped_packages.insert(package_key);
                    continue;
                }
                return Err(missing_installed_manifest(package, None));
            }
            let project_manifest = node_modules_package_json(project_dir, &package.name);
            match read_matching_manifest_metadata(&project_manifest, package)? {
                ManifestProbe::Match(metadata) => {
                    metadata_by_package.insert(package_key, metadata);
                    continue;
                }
                ManifestProbe::Missing | ManifestProbe::DifferentPackage { .. } => {}
            }

            if store_version == lpm_store::StoreVersion::V1
                && let Some(baseline) =
                    lpm_store::find_installed_package_baseline_by_identity_indexed(
                        &baseline_index,
                        &root_for_lock,
                        &package.name,
                        &package.version,
                        package.integrity.as_deref(),
                    )
            {
                let manifest_path = baseline.package_dir.join("package.json");
                let metadata = read_required_manifest_metadata(&manifest_path, package)?;
                metadata_by_package.insert(package_key, metadata);
                continue;
            }

            if platform_skipped_candidates.contains(&package_key) {
                platform_skipped_packages.insert(package_key);
                continue;
            }

            return Err(missing_installed_manifest(package, None));
        }
        Ok(InstalledManifestInventory {
            metadata_by_package,
            platform_skipped_packages,
        })
    })
}

enum ManifestProbe {
    Missing,
    Match(ManifestMetadata),
    DifferentPackage {
        name: Option<String>,
        version: Option<String>,
    },
}

fn read_required_manifest_metadata(
    path: &Path,
    package: &LockedPackage,
) -> Result<ManifestMetadata, LpmError> {
    match read_matching_manifest_metadata(path, package)? {
        ManifestProbe::Match(metadata) => Ok(metadata),
        ManifestProbe::Missing => Err(missing_installed_manifest(package, Some(path))),
        ManifestProbe::DifferentPackage { name, version } => Err(mismatched_installed_manifest(
            package,
            path,
            name.as_deref(),
            version.as_deref(),
        )),
    }
}

fn read_matching_manifest_metadata(
    path: &Path,
    package: &LockedPackage,
) -> Result<ManifestProbe, LpmError> {
    let content = match lpm_common::read_text_regular_file_capped_with_metadata(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok((content, _)) => content,
        Err(BoundedReadError::NotFound { .. }) => return Ok(ManifestProbe::Missing),
        Err(error) => {
            return Err(LpmError::Store(format!(
                "failed to read installed package manifest: {error}"
            )));
        }
    };
    let value: Value =
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).map_err(|error| {
            LpmError::Store(format!(
                "failed to parse installed package manifest {}: {error}",
                path.display()
            ))
        })?;
    if manifest_matches_package(&value, package) {
        Ok(ManifestProbe::Match(extract_manifest_metadata(&value)))
    } else {
        Ok(ManifestProbe::DifferentPackage {
            name: value.get("name").and_then(Value::as_str).map(str::to_owned),
            version: value
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }
}

fn manifest_matches_package(value: &Value, package: &LockedPackage) -> bool {
    value.get("name").and_then(Value::as_str) == Some(package.name.as_str())
        && value.get("version").and_then(Value::as_str) == Some(package.version.as_str())
}

pub(crate) fn package_metadata_key(package: &LockedPackage) -> String {
    if let Some(instance_id) = package.instance_id {
        return instance_id.to_string();
    }
    package_artifact_key(package)
}

pub(crate) fn package_artifact_key(package: &LockedPackage) -> String {
    let source = package.source.as_deref().unwrap_or("");
    let integrity = package.integrity.as_deref().unwrap_or("");
    let mut key = String::with_capacity(
        package.name.len() + package.version.len() + source.len() + integrity.len() + 3,
    );
    key.push_str(&package.name);
    key.push('\0');
    key.push_str(&package.version);
    key.push('\0');
    key.push_str(source);
    key.push('\0');
    key.push_str(integrity);
    key
}

fn collect_licenses(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.trim().is_empty() => out.push(s.trim().to_string()),
        Value::Object(obj) => {
            if let Some(s) = obj
                .get("type")
                .or_else(|| obj.get("name"))
                .or_else(|| obj.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                out.push(s.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_licenses(item, out);
            }
        }
        _ => {}
    }
}

fn extract_urlish(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(obj) => obj
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn extract_author(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(obj) => obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

fn node_modules_package_json(project_dir: &Path, name: &str) -> PathBuf {
    project_dir
        .join("node_modules")
        .join(name)
        .join("package.json")
}

fn missing_installed_manifest(package: &LockedPackage, path: Option<&Path>) -> LpmError {
    let location = path.map_or_else(
        || "in this project's linker graph".to_string(),
        |path| format!("at {}", path.display()),
    );
    LpmError::NotFound(format!(
        "installed package manifest for {}@{} was not found {location}. Run `lpm install` to repair this project's dependencies",
        package.name, package.version
    ))
}

fn mismatched_installed_manifest(
    package: &LockedPackage,
    path: &Path,
    actual_name: Option<&str>,
    actual_version: Option<&str>,
) -> LpmError {
    let actual_name = actual_name.unwrap_or("<missing name>");
    let actual_version = actual_version.unwrap_or("<missing version>");
    LpmError::Store(format!(
        "installed package manifest at {} identifies {actual_name}@{actual_version}, expected {}@{}. Run `lpm install` to repair this project's dependencies",
        path.display(),
        package.name,
        package.version
    ))
}

fn platform_skipped_package_keys(
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
    roots: &[(String, usize, graph::PackageScope)],
) -> BTreeSet<String> {
    let packages = &lockfile.packages;
    let adjacency = graph::package_adjacency(packages, indexes);
    let blocked: Vec<_> = packages
        .iter()
        .map(|package| package.optional && !locked_package_matches_current_platform(package))
        .collect();
    let mut candidates = vec![false; packages.len()];
    let mut queue: VecDeque<_> = blocked
        .iter()
        .enumerate()
        .filter_map(|(index, blocked)| blocked.then_some(index))
        .collect();
    while let Some(index) = queue.pop_front() {
        if candidates[index] {
            continue;
        }
        candidates[index] = true;
        queue.extend(
            adjacency[index]
                .iter()
                .copied()
                .filter(|&child| packages[child].optional),
        );
    }
    let mut reachable = vec![false; packages.len()];
    queue.extend(roots.iter().map(|(_, index, _)| *index));
    queue.extend(
        packages
            .iter()
            .enumerate()
            .filter_map(|(index, package)| (!package.optional).then_some(index)),
    );
    while let Some(index) = queue.pop_front() {
        if blocked[index] || reachable[index] {
            continue;
        }
        reachable[index] = true;
        queue.extend(adjacency[index].iter().copied());
    }
    packages
        .iter()
        .enumerate()
        .filter(|(index, _)| candidates[*index] && !reachable[*index])
        .map(|(_, package)| package_metadata_key(package))
        .collect()
}

pub(crate) fn installed_lockfile_paths(
    project_dir: &Path,
    lockfile: &Lockfile,
) -> Result<BTreeMap<String, PathBuf>, LpmError> {
    let root_json = read_json_file(&project_dir.join("package.json"))?;
    let indexes = graph::PackageIndexes::new(&lockfile.packages);
    let roots = graph::selected_roots(&root_json, lockfile, &indexes);
    installed_package_paths(project_dir, lockfile, &indexes, &roots)
}

fn installed_package_paths(
    project_dir: &Path,
    lockfile: &Lockfile,
    indexes: &graph::PackageIndexes<'_>,
    roots: &[(String, usize, graph::PackageScope)],
) -> Result<BTreeMap<String, PathBuf>, LpmError> {
    let project_dir = project_dir.canonicalize()?;
    let mut paths = BTreeMap::new();
    let mut pending = VecDeque::new();
    for (local, index, _) in roots {
        if let Some(path) = installed_slot(&project_dir, local)? {
            pending.push_back((*index, path));
        }
    }
    while let Some((index, path)) = pending.pop_front() {
        let package = &lockfile.packages[index];
        let key = package_metadata_key(package);
        if paths.contains_key(&key) {
            continue;
        }
        paths.insert(key, path.clone());
        for (local, target_index) in graph::package_targets(package, indexes) {
            if paths.contains_key(&package_metadata_key(&lockfile.packages[target_index])) {
                continue;
            }
            let mut resolved = None;
            for directory in path.ancestors() {
                if let Some(candidate) = installed_slot(directory, local)? {
                    resolved = Some(candidate);
                    break;
                }
                if directory == project_dir {
                    break;
                }
            }
            if resolved.is_none() && !path.starts_with(&project_dir) {
                resolved = installed_slot(&project_dir, local)?;
            }
            if let Some(path) = resolved {
                pending.push_back((target_index, path));
            }
        }
    }
    Ok(paths)
}

fn installed_slot(directory: &Path, local: &str) -> Result<Option<PathBuf>, LpmError> {
    Lockfile::validate_package_name_and_version(local, "0.0.0")
        .map_err(|error| LpmError::Store(error.to_string()))?;
    let path = directory.join("node_modules").join(local);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path.canonicalize()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn locked_package_matches_current_platform(package: &LockedPackage) -> bool {
    if package.os.is_empty() && package.cpu.is_empty() && package.libc.is_empty() {
        return true;
    }
    lpm_resolver::is_platform_compatible(&lpm_resolver::PlatformMeta {
        os: package.os.clone(),
        cpu: package.cpu.clone(),
        libc: package.libc.clone(),
    })
}

pub(crate) fn license_expression_from_list(licenses: &[String]) -> String {
    if licenses.is_empty() {
        return "NOASSERTION".to_string();
    }
    if licenses.len() == 1 {
        return licenses[0].clone();
    }
    licenses
        .iter()
        .map(|license| {
            if license.contains(char::is_whitespace) {
                format!("({license})")
            } else {
                license.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform_skipped_test_keys(packages: Vec<LockedPackage>) -> BTreeSet<String> {
        let lockfile = Lockfile {
            packages,
            ..Lockfile::new()
        };
        platform_skipped_package_keys(
            &lockfile,
            &graph::PackageIndexes::new(&lockfile.packages),
            &[],
        )
    }

    fn locked_package(name: &str, optional: bool) -> LockedPackage {
        LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            optional,
            ..Default::default()
        }
    }

    #[test]
    fn extract_manifest_metadata_collects_legacy_license_shapes() {
        let value = serde_json::json!({
            "license": { "type": "MIT" },
            "licenses": ["Apache-2.0", { "name": "BSD-3-Clause" }],
        });

        let metadata = extract_manifest_metadata(&value);

        assert_eq!(metadata.licenses, vec!["Apache-2.0", "BSD-3-Clause", "MIT"]);
    }

    #[test]
    fn platform_skip_includes_optional_descendants_of_incompatible_package() {
        let mut platform_package = locked_package("platform-package", true);
        platform_package.cpu = vec!["wasm32".to_string()];
        platform_package.dependencies = vec!["optional-runtime@1.0.0".to_string()];
        let runtime = locked_package("optional-runtime", true);

        let skipped = platform_skipped_test_keys(vec![platform_package.clone(), runtime.clone()]);

        assert_eq!(
            skipped,
            BTreeSet::from([
                package_metadata_key(&platform_package),
                package_metadata_key(&runtime),
            ])
        );
    }

    #[test]
    fn platform_skip_preserves_descendant_with_required_reachability() {
        let mut platform_package = locked_package("platform-package", true);
        platform_package.cpu = vec!["wasm32".to_string()];
        platform_package.dependencies = vec!["shared-runtime@1.0.0".to_string()];
        let runtime = locked_package("shared-runtime", false);

        let skipped = platform_skipped_test_keys(vec![platform_package.clone(), runtime]);

        assert_eq!(
            skipped,
            BTreeSet::from([package_metadata_key(&platform_package)])
        );
    }
}
