use lpm_common::{BoundedReadError, LpmError, LpmRoot, with_shared_lock};
use lpm_lockfile::LockedPackage;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
        for license in other.licenses {
            if !self.licenses.iter().any(|existing| existing == &license) {
                self.licenses.push(license);
            }
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
    let content = lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
    serde_json::from_str(&content).map_err(|e| {
        LpmError::Registry(format!("failed to parse JSON from {}: {e}", path.display()))
    })
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
    packages: &[LockedPackage],
) -> Result<InstalledManifestInventory, LpmError> {
    let root = LpmRoot::from_env()?;
    let lock_path = root.store_lock();
    let root_for_lock = root;
    with_shared_lock(lock_path, || {
        let baseline_index = lpm_store::V2BaselineIndex::for_project(project_dir, &root_for_lock);
        let store_version = lpm_store::StoreVersion::from_env();
        let platform_skipped_candidates = platform_skipped_package_keys(packages);
        let mut metadata_by_package = BTreeMap::new();
        let mut platform_skipped_packages = BTreeSet::new();
        for package in packages {
            let package_key = package_metadata_key(package);
            let virtual_baseline = match package.integrity.as_deref() {
                Some(integrity) => baseline_index.lookup_by_integrity(integrity),
                None => baseline_index.lookup(&package.name, &package.version),
            };
            if let Some(baseline) = virtual_baseline {
                let manifest_path = baseline.package_dir.join("package.json");
                let metadata = read_required_manifest_metadata(&manifest_path, package)?;
                metadata_by_package.insert(package_key, metadata);
                continue;
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
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(BoundedReadError::NotFound { .. }) => return Ok(ManifestProbe::Missing),
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "failed to read installed package manifest: {error}"
                )));
            }
        };
    let value: Value = serde_json::from_str(&content).map_err(|error| {
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
    let source = package.source.as_deref().unwrap_or("");
    let mut key =
        String::with_capacity(package.name.len() + package.version.len() + source.len() + 2);
    key.push_str(&package.name);
    key.push('\0');
    key.push_str(&package.version);
    key.push('\0');
    key.push_str(source);
    key
}

fn collect_licenses(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.is_empty() => out.push(s.clone()),
        Value::Object(obj) => {
            if let Some(s) = obj
                .get("type")
                .or_else(|| obj.get("name"))
                .or_else(|| obj.get("url"))
                .and_then(Value::as_str)
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

fn platform_skipped_package_keys(packages: &[LockedPackage]) -> BTreeSet<String> {
    let mut packages_by_pin: HashMap<String, Vec<usize>> = HashMap::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        packages_by_pin
            .entry(package_pin(&package.name, &package.version))
            .or_default()
            .push(index);
    }

    let mut skipped = vec![false; packages.len()];
    let mut queue = VecDeque::new();
    for (index, package) in packages.iter().enumerate() {
        if package.optional && !locked_package_matches_current_platform(package) {
            skipped[index] = true;
            queue.push_back(index);
        }
    }

    while let Some(index) = queue.pop_front() {
        let package = &packages[index];
        for dependency in package.dependencies.iter().chain(&package.peers) {
            let Some((local_name, version)) = split_dependency_pin(dependency) else {
                continue;
            };
            let target_name = package
                .alias_dependencies
                .iter()
                .find(|[local, _target]| local == local_name)
                .map_or(local_name, |[_local, target]| target.as_str());
            let target_pin = if target_name == local_name {
                Cow::Borrowed(dependency.as_str())
            } else {
                Cow::Owned(package_pin(target_name, version))
            };
            let Some(target_indices) = packages_by_pin.get(target_pin.as_ref()) else {
                continue;
            };
            for &target_index in target_indices {
                if packages[target_index].optional && !skipped[target_index] {
                    skipped[target_index] = true;
                    queue.push_back(target_index);
                }
            }
        }
    }

    packages
        .iter()
        .zip(skipped)
        .filter(|(_package, skipped)| *skipped)
        .map(|(package, _skipped)| package_metadata_key(package))
        .collect()
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

fn package_pin(name: &str, version: &str) -> String {
    let mut pin = String::with_capacity(name.len() + version.len() + 1);
    pin.push_str(name);
    pin.push('@');
    pin.push_str(version);
    pin
}

fn split_dependency_pin(input: &str) -> Option<(&str, &str)> {
    let split_at = input.rfind('@')?;
    if split_at == 0 || split_at + 1 == input.len() {
        return None;
    }
    Some((&input[..split_at], &input[split_at + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let skipped = platform_skipped_package_keys(&[platform_package.clone(), runtime.clone()]);

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

        let skipped = platform_skipped_package_keys(&[platform_package.clone(), runtime]);

        assert_eq!(
            skipped,
            BTreeSet::from([package_metadata_key(&platform_package)])
        );
    }
}
