use lpm_common::{LpmError, LpmRoot, with_shared_lock};
use lpm_lockfile::LockedPackage;
use serde_json::Value;
use std::collections::BTreeMap;
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

pub(crate) fn read_json_file(path: &Path) -> Result<Value, LpmError> {
    let content = std::fs::read_to_string(path).map_err(LpmError::Io)?;
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

pub(crate) fn read_local_metadata(
    project_dir: &Path,
    packages: &[LockedPackage],
) -> Result<BTreeMap<String, ManifestMetadata>, LpmError> {
    let root = LpmRoot::from_env()?;
    let lock_path = root.store_lock();
    let root_for_lock = root;
    with_shared_lock(lock_path, || {
        let mut out = BTreeMap::new();
        for package in packages {
            let mut metadata = ManifestMetadata::default();
            if let Some(node_modules_metadata) = read_matching_manifest_metadata(
                &node_modules_package_json(project_dir, &package.name),
                package,
            )? {
                metadata.merge_missing(node_modules_metadata);
            }
            if let Some(baseline) = lpm_store::find_installed_package_baseline(
                &root_for_lock,
                &package.name,
                &package.version,
            )? && let Some(store_metadata) = read_matching_manifest_metadata(
                &baseline.package_dir.join("package.json"),
                package,
            )? {
                metadata.merge_missing(store_metadata);
            }
            if !metadata_is_empty(&metadata) {
                out.insert(package_metadata_key(package), metadata);
            }
        }
        Ok(out)
    })
}

fn read_matching_manifest_metadata(
    path: &Path,
    package: &LockedPackage,
) -> Result<Option<ManifestMetadata>, LpmError> {
    match read_json_file(path) {
        Ok(value) => {
            if manifest_matches_package(&value, package) {
                Ok(Some(extract_manifest_metadata(&value)))
            } else {
                Ok(None)
            }
        }
        Err(LpmError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
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

fn metadata_is_empty(metadata: &ManifestMetadata) -> bool {
    metadata.description.is_none()
        && metadata.licenses.is_empty()
        && metadata.homepage.is_none()
        && metadata.repository.is_none()
        && metadata.author.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_manifest_metadata_collects_legacy_license_shapes() {
        let value = serde_json::json!({
            "license": { "type": "MIT" },
            "licenses": ["Apache-2.0", { "name": "BSD-3-Clause" }],
        });

        let metadata = extract_manifest_metadata(&value);

        assert_eq!(metadata.licenses, vec!["Apache-2.0", "BSD-3-Clause", "MIT"]);
    }
}
