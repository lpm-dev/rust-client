use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use lpm_common::{BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, read_text_file_capped};

use crate::error::WorkspaceError;
use crate::package_json::{PackageJson, strip_json_bom_str};

pub type CatalogReferences = BTreeMap<String, BTreeSet<String>>;

pub fn collect_catalog_references(package_json: &PackageJson, references: &mut CatalogReferences) {
    collect_catalog_references_from_deps(&package_json.dependencies, references);
    collect_catalog_references_from_deps(&package_json.dev_dependencies, references);
    collect_catalog_references_from_deps(&package_json.optional_dependencies, references);
    collect_catalog_references_from_deps(&package_json.peer_dependencies, references);
    collect_catalog_references_from_overrides(&package_json.overrides, references);
    collect_catalog_references_from_overrides(&package_json.resolutions, references);
    if let Some(lpm) = &package_json.lpm {
        collect_catalog_references_from_overrides(&lpm.overrides, references);
    }
}

fn collect_catalog_references_from_deps(
    deps: &HashMap<String, String>,
    references: &mut CatalogReferences,
) {
    for (package, range) in deps {
        let Some(catalog_name) = catalog_name_from_reference(range) else {
            continue;
        };
        references
            .entry(catalog_name.to_string())
            .or_default()
            .insert(package.clone());
    }
}

fn collect_catalog_references_from_overrides(
    overrides: &HashMap<String, String>,
    references: &mut CatalogReferences,
) {
    for (selector, target) in overrides {
        let Some(catalog_name) = catalog_name_from_reference(target) else {
            continue;
        };
        let Some(package) = override_selector_leaf_name(selector) else {
            continue;
        };
        references
            .entry(catalog_name.to_string())
            .or_default()
            .insert(package.to_string());
    }
}

fn override_selector_leaf_name(selector: &str) -> Option<&str> {
    let leaf = selector.rsplit('>').next()?.trim();
    if leaf.is_empty() {
        return None;
    }

    let scope_offset = usize::from(leaf.starts_with('@'));
    let search = &leaf[scope_offset..];
    let name_end = search
        .find('@')
        .map_or(leaf.len(), |index| scope_offset + index);
    let name = leaf[..name_end].trim();
    if name.is_empty() { None } else { Some(name) }
}

fn catalog_name_from_reference(reference: &str) -> Option<&str> {
    let catalog_name = reference.strip_prefix("catalog:")?;
    if catalog_name.is_empty() {
        Some("default")
    } else {
        Some(catalog_name)
    }
}

/// Prune unreferenced `package.json > catalogs` entries.
pub fn prune_unused_package_json_catalogs(
    path: &Path,
    references: &CatalogReferences,
) -> Result<bool, WorkspaceError> {
    let content = read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| WorkspaceError::Io(error.to_string()))?;
    let mut doc: serde_json::Value =
        serde_json::from_str(strip_json_bom_str(&content)).map_err(|e| {
            WorkspaceError::Parse(format!(
                "failed to parse package manifest {}: {e}",
                path.display()
            ))
        })?;

    if !prune_json_catalogs(&mut doc, references) {
        return Ok(false);
    }

    let updated = serde_json::to_string_pretty(&doc).map_err(|e| {
        WorkspaceError::Parse(format!(
            "failed to serialize package manifest {}: {e}",
            path.display()
        ))
    })?;
    lpm_common::write_file_atomic(path, format!("{updated}\n"))
        .map_err(|e| WorkspaceError::Io(format!("failed to write {}: {e}", path.display())))?;
    Ok(true)
}

fn prune_json_catalogs(doc: &mut serde_json::Value, references: &CatalogReferences) -> bool {
    let Some(root) = doc.as_object_mut() else {
        return false;
    };
    let Some(catalogs) = root
        .get_mut("catalogs")
        .and_then(|value| value.as_object_mut())
    else {
        return false;
    };

    let mut changed = false;
    let catalog_names: Vec<String> = catalogs.keys().cloned().collect();
    for catalog_name in catalog_names {
        let Some(entries) = catalogs
            .get_mut(&catalog_name)
            .and_then(|value| value.as_object_mut())
        else {
            continue;
        };
        let package_names: Vec<String> = entries.keys().cloned().collect();
        for package_name in package_names {
            if !catalog_reference_exists(references, &catalog_name, &package_name) {
                entries.remove(&package_name);
                changed = true;
            }
        }
        if entries.is_empty() {
            catalogs.remove(&catalog_name);
            changed = true;
        }
    }

    if catalogs.is_empty() {
        root.remove("catalogs");
        changed = true;
    }

    changed
}

/// Prune unreferenced `pnpm-workspace.yaml` `catalog`/`catalogs` entries.
pub fn prune_unused_pnpm_workspace_catalogs(
    path: &Path,
    references: &CatalogReferences,
) -> Result<bool, WorkspaceError> {
    let content = match read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => content,
        Err(BoundedReadError::NotFound { .. }) => return Ok(false),
        Err(error) => return Err(WorkspaceError::Io(error.to_string())),
    };
    if content.trim().is_empty() {
        return Ok(false);
    }

    let mut doc: serde_yaml::Value = serde_yaml::from_str(&content).map_err(|e| {
        WorkspaceError::Parse(format!(
            "failed to parse pnpm workspace manifest {}: {e}",
            path.display()
        ))
    })?;

    if !prune_yaml_catalogs(&mut doc, references) {
        return Ok(false);
    }

    let updated = serde_yaml::to_string(&doc).map_err(|e| {
        WorkspaceError::Parse(format!(
            "failed to serialize pnpm workspace manifest {}: {e}",
            path.display()
        ))
    })?;
    lpm_common::write_file_atomic(path, updated)
        .map_err(|e| WorkspaceError::Io(format!("failed to write {}: {e}", path.display())))?;
    Ok(true)
}

fn prune_yaml_catalogs(doc: &mut serde_yaml::Value, references: &CatalogReferences) -> bool {
    let Some(root) = doc.as_mapping_mut() else {
        return false;
    };

    let mut changed = false;
    changed |= prune_yaml_default_catalog(root, references);
    changed |= prune_yaml_named_catalogs(root, references);
    changed
}

fn prune_yaml_default_catalog(
    root: &mut serde_yaml::Mapping,
    references: &CatalogReferences,
) -> bool {
    let key = serde_yaml::Value::String("catalog".to_string());
    let mut remove_catalog = false;
    let mut changed = false;

    if let Some(entries) = root.get_mut(&key).and_then(|value| value.as_mapping_mut()) {
        changed |= prune_yaml_catalog_entries(entries, "default", references);
        remove_catalog = entries.is_empty();
    }

    if remove_catalog {
        root.remove(&key);
        changed = true;
    }

    changed
}

fn prune_yaml_named_catalogs(
    root: &mut serde_yaml::Mapping,
    references: &CatalogReferences,
) -> bool {
    let key = serde_yaml::Value::String("catalogs".to_string());
    let mut remove_catalogs = false;
    let mut changed = false;

    if let Some(catalogs) = root.get_mut(&key).and_then(|value| value.as_mapping_mut()) {
        let catalog_names: Vec<serde_yaml::Value> = catalogs.keys().cloned().collect();
        for catalog_key in catalog_names {
            let Some(catalog_name) = catalog_key.as_str().map(str::to_string) else {
                continue;
            };
            let mut remove_catalog = false;
            if let Some(entries) = catalogs
                .get_mut(&catalog_key)
                .and_then(|value| value.as_mapping_mut())
            {
                changed |= prune_yaml_catalog_entries(entries, &catalog_name, references);
                remove_catalog = entries.is_empty();
            }
            if remove_catalog {
                catalogs.remove(&catalog_key);
                changed = true;
            }
        }
        remove_catalogs = catalogs.is_empty();
    }

    if remove_catalogs {
        root.remove(&key);
        changed = true;
    }

    changed
}

fn prune_yaml_catalog_entries(
    entries: &mut serde_yaml::Mapping,
    catalog_name: &str,
    references: &CatalogReferences,
) -> bool {
    let mut changed = false;
    let package_keys: Vec<serde_yaml::Value> = entries.keys().cloned().collect();
    for package_key in package_keys {
        let Some(package_name) = package_key.as_str() else {
            continue;
        };
        if !catalog_reference_exists(references, catalog_name, package_name) {
            entries.remove(&package_key);
            changed = true;
        }
    }
    changed
}

fn catalog_reference_exists(
    references: &CatalogReferences,
    catalog_name: &str,
    package_name: &str,
) -> bool {
    references
        .get(catalog_name)
        .is_some_and(|packages| packages.contains(package_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn collect_catalog_references_reads_dependency_fields() {
        let pkg: PackageJson = serde_json::from_str(
            r#"{
                "dependencies": {"react": "catalog:"},
                "devDependencies": {"vitest": "catalog:testing"},
                "optionalDependencies": {"fsevents": "^2.0.0"},
                "peerDependencies": {"typescript": "catalog:tooling"},
                "overrides": {"react-dom": "catalog:"},
                "resolutions": {"vite>esbuild": "catalog:build"},
                "lpm": {
                    "overrides": {
                        "@types/react@^18.0.0": "catalog:types"
                    }
                }
            }"#,
        )
        .unwrap();
        let mut references = CatalogReferences::new();

        collect_catalog_references(&pkg, &mut references);

        assert!(references["default"].contains("react"));
        assert!(references["default"].contains("react-dom"));
        assert!(references["testing"].contains("vitest"));
        assert!(references["tooling"].contains("typescript"));
        assert!(references["build"].contains("esbuild"));
        assert!(references["types"].contains("@types/react"));
        assert!(
            !references
                .values()
                .any(|packages| packages.contains("fsevents"))
        );
    }

    #[test]
    fn prune_unused_package_json_catalogs_removes_unreferenced_entries() {
        let dir = tempfile::tempdir().unwrap();
        let package_json_path = dir.path().join("package.json");
        fs::write(
            &package_json_path,
            r#"{
                "catalogs": {
                    "default": {
                        "react": "^18.0.0",
                        "unused": "^1.0.0"
                    },
                    "testing": {
                        "unused": "^1.0.0"
                    }
                }
            }"#,
        )
        .unwrap();
        let mut references = CatalogReferences::new();
        references
            .entry("default".to_string())
            .or_default()
            .insert("react".to_string());

        let changed = prune_unused_package_json_catalogs(&package_json_path, &references).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&package_json_path).unwrap()).unwrap();

        assert!(changed);
        assert_eq!(doc["catalogs"]["default"]["react"], "^18.0.0");
        assert!(doc["catalogs"]["default"].get("unused").is_none());
        assert!(doc["catalogs"].get("testing").is_none());
    }

    #[test]
    fn prune_unused_pnpm_workspace_catalogs_removes_unreferenced_entries() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_path = dir.path().join("pnpm-workspace.yaml");
        fs::write(
            &workspace_path,
            r#"packages:
  - "packages/*"
catalog:
  react: ^18.0.0
  unused: ^1.0.0
catalogs:
  testing:
    vitest: ^1.0.0
    unused: ^1.0.0
"#,
        )
        .unwrap();
        let mut references = CatalogReferences::new();
        references
            .entry("default".to_string())
            .or_default()
            .insert("react".to_string());
        references
            .entry("testing".to_string())
            .or_default()
            .insert("vitest".to_string());

        let changed = prune_unused_pnpm_workspace_catalogs(&workspace_path, &references).unwrap();
        let updated = fs::read_to_string(&workspace_path).unwrap();

        assert!(changed);
        assert!(updated.contains("react"));
        assert!(updated.contains("vitest"));
        assert!(!updated.contains("unused"));
    }
}
