use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, VerifierError};

const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".lpm",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    "coverage",
    "dist",
    "node_modules",
    "target",
];

pub fn canonical_workspace(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|source| VerifierError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !canonical.is_dir() {
        return Err(VerifierError::InvalidWorkspace {
            path: path.to_path_buf(),
        });
    }
    Ok(canonical)
}

pub fn discover_files(root: &Path, filename: &str) -> Result<Vec<PathBuf>> {
    let mut matches = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|source| VerifierError::Read {
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| VerifierError::Read {
                path: directory.clone(),
                source,
            })?;
            let file_type = entry.file_type().map_err(|source| VerifierError::Read {
                path: entry.path(),
                source,
            })?;
            let name = entry.file_name();
            if file_type.is_file() && name == filename {
                matches.push(entry.path());
            } else if file_type.is_dir()
                && !file_type.is_symlink()
                && !SKIPPED_DIRECTORIES
                    .iter()
                    .any(|skipped| name == std::ffi::OsStr::new(skipped))
            {
                pending.push(entry.path());
            }
        }
    }
    matches.sort();
    Ok(matches)
}

pub fn discover_workspace_packages(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut packages = BTreeMap::new();
    for manifest_path in discover_files(root, "package.json")? {
        let bytes = std::fs::read(&manifest_path).map_err(|source| VerifierError::Read {
            path: manifest_path.clone(),
            source,
        })?;
        let manifest: PackageManifest =
            serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&bytes)).map_err(|source| {
                VerifierError::JsonRead {
                    path: manifest_path.clone(),
                    source,
                }
            })?;
        let Some(name) = manifest.name else {
            continue;
        };
        let package_dir = manifest_path
            .parent()
            .expect("discovered package.json has a parent");
        let link_dir = manifest
            .publish_config
            .directory
            .as_deref()
            .filter(|directory| valid_package_relative_path(directory))
            .map_or_else(
                || package_dir.to_path_buf(),
                |directory| package_dir.join(directory),
            );
        packages.insert(name, relative_path(root, &link_dir));
    }
    Ok(packages)
}

#[derive(Debug, Serialize)]
pub struct ImporterInventory {
    schema_version: u32,
    importer_paths: Vec<String>,
}

pub fn discover_recursive_importers(root: &Path) -> Result<ImporterInventory> {
    let root = canonical_workspace(root)?;
    let workspace = lpm_workspace::discover_workspace(&root).map_err(|error| {
        VerifierError::WorkspaceDiscovery {
            path: root.clone(),
            message: error.to_string(),
        }
    })?;
    let mut importer_paths = vec![".".to_string()];
    if let Some(workspace) = workspace {
        importer_paths.reserve(workspace.members.len());
        importer_paths.extend(
            workspace
                .members
                .iter()
                .map(|member| relative_path(&workspace.root, &member.path)),
        );
    }
    importer_paths.sort();
    importer_paths.dedup();
    Ok(ImporterInventory {
        schema_version: 1,
        importer_paths,
    })
}

pub fn relative_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut normalized = String::new();
    for component in relative.components() {
        if matches!(component, Component::CurDir) {
            continue;
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(&component.as_os_str().to_string_lossy());
    }
    if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

pub fn normalize_lock_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    normalized
        .strip_prefix("./")
        .unwrap_or(&normalized)
        .trim_end_matches('/')
        .to_string()
}

pub fn normalize_relative_path(base: &str, raw_path: &str) -> String {
    let path = Path::new(base).join(raw_path);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                components.pop();
            }
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    if components.is_empty() {
        ".".into()
    } else {
        components.join("/")
    }
}

#[derive(Debug, Deserialize)]
struct PackageManifest {
    name: Option<String>,
    #[serde(default, rename = "publishConfig")]
    publish_config: PublishConfigManifest,
}

#[derive(Debug, Default, Deserialize)]
struct PublishConfigManifest {
    directory: Option<String>,
}

fn valid_package_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !Path::new(path).is_absolute()
        && !Path::new(path).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_discovery_skips_installed_and_build_trees() {
        let directory = tempfile::tempdir().expect("create fixture");
        std::fs::create_dir_all(directory.path().join("packages/app"))
            .expect("create workspace package");
        std::fs::create_dir_all(directory.path().join("node_modules/hidden"))
            .expect("create installed package");
        std::fs::write(
            directory.path().join("packages/app/package.json"),
            r#"{"name":"@fixture/app"}"#,
        )
        .expect("write workspace manifest");
        std::fs::write(
            directory.path().join("node_modules/hidden/package.json"),
            r#"{"name":"hidden"}"#,
        )
        .expect("write installed manifest");

        let packages = discover_workspace_packages(directory.path()).expect("discover packages");

        assert_eq!(
            packages,
            BTreeMap::from([("@fixture/app".into(), "packages/app".into())])
        );
    }

    #[test]
    fn package_discovery_accepts_utf8_bom_prefixed_manifests() {
        let directory = tempfile::tempdir().expect("create fixture");
        std::fs::write(
            directory.path().join("package.json"),
            b"\xEF\xBB\xBF{\"name\":\"bom-package\"}",
        )
        .expect("write BOM manifest");

        let packages = discover_workspace_packages(directory.path()).expect("discover packages");

        assert_eq!(packages.get("bom-package").map(String::as_str), Some("."));
    }

    #[test]
    fn package_discovery_uses_the_declared_publish_directory() {
        let directory = tempfile::tempdir().expect("create fixture");
        std::fs::create_dir_all(directory.path().join("packages/library/build"))
            .expect("create publish directory");
        std::fs::write(
            directory.path().join("packages/library/package.json"),
            r#"{"name":"@fixture/library","publishConfig":{"directory":"build"}}"#,
        )
        .expect("write package manifest");

        let packages = discover_workspace_packages(directory.path()).expect("discover packages");

        assert_eq!(
            packages.get("@fixture/library").map(String::as_str),
            Some("packages/library/build"),
        );
    }

    #[test]
    fn recursive_importer_discovery_uses_declared_workspace_members_only() {
        let directory = tempfile::tempdir().expect("create fixture");
        std::fs::create_dir_all(directory.path().join("packages/member"))
            .expect("create workspace member");
        std::fs::create_dir_all(directory.path().join("fixtures/not-a-member"))
            .expect("create non-member fixture");
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        )
        .expect("write root manifest");
        std::fs::write(
            directory.path().join("packages/member/package.json"),
            r#"{"name":"member"}"#,
        )
        .expect("write member manifest");
        std::fs::write(
            directory.path().join("fixtures/not-a-member/package.json"),
            r#"{"name":"not-a-member"}"#,
        )
        .expect("write non-member manifest");

        let inventory = discover_recursive_importers(directory.path()).expect("discover importers");

        assert_eq!(inventory.importer_paths, [".", "packages/member"]);
    }

    #[test]
    fn relative_root_is_dot_and_nested_paths_use_forward_slashes() {
        let root = Path::new("/tmp/workspace");
        assert_eq!(relative_path(root, root), ".");
        assert_eq!(
            relative_path(root, &root.join("packages/app")),
            "packages/app"
        );
    }

    #[test]
    fn relative_link_paths_are_resolved_without_escaping_the_workspace_name_space() {
        assert_eq!(
            normalize_relative_path("packages/app", "../shared"),
            "packages/shared"
        );
        assert_eq!(normalize_relative_path(".", "packages/app"), "packages/app");
    }
}
