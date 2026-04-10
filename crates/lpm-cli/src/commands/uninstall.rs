use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
struct UninstallResult {
    removed: Vec<String>,
    not_found: Vec<String>,
}

fn remove_from_manifest(doc: &mut Value, packages: &[String], json_output: bool) -> UninstallResult {
    let mut removed = Vec::new();
    let mut not_found = Vec::new();

    for name in packages {
        let mut found = false;

        for key in &["dependencies", "devDependencies"] {
            if let Some(deps) = doc.get_mut(*key)
                && let Some(obj) = deps.as_object_mut()
                && obj.remove(name).is_some()
            {
                found = true;
                if !json_output {
                    output::info(&format!("Removed {} from {}", name.bold(), key));
                }
            }
        }

        if found {
            removed.push(name.clone());
        } else {
            not_found.push(name.clone());
        }
    }

    UninstallResult { removed, not_found }
}

fn cleanup_removed_packages(project_dir: &Path, removed: &[String]) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if lockfile_path.exists() {
        std::fs::remove_file(&lockfile_path)?;
    }

    let node_modules = project_dir.join("node_modules");
    for name in removed {
        let link = node_modules.join(name);
        if link.symlink_metadata().is_ok()
            && (link.is_dir()
                || link
                    .symlink_metadata()
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false))
        {
            #[cfg(unix)]
            std::fs::remove_file(&link)
                .or_else(|_| std::fs::remove_dir(&link))
                .ok();
            #[cfg(windows)]
            std::fs::remove_dir(&link).ok();
        }
    }

    Ok(())
}

fn uninstall_from_project(
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<UninstallResult, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    let content = std::fs::read_to_string(&pkg_json_path)?;
    let mut doc: Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let result = remove_from_manifest(&mut doc, packages, json_output);
    if result.removed.is_empty() {
        return Ok(result);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(&pkg_json_path, format!("{updated}\n"))?;

    cleanup_removed_packages(project_dir, &result.removed)?;

    Ok(result)
}

pub async fn run(
    _client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    if packages.is_empty() {
        return Err(LpmError::Registry(
            "specify at least one package to uninstall".to_string(),
        ));
    }
    let result = uninstall_from_project(project_dir, packages, json_output)?;

    if result.removed.is_empty() {
        if !json_output {
            output::warn("No packages were removed (not found in dependencies)");
        }
        return Ok(());
    }

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "removed": result.removed,
            "not_found": result.not_found,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        if !result.not_found.is_empty() {
            output::warn(&format!(
                "Not found in dependencies: {}",
                result.not_found.join(", ")
            ));
        }
        println!();
        output::success(&format!(
            "Removed {} package(s)",
            result.removed.len().to_string().bold()
        ));
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_package_json(project_dir: &Path, value: &Value) {
        std::fs::write(
            project_dir.join("package.json"),
            format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn remove_from_manifest_tracks_removed_and_not_found() {
        let mut manifest = json!({
            "dependencies": {
                "foo": "1.0.0",
                "bar": "2.0.0"
            },
            "devDependencies": {
                "baz": "3.0.0"
            }
        });
        let packages = vec!["foo".to_string(), "baz".to_string(), "missing".to_string()];

        let result = remove_from_manifest(&mut manifest, &packages, true);

        assert_eq!(
            result,
            UninstallResult {
                removed: vec!["foo".to_string(), "baz".to_string()],
                not_found: vec!["missing".to_string()],
            }
        );
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(manifest["devDependencies"].get("baz").is_none());
        assert_eq!(manifest["dependencies"]["bar"], "2.0.0");
    }

    #[test]
    fn uninstall_from_project_removes_targeted_dependency_and_lockfile_only_when_changed() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0",
                    "bar": "2.0.0"
                },
                "devDependencies": {
                    "baz": "3.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("foo")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("bar")).unwrap();

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        assert_eq!(result.removed, vec!["foo".to_string()]);
        assert!(
            !dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should be removed when manifest changes"
        );
        assert!(
            !dir.path().join("node_modules").join("foo").exists(),
            "removed package directory should be cleaned up"
        );
        assert!(
            dir.path().join("node_modules").join("bar").exists(),
            "unrelated node_modules entries must be preserved"
        );

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
        assert_eq!(manifest["dependencies"]["bar"], "2.0.0");
        assert_eq!(manifest["devDependencies"]["baz"], "3.0.0");
    }

    #[test]
    fn uninstall_from_project_preserves_files_when_package_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "bar": "2.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();

        let original_manifest = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let result = uninstall_from_project(dir.path(), &["missing".to_string()], true).unwrap();

        assert!(result.removed.is_empty());
        assert_eq!(result.not_found, vec!["missing".to_string()]);
        assert!(
            dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should remain when nothing was removed"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            original_manifest,
            "package.json should not be rewritten when no dependency matched"
        );
    }
}
