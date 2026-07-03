use lpm_common::LpmError;
use lpm_semver::{Version, VersionBump, VersionReq};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

const DEPENDENCY_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReleasePlan {
    pub(crate) packages: Vec<PackageRelease>,
    pub(crate) dependency_updates: Vec<DependencyUpdate>,
    pub(crate) files: Vec<FileUpdate>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageRelease {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) manifest_path: PathBuf,
    pub(crate) old_version: String,
    pub(crate) new_version: String,
    pub(crate) bump: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DependencyUpdate {
    pub(crate) dependent: String,
    pub(crate) dependency: String,
    pub(crate) section: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) old_spec: String,
    pub(crate) new_spec: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FileUpdate {
    pub(crate) path: PathBuf,
    pub(crate) changes: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedManifest {
    pub(crate) path: PathBuf,
    pub(crate) json: serde_json::Value,
    pub(crate) changes: usize,
}

#[derive(Debug, Clone)]
struct WorkspaceManifest {
    name: String,
    version: Version,
    path: PathBuf,
    manifest_path: PathBuf,
    json: serde_json::Value,
}

impl ReleasePlan {
    pub(crate) fn to_json(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "dry_run": dry_run,
            "packages": self.packages,
            "dependency_updates": self.dependency_updates,
            "files": self.files,
        })
    }

    pub(crate) fn planned_manifests(&self) -> Result<Vec<PlannedManifest>, LpmError> {
        let mut manifests: BTreeMap<PathBuf, PlannedManifest> = BTreeMap::new();

        for package in &self.packages {
            let entry = manifests
                .entry(package.manifest_path.clone())
                .or_insert_with(|| PlannedManifest {
                    path: package.manifest_path.clone(),
                    json: serde_json::Value::Null,
                    changes: 0,
                });
            if entry.json.is_null() {
                entry.json = read_manifest_json(&package.manifest_path)?;
            }
            entry.changes += 1;
            set_top_level_string(&mut entry.json, "version", &package.new_version)?;
        }

        for update in &self.dependency_updates {
            let entry = manifests
                .entry(update.manifest_path.clone())
                .or_insert_with(|| PlannedManifest {
                    path: update.manifest_path.clone(),
                    json: serde_json::Value::Null,
                    changes: 0,
                });
            if entry.json.is_null() {
                entry.json = read_manifest_json(&update.manifest_path)?;
            }
            entry.changes += 1;
            set_dependency_string(
                &mut entry.json,
                &update.section,
                &update.dependency,
                &update.new_spec,
            )?;
        }

        Ok(manifests.into_values().collect())
    }
}

pub(crate) fn write_planned_manifests(manifests: &[PlannedManifest]) -> Result<(), LpmError> {
    for manifest in manifests {
        let mut bytes = serde_json::to_vec_pretty(&manifest.json)?;
        bytes.push(b'\n');
        lpm_common::write_file_atomic(&manifest.path, &bytes)?;
    }
    Ok(())
}

pub(crate) fn plan_single_package(
    project_dir: &Path,
    bump: &VersionBump,
) -> Result<ReleasePlan, LpmError> {
    let manifest_path = project_dir.join("package.json");
    let manifest = read_workspace_manifest(project_dir, manifest_path)?;
    let package = bumped_package(manifest, bump)?;
    Ok(ReleasePlan {
        files: vec![FileUpdate {
            path: package.manifest_path.clone(),
            changes: 1,
        }],
        packages: vec![package],
        dependency_updates: Vec::new(),
    })
}

pub(crate) fn plan_workspace(
    workspace: &lpm_workspace::Workspace,
    selected: &[usize],
    bump_by_name: &HashMap<String, VersionBump>,
    default_bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let selected_set: HashSet<usize> = selected.iter().copied().collect();
    let mut manifests = Vec::with_capacity(workspace.members.len());
    for member in &workspace.members {
        manifests.push(read_workspace_manifest(
            &member.path,
            member.path.join("package.json"),
        )?);
    }

    let mut packages = Vec::new();
    for (idx, manifest) in manifests.iter().cloned().enumerate() {
        if !selected_set.contains(&idx) {
            continue;
        }
        let Some(bump) = bump_by_name.get(&manifest.name).or(default_bump) else {
            return Err(LpmError::Script(format!(
                "no bump level provided for workspace package `{}`. Pass --bump or add .lpm/changes entries.",
                manifest.name
            )));
        };
        packages.push(bumped_package(manifest, bump)?);
    }

    let bumped_versions: HashMap<String, (&str, &str)> = packages
        .iter()
        .map(|package| {
            (
                package.name.clone(),
                (package.old_version.as_str(), package.new_version.as_str()),
            )
        })
        .collect();
    let dependency_updates = plan_dependency_updates(&manifests, &bumped_versions)?;
    let files = summarize_file_updates(&packages, &dependency_updates);

    Ok(ReleasePlan {
        packages,
        dependency_updates,
        files,
    })
}

pub(crate) fn validate_workspace_internal_ranges(
    workspace: &lpm_workspace::Workspace,
) -> Result<(), LpmError> {
    let mut versions = HashMap::with_capacity(workspace.members.len());
    for member in &workspace.members {
        let manifest = read_workspace_manifest(&member.path, member.path.join("package.json"))?;
        versions.insert(manifest.name, manifest.version.to_string());
    }

    for member in &workspace.members {
        let manifest = read_workspace_manifest(&member.path, member.path.join("package.json"))?;
        let Some(obj) = manifest.json.as_object() else {
            continue;
        };
        for section in DEPENDENCY_SECTIONS {
            let Some(deps) = obj.get(*section).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for (dependency, spec_value) in deps {
                let Some(version) = versions.get(dependency.as_str()) else {
                    continue;
                };
                let Some(spec) = spec_value.as_str() else {
                    continue;
                };
                if dynamic_workspace_spec(spec) || spec.starts_with("catalog:") {
                    continue;
                }
                let range = spec.strip_prefix("workspace:").unwrap_or(spec);
                if !range_satisfies_version(range, version) {
                    return Err(LpmError::Script(format!(
                        "`{}` depends on `{}` as `{}` in {}, which does not accept current workspace version {}",
                        manifest.name,
                        dependency,
                        spec,
                        manifest.manifest_path.display(),
                        version
                    )));
                }
            }
        }
    }
    Ok(())
}

fn read_workspace_manifest(
    path: &Path,
    manifest_path: PathBuf,
) -> Result<WorkspaceManifest, LpmError> {
    let json = read_manifest_json(&manifest_path)?;
    let obj = json.as_object().ok_or_else(|| {
        LpmError::Script(format!(
            "{} must contain a JSON object",
            manifest_path.display()
        ))
    })?;
    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LpmError::Script(format!(
                "{} is missing a string `name` field",
                manifest_path.display()
            ))
        })?
        .to_string();
    let version = obj
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LpmError::Script(format!(
                "{} is missing a string `version` field",
                manifest_path.display()
            ))
        })
        .and_then(Version::parse)?;

    Ok(WorkspaceManifest {
        name,
        version,
        path: path.to_path_buf(),
        manifest_path,
        json,
    })
}

fn read_manifest_json(path: &Path) -> Result<serde_json::Value, LpmError> {
    let content = std::fs::read_to_string(path).map_err(LpmError::Io)?;
    serde_json::from_str(&content).map_err(LpmError::Json)
}

fn bumped_package(
    manifest: WorkspaceManifest,
    bump: &VersionBump,
) -> Result<PackageRelease, LpmError> {
    let new_version = manifest.version.bump(bump)?;
    if new_version <= manifest.version {
        return Err(LpmError::Script(format!(
            "`{}` would move from {} to {}; release versions must increase",
            manifest.name, manifest.version, new_version
        )));
    }
    Ok(PackageRelease {
        name: manifest.name,
        path: manifest.path,
        manifest_path: manifest.manifest_path,
        old_version: manifest.version.to_string(),
        new_version: new_version.to_string(),
        bump: bump.as_str().to_string(),
    })
}

fn plan_dependency_updates(
    manifests: &[WorkspaceManifest],
    bumped_versions: &HashMap<String, (&str, &str)>,
) -> Result<Vec<DependencyUpdate>, LpmError> {
    let mut updates = Vec::new();
    for manifest in manifests {
        let Some(obj) = manifest.json.as_object() else {
            continue;
        };
        for section in DEPENDENCY_SECTIONS {
            let Some(deps) = obj.get(*section).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for (dependency, spec_value) in deps {
                let Some((old_version, new_version)) = bumped_versions.get(dependency.as_str())
                else {
                    continue;
                };
                let Some(old_spec) = spec_value.as_str() else {
                    continue;
                };
                if let Some(new_spec) = updated_dependency_spec(old_spec, old_version, new_version)
                {
                    if new_spec != old_spec {
                        updates.push(DependencyUpdate {
                            dependent: manifest.name.clone(),
                            dependency: dependency.clone(),
                            section: (*section).to_string(),
                            manifest_path: manifest.manifest_path.clone(),
                            old_spec: old_spec.to_string(),
                            new_spec,
                        });
                    }
                    continue;
                }
                if dynamic_workspace_spec(old_spec) || old_spec.starts_with("catalog:") {
                    continue;
                }
                let validation_range = old_spec.strip_prefix("workspace:").unwrap_or(old_spec);
                if !range_satisfies_version(validation_range, new_version) {
                    return Err(LpmError::Script(format!(
                        "`{}` depends on `{}` as `{}` in {}, which will not accept {}. Update the range or use an exact, caret, tilde, workspace, or catalog spec.",
                        manifest.name,
                        dependency,
                        old_spec,
                        manifest.manifest_path.display(),
                        new_version
                    )));
                }
            }
        }
    }
    Ok(updates)
}

fn dynamic_workspace_spec(spec: &str) -> bool {
    matches!(spec.strip_prefix("workspace:"), Some("*" | "^" | "~"))
}

fn updated_dependency_spec(old_spec: &str, old_version: &str, new_version: &str) -> Option<String> {
    let (workspace_prefix, inner) = old_spec
        .strip_prefix("workspace:")
        .map_or(("", old_spec), |inner| ("workspace:", inner));

    match inner {
        "*" | "^" | "~" => return None,
        _ => {}
    }

    if range_satisfies_version(inner, new_version) {
        return None;
    }

    let replacement = if inner == old_version {
        Some(new_version.to_string())
    } else if let Some(rest) = inner.strip_prefix('^') {
        (rest == old_version).then(|| format!("^{new_version}"))
    } else if let Some(rest) = inner.strip_prefix('~') {
        (rest == old_version).then(|| format!("~{new_version}"))
    } else {
        None
    };

    replacement.map(|spec| format!("{workspace_prefix}{spec}"))
}

fn range_satisfies_version(range: &str, version: &str) -> bool {
    let Ok(req) = VersionReq::parse(range) else {
        return false;
    };
    let Ok(version) = Version::parse(version) else {
        return false;
    };
    req.matches(&version)
}

fn summarize_file_updates(
    packages: &[PackageRelease],
    dependency_updates: &[DependencyUpdate],
) -> Vec<FileUpdate> {
    let mut counts: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for package in packages {
        *counts.entry(package.manifest_path.clone()).or_default() += 1;
    }
    for update in dependency_updates {
        *counts.entry(update.manifest_path.clone()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(path, changes)| FileUpdate { path, changes })
        .collect()
}

fn set_top_level_string(
    json: &mut serde_json::Value,
    key: &str,
    value: &str,
) -> Result<(), LpmError> {
    let obj = json
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json must contain a JSON object".into()))?;
    obj.insert(
        key.to_string(),
        serde_json::Value::String(value.to_string()),
    );
    Ok(())
}

fn set_dependency_string(
    json: &mut serde_json::Value,
    section: &str,
    dependency: &str,
    value: &str,
) -> Result<(), LpmError> {
    let Some(deps) = json
        .as_object_mut()
        .and_then(|obj| obj.get_mut(section))
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Err(LpmError::Script(format!(
            "missing `{section}` while applying release plan"
        )));
    };
    deps.insert(
        dependency.to_string(),
        serde_json::Value::String(value.to_string()),
    );
    Ok(())
}

pub(crate) fn load_change_bumps(
    workspace_root: &Path,
) -> Result<HashMap<String, VersionBump>, LpmError> {
    let changes_dir = workspace_root.join(".lpm").join("changes");
    if !changes_dir.is_dir() {
        return Ok(HashMap::new());
    }

    let mut bumps = HashMap::new();
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&changes_dir).map_err(LpmError::Io)? {
        let entry = entry.map_err(LpmError::Io)?;
        let path = entry.path();
        if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();

    for path in paths {
        let content = std::fs::read_to_string(&path).map_err(LpmError::Io)?;
        parse_change_file(&content, &path, &mut bumps)?;
    }
    Ok(bumps)
}

fn parse_change_file(
    content: &str,
    path: &Path,
    bumps: &mut HashMap<String, VersionBump>,
) -> Result<(), LpmError> {
    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(package) = parts.next() else {
            continue;
        };
        let Some(bump_raw) = parts.next() else {
            return Err(LpmError::Script(format!(
                "{}:{} must be `<package> <bump>`",
                path.display(),
                line_idx + 1
            )));
        };
        if parts.next().is_some() {
            return Err(LpmError::Script(format!(
                "{}:{} must contain exactly two fields",
                path.display(),
                line_idx + 1
            )));
        }
        let bump = bump_raw.parse::<VersionBump>()?;
        bumps.insert(package.to_string(), bump);
    }
    Ok(())
}

pub(crate) fn sorted_selected_indices(
    graph: &lpm_task::graph::WorkspaceGraph,
    selected: &HashSet<usize>,
) -> Result<Vec<usize>, LpmError> {
    let sorted = graph
        .topological_sort()
        .map_err(|error| LpmError::Script(error.to_string()))?;
    Ok(sorted
        .into_iter()
        .filter(|idx| selected.contains(idx))
        .collect())
}

pub(crate) fn ensure_unique_selection(selected: &[usize]) -> Vec<usize> {
    let mut seen = BTreeSet::new();
    selected
        .iter()
        .copied()
        .filter(|idx| seen.insert(*idx))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_workspace::{PackageJson, Workspace, WorkspaceMember};
    use tempfile::TempDir;

    fn write_manifest(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("package.json"), body).unwrap();
    }

    fn workspace_with_app_dep(app_dep: &str) -> (TempDir, Workspace) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let core = root.join("packages/core");
        let app = root.join("packages/app");
        write_manifest(&core, r#"{"name":"core","version":"1.2.3"}"#);
        write_manifest(
            &app,
            &format!(r#"{{"name":"app","version":"2.0.0","dependencies":{{"core":"{app_dep}"}}}}"#),
        );
        let workspace = Workspace {
            root,
            root_package: PackageJson::default(),
            members: vec![
                WorkspaceMember {
                    path: core.clone(),
                    package: lpm_workspace::read_package_json(&core.join("package.json")).unwrap(),
                },
                WorkspaceMember {
                    path: app.clone(),
                    package: lpm_workspace::read_package_json(&app.join("package.json")).unwrap(),
                },
            ],
        };
        (tmp, workspace)
    }

    #[test]
    fn plan_workspace_updates_dependent_range_when_new_version_is_outside_existing_range() {
        let (_tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Major)).unwrap();

        assert_eq!(plan.dependency_updates.len(), 1);
        assert_eq!(plan.dependency_updates[0].old_spec, "^1.2.3");
        assert_eq!(plan.dependency_updates[0].new_spec, "^2.0.0");
    }

    #[test]
    fn plan_workspace_leaves_dependent_range_when_new_version_is_satisfied() {
        let (_tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Patch)).unwrap();

        assert!(plan.dependency_updates.is_empty());
    }

    #[test]
    fn plan_workspace_leaves_workspace_caret_range_when_new_version_is_satisfied() {
        let (_tmp, workspace) = workspace_with_app_dep("workspace:^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Patch)).unwrap();

        assert!(plan.dependency_updates.is_empty());
    }

    #[test]
    fn plan_workspace_rejects_unselected_dependent_with_unrewritable_range() {
        let (_tmp, workspace) = workspace_with_app_dep(">=1 <2");
        let err = plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Major))
            .unwrap_err();

        assert!(err.to_string().contains("will not accept 2.0.0"));
    }

    #[test]
    fn plan_workspace_rejects_selected_dependent_with_unrewritable_stale_range() {
        let (_tmp, workspace) = workspace_with_app_dep(">=1 <2");
        let err = plan_workspace(
            &workspace,
            &[0, 1],
            &HashMap::new(),
            Some(&VersionBump::Major),
        )
        .unwrap_err();

        assert!(err.to_string().contains("will not accept 2.0.0"));
    }
}
