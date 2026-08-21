use super::*;

pub(crate) fn plan_single_package(
    project_dir: &Path,
    bump: &VersionBump,
) -> Result<ReleasePlan, LpmError> {
    let manifest_path = project_dir.join("package.json");
    let manifest = read_workspace_manifest(project_dir, manifest_path)?;
    let package = bumped_package(&manifest, bump)?;
    let source_manifests = BTreeMap::from([(
        manifest.manifest_path.clone(),
        SourceManifest {
            original_bytes: manifest.original_bytes,
            json: manifest.json,
        },
    )]);
    Ok(ReleasePlan {
        files: vec![FileUpdate {
            path: package.manifest_path.clone(),
            changes: 1,
        }],
        packages: vec![package],
        dependency_updates: Vec::new(),
        source_manifests,
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
    for (idx, manifest) in manifests.iter().enumerate() {
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
    let changed_paths = files
        .iter()
        .map(|file| file.path.as_path())
        .collect::<BTreeSet<_>>();
    let source_manifests = manifests
        .into_iter()
        .filter(|manifest| changed_paths.contains(manifest.manifest_path.as_path()))
        .map(|manifest| {
            (
                manifest.manifest_path,
                SourceManifest {
                    original_bytes: manifest.original_bytes,
                    json: manifest.json,
                },
            )
        })
        .collect();

    Ok(ReleasePlan {
        packages,
        dependency_updates,
        files,
        source_manifests,
    })
}

pub(crate) fn validate_workspace_internal_ranges(
    workspace: &lpm_workspace::Workspace,
) -> Result<(), LpmError> {
    let mut versions = HashMap::with_capacity(workspace.members.len());
    for member in &workspace.members {
        let manifest_path = member.path.join("package.json");
        let name = member.package.name.as_deref().ok_or_else(|| {
            LpmError::Script(format!(
                "{} is missing a string `name` field",
                manifest_path.display()
            ))
        })?;
        let version = member
            .package
            .version
            .as_deref()
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "{} is missing a string `version` field",
                    manifest_path.display()
                ))
            })
            .and_then(Version::parse)?;
        versions.insert(name, version.to_string());
    }

    for member in &workspace.members {
        let manifest_path = member.path.join("package.json");
        let name = member.package.name.as_deref().ok_or_else(|| {
            LpmError::Script(format!(
                "{} is missing a string `name` field",
                manifest_path.display()
            ))
        })?;
        let dependency_sections = [
            &member.package.dependencies,
            &member.package.dev_dependencies,
            &member.package.peer_dependencies,
            &member.package.optional_dependencies,
        ];
        for dependencies in dependency_sections {
            for (dependency, spec) in dependencies {
                let Some(version) = versions.get(dependency.as_str()) else {
                    continue;
                };
                if dynamic_workspace_spec(spec) || spec.starts_with("catalog:") {
                    continue;
                }
                let range = spec.strip_prefix("workspace:").unwrap_or(spec);
                if !range_satisfies_version(range, version) {
                    return Err(LpmError::Script(format!(
                        "`{}` depends on `{}` as `{}` in {}, which does not accept current workspace version {}",
                        name,
                        dependency,
                        spec,
                        manifest_path.display(),
                        version
                    )));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn read_workspace_manifest(
    path: &Path,
    manifest_path: PathBuf,
) -> Result<WorkspaceManifest, LpmError> {
    let original_bytes: Arc<[u8]> =
        lpm_common::read_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?
            .into();
    let json: serde_json::Value =
        serde_json::from_slice(&original_bytes).map_err(LpmError::Json)?;
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
        original_bytes,
        json,
    })
}

pub(super) fn bumped_package(
    manifest: &WorkspaceManifest,
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
        name: manifest.name.clone(),
        path: manifest.path.clone(),
        manifest_path: manifest.manifest_path.clone(),
        old_version: manifest.version.to_string(),
        new_version: new_version.to_string(),
        bump: bump.as_str().to_string(),
    })
}

pub(super) fn plan_dependency_updates(
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

pub(super) fn dynamic_workspace_spec(spec: &str) -> bool {
    matches!(spec.strip_prefix("workspace:"), Some("*" | "^" | "~"))
}

pub(super) fn updated_dependency_spec(
    old_spec: &str,
    old_version: &str,
    new_version: &str,
) -> Option<String> {
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

pub(super) fn range_satisfies_version(range: &str, version: &str) -> bool {
    let Ok(req) = VersionReq::parse(range) else {
        return false;
    };
    let Ok(version) = Version::parse(version) else {
        return false;
    };
    req.matches(&version)
}

pub(super) fn summarize_file_updates(
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

pub(super) fn replace_top_level_string(
    json: &mut serde_json::Value,
    key: &str,
    expected: &str,
    value: &str,
) -> Result<(), LpmError> {
    let obj = json
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json must contain a JSON object".into()))?;
    let actual = obj.get(key).and_then(serde_json::Value::as_str);
    if actual != Some(expected) {
        return Err(LpmError::Script(format!(
            "release plan expected `{key}` to be `{expected}`"
        )));
    }
    obj.insert(
        key.to_string(),
        serde_json::Value::String(value.to_string()),
    );
    Ok(())
}

pub(super) fn replace_dependency_string(
    json: &mut serde_json::Value,
    section: &str,
    dependency: &str,
    expected: &str,
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
    let actual = deps.get(dependency).and_then(serde_json::Value::as_str);
    if actual != Some(expected) {
        return Err(LpmError::Script(format!(
            "release plan expected `{dependency}` in `{section}` to be `{expected}`"
        )));
    }
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
        let content =
            lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
        parse_change_file(&content, &path, &mut bumps)?;
    }
    Ok(bumps)
}

pub(super) fn parse_change_file(
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
