use super::*;

#[cfg(test)]
pub(super) fn plan_single_package(
    project_dir: &Path,
    bump: &VersionBump,
) -> Result<ReleasePlan, LpmError> {
    let manifest_path = project_dir.join("package.json");
    let manifest = read_workspace_manifest(project_dir, manifest_path)?;
    plan_manifest(manifest, bump)
}

pub(super) fn plan_manifest(
    manifest: WorkspaceManifest,
    bump: &VersionBump,
) -> Result<ReleasePlan, LpmError> {
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

#[cfg(test)]
pub(super) fn plan_workspace(
    workspace: &lpm_workspace::Workspace,
    selected: &[usize],
    bump_by_name: &HashMap<String, VersionBump>,
    default_bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let root = open_root_directory_nofollow(&workspace.root)?;
    plan_workspace_from_open_root(workspace, &root, selected, bump_by_name, default_bump)
}

pub(crate) fn plan_workspace_from_open_root(
    workspace: &lpm_workspace::Workspace,
    root: &cap_std::fs::Dir,
    selected: &[usize],
    bump_by_name: &HashMap<String, VersionBump>,
    default_bump: Option<&VersionBump>,
) -> Result<ReleasePlan, LpmError> {
    let read = |path: &Path| {
        let manifest_path = path.join("package.json");
        let relative = planned_manifest_relative_path(&workspace.root, &manifest_path)?;
        let target = open_manifest_target(root, &workspace.root, &relative)?;
        parse_workspace_manifest(path, manifest_path, read_manifest_target(&target)?)
    };
    if selected.len() > MAX_RELEASE_JOURNAL_ENTRIES {
        return Err(LpmError::Script(format!(
            "release plan changes {} manifests, exceeding the transaction limit of {MAX_RELEASE_JOURNAL_ENTRIES}",
            selected.len()
        )));
    }
    let mut selected_manifests = BTreeMap::new();
    let mut packages = Vec::with_capacity(selected.len());
    let mut total_original_bytes = 0usize;
    for index in selected {
        let manifest = read(&workspace.members[*index].path)?;
        let Some(bump) = bump_by_name.get(&manifest.name).or(default_bump) else {
            return Err(LpmError::Script(format!(
                "no bump level provided for workspace package `{}`. Pass --bump or add .lpm/changes entries.",
                manifest.name
            )));
        };
        total_original_bytes += manifest.original_bytes.len();
        check_original_budget(total_original_bytes)?;
        packages.push(bumped_package(&manifest, bump)?);
        selected_manifests.insert(manifest.manifest_path.clone(), manifest);
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
    let mut dependency_updates = Vec::new();
    let mut source_manifests = BTreeMap::new();
    for path in workspace
        .members
        .iter()
        .map(|member| member.path.as_path())
        .chain(std::iter::once(workspace.root.as_path()))
    {
        let selected = selected_manifests.remove(&path.join("package.json"));
        let was_selected = selected.is_some();
        let manifest = match selected {
            Some(manifest) => manifest,
            None => read(path)?,
        };
        let updates = plan_dependency_updates(
            std::slice::from_ref(&manifest),
            &bumped_versions,
            &workspace.root_package.catalogs,
        )?;
        if was_selected || !updates.is_empty() {
            if source_manifests.len() >= MAX_RELEASE_JOURNAL_ENTRIES {
                return Err(LpmError::Script(format!(
                    "release plan exceeds the transaction limit of {MAX_RELEASE_JOURNAL_ENTRIES} manifests"
                )));
            }
            if !was_selected {
                total_original_bytes += manifest.original_bytes.len();
                check_original_budget(total_original_bytes)?;
            }
            source_manifests.insert(
                manifest.manifest_path,
                SourceManifest {
                    original_bytes: manifest.original_bytes,
                    json: manifest.json,
                },
            );
            dependency_updates.extend(updates);
        }
    }
    let files = summarize_file_updates(&packages, &dependency_updates);

    Ok(ReleasePlan {
        packages,
        dependency_updates,
        files,
        source_manifests,
    })
}

fn check_original_budget(bytes: usize) -> Result<(), LpmError> {
    if bytes > MAX_RELEASE_ORIGINAL_BYTES {
        return Err(LpmError::Script(format!(
            "release manifest originals exceed the {} MiB durable transaction limit",
            MAX_RELEASE_ORIGINAL_BYTES / (1024 * 1024)
        )));
    }
    Ok(())
}

pub(crate) fn validate_workspace_internal_ranges(
    workspace: &lpm_workspace::Workspace,
) -> Result<(), LpmError> {
    let versions: HashMap<&str, Option<&str>> = workspace
        .members
        .iter()
        .filter_map(|member| {
            member
                .package
                .name
                .as_deref()
                .map(|name| (name, member.package.version.as_deref()))
        })
        .collect();
    for (path, package) in std::iter::once((&workspace.root, &workspace.root_package)).chain(
        workspace
            .members
            .iter()
            .map(|member| (&member.path, &member.package)),
    ) {
        let name = package.name.as_deref().unwrap_or(".");
        let dependency_sections = [
            &package.dependencies,
            &package.dev_dependencies,
            &package.peer_dependencies,
            &package.optional_dependencies,
        ];
        for dependencies in dependency_sections {
            for (dependency, spec) in dependencies {
                let Some(version) = versions.get(dependency.as_str()) else {
                    continue;
                };
                let version = version.ok_or_else(|| LpmError::Script(format!(
                    "workspace dependency `{dependency}` of `{name}` is missing a string `version` field"
                )))?;
                Version::parse(version)?;
                let resolved =
                    resolve_release_spec(dependency, spec, &workspace.root_package.catalogs)?;
                if dynamic_workspace_spec(&resolved) {
                    continue;
                }
                let range = resolved.strip_prefix("workspace:").unwrap_or(&resolved);
                if !range_satisfies_version(range, version) {
                    return Err(LpmError::Script(format!(
                        "`{name}` depends on `{dependency}` as `{spec}` in {}, which does not accept current workspace version {version}",
                        path.join("package.json").display(),
                    )));
                }
            }
        }
    }
    Ok(())
}

fn resolve_release_spec<'a>(
    dependency: &str,
    spec: &'a str,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<std::borrow::Cow<'a, str>, LpmError> {
    if !spec.starts_with("catalog:") {
        return Ok(std::borrow::Cow::Borrowed(spec));
    }
    let mut resolved = HashMap::from([(dependency.to_string(), spec.to_string())]);
    lpm_workspace::resolve_catalog_protocol(&mut resolved, catalogs)
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
    Ok(std::borrow::Cow::Owned(
        resolved.remove(dependency).expect("catalog entry retained"),
    ))
}

#[cfg(test)]
pub(super) fn read_workspace_manifest(
    path: &Path,
    manifest_path: PathBuf,
) -> Result<WorkspaceManifest, LpmError> {
    let (original_bytes, _) = lpm_common::read_regular_file_capped_with_metadata(
        &manifest_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    parse_workspace_manifest(path, manifest_path, original_bytes)
}

pub(super) fn parse_workspace_manifest(
    path: &Path,
    manifest_path: PathBuf,
    original_bytes: Vec<u8>,
) -> Result<WorkspaceManifest, LpmError> {
    let original_bytes: Arc<[u8]> = original_bytes.into();
    let json: serde_json::Value =
        serde_json::from_slice(lpm_common::strip_utf8_bom_bytes(&original_bytes))
            .map_err(LpmError::Json)?;
    let obj = json.as_object().ok_or_else(|| {
        LpmError::Script(format!(
            "{} must contain a JSON object",
            manifest_path.display()
        ))
    })?;
    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(".")
        .to_string();

    Ok(WorkspaceManifest {
        name,
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
    for field in ["name", "version"] {
        if manifest
            .json
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(LpmError::Script(format!(
                "{} is missing a string `{field}` field",
                manifest.manifest_path.display()
            )));
        }
    }
    let old_version = manifest.json["version"]
        .as_str()
        .expect("validated version");
    let version = Version::parse(old_version)?;
    let new_version = version.bump(bump)?;
    if new_version <= version {
        return Err(LpmError::Script(format!(
            "`{}` would move from {} to {}; release versions must increase",
            manifest.name, version, new_version
        )));
    }
    let mut new_version = new_version.to_string();
    if let VersionBump::Exact(exact) = bump
        && let Some((_, build)) = exact.split_once('+')
    {
        new_version.truncate(new_version.find('+').unwrap_or(new_version.len()));
        new_version.push('+');
        new_version.push_str(build);
    }
    Ok(PackageRelease {
        name: manifest.name.clone(),
        path: manifest.path.clone(),
        manifest_path: manifest.manifest_path.clone(),
        old_version: old_version.to_string(),
        new_version,
        bump: bump.as_str().to_string(),
    })
}

pub(super) fn plan_dependency_updates(
    manifests: &[WorkspaceManifest],
    bumped_versions: &HashMap<String, (&str, &str)>,
    catalogs: &HashMap<String, HashMap<String, String>>,
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
                let resolved = resolve_release_spec(dependency, old_spec, catalogs)?;
                if dynamic_workspace_spec(&resolved) {
                    continue;
                }
                let validation_range = resolved.strip_prefix("workspace:").unwrap_or(&resolved);
                if !range_satisfies_version(validation_range, new_version) {
                    return Err(LpmError::Script(format!(
                        "`{}` depends on `{}` as `{}` in {}, which will not accept {}. Update the dependency range or its catalog entry.",
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

    let same_version =
        |candidate: &str| match (Version::parse(candidate), Version::parse(old_version)) {
            (Ok(candidate), Ok(old)) => candidate == old,
            _ => false,
        };
    let replacement = if same_version(inner) {
        Some(new_version.to_string())
    } else if let Some(rest) = inner.strip_prefix('^') {
        same_version(rest).then(|| format!("^{new_version}"))
    } else if let Some(rest) = inner.strip_prefix('~') {
        same_version(rest).then(|| format!("~{new_version}"))
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

const MAX_CHANGE_FILES: usize = 10_000;
const MAX_CHANGE_ENTRIES: usize = 100_000;
const MAX_CHANGE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn load_change_bumps(
    workspace_root: &Path,
    root: &cap_std::fs::Dir,
) -> Result<HashMap<String, VersionBump>, LpmError> {
    use cap_fs_ext::{
        DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
    };
    let lpm = root.open_dir_nofollow(".lpm").map_err(LpmError::Io)?;
    let changes = match lpm.open_dir_nofollow("changes") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "cannot open release changes directory: {error}"
            )));
        }
    };
    let mut bumps = HashMap::new();
    let mut paths = Vec::new();
    let mut path_bytes = 0usize;
    for (index, entry) in changes.entries().map_err(LpmError::Io)?.enumerate() {
        if index >= MAX_CHANGE_ENTRIES {
            return Err(change_limit_error("directory entry", MAX_CHANGE_ENTRIES));
        }
        let name = entry.map_err(LpmError::Io)?.file_name();
        let metadata = changes.symlink_metadata(&name).map_err(LpmError::Io)?;
        if crate::commands::publish_common::metadata_is_link_or_reparse(&metadata) {
            return Err(LpmError::Script(
                "release change files must not be symbolic links".into(),
            ));
        }
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            return Err(LpmError::Script(
                "release changes require regular files".into(),
            ));
        }
        path_bytes = path_bytes.saturating_add(name.as_encoded_bytes().len());
        if paths.len() >= MAX_CHANGE_FILES {
            return Err(change_limit_error("file", MAX_CHANGE_FILES));
        }
        if path_bytes > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize {
            return Err(change_limit_error(
                "filename byte",
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize,
            ));
        }
        paths.push(name);
    }
    paths.sort_unstable();
    let mut total_bytes = 0u64;
    let mut records = 0usize;
    for name in paths {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = changes.open_with(&name, &options).map_err(LpmError::Io)?;
        let metadata = file.metadata().map_err(LpmError::Io)?;
        if !metadata.is_file()
            || crate::commands::publish_common::metadata_is_link_or_reparse(&metadata)
        {
            return Err(LpmError::Script(
                "release changes require regular files".into(),
            ));
        }
        let cap = lpm_common::CONFIG_FILE_SIZE_CAP_BYTES.min(MAX_CHANGE_BYTES - total_bytes);
        let path = workspace_root.join(".lpm/changes").join(name);
        let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
            file.into_std(),
            &path,
            cap,
            metadata.len(),
        )
        .map_err(|error| {
            LpmError::Script(format!(
                "release changes exceed a file or aggregate byte limit: {error}"
            ))
        })?;
        total_bytes += content.len() as u64;
        parse_change_file(&content, &path, &mut bumps, &mut records)?;
    }
    Ok(bumps)
}

fn change_limit_error(kind: &str, limit: usize) -> LpmError {
    LpmError::Script(format!(
        "release changes exceed the {kind} limit of {limit}"
    ))
}

pub(super) fn parse_change_file(
    content: &str,
    path: &Path,
    bumps: &mut HashMap<String, VersionBump>,
    records: &mut usize,
) -> Result<(), LpmError> {
    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        *records += 1;
        if *records > MAX_CHANGE_ENTRIES {
            return Err(change_limit_error("record", MAX_CHANGE_ENTRIES));
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
        if let Some(existing) = bumps.get(package) {
            if existing != &bump {
                return Err(LpmError::Script(format!(
                    "{}:{} conflicts with another change entry for `{package}`: {} versus {}",
                    path.display(),
                    line_idx + 1,
                    existing.as_str(),
                    bump.as_str()
                )));
            }
        } else {
            bumps.insert(package.to_string(), bump);
        }
    }
    Ok(())
}

pub(crate) fn sorted_selected_indices(
    graph: &lpm_task::graph::WorkspaceGraph,
    selected: &HashSet<usize>,
) -> Result<Vec<usize>, LpmError> {
    let mut unmet = vec![0usize; graph.len()];
    let mut queue = std::collections::VecDeque::with_capacity(selected.len());
    for (index, count) in unmet.iter_mut().enumerate() {
        if selected.contains(&index) {
            *count = graph.edges[index]
                .iter()
                .filter(|dependency| selected.contains(dependency))
                .count();
            if *count == 0 {
                queue.push_back(index);
            }
        }
    }
    let mut sorted = Vec::with_capacity(selected.len());
    while let Some(index) = queue.pop_front() {
        sorted.push(index);
        for dependent in &graph.reverse_edges[index] {
            if selected.contains(dependent) {
                unmet[*dependent] -= 1;
                if unmet[*dependent] == 0 {
                    queue.push_back(*dependent);
                }
            }
        }
    }
    if sorted.len() != selected.len() {
        let names: Vec<&str> = unmet
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(index, _)| graph.members[index].name.as_str())
            .collect();
        return Err(LpmError::Script(format!(
            "dependency cycle detected in selected workspace packages: {}",
            names.join(", ")
        )));
    }
    Ok(sorted)
}

pub(crate) fn ensure_unique_selection(selected: &[usize]) -> Vec<usize> {
    let mut seen = BTreeSet::new();
    selected
        .iter()
        .copied()
        .filter(|idx| seen.insert(*idx))
        .collect()
}
