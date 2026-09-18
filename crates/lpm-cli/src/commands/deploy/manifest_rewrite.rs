use lpm_common::LpmError;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::copy::{CopyStats, copy_member_source};
use super::file_select::normalize_relative_path;
use super::{DEPLOY_WORKSPACE_DIR, DependencyMode, ManifestSelectionStats};

/// The dependency sections in `package.json` that may contain `workspace:*`
/// references. Iterated by deploy manifest rewrite helpers to make the deploy
/// output self-contained.
const REWRITE_DEP_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

#[cfg(test)]
/// Rewrite `workspace:*` references in the deploy output's `package.json`
/// to concrete versions, using the **source workspace** as the version
/// source. The deploy output dir has no parent workspace, so without this
/// rewrite the install pipeline at the output dir would fail to resolve
/// `workspace:*` deps.
///
/// Iterates `dependencies`, `devDependencies`, `peerDependencies`, and
/// `optionalDependencies`. Even though LPM's install pipeline only resolves
/// `dependencies` (covered by deploy tests), the deploy
/// output should be a clean, lookup-able package.json — so we rewrite all
/// four sections defensively.
///
/// **Read-only on the source side**: this function never modifies any file
/// outside `output_dir`. The source workspace manifests are untouched.
///
/// Returns the total number of `workspace:*` references rewritten across
/// all sections.
pub(in crate::commands::deploy) fn rewrite_workspace_protocol_in_deploy_manifest(
    output_dir: &Path,
    source_cwd: &Path,
) -> Result<usize, LpmError> {
    // Discover the source workspace from the original cwd. The deploy
    // output dir is intentionally outside the workspace tree (enforced
    // at target resolution), so we can't discover from there.
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;

    let manifest_path = output_dir.join("package.json");
    let content =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
            LpmError::Script(format!(
                "failed to read deploy manifest at {manifest_path:?}: {e}"
            ))
        })?;

    let mut doc: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let mut total_rewritten = 0;

    for section in REWRITE_DEP_SECTIONS {
        let Some(section_obj) = doc.get_mut(*section).and_then(|v| v.as_object_mut()) else {
            continue;
        };

        // Snapshot the section as a HashMap for the resolver. The resolver
        // mutates the HashMap in place; we then write the rewritten values
        // back into the original Map preserving key order.
        let mut temp_deps: HashMap<String, String> = section_obj
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();

        let resolved = lpm_workspace::resolve_workspace_protocol(&mut temp_deps, &workspace)
            .map_err(|e| LpmError::Script(format!("deploy: workspace protocol error: {e}")))?;

        // Apply each rewrite back into the section_obj, preserving the
        // original key order.
        for (name, _original_protocol, _resolved_version) in &resolved {
            if let Some(new_value) = temp_deps.get(name) {
                section_obj.insert(name.clone(), serde_json::Value::String(new_value.clone()));
            }
        }

        total_rewritten += resolved.len();
    }

    // Only write the manifest back if at least one rewrite happened.
    // Otherwise leave the source-copied bytes as-is (preserves any quirks
    // in the source formatting).
    //
    // CRITICAL: `copy_member_source` uses hardlinks for performance. A
    // naive `std::fs::write` here would write THROUGH the hardlink and
    // mutate the source workspace's `package.json`. To preserve the
    // read-only-on-source invariant, we must `remove_file` first to
    // unlink the path from the shared inode, then write a fresh file.
    // This guarantees the source manifest is byte-identical even if the
    // file copy used a hardlink fast path.
    if total_rewritten > 0 {
        let updated = serde_json::to_string_pretty(&doc)
            .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;
        // Break any potential hardlink by unlinking the path first.
        // remove_file is idempotent for our purposes — if it doesn't exist
        // (it should), we still create it below.
        let _ = std::fs::remove_file(&manifest_path);
        std::fs::write(&manifest_path, format!("{updated}\n"))
            .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;
    }

    Ok(total_rewritten)
}

#[cfg(test)]
/// Strip `devDependencies` from the deploy output's `package.json`.
///
/// Deploy produces a **production closure**. After `lpm install`
/// resolves both `dependencies` and `devDependencies` (matching pnpm / npm
/// semantics), so if we left `devDependencies` in the copied manifest the
/// install pipeline inside the output dir would drag dev-only packages
/// (vitest, tsup, eslint, etc.) into the deploy closure. That would bloat
/// Docker images and re-open the class of bugs this command exists to
/// prevent.
///
/// The function is a no-op when the section is absent, a no-op when the
/// section exists but is empty, and otherwise removes the key entirely.
/// Returns the number of devDependency entries that were stripped so the
/// caller can surface it in the deploy summary.
///
/// **Hardlink safety.** [`copy_member_source`] uses `hard_link` as a
/// performance fast path, so the output's `package.json` can share an
/// inode with the source workspace's `package.json`. A naive `write`
/// would mutate the source. We use the same `remove_file` + fresh
/// `write` dance as [`rewrite_workspace_protocol_in_deploy_manifest`]
/// to break the potential hardlink.
pub(in crate::commands::deploy) fn strip_dev_dependencies_from_deploy_manifest(
    output_dir: &Path,
) -> Result<usize, LpmError> {
    let manifest_path = output_dir.join("package.json");
    let content =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
            LpmError::Script(format!(
                "failed to read deploy manifest at {manifest_path:?}: {e}"
            ))
        })?;

    let mut doc: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let stripped_count = doc
        .get("devDependencies")
        .and_then(|v| v.as_object())
        .map_or(0, |o| o.len());

    if stripped_count == 0 {
        // Key missing or empty object: nothing to do, nothing to write.
        // Leaving the (possibly hardlinked) bytes alone preserves source
        // formatting and avoids an unnecessary write.
        return Ok(0);
    }

    if let Some(obj) = doc.as_object_mut() {
        obj.remove("devDependencies");
    }

    let updated = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;

    // Break any potential hardlink to the source manifest, then write a
    // fresh inode at the path. See the hardlink-safety rationale above.
    let _ = std::fs::remove_file(&manifest_path);
    std::fs::write(&manifest_path, format!("{updated}\n"))
        .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;

    Ok(stripped_count)
}

pub(in crate::commands::deploy) fn read_manifest_value(
    manifest_path: &Path,
) -> Result<serde_json::Value, LpmError> {
    let content =
        lpm_common::read_text_file_capped(manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|e| {
                LpmError::Script(format!(
                    "deploy: failed to read manifest at {manifest_path:?}: {e}"
                ))
            })?;
    serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))
}

fn write_manifest_value(manifest_path: &Path, doc: &serde_json::Value) -> Result<(), LpmError> {
    let updated = serde_json::to_string_pretty(doc)
        .map_err(|e| LpmError::Script(format!("deploy: failed to serialize manifest: {e}")))?;
    let _ = std::fs::remove_file(manifest_path);
    std::fs::write(manifest_path, format!("{updated}\n"))
        .map_err(|e| LpmError::Script(format!("deploy: failed to write manifest: {e}")))
}

fn section_len(doc: &serde_json::Value, section: &str) -> usize {
    doc.get(section)
        .and_then(|value| value.as_object())
        .map_or(0, |object| object.len())
}

fn remove_manifest_section(doc: &mut serde_json::Value, section: &str) -> usize {
    let count = section_len(doc, section);
    if count > 0
        && let Some(object) = doc.as_object_mut()
    {
        object.remove(section);
    }
    count
}

pub(in crate::commands::deploy) fn apply_dependency_selection_to_manifest_path(
    manifest_path: &Path,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<ManifestSelectionStats, LpmError> {
    let mut doc = read_manifest_value(manifest_path)?;
    let mut stats = ManifestSelectionStats::default();

    let optional_names: Vec<String> = doc
        .get("optionalDependencies")
        .and_then(|value| value.as_object())
        .map(|deps| deps.keys().cloned().collect())
        .unwrap_or_default();
    for (section, count) in [
        ("dependencies", &mut stats.production_dependencies_stripped),
        ("devDependencies", &mut stats.dev_dependencies_stripped),
    ] {
        if let Some(deps) = doc.get_mut(section).and_then(|value| value.as_object_mut()) {
            for name in &optional_names {
                *count += usize::from(deps.remove(name).is_some());
            }
        }
    }

    match mode {
        DependencyMode::Production => {
            stats.dev_dependencies_stripped += remove_manifest_section(&mut doc, "devDependencies");
        }
        DependencyMode::Development => {
            stats.production_dependencies_stripped +=
                remove_manifest_section(&mut doc, "dependencies");
            stats.optional_dependencies_stripped =
                remove_manifest_section(&mut doc, "optionalDependencies");
        }
    }

    if no_optional && matches!(mode, DependencyMode::Production) {
        stats.optional_dependencies_stripped =
            remove_manifest_section(&mut doc, "optionalDependencies");
    }

    if let Some(name) = doc
        .get("name")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
    {
        for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
            if let Some(spec) = doc
                .get(section)
                .and_then(|deps| deps.get(&name))
                .and_then(|value| value.as_str())
                && spec.starts_with("workspace:")
            {
                return Err(LpmError::Workspace(format!(
                    "workspace member `{name}` depends on itself via {section}.{name} = `{spec}`"
                )));
            }
        }
        if let Some(deps) = doc
            .get_mut("devDependencies")
            .and_then(|value| value.as_object_mut())
            && deps
                .get(&name)
                .and_then(|value| value.as_str())
                .is_some_and(|spec| spec.starts_with("workspace:"))
        {
            deps.remove(&name);
            stats.dev_dependencies_stripped += 1;
        }
    }

    if stats.dev_dependencies_stripped > 0
        || stats.production_dependencies_stripped > 0
        || stats.optional_dependencies_stripped > 0
    {
        write_manifest_value(manifest_path, &doc)?;
    }

    Ok(stats)
}

pub(in crate::commands::deploy) fn apply_dependency_selection_to_deploy_manifest(
    output_dir: &Path,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<ManifestSelectionStats, LpmError> {
    apply_dependency_selection_to_manifest_path(&output_dir.join("package.json"), mode, no_optional)
}

fn workspace_dependencies_for_package(
    pkg: &lpm_workspace::PackageJson,
    mode: DependencyMode,
    no_optional: bool,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<Vec<(String, String)>, LpmError> {
    let mut dependencies = match mode {
        DependencyMode::Production => pkg.dependencies.clone(),
        DependencyMode::Development => pkg
            .dev_dependencies
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != pkg.name.as_deref())
            .map(|(name, spec)| (name.clone(), spec.clone()))
            .collect(),
    };
    for (name, spec) in &pkg.optional_dependencies {
        if !no_optional && matches!(mode, DependencyMode::Production) {
            dependencies.insert(name.clone(), spec.clone());
        } else {
            dependencies.remove(name);
        }
    }
    // Peers can require sources outside the selected installation roots.
    // Resolve each section separately so an ordinary dependency does not hide
    // a workspace peer declaration under the same name.
    lpm_workspace::resolve_catalog_protocol(&mut dependencies, catalogs)
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
    let mut peers = pkg.peer_dependencies.clone();
    lpm_workspace::resolve_catalog_protocol(&mut peers, catalogs)
        .map_err(|error| LpmError::Workspace(error.to_string()))?;
    Ok(dependencies
        .into_iter()
        .chain(peers)
        .filter(|(_, spec)| spec.starts_with("workspace:"))
        .collect())
}

pub(in crate::commands::deploy) fn copy_workspace_dependency_closure(
    output_dir: &Path,
    source_cwd: &Path,
    root_member_name: &str,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<(usize, usize, CopyStats, ManifestSelectionStats), LpmError> {
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;

    let mut members_by_name: HashMap<&str, (&lpm_workspace::PackageJson, &Path)> = workspace
        .members
        .iter()
        .filter_map(|member| {
            Some((
                member.package.name.as_deref()?,
                (&member.package, member.path.as_path()),
            ))
        })
        .collect();
    if let Some(name) = workspace.root_package.name.as_deref() {
        members_by_name.insert(name, (&workspace.root_package, workspace.root.as_path()));
    }

    let mut queue = VecDeque::from([(root_member_name, mode)]);
    let mut visited = HashSet::new();
    while let Some((name, selection)) = queue.pop_front() {
        if !visited.insert(name) {
            continue;
        }
        let (package, _) = members_by_name.get(name).ok_or_else(|| {
            LpmError::Script(format!("deploy: workspace provider {name:?} was not found"))
        })?;
        for (dependency, spec) in workspace_dependencies_for_package(
            package,
            selection,
            no_optional,
            &workspace.root_package.catalogs,
        )? {
            let (provider, _) = members_by_name.get(dependency.as_str()).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: {name:?} requires missing workspace provider {dependency:?}"
                ))
            })?;
            lpm_workspace::validate_workspace_protocol_version(
                &dependency,
                &spec,
                provider.version.as_deref().unwrap_or("0.0.0"),
            )
            .map_err(|error| LpmError::Script(format!("deploy: {error}")))?;
            if !visited.contains(dependency.as_str()) {
                let provider_name = provider
                    .name
                    .as_deref()
                    .ok_or_else(|| LpmError::Workspace("workspace provider has no name".into()))?;
                queue.push_back((provider_name, DependencyMode::Production));
            }
        }
    }
    visited.remove(root_member_name);
    let mut selected_names: Vec<&str> = visited.into_iter().collect();
    selected_names.sort_unstable();
    let mut destination_by_name = HashMap::with_capacity(selected_names.len() + 1);
    destination_by_name.insert(root_member_name.to_string(), output_dir.to_path_buf());
    // Sibling destinations prevent a nested provider copy from overwriting an
    // earlier hardlink to the source workspace.
    for (index, name) in selected_names.iter().enumerate() {
        destination_by_name.insert(
            (*name).to_string(),
            output_dir
                .join(DEPLOY_WORKSPACE_DIR)
                .join(format!("provider-{index:06}")),
        );
    }

    let mut copy_stats = CopyStats::default();
    let mut selection_stats = ManifestSelectionStats::default();
    let mut workspace_spec_rewrites = 0;
    for name in &selected_names {
        let (_, source_dir) = members_by_name.get(name).ok_or_else(|| {
            LpmError::Script(format!("deploy: workspace provider {name:?} disappeared"))
        })?;
        let destination = destination_by_name
            .get(*name)
            .ok_or_else(|| LpmError::Script(format!("deploy: missing destination for {name:?}")))?;
        let stats = copy_member_source(source_dir, destination)?;
        copy_stats.files_copied += stats.files_copied;
        copy_stats.files_skipped += stats.files_skipped;
        copy_stats.bytes_copied += stats.bytes_copied;

        let manifest_path = destination.join("package.json");
        let member_selection = apply_dependency_selection_to_manifest_path(
            &manifest_path,
            DependencyMode::Production,
            no_optional,
        )?;
        selection_stats.add(&member_selection);
        workspace_spec_rewrites += rewrite_workspace_specs_to_file_paths(
            &manifest_path,
            &destination_by_name,
            &workspace.root_package.catalogs,
        )?;
    }

    workspace_spec_rewrites += rewrite_workspace_specs_to_file_paths(
        &output_dir.join("package.json"),
        &destination_by_name,
        &workspace.root_package.catalogs,
    )?;

    Ok((
        selected_names.len(),
        workspace_spec_rewrites,
        copy_stats,
        selection_stats,
    ))
}

fn rewrite_workspace_specs_to_file_paths(
    manifest_path: &Path,
    destination_by_name: &HashMap<String, PathBuf>,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<usize, LpmError> {
    let mut doc = read_manifest_value(manifest_path)?;
    let manifest_dir = manifest_path.parent().ok_or_else(|| {
        LpmError::Script(format!(
            "deploy: manifest path {manifest_path:?} has no parent directory"
        ))
    })?;
    let mut rewritten = 0;
    let mut catalogs_resolved = false;

    for section in REWRITE_DEP_SECTIONS {
        let Some(section_obj) = doc
            .get_mut(*section)
            .and_then(|value| value.as_object_mut())
        else {
            continue;
        };
        let mut catalog_deps: HashMap<String, String> = section_obj
            .iter()
            .filter_map(|(name, value)| {
                value
                    .as_str()
                    .filter(|spec| spec.starts_with("catalog:"))
                    .map(|spec| (name.clone(), spec.to_string()))
            })
            .collect();
        lpm_workspace::resolve_catalog_protocol(&mut catalog_deps, catalogs)
            .map_err(|error| LpmError::Workspace(error.to_string()))?;
        catalogs_resolved |= !catalog_deps.is_empty();
        for (name, spec) in catalog_deps {
            section_obj.insert(name, serde_json::Value::String(spec));
        }
        let keys: Vec<String> = section_obj.keys().cloned().collect();
        for name in keys {
            let Some(raw_spec) = section_obj.get(&name).and_then(|value| value.as_str()) else {
                continue;
            };
            if !raw_spec.starts_with("workspace:") {
                continue;
            }
            let Some(destination) = destination_by_name.get(&name) else {
                continue;
            };
            let relative = pathdiff::diff_paths(destination, manifest_dir).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: failed to compute relative file path from {manifest_dir:?} to {destination:?}"
                ))
            })?;
            let relative = normalize_relative_path(&relative);
            let relative = if relative.is_empty() { "." } else { &relative };
            section_obj.insert(name, serde_json::Value::String(format!("file:{relative}")));
            rewritten += 1;
        }
    }

    if rewritten > 0 || catalogs_resolved {
        write_manifest_value(manifest_path, &doc)?;
    }

    Ok(rewritten)
}
