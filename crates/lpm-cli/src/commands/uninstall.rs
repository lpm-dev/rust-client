use super::uninstall_ui;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, PartialEq, Eq)]
struct UninstallResult {
    removed: Vec<String>,
    not_found: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct CleanupReport {
    orphaned: Vec<PackageVersion>,
    cleaned_empty_dirs: usize,
    freed_bytes: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct PackageVersion {
    name: String,
    version: String,
}

fn remove_from_manifest(doc: &mut Value, packages: &[String]) -> UninstallResult {
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

pub(crate) fn cleanup_removed_packages(
    project_dir: &Path,
    removed: &[String],
    direct_versions: &HashMap<String, String>,
) -> Result<CleanupReport, LpmError> {
    let pruned = prune_lockfile_to_current_manifest(project_dir)?;
    let orphaned: Vec<PackageVersion> = pruned
        .removed_packages
        .into_iter()
        .filter(|package| {
            direct_versions
                .get(&package.name)
                .is_none_or(|version| version != &package.version)
        })
        .collect();

    invalidate_install_hash_marker(project_dir)?;

    let node_modules = project_dir.join("node_modules");
    let mut freed_bytes = 0u64;
    for name in removed {
        if name.starts_with("@lpm.dev/") {
            freed_bytes = freed_bytes
                .saturating_add(crate::commands::skills::package::remove(project_dir, name)?);
            if let Ok(package) = lpm_common::PackageName::parse(name) {
                crate::editor_skills::remove_editor_skills(project_dir, &package.short());
            }
        }
        freed_bytes =
            freed_bytes.saturating_add(cleanup_bin_shims_for_package(&node_modules, name)?);
        freed_bytes = freed_bytes.saturating_add(remove_node_modules_entry(&node_modules, name)?);
    }
    for package in &orphaned {
        freed_bytes = freed_bytes
            .saturating_add(cleanup_bin_shims_for_package(&node_modules, &package.name)?);
        freed_bytes =
            freed_bytes.saturating_add(remove_node_modules_entry(&node_modules, &package.name)?);
    }

    let cleaned_empty_dirs = cleanup_empty_scope_dirs(&node_modules, removed, &orphaned)?;

    Ok(CleanupReport {
        orphaned,
        cleaned_empty_dirs,
        freed_bytes,
    })
}

fn invalidate_install_hash_marker(project_dir: &Path) -> Result<(), LpmError> {
    let path = project_dir.join(".lpm").join("install-hash");
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(&path)?;
        return Ok(());
    }

    #[cfg(unix)]
    std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path))?;
    #[cfg(windows)]
    std::fs::remove_dir(&path).or_else(|_| std::fs::remove_file(&path))?;

    Ok(())
}

fn cleanup_bin_shims_for_package(node_modules: &Path, name: &str) -> Result<u64, LpmError> {
    let package_dir = node_modules.join(name);
    let manifest_path = package_dir.join("package.json");
    let Ok(pkg_json) = lpm_workspace::read_package_json(&manifest_path) else {
        return Ok(0);
    };
    let Some(bin_config) = pkg_json.bin.as_ref() else {
        return Ok(0);
    };

    let package_name = pkg_json.name.as_deref().unwrap_or(name);
    let bin_dir = node_modules.join(".bin");
    let mut freed_bytes = 0u64;
    for (cmd_name, script_path) in bin_config.entries(package_name) {
        let Some(shim_path) = safe_bin_shim_path(&bin_dir, &cmd_name) else {
            continue;
        };
        let expected_target = package_dir.join(script_path);
        freed_bytes =
            freed_bytes.saturating_add(remove_owned_bin_shim(&shim_path, &expected_target)?);

        #[cfg(windows)]
        {
            let cmd_path = shim_path.with_extension("cmd");
            freed_bytes =
                freed_bytes.saturating_add(remove_owned_cmd_shim(&cmd_path, &expected_target)?);
        }
    }

    Ok(freed_bytes)
}

fn safe_bin_shim_path(bin_dir: &Path, cmd_name: &str) -> Option<PathBuf> {
    if cmd_name.is_empty()
        || cmd_name == "."
        || cmd_name == ".."
        || cmd_name.contains('/')
        || cmd_name.contains('\\')
    {
        return None;
    }
    Some(bin_dir.join(cmd_name))
}

fn remove_owned_bin_shim(shim_path: &Path, expected_target: &Path) -> Result<u64, LpmError> {
    let Ok(metadata) = shim_path.symlink_metadata() else {
        return Ok(0);
    };
    if !metadata.file_type().is_symlink() {
        return Ok(0);
    }

    let Ok(actual_target) = std::fs::read_link(shim_path) else {
        return Ok(0);
    };
    let actual_abs = if actual_target.is_absolute() {
        actual_target
    } else {
        shim_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(actual_target)
    };
    let Ok(actual_canonical) = actual_abs.canonicalize() else {
        return Ok(0);
    };
    let Ok(expected_canonical) = expected_target.canonicalize() else {
        return Ok(0);
    };
    if actual_canonical != expected_canonical {
        return Ok(0);
    }

    let freed_bytes = removable_path_size(shim_path, &metadata);
    std::fs::remove_file(shim_path)?;
    Ok(freed_bytes)
}

#[cfg(windows)]
fn remove_owned_cmd_shim(shim_path: &Path, expected_target: &Path) -> Result<u64, LpmError> {
    let Ok(metadata) = shim_path.symlink_metadata() else {
        return Ok(0);
    };
    if !metadata.is_file() {
        return Ok(0);
    }
    let Ok(expected_canonical) = expected_target.canonicalize() else {
        return Ok(0);
    };
    let Ok(content) = std::fs::read_to_string(shim_path) else {
        return Ok(0);
    };
    if !content.contains(&expected_canonical.to_string_lossy().replace('/', "\\")) {
        return Ok(0);
    }
    let freed_bytes = removable_path_size(shim_path, &metadata);
    std::fs::remove_file(shim_path)?;
    Ok(freed_bytes)
}

fn remove_node_modules_entry(node_modules: &Path, name: &str) -> Result<u64, LpmError> {
    let link = node_modules.join(name);
    let Ok(metadata) = link.symlink_metadata() else {
        return Ok(0);
    };
    let freed_bytes = removable_path_size(&link, &metadata);

    if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        std::fs::remove_file(&link).or_else(|_| std::fs::remove_dir(&link))?;
        #[cfg(windows)]
        std::fs::remove_dir(&link).or_else(|_| std::fs::remove_file(&link))?;
        return Ok(freed_bytes);
    }

    if metadata.is_dir() {
        std::fs::remove_dir_all(&link)?;
        return Ok(freed_bytes);
    }

    if metadata.is_file() {
        std::fs::remove_file(&link)?;
    }

    Ok(freed_bytes)
}

fn removable_path_size(path: &Path, metadata: &std::fs::Metadata) -> u64 {
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return metadata.len();
    }
    if metadata.is_dir() {
        return crate::commands::cache::dir_size(path).unwrap_or(0);
    }
    0
}

fn cleanup_empty_scope_dirs(
    node_modules: &Path,
    removed: &[String],
    orphaned: &[PackageVersion],
) -> Result<usize, LpmError> {
    let mut scopes: Vec<&str> = removed
        .iter()
        .filter_map(|name| npm_scope_name(name))
        .chain(
            orphaned
                .iter()
                .filter_map(|package| npm_scope_name(&package.name)),
        )
        .collect();
    scopes.sort_unstable();
    scopes.dedup();

    let mut cleaned = 0usize;
    for scope in scopes {
        let scope_dir = node_modules.join(scope);
        let Ok(mut entries) = std::fs::read_dir(&scope_dir) else {
            continue;
        };
        if entries.next().is_none() {
            std::fs::remove_dir(&scope_dir)?;
            cleaned += 1;
        }
    }

    Ok(cleaned)
}

fn npm_scope_name(name: &str) -> Option<&str> {
    if !name.starts_with('@') {
        return None;
    }
    name.split_once('/').map(|(scope, _)| scope)
}

fn collect_manifest_dependency_specs(doc: &Value) -> HashMap<String, String> {
    let mut specs = HashMap::new();

    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(obj) = doc.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in obj {
            if let Some(spec) = spec.as_str() {
                specs.insert(name.clone(), spec.to_string());
            }
        }
    }

    specs
}

fn requested_range_for_locked_lookup(requested_spec: &str) -> Option<String> {
    match lpm_resolver::Specifier::parse(requested_spec).ok()? {
        lpm_resolver::Specifier::SemverRange(range) => Some(range),
        lpm_resolver::Specifier::NpmAlias { range, .. } => Some(range),
        _ => None,
    }
}

fn select_locked_package_for_requested_spec<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    target: &str,
    requested_spec: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    let requested_range = requested_range_for_locked_lookup(requested_spec)
        .and_then(|range| lpm_resolver::NpmRange::parse(&range).ok());
    let mut first_match: Option<&lpm_lockfile::LockedPackage> = None;
    let mut best_satisfying: Option<(lpm_resolver::NpmVersion, &lpm_lockfile::LockedPackage)> =
        None;
    let mut best_any: Option<(lpm_resolver::NpmVersion, &lpm_lockfile::LockedPackage)> = None;

    for candidate in lockfile.packages.iter().filter(|pkg| pkg.name == target) {
        if first_match.is_none() {
            first_match = Some(candidate);
        }

        let Ok(version) = lpm_resolver::NpmVersion::parse(&candidate.version) else {
            continue;
        };

        let better_any = best_any.as_ref().is_none_or(|(best, _)| version > *best);
        if better_any {
            best_any = Some((version.clone(), candidate));
        }

        if let Some(range) = requested_range.as_ref()
            && range.satisfies(&version)
        {
            let better_satisfying = best_satisfying
                .as_ref()
                .is_none_or(|(best, _)| version > *best);
            if better_satisfying {
                best_satisfying = Some((version, candidate));
            }
        }
    }

    best_satisfying
        .map(|(_, candidate)| candidate)
        .or_else(|| best_any.map(|(_, candidate)| candidate))
        .or(first_match)
}

fn split_locked_dependency(entry: &str) -> Option<(&str, &str)> {
    let at = entry.rfind('@')?;
    (at > 0).then(|| (&entry[..at], &entry[at + 1..]))
}

fn locked_package_versions(project_dir: &Path, packages: &[String]) -> HashMap<String, String> {
    let mut versions = HashMap::with_capacity(packages.len());
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if let Ok(lockfile) = lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
        let package_names: HashSet<&str> = packages.iter().map(String::as_str).collect();
        for pkg in &lockfile.packages {
            if package_names.contains(pkg.name.as_str()) {
                versions.insert(pkg.name.clone(), pkg.version.clone());
            }
        }
    }

    for name in packages {
        if versions.contains_key(name) {
            continue;
        }
        if let Some(version) = node_modules_package_version(project_dir, name) {
            versions.insert(name.clone(), version);
        }
    }

    versions
}

fn node_modules_package_version(project_dir: &Path, package: &str) -> Option<String> {
    let manifest_path = project_dir
        .join("node_modules")
        .join(package)
        .join("package.json");
    let content = std::fs::read_to_string(manifest_path).ok()?;
    let manifest: Value = serde_json::from_str(&content).ok()?;
    manifest
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[derive(Debug, Default)]
struct LockfilePruneReport {
    removed_packages: Vec<PackageVersion>,
}

fn prune_lockfile_to_current_manifest(project_dir: &Path) -> Result<LockfilePruneReport, LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return Ok(LockfilePruneReport::default());
    }

    let manifest_path = project_dir.join("package.json");
    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest: Value =
        serde_json::from_str(&manifest_content).map_err(|e| LpmError::Registry(e.to_string()))?;
    let direct_specs = collect_manifest_dependency_specs(&manifest);

    let Ok(mut lockfile) = lpm_lockfile::Lockfile::read_fast(&lockfile_path) else {
        return Ok(LockfilePruneReport::default());
    };

    let package_key = |name: &str, version: &str| -> String {
        let mut key = String::with_capacity(name.len() + 1 + version.len());
        key.push_str(name);
        key.push('\x00');
        key.push_str(version);
        key
    };

    if direct_specs.is_empty() {
        let removed_packages = lockfile
            .packages
            .iter()
            .map(|pkg| PackageVersion {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
            })
            .collect();
        lockfile.packages.clear();
        lockfile.root_aliases.clear();
        lockfile.ambient_peer_installs.clear();
        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(e.to_string()))?;
        return Ok(LockfilePruneReport { removed_packages });
    }

    let package_index: HashMap<String, &lpm_lockfile::LockedPackage> = lockfile
        .packages
        .iter()
        .map(|pkg| (package_key(&pkg.name, &pkg.version), pkg))
        .collect();
    let mut reachable: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    for (local, requested_spec) in &direct_specs {
        let target = lockfile
            .root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(candidate) =
            select_locked_package_for_requested_spec(&lockfile, &target, requested_spec)
        {
            queue.push_back(package_key(&candidate.name, &candidate.version));
        }
    }

    while let Some(next) = queue.pop_front() {
        if !reachable.insert(next.clone()) {
            continue;
        }
        let Some(pkg) = package_index.get(&next) else {
            continue;
        };

        for dep in pkg.dependencies.iter().chain(pkg.peers.iter()) {
            let Some((local_name, version)) = split_locked_dependency(dep) else {
                continue;
            };
            let target = pkg
                .alias_dependencies
                .iter()
                .find(|pair| pair[0] == local_name)
                .map_or(local_name, |pair| pair[1].as_str());
            let dep_key = package_key(target, version);
            if package_index.contains_key(&dep_key) {
                queue.push_back(dep_key);
            }
        }
    }

    let removed_packages = lockfile
        .packages
        .iter()
        .filter(|pkg| !reachable.contains(&package_key(&pkg.name, &pkg.version)))
        .map(|pkg| PackageVersion {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
        })
        .collect();

    lockfile
        .packages
        .retain(|pkg| reachable.contains(&package_key(&pkg.name, &pkg.version)));
    lockfile
        .root_aliases
        .retain(|local, _| direct_specs.contains_key(local));

    let kept_names: std::collections::HashSet<&str> = lockfile
        .packages
        .iter()
        .map(|pkg| pkg.name.as_str())
        .collect();
    lockfile
        .ambient_peer_installs
        .retain(|name| kept_names.contains(name.as_str()));

    lockfile
        .write_all(&lockfile_path)
        .map_err(|e| LpmError::Registry(e.to_string()))?;

    Ok(LockfilePruneReport { removed_packages })
}

/// per-manifest uninstall helper.
///
/// Reads `pkg_json_path`, removes the requested package entries from
/// `dependencies`/`devDependencies`, and writes the manifest back atomically.
/// Does NOT touch the lockfile or `node_modules` — those are the caller's
/// job and happen per target at the manifest's own parent directory.
fn uninstall_from_manifest(
    pkg_json_path: &Path,
    packages: &[String],
    _json_output: bool,
) -> Result<UninstallResult, LpmError> {
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(format!(
            "no package.json at {}",
            pkg_json_path.display()
        )));
    }

    let content = std::fs::read_to_string(pkg_json_path)?;
    let mut doc: Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let result = remove_from_manifest(&mut doc, packages);
    if result.removed.is_empty() {
        return Ok(result);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    lpm_common::write_file_atomic(pkg_json_path, format!("{updated}\n"))?;
    Ok(result)
}

/// Legacy single-project uninstall — thin wrapper around
/// [`uninstall_from_manifest`] + [`cleanup_removed_packages`]. Production
/// callers go through [`run`] which uses the per-target helpers directly.
/// Kept as a stable internal helper that the existing pre-existing test
/// suite exercises end-to-end.
#[allow(dead_code)] // used by tests; production callers use the per-target helpers
fn uninstall_from_project(
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<UninstallResult, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    let result = uninstall_from_manifest(&pkg_json_path, packages, json_output)?;
    if !result.removed.is_empty() {
        let direct_versions = locked_package_versions(project_dir, &result.removed);
        cleanup_removed_packages(project_dir, &result.removed, &direct_versions)?;
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    _client: &RegistryClient,
    cwd: &Path,
    packages: &[String],
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    workspace_root_flag: bool,
    fail_if_no_match: bool,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if packages.is_empty() {
        return Err(LpmError::Registry(
            "specify at least one package to uninstall".to_string(),
        ));
    }

    // route through the shared target resolver, which
    // handles all 8 cells of the install/uninstall decision matrix
    // (standalone, workspace member dir, -w, --filter, etc.).
    let targets = crate::commands::install_targets::resolve_install_targets(
        cwd,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        workspace_root_flag,
        true, // has_packages
    )?;

    // Empty result from --filter (mirrors D3 / workspace install semantics).
    //
    // audit follow-through: surface the D2 substring → glob migration
    // hint when any filter looks like a bare name that would have
    // substring-matched pre-Same behavior as `lpm install --filter`
    // and `lpm run --filter`.
    if targets.member_manifests.is_empty() {
        let hint = crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);

        if fail_if_no_match {
            let base = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base}\n\n{h}"),
                None => base.to_string(),
            }));
        }
        if !json_output {
            uninstall_ui::warn_no_filter_match();
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", install_ui::dim(line));
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    // Multi-member confirmation prompt — mirror of the install-side
    // `confirm_multi_member_mutation` call. See its docstring for the
    // full contract.
    if targets.multi_member {
        crate::commands::install::confirm_multi_member_mutation(
            "Removing",
            packages.len(),
            &targets.member_manifests,
            yes,
            json_output,
        )?;
    }

    let uninstall_start = Instant::now();
    if !json_output {
        uninstall_ui::phase_resolving_graph(packages.len());
    }

    // Run uninstall against every target manifest. Aggregate results so we
    // can report a single deduped (removed, not_found) summary at the end.
    //
    // audit correction: lockfile + node_modules cleanup happens
    // PER TARGET at the member's own dir. LPM uses per-directory lockfiles
    // and per-directory node_modules, so a multi-member uninstall must
    // clean each member's own state — not the workspace root's.
    let mut all_removed: Vec<String> = Vec::new();
    let mut all_not_found: Vec<String> = Vec::new();
    let mut removed_versions: HashMap<String, String> = HashMap::new();
    let mut all_orphaned: Vec<PackageVersion> = Vec::new();
    let mut cleaned_empty_dirs = 0usize;
    let mut freed_bytes = 0u64;
    for manifest_path in &targets.member_manifests {
        let per_member = uninstall_from_manifest(manifest_path, packages, json_output)?;

        if !per_member.removed.is_empty() {
            // Clean THIS member's lockfile and node_modules. install_root_for
            // returns the manifest's parent directory.
            let member_dir = crate::commands::install_targets::install_root_for(manifest_path);
            let per_member_versions = locked_package_versions(member_dir, &per_member.removed);
            removed_versions.extend(per_member_versions.clone());
            let cleanup =
                cleanup_removed_packages(member_dir, &per_member.removed, &per_member_versions)?;
            all_orphaned.extend(cleanup.orphaned);
            cleaned_empty_dirs += cleanup.cleaned_empty_dirs;
            freed_bytes = freed_bytes.saturating_add(cleanup.freed_bytes);
        }

        all_removed.extend(per_member.removed);
        all_not_found.extend(per_member.not_found);
    }

    // A package is "not found" only if no target manifest had it. If at
    // least one target removed it, drop it from the not_found set.
    let removed_set: std::collections::HashSet<&str> =
        all_removed.iter().map(String::as_str).collect();
    all_not_found.retain(|name| !removed_set.contains(name.as_str()));

    // Dedupe both lists for stable output.
    all_removed.sort();
    all_removed.dedup();
    all_not_found.sort();
    all_not_found.dedup();
    all_orphaned.sort();
    all_orphaned.dedup();

    if all_removed.is_empty() {
        if !json_output {
            uninstall_ui::warn_no_packages_removed();
        }
        return Ok(());
    }

    if json_output {
        let target_set: Vec<String> = targets
            .member_manifests
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let json = serde_json::json!({
            "success": true,
            "removed": all_removed,
            "not_found": all_not_found,
            "target_set": target_set,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        eprintln!();
        for name in &all_removed {
            uninstall_ui::minus_package(name, removed_versions.get(name).map(String::as_str));
        }
        for package in &all_orphaned {
            uninstall_ui::minus_orphaned_package(&package.name, &package.version);
        }
        if !all_not_found.is_empty() {
            eprintln!();
            uninstall_ui::warn_not_found(&all_not_found);
        }
        if cleaned_empty_dirs > 0 {
            eprintln!();
            uninstall_ui::done_cleaned_empty_dirs(cleaned_empty_dirs);
        }
        uninstall_ui::done_freed_disk(freed_bytes);
        eprintln!();
        uninstall_ui::done_removed(all_removed.len(), uninstall_start.elapsed());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[allow(clippy::too_many_arguments)]
    async fn run(
        client: &RegistryClient,
        cwd: &Path,
        packages: &[String],
        filters: &[String],
        workspace_root_flag: bool,
        fail_if_no_match: bool,
        yes: bool,
        json_output: bool,
    ) -> Result<(), LpmError> {
        super::run(
            client,
            cwd,
            packages,
            filters,
            &[],
            &[],
            &[],
            workspace_root_flag,
            fail_if_no_match,
            yes,
            json_output,
        )
        .await
    }

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

        let result = remove_from_manifest(&mut manifest, &packages);

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
    fn uninstall_from_project_preserves_lockfile_and_invalidates_install_hash_when_changed() {
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
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(dir.path().join(".lpm").join("install-hash"), "hash").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("foo")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("bar")).unwrap();

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        assert_eq!(result.removed, vec!["foo".to_string()]);
        assert!(
            dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should stay on disk when manifest changes"
        );
        assert!(
            !dir.path().join(".lpm").join("install-hash").exists(),
            "install-hash must be invalidated when manifest changes"
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
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(dir.path().join(".lpm").join("install-hash"), "hash").unwrap();

        let original_manifest = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let result = uninstall_from_project(dir.path(), &["missing".to_string()], true).unwrap();

        assert!(result.removed.is_empty());
        assert_eq!(result.not_found, vec!["missing".to_string()]);
        assert!(
            dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should remain when nothing was removed"
        );
        assert!(
            dir.path().join(".lpm").join("install-hash").exists(),
            "install-hash should remain when nothing was removed"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            original_manifest,
            "package.json should not be rewritten when no dependency matched"
        );
    }

    // ── gap-filling additions ────────────────────────

    #[test]
    fn remove_from_manifest_handles_scoped_package_names() {
        let mut manifest = json!({
            "dependencies": {
                "@lpm.dev/acme.foo": "1.0.0",
                "@scope/bar": "2.0.0",
                "plain": "3.0.0"
            }
        });

        let result = remove_from_manifest(
            &mut manifest,
            &["@lpm.dev/acme.foo".to_string(), "@scope/bar".to_string()],
        );

        assert_eq!(
            result.removed,
            vec!["@lpm.dev/acme.foo".to_string(), "@scope/bar".to_string()]
        );
        assert!(result.not_found.is_empty());
        assert!(manifest["dependencies"].get("@lpm.dev/acme.foo").is_none());
        assert!(manifest["dependencies"].get("@scope/bar").is_none());
        assert_eq!(manifest["dependencies"]["plain"], "3.0.0");
    }

    #[test]
    fn remove_from_manifest_does_not_touch_peer_or_optional_dependencies() {
        // Documents intentional behavior: only `dependencies` and `devDependencies`
        // are managed by uninstall. Peer and optional dependency entries are left
        // alone because removing them blindly would break consumers.
        let mut manifest = json!({
            "dependencies": { "foo": "1.0.0" },
            "peerDependencies": { "foo": ">=1.0.0" },
            "optionalDependencies": { "foo": "1.0.0" }
        });

        let result = remove_from_manifest(&mut manifest, &["foo".to_string()]);

        assert_eq!(result.removed, vec!["foo".to_string()]);
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(
            manifest["peerDependencies"].get("foo").is_some(),
            "peerDependencies must be left untouched by uninstall"
        );
        assert!(
            manifest["optionalDependencies"].get("foo").is_some(),
            "optionalDependencies must be left untouched by uninstall"
        );
    }

    #[test]
    fn remove_from_manifest_handles_missing_dependency_sections_gracefully() {
        // A manifest with no `dependencies` or `devDependencies` should still
        // succeed (every requested package becomes not_found).
        let mut manifest = json!({ "name": "demo" });

        let result = remove_from_manifest(&mut manifest, &["foo".to_string()]);

        assert!(result.removed.is_empty());
        assert_eq!(result.not_found, vec!["foo".to_string()]);
    }

    #[test]
    fn uninstall_from_project_removes_multiple_packages_at_once() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0",
                    "bar": "2.0.0",
                    "keep": "3.0.0"
                },
                "devDependencies": {
                    "baz": "4.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("foo")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("bar")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("baz")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("keep")).unwrap();
        std::fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        std::fs::write(dir.path().join(".lpm").join("install-hash"), "hash").unwrap();

        let result = uninstall_from_project(
            dir.path(),
            &["foo".to_string(), "bar".to_string(), "baz".to_string()],
            true,
        )
        .unwrap();

        assert_eq!(
            result.removed,
            vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
        );
        assert!(result.not_found.is_empty());

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(manifest["dependencies"].get("bar").is_none());
        assert!(manifest["devDependencies"].get("baz").is_none());
        assert_eq!(manifest["dependencies"]["keep"], "3.0.0");

        assert!(!dir.path().join("node_modules").join("foo").exists());
        assert!(!dir.path().join("node_modules").join("bar").exists());
        assert!(!dir.path().join("node_modules").join("baz").exists());
        assert!(dir.path().join("node_modules").join("keep").exists());
        assert!(dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists());
        assert!(!dir.path().join(".lpm").join("install-hash").exists());
    }

    #[test]
    fn uninstall_from_project_removes_dev_only_dependency() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "keep": "1.0.0"
                },
                "devDependencies": {
                    "vitest": "2.0.0"
                }
            }),
        );

        let result = uninstall_from_project(dir.path(), &["vitest".to_string()], true).unwrap();

        assert_eq!(result.removed, vec!["vitest".to_string()]);
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["devDependencies"].get("vitest").is_none());
        assert_eq!(manifest["dependencies"]["keep"], "1.0.0");
    }

    #[test]
    fn uninstall_from_project_preserves_unrelated_manifest_sections() {
        // Important: the writer uses serde_json::to_string_pretty which can
        // reorder keys. This test asserts that NON-TARGET sections survive
        // the rewrite even if formatting is not byte-identical.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "version": "1.0.0",
                "scripts": {
                    "build": "tsup",
                    "test": "vitest"
                },
                "dependencies": {
                    "foo": "1.0.0"
                },
                "peerDependencies": {
                    "react": ">=18"
                },
                "optionalDependencies": {
                    "fsevents": "*"
                },
                "lpm": {
                    "trustedDependencies": ["esbuild"]
                }
            }),
        );

        uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["name"], "demo");
        assert_eq!(manifest["version"], "1.0.0");
        assert_eq!(manifest["scripts"]["build"], "tsup");
        assert_eq!(manifest["scripts"]["test"], "vitest");
        assert_eq!(manifest["peerDependencies"]["react"], ">=18");
        assert_eq!(manifest["optionalDependencies"]["fsevents"], "*");
        assert_eq!(manifest["lpm"]["trustedDependencies"][0], "esbuild");
        assert!(manifest["dependencies"].get("foo").is_none());
    }

    #[test]
    fn uninstall_from_project_errors_when_package_json_missing() {
        let dir = tempfile::tempdir().unwrap();
        // No package.json written.

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true);

        assert!(result.is_err(), "missing package.json must be a hard error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("package.json"),
            "error message should mention package.json, got: {err}"
        );
    }

    #[test]
    fn uninstall_from_project_errors_when_package_json_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{not valid json").unwrap();
        let original = std::fs::read_to_string(dir.path().join("package.json")).unwrap();

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true);

        assert!(
            result.is_err(),
            "malformed package.json must be a hard error, never silent"
        );
        // Critical: do NOT overwrite a malformed manifest with serialized output.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            original,
            "malformed manifest must be left as-is on parse failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_from_project_removes_symlink_in_node_modules() {
        // The cleanup path treats symlinks specially (must remove via remove_file
        // on unix, not remove_dir, because symlinks are file nodes). This test
        // exercises that path.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0"
                }
            }),
        );

        // Create a real package elsewhere and symlink it into node_modules/foo
        let store_pkg = dir.path().join("store").join("foo");
        std::fs::create_dir_all(&store_pkg).unwrap();
        std::fs::write(store_pkg.join("index.js"), "module.exports={}").unwrap();

        let node_modules = dir.path().join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();
        std::os::unix::fs::symlink(&store_pkg, node_modules.join("foo")).unwrap();
        assert!(
            node_modules.join("foo").symlink_metadata().is_ok(),
            "symlink should exist before uninstall"
        );

        uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        assert!(
            node_modules.join("foo").symlink_metadata().is_err(),
            "symlinked node_modules entry must be removed"
        );
        // The store target must NOT be touched — only the link.
        assert!(
            store_pkg.join("index.js").exists(),
            "symlink target (store package) must not be deleted"
        );
    }

    #[tokio::test]
    async fn run_returns_error_for_empty_packages_list() {
        // The public `run` entrypoint must reject an empty packages list.
        // The client is unused on this code path (uninstall never hits the
        // network) so a default-constructed client is safe.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        // signature gained filters/-w/fail_if_no_match params.
        let result = run(&client, dir.path(), &[], &[], false, false, false, true).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("at least one package"),
            "error should explain the constraint, got: {err}"
        );
    }

    // ── workspace-aware uninstall behavior ────────────

    #[tokio::test]
    async fn run_uninstall_in_standalone_project_targets_cwd_manifest() {
        // Standalone project (no workspace) — dispatch falls through
        // to the legacy single-target path via resolve_install_targets.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": { "foo": "1.0.0" }
            }),
        );
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &[],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok(), "uninstall should succeed: {result:?}");

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
    }

    #[tokio::test]
    async fn run_uninstall_with_w_flag_in_standalone_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        // -w in a standalone project must surface the resolve_install_targets error
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &[],
            true,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workspace"));
    }

    #[tokio::test]
    async fn run_uninstall_with_filter_in_standalone_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["web".to_string()],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workspace"));
    }

    /// Helper: build a real on-disk workspace fixture with the given members.
    /// Each member starts with a small dependency set so uninstall has
    /// something to remove.
    #[allow(clippy::type_complexity)] // test fixture builder; tuple shape mirrors caller usage
    fn write_workspace_fixture(root: &std::path::Path, members: &[(&str, &str, &[(&str, &str)])]) {
        std::fs::create_dir_all(root).unwrap();
        let workspace_globs: Vec<String> =
            members.iter().map(|(_, p, _)| (*p).to_string()).collect();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": workspace_globs,
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        for (name, path, deps) in members {
            let dir = root.join(path);
            std::fs::create_dir_all(&dir).unwrap();
            let mut deps_obj = serde_json::Map::new();
            for (k, v) in *deps {
                deps_obj.insert((*k).to_string(), json!(*v));
            }
            let pkg = json!({
                "name": name,
                "version": "0.0.0",
                "dependencies": deps_obj,
            });
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn run_uninstall_with_filter_removes_only_from_targeted_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("web", "packages/web", &[("foo", "1.0.0"), ("bar", "2.0.0")]),
                ("admin", "packages/admin", &[("foo", "1.0.0")]),
            ],
        );

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["web".to_string()],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok(), "expected success: {result:?}");

        // web should have foo removed, bar preserved
        let web: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/web/package.json")).unwrap(),
        )
        .unwrap();
        assert!(web["dependencies"].get("foo").is_none());
        assert_eq!(web["dependencies"]["bar"], "2.0.0");

        // admin should be untouched (foo still present)
        let admin: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/admin/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(admin["dependencies"]["foo"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_with_glob_filter_removes_from_each_matching_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("ui-button", "packages/ui-button", &[("foo", "1.0.0")]),
                ("ui-card", "packages/ui-card", &[("foo", "1.0.0")]),
                ("auth", "packages/auth", &[("foo", "1.0.0")]),
            ],
        );

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["ui-*".to_string()],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok());

        // Both ui members lost foo
        for member in ["ui-button", "ui-card"] {
            let pkg: Value = serde_json::from_str(
                &std::fs::read_to_string(
                    dir.path().join(format!("packages/{member}/package.json")),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(pkg["dependencies"].get("foo").is_none());
        }
        // auth still has foo (didn't match the filter)
        let auth: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/auth/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(auth["dependencies"]["foo"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_with_w_flag_targets_root_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[("web", "packages/web", &[("local-only", "1.0.0")])],
        );
        // Add a root-level dep to the workspace root manifest
        let root_pkg_path = dir.path().join("package.json");
        let mut root_pkg: Value =
            serde_json::from_str(&std::fs::read_to_string(&root_pkg_path).unwrap()).unwrap();
        root_pkg["dependencies"] = json!({ "shared-tool": "1.0.0" });
        std::fs::write(
            &root_pkg_path,
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["shared-tool".to_string()],
            &[],
            true, // -w
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok());

        let root_after: Value =
            serde_json::from_str(&std::fs::read_to_string(&root_pkg_path).unwrap()).unwrap();
        assert!(root_after["dependencies"].get("shared-tool").is_none());

        // web member's local-only dep is untouched
        let web: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/web/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(web["dependencies"]["local-only"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_w_and_filter_together_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["foo".to_string()],
            true, // -w + --filter together
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("`-w`") && err.contains("`--filter`"));
    }

    #[tokio::test]
    async fn run_uninstall_at_workspace_root_with_packages_no_flag_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        // No -w, no --filter, packages provided, cwd at workspace root → ambiguous
        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &[],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }

    #[tokio::test]
    async fn run_uninstall_in_member_dir_no_flag_targets_current_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("foo", "packages/foo", &[("lodash", "4.0.0")]),
                ("bar", "packages/bar", &[("lodash", "4.0.0")]),
            ],
        );
        let foo_dir = dir.path().join("packages/foo");

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            &foo_dir,
            &["lodash".to_string()],
            &[],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok(), "expected success: {result:?}");

        // foo lost lodash
        let foo: Value =
            serde_json::from_str(&std::fs::read_to_string(foo_dir.join("package.json")).unwrap())
                .unwrap();
        assert!(foo["dependencies"].get("lodash").is_none());

        // bar still has lodash
        let bar: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/bar/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(bar["dependencies"]["lodash"], "4.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_with_fail_flag_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["does-not-exist".to_string()],
            false,
            true,  // fail_if_no_match
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--fail-if-no-match"));
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_without_fail_flag_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["does-not-exist".to_string()],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(
            result.is_ok(),
            "no-match without --fail flag should be OK: {result:?}"
        );

        // bar is still in foo's manifest (nothing was removed)
        let foo: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/foo/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(foo["dependencies"]["bar"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_with_fail_flag_includes_d2_hint_for_bare_names() {
        // When --fail-if-no-match fires and the filter list contains bare names
        // that would have substring-matched previously, the error message must
        // surface the D2 migration hint.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            // Bare name filter that matches nothing: exact 'core' substring scenario.
            &["core".to_string()],
            false,
            true,  // fail_if_no_match
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err(), "fail_if_no_match must error on no match");

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("D2"),
            "error must reference design decision D2, got: {err}"
        );
        assert!(
            err.contains("\"*core*\"") || err.contains("\"*/core\""),
            "error must suggest at least one glob form, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_for_glob_filter_does_not_emit_d2_hint() {
        // Negative case: if the user is already using a glob, they don't
        // need the migration hint (they're not coming from substring matching).
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["nonexistent-*".to_string()], // glob that matches nothing
            false,
            true,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("D2"),
            "glob-only filter must NOT trigger the D2 migration hint, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_uninstall_lockfile_cleanup_happens_per_member_not_at_workspace_root() {
        // audit correction: LPM uses per-directory lockfiles. A
        // multi-member uninstall must clean each TARGETED member's own
        // lockfile — and must NOT touch the workspace root lockfile (or any
        // unrelated member's lockfile).
        //
        // The original implementation set install_root = workspace_root
        // and removed only the workspace root lockfile. That was wrong:
        // member node_modules/lockfiles were left stale, and the workspace
        // root lockfile (if any) might not even be related to the members.
        //
        // This test asserts the current behavior:
        //   1. Each TARGETED member's lockfile is preserved in place.
        //   2. The workspace root lockfile is NOT touched.
        //   3. Unrelated members' lockfiles are NOT touched.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("ui-a", "packages/ui-a", &[("foo", "1.0.0")]),
                ("ui-b", "packages/ui-b", &[("foo", "1.0.0")]),
                ("auth", "packages/auth", &[("foo", "1.0.0")]), // unrelated to filter
            ],
        );

        // Place lockfiles in: workspace root + each member dir
        let root_lock = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        let ui_a_lock = dir
            .path()
            .join("packages")
            .join("ui-a")
            .join(lpm_lockfile::LOCKFILE_NAME);
        let ui_b_lock = dir
            .path()
            .join("packages")
            .join("ui-b")
            .join(lpm_lockfile::LOCKFILE_NAME);
        let auth_lock = dir
            .path()
            .join("packages")
            .join("auth")
            .join(lpm_lockfile::LOCKFILE_NAME);

        for path in [&root_lock, &ui_a_lock, &ui_b_lock, &auth_lock] {
            std::fs::write(path, "stub-lock-content").unwrap();
        }

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["ui-*".to_string()], // matches ui-a and ui-b only
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok(), "uninstall should succeed: {result:?}");

        // CRITICAL: targeted members' lockfiles must remain in place
        assert!(
            ui_a_lock.exists(),
            "ui-a lockfile must remain (it's a filter target)"
        );
        assert!(
            ui_b_lock.exists(),
            "ui-b lockfile must remain (it's a filter target)"
        );

        // CRITICAL: unrelated members' lockfiles must be preserved
        assert!(
            auth_lock.exists(),
            "auth lockfile must be preserved (not in filter target set)"
        );

        // CRITICAL: workspace root lockfile must NOT be touched
        assert!(
            root_lock.exists(),
            "workspace root lockfile must NOT be touched by a member-targeted uninstall"
        );
    }

    // ── Install pipeline runs at member dir for filtered installs ───────────

    #[tokio::test]
    async fn run_uninstall_targets_member_dir_lockfile_for_in_member_dir_default() {
        // When the user is `cd packages/foo && lpm uninstall bar`, the
        // lockfile that gets cleaned is packages/foo/lpm.lock — NOT the
        // workspace root lockfile.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);

        let foo_dir = dir.path().join("packages").join("foo");
        let foo_lock = foo_dir.join(lpm_lockfile::LOCKFILE_NAME);
        let root_lock = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        std::fs::write(&foo_lock, "stub").unwrap();
        std::fs::write(&root_lock, "stub").unwrap();

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            &foo_dir,
            &["bar".to_string()],
            &[],
            false,
            false,
            false, // yes —  prompt is TTY-only; tests bypass via non-TTY
            true,
        )
        .await;
        assert!(result.is_ok());

        assert!(
            foo_lock.exists(),
            "member lockfile must remain when uninstalling from inside the member dir"
        );
        assert!(
            root_lock.exists(),
            "workspace root lockfile must NOT be touched by an in-member uninstall"
        );
    }
}
