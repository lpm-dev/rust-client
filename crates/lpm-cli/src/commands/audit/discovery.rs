//! Universal package discovery for audit.
//!
//! Discovers packages from any supported lockfile format or by walking
//! `node_modules/` as a fallback. Reuses parsers from `lpm-migrate`.
//!
//! Priority: `lpm.lock` → `package-lock.json` → `pnpm-lock.yaml`
//!           → `yarn.lock` → `node_modules/` walk (degraded mode).

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lpm_common::LpmError;

/// How a discovered package can be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Source is present on disk, can be behaviorally analyzed.
    FullLocal,
    /// Package can be queried in OSV but source is unavailable (e.g., Yarn PnP).
    OsvOnly,
    /// @lpm.dev package with registry metadata, source in LPM store.
    RegistryAndStore,
    /// Lockfile says it exists, but source is not present on disk.
    LocalMissing,
}

/// A package discovered during the inventory phase.
#[derive(Debug, Clone)]
#[allow(dead_code)] // is_dev and is_optional used by --fail-on policy
pub struct DiscoveredPackage {
    /// Package name (e.g., "react", "@scope/name", "@lpm.dev/owner.pkg").
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// Path relative to project root (e.g., "node_modules/react").
    /// For LPM store packages this is the lockfile key.
    pub path: String,
    /// SRI integrity hash from the lockfile (e.g., "sha512-...").
    pub integrity: Option<String>,
    /// Patch-file digest from `lpm.lock`, when this package's installed bytes are patched.
    pub patch_sha256: Option<String>,
    /// Tarball resolved URL. Used for private registry detection.
    pub resolved_url: Option<String>,
    /// How this package can be scanned.
    pub scan_mode: ScanMode,
    /// Whether this is a dev dependency.
    pub is_dev: bool,
    /// Whether this is an optional dependency.
    pub is_optional: bool,
    /// Direct dependencies: (name, exact_version).
    /// Extracted from lockfile dependency edges. Used by the query engine
    /// for `>` combinator traversal (e.g., `lpm query :eval > :network`).
    pub dependencies: Vec<(String, String)>,
}

/// Which package manager produced the inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerKind {
    Lpm,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    /// No lockfile — walked `node_modules/` directly.
    FallbackNodeModules,
}

impl std::fmt::Display for ManagerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerKind::Lpm => write!(f, "lpm"),
            ManagerKind::Npm => write!(f, "npm"),
            ManagerKind::Pnpm => write!(f, "pnpm"),
            ManagerKind::Yarn => write!(f, "yarn"),
            ManagerKind::Bun => write!(f, "bun"),
            ManagerKind::FallbackNodeModules => write!(f, "node_modules"),
        }
    }
}

/// Result of package discovery.
pub struct DiscoveryResult {
    /// Which package manager was detected.
    pub manager: ManagerKind,
    /// Path to the lockfile (if any).
    pub lockfile_path: Option<PathBuf>,
    /// The project root where the lockfile / node_modules was found.
    pub project_root: PathBuf,
    /// Whether this is degraded mode (no lockfile, weaker identity).
    pub is_degraded: bool,
    /// Whether Yarn PnP was detected (packages are OsvOnly).
    pub is_yarn_pnp: bool,
    /// All discovered packages.
    pub packages: Vec<DiscoveredPackage>,
    pub(super) lpm_lockfile: Option<Arc<lpm_lockfile::Lockfile>>,
    pub(super) lpm_lockfile_content: Option<Arc<[u8]>>,
}

#[cfg(test)]
thread_local! {
    static FOREIGN_LOCKFILE_SNAPSHOT_READS: Cell<usize> = const { Cell::new(0) };
}

/// Discover all packages in a project.
///
/// Walks up from `start_dir` to find the closest lockfile, then parses it.
/// Falls back to walking `node_modules/` if no lockfile is found.
///
/// Priority:
/// 1. `lpm.lock` always wins (LPM-managed project)
/// 2. For foreign lockfiles, uses `lpm-migrate`'s mtime-based detection
///    (most recently modified lockfile wins when multiple exist)
/// 3. Falls back to walking `node_modules/` (degraded mode)
pub fn discover_packages(start_dir: &Path) -> Result<DiscoveryResult, LpmError> {
    discover_packages_with_options(start_dir, false)
}

pub(super) fn discover_packages_retaining_lpm_lockfile(
    start_dir: &Path,
) -> Result<DiscoveryResult, LpmError> {
    discover_packages_with_options(start_dir, true)
}

fn discover_packages_with_options(
    start_dir: &Path,
    retain_lpm_lockfile: bool,
) -> Result<DiscoveryResult, LpmError> {
    // Walk up to find a lockfile
    let mut current = start_dir.to_path_buf();
    loop {
        // 1. lpm.lock — always highest priority (LPM-managed project)
        if current.join("lpm.lock").exists() {
            return discover_from_lpm_lock(start_dir, &current, retain_lpm_lockfile);
        }

        // 2. Foreign lockfiles — use lpm-migrate's mtime-based detection.
        // This correctly handles projects with multiple lockfiles by
        // picking the most recently modified one.
        if let Some(source) = lpm_migrate::detect::detect_lockfile(&current)? {
            return match source.kind {
                lpm_migrate::SourceKind::Npm => discover_from_npm_lockfile(&current, &source.path),
                lpm_migrate::SourceKind::Pnpm => {
                    discover_from_pnpm_lockfile(&current, &source.path)
                }
                lpm_migrate::SourceKind::Yarn => {
                    discover_from_yarn_lockfile(&current, &source.path)
                }
                lpm_migrate::SourceKind::Bun => discover_from_bun_lockfile(&current, &source.path),
            };
        }

        // Walk up
        if !current.pop() {
            break;
        }
    }

    // No lockfile found — try node_modules/ fallback from start_dir
    let nm_dir = start_dir.join("node_modules");
    if nm_dir.is_dir() {
        return Ok(discover_from_node_modules(start_dir));
    }

    Err(LpmError::NotFound(
        "No lockfile or node_modules found. Nothing to audit.".into(),
    ))
}

// ─── LPM lockfile ───────────────────────────────────────────────────────────

fn discover_from_lpm_lock(
    start_dir: &Path,
    project_root: &Path,
    retain_lockfile: bool,
) -> Result<DiscoveryResult, LpmError> {
    let target_root =
        lpm_workspace::find_project_root(start_dir).unwrap_or_else(|| start_dir.to_path_buf());
    let (lockfile_path, lockfile, lpm_lockfile_content) = if retain_lockfile {
        let project = lpm_lockfile::Lockfile::read_for_project(&target_root)
            .map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?;
        (
            project.path,
            project.lockfile,
            Some(Arc::<[u8]>::from(project.content.into_bytes())),
        )
    } else {
        (
            project_root.join("lpm.lock"),
            crate::commands::install::workspace_lockfile::read_project(&target_root)
                .map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?,
            None,
        )
    };

    let packages = lockfile
        .packages
        .iter()
        .map(|p| {
            // All packages in lpm.lock (both @lpm.dev and npm) are in the
            // LPM store at ~/.lpm/store/v1/<name>@<version>/. The store-backed
            // scan uses store.package_dir(name, version), not the path field.

            // Parse dependencies from "name@version" format
            let dependencies = p
                .dependencies
                .iter()
                .filter_map(|dep_ref| {
                    dep_ref
                        .rfind('@')
                        .map(|at| (dep_ref[..at].to_string(), dep_ref[at + 1..].to_string()))
                })
                .collect();

            let selector = format!("{}@{}", p.name, p.version);
            let patch_sha256 = lockfile
                .patches
                .get(&selector)
                .map(|patch| patch.sha256.clone());

            DiscoveredPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                path: format!("node_modules/{}", p.name),
                integrity: p.integrity.clone(),
                patch_sha256,
                resolved_url: None,
                scan_mode: ScanMode::RegistryAndStore,
                is_dev: false,
                is_optional: false,
                dependencies,
            }
        })
        .collect();

    let lpm_lockfile = retain_lockfile.then(|| Arc::new(lockfile));
    Ok(DiscoveryResult {
        manager: ManagerKind::Lpm,
        lockfile_path: Some(lockfile_path),
        project_root: target_root,
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile,
        lpm_lockfile_content,
    })
}

// ─── npm (package-lock.json) ────────────────────────────────────────────────

fn discover_from_npm_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let parsed = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::npm::parse_snapshot(&snapshot)?
    };
    let exact_paths = parsed.package_paths.is_some();
    let packages = migrated_to_discovered(
        project_root,
        parsed.packages,
        parsed.package_paths,
        exact_paths,
    )?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Npm,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
    })
}

// ─── pnpm (pnpm-lock.yaml) ─────────────────────────────────────────────────

fn discover_from_pnpm_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let migrated = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::pnpm::parse_str(&snapshot)?
    };
    let installed_paths = installed_pnpm_package_paths(project_root, &migrated)?;
    let packages = migrated_to_discovered_pnpm(project_root, migrated, installed_paths)?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Pnpm,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
    })
}

// ─── yarn (yarn.lock) ───────────────────────────────────────────────────────

fn discover_from_yarn_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    // Check for Yarn PnP
    let is_yarn_pnp =
        project_root.join(".pnp.cjs").exists() || project_root.join(".pnp.js").exists();

    let migrated = {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::yarn::parse_str(&snapshot)?
    };

    let packages: Vec<DiscoveredPackage> = if is_yarn_pnp {
        // PnP mode — packages are in zip archives, can't scan source
        migrated
            .into_iter()
            .map(|package| {
                let path = format!("node_modules/{}", package.name);
                DiscoveredPackage {
                    name: package.name,
                    version: package.version,
                    path,
                    integrity: package.integrity,
                    patch_sha256: None,
                    resolved_url: package.resolved,
                    scan_mode: ScanMode::OsvOnly,
                    is_dev: package.is_dev,
                    is_optional: package.is_optional,
                    dependencies: package.dependencies,
                }
            })
            .collect()
    } else {
        migrated_to_discovered(project_root, migrated, None, false)?
    };

    Ok(DiscoveryResult {
        manager: ManagerKind::Yarn,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
    })
}

// ─── bun (bun.lockb / bun.lock) ────────────────────────────────────────────

fn discover_from_bun_lockfile(
    project_root: &Path,
    lockfile_path: &Path,
) -> Result<DiscoveryResult, LpmError> {
    let migrated = if lockfile_path
        .extension()
        .is_some_and(|extension| extension == "lock")
    {
        let snapshot = read_foreign_lockfile_snapshot(lockfile_path)?;
        lpm_migrate::bun::parse_json_str(&snapshot)?
    } else {
        lpm_migrate::bun::parse_selected(lockfile_path)?
    };
    let packages = migrated_to_discovered(project_root, migrated, None, false)?;

    Ok(DiscoveryResult {
        manager: ManagerKind::Bun,
        lockfile_path: Some(lockfile_path.to_path_buf()),
        project_root: project_root.to_path_buf(),
        is_degraded: false,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
    })
}

// ─── node_modules fallback (degraded mode) ──────────────────────────────────

fn discover_from_node_modules(project_root: &Path) -> DiscoveryResult {
    let nm_dir = project_root.join("node_modules");

    let mut entries: Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf)> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_node_modules_entries(project_root, &nm_dir, &mut entries, &mut visited);

    let version_lookup: std::collections::HashMap<std::path::PathBuf, (String, String)> = entries
        .iter()
        .map(|(pkg, _, pkg_dir)| (pkg_dir.clone(), (pkg.name.clone(), pkg.version.clone())))
        .collect();

    let packages = entries
        .into_iter()
        .map(|(mut pkg, dep_names, pkg_dir)| {
            pkg.dependencies = dep_names
                .into_iter()
                .filter_map(|dep_name| {
                    resolve_node_modules_dependency(
                        &pkg_dir,
                        &dep_name,
                        project_root,
                        &version_lookup,
                    )
                })
                .collect();
            pkg
        })
        .collect();

    DiscoveryResult {
        manager: ManagerKind::FallbackNodeModules,
        lockfile_path: None,
        project_root: project_root.to_path_buf(),
        is_degraded: true,
        is_yarn_pnp: false,
        packages,
        lpm_lockfile: None,
        lpm_lockfile_content: None,
    }
}

fn collect_node_modules_entries(
    project_root: &Path,
    node_modules: &Path,
    entries: &mut Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf)>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
) {
    let Ok(metadata) = std::fs::symlink_metadata(node_modules) else {
        return;
    };
    if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
        return;
    }
    let Ok(identity) = node_modules.canonicalize() else {
        return;
    };
    if !visited.insert(identity) {
        return;
    }
    let Ok(dir_entries) = std::fs::read_dir(node_modules) else {
        return;
    };

    for entry in dir_entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
            continue;
        }

        if name.starts_with('@') {
            let Ok(scoped_entries) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            for scoped_entry in scoped_entries.flatten() {
                let Ok(scoped_metadata) = std::fs::symlink_metadata(scoped_entry.path()) else {
                    continue;
                };
                if !scoped_metadata.is_dir() || lpm_common::is_symlink_or_junction(&scoped_metadata)
                {
                    continue;
                }
                let scoped_name = scoped_entry.file_name().to_string_lossy().to_string();
                let full_name = format!("{name}/{scoped_name}");
                collect_node_modules_package(
                    project_root,
                    &scoped_entry.path(),
                    &full_name,
                    entries,
                    visited,
                );
            }
        } else {
            collect_node_modules_package(project_root, &entry.path(), &name, entries, visited);
        }
    }
}

fn collect_node_modules_package(
    project_root: &Path,
    package_dir: &Path,
    name: &str,
    entries: &mut Vec<(DiscoveredPackage, Vec<String>, std::path::PathBuf)>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
) {
    if let Some((package, dependencies)) =
        read_package_from_node_modules(project_root, package_dir, name)
    {
        entries.push((package, dependencies, package_dir.to_path_buf()));
    }
    collect_node_modules_entries(
        project_root,
        &package_dir.join("node_modules"),
        entries,
        visited,
    );
}

fn resolve_node_modules_dependency(
    package_dir: &Path,
    dependency: &str,
    project_root: &Path,
    versions: &std::collections::HashMap<std::path::PathBuf, (String, String)>,
) -> Option<(String, String)> {
    let mut base = package_dir.to_path_buf();
    loop {
        let candidate = base.join("node_modules").join(dependency);
        if let Some(version) = versions.get(&candidate) {
            return Some(version.clone());
        }
        let parent = base.parent()?;
        base = if parent
            .file_name()
            .is_some_and(|name| name == "node_modules")
        {
            parent.parent()?.to_path_buf()
        } else {
            parent.to_path_buf()
        };
        if !base.starts_with(project_root) {
            return None;
        }
    }
}

/// Read a single package's info from its `node_modules/<name>/package.json`.
///
/// Returns the discovered package and its dependency names (unresolved).
/// Dependency versions are resolved in a second pass after all packages
/// have been discovered, using a `name → version` lookup.
fn read_package_from_node_modules(
    project_root: &Path,
    pkg_dir: &Path,
    name: &str,
) -> Option<(DiscoveredPackage, Vec<String>)> {
    let pkg_json_path = pkg_dir.join("package.json");
    let content =
        lpm_common::read_text_file_capped(&pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let version = json.get("version")?.as_str()?.to_string();
    let canonical_name = json
        .get("name")
        .and_then(|value| value.as_str())
        .unwrap_or(name)
        .to_string();

    let rel_path = pkg_dir.strip_prefix(project_root).ok()?;
    let path = rel_path.to_string_lossy().to_string();

    // Extract dependency names from package.json (versions resolved in second pass)
    let mut dep_names = Vec::new();
    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        for dep_name in deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }
    if let Some(opt_deps) = json.get("optionalDependencies").and_then(|d| d.as_object()) {
        for dep_name in opt_deps.keys() {
            dep_names.push(dep_name.clone());
        }
    }

    Some((
        DiscoveredPackage {
            name: canonical_name,
            version,
            path,
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            scan_mode: ScanMode::FullLocal,
            is_dev: false,            // Can't determine without lockfile
            is_optional: false,       // Can't determine without lockfile
            dependencies: Vec::new(), // Resolved in second pass
        },
        dep_names,
    ))
}

// ─── Shared conversion ─────────────────────────────────────────────────────

fn read_foreign_lockfile_snapshot(path: &Path) -> Result<String, LpmError> {
    #[cfg(test)]
    FOREIGN_LOCKFILE_SNAPSHOT_READS.set(FOREIGN_LOCKFILE_SNAPSHOT_READS.get() + 1);
    lpm_migrate::read_lockfile_snapshot(path)
}

fn migrated_to_discovered(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
    mut raw_paths: Option<HashMap<String, Vec<String>>>,
    require_exact_paths: bool,
) -> Result<Vec<DiscoveredPackage>, LpmError> {
    migrated_to_discovered_with(project_root, migrated, |package| {
        let package_key = format!("{}@{}", package.name, package.version);
        let path = raw_paths.as_mut().and_then(|paths| {
            let queued = paths.get_mut(&package_key)?;
            if queued.is_empty() {
                None
            } else {
                Some(queued.remove(0))
            }
        });
        if let Some(path) = path {
            Ok(SelectedPackagePath::Validate(path))
        } else if require_exact_paths {
            Err(LpmError::Script(format!(
                "package-lock.json did not retain an exact package path for {package_key}"
            )))
        } else {
            Ok(SelectedPackagePath::Validate(format!(
                "node_modules/{}",
                package.name
            )))
        }
    })
}

enum SelectedPackagePath {
    Validate(String),
    Missing(String),
}

fn migrated_to_discovered_with<F>(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
    mut select_path: F,
) -> Result<Vec<DiscoveredPackage>, LpmError>
where
    F: FnMut(&lpm_migrate::MigratedPackage) -> Result<SelectedPackagePath, LpmError>,
{
    let canonical_project_root = project_root.canonicalize().map_err(LpmError::Io)?;
    let mut packages = Vec::with_capacity(migrated.len());

    for package in migrated {
        let selected_path = select_path(&package)?;
        let lpm_migrate::MigratedPackage {
            lockfile_key: _,
            name,
            version,
            resolved,
            integrity,
            dependencies,
            is_optional,
            is_dev,
        } = package;
        let (path, scan_mode) = match selected_path {
            SelectedPackagePath::Validate(path) => {
                let scan_mode = package_scan_mode(project_root, &canonical_project_root, &path)?;
                (path, scan_mode)
            }
            SelectedPackagePath::Missing(path) => (path, ScanMode::LocalMissing),
        };

        packages.push(DiscoveredPackage {
            name,
            version,
            path,
            integrity,
            patch_sha256: None,
            resolved_url: resolved,
            scan_mode,
            is_dev,
            is_optional,
            dependencies,
        });
    }

    Ok(packages)
}

struct InstalledPnpmPackagePaths {
    virtual_store_present: bool,
    paths_by_lockfile_key: HashMap<String, String>,
}

fn migrated_to_discovered_pnpm(
    project_root: &Path,
    migrated: Vec<lpm_migrate::MigratedPackage>,
    installed: InstalledPnpmPackagePaths,
) -> Result<Vec<DiscoveredPackage>, LpmError> {
    migrated_to_discovered_with(project_root, migrated, |package| {
        if !installed.virtual_store_present {
            return Ok(SelectedPackagePath::Validate(format!(
                "node_modules/{}",
                package.name
            )));
        }
        let key = package.lockfile_key.as_deref().ok_or_else(|| {
            LpmError::Script(format!(
                "pnpm lockfile did not retain the package instance key for {}@{}",
                package.name, package.version
            ))
        })?;
        if let Some(path) = installed.paths_by_lockfile_key.get(key) {
            return Ok(SelectedPackagePath::Validate(path.clone()));
        }
        let directory = lpm_migrate::pnpm::virtual_store_directory_name(key)?;
        Ok(SelectedPackagePath::Missing(format!(
            "node_modules/.pnpm/{directory}/node_modules/{}",
            package.name
        )))
    })
}

fn package_scan_mode(
    project_root: &Path,
    canonical_project_root: &Path,
    relative_path: &str,
) -> Result<ScanMode, LpmError> {
    let relative = Path::new(relative_path);
    if relative_path.contains('\\')
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(LpmError::Script(format!(
            "lockfile contains an unsafe package path: {relative_path}"
        )));
    }

    let absolute = project_root.join(relative);
    match std::fs::metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() => {
            let canonical = absolute.canonicalize().map_err(LpmError::Io)?;
            if !canonical.starts_with(canonical_project_root) {
                return Err(LpmError::Script(format!(
                    "lockfile package path resolves outside the project: {relative_path}"
                )));
            }
            Ok(ScanMode::FullLocal)
        }
        Ok(_) => Ok(ScanMode::LocalMissing),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_nearest_existing_ancestor(&absolute, canonical_project_root, relative_path)?;
            Ok(ScanMode::LocalMissing)
        }
        Err(error) => Err(LpmError::Io(error)),
    }
}

fn validate_nearest_existing_ancestor(
    absolute: &Path,
    canonical_project_root: &Path,
    relative_path: &str,
) -> Result<(), LpmError> {
    let mut probe = absolute;
    loop {
        match probe.canonicalize() {
            Ok(canonical) => {
                if canonical.starts_with(canonical_project_root) {
                    return Ok(());
                }
                return Err(LpmError::Script(format!(
                    "lockfile package path resolves outside the project: {relative_path}"
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                probe = probe.parent().ok_or_else(|| {
                    LpmError::Script(format!(
                        "lockfile package path has no project ancestor: {relative_path}"
                    ))
                })?;
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    }
}

fn installed_pnpm_package_paths(
    project_root: &Path,
    packages: &[lpm_migrate::MigratedPackage],
) -> Result<InstalledPnpmPackagePaths, LpmError> {
    use cap_fs_ext::DirExt as _;

    let canonical_root = project_root.canonicalize().map_err(LpmError::Io)?;
    let root = cap_std::fs::Dir::open_ambient_dir(&canonical_root, cap_std::ambient_authority())
        .map_err(LpmError::Io)?;
    let node_modules = match root.open_dir_nofollow("node_modules") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstalledPnpmPackagePaths {
                virtual_store_present: false,
                paths_by_lockfile_key: HashMap::new(),
            });
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    let virtual_store = match node_modules.open_dir_nofollow(".pnpm") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InstalledPnpmPackagePaths {
                virtual_store_present: false,
                paths_by_lockfile_key: HashMap::new(),
            });
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "pnpm virtual store is linked, invalid, or unreadable: {error}"
            )));
        }
    };

    let mut paths = HashMap::with_capacity(packages.len());
    for package in packages {
        let Some(key) = package.lockfile_key.as_deref() else {
            continue;
        };
        let store_directory = lpm_migrate::pnpm::virtual_store_directory_name(key)?;
        let instance = match virtual_store.open_dir_nofollow(&store_directory) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "failed to open pnpm package instance {store_directory}: {error}"
                )));
            }
        };
        let package_root = match open_pnpm_package_directory(&instance, &package.name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(LpmError::Io(error)),
        };
        if !pnpm_manifest_matches(&package_root, &package.name, &package.version)? {
            continue;
        }
        paths.insert(
            key.to_string(),
            format!(
                "node_modules/.pnpm/{store_directory}/node_modules/{}",
                package.name
            ),
        );
    }
    Ok(InstalledPnpmPackagePaths {
        virtual_store_present: true,
        paths_by_lockfile_key: paths,
    })
}

fn open_pnpm_package_directory(
    instance: &cap_std::fs::Dir,
    package_name: &str,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt as _;

    let mut directory = instance.open_dir_nofollow("node_modules")?;
    for component in Path::new(package_name).components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pnpm package name contains an unsafe path component",
            ));
        };
        directory = directory.open_dir_nofollow(name)?;
    }
    Ok(directory)
}

fn pnpm_manifest_matches(
    package_dir: &cap_std::fs::Dir,
    expected_name: &str,
    expected_version: &str,
) -> Result<bool, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match package_dir.open_with("package.json", &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_file() || metadata.is_symlink() {
        return Ok(false);
    }
    let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file.into_std(),
        Path::new("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        metadata.len(),
    )
    .map_err(|error| {
        LpmError::Script(format!(
            "failed to read installed pnpm package metadata: {error}"
        ))
    })?;
    let manifest: serde_json::Value = serde_json::from_str(&content).map_err(|error| {
        LpmError::Script(format!("invalid installed pnpm package metadata: {error}"))
    })?;
    Ok(
        manifest.get("name").and_then(serde_json::Value::as_str) == Some(expected_name)
            && manifest.get("version").and_then(serde_json::Value::as_str)
                == Some(expected_version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn npm_lockfile_preserves_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "4.22.1"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"express": "4.22.1"}},
					"node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz",
						"integrity": "sha512-abc",
						"dependencies": {"accepts": "1.3.8", "qs": "6.14.0"}
					},
					"node_modules/accepts": {
						"version": "1.3.8",
						"resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
						"integrity": "sha512-def"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz",
						"integrity": "sha512-ghi"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs so ScanMode is FullLocal
        fs::create_dir_all(dir.path().join("node_modules/express")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/accepts")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Npm);
        assert_eq!(result.packages.len(), 3);

        // Express should have dependency edges to accepts and qs
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );

        // Leaf packages should have no dependencies
        let accepts = result
            .packages
            .iter()
            .find(|p| p.name == "accepts")
            .expect("accepts not found");
        assert!(accepts.dependencies.is_empty());
    }

    #[test]
    fn npm_nested_deps_get_correct_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "6.14.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "6.14.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "6.5.3"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "6.5.3",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.5.3.tgz"
					},
					"node_modules/qs": {
						"version": "6.14.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.14.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Package "a" should depend on qs@6.5.3 (nested), not qs@6.14.0 (hoisted)
        let a = result
            .packages
            .iter()
            .find(|p| p.name == "a")
            .expect("package a not found");
        assert_eq!(a.dependencies.len(), 1);
        assert_eq!(a.dependencies[0], ("qs".to_string(), "6.5.3".to_string()));
    }

    #[test]
    fn node_modules_fallback_builds_edges() {
        let dir = tempfile::tempdir().unwrap();

        // Create packages in node_modules (no lockfile)
        let express_dir = dir.path().join("node_modules/express");
        fs::create_dir_all(&express_dir).unwrap();
        fs::write(
            express_dir.join("package.json"),
            r#"{"name": "express", "version": "4.22.1", "dependencies": {"qs": "6.14.0"}}"#,
        )
        .unwrap();

        let qs_dir = dir.path().join("node_modules/qs");
        fs::create_dir_all(&qs_dir).unwrap();
        fs::write(
            qs_dir.join("package.json"),
            r#"{"name": "qs", "version": "6.14.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::FallbackNodeModules);
        assert!(result.is_degraded);
        assert_eq!(result.packages.len(), 2);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        // Should resolve edge to qs@6.14.0 from installed version
        assert_eq!(express.dependencies.len(), 1);
        assert_eq!(
            express.dependencies[0],
            ("qs".to_string(), "6.14.0".to_string())
        );
    }

    #[test]
    fn node_modules_fallback_discovers_nested_transitive_packages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"parent":"1.0.0"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/parent/node_modules/child")).unwrap();
        fs::write(
            dir.path().join("node_modules/parent/package.json"),
            r#"{"name":"parent","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("node_modules/parent/node_modules/child/package.json"),
            r#"{"name":"child","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path());

        assert_eq!(result.packages.len(), 2);
        assert!(result.packages.iter().any(|package| {
            package.name == "child" && package.path == "node_modules/parent/node_modules/child"
        }));
        let parent = result
            .packages
            .iter()
            .find(|package| package.name == "parent")
            .unwrap();
        assert_eq!(
            parent.dependencies,
            vec![("child".to_string(), "1.0.0".to_string())]
        );
    }

    #[test]
    fn node_modules_fallback_uses_manifest_name_for_npm_alias_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/local-alias")).unwrap();
        fs::write(
            dir.path().join("node_modules/local-alias/package.json"),
            r#"{"name":"canonical-package","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_from_node_modules(dir.path());

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "canonical-package");
        assert_eq!(result.packages[0].path, "node_modules/local-alias");
    }

    #[test]
    fn lpm_lock_extracts_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.lock"),
            r#"
[metadata]
lockfile-version = 1
resolved-with = "pubgrub"

[[packages]]
name = "accepts"
version = "1.3.8"

[[packages]]
name = "express"
version = "4.22.1"
dependencies = ["accepts@1.3.8", "qs@6.14.0"]

[[packages]]
name = "qs"
version = "6.14.0"
"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.manager, ManagerKind::Lpm);
        assert_eq!(result.packages.len(), 3);

        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(express.dependencies.len(), 2);
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "accepts" && v == "1.3.8")
        );
        assert!(
            express
                .dependencies
                .iter()
                .any(|(n, v)| n == "qs" && v == "6.14.0")
        );
    }

    #[test]
    fn node_modules_fallback_unresolved_deps_filtered() {
        let dir = tempfile::tempdir().unwrap();

        // Package depends on "missing-pkg" which isn't installed
        let pkg_dir = dir.path().join("node_modules/my-pkg");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "my-pkg", "version": "1.0.0", "dependencies": {"missing-pkg": "^1.0.0"}}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        let pkg = result
            .packages
            .iter()
            .find(|p| p.name == "my-pkg")
            .expect("my-pkg not found");
        // missing-pkg is not in node_modules, so it should be filtered out
        assert!(pkg.dependencies.is_empty());
    }

    #[test]
    fn cache_stores_and_retrieves_dependencies() {
        let dir = tempfile::tempdir().unwrap();

        let mut cache = super::super::cache::ProjectAuditCache::new("npm");
        let analysis = lpm_security::behavioral::PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "T00:00:00Z".to_string(),
            source: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            meta: Default::default(),
        };
        let deps = vec![
            ("accepts".to_string(), "1.3.8".to_string()),
            ("qs".to_string(), "6.14.0".to_string()),
        ];

        cache.insert(
            "node_modules/express".to_string(),
            "express".to_string(),
            "4.22.1".to_string(),
            Some("sha512-abc".to_string()),
            analysis,
            deps.clone(),
        );

        // Write and read back
        cache.write(dir.path()).unwrap();
        let loaded =
            super::super::cache::ProjectAuditCache::read(dir.path()).expect("cache should load");

        let entry = loaded
            .entries
            .get("node_modules/express")
            .expect("entry should exist");
        assert_eq!(entry.dependencies, deps);
    }

    #[test]
    fn npm_duplicate_name_version_at_different_paths_preserved() {
        // Bug: parse_npm_package_paths keys by name@version, so two instances
        // of qs@1.0.0 at different paths collapse onto one. The second insert
        // overwrites the first, losing a package instance.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"a": "1.0.0", "qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"dependencies": {"a": "1.0.0", "qs": "1.0.0"}},
					"node_modules/a": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
						"dependencies": {"qs": "1.0.0"}
					},
					"node_modules/a/node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        // Create node_modules dirs
        fs::create_dir_all(dir.path().join("node_modules/a/node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/a")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Must have 3 packages: a, qs (hoisted), qs (nested under a)
        assert_eq!(
            result.packages.len(),
            3,
            "expected 3 packages, got {}",
            result.packages.len()
        );

        // Both qs instances must have DIFFERENT paths
        let qs_packages: Vec<&DiscoveredPackage> =
            result.packages.iter().filter(|p| p.name == "qs").collect();
        assert_eq!(qs_packages.len(), 2, "expected 2 qs instances");

        let mut paths: Vec<&str> = qs_packages.iter().map(|p| p.path.as_str()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["node_modules/a/node_modules/qs", "node_modules/qs"],
            "qs instances must have distinct paths"
        );
    }

    #[test]
    fn npm_workspace_entries_dont_abort_path_recovery() {
        // Bug: workspace entries like "packages/app" in package-lock.json
        // caused parse_npm_package_paths to return None via ? propagation,
        // losing ALL path recovery for the entire lockfile.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
				"lockfileVersion": 3,
				"packages": {
					"": {"workspaces": ["packages/*"], "dependencies": {"qs": "1.0.0"}},
					"node_modules/qs": {
						"version": "1.0.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-1.0.0.tgz"
					},
					"node_modules/lodash": {
						"version": "4.17.21",
						"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
					},
					"node_modules/web": {
						"resolved": "packages/web",
						"link": true
					},
					"packages/web": {
						"name": "web",
						"version": "1.0.0",
						"dependencies": {"lodash": "^4.17.0"}
					},
					"packages/web/node_modules/express": {
						"version": "4.22.1",
						"resolved": "https://registry.npmjs.org/express/-/express-4.22.1.tgz"
					}
				}
			}"#,
        )
        .unwrap();

        fs::create_dir_all(dir.path().join("node_modules/qs")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/lodash")).unwrap();
        fs::create_dir_all(dir.path().join("packages/web/node_modules/express")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        // Should discover qs, lodash, AND express (under workspace member)
        assert!(
            result.packages.len() >= 3,
            "expected at least 3 packages, got {}",
            result.packages.len()
        );

        // Express should have the workspace-nested path
        let express = result
            .packages
            .iter()
            .find(|p| p.name == "express")
            .expect("express not found");
        assert_eq!(
            express.path, "packages/web/node_modules/express",
            "express should have workspace-nested path"
        );
    }

    #[test]
    fn malformed_child_lockfile_does_not_fall_back_to_an_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("package-lock.json"), "{not-json").unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/ancestor": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/ancestor/-/ancestor-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(&child)
            .err()
            .expect("child lockfile must fail");

        assert!(
            error.to_string().contains("package-lock.json"),
            "the malformed child lockfile must be reported instead of selecting the ancestor: {error}"
        );
    }

    #[test]
    fn malformed_lockfile_does_not_fall_back_to_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package-lock.json"), "{not-json").unwrap();
        fs::create_dir_all(dir.path().join("node_modules/fallback")).unwrap();
        fs::write(
            dir.path().join("node_modules/fallback/package.json"),
            r#"{"name":"fallback","version":"1.0.0"}"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("malformed lockfile must fail");

        assert!(
            error.to_string().contains("package-lock.json"),
            "the malformed lockfile must be reported instead of using degraded discovery: {error}"
        );
    }

    #[test]
    fn npm_registry_metadata_remains_bound_to_its_exact_package_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/consumer/node_modules/shared": {
                        "version": "1.0.0"
                    },
                    "node_modules/shared": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz",
                        "integrity": "sha512-registry"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/consumer/node_modules/shared")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/shared")).unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].path, "node_modules/shared");
        assert_eq!(
            result.packages[0].integrity.as_deref(),
            Some("sha512-registry")
        );
    }

    #[test]
    fn npm_absolute_package_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "/tmp/outside/node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("absolute package path must fail");

        assert!(
            error.to_string().contains("package path"),
            "absolute npm package paths must fail closed: {error}"
        );
    }

    #[test]
    fn pnpm_transitive_package_uses_its_virtual_store_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  child@1.0.0:
    resolution:
      integrity: sha512-child
      tarball: https://registry.npmjs.org/child/-/child-1.0.0.tgz
"#,
        )
        .unwrap();
        let installed = dir
            .path()
            .join("node_modules/.pnpm/child@1.0.0/node_modules/child");
        fs::create_dir_all(&installed).unwrap();
        fs::write(
            installed.join("package.json"),
            r#"{"name":"child","version":"1.0.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(
            result.packages[0].path,
            "node_modules/.pnpm/child@1.0.0/node_modules/child"
        );
        assert_eq!(result.packages[0].scan_mode, ScanMode::FullLocal);
    }

    #[test]
    fn pnpm_peer_contexts_keep_their_exact_paths_and_dependency_edges() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  consumer@1.0.0:
    resolution: {integrity: sha512-consumer}
  left@1.0.0:
    resolution: {integrity: sha512-left}
  right@2.0.0:
    resolution: {integrity: sha512-right}
snapshots:
  consumer@1.0.0(left@1.0.0):
    dependencies:
      left: 1.0.0
  consumer@1.0.0(right@2.0.0):
    dependencies:
      right: 2.0.0
  left@1.0.0: {}
  right@2.0.0: {}
"#,
        )
        .unwrap();
        for (store_directory, name, version) in [
            ("consumer@1.0.0_left@1.0.0", "consumer", "1.0.0"),
            ("consumer@1.0.0_right@2.0.0", "consumer", "1.0.0"),
            ("left@1.0.0", "left", "1.0.0"),
            ("right@2.0.0", "right", "2.0.0"),
        ] {
            let package = dir
                .path()
                .join("node_modules/.pnpm")
                .join(store_directory)
                .join("node_modules")
                .join(name);
            fs::create_dir_all(&package).unwrap();
            fs::write(
                package.join("package.json"),
                format!(r#"{{"name":"{name}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let result = discover_packages(dir.path()).unwrap();
        let consumers: Vec<_> = result
            .packages
            .iter()
            .filter(|package| package.name == "consumer")
            .collect();

        assert_eq!(consumers.len(), 2);
        assert!(consumers.iter().any(|package| {
            package.path.contains("consumer@1.0.0_left@1.0.0")
                && package.dependencies == vec![("left".to_string(), "1.0.0".to_string())]
        }));
        assert!(consumers.iter().any(|package| {
            package.path.contains("consumer@1.0.0_right@2.0.0")
                && package.dependencies == vec![("right".to_string(), "2.0.0".to_string())]
        }));
    }

    #[test]
    fn pnpm_missing_exact_instance_does_not_scan_a_different_hoisted_version() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  child@1.0.0:
    resolution:
      integrity: sha512-child-v1
      tarball: https://registry.npmjs.org/child/-/child-1.0.0.tgz
"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules/.pnpm")).unwrap();
        let hoisted = dir.path().join("node_modules/child");
        fs::create_dir_all(&hoisted).unwrap();
        fs::write(
            hoisted.join("package.json"),
            r#"{"name":"child","version":"2.0.0"}"#,
        )
        .unwrap();

        let result = discover_packages(dir.path()).unwrap();

        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].version, "1.0.0");
        assert_eq!(result.packages[0].scan_mode, ScanMode::LocalMissing);
        assert_ne!(result.packages[0].path, "node_modules/child");
    }

    #[cfg(unix)]
    #[test]
    fn pnpm_virtual_store_symlink_is_rejected_before_external_manifest_reads() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
packages:
  escaped@1.0.0:
    resolution:
      integrity: sha512-escaped
      tarball: https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz
"#,
        )
        .unwrap();
        let external_package = outside.path().join("escaped@1.0.0/node_modules/escaped");
        fs::create_dir_all(&external_package).unwrap();
        fs::write(
            external_package.join("package.json"),
            r#"{"name":"escaped","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        symlink(outside.path(), dir.path().join("node_modules/.pnpm")).unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("linked pnpm virtual store must fail");

        assert!(error.to_string().contains("virtual store"));
    }

    #[test]
    fn newer_bun_binary_lockfile_is_not_replaced_by_stale_text_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bun.lock"), r#"{"packages":{}}"#).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(dir.path().join("bun.lockb"), b"not-a-bun-lockfile").unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("selected binary lockfile must fail");

        assert!(
            error.to_string().contains("bun.lockb") || error.to_string().contains("bun"),
            "the selected binary lockfile must remain authoritative: {error}"
        );
    }

    #[test]
    fn npm_discovery_reads_one_lockfile_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/once": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/once/-/once-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();
        FOREIGN_LOCKFILE_SNAPSHOT_READS.set(0);

        discover_packages(dir.path()).unwrap();

        assert_eq!(FOREIGN_LOCKFILE_SNAPSHOT_READS.get(), 1);
    }

    #[test]
    fn pnpm_discovery_reads_one_lockfile_snapshot_for_each_supported_format() {
        for (version, key) in [
            ("5.4", "/once/1.0.0"),
            ("6.0", "/once@1.0.0"),
            ("9.0", "once@1.0.0"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(
                dir.path().join("pnpm-lock.yaml"),
                format!(
                    "lockfileVersion: '{version}'\npackages:\n  '{key}':\n    resolution:\n      tarball: https://registry.npmjs.org/once/-/once-1.0.0.tgz\n"
                ),
            )
            .unwrap();
            FOREIGN_LOCKFILE_SNAPSHOT_READS.set(0);

            let discovery = discover_packages(dir.path()).unwrap();

            assert_eq!(
                FOREIGN_LOCKFILE_SNAPSHOT_READS.get(),
                1,
                "pnpm lockfile version {version} was read more than once"
            );
            assert_eq!(discovery.packages.len(), 1);
        }
    }

    #[test]
    fn npm_parent_traversal_package_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "../node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("parent traversal must fail");

        assert!(error.to_string().contains("unsafe package path"));
    }

    #[cfg(unix)]
    #[test]
    fn npm_package_symlink_outside_project_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/escaped": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/escaped/-/escaped-1.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        symlink(outside.path(), dir.path().join("node_modules/escaped")).unwrap();

        let error = discover_packages(dir.path())
            .err()
            .expect("outside symlink must fail");

        assert!(error.to_string().contains("outside the project"));
    }

    #[cfg(windows)]
    #[test]
    fn node_modules_fallback_does_not_follow_package_junctions() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join("node_modules")).unwrap();
        fs::write(
            outside.path().join("package.json"),
            r#"{"name":"outside","version":"9.0.0"}"#,
        )
        .unwrap();
        lpm_common::create_dir_symlink_or_junction(
            outside.path(),
            &project.path().join("node_modules/outside"),
        )
        .unwrap();

        let discovery = discover_from_node_modules(project.path());

        assert!(discovery.packages.is_empty());
    }

    #[test]
    fn retained_lpm_snapshot_does_not_change_after_lockfile_replacement() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"snapshot","version":"1.0.0"}"#,
        )
        .unwrap();
        let lockfile_path = dir.path().join("lpm.lock");
        fs::write(
            &lockfile_path,
            format!(
                r#"[metadata]
lockfile-version = {}
resolved-with = "pubgrub"

[[packages]]
name = "before"
version = "1.0.0"
"#,
                lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            ),
        )
        .unwrap();
        let discovery = discover_packages_retaining_lpm_lockfile(dir.path()).unwrap();
        fs::write(
            &lockfile_path,
            format!(
                r#"[metadata]
lockfile-version = {}
resolved-with = "pubgrub"

[[packages]]
name = "after"
version = "2.0.0"
"#,
                lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            ),
        )
        .unwrap();

        let retained = discovery.lpm_lockfile.as_ref().unwrap();
        assert_eq!(retained.packages[0].name, "before");
        assert!(
            !crate::commands::install::workspace_lockfile::project_lockfile_unchanged(
                dir.path(),
                Some(retained)
            )
            .unwrap()
        );
    }
}
