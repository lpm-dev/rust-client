//! node_modules layout manager for LPM.
//!
//! Creates pnpm-style isolated node_modules with symlinks:
//!
//! ```text
//! node_modules/
//!   .lpm/                                    ← internal store
//!     express@4.22.1/
//!       node_modules/
//!         express/  → <global-store>         ← hardlink/copy from store
//!         debug/    → ../../debug@2.6.9/node_modules/debug
//!         send/     → ../../send@0.19.2/node_modules/send
//!     debug@2.6.9/
//!       node_modules/
//!         debug/    → <global-store>
//!         ms/       → ../../ms@2.0.0/node_modules/ms
//!   express/ → .lpm/express@4.22.1/node_modules/express   ← direct dep symlink
//! ```
//!
//! Properties:
//! - Only direct dependencies appear in root `node_modules/` as symlinks
//! - All packages live in `.lpm/` with their own `node_modules/` for their deps
//! - Strict isolation: phantom dependencies are not importable
//!
//! Compatibility: hoisted mode, Windows junctions, self-ref — see phase-20-todo.md.
//! Performance: incremental linking — see phase-18-todo.md.

use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// Validate a self-reference package name to prevent path traversal.
///
/// Returns `true` if the name is safe to use as a directory name under `node_modules/`.
fn is_valid_self_ref_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('\\')
        && !name.starts_with('/')
        && !name.contains('\0')
}

/// System binaries that packages should not shadow without warning.
const SHADOWED_BINARIES: &[&str] = &[
    "node", "npm", "npx", "sh", "bash", "zsh", "fish", "git", "curl", "wget", "sudo", "python",
    "python3", "ruby", "perl", "env", "cat", "ls", "rm", "cp", "mv", "mkdir", "chmod",
];

/// Validate a bin entry name. Returns `Ok(())` if the name is acceptable,
/// `Err(reason)` if it must be rejected entirely.
/// Logs a warning (but does not reject) for names that shadow common system binaries.
fn validate_bin_name(name: &str, pkg_name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("bin name is empty".to_string());
    }
    if name.contains('\0') {
        return Err("bin name contains null byte".to_string());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!(
            "bin name \"{name}\" contains path separators or traversal components"
        ));
    }

    // Warn (don't reject) for shadowing common system binaries
    if SHADOWED_BINARIES.contains(&name) {
        tracing::warn!(
            "package \"{pkg_name}\" declares bin \"{name}\" which shadows a common system binary"
        );
    }

    Ok(())
}

/// Validate that a bin script path does not escape its package directory via path traversal.
/// Returns `Ok(canonical_target)` with the validated canonical path, or `Err(reason)`.
fn validate_bin_target(pkg_dir: &Path, script_path: &str) -> Result<PathBuf, String> {
    // Quick reject: script_path must not contain `..` components
    let joined = pkg_dir.join(script_path);
    for component in joined.components() {
        if component == Component::ParentDir {
            return Err(format!(
                "bin target \"{script_path}\" contains path traversal (\"..\")"
            ));
        }
    }

    // Canonicalize and verify containment (the target file must exist for canonicalize)
    let canonical_target = joined
        .canonicalize()
        .map_err(|e| format!("cannot resolve bin target \"{script_path}\": {e}"))?;
    let canonical_pkg = pkg_dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve package dir: {e}"))?;

    if !canonical_target.starts_with(&canonical_pkg) {
        return Err(format!(
            "bin target \"{}\" resolves outside package directory \"{}\"",
            canonical_target.display(),
            canonical_pkg.display()
        ));
    }

    Ok(canonical_target)
}

/// Check if a path string contains cmd.exe metacharacters that could enable injection.
/// Returns `Err(reason)` if dangerous characters are found.
#[allow(dead_code)]
fn validate_cmd_path(path: &str) -> Result<(), String> {
    const DANGEROUS: &[char] = &['"', '&', '|', '<', '>', '^', '%', '\n', '\r'];
    for ch in DANGEROUS {
        if path.contains(*ch) {
            return Err(format!(
                "bin target path contains dangerous character '{ch}' for cmd.exe"
            ));
        }
    }
    Ok(())
}

/// Linking strategy for node_modules.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum LinkerMode {
    /// pnpm-style isolated layout (default). Strict, no phantom deps.
    #[default]
    Isolated,
    /// npm v3+ style hoisted layout. Flat, phantom deps accessible.
    Hoisted,
}

/// Create a symlink (Unix) or junction (Windows) from `link` pointing to `target`.
///
/// On Windows, NTFS junctions don't require admin privileges (unlike symlinks).
/// We use `cmd /c mklink /J` which handles junction creation natively.
/// Junctions require absolute paths, so we resolve relative targets before creating.
/// Falls back to `symlink_dir` if junction creation fails.
///
/// On Unix, creates a standard symlink (relative paths work fine).
#[cfg(windows)]
fn create_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    // Try symlink_dir first — works without admin on many modern Windows setups
    // (Developer Mode, or appropriate policy settings).
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return Ok(());
    }

    // Junctions require absolute target paths. If target is relative,
    // resolve it relative to the link's parent directory.
    let abs_target = if target.is_relative() {
        let base = link.parent().unwrap_or(Path::new("."));
        match base.canonicalize() {
            Ok(abs_base) => abs_base.join(target),
            Err(_) => base.join(target),
        }
    } else {
        target.to_path_buf()
    };

    // Validate paths before passing to cmd to prevent command injection.
    let link_str = link.to_string_lossy();
    let target_str = abs_target.to_string_lossy();
    if let Err(reason) = validate_cmd_path(&link_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: link path {reason}"),
        ));
    }
    if let Err(reason) = validate_cmd_path(&target_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: target path {reason}"),
        ));
    }

    // Fallback: junction via cmd /c mklink /J (no admin required)
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J", &link_str, &target_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to create junction or symlink",
        )),
    }
}

#[cfg(unix)]
fn create_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// A package to be linked into node_modules.
#[derive(Debug, Clone)]
pub struct LinkTarget {
    /// Package name (e.g., "express", "@types/node").
    pub name: String,
    /// Exact version string.
    pub version: String,
    /// Path to the package in the global store.
    pub store_path: PathBuf,
    /// Dependencies of this package: (dep_name, dep_version).
    pub dependencies: Vec<(String, String)>,
    /// Whether this is a direct dependency of the root project.
    pub is_direct: bool,
}

/// Create the pnpm-style node_modules layout.
///
/// # Arguments
/// * `project_dir` - The project root (where node_modules/ will be created)
/// * `packages` - All resolved packages with their store paths and dependencies
/// * `force` - When true, ignore `.linked` marker files and re-link everything
/// * `self_package_name` - If set, creates a self-referencing symlink so the package
///   can `require("itself")`. This is a node_modules/<name> → project_dir symlink.
///   Skipped if a direct dependency already occupies that name.
pub fn link_packages(
    project_dir: &Path,
    packages: &[LinkTarget],
    force: bool,
    self_package_name: Option<&str>,
) -> Result<LinkResult, LpmError> {
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = node_modules.join(".lpm");

    // Create base directories
    std::fs::create_dir_all(&lpm_dir)?;

    let mut linked_count = 0;
    let mut symlinked_count = 0;
    let mut skipped_count = 0;

    // Incremental: collect expected entries so we can clean up stale ones
    let expected_entries: std::collections::HashSet<String> = packages
        .iter()
        .map(|p| {
            let safe = p.name.replace('/', "+");
            format!("{safe}@{}", p.version)
        })
        .collect();

    // Clean up stale .lpm entries that are no longer in the resolution
    if let Ok(entries) = std::fs::read_dir(&lpm_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !expected_entries.contains(&name) {
                let _ = std::fs::remove_dir_all(entry.path());
                tracing::debug!("incremental: removed stale .lpm/{name}");
            }
        }
    }

    // Also clean up stale root symlinks
    if let Ok(entries) = std::fs::read_dir(&node_modules) {
        let direct_names: std::collections::HashSet<&str> = packages
            .iter()
            .filter(|p| p.is_direct)
            .map(|p| p.name.as_str())
            .collect();

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".lpm" || name.starts_with('.') {
                continue;
            }
            // For scoped packages, check the full path
            let full_name = if entry.path().is_dir() && name.starts_with('@') {
                // Check children of scope dir
                if let Ok(scope_entries) = std::fs::read_dir(entry.path()) {
                    for se in scope_entries.flatten() {
                        let scoped_name = format!("{name}/{}", se.file_name().to_string_lossy());
                        if !direct_names.contains(scoped_name.as_str())
                            && se
                                .path()
                                .symlink_metadata()
                                .map(|m| m.file_type().is_symlink())
                                .unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(se.path());
                            tracing::debug!(
                                "incremental: removed stale root symlink {scoped_name}"
                            );
                        }
                    }
                }
                continue;
            } else {
                name.clone()
            };
            if !direct_names.contains(full_name.as_str())
                && entry
                    .path()
                    .symlink_metadata()
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            {
                let _ = std::fs::remove_file(entry.path());
                tracing::debug!("incremental: removed stale root symlink {full_name}");
            }
        }
    }

    // Phase 1: Create .lpm/<name>@<version>/node_modules/<name> for each package
    for pkg in packages {
        let safe_name = pkg.name.replace('/', "+");
        let pkg_entry_dir = lpm_dir.join(format!("{safe_name}@{}", pkg.version));
        let marker_path = pkg_entry_dir.join(".linked");

        // NOTE: The .linked marker check is not atomic with the linking operation.
        // A local attacker with filesystem access could plant a fake marker to prevent
        // re-linking. However, local filesystem access already implies full compromise
        // (can modify node_modules directly), so this is an accepted risk.
        // The marker is a performance optimization, not a security boundary.

        // Incremental: skip packages that already have a completed link marker
        if !force && marker_path.exists() {
            skipped_count += 1;
            tracing::debug!(
                "incremental: skipping {safe_name}@{} (marker present)",
                pkg.version
            );
            continue;
        }

        let pkg_nm = pkg_entry_dir.join("node_modules").join(&pkg.name);

        // Clean up interrupted links (directory exists but marker absent)
        if !force && pkg_nm.exists() && !marker_path.exists() {
            tracing::debug!("cleaning up interrupted link for {}", safe_name);
            let _ = std::fs::remove_dir_all(&pkg_nm);
        }

        if !pkg_nm.exists() {
            // Create parent dirs (handles scoped packages like @types/node)
            if let Some(parent) = pkg_nm.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Hardlink from global store (zero disk cost on same filesystem)
            link_dir_recursive(&pkg.store_path, &pkg_nm)?;
            linked_count += 1;
        }

        // Write marker after successful link (empty file, cheap to create)
        if let Err(e) = std::fs::write(&marker_path, "") {
            tracing::warn!(
                "failed to write link marker for {}@{}: {}",
                safe_name,
                pkg.version,
                e
            );
        }
    }

    // Phase 2: Create internal symlinks for transitive dependencies
    for pkg in packages {
        let safe_name = pkg.name.replace('/', "+");
        let pkg_nm_dir = lpm_dir
            .join(format!("{safe_name}@{}", pkg.version))
            .join("node_modules");

        for (dep_name, dep_version) in &pkg.dependencies {
            let dep_link = pkg_nm_dir.join(dep_name);

            if dep_link.exists() || dep_link.symlink_metadata().is_ok() {
                continue;
            }

            // Create parent for scoped packages
            if let Some(parent) = dep_link.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Symlink to the dep's location in .lpm/
            // Base: ../../<dep>@<ver>/node_modules/<dep>
            // For scoped deps like @types/node, the symlink is at
            // .lpm/<pkg>/node_modules/@types/node — one extra level deep.
            // Need ../../../ instead of ../../ to traverse up from the scope dir.
            let safe_dep = dep_name.replace('/', "+");
            let depth = 2 + dep_name.matches('/').count();
            let mut target = PathBuf::new();
            for _ in 0..depth {
                target.push("..");
            }
            target.push(format!("{safe_dep}@{dep_version}"));
            target.push("node_modules");
            target.push(dep_name);

            create_symlink_or_junction(&target, &dep_link)?;

            symlinked_count += 1;
        }
    }

    // Phase 3: Create root symlinks for direct dependencies
    for pkg in packages.iter().filter(|p| p.is_direct) {
        let root_link = node_modules.join(&pkg.name);

        if root_link.exists() || root_link.symlink_metadata().is_ok() {
            continue;
        }

        // Create parent for scoped packages
        if let Some(parent) = root_link.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let safe_name = pkg.name.replace('/', "+");

        // For scoped packages like @lpm.dev/neo.colors, the symlink lives at
        // node_modules/@lpm.dev/neo.colors, which is one level deeper than root.
        // We need "../.lpm/..." instead of ".lpm/..." to traverse up from the scope dir.
        let depth = pkg.name.matches('/').count();
        let mut target = PathBuf::new();
        for _ in 0..depth {
            target.push("..");
        }
        target.push(".lpm");
        target.push(format!("{safe_name}@{}", pkg.version));
        target.push("node_modules");
        target.push(&pkg.name);

        create_symlink_or_junction(&target, &root_link)?;

        symlinked_count += 1;
    }

    // Phase 3.5: Self-reference — package can require("itself")
    // Creates node_modules/<name> → project_dir so the package can import itself
    // by name. This matches npm/pnpm behavior. Only created if the name slot
    // isn't already taken by a direct dependency.
    let mut self_referenced = false;
    if let Some(self_name) = self_package_name {
        if !is_valid_self_ref_name(self_name) {
            tracing::warn!(
                "skipping self-reference for invalid package name: {}",
                self_name
            );
        } else {
            let self_link = node_modules.join(self_name);
            if !self_link.exists() && self_link.symlink_metadata().is_err() {
                // Handle scoped packages: create @scope/ directory first
                if self_name.starts_with('@')
                    && let Some(scope_dir) = self_link.parent()
                {
                    let _ = std::fs::create_dir_all(scope_dir);
                }
                // Symlink node_modules/{name} → project root
                // For scoped packages, we need to go up one extra level
                let depth = self_name.matches('/').count();
                let mut target = PathBuf::new();
                for _ in 0..depth {
                    target.push("..");
                }
                target.push(".."); // up from node_modules/
                create_symlink_or_junction(&target, &self_link)?;
                self_referenced = true;
                symlinked_count += 1;
            }
        } // else (valid self-ref name)
    }

    // Phase 4: Create node_modules/.bin/ with executable symlinks
    let bin_count = create_bin_links(&node_modules, &lpm_dir, packages)?;

    Ok(LinkResult {
        linked: linked_count,
        symlinked: symlinked_count,
        bin_linked: bin_count,
        skipped: skipped_count,
        self_referenced,
    })
}

/// Create the npm v3+ style hoisted node_modules layout.
///
/// All packages are placed directly into `node_modules/` (flat). When two packages
/// need different versions of the same dependency, the direct dependency (or the
/// first encountered) wins the root position, and the other is nested under its
/// dependent's `node_modules/`.
///
/// Layout:
/// ```text
/// node_modules/
///   express/    -> <store>   (hoisted)
///   debug/      -> <store>   (hoisted, version used by express)
///   ms/         -> <store>   (hoisted)
///   other-pkg/
///     node_modules/
///       debug/  -> <store>   (nested, different version than root)
/// ```
pub fn link_packages_hoisted(
    project_dir: &Path,
    packages: &[LinkTarget],
    force: bool,
) -> Result<LinkResult, LpmError> {
    let node_modules = project_dir.join("node_modules");

    // Clean up old node_modules contents (but keep .bin/ and .lpm/)
    if node_modules.exists()
        && force
        && let Ok(entries) = std::fs::read_dir(&node_modules)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name != ".bin" && name != ".lpm" {
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    std::fs::create_dir_all(&node_modules)?;

    // Phase 1: Determine hoisting layout.
    //
    // Build a dependency graph so we can figure out which package "depends on"
    // which conflicting version. The algorithm:
    //   1. Walk all packages in order. Try to claim the root node_modules/<name> slot.
    //   2. If a name is already claimed by a different version, decide who gets root:
    //      - Direct deps always win root over transitive deps.
    //      - Among equal priority, first-come-first-served (stable for determinism).
    //   3. The loser gets nested under one of its dependents.
    let mut hoisted: HashMap<String, usize> = HashMap::with_capacity(packages.len());
    // (package_index, parent_name) -- packages that must be nested
    let mut nested: Vec<(usize, String)> = Vec::new();

    // Build a reverse-dependency map: (package_name, version) -> list of dependent names.
    // Used to decide where to nest a conflicting package.
    let mut depended_by: HashMap<(String, String), Vec<String>> = HashMap::new();
    for pkg in packages {
        for (dep_name, dep_ver) in &pkg.dependencies {
            depended_by
                .entry((dep_name.clone(), dep_ver.clone()))
                .or_default()
                .push(pkg.name.clone());
        }
    }

    for (idx, pkg) in packages.iter().enumerate() {
        if let Some(&existing_idx) = hoisted.get(&pkg.name) {
            let existing = &packages[existing_idx];
            if existing.version == pkg.version {
                // Same name, same version: already hoisted, skip duplicate.
                continue;
            }
            // Version conflict. Direct dep wins root position.
            if pkg.is_direct && !existing.is_direct {
                // Evict existing to nested, hoist the new one.
                let parent = depended_by
                    .get(&(existing.name.clone(), existing.version.clone()))
                    .and_then(|v: &Vec<String>| v.first().cloned())
                    .unwrap_or_else(|| pkg.name.clone());
                nested.push((existing_idx, parent));
                hoisted.insert(pkg.name.clone(), idx);
            } else {
                // Keep existing at root, nest the new one.
                let parent = depended_by
                    .get(&(pkg.name.clone(), pkg.version.clone()))
                    .and_then(|v: &Vec<String>| v.first().cloned())
                    .unwrap_or_else(|| existing.name.clone());
                nested.push((idx, parent));
            }
        } else {
            hoisted.insert(pkg.name.clone(), idx);
        }
    }

    let mut linked_count = 0;

    // Phase 2: Link hoisted packages directly into root node_modules/
    for (name, &pkg_idx) in &hoisted {
        let pkg = &packages[pkg_idx];
        let target_dir = node_modules.join(name);

        if target_dir.exists() {
            continue;
        }

        // Handle scoped packages (@scope/name -> create @scope/ dir first)
        if name.starts_with('@')
            && let Some(parent) = target_dir.parent()
        {
            std::fs::create_dir_all(parent)?;
        }

        link_dir_recursive(&pkg.store_path, &target_dir)?;
        linked_count += 1;
    }

    // Phase 3: Link nested (conflicting) packages under their parent's node_modules/
    for (pkg_idx, parent_name) in &nested {
        let pkg = &packages[*pkg_idx];

        // Find the parent's root location (it should be hoisted)
        let parent_nm = if hoisted.contains_key(parent_name) {
            // Parent is at node_modules/<parent_name>, nest under
            // node_modules/<parent_name>/node_modules/<pkg_name>
            node_modules.join(parent_name).join("node_modules")
        } else {
            // Parent is itself nested; fall back to nesting under root .lpm/
            // This is rare but handles deep conflicts.
            node_modules.join(".lpm").join("nested")
        };

        let nested_dir = parent_nm.join(&pkg.name);
        if nested_dir.exists() {
            continue;
        }

        // Handle scoped packages
        if let Some(parent) = nested_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }

        link_dir_recursive(&pkg.store_path, &nested_dir)?;
        linked_count += 1;
    }

    // Phase 4: Binary links for hoisted packages.
    let bin_count = create_bin_links_hoisted(&node_modules, packages, &hoisted)?;

    Ok(LinkResult {
        linked: linked_count,
        symlinked: 0, // hoisted mode uses direct copies, not symlinks
        bin_linked: bin_count,
        skipped: 0,
        self_referenced: false,
    })
}

/// Create bin links for hoisted mode.
///
/// In hoisted mode, packages live directly in `node_modules/<name>/` rather than
/// `.lpm/<name>@<ver>/node_modules/<name>/`. We read package.json from the
/// hoisted location.
fn create_bin_links_hoisted(
    node_modules: &Path,
    packages: &[LinkTarget],
    hoisted: &HashMap<String, usize>,
) -> Result<usize, LpmError> {
    let bin_dir = node_modules.join(".bin");
    let mut count = 0;

    for (name, &pkg_idx) in hoisted {
        let pkg = &packages[pkg_idx];
        let pkg_dir = node_modules.join(name);

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "skipping bin links for {}: failed to parse package.json: {e}",
                    pkg.name
                );
                continue;
            }
        };

        let bin_config = match &pkg_json.bin {
            Some(b) => b,
            None => continue,
        };

        let pkg_name = pkg_json.name.as_deref().unwrap_or(&pkg.name);
        let entries = bin_config.entries(pkg_name);

        if entries.is_empty() {
            continue;
        }

        std::fs::create_dir_all(&bin_dir)?;

        for (cmd_name, script_path) in &entries {
            // Finding #2: validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Finding #1: validate bin target path (no traversal)
            let target = match validate_bin_target(&pkg_dir, script_path) {
                Ok(t) => t,
                Err(reason) => {
                    tracing::warn!("bin: rejecting {cmd_name} from {pkg_name}: {reason}");
                    continue;
                }
            };

            let bin_link = bin_dir.join(cmd_name);

            if bin_link.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&bin_link);
            }

            // Finding #13: use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target =
                    pathdiff::diff_paths(&target, &bin_dir).unwrap_or_else(|| target.clone());
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Finding #6: add execute only (0o111), not full 0o755
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&target) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(mode | 0o111),
                        )?;
                    }
                }
            }

            #[cfg(windows)]
            {
                let target_str = target.to_string_lossy();
                // Finding #3: validate target path before interpolating into .cmd
                if let Err(reason) = validate_cmd_path(&target_str) {
                    tracing::warn!("bin: skipping .cmd shim for {cmd_name}: {reason}");
                    continue;
                }
                let cmd_content = format!(
                    "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
                );
                let cmd_path = bin_dir.join(format!("{cmd_name}.cmd"));
                std::fs::write(&cmd_path, cmd_content)?;
            }

            tracing::debug!("bin: {cmd_name} -> {}", target.display());
            count += 1;
        }
    }

    Ok(count)
}

/// Create `node_modules/.bin/` directory with symlinks to package executables.
///
/// Reads each package's `package.json` for the `"bin"` field and creates
/// executable symlinks in `node_modules/.bin/`.
pub fn create_bin_links(
    node_modules: &Path,
    lpm_dir: &Path,
    packages: &[LinkTarget],
) -> Result<usize, LpmError> {
    let bin_dir = node_modules.join(".bin");
    let mut count = 0;

    for pkg in packages {
        let safe_name = pkg.name.replace('/', "+");
        let pkg_dir = lpm_dir
            .join(format!("{safe_name}@{}", pkg.version))
            .join("node_modules")
            .join(&pkg.name);

        let pkg_json_path = pkg_dir.join("package.json");
        if !pkg_json_path.exists() {
            continue;
        }

        // Read the bin field from the installed package's package.json
        let pkg_json = match lpm_workspace::read_package_json(&pkg_json_path) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    "skipping bin links for {}: failed to parse package.json: {e}",
                    pkg.name
                );
                continue;
            }
        };

        let bin_config = match &pkg_json.bin {
            Some(b) => b,
            None => continue,
        };

        let pkg_name = pkg_json.name.as_deref().unwrap_or(&pkg.name);
        let entries = bin_config.entries(pkg_name);

        if entries.is_empty() {
            continue;
        }

        // Create .bin dir only if we have entries
        std::fs::create_dir_all(&bin_dir)?;

        for (cmd_name, script_path) in &entries {
            // Finding #2: validate bin name
            if let Err(reason) = validate_bin_name(cmd_name, pkg_name) {
                tracing::warn!("bin: rejecting \"{cmd_name}\" from {pkg_name}: {reason}");
                continue;
            }

            // Finding #1: validate bin target path (no traversal)
            let target = match validate_bin_target(&pkg_dir, script_path) {
                Ok(t) => t,
                Err(reason) => {
                    tracing::warn!("bin: rejecting {cmd_name} from {pkg_name}: {reason}");
                    continue;
                }
            };

            let bin_link = bin_dir.join(cmd_name);

            // Remove existing link if present
            if bin_link.symlink_metadata().is_ok() {
                let _ = std::fs::remove_file(&bin_link);
            }

            // Finding #13: use relative symlinks for portability
            #[cfg(unix)]
            {
                let rel_target =
                    pathdiff::diff_paths(&target, &bin_dir).unwrap_or_else(|| target.clone());
                std::os::unix::fs::symlink(&rel_target, &bin_link)?;

                // Finding #6: add execute only (0o111), not full 0o755
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&target) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(mode | 0o111),
                        )?;
                    }
                }
            }

            #[cfg(windows)]
            {
                let target_str = target.to_string_lossy();
                // Finding #3: validate target path before interpolating into .cmd
                if let Err(reason) = validate_cmd_path(&target_str) {
                    tracing::warn!("bin: skipping .cmd shim for {cmd_name}: {reason}");
                    continue;
                }
                let cmd_content = format!(
                    "@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
                );
                let cmd_path = bin_dir.join(format!("{cmd_name}.cmd"));
                std::fs::write(&cmd_path, cmd_content)?;
            }

            tracing::debug!("bin: {cmd_name} → {}", target.display());
            count += 1;
        }
    }

    Ok(count)
}

/// Result of the linking operation.
#[derive(Debug)]
pub struct LinkResult {
    /// Number of packages copied from store.
    pub linked: usize,
    /// Number of symlinks created.
    pub symlinked: usize,
    /// Number of bin links created.
    pub bin_linked: usize,
    /// Number of packages skipped (already linked, marker present).
    pub skipped: usize,
    /// Whether a self-referencing symlink was created for the project package.
    pub self_referenced: bool,
}

/// Recursively link a directory from the global store into node_modules.
///
/// Strategy priority:
/// 1. macOS APFS: `clonefile()` (copy-on-write, instant, zero disk cost until modified)
/// 2. Hardlink (same filesystem, zero disk cost, shared inode)
/// 3. Copy (fallback for cross-device or permissions)
fn link_dir_recursive(src: &Path, dst: &Path) -> Result<(), LpmError> {
    // On macOS, try clonefile first (copies entire directory tree as CoW in one syscall)
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            return Ok(());
        }
    }

    // Fallback: file-by-file hardlink/copy
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            link_dir_recursive(&src_path, &dst_path)?;
        } else {
            // Try hardlink first (instant, zero disk cost on same filesystem)
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                // Fallback to copy
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }

    Ok(())
}

/// Try to use macOS `clonefile()` syscall for instant copy-on-write.
/// Returns true if successful, false if not (caller should fall back).
#[cfg(target_os = "macos")]
fn try_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = match CString::new(src.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dst_c = match CString::new(dst.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // clonefile(src, dst, flags) — flag 0 = no special flags
    // Returns 0 on success, -1 on failure
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };

    if result == 0 {
        tracing::debug!("clonefile: {} → {}", src.display(), dst.display());
        true
    } else {
        false
    }
}

// Declare the libc clonefile function for macOS
#[cfg(target_os = "macos")]
mod libc {
    unsafe extern "C" {
        pub fn clonefile(
            src: *const std::os::raw::c_char,
            dst: *const std::os::raw::c_char,
            flags: u32,
        ) -> std::os::raw::c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_fake_store_package(dir: &Path, name: &str) -> PathBuf {
        let pkg_dir = dir.join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!("{{\"name\":\"{name}\"}}"),
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "module.exports = {}").unwrap();
        pkg_dir
    }

    #[test]
    fn link_single_direct_dep() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.linked, 1);

        // Root symlink exists
        let root_link = project_dir.path().join("node_modules/foo");
        assert!(root_link.symlink_metadata().is_ok());

        // Can read through symlink
        assert!(root_link.join("package.json").exists());
    }

    #[test]
    fn link_with_transitive_dep() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                is_direct: true,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![],
                is_direct: false,
            },
        ];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // express is accessible from root
        assert!(
            project_dir
                .path()
                .join("node_modules/express")
                .symlink_metadata()
                .is_ok()
        );

        // debug is NOT in root (it's transitive)
        assert!(
            !project_dir
                .path()
                .join("node_modules/debug")
                .symlink_metadata()
                .is_ok()
        );

        // debug IS accessible from express's node_modules
        let express_debug = project_dir
            .path()
            .join("node_modules/.lpm/express@4.22.1/node_modules/debug");
        assert!(express_debug.symlink_metadata().is_ok());

        assert!(result.linked >= 2);
    }

    #[test]
    fn lpm_dir_created() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "x");

        link_packages(
            project_dir.path(),
            &[LinkTarget {
                name: "x".to_string(),
                version: "1.0.0".to_string(),
                store_path,
                dependencies: vec![],
                is_direct: true,
            }],
            false,
            None,
        )
        .unwrap();

        assert!(project_dir.path().join("node_modules/.lpm").is_dir());
    }

    fn create_fake_store_package_with_bin(dir: &Path, name: &str, bin_field: &str) -> PathBuf {
        let pkg_dir = dir.join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!("{{\"name\":\"{name}\",\"bin\":{bin_field}}}"),
        )
        .unwrap();
        std::fs::write(
            pkg_dir.join("cli.js"),
            "#!/usr/bin/env node\nconsole.log('hi')",
        )
        .unwrap();
        pkg_dir
    }

    #[test]
    fn bin_links_created_for_string_bin() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path =
            create_fake_store_package_with_bin(store_dir.path(), "my-tool", "\"./cli.js\"");

        let packages = vec![LinkTarget {
            name: "my-tool".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 1);

        let bin_link = project_dir.path().join("node_modules/.bin/my-tool");
        assert!(
            bin_link.symlink_metadata().is_ok(),
            ".bin/my-tool should exist"
        );
    }

    #[test]
    fn bin_links_created_for_map_bin() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package_with_bin(
            store_dir.path(),
            "multi-bin",
            "{\"cmd-a\": \"./cli.js\", \"cmd-b\": \"./cli.js\"}",
        );

        let packages = vec![LinkTarget {
            name: "multi-bin".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 2);

        assert!(
            project_dir
                .path()
                .join("node_modules/.bin/cmd-a")
                .symlink_metadata()
                .is_ok()
        );
        assert!(
            project_dir
                .path()
                .join("node_modules/.bin/cmd-b")
                .symlink_metadata()
                .is_ok()
        );
    }

    #[test]
    fn no_bin_dir_without_bins() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        // Package without "bin" field
        let store_path = create_fake_store_package(store_dir.path(), "no-bin");

        let packages = vec![LinkTarget {
            name: "no-bin".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 0);
        assert!(!project_dir.path().join("node_modules/.bin").exists());
    }

    #[test]
    fn incremental_link_creates_marker() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        link_packages(project_dir.path(), &packages, false, None).unwrap();

        // Marker file should exist after linking
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/foo@1.0.0/.linked");
        assert!(
            marker.exists(),
            ".linked marker should be created after linking"
        );
    }

    #[test]
    fn incremental_link_skips_if_marker_present() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "bar");

        let packages = vec![LinkTarget {
            name: "bar".to_string(),
            version: "2.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        // First link — creates everything
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);
        assert_eq!(result1.skipped, 0);

        // Second link — marker present, should skip
        let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result2.linked, 0);
        assert_eq!(result2.skipped, 1);

        // Files still accessible through symlinks
        assert!(
            project_dir
                .path()
                .join("node_modules/bar/package.json")
                .exists()
        );
    }

    #[test]
    fn incremental_link_relinks_if_marker_missing() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "baz");

        let packages = vec![LinkTarget {
            name: "baz".to_string(),
            version: "3.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        // First link — creates marker
        let result1 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result1.linked, 1);

        // Delete marker to simulate corruption/manual cleanup
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/baz@3.0.0/.linked");
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();

        // Remove the linked package dir to force re-link
        let pkg_dir = project_dir
            .path()
            .join("node_modules/.lpm/baz@3.0.0/node_modules/baz");
        std::fs::remove_dir_all(&pkg_dir).unwrap();

        // Re-link — marker gone, should re-link
        let result2 = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result2.linked, 1);
        assert_eq!(result2.skipped, 0);

        // Marker should be re-created
        assert!(marker.exists());
    }

    #[test]
    fn force_relinks_despite_marker() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "qux");

        let packages = vec![LinkTarget {
            name: "qux".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        // First link
        link_packages(project_dir.path(), &packages, false, None).unwrap();
        let marker = project_dir
            .path()
            .join("node_modules/.lpm/qux@1.0.0/.linked");
        assert!(marker.exists());

        // Force re-link — should NOT skip despite marker
        let result = link_packages(project_dir.path(), &packages, true, None).unwrap();
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn self_reference_created_for_named_package() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result =
            link_packages(project_dir.path(), &packages, false, Some("my-project")).unwrap();
        assert!(result.self_referenced);

        // Self-reference symlink should exist
        let self_link = project_dir.path().join("node_modules/my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "self-reference symlink should exist"
        );
    }

    #[test]
    fn self_reference_scoped_creates_scope_dir() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(
            project_dir.path(),
            &packages,
            false,
            Some("@myorg/my-project"),
        )
        .unwrap();
        assert!(result.self_referenced);

        // Scope directory should be created
        let scope_dir = project_dir.path().join("node_modules/@myorg");
        assert!(scope_dir.is_dir(), "@myorg scope dir should exist");

        // Self-reference symlink should exist
        let self_link = project_dir.path().join("node_modules/@myorg/my-project");
        assert!(
            self_link.symlink_metadata().is_ok(),
            "scoped self-reference symlink should exist"
        );
    }

    #[test]
    fn no_self_reference_without_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert!(!result.self_referenced);
    }

    #[test]
    fn self_reference_skipped_when_dep_exists_with_same_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "conflicting");

        // Direct dep has the same name as the self-reference
        let packages = vec![LinkTarget {
            name: "conflicting".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        // Self-package name matches a direct dep — dep should win
        let result =
            link_packages(project_dir.path(), &packages, false, Some("conflicting")).unwrap();
        assert!(
            !result.self_referenced,
            "self-reference should be skipped when dep occupies the name"
        );

        // The link should point to the dep, not the project root
        let link = project_dir.path().join("node_modules/conflicting");
        assert!(link.symlink_metadata().is_ok());
    }

    // ---- Hoisted mode tests ----

    #[test]
    fn hoisted_mode_flattens_all_packages() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_store = create_fake_store_package(store_dir.path(), "debug");
        let ms_store = create_fake_store_package(store_dir.path(), "ms");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                is_direct: true,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_store,
                dependencies: vec![("ms".to_string(), "2.0.0".to_string())],
                is_direct: false,
            },
            LinkTarget {
                name: "ms".to_string(),
                version: "2.0.0".to_string(),
                store_path: ms_store,
                dependencies: vec![],
                is_direct: false,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();
        assert_eq!(result.linked, 3);

        // All packages should be at root node_modules/
        assert!(project_dir.path().join("node_modules/express").exists());
        assert!(project_dir.path().join("node_modules/debug").exists());
        assert!(project_dir.path().join("node_modules/ms").exists());
    }

    #[test]
    fn hoisted_mode_nests_conflicts() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let express_store = create_fake_store_package(store_dir.path(), "express");
        let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
        let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");
        let other_store = create_fake_store_package(store_dir.path(), "other");

        let packages = vec![
            LinkTarget {
                name: "express".to_string(),
                version: "4.22.1".to_string(),
                store_path: express_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                is_direct: true,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                is_direct: false,
            },
            LinkTarget {
                name: "other".to_string(),
                version: "1.0.0".to_string(),
                store_path: other_store,
                dependencies: vec![("debug".to_string(), "3.0.0".to_string())],
                is_direct: true,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                is_direct: false,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();

        // One debug at root, one nested
        assert!(project_dir.path().join("node_modules/debug").exists());

        // The conflicting version should be nested under its dependent
        let nested_debug = project_dir
            .path()
            .join("node_modules/other/node_modules/debug");
        assert!(
            nested_debug.exists(),
            "conflicting debug version should be nested under its dependent"
        );

        // Total linked = express + debug@root + other + debug@nested = 4
        assert_eq!(result.linked, 4);
    }

    #[test]
    fn hoisted_mode_prefers_direct_deps() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let parent_store = create_fake_store_package(store_dir.path(), "parent");
        let debug_v2_store = create_fake_store_package(store_dir.path(), "debug-v2");
        let debug_v3_store = create_fake_store_package(store_dir.path(), "debug-v3");

        let packages = vec![
            LinkTarget {
                name: "parent".to_string(),
                version: "1.0.0".to_string(),
                store_path: parent_store,
                dependencies: vec![("debug".to_string(), "2.6.9".to_string())],
                is_direct: true,
            },
            LinkTarget {
                name: "debug".to_string(),
                version: "2.6.9".to_string(),
                store_path: debug_v2_store,
                dependencies: vec![],
                is_direct: false,
            },
            // Direct dep with different version should win root
            LinkTarget {
                name: "debug".to_string(),
                version: "3.0.0".to_string(),
                store_path: debug_v3_store,
                dependencies: vec![],
                is_direct: true,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();

        // debug at root should exist
        assert!(project_dir.path().join("node_modules/debug").exists());

        // The direct dep (3.0.0) should have won root position.
        // The transitive (2.6.9) should be nested under "parent".
        let nested_debug = project_dir
            .path()
            .join("node_modules/parent/node_modules/debug");
        assert!(
            nested_debug.exists(),
            "transitive debug should be nested under parent"
        );

        assert!(result.linked >= 3);
    }

    // ---- Security audit tests ----

    // Finding #1: Path traversal in bin targets
    #[test]
    fn bin_target_path_traversal_rejected() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        // Create an "outside" file that the traversal would target
        let outside_file = store_dir.path().join("outside_secret");
        std::fs::write(&outside_file, "secret data").unwrap();

        // Create a package whose bin points to ../../outside_secret
        let pkg_name = "evil-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
        )
        .unwrap();
        // Create a dummy file so the package dir exists but the target escapes
        std::fs::write(pkg_dir.join("index.js"), "").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // The traversal bin should be rejected — no bin link created
        assert_eq!(
            result.bin_linked, 0,
            "path traversal bin target should be rejected"
        );

        // Verify no symlink was created in .bin/
        let bin_link = project_dir.path().join("node_modules/.bin/evil");
        assert!(
            !bin_link.symlink_metadata().is_ok(),
            "no symlink should exist for path-traversing bin"
        );
    }

    // Finding #2: Bin name validation
    #[test]
    fn bin_name_with_path_separator_rejected() {
        assert!(validate_bin_name("../escape", "pkg").is_err());
    }

    #[test]
    fn bin_name_empty_rejected() {
        assert!(validate_bin_name("", "pkg").is_err());
    }

    #[test]
    fn bin_name_normal_allowed() {
        assert!(validate_bin_name("normal-cli", "pkg").is_ok());
    }

    #[test]
    fn bin_name_node_warns_but_allowed() {
        // "node" should be allowed (Ok) but logs a warning
        assert!(validate_bin_name("node", "pkg").is_ok());
    }

    #[test]
    fn bin_name_with_null_byte_rejected() {
        assert!(validate_bin_name("bad\0name", "pkg").is_err());
    }

    #[test]
    fn bin_name_with_backslash_rejected() {
        assert!(validate_bin_name("bad\\name", "pkg").is_err());
    }

    // Finding #3: Windows cmd shim injection
    #[test]
    fn cmd_path_with_metacharacters_rejected() {
        assert!(validate_cmd_path(r#"" & whoami & echo ""#).is_err());
        assert!(validate_cmd_path("normal/path/to/script.js").is_ok());
        assert!(validate_cmd_path("path|injection").is_err());
        assert!(validate_cmd_path("path<injection").is_err());
        assert!(validate_cmd_path("path>injection").is_err());
        assert!(validate_cmd_path("path^injection").is_err());
        assert!(validate_cmd_path("path%injection").is_err());
        assert!(validate_cmd_path("path\ninjection").is_err());
    }

    // Finding #5: Validate cmd paths for junction creation
    #[test]
    fn validate_cmd_path_rejects_ampersand() {
        assert!(validate_cmd_path("C:\\foo & del C:\\").is_err());
    }

    #[test]
    fn validate_cmd_path_allows_normal_path() {
        assert!(validate_cmd_path("C:\\Users\\foo\\node_modules").is_ok());
    }

    // Finding #6: Permission bits
    #[cfg(unix)]
    #[test]
    fn permission_bits_add_execute_only() {
        // mode | 0o111 should add execute without adding write for group/other
        let original_mode: u32 = 0o644;
        let fixed = original_mode | 0o111;
        assert_eq!(fixed, 0o755, "644 | 111 should be 755");

        let original_mode_2: u32 = 0o600;
        let fixed_2 = original_mode_2 | 0o111;
        assert_eq!(fixed_2, 0o711, "600 | 111 should be 711, not 755");

        // Prove the old code was wrong:
        let old_broken: u32 = 0o600 | 0o755;
        assert_eq!(old_broken, 0o755, "old code would force 755 regardless");
        assert_ne!(
            fixed_2, old_broken,
            "new code preserves restrictive permissions"
        );
    }

    // Finding #13: Relative symlinks
    #[cfg(unix)]
    #[test]
    fn bin_links_use_relative_symlinks() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path =
            create_fake_store_package_with_bin(store_dir.path(), "rel-tool", "\"./cli.js\"");

        let packages = vec![LinkTarget {
            name: "rel-tool".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(result.bin_linked, 1);

        let bin_link = project_dir.path().join("node_modules/.bin/rel-tool");
        assert!(
            bin_link.symlink_metadata().is_ok(),
            ".bin/rel-tool should exist"
        );

        // Read the symlink target and verify it's relative
        let link_target = std::fs::read_link(&bin_link).unwrap();
        assert!(
            !link_target.is_absolute(),
            "bin symlink should be relative, got: {}",
            link_target.display()
        );
    }

    // Finding #1 in hoisted mode
    #[test]
    fn bin_target_path_traversal_rejected_hoisted() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let outside_file = store_dir.path().join("outside_secret");
        std::fs::write(&outside_file, "secret data").unwrap();

        let pkg_name = "evil-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"evil-pkg","bin":{"evil":"../../outside_secret"}}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "path traversal bin target should be rejected in hoisted mode"
        );
    }

    // Finding #2 integration: bin name ../escape should not create a link
    #[test]
    fn bin_name_escape_not_linked() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let pkg_name = "escape-pkg";
        let pkg_dir = store_dir.path().join(pkg_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"escape-pkg","bin":{"../escape":"./cli.js"}}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("cli.js"), "#!/usr/bin/env node").unwrap();

        let packages = vec![LinkTarget {
            name: pkg_name.to_string(),
            version: "1.0.0".to_string(),
            store_path: pkg_dir,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();
        assert_eq!(
            result.bin_linked, 0,
            "bin name with path traversal should be rejected"
        );
    }

    // ---- Finding: Self-reference name validation ----

    #[test]
    fn self_ref_name_valid_plain() {
        assert!(is_valid_self_ref_name("my-package"));
    }

    #[test]
    fn self_ref_name_valid_scoped() {
        assert!(is_valid_self_ref_name("@scope/my-package"));
    }

    #[test]
    fn self_ref_name_invalid_traversal() {
        assert!(!is_valid_self_ref_name("../../etc"));
    }

    #[test]
    fn self_ref_name_invalid_empty() {
        assert!(!is_valid_self_ref_name(""));
    }

    #[test]
    fn self_ref_name_invalid_null_byte() {
        assert!(!is_valid_self_ref_name("a\0b"));
    }

    #[test]
    fn self_ref_name_invalid_backslash() {
        assert!(!is_valid_self_ref_name("foo\\bar"));
    }

    #[test]
    fn self_ref_name_invalid_absolute() {
        assert!(!is_valid_self_ref_name("/etc/passwd"));
    }

    #[test]
    fn self_ref_traversal_skipped_no_error() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "foo");

        let packages = vec![LinkTarget {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        // Use a traversal name — should not create symlink, should not error
        let result =
            link_packages(project_dir.path(), &packages, false, Some("../../evil")).unwrap();
        assert!(!result.self_referenced);

        // No symlink created outside node_modules
        let evil_link = project_dir.path().join("node_modules/../../evil");
        assert!(!evil_link.symlink_metadata().is_ok());
    }

    // ---- Finding: Additional hoisted mode tests ----

    #[test]
    fn hoisted_mode_empty_packages() {
        let project_dir = tempfile::tempdir().unwrap();

        let result = link_packages_hoisted(project_dir.path(), &[], false).unwrap();
        assert_eq!(result.linked, 0);
        assert_eq!(result.bin_linked, 0);
    }

    #[test]
    fn hoisted_mode_single_package() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "solo");

        let packages = vec![LinkTarget {
            name: "solo".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();
        assert_eq!(result.linked, 1);
        assert!(project_dir.path().join("node_modules/solo").exists());
        assert!(
            project_dir
                .path()
                .join("node_modules/solo/package.json")
                .exists()
        );
    }

    #[test]
    fn hoisted_mode_multiple_conflicts() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let a_store = create_fake_store_package(store_dir.path(), "a");
        let b_store = create_fake_store_package(store_dir.path(), "b");
        let shared_v1_store = create_fake_store_package(store_dir.path(), "shared-v1");
        let shared_v2_store = create_fake_store_package(store_dir.path(), "shared-v2");
        let util_v1_store = create_fake_store_package(store_dir.path(), "util-v1");
        let util_v2_store = create_fake_store_package(store_dir.path(), "util-v2");

        let packages = vec![
            LinkTarget {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
                store_path: a_store,
                dependencies: vec![
                    ("shared".to_string(), "1.0.0".to_string()),
                    ("util".to_string(), "1.0.0".to_string()),
                ],
                is_direct: true,
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "1.0.0".to_string(),
                store_path: shared_v1_store,
                dependencies: vec![],
                is_direct: false,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "1.0.0".to_string(),
                store_path: util_v1_store,
                dependencies: vec![],
                is_direct: false,
            },
            LinkTarget {
                name: "b".to_string(),
                version: "1.0.0".to_string(),
                store_path: b_store,
                dependencies: vec![
                    ("shared".to_string(), "2.0.0".to_string()),
                    ("util".to_string(), "2.0.0".to_string()),
                ],
                is_direct: true,
            },
            LinkTarget {
                name: "shared".to_string(),
                version: "2.0.0".to_string(),
                store_path: shared_v2_store,
                dependencies: vec![],
                is_direct: false,
            },
            LinkTarget {
                name: "util".to_string(),
                version: "2.0.0".to_string(),
                store_path: util_v2_store,
                dependencies: vec![],
                is_direct: false,
            },
        ];

        let result = link_packages_hoisted(project_dir.path(), &packages, false).unwrap();

        // Root should have: a, b, shared (v1 wins first-come), util (v1 wins first-come)
        assert!(project_dir.path().join("node_modules/a").exists());
        assert!(project_dir.path().join("node_modules/b").exists());
        assert!(project_dir.path().join("node_modules/shared").exists());
        assert!(project_dir.path().join("node_modules/util").exists());

        // Conflicting v2 should be nested under b
        assert!(
            project_dir
                .path()
                .join("node_modules/b/node_modules/shared")
                .exists()
        );
        assert!(
            project_dir
                .path()
                .join("node_modules/b/node_modules/util")
                .exists()
        );

        // 4 root + 2 nested = 6
        assert_eq!(result.linked, 6);
    }

    #[test]
    fn interrupted_link_cleaned_up_and_relinked() {
        let store_dir = tempfile::tempdir().unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let store_path = create_fake_store_package(store_dir.path(), "partial");

        // Simulate an interrupted link: create the pkg_nm directory but NOT the .linked marker
        let lpm_dir = project_dir.path().join("node_modules/.lpm");
        let pkg_entry_dir = lpm_dir.join("partial@1.0.0");
        let pkg_nm = pkg_entry_dir.join("node_modules").join("partial");
        std::fs::create_dir_all(&pkg_nm).unwrap();
        // Write a partial file to prove this directory gets cleaned up
        std::fs::write(pkg_nm.join("stale.txt"), "should be removed").unwrap();
        // Crucially, do NOT create pkg_entry_dir.join(".linked")

        let packages = vec![LinkTarget {
            name: "partial".to_string(),
            version: "1.0.0".to_string(),
            store_path,
            dependencies: vec![],
            is_direct: true,
        }];

        let result = link_packages(project_dir.path(), &packages, false, None).unwrap();

        // The stale directory should have been cleaned up and re-linked
        assert_eq!(
            result.linked, 1,
            "package should be re-linked after cleanup"
        );

        // The stale file should be gone
        assert!(
            !pkg_nm.join("stale.txt").exists(),
            "stale file should be removed"
        );

        // The real package files should be present
        assert!(
            pkg_nm.join("package.json").exists(),
            "package.json should exist after re-link"
        );

        // The .linked marker should now exist
        assert!(
            pkg_entry_dir.join(".linked").exists(),
            ".linked marker should be created"
        );
    }
}
