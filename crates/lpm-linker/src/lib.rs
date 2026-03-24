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
//! # TODOs
//! - [ ] Hoisted mode fallback (`--linker hoisted`) for compatibility
//! - [ ] Windows junction points (no admin required)
//! - [ ] Self-referencing support (package can require itself)
//! - [ ] Incremental linking (only re-link changed packages)

use lpm_common::LpmError;
use std::path::{Path, PathBuf};

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
pub fn link_packages(project_dir: &Path, packages: &[LinkTarget]) -> Result<LinkResult, LpmError> {
    let node_modules = project_dir.join("node_modules");
    let lpm_dir = node_modules.join(".lpm");

    // Create base directories
    std::fs::create_dir_all(&lpm_dir)?;

    let mut linked_count = 0;
    let mut symlinked_count = 0;

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
                            && se.path().symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false)
                        {
                            let _ = std::fs::remove_file(se.path());
                            tracing::debug!("incremental: removed stale root symlink {scoped_name}");
                        }
                    }
                }
                continue;
            } else {
                name.clone()
            };
            if !direct_names.contains(full_name.as_str())
                && entry.path().symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false)
            {
                let _ = std::fs::remove_file(entry.path());
                tracing::debug!("incremental: removed stale root symlink {full_name}");
            }
        }
    }

    // Phase 1: Create .lpm/<name>@<version>/node_modules/<name> for each package
    for pkg in packages {
        let safe_name = pkg.name.replace('/', "+");
        let pkg_nm = lpm_dir
            .join(format!("{safe_name}@{}", pkg.version))
            .join("node_modules")
            .join(&pkg.name);

        if !pkg_nm.exists() {
            // Create parent dirs (handles scoped packages like @types/node)
            if let Some(parent) = pkg_nm.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Hardlink from global store (zero disk cost on same filesystem)
            link_dir_recursive(&pkg.store_path, &pkg_nm)?;
            linked_count += 1;
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

            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dep_link)?;

            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&target, &dep_link)?;

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

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &root_link)?;

        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&target, &root_link)?;

        symlinked_count += 1;
    }

    Ok(LinkResult {
        linked: linked_count,
        symlinked: symlinked_count,
    })
}

/// Result of the linking operation.
#[derive(Debug)]
pub struct LinkResult {
    /// Number of packages copied from store.
    pub linked: usize,
    /// Number of symlinks created.
    pub symlinked: usize,
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
    let result = unsafe {
        libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0)
    };

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

        let result = link_packages(project_dir.path(), &packages).unwrap();
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

        let result = link_packages(project_dir.path(), &packages).unwrap();

        // express is accessible from root
        assert!(project_dir
            .path()
            .join("node_modules/express")
            .symlink_metadata()
            .is_ok());

        // debug is NOT in root (it's transitive)
        assert!(!project_dir
            .path()
            .join("node_modules/debug")
            .symlink_metadata()
            .is_ok());

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
        )
        .unwrap();

        assert!(project_dir.path().join("node_modules/.lpm").is_dir());
    }
}
