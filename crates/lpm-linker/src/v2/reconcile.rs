use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lpm_common::LpmError;
use lpm_common::symlink::create_dir_symlink_or_junction;
use lpm_store::v2::Store;

use super::V2Target;
use super::keymap::KeyMap;
use crate::LinkTarget;
use crate::validation::{
    ensure_real_dir_with_prefix, is_safe_node_modules_entry_name as is_safe_root_link_name,
};

/// Wipe legacy project link state so the v2 install starts clean.
pub(super) fn cleanup_v1_state(project_dir: &Path) -> Result<(), LpmError> {
    // `<project>/.lpm/wrappers/` — the v1 isolated layout.
    let v1_wrappers = project_dir.join(".lpm").join("wrappers");
    if v1_wrappers.exists() {
        std::fs::remove_dir_all(&v1_wrappers).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to wipe legacy v1 wrappers at {}: {e}",
                v1_wrappers.display()
            ))
        })?;
    }
    // `<project>/.lpm/hoisted/` — hoisted layout sidecar.
    let hoisted = project_dir.join(".lpm").join("hoisted");
    if hoisted.exists() {
        std::fs::remove_dir_all(&hoisted).map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to wipe legacy hoisted state at {}: {e}",
                hoisted.display()
            ))
        })?;
    }
    Ok(())
}

pub(super) fn reconcile_project_node_modules(
    project_dir: &Path,
    targets: &[V2Target],
    self_package_name: Option<&str>,
    preserve_internal_lpm_dir: bool,
) -> Result<(), LpmError> {
    let nm = project_dir.join("node_modules");
    if !nm.exists() {
        return Ok(());
    }

    let mut desired = HashSet::new();
    for v2t in targets {
        desired.extend(root_link_names(&v2t.target));
    }
    if let Some(self_name) = self_package_name
        && is_safe_root_link_name(self_name)
    {
        desired.insert(self_name.to_string());
    }

    let entries = std::fs::read_dir(&nm).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read project node_modules at {}: {e}",
            nm.display()
        ))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".bin" {
            continue;
        }
        let is_real_dir = path
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if preserve_internal_lpm_dir && name == ".lpm" && is_real_dir {
            continue;
        }
        if name.starts_with('@') && is_real_dir {
            reconcile_scoped_root_dir(&path, &name, &desired)?;
            if std::fs::read_dir(&path)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(&path);
            }
            continue;
        }
        if !desired.contains(name.as_ref()) {
            remove_node_modules_entry(&path, "stale root entry")?;
        }
    }

    Ok(())
}

pub(super) fn reconcile_scoped_root_dir(
    scope_dir: &Path,
    scope_name: &str,
    desired: &HashSet<String>,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(scope_dir).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to read scoped node_modules dir at {}: {e}",
            scope_dir.display()
        ))
    })?;
    for entry in entries.flatten() {
        let child_path = entry.path();
        let child_name = entry.file_name();
        let full_name = format!("{scope_name}/{}", child_name.to_string_lossy());
        if !desired.contains(&full_name) {
            remove_node_modules_entry(&child_path, "stale scoped root entry")?;
        }
    }
    Ok(())
}

pub(super) fn remove_node_modules_entry(path: &Path, label: &str) -> Result<(), LpmError> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };
    let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to remove {label} at {}: {e}",
            path.display()
        ))
    })
}

/// Create `<project>/node_modules/<root_link_name>` symlinks pointing
/// into the v2 store's link package dirs.
pub(super) fn create_root_symlinks(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
) -> Result<usize, LpmError> {
    let nm = ensure_node_modules_dir(project_dir)?;

    // Scratch `PathBuf` reused across iterations. The naïve
    // `nm.join(&root_name)` allocates a fresh `PathBuf` per
    // root_name; with a single cleared+pushed buffer the underlying
    // capacity is reused (~100 fewer allocations on a typical install).
    let mut link_path = PathBuf::with_capacity(nm.as_os_str().len() + 64);
    let mut count = 0usize;
    for v2t in targets {
        let names = root_link_names(&v2t.target);
        if names.is_empty() {
            continue;
        }
        let key = key_map.get_for(&v2t.target).ok_or_else(|| {
            LpmError::Store(format!(
                "v2 linker: missing graph key for {}@{} during root-symlink pass",
                v2t.target.name, v2t.target.version
            ))
        })?;
        let target_path = store.paths().link_package_dir(key);
        for root_name in names {
            link_path.clear();
            link_path.push(&nm);
            link_path.push(&root_name);
            ensure_link_parent_dir(&nm, &link_path, "root symlink")?;
            if symlink_points_to(&link_path, &target_path) {
                count += 1;
                continue;
            }
            // Best-effort cleanup: if a stale symlink/file is at the
            // slot, remove before re-creating. Should be a no-op after
            // `cleanup_v1_state` already wiped node_modules — defensive
            // guard for direct callers.
            //
            // A concurrent install racing on the same project can
            // re-populate the slot between cleanup and create, causing
            // `AlreadyExists`. Tolerate one retry after a second cleanup
            // pass; if it still fails, escalate.
            for attempt in 0..2u8 {
                if link_path.symlink_metadata().is_ok() {
                    let _ = std::fs::remove_file(&link_path);
                    let _ = std::fs::remove_dir_all(&link_path);
                }
                match create_dir_symlink_or_junction(&target_path, &link_path) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                        // A racing installer re-populated the slot
                        // between our remove and create. Loop once.
                        continue;
                    }
                    Err(e) => {
                        return Err(LpmError::Store(format!(
                            "v2 linker: failed to create root symlink {} → {}: {e}",
                            link_path.display(),
                            target_path.display()
                        )));
                    }
                }
            }
            count += 1;
        }
    }
    Ok(count)
}

pub(super) fn symlink_points_to(link_path: &Path, target_path: &Path) -> bool {
    let Ok(existing_target) = std::fs::read_link(link_path) else {
        return false;
    };
    if existing_target == target_path {
        return true;
    }
    if existing_target.is_relative()
        && let Some(parent) = link_path.parent()
    {
        return parent.join(existing_target) == target_path;
    }
    false
}

/// Resolve a target's root-symlink filenames. Mirrors v1's contract
/// (see [`LinkTarget::root_link_names`] docs):
///
/// - `Some([])` — explicit "no root symlinks."
/// - `Some([…])` — explicit list of root names.
/// - `None` + direct dep — single root symlink at `[name]`.
/// - `None` + transitive — empty.
///
/// Filters out any name that contains a path separator or `..`
/// component — a resolver bug (or, worst case, attacker-influenced
/// `root_link_names` data on a future code path) could otherwise
/// land symlink slots outside `<project>/node_modules/`. The root-
/// symlink writer at the call site does `remove_dir_all` on the
/// computed `link_path` before creating the symlink, so a traversal
/// here would `remove_dir_all` an arbitrary path. Refuse-and-warn is
/// the same posture used by the v1 bin emitter and v2's bin loop
/// (see [`crate::validate_bin_name`]).
pub(super) fn root_link_names(target: &LinkTarget) -> Vec<String> {
    let raw: Vec<String> = if let Some(names) = &target.root_link_names {
        names.clone()
    } else if target.is_direct {
        vec![target.name.clone()]
    } else {
        Vec::new()
    };
    raw.into_iter()
        .filter(|name| {
            if is_safe_root_link_name(name) {
                true
            } else {
                tracing::warn!(
                    "v2 linker: rejecting unsafe root_link_name {name:?} for {}@{} \
                     — contains path separator, traversal, or null byte",
                    target.name,
                    target.version
                );
                false
            }
        })
        .collect()
}

#[inline]
pub(super) fn is_direct(target: &LinkTarget) -> bool {
    if let Some(names) = &target.root_link_names {
        return !names.is_empty();
    }
    target.is_direct
}

/// `<project>/node_modules/<self_name>` → `<project_dir>` symlink.
/// Skipped if the slot is already occupied (a direct dep with the
/// same name took the spot).
pub(super) fn create_self_ref(project_dir: &Path, self_name: &str) -> Result<bool, LpmError> {
    if !is_safe_root_link_name(self_name) {
        tracing::warn!("v2 linker: skipping self-reference for unsafe package name: {self_name:?}");
        return Ok(false);
    }

    let nm = ensure_node_modules_dir(project_dir)?;
    let link_path = nm.join(self_name);
    if link_path.symlink_metadata().is_ok() {
        return Ok(false);
    }
    ensure_link_parent_dir(&nm, &link_path, "self-reference")?;
    create_dir_symlink_or_junction(project_dir, &link_path).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create self-ref symlink {} → {}: {e}",
            link_path.display(),
            project_dir.display()
        ))
    })?;
    Ok(true)
}

pub(super) fn ensure_node_modules_dir(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let nm = project_dir.join("node_modules");
    std::fs::create_dir_all(&nm).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create project node_modules at {}: {e}",
            nm.display()
        ))
    })?;
    ensure_real_dir(&nm, "project node_modules")?;
    Ok(nm)
}

pub(super) fn ensure_link_parent_dir(
    root: &Path,
    link_path: &Path,
    label: &str,
) -> Result<(), LpmError> {
    let Some(parent) = link_path.parent() else {
        return Err(LpmError::Store(format!(
            "v2 linker: {label} path has no parent: {}",
            link_path.display()
        )));
    };
    if parent == root {
        return Ok(());
    }
    match parent.symlink_metadata() {
        Ok(_) => ensure_real_dir(parent, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to create {label} parent at {}: {e}",
                    parent.display()
                ))
            })?;
            ensure_real_dir(parent, label)
        }
        Err(error) => Err(LpmError::Store(format!(
            "v2 linker: failed to inspect {label} parent at {}: {error}",
            parent.display()
        ))),
    }
}

pub(super) fn ensure_real_dir(path: &Path, label: &str) -> Result<(), LpmError> {
    ensure_real_dir_with_prefix(path, label, "v2 linker: ")
}
