use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use lpm_common::{LpmError, LpmRoot};
use lpm_store::v2::{GraphKey, LinkMeta, Store};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

pub(super) fn open_directory(parent: &Dir, relative: &Path) -> Result<Option<Dir>, LpmError> {
    let mut current = parent.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Store(
                "cache prune: invalid internal directory path".into(),
            ));
        };
        current = match current.open_dir_nofollow(name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(LpmError::Store(format!(
                    "cache prune: unsafe or unreadable directory {}: {error}",
                    relative.display()
                )));
            }
        };
    }
    Ok(Some(current))
}

pub(super) fn open_store(
    root: &LpmRoot,
    store: &Store,
    create: bool,
) -> Result<Option<Dir>, LpmError> {
    let home = Dir::open_ambient_dir(root.root(), cap_std::ambient_authority())?;
    let relative = store
        .paths()
        .root()
        .strip_prefix(root.root())
        .map_err(|_| LpmError::Store("cache prune: store is outside the configured root".into()))?;
    if !create {
        return open_directory(&home, relative);
    }
    let mut current = home;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Store("cache prune: invalid store path".into()));
        };
        current = super::super::cache::open_or_create_directory(
            &current,
            name,
            store.paths().root(),
            "package store",
        )?;
    }
    Ok(Some(current))
}

pub(super) fn validate_layout(store: &Store, directory: &Dir) -> Result<(), LpmError> {
    for name in [
        "links",
        "objects",
        "compat",
        "builds",
        ".prune-tombstones",
        "blobs/blake3",
        "trees",
        "sources",
        "metadata/source-validations",
        "materialized",
    ] {
        open_directory(directory, Path::new(name))?;
    }
    for path in [
        store.paths().build_locks_root(),
        store.paths().build_entry_locks_root(),
    ] {
        let relative = path
            .strip_prefix(store.paths().root())
            .map_err(|_| LpmError::Store("cache prune: invalid lock directory".into()))?;
        open_directory(directory, relative)?;
    }
    Ok(())
}

pub(super) fn walk_link_entries(
    store: &Store,
    mut visit: impl FnMut(PathBuf, PathBuf, LinkMeta) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let root = store.paths().links_root();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(super::prune_inspection_error(&root, error)),
    };
    let links_root_canonical = std::fs::canonicalize(&root)
        .map_err(|error| super::prune_inspection_error(&root, error))?;
    let mut verified_real_dirs: HashSet<PathBuf> = HashSet::new();

    for entry in entries {
        let entry = entry.map_err(|error| super::prune_inspection_error(&root, error))?;
        let file_name = entry.file_name();
        if lpm_store::v2::is_staging_dir_name(&file_name) {
            continue;
        }
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|error| super::prune_inspection_error(&path, error))?;
        if lpm_common::is_symlink_or_junction(&metadata) {
            return Err(LpmError::Store(format!(
                "cache prune: redirected link entry at {}",
                path.display()
            )));
        }
        if !metadata.is_dir() {
            continue;
        }
        verified_real_dirs.insert(path.clone());
        let meta = LinkMeta::read_from(&path)?;
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&meta.graph_key_digest_hex, &mut digest)
            .map_err(|_| LpmError::Store("cache prune: invalid graph identity".into()))?;
        let key = GraphKey::from_recorded(&meta.name, &meta.version, digest);
        let object = store.paths().object_dir(&meta.source_sri)?;
        let object_name = object
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| LpmError::Store("cache prune: invalid object identity".into()))?;
        if file_name != OsStr::new(key.dir_name())
            || meta.object_path != format!("objects/{object_name}")
            || meta.deps.iter().any(|dep| {
                dep.target_graph_key.len() != 64
                    || !dep
                        .target_graph_key
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(LpmError::Store(format!(
                "cache prune: inconsistent link identity at {}; repair the installation before pruning",
                path.display()
            )));
        }
        for dependency in &meta.deps {
            if !safe_package_path(&dependency.local) || !safe_package_path(&dependency.target_name)
            {
                return Err(LpmError::Store(format!(
                    "cache prune: unsafe dependency name at {}",
                    path.display()
                )));
            }
            let mut digest = [0u8; 32];
            hex::decode_to_slice(&dependency.target_graph_key, &mut digest)
                .map_err(|_| LpmError::Store("cache prune: invalid dependency identity".into()))?;
            let target = GraphKey::from_recorded(
                &dependency.target_name,
                &dependency.target_version,
                digest,
            );

            let mut parent_buf = [OsStr::new(""); 6];
            let mut parent_len = 0usize;
            parent_buf[parent_len] = file_name.as_os_str();
            parent_len += 1;
            parent_buf[parent_len] = OsStr::new("node_modules");
            parent_len += 1;
            if dependency.local == meta.name {
                for part in meta.name.split('/') {
                    parent_buf[parent_len] = OsStr::new(part);
                    parent_len += 1;
                }
                parent_buf[parent_len] = OsStr::new("node_modules");
                parent_len += 1;
            }
            let dep_leaf = match dependency.local.split_once('/') {
                Some((scope, leaf)) => {
                    parent_buf[parent_len] = OsStr::new(scope);
                    parent_len += 1;
                    OsStr::new(leaf)
                }
                None => OsStr::new(dependency.local.as_str()),
            };
            let parent_components = &parent_buf[..parent_len];
            let mut link = path_from_components(&root, parent_components);
            link.push(dep_leaf);

            let mut expected_buf = [OsStr::new(""); 4];
            let mut expected_len = 0usize;
            expected_buf[expected_len] = OsStr::new(target.dir_name());
            expected_len += 1;
            expected_buf[expected_len] = OsStr::new("node_modules");
            expected_len += 1;
            for part in dependency.target_name.split('/') {
                expected_buf[expected_len] = OsStr::new(part);
                expected_len += 1;
            }
            let expected_components = &expected_buf[..expected_len];
            let expected_path = store.paths().link_package_dir(&target);

            let parent_is_real =
                ensure_real_dir_chain(&root, parent_components, &mut verified_real_dirs)?;
            let expected_is_real =
                ensure_real_dir_chain(&root, expected_components, &mut verified_real_dirs)?;
            if parent_is_real && expected_is_real {
                let expected_canonical =
                    path_from_components(&links_root_canonical, expected_components);
                if let Ok(raw_target) = std::fs::read_link(&link)
                    && fast_link_target_matches(
                        &raw_target,
                        parent_components,
                        expected_components,
                        &expected_path,
                        &expected_canonical,
                    )
                {
                    continue;
                }
            }

            let actual = std::fs::canonicalize(&link)
                .map_err(|error| super::prune_inspection_error(&link, error))?;
            let expected = if expected_is_real {
                path_from_components(&links_root_canonical, expected_components)
            } else {
                std::fs::canonicalize(&expected_path)
                    .map_err(|error| super::prune_inspection_error(&expected_path, error))?
            };
            if actual != expected {
                return Err(LpmError::Store(format!(
                    "cache prune: dependency metadata disagrees with installed link at {}",
                    link.display()
                )));
            }
        }
        let canonical_dir = links_root_canonical.join(&file_name);
        visit(path, canonical_dir, meta)?;
    }
    Ok(())
}

fn path_from_components(base: &Path, components: &[&OsStr]) -> PathBuf {
    let extra: usize = components.iter().map(|c| c.len() + 1).sum();
    let mut out = PathBuf::with_capacity(base.as_os_str().len() + extra);
    out.push(base);
    for component in components {
        out.push(component);
    }
    out
}

/// Verifies that every prefix along `root / components[0] / ... / components[k]`
/// is a real non-symlink directory, caching verified prefixes across the walk.
/// Returns `Ok(false)` when a component is missing or is not a real directory so
/// the caller can fall back to `canonicalize`.
fn ensure_real_dir_chain(
    root: &Path,
    components: &[&OsStr],
    verified: &mut HashSet<PathBuf>,
) -> Result<bool, LpmError> {
    let full = path_from_components(root, components);
    if verified.contains(&full) {
        return Ok(true);
    }
    let mut cursor = PathBuf::with_capacity(full.as_os_str().len());
    cursor.push(root);
    for component in components {
        cursor.push(component);
        if verified.contains(&cursor) {
            continue;
        }
        match std::fs::symlink_metadata(&cursor) {
            Ok(meta) if meta.is_dir() && !lpm_common::is_symlink_or_junction(&meta) => {
                verified.insert(cursor.clone());
            }
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(super::prune_inspection_error(&cursor, error)),
        }
    }
    Ok(true)
}

/// Pure lexical equivalence check for a symlink whose parent chain and expected
/// target chain under `links_root` have both been verified as real non-symlink
/// directories. Disallows `..` after any normal component so an intermediate
/// symlink traversal like `../../evil_symlink/../../target` always falls back
/// to `canonicalize`.
fn fast_link_target_matches(
    raw_target: &Path,
    parent_components: &[&OsStr],
    expected_components: &[&OsStr],
    expected_path: &Path,
    expected_canonical: &Path,
) -> bool {
    if raw_target.is_absolute() {
        if raw_target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return false;
        }
        return raw_target == expected_path || raw_target == expected_canonical;
    }

    let mut up_count = 0usize;
    let mut seen_normal = false;
    let mut tail_len = 0usize;
    for component in raw_target.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if seen_normal {
                    return false;
                }
                up_count += 1;
            }
            Component::Normal(_) => {
                seen_normal = true;
                tail_len += 1;
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    if up_count > parent_components.len() {
        return false;
    }
    let prefix = &parent_components[..parent_components.len() - up_count];
    if prefix.len() + tail_len != expected_components.len() {
        return false;
    }
    if prefix != &expected_components[..prefix.len()] {
        return false;
    }
    let mut expected_tail = expected_components[prefix.len()..].iter().copied();
    for component in raw_target.components() {
        if let Component::Normal(name) = component
            && expected_tail.next() != Some(name)
        {
            return false;
        }
    }
    expected_tail.next().is_none()
}

fn safe_package_path(name: &str) -> bool {
    let parts = name.split('/').collect::<Vec<_>>();
    let valid_shape = if name.starts_with('@') {
        parts.len() == 2 && parts[0].len() > 1
    } else {
        parts.len() == 1
    };
    valid_shape
        && parts.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && !part
                    .bytes()
                    .any(|byte| byte == b'\\' || byte == b':' || byte.is_ascii_control())
        })
}

pub(super) fn validate_deletion_parents(
    directory: &Dir,
    store: &Store,
    plan: &super::PruneSummary,
) -> Result<(), LpmError> {
    let mut seen = std::collections::HashSet::new();
    for paths in [
        &plan.link_entries_orphaned,
        &plan.object_entries_orphaned,
        &plan.cas_tree_files_orphaned,
        &plan.cas_blob_files_orphaned,
        &plan.cas_source_record_files_orphaned,
        &plan.cas_source_validation_files_orphaned,
        &plan.cas_materialized_entries_orphaned,
        &plan.compat_islands_orphaned,
        &plan.build_artifacts_orphaned,
    ] {
        for path in paths {
            let relative = path
                .parent()
                .and_then(|parent| parent.strip_prefix(store.paths().root()).ok())
                .ok_or_else(|| LpmError::Store("cache prune: target escapes store".into()))?;
            if seen.insert(relative) {
                open_directory(directory, relative)?;
            }
        }
    }
    Ok(())
}
