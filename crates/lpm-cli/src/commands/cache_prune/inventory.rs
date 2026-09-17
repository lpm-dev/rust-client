use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;
use lpm_common::{LpmError, LpmRoot};
use lpm_store::v2::{GraphKey, LinkMeta, Store};
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
    mut visit: impl FnMut(PathBuf, LinkMeta) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let root = store.paths().links_root();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(super::prune_inspection_error(&root, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| super::prune_inspection_error(&root, error))?;
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
        if entry.file_name() != std::ffi::OsStr::new(key.dir_name())
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
            let mut link = path.join("node_modules");
            if dependency.local == meta.name {
                link.push(&meta.name);
                link.push("node_modules");
            }
            link.push(&dependency.local);
            let actual = std::fs::canonicalize(&link)
                .map_err(|error| super::prune_inspection_error(&link, error))?;
            let expected_path = store.paths().link_package_dir(&target);
            let expected = std::fs::canonicalize(&expected_path)
                .map_err(|error| super::prune_inspection_error(&expected_path, error))?;
            if actual != expected {
                return Err(LpmError::Store(format!(
                    "cache prune: dependency metadata disagrees with installed link at {}",
                    link.display()
                )));
            }
        }
        visit(path, meta)?;
    }
    Ok(())
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
