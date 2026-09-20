use lpm_common::LpmError;
use std::path::Path;

pub(super) fn entry_exists(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn removed_size(path: &Path) -> u64 {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) => 0,
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => crate::commands::cache::dir_size(path).unwrap_or(0),
        Err(_) => 0,
    }
}

pub(super) fn ensure_directory(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata) => {
            Ok(())
        }
        Ok(_) => Err(LpmError::Store(format!(
            "store path is not a real directory: {}",
            lpm_common::sanitize_for_terminal(&path.display().to_string())
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn verify_directory_chain(root: &Path, path: &Path) -> Result<(), LpmError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LpmError::Store("package path is outside the store".into()))?;
    ensure_directory(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(LpmError::Store("invalid store path component".into()));
        }
        current.push(component);
        ensure_directory(&current)?;
    }
    Ok(())
}

pub(super) fn verify_roots(root: &Path) -> Result<(), LpmError> {
    for relative in [
        "v1",
        "v2",
        "v3",
        "v2/links",
        "v2/objects",
        "v3/links",
        "v3/objects",
        "v3/blobs/blake3",
        "v3/trees",
        "v3/sources",
        "v3/metadata/source-validations",
        "v3/materialized",
    ] {
        verify_directory_chain(root, &root.join(relative))?;
    }
    Ok(())
}

pub(super) fn verify_object_directories(root: &Path) -> Result<(), LpmError> {
    if !entry_exists(root)? {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if lpm_common::is_symlink_or_junction(&metadata) {
            ensure_directory(&entry.path())?;
        }
    }
    Ok(())
}
