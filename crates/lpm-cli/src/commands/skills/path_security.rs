use lpm_common::LpmError;
use std::path::{Component, Path, PathBuf};

pub(super) fn ensure_contained_directory(
    anchor: &Path,
    directory: &Path,
    label: &str,
) -> Result<PathBuf, LpmError> {
    let relative = directory.strip_prefix(anchor).map_err(|_| {
        LpmError::Registry(format!(
            "refusing {label} path outside its intended root: {}",
            directory.display()
        ))
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LpmError::Registry(format!(
            "refusing unsafe {label} path: {}",
            directory.display()
        )));
    }

    if !anchor.exists() {
        std::fs::create_dir_all(anchor)?;
    }
    let canonical_anchor = anchor.canonicalize().map_err(LpmError::Io)?;
    let mut current = anchor.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LpmError::Registry(format!(
                    "refusing to write {label} through symlinked directory: {}",
                    current.display()
                )));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(LpmError::Registry(format!(
                    "refusing to write {label} through non-directory path: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Err(error) = std::fs::create_dir(&current)
                    && error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(LpmError::Io(error));
                }
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LpmError::Registry(format!(
                "refusing to write {label} through non-directory or symlinked path: {}",
                current.display()
            )));
        }
        let canonical = current.canonicalize().map_err(LpmError::Io)?;
        if !canonical.starts_with(&canonical_anchor) {
            return Err(LpmError::Registry(format!(
                "refusing {label} path outside its intended root: {}",
                current.display()
            )));
        }
    }
    directory.canonicalize().map_err(LpmError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn contained_directory_rejects_an_intermediate_symlink() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("linked")).unwrap();

        let error = ensure_contained_directory(
            project.path(),
            &project.path().join("linked/child"),
            "test",
        )
        .unwrap_err();

        assert!(error.to_string().contains("symlinked directory"));
        assert!(!outside.path().join("child").exists());
    }
}
