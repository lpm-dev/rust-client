use lpm_common::{LpmError, LpmRoot};
use std::path::{Path, PathBuf};

pub(crate) fn validate_name(name: &str) -> Result<(), LpmError> {
    if name.is_empty()
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LpmError::Plugin(format!(
            "invalid managed tool name: {name:?}"
        )));
    }
    Ok(())
}

pub(crate) fn operation_lock(namespace: &str, name: &str) -> Result<PathBuf, LpmError> {
    validate_name(name)?;
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Plugin(format!("could not determine LPM home: {error}")))?;
    Ok(root
        .root()
        .join(".locks")
        .join(namespace)
        .join("operations")
        .join(format!("{name}.lock")))
}

pub(crate) fn directory_if_present(path: &Path) -> Result<(), LpmError> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(LpmError::Plugin(format!(
            "managed tool directory is not a regular directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

// Publication and rollback stay synchronous while the caller holds the tool lock.
pub(crate) fn publish(staged: &Path, target: &Path) -> Result<(), LpmError> {
    let parent = target
        .parent()
        .ok_or_else(|| LpmError::Plugin("managed tool installation has no parent".into()))?;
    let backup = tempfile::Builder::new()
        .prefix(".lpm-tool-backup-")
        .tempdir_in(parent)?;
    let previous = backup.path().join("previous");
    let had_previous = target.symlink_metadata().is_ok();
    if had_previous {
        std::fs::rename(target, &previous)?;
    }
    if let Err(error) = std::fs::rename(staged, target) {
        if had_previous && let Err(restore_error) = std::fs::rename(&previous, target) {
            let retained = backup.keep().join("previous");
            return Err(LpmError::Plugin(format!(
                "failed to publish tool: {error}; failed to restore previous installation: {restore_error}. Previous files remain at {}",
                retained.display()
            )));
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_publication_restores_the_previous_complete_tree() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("installed");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("binary"), "previous").unwrap();
        assert!(publish(&root.path().join("missing-stage"), &target).is_err());
        assert_eq!(
            std::fs::read_to_string(target.join("binary")).unwrap(),
            "previous"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn publication_replaces_the_binary_and_receipt_together() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("installed");
        let stage = root.path().join("stage");
        for (path, bytes) in [(&target, "previous"), (&stage, "new")] {
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("binary"), bytes).unwrap();
            std::fs::write(path.join("receipt"), bytes).unwrap();
        }
        publish(&stage, &target).unwrap();
        assert_eq!(
            std::fs::read_to_string(target.join("binary")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("receipt")).unwrap(),
            "new"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn directory_validation_rejects_links_and_files() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let link = root.path().join("linked");
        std::os::unix::fs::symlink(external.path(), &link).unwrap();
        assert!(directory_if_present(&link).is_err());
        let file = root.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(directory_if_present(&file).is_err());
    }
}
