use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, OpenOptions};
use lpm_common::LpmError;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) fn extract_and_publish(archive: &Path, target: &Path) -> Result<Vec<PathBuf>, LpmError> {
    let stage = tempfile::tempdir()?;
    let mut files = lpm_extractor::extract_tarball_from_file(archive, stage.path())?;
    files.sort_unstable();
    files.dedup();
    let source = Dir::open_ambient_dir(stage.path(), cap_std::ambient_authority())?;
    std::fs::create_dir_all(target)?;
    let output = Dir::open_ambient_dir(target, cap_std::ambient_authority())?;
    publish_files_with(&source, &output, &files, target, std::io::copy)?;
    Ok(files)
}

fn publish_files_with(
    source: &Dir,
    output: &Dir,
    files: &[PathBuf],
    target: &Path,
    mut copy: impl FnMut(&mut File, &mut File) -> io::Result<u64>,
) -> Result<usize, LpmError> {
    for relative in files {
        validate_relative_path(relative)?;
        if let Some(parent) = output_parent(output, relative, false, &mut 0)? {
            match parent.symlink_metadata(relative.file_name().ok_or_else(invalid_path)?) {
                Ok(_) => return Err(collision(relative)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    let mut completed = 0;
    let mut created_directories = 0;
    for relative in files {
        let mut created_file = false;
        let result = (|| -> Result<(), LpmError> {
            let parent = output_parent(output, relative, true, &mut created_directories)?
                .ok_or_else(invalid_path)?;
            let name = relative.file_name().ok_or_else(invalid_path)?;
            let mut read_options = OpenOptions::new();
            read_options.read(true).follow(FollowSymlinks::No);
            let mut input = source.open_with(relative, &read_options)?.into_std();
            let permissions = input.metadata()?.permissions();
            let mut write_options = OpenOptions::new();
            write_options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            let mut destination = parent
                .open_with(name, &write_options)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        collision(relative)
                    } else {
                        error.into()
                    }
                })?
                .into_std();
            created_file = true;
            copy(&mut input, &mut destination)?;
            destination.set_permissions(permissions)?;
            Ok(())
        })();
        if let Err(error) = result {
            let incomplete = if created_file {
                format!("; incomplete new file: {}", relative.display())
            } else {
                String::new()
            };
            return Err(LpmError::Registry(format!(
                "download publication stopped at {}: {error}. {completed} completed new file(s) and {created_directories} new directory/directories remain in {}{incomplete}. Existing entries were not replaced; use a fresh output directory before retrying",
                relative.display(),
                target.display(),
            )));
        }
        completed += 1;
    }
    Ok(completed)
}

fn output_parent(
    root: &Dir,
    relative: &Path,
    create: bool,
    created: &mut usize,
) -> Result<Option<Dir>, LpmError> {
    let mut parent = root.try_clone()?;
    let components = relative.parent().ok_or_else(invalid_path)?.components();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid_path());
        };
        match crate::directory_transaction::open_directory_shared(&parent, name) {
            Ok(child) => parent = child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                match parent.create_dir(name) {
                    Ok(()) => *created += 1,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                parent = crate::directory_transaction::open_directory_shared(&parent, name)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some(parent))
}

fn validate_relative_path(path: &Path) -> Result<(), LpmError> {
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid_path());
    }
    Ok(())
}

fn invalid_path() -> LpmError {
    LpmError::Registry("invalid relative path in extracted package".into())
}

fn collision(path: &Path) -> LpmError {
    LpmError::Registry(format!(
        "download output already contains {}; choose a different output directory or move the conflicting entry",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn racing_leaf_is_preserved_and_completed_new_files_are_reported() {
        let stage = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(stage.path().join("a"), b"first").unwrap();
        std::fs::write(stage.path().join("b"), b"second").unwrap();
        let source = Dir::open_ambient_dir(stage.path(), cap_std::ambient_authority()).unwrap();
        let output = Dir::open_ambient_dir(target.path(), cap_std::ambient_authority()).unwrap();
        let error = publish_files_with(
            &source,
            &output,
            &["a".into(), "b".into()],
            target.path(),
            |input, destination| {
                let written = std::io::copy(input, destination)?;
                output.write("b", b"racing writer")?;
                Ok(written)
            },
        )
        .unwrap_err();
        assert_eq!(std::fs::read(target.path().join("a")).unwrap(), b"first");
        assert_eq!(
            std::fs::read(target.path().join("b")).unwrap(),
            b"racing writer"
        );
        assert!(
            error.to_string().contains("1 completed new file(s)"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("incomplete new file"),
            "{error}"
        );
    }

    #[test]
    fn interrupted_copy_reports_incomplete_new_file_without_deleting_other_entries() {
        let stage = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(stage.path().join("a"), b"complete contents").unwrap();
        std::fs::write(target.path().join("keep"), b"original").unwrap();
        let source = Dir::open_ambient_dir(stage.path(), cap_std::ambient_authority()).unwrap();
        let output = Dir::open_ambient_dir(target.path(), cap_std::ambient_authority()).unwrap();
        let error = publish_files_with(
            &source,
            &output,
            &["a".into()],
            target.path(),
            |_, destination| {
                destination.write_all(b"partial")?;
                Err(io::Error::other("injected write failure"))
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("incomplete new file: a"),
            "{error}"
        );
        assert_eq!(std::fs::read(target.path().join("a")).unwrap(), b"partial");
        assert_eq!(
            std::fs::read(target.path().join("keep")).unwrap(),
            b"original"
        );
    }
}
