use crate::{ExtractionRecord, PathLedgerBudget};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use lpm_common::LpmError;
use std::{
    collections::HashMap,
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Identity(u64, u64);

impl Identity {
    fn from_cap(metadata: &cap_std::fs::Metadata) -> Self {
        Self(metadata.dev(), metadata.ino())
    }
}

struct DirectoryRecord {
    identity: Identity,
    created: bool,
}

struct Parent {
    path: PathBuf,
    directory: Dir,
    identity: Identity,
}

pub(crate) struct OutputTree {
    root_path: PathBuf,
    visible_root_path: PathBuf,
    root: Dir,
    root_identity: Identity,
    directories: HashMap<PathBuf, DirectoryRecord>,
    parent: Option<Parent>,
}

impl OutputTree {
    pub(crate) fn new(root_path: PathBuf, visible_root_path: PathBuf) -> Result<Self, LpmError> {
        let root = Dir::open_ambient_dir(&root_path, ambient_authority())?;
        let root_identity = Identity::from_cap(&root.dir_metadata()?);
        Ok(Self {
            root_path,
            visible_root_path,
            root,
            root_identity,
            directories: HashMap::with_capacity(64),
            parent: None,
        })
    }

    pub(crate) fn prepare_parent(
        &mut self,
        path: &Path,
        budget: &mut PathLedgerBudget,
    ) -> Result<(), LpmError> {
        let parent = path.parent().unwrap_or(Path::new(""));
        if parent.as_os_str().is_empty() {
            self.parent = None;
            return Ok(());
        }
        if self
            .parent
            .as_ref()
            .is_some_and(|cached| cached.path == parent)
        {
            return Ok(());
        }
        self.parent = None;

        let mut current = None::<Dir>;
        let mut prefix = PathBuf::with_capacity(parent.as_os_str().len());
        let mut identity = self.root_identity;
        for component in parent.components() {
            prefix.push(component);
            let name = Path::new(component.as_os_str());
            let base = current.as_ref().unwrap_or(&self.root);
            let known = self.directories.get(&prefix);
            let (next, created) = match base.open_dir_nofollow(name) {
                Ok(next) => (next, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound && known.is_none() => {
                    budget.reserve(&prefix)?;
                    base.create_dir(name)?;
                    match base.open_dir_nofollow(name) {
                        Ok(directory) => (directory, true),
                        Err(error) => {
                            let _ = base.remove_dir(name);
                            return Err(path_error(error, &prefix));
                        }
                    }
                }
                Err(error) => return Err(path_error(error, &prefix)),
            };
            identity = Identity::from_cap(&next.dir_metadata()?);
            if let Some(record) = known {
                if identity != record.identity {
                    return Err(changed_directory(&prefix));
                }
            } else {
                if !created {
                    budget.reserve(&prefix)?;
                }
                self.directories
                    .insert(prefix.clone(), DirectoryRecord { identity, created });
            }
            current = Some(next);
        }
        if let Some(directory) = current {
            self.parent = Some(Parent {
                path: prefix,
                directory,
                identity,
            });
        }
        Ok(())
    }

    pub(crate) fn create_file(
        &self,
        path: &Path,
        duplicate: bool,
    ) -> Result<PendingFile<'_>, LpmError> {
        let directory = self.parent.as_ref().map_or(&self.root, |p| &p.directory);
        let name = path.file_name().ok_or_else(|| changed_directory(path))?;
        if duplicate {
            let metadata = directory.symlink_metadata(name)?;
            if !metadata.is_file() {
                return Err(LpmError::Registry(format!(
                    "non-file path blocks duplicate tarball entry: {}",
                    path.display()
                )));
            }
            directory.remove_file(name)?;
        }

        let mut options = OpenOptions::new();
        options.write(true).follow(FollowSymlinks::No);
        if duplicate {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let file = directory
            .open_with(name, &options)
            .map_err(|error| path_error(error, path))?
            .into_std();
        Ok(PendingFile {
            file,
            directory,
            name: PathBuf::from(name),
            committed: false,
        })
    }

    fn validate_root(&self) -> Result<(), LpmError> {
        let current = Dir::open_ambient_dir(&self.root_path, ambient_authority())?;
        if Identity::from_cap(&current.dir_metadata()?) != self.root_identity {
            return Err(changed_directory(&self.root_path));
        }
        let visible = Dir::open_ambient_dir(&self.visible_root_path, ambient_authority())?;
        if Identity::from_cap(&visible.dir_metadata()?) != self.root_identity {
            return Err(changed_directory(&self.visible_root_path));
        }
        Ok(())
    }

    pub(crate) fn validate_parent_for_inspection(&self) -> Result<(), LpmError> {
        self.validate_root()?;
        if let Some(parent) = &self.parent {
            let current = self
                .open_recorded_directory(&parent.path)?
                .ok_or_else(|| changed_directory(&parent.path))?;
            if Identity::from_cap(&current.dir_metadata()?) != parent.identity {
                return Err(changed_directory(&parent.path));
            }
        }
        Ok(())
    }

    fn open_recorded_directory(&self, path: &Path) -> Result<Option<Dir>, LpmError> {
        let mut current = None::<Dir>;
        let mut prefix = PathBuf::with_capacity(path.as_os_str().len());
        for component in path.components() {
            prefix.push(component);
            let record = self
                .directories
                .get(&prefix)
                .ok_or_else(|| changed_directory(&prefix))?;
            let base = current.as_ref().unwrap_or(&self.root);
            let next = base
                .open_dir_nofollow(Path::new(component.as_os_str()))
                .map_err(|error| path_error(error, &prefix))?;
            if Identity::from_cap(&next.dir_metadata()?) != record.identity {
                return Err(changed_directory(&prefix));
            }
            current = Some(next);
        }
        Ok(current)
    }

    pub(crate) fn validate(&mut self) -> Result<(), LpmError> {
        self.parent = None;
        self.validate_root()?;
        for path in self.directories.keys() {
            self.open_recorded_directory(path)?;
        }
        Ok(())
    }

    pub(crate) fn accepted_file_identity(&self, path: &Path) -> Result<Identity, LpmError> {
        let directory = self
            .parent
            .as_ref()
            .map_or(&self.root, |parent| &parent.directory);
        let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
        let metadata = directory.symlink_metadata(leaf)?;
        if !metadata.is_file() {
            return Err(changed_file(path));
        }
        Ok(Identity::from_cap(&metadata))
    }

    pub(crate) fn cleanup<E: ExtractionRecord>(&mut self, files: &[E], identities: &[Identity]) {
        self.parent = None;
        if files.len() != identities.len() {
            return;
        }
        for (record, identity) in files.iter().zip(identities).rev() {
            let path = record.relative_path();
            let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
                continue;
            };
            if let Ok(directory) = self.open_recorded_directory(parent) {
                let base = directory.as_ref().unwrap_or(&self.root);
                if base
                    .symlink_metadata(leaf)
                    .is_ok_and(|metadata| *identity == Identity::from_cap(&metadata))
                {
                    let _ = base.remove_file(leaf);
                }
            }
        }

        let mut created = self
            .directories
            .iter()
            .filter_map(|(path, record)| record.created.then_some(path.as_path()))
            .collect::<Vec<_>>();
        created.sort_unstable_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in created {
            let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else {
                continue;
            };
            if let Ok(directory) = self.open_recorded_directory(parent) {
                let base = directory.as_ref().unwrap_or(&self.root);
                if let Ok(metadata) = base.symlink_metadata(leaf)
                    && metadata.is_dir()
                    && self
                        .directories
                        .get(path)
                        .is_some_and(|record| record.identity == Identity::from_cap(&metadata))
                {
                    let _ = base.remove_dir(leaf);
                }
            }
        }
    }
}

pub(crate) struct PendingFile<'a> {
    pub(crate) file: File,
    directory: &'a Dir,
    name: PathBuf,
    committed: bool,
}

impl PendingFile<'_> {
    pub(crate) fn identity(&self) -> Result<Identity, LpmError> {
        Ok(Identity::from_cap(&cap_std::fs::Metadata::from_file(
            &self.file,
        )?))
    }
    pub(crate) fn validate(&self) -> Result<(), LpmError> {
        let written = cap_std::fs::Metadata::from_file(&self.file)?;
        let current = self.directory.symlink_metadata(&self.name)?;
        if !current.is_file() || Identity::from_cap(&written) != Identity::from_cap(&current) {
            return Err(LpmError::Registry(
                "tarball output file changed before inspection".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingFile<'_> {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(written) = cap_std::fs::Metadata::from_file(&self.file)
            && let Ok(current) = self.directory.symlink_metadata(&self.name)
            && current.is_file()
            && Identity::from_cap(&written) == Identity::from_cap(&current)
        {
            let _ = self.directory.remove_file(&self.name);
        }
    }
}

fn changed_directory(path: &Path) -> LpmError {
    LpmError::Registry(format!(
        "tarball extraction directory changed: {}",
        path.display()
    ))
}

fn changed_file(path: &Path) -> LpmError {
    LpmError::Registry(format!(
        "tarball output file changed after inspection: {}",
        path.display()
    ))
}

fn path_error(error: io::Error, path: &Path) -> LpmError {
    if matches!(
        error.kind(),
        io::ErrorKind::NotADirectory | io::ErrorKind::InvalidInput
    ) {
        LpmError::Registry(format!(
            "path traversal detected or non-directory in tarball target: {}",
            path.display()
        ))
    } else {
        LpmError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_parent_cannot_redirect_a_later_write_or_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = Path::new("lib/file");
        let mut output = OutputTree::new(root.clone(), root.clone()).unwrap();
        output
            .prepare_parent(path, &mut PathLedgerBudget::new(usize::MAX))
            .unwrap();
        let pending = output.create_file(path, false).unwrap();
        let written_identity = pending.identity().unwrap();
        pending.validate().unwrap();
        output.validate_parent_for_inspection().unwrap();
        pending.commit();
        let identity = output.accepted_file_identity(path).unwrap();
        assert!(identity == written_identity);
        std::fs::rename(root.join("lib"), root.join("moved")).unwrap();
        std::fs::create_dir(root.join("lib")).unwrap();
        std::fs::write(root.join(path), b"keep").unwrap();
        output.cleanup(&[path.to_path_buf()], &[identity]);
        assert_eq!(std::fs::read(root.join(path)).unwrap(), b"keep");
        let result = output
            .prepare_parent(
                Path::new("lib/second"),
                &mut PathLedgerBudget::new(usize::MAX),
            )
            .and_then(|()| {
                output
                    .create_file(Path::new("lib/second"), false)
                    .map(|p| p.commit())
            })
            .and_then(|()| output.validate());
        assert!(result.is_err());
        assert!(!root.join("lib/second").exists());
    }

    #[test]
    fn partial_cleanup_preserves_a_replacement_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let path = Path::new("partial");
        let root = dir.path().canonicalize().unwrap();
        let output = OutputTree::new(root.clone(), root.clone()).unwrap();
        let pending = output.create_file(path, false).unwrap();
        std::fs::rename(root.join(path), root.join("moved")).unwrap();
        std::fs::write(root.join(path), b"keep").unwrap();
        assert!(pending.validate().is_err());
        drop(pending);
        assert_eq!(std::fs::read(root.join(path)).unwrap(), b"keep");
    }
}
