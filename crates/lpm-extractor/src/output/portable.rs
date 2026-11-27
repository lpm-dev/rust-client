use crate::{ExtractedFileStamp, ExtractionRecord, PathLedgerBudget};
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
    sync::Arc,
};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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
    directory: Arc<Dir>,
    identity: Identity,
}

const MAX_CACHED_PARENTS: usize = 64;

struct LruNode {
    parent: Parent,
    prev: Option<usize>,
    next: Option<usize>,
}

struct ParentCache {
    nodes: Vec<Option<LruNode>>,
    free_slots: Vec<usize>,
    index: HashMap<PathBuf, usize>,
    head: Option<usize>,
    tail: Option<usize>,
    capacity: usize,
}

impl ParentCache {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity),
            free_slots: Vec::new(),
            index: HashMap::with_capacity(capacity),
            head: None,
            tail: None,
            capacity,
        }
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.free_slots.clear();
        self.index.clear();
        self.head = None;
        self.tail = None;
    }

    fn unlink(&mut self, slot: usize) -> Parent {
        let node = self.nodes[slot].take().expect("LRU slot must be occupied");
        match node.prev {
            Some(prev) => {
                if let Some(prev_node) = self.nodes[prev].as_mut() {
                    prev_node.next = node.next;
                }
            }
            None => self.head = node.next,
        }
        match node.next {
            Some(next) => {
                if let Some(next_node) = self.nodes[next].as_mut() {
                    next_node.prev = node.prev;
                }
            }
            None => self.tail = node.prev,
        }
        self.free_slots.push(slot);
        node.parent
    }

    fn take(&mut self, path: &Path) -> Option<Parent> {
        let slot = self.index.remove(path)?;
        Some(self.unlink(slot))
    }

    fn insert(&mut self, parent: Parent) {
        if self.capacity == 0 {
            return;
        }
        if let Some(existing) = self.index.remove(&parent.path) {
            let _ = self.unlink(existing);
        } else if self.index.len() >= self.capacity
            && let Some(lru_slot) = self.tail
        {
            let evicted = self.unlink(lru_slot);
            self.index.remove(&evicted.path);
        }
        let path_key = parent.path.clone();
        let old_head = self.head;
        let node = LruNode {
            parent,
            prev: None,
            next: old_head,
        };
        let slot = if let Some(slot) = self.free_slots.pop() {
            self.nodes[slot] = Some(node);
            slot
        } else {
            let slot = self.nodes.len();
            self.nodes.push(Some(node));
            slot
        };
        if let Some(head_slot) = old_head
            && let Some(head_node) = self.nodes[head_slot].as_mut()
        {
            head_node.prev = Some(slot);
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
        self.index.insert(path_key, slot);
    }
}

pub(crate) struct OutputTree {
    root_path: PathBuf,
    visible_root_path: PathBuf,
    root: Arc<Dir>,
    root_identity: Identity,
    directories: HashMap<PathBuf, DirectoryRecord>,
    directory_identities: HashMap<Identity, PathBuf>,
    parent: Option<Parent>,
    recent_parents: ParentCache,
}

impl OutputTree {
    pub(crate) fn new(root_path: PathBuf, visible_root_path: PathBuf) -> Result<Self, LpmError> {
        let root = Dir::open_ambient_dir(&root_path, ambient_authority())?;
        let root_identity = Identity::from_cap(&root.dir_metadata()?);
        let mut directory_identities = HashMap::with_capacity(64);
        directory_identities.insert(root_identity, PathBuf::new());
        Ok(Self {
            root_path,
            visible_root_path,
            root: Arc::new(root),
            root_identity,
            directories: HashMap::with_capacity(64),
            directory_identities,
            parent: None,
            recent_parents: ParentCache::with_capacity(MAX_CACHED_PARENTS),
        })
    }

    fn park_current_parent(&mut self) {
        let Some(previous) = self.parent.take() else {
            return;
        };
        self.recent_parents.insert(previous);
    }

    pub(crate) fn prepare_parent(
        &mut self,
        path: &Path,
        budget: &mut PathLedgerBudget,
    ) -> Result<(), LpmError> {
        let parent = path.parent().unwrap_or(Path::new(""));
        if parent.as_os_str().is_empty() {
            self.park_current_parent();
            return Ok(());
        }
        if self
            .parent
            .as_ref()
            .is_some_and(|cached| cached.path == parent)
        {
            return Ok(());
        }
        self.park_current_parent();
        if let Some(cached) = self.recent_parents.take(parent)
            && self
                .directories
                .get(parent)
                .is_some_and(|record| record.identity == cached.identity)
        {
            self.parent = Some(cached);
            return Ok(());
        }

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
                if let Some(existing_dir) = self.directory_identities.get(&identity)
                    && existing_dir != &prefix
                {
                    return Err(LpmError::Registry(format!(
                        "directory path collision in tarball: {} aliases {}",
                        prefix.display(),
                        existing_dir.display()
                    )));
                }
                if !created {
                    budget.reserve(&prefix)?;
                }
                self.directories
                    .insert(prefix.clone(), DirectoryRecord { identity, created });
                self.directory_identities.insert(identity, prefix.clone());
            }
            current = Some(next);
        }
        if let Some(directory) = current {
            self.parent = Some(Parent {
                path: prefix,
                directory: Arc::new(directory),
                identity,
            });
        }
        Ok(())
    }

    pub(crate) fn create_file(
        &self,
        path: &Path,
        duplicate: bool,
    ) -> Result<PendingFile, LpmError> {
        let file = self.new_file(path)?;
        if duplicate {
            file.replace()
        } else {
            file.create()
        }
    }

    /// Resolve `path` in the prepared parent without touching the filesystem,
    /// so another thread can create the file.
    pub(crate) fn new_file(&self, path: &Path) -> Result<NewFile, LpmError> {
        let directory = self.parent.as_ref().map_or(&self.root, |p| &p.directory);
        let name = path.file_name().ok_or_else(|| changed_directory(path))?;
        Ok(NewFile {
            directory: Arc::clone(directory),
            name: PathBuf::from(name),
            path: path.to_path_buf(),
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
        self.recent_parents.clear();
        self.validate_root()?;
        if self.directories.is_empty() {
            return Ok(());
        }
        // Sort lexicographically so every recorded ancestor precedes its
        // descendants, allowing each directory to be opened once from an
        // already-validated parent handle instead of re-walking from root.
        let mut paths: Vec<&Path> = self.directories.keys().map(PathBuf::as_path).collect();
        paths.sort_unstable();
        let mut stack: Vec<(&Path, Dir)> = Vec::new();
        for path in paths {
            let record = self
                .directories
                .get(path)
                .ok_or_else(|| changed_directory(path))?;
            let parent_path = path.parent().unwrap_or(Path::new(""));
            while stack
                .last()
                .is_some_and(|(top_path, _)| *top_path != parent_path)
            {
                stack.pop();
            }
            let opened = if let Some((_, parent_dir)) = stack.last() {
                let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
                let next = parent_dir
                    .open_dir_nofollow(Path::new(leaf))
                    .map_err(|error| path_error(error, path))?;
                if Identity::from_cap(&next.dir_metadata()?) != record.identity {
                    return Err(changed_directory(path));
                }
                next
            } else if parent_path.as_os_str().is_empty() {
                let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
                let next = self
                    .root
                    .open_dir_nofollow(Path::new(leaf))
                    .map_err(|error| path_error(error, path))?;
                if Identity::from_cap(&next.dir_metadata()?) != record.identity {
                    return Err(changed_directory(path));
                }
                next
            } else {
                self.open_recorded_directory(path)?
                    .ok_or_else(|| changed_directory(path))?
            };
            stack.push((path, opened));
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
        self.recent_parents.clear();
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

/// A regular file to create in a verified extraction directory.
pub(crate) struct NewFile {
    directory: Arc<Dir>,
    name: PathBuf,
    path: PathBuf,
}

impl NewFile {
    /// Create a brand-new regular file without following a symlink or
    /// overwriting an already-existing aliased entry (e.g. 8.3 short names).
    pub(crate) fn create(self) -> Result<PendingFile, LpmError> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        self.open(&options)
    }

    /// Remove the regular file an earlier entry wrote at this name, then create it.
    fn replace(self) -> Result<PendingFile, LpmError> {
        let metadata = self.directory.symlink_metadata(&self.name)?;
        if !metadata.is_file() {
            return Err(LpmError::Registry(format!(
                "non-file path blocks duplicate tarball entry: {}",
                self.path.display()
            )));
        }
        self.directory.remove_file(&self.name)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        self.open(&options)
    }

    fn open(self, options: &OpenOptions) -> Result<PendingFile, LpmError> {
        let file = self
            .directory
            .open_with(&self.name, options)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists
                    && let Ok(meta) = self.directory.symlink_metadata(&self.name)
                    && meta.file_type().is_symlink()
                {
                    return path_error(
                        io::Error::new(io::ErrorKind::InvalidInput, error),
                        &self.path,
                    );
                }
                path_error(error, &self.path)
            })?
            .into_std();
        Ok(PendingFile {
            file,
            directory: self.directory,
            name: self.name,
            committed: false,
        })
    }
}

pub(crate) struct PendingFile {
    pub(crate) file: File,
    directory: Arc<Dir>,
    name: PathBuf,
    committed: bool,
}

impl PendingFile {
    pub(crate) fn identity(&self) -> Result<Identity, LpmError> {
        Ok(Identity::from_cap(&cap_std::fs::Metadata::from_file(
            &self.file,
        )?))
    }
    pub(crate) fn stamp(&self) -> Option<ExtractedFileStamp> {
        #[cfg(windows)]
        {
            let stamp = lpm_common::windows_regular_file_stamp_from_open_file(&self.file)?;
            let meta = self.file.metadata().ok()?;
            let mode = if meta.permissions().readonly() {
                0o444
            } else {
                0o644
            };
            Some(ExtractedFileStamp {
                identity: stamp.identity,
                size: stamp.len,
                mode,
                mtime_ns: stamp.mtime_ns,
                ctime_ns: stamp.ctime_ns,
            })
        }
        #[cfg(not(windows))]
        {
            None
        }
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

    pub(crate) fn complete(self) -> Result<CompletedFile, LpmError> {
        let identity = self.identity()?;
        Ok(CompletedFile {
            pending: self,
            identity,
        })
    }
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingFile {
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

pub(crate) struct CompletedFile {
    // Pin the original file identity until ordered acceptance or rollback.
    pending: PendingFile,
    identity: Identity,
}

impl CompletedFile {
    pub(crate) fn verify_for_commit(&self) -> Result<Option<ExtractedFileStamp>, LpmError> {
        let current = self
            .pending
            .directory
            .symlink_metadata(&self.pending.name)?;
        if !current.is_file() || self.identity != Identity::from_cap(&current) {
            return Err(LpmError::Registry(
                "tarball output file changed before acceptance".into(),
            ));
        }
        Ok(self.pending.stamp())
    }

    pub(crate) fn finish_commit(self) -> Identity {
        let identity = self.identity;
        self.pending.commit();
        identity
    }

    #[cfg(test)]
    pub(crate) fn commit(self) -> Result<(Identity, Option<ExtractedFileStamp>), LpmError> {
        let stamp = self.verify_for_commit()?;
        Ok((self.finish_commit(), stamp))
    }
}

#[cfg(test)]
#[path = "completed_tests.rs"]
mod completed_tests;

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
        output
            .prepare_parent(
                Path::new("root-file"),
                &mut PathLedgerBudget::new(usize::MAX),
            )
            .unwrap();
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

    #[cfg(windows)]
    #[test]
    fn cached_parent_handle_prevents_directory_replacement_until_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut output = OutputTree::new(root.clone(), root.clone()).unwrap();
        let mut budget = PathLedgerBudget::new(usize::MAX);
        output
            .prepare_parent(Path::new("lib/file"), &mut budget)
            .unwrap();
        let error = std::fs::rename(root.join("lib"), root.join("moved")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32));
        output
            .prepare_parent(Path::new("root-file"), &mut budget)
            .unwrap();
        std::fs::rename(root.join("lib"), root.join("moved")).unwrap();
        assert!(output.validate().is_err());
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
