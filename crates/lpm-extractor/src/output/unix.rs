use crate::{ExtractedFileStamp, ExtractionRecord, PathLedgerBudget};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct Identity {
    device: i128,
    inode: i128,
}
impl Identity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: i128::from(metadata.dev()),
            inode: i128::from(metadata.ino()),
        }
    }
    fn from_stat(metadata: &libc::stat) -> Self {
        Self {
            device: i128::from(metadata.st_dev),
            inode: i128::from(metadata.st_ino),
        }
    }
}
struct DirectoryRecord {
    identity: Identity,
    created: bool,
}
struct Parent {
    path: PathBuf,
    name: CString,
    file: Arc<File>,
    identity: Identity,
}

const MIN_CACHED_PARENTS: usize = 4;
const MAX_CACHED_PARENTS: usize = 32;

fn parent_cache_capacity_for_limit(soft: u64, max_concurrent: usize) -> usize {
    if soft < 128 {
        return MIN_CACHED_PARENTS;
    }
    let per_extraction = (soft / 4) / (max_concurrent.max(1) as u64);
    usize::try_from(per_extraction)
        .unwrap_or(MAX_CACHED_PARENTS)
        .clamp(MIN_CACHED_PARENTS, MAX_CACHED_PARENTS)
}

fn parent_cache_capacity() -> usize {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes this valid out pointer on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return MIN_CACHED_PARENTS;
    }
    // SAFETY: getrlimit succeeded.
    let soft = unsafe { limit.assume_init() }.rlim_cur;
    let max_concurrent = lpm_common::resources::default_fetch_extract_permits(
        lpm_common::resources::effective_cpu_count(),
        lpm_common::resources::effective_memory_limit_bytes(),
    );
    parent_cache_capacity_for_limit(soft, max_concurrent)
}

fn is_descriptor_exhaustion(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

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
    root: Arc<File>,
    root_identity: Identity,
    directories: HashMap<PathBuf, DirectoryRecord>,
    directory_identities: HashMap<Identity, PathBuf>,
    parent: Option<Parent>,
    recent_parents: Arc<Mutex<ParentCache>>,
}

impl OutputTree {
    pub(crate) fn new(root_path: PathBuf, visible_root_path: PathBuf) -> Result<Self, LpmError> {
        let root = open_directory(libc::AT_FDCWD, &c_path(&root_path)?)?;
        let root_identity = Identity::from_metadata(&root.metadata()?);
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
            recent_parents: Arc::new(Mutex::new(ParentCache::with_capacity(
                parent_cache_capacity(),
            ))),
        })
    }

    fn park_current_parent(&mut self) {
        let Some(previous) = self.parent.take() else {
            return;
        };
        self.recent_parents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(previous);
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
        let taken = self
            .recent_parents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(parent);
        if let Some(cached) = taken
            && self
                .directories
                .get(parent)
                .is_some_and(|record| record.identity == cached.identity)
        {
            self.parent = Some(cached);
            return Ok(());
        }
        if let Some(record) = self.directories.get(parent) {
            let opened = match open_known_parent(&self.root, parent) {
                Ok(opened) => opened,
                Err(error) if is_descriptor_exhaustion(&error) => {
                    let evicted = {
                        let mut recent = self
                            .recent_parents
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let had_entries = !recent.index.is_empty();
                        recent.clear();
                        had_entries
                    };
                    if evicted {
                        open_known_parent(&self.root, parent)?
                    } else {
                        return Err(error.into());
                    }
                }
                Err(error) => return Err(error.into()),
            };
            if let Some((directory, name)) = opened {
                let identity = Identity::from_metadata(&directory.metadata()?);
                if identity != record.identity {
                    return Err(changed_directory(parent));
                }
                self.parent = Some(Parent {
                    path: parent.to_path_buf(),
                    name,
                    file: Arc::new(directory),
                    identity,
                });
                return Ok(());
            }
        }
        let mut current = None::<File>;
        let mut prefix = PathBuf::with_capacity(parent.as_os_str().len());
        let mut identity = self.root_identity;
        for component in parent.components() {
            prefix.push(component);
            let name = CString::new(component.as_os_str().as_bytes()).map_err(invalid_path)?;
            let base = current.as_ref().unwrap_or(&self.root).as_raw_fd();
            let known = self.directories.get(&prefix);
            let open_or_retry = || match open_directory(base, &name) {
                Ok(next) => Ok(next),
                Err(error) if is_descriptor_exhaustion(&error) => {
                    let evicted = {
                        let mut recent = self
                            .recent_parents
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let had_entries = !recent.index.is_empty();
                        recent.clear();
                        had_entries
                    };
                    if evicted {
                        open_directory(base, &name)
                    } else {
                        Err(error)
                    }
                }
                Err(error) => Err(error),
            };
            let (next, created) = match open_or_retry() {
                Ok(next) => (next, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound && known.is_none() => {
                    budget.reserve(&prefix)?;
                    mkdir(base, &name)?;
                    match open_or_retry() {
                        Ok(directory) => (directory, true),
                        Err(error) => {
                            let _ = unlink(base, &name, libc::AT_REMOVEDIR);
                            return Err(path_error(error, &prefix));
                        }
                    }
                }
                Err(error) => return Err(path_error(error, &prefix)),
            };
            identity = Identity::from_metadata(&next.metadata()?);
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
        if let Some(file) = current {
            self.parent = Some(Parent {
                path: prefix,
                name: c_path(parent)?,
                file: Arc::new(file),
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
        let directory = self
            .parent
            .as_ref()
            .map_or(&self.root, |parent| &parent.file);
        let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
        Ok(NewFile {
            directory: Arc::clone(directory),
            name: CString::new(leaf.as_bytes()).map_err(invalid_path)?,
            path: path.to_path_buf(),
            recent_parents: Arc::downgrade(&self.recent_parents),
        })
    }

    fn validate_root(&self) -> Result<(), LpmError> {
        let metadata = std::fs::symlink_metadata(&self.root_path)?;
        if !metadata.is_dir() || Identity::from_metadata(&metadata) != self.root_identity {
            return Err(changed_directory(&self.root_path));
        }
        let visible = std::fs::metadata(&self.visible_root_path)?;
        if !visible.is_dir() || Identity::from_metadata(&visible) != self.root_identity {
            return Err(changed_directory(&self.visible_root_path));
        }
        Ok(())
    }

    pub(crate) fn validate_parent_for_inspection(&self) -> Result<(), LpmError> {
        self.validate_root()?;
        if let Some(parent) = &self.parent {
            let metadata = stat_at(self.root.as_raw_fd(), &parent.name)?;
            // Identity checking also rejects an intermediate symlink redirected to another tree.
            if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
                || Identity::from_stat(&metadata) != parent.identity
            {
                return Err(changed_directory(&parent.path));
            }
        }
        Ok(())
    }

    fn open_recorded_directory(&self, path: &Path) -> Result<Option<File>, LpmError> {
        let mut current = None::<File>;
        let mut prefix = PathBuf::with_capacity(path.as_os_str().len());
        for component in path.components() {
            prefix.push(component);
            let record = self
                .directories
                .get(&prefix)
                .ok_or_else(|| changed_directory(&prefix))?;
            let name = CString::new(component.as_os_str().as_bytes()).map_err(invalid_path)?;
            let next = open_directory(current.as_ref().unwrap_or(&self.root).as_raw_fd(), &name)
                .map_err(|error| path_error(error, &prefix))?;
            if Identity::from_metadata(&next.metadata()?) != record.identity {
                return Err(changed_directory(&prefix));
            }
            current = Some(next);
        }
        Ok(current)
    }

    pub(crate) fn validate(&mut self) -> Result<(), LpmError> {
        self.parent = None;
        self.recent_parents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.validate_root()?;
        for (path, record) in &self.directories {
            if let Some((directory, _)) = open_known_parent(&self.root, path)? {
                if Identity::from_metadata(&directory.metadata()?) != record.identity {
                    return Err(changed_directory(path));
                }
            } else {
                self.open_recorded_directory(path)?;
            }
        }
        Ok(())
    }

    pub(crate) fn accepted_file_identity(&self, path: &Path) -> Result<Identity, LpmError> {
        let directory = self
            .parent
            .as_ref()
            .map_or(&self.root, |parent| &parent.file);
        let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
        let name = CString::new(leaf.as_bytes()).map_err(invalid_path)?;
        let metadata = stat_at(directory.as_raw_fd(), &name)?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(changed_file(path));
        }
        Ok(Identity::from_stat(&metadata))
    }

    pub(crate) fn cleanup<E: ExtractionRecord>(&mut self, files: &[E], identities: &[Identity]) {
        self.parent = None;
        self.recent_parents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        if files.len() != identities.len() {
            return;
        }
        for (record, identity) in files.iter().zip(identities).rev() {
            let path = record.relative_path();
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(leaf) = path.file_name() else {
                continue;
            };
            if let Ok(directory) = self.open_recorded_directory(parent)
                && let Ok(name) = CString::new(leaf.as_bytes())
            {
                let base = directory.as_ref().unwrap_or(&self.root).as_raw_fd();
                if stat_at(base, &name)
                    .is_ok_and(|metadata| *identity == Identity::from_stat(&metadata))
                {
                    let _ = unlink(base, &name, 0);
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
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(leaf) = path.file_name() else {
                continue;
            };
            if let Ok(directory) = self.open_recorded_directory(parent)
                && let Ok(name) = CString::new(leaf.as_bytes())
            {
                let base = directory.as_ref().unwrap_or(&self.root).as_raw_fd();
                if let Ok(metadata) = stat_at(base, &name)
                    && metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                    && self
                        .directories
                        .get(path)
                        .is_some_and(|record| record.identity == Identity::from_stat(&metadata))
                {
                    let _ = unlink(base, &name, libc::AT_REMOVEDIR);
                }
            }
        }
    }
}

/// A regular file to create in a verified extraction directory.
pub(crate) struct NewFile {
    directory: Arc<File>,
    name: CString,
    path: PathBuf,
    recent_parents: Weak<Mutex<ParentCache>>,
}

impl NewFile {
    /// Create a brand-new regular file without following a symlink or
    /// overwriting an already-existing aliased entry (e.g. APFS NFC/NFD).
    pub(crate) fn create(self) -> Result<PendingFile, LpmError> {
        self.open(libc::O_EXCL)
    }

    /// Remove the regular file an earlier entry wrote at this name, then create it.
    fn replace(self) -> Result<PendingFile, LpmError> {
        let base = self.directory.as_raw_fd();
        let metadata = stat_at(base, &self.name)?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(LpmError::Registry(format!(
                "non-file path blocks duplicate tarball entry: {}",
                self.path.display()
            )));
        }
        unlink(base, &self.name, 0)?;
        self.open(libc::O_EXCL)
    }

    fn open(self, mode_flag: i32) -> Result<PendingFile, LpmError> {
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW | mode_flag;
        let base = self.directory.as_raw_fd();
        let open_result = match open_at(base, &self.name, flags, 0o666) {
            Ok(file) => Ok(file),
            Err(error) if is_descriptor_exhaustion(&error) => {
                let evicted = self.recent_parents.upgrade().is_some_and(|cache| {
                    let mut recent = cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let had_entries = !recent.index.is_empty();
                    recent.clear();
                    had_entries
                });
                if evicted {
                    open_at(base, &self.name, flags, 0o666)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        };
        let file = open_result.map_err(|error| {
            // POSIX specifies EEXIST for O_CREAT|O_EXCL|O_NOFOLLOW on an
            // existing symlink; classify symlinks as ELOOP so callers still
            // receive LpmError::PathTraversal.
            if error.kind() == io::ErrorKind::AlreadyExists
                && let Ok(meta) = stat_at(base, &self.name)
                && (meta.st_mode & libc::S_IFMT) == libc::S_IFLNK
            {
                return path_error(io::Error::from_raw_os_error(libc::ELOOP), &self.path);
            }
            path_error(error, &self.path)
        })?;
        Ok(PendingFile {
            file,
            directory: self.directory,
            name: self.name,
            committed: false,
        })
    }
}

fn unix_timespec_to_ns(secs: i64, nsec: i64) -> Option<u64> {
    u64::try_from(secs)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(nsec).ok()?)
}

fn unix_stamp_from_metadata(meta: &Metadata) -> Option<ExtractedFileStamp> {
    Some(ExtractedFileStamp {
        identity: lpm_common::FileIdentity {
            volume: meta.dev(),
            file_id: u128::from(meta.ino()),
        },
        size: meta.len(),
        mode: meta.mode() & 0o7777,
        mtime_ns: unix_timespec_to_ns(meta.mtime(), meta.mtime_nsec())?,
        ctime_ns: unix_timespec_to_ns(meta.ctime(), meta.ctime_nsec())?,
    })
}

fn unix_stamp_from_stat(current: &libc::stat) -> Option<ExtractedFileStamp> {
    let volume = u64::try_from(i128::from(current.st_dev)).ok()?;
    let ino = u64::try_from(i128::from(current.st_ino)).ok()?;
    let size = u64::try_from(i128::from(current.st_size)).ok()?;
    let mode = u32::try_from(i128::from(current.st_mode)).ok()? & 0o7777;
    let mtime = i64::try_from(i128::from(current.st_mtime)).ok()?;
    let mtime_nsec = i64::try_from(i128::from(current.st_mtime_nsec)).ok()?;
    let ctime = i64::try_from(i128::from(current.st_ctime)).ok()?;
    let ctime_nsec = i64::try_from(i128::from(current.st_ctime_nsec)).ok()?;
    Some(ExtractedFileStamp {
        identity: lpm_common::FileIdentity {
            volume,
            file_id: u128::from(ino),
        },
        size,
        mode,
        mtime_ns: unix_timespec_to_ns(mtime, mtime_nsec)?,
        ctime_ns: unix_timespec_to_ns(ctime, ctime_nsec)?,
    })
}

pub(crate) struct PendingFile {
    pub(crate) file: File,
    directory: Arc<File>,
    name: CString,
    committed: bool,
}
impl PendingFile {
    pub(crate) fn identity(&self) -> Result<Identity, LpmError> {
        Ok(Identity::from_metadata(&self.file.metadata()?))
    }
    pub(crate) fn validate(&self) -> Result<(), LpmError> {
        let written = self.file.metadata()?;
        let current = stat_at(self.directory.as_raw_fd(), &self.name)?;
        if current.st_mode & libc::S_IFMT != libc::S_IFREG
            || Identity::from_metadata(&written) != Identity::from_stat(&current)
        {
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
    pub(crate) fn commit_with_stamp(
        mut self,
    ) -> Result<(Identity, Option<ExtractedFileStamp>), LpmError> {
        let meta = self.file.metadata()?;
        let identity = Identity::from_metadata(&meta);
        let stamp = unix_stamp_from_metadata(&meta);
        self.committed = true;
        Ok((identity, stamp))
    }
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(written) = self.file.metadata()
            && let Ok(current) = stat_at(self.directory.as_raw_fd(), &self.name)
            && Identity::from_metadata(&written) == Identity::from_stat(&current)
        {
            let _ = unlink(self.directory.as_raw_fd(), &self.name, 0);
        }
    }
}

fn invalid_path(_: std::ffi::NulError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "tarball target contains a NUL byte",
    )
}
fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(invalid_path)
}
pub(crate) struct CompletedFile {
    // Pin the original file identity until ordered acceptance or rollback.
    pending: PendingFile,
    identity: Identity,
}

impl CompletedFile {
    pub(crate) fn verify_for_commit(&self) -> Result<Option<ExtractedFileStamp>, LpmError> {
        let current = stat_at(self.pending.directory.as_raw_fd(), &self.pending.name)?;
        if current.st_mode & libc::S_IFMT != libc::S_IFREG
            || self.identity != Identity::from_stat(&current)
        {
            return Err(LpmError::Registry(
                "tarball output file changed before acceptance".into(),
            ));
        }
        Ok(unix_stamp_from_stat(&current))
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
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        LpmError::Registry(format!(
            "path traversal detected or non-directory in tarball target: {}",
            path.display()
        ))
    } else {
        LpmError::Io(error)
    }
}
fn owned_file(descriptor: RawFd) -> io::Result<File> {
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: The successful open returned a new descriptor owned by this File.
        File::from_raw_fd(descriptor)
    })
}
fn open_directory(base: RawFd, name: &CStr) -> io::Result<File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let access = libc::O_PATH;
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "aix"
    ))]
    let access = libc::O_SEARCH;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "aix"
    )))]
    let access = libc::O_RDONLY;
    open_at(
        base,
        name,
        access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

#[cfg(target_vendor = "apple")]
fn open_known_parent(root: &File, path: &Path) -> io::Result<Option<(File, CString)>> {
    let path = c_path(path)?;
    match open_at(
        root.as_raw_fd(),
        &path,
        libc::O_SEARCH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY,
        0,
    ) {
        Ok(directory) => Ok(Some((directory, path))),
        Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn open_known_parent(root: &File, path: &Path) -> io::Result<Option<(File, CString)>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    let path = c_path(path)?;
    match rustix::fs::openat2(
        root,
        path.as_c_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(directory) => Ok(Some((File::from(directory), path))),
        Err(error) if confined_open_unavailable(error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn confined_open_unavailable(error: rustix::io::Errno) -> bool {
    // Some sandbox filters report an unavailable syscall as EPERM.
    matches!(
        error,
        rustix::io::Errno::NOSYS
            | rustix::io::Errno::INVAL
            | rustix::io::Errno::NOTSUP
            | rustix::io::Errno::PERM
    )
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn open_known_parent(_root: &File, _path: &Path) -> io::Result<Option<(File, CString)>> {
    Ok(None)
}
fn mkdir(base: RawFd, name: &CStr) -> io::Result<()> {
    retry_syscall(|| unsafe {
        // SAFETY: The base descriptor is live and name is NUL-terminated.
        libc::mkdirat(base, name.as_ptr(), 0o777)
    })
}
fn unlink(base: RawFd, name: &CStr, flags: i32) -> io::Result<()> {
    retry_syscall(|| unsafe {
        // SAFETY: The base descriptor is live and name is NUL-terminated.
        libc::unlinkat(base, name.as_ptr(), flags)
    })
}
fn stat_at(base: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    retry_syscall(|| unsafe {
        // SAFETY: name is NUL-terminated and metadata points to writable stat storage.
        libc::fstatat(
            base,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(unsafe {
        // SAFETY: Successful fstatat initialized the entire structure.
        metadata.assume_init()
    })
}
fn open_at(base: RawFd, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        let descriptor = unsafe {
            // SAFETY: The base descriptor is live and name is NUL-terminated.
            libc::openat(base, name.as_ptr(), flags, mode as libc::c_uint)
        };
        match owned_file(descriptor) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn retry_syscall(mut syscall: impl FnMut() -> i32) -> io::Result<()> {
    loop {
        if syscall() >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    fn kernel_supports_confined_open(root: &File) -> bool {
        match rustix::fs::openat2(
            root,
            c".",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        ) {
            Ok(_) => true,
            Err(
                rustix::io::Errno::NOSYS
                | rustix::io::Errno::INVAL
                | rustix::io::Errno::NOTSUP
                | rustix::io::Errno::PERM,
            ) => false,
            Err(error) => panic!("cannot probe confined directory opening: {error}"),
        }
    }

    #[test]
    fn known_parent_reopen_uses_kernel_confinement_when_available() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib/inner")).unwrap();
        let root = File::open(dir.path()).unwrap();
        if !kernel_supports_confined_open(&root) {
            return;
        }
        let (opened, _) = open_known_parent(&root, Path::new("lib/inner"))
            .unwrap()
            .expect("supported kernels must use the confined directory open");
        assert!(
            Identity::from_metadata(&opened.metadata().unwrap())
                == Identity::from_metadata(
                    &std::fs::metadata(dir.path().join("lib/inner")).unwrap()
                )
        );
    }

    #[test]
    fn known_parent_reopen_rejects_symlink_components() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib/inner")).unwrap();
        let root = File::open(dir.path()).unwrap();
        if !kernel_supports_confined_open(&root) {
            return;
        }
        std::fs::rename(dir.path().join("lib"), dir.path().join("moved")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("moved"), dir.path().join("lib")).unwrap();
        let result = open_known_parent(&root, Path::new("lib/inner"));
        assert!(matches!(result, Err(error) if error.raw_os_error() == Some(libc::ELOOP)));
    }

    #[test]
    fn confined_open_falls_back_only_for_unavailable_capabilities() {
        use rustix::io::Errno;
        for error in [Errno::NOSYS, Errno::INVAL, Errno::NOTSUP, Errno::PERM] {
            assert!(confined_open_unavailable(error), "{error}");
        }
        for error in [
            Errno::AGAIN,
            Errno::LOOP,
            Errno::XDEV,
            Errno::NOENT,
            Errno::NOTDIR,
            Errno::ACCESS,
            Errno::IO,
        ] {
            assert!(!confined_open_unavailable(error), "{error}");
        }
    }
}

#[cfg(test)]
mod parent_cache_tests {
    use super::*;

    fn dummy_parent(file: &Arc<File>, name: &str, inode: i128) -> Parent {
        Parent {
            path: PathBuf::from(name),
            name: CString::new(name).unwrap(),
            file: Arc::clone(file),
            identity: Identity { device: 1, inode },
        }
    }

    #[test]
    fn parent_cache_evicts_least_recently_used_entry_in_constant_time() {
        let dir = tempfile::tempdir().unwrap();
        let file = Arc::new(File::open(dir.path()).unwrap());
        let mut cache = ParentCache::with_capacity(3);
        cache.insert(dummy_parent(&file, "a", 1));
        cache.insert(dummy_parent(&file, "b", 2));
        cache.insert(dummy_parent(&file, "c", 3));

        // Promote `a` by taking and re-inserting it, then insert `d` so `b` is evicted.
        let promoted = cache.take(Path::new("a")).unwrap();
        assert_eq!(promoted.identity.inode, 1);
        cache.insert(promoted);
        cache.insert(dummy_parent(&file, "d", 4));

        assert!(cache.take(Path::new("b")).is_none());
        assert_eq!(cache.take(Path::new("a")).unwrap().identity.inode, 1);
        assert_eq!(cache.take(Path::new("c")).unwrap().identity.inode, 3);
        assert_eq!(cache.take(Path::new("d")).unwrap().identity.inode, 4);
    }

    #[test]
    fn parent_cache_capacity_leaves_descriptor_headroom_for_concurrent_extractions() {
        let at_512 = parent_cache_capacity_for_limit(512, 8);
        assert!(
            at_512 * 8 <= 128,
            "8 concurrent extractions at RLIMIT_NOFILE=512 must stay within 25% of soft limit, got {at_512} each"
        );
        assert_eq!(parent_cache_capacity_for_limit(64, 8), MIN_CACHED_PARENTS);
        assert_eq!(
            parent_cache_capacity_for_limit(10_240, 4),
            MAX_CACHED_PARENTS
        );
    }

    #[test]
    fn root_file_creation_evicts_cached_parent_dirfds_on_emfile() {
        const CHILD: &str = "LPM_TEST_ROOT_FILE_EMFILE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "output::unix::parent_cache_tests::root_file_creation_evicts_cached_parent_dirfds_on_emfile",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is valid writable storage for `getrlimit`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let tight = libc::rlimit {
            rlim_cur: 64.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: lowering soft limit to <= hard limit in this isolated child process.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) }, 0);

        let mut output =
            OutputTree::new(dir.path().to_path_buf(), dir.path().to_path_buf()).unwrap();
        let mut budget = PathLedgerBudget::new(1024 * 1024);
        for idx in 0..16 {
            let rel = PathBuf::from(format!("sub{idx}/file.js"));
            output.prepare_parent(&rel, &mut budget).unwrap();
            let pending = output.create_file(&rel, false).unwrap();
            pending.commit();
        }
        // Park the last parent into recent_parents by preparing a root-level file.
        let root_file = Path::new("root-entry.js");
        output.prepare_parent(root_file, &mut budget).unwrap();

        // Exhaust all remaining file descriptors until opening fails with EMFILE.
        let mut fillers = Vec::new();
        while let Ok(f) = File::open(dir.path()) {
            fillers.push(f);
        }

        // Creating the root-level file must evict cached parent dirfds and succeed.
        let pending = output
            .create_file(root_file, false)
            .expect("file creation must evict cached parent dirfds on EMFILE");
        pending.commit();
        drop(fillers);
    }
}
