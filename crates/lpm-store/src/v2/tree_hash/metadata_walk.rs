//! Parallel directory collection for the tree metadata digest.
//!
//! The digest hashes one record per entry in depth-first order with sorted
//! names. Directory reads dominate its cost, so helper threads read directories
//! concurrently and the caller hashes the collected entries in walk order. The
//! digest and the first reported error match a sequential walk.

use super::*;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// Directories that must be waiting before helper threads start. Most package
/// trees finish on the calling thread without starting any.
const HELPER_START_PENDING_DIRS: usize = 16;
/// Threads reading directories concurrently, including the caller.
const WALK_THREADS: usize = 4;

#[derive(Clone, Copy)]
pub(super) enum MetadataReader {
    #[cfg(target_os = "macos")]
    Bulk,
    Portable,
}

impl MetadataReader {
    fn buffer(self) -> Vec<u8> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Bulk => vec![0; 64 * 1024],
            Self::Portable => Vec::new(),
        }
    }

    fn read(
        self,
        root: &Path,
        dir: &Path,
        buffer: &mut [u8],
    ) -> Result<Vec<ObjectTreeEntry>, LpmError> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Bulk => {
                let mut entries = read_bulk_metadata_entries(dir, buffer)?;
                entries.retain(|entry| !is_object_metadata_sidecar_name(root, dir, &entry.name));
                Ok(entries)
            }
            Self::Portable => {
                let _ = buffer;
                read_object_tree_entries(root, dir)
            }
        }
    }

    /// Bulk records carry no symlink size, so that walk hashes the target length.
    fn symlink_len(self, entry: &ObjectTreeEntry, target: &[u8]) -> u64 {
        match self {
            #[cfg(target_os = "macos")]
            Self::Bulk => target.len() as u64,
            Self::Portable => {
                let _ = target;
                entry.len
            }
        }
    }
}

enum CollectedKind {
    Directory(usize),
    File,
    Symlink(Result<Vec<u8>, LpmError>),
    Unsupported,
}

struct CollectedEntry {
    entry: ObjectTreeEntry,
    kind: CollectedKind,
}

struct CollectedDir {
    path: PathBuf,
    entries: Result<Vec<CollectedEntry>, LpmError>,
}

struct PendingDir {
    id: usize,
    path: PathBuf,
}

struct WalkState {
    pending: Vec<PendingDir>,
    active: usize,
    dirs: Vec<Option<CollectedDir>>,
}

struct Walk<'a> {
    root: &'a Path,
    reader: MetadataReader,
    state: Mutex<WalkState>,
    changed: Condvar,
}

impl Walk<'_> {
    fn lock(&self) -> MutexGuard<'_, WalkState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_dir(&self) -> Option<PendingDir> {
        let mut state = self.lock();
        loop {
            if let Some(dir) = state.pending.pop() {
                state.active += 1;
                return Some(dir);
            }
            if state.active == 0 {
                return None;
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Read one directory and publish it; returns the number of waiting directories.
    fn process(&self, dir: PendingDir, buffer: &mut [u8]) -> usize {
        let read = self
            .reader
            .read(self.root, &dir.path, buffer)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| {
                        let kind = match entry.kind {
                            ObjectTreeEntryKind::Directory => CollectedKind::Directory(usize::MAX),
                            ObjectTreeEntryKind::File => CollectedKind::File,
                            ObjectTreeEntryKind::Symlink => CollectedKind::Symlink(
                                read_symlink_target(&dir.path.join(&entry.name)),
                            ),
                            ObjectTreeEntryKind::Unsupported => CollectedKind::Unsupported,
                        };
                        CollectedEntry { entry, kind }
                    })
                    .collect::<Vec<_>>()
            });

        let mut state = self.lock();
        let entries = read.map(|mut entries| {
            for collected in &mut entries {
                if let CollectedKind::Directory(child) = &mut collected.kind {
                    *child = state.dirs.len();
                    state.dirs.push(None);
                    state.pending.push(PendingDir {
                        id: *child,
                        path: dir.path.join(&collected.entry.name),
                    });
                }
            }
            entries
        });
        state.dirs[dir.id] = Some(CollectedDir {
            path: dir.path,
            entries,
        });
        state.active -= 1;
        let pending = state.pending.len();
        drop(state);
        self.changed.notify_all();
        pending
    }

    fn work(&self) {
        let mut buffer = self.reader.buffer();
        while let Some(dir) = self.next_dir() {
            self.process(dir, &mut buffer);
        }
    }
}

fn read_symlink_target(path: &Path) -> Result<Vec<u8>, LpmError> {
    let target = std::fs::read_link(path).map_err(|e| {
        LpmError::Store(format!(
            "failed to read virtual-store object symlink {}: {e}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    push_os_str_bytes(&mut bytes, target.as_os_str());
    Ok(bytes)
}

struct Collected {
    dirs: Vec<Option<CollectedDir>>,
    helpers: usize,
}

fn collect(root: &Path, reader: MetadataReader) -> Collected {
    let walk = Walk {
        root,
        reader,
        state: Mutex::new(WalkState {
            pending: vec![PendingDir {
                id: 0,
                path: root.to_path_buf(),
            }],
            active: 0,
            dirs: vec![None],
        }),
        changed: Condvar::new(),
    };
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(WALK_THREADS);
    let mut helpers = 0;
    let mut helpers_requested = false;
    std::thread::scope(|scope| {
        let mut buffer = reader.buffer();
        while let Some(dir) = walk.next_dir() {
            let pending = walk.process(dir, &mut buffer);
            if !helpers_requested && pending >= HELPER_START_PENDING_DIRS {
                helpers_requested = true;
                for _ in 1..threads {
                    // A failed spawn leaves the remaining reads on the threads that exist.
                    if std::thread::Builder::new()
                        .name("lpm-tree-walk".to_owned())
                        .spawn_scoped(scope, || walk.work())
                        .is_ok()
                    {
                        helpers += 1;
                    }
                }
            }
        }
    });
    Collected {
        dirs: walk
            .state
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .dirs,
        helpers,
    }
}

fn hash_collected(
    dirs: &mut [Option<CollectedDir>],
    id: usize,
    reader: MetadataReader,
    relative: &mut Vec<u8>,
    hasher: &mut Sha256,
) -> Result<(), LpmError> {
    let dir = dirs.get_mut(id).and_then(Option::take).ok_or_else(|| {
        LpmError::Store("virtual-store metadata walk lost a discovered directory".to_owned())
    })?;
    for collected in dir.entries? {
        let relative_len = relative.len();
        if relative_len != 0 {
            relative.push(b'/');
        }
        push_os_str_bytes(relative, &collected.entry.name);
        let entry = &collected.entry;
        let result = match collected.kind {
            CollectedKind::Directory(child) => {
                hash_tree_metadata_record(hasher, b"dir", relative, entry, &[]);
                hash_collected(dirs, child, reader, relative, hasher)
            }
            CollectedKind::File => {
                hash_tree_metadata_record(hasher, b"file", relative, entry, &[]);
                Ok(())
            }
            CollectedKind::Symlink(target) => target.map(|target| {
                hash_tree_metadata_fields(
                    hasher,
                    b"symlink",
                    relative,
                    entry.mode,
                    reader.symlink_len(entry, &target),
                    entry.modified_time_nanos,
                    entry.change_time_nanos,
                    &target,
                );
            }),
            CollectedKind::Unsupported => Err(LpmError::Store(format!(
                "unsupported virtual-store object entry type at {}",
                dir.path.join(&entry.name).display()
            ))),
        };
        relative.truncate(relative_len);
        result?;
    }
    Ok(())
}

pub(super) fn tree_metadata_integrity(
    root: &Path,
    reader: MetadataReader,
) -> Result<String, LpmError> {
    tree_metadata_integrity_with_helpers(root, reader).map(|(integrity, _)| integrity)
}

fn tree_metadata_integrity_with_helpers(
    root: &Path,
    reader: MetadataReader,
) -> Result<(String, usize), LpmError> {
    let Collected { mut dirs, helpers } = collect(root, reader);
    let mut hasher = Sha256::new();
    hash_collected(&mut dirs, 0, reader, &mut Vec::new(), &mut hasher)?;
    Ok((
        format!("sha256-{}", hex::encode(hasher.finalize())),
        helpers,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequential_portable(root: &Path) -> Result<String, LpmError> {
        let mut hasher = Sha256::new();
        hash_object_tree_dir(root, root, None, &mut hasher, None)?;
        Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
    }

    /// A tree wide enough to start helper threads, with nested files and symlinks.
    fn wide_tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("package.json"), b"{}").unwrap();
        for branch in 0..24 {
            let branch_dir = root.path().join(format!("branch-{branch:02}"));
            for leaf in 0..3 {
                let leaf_dir = branch_dir.join(format!("leaf-{leaf}"));
                std::fs::create_dir_all(&leaf_dir).unwrap();
                for file in 0..4 {
                    std::fs::write(leaf_dir.join(format!("file-{file}.js")), [branch as u8; 17])
                        .unwrap();
                }
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink("leaf-0/file-0.js", branch_dir.join("entry.js")).unwrap();
        }
        root
    }

    #[test]
    fn parallel_walk_matches_the_sequential_digest_and_uses_helpers() {
        let tree = wide_tree();
        let (parallel, helpers) =
            tree_metadata_integrity_with_helpers(tree.path(), MetadataReader::Portable).unwrap();
        assert_eq!(parallel, sequential_portable(tree.path()).unwrap());
        if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) > 1 {
            assert!(helpers > 0, "a wide tree must start helper threads");
        }
    }

    #[test]
    fn small_trees_stay_on_the_calling_thread() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tree.path().join("lib/nested")).unwrap();
        std::fs::write(tree.path().join("lib/nested/index.js"), b"x").unwrap();
        let (parallel, helpers) =
            tree_metadata_integrity_with_helpers(tree.path(), MetadataReader::Portable).unwrap();
        assert_eq!(helpers, 0);
        assert_eq!(parallel, sequential_portable(tree.path()).unwrap());
    }

    #[test]
    fn parallel_walk_ignores_root_sidecars_only() {
        let tree = wide_tree();
        let before = tree_metadata_integrity(tree.path(), MetadataReader::Portable).unwrap();
        std::fs::write(tree.path().join(TREE_SNAPSHOT_FILENAME), b"{}").unwrap();
        assert_eq!(
            tree_metadata_integrity(tree.path(), MetadataReader::Portable).unwrap(),
            before
        );
        std::fs::write(
            tree.path().join("branch-03").join(TREE_SNAPSHOT_FILENAME),
            b"{}",
        )
        .unwrap();
        assert_ne!(
            tree_metadata_integrity(tree.path(), MetadataReader::Portable).unwrap(),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn parallel_walk_reports_the_first_error_in_walk_order() {
        use std::os::unix::fs::PermissionsExt as _;
        let tree = wide_tree();
        let fifo = tree.path().join("branch-01/leaf-2/pipe");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let unreadable = tree.path().join("branch-20/leaf-1");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let parallel = tree_metadata_integrity(tree.path(), MetadataReader::Portable);
        let sequential = sequential_portable(tree.path());
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            parallel.unwrap_err().to_string(),
            sequential.unwrap_err().to_string()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bulk_and_portable_parallel_walks_agree() {
        let tree = wide_tree();
        assert_eq!(
            tree_metadata_integrity(tree.path(), MetadataReader::Bulk).unwrap(),
            tree_metadata_integrity(tree.path(), MetadataReader::Portable).unwrap()
        );
    }
}
