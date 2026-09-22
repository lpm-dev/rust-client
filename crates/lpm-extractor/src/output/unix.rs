use crate::{ExtractionRecord, PathLedgerBudget};
use lpm_common::LpmError;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Eq, PartialEq)]
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
    file: File,
    identity: Identity,
}

pub(crate) struct OutputTree {
    root_path: PathBuf,
    visible_root_path: PathBuf,
    root: File,
    root_identity: Identity,
    directories: HashMap<PathBuf, DirectoryRecord>,
    parent: Option<Parent>,
}

impl OutputTree {
    pub(crate) fn new(root_path: PathBuf, visible_root_path: PathBuf) -> Result<Self, LpmError> {
        let root = open_directory(libc::AT_FDCWD, &c_path(&root_path)?)?;
        let root_identity = Identity::from_metadata(&root.metadata()?);
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
        if let Some(record) = self.directories.get(parent)
            && let Some((directory, name)) = open_known_parent(&self.root, parent)?
        {
            let identity = Identity::from_metadata(&directory.metadata()?);
            if identity != record.identity {
                return Err(changed_directory(parent));
            }
            self.parent = Some(Parent {
                path: parent.to_path_buf(),
                name,
                file: directory,
                identity,
            });
            return Ok(());
        }
        let mut current = None::<File>;
        let mut prefix = PathBuf::with_capacity(parent.as_os_str().len());
        let mut identity = self.root_identity;
        for component in parent.components() {
            prefix.push(component);
            let name = CString::new(component.as_os_str().as_bytes()).map_err(invalid_path)?;
            let base = current.as_ref().unwrap_or(&self.root).as_raw_fd();
            let known = self.directories.get(&prefix);
            let (next, created) = match open_directory(base, &name) {
                Ok(next) => (next, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound && known.is_none() => {
                    budget.reserve(&prefix)?;
                    mkdir(base, &name)?;
                    match open_directory(base, &name) {
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
                if !created {
                    budget.reserve(&prefix)?;
                }
                self.directories
                    .insert(prefix.clone(), DirectoryRecord { identity, created });
            }
            current = Some(next);
        }
        if let Some(file) = current {
            self.parent = Some(Parent {
                path: prefix,
                name: c_path(parent)?,
                file,
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
        let directory = self
            .parent
            .as_ref()
            .map_or(&self.root, |parent| &parent.file);
        let leaf = path.file_name().ok_or_else(|| changed_directory(path))?;
        let name = CString::new(leaf.as_bytes()).map_err(invalid_path)?;
        let base = directory.as_raw_fd();
        if duplicate {
            let metadata = stat_at(base, &name)?;
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(LpmError::Registry(format!(
                    "non-file path blocks duplicate tarball entry: {}",
                    path.display()
                )));
            }
            unlink(base, &name, 0)?;
        }
        let flags = libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if duplicate {
                libc::O_EXCL
            } else {
                libc::O_TRUNC
            };
        let file = open_at(base, &name, flags, 0o666).map_err(|error| path_error(error, path))?;
        Ok(PendingFile {
            file,
            directory,
            name,
            committed: false,
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

pub(crate) struct PendingFile<'a> {
    pub(crate) file: File,
    directory: &'a File,
    name: CString,
    committed: bool,
}
impl PendingFile<'_> {
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
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for PendingFile<'_> {
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
