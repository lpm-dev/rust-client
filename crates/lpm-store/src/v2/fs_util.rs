use std::path::{Path, PathBuf};

use lpm_common::{LpmError, is_symlink_or_junction};

use super::integrity::has_local_source_sentinel;
use super::tree_hash::{TreeMetadataBuilder, TreeMetadataKind, is_object_metadata_sidecar};

pub(crate) fn tmp_sibling(dir: &Path) -> PathBuf {
    // Random 64-bit suffix replaces the pid+tid pair so a same-UID
    // attacker can't predict the tmp path and plant a symlink there
    // before we create the dir. PID + thread::id() are both
    // observable in /proc on Linux; the random suffix is uniformly
    // unpredictable across all UIDs that can read the parent dir.
    use rand::Rng;
    let suffix: u64 = rand::rng().next_u64();
    dir.with_extension(format!("tmp.{suffix:016x}"))
}

/// Whether `name` is a staging directory that [`tmp_sibling`] made: an
/// entry an install is still writing, or one an interrupted install left.
pub fn is_staging_dir_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.rsplit_once(".tmp."))
        .is_some_and(|(_, suffix)| {
            suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Pre-create a tmp staging dir at 0o700 on Unix so partial extracts
/// can't be read by other UIDs on a shared host. The extractor will
/// `create_dir_all` again on this same path — a no-op once the dir
/// already exists at the restricted mode. On filesystems without
/// POSIX modes the mode is silently ignored, which matches the
/// broader credential-metadata posture.
pub(crate) fn create_tmp_dir_locked(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Ensure a store-tier directory exists at 0o700. Idempotent — if the
/// directory is already present, its perms are tightened in place.
///
/// `~/.lpm/store/v2/objects/` and `~/.lpm/store/v2/links/` carry
/// extracted package bytes (including private `@org/*` packages).
/// `create_dir_all`'s default-umask creation lets shared-host /
/// shared-CI-runner / NFS-mounted layouts disclose those bytes to
/// every other local uid. Stamping 0o700 on the store-tier dirs
/// closes that shape without touching how each link entry stages —
/// the per-entry tmp dir is also 0o700, and intra-tree perms are
/// preserved via the atomic rename.
///
/// No-op on platforms without POSIX modes, where the perms knob does
/// not apply.
pub(crate) fn ensure_store_tier_dir_locked(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !is_symlink_or_junction(&metadata) => metadata,
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "refusing non-directory store tier at {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                builder.mode(0o700);
                builder.create(path)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(path)?;
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir() || is_symlink_or_junction(&metadata) {
                return Err(std::io::Error::other(format!(
                    "refusing non-directory store tier at {}",
                    path.display()
                )));
            }
            metadata
        }
        Err(error) => return Err(error),
    };

    #[cfg(target_os = "macos")]
    drop_inherited_access(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 == 0o700 {
            Ok(())
        } else {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(())
    }
}

/// [`ensure_store_tier_dir_locked`] for an existing tier a reuse reads,
/// which an earlier release may have left open to others, once per process:
/// later reuses from the same tier check nothing. A missing tier is left
/// for the writer that creates it.
pub(crate) fn harden_store_tier_once(path: &Path) -> std::io::Result<()> {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex, PoisonError};

    static HARDENED: LazyLock<Mutex<HashSet<PathBuf>>> =
        LazyLock::new(|| Mutex::new(HashSet::new()));
    if HARDENED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(path)
    {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    ensure_store_tier_dir_locked(path)?;
    HARDENED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(path.to_path_buf());
    Ok(())
}

/// Drops the access list entries the store directory at `path` took from
/// the directory above it, which grant access its mode doesn't, and pass on
/// to everything extracted inside.
#[cfg(target_os = "macos")]
fn drop_inherited_access(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if !lpm_common::macos_acl::has_extended_acl_at(path)? {
        return Ok(());
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(::libc::O_DIRECTORY | ::libc::O_NOFOLLOW | ::libc::O_CLOEXEC)
        .open(path)?;
    lpm_common::macos_acl::drop_extended_acl(&directory)
}

/// Recursively copy `src/` to `dst/`. Used by the v1 → v2 cache-hit
/// translation. `std::fs::copy` invokes the kernel's
/// `copy_file_range(2)` on Linux (CoW reflink on Btrfs/XFS) and
/// `fcopyfile(2)` on macOS, so the copy is essentially free on
/// reflink-capable filesystems and bounded by a single tar-extract's
/// IO cost otherwise. We don't reach for `clonefile()` directly — the
/// translation runs once per package per machine, never on the hot
/// install path.
pub(crate) fn copy_dir_recursively(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_src = entry.path();
        let entry_dst = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursively(&entry_src, &entry_dst)?;
        } else if ft.is_symlink() {
            // Refuse to migrate symlinks from a v1 store entry into the
            // v2 object dir. The v1 extractor's `is_file()` filter
            // already prevents symlinks from being written into store
            // entries under normal operation, so a symlink here is
            // either (a) a manually-planted artefact by a local attacker
            // or (b) a regression in the v1 extractor's filter. Both
            // cases would faithfully reproduce the symlink target into
            // every link entry that consumed the migrated object —
            // i.e. a `/etc/passwd` symlink becomes readable through
            // every consuming project's node_modules. Skip with a
            // tracing::warn so the migration completes for the
            // surrounding files but the unsafe link is dropped.
            tracing::warn!(
                src = %entry_src.display(),
                "v1→virtual-store copy: skipping symlink (refused — v1 store entries should not contain symlinks)",
            );
        } else if ft.is_file() {
            std::fs::copy(&entry_src, &entry_dst)?;
        }
        // Block / char / fifo entries inside an extracted npm
        // package would be malformed input — silently skip.
    }
    Ok(())
}

// Centralized symlink helper so v2 inherits the linker's Windows
// `mklink /J` junction fallback automatically — a hand-written
// `symlink_dir`-only path would regress Windows users without
// Developer Mode.
pub(crate) use lpm_common::symlink::create_dir_symlink_or_junction as create_dir_symlink;
pub(crate) use lpm_common::symlink::create_symlink as create_fs_symlink;

/// Materialize `src/` into `dst/` using independent bytes.
///
/// macOS gets `clonefile()` for whole-directory copy-on-write. Other
/// platforms use file copies, which lets Linux choose copy_file_range or
/// filesystem reflinks without sharing hardlink inodes between the object
/// store and executable link entries.
pub(crate) fn materialize_into(src: &Path, dst: &Path) -> Result<(), LpmError> {
    let allow_source_symlinks = has_local_source_sentinel(src);
    materialize_into_inner(src, src, dst, allow_source_symlinks)
}

#[tracing::instrument(
    target = "lpm_install_timeline",
    level = "trace",
    name = "link_materialize",
    skip_all
)]
pub(crate) fn materialize_into_with_integrity(
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<Option<String>, LpmError> {
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            remove_materialized_object_sidecars(dst)?;
            return Ok(None);
        }
    }
    materialize_into_portable_with_integrity_inner(src, dst, allow_source_symlinks).map(Some)
}

fn materialize_into_portable_with_integrity_inner(
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<String, LpmError> {
    let mut metadata = TreeMetadataBuilder::new();
    materialize_into_inner_impl(
        src,
        src,
        dst,
        dst,
        allow_source_symlinks,
        false,
        Some(&mut metadata),
    )?;
    Ok(metadata.finish())
}

#[cfg(test)]
pub(crate) fn materialize_into_portable_with_integrity(
    src: &Path,
    dst: &Path,
) -> Result<String, LpmError> {
    materialize_into_portable_with_integrity_inner(src, dst, has_local_source_sentinel(src))
}

#[cfg(all(test, unix))]
pub(crate) fn materialize_into_portable_with_integrity_and_symlink_policy(
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<String, LpmError> {
    materialize_into_portable_with_integrity_inner(src, dst, allow_source_symlinks)
}

pub(crate) fn materialize_into_inner(
    root: &Path,
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<(), LpmError> {
    materialize_into_inner_impl(root, src, dst, dst, allow_source_symlinks, true, None)
}

fn materialize_into_inner_impl(
    root: &Path,
    src: &Path,
    dst: &Path,
    destination_root: &Path,
    allow_source_symlinks: bool,
    allow_clonefile: bool,
    mut tree_metadata: Option<&mut TreeMetadataBuilder>,
) -> Result<(), LpmError> {
    #[cfg(target_os = "macos")]
    {
        if allow_clonefile && try_clonefile(src, dst) {
            remove_materialized_object_sidecars(dst)?;
            return Ok(());
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = allow_clonefile;

    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "failed to create virtual-store link package dir at {}: {e}",
            dst.display()
        ))
    })?;

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read virtual-store source object dir {}: {e}",
            src.display()
        ))
    })? {
        let entry = entry.map_err(|e| {
            LpmError::Store(format!("failed to enumerate virtual-store source dir: {e}"))
        })?;
        // The listing reports entry types on the file systems stores live
        // on; `file_type` stats only where it doesn't.
        let file_type = entry.file_type().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat virtual-store source entry {}: {e}",
                entry.path().display()
            ))
        })?;
        entries.push((entry.file_name(), file_type));
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (name, file_type) in entries {
        let src_path = src.join(&name);
        if is_object_metadata_sidecar(root, &src_path) {
            continue;
        }
        let dst_path = dst.join(&name);

        if file_type.is_dir() {
            let record = tree_metadata
                .as_deref_mut()
                .map(|metadata| {
                    metadata.reserve(destination_root, &dst_path, TreeMetadataKind::Directory)
                })
                .transpose()?;
            materialize_into_inner_impl(
                root,
                &src_path,
                &dst_path,
                destination_root,
                allow_source_symlinks,
                allow_clonefile,
                tree_metadata.as_deref_mut(),
            )?;
            if let (Some(metadata), Some(record)) = (tree_metadata.as_deref_mut(), record) {
                metadata.refresh(record, &dst_path, Vec::new())?;
            }
        } else if file_type.is_symlink() {
            if !allow_source_symlinks {
                // Refuse symlink entries — the extractor's `is_file()`
                // filter blocks them at extract time, so a symlink under
                // `objects/` means a same-UID actor planted it. Symmetric
                // with the v1→v2 `copy_dir_recursively` refusal.
                let target = std::fs::read_link(&src_path).unwrap_or_default();
                return Err(LpmError::Store(format!(
                    "refusing virtual-store symlink entry {} → {}; symlinks must not appear under objects/",
                    src_path.display(),
                    target.display(),
                )));
            }
            let target = std::fs::read_link(&src_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read virtual-store local-source symlink {}: {e}",
                    src_path.display()
                ))
            })?;
            create_fs_symlink(&target, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to recreate virtual-store local-source symlink {} → {}: {e}",
                    dst_path.display(),
                    target.display()
                ))
            })?;
            if let Some(metadata) = tree_metadata.as_deref_mut() {
                metadata.record(
                    destination_root,
                    &dst_path,
                    TreeMetadataKind::Symlink,
                    os_str_bytes(target.as_os_str()),
                )?;
            }
        } else {
            materialize_regular_file(&src_path, &dst_path)?;
            if let Some(metadata) = tree_metadata.as_deref_mut() {
                // Stat by path once the copy is closed: NFS and some FUSE
                // mounts settle mtime at close, after any handle stat.
                metadata.record(
                    destination_root,
                    &dst_path,
                    TreeMetadataKind::File,
                    Vec::new(),
                )?;
            }
        }
    }

    Ok(())
}

fn materialize_regular_file(src: &Path, dst: &Path) -> Result<(), LpmError> {
    #[cfg(target_os = "linux")]
    {
        linux_copy::copy_file(src, dst)
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::fs::copy(src, dst).map_err(|copy_err| {
            LpmError::Store(format!(
                "failed to copy virtual-store source file {} → {}: {copy_err}",
                src.display(),
                dst.display()
            ))
        })?;
        Ok(())
    }
}

#[cfg(unix)]
fn os_str_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_str_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn os_str_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

#[cfg(target_os = "linux")]
pub(crate) mod linux_copy {
    use lpm_common::LpmError;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Smaller files are copied rather than reflinked. Cloning a file
    /// written moments earlier first forces its dirty pages to disk, which
    /// on XFS and btrfs costs more than copying a small file. `copy_file_range`
    /// can't stand in for the copy: on those file systems it clones too.
    pub(crate) const MIN_REFLINK_BYTES: u64 = 64 * 1024;

    const COPY_BUFFER_BYTES: usize = 64 * 1024;

    /// The last device that refused a reflink, or `u64::MAX`.
    static NO_REFLINK_DEVICE: AtomicU64 = AtomicU64::new(u64::MAX);
    /// The last `(src_dev, dst_dev)` pair that returned `EXDEV`, or `u64::MAX`.
    static EXDEV_PAIR: AtomicU64 = AtomicU64::new(u64::MAX);
    /// The last device that refused `copy_file_range`, or `u64::MAX`.
    static NO_COPY_FILE_RANGE_DEVICE: AtomicU64 = AtomicU64::new(u64::MAX);

    #[inline]
    fn device_pair_tag(src_dev: u64, dst_dev: u64) -> u64 {
        let mixed = src_dev.rotate_left(17) ^ dst_dev.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        if mixed == u64::MAX { 0 } else { mixed }
    }

    #[cfg(test)]
    thread_local! {
        pub(crate) static REFLINK_CANDIDATES: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    pub fn copy_file(src: &Path, dst: &Path) -> Result<(), LpmError> {
        let failed = |action: &str, error: std::io::Error| {
            LpmError::Store(format!(
                "failed to {action} virtual-store source file {} → {}: {error}",
                src.display(),
                dst.display()
            ))
        };
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(src)
            .map_err(|error| failed("open", error))?;
        let source_metadata = source
            .metadata()
            .map_err(|error| failed("inspect", error))?;
        if !source_metadata.is_file() {
            return Err(failed(
                "copy",
                std::io::Error::other("the source is not a regular file"),
            ));
        }
        let mode = source_metadata.permissions().mode() & 0o7777;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)
            .map_err(|error| failed("create", error))?;
        let copied = fill(&mut source, &mut destination, &source_metadata).and_then(|()| {
            if mode == 0o600 {
                Ok(())
            } else {
                destination.set_permissions(std::fs::Permissions::from_mode(mode))
            }
        });
        copied.map_err(|error| {
            drop(destination);
            let _ = std::fs::remove_file(dst);
            failed("copy", error)
        })
    }

    fn fill(
        source: &mut File,
        destination: &mut File,
        source_metadata: &Metadata,
    ) -> std::io::Result<()> {
        let len = source_metadata.len();
        if len >= MIN_REFLINK_BYTES {
            let src_dev = source_metadata.dev();
            let dst_dev = destination.metadata()?.dev();
            let pair = device_pair_tag(src_dev, dst_dev);
            if EXDEV_PAIR.load(Ordering::Relaxed) != pair
                && (reflink(source, destination, src_dev, pair)?
                    || copy_file_range(source, destination, len, src_dev, pair)?)
            {
                return Ok(());
            }
        }
        copy_through_buffer(source, destination, len)
    }

    fn reflink(
        source: &File,
        destination: &File,
        device: u64,
        pair: u64,
    ) -> std::io::Result<bool> {
        #[cfg(test)]
        REFLINK_CANDIDATES.with(|candidates| candidates.set(candidates.get() + 1));
        if NO_REFLINK_DEVICE.load(Ordering::Relaxed) == device {
            return Ok(false);
        }
        const FICLONE: libc::Ioctl = 0x4004_9409;
        // SAFETY: both descriptors are live regular files, and FICLONE only
        // reads the source and fills the empty destination.
        if unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL | libc::ENOSYS) => {
                NO_REFLINK_DEVICE.store(device, Ordering::Relaxed);
                Ok(false)
            }
            Some(libc::EXDEV) => {
                EXDEV_PAIR.store(pair, Ordering::Relaxed);
                Ok(false)
            }
            _ => Err(error),
        }
    }

    fn copy_file_range(
        source: &File,
        destination: &File,
        len: u64,
        device: u64,
        pair: u64,
    ) -> std::io::Result<bool> {
        if NO_COPY_FILE_RANGE_DEVICE.load(Ordering::Relaxed) == device {
            return Ok(false);
        }
        let mut saw_exdev = false;
        let mut saw_unsupported = false;
        let copied = copy_in_kernel(len, |requested| {
            // SAFETY: both descriptors are live; null offsets use and advance
            // each file's own position.
            let written = unsafe {
                libc::copy_file_range(
                    source.as_raw_fd(),
                    std::ptr::null_mut(),
                    destination.as_raw_fd(),
                    std::ptr::null_mut(),
                    requested,
                    0,
                )
            };
            usize::try_from(written).map_err(|_| {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EXDEV) => saw_exdev = true,
                    Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => saw_unsupported = true,
                    _ => {}
                }
                err
            })
        })?;
        if !copied {
            if saw_exdev {
                EXDEV_PAIR.store(pair, Ordering::Relaxed);
            } else if saw_unsupported {
                NO_COPY_FILE_RANGE_DEVICE.store(device, Ordering::Relaxed);
            }
        }
        Ok(copied)
    }

    /// Runs `copy_chunk` until `len` bytes moved. `Ok(false)` when the file
    /// system refused before any byte moved, which some (overlayfs, FUSE and
    /// network mounts) signal by copying nothing, as `std::fs::copy` treats it.
    pub(crate) fn copy_in_kernel(
        len: u64,
        mut copy_chunk: impl FnMut(usize) -> std::io::Result<usize>,
    ) -> std::io::Result<bool> {
        let mut copied = 0u64;
        while copied < len {
            let requested = usize::try_from(len - copied)
                .unwrap_or(usize::MAX)
                .min(1 << 30);
            match copy_chunk(requested) {
                Ok(0) if copied == 0 => return Ok(false),
                Ok(0) => break,
                Ok(written) => copied += written as u64,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error)
                    if copied == 0
                        && matches!(
                            error.raw_os_error(),
                            Some(
                                libc::EXDEV
                                    | libc::ENOSYS
                                    | libc::EOPNOTSUPP
                                    | libc::EINVAL
                                    | libc::EPERM
                                    | libc::EBADF
                                    | libc::EOVERFLOW
                            )
                        ) =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        if copied != len {
            return Err(source_changed());
        }
        Ok(true)
    }

    fn copy_through_buffer(
        source: &mut File,
        destination: &mut File,
        len: u64,
    ) -> std::io::Result<()> {
        thread_local! {
            static BUFFER: std::cell::RefCell<Vec<u8>> =
                std::cell::RefCell::new(vec![0; COPY_BUFFER_BYTES + 1]);
        }
        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            // On regular files smaller than the buffer, a single `read(len + 1)`
            // returning `len` bytes proves EOF in one syscall instead of two.
            if let Ok(len_usize) = usize::try_from(len)
                && len_usize < COPY_BUFFER_BYTES
            {
                let mut copied = 0usize;
                loop {
                    let read = match source.read(&mut buffer[copied..=len_usize]) {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    };
                    copied += read;
                    if copied > len_usize {
                        return Err(source_changed());
                    }
                    if copied == len_usize && read == len_usize {
                        // A single short read into a `len + 1` slice already hit EOF.
                        break;
                    }
                }
                if copied != len_usize {
                    return Err(source_changed());
                }
                if copied > 0 {
                    destination.write_all(&buffer[..copied])?;
                }
                return Ok(());
            }

            let mut copied = 0u64;
            loop {
                let read = match source.read(&mut buffer[..COPY_BUFFER_BYTES]) {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                destination.write_all(&buffer[..read])?;
                copied += read as u64;
            }
            if copied != len {
                return Err(source_changed());
            }
            Ok(())
        })
    }

    fn source_changed() -> std::io::Error {
        std::io::Error::other("the source changed while it was copied")
    }

    #[cfg(test)]
    mod tests {
        use super::copy_in_kernel;

        fn os_error(code: i32) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(code))
        }

        #[test]
        fn a_first_copy_of_nothing_falls_back_to_reading_and_writing() {
            assert!(!copy_in_kernel(100, |_| Ok(0)).unwrap());
        }

        #[test]
        fn a_refusal_before_any_byte_moved_falls_back() {
            for code in [libc::EXDEV, libc::EBADF, libc::EOVERFLOW, libc::EOPNOTSUPP] {
                assert!(!copy_in_kernel(100, |_| os_error(code)).unwrap(), "{code}");
            }
        }

        #[test]
        fn a_copy_that_stops_after_progress_is_an_error() {
            let mut calls = [Ok(60), Ok(0)].into_iter();
            assert!(copy_in_kernel(100, |_| calls.next().unwrap()).is_err());
            let mut calls = [Ok(60), os_error(libc::EXDEV)].into_iter();
            assert!(copy_in_kernel(100, |_| calls.next().unwrap()).is_err());
        }

        #[test]
        fn an_interrupted_copy_is_retried() {
            let mut calls = [os_error(libc::EINTR), Ok(40), Ok(60)].into_iter();
            assert!(copy_in_kernel(100, |_| calls.next().unwrap()).unwrap());
        }

        #[test]
        fn small_file_copy_preserves_bytes_and_permissions_including_owner_only() {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let src_600 = dir.path().join("secret.txt");
            let dst_600 = dir.path().join("secret-copy.txt");
            std::fs::write(&src_600, b"hello small file").unwrap();
            std::fs::set_permissions(&src_600, std::fs::Permissions::from_mode(0o600)).unwrap();
            super::copy_file(&src_600, &dst_600).unwrap();
            assert_eq!(std::fs::read(&dst_600).unwrap(), b"hello small file");
            assert_eq!(
                std::fs::metadata(&dst_600).unwrap().permissions().mode() & 0o777,
                0o600
            );

            let src_755 = dir.path().join("bin.sh");
            let dst_755 = dir.path().join("bin-copy.sh");
            std::fs::write(&src_755, b"#!/bin/sh\necho ok\n").unwrap();
            std::fs::set_permissions(&src_755, std::fs::Permissions::from_mode(0o755)).unwrap();
            super::copy_file(&src_755, &dst_755).unwrap();
            assert_eq!(std::fs::read(&dst_755).unwrap(), b"#!/bin/sh\necho ok\n");
            assert_eq!(
                std::fs::metadata(&dst_755).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_materialized_object_sidecars(dst: &Path) -> Result<(), LpmError> {
    use super::integrity::{OBJECT_INTEGRITY_FILENAME, TREE_SNAPSHOT_FILENAME};
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    const SIDECARS: [&CStr; 4] = [
        c".integrity",
        c".lpm-security.json",
        c".lpm-object-integrity",
        c".lpm-tree-snapshot.json",
    ];
    debug_assert_eq!(SIDECARS[2].to_str(), Ok(OBJECT_INTEGRITY_FILENAME));
    debug_assert_eq!(SIDECARS[3].to_str(), Ok(TREE_SNAPSHOT_FILENAME));

    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(::libc::O_DIRECTORY | ::libc::O_CLOEXEC)
        .open(dst)
        .map_err(|e| {
            LpmError::Store(format!(
                "failed to open materialized package dir {} to clean metadata sidecars: {e}",
                dst.display()
            ))
        })?;
    let dirfd = dir.as_raw_fd();
    for name in SIDECARS {
        // SAFETY: `dirfd` is a valid open directory fd and `name` is a static NUL-terminated CStr.
        if unsafe { ::libc::unlinkat(dirfd, name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(LpmError::Store(format!(
                    "failed to remove virtual-store metadata sidecar from materialized package at {}: {error}",
                    dst.join(name.to_string_lossy().as_ref()).display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn try_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Ok(src_c) = CString::new(src.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(dst_c) = CString::new(dst.as_os_str().as_bytes()) else {
        return false;
    };

    let _span = tracing::trace_span!(target: "lpm_install_timeline", "clonefile").entered();

    // SAFETY: clonefile takes two NUL-terminated C strings and a flags
    // word. Both pointers are valid for the duration of the call (the
    // CStrings outlive it), and we pass `0` for flags (no special
    // behavior). Returns 0 on success, -1 on failure.
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    tracing::event!(name: "clone_result", target: "lpm_install_timeline", tracing::Level::TRACE, success = result == 0);
    if result == 0 {
        tracing::debug!(
            src = %src.display(),
            dst = %dst.display(),
            "virtual-store materialize: clonefile"
        );
        true
    } else {
        false
    }
}

#[cfg(target_os = "macos")]
mod libc {
    unsafe extern "C" {
        pub fn clonefile(
            src: *const std::os::raw::c_char,
            dst: *const std::os::raw::c_char,
            flags: u32,
        ) -> std::os::raw::c_int;
    }
}
