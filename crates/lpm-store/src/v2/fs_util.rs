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
    use rand::RngCore;
    let suffix: u64 = rand::thread_rng().next_u64();
    dir.with_extension(format!("tmp.{suffix:016x}"))
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
        Ok(())
    }
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

    let mut names = Vec::new();
    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read virtual-store source object dir {}: {e}",
            src.display()
        ))
    })? {
        names.push(
            entry
                .map_err(|e| {
                    LpmError::Store(format!("failed to enumerate virtual-store source dir: {e}"))
                })?
                .file_name(),
        );
    }
    names.sort_unstable();

    for name in names {
        let src_path = src.join(&name);
        if is_object_metadata_sidecar(root, &src_path) {
            continue;
        }
        let dst_path = dst.join(&name);

        let file_type = std::fs::symlink_metadata(&src_path)
            .map_err(|e| {
                LpmError::Store(format!(
                    "failed to stat virtual-store source entry {}: {e}",
                    src_path.display()
                ))
            })?
            .file_type();

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
    if try_linux_reflink(src, dst)? {
        return Ok(());
    }

    std::fs::copy(src, dst).map_err(|copy_err| {
        LpmError::Store(format!(
            "failed to copy virtual-store source file {} → {}: {copy_err}",
            src.display(),
            dst.display()
        ))
    })?;
    Ok(())
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
fn try_linux_reflink(src: &Path, dst: &Path) -> Result<bool, LpmError> {
    use std::collections::HashSet;
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::sync::{Mutex, OnceLock};

    static UNSUPPORTED_FILESYSTEMS: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    let src_metadata = std::fs::metadata(src).map_err(|error| {
        LpmError::Store(format!(
            "failed to inspect reflink source {}: {error}",
            src.display()
        ))
    })?;
    let device = src_metadata.dev();
    if UNSUPPORTED_FILESYSTEMS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&device)
    {
        return Ok(false);
    }

    let source = std::fs::File::open(src).map_err(|error| {
        LpmError::Store(format!(
            "failed to open reflink source {}: {error}",
            src.display()
        ))
    })?;
    let destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|error| {
            LpmError::Store(format!(
                "failed to create reflink destination {}: {error}",
                dst.display()
            ))
        })?;
    const FICLONE: libc::Ioctl = 0x4004_9409;
    // SAFETY: both descriptors are live regular files opened above, and
    // FICLONE only reads the source fd and initializes the empty destination.
    let result = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
    if result == 0 {
        std::fs::set_permissions(dst, src_metadata.permissions()).map_err(|error| {
            let _ = std::fs::remove_file(dst);
            LpmError::Store(format!(
                "failed to apply reflink destination mode at {}: {error}",
                dst.display()
            ))
        })?;
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    drop(destination);
    let _ = std::fs::remove_file(dst);
    match error.raw_os_error() {
        Some(libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL | libc::ENOSYS) => {
            UNSUPPORTED_FILESYSTEMS
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(device);
            Ok(false)
        }
        Some(libc::EXDEV) => Ok(false),
        _ => Err(LpmError::Store(format!(
            "failed to reflink {} → {}: {error}",
            src.display(),
            dst.display()
        ))),
    }
}

#[cfg(target_os = "macos")]
fn remove_materialized_object_sidecars(dst: &Path) -> Result<(), LpmError> {
    use super::integrity::{OBJECT_INTEGRITY_FILENAME, TREE_SNAPSHOT_FILENAME};

    for name in [
        ".integrity",
        ".lpm-security.json",
        OBJECT_INTEGRITY_FILENAME,
        TREE_SNAPSHOT_FILENAME,
    ] {
        let path = dst.join(name);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove virtual-store metadata sidecar from materialized package at {}: {e}",
                    path.display()
                ))
            })?;
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

    // SAFETY: clonefile takes two NUL-terminated C strings and a flags
    // word. Both pointers are valid for the duration of the call (the
    // CStrings outlive it), and we pass `0` for flags (no special
    // behavior). Returns 0 on success, -1 on failure.
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
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
