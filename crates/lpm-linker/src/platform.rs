use lpm_common::LpmError;
use std::path::Path;

#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
pub(crate) fn relative_symlink_target_from_parent(target: &Path, link_parent: &Path) -> PathBuf {
    let link_parent_canonical = link_parent
        .canonicalize()
        .unwrap_or_else(|_| link_parent.to_path_buf());
    pathdiff::diff_paths(target, &link_parent_canonical).unwrap_or_else(|| target.to_path_buf())
}

#[cfg(unix)]
pub(crate) fn make_bin_target_executable(target: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = std::fs::metadata(target) else {
        return Ok(());
    };
    let mode = meta.permissions().mode();
    if mode & 0o111 != 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    detach_single_hardlinked_file(target)?;
    #[cfg(all(unix, not(target_os = "linux")))]
    detach_single_hardlinked_file(target);
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode | 0o111))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn detach_single_hardlinked_file(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.nlink() <= 1 {
        return Ok(());
    }

    lpm_common::write_file_atomic_with(path, lpm_common::AtomicWriteOptions::new(), |destination| {
        let mut source = std::fs::File::open(path)?;
        std::io::copy(&mut source, destination)?;
        Ok(())
    })
    .map_err(LpmError::Io)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn detach_single_hardlinked_file(_path: &Path) {}

// Windows command-path validation is shared with lpm-store so both
// linkers enforce the same executable shim safety contract.
#[cfg(windows)]
pub(crate) use lpm_common::symlink::validate_cmd_path;

/// Create a symlink (Unix) or junction (Windows) from `link` pointing to `target`.
///
/// On Windows, NTFS junctions don't require admin privileges (unlike symlinks).
/// We use `cmd /c mklink /J` which handles junction creation natively.
/// Junctions require absolute paths, so we resolve relative targets before creating.
/// Falls back to `symlink_dir` if junction creation fails.
///
// Directory-link creation is shared with lpm-store so v1 and v2 keep
// the same Windows symlink-then-junction fallback behavior.
pub(crate) use lpm_common::symlink::{
    create_dir_symlink_or_junction as create_symlink_or_junction,
    create_symlink as create_fs_symlink,
};
/// Break shared inodes inside a live per-package directory so subsequent
/// writes cannot propagate to any other path referencing those inodes.
///
/// **Why this exists.** Current v2/v3 virtual-store materialization uses
/// independent writable inodes. The legacy v1 linker and synthetic or
/// externally-created layouts can still contain hardlinks, so lifecycle
/// execution keeps this Linux defense-in-depth boundary. macOS uses CoW
/// clones and Windows copies, so they do not need inode detachment.
///
/// **What it does.** Walks `dir` recursively. For every regular file
/// with `nlink > 1`, copies the content to a sibling temp file and
/// atomically renames it back over the original. After the rename
/// the live entry points at a fresh inode (nlink = 1) while the
/// other entries still point at the original inode (nlink decremented
/// by 1). Subsequent writes through the live path stay isolated.
///
/// **Why this is fast where it matters.** `std::fs::copy` on Linux
/// uses the `copy_file_range(2)` syscall, which the kernel implements
/// as a copy-on-write reflink on filesystems that support it
/// (Btrfs, XFS with `reflink=1`, F2FS, OverlayFS-on-Btrfs) and as a
/// kernel-side bulk copy elsewhere (ext4). So on CoW filesystems the
/// detach is essentially free; on ext4 it pays the IO cost of one
/// copy of each scripted package's tree, which is bounded by the
/// fact that only packages with lifecycle scripts hit this path
/// (~10% of dependencies in a typical install).
///
/// **Symlinks are preserved**, not detached. Linker layouts use them
/// for dependency edges, and replacing those paths would corrupt the
/// graph. We use [`std::fs::symlink_metadata`] to inspect file type
/// without following links.
///
/// **No-op on macOS / Windows.** macOS already gets CoW from
/// `clonefile()`; Windows already gets independent copies. The
/// function compiles to a constant-zero return on those platforms.
///
/// Returns the number of files detached (always 0 on non-Linux,
/// 0 on Linux when every file already had `nlink == 1`).
pub fn detach_package_hardlinks(dir: &Path) -> Result<usize, LpmError> {
    #[cfg(target_os = "linux")]
    {
        detach_hardlinks_recursive(dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        Ok(0)
    }
}

#[cfg(target_os = "linux")]
fn detach_hardlinks_recursive(dir: &Path) -> Result<usize, LpmError> {
    use std::os::unix::fs::MetadataExt;

    // Materialize the entry list before replacements add and remove
    // same-directory temporary entries.
    let entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;

    let mut detached = 0usize;
    for entry in entries {
        let path = entry.path();

        // `symlink_metadata` does NOT follow symlinks — required so
        // sibling-dep symlinks under `.lpm/<safe>@<ver>/node_modules/`
        // are left alone (their targets are other packages' live
        // dirs, which get detached by their own pre-script pass if
        // they themselves run scripts).
        let metadata = std::fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            detached += detach_hardlinks_recursive(&path)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if metadata.nlink() <= 1 {
            // Already independent (could be a copy from the
            // cross-device fallback in `link_dir_recursive`, or a
            // file we detached in a previous run). Idempotent skip.
            continue;
        }

        lpm_common::write_file_atomic_with(
            &path,
            lpm_common::AtomicWriteOptions::new(),
            |destination| -> std::io::Result<()> {
                let mut source = std::fs::File::open(&path)?;
                std::io::copy(&mut source, destination)?;
                Ok(())
            },
        )?;
        detached += 1;
    }
    Ok(detached)
}
