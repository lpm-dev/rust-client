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

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let tmp = path.with_file_name(format!("{DETACH_TMP_PREFIX}{file_name}-{}", metadata.ino()));
    if tmp.exists() {
        let _ = std::fs::remove_file(&tmp);
    }
    std::fs::copy(path, &tmp)?;
    std::fs::set_permissions(&tmp, metadata.permissions())?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            Err(error.into())
        }
    }
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
/// Break shared inodes inside a live per-package directory so
/// subsequent writes don't propagate into the global content-addressable
/// store at `~/.lpm/store/v1/`.
///
/// **Why this exists.** [`link_dir_recursive`] uses `std::fs::hard_link`
/// on Linux. A hard link makes the live file and the store file
/// share an inode, so a lifecycle script that mutates a file in
/// its own package directory mutates the store too. macOS uses
/// `clonefile()` (CoW), which makes writes independent at link
/// time, and Windows always copies, so the bug is Linux-specific.
///
/// **What it does.** Walks `dir` recursively. For every regular file
/// with `nlink > 1`, copies the content to a sibling temp file and
/// atomically renames it back over the original. After the rename
/// the live entry points at a fresh inode (nlink = 1) while the
/// store entry still points at the original inode (nlink decremented
/// by 1). Subsequent writes through the live path no longer reach
/// the store.
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
/// **Symlinks are preserved**, not detached. The isolated linker
/// uses symlinks under `<project>/node_modules/.lpm/<safe>@<ver>/node_modules/`
/// to expose a package's siblings — breaking those would corrupt the
/// dep graph. We use [`std::fs::symlink_metadata`] to inspect file
/// type without following links.
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
const DETACH_TMP_PREFIX: &str = ".lpm-detach-tmp-";

#[cfg(target_os = "linux")]
fn detach_hardlinks_recursive(dir: &Path) -> Result<usize, LpmError> {
    use std::os::unix::fs::MetadataExt;

    // Materialize the entry list before we start mutating the dir.
    // Doing so lets us (a) sweep leftover temp files from a prior
    // interrupted detach without invalidating the iterator, and
    // (b) keep ownership of OsString file names independent of the
    // open dir handle.
    let entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;

    let mut detached = 0usize;
    for entry in entries {
        let path = entry.path();
        let file_name_os = entry.file_name();
        let file_name = file_name_os.to_string_lossy();

        // Sweep leftover temp files from a previous run that crashed
        // between `fs::copy` and `fs::rename`. These have nlink == 1
        // (fresh-from-copy) so the detach loop below would skip them,
        // leaving them visible to Node's `readdir` calls inside the
        // package directory. Best-effort: a remove failure here is
        // not fatal — surface it but keep going. A successful sweep
        // is logged at debug so an operator chasing "where did file
        // X go" has a paper trail without polluting normal output.
        if file_name.starts_with(DETACH_TMP_PREFIX) {
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::debug!("swept stale detach temp file: {}", path.display()),
                Err(e) => tracing::warn!(
                    "could not remove stale detach temp file {}: {e}",
                    path.display()
                ),
            }
            continue;
        }

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

        // Build a temp filename that's reserved for our use
        // (`.lpm-detach-tmp-<ino>`) so it (a) won't collide with any
        // package file, (b) is per-inode unique inside the dir.
        let temp_name = format!("{DETACH_TMP_PREFIX}{}", metadata.ino());
        let temp_path = path.with_file_name(temp_name);

        // Copy → rename. `fs::copy` creates a new inode populated
        // with the source bytes (using `copy_file_range` on Linux),
        // and `fs::rename` is atomic when src + dst are on the same
        // filesystem (which they are, both under `dir`). After this
        // the original directory entry points at the new inode and
        // the store's entry still points at the old one.
        std::fs::copy(&path, &temp_path)?;
        std::fs::rename(&temp_path, &path)?;
        detached += 1;
    }
    Ok(detached)
}
