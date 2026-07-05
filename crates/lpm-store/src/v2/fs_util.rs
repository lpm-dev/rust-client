use std::path::{Path, PathBuf};

use lpm_common::LpmError;

use super::integrity::has_local_source_sentinel;
use super::tree_hash::is_object_metadata_sidecar;

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
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
                "v1→v2 copy: skipping symlink (refused — v1 store entries should not contain symlinks)",
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

pub(crate) fn materialize_into_inner(
    root: &Path,
    src: &Path,
    dst: &Path,
    allow_source_symlinks: bool,
) -> Result<(), LpmError> {
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            remove_materialized_object_sidecars(dst)?;
            return Ok(());
        }
    }

    std::fs::create_dir_all(dst).map_err(|e| {
        LpmError::Store(format!(
            "failed to create v2 link package dir at {}: {e}",
            dst.display()
        ))
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| {
        LpmError::Store(format!(
            "failed to read v2 source object dir {}: {e}",
            src.display()
        ))
    })? {
        let entry = entry
            .map_err(|e| LpmError::Store(format!("failed to enumerate v2 source dir: {e}")))?;
        let src_path = entry.path();
        if is_object_metadata_sidecar(root, &src_path) {
            continue;
        }
        let dst_path = dst.join(entry.file_name());

        let file_type = entry.file_type().map_err(|e| {
            LpmError::Store(format!(
                "failed to stat v2 source entry {}: {e}",
                src_path.display()
            ))
        })?;

        if file_type.is_dir() {
            materialize_into_inner(root, &src_path, &dst_path, allow_source_symlinks)?;
        } else if file_type.is_symlink() {
            if !allow_source_symlinks {
                // Refuse symlink entries — the extractor's `is_file()`
                // filter blocks them at extract time, so a symlink under
                // `objects/` means a same-UID actor planted it. Symmetric
                // with the v1→v2 `copy_dir_recursively` refusal.
                let target = std::fs::read_link(&src_path).unwrap_or_default();
                return Err(LpmError::Store(format!(
                    "refusing v2 symlink entry {} → {}; symlinks must not appear under objects/",
                    src_path.display(),
                    target.display(),
                )));
            }
            let target = std::fs::read_link(&src_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to read v2 local-source symlink {}: {e}",
                    src_path.display()
                ))
            })?;
            create_fs_symlink(&target, &dst_path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to recreate v2 local-source symlink {} → {}: {e}",
                    dst_path.display(),
                    target.display()
                ))
            })?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|copy_err| {
                LpmError::Store(format!(
                    "failed to copy v2 source file {} → {}: {copy_err}",
                    src_path.display(),
                    dst_path.display()
                ))
            })?;
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_materialized_object_sidecars(dst: &Path) -> Result<(), LpmError> {
    use super::integrity::OBJECT_INTEGRITY_FILENAME;

    for name in [
        ".integrity",
        ".lpm-security.json",
        OBJECT_INTEGRITY_FILENAME,
    ] {
        let path = dst.join(name);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove v2 metadata sidecar from materialized package at {}: {e}",
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
            "v2 materialize: clonefile"
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
