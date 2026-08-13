use crate::platform::create_fs_symlink;
use lpm_common::LpmError;
use std::path::Path;

/// Materialize a `Source::Directory`
/// (file: directory dep) into the consumer's `.lpm/<wrapper>/...`
/// tree via per-file symlinks pointing at the source realpath.
///
/// Walks `src` recursively; mirrors directory structure as real
/// dirs in `dst`; for every regular file (or non-recursive symlink),
/// creates an absolute symlink at the corresponding path inside
/// `dst` pointing at the source file. The source dir is
/// canonicalized first so the realpath is stable even if `src` is
/// a symlink chain.
///
/// **Why per-file symlinks (not a single dir-symlink at
/// `node_modules/<name>`):** a directory symlink would make the
/// wrapped package's *realpath* `src`, which lives outside the
/// consumer's `node_modules/` tree. Node's module-resolution
/// algorithm walks ancestors from the realpath, so transitive
/// `require('lodash')` from inside the wrapped package would NOT
/// find the consumer's `node_modules/lodash/`. Per-file symlinks
/// keep the realpath inside the wrapper, where ancestor walks
/// still land in the consumer's `node_modules/`.
///
/// **Excludes** `node_modules/` and `.git/` at *any* depth.
/// Source-tree `node_modules/` would let untracked host state
/// silently change install output. `.git/` is huge and meaningless to
/// expose. Other dotfiles/dotdirs are NOT excluded — they may
/// carry intentional package metadata (`.npmrc`, `.npmignore`,
/// dotted bin shims).
///
/// **Symlinks are absolute.** Both absolute and relative are equally
/// fragile under moves: identity includes the source path, so any move is
/// already a re-resolve event. Absolute is the simpler default.
///
/// Returns the count of symlinks created (used by the caller's
/// `OnePackageResult::symlinks_created` stat).
pub(crate) fn materialize_directory_source(src: &Path, dst: &Path) -> Result<u64, LpmError> {
    let src = src.canonicalize().map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to canonicalize directory source {}: {e}",
                src.display()
            ),
        ))
    })?;
    let mut count = 0u64;
    walk_directory_source(&src, &src, dst, &mut count, 0)?;
    Ok(count)
}

/// Maximum directory-source walk depth.
///
/// Directory sources can contain symlink cycles or pathological nesting.
/// The linker walks one source tree structurally, so a bounded depth
/// prevents stack exhaustion without affecting normal JavaScript package
/// trees.
pub(crate) const MAX_DIRECTORY_SOURCE_DEPTH: usize = 256;

fn walk_directory_source(
    source_root: &Path,
    src: &Path,
    dst: &Path,
    count: &mut u64,
    depth: usize,
) -> Result<(), LpmError> {
    if depth > MAX_DIRECTORY_SOURCE_DEPTH {
        return Err(LpmError::Io(std::io::Error::other(format!(
            "directory source exceeds maximum walk depth ({MAX_DIRECTORY_SOURCE_DEPTH}) at {}",
            src.display()
        ))));
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        // Recursively exclude node_modules + .git from any depth.
        if name == "node_modules" || name == ".git" {
            continue;
        }
        let entry_src = entry.path();
        let entry_dst = dst.join(&name);
        let metadata = std::fs::symlink_metadata(&entry_src)?;
        let ft = metadata.file_type();
        if ft.is_dir() {
            walk_directory_source(source_root, &entry_src, &entry_dst, count, depth + 1)?;
        } else if ft.is_file() || ft.is_symlink() {
            // For symlinks, dereference once via canonicalize so the
            // wrapper exposes the file's real content rather than a
            // chain. canonicalize on a missing/broken symlink errors;
            // fall back to the entry's lexical path so a broken link
            // in the source doesn't fail the whole materialize (the
            // wrapper will then point at the same broken target,
            // matching what Node would see in the source).
            let abs_target = entry_src
                .canonicalize()
                .unwrap_or_else(|_| entry_src.clone());
            // When a symlink in the source tree resolves outside the source's
            // own realpath (e.g., `a/b → ../../etc`), the wrapper
            // exposes content the consumer probably didn't intend to
            // import. Node never re-follows wrapper symlinks during
            // module resolution (the wrapper is the realpath as far as
            // require() is concerned), so the escape is inert at
            // runtime — but it's worth surfacing so a packager can see
            // they're shipping a path that won't survive a tarball
            // round-trip. `tracing::warn!` lands in `lpm install -v`
            // output; default-level installs see nothing, matching the
            // "passes through what Node would see" contract.
            if ft.is_symlink() && !abs_target.starts_with(source_root) {
                tracing::warn!(
                    source = %source_root.display(),
                    symlink = %entry_src.display(),
                    target = %abs_target.display(),
                    "symlink escapes directory source root; \
                     exposing target as-is (matches Node resolution from the source itself)",
                );
            }
            create_fs_symlink(&abs_target, &entry_dst)?;
            *count += 1;
        }
        // Other file types (devices, sockets, fifos) silently
        // skipped — they have no business in a JS package.
    }
    Ok(())
}

/// Recursively link a directory from the global store into node_modules.
///
/// Strategy priority:
/// 1. macOS APFS: `clonefile()` (copy-on-write, instant, zero disk cost until modified)
/// 2. Hardlink (same filesystem, zero disk cost, shared inode)
/// 3. Copy (fallback for cross-device or permissions)
pub(crate) fn link_dir_recursive(src: &Path, dst: &Path) -> Result<(), LpmError> {
    materialize_dir_recursive(src, dst, true)
}

/// Recursively copy a directory without sharing writable file inodes.
pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), LpmError> {
    materialize_dir_recursive(src, dst, false)
}

fn materialize_dir_recursive(
    src: &Path,
    dst: &Path,
    allow_hardlinks: bool,
) -> Result<(), LpmError> {
    // On macOS, try clonefile first (copies entire directory tree as CoW in one syscall)
    #[cfg(target_os = "macos")]
    {
        if try_clonefile(src, dst) {
            return Ok(());
        }
    }

    // Fallback: file-by-file hardlink/copy
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            materialize_dir_recursive(&src_path, &dst_path, allow_hardlinks)?;
        } else if file_type.is_symlink() {
            return Err(LpmError::Store(format!(
                "refusing to follow symlink while linking package store entry: {}",
                src_path.display()
            )));
        } else if file_type.is_file() {
            if !allow_hardlinks {
                std::fs::copy(&src_path, &dst_path)?;
            } else if let Err(e) = std::fs::hard_link(&src_path, &dst_path) {
                // Hardlink refusals fall into a few classes: cross-volume
                // mounts, permissions, and Windows junctions inside the CAS
                // store. Copy fallback is correct but can become a visible
                // disk-cost cliff, so keep it observable under verbose logs.
                tracing::trace!(
                    src = %src_path.display(),
                    dst = %dst_path.display(),
                    error = %e,
                    "link_dir_recursive: hardlink failed, falling back to copy",
                );
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }

    Ok(())
}

/// Try to use macOS `clonefile()` syscall for instant copy-on-write.
/// Returns true if successful, false if not (caller should fall back).
///
/// `clonefile` on a directory recurses the whole subtree (files, dirs, and
/// symlinks) in a single syscall, so callers cloning a pre-built tree get a
/// CoW copy at the cost of one syscall regardless of entry count. Requires
/// `dst` to not already exist and `src`/`dst` to share a volume.
#[cfg(target_os = "macos")]
pub(crate) fn try_clonefile(src: &Path, dst: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = match CString::new(src.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let dst_c = match CString::new(dst.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // SAFETY: clonefile takes two NUL-terminated C strings and a flags
    // word. Both pointers are valid for the duration of the call (the
    // CStrings outlive it), and we pass `0` for flags (no special
    // behavior). Returns 0 on success, -1 on failure.
    let result = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };

    if result == 0 {
        tracing::debug!("clonefile: {} → {}", src.display(), dst.display());
        true
    } else {
        false
    }
}

// Declare the libc clonefile function for macOS
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
