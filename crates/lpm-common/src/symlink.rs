//! Cross-platform directory-symlink helper.
//!
//! Provides shared creation, detection, and removal helpers for directory
//! links so callers do not need to duplicate platform-specific behavior:
//!
//! - **Unix:** plain `symlink(2)` via [`std::os::unix::fs::symlink`].
//! - **Windows:** tries [`std::os::windows::fs::symlink_dir`] first
//!   (works under Developer Mode or with appropriate policy). On
//!   failure, falls back to NTFS junctions via `cmd /c mklink /J`,
//!   which does not require admin privileges. Junction targets must
//!   be absolute, so relative targets are resolved against the link's
//!   parent and lexically cleaned (`..` segments simplified) before
//!   being handed to cmd. Path strings are validated against cmd.exe
//!   metacharacters to prevent command injection.
//!
//! Both lpm-linker (for the install-time wrapper layout) and
//! lpm-store v2 (for sibling-symlinks under `links/<graph-key>/`) use
//! this. Centralized so a future Windows correctness or security fix
//! lands in one place.

#[cfg(windows)]
use std::path::PathBuf;
use std::path::{Component, Path};

/// Create a directory link from `link` pointing to `target`.
///
/// On Unix, this is a relative-or-absolute `symlink(2)`. On Windows,
/// the call tries `CreateSymbolicLinkW` first and silently falls back
/// to `mklink /J` (NTFS junction) if the symlink fails — junctions
/// don't need admin privileges, so this is the practical Windows
/// path for end-user installs.
///
/// Returns the underlying I/O error if neither the symlink nor the
/// junction call succeeds. Callers should surface the error rather
/// than retrying — a hard failure here typically means a path
/// validation issue (invalid chars on Windows) or filesystem
/// permission, neither of which a retry resolves.
pub fn create_dir_symlink_or_junction(target: &Path, link: &Path) -> std::io::Result<()> {
    create_dir_symlink_or_junction_inner(target, link)
}

/// Create a filesystem symlink from `link` to `target`.
///
/// - **Unix:** plain `symlink(2)` for files and directories.
/// - **Windows:** `symlink_file` for files; directory targets reuse
///   [`create_dir_symlink_or_junction`] so the junction fallback still
///   applies.
pub fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    create_symlink_inner(target, link)
}

/// Return whether metadata obtained with [`std::fs::symlink_metadata`]
/// describes a symbolic link or Windows reparse-point junction.
pub fn is_symlink_or_junction(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Remove one filesystem entry without traversing a directory link.
///
/// Windows requires directory symlinks and junctions to be removed with
/// `remove_dir`, while Unix removes directory symlinks with `remove_file`.
/// Real directories are removed recursively and regular files use
/// `remove_file` on every platform.
pub fn remove_path_entry(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if is_symlink_or_junction(&metadata) {
        return remove_link(path, &metadata);
    }
    if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(unix)]
fn remove_link(path: &Path, _metadata: &std::fs::Metadata) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

#[cfg(windows)]
fn remove_link(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    if metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(unix)]
fn create_dir_symlink_or_junction_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(unix)]
fn create_symlink_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_dir_symlink_or_junction_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    let abs_target = absolute_windows_link_target(target, link)?;

    // Try symlink_dir first — works without admin on Windows setups
    // running with Developer Mode or with the SeCreateSymbolicLink
    // privilege granted via group policy.
    if std::os::windows::fs::symlink_dir(&abs_target, link).is_ok() {
        return Ok(());
    }

    // Validate path strings before handing them to cmd.exe.
    let link_str = link.to_string_lossy();
    let target_str = abs_target.to_string_lossy();
    if let Err(reason) = validate_cmd_path(&link_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: link path {reason}"),
        ));
    }
    if let Err(reason) = validate_cmd_path(&target_str) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing junction: target path {reason}"),
        ));
    }

    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J", &link_str, &target_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(std::io::Error::other(
            "failed to create junction or symlink",
        )),
    }
}

#[cfg(windows)]
fn absolute_windows_link_target(target: &Path, link: &Path) -> std::io::Result<PathBuf> {
    if target.is_absolute() {
        return Ok(lexically_clean(target));
    }

    let link_parent = link.parent().unwrap_or(Path::new("."));
    let absolute_parent = if link_parent.is_absolute() {
        link_parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(link_parent)
    };
    Ok(lexically_clean(&absolute_parent.join(target)))
}

#[cfg(windows)]
fn create_symlink_inner(target: &Path, link: &Path) -> std::io::Result<()> {
    match std::fs::metadata(target) {
        Ok(meta) if meta.is_dir() => create_dir_symlink_or_junction_inner(target, link),
        Ok(_) => std::os::windows::fs::symlink_file(target, link),
        Err(e) => Err(e),
    }
}

/// Lexically simplify `..` and `.` segments in a path without touching
/// the filesystem. Used by the Windows junction path so `mklink /J`
/// receives a canonical absolute target.
///
/// `a/b/../c` → `a/c`, `./a` → `a`, leading `..` segments are
/// preserved (we have no parent to pop into). Leading `RootDir` /
/// `Prefix` components are kept verbatim.
#[cfg(windows)]
fn lexically_clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::ParentDir => {
                let last_is_normal =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                if last_is_normal {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Reject path strings containing cmd.exe metacharacters. Used before
/// `cmd /c mklink /J` and before emitting a `.cmd` bin shim. Covers
/// the sub-expression triple `( ) ;` and the quote-bypass triple
/// `` ` ' \t`` so a crafted `package.json > name` can't reach cmd.exe's
/// parser through double-quoted argument shapes.
#[cfg(windows)]
pub fn validate_cmd_path(path: &str) -> Result<(), String> {
    const DANGEROUS: &[char] = &[
        '"', '&', '|', '<', '>', '^', '%', '\n', '\r', '(', ')', ';', '`', '\'', '\t',
    ];
    for ch in DANGEROUS {
        if path.contains(*ch) {
            return Err(format!(
                "path contains dangerous character '{ch}' for cmd.exe"
            ));
        }
    }
    Ok(())
}

// Suppress an "unused" warning on Unix — `Component` is referenced
// only by the Windows `lexically_clean` helper.
#[cfg(not(windows))]
const _: fn(Component<'_>) = |_| {};

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn validate_cmd_path_allows_normal_path() {
        assert!(validate_cmd_path("C:\\Users\\dev\\project").is_ok());
    }

    #[test]
    fn validate_cmd_path_rejects_ampersand() {
        let err = validate_cmd_path("C:\\evil & rm -rf").unwrap_err();
        assert!(err.contains('&'));
    }

    #[test]
    fn validate_cmd_path_rejects_paren_subshell() {
        let err = validate_cmd_path("C:\\evil(echo+pwned)\\node.exe").unwrap_err();
        assert!(err.contains('('));
    }

    #[test]
    fn validate_cmd_path_rejects_semicolon() {
        let err = validate_cmd_path("C:\\evil;malicious.bat").unwrap_err();
        assert!(err.contains(';'));
    }

    #[test]
    fn validate_cmd_path_rejects_backtick() {
        let err = validate_cmd_path("C:\\evil`echo`.exe").unwrap_err();
        assert!(err.contains('`'));
    }

    #[test]
    fn validate_cmd_path_rejects_single_quote() {
        let err = validate_cmd_path("C:\\evil'cmd'.exe").unwrap_err();
        assert!(err.contains('\''));
    }

    #[test]
    fn validate_cmd_path_rejects_tab() {
        let err = validate_cmd_path("C:\\evil\tmalicious").unwrap_err();
        assert!(err.contains('\t'));
    }

    #[test]
    fn lexically_clean_simplifies_double_dots() {
        let cleaned = lexically_clean(Path::new("a/b/../c"));
        assert_eq!(cleaned, PathBuf::from("a/c"));
    }

    #[test]
    fn directory_link_survives_parent_rename_and_removes_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();

        let staged = dir.path().join("staged");
        std::fs::create_dir(&staged).unwrap();
        let link = staged.join("link");
        create_dir_symlink_or_junction(Path::new("../target"), &link).unwrap();

        let published = dir.path().join("published");
        std::fs::rename(&staged, &published).unwrap();
        let published_link = published.join("link");
        assert_eq!(std::fs::read(published_link.join("marker")).unwrap(), b"ok");

        remove_path_entry(&published_link).unwrap();
        assert!(published_link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn create_dir_symlink_round_trips_unix() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        create_dir_symlink_or_junction(&target, &link).unwrap();
        let read = std::fs::read_link(&link).unwrap();
        assert_eq!(read, target);
    }

    #[test]
    fn create_symlink_round_trips_file_unix() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.js");
        std::fs::write(&target, b"console.log('ok')\n").unwrap();
        let link = dir.path().join("link.js");
        create_symlink(&target, &link).unwrap();
        let read = std::fs::read_link(&link).unwrap();
        assert_eq!(read, target);
    }

    #[test]
    fn remove_path_entry_unlinks_directory_symlink_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"ok").unwrap();
        let link = dir.path().join("link");
        create_dir_symlink_or_junction(&target, &link).unwrap();

        remove_path_entry(&link).unwrap();

        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"ok");
    }
}
