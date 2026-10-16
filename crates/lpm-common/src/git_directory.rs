//! Git directories as git recognizes them, read from the files git reads,
//! for where git can't be asked or running it would cost too much.

use std::path::{Path, PathBuf};

use crate::BoundedReadError;

/// The largest `.git` file git reads; it stops at a larger one.
const GITFILE_LIMIT: u64 = 1024 * 1024;

/// Whether a `.git` entry marks a repository as git 2.53 reads one: a
/// directory, or a link to one, that's a git directory ([`is_git_directory`]),
/// or a file, or a link to one, pointing at one as git reads it: `gitdir: `
/// and the rest of the file, but for the line breaks that end it, a path
/// from the file's directory. Git looks past a directory that isn't a git
/// directory, and any other entry, and stops at a file that doesn't point at
/// one, or is too large to be a pointer.
pub fn marks_a_repository(git: &Path) -> bool {
    git_directory_of(git).is_some()
}

/// The git directory a `.git` entry marks, as [`marks_a_repository`] reads
/// it: the entry itself, or the directory its pointer names.
pub fn git_directory_of(git: &Path) -> Option<PathBuf> {
    match std::fs::metadata(git) {
        Ok(metadata) if metadata.is_dir() => is_git_directory(git).then(|| git.to_path_buf()),
        Ok(metadata) if metadata.is_file() => {
            let (contents, _) =
                crate::read_regular_file_capped_with_metadata(git, GITFILE_LIMIT).ok()?;
            let pointer = contents
                .strip_prefix(b"gitdir: ")
                .map(trim_line_breaks)
                .map(until_nul)
                .filter(|path| !path.is_empty())?;
            let directory = git
                .parent()
                .unwrap_or(Path::new("."))
                .join(path_from_bytes(pointer));
            is_git_directory(&directory).then_some(directory)
        }
        _ => None,
    }
}

/// The git directories of the repository `directory` is in, as git finds
/// it from there: the one the nearest `.git` that marks a repository gives,
/// and the common directory a worktree's names. Empty outside a repository.
pub fn repository_git_directories(directory: &Path) -> Vec<PathBuf> {
    let Some(git_directory) = directory
        .ancestors()
        .find_map(|ancestor| git_directory_of(&ancestor.join(".git")))
    else {
        return Vec::new();
    };
    let common = common_directory(&git_directory);
    let mut directories = vec![git_directory];
    if let Some(common) = common
        && !directories.contains(&common)
    {
        directories.push(common);
    }
    directories
}

/// Whether `directory` is a git directory as git's `is_git_directory`
/// reads one: its `HEAD` names a branch or a commit ([`names_a_head`]), and
/// its common directory, which a worktree's `commondir` file names, has
/// `objects` and `refs` it can search.
pub fn is_git_directory(directory: &Path) -> bool {
    common_directory(directory).is_some()
}

/// The common directory of `directory` where that is a git directory
/// ([`is_git_directory`]): `directory` itself, or the one its `commondir`
/// file names.
pub fn common_directory(directory: &Path) -> Option<PathBuf> {
    if !names_a_head(&directory.join("HEAD")) {
        return None;
    }
    // Git fails on a `commondir` file it can't read, an empty one, or one
    // naming a path that doesn't resolve.
    let common = match crate::read_regular_file_capped_with_metadata(
        &directory.join("commondir"),
        GITFILE_LIMIT,
    ) {
        Ok((contents, _)) => {
            let path = until_nul(trim_line_breaks(&contents));
            if path.is_empty() {
                return None;
            }
            std::fs::canonicalize(directory.join(path_from_bytes(path))).ok()?
        }
        Err(BoundedReadError::NotFound { .. }) => directory.to_path_buf(),
        Err(_) => return None,
    };
    (searchable(&common.join("objects")) && searchable(&common.join("refs"))).then_some(common)
}

/// A path from the bytes git writes or reads; on Windows, where git writes
/// paths as UTF-8, only UTF-8 reads as one.
pub fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// `bytes` up to a NUL, where git, reading them as a C string, stops.
fn until_nul(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// `bytes` without the line breaks, CR or LF, that end it.
fn trim_line_breaks(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b'\n' | b'\r'))
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// Whether a `HEAD` file names a branch or a commit as git's
/// `validate_headref` reads one: a link into `refs/`, or a file starting
/// with `ref:` and a name in `refs/` after any spaces, or with an object ID
/// in hex, of which git reads the first 255 bytes.
fn names_a_head(head: &Path) -> bool {
    match std::fs::symlink_metadata(head) {
        Ok(metadata) if metadata.file_type().is_symlink() => std::fs::read_link(head)
            .is_ok_and(|target| target.as_os_str().as_encoded_bytes().starts_with(b"refs/")),
        Ok(_) => {
            let Some(contents) = first_bytes(head, 255) else {
                return false;
            };
            contents.strip_prefix(b"ref:").is_some_and(|name| {
                // Git's own isspace: a space, tab, LF or CR, not a vertical
                // tab or form feed.
                let start = name
                    .iter()
                    .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
                    .unwrap_or(name.len());
                name[start..].starts_with(b"refs/")
            }) || contents
                .get(..40)
                .is_some_and(|id| id.iter().all(u8::is_ascii_hexdigit))
        }
        Err(_) => false,
    }
}

/// Up to `limit` bytes from the start of a regular file, opened without
/// blocking on a special file.
fn first_bytes(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut contents = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, limit), &mut contents).ok()?;
    Some(contents)
}

/// Whether git can search `path`, as its `access(X_OK)` checks.
fn searchable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        std::ffi::CString::new(path.as_os_str().as_bytes())
            // SAFETY: `path` is NUL-terminated.
            .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0)
    }
    #[cfg(not(unix))]
    {
        path.is_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Makes `directory/.git` a git directory as `git init` leaves one:
    /// `HEAD`, `objects` and `refs`.
    fn repository_entry(directory: &Path) {
        for name in ["objects", "refs/heads"] {
            std::fs::create_dir_all(directory.join(".git").join(name)).unwrap();
        }
        std::fs::write(directory.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    /// Makes `directory/.git` a directory holding only `HEAD`, which git
    /// looks past.
    fn head_only_entry(directory: &Path) {
        std::fs::create_dir_all(directory.join(".git")).unwrap();
        std::fs::write(directory.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn a_repository_s_git_directories_are_found_from_any_directory_in_it() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repository");
        std::fs::create_dir_all(root.join("packages/app")).unwrap();
        assert!(repository_git_directories(&root.join("packages/app")).is_empty());
        head_only_entry(&root.join("packages"));
        repository_entry(&root);
        assert_eq!(
            repository_git_directories(&root.join("packages/app")),
            [root.join(".git")]
        );

        let worktree_git = root.join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        let checkout = directory.path().join("feature");
        std::fs::create_dir_all(checkout.join("src")).unwrap();
        std::fs::write(
            checkout.join(".git"),
            "gitdir: ../repository/.git/worktrees/feature\n",
        )
        .unwrap();
        assert_eq!(
            repository_git_directories(&checkout.join("src")),
            [
                checkout.join("../repository/.git/worktrees/feature"),
                std::fs::canonicalize(root.join(".git")).unwrap()
            ]
        );
    }

    #[test]
    fn takes_a_git_entry_for_a_repository_s_only_as_git_would() {
        let directory = tempfile::tempdir().unwrap();
        let git = directory.path().join(".git");

        repository_entry(&directory.path().join("elsewhere"));
        let absolute = format!(
            "gitdir: {}\n",
            directory.path().join("elsewhere/.git").display()
        );
        for (contents, repository) in [
            ("", false),
            ("not a pointer\n", false),
            ("gitdir:elsewhere/.git\n", false),
            ("gitdir: \n", false),
            ("gitdir: gone/.git\n", false),
            ("gitdir: elsewhere/.git\n", true),
            ("gitdir: elsewhere/.git\r\n", true),
            ("gitdir: elsewhere/.git\n\n\r\n", true),
            (absolute.as_str(), true),
            // Git reads the whole file as the path: a second line, or a
            // space at its end, is part of it.
            ("gitdir: elsewhere/.git\nsecond line\n", false),
            ("gitdir: elsewhere/.git \n", false),
            // A directory without `HEAD`, `objects` and `refs` isn't one.
            ("gitdir: elsewhere\n", false),
        ] {
            std::fs::write(&git, contents).unwrap();
            assert_eq!(marks_a_repository(&git), repository, "{contents:?}");
        }
        // Git reads a pointer of up to 1 MiB, and stops at a larger file.
        let mut padded = b"gitdir: elsewhere/.git".to_vec();
        padded.resize(1024 * 1024, b'\n');
        std::fs::write(&git, &padded).unwrap();
        assert!(marks_a_repository(&git));
        padded.push(b'\n');
        std::fs::write(&git, &padded).unwrap();
        assert!(!marks_a_repository(&git));
        std::fs::remove_file(&git).unwrap();

        std::fs::create_dir(&git).unwrap();
        assert!(!marks_a_repository(&git));
        head_only_entry(directory.path());
        assert!(!marks_a_repository(&git));
        repository_entry(directory.path());
        assert!(marks_a_repository(&git));

        #[cfg(unix)]
        {
            let linked = directory.path().join("linked");
            std::fs::create_dir(&linked).unwrap();
            std::os::unix::fs::symlink(&git, linked.join(".git")).unwrap();
            assert!(marks_a_repository(&linked.join(".git")));
            // Git follows a link to a `.git` file too.
            let pointer = directory.path().join("pointer");
            std::fs::write(&pointer, "gitdir: elsewhere/.git\n").unwrap();
            let linked_file = directory.path().join("linked-file");
            std::fs::create_dir(&linked_file).unwrap();
            std::os::unix::fs::symlink(&pointer, linked_file.join(".git")).unwrap();
            assert!(!marks_a_repository(&linked_file.join(".git")));
            std::os::unix::fs::symlink(
                directory.path().join("elsewhere"),
                linked_file.join("elsewhere"),
            )
            .unwrap();
            assert!(marks_a_repository(&linked_file.join(".git")));
        }
        assert!(!marks_a_repository(&directory.path().join("gone/.git")));

        // Git reads a pointer as a C string, so it ends at a NUL.
        let nul_dir = tempfile::tempdir().unwrap();
        repository_entry(&nul_dir.path().join("elsewhere"));
        std::fs::write(
            nul_dir.path().join(".git"),
            b"gitdir: elsewhere/.git\0junk\n",
        )
        .unwrap();
        assert!(marks_a_repository(&nul_dir.path().join(".git")));

        // A pointer with no path is none, even in a git directory, which the
        // empty path would otherwise name.
        let bare = tempfile::tempdir().unwrap();
        for name in ["objects", "refs"] {
            std::fs::create_dir(bare.path().join(name)).unwrap();
        }
        std::fs::write(bare.path().join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(bare.path().join(".git"), "gitdir: \n").unwrap();
        assert!(!marks_a_repository(&bare.path().join(".git")));
    }

    #[test]
    fn takes_a_git_directory_only_as_git_s_is_git_directory_would() {
        let directory = tempfile::tempdir().unwrap();
        let git = directory.path().join(".git");
        repository_entry(directory.path());
        let head = git.join("HEAD");
        // Git reads the first 255 bytes of it.
        let within = format!("ref:{}refs/heads/main\n", " ".repeat(240));
        let past = format!("ref:{}refs/heads/main\n", " ".repeat(260));
        for (contents, repository) in [
            ("ref: refs/heads/main\n", true),
            ("ref:refs/heads/main", true),
            ("ref: \t\r\n refs/heads/main\n", true),
            ("ref: \x0b refs/heads/main\n", false),
            ("ref: \x0c refs/heads/main\n", false),
            ("ref: heads/main\n", false),
            (within.as_str(), true),
            (past.as_str(), false),
            ("refs/heads/main\n", false),
            ("0123456789abcdef0123456789ABCDEF01234567\n", true),
            ("0123456789abcdef0123456789abcdef01234567", true),
            ("0123456789abcdef0123456789abcdef0123456\n", false),
            ("0123456789abcdef0123456789abcdef0123456g\n", false),
            ("", false),
        ] {
            std::fs::write(&head, contents).unwrap();
            assert_eq!(marks_a_repository(&git), repository, "{contents:?}");
        }
        std::fs::write(&head, "ref: refs/heads/main\n").unwrap();

        for missing in ["objects", "refs"] {
            let aside = directory.path().join("aside");
            std::fs::rename(git.join(missing), &aside).unwrap();
            assert!(!marks_a_repository(&git), "{missing}");
            std::fs::rename(&aside, git.join(missing)).unwrap();
        }
        assert!(marks_a_repository(&git));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::remove_file(&head).unwrap();
            std::os::unix::fs::symlink("refs/heads/main", &head).unwrap();
            assert!(marks_a_repository(&git));
            std::fs::remove_file(&head).unwrap();
            std::os::unix::fs::symlink("../elsewhere", &head).unwrap();
            assert!(!marks_a_repository(&git));
            std::fs::remove_file(&head).unwrap();
            std::fs::write(&head, "ref: refs/heads/main\n").unwrap();

            // Git checks it can search them, unless run as root.
            if crate::current_uid() != 0 {
                let objects = git.join("objects");
                std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o600)).unwrap();
                assert!(!marks_a_repository(&git));
                std::fs::set_permissions(&objects, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    #[test]
    fn takes_a_worktree_s_git_directory_by_its_common_directory() {
        let directory = tempfile::tempdir().unwrap();
        repository_entry(directory.path());
        let worktree_git = directory.path().join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        let checkout = directory.path().join("feature");
        std::fs::create_dir(&checkout).unwrap();
        std::fs::write(
            checkout.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();

        // Without `commondir`, the worktree's own directory has no
        // `objects` or `refs`.
        assert!(!marks_a_repository(&checkout.join(".git")));
        for (common, repository) in [
            ("../..\n", true),
            ("../..\r\n", true),
            ("../../objects\n", false),
            ("../gone\n", false),
            // Git fails on an empty one.
            ("\n", false),
            ("", false),
        ] {
            std::fs::write(worktree_git.join("commondir"), common).unwrap();
            assert_eq!(
                marks_a_repository(&checkout.join(".git")),
                repository,
                "{common:?}"
            );
        }
        std::fs::write(
            worktree_git.join("commondir"),
            format!("{}\n", directory.path().join(".git").display()),
        )
        .unwrap();
        assert!(marks_a_repository(&checkout.join(".git")));
    }
}
