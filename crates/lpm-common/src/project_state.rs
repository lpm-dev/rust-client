//! The project's `.lpm` directory, which holds LPM's machine-local state.
//!
//! Nothing in it belongs in git: installs rebuild what they need, and the
//! rest (certificates, tunnel captures, recovery journals, sync checkpoints)
//! belongs to one machine. The directory ignores itself through its own
//! `.gitignore`, as tool caches such as `.pytest_cache` do, so it stays out
//! of git wherever the project sits in a repository and the project's own
//! `.gitignore` is never edited. Files a team commits live outside it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The project state directory's name.
pub const PROJECT_STATE_DIR: &str = ".lpm";

/// The ignore file the state directory keeps.
pub const PROJECT_STATE_IGNORE_FILE: &str = ".gitignore";

/// What [`PROJECT_STATE_IGNORE_FILE`] holds.
pub const PROJECT_STATE_IGNORE: &str =
    "# LPM's machine-local state. Nothing here belongs in git.\n*\n";

/// The project state directory for `project_dir`, without touching disk.
pub fn project_state_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(PROJECT_STATE_DIR)
}

/// Opens `<project_dir>/.lpm`, creating it owner-only when missing, and
/// keeps it out of git. A link at `.lpm` is refused. Failing to write the
/// ignore file is logged, not returned: it never blocks the command that
/// needs the state.
pub fn ensure_project_state_dir(project_dir: &Path) -> std::io::Result<PathBuf> {
    let root = cap_std::fs::Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to open project {}: {error}", project_dir.display()),
            )
        })?;
    ensure_project_state_dir_in(&root, project_dir)?;
    Ok(project_state_dir(project_dir))
}

/// [`ensure_project_state_dir`] relative to an already-open project root.
/// `project_display` names the root in errors.
pub fn ensure_project_state_dir_in(
    project_root: &cap_std::fs::Dir,
    project_display: &Path,
) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt as _;

    let state_display = project_state_dir(project_display);
    let refuse = |error: std::io::Error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "refusing LPM state directory that is not a real directory at {}: {error}",
                state_display.display()
            ),
        )
    };
    let directory = match project_root.open_dir_nofollow(PROJECT_STATE_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_state_dir(project_root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to create LPM state directory {}: {error}",
                            state_display.display()
                        ),
                    ));
                }
            }
            project_root
                .open_dir_nofollow(PROJECT_STATE_DIR)
                .map_err(refuse)?
        }
        Err(error) => return Err(refuse(error)),
    };
    let metadata = directory.dir_metadata().map_err(refuse)?;
    if !metadata.is_dir() || crate::paths::capability_metadata_is_link_or_reparse(&metadata) {
        return Err(refuse(std::io::Error::other("a link or not a directory")));
    }
    keep_state_dir_ignored_or_warn(&directory, &state_display);
    Ok(directory)
}

/// [`keep_state_dir_ignored`] for a state directory a caller opened itself,
/// logging what it can't do. `state_display` names the directory in the log.
pub fn keep_state_dir_ignored_or_warn(directory: &cap_std::fs::Dir, state_display: &Path) {
    if let Err(error) = keep_state_dir_ignored(directory) {
        tracing::warn!(
            "could not keep {} out of git: {error}",
            state_display.display()
        );
    }
}

/// Keeps an existing `<project_dir>/.lpm` out of git; does nothing when the
/// project has none. Commands run this when they finish, so state written
/// by any path ends up ignored.
pub fn keep_existing_project_state_ignored(project_dir: &Path) {
    use cap_fs_ext::DirExt as _;

    let Ok(root) = cap_std::fs::Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())
    else {
        return;
    };
    let Ok(directory) = root.open_dir_nofollow(PROJECT_STATE_DIR) else {
        return;
    };
    keep_state_dir_ignored_or_warn(&directory, &project_state_dir(project_dir));
}

/// Makes the open state directory's `.gitignore` ignore everything in it,
/// rewriting one that doesn't. One that is a link or not a regular file, or
/// that its owner keeps from being written (read-only, or on Unix another
/// user's), is left as it is and reported.
pub fn keep_state_dir_ignored(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    let name = OsStr::new(PROJECT_STATE_IGNORE_FILE);
    match read_ignore_file(directory, name)? {
        Some((existing, _)) if ignores_everything(&existing) => return Ok(()),
        Some((_, metadata)) => refuse_kept_from_writing(&metadata)?,
        None => {}
    }
    crate::write_file_atomic_in_dir_with_options(
        directory,
        name,
        crate::AtomicWriteOptions::new().unix_mode(0o644),
        |file| std::io::Write::write_all(file, PROJECT_STATE_IGNORE.as_bytes()),
    )
}

fn create_state_dir(project_root: &cap_std::fs::Dir) -> std::io::Result<()> {
    #[cfg(unix)]
    let builder = {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = cap_std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = cap_std::fs::DirBuilder::new();
    project_root.create_dir_with(PROJECT_STATE_DIR, &builder)
}

fn read_ignore_file(
    directory: &cap_std::fs::Dir,
    name: &OsStr,
) -> std::io::Result<Option<(Vec<u8>, cap_std::fs::Metadata)>> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!("{PROJECT_STATE_IGNORE_FILE} is a link or can't be opened: {error}"),
            ));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || crate::paths::capability_metadata_is_link_or_reparse(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{PROJECT_STATE_IGNORE_FILE} is a link or not a regular file"),
        ));
    }
    let bytes = crate::read_stream_capped(file.into_std(), crate::CONFIG_FILE_SIZE_CAP_BYTES)?;
    Ok(Some((bytes, metadata)))
}

fn refuse_kept_from_writing(metadata: &cap_std::fs::Metadata) -> std::io::Result<()> {
    #[cfg(unix)]
    let read_only = {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != crate::current_uid() && crate::current_uid() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{PROJECT_STATE_IGNORE_FILE} belongs to another user"),
            ));
        }
        metadata.permissions().mode() & 0o200 == 0
    };
    #[cfg(not(unix))]
    let read_only = metadata.permissions().readonly();
    if read_only {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{PROJECT_STATE_IGNORE_FILE} is read-only"),
        ));
    }
    Ok(())
}

/// Whether these `.gitignore` lines, read as git reads them, ignore every
/// entry: a `*` or `**` rule with no negation after it.
pub fn ignores_everything(lines: &[u8]) -> bool {
    let mut ignored = false;
    for line in lines.split(|byte| *byte == b'\n') {
        let pattern = git_pattern(line);
        if pattern.is_empty() || pattern.starts_with(b"#") {
            continue;
        }
        if pattern.starts_with(b"!") {
            ignored = false;
            continue;
        }
        let unanchored = pattern.strip_prefix(b"/").unwrap_or(pattern);
        if unanchored == b"*" || unanchored == b"**" {
            ignored = true;
        }
    }
    ignored
}

/// A `.gitignore` line as git reads it: without one trailing carriage
/// return or trailing spaces that aren't escaped. Leading whitespace stays
/// part of the pattern, as it does for git.
pub fn git_pattern(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut end = line.len();
    while end > 0 && line[end - 1] == b' ' && !(end >= 2 && line[end - 2] == b'\\') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_the_state_directory_with_an_ignore_file_that_ignores_everything() {
        let project = tempfile::tempdir().unwrap();

        let state = ensure_project_state_dir(project.path()).unwrap();

        assert_eq!(state, project.path().join(".lpm"));
        let ignore = std::fs::read_to_string(state.join(".gitignore")).unwrap();
        assert_eq!(ignore, PROJECT_STATE_IGNORE);
        assert!(ignores_everything(ignore.as_bytes()));
    }

    #[cfg(unix)]
    #[test]
    fn a_created_state_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let project = tempfile::tempdir().unwrap();

        let state = ensure_project_state_dir(project.path()).unwrap();

        let mode = std::fs::metadata(state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn rewrites_an_ignore_file_that_leaves_entries_tracked() {
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(
            state.join(".gitignore"),
            "# LPM tunnel captures hold request headers and bodies.\ninspector.db*\n",
        )
        .unwrap();

        ensure_project_state_dir(project.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(state.join(".gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );
    }

    #[test]
    fn keeps_an_ignore_file_that_already_ignores_everything() {
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join(".gitignore"), "/**\r\n").unwrap();

        ensure_project_state_dir(project.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(state.join(".gitignore")).unwrap(),
            "/**\r\n"
        );
    }

    #[test]
    fn a_negation_after_the_wildcard_leaves_entries_tracked() {
        assert!(!ignores_everything(b"*\n!changes/\n"));
        assert!(ignores_everything(b"!changes/\n*\n"));
        assert!(!ignores_everything(b"# *\n"));
        assert!(!ignores_everything(b"inspector.db*\n"));
        assert!(ignores_everything(b"*   \n"));
    }

    #[test]
    fn the_sweep_leaves_projects_without_state_alone() {
        let project = tempfile::tempdir().unwrap();

        keep_existing_project_state_ignored(project.path());

        assert!(!project.path().join(".lpm").exists());
    }

    #[test]
    fn the_sweep_adds_the_ignore_file_to_existing_state() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();

        keep_existing_project_state_ignored(project.path());

        assert_eq!(
            std::fs::read_to_string(project.path().join(".lpm/.gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_linked_state_directory() {
        let project = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), project.path().join(".lpm")).unwrap();

        assert!(ensure_project_state_dir(project.path()).is_err());
        assert!(!elsewhere.path().join(".gitignore").exists());
    }

    #[cfg(unix)]
    #[test]
    fn leaves_a_linked_ignore_file_alone() {
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        let target = project.path().join("target");
        std::fs::write(&target, "keep\n").unwrap();
        std::os::unix::fs::symlink(&target, state.join(".gitignore")).unwrap();

        ensure_project_state_dir(project.path()).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
    }

    #[cfg(unix)]
    #[test]
    fn leaves_a_read_only_ignore_file_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        let ignore = state.join(".gitignore");
        std::fs::write(&ignore, "kept\n").unwrap();
        for mode in [0o444, 0o464] {
            std::fs::set_permissions(&ignore, std::fs::Permissions::from_mode(mode)).unwrap();

            ensure_project_state_dir(project.path()).unwrap();

            assert_eq!(
                std::fs::read_to_string(&ignore).unwrap(),
                "kept\n",
                "{mode:o}"
            );
        }
    }
}
