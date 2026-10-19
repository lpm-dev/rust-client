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

/// What [`PROJECT_STATE_IGNORE_FILE`] holds in a deploy output, whose `.lpm`
/// also holds the package store and workspace sources its dependencies are:
/// those travel with the output, and so does this file, so that a clone
/// keeps them committed; the rest stays machine-local.
pub const DEPLOY_OUTPUT_STATE_IGNORE: &str = "# LPM's machine-local state, but for this \
     file and the package store and workspace sources this deploy output's dependencies are.\n\
     *\n!/.gitignore\n!/store/\n!/store/**\n!/deploy-workspace/\n!/deploy-workspace/**\n";

/// Whether the state directory's ignore file `existing` keeps what it must
/// out of git: everything, or everything but a deploy output's
/// dependencies.
pub fn keeps_state_out_of_git(existing: &[u8]) -> bool {
    ignores_everything(existing) || is_deploy_output_state_ignore(existing)
}

/// Whether the state directory's ignore file `existing` is a deploy
/// output's: whether git reads in it the rules of
/// [`DEPLOY_OUTPUT_STATE_IGNORE`], in their order, whatever its comments
/// say and whatever line endings a checkout gave it, as Git for Windows'
/// `core.autocrlf` gives it CRLF.
pub fn is_deploy_output_state_ignore(existing: &[u8]) -> bool {
    ignore_rules(existing).eq(ignore_rules(DEPLOY_OUTPUT_STATE_IGNORE.as_bytes()))
}

/// The rules of an ignore file, as git reads its lines: past a leading byte
/// order mark, which some editors write, without blank lines and comments.
fn ignore_rules(lines: &[u8]) -> impl Iterator<Item = &[u8]> {
    crate::strip_utf8_bom_bytes(lines)
        .split(|byte| *byte == b'\n')
        .map(git_pattern)
        .filter(|pattern| !pattern.is_empty() && !pattern.starts_with(b"#"))
}

/// Whether a deploy output's ignore file lets git commit `path`, a file in
/// its state directory, `/`-separated and relative to it.
pub fn deploy_output_commits(path: &str) -> bool {
    path == PROJECT_STATE_IGNORE_FILE
        || ["store", "deploy-workspace"].iter().any(|directory| {
            path.strip_prefix(directory)
                .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// The project state directory for `project_dir`, without touching disk.
pub fn project_state_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(PROJECT_STATE_DIR)
}

/// The directories in the project state directory that hold installed
/// packages: the isolated layout's `wrappers/` and the hoisted layout's
/// `hoisted/nested/`. A package's lifecycle scripts may read and write
/// them; the rest of `.lpm` is LPM's own state, which scripts may not touch.
pub fn project_package_dirs(project_dir: &Path) -> [PathBuf; 2] {
    let state = project_state_dir(project_dir);
    [state.join("wrappers"), state.join("hoisted").join("nested")]
}

/// Opens `<project_dir>/.lpm`, creating it owner-only when missing, and
/// keeps it owner-only on Unix and out of git. A link at `.lpm` is refused.
/// Failing to restrict the directory or to write the ignore file is logged,
/// not returned: it never blocks the command that needs the state.
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
    keep_state_dir_owner_only_or_warn(&directory, &metadata, &state_display);
    keep_state_dir_ignored_or_warn(&directory, &state_display);
    Ok(directory)
}

/// Keeps the open state directory to its owner, as LPM creates it, logging
/// what it can't do: a directory an earlier version created, or that was
/// opened up since, loses the group and other access its mode grants, and on
/// macOS the access list entries it took from the project directory, which
/// would pass on to everything LPM writes in it. Another user's directory is
/// left as it is.
#[cfg(unix)]
fn keep_state_dir_owner_only_or_warn(
    directory: &cap_std::fs::Dir,
    metadata: &cap_std::fs::Metadata,
    state_display: &Path,
) {
    use cap_std::fs::{MetadataExt as _, PermissionsExt as _};

    if metadata.uid() != crate::current_uid() {
        return;
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0
        && let Err(error) =
            directory.set_permissions(".", cap_std::fs::Permissions::from_mode(mode & !0o077))
    {
        tracing::warn!(
            "could not keep {} owner-only: {error}",
            state_display.display()
        );
    }
    #[cfg(target_os = "macos")]
    if let Err(error) = crate::macos_acl::drop_extended_acl(directory) {
        tracing::warn!(
            "could not remove the access list entries {} took from its directory: {error}",
            state_display.display()
        );
    }
}

#[cfg(not(unix))]
fn keep_state_dir_owner_only_or_warn(
    _directory: &cap_std::fs::Dir,
    _metadata: &cap_std::fs::Metadata,
    _state_display: &Path,
) {
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

/// Keeps an existing `<project_dir>/.lpm` owner-only on Unix and out of git;
/// does nothing when the project has none. Commands run this when they
/// finish, so state written by any path ends up private and ignored.
pub fn keep_existing_project_state_ignored(project_dir: &Path) {
    use cap_fs_ext::DirExt as _;

    let Ok(root) = cap_std::fs::Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())
    else {
        return;
    };
    let Ok(directory) = root.open_dir_nofollow(PROJECT_STATE_DIR) else {
        return;
    };
    let state_display = project_state_dir(project_dir);
    if let Ok(metadata) = directory.dir_metadata() {
        keep_state_dir_owner_only_or_warn(&directory, &metadata, &state_display);
    }
    keep_state_dir_ignored_or_warn(&directory, &state_display);
}

/// Makes the open state directory's `.gitignore` ignore everything in it,
/// rewriting one that doesn't. One that is a link or not a regular file, or
/// that its owner keeps from being written (read-only, or on Unix another
/// user's), is left as it is and reported.
pub fn keep_state_dir_ignored(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    let name = OsStr::new(PROJECT_STATE_IGNORE_FILE);
    match read_ignore_file(directory, name)? {
        Some((existing, _)) if keeps_state_out_of_git(&existing) => return Ok(()),
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
    for pattern in ignore_rules(lines) {
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

    #[cfg(unix)]
    #[test]
    fn an_existing_state_directory_open_to_others_is_made_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_project_state_dir(project.path()).unwrap();
        assert_eq!(mode(&state), 0o700);

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
        keep_existing_project_state_ignored(project.path());
        assert_eq!(mode(&state), 0o700);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_state_directory_drops_access_the_project_directory_hands_down() {
        let project = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args([
                "+a",
                "group:everyone allow read,write,list,search,add_file,add_subdirectory,file_inherit,directory_inherit",
            ])
            .arg(project.path())
            .status()
            .unwrap();
        assert!(status.success());
        let has_acl = |path: &Path| crate::macos_acl::has_extended_acl_at(path).unwrap();

        let state = ensure_project_state_dir(project.path()).unwrap();
        assert!(!has_acl(&state));
        assert!(!has_acl(&state.join(PROJECT_STATE_IGNORE_FILE)));

        std::fs::remove_dir_all(&state).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(has_acl(&state));
        keep_existing_project_state_ignored(project.path());
        assert!(!has_acl(&state));
        assert!(!has_acl(&state.join(PROJECT_STATE_IGNORE_FILE)));
    }

    #[test]
    fn a_deploy_output_s_state_offers_git_its_dependencies_and_nothing_else() {
        let output = tempfile::tempdir().unwrap();
        let Ok(init) = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(output.path())
            .status()
        else {
            return;
        };
        assert!(init.success());
        let state = output.path().join(".lpm");
        for file in [
            "store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            "deploy-workspace/provider-000000/package.json",
            "known-projects.json",
            "install-hash",
            "cache/metadata/a.json",
        ] {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        std::fs::write(state.join(".gitignore"), DEPLOY_OUTPUT_STATE_IGNORE).unwrap();

        keep_existing_project_state_ignored(output.path());

        assert_eq!(
            std::fs::read_to_string(state.join(".gitignore")).unwrap(),
            DEPLOY_OUTPUT_STATE_IGNORE
        );
        let offered = std::process::Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard"])
            .current_dir(output.path())
            .output()
            .unwrap();
        let mut offered: Vec<_> = String::from_utf8_lossy(&offered.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        offered.sort();
        assert_eq!(
            offered,
            [
                ".lpm/.gitignore",
                ".lpm/deploy-workspace/provider-000000/package.json",
                ".lpm/store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            ]
        );
    }

    #[test]
    fn a_deploy_output_s_ignore_file_is_known_by_its_rules_as_git_reads_them() {
        let variant = DEPLOY_OUTPUT_STATE_IGNORE;
        let rules = variant.split_once('\n').unwrap().1;
        for kept in [
            variant.replace('\n', "\r\n"),
            format!("# Worded otherwise.\n\n{rules}"),
            rules.to_string(),
        ] {
            assert!(is_deploy_output_state_ignore(kept.as_bytes()), "{kept:?}");
        }
        // Each of these ignores nothing git would read as `*`.
        for crafted in [
            variant.replacen("*\n", "*\r\r\n", 1),
            variant.replacen("*\n", "\r*\n", 1),
            variant.replacen("!/store/\n", "!/st\rore/\n", 1),
        ] {
            assert!(
                !is_deploy_output_state_ignore(crafted.as_bytes()),
                "{crafted:?}"
            );
            let output = tempfile::tempdir().unwrap();
            let state = output.path().join(".lpm");
            std::fs::create_dir(&state).unwrap();
            std::fs::write(state.join(".gitignore"), &crafted).unwrap();

            keep_existing_project_state_ignored(output.path());

            assert_eq!(
                std::fs::read_to_string(state.join(".gitignore")).unwrap(),
                PROJECT_STATE_IGNORE,
                "{crafted:?}"
            );
        }
    }

    #[test]
    fn a_deploy_output_s_ignore_file_checked_out_with_crlf_endings_is_kept() {
        let output = tempfile::tempdir().unwrap();
        let state = output.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        // As a Git for Windows checkout with `core.autocrlf` writes it.
        let checked_out = DEPLOY_OUTPUT_STATE_IGNORE.replace('\n', "\r\n");
        std::fs::write(state.join(".gitignore"), &checked_out).unwrap();

        keep_existing_project_state_ignored(output.path());

        assert_eq!(
            std::fs::read_to_string(state.join(".gitignore")).unwrap(),
            checked_out
        );
        assert!(deploy_output_commits("store/v2/links/a/index.js"));
        assert!(deploy_output_commits("deploy-workspace/provider-000000"));
        assert!(deploy_output_commits(".gitignore"));
        assert!(!deploy_output_commits("known-projects.json"));
        assert!(!deploy_output_commits("storefront/x"));
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
        assert!(ignores_everything("\u{feff}*\r\n".as_bytes()));
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
