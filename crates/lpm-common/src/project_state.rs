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

/// The project's committed LPM records at its root, which LPM writes
/// itself.
pub const PROJECT_RECORD_FILES: &[&str] = &[
    "lpm.lock",
    "lpm.lockb",
    "lpm-sources.json",
    "lpm-agent-skills.json",
];

/// Root directories of the project's committed LPM records.
pub const PROJECT_RECORD_DIRS: &[&str] = &["lpm-changes"];

/// Whether a deploy output's ignore file lets git commit `path`, a file in
/// its state directory, `/`-separated and relative to it.
pub fn deploy_output_commits(path: &str) -> bool {
    path == PROJECT_STATE_IGNORE_FILE
        || ["store", "deploy-workspace"].iter().any(|directory| {
            path.strip_prefix(directory)
                .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// Whether a path component names a project state directory, as a
/// filesystem that folds names resolves it: without regard to case, and
/// without the marks HFS+ ignores.
pub fn is_project_state_name(name: &OsStr) -> bool {
    name.eq_ignore_ascii_case(PROJECT_STATE_DIR)
        || name.to_str().is_some_and(|name| {
            !name.is_ascii()
                && crate::names::fold_name(name).eq_ignore_ascii_case(PROJECT_STATE_DIR)
        })
}

/// Whether `name` in `parent` is one of `names` there by a short name,
/// such as `LPM~1` for `.lpm` or `LPM~1.LOC` for `lpm.lock`, which a volume
/// that makes them (NTFS, FAT) resolves in every open, from any system
/// (WSL's `/mnt/c`, Linux's ntfs3 and vfat), and only the file's identity
/// tells from a name of its own. Short names hold a `~`.
pub fn is_short_name_of<'a>(
    parent: &Path,
    name: &OsStr,
    names: impl IntoIterator<Item = &'a str>,
) -> bool {
    name.to_string_lossy().contains('~')
        && names
            .into_iter()
            .any(|long| crate::project_git::same_file(&parent.join(name), &parent.join(long)))
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

/// Keeps the open state directory to its owner and SYSTEM, letting
/// sandboxed lifecycle scripts through to what they are granted inside, as
/// [`crate::owner_only::protect_state_directory`] does; what an earlier
/// release left inside stops inheriting the project directory's access.
#[cfg(windows)]
fn keep_state_dir_owner_only_or_warn(
    directory: &cap_std::fs::Dir,
    _metadata: &cap_std::fs::Metadata,
    state_display: &Path,
) {
    if let Err(error) = crate::owner_only::protect_state_directory(directory, true) {
        tracing::warn!(
            "could not keep {} to its owner: {error}",
            state_display.display()
        );
    }
}

#[cfg(not(any(unix, windows)))]
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

/// Whether an LPM home's `.gitignore` ignores everything LPM writes there,
/// for every repository that walks into the home, as the file's own rules
/// decide it: it ignores everything, and may then take back only names LPM
/// keeps nothing private in, such as a dotfiles repository's `config.toml`.
fn keeps_lpm_home_out(lines: &[u8]) -> bool {
    const USERS_OWN: [&[u8]; 2] = [b".gitignore", b"config.toml"];
    let mut ignored = false;
    for pattern in ignore_rules(lines) {
        if let Some(negated) = pattern.strip_prefix(b"!") {
            let name = negated.strip_prefix(b"/").unwrap_or(negated);
            if !USERS_OWN.contains(&name) {
                ignored = false;
            }
            continue;
        }
        let unanchored = pattern.strip_prefix(b"/").unwrap_or(pattern);
        if unanchored == b"*" || unanchored == b"**" {
            ignored = true;
        }
    }
    ignored
}

/// Why git could commit what an LPM home holds, which LPM couldn't keep out
/// of git, as the command-start check reports it.
#[derive(Debug)]
pub struct LpmHomeExposed {
    reason: String,
    at_repository_root: bool,
}

impl LpmHomeExposed {
    /// What keeps the home out of git: an ignore file in it that ignores
    /// everything, or another home. A repository's root gets only the second,
    /// as such a file would hide the whole repository.
    #[must_use]
    pub fn remedy(&self) -> &'static str {
        if self.at_repository_root {
            "point LPM_HOME at a directory of its own"
        } else {
            "give it a .gitignore that ignores everything (`*`), or point LPM_HOME at a directory of its own"
        }
    }

    /// Whether the home is a repository's root, which only another home
    /// keeps out of git.
    #[must_use]
    pub fn at_repository_root(&self) -> bool {
        self.at_repository_root
    }
}

impl std::fmt::Display for LpmHomeExposed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// Keeps `root`, an LPM home, out of git as a project's `.lpm` keeps
/// itself, with a `.gitignore` that ignores everything in it. An LPM home
/// inside a repository, as `LPM_HOME="$PWD/.lpm-ci"` puts one, would
/// otherwise offer its login and env secrets to `git add`. Fails with the
/// reason when a repository is around a home it can't keep out, where
/// secrets must not be written; elsewhere what it can't do is logged.
pub fn keep_lpm_home_ignored(root: &Path) -> Result<(), String> {
    keep_lpm_home_out_of_git(root).map_err(|exposed| exposed.reason)
}

/// [`keep_lpm_home_ignored`], failing with what keeps the home in git, for
/// a caller that tells its user how to fix it.
pub fn keep_lpm_home_out_of_git(root: &Path) -> Result<(), LpmHomeExposed> {
    match cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority()) {
        Ok(directory) => keep_open_lpm_home_ignored(&directory, root),
        Err(error) => lpm_home_left_in_git(root, &error, false),
    }
}

/// [`keep_lpm_home_ignored`] for an LPM home a caller opened itself, at
/// `home_display`.
pub fn keep_lpm_home_ignored_in(
    directory: &cap_std::fs::Dir,
    home_display: &Path,
) -> Result<(), String> {
    keep_open_lpm_home_ignored(directory, home_display).map_err(|exposed| exposed.reason)
}

/// `LPM_HOME` can name a directory LPM doesn't own, so unlike `.lpm`'s, an
/// ignore file already there is left as it is, and a repository's root,
/// which the file would hide whole, gets none.
fn keep_open_lpm_home_ignored(
    directory: &cap_std::fs::Dir,
    home_display: &Path,
) -> Result<(), LpmHomeExposed> {
    let name = OsStr::new(PROJECT_STATE_IGNORE_FILE);
    let at_repository_root = directory.symlink_metadata(".git").is_ok();
    let kept_out = match read_ignore_file(directory, name) {
        Ok(Some((existing, _))) if keeps_lpm_home_out(&existing) => return Ok(()),
        Ok(_) if at_repository_root => {
            Err(std::io::Error::other("it is the root of a git repository"))
        }
        Ok(Some(_)) => Err(std::io::Error::other(format!(
            "its {PROJECT_STATE_IGNORE_FILE} doesn't ignore everything LPM writes there"
        ))),
        Ok(None) => crate::write_file_atomic_in_dir_with_options(
            directory,
            name,
            crate::AtomicWriteOptions::new().unix_mode(0o644),
            |file| std::io::Write::write_all(file, PROJECT_STATE_IGNORE.as_bytes()),
        ),
        Err(error) => Err(error),
    };
    match kept_out {
        Ok(()) => Ok(()),
        Err(error) => lpm_home_left_in_git(home_display, &error, at_repository_root),
    }
}

/// Readies the LPM home at `root` for a command, before anything writes
/// there: keeps it out of git, creating it with its ignore file first where
/// a repository is around it. Fails where a repository is around a home LPM
/// can't keep out of git, whose files git could then commit, so the command
/// must not run.
pub fn guard_lpm_home(root: &Path) -> Result<(), LpmHomeExposed> {
    let opened = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority());
    let directory = match opened {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !in_a_repository(root) {
                return Ok(());
            }
            match std::fs::create_dir_all(root).and_then(|()| {
                cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
            }) {
                Ok(directory) => directory,
                Err(error) => return lpm_home_left_in_git(root, &error, false),
            }
        }
        Err(error) => return lpm_home_left_in_git(root, &error, false),
    };
    keep_lpm_home_owner_only_or_warn(&directory, root);
    keep_open_lpm_home_ignored(&directory, root)
}

/// Keeps an existing LPM home at `root` out of git as
/// [`keep_lpm_home_ignored`] does; creates none. Commands run this when they
/// finish, so whatever wrote to the home, it ends up ignored. What it can't
/// do is only logged: the check at the command's start has reported it, and
/// writers of secrets there refuse on their own.
pub fn keep_existing_lpm_home_ignored(root: &Path) {
    let Ok(directory) = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
    else {
        return;
    };
    keep_lpm_home_owner_only_or_warn(&directory, root);
    if let Err(exposed) = keep_open_lpm_home_ignored(&directory, root) {
        tracing::debug!("{exposed}");
    }
}

/// Keeps the LPM home to its owner and SYSTEM on Windows, letting
/// sandboxed lifecycle scripts through to the store they are granted, as
/// [`crate::owner_only::protect_state_directory`] does for what is created
/// there from now on. What is already in it keeps its access: store files
/// are hard links in projects' `node_modules`, and a home in the user's
/// profile inherits the profile's.
#[cfg(windows)]
fn keep_lpm_home_owner_only_or_warn(directory: &cap_std::fs::Dir, root: &Path) {
    if let Err(error) = crate::owner_only::protect_state_directory(directory, false) {
        tracing::warn!("could not keep {} to its owner: {error}", root.display());
    }
}

#[cfg(not(windows))]
fn keep_lpm_home_owner_only_or_warn(_directory: &cap_std::fs::Dir, _root: &Path) {}

/// Why git could commit what the LPM home at `home` holds, which `error`
/// kept LPM from ignoring, when a directory at or above it holds a `.git`,
/// as `home` names it or where it is once links are followed; else that is
/// only logged.
fn lpm_home_left_in_git(
    home: &Path,
    error: &std::io::Error,
    at_repository_root: bool,
) -> Result<(), LpmHomeExposed> {
    let reason = format!(
        "could not keep the LPM home {} out of git: {error}",
        home.display()
    );
    if in_a_repository(home) {
        return Err(LpmHomeExposed {
            reason,
            at_repository_root,
        });
    }
    tracing::debug!("{reason}");
    Ok(())
}

/// Whether a directory at or above `path` holds a `.git`, as `path` names it
/// or where it is once links are followed.
fn in_a_repository(path: &Path) -> bool {
    let lexically = |path: &Path| {
        path.ancestors()
            .any(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
    };
    lexically(path) || resolved(path).is_some_and(|resolved| lexically(&resolved))
}

/// `path` with every link on the way followed, as far as it exists.
fn resolved(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find_map(|existing| {
            std::fs::canonicalize(existing)
                .ok()
                .map(|resolved| (existing, resolved))
        })
        .and_then(|(existing, resolved)| {
            path.strip_prefix(existing)
                .ok()
                .map(|missing| resolved.join(missing))
        })
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
    fn an_lpm_home_gets_an_ignore_file_but_keeps_one_it_already_has() {
        let home = tempfile::tempdir().unwrap();
        keep_lpm_home_ignored(home.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.path().join(".gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );

        // `LPM_HOME` can name a directory LPM doesn't own, such as a project.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".gitignore"), "node_modules/\n").unwrap();
        keep_lpm_home_ignored(project.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(project.path().join(".gitignore")).unwrap(),
            "node_modules/\n"
        );

        // A repository's root, which the file would hide whole.
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        keep_lpm_home_ignored(repository.path()).unwrap_err();
        assert!(!repository.path().join(".gitignore").exists());
    }

    #[test]
    fn an_lpm_home_git_could_commit_is_an_error_and_one_outside_a_repository_is_not() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join(".gitignore"), "node_modules/\n").unwrap();
        keep_lpm_home_ignored(outside.path()).unwrap();

        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let home = repository.path().join("packages/app");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".gitignore"), "node_modules/\n").unwrap();
        let reason = keep_lpm_home_ignored(&home).unwrap_err();
        assert!(reason.contains("doesn't ignore everything"), "{reason}");
        let exposed = keep_lpm_home_out_of_git(&home).unwrap_err();
        assert_eq!(exposed.to_string(), reason);
        assert!(!exposed.at_repository_root());
        let at_root = keep_lpm_home_out_of_git(repository.path()).unwrap_err();
        assert!(at_root.at_repository_root(), "{at_root}");

        std::fs::remove_file(home.join(".gitignore")).unwrap();
        keep_lpm_home_ignored(&home).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(".gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_lpm_home_reached_through_a_link_is_judged_where_it_is() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let home = repository.path().join("state");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join(".gitignore"), "cache/\n").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let alias = outside.path().join("lpm-home");
        std::os::unix::fs::symlink(&home, &alias).unwrap();

        keep_lpm_home_ignored(&home).unwrap_err();
        let reason = keep_lpm_home_ignored(&alias).unwrap_err();

        assert!(reason.contains("doesn't ignore everything"), "{reason}");
    }

    #[test]
    fn the_sweep_keeps_an_existing_lpm_home_ignored_and_creates_none() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("lpm-home");
        keep_existing_lpm_home_ignored(&missing);
        assert!(!missing.exists());

        std::fs::create_dir(&missing).unwrap();
        keep_existing_lpm_home_ignored(&missing);
        assert_eq!(
            std::fs::read_to_string(missing.join(".gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );
    }

    #[test]
    fn an_lpm_home_is_kept_by_an_ignore_file_that_keeps_only_the_user_s_config_tracked() {
        let repository = tempfile::tempdir().unwrap();
        let Ok(init) = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(repository.path())
            .status()
        else {
            return;
        };
        assert!(init.success());
        let home = repository.path().join(".lpm");
        std::fs::create_dir(&home).unwrap();
        // A dotfiles repository that commits the user's defaults.
        for kept in [
            "*\n!.gitignore\n!config.toml\n",
            "/*\n!/config.toml\n",
            // As Windows PowerShell 5.1 writes UTF-8, which git reads past.
            "\u{feff}*\r\n",
            "\u{feff}*\n!config.toml\n",
        ] {
            std::fs::write(home.join(".gitignore"), kept).unwrap();
            guard_lpm_home(&home).unwrap_or_else(|error| panic!("{kept:?}: {error}"));
            assert_eq!(
                std::fs::read_to_string(home.join(".gitignore")).unwrap(),
                kept
            );
        }
        // Rules that leave something LPM writes there to any repository
        // that walks into the home, an outer one past a nested repository's
        // own exclude included.
        for exposed in [
            "cache/\n",
            ".*\n",
            "*\n!certs/\n!certs/**\n",
            "*\n!*.pem\n",
            "\u{feff}cache/\n",
        ] {
            std::fs::write(home.join(".gitignore"), exposed).unwrap();
            let error = guard_lpm_home(&home).unwrap_err().to_string();
            assert!(
                error.contains("doesn't ignore everything"),
                "{exposed:?}: {error}"
            );
        }
    }

    #[test]
    fn an_lpm_home_at_a_repository_s_root_is_refused_as_that_whatever_ignore_file_it_has() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        for ignore_file in [None, Some("node_modules/\n"), Some("cache/\n!*.pem\n")] {
            let path = repository.path().join(".gitignore");
            match ignore_file {
                Some(rules) => std::fs::write(&path, rules).unwrap(),
                None => drop(std::fs::remove_file(&path)),
            }
            let exposed = guard_lpm_home(repository.path()).unwrap_err();
            assert!(
                exposed
                    .to_string()
                    .contains("it is the root of a git repository"),
                "{ignore_file:?}: {exposed}"
            );
            // A `*` there would hide the whole repository.
            assert_eq!(
                exposed.remedy(),
                "point LPM_HOME at a directory of its own",
                "{ignore_file:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).ok().as_deref(),
                ignore_file,
                "the repository's ignore file is left as it is"
            );
        }

        // One whose own ignore file keeps everything out, as a repository
        // of the user's config would, is kept.
        std::fs::write(
            repository.path().join(".gitignore"),
            "*\n!.gitignore\n!config.toml\n",
        )
        .unwrap();
        guard_lpm_home(repository.path()).unwrap();

        // Below the root, the home can be given an ignore file of its own.
        let home = repository.path().join(".lpm-ci");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join(".gitignore"), "cache/\n").unwrap();
        let exposed = guard_lpm_home(&home).unwrap_err();
        assert!(
            exposed.remedy().contains("ignores everything (`*`)"),
            "{exposed}"
        );
    }

    #[test]
    fn a_command_finds_its_lpm_home_ignored_before_anything_writes_there() {
        // Outside a repository, a home that doesn't exist yet is left to
        // whatever writes there first.
        let outside = tempfile::tempdir().unwrap();
        guard_lpm_home(&outside.path().join("lpm-home")).unwrap();
        assert!(!outside.path().join("lpm-home").exists());

        // Inside one, it is made with its ignore file first.
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let home = repository.path().join(".lpm-ci");
        guard_lpm_home(&home).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(".gitignore")).unwrap(),
            PROJECT_STATE_IGNORE
        );

        // A home there that git could commit doesn't get a command.
        std::fs::write(home.join(".gitignore"), "cache/\n").unwrap();
        let error = guard_lpm_home(&home).unwrap_err().to_string();
        assert!(error.contains("doesn't ignore everything"), "{error}");
        // Outside a repository the same home is the user's to keep.
        let elsewhere = outside.path().join("kept");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join(".gitignore"), "cache/\n").unwrap();
        guard_lpm_home(&elsewhere).unwrap();
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
