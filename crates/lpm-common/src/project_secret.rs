//! Secret files LPM writes into a project, such as a `.env` with real
//! values or an `.npmrc` with a token. Each one is kept out of git before
//! the secret reaches disk, then written owner-only and atomically, never
//! through a symbolic link. A file outside the project is written the same
//! way without touching any ignore file.

use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::fs::{Dir, OpenOptions};

use crate::atomic_write::file_identity;
#[cfg(windows)]
use crate::atomic_write::windows_file_information;
use crate::project_git::{GitProbeError, git_failure, inside_work_tree, run_git, tracked_entries};

/// Where the rule that keeps a secret file out of git goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreFile {
    /// The project's `.gitignore`, which the team shares.
    ProjectGitignore,
    /// The repository's `info/exclude`, which stays on this machine. For
    /// files written in CI, where editing a tracked file dirties the tree.
    RepositoryExclude,
}

/// What a failure to keep the file out of git does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreFailure {
    /// Write nothing and return the failure.
    Refuse,
    /// Write the file and report the failure as a warning.
    Warn,
}

/// What happens when the destination exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    Replace,
    /// Leave it as it is; the write reports `written: false`.
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretFileOptions {
    pub ignore_file: IgnoreFile,
    pub on_ignore_failure: IgnoreFailure,
    pub existing: Existing,
}

/// How a secret file is kept out of git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretIgnore {
    /// The file is in no git work tree, so no ignore file was edited.
    OutsideProject,
    /// Git already ignores it.
    AlreadyIgnored,
    /// A rule for it was added to `file`, and git confirmed it.
    Added { file: PathBuf },
    /// No git repository holds the project. `added` names the ignore file
    /// that took a rule anyway, so the file stays ignored if one is created.
    NoRepository { added: Option<PathBuf> },
    /// Git could not be run, so nothing was confirmed.
    Unverified { added: Option<PathBuf> },
    /// Keeping the file out of git failed and the caller chose to go on.
    Failed,
}

/// The outcome of [`write_secret_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretWrite {
    pub path: PathBuf,
    /// Whether the file was written; `false` when [`Existing::Keep`] found it.
    pub written: bool,
    pub ignore: SecretIgnore,
    /// What the user should know: an unconfirmed or failed ignore rule.
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    #[error(
        "{path} is tracked by git, so a secret written there would be committed; untrack it with \
         `{untrack}`, then run the command again"
    )]
    Tracked { path: PathBuf, untrack: String },
    #[error("refusing to write a secret through the symbolic link or junction at {path}")]
    Link { path: PathBuf },
    #[error("{path} is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("could not keep {path} out of git: {reason}")]
    Ignore { path: PathBuf, reason: String },
    #[error("failed to write {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl From<SecretFileError> for crate::LpmError {
    fn from(error: SecretFileError) -> Self {
        Self::ProjectFile(error.to_string())
    }
}

/// Writes `contents` to `path`, a secret file, making git ignore it first
/// when it is inside `project_dir`, or else in another git work tree, such
/// as the repository a workspace member's project sits in, whose root then
/// takes the rule.
pub fn write_secret_file(
    project_dir: &Path,
    path: &Path,
    contents: &[u8],
    options: SecretFileOptions,
) -> Result<SecretWrite, SecretFileError> {
    let path = absolute_normalized(path).map_err(|source| SecretFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let (project_dir, relative) = match ignore_anchor(project_dir, &path) {
        Anchor::WorkTree { root, relative } => (root, relative),
        Anchor::Outside(outside) => {
            let (ignore, warnings) = outside.ignore(&path, options.on_ignore_failure)?;
            let written = write_outside_project(&path, contents, options.existing)?;
            return Ok(SecretWrite {
                path,
                written,
                ignore,
                warnings,
            });
        }
    };
    let project_dir = project_dir.as_path();

    let root =
        Dir::open_ambient_dir(project_dir, cap_std::ambient_authority()).map_err(|source| {
            SecretFileError::Io {
                path: project_dir.to_path_buf(),
                source,
            }
        })?;
    let (parent, name) = open_parent(&root, project_dir, &relative)?;
    let exists = destination_exists(&parent, name, &path)?;
    let tracked_is_fatal = !(exists && options.existing == Existing::Keep);
    let (ignore, warnings) = keep_relative_ignored(
        project_dir,
        &relative,
        options.ignore_file,
        options.on_ignore_failure,
        tracked_is_fatal,
    )?;
    if exists && options.existing == Existing::Keep {
        return Ok(SecretWrite {
            path,
            written: false,
            ignore,
            warnings,
        });
    }
    let written = write_in_dir(&parent, name, contents, options.existing, &path)?;
    Ok(SecretWrite {
        path,
        written,
        ignore,
        warnings,
    })
}

/// Makes git ignore `path`, an existing file inside `project_dir` that
/// holds secrets, as [`write_secret_file`] does before it writes. A file
/// git tracks is reported as a warning: ignoring can't untrack it.
pub fn keep_secret_file_ignored(
    project_dir: &Path,
    path: &Path,
    ignore_file: IgnoreFile,
    on_failure: IgnoreFailure,
) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
    let path = absolute_normalized(path).map_err(|source| SecretFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    match ignore_anchor(project_dir, &path) {
        Anchor::WorkTree { root, relative } => {
            keep_relative_ignored(&root, &relative, ignore_file, on_failure, false)
        }
        Anchor::Outside(outside) => outside.ignore(&path, on_failure),
    }
}

/// Makes git ignore `path` before the caller writes a secret there itself,
/// as [`write_secret_file`] does: a tracked file is refused.
pub fn prepare_secret_destination(
    project_dir: &Path,
    path: &Path,
    ignore_file: IgnoreFile,
    on_failure: IgnoreFailure,
) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
    let path = absolute_normalized(path).map_err(|source| SecretFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    match ignore_anchor(project_dir, &path) {
        Anchor::WorkTree { root, relative } => {
            keep_relative_ignored(&root, &relative, ignore_file, on_failure, true)
        }
        Anchor::Outside(outside) => outside.ignore(&path, on_failure),
    }
}

/// Where git's ignore rules for a secret file come from.
enum Anchor {
    /// `root`, the project directory or the git work tree that holds the
    /// file, with the file's path relative to it.
    WorkTree {
        root: PathBuf,
        relative: PathBuf,
    },
    Outside(Outside),
}

/// Why a secret file outside the project has no work tree to keep it out of
/// git.
enum Outside {
    /// No git work tree holds it.
    NoWorkTree,
    /// Git could not be run, so whether one holds it is unknown.
    GitMissing(String),
    /// Git could not tell whether one holds it.
    Unknown(String),
}

impl Outside {
    /// A file no work tree holds needs nothing; one git can't place is
    /// refused or warned about as `on_failure` says, as a file in the
    /// project would be.
    fn ignore(
        self,
        path: &Path,
        on_failure: IgnoreFailure,
    ) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
        let display = path.display();
        match self {
            Self::NoWorkTree => Ok((SecretIgnore::OutsideProject, Vec::new())),
            Self::GitMissing(reason) => Ok((
                SecretIgnore::Unverified { added: None },
                vec![format!(
                    "git could not be run ({reason}), so LPM could not confirm that git ignores {display}"
                )],
            )),
            Self::Unknown(reason) => match on_failure {
                IgnoreFailure::Refuse => Err(SecretFileError::Ignore {
                    path: path.to_path_buf(),
                    reason,
                }),
                IgnoreFailure::Warn => Ok((
                    SecretIgnore::Failed,
                    vec![format!(
                        "could not keep {display} out of git ({reason}); make sure it is never committed"
                    )],
                )),
            },
        }
    }
}

/// Where git's ignore rules for `path` come from: `project_dir` for a path
/// inside it, unless a repository nested in the project holds the path,
/// and else the git work tree that holds `path`; the root of that work tree
/// takes the rule.
fn ignore_anchor(project_dir: &Path, path: &Path) -> Anchor {
    if let Some(relative) = project_relative(project_dir, path) {
        return match nested_repository(project_dir, path) {
            Some(nested) => work_tree_anchor(&nested, path),
            None => Anchor::WorkTree {
                root: project_dir.to_path_buf(),
                relative,
            },
        };
    }
    let Some(parent) = path.parent() else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    work_tree_anchor(parent, path)
}

/// The directory below `project_dir` and above `path` nearest `path` that
/// holds a `.git`, as a repository cloned into the project, or a submodule,
/// does.
fn nested_repository(project_dir: &Path, path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .take_while(|directory| *directory != project_dir && directory.starts_with(project_dir))
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

/// The anchor in the git work tree that holds `directory`, an existing
/// directory at or above `path`.
fn work_tree_anchor(directory: &Path, path: &Path) -> Anchor {
    // A directory that doesn't exist fails the write that follows.
    let Ok(directory) = directory.canonicalize() else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    let Some(name) = path.file_name() else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    let below = path
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .and_then(|parent| parent.strip_prefix(&directory).ok().map(Path::to_path_buf))
        .unwrap_or_default();
    match work_tree_of(&directory) {
        Ok(Some((root, prefix))) => Anchor::WorkTree {
            root,
            relative: prefix.join(below).join(name),
        },
        Ok(None) => Anchor::Outside(Outside::NoWorkTree),
        Err(GitProbeError::GitMissing(reason)) => Anchor::Outside(Outside::GitMissing(reason)),
        Err(GitProbeError::Failed(reason)) => Anchor::Outside(Outside::Unknown(reason)),
    }
}

/// The root of the git work tree that holds `directory`, with
/// `directory`'s path inside it, as git spells both.
fn work_tree_of(directory: &Path) -> Result<Option<(PathBuf, PathBuf)>, GitProbeError> {
    if !inside_work_tree(directory)? {
        return Ok(None);
    }
    let located = run_git(
        directory,
        &["rev-parse", "--show-toplevel", "--show-prefix"],
    )?;
    if !located.status.success() {
        return Err(GitProbeError::Failed(git_failure(&located)));
    }
    let output = String::from_utf8(located.stdout)
        .map_err(|_| GitProbeError::Failed("git returned a path that is not UTF-8".into()))?;
    let mut lines = output.lines();
    let (Some(root), prefix) = (lines.next(), lines.next().unwrap_or("")) else {
        return Err(GitProbeError::Failed("git returned no work tree".into()));
    };
    Ok(Some((PathBuf::from(root), PathBuf::from(prefix))))
}

impl SecretIgnore {
    /// The ignore file that took a rule, if one did.
    pub fn added_to(&self) -> Option<&Path> {
        match self {
            Self::Added { file } => Some(file),
            Self::NoRepository { added } | Self::Unverified { added } => added.as_deref(),
            Self::OutsideProject | Self::AlreadyIgnored | Self::Failed => None,
        }
    }
}

fn keep_relative_ignored(
    project_dir: &Path,
    relative: &Path,
    ignore_file: IgnoreFile,
    on_failure: IgnoreFailure,
    tracked_is_fatal: bool,
) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
    let path = project_dir.join(relative);
    let display = portable(relative);
    let fail = |reason: String| -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
        match on_failure {
            IgnoreFailure::Refuse => Err(SecretFileError::Ignore {
                path: path.clone(),
                reason,
            }),
            IgnoreFailure::Warn => Ok((
                SecretIgnore::Failed,
                vec![format!(
                    "could not keep {display} out of git ({reason}); make sure it is never committed"
                )],
            )),
        }
    };
    let rule = match ignore_rule(relative) {
        Ok(rule) => rule,
        Err(reason) => return fail(reason),
    };

    let repository = match probe_repository(project_dir) {
        Ok(repository) => repository,
        Err(GitProbeError::GitMissing(reason)) => {
            let mut warnings = vec![format!(
                "git could not be run ({reason}), so LPM could not confirm that git ignores {display}"
            )];
            let added = match ignore_file {
                IgnoreFile::ProjectGitignore => match append_project_rule(project_dir, &rule) {
                    Ok(file) => Some(file),
                    Err(error) => {
                        warnings.push(format!(
                            "could not add {display} to {} ({error}); add it before committing",
                            project_dir.join(".gitignore").display()
                        ));
                        None
                    }
                },
                IgnoreFile::RepositoryExclude => None,
            };
            return Ok((SecretIgnore::Unverified { added }, warnings));
        }
        Err(GitProbeError::Failed(reason)) => return fail(reason),
    };
    let Some(repository) = repository else {
        // No repository can commit the file yet, so a rule that can't be
        // written is a warning wherever the caller would refuse.
        return Ok(match ignore_file {
            IgnoreFile::ProjectGitignore => match append_project_rule(project_dir, &rule) {
                Ok(file) => (SecretIgnore::NoRepository { added: Some(file) }, Vec::new()),
                Err(error) => (
                    SecretIgnore::NoRepository { added: None },
                    vec![format!(
                        "could not add {display} to {} ({error}); add it before committing",
                        project_dir.join(".gitignore").display()
                    )],
                ),
            },
            IgnoreFile::RepositoryExclude => {
                (SecretIgnore::NoRepository { added: None }, Vec::new())
            }
        });
    };

    match tracked_entries(project_dir, &[&display]) {
        Ok(None) => {}
        Ok(Some(tracked)) if tracked.is_empty() => {}
        Ok(Some(tracked)) => {
            let untrack = tracked.untrack_command();
            if tracked_is_fatal {
                return Err(SecretFileError::Tracked { path, untrack });
            }
            return Ok((
                SecretIgnore::Failed,
                vec![format!(
                    "git tracks {display}, so its secrets will be committed; untrack it with \
                     `{untrack}`"
                )],
            ));
        }
        Err(error) => return fail(error.into_reason()),
    }
    match is_ignored(project_dir, relative) {
        Ok(true) => return Ok((SecretIgnore::AlreadyIgnored, Vec::new())),
        Ok(false) => {}
        Err(reason) => return fail(reason),
    }
    let (target, added) = match ignore_file {
        IgnoreFile::ProjectGitignore => (
            project_dir.join(".gitignore"),
            append_project_rule(project_dir, &rule),
        ),
        IgnoreFile::RepositoryExclude => {
            let repository_rule = match ignore_rule(&repository.prefix.join(relative)) {
                Ok(rule) => rule,
                Err(reason) => return fail(reason),
            };
            (
                repository.exclude.clone(),
                append_rule_at(&repository.exclude, &repository_rule),
            )
        }
    };
    let file = match added {
        Ok(file) => file,
        Err(error) => return fail(format!("could not add it to {}: {error}", target.display())),
    };
    match is_ignored(project_dir, relative) {
        Ok(true) => Ok((SecretIgnore::Added { file }, Vec::new())),
        Ok(false) => fail(format!(
            "the rule added to {} is overridden by a later or deeper ignore rule",
            file.display()
        )),
        Err(reason) => fail(reason),
    }
}

struct Repository {
    /// The project directory's path inside the work tree.
    prefix: PathBuf,
    exclude: PathBuf,
}

fn probe_repository(project_dir: &Path) -> Result<Option<Repository>, GitProbeError> {
    if !inside_work_tree(project_dir)? {
        return Ok(None);
    }
    let located = run_git(
        project_dir,
        &["rev-parse", "--git-path", "info/exclude", "--show-prefix"],
    )?;
    if !located.status.success() {
        return Err(GitProbeError::Failed(git_failure(&located)));
    }
    let output = String::from_utf8(located.stdout)
        .map_err(|_| GitProbeError::Failed("git returned a path that is not UTF-8".into()))?;
    let mut lines = output.lines();
    let (Some(exclude), prefix) = (lines.next(), lines.next().unwrap_or("")) else {
        return Err(GitProbeError::Failed(
            "git returned no repository paths".into(),
        ));
    };
    let exclude = Path::new(exclude);
    Ok(Some(Repository {
        prefix: PathBuf::from(prefix),
        exclude: if exclude.is_absolute() {
            exclude.to_path_buf()
        } else {
            project_dir.join(exclude)
        },
    }))
}

fn is_ignored(project_dir: &Path, relative: &Path) -> Result<bool, String> {
    let path = portable(relative);
    let output = run_git(project_dir, &["check-ignore", "-q", "--", &path])
        .map_err(GitProbeError::into_reason)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(git_failure(&output)),
    }
}

/// An anchored `.gitignore` rule matching exactly `relative`, with the
/// characters git reads as pattern syntax escaped.
fn ignore_rule(relative: &Path) -> Result<String, String> {
    let mut rule = String::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(format!(
                "{} is not a plain project path",
                relative.display()
            ));
        };
        let name = name
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", relative.display()))?;
        if name.chars().any(char::is_control) {
            return Err(format!(
                "{} holds a control character, which an ignore rule can't express",
                relative.display()
            ));
        }
        rule.push('/');
        let body = name.trim_end_matches(' ');
        for character in body.chars() {
            if matches!(character, '\\' | '*' | '?' | '[') {
                rule.push('\\');
            }
            rule.push(character);
        }
        for _ in body.len()..name.len() {
            rule.push_str("\\ ");
        }
    }
    if rule.is_empty() {
        return Err("an empty path can't be ignored".into());
    }
    Ok(rule)
}

fn append_project_rule(project_dir: &Path, rule: &str) -> io::Result<PathBuf> {
    let directory = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    append_rule(&directory, OsStr::new(".gitignore"), rule)?;
    Ok(project_dir.join(".gitignore"))
}

fn append_rule_at(file: &Path, rule: &str) -> io::Result<PathBuf> {
    let (Some(parent), Some(name)) = (file.parent(), file.file_name()) else {
        return Err(io::Error::other(format!(
            "{} is not a file path",
            file.display()
        )));
    };
    std::fs::create_dir_all(parent)?;
    let directory = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    append_rule(&directory, name, rule)?;
    Ok(file.to_path_buf())
}

/// How often an ignore-file update starts over when another one replaced the
/// file while it waited for the lock.
const IGNORE_FILE_ATTEMPTS: usize = 8;

/// Appends `rule` as its own line to the ignore file `name` in `directory`
/// unless the file already holds it, refusing a link or a file with other
/// hard links and holding a lock while the file's identity stays the same.
/// A file another update replaced while this one waited is opened again.
fn append_rule(directory: &Dir, name: &OsStr, rule: &str) -> io::Result<()> {
    for _ in 0..IGNORE_FILE_ATTEMPTS {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .append(true)
            .create(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        let file = directory.open_with(name, &options)?.into_std();
        validate_ignore_file(&file)?;
        let _lock = crate::acquire_single_file_exclusive_lock_from_file(file.try_clone()?)
            .map_err(io::Error::other)?;
        if is_current_ignore_file(directory, name, &file)? {
            return append_to_locked_ignore_file(directory, name, file, rule);
        }
    }
    Err(io::Error::other(
        "the ignore file kept changing during the update",
    ))
}

fn append_to_locked_ignore_file(
    directory: &Dir,
    name: &OsStr,
    mut file: std::fs::File,
    rule: &str,
) -> io::Result<()> {
    let (existing, _) = crate::read_text_file_capped_from_open_file(
        file.try_clone()?,
        Path::new(name),
        crate::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(io::Error::other)?;
    // The unanchored spelling also matches the path, at any depth.
    let unanchored = rule.trim_start_matches('/');
    if existing
        .lines()
        .any(|line| line == rule || line == unanchored)
    {
        return Ok(());
    }
    let mut addition = String::with_capacity(rule.len() + 2);
    if !existing.is_empty() && !existing.ends_with('\n') {
        addition.push('\n');
    }
    addition.push_str(rule);
    addition.push('\n');
    if !is_current_ignore_file(directory, name, &file)? {
        return Err(io::Error::other(
            "the ignore file changed during the update",
        ));
    }
    file.write_all(addition.as_bytes())?;
    file.sync_all()
}

/// What [`rewrite_ignore_file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreRewrite {
    Unchanged,
    Rewritten,
    Removed,
}

/// Rewrites the ignore file at `path` to what `transform` makes of it, and
/// removes the file when that is only whitespace. It takes the lock that
/// [`write_secret_file`] holds to append a rule, and reads the file again
/// after taking it, so `transform` sees every rule appended before.
/// `transform` returning `None` leaves the file alone, which a first read
/// without the lock settles, as does a missing file, a link, or a file with
/// other hard links.
pub fn rewrite_ignore_file(
    path: &Path,
    transform: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> io::Result<IgnoreRewrite> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(IgnoreRewrite::Unchanged);
    };
    match crate::read_file_capped_unlinked(path, crate::CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok((content, _)) if transform(&content).is_some() => {}
        _ => return Ok(IgnoreRewrite::Unchanged),
    }
    let directory = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    for _ in 0..IGNORE_FILE_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = match directory.open_with(name, &options) {
            Ok(file) => file.into_std(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(IgnoreRewrite::Unchanged);
            }
            Err(error) => return Err(error),
        };
        if validate_ignore_file(&file).is_err() {
            return Ok(IgnoreRewrite::Unchanged);
        }
        let _lock = crate::acquire_single_file_exclusive_lock_from_file(file.try_clone()?)
            .map_err(io::Error::other)?;
        if !is_current_ignore_file(&directory, name, &file)? {
            continue;
        }
        let (content, _) = crate::read_file_capped_from_open_file(
            file,
            Path::new(name),
            crate::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(io::Error::other)?;
        let Some(rewritten) = transform(&content) else {
            return Ok(IgnoreRewrite::Unchanged);
        };
        if rewritten.iter().all(u8::is_ascii_whitespace) {
            directory.remove_file(name)?;
            return Ok(IgnoreRewrite::Removed);
        }
        crate::write_file_atomic_in_dir_with_options(
            &directory,
            name,
            crate::AtomicWriteOptions::new(),
            |output| output.write_all(&rewritten),
        )?;
        return Ok(IgnoreRewrite::Rewritten);
    }
    Err(io::Error::other(
        "the ignore file kept changing during the update",
    ))
}

fn validate_ignore_file(file: &std::fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || crate::is_symlink_or_junction(&metadata) {
        return Err(io::Error::other("the ignore file is not a regular file"));
    }
    if link_count(file)? != 1 {
        return Err(io::Error::other("the ignore file has other hard links"));
    }
    Ok(())
}

/// Whether `retained` is still the file at `name`. The file at `name` being
/// a link or having other hard links is an error; `retained`, once replaced,
/// has none left.
fn is_current_ignore_file(
    directory: &Dir,
    name: &OsStr,
    retained: &std::fs::File,
) -> io::Result<bool> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let current = match directory.open_with(name, &options) {
        Ok(current) => current.into_std(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_ignore_file(&current)?;
    Ok(file_identity(retained)? == file_identity(&current)?)
}

#[cfg(unix)]
fn link_count(file: &std::fs::File) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn link_count(file: &std::fs::File) -> io::Result<u64> {
    Ok(u64::from(windows_file_information(file)?.nNumberOfLinks))
}

#[cfg(not(any(unix, windows)))]
fn link_count(_file: &std::fs::File) -> io::Result<u64> {
    Ok(1)
}

/// The directory holding `relative` inside `root`, opened without
/// following links, and the file name in it.
fn open_parent<'a>(
    root: &Dir,
    project_dir: &Path,
    relative: &'a Path,
) -> Result<(Dir, &'a OsStr), SecretFileError> {
    let name = relative
        .file_name()
        .ok_or_else(|| SecretFileError::NotRegular {
            path: project_dir.join(relative),
        })?;
    let mut directory = root.try_clone().map_err(|source| SecretFileError::Io {
        path: project_dir.to_path_buf(),
        source,
    })?;
    let mut current = project_dir.to_path_buf();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        let Component::Normal(segment) = component else {
            continue;
        };
        current.push(segment);
        match directory.symlink_metadata(segment) {
            Ok(metadata) if is_link_or_reparse(&metadata) => {
                return Err(SecretFileError::Link { path: current });
            }
            Ok(_) => {}
            Err(source) => {
                return Err(SecretFileError::Io {
                    path: current,
                    source,
                });
            }
        }
        directory = directory
            .open_dir_nofollow(segment)
            .map_err(|source| SecretFileError::Io {
                path: current.clone(),
                source,
            })?;
    }
    Ok((directory, name))
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn destination_exists(directory: &Dir, name: &OsStr, path: &Path) -> Result<bool, SecretFileError> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_dir() => Err(SecretFileError::NotRegular {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(SecretFileError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_in_dir(
    directory: &Dir,
    name: &OsStr,
    contents: &[u8],
    existing: Existing,
    path: &Path,
) -> Result<bool, SecretFileError> {
    let options = crate::AtomicWriteOptions::new()
        .owner_only()
        .sync_file()
        .sync_parent();
    let write = |file: &mut cap_std::fs::File| file.write_all(contents);
    let io_error = |source| SecretFileError::Io {
        path: path.to_path_buf(),
        source,
    };
    match existing {
        Existing::Replace => {
            crate::write_file_atomic_in_dir_with_options(directory, name, options, write)
                .map_err(io_error)?;
            Ok(true)
        }
        Existing::Keep => crate::atomic_write::create_file_atomic_in_dir_with_options(
            directory, name, options, write,
        )
        .map(|created| created.is_some())
        .map_err(io_error),
    }
}

fn write_outside_project(
    path: &Path,
    contents: &[u8],
    existing: Existing,
) -> Result<bool, SecretFileError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(SecretFileError::NotRegular {
            path: path.to_path_buf(),
        });
    };
    let directory =
        Dir::open_ambient_dir(parent, cap_std::ambient_authority()).map_err(|source| {
            SecretFileError::Io {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    if destination_exists(&directory, name, path)? && existing == Existing::Keep {
        return Ok(false);
    }
    write_in_dir(&directory, name, contents, existing, path)
}

fn absolute_normalized(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

/// `path` relative to the project, spelled through the project directory
/// as given or as it resolves; `None` outside it or at its root.
fn project_relative(project_dir: &Path, path: &Path) -> Option<PathBuf> {
    let given = absolute_normalized(project_dir).ok();
    let resolved = std::fs::canonicalize(project_dir).ok();
    let path_resolved = path
        .parent()
        .and_then(|parent| std::fs::canonicalize(parent).ok())
        .zip(path.file_name())
        .map(|(parent, name)| parent.join(name));
    let candidates = [Some(path.to_path_buf()), path_resolved];
    for root in [given, resolved].into_iter().flatten() {
        for candidate in candidates.iter().flatten() {
            if let Ok(relative) = candidate.strip_prefix(&root)
                && !relative.as_os_str().is_empty()
            {
                return Some(relative.to_path_buf());
            }
        }
    }
    None
}

fn portable(relative: &Path) -> String {
    let mut out = String::new();
    for component in relative.components() {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&component.as_os_str().to_string_lossy());
    }
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::project_git::hardened_git_command;

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn repository() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
        ] {
            let status = hardened_git_command(dir.path(), args).status().unwrap();
            assert!(status.success(), "git {args:?}");
        }
        dir
    }

    const PROJECT: SecretFileOptions = SecretFileOptions {
        ignore_file: IgnoreFile::ProjectGitignore,
        on_ignore_failure: IgnoreFailure::Refuse,
        existing: Existing::Replace,
    };

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ignores_then_writes_an_owner_only_secret() {
        if !git_available() {
            return;
        }
        let project = repository();
        let path = project.path().join(".env.local");

        let write = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT).unwrap();

        assert!(write.written);
        assert_eq!(
            write.ignore,
            SecretIgnore::Added {
                file: project.path().join(".gitignore")
            }
        );
        assert_eq!(
            std::fs::read_to_string(project.path().join(".gitignore")).unwrap(),
            "/.env.local\n"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"TOKEN=x\n");
        assert_eq!(mode(&path), 0o600);
        assert!(write.warnings.is_empty());

        let again = write_secret_file(project.path(), &path, b"TOKEN=y\n", PROJECT).unwrap();
        assert_eq!(again.ignore, SecretIgnore::AlreadyIgnored);
        assert_eq!(
            std::fs::read_to_string(project.path().join(".gitignore")).unwrap(),
            "/.env.local\n"
        );
    }

    #[test]
    fn refuses_a_tracked_file_without_writing_it() {
        if !git_available() {
            return;
        }
        let project = repository();
        let path = project.path().join(".env");
        std::fs::write(&path, "TOKEN=\n").unwrap();
        let status = hardened_git_command(project.path(), &["add", ".env"])
            .status()
            .unwrap();
        assert!(status.success());

        let error = write_secret_file(project.path(), &path, b"TOKEN=secret\n", PROJECT)
            .expect_err("a tracked file must not receive a secret");

        assert!(matches!(error, SecretFileError::Tracked { .. }), "{error}");
        let message = error.to_string();
        assert!(
            message.contains("`git -C ") && message.contains(" rm --cached -- .env`"),
            "{message}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "TOKEN=\n");
        assert!(!project.path().join(".gitignore").exists());
    }

    #[test]
    fn a_secret_in_a_repository_nested_in_the_project_answers_to_that_repository() {
        if !git_available() {
            return;
        }
        for project_in_git in [true, false] {
            let project = if project_in_git {
                repository()
            } else {
                tempfile::tempdir().unwrap()
            };
            let nested = project.path().join("infra");
            std::fs::create_dir(&nested).unwrap();
            for args in [
                &["init", "-q"][..],
                &["config", "core.excludesFile", "/dev/null"],
            ] {
                assert!(
                    hardened_git_command(&nested, args)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            std::fs::write(nested.join(".env"), "TOKEN=\n").unwrap();
            assert!(
                hardened_git_command(&nested, &["add", ".env"])
                    .status()
                    .unwrap()
                    .success()
            );

            let error = write_secret_file(
                project.path(),
                &nested.join(".env"),
                b"TOKEN=secret\n",
                PROJECT,
            )
            .expect_err("a file the nested repository tracks must not receive a secret");
            assert!(
                matches!(error, SecretFileError::Tracked { .. }),
                "project in git: {project_in_git}: {error}"
            );
            assert_eq!(
                std::fs::read_to_string(nested.join(".env")).unwrap(),
                "TOKEN=\n"
            );

            let write = write_secret_file(
                project.path(),
                &nested.join(".env.local"),
                b"TOKEN=x\n",
                PROJECT,
            )
            .unwrap();
            assert_eq!(
                write.ignore,
                SecretIgnore::Added {
                    file: nested.canonicalize().unwrap().join(".gitignore")
                },
                "project in git: {project_in_git}"
            );
            assert!(!project.path().join(".gitignore").exists());
        }
    }

    #[test]
    fn refuses_a_file_git_tracks_in_another_case_where_git_ignores_case() {
        if !git_available() {
            return;
        }
        let project = repository();
        std::fs::write(project.path().join(".ENV"), "PLACEHOLDER=1\n").unwrap();
        for args in [
            &["config", "core.ignorecase", "true"][..],
            &["add", "--", ".ENV"],
        ] {
            let status = hardened_git_command(project.path(), args).status().unwrap();
            assert!(status.success(), "git {args:?}");
        }

        // Where the disk tells `.ENV` from `.env`, the secret goes into a
        // file git doesn't track.
        if !project.path().join(".env").exists() {
            return;
        }
        let error = write_secret_file(
            project.path(),
            &project.path().join(".env"),
            b"TOKEN=secret\n",
            PROJECT,
        )
        .expect_err("a file git commits as .ENV must not receive a secret");

        assert!(matches!(error, SecretFileError::Tracked { .. }), "{error}");
        assert!(error.to_string().contains("rm --cached -- .ENV"), "{error}");
        assert_eq!(
            std::fs::read_to_string(project.path().join(".ENV")).unwrap(),
            "PLACEHOLDER=1\n"
        );
        assert!(!project.path().join(".gitignore").exists());
    }

    #[test]
    fn repository_exclude_leaves_the_shared_gitignore_alone() {
        if !git_available() {
            return;
        }
        let project = repository();
        let member = project.path().join("apps/web");
        std::fs::create_dir_all(&member).unwrap();
        let path = member.join(".env");

        let write = write_secret_file(
            &member,
            &path,
            b"TOKEN=x\n",
            SecretFileOptions {
                ignore_file: IgnoreFile::RepositoryExclude,
                ..PROJECT
            },
        )
        .unwrap();

        let exclude = project.path().join(".git/info/exclude");
        assert!(matches!(write.ignore, SecretIgnore::Added { .. }));
        assert!(
            std::fs::read_to_string(&exclude)
                .unwrap()
                .lines()
                .any(|line| line == "/apps/web/.env")
        );
        assert!(!member.join(".gitignore").exists());
        assert!(!project.path().join(".gitignore").exists());
    }

    #[test]
    fn a_negation_that_wins_refuses_or_warns_as_asked() {
        if !git_available() {
            return;
        }
        let project = repository();
        let config = project.path().join("config");
        std::fs::create_dir(&config).unwrap();
        std::fs::write(config.join(".gitignore"), "!.env\n").unwrap();
        let path = config.join(".env");

        let error = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT)
            .expect_err("an overridden rule must refuse");
        assert!(matches!(error, SecretFileError::Ignore { .. }), "{error}");
        assert!(!path.exists());

        let write = write_secret_file(
            project.path(),
            &path,
            b"TOKEN=x\n",
            SecretFileOptions {
                on_ignore_failure: IgnoreFailure::Warn,
                ..PROJECT
            },
        )
        .unwrap();
        assert!(write.written);
        assert_eq!(write.ignore, SecretIgnore::Failed);
        assert_eq!(write.warnings.len(), 1);
    }

    #[test]
    fn escapes_names_git_would_read_as_patterns() {
        if !git_available() {
            return;
        }
        let project = repository();
        let path = project.path().join("a*b [1] ");

        let write = write_secret_file(project.path(), &path, b"x", PROJECT).unwrap();

        assert!(matches!(write.ignore, SecretIgnore::Added { .. }));
        assert_eq!(
            std::fs::read_to_string(project.path().join(".gitignore")).unwrap(),
            "/a\\*b \\[1]\\ \n"
        );
        assert!(!is_ignored(project.path(), Path::new("aXb [1] ")).unwrap());
    }

    #[test]
    fn outside_the_project_no_ignore_file_is_touched() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = project.path().join("../").join(
            outside
                .path()
                .strip_prefix(project.path().parent().unwrap())
                .unwrap_or(outside.path()),
        );
        let path = absolute_normalized(&path).unwrap().join("ci.env");

        let write = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT).unwrap();

        assert_eq!(write.ignore, SecretIgnore::OutsideProject);
        assert_eq!(mode(&outside.path().join("ci.env")), 0o600);
        assert!(!project.path().join(".gitignore").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_s_inheritable_read_entry_never_reaches_the_secret() {
        let outside = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("group:everyone allow read,file_inherit")
            .arg(outside.path())
            .status()
            .unwrap();
        assert!(status.success());
        let project = tempfile::tempdir().unwrap();

        for (name, existing) in [
            ("replaced.env", Existing::Replace),
            ("kept.env", Existing::Keep),
        ] {
            let path = outside.path().join(name);
            let write = write_secret_file(
                project.path(),
                &path,
                b"TOKEN=x\n",
                SecretFileOptions {
                    existing,
                    ..PROJECT
                },
            )
            .unwrap();

            assert!(write.written, "{name}");
            assert_eq!(mode(&path), 0o600, "{name}");
            let file = std::fs::File::open(&path).unwrap();
            assert!(
                !crate::macos_acl::has_extended_acl(&file).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn a_rewrite_keeps_a_rule_appended_while_it_waited_for_the_lock() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join(".gitignore");
        std::fs::write(&path, "node_modules/\nold-entry\n").unwrap();
        let held = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let lock = crate::acquire_single_file_exclusive_lock_from_file(held).unwrap();
        let (read, was_read) = std::sync::mpsc::channel();

        let rewrite = std::thread::spawn({
            let path = path.clone();
            move || {
                rewrite_ignore_file(&path, |content| {
                    let _ = read.send(());
                    let text = std::str::from_utf8(content).unwrap();
                    text.contains("old-entry")
                        .then(|| text.replace("old-entry\n", "").into_bytes())
                })
            }
        });
        was_read.recv().unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"/.env\n")
            .unwrap();
        drop(lock);

        assert_eq!(rewrite.join().unwrap().unwrap(), IgnoreRewrite::Rewritten);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "node_modules/\n/.env\n"
        );
    }

    #[test]
    fn an_append_follows_an_ignore_file_replaced_while_it_waited() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join(".gitignore");
        std::fs::write(&path, "node_modules/\n").unwrap();
        let held = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let lock = crate::acquire_single_file_exclusive_lock_from_file(held).unwrap();

        let append = std::thread::spawn({
            let project = project.path().to_path_buf();
            move || append_project_rule(&project, "/.env")
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        crate::write_file_atomic(&path, "node_modules/\ndist/\n").unwrap();
        drop(lock);

        append.join().unwrap().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "node_modules/\ndist/\n/.env\n"
        );
    }

    #[test]
    fn a_destination_elsewhere_in_the_repository_is_kept_out_of_git_at_its_root() {
        if !git_available() {
            return;
        }
        let repository = repository();
        let member = repository.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(repository.path().join(".env.shared"), "SHARED=1\n").unwrap();
        let status = hardened_git_command(repository.path(), &["add", ".env.shared"])
            .status()
            .unwrap();
        assert!(status.success());

        let tracked = write_secret_file(
            &member,
            &member.join("../../.env.shared"),
            b"TOKEN=x\n",
            PROJECT,
        );
        assert!(
            matches!(tracked, Err(SecretFileError::Tracked { .. })),
            "{tracked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(repository.path().join(".env.shared")).unwrap(),
            "SHARED=1\n"
        );

        let write = write_secret_file(
            &member,
            &member.join("../../.env.ci"),
            b"TOKEN=x\n",
            PROJECT,
        )
        .unwrap();

        assert!(write.written);
        assert!(
            matches!(write.ignore, SecretIgnore::Added { .. }),
            "{:?}",
            write.ignore
        );
        assert!(
            std::fs::read_to_string(repository.path().join(".gitignore"))
                .unwrap()
                .lines()
                .any(|line| line == "/.env.ci")
        );
        assert!(is_ignored(repository.path(), Path::new(".env.ci")).unwrap());
        assert!(!member.join(".gitignore").exists());

        let sibling = repository.path().join("packages/lib");
        std::fs::create_dir_all(&sibling).unwrap();
        let write = write_secret_file(
            &member,
            &member.join("../lib/.env.lib"),
            b"TOKEN=x\n",
            PROJECT,
        )
        .unwrap();

        assert!(write.written);
        assert!(is_ignored(repository.path(), Path::new("packages/lib/.env.lib")).unwrap());
    }

    #[test]
    fn outside_the_project_a_git_file_git_can_t_follow_is_refused_or_warned_about() {
        if !git_available() {
            return;
        }
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let missing = outside.path().join("moved-away");
        std::fs::write(
            outside.path().join(".git"),
            format!("gitdir: {}\n", missing.display()),
        )
        .unwrap();
        let path = outside.path().join("ci.env");

        let refused = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT);
        assert!(
            matches!(refused, Err(SecretFileError::Ignore { .. })),
            "{refused:?}"
        );
        assert!(!path.exists());
        let kept = keep_secret_file_ignored(
            project.path(),
            &outside.path().join(".git"),
            IgnoreFile::ProjectGitignore,
            IgnoreFailure::Refuse,
        );
        assert!(
            matches!(kept, Err(SecretFileError::Ignore { .. })),
            "{kept:?}"
        );

        let warned = write_secret_file(
            project.path(),
            &path,
            b"TOKEN=x\n",
            SecretFileOptions {
                on_ignore_failure: IgnoreFailure::Warn,
                ..PROJECT
            },
        )
        .unwrap();
        assert!(warned.written);
        assert_eq!(warned.ignore, SecretIgnore::Failed);
        assert_eq!(warned.warnings.len(), 1, "{:?}", warned.warnings);
        assert!(!project.path().join(".gitignore").exists());
    }

    #[test]
    fn outside_a_repository_the_rule_still_lands_in_gitignore() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join(".env");

        let write = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT).unwrap();

        if git_available() {
            assert_eq!(
                write.ignore,
                SecretIgnore::NoRepository {
                    added: Some(project.path().join(".gitignore"))
                }
            );
        }
        assert_eq!(
            std::fs::read_to_string(project.path().join(".gitignore")).unwrap(),
            "/.env\n"
        );
    }

    #[test]
    fn keep_leaves_an_existing_file_and_still_ignores_it() {
        if !git_available() {
            return;
        }
        let project = repository();
        let path = project.path().join(".env");
        std::fs::write(&path, "MINE=1\n").unwrap();

        let write = write_secret_file(
            project.path(),
            &path,
            b"TEMPLATE=1\n",
            SecretFileOptions {
                existing: Existing::Keep,
                ..PROJECT
            },
        )
        .unwrap();

        assert!(!write.written);
        assert!(matches!(write.ignore, SecretIgnore::Added { .. }));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "MINE=1\n");
    }

    #[test]
    fn an_unwritable_gitignore_refuses_in_a_repository_and_warns_outside_one() {
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "outside\n").unwrap();
        let link_gitignore = |project: &Path| {
            std::os::unix::fs::symlink(outside.path(), project.join(".gitignore")).unwrap();
        };

        if git_available() {
            let project = repository();
            link_gitignore(project.path());
            let path = project.path().join(".env");
            let error = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT)
                .expect_err("a repository must keep the secret out of git first");
            assert!(error.to_string().contains(".gitignore"), "{error}");
            assert!(!path.exists());
        }

        let project = tempfile::tempdir().unwrap();
        link_gitignore(project.path());
        let path = project.path().join(".env");
        let write = write_secret_file(project.path(), &path, b"TOKEN=x\n", PROJECT).unwrap();
        assert!(write.written);
        assert_eq!(write.ignore, SecretIgnore::NoRepository { added: None });
        assert!(
            write.warnings[0].contains("before committing"),
            "{:?}",
            write.warnings
        );
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "outside\n"
        );
    }

    #[test]
    fn refuses_to_write_through_a_linked_directory() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("config")).unwrap();

        let error = write_secret_file(
            project.path(),
            &project.path().join("config/.env"),
            b"TOKEN=x\n",
            PROJECT,
        )
        .expect_err("a linked directory must be refused");

        assert!(matches!(error, SecretFileError::Link { .. }), "{error}");
        assert!(!outside.path().join(".env").exists());
    }
}
