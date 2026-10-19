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
use crate::project_git::{
    Found, GitProbeError, Index, disk_spelling, git_failure, indexes_listing, run_git,
};

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
    /// Rules for it were added to `files`, the ignore file of the repository
    /// that holds it first, and git confirmed them.
    Added { files: Vec<PathBuf> },
    /// No git repository holds the project. `added` names the ignore file
    /// that took a rule anyway, so the file stays ignored if one is created.
    NoRepository { added: Option<PathBuf> },
    /// Git could not be run, or couldn't answer where the caller chose to go
    /// on, so nothing was confirmed.
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
    /// `untrack` holds the commands that untrack it, each quoted in
    /// backticks.
    #[error(
        "{path} is tracked by git, so a secret written there would be committed; untrack it with \
         {untrack}, then run the command again"
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
    let in_project = project_relative(project_dir, &path);
    let anchor = ignore_anchor(project_dir, &path, in_project.as_deref());
    // A file in the project is written along its path from the project
    // directory, whichever repository's rules keep it out of git, so a link
    // or a missing directory on the way stops the write there.
    let (walk_root, walk, anchor) = match (in_project, anchor) {
        (Some(relative), anchor) => (project_dir.to_path_buf(), relative, anchor),
        (
            None,
            Anchor::WorkTree {
                root,
                relative,
                git,
            },
        ) => (
            root.clone(),
            relative.clone(),
            Anchor::WorkTree {
                root,
                relative,
                git,
            },
        ),
        (None, Anchor::Outside(outside)) => {
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

    let root =
        Dir::open_ambient_dir(&walk_root, cap_std::ambient_authority()).map_err(|source| {
            SecretFileError::Io {
                path: walk_root.clone(),
                source,
            }
        })?;
    let (parent, name) = open_parent(&root, &walk_root, &walk)?;
    let exists = destination_exists(&parent, name, &path)?;
    let tracked_is_fatal = !(exists && options.existing == Existing::Keep);
    let (ignore, warnings) = match anchor {
        Anchor::WorkTree {
            root,
            relative,
            git,
        } => keep_relative_ignored(
            &root,
            &relative,
            &walk,
            git,
            options.ignore_file,
            options.on_ignore_failure,
            tracked_is_fatal,
        )?,
        Anchor::Outside(outside) => outside.ignore(&path, options.on_ignore_failure)?,
    };
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

/// Makes git ignore `path`, an existing file that holds secrets, where it
/// is once links on the way are followed, as [`write_secret_file`] does
/// before it writes. A file git tracks is reported as a warning: ignoring
/// can't untrack it.
pub fn keep_secret_file_ignored(
    project_dir: &Path,
    path: &Path,
    ignore_file: IgnoreFile,
    on_failure: IgnoreFailure,
) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
    let path = std::fs::canonicalize(path)
        .or_else(|_| absolute_normalized(path))
        .map_err(|source| SecretFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let in_project = project_relative(project_dir, &path);
    match ignore_anchor(project_dir, &path, in_project.as_deref()) {
        Anchor::WorkTree {
            root,
            relative,
            git,
        } => {
            let shown = in_project.as_deref().unwrap_or(&relative);
            keep_relative_ignored(&root, &relative, shown, git, ignore_file, on_failure, false)
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
    let in_project = project_relative(project_dir, &path);
    match ignore_anchor(project_dir, &path, in_project.as_deref()) {
        Anchor::WorkTree {
            root,
            relative,
            git,
        } => {
            let shown = in_project.as_deref().unwrap_or(&relative);
            keep_relative_ignored(&root, &relative, shown, git, ignore_file, on_failure, true)
        }
        Anchor::Outside(outside) => outside.ignore(&path, on_failure),
    }
}

/// Where git's ignore rules for a secret file come from.
enum Anchor {
    /// `root`, the project directory or the root of the git work tree that
    /// holds the file, whose `.gitignore` takes the rule, with the file's
    /// path relative to it, and what git found there.
    WorkTree {
        root: PathBuf,
        relative: PathBuf,
        git: Result<Git, GitProbeError>,
    },
    Outside(Outside),
}

/// What git found for a secret file.
struct Git {
    /// The repository that holds the anchor; `None` when none does.
    repository: Option<Repository>,
    /// Every index that can list the file, the repository's among them.
    indexes: Vec<Index>,
}

struct Repository {
    /// The work tree's root.
    root: PathBuf,
    /// The anchor's path inside the work tree.
    prefix: PathBuf,
    exclude: PathBuf,
}

impl Repository {
    /// The repository of `index`, whose work tree holds the anchor at
    /// `prefix`.
    fn of(index: &Index, prefix: PathBuf) -> Result<Self, GitProbeError> {
        let exclude = index
            .work_tree
            .git_path
            .clone()
            .ok_or_else(|| GitProbeError::Failed("git returned no repository paths".into()))?;
        Ok(Self {
            root: index.work_tree.root.clone(),
            prefix,
            exclude,
        })
    }
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

/// Where git's ignore rules for `path` come from: for `in_project`, its
/// path in `project_dir`, the project, as [`in_project_anchor`] finds them,
/// and else the git work tree that holds `path`, whose root takes the rule.
fn ignore_anchor(project_dir: &Path, path: &Path, in_project: Option<&Path>) -> Anchor {
    match in_project {
        Some(relative) => in_project_anchor(project_dir, relative),
        None => work_tree_anchor(path),
    }
}

/// The anchor for `relative`, a path in `project_dir`: the root of the
/// deepest repository nested in the project that holds it, as one cloned
/// into the project, or a submodule, does, with the rest of `relative`
/// below git's path for that root; else the project directory. Where git
/// can't answer, the nearest directory on the way that holds a `.git` is
/// taken for such a root.
fn in_project_anchor(project_dir: &Path, relative: &Path) -> Anchor {
    let indexes = match indexes_listing(project_dir, &[&portable(relative)], Some("info/exclude")) {
        Ok(indexes) => indexes,
        Err(error) => {
            let (root, relative) = match nested_repository(project_dir, relative) {
                Some(depth) => {
                    let mut components = relative.components();
                    let root =
                        project_dir.join(components.by_ref().take(depth).collect::<PathBuf>());
                    (root, components.collect())
                }
                None => (project_dir.to_path_buf(), relative.to_path_buf()),
            };
            return Anchor::WorkTree {
                root,
                relative,
                git: Err(error),
            };
        }
    };
    let nested = indexes
        .iter()
        .filter_map(|index| match index.found {
            Found::Nested { depth } => Some((depth, index)),
            Found::Holding | Found::Around => None,
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, index)| index);
    let (root, relative, repository) = match nested {
        Some(nested) => (
            nested.work_tree.root.clone(),
            PathBuf::from(&nested.paths[0]),
            Some(Repository::of(nested, PathBuf::new())),
        ),
        None => (
            project_dir.to_path_buf(),
            relative.to_path_buf(),
            indexes
                .iter()
                .find(|index| index.found == Found::Holding)
                .map(|holding| Repository::of(holding, PathBuf::from(&holding.work_tree.prefix))),
        ),
    };
    Anchor::WorkTree {
        root,
        relative,
        git: repository.transpose().map(|repository| Git {
            repository,
            indexes,
        }),
    }
}

/// How many of the leading directories of `relative`, a path in
/// `project_dir`, name the one nearest the path that holds a `.git`.
fn nested_repository(project_dir: &Path, relative: &Path) -> Option<usize> {
    let mut directory = project_dir.to_path_buf();
    let mut nearest = None;
    for (index, component) in relative.parent()?.components().enumerate() {
        directory.push(component);
        if std::fs::symlink_metadata(directory.join(".git")).is_ok() {
            nearest = Some(index + 1);
        }
    }
    nearest
}

/// The anchor in the git work tree that holds the directory of `path`, a
/// path outside the project, as that directory resolves.
fn work_tree_anchor(path: &Path) -> Anchor {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    // A directory that doesn't exist fails the write that follows.
    let Ok(directory) = parent.canonicalize() else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    // A name that isn't UTF-8 is still placed, so a work tree that holds it
    // refuses it for want of an ignore rule.
    let asked: Vec<&str> = name.to_str().into_iter().collect();
    let indexes = match indexes_listing(&directory, &asked, Some("info/exclude")) {
        Ok(indexes) => indexes,
        Err(GitProbeError::GitMissing(reason)) => {
            return Anchor::Outside(Outside::GitMissing(reason));
        }
        Err(GitProbeError::Failed(reason)) => return Anchor::Outside(Outside::Unknown(reason)),
    };
    let Some(holding) = indexes.iter().find(|index| index.found == Found::Holding) else {
        return Anchor::Outside(Outside::NoWorkTree);
    };
    let root = holding.work_tree.root.clone();
    let relative = PathBuf::from(&holding.work_tree.prefix).join(name);
    let repository = Repository::of(holding, PathBuf::new());
    Anchor::WorkTree {
        root,
        relative,
        git: repository.map(|repository| Git {
            repository: Some(repository),
            indexes,
        }),
    }
}

impl SecretIgnore {
    /// The ignore files that took a rule.
    pub fn added_to(&self) -> &[PathBuf] {
        match self {
            Self::Added { files } => files,
            Self::NoRepository { added } | Self::Unverified { added } => {
                added.as_ref().map_or(&[], std::slice::from_ref)
            }
            Self::OutsideProject | Self::AlreadyIgnored | Self::Failed => &[],
        }
    }
}

/// Keeps `relative`, a path below `project_dir`, the anchor whose ignore
/// file takes the rule, out of every index `git` found; `shown` names the
/// file in messages as the caller does.
#[allow(clippy::too_many_arguments)]
fn keep_relative_ignored(
    project_dir: &Path,
    relative: &Path,
    shown: &Path,
    git: Result<Git, GitProbeError>,
    ignore_file: IgnoreFile,
    on_failure: IgnoreFailure,
    tracked_is_fatal: bool,
) -> Result<(SecretIgnore, Vec<String>), SecretFileError> {
    let path = project_dir.join(relative);
    let display = portable(shown);
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
    // Git lists each directory as the disk stores it, which the path given
    // can respell, as `INFRA` or `ſkills` can name `infra/` or `skills/`.
    let spellings = spellings_in(project_dir, relative);
    let rules = match spellings
        .iter()
        .map(|spelling| ignore_rule(spelling))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(rules) => rules,
        Err(reason) => return fail(reason),
    };
    // Where git can't confirm anything, the rule still protects the file
    // once git can read it.
    let unverified = |warning: String| {
        let mut warnings = vec![warning];
        let added = match ignore_file {
            IgnoreFile::ProjectGitignore => {
                let mut added = None;
                for rule in &rules {
                    match append_project_rule(project_dir, rule) {
                        Ok(file) => added = Some(file),
                        Err(error) => {
                            warnings.push(format!(
                                "could not add {display} to {} ({error}); add it before committing",
                                project_dir.join(".gitignore").display()
                            ));
                            break;
                        }
                    }
                }
                added
            }
            IgnoreFile::RepositoryExclude => None,
        };
        (SecretIgnore::Unverified { added }, warnings)
    };

    let git = match git {
        Ok(git) => git,
        Err(GitProbeError::GitMissing(reason)) => {
            return Ok(unverified(format!(
                "git could not be run ({reason}), so LPM could not confirm that git ignores {display}"
            )));
        }
        Err(GitProbeError::Failed(reason)) => {
            return match on_failure {
                IgnoreFailure::Refuse => fail(reason),
                IgnoreFailure::Warn => Ok(unverified(format!(
                    "could not keep {display} out of git ({reason}); make sure it is never committed"
                ))),
            };
        }
    };
    let Some(repository) = git.repository else {
        // No repository can commit the file yet, so a rule that can't be
        // written is a warning wherever the caller would refuse.
        return Ok(match ignore_file {
            IgnoreFile::ProjectGitignore => {
                let mut added = None;
                let mut warnings = Vec::new();
                for rule in &rules {
                    match append_project_rule(project_dir, rule) {
                        Ok(file) => added = Some(file),
                        Err(error) => {
                            warnings.push(format!(
                                "could not add {display} to {} ({error}); add it before committing",
                                project_dir.join(".gitignore").display()
                            ));
                            break;
                        }
                    }
                }
                (SecretIgnore::NoRepository { added }, warnings)
            }
            IgnoreFile::RepositoryExclude => {
                (SecretIgnore::NoRepository { added: None }, Vec::new())
            }
        });
    };

    // The rule only keeps an untracked file out, and an index made before
    // a repository inside its work tree still commits what it lists there.
    let mut untrack = Vec::new();
    let mut warnings = Vec::new();
    for index in &git.indexes {
        match index.tracked() {
            Ok(tracked) if tracked.is_empty() => {}
            Ok(tracked) => untrack.push(format!("`{}`", tracked.untrack_command())),
            Err(error) => match on_failure {
                IgnoreFailure::Refuse => return fail(error.into_reason()),
                IgnoreFailure::Warn => warnings.push(format!(
                    "could not tell whether {} tracks {display} ({}); make sure it doesn't",
                    index.work_tree.root.display(),
                    error.into_reason()
                )),
            },
        }
    }
    if !untrack.is_empty() {
        let untrack = untrack.join(" and ");
        if tracked_is_fatal {
            return Err(SecretFileError::Tracked { path, untrack });
        }
        return Ok((
            SecretIgnore::Failed,
            vec![format!(
                "git tracks {display}, so its secrets will be committed; untrack it with {untrack}"
            )],
        ));
    }
    let overridden = |file: &Path| {
        format!(
            "the rule added to {} is overridden by a later or deeper ignore rule",
            file.display()
        )
    };
    let mut added: Vec<PathBuf> = Vec::new();
    let mut record = |file: PathBuf| {
        if !added.contains(&file) {
            added.push(file);
        }
    };
    let mut gitignore_ruled = false;
    // Every spelling's rule is added before any is checked: git can read one
    // spelling as another, as macOS's reads a decomposed name composed, and
    // then judges it by the other's rule.
    let mut ruled = Vec::new();
    for (spelling, rule) in spellings.iter().zip(&rules) {
        match is_ignored(project_dir, spelling) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(reason) => return fail(reason),
        }
        let appended = match ignore_file {
            IgnoreFile::ProjectGitignore => {
                gitignore_ruled = true;
                append_project_rule(project_dir, rule).map_err(|error| {
                    format!(
                        "could not add it to {}: {error}",
                        project_dir.join(".gitignore").display()
                    )
                })
            }
            IgnoreFile::RepositoryExclude => ignore_rule(&repository.prefix.join(spelling))
                .and_then(|rule| {
                    append_rule_at(&repository.exclude, &rule).map_err(|error| {
                        format!(
                            "could not add it to {}: {error}",
                            repository.exclude.display()
                        )
                    })
                }),
        };
        match appended {
            Ok(file) => ruled.push((spelling, file)),
            Err(reason) => return fail(reason),
        }
    }
    for (spelling, file) in ruled {
        match is_ignored(project_dir, spelling) {
            Ok(true) => record(file),
            Ok(false) => return fail(overridden(&file)),
            Err(reason) => return fail(reason),
        }
    }
    // A repository around the anchor's repository whose index lists files
    // under that repository's root looks inside, so it must ignore the file
    // too. It reads the anchor's `.gitignore` on its way down, but not the
    // anchor's `info/exclude`.
    let depth = repository.prefix.components().count() + relative.components().count();
    for index in git
        .indexes
        .iter()
        .filter(|index| index.work_tree.root != repository.root)
    {
        let Some(inside) = index.paths.first().map(Path::new) else {
            continue;
        };
        let root = &index.work_tree.root;
        let spellings = spellings_in(root, inside);
        // Git walks the directory under the name the disk stores, the last
        // spelling.
        match lists_files_under(root, &spellings[spellings.len() - 1], depth) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(reason) => return fail(reason),
        }
        let mut ruled = Vec::new();
        for spelling in spellings {
            match is_ignored(root, &spelling) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(reason) => return fail(reason),
            }
            let file = match ignore_file {
                IgnoreFile::ProjectGitignore if gitignore_ruled => None,
                IgnoreFile::ProjectGitignore => {
                    gitignore_ruled = true;
                    let mut file = None;
                    for rule in &rules {
                        match append_project_rule(project_dir, rule) {
                            Ok(appended) => file = Some(appended),
                            Err(error) => {
                                return fail(format!(
                                    "could not add it to {}: {error}",
                                    project_dir.join(".gitignore").display()
                                ));
                            }
                        }
                    }
                    file
                }
                IgnoreFile::RepositoryExclude => {
                    let Some(exclude) = &index.work_tree.git_path else {
                        continue;
                    };
                    match ignore_rule(&spelling).and_then(|rule| {
                        append_rule_at(exclude, &rule).map_err(|error| {
                            format!("could not add it to {}: {error}", exclude.display())
                        })
                    }) {
                        Ok(file) => Some(file),
                        Err(reason) => return fail(reason),
                    }
                }
            };
            ruled.push((spelling, file));
        }
        for (spelling, file) in ruled {
            match is_ignored(root, &spelling) {
                Ok(true) => {
                    if let Some(file) = file {
                        record(file);
                    }
                }
                Ok(false) => {
                    return fail(format!(
                        "the repository at {} still doesn't ignore {} once the rule is added",
                        root.display(),
                        portable(&spelling)
                    ));
                }
                Err(reason) => return fail(reason),
            }
        }
    }
    Ok((
        if added.is_empty() {
            SecretIgnore::AlreadyIgnored
        } else {
            SecretIgnore::Added { files: added }
        },
        warnings,
    ))
}

/// `relative`, a path below `root`, and last, where the disk stores a
/// directory on it under another name, the path as git lists it.
fn spellings_in(root: &Path, relative: &Path) -> Vec<PathBuf> {
    let mut spellings = vec![relative.to_path_buf()];
    if let Some(stored) = disk_spelling(root, &portable(relative)).map(PathBuf::from)
        && stored != relative
    {
        spellings.push(stored);
    }
    spellings
}

/// Whether the index of the work tree at `root` lists files in the directory
/// `inside`, a path from that root as the disk stores it, names without its
/// last `depth`, so that git there looks inside it rather than taking it for
/// a repository of its own. Git compares the names as its `core.ignorecase`
/// says. A gitlink at that directory, which a submodule is, is such a
/// repository: git never looks inside one, and refuses to answer for a path
/// in it. A gitlink deeper down is listed in it like a file.
fn lists_files_under(root: &Path, inside: &Path, depth: usize) -> Result<bool, String> {
    let names: Vec<_> = inside.components().collect();
    let directory: PathBuf = names[..names.len().saturating_sub(depth)].iter().collect();
    let directory_depth = directory.components().count();
    if directory_depth == 0 {
        return Ok(true);
    }
    let magic = if crate::project_git::ignores_case(root).map_err(GitProbeError::into_reason)? {
        "literal,icase"
    } else {
        "literal"
    };
    let pathspec = format!(":({magic}){}/", portable(&directory));
    crate::project_git::git_lists_any(
        root,
        &["ls-files", "-z", "--stage", "--", &pathspec],
        |entry| {
            let path = entry
                .splitn(2, |byte| *byte == b'\t')
                .nth(1)
                .unwrap_or_default();
            !(entry.starts_with(GITLINK_MODE)
                && path.split(|byte| *byte == b'/').count() == directory_depth)
        },
    )
    .map_err(GitProbeError::into_reason)
}

/// The mode `git ls-files --stage` gives a gitlink.
const GITLINK_MODE: &[u8] = b"160000 ";

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

/// `path` relative to the project: below the project directory as given
/// or as it resolves, or below a directory on the path that is the project
/// directory by another name, such as a link to it, as the path spells the
/// rest; else below the project as the path's parent resolves. `None`
/// outside it or at its root.
fn project_relative(project_dir: &Path, path: &Path) -> Option<PathBuf> {
    let given = absolute_normalized(project_dir).ok();
    let resolved = std::fs::canonicalize(project_dir).ok();
    let below = |candidate: &Path| {
        [given.as_deref(), resolved.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|root| {
                candidate
                    .strip_prefix(root)
                    .ok()
                    .filter(|relative| !relative.as_os_str().is_empty())
                    .map(Path::to_path_buf)
            })
    };
    if let Some(relative) = below(path) {
        return Some(relative);
    }
    if let Ok(project) = crate::project_git::path_identity(project_dir) {
        // The outermost, should a link in the project lead back to it.
        let outermost = path
            .ancestors()
            .skip(1)
            .filter(|ancestor| {
                crate::project_git::path_identity(ancestor)
                    .is_ok_and(|identity| identity == project)
            })
            .last();
        if let Some(ancestor) = outermost {
            return path.strip_prefix(ancestor).ok().map(Path::to_path_buf);
        }
    }
    let path_resolved = path
        .parent()
        .and_then(|parent| std::fs::canonicalize(parent).ok())
        .zip(path.file_name())
        .map(|(parent, name)| parent.join(name))?;
    below(&path_resolved)
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
                files: vec![project.path().join(".gitignore")]
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
                    files: vec![nested.canonicalize().unwrap().join(".gitignore")]
                },
                "project in git: {project_in_git}"
            );
            assert!(!project.path().join(".gitignore").exists());
        }
    }

    #[test]
    fn a_nested_repository_reached_through_another_spelling_of_the_project_answers_too() {
        if !git_available() {
            return;
        }
        let project = repository();
        let nested = project.path().join("infra");
        std::fs::create_dir(&nested).unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
            &["config", "core.precomposeunicode", "true"],
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
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("project");
        std::os::unix::fs::symlink(project.path(), &alias).unwrap();

        let error = write_secret_file(
            project.path(),
            &alias.join("infra/.env"),
            b"TOKEN=secret\n",
            PROJECT,
        )
        .expect_err("the nested repository tracks the file");

        assert!(matches!(error, SecretFileError::Tracked { .. }), "{error}");
        assert_eq!(
            std::fs::read_to_string(nested.join(".env")).unwrap(),
            "TOKEN=\n"
        );
    }

    fn nested_repository_in(project: &Path) -> PathBuf {
        let nested = project.join("infra");
        std::fs::create_dir_all(nested.join("sub")).unwrap();
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
        nested
    }

    #[test]
    fn a_secret_under_a_nested_repository_goes_where_its_path_says_or_nowhere() {
        if !git_available() {
            return;
        }
        let project = repository();
        let nested = nested_repository_in(project.path());
        std::fs::write(nested.join(".env"), "API_KEY=nested\n").unwrap();
        std::fs::create_dir(project.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink("../elsewhere", nested.join("link")).unwrap();
        std::os::unix::fs::symlink("sub", nested.join("sublink")).unwrap();

        let missing = write_secret_file(
            project.path(),
            &nested.join("missing/.env"),
            b"API_KEY=project\n",
            PROJECT,
        )
        .expect_err("a directory that doesn't exist takes no secret");
        assert!(matches!(missing, SecretFileError::Io { .. }), "{missing}");
        for linked in ["link", "sublink"] {
            let error = write_secret_file(
                project.path(),
                &nested.join(linked).join(".env"),
                b"API_KEY=project\n",
                PROJECT,
            )
            .expect_err("a secret doesn't go through a link");
            assert!(
                matches!(error, SecretFileError::Link { .. }),
                "{linked}: {error}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(nested.join(".env")).unwrap(),
            "API_KEY=nested\n"
        );
        assert!(!nested.join(".gitignore").exists());
        assert!(!nested.join("sub/.env").exists());
        assert!(!project.path().join("elsewhere/.env").exists());

        let write = write_secret_file(
            project.path(),
            &nested.join("sub/.env"),
            b"API_KEY=project\n",
            PROJECT,
        )
        .unwrap();
        assert_eq!(
            write.ignore,
            SecretIgnore::Added {
                files: vec![nested.canonicalize().unwrap().join(".gitignore")]
            }
        );
        assert_eq!(
            std::fs::read_to_string(nested.join(".gitignore")).unwrap(),
            "/sub/.env\n"
        );
        assert_eq!(
            std::fs::read_to_string(nested.join("sub/.env")).unwrap(),
            "API_KEY=project\n"
        );
    }

    #[test]
    fn a_file_the_project_s_index_lists_under_a_nested_repository_takes_no_secret() {
        if !git_available() {
            return;
        }
        let project = repository();
        std::fs::create_dir(project.path().join("infra")).unwrap();
        std::fs::write(project.path().join("infra/.env"), "TOKEN=\n").unwrap();
        assert!(
            hardened_git_command(project.path(), &["add", "infra/.env"])
                .status()
                .unwrap()
                .success()
        );
        let nested = nested_repository_in(project.path());

        let error = write_secret_file(
            project.path(),
            &nested.join(".env"),
            b"TOKEN=secret\n",
            PROJECT,
        )
        .expect_err("the project's index still lists the file");

        assert!(matches!(error, SecretFileError::Tracked { .. }), "{error}");
        assert!(
            error.to_string().contains(" rm --cached -- infra/.env`"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(nested.join(".env")).unwrap(),
            "TOKEN=\n"
        );
        assert!(!nested.join(".gitignore").exists());
    }

    #[test]
    fn a_file_the_index_around_the_project_s_repository_lists_takes_no_secret() {
        if !git_available() {
            return;
        }
        let outer = repository();
        let project = outer.path().join("app");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join(".env"), "TOKEN=\n").unwrap();
        assert!(
            hardened_git_command(outer.path(), &["add", "app/.env"])
                .status()
                .unwrap()
                .success()
        );
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
        ] {
            assert!(
                hardened_git_command(&project, args)
                    .status()
                    .unwrap()
                    .success()
            );
        }

        let error = write_secret_file(&project, &project.join(".env"), b"TOKEN=secret\n", PROJECT)
            .expect_err("the outer index still lists the file");

        assert!(matches!(error, SecretFileError::Tracked { .. }), "{error}");
        assert!(
            error.to_string().contains(" rm --cached -- app/.env`"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(project.join(".env")).unwrap(),
            "TOKEN=\n"
        );
    }

    /// A repository at `inner`, inside `outer`'s work tree, whose index
    /// still lists a file there from before `inner` was made.
    fn repository_made_inside_a_listed_directory(outer: &Path, inner: &str) -> PathBuf {
        let inner = outer.join(inner);
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("README"), "readme\n").unwrap();
        let relative = inner.strip_prefix(outer).unwrap().join("README");
        assert!(
            hardened_git_command(outer, &["add", "--", relative.to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
        ] {
            assert!(
                hardened_git_command(&inner, args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        inner
    }

    #[test]
    fn a_ci_secret_is_kept_out_of_every_index_that_lists_its_directory() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        // The project's index lists a file under a repository nested in it.
        let project = repository();
        let nested = repository_made_inside_a_listed_directory(project.path(), "infra");
        let write =
            write_secret_file(project.path(), &nested.join(".env.ci"), b"TOKEN=x\n", CI).unwrap();
        assert!(
            matches!(&write.ignore, SecretIgnore::Added { files } if files.len() == 2),
            "{:?}",
            write.ignore
        );
        assert!(is_ignored(project.path(), Path::new("infra/.env.ci")).unwrap());
        assert!(is_ignored(&nested, Path::new(".env.ci")).unwrap());

        // An index around the project's repository lists a file in it.
        let outer = repository();
        let app = repository_made_inside_a_listed_directory(outer.path(), "app");
        write_secret_file(&app, &app.join(".env.ci"), b"TOKEN=x\n", CI).unwrap();
        assert!(is_ignored(outer.path(), Path::new("app/.env.ci")).unwrap());
        assert!(is_ignored(&app, Path::new(".env.ci")).unwrap());
    }

    #[test]
    fn a_secret_in_a_repository_its_superproject_records_as_a_gitlink_is_written() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        // The superproject records `sub` as a gitlink, as `git submodule add`
        // does, and never looks inside it.
        let superproject = repository();
        let sub = superproject.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("README"), "readme\n").unwrap();
        for (directory, args) in [
            (sub.as_path(), &["init", "-q"][..]),
            (&sub, &["config", "core.excludesFile", "/dev/null"]),
            (&sub, &["add", "README"]),
            (
                &sub,
                &[
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.test",
                    "commit",
                    "-q",
                    "-m",
                    "x",
                ],
            ),
            (superproject.path(), &["add", "sub"]),
        ] {
            assert!(
                hardened_git_command(directory, args)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "git {args:?}"
            );
        }
        for (options, name) in [(PROJECT, ".env"), (CI, ".env.ci")] {
            write_secret_file(&sub, &sub.join(name), b"TOKEN=x\n", options)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(is_ignored(&sub, Path::new(name)).unwrap(), "{name}");

            let from_above = format!("{name}.above");
            write_secret_file(
                superproject.path(),
                &sub.join(&from_above),
                b"TOKEN=x\n",
                options,
            )
            .unwrap_or_else(|error| panic!("{from_above}: {error}"));
            assert!(
                is_ignored(&sub, Path::new(&from_above)).unwrap(),
                "{from_above}"
            );
        }
    }

    #[test]
    fn a_gitlink_below_a_listed_directory_still_has_its_index_look_inside() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        for (options, name) in [(CI, ".env.ci"), (PROJECT, ".env")] {
            // The outer index records only `app/sub`, a gitlink, below `app/`,
            // so git still looks inside `app/` once it is a repository.
            let outer = repository();
            let sub = outer.path().join("app/sub");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("README"), "readme\n").unwrap();
            for (directory, args) in [
                (sub.as_path(), &["init", "-q"][..]),
                (&sub, &["add", "README"]),
                (
                    &sub,
                    &[
                        "-c",
                        "user.name=t",
                        "-c",
                        "user.email=t@example.test",
                        "commit",
                        "-q",
                        "-m",
                        "x",
                    ],
                ),
                (outer.path(), &["add", "app/sub"]),
            ] {
                assert!(
                    hardened_git_command(directory, args)
                        .output()
                        .unwrap()
                        .status
                        .success(),
                    "git {args:?}"
                );
            }
            let app = outer.path().join("app");
            for args in [
                &["init", "-q"][..],
                &["config", "core.excludesFile", "/dev/null"],
            ] {
                assert!(hardened_git_command(&app, args).status().unwrap().success());
            }
            // The app's own exclude already ignores it, as one written earlier.
            std::fs::write(app.join(".git/info/exclude"), format!("/{name}\n")).unwrap();

            write_secret_file(&app, &app.join(name), b"TOKEN=x\n", options).unwrap();

            assert!(
                is_ignored(outer.path(), &Path::new("app").join(name)).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn a_submodule_s_secret_is_judged_by_the_superproject_as_git_compares_names() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        for ignorecase in ["false", "true"] {
            for (options, name) in [(PROJECT, ".env"), (CI, ".env.ci")] {
                // The superproject records `app` as a gitlink and also lists
                // `APP/README`, which is another directory where git compares
                // case, and `app` itself where it ignores case.
                let superproject = repository();
                let app = superproject.path().join("app");
                std::fs::create_dir(&app).unwrap();
                std::fs::write(app.join("README"), "readme\n").unwrap();
                for (directory, args) in [
                    (app.as_path(), &["init", "-q"][..]),
                    (&app, &["config", "core.excludesFile", "/dev/null"]),
                    (&app, &["add", "README"]),
                    (
                        &app,
                        &[
                            "-c",
                            "user.name=t",
                            "-c",
                            "user.email=t@example.test",
                            "commit",
                            "-q",
                            "-m",
                            "x",
                        ],
                    ),
                    (superproject.path(), &["add", "app"]),
                    (
                        superproject.path(),
                        &["config", "core.ignorecase", ignorecase],
                    ),
                ] {
                    assert!(
                        hardened_git_command(directory, args)
                            .output()
                            .unwrap()
                            .status
                            .success(),
                        "git {args:?}"
                    );
                }
                let blob =
                    hardened_git_command(superproject.path(), &["hash-object", "-w", "app/README"])
                        .output()
                        .unwrap();
                assert!(blob.status.success());
                let cacheinfo = format!(
                    "100644,{},APP/README",
                    String::from_utf8(blob.stdout).unwrap().trim()
                );
                assert!(
                    hardened_git_command(
                        superproject.path(),
                        &["update-index", "--add", "--cacheinfo", &cacheinfo],
                    )
                    .status()
                    .unwrap()
                    .success()
                );

                let written = write_secret_file(&app, &app.join(name), b"TOKEN=x\n", options);

                if ignorecase == "false" {
                    // Git never looks inside the submodule.
                    written.unwrap_or_else(|error| panic!("{name}: {error}"));
                    assert!(is_ignored(&app, Path::new(name)).unwrap(), "{name}");
                } else {
                    // Git walks into `app` and would commit the file there,
                    // and can't say whether it ignores it.
                    assert!(written.is_err(), "{name}");
                    assert!(!app.join(name).exists(), "{name}");
                }
            }
        }
    }

    #[test]
    fn a_secret_in_a_package_below_a_nested_repository_is_kept_out_of_the_index_around_it() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        for (options, name) in [(CI, ".env.ci"), (PROJECT, ".env")] {
            // The outer index lists `app/README` from before `app` was a
            // repository, and nothing in the package below it.
            let outer = repository();
            let app = repository_made_inside_a_listed_directory(outer.path(), "app");
            let web = app.join("packages/web");
            std::fs::create_dir_all(&web).unwrap();
            std::fs::write(
                app.join(".git/info/exclude"),
                format!("/packages/web/{name}\n"),
            )
            .unwrap();

            write_secret_file(&web, &web.join(name), b"TOKEN=x\n", options).unwrap();

            assert!(
                is_ignored(outer.path(), &Path::new("app/packages/web").join(name)).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn an_index_around_is_asked_under_the_name_git_lists_for_a_respelled_repository() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        // The project's index lists `sub/README` from before `sub` was a
        // repository; the path names `sub` with `ſ`, which git's
        // case-insensitive matching doesn't fold.
        let project = repository();
        let sub = repository_made_inside_a_listed_directory(project.path(), "sub");
        if !project.path().join("\u{17F}ub").exists() {
            return;
        }

        write_secret_file(
            project.path(),
            &project.path().join("\u{17F}ub/.env.ci"),
            b"TOKEN=x\n",
            CI,
        )
        .unwrap();

        assert!(is_ignored(project.path(), Path::new("sub/.env.ci")).unwrap());
        assert!(is_ignored(&sub, Path::new(".env.ci")).unwrap());
    }

    #[test]
    fn a_secret_s_rule_covers_the_name_git_lists_for_a_respelled_directory() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        for options in [PROJECT, CI] {
            let project = repository();
            std::fs::create_dir(project.path().join("skills")).unwrap();
            // `ſ` reaches `skills/` only where the disk folds case beyond
            // ASCII; git lists the directory as the disk stores it.
            if !project.path().join("\u{17F}kills").exists() {
                return;
            }
            write_secret_file(
                project.path(),
                &project.path().join("\u{17F}kills/export.env"),
                b"TOKEN=x\n",
                options,
            )
            .unwrap();
            assert!(
                is_ignored(project.path(), Path::new("skills/export.env")).unwrap(),
                "{options:?}"
            );

            // ASCII case where git compares case.
            std::fs::create_dir(project.path().join("infra")).unwrap();
            assert!(
                hardened_git_command(project.path(), &["config", "core.ignorecase", "false"])
                    .status()
                    .unwrap()
                    .success()
            );
            write_secret_file(
                project.path(),
                &project.path().join("INFRA/export.env"),
                b"TOKEN=x\n",
                options,
            )
            .unwrap();
            assert!(
                is_ignored(project.path(), Path::new("infra/export.env")).unwrap(),
                "{options:?}"
            );
        }
    }

    #[test]
    fn a_secret_named_through_a_decomposed_directory_is_kept_out_where_git_composes_names() {
        if !git_available() {
            return;
        }
        const CI: SecretFileOptions = SecretFileOptions {
            ignore_file: IgnoreFile::RepositoryExclude,
            ..PROJECT
        };
        let composed = "caf\u{e9}";
        let decomposed = "cafe\u{301}";
        for (options, name) in [(PROJECT, ".env"), (CI, ".env.ci")] {
            // The directory is stored composed and named decomposed; git, as
            // on macOS, reads a name it is given composed.
            let project = repository();
            std::fs::create_dir(project.path().join(composed)).unwrap();
            if !project.path().join(decomposed).exists() {
                return;
            }
            assert!(
                hardened_git_command(
                    project.path(),
                    &["config", "core.precomposeunicode", "true"]
                )
                .status()
                .unwrap()
                .success()
            );
            write_secret_file(
                project.path(),
                &project.path().join(decomposed).join(name),
                b"TOKEN=x\n",
                options,
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(
                is_ignored(project.path(), &Path::new(composed).join(name)).unwrap(),
                "{name}"
            );

            // A repository in it, which the project's index lists files in.
            let outer = repository();
            let nested = repository_made_inside_a_listed_directory(outer.path(), composed);
            for directory in [outer.path(), nested.as_path()] {
                assert!(
                    hardened_git_command(directory, &["config", "core.precomposeunicode", "true"])
                        .status()
                        .unwrap()
                        .success()
                );
            }
            write_secret_file(
                outer.path(),
                &outer.path().join(decomposed).join(name),
                b"TOKEN=x\n",
                options,
            )
            .unwrap_or_else(|error| panic!("nested {name}: {error}"));
            assert!(
                is_ignored(outer.path(), &Path::new(composed).join(name)).unwrap(),
                "nested {name}"
            );
        }
    }

    #[test]
    fn a_secret_its_repository_excludes_is_kept_out_of_the_index_around_it_too() {
        if !git_available() {
            return;
        }
        let outer = repository();
        let app = repository_made_inside_a_listed_directory(outer.path(), "app");
        std::fs::write(app.join(".git/info/exclude"), "/.env\n").unwrap();

        write_secret_file(&app, &app.join(".env"), b"TOKEN=x\n", PROJECT).unwrap();

        assert!(is_ignored(outer.path(), Path::new("app/.env")).unwrap());
        assert!(is_ignored(&app, Path::new(".env")).unwrap());
    }

    #[test]
    fn a_bare_repository_above_a_worktree_inside_it_is_no_index_to_ask() {
        if !git_available() {
            return;
        }
        // A repository above, as a home directory can be, and a bare clone
        // whose worktree lives inside it.
        let home = repository();
        let source = repository();
        std::fs::write(source.path().join("README"), "readme\n").unwrap();
        for args in [
            &["add", "README"][..],
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.test",
                "commit",
                "-q",
                "-m",
                "x",
            ],
        ] {
            assert!(
                hardened_git_command(source.path(), args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let bare = home.path().join("app.git");
        assert!(
            std::process::Command::new("git")
                .args(["clone", "-q", "--bare"])
                .arg(source.path())
                .arg(&bare)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap()
                .success()
        );
        assert!(
            hardened_git_command(
                &bare,
                &[
                    "-c",
                    "safe.bareRepository=all",
                    "worktree",
                    "add",
                    "-q",
                    "main"
                ]
            )
            .status()
            .unwrap()
            .success()
        );
        let worktree = bare.join("main");

        let write = write_secret_file(&worktree, &worktree.join(".env"), b"TOKEN=x\n", PROJECT)
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            matches!(write.ignore, SecretIgnore::Added { .. }),
            "{:?}",
            write.ignore
        );
        assert!(is_ignored(&worktree, Path::new(".env")).unwrap());
    }

    #[test]
    fn an_index_above_a_bare_repository_s_git_file_is_still_asked() {
        if !git_available() {
            return;
        }
        // The outer index lists `p/main/.env` from before `p` held a bare
        // repository, which `p/.git` points to, and its worktree `p/main`.
        let outer = repository();
        let parent = outer.path().join("p");
        std::fs::create_dir_all(parent.join("main")).unwrap();
        std::fs::write(parent.join("main/.env"), "TOKEN=old\n").unwrap();
        assert!(
            hardened_git_command(outer.path(), &["add", "--", "p/main/.env"])
                .status()
                .unwrap()
                .success()
        );
        std::fs::remove_dir_all(parent.join("main")).unwrap();
        let source = repository();
        std::fs::write(source.path().join("README"), "readme\n").unwrap();
        for args in [
            &["add", "README"][..],
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.test",
                "commit",
                "-q",
                "-m",
                "x",
            ],
        ] {
            assert!(
                hardened_git_command(source.path(), args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert!(
            std::process::Command::new("git")
                .args(["clone", "-q", "--bare"])
                .arg(source.path())
                .arg(parent.join(".bare"))
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(parent.join(".git"), "gitdir: ./.bare\n").unwrap();
        assert!(
            hardened_git_command(
                &parent.join(".bare"),
                &[
                    "-c",
                    "safe.bareRepository=all",
                    "worktree",
                    "add",
                    "-q",
                    "../main"
                ]
            )
            .status()
            .unwrap()
            .success()
        );
        let worktree = parent.join("main");

        let error = write_secret_file(&worktree, &worktree.join(".env"), b"TOKEN=x\n", PROJECT)
            .unwrap_err();

        let SecretFileError::Tracked { untrack, .. } = &error else {
            panic!("{error}");
        };
        assert!(untrack.contains("p/main/.env"), "{untrack}");
    }

    #[test]
    fn a_rule_is_still_added_where_a_warning_stands_for_an_index_git_cant_ask() {
        if !git_available() {
            return;
        }
        // A `.git` file above the project's repository that points nowhere.
        let outer = tempfile::tempdir().unwrap();
        std::fs::write(
            outer.path().join(".git"),
            "gitdir: /nonexistent/repository\n",
        )
        .unwrap();
        let project = outer.path().join("app");
        std::fs::create_dir(&project).unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "core.excludesFile", "/dev/null"],
        ] {
            assert!(
                hardened_git_command(&project, args)
                    .status()
                    .unwrap()
                    .success()
            );
        }

        let refused = write_secret_file(&project, &project.join(".env"), b"TOKEN=x\n", PROJECT);
        assert!(
            matches!(refused, Err(SecretFileError::Ignore { .. })),
            "{refused:?}"
        );
        assert!(!project.join(".env").exists());

        let warned = write_secret_file(
            &project,
            &project.join(".env"),
            b"TOKEN=x\n",
            SecretFileOptions {
                on_ignore_failure: IgnoreFailure::Warn,
                ..PROJECT
            },
        )
        .unwrap();
        assert_eq!(warned.ignore.added_to(), [project.join(".gitignore")]);
        assert!(!warned.warnings.is_empty());
        assert_eq!(
            std::fs::read_to_string(project.join(".gitignore")).unwrap(),
            "/.env\n"
        );
    }

    #[test]
    fn a_link_at_the_destination_is_checked_as_the_link_not_as_what_it_leads_to() {
        if !git_available() {
            return;
        }
        let project = repository();
        for (link, target) in [
            (".env", ".env.development"),
            ("secrets.env", "secret-dev.env"),
        ] {
            std::fs::write(project.path().join(target), "DEFAULT=1\n").unwrap();
            assert!(
                hardened_git_command(project.path(), &["add", target])
                    .status()
                    .unwrap()
                    .success()
            );
            std::os::unix::fs::symlink(target, project.path().join(link)).unwrap();

            let write = write_secret_file(
                project.path(),
                &project.path().join(link),
                b"TOKEN=secret\n",
                PROJECT,
            )
            .unwrap_or_else(|error| panic!("{link}: {error}"));

            assert!(write.written);
            assert!(
                !std::fs::symlink_metadata(project.path().join(link))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(
                std::fs::read_to_string(project.path().join(link)).unwrap(),
                "TOKEN=secret\n"
            );
            assert_eq!(
                std::fs::read_to_string(project.path().join(target)).unwrap(),
                "DEFAULT=1\n"
            );
        }

        std::os::unix::fs::symlink(".env.development", project.path().join(".env.linked")).unwrap();
        assert!(
            hardened_git_command(project.path(), &["add", ".env.linked"])
                .status()
                .unwrap()
                .success()
        );
        let error = write_secret_file(
            project.path(),
            &project.path().join(".env.linked"),
            b"TOKEN=secret\n",
            PROJECT,
        )
        .expect_err("git tracks the link");
        let message = error.to_string();
        assert!(
            matches!(error, SecretFileError::Tracked { .. }),
            "{message}"
        );
        assert!(
            message.contains(" rm --cached -- .env.linked`")
                && !message.contains(".env.development"),
            "{message}"
        );
    }

    #[test]
    fn a_path_through_another_spelling_of_the_project_meets_the_project_s_link_refusal() {
        if !git_available() {
            return;
        }
        let project = repository();
        std::fs::create_dir(project.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", project.path().join("linked")).unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("project");
        std::os::unix::fs::symlink(project.path(), &alias).unwrap();

        let error = write_secret_file(
            project.path(),
            &alias.join("linked/.env"),
            b"TOKEN=secret\n",
            PROJECT,
        )
        .expect_err("a secret doesn't go through a link in the project");

        assert!(matches!(error, SecretFileError::Link { .. }), "{error}");
        assert!(!project.path().join("real/.env").exists());
        assert!(!project.path().join(".gitignore").exists());
    }

    #[test]
    fn an_imported_file_reached_through_a_link_is_ignored_where_it_is() {
        if !git_available() {
            return;
        }
        let project = repository();
        let nested = nested_repository_in(project.path());
        std::os::unix::fs::symlink("sub", nested.join("sublink")).unwrap();
        std::fs::write(nested.join("sub/.env"), "API_KEY=x\n").unwrap();
        std::fs::create_dir(project.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", project.path().join("linked")).unwrap();
        std::fs::write(project.path().join("real/.env"), "API_KEY=x\n").unwrap();

        for (source, ignore_file, rule) in [
            (
                nested.join("sublink/.env"),
                nested.join(".gitignore"),
                "/sub/.env\n",
            ),
            (
                project.path().join("linked/.env"),
                project.path().join(".gitignore"),
                "/real/.env\n",
            ),
        ] {
            keep_secret_file_ignored(
                project.path(),
                &source,
                IgnoreFile::ProjectGitignore,
                IgnoreFailure::Refuse,
            )
            .unwrap();

            assert_eq!(
                std::fs::read_to_string(&ignore_file).unwrap(),
                rule,
                "{}",
                source.display()
            );
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
