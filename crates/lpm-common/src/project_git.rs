use std::path::{Path, PathBuf};

/// A git command for a project that may be untrusted: no `GIT_*` variable
/// from the environment, no `core.fsmonitor` program, which reading the
/// index would run, and no repository found as a bare one, which a cloned
/// project can contain with its own config.
pub fn hardened_git_command(project_dir: &Path, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "safe.bareRepository=explicit",
        ])
        .args(args)
        .current_dir(project_dir)
        .env("LC_ALL", "C");
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GIT_"))
        {
            command.env_remove(name);
        }
    }
    command
}

/// Why git found no repository to answer from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitDiscoveryFailure {
    /// Git found no repository there or in any directory above.
    NoRepository,
    /// Git stopped looking before it found one: at a filesystem boundary,
    /// or at a `.git` file that doesn't point at a repository, which no git
    /// command there gets past. A repository above can still hold the
    /// directory.
    Stopped,
    /// Git refused, for a repository it won't use, such as one another user
    /// owns, or failed for another reason.
    Refused,
}

/// How git's `fatal: ` line starts, with `LC_ALL=C`, where it found no
/// repository, and where it stopped looking. Git 2.56 reports a `.git` file
/// pointing at no repository as "gitfile does not point to a valid
/// repository: <file>"; earlier releases as "not a git repository: <target>".
const NO_REPOSITORY_MESSAGE: &str = "not a git repository (or any of the parent directories)";
const STOPPED_MESSAGES: [&str; 6] = [
    "not a git repository (or any parent up to mount",
    "not a git repository: ",
    "gitfile does not point to a valid repository",
    "invalid gitfile format",
    "no path in gitfile",
    "too large to be a .git file",
];

/// Reads git's failure from the start of its `fatal: ` line, as the rest can
/// quote a path, and without regard to case, as releases before 2.17 write
/// "Not a git repository".
pub fn git_discovery_failure(stderr: &[u8]) -> GitDiscoveryFailure {
    let message = String::from_utf8_lossy(stderr);
    for line in message.lines() {
        let Some(reason) = line.strip_prefix("fatal: ") else {
            continue;
        };
        let starts = |start: &str| {
            reason
                .get(..start.len())
                .is_some_and(|text| text.eq_ignore_ascii_case(start))
        };
        if starts(NO_REPOSITORY_MESSAGE) {
            return GitDiscoveryFailure::NoRepository;
        }
        if STOPPED_MESSAGES.into_iter().any(starts) || unreadable_git_file(reason, starts) {
            return GitDiscoveryFailure::Stopped;
        }
    }
    GitDiscoveryFailure::Refused
}

/// Whether git's `fatal: ` line says it couldn't open or read a `.git`
/// file, which it names: "error opening '<path>'" and "error reading
/// <path>", told from git's other errors that start the same way, such as
/// "error reading from <file>", by the name.
fn unreadable_git_file(reason: &str, starts: impl Fn(&str) -> bool) -> bool {
    let names_a_git_file = |path: &str| path.ends_with("/.git") || path == ".git";
    if starts("error opening '") {
        // The path is quoted, then ": " and the system's error; the path
        // itself can hold a quote.
        return reason["error opening '".len()..]
            .rsplit_once("': ")
            .is_some_and(|(path, _)| names_a_git_file(path));
    }
    starts("error reading ") && names_a_git_file(reason["error reading ".len()..].trim_end())
}

/// Why git couldn't answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitProbeError {
    /// Git could not be run.
    GitMissing(String),
    /// Git ran but could not answer.
    Failed(String),
}

impl GitProbeError {
    pub fn into_reason(self) -> String {
        match self {
            Self::GitMissing(reason) | Self::Failed(reason) => reason,
        }
    }
}

impl std::fmt::Display for GitProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitMissing(reason) => write!(formatter, "git could not be run ({reason})"),
            Self::Failed(reason) => formatter.write_str(reason),
        }
    }
}

/// Runs a [`hardened_git_command`] in `dir` to completion, with no input.
pub fn run_git(dir: &Path, args: &[&str]) -> Result<std::process::Output, GitProbeError> {
    probe_command(dir, args)
        .output()
        .map_err(|error| match error.kind() {
            // Spawning in a directory that is gone fails the same way.
            std::io::ErrorKind::NotFound if !dir.is_dir() => GitProbeError::Failed(format!(
                "git could not run in {}, which is not a directory",
                dir.display()
            )),
            std::io::ErrorKind::NotFound => GitProbeError::GitMissing(error.to_string()),
            _ => GitProbeError::Failed(format!("failed to run git: {error}")),
        })
}

fn probe_command(dir: &Path, args: &[&str]) -> std::process::Command {
    let mut command = hardened_git_command(dir, args);
    // A repository above a mounted project directory can still track it.
    command.env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "1");
    command.stdin(std::process::Stdio::null());
    command
}

/// Git's error output, made safe to print on one line.
pub fn git_failure(output: &std::process::Output) -> String {
    crate::sanitize_terminal_inline(String::from_utf8_lossy(&output.stderr).trim()).into_owned()
}

/// Whether `dir` is in a git work tree; failing to tell is an error, as a
/// repository git stopped short of can still hold it.
pub fn inside_work_tree(dir: &Path) -> Result<bool, GitProbeError> {
    let inside = run_git(dir, &["rev-parse", "--is-inside-work-tree"])?;
    if !inside.status.success() {
        return match discovery_failure(&inside) {
            Some(reason) => Err(GitProbeError::Failed(reason)),
            None => Ok(false),
        };
    }
    Ok(inside.stdout.trim_ascii() == b"true")
}

/// Whether `dir` or a directory above it holds a `.git`, which marks a
/// repository: where git can't be run, a reason to treat git as unable to
/// answer rather than as having found no repository.
pub fn repository_marker_above(dir: &Path) -> bool {
    std::path::absolute(dir)
        .unwrap_or_else(|_| dir.to_path_buf())
        .ancestors()
        .any(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
}

/// The bytes git's index holds at stage 0 for `entry`, a path relative to
/// the work tree `root`, as stored: no filter or conversion runs. Fails for
/// an entry with conflicts, which has no stage 0, and past `limit` bytes.
pub fn indexed_blob(root: &Path, entry: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    let object = format!(":0:{entry}");
    let mut command = probe_command(root, &["cat-file", "blob", &object]);
    let output = crate::process_output::output_capped(&mut command, TIMEOUT, limit)?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "git could not read {entry} from the index"
        )));
    }
    Ok(output.stdout)
}

/// Why git found no repository, or `None` when it found that none holds the
/// directory.
fn discovery_failure(output: &std::process::Output) -> Option<String> {
    match git_discovery_failure(&output.stderr) {
        GitDiscoveryFailure::NoRepository if output.status.code() == Some(128) => None,
        GitDiscoveryFailure::Stopped => Some(format!(
            "git stopped at a .git file it can't use ({})",
            git_failure(output)
        )),
        _ => Some(git_failure(output)),
    }
}

/// What git's index tracks at some paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    /// The root of the work tree, which `entries` are relative to.
    pub root: PathBuf,
    /// The tracked files, spelled as the index spells them.
    pub entries: Vec<String>,
    /// For each entry, the start of it that spells the path it was found
    /// for, so a recursive removal takes nothing beyond that path.
    spellings: Vec<String>,
}

/// The index entries git takes for `paths`, each relative to `dir` and
/// spelled with `/`: the file at the path, or every file under it. `None`
/// when no git work tree holds `dir`.
///
/// The index can spell a path otherwise, in its file name or in a directory
/// above it, with another case, with a character a filesystem takes for
/// one in the path, such as `ſ` for `s`, or with an NTFS short name. Such
/// an entry counts when it is the very file the path names on disk, or
/// would be once what is missing below their deepest existing directory is
/// created there, whatever `core.ignorecase` says; when the missing names
/// differ only in case, it counts where `core.ignorecase` is set, as git
/// then commits a file written there as that entry.
pub fn tracked_entries(dir: &Path, paths: &[&str]) -> Result<Option<Tracked>, GitProbeError> {
    let Some((root, prefix)) = work_tree_location(dir)? else {
        return Ok(None);
    };
    let queried: Vec<String> = paths
        .iter()
        .map(|path| format!("{prefix}{}", path.trim_end_matches('/')))
        .collect();
    // NTFS also resolves a name's 8.3 short form, such as `LPM~1` for
    // `.lpm`, so any entry with a `~` in a name can be the same file.
    let short_names: &[&str] = if cfg!(windows) {
        &[":(glob)**/*~*", ":(glob)**/*~*/**"]
    } else {
        &[]
    };
    let pathspecs: Vec<String> = queried
        .iter()
        .flat_map(|path| candidate_pathspecs(path))
        .chain(short_names.iter().map(|pathspec| (*pathspec).to_owned()))
        .collect();
    let mut args = Vec::with_capacity(pathspecs.len() + 4);
    args.extend(["ls-files", "-z", "--cached", "--"]);
    args.extend(pathspecs.iter().map(String::as_str));
    let listed = run_git(&root, &args)?;
    if !listed.status.success() {
        return Err(GitProbeError::Failed(git_failure(&listed)));
    }
    let mut decided: std::collections::HashMap<(String, usize), bool> =
        std::collections::HashMap::new();
    let mut ignores_case_setting = None;
    let mut tracked = Tracked {
        root,
        entries: Vec::new(),
        spellings: Vec::new(),
    };
    for entry in listed.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let entry = String::from_utf8_lossy(entry).into_owned();
        for (index, path) in queried.iter().enumerate() {
            let Some(spelling) = leading_components(&entry, path.split('/').count()) else {
                continue;
            };
            let counts = if spelling == path {
                true
            } else if let Some(&counts) = decided.get(&(spelling.to_owned(), index)) {
                counts
            } else {
                let counts = match aliases(&tracked.root, spelling, path)? {
                    Some(same) => same,
                    None => {
                        fold_case(spelling) == fold_case(path)
                            && *match &ignores_case_setting {
                                Some(setting) => setting,
                                None => ignores_case_setting.insert(ignores_case(&tracked.root)?),
                            }
                    }
                };
                decided.insert((spelling.to_owned(), index), counts);
                counts
            };
            if counts {
                tracked.spellings.push(spelling.to_owned());
                tracked.entries.push(entry);
                break;
            }
        }
    }
    Ok(Some(tracked))
}

/// ASCII characters a filesystem can take another character for, beyond the
/// ASCII case git's `icase` folds: `ſ` for `s`, the Kelvin sign for `k`,
/// the dotless `ı` NTFS takes for `i`, and the characters canonically
/// equivalent to `;` and `` ` ``.
const RESPELLABLE_ASCII: &[u8] = b"iksIKS;`";

/// Pathspecs for every index entry a filesystem could take for `path`, or
/// for a file under it: case-insensitive, with a wildcard in place of each
/// character another can stand for. They also match entries that are other
/// files, which [`tracked_entries`] sets apart.
fn candidate_pathspecs(path: &str) -> [String; 2] {
    let pattern = respelling_glob(path);
    [
        format!(":(icase,glob){pattern}"),
        format!(":(icase,glob){pattern}/**"),
    ]
}

/// A glob for `:(icase,glob)` pathspecs that matches every name a filesystem
/// could take for `path`: `path` with glob characters escaped and a `*` in
/// place of each character another can stand for. It matches other names
/// too; [`fold_case`] tells which of those differ from `path` in case only.
pub fn respelling_glob(path: &str) -> String {
    let mut pattern = String::with_capacity(path.len() + 8);
    let mut wildcard = false;
    for character in path.chars() {
        if !character.is_ascii() || RESPELLABLE_ASCII.contains(&(character as u8)) {
            if !wildcard {
                pattern.push('*');
            }
            wildcard = true;
            continue;
        }
        if matches!(character, '*' | '?' | '[' | '\\') {
            pattern.push('\\');
        }
        pattern.push(character);
        wildcard = false;
    }
    pattern
}

/// The first `depth` `/`-separated components of `entry`, or `None` when it
/// has fewer.
fn leading_components(entry: &str, depth: usize) -> Option<&str> {
    match entry.match_indices('/').nth(depth - 1) {
        Some((end, _)) => Some(&entry[..end]),
        None => (entry.split('/').count() == depth).then_some(entry),
    }
}

/// `name` with case set aside the way a case-insensitive filesystem sets it
/// aside, as far as std's Unicode case mappings tell: `ſ`, `S` and `s` all
/// read as `s`.
pub fn fold_case(name: &str) -> String {
    name.to_uppercase().to_lowercase()
}

/// The root of the git work tree that holds `dir`, and `dir`'s path in it
/// ending in `/`, or `""` at the root. `None` outside a work tree.
fn work_tree_location(dir: &Path) -> Result<Option<(PathBuf, String)>, GitProbeError> {
    let located = run_git(
        dir,
        &[
            "rev-parse",
            "--is-inside-work-tree",
            "--show-toplevel",
            "--show-prefix",
        ],
    )?;
    let output = String::from_utf8(located.stdout.clone())
        .map_err(|_| GitProbeError::Failed("git returned a path that is not UTF-8".into()))?;
    let mut lines = output.lines();
    match lines.next() {
        Some("true") if located.status.success() => {}
        // Inside a `.git` directory, which no work tree holds.
        Some("false") => return Ok(None),
        _ => {
            return match discovery_failure(&located) {
                Some(reason) => Err(GitProbeError::Failed(reason)),
                None => Ok(None),
            };
        }
    }
    let (Some(root), prefix) = (lines.next(), lines.next().unwrap_or("")) else {
        return Err(GitProbeError::Failed("git returned no work tree".into()));
    };
    Ok(Some((PathBuf::from(root), prefix.to_owned())))
}

/// Whether `indexed`, a path in the work tree `root` as the index spells
/// it, and `queried`, the path asked about, both relative to `root` with the
/// same number of components, name one file on disk: the files themselves
/// when both exist, else their deepest existing ancestors, as long as the
/// missing names below are spelled alike. `None` when those missing names
/// differ only in case, which the disk can't settle.
fn aliases(root: &Path, indexed: &str, queried: &str) -> Result<Option<bool>, GitProbeError> {
    let identity = |path: &Path| match path_identity(path) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(GitProbeError::Failed(format!(
            "could not tell whether {queried} is {indexed} in {}: {error}",
            root.display()
        ))),
    };
    let indexed_names: Vec<&str> = indexed.split('/').collect();
    let queried_names: Vec<&str> = queried.split('/').collect();
    let mut indexed_path = root.join(indexed);
    let mut queried_path = root.join(queried);
    for existing in (0..=indexed_names.len()).rev() {
        match (identity(&indexed_path)?, identity(&queried_path)?) {
            (Some(indexed_identity), Some(queried_identity)) => {
                let (indexed_missing, queried_missing) =
                    (&indexed_names[existing..], &queried_names[existing..]);
                return Ok(if indexed_identity != queried_identity {
                    Some(false)
                } else if indexed_missing == queried_missing {
                    Some(true)
                } else if fold_case(&indexed_missing.join("/"))
                    == fold_case(&queried_missing.join("/"))
                {
                    None
                } else {
                    Some(false)
                });
            }
            (None, None) if existing > 0 => {
                indexed_path.pop();
                queried_path.pop();
            }
            _ => return Ok(Some(false)),
        }
    }
    Ok(Some(false))
}

#[cfg(unix)]
fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    crate::atomic_write::file_identity(&file)
}

#[cfg(not(any(unix, windows)))]
fn path_identity(_path: &Path) -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

fn ignores_case(dir: &Path) -> Result<bool, GitProbeError> {
    let output = run_git(dir, &["config", "--bool", "--get", "core.ignorecase"])?;
    match (output.status.code(), output.stdout.trim_ascii()) {
        (Some(0), b"true") => Ok(true),
        (Some(0), b"false") | (Some(1), _) => Ok(false),
        _ => Err(GitProbeError::Failed(format!(
            "git could not read core.ignorecase ({})",
            git_failure(&output)
        ))),
    }
}

/// How many entries [`Tracked::untrack_command`] names before it names the
/// paths that hold them instead.
const UNTRACK_NAMED_ENTRIES: usize = 3;

impl Tracked {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A command that stops git tracking the entries, which works from any
    /// directory. A repository can name its files anything, so an entry
    /// that isn't plain is named by the path asked about, in the index's
    /// spelling, rather than pasted into the command.
    pub fn untrack_command(&self) -> String {
        let plain = |entry: &str| {
            !entry.is_empty()
                && entry
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+@,=".contains(&byte))
        };
        let recursive = self.entries.len() > UNTRACK_NAMED_ENTRIES
            || self.entries.iter().any(|entry| !plain(entry));
        let mut words: Vec<&str> = if recursive {
            self.spellings.iter().map(String::as_str).collect()
        } else {
            self.entries.iter().map(String::as_str).collect()
        };
        words.sort_unstable();
        words.dedup();
        let literal = words
            .iter()
            .any(|word| word.starts_with(':') || word.contains(['*', '?', '[', '\\']));
        let mut command = format!("git -C {}", shell_word(&self.root.to_string_lossy()));
        if literal {
            command.push_str(" --literal-pathspecs");
        }
        command.push_str(if recursive {
            " rm -r --cached --"
        } else {
            " rm --cached --"
        });
        for word in words {
            command.push(' ');
            command.push_str(&shell_word(word));
        }
        command
    }
}

/// `word` as one shell word, quoted the way the platform's shells read it
/// when anything in it is special.
fn shell_word(word: &str) -> std::borrow::Cow<'_, str> {
    // PowerShell, the default shell, expands `$` and backticks inside double
    // quotes but reads single quotes literally.
    #[cfg(windows)]
    {
        let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/\\._-+@:,=".contains(&byte);
        if !word.is_empty() && word.bytes().all(plain) {
            std::borrow::Cow::Borrowed(word)
        } else {
            std::borrow::Cow::Owned(format!("'{}'", word.replace('\'', "''")))
        }
    }
    #[cfg(not(windows))]
    {
        // A path holds no NUL, the one byte a shell word can't.
        shlex::try_quote(word).unwrap_or(std::borrow::Cow::Borrowed(word))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_git_s_failure_from_the_start_of_its_fatal_line() {
        for (stderr, failure) in [
            (
                "fatal: not a git repository (or any of the parent directories): .git\n",
                GitDiscoveryFailure::NoRepository,
            ),
            (
                "fatal: Not a git repository (or any of the parent directories): .git\n",
                GitDiscoveryFailure::NoRepository,
            ),
            (
                "fatal: not a git repository (or any parent up to mount point /mnt)\n\
                 Stopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: Not a git repository (or any parent up to mount point /mnt)\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: invalid gitfile format: /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: Invalid gitfile format: /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: no path in gitfile: /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: No path in gitfile: /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: not a git repository: /work/gone/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: gitfile does not point to a valid repository: /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: error opening '/work/app/.git': Permission denied\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: too large to be a .git file: '/work/app/.git'\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: error reading /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: Error reading /work/app/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: error reading from /work/app/.git/index: Input/output error\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: error reading directory '/work/app/src'\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: error opening '/work/app/.git/index': Permission denied\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: error opening '/work/it's/app/.git': Permission denied\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: error opening '/work/app/x.git': Permission denied\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: invalid gitfile format: /work/not a git repository/.git\n",
                GitDiscoveryFailure::Stopped,
            ),
            (
                "fatal: error reading /work/app/x.git\n",
                GitDiscoveryFailure::Refused,
            ),
            ("fatal: error reading .git\n", GitDiscoveryFailure::Stopped),
            (
                "warning: unable to access '/home/user/.config/git/attributes'\n\
                 fatal: not a git repository (or any of the parent directories): .git\n",
                GitDiscoveryFailure::NoRepository,
            ),
            (
                "fatal: detected dubious ownership in repository at \
                 '/work/not a git repository (or any of the parent directories)'\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "warning: not a git repository (or any of the parent directories)\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: detected dubious ownership in repository at '/work/app'\n",
                GitDiscoveryFailure::Refused,
            ),
            (
                "fatal: cannot use bare repository '/work/app' (safe.bareRepository is 'explicit')\n",
                GitDiscoveryFailure::Refused,
            ),
            ("", GitDiscoveryFailure::Refused),
        ] {
            assert_eq!(
                git_discovery_failure(stderr.as_bytes()),
                failure,
                "{stderr}"
            );
        }
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn git(dir: &Path, args: &[&str]) {
        let output = hardened_git_command(dir, args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_directory_that_is_gone_is_a_failure_not_a_missing_git() {
        if !git_available() {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let gone = parent.path().join("gone");

        let failure = run_git(&gone, &["--version"]).unwrap_err();

        assert!(
            matches!(&failure, GitProbeError::Failed(reason) if reason.contains("not a directory")),
            "{failure:?}"
        );
    }

    #[test]
    fn looks_for_the_repository_past_filesystem_boundaries() {
        let command = probe_command(Path::new("."), &["rev-parse"]);

        assert!(command.get_envs().any(|(name, value)| {
            name == "GIT_DISCOVERY_ACROSS_FILESYSTEM" && value == Some(std::ffi::OsStr::new("1"))
        }));
    }

    fn ignores_case_on_disk(dir: &Path) -> bool {
        std::fs::write(dir.join("case-probe"), "").unwrap();
        let ignores = dir.join("CASE-PROBE").exists();
        std::fs::remove_file(dir.join("case-probe")).unwrap();
        ignores
    }

    fn entries(tracked: Option<Tracked>) -> Vec<String> {
        tracked.expect("a work tree").entries
    }

    #[test]
    fn an_entry_in_another_case_counts_when_it_is_the_file_on_disk() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if !ignores_case_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join("DIR/.LPM/certs")).unwrap();
        std::fs::write(dir.join("DIR/.LPM/certs/key.pem"), "placeholder\n").unwrap();
        std::fs::write(dir.join("DIR/.ENV"), "PLACEHOLDER=1\n").unwrap();
        git(dir, &["add", "-f", "--", "DIR"]);
        std::fs::rename(dir.join("DIR"), dir.join("moving")).unwrap();
        std::fs::rename(dir.join("moving"), dir.join("dir")).unwrap();
        let member = dir.join("dir");

        for ignorecase in ["true", "false"] {
            git(dir, &["config", "core.ignorecase", ignorecase]);
            let tracked = tracked_entries(&member, &[".env", ".lpm/certs"])
                .unwrap()
                .unwrap();
            assert_eq!(
                tracked.entries,
                ["DIR/.ENV", "DIR/.LPM/certs/key.pem"],
                "core.ignorecase={ignorecase}"
            );
            assert!(
                tracked
                    .untrack_command()
                    .ends_with(" rm --cached -- DIR/.ENV DIR/.LPM/certs/key.pem"),
                "{}",
                tracked.untrack_command()
            );
        }
    }

    #[test]
    fn an_entry_in_another_case_that_isn_t_on_disk_counts_where_git_ignores_case() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        std::fs::create_dir(dir.join("upper")).unwrap();
        std::fs::write(dir.join("upper/.ENV"), "PLACEHOLDER=1\n").unwrap();
        git(dir, &["add", "--", "upper/.ENV"]);
        std::fs::remove_file(dir.join("upper/.ENV")).unwrap();
        let member = dir.join("upper");

        git(dir, &["config", "core.ignorecase", "false"]);
        assert!(entries(tracked_entries(&member, &[".env"]).unwrap()).is_empty());
        assert_eq!(
            entries(tracked_entries(&member, &[".ENV"]).unwrap()),
            ["upper/.ENV"]
        );

        git(dir, &["config", "core.ignorecase", "true"]);
        assert_eq!(
            entries(tracked_entries(&member, &[".env"]).unwrap()),
            ["upper/.ENV"]
        );
    }

    /// Whether the disk takes `ſ` for `s`, as APFS and NTFS do.
    fn folds_long_s_on_disk(dir: &Path) -> bool {
        std::fs::write(dir.join("fold-probe-s"), "").unwrap();
        let folds = dir.join("fold-probe-\u{17F}").exists();
        std::fs::remove_file(dir.join("fold-probe-s")).unwrap();
        folds
    }

    const RESPELLED: [(&str, &str); 3] = [
        (".lpm/cert\u{17F}/key.pem", ".lpm/certs"),
        ("lpm.j\u{17F}on", "lpm.json"),
        (".env.bac\u{212A}up", ".env.backup"),
    ];

    #[test]
    fn an_entry_spelled_with_a_letter_the_disk_folds_beyond_ascii_counts() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if !folds_long_s_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join(".lpm/cert\u{17F}")).unwrap();
        for (indexed, _) in RESPELLED {
            std::fs::write(dir.join(indexed), "placeholder\n").unwrap();
        }
        git(dir, &["add", "-f", "--", "."]);

        for ignorecase in ["true", "false"] {
            git(dir, &["config", "core.ignorecase", ignorecase]);
            for (indexed, asked) in RESPELLED {
                assert_eq!(
                    entries(tracked_entries(dir, &[asked]).unwrap()),
                    [indexed],
                    "{asked} with core.ignorecase={ignorecase}"
                );
            }
        }
    }

    #[test]
    fn an_entry_spelled_with_a_letter_filesystems_fold_counts_off_disk_where_git_ignores_case() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        let respelled = [
            RESPELLED[0],
            RESPELLED[1],
            (".env.product\u{131}on", ".env.production"),
        ];
        std::fs::create_dir_all(dir.join(".lpm/cert\u{17F}")).unwrap();
        for (indexed, _) in respelled {
            std::fs::write(dir.join(indexed), "placeholder\n").unwrap();
        }
        git(dir, &["add", "-f", "--", "."]);
        std::fs::remove_dir_all(dir.join(".lpm")).unwrap();
        for (indexed, _) in &respelled[1..] {
            std::fs::remove_file(dir.join(indexed)).unwrap();
        }

        git(dir, &["config", "core.ignorecase", "true"]);
        for (indexed, asked) in respelled {
            assert_eq!(
                entries(tracked_entries(dir, &[asked]).unwrap()),
                [indexed],
                "{asked}"
            );
        }
        git(dir, &["config", "core.ignorecase", "false"]);
        for (_, asked) in respelled {
            assert!(
                entries(tracked_entries(dir, &[asked]).unwrap()).is_empty(),
                "{asked}"
            );
        }
    }

    #[test]
    fn a_directory_above_the_project_the_disk_spells_otherwise_still_holds_its_entries() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if !ignores_case_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join("packages/app/.lpm/certs")).unwrap();
        std::fs::write(dir.join("packages/app/.env"), "PLACEHOLDER=1\n").unwrap();
        std::fs::write(dir.join("packages/app/.lpm/certs/key.pem"), "placeholder\n").unwrap();
        git(dir, &["add", "-f", "--", "packages"]);
        std::fs::rename(dir.join("packages"), dir.join("moving")).unwrap();
        std::fs::rename(dir.join("moving"), dir.join("Packages")).unwrap();
        std::fs::rename(dir.join("Packages/app"), dir.join("Packages/moving")).unwrap();
        std::fs::rename(dir.join("Packages/moving"), dir.join("Packages/App")).unwrap();

        let tracked = tracked_entries(&dir.join("Packages/App"), &[".env", ".lpm"])
            .unwrap()
            .unwrap();
        assert_eq!(
            tracked.entries,
            ["packages/app/.env", "packages/app/.lpm/certs/key.pem"]
        );
        assert!(
            tracked
                .untrack_command()
                .ends_with(" rm --cached -- packages/app/.env packages/app/.lpm/certs/key.pem"),
            "{}",
            tracked.untrack_command()
        );
    }

    #[test]
    fn the_index_s_blob_is_what_git_staged_not_what_the_work_tree_holds() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        let mut names = vec!["lpm.json"];
        // A name that reads as a stage number before the path.
        if cfg!(unix) {
            names.push("1:lpm.json");
        }
        for name in &names {
            std::fs::write(dir.join(name), "staged").unwrap();
            git(dir, &["add", "--", &format!(":(literal){name}")]);
            std::fs::write(dir.join(name), "edited").unwrap();
            assert_eq!(indexed_blob(dir, name, 64).unwrap(), b"staged", "{name}");
        }
        assert!(indexed_blob(dir, "untracked.json", 64).is_err());
        assert!(indexed_blob(dir, "lpm.json", 3).is_err());
    }

    #[test]
    fn every_ascii_character_another_can_stand_for_is_left_to_a_wildcard() {
        let canonical_singletons = [('\u{37E}', ';'), ('\u{1FEF}', '`'), ('\u{212A}', 'K')];
        for (equivalent, ascii) in canonical_singletons {
            assert!(RESPELLABLE_ASCII.contains(&(ascii as u8)), "{equivalent:?}");
        }
        for character in '\u{80}'..=char::MAX {
            let folded = fold_case(character.encode_utf8(&mut [0; 4]));
            let mut folded_chars = folded.chars();
            if let (Some(single), None) = (folded_chars.next(), folded_chars.next())
                && single.is_ascii()
            {
                assert!(
                    RESPELLABLE_ASCII.contains(&(single as u8)),
                    "{character:?} folds to {single:?}"
                );
            }
        }
        assert_eq!(
            candidate_pathspecs("a/.lpm/certs/x*?[\\k\u{e9};"),
            [
                ":(icase,glob)a/.lpm/cert*/x\\*\\?\\[\\\\*",
                ":(icase,glob)a/.lpm/cert*/x\\*\\?\\[\\\\*/**"
            ]
        );
    }

    #[test]
    fn a_missing_entry_under_a_directory_the_disk_takes_for_the_queried_one_counts() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if !ignores_case_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join("DIR/.lpm/certs")).unwrap();
        std::fs::write(dir.join("DIR/.env"), "PLACEHOLDER=1\n").unwrap();
        std::fs::write(dir.join("DIR/.lpm/certs/key.pem"), "placeholder\n").unwrap();
        git(dir, &["add", "-f", "--", "DIR"]);
        std::fs::remove_file(dir.join("DIR/.env")).unwrap();
        std::fs::remove_file(dir.join("DIR/.lpm/certs/key.pem")).unwrap();
        std::fs::rename(dir.join("DIR"), dir.join("moving")).unwrap();
        std::fs::rename(dir.join("moving"), dir.join("dir")).unwrap();
        // Git reads `DIR/.env` through `dir/`, so a file written there is
        // that entry whatever core.ignorecase says.
        git(dir, &["config", "core.ignorecase", "false"]);

        assert_eq!(
            entries(tracked_entries(&dir.join("dir"), &[".env", ".lpm/certs/key.pem"]).unwrap()),
            ["DIR/.env", "DIR/.lpm/certs/key.pem"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn an_entry_through_an_ntfs_short_name_counts() {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        std::fs::create_dir_all(dir.join(".lpm/certs")).unwrap();
        let long: Vec<u16> = dir
            .join(".lpm")
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut short = vec![0u16; 1024];
        // SAFETY: both buffers are valid for the lengths passed.
        let length =
            unsafe { GetShortPathNameW(long.as_ptr(), short.as_mut_ptr(), short.len() as u32) };
        let short = std::ffi::OsString::from_wide(&short[..length as usize]);
        let Some(name) = std::path::Path::new(&short)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| length > 0 && name.contains('~'))
        else {
            // The volume makes no short names.
            return;
        };
        std::fs::write(dir.join("blob"), "placeholder\n").unwrap();
        let hashed = hardened_git_command(dir, &["hash-object", "-w", "blob"])
            .output()
            .unwrap();
        let blob = String::from_utf8(hashed.stdout).unwrap();
        let entry = format!("{name}/certs/key.pem");
        git(
            dir,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("100644,{},{entry}", blob.trim()),
            ],
        );

        assert_eq!(
            entries(tracked_entries(dir, &[".lpm/certs"]).unwrap()),
            [entry]
        );
    }

    #[test]
    fn an_entry_in_another_case_is_another_file_where_the_disk_tells_them_apart() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if ignores_case_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        std::fs::write(dir.join(".ENV"), "PLACEHOLDER=1\n").unwrap();
        git(dir, &["add", "--", ".ENV"]);
        git(dir, &["config", "core.ignorecase", "true"]);

        assert!(entries(tracked_entries(dir, &[".env"]).unwrap()).is_empty());
    }

    #[test]
    fn nothing_is_tracked_outside_a_repository_and_a_broken_git_file_is_a_failure() {
        if !git_available() {
            return;
        }
        let outside = tempfile::tempdir().unwrap();
        assert_eq!(tracked_entries(outside.path(), &[".env"]).unwrap(), None);

        std::fs::write(outside.path().join(".git"), "gitdir: ../gone/.git\n").unwrap();
        let failure = tracked_entries(outside.path(), &[".env"]).unwrap_err();
        assert!(
            matches!(&failure, GitProbeError::Failed(reason) if reason.contains("stopped at a .git file")),
            "{failure:?}"
        );
    }

    fn tracked(root: &str, queried: &[&str], entries: &[&str]) -> Tracked {
        let spelling = |entry: &str| {
            queried
                .iter()
                .find_map(|path| {
                    leading_components(entry, path.split('/').count())
                        .filter(|spelling| fold_case(spelling) == fold_case(path))
                })
                .expect("each entry is under a queried path")
                .to_owned()
        };
        Tracked {
            root: PathBuf::from(root),
            entries: entries.iter().map(|entry| (*entry).to_owned()).collect(),
            spellings: entries.iter().map(|entry| spelling(entry)).collect(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_untrack_command_works_from_anywhere_and_takes_nothing_beyond_the_query() {
        assert_eq!(
            tracked("/work/my app", &[".env"], &[".ENV"]).untrack_command(),
            "git -C '/work/my app' rm --cached -- .ENV"
        );
        assert_eq!(
            tracked("/work", &["a*b [1]"], &["a*b [1]"]).untrack_command(),
            "git -C /work --literal-pathspecs rm -r --cached -- 'a*b [1]'"
        );
        let many = [
            ".LPM/certs/a",
            ".LPM/certs/b",
            ".LPM/certs/c",
            ".LPM/certs/d",
        ];
        assert_eq!(
            tracked("/work", &[".lpm/certs"], &many).untrack_command(),
            "git -C /work rm -r --cached -- .LPM/certs"
        );
        assert_eq!(
            tracked("/work", &[".lpm"], &many).untrack_command(),
            "git -C /work rm -r --cached -- .LPM"
        );
    }

    #[test]
    fn a_name_a_repository_planted_never_reaches_the_untrack_command() {
        for planted in [
            ".lpm/$(Start-Process calc)",
            ".lpm/`whoami`",
            ".lpm/%PATH%",
            ".lpm/a;rm -rf ~",
        ] {
            let command = tracked("/work", &[".lpm"], &[planted, ".lpm/ok"]).untrack_command();
            assert!(
                command.ends_with(" rm -r --cached -- .lpm"),
                "{planted}: {command}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_words_are_quoted_the_way_powershell_reads_literally() {
        assert_eq!(shell_word("C:\\work\\app"), "C:\\work\\app");
        assert_eq!(shell_word("C:\\my work\\it's"), "'C:\\my work\\it''s'");
        assert_eq!(shell_word("$(calc)"), "'$(calc)'");
    }
}
