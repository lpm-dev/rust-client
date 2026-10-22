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
    #[cfg(target_os = "macos")]
    refuse_git_stub()?;
    probe_command(dir, args)
        .output()
        .map_err(|error| spawn_failure(dir, &error))
}

/// Runs a [`hardened_git_command`] in `dir` and reads the NUL-terminated
/// records it prints until `wanted` takes one, then stops git: whether one
/// did. One record is held at a time, however much git lists.
pub(crate) fn git_lists_any(
    dir: &Path,
    args: &[&str],
    wanted: impl FnMut(&[u8]) -> bool,
) -> Result<bool, GitProbeError> {
    #[cfg(target_os = "macos")]
    refuse_git_stub()?;
    first_record_matching(dir, probe_command(dir, args), wanted)
}

/// Fails as though git were missing where the `git` on `PATH` is macOS's
/// `/usr/bin/git` with no developer tools selected: that stub opens the
/// Command Line Tools installer, as an app that asks git looks to the user
/// to have done, and then fails.
#[cfg(target_os = "macos")]
fn refuse_git_stub() -> Result<(), GitProbeError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    // Only finding the tools is kept: they can be installed while an app
    // that asks git keeps running.
    static TOOLS_FOUND: AtomicBool = AtomicBool::new(false);
    if TOOLS_FOUND.load(Ordering::Relaxed) {
        return Ok(());
    }
    let path = std::env::var_os("PATH");
    match git_stub_without_tools(path.as_deref(), selected_developer_directory) {
        Some(reason) => Err(GitProbeError::GitMissing(reason)),
        None => {
            TOOLS_FOUND.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
}

/// Why the `git` that `path`, a `PATH` value, finds first can't run: it is
/// `/usr/bin/git`, and the developer directory `selected` names holds no
/// git for it to run.
#[cfg(target_os = "macos")]
fn git_stub_without_tools(
    path: Option<&std::ffi::OsStr>,
    selected: impl FnOnce() -> Option<PathBuf>,
) -> Option<String> {
    use std::os::unix::fs::PermissionsExt as _;

    let git = std::env::split_paths(path?)
        .map(|directory| directory.join("git"))
        .find(|candidate| {
            std::fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })?;
    if std::fs::canonicalize(&git).ok()? != Path::new("/usr/bin/git") {
        return None;
    }
    if selected().is_some_and(|developer| developer.join("usr/bin/git").is_file()) {
        return None;
    }
    Some(
        "macOS's git needs the Command Line Tools, which aren't installed; install them with \
         `xcode-select --install`"
            .to_owned(),
    )
}

/// The developer directory `/usr/bin/git` runs git from, as `xcode-select`
/// reports it without offering to install one.
#[cfg(target_os = "macos")]
fn selected_developer_directory() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;

    let output = std::process::Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| PathBuf::from(std::ffi::OsStr::from_bytes(output.stdout.trim_ascii_end())))
}

fn first_record_matching(
    dir: &Path,
    mut command: std::process::Command,
    mut wanted: impl FnMut(&[u8]) -> bool,
) -> Result<bool, GitProbeError> {
    use std::io::{BufRead as _, Read as _};

    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| spawn_failure(dir, &error))?;
    let stop = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let Some(stdout) = child.stdout.take() else {
        stop(&mut child);
        return Err(GitProbeError::Failed(
            "git's output could not be read".into(),
        ));
    };
    let mut reader = std::io::BufReader::new(stdout);
    let mut record = Vec::new();
    loop {
        record.clear();
        match reader.read_until(0, &mut record) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                drop(reader);
                stop(&mut child);
                return Err(GitProbeError::Failed(format!(
                    "failed to read git's output: {error}"
                )));
            }
        }
        if record.last() == Some(&0) {
            record.pop();
        }
        if !record.is_empty() && wanted(&record) {
            drop(reader);
            stop(&mut child);
            return Ok(true);
        }
    }
    drop(reader);
    // Git writes little to stderr, so it can't fill the pipe while its
    // output is read.
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    let status = child
        .wait()
        .map_err(|error| GitProbeError::Failed(format!("failed to wait for git: {error}")))?;
    if status.success() {
        Ok(false)
    } else {
        Err(GitProbeError::Failed(sanitized_stderr(&stderr)))
    }
}

/// Why git couldn't be started in `dir`.
fn spawn_failure(dir: &Path, error: &std::io::Error) -> GitProbeError {
    // Spawning in a directory that is gone fails too, as NotFound on Unix
    // and as an invalid directory name on Windows.
    if !dir.is_dir() {
        return GitProbeError::Failed(format!(
            "git could not run in {}, which is not a directory",
            dir.display()
        ));
    }
    match error.kind() {
        std::io::ErrorKind::NotFound => GitProbeError::GitMissing(error.to_string()),
        _ => GitProbeError::Failed(format!("failed to run git: {error}")),
    }
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
    sanitized_stderr(&output.stderr)
}

fn sanitized_stderr(stderr: &[u8]) -> String {
    crate::sanitize_terminal_inline(String::from_utf8_lossy(stderr).trim()).into_owned()
}

/// Whether `dir` is in a git work tree; failing to tell is an error, as a
/// repository git stopped short of can still hold it.
pub fn inside_work_tree(dir: &Path) -> Result<bool, GitProbeError> {
    let inside = run_git(dir, &["rev-parse", "--is-inside-work-tree"])?;
    if !inside.status.success() {
        return match discovery_failure(dir, &inside) {
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

/// [`repository_marker_above`] for [`tracked_entries_in_any_repository`]:
/// a `.git` at or above `dir`, or in a directory on the way from `dir` to
/// one of `paths`.
pub fn repository_marker_around(dir: &Path, paths: &[&str]) -> bool {
    repository_marker_above(dir)
        || paths.iter().any(|path| {
            nested_candidates(dir, path)
                .into_iter()
                .any(|(directory, _)| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        })
}

/// [`tracked_entries`] for `paths` in `dir`, asked of every index that can
/// list them, as [`indexes_listing`] finds them: the repositories that
/// track something come back, each once. `None` when no work tree holds
/// `dir` or any directory on the way to the paths.
pub fn tracked_entries_in_any_repository(
    dir: &Path,
    paths: &[&str],
) -> Result<Option<Vec<Tracked>>, GitProbeError> {
    let indexes = indexes_listing(dir, paths, None)?;
    if indexes.is_empty() {
        return Ok(None);
    }
    let mut found = Vec::new();
    for index in &indexes {
        let tracked = index.tracked()?;
        if !tracked.entries.is_empty() {
            found.push(tracked);
        }
    }
    Ok(Some(found))
}

/// The bytes git's index holds at stage 0 for `entry`, a path relative to
/// the work tree `root`, as stored: no filter or conversion runs. Fails for
/// an entry with conflicts, which has no stage 0, and past `limit` bytes.
pub fn indexed_blob(root: &Path, entry: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    #[cfg(target_os = "macos")]
    refuse_git_stub()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()))?;
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

/// Why git, run in `dir`, found no repository, or `None` when it found that
/// none holds the directory.
fn discovery_failure(dir: &Path, output: &std::process::Output) -> Option<String> {
    match git_discovery_failure(&output.stderr) {
        GitDiscoveryFailure::NoRepository if output.status.code() == Some(128) => None,
        // Git names neither the file nor, in Apple's build, where it points.
        GitDiscoveryFailure::Stopped => Some(
            match dir
                .ancestors()
                .map(|directory| directory.join(".git"))
                .find(|marker| marker.is_file())
            {
                Some(marker) => format!(
                    "git stopped at {}, a .git file it can't use ({})",
                    marker.display(),
                    git_failure(output)
                ),
                None => format!(
                    "git stopped at a .git file it can't use ({})",
                    git_failure(output)
                ),
            },
        ),
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
/// created there, as that directory looks names up, whatever
/// `core.ignorecase` says. Where the disk can't tell whether the directory
/// ignores case, missing names that differ only in case count where
/// `core.ignorecase` is set, as git then commits a file written there as
/// that entry.
pub fn tracked_entries(dir: &Path, paths: &[&str]) -> Result<Option<Tracked>, GitProbeError> {
    match locate_work_tree(dir, None)? {
        Some(work_tree) => tracked_entries_in(&work_tree, paths).map(Some),
        None => Ok(None),
    }
}

/// [`tracked_entries`] in a work tree the caller has located, with `paths`
/// relative to the directory it was located from.
pub(crate) fn tracked_entries_in(
    work_tree: &WorkTree,
    paths: &[&str],
) -> Result<Tracked, GitProbeError> {
    tracked_entries_in_where(work_tree, paths, crate::names::names_ignore_marks)
}

/// [`tracked_entries_in`] with `ignores_marks` telling whether the volume
/// holding a directory leaves out of names the marks HFS+ leaves out.
fn tracked_entries_in_where(
    work_tree: &WorkTree,
    paths: &[&str],
    ignores_marks: fn(&Path) -> bool,
) -> Result<Tracked, GitProbeError> {
    let WorkTree { root, prefix, .. } = work_tree;
    let root = root.clone();
    let mut queried: Vec<String> = paths
        .iter()
        .map(|path| format!("{prefix}{path}").trim_end_matches('/').to_owned())
        .collect();
    // An empty path is the whole work tree, whose every entry counts.
    if queried.iter().any(String::is_empty) {
        let listed = run_git(&root, &["ls-files", "-z", "--cached"])?;
        if !listed.status.success() {
            return Err(GitProbeError::Failed(git_failure(&listed)));
        }
        let entries: Vec<String> = listed
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf8_lossy(entry).into_owned())
            .collect();
        return Ok(Tracked {
            root,
            spellings: vec![".".to_owned(); entries.len()],
            entries,
        });
    }
    // A path asked by another name than the disk's, an NTFS short name or a
    // linked directory, is asked for under the disk's name too.
    for index in 0..queried.len() {
        if let Some(spelled) = disk_spelling(&root, &queried[index])
            && !queried.contains(&spelled)
        {
            queried.push(spelled);
        }
    }
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
    let mut disk = DiskAnswers::default();
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
                let counts = match aliases(&tracked.root, spelling, path, &mut disk, ignores_marks)?
                {
                    Some(same) => same,
                    None => {
                        let same_name = fold_case(spelling) == fold_case(path)
                            || (holds_a_mark(spelling) || holds_a_mark(path))
                                && disk.ignores_marks(&tracked.root, ignores_marks)
                                && fold_case(&crate::names::fold_name(spelling))
                                    == fold_case(&crate::names::fold_name(path));
                        same_name
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
    Ok(tracked)
}

/// `path`, relative to the work tree `root`, as the disk names it: its
/// deepest existing ancestor resolved to its long, link-free name, the rest
/// as given. A link at `path` itself is the file git would track there, so
/// it keeps its own name, as its directory lists it. `None` where that isn't
/// in the work tree or can't be told.
pub(crate) fn disk_spelling(root: &Path, path: &str) -> Option<String> {
    let resolved_root = std::fs::canonicalize(root).ok()?;
    let mut existing = root.join(path);
    let resolved = if std::fs::symlink_metadata(&existing)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        link_on_disk(&existing)?
    } else {
        let mut missing = Vec::new();
        let mut resolved = loop {
            match std::fs::canonicalize(&existing) {
                Ok(resolved) => break resolved,
                Err(_) => {
                    missing.push(existing.file_name()?.to_owned());
                    existing.pop();
                }
            }
        };
        resolved.extend(missing.iter().rev());
        resolved
    };
    let names: Vec<&str> = resolved
        .strip_prefix(&resolved_root)
        .ok()?
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<_>>()?;
    (!names.is_empty()).then(|| names.join("/"))
}

/// `link`, a symbolic link or junction, as the disk spells it without
/// following it: its directory resolved, and its own name as that directory
/// lists it.
#[cfg(unix)]
fn link_on_disk(link: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::{DirEntryExt as _, MetadataExt as _};
    let name = link.file_name()?;
    let directory = std::fs::canonicalize(link.parent()?).ok()?;
    let metadata = std::fs::symlink_metadata(link).ok()?;
    let mut listed = None;
    for entry in std::fs::read_dir(&directory).ok()?.flatten() {
        if entry.file_name() == name {
            return Some(directory.join(name));
        }
        if listed.is_none()
            && entry.ino() == metadata.ino()
            && entry
                .metadata()
                .is_ok_and(|entry| (entry.dev(), entry.ino()) == (metadata.dev(), metadata.ino()))
        {
            listed = Some(entry.file_name());
        }
    }
    Some(directory.join(listed.unwrap_or_else(|| name.to_owned())))
}

#[cfg(windows)]
fn link_on_disk(link: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let file = open_entry(link).ok()?;
    let mut buffer = vec![0_u16; 512];
    loop {
        let capacity = u32::try_from(buffer.len()).ok()?;
        // SAFETY: the handle is valid for the call and `buffer` holds
        // `capacity` writable units.
        let length = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), capacity, 0)
        } as usize;
        match length {
            0 => return None,
            written if written < buffer.len() => {
                buffer.truncate(written);
                return Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
            }
            needed => buffer.resize(needed, 0),
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn link_on_disk(_link: &Path) -> Option<PathBuf> {
    None
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

/// `path` as Win32 path lookup reads it on Windows: each name without the
/// dots and spaces it ends with, but for `.` and `..`. Elsewhere `path`.
fn as_win32_reads(path: &str) -> std::borrow::Cow<'_, str> {
    if !cfg!(windows) {
        return std::borrow::Cow::Borrowed(path);
    }
    let trimmed: Vec<&str> = path
        .split('/')
        .map(|name| match name {
            "." | ".." => name,
            _ => name.trim_end_matches(['.', ' ']),
        })
        .collect();
    std::borrow::Cow::Owned(trimmed.join("/"))
}

/// A glob for `:(icase,glob)` pathspecs that matches every name a filesystem
/// could take for `path`: `path` with glob characters escaped, a `*` in
/// place of each character another can stand for, and of each one that
/// starts a sequence a composed character can stand for, and a `*` around
/// every other character, as HFS+ leaves zero-width and directional marks
/// out of names wherever they are and Win32 lookup drops dots and spaces a
/// name ends with. It matches other names too; on-disk identity, or
/// [`fold_case`], tells which of those are the file.
pub fn respelling_glob(path: &str) -> String {
    let mut pattern = String::with_capacity(path.len() * 2 + 8);
    for (index, name) in path.split('/').enumerate() {
        if index > 0 {
            pattern.push('/');
        }
        pattern.push('*');
        let mut characters = name.chars().peekable();
        while let Some(character) = characters.next() {
            // An ASCII character followed by a combining mark can be the
            // base of a sequence that another name spells as one composed
            // character.
            let base_of_a_sequence = characters
                .peek()
                .is_some_and(|next| unicode_normalization::char::is_combining_mark(*next));
            if !character.is_ascii()
                || base_of_a_sequence
                || RESPELLABLE_ASCII.contains(&(character as u8))
            {
                continue;
            }
            if matches!(character, '*' | '?' | '[' | '\\') {
                pattern.push('\\');
            }
            pattern.push(character);
            pattern.push('*');
        }
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
/// read as `s`, and `ẞ`, `ß` and `ss` as `ss`. Lowercasing first takes `ẞ`
/// to `ß`, which uppercases to `SS`.
pub fn fold_case(name: &str) -> String {
    name.to_lowercase().to_uppercase().to_lowercase()
}

/// The characters beyond its two ASCII cases that [`fold_case`] reads as
/// the ASCII letter `letter`.
pub fn non_ascii_folds(letter: char) -> &'static [char] {
    match letter.to_ascii_lowercase() {
        'i' => &['\u{131}'],
        'k' => &['\u{212A}'],
        's' => &['\u{17F}'],
        _ => &[],
    }
}

/// The git work tree that holds a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkTree {
    /// Its root.
    pub(crate) root: PathBuf,
    /// The directory's path in it ending in `/`, or `""` at the root.
    pub(crate) prefix: String,
    /// Where git keeps the path asked for, relative to the directory unless
    /// absolute, as `git rev-parse --git-path` names it.
    pub(crate) git_path: Option<PathBuf>,
}

/// The git work tree that holds `dir`, and where git keeps `git_path` when
/// asked, in one git run. `None` outside a work tree.
pub(crate) fn locate_work_tree(
    dir: &Path,
    git_path: Option<&str>,
) -> Result<Option<WorkTree>, GitProbeError> {
    let mut args = vec![
        "rev-parse",
        "--is-inside-work-tree",
        "--show-toplevel",
        "--show-prefix",
    ];
    if let Some(git_path) = git_path {
        args.extend(["--git-path", git_path]);
    }
    let located = run_git(dir, &args)?;
    let output = String::from_utf8(located.stdout.clone())
        .map_err(|_| GitProbeError::Failed("git returned a path that is not UTF-8".into()))?;
    let mut lines = output.lines();
    match lines.next() {
        Some("true") if located.status.success() => {}
        // Inside a `.git` directory, which no work tree holds.
        Some("false") => return Ok(None),
        _ => {
            return match discovery_failure(dir, &located) {
                Some(reason) => Err(GitProbeError::Failed(reason)),
                None => Ok(None),
            };
        }
    }
    let (Some(root), prefix) = (lines.next(), lines.next().unwrap_or("")) else {
        return Err(GitProbeError::Failed("git returned no work tree".into()));
    };
    let git_path = match git_path {
        Some(_) => Some(PathBuf::from(lines.next().ok_or_else(|| {
            GitProbeError::Failed("git returned no repository path".into())
        })?)),
        None => None,
    };
    Ok(Some(WorkTree {
        root: PathBuf::from(root),
        prefix: prefix.to_owned(),
        git_path,
    }))
}

/// The root of the git work tree that holds `dir`, and where `dir` is in
/// it: `/`-separated and ending in `/`, or `""` at the root. `None` outside
/// a work tree.
pub fn work_tree_location(dir: &Path) -> Result<Option<(PathBuf, String)>, GitProbeError> {
    Ok(locate_work_tree(dir, None)?.map(|work_tree| (work_tree.root, work_tree.prefix)))
}

/// A work tree whose index can list the paths [`indexes_listing`] was asked
/// about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Index {
    /// The work tree, as located from the directory `found` names, with an
    /// absolute `git_path`.
    pub(crate) work_tree: WorkTree,
    pub(crate) found: Found,
    /// The paths, from the work tree's root.
    pub(crate) paths: Vec<String>,
}

/// Where [`indexes_listing`] found a work tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    /// It holds the directory the paths are relative to.
    Holding,
    /// It starts in the directory that the first `depth` names of a path
    /// name, as a clone or a submodule there does.
    Nested { depth: usize },
    /// It holds the root of another one.
    Around,
}

impl Index {
    /// What its index tracks at its paths.
    pub(crate) fn tracked(&self) -> Result<Tracked, GitProbeError> {
        if self.paths.is_empty() {
            return Ok(Tracked {
                root: self.work_tree.root.clone(),
                entries: Vec::new(),
                spellings: Vec::new(),
            });
        }
        let paths: Vec<&str> = self.paths.iter().map(String::as_str).collect();
        tracked_entries_in(
            &WorkTree {
                root: self.work_tree.root.clone(),
                prefix: String::new(),
                git_path: None,
            },
            &paths,
        )
    }
}

/// Each work tree whose index can list one of `paths`, `/`-separated and
/// relative to `dir`, once, with `git_path` asked of it when given: the one
/// that holds `dir`, even for no paths; each one that starts in a directory on the way to a
/// path, such as a clone or a submodule there, whose files the index around
/// it doesn't list; and each one that holds another's root, as an index can
/// still list the files it had before a repository was made inside it.
pub(crate) fn indexes_listing(
    dir: &Path,
    paths: &[&str],
    git_path: Option<&str>,
) -> Result<Vec<Index>, GitProbeError> {
    /// The index of `work_tree`, located from `located_from`, among
    /// `indexes`, added when it is new.
    fn index_of<'a>(
        indexes: &'a mut Vec<Index>,
        located_from: &Path,
        mut work_tree: WorkTree,
        found: Found,
    ) -> &'a mut Index {
        let position = match indexes
            .iter()
            .position(|known| known.work_tree.root == work_tree.root)
        {
            Some(position) => position,
            None => {
                if let Some(git_path) = work_tree.git_path.as_mut()
                    && git_path.is_relative()
                {
                    *git_path = located_from.join(&*git_path);
                }
                indexes.push(Index {
                    work_tree,
                    found,
                    paths: Vec::new(),
                });
                indexes.len() - 1
            }
        };
        &mut indexes[position]
    }

    /// Adds `rest`, relative to `located_from`, to what `work_tree`, located
    /// there, is asked.
    fn add(
        indexes: &mut Vec<Index>,
        located_from: &Path,
        work_tree: WorkTree,
        found: Found,
        rest: &str,
    ) {
        let path = format!("{}{rest}", work_tree.prefix)
            .trim_end_matches('/')
            .to_owned();
        let index = index_of(indexes, located_from, work_tree, found);
        if !index.paths.contains(&path) {
            index.paths.push(path);
        }
    }

    let paths: Vec<&str> = paths
        .iter()
        .map(|path| path.trim_end_matches('/'))
        .collect();
    let mut indexes = Vec::new();
    if let Some(work_tree) = locate_work_tree(dir, git_path)? {
        index_of(&mut indexes, dir, work_tree.clone(), Found::Holding);
        for path in &paths {
            add(&mut indexes, dir, work_tree.clone(), Found::Holding, path);
        }
    }
    let holding_root = indexes.first().map(|index| index.work_tree.root.clone());
    for path in &paths {
        for (depth, (directory, rest)) in nested_candidates(dir, path).into_iter().enumerate() {
            // A `.git` that git looks past locates a work tree already found.
            if std::fs::symlink_metadata(directory.join(".git")).is_ok()
                && let Some(work_tree) = locate_work_tree(&directory, git_path)?
            {
                let found = Found::Nested { depth: depth + 1 };
                add(&mut indexes, &directory, work_tree, found, &rest);
            }
        }
    }
    // The work tree holding `dir` was asked every path, so only a work tree
    // outside its root, or that one itself, can have another around it that
    // isn't known yet. It is looked for from the nearest directory above
    // that holds a `.git` with a work tree: one in between can only be a
    // bare repository, as one with worktrees inside it is, or a `.git` file
    // pointing to one, and that has no work tree to list a path.
    let mut next = 0;
    while let Some(index) = indexes.get(next) {
        next += 1;
        let root = &index.work_tree.root;
        let Some(parent) = root.parent() else {
            continue;
        };
        if holding_root
            .as_ref()
            .is_some_and(|holding| parent.starts_with(holding))
        {
            continue;
        }
        let mut search = Some(parent);
        let mut around = None;
        while let Some(start) = search {
            let Some(marker) = start
                .ancestors()
                .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
            else {
                break;
            };
            if let Some(work_tree) = locate_work_tree(marker, git_path)? {
                around = Some((marker, work_tree));
                break;
            }
            search = marker.parent();
        }
        let Some((marker, work_tree)) = around else {
            continue;
        };
        let Some(below) = root
            .strip_prefix(marker)
            .ok()
            .and_then(|below| {
                below
                    .components()
                    .map(|component| component.as_os_str().to_str())
                    .collect::<Option<Vec<_>>>()
            })
            .map(|names| names.join("/"))
        else {
            continue;
        };
        let marker = marker.to_path_buf();
        let inner: Vec<String> = index
            .paths
            .iter()
            .map(|path| {
                if path.is_empty() {
                    below.clone()
                } else {
                    format!("{below}/{path}")
                }
            })
            .collect();
        for rest in &inner {
            add(
                &mut indexes,
                &marker,
                work_tree.clone(),
                Found::Around,
                rest,
            );
        }
    }
    Ok(indexes)
}

/// Each directory on the way from `dir` to `path`, `path` itself included,
/// with the rest of `path` below it.
fn nested_candidates(dir: &Path, path: &str) -> Vec<(PathBuf, String)> {
    let components: Vec<&str> = path
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    let mut directory = dir.to_path_buf();
    components
        .iter()
        .enumerate()
        .map(|(depth, component)| {
            directory.push(component);
            (directory.clone(), components[depth + 1..].join("/"))
        })
        .collect()
}

/// Whether `indexed`, a path in the work tree `root` as the index spells
/// it, and `queried`, the path asked about, both relative to `root` with the
/// same number of components, name one file on disk: the files themselves
/// when both exist, else their deepest existing ancestors, as long as the
/// filesystem would take the missing names below for each other: spelled
/// alike, canonically equivalent on macOS, whose filesystems ignore
/// normalization, or alike but for case in a directory that ignores case,
/// and for the marks HFS+ leaves out of names on a volume `ignores_marks`
/// says does. `None` when they are alike but for case and the disk can't
/// tell whether the directory ignores case.
fn aliases(
    root: &Path,
    indexed: &str,
    queried: &str,
    disk: &mut DiskAnswers,
    ignores_marks: fn(&Path) -> bool,
) -> Result<Option<bool>, GitProbeError> {
    let mut identity = |path: &Path| match disk.identity(path) {
        Ok(identity) => Ok(identity),
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
                if indexed_identity != queried_identity {
                    return Ok(Some(false));
                }
                let (indexed_missing, queried_missing) = (
                    as_win32_reads(&indexed_missing.join("/")).into_owned(),
                    as_win32_reads(&queried_missing.join("/")).into_owned(),
                );
                if indexed_missing == queried_missing
                    || (cfg!(target_os = "macos")
                        && canonical(&indexed_missing) == canonical(&queried_missing))
                {
                    return Ok(Some(true));
                }
                // A directory that ignores case also takes canonically
                // equivalent names for one on APFS and Linux casefolding,
                // but not on NTFS, which compares names as stored.
                let marks = (holds_a_mark(&indexed_missing) || holds_a_mark(&queried_missing))
                    && disk.ignores_marks(&indexed_path, ignores_marks);
                let caseless = |name: &str| {
                    let name = if marks {
                        crate::names::fold_name(name)
                    } else {
                        std::borrow::Cow::Borrowed(name)
                    };
                    if cfg!(windows) {
                        fold_case(&name)
                    } else {
                        canonical(&fold_case(&canonical(&name)))
                    }
                };
                if caseless(&indexed_missing) != caseless(&queried_missing) {
                    return Ok(Some(false));
                }
                return Ok(match ignores_case_in(&indexed_path)? {
                    Some(true) => Some(true),
                    _ => None,
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

/// What one [`tracked_entries`] call reads from disk, once however many
/// candidates share it: the [`entry_identity`] of each path it looks at,
/// `None` for one that doesn't exist, and whether the volume an existing
/// directory is on ignores the marks HFS+ ignores.
#[derive(Default)]
struct DiskAnswers {
    identities: std::collections::HashMap<PathBuf, Option<(u64, u64)>>,
    ignores_marks: std::collections::HashMap<PathBuf, bool>,
}

impl DiskAnswers {
    fn identity(&mut self, path: &Path) -> std::io::Result<Option<(u64, u64)>> {
        if let Some(known) = self.identities.get(path) {
            return Ok(*known);
        }
        let identity = match entry_identity(path) {
            Ok(identity) => Some(identity),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        self.identities.insert(path.to_path_buf(), identity);
        Ok(identity)
    }

    fn ignores_marks(&mut self, directory: &Path, ask: fn(&Path) -> bool) -> bool {
        *self
            .ignores_marks
            .entry(directory.to_path_buf())
            .or_insert_with(|| ask(directory))
    }
}

/// Whether `name` holds a mark HFS+ ignores, the only names whose answer
/// from a volume that ignores them differs.
fn holds_a_mark(name: &str) -> bool {
    name.chars().any(crate::names::is_ignored_in_names)
}

/// Whether `a` and `b` both exist and are one file or directory on disk.
pub fn same_file(a: &Path, b: &Path) -> bool {
    matches!((path_identity(a), path_identity(b)), (Ok(a), Ok(b)) if a == b)
}

/// `name` in Unicode canonical decomposition, the form in which canonically
/// equivalent names are equal.
fn canonical(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization as _;
    name.nfd().collect()
}

/// Whether the filesystem looks names up in `directory` without regard to
/// case, as told by a name there, or `directory`'s own name in its parent,
/// with the case of its ASCII letters swapped: the same file means it
/// ignores case, none or another one that it doesn't. `None` when no name
/// tells.
fn ignores_case_in(directory: &Path) -> Result<Option<bool>, GitProbeError> {
    let tells = |path: &Path| -> Result<Option<bool>, GitProbeError> {
        let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            return Ok(None);
        };
        let swapped: String = name
            .chars()
            .map(|character| {
                if character.is_ascii_lowercase() {
                    character.to_ascii_uppercase()
                } else {
                    character.to_ascii_lowercase()
                }
            })
            .collect();
        if swapped == name {
            return Ok(None);
        }
        let failed = |error: std::io::Error| {
            GitProbeError::Failed(format!(
                "could not tell whether {} ignores case: {error}",
                path.display()
            ))
        };
        let Ok(original) = entry_identity(path) else {
            return Ok(None);
        };
        match entry_identity(&path.with_file_name(&swapped)) {
            Ok(respelled) => Ok(Some(respelled == original)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(false)),
            Err(error) => Err(failed(error)),
        }
    };
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            if let Some(told) = tells(&entry.path())? {
                return Ok(Some(told));
            }
        }
    }
    tells(directory)
}

#[cfg(unix)]
pub(crate) fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub(crate) fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    crate::atomic_write::file_identity(&open_for_identity(path, 0)?)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn path_identity(_path: &Path) -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// The identity of the file at `path` itself: a link there is the link,
/// not what it leads to, as git tracks a link as the link.
#[cfg(unix)]
fn entry_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn entry_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    crate::atomic_write::file_identity(&open_entry(path)?)
}

#[cfg(not(any(unix, windows)))]
fn entry_identity(_path: &Path) -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// The file or directory at `path`, opened only to read its attributes,
/// with `flags` added to the open.
#[cfg(windows)]
fn open_for_identity(path: &Path, flags: u32) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
    };
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | flags)
        .open(path)
}

/// [`open_for_identity`] of a link or junction itself.
#[cfg(windows)]
fn open_entry(path: &Path) -> std::io::Result<std::fs::File> {
    open_for_identity(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

/// Whether git in the work tree around `dir` compares names folding ASCII
/// case, as `core.ignorecase` says.
pub(crate) fn ignores_case(dir: &Path) -> Result<bool, GitProbeError> {
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
    /// Keeps the entries `keep` accepts, given each one's path below the
    /// path it was found for, empty for that path itself. An untrack command
    /// that names paths rather than entries then names the first directory
    /// below that path holding a kept entry, never the path itself.
    pub fn retain_below(&mut self, mut keep: impl FnMut(&str) -> bool) {
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut spellings = Vec::with_capacity(self.entries.len());
        for (entry, spelling) in self.entries.drain(..).zip(self.spellings.drain(..)) {
            // A repository of the path's own spells the path `.`.
            let below = if spelling == "." {
                Some(entry.as_str())
            } else {
                entry
                    .strip_prefix(spelling.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
            };
            if !keep(below.unwrap_or_default()) {
                continue;
            }
            let spelling = match below.and_then(|below| below.split('/').next()) {
                Some(first) if spelling == "." => first.to_owned(),
                Some(first) => format!("{spelling}/{first}"),
                None => spelling,
            };
            entries.push(entry);
            spellings.push(spelling);
        }
        self.entries = entries;
        self.spellings = spellings;
    }

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
pub fn shell_word(word: &str) -> std::borrow::Cow<'_, str> {
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_s_git_stub_counts_as_missing_git_until_developer_tools_are_selected() {
        let first = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tools.path().join("usr/bin")).unwrap();
        std::fs::write(tools.path().join("usr/bin/git"), "").unwrap();
        // A directory ahead of `/usr/bin` whose `git` leads to the stub.
        std::os::unix::fs::symlink("/usr/bin/git", first.path().join("git")).unwrap();
        let path = std::env::join_paths([first.path(), Path::new("/usr/bin")]).unwrap();
        let path = Some(path.as_os_str());

        let missing = git_stub_without_tools(path, || None).unwrap();
        assert!(missing.contains("xcode-select --install"), "{missing}");
        let empty = tempfile::tempdir().unwrap();
        assert!(git_stub_without_tools(path, || Some(empty.path().to_path_buf())).is_some());
        assert_eq!(
            git_stub_without_tools(path, || Some(tools.path().to_path_buf())),
            None
        );

        // A git of its own ahead of the stub runs without developer tools,
        // and a PATH without git leaves spawning to report it missing.
        let own = tempfile::tempdir().unwrap();
        let git = own.path().join("git");
        std::fs::write(&git, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&git, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let ahead = std::env::join_paths([own.path(), Path::new("/usr/bin")]).unwrap();
        assert_eq!(git_stub_without_tools(Some(&ahead), || None), None);
        assert_eq!(
            git_stub_without_tools(Some(empty.path().as_os_str()), || None),
            None
        );
        assert_eq!(git_stub_without_tools(None, || None), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_listing_stops_at_the_first_record_wanted() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf 'skip\\0want\\0'; exec sleep 30"])
            .current_dir(dir.path());
        let started = std::time::Instant::now();
        let mut seen = Vec::new();

        let found = first_record_matching(dir.path(), command, |record| {
            seen.push(record.to_vec());
            record == b"want"
        })
        .unwrap();

        assert!(found);
        assert_eq!(seen, [b"skip".to_vec(), b"want".to_vec()]);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn a_listing_without_a_wanted_record_is_read_to_its_end_and_a_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let shell = |script: &str| {
            let mut command = std::process::Command::new("/bin/sh");
            command.args(["-c", script]).current_dir(dir.path());
            command
        };

        assert!(!first_record_matching(dir.path(), shell("printf 'a\\0b\\0'"), |_| false).unwrap());
        let failure = first_record_matching(dir.path(), shell("echo broken >&2; exit 3"), |_| true)
            .unwrap_err();
        assert!(
            matches!(&failure, GitProbeError::Failed(reason) if reason.contains("broken")),
            "{failure:?}"
        );
    }

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

    /// HFS+ leaves zero-width and directional marks out of names, so an
    /// entry with one is the file without it there, and only there.
    #[test]
    fn an_entry_with_a_mark_hfs_ignores_counts_only_where_the_volume_ignores_marks() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        if !ignores_case_on_disk(dir) {
            return;
        }
        git(dir, &["init", "-q"]);
        git(dir, &["config", "core.ignorecase", "true"]);
        std::fs::create_dir_all(dir.join(".l\u{200C}pm/certs")).unwrap();
        std::fs::write(dir.join(".l\u{200C}pm/certs/key.pem"), "placeholder\n").unwrap();
        git(dir, &["add", "-f", "--", "."]);
        std::fs::remove_dir_all(dir.join(".l\u{200C}pm")).unwrap();
        let work_tree = locate_work_tree(dir, None).unwrap().unwrap();

        let on_hfs =
            tracked_entries_in_where(&work_tree, &[".lpm/certs/key.pem"], |_| true).unwrap();
        let elsewhere =
            tracked_entries_in_where(&work_tree, &[".lpm/certs/key.pem"], |_| false).unwrap();

        assert_eq!(on_hfs.entries, [".l\u{200C}pm/certs/key.pem"]);
        assert!(elsewhere.entries.is_empty(), "{:?}", elsewhere.entries);
    }

    #[test]
    fn the_volume_is_asked_about_marks_once_and_only_for_a_name_with_one() {
        static QUERIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn counted(_: &Path) -> bool {
            QUERIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        std::fs::write(dir.join("blob.txt"), "placeholder\n").unwrap();
        let hashed = hardened_git_command(dir, &["hash-object", "-w", "blob.txt"])
            .output()
            .unwrap();
        std::fs::remove_file(dir.join("blob.txt")).unwrap();
        let blob = String::from_utf8(hashed.stdout).unwrap();
        let blob = blob.trim();
        // Index entries that aren't on disk, sharing the work tree's root as
        // the nearest directory that is.
        for index in 0..20 {
            for name in [format!(".a{index}lxpxm"), format!(".l\u{200C}p{index}m")] {
                git(
                    dir,
                    &[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("100644,{blob},{name}/file.js"),
                    ],
                );
            }
        }
        let work_tree = locate_work_tree(dir, None).unwrap().unwrap();

        let tracked = tracked_entries_in_where(&work_tree, &[".lpm"], counted).unwrap();

        assert!(tracked.entries.is_empty(), "{:?}", tracked.entries);
        assert_eq!(QUERIES.load(std::sync::atomic::Ordering::Relaxed), 1);
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

        // Where the disk folds case, git reads `.ENV` through a `.env`
        // written there whatever core.ignorecase says.
        let folds = ignores_case_on_disk(dir);
        git(dir, &["config", "core.ignorecase", "false"]);
        assert_eq!(
            entries(tracked_entries(&member, &[".env"]).unwrap()).is_empty(),
            !folds
        );
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

    /// Whether the disk takes `ſ` for `s`, as APFS does.
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
        // Where the disk folds case, git reads each entry through the file
        // a write would make, whatever core.ignorecase says.
        let folds = ignores_case_on_disk(dir);
        git(dir, &["config", "core.ignorecase", "false"]);
        for (_, asked) in respelled {
            assert_eq!(
                entries(tracked_entries(dir, &[asked]).unwrap()).is_empty(),
                !folds,
                "{asked}"
            );
        }
    }

    #[test]
    fn a_decomposed_query_lists_the_composed_entry_and_the_other_way_round() {
        assert_eq!(respelling_glob(".env-cafe\u{301}"), "*.*e*n*v*-*c*a*f*");
        assert_eq!(respelling_glob(".env-caf\u{e9}"), "*.*e*n*v*-*c*a*f*");
        if !git_available() || !cfg!(target_os = "macos") {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        git(dir, &["config", "core.precomposeunicode", "false"]);
        for (indexed, asked) in [
            (".env-caf\u{e9}", ".env-cafe\u{301}"),
            (".env-dee\u{301}", ".env-de\u{e9}"),
        ] {
            std::fs::write(dir.join(indexed), "placeholder\n").unwrap();
            git(dir, &["add", "--", indexed]);
            assert_eq!(
                entries(tracked_entries(dir, &[asked]).unwrap()),
                [indexed],
                "{asked:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_path_asked_through_a_linked_directory_is_checked_as_the_disk_spells_it() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        std::fs::create_dir(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/secret.env"), "placeholder\n").unwrap();
        git(dir, &["add", "--", "real/secret.env"]);
        std::os::unix::fs::symlink("real", dir.join("link")).unwrap();

        assert_eq!(
            entries(tracked_entries(dir, &["link/secret.env"]).unwrap()),
            ["real/secret.env"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn an_entry_ending_in_a_dot_or_a_space_is_the_file_without_them() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        let blob = hardened_git_command(dir, &["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child.stdin.take().unwrap().write_all(b"placeholder\n")?;
                child.wait_with_output()
            })
            .unwrap();
        let blob = String::from_utf8(blob.stdout).unwrap();
        // As a commit made where those names are files carries them; Git
        // for Windows refuses to add them itself.
        for entry in [".npmrc.", ".env ", "certs./key.pem"] {
            git(
                dir,
                &[
                    "-c",
                    "core.protectNTFS=false",
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("100644,{},{entry}", blob.trim()),
                ],
            );
        }
        std::fs::write(dir.join(".npmrc"), "token\n").unwrap();

        assert_eq!(
            entries(tracked_entries(dir, &[".npmrc"]).unwrap()),
            [".npmrc."]
        );
        assert_eq!(entries(tracked_entries(dir, &[".env"]).unwrap()), [".env "]);
        assert_eq!(
            entries(tracked_entries(dir, &["certs/key.pem"]).unwrap()),
            ["certs./key.pem"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_path_asked_by_its_ntfs_short_name_finds_the_long_entry() {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        std::fs::write(dir.join("credentials.env"), "placeholder\n").unwrap();
        git(dir, &["add", "--", "credentials.env"]);
        let long: Vec<u16> = dir
            .join("credentials.env")
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

        assert_eq!(
            entries(tracked_entries(dir, &[&name]).unwrap()),
            ["credentials.env"]
        );
    }

    #[test]
    fn a_missing_entry_spelled_with_a_canonically_equivalent_character_counts_on_macos() {
        if !git_available() {
            return;
        }
        let repository = tempfile::tempdir().unwrap();
        let dir = repository.path();
        git(dir, &["init", "-q"]);
        // U+037E GREEK QUESTION MARK is canonically `;`.
        std::fs::write(dir.join("secret\u{37E}.env"), "placeholder\n").unwrap();
        git(dir, &["add", "--", "."]);
        std::fs::remove_file(dir.join("secret\u{37E}.env")).unwrap();
        git(dir, &["config", "core.ignorecase", "false"]);

        assert_eq!(
            entries(tracked_entries(dir, &["secret;.env"]).unwrap()),
            if cfg!(target_os = "macos") {
                vec!["secret\u{37E}.env".to_owned()]
            } else {
                Vec::new()
            }
        );
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

    #[cfg(unix)]
    #[test]
    fn a_link_tracked_under_another_case_counts_though_it_leads_nowhere() {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir().unwrap();
        let dir = directory.path();
        git(dir, &["init", "-q"]);
        git(dir, &["config", "core.ignorecase", "false"]);
        std::os::unix::fs::symlink("missing-target", dir.join(".ENV")).unwrap();
        git(dir, &["add", "--", ".ENV"]);
        let same_entry = std::fs::symlink_metadata(dir.join(".env")).is_ok_and(|lower| {
            std::fs::symlink_metadata(dir.join(".ENV")).unwrap().ino() == lower.ino()
        });
        if !same_entry {
            return;
        }

        let tracked = tracked_entries(dir, &[".env"]).unwrap().unwrap();

        assert_eq!(tracked.entries, [".ENV"]);
    }

    #[test]
    fn asks_each_repository_on_the_way_to_a_path_once() {
        let outside = tempfile::tempdir().unwrap();
        assert_eq!(
            tracked_entries_in_any_repository(outside.path(), &[".lpm/certs"]).unwrap(),
            None
        );

        let state_repository = tempfile::tempdir().unwrap();
        let state = state_repository.path().join(".lpm");
        std::fs::create_dir_all(state.join("certs")).unwrap();
        std::fs::write(state.join("certs/key.pem"), "placeholder").unwrap();
        git(&state, &["init", "-q"]);
        git(&state, &["add", "certs/key.pem"]);
        let found = tracked_entries_in_any_repository(state_repository.path(), &[".lpm/certs"])
            .unwrap()
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entries, ["certs/key.pem"]);

        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm");
        std::fs::create_dir_all(state.join("certs")).unwrap();
        std::fs::write(state.join("certs/key.pem"), "placeholder").unwrap();
        git(project.path(), &["init", "-q"]);
        git(project.path(), &["add", "-f", ".lpm/certs/key.pem"]);
        // Git looks past an empty `.git` directory to the project's repository.
        std::fs::create_dir(state.join(".git")).unwrap();
        let found = tracked_entries_in_any_repository(project.path(), &[".lpm/certs"])
            .unwrap()
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entries, [".lpm/certs/key.pem"]);
        assert_eq!(
            repository_marker_around(outside.path(), &[".lpm/certs"]),
            repository_marker_above(outside.path())
        );
        assert!(repository_marker_around(project.path(), &[".lpm/certs"]));
    }

    #[test]
    fn asks_the_index_around_a_repository_made_inside_its_work_tree() {
        let outer = tempfile::tempdir().unwrap();
        let project = outer.path().join("apps/web");
        std::fs::create_dir_all(project.join(".lpm/certs")).unwrap();
        std::fs::write(project.join(".lpm/certs/key.pem"), "placeholder").unwrap();
        git(outer.path(), &["init", "-q"]);
        git(outer.path(), &["add", "-f", "apps/web/.lpm/certs/key.pem"]);
        git(&project, &["init", "-q"]);
        git(&project.join(".lpm"), &["init", "-q"]);

        let found = tracked_entries_in_any_repository(&project, &[".lpm/certs"])
            .unwrap()
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entries, ["apps/web/.lpm/certs/key.pem"]);
        assert_eq!(
            found[0].root.canonicalize().unwrap(),
            outer.path().canonicalize().unwrap()
        );
        let indexes = indexes_listing(&project, &[".lpm/certs"], None).unwrap();
        assert_eq!(
            indexes
                .iter()
                .map(|index| (index.found, index.paths.clone()))
                .collect::<Vec<_>>(),
            [
                (Found::Holding, vec![".lpm/certs".to_owned()]),
                (Found::Nested { depth: 1 }, vec!["certs".to_owned()]),
                (Found::Around, vec!["apps/web/.lpm/certs".to_owned()]),
            ]
        );
    }

    #[test]
    fn case_is_set_aside_as_a_case_insensitive_filesystem_sets_it_aside() {
        for (name, as_read) in [
            ("\u{17F}KILLS", "skills"),
            (".pgpa\u{1E9E}", ".pgpass"),
            (".pgpa\u{DF}", ".pgpass"),
            ("\u{212A}ey", "key"),
        ] {
            assert_eq!(fold_case(name), as_read, "{name}");
        }
    }

    #[test]
    fn names_every_character_that_folds_to_an_ascii_letter() {
        for character in '\u{80}'..=char::MAX {
            let folded = fold_case(character.encode_utf8(&mut [0; 4]));
            let mut folded_chars = folded.chars();
            if let (Some(single), None) = (folded_chars.next(), folded_chars.next())
                && single.is_ascii_alphabetic()
            {
                assert!(
                    non_ascii_folds(single).contains(&character),
                    "{character:?} folds to {single:?}"
                );
            }
        }
        for letter in ('a'..='z').chain('A'..='Z') {
            for character in non_ascii_folds(letter) {
                assert_eq!(
                    fold_case(character.encode_utf8(&mut [0; 4])),
                    letter.to_ascii_lowercase().to_string()
                );
            }
        }
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
                ":(icase,glob)*a*/*.*l*p*m*/*c*e*r*t*/*x*\\**\\?*\\[*\\\\*",
                ":(icase,glob)*a*/*.*l*p*m*/*c*e*r*t*/*x*\\**\\?*\\[*\\\\*/**"
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
        let below = outside.path().join("app");
        std::fs::create_dir(&below).unwrap();
        let stale = format!("git stopped at {}", outside.path().join(".git").display());
        for dir in [outside.path(), below.as_path()] {
            let failure = tracked_entries(dir, &[".env"]).unwrap_err();
            assert!(
                matches!(&failure, GitProbeError::Failed(reason) if reason.contains(&stale)),
                "{failure:?}"
            );
        }
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
