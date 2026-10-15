use std::path::Path;

/// A git command for a project that may be untrusted: no `GIT_*` variable
/// from the environment, no `core.fsmonitor` program, which reading the
/// index would run, and no repository found as a bare one, which a cloned
/// project can contain with its own config.
pub(crate) fn hardened_git_command(project_dir: &Path, args: &[&str]) -> std::process::Command {
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
pub(crate) enum GitDiscoveryFailure {
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
pub(crate) fn git_discovery_failure(stderr: &[u8]) -> GitDiscoveryFailure {
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
}
