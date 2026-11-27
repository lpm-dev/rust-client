use std::path::{Path, PathBuf};

const BEGIN: &str = "# BEGIN LPM linked skills: ";
const END: &str = "# END LPM linked skills: ";
const WORKTREE_TAG: &str = " [worktree ";
const MAX_EXCLUDE_BYTES: u64 = 1024 * 1024;

/// What keeping linked skills out of Git did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExcludeOutcome {
    /// The project isn't in a Git repository.
    NotARepository,
    Updated,
    Unchanged,
    /// Git couldn't be asked, or its exclude file couldn't be written; the
    /// reason is for a warning.
    Failed(String),
}

/// Makes the repository's local exclude file (`info/exclude`, which Git
/// reads like `.gitignore` but never commits) list exactly `entries`,
/// project-relative link paths, in a block that names the project and,
/// since every worktree of a repository shares the file, the worktree. An
/// empty `entries` removes the block. Blocks of worktrees Git has since
/// removed go too.
pub(crate) fn sync_exclude_block(project_dir: &Path, entries: &[String]) -> ExcludeOutcome {
    if !lpm_common::project_git::repository_marker_above(project_dir) {
        return ExcludeOutcome::NotARepository;
    }
    let output = match lpm_common::project_git::run_git(
        project_dir,
        &[
            "rev-parse",
            "--show-toplevel",
            "--git-path",
            "info/exclude",
            "--git-dir",
            "--git-common-dir",
        ],
    ) {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return if entries.is_empty() {
                ExcludeOutcome::Unchanged
            } else {
                ExcludeOutcome::Failed(lpm_common::project_git::git_failure(&output))
            };
        }
        Err(error) => {
            return if entries.is_empty() {
                ExcludeOutcome::Unchanged
            } else {
                ExcludeOutcome::Failed(error.to_string())
            };
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines().map(|line| {
        let path = PathBuf::from(line.trim());
        if path.is_absolute() {
            path
        } else {
            project_dir.join(path)
        }
    });
    let (Some(toplevel), Some(exclude), Some(git_dir), Some(common_dir)) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return ExcludeOutcome::Failed("git did not report the repository layout".into());
    };
    let Some(prefix) = project_prefix(project_dir, &toplevel) else {
        return ExcludeOutcome::Failed(format!(
            "{} is not inside the repository at {}",
            project_dir.display(),
            toplevel.display()
        ));
    };
    let label = block_label(&prefix, worktree_name(&git_dir, &common_dir).as_deref());
    if let Some(parent) = exclude.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return ExcludeOutcome::Failed(error.to_string());
    }
    let _lock = match lpm_common::acquire_exclusive_lock(exclude.with_file_name("exclude.lpm-lock"))
    {
        Ok(lock) => lock,
        Err(error) => return ExcludeOutcome::Failed(error.to_string()),
    };
    let current = match lpm_common::read_file_capped(&exclude, MAX_EXCLUDE_BYTES) {
        Ok(content) => String::from_utf8_lossy(&content).into_owned(),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => String::new(),
        Err(error) => return ExcludeOutcome::Failed(error.to_string()),
    };
    let worktrees = common_dir.join("worktrees");
    let updated = match replace_block(&current, &label, &prefix, entries, |name| {
        worktrees.join(name).is_dir()
    }) {
        Ok(updated) => updated,
        Err(reason) => return ExcludeOutcome::Failed(format!("{}: {reason}", exclude.display())),
    };
    if updated == current {
        return ExcludeOutcome::Unchanged;
    }
    match lpm_common::write_file_atomic(&exclude, updated) {
        Ok(()) => ExcludeOutcome::Updated,
        Err(error) => ExcludeOutcome::Failed(error.to_string()),
    }
}

/// The project's path inside the work tree, `/`-separated, empty at its
/// root.
fn project_prefix(project_dir: &Path, toplevel: &Path) -> Option<String> {
    let project = project_dir.canonicalize().ok()?;
    let toplevel = toplevel.canonicalize().ok()?;
    let relative = project.strip_prefix(&toplevel).ok()?;
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some(parts.join("/"))
}

/// The name Git gave the linked worktree whose Git directory is `git_dir`,
/// or `None` for the main worktree.
fn worktree_name(git_dir: &Path, common_dir: &Path) -> Option<String> {
    let git_dir = git_dir.canonicalize().ok()?;
    let common_dir = common_dir.canonicalize().ok()?;
    if git_dir == common_dir || git_dir.parent()? != common_dir.join("worktrees") {
        return None;
    }
    git_dir.file_name()?.to_str().map(str::to_string)
}

fn block_label(prefix: &str, worktree: Option<&str>) -> String {
    let mut label = if prefix.is_empty() {
        ".".to_string()
    } else {
        prefix.replace(['\n', '\r'], " ")
    };
    if let Some(worktree) = worktree {
        label.push_str(WORKTREE_TAG);
        label.push_str(worktree);
        label.push(']');
    }
    label
}

/// `content` with the block labelled `label` holding `entries`, or without
/// it when there are none, and without the blocks of linked worktrees
/// `worktree_exists` no longer finds. Other lines, including the blocks of
/// other projects and worktrees, stay. An error when this project's block
/// has lost its end line, which leaves where it ends unknown.
fn replace_block(
    content: &str,
    label: &str,
    prefix: &str,
    entries: &[String],
    worktree_exists: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut output = String::with_capacity(content.len() + entries.len() * 48);
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let Some(block_label) = line.strip_prefix(BEGIN) else {
            output.push_str(line);
            output.push('\n');
            index += 1;
            continue;
        };
        let end_line = format!("{END}{block_label}");
        let Some(length) = lines[index + 1..].iter().position(|line| *line == end_line) else {
            if block_label == label {
                return Err(format!(
                    "its `{line}` block has no end line, so LPM left the file alone"
                ));
            }
            output.push_str(line);
            output.push('\n');
            index += 1;
            continue;
        };
        let block_end = index + 1 + length;
        let removed_worktree = block_label
            .rsplit_once(WORKTREE_TAG)
            .and_then(|(_, rest)| rest.strip_suffix(']'))
            .is_some_and(|worktree| !worktree_exists(worktree));
        if block_label == label || removed_worktree {
            if output.ends_with("\n\n") {
                output.pop();
            }
        } else {
            for line in &lines[index..=block_end] {
                output.push_str(line);
                output.push('\n');
            }
        }
        index = block_end + 1;
    }
    if !entries.is_empty() {
        if !output.is_empty() && !output.ends_with("\n\n") {
            output.push('\n');
        }
        output.push_str(BEGIN);
        output.push_str(label);
        output.push('\n');
        for entry in entries {
            output.push('/');
            if !prefix.is_empty() {
                output.push_str(&escape(prefix));
                output.push('/');
            }
            output.push_str(&escape(entry));
            output.push('\n');
        }
        output.push_str(END);
        output.push_str(label);
        output.push('\n');
    }
    Ok(output)
}

/// Escapes the characters Git's ignore patterns give meaning to.
fn escape(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for character in path.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\' | '!' | '#') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_lists_anchored_paths_and_keeps_other_lines() {
        let existing = "# user rules\n*.log\n";
        let updated = replace_block(
            existing,
            "apps/web",
            "apps/web",
            &[
                ".agents/skills/deploy".into(),
                ".claude/skills/deploy".into(),
            ],
            |_| true,
        )
        .unwrap();
        assert_eq!(
            updated,
            "# user rules\n*.log\n\n# BEGIN LPM linked skills: apps/web\n/apps/web/.agents/skills/deploy\n/apps/web/.claude/skills/deploy\n# END LPM linked skills: apps/web\n"
        );
    }

    #[test]
    fn replacing_the_block_is_idempotent_and_empty_entries_remove_it() {
        let entries = vec![".agents/skills/deploy".to_string()];
        let once = replace_block("*.log\n", ".", "", &entries, |_| true).unwrap();
        let twice = replace_block(&once, ".", "", &entries, |_| true).unwrap();
        assert_eq!(once, twice);
        assert_eq!(
            replace_block(&once, ".", "", &[], |_| true).unwrap(),
            "*.log\n"
        );
    }

    #[test]
    fn another_projects_block_is_left_alone() {
        let content = replace_block(
            "",
            "apps/api",
            "apps/api",
            &[".agents/skills/a".into()],
            |_| true,
        )
        .unwrap();
        let both = replace_block(
            &content,
            "apps/web",
            "apps/web",
            &[".agents/skills/b".into()],
            |_| true,
        )
        .unwrap();
        assert!(both.contains("/apps/api/.agents/skills/a"));
        assert!(both.contains("/apps/web/.agents/skills/b"));
        let web_removed = replace_block(&both, "apps/web", "apps/web", &[], |_| true).unwrap();
        assert!(web_removed.contains("/apps/api/.agents/skills/a"));
        assert!(!web_removed.contains("apps/web"));
    }

    #[test]
    fn blocks_of_removed_worktrees_are_dropped_and_others_kept() {
        let entries = [".agents/skills/a".to_string()];
        let content = ["gone", "live"]
            .iter()
            .fold(String::new(), |content, worktree| {
                replace_block(
                    &content,
                    &block_label("", Some(worktree)),
                    "",
                    &entries,
                    |_| true,
                )
                .unwrap()
            });
        let updated = replace_block(&content, ".", "", &entries, |name| name == "live").unwrap();
        assert!(!updated.contains("[worktree gone]"), "{updated}");
        assert!(updated.contains("[worktree live]"), "{updated}");
        assert!(updated.contains(&format!("{BEGIN}.\n")), "{updated}");
    }

    #[test]
    fn pattern_characters_are_escaped() {
        assert_eq!(escape("a[b]*?!#"), "a\\[b\\]\\*\\?\\!\\#");
    }

    fn git(directory: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(directory)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", directory)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn repository() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        git(directory.path(), &["init", "-q"]);
        git(
            directory.path(),
            &[
                "-c",
                "user.name=LPM",
                "-c",
                "user.email=lpm@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
        );
        directory
    }

    fn exclude_of(repository: &Path) -> String {
        std::fs::read_to_string(repository.join(".git/info/exclude")).unwrap_or_default()
    }

    #[test]
    fn each_worktree_of_a_repository_keeps_its_own_block() {
        let main = repository();
        let parent = tempfile::tempdir().unwrap();
        let worktree = parent.path().join("worktree");
        git(
            main.path(),
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                worktree.to_str().unwrap(),
            ],
        );

        assert_eq!(
            sync_exclude_block(main.path(), &[".agents/skills/first".into()]),
            ExcludeOutcome::Updated
        );
        assert_eq!(
            sync_exclude_block(&worktree, &[".agents/skills/second".into()]),
            ExcludeOutcome::Updated
        );

        let exclude = exclude_of(main.path());
        assert!(exclude.contains("/.agents/skills/first"), "{exclude}");
        assert!(exclude.contains("/.agents/skills/second"), "{exclude}");
    }

    #[test]
    fn an_unterminated_block_and_the_lines_after_it_are_kept() {
        let repository = repository();
        assert_eq!(
            sync_exclude_block(repository.path(), &[".agents/skills/first".into()]),
            ExcludeOutcome::Updated
        );
        let path = repository.path().join(".git/info/exclude");
        let mut damaged: String = exclude_of(repository.path())
            .lines()
            .filter(|line| !line.starts_with(END))
            .map(|line| format!("{line}\n"))
            .collect();
        damaged.push_str("*.log\n");
        std::fs::write(&path, &damaged).unwrap();

        let outcome = sync_exclude_block(repository.path(), &[".agents/skills/second".into()]);

        assert!(matches!(outcome, ExcludeOutcome::Failed(_)), "{outcome:?}");
        assert_eq!(exclude_of(repository.path()), damaged);
    }

    #[test]
    fn a_project_outside_any_repository_needs_no_exclusion() {
        let project = tempfile::tempdir().unwrap();
        if lpm_common::project_git::repository_marker_above(project.path()) {
            return;
        }
        assert_eq!(
            sync_exclude_block(project.path(), &[".agents/skills/a".into()]),
            ExcludeOutcome::NotARepository
        );
    }
}
