use std::path::Path;
use std::time::Duration;

use crate::doctor_catalog;

use super::check::Check;

const GIT_TIMEOUT: Duration = Duration::from_secs(2);
const GIT_OUTPUT_LIMIT: usize = 1024 * 1024;
const NAMED_FILES: usize = 3;

/// Whether git tracks anything in the project's `.lpm`. Files committed
/// before `.lpm` ignored itself stay tracked, and a tracked trust snapshot
/// or build state can hide the warnings they exist to raise. No row when
/// git can't answer or the project isn't in a repository.
pub(super) fn check_project_state_tracked(project_dir: &Path) -> Option<Check> {
    let mut command = lpm_common::project_git::hardened_git_command(
        project_dir,
        &["ls-files", "-z", "--cached", "--", ".lpm"],
    );
    let tracked = match lpm_common::process_output::output_capped(
        &mut command,
        GIT_TIMEOUT,
        GIT_OUTPUT_LIMIT,
    ) {
        Ok(output) if output.status.success() => Tracked::Listed(parse_names(&output.stdout)),
        Ok(_) => return None,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => Tracked::TooManyToList,
        Err(_) => return None,
    };
    match tracked {
        Tracked::Listed(names) if names.is_empty() => project_dir
            .join(lpm_common::PROJECT_STATE_DIR)
            .is_dir()
            .then(|| {
                Check::pass(
                    &doctor_catalog::PROJECT_STATE_UNTRACKED,
                    "git tracks nothing in .lpm",
                )
            }),
        Tracked::Listed(names) => Some(Check::warn(
            &doctor_catalog::PROJECT_STATE_TRACKED,
            &tracked_message(&names),
        )),
        Tracked::TooManyToList => Some(Check::warn(
            &doctor_catalog::PROJECT_STATE_TRACKED,
            "git tracks many files in .lpm, which holds machine-local state; run: git rm -r --cached .lpm, then commit",
        )),
    }
}

enum Tracked {
    Listed(Vec<String>),
    TooManyToList,
}

fn parse_names(stdout: &[u8]) -> Vec<String> {
    stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| {
            lpm_common::sanitize_terminal_inline(&String::from_utf8_lossy(name)).into_owned()
        })
        .collect()
}

fn tracked_message(names: &[String]) -> String {
    let shown = names
        .iter()
        .take(NAMED_FILES)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let more = names.len().saturating_sub(NAMED_FILES);
    let rest = if more == 0 {
        String::new()
    } else {
        format!(" and {more} more")
    };
    format!(
        "git tracks {shown}{rest} in .lpm, which holds machine-local state; run: git rm -r --cached .lpm, then commit"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    fn git(directory: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(directory)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn repository() -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        git(project.path(), &["init", "--quiet"]);
        project
    }

    #[test]
    fn warns_about_state_committed_before_lpm_ignored_itself() {
        let project = repository();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::fs::write(project.path().join(".lpm/trust-snapshot.json"), "{}").unwrap();
        git(project.path(), &["add", "-f", ".lpm/trust-snapshot.json"]);

        let check = check_project_state_tracked(project.path()).unwrap();

        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check.detail.contains(".lpm/trust-snapshot.json")
                && check.detail.contains("git rm -r --cached .lpm"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn passes_when_git_tracks_nothing_in_lpm() {
        let project = repository();
        lpm_common::ensure_project_state_dir(project.path()).unwrap();
        std::fs::write(project.path().join(".lpm/install-hash"), "x").unwrap();

        let check = check_project_state_tracked(project.path()).unwrap();

        assert_eq!(check.severity, Severity::Pass);
    }

    #[test]
    fn has_no_row_outside_a_repository_or_without_state() {
        let outside = tempfile::tempdir().unwrap();
        let repository = repository();

        assert!(check_project_state_tracked(repository.path()).is_none());
        assert!(check_project_state_tracked(outside.path()).is_none());
    }

    #[test]
    fn names_three_files_and_counts_the_rest() {
        let names: Vec<String> = (1..=5).map(|index| format!(".lpm/{index}")).collect();

        assert_eq!(
            tracked_message(&names),
            "git tracks .lpm/1, .lpm/2, .lpm/3 and 2 more in .lpm, which holds machine-local state; run: git rm -r --cached .lpm, then commit"
        );
    }
}
