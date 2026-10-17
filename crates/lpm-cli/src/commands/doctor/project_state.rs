use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

const NAMED_FILES: usize = 3;
const IGNORE_FILE_READ_CAP_BYTES: u64 = 64 * 1024;
const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const GIT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// The paths a deploy output commits for its dependencies, `node_modules`
/// first.
const DEPLOY_OUTPUT_DEPENDENCIES: [&str; 3] =
    ["node_modules", ".lpm/store", ".lpm/deploy-workspace"];

/// Those of [`DEPLOY_OUTPUT_DEPENDENCIES`] in `.lpm`, relative to it.
const STATE_DEPENDENCIES: [&str; 2] = ["store", "deploy-workspace"];

/// Whether `project_dir` is a deploy output, as its `.lpm/.gitignore` says.
fn is_deploy_output(project_dir: &Path) -> bool {
    lpm_common::read_file_capped(
        &project_dir
            .join(lpm_common::PROJECT_STATE_DIR)
            .join(lpm_common::project_state::PROJECT_STATE_IGNORE_FILE),
        IGNORE_FILE_READ_CAP_BYTES,
    )
    .is_ok_and(|existing| lpm_common::project_state::is_deploy_output_state_ignore(&existing))
}

/// In a deploy output in a git work tree, whether git leaves out any of the
/// files its dependencies are, by any rule it reads: an ignore file a
/// dependency brought, one above the output, the repository's
/// `info/exclude` or a global excludes file, which the deploy can't see.
/// A repository of `.lpm`'s own commits the dependencies there, and the one
/// around the output doesn't look inside it, so each is asked about its
/// own. No row elsewhere, or when git can't answer.
pub(super) fn check_deploy_output_dependencies_committable(project_dir: &Path) -> Option<Check> {
    if !is_deploy_output(project_dir) {
        return None;
    }
    let state_dir = project_dir.join(lpm_common::PROJECT_STATE_DIR);
    let state_has_its_own = lpm_common::project_git::work_tree_location(&state_dir)
        .ok()?
        .is_some_and(|(_, prefix)| prefix.is_empty());
    let mut repositories = Vec::with_capacity(2);
    if let Some((root, prefix)) = lpm_common::project_git::work_tree_location(project_dir).ok()? {
        // Git lists nothing in a directory it ignores whole, as a rule above
        // the output can make it.
        if !prefix.is_empty()
            && let Some(rule) = rule_ignoring_whole(project_dir, &root)?
        {
            return Some(Check::warn(
                &doctor_catalog::DEPLOY_OUTPUT_DEPENDENCIES_IGNORED,
                &format!(
                    "git ignores this whole deploy output, by `{}` on line {} of {}, so a commit leaves out its dependencies with the rest of it; change that rule to commit it",
                    lpm_common::sanitize_terminal_inline(&rule.pattern),
                    rule.line,
                    lpm_common::sanitize_terminal_inline(&rule.source.to_string_lossy())
                ),
            ));
        }
        let pathspecs: &[&str] = if state_has_its_own {
            &DEPLOY_OUTPUT_DEPENDENCIES[..1]
        } else {
            &DEPLOY_OUTPUT_DEPENDENCIES
        };
        repositories.push((project_dir.to_path_buf(), "", pathspecs));
    }
    if state_has_its_own {
        repositories.push((state_dir, ".lpm/", &STATE_DEPENDENCIES[..]));
    }
    if repositories.is_empty() {
        return None;
    }
    let mut found = Vec::with_capacity(repositories.len());
    for (directory, shown_from, pathspecs) in repositories {
        let ignored = ignored_by_git(&directory, pathspecs)?;
        if !ignored.is_empty() {
            found.push((directory, shown_from, ignored));
        }
    }
    if found.is_empty() {
        return Some(Check::pass(
            &doctor_catalog::DEPLOY_OUTPUT_DEPENDENCIES_COMMITTABLE,
            "git leaves out none of this deploy output's dependencies",
        ));
    }
    let commands: Vec<String> = found
        .iter()
        .map(|(directory, _, ignored)| {
            let words: Vec<String> = ignored
                .iter()
                .map(|entry| lpm_common::project_git::shell_word(entry).into_owned())
                .collect();
            format!(
                "git -C {} add -f -- {}",
                lpm_common::project_git::shell_word(&directory.to_string_lossy()),
                words.join(" ")
            )
        })
        .collect();
    let named: Vec<String> = found
        .iter()
        .flat_map(|(_, shown_from, ignored)| {
            ignored
                .iter()
                .map(move |entry| format!("{shown_from}{entry}"))
        })
        .collect();
    let shown = named
        .iter()
        .take(NAMED_FILES)
        .map(|entry| lpm_common::sanitize_terminal_inline(entry))
        .collect::<Vec<_>>()
        .join(", ");
    let more = named.len().saturating_sub(NAMED_FILES);
    let rest = if more == 0 {
        String::new()
    } else {
        format!(" and {more} more")
    };
    Some(Check::warn(
        &doctor_catalog::DEPLOY_OUTPUT_DEPENDENCIES_IGNORED,
        &format!(
            "git ignores {shown}{rest}, which this deploy output's dependencies need; commit them with: {}",
            lpm_common::sanitize_terminal_inline(&commands.join("; "))
        ),
    ))
}

/// A rule git reads: its pattern, its line, and the file it is in.
struct IgnoreRule {
    source: std::path::PathBuf,
    line: String,
    pattern: String,
}

/// The rule that makes git ignore `directory` as a whole, which is in the
/// work tree at `root`. `Some(None)` when none does, `None` when git can't
/// answer. Asked with `-z`, as git's plain output quotes a name with
/// unusual characters and a `:` can't tell a name's end. With `--verbose`
/// git also names a negated rule that matched last, which takes the
/// directory back; a literal `!` starting a pattern is written `\!`.
fn rule_ignoring_whole(directory: &Path, root: &Path) -> Option<Option<IgnoreRule>> {
    let mut command = lpm_common::project_git::hardened_git_command(
        directory,
        &["check-ignore", "--verbose", "-z", "--stdin"],
    );
    let output = lpm_common::process_output::output_capped_with_input(
        &mut command,
        b".\0",
        GIT_TIMEOUT,
        GIT_OUTPUT_LIMIT,
    )
    .ok()?;
    match output.status.code() {
        Some(0) => Some(
            parse_ignore_rule(&output.stdout, root).filter(|rule| !rule.pattern.starts_with('!')),
        ),
        Some(1) => Some(None),
        _ => None,
    }
}

/// `<source>\0<line>\0<pattern>\0<path>\0`, as `git check-ignore
/// --verbose -z` writes it, with a source in the work tree named from its
/// root.
fn parse_ignore_rule(output: &[u8], root: &Path) -> Option<IgnoreRule> {
    let mut fields = output.split(|byte| *byte == 0);
    let source = lpm_common::git_directory::path_from_bytes(
        fields.next().filter(|source| !source.is_empty())?,
    );
    let line = String::from_utf8_lossy(fields.next()?).into_owned();
    let pattern = String::from_utf8_lossy(fields.next()?).into_owned();
    Some(IgnoreRule {
        source: if source.is_relative() {
            root.join(source)
        } else {
            source
        },
        line,
        pattern,
    })
}

/// What git in `directory` ignores of `pathspecs`, relative to it, a
/// directory it ignores whole named once. `None` when git can't answer.
fn ignored_by_git(directory: &Path, pathspecs: &[&str]) -> Option<Vec<String>> {
    let mut command = lpm_common::project_git::hardened_git_command(
        directory,
        &[
            &[
                "ls-files",
                "-z",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--directory",
                "--",
            ][..],
            pathspecs,
        ]
        .concat(),
    );
    let output =
        lpm_common::process_output::output_capped(&mut command, GIT_TIMEOUT, GIT_OUTPUT_LIMIT)
            .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf8_lossy(entry).into_owned())
            .collect(),
    )
}

/// Whether git tracks anything in the project's `.lpm`, under any spelling
/// git takes for it. Files committed before `.lpm` ignored itself stay
/// tracked, and a tracked trust snapshot or build state can hide the
/// warnings they exist to raise. No row when git can't answer or the
/// project isn't in a repository.
pub(super) fn check_project_state_tracked(project_dir: &Path) -> Option<Check> {
    let state = lpm_common::PROJECT_STATE_DIR;
    let mut found =
        lpm_common::project_git::tracked_entries_in_any_repository(project_dir, &[state])
            .ok()??;
    // A deploy output commits the dependencies its `.lpm` holds.
    let deploy_output = is_deploy_output(project_dir);
    let mut dependencies_tracked = false;
    if deploy_output {
        for tracked in &mut found {
            let before = tracked.entries.len();
            // `.lpm` itself, in the index of a repository around it, is the
            // gitlink to a repository of its own, whose entries are asked
            // about on their own.
            tracked.retain_below(|below| {
                !below.is_empty() && !lpm_common::project_state::deploy_output_commits(below)
            });
            dependencies_tracked |= tracked.entries.len() < before;
        }
        found.retain(|tracked| !tracked.entries.is_empty());
    }
    if found.is_empty() {
        return project_dir.join(state).is_dir().then(|| {
            Check::pass(
                &doctor_catalog::PROJECT_STATE_UNTRACKED,
                if dependencies_tracked {
                    "git tracks only this deploy output's dependencies in .lpm"
                } else {
                    "git tracks nothing in .lpm"
                },
            )
        });
    }
    let entries: Vec<String> = found
        .iter()
        .flat_map(|tracked| tracked.entries.iter().cloned())
        .collect();
    let commands: Vec<String> = found
        .iter()
        .map(lpm_common::project_git::Tracked::untrack_command)
        .collect();
    Some(Check::warn(
        &doctor_catalog::PROJECT_STATE_TRACKED,
        &tracked_message(&entries, &commands.join("; ")),
    ))
}

fn tracked_message(names: &[String], untrack: &str) -> String {
    let shown = names
        .iter()
        .take(NAMED_FILES)
        .map(|name| lpm_common::sanitize_terminal_inline(name))
        .collect::<Vec<_>>()
        .join(", ");
    let more = names.len().saturating_sub(NAMED_FILES);
    let rest = if more == 0 {
        String::new()
    } else {
        format!(" and {more} more")
    };
    format!(
        "git tracks {shown}{rest} in .lpm, which holds machine-local state; run: {}, then commit",
        lpm_common::sanitize_terminal_inline(untrack)
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
    fn a_deploy_output_s_committed_dependencies_are_not_machine_local_state() {
        let project = repository();
        let state = project.path().join(".lpm");
        for file in [
            "store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            "deploy-workspace/provider-000000/package.json",
        ] {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        std::fs::write(
            state.join(".gitignore"),
            lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
        )
        .unwrap();
        let check = check_project_state_tracked(project.path()).unwrap();
        assert_eq!(check.detail, "git tracks nothing in .lpm");
        git(project.path(), &["add", "-A"]);

        let check = check_project_state_tracked(project.path()).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);
        assert_eq!(
            check.detail,
            "git tracks only this deploy output's dependencies in .lpm"
        );

        std::fs::write(state.join("known-projects.json"), "{}").unwrap();
        git(project.path(), &["add", "-f", ".lpm/known-projects.json"]);

        let check = check_project_state_tracked(project.path()).unwrap();
        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check
                .detail
                .starts_with("git tracks .lpm/known-projects.json in .lpm")
                && check
                    .detail
                    .contains(" rm --cached -- .lpm/known-projects.json, then commit"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn a_deploy_output_s_dependencies_in_a_repository_of_lpm_s_own_stay_committed() {
        let output = tempfile::tempdir().unwrap();
        let state = output.path().join(".lpm");
        for file in [
            "store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            "deploy-workspace/provider-000000/package.json",
        ] {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        std::fs::write(
            state.join(".gitignore"),
            lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
        )
        .unwrap();
        git(&state, &["init", "--quiet"]);
        git(&state, &["add", "-A"]);

        let check = check_project_state_tracked(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);

        // The output's own repository holds `.lpm` as a gitlink to it.
        git(
            &state,
            &[
                "-c",
                "user.name=deploy",
                "-c",
                "user.email=deploy@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "dependencies",
            ],
        );
        git(output.path(), &["init", "--quiet"]);
        git(output.path(), &["add", "-A"]);
        let check = check_project_state_tracked(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);

        let local = [
            "known-projects.json",
            "install-hash",
            "trust-snapshot.json",
            "cache/metadata/a.json",
        ];
        for file in local {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "{}").unwrap();
        }
        git(&state, &[&["add", "-f", "--"][..], &local[..]].concat());

        let check = check_project_state_tracked(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check.detail.contains(
                " rm -r --cached -- cache install-hash known-projects.json trust-snapshot.json, then commit"
            ),
            "{}",
            check.detail
        );
    }

    #[test]
    fn a_deploy_output_s_dependencies_git_would_leave_out_are_named() {
        let output = repository();
        let state = output.path().join(".lpm");
        for file in [
            "store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            "store/v2/links/b@1.0.0+0/node_modules/b/dist/index.js",
        ] {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        std::fs::create_dir_all(output.path().join("node_modules")).unwrap();
        std::fs::write(output.path().join("node_modules/.modules.yaml"), "x").unwrap();
        // Outside a deploy output there's no row.
        assert!(check_deploy_output_dependencies_committable(output.path()).is_none());
        std::fs::write(
            state.join(".gitignore"),
            lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
        )
        .unwrap();

        let check = check_deploy_output_dependencies_committable(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);

        // A dependency's own ignore file, and a rule of the repository's.
        std::fs::write(
            state.join("store/v2/links/b@1.0.0+0/node_modules/b/.gitignore"),
            "dist/\n",
        )
        .unwrap();
        std::fs::write(output.path().join(".git/info/exclude"), "node_modules/\n").unwrap();

        let check = check_deploy_output_dependencies_committable(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check.detail.contains(
                " add -f -- .lpm/store/v2/links/b@1.0.0+0/node_modules/b/dist/ node_modules/"
            ),
            "{}",
            check.detail
        );
    }

    #[test]
    fn a_deploy_output_s_dependencies_a_repository_of_lpm_s_own_would_leave_out_are_named() {
        let output = tempfile::tempdir().unwrap();
        let state = output.path().join(".lpm");
        for file in [
            "store/v2/links/a@1.0.0+0/node_modules/a/index.js",
            "store/v2/links/b@1.0.0+0/node_modules/b/dist/index.js",
        ] {
            let path = state.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        std::fs::write(
            state.join(".gitignore"),
            lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
        )
        .unwrap();
        git(&state, &["init", "--quiet"]);

        let check = check_deploy_output_dependencies_committable(output.path()).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);

        std::fs::write(
            state.join("store/v2/links/b@1.0.0+0/node_modules/b/.gitignore"),
            "dist/\n",
        )
        .unwrap();
        let command = format!(
            "git -C {} add -f -- store/v2/links/b@1.0.0+0/node_modules/b/dist/",
            lpm_common::project_git::shell_word(&state.to_string_lossy())
        );
        // On its own, and committed, with the output's repository around it
        // holding it as a gitlink, which git there doesn't look inside.
        for around in [false, true] {
            if around {
                git(&state, &["add", "-A"]);
                git(
                    &state,
                    &[
                        "-c",
                        "user.name=deploy",
                        "-c",
                        "user.email=deploy@example.invalid",
                        "commit",
                        "--quiet",
                        "-m",
                        "dependencies",
                    ],
                );
                git(output.path(), &["init", "--quiet"]);
                git(output.path(), &["add", "-A"]);
            }
            let check = check_deploy_output_dependencies_committable(output.path()).unwrap();
            assert_eq!(check.severity, Severity::Warn, "{}", check.detail);
            assert!(
                check
                    .detail
                    .starts_with("git ignores .lpm/store/v2/links/b@1.0.0+0/node_modules/b/dist/,")
                    && check.detail.ends_with(&command),
                "{}",
                check.detail
            );
        }

        // Each repository's command, one after another.
        let dependency = output.path().join("node_modules/c");
        std::fs::create_dir_all(dependency.join("lib")).unwrap();
        std::fs::write(dependency.join(".gitignore"), "lib/\n").unwrap();
        std::fs::write(dependency.join("lib/y.js"), "x").unwrap();
        let check = check_deploy_output_dependencies_committable(output.path()).unwrap();
        let outer = format!(
            "git -C {} add -f -- node_modules/c/lib/; ",
            lpm_common::project_git::shell_word(&output.path().to_string_lossy())
        );
        assert!(
            check.detail.contains(&format!("{outer}{command}")),
            "{}",
            check.detail
        );
    }

    #[test]
    fn an_ignore_rule_s_file_is_named_as_it_is_on_disk() {
        // Git quotes a name with non-ASCII characters in its plain output,
        // and a directory's name can hold `:<digits>:`.
        for directory in ["apps:123:release", "apps-\u{FC}"] {
            let repository = repository();
            let output = repository.path().join(directory).join("out");
            let state = output.join(".lpm");
            std::fs::create_dir_all(&state).unwrap();
            std::fs::write(
                state.join(".gitignore"),
                lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
            )
            .unwrap();
            std::fs::write(
                repository.path().join(directory).join(".gitignore"),
                "out/\n",
            )
            .unwrap();

            let check = check_deploy_output_dependencies_committable(&output).unwrap();

            let root = std::fs::canonicalize(repository.path()).unwrap();
            let rule = format!(
                "git ignores this whole deploy output, by `out/` on line 1 of {},",
                root.join(directory).join(".gitignore").display()
            );
            assert!(check.detail.starts_with(&rule), "{}", check.detail);
        }
    }

    #[test]
    fn an_ignore_rule_is_read_from_git_s_nul_separated_fields() {
        let rule =
            parse_ignore_rule(b"dir:12:x/.gitignore\x001\0a:b\0.\0", Path::new("/repo")).unwrap();
        assert_eq!(rule.source, Path::new("/repo/dir:12:x/.gitignore"));
        assert_eq!(rule.line, "1");
        assert_eq!(rule.pattern, "a:b");
        let rule =
            parse_ignore_rule(b"/etc/gitignore\x007\0apps/\0.\0", Path::new("/repo")).unwrap();
        assert_eq!(rule.source, Path::new("/etc/gitignore"));
        assert!(parse_ignore_rule(b"", Path::new("/repo")).is_none());
    }

    #[test]
    fn a_deploy_output_git_ignores_whole_is_named_with_its_rule() {
        let repository = repository();
        std::fs::write(repository.path().join(".gitignore"), "apps/\n").unwrap();
        let output = repository.path().join("apps/out");
        let state = output.join(".lpm");
        let dependency = state.join("store/v2/links/a@1.0.0+0/node_modules/a/index.js");
        std::fs::create_dir_all(dependency.parent().unwrap()).unwrap();
        std::fs::write(&dependency, "x").unwrap();
        std::fs::write(
            state.join(".gitignore"),
            lpm_common::project_state::DEPLOY_OUTPUT_STATE_IGNORE,
        )
        .unwrap();

        let check = check_deploy_output_dependencies_committable(&output).unwrap();

        assert_eq!(check.severity, Severity::Warn, "{}", check.detail);
        let root = std::fs::canonicalize(repository.path()).unwrap();
        let rule = format!(
            "git ignores this whole deploy output, by `apps/` on line 1 of {},",
            root.join(".gitignore").display()
        );
        assert!(check.detail.starts_with(&rule), "{}", check.detail);

        // A rule in a `.gitignore` below the repository's top.
        std::fs::write(repository.path().join(".gitignore"), "").unwrap();
        std::fs::write(repository.path().join("apps/.gitignore"), "out/\n").unwrap();
        let check = check_deploy_output_dependencies_committable(&output).unwrap();
        let rule = format!(
            "git ignores this whole deploy output, by `out/` on line 1 of {},",
            root.join("apps/.gitignore").display()
        );
        assert!(check.detail.starts_with(&rule), "{}", check.detail);
        std::fs::remove_file(repository.path().join("apps/.gitignore")).unwrap();

        // Taken back, the output's dependencies are asked about again.
        std::fs::write(repository.path().join(".gitignore"), "apps/*\n!apps/out/\n").unwrap();
        let check = check_deploy_output_dependencies_committable(&output).unwrap();
        assert_eq!(check.severity, Severity::Pass, "{}", check.detail);

        // A rule that takes the output back, which `check-ignore --verbose`
        // names as the last one matching, as the whitelist idiom's does.
        for rules in ["*\n!*/\n", "**\n!**/\n"] {
            std::fs::write(repository.path().join(".gitignore"), rules).unwrap();
            let check = check_deploy_output_dependencies_committable(&output).unwrap();
            assert!(
                !check.detail.contains("whole deploy output"),
                "{rules:?}: {}",
                check.detail
            );
        }
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
                && check
                    .detail
                    .contains(" rm --cached -- .lpm/trust-snapshot.json, then commit"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn warns_about_state_git_tracks_under_another_case_where_git_ignores_case() {
        let project = repository();
        std::fs::create_dir(project.path().join(".LPM")).unwrap();
        std::fs::write(project.path().join(".LPM/trust-snapshot.json"), "{}").unwrap();
        git(project.path(), &["config", "core.ignorecase", "true"]);
        git(project.path(), &["add", "-f", ".LPM/trust-snapshot.json"]);
        // Where the disk tells `.LPM` from `.lpm`, it isn't LPM's state.
        if !project.path().join(".lpm").exists() {
            return;
        }

        let check = check_project_state_tracked(project.path()).unwrap();

        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check
                .detail
                .contains(" rm --cached -- .LPM/trust-snapshot.json, then commit"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn warns_about_state_a_repository_of_lpm_s_own_tracks() {
        let project = repository();
        let state = project.path().join(".lpm");
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join("trust-snapshot.json"), "{}").unwrap();
        git(&state, &["init", "--quiet"]);
        git(&state, &["add", "trust-snapshot.json"]);

        let check = check_project_state_tracked(project.path()).unwrap();

        assert_eq!(check.severity, Severity::Warn);
        assert!(
            check
                .detail
                .contains(" rm --cached -- trust-snapshot.json, then commit"),
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
            tracked_message(&names, "git -C /work rm -r --cached -- .lpm"),
            "git tracks .lpm/1, .lpm/2, .lpm/3 and 2 more in .lpm, which holds machine-local state; run: git -C /work rm -r --cached -- .lpm, then commit"
        );
    }
}
