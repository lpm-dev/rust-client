//! Directories scripts may write, and the mounts in them, that show the
//! project's `.lpm`, the LPM home or the repository's git directories under
//! another path. Landlock grants a hierarchy by the files it holds, so a
//! bind mount there would give scripts the state the path checks keep from
//! them, or hooks and config git runs outside the sandbox. Mounts are placed
//! by the files the table says they show (NFS's by the server directory
//! their source names); where a line doesn't tell, a directory is checked by
//! identity for being the state or holding it.

use std::path::{Path, PathBuf};

use lpm_common::mounts::{Mount, filesystem_location};

/// Refuses a writable root, or a mount below one, that shows protected
/// state ([`protected_state`]) where its path doesn't say so. The mount
/// table is read before scripts run; one that can't be read refuses too.
#[cfg(target_os = "linux")]
pub(crate) fn refuse_state_aliases(
    spec: &crate::SandboxSpec,
    rules: &[(PathBuf, crate::landlock_rules::RuleAccess)],
) -> Result<(), crate::SandboxError> {
    let table =
        lpm_common::mounts::mount_table().map_err(|error| crate::SandboxError::InvalidSpec {
            reason: format!(
                "sandbox: can't read the mount table to check that no directory scripts \
                 write shows the project's .lpm, the LPM home or the repository's git \
                 directory: {error}"
            ),
        })?;
    let lpm_home = lpm_common::LpmRoot::from_env().ok();
    let protected = protected_state(
        &spec.project_dir,
        lpm_home.as_ref().map(lpm_common::LpmRoot::root),
    );
    let writable: Vec<PathBuf> = rules
        .iter()
        .filter(|(_, access)| *access == crate::landlock_rules::RuleAccess::ReadWrite)
        .filter_map(|(path, _)| std::fs::canonicalize(path).ok())
        .collect();
    match first_alias(&table, &writable, &protected, is_same_directory) {
        Some(alias) => Err(crate::SandboxError::InvalidSpec {
            reason: format!(
                "sandbox: {} shows {} through the mount at {}, which scripts may not write; \
                 remove that mount or keep it out of the directories scripts write",
                alias.root.display(),
                alias.state.display(),
                alias.shown_at.display()
            ),
        }),
        None => Ok(()),
    }
}

/// The directories scripts may write nothing in, canonical: the project's
/// `.lpm`, the LPM home, and the git directories of the repository the
/// project is in, a worktree's common directory included.
pub(crate) fn protected_state(project_dir: &Path, lpm_home: Option<&Path>) -> Vec<PathBuf> {
    let mut protected = vec![project_dir.join(lpm_common::PROJECT_STATE_DIR)];
    protected.extend(lpm_home.map(Path::to_path_buf));
    protected.extend(lpm_common::git_directory::repository_git_directories(
        project_dir,
    ));
    let mut canonical: Vec<PathBuf> = Vec::with_capacity(protected.len());
    for path in protected {
        if let Ok(path) = std::fs::canonicalize(path)
            && !canonical.contains(&path)
        {
            canonical.push(path);
        }
    }
    canonical
}

/// Whether `shown`, a path without links, is the directory `state` is,
/// reached as it names it: a link Landlock would follow to the state's own
/// path is no alias.
fn is_same_directory(shown: &Path, state: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(shown), std::fs::metadata(state)) {
        (Ok(shown_metadata), Ok(state_metadata)) => {
            shown_metadata.dev() == state_metadata.dev()
                && shown_metadata.ino() == state_metadata.ino()
                && std::fs::canonicalize(shown).is_ok_and(|resolved| resolved == shown)
        }
        _ => false,
    }
}

/// A writable root that shows protected state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Alias {
    pub(crate) root: PathBuf,
    pub(crate) shown_at: PathBuf,
    pub(crate) state: PathBuf,
}

/// The first of `writable`, canonical paths, whose files are, hold or are
/// in a protected directory's other than as its path places them: its path
/// neither is in that directory nor holds it, or does but names other files
/// there, as a package's own directory in the state does when it is a bind
/// of the state; or that holds a mount showing other files than its path
/// did before it, which are, hold or are in a protected directory's,
/// wherever the mount's path is. Where the table can't place a root's or a
/// mount's files (NFS), it is an alias when, by `same_directory`, it is a
/// protected directory or holds one under the names that end its path,
/// which a directory below that one never does.
pub(crate) fn first_alias(
    table: &[Mount],
    writable: &[PathBuf],
    protected: &[PathBuf],
    same_directory: impl Fn(&Path, &Path) -> bool,
) -> Option<Alias> {
    let shows = |view: &Path, state: &Path| {
        let names: Vec<_> = state
            .components()
            .filter(|component| matches!(component, std::path::Component::Normal(_)))
            .collect();
        (0..=names.len()).any(|count| {
            let shown = names[names.len() - count..]
                .iter()
                .fold(view.to_path_buf(), |path, name| path.join(name));
            same_directory(&shown, state)
        })
    };
    let located: Vec<(&PathBuf, (&str, PathBuf))> = protected
        .iter()
        .filter_map(|state| Some((state, filesystem_location(table, state)?)))
        .collect();
    let reaching = |device: &str, files: &Path| {
        located
            .iter()
            .find(|(_, (state_device, state_files))| {
                device == *state_device && related(files, state_files)
            })
            .map(|(state, _)| (*state).clone())
    };
    for root in writable {
        let state = match filesystem_location(table, root) {
            Some((device, files)) => located
                .iter()
                .find(|(state, (state_device, state_files))| {
                    device == *state_device
                        && related(&files, state_files)
                        && !placed_as_named(root, &files, state, state_files)
                })
                .map(|(state, _)| *state),
            None => protected
                .iter()
                .find(|state| !state.starts_with(root) && shows(root, state)),
        };
        if let Some(state) = state {
            return Some(Alias {
                root: root.clone(),
                shown_at: root.clone(),
                state: state.clone(),
            });
        }
        for (index, mount) in table.iter().enumerate() {
            if mount.mount_point == *root || !mount.mount_point.starts_with(root) {
                continue;
            }
            let Some((key, files)) = &mount.shows else {
                if let Some(state) = protected
                    .iter()
                    .find(|state| shows(&mount.mount_point, state))
                {
                    return Some(Alias {
                        root: root.clone(),
                        shown_at: mount.mount_point.clone(),
                        state: state.clone(),
                    });
                }
                continue;
            };
            let Some(state) = reaching(key, files) else {
                continue;
            };
            // The mounts before it, scanned only for one that relates to the
            // state, tell a bind of a directory onto itself.
            let before = filesystem_location(&table[..index], &mount.mount_point);
            if before.as_ref().is_some_and(|(before_key, before_files)| {
                before_key == key && before_files == files
            }) {
                continue;
            }
            return Some(Alias {
                root: root.clone(),
                shown_at: mount.mount_point.clone(),
                state,
            });
        }
    }
    None
}

fn related(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Whether `root`, whose files are `files`, is in `state` or holds it, the
/// state's files being `state_files`, with the files its path names there:
/// the two are as far apart on the filesystem as their paths are.
fn placed_as_named(root: &Path, files: &Path, state: &Path, state_files: &Path) -> bool {
    if let Ok(below) = root.strip_prefix(state) {
        files == state_files.join(below)
    } else if let Ok(below) = state.strip_prefix(root) {
        state_files == files.join(below)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &[u8] = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
        30 22 8:2 / /home rw - ext4 /dev/sda2 rw\n\
        40 30 8:2 /u/proj/.lpm /home/u/proj/mirror rw - ext4 /dev/sda2 rw\n\
        41 30 8:2 /u/proj/.lpm/certs /home/u/proj/node_modules/x/certs rw - ext4 /dev/sda2 rw\n\
        42 22 8:2 /u /mnt/alias rw - ext4 /dev/sda2 rw\n\
        43 22 8:2 /u/.lpm /srv/home rw - ext4 /dev/sda2 rw\n\
        44 30 8:2 /u/proj/.lpm /home/u/proj/.lpm/wrappers/a/mirror rw - ext4 /dev/sda2 rw\n\
        45 30 8:2 /u/.lpm /home/u/.lpm/store/v2/links/b/node_modules/b/mirror rw - ext4 /dev/sda2 rw\n\
        46 30 8:2 /u/proj/.lpm/wrappers/c/same /home/u/proj/.lpm/wrappers/c/same rw - ext4 /dev/sda2 rw\n\
        47 30 8:2 /u/proj/.lpm /home/u/.lpm/store/v2/links/d/node_modules/d rw - ext4 /dev/sda2 rw\n\
        48 30 8:2 /u/proj/.git /home/u/proj/.husky/control rw - ext4 /dev/sda2 rw\n\
        49 30 8:2 /u/proj/.lpm /home/u/proj/.lpm/wrappers/e rw - ext4 /dev/sda2 rw\n\
        57 30 8:2 /u/.lpm /home/u/.lpm/store/v2/links/f/node_modules/f rw - ext4 /dev/sda2 rw\n\
        58 30 8:2 /u/proj/.lpm/certs /home/u/proj/.lpm/wrappers/g rw - ext4 /dev/sda2 rw\n\
        59 30 8:2 /u/.lpm/store/v2/links/a/node_modules/a /home/u/.lpm/store/v2/links/h/node_modules/h rw - ext4 /dev/sda2 rw\n";

    fn alias(writable: &str) -> Option<Alias> {
        let table = lpm_common::mounts::parse_mount_table(TABLE).unwrap();
        first_alias(
            &table,
            &[PathBuf::from(writable)],
            &[
                PathBuf::from("/home/u/proj/.lpm"),
                PathBuf::from("/home/u/.lpm"),
                PathBuf::from("/home/u/proj/.git"),
            ],
            |_, _| false,
        )
    }

    #[test]
    fn a_writable_directory_that_shows_lpm_state_through_a_mount_is_found() {
        // A bind mount of `.lpm` as the directory itself, one below a
        // built-in root, one of a directory holding the state, and one of
        // the LPM home.
        for (writable, shown_at, state) in [
            (
                "/home/u/proj/mirror",
                "/home/u/proj/mirror",
                "/home/u/proj/.lpm",
            ),
            (
                "/home/u/proj/node_modules",
                "/home/u/proj/node_modules/x/certs",
                "/home/u/proj/.lpm",
            ),
            ("/mnt/alias", "/mnt/alias", "/home/u/proj/.lpm"),
            ("/srv", "/srv/home", "/home/u/.lpm"),
            // A mount inside a package's own directory in the state, which
            // shows the rest of it.
            (
                "/home/u/proj/.lpm/wrappers/a",
                "/home/u/proj/.lpm/wrappers/a/mirror",
                "/home/u/proj/.lpm",
            ),
            (
                "/home/u/.lpm/store/v2/links/b/node_modules/b",
                "/home/u/.lpm/store/v2/links/b/node_modules/b/mirror",
                "/home/u/.lpm",
            ),
            // A package directory in the LPM home that is a bind of the
            // project's `.lpm`.
            (
                "/home/u/.lpm/store/v2/links/d/node_modules/d",
                "/home/u/.lpm/store/v2/links/d/node_modules/d",
                "/home/u/proj/.lpm",
            ),
            // The repository's hooks and config.
            (
                "/home/u/proj/.husky",
                "/home/u/proj/.husky/control",
                "/home/u/proj/.git",
            ),
            // A package's own directory in the state that is a bind of the
            // state it is in.
            (
                "/home/u/proj/.lpm/wrappers/e",
                "/home/u/proj/.lpm/wrappers/e",
                "/home/u/proj/.lpm",
            ),
            (
                "/home/u/.lpm/store/v2/links/f/node_modules/f",
                "/home/u/.lpm/store/v2/links/f/node_modules/f",
                "/home/u/.lpm",
            ),
            // A package's own directory that is a bind of another part of
            // the state: `.lpm/certs`, or another package's store directory.
            (
                "/home/u/proj/.lpm/wrappers/g",
                "/home/u/proj/.lpm/wrappers/g",
                "/home/u/proj/.lpm",
            ),
            (
                "/home/u/.lpm/store/v2/links/h/node_modules/h",
                "/home/u/.lpm/store/v2/links/h/node_modules/h",
                "/home/u/.lpm",
            ),
        ] {
            assert_eq!(
                alias(writable),
                Some(Alias {
                    root: PathBuf::from(writable),
                    shown_at: PathBuf::from(shown_at),
                    state: PathBuf::from(state),
                }),
                "{writable}"
            );
        }
    }

    /// NFS writes `/` as every mount's root and gives a mount with other
    /// options a device of its own; its source names the server directory
    /// the mount shows, a bind's included.
    const NFS: &[u8] = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
        50 22 0:52 / /home/u rw - nfs4 fs1:/export/home/u rw,vers=4.2,addr=10.0.0.5\n\
        51 22 0:52 / /proj/app rw - nfs4 fs1:/export/proj/app rw,vers=4.2,addr=10.0.0.5\n\
        52 22 0:52 / /app rw - nfs4 fs1:/export/home/u/proj rw,vers=4.2,addr=10.0.0.5\n\
        53 22 0:52 / /root/.lpm rw - nfs4 fs1:/export/home/u/.lpm rw,vers=4.2,addr=10.0.0.5\n\
        54 52 0:52 / /app/node_modules/x rw - nfs4 fs1:/export/home/u/proj rw,vers=4.2,addr=10.0.0.5\n\
        55 22 0:53 / /tmp/s/view rw - nfs4 fs1:/export rw,vers=4.2,soft,addr=10.0.0.5\n\
        56 52 0:52 / /app/.lpm/wrappers/a rw - nfs4 fs1:/export/home/u/proj/.lpm rw,vers=4.2,addr=10.0.0.5\n\
        57 52 0:52 / /app/node_modules/c rw - nfs4 fs1:/export/home/u/proj/.lpm/certs rw,vers=4.2,addr=10.0.0.5\n\
        58 22 0:54 / /mnt/v rw - nfs4 fs1:/export/home rw,vers=4.2,soft,addr=10.0.0.5\n";

    fn nfs_alias(writable: &str, protected: &[&str]) -> Option<Alias> {
        let table = lpm_common::mounts::parse_mount_table(NFS).unwrap();
        let protected: Vec<PathBuf> = protected.iter().map(PathBuf::from).collect();
        first_alias(&table, &[PathBuf::from(writable)], &protected, |_, _| false)
    }

    #[test]
    fn mounts_of_one_nfs_filesystem_are_no_aliases_of_each_other() {
        // The project and the home, or a container's binds of them, from
        // one server filesystem.
        for (writable, protected) in [
            (
                "/home/u/.lpm/store/v2/links/a/node_modules/a",
                ["/proj/app/.lpm", "/home/u/.lpm"],
            ),
            ("/proj/app/node_modules", ["/proj/app/.lpm", "/home/u/.lpm"]),
            ("/home/u/.cache", ["/proj/app/.lpm", "/home/u/.lpm"]),
            (
                "/root/.lpm/store/v2/links/a/node_modules/a",
                ["/app/.lpm", "/root/.lpm"],
            ),
        ] {
            assert_eq!(nfs_alias(writable, &protected), None, "{writable}");
        }
    }

    #[test]
    fn an_nfs_mount_showing_protected_state_is_found_by_the_directory_its_source_names() {
        for (writable, shown_at, state) in [
            // A bind of the project below `node_modules`, which holds `.lpm`.
            ("/app/node_modules", "/app/node_modules/x", "/app/.lpm"),
            // A bind of a directory in `.lpm`.
            ("/app/node_modules/c", "/app/node_modules/c", "/app/.lpm"),
            // A view of the home's parent, mounted with other options.
            ("/tmp/s", "/tmp/s/view", "/home/u/.lpm"),
            ("/mnt/v", "/mnt/v", "/home/u/.lpm"),
            // A package's own directory in `.lpm` that is a bind of it.
            ("/app/.lpm/wrappers/a", "/app/.lpm/wrappers/a", "/app/.lpm"),
        ] {
            assert_eq!(
                nfs_alias(writable, &[state]),
                Some(Alias {
                    root: PathBuf::from(writable),
                    shown_at: PathBuf::from(shown_at),
                    state: PathBuf::from(state),
                }),
                "{writable}"
            );
        }
    }

    /// Mounts whose line names no directory, NFS ones with a source that
    /// isn't `server:/path`, are checked by identity.
    const UNPLACED: &[u8] = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
        60 22 0:60 / /proj/app rw - nfs4 fs1 rw\n\
        61 22 0:60 / /home/u rw - nfs4 fs1 rw\n";

    fn unplaced_alias(writable: &str, protected: &[&str], same: &[(&str, &str)]) -> Option<Alias> {
        let table = lpm_common::mounts::parse_mount_table(UNPLACED).unwrap();
        let protected: Vec<PathBuf> = protected.iter().map(PathBuf::from).collect();
        first_alias(
            &table,
            &[PathBuf::from(writable)],
            &protected,
            |shown: &Path, state: &Path| {
                same.iter()
                    .any(|(a, b)| shown == Path::new(a) && state == Path::new(b))
            },
        )
    }

    #[test]
    fn a_mount_its_line_doesn_t_place_is_checked_by_identity() {
        // A root that holds the state under its own names.
        assert_eq!(
            unplaced_alias(
                "/proj/app/node_modules",
                &["/home/u/.lpm"],
                &[("/proj/app/node_modules/u/.lpm", "/home/u/.lpm")]
            ),
            Some(Alias {
                root: PathBuf::from("/proj/app/node_modules"),
                shown_at: PathBuf::from("/proj/app/node_modules"),
                state: PathBuf::from("/home/u/.lpm"),
            })
        );
        // A package's own directory in `.lpm` that is `.lpm` itself, and one
        // that holds the repository, found through the second protected
        // directory once the first relates by path.
        for (writable, same, state) in [
            (
                "/proj/app/.lpm/wrappers/a",
                ("/proj/app/.lpm/wrappers/a", "/proj/app/.lpm"),
                "/proj/app/.lpm",
            ),
            (
                "/proj/app/.lpm/wrappers/f",
                ("/proj/app/.lpm/wrappers/f/.git", "/proj/app/.git"),
                "/proj/app/.git",
            ),
        ] {
            assert_eq!(
                unplaced_alias(writable, &["/proj/app/.lpm", "/proj/app/.git"], &[same]),
                Some(Alias {
                    root: PathBuf::from(writable),
                    shown_at: PathBuf::from(writable),
                    state: PathBuf::from(state),
                }),
                "{writable}"
            );
        }
        assert_eq!(
            unplaced_alias("/proj/app/node_modules", &["/home/u/.lpm"], &[]),
            None
        );
    }

    /// The thread's CPU time, which other load on the machine doesn't
    /// stretch.
    fn thread_cpu_time() -> std::time::Duration {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `time` is writable storage of the type the call fills.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
            0
        );
        std::time::Duration::new(
            u64::try_from(time.tv_sec).unwrap(),
            u32::try_from(time.tv_nsec).unwrap(),
        )
    }

    /// A container can bind each package below `node_modules`; each such
    /// mount is weighed against the state once, not against every mount
    /// before it.
    #[test]
    fn many_mounts_below_a_writable_root_are_checked_in_linear_time() {
        let mut table = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n".to_vec();
        for index in 0..10_000 {
            table.extend(
                format!(
                    "{} 22 8:1 /sources/p{index} /work/proj/node_modules/p{index} rw - ext4 /dev/sda1 rw\n",
                    100 + index
                )
                .as_bytes(),
            );
        }
        let table = lpm_common::mounts::parse_mount_table(&table).unwrap();
        let protected = [
            PathBuf::from("/work/proj/.lpm"),
            PathBuf::from("/home/u/.lpm"),
            PathBuf::from("/work/proj/.git"),
        ];

        let start = thread_cpu_time();
        let alias = first_alias(
            &table,
            &[PathBuf::from("/work/proj/node_modules")],
            &protected,
            |_, _| false,
        );
        let spent = thread_cpu_time() - start;

        assert_eq!(alias, None);
        assert!(spent < std::time::Duration::from_millis(500), "{spent:?}");
    }

    #[test]
    fn a_link_to_the_state_is_no_view_of_it() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let state = root.join("proj/.lpm");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(root.join("view")).unwrap();
        std::os::unix::fs::symlink(&state, root.join("view/.lpm")).unwrap();
        assert!(!is_same_directory(&root.join("view/.lpm"), &state));
        assert!(is_same_directory(&state, &state));
    }

    #[test]
    fn the_repository_s_git_directories_are_protected_with_the_state() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("repository/proj");
        let lpm_home = directory.path().join("lpm-home");
        let git = directory.path().join("repository/.git");
        for created in [
            project.join(".lpm"),
            git.join("objects"),
            git.join("refs"),
            lpm_home.clone(),
        ] {
            std::fs::create_dir_all(created).unwrap();
        }
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let canonical = |path: PathBuf| std::fs::canonicalize(path).unwrap();
        assert_eq!(
            protected_state(&project, Some(&lpm_home)),
            [
                canonical(project.join(".lpm")),
                canonical(lpm_home.clone()),
                canonical(git.clone())
            ]
        );

        // A worktree's own git directory, and the common one its hooks and
        // config are in.
        let worktree_git = git.join("worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::write(worktree_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        let checkout = directory.path().join("feature");
        std::fs::create_dir(&checkout).unwrap();
        std::fs::write(
            checkout.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        assert_eq!(
            protected_state(&checkout, None),
            [canonical(worktree_git), canonical(git)]
        );
    }

    #[test]
    fn a_writable_directory_its_own_path_places_is_no_alias() {
        // The package's directory in the LPM home's store, a directory
        // beside `.lpm`, and one through a bind of the home that doesn't
        // reach the state.
        for writable in [
            "/home/u/.lpm/store/v2/links/a/node_modules/a",
            "/home/u/proj/build",
            "/mnt/alias/proj/build",
            "/tmp/lpm-script",
            // A bind of a directory onto itself shows what its path did.
            "/home/u/proj/.lpm/wrappers/c",
        ] {
            assert_eq!(alias(writable), None, "{writable}");
        }
    }
}
