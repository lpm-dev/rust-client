//! The marker a cached task's processes report to (see
//! [`lpm_vault::override_marker`]): each cached task has a directory of its
//! own, so only that task, and what depends on it, stays out of the task
//! caches when an `lpm` it starts reads what its key doesn't hold. A task's
//! processes get it with the markers this process inherited, so every `lpm`
//! above learns of the read too.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

pub use lpm_vault::override_marker::MARKER_ENV;
use lpm_vault::override_marker::Reported;

thread_local! {
    /// The marker list the task this thread starts gets, while it's watched.
    static WATCHED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A task's own marker, watched until it's dropped: the processes the task
/// starts on this thread report to it and to the markers this process
/// inherited.
#[must_use]
pub struct TaskMarker {
    /// The task's directory, or why it couldn't be made or passed to the
    /// task, so what the task reads can't be told.
    directory: Result<PathBuf, String>,
    previous: Option<String>,
}

impl TaskMarker {
    /// A marker of its own for the task this thread starts next. One that
    /// can't be made or passed is uncertain, which the `lpm` processes above
    /// are told at once.
    pub fn watch() -> Result<Self, String> {
        Self::watch_in(&std::env::temp_dir())
    }

    /// [`Self::watch`] with the marker in `temporary`.
    fn watch_in(temporary: &Path) -> Result<Self, String> {
        let directory = new_marker_directory(temporary).and_then(|directory| {
            let list = std::env::join_paths(
                lpm_vault::override_marker::inherited()
                    .iter()
                    .chain(std::iter::once(&directory)),
            )
            .ok()
            .and_then(|list| list.into_string().ok());
            match list {
                Some(list) => Ok((directory, list)),
                None => {
                    let _ = std::fs::remove_dir(&directory);
                    Err(format!(
                        "{} can't be passed to a process in a list of paths",
                        directory.display()
                    ))
                }
            }
        });
        if directory.is_err() {
            lpm_vault::override_marker::report_uncertain()?;
        }
        let (directory, list) = match directory {
            Ok((directory, list)) => (Ok(directory), Some(list)),
            Err(reason) => (Err(reason), None),
        };
        let previous = WATCHED.with_borrow_mut(|watched| std::mem::replace(watched, list));
        Ok(Self {
            directory,
            previous,
        })
    }

    /// Why the task has no marker of its own, when it has none.
    pub fn unwatched(&self) -> Option<&str> {
        self.directory.as_ref().err().map(String::as_str)
    }

    /// What keeps what the task built out of a cache whose key holds the
    /// reads that `keyed` entries report (see
    /// [`lpm_vault::override_marker::Access::keyed`]); `None`
    /// when every `lpm` the task started, if any, made only such reads.
    pub fn unkeyed(&self, keyed: &[String]) -> Option<Unkeyed> {
        match &self.directory {
            Ok(directory) => unkeyed(directory, keyed),
            Err(_) => Some(Unkeyed::Unwatched),
        }
    }
}

/// Why what a task built can't be cached under its key, the most specific
/// reason first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unkeyed {
    /// An `lpm` the task started changed personal overrides.
    Changed,
    /// An `lpm` the task started read, with personal overrides applied,
    /// what the key doesn't hold: another env project or environment, or
    /// values or overrides other than the key's.
    Used,
    /// An `lpm` the task started read every environment of an env project,
    /// as `lpm env ls` and `lpm env check` without `--env` do.
    EveryEnvironment,
    /// An `lpm` the task started couldn't make a marker for a task of its
    /// own, so what that task used can't be told.
    Untold,
    /// The marker was gone, or couldn't be listed, once the task ended, as
    /// when the task empties the temporary folder.
    Unlisted,
    /// The marker holds a file no `lpm` adds.
    Foreign,
    /// The task has no marker of its own (see [`TaskMarker::unwatched`]).
    Unwatched,
}

/// [`TaskMarker::unkeyed`] for the entries in `directory`.
fn unkeyed(directory: &Path, keyed: &[String]) -> Option<Unkeyed> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Some(Unkeyed::Unlisted);
    };
    let mut found: Option<Unkeyed> = None;
    for entry in entries {
        let reason = match entry {
            Err(_) => Unkeyed::Unlisted,
            Ok(entry) => match entry.file_name().to_str() {
                Some(name) if keyed.iter().any(|keyed| keyed == name) => continue,
                Some(name) => match Reported::of_entry(name) {
                    Some(Reported::Change) => return Some(Unkeyed::Changed),
                    Some(Reported::Environment | Reported::Overrides) => Unkeyed::Used,
                    Some(Reported::Environments) => Unkeyed::EveryEnvironment,
                    Some(Reported::Uncertain) => Unkeyed::Untold,
                    None => Unkeyed::Foreign,
                },
                None => Unkeyed::Foreign,
            },
        };
        found = Some(found.map_or(reason, |found| found.min(reason)));
    }
    found
}

impl Drop for TaskMarker {
    fn drop(&mut self) {
        if let Ok(directory) = &self.directory {
            let _ = std::fs::remove_dir_all(directory);
        }
        let previous = self.previous.take();
        WATCHED.with_borrow_mut(|watched| *watched = previous);
    }
}

/// The marker list the processes this thread starts get: the watched
/// task's, or the one this process inherited. It's UTF-8, as a runtime
/// value must be; an inherited list that isn't stays in this process's own
/// environment, which a process it starts inherits.
pub(crate) fn marker() -> Option<String> {
    WATCHED.with_borrow(Clone::clone).or_else(|| {
        let inherited = lpm_vault::override_marker::inherited();
        (!inherited.is_empty())
            .then(|| std::env::join_paths(inherited).ok()?.into_string().ok())
            .flatten()
    })
}

/// A new directory only this user can add to, in `temporary`, the user's
/// temporary directory, named by the process and a random number, absolute
/// so a process in another folder reports to the same one, or why it can't
/// be made.
fn new_marker_directory(temporary: &Path) -> Result<PathBuf, String> {
    use std::hash::{BuildHasher as _, Hasher as _};

    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let directory = temporary.join(format!(
        "lpm-personal-overrides-{}-{random:016x}",
        std::process::id()
    ));
    let directory = std::path::absolute(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        let mut builder = builder;
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
    };
    builder
        .create(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_vault::override_marker::Access;

    fn report(directory: &Path, access: Access<'_>) {
        std::fs::write(directory.join(access.entry()), "").expect("a nested lpm reports");
    }

    fn read(vault_id: &'static str, environment: &'static str, overrides: bool) -> Access<'static> {
        Access::Environment {
            vault_id,
            environment,
            values: None,
            overrides: overrides.then(record),
        }
    }

    fn record() -> lpm_vault::OverridesIdentity {
        lpm_vault::OverridesIdentity::of(b"record")
    }

    fn keyed() -> [String; 2] {
        Access::keyed("vault-1", "default", None, None)
    }

    #[test]
    fn a_task_reports_to_its_own_marker_while_it_is_watched() {
        let outer = marker();
        let task = TaskMarker::watch().expect("watch");
        let directory = task.directory.clone().expect("a marker of its own");
        assert!(directory.is_absolute());
        assert!(
            marker().is_some_and(|list| {
                std::env::split_paths(&list).last().as_deref() == Some(directory.as_path())
            }),
            "its own marker comes after the ones this process inherited"
        );
        assert_eq!(task.unkeyed(&keyed()), None, "nothing read yet");
        assert_eq!(task.unkeyed(&[]), None);

        report(&directory, read("vault-1", "default", false));
        report(
            &directory,
            Access::Overrides {
                vault_id: "vault-1",
                overrides: None,
            },
        );
        assert_eq!(task.unkeyed(&keyed()), None, "reads the key holds");
        assert_eq!(
            task.unkeyed(&[]),
            Some(Unkeyed::Used),
            "a task of a project without one"
        );
        drop(task);

        assert!(!directory.exists(), "the marker goes with the task");
        assert_eq!(marker(), outer);
    }

    #[test]
    fn a_use_the_key_doesn_t_hold_keeps_the_task_out() {
        for (access, reason) in [
            (read("vault-2", "default", false), Unkeyed::Used),
            (read("Vault-1", "default", false), Unkeyed::Used),
            (read("vault-1", "staging", false), Unkeyed::Used),
            (read("vault-1", "default", true), Unkeyed::Used),
            (
                Access::Environment {
                    vault_id: "vault-1",
                    environment: "default",
                    values: Some(lpm_vault::ValuesIdentity::of(
                        &std::collections::HashMap::from([(
                            "API_URL".to_owned(),
                            "one".to_owned(),
                        )]),
                    )),
                    overrides: None,
                },
                Unkeyed::Used,
            ),
            (
                Access::Environments {
                    vault_id: "vault-1",
                    overrides: false,
                },
                Unkeyed::EveryEnvironment,
            ),
            (
                Access::Overrides {
                    vault_id: "vault-1",
                    overrides: Some(record()),
                },
                Unkeyed::Used,
            ),
            (
                Access::Change {
                    vault_id: "vault-1",
                },
                Unkeyed::Changed,
            ),
            (Access::Uncertain, Unkeyed::Untold),
        ] {
            let task = TaskMarker::watch().expect("watch");
            report(task.directory.as_deref().expect("marker"), access);
            assert_eq!(task.unkeyed(&keyed()), Some(reason), "{access:?}");
        }
    }

    #[test]
    fn a_marker_that_can_t_be_listed_or_holds_an_unknown_entry_can_t_be_told() {
        let root = tempfile::tempdir().expect("temporary folder");
        assert_eq!(
            unkeyed(&root.path().join("gone"), &keyed()),
            Some(Unkeyed::Unlisted)
        );

        let unknown = root.path().join("unknown");
        std::fs::create_dir(&unknown).expect("marker");
        std::fs::write(unknown.join("read-vault-1"), "").expect("entry");
        assert_eq!(unkeyed(&unknown, &keyed()), Some(Unkeyed::Foreign));

        let both = root.path().join("both");
        std::fs::create_dir(&both).expect("marker");
        std::fs::write(both.join("read-vault-1"), "").expect("entry");
        report(&both, Access::Uncertain);
        report(
            &both,
            Access::Environments {
                vault_id: "vault-1",
                overrides: false,
            },
        );
        assert_eq!(
            unkeyed(&both, &keyed()),
            Some(Unkeyed::EveryEnvironment),
            "a use is named before what can't be told"
        );
        report(&both, read("vault-2", "default", false));
        assert_eq!(unkeyed(&both, &keyed()), Some(Unkeyed::Used));
        report(
            &both,
            Access::Change {
                vault_id: "vault-2",
            },
        );
        assert_eq!(
            unkeyed(&both, &keyed()),
            Some(Unkeyed::Changed),
            "a change is named first"
        );

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            use std::os::unix::fs::PermissionsExt as _;

            // APFS refuses a name that isn't UTF-8; most Linux file
            // systems take it.
            let not_utf8 = root.path().join("not-utf8");
            std::fs::create_dir(&not_utf8).expect("marker");
            if std::fs::write(not_utf8.join(std::ffi::OsStr::from_bytes(b"read-\xff")), "").is_ok()
            {
                assert_eq!(unkeyed(&not_utf8, &keyed()), Some(Unkeyed::Foreign));
            }

            let unreadable = root.path().join("unreadable");
            std::fs::create_dir(&unreadable).expect("marker");
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o300))
                .expect("make it unreadable");
            let listed = std::fs::read_dir(&unreadable).is_ok();
            assert!(listed || unkeyed(&unreadable, &keyed()) == Some(Unkeyed::Unlisted));
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700))
                .expect("make it readable again");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_that_can_t_be_passed_to_the_task_is_uncertain() {
        let root = tempfile::tempdir().expect("temporary folder");
        let separated = root.path().join("a:b");
        std::fs::create_dir(&separated).expect("a folder whose path holds the separator");
        let outer = marker();

        let task = TaskMarker::watch_in(&separated).expect("watch");

        assert!(
            task.unwatched()
                .is_some_and(|reason| reason.contains("a:b"))
        );
        assert_eq!(task.unkeyed(&keyed()), Some(Unkeyed::Unwatched));
        assert_eq!(task.unkeyed(&[]), Some(Unkeyed::Unwatched));
        assert_eq!(marker(), outer, "the task gets the inherited markers");
        assert_eq!(
            std::fs::read_dir(&separated).expect("folder").count(),
            0,
            "the marker that couldn't be passed is gone"
        );
    }

    #[test]
    fn a_marker_that_can_t_be_made_says_why() {
        let root = tempfile::tempdir().expect("temporary folder");
        let gone = root.path().join("gone");

        let task = TaskMarker::watch_in(&gone).expect("watch");

        assert!(
            task.unwatched()
                .is_some_and(|reason| reason.contains("gone")),
            "{:?}",
            task.unwatched()
        );
        assert_eq!(task.unkeyed(&keyed()), Some(Unkeyed::Unwatched));
    }

    #[cfg(unix)]
    #[test]
    fn a_task_s_marker_is_its_user_s_alone() {
        use std::os::unix::fs::PermissionsExt as _;

        let task = TaskMarker::watch().expect("watch");
        let directory = task.directory.as_deref().expect("marker");
        let mode = std::fs::metadata(directory)
            .expect("marker")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
