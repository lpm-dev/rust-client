//! The marker a cached task's processes report to (see
//! [`lpm_vault::override_marker`]): each cached task has a directory of its
//! own, so only that task, and what depends on it, stays out of the task
//! caches when an `lpm` it starts reads what its key doesn't hold. A task's
//! processes get it with the markers this process inherited, so every `lpm`
//! above learns of the read too.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use lpm_vault::override_marker::Access;
pub use lpm_vault::override_marker::MARKER_ENV;

thread_local! {
    /// The marker list the task this thread starts gets, while it's watched.
    static WATCHED: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A task's own marker, watched until it's dropped: the processes the task
/// starts on this thread report to it and to the markers this process
/// inherited.
#[must_use]
pub struct TaskMarker {
    /// The task's directory; `None` when it couldn't be made or passed to
    /// the task, so what the task reads can't be told.
    directory: Option<PathBuf>,
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
        let directory = new_marker_directory(temporary);
        let list = directory.as_ref().and_then(|directory| {
            std::env::join_paths(
                lpm_vault::override_marker::inherited()
                    .iter()
                    .chain(std::iter::once(directory)),
            )
            .ok()?
            .into_string()
            .ok()
        });
        let directory = match (directory, &list) {
            (Some(directory), Some(_)) => Some(directory),
            (directory, _) => {
                if let Some(directory) = directory {
                    let _ = std::fs::remove_dir(directory);
                }
                lpm_vault::override_marker::report_uncertain()?;
                None
            }
        };
        let previous = WATCHED.with_borrow_mut(|watched| std::mem::replace(watched, list));
        Ok(Self {
            directory,
            previous,
        })
    }

    /// What keeps what the task built out of a cache whose key holds the
    /// values and personal overrides of the env project `keyed_vault`;
    /// `None` when every `lpm` the task started, if any, only read that
    /// project.
    pub fn unkeyed(&self, keyed_vault: Option<&str>) -> Option<Unkeyed> {
        match &self.directory {
            Some(directory) => unkeyed(directory, keyed_vault),
            None => Some(Unkeyed::Unknown),
        }
    }
}

/// Why what a task built can't be cached under its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unkeyed {
    /// An `lpm` the task started used another env project, or changed
    /// personal overrides.
    Used,
    /// What the task's `lpm` processes used can't be told: its marker
    /// couldn't be made, passed or listed, or holds an entry no `lpm` adds.
    Unknown,
}

/// [`TaskMarker::unkeyed`] for the entries in `directory`. A use the key
/// doesn't hold is named before what can't be told.
fn unkeyed(directory: &Path, keyed_vault: Option<&str>) -> Option<Unkeyed> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Some(Unkeyed::Unknown);
    };
    let mut found = None;
    for entry in entries {
        let reason = match entry {
            Ok(entry) => match entry.file_name().to_str().and_then(Access::of_entry) {
                Some(Access::Read(vault_id)) if keyed_vault == Some(vault_id) => continue,
                Some(Access::Read(_) | Access::Change(_)) => Unkeyed::Used,
                Some(Access::Uncertain) | None => Unkeyed::Unknown,
            },
            Err(_) => Unkeyed::Unknown,
        };
        if reason == Unkeyed::Used {
            return Some(reason);
        }
        found = Some(reason);
    }
    found
}

impl Drop for TaskMarker {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
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
/// so a process in another folder reports to the same one. `None` when it
/// can't be made.
fn new_marker_directory(temporary: &Path) -> Option<PathBuf> {
    use std::hash::{BuildHasher as _, Hasher as _};

    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let directory = std::path::absolute(temporary.join(format!(
        "lpm-personal-overrides-{}-{random:016x}",
        std::process::id()
    )))
    .ok()?;
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        let mut builder = builder;
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
    };
    builder.create(&directory).ok()?;
    Some(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(directory: &Path, access: Access<'_>) {
        std::fs::write(directory.join(access.entry()), "").expect("a nested lpm reports");
    }

    #[test]
    fn a_task_reports_to_its_own_marker_while_it_is_watched() {
        let outer = marker();
        let task = TaskMarker::watch().expect("watch");
        let directory = task.directory.clone().expect("a marker of its own");
        assert!(directory.is_absolute());
        assert_eq!(marker().as_deref(), directory.to_str());
        assert_eq!(task.unkeyed(Some("vault-1")), None, "nothing read yet");
        assert_eq!(task.unkeyed(None), None);

        report(&directory, Access::Read("vault-1"));
        assert_eq!(task.unkeyed(Some("vault-1")), None, "a read the key holds");
        assert_eq!(
            task.unkeyed(None),
            Some(Unkeyed::Used),
            "a task of a project without one"
        );
        drop(task);

        assert!(!directory.exists(), "the marker goes with the task");
        assert_eq!(marker(), outer);
    }

    #[test]
    fn a_read_of_another_project_or_a_change_or_an_uncertain_one_is_reported() {
        for (access, reason) in [
            (Access::Read("vault-2"), Unkeyed::Used),
            (Access::Change("vault-1"), Unkeyed::Used),
            (Access::Uncertain, Unkeyed::Unknown),
        ] {
            let task = TaskMarker::watch().expect("watch");
            report(task.directory.as_deref().expect("marker"), access);
            assert_eq!(task.unkeyed(Some("vault-1")), Some(reason), "{access:?}");
        }
    }

    #[test]
    fn a_marker_that_can_t_be_listed_or_an_unknown_entry_counts_as_read() {
        let root = tempfile::tempdir().expect("temporary folder");
        assert_eq!(
            unkeyed(&root.path().join("gone"), Some("vault-1")),
            Some(Unkeyed::Unknown)
        );

        let unknown = root.path().join("unknown");
        std::fs::create_dir(&unknown).expect("marker");
        std::fs::write(unknown.join("write-vault-1"), "").expect("entry");
        assert_eq!(unkeyed(&unknown, Some("vault-1")), Some(Unkeyed::Unknown));

        let similar = root.path().join("similar");
        std::fs::create_dir(&similar).expect("marker");
        std::fs::write(similar.join("read-vault-1.tmp"), "").expect("entry");
        assert_eq!(
            unkeyed(&similar, Some("vault-1")),
            Some(Unkeyed::Used),
            "a read of the project vault-1.tmp"
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
                assert_eq!(unkeyed(&not_utf8, Some("vault-1")), Some(Unkeyed::Unknown));
            }

            let unreadable = root.path().join("unreadable");
            std::fs::create_dir(&unreadable).expect("marker");
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o300))
                .expect("make it unreadable");
            let listed = std::fs::read_dir(&unreadable).is_ok();
            assert!(listed || unkeyed(&unreadable, Some("vault-1")) == Some(Unkeyed::Unknown));
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

        assert!(task.directory.is_none());
        assert_eq!(task.unkeyed(Some("vault-1")), Some(Unkeyed::Unknown));
        assert_eq!(task.unkeyed(None), Some(Unkeyed::Unknown));
        assert_eq!(marker(), outer, "the task gets the inherited markers");
        assert_eq!(
            std::fs::read_dir(&separated).expect("folder").count(),
            0,
            "the marker that couldn't be passed is gone"
        );
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
