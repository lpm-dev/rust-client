//! The marker a cached task's processes report to when an `lpm` they start
//! reads personal overrides (see [`lpm_vault::override_marker`]): each cached
//! task has its own, so only that task, and what depends on it, stays out of
//! the task caches. A task's processes get it with the markers this process
//! inherited, so every `lpm` above learns of the read too.

use std::cell::RefCell;
use std::path::PathBuf;

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
    path: PathBuf,
    /// The marker list couldn't be passed to the task, so a read can't be
    /// ruled out.
    undelivered: bool,
    previous: Option<String>,
}

impl TaskMarker {
    /// A marker of its own for the task this thread starts next. One that
    /// can't be passed counts as read, which the `lpm` processes above are
    /// told at once.
    pub fn watch() -> Result<Self, String> {
        let path = new_marker_path();
        let list = std::env::join_paths(
            lpm_vault::override_marker::inherited()
                .iter()
                .chain(path.as_ref()),
        )
        .ok()
        .and_then(|list| list.into_string().ok());
        let undelivered = path.is_none() || list.is_none();
        if undelivered {
            lpm_vault::override_marker::report_read()?;
        }
        let previous = WATCHED.with_borrow_mut(|watched| std::mem::replace(watched, list));
        Ok(Self {
            path: path.unwrap_or_default(),
            undelivered,
            previous,
        })
    }

    /// Whether an `lpm` the task started read personal overrides: its marker
    /// is there, can't be told absent, or couldn't be passed to the task.
    pub fn read_overrides(&self) -> bool {
        self.undelivered
            || !matches!(
                self.path.symlink_metadata(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
    }
}

impl Drop for TaskMarker {
    fn drop(&mut self) {
        if !self.undelivered {
            let _ = std::fs::remove_file(&self.path);
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

/// A path no file is at yet, private to this process: in the user's
/// temporary directory, named by the process and a random number, absolute
/// so a process in another folder reports to the same file. `None` when it
/// can't be made absolute.
fn new_marker_path() -> Option<PathBuf> {
    use std::hash::{BuildHasher as _, Hasher as _};

    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    std::path::absolute(std::env::temp_dir().join(format!(
        "lpm-personal-overrides-{}-{random:016x}",
        std::process::id()
    )))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_reports_to_its_own_marker_while_it_is_watched() {
        let outer = marker();
        let task = TaskMarker::watch().expect("watch");
        assert!(task.path.is_absolute());
        assert_eq!(marker().as_deref(), task.path.to_str());
        assert!(!task.read_overrides());

        std::fs::write(&task.path, "").expect("a nested lpm reports");
        assert!(task.read_overrides());
        let path = task.path.clone();
        drop(task);

        assert!(!path.exists(), "the marker goes with the task");
        assert_eq!(marker(), outer);
    }
}
