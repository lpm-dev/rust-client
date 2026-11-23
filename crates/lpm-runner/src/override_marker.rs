//! The markers a cached task's processes report to when an `lpm` they start
//! reads personal overrides (see [`lpm_vault::override_marker`]): each
//! cached task has its own, so only that task, and what depends on it, stays
//! out of the task caches.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

pub use lpm_vault::override_marker::MARKER_ENV;

thread_local! {
    /// The marker of the task this thread starts, while it's watched.
    static WATCHED: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// A task's own marker, watched until it's dropped: the processes the task
/// starts on this thread report to it, not to the marker this process
/// inherited.
#[must_use]
pub struct TaskMarker {
    path: PathBuf,
    previous: Option<PathBuf>,
}

impl TaskMarker {
    /// A marker of its own for the task this thread starts next.
    pub fn watch() -> Self {
        let path = new_marker_path();
        let previous = WATCHED.with_borrow_mut(|watched| watched.replace(path.clone()));
        Self { path, previous }
    }

    /// Whether an `lpm` the task started read personal overrides: its marker
    /// is there, can't be told absent, or couldn't be passed to the task.
    pub fn read_overrides(&self) -> bool {
        self.path.to_str().is_none()
            || !matches!(
                self.path.symlink_metadata(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            )
    }
}

impl Drop for TaskMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let previous = self.previous.take();
        WATCHED.with_borrow_mut(|watched| *watched = previous);
    }
}

/// The marker the processes this thread starts report to: the watched
/// task's, or the one this process inherited.
pub(crate) fn marker() -> Option<PathBuf> {
    WATCHED
        .with_borrow(Clone::clone)
        .or_else(|| lpm_vault::override_marker::inherited().map(Path::to_path_buf))
}

/// A path no file is at yet, private to this process: in the user's
/// temporary directory, named by the process and a random number.
fn new_marker_path() -> PathBuf {
    use std::hash::{BuildHasher as _, Hasher as _};

    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    std::env::temp_dir().join(format!(
        "lpm-personal-overrides-{}-{random:016x}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_reports_to_its_own_marker_while_it_is_watched() {
        let outer = marker();
        let task = TaskMarker::watch();
        assert_eq!(marker().as_deref(), Some(task.path.as_path()));
        assert!(!task.read_overrides());

        std::fs::write(&task.path, "").expect("a nested lpm reports");
        assert!(task.read_overrides());
        let path = task.path.clone();
        drop(task);

        assert!(!path.exists(), "the marker goes with the task");
        assert_eq!(marker(), outer);
    }
}
