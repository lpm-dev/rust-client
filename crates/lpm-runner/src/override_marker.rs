//! Whether an `lpm` a task started applied this computer's personal
//! overrides, which a task cache that shares outputs must know: the task's
//! own environment can't show what a nested `lpm run` or `lpm env print`
//! read for another environment.
//!
//! An `lpm` that may share task outputs passes its tasks a marker path. An
//! `lpm` that inherits one creates that file once it applies an override,
//! and passes the same path on, so every depth reports to the outermost.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, OnceLock};

/// The variable that carries the marker path to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// The marker this process inherited from the `lpm` that started it.
static INHERITED: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    std::env::var_os(MARKER_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
});

/// The marker this process made for its own tasks, when it inherited none.
static OWN: OnceLock<PathBuf> = OnceLock::new();

static RECORDED: AtomicBool = AtomicBool::new(false);

/// Have the tasks this process starts report personal overrides they apply
/// through a nested `lpm`, before the first of them starts.
pub fn watch_nested_personal_overrides() {
    if INHERITED.is_none() {
        OWN.get_or_init(new_marker_path);
    }
}

/// The marker path this process's tasks get, when it has one.
pub(crate) fn marker() -> Option<&'static Path> {
    INHERITED
        .as_deref()
        .or_else(|| OWN.get().map(PathBuf::as_path))
}

/// Report to the `lpm` that started this one that it applied a personal
/// override. The file is only ever created, never followed or written to,
/// so whatever lies at the path is left alone.
pub(crate) fn record_personal_overrides_applied() {
    let Some(path) = INHERITED.as_deref() else {
        return;
    };
    if RECORDED.swap(true, Ordering::Relaxed) {
        return;
    }
    if let Err(error) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        tracing::warn!(
            "couldn't tell the lpm that started this one that personal overrides apply: {error}"
        );
    }
}

/// Whether an `lpm` this process's tasks started applied a personal
/// override, or, under an outer `lpm`, any `lpm` that reports to it did.
pub fn nested_personal_overrides_applied() -> bool {
    marker().is_some_and(|path| path.symlink_metadata().is_ok())
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

/// Remove this process's own marker once its tasks have all ended.
pub fn forget_nested_personal_overrides() {
    if let Some(path) = OWN.get() {
        let _ = std::fs::remove_file(path);
    }
}
