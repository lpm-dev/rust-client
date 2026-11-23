//! Telling the `lpm` that started this one that it read this computer's
//! personal overrides, which a task cache that shares outputs must know: a
//! task's own environment can't show what a nested `lpm` read for another
//! environment or project.
//!
//! An `lpm` that caches a task passes it a marker path in
//! [`MARKER_ENV`]; an `lpm` that inherits one creates that file once it reads
//! a project's overrides. The file is only ever created, never followed or
//! written to.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// The variable that carries the marker path to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// The marker this process inherited from the `lpm` that started it.
static INHERITED: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    std::env::var_os(MARKER_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
});

static REPORTED: AtomicBool = AtomicBool::new(false);

/// The marker this process inherited, which the tasks it starts without one
/// of their own report to as well.
pub fn inherited() -> Option<&'static Path> {
    INHERITED.as_deref()
}

/// Tell the `lpm` that started this one that it read a project's personal
/// overrides, or that a task it started did. One that can't be told would
/// share what this one builds, so the read fails instead.
pub fn report_read() -> Result<(), String> {
    let Some(path) = inherited() else {
        return Ok(());
    };
    if REPORTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(format!(
                "couldn't tell the lpm that started this one that it read personal overrides, so it could share outputs built with them: {error}"
            ));
        }
    }
    REPORTED.store(true, Ordering::Relaxed);
    Ok(())
}
