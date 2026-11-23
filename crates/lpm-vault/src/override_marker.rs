//! Telling every `lpm` that started this one, however deep, that it read
//! this computer's personal overrides, which a task cache that shares
//! outputs must know: a task's own environment can't show what a nested
//! `lpm` read for another environment or project.
//!
//! [`MARKER_ENV`] holds a list of marker paths, as a `PATH`-style list: an
//! `lpm` that caches a task adds a marker of its own to what it inherited and
//! passes the list to the task. An `lpm` that reads a project's overrides
//! creates every marker in the list before it uses them, so each `lpm` above
//! it knows, whether or not those between them end well. A marker file is
//! only ever created, never followed or written to.

use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// The variable that carries the marker paths to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// The markers this process inherited from the `lpm` processes above it.
static INHERITED: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    std::env::var_os(MARKER_ENV)
        .map(|list| {
            std::env::split_paths(&list)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default()
});

static REPORTED: AtomicBool = AtomicBool::new(false);

/// The markers this process inherited, which the tasks it starts report to
/// as well.
pub fn inherited() -> &'static [PathBuf] {
    &INHERITED
}

/// Tell every `lpm` above this one that it read a project's personal
/// overrides, or that a task it started did, before anything uses them. One
/// that can't be told would share what this one builds, so the read fails
/// instead.
pub fn report_read() -> Result<(), String> {
    if REPORTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    for path in inherited() {
        let refused = |reason: &dyn std::fmt::Display| {
            format!(
                "couldn't tell an lpm that started this one that it read personal overrides, so it could share outputs built with them: {reason}"
            )
        };
        if !path.is_absolute() {
            return Err(refused(&format!(
                "{} names a path that isn't absolute",
                MARKER_ENV
            )));
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(refused(&error)),
        }
    }
    REPORTED.store(true, Ordering::Relaxed);
    Ok(())
}
