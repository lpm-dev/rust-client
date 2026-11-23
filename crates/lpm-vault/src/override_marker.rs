//! Telling every `lpm` that started this one, however deep, which env
//! projects it read with their personal overrides, or whose overrides it
//! changed, which a task cache must know: a cached task's key holds its own
//! project's values and overrides, but not what a nested `lpm` reads of
//! another project.
//!
//! [`MARKER_ENV`] holds a `PATH`-style list of directories: an `lpm` that
//! caches a task makes a directory for it, adds it to the list it inherited,
//! and passes the list to the task. Before an `lpm` uses what it read, or
//! changes overrides, it adds an entry to every directory in the list, so
//! each `lpm` above it knows, whether or not those between them end well.
//! An entry is an empty file, only ever created, never followed or written
//! to. It names the env project and nothing of what was read, since
//! anything the same user runs can list it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

/// The variable that carries the marker directories to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// How the message of an access that couldn't be reported starts.
const UNREPORTED: &str = "couldn't tell an lpm that started this one which env project it uses";

/// Whether `message` is that of an access that couldn't be reported.
pub fn describes(message: &str) -> bool {
    message.starts_with(UNREPORTED)
}

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

/// The entries this process added to every inherited marker.
static REPORTED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

/// The markers this process inherited, which the tasks it starts report to
/// as well.
pub fn inherited() -> &'static [PathBuf] {
    &INHERITED
}

/// What an `lpm` below reported to a marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access<'a> {
    /// It read the env project's values with its personal overrides
    /// applied, or its overrides, which it may have none of.
    Read(&'a str),
    /// It changed the env project's personal overrides.
    Change(&'a str),
    /// What it read can't be told: it couldn't pass a marker to a task.
    Uncertain,
}

impl<'a> Access<'a> {
    /// The name of the entry that reports it: a vault ID is a safe file
    /// name, which [`crate::vault_id::is_safe_vault_id`] checks.
    pub fn entry(self) -> String {
        match self {
            Self::Read(vault_id) => format!("read-{vault_id}"),
            Self::Change(vault_id) => format!("change-{vault_id}"),
            Self::Uncertain => "uncertain".to_owned(),
        }
    }

    /// What the entry named `entry` reports; `None` for a name no `lpm`
    /// gives an entry.
    pub fn of_entry(entry: &'a str) -> Option<Self> {
        if entry == "uncertain" {
            return Some(Self::Uncertain);
        }
        let (kind, vault_id) = entry.split_once('-')?;
        if !crate::vault_id::is_safe_vault_id(vault_id) {
            return None;
        }
        match kind {
            "read" => Some(Self::Read(vault_id)),
            "change" => Some(Self::Change(vault_id)),
            _ => None,
        }
    }
}

/// Tell every `lpm` above this one that it read the env project `vault_id`
/// with its personal overrides, before anything uses what it read.
pub fn report_read(vault_id: &str) -> Result<(), String> {
    report(Access::Read(vault_id))
}

/// Tell every `lpm` above this one that it's about to change the personal
/// overrides of the env project `vault_id`.
pub fn report_change(vault_id: &str) -> Result<(), String> {
    report(Access::Change(vault_id))
}

/// Tell every `lpm` above this one that it can't tell what a task it
/// started reads.
pub fn report_uncertain() -> Result<(), String> {
    report(Access::Uncertain)
}

/// Add `access`'s entry to every inherited marker, once a process. One that
/// can't be told would share what this one builds, so the access fails
/// instead.
fn report(access: Access<'_>) -> Result<(), String> {
    if inherited().is_empty() {
        return Ok(());
    }
    let entry = access.entry();
    let mut reported = REPORTED.lock().unwrap_or_else(PoisonError::into_inner);
    if reported.contains(&entry) {
        return Ok(());
    }
    report_to(inherited(), &entry)?;
    reported.insert(entry);
    Ok(())
}

/// Create `entry` in each of `markers`, where an `lpm` above watches.
fn report_to(markers: &[PathBuf], entry: &str) -> Result<(), String> {
    for marker in markers {
        add_entry(marker, entry).map_err(|reason| {
            format!(
                "{UNREPORTED}, so that lpm could share outputs built with personal overrides: {MARKER_ENV} names {}, {reason}. Run this outside the task that lpm started, or remove {MARKER_ENV} from its environment if nothing above it caches what it builds",
                lpm_common::sanitize_terminal_inline(&marker.display().to_string())
            )
        })?;
    }
    Ok(())
}

fn add_entry(marker: &Path, entry: &str) -> Result<(), String> {
    if !marker.is_absolute() {
        return Err("which isn't an absolute path".to_owned());
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker.join(entry))
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err("which isn't there: the task that lpm started may have ended".to_owned())
        }
        Err(error) => Err(format!("where an entry can't be added ({error})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_names_the_project_and_what_was_done_to_it_and_nothing_read() {
        for access in [
            Access::Read("vault-1"),
            Access::Change("vault-1"),
            Access::Uncertain,
        ] {
            assert_eq!(Access::of_entry(&access.entry()), Some(access));
        }
        assert_eq!(Access::Read("vault-1").entry(), "read-vault-1");
        for unknown in [
            "read-",
            "read-..",
            "write-vault-1",
            "uncertain-vault-1",
            "read",
        ] {
            assert_eq!(Access::of_entry(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn a_read_is_reported_to_every_marker_above() {
        let root = tempfile::tempdir().expect("temporary folder");
        let markers = [root.path().join("outer"), root.path().join("inner")];
        for marker in &markers {
            std::fs::create_dir(marker).expect("marker");
        }

        report_to(&markers, "read-vault-1").expect("reported");
        report_to(&markers, "read-vault-1").expect("an entry that's there already");

        for marker in &markers {
            let entries: Vec<_> = std::fs::read_dir(marker)
                .expect("entries")
                .map(|entry| entry.expect("entry").file_name())
                .collect();
            assert_eq!(entries, ["read-vault-1"], "{}", marker.display());
        }
    }

    #[test]
    fn a_marker_that_can_t_be_told_fails_the_read() {
        let root = tempfile::tempdir().expect("temporary folder");
        let file = root.path().join("a-file");
        std::fs::write(&file, "").expect("a file where a marker would be");
        for (marker, reason) in [
            (PathBuf::from("relative"), "isn't an absolute path"),
            (root.path().join("gone"), "isn't there"),
            (file, "where an entry can't be added"),
        ] {
            let error =
                report_to(std::slice::from_ref(&marker), "read-vault-1").expect_err("refused");
            assert!(describes(&error), "{error}");
            assert!(error.contains(MARKER_ENV), "{error}");
            assert!(error.contains(reason), "{}: {error}", marker.display());
        }
    }
}
