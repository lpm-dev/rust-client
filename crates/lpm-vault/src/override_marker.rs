//! Telling every `lpm` that started this one, however deep, which env
//! projects it read with their personal overrides, or whose overrides it
//! changed, which a task cache must know: a cached task's key holds one
//! environment's values of its own project, and that project's overrides,
//! but not what a nested `lpm` reads otherwise.
//!
//! [`MARKER_ENV`] holds a `PATH`-style list of directories: an `lpm` that
//! caches a task makes a directory for it, adds it to the list it inherited,
//! and passes the list to the task. Before an `lpm` uses what it read, or
//! changes overrides, it adds an entry to every directory in the list, so
//! each `lpm` above it knows, whether or not those between them end well.
//! An entry is an empty file, only ever created, never followed or written
//! to. Its name is the kind of access and a digest of the store, project
//! and environment it touched and whether the project had overrides, so
//! names that differ only in case, as some file systems can't keep apart,
//! never meet, and nothing of what was read is in it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

/// The variable that carries the marker directories to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// How the message of an access that couldn't be reported starts: with
/// [`MARKER_ENV`] and the marker it names.
const UNREPORTED: &str = "LPM_PERSONAL_OVERRIDES_MARKER names ";

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

/// The store this process reads env projects from: its LPM home, which
/// chooses both the file store and the Keychain's services, as one
/// comparable value. Empty when there's none, and then nothing is read.
static STORE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    lpm_common::paths::LpmRoot::from_env()
        .map(|root| root.identity().into_os_string().into_encoded_bytes())
        .unwrap_or_default()
});

/// The markers this process inherited, which the tasks it starts report to
/// as well.
pub fn inherited() -> &'static [PathBuf] {
    &INHERITED
}

/// What an `lpm` below reported to a marker, of the env project with
/// `vault_id` in this process's store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access<'a> {
    /// It read `environment`'s values with the project's personal overrides
    /// applied; `overrides` when the project had any.
    Environment {
        vault_id: &'a str,
        environment: &'a str,
        overrides: bool,
    },
    /// It read every environment's values with the project's overrides
    /// applied.
    Environments { vault_id: &'a str, overrides: bool },
    /// It read the project's overrides of every environment.
    Overrides { vault_id: &'a str, overrides: bool },
    /// It changed the project's overrides.
    Change { vault_id: &'a str },
    /// What it used can't be told: it couldn't pass a marker to a task.
    Uncertain,
}

/// The name of the entry that reports an access no `lpm` can tell.
const UNCERTAIN: &str = "uncertain";

/// The kinds of the entries that report an access that can be told.
const KINDS: [&str; 4] = ["environment", "environments", "overrides", "change"];

impl Access<'_> {
    /// The name of the entry that reports it.
    pub fn entry(self) -> String {
        let (kind, vault_id, environment, overrides) = match self {
            Self::Environment {
                vault_id,
                environment,
                overrides,
            } => (KINDS[0], vault_id, environment, overrides),
            Self::Environments {
                vault_id,
                overrides,
            } => (KINDS[1], vault_id, "", overrides),
            Self::Overrides {
                vault_id,
                overrides,
            } => (KINDS[2], vault_id, "", overrides),
            Self::Change { vault_id } => (KINDS[3], vault_id, "", false),
            Self::Uncertain => return UNCERTAIN.to_owned(),
        };
        use sha2::Digest as _;
        // No part holds a NUL: a path, a vault ID or an environment can't.
        let digest = sha2::Sha256::new()
            .chain_update(kind)
            .chain_update([0])
            .chain_update(STORE.as_slice())
            .chain_update([0])
            .chain_update(vault_id)
            .chain_update([0])
            .chain_update(environment)
            .chain_update([0])
            .chain_update([u8::from(overrides)])
            .finalize();
        format!("{kind}-{}", hex::encode(digest))
    }

    /// The entries of the reads a task's key holds, when it holds
    /// `environment`'s values of the project with `vault_id`, read with its
    /// overrides, which it has when `overrides`: that read, and one of its
    /// overrides alone, which the key holds in every environment.
    pub fn keyed(vault_id: &str, environment: &str, overrides: bool) -> [String; 2] {
        [
            Access::Environment {
                vault_id,
                environment,
                overrides,
            }
            .entry(),
            Access::Overrides {
                vault_id,
                overrides,
            }
            .entry(),
        ]
    }
}

/// What the entry named `entry` says, when an `lpm` adds such an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// An access that can be told.
    Access,
    /// An access no `lpm` can tell.
    Uncertain,
}

impl Reported {
    /// What the entry named `entry` says; `None` for a name no `lpm` gives
    /// an entry.
    pub fn of_entry(entry: &str) -> Option<Self> {
        if entry == UNCERTAIN {
            return Some(Self::Uncertain);
        }
        let (kind, digest) = entry.rsplit_once('-')?;
        (KINDS.contains(&kind)
            && digest.len() == 64
            && digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
        .then_some(Self::Access)
    }
}

/// Tell every `lpm` above this one about `access`, before anything uses
/// what it read, or before it changes overrides.
pub fn report_access(access: Access<'_>) -> Result<(), String> {
    report(access)
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
    #[cfg(test)]
    if let Some(markers) = REPORTING_TO.with_borrow(Clone::clone) {
        return report_to(&markers, &access.entry());
    }
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

#[cfg(test)]
thread_local! {
    /// The markers this thread reports to in place of the inherited ones.
    static REPORTING_TO: std::cell::RefCell<Option<Vec<PathBuf>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `work` on this thread as though `markers` were inherited.
#[cfg(test)]
pub(crate) fn reporting_to<T>(markers: Vec<PathBuf>, work: impl FnOnce() -> T) -> T {
    REPORTING_TO.with_borrow_mut(|reporting| *reporting = Some(markers));
    let result = work();
    REPORTING_TO.with_borrow_mut(|reporting| *reporting = None);
    result
}

/// Create `entry` in each of `markers`, where an `lpm` above watches.
fn report_to(markers: &[PathBuf], entry: &str) -> Result<(), String> {
    for marker in markers {
        add_entry(marker, entry).map_err(|reason| {
            format!(
                "{UNREPORTED}{}, {reason}, so the lpm that set it couldn't be told which env project this one uses, and this one used nothing. If no lpm above this one caches what it builds, run it as `env -u {MARKER_ENV} lpm ...`",
                lpm_common::sanitize_terminal_inline(&marker.display().to_string())
            )
        })?;
    }
    Ok(())
}

/// Add `entry` to `marker`. A marker that's gone needs none: the `lpm` that
/// made it removes it only once it decided about its task, and one still
/// watching treats a marker it can't list as a use it can't tell, so a
/// process that outlives a task still runs.
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
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(format!("where an entry can't be added ({error})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_names_what_was_done_and_to_what_and_nothing_read() {
        let read = |vault_id, environment, overrides| {
            Access::Environment {
                vault_id,
                environment,
                overrides,
            }
            .entry()
        };
        let entries = [
            read("vault-1", "default", false),
            read("vault-1", "default", true),
            read("vault-1", "staging", false),
            read("Vault-1", "default", false),
            read("vault-2", "default", false),
            Access::Environments {
                vault_id: "vault-1",
                overrides: false,
            }
            .entry(),
            Access::Overrides {
                vault_id: "vault-1",
                overrides: false,
            }
            .entry(),
            Access::Change {
                vault_id: "vault-1",
            }
            .entry(),
        ];
        let distinct: HashSet<String> = entries.iter().map(|entry| entry.to_lowercase()).collect();
        assert_eq!(distinct.len(), entries.len(), "{entries:?}");
        for entry in &entries {
            assert_eq!(Reported::of_entry(entry), Some(Reported::Access), "{entry}");
            assert!(!entry.contains("vault"), "names no project: {entry}");
        }
        assert_eq!(
            Reported::of_entry(&Access::Uncertain.entry()),
            Some(Reported::Uncertain)
        );
        assert_eq!(
            Access::keyed("vault-1", "default", false),
            [entries[0].clone(), entries[6].clone()]
        );
        for unknown in [
            "read-vault-1",
            "environment-",
            "environment-0123",
            "write-0000000000000000000000000000000000000000000000000000000000000000",
            "environment-000000000000000000000000000000000000000000000000000000000000000G",
        ] {
            assert_eq!(Reported::of_entry(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn projects_whose_ids_differ_only_in_case_get_entries_a_file_system_keeps_apart() {
        let root = tempfile::tempdir().expect("temporary folder");
        let marker = root.path().join("marker");
        std::fs::create_dir(&marker).expect("marker");
        for vault_id in ["project", "Project"] {
            let entry = Access::Environment {
                vault_id,
                environment: "default",
                overrides: true,
            }
            .entry();
            report_to(std::slice::from_ref(&marker), &entry).expect("reported");
        }
        assert_eq!(std::fs::read_dir(&marker).expect("entries").count(), 2);
    }

    #[test]
    fn a_read_is_reported_to_every_marker_above() {
        let root = tempfile::tempdir().expect("temporary folder");
        let markers = [root.path().join("outer"), root.path().join("inner")];
        for marker in &markers {
            std::fs::create_dir(marker).expect("marker");
        }

        let entry = Access::Change {
            vault_id: "vault-1",
        }
        .entry();
        report_to(&markers, &entry).expect("reported");
        report_to(&markers, &entry).expect("an entry that's there already");

        for marker in &markers {
            let entries: Vec<_> = std::fs::read_dir(marker)
                .expect("entries")
                .map(|entry| entry.expect("entry").file_name())
                .collect();
            assert_eq!(entries, [entry.as_str()], "{}", marker.display());
        }
    }

    #[test]
    fn a_marker_that_can_t_be_told_fails_the_read() {
        let root = tempfile::tempdir().expect("temporary folder");
        let file = root.path().join("a-file");
        std::fs::write(&file, "").expect("a file where a marker would be");
        for (marker, reason) in [
            (PathBuf::from("relative"), "isn't an absolute path"),
            (file, "where an entry can't be added"),
        ] {
            let error =
                report_to(std::slice::from_ref(&marker), "read-vault-1").expect_err("refused");
            assert!(describes(&error), "{error}");
            assert!(error.starts_with(MARKER_ENV), "{error}");
            assert!(error.contains(reason), "{}: {error}", marker.display());
            assert!(
                error.contains("env -u LPM_PERSONAL_OVERRIDES_MARKER"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_marker_whose_task_ended_needs_no_entry() {
        let root = tempfile::tempdir().expect("temporary folder");
        let watching = root.path().join("watching");
        std::fs::create_dir(&watching).expect("marker");
        let markers = [root.path().join("ended"), watching.clone()];

        report_to(&markers, "read-vault-1").expect("reported to the marker still there");

        assert!(watching.join("read-vault-1").exists());
        assert!(!markers[0].exists());
    }
}
