//! Telling every `lpm` that started this one, however deep, which env
//! projects it read with their personal overrides, or whose overrides it
//! changed, which a task cache must know: a cached task's key holds one
//! environment's values of its own project, and that project's overrides,
//! but not what a nested `lpm` reads otherwise. It also tells them each
//! folder it found no env project for, which a cache checks still has none
//! before it uses what the task built.
//!
//! [`MARKER_ENV`] holds a `PATH`-style list of directories: an `lpm` that
//! caches a task makes a directory for it, adds it to the list it inherited,
//! and passes the list to the task. Before an `lpm` uses what it read, or
//! changes overrides, it adds an entry to every directory in the list, so
//! each `lpm` above it knows, whether or not those between them end well.
//! An entry is only ever created, never followed or written to after. Its
//! name is the kind of access and a digest of the store, project and
//! environment it touched and whether the project had overrides, so names
//! that differ only in case, as some file systems can't keep apart, never
//! meet, and nothing of what was read is in it. It's empty, but for a folder
//! without an env project: that entry holds the folder's path, whose digest
//! its name is, written whole before it takes the name.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

/// The variable that carries the marker directories to a task's process.
pub const MARKER_ENV: &str = "LPM_PERSONAL_OVERRIDES_MARKER";

/// Whether `name` is [`MARKER_ENV`] as the host compares variable names:
/// without case on Windows.
pub fn names_the_marker(name: &std::ffi::OsStr) -> bool {
    if cfg!(windows) {
        name.eq_ignore_ascii_case(MARKER_ENV)
    } else {
        name == MARKER_ENV
    }
}

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

/// The store this process reads env projects from, as one comparable value
/// (see [`store_of`]). Empty when there's none, and then nothing is read.
static STORE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    lpm_common::paths::LpmRoot::from_env()
        .map(|root| store_of(root.identity(), root.credential_scope().as_deref()))
        .unwrap_or_default()
});

/// The store of the LPM home whose identity is `identity`, read with the
/// credential scope `scope`: the home chooses the file store, and the scope
/// the Keychain's services, which also follow `HOME`. The scope is always a
/// part, empty for the default home, so no two stores read alike.
fn store_of(identity: PathBuf, scope: Option<&str>) -> Vec<u8> {
    let mut store = identity.into_os_string().into_encoded_bytes();
    store.push(0);
    store.extend_from_slice(scope.unwrap_or_default().as_bytes());
    store
}

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
    /// applied: `values` identifies the values it read, when there were any,
    /// and `overrides` the project's overrides, when it had any.
    Environment {
        vault_id: &'a str,
        environment: &'a str,
        values: Option<crate::ValuesIdentity>,
        overrides: Option<crate::OverridesIdentity>,
    },
    /// It read every environment's values with the project's overrides
    /// applied.
    Environments { vault_id: &'a str, overrides: bool },
    /// It read the project's overrides of every environment, which
    /// `overrides` identifies when it had any.
    Overrides {
        vault_id: &'a str,
        overrides: Option<crate::OverridesIdentity>,
    },
    /// It changed the project's overrides.
    Change { vault_id: &'a str },
    /// It found no env project for `folder`, the canonical path of the
    /// folder it ran for, so it read nothing there.
    NoProject { folder: &'a str },
    /// What it used can't be told: it couldn't pass a marker to a task.
    Uncertain,
}

/// The name of the entry that reports an access no `lpm` can tell.
const UNCERTAIN: &str = "uncertain";

/// The kinds of the entries that report an access that can be told.
const KINDS: [&str; 5] = [
    "environment",
    "environments",
    "overrides",
    "change",
    "absent",
];

/// The most a folder's entry holds, past which it isn't one an `lpm` added.
const MAX_FOLDER_BYTES: u64 = 64 * 1024;

impl<'a> Access<'a> {
    /// The name of the entry that reports it. A read's names what it read
    /// by digest, so it's one a task's key holds only when the key holds
    /// exactly that, even after the project changed back by the task's end.
    pub fn entry(self) -> String {
        self.entry_in(&STORE)
    }

    /// [`Self::entry`] for an `lpm` reading `store`.
    fn entry_in(self, store: &[u8]) -> String {
        use sha2::Digest as _;
        fn identified(hasher: sha2::Sha256, digest: Option<&[u8; 32]>) -> sha2::Sha256 {
            match digest {
                None => hasher.chain_update([0]),
                Some(digest) => hasher.chain_update([1]).chain_update(digest),
            }
        }
        let (kind, vault_id, environment) = match self {
            Self::Environment {
                vault_id,
                environment,
                ..
            } => (KINDS[0], vault_id, environment),
            Self::Environments { vault_id, .. } => (KINDS[1], vault_id, ""),
            Self::Overrides { vault_id, .. } => (KINDS[2], vault_id, ""),
            Self::Change { vault_id } => (KINDS[3], vault_id, ""),
            // Whether a folder has an env project is its lpm.json's to say,
            // whichever store an `lpm` reads.
            Self::NoProject { folder } => {
                let digest = sha2::Sha256::new()
                    .chain_update(KINDS[4])
                    .chain_update([0])
                    .chain_update(folder)
                    .finalize();
                return format!("{}-{}", KINDS[4], hex::encode(digest));
            }
            Self::Uncertain => return UNCERTAIN.to_owned(),
        };
        // No part holds a NUL: a path, a vault ID or an environment can't.
        let named = sha2::Sha256::new()
            .chain_update(kind)
            .chain_update([0])
            .chain_update(store)
            .chain_update([0])
            .chain_update(vault_id)
            .chain_update([0])
            .chain_update(environment)
            .chain_update([0]);
        let digest = match self {
            Self::Environment {
                values, overrides, ..
            } => identified(
                identified(named, values.as_ref().map(|values| &values.0)),
                overrides.as_ref().map(|overrides| &overrides.0),
            ),
            Self::Environments { overrides, .. } => named.chain_update([u8::from(overrides)]),
            Self::Overrides { overrides, .. } => {
                identified(named, overrides.as_ref().map(|overrides| &overrides.0))
            }
            Self::Change { .. } | Self::NoProject { .. } | Self::Uncertain => named,
        }
        .finalize();
        format!("{kind}-{}", hex::encode(digest))
    }

    /// The entries of the reads a task's key holds, when it holds
    /// `environment`'s values of the project with `vault_id`, which `values`
    /// identifies when there are any, read with its overrides, which
    /// `overrides` identifies when it has any: that read, and one of its
    /// overrides alone, which the key holds in every environment.
    pub fn keyed(
        vault_id: &str,
        environment: &str,
        values: Option<crate::ValuesIdentity>,
        overrides: Option<crate::OverridesIdentity>,
    ) -> [String; 2] {
        [
            Access::Environment {
                vault_id,
                environment,
                values,
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

    /// What its entry holds: the folder of a [`Self::NoProject`], else
    /// nothing.
    fn content(self) -> &'a [u8] {
        match self {
            Self::NoProject { folder } => folder.as_bytes(),
            _ => &[],
        }
    }
}

/// What the entry named `entry` says, when an `lpm` adds such an entry: the
/// kind of [`Access`] it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    Environment,
    Environments,
    Overrides,
    Change,
    NoProject,
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
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return None;
        }
        [
            Self::Environment,
            Self::Environments,
            Self::Overrides,
            Self::Change,
            Self::NoProject,
        ]
        .into_iter()
        .zip(KINDS)
        .find_map(|(reported, name)| (name == kind).then_some(reported))
    }
}

/// Tell every `lpm` above this one about `access`, before anything uses
/// what it read, or before it changes overrides.
pub fn report_access(access: Access<'_>) -> Result<(), String> {
    report(|| access)
}

/// [`report_access`] for an access that takes work to describe, such as a
/// digest of the values read, which is done only when an `lpm` above this
/// one watches.
pub fn report_access_with<'a>(access: impl FnOnce() -> Access<'a>) -> Result<(), String> {
    report(access)
}

/// Tell every `lpm` above this one that it can't tell what a task it
/// started reads.
pub fn report_uncertain() -> Result<(), String> {
    report(|| Access::Uncertain)
}

/// Tell every `lpm` above this one that `project_dir` has no env project, so
/// this one reads nothing there, before it goes on without one. A folder
/// whose canonical path can't be found or isn't UTF-8 can't be named in an
/// entry, so it's a use no `lpm` can tell.
pub fn report_no_project(project_dir: &Path) -> Result<(), String> {
    if !reporting() {
        return Ok(());
    }
    match std::fs::canonicalize(project_dir)
        .ok()
        .and_then(|folder| folder.into_os_string().into_string().ok())
    {
        Some(folder) => report(|| Access::NoProject { folder: &folder }),
        None => report_uncertain(),
    }
}

/// The folder the entry named `entry` in `marker` says has no env project,
/// when it's one an `lpm` added: a canonical path whose digest its name is.
pub fn folder_without_env_project(marker: &Path, entry: &str) -> Option<PathBuf> {
    if Reported::of_entry(entry) != Some(Reported::NoProject) {
        return None;
    }
    let folder = std::fs::File::open(marker.join(entry))
        .ok()
        .and_then(|file| {
            use std::io::Read as _;
            let mut folder = String::new();
            file.take(MAX_FOLDER_BYTES + 1)
                .read_to_string(&mut folder)
                .ok()?;
            Some(folder)
        })?;
    (folder.len() as u64 <= MAX_FOLDER_BYTES
        && Path::new(&folder).is_absolute()
        && Access::NoProject { folder: &folder }.entry() == entry)
        .then(|| PathBuf::from(folder))
}

/// Whether an `lpm` above this one watches what this one uses.
fn reporting() -> bool {
    #[cfg(test)]
    if REPORTING_TO.with_borrow(Option::is_some) {
        return true;
    }
    !inherited().is_empty()
}

/// Add `access`'s entry to every inherited marker, once a process. One that
/// can't be told would share what this one builds, so the access fails
/// instead.
fn report<'a>(access: impl FnOnce() -> Access<'a>) -> Result<(), String> {
    #[cfg(test)]
    if let Some(markers) = REPORTING_TO.with_borrow(Clone::clone) {
        let access = access();
        return report_to(&markers, &access.entry(), access.content());
    }
    if inherited().is_empty() {
        return Ok(());
    }
    let access = access();
    let entry = access.entry();
    let mut reported = REPORTED.lock().unwrap_or_else(PoisonError::into_inner);
    if reported.contains(&entry) {
        return Ok(());
    }
    report_to(inherited(), &entry, access.content())?;
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

/// How to run an `lpm` without the variable, in the shell the platform's
/// commands are typed in.
const WITHOUT_MARKER: &str = if cfg!(windows) {
    "remove the variable with `set LPM_PERSONAL_OVERRIDES_MARKER=` (cmd) or `Remove-Item Env:LPM_PERSONAL_OVERRIDES_MARKER` (PowerShell), then run it again"
} else {
    "run it as `env -u LPM_PERSONAL_OVERRIDES_MARKER lpm ...`"
};

/// Create `entry`, holding `content`, in each of `markers`, where an `lpm`
/// above watches.
fn report_to(markers: &[PathBuf], entry: &str, content: &[u8]) -> Result<(), String> {
    for marker in markers {
        add_entry(marker, entry, content).map_err(|reason| {
            format!(
                "{UNREPORTED}{}, {reason}, so the lpm that set it couldn't be told which env project this one uses, and this one used nothing. If no lpm above this one caches what it builds, {WITHOUT_MARKER}",
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
fn add_entry(marker: &Path, entry: &str, content: &[u8]) -> Result<(), String> {
    if !marker.is_absolute() {
        return Err("which isn't an absolute path".to_owned());
    }
    let added = if content.is_empty() {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker.join(entry))
            .map(drop)
    } else {
        add_entry_holding(marker, entry, content)
    };
    match added {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        // Windows says a path through a file isn't found, as it says of a
        // marker that's gone, so only a marker with nothing at its path is.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && std::fs::symlink_metadata(marker)
                    .is_err_and(|missing| missing.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(error) => Err(format!("where an entry can't be added ({error})")),
    }
}

/// Add `entry` holding `content`, written whole under a name of this
/// process's own before it takes the entry's, so no `lpm` reads part of it.
/// An entry already there holds the same, as its name is its digest.
fn add_entry_holding(marker: &Path, entry: &str, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let path = marker.join(entry);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Ok(());
    }
    let staging = marker.join(format!(".{entry}.{}", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staging)
        .and_then(|mut file| file.write_all(content))
        .and_then(|()| {
            std::fs::rename(&staging, &path).or_else(|error| {
                if std::fs::symlink_metadata(&path).is_ok() {
                    Ok(())
                } else {
                    Err(error)
                }
            })
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_without_an_env_project_is_held_by_its_entry_whose_name_is_its_digest() {
        let marker = tempfile::tempdir().expect("marker");
        let folder = tempfile::tempdir().expect("folder");
        let canonical = std::fs::canonicalize(folder.path())
            .expect("canonical")
            .into_os_string()
            .into_string()
            .expect("UTF-8");
        let entry = Access::NoProject { folder: &canonical }.entry();
        assert_eq!(Reported::of_entry(&entry), Some(Reported::NoProject));

        for _ in 0..2 {
            reporting_to(vec![marker.path().to_owned()], || {
                report_no_project(folder.path())
            })
            .expect("report");
        }
        let names: Vec<String> = std::fs::read_dir(marker.path())
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect();
        assert_eq!(names, [entry.clone()], "one entry, and nothing staged left");
        assert_eq!(
            folder_without_env_project(marker.path(), &entry),
            Some(PathBuf::from(&canonical))
        );

        let elsewhere = Access::NoProject {
            folder: "/elsewhere",
        }
        .entry();
        std::fs::write(marker.path().join(&elsewhere), &canonical).expect("plant");
        assert_eq!(
            folder_without_env_project(marker.path(), &elsewhere),
            None,
            "a folder its name isn't the digest of"
        );
        std::fs::write(
            marker.path().join(&entry),
            &canonical[..canonical.len() - 1],
        )
        .expect("cut");
        assert_eq!(
            folder_without_env_project(marker.path(), &entry),
            None,
            "part of a folder"
        );
        let relative = Access::NoProject { folder: "relative" }.entry();
        std::fs::write(marker.path().join(&relative), "relative").expect("plant");
        assert_eq!(folder_without_env_project(marker.path(), &relative), None);
        let change = Access::Change {
            vault_id: "vault-1",
        }
        .entry();
        std::fs::write(marker.path().join(&change), &canonical).expect("plant");
        assert_eq!(folder_without_env_project(marker.path(), &change), None);
    }

    #[test]
    fn an_entry_names_what_was_done_to_what_and_by_digest_what_was_read() {
        let values = |value: &str| {
            Some(crate::ValuesIdentity::of(&std::collections::HashMap::from(
                [("API_URL".to_owned(), value.to_owned())],
            )))
        };
        let overrides = |record: &[u8]| Some(crate::OverridesIdentity::of(record));
        let read = |vault_id, environment, values, overrides| {
            Access::Environment {
                vault_id,
                environment,
                values,
                overrides,
            }
            .entry()
        };
        let entries = [
            read("vault-1", "default", None, None),
            read("vault-1", "default", values("one"), None),
            read("vault-1", "default", values("two"), None),
            read("vault-1", "default", None, overrides(b"first")),
            read("vault-1", "default", None, overrides(b"second")),
            read("vault-1", "default", values("one"), overrides(b"first")),
            read("vault-1", "staging", None, None),
            read("Vault-1", "default", None, None),
            read("vault-2", "default", None, None),
            Access::Environments {
                vault_id: "vault-1",
                overrides: false,
            }
            .entry(),
            Access::Overrides {
                vault_id: "vault-1",
                overrides: None,
            }
            .entry(),
            Access::Overrides {
                vault_id: "vault-1",
                overrides: overrides(b"first"),
            }
            .entry(),
            Access::Change {
                vault_id: "vault-1",
            }
            .entry(),
            Access::NoProject {
                folder: "/repo/vault-1",
            }
            .entry(),
        ];
        let distinct: HashSet<String> = entries.iter().map(|entry| entry.to_lowercase()).collect();
        assert_eq!(distinct.len(), entries.len(), "{entries:?}");
        for entry in &entries {
            assert!(
                Reported::of_entry(entry).is_some_and(|reported| reported != Reported::Uncertain),
                "{entry}"
            );
            assert!(!entry.contains("vault"), "names no project: {entry}");
        }
        assert_eq!(
            [&entries[0], &entries[9], &entries[10], &entries[12]]
                .map(|entry| Reported::of_entry(entry)),
            [
                Some(Reported::Environment),
                Some(Reported::Environments),
                Some(Reported::Overrides),
                Some(Reported::Change)
            ]
        );
        assert_eq!(
            Reported::of_entry(&Access::Uncertain.entry()),
            Some(Reported::Uncertain)
        );
        assert_eq!(
            Access::keyed("vault-1", "default", None, None),
            [entries[0].clone(), entries[10].clone()]
        );
        assert_eq!(
            Access::keyed("vault-1", "default", values("one"), overrides(b"first")),
            [entries[5].clone(), entries[11].clone()]
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
    fn the_marker_variable_is_named_as_the_host_spells_names() {
        assert!(names_the_marker(std::ffi::OsStr::new(MARKER_ENV)));
        assert_eq!(
            names_the_marker(std::ffi::OsStr::new(&MARKER_ENV.to_ascii_lowercase())),
            cfg!(windows),
            "Windows passes names without case"
        );
        assert!(!names_the_marker(std::ffi::OsStr::new(
            "LPM_PERSONAL_OVERRIDES"
        )));
    }

    #[test]
    fn an_lpm_home_read_with_another_credential_scope_is_another_store() {
        let read = Access::Environment {
            vault_id: "vault-1",
            environment: "default",
            values: None,
            overrides: None,
        };
        let home = PathBuf::from("/home/someone/.lpm");
        let entries: HashSet<String> = [
            store_of(home.clone(), None),
            store_of(home, Some("0123456789abcdef")),
            store_of(PathBuf::from("/home/someone/.lpm2"), None),
        ]
        .iter()
        .map(|store| read.entry_in(store))
        .collect();

        assert_eq!(entries.len(), 3);
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
                values: None,
                overrides: Some(crate::OverridesIdentity::of(b"record")),
            }
            .entry();
            report_to(std::slice::from_ref(&marker), &entry, &[]).expect("reported");
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
        report_to(&markers, &entry, &[]).expect("reported");
        report_to(&markers, &entry, &[]).expect("an entry that's there already");

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
                report_to(std::slice::from_ref(&marker), "read-vault-1", &[]).expect_err("refused");
            assert!(describes(&error), "{error}");
            assert!(error.starts_with(MARKER_ENV), "{error}");
            assert!(error.contains(reason), "{}: {error}", marker.display());
            let remedy = if cfg!(windows) {
                "Remove-Item Env:LPM_PERSONAL_OVERRIDES_MARKER"
            } else {
                "env -u LPM_PERSONAL_OVERRIDES_MARKER"
            };
            assert!(error.contains(remedy), "{error}");
        }
    }

    #[test]
    fn a_marker_whose_task_ended_needs_no_entry() {
        let root = tempfile::tempdir().expect("temporary folder");
        let watching = root.path().join("watching");
        std::fs::create_dir(&watching).expect("marker");
        let markers = [root.path().join("ended"), watching.clone()];

        report_to(&markers, "read-vault-1", &[]).expect("reported to the marker still there");

        assert!(watching.join("read-vault-1").exists());
        assert!(!markers[0].exists());
    }
}
