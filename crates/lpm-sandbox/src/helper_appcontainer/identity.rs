//! A stable AppContainer's grants across runs, and grants that profiles
//! no longer existing left behind.
//!
//! A package's scripts run in one AppContainer per project, so each run
//! grants that identity its spec's trees again. The grant record names
//! the trees the identity was last granted: a run revokes those its spec
//! no longer grants before it grants its own, and a cleanup run revokes
//! all of them. Both happen under the identity's lock, which a run holds
//! until its child exits, so no other run of the identity changes them
//! meanwhile.
//!
//! The record also names what a run sets outside those trees for as long
//! as it lasts ([`RunAccess`]). A run takes that back when it ends; one
//! stopped first, as a script over its time limit is, can't, so the next
//! run of the identity or its cleanup does.

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetLengthSid, GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER_LOCAL_SETTINGS, KEY_QUERY_VALUE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};

/// What a grant or sweep record holds: the trees as the helper left them
/// and, in a grant record, what a run still holds outside them.
#[derive(serde::Serialize, serde::Deserialize)]
struct TreeRecord {
    version: u32,
    trees: Vec<PathBuf>,
    /// Left out when empty, and read as empty where an earlier release
    /// wrote the record.
    #[serde(default, skip_serializing_if = "RunAccess::is_empty")]
    run: RunAccess,
}

/// What a run sets for its identity outside the identity's trees, for as
/// long as the run lasts.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct RunAccess {
    /// Directories the identity may pass through to reach its trees.
    #[serde(default)]
    pub(super) traversed: Vec<PathBuf>,
    /// Secrets the identity is denied reading.
    #[serde(default)]
    pub(super) denied: Vec<PathBuf>,
}

impl RunAccess {
    fn is_empty(&self) -> bool {
        self.traversed.is_empty() && self.denied.is_empty()
    }

    /// Names `other`'s entries too, each once.
    fn add(&mut self, other: &Self) {
        let add = |held: &mut Vec<PathBuf>, more: &[PathBuf]| {
            for path in more {
                if !held.contains(path) {
                    held.push(path.clone());
                }
            }
        };
        add(&mut self.traversed, &other.traversed);
        add(&mut self.denied, &other.denied);
    }

    /// Stops naming `other`'s entries.
    fn remove(&mut self, other: &Self) {
        self.traversed
            .retain(|path| !other.traversed.contains(path));
        self.denied.retain(|path| !other.denied.contains(path));
    }
}

const TREE_RECORD_VERSION: u32 = 1;

impl TreeRecord {
    fn naming(trees: Vec<PathBuf>, run: RunAccess) -> Self {
        Self {
            version: TREE_RECORD_VERSION,
            trees,
            run,
        }
    }

    fn empty() -> Self {
        Self::naming(Vec::new(), RunAccess::default())
    }
}

/// What `path` records; nothing when it doesn't exist yet. One that
/// can't be read is logged and read as naming nothing: the run then
/// revokes nothing it doesn't grant again, and writes a new record.
fn read_record(path: &Path) -> TreeRecord {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<TreeRecord>(&bytes) {
            Ok(record) if record.version == TREE_RECORD_VERSION => record,
            Ok(record) => {
                tracing::warn!(
                    target: "lpm_sandbox::helper_appcontainer",
                    "ignoring {} written by another release (version {})",
                    path.display(),
                    record.version,
                );
                TreeRecord::empty()
            }
            Err(error) => {
                tracing::warn!(
                    target: "lpm_sandbox::helper_appcontainer",
                    "ignoring unreadable {}: {error}",
                    path.display(),
                );
                TreeRecord::empty()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TreeRecord::empty(),
        Err(error) => {
            tracing::warn!(
                target: "lpm_sandbox::helper_appcontainer",
                "ignoring unreadable {}: {error}",
                path.display(),
            );
            TreeRecord::empty()
        }
    }
}

/// What `path` records, as a cleanup must have it: a record it can't
/// read, or that another release wrote, may name access still set, so it
/// is an error rather than nothing. A record that doesn't exist names
/// nothing.
fn read_record_strictly(path: &Path) -> Result<TreeRecord, AppContainerError> {
    let unreadable = |source: std::io::Error| AppContainerError::GrantRecord {
        path: path.to_path_buf(),
        source,
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TreeRecord::empty());
        }
        Err(error) => return Err(unreadable(error)),
    };
    match serde_json::from_slice::<TreeRecord>(&bytes) {
        Ok(record) if record.version == TREE_RECORD_VERSION => Ok(record),
        Ok(record) => Err(unreadable(std::io::Error::other(format!(
            "written by another release (version {})",
            record.version
        )))),
        Err(error) => Err(unreadable(std::io::Error::other(error))),
    }
}

fn write_record(path: &Path, record: &TreeRecord) -> Result<(), AppContainerError> {
    let bytes = serde_json::to_vec_pretty(record).expect("a tree record serializes");
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| lpm_common::write_file_atomic(path, bytes));
    written.map_err(|source| AppContainerError::GrantRecord {
        path: path.to_path_buf(),
        source,
    })
}

/// `path` as Windows compares paths: case-insensitively, either
/// separator, without a verbatim prefix or a trailing separator.
fn comparable(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\").to_lowercase();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches('\\').to_owned()
}

/// Whether `path` is one of `trees` or inside one of them.
fn is_covered(path: &Path, trees: &[String]) -> bool {
    let path = comparable(path);
    trees.iter().any(|tree| {
        path == *tree
            || path
                .strip_prefix(tree.as_str())
                .is_some_and(|rest| rest.starts_with('\\'))
    })
}

/// Holds the identity `name` for the rest of a run, against other runs
/// of the same project and package, in any process or session.
pub(super) fn lock(name: &str) -> Result<ProfileCreationLock, AppContainerError> {
    setup::lock_named(&format!(r"Global\LpmSandboxIdentity-{name}"))
}

/// Revokes the trees the identity was last granted that `current`
/// doesn't hold, before a run grants `current`. The record first names
/// both, so a run that stops partway leaves the next one every tree it
/// may have granted.
pub(super) fn revoke_stale_grants(
    record: &Path,
    current: &[PathBuf],
    sid: PSID,
) -> Result<(), AppContainerError> {
    let previous = read_record(record);
    let covering: Vec<String> = current.iter().map(|tree| comparable(tree)).collect();
    let stale: Vec<PathBuf> = previous
        .trees
        .iter()
        .filter(|tree| !is_covered(tree, &covering))
        .cloned()
        .collect();
    let mut both = current.to_vec();
    both.extend(stale.iter().cloned());
    write_record(record, &TreeRecord::naming(both, previous.run))?;
    for tree in &stale {
        if let Err(error) = revoke_tree(tree, sid, false) {
            tracing::warn!(
                target: "lpm_sandbox::helper_appcontainer",
                "couldn't revoke this package's earlier access to {}: {error}",
                tree.display(),
            );
        }
    }
    Ok(())
}

/// Records that the identity holds `granted`, once a run granted it.
pub(super) fn record_grants(record: &Path, granted: &[PathBuf]) -> Result<(), AppContainerError> {
    let run = read_record(record).run;
    write_record(record, &TreeRecord::naming(granted.to_vec(), run))
}

/// Names `access` in the record before a run sets it, so a run stopped
/// before it ends leaves the next one everything it may have set.
pub(super) fn record_run_access(
    record: &Path,
    access: &RunAccess,
) -> Result<(), AppContainerError> {
    if access.is_empty() {
        return Ok(());
    }
    let mut recorded = read_record(record);
    recorded.run.add(access);
    write_record(record, &recorded)
}

/// Stops naming `access` in the record, once a run took it back.
pub(super) fn forget_run_access(
    record: &Path,
    access: &RunAccess,
) -> Result<(), AppContainerError> {
    let mut recorded = read_record(record);
    if recorded.run.is_empty() {
        return Ok(());
    }
    recorded.run.remove(access);
    write_record(record, &recorded)
}

/// Takes back what an earlier run of the identity set for as long as it
/// lasted and was stopped before taking back. What it can't take back
/// stays in the record for the run after this one.
pub(super) fn take_back_run_access(record: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let mut recorded = read_record(record);
    if recorded.run.is_empty() {
        return Ok(());
    }
    let (left, _) = take_back(&recorded.run, sid);
    recorded.run = left;
    write_record(record, &recorded)
}

/// Removes the identity's traversal of each directory `access` names and
/// its read denial on each secret. An entry that is gone, or became a
/// link, holds neither. Says what it couldn't take back, and the first
/// reason.
fn take_back(access: &RunAccess, sid: PSID) -> (RunAccess, Option<AppContainerError>) {
    let mut left = RunAccess::default();
    let mut first = None;
    let mut keep = |held: &mut Vec<PathBuf>, path: &Path, error: AppContainerError| {
        tracing::warn!(
            target: "lpm_sandbox::helper_appcontainer",
            "couldn't take back an earlier run's access to {}: {error}",
            path.display(),
        );
        held.push(path.to_path_buf());
        first.get_or_insert(error);
    };
    let sid_address = sid as usize;
    // SAFETY: both SIDs are valid for the comparison.
    let granted = move |ace: PSID| unsafe { EqualSid(ace, sid_address as PSID) != 0 };
    for path in &access.traversed {
        match setup::remove_allowed_aces_where(path, granted) {
            Ok(_) => {}
            Err(error) if left_the_tree(&error) => {}
            Err(error) => keep(&mut left.traversed, path, error),
        }
    }
    for path in &access.denied {
        match setup::remove_appcontainer_read_deny(path, sid) {
            Ok(()) => {}
            Err(error) if left_the_tree(&error) => {}
            Err(error) => keep(&mut left.denied, path, error),
        }
    }
    (left, first)
}

/// Revokes every tree the identity was granted, takes back what a run of
/// it left set, and removes its record, as a cleanup run does once the
/// package leaves the project.
pub(super) fn revoke_all(record: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let recorded = read_record_strictly(record)?;
    let mut failed = None;
    for tree in &recorded.trees {
        if let Err(error) = revoke_tree(tree, sid, true) {
            failed.get_or_insert(error);
        }
    }
    if let (_, Some(error)) = take_back(&recorded.run, sid) {
        failed.get_or_insert(error);
    }
    if let Some(error) = failed {
        return Err(error);
    }
    match std::fs::remove_file(record) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AppContainerError::GrantRecord {
            path: record.to_path_buf(),
            source,
        }),
    }
}

/// Removes `sid`'s access-allowed ACEs from `root` and everything below
/// it, as granting set them, without following links; a DACL without one
/// isn't written. A root that is gone, or a link, which no grant went
/// through, needs nothing.
///
/// With `every_entry`, an entry below the root that still grants `sid`
/// fails the revoke as the root would, and so does one it can't list or
/// inspect, which may: the profile must outlive them, as a new one for the
/// same project and package gets the same SID. An entry that vanished or
/// became a link meanwhile holds nothing of it.
fn revoke_tree(root: &Path, sid: PSID, every_entry: bool) -> Result<(), AppContainerError> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AppContainerError::InspectDaclPath {
                path: root.to_path_buf(),
                source,
            });
        }
    };
    if is_reparse_point(&metadata) {
        return Ok(());
    }
    let sid_address = sid as usize;
    // SAFETY: both SIDs are valid for the comparison.
    let granted = move |ace: PSID| unsafe { EqualSid(ace, sid_address as PSID) != 0 };
    setup::remove_allowed_aces_where(root, granted)?;
    if metadata.is_dir() {
        let failed = Mutex::new(None);
        let unvisited = visit_entries_below(root, &|path| match setup::remove_allowed_aces_where(
            path, granted,
        ) {
            Ok(_) => {}
            Err(error) if every_entry && !left_the_tree(&error) => {
                failed
                    .lock()
                    .expect("revoke failure lock")
                    .get_or_insert(error);
            }
            Err(error) => {
                tracing::debug!(path = %path.display(), "skip DACL revoke: {error}");
            }
        });
        if let Some(error) = failed.into_inner().expect("revoke failure lock") {
            return Err(error);
        }
        if every_entry && let Some((path, source)) = unvisited.into_iter().next() {
            return Err(AppContainerError::InspectDaclPath { path, source });
        }
    }
    Ok(())
}

/// Whether `error` says an entry is gone or became a link since it was
/// listed, so it holds no grant of the identity.
fn left_the_tree(error: &AppContainerError) -> bool {
    match error {
        AppContainerError::ReparsePointRoot { .. } => true,
        AppContainerError::ReadDacl { win32_error, .. }
        | AppContainerError::WriteDacl { win32_error, .. } => {
            matches!(*win32_error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        }
        _ => false,
    }
}

/// Sweeps each of `trees` that `record` doesn't name yet of access
/// granted to AppContainer profiles that no longer exist, as each
/// lifecycle run of earlier releases left behind, then names it there.
/// Each tree is swept once, under one lock for every run. `own` is the
/// profile this run uses: where the system doesn't list it, it can't say
/// which profiles exist, and no tree is swept or named.
pub(super) fn sweep_dead_grants(
    record: &Path,
    trees: &[PathBuf],
    own: PSID,
) -> Result<(), AppContainerError> {
    let _lock = setup::lock_named(r"Global\LpmSandboxSweep")?;
    let mut swept = read_record(record).trees;
    let covering: Vec<String> = swept.iter().map(|tree| comparable(tree)).collect();
    let pending: Vec<&PathBuf> = trees
        .iter()
        .filter(|tree| !is_covered(tree, &covering))
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let Some(liveness) = Liveness::new(own) else {
        tracing::debug!(
            target: "lpm_sandbox::helper_appcontainer",
            "the AppContainer profile list doesn't name this run's profile; sweeping nothing",
        );
        return Ok(());
    };
    for tree in pending {
        sweep_tree(tree, &liveness);
        swept.push(tree.clone());
    }
    write_record(record, &TreeRecord::naming(swept, RunAccess::default()))
}

fn sweep_tree(root: &Path, liveness: &Liveness) {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return;
    };
    if is_reparse_point(&metadata) {
        return;
    }
    let sweep = |path: &Path| {
        if let Err(error) =
            setup::remove_allowed_aces_where(path, |sid| liveness.is_dead_package(sid))
        {
            tracing::debug!(path = %path.display(), "skip DACL sweep: {error}");
        }
    };
    sweep(root);
    if metadata.is_dir() {
        visit_entries_below(root, &sweep);
    }
}

/// Which AppContainer package SIDs still name a profile, as the current
/// user's profile list says, asked once per SID.
struct Liveness {
    profiles: RegistryKey,
    known: Mutex<HashMap<Vec<u8>, bool>>,
}

impl Liveness {
    /// The current user's profile list, where it names `own`.
    fn new(own: PSID) -> Option<Self> {
        let profiles = profile_list()?;
        (lists_profile(&profiles, own) == Some(true)).then(|| Self {
            profiles,
            known: Mutex::default(),
        })
    }

    /// Whether `sid` is an AppContainer package's, `S-1-15-2-` and seven
    /// sub-authorities as a profile name derives, that no profile maps
    /// to. The well-known `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) and
    /// `ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`) have two
    /// sub-authorities, and are never dead.
    fn is_dead_package(&self, sid: PSID) -> bool {
        // SAFETY: `sid` points at a valid SID inside a live ACL.
        let (authority, count, first) = unsafe {
            let authority = (*GetSidIdentifierAuthority(sid)).Value;
            let count = *GetSidSubAuthorityCount(sid);
            let first = (count > 0).then(|| *GetSidSubAuthority(sid, 0));
            (authority, count, first)
        };
        if authority != [0, 0, 0, 0, 0, 15] || count != 8 || first != Some(2) {
            return false;
        }
        // SAFETY: `sid` is valid, and `GetLengthSid` reads only its header.
        let length = unsafe { GetLengthSid(sid) } as usize;
        // SAFETY: a valid SID spans `GetLengthSid` bytes.
        let key = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec();
        let mut known = self.known.lock().expect("liveness cache lock");
        if let Some(&dead) = known.get(&key) {
            return dead;
        }
        let dead = lists_profile(&self.profiles, sid) == Some(false);
        known.insert(key, dead);
        dead
    }
}

/// An open registry key, closed on drop.
struct RegistryKey(HKEY);

// SAFETY: a registry key handle may be used and closed from any thread.
unsafe impl Send for RegistryKey {}
// SAFETY: as above; opening keys below one doesn't change it.
unsafe impl Sync for RegistryKey {}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: the key was opened by `open_key` and is closed only here.
        unsafe { RegCloseKey(self.0) };
    }
}

/// `path` below `parent`, opened for `access`, or the Win32 error.
fn open_key(parent: HKEY, path: *const u16, access: u32) -> Result<RegistryKey, u32> {
    let mut key = ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `key` is a writable out pointer.
    let error = unsafe { RegOpenKeyExW(parent, path, 0, access, &mut key) };
    if error == ERROR_SUCCESS {
        Ok(RegistryKey(key))
    } else {
        Err(error)
    }
}

/// The current user's AppContainer profile list, which names each profile
/// by its SID from `CreateAppContainerProfile` until
/// `DeleteAppContainerProfile`.
fn profile_list() -> Option<RegistryKey> {
    let path =
        str_to_wide_with_nul(r"Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings");
    open_key(HKEY_CURRENT_USER_LOCAL_SETTINGS, path.as_ptr(), KEY_READ).ok()
}

/// Whether `profiles` names `sid`; none where the system can't say.
fn lists_profile(profiles: &RegistryKey, sid: PSID) -> Option<bool> {
    let mut text = ptr::null_mut();
    // SAFETY: `sid` is valid; the string is LocalFree-owned on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    let _text = LocalAllocGuard(text.cast());
    match open_key(profiles.0, text, KEY_QUERY_VALUE) {
        Ok(_) => Some(true),
        Err(ERROR_FILE_NOT_FOUND) => Some(false),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_name(prefix: &str) -> String {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        format!("{prefix}{:x}{unique:x}", std::process::id())
    }

    /// Whether `path`'s DACL holds an access-allowed ACE for `sid`.
    fn grants(path: &Path, sid: PSID) -> bool {
        let wide = to_wide_with_nul(path.as_os_str());
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the path lives through the call and both outputs are initialized.
        let error = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(error, ERROR_SUCCESS, "{}", path.display());
        let _descriptor = LocalAllocGuard(descriptor as *mut _);
        // SAFETY: both SIDs are valid for the comparison.
        let matching =
            dacl_without_allowed_aces_where(path, dacl, |ace| unsafe { EqualSid(ace, sid) != 0 })
                .unwrap()
                .removed;
        matching > 0
    }

    fn tree_with_a_file(root: &Path, name: &str) -> PathBuf {
        let tree = root.join(name);
        std::fs::create_dir_all(tree.join("inner")).unwrap();
        std::fs::write(tree.join("inner").join("file.txt"), b"x").unwrap();
        tree
    }

    fn delete_profile(name: &str) {
        let mut cleanup = AppContainerProfileCleanup::new(name, true);
        let _ = cleanup.delete();
    }

    #[test]
    fn a_tree_the_spec_no_longer_grants_is_revoked_from_the_identity() {
        let name = unique_name("LpmIdentityStale");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let kept = tree_with_a_file(root.path(), "kept");
        let dropped = tree_with_a_file(root.path(), "dropped");
        for tree in [&kept, &dropped] {
            grant_dacl_ace_to_tree(tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        }
        let record = root.path().join("grants.json");
        record_grants(&record, &[kept.clone(), dropped.clone()]).unwrap();

        revoke_stale_grants(&record, std::slice::from_ref(&kept), sid.0).unwrap();

        assert!(grants(&kept.join("inner").join("file.txt"), sid.0));
        assert!(!grants(&dropped, sid.0));
        assert!(!grants(&dropped.join("inner").join("file.txt"), sid.0));
        delete_profile(&name);
    }

    #[test]
    fn a_cleanup_run_revokes_every_recorded_tree_and_deletes_the_profile() {
        let name = unique_name("LpmIdentityCleanup");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "granted");
        grant_dacl_ace_to_tree(&tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        let record = root.path().join("grants.json");
        record_grants(&record, std::slice::from_ref(&tree)).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");
        assert_eq!(lists_profile(&profiles, sid.0), Some(true));
        let args = crate::helper_protocol::parse_argv(
            [
                "--protocol-version",
                &crate::helper_protocol::PROTOCOL_VERSION.to_string(),
                "--appcontainer-name",
                &name,
                "--grant-record",
                record.to_str().unwrap(),
                "--revoke-only",
                "--delete-appcontainer-profile",
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        )
        .unwrap();

        assert_eq!(run_revoke_only(&args).unwrap(), 0);

        assert!(!grants(&tree, sid.0));
        assert!(!grants(&tree.join("inner").join("file.txt"), sid.0));
        assert!(!record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(false));
    }

    /// Disables every privilege of this process until it drops, for a check
    /// the revoke's walker threads make as well as this one: hosted CI
    /// administrators hold backup and restore privileges that open any
    /// directory to change it. Nothing else in these tests uses one.
    struct ProcessWithoutPrivileges {
        token: HandleGuard,
        previous: Vec<u64>,
        // Held until the privileges are back: two tests that each took them
        // away would otherwise give them back while the other still ran.
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    static PROCESS_PRIVILEGES: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl ProcessWithoutPrivileges {
        fn new() -> Self {
            let serial = PROCESS_PRIVILEGES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            use windows_sys::Win32::Security::{
                AdjustTokenPrivileges, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut token = ptr::null_mut();
            // SAFETY: the pseudo handle is valid and `token` is writable.
            assert_ne!(
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        &mut token,
                    )
                },
                0
            );
            let token = HandleGuard(token);
            let mut previous = vec![0u64; 512];
            let mut length = 0;
            // SAFETY: disable-all ignores the new state; `previous` is
            // writable for the size passed.
            assert_ne!(
                unsafe {
                    AdjustTokenPrivileges(
                        token.as_raw(),
                        1,
                        ptr::null(),
                        (previous.len() * 8) as u32,
                        previous.as_mut_ptr().cast(),
                        &mut length,
                    )
                },
                0
            );
            Self {
                token,
                previous,
                _serial: serial,
            }
        }
    }

    impl Drop for ProcessWithoutPrivileges {
        fn drop(&mut self) {
            // SAFETY: `previous` holds the TOKEN_PRIVILEGES the disable
            // returned, which this restores.
            unsafe {
                windows_sys::Win32::Security::AdjustTokenPrivileges(
                    self.token.as_raw(),
                    0,
                    self.previous.as_ptr().cast(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
        }
    }

    /// Deletes the profile `0` names when a test ends, however it ends.
    struct Profile(String);

    impl Drop for Profile {
        fn drop(&mut self) {
            delete_profile(&self.0);
        }
    }

    fn revoke_only_args(name: &str, record: &Path) -> HelperArgs {
        crate::helper_protocol::parse_argv(
            [
                "--protocol-version",
                &crate::helper_protocol::PROTOCOL_VERSION.to_string(),
                "--appcontainer-name",
                name,
                "--grant-record",
                record.to_str().unwrap(),
                "--revoke-only",
                "--delete-appcontainer-profile",
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        )
        .unwrap()
    }

    #[test]
    fn a_run_that_cannot_pass_through_a_directory_records_and_sets_nothing() {
        let name = unique_name("LpmIdentityNoWay");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let locked = root.path().join("locked");
        let project = locked.join("project");
        std::fs::create_dir_all(&project).unwrap();
        lock_directory_for_test(&locked);
        // The lock took away every entry `project` inherited, and the run
        // has to open it to reach `locked` as a directory above it.
        let user = setup::current_user_sid().unwrap();
        let granted = std::process::Command::new("icacls.exe")
            .arg(&project)
            .args(["/grant", &format!("*{user}:(OI)(CI)F")])
            .output()
            .unwrap();
        assert!(granted.status.success(), "{granted:?}");
        let reading = |directory: &Path| {
            crate::helper_protocol::parse_argv(
                [
                    "--protocol-version",
                    &crate::helper_protocol::PROTOCOL_VERSION.to_string(),
                    "--appcontainer-name",
                    &name,
                    "--stdio-stdin",
                    "null",
                    "--stdio-stdout",
                    "null",
                    "--stdio-stderr",
                    "null",
                    "--readable-dir",
                    directory.to_str().unwrap(),
                    "--",
                    "cmd.exe",
                ]
                .into_iter()
                .map(std::ffi::OsString::from),
            )
            .unwrap()
        };
        // A standard account without the sandbox setup can't change the
        // drive's root, so a run there stops before it reaches `locked`. A
        // run for the directory beside `locked`, ended before it sets
        // anything, tells where that is.
        let beside = root.path().join("beside");
        std::fs::create_dir(&beside).unwrap();
        let mut passable = false;
        let stopped_above = without_privileges(|| {
            setup::prepare(&reading(&beside), &sid, |_| {
                passable = true;
                Err(AppContainerError::Setup {
                    reason: "ended before anything is set".into(),
                })
            })
            .err()
        });
        let expected = match stopped_above {
            Some(AppContainerError::SetupRequired { path }) if !passable => path,
            Some(AppContainerError::Setup { .. }) if passable => locked.canonicalize().unwrap(),
            other => panic!("{other:?}"),
        };
        let mut recorded = false;

        let stopped = without_privileges(|| {
            setup::prepare(&reading(&project), &sid, |_| {
                recorded = true;
                Ok(())
            })
            .err()
        });

        let Some(AppContainerError::SetupRequired { path }) = &stopped else {
            panic!("{stopped:?}");
        };
        assert_eq!(
            path.canonicalize().unwrap(),
            expected.canonicalize().unwrap(),
            "the run stops at the first directory it can't change"
        );
        assert!(!recorded);
        for directory in root.path().ancestors().chain([locked.as_path()]) {
            assert!(!grants(directory, sid.0), "{}", directory.display());
        }
        std::fs::remove_dir(&project).unwrap();
        std::fs::remove_dir(&locked).unwrap();
    }

    #[test]
    fn a_cleanup_run_passes_a_recorded_tree_it_never_granted_and_could_not_change() {
        let name = unique_name("LpmIdentityUnchanged");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "granted");
        grant_dacl_ace_to_tree(&tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        lock_directory_for_test(&locked);
        let record = root.path().join("grants.json");
        record_grants(&record, &[locked.clone(), tree.clone()]).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");

        assert_eq!(
            without_privileges(|| run_revoke_only(&revoke_only_args(&name, &record))).unwrap(),
            0
        );

        assert!(!grants(&tree.join("inner").join("file.txt"), sid.0));
        assert!(!record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(false));
        std::fs::remove_dir(&locked).unwrap();
    }

    #[test]
    fn a_cleanup_run_keeps_the_profile_while_a_tree_it_cannot_change_holds_its_grant() {
        let name = unique_name("LpmIdentityStuck");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        grant_dacl_ace_to_tree(&locked, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        lock_directory_for_test(&locked);
        let record = root.path().join("grants.json");
        record_grants(&record, std::slice::from_ref(&locked)).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");

        let error =
            without_privileges(|| run_revoke_only(&revoke_only_args(&name, &record))).unwrap_err();

        assert!(
            matches!(
                &error,
                AppContainerError::WriteDacl { path, win32_error: 5 } if path == &locked
            ),
            "{error:?}"
        );
        assert!(grants(&locked, sid.0));
        assert!(record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(true));
        std::fs::remove_dir(&locked).unwrap();
    }

    /// A grant left below a tree's root outlives the profile just as one on
    /// the root would.
    #[test]
    fn a_cleanup_run_keeps_the_profile_while_an_entry_below_a_tree_holds_its_grant() {
        let name = unique_name("LpmIdentityStuckBelow");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        let locked = tree.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        grant_dacl_ace_to_tree(&tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        lock_directory_for_test(&locked);
        assert!(grants(&locked, sid.0));
        let record = root.path().join("grants.json");
        record_grants(&record, std::slice::from_ref(&tree)).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");

        let unprivileged = ProcessWithoutPrivileges::new();
        let error = run_revoke_only(&revoke_only_args(&name, &record)).unwrap_err();
        drop(unprivileged);

        assert!(
            matches!(
                &error,
                AppContainerError::WriteDacl { path, win32_error: 5 } if path == &locked
            ),
            "{error:?}"
        );
        assert!(grants(&locked, sid.0));
        assert!(!grants(&tree, sid.0));
        assert!(record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(true));
        std::fs::remove_dir(&locked).unwrap();
    }

    /// A record that can't be read may name trees still granted; the
    /// profile and the record stay until one that can be read is cleaned up.
    #[test]
    fn a_cleanup_run_keeps_the_profile_when_its_record_can_t_be_read() {
        let name = unique_name("LpmIdentityUnreadable");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let record = root.path().join("grants.json");
        std::fs::write(&record, b"not json").unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");

        let error = run_revoke_only(&revoke_only_args(&name, &record)).unwrap_err();

        assert!(
            matches!(&error, AppContainerError::GrantRecord { path, .. } if path == &record),
            "{error:?}"
        );
        assert!(record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(true));
    }

    /// Part of a tree the cleanup can't list may hold the identity's grant,
    /// as the directory below it here does.
    #[test]
    fn a_cleanup_run_keeps_the_profile_while_part_of_a_tree_can_t_be_listed() {
        struct DeniedListing(PathBuf, String);
        impl Drop for DeniedListing {
            fn drop(&mut self) {
                let _ = std::process::Command::new("icacls.exe")
                    .arg(&self.0)
                    .args(["/remove:d", &format!("*{}", self.1)])
                    .output();
            }
        }
        let name = unique_name("LpmIdentityUnlisted");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        let hidden = tree.join("hidden");
        std::fs::create_dir_all(hidden.join("inner")).unwrap();
        grant_dacl_ace_to_tree(&tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        let user = setup::current_user_sid().unwrap();
        let output = std::process::Command::new("icacls.exe")
            .arg(&hidden)
            .args(["/deny", &format!("*{user}:(RD)")])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let _denied = DeniedListing(hidden.clone(), user);
        let record = root.path().join("grants.json");
        record_grants(&record, std::slice::from_ref(&tree)).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");

        let unprivileged = ProcessWithoutPrivileges::new();
        let error = run_revoke_only(&revoke_only_args(&name, &record)).unwrap_err();
        drop(unprivileged);

        assert!(
            matches!(&error, AppContainerError::InspectDaclPath { path, .. } if path == &hidden),
            "{error:?}"
        );
        assert!(grants(&hidden.join("inner"), sid.0));
        assert!(record.exists());
        assert_eq!(lists_profile(&profiles, sid.0), Some(true));
    }

    #[test]
    fn a_sweep_removes_grants_to_profiles_that_no_longer_exist_once() {
        let live_name = unique_name("LpmSweepLive");
        let live = create_or_reuse_appcontainer_sid(&live_name).unwrap();
        let dead = derive_appcontainer_sid(&unique_name("LpmSweepDead")).unwrap();
        let profiles = profile_list().expect("the user's AppContainer profile list");
        assert_eq!(lists_profile(&profiles, live.0), Some(true));
        assert_eq!(lists_profile(&profiles, dead.0), Some(false));
        let mut buffer = vec![0u8; 64];
        let packages = build_capability_attr(WinBuiltinAnyPackageSid, &mut buffer).unwrap();
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "swept");
        let file = tree.join("inner").join("file.txt");
        for sid in [live.0, dead.0, packages.Sid] {
            grant_dacl_ace_to_tree(&tree, None, sid, FILE_GENERIC_READ, true).unwrap();
        }
        let record = root.path().join("swept.json");

        sweep_dead_grants(&record, std::slice::from_ref(&tree), live.0).unwrap();

        for path in [&tree, &file] {
            assert!(!grants(path, dead.0), "{}", path.display());
            assert!(grants(path, live.0), "{}", path.display());
            assert!(grants(path, packages.Sid), "{}", path.display());
        }
        assert_eq!(read_record(&record).trees, std::slice::from_ref(&tree));
        grant_dacl_ace_to_tree(&tree, None, dead.0, FILE_GENERIC_READ, true).unwrap();
        sweep_dead_grants(&record, std::slice::from_ref(&tree), live.0).unwrap();
        assert!(grants(&tree, dead.0), "a swept tree was swept again");
        delete_profile(&live_name);
    }

    #[test]
    fn a_sweep_whose_own_profile_is_not_listed_sweeps_and_records_nothing() {
        let unlisted = derive_appcontainer_sid(&unique_name("LpmSweepUnlisted")).unwrap();
        let dead = derive_appcontainer_sid(&unique_name("LpmSweepDead")).unwrap();
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "kept");
        grant_dacl_ace_to_tree(&tree, None, dead.0, FILE_GENERIC_READ, true).unwrap();
        let record = root.path().join("swept.json");

        sweep_dead_grants(&record, std::slice::from_ref(&tree), unlisted.0).unwrap();

        assert!(grants(&tree, dead.0));
        assert!(grants(&tree.join("inner").join("file.txt"), dead.0));
        assert!(!record.exists());
    }

    #[test]
    fn a_tree_covers_itself_and_what_is_inside_it_in_any_spelling() {
        let trees = vec![comparable(Path::new(r"C:\Users\Me\project\node_modules"))];
        for path in [
            r"C:\Users\Me\project\node_modules",
            r"c:/users/me/project/node_modules/",
            r"\\?\C:\Users\Me\project\node_modules\esbuild",
        ] {
            assert!(is_covered(Path::new(path), &trees), "{path}");
        }
        for path in [r"C:\Users\Me\project", r"C:\Users\Me\project\node_modules2"] {
            assert!(!is_covered(Path::new(path), &trees), "{path}");
        }
    }

    #[test]
    fn a_record_round_trips_and_an_unreadable_one_reads_as_none() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("nested").join("grants.json");
        assert!(read_record(&record).trees.is_empty());
        let trees = vec![PathBuf::from(r"C:\one"), PathBuf::from(r"C:\two")];
        let run = RunAccess {
            traversed: vec![PathBuf::from(r"C:\")],
            denied: vec![PathBuf::from(r"C:\one\.env")],
        };
        write_record(&record, &TreeRecord::naming(trees.clone(), run.clone())).unwrap();
        let read = read_record(&record);
        assert_eq!((read.trees, read.run), (trees, run));
        std::fs::write(&record, b"not json").unwrap();
        let read = read_record(&record);
        assert!(read.trees.is_empty() && read.run.is_empty());
    }

    #[test]
    fn a_record_an_earlier_release_wrote_names_nothing_a_run_left_set() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("grants.json");
        std::fs::write(&record, br#"{"version":1,"trees":["C:\\one"]}"#).unwrap();

        let read = read_record_strictly(&record).unwrap();

        assert_eq!(read.trees, [PathBuf::from(r"C:\one")]);
        assert!(read.run.is_empty());
        write_record(&record, &read).unwrap();
        assert!(
            !std::fs::read_to_string(&record).unwrap().contains("run"),
            "a record that names no run access reads as before in an earlier release"
        );
    }

    /// Whether `path`'s DACL holds an access-denied ACE for `sid`.
    fn denies(path: &Path, sid: PSID) -> bool {
        let wide = to_wide_with_nul(path.as_os_str());
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the path lives through the call and both outputs are initialized.
        let error = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(error, ERROR_SUCCESS, "{}", path.display());
        let _descriptor = LocalAllocGuard(descriptor as *mut _);
        let matching = dacl_without_aces_where(path, dacl, ACCESS_DENIED_ACE_TYPE, |ace| {
            // SAFETY: both SIDs are valid for the comparison.
            unsafe { EqualSid(ace, sid) != 0 }
        })
        .unwrap()
        .removed;
        matching > 0
    }

    /// What a run that was stopped before it ended leaves behind: its
    /// traversal of `passed` and its read denial on `secret`, both named
    /// in `record`.
    fn stopped_run(record: &Path, passed: &Path, secret: &Path, sid: PSID) -> RunAccess {
        let access = RunAccess {
            traversed: vec![passed.to_path_buf()],
            denied: vec![secret.to_path_buf()],
        };
        record_run_access(record, &access).unwrap();
        setup::update_ace(passed, sid, Some((setup::METADATA_ACCESS, 0))).unwrap();
        setup::deny_appcontainer_read(secret, sid).unwrap();
        assert!(grants(passed, sid) && denies(secret, sid));
        access
    }

    #[test]
    fn the_next_run_takes_back_what_a_stopped_run_left_set() {
        let name = unique_name("LpmIdentityStopped");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "granted");
        let secret = root.path().join(".env");
        std::fs::write(&secret, b"TOKEN=1").unwrap();
        let record = root.path().join("grants.json");
        record_grants(&record, std::slice::from_ref(&tree)).unwrap();
        stopped_run(&record, root.path(), &secret, sid.0);

        take_back_run_access(&record, sid.0).unwrap();

        assert!(!grants(root.path(), sid.0));
        assert!(!denies(&secret, sid.0));
        let read = read_record(&record);
        assert!(read.run.is_empty());
        assert_eq!(read.trees, [tree], "the identity's trees stay recorded");
        delete_profile(&name);
    }

    #[test]
    fn revoking_a_stale_tree_keeps_what_a_stopped_run_left_recorded() {
        let name = unique_name("LpmIdentityStaleRun");
        let sid = derive_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let kept = tree_with_a_file(root.path(), "kept");
        let dropped = tree_with_a_file(root.path(), "dropped");
        let record = root.path().join("grants.json");
        record_grants(&record, &[kept.clone(), dropped]).unwrap();
        let left = RunAccess {
            traversed: vec![root.path().to_path_buf()],
            denied: vec![root.path().join(".env")],
        };
        record_run_access(&record, &left).unwrap();

        revoke_stale_grants(&record, std::slice::from_ref(&kept), sid.0).unwrap();

        assert_eq!(read_record(&record).run, left);
    }

    #[test]
    fn a_run_that_ends_forgets_what_it_took_back_and_keeps_the_rest() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("grants.json");
        let kept = RunAccess {
            traversed: vec![PathBuf::from(r"C:\kept")],
            denied: Vec::new(),
        };
        let ended = RunAccess {
            traversed: vec![PathBuf::from(r"C:\Users")],
            denied: vec![PathBuf::from(r"C:\Users\me\.env")],
        };
        record_run_access(&record, &kept).unwrap();
        record_run_access(&record, &ended).unwrap();
        record_grants(&record, &[PathBuf::from(r"C:\tree")]).unwrap();

        forget_run_access(&record, &ended).unwrap();

        let read = read_record(&record);
        assert_eq!(read.run, kept);
        assert_eq!(read.trees, [PathBuf::from(r"C:\tree")]);
    }

    #[test]
    fn an_entry_that_is_gone_holds_nothing_to_take_back() {
        let name = unique_name("LpmIdentityGone");
        let sid = derive_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let record = root.path().join("grants.json");
        record_run_access(
            &record,
            &RunAccess {
                traversed: vec![root.path().join("removed")],
                denied: vec![root.path().join("removed").join(".env")],
            },
        )
        .unwrap();

        take_back_run_access(&record, sid.0).unwrap();

        assert!(read_record(&record).run.is_empty());
    }

    #[test]
    fn a_cleanup_run_takes_back_what_a_stopped_run_left_set() {
        let name = unique_name("LpmIdentityCleanupStopped");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join(".env");
        std::fs::write(&secret, b"TOKEN=1").unwrap();
        let record = root.path().join("grants.json");
        stopped_run(&record, root.path(), &secret, sid.0);

        revoke_all(&record, sid.0).unwrap();

        assert!(!grants(root.path(), sid.0));
        assert!(!denies(&secret, sid.0));
        assert!(!record.exists());
        delete_profile(&name);
    }
}
