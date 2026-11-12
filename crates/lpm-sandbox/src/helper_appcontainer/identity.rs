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

/// What a grant or sweep record holds: the trees as the helper left them.
#[derive(serde::Serialize, serde::Deserialize)]
struct TreeRecord {
    version: u32,
    trees: Vec<PathBuf>,
}

const TREE_RECORD_VERSION: u32 = 1;

/// The trees `path` records; none when it doesn't exist yet. One that
/// can't be read is logged and read as none: the run then revokes nothing
/// it doesn't grant again, and writes a new record.
fn read_record(path: &Path) -> Vec<PathBuf> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<TreeRecord>(&bytes) {
            Ok(record) if record.version == TREE_RECORD_VERSION => record.trees,
            Ok(record) => {
                tracing::warn!(
                    target: "lpm_sandbox::helper_appcontainer",
                    "ignoring {} written by another release (version {})",
                    path.display(),
                    record.version,
                );
                Vec::new()
            }
            Err(error) => {
                tracing::warn!(
                    target: "lpm_sandbox::helper_appcontainer",
                    "ignoring unreadable {}: {error}",
                    path.display(),
                );
                Vec::new()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            tracing::warn!(
                target: "lpm_sandbox::helper_appcontainer",
                "ignoring unreadable {}: {error}",
                path.display(),
            );
            Vec::new()
        }
    }
}

fn write_record(path: &Path, trees: &[PathBuf]) -> Result<(), AppContainerError> {
    let record = TreeRecord {
        version: TREE_RECORD_VERSION,
        trees: trees.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&record).expect("a tree record serializes");
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
        .iter()
        .filter(|tree| !is_covered(tree, &covering))
        .cloned()
        .collect();
    let mut both = current.to_vec();
    both.extend(stale.iter().cloned());
    write_record(record, &both)?;
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
    write_record(record, granted)
}

/// Revokes every tree the identity was granted and removes its record,
/// as a cleanup run does once the package leaves the project.
pub(super) fn revoke_all(record: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let mut failed = None;
    for tree in read_record(record) {
        if let Err(error) = revoke_tree(&tree, sid, true) {
            failed.get_or_insert(error);
        }
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
/// fails the revoke as the root would: the profile must outlive it, as a
/// new one for the same project and package gets the same SID. An entry
/// that vanished or became a link meanwhile holds nothing of it.
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
        visit_entries_below(
            root,
            &|path| match setup::remove_allowed_aces_where(path, granted) {
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
            },
        );
        if let Some(error) = failed.into_inner().expect("revoke failure lock") {
            return Err(error);
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
    let mut swept = read_record(record);
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
    write_record(record, &swept)
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
        let (_, matching) =
            dacl_without_allowed_aces_where(path, dacl, |ace| unsafe { EqualSid(ace, sid) != 0 })
                .unwrap();
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

    /// Makes `path` a directory this process can read but not change while
    /// it runs without privileges, as `C:\Program Files\nodejs` is to its
    /// user: a best-effort grant there never lands, yet the grant record
    /// names it.
    fn lock_directory(path: &Path) {
        let user = setup::current_user_sid().unwrap();
        // Entries inherited from the tree become the directory's own, a
        // grant among them; then only reading is left, to this user and,
        // through OWNER RIGHTS, to the owner, an elevated test's too.
        let icacls = |args: &[&str]| {
            let output = std::process::Command::new("icacls.exe")
                .arg(path)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
        };
        icacls(&["/inheritance:d"]);
        icacls(&[
            "/remove:g",
            "*S-1-5-32-544",
            "*S-1-5-18",
            &format!("*{user}"),
        ]);
        icacls(&["/grant", &format!("*{user}:(RX)"), "*S-1-3-4:(RX)"]);
        assert!(!without_privileges(|| setup::can_change_permissions(path)));
    }

    /// Disables every privilege of this process until it drops, for a check
    /// the revoke's walker threads make as well as this one: hosted CI
    /// administrators hold backup and restore privileges that open any
    /// directory to change it. Nothing else in these tests uses one.
    struct ProcessWithoutPrivileges {
        token: HandleGuard,
        previous: Vec<u64>,
    }

    impl ProcessWithoutPrivileges {
        fn new() -> Self {
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
            Self { token, previous }
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
    fn a_cleanup_run_passes_a_recorded_tree_it_never_granted_and_could_not_change() {
        let name = unique_name("LpmIdentityUnchanged");
        let sid = create_or_reuse_appcontainer_sid(&name).unwrap();
        let _profile = Profile(name.clone());
        let root = tempfile::tempdir().unwrap();
        let tree = tree_with_a_file(root.path(), "granted");
        grant_dacl_ace_to_tree(&tree, None, sid.0, FILE_GENERIC_READ, true).unwrap();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        lock_directory(&locked);
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
        lock_directory(&locked);
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
        lock_directory(&locked);
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
        assert_eq!(read_record(&record), std::slice::from_ref(&tree));
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
        assert!(read_record(&record).is_empty());
        let trees = vec![PathBuf::from(r"C:\one"), PathBuf::from(r"C:\two")];
        write_record(&record, &trees).unwrap();
        assert_eq!(read_record(&record), trees);
        std::fs::write(&record, b"not json").unwrap();
        assert!(read_record(&record).is_empty());
    }
}
