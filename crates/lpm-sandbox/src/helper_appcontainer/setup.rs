//! Per-directory capabilities for explicitly approved Windows filesystem access.

use super::*;

mod walk;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use windows_sys::Win32::Security::{
    CopySid, DeriveCapabilitySidsFromName, GetLengthSid, GetTokenInformation, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE,
    GetFileInformationByHandle, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const METADATA_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE;
const TOOL_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// The approved access to one directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Metadata and traversal of this directory only, without directory enumeration.
    Metadata,
    /// Read and execute this tool tree, without following links or granting writes.
    ToolReadExecute,
}

impl Permission {
    fn mask(self) -> u32 {
        match self {
            Self::Metadata => METADATA_ACCESS,
            Self::ToolReadExecute => TOOL_ACCESS,
        }
    }

    fn inheritance(self) -> u32 {
        match self {
            Self::Metadata => 0,
            Self::ToolReadExecute => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    volume: u32,
    index: u64,
}

/// A directory grant shown before setup changes permissions.
#[derive(Debug, Serialize)]
pub struct Grant {
    /// Canonical directory path.
    pub path: PathBuf,
    /// Access approved by this grant.
    pub permission: Permission,
    /// Whether the root currently carries the expected capability grant.
    pub configured: bool,
    #[serde(skip)]
    identity: Identity,
    #[serde(skip)]
    capability_name: String,
}

/// A preview bound to a specific Windows user and directory identities.
#[derive(Debug, Serialize)]
pub struct Plan {
    /// User whose unelevated sandbox processes can use these grants.
    pub user_sid: String,
    /// Exact directory permissions requested by the setup command.
    pub grants: Vec<Grant>,
}

pub(super) struct CapabilitySid(Vec<u32>);

impl CapabilitySid {
    pub(super) fn raw(&self) -> PSID {
        self.0.as_ptr() as PSID
    }
}

fn failure(reason: impl Into<String>) -> AppContainerError {
    AppContainerError::Setup {
        reason: reason.into(),
    }
}

fn last_error(operation: &str) -> AppContainerError {
    failure(format!("{operation}: {}", std::io::Error::last_os_error()))
}

fn process_token() -> Result<HandleGuard, AppContainerError> {
    let mut token = ptr::null_mut();
    // SAFETY: the pseudo process handle is valid and the out parameter is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("read the Windows user token"));
    }
    Ok(HandleGuard(token))
}

/// Return the Windows user SID without reading credentials or environment variables.
pub fn current_user_sid() -> Result<String, AppContainerError> {
    let token = process_token()?;
    let mut length = 0;
    // SAFETY: the first call requests the required buffer length only.
    unsafe { GetTokenInformation(token.as_raw(), TokenUser, ptr::null_mut(), 0, &mut length) };
    if length == 0 {
        return Err(last_error("size the Windows user identity"));
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the aligned buffer has at least `length` bytes and the token remains open.
    if unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(last_error("read the Windows user identity"));
    }
    // SAFETY: a successful TokenUser query initializes the TOKEN_USER header.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> Result<String, AppContainerError> {
    let mut text = ptr::null_mut();
    // SAFETY: the SID is valid and the API returns a LocalFree-owned terminated string.
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut text)
    } == 0
    {
        return Err(last_error("format the Windows user identity"));
    }
    let _text = LocalAllocGuard(text.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: `length` is the valid initialized string length.
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, length)
    }))
}

fn normalize_user_sid(value: &str) -> Result<String, AppContainerError> {
    let mut sid = ptr::null_mut();
    let wide = str_to_wide_with_nul(value);
    if value.contains('\0') {
        return Err(failure("the target user SID contains NUL"));
    }
    // SAFETY: the terminated string and initialized out parameter live through the call.
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(wide.as_ptr(), &mut sid)
    } == 0
    {
        return Err(failure(
            "invalid target user SID; copy user_sid from the unelevated preview",
        ));
    }
    let sid = SidGuard(sid);
    sid_string(sid.0)
}

/// Whether the current process has an elevated Windows token.
pub fn is_elevated() -> Result<bool, AppContainerError> {
    let token = process_token()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    // SAFETY: elevation is a correctly sized writable TOKEN_ELEVATION record.
    if unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenElevation,
            ptr::addr_of_mut!(elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(last_error("read the Windows elevation state"));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn capability_sid(name: &str) -> Result<CapabilitySid, AppContainerError> {
    struct AllocatedSids {
        data: *mut PSID,
        count: u32,
    }
    impl Drop for AllocatedSids {
        fn drop(&mut self) {
            if self.data.is_null() {
                return;
            }
            // SAFETY: the API allocates the array and each SID with LocalAlloc.
            unsafe {
                for index in 0..self.count as usize {
                    LocalFree(*self.data.add(index) as HLOCAL);
                }
                LocalFree(self.data.cast());
            }
        }
    }
    let mut groups = AllocatedSids {
        data: ptr::null_mut(),
        count: 0,
    };
    let mut capabilities = AllocatedSids {
        data: ptr::null_mut(),
        count: 0,
    };
    let wide = str_to_wide_with_nul(name);
    // SAFETY: all out parameters are initialized and owned by their cleanup guards.
    if unsafe {
        DeriveCapabilitySidsFromName(
            wide.as_ptr(),
            &mut groups.data,
            &mut groups.count,
            &mut capabilities.data,
            &mut capabilities.count,
        )
    } == 0
    {
        return Err(last_error("derive a sandbox filesystem capability"));
    }
    if capabilities.count != 1 || capabilities.data.is_null() {
        return Err(failure(
            "Windows returned an unexpected filesystem capability",
        ));
    }
    // SAFETY: the successful API call returned one valid SID.
    let raw = unsafe { *capabilities.data };
    let length = unsafe { GetLengthSid(raw) };
    let mut copy = vec![0u32; (length as usize).div_ceil(4)];
    // SAFETY: the aligned destination can hold the complete SID.
    if unsafe { CopySid(length, copy.as_mut_ptr().cast(), raw) } == 0 {
        return Err(last_error("copy a sandbox filesystem capability"));
    }
    Ok(CapabilitySid(copy))
}

fn open_permissions(
    path: &Path,
    write: bool,
) -> Result<(HandleGuard, Identity), AppContainerError> {
    let path_wide = to_wide_with_nul(path.as_os_str());
    // SAFETY: no handle is inherited; the final component is opened without following links.
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | if write { WRITE_DAC } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let path = path.to_path_buf();
        let win32_error = unsafe { GetLastError() };
        return Err(if write {
            AppContainerError::WriteDacl { path, win32_error }
        } else {
            AppContainerError::ReadDacl { path, win32_error }
        });
    }
    let handle = HandleGuard(raw);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is live and `info` is a correctly sized output record.
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(last_error("inspect a sandbox permission target"));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AppContainerError::ReparsePointRoot {
            path: path.to_path_buf(),
        });
    }
    Ok((
        handle,
        Identity {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        },
    ))
}

fn grant_for(
    path: &Path,
    permission: Permission,
    user_sid: &str,
) -> Result<Grant, AppContainerError> {
    let target = walk::Target::preview(path)?;
    let path = target.canonical_directory()?;
    let identity = target.identity;
    let mut hash = Sha256::new();
    hash.update(user_sid.as_bytes());
    hash.update([
        0,
        match permission {
            Permission::Metadata => 0,
            Permission::ToolReadExecute => 1,
        },
    ]);
    hash.update(identity.volume.to_le_bytes());
    hash.update(identity.index.to_le_bytes());
    for unit in path.as_os_str().encode_wide() {
        hash.update(unit.to_le_bytes());
    }
    let capability_name = format!("lpm.filesystem.v1.{}", hex::encode(hash.finalize()));
    let sid = capability_sid(&capability_name)?;
    let configured = has_grant(
        &target.handle,
        &path,
        sid.raw(),
        permission.mask(),
        permission.inheritance(),
    )?;
    Ok(Grant {
        path,
        permission,
        configured,
        identity,
        capability_name,
    })
}

/// Resolve an existing directory without following links or junctions in any component.
pub fn canonical_directory(path: &Path) -> Result<PathBuf, AppContainerError> {
    walk::Target::preview(path)?.canonical_directory()
}

/// Preview ancestor metadata and explicitly selected tool permissions without mutations.
pub fn preview(
    project: &Path,
    tools: &[PathBuf],
    user_sid: Option<&str>,
) -> Result<Plan, AppContainerError> {
    preview_paths(&[project.to_path_buf()], tools, user_sid)
}

/// Preview metadata ancestors for multiple roots, plus explicit readable tool trees.
pub fn preview_paths(
    metadata_roots: &[PathBuf],
    tools: &[PathBuf],
    user_sid: Option<&str>,
) -> Result<Plan, AppContainerError> {
    let user_sid = match user_sid {
        Some(value) => normalize_user_sid(value)?,
        None => current_user_sid()?,
    };
    let mut paths = BTreeMap::new();
    let roots = metadata_roots.iter().chain(tools).cloned();
    for root in roots {
        let root = grant_for(&root, Permission::Metadata, &user_sid)?.path;
        for parent in root.ancestors().skip(1) {
            paths
                .entry(parent.to_path_buf())
                .or_insert(Permission::Metadata);
        }
    }
    for tool in tools {
        let tool = grant_for(tool, Permission::ToolReadExecute, &user_sid)?.path;
        if tool.parent().is_none() {
            return Err(failure(
                "a drive root cannot be approved as a tool directory",
            ));
        }
        paths.insert(tool, Permission::ToolReadExecute);
    }
    let mut grants = Vec::new();
    for (path, permission) in paths {
        let grant = grant_for(&path, permission, &user_sid)?;
        // A sandboxed run needs nothing on an ancestor every AppContainer
        // may traverse already, as `C:\Program Files` lets them, and such
        // a directory is often one administrators can't change.
        if permission == Permission::Metadata
            && !grant.configured
            && packages_can_traverse(&grant.path)?
        {
            continue;
        }
        grants.push(grant);
    }
    Ok(Plan { user_sid, grants })
}

/// Whether every AppContainer may already read `path`'s metadata and
/// traverse it, so a sandboxed run needs no capability or grant there.
fn packages_can_traverse(path: &Path) -> Result<bool, AppContainerError> {
    let mut buffer = vec![0; 64];
    let packages = build_capability_attr(WinBuiltinAnyPackageSid, &mut buffer)?;
    let (handle, _) = open_permissions(path, false)?;
    has_grant(&handle, path, packages.Sid, METADATA_ACCESS, 0)
}

/// Find protected ancestors that need setup, without changing permissions or walking trees.
pub fn required_metadata_setup(roots: &[PathBuf]) -> Result<Vec<PathBuf>, AppContainerError> {
    let user = current_user_sid()?;
    let mut ancestors = std::collections::BTreeSet::new();
    for root in roots {
        let root = root
            .canonicalize()
            .map_err(|error| failure(error.to_string()))?;
        ancestors.extend(root.ancestors().skip(1).map(Path::to_path_buf));
    }
    let mut missing = Vec::new();
    for path in ancestors {
        if grant_for(&path, Permission::Metadata, &user)?.configured
            || packages_can_traverse(&path)?
        {
            continue;
        }
        if open_permissions(&path, true).is_err() {
            missing.push(path);
        }
    }
    Ok(missing)
}

fn read_dacl(
    handle: &HandleGuard,
    path: &Path,
) -> Result<(*mut ACL, LocalAllocGuard), AppContainerError> {
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: the live handle has READ_CONTROL and all out parameters are initialized.
    let error = unsafe {
        GetSecurityInfo(
            handle.as_raw(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != ERROR_SUCCESS {
        return Err(AppContainerError::ReadDacl {
            path: path.to_path_buf(),
            win32_error: error,
        });
    }
    let guard = LocalAllocGuard(descriptor.cast());
    if acl.is_null() {
        return Err(AppContainerError::NullDacl {
            path: path.to_path_buf(),
        });
    }
    Ok((acl, guard))
}

fn has_grant(
    handle: &HandleGuard,
    path: &Path,
    sid: PSID,
    mask: u32,
    inheritance: u32,
) -> Result<bool, AppContainerError> {
    let (acl, _descriptor) = read_dacl(handle, path)?;
    let mut granted = 0;
    // SAFETY: the DACL and its ACEs remain owned by the live security descriptor.
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(last_error("read a sandbox permission entry"));
        }
        let header = ace as *const windows_sys::Win32::Security::ACE_HEADER;
        unsafe {
            let flags = (*header).AceFlags as u32;
            if flags & windows_sys::Win32::Security::INHERIT_ONLY_ACE != 0 {
                continue;
            }
            // Readiness is conservative when a deny or conditional ACE could
            // override an allow through another group in the eventual token.
            if (*header).AceType != ACCESS_ALLOWED_ACE_TYPE {
                return Ok(false);
            }
            let allowed = ace as *const ACCESS_ALLOWED_ACE;
            if EqualSid(ptr::addr_of!((*allowed).SidStart) as PSID, sid) != 0
                && flags & windows_sys::Win32::Security::INHERIT_ONLY_ACE == 0
                && flags & inheritance == inheritance
            {
                let mut access = (*allowed).Mask;
                windows_sys::Win32::Security::MapGenericMask(
                    &mut access,
                    &windows_sys::Win32::Security::GENERIC_MAPPING {
                        GenericRead: FILE_GENERIC_READ,
                        GenericWrite: FILE_GENERIC_WRITE,
                        GenericExecute: FILE_GENERIC_EXECUTE,
                        GenericAll: windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
                    },
                );
                granted |= access;
            }
        }
    }
    Ok(granted & mask == mask)
}

fn write_dacl(handle: &HandleGuard, path: &Path, acl: *mut ACL) -> Result<(), AppContainerError> {
    let mut descriptor = windows_sys::Win32::Security::SECURITY_DESCRIPTOR::default();
    // SAFETY: the initialized descriptor borrows the live ACL for the duration of the call.
    let success = unsafe {
        let raw = ptr::addr_of_mut!(descriptor).cast();
        windows_sys::Win32::Security::InitializeSecurityDescriptor(raw, 1) != 0
            && windows_sys::Win32::Security::SetSecurityDescriptorDacl(raw, 1, acl, 0) != 0
            && windows_sys::Win32::Security::SetKernelObjectSecurity(
                handle.as_raw(),
                DACL_SECURITY_INFORMATION,
                raw,
            ) != 0
    };
    if !success {
        return Err(AppContainerError::WriteDacl {
            path: path.to_path_buf(),
            win32_error: unsafe { GetLastError() },
        });
    }
    Ok(())
}

fn lock_object(identity: Identity) -> Result<ProfileCreationLock, AppContainerError> {
    let name = format!(
        r"Global\LpmSandboxDacl-{:08x}-{:016x}",
        identity.volume, identity.index
    );
    lock_named(&name)
}

pub(super) fn lock_named(name: &str) -> Result<ProfileCreationLock, AppContainerError> {
    let wide = str_to_wide_with_nul(name);
    let sddl = str_to_wide_with_nul("D:(A;;0x00100001;;;AU)(A;;GA;;;SY)");
    let mut descriptor = ptr::null_mut();
    // SAFETY: the SDDL is terminated and the descriptor is LocalFree-owned on success.
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr(), 1, &mut descriptor, ptr::null_mut())
    } == 0
    {
        return Err(last_error("create the permission lock descriptor"));
    }
    let _descriptor = LocalAllocGuard(descriptor.cast());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // Different logon sessions can update the same DACL. Share only mutex
    // synchronization/modification rights, never filesystem permissions.
    // SAFETY: the name and descriptor live through the non-inheriting create call.
    let raw = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexExW(
            &attributes,
            wide.as_ptr(),
            0,
            0x0010_0001,
        )
    };
    if raw.is_null() {
        return Err(last_error("open the sandbox permission lock"));
    }
    let handle = HandleGuard(raw);
    let wait = unsafe { WaitForSingleObject(raw, INFINITE) };
    if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
        return Err(last_error("acquire the sandbox permission lock"));
    }
    Ok(ProfileCreationLock(handle))
}

pub(super) fn update_ace(
    path: &Path,
    sid: PSID,
    grant: Option<(u32, u32)>,
) -> Result<(), AppContainerError> {
    let (handle, identity) = open_permissions(path, true)?;
    let _lock = lock_object(identity)?;
    update_open_ace(&handle, path, sid, grant)
}

/// Removes the access-allowed ACEs whose SID `drops` picks from `path`'s
/// DACL, under the lock every DACL update here takes, and says how many
/// it removed. A DACL it would leave as it is isn't written.
pub(super) fn remove_allowed_aces_where(
    path: &Path,
    drops: impl Fn(PSID) -> bool,
) -> Result<usize, AppContainerError> {
    let (handle, identity) = open_permissions(path, true)?;
    let _lock = lock_object(identity)?;
    let (old, _descriptor) = read_dacl(&handle, path)?;
    let (mut filtered, removed) = super::dacl_without_allowed_aces_where(path, old, drops)?;
    if removed > 0 {
        write_dacl(&handle, path, filtered.as_mut_ptr().cast())?;
    }
    Ok(removed)
}

fn update_open_ace(
    handle: &HandleGuard,
    path: &Path,
    sid: PSID,
    grant: Option<(u32, u32)>,
) -> Result<(), AppContainerError> {
    let (old, _descriptor) = read_dacl(handle, path)?;
    match grant {
        Some((mask, inheritance)) => {
            let entry = EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask,
                grfAccessMode: SET_ACCESS,
                grfInheritance: inheritance,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_GROUP,
                    ptstrName: sid.cast(),
                },
            };
            let mut updated = ptr::null_mut();
            // SAFETY: the SID and old ACL remain live through the synchronous merge.
            let error = unsafe { SetEntriesInAclW(1, &entry, old, &mut updated) };
            if error != ERROR_SUCCESS {
                return Err(AppContainerError::MergeDacl {
                    path: path.to_path_buf(),
                    win32_error: error,
                });
            }
            let _updated = LocalAllocGuard(updated.cast());
            write_dacl(handle, path, updated)
        }
        None => remove_open_ace(handle, path, sid).map(|_| ()),
    }
}

/// Takes `sid`'s allow entries out of the open object's DACL, writing
/// nothing when it holds none, and gives back the DACL it had when it did.
fn remove_open_ace(
    handle: &HandleGuard,
    path: &Path,
    sid: PSID,
) -> Result<Option<Vec<u32>>, AppContainerError> {
    let (old, _descriptor) = read_dacl(handle, path)?;
    // SAFETY: both SIDs are valid for the comparison.
    let (mut filtered, removed) =
        super::dacl_without_allowed_aces_where(path, old, |ace| unsafe {
            EqualSid(ace, sid) != 0
        })?;
    if removed == 0 {
        return Ok(None);
    }
    // SAFETY: `old` is the DACL inside the live descriptor, `AclSize` bytes long.
    let size = usize::from(unsafe { (*old).AclSize });
    let mut saved = vec![0u32; size.div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: `saved` holds at least `size` bytes and doesn't overlap `old`.
    unsafe { ptr::copy_nonoverlapping(old.cast::<u8>(), saved.as_mut_ptr().cast::<u8>(), size) };
    write_dacl(handle, path, filtered.as_mut_ptr().cast())?;
    Ok(Some(saved))
}

/// A tree that receives a lifecycle grant: its root, opened once by path,
/// and every entry below it, opened relative to that handle by
/// [`walk::Target::below`]. Lifecycle scripts running at the same time can
/// write inside the tree, so a name listed as a directory may be a junction
/// by the time its entries are granted; a grant reached through it would
/// land outside the tree and never be revoked.
pub(super) struct GrantTree {
    root: walk::Target,
    path: PathBuf,
}

// SAFETY: threads only open entries relative to the root handle, which the
// kernel serves concurrently; the handle is closed once, when the tree drops.
unsafe impl Sync for GrantTree {}

impl GrantTree {
    /// Opens `path` for a grant. Links among its ancestors are followed, as
    /// a configured root may sit below one, but a root that is itself a link
    /// is refused.
    pub(super) fn open(path: &Path) -> Result<Self, AppContainerError> {
        let (handle, identity) = open_permissions(path, true)?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is live and the output is correctly sized.
        if unsafe { GetFileInformationByHandle(handle.as_raw(), &mut info) } == 0 {
            return Err(last_error("inspect a sandbox grant root"));
        }
        Ok(Self {
            root: walk::Target {
                handle,
                identity,
                directory: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            },
            path: path.to_path_buf(),
        })
    }

    /// Opens `path` for a grant from `base`, a writable root above it,
    /// refusing a reparse point anywhere between the two: a script may turn
    /// any directory below `base` into one.
    pub(super) fn open_below(base: &Path, path: &Path) -> Result<Self, AppContainerError> {
        let relative = path.strip_prefix(base).map_err(|_| {
            failure(format!(
                "{} is outside the writable root {}",
                path.display(),
                base.display()
            ))
        })?;
        let (handle, identity) = open_permissions(base, false)?;
        let base = walk::Target {
            handle,
            identity,
            directory: true,
        };
        Ok(Self {
            root: base.below(relative, path)?,
            path: path.to_path_buf(),
        })
    }

    pub(super) fn is_directory(&self) -> bool {
        self.root.directory
    }

    pub(super) fn grant_root(&self, sid: PSID, grant: (u32, u32)) -> Result<(), AppContainerError> {
        update_pinned_ace(&self.root.handle, &self.path, sid, Some(grant))
    }

    /// Grants `sid` on `path`, an entry below the root, opened without
    /// passing through a reparse point anywhere below the root.
    pub(super) fn grant_entry(
        &self,
        path: &Path,
        sid: PSID,
        grant: (u32, u32),
    ) -> Result<(), AppContainerError> {
        let relative = path.strip_prefix(&self.path).map_err(|_| {
            failure(format!(
                "{} is outside the sandbox grant root {}",
                path.display(),
                self.path.display()
            ))
        })?;
        let entry = self.root.below(relative, path)?;
        update_pinned_ace(&entry.handle, path, sid, Some(grant))
    }
}

/// Denies `sid` reading `path` and removes any allow entry it has there,
/// leaving every other entry and the file's inheritance as they were. The
/// update holds the lock every DACL write here takes: runs of other packages
/// deny and release their own SIDs on the same project secrets at the same
/// time, and none may undo another's denial or lose a grant update.
pub(super) fn deny_appcontainer_read(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let (handle, identity) = open_permissions(path, true)?;
    let _lock = lock_object(identity)?;
    let (old, _descriptor) = read_dacl(&handle, path)?;
    let mut filtered = dacl_without_allowed_aces_for_sid(path, old, sid)?;
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        grfAccessMode: windows_sys::Win32::Security::Authorization::DENY_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: sid.cast(),
        },
    };
    let mut denied = ptr::null_mut();
    // SAFETY: the filtered ACL and the SID remain valid through the merge,
    // which places the explicit deny ahead of every allow.
    let error = unsafe { SetEntriesInAclW(1, &entry, filtered.as_mut_ptr().cast(), &mut denied) };
    if error != ERROR_SUCCESS {
        return Err(AppContainerError::MergeDacl {
            path: path.to_path_buf(),
            win32_error: error,
        });
    }
    let _denied = LocalAllocGuard(denied.cast());
    write_dacl(&handle, path, denied)
}

/// Removes the read denial [`deny_appcontainer_read`] gave `sid` on `path`,
/// and nothing else, under the same lock.
pub(super) fn remove_appcontainer_read_deny(
    path: &Path,
    sid: PSID,
) -> Result<(), AppContainerError> {
    let (handle, identity) = open_permissions(path, true)?;
    let _lock = lock_object(identity)?;
    let (old, _descriptor) = read_dacl(&handle, path)?;
    let (mut filtered, removed) =
        super::dacl_without_aces_where(path, old, ACCESS_DENIED_ACE_TYPE, |ace_sid| {
            // SAFETY: both SIDs are valid for the comparison.
            unsafe { EqualSid(ace_sid, sid) != 0 }
        })?;
    if removed > 0 {
        write_dacl(&handle, path, filtered.as_mut_ptr().cast())?;
    }
    Ok(())
}

// Reject reparses during the kernel path lookup. Child traversal then uses
// directory handles, because a pinned directory can still become a junction.
fn pin_grant(entry: &Grant) -> Result<(Vec<walk::Target>, walk::Target), AppContainerError> {
    let mut parents = Vec::new();
    for ancestor in entry
        .path
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        parents.push(walk::Target::open(ancestor, false)?);
    }
    let root = walk::Target::open(&entry.path, true)?;
    if root.identity != entry.identity {
        return Err(failure(format!(
            "{} changed after the preview; create a new preview",
            entry.path.display()
        )));
    }
    Ok((parents, root))
}

fn update_pinned_ace(
    handle: &HandleGuard,
    path: &Path,
    sid: PSID,
    value: Option<(u32, u32)>,
) -> Result<(), AppContainerError> {
    let _lock = lock_pinned(handle)?;
    update_open_ace(handle, path, sid, value)
}

/// The lock on the object `handle` has open, which every DACL change to it
/// takes.
fn lock_pinned(handle: &HandleGuard) -> Result<impl Drop, AppContainerError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the pinned file handle is live and the output is correctly sized.
    if unsafe { GetFileInformationByHandle(handle.as_raw(), &mut info) } == 0 {
        return Err(last_error("inspect the pinned permission target"));
    }
    lock_object(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

/// A DACL a removal replaced, kept with the object it belongs to, so that
/// undoing the run writes back exactly that.
pub(super) struct SavedDacl {
    handle: HandleGuard,
    path: PathBuf,
    dacl: Vec<u32>,
}

/// Takes `sid`'s entries out of the pinned object's DACL, as
/// [`update_pinned_ace`] does, and adds the DACL it had to `journal` when
/// it held any.
pub(super) fn remove_pinned_ace_saving(
    handle: &HandleGuard,
    path: &Path,
    sid: PSID,
    journal: &mut Vec<SavedDacl>,
) -> Result<(), AppContainerError> {
    let _lock = lock_pinned(handle)?;
    let Some(dacl) = remove_open_ace(handle, path, sid)? else {
        return Ok(());
    };
    let mut duplicate = ptr::null_mut();
    // SAFETY: both process handles are this process's pseudo handle, and
    // `handle` is live; the duplicate is owned by the guard below.
    if unsafe {
        windows_sys::Win32::Foundation::DuplicateHandle(
            GetCurrentProcess(),
            handle.as_raw(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let error = last_error("keep the permission target open to undo a removal");
        // Put this one back now: nothing else would.
        let _ = write_dacl(handle, path, dacl.as_ptr().cast_mut().cast());
        return Err(error);
    }
    journal.push(SavedDacl {
        handle: HandleGuard(duplicate),
        path: path.to_path_buf(),
        dacl,
    });
    Ok(())
}

/// Writes back, newest first, the DACLs a removal replaced.
fn restore_saved(journal: Vec<SavedDacl>) -> Result<(), AppContainerError> {
    let mut first_error = None;
    for mut saved in journal.into_iter().rev() {
        let restored = lock_pinned(&saved.handle).and_then(|_lock| {
            write_dacl(&saved.handle, &saved.path, saved.dacl.as_mut_ptr().cast())
        });
        if let Err(error) = restored {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Apply or remove only the previewed capabilities. This function never runs package scripts.
/// It opens every directory before it changes one, and a failure partway
/// puts back what it had changed.
pub fn apply(plan: &Plan, remove: bool) -> Result<(), AppContainerError> {
    if !is_elevated()? {
        return Err(failure(
            "open an administrator terminal to apply or remove permissions; keep publishing in your normal terminal",
        ));
    }
    apply_plan(plan, remove)
}

fn apply_plan(plan: &Plan, remove: bool) -> Result<(), AppContainerError> {
    // Every tree's setup lock is held, taken in one order, from the first
    // look until the last change or undo: another run's change to these
    // trees can't land between what this run found and what it puts back.
    let mut capabilities: Vec<&str> = plan
        .grants
        .iter()
        .map(|entry| entry.capability_name.as_str())
        .collect();
    capabilities.sort_unstable();
    capabilities.dedup();
    let _setup_locks = capabilities
        .into_iter()
        .map(|name| lock_named(&format!(r"Global\LpmSandboxSetup-{name}")))
        .collect::<Result<Vec<_>, _>>()?;
    // Each directory is opened, and whether it holds its capability noted,
    // before any changes: what a failure puts back is what this run found.
    let targets = plan
        .grants
        .iter()
        .map(|entry| {
            let (parents, root) = pin_grant(entry)?;
            let sid = capability_sid(&entry.capability_name)?;
            let held = holds_ace(&root.handle, &entry.path, sid.raw())?;
            Ok((parents, root, sid, held))
        })
        .collect::<Result<Vec<_>, AppContainerError>>()
        .map_err(|error| failure(format!("{}. Nothing was changed", setup_reason(error))))?;
    // What each removal replaced, in order, to write back on a failure: a
    // removal that granted the tree again would also reach files that never
    // held the capability.
    let mut removed: Vec<Vec<SavedDacl>> = Vec::with_capacity(plan.grants.len());
    for (index, entry) in plan.grants.iter().enumerate() {
        let (_, root, sid, _) = &targets[index];
        let changed = if remove {
            let mut journal = Vec::new();
            let changed = change_grant_saving(entry, root, sid, false, Some(&mut journal));
            removed.push(journal);
            changed
        } else {
            change_grant(entry, root, sid, true)
        };
        let Err(error) = changed else {
            continue;
        };
        let mut undo_error = None;
        for journal in removed.drain(..).rev() {
            if let Err(error) = restore_saved(journal) {
                undo_error.get_or_insert(error);
            }
        }
        for (undone, entry) in plan.grants[..=index].iter().enumerate().rev() {
            let (_, root, sid, held) = &targets[undone];
            let undo = match (remove, *held) {
                // A removal is undone from what it saved, above.
                (true, _) => Ok(()),
                // A grant that wasn't there before: remove it again.
                (false, false) => change_grant(entry, root, sid, false),
                // Applying again took away only the root's entry, while it
                // walked the tree, and gave it back unless it stopped there.
                (false, true) if undone == index => restore_root(entry, root, sid),
                _ => Ok(()),
            };
            if let Err(error) = undo {
                undo_error.get_or_insert(error);
            }
        }
        let stopped = format!(
            "permission setup stopped at {}: {}",
            entry.path.display(),
            setup_reason(error)
        );
        // Applying a tool tree again grants what it reaches below the root
        // as it walks, and puts back only the root's own entry.
        let reapplied_tool =
            !remove && targets[index].3 && entry.permission == Permission::ToolReadExecute;
        return Err(failure(match undo_error {
            None if reapplied_tool => format!(
                "{stopped}. It put back what it had changed, except that files in that tool tree it reached may now be readable, as the rest of the tree already is"
            ),
            None => format!("{stopped}. It put back what it had changed"),
            Some(undo_error) => format!(
                "{stopped}. Putting back what it had changed failed too ({}), so some permissions may have changed; preview and retry the same operation",
                setup_reason(undo_error)
            ),
        }));
    }
    Ok(())
}

/// `error`'s message without the "setup failed" its [`failure`] wrapper
/// adds again.
fn setup_reason(error: AppContainerError) -> String {
    match error {
        AppContainerError::Setup { reason } => reason,
        other => other.to_string(),
    }
}

/// Whether `path`'s DACL holds an access-allowed entry for `sid`.
fn holds_ace(handle: &HandleGuard, path: &Path, sid: PSID) -> Result<bool, AppContainerError> {
    let (dacl, _descriptor) = read_dacl(handle, path)?;
    // SAFETY: both SIDs are valid for the comparison.
    let (_, held) = super::dacl_without_allowed_aces_where(path, dacl, |ace| unsafe {
        EqualSid(ace, sid) != 0
    })?;
    Ok(held > 0)
}

/// Gives `entry`'s root its capability entry back, as it had before.
fn restore_root(
    entry: &Grant,
    root: &walk::Target,
    sid: &CapabilitySid,
) -> Result<(), AppContainerError> {
    let _setup_lock = lock_named(&format!(
        r"Global\LpmSandboxSetup-{}",
        entry.capability_name
    ))?;
    update_pinned_ace(
        &root.handle,
        &entry.path,
        sid.raw(),
        Some((entry.permission.mask(), entry.permission.inheritance())),
    )
}

/// Grants `entry`'s capability on its pinned `root`, or removes it.
fn change_grant(
    entry: &Grant,
    root: &walk::Target,
    sid: &CapabilitySid,
    grant: bool,
) -> Result<(), AppContainerError> {
    change_grant_saving(entry, root, sid, grant, None)
}

/// [`change_grant`], adding to `journal`, for a removal, each DACL it
/// replaces, so that undoing it puts back only what was there.
fn change_grant_saving(
    entry: &Grant,
    root: &walk::Target,
    sid: &CapabilitySid,
    grant: bool,
    mut journal: Option<&mut Vec<SavedDacl>>,
) -> Result<(), AppContainerError> {
    // Serialize the complete tree update separately from individual DACL
    // merges, including across administrator accounts and logon sessions.
    let _setup_lock = lock_named(&format!(
        r"Global\LpmSandboxSetup-{}",
        entry.capability_name
    ))?;
    let value = grant.then_some((entry.permission.mask(), entry.permission.inheritance()));
    let remove_root = |journal: Option<&mut Vec<SavedDacl>>| match journal {
        Some(journal) => remove_pinned_ace_saving(&root.handle, &entry.path, sid.raw(), journal),
        None => update_pinned_ace(&root.handle, &entry.path, sid.raw(), None),
    };
    if entry.permission == Permission::ToolReadExecute {
        // Re-applying also deactivates the root until the walk completes.
        remove_root(journal.as_deref_mut())?;
        walk::children_saving(root, &entry.path, sid.raw(), value, journal.as_deref_mut())?;
    }
    match value {
        Some(_) => update_pinned_ace(&root.handle, &entry.path, sid.raw(), value),
        None => remove_root(journal),
    }
}

pub(super) struct PreparedAccess<'a> {
    pub(super) capabilities: Vec<CapabilitySid>,
    pub(super) configured_tools: HashSet<PathBuf>,
    temporary: Vec<PathBuf>,
    invocation: &'a SidGuard,
}

impl Drop for PreparedAccess<'_> {
    fn drop(&mut self) {
        for path in self.temporary.iter().rev() {
            if let Err(error) = update_ace(path, self.invocation.0, None) {
                tracing::warn!(path = %path.display(), "cannot remove temporary sandbox metadata access: {error}");
            }
        }
    }
}

pub(super) fn prepare<'a>(
    args: &HelperArgs,
    invocation: &'a SidGuard,
) -> Result<PreparedAccess<'a>, AppContainerError> {
    let user_sid = current_user_sid()?;
    let mut access = PreparedAccess {
        capabilities: Vec::new(),
        configured_tools: HashSet::new(),
        temporary: Vec::new(),
        invocation,
    };
    let roots: Vec<PathBuf> = args
        .readable_dirs
        .iter()
        .chain(&args.writable_dirs)
        .chain(&args.best_effort_readable_dirs)
        .filter(|path| {
            std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(&metadata))
        })
        .filter_map(|path| path.canonicalize().ok())
        .collect();
    let mut ancestors = std::collections::BTreeSet::new();
    for root in &roots {
        ancestors.extend(
            root.ancestors()
                .skip(1)
                .filter(|ancestor| !roots.iter().any(|root| ancestor.starts_with(root)))
                .map(Path::to_path_buf),
        );
    }
    for path in ancestors {
        let entry = grant_for(&path, Permission::Metadata, &user_sid)?;
        if entry.configured {
            access
                .capabilities
                .push(capability_sid(&entry.capability_name)?);
        } else if !packages_can_traverse(&path)? {
            update_ace(&path, invocation.0, Some((METADATA_ACCESS, 0)))
                .map_err(|_| AppContainerError::SetupRequired { path: path.clone() })?;
            access.temporary.push(path);
        }
    }
    let protected_paths: Vec<_> = args
        .secret_read_denied_paths
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect();
    for tool in &args.best_effort_readable_dirs {
        if !std::fs::symlink_metadata(tool)
            .is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(&metadata))
        {
            continue;
        }
        let canonical = tool
            .canonicalize()
            .map_err(|error| failure(error.to_string()))?;
        let entry = grant_for(&canonical, Permission::ToolReadExecute, &user_sid)?;
        // A tool capability can authorize reads independently of the deny
        // for this invocation's SID. Exclude both ancestors and descendants
        // of protected paths from the capability set.
        if entry.configured
            && !protected_paths
                .iter()
                .any(|path| path.starts_with(&entry.path) || entry.path.starts_with(path))
        {
            access.configured_tools.insert(entry.path.clone());
            access
                .capabilities
                .push(capability_sid(&entry.capability_name)?);
        }
    }
    Ok(access)
}

/// Whether this thread can open `path` to change its permissions.
#[cfg(test)]
pub(super) fn can_change_permissions(path: &Path) -> bool {
    open_permissions(path, true).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, SE_DACL_PROTECTED};

    #[test]
    fn metadata_grants_do_not_inherit_and_removal_preserves_other_capabilities() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path();
        let first = grant_for(path, Permission::Metadata, &current_user_sid().unwrap()).unwrap();
        let other = grant_for(path, Permission::Metadata, "S-1-5-21-1-2-3-1001").unwrap();
        let first_sid = capability_sid(&first.capability_name).unwrap();
        let other_sid = capability_sid(&other.capability_name).unwrap();
        let (parent, _) = open_permissions(path, false).unwrap();
        let (_, old_descriptor) = read_dacl(&parent, path).unwrap();
        let mut old_control = 0;
        let mut revision = 0;
        // SAFETY: the descriptor is live and both out parameters are correctly typed.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorControl(old_descriptor.0, &mut old_control, &mut revision)
            },
            0
        );
        update_ace(path, first_sid.raw(), Some((METADATA_ACCESS, 0))).unwrap();
        update_ace(path, other_sid.raw(), Some((METADATA_ACCESS, 0))).unwrap();
        let child_path = path.join("unrelated.txt");
        std::fs::write(&child_path, "private content").unwrap();
        let (child, _) = open_permissions(&child_path, false).unwrap();
        assert!(!has_grant(&child, &child_path, first_sid.raw(), METADATA_ACCESS, 0).unwrap());
        assert!(has_grant(&parent, path, first_sid.raw(), METADATA_ACCESS, 0).unwrap());
        update_ace(path, first_sid.raw(), None).unwrap();
        assert!(!has_grant(&parent, path, first_sid.raw(), METADATA_ACCESS, 0).unwrap());
        assert!(has_grant(&parent, path, other_sid.raw(), METADATA_ACCESS, 0).unwrap());
        let (_, new_descriptor) = read_dacl(&parent, path).unwrap();
        let mut new_control = 0;
        // SAFETY: the descriptor is live and both out parameters are correctly typed.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorControl(new_descriptor.0, &mut new_control, &mut revision)
            },
            0
        );
        assert_eq!(
            old_control & SE_DACL_PROTECTED,
            new_control & SE_DACL_PROTECTED
        );
    }

    #[test]
    fn capabilities_are_bound_to_the_user_permission_path_and_directory_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("tool");
        std::fs::create_dir(&path).unwrap();
        let user = current_user_sid().unwrap();
        let initial = grant_for(&path, Permission::Metadata, &user).unwrap();
        let tool = grant_for(&path, Permission::ToolReadExecute, &user).unwrap();
        let other_user = grant_for(&path, Permission::Metadata, "S-1-5-21-1-2-3-1001").unwrap();
        assert_ne!(initial.capability_name, tool.capability_name);
        assert_ne!(initial.capability_name, other_user.capability_name);
        std::fs::rename(&path, temporary.path().join("moved")).unwrap();
        std::fs::create_dir(&path).unwrap();
        let replacement = grant_for(&path, Permission::Metadata, &user).unwrap();
        assert_ne!(initial.identity, replacement.identity);
        assert_ne!(initial.capability_name, replacement.capability_name);
    }

    /// `C:\Program Files` lets every AppContainer traverse it, and is
    /// owned by TrustedInstaller, so administrators can't change it.
    #[test]
    fn preview_leaves_out_ancestors_every_app_container_can_traverse() {
        let temporary = tempfile::tempdir().unwrap();
        let open = temporary.path().join("open");
        let project = open.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let mut buffer = vec![0; 64];
        let packages = build_capability_attr(WinBuiltinAnyPackageSid, &mut buffer).unwrap();
        update_ace(&open, packages.Sid, Some((METADATA_ACCESS, 0))).unwrap();

        let plan = preview(&project, &[], None).unwrap();

        let open = canonical_directory(&open).unwrap();
        assert!(
            !plan.grants.iter().any(|grant| grant.path == open),
            "{:?}",
            plan.grants
        );
        let parent = canonical_directory(temporary.path()).unwrap();
        assert_eq!(
            plan.grants.iter().any(|grant| grant.path == parent),
            !packages_can_traverse(&parent).unwrap()
        );

        // A grant an earlier setup made there stays in the plan, so
        // `--remove` still takes it away.
        let user = current_user_sid().unwrap();
        let earlier = grant_for(&open, Permission::Metadata, &user).unwrap();
        let sid = capability_sid(&earlier.capability_name).unwrap();
        update_ace(&open, sid.raw(), Some((METADATA_ACCESS, 0))).unwrap();
        let plan = preview(&project, &[], None).unwrap();
        assert!(
            plan.grants
                .iter()
                .any(|grant| grant.path == open && grant.configured),
            "{:?}",
            plan.grants
        );
    }

    /// Makes `path` a directory this process can read but not change, as
    /// `C:\Program Files` is to an administrator, while it runs without
    /// privileges.
    fn unchangeable_directory(path: &Path) {
        std::fs::create_dir(path).unwrap();
        lock_directory_for_test(path);
    }

    #[test]
    fn setup_changes_nothing_when_one_directory_cannot_be_changed() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        std::fs::create_dir(&first).unwrap();
        let locked = temporary.path().join("locked");
        unchangeable_directory(&locked);
        let user = current_user_sid().unwrap();
        let plan = Plan {
            grants: vec![
                grant_for(&first, Permission::Metadata, &user).unwrap(),
                grant_for(&locked, Permission::Metadata, &user).unwrap(),
            ],
            user_sid: user.clone(),
        };

        let error = without_privileges(|| apply_plan(&plan, false))
            .unwrap_err()
            .to_string();

        assert!(error.contains("cannot update permissions for"), "{error}");
        assert!(error.contains("Nothing was changed"), "{error}");
        assert!(
            !grant_for(&first, Permission::Metadata, &user)
                .unwrap()
                .configured
        );
        std::fs::remove_dir(&locked).unwrap();
    }

    #[test]
    fn setup_that_stops_partway_puts_back_what_it_changed() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let tool = temporary.path().join("tool");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&tool).unwrap();
        // Entries are listed in name order, so the walk grants this file
        // before it stops at the hard link.
        let granted = tool.join("a-granted.txt");
        std::fs::write(&granted, "tool").unwrap();
        let outside = temporary.path().join("outside.txt");
        std::fs::write(&outside, "private").unwrap();
        std::fs::hard_link(&outside, tool.join("z-linked.txt")).unwrap();
        let user = current_user_sid().unwrap();
        let plan = Plan {
            grants: vec![
                grant_for(&first, Permission::Metadata, &user).unwrap(),
                grant_for(&tool, Permission::ToolReadExecute, &user).unwrap(),
            ],
            user_sid: user.clone(),
        };

        let error = apply_plan(&plan, false).unwrap_err().to_string();

        assert!(error.contains("multiple hard links"), "{error}");
        assert!(error.contains("It put back what it had changed"), "{error}");
        assert_eq!(error.matches("setup failed").count(), 1, "{error}");
        assert!(
            !grant_for(&first, Permission::Metadata, &user)
                .unwrap()
                .configured
        );
        let sid = capability_sid(&plan.grants[1].capability_name).unwrap();
        for path in [&tool, &granted] {
            let (handle, _) = open_permissions(path, false).unwrap();
            assert!(
                !has_grant(&handle, path, sid.raw(), TOOL_ACCESS, 0).unwrap(),
                "{}",
                path.display()
            );
        }
    }

    /// A removal that stops partway puts back what it took away and nothing
    /// more: a file in a tool tree that held no entry for the tool's
    /// capability, such as one its owner kept from it, still holds none,
    /// rather than gaining one as granting the tree again would give it.
    #[test]
    fn a_removal_that_stops_puts_back_only_what_it_took() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        std::fs::create_dir(&first).unwrap();
        let open = first.join("a-open.txt");
        let kept_out = first.join("b-kept-out.txt");
        std::fs::write(&open, "tool").unwrap();
        std::fs::write(&kept_out, "private").unwrap();
        let second = temporary.path().join("second");
        std::fs::create_dir(&second).unwrap();
        let user = current_user_sid().unwrap();
        let plan = Plan {
            grants: vec![
                grant_for(&first, Permission::ToolReadExecute, &user).unwrap(),
                grant_for(&second, Permission::ToolReadExecute, &user).unwrap(),
            ],
            user_sid: user.clone(),
        };
        apply_plan(&plan, false).unwrap();
        let first_sid = capability_sid(&plan.grants[0].capability_name).unwrap();
        let output = std::process::Command::new("icacls.exe")
            .arg(&kept_out)
            .arg("/inheritance:d")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        update_ace(&kept_out, first_sid.raw(), None).unwrap();
        // The removal of the second tree stops at a directory it can't
        // change, after the first tree's removal went through.
        let locked = second.join("locked");
        std::fs::create_dir(&locked).unwrap();
        lock_directory_for_test(&locked);

        let error = without_privileges(|| apply_plan(&plan, true))
            .unwrap_err()
            .to_string();

        assert!(error.contains("It put back what it had changed"), "{error}");
        let holds = |path: &Path| {
            let (handle, _) = open_permissions(path, false).unwrap();
            holds_ace(&handle, path, first_sid.raw()).unwrap()
        };
        assert!(
            !holds(&kept_out),
            "the removal's undo granted a file it never held"
        );
        assert!(holds(&first));
        assert!(holds(&open));
        std::fs::remove_dir(&locked).unwrap();
    }

    /// Applying again walks the tree with the root's entry taken away; a
    /// walk that stops gives that entry back rather than leaving a tool
    /// that worked unusable.
    #[test]
    fn a_reapply_that_stops_keeps_the_tool_it_had() {
        let temporary = tempfile::tempdir().unwrap();
        let tool = temporary.path().join("tool");
        std::fs::create_dir(&tool).unwrap();
        std::fs::write(tool.join("a-tool.exe"), "tool").unwrap();
        let user = current_user_sid().unwrap();
        let plan = Plan {
            grants: vec![grant_for(&tool, Permission::ToolReadExecute, &user).unwrap()],
            user_sid: user.clone(),
        };
        apply_plan(&plan, false).unwrap();
        let outside = temporary.path().join("outside.txt");
        std::fs::write(&outside, "private").unwrap();
        std::fs::hard_link(&outside, tool.join("z-linked.txt")).unwrap();

        let error = apply_plan(&plan, false).unwrap_err().to_string();

        assert!(error.contains("It put back what it had changed"), "{error}");
        assert!(
            grant_for(&tool, Permission::ToolReadExecute, &user)
                .unwrap()
                .configured
        );
    }

    /// A removal walk passes a file with names outside the tree, and writes
    /// nothing to one it holds no grant on: a rewrite would drop the
    /// DACL's protected and auto-inherited flags.
    #[test]
    fn a_removal_leaves_a_hard_linked_file_it_never_granted_untouched() {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;

        let temporary = tempfile::tempdir().unwrap();
        let tool = temporary.path().join("tool");
        std::fs::create_dir(&tool).unwrap();
        let outside = temporary.path().join("outside.txt");
        std::fs::write(&outside, "private").unwrap();
        let user = current_user_sid().unwrap();
        let output = std::process::Command::new("icacls.exe")
            .arg(&outside)
            .args(["/inheritance:d"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        std::fs::hard_link(&outside, tool.join("linked.txt")).unwrap();
        let descriptor = || {
            let (handle, _) = open_permissions(&outside, false).unwrap();
            let mut descriptor = ptr::null_mut();
            // SAFETY: the handle has READ_CONTROL and the output is initialized.
            let error = unsafe {
                GetSecurityInfo(
                    handle.as_raw(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut descriptor,
                )
            };
            assert_eq!(error, ERROR_SUCCESS);
            let _descriptor = LocalAllocGuard(descriptor.cast());
            let mut text = ptr::null_mut();
            // SAFETY: the descriptor is live; the string is LocalFree-owned.
            assert_ne!(
                unsafe {
                    ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        descriptor,
                        1,
                        DACL_SECURITY_INFORMATION,
                        &mut text,
                        ptr::null_mut(),
                    )
                },
                0
            );
            let _text = LocalAllocGuard(text.cast());
            let length = (0..)
                .take_while(|&at| unsafe { *text.add(at) } != 0)
                .count();
            // SAFETY: the string has `length` initialized units.
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
        };
        let before = descriptor();
        assert!(before.starts_with("D:PAI"), "{before}");
        let entry = grant_for(&tool, Permission::ToolReadExecute, &user).unwrap();
        let sid = capability_sid(&entry.capability_name).unwrap();
        let (_parents, root) = pin_grant(&entry).unwrap();

        change_grant(&entry, &root, &sid, false).unwrap();

        assert_eq!(descriptor(), before);
    }

    #[test]
    fn preview_rejects_a_drive_root_as_a_readable_tool_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let canonical = temporary.path().canonicalize().unwrap();
        let root = canonical.ancestors().last().unwrap().to_path_buf();
        let error = preview(temporary.path(), &[root], None).unwrap_err();
        assert!(
            error.to_string().contains("drive root cannot be approved"),
            "{error}"
        );
    }

    #[test]
    fn pinned_preview_refuses_replaced_roots_and_blocks_ancestor_rename() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("parent");
        let root = parent.join("tool");
        std::fs::create_dir_all(&root).unwrap();
        let grant = grant_for(
            &root,
            Permission::ToolReadExecute,
            &current_user_sid().unwrap(),
        )
        .unwrap();
        let pins = pin_grant(&grant).unwrap();
        assert!(std::fs::rename(&parent, temporary.path().join("moved-parent")).is_err());
        assert!(std::fs::rename(&root, parent.join("moved-tool")).is_err());
        drop(pins);
        std::fs::rename(&root, parent.join("old-tool")).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(pin_grant(&grant).is_err());
    }

    #[test]
    fn tool_walk_skips_junctions_and_rejects_hardlinked_files() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("tool");
        let outside = temporary.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let secret = outside.join("private.txt");
        std::fs::write(&secret, "private").unwrap();
        let link = root.join("redirect");
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let entry = grant_for(
            &root,
            Permission::ToolReadExecute,
            &current_user_sid().unwrap(),
        )
        .unwrap();
        let sid = capability_sid(&entry.capability_name).unwrap();
        let (_parents, root_target) = pin_grant(&entry).unwrap();
        walk::children(
            &root_target,
            &entry.path,
            sid.raw(),
            Some((TOOL_ACCESS, entry.permission.inheritance())),
        )
        .unwrap();
        let (file, _) = open_permissions(&secret, false).unwrap();
        assert!(!has_grant(&file, &secret, sid.raw(), TOOL_ACCESS, 0).unwrap());
        std::fs::hard_link(&secret, root.join("hardlink.txt")).unwrap();
        let error = walk::children(&root_target, &entry.path, sid.raw(), Some((TOOL_ACCESS, 0)))
            .unwrap_err();
        assert!(error.to_string().contains("multiple hard links"), "{error}");
    }

    #[test]
    fn tool_permissions_apply_idempotently_and_remove_without_granting_writes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("tool");
        let child = root.join("bin");
        std::fs::create_dir_all(&child).unwrap();
        let file_path = child.join("tool.exe");
        std::fs::write(&file_path, "tool").unwrap();
        let user = current_user_sid().unwrap();
        let entry = grant_for(&root, Permission::ToolReadExecute, &user).unwrap();
        let sid = capability_sid(&entry.capability_name).unwrap();
        let (_parents, handle) = pin_grant(&entry).unwrap();
        for _ in 0..2 {
            walk::children(
                &handle,
                &entry.path,
                sid.raw(),
                Some((TOOL_ACCESS, entry.permission.inheritance())),
            )
            .unwrap();
            update_pinned_ace(
                &handle.handle,
                &entry.path,
                sid.raw(),
                Some((TOOL_ACCESS, entry.permission.inheritance())),
            )
            .unwrap();
        }
        assert!(
            grant_for(&root, Permission::ToolReadExecute, &user)
                .unwrap()
                .configured
        );
        let (file, _) = open_permissions(&file_path, false).unwrap();
        assert!(has_grant(&file, &file_path, sid.raw(), TOOL_ACCESS, 0).unwrap());
        assert!(!has_grant(&file, &file_path, sid.raw(), FILE_GENERIC_WRITE, 0).unwrap());
        update_pinned_ace(&handle.handle, &entry.path, sid.raw(), None).unwrap();
        walk::children(&handle, &entry.path, sid.raw(), None).unwrap();
        assert!(
            !grant_for(&root, Permission::ToolReadExecute, &user)
                .unwrap()
                .configured
        );
        assert!(!has_grant(&file, &file_path, sid.raw(), TOOL_ACCESS, 0).unwrap());
    }

    #[test]
    fn preview_refuses_a_tool_beneath_a_junction_ancestor() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        std::fs::create_dir_all(outside.join("tool")).unwrap();
        let link = temporary.path().join("redirect");
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            grant_for(
                &link.join("tool"),
                Permission::ToolReadExecute,
                &current_user_sid().unwrap()
            )
            .is_err(),
            "preview must not turn a junction path into approval of its target"
        );
    }

    #[test]
    fn tool_permission_walk_covers_multiple_directory_batches_and_restarts_on_removal() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("tool");
        let nested = root.join("bin").join("Unicode tools λ");
        std::fs::create_dir_all(&nested).unwrap();
        let paths: Vec<_> = (0..700)
            .map(|index| root.join(format!("tool-{index:04}-with-a-long-name.exe")))
            .chain([nested.join("工具.exe")])
            .collect();
        for path in &paths {
            std::fs::write(path, "tool").unwrap();
        }
        let entry = grant_for(
            &root,
            Permission::ToolReadExecute,
            &current_user_sid().unwrap(),
        )
        .unwrap();
        let sid = capability_sid(&entry.capability_name).unwrap();
        let (_parents, target) = pin_grant(&entry).unwrap();
        for configured in [true, false] {
            walk::children(
                &target,
                &entry.path,
                sid.raw(),
                configured.then_some((TOOL_ACCESS, 0)),
            )
            .unwrap();
            for path in &paths {
                let (file, _) = open_permissions(path, false).unwrap();
                assert_eq!(
                    has_grant(&file, path, sid.raw(), TOOL_ACCESS, 0).unwrap(),
                    configured,
                    "{}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn setup_does_not_grant_outside_files_after_in_place_junction_conversion() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("tool");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let secret = outside.join("private.txt");
        std::fs::write(&secret, "private").unwrap();
        let entry = grant_for(
            &root,
            Permission::ToolReadExecute,
            &current_user_sid().unwrap(),
        )
        .unwrap();
        let (_parents, root_target) = pin_grant(&entry).unwrap();
        let substitute = outside
            .canonicalize()
            .unwrap()
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        let mut substitute = substitute;
        substitute[1] = b'?' as u16;
        let data_length = 8 + (substitute.len() + 2) * 2;
        let mut data = Vec::new();
        data.extend_from_slice(&0xa0000003u32.to_le_bytes());
        data.extend_from_slice(&(data_length as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        for value in [
            0,
            (substitute.len() * 2) as u16,
            ((substitute.len() + 1) * 2) as u16,
            0,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        for unit in substitute {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0, 0, 0]);
        let wide = to_wide_with_nul(root.as_os_str());
        let convert = |access| {
            // SAFETY: the path is terminated and no handle is inherited.
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return false;
            }
            let handle = HandleGuard(raw);
            let mut returned = 0;
            // SAFETY: the initialized reparse buffer and output live through the synchronous call.
            let changed = unsafe {
                windows_sys::Win32::System::IO::DeviceIoControl(
                    handle.as_raw(),
                    0x000900a4,
                    data.as_ptr().cast(),
                    data.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            changed != 0
        };
        assert!(
            convert(windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES),
            "junction conversion control must succeed"
        );
        let sid = capability_sid(&entry.capability_name).unwrap();
        let _result = walk::children(&root_target, &entry.path, sid.raw(), Some((TOOL_ACCESS, 0)));
        let (file, _) = open_permissions(&secret, false).unwrap();
        assert!(
            !has_grant(&file, &secret, sid.raw(), TOOL_ACCESS, 0).unwrap(),
            "setup followed the changed directory and granted access outside the approved tree"
        );
    }
}
