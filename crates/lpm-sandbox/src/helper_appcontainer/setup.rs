//! Per-directory capabilities for explicitly approved Windows filesystem access.

use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use windows_sys::Win32::Security::{
    CopySid, DeriveCapabilitySidsFromName, GetLengthSid, GetTokenInformation, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, GetFileInformationByHandle,
    READ_CONTROL, WRITE_DAC,
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
    open_permissions_with_sharing(path, write, true)
}

fn open_permissions_with_sharing(
    path: &Path,
    write: bool,
    allow_delete: bool,
) -> Result<(HandleGuard, Identity), AppContainerError> {
    let path_wide = to_wide_with_nul(path.as_os_str());
    // SAFETY: no handle is inherited; the final component is opened without following links.
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | if write { WRITE_DAC } else { 0 }
                // Metadata-only handles do not enforce Windows share restrictions.
                | if allow_delete { 0 } else { windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA },
            FILE_SHARE_READ | if allow_delete { FILE_SHARE_WRITE | FILE_SHARE_DELETE } else { 0 },
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(AppContainerError::ReadDacl {
            path: path.to_path_buf(),
            win32_error: unsafe { GetLastError() },
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
    if write
        && !allow_delete
        && info.nNumberOfLinks > 1
        && info.dwFileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
            == 0
    {
        return Err(failure(format!(
            "{} has multiple hard links; approve a tool copy without hard links",
            path.display()
        )));
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
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| failure(format!("inspect {}: {error}", path.display())))?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(failure(format!(
            "{} must be an existing directory, without a link or junction",
            path.display()
        )));
    }
    let path = path
        .canonicalize()
        .map_err(|error| failure(format!("resolve {}: {error}", path.display())))?;
    let (handle, identity) = open_permissions(&path, false)?;
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
    let capability_name = format!("lpm.filesystem.v1.{:x}", hash.finalize());
    let sid = capability_sid(&capability_name)?;
    let configured = has_grant(
        &handle,
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
    let grants = paths
        .into_iter()
        .map(|(path, permission)| grant_for(&path, permission, &user_sid))
        .collect::<Result<_, _>>()?;
    Ok(Plan { user_sid, grants })
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
    let mut buffer = vec![0; 64];
    let packages = build_capability_attr(WinBuiltinAnyPackageSid, &mut buffer)?;
    let mut missing = Vec::new();
    for path in ancestors {
        if grant_for(&path, Permission::Metadata, &user)?.configured {
            continue;
        }
        let (handle, _) = open_permissions(&path, false)?;
        if !has_grant(&handle, &path, packages.Sid, METADATA_ACCESS, 0)?
            && open_permissions(&path, true).is_err()
        {
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

fn lock_named(name: &str) -> Result<ProfileCreationLock, AppContainerError> {
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
        None => {
            let mut filtered = dacl_without_allowed_aces_for_sid(path, old, sid)?;
            write_dacl(handle, path, filtered.as_mut_ptr().cast())
        }
    }
}

// Pin each ancestor without delete sharing, so an elevated path walk cannot
// be redirected through a renamed directory or a replacement junction.
fn pin_grant(entry: &Grant) -> Result<(Vec<HandleGuard>, HandleGuard), AppContainerError> {
    let mut parents = Vec::new();
    for ancestor in entry
        .path
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        parents.push(open_permissions_with_sharing(ancestor, false, false)?.0);
    }
    let (root, identity) = open_permissions_with_sharing(&entry.path, true, false)?;
    if identity != entry.identity {
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
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the pinned file handle is live and the output is correctly sized.
    if unsafe { GetFileInformationByHandle(handle.as_raw(), &mut info) } == 0 {
        return Err(last_error("inspect the pinned permission target"));
    }
    let _lock = lock_object(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })?;
    update_open_ace(handle, path, sid, value)
}

fn update_tool_children(
    root: &Path,
    sid: PSID,
    value: Option<(u32, u32)>,
) -> Result<(), AppContainerError> {
    struct Frame {
        entries: std::fs::ReadDir,
        _pin: Option<HandleGuard>,
    }
    let read = |path: &Path| {
        std::fs::read_dir(path)
            .map_err(|error| failure(format!("read {}: {error}", path.display())))
    };
    let mut stack = vec![Frame {
        entries: read(root)?,
        _pin: None,
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(child) = frame.entries.next() else {
            stack.pop();
            continue;
        };
        let path = child.map_err(|error| failure(error.to_string()))?.path();
        let (handle, _) = match open_permissions_with_sharing(&path, true, false) {
            Ok(opened) => opened,
            Err(AppContainerError::ReparsePointRoot { .. }) => continue,
            Err(error) => return Err(error),
        };
        update_pinned_ace(&handle, &path, sid, value)?;
        if std::fs::metadata(&path)
            .map_err(|error| failure(error.to_string()))?
            .is_dir()
        {
            stack.push(Frame {
                entries: read(&path)?,
                _pin: Some(handle),
            });
        }
    }
    Ok(())
}

/// Apply or remove only the previewed capabilities. This function never runs package scripts.
/// A failure can leave some grants applied or removed; repeat the preview and retry.
pub fn apply(plan: &Plan, remove: bool) -> Result<(), AppContainerError> {
    if !is_elevated()? {
        return Err(failure(
            "open an administrator terminal to apply or remove permissions; keep publishing in your normal terminal",
        ));
    }
    for entry in &plan.grants {
        let (_parents, root) = pin_grant(entry)?;
        let sid = capability_sid(&entry.capability_name)?;
        // Serialize the complete tree update separately from individual DACL
        // merges, including across administrator accounts and logon sessions.
        let _setup_lock = lock_named(&format!(
            r"Global\LpmSandboxSetup-{}",
            entry.capability_name
        ))?;
        let value = (!remove).then_some((entry.permission.mask(), entry.permission.inheritance()));
        let result = (|| {
            if entry.permission == Permission::ToolReadExecute {
                // Re-applying also deactivates the root until the walk completes.
                update_pinned_ace(&root, &entry.path, sid.raw(), None)?;
                update_tool_children(&entry.path, sid.raw(), value)?;
            }
            update_pinned_ace(&root, &entry.path, sid.raw(), value)
        })();
        result.map_err(|error: AppContainerError| failure(format!(
            "permission setup stopped at {}: {error}. Some permissions may have changed; preview and retry the same operation",
            entry.path.display()
        )))?;
    }
    Ok(())
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
    let mut package_sid_buffer = vec![0; 64];
    let packages = build_capability_attr(WinBuiltinAnyPackageSid, &mut package_sid_buffer)?;
    for path in ancestors {
        let entry = grant_for(&path, Permission::Metadata, &user_sid)?;
        if entry.configured {
            access
                .capabilities
                .push(capability_sid(&entry.capability_name)?);
        } else {
            let (handle, _) = open_permissions(&path, false)?;
            if has_grant(&handle, &path, packages.Sid, METADATA_ACCESS, 0)? {
                continue;
            }
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
        let entry = grant_for(tool, Permission::ToolReadExecute, &user_sid)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let (_parents, _root) = pin_grant(&entry).unwrap();
        update_tool_children(
            &entry.path,
            sid.raw(),
            Some((TOOL_ACCESS, entry.permission.inheritance())),
        )
        .unwrap();
        let (file, _) = open_permissions(&secret, false).unwrap();
        assert!(!has_grant(&file, &secret, sid.raw(), TOOL_ACCESS, 0).unwrap());
        std::fs::hard_link(&secret, root.join("hardlink.txt")).unwrap();
        let error =
            update_tool_children(&entry.path, sid.raw(), Some((TOOL_ACCESS, 0))).unwrap_err();
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
            update_tool_children(
                &entry.path,
                sid.raw(),
                Some((TOOL_ACCESS, entry.permission.inheritance())),
            )
            .unwrap();
            update_pinned_ace(
                &handle,
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
        update_pinned_ace(&handle, &entry.path, sid.raw(), None).unwrap();
        update_tool_children(&entry.path, sid.raw(), None).unwrap();
        assert!(
            !grant_for(&root, Permission::ToolReadExecute, &user)
                .unwrap()
                .configured
        );
        assert!(!has_grant(&file, &file_path, sid.raw(), TOOL_ACCESS, 0).unwrap());
    }

    #[test]
    fn pinned_directories_refuse_in_place_junction_conversion() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("tool");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let entry = grant_for(
            &root,
            Permission::ToolReadExecute,
            &current_user_sid().unwrap(),
        )
        .unwrap();
        let _pins = pin_grant(&entry).unwrap();
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
        for access in [
            windows_sys::Win32::Foundation::GENERIC_WRITE,
            windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES,
            0,
        ] {
            assert!(
                !convert(access),
                "junction conversion succeeded with access mask {access:x}"
            );
        }
        drop(_pins);
        assert!(
            convert(windows_sys::Win32::Foundation::GENERIC_WRITE),
            "unpinned junction control must succeed"
        );
    }
}
