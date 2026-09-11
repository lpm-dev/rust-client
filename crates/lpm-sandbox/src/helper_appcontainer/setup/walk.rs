use super::*;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileNamesInformation, NtCreateFile, NtQueryDirectoryFile,
};
use windows_sys::Win32::Foundation::{
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES,
    STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_STOPPED_ON_SYMLINK, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA, GetFinalPathNameByHandleW,
    SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) struct Target {
    pub(super) handle: HandleGuard,
    pub(super) identity: Identity,
    pub(super) directory: bool,
}

impl Target {
    pub(super) fn open(path: &Path, write: bool) -> Result<Self, AppContainerError> {
        Self::open_path(path, write, true)
    }

    pub(super) fn preview(path: &Path) -> Result<Self, AppContainerError> {
        Self::open_path(path, false, false)
    }

    fn open_path(path: &Path, write: bool, pin: bool) -> Result<Self, AppContainerError> {
        let absolute = std::path::absolute(path)
            .map_err(|error| failure(format!("resolve {}: {error}", path.display())))?;
        let mut name: Vec<_> = absolute.as_os_str().encode_wide().collect();
        if !name.starts_with(&[92, 92, 63, 92]) {
            name = if name.starts_with(&[92, 92]) {
                r"\\?\UNC\"
                    .encode_utf16()
                    .chain(name.into_iter().skip(2))
                    .collect()
            } else {
                r"\\?\".encode_utf16().chain(name).collect()
            };
        }
        // The object manager uses \??\ for the Win32 extended-path prefix.
        name[1] = b'?' as u16;
        Self::open_name(ptr::null_mut(), name, path, write, pin)
    }

    pub(super) fn canonical_directory(&self) -> Result<PathBuf, AppContainerError> {
        if !self.directory {
            return Err(failure("setup requires an existing directory"));
        }
        let mut name = vec![0u16; 512];
        loop {
            // SAFETY: the target handle is open and the UTF-16 output has the advertised size.
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    self.handle.as_raw(),
                    name.as_mut_ptr(),
                    name.len() as u32,
                    0,
                )
            } as usize;
            if length == 0 {
                return Err(last_error("resolve a sandbox setup directory"));
            }
            if length < name.len() {
                name.truncate(length);
                return Ok(PathBuf::from(OsString::from_wide(&name)));
            }
            if length > 32768 {
                return Err(failure("setup path exceeds the Windows path limit"));
            }
            name.resize(length + 1, 0);
        }
    }

    fn child(&self, name: &OsStr, path: &Path) -> Result<Self, AppContainerError> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(failure("setup received an invalid directory entry"));
        }
        Self::open_name(
            self.handle.as_raw(),
            name.encode_wide().collect(),
            path,
            true,
            true,
        )
    }

    fn open_name(
        parent: HANDLE,
        mut name: Vec<u16>,
        path: &Path,
        write: bool,
        pin: bool,
    ) -> Result<Self, AppContainerError> {
        let length = name
            .len()
            .checked_mul(2)
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| failure("setup path exceeds the Windows path limit"))?;
        if name.contains(&0) {
            return Err(failure("setup path contains NUL"));
        }
        let name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent,
            ObjectName: &name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: ptr::null(),
            SecurityQualityOfService: ptr::null(),
        };
        let mut raw = ptr::null_mut();
        let mut io = IO_STATUS_BLOCK::default();
        // SAFETY: the parent handle and counted name remain live; the synchronous
        // open never follows a reparse point, including in intermediate components.
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                READ_CONTROL
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE
                    | if pin { FILE_READ_DATA } else { 0 }
                    | if write { WRITE_DAC } else { 0 },
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | if pin { 0 } else { FILE_SHARE_DELETE },
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT
                    | FILE_OPEN_FOR_BACKUP_INTENT
                    | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status == STATUS_REPARSE_POINT_ENCOUNTERED || status == STATUS_STOPPED_ON_SYMLINK {
            return Err(AppContainerError::ReparsePointRoot {
                path: path.to_path_buf(),
            });
        }
        if status < 0 {
            return Err(AppContainerError::ReadDacl {
                path: path.to_path_buf(),
                // SAFETY: status is the NTSTATUS returned by NtCreateFile.
                win32_error: unsafe { RtlNtStatusToDosError(status) },
            });
        }
        let handle = HandleGuard(raw);
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the successful open owns the handle; info is writable.
        if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
            return Err(last_error("inspect a sandbox setup target"));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AppContainerError::ReparsePointRoot {
                path: path.to_path_buf(),
            });
        }
        let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if write && !directory && info.nNumberOfLinks > 1 {
            return Err(failure(format!(
                "{} has multiple hard links; approve a tool copy without hard links",
                path.display()
            )));
        }
        Ok(Self {
            handle,
            identity: Identity {
                volume: info.dwVolumeSerialNumber,
                index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            },
            directory,
        })
    }
}

fn names(
    target: &Target,
    buffer: &mut [u64],
    restart: &mut bool,
) -> Result<Option<Vec<OsString>>, AppContainerError> {
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: the directory was opened synchronously; the aligned writable
    // buffer and output remain live until enumeration completes.
    let status = unsafe {
        NtQueryDirectoryFile(
            target.handle.as_raw(),
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(buffer) as u32,
            FileNamesInformation,
            false,
            ptr::null(),
            *restart,
        )
    };
    *restart = false;
    if status == STATUS_NO_MORE_FILES {
        return Ok(None);
    }
    if status < 0 {
        // SAFETY: status is the result of NtQueryDirectoryFile.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(failure(format!(
            "enumerate a sandbox tool directory: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )));
    }
    if io.Information > std::mem::size_of_val(buffer) {
        return Err(failure("Windows returned an invalid directory buffer"));
    }
    // SAFETY: the synchronous call initialized Information bytes in buffer.
    let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), io.Information) };
    let mut offset = 0;
    let mut names = Vec::new();
    loop {
        let record = data
            .get(offset..)
            .filter(|record| record.len() >= 12)
            .ok_or_else(|| failure("Windows returned an incomplete directory entry"))?;
        let next = u32::from_le_bytes(
            record[..4]
                .try_into()
                .map_err(|_| failure("invalid directory offset"))?,
        ) as usize;
        let length = u32::from_le_bytes(
            record[8..12]
                .try_into()
                .map_err(|_| failure("invalid directory name length"))?,
        ) as usize;
        let end = 12usize
            .checked_add(length)
            .filter(|end| *end <= record.len() && length.is_multiple_of(2))
            .ok_or_else(|| failure("Windows returned an invalid directory name"))?;
        let wide: Vec<_> = record[12..end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name = OsString::from_wide(&wide);
        if name != "." && name != ".." {
            names.push(name);
        }
        if next == 0 {
            break;
        }
        if next < end || next > record.len() {
            return Err(failure("Windows returned an invalid directory offset"));
        }
        offset += next;
    }
    Ok(Some(names))
}

pub(super) fn children(
    root: &Target,
    path: &Path,
    sid: PSID,
    value: Option<(u32, u32)>,
) -> Result<(), AppContainerError> {
    struct Frame {
        target: Target,
        path: PathBuf,
        pending: std::vec::IntoIter<OsString>,
        restart: bool,
    }
    let mut buffer = vec![0u64; 2048];
    let mut stack: Vec<Frame> = Vec::new();
    let mut root_pending = Vec::new().into_iter();
    let mut root_restart = true;
    loop {
        let (target, directory, pending, restart) = match stack.last_mut() {
            Some(frame) => (
                &frame.target,
                frame.path.as_path(),
                &mut frame.pending,
                &mut frame.restart,
            ),
            None => (root, path, &mut root_pending, &mut root_restart),
        };
        let name = match pending.next() {
            Some(name) => name,
            None => match names(target, &mut buffer, restart)? {
                Some(names) => {
                    *pending = names.into_iter();
                    continue;
                }
                None if stack.is_empty() => return Ok(()),
                None => {
                    stack.pop();
                    continue;
                }
            },
        };
        let child_path = directory.join(&name);
        let child = match target.child(&name, &child_path) {
            Ok(child) => child,
            Err(AppContainerError::ReparsePointRoot { .. }) => continue,
            Err(error) => return Err(error),
        };
        update_pinned_ace(&child.handle, &child_path, sid, value)?;
        if child.directory {
            stack.push(Frame {
                target: child,
                path: child_path,
                pending: Vec::new().into_iter(),
                restart: true,
            });
        }
    }
}
