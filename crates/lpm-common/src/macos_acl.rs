//! Access on macOS that the file mode doesn't show. Extended access control
//! list entries grant it: an `everyone allow read` entry, inherited from a
//! directory, makes a 0600 file readable by any user. So does a volume that
//! ignores ownership, on which every user owns every file.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::os::fd::{AsFd, AsRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
/// What lets someone change a directory's entries, or who may: adding a
/// file or a subdirectory, deleting a child, and changing its ACL or owner.
const ENTRY_CHANGING_PERMISSIONS: [c_int; 5] = [1 << 2, 1 << 5, 1 << 6, 1 << 12, 1 << 13];

unsafe extern "C" {
    fn acl_free(value: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_fd_np(file_descriptor: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_get_perm_np(permset: *mut c_void, perm: c_int) -> c_int;
    fn acl_get_permset(entry: *mut c_void, permset: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_link_np(path: *const c_char, acl_type: c_int) -> *mut c_void;
    fn acl_init(entry_count: c_int) -> *mut c_void;
    fn acl_set_fd_np(file_descriptor: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
}

/// Whether the volume holding the open file or directory ignores ownership,
/// as one mounted `noowners` does, which external drives are by default:
/// every user is then the owner of its files, whatever their mode.
pub fn ignores_ownership(handle: impl AsFd) -> io::Result<bool> {
    let mut volume = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs fills `volume` from a descriptor that stays open while
    // `handle` is borrowed.
    if unsafe { libc::fstatfs(handle.as_fd().as_raw_fd(), volume.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded, so it filled `volume`.
    let flags = unsafe { volume.assume_init() }.f_flags;
    Ok(flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0)
}

/// Whether the open file or directory has extended ACL entries.
pub fn has_extended_acl(handle: impl AsFd) -> io::Result<bool> {
    let file_descriptor = handle.as_fd().as_raw_fd();
    // SAFETY: acl_get_fd_np reads a descriptor that stays open while
    // `handle` is borrowed.
    extended_acl_found(|| unsafe { acl_get_fd_np(file_descriptor, ACL_TYPE_EXTENDED) })
}

/// Whether the entry at `path` has extended ACL entries, read without
/// following a link there. It opens nothing, so it leaves alone the locks
/// this process holds on the file, which closing any descriptor of it would
/// drop. An entry that's gone has none.
pub fn has_extended_acl_at(path: &Path) -> io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: acl_get_link_np reads a NUL-terminated path that outlives the
    // call.
    extended_acl_found(|| unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) })
}

/// Runs an `acl_get_*_np` call and frees what it returns. Null with `ENOENT`
/// means the entry has no extended ACL, or is gone.
fn extended_acl_found(get: impl FnOnce() -> *mut c_void) -> io::Result<bool> {
    // SAFETY: errno is this thread's own, and the ACL `get` returns, if not
    // null, is freed once.
    unsafe {
        *libc::__error() = 0;
        let acl = get();
        if acl.is_null() {
            let error = *libc::__error();
            return if error == 0 || error == libc::ENOENT {
                Ok(false)
            } else {
                Err(io::Error::from_raw_os_error(error))
            };
        }
        if acl_free(acl) == 0 {
            Ok(true)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Whether the open directory's extended ACL allows anyone to add, remove
/// or rename its entries, or to change its ACL or owner. Every allow entry
/// counts, whoever it names, as the directory's owner needs none.
pub fn allows_entry_changes(handle: impl AsFd) -> io::Result<bool> {
    let file_descriptor = handle.as_fd().as_raw_fd();
    // SAFETY: errno is this thread's own; the ACL is freed once, and the
    // entries and permission sets read from it are used only before that.
    unsafe {
        *libc::__error() = 0;
        let acl = acl_get_fd_np(file_descriptor, ACL_TYPE_EXTENDED);
        if acl.is_null() {
            let error = *libc::__error();
            return if error == 0 || error == libc::ENOENT {
                Ok(false)
            } else {
                Err(io::Error::from_raw_os_error(error))
            };
        }
        let allows = allow_entry_changes_in(acl);
        if acl_free(acl) != 0 && allows.is_ok() {
            return Err(io::Error::last_os_error());
        }
        allows
    }
}

/// # Safety
/// `acl` must be a live ACL from `acl_get_fd_np`.
unsafe fn allow_entry_changes_in(acl: *mut c_void) -> io::Result<bool> {
    let mut entry = std::ptr::null_mut();
    let mut entry_id = ACL_FIRST_ENTRY;
    // SAFETY: as the caller guarantees; each out-pointer is a local.
    unsafe {
        while acl_get_entry(acl, entry_id, &mut entry) == 0 {
            entry_id = ACL_NEXT_ENTRY;
            let mut tag = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 {
                return Err(io::Error::last_os_error());
            }
            if tag != ACL_EXTENDED_ALLOW {
                continue;
            }
            let mut permset = std::ptr::null_mut();
            if acl_get_permset(entry, &mut permset) != 0 {
                return Err(io::Error::last_os_error());
            }
            for permission in ENTRY_CHANGING_PERMISSIONS {
                match acl_get_perm_np(permset, permission) {
                    0 => {}
                    1 => return Ok(true),
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }
    }
    Ok(false)
}

/// Removes the extended ACL entries the open file or directory has, such as
/// those it took from its directory. A volume that holds no ACLs leaves
/// nothing to remove.
pub fn drop_extended_acl(handle: impl AsFd) -> io::Result<()> {
    match has_extended_acl(&handle) {
        Ok(true) => clear_extended_acl(handle),
        Ok(false) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::EOPNOTSUPP)) => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Removes every extended ACL entry from the open file or directory, and
/// checks that none remain.
pub fn clear_extended_acl(handle: impl AsFd) -> io::Result<()> {
    let file_descriptor = handle.as_fd().as_raw_fd();
    // SAFETY: acl_init returns either null or an empty ACL this function
    // frees once; acl_set_fd_np only reads it, and writes to a descriptor
    // that stays open while `handle` is borrowed.
    let error = unsafe {
        let acl = acl_init(0);
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let set = acl_set_fd_np(file_descriptor, acl, ACL_TYPE_EXTENDED);
        let error = (set != 0).then(io::Error::last_os_error);
        if acl_free(acl) != 0 && error.is_none() {
            return Err(io::Error::last_os_error());
        }
        error
    };
    if let Some(error) = error {
        return Err(error);
    }
    if has_extended_acl(handle)? {
        return Err(io::Error::other(
            "extended access control remained after removal",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_volume_that_keeps_ownership_reads_as_such() {
        let directory = tempfile::tempdir().unwrap();
        let handle = std::fs::File::open(directory.path()).unwrap();

        assert!(!ignores_ownership(&handle).unwrap());
    }

    #[test]
    fn a_volume_mounted_without_owners_reads_as_ignoring_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("volume.dmg");
        let mount_point = directory.path().join("mounted");
        std::fs::create_dir(&mount_point).unwrap();
        let attached = crate::test_disk_image::AttachedImage::new(
            &image,
            &mount_point,
            &["-size", "2m", "-fs", "HFS+", "-volname", "lpm-noowners"],
            &["-owners", "off"],
        );

        let handle = std::fs::File::open(attached.path()).unwrap();

        assert!(ignores_ownership(&handle).unwrap());
    }

    fn add_entry(path: &std::path::Path, entry: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn finds_and_clears_a_file_s_extended_entries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("captures");
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(!has_extended_acl(&file).unwrap());

        add_entry(&path, "group:everyone allow read");
        assert!(has_extended_acl(&file).unwrap());

        clear_extended_acl(&file).unwrap();
        assert!(!has_extended_acl(&file).unwrap());
    }

    #[test]
    fn reads_an_entry_s_extended_entries_by_path_without_following_a_link() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("captures");
        let link = directory.path().join("link");
        std::fs::write(&path, b"").unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(!has_extended_acl_at(&path).unwrap());

        add_entry(&path, "group:everyone allow read");

        assert!(has_extended_acl_at(&path).unwrap());
        assert!(!has_extended_acl_at(&link).unwrap());
        assert!(!has_extended_acl_at(&directory.path().join("gone")).unwrap());
    }

    #[test]
    fn clears_a_directory_s_inheritable_entries() {
        let directory = tempfile::tempdir().unwrap();
        add_entry(
            directory.path(),
            "group:everyone allow read,write,file_inherit,directory_inherit",
        );
        let handle = std::fs::File::open(directory.path()).unwrap();

        clear_extended_acl(&handle).unwrap();

        std::fs::write(directory.path().join("created"), b"").unwrap();
        let created = std::fs::File::open(directory.path().join("created")).unwrap();
        assert!(!has_extended_acl(&handle).unwrap());
        assert!(!has_extended_acl(&created).unwrap());
    }
}
