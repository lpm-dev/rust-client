//! Whether other users can change what a path leads to. A directory's
//! entries can be renamed, removed or replaced by whoever may write to it,
//! or change its mode or ACL, so files opened by name further down are only
//! as safe as every directory on the way.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

/// A directory on a path that a user other than the one trusted, or root,
/// can change the entries of, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changeable {
    pub directory: PathBuf,
    pub reason: &'static str,
}

/// How many links a path may pass through, as Linux allows.
const MAX_LINKS: usize = 40;

/// The first directory, resolving `path` a component at a time as the
/// kernel does, whose entries a user other than `uid` and root can change:
/// one another user owns; one its group may write, unless its group is
/// `uid`'s own and has no other member, as with user-private groups; one
/// anyone may write; and one whose ACL lets others add or remove entries.
/// A sticky directory, as `/tmp`, is safe even so for an entry `uid` or
/// root owns, which only they may move. A link is followed, and its target
/// resolved the same way. None when every directory consulted is safe.
pub fn first_changeable_directory(path: &Path, uid: u32) -> io::Result<Option<Changeable>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    push_components(&mut pending, &absolute);
    let mut current = PathBuf::from("/");
    if let Some(found) = changeable(&current, &std::fs::metadata(&current)?, uid)? {
        return Ok(Some(found));
    }
    let mut links = 0;
    while let Some(name) = pending.pop() {
        if name == OsStr::new("/") {
            current = PathBuf::from("/");
            continue;
        }
        if name == OsStr::new("..") {
            current.pop();
            continue;
        }
        let parent = std::fs::metadata(&current)?;
        let next = current.join(&name);
        let entry = std::fs::symlink_metadata(&next)?;
        if parent.mode() & 0o1000 != 0
            && entry.uid() != uid
            && entry.uid() != 0
            && others_may_add(&parent, uid, Acl::At(&current))?.is_some()
        {
            return Ok(Some(Changeable {
                directory: current,
                reason: "others may add to it, and the entry on the path belongs to another user",
            }));
        }
        if entry.file_type().is_symlink() {
            links += 1;
            if links > MAX_LINKS {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let target = std::fs::read_link(&next)?;
            push_components(&mut pending, &target);
            continue;
        }
        current = next;
        if entry.is_dir()
            && let Some(found) = changeable(&current, &entry, uid)?
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Pushes `path`'s components onto `pending` so they pop in order; an
/// absolute path starts from the root again.
fn push_components(pending: &mut Vec<std::ffi::OsString>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::RootDir => pending.push("/".into()),
            Component::ParentDir => pending.push("..".into()),
            Component::Normal(name) => pending.push(name.to_os_string()),
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

/// Where a directory's ACL is read from: its path, which isn't followed
/// if it's a link, or a handle open on it.
#[derive(Clone, Copy)]
enum Acl<'a> {
    At(&'a Path),
    Of(&'a std::fs::File),
}

fn changeable(
    directory: &Path,
    metadata: &std::fs::Metadata,
    uid: u32,
) -> io::Result<Option<Changeable>> {
    Ok(
        why_changeable(metadata, uid, Acl::At(directory))?.map(|reason| Changeable {
            directory: directory.to_path_buf(),
            reason,
        }),
    )
}

/// Why users other than `uid` and root can change the entries of the
/// directory `metadata` describes, if they can; in a sticky one, only an
/// entry's owner can move it.
fn why_changeable(
    metadata: &std::fs::Metadata,
    uid: u32,
    acl: Acl<'_>,
) -> io::Result<Option<&'static str>> {
    if metadata.uid() != uid && metadata.uid() != 0 {
        return Ok(Some("it belongs to another user"));
    }
    if metadata.mode() & 0o1000 == 0 {
        return others_may_add(metadata, uid, acl);
    }
    #[cfg(target_os = "macos")]
    if acl_allows_entry_changes(acl)? {
        return Ok(Some(MACOS_ACL_REASON));
    }
    Ok(None)
}

/// Why users other than `uid` and root may add entries to the directory
/// `metadata` describes, sticky or not, if they may.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(unused_variables)
)]
fn others_may_add(
    metadata: &std::fs::Metadata,
    uid: u32,
    acl: Acl<'_>,
) -> io::Result<Option<&'static str>> {
    #[cfg(target_os = "macos")]
    if acl_allows_entry_changes(acl)? {
        return Ok(Some(MACOS_ACL_REASON));
    }
    let mode = metadata.mode();
    if mode & 0o002 != 0 {
        return Ok(Some("anyone may write to it"));
    }
    if mode & 0o020 == 0 {
        return Ok(None);
    }
    // With an ACL, the group's bits are the most any of its entries
    // grants, and other users may have entries of their own.
    #[cfg(target_os = "linux")]
    if has_posix_acl(acl)? {
        return Ok(Some("its access control list may let others write to it"));
    }
    if group_is_private(metadata.gid(), uid)? {
        return Ok(None);
    }
    Ok(Some("its group, which has other members, may write to it"))
}

#[cfg(target_os = "macos")]
const MACOS_ACL_REASON: &str = "its access control list lets others change its entries";

/// Whether a directory's ACL lets others add, remove or rename its
/// entries, whatever its mode, as a macOS ACL can; a Linux ACL can grant
/// no more than its mode's group bits show.
#[cfg(target_os = "macos")]
fn acl_allows_entry_changes(acl: Acl<'_>) -> io::Result<bool> {
    match acl {
        Acl::At(directory) => {
            crate::macos_acl::allows_entry_changes(crate::open_nofollow(directory)?)
        }
        Acl::Of(handle) => crate::macos_acl::allows_entry_changes(handle),
    }
}

/// Whether a directory has an access ACL beyond its mode, which Linux
/// keeps in an extended attribute; one on a filesystem without them has
/// none.
#[cfg(target_os = "linux")]
fn has_posix_acl(acl: Acl<'_>) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;

    const NAME: &CStr = c"system.posix_acl_access";
    // SAFETY: the strings are NUL-terminated and outlive the calls, the
    // descriptor is open for the call, and a size of 0 only asks the
    // attribute's length, writing nothing.
    let size = match acl {
        Acl::At(directory) => {
            let path = CString::new(directory.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            unsafe { libc::lgetxattr(path.as_ptr(), NAME.as_ptr(), std::ptr::null_mut(), 0) }
        }
        Acl::Of(handle) => unsafe {
            libc::fgetxattr(handle.as_raw_fd(), NAME.as_ptr(), std::ptr::null_mut(), 0)
        },
    };
    if size >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
        _ => Err(error),
    }
}

/// A user's name, primary group and every group they're in, from the
/// system's user database; None for a user it doesn't know, as a host's
/// user in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: CString,
    pub gid: u32,
}

/// The account of `uid`, or None where the user database has none.
pub fn account(uid: u32) -> io::Result<Option<Account>> {
    let mut buffer = vec![0u8; 1024];
    loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry`, `buffer` and `result` outlive the call, which
        // writes no more than `buffer.len()` bytes into `buffer`.
        let error = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if error == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: on success `pw_name` points at a NUL-terminated name
        // within `buffer`.
        let name = unsafe { CStr::from_ptr(entry.pw_name) }.to_owned();
        return Ok(Some(Account {
            name,
            gid: entry.pw_gid,
        }));
    }
}

/// A group's name and the names in its member list.
struct Group {
    name: CString,
    members: Vec<CString>,
}

/// Group `gid`, or None for a group the database doesn't know.
fn group(gid: u32) -> io::Result<Option<Group>> {
    let mut buffer = vec![0u8; 4096];
    loop {
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: as in `account`.
        let error = unsafe {
            libc::getgrgid_r(
                gid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if error == libc::ERANGE && buffer.len() < 1 << 22 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: on success `gr_name` points at a NUL-terminated name
        // within `buffer`.
        let name = unsafe { CStr::from_ptr(entry.gr_name) }.to_owned();
        let mut members = Vec::new();
        let mut member = entry.gr_mem;
        // SAFETY: `gr_mem` is a NULL-terminated array of NUL-terminated
        // names within `buffer`.
        unsafe {
            while !member.is_null() && !(*member).is_null() {
                members.push(CStr::from_ptr(*member).to_owned());
                member = member.add(1);
            }
        }
        return Ok(Some(Group { name, members }));
    }
}

/// Whether group `gid` is `uid`'s alone, as a user-private group is:
/// `uid`'s primary group, named after them, listing no other member. Users
/// whose primary group it is aren't listed as members, so a group many
/// users share that way, as `users`, isn't taken for one; its name isn't
/// theirs.
pub fn group_is_private(gid: u32, uid: u32) -> io::Result<bool> {
    let Some(account) = account(uid)? else {
        return Ok(false);
    };
    if account.gid != gid {
        return Ok(false);
    }
    Ok(group(gid)?.is_some_and(|group| {
        group.name == account.name && group.members.iter().all(|member| *member == account.name)
    }))
}

/// The groups `account` is in, its primary group first, as the user
/// database lists them.
#[cfg(target_os = "linux")]
pub fn groups_of(account: &Account) -> io::Result<Vec<u32>> {
    let mut count: libc::c_int = 32;
    loop {
        let mut groups = vec![0 as libc::gid_t; count as usize];
        let mut wanted = count;
        // SAFETY: `groups` has room for `wanted` IDs; the call writes how
        // many it found, or needs, into `wanted`.
        let found = unsafe {
            libc::getgrouplist(
                account.name.as_ptr(),
                account.gid,
                groups.as_mut_ptr(),
                &mut wanted,
            )
        };
        if found >= 0 {
            groups.truncate(wanted as usize);
            return Ok(groups);
        }
        if wanted <= count || wanted > 1 << 16 {
            return Err(io::Error::other("the user's groups can't be listed"));
        }
        count = wanted;
    }
}

/// Gives what root left in `directory` to `uid` and `gid`, as a command run
/// with `sudo` leaves what it makes root's: the regular files `names`
/// there, then `directory`. Only while `directory` is root's and no one
/// else may change its entries, so nothing in it can have been moved there
/// from elsewhere; and only files with no other hard link, each through a
/// handle that doesn't follow a link, so nothing elsewhere is given away.
/// Returns those of `names` root still owns there, other than links. A
/// missing `directory`, or a link, has nothing to give.
pub fn give_root_entries(
    directory: &Path,
    names: &[&OsStr],
    uid: u32,
    gid: u32,
) -> io::Result<Vec<std::ffi::OsString>> {
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let path = CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is NUL-terminated and outlives the call.
    let directory_fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_DIRECTORY) };
    if directory_fd < 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR)
        ) {
            return Ok(Vec::new());
        }
        return Err(error);
    }
    // SAFETY: the descriptor was just opened and is owned here.
    let directory_handle =
        unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(directory_fd) };
    let directory_metadata = directory_handle.metadata()?;
    let roots_alone = directory_metadata.uid() == 0
        && others_may_add(&directory_metadata, 0, Acl::Of(&directory_handle))?.is_none();
    let mut kept = Vec::new();
    for name in names {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: the directory descriptor is open and `c_name` is
        // NUL-terminated.
        let fd = unsafe { libc::openat(directory_fd, c_name.as_ptr(), flags) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            // A link is left for the opening to refuse, whoever made it.
            if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ELOOP)) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: as above.
        let handle = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let metadata = handle.metadata()?;
        if metadata.uid() != 0 {
            continue;
        }
        if roots_alone && metadata.is_file() && metadata.nlink() == 1 {
            std::os::unix::fs::fchown(&handle, Some(uid), Some(gid))?;
        } else {
            kept.push(name.to_os_string());
        }
    }
    if roots_alone {
        std::os::unix::fs::fchown(&directory_handle, Some(uid), Some(gid))?;
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn me() -> u32 {
        crate::current_uid()
    }

    #[test]
    fn a_path_through_directories_only_its_user_may_change_is_safe() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        set_mode(&project, 0o755);

        assert_eq!(first_changeable_directory(&project, me()).unwrap(), None);
    }

    #[test]
    fn a_directory_anyone_may_write_is_changeable_unless_sticky() {
        let directory = tempfile::tempdir().unwrap();
        let shared = directory.path().join("shared");
        let project = shared.join("project");
        std::fs::create_dir_all(&project).unwrap();
        set_mode(&shared, 0o777);

        let found = first_changeable_directory(&project, me()).unwrap().unwrap();
        assert_eq!(found.directory, shared.canonicalize().unwrap());
        assert_eq!(found.reason, "anyone may write to it");

        set_mode(&shared, 0o1777);
        assert_eq!(first_changeable_directory(&project, me()).unwrap(), None);
    }

    #[test]
    fn a_link_is_followed_and_its_target_checked() {
        let directory = tempfile::tempdir().unwrap();
        let open = directory.path().join("open");
        let project = open.join("project");
        std::fs::create_dir_all(&project).unwrap();
        set_mode(&open, 0o777);
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&project, &link).unwrap();

        let found = first_changeable_directory(&link, me()).unwrap().unwrap();
        assert_eq!(found.directory, open.canonicalize().unwrap());
    }

    #[test]
    fn a_link_in_a_directory_anyone_may_write_is_changeable() {
        let directory = tempfile::tempdir().unwrap();
        let open = directory.path().join("open");
        let project = directory.path().join("project");
        std::fs::create_dir(&open).unwrap();
        std::fs::create_dir(&project).unwrap();
        let link = open.join("link");
        std::os::unix::fs::symlink(&project, &link).unwrap();
        set_mode(&open, 0o777);

        let found = first_changeable_directory(&link, me()).unwrap().unwrap();
        assert_eq!(found.directory, open.canonicalize().unwrap());
    }

    #[test]
    fn another_user_s_directory_is_changeable() {
        let directory = tempfile::tempdir().unwrap();
        let (owner, another) = if me() == 0 {
            std::os::unix::fs::chown(directory.path(), Some(USER), None).unwrap();
            (USER, ANOTHER_USER)
        } else {
            (me(), me() + 1)
        };
        let metadata = std::fs::metadata(directory.path()).unwrap();
        let acl = Acl::At(directory.path());

        assert_eq!(
            why_changeable(&metadata, another, acl).unwrap(),
            Some("it belongs to another user")
        );
        assert_eq!(why_changeable(&metadata, owner, acl).unwrap(), None);
    }

    #[test]
    fn a_group_writable_directory_is_changeable_unless_its_group_is_the_user_s_alone() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        set_mode(&project, 0o775);
        let gid = std::fs::metadata(&project).unwrap().gid();

        let found = first_changeable_directory(&project, me()).unwrap();
        if group_is_private(gid, me()).unwrap() {
            assert_eq!(found, None);
        } else {
            assert_eq!(
                found.unwrap().reason,
                "its group, which has other members, may write to it"
            );
        }
    }

    #[test]
    fn a_group_is_private_only_as_the_user_s_primary_group_named_after_them_alone() {
        let Some(account) = account(me()).unwrap() else {
            return;
        };
        let primary = group(account.gid).unwrap();
        assert_eq!(
            group_is_private(account.gid, me()).unwrap(),
            primary.is_some_and(|primary| primary.name == account.name
                && primary.members.iter().all(|member| *member == account.name))
        );
        assert!(!group_is_private(account.gid, me() + 1_000_000).unwrap());
        assert!(!group_is_private(account.gid.wrapping_add(1), me()).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_acl_letting_anyone_add_entries_makes_a_directory_changeable() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let chmod = |entry: &str| {
            assert!(
                std::process::Command::new("/bin/chmod")
                    .args(["+a", entry])
                    .arg(&project)
                    .status()
                    .unwrap()
                    .success()
            );
        };

        chmod("everyone deny delete");
        assert_eq!(first_changeable_directory(&project, me()).unwrap(), None);
        chmod("everyone allow add_file");
        assert_eq!(
            first_changeable_directory(&project, me())
                .unwrap()
                .unwrap()
                .reason,
            "its access control list lets others change its entries"
        );
    }

    #[test]
    fn a_user_s_own_entries_are_neither_given_nor_kept() {
        if me() == 0 {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("mine"), b"").unwrap();

        let kept = give_root_entries(
            directory.path(),
            &[OsStr::new("mine"), OsStr::new("missing")],
            me() + 1,
            0,
        )
        .unwrap();

        assert!(kept.is_empty(), "{kept:?}");
        assert_eq!(
            std::fs::metadata(directory.path().join("mine"))
                .unwrap()
                .uid(),
            me()
        );
        assert_eq!(std::fs::metadata(directory.path()).unwrap().uid(), me());
    }

    #[test]
    fn a_missing_directory_or_a_link_has_nothing_to_give() {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();

        for path in [directory.path().join("missing"), link] {
            assert!(
                give_root_entries(&path, &[OsStr::new("any")], me() + 1, 0)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    /// A user other than root, whose directories root's tests make.
    const USER: u32 = 65_000;
    const USER_GROUP: u32 = 65_001;
    const ANOTHER_USER: u32 = 65_002;

    fn owners(path: &Path) -> (u32, u32) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        (metadata.uid(), metadata.gid())
    }

    /// Runs only as root, as in the root container the gate runs Linux
    /// tests in once more; CI's runner isn't root.
    #[test]
    fn as_root_what_root_alone_made_is_given_but_never_what_leads_elsewhere() {
        if me() != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o755);
        let elsewhere = root.path().join("elsewhere");
        let linked = root.path().join("linked");
        std::fs::write(&elsewhere, b"root's").unwrap();
        std::fs::write(&linked, b"root's").unwrap();
        let directory = root.path().join("lpm");
        std::fs::create_dir(&directory).unwrap();
        set_mode(&directory, 0o755);
        std::fs::write(directory.join("made"), b"").unwrap();
        std::fs::hard_link(&linked, directory.join("hard-link")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, directory.join("link")).unwrap();
        std::fs::create_dir(directory.join("folder")).unwrap();
        std::fs::write(directory.join("another's"), b"").unwrap();
        std::os::unix::fs::chown(directory.join("another's"), Some(ANOTHER_USER), None).unwrap();
        let names = [
            "made",
            "hard-link",
            "link",
            "folder",
            "another's",
            "missing",
        ]
        .map(OsStr::new);

        let kept = give_root_entries(&directory, &names, USER, USER_GROUP).unwrap();

        assert_eq!(kept, ["hard-link", "folder"]);
        assert_eq!(owners(&directory.join("made")), (USER, USER_GROUP));
        assert_eq!(owners(&directory), (USER, USER_GROUP));
        for unchanged in [
            &linked,
            &elsewhere,
            &directory.join("link"),
            &directory.join("folder"),
        ] {
            assert_eq!(owners(unchanged), (0, 0), "{}", unchanged.display());
        }
        assert_eq!(owners(&directory.join("another's")).0, ANOTHER_USER);
    }

    #[test]
    fn as_root_nothing_is_given_from_a_directory_others_may_change() {
        if me() != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o755);
        for (owner, mode) in [(0, 0o777), (0, 0o1777), (USER, 0o755)] {
            let directory = root.path().join(format!("{owner}-{mode:o}"));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("made"), b"").unwrap();
            std::os::unix::fs::chown(&directory, Some(owner), None).unwrap();
            set_mode(&directory, mode);

            let kept =
                give_root_entries(&directory, &[OsStr::new("made")], USER, USER_GROUP).unwrap();

            assert_eq!(kept, ["made"], "{}", directory.display());
            assert_eq!(owners(&directory.join("made")), (0, 0));
            assert_eq!(owners(&directory).0, owner);
        }
    }

    #[test]
    fn as_root_a_sticky_directory_its_group_may_write_leaves_another_user_s_entry_changeable() {
        if me() != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o755);
        let shared = root.path().join("shared");
        let project = shared.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::os::unix::fs::chown(&shared, Some(0), Some(USER_GROUP)).unwrap();
        set_mode(&shared, 0o1770);

        std::os::unix::fs::chown(&project, Some(ANOTHER_USER), None).unwrap();
        let found = first_changeable_directory(&project, USER).unwrap().unwrap();
        assert_eq!(found.directory, shared);
        assert_eq!(
            found.reason,
            "others may add to it, and the entry on the path belongs to another user"
        );

        std::os::unix::fs::chown(&project, Some(USER), None).unwrap();
        assert_eq!(first_changeable_directory(&project, USER).unwrap(), None);
    }

    /// Gives `path` an access ACL letting `uid` write to it, as `setfacl -m
    /// u:<uid>:rwx` does, or says the filesystem keeps none.
    #[cfg(target_os = "linux")]
    fn let_write(path: &Path, uid: u32) -> bool {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (0x01u16, 7u16, u32::MAX),
            (0x02, 7, uid),
            (0x04, 5, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 5, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the strings are NUL-terminated and the value holds
        // `acl.len()` bytes, all outliving the call.
        let result = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if result == 0 {
            return true;
        }
        let error = io::Error::last_os_error();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTSUP), "{error}");
        false
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_acl_that_may_let_others_write_makes_a_directory_changeable_whatever_its_group() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        if !let_write(&project, me() + 1) {
            return;
        }

        assert_eq!(
            first_changeable_directory(&project, me())
                .unwrap()
                .unwrap()
                .reason,
            "its access control list may let others write to it"
        );
    }
}
