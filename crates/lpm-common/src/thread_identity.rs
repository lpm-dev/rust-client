//! A thread's own filesystem identity, on Linux, whose kernel keeps each
//! thread's credentials: root can reach files as another user on one thread
//! alone, so a path that user controls leads only where that user could go,
//! however it changes meanwhile. The C library's `setgroups` sets every
//! thread's groups, so the thread's own are set with the system call itself.

use std::io;

/// The calling thread reaching files as another user, until this is
/// dropped, which gives the thread back the identity it had. A thread it
/// starts meanwhile keeps the user's for good, as Linux gives a new thread
/// its creator's.
#[must_use = "the thread acts as the user only while this is held"]
#[derive(Debug)]
pub struct ActingAs {
    fsuid: libc::uid_t,
    fsgid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

/// Has the calling thread reach files as `uid`, with `gid` as its only
/// group. The kernel takes root's file capabilities from a thread whose
/// filesystem user isn't root, so its access is the user's. Fails, leaving
/// the thread as it was, where it may not take the identity: without
/// `CAP_SETUID` and `CAP_SETGID`, or for an ID its user namespace doesn't
/// map.
pub fn act_as(uid: u32, gid: u32) -> io::Result<ActingAs> {
    let acting = ActingAs {
        fsuid: filesystem_uid(),
        fsgid: filesystem_gid(),
        groups: thread_groups()?,
    };
    set_thread_groups(&[gid])?;
    // SAFETY: each changes only the calling thread's credentials, and takes
    // no pointer.
    unsafe {
        libc::setfsgid(gid);
        libc::setfsuid(uid);
    }
    if filesystem_uid() != uid || filesystem_gid() != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("this process may not reach files as user {uid} and group {gid}"),
        ));
    }
    Ok(acting)
}

impl Drop for ActingAs {
    /// A thread that could take the identity keeps the capabilities to give
    /// it back: `CAP_SETUID` and `CAP_SETGID` aren't file capabilities.
    fn drop(&mut self) {
        // SAFETY: as in `act_as`.
        unsafe {
            libc::setfsuid(self.fsuid);
            libc::setfsgid(self.fsgid);
        }
        let _ = set_thread_groups(&self.groups);
    }
}

/// The thread's filesystem user ID. `setfsuid` reports no failure, so the
/// current one is read by asking for an ID no user has, which changes
/// nothing and returns it.
pub fn filesystem_uid() -> u32 {
    // SAFETY: as in `act_as`; an invalid ID changes nothing.
    unsafe { libc::setfsuid(libc::uid_t::MAX) as u32 }
}

/// The thread's filesystem group ID, read as [`filesystem_uid`] is.
pub fn filesystem_gid() -> u32 {
    // SAFETY: as in `act_as`; an invalid ID changes nothing.
    unsafe { libc::setfsgid(libc::gid_t::MAX) as u32 }
}

/// The calling thread's supplementary groups.
pub fn thread_groups() -> io::Result<Vec<libc::gid_t>> {
    loop {
        // SAFETY: a count of 0 only asks how many groups there are.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut groups = vec![0; count as usize];
        // SAFETY: `groups` has room for `count` IDs.
        let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if filled >= 0 {
            groups.truncate(filled as usize);
            return Ok(groups);
        }
        // The groups grew in between; ask again.
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(io::Error::last_os_error());
        }
    }
}

fn set_thread_groups(groups: &[libc::gid_t]) -> io::Result<()> {
    // SAFETY: the system call reads `groups.len()` IDs from `groups`, and
    // changes only the calling thread's credentials.
    let result = unsafe { libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_that_may_not_act_as_another_user_is_left_as_it_was() {
        if crate::current_uid() == 0 {
            return;
        }
        let before = (filesystem_uid(), filesystem_gid(), thread_groups().unwrap());

        let error = act_as(crate::current_uid() + 1, before.1 + 1).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            (filesystem_uid(), filesystem_gid(), thread_groups().unwrap()),
            before
        );
    }

    /// Runs only as root, as in the root container the gate runs Linux
    /// tests in once more; CI's runner isn't root.
    #[test]
    fn as_root_a_thread_reaches_files_as_the_user_and_alone_until_it_lets_go() {
        if crate::current_uid() != 0 {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("root-only");
        std::fs::write(&private, b"root's").unwrap();
        std::fs::set_permissions(
            &private,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        let before = (filesystem_uid(), filesystem_gid(), thread_groups().unwrap());
        let (ask, asked) = std::sync::mpsc::channel::<()>();
        let elsewhere = private.clone();
        let another_thread = std::thread::spawn(move || {
            asked.recv().unwrap();
            std::fs::read(elsewhere)
        });

        {
            let _acting = act_as(65_000, 65_000).unwrap();
            assert_eq!((filesystem_uid(), filesystem_gid()), (65_000, 65_000));
            assert_eq!(thread_groups().unwrap(), vec![65_000]);
            assert_eq!(
                std::fs::read(&private).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            ask.send(()).unwrap();
            assert_eq!(another_thread.join().unwrap().unwrap(), b"root's");
        }

        assert_eq!(
            (filesystem_uid(), filesystem_gid(), thread_groups().unwrap()),
            before
        );
        assert_eq!(std::fs::read(&private).unwrap(), b"root's");
    }
}
