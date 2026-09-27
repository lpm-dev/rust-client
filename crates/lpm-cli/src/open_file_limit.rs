//! The process's limit on open files.
//!
//! macOS starts processes with a soft limit of 256 descriptors, too few for
//! the parallel file writers extraction budgets for, while the hard limit
//! allows far more. Node, Bun and Go raise their soft limit at startup the
//! same way. Child processes inherit the raised limit, as they do under npm
//! and Bun.

/// Raise the soft limit on open files to the hard limit, capped on macOS at
/// `kern.maxfilesperproc`. A failure leaves the limit unchanged.
#[cfg(unix)]
pub(crate) fn raise() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit initializes this valid out pointer on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    let Some(soft) = raised_soft_limit(limit.rlim_cur, limit.rlim_max, per_process_maximum())
    else {
        return;
    };
    let raised = libc::rlimit {
        rlim_cur: soft,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: setrlimit only reads this valid limit and changes nothing on failure.
    unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
    }
}

#[cfg(not(unix))]
pub(crate) fn raise() {}

#[cfg(unix)]
fn raised_soft_limit(
    soft: libc::rlim_t,
    hard: libc::rlim_t,
    per_process: Option<libc::rlim_t>,
) -> Option<libc::rlim_t> {
    let target = per_process.map_or(hard, |maximum| hard.min(maximum));
    (target > soft && target != libc::RLIM_INFINITY).then_some(target)
}

/// macOS rejects a soft limit above `kern.maxfilesperproc`, and its hard
/// limit is usually unlimited.
#[cfg(target_os = "macos")]
fn per_process_maximum() -> Option<libc::rlim_t> {
    let mut maximum: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated and `size` matches the output buffer.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&raw mut maximum).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && maximum > 0).then_some(maximum as libc::rlim_t)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn per_process_maximum() -> Option<libc::rlim_t> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::raised_soft_limit;

    #[test]
    fn the_soft_limit_rises_to_the_hard_limit_within_the_per_process_maximum() {
        assert_eq!(raised_soft_limit(256, 65_536, None), Some(65_536));
        assert_eq!(
            raised_soft_limit(256, libc::RLIM_INFINITY, Some(184_320)),
            Some(184_320)
        );
        assert_eq!(raised_soft_limit(256, 10_240, Some(184_320)), Some(10_240));
    }

    #[test]
    fn a_soft_limit_already_at_the_target_or_an_unbounded_target_is_left_alone() {
        assert_eq!(raised_soft_limit(65_536, 65_536, None), None);
        assert_eq!(
            raised_soft_limit(184_320, libc::RLIM_INFINITY, Some(184_320)),
            None
        );
        assert_eq!(raised_soft_limit(256, libc::RLIM_INFINITY, None), None);
    }
}
