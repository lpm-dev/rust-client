//! Per-process resource limits applied to sandboxed lifecycle
//! scripts. Defense-in-depth against denial-of-service from
//! malicious or runaway post-install scripts (fork bomb, fd
//! exhaustion, CPU-spinning).
//!
//! Unix backends (landlock on Linux, seatbelt on macOS) install
//! these via `setrlimit(2)` from inside the `pre_exec` closure —
//! a single syscall per limit, async-signal-safe.
//!
//! Windows applies the corresponding `JOB_OBJECT_LIMIT_*` flags
//! on the job object; that path is wired in `windows.rs` rather
//! than here because the Windows job-attach already exists as a
//! dedicated subsystem.
//!
//! # Why these values
//!
//! Limits trade off "block runaway scripts" against "don't break
//! legitimate installers." The constants below were chosen to be
//! generous enough that real lifecycle scripts (large monorepos,
//! prebuilt-binary downloaders, electron-rebuild) don't hit them,
//! and tight enough that the documented attack shapes (fork bomb,
//! fd exhaustion, infinite-loop CPU spinner) terminate via SIGXCPU
//! / EAGAIN / EMFILE rather than starving the host.
//!
//! # Linux NPROC scope note
//!
//! `RLIMIT_NPROC` is checked at `fork(2)` against the calling
//! user's total process count, not the lifecycle script's
//! descendants alone. A laptop with 200 background processes
//! has 200 against the cap, not the script's 1. We accept this
//! because the value (`MAX_PROCESSES`) leaves comfortable
//! headroom over typical desktop loads while still capping a
//! fork bomb's exponential growth before the host runs out of
//! pids. Proper per-script process isolation would need
//! `cgroup.pids` on Linux; tracked separately.

#![cfg(unix)]

/// Per-process file-descriptor cap. 4096 is the common soft
/// default for npm/pnpm installs; lower would break trees with
/// many concurrent dep extractions.
pub(crate) const MAX_OPEN_FILES: u64 = 4096;

/// Per-process CPU-seconds cap. Complements the wall-clock
/// timeout in `rebuild.rs` — a script that spin-locks on CPU
/// hits this before the wall clock fires, and SIGXCPU is more
/// diagnostic than the wall-clock SIGKILL.
pub(crate) const MAX_CPU_SECONDS: u64 = 600;

/// User-wide process cap. See module-level note on Linux scope.
pub(crate) const MAX_PROCESSES: u64 = 4096;

/// Install the resource limits inside a sandboxed child's
/// `pre_exec` closure. Each limit is best-effort: a `setrlimit`
/// failure (typically EPERM if the hard cap was already lower
/// than our requested soft cap, or EINVAL on an obscure kernel)
/// is ignored — the limit we couldn't tighten falls back to the
/// inherited value, which is no worse than the prior baseline
/// before this layer was added.
///
/// SAFETY: AS-safe. Each `setrlimit` call is a single syscall.
/// The `rlimit` struct is a POD constructed on the stack with no
/// heap allocation. Constants are typed correctly per-platform by
/// the libc crate (`__rlimit_resource_t` on Linux, `c_int` on
/// macOS) so the calls compile on both targets verbatim.
#[inline]
pub(crate) fn apply_resource_limits_as_safe() {
    let cap_procs = libc::rlimit {
        rlim_cur: MAX_PROCESSES as libc::rlim_t,
        rlim_max: MAX_PROCESSES as libc::rlim_t,
    };
    let cap_files = libc::rlimit {
        rlim_cur: MAX_OPEN_FILES as libc::rlim_t,
        rlim_max: MAX_OPEN_FILES as libc::rlim_t,
    };
    let cap_cpu = libc::rlimit {
        rlim_cur: MAX_CPU_SECONDS as libc::rlim_t,
        rlim_max: MAX_CPU_SECONDS as libc::rlim_t,
    };
    // SAFETY: passing a valid `rlimit` for a defined resource id.
    // Return values ignored — see fn doc.
    unsafe {
        libc::setrlimit(libc::RLIMIT_NPROC, &cap_procs);
        libc::setrlimit(libc::RLIMIT_NOFILE, &cap_files);
        libc::setrlimit(libc::RLIMIT_CPU, &cap_cpu);
    }
}
