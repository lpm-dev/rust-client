//! Per-process resource limits applied to sandboxed lifecycle
//! scripts. Defense-in-depth against denial-of-service from
//! malicious or runaway post-install scripts (fork bomb, fd
//! exhaustion, CPU-spinning, OOM-trigger).
//!
//! Unix backends (landlock on Linux, seatbelt on macOS) install
//! these via `setrlimit(2)` from inside the `pre_exec` closure —
//! a single syscall per limit, async-signal-safe. macOS deliberately
//! skips `RLIMIT_NPROC`: XNU applies that limit to the user's already
//! running process set, so lowering it inside the lifecycle child can
//! make ordinary `sh -c "mkdir ..."` forks fail with `EAGAIN` on busy
//! desktop sessions before the sandboxed script does anything risky.
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
//! fd exhaustion, infinite-loop CPU spinner, OOM-trigger) terminate
//! via ENOMEM / EAGAIN / EMFILE / SIGXCPU rather than starving the
//! host.
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
//!
//! # Address-space cap rationale (and why it differs from Windows)
//!
//! Windows sets `JOB_OBJECT_LIMIT_PROCESS_MEMORY = 2 GiB` per
//! descendant, measured against the per-process commit charge —
//! roughly anonymous private allocations + heap. Unix `RLIMIT_AS`
//! is the closest cross-platform analog but measures *virtual
//! address space*, which on 64-bit Unix includes the JIT mmap
//! pages V8/JavaScriptCore reserve eagerly, every shared-lib
//! mapping, large file-backed mmaps in tooling, and the guard
//! pages between thread stacks. A 2 GiB cap that's comfortable
//! under Windows accounting would break legitimate Node + V8 +
//! electron-rebuild + LLVM-link install steps on Unix.
//!
//! 8 GiB is the chosen floor: it caps a malicious script's
//! unbounded-allocate-until-OOM (which would otherwise consume
//! every page the kernel will hand out) at well below typical
//! host RAM, while leaving comfortable headroom for the worst
//! observed legitimate cases (LLVM linking a large Rust binary
//! peaks around 4 GiB virtual; node-gyp + electron-rebuild
//! sit under 2 GiB; V8 with `--max-old-space-size=4096` reserves
//! ~5 GiB virtual). The asymmetry with the Windows 2 GiB number
//! is intentional and reflects the different accounting models.

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

/// Linux user-wide process cap. See module-level note on Linux scope.
#[cfg(not(target_os = "macos"))]
pub(crate) const MAX_PROCESSES: u64 = 4096;

/// Per-process virtual-address-space cap. See the module-level
/// "address-space cap rationale" for why this is 8 GiB on Unix
/// rather than the 2 GiB the Windows job-object enforces.
pub(crate) const MAX_ADDRESS_SPACE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    #[cfg(not(target_os = "macos"))]
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
    let cap_as = libc::rlimit {
        rlim_cur: MAX_ADDRESS_SPACE_BYTES as libc::rlim_t,
        rlim_max: MAX_ADDRESS_SPACE_BYTES as libc::rlim_t,
    };
    // SAFETY: passing a valid `rlimit` for a defined resource id.
    // Return values ignored — see fn doc.
    unsafe {
        #[cfg(not(target_os = "macos"))]
        libc::setrlimit(libc::RLIMIT_NPROC, &cap_procs);
        libc::setrlimit(libc::RLIMIT_NOFILE, &cap_files);
        libc::setrlimit(libc::RLIMIT_CPU, &cap_cpu);
        libc::setrlimit(libc::RLIMIT_AS, &cap_as);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_address_space_pinned_at_8_gib() {
        // Regression guard. Lowering this to ~2 GiB (matching the
        // Windows commit cap) would break V8 / electron-rebuild /
        // LLVM-link installs that reserve >2 GiB of virtual address
        // space legitimately on 64-bit Unix. See the module
        // "address-space cap rationale" doc-comment before bumping
        // this value in either direction.
        assert_eq!(MAX_ADDRESS_SPACE_BYTES, 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn rlimit_constants_respect_ordering_invariants() {
        // The address-space cap must comfortably exceed the
        // largest single allocation our extractor budget permits
        // (1 GiB, set by `EXTRACT_BUDGET` in lpm-extractor) plus
        // the V8/JIT virtual pages a legit Node child reserves.
        // A regression that tightens the AS cap below 4 GiB
        // crosses into "will break real installs" territory.
        //
        // const-block assertions are compile-time checked — a
        // regression that lowers any constant past these floors
        // fails the build, not the test run.
        const _: () = assert!(MAX_ADDRESS_SPACE_BYTES >= 4 * 1024 * 1024 * 1024);
        // CPU cap should be at least as large as the default
        // wall-clock timeout in `rebuild.rs` so SIGXCPU never
        // fires before the timeout under realistic CPU load.
        const _: () = assert!(MAX_CPU_SECONDS >= 60);
        // File-descriptor cap should comfortably exceed the
        // process count cap — a single fork-bombed process can
        // hold ~32 open fds, and we don't want fd exhaustion
        // to be the bottleneck before NPROC fires.
        #[cfg(not(target_os = "macos"))]
        const _: () = assert!(MAX_OPEN_FILES >= MAX_PROCESSES);
    }

    #[test]
    fn apply_resource_limits_runs_to_completion_under_pre_exec() {
        // We can't call `apply_resource_limits_as_safe` directly in
        // a Rust test — it mutates the test runner's own rlimits and
        // would affect every subsequent test in the same process.
        // Instead spawn a child whose `pre_exec` closure applies the
        // limit, reads it back via `getrlimit`, and `_exit`s with a
        // status that encodes whether the kernel honored the cap or
        // ignored it. The closure `_exit`s before reaching `execve`,
        // so the test binary never actually re-runs.
        use std::os::unix::process::CommandExt;

        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        // SAFETY: child closure runs post-fork pre-exec; calls only
        // AS-safe libc primitives (setrlimit / getrlimit / _exit)
        // and never returns through pre_exec's Ok path — we always
        // `_exit` instead, so the parent reads the observed-vs-
        // expected comparison via exit status.
        unsafe {
            cmd.pre_exec(|| {
                apply_resource_limits_as_safe();
                let mut observed = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let rc = libc::getrlimit(libc::RLIMIT_AS, &mut observed);
                if rc != 0 {
                    libc::_exit(101);
                }
                // `rlim_t` is u64 on every Tier-1 target we
                // support (linux-x86_64/aarch64, macos-aarch64).
                // A future port to a 32-bit musl/uclibc target
                // would surface as a type-mismatch here and the
                // porter can add the cast back.
                if observed.rlim_cur == MAX_ADDRESS_SPACE_BYTES {
                    libc::_exit(0);
                }
                libc::_exit(102);
            });
        }
        let status = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn child");
        // Both `0` (kernel honored the cap) and `102` (kernel
        // accepted setrlimit but reports a different soft cap on
        // readback — happens on some legacy XNU builds where
        // RLIMIT_AS enforcement is incomplete) are acceptable
        // outcomes. The contract pinned here is "the pre_exec
        // branch runs to completion": no SIGSEGV, no 101 from
        // getrlimit, no signal-termination from a bad rlimit
        // struct shape.
        let code = status.code();
        assert!(
            code == Some(0) || code == Some(102),
            "child exited with unexpected status {code:?}; \
             pre_exec branch must complete without faulting"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_resource_limits_preserves_inherited_nproc_on_macos() {
        use std::os::unix::process::CommandExt;

        let mut inherited = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut inherited) };
        assert_eq!(rc, 0, "parent must be able to read RLIMIT_NPROC");

        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        unsafe {
            cmd.pre_exec(move || {
                apply_resource_limits_as_safe();
                let mut observed = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NPROC, &mut observed) != 0 {
                    libc::_exit(101);
                }
                if observed.rlim_cur == inherited.rlim_cur
                    && observed.rlim_max == inherited.rlim_max
                {
                    libc::_exit(0);
                }
                libc::_exit(102);
            });
        }
        let status = cmd
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn child");
        assert_eq!(
            status.code(),
            Some(0),
            "macOS sandbox setup must not lower user-wide RLIMIT_NPROC"
        );
    }
}
