//! seccomp-bpf filter that denies the `socket(2)`
//! variants landlock V4 can't cover. Layered on top of the
//! landlock V4 ruleset in the strict posture's pre_exec closure.
//!
//! # What this layer adds
//!
//! The landlock V4 ruleset denies `BindTcp` /
//! `ConnectTcp` only. UDP-based egress, raw sockets, AF_PACKET,
//! and AF_NETLINK pass through landlock untouched. The seccomp
//! filter built here intercepts `socket(2)` and returns
//! `EACCES` for the following (family, type) combinations:
//!
//! | Family       | Type (masked)     | Reason                                |
//! |--------------|-------------------|---------------------------------------|
//! | `AF_INET`    | `SOCK_DGRAM`      | Direct UDP IPv4 egress.               |
//! | `AF_INET`    | `SOCK_RAW`        | Raw IPv4 packets.                     |
//! | `AF_INET`    | `SOCK_SEQPACKET`  | SCTP one-to-many IPv4 egress.         |
//! | `AF_INET`    | `SOCK_DCCP`       | DCCP IPv4 egress.                     |
//! | `AF_INET6`   | `SOCK_DGRAM`      | Direct UDP IPv6 egress.               |
//! | `AF_INET6`   | `SOCK_RAW`        | Raw IPv6 packets.                     |
//! | `AF_INET6`   | `SOCK_SEQPACKET`  | SCTP one-to-many IPv6 egress.         |
//! | `AF_INET6`   | `SOCK_DCCP`       | DCCP IPv6 egress.                     |
//! | `AF_PACKET`  | (any)             | L2 raw frames.                        |
//! | `AF_NETLINK` | (any)             | Routing / interface probes.           |
//!
//! `SOCK_NONBLOCK | SOCK_CLOEXEC` are masked off the type arg
//! before comparison so callers that pass `SOCK_DGRAM |
//! SOCK_CLOEXEC` (libuv's normal shape) still match the rule.
//!
//! SCTP one-to-one (`AF_INET[6] + SOCK_STREAM + IPPROTO_SCTP`)
//! is not covered by the socket-type matrix — it shares the
//! TCP stream type. The 3-arg deny rule at the bottom of the
//! socket rule list rejects it explicitly by matching the
//! protocol argument.
//!
//! # What this layer intentionally does NOT cover
//!
//! - `AF_UNIX` / `AF_LOCAL` — allowed (legitimate IPC needs in
//!   npm daemon comms, husky hooks, IDE debug protocols).
//! - Anything outside the matrix above — falls through to the
//!   default `Allow` action; landlock + filesystem rules remain
//!   the canonical denial points for the rest.
//! - Resolver-mediated DNS (`getaddrinfo`) — host-dependent;
//!   may route through AF_UNIX (allowed) or TCP fallback
//!   (caught by landlock, not by this filter). The audit
//!   harness keeps `dns_failure_seen` as a separate soft axis
//!   for this reason.
//!
//! # Accepted-posture trade-off (M63)
//!
//! The default action is [`SeccompAction::Allow`], so every syscall
//! that is not `socket(2)` passes through this filter untouched. That
//! includes a number of in-sandbox primitives an approved script
//! could chain into sandbox-escape or lateral-movement attempts:
//!
//! - `ptrace(2)` — could attach to a peer `lpm-rs` subprocess that
//!   holds vault unlock state or a session bearer in memory.
//! - `personality(2)` (`0xffffffff`) — disables ASLR for the child.
//! - `unshare(2)` (`CLONE_NEWUSER | CLONE_NEWNS`) — enters a user
//!   namespace where the script is "root" inside the namespace.
//!   landlock V4 attaches to the new namespace's view, but the
//!   attack surface widens (capabilities, mount manipulation).
//! - `keyctl(2)` / `add_key(2)` — could manipulate the per-user
//!   keyring.
//! - `bpf(2)` (`BPF_PROG_LOAD`) combined with user-ns.
//!
//! `PR_SET_NO_NEW_PRIVS` (issued by `seccompiler::apply_filter`)
//! blocks setuid escalation but NOT any of the above. The runtime
//! defenses are: (a) the script approval gate, which any of these
//! would require to reach the child in the first place; (b)
//! landlock V4 filesystem rules and network containment, which still
//! deny non-allow-listed paths and outbound TCP regardless of what
//! the script does after a successful `unshare` / `ptrace`; (c) the
//! `pre_exec` install order — landlock + seccomp install before
//! `execve`, so the script can't strip them.
//!
//! A future hardening pass could turn this filter into a full
//! deny-by-default seccomp profile (allowlist of "known-good"
//! syscalls), but the deny-everything default would need a per-
//! Node-major-version syscall inventory to avoid breaking legitimate
//! lifecycle scripts.
//!
//! # Filters every enforce posture installs
//!
//! The socket matrix above is strict-only. [`build_containment_filters`]
//! assembles the filters installed in the default and degraded postures
//! too, because they keep the filesystem and process containment honest
//! rather than deny network:
//!
//! - [`build_x32_abi_deny_filter`] (x86_64) refuses every x32 syscall, so
//!   no filter here can be bypassed through the x32 ABI. See below.
//! - [`build_process_group_filters`] keeps every descendant in the
//!   process group the kill-on-exit path signals.
//! - [`build_io_uring_deny_filter`] answers the three `io_uring`
//!   syscalls with `ENOSYS`. A ring's socket, connect, open and send
//!   operations skip the `socket(2)` the matrix sees, and before kernel
//!   6.10 the file operations skip landlock too. Runtimes that probe
//!   for `io_uring` fall back to epoll and their threadpool.
//! - [`build_terminal_injection_deny_filter`] refuses `TIOCSTI` and
//!   `TIOCLINUX`, which would let a script type into the user's
//!   terminal through an inherited descriptor.
//!
//! # Async-signal safety
//!
//! Filter compilation in [`build_socket_deny_filter`] happens
//! parent-side (allocates, builds the BPF program vector).
//! Installation via [`seccompiler::apply_filter`] in the child
//! is a single `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, …)`
//! syscall (after one `prctl(PR_SET_NO_NEW_PRIVS, 1, …)` that
//! `apply_filter` issues itself) — both AS-safe.
//!
//! # Architecture support
//!
//! x86_64 and aarch64 only. Both use the direct `socket(2)`
//! syscall, not the legacy `socketcall(2)` multiplexer that
//! i386 / 32-bit ARM use. seccompiler's `TargetArch` picks the
//! right syscall number table at compile time.
//!
//! # x32 ABI (x86_64 only)
//!
//! On a host where `CONFIG_X86_X32_ABI=y` is enabled, an x32 caller
//! issues syscalls with `__X32_SYSCALL_BIT` (`0x40000000`) set in the
//! number, under the same audit arch as x86_64, so a rule keyed on an
//! x86_64 number never sees them. Registering each rule again under
//! `__X32_SYSCALL_BIT | number` isn't enough either: syscalls that pass
//! structures through have their own x32 entry, `ioctl` among them (16 on
//! x86_64, 514 on x32). So every enforce posture refuses the whole x32 ABI
//! with `EPERM` instead. Lifecycle scripts have no use for it, and most
//! distribution kernels disable it already. 32-bit x86 calls carry another
//! audit arch, which every seccompiler-built filter here kills.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "seccomp socket() deny filter only supports linux-x86_64 and \
     linux-aarch64. Other architectures (linux-i386 / linux-arm32 / linux-riscv64) \
     need their own audit of the socket(2) calling convention before being added."
);

/// Mask that clears the `SOCK_NONBLOCK` / `SOCK_CLOEXEC` flag
/// bits from the type argument of `socket(2)`. After masking,
/// the type value matches one of `SOCK_STREAM`, `SOCK_DGRAM`,
/// `SOCK_RAW`, etc.
///
/// Without the mask, a caller doing `socket(AF_INET, SOCK_DGRAM
/// | SOCK_CLOEXEC, 0)` — the libuv normal shape — would have
/// `type == 0x802` rather than `0x2 == SOCK_DGRAM` and the deny
/// rule would miss.
const TYPE_MASK: u64 = !((libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64);

/// `__X32_SYSCALL_BIT` from `linux/include/uapi/asm-generic/unistd.h`.
/// An x32 caller on a `CONFIG_X86_X32_ABI=y` host issues each syscall
/// with this bit OR'd into the syscall number.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// Build the deny rule vector for `socket(2)`.
fn build_socket_rules() -> Result<Vec<SeccompRule>, seccompiler::Error> {
    fn family_type(family: i32, ty: i32) -> Result<SeccompRule, seccompiler::Error> {
        Ok(SeccompRule::new(vec![
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, family as u64)?,
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(TYPE_MASK),
                ty as u64,
            )?,
        ])?)
    }

    fn family_only(family: i32) -> Result<SeccompRule, seccompiler::Error> {
        Ok(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            family as u64,
        )?])?)
    }

    Ok(vec![
        family_type(libc::AF_INET, libc::SOCK_DGRAM)?,
        family_type(libc::AF_INET, libc::SOCK_RAW)?,
        family_type(libc::AF_INET, libc::SOCK_SEQPACKET)?,
        family_type(libc::AF_INET, libc::SOCK_DCCP)?,
        family_type(libc::AF_INET6, libc::SOCK_DGRAM)?,
        family_type(libc::AF_INET6, libc::SOCK_RAW)?,
        family_type(libc::AF_INET6, libc::SOCK_SEQPACKET)?,
        family_type(libc::AF_INET6, libc::SOCK_DCCP)?,
        // SCTP one-to-one: AF_INET[6] + SOCK_STREAM + IPPROTO_SCTP.
        // landlock V4 BindTcp/ConnectTcp may or may not key on
        // protocol (kernel implementation-defined). Explicit 3-arg
        // match closes the gap regardless.
        SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET as u64,
            )?,
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(TYPE_MASK),
                libc::SOCK_STREAM as u64,
            )?,
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::IPPROTO_SCTP as u64,
            )?,
        ])?,
        SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET6 as u64,
            )?,
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(TYPE_MASK),
                libc::SOCK_STREAM as u64,
            )?,
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::IPPROTO_SCTP as u64,
            )?,
        ])?,
        family_only(libc::AF_PACKET)?,
        family_only(libc::AF_NETLINK)?,
    ])
}

/// Build the socket() deny filter. Called on the
/// parent process before fork; the resulting [`BpfProgram`] is
/// moved into the spawn's `pre_exec` closure and installed via
/// [`seccompiler::apply_filter`].
///
/// On compile failure (which should not happen with a static
/// rule set — every condition validates) returns
/// `seccompiler::Error` for the caller to wrap as a sandbox
/// error.
pub fn build_socket_deny_filter() -> Result<BpfProgram, seccompiler::Error> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    rules.insert(libc::SYS_socket, build_socket_rules()?);

    let filter = SeccompFilter::new(
        rules,
        // Default: allow. `socket(2)` calls that don't match any
        // rule (AF_UNIX, AF_INET/SOCK_STREAM, etc.) pass through.
        // Every other syscall also passes through — landlock V4
        // is the canonical denial point for non-socket sinks.
        SeccompAction::Allow,
        // On match: return EACCES at the syscall layer. Same
        // errno macOS Seatbelt produces for a denied socket(),
        // so the workflow-test assertion can use one token set
        // for both platforms.
        SeccompAction::Errno(libc::EACCES as u32),
        TARGET_ARCH,
    )?;

    let program: BpfProgram = filter.try_into()?;
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_compiles_to_non_empty_program() {
        // Smoke test: the rule set is statically defined, so
        // compilation is deterministic. A non-empty BpfProgram
        // means seccompiler emitted at least the dispatch + a
        // rule chain for `socket`. A regression that drops all
        // rules (e.g. a refactor that empties the BTreeMap)
        // surfaces here.
        let program = build_socket_deny_filter().expect("static filter must compile");
        assert!(
            program.len() > 1,
            "BpfProgram must contain more than the default return; got {} instructions",
            program.len(),
        );
    }

    #[test]
    fn type_mask_clears_only_flag_bits() {
        // Pin the masking math: SOCK_DGRAM | SOCK_CLOEXEC must
        // survive the mask as SOCK_DGRAM. A regression that
        // typo'd the mask (e.g. swapped `!` for `&`) trips this.
        let masked_dgram_with_cloexec = (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as u64 & TYPE_MASK;
        assert_eq!(masked_dgram_with_cloexec, libc::SOCK_DGRAM as u64);

        let masked_dgram_with_nonblock =
            (libc::SOCK_DGRAM | libc::SOCK_NONBLOCK) as u64 & TYPE_MASK;
        assert_eq!(masked_dgram_with_nonblock, libc::SOCK_DGRAM as u64);

        let masked_raw =
            (libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64 & TYPE_MASK;
        assert_eq!(masked_raw, libc::SOCK_RAW as u64);

        let masked_seqpacket = (libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC) as u64 & TYPE_MASK;
        assert_eq!(masked_seqpacket, libc::SOCK_SEQPACKET as u64);

        let masked_dccp = (libc::SOCK_DCCP | libc::SOCK_NONBLOCK) as u64 & TYPE_MASK;
        assert_eq!(masked_dccp, libc::SOCK_DCCP as u64);
    }

    #[test]
    fn socket_rule_matrix_covers_sctp_and_dccp_types() {
        let rules = build_socket_rules().expect("rule construction infallible");
        // Family/type pairs (8) + 2 SCTP-over-stream rules + 2 family-only
        // (AF_PACKET, AF_NETLINK) = 12 rules total.
        assert_eq!(
            rules.len(),
            12,
            "expected 12 socket deny rules (8 family/type + 2 SCTP-stream + 2 family-only); \
             a regression that dropped SOCK_SEQPACKET, SOCK_DCCP, or IPPROTO_SCTP shape \
             surfaces here",
        );
    }

    #[test]
    fn x32_syscall_bit_constant_pinned() {
        // The kernel headers define __X32_SYSCALL_BIT as
        // 0x40000000. A typo here would aim the x32 deny at the
        // wrong syscall numbers without breaking compilation.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(X32_SYSCALL_BIT, 0x4000_0000);
    }
}

/// Deny the `io_uring` syscalls with `ENOSYS`, as on a kernel built
/// without it, so callers that probe for it fall back to plain syscalls.
/// Installed in every enforce posture: a ring's socket, connect, open and
/// send operations skip the syscalls the socket matrix and pre-6.10
/// landlock see.
pub(crate) fn build_io_uring_deny_filter() -> Result<BpfProgram, seccompiler::Error> {
    let filter = SeccompFilter::new(
        IO_URING_SYSCALLS
            .into_iter()
            .map(|syscall| (syscall, Vec::new()))
            .collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        TARGET_ARCH,
    )?;
    Ok(filter.try_into()?)
}

const IO_URING_SYSCALLS: [i64; 3] = [
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// Terminal ioctls that push bytes into a terminal's input queue. A script
/// with the user's terminal on an inherited descriptor could otherwise type
/// a command the user's shell runs after LPM exits (`TIOCSTI`, which kernels
/// before 6.2 allow by default), or do the same through the virtual-console
/// selection paste (`TIOCLINUX`). Matched on the low 32 bits, as the kernel
/// reads the request as `unsigned int`.
pub(crate) fn build_terminal_injection_deny_filter() -> Result<BpfProgram, seccompiler::Error> {
    let rules = TERMINAL_INJECTION_IOCTLS
        .into_iter()
        .map(|request| {
            SeccompRule::new(vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                request,
            )?])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let filter = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_ioctl, rules)]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TARGET_ARCH,
    )?;
    Ok(filter.try_into()?)
}

// `libc::Ioctl` is `c_ulong` on glibc and `c_int` on musl.
#[allow(clippy::unnecessary_cast)]
const TERMINAL_INJECTION_IOCTLS: [u64; 2] = [libc::TIOCSTI as u64, libc::TIOCLINUX as u64];

/// Refuse every x32 syscall with `EPERM`; see the module docs for why the
/// whole ABI goes rather than a mirror of each rule. seccompiler matches
/// whole syscall numbers only, so this filter is written as BPF directly.
#[cfg(target_arch = "x86_64")]
pub(crate) fn build_x32_abi_deny_filter() -> BpfProgram {
    /// Offsets into `struct seccomp_data`.
    const NR: u32 = 0;
    const ARCH: u32 = 4;
    /// `AUDIT_ARCH_X86_64` from `<linux/audit.h>`, which x32 calls carry too.
    const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

    fn op(code: u32, jump_if_true: u8, jump_if_false: u8, k: u32) -> seccompiler::sock_filter {
        seccompiler::sock_filter {
            code: code as u16,
            jt: jump_if_true,
            jf: jump_if_false,
            k,
        }
    }
    let load = |offset| op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, offset);
    vec![
        load(ARCH),
        // Calls under another arch fall through to allow here; the
        // seccompiler-built filters installed alongside kill them.
        op(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            3,
            AUDIT_ARCH_X86_64,
        ),
        load(NR),
        op(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            0,
            1,
            X32_SYSCALL_BIT as u32,
        ),
        op(
            libc::BPF_RET | libc::BPF_K,
            0,
            0,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ),
        op(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// The seccomp filters every enforce posture installs, whatever its network
/// policy, before any other: the x32 ABI deny (x86_64), the process-group
/// lock, the `io_uring` deny and the terminal input-injection deny.
pub(crate) fn build_containment_filters(
    virtualize_self_process_group: bool,
) -> Result<Vec<BpfProgram>, seccompiler::Error> {
    let mut filters = Vec::with_capacity(5);
    #[cfg(target_arch = "x86_64")]
    filters.push(build_x32_abi_deny_filter());
    filters.extend(build_process_group_filters(virtualize_self_process_group)?);
    filters.push(build_io_uring_deny_filter()?);
    filters.push(build_terminal_injection_deny_filter()?);
    Ok(filters)
}

#[cfg(test)]
mod containment_filter_tests {
    use super::*;

    fn in_filtered_child(program: &BpfProgram, probe: impl Fn() -> i32) -> i32 {
        in_child_under(std::slice::from_ref(program), probe)
    }

    /// Forks a child that installs `programs` and returns `probe`'s result
    /// as its exit status, so the filters never touch the test process.
    /// `probe` must make only syscalls: it runs after a fork of a
    /// multithreaded process.
    fn in_child_under(programs: &[BpfProgram], probe: impl Fn() -> i32) -> i32 {
        // SAFETY: the child calls only syscalls and `_exit`, and the parent
        // waits for exactly the child it created.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                for program in programs {
                    if seccompiler::apply_filter(program).is_err() {
                        libc::_exit(100);
                    }
                }
                libc::_exit(probe());
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status), "status={status}");
            libc::WEXITSTATUS(status)
        }
    }

    fn errno() -> i32 {
        // SAFETY: errno is thread-local and always readable.
        unsafe { *libc::__errno_location() }
    }

    #[test]
    fn io_uring_setup_reports_enosys_inside_the_filter() {
        let program = build_io_uring_deny_filter().unwrap();
        let status = in_filtered_child(&program, || {
            let mut params = [0_u8; 120];
            // SAFETY: io_uring_setup reads and writes a 120-byte params struct.
            let result = unsafe { libc::syscall(libc::SYS_io_uring_setup, 4, params.as_mut_ptr()) };
            match (result, errno()) {
                (0.., _) => 1,
                (_, libc::ENOSYS) => 0,
                _ => 2,
            }
        });
        assert_eq!(status, 0, "1: a ring was created; 2: the wrong errno");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn the_containment_filters_refuse_every_x32_syscall_and_still_run_native_ones() {
        // Each filtered syscall's x86_64 number, x32's own `ioctl` entry
        // (514), and an unfiltered syscall, all called with the x32 bit.
        // A kernel without x32 answers ENOSYS, so only the filter yields
        // EPERM. Every call names fd -1, so none can act if one gets past.
        const X32_PROBES: [i64; 7] = [
            514,
            libc::SYS_ioctl,
            libc::SYS_socket,
            libc::SYS_setsid,
            libc::SYS_setpgid,
            libc::SYS_io_uring_setup,
            libc::SYS_getpid,
        ];
        for virtualize in [false, true] {
            let programs = build_containment_filters(virtualize).unwrap();
            let status = in_child_under(&programs, || {
                let byte = b'x';
                for (index, number) in (1..).zip(X32_PROBES) {
                    // SAFETY: fd -1 names no file; the byte outlives the call.
                    let result = unsafe {
                        libc::syscall(X32_SYSCALL_BIT | number, -1, libc::TIOCSTI, &byte)
                    };
                    if result != -1 || errno() != libc::EPERM {
                        return index;
                    }
                }
                // SAFETY: getppid has no preconditions.
                if unsafe { libc::getppid() } > 0 {
                    0
                } else {
                    50
                }
            });
            assert_eq!(
                status, 0,
                "virtualize={virtualize}: 1-7 name the X32_PROBES entry that was not \
                 refused with EPERM; 50: a native syscall failed"
            );
        }
    }

    #[test]
    fn terminal_input_injection_is_denied_but_other_terminal_ioctls_work() {
        let mut controller = 0;
        let mut device = 0;
        // SAFETY: openpty writes two descriptors; the name, termios and
        // window size inputs are optional and left null.
        let opened = unsafe {
            libc::openpty(
                &mut controller,
                &mut device,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "openpty: {}", std::io::Error::last_os_error());
        let program = build_terminal_injection_deny_filter().unwrap();

        let status = in_filtered_child(&program, || {
            let byte = b'x';
            // SAFETY: TIOCSTI reads one byte through the pointer.
            if unsafe { libc::ioctl(device, libc::TIOCSTI, &byte) } != -1 {
                return 1;
            }
            if errno() != libc::EPERM {
                return 2;
            }
            let mut size = libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: TIOCGWINSZ writes one winsize through the pointer.
            if unsafe { libc::ioctl(device, libc::TIOCGWINSZ, &mut size) } != 0 {
                return 3;
            }
            0
        });
        // SAFETY: both descriptors came from openpty above.
        unsafe {
            libc::close(device);
            libc::close(controller);
        }
        assert_eq!(
            status, 0,
            "1: TIOCSTI injected input; 2: the wrong errno; 3: an ordinary terminal ioctl failed"
        );
    }
}

/// Keep descendants in the process group established before the filter is installed.
pub(crate) fn build_process_group_filter() -> Result<BpfProgram, seccompiler::Error> {
    let filter = SeccompFilter::new(
        BTreeMap::from([
            (libc::SYS_setsid, Vec::new()),
            (libc::SYS_setpgid, Vec::new()),
        ]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TARGET_ARCH,
    )?;
    Ok(filter.try_into()?)
}

pub(crate) fn build_process_group_filters(
    virtualize_self_process_group: bool,
) -> Result<Vec<BpfProgram>, seccompiler::Error> {
    if !virtualize_self_process_group {
        return Ok(vec![build_process_group_filter()?]);
    }

    let mut denied = BTreeMap::new();
    denied.insert(libc::SYS_setsid, Vec::new());
    denied.insert(
        libc::SYS_setpgid,
        (0..2)
            .map(|index| {
                SeccompRule::new(vec![SeccompCondition::new(
                    index,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::Ne,
                    0,
                )?])
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let deny = SeccompFilter::new(
        denied,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TARGET_ARCH,
    )?;

    // SwiftPM's posix_spawn requests a new child group. A successful no-op
    // keeps compiler descendants in our kill group; allowing the syscall
    // would let a manifest leave that group and outlive the deadline.
    let noop = SeccompFilter::new(
        BTreeMap::from([(
            libc::SYS_setpgid,
            vec![SeccompRule::new(
                (0..2)
                    .map(|index| {
                        SeccompCondition::new(index, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )?],
        )]),
        SeccompAction::Allow,
        SeccompAction::Errno(0),
        TARGET_ARCH,
    )?;
    Ok(vec![deny.try_into()?, noop.try_into()?])
}

#[cfg(test)]
mod process_group_tests {
    use super::*;

    #[test]
    fn swift_child_group_request_succeeds_without_changing_the_supervised_group() {
        let programs = build_process_group_filters(true).unwrap();
        // SAFETY: the fork child performs only syscalls and exits without
        // destructors. The parent waits for exactly its own child.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let group = libc::getpgrp();
                for program in &programs {
                    if seccompiler::apply_filter(program).is_err() {
                        libc::_exit(20);
                    }
                }
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(21);
                }
                libc::_exit(if libc::getpgrp() == group { 0 } else { 22 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "Swift child group request failed or escaped: status={status}"
            );
        }
    }

    #[test]
    fn swift_group_emulation_denies_explicit_group_and_session_changes() {
        let programs = build_process_group_filters(true).unwrap();
        // SAFETY: each child uses only syscalls and exits without destructors.
        // The parent waits for exactly the child it just created.
        unsafe {
            for explicit_pid in [false, true] {
                let pid = libc::fork();
                assert!(pid >= 0);
                if pid == 0 {
                    for program in &programs {
                        if seccompiler::apply_filter(program).is_err() {
                            libc::_exit(20);
                        }
                    }
                    let (target, group) = if explicit_pid {
                        (libc::getpid(), 0)
                    } else {
                        (0, libc::getpgrp())
                    };
                    if libc::setpgid(target, group) != -1
                        || *libc::__errno_location() != libc::EPERM
                    {
                        libc::_exit(21);
                    }
                    if libc::setsid() != -1 || *libc::__errno_location() != libc::EPERM {
                        libc::_exit(22);
                    }
                    libc::_exit(0);
                }
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                assert!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "explicit_pid={explicit_pid}, status={status}"
                );
            }
        }
    }

    fn probe_group_change(syscall: i64, filtered: bool, virtualize: bool) {
        let programs = build_process_group_filters(virtualize).unwrap();
        // SAFETY: the fork child uses only direct syscalls and exits without
        // running destructors. The parent waits for exactly its own child.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                if filtered {
                    for program in &programs {
                        if seccompiler::apply_filter(program).is_err() {
                            libc::_exit(20);
                        }
                    }
                }
                let result = libc::syscall(syscall, 0, 0);
                let error = *libc::__errno_location();
                let expected = if filtered {
                    result == -1 && error == libc::EPERM
                } else {
                    result >= 0
                };
                libc::_exit(if expected { 0 } else { 21 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "group syscall {syscall}, filtered={filtered}, status={status}"
            );
        }
    }

    #[test]
    fn group_changes_succeed_without_filter_and_are_denied_with_filter() {
        for syscall in [libc::SYS_setsid, libc::SYS_setpgid] {
            probe_group_change(syscall, false, false);
            probe_group_change(syscall, true, false);
        }
    }
}
