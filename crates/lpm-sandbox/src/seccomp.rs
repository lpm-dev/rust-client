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
//! - `io_uring_setup(2)` — landlock awareness was only added in
//!   kernel ≥ 6.10; older kernels with `io_uring` give the script
//!   a filesystem I/O channel outside this filter's view.
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
//! lifecycle scripts. Tracked as accepted-posture in
//! `private/security-findings.md` under M63.
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
//! # x32 ABI mirror (x86_64 only)
//!
//! On a host where `CONFIG_X86_X32_ABI=y` is enabled, an x32
//! caller issues syscalls with the `__X32_SYSCALL_BIT`
//! (`0x40000000`) OR'd into the syscall number. seccompiler's
//! filter is keyed on the literal syscall number, so a
//! plain x86_64-targeted filter does not match x32 calls —
//! every rule is bypassed. To close the specific `socket(2)`
//! bypass, the deny rules are also registered under
//! `__X32_SYSCALL_BIT | SYS_socket` so the same family/type
//! matrix applies to x32 socket() invocations. aarch64 has
//! no x32 ABI so this mirror is x86_64-only.
//!
//! The broader x32 surface (every other syscall) remains
//! unfiltered. We accept this trade-off because the script
//! approval gate, landlock V4 filesystem rules, and seccomp
//! socket gate together still cover the egress paths a
//! lifecycle script would reach for; the x32 mirror closes
//! the specific bypass that the audit harness reproduced.

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

/// IPPROTO_SCTP. Not exposed by libc 0.2 on every target, so pin
/// the IANA-assigned value here. Used to deny the
/// `AF_INET[6] + SOCK_STREAM + IPPROTO_SCTP` shape (SCTP one-to-one),
/// which would otherwise bypass the family/type matrix.
const IPPROTO_SCTP: u64 = 132;

/// Build the deny rule vector for `socket(2)`. The same vector is
/// registered under both `SYS_socket` and (on x86_64) the x32
/// `__X32_SYSCALL_BIT | SYS_socket` key so the matrix applies to
/// x32 callers too.
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
            SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, IPPROTO_SCTP)?,
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
            SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, IPPROTO_SCTP)?,
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

    #[cfg(target_arch = "x86_64")]
    {
        rules.insert(X32_SYSCALL_BIT | libc::SYS_socket, build_socket_rules()?);
    }

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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_mirror_registered_on_x86_64() {
        // The filter must contain dispatch entries for both the
        // x86_64 SYS_socket and the x32 mirror. seccompiler emits
        // the dispatcher table inline; we exercise the public
        // entrypoint and assume the program length grows with the
        // mirror rule set. A regression that drops the x32 mirror
        // would halve the per-rule dispatch length.
        let with_mirror = build_socket_deny_filter().expect("filter compiles");
        // Sanity floor — the rule set is 12 rules × 2 keys, each
        // emitting multiple BPF instructions plus dispatch.
        assert!(
            with_mirror.len() > 40,
            "x32-mirror filter must include both syscall keys; got {} instructions",
            with_mirror.len(),
        );
    }

    #[test]
    fn x32_syscall_bit_constant_pinned() {
        // The kernel headers define __X32_SYSCALL_BIT as
        // 0x40000000. A typo here silently disables the x32
        // mirror without breaking compilation.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(X32_SYSCALL_BIT, 0x4000_0000);
    }
}
