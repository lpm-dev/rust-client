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
//! | Family       | Type (masked)   | Reason                          |
//! |--------------|-----------------|---------------------------------|
//! | `AF_INET`    | `SOCK_DGRAM`    | Direct UDP IPv4 egress.         |
//! | `AF_INET`    | `SOCK_RAW`      | Raw IPv4 packets.               |
//! | `AF_INET6`   | `SOCK_DGRAM`    | Direct UDP IPv6 egress.         |
//! | `AF_INET6`   | `SOCK_RAW`      | Raw IPv6 packets.               |
//! | `AF_PACKET`  | (any)           | L2 raw frames.                  |
//! | `AF_NETLINK` | (any)           | Routing / interface probes.     |
//!
//! `SOCK_NONBLOCK | SOCK_CLOEXEC` are masked off the type arg
//! before comparison so callers that pass `SOCK_DGRAM |
//! SOCK_CLOEXEC` (libuv's normal shape) still match the rule.
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

    let socket_rules = vec![
        // AF_INET + SOCK_DGRAM (UDP IPv4).
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
                libc::SOCK_DGRAM as u64,
            )?,
        ])?,
        // AF_INET + SOCK_RAW.
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
                libc::SOCK_RAW as u64,
            )?,
        ])?,
        // AF_INET6 + SOCK_DGRAM (UDP IPv6).
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
                libc::SOCK_DGRAM as u64,
            )?,
        ])?,
        // AF_INET6 + SOCK_RAW.
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
                libc::SOCK_RAW as u64,
            )?,
        ])?,
        // AF_PACKET (any type): L2 raw frames.
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_PACKET as u64,
        )?])?,
        // AF_NETLINK (any type): routing / interface probes.
        SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_NETLINK as u64,
        )?])?,
    ];
    rules.insert(libc::SYS_socket, socket_rules);

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
    }
}
