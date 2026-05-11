//! Linux landlock backend: restricts the child process's filesystem
//! access via a ruleset installed through the landlock LSM. Phase 46
//! P5 Chunk 3.
//!
//! # Async-signal safety
//!
//! The closure passed to [`std::os::unix::process::CommandExt::pre_exec`]
//! runs in the forked child between `fork` and `execve`. In a
//! multi-threaded parent, only the calling thread survives in the
//! child; other threads may have been holding the allocator mutex,
//! the stdio mutex, or any other userspace lock when `fork` fired.
//! Taking those locks in the child deadlocks immediately. Only
//! async-signal-safe (AS-safe) operations are legal — direct
//! syscalls, raw errno writes, integer/enum manipulation, etc.
//!
//! This backend therefore splits work across the fork boundary:
//!
//! **Parent side** (normal multi-threaded context):
//! - [`Ruleset::default`] / [`handle_access`] / [`RulesetAttr::create`] —
//!   allocates Rust-side state, makes the `landlock_create_ruleset`
//!   syscall to get the ruleset FD.
//! - Per-path [`PathFd::new`] (opens `open(2)` for each allow-path)
//!   and [`Ruleset::add_rule`] (feeds each `PathBeneath` through
//!   `landlock_add_rule`). Paths that don't exist are skipped with
//!   a `tracing::debug!` advisory — parent logging is safe.
//! - The assembled [`RulesetCreated`] (which owns the ruleset FD +
//!   in-memory state) is moved into the pre_exec closure.
//!
//! **Child side** (post-fork, pre-exec, AS-safe only):
//! - [`Option::take`] to extract the `RulesetCreated` captured by
//!   move.
//! - [`RulesetCreated::restrict_self`] — audited call path: two
//!   direct syscalls (`prctl(PR_SET_NO_NEW_PRIVS)` and
//!   `landlock_restrict_self`) plus enum/integer field shuffles.
//!   No heap allocation, no lock acquisition.
//! - On failure, [`write_stderr_as_safe`] — raw `write(2)` to fd 2,
//!   bypassing `std::io::Stderr::lock()` which is NOT safe here.
//! - [`std::io::Error::from_raw_os_error`] to propagate errno —
//!   wraps an integer, does not allocate (contrast with
//!   `io::Error::new(kind, &str)` which goes through `Box<Custom>`
//!   and IS allocating).
//!
//! Crucially we do NOT `eprintln!`, `format!`, `Box::new`, or call
//! any trait method whose implementation is opaque from the
//! child's perspective. The landlock library's `restrict_self` is
//! the only exception, and we've audited its source.
//!
//! # Kernel probe
//!
//! [`LandlockSandbox::new`] runs in the PARENT and decides which
//! posture to construct from the detected kernel version
//! ([`crate::posture_decision::decide_posture`]) and the caller's
//! [`SandboxOptions::allow_degraded`] opt-in:
//!
//! - **Strict** (default on kernels ≥ 6.7): probe landlock at ABI V4
//!   with [`landlock::CompatLevel::HardRequirement`]. On success we
//!   construct the strict backend, which installs filesystem rules
//!   AND declares `AccessNet::from_all(V4)` (BindTcp + ConnectTcp)
//!   with NO `NetPort` allow rules — landlock then default-denies
//!   outbound TCP. **UDP / raw / AF_PACKET / DNS-via-UDP are NOT
//!   denied by V4 alone** — that's the Phase 46.1.1 seccomp-bpf
//!   layer's job. On V4 probe failure the kernel reported ≥ 6.7
//!   but landlock itself isn't reachable (LSM disabled, etc.) —
//!   we surface [`SandboxError::KernelTooOld`] with
//!   `required: "6.7"`.
//! - **Degraded** (kernel < 6.7 AND `allow_degraded = true`): probe
//!   landlock at ABI V1 (filesystem-only). The construction-side
//!   succeeds when V1 is reachable; the install pipeline emits the
//!   per-install structured stderr warning via
//!   [`crate::SandboxPosture::degraded_warning_line`].
//! - **Refuse** (kernel < 6.7 AND `allow_degraded = false`, the
//!   strict default): surface `SandboxError::KernelTooOld` with
//!   `required: "6.7"` before the script ever spawns. Refusal is
//!   symmetric with the Windows path per the Chunk 1 signoff. The
//!   user's interim options are `--unsafe-full-env --no-sandbox`,
//!   adding the package to `trustedDependencies`, or upgrading the
//!   kernel.
//!
//! # Enforcement guard
//!
//! If the child's `restrict_self` returns
//! [`RulesetStatus::NotEnforced`] (the landlock LSM disappeared
//! between parent probe and child fork — effectively never in
//! practice), we bail rather than run the script unsandboxed. The
//! guard keeps the security floor consistent even under the
//! hypothetical race.

#![cfg(target_os = "linux")]

use crate::landlock_rules::{RuleAccess, describe_rules};
use crate::posture_decision::{PostureDecision, REQUIRED_KERNEL_FOR_STRICT, decide_posture};
use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec,
    SandboxedCommand,
};
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus,
};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

/// Phase 46.1: minimum kernel version the strict posture targets.
/// V4 landed in 6.7 (January 2024) and is the first ABI that
/// carries network access rules; below this floor the backend has
/// no kernel-level mechanism to deny outbound network, so the
/// Strict posture refuses and routes the user to the three
/// remediations (degraded opt-in, `--unsafe-full-env --no-sandbox`,
/// or kernel upgrade).
const MIN_KERNEL_VERSION_STRICT: &str = REQUIRED_KERNEL_FOR_STRICT;

/// Phase 46.1 fallback floor: V1 landed in 5.13. Used by the
/// degraded posture's V1 probe to give an honest error if even V1
/// is unreachable (landlock LSM disabled entirely).
const MIN_KERNEL_VERSION_FALLBACK: &str = "5.13";

/// Phase 46.1 Strict ABI: V4 (kernel 6.7+). Adds network access
/// rules on top of V1's filesystem set; an empty
/// `AccessNet::from_all(V4)` handler with no `NetPort` allows
/// yields default-deny for both `BindTcp` and `ConnectTcp`.
const TARGET_ABI_STRICT: ABI = ABI::V4;

/// Phase 46.1 Degraded ABI: V1 (kernel 5.13+). Filesystem-only —
/// matches the Phase 46 P5 behaviour exactly. Used only when the
/// user has set `[sandbox] allow-degraded = true` AND the detected
/// kernel is below the V4 floor.
const TARGET_ABI_FALLBACK: ABI = ABI::V1;

/// Internal posture tag the backend constructs after the kernel
/// version + landlock probe. Pinned at construction time and
/// referenced by both `build_parent_side_ruleset` (which picks the
/// ABI and decides whether to install the network handler) and the
/// `Sandbox::posture` implementation (which surfaces the enforced
/// dimensions for the install pipeline's warning + doctor surfaces).
#[derive(Debug, Clone)]
enum BackendPosture {
    /// V1 with FS rules only, no AccessNet rules. Reached when the
    /// user picked `[sandbox] mode = "default"` (or accepted the
    /// default default). Matches the Phase 46 P5 baseline. Phase
    /// 46.1 rework (2026-05-11): added so the doctor / posture
    /// surfaces can distinguish "user chose default" from "user
    /// chose strict but kernel forced fallback" (`Degraded`).
    Default,
    /// V4 with both FS rules and network handling installed. The
    /// full Phase 46.1 strict contract. Reached when the user opts
    /// into strict mode AND the kernel delivers landlock V4.
    Strict,
    /// V1 with FS rules only. Triggered when the user opts into
    /// strict mode (`deny_outbound_network = true`) BUT the kernel
    /// is below the V4 floor AND `[sandbox] allow-degraded = true`
    /// is set. The `detected_kernel` field flows into the
    /// per-install warning so users see the fallback explicitly.
    Degraded { detected_kernel: String },
}

impl BackendPosture {
    /// Landlock ABI level the parent-side ruleset builder uses.
    fn abi(&self) -> ABI {
        match self {
            BackendPosture::Strict => TARGET_ABI_STRICT,
            BackendPosture::Default | BackendPosture::Degraded { .. } => TARGET_ABI_FALLBACK,
        }
    }

    /// `true` iff this posture installs landlock V4's TCP-deny
    /// handler (`AccessNet::from_all(V4)` — BindTcp + ConnectTcp).
    /// Only Strict does; `Default` and `Degraded` explicitly do
    /// not.
    ///
    /// Naming: "enforces TCP" would be more precise than "enforces
    /// network" — landlock V4 doesn't cover UDP / raw / AF_PACKET.
    /// The full network-denial story on Linux is `enforces_tcp`
    /// (this method) AND, after Phase 46.1.1 lands, the seccomp-bpf
    /// filter that denies the non-TCP socket families. The method
    /// name stays `enforces_network` because that matches the
    /// landlock-side intent — the seccomp layer will be its own
    /// predicate when it lands.
    fn enforces_network(&self) -> bool {
        matches!(self, BackendPosture::Strict)
    }
}

pub(crate) struct LandlockSandbox {
    spec: SandboxSpec,
    mode: SandboxMode,
    posture: BackendPosture,
}

impl LandlockSandbox {
    pub(crate) fn new(
        spec: SandboxSpec,
        mode: SandboxMode,
        options: SandboxOptions,
    ) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => {
                let posture = if options.deny_outbound_network {
                    // Strict path — Phase 46.1's locked contract.
                    // Two-step decision: (a) pure version-based
                    // posture pick via [`decide_posture`]; (b) live
                    // landlock probe at the chosen ABI to confirm
                    // the kernel actually delivers it.
                    let detected = detect_kernel_version();
                    match decide_posture(&detected, options.allow_degraded) {
                        PostureDecision::Strict => {
                            probe_landlock_at(TARGET_ABI_STRICT, /* with_network */ true).map_err(
                                |_| SandboxError::KernelTooOld {
                                    detected: detected.clone(),
                                    required: MIN_KERNEL_VERSION_STRICT.to_string(),
                                    remediation: strict_remediation(),
                                },
                            )?;
                            BackendPosture::Strict
                        }
                        PostureDecision::Degraded { detected_kernel } => {
                            probe_landlock_at(TARGET_ABI_FALLBACK, /* with_network */ false)
                                .map_err(|_| SandboxError::KernelTooOld {
                                    detected: detected_kernel.clone(),
                                    required: MIN_KERNEL_VERSION_FALLBACK.to_string(),
                                    remediation: degraded_v1_probe_failed_remediation(),
                                })?;
                            BackendPosture::Degraded { detected_kernel }
                        }
                        PostureDecision::Refuse {
                            detected_kernel,
                            required_kernel,
                        } => {
                            return Err(SandboxError::KernelTooOld {
                                detected: detected_kernel,
                                required: required_kernel.to_string(),
                                remediation: strict_remediation(),
                            });
                        }
                    }
                } else {
                    // Default path — Phase 46.1 rework (2026-05-11).
                    // The user picked the relaxed mode (or accepted
                    // the default default). V1 floor is sufficient
                    // (filesystem rules only, no AccessNet
                    // declaration). `allow_degraded` is irrelevant
                    // here — V1 is what we'd fall back to anyway,
                    // and it's not a "degraded" state because the
                    // user didn't ask for stricter coverage.
                    //
                    // Still probe to surface a meaningful error if
                    // landlock is entirely absent (LSM disabled,
                    // kernel < 5.13). Without this, a missing-LSM
                    // host would silently produce a useless sandbox.
                    probe_landlock_at(TARGET_ABI_FALLBACK, /* with_network */ false).map_err(
                        |_| {
                            let detected = detect_kernel_version();
                            SandboxError::KernelTooOld {
                                detected,
                                required: MIN_KERNEL_VERSION_FALLBACK.to_string(),
                                remediation: default_mode_probe_failed_remediation(),
                            }
                        },
                    )?;
                    BackendPosture::Default
                };
                Ok(Self {
                    spec,
                    mode,
                    posture,
                })
            }
            // Chunk 4: landlock has no native observe-only primitive
            // (RulesetStatus::NotEnforced / PartiallyEnforced /
            // FullyEnforced + CompatLevel::BestEffort don't model
            // "allow but log"). Per the Chunk 4 plan signoff, we
            // reject LogOnly honestly rather than invent a pseudo-
            // mode that would pretend to observe while silently
            // doing nothing.
            SandboxMode::LogOnly => Err(SandboxError::ModeNotSupportedOnPlatform {
                platform: "linux".to_string(),
                mode: SandboxMode::LogOnly,
                remediation: "landlock has no native observe-only primitive in \
                         Phase 46 P5. To debug a sandbox false-positive, re-run \
                         with --unsafe-full-env --no-sandbox. `--sandbox-log` \
                         remains available on macOS."
                    .to_string(),
            }),
            // Disabled never reaches this backend — factory routes
            // it to NoopSandbox. Defensive error symmetric with
            // the macOS backend's guard.
            SandboxMode::Disabled => Err(SandboxError::InvalidSpec {
                reason: "SandboxMode::Disabled reached LandlockSandbox — should \
                             have been routed to NoopSandbox by the factory"
                    .to_string(),
            }),
        }
    }
}

/// User-facing remediation string for the strict posture's refusal
/// (kernel < 6.7 + `allow_degraded = false`). Names all four
/// remediations so the user can pick the right one without
/// re-reading the docs.
fn strict_remediation() -> String {
    "remediation options: (1) set `[sandbox] allow-degraded = true` in \
     `~/.lpm/config.toml` or `./lpm.toml` to fall back to landlock V1 \
     (filesystem-only — NO outbound TCP denial, NO UDP denial); \
     (2) add the package to `package.json > lpm > trustedDependencies` \
     to skip the sandbox for this dependency; (3) re-run with \
     `--unsafe-full-env --no-sandbox` to skip the sandbox wholesale; \
     (4) upgrade the host kernel to 6.7+ to get the Phase 46.1 strict \
     posture (filesystem-write containment + outbound TCP denial; UDP \
     denial lands in Phase 46.1.1's seccomp-bpf layer)."
        .to_string()
}

/// Used when the user opted into degraded posture but even the V1
/// fallback probe failed (landlock LSM disabled entirely). Points
/// at the kernel upgrade or the wholesale escape hatch — the
/// degraded opt-in can't help when V1 itself is unreachable.
fn degraded_v1_probe_failed_remediation() -> String {
    "even the V1 (filesystem-only) fallback failed — landlock appears to \
     be disabled on this kernel. Re-run with `--no-sandbox`, add the \
     package to `package.json > lpm > trustedDependencies`, or rebuild \
     the kernel with CONFIG_SECURITY_LANDLOCK=y."
        .to_string()
}

/// Used when the user is on the relaxed default mode but the V1
/// probe fails (landlock LSM disabled entirely). Same recourses as
/// the degraded path — the default mode can't deliver any sandbox
/// either if V1 is unreachable.
fn default_mode_probe_failed_remediation() -> String {
    "landlock appears to be disabled on this kernel (even the V1 \
     filesystem-only baseline failed to load). Re-run with \
     `--no-sandbox`, add the package to `package.json > lpm > \
     trustedDependencies`, or rebuild the kernel with \
     CONFIG_SECURITY_LANDLOCK=y."
        .to_string()
}

impl Sandbox for LandlockSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<Child, SandboxError> {
        let mut command = Command::new(&cmd.program);
        command.args(&cmd.args);
        if cmd.env_clear {
            command.env_clear();
        }
        for (k, v) in &cmd.envs {
            command.env(k, v);
        }
        if let Some(dir) = &cmd.current_dir {
            command.current_dir(dir);
        }
        command.stdout(Stdio::from(cmd.stdout));
        command.stderr(Stdio::from(cmd.stderr));
        command.stdin(Stdio::from(cmd.stdin));
        // Matches the macOS and Noop backends — kill-tree-on-timeout
        // parity. `process_group(0)` is wired by the stdlib in its
        // own post-fork / pre-exec step and does not conflict with
        // our own `pre_exec` closure below.
        command.process_group(0);

        // Build the landlock ruleset entirely in the PARENT — see
        // the module doc for the async-signal-safety rationale. All
        // the allocating / lock-acquiring work (ruleset struct
        // construction, per-path `open(2)` via PathFd::new, per-rule
        // `landlock_add_rule` via Ruleset::add_rule) happens here in
        // normal multi-threaded context. The child's pre_exec body
        // only touches direct syscalls.
        let ruleset = build_parent_side_ruleset(&self.spec, &self.posture).map_err(|e| {
            SandboxError::ProfileRenderFailed {
                reason: format!("landlock ruleset build failed: {e}"),
            }
        })?;

        // Option wrapper lets a FnMut closure consume the ruleset
        // once (via `take`) while satisfying the FnMut bound
        // `Command::pre_exec` requires. In practice the kernel only
        // invokes pre_exec once per spawn; the `take().ok_or(...)`
        // path below catches the hypothetical double-invocation.
        let mut ruleset_opt = Some(ruleset);

        // SAFETY: This closure runs post-fork, pre-exec in the
        // child. The body is AS-safe: no heap allocation, no lock
        // acquisition, no `format!` / `eprintln!`. All possible
        // operations inside are either (a) direct syscalls via
        // `libc` or `landlock` crate, (b) integer / enum
        // manipulation, or (c) `io::Error::from_raw_os_error` which
        // wraps an integer without allocating. The captured
        // `ruleset_opt` holds a `RulesetCreated` whose `Drop`
        // closes the inherited FD via `close(2)` — also AS-safe.
        // See the module doc for the full audit.
        unsafe {
            command.pre_exec(move || {
                let rs = match ruleset_opt.take() {
                    Some(r) => r,
                    None => {
                        write_stderr_as_safe(b"landlock: pre_exec invoked without ruleset\n");
                        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                    }
                };
                match rs.restrict_self() {
                    Ok(status) if matches!(status.ruleset, RulesetStatus::NotEnforced) => {
                        write_stderr_as_safe(
                            b"landlock: ruleset NotEnforced; refusing to run unsandboxed\n",
                        );
                        Err(std::io::Error::from_raw_os_error(libc::EPERM))
                    }
                    Ok(_) => Ok(()),
                    Err(_) => {
                        // Discard the RulesetError's Display body
                        // — formatting it would allocate. The
                        // `landlock:` prefix on stderr tells users
                        // to look at parent-side tracing for
                        // details.
                        write_stderr_as_safe(b"landlock: restrict_self failed\n");
                        Err(std::io::Error::from_raw_os_error(libc::EPERM))
                    }
                }
            });
        }

        command.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: format!("landlock spawn failed: {e}"),
        })
    }

    fn backend_name(&self) -> &'static str {
        "landlock"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }

    fn posture(&self) -> SandboxPosture {
        match &self.posture {
            BackendPosture::Default => SandboxPosture::Default,
            BackendPosture::Strict => SandboxPosture::Strict,
            BackendPosture::Degraded { detected_kernel } => SandboxPosture::Degraded {
                kernel: detected_kernel.clone(),
                abi: "v1",
                missing: "network-containment",
            },
        }
    }
}

/// Parent-side landlock probe at a specific ABI. Builds a
/// HardRequirement ruleset declaring the FS + (optionally) network
/// access classes the constructed sandbox will install. Used by
/// [`LandlockSandbox::new`] AFTER [`decide_posture`] picks which ABI
/// to target — the probe confirms the kernel actually delivers
/// landlock at that level (the version string can be spoofed or
/// reported correctly while the LSM is disabled in the build).
///
/// On success the probe is dropped (FD closes). On failure the
/// caller decides which `SandboxError::KernelTooOld { required: …}`
/// minimum to surface based on which probe was tried.
fn probe_landlock_at(abi: ABI, with_network: bool) -> Result<(), RulesetError> {
    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))?;
    if with_network {
        // `AccessNet::from_all(V4)` is `BindTcp | ConnectTcp`. With
        // HardRequirement set, calling handle_access on a kernel
        // that doesn't expose the V4 network capabilities errors —
        // exactly the signal we want from the probe.
        builder = builder.handle_access(AccessNet::from_all(abi))?;
    }
    let _ruleset = builder.create()?;
    Ok(())
}

/// Build the full landlock ruleset on the PARENT process, before
/// fork. All heap allocation, PathFd opening, and add_rule calls
/// happen here so the child's pre_exec body stays async-signal-safe.
///
/// Missing paths are skipped with a parent-side `tracing::debug!`
/// advisory rather than failing the whole spawn — a partial rule
/// set is a tighter security posture than no sandbox at all, and
/// the escape hatch remains `--unsafe-full-env --no-sandbox` if the
/// user needs the missing rule's access.
///
/// Phase 46.1: when `posture` is [`BackendPosture::Strict`], the
/// ruleset also declares `handle_access(AccessNet::from_all(V4))`
/// (BindTcp + ConnectTcp) but installs no `NetPort` allow rules —
/// landlock then default-denies every TCP bind / connect, which is
/// the kernel-level outbound network denial Phase 46.1 ships.
fn build_parent_side_ruleset(
    spec: &SandboxSpec,
    posture: &BackendPosture,
) -> Result<RulesetCreated, RulesetError> {
    let abi = posture.abi();
    let rw = AccessFs::from_all(abi);
    let read = AccessFs::from_read(abi);
    let mut builder = Ruleset::default().handle_access(rw)?;
    if posture.enforces_network() {
        // Strict V4 only: declare the network access classes so
        // they participate in the deny-default. We deliberately add
        // NO `NetPort` rules — landlock's contract is that a class
        // declared via `handle_access` with no per-rule allows is
        // default-denied. That gives us the "no outbound, no
        // loopback exemption" posture the design note Q1 locks.
        builder = builder.handle_access(AccessNet::from_all(abi))?;
    }
    let mut ruleset = builder.create()?;
    for (path, access) in describe_rules(spec) {
        let fd = match PathFd::new(&path) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::debug!("landlock: skip {} ({e})", path.display());
                continue;
            }
        };
        let access_bits = match access {
            RuleAccess::Read => read,
            RuleAccess::ReadWrite => rw,
        };
        ruleset = ruleset.add_rule(PathBeneath::new(fd, access_bits))?;
    }
    Ok(ruleset)
}

/// Async-signal-safe stderr write. Bypasses [`std::io::Stderr::lock`]
/// (which holds a userspace mutex and deadlocks post-fork in
/// multi-threaded processes) by issuing a direct `write(2)` to fd 2.
///
/// Return value is intentionally ignored — there's no meaningful
/// recovery at the pre_exec-failure call site, and `write` itself
/// is AS-safe regardless of outcome.
#[inline]
fn write_stderr_as_safe(msg: &[u8]) {
    // SAFETY: fd 2 is guaranteed open by the stdlib at process
    // start and our Command configuration doesn't close it. `msg`
    // is a static byte slice, so the pointer and length are valid
    // for the duration of the call. `libc::write` is AS-safe.
    unsafe {
        let _ = libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

/// Best-effort kernel version probe for the [`SandboxError::KernelTooOld`]
/// denial message. Reads `/proc/sys/kernel/osrelease` and trims
/// whitespace. Falls back to `"unknown"` — the `required` field
/// already names what's needed; `detected` is display-only.
fn detect_kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxMode, SandboxOptions, SandboxStdio, SandboxedCommand, new_for_platform};
    use std::path::PathBuf;

    fn realistic_spec() -> SandboxSpec {
        let home = dirs::home_dir().expect("home dir for test");
        let tmp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        SandboxSpec {
            package_dir: home.join(".lpm/store/testpkg@0.1.0"),
            project_dir: home.join("lpm-sandbox-test-project"),
            package_name: "testpkg".into(),
            package_version: "0.1.0".into(),
            store_root: home.join(".lpm/store"),
            home_dir: home,
            tmpdir: tmp,
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn new_rejects_logonly_with_mode_specific_error() {
        // Chunk 4 contract: Linux refuses LogOnly with a
        // ModeNotSupportedOnPlatform error whose remediation names
        // `--unsafe-full-env --no-sandbox` as the workaround. This
        // test runs regardless of kernel support — the mode check
        // happens BEFORE the posture decision so users on old
        // kernels get the same clear message.
        match LandlockSandbox::new(
            realistic_spec(),
            SandboxMode::LogOnly,
            SandboxOptions::default(),
        ) {
            Err(SandboxError::ModeNotSupportedOnPlatform {
                platform,
                mode,
                remediation,
            }) => {
                assert_eq!(platform, "linux");
                assert_eq!(mode, SandboxMode::LogOnly);
                assert!(
                    remediation.contains("--unsafe-full-env --no-sandbox"),
                    "remediation must name the interim workaround: {remediation}"
                );
                assert!(
                    remediation.contains("macOS"),
                    "remediation should mention --sandbox-log is available on macOS"
                );
            }
            Ok(_) => panic!("LogOnly on Linux must be rejected by LandlockSandbox::new"),
            Err(other) => panic!("expected ModeNotSupportedOnPlatform, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_disabled_mode_defensively() {
        // Symmetric with the macOS backend guard. Factory should
        // never route Disabled here; if it does, bail with a clear
        // error instead of silently installing an unnecessary
        // landlock ruleset.
        match LandlockSandbox::new(
            realistic_spec(),
            SandboxMode::Disabled,
            SandboxOptions::default(),
        ) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("Disabled"));
                assert!(reason.contains("NoopSandbox"));
            }
            Ok(_) => panic!("Disabled mode must be rejected by LandlockSandbox::new"),
            Err(other) => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn new_default_options_returns_default_posture() {
        // Phase 46.1 rework (2026-05-11): default options give the
        // relaxed default — V1 baseline, no AccessNet rules. The
        // kernel-version probe still runs (V1 floor) so this test
        // can fail with `KernelTooOld { required: "5.13" }` only on
        // hosts where landlock is entirely disabled.
        match LandlockSandbox::new(
            realistic_spec(),
            SandboxMode::Enforce,
            SandboxOptions::default(),
        ) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
                assert_eq!(sb.posture(), SandboxPosture::Default);
            }
            Err(SandboxError::KernelTooOld { required, .. }) => {
                // Landlock LSM disabled entirely; V1 probe failed.
                assert_eq!(required, MIN_KERNEL_VERSION_FALLBACK);
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn new_strict_either_succeeds_or_surfaces_kernel_too_old() {
        // Phase 46.1 strict path: `deny_outbound_network = true`
        // engages V4 with AccessNet rules. On a host at or above
        // kernel 6.7, construction succeeds with `Strict` posture.
        // On a host below 6.7 (and `allow_degraded = false`), the
        // backend surfaces `KernelTooOld { required: "6.7" }` with
        // a remediation block naming the four named recourses.
        let options = SandboxOptions {
            deny_outbound_network: true,
            ..SandboxOptions::default()
        };
        match LandlockSandbox::new(realistic_spec(), SandboxMode::Enforce, options) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
                assert_eq!(sb.posture(), SandboxPosture::Strict);
            }
            Err(SandboxError::KernelTooOld {
                detected,
                required,
                remediation,
            }) => {
                assert_eq!(required, MIN_KERNEL_VERSION_STRICT);
                assert!(!detected.is_empty());
                assert!(
                    remediation.contains("--unsafe-full-env --no-sandbox"),
                    "remediation must name the escape hatch: {remediation}"
                );
                assert!(
                    remediation.contains("allow-degraded"),
                    "remediation must name the degraded-posture opt-in: {remediation}"
                );
                assert!(
                    remediation.contains("trustedDependencies"),
                    "remediation must name the per-package trust escape: {remediation}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// Phase 46.1: on a Linux host below the 6.7 floor AND with
    /// strict requested, the `allow_degraded = true` opt-in must
    /// produce a V1 (filesystem-only) sandbox with
    /// [`SandboxPosture::Degraded`]. On a host at or above 6.7 the
    /// opt-in is a no-op — the backend still returns Strict.
    #[test]
    fn new_strict_with_allow_degraded_returns_degraded_on_old_kernels_strict_on_new() {
        let options = SandboxOptions {
            deny_outbound_network: true,
            allow_degraded: true,
        };
        match LandlockSandbox::new(realistic_spec(), SandboxMode::Enforce, options) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
                match sb.posture() {
                    SandboxPosture::Strict => {
                        // CI runner at 6.7+ — opt-in is a no-op.
                    }
                    SandboxPosture::Degraded {
                        kernel,
                        abi,
                        missing,
                    } => {
                        assert!(!kernel.is_empty());
                        assert_eq!(abi, "v1");
                        assert_eq!(missing, "network-containment");
                    }
                    other => panic!("unexpected posture from landlock backend: {other:?}"),
                }
            }
            Err(SandboxError::KernelTooOld { required, .. }) => {
                // V1 fallback probe also failed — landlock LSM
                // disabled entirely. Error names the 5.13 floor.
                assert_eq!(required, MIN_KERNEL_VERSION_FALLBACK);
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn detect_kernel_version_returns_nonempty_on_linux() {
        let v = detect_kernel_version();
        assert!(!v.is_empty());
    }

    #[test]
    fn build_parent_side_ruleset_tolerates_missing_optional_paths() {
        // The rules include `/tmp/nonexistent-blahblahblah-extras`
        // (via extra_write_dirs) which must be SKIPPED rather than
        // causing the whole ruleset build to fail. Regression guard
        // for the AS-safety rewrite: the skip logic lives parent-side
        // and must stay there.
        let mut spec = realistic_spec();
        spec.extra_write_dirs
            .push(PathBuf::from("/tmp/lpm-sandbox-chunk3-nonexistent-path"));
        // If the kernel doesn't have landlock at the strict V4 ABI,
        // construction via the LandlockSandbox::new path would route
        // through `decide_posture` + the probe layer first. The
        // `build_parent_side_ruleset` test below exercises the
        // post-decision rule-build path against both postures so we
        // cover the Strict-V4 + network-handler shape AND the
        // Degraded-V1 filesystem-only shape regardless of host
        // kernel availability.
        for posture in [
            BackendPosture::Strict,
            BackendPosture::Degraded {
                detected_kernel: "5.15.0-test".to_string(),
            },
        ] {
            match build_parent_side_ruleset(&spec, &posture) {
                Ok(_) => {} // ruleset built, missing extra was skipped
                Err(e) => {
                    // Only acceptable error: the kernel doesn't support
                    // landlock at this ABI, which presents as a
                    // handle_access / create() failure. Any other
                    // error is a regression.
                    let msg = format!("{e}");
                    assert!(
                        msg.contains("create")
                            || msg.contains("handle_access")
                            || msg.contains("HandleAccesses"),
                        "unexpected build_parent_side_ruleset error for posture {posture:?}: {msg}",
                    );
                }
            }
        }
    }

    #[test]
    fn spawns_a_trivial_benign_command_under_enforce() {
        let sb = match new_for_platform(realistic_spec(), SandboxMode::Enforce) {
            Ok(sb) => sb,
            Err(SandboxError::KernelTooOld { .. }) => return,
            Err(e) => panic!("factory failed: {e:?}"),
        };
        let cmd = SandboxedCommand::new("/usr/bin/true").envs_cleared([("PATH", "/usr/bin:/bin")]);
        let mut child = sb.spawn(cmd).expect("spawn under enforce");
        let status = child.wait().expect("wait");
        assert!(status.success(), "/usr/bin/true under landlock must exit 0");
    }

    #[test]
    fn enforces_deny_on_read_outside_allow_list() {
        // Forbidden target MUST live at a path no sandbox rule
        // covers. `tempfile::tempdir()` on Linux defaults under
        // `/tmp/.tmpXXX/`, which IS in the allow list (the sandbox
        // deliberately permits `/tmp` by design, see compat_greens'
        // `tmp_scratch_write_shape_succeeds`). Using `/tmp`-rooted
        // probes here would test the sandbox's CORRECT /tmp
        // permission rather than its deny-default — the
        // 2026-04-23 Linux CI surfaced exactly this false-failure.
        // Use `/var/tmp/lpm-probe-<pid>/` instead: `/var/tmp` is a
        // real POSIX scratch directory (persistent across reboots,
        // always writable by the test user) that is NOT in any
        // sandbox rule, and is guaranteed disjoint from the
        // tempfile default root.
        let probe_dir = PathBuf::from("/var/tmp")
            .join(format!("lpm-sandbox-read-probe-{}", std::process::id()));
        std::fs::create_dir_all(&probe_dir).unwrap();
        let secret = probe_dir.join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();
        let sb = match new_for_platform(realistic_spec(), SandboxMode::Enforce) {
            Ok(sb) => sb,
            Err(SandboxError::KernelTooOld { .. }) => {
                let _ = std::fs::remove_dir_all(&probe_dir);
                return;
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&probe_dir);
                panic!("factory failed: {e:?}");
            }
        };

        let mut cmd = SandboxedCommand::new("/bin/cat")
            .arg(&secret)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        let _ = std::fs::remove_dir_all(&probe_dir);
        assert!(
            !status.success(),
            "landlock must deny reading an out-of-list path — status {status:?}"
        );
    }

    #[test]
    fn allows_write_into_package_dir_under_enforce() {
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        let home = dirs::home_dir().expect("home");

        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = match new_for_platform(spec, SandboxMode::Enforce) {
            Ok(sb) => sb,
            Err(SandboxError::KernelTooOld { .. }) => return,
            Err(e) => panic!("factory failed: {e:?}"),
        };

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg("echo hi > marker")
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "write into package_dir under landlock must succeed, got {status:?}"
        );
        assert!(pkg_dir.join("marker").exists());
    }

    #[test]
    fn denies_write_outside_allow_list_under_enforce() {
        let td = tempfile::tempdir().unwrap();
        let pkg_dir = td.path().join("store").join("pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let project_dir = td.path().join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        // `forbidden` MUST live at a path no sandbox rule covers.
        // `td` is under `/tmp/.tmpXXX/` on Linux; `/tmp` is in the
        // RW allow list by design, so a `td`-rooted target would
        // be correctly PERMITTED and this test would false-fail.
        // Use `/var/tmp/...` — a real POSIX scratch dir not under
        // any rule — to exercise actual deny-default enforcement.
        let forbidden = PathBuf::from("/var/tmp").join(format!(
            "lpm-sandbox-write-probe-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&forbidden); // ensure pristine
        let home = dirs::home_dir().expect("home");

        let spec = SandboxSpec {
            package_dir: pkg_dir.clone(),
            project_dir,
            package_name: "pkg".into(),
            package_version: "1.0.0".into(),
            store_root: td.path().join("store"),
            home_dir: home,
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        };
        let sb = match new_for_platform(spec, SandboxMode::Enforce) {
            Ok(sb) => sb,
            Err(SandboxError::KernelTooOld { .. }) => return,
            Err(e) => panic!("factory failed: {e:?}"),
        };

        let mut cmd = SandboxedCommand::new("/bin/sh")
            .arg("-c")
            .arg(format!("echo leak > {}", forbidden.display()))
            .current_dir(&pkg_dir)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
        assert!(
            !status.success(),
            "landlock must deny writes outside the allow list — status {status:?}"
        );
        assert!(
            !forbidden.exists(),
            "sandbox escape: forbidden file was created"
        );
    }
}
