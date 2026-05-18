//! Linux landlock backend: restricts the child process's filesystem
//! access via a ruleset installed through the landlock LSM.
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
//! - [`Option::take`] to extract the captured `RulesetCreated`
//!   and `seccompiler::BpfProgram`.
//! - [`seccompiler::apply_filter`] — audited call path: two
//!   direct syscalls (`prctl(PR_SET_NO_NEW_PRIVS, 1, …)` to
//!   satisfy the unprivileged-seccomp precondition, then
//!   `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, …)`) plus
//!   a stack-allocated `sock_fprog` pointing at the BpfProgram's
//!   `Vec<sock_filter>` backing buffer. No heap allocation in
//!   the syscall path; the kernel `copy_from_user`s the filter
//!   so we don't need to keep ownership beyond the call.
//! - [`RulesetCreated::restrict_self`] — audited call path: two
//!   direct syscalls (`prctl(PR_SET_NO_NEW_PRIVS)` and
//!   `landlock_restrict_self`) plus enum/integer field shuffles.
//!   No heap allocation, no lock acquisition.
//! - On failure, [`write_stderr_as_safe`] — raw `write(2)` to fd 2,
//!   bypassing `std::io::Stderr::lock()` which is NOT safe here.
//!   Prefixes are per-layer: `seccomp:` for the seccomp
//!   filter install, `landlock:` for the V4 ruleset install,
//!   `lpm-sandbox:` for cross-layer / dispatch failures.
//! - [`std::io::Error::from_raw_os_error`] to propagate errno —
//!   wraps an integer, does not allocate (contrast with
//!   `io::Error::new(kind, &str)` which goes through `Box<Custom>`
//!   and IS allocating).
//!
//! Crucially we do NOT `eprintln!`, `format!`, `Box::new`, or call
//! any trait method whose implementation is opaque from the
//! child's perspective. The landlock library's `restrict_self`
//! and seccompiler's `apply_filter` are the only exceptions,
//! and we've audited both source paths.
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
//!   outbound TCP. The pre_exec closure ALSO installs the
//!   seccomp-bpf filter that denies direct
//!   `socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)`,
//!   `socket(AF_PACKET, …)`, and `socket(AF_NETLINK, …)` — closing
//!   the UDP / raw / L2 / routing-probe gap landlock V4 leaves
//!   open. **AF_UNIX is intentionally allowed** (legitimate IPC
//!   needs: node-ipc, husky hooks, npm daemon comms); resolver-
//!   mediated DNS remains host-dependent (NSS may route through
//!   AF_UNIX or TCP fallback). On V4 probe failure the kernel
//!   reported ≥ 6.7 but landlock itself isn't reachable (LSM
//!   disabled, etc.) — we surface [`SandboxError::KernelTooOld`]
//!   with `required: "6.7"`.
//!
//!   **Accepted-posture trade-off (H14):** the AF_UNIX carve-out is
//!   asymmetric with macOS strict (Seatbelt denies every socket
//!   family). systemd-resolved over the UNIX socket continues to
//!   resolve from inside the sandbox, and `$SSH_AUTH_SOCK` —
//!   typically under `/tmp` which is in the read+write allow-list —
//!   remains reachable. Narrowing to "AF_UNIX only for fd-passing
//!   inherited from parent" would need a per-syscall socketpair gate
//!   that landlock+seccomp don't currently offer; the runtime defense
//!   is the network-containment + project-output-containment posture
//!   limiting what an in-sandbox AF_UNIX consumer can exfiltrate. A
//!   later mitigation handle is `[sandbox] unix-socket-denylist`
//!   listing well-known agent sockets, but it requires per-distro
//!   path inventory and isn't shipped today.
//! - **Degraded** (kernel < 6.7 AND `allow_degraded = true`): probe
//!   landlock at ABI V1 (filesystem-only). The construction-side
//!   succeeds when V1 is reachable; the install pipeline emits the
//!   per-install structured stderr warning via
//!   [`crate::SandboxPosture::degraded_warning_line`].
//! - **Refuse** (kernel < 6.7 AND `allow_degraded = false`, the
//!   strict default): surface `SandboxError::KernelTooOld` with
//!   `required: "6.7"` before the script ever spawns. Refusal is
//!   symmetric with the Windows path. The user's interim options are
//!   `--no-sandbox`, adding the package to `trustedDependencies`, or
//!   upgrading the kernel.
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

/// minimum kernel version the strict posture targets.
/// V4 landed in 6.7 (January 2024) and is the first ABI that
/// carries network access rules; below this floor the backend has
/// no kernel-level mechanism to deny outbound network, so the
/// Strict posture refuses and routes the user to the named
/// remediations (degraded opt-in, `--no-sandbox`, drop back to
/// the default posture via `lpm config sandbox --set default`,
/// or kernel upgrade).
const MIN_KERNEL_VERSION_STRICT: &str = REQUIRED_KERNEL_FOR_STRICT;

/// fallback floor: V1 landed in 5.13. Used by the
/// degraded posture's V1 probe to give an honest error if even V1
/// is unreachable (landlock LSM disabled entirely).
const MIN_KERNEL_VERSION_FALLBACK: &str = "5.13";

/// Strict ABI: V4 (kernel 6.7+). Adds network access
/// rules on top of V1's filesystem set; an empty
/// `AccessNet::from_all(V4)` handler with no `NetPort` allows
/// yields default-deny for both `BindTcp` and `ConnectTcp`.
const TARGET_ABI_STRICT: ABI = ABI::V4;

/// Degraded ABI: V1 (kernel 5.13+). Filesystem-only — no network
/// containment. Used only when the user has set
/// `[sandbox] allow-degraded = true` AND the detected kernel is
/// below the V4 floor.
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
    /// default default). FS-only, no network containment. Added so
    /// the doctor / posture surfaces can distinguish "user chose
    /// default" from "user chose strict but kernel forced fallback"
    /// (`Degraded`).
    Default,
    /// V4 with both FS rules and network handling installed. The
    /// full strict contract. Reached when the user opts
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
    /// Naming: "enforces TCP" would be more precise — landlock V4
    /// doesn't cover UDP / raw / AF_PACKET / AF_NETLINK. The
    /// non-TCP coverage on Linux is layered on by the sibling
    /// predicate [`Self::installs_seccomp_filter`], which gates
    /// the seccomp-bpf install in the pre_exec
    /// closure. The two predicates always agree (both `true` for
    /// `Strict`, `false` otherwise) but live separately so the
    /// landlock-side ruleset builder
    /// ([`build_parent_side_ruleset`]) and the seccomp-side
    /// install can each gate on their own concern.
    fn enforces_network(&self) -> bool {
        matches!(self, BackendPosture::Strict)
    }

    /// `true` iff this posture installs the seccomp-bpf
    /// seccomp-bpf `socket(2)` deny filter on top of the
    /// landlock ruleset. Covers direct UDP (AF_INET/AF_INET6 +
    /// SOCK_DGRAM), raw sockets, AF_PACKET, and AF_NETLINK —
    /// the families landlock V4 doesn't reach.
    ///
    /// Only `Strict` returns `true`. `Default` and `Degraded`
    /// explicitly skip the seccomp layer: `Default` is the
    /// relaxed posture by design, and `Degraded` only reaches
    /// V1 (filesystem-only) — adding seccomp without landlock
    /// V4 would create a Linux strict-posture variant the
    /// upstream contract doesn't promise.
    ///
    /// The pre_exec closure consults this predicate to decide
    /// whether to call [`seccompiler::apply_filter`] before
    /// landlock's `restrict_self`.
    fn installs_seccomp_filter(&self) -> bool {
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
                    // Strict path — the locked contract.
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
                    // Default path — rework.
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
            // Landlock has no native observe-only primitive
            // (RulesetStatus::NotEnforced / PartiallyEnforced /
            // FullyEnforced + CompatLevel::BestEffort don't model
            // "allow but log"), so we reject LogOnly honestly rather
            // than invent a pseudo-mode that would pretend to observe
            // while silently doing nothing.
            SandboxMode::LogOnly => Err(SandboxError::ModeNotSupportedOnPlatform {
                platform: "linux".to_string(),
                mode: SandboxMode::LogOnly,
                remediation: "landlock has no native observe-only primitive. \
                         To debug a sandbox false-positive, re-run \
                         with --no-sandbox. `--sandbox-log` remains available on \
                         macOS."
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
///
/// Option (3) names `--no-sandbox` as a single flag. A fifth shortcut
/// is also available: drop back to the default posture via
/// `lpm config sandbox --set default` — for many users this is the
/// right answer because they didn't realise strict was the more
/// restrictive opt-in.
fn strict_remediation() -> String {
    "remediation options: (1) set `[sandbox] allow-degraded = true` in \
     `~/.lpm/config.toml` or `./lpm.toml` to fall back to landlock V1 \
     (filesystem-only — NO outbound TCP denial, NO UDP denial); \
     (2) add the package to `package.json > lpm > trustedDependencies` \
     to skip the sandbox for this dependency; (3) re-run with \
     `--no-sandbox` to skip the sandbox wholesale for one command; \
     (4) upgrade the host kernel to 6.7+ to get the strict posture \
     (filesystem-write containment + outbound TCP denial via landlock \
     V4 + direct UDP / raw / AF_PACKET / AF_NETLINK denial via the \
     seccomp-bpf layer; AF_UNIX intentionally allowed); \
     (5) run `lpm config sandbox --set default` to drop back to the \
     recommended default posture (filesystem + env containment, \
     network allowed)."
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

        // compile the seccomp socket(2) deny filter
        // parent-side. Like the landlock ruleset, all the
        // allocating work (building the BTreeMap of rules,
        // emitting BPF instructions into a Vec<sock_filter>)
        // happens here on the parent thread before fork; the
        // child only issues the AS-safe `prctl(PR_SET_SECCOMP)`
        // syscall via `seccompiler::apply_filter`.
        //
        // The filter is `None` when the posture doesn't install
        // it (Default / Degraded). On compile failure we surface
        // `ProfileRenderFailed` matching the landlock-side error
        // path; the build is deterministic over a static rule
        // set, so this branch should never fire in practice.
        let seccomp_program = if self.posture.installs_seccomp_filter() {
            Some(crate::seccomp::build_socket_deny_filter().map_err(|e| {
                SandboxError::ProfileRenderFailed {
                    reason: format!("seccomp filter build failed: {e}"),
                }
            })?)
        } else {
            None
        };

        // Secret-file overlay: parent-side enumeration of secret
        // paths under project_dir + pre-formatted uid_map bytes for
        // the child's user-namespace setup. `None` when the project
        // has no secrets to overlay (clean project, or every match
        // is in the user's `secret_read_allow` opt-in list); the
        // pre_exec closure skips the unshare dance entirely in
        // that case. Failure to enumerate isn't fatal — overlay
        // is best-effort containment, not a security floor.
        let overlay_spec = crate::linux_secret_overlay::SecretOverlaySpec::build(
            &self.spec.project_dir,
            &self.spec.secret_read_allow,
        );
        if let Some(ref s) = overlay_spec {
            tracing::debug!(
                count = s.paths.len(),
                "secret overlay: enumerated {} project secret files for bind-mount",
                s.paths.len()
            );
        }

        // Option wrapper lets a FnMut closure consume each layer's
        // input once (via `take`) while satisfying the FnMut bound
        // `Command::pre_exec` requires. In practice the kernel only
        // invokes pre_exec once per spawn; the `take().ok_or(...)`
        // path below catches the hypothetical double-invocation.
        let mut ruleset_opt = Some(ruleset);
        let mut seccomp_opt = seccomp_program;
        let mut overlay_opt = overlay_spec;
        // Capture strict-posture flag before the move-closure so the
        // child can fail-closed on `RulesetStatus::PartiallyEnforced` —
        // an atypical kernel build (custom V4 LSM that exposes the V4
        // ABI but only partially wires BindTcp/ConnectTcp) would
        // otherwise silently degrade the TCP-deny claim to a no-op.
        // Default/Degraded postures accept partial enforcement: they
        // only depend on V1 filesystem rules.
        let is_strict_posture = matches!(self.posture, BackendPosture::Strict);

        // SAFETY: This closure runs post-fork, pre-exec in the
        // child. The body is AS-safe: no heap allocation, no lock
        // acquisition, no `format!` / `eprintln!`. All possible
        // operations inside are either (a) direct syscalls via
        // `libc`, `landlock`, or `seccompiler`, (b) integer /
        // enum manipulation, or (c) `io::Error::from_raw_os_error`
        // which wraps an integer without allocating.
        //
        // Captured-state Drop audit (load-bearing — both captures
        // need explicit handling, neither is trivially AS-safe):
        //   - `ruleset_opt` holds an `Option<RulesetCreated>`. We
        //     `take()` it inside the closure; `restrict_self`
        //     consumes the `RulesetCreated` by value, so its
        //     `Drop` (which closes the inherited FD via `close(2)`,
        //     AS-safe) runs INSIDE `restrict_self`'s call frame —
        //     not at our closure's scope exit. The post-`take()`
        //     `None` left in `ruleset_opt` drops trivially.
        //   - `seccomp_opt` holds an `Option<BpfProgram>` where
        //     `BpfProgram = Vec<sock_filter>`. Vec's `Drop` frees
        //     its heap allocation — `free()` is NOT AS-safe in
        //     a multithreaded fork-child (it can deadlock against
        //     an allocator mutex that another thread held when
        //     `fork` fired). We `take()` the program out of the
        //     Option, then immediately wrap it in `ManuallyDrop`
        //     so its inner Vec is NEVER freed in the child. See
        //     the inline rationale at the seccomp-install site
        //     below. The post-`take()` `None` in `seccomp_opt`
        //     drops trivially.
        //
        // install order:
        //   1. seccompiler::apply_filter — installs the socket(2)
        //      deny filter. apply_filter ITSELF issues
        //      prctl(PR_SET_NO_NEW_PRIVS, 1, …) first (required
        //      for unprivileged seccomp install), then the
        //      seccomp(2) syscall. Both are direct, AS-safe.
        //   2. landlock_ruleset.restrict_self — the canonical
        //      lockdown call (also redundantly asserts
        //      NO_NEW_PRIVS, a no-op since step 1 set it).
        // Both layers fail-closed: any failure returns EPERM
        // from the closure, the kernel skips execve, the
        // lifecycle script never runs.
        unsafe {
            command.pre_exec(move || {
                // ── Layer 0: secret-file bind-mount overlay ──
                // Best-effort: enter a user+mount namespace and
                // bind-mount /dev/null over every enumerated
                // project secret file. AS-safe by construction (no
                // alloc, direct syscalls only). Failure to unshare
                // (hardened distro, kernel sysctl, AppArmor) silently
                // no-ops — the macOS-equivalent containment is what
                // we strive for; Linux falls back to "same as no
                // overlay", which is the baseline before this layer.
                //
                // ManuallyDrop wrap mirrors the seccomp Vec handling
                // below: `SecretOverlaySpec` owns a `Vec<CString>` +
                // two `Vec<u8>` maps; Drop would call free() many
                // times in the child, which is NOT AS-safe. The
                // wrap suppresses Drop; the child either execve's
                // (full address-space replace) or returns an Err
                // before that (no unwind) — either way the
                // suppressed allocation is harmless.
                if let Some(spec) = overlay_opt.take() {
                    let spec = std::mem::ManuallyDrop::new(spec);
                    // SAFETY: nested in the outer `unsafe` of the
                    // pre_exec closure; clippy correctly flags an
                    // explicit `unsafe { ... }` here as redundant.
                    crate::linux_secret_overlay::apply_secret_overlay_in_child(&spec);
                }

                // ── Layer 1: seccomp ──
                // Take the BpfProgram out of the Option, then
                // wrap it in `ManuallyDrop` so its inner
                // `Vec<sock_filter>` is NOT freed in the child.
                //
                // Why ManuallyDrop matters: `BpfProgram` is a
                // `Vec<sock_filter>`; on Drop, the Vec frees its
                // heap allocation — and `free()` is NOT AS-safe.
                // In a multithreaded parent, another thread may
                // have held the allocator mutex when `fork`
                // fired; calling free() in the child would
                // deadlock against that mutex's now-orphan
                // owner. `apply_filter` already `copy_from_user`s
                // the program into the kernel, so we don't need
                // userspace ownership after the call. The child
                // either execve()s (full address-space replace —
                // leak harmless) or _exits via the error path
                // (no unwind — leak harmless).
                //
                // ManuallyDrop suppresses both Ok and Err paths
                // uniformly: even if `apply_filter` returned Err
                // and we returned EPERM below, the closure scope
                // exit would otherwise have run `program.drop()`.
                if let Some(program) = seccomp_opt.take() {
                    let program = std::mem::ManuallyDrop::new(program);
                    // `Err(_e)` discard is deliberate:
                    // seccompiler::Error's Display body allocates
                    // (format!-style), which is NOT AS-safe in
                    // the child. The `seccomp:` prefix steers
                    // users to parent-side tracing for the
                    // underlying errno (typically EACCES if
                    // NO_NEW_PRIVS failed, ENOSYS on kernels
                    // without CONFIG_SECCOMP_FILTER). Use `match`
                    // rather than `if let Err(..)` to avoid
                    // clippy's `collapsible_if` flagging the
                    // outer + inner condition pair.
                    match seccompiler::apply_filter(&program) {
                        Ok(()) => {}
                        Err(_) => {
                            write_stderr_as_safe(b"seccomp: apply_filter failed\n");
                            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                        }
                    }
                }

                // ── Layer 2: landlock (the strict posture) ──
                let rs = match ruleset_opt.take() {
                    Some(r) => r,
                    None => {
                        write_stderr_as_safe(
                            b"lpm-sandbox: pre_exec invoked without landlock ruleset\n",
                        );
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
                    Ok(status)
                        if is_strict_posture
                            && !matches!(status.ruleset, RulesetStatus::FullyEnforced) =>
                    {
                        // Strict posture promises TCP-egress denial.
                        // A `PartiallyEnforced` status means the kernel
                        // accepted some but not all rules — under
                        // strict, we can't tell which, so fail-closed
                        // rather than ship the user a sandbox that
                        // pretends to deny network while silently
                        // letting it through.
                        write_stderr_as_safe(
                            b"landlock: PartiallyEnforced under strict posture; refusing\n",
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
            reason: format!("lpm-sandbox spawn failed: {e}"),
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
/// the escape hatch remains `--no-sandbox` if the user needs the
/// missing rule's access.
///
/// when `posture` is [`BackendPosture::Strict`], the
/// ruleset also declares `handle_access(AccessNet::from_all(V4))`
/// (BindTcp + ConnectTcp) but installs no `NetPort` allow rules —
/// landlock then default-denies every TCP bind / connect, which is
/// the kernel-level outbound network denial ships.
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
            secret_read_allow: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn new_rejects_logonly_with_mode_specific_error() {
        // Linux refuses LogOnly with a ModeNotSupportedOnPlatform
        // error whose remediation names `--no-sandbox` as the
        // workaround. This test runs regardless of kernel support —
        // the mode check happens BEFORE the posture decision so users
        // on old kernels get the same clear message.
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
                    remediation.contains("--no-sandbox"),
                    "remediation must name the interim workaround: {remediation}"
                );
                assert!(
                    !remediation.contains("--unsafe-full-env"),
                    "legacy partner flag must be gone: {remediation}",
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
        // default options give the
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
        // strict path: `deny_outbound_network = true`
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
                // single `--no-sandbox` flag.
                assert!(
                    remediation.contains("--no-sandbox"),
                    "remediation must name the escape hatch: {remediation}"
                );
                assert!(
                    !remediation.contains("--unsafe-full-env"),
                    "legacy partner flag must be gone: {remediation}",
                );
                assert!(
                    remediation.contains("allow-degraded"),
                    "remediation must name the degraded-posture opt-in: {remediation}"
                );
                assert!(
                    remediation.contains("trustedDependencies"),
                    "remediation must name the per-package trust escape: {remediation}"
                );
                // the wizard shortcut also lives
                // in the remediation now.
                assert!(
                    remediation.contains("lpm config sandbox"),
                    "remediation must name the wizard shortcut: {remediation}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// on a Linux host below the 6.7 floor AND with
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
        // Linux CI surfaced exactly this false-failure.
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
            secret_read_allow: Vec::new(),
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
            secret_read_allow: Vec::new(),
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
