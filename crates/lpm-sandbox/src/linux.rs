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
//! [`LandlockSandbox::new`] runs in the PARENT and tests whether the
//! kernel supports landlock by building a
//! [`landlock::CompatLevel::HardRequirement`] ruleset at ABI V1
//! (kernel 5.13+). On success the probe is dropped (FD closes); on
//! failure we surface [`SandboxError::KernelTooOld`] —
//! refuse-to-run, symmetric with the Windows path per the Chunk 1
//! signoff. The user's interim option is
//! `--unsafe-full-env --no-sandbox`.
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
use crate::{Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxedCommand};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus,
};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

/// Minimum kernel version this backend targets. The crate's
/// [`ABI::V1`] maps to this release; lower kernels cause the
/// hard-requirement probe in [`LandlockSandbox::new`] to error,
/// which we surface as [`SandboxError::KernelTooOld`].
const MIN_KERNEL_VERSION: &str = "5.13";

/// Landlock ABI version we program against. Pinned to V1 so the
/// rule description + enforcement behavior is stable across distros
/// — newer ABIs add capabilities (TruncateAllowed in V2, Refer in
/// V3, network in V4+) that Phase 46 P5 doesn't use. Future work can
/// bump this in the same module without changing the call site.
const TARGET_ABI: ABI = ABI::V1;

pub(crate) struct LandlockSandbox {
    spec: SandboxSpec,
    mode: SandboxMode,
}

impl LandlockSandbox {
    pub(crate) fn new(spec: SandboxSpec, mode: SandboxMode) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => {
                probe_kernel_support()?;
            }
            // Chunk 4: landlock has no native observe-only primitive
            // (RulesetStatus::NotEnforced / PartiallyEnforced /
            // FullyEnforced + CompatLevel::BestEffort don't model
            // "allow but log"). Per the Chunk 4 plan signoff, we
            // reject LogOnly honestly rather than invent a pseudo-
            // mode that would pretend to observe while silently
            // doing nothing.
            SandboxMode::LogOnly => {
                return Err(SandboxError::ModeNotSupportedOnPlatform {
                    platform: "linux".to_string(),
                    mode: SandboxMode::LogOnly,
                    remediation: "landlock has no native observe-only primitive in \
                         Phase 46 P5. To debug a sandbox false-positive, re-run \
                         with --unsafe-full-env --no-sandbox. `--sandbox-log` \
                         remains available on macOS."
                        .to_string(),
                });
            }
            // Disabled never reaches this backend — factory routes
            // it to NoopSandbox. Defensive error symmetric with
            // the macOS backend's guard.
            SandboxMode::Disabled => {
                return Err(SandboxError::InvalidSpec {
                    reason: "SandboxMode::Disabled reached LandlockSandbox — should \
                             have been routed to NoopSandbox by the factory"
                        .to_string(),
                });
            }
        }
        Ok(Self { spec, mode })
    }
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
        let ruleset = build_parent_side_ruleset(&self.spec).map_err(|e| {
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
}

/// Parent-side kernel probe. Builds a HardRequirement ruleset at
/// [`TARGET_ABI`]; any failure is treated as "this kernel doesn't
/// support landlock" regardless of the specific error variant.
/// Treating all probe errors as KernelTooOld keeps the denial
/// message pointed at the same remediation — upgrade the kernel or
/// use `--unsafe-full-env --no-sandbox`.
fn probe_kernel_support() -> Result<(), SandboxError> {
    let build = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .and_then(|r| r.create());
    match build {
        Ok(_ruleset_created) => Ok(()),
        Err(_) => Err(SandboxError::KernelTooOld {
            detected: detect_kernel_version(),
            required: MIN_KERNEL_VERSION.to_string(),
            remediation: "upgrade to Linux 5.13+ with landlock enabled, or re-run with \
                 --unsafe-full-env --no-sandbox to execute scripts without \
                 containment. `script-policy = deny` is the always-safe default."
                .to_string(),
        }),
    }
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
fn build_parent_side_ruleset(spec: &SandboxSpec) -> Result<RulesetCreated, RulesetError> {
    let rw = AccessFs::from_all(TARGET_ABI);
    let read = AccessFs::from_read(TARGET_ABI);
    let mut ruleset = Ruleset::default().handle_access(rw)?.create()?;
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
    use crate::{SandboxMode, SandboxStdio, SandboxedCommand, new_for_platform};
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
        // happens BEFORE probe_kernel_support so users on old
        // kernels get the same clear message.
        match LandlockSandbox::new(realistic_spec(), SandboxMode::LogOnly) {
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
        match LandlockSandbox::new(realistic_spec(), SandboxMode::Disabled) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("Disabled"));
                assert!(reason.contains("NoopSandbox"));
            }
            Ok(_) => panic!("Disabled mode must be rejected by LandlockSandbox::new"),
            Err(other) => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn new_either_succeeds_or_surfaces_kernel_too_old() {
        match LandlockSandbox::new(realistic_spec(), SandboxMode::Enforce) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
            }
            Err(SandboxError::KernelTooOld {
                detected,
                required,
                remediation,
            }) => {
                assert_eq!(required, MIN_KERNEL_VERSION);
                assert!(!detected.is_empty());
                assert!(
                    remediation.contains("--unsafe-full-env --no-sandbox"),
                    "remediation must name the escape hatch: {remediation}"
                );
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
        // If the kernel doesn't have landlock, probe_kernel_support
        // handles that — but build_parent_side_ruleset is independent
        // of that probe and can still be exercised.
        match build_parent_side_ruleset(&spec) {
            Ok(_) => {} // ruleset built, missing extra was skipped
            Err(e) => {
                // Only acceptable error: the kernel doesn't support
                // landlock at all, which presents as a create()
                // failure. Any other error is a regression.
                let msg = format!("{e}");
                assert!(
                    msg.contains("create")
                        || msg.contains("handle_access")
                        || msg.contains("HandleAccesses"),
                    "unexpected build_parent_side_ruleset error: {msg}"
                );
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
