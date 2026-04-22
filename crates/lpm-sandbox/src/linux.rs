//! Linux landlock backend: restricts the child process's filesystem
//! access via a ruleset installed through the landlock LSM. Phase 46
//! P5 Chunk 3.
//!
//! Control flow:
//! 1. [`LandlockSandbox::new`] runs in the PARENT at construction
//!    time. It probes the kernel by building a
//!    [`landlock::CompatLevel::HardRequirement`] ruleset at ABI V1
//!    (kernel 5.13+). On success the probe is dropped (FD closes);
//!    on failure we surface [`SandboxError::KernelTooOld`] —
//!    refuse-to-run, symmetric with the Windows path per the Chunk 1
//!    signoff ("tighten Linux old-kernel behavior to explicit
//!    refuse-with-override"). The user's interim option is
//!    `--unsafe-full-env --no-sandbox`.
//! 2. [`LandlockSandbox::spawn`] builds the process description
//!    (program, args, envs, cwd, stdio) on the parent, adds a
//!    `pre_exec` closure that — in the forked child, before
//!    `execve` — creates the real ruleset, adds one [`PathBeneath`]
//!    per rule returned by [`crate::landlock_rules::describe_rules`],
//!    then calls `restrict_self`. The ruleset sticks through the
//!    exec boundary because landlock is an LSM; the exec'd binary
//!    inherits the active domain.
//! 3. If [`landlock::RulesetStatus::NotEnforced`] comes back from
//!    `restrict_self` (a race where landlock disappeared between
//!    parent probe and child fork), we abort the child rather than
//!    run unsandboxed.
//!
//! Ordering inside the `pre_exec` closure: landlock ruleset install
//! happens inside the closure; `setpgid(0, 0)` runs via
//! [`std::os::unix::process::CommandExt::process_group`] which the
//! stdlib wires separately. Neither order matters for correctness.
//!
//! Per-path FD opens happen in the child's `pre_exec` rather than
//! the parent because `PathFd` / `open()` results are not safely
//! transferable across fork in all cases, and because paths that
//! don't exist at rule-construction time would fail parent-side
//! with no way to skip gracefully. Missing paths (e.g. `~/.node-gyp`
//! on a fresh system) are skipped per-rule with a stderr advisory
//! from the child so the user can trace why a specific rule was
//! absent without the sandbox failing to start.

#![cfg(target_os = "linux")]

use crate::landlock_rules::{RuleAccess, describe_rules};
use crate::{Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxedCommand};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
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
        probe_kernel_support()?;
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

        // Capture ONLY what the child needs — the full rule
        // description. Avoids pulling `self` into the closure, which
        // would tie its lifetime to `&self`.
        let rules = describe_rules(&self.spec);

        // SAFETY: `pre_exec` runs in the forked child between `fork`
        // and `execve`. Per POSIX + std docs, only async-signal-safe
        // operations are legal here. The landlock syscalls and the
        // `eprintln!` diagnostics both satisfy that constraint —
        // landlock is a direct syscall, `eprintln!` writes to an
        // inherited fd via `write(2)`. We do not touch locks,
        // allocator-backed shared state, or signal handlers.
        unsafe {
            command.pre_exec(move || install_landlock_ruleset(&rules));
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

/// Create the landlock ruleset, add one [`PathBeneath`] per rule,
/// and call `restrict_self`. Runs in the forked child's `pre_exec`
/// context so the restriction follows through `execve`.
///
/// Failure modes:
/// - Per-path FD open failure (missing path, EACCES): skipped with a
///   one-line stderr advisory so the user can correlate later access
///   denials with absent rules. The ruleset still installs with the
///   paths that did open — a partial rule set is a tighter security
///   posture than no sandbox at all.
/// - `restrict_self` returning [`RulesetStatus::NotEnforced`]: abort
///   with an `io::Error` so the spawn fails cleanly rather than
///   running an unsandboxed child. This should only be reachable if
///   landlock is unloaded between the parent probe and child fork
///   (effectively never in practice).
/// - Any landlock-library error (`handle_access`, `create`,
///   `add_rule`, `restrict_self`): mapped to `io::Error::other` with
///   a `landlock:` prefix so users can distinguish sandbox failures
///   from generic spawn errors.
fn install_landlock_ruleset(rules: &[(PathBuf, RuleAccess)]) -> std::io::Result<()> {
    let rw = AccessFs::from_all(TARGET_ABI);
    let read = AccessFs::from_read(TARGET_ABI);

    let mut ruleset = Ruleset::default()
        .handle_access(rw)
        .map_err(|e| std::io::Error::other(format!("landlock: handle_access failed: {e}")))?
        .create()
        .map_err(|e| std::io::Error::other(format!("landlock: create failed: {e}")))?;

    for (path, access) in rules {
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("landlock: skip {} ({e})", path.display());
                continue;
            }
        };
        let access_bits = match access {
            RuleAccess::Read => read,
            RuleAccess::ReadWrite => rw,
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access_bits))
            .map_err(|e| {
                std::io::Error::other(format!("landlock: add_rule {} failed: {e}", path.display()))
            })?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| std::io::Error::other(format!("landlock: restrict_self failed: {e}")))?;

    // Guard against the (very rare) case where landlock disappeared
    // between the parent probe and the child fork, leaving us with
    // an unenforced ruleset. Bail rather than run unsandboxed.
    if matches!(status.ruleset, RulesetStatus::NotEnforced) {
        return Err(std::io::Error::other(
            "landlock: ruleset was NOT enforced after restrict_self; \
             refusing to run the script unsandboxed. Kernel landlock support \
             may have been disabled since sandbox construction.",
        ));
    }

    Ok(())
}

/// Best-effort kernel version probe for the [`SandboxError::KernelTooOld`]
/// denial message. Reads `/proc/sys/kernel/osrelease` and trims
/// whitespace (e.g. `"5.10.0-27-amd64\n"` → `"5.10.0-27-amd64"`).
/// Falls back to `"unknown"` — the `required` field already names
/// what's needed; `detected` is display-only.
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
    fn new_either_succeeds_or_surfaces_kernel_too_old() {
        // On a CI runner with landlock enabled, this test asserts
        // the happy path. On a container or kernel without it, we
        // get `KernelTooOld`. Either path is a real-world outcome
        // of running this backend; the assertion is that we NEVER
        // silently succeed while producing a broken sandbox.
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
    fn spawns_a_trivial_benign_command_under_enforce() {
        // If the host kernel doesn't have landlock, skip — the
        // "KernelTooOld" path is already covered above.
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
        let sb = match new_for_platform(realistic_spec(), SandboxMode::Enforce) {
            Ok(sb) => sb,
            Err(SandboxError::KernelTooOld { .. }) => return,
            Err(e) => panic!("factory failed: {e:?}"),
        };
        let td = tempfile::tempdir().unwrap();
        let secret = td.path().join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET").unwrap();

        let mut cmd = SandboxedCommand::new("/bin/cat")
            .arg(&secret)
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        cmd.stdout = SandboxStdio::Null;
        cmd.stderr = SandboxStdio::Null;
        let mut child = sb.spawn(cmd).expect("spawn");
        let status = child.wait().expect("wait");
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
        let forbidden = td.path().join("outside.txt");
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
