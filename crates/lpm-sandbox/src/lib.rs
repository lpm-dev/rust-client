//! Filesystem-scoped sandbox for LPM post-install script execution.
//!
//! Phase 46 P5. This crate owns the execution-time containment machinery;
//! [`lpm-security`](../lpm_security/index.html) stays policy-only.
//!
//! The crate is intentionally narrow. Callers build a [`SandboxedCommand`]
//! (a platform-neutral description of the process they want to run),
//! obtain a [`Sandbox`] from [`new_for_platform`] for a given
//! [`SandboxSpec`] paired with a [`SandboxMode`], then call
//! [`Sandbox::spawn`]. The backend decides how to apply containment:
//! macOS routes the spawn through `sandbox-exec`, and Linux installs a
//! landlock ruleset via `pre_exec` in the forked child.
//!
//! ## Chunk 1 status
//!
//! This is the scaffolding chunk. Only [`NoopSandbox`] (the backend for
//! [`SandboxMode::Disabled`]) is functional. Platform backends return
//! [`SandboxError::ProfileRenderFailed`] from [`Sandbox::spawn`] until
//! Chunks 2 (macOS) and 3 (Linux) wire them up. Windows returns
//! [`SandboxError::UnsupportedPlatform`] now and stays unsupported
//! through Phase 46 per decision D10; Phase 46.1 adds the Job-Objects
//! backend.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
mod seatbelt;

#[cfg(target_os = "linux")]
mod linux;

// Rule description is platform-neutral so macOS CI + developer-host
// test runs exercise it without a Linux kernel. The module is gated
// on `target_os = "linux"` for production builds (where `linux.rs`
// consumes it) and on `test` for any test build (so the rules unit
// tests run on the macOS developer host). Non-Linux production
// builds don't compile this module at all, which matches CLAUDE.md's
// cross-platform hygiene rule.
#[cfg(any(target_os = "linux", test))]
mod landlock_rules;

pub mod config;
pub use config::load_sandbox_write_dirs;

/// Inputs the sandbox backend needs to render its containment profile
/// for a single post-install script invocation.
///
/// All paths are absolute. The sandbox variable interpolation set
/// (`{store}`, `{pkg}`, `{version}`, `{project}`, `{home}`, `{tmpdir}`)
/// maps 1:1 onto the fields below; [`extra_write_dirs`] widens the
/// writable set per `package.json > lpm > scripts > sandboxWriteDirs`.
///
/// [`extra_write_dirs`]: SandboxSpec::extra_write_dirs
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// `{store}/{pkg}@{version}` — the package's own content-addressable
    /// store directory. The primary writable root per §9.3.
    pub package_dir: PathBuf,
    /// Absolute path to the project root (the directory containing
    /// `package.json`). Readable broadly; writable under narrow subpaths
    /// (`node_modules`, `.husky`, `.lpm`).
    pub project_dir: PathBuf,
    /// Package identity for profile interpolation + denial messages.
    /// e.g. `"prisma"` or `"@napi-rs/canvas"`.
    pub package_name: String,
    /// Package version string, e.g. `"5.22.0"`. Paired with
    /// [`package_name`](Self::package_name) for `{pkg}@{version}`.
    pub package_version: String,
    /// The LPM content-addressable store root (`~/.lpm/store`). Readable
    /// broadly so scripts can cross-reference their own hoisted deps.
    pub store_root: PathBuf,
    /// `$HOME`. Used to expand `$HOME/.cache`, `$HOME/.node-gyp`,
    /// `$HOME/.npm` in the §9.3 writable set and `$HOME/.nvm/versions`
    /// in the read set.
    pub home_dir: PathBuf,
    /// `$TMPDIR`. Per-user temp on macOS, typically `/tmp` on Linux.
    /// `/tmp` itself is already in the writable set.
    pub tmpdir: PathBuf,
    /// Extra writable subpaths from `package.json > lpm > scripts >
    /// sandboxWriteDirs`. Loader resolves relative paths against
    /// [`project_dir`](Self::project_dir) before constructing the spec.
    pub extra_write_dirs: Vec<PathBuf>,
}

/// How the sandbox applies containment for a given spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxMode {
    /// Default. OS-level block on any access outside the allow-set.
    /// The only mode that raises the security floor.
    Enforce,
    /// Diagnostic-only. Emits structured trace events for would-be
    /// denials but does not block. **Not authoritative** — never
    /// substitutes for [`Enforce`](Self::Enforce). Intended for
    /// compat debugging via `--sandbox-log`.
    LogOnly,
    /// No containment. Used only by the `--unsafe-full-env
    /// --no-sandbox` escape hatch. Emits a loud CLI banner at the
    /// call site (not this crate's responsibility).
    Disabled,
}

/// How a child's stdio should be wired. Superset subset of
/// [`std::process::Stdio`] variants the sandbox knows how to map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStdio {
    /// Inherit the parent's file descriptor.
    Inherit,
    /// Capture into a pipe the caller can read.
    Piped,
    /// Discard.
    Null,
}

impl From<SandboxStdio> for std::process::Stdio {
    fn from(s: SandboxStdio) -> Self {
        match s {
            SandboxStdio::Inherit => std::process::Stdio::inherit(),
            SandboxStdio::Piped => std::process::Stdio::piped(),
            SandboxStdio::Null => std::process::Stdio::null(),
        }
    }
}

/// Platform-neutral description of a process the sandbox should spawn.
///
/// Sandbox-specific wrapping (e.g. prepending `sandbox-exec -p <profile>`
/// on macOS, installing a `pre_exec` hook on Linux) happens inside the
/// [`Sandbox`] backend at spawn time. Callers never construct a
/// [`std::process::Command`] directly.
#[derive(Debug)]
pub struct SandboxedCommand {
    /// The program to execute, e.g. `"sh"` for lifecycle scripts.
    pub program: OsString,
    /// Arguments to the program, e.g. `["-c", "node install.js"]`.
    pub args: Vec<OsString>,
    /// Explicit environment. [`env_clear`](Self::env_clear) controls
    /// whether this fully replaces the parent env.
    pub envs: Vec<(OsString, OsString)>,
    /// If `true`, the parent's environment is cleared before [`envs`](Self::envs)
    /// is applied. Matches [`std::process::Command::env_clear`].
    pub env_clear: bool,
    /// Working directory for the child. [`None`] inherits the parent's.
    pub current_dir: Option<PathBuf>,
    /// Wiring for the child's stdout.
    pub stdout: SandboxStdio,
    /// Wiring for the child's stderr.
    pub stderr: SandboxStdio,
    /// Wiring for the child's stdin.
    pub stdin: SandboxStdio,
}

impl SandboxedCommand {
    /// Build a minimal command — program + args only. All other fields
    /// default to "inherit / no override" so callers can set only what
    /// they care about.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            env_clear: false,
            current_dir: None,
            stdout: SandboxStdio::Inherit,
            stderr: SandboxStdio::Inherit,
            stdin: SandboxStdio::Inherit,
        }
    }

    /// Append a single argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Replace the environment (setting [`env_clear`](Self::env_clear))
    /// with the given key/value pairs.
    pub fn envs_cleared<K, V, I>(mut self, envs: I) -> Self
    where
        K: Into<OsString>,
        V: Into<OsString>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.env_clear = true;
        self.envs.clear();
        for (k, v) in envs {
            self.envs.push((k.into(), v.into()));
        }
        self
    }

    /// Set the child's working directory.
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }
}

/// Structured reasons a sandbox operation can fail. Every variant
/// carries enough information for the CLI to surface an actionable
/// denial line (§9 + §12.5).
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The current platform has no sandbox backend. Windows (Phase 46)
    /// and non-{macOS,Linux} unix variants hit this arm. [`remediation`]
    /// is the user-facing next-step string.
    ///
    /// [`remediation`]: SandboxError::UnsupportedPlatform::remediation
    #[error("sandbox unavailable on {platform} — {remediation}")]
    UnsupportedPlatform {
        /// Lowercase platform identifier (`"windows"`, `"freebsd"`, …).
        platform: String,
        /// User-facing next-step. Directs to the escape hatch or the
        /// Phase 46.1 deferral as appropriate.
        remediation: String,
    },

    /// Linux kernel is older than the landlock ABI level the sandbox
    /// needs. Emitted by the Linux backend; symmetric with
    /// [`UnsupportedPlatform`](Self::UnsupportedPlatform) per the
    /// refuse-to-run stance agreed in Chunk 1 signoff.
    #[error(
        "Linux kernel too old for landlock sandbox (detected {detected}, need {required}) — \
		 {remediation}"
    )]
    KernelTooOld {
        /// `uname -r` output or parsed equivalent.
        detected: String,
        /// Minimum kernel version the backend requires, e.g. `"5.13"`.
        required: String,
        /// User-facing next-step.
        remediation: String,
    },

    /// Profile synthesis or ruleset construction failed before spawn.
    /// Carries the backend-specific reason so denial lines remain
    /// actionable (e.g. "invalid path in sandboxWriteDirs: …").
    #[error("failed to render sandbox profile: {reason}")]
    ProfileRenderFailed {
        /// Backend-specific failure detail.
        reason: String,
    },

    /// The child process failed to spawn. Distinct from a sandbox-rule
    /// denial — typically means `sandbox-exec` or the target program
    /// isn't on `$PATH`, or a syscall (clone/fork/exec) failed.
    #[error("failed to spawn sandboxed child: {reason}")]
    SpawnFailed {
        /// `std::io::Error` message or equivalent.
        reason: String,
    },

    /// Caller provided a [`SandboxSpec`] the backend can't use, e.g.
    /// a relative `package_dir` or empty `package_name`.
    #[error("invalid sandbox spec: {reason}")]
    InvalidSpec {
        /// Which field violated what invariant.
        reason: String,
    },
}

/// Trait every platform backend implements.
///
/// Object-safe so callers hold `Box<dyn Sandbox>`. [`spawn`] owns the
/// entire OS-level process creation so backends can insert their
/// wrapper program (macOS) or `pre_exec` hook (Linux) without leaking
/// mechanism into the call site.
///
/// [`spawn`]: Sandbox::spawn
pub trait Sandbox: Send + Sync {
    /// Spawn the given command under this sandbox. Returns a running
    /// [`std::process::Child`] on success.
    fn spawn(&self, cmd: SandboxedCommand) -> Result<std::process::Child, SandboxError>;

    /// Short identifier for logs and denial messages: `"seatbelt"`,
    /// `"landlock"`, `"noop"`.
    fn backend_name(&self) -> &'static str;

    /// The [`SandboxMode`] this instance was constructed for. Callers
    /// use this to gate diagnostic-mode-only UI (e.g. `--sandbox-log`
    /// banners) without reaching into backend-specific state.
    fn mode(&self) -> SandboxMode;
}

/// Returns a sandbox for the current platform + mode.
///
/// Dispatch is `cfg`-gated per CLAUDE.md hygiene rule: each platform
/// arm pulls only its own backend module, and non-supported platforms
/// return [`SandboxError::UnsupportedPlatform`] directly without
/// compiling platform-specific code they don't have.
///
/// [`SandboxMode::Disabled`] always succeeds with a [`NoopSandbox`]
/// regardless of platform — the `--unsafe-full-env --no-sandbox`
/// escape hatch must work everywhere, including Windows.
pub fn new_for_platform(
    spec: SandboxSpec,
    mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    if matches!(mode, SandboxMode::Disabled) {
        return Ok(Box::new(NoopSandbox { spec, mode }));
    }

    validate_spec(&spec)?;
    platform_backend(spec, mode)
}

#[cfg(target_os = "macos")]
fn platform_backend(
    spec: SandboxSpec,
    mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    Ok(Box::new(macos::SeatbeltSandbox::new(spec, mode)?))
}

#[cfg(target_os = "linux")]
fn platform_backend(
    spec: SandboxSpec,
    mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    Ok(Box::new(linux::LandlockSandbox::new(spec, mode)?))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_backend(
    _spec: SandboxSpec,
    _mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    Err(SandboxError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
        remediation: unsupported_remediation(std::env::consts::OS),
    })
}

/// User-facing remediation string for [`SandboxError::UnsupportedPlatform`].
///
/// Centralized so Windows (Phase 46.1 deferral) and generic-unix
/// platforms share consistent wording, and so Chunk 4's CLI-side
/// message test has a single source of truth.
pub fn unsupported_remediation(platform: &str) -> String {
    match platform {
        "windows" => "enforcement deferred to Phase 46.1. Re-run with \
			 --unsafe-full-env --no-sandbox to execute scripts without \
			 containment, or set script-policy = deny."
            .to_string(),
        _ => format!(
            "{platform} has no LPM sandbox backend. Re-run with \
			 --unsafe-full-env --no-sandbox to execute scripts without \
			 containment, or set script-policy = deny."
        ),
    }
}

fn validate_spec(spec: &SandboxSpec) -> Result<(), SandboxError> {
    if spec.package_name.is_empty() {
        return Err(SandboxError::InvalidSpec {
            reason: "package_name is empty".into(),
        });
    }
    if spec.package_version.is_empty() {
        return Err(SandboxError::InvalidSpec {
            reason: "package_version is empty".into(),
        });
    }
    for (field, path) in [
        ("package_dir", &spec.package_dir),
        ("project_dir", &spec.project_dir),
        ("store_root", &spec.store_root),
        ("home_dir", &spec.home_dir),
        ("tmpdir", &spec.tmpdir),
    ] {
        if !path.is_absolute() {
            return Err(SandboxError::InvalidSpec {
                reason: format!("{field} must be absolute, got {}", path.display()),
            });
        }
    }
    for (i, p) in spec.extra_write_dirs.iter().enumerate() {
        if !p.is_absolute() {
            return Err(SandboxError::InvalidSpec {
                reason: format!(
                    "extra_write_dirs[{i}] must be absolute after resolution, got {}",
                    p.display()
                ),
            });
        }
    }
    Ok(())
}

/// No-op sandbox backend. Used only for [`SandboxMode::Disabled`] —
/// spawns the command with no containment applied. Not available to
/// [`SandboxMode::Enforce`] or [`SandboxMode::LogOnly`].
pub struct NoopSandbox {
    #[allow(dead_code)]
    spec: SandboxSpec,
    mode: SandboxMode,
}

impl Sandbox for NoopSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<std::process::Child, SandboxError> {
        let mut command = std::process::Command::new(&cmd.program);
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
        command.stdout(std::process::Stdio::from(cmd.stdout));
        command.stderr(std::process::Stdio::from(cmd.stderr));
        command.stdin(std::process::Stdio::from(cmd.stdin));
        // Put the child in its own process group so the caller's
        // timeout path can kill the whole tree with `kill(-pid, SIGKILL)`.
        // Matches the pre-Phase-46 build.rs behavior and the other
        // backends (Seatbelt, Landlock) — keeps `--no-sandbox` behaving
        // like the legacy direct-spawn in every observable way.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: e.to_string(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "noop"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_spec() -> SandboxSpec {
        SandboxSpec {
            package_dir: PathBuf::from("/home/u/.lpm/store/prisma@5.22.0"),
            project_dir: PathBuf::from("/home/u/proj"),
            package_name: "prisma".into(),
            package_version: "5.22.0".into(),
            store_root: PathBuf::from("/home/u/.lpm/store"),
            home_dir: PathBuf::from("/home/u"),
            tmpdir: PathBuf::from("/tmp"),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn sandbox_spec_constructs_and_clones() {
        let a = sample_spec();
        let b = a.clone();
        assert_eq!(a.package_name, b.package_name);
        assert_eq!(a.package_dir, b.package_dir);
    }

    #[test]
    fn sandbox_mode_is_copy_and_comparable() {
        let m = SandboxMode::Enforce;
        let n = m;
        assert_eq!(m, n);
        assert_ne!(SandboxMode::Enforce, SandboxMode::LogOnly);
        assert_ne!(SandboxMode::LogOnly, SandboxMode::Disabled);
    }

    #[test]
    fn sandboxed_command_builder_sets_program_and_args() {
        let cmd = SandboxedCommand::new("sh")
            .arg("-c")
            .arg("echo hi")
            .current_dir("/tmp")
            .envs_cleared([("PATH", "/usr/bin:/bin")]);
        assert_eq!(cmd.program, OsString::from("sh"));
        assert_eq!(
            cmd.args,
            vec![OsString::from("-c"), OsString::from("echo hi")]
        );
        assert_eq!(cmd.current_dir, Some(PathBuf::from("/tmp")));
        assert!(cmd.env_clear);
        assert_eq!(cmd.envs.len(), 1);
    }

    #[test]
    fn error_display_unsupported_platform_mentions_platform_and_remediation() {
        let e = SandboxError::UnsupportedPlatform {
            platform: "windows".into(),
            remediation: unsupported_remediation("windows"),
        };
        let msg = format!("{e}");
        assert!(msg.contains("windows"), "got: {msg}");
        assert!(msg.contains("Phase 46.1"), "got: {msg}");
        assert!(msg.contains("--unsafe-full-env --no-sandbox"), "got: {msg}");
    }

    #[test]
    fn error_display_kernel_too_old_carries_versions() {
        let e = SandboxError::KernelTooOld {
            detected: "5.10.0".into(),
            required: "5.13".into(),
            remediation: "upgrade kernel or use --unsafe-full-env --no-sandbox".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("5.10.0"));
        assert!(msg.contains("5.13"));
        assert!(msg.contains("landlock"));
    }

    #[test]
    fn error_display_profile_render_failed_contains_reason() {
        let e = SandboxError::ProfileRenderFailed {
            reason: "invalid path in sandboxWriteDirs".into(),
        };
        assert!(format!("{e}").contains("invalid path in sandboxWriteDirs"));
    }

    #[test]
    fn error_display_spawn_failed_contains_reason() {
        let e = SandboxError::SpawnFailed {
            reason: "No such file or directory (os error 2)".into(),
        };
        assert!(format!("{e}").contains("No such file or directory"));
    }

    #[test]
    fn error_display_invalid_spec_contains_reason() {
        let e = SandboxError::InvalidSpec {
            reason: "package_name is empty".into(),
        };
        assert!(format!("{e}").contains("package_name is empty"));
    }

    #[test]
    fn unsupported_remediation_windows_points_to_46_1_and_escape_hatch() {
        let s = unsupported_remediation("windows");
        assert!(s.contains("Phase 46.1"));
        assert!(s.contains("--unsafe-full-env --no-sandbox"));
        assert!(s.contains("script-policy = deny"));
    }

    #[test]
    fn unsupported_remediation_generic_unix_names_platform() {
        let s = unsupported_remediation("freebsd");
        assert!(s.contains("freebsd"));
        assert!(s.contains("--unsafe-full-env --no-sandbox"));
    }

    #[test]
    fn validate_spec_rejects_empty_package_name() {
        let mut s = sample_spec();
        s.package_name.clear();
        match validate_spec(&s) {
            Err(SandboxError::InvalidSpec { reason }) => {
                assert!(reason.contains("package_name"));
            }
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn validate_spec_rejects_empty_package_version() {
        let mut s = sample_spec();
        s.package_version.clear();
        assert!(matches!(
            validate_spec(&s),
            Err(SandboxError::InvalidSpec { reason }) if reason.contains("package_version")
        ));
    }

    #[test]
    fn validate_spec_rejects_relative_package_dir() {
        let mut s = sample_spec();
        s.package_dir = PathBuf::from("relative/path");
        assert!(matches!(
            validate_spec(&s),
            Err(SandboxError::InvalidSpec { reason }) if reason.contains("package_dir") && reason.contains("absolute")
        ));
    }

    #[test]
    fn validate_spec_rejects_relative_project_dir() {
        let mut s = sample_spec();
        s.project_dir = PathBuf::from("./proj");
        assert!(matches!(
            validate_spec(&s),
            Err(SandboxError::InvalidSpec { reason }) if reason.contains("project_dir")
        ));
    }

    #[test]
    fn validate_spec_rejects_relative_extra_write_dir() {
        let mut s = sample_spec();
        s.extra_write_dirs.push(PathBuf::from("relative/writable"));
        assert!(matches!(
            validate_spec(&s),
            Err(SandboxError::InvalidSpec { reason }) if reason.contains("extra_write_dirs[0]")
        ));
    }

    #[test]
    fn validate_spec_accepts_wellformed_input() {
        assert!(validate_spec(&sample_spec()).is_ok());
    }

    #[test]
    fn disabled_mode_returns_noop_sandbox_on_any_platform() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled)
            .expect("disabled mode must succeed");
        assert_eq!(sb.backend_name(), "noop");
        assert_eq!(sb.mode(), SandboxMode::Disabled);
    }

    #[test]
    fn noop_sandbox_runs_a_trivial_command() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled).unwrap();
        let cmd = SandboxedCommand::new("true")
            .envs_cleared([("PATH", std::env::var_os("PATH").unwrap_or_default())]);
        let mut child = sb.spawn(cmd).expect("noop spawn must succeed");
        let status = child.wait().expect("wait");
        assert!(status.success(), "true must exit 0, got {status:?}");
    }

    #[test]
    fn noop_sandbox_reports_spawn_failure_structurally() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled).unwrap();
        let cmd = SandboxedCommand::new("/does/not/exist/lpm-sandbox-test-probe");
        match sb.spawn(cmd) {
            Err(SandboxError::SpawnFailed { reason }) => {
                assert!(!reason.is_empty(), "reason must be populated");
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    #[test]
    fn factory_rejects_invalid_spec_for_enforcing_modes() {
        let mut s = sample_spec();
        s.package_name.clear();
        let r = new_for_platform(s, SandboxMode::Enforce);
        assert!(matches!(r, Err(SandboxError::InvalidSpec { .. })));
    }

    #[test]
    fn factory_does_not_validate_spec_for_disabled_mode() {
        // Disabled should be the one mode that always works, because
        // the escape hatch must be reachable even with a mis-built
        // spec. Validation is backend-side only.
        let mut s = sample_spec();
        s.package_name.clear();
        assert!(new_for_platform(s, SandboxMode::Disabled).is_ok());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn factory_returns_unsupported_platform_on_unsupported_os() {
        let r = new_for_platform(sample_spec(), SandboxMode::Enforce);
        match r {
            Err(SandboxError::UnsupportedPlatform {
                platform,
                remediation,
            }) => {
                assert_eq!(platform, std::env::consts::OS);
                assert!(remediation.contains("--unsafe-full-env --no-sandbox"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_returns_seatbelt_backend_on_macos() {
        // Chunk 2 landed the real Seatbelt impl. Behavior-level tests
        // for spawn + containment live in the `macos` module's own
        // tests; this one asserts the factory wiring only.
        let sb = new_for_platform(sample_spec(), SandboxMode::Enforce)
            .expect("macOS factory must succeed");
        assert_eq!(sb.backend_name(), "seatbelt");
        assert_eq!(sb.mode(), SandboxMode::Enforce);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn factory_returns_landlock_backend_on_linux() {
        // Chunk 3: real landlock impl replaces the Chunk 1 stub.
        // Construction either succeeds (kernel supports landlock)
        // or fails cleanly with KernelTooOld. Behavior-level tests
        // (real `restrict_self` + containment probes) live in the
        // `linux` module's own tests.
        match new_for_platform(sample_spec(), SandboxMode::Enforce) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
                assert_eq!(sb.mode(), SandboxMode::Enforce);
            }
            Err(SandboxError::KernelTooOld { required, .. }) => {
                assert_eq!(required, "5.13");
            }
            Err(other) => panic!("unexpected factory error: {other:?}"),
        }
    }
}
