//! Filesystem-scoped sandbox for LPM post-install script execution.
//!
//! Filesystem-write containment launched with Seatbelt on macOS and
//! landlock V1 on Linux. Outbound network denial was added on top.
//!
//! ## Network-denial scope
//!
//! There is a **platform asymmetry** to be honest about:
//!
//! - **macOS** — Seatbelt's `(deny default)` covers every socket
//!   family / type. Dropping `(allow network*)` denies TCP, UDP,
//!   raw sockets, AF_PACKET, AF_NETLINK, DNS — everything outbound.
//!   Full outbound network denial.
//! - **Linux landlock V4 + seccomp-bpf** — two layered kernel
//!   mechanisms. Landlock V4
//!   (`AccessNet::from_all(V4)`) denies outbound TCP (`BindTcp` +
//!   `ConnectTcp`). On top of that, a seccomp-bpf filter denies
//!   direct `socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)`,
//!   `socket(AF_PACKET, …)`, and `socket(AF_NETLINK, …)` —
//!   closing the UDP / raw / L2 / routing-probe gap landlock V4
//!   leaves open. **AF_UNIX / AF_LOCAL stay allowed at the
//!   seccomp layer** so legitimate install-time IPC (node-ipc,
//!   husky's hook protocol, npm daemon communication) keeps
//!   working — that's the honest carve-out from full macOS
//!   parity. Resolver-mediated DNS remains host-dependent: glibc
//!   NSS may route through AF_UNIX (allowed) or fall through to
//!   TCP port 53 (caught by landlock, not seccomp).
//!
//! [`SandboxPosture::Strict`] documents this asymmetry at the
//! trait-doc level, and `lpm doctor` reports it on every Linux
//! run so users see what's actually enforced rather than
//! claiming full network denial.
//!
//! [`lpm-security`](../lpm_security/index.html) stays policy-only.
//!
//! The crate is intentionally narrow. Callers build a [`SandboxedCommand`]
//! (a platform-neutral description of the process they want to run),
//! obtain a [`Sandbox`] from [`new_for_platform`] (or
//! [`new_for_platform_with_options`] when the caller wants to thread
//! the `[sandbox] allow-degraded` knob through), then call
//! [`Sandbox::spawn`]. The backend decides how to apply containment:
//! macOS routes the spawn through `sandbox-exec`, and Linux installs a
//! landlock ruleset via `pre_exec` in the forked child.
//!
//! ## Backend coverage
//!
//! | Platform | [`SandboxMode::Enforce`] | [`SandboxMode::LogOnly`] | [`SandboxMode::Disabled`] |
//! |----------|--------------------------|---------------------------|----------------------------|
//! | macOS    | Seatbelt (`sandbox-exec`), `(deny default)` + narrow allows; **full outbound network denied**, no loopback exemption — every socket family / type covered. | Seatbelt w/ `(allow (with report) default)` fallback | [`NoopSandbox`] |
//! | Linux    | landlock V4 (kernel 6.7+) + seccomp-bpf layered together — filesystem + **outbound TCP** (landlock: BindTcp + ConnectTcp) + **direct UDP / raw / AF_PACKET / AF_NETLINK** (seccomp: `socket(2)` deny matrix). AF_UNIX intentionally allowed for legitimate IPC; resolver-mediated DNS remains host-dependent (NSS via AF_UNIX or TCP fallback). Kernels < 6.7 return [`SandboxError::KernelTooOld`] by default; explicit opt-in via `[sandbox] allow-degraded = true` falls back to V1 filesystem-only (no seccomp layer either) with a one-line stderr warning per install. | [`SandboxError::ModeNotSupportedOnPlatform`] — no native observe-only | [`NoopSandbox`] |
//! | Windows  | Mandatory Integrity Control (drop child to Low IL) + Job Object for kill-tree. Filesystem-write containment only — outbound network denial is **not** implemented; under default mode the posture is [`SandboxPosture::Default`]. Strict mode (`deny_outbound_network = true`) refuses with [`SandboxError::UnsupportedPlatform`] unless `allow_degraded = true`, in which case the backend succeeds with [`SandboxPosture::Degraded`] (`missing = "network-containment"`). | [`SandboxError::ModeNotSupportedOnPlatform`] — Mandatory Integrity Control has no native observe-only either | [`NoopSandbox`] |
//!
//! [`SandboxMode::Disabled`] always succeeds with a [`NoopSandbox`]:
//! the `--no-sandbox` escape hatch must be reachable from every
//! platform, including Windows.
//!
//! ## Posture
//!
//! [`Sandbox::posture`] reports whether the constructed backend
//! enforces the full contract ([`SandboxPosture::Strict`])
//! or has fallen back to filesystem-only on a kernel that can't
//! support network denial ([`SandboxPosture::Degraded`]). The install
//! pipeline uses this to emit the per-install structured stderr
//! warning exactly once when the user has opted into the degraded
//! posture via `[sandbox] allow-degraded = true`.

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

// seccomp-bpf filter for the socket(2) deny matrix
// (UDP / raw / AF_PACKET / AF_NETLINK). Layered on top of the
// landlock V4 ruleset in [`linux`]'s `pre_exec` closure when the
// posture is Strict. Exercised by the `socket-probe` test bin
// (`src/bin/socket-probe.rs`) and the `sandbox_udp_denial`
// workflow test.
#[cfg(target_os = "linux")]
mod seccomp;

// Per-process resource limits (RLIMIT_NPROC / NOFILE / CPU) wired
// into the Unix backends' `pre_exec` closures. Defense-in-depth
// against fork-bomb / fd-exhaustion / CPU-spinner DoS from a
// lifecycle script. macOS + Linux only — Windows uses
// `JOB_OBJECT_LIMIT_*` instead, wired in `windows.rs`.
#[cfg(unix)]
mod rlimits;

// Windows backend via Mandatory Integrity Control (drop
// child to Low IL) + Job Object for kill-tree parity with Unix's
// process group. See [`windows`] module docs for the mechanism + the
// platform-asymmetric posture mapping (Default OK; Strict needs
// WFP layer).
#[cfg(target_os = "windows")]
mod windows;

// argv contract for the `lpm-sandbox-helper.exe`
// helper. Cross-platform parser so the unit tests run on every CI
// runner; the helper binary itself is Windows-only. The module gates
// internally on `cfg(any(target_os = "windows", test))` — see its
// crate-doc preamble.
pub mod helper_protocol;

// AppContainer launcher invoked from
// `lpm-sandbox-helper.exe` on Windows. The Win32 surface (SID,
// DACL, STARTUPINFOEXW, Job Object) is reachable only on Windows;
// the module gates internally on `cfg(target_os = "windows")`.
#[cfg(target_os = "windows")]
pub mod helper_appcontainer;

// Parent-side AppContainer backend (lives in
// `lpm.exe`, drives the helper binary). The factory below picks
// this backend over [`windows::WindowsSandbox`] when
// `locate_sandbox_helper` finds the helper.
#[cfg(target_os = "windows")]
mod windows_appcontainer;

// Rule description is platform-neutral so macOS CI + developer-host
// test runs exercise it without a Linux kernel. The module is gated
// on `target_os = "linux"` for production builds (where `linux.rs`
// consumes it) and on `test` for any test build (so the rules unit
// tests run on the macOS developer host). Non-Linux production
// builds don't compile this module at all.
//
// excluded from Windows test builds. The
// rule fixtures use hard-coded POSIX paths (`/home/u/...`, `/tmp`,
// `/dev/null`, …) that aren't absolute on Windows, so on a Windows
// test host they'd surface as InvalidSpec rejections — pure noise
// for a Linux-only consumer. The Windows backend has its own
// allow-set rendering (`crate::windows::writable_allow_set`) and
// its own tests.
#[cfg(any(target_os = "linux", all(test, not(target_os = "windows"))))]
mod landlock_rules;

// posture-decision helper. Pure (string in, decision out),
// platform-neutral so the macOS-host unit tests exercise the same
// table that the Linux backend uses in production. Compiles under
// the same gate as `landlock_rules`: Linux production, plus any
// `test` build so the strict-vs-degraded table is testable on every
// developer's machine without spinning up a Linux VM. Non-Linux
// production builds skip the module — they have no consumer.
//
// the Windows backend has its own
// `decide_posture` (`crate::windows::decide_posture`), so this
// Linux-shaped one stays gated off on Windows builds. Same
// rationale as `landlock_rules` above.
#[cfg(any(target_os = "linux", all(test, not(target_os = "windows"))))]
mod posture_decision;

// Shared secret-file path catalog consumed by the Seatbelt
// (macOS) deny renderer AND the Linux bind-mount overlay
// enumerator. Single source of truth — `mod secret_paths;` makes
// drift a type-system error. Gated on macOS + Linux + non-Windows
// tests (Windows currently has no overlay layer; the const lists
// would be dead code there).
#[cfg(any(
    target_os = "macos",
    target_os = "linux",
    all(test, not(target_os = "windows"))
))]
mod secret_paths;

// Linux secret-file overlay (bind-mounts /dev/null over secret
// paths under project_dir). Same gate shape as `landlock_rules`:
// Linux production + every non-Windows test build, so macOS unit
// tests exercise the enumerator. The `apply_secret_overlay_in_child`
// AS-safe hook + the `SecretOverlaySpec::build` constructor are
// `target_os = "linux"`-gated inside the module.
#[cfg(any(target_os = "linux", all(test, not(target_os = "windows"))))]
mod linux_secret_overlay;

pub mod config;
pub use config::{load_sandbox_read_allow, load_sandbox_write_dirs};

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
    /// store directory. The primary writable root for lifecycle scripts.
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
    /// `$HOME/.npm` in the sandbox writable set and `$HOME/.nvm/versions`
    /// in the read set.
    pub home_dir: PathBuf,
    /// `$TMPDIR`. Per-user temp on macOS, typically `/tmp` on Linux.
    /// `/tmp` itself is already in the writable set.
    pub tmpdir: PathBuf,
    /// Extra writable subpaths from `package.json > lpm > scripts >
    /// sandboxWriteDirs`. Loader resolves relative paths against
    /// [`project_dir`](Self::project_dir) before constructing the spec.
    pub extra_write_dirs: Vec<PathBuf>,
    /// Project-relative paths the user has explicitly opted in for
    /// lifecycle-script reads despite matching the built-in secret-file
    /// deny list (e.g. `.env`, `*.pem`, `.aws/`). Resolved to absolute
    /// project-rooted paths by the loader. The sandbox backends omit
    /// the deny rule / bind-mount for any path in this list.
    ///
    /// Empty by default. Populated from `package.json > lpm > scripts >
    /// sandboxReadAllow` (per-project) and `~/.lpm/config.toml >
    /// [sandbox] script-read-allow` (per-user). Same precedence and
    /// validation shape as [`extra_write_dirs`](Self::extra_write_dirs):
    /// every entry must canonicalize inside `project_dir`, traversal
    /// (`..`) and absolute paths outside the project are rejected by
    /// the loader.
    pub secret_read_allow: Vec<PathBuf>,
}

/// Caller-tunable knobs the sandbox factory consumes alongside
/// [`SandboxSpec`] and [`SandboxMode`]. introduces this
/// struct so the install layer can thread the
/// `[sandbox] allow-degraded` config knob through to the Linux
/// backend without changing every call site that doesn't need it.
///
/// New fields land here with `Default` semantics matching the strict
/// (most-secure) interpretation — callers who do not set them
/// explicitly inherit the conservative posture.
#[derive(Debug, Clone, Default)]
pub struct SandboxOptions {
    /// opt-in escape hatch for the Linux backend on
    /// kernels older than 6.7 (the landlock V4 floor). When `false`
    /// (the default), kernels < 6.7 surface
    /// [`SandboxError::KernelTooOld`] with `required: "6.7"` and the
    /// lifecycle script does not run. When `true`, the backend falls
    /// back to landlock V1 (filesystem-only) and the install
    /// pipeline emits a one-line structured stderr warning naming
    /// the active ABI + missing dimension. macOS ignores the flag
    /// (its backend has no degraded mode — Seatbelt enforces both
    /// filesystem and network in the same profile).
    ///
    /// This knob is only consulted when `deny_outbound_network = true`
    /// (strict mode). When network denial is off, the V1 floor is
    /// always usable on any landlock-capable kernel and there is no
    /// "degraded" state to fall back to — the backend just behaves
    /// in filesystem-only mode (filesystem + env containment).
    pub allow_degraded: bool,

    /// Whether the constructed sandbox should deny outbound network
    /// from inside the lifecycle script.
    ///
    /// When `false` (the default), the sandbox enforces only
    /// filesystem-write containment + env scrubbing. Outbound
    /// network is allowed. This is the shape
    /// most real-world scripted packages need
    /// (sharp/prisma/puppeteer/`@lpm-registry/cli`/etc. all download
    /// prebuilts or browser engines during postinstall).
    ///
    /// When `true`, the sandbox additionally denies outbound
    /// network — TCP `connect(2)` and `bind(2)` on Linux landlock
    /// V4, all socket families via Seatbelt's `(deny default)` on
    /// macOS. This is the "paranoid / CI / enterprise" path the
    /// user opts into via `--strict-sandbox` (or its alias
    /// `--paranoid`), `[sandbox] mode = "strict"` in
    /// `~/.lpm/config.toml` / `./lpm.toml`, or
    /// `LPM_STRICT_SANDBOX=1` in the env.
    ///
    /// Participates in the sandbox CLI / config / env precedence chain.
    pub deny_outbound_network: bool,

    /// Restrict persistent writes to the package directory and the supplied
    /// temporary directory. This is used only while producing a reusable
    /// lifecycle-build artifact; normal lifecycle execution keeps the broader
    /// compatibility write set.
    pub build_cache_isolation: bool,
}

impl SandboxOptions {
    /// Build a [`SandboxOptions`] with `allow_degraded` set to the
    /// supplied value. Symmetric helper for call sites that read the
    /// config knob and want a one-line constructor.
    pub fn with_allow_degraded(allow_degraded: bool) -> Self {
        Self {
            allow_degraded,
            ..Self::default()
        }
    }

    /// Build a [`SandboxOptions`] with `deny_outbound_network` set
    /// to the supplied value. Used by the install pipeline after
    /// resolving the `--strict-sandbox` / `[sandbox] mode` /
    /// `LPM_STRICT_SANDBOX` precedence chain.
    pub fn with_deny_outbound_network(deny_outbound_network: bool) -> Self {
        Self {
            deny_outbound_network,
            ..Self::default()
        }
    }
}

/// Which dimensions the constructed sandbox actually enforces.
/// Returned from [`Sandbox::posture`] so the install pipeline + the
/// `lpm doctor` surface can show the user's effective security
/// shape and emit the per-install structured warning exactly when
/// the user is on a fallback path.
///
/// [`SandboxPosture::Default`] distinguishes "user picked the
/// relaxed mode" from "user picked strict but kernel forced a
/// fallback" ([`SandboxPosture::Degraded`]). Both have the same
/// runtime semantics (filesystem-only); the distinction matters
/// for doctor / warning text + telemetry classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxPosture {
    /// rework default: filesystem-write containment +
    /// env scrubbing. Outbound network **allowed** — the user
    /// picked the relaxed mode, either by accepting the default or
    /// by explicit `[sandbox] mode = "default"`.
    ///
    /// No per-install warning is emitted because this is a chosen
    /// state, not a fallback.
    Default,
    /// strict posture: filesystem-write containment +
    /// outbound network denial. Reached when the user opts into
    /// strict mode (`--strict-sandbox` / `--paranoid` /
    /// `[sandbox] mode = "strict"` / `LPM_STRICT_SANDBOX=1`).
    ///
    /// **Network-denial coverage is platform-asymmetric.** Strict
    /// means:
    ///
    /// - **macOS Seatbelt** — full outbound network denial. Every
    ///   socket family / type (TCP, UDP, raw, AF_PACKET,
    ///   AF_NETLINK, DNS, AF_UNIX) goes to the deny path under
    ///   the `(deny default)` rule.
    /// - **Linux landlock V4 + seccomp-bpf** — two
    ///   layered kernel mechanisms. Landlock V4
    ///   (`AccessNet::from_all`) denies TCP `BindTcp` /
    ///   `ConnectTcp`. The pre_exec closure ALSO installs a
    ///   seccomp filter that denies direct
    ///   `socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)`,
    ///   `socket(AF_PACKET, ...)`, and
    ///   `socket(AF_NETLINK, ...)`. **AF_UNIX is intentionally
    ///   allowed at the seccomp layer** for legitimate IPC needs
    ///   (node-ipc, husky hooks, npm daemon comms) — an honest
    ///   carve-out from full macOS parity. Resolver-mediated DNS
    ///   remains host-dependent (NSS via AF_UNIX or TCP
    ///   fallback).
    ///
    /// `lpm doctor` surfaces this asymmetry on every run so users
    /// see the real platform coverage rather than the aspirational
    /// one. The runtime gates
    /// `tests/workflows/tests/sandbox_network_denial.rs` (TCP) and
    /// `tests/workflows/tests/sandbox_udp_denial.rs` (UDP / raw /
    /// AF_PACKET / AF_NETLINK) pin the contract.
    Strict,
    /// Filesystem containment is active, but network denial is not.
    /// Linux landlock backend on kernels < 6.7 with the user's
    /// opt-in to degraded posture. The `kernel` field carries the
    /// detected kernel version for surfacing in the structured
    /// per-install warning + `lpm doctor`; `missing` names the
    /// dropped dimension (currently always `"network-containment"`
    /// — the field is structured so future fallbacks can name
    /// additional missing pieces without a wire-format break).
    Degraded {
        /// Detected kernel version string, e.g. `"5.15.0-1063-aws"`.
        kernel: String,
        /// Active landlock ABI level, e.g. `"v1"`. Lower-case so
        /// the doctor / warning lines have a uniform spelling.
        abi: &'static str,
        /// Comma-separated names of the dimensions that are NOT
        /// enforced in this posture. Currently only
        /// `"network-containment"` — kept as a string for forward
        /// compatibility.
        missing: &'static str,
    },
    /// No containment applied (e.g. [`NoopSandbox`] for the
    /// `--no-sandbox` escape hatch, or platforms without a backend).
    /// Posture-aware UI surfaces this as "containment off" rather
    /// than conflating with strict.
    Disabled,
}

impl SandboxPosture {
    /// Render the per-install structured stderr warning
    /// line for this posture, or `None` if no warning is required.
    ///
    /// Returns `Some(...)` only for [`SandboxPosture::Degraded`] —
    /// the strict posture is honest by default and needs no
    /// per-install reminder, the disabled posture is already
    /// surfaced by the `--no-sandbox` CLI banner.
    ///
    /// Format is grep-stable so log scrapers can parse it
    /// mechanically:
    ///
    /// ```text
    /// warning: sandbox.degraded: kernel=<kernel> abi=<abi> missing=<missing> policy=allow-degraded
    /// ```
    pub fn degraded_warning_line(&self) -> Option<String> {
        match self {
            SandboxPosture::Degraded {
                kernel,
                abi,
                missing,
            } => Some(format!(
                "warning: sandbox.degraded: kernel={kernel} abi={abi} missing={missing} policy=allow-degraded"
            )),
            SandboxPosture::Default | SandboxPosture::Strict | SandboxPosture::Disabled => None,
        }
    }
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
    /// No containment. Used only by the `--no-sandbox` escape hatch.
    /// Emits a loud CLI banner at the call site (not this crate's
    /// responsibility).
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
/// denial line.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The current platform has no sandbox backend. Windows
    /// and non-{macOS,Linux} unix variants hit this arm. [`remediation`]
    /// is the user-facing next-step string.
    ///
    /// [`remediation`]: SandboxError::UnsupportedPlatform::remediation
    #[error("sandbox unavailable on {platform} — {remediation}")]
    UnsupportedPlatform {
        /// Lowercase platform identifier (`"windows"`, `"freebsd"`, …).
        platform: String,
        /// User-facing next-step. Directs to the escape hatch or the
        /// deferral as appropriate.
        remediation: String,
    },

    /// Linux kernel is older than the landlock ABI level the sandbox
    /// needs. Emitted by the Linux backend; symmetric with
    /// [`UnsupportedPlatform`](Self::UnsupportedPlatform) in its
    /// refuse-to-run stance.
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

    /// The backend for this platform exists, but the requested
    /// [`SandboxMode`] has no implementation on this platform.
    /// Linux LogOnly hits this — landlock has no native observe-only
    /// primitive, so the honest answer is "reject the mode" rather
    /// than pseudo-mode it.
    ///
    /// Distinct from [`UnsupportedPlatform`](Self::UnsupportedPlatform)
    /// (the whole platform lacks a backend) so callers + tests can
    /// distinguish "no containment here" from "no diagnostic mode
    /// here, but Enforce works fine."
    #[error("sandbox mode {mode:?} is not supported on {platform} — {remediation}")]
    ModeNotSupportedOnPlatform {
        /// Lowercase platform identifier (`"linux"`, `"windows"`, …).
        platform: String,
        /// The offending mode — usually [`SandboxMode::LogOnly`] on
        /// Linux.
        mode: SandboxMode,
        /// User-facing next-step. Names the interim workaround
        /// (typically `--no-sandbox` — rework collapsed
        /// the legacy `--unsafe-full-env` partner) so users aren't
        /// stuck guessing.
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

    /// Which dimensions this instance actually enforces.
    ///
    /// Backends must override this — there is no meaningful default.
    /// Seatbelt + landlock decide based on `deny_outbound_network`
    /// (and on Linux, on the kernel-version probe result for
    /// strict-with-fallback shapes). `NoopSandbox` returns
    /// [`SandboxPosture::Disabled`].
    ///
    /// Install-pipeline callers query this once after the pre-probe
    /// and emit [`SandboxPosture::degraded_warning_line`] when the
    /// returned posture is `Degraded`. Posture is constant for the
    /// lifetime of the sandbox instance — the probe runs once at
    /// construction.
    fn posture(&self) -> SandboxPosture;
}

/// Returns a sandbox for the current platform + mode with the
/// default [`SandboxOptions`] (`allow_degraded = false`).
///
/// Dispatch is `cfg`-gated: each platform arm pulls only its own backend
/// module, and non-supported platforms return
/// [`SandboxError::UnsupportedPlatform`] directly without compiling
/// platform-specific code they don't have.
///
/// [`SandboxMode::Disabled`] always succeeds with a [`NoopSandbox`]
/// regardless of platform — the `--no-sandbox` escape hatch must
/// work everywhere, including Windows.
///
/// Callers that need to thread the `[sandbox] allow-degraded` knob
/// through (install pipeline, doctor) use
/// [`new_for_platform_with_options`] instead.
pub fn new_for_platform(
    spec: SandboxSpec,
    mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    new_for_platform_with_options(spec, mode, SandboxOptions::default())
}

/// as [`new_for_platform`] but accepts a
/// [`SandboxOptions`] so callers can opt into the degraded posture
/// on kernels that don't support landlock V4.
///
/// Production call sites that have read the user's
/// `[sandbox] allow-degraded` config (install / rebuild) go through
/// this entry point; backend tests and the doctor probe that don't
/// need to opt into degradation keep using [`new_for_platform`].
pub fn new_for_platform_with_options(
    spec: SandboxSpec,
    mode: SandboxMode,
    options: SandboxOptions,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    if matches!(mode, SandboxMode::Disabled) {
        return Ok(Box::new(NoopSandbox { spec, mode }));
    }

    validate_spec(&spec)?;
    platform_backend(spec, mode, options)
}

#[cfg(target_os = "macos")]
fn platform_backend(
    spec: SandboxSpec,
    mode: SandboxMode,
    options: SandboxOptions,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    // macOS Seatbelt has a single posture — when
    // `deny_outbound_network` is set, the profile drops
    // `(allow network*)` and the opening `(deny default)` covers
    // every socket family unconditionally. `allow_degraded` is
    // meaningless on macOS (Seatbelt is either fully active or
    // off — no fallback ABI shape) and we deliberately ignore it.
    Ok(Box::new(macos::SeatbeltSandbox::new(spec, mode, options)?))
}

#[cfg(target_os = "linux")]
fn platform_backend(
    spec: SandboxSpec,
    mode: SandboxMode,
    options: SandboxOptions,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    Ok(Box::new(linux::LandlockSandbox::new(spec, mode, options)?))
}

#[cfg(target_os = "windows")]
fn platform_backend(
    spec: SandboxSpec,
    mode: SandboxMode,
    options: SandboxOptions,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    // Prefer the AppContainer backend when its helper binary is
    // reachable. AppContainer delivers full strict (filesystem-write
    // containment + outbound network denial); the Mandatory Integrity
    // Control backend remains as the fallback path when the helper
    // binary is missing (npm install corruption, manual binary fetch,
    // dev-build that didn't bundle the helper).
    //
    // The two backends keep separate posture decisions
    // ([`windows::decide_posture`] vs
    // [`windows_appcontainer::decide_appcontainer_posture`]) so
    // The AppContainer backend must not accidentally weaken the
    // Low IL backend's strict-without-degraded refusal contract.
    if let Some(helper_path) = windows_appcontainer::locate_sandbox_helper() {
        return Ok(Box::new(windows_appcontainer::AppContainerSandbox::new(
            spec,
            mode,
            options,
            helper_path,
        )?));
    }
    // Helper missing: log once at info-level so the active backend
    // is observable, then fall back to the 46.2 Low IL path. The
    // doctor surface ([`crate::Sandbox::backend_name`]) carries the
    // same signal for users.
    tracing::info!(
        target: "lpm_sandbox::windows",
        "lpm-sandbox-helper.exe not found next to lpm.exe; falling back to \
         the Low IL backend (no outbound-network containment)",
    );
    Ok(Box::new(windows::WindowsSandbox::new(spec, mode, options)?))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_backend(
    _spec: SandboxSpec,
    _mode: SandboxMode,
    _options: SandboxOptions,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    Err(SandboxError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
        remediation: unsupported_remediation(std::env::consts::OS),
    })
}

/// Ensure the "standard" writable subpaths referenced by the sandbox
/// profile actually exist on disk, creating any that don't.
///
/// Sandbox rules of the shape `(subpath "{project}/.husky")` allow
/// writes INSIDE `.husky`, but creating `.husky` itself requires
/// write on its parent (`{project}`) which we deliberately DON'T
/// grant (scripts would gain write on the whole project tree).
/// Scripts like `husky install` running on a fresh project would
/// fail without this helper — they'd try to create `.husky`
/// themselves and hit the sandbox rule gap.
///
/// also pre-creates every entry of
/// `spec.extra_write_dirs`. Before this, a user-declared
/// `sandboxWriteDirs: ["build-output"]` entry would be accepted by
/// the validator and then silently denied at runtime — the Windows
/// backend's `apply_low_il_label` skips nonexistent paths, the
/// script would try to `mkdir build-output` against a Medium-IL
/// `project_dir` it can't write to, and the install would fail. The
/// Seatbelt + landlock backends had the same hazard but it was less
/// visible because POSIX `mkdir` against a Medium-IL parent fails
/// with a clearer message; on Windows the failure mode was an opaque
/// ERROR_ACCESS_DENIED. Pre-creating means every `extra_write_dirs`
/// entry exists when `apply_low_il_label` / landlock / Seatbelt sees
/// it, so the label / rule actually lands and the script can write.
///
/// Callers (build.rs production path + compat-corpus test fixtures)
/// invoke this once before spawning scripts. Paths that already
/// exist are left alone.
///
/// Errors surface as `SandboxError::InvalidSpec` with an actionable
/// reason so the caller can distinguish "sandbox couldn't prep the
/// filesystem" from "the sandbox itself failed."
pub fn prepare_writable_dirs(spec: &SandboxSpec) -> Result<(), SandboxError> {
    // Built-in writable subpaths first. These mirror the
    // standard-allow-set entries every backend renders into its
    // profile / ruleset / IL label.
    let builtin = [
        spec.project_dir.join(".husky"),
        spec.project_dir.join(".lpm"),
        spec.project_dir.join("node_modules"),
        spec.home_dir.join(".cache"),
        spec.home_dir.join(".node-gyp"),
        spec.home_dir.join(".npm"),
    ];
    for p in &builtin {
        ensure_writable_dir_exists(p)?;
    }

    // Then user-declared `sandboxWriteDirs`. These have already been
    // validated by `load_sandbox_write_dirs` — joined-with-project
    // for relative entries, dangerous-root + allowlist + traversal
    // checked. Creating them here closes the
    // "declared-but-not-yet-on-disk" gap that would otherwise
    // surface as a runtime denial on Windows.
    for p in &spec.extra_write_dirs {
        ensure_writable_dir_exists(p)?;
    }
    Ok(())
}

fn ensure_writable_dir_exists(p: &std::path::Path) -> Result<(), SandboxError> {
    if !p.exists()
        && let Err(e) = std::fs::create_dir_all(p)
    {
        return Err(SandboxError::InvalidSpec {
            reason: format!(
                "failed to prepare writable dir {}: {e}. The sandbox needs \
                     this path to exist before scripts run — see \
                     `prepare_writable_dirs` docs.",
                p.display()
            ),
        });
    }
    Ok(())
}

/// Tear down the entire process tree for a sandboxed child by PID.
///
/// On Unix this is a no-op: the install pipeline already kills the
/// child's process group directly via `kill(-pid, SIGKILL)` because
/// the [`Sandbox::spawn`] path puts the lifecycle child in its own
/// group via `process_group(0)`.
///
/// On Windows the lifecycle child is attached to a Job Object with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, but the parent retains a
/// handle to the Job (held inside the sandbox crate so descendants
/// survive `Child::wait`). Calling `child.kill()` only terminates
/// the root process; descendants survive until parent exit. Routing
/// through this function instead calls `TerminateJobObject` which
/// the kernel propagates to every member of the tree, then drops
/// the cached handle so the kernel reclaims the Job.
///
/// Idempotent: PIDs without a tracked entry (Unix; Windows children
/// that exited normally; PIDs from non-sandboxed spawns) are silent
/// no-ops. Always pair with `Child::kill()` for belt-and-suspenders
/// behavior on platforms where the tracker isn't populated.
pub fn terminate_sandbox_tree(_pid: u32) {
    #[cfg(target_os = "windows")]
    windows::terminate_sandbox_tree(_pid);
}

/// Release the sandbox-tracker entry for a child that exited
/// normally (no timeout, no panic). On Unix this is a no-op. On
/// Windows it drops the cached Job-Object handle so the kernel can
/// reclaim it — without this, the tracker accumulates one open
/// HANDLE per successful lifecycle script for the parent's lifetime.
///
/// Production callers in the install pipeline invoke this after a
/// `Child::wait` returns naturally; the timeout-kill path uses
/// [`terminate_sandbox_tree`] instead which also handles release.
///
/// Idempotent: missing entries are silent no-ops.
pub fn release_sandbox_tracker(_pid: u32) {
    #[cfg(target_os = "windows")]
    windows::release_sandbox_tracker_entry(_pid);
}

/// User-facing remediation string for [`SandboxError::UnsupportedPlatform`].
///
/// Centralized so unsupported platforms share consistent wording and
/// the CLI-side message test has a single source of truth.
///
/// The remediation names `--no-sandbox` as a single flag.
///
/// Windows has a real backend (`windows::WindowsSandbox`), so the
/// legacy "Windows isn't supported" special case is gone. The
/// Windows strict-mode refusal
/// path generates its OWN remediation via
/// `windows::strict_not_yet_supported_remediation`; this generic
/// helper only fires for unsupported platforms (FreeBSD, OpenBSD,
/// illumos, etc.).
pub fn unsupported_remediation(platform: &str) -> String {
    format!(
        "{platform} has no LPM sandbox backend. Re-run with \
		 --no-sandbox to execute scripts without containment, or set \
		 script-policy = deny."
    )
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
            // `tmpdir` is the one field that's commonly sourced from
            // a user-controlled env var (`TMPDIR` on Unix, `TMP`/
            // `TEMP` on Windows) rather than a path we constructed
            // internally. A relative value usually means the env var
            // itself is misconfigured — surface that hint in the
            // error so the user can fix the root cause rather than
            // chasing the call site. The rationale for rejecting (vs
            // silently canonicalizing) a relative tmpdir: any relative
            // path is interpreted against the process cwd, which can
            // differ from user intent and is not verifiable at sandbox
            // construction time.
            let reason = if field == "tmpdir" {
                format!(
                    "tmpdir must be absolute, got {}. Common cause: \
                     the TMPDIR (Unix) or TMP / TEMP (Windows) env var \
                     is set to a relative path. Unset it, or set it to \
                     an absolute path, before invoking lpm.",
                    path.display()
                )
            } else {
                format!("{field} must be absolute, got {}", path.display())
            };
            return Err(SandboxError::InvalidSpec { reason });
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
        // Matches the other backends (Seatbelt, Landlock) — keeps
        // `--no-sandbox` behaving like the legacy direct-spawn in
        // every observable way.
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

    fn posture(&self) -> SandboxPosture {
        SandboxPosture::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Platform-aware fixture. `validate_spec` requires every path
    /// to be absolute by the calling OS's definition — `/home/u/...`
    /// is absolute on Unix but **NOT** on Windows (Windows requires a
    /// drive letter prefix or UNC root). The cfg block below keeps
    /// the existing Unix paths verbatim and provides a drive-letter
    /// equivalent for Windows so the same assertions pass on both.
    fn sample_spec() -> SandboxSpec {
        #[cfg(not(target_os = "windows"))]
        const PKG_DIR: &str = "/home/u/.lpm/store/prisma@5.22.0";
        #[cfg(not(target_os = "windows"))]
        const PROJECT_DIR: &str = "/home/u/proj";
        #[cfg(not(target_os = "windows"))]
        const STORE_ROOT: &str = "/home/u/.lpm/store";
        #[cfg(not(target_os = "windows"))]
        const HOME_DIR: &str = "/home/u";
        #[cfg(not(target_os = "windows"))]
        const TMPDIR: &str = "/tmp";

        #[cfg(target_os = "windows")]
        const PKG_DIR: &str = r"C:\lpm-test\home\u\.lpm\store\prisma@5.22.0";
        #[cfg(target_os = "windows")]
        const PROJECT_DIR: &str = r"C:\lpm-test\home\u\proj";
        #[cfg(target_os = "windows")]
        const STORE_ROOT: &str = r"C:\lpm-test\home\u\.lpm\store";
        #[cfg(target_os = "windows")]
        const HOME_DIR: &str = r"C:\lpm-test\home\u";
        #[cfg(target_os = "windows")]
        const TMPDIR: &str = r"C:\lpm-test\tmp";

        SandboxSpec {
            package_dir: PathBuf::from(PKG_DIR),
            project_dir: PathBuf::from(PROJECT_DIR),
            package_name: "prisma".into(),
            package_version: "5.22.0".into(),
            store_root: PathBuf::from(STORE_ROOT),
            home_dir: PathBuf::from(HOME_DIR),
            tmpdir: PathBuf::from(TMPDIR),
            secret_read_allow: Vec::new(),
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
        // Windows is no longer unsupported,
        // so we exercise the generic-unsupported path here with a
        // platform that genuinely has no backend (FreeBSD). The
        // Windows-specific strict-not-yet-supported remediation is
        // generated by the Windows backend itself and tested in
        // [`windows::tests`].
        let e = SandboxError::UnsupportedPlatform {
            platform: "freebsd".into(),
            remediation: unsupported_remediation("freebsd"),
        };
        let msg = format!("{e}");
        assert!(msg.contains("freebsd"), "got: {msg}");
        assert!(msg.contains("has no LPM sandbox backend"), "got: {msg}");
        assert!(msg.contains("--no-sandbox"), "got: {msg}");
        assert!(
            !msg.contains("--unsafe-full-env"),
            "legacy partner flag must be gone: {msg}",
        );
    }

    #[test]
    fn error_display_kernel_too_old_carries_versions() {
        let e = SandboxError::KernelTooOld {
            detected: "5.10.0".into(),
            required: "5.13".into(),
            remediation: "upgrade kernel or use --no-sandbox".into(),
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
    fn error_display_mode_not_supported_on_platform_names_mode_platform_and_remediation() {
        let e = SandboxError::ModeNotSupportedOnPlatform {
            platform: "linux".into(),
            mode: SandboxMode::LogOnly,
            remediation: "landlock has no observe-only primitive. Use --no-sandbox to \
                debug a sandbox false-positive."
                .into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("linux"), "got: {msg}");
        assert!(msg.contains("LogOnly"), "got: {msg}");
        // single `--no-sandbox` flag.
        assert!(
            msg.contains("--no-sandbox"),
            "must point at the workaround: {msg}"
        );
    }

    #[test]
    fn unsupported_remediation_generic_unix_names_platform() {
        // Windows is no longer routed
        // through this helper — its own backend generates a richer
        // remediation when strict mode is requested without the
        // degraded opt-in. The helper now produces a uniform
        // message for every platform that genuinely has no backend
        // (FreeBSD, OpenBSD, illumos, …).
        let s = unsupported_remediation("freebsd");
        assert!(s.contains("freebsd"));
        // single `--no-sandbox` flag.
        assert!(s.contains("--no-sandbox"));
        assert!(
            !s.contains("--unsafe-full-env"),
            "legacy partner flag must be gone: {s}",
        );
        assert!(s.contains("script-policy = deny"));
    }

    /// follow-up: every entry of `spec.extra_write_dirs`
    /// must exist on disk after `prepare_writable_dirs` returns.
    /// Without this, a user-declared `sandboxWriteDirs: ["build-output"]`
    /// would survive validation but be silently denied at runtime
    /// (the Windows backend's `apply_low_il_label` skips nonexistent
    /// paths, the script then tries `mkdir build-output` against a
    /// Medium-IL `project_dir`, and fails with ERROR_ACCESS_DENIED).
    #[test]
    fn prepare_writable_dirs_creates_extra_write_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = tmp.path().join("proj");
        let home = tmp.path().join("home");
        let extra_a = project.join("build-output");
        let extra_b = tmp.path().join("siblings").join("dist");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let spec = SandboxSpec {
            package_dir: tmp.path().join("pkg"),
            project_dir: project.clone(),
            package_name: "p".into(),
            package_version: "1.0.0".into(),
            store_root: tmp.path().join("store"),
            home_dir: home.clone(),
            tmpdir: tmp.path().join("tmpdir"),
            secret_read_allow: Vec::new(),
            extra_write_dirs: vec![extra_a.clone(), extra_b.clone()],
        };
        std::fs::create_dir_all(&spec.package_dir).unwrap();
        std::fs::create_dir_all(&spec.tmpdir).unwrap();

        prepare_writable_dirs(&spec).expect("prep must succeed");

        // Builtins:
        assert!(project.join(".husky").exists(), "missing .husky");
        assert!(project.join(".lpm").exists(), "missing .lpm");
        assert!(
            project.join("node_modules").exists(),
            "missing node_modules"
        );
        assert!(home.join(".cache").exists(), "missing .cache");
        assert!(home.join(".node-gyp").exists(), "missing .node-gyp");
        assert!(home.join(".npm").exists(), "missing .npm");

        // The actual fix:
        assert!(
            extra_a.exists() && extra_a.is_dir(),
            "extra_write_dirs[0] must be pre-created: {}",
            extra_a.display()
        );
        assert!(
            extra_b.exists() && extra_b.is_dir(),
            "extra_write_dirs[1] must be pre-created even when its parent didn't exist: {}",
            extra_b.display()
        );
    }

    #[test]
    fn unsupported_remediation_uses_generic_message_on_windows() {
        // Pin the removal of the legacy Windows special case so a
        // future change has to delete this test on the way through.
        // Windows has a real backend;
        // the generic message is the right shape now that Windows reaches the
        // same surface as the other supported OSes.
        let s = unsupported_remediation("windows");
        assert!(
            s.contains("has no LPM sandbox backend"),
            "Windows must use the generic shape now that it has a backend: {s}",
        );
        assert!(
            !s.contains("isn't supported"),
            "legacy Windows-special wording must be gone: {s}",
        );
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
    fn validate_spec_rejects_relative_tmpdir_with_env_var_hint() {
        // Relative `tmpdir` almost always means the user's TMPDIR /
        // TMP / TEMP env var is misconfigured. Pin both the
        // rejection AND the env-var hint, so the actionable
        // remediation text doesn't get lost in a future refactor.
        // We deliberately fail loud rather than silently
        // canonicalizing a relative tmpdir, because silent
        // canonicalization would paper over the upstream env-var bug.
        let mut s = sample_spec();
        s.tmpdir = PathBuf::from("relative/tmp");
        let err = validate_spec(&s).expect_err("relative tmpdir must be rejected");
        let SandboxError::InvalidSpec { reason } = err else {
            panic!("expected InvalidSpec, got {err:?}");
        };
        assert!(
            reason.contains("tmpdir"),
            "reason must name the offending field: {reason}"
        );
        assert!(
            reason.contains("absolute"),
            "reason must say the path was non-absolute: {reason}"
        );
        // The actionable hint is the whole point of this variant:
        // without it the user sees "tmpdir must be absolute" and
        // doesn't know to look at their env vars.
        assert!(
            reason.contains("TMPDIR") || reason.contains("TMP") || reason.contains("TEMP"),
            "reason must hint at the TMPDIR / TMP / TEMP env var: {reason}"
        );
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

    /// Platform-portable "succeed immediately" command for noop /
    /// sandbox smoke tests. POSIX hosts have `true` on PATH;
    /// Windows ships `cmd.exe` in `%SYSTEMROOT%\System32` and we
    /// pass it through `cmd.exe /c exit 0`. Returns the program +
    /// args + minimum env passthrough required to actually run the
    /// child (Windows cmd.exe needs SYSTEMROOT/COMSPEC/WINDIR to
    /// resolve its own DLL load chain — these env vars must be passed
    /// through or the process fails to start).
    fn trivial_success_command() -> SandboxedCommand {
        let pass = |k: &str| -> (String, OsString) {
            (k.to_string(), std::env::var_os(k).unwrap_or_default())
        };
        #[cfg(unix)]
        {
            SandboxedCommand::new("true").envs_cleared([pass("PATH")])
        }
        #[cfg(windows)]
        {
            SandboxedCommand::new("cmd.exe")
                .arg("/D")
                .arg("/C")
                .arg("exit 0")
                .envs_cleared([
                    pass("PATH"),
                    pass("SYSTEMROOT"),
                    pass("COMSPEC"),
                    pass("WINDIR"),
                ])
        }
    }

    /// Platform-portable "definitely doesn't exist" program path
    /// for the spawn-failure structural test. The Unix form uses a
    /// POSIX-shaped sentinel; the Windows form uses a drive-rooted
    /// path so the OS path resolver actually treats it as absolute
    /// (a leading `/` on Windows resolves relative to the current
    /// drive's root, which is non-deterministic across hosts).
    fn nonexistent_program() -> &'static str {
        #[cfg(unix)]
        {
            "/does/not/exist/lpm-sandbox-test-probe"
        }
        #[cfg(windows)]
        {
            r"C:\does\not\exist\lpm-sandbox-test-probe.exe"
        }
    }

    #[test]
    fn noop_sandbox_runs_a_trivial_command() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled).unwrap();
        let mut child = sb
            .spawn(trivial_success_command())
            .expect("noop spawn must succeed");
        let status = child.wait().expect("wait");
        assert!(
            status.success(),
            "trivial success command must exit 0, got {status:?}"
        );
    }

    #[test]
    fn noop_sandbox_reports_spawn_failure_structurally() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled).unwrap();
        let cmd = SandboxedCommand::new(nonexistent_program());
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

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    #[test]
    fn factory_returns_unsupported_platform_on_unsupported_os() {
        let r = new_for_platform(sample_spec(), SandboxMode::Enforce);
        match r {
            Err(SandboxError::UnsupportedPlatform {
                platform,
                remediation,
            }) => {
                assert_eq!(platform, std::env::consts::OS);
                // single `--no-sandbox` flag.
                assert!(remediation.contains("--no-sandbox"));
                assert!(
                    !remediation.contains("--unsafe-full-env"),
                    "legacy partner flag must be gone: {remediation}",
                );
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_returns_seatbelt_backend_on_macos() {
        // Behavior-level tests for spawn + containment live in the
        // `macos` module's own tests; this one asserts factory wiring.
        let sb = new_for_platform(sample_spec(), SandboxMode::Enforce)
            .expect("macOS factory must succeed");
        assert_eq!(sb.backend_name(), "seatbelt");
        assert_eq!(sb.mode(), SandboxMode::Enforce);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn factory_returns_windows_backend_on_windows() {
        // real backend via Mandatory
        // Integrity Control + Job Object. Default options yield the
        // relaxed default — filesystem-write containment only,
        // network allowed. Construction has no kernel-version gate
        // (MIC has been in every Windows release since Vista), so
        // the only acceptable outcomes are `Ok` with backend name
        // `windows-il`. A failure here means the FFI binding broke;
        // surface it as a panic.
        let sb = new_for_platform(sample_spec(), SandboxMode::Enforce).expect(
            "Windows factory must succeed on a host that supports Mandatory Integrity Control",
        );
        assert_eq!(sb.backend_name(), "windows-il");
        assert_eq!(sb.mode(), SandboxMode::Enforce);
        assert_eq!(sb.posture(), SandboxPosture::Default);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn factory_returns_landlock_backend_on_linux() {
        // Default options give `Default` posture (V1 baseline).
        // Construction either succeeds (landlock V1 reachable) or
        // surfaces `KernelTooOld { required: "5.13" }` on hosts
        // where landlock is entirely disabled.
        match new_for_platform(sample_spec(), SandboxMode::Enforce) {
            Ok(sb) => {
                assert_eq!(sb.backend_name(), "landlock");
                assert_eq!(sb.mode(), SandboxMode::Enforce);
                // Default-default path returns `Default` posture —
                // V1 with filesystem rules only, no AccessNet.
                assert_eq!(sb.posture(), SandboxPosture::Default);
            }
            Err(SandboxError::KernelTooOld { required, .. }) => {
                // Landlock LSM disabled entirely; V1 probe failed.
                assert_eq!(required, "5.13");
            }
            Err(other) => panic!("unexpected factory error: {other:?}"),
        }
    }

    /// Every backend produced by the factory must return a sensible
    /// posture. NoopSandbox is Disabled; the real backends are Strict
    /// by default. The Degraded posture is
    /// reachable only via [`new_for_platform_with_options`] +
    /// `allow_degraded = true` on a Linux kernel < 6.7 — that path
    /// is tested in [`crate::linux::tests`].
    #[test]
    fn noop_sandbox_reports_disabled_posture() {
        let sb = new_for_platform(sample_spec(), SandboxMode::Disabled).unwrap();
        assert_eq!(sb.posture(), SandboxPosture::Disabled);
    }

    #[test]
    fn degraded_warning_line_format_is_grep_stable() {
        // Pin the exact format the install pipeline emits + log
        // scrapers parse. A whitespace / separator change here is
        // a wire-format break.
        let p = SandboxPosture::Degraded {
            kernel: "5.15.0-1063-aws".to_string(),
            abi: "v1",
            missing: "network-containment",
        };
        let line = p.degraded_warning_line().expect("Degraded → Some");
        assert_eq!(
            line,
            "warning: sandbox.degraded: kernel=5.15.0-1063-aws abi=v1 missing=network-containment policy=allow-degraded",
        );
    }

    #[test]
    fn degraded_warning_line_is_none_for_strict_and_disabled() {
        assert_eq!(SandboxPosture::Strict.degraded_warning_line(), None);
        assert_eq!(SandboxPosture::Disabled.degraded_warning_line(), None);
    }

    #[test]
    fn sandbox_options_default_is_strict_posture() {
        // The `Default` impl must reflect "don't accept degradation"
        // — installs that don't go through the config loader (eg.
        // unit tests) inherit the strict floor.
        let opts = SandboxOptions::default();
        assert!(!opts.allow_degraded);
    }

    #[test]
    fn sandbox_options_with_allow_degraded_sets_flag() {
        let opts = SandboxOptions::with_allow_degraded(true);
        assert!(opts.allow_degraded);
        let opts = SandboxOptions::with_allow_degraded(false);
        assert!(!opts.allow_degraded);
    }
}
