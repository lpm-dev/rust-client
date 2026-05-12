//! Filesystem-scoped sandbox for LPM post-install script execution.
//!
//! Phase 46 P5 shipped filesystem-write containment (Seatbelt on
//! macOS, landlock V1 on Linux). Phase 46.1 adds outbound network
//! denial on top — see the design note at
//! [`DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.1-sandbox-network-denial.md`](../../../../../../a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.1-sandbox-network-denial.md)
//! for the locked Q1-Q3 decisions and contract specifics.
//!
//! ## Network-denial scope (Phase 46.1)
//!
//! There is a **platform asymmetry** to be honest about:
//!
//! - **macOS** — Seatbelt's `(deny default)` covers every socket
//!   family / type. Dropping `(allow network*)` denies TCP, UDP,
//!   raw sockets, AF_PACKET, AF_NETLINK, DNS — everything outbound.
//!   Full outbound network denial.
//! - **Linux landlock V4** — `AccessNet::from_all(V4)` only handles
//!   `BindTcp` and `ConnectTcp`. UDP-based egress (raw `SOCK_DGRAM`,
//!   DNS-via-UDP, AF_PACKET, AF_NETLINK) **is NOT denied** by V4
//!   alone. The strict posture therefore enforces "filesystem +
//!   outbound TCP denial" on Linux V4, not full network denial.
//!
//! Closing the Linux UDP / raw / DNS-via-UDP gap requires a
//! second enforcement layer (seccomp-bpf), filed as **Phase 46.1.1**.
//! [`SandboxPosture::Strict`] therefore documents this asymmetry
//! at the trait-doc level, and `lpm doctor` reports it on every
//! Linux run so users see the real coverage rather than the
//! aspirational one.
//!
//! [`lpm-security`](../lpm_security/index.html) stays policy-only.
//!
//! The crate is intentionally narrow. Callers build a [`SandboxedCommand`]
//! (a platform-neutral description of the process they want to run),
//! obtain a [`Sandbox`] from [`new_for_platform`] (or
//! [`new_for_platform_with_options`] when the caller wants to thread
//! the Phase 46.1 `[sandbox] allow-degraded` knob through), then call
//! [`Sandbox::spawn`]. The backend decides how to apply containment:
//! macOS routes the spawn through `sandbox-exec`, and Linux installs a
//! landlock ruleset via `pre_exec` in the forked child.
//!
//! ## Backend coverage
//!
//! | Platform | [`SandboxMode::Enforce`] | [`SandboxMode::LogOnly`] | [`SandboxMode::Disabled`] |
//! |----------|--------------------------|---------------------------|----------------------------|
//! | macOS    | Seatbelt (`sandbox-exec`), `(deny default)` + narrow allows; **full outbound network denied** (Phase 46.1, no loopback exemption) — every socket family / type covered. | Seatbelt w/ `(allow (with report) default)` fallback | [`NoopSandbox`] |
//! | Linux    | landlock V4 (kernel 6.7+) — filesystem + **outbound TCP** denial (BindTcp + ConnectTcp). UDP / raw / AF_PACKET / AF_NETLINK / DNS-via-UDP are NOT denied by V4 alone — closing that gap is Phase 46.1.1's seccomp-bpf layer. Kernels < 6.7 return [`SandboxError::KernelTooOld`] by default; explicit opt-in via `[sandbox] allow-degraded = true` falls back to V1 filesystem-only with a one-line stderr warning per install. | [`SandboxError::ModeNotSupportedOnPlatform`] — no native observe-only | [`NoopSandbox`] |
//! | Windows  | [`SandboxError::UnsupportedPlatform`] — deferred to Phase 46.2 (Phase 46.1 left Windows out of scope; see design note) | [`SandboxError::UnsupportedPlatform`] | [`NoopSandbox`] |
//!
//! [`SandboxMode::Disabled`] always succeeds with a [`NoopSandbox`]:
//! the `--no-sandbox` escape hatch (Phase 46.1 rework: single flag —
//! the legacy `--unsafe-full-env` partner was collapsed per Q6 of the
//! DX redline) has to be reachable from every platform, including
//! Windows.
//!
//! ## Posture (Phase 46.1)
//!
//! [`Sandbox::posture`] reports whether the constructed backend
//! enforces the full Phase 46.1 contract ([`SandboxPosture::Strict`])
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

// Rule description is platform-neutral so macOS CI + developer-host
// test runs exercise it without a Linux kernel. The module is gated
// on `target_os = "linux"` for production builds (where `linux.rs`
// consumes it) and on `test` for any test build (so the rules unit
// tests run on the macOS developer host). Non-Linux production
// builds don't compile this module at all, which matches CLAUDE.md's
// cross-platform hygiene rule.
#[cfg(any(target_os = "linux", test))]
mod landlock_rules;

// Phase 46.1 posture-decision helper. Pure (string in, decision out),
// platform-neutral so the macOS-host unit tests exercise the same
// table that the Linux backend uses in production. Compiles under
// the same gate as `landlock_rules`: Linux production, plus any
// `test` build so the strict-vs-degraded table is testable on every
// developer's machine without spinning up a Linux VM. Non-Linux
// production builds skip the module — they have no consumer.
#[cfg(any(target_os = "linux", test))]
mod posture_decision;

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

/// Caller-tunable knobs the sandbox factory consumes alongside
/// [`SandboxSpec`] and [`SandboxMode`]. Phase 46.1 introduces this
/// struct so the install layer can thread the
/// `[sandbox] allow-degraded` config knob through to the Linux
/// backend without changing every call site that doesn't need it.
///
/// New fields land here with `Default` semantics matching the strict
/// (most-secure) interpretation — callers who do not set them
/// explicitly inherit the conservative posture.
#[derive(Debug, Clone, Default)]
pub struct SandboxOptions {
    /// Phase 46.1: opt-in escape hatch for the Linux backend on
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
    /// like Phase 46 P5 (filesystem + env containment).
    pub allow_degraded: bool,

    /// Phase 46.1 rework (2026-05-11): whether the constructed
    /// sandbox should deny outbound network from inside the
    /// lifecycle script.
    ///
    /// When `false` (the default), the sandbox enforces only the
    /// Phase 46 P5 contract: filesystem-write containment + env
    /// scrubbing. Outbound network is allowed. This is the shape
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
    /// See
    /// `DOCS/new-features/37-rust-client-RUNNER-VISION-phase46-DX.md`
    /// for the full scenario matrix and CLI / config / env
    /// precedence chain.
    pub deny_outbound_network: bool,
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
/// Reworked 2026-05-11 (Phase 46.1 rework): added
/// [`SandboxPosture::Default`] to distinguish "user picked the
/// relaxed mode" from "user picked strict but kernel forced a
/// fallback" ([`SandboxPosture::Degraded`]). Both have the same
/// runtime semantics (filesystem-only); the distinction matters
/// for doctor / warning text + telemetry classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxPosture {
    /// Phase 46.1 rework default: filesystem-write containment +
    /// env scrubbing. Outbound network **allowed** — the user
    /// picked the relaxed mode, either by accepting the default or
    /// by explicit `[sandbox] mode = "default"`.
    ///
    /// Same on-host runtime as Phase 46 P5. No per-install warning
    /// is emitted because this is a chosen state, not a fallback.
    Default,
    /// Phase 46.1 strict posture: filesystem-write containment +
    /// outbound network denial. Reached when the user opts into
    /// strict mode (`--strict-sandbox` / `--paranoid` /
    /// `[sandbox] mode = "strict"` / `LPM_STRICT_SANDBOX=1`).
    ///
    /// **Network-denial coverage is platform-asymmetric.** Strict
    /// means:
    ///
    /// - **macOS Seatbelt** — full outbound network denial. Every
    ///   socket family / type (TCP, UDP, raw, AF_PACKET,
    ///   AF_NETLINK, DNS) goes to the deny path under the
    ///   `(deny default)` rule.
    /// - **Linux landlock V4** — outbound **TCP** denial only.
    ///   The V4 ABI's `AccessNet::from_all` covers `BindTcp` and
    ///   `ConnectTcp`. UDP-based egress (`SOCK_DGRAM` for IPv4 +
    ///   IPv6, raw sockets, AF_PACKET, AF_NETLINK, DNS-via-UDP)
    ///   is NOT denied. Closing that gap is **Phase 46.1.1's
    ///   seccomp-bpf layer**, tracked at
    ///   `DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.1.1-seccomp-udp-denial.md`.
    ///
    /// `lpm doctor` surfaces this asymmetry on every run so users
    /// see the real platform coverage rather than the aspirational
    /// one. The runtime gate
    /// `tests/workflows/tests/sandbox_network_denial.rs` exercises
    /// the TCP path on both platforms; the UDP / raw-socket path
    /// gets its own workflow test alongside Phase 46.1.1.
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
    /// `--no-sandbox` escape hatch — Phase 46.1 rework collapsed
    /// the legacy `--unsafe-full-env` partner per Q6 — or platforms
    /// without a backend). Posture-aware UI surfaces this as
    /// "containment off" rather than conflating with strict.
    Disabled,
}

impl SandboxPosture {
    /// Render the Phase 46.1 per-install structured stderr warning
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
    /// No containment. Used only by the `--no-sandbox` escape
    /// hatch (Phase 46.1 rework: single flag, legacy
    /// `--unsafe-full-env` partner collapsed per Q6). Emits a loud
    /// CLI banner at the call site (not this crate's responsibility).
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

    /// The backend for this platform exists, but the requested
    /// [`SandboxMode`] has no implementation on this platform.
    /// Phase 46 P5 Chunk 4 introduces this for Linux LogOnly:
    /// landlock has no native observe-only primitive, so the honest
    /// answer is "reject the mode" rather than pseudo-mode it.
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
        /// (typically `--no-sandbox` — Phase 46.1 rework collapsed
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
/// Dispatch is `cfg`-gated per CLAUDE.md hygiene rule: each platform
/// arm pulls only its own backend module, and non-supported platforms
/// return [`SandboxError::UnsupportedPlatform`] directly without
/// compiling platform-specific code they don't have.
///
/// [`SandboxMode::Disabled`] always succeeds with a [`NoopSandbox`]
/// regardless of platform — the `--no-sandbox` escape hatch (Phase
/// 46.1 rework: single flag) must work everywhere, including Windows.
///
/// Callers that need to thread the Phase 46.1
/// `[sandbox] allow-degraded` knob through (install pipeline, doctor)
/// use [`new_for_platform_with_options`] instead.
pub fn new_for_platform(
    spec: SandboxSpec,
    mode: SandboxMode,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    new_for_platform_with_options(spec, mode, SandboxOptions::default())
}

/// Phase 46.1: as [`new_for_platform`] but accepts a
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
/// Phase 46 P5 Chunk 5: sandbox rules of the shape `(subpath
/// "{project}/.husky")` allow writes INSIDE `.husky`, but creating
/// `.husky` itself requires write on its parent (`{project}`) which
/// we deliberately DON'T grant (scripts would gain write on the
/// whole project tree). Scripts like `husky install` running on a
/// fresh project would fail without this helper — they'd try to
/// create `.husky` themselves and hit the sandbox rule gap.
///
/// Callers (build.rs production path + compat-corpus test fixtures)
/// invoke this once before spawning scripts. Paths that already
/// exist are left alone.
///
/// Errors surface as `SandboxError::InvalidSpec` with an actionable
/// reason so the caller can distinguish "sandbox couldn't prep the
/// filesystem" from "the sandbox itself failed."
pub fn prepare_writable_dirs(spec: &SandboxSpec) -> Result<(), SandboxError> {
    let candidates = [
        spec.project_dir.join(".husky"),
        spec.project_dir.join(".lpm"),
        spec.project_dir.join("node_modules"),
        spec.home_dir.join(".cache"),
        spec.home_dir.join(".node-gyp"),
        spec.home_dir.join(".npm"),
    ];
    for p in &candidates {
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
    }
    Ok(())
}

/// User-facing remediation string for [`SandboxError::UnsupportedPlatform`].
///
/// Centralized so unsupported platforms share consistent wording and
/// the CLI-side message test has a single source of truth.
///
/// Phase 46.1 rework (2026-05-11): the `--unsafe-full-env` partner
/// flag was collapsed into `--no-sandbox` (Q6), so the remediation
/// names a single flag now.
pub fn unsupported_remediation(platform: &str) -> String {
    match platform {
        "windows" => "sandbox enforcement isn't supported on Windows yet. Re-run with \
			 --no-sandbox to execute scripts without containment, or set \
			 script-policy = deny."
            .to_string(),
        _ => format!(
            "{platform} has no LPM sandbox backend. Re-run with \
			 --no-sandbox to execute scripts without containment, or set \
			 script-policy = deny."
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

    fn posture(&self) -> SandboxPosture {
        SandboxPosture::Disabled
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
        assert!(msg.contains("isn't supported"), "got: {msg}");
        // Phase 46.1 rework (2026-05-11): single `--no-sandbox` flag,
        // legacy `--unsafe-full-env` partner removed per Q6.
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
        // Phase 46.1 rework: single `--no-sandbox` flag.
        assert!(
            msg.contains("--no-sandbox"),
            "must point at the workaround: {msg}"
        );
    }

    #[test]
    fn unsupported_remediation_windows_says_not_supported_yet_and_names_escape_hatch() {
        let s = unsupported_remediation("windows");
        assert!(s.contains("isn't supported"));
        // Phase 46.1 rework: single `--no-sandbox` flag.
        assert!(s.contains("--no-sandbox"));
        assert!(
            !s.contains("--unsafe-full-env"),
            "legacy partner flag must be gone: {s}",
        );
        assert!(s.contains("script-policy = deny"));
    }

    #[test]
    fn unsupported_remediation_generic_unix_names_platform() {
        let s = unsupported_remediation("freebsd");
        assert!(s.contains("freebsd"));
        // Phase 46.1 rework: single `--no-sandbox` flag.
        assert!(s.contains("--no-sandbox"));
        assert!(
            !s.contains("--unsafe-full-env"),
            "legacy partner flag must be gone: {s}",
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
                // Phase 46.1 rework: single `--no-sandbox` flag.
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
        // Phase 46.1 rework (2026-05-11): default options give
        // `Default` posture (V1 baseline). Construction either
        // succeeds (landlock V1 reachable — the bar is low) or
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

    /// Phase 46.1: every backend produced by the factory must
    /// return a sensible posture. NoopSandbox is Disabled; the
    /// real backends are Strict by default. The Degraded posture is
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
