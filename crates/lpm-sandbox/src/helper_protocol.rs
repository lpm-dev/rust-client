//! Argv contract between the parent (`lpm.exe`) and the helper
//! (`lpm-sandbox-helper.exe`).
//!
//! Rust's stable `std::process::Command` builds the
//! child via `STARTUPINFOW`, not `STARTUPINFOEXW`. AppContainer's
//! `SECURITY_CAPABILITIES` must be attached via
//! `STARTUPINFOEX.lpAttributeList` carrying
//! `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, so the parent
//! invokes a separate helper binary that does the `CreateProcessW`
//! call directly. The argv shape below is the only IPC channel — no
//! sockets, no named pipes — so it has to be stable enough to refuse
//! mismatched parent/helper pairs loudly.
//!
//! The parser lives in the lib (not the bin file) so:
//!   1. Unit tests can pin the contract on any host (macOS / Linux
//!      CI runners build the workspace too) without spawning the
//!      helper.
//!   2. The parent-side `AppContainerSandbox::spawn` and the
//!      helper-side `main` share a single source of truth for the
//!      flag names + version constant.
//!
//! Module gating: Windows production builds compile this (the helper
//! bin consumes it) and every `cfg(test)` build (so the parser is
//! testable from a Linux developer host without a Windows kernel).
//! Non-Windows production builds skip it entirely.

#![cfg(any(target_os = "windows", test))]

use std::ffi::OsString;
use std::path::PathBuf;

/// Wire-version constant exchanged via `--protocol-version`.
///
/// The helper hard-codes this value and refuses any parent that
/// passes a different number. Catches the broken-state where someone
/// upgrades `lpm.exe` but the npm package's helper binary is stale
/// (or vice versa) — the failure surfaces as a clear "reinstall lpm"
/// error rather than an opaque AppContainer construction crash.
///
/// Bumping this constant requires coordinated work on both the
/// parent serializer ([`crate`]-side `AppContainerSandbox::spawn`)
/// and the helper-side parser; during development the only
/// valid value is `3`.
pub const PROTOCOL_VERSION: u32 = 3;

/// The only argument with which `lpm-sandbox-helper.exe` prints
/// [`HELPER_RELEASE`] and exits. A helper from before it knew this flag
/// exits with an argument error instead.
pub const RELEASE_FLAG: &str = "--version";

/// The release the helper was built for, as lpm of the same release
/// reports its own version, so that lpm can tell a helper an earlier
/// release left beside it, which still speaks [`PROTOCOL_VERSION`].
pub const HELPER_RELEASE: &str = match option_env!("LPM_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// Prefix for production AppContainer profile names. Each project and
/// package pair appends a digest of the two, so a package's scripts keep
/// one identity in a project, and the trees it was granted are recorded
/// per identity rather than left behind by a new one on every run.
pub const APPCONTAINER_NAME: &str = "LpmSandboxLifecycleChild";

/// How the helper should configure the lifecycle child's stdio
/// endpoints. The parent picks one per stream based on the
/// `SandboxedCommand` it was asked to spawn; the helper translates
/// to `STARTUPINFOW.hStd*` + `STARTF_USESTDHANDLES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// Inherit the helper's corresponding stream (which the parent
    /// inherited from its own parent).
    Inherit,
    /// Redirect to `NUL` — discards output / supplies empty input.
    Null,
    /// The parent attached a pipe to the helper for this stream;
    /// the helper forwards it to the child unchanged (the helper
    /// itself doesn't read/write the stream).
    Piped,
}

impl StdioMode {
    /// Spelling used in argv. Symmetric with [`StdioMode::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            StdioMode::Inherit => "inherit",
            StdioMode::Null => "null",
            StdioMode::Piped => "piped",
        }
    }

    /// Parse the canonical argv spelling. Returns `None` for any
    /// other input so the caller can surface a contract-mismatch
    /// error with the offending token.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "inherit" => Some(StdioMode::Inherit),
            "null" => Some(StdioMode::Null),
            "piped" => Some(StdioMode::Piped),
            _ => None,
        }
    }
}

/// Parsed helper argv. The helper builds this once at startup and
/// passes it to the AppContainer spawn routine; the parent-side
/// serializer ([`crate`]-side `AppContainerSandbox::spawn`) produces
/// exactly this shape via the round-trip flags below.
///
/// Stored env entries keep the raw `KEY=VALUE` form because Windows
/// `CreateProcessW`'s `lpEnvironment` block is itself a flat
/// `KEY=VALUE\0`-joined buffer — splitting and re-joining would be
/// pure round-trip waste. The split happens at the consumer
/// (`split_env_entry`) only when a structured form is actually
/// needed (e.g. the helper's `env_clear` simulation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Echoes [`PROTOCOL_VERSION`]. Verified equal before any other
    /// argv field is interpreted, so a version mismatch fails fast
    /// without touching AppContainer state.
    pub protocol_version: u32,
    /// AppContainer profile name (`--appcontainer-name`). Always
    /// a per-invocation name derived from [`APPCONTAINER_NAME`] in
    /// production; an argv flag for future-proofing + testability.
    pub appcontainer_name: String,
    /// Delete the AppContainer profile when the helper finishes, as a
    /// cleanup run does once a package leaves its project.
    pub delete_appcontainer_profile: bool,
    /// Where the helper keeps the trees this AppContainer was granted
    /// (`--grant-record`), so a later run revokes the ones its spec no
    /// longer grants, and a cleanup run all of them.
    pub grant_record: Option<PathBuf>,
    /// Where the parent finds which project and package the identity
    /// belongs to (`--identity-record`). A run records
    /// [`identity_owner`](Self::identity_owner) there, unless it is
    /// recorded, before it creates the profile or grants anything. A
    /// revoke-only run removes it once the identity is released. Each
    /// happens while the helper holds the identity, so a run and a cleanup
    /// of one identity can't leave it holding access no record names.
    pub identity_record: Option<PathBuf>,
    /// The project and package a run records the identity for
    /// (`--identity-project`, `--identity-package`). Present exactly when
    /// a run has an [`identity_record`](Self::identity_record).
    pub identity_owner: Option<IdentityOwner>,
    /// Revoke every tree [`grant_record`](Self::grant_record) lists,
    /// delete the profile if asked to, and exit without a program
    /// (`--revoke-only`).
    pub revoke_only: bool,
    /// Take back what a run of this identity that was stopped left set for
    /// as long as it lasted, keep its trees and its profile, and exit
    /// without a program (`--take-back-run`).
    pub take_back_run: bool,
    /// The named Job the run's script joins (`--job`). The process that
    /// started the helper made it and keeps it open, so it can end and
    /// count the script's processes once the helper is gone. The run
    /// records the name, so a cleanup ends what is left in the Job before
    /// it takes anything of the run back. Without it the helper makes a
    /// Job of its own. With `--take-back-run` it names the stopped run to
    /// take back, by the Job its script was in.
    pub job: Option<String>,
    /// Trees already swept of grants to AppContainer profiles that no
    /// longer exist, as earlier releases' per-run profiles left behind
    /// (`--sweep-record`), so each tree is swept once.
    pub sweep_record: Option<PathBuf>,
    /// Directories to grant the AppContainer SID *read* on (RXA)
    /// via DACL ACEs. Mirrors the cross-platform "reads broad"
    /// contract — see [`crate`]-side `readable_allow_set`.
    ///
    /// **Strict semantics:** a root-level grant failure on these
    /// dirs is FATAL — they're under our control (project_dir,
    /// ~/.nvm/versions, etc.) and a failure means the sandbox
    /// couldn't be constructed correctly. Surface the error
    /// instead of silently downgrading containment.
    pub readable_dirs: Vec<PathBuf>,
    /// Directories to grant Read+Execute on with **best-effort**
    /// semantics: a root-level grant failure is logged at WARN but
    /// the spawn proceeds. Used for PATH-derived tool dirs (e.g.
    /// `C:\Program Files\nodejs`) that are SYSTEM-owned and can't
    /// be DACL-modified by an unprivileged `lpm.exe`. The
    /// lifecycle child either succeeds (the user happened to have
    /// the tool installed in a user-writable location, or the
    /// script doesn't need the tool) or fails downstream with a
    /// clear "tool not found" message — both of which are better
    /// surface than a hard `lpm.exe` spawn failure that lists a
    /// Win32 error code.
    pub best_effort_readable_dirs: Vec<PathBuf>,
    /// Directories to grant *read + write + execute* on. Writable
    /// grants run after readable grants so an overlapping path keeps RW.
    pub writable_dirs: Vec<PathBuf>,
    /// Existing project secret files whose read access must be
    /// denied after the broad directory grants are applied.
    pub secret_read_denied_paths: Vec<PathBuf>,
    /// Lifecycle child's working directory. `None` means inherit
    /// the helper's CWD.
    pub working_dir: Option<PathBuf>,
    /// When `true`, the helper builds the child's env from
    /// [`envs`](Self::envs) alone (no inheritance from the helper's
    /// env block).
    pub env_clear: bool,
    /// `KEY=VALUE` env entries. Order is preserved — later entries
    /// for the same key override earlier ones, matching
    /// `Command::env` semantics.
    pub envs: Vec<OsString>,
    /// Stdin disposition for the child.
    pub stdio_stdin: StdioMode,
    /// Stdout disposition for the child.
    pub stdio_stdout: StdioMode,
    /// Stderr disposition for the child.
    pub stdio_stderr: StdioMode,
    /// When `true`, include the `InternetClient` capability SID in
    /// the child's `SECURITY_CAPABILITIES` (Default posture). When
    /// `false`, ship an empty capability list — full default-deny
    /// including outbound network (Strict posture).
    pub grant_internet_client: bool,
    /// Lifecycle child's program path. Always present (parser
    /// rejects argv without it).
    pub program: OsString,
    /// Lifecycle child's arguments.
    pub program_args: Vec<OsString>,
}

/// The project and package a sandbox identity belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityOwner {
    /// The project directory, absolute.
    pub project: PathBuf,
    /// The package's name.
    pub package: String,
}

/// Parse failure shapes. Each variant carries enough context for the
/// helper's stderr to name the offending field so users (or the
/// release-installer flow) can self-diagnose without reading the
/// helper source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// A flag that takes a value was given without one (last positional
    /// argv slot).
    #[error("flag `{0}` requires a value but none was provided")]
    MissingValue(String),
    /// An unrecognized flag was seen before the `--` separator.
    /// Unknown flags are NOT silently passed through to the lifecycle
    /// child because the parent contract is explicit about which
    /// flags are wire-stable; an unknown flag means the parent/helper
    /// versions have diverged.
    #[error(
        "unrecognized helper flag `{0}` — parent and helper protocol versions appear to be out of sync; reinstall lpm"
    )]
    UnknownFlag(String),
    /// A `--stdio-*` flag was given a value that's not
    /// `inherit|null|piped`.
    #[error("stdio flag `{flag}` received `{value}`, expected one of `inherit`, `null`, `piped`")]
    InvalidStdio {
        /// Which of `--stdio-stdin` / `--stdio-stdout` / `--stdio-stderr`.
        flag: String,
        /// The offending value.
        value: String,
    },
    /// Argv contained no `--` separator between helper flags and
    /// program argv. Refusing is safer than guessing where the
    /// program starts — a malformed parent might emit
    /// `--writable-dir <path> /bin/sh` and we'd silently run sh
    /// instead of treating it as a writable-dir value.
    #[error("argv is missing the `--` separator before the program path")]
    MissingSeparator,
    /// `--` separator was present but no program followed it.
    #[error("argv contains `--` but no program path follows it")]
    MissingProgram,
    /// A cleanup run (`--revoke-only`, `--take-back-run`) runs no program,
    /// so argv with one is a protocol break.
    #[error("`{0}` runs no program, but argv names one after `--`")]
    ProgramWithCleanup(&'static str),
    /// `--revoke-only` and `--take-back-run` are different cleanups.
    #[error("`--revoke-only` and `--take-back-run` were both given")]
    TwoCleanups,
    /// A script in a Job the caller holds outlives a stopped helper, so
    /// the run must have a record to name the Job in.
    #[error("`--job` needs `--grant-record`")]
    JobWithoutRecord,
    /// `--revoke-only` cleans up after every run of the identity, and finds
    /// their Jobs in the grant record.
    #[error("`--revoke-only` cleans up after every run, but `--job` names the Job of one")]
    JobWithRevokeOnly,
    /// `--take-back-run` leaves the identity for its next run.
    #[error("`--take-back-run` keeps the profile `--delete-appcontainer-profile` would delete")]
    TakeBackDeletesProfile,
    /// `--take-back-run` leaves the identity for its next run, which the
    /// identity record must keep naming.
    #[error("`--take-back-run` keeps the identity whose record `--identity-record` names")]
    TakeBackWithIdentityRecord,
    /// A revoke-only run removes the identity record once the identity is
    /// gone, and a profile that is kept would be left with no record.
    #[error(
        "`--revoke-only` removes `--identity-record` only with `--delete-appcontainer-profile`"
    )]
    IdentityRecordOutlivedByProfile,
    /// The project and package are what a run records for its identity.
    #[error(
        "`--identity-project` and `--identity-package` are what a run records in \
         `--identity-record`, so they need a run that has one"
    )]
    IdentityOwnerOutsideRecordedRun,
    /// A required flag was absent.
    #[error("required flag `--{0}` was not provided")]
    MissingFlag(String),
    /// `--protocol-version` value was not an integer.
    #[error("`--protocol-version` value `{0}` is not a valid u32")]
    ProtocolVersionParse(String),
    /// `--protocol-version` parsed but doesn't match
    /// [`PROTOCOL_VERSION`]. The error message names the remediation
    /// because this is the most common version-drift symptom: the
    /// user upgraded `lpm.exe` but the npm package's
    /// `lpm-sandbox-helper.exe` is stale (or vice versa).
    #[error(
        "protocol version mismatch: parent supplied {found}, this helper supports {expected}. Reinstall lpm so the helper binary matches `lpm.exe`."
    )]
    ProtocolVersionMismatch {
        /// Version number the parent claimed.
        found: u32,
        /// Version this helper actually supports
        /// ([`PROTOCOL_VERSION`]).
        expected: u32,
    },
    /// A grant named a path that isn't absolute, which would resolve
    /// against wherever the helper runs.
    #[error("helper flag `{flag}` needs an absolute path, not `{value}`")]
    NotAbsolute {
        /// The grant flag.
        flag: String,
        /// The path it was given.
        value: String,
    },
}

/// Parse `argv[1..]` into a [`HelperArgs`].
///
/// The function takes an iterator of `OsString` to match the shape
/// `std::env::args_os().skip(1)` produces; the helper main
/// dispatches the result of this function into the AppContainer
/// dance, and unit tests build synthetic argv vectors directly.
///
/// Recognized flags (each maps onto exactly one [`HelperArgs`] field):
///
/// | Flag | Value | Repetition |
/// |------|-------|------------|
/// | `--protocol-version` | u32 (must equal [`PROTOCOL_VERSION`]) | required, once |
/// | `--appcontainer-name` | non-empty string | required, once |
/// | `--delete-appcontainer-profile` | (flag) | optional |
/// | `--grant-record` | absolute path | optional, once (required by a cleanup run) |
/// | `--identity-record` | absolute path | optional, once (not with `--take-back-run`; with `--revoke-only`, needs `--delete-appcontainer-profile`) |
/// | `--identity-project` | absolute path | once with `--identity-record` on a run, otherwise refused |
/// | `--identity-package` | package name | once with `--identity-record` on a run, otherwise refused |
/// | `--revoke-only` | (flag) | optional cleanup run: no stdio flags, `--` or program |
/// | `--take-back-run` | (flag) | optional cleanup run: no stdio flags, `--` or program |
/// | `--sweep-record` | absolute path | optional, once |
/// | `--readable-dir` | absolute path | zero+ (strict — root-grant failure is fatal) |
/// | `--readable-dir-best-effort` | absolute path | zero+ (root-grant failure logs WARN + continues) |
/// | `--writable-dir` | absolute path | zero+ |
/// | `--secret-read-deny` | absolute path | zero+ |
/// | `--working-dir` | absolute path | optional, once |
/// | `--env-clear` | (flag) | optional |
/// | `--env` | `KEY=VALUE` string | zero+ |
/// | `--stdio-stdin` | `inherit\|null\|piped` | required, once |
/// | `--stdio-stdout` | `inherit\|null\|piped` | required, once |
/// | `--stdio-stderr` | `inherit\|null\|piped` | required, once |
/// | `--grant-internet-client` | (flag) | optional |
/// | `--` | (separator) | required |
///
/// Repeated single-value flags overwrite the previous value (last
/// wins). The parent currently never emits repeats; this behavior is
/// chosen for forward compatibility rather than as a feature.
pub fn parse_argv<I>(args: I) -> Result<HelperArgs, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut it = args.into_iter();
    let mut protocol_version: Option<u32> = None;
    let mut appcontainer_name: Option<String> = None;
    let mut delete_appcontainer_profile = false;
    let mut grant_record: Option<PathBuf> = None;
    let mut identity_record: Option<PathBuf> = None;
    let mut identity_project: Option<PathBuf> = None;
    let mut identity_package: Option<String> = None;
    let mut revoke_only = false;
    let mut take_back_run = false;
    let mut job: Option<String> = None;
    let mut sweep_record: Option<PathBuf> = None;
    let mut readable_dirs: Vec<PathBuf> = Vec::new();
    let mut best_effort_readable_dirs: Vec<PathBuf> = Vec::new();
    let mut writable_dirs: Vec<PathBuf> = Vec::new();
    let mut secret_read_denied_paths: Vec<PathBuf> = Vec::new();
    let mut working_dir: Option<PathBuf> = None;
    let mut env_clear = false;
    let mut envs: Vec<OsString> = Vec::new();
    let mut stdio_stdin: Option<StdioMode> = None;
    let mut stdio_stdout: Option<StdioMode> = None;
    let mut stdio_stderr: Option<StdioMode> = None;
    let mut grant_internet_client = false;
    let mut saw_separator = false;
    let mut program: Option<OsString> = None;
    let mut program_args: Vec<OsString> = Vec::new();

    while let Some(arg) = it.next() {
        // After the `--` separator everything is consumed verbatim
        // for the lifecycle child's argv.
        if saw_separator {
            if program.is_none() {
                program = Some(arg);
            } else {
                program_args.push(arg);
            }
            continue;
        }
        // We need to inspect the flag as a UTF-8 string. Helper-side
        // flags are always ASCII; if a caller managed to pass a
        // non-UTF-8 OsString as a flag name that's a protocol break
        // worth surfacing rather than silently misinterpreting.
        let flag = match arg.to_str() {
            Some(s) => s.to_owned(),
            None => return Err(ParseError::UnknownFlag(arg.to_string_lossy().into_owned())),
        };
        match flag.as_str() {
            "--" => {
                saw_separator = true;
            }
            "--protocol-version" => {
                let raw = next_value(&mut it, "--protocol-version")?;
                let raw_str = raw.to_string_lossy().into_owned();
                let parsed = raw_str
                    .parse::<u32>()
                    .map_err(|_| ParseError::ProtocolVersionParse(raw_str))?;
                protocol_version = Some(parsed);
            }
            "--appcontainer-name" => {
                let raw = next_value(&mut it, "--appcontainer-name")?;
                // AppContainer names are ASCII per Microsoft's
                // documented constraints (NamedObject naming +
                // filesystem-safe). Refuse non-UTF-8 to keep the
                // contract honest.
                let s = raw
                    .to_str()
                    .ok_or_else(|| ParseError::UnknownFlag("--appcontainer-name".to_string()))?
                    .to_owned();
                appcontainer_name = Some(s);
            }
            "--delete-appcontainer-profile" => {
                delete_appcontainer_profile = true;
            }
            "--grant-record" => {
                grant_record = Some(absolute_value(&mut it, "--grant-record")?);
            }
            "--identity-record" => {
                identity_record = Some(absolute_value(&mut it, "--identity-record")?);
            }
            "--identity-project" => {
                identity_project = Some(absolute_value(&mut it, "--identity-project")?);
            }
            "--identity-package" => {
                let raw = next_value(&mut it, "--identity-package")?;
                let package = raw
                    .to_str()
                    .ok_or_else(|| ParseError::UnknownFlag("--identity-package".to_string()))?;
                identity_package = Some(package.to_owned());
            }
            "--revoke-only" => {
                revoke_only = true;
            }
            "--take-back-run" => {
                take_back_run = true;
            }
            "--job" => {
                let raw = next_value(&mut it, "--job")?;
                let name = raw
                    .to_str()
                    .ok_or_else(|| ParseError::UnknownFlag("--job".to_string()))?;
                job = Some(name.to_owned());
            }
            "--sweep-record" => {
                sweep_record = Some(absolute_value(&mut it, "--sweep-record")?);
            }
            "--readable-dir" => {
                readable_dirs.push(absolute_value(&mut it, "--readable-dir")?);
            }
            "--readable-dir-best-effort" => {
                best_effort_readable_dirs
                    .push(absolute_value(&mut it, "--readable-dir-best-effort")?);
            }
            "--writable-dir" => {
                writable_dirs.push(absolute_value(&mut it, "--writable-dir")?);
            }
            "--secret-read-deny" => {
                secret_read_denied_paths.push(absolute_value(&mut it, "--secret-read-deny")?);
            }
            "--working-dir" => {
                let raw = next_value(&mut it, "--working-dir")?;
                working_dir = Some(PathBuf::from(raw));
            }
            "--env-clear" => {
                env_clear = true;
            }
            "--env" => {
                let raw = next_value(&mut it, "--env")?;
                envs.push(raw);
            }
            "--stdio-stdin" => {
                let raw = next_value(&mut it, "--stdio-stdin")?;
                stdio_stdin = Some(parse_stdio("--stdio-stdin", &raw)?);
            }
            "--stdio-stdout" => {
                let raw = next_value(&mut it, "--stdio-stdout")?;
                stdio_stdout = Some(parse_stdio("--stdio-stdout", &raw)?);
            }
            "--stdio-stderr" => {
                let raw = next_value(&mut it, "--stdio-stderr")?;
                stdio_stderr = Some(parse_stdio("--stdio-stderr", &raw)?);
            }
            "--grant-internet-client" => {
                grant_internet_client = true;
            }
            other => {
                return Err(ParseError::UnknownFlag(other.to_owned()));
            }
        }
    }

    let cleanup = match (revoke_only, take_back_run) {
        (true, true) => return Err(ParseError::TwoCleanups),
        (true, false) => Some("--revoke-only"),
        (false, true) => Some("--take-back-run"),
        (false, false) => None,
    };
    if take_back_run && delete_appcontainer_profile {
        return Err(ParseError::TakeBackDeletesProfile);
    }
    if let Some(cleanup) = cleanup {
        if job.is_some() && revoke_only {
            return Err(ParseError::JobWithRevokeOnly);
        }
        if saw_separator {
            return Err(ParseError::ProgramWithCleanup(cleanup));
        }
        if grant_record.is_none() {
            return Err(ParseError::MissingFlag("grant-record".to_string()));
        }
    } else if !saw_separator {
        return Err(ParseError::MissingSeparator);
    }
    if job.is_some() && grant_record.is_none() {
        return Err(ParseError::JobWithoutRecord);
    }
    if identity_record.is_some() {
        if take_back_run {
            return Err(ParseError::TakeBackWithIdentityRecord);
        }
        if revoke_only && !delete_appcontainer_profile {
            return Err(ParseError::IdentityRecordOutlivedByProfile);
        }
    }
    let recorded_run = identity_record.is_some() && cleanup.is_none();
    let identity_owner = match (identity_project, identity_package) {
        (Some(_), _) | (_, Some(_)) if !recorded_run => {
            return Err(ParseError::IdentityOwnerOutsideRecordedRun);
        }
        (Some(project), Some(package)) => Some(IdentityOwner { project, package }),
        (None, None) if !recorded_run => None,
        (None, _) => return Err(ParseError::MissingFlag("identity-project".to_string())),
        (Some(_), None) => return Err(ParseError::MissingFlag("identity-package".to_string())),
    };
    let program = match program {
        Some(program) => program,
        None if cleanup.is_some() => OsString::new(),
        None => return Err(ParseError::MissingProgram),
    };

    let protocol_version =
        protocol_version.ok_or_else(|| ParseError::MissingFlag("protocol-version".to_string()))?;
    if protocol_version != PROTOCOL_VERSION {
        return Err(ParseError::ProtocolVersionMismatch {
            found: protocol_version,
            expected: PROTOCOL_VERSION,
        });
    }

    let appcontainer_name = appcontainer_name
        .ok_or_else(|| ParseError::MissingFlag("appcontainer-name".to_string()))?;
    let stdio = |mode: Option<StdioMode>, flag: &str| match mode {
        Some(mode) => Ok(mode),
        None if cleanup.is_some() => Ok(StdioMode::Null),
        None => Err(ParseError::MissingFlag(flag.to_string())),
    };
    let stdio_stdin = stdio(stdio_stdin, "stdio-stdin")?;
    let stdio_stdout = stdio(stdio_stdout, "stdio-stdout")?;
    let stdio_stderr = stdio(stdio_stderr, "stdio-stderr")?;

    Ok(HelperArgs {
        protocol_version,
        appcontainer_name,
        delete_appcontainer_profile,
        grant_record,
        identity_record,
        identity_owner,
        revoke_only,
        take_back_run,
        job,
        sweep_record,
        readable_dirs,
        best_effort_readable_dirs,
        writable_dirs,
        secret_read_denied_paths,
        working_dir,
        env_clear,
        envs,
        stdio_stdin,
        stdio_stdout,
        stdio_stderr,
        grant_internet_client,
        program,
        program_args,
    })
}

fn next_value<I>(it: &mut I, flag: &str) -> Result<OsString, ParseError>
where
    I: Iterator<Item = OsString>,
{
    it.next()
        .ok_or_else(|| ParseError::MissingValue(flag.to_string()))
}

/// The value of `flag`, a grant, which must be an absolute path.
fn absolute_value<I>(it: &mut I, flag: &str) -> Result<PathBuf, ParseError>
where
    I: Iterator<Item = OsString>,
{
    let raw = next_value(it, flag)?;
    if !is_windows_absolute(&raw) {
        return Err(ParseError::NotAbsolute {
            flag: flag.to_string(),
            value: raw.to_string_lossy().into_owned(),
        });
    }
    Ok(PathBuf::from(raw))
}

/// Whether `path` is absolute as Windows reads it, whichever platform
/// parses it: a drive with a root, such as `C:\`, or a UNC, device or
/// verbatim path, such as `\\server\share` or `\\?\C:\`.
fn is_windows_absolute(path: &std::ffi::OsStr) -> bool {
    let separator = |byte: &u8| matches!(byte, b'\\' | b'/');
    match path.as_encoded_bytes() {
        [first, second, ..] if separator(first) && separator(second) => true,
        [drive, b':', root, ..] => drive.is_ascii_alphabetic() && separator(root),
        _ => false,
    }
}

fn parse_stdio(flag: &str, raw: &OsString) -> Result<StdioMode, ParseError> {
    let s = raw.to_str().ok_or_else(|| ParseError::InvalidStdio {
        flag: flag.to_string(),
        value: raw.to_string_lossy().into_owned(),
    })?;
    StdioMode::parse(s).ok_or_else(|| ParseError::InvalidStdio {
        flag: flag.to_string(),
        value: s.to_string(),
    })
}

/// Split a `KEY=VALUE` env entry into its two halves.
///
/// On Windows the underlying bytes are WTF-16; on Unix they're raw
/// bytes. Both forms find the FIRST `=` (codepoint U+003D) and split
/// there. Returns `None` if the entry has no `=` at all (treated as
/// a malformed entry by the helper — it would be dropped rather than
/// inserted into the child env).
///
/// Public for the helper's spawn path and for unit tests that pin
/// the splitting behavior cross-platform.
pub fn split_env_entry(entry: &std::ffi::OsStr) -> Option<(OsString, OsString)> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<u16> = entry.encode_wide().collect();
        let eq_pos = wide.iter().position(|&u| u == u16::from(b'='))?;
        let key = OsString::from_wide(&wide[..eq_pos]);
        let value = OsString::from_wide(&wide[eq_pos + 1..]);
        Some((key, value))
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let bytes = entry.as_bytes();
        let eq_pos = bytes.iter().position(|&b| b == b'=')?;
        let key = OsString::from_vec(bytes[..eq_pos].to_vec());
        let value = OsString::from_vec(bytes[eq_pos + 1..].to_vec());
        Some((key, value))
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        // Test-only fallback for platforms with neither byte nor
        // wide OsStr access (e.g. WASI). The lib's outer cfg gate
        // already excludes production builds on these platforms;
        // this arm exists so the test cfg on a hypothetical such
        // host still compiles cleanly.
        let s = entry.to_str()?;
        let (k, v) = s.split_once('=')?;
        Some((OsString::from(k), OsString::from(v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(|s| OsString::from(*s)).collect()
    }

    fn minimal_required_flags() -> Vec<&'static str> {
        vec![
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild",
            "--stdio-stdin",
            "null",
            "--stdio-stdout",
            "inherit",
            "--stdio-stderr",
            "inherit",
            "--",
            "C:/Windows/System32/cmd.exe",
        ]
    }

    #[test]
    fn parse_argv_accepts_a_revoke_only_run_without_stdio_or_program() {
        let parsed = parse_argv(make_argv(&[
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild-0123",
            "--grant-record",
            "C:/Users/me/.lpm/sandbox/appcontainers/LpmSandboxLifecycleChild-0123.grants.json",
            "--revoke-only",
            "--delete-appcontainer-profile",
        ]))
        .expect("a revoke-only argv must parse");
        assert!(parsed.revoke_only);
        assert!(parsed.delete_appcontainer_profile);
        assert!(parsed.grant_record.is_some());
        assert!(parsed.program.is_empty());
        assert_eq!(parsed.stdio_stdin, StdioMode::Null);
    }

    #[test]
    fn parse_argv_refuses_a_revoke_only_run_without_a_record_or_with_a_program() {
        let base = [
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild-0123",
            "--revoke-only",
        ];
        assert_eq!(
            parse_argv(make_argv(&base)).unwrap_err(),
            ParseError::MissingFlag("grant-record".to_string())
        );
        let mut with_program = base.to_vec();
        with_program.extend([
            "--grant-record",
            "C:/record.json",
            "--",
            "C:/Windows/System32/cmd.exe",
        ]);
        assert_eq!(
            parse_argv(make_argv(&with_program)).unwrap_err(),
            ParseError::ProgramWithCleanup("--revoke-only")
        );
    }

    #[test]
    fn parse_argv_accepts_a_take_back_run_as_it_does_a_revoke_only_one() {
        let base = [
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild-0123",
            "--take-back-run",
        ];
        assert_eq!(
            parse_argv(make_argv(&base)).unwrap_err(),
            ParseError::MissingFlag("grant-record".to_string())
        );
        let mut recorded = base.to_vec();
        recorded.extend(["--grant-record", "C:/record.json"]);

        let parsed = parse_argv(make_argv(&recorded)).expect("a take-back argv must parse");

        assert!(parsed.take_back_run && !parsed.revoke_only);
        assert!(parsed.program.is_empty());
        assert_eq!(parsed.stdio_stdin, StdioMode::Null);
        let mut with_program = recorded.clone();
        with_program.extend(["--", "C:/Windows/System32/cmd.exe"]);
        assert_eq!(
            parse_argv(make_argv(&with_program)).unwrap_err(),
            ParseError::ProgramWithCleanup("--take-back-run")
        );
        let mut both = recorded.clone();
        both.push("--revoke-only");
        assert_eq!(
            parse_argv(make_argv(&both)).unwrap_err(),
            ParseError::TwoCleanups
        );
        let mut deleting = recorded;
        deleting.push("--delete-appcontainer-profile");
        assert_eq!(
            parse_argv(make_argv(&deleting)).unwrap_err(),
            ParseError::TakeBackDeletesProfile
        );
    }

    #[test]
    fn parse_argv_takes_a_job_for_a_run_and_for_a_take_back_of_one() {
        let identity = [
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild-0123",
            "--grant-record",
            "C:/record.json",
        ];
        let job = ["--job", r"Global\LpmSandboxRun-1"];
        let program = [
            "--stdio-stdin",
            "null",
            "--stdio-stdout",
            "null",
            "--stdio-stderr",
            "null",
            "--",
            "C:/Windows/System32/cmd.exe",
        ];
        let argv = |parts: &[&[&'static str]]| make_argv(&parts.concat());

        assert_eq!(
            parse_argv(argv(&[&identity, &job, &program])).unwrap().job,
            Some(r"Global\LpmSandboxRun-1".to_string())
        );
        assert_eq!(parse_argv(argv(&[&identity, &program])).unwrap().job, None);
        assert_eq!(
            parse_argv(argv(&[&identity[..4], &job, &program])).unwrap_err(),
            ParseError::JobWithoutRecord
        );
        let taken_back = parse_argv(argv(&[&identity, &job, &["--take-back-run"]])).unwrap();
        assert!(taken_back.take_back_run);
        assert_eq!(taken_back.job, Some(r"Global\LpmSandboxRun-1".to_string()));
        assert_eq!(
            parse_argv(argv(&[&identity, &job, &["--revoke-only"]])).unwrap_err(),
            ParseError::JobWithRevokeOnly
        );
    }

    const IDENTITY: [&str; 6] = [
        "--protocol-version",
        "3",
        "--appcontainer-name",
        "LpmSandboxLifecycleChild-0123",
        "--grant-record",
        "C:/records/LpmSandboxLifecycleChild-0123.grants.json",
    ];
    const IDENTITY_RECORD: [&str; 2] = [
        "--identity-record",
        "C:/records/LpmSandboxLifecycleChild-0123.identity.json",
    ];
    const OWNER: [&str; 4] = [
        "--identity-project",
        "C:/work/app",
        "--identity-package",
        "@scope/pkg",
    ];
    const PROGRAM: [&str; 8] = [
        "--stdio-stdin",
        "null",
        "--stdio-stdout",
        "null",
        "--stdio-stderr",
        "null",
        "--",
        "C:/Windows/System32/cmd.exe",
    ];
    const RELEASE: [&str; 2] = ["--revoke-only", "--delete-appcontainer-profile"];

    fn concat(parts: &[&[&'static str]]) -> Vec<OsString> {
        make_argv(&parts.concat())
    }

    #[test]
    fn parse_argv_takes_an_identity_record_with_its_owner_for_a_run_and_alone_for_a_release() {
        let run = parse_argv(concat(&[&IDENTITY, &IDENTITY_RECORD, &OWNER, &PROGRAM]))
            .expect("a run that records its identity must parse");
        let released = parse_argv(concat(&[&IDENTITY, &IDENTITY_RECORD, &RELEASE]))
            .expect("a release that removes the identity's record must parse");
        let unrecorded = parse_argv(concat(&[&IDENTITY, &PROGRAM])).unwrap();

        let record = Some(PathBuf::from(IDENTITY_RECORD[1]));
        assert_eq!(run.identity_record, record);
        assert_eq!(
            run.identity_owner,
            Some(IdentityOwner {
                project: PathBuf::from("C:/work/app"),
                package: "@scope/pkg".to_string(),
            })
        );
        assert_eq!(released.identity_record, record);
        assert_eq!(released.identity_owner, None);
        assert_eq!(unrecorded.identity_record, None);
        assert_eq!(unrecorded.identity_owner, None);
    }

    #[test]
    fn parse_argv_refuses_an_identity_record_a_run_or_release_would_leave_wrong() {
        let refused = |parts: &[&[&'static str]]| parse_argv(concat(parts)).unwrap_err();

        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &PROGRAM]),
            ParseError::MissingFlag("identity-project".to_string())
        );
        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &OWNER[..2], &PROGRAM]),
            ParseError::MissingFlag("identity-package".to_string())
        );
        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &OWNER[2..], &PROGRAM]),
            ParseError::MissingFlag("identity-project".to_string())
        );
        assert_eq!(
            refused(&[&IDENTITY, &OWNER, &PROGRAM]),
            ParseError::IdentityOwnerOutsideRecordedRun
        );
        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &OWNER, &RELEASE]),
            ParseError::IdentityOwnerOutsideRecordedRun
        );
        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &RELEASE[..1]]),
            ParseError::IdentityRecordOutlivedByProfile
        );
        assert_eq!(
            refused(&[&IDENTITY, &IDENTITY_RECORD, &["--take-back-run"]]),
            ParseError::TakeBackWithIdentityRecord
        );
        for flag in ["--identity-record", "--identity-project"] {
            assert!(
                matches!(
                    refused(&[&IDENTITY, &[flag, "relative/path"], &PROGRAM]),
                    ParseError::NotAbsolute { .. }
                ),
                "{flag}"
            );
        }
    }

    #[test]
    fn parse_argv_takes_the_records_as_absolute_paths() {
        for flag in ["--grant-record", "--sweep-record"] {
            let mut argv = minimal_required_flags();
            argv.splice(0..0, [flag, "relative/record.json"]);
            assert!(
                matches!(
                    parse_argv(make_argv(&argv)).unwrap_err(),
                    ParseError::NotAbsolute { .. }
                ),
                "{flag}"
            );
            let mut argv = minimal_required_flags();
            argv.splice(0..0, [flag, "C:/Users/me/.lpm/record.json"]);
            let parsed = parse_argv(make_argv(&argv)).unwrap();
            let recorded = if flag == "--grant-record" {
                parsed.grant_record
            } else {
                parsed.sweep_record
            };
            assert_eq!(
                recorded,
                Some(PathBuf::from("C:/Users/me/.lpm/record.json"))
            );
        }
    }

    #[test]
    fn parse_argv_accepts_minimal_required_flags() {
        let argv = make_argv(&minimal_required_flags());
        let parsed = parse_argv(argv).expect("minimal argv must parse");
        assert_eq!(parsed.protocol_version, PROTOCOL_VERSION);
        assert_eq!(parsed.appcontainer_name, APPCONTAINER_NAME);
        assert!(!parsed.delete_appcontainer_profile);
        assert_eq!(parsed.stdio_stdin, StdioMode::Null);
        assert_eq!(parsed.stdio_stdout, StdioMode::Inherit);
        assert_eq!(parsed.stdio_stderr, StdioMode::Inherit);
        assert_eq!(
            parsed.program,
            OsString::from("C:/Windows/System32/cmd.exe")
        );
        assert!(parsed.program_args.is_empty());
        assert!(parsed.readable_dirs.is_empty());
        assert!(parsed.best_effort_readable_dirs.is_empty());
        assert!(parsed.writable_dirs.is_empty());
        assert!(parsed.secret_read_denied_paths.is_empty());
        assert!(parsed.envs.is_empty());
        assert!(!parsed.env_clear);
        assert!(!parsed.grant_internet_client);
        assert!(parsed.working_dir.is_none());
    }

    #[test]
    fn parse_argv_collects_best_effort_readable_dirs_separately_from_strict() {
        let mut parts = minimal_required_flags();
        parts.splice(
            10..10,
            [
                "--readable-dir",
                "C:/projects/p",
                "--readable-dir-best-effort",
                "C:/Program Files/nodejs",
                "--readable-dir-best-effort",
                "C:/Program Files/Git/cmd",
            ]
            .iter()
            .copied(),
        );
        let parsed = parse_argv(make_argv(&parts)).expect("argv must parse");
        assert_eq!(
            parsed.readable_dirs,
            vec![PathBuf::from("C:/projects/p")],
            "strict readable_dirs must NOT mix with best-effort variant",
        );
        assert_eq!(
            parsed.best_effort_readable_dirs,
            vec![
                PathBuf::from("C:/Program Files/nodejs"),
                PathBuf::from("C:/Program Files/Git/cmd"),
            ],
            "best-effort entries are collected in their own bucket",
        );
    }

    #[test]
    fn parse_argv_refuses_a_grant_that_is_not_an_absolute_path() {
        for flag in [
            "--readable-dir",
            "--readable-dir-best-effort",
            "--writable-dir",
            "--secret-read-deny",
        ] {
            for path in [".", "tools", "C:tools", "/tools", "\\tools"] {
                let mut parts = minimal_required_flags();
                parts.splice(10..10, [flag, path].iter().copied());
                let error = parse_argv(make_argv(&parts)).expect_err("a relative grant");
                assert!(
                    matches!(&error, ParseError::NotAbsolute { flag: named, .. } if named == flag),
                    "{flag} {path}: {error}"
                );
            }
            for path in [
                "C:/projects/p",
                "C:\\projects\\p",
                "\\\\?\\C:\\projects\\p",
                "\\\\server\\share\\tools",
            ] {
                let mut parts = minimal_required_flags();
                parts.splice(10..10, [flag, path].iter().copied());
                parse_argv(make_argv(&parts))
                    .unwrap_or_else(|error| panic!("{flag} {path}: {error}"));
            }
        }
    }

    #[test]
    fn parse_argv_collects_repeated_dir_flags_in_order() {
        let mut parts = minimal_required_flags();
        parts.splice(
            10..10,
            [
                "--readable-dir",
                "C:/projects/p",
                "--writable-dir",
                "C:/projects/p/node_modules",
                "--writable-dir",
                "C:/projects/p/.husky",
                "--readable-dir",
                "C:/users/u/.nvm/versions",
            ]
            .iter()
            .copied(),
        );
        let parsed = parse_argv(make_argv(&parts)).expect("argv must parse");
        assert_eq!(
            parsed.readable_dirs,
            vec![
                PathBuf::from("C:/projects/p"),
                PathBuf::from("C:/users/u/.nvm/versions"),
            ],
        );
        assert_eq!(
            parsed.writable_dirs,
            vec![
                PathBuf::from("C:/projects/p/node_modules"),
                PathBuf::from("C:/projects/p/.husky"),
            ],
        );
    }

    #[test]
    fn parse_argv_accepts_repeated_secret_read_denials() {
        let mut parts = minimal_required_flags();
        parts.splice(
            10..10,
            [
                "--secret-read-deny",
                "C:/projects/p/.env",
                "--secret-read-deny",
                "C:/projects/p/deploy.pem",
            ]
            .iter()
            .copied(),
        );

        let parsed = parse_argv(make_argv(&parts))
            .expect("secret denial paths must round-trip through argv");
        assert_eq!(
            parsed.secret_read_denied_paths,
            vec![
                PathBuf::from("C:/projects/p/.env"),
                PathBuf::from("C:/projects/p/deploy.pem"),
            ]
        );
    }

    #[test]
    fn parse_argv_collects_env_entries_preserving_value_equals_signs() {
        let mut parts = minimal_required_flags();
        parts.splice(
            10..10,
            ["--env", "FOO=bar", "--env", "EQUATION=a=b=c"]
                .iter()
                .copied(),
        );
        let parsed = parse_argv(make_argv(&parts)).expect("argv must parse");
        assert_eq!(
            parsed.envs,
            vec![OsString::from("FOO=bar"), OsString::from("EQUATION=a=b=c")]
        );
    }

    #[test]
    fn parse_argv_treats_boolean_flags_as_boolean_flags() {
        let mut parts = minimal_required_flags();
        parts.splice(
            10..10,
            [
                "--env-clear",
                "--grant-internet-client",
                "--delete-appcontainer-profile",
            ]
            .iter()
            .copied(),
        );
        let parsed = parse_argv(make_argv(&parts)).expect("argv must parse");
        assert!(parsed.env_clear);
        assert!(parsed.grant_internet_client);
        assert!(parsed.delete_appcontainer_profile);
    }

    #[test]
    fn parse_argv_captures_program_args_after_separator() {
        let mut parts = minimal_required_flags();
        parts.extend(["/c", "echo", "hello world"]);
        let parsed = parse_argv(make_argv(&parts)).expect("argv must parse");
        assert_eq!(
            parsed.program,
            OsString::from("C:/Windows/System32/cmd.exe")
        );
        assert_eq!(
            parsed.program_args,
            vec![
                OsString::from("/c"),
                OsString::from("echo"),
                OsString::from("hello world"),
            ]
        );
    }

    #[test]
    fn parse_argv_rejects_protocol_version_mismatch_with_named_remediation() {
        let mut parts = minimal_required_flags();
        // Bump the version value but keep every other required field.
        // Position 1 is the value slot right after `--protocol-version`.
        parts[1] = "999";
        let err = parse_argv(make_argv(&parts)).expect_err("mismatch must error");
        match err {
            ParseError::ProtocolVersionMismatch { found, expected } => {
                assert_eq!(found, 999);
                assert_eq!(expected, PROTOCOL_VERSION);
            }
            other => panic!("expected ProtocolVersionMismatch, got {other:?}"),
        }
        // The user-facing error text must name the remediation
        // ("reinstall lpm") so a stale-helper situation is
        // self-diagnosable from stderr alone.
        let rendered = format!("{}", err);
        assert!(
            rendered.contains("protocol version") && rendered.contains("Reinstall lpm"),
            "ProtocolVersionMismatch Display must name remediation; got: {rendered}",
        );
    }

    #[test]
    fn parse_argv_rejects_unparseable_protocol_version() {
        let mut parts = minimal_required_flags();
        parts[1] = "abc";
        let err = parse_argv(make_argv(&parts)).expect_err("non-u32 must error");
        assert_eq!(err, ParseError::ProtocolVersionParse("abc".to_string()));
    }

    #[test]
    fn parse_argv_rejects_unknown_flag_naming_offender() {
        let mut parts = minimal_required_flags();
        parts.insert(0, "--unknown-flag");
        let err = parse_argv(make_argv(&parts)).expect_err("unknown flag must error");
        assert_eq!(err, ParseError::UnknownFlag("--unknown-flag".to_string()));
    }

    #[test]
    fn parse_argv_rejects_missing_separator() {
        // Drop the `--` and the program token.
        let parts: Vec<&str> = minimal_required_flags()
            .into_iter()
            .filter(|p| *p != "--" && *p != "C:/Windows/System32/cmd.exe")
            .collect();
        let err = parse_argv(make_argv(&parts)).expect_err("missing `--` must error");
        assert_eq!(err, ParseError::MissingSeparator);
    }

    #[test]
    fn parse_argv_rejects_separator_without_program() {
        // Keep `--` but drop the program token.
        let parts: Vec<&str> = minimal_required_flags()
            .into_iter()
            .filter(|p| *p != "C:/Windows/System32/cmd.exe")
            .collect();
        let err = parse_argv(make_argv(&parts)).expect_err("`--` without program must error");
        assert_eq!(err, ParseError::MissingProgram);
    }

    #[test]
    fn parse_argv_rejects_flag_with_missing_value_at_argv_end() {
        let parts = vec![
            "--protocol-version",
            // Missing value for --protocol-version — it's the last
            // token, so `next_value` returns None.
        ];
        let err = parse_argv(make_argv(&parts)).expect_err("missing value must error");
        assert_eq!(
            err,
            ParseError::MissingValue("--protocol-version".to_string())
        );
    }

    #[test]
    fn parse_argv_rejects_invalid_stdio_value_naming_flag_and_value() {
        let mut parts = minimal_required_flags();
        // Replace the --stdio-stdin value (slot 5 in the minimal vec).
        parts[5] = "tee-stderr";
        let err = parse_argv(make_argv(&parts)).expect_err("bad stdio value must error");
        match err {
            ParseError::InvalidStdio { flag, value } => {
                assert_eq!(flag, "--stdio-stdin");
                assert_eq!(value, "tee-stderr");
            }
            other => panic!("expected InvalidStdio, got {other:?}"),
        }
    }

    #[test]
    fn parse_argv_requires_each_stdio_flag_individually() {
        // Drop --stdio-stderr + its value; keep stdin + stdout.
        let parts: Vec<&str> = vec![
            "--protocol-version",
            "3",
            "--appcontainer-name",
            "LpmSandboxLifecycleChild",
            "--stdio-stdin",
            "null",
            "--stdio-stdout",
            "inherit",
            "--",
            "C:/Windows/System32/cmd.exe",
        ];
        let err = parse_argv(make_argv(&parts)).expect_err("missing stdio-stderr must error");
        assert_eq!(err, ParseError::MissingFlag("stdio-stderr".to_string()));
    }

    #[test]
    fn parse_argv_requires_appcontainer_name() {
        let parts: Vec<&str> = vec![
            "--protocol-version",
            "3",
            "--stdio-stdin",
            "null",
            "--stdio-stdout",
            "inherit",
            "--stdio-stderr",
            "inherit",
            "--",
            "C:/Windows/System32/cmd.exe",
        ];
        let err = parse_argv(make_argv(&parts)).expect_err("missing name must error");
        assert_eq!(
            err,
            ParseError::MissingFlag("appcontainer-name".to_string())
        );
    }

    #[test]
    fn split_env_entry_isolates_first_equals_only() {
        let (k, v) =
            split_env_entry(std::ffi::OsStr::new("KEY=a=b=c")).expect("entry with `=` must split");
        assert_eq!(k, OsString::from("KEY"));
        assert_eq!(v, OsString::from("a=b=c"));
    }

    #[test]
    fn split_env_entry_returns_none_when_no_equals() {
        assert!(split_env_entry(std::ffi::OsStr::new("MALFORMED")).is_none());
    }

    #[test]
    fn split_env_entry_allows_empty_value() {
        let (k, v) =
            split_env_entry(std::ffi::OsStr::new("KEY=")).expect("trailing `=` is a valid split");
        assert_eq!(k, OsString::from("KEY"));
        assert_eq!(v, OsString::new());
    }

    #[test]
    fn stdio_mode_roundtrips_canonical_strings() {
        for mode in [StdioMode::Inherit, StdioMode::Null, StdioMode::Piped] {
            assert_eq!(StdioMode::parse(mode.as_str()), Some(mode));
        }
    }
}
