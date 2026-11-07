//! Package managers started by a tool that `lpm dlx` or `lpm exec` runs.
//!
//! Scaffolders install the projects they generate with whichever package
//! manager they detect, so the dependencies' lifecycle scripts would run
//! under that manager's rules instead of LPM's: npm 11 and older run every
//! dependency script, and a tool can approve builds for pnpm before it
//! calls `pnpm install`. The tool's PATH therefore gets shims for the
//! package managers installed on this machine. Installs, clean installs
//! and run-a-package commands go to `lpm install`, `lpm ci`, `lpm exec` or
//! `lpm dlx`, so dependency scripts follow LPM's approvals; every other
//! command, and any flag this module does not translate, runs the real
//! binary. When the tool exits, LPM lists the package-manager commands it
//! ran and any script approvals it wrote.
//!
//! The tool itself is trusted code with the user's privileges. The shims
//! keep LPM's approval rules for the third-party scripts its installs
//! would run; they are not a boundary against the tool.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::install_ui;

/// File that marks a directory as LPM shims. The real-binary lookup and
/// nested LPM commands skip every marked PATH directory, which keeps a
/// shim from finding itself even when a tool strips the environment.
const SHIM_MARKER: &str = ".lpm-nested-pm-shims";
/// File the shims append one [`LogEntry`] line to per command.
pub(crate) const LOG_ENV: &str = "LPM_NESTED_PM_LOG";
/// When the tool started, in nanoseconds since the Unix epoch.
const STARTED_ENV: &str = "LPM_NESTED_PM_STARTED";
const USER_AGENT_ENV: &str = "npm_config_user_agent";

const MANAGERS: &[&str] = &[
    "npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "bun", "bunx",
];
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_SHIM_BYTES: u64 = 64 * 1024;

/// The `npm_config_user_agent` LPM gives the tools it runs, in the
/// `<pm>/<version> npm/? node/<version> <platform> <arch>` shape pnpm and
/// Yarn use. Tools that pick the package manager from the first token can
/// then call `lpm` directly.
pub(crate) fn user_agent() -> String {
    format!(
        "lpm/{} npm/? node/? {} {}",
        env!("CARGO_PKG_VERSION"),
        node_platform(std::env::consts::OS),
        node_arch(std::env::consts::ARCH),
    )
}

fn node_platform(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn node_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "powerpc64" => "ppc64",
        other => other,
    }
}

/// Shims and the command log for one tool run.
pub(crate) struct NestedPmSession {
    shim_dir: PathBuf,
    log: tempfile::NamedTempFile,
}

impl NestedPmSession {
    /// Shims for the package managers found on `path`. `None` when none
    /// is installed, so the tool sees the same commands it would without
    /// LPM.
    pub(crate) fn prepare(path: &OsStr) -> Result<Option<Self>, LpmError> {
        let managers: Vec<&str> = MANAGERS
            .iter()
            .copied()
            .filter(|manager| find_on_path(manager, path).is_some())
            .collect();
        if managers.is_empty() {
            return Ok(None);
        }
        let lpm = std::env::current_exe()?;
        let shim_dir = ensure_shim_dir(&lpm, &managers)?;
        let log = tempfile::Builder::new()
            .prefix("lpm-nested-pm-")
            .suffix(".jsonl")
            .tempfile()?;
        Ok(Some(Self { shim_dir, log }))
    }

    /// Put the shims first on `command`'s PATH and point them at the log.
    pub(crate) fn apply(&self, command: &mut Command) -> Result<(), LpmError> {
        let inherited = command
            .get_envs()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
            .and_then(|(_, value)| value.map(OsStr::to_os_string))
            .or_else(|| std::env::var_os("PATH"))
            .unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.shim_dir.clone()).chain(std::env::split_paths(&inherited)),
        )
        .map_err(|error| {
            LpmError::Script(format!(
                "could not add package-manager shims to PATH: {error}"
            ))
        })?;
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        command
            .env("PATH", path)
            .env(LOG_ENV, self.log.path())
            .env(STARTED_ENV, started.to_string());
        Ok(())
    }

    /// Commands the tool's package-manager calls ran, in order.
    pub(crate) fn entries(&self) -> Log {
        read_log(self.log.path())
    }
}

/// Sets the honest user agent on a tool's command, with or without shims.
pub(crate) fn apply_user_agent(command: &mut Command) {
    command.env(USER_AGENT_ENV, user_agent());
}

fn ensure_shim_dir(lpm: &Path, managers: &[&str]) -> Result<PathBuf, LpmError> {
    let mut identity = Sha256::new();
    identity.update(lpm.as_os_str().as_encoded_bytes());
    identity.update([0]);
    identity.update(env!("CARGO_PKG_VERSION").as_bytes());
    for manager in managers {
        identity.update([0]);
        identity.update(manager.as_bytes());
    }
    let key = hex::encode(&identity.finalize()[..8]);
    let dir = lpm_common::LpmRoot::from_env()?
        .cache_root()
        .join("nested-pm")
        .join(key);
    std::fs::create_dir_all(&dir)?;
    let marker = dir.join(SHIM_MARKER);
    if !marker.is_file() {
        lpm_common::write_file_atomic(&marker, b"LPM package-manager shims\n")?;
    }
    for manager in managers {
        let target = dir.join(shim_file_name(manager));
        let content = shim_script(lpm, manager);
        if lpm_common::read_file_capped(&target, MAX_SHIM_BYTES)
            .is_ok_and(|existing| existing == content)
        {
            continue;
        }
        lpm_common::write_file_atomic_with_options(
            &target,
            &content,
            lpm_common::AtomicWriteOptions::default().unix_mode(0o755),
        )?;
    }
    #[cfg(windows)]
    for manager in managers {
        ensure_launcher(lpm, &dir.join(format!("{manager}.exe")))?;
    }
    Ok(dir)
}

/// On Windows, a process started without a shell (Node's `spawn('bun')`)
/// finds only `.com` and `.exe` files, so a `.cmd` shim alone would be
/// skipped for a real `bun.exe` later on PATH. Each shim therefore also
/// gets an `.exe` that is the LPM binary itself, hard-linked when the
/// volume allows and copied otherwise; [`launcher_manager`] recognizes
/// it at startup.
#[cfg(any(windows, test))]
fn ensure_launcher(lpm: &Path, target: &Path) -> Result<(), LpmError> {
    if launcher_in_place(target)? {
        return Ok(());
    }
    match std::fs::hard_link(lpm, target) {
        Ok(()) => return Ok(()),
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists && launcher_in_place(target)? =>
        {
            return Ok(());
        }
        Err(_) => {}
    }
    let mut source = std::fs::File::open(lpm)?;
    lpm_common::write_file_atomic_with(
        target,
        lpm_common::AtomicWriteOptions::default(),
        |file| std::io::copy(&mut source, file).map(drop),
    )?;
    Ok(())
}

/// Whether a launcher file is already at `target`. A directory, symlink
/// or other entry there is an error rather than something to replace.
#[cfg(any(windows, test))]
fn launcher_in_place(target: &Path) -> Result<bool, LpmError> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(LpmError::Script(format!(
            "{} is in the way of an LPM package-manager launcher",
            target.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The package manager a shim launcher stands in for, when the running
/// binary is one of the `.exe` launchers in the session's shim directory.
#[cfg(any(windows, test))]
pub(crate) fn launcher_manager(exe: &Path) -> Option<&'static str> {
    if !is_shim_dir(exe.parent()?) {
        return None;
    }
    let stem = exe.file_stem()?.to_str()?.to_ascii_lowercase();
    MANAGERS.iter().copied().find(|manager| *manager == stem)
}

/// Run a shimmed command and exit with its status.
pub(crate) fn exit_with_shim(manager: &str, args: Vec<OsString>) -> ! {
    let code = match run_shim(manager, args) {
        Ok(()) => 0,
        Err(LpmError::ExitCode(code)) => code,
        Err(error) => {
            eprintln!(
                "lpm: {}",
                lpm_common::sanitize_terminal_multiline(&error.to_string())
            );
            1
        }
    };
    std::process::exit(code);
}

fn shim_file_name(manager: &str) -> String {
    if cfg!(windows) {
        format!("{manager}.cmd")
    } else {
        manager.to_string()
    }
}

/// The shim for `manager`. On Windows it hands off to the `.exe`
/// launcher beside it, which keeps the file ASCII: cmd.exe reads batch
/// files in the OEM code page, so an LPM path with non-ASCII characters
/// written into it would break.
fn shim_script(lpm: &Path, manager: &str) -> Vec<u8> {
    if cfg!(windows) {
        format!("@echo off\r\n\"%~dp0{manager}.exe\" %*\r\nexit /b %ERRORLEVEL%\r\n").into_bytes()
    } else {
        let lpm = lpm.to_string_lossy();
        let quoted = lpm.replace('\'', r"'\''");
        format!("#!/bin/sh\nexec '{quoted}' internal-nested-pm {manager} -- \"$@\"\n").into_bytes()
    }
}

fn is_shim_dir(dir: &Path) -> bool {
    dir.join(SHIM_MARKER).is_file()
}

/// First executable named `name` on `path` outside any shim directory.
/// Honors `PATHEXT` on Windows.
pub(crate) fn find_on_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty() && !is_shim_dir(dir))
        .flat_map(|dir| {
            extensions
                .iter()
                .map(move |ext| dir.join(format!("{name}{ext}")))
        })
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// What a shimmed command becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Run `lpm <args>`, in `dir` when the command named another directory.
    Lpm {
        args: Vec<String>,
        dir: Option<PathBuf>,
    },
    /// Run the real package manager with the original arguments.
    Real,
}

impl Plan {
    fn summary(&self) -> String {
        match self {
            Self::Lpm { args, .. } => format!("lpm {}", args.join(" ")),
            Self::Real => "real".into(),
        }
    }
}

/// Translate `manager args…` started in `cwd`. `local_bin` reports
/// whether a binary is installed in the project at a directory, for
/// `npx`-style runners that prefer local binaries.
pub(crate) fn translate(
    manager: &str,
    args: &[String],
    cwd: &Path,
    local_bin: &dyn Fn(&Path, &str) -> bool,
) -> Plan {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match manager {
        "npx" => runner(&args, Runner::LocalFirst, cwd, None, local_bin),
        "bunx" => runner(&args, Runner::LocalFirst, cwd, None, local_bin),
        "pnpx" => runner(&args, Runner::Download, cwd, None, local_bin),
        "npm" | "pnpm" | "yarn" | "yarnpkg" | "bun" => {
            manager_command(manager, &args, cwd, local_bin).unwrap_or(Plan::Real)
        }
        _ => Plan::Real,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Runner {
    /// Runs an installed binary when there is one (`npx`, `bunx`).
    LocalFirst,
    /// Always downloads the package (`pnpm dlx`, `yarn dlx`, `pnpx`).
    Download,
}

const NPM_INSTALL: &[&str] = &[
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
    "add",
];
const NPM_CLEAN_INSTALL: &[&str] = &[
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
];

/// Flags that take the next token as their value. `-C` is `--prefix` for
/// npm and `--dir` for pnpm.
const VALUE_FLAGS: &[&str] = &[
    "--prefix",
    "-C",
    "--dir",
    "--cwd",
    "--loglevel",
    "--reporter",
    "--registry",
];

/// Effect of one install flag on the translated `lpm install`.
enum InstallFlag {
    Dir,
    Registry,
    Lpm(&'static str),
    Ignore,
    /// Changes what is installed or where, beyond what `lpm install`
    /// expresses: run the real binary.
    Unsupported,
}

fn install_flag(manager: &str, flag: &str) -> InstallFlag {
    let (name, value) = flag
        .split_once('=')
        .map_or((flag, None), |(n, v)| (n, Some(v)));
    // `--frozen-lockfile=false` turns a boolean flag off rather than on.
    let off = matches!(value, Some("false" | "0"));
    let on_or_ignore = |lpm: &'static str| {
        if off {
            InstallFlag::Ignore
        } else {
            InstallFlag::Lpm(lpm)
        }
    };
    match (manager, name) {
        ("npm", "--prefix" | "-C") | ("pnpm", "-C" | "--dir") | ("yarn" | "bun", "--cwd") => {
            InstallFlag::Dir
        }
        (_, "--registry") => InstallFlag::Registry,
        (_, "--save-dev")
        | ("npm" | "pnpm" | "yarn" | "bun", "-D")
        | ("yarn" | "bun", "--dev")
        | ("bun", "-d" | "--development") => on_or_ignore("-D"),
        ("npm", "--omit") if value == Some("dev") => InstallFlag::Lpm("--prod"),
        ("npm", "--production" | "--prod")
        | ("pnpm", "-P" | "--prod" | "--production")
        | ("yarn", "--production" | "--prod")
        | ("bun", "-p" | "--production") => on_or_ignore("--prod"),
        ("pnpm" | "yarn" | "bun", "--frozen-lockfile") | ("yarn", "--immutable") => {
            InstallFlag::Lpm(if off {
                "--no-frozen-lockfile"
            } else {
                "--frozen-lockfile"
            })
        }
        (_, "--no-frozen-lockfile") => InstallFlag::Lpm("--no-frozen-lockfile"),
        (_, "--save-exact" | "--exact") | ("npm" | "pnpm" | "yarn" | "bun", "-E") => {
            on_or_ignore("--exact")
        }
        ("yarn", "--ignore-engines") => on_or_ignore("--no-engine-strict"),
        (_, "--offline") => on_or_ignore("--offline"),
        (_, "--ignore-scripts") => on_or_ignore("--policy=deny"),
        (_, "--strict-peer-dependencies") => InstallFlag::Lpm(if off {
            "--no-strict-peer-dependencies"
        } else {
            "--strict-peer-dependencies"
        }),
        (
            _,
            "--no-audit"
            | "--audit"
            | "--no-fund"
            | "--fund"
            | "--prefer-offline"
            | "--silent"
            | "-s"
            | "--quiet"
            | "-q"
            | "--loglevel"
            | "--progress"
            | "--no-progress"
            | "--reporter"
            | "--non-interactive"
            | "--no-summary"
            | "--color"
            | "--no-color"
            | "--force"
            | "--save"
            | "-S"
            | "--save-prod"
            | "--legacy-peer-deps"
            | "--no-package-lock"
            | "--prefer-frozen-lockfile"
            | "--yes",
        ) => InstallFlag::Ignore,
        ("npm", "-P") => InstallFlag::Ignore,
        _ => InstallFlag::Unsupported,
    }
}

/// `--version` / `--help` answer and exit instead of running the
/// command's default action (a bare `yarn` installs).
fn has_query_flag(args: &[&str]) -> bool {
    args.iter()
        .any(|arg| matches!(*arg, "--version" | "-v" | "-V" | "--help" | "-h"))
}

/// `None` when the command is not one this module translates, or uses a
/// flag it cannot carry over.
fn manager_command(
    manager: &str,
    args: &[&str],
    cwd: &Path,
    local_bin: &dyn Fn(&Path, &str) -> bool,
) -> Option<Plan> {
    let manager = if manager == "yarnpkg" {
        "yarn"
    } else {
        manager
    };
    let subcommand_index = first_positional(args);
    let subcommand = subcommand_index.map(|index| args[index]);
    let is_install = match (manager, subcommand) {
        ("npm", Some(sub)) => NPM_INSTALL.contains(&sub),
        ("pnpm", Some("install" | "i" | "add")) => true,
        ("yarn", None) => !has_query_flag(args),
        ("yarn", Some("install" | "add")) => true,
        ("bun", Some("install" | "i" | "add" | "a")) => true,
        _ => false,
    };
    let is_clean_install = match (manager, subcommand) {
        ("npm", Some(sub)) => NPM_CLEAN_INSTALL.contains(&sub),
        ("bun", Some("ci")) => true,
        _ => false,
    };
    if is_install || is_clean_install {
        return install(manager, args, subcommand_index, is_clean_install, cwd);
    }
    if matches!(manager, "npm" | "pnpm" | "yarn")
        && subcommand.is_some_and(|sub| matches!(sub, "create" | "init" | "innit"))
    {
        return initializer(args, subcommand_index?);
    }
    let kind = match (manager, subcommand) {
        ("npm", Some("exec" | "x")) | ("bun", Some("x")) => Runner::LocalFirst,
        ("pnpm" | "yarn", Some("dlx")) => Runner::Download,
        _ => return None,
    };
    let index = subcommand_index?;
    let dir = runner_dir(manager, &args[..index], cwd)?;
    Some(runner(&args[index + 1..], kind, cwd, dir, local_bin))
}

/// `npm create x …` / `npm init x …` / `pnpm create x …` / `yarn create
/// x …` run the `create-x` package, as `lpm create x …` does. `npm init`
/// without an initializer only writes a manifest, and options before the
/// subcommand are left to the real package manager.
fn initializer(args: &[&str], subcommand_index: usize) -> Option<Plan> {
    if subcommand_index != 0 {
        return None;
    }
    let rest = &args[1..];
    let (spec, forwarded) = match rest {
        ["--", spec, forwarded @ ..] => (*spec, forwarded),
        [spec, forwarded @ ..] if !spec.starts_with('-') => (*spec, forwarded),
        _ => return None,
    };
    let forwarded = forwarded.iter().skip_while(|arg| **arg == "--");
    Some(Plan::Lpm {
        args: ["create".to_string(), spec.to_string(), "--".to_string()]
            .into_iter()
            .chain(forwarded.map(|arg| (*arg).to_string()))
            .collect(),
        dir: None,
    })
}

/// The directory a manager option before the subcommand moves a runner to
/// (`Some(None)` when none does). `None` when an option changes runner
/// behavior in a way `lpm exec` / `lpm dlx` cannot reproduce.
fn runner_dir(manager: &str, options: &[&str], cwd: &Path) -> Option<Option<PathBuf>> {
    let mut dir = None;
    let mut index = 0;
    while index < options.len() {
        let option = options[index];
        index += 1;
        let value = if VALUE_FLAGS.contains(&option) {
            let value = *options.get(index)?;
            index += 1;
            Some(value)
        } else {
            option.split_once('=').map(|(_, value)| value)
        };
        match install_flag(manager, option) {
            InstallFlag::Dir => dir = Some(cwd.join(value?)),
            InstallFlag::Ignore => {}
            _ => return None,
        }
    }
    Some(dir)
}

fn install(
    manager: &str,
    args: &[&str],
    subcommand_index: Option<usize>,
    clean: bool,
    cwd: &Path,
) -> Option<Plan> {
    let mut lpm_flags: BTreeSet<&str> = BTreeSet::new();
    let mut packages = Vec::new();
    let mut dir = None;
    let mut registry = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        if Some(index - 1) == subcommand_index {
            continue;
        }
        if arg == "--" {
            return None;
        }
        if !arg.starts_with('-') {
            packages.push(arg.to_string());
            continue;
        }
        let value = if VALUE_FLAGS.contains(&arg) {
            let value = *args.get(index)?;
            index += 1;
            Some(value)
        } else {
            arg.split_once('=').map(|(_, value)| value)
        };
        match install_flag(manager, arg) {
            InstallFlag::Dir => dir = Some(cwd.join(value?)),
            InstallFlag::Registry => registry = Some(value?),
            InstallFlag::Lpm(flag) => {
                lpm_flags.insert(flag);
            }
            InstallFlag::Ignore => {}
            InstallFlag::Unsupported => return None,
        }
    }
    let mut lpm_args = Vec::with_capacity(packages.len() + lpm_flags.len() + 1);
    if clean {
        if !packages.is_empty() {
            return None;
        }
        lpm_args.push("ci".to_string());
        lpm_flags.retain(|flag| {
            matches!(
                *flag,
                "--prod"
                    | "--offline"
                    | "--policy=deny"
                    | "--strict-peer-dependencies"
                    | "--no-strict-peer-dependencies"
                    | "--no-engine-strict"
            )
        });
    } else {
        lpm_args.push("install".to_string());
        if packages.is_empty() {
            lpm_flags.remove("-D");
            lpm_flags.remove("--exact");
        } else {
            lpm_flags.retain(|flag| !matches!(*flag, "--frozen-lockfile" | "--prod" | "--offline"));
        }
    }
    lpm_args.extend(lpm_flags.iter().map(|flag| (*flag).to_string()));
    if let Some(registry) = registry {
        lpm_args.push(format!("--registry={registry}"));
    }
    lpm_args.extend(packages);
    Some(Plan::Lpm {
        args: lpm_args,
        dir,
    })
}

fn first_positional(args: &[&str]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if arg == "--" {
            return None;
        }
        if !arg.starts_with('-') {
            return Some(index);
        }
        index += if VALUE_FLAGS.contains(&arg) { 2 } else { 1 };
    }
    None
}

/// `npx tool args…` and friends. Runs an installed binary through
/// `lpm exec` when the runner would, otherwise downloads through
/// `lpm dlx`. Flags that change which package provides the command run
/// the real runner.
fn runner(
    args: &[&str],
    kind: Runner,
    cwd: &Path,
    dir: Option<PathBuf>,
    local_bin: &dyn Fn(&Path, &str) -> bool,
) -> Plan {
    let mut index = 0;
    let mut local_only = false;
    while index < args.len() {
        match args[index] {
            "--" => {
                index += 1;
                break;
            }
            "-y" | "--yes" | "--quiet" | "-q" | "--silent" => index += 1,
            "--no-install" | "--no" => {
                local_only = true;
                index += 1;
            }
            flag if flag.starts_with('-') => return Plan::Real,
            _ => break,
        }
    }
    let Some((command, rest)) = args.get(index..).and_then(<[&str]>::split_first) else {
        return Plan::Real;
    };
    let rest = rest.iter().map(|arg| (*arg).to_string());
    let lookup_dir = dir.clone().unwrap_or_else(|| cwd.to_path_buf());
    // `--` keeps the tool's own flags (`-v`, `--json`, `--env`) from being
    // read as LPM's.
    let run = |subcommand: &str| Plan::Lpm {
        args: [
            subcommand.to_string(),
            (*command).to_string(),
            "--".to_string(),
        ]
        .into_iter()
        .chain(rest.clone())
        .collect(),
        dir: dir.clone(),
    };
    if kind == Runner::LocalFirst && !command.contains('@') && local_bin(&lookup_dir, command) {
        return run("exec");
    }
    if local_only {
        return Plan::Real;
    }
    run("dlx")
}

/// Lockfiles that mark which package manager owns a project.
const LOCKFILES: &[(&str, bool)] = &[
    ("lpm.lock", true),
    ("package-lock.json", false),
    ("npm-shrinkwrap.json", false),
    ("pnpm-lock.yaml", false),
    ("yarn.lock", false),
    ("bun.lock", false),
    ("bun.lockb", false),
];

/// Where a project's lockfile lives and which one it is, when it belongs
/// to another package manager. The project is the nearest directory at or
/// above `dir` with a `package.json`; a workspace member's lockfile lives
/// at the workspace root above it. A project with `lpm.lock`, with no
/// lockfile yet, or with none in its own workspace is LPM's to install; a
/// stray lockfile further up (`~/package-lock.json`) does not count.
fn foreign_lockfile(dir: &Path) -> Option<(&Path, &'static str)> {
    let project = dir
        .ancestors()
        .find(|ancestor| ancestor.join("package.json").is_file())?;
    if let Some(lockfile) = lockfile_in(project) {
        return lockfile.map(|file| (project, file));
    }
    let root = project
        .ancestors()
        .skip(1)
        .find(|ancestor| is_workspace_root(ancestor))?;
    lockfile_in(root)?.map(|file| (root, file))
}

/// `None` when `dir` has no lockfile, `Some(None)` when it has
/// `lpm.lock`, and `Some(Some(file))` for another manager's lockfile.
fn lockfile_in(dir: &Path) -> Option<Option<&'static str>> {
    let mut foreign = None;
    for (file, is_lpm) in LOCKFILES {
        if dir.join(file).is_file() {
            if *is_lpm {
                return Some(None);
            }
            foreign.get_or_insert(*file);
        }
    }
    foreign.map(Some)
}

fn is_workspace_root(dir: &Path) -> bool {
    if dir.join("pnpm-workspace.yaml").is_file() {
        return true;
    }
    lpm_common::read_text_file_capped(
        &dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()
    .and_then(|content| {
        serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(&content)).ok()
    })
    .is_some_and(|manifest| manifest.get("workspaces").is_some())
}

/// Whether `path` was created, or replaced, at or after `start`. A
/// scaffold template that copies or extracts its own lockfile does not
/// make the generated project another package manager's: the change time
/// moves even when the modification time is preserved.
fn changed_since(path: &Path, start: SystemTime) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        u64::try_from(metadata.ctime()).ok().and_then(|seconds| {
            let nanos = u32::try_from(metadata.ctime_nsec()).unwrap_or(0);
            UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
        })
    };
    #[cfg(not(unix))]
    let changed = metadata.created().ok();
    changed.is_some_and(|changed| changed >= start)
}

/// `plan` with installs into a project another package manager owned
/// before the tool started turned back into the real command, and why.
/// Once a command in this run has left a project to its owner, later
/// ones do too, even after that manager rewrote its lockfile.
fn respect_project_owner(
    plan: Plan,
    cwd: &Path,
    started: Option<SystemTime>,
    earlier: &[LogEntry],
) -> (Plan, Option<String>) {
    let Plan::Lpm { args, dir } = &plan else {
        return (plan, None);
    };
    if !matches!(args.first().map(String::as_str), Some("install" | "ci")) {
        return (plan, None);
    }
    let Some((project, lockfile)) = foreign_lockfile(dir.as_deref().unwrap_or(cwd)) else {
        return (plan, None);
    };
    let owned_earlier = earlier
        .iter()
        .any(|entry| entry.reason.is_some() && entry.dir.starts_with(project));
    let created_by_tool =
        started.is_some_and(|started| changed_since(&project.join(lockfile), started));
    if created_by_tool && !owned_earlier {
        return (plan, None);
    }
    (Plan::Real, Some(format!("the project uses {lockfile}")))
}

/// One shimmed command, as the shim recorded it before running it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LogEntry {
    pub manager: String,
    pub args: Vec<String>,
    pub dir: PathBuf,
    /// `lpm …` for a translated command, `real` for the real binary.
    pub ran: String,
    /// Why a command LPM could translate ran the real binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Entries read from a command log, and whether it was cut off at
/// [`MAX_LOG_BYTES`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Log {
    pub entries: Vec<LogEntry>,
    pub truncated: bool,
}

fn read_log(path: &Path) -> Log {
    let Ok(file) = std::fs::File::open(path) else {
        return Log::default();
    };
    let truncated = file
        .metadata()
        .is_ok_and(|metadata| metadata.len() > MAX_LOG_BYTES);
    let Ok(mut bytes) =
        lpm_common::read_stream_capped(std::io::Read::take(file, MAX_LOG_BYTES), MAX_LOG_BYTES)
    else {
        return Log::default();
    };
    if truncated {
        let complete = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |end| end + 1);
        bytes.truncate(complete);
    }
    Log {
        entries: String::from_utf8_lossy(&bytes)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
        truncated,
    }
}

fn append_log(path: &Path, entry: &LogEntry) {
    let Ok(mut line) = serde_json::to_vec(entry) else {
        return;
    };
    line.push(b'\n');
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
        let _ = file.write_all(&line);
    }
}

/// Entry point of the hidden `internal-nested-pm` command the shims call.
pub(crate) fn run_shim(manager: &str, args: Vec<OsString>) -> Result<(), LpmError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let cwd = std::env::current_dir()?;
    let text_args: Option<Vec<String>> = args
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect();
    let plan = match &text_args {
        Some(text_args) => translate(manager, text_args, &cwd, &|dir, bin| {
            lpm_runner::script::local_bin_exists(dir, bin)
        }),
        None => Plan::Real,
    };
    // The directory the command installs into, kept for the report even
    // when the install is left to the project's own package manager.
    let target_dir = match &plan {
        Plan::Lpm { dir: Some(dir), .. } => dir.clone(),
        _ => cwd.clone(),
    };
    let log = std::env::var_os(LOG_ENV).map(PathBuf::from);
    let earlier = log
        .as_deref()
        .map(|log| read_log(log).entries)
        .unwrap_or_default();
    let started = std::env::var(STARTED_ENV)
        .ok()
        .and_then(|nanos| nanos.parse::<u64>().ok())
        .map(|nanos| UNIX_EPOCH + Duration::from_nanos(nanos));
    let (plan, reason) = respect_project_owner(plan, &cwd, started, &earlier);
    if let Some(log) = log {
        append_log(
            &log,
            &LogEntry {
                manager: manager.to_string(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
                dir: target_dir,
                ran: plan.summary(),
                reason,
            },
        );
    }
    let mut command = match plan {
        Plan::Lpm { args, dir } => {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args(args)
                .current_dir(dir.unwrap_or(cwd))
                .env("PATH", path_without_shims(&path)?)
                .env_remove(LOG_ENV)
                .env_remove(STARTED_ENV)
                .env_remove(USER_AGENT_ENV);
            command
        }
        Plan::Real => {
            let Some(real) = find_on_path(manager, &path) else {
                eprintln!("{manager}: command not found");
                return Err(LpmError::ExitCode(127));
            };
            let mut command = Command::new(real);
            command.args(&args);
            command
        }
    };
    let signals = lpm_runner::execution::ExecutionSignals::new()?;
    let status = signals.run(&mut command)?;
    if status.success() {
        Ok(())
    } else {
        Err(LpmError::ExitCode(lpm_runner::shell::exit_code(&status)))
    }
}

fn path_without_shims(path: &OsStr) -> Result<OsString, LpmError> {
    std::env::join_paths(std::env::split_paths(path).filter(|dir| !is_shim_dir(dir)))
        .map_err(|error| LpmError::Script(format!("could not rebuild PATH: {error}")))
}

/// A tool run with the user agent set and, when any package manager is
/// installed, the shims on its PATH.
pub(crate) struct ToolRun {
    session: Option<NestedPmSession>,
}

impl ToolRun {
    pub(crate) fn attach(command: &mut Command) -> Self {
        apply_user_agent(command);
        let path = command
            .get_envs()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
            .and_then(|(_, value)| value.map(OsStr::to_os_string))
            .or_else(|| std::env::var_os("PATH"))
            .unwrap_or_default();
        let session = match NestedPmSession::prepare(&path).and_then(|session| {
            if let Some(session) = &session {
                session.apply(command)?;
            }
            Ok(session)
        }) {
            Ok(session) => session,
            Err(error) => {
                install_ui::warn_untrusted(&format!(
                    "could not route the tool's package-manager commands through LPM ({error}); \
                     installs it starts will follow that package manager's script rules"
                ));
                None
            }
        };
        Self { session }
    }

    /// List the package-manager commands the tool ran and the script
    /// approvals it left in the directories they ran in.
    pub(crate) fn report(self, tool: &str, caller_dir: &Path) {
        let Some(session) = self.session else {
            return;
        };
        let Log { entries, truncated } = session.entries();
        if entries.is_empty() {
            return;
        }
        let shown = |dir: &Path| -> String {
            match dir.strip_prefix(caller_dir) {
                Ok(relative) if relative.as_os_str().is_empty() => ".".into(),
                Ok(relative) => relative.display().to_string(),
                Err(_) => dir.display().to_string(),
            }
        };
        install_ui::phase_untrusted(&format!(
            "{tool} ran {} package-manager command{}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        ));
        for entry in &entries {
            let command = std::iter::once(entry.manager.as_str())
                .chain(entry.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            let outcome = if entry.ran == "real" {
                let because = entry
                    .reason
                    .as_deref()
                    .map(|reason| format!(" because {reason}"))
                    .unwrap_or_default();
                if is_install_command(&entry.manager, &entry.args) {
                    format!(
                        "ran {} directly{because}; its dependency scripts followed {}'s rules, not LPM's",
                        entry.manager, entry.manager
                    )
                } else {
                    format!("ran {} directly{because}", entry.manager)
                }
            } else {
                format!("handled by {}", entry.ran)
            };
            install_ui::detail_untrusted(&format!(
                "{command}  →  {outcome}  (in {})",
                shown(&entry.dir)
            ));
        }
        if truncated {
            install_ui::detail("more commands ran than the log holds; the list above is the start");
        }
        let mut dirs: Vec<&Path> = entries.iter().map(|entry| entry.dir.as_path()).collect();
        dirs.sort();
        dirs.dedup();
        let written: Vec<WrittenApproval> = dirs
            .into_iter()
            .flat_map(written_script_approvals)
            .collect();
        if written.is_empty() {
            return;
        }
        install_ui::warn_untrusted(&format!(
            "{tool} left script approvals in the project it set up:"
        ));
        for approval in &written {
            install_ui::detail_untrusted(&format!(
                "{}  {}",
                shown(&approval.file),
                approval.detail
            ));
        }
        install_ui::detail(
            "LPM ignores npm, pnpm, Yarn and bun approval lists; lpm.trustedDependencies applies only after you approve it on this machine",
        );
    }
}

/// True when `manager args…` installs packages, whether or not it was
/// translated.
fn is_install_command(manager: &str, args: &[String]) -> bool {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let subcommand = first_positional(&args).map(|index| args[index]);
    match (manager, subcommand) {
        ("npm", Some(sub)) => NPM_INSTALL.contains(&sub) || NPM_CLEAN_INSTALL.contains(&sub),
        ("pnpm", Some(sub)) => matches!(sub, "install" | "i" | "add"),
        ("yarn" | "yarnpkg", None) => !has_query_flag(&args),
        ("yarn" | "yarnpkg", Some(sub)) => matches!(sub, "install" | "add"),
        ("bun", Some(sub)) => matches!(sub, "install" | "i" | "add" | "a" | "ci"),
        _ => false,
    }
}

/// One approval list found in a project directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WrittenApproval {
    pub file: PathBuf,
    pub detail: String,
}

/// Script approval lists for any package manager in `dir`'s
/// `package.json`, `pnpm-workspace.yaml`, `.npmrc` and `.yarnrc.yml`.
pub(crate) fn written_script_approvals(dir: &Path) -> Vec<WrittenApproval> {
    let mut found = Vec::new();
    let read = |name: &str| {
        let path = dir.join(name);
        lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .ok()
            .map(|content| (path, lpm_common::strip_utf8_bom_str(&content).to_owned()))
    };
    if let Some((path, content)) = read("package.json")
        && let Ok(serde_json::Value::Object(manifest)) = serde_json::from_str(&content)
    {
        for (field, packages) in lpm_security::reach::declared_script_approvals(&manifest) {
            if !packages.is_empty() {
                found.push(WrittenApproval {
                    file: path.clone(),
                    detail: format!("{field}: {}", list(&packages)),
                });
            }
        }
    }
    if let Some((path, content)) = read("pnpm-workspace.yaml")
        && let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content)
    {
        if let Some(builds) = yaml
            .get("allowBuilds")
            .and_then(serde_yaml::Value::as_mapping)
        {
            let packages: Vec<String> = builds
                .iter()
                .filter(|(_, allowed)| allowed.as_bool() != Some(false))
                .filter_map(|(name, _)| name.as_str().map(str::to_owned))
                .collect();
            if !packages.is_empty() {
                found.push(WrittenApproval {
                    file: path.clone(),
                    detail: format!("allowBuilds: {}", list(&packages)),
                });
            }
        }
        if let Some(only) = yaml
            .get("onlyBuiltDependencies")
            .and_then(serde_yaml::Value::as_sequence)
        {
            let packages: Vec<String> = only
                .iter()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect();
            if !packages.is_empty() {
                found.push(WrittenApproval {
                    file: path.clone(),
                    detail: format!("onlyBuiltDependencies: {}", list(&packages)),
                });
            }
        }
        if yaml
            .get("dangerouslyAllowAllBuilds")
            .and_then(serde_yaml::Value::as_bool)
            == Some(true)
        {
            found.push(WrittenApproval {
                file: path,
                detail: "dangerouslyAllowAllBuilds: true".into(),
            });
        }
    }
    if let Some((path, content)) = read(".npmrc") {
        for line in content.lines() {
            let line = line.trim();
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            let approves = match key {
                "ignore-scripts" => value == "false",
                "dangerously-allow-all-scripts" | "dangerously-allow-all-builds" => value == "true",
                "allow-scripts" | "only-built-dependencies[]" => !value.is_empty(),
                _ => false,
            };
            if approves {
                found.push(WrittenApproval {
                    file: path.clone(),
                    detail: format!("{key}={value}"),
                });
            }
        }
    }
    if let Some((path, content)) = read(".yarnrc.yml")
        && let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&content)
        && yaml
            .get("enableScripts")
            .and_then(serde_yaml::Value::as_bool)
            == Some(true)
    {
        found.push(WrittenApproval {
            file: path,
            detail: "enableScripts: true".into(),
        });
    }
    found
}

fn list(packages: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut text = packages[..packages.len().min(SHOWN)].join(", ");
    if packages.len() > SHOWN {
        text.push_str(&format!(" and {} more", packages.len() - SHOWN));
    }
    text
}

/// Run a project-local binary for `lpm exec` and the `lpm <bin>`
/// shortcut, with package-manager commands it starts routed through LPM.
pub(crate) fn run_local_tool(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let mut command = lpm_runner::script::build_local_bin_command(
        project_dir,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        bin_hint,
    )?;
    let tool = ToolRun::attach(&mut command);
    let result = lpm_runner::script::run_built_local_bin_command(command);
    tool.report(command_name, project_dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(manager: &str, args: &str) -> Plan {
        plan_with_local(manager, args, &[])
    }

    fn plan_with_local(manager: &str, args: &str, local: &[&str]) -> Plan {
        let args: Vec<String> = shlex::split(args).unwrap();
        translate(manager, &args, Path::new("/work"), &|_, bin| {
            local.contains(&bin)
        })
    }

    fn lpm(args: &str) -> Plan {
        Plan::Lpm {
            args: shlex::split(args).unwrap(),
            dir: None,
        }
    }

    fn lpm_in(args: &str, dir: &str) -> Plan {
        Plan::Lpm {
            args: shlex::split(args).unwrap(),
            dir: Some(Path::new("/work").join(dir)),
        }
    }

    #[test]
    fn project_installs_from_every_manager_run_lpm_install() {
        for (manager, args) in [
            ("npm", "install"),
            ("npm", "i --no-audit --no-fund --loglevel error"),
            ("npm", "isntall"),
            ("pnpm", "install --reporter=silent"),
            ("pnpm", "i"),
            ("yarn", ""),
            ("yarn", "install --non-interactive"),
            ("yarnpkg", "install"),
            ("bun", "install --no-summary"),
        ] {
            assert_eq!(plan(manager, args), lpm("install"), "{manager} {args}");
        }
    }

    #[test]
    fn install_flags_with_lpm_equivalents_carry_over() {
        assert_eq!(
            plan("pnpm", "install --frozen-lockfile"),
            lpm("install --frozen-lockfile")
        );
        assert_eq!(
            plan("yarn", "--immutable"),
            lpm("install --frozen-lockfile")
        );
        assert_eq!(plan("bun", "install --production"), lpm("install --prod"));
        assert_eq!(plan("npm", "install --omit=dev"), lpm("install --prod"));
        assert_eq!(plan("npm", "install --offline"), lpm("install --offline"));
        assert_eq!(
            plan("npm", "install --ignore-scripts"),
            lpm("install --policy=deny")
        );
        assert_eq!(plan("npm", "ci"), lpm("ci"));
        assert_eq!(
            plan("npm", "clean-install --omit=dev --no-audit"),
            lpm("ci --prod")
        );
    }

    #[test]
    fn adding_packages_runs_lpm_install_with_the_packages() {
        assert_eq!(
            plan("npm", "install -D vite@7 typescript"),
            lpm("install -D vite@7 typescript")
        );
        assert_eq!(plan("pnpm", "add --save-dev vite"), lpm("install -D vite"));
        assert_eq!(plan("yarn", "add vite --dev"), lpm("install -D vite"));
        assert_eq!(plan("bun", "add -d vite"), lpm("install -D vite"));
        assert_eq!(
            plan("npm", "add -E react react-dom"),
            lpm("install --exact react react-dom")
        );
    }

    #[test]
    fn directory_flags_move_the_install() {
        assert_eq!(
            plan("npm", "--prefix app install"),
            lpm_in("install", "app")
        );
        assert_eq!(plan("pnpm", "-C app install"), lpm_in("install", "app"));
        assert_eq!(plan("pnpm", "--dir=app install"), lpm_in("install", "app"));
        assert_eq!(plan("yarn", "--cwd app"), lpm_in("install", "app"));
        assert_eq!(plan("bun", "install --cwd app"), lpm_in("install", "app"));
    }

    #[test]
    fn installs_lpm_cannot_express_run_the_real_package_manager() {
        for (manager, args) in [
            ("npm", "install -g create-thing"),
            ("npm", "install --workspace docs"),
            ("npm", "ci some-package"),
            ("pnpm", "add -g thing"),
            ("pnpm", "install --filter docs"),
            ("pnpm", "install --shamefully-hoist"),
            ("yarn", "global add thing"),
            ("npm", "install -- thing"),
        ] {
            assert_eq!(plan(manager, args), Plan::Real, "{manager} {args}");
        }
    }

    #[test]
    fn non_install_commands_run_the_real_package_manager() {
        for (manager, args) in [
            ("npm", "run dev"),
            ("npm", "--version"),
            ("npm", "pkg set name=x"),
            ("pnpm", "run build"),
            ("pnpm", "exec tsc"),
            ("yarn", "build"),
            ("bun", "run dev"),
            ("bun", "./script.ts"),
        ] {
            assert_eq!(plan(manager, args), Plan::Real, "{manager} {args}");
        }
    }

    #[test]
    fn local_first_runners_use_installed_binaries_and_download_the_rest() {
        assert_eq!(
            plan_with_local("npx", "tsc --noEmit", &["tsc"]),
            lpm("exec tsc -- --noEmit")
        );
        assert_eq!(plan_with_local("bunx", "tsc", &["tsc"]), lpm("exec tsc --"));
        assert_eq!(
            plan_with_local("npm", "exec -- tsc -b", &["tsc"]),
            lpm("exec tsc -- -b")
        );
        assert_eq!(
            plan("npx", "-y create-vite@latest app"),
            lpm("dlx create-vite@latest -- app")
        );
        assert_eq!(plan("npx", "cowsay hi"), lpm("dlx cowsay -- hi"));
        assert_eq!(plan("npm", "x cowsay"), lpm("dlx cowsay --"));
        assert_eq!(plan("bun", "x cowsay"), lpm("dlx cowsay --"));
        assert_eq!(
            plan_with_local("npx", "tsc@5 --version", &["tsc"]),
            lpm("dlx tsc@5 -- --version"),
            "a versioned spec asks for a download"
        );
    }

    #[test]
    fn download_runners_always_go_through_lpm_dlx() {
        assert_eq!(
            plan_with_local("pnpm", "dlx tsc", &["tsc"]),
            lpm("dlx tsc --")
        );
        assert_eq!(
            plan("yarn", "dlx create-thing app"),
            lpm("dlx create-thing -- app")
        );
        assert_eq!(plan("pnpx", "create-thing"), lpm("dlx create-thing --"));
    }

    #[test]
    fn runner_flags_that_pick_another_package_run_the_real_runner() {
        assert_eq!(plan("npx", "-p typescript tsc"), Plan::Real);
        assert_eq!(plan("npx", "--package=typescript tsc"), Plan::Real);
        assert_eq!(plan("npx", "-c 'tsc && vite'"), Plan::Real);
        assert_eq!(plan("npx", "--no-install tsc"), Plan::Real);
        assert_eq!(plan("npx", ""), Plan::Real);
    }

    #[test]
    fn user_agent_names_lpm_first_in_the_npm_shape() {
        let agent = user_agent();
        assert!(
            agent.starts_with(&format!("lpm/{} npm/? node/? ", env!("CARGO_PKG_VERSION"))),
            "{agent}"
        );
        assert_eq!(node_platform("macos"), "darwin");
        assert_eq!(node_platform("windows"), "win32");
        assert_eq!(node_platform("linux"), "linux");
        assert_eq!(node_arch("x86_64"), "x64");
        assert_eq!(node_arch("aarch64"), "arm64");
    }

    #[cfg(unix)]
    #[test]
    fn shim_script_quotes_the_lpm_path_for_sh() {
        let script =
            String::from_utf8(shim_script(Path::new("/opt/it's lpm/lpm-rs"), "pnpm")).unwrap();
        assert_eq!(
            script,
            "#!/bin/sh\nexec '/opt/it'\\''s lpm/lpm-rs' internal-nested-pm pnpm -- \"$@\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_binary_lookup_skips_every_marked_shim_directory() {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let other_session = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        for dir in [shims.path(), other_session.path(), real.path()] {
            let file = dir.join("pnpm");
            std::fs::write(&file, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        for dir in [shims.path(), other_session.path()] {
            std::fs::write(dir.join(SHIM_MARKER), "").unwrap();
        }
        let path = std::env::join_paths([shims.path(), other_session.path(), real.path()]).unwrap();
        assert_eq!(find_on_path("pnpm", &path), Some(real.path().join("pnpm")));
        assert_eq!(find_on_path("yarn", &path), None);
        assert_eq!(
            path_without_shims(&path).unwrap(),
            std::env::join_paths([real.path()]).unwrap()
        );
    }

    #[test]
    fn approvals_written_for_any_package_manager_are_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name":"app",
                "allowScripts":{"esbuild@0.28.2":true,"core-js":false},
                "trustedDependencies":["sharp"],
                "lpm":{"trustedDependencies":["better-sqlite3"]}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - prototypes/*\nallowBuilds:\n  esbuild: true\n  core-js: false\nonlyBuiltDependencies:\n  - sharp\ndangerouslyAllowAllBuilds: true\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\nignore-scripts=false\nallow-scripts=canvas\nignore-scripts = true\n",
        )
        .unwrap();
        std::fs::write(dir.path().join(".yarnrc.yml"), "enableScripts: true\n").unwrap();

        let details: Vec<(String, String)> = written_script_approvals(dir.path())
            .into_iter()
            .map(|found| {
                (
                    found
                        .file
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    found.detail,
                )
            })
            .collect();
        let expected = [
            ("package.json", "allowScripts: esbuild"),
            ("package.json", "trustedDependencies: sharp"),
            ("package.json", "lpm.trustedDependencies: better-sqlite3"),
            ("pnpm-workspace.yaml", "allowBuilds: esbuild"),
            ("pnpm-workspace.yaml", "onlyBuiltDependencies: sharp"),
            ("pnpm-workspace.yaml", "dangerouslyAllowAllBuilds: true"),
            (".npmrc", "ignore-scripts=false"),
            (".npmrc", "allow-scripts=canvas"),
            (".yarnrc.yml", "enableScripts: true"),
        ]
        .map(|(file, detail)| (file.to_string(), detail.to_string()));
        assert_eq!(details, expected);
    }

    #[test]
    fn project_without_approval_lists_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"app"}"#).unwrap();
        std::fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n",
        )
        .unwrap();
        assert!(written_script_approvals(dir.path()).is_empty());
    }

    #[test]
    fn install_commands_are_recognized_whether_or_not_they_were_translated() {
        let args = |text: &str| shlex::split(text).unwrap();
        assert!(is_install_command("npm", &args("install -g thing")));
        assert!(is_install_command(
            "pnpm",
            &args("install --shamefully-hoist")
        ));
        assert!(is_install_command("yarn", &args("--frozen-lockfile")));
        assert!(!is_install_command("npm", &args("run build")));
        assert!(!is_install_command("pnpm", &args("exec tsc")));
    }

    #[test]
    fn installs_into_projects_owned_by_another_package_manager_stay_with_it() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("package.json"), "{}").unwrap();
        let app = root.path().join("apps/web");
        std::fs::create_dir_all(&app).unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            None,
            "a fresh project is LPM's to install"
        );

        std::fs::write(root.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            Some((root.path(), "pnpm-lock.yaml"))
        );
        let started = SystemTime::now() + Duration::from_secs(60);
        let (plan, reason) = respect_project_owner(lpm("install"), &app, Some(started), &[]);
        assert_eq!(plan, Plan::Real);
        assert_eq!(reason.as_deref(), Some("the project uses pnpm-lock.yaml"));
        assert_eq!(
            respect_project_owner(lpm("dlx cowsay --"), &app, Some(started), &[]),
            (lpm("dlx cowsay --"), None),
            "running a package does not install into the project"
        );

        std::fs::write(app.join("package.json"), "{}").unwrap();
        std::fs::write(app.join("lpm.lock"), "").unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            None,
            "the nearest lockfile is LPM's"
        );
        std::fs::write(app.join("package-lock.json"), "").unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            None,
            "lpm.lock wins beside another lockfile"
        );
    }

    #[test]
    fn lockfile_a_tool_wrote_during_the_run_does_not_make_the_project_foreign() {
        let started = SystemTime::now() - Duration::from_secs(60);
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        std::fs::write(project.path().join("package-lock.json"), "{}").unwrap();
        assert_eq!(
            respect_project_owner(lpm("install"), project.path(), Some(started), &[]),
            (lpm("install"), None),
            "a template's copied lockfile was written after the tool started"
        );

        let earlier = [LogEntry {
            manager: "npm".into(),
            args: vec!["install".into()],
            dir: project.path().to_path_buf(),
            ran: "real".into(),
            reason: Some("the project uses package-lock.json".into()),
        }];
        assert_eq!(
            respect_project_owner(lpm("install"), project.path(), Some(started), &earlier).0,
            Plan::Real,
            "once left to its owner in this run, a rewritten lockfile keeps the project there"
        );
    }

    #[test]
    fn yarn_version_and_help_queries_run_the_real_yarn() {
        for args in ["--version", "-v", "--help"] {
            assert_eq!(plan("yarn", args), Plan::Real, "yarn {args}");
        }
        assert!(!is_install_command("yarn", &["--version".to_string()]));
    }

    #[test]
    fn boolean_flags_set_to_false_turn_the_option_off() {
        assert_eq!(plan("npm", "install --production=false"), lpm("install"));
        assert_eq!(
            plan("pnpm", "install --frozen-lockfile=false"),
            lpm("install --no-frozen-lockfile")
        );
        assert_eq!(
            plan("npm", "install --ignore-scripts=false"),
            lpm("install")
        );
        assert_eq!(
            plan("npm", "install --save-dev=false vite"),
            lpm("install vite")
        );
        assert_eq!(
            plan("pnpm", "install --strict-peer-dependencies=false"),
            lpm("install --no-strict-peer-dependencies")
        );
    }

    #[test]
    fn clean_install_keeps_script_policy_and_peer_flags() {
        assert_eq!(
            plan("npm", "ci --ignore-scripts --strict-peer-dependencies"),
            lpm("ci --policy=deny --strict-peer-dependencies")
        );
    }

    #[test]
    fn registry_flag_carries_over_to_lpm() {
        assert_eq!(
            plan("npm", "install --registry https://registry.example/"),
            lpm("install --registry=https://registry.example/")
        );
        assert_eq!(
            plan("pnpm", "add --registry=https://registry.example/ vite"),
            lpm("install --registry=https://registry.example/ vite")
        );
    }

    #[test]
    fn runner_directory_options_before_the_subcommand_move_the_lookup() {
        let args: Vec<String> = shlex::split("--prefix other exec -- tool --flag").unwrap();
        let plan = translate("npm", &args, Path::new("/work"), &|dir, bin| {
            dir == Path::new("/work/other") && bin == "tool"
        });
        assert_eq!(
            plan,
            lpm_in("exec tool -- --flag", "other"),
            "the binary installed under --prefix runs, from there"
        );
        assert_eq!(
            plan_with_local("npm", "--foo bar exec tool", &["tool"]),
            Plan::Real,
            "an option LPM cannot reproduce runs the real runner"
        );
    }

    #[test]
    fn launcher_is_recognized_only_inside_a_marked_shim_directory() {
        let shims = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(shims.path().join(SHIM_MARKER), "").unwrap();
        assert_eq!(launcher_manager(&shims.path().join("bun.exe")), Some("bun"));
        assert_eq!(launcher_manager(&shims.path().join("NPM.EXE")), Some("npm"));
        assert_eq!(launcher_manager(&shims.path().join("lpm.exe")), None);
        assert_eq!(launcher_manager(&elsewhere.path().join("bun.exe")), None);
    }

    #[test]
    fn launcher_is_the_lpm_binary_and_an_existing_launcher_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let lpm = dir.path().join("lpm.exe");
        std::fs::write(&lpm, b"lpm binary").unwrap();
        let launcher = dir.path().join("bun.exe");

        ensure_launcher(&lpm, &launcher).unwrap();
        assert_eq!(std::fs::read(&launcher).unwrap(), b"lpm binary");

        std::fs::remove_file(&lpm).unwrap();
        ensure_launcher(&lpm, &launcher).unwrap();
        assert_eq!(std::fs::read(&launcher).unwrap(), b"lpm binary");
    }

    #[test]
    fn launcher_refuses_to_reuse_a_directory_in_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let lpm = dir.path().join("lpm.exe");
        std::fs::write(&lpm, b"lpm binary").unwrap();
        let launcher = dir.path().join("bun.exe");
        std::fs::create_dir(&launcher).unwrap();

        let error = ensure_launcher(&lpm, &launcher).unwrap_err();
        assert!(error.to_string().contains("in the way"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn launcher_does_not_write_through_a_symlink_in_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let lpm = dir.path().join("lpm.exe");
        std::fs::write(&lpm, b"lpm binary").unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let launcher = dir.path().join("bun.exe");
        std::os::unix::fs::symlink(&victim, &launcher).unwrap();

        assert!(ensure_launcher(&lpm, &launcher).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }

    #[test]
    fn initializers_run_through_lpm_create() {
        assert_eq!(
            plan("npm", "create vite@latest app --template react"),
            lpm("create vite@latest -- app --template react")
        );
        assert_eq!(
            plan("npm", "create -- vike@latest --vue app"),
            lpm("create vike@latest -- --vue app")
        );
        assert_eq!(plan("npm", "init vite app"), lpm("create vite -- app"));
        assert_eq!(plan("pnpm", "create astro"), lpm("create astro --"));
        assert_eq!(
            plan("yarn", "create next-app app"),
            lpm("create next-app -- app")
        );
        assert_eq!(
            plan("npm", "init -y"),
            Plan::Real,
            "init without an initializer"
        );
        assert_eq!(
            plan("bun", "create owner/repo"),
            Plan::Real,
            "bun templates differ"
        );
    }

    #[test]
    fn exact_save_engine_and_unfrozen_flags_carry_over() {
        assert_eq!(
            plan("npm", "install --save-exact react"),
            lpm("install --exact react")
        );
        assert_eq!(plan("pnpm", "add -E react"), lpm("install --exact react"));
        assert_eq!(plan("npm", "install -E"), lpm("install"), "nothing to save");
        assert_eq!(
            plan("yarn", "--ignore-engines"),
            lpm("install --no-engine-strict")
        );
        assert_eq!(
            plan("yarn", "install --no-frozen-lockfile"),
            lpm("install --no-frozen-lockfile")
        );
        assert_eq!(plan("npm", "install --force"), lpm("install"));
    }

    #[test]
    fn bun_clean_install_runs_lpm_ci() {
        assert_eq!(plan("bun", "ci"), lpm("ci"));
        assert!(is_install_command("bun", &["ci".to_string()]));
    }

    #[test]
    fn lockfile_ownership_stops_at_the_project_and_its_workspace() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("package-lock.json"), "{}").unwrap();
        let app = home.path().join("code/my-app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("package.json"), "{}").unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            None,
            "a stray lockfile above the project"
        );

        let repo = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n",
        )
        .unwrap();
        std::fs::write(repo.path().join("pnpm-lock.yaml"), "").unwrap();
        let member = repo.path().join("apps/web");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), "{}").unwrap();
        assert_eq!(
            foreign_lockfile(&member),
            Some((repo.path(), "pnpm-lock.yaml")),
            "a workspace member's lockfile lives at the workspace root"
        );
    }

    #[test]
    fn oversized_log_keeps_the_complete_entries_it_can_read() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let entry = LogEntry {
            manager: "npm".into(),
            args: vec!["x".repeat(4096)],
            dir: PathBuf::from("/work"),
            ran: "real".into(),
            reason: None,
        };
        let line_len = serde_json::to_vec(&entry).unwrap().len() as u64 + 1;
        let count = MAX_LOG_BYTES / line_len + 2;
        for _ in 0..count {
            append_log(log.path(), &entry);
        }
        let read = read_log(log.path());
        assert!(read.truncated);
        assert_eq!(read.entries.len() as u64, MAX_LOG_BYTES / line_len);
    }

    #[test]
    fn log_round_trips_and_skips_lines_it_cannot_read() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let entry = LogEntry {
            manager: "pnpm".into(),
            args: vec!["install".into()],
            dir: PathBuf::from("/work/app"),
            ran: "lpm install".into(),
            reason: None,
        };
        append_log(log.path(), &entry);
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        append_log(log.path(), &entry);
        assert_eq!(
            read_log(log.path()),
            Log {
                entries: vec![entry.clone(), entry],
                truncated: false,
            }
        );
    }
}
