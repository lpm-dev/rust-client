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

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::install_ui;

/// Directory holding this session's shims. Nested LPM commands remove it
/// from PATH so their own children never reach the shims.
pub(crate) const SHIMS_ENV: &str = "LPM_NESTED_PM_SHIMS";
/// File the shims append one [`LogEntry`] line to per command.
pub(crate) const LOG_ENV: &str = "LPM_NESTED_PM_LOG";
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
            .filter(|manager| find_on_path(manager, path, None).is_some())
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
        command
            .env("PATH", path)
            .env(SHIMS_ENV, &self.shim_dir)
            .env(LOG_ENV, self.log.path());
        Ok(())
    }

    /// Commands the tool's package-manager calls ran, in order.
    pub(crate) fn entries(&self) -> Vec<LogEntry> {
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
    Ok(dir)
}

fn shim_file_name(manager: &str) -> String {
    if cfg!(windows) {
        format!("{manager}.cmd")
    } else {
        manager.to_string()
    }
}

fn shim_script(lpm: &Path, manager: &str) -> Vec<u8> {
    let lpm = lpm.to_string_lossy();
    if cfg!(windows) {
        format!(
            "@echo off\r\n\"{lpm}\" internal-nested-pm {manager} -- %*\r\nexit /b %ERRORLEVEL%\r\n"
        )
        .into_bytes()
    } else {
        let quoted = lpm.replace('\'', r"'\''");
        format!("#!/bin/sh\nexec '{quoted}' internal-nested-pm {manager} -- \"$@\"\n").into_bytes()
    }
}

/// First executable named `name` on `path`, skipping `skip`. Honors
/// `PATHEXT` on Windows.
pub(crate) fn find_on_path(name: &str, path: &OsStr, skip: Option<&Path>) -> Option<PathBuf> {
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
        .filter(|dir| !dir.as_os_str().is_empty() && skip.is_none_or(|skip| !same_dir(dir, skip)))
        .flat_map(|dir| {
            extensions
                .iter()
                .map(move |ext| dir.join(format!("{name}{ext}")))
        })
        .find(|candidate| is_executable(candidate))
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(a), Ok(b)) if a == b)
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
        "npx" => runner(&args, Runner::LocalFirst, cwd, local_bin),
        "bunx" => runner(&args, Runner::LocalFirst, cwd, local_bin),
        "pnpx" => runner(&args, Runner::Download, cwd, local_bin),
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
];

/// Effect of one install flag on the translated `lpm install`.
enum InstallFlag {
    Dir,
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
    match (manager, name) {
        ("npm", "--prefix" | "-C") | ("pnpm", "-C" | "--dir") | ("yarn" | "bun", "--cwd") => {
            InstallFlag::Dir
        }
        (_, "--save-dev")
        | ("npm" | "pnpm" | "yarn" | "bun", "-D")
        | ("yarn" | "bun", "--dev")
        | ("bun", "-d" | "--development") => InstallFlag::Lpm("-D"),
        ("npm", "--production" | "--prod") | ("npm", "--omit")
            if value == Some("dev") || name != "--omit" =>
        {
            InstallFlag::Lpm("--prod")
        }
        ("pnpm", "-P" | "--prod" | "--production")
        | ("yarn", "--production" | "--prod")
        | ("bun", "-p" | "--production") => InstallFlag::Lpm("--prod"),
        ("pnpm" | "yarn" | "bun", "--frozen-lockfile") | ("yarn", "--immutable") => {
            InstallFlag::Lpm("--frozen-lockfile")
        }
        (_, "--offline") => InstallFlag::Lpm("--offline"),
        (_, "--ignore-scripts") if value.is_none_or(|v| v == "true") => {
            InstallFlag::Lpm("--policy=deny")
        }
        (_, "--strict-peer-dependencies") => InstallFlag::Lpm("--strict-peer-dependencies"),
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
            | "--save-exact"
            | "--exact"
            | "-E"
            | "--save"
            | "-S"
            | "--save-prod"
            | "--legacy-peer-deps"
            | "--no-package-lock"
            | "--prefer-frozen-lockfile"
            | "--yes"
            | "--no-optional-yes",
        ) => InstallFlag::Ignore,
        ("npm", "-P") => InstallFlag::Ignore,
        _ => InstallFlag::Unsupported,
    }
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
        ("yarn", None | Some("install" | "add")) => true,
        ("bun", Some("install" | "i" | "add" | "a")) => true,
        _ => false,
    };
    let is_clean_install =
        manager == "npm" && subcommand.is_some_and(|sub| NPM_CLEAN_INSTALL.contains(&sub));
    let rest = subcommand_index.map_or(args, |index| &args[index + 1..]);
    if is_install || is_clean_install {
        return install(manager, args, subcommand_index, is_clean_install, cwd);
    }
    match (manager, subcommand) {
        ("npm", Some("exec" | "x")) | ("bun", Some("x")) => {
            Some(runner(rest, Runner::LocalFirst, cwd, local_bin))
        }
        ("pnpm" | "yarn", Some("dlx")) => Some(runner(rest, Runner::Download, cwd, local_bin)),
        _ => None,
    }
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
        lpm_flags.retain(|flag| matches!(*flag, "--prod" | "--offline"));
    } else {
        lpm_args.push("install".to_string());
        if packages.is_empty() {
            lpm_flags.remove("-D");
        } else {
            lpm_flags.retain(|flag| !matches!(*flag, "--frozen-lockfile" | "--prod" | "--offline"));
        }
    }
    lpm_args.extend(lpm_flags.iter().map(|flag| (*flag).to_string()));
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
    if kind == Runner::LocalFirst && !command.contains('@') && local_bin(cwd, command) {
        return Plan::Lpm {
            args: std::iter::once("exec".to_string())
                .chain(std::iter::once((*command).to_string()))
                .chain(rest)
                .collect(),
            dir: None,
        };
    }
    if local_only {
        return Plan::Real;
    }
    Plan::Lpm {
        args: std::iter::once("dlx".to_string())
            .chain(std::iter::once((*command).to_string()))
            .chain(rest)
            .collect(),
        dir: None,
    }
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

/// The lockfile of the nearest directory at or above `dir` that has one,
/// when no `lpm.lock` sits beside it. Such a project belongs to another
/// package manager, so its installs stay with that manager; a project with
/// `lpm.lock`, or with no lockfile yet, is LPM's to install.
fn foreign_lockfile(dir: &Path) -> Option<&'static str> {
    for ancestor in dir.ancestors() {
        let mut foreign = None;
        for (file, is_lpm) in LOCKFILES {
            if ancestor.join(file).is_file() {
                if *is_lpm {
                    return None;
                }
                foreign.get_or_insert(*file);
            }
        }
        if foreign.is_some() {
            return foreign;
        }
    }
    None
}

/// `plan` with installs into a project another package manager owns
/// turned back into the real command, and why.
fn respect_project_owner(plan: Plan, cwd: &Path) -> (Plan, Option<String>) {
    let Plan::Lpm { args, dir } = &plan else {
        return (plan, None);
    };
    if !matches!(args.first().map(String::as_str), Some("install" | "ci")) {
        return (plan, None);
    }
    match foreign_lockfile(dir.as_deref().unwrap_or(cwd)) {
        Some(lockfile) => (Plan::Real, Some(format!("the project uses {lockfile}"))),
        None => (plan, None),
    }
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

fn read_log(path: &Path) -> Vec<LogEntry> {
    let Ok(bytes) = lpm_common::read_file_capped(path, MAX_LOG_BYTES) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
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
    let shim_dir = std::env::var_os(SHIMS_ENV).map(PathBuf::from);
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
    let (plan, reason) = respect_project_owner(plan, &cwd);
    if let Some(log) = std::env::var_os(LOG_ENV) {
        append_log(
            Path::new(&log),
            &LogEntry {
                manager: manager.to_string(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
                dir: match &plan {
                    Plan::Lpm { dir: Some(dir), .. } => dir.clone(),
                    _ => cwd.clone(),
                },
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
                .env("PATH", path_without(&path, shim_dir.as_deref())?)
                .env_remove(SHIMS_ENV)
                .env_remove(LOG_ENV)
                .env_remove(USER_AGENT_ENV);
            command
        }
        Plan::Real => {
            let Some(real) = find_on_path(manager, &path, shim_dir.as_deref()) else {
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

fn path_without(path: &OsStr, skip: Option<&Path>) -> Result<OsString, LpmError> {
    let Some(skip) = skip else {
        return Ok(path.to_os_string());
    };
    std::env::join_paths(std::env::split_paths(path).filter(|dir| !same_dir(dir, skip)))
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
        let entries = session.entries();
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
        ("yarn" | "yarnpkg", None) => true,
        ("yarn" | "yarnpkg", Some(sub)) => matches!(sub, "install" | "add"),
        ("bun", Some(sub)) => matches!(sub, "install" | "i" | "add" | "a"),
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
            lpm("install react react-dom")
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
            ("npm", "install --registry https://example.invalid"),
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
            lpm("exec tsc --noEmit")
        );
        assert_eq!(plan_with_local("bunx", "tsc", &["tsc"]), lpm("exec tsc"));
        assert_eq!(
            plan_with_local("npm", "exec -- tsc -b", &["tsc"]),
            lpm("exec tsc -b")
        );
        assert_eq!(
            plan("npx", "-y create-vite@latest app"),
            lpm("dlx create-vite@latest app")
        );
        assert_eq!(plan("npx", "cowsay hi"), lpm("dlx cowsay hi"));
        assert_eq!(plan("npm", "x cowsay"), lpm("dlx cowsay"));
        assert_eq!(plan("bun", "x cowsay"), lpm("dlx cowsay"));
        assert_eq!(
            plan_with_local("npx", "tsc@5 --version", &["tsc"]),
            lpm("dlx tsc@5 --version"),
            "a versioned spec asks for a download"
        );
    }

    #[test]
    fn download_runners_always_go_through_lpm_dlx() {
        assert_eq!(plan_with_local("pnpm", "dlx tsc", &["tsc"]), lpm("dlx tsc"));
        assert_eq!(
            plan("yarn", "dlx create-thing app"),
            lpm("dlx create-thing app")
        );
        assert_eq!(plan("pnpx", "create-thing"), lpm("dlx create-thing"));
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
    fn real_binary_lookup_skips_the_shim_directory() {
        use std::os::unix::fs::PermissionsExt;
        let shims = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        for dir in [shims.path(), real.path()] {
            let file = dir.join("pnpm");
            std::fs::write(&file, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([shims.path(), real.path()]).unwrap();
        assert_eq!(
            find_on_path("pnpm", &path, None),
            Some(shims.path().join("pnpm"))
        );
        assert_eq!(
            find_on_path("pnpm", &path, Some(shims.path())),
            Some(real.path().join("pnpm"))
        );
        assert_eq!(find_on_path("yarn", &path, None), None);
        assert_eq!(
            path_without(&path, Some(shims.path())).unwrap(),
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
        let app = root.path().join("apps/web");
        std::fs::create_dir_all(&app).unwrap();
        assert_eq!(
            foreign_lockfile(&app),
            None,
            "a fresh project is LPM's to install"
        );

        std::fs::write(root.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(foreign_lockfile(&app), Some("pnpm-lock.yaml"));
        let (plan, reason) = respect_project_owner(lpm("install"), &app);
        assert_eq!(plan, Plan::Real);
        assert_eq!(reason.as_deref(), Some("the project uses pnpm-lock.yaml"));
        assert_eq!(
            respect_project_owner(lpm("dlx cowsay"), &app),
            (lpm("dlx cowsay"), None),
            "running a package does not install into the project"
        );

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
        assert_eq!(read_log(log.path()), [entry.clone(), entry]);
    }
}
