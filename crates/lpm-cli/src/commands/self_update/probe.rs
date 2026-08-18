use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use lpm_common::LpmError;

#[cfg(not(debug_assertions))]
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
// Debug binaries can spend tens of seconds in loader/linker work when the
// workflow suite launches every self-update case concurrently.
#[cfg(debug_assertions)]
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(not(debug_assertions))]
const MANAGER_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(debug_assertions)]
const MANAGER_QUERY_TIMEOUT: Duration = Duration::from_secs(120);
const MANAGER_UPDATE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const VERSION_OUTPUT_LIMIT: usize = 4 * 1024;

#[derive(Clone)]
struct ChildEnvironment {
    path: OsString,
    variables: Vec<(OsString, OsString)>,
}

impl ChildEnvironment {
    fn from_current(
        sanitized_path: &OsStr,
        environment_exclusion_root: Option<&Path>,
        account_home: &Path,
        current_executable: &Path,
        manager_program: &Path,
    ) -> Self {
        let mut variables = std::env::vars_os()
            .filter(|(key, value)| {
                child_environment_entry_allowed(
                    key,
                    value,
                    environment_exclusion_root,
                    account_home,
                    current_executable,
                    manager_program,
                )
            })
            .collect::<Vec<_>>();
        variables.push((
            OsString::from(if cfg!(windows) { "USERPROFILE" } else { "HOME" }),
            account_home.as_os_str().to_owned(),
        ));
        variables.extend(probe_os_variables());
        Self {
            path: sanitized_path.to_owned(),
            variables,
        }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env_clear()
            .envs(self.variables.iter().map(|(key, value)| (key, value)))
            .env("PATH", &self.path);
    }
}

#[derive(Clone)]
struct ProbeEnvironment {
    path: Option<OsString>,
    variables: Vec<(OsString, OsString)>,
}

impl ProbeEnvironment {
    fn for_launcher(sanitized_path: &OsStr) -> Self {
        Self {
            path: Some(sanitized_path.to_owned()),
            variables: probe_os_variables(),
        }
    }

    fn for_staged_binary() -> Self {
        Self {
            path: None,
            variables: probe_os_variables(),
        }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env_clear()
            .envs(self.variables.iter().map(|(key, value)| (key, value)));
        if let Some(path) = self.path.as_ref() {
            command.env("PATH", path);
        }
    }
}

#[cfg(windows)]
fn probe_os_variables() -> Vec<(OsString, OsString)> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0_u16; 32_768];
    // SAFETY: `buffer` is writable for the supplied length. The function
    // writes at most that many UTF-16 code units and returns their count.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Vec::new();
    }
    let mut system_directory = PathBuf::from(OsString::from_wide(&buffer[..length]));
    system_directory.push("cmd.exe");
    let windows_directory = system_directory
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let mut variables = Vec::with_capacity(4);
    variables.push((OsString::from("COMSPEC"), system_directory.into_os_string()));
    if let Some(windows_directory) = windows_directory {
        variables.push((
            OsString::from("SYSTEMROOT"),
            windows_directory.as_os_str().to_owned(),
        ));
        variables.push((OsString::from("WINDIR"), windows_directory.into_os_string()));
    }
    variables.push((
        OsString::from("PATHEXT"),
        OsString::from(".COM;.EXE;.BAT;.CMD"),
    ));
    variables
}

#[cfg(not(windows))]
fn probe_os_variables() -> Vec<(OsString, OsString)> {
    Vec::new()
}

fn child_environment_key_allowed(key: &OsStr) -> bool {
    let key = key.to_string_lossy().to_ascii_uppercase();
    matches!(
        key.as_str(),
        "HOME"
            | "USER"
            | "LOGNAME"
            | "LANG"
            | "LC_ALL"
            | "USERPROFILE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMDATA"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "XDG_CACHE_HOME"
            | "CARGO_HOME"
            | "CARGO_INSTALL_ROOT"
            | "RUSTUP_HOME"
            | "PNPM_HOME"
            | "NPM_CONFIG_GLOBAL_DIR"
            | "NPM_CONFIG_GLOBAL_BIN_DIR"
            | "NPM_CONFIG_PREFIX"
            | "BUN_INSTALL"
            | "BUN_INSTALL_GLOBAL_DIR"
            | "BUN_INSTALL_GLOBAL_BIN_DIR"
            | "YARN_GLOBAL_FOLDER"
            | "VOLTA_HOME"
            | "HTTPS_PROXY"
            | "HTTP_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "NODE_EXTRA_CA_CERTS"
            | "TEMP"
            | "TMP"
            | "TMPDIR"
    ) || key.starts_with("LC_")
}

fn child_environment_entry_allowed(
    key: &OsStr,
    value: &OsStr,
    excluded_root: Option<&Path>,
    account_home: &Path,
    current_executable: &Path,
    manager_program: &Path,
) -> bool {
    if !child_environment_key_allowed(key) {
        return false;
    }
    let key = key.to_string_lossy();
    if matches_ignore_ascii_case(&key, &["HOME", "USERPROFILE"]) {
        return false;
    }
    if !matches_ignore_ascii_case(
        &key,
        &[
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "CARGO_HOME",
            "CARGO_INSTALL_ROOT",
            "RUSTUP_HOME",
            "PNPM_HOME",
            "NPM_CONFIG_GLOBAL_DIR",
            "NPM_CONFIG_GLOBAL_BIN_DIR",
            "NPM_CONFIG_PREFIX",
            "BUN_INSTALL",
            "BUN_INSTALL_GLOBAL_DIR",
            "BUN_INSTALL_GLOBAL_BIN_DIR",
            "YARN_GLOBAL_FOLDER",
            "VOLTA_HOME",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
            "TEMP",
            "TMP",
            "TMPDIR",
        ],
    ) {
        return true;
    }
    let path = Path::new(value);
    if !path.is_absolute() || excluded_root.is_some_and(|root| path_may_be_within(path, root)) {
        return false;
    }
    if matches_ignore_ascii_case(&key, &["TEMP", "TMP", "TMPDIR"]) {
        return true;
    }
    if matches_ignore_ascii_case(
        &key,
        &["SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"],
    ) {
        return path_is_system_configuration(path);
    }
    if key.eq_ignore_ascii_case("CARGO_HOME") {
        return path_is_specific_ancestor(path, manager_program);
    }
    if key.eq_ignore_ascii_case("RUSTUP_HOME") {
        return paths_resolve_to_same_location(path, &account_home.join(".rustup"));
    }
    if key.eq_ignore_ascii_case("CARGO_INSTALL_ROOT") {
        return path_is_specific_ancestor(path, current_executable);
    }
    if path_is_known_within(path, account_home) {
        return true;
    }
    if matches_ignore_ascii_case(
        &key,
        &[
            "NPM_CONFIG_GLOBAL_DIR",
            "NPM_CONFIG_GLOBAL_BIN_DIR",
            "NPM_CONFIG_PREFIX",
            "PNPM_HOME",
            "BUN_INSTALL",
            "BUN_INSTALL_GLOBAL_DIR",
            "BUN_INSTALL_GLOBAL_BIN_DIR",
            "YARN_GLOBAL_FOLDER",
            "VOLTA_HOME",
        ],
    ) && (path_is_specific_ancestor(path, current_executable)
        || path_is_specific_ancestor(path, manager_program))
    {
        return true;
    }
    false
}

fn path_is_specific_ancestor(root: &Path, candidate: &Path) -> bool {
    root.parent().is_some()
        && root
            .parent()
            .is_some_and(|parent| parent.parent().is_some())
        && path_is_known_within(candidate, root)
}

#[cfg(unix)]
fn path_is_system_configuration(path: &Path) -> bool {
    [
        Path::new("/etc"),
        Path::new("/usr/local/etc"),
        Path::new("/opt/homebrew/etc"),
        Path::new("/Library"),
    ]
    .into_iter()
    .any(|root| path_is_known_within(path, root))
}

#[cfg(not(unix))]
fn path_is_system_configuration(_path: &Path) -> bool {
    false
}

fn matches_ignore_ascii_case(value: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

pub(super) fn sanitized_current_path(excluded_root: Option<&Path>) -> Result<OsString, LpmError> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        LpmError::SelfUpdate("cannot verify self-update because PATH is unset".to_string())
    })?;
    let resolved_excluded_root = excluded_root
        .map(resolve_for_containment)
        .transpose()
        .map_err(|()| {
            LpmError::SelfUpdate(
                "could not resolve the active containment root for PATH filtering".to_string(),
            )
        })?;
    let entries = std::env::split_paths(&path)
        .filter(|entry| entry.is_absolute())
        .filter(|entry| !path_has_node_modules_bin(entry))
        .filter(|entry| {
            resolved_excluded_root.as_ref().is_none_or(|root| {
                resolve_for_containment(entry).is_ok_and(|entry| !entry.starts_with(root))
            })
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not build a sanitized PATH for self-update: {error}"
        ))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgramKind {
    Native,
    #[cfg(windows)]
    CmdScript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedProgram {
    path: PathBuf,
    kind: ProgramKind,
}

impl ResolvedProgram {
    fn current_executable() -> Result<Self, LpmError> {
        let path = std::env::current_exe().map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not resolve the running executable for post-update verification: {error}"
            ))
        })?;
        let path = std::fs::canonicalize(&path).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not resolve the running executable for post-update verification: {error}"
            ))
        })?;
        Ok(Self {
            path,
            kind: ProgramKind::Native,
        })
    }

    fn on_path(name: &str, path: &OsStr, project_root: Option<&Path>) -> Result<Self, LpmError> {
        resolve_program_on_path(name, path, project_root).ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "cannot verify self-update because `{name}` does not resolve to an absolute non-project executable on PATH"
            ))
        })
    }

    fn command(&self, args: &[OsString]) -> Command {
        match self.kind {
            ProgramKind::Native => {
                let mut command = Command::new(&self.path);
                command.args(args);
                command
            }
            #[cfg(windows)]
            ProgramKind::CmdScript => {
                let mut command = Command::new(&self.path);
                command.args(args);
                command
            }
        }
    }
}

pub(super) struct BoundUpdateCommand {
    program: ResolvedProgram,
    program_identity: same_file::Handle,
    args: Vec<OsString>,
    logical_name: &'static str,
    environment: ChildEnvironment,
    account_home: PathBuf,
}

impl BoundUpdateCommand {
    pub(super) fn bind(
        logical_name: &'static str,
        args: &[OsString],
        sanitized_path: &OsStr,
        project_root: Option<&Path>,
        environment_exclusion_root: Option<&Path>,
        account_home: &Path,
        current_executable: &Path,
    ) -> Result<Self, LpmError> {
        let mut program = ResolvedProgram::on_path(logical_name, sanitized_path, project_root)?;
        program.path = std::fs::canonicalize(&program.path).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "cannot bind the resolved {logical_name} executable: {error}"
            ))
        })?;
        if is_project_local_program(&program.path, project_root) {
            return Err(LpmError::SelfUpdate(format!(
                "cannot bind {logical_name} from a project-local path"
            )));
        }
        let program_identity = same_file::Handle::from_path(&program.path).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "cannot bind the resolved {logical_name} executable identity: {error}"
            ))
        })?;
        let environment = ChildEnvironment::from_current(
            sanitized_path,
            environment_exclusion_root,
            account_home,
            current_executable,
            &program.path,
        );
        Ok(Self {
            program,
            program_identity,
            args: args.to_vec(),
            logical_name,
            environment,
            account_home: account_home.to_path_buf(),
        })
    }

    pub(super) fn render_verified_plan(&self) -> Result<String, LpmError> {
        super::render_update_invocation(self.program.path.as_os_str(), &self.args)
    }

    pub(super) fn verified_program_utf8(&self) -> Result<&str, LpmError> {
        self.program.path.to_str().ok_or_else(|| {
            LpmError::SelfUpdate(
                "cannot emit a runnable self-update plan containing a non-UTF-8 program path"
                    .to_string(),
            )
        })
    }

    pub(super) fn args_utf8(&self) -> Result<Vec<&str>, LpmError> {
        super::utf8_update_args(&self.args)
    }

    pub(super) fn ensure_owns_launcher(
        &self,
        probe: &VersionProbe,
        method: &super::InstallMethod,
    ) -> Result<(), LpmError> {
        self.ensure_program_unchanged()?;
        let launcher_dir = &probe.launcher_dir;
        if !manager_program_location_allowed(&self.program.path, launcher_dir, &self.account_home) {
            return Err(LpmError::SelfUpdate(format!(
                "refusing to run {} from an untrusted filesystem location",
                self.logical_name
            )));
        }
        match method {
            super::InstallMethod::Npm => {
                let prefix = self.query_absolute_path(&["prefix", "--global"])?;
                let prefix_bin = prefix.join("bin");
                if path_is_known_within(&probe.expected_executable, &prefix)
                    && (paths_resolve_to_same_location(launcher_dir, &prefix)
                        || paths_resolve_to_same_location(launcher_dir, &prefix_bin))
                {
                    return Ok(());
                }
            }
            super::InstallMethod::Pnpm => {
                let bin = self.query_absolute_path(&["bin", "--global"])?;
                if paths_resolve_to_same_location(launcher_dir, &bin) {
                    return Ok(());
                }
            }
            super::InstallMethod::Bun => {
                let bin = self.query_absolute_path(&["pm", "bin", "--global"])?;
                if paths_resolve_to_same_location(launcher_dir, &bin) {
                    return Ok(());
                }
            }
            super::InstallMethod::Yarn => {
                let bin = self.query_absolute_path(&["global", "bin"])?;
                if paths_resolve_to_same_location(launcher_dir, &bin) {
                    return Ok(());
                }
            }
            super::InstallMethod::Volta => {
                let executable = self.query_absolute_path(&["which", "lpm"])?;
                if paths_resolve_to_same_location(&probe.expected_executable, &executable) {
                    return Ok(());
                }
            }
            super::InstallMethod::Homebrew => {
                let prefix = self.query_absolute_path(&["--prefix", "lpm"])?;
                if path_is_known_within(&probe.expected_executable, &prefix) {
                    return Ok(());
                }
            }
            super::InstallMethod::Cargo => return Ok(()),
            super::InstallMethod::Standalone => return Ok(()),
        }
        Err(LpmError::SelfUpdate(format!(
            "refusing to run {} because its global target does not own the active LPM launcher",
            self.logical_name
        )))
    }

    fn query_absolute_path(&self, args: &[&str]) -> Result<PathBuf, LpmError> {
        self.ensure_program_unchanged()?;
        let args = args.iter().map(OsString::from).collect::<Vec<_>>();
        let mut command = self.program.command(&args);
        self.environment.apply(&mut command);
        command
            .current_dir(
                self.program
                    .path
                    .parent()
                    .unwrap_or_else(|| Path::new(std::path::MAIN_SEPARATOR_STR)),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("NO_COLOR", "1");
        let output = run_bounded(
            &mut command,
            MANAGER_QUERY_TIMEOUT,
            "package-manager ownership query",
        )?;
        if !output.status.success()
            || output.stdout.overflowed
            || output.stderr.overflowed
            || output.stdout.read_error.is_some()
            || output.stderr.read_error.is_some()
        {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify the {} global install target",
                self.logical_name
            )));
        }
        let bytes = remove_one_line_ending(&output.stdout.bytes);
        let value = std::str::from_utf8(bytes).map_err(|_| {
            LpmError::SelfUpdate(format!(
                "{} returned a non-UTF-8 global install target",
                self.logical_name
            ))
        })?;
        if value.is_empty() || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(LpmError::SelfUpdate(format!(
                "{} returned an invalid global install target",
                self.logical_name
            )));
        }
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(LpmError::SelfUpdate(format!(
                "{} returned a relative global install target",
                self.logical_name
            )));
        }
        Ok(path)
    }

    pub(super) fn run(&self) -> Result<(), LpmError> {
        self.ensure_program_unchanged()?;
        let mut command = self.program.command(&self.args);
        self.environment.apply(&mut command);
        command.current_dir(
            self.program
                .path
                .parent()
                .unwrap_or_else(|| Path::new(std::path::MAIN_SEPARATOR_STR)),
        );
        let child = lpm_sandbox::spawn_tracked_command(&mut command).map_err(|error| {
            LpmError::Script(format!("failed to run {}: {error}", self.logical_name))
        })?;
        let status = crate::commands::rebuild::process_tree::wait_with_timeout(
            child,
            &MANAGER_UPDATE_TIMEOUT,
        )
        .map_err(|error| LpmError::Script(format!("{} {error}", self.logical_name)))?;
        if !status.success() {
            return Err(LpmError::Script(format!(
                "{} exited with code {}",
                self.logical_name,
                status.code().unwrap_or(-1)
            )));
        }
        Ok(())
    }

    fn ensure_program_unchanged(&self) -> Result<(), LpmError> {
        let current = same_file::Handle::from_path(&self.program.path).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "{} changed after it was bound for self-update: {error}",
                self.logical_name
            ))
        })?;
        if current != self.program_identity {
            return Err(LpmError::SelfUpdate(format!(
                "{} changed after it was bound for self-update",
                self.logical_name
            )));
        }
        Ok(())
    }
}

pub(super) struct VersionProbe {
    program: ResolvedProgram,
    launcher_dir: PathBuf,
    launcher_binding: Option<LauncherBinding>,
    environment: ProbeEnvironment,
    working_dir: PathBuf,
    expected_executable: PathBuf,
    timeout: Duration,
}

struct LauncherBinding {
    program: ResolvedProgram,
    current_directory: PathBuf,
    account_home: PathBuf,
}

impl LauncherBinding {
    fn rebind(&self) -> Result<ResolvedProgram, LpmError> {
        if !manager_program_location_allowed(
            &self.program.path,
            &self.current_directory,
            &self.account_home,
        ) {
            return Err(LpmError::SelfUpdate(
                "refusing to verify the updated LPM launcher from an untrusted filesystem location"
                    .to_string(),
            ));
        }
        let path = std::fs::canonicalize(&self.program.path).map_err(|error| {
            LpmError::SelfUpdate(format!("could not bind the updated LPM launcher: {error}"))
        })?;
        if !manager_program_location_allowed(&path, &self.current_directory, &self.account_home) {
            return Err(LpmError::SelfUpdate(
                "refusing to verify the updated LPM launcher target from an untrusted filesystem location"
                    .to_string(),
            ));
        }
        Ok(ResolvedProgram {
            path,
            kind: self.program.kind.clone(),
        })
    }
}

impl VersionProbe {
    pub(super) fn verify_staged(
        temporary: &tempfile::NamedTempFile,
        expected_sha256: &str,
        version: &str,
    ) -> Result<(), LpmError> {
        super::download::ensure_staged_file_unchanged(temporary, expected_sha256)?;
        let path = temporary.path();
        let path = std::fs::canonicalize(path).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not resolve the staged self-update binary {}: {error}",
                path.display()
            ))
        })?;
        let environment = ProbeEnvironment::for_staged_binary();
        let working_dir = path
            .parent()
            .unwrap_or_else(|| Path::new(std::path::MAIN_SEPARATOR_STR))
            .to_path_buf();
        Self {
            program: ResolvedProgram {
                path: path.clone(),
                kind: ProgramKind::Native,
            },
            launcher_dir: working_dir.clone(),
            launcher_binding: None,
            environment,
            working_dir,
            expected_executable: path,
            timeout: VERSION_PROBE_TIMEOUT,
        }
        .verify(version, "in the staged release asset", false)
    }

    pub(super) fn bind_and_preflight(
        use_current_executable: bool,
        current_version: &str,
        current_executable: &Path,
        working_dir: &Path,
        sanitized_path: &OsStr,
        project_root: Option<&Path>,
        account_home: &Path,
    ) -> Result<Self, LpmError> {
        let environment = ProbeEnvironment::for_launcher(sanitized_path);
        let launcher_program = if use_current_executable {
            ResolvedProgram::current_executable()?
        } else {
            let path = environment.path.as_deref().ok_or_else(|| {
                LpmError::SelfUpdate("launcher probe has no sanitized PATH".to_string())
            })?;
            ResolvedProgram::on_path("lpm", path, project_root)?
        };
        let launcher_dir = launcher_program
            .path
            .parent()
            .ok_or_else(|| {
                LpmError::SelfUpdate(
                    "could not resolve the active LPM launcher directory".to_string(),
                )
            })?
            .to_path_buf();
        let current_directory = current_executable.parent().ok_or_else(|| {
            LpmError::SelfUpdate(
                "could not resolve the active LPM executable directory".to_string(),
            )
        })?;
        if !manager_program_location_allowed(
            &launcher_program.path,
            current_directory,
            account_home,
        ) {
            return Err(LpmError::SelfUpdate(
                "refusing to verify an LPM launcher from an untrusted filesystem location"
                    .to_string(),
            ));
        }
        let program_path = std::fs::canonicalize(&launcher_program.path).map_err(|error| {
            LpmError::SelfUpdate(format!("could not bind the active LPM launcher: {error}"))
        })?;
        let program = ResolvedProgram {
            path: program_path,
            kind: launcher_program.kind.clone(),
        };
        let probe = Self {
            program,
            launcher_dir,
            launcher_binding: Some(LauncherBinding {
                program: launcher_program,
                current_directory: current_directory.to_path_buf(),
                account_home: account_home.to_path_buf(),
            }),
            environment,
            working_dir: working_dir.to_path_buf(),
            expected_executable: current_executable.to_path_buf(),
            timeout: VERSION_PROBE_TIMEOUT,
        };
        probe.verify(current_version, "before the update", true)?;
        Ok(probe)
    }

    pub(super) fn verify_requested(&self, version: &str) -> Result<(), LpmError> {
        let program = self
            .launcher_binding
            .as_ref()
            .map(LauncherBinding::rebind)
            .transpose()?
            .unwrap_or_else(|| self.program.clone());
        self.verify_with_program(
            &program,
            version,
            "after the package manager exited successfully",
            false,
        )
    }

    fn verify(&self, version: &str, phase: &str, verify_executable: bool) -> Result<(), LpmError> {
        self.verify_with_program(&self.program, version, phase, verify_executable)
    }

    fn verify_with_program(
        &self,
        program: &ResolvedProgram,
        version: &str,
        phase: &str,
        verify_executable: bool,
    ) -> Result<(), LpmError> {
        let mut args = vec![OsString::from("-V")];
        if verify_executable {
            args.push("--self-update-probe-executable".into());
            args.push(self.expected_executable.as_os_str().to_owned());
        }
        let mut command = program.command(&args);
        sanitize_probe_command(&mut command, &self.environment, &self.working_dir);
        let output = run_bounded(&mut command, self.timeout, "bound LPM version probe")?;

        if output.stdout.read_error.is_some() || output.stderr.read_error.is_some() {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify LPM {phase}: failed to read version output"
            )));
        }
        if output.stdout.overflowed || output.stderr.overflowed {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify LPM {phase}: version output exceeded {VERSION_OUTPUT_LIMIT} bytes"
            )));
        }
        if !output.status.success() {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify LPM {phase}: the bound launcher exited with code {}",
                output.status.code().unwrap_or(-1)
            )));
        }
        if !output.stderr.bytes.is_empty() {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify LPM {phase}: the bound launcher wrote unexpected stderr"
            )));
        }

        let expected = if verify_executable {
            format!("lpm {version}\nself-update-executable-ok")
        } else {
            format!("lpm {version}")
        };
        let stdout = remove_one_line_ending(&output.stdout.bytes);
        if stdout != expected.as_bytes() {
            return Err(LpmError::SelfUpdate(format!(
                "could not verify LPM {phase}: the bound launcher did not report exact version {version}"
            )));
        }
        Ok(())
    }
}

fn sanitize_probe_command(
    command: &mut Command,
    environment: &ProbeEnvironment,
    working_dir: &Path,
) {
    environment.apply(command);
    command
        .current_dir(working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LPM_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .env_remove("FORCE_COLOR");
}

fn resolve_program_on_path(
    name: &str,
    path: &OsStr,
    project_root: Option<&Path>,
) -> Option<ResolvedProgram> {
    for directory in std::env::split_paths(path) {
        if !directory.is_absolute() {
            continue;
        }
        for (candidate, kind) in candidates(&directory, name) {
            if !candidate.is_file() || is_project_local_program(&candidate, project_root) {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let Ok(metadata) = candidate.metadata() else {
                    continue;
                };
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Some(ResolvedProgram {
                path: candidate,
                kind,
            });
        }
    }
    None
}

#[cfg(not(windows))]
fn candidates(directory: &Path, name: &str) -> std::iter::Once<(PathBuf, ProgramKind)> {
    std::iter::once((directory.join(name), ProgramKind::Native))
}

#[cfg(windows)]
fn candidates(directory: &Path, name: &str) -> Vec<(PathBuf, ProgramKind)> {
    windows_candidates(directory, name, OsStr::new(".EXE;.CMD"))
}

#[cfg(windows)]
fn windows_candidates(
    directory: &Path,
    name: &str,
    extensions: &OsStr,
) -> Vec<(PathBuf, ProgramKind)> {
    extensions
        .to_string_lossy()
        .split(';')
        .filter_map(|extension| {
            let extension = extension.trim();
            if extension.eq_ignore_ascii_case(".EXE") {
                Some((
                    directory.join(format!("{name}{extension}")),
                    ProgramKind::Native,
                ))
            } else if extension.eq_ignore_ascii_case(".CMD") {
                Some((
                    directory.join(format!("{name}{extension}")),
                    ProgramKind::CmdScript,
                ))
            } else {
                None
            }
        })
        .collect()
}

fn is_project_local_program(candidate: &Path, project_root: Option<&Path>) -> bool {
    path_has_node_modules_bin(candidate)
        || project_root.is_some_and(|root| path_may_be_within(candidate, root))
}

fn path_has_node_modules_bin(path: &Path) -> bool {
    let mut previous_was_node_modules = false;
    for component in path.components() {
        let Some(component) = component.as_os_str().to_str() else {
            previous_was_node_modules = false;
            continue;
        };
        if previous_was_node_modules && component.eq_ignore_ascii_case(".bin") {
            return true;
        }
        previous_was_node_modules = component.eq_ignore_ascii_case("node_modules");
    }
    false
}

fn path_may_be_within(candidate: &Path, root: &Path) -> bool {
    match (
        resolve_for_containment(candidate),
        resolve_for_containment(root),
    ) {
        (Ok(candidate), Ok(root)) => candidate.starts_with(root),
        _ => true,
    }
}

fn path_is_known_within(candidate: &Path, root: &Path) -> bool {
    resolve_for_containment(candidate)
        .and_then(|candidate| resolve_for_containment(root).map(|root| candidate.starts_with(root)))
        .unwrap_or(false)
}

fn resolve_for_containment(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(());
    }

    let mut unresolved = Vec::<OsString>::new();
    let mut ancestor = path;
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(ancestor) {
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        unresolved.push(ancestor.file_name().ok_or(())?.to_owned());
        ancestor = ancestor.parent().ok_or(())?;
    }
}

fn paths_resolve_to_same_location(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn manager_program_location_allowed(
    manager: &Path,
    _launcher_dir: &Path,
    account_home: &Path,
) -> bool {
    if path_is_known_within(manager, account_home) {
        #[cfg(unix)]
        return manager_path_is_private_to_account(manager, account_home);
        #[cfg(windows)]
        return super::windows_trust::path_is_private_to_account(manager, account_home);
        #[cfg(not(any(unix, windows)))]
        return false;
    }
    if path_is_temporary(manager, account_home) {
        return false;
    }
    manager_path_has_trusted_ownership(manager)
}

#[cfg(unix)]
fn manager_path_is_private_to_account(manager: &Path, account_home: &Path) -> bool {
    let Ok(resolved_manager) = std::fs::canonicalize(manager) else {
        return false;
    };
    if !path_is_known_within(&resolved_manager, account_home) {
        return false;
    }

    path_chain_is_private_to_account(&resolved_manager, account_home, false)
        && (path_chain_is_private_to_account(manager, account_home, true)
            || trusted_path_chain_has_expected_ownership(manager, true, false))
}

#[cfg(unix)]
fn path_chain_is_private_to_account(
    path: &Path,
    account_home: &Path,
    allow_leaf_symlink: bool,
) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    for (index, ancestor) in path.ancestors().enumerate() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        let leaf_symlink = index == 0 && allow_leaf_symlink && metadata.file_type().is_symlink();
        if (!leaf_symlink && metadata.file_type().is_symlink()) || metadata.uid() != effective_uid {
            return false;
        }
        if !leaf_symlink && metadata.permissions().mode() & 0o022 != 0 {
            return false;
        }
        if ancestor == account_home
            || std::fs::canonicalize(ancestor).is_ok_and(|path| path == account_home)
        {
            return true;
        }
    }
    false
}

fn path_is_temporary(path: &Path, account_home: &Path) -> bool {
    let mut roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
    let environment_temp = std::env::temp_dir();
    if !path_is_known_within(&environment_temp, account_home) {
        roots.push(environment_temp);
    }
    roots.iter().any(|root| path_is_known_within(path, root))
}

#[cfg(unix)]
fn manager_path_has_trusted_ownership(manager: &Path) -> bool {
    let Ok(resolved_manager) = std::fs::canonicalize(manager) else {
        return false;
    };
    let allow_owner_group_write = is_homebrew_manager_path(manager);
    trusted_path_chain_has_expected_ownership(manager, true, allow_owner_group_write)
        && trusted_path_chain_has_expected_ownership(
            &resolved_manager,
            false,
            allow_owner_group_write || is_homebrew_manager_path(&resolved_manager),
        )
}

#[cfg(unix)]
fn is_homebrew_manager_path(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("brew"))
        && [
            Path::new("/opt/homebrew"),
            Path::new("/usr/local/Homebrew"),
            Path::new("/usr/local/bin"),
            Path::new("/home/linuxbrew/.linuxbrew"),
        ]
        .into_iter()
        .any(|root| path_is_known_within(path, root))
}

#[cfg(unix)]
fn trusted_path_chain_has_expected_ownership(
    path: &Path,
    allow_leaf_symlink: bool,
    allow_effective_owner_group_write: bool,
) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    for (index, ancestor) in path.ancestors().enumerate() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        let leaf_symlink = index == 0 && allow_leaf_symlink && metadata.file_type().is_symlink();
        let owner = metadata.uid();
        if (!leaf_symlink && metadata.file_type().is_symlink())
            || (owner != 0 && owner != effective_uid)
        {
            return false;
        }
        if leaf_symlink {
            continue;
        }
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0
            || (mode & 0o020 != 0 && !(allow_effective_owner_group_write && owner == effective_uid))
        {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn manager_path_has_trusted_ownership(manager: &Path) -> bool {
    super::windows_trust::path_is_trusted_system_install(manager)
}

#[cfg(not(any(unix, windows)))]
fn manager_path_has_trusted_ownership(_manager: &Path) -> bool {
    false
}

struct CapturedStream {
    bytes: Vec<u8>,
    overflowed: bool,
    read_error: Option<String>,
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

struct OutputReaders {
    stdout: JoinHandle<CapturedStream>,
    stderr: JoinHandle<CapturedStream>,
    process_finished: Arc<AtomicBool>,
    limit_exceeded: Arc<AtomicBool>,
}

impl OutputReaders {
    fn finish_and_join(self) -> Result<(CapturedStream, CapturedStream), LpmError> {
        self.process_finished.store(true, Ordering::Release);
        let stdout = self.stdout.join();
        let stderr = self.stderr.join();
        match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => Ok((stdout, stderr)),
            (Err(_), Ok(_)) => Err(LpmError::SelfUpdate(
                "LPM version stdout reader panicked".to_string(),
            )),
            (Ok(_), Err(_)) => Err(LpmError::SelfUpdate(
                "LPM version stderr reader panicked".to_string(),
            )),
            (Err(_), Err(_)) => Err(LpmError::SelfUpdate(
                "LPM version output readers panicked".to_string(),
            )),
        }
    }
}

fn run_bounded(
    command: &mut Command,
    timeout: Duration,
    description: &str,
) -> Result<BoundedOutput, LpmError> {
    let mut child = lpm_sandbox::spawn_tracked_command(command).map_err(|error| {
        LpmError::SelfUpdate(format!("failed to start the {description}: {error}"))
    })?;
    let Some(stdout) = child.stdout.take() else {
        terminate_started_child(&mut child);
        return Err(LpmError::SelfUpdate(
            "LPM version probe stdout was not piped".to_string(),
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_started_child(&mut child);
        return Err(LpmError::SelfUpdate(
            "LPM version probe stderr was not piped".to_string(),
        ));
    };
    let readers = spawn_output_readers(&mut child, stdout, stderr)?;
    let status = crate::commands::rebuild::process_tree::wait_with_timeout_or_cancel(
        child,
        &timeout,
        &readers.limit_exceeded,
        &format!("{description} output exceeded {VERSION_OUTPUT_LIMIT} bytes"),
    );
    let (stdout, stderr) = readers.finish_and_join()?;
    let status = status.map_err(|error| LpmError::SelfUpdate(format!("{description} {error}")))?;
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn terminate_started_child(child: &mut std::process::Child) {
    crate::commands::rebuild::process_tree::kill_process_tree(child);
    let _ = child.wait();
}

fn spawn_output_readers(
    child: &mut std::process::Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
) -> Result<OutputReaders, LpmError> {
    let process_finished = Arc::new(AtomicBool::new(false));
    let limit_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_finished = Arc::clone(&process_finished);
    let stderr_finished = Arc::clone(&process_finished);
    let stdout_limit_exceeded = Arc::clone(&limit_exceeded);
    let stderr_limit_exceeded = Arc::clone(&limit_exceeded);
    let stdout = std::thread::Builder::new()
        .name("lpm-version-stdout".to_string())
        .spawn(move || read_bounded_stream(stdout, &stdout_finished, &stdout_limit_exceeded))
        .map_err(|error| {
            terminate_started_child(child);
            LpmError::SelfUpdate(format!(
                "failed to start LPM version stdout reader: {error}"
            ))
        })?;
    let stderr = match std::thread::Builder::new()
        .name("lpm-version-stderr".to_string())
        .spawn(move || read_bounded_stream(stderr, &stderr_finished, &stderr_limit_exceeded))
    {
        Ok(stderr) => stderr,
        Err(error) => {
            terminate_started_child(child);
            process_finished.store(true, Ordering::Release);
            let _ = stdout.join();
            return Err(LpmError::SelfUpdate(format!(
                "failed to start LPM version stderr reader: {error}"
            )));
        }
    };
    Ok(OutputReaders {
        stdout,
        stderr,
        process_finished,
        limit_exceeded,
    })
}

fn retain_chunk(captured: &mut CapturedStream, chunk: &[u8]) {
    let remaining = VERSION_OUTPUT_LIMIT.saturating_sub(captured.bytes.len());
    let retained = remaining.min(chunk.len());
    captured.bytes.extend_from_slice(&chunk[..retained]);
    captured.overflowed |= retained < chunk.len();
}

fn read_next_chunk<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    captured: &mut CapturedStream,
) -> bool {
    loop {
        match reader.read(buffer) {
            Ok(0) => return false,
            Ok(read) => {
                retain_chunk(captured, &buffer[..read]);
                return true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                captured.read_error = Some(error.to_string());
                return false;
            }
        }
    }
}

#[cfg(unix)]
fn read_bounded_stream<R>(
    mut reader: R,
    process_finished: &AtomicBool,
    limit_exceeded: &AtomicBool,
) -> CapturedStream
where
    R: Read + std::os::fd::AsRawFd,
{
    let mut captured = CapturedStream {
        bytes: Vec::with_capacity(VERSION_OUTPUT_LIMIT),
        overflowed: false,
        read_error: None,
    };
    let mut buffer = [0_u8; 1024];
    loop {
        match wait_for_unix_output(reader.as_raw_fd(), process_finished) {
            Ok(true) => {
                if !read_next_chunk(&mut reader, &mut buffer, &mut captured) {
                    break;
                }
                if captured.overflowed {
                    limit_exceeded.store(true, Ordering::Release);
                    break;
                }
                if process_finished.load(Ordering::Acquire)
                    && captured.bytes.len() >= VERSION_OUTPUT_LIMIT
                {
                    break;
                }
            }
            Ok(false) => break,
            Err(error) => {
                captured.read_error = Some(error);
                break;
            }
        }
    }
    captured
}

#[cfg(unix)]
fn wait_for_unix_output(
    fd: std::os::fd::RawFd,
    process_finished: &AtomicBool,
) -> Result<bool, String> {
    if fd < 0 {
        return Err("version output reader has an invalid descriptor".to_string());
    }
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    loop {
        let timeout = if process_finished.load(Ordering::Acquire) {
            0
        } else {
            50
        };
        // SAFETY: `poll_fd` is initialized and `fd` remains owned by the
        // reader for the duration of this synchronous call.
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout) };
        if result > 0 {
            if poll_fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(format!(
                    "version output poll failed with events 0x{:x}",
                    poll_fd.revents
                ));
            }
            return Ok(poll_fd.revents & (libc::POLLIN | libc::POLLHUP) != 0);
        }
        if result == 0 {
            if process_finished.load(Ordering::Acquire) {
                return Ok(false);
            }
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.to_string());
        }
    }
}

#[cfg(windows)]
fn read_bounded_stream<R>(
    mut reader: R,
    process_finished: &AtomicBool,
    limit_exceeded: &AtomicBool,
) -> CapturedStream
where
    R: Read + std::os::windows::io::AsRawHandle,
{
    let mut captured = CapturedStream {
        bytes: Vec::with_capacity(VERSION_OUTPUT_LIMIT),
        overflowed: false,
        read_error: None,
    };
    let mut buffer = [0_u8; 1024];
    loop {
        match wait_for_windows_output(reader.as_raw_handle(), process_finished) {
            Ok(true) => {
                if !read_next_chunk(&mut reader, &mut buffer, &mut captured) {
                    break;
                }
                if captured.overflowed {
                    limit_exceeded.store(true, Ordering::Release);
                    break;
                }
                if process_finished.load(Ordering::Acquire)
                    && captured.bytes.len() >= VERSION_OUTPUT_LIMIT
                {
                    break;
                }
            }
            Ok(false) => break,
            Err(error) => {
                captured.read_error = Some(error);
                break;
            }
        }
    }
    captured
}

#[cfg(windows)]
fn wait_for_windows_output(
    handle: std::os::windows::io::RawHandle,
    process_finished: &AtomicBool,
) -> Result<bool, String> {
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, GetLastError,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    loop {
        let mut available = 0_u32;
        // SAFETY: `handle` belongs to this reader and remains valid for the
        // call. Null buffers request only the available-byte count.
        let result = unsafe {
            PeekNamedPipe(
                handle as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            // SAFETY: `PeekNamedPipe` just failed on this thread.
            let error = unsafe { GetLastError() };
            if matches!(
                error,
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            ) {
                return Ok(false);
            }
            return Err(std::io::Error::from_raw_os_error(error as i32).to_string());
        }
        if available > 0 {
            return Ok(true);
        }
        if process_finished.load(Ordering::Acquire) {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(any(unix, windows)))]
fn read_bounded_stream<R>(
    mut reader: R,
    _process_finished: &AtomicBool,
    limit_exceeded: &AtomicBool,
) -> CapturedStream
where
    R: Read,
{
    let mut captured = CapturedStream {
        bytes: Vec::with_capacity(VERSION_OUTPUT_LIMIT),
        overflowed: false,
        read_error: None,
    };
    let mut buffer = [0_u8; 1024];
    loop {
        if !read_next_chunk(&mut reader, &mut buffer, &mut captured) {
            break;
        }
        if captured.overflowed {
            limit_exceeded.store(true, Ordering::Release);
            break;
        }
    }
    captured
}

fn remove_one_line_ending(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InterruptedThenData {
        interrupted: bool,
        data: std::io::Cursor<Vec<u8>>,
    }

    impl Read for InterruptedThenData {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.data.read(buffer)
        }
    }

    struct DataThenError {
        data_returned: bool,
    }

    impl Read for DataThenError {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.data_returned {
                self.data_returned = true;
                let data = b"lpm 1.2.3\n";
                buffer[..data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
            Err(std::io::Error::other("fixture read failure"))
        }
    }

    #[cfg(unix)]
    struct InvalidUnixReader;

    #[cfg(unix)]
    impl Read for InvalidUnixReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    #[cfg(unix)]
    impl std::os::fd::AsRawFd for InvalidUnixReader {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            -1
        }
    }

    #[cfg(windows)]
    struct InvalidWindowsReader;

    #[cfg(windows)]
    impl Read for InvalidWindowsReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    #[cfg(windows)]
    impl std::os::windows::io::AsRawHandle for InvalidWindowsReader {
        fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as _
        }
    }

    fn empty_capture() -> CapturedStream {
        CapturedStream {
            bytes: Vec::new(),
            overflowed: false,
            read_error: None,
        }
    }

    #[test]
    fn bounded_reader_retries_interrupted_reads() {
        let mut reader = InterruptedThenData {
            interrupted: false,
            data: std::io::Cursor::new(b"lpm 1.2.3\n".to_vec()),
        };
        let mut buffer = [0_u8; 32];
        let mut captured = empty_capture();

        assert!(read_next_chunk(&mut reader, &mut buffer, &mut captured));
        assert_eq!(captured.bytes, b"lpm 1.2.3\n");
    }

    #[test]
    fn bounded_reader_records_hard_errors_after_valid_bytes() {
        let mut reader = DataThenError {
            data_returned: false,
        };
        let mut buffer = [0_u8; 32];
        let mut captured = empty_capture();
        assert!(read_next_chunk(&mut reader, &mut buffer, &mut captured));

        assert!(!read_next_chunk(&mut reader, &mut buffer, &mut captured));
        assert_eq!(captured.read_error.as_deref(), Some("fixture read failure"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_records_poll_errors() {
        let finished = AtomicBool::new(false);
        let limit_exceeded = AtomicBool::new(false);

        let captured = read_bounded_stream(InvalidUnixReader, &finished, &limit_exceeded);

        assert!(captured.read_error.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn bounded_reader_records_pipe_readiness_errors() {
        let finished = AtomicBool::new(false);
        let limit_exceeded = AtomicBool::new(false);

        let captured = read_bounded_stream(InvalidWindowsReader, &finished, &limit_exceeded);

        assert!(captured.read_error.is_some());
    }

    #[test]
    fn resolve_program_on_path_ignores_relative_and_project_local_entries() {
        let project = tempfile::tempdir().unwrap();
        let local_bin = project.path().join("tools").join("bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        let executable = local_bin.join("lpm");
        std::fs::write(&executable, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::env::join_paths([Path::new("relative"), local_bin.as_path()]).unwrap();

        assert!(resolve_program_on_path("lpm", &path, Some(project.path())).is_none());
    }

    #[test]
    fn path_resolution_does_not_treat_home_as_a_project_without_a_manifest() {
        let home = tempfile::tempdir().unwrap();
        let global_bin = home.path().join(".local").join("bin");
        std::fs::create_dir_all(&global_bin).unwrap();
        let executable = global_bin.join("lpm");
        std::fs::write(&executable, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        assert!(!is_project_local_program(&executable, None));
    }

    #[test]
    fn positive_containment_rejects_parent_directory_components() {
        assert!(!path_is_known_within(
            Path::new("/opt/homebrew/Cellar/lpm/1.0/bin/lpm"),
            Path::new("/opt/homebrew/Cellar/../unrelated")
        ));
    }

    #[test]
    fn unrecognized_working_directory_does_not_remove_a_global_manager_from_path() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let _environment = crate::test_env::ScopedEnv::set([(
            "PATH",
            std::env::join_paths([bin.as_path()]).unwrap(),
        )]);
        let sanitized_path = sanitized_current_path(None).unwrap();

        let environment = ChildEnvironment::from_current(
            &sanitized_path,
            Some(directory.path()),
            directory.path(),
            &bin.join("lpm"),
            &bin.join("npm"),
        );

        assert_eq!(
            std::env::split_paths(&environment.path).collect::<Vec<_>>(),
            vec![bin]
        );
    }

    #[test]
    #[ignore = "manual release-mode manager binding memory and latency probe"]
    fn manager_binding_probe_reports_latency_for_existing_path_entries() {
        let entry_count = std::env::var("LPM_MANAGER_BINDING_BENCH_ENTRIES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(200)
            .max(1);
        let manager_position = std::env::var("LPM_MANAGER_BINDING_BENCH_POSITION")
            .unwrap_or_else(|_| "last".to_string());
        let mode =
            std::env::var("LPM_MANAGER_BINDING_BENCH_MODE").unwrap_or_else(|_| "bind".to_string());
        let working_dir = std::env::current_dir().unwrap();
        let base = tempfile::tempdir_in(&working_dir).unwrap();
        let excluded_root = base.path().join("excluded-project");
        let excluded_bin = excluded_root.join("bin");
        std::fs::create_dir_all(&excluded_bin).unwrap();
        let mut entries = Vec::with_capacity(entry_count + 1);
        for index in 0..entry_count {
            let entry = base.path().join(format!("manager-path-{index}"));
            std::fs::create_dir(&entry).unwrap();
            entries.push(entry);
        }
        let manager_index = match manager_position.as_str() {
            "first" => 0,
            "last" => entry_count.saturating_sub(1),
            other => panic!("unknown LPM_MANAGER_BINDING_BENCH_POSITION `{other}`"),
        };
        let manager = entries[manager_index].join(if cfg!(windows) { "npm.cmd" } else { "npm" });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::write(&manager, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(windows)]
        std::fs::write(&manager, b"@exit /b 0\r\n").unwrap();
        #[cfg(not(any(unix, windows)))]
        std::fs::write(&manager, b"").unwrap();
        entries.push(excluded_bin);
        let joined = std::env::join_paths(&entries).unwrap();
        let _environment = crate::test_env::ScopedEnv::set([("PATH", joined)]);
        let account_home = super::super::canonical_account_home().unwrap();
        let current_executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let args = [OsString::from("install"), OsString::from("lpm@1.2.3")];

        let started = std::time::Instant::now();
        let bound = match mode.as_str() {
            "fixture" => None,
            "sanitize" => {
                let sanitized = sanitized_current_path(Some(&excluded_root)).unwrap();
                assert_eq!(std::env::split_paths(&sanitized).count(), entry_count);
                None
            }
            "bind" => {
                let sanitized = sanitized_current_path(Some(&excluded_root)).unwrap();
                let bound = BoundUpdateCommand::bind(
                    "npm",
                    &args,
                    &sanitized,
                    None,
                    Some(&excluded_root),
                    &account_home,
                    &current_executable,
                )
                .unwrap();
                assert_eq!(bound.program.path, std::fs::canonicalize(&manager).unwrap());
                Some(bound)
            }
            other => panic!("unknown LPM_MANAGER_BINDING_BENCH_MODE `{other}`"),
        };

        eprintln!(
            "manager_binding mode={mode} position={manager_position} entries={entry_count} elapsed_us={}",
            started.elapsed().as_micros()
        );
        std::hint::black_box(entries);
        std::hint::black_box(bound);
    }

    #[test]
    fn manager_environment_recognizes_platform_temp_variables() {
        for key in ["TEMP", "TMP", "TMPDIR"] {
            assert!(child_environment_key_allowed(OsStr::new(key)), "key {key}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn probe_environment_pins_comspec_to_the_system_directory() {
        let variables = probe_os_variables();
        let comspec = variables
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(OsStr::new("COMSPEC")))
            .map(|(_, value)| PathBuf::from(value))
            .unwrap();

        assert!(comspec.is_absolute());
        assert!(
            comspec
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(OsStr::new("cmd.exe")))
        );
        for key in ["SYSTEMROOT", "WINDIR", "PATHEXT"] {
            assert!(
                variables
                    .iter()
                    .any(|(actual, _)| actual.eq_ignore_ascii_case(OsStr::new(key))),
                "missing {key}"
            );
        }
    }

    #[test]
    fn manager_environment_accepts_only_absolute_temp_paths_outside_the_project() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        assert!(child_environment_entry_allowed(
            OsStr::new("TMPDIR"),
            outside.path().as_os_str(),
            Some(project.path()),
            outside.path(),
            &outside.path().join("lpm"),
            &outside.path().join("npm")
        ));
        assert!(!child_environment_entry_allowed(
            OsStr::new("TMPDIR"),
            OsStr::new("relative-temp"),
            Some(project.path()),
            outside.path(),
            &outside.path().join("lpm"),
            &outside.path().join("npm")
        ));
        assert!(!child_environment_entry_allowed(
            OsStr::new("TMPDIR"),
            project.path().as_os_str(),
            Some(project.path()),
            outside.path(),
            &outside.path().join("lpm"),
            &outside.path().join("npm")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn manager_environment_rejects_a_nonexistent_temp_below_a_project_symlink() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let alias = outside.path().join("project-alias");
        symlink(project.path(), &alias).unwrap();
        let temp = alias.join("not-created-yet");

        assert!(!child_environment_entry_allowed(
            OsStr::new("TMPDIR"),
            temp.as_os_str(),
            Some(project.path()),
            outside.path(),
            &outside.path().join("lpm"),
            &outside.path().join("npm")
        ));
    }

    #[test]
    fn manager_environment_rejects_project_local_home_and_cargo_configuration() {
        let project = tempfile::tempdir().unwrap();
        let account = tempfile::tempdir().unwrap();

        for key in ["HOME", "CARGO_HOME", "RUSTUP_HOME", "XDG_CONFIG_HOME"] {
            assert!(
                !child_environment_entry_allowed(
                    OsStr::new(key),
                    project.path().as_os_str(),
                    Some(project.path()),
                    account.path(),
                    &account.path().join("lpm"),
                    &account.path().join("npm")
                ),
                "key {key}"
            );
        }
    }

    #[test]
    fn manager_environment_rejects_project_local_ca_files() {
        let project = tempfile::tempdir().unwrap();
        let account = tempfile::tempdir().unwrap();
        let certificate = project.path().join("ca.pem");
        std::fs::write(&certificate, b"not-a-real-certificate").unwrap();

        for key in ["SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"] {
            assert!(
                !child_environment_entry_allowed(
                    OsStr::new(key),
                    certificate.as_os_str(),
                    Some(project.path()),
                    account.path(),
                    &account.path().join("lpm"),
                    &account.path().join("npm")
                ),
                "key {key}"
            );
        }
    }

    #[test]
    fn manager_environment_rejects_external_home_cargo_and_ca_configuration() {
        let project = tempfile::tempdir().unwrap();
        let account = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();

        for key in ["HOME", "CARGO_HOME", "RUSTUP_HOME", "NODE_EXTRA_CA_CERTS"] {
            assert!(
                !child_environment_entry_allowed(
                    OsStr::new(key),
                    external.path().as_os_str(),
                    Some(project.path()),
                    account.path(),
                    &account.path().join("lpm"),
                    &account.path().join("npm")
                ),
                "key {key}"
            );
        }
    }

    #[test]
    fn manager_environment_rejects_unrelated_account_cargo_and_ca_configuration() {
        let project = tempfile::tempdir().unwrap();
        let account = tempfile::tempdir().unwrap();
        let manager = account.path().join("bin").join("npm");

        for (key, value) in [
            ("CARGO_HOME", account.path().join("evil-cargo")),
            ("RUSTUP_HOME", account.path().join("evil-rustup")),
            ("SSL_CERT_FILE", account.path().join("evil-ca.pem")),
            ("SSL_CERT_DIR", account.path().join("evil-ca")),
            (
                "NODE_EXTRA_CA_CERTS",
                account.path().join("evil-node-ca.pem"),
            ),
        ] {
            assert!(
                !child_environment_entry_allowed(
                    OsStr::new(key),
                    value.as_os_str(),
                    Some(project.path()),
                    account.path(),
                    &account.path().join("lpm"),
                    &manager,
                ),
                "key {key}"
            );
        }
    }

    #[test]
    fn manager_binding_rejects_an_external_temporary_executable() {
        let account = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let manager = external.path().join("npm");
        std::fs::write(&manager, b"").unwrap();

        assert!(!manager_program_location_allowed(
            &manager,
            account.path(),
            account.path()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn manager_binding_rejects_an_account_manager_in_a_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let account = tempfile::tempdir().unwrap();
        let shared = account.path().join("shared-bin");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let manager = shared.join("npm");
        std::fs::write(&manager, b"").unwrap();

        assert!(!manager_program_location_allowed(
            &manager,
            account.path(),
            account.path()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_external_manager_rejects_a_group_writable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let shared = root.path().join("shared-bin");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).unwrap();
        let manager = shared.join("npm");
        std::fs::write(&manager, b"").unwrap();

        assert!(!manager_path_has_trusted_ownership(&manager));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_homebrew_chain_accepts_effective_owner_group_writable_components() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        let manager = bin.join("brew");
        std::fs::write(&manager, b"").unwrap();

        assert!(trusted_path_chain_has_expected_ownership(
            &manager, false, true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_external_manager_accepts_a_leaf_symlink_to_a_trusted_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root_path = std::fs::canonicalize(root.path()).unwrap();
        let target = root_path.join("manager-target");
        std::fs::write(&target, b"").unwrap();
        let launcher = root_path.join("manager");
        symlink(&target, &launcher).unwrap();

        assert!(manager_path_has_trusted_ownership(&launcher));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_external_launcher_accepts_a_private_account_target() {
        use std::os::unix::fs::symlink;

        let account = tempfile::tempdir().unwrap();
        let account_home = std::fs::canonicalize(account.path()).unwrap();
        let target = account_home.join("lpm-target");
        std::fs::write(&target, b"").unwrap();
        let prefix = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let prefix = std::fs::canonicalize(prefix.path()).unwrap();
        let launcher = prefix.join("lpm");
        symlink(&target, &launcher).unwrap();

        assert!(manager_program_location_allowed(
            &launcher,
            target.parent().unwrap(),
            &account_home,
        ));
    }

    #[test]
    fn cargo_ownership_accepts_a_verified_custom_install_root() {
        let account = tempfile::tempdir().unwrap();
        let account_home = std::fs::canonicalize(account.path()).unwrap();
        let cargo_bin = account_home.join("cargo-home").join("bin");
        std::fs::create_dir_all(&cargo_bin).unwrap();
        let cargo = cargo_bin.join(if cfg!(windows) { "cargo.exe" } else { "cargo" });
        std::fs::write(&cargo, b"").unwrap();

        let install_root = account_home.join("custom-install-root");
        let install_bin = install_root.join("bin");
        std::fs::create_dir_all(&install_bin).unwrap();
        let lpm = install_bin.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&lpm, b"").unwrap();
        std::fs::write(
            install_root.join(".crates2.json"),
            format!(
                r#"{{"installs":{{"lpm-cli 0.74.1 (registry+https://github.com/rust-lang/crates.io-index)":{{"bins":["{}"]}}}}}}"#,
                lpm.file_stem().unwrap().to_string_lossy()
            ),
        )
        .unwrap();

        let manager_environment =
            ChildEnvironment::from_current(OsStr::new(""), None, &account_home, &lpm, &cargo);
        let program_identity = same_file::Handle::from_path(&cargo).unwrap();
        let command = BoundUpdateCommand {
            program: ResolvedProgram {
                path: cargo,
                kind: ProgramKind::Native,
            },
            program_identity,
            args: Vec::new(),
            logical_name: "cargo",
            environment: manager_environment,
            account_home,
        };
        let probe = VersionProbe {
            program: ResolvedProgram {
                path: lpm.clone(),
                kind: ProgramKind::Native,
            },
            launcher_dir: install_bin.clone(),
            launcher_binding: None,
            environment: ProbeEnvironment::for_staged_binary(),
            working_dir: install_bin,
            expected_executable: lpm,
            timeout: VERSION_PROBE_TIMEOUT,
        };

        command
            .ensure_owns_launcher(&probe, &super::super::InstallMethod::Cargo)
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn manager_ownership_query_accepts_a_bounded_stderr_warning() {
        let (directory, program) =
            executable_script("printf '%s\\n' \"$PWD\"; printf 'configuration warning\\n' >&2");
        let account_home = std::fs::canonicalize(directory.path()).unwrap();
        let environment = ChildEnvironment::from_current(
            OsStr::new(""),
            None,
            &account_home,
            &program.path,
            &program.path,
        );
        let command = BoundUpdateCommand {
            program_identity: same_file::Handle::from_path(&program.path).unwrap(),
            program,
            args: Vec::new(),
            logical_name: "npm",
            environment,
            account_home: account_home.clone(),
        };

        assert_eq!(
            command
                .query_absolute_path(&["prefix", "--global"])
                .unwrap(),
            account_home
        );
    }

    #[cfg(unix)]
    #[test]
    fn bound_manager_refuses_to_run_after_its_path_is_replaced() {
        use std::os::unix::fs::PermissionsExt;

        let account = tempfile::tempdir().unwrap();
        let account_home = std::fs::canonicalize(account.path()).unwrap();
        let bin = account_home.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let manager = bin.join("npm");
        std::fs::write(&manager, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();
        let current_executable = bin.join("lpm");
        std::fs::write(&current_executable, b"").unwrap();
        let command = BoundUpdateCommand::bind(
            "npm",
            &[],
            bin.as_os_str(),
            None,
            None,
            &account_home,
            &current_executable,
        )
        .unwrap();
        let displaced = bin.join("npm-original");
        std::fs::rename(&manager, displaced).unwrap();
        let marker = account_home.join("replacement-ran");
        std::fs::write(
            &manager,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = command
            .run()
            .expect_err("a bound package-manager path must retain its file identity");

        assert!(error.to_string().contains("changed after it was bound"));
        assert!(!marker.exists(), "the replacement manager must not run");
    }

    #[cfg(unix)]
    #[test]
    fn path_resolution_rejects_an_outside_symlink_to_a_project_program() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let project = tempfile::tempdir().unwrap();
        let project_program = project.path().join("tools").join("lpm");
        std::fs::create_dir_all(project_program.parent().unwrap()).unwrap();
        std::fs::write(&project_program, b"").unwrap();
        std::fs::set_permissions(&project_program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(&project_program, outside.path().join("lpm")).unwrap();

        assert!(
            resolve_program_on_path("lpm", outside.path().as_os_str(), Some(project.path()))
                .is_none()
        );
    }

    #[test]
    fn remove_one_line_ending_preserves_every_other_byte() {
        assert_eq!(remove_one_line_ending(b"lpm 1.2.3\n"), b"lpm 1.2.3");
        assert_eq!(remove_one_line_ending(b"lpm 1.2.3\r\n"), b"lpm 1.2.3");
        assert_eq!(remove_one_line_ending(b"lpm 1.2.3\n\n"), b"lpm 1.2.3\n");
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_resolution_supports_exe_and_cmd_launchers() {
        let directory = Path::new(r"C:\tools");
        assert_eq!(
            windows_candidates(directory, "lpm", OsStr::new(".EXE;.CMD")),
            vec![
                (directory.join("lpm.EXE"), ProgramKind::Native),
                (directory.join("lpm.CMD"), ProgramKind::CmdScript),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_cmd_probe_runs_from_a_parenthesized_unicode_path() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("Program Files (x86) Ω");
        std::fs::create_dir(&bin).unwrap();
        let path = bin.join("lpm.cmd");
        std::fs::write(
            &path,
            "@echo off\r\nif not \"%~1\"==\"-V\" exit /b 9\r\necho lpm 1.2.3\r\n",
        )
        .unwrap();
        let program = ResolvedProgram {
            path: path.clone(),
            kind: ProgramKind::CmdScript,
        };
        let probe = VersionProbe {
            expected_executable: path,
            program,
            launcher_dir: bin.clone(),
            launcher_binding: None,
            environment: ProbeEnvironment::for_launcher(bin.as_os_str()),
            working_dir: bin,
            timeout: VERSION_PROBE_TIMEOUT,
        };

        probe.verify_requested("1.2.3").unwrap();
    }

    #[cfg(unix)]
    fn executable_script(body: &str) -> (tempfile::TempDir, ResolvedProgram) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("probe");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            directory,
            ResolvedProgram {
                path,
                kind: ProgramKind::Native,
            },
        )
    }

    #[cfg(unix)]
    fn version_probe(program: ResolvedProgram) -> VersionProbe {
        let working_dir = program.path.parent().unwrap().to_path_buf();
        VersionProbe {
            expected_executable: program.path.clone(),
            launcher_dir: working_dir.clone(),
            program,
            launcher_binding: None,
            environment: ProbeEnvironment::for_staged_binary(),
            working_dir,
            timeout: VERSION_PROBE_TIMEOUT,
        }
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_accepts_only_the_exact_requested_version() {
        let (_directory, program) = executable_script("printf 'lpm 1.2.3\\n'");
        version_probe(program).verify_requested("1.2.3").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_version_probe_does_not_require_or_forward_path() {
        let environment = ProbeEnvironment::for_staged_binary();

        assert!(environment.path.is_none());
        assert!(
            environment
                .variables
                .iter()
                .all(|(key, _)| !key.eq_ignore_ascii_case(OsStr::new("PATH")))
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_preserves_the_original_working_directory() {
        let expected = tempfile::tempdir().unwrap();
        let canonical_expected = std::fs::canonicalize(expected.path()).unwrap();
        let body = format!(
            "if [ \"$PWD\" != '{}' ]; then exit 9; fi; printf 'lpm 1.2.3\\n'",
            canonical_expected.display()
        );
        let (_directory, program) = executable_script(&body);
        let mut probe = version_probe(program);
        probe.working_dir = expected.path().to_path_buf();

        probe.verify_requested("1.2.3").unwrap();
    }

    #[cfg(unix)]
    fn missing_pipe_child_reaches_marker(stderr_piped: bool) -> bool {
        let state = tempfile::tempdir().unwrap();
        let pid_file = state.path().join("pid");
        let marker = state.path().join("marker");
        let body = format!(
            "printf '%s' $$ > '{}'; /bin/sleep 0.2; : > '{}'; /bin/sleep 30",
            pid_file.display(),
            marker.display()
        );
        let (_directory, program) = executable_script(&body);
        let mut command = program.command(&[]);
        command.stdin(Stdio::null());
        if stderr_piped {
            command.stderr(Stdio::piped());
        } else {
            command.stdout(Stdio::piped());
        }

        let _ = run_bounded(&mut command, Duration::from_secs(2), "missing-pipe test");
        std::thread::sleep(Duration::from_millis(400));
        let reached_marker = marker.exists();
        if reached_marker
            && let Ok(pid) = std::fs::read_to_string(pid_file)
            && let Ok(pid) = pid.parse::<i32>()
        {
            // SAFETY: the PID was written by the dedicated test child.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        reached_marker
    }

    #[cfg(unix)]
    #[test]
    fn missing_stdout_pipe_kills_the_started_probe() {
        assert!(!missing_pipe_child_reaches_marker(true));
    }

    #[cfg(unix)]
    #[test]
    fn missing_stderr_pipe_kills_the_started_probe() {
        assert!(!missing_pipe_child_reaches_marker(false));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_a_stale_version() {
        let (_directory, program) = executable_script("printf 'lpm 1.2.2\\n'");
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(error.to_string().contains("exact version 1.2.3"));
    }

    #[cfg(unix)]
    #[test]
    fn staged_release_probe_rejects_a_binary_with_the_wrong_embedded_version() {
        use sha2::Digest as _;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("lpm");
        std::fs::write(&current, b"").unwrap();
        let mut temporary = super::super::download::create_staged_binary(&current).unwrap();
        let body = b"#!/bin/sh\nprintf 'lpm 1.2.2\\n'\n";
        temporary.as_file_mut().write_all(body).unwrap();
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(body));
        let temporary = super::super::download::finish_staged_binary(temporary).unwrap();

        let error = VersionProbe::verify_staged(&temporary, &sha256, "1.2.3").unwrap_err();
        assert!(
            error.to_string().contains("exact version 1.2.3"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_a_nonzero_exit() {
        let (_directory, program) = executable_script("exit 7");
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(error.to_string().contains("exited with code 7"));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_stderr_even_with_exact_stdout() {
        let (_directory, program) =
            executable_script("printf 'lpm 1.2.3\\n'; printf 'warning\\n' >&2");
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(error.to_string().contains("unexpected stderr"));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_malformed_stdout() {
        let (_directory, program) = executable_script("printf '1.2.3\\n'");
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(error.to_string().contains("exact version 1.2.3"));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_multiple_stdout_lines() {
        let (_directory, program) = executable_script("printf 'lpm 1.2.3\\nextra\\n'");
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(error.to_string().contains("exact version 1.2.3"));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_output_larger_than_the_protocol_limit() {
        let body = format!("printf '{}\\n'", "x".repeat(VERSION_OUTPUT_LIMIT + 1));
        let (_directory, program) = executable_script(&body);
        let error = version_probe(program)
            .verify_requested("1.2.3")
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeded 4096 bytes"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_terminates_immediately_when_output_exceeds_the_limit() {
        let (_directory, program) = executable_script("while :; do printf x; done");
        let mut probe = version_probe(program);
        probe.timeout = Duration::from_secs(2);
        let started = std::time::Instant::now();

        let error = probe.verify_requested("1.2.3").unwrap_err();

        assert!(
            error.to_string().contains("exceeded 4096 bytes"),
            "unexpected error: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_times_out_and_reaps_a_hung_process() {
        let (_directory, program) = executable_script("sleep 30");
        let mut probe = version_probe(program);
        probe.timeout = Duration::from_millis(100);
        let started = std::time::Instant::now();
        let error = probe.verify_requested("1.2.3").unwrap_err();
        assert!(error.to_string().contains("timeout after"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_does_not_wait_for_a_writer_left_by_an_exited_root() {
        let body = "(while :; do printf x; done) & writer=$!; (sleep 7; kill $writer) >/dev/null 2>&1 & printf 'lpm 1.2.3\\n'";
        let (_directory, program) = executable_script(body);
        let started = std::time::Instant::now();
        let _ = version_probe(program).verify_requested("1.2.3");
        assert!(started.elapsed() < Duration::from_secs(6));
    }

    #[cfg(unix)]
    #[test]
    fn detached_writer_helper() {
        use std::io::Write;

        let Some(pid_file) = std::env::var_os("LPM_TEST_DETACHED_WRITER_PID") else {
            return;
        };
        // SAFETY: this helper is a subprocess that has not created threads;
        // it detaches itself solely to exercise process-tree cleanup.
        assert_ne!(unsafe { libc::setsid() }, -1);
        std::fs::write(pid_file, std::process::id().to_string()).unwrap();
        let mut stdout = std::io::stdout().lock();
        let chunk = vec![b'x'; 1024 * 1024];
        while stdout.write_all(&chunk).is_ok() {}
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_does_not_wait_for_a_detached_writer_after_root_exit() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("detached-writer.pid");
        let test_binary = std::env::current_exe().unwrap();
        let body = format!(
            "LPM_TEST_DETACHED_WRITER_PID='{}' '{}' --exact 'commands::self_update::probe::tests::detached_writer_helper' --nocapture &\nwhile [ ! -s '{}' ]; do :; done\nprintf 'lpm 1.2.3\\n'",
            pid_file.display(),
            test_binary.display(),
            pid_file.display(),
        );
        let (_script_directory, program) = executable_script(&body);
        let kill_file = pid_file;
        let killer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let pid = loop {
                if let Ok(value) = std::fs::read_to_string(&kill_file)
                    && let Ok(pid) = value.parse::<i32>()
                {
                    break pid;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "helper did not publish its pid"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            std::thread::sleep(Duration::from_secs(3));
            // SAFETY: `pid` was written by the dedicated helper subprocess.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        });

        let started = std::time::Instant::now();
        let _ = version_probe(program).verify_requested("1.2.3");
        let elapsed = started.elapsed();
        killer.join().unwrap();

        assert!(elapsed < Duration::from_secs(2), "elapsed {elapsed:?}");
    }
}
