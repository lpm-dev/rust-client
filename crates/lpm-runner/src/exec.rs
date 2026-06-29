//! Direct file execution for `lpm exec src/seed.ts`.
//!
//! Execution is planned in explicit stages: resolve the target, classify the
//! file, resolve the effective runtime, choose a strategy, then spawn the
//! command directly without a shell.

use crate::bin_path::{self, ManagedRuntimeHint};
use crate::dotenv;
use crate::shell;
use lpm_common::LpmError;
use lpm_common::paths::LpmRoot;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::thread;

const SUPPORTED_FILE_TYPES: &str = ".js, .mjs, .cjs, .ts, .tsx, .mts, .cts";
const LPM_TS_RUNTIME_LOADER_VERSION: &str = "1";
const LPM_TS_RUNTIME_LOADER_SOURCE: &str = include_str!("lpm_ts_runtime_loader.cjs");
const LPM_TS_RUNTIME_NODE_OPTIONS_PREFIX: &str = "--disable-warning=ExperimentalWarning";

#[derive(Debug, Clone)]
pub struct ExecTargetDescription {
    pub runtime_label: String,
}

#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub env_mode: Option<String>,
    pub no_env_check: bool,
    pub managed_runtime_hint: ManagedRuntimeHint,
    pub plain_node: bool,
    pub runtime_cache_root: Option<PathBuf>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            env_mode: None,
            no_env_check: false,
            managed_runtime_hint: ManagedRuntimeHint::Unknown,
            plain_node: false,
            runtime_cache_root: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecFileKind {
    JavaScript,
    TypeScript,
    Tsx,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExecRuntime {
    Node {
        version: Option<String>,
    },
    LpmTsRuntime {
        node_version: Option<String>,
        loader: PathBuf,
    },
    LocalTsx {
        binary: PathBuf,
    },
}

impl ExecRuntime {
    fn display_label(&self) -> String {
        match self {
            Self::Node { version } => version.as_deref().map_or_else(
                || "Node.js".to_string(),
                |version| format!("Node.js {version}"),
            ),
            Self::LpmTsRuntime { node_version, .. } => node_version.as_deref().map_or_else(
                || "Node.js + LPM TS runtime".to_string(),
                |version| format!("Node.js {version} + LPM TS runtime"),
            ),
            Self::LocalTsx { .. } => "local tsx".to_string(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExecStrategy {
    Node,
    NodeStripTypes,
    LpmTsRuntime { loader: PathBuf, cache_dir: PathBuf },
    LocalTsx { binary: PathBuf },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChildPropagationMode {
    Disabled,
    LpmTsRuntime,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeLaunchConfig {
    pub program: PathBuf,
    pub node_flags: Vec<String>,
    pub entry_args: Vec<String>,
    pub path: String,
    pub env_overrides: Vec<(String, String)>,
    pub child_propagation: ChildPropagationMode,
}

impl NodeLaunchConfig {
    fn to_command_plan(&self) -> ExecCommandPlan {
        let mut args = Vec::with_capacity(self.node_flags.len() + self.entry_args.len());
        args.extend(self.node_flags.iter().cloned());
        args.extend(self.entry_args.iter().cloned());
        ExecCommandPlan {
            program: self.program.clone(),
            args,
            path: self.path.clone(),
            env_overrides: self.env_overrides.clone(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecCommandPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub path: String,
    pub env_overrides: Vec<(String, String)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecPlan {
    pub resolved_path: PathBuf,
    pub file_kind: ExecFileKind,
    pub runtime: ExecRuntime,
    pub strategy: ExecStrategy,
    pub command: ExecCommandPlan,
    pub node_launch: Option<NodeLaunchConfig>,
    pub env_mode: Option<String>,
    pub no_env_check: bool,
}

impl ExecPlan {
    pub fn runtime_label(&self) -> String {
        self.runtime.display_label()
    }
}

pub fn describe_exec_target(
    project_dir: &Path,
    file_path: &str,
) -> Result<ExecTargetDescription, LpmError> {
    describe_exec_target_with_options(project_dir, file_path, &ExecOptions::default())
}

pub fn describe_exec_target_with_options(
    project_dir: &Path,
    file_path: &str,
    options: &ExecOptions,
) -> Result<ExecTargetDescription, LpmError> {
    let plan = build_exec_plan(project_dir, file_path, &[], options)?;

    Ok(ExecTargetDescription {
        runtime_label: plan.runtime_label(),
    })
}

/// Build the execution plan for a direct file target.
pub fn build_exec_plan(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    options: &ExecOptions,
) -> Result<ExecPlan, LpmError> {
    let resolved_path = resolve_exec_path(project_dir, file_path)?;
    let file_kind = detect_file_kind(&resolved_path)?;
    let path =
        bin_path::build_path_with_bins_pre_resolved(project_dir, &options.managed_runtime_hint);
    let node_version = detect_effective_node_version_with_path(&path);
    let strategy = choose_exec_strategy(file_kind, project_dir, node_version.as_deref(), options)?;
    let runtime = runtime_for_strategy(&strategy, node_version);
    let (command, node_launch) =
        build_command_plan(project_dir, &strategy, file_path, extra_args, path);

    Ok(ExecPlan {
        resolved_path,
        file_kind,
        runtime,
        strategy,
        command,
        node_launch,
        env_mode: options.env_mode.clone(),
        no_env_check: options.no_env_check,
    })
}

/// Execute a file directly, auto-detecting the runtime.
///
/// Uses direct process spawning with no shell intermediary.
pub fn exec_file(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
) -> Result<(), LpmError> {
    exec_file_with_options(project_dir, file_path, extra_args, &ExecOptions::default())
}

pub fn exec_file_with_options(
    project_dir: &Path,
    file_path: &str,
    extra_args: &[String],
    options: &ExecOptions,
) -> Result<(), LpmError> {
    let plan = build_exec_plan(project_dir, file_path, extra_args, options)?;
    execute_exec_plan(project_dir, &plan)
}

pub fn execute_exec_plan(project_dir: &Path, plan: &ExecPlan) -> Result<(), LpmError> {
    let env_vars = dotenv::load_project_env_with_schema_validation(
        project_dir,
        plan.env_mode.as_deref(),
        !plan.no_env_check,
    )?;

    let mut command = Command::new(&plan.command.program);
    command
        .args(&plan.command.args)
        .current_dir(project_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    shell::strip_inherited_env_hooks(&mut command);
    if !env_vars.is_empty() {
        command.envs(&env_vars);
    }
    for (key, value) in &plan.command.env_overrides {
        command.env(key, value);
    }
    command.env("PATH", &plan.command.path);

    let mut child = command.spawn().map_err(|e| {
        LpmError::Script(format!(
            "failed to execute '{}': {e}",
            plan.command.program.display()
        ))
    })?;
    let status = wait_for_child(&mut child)?;

    if !status.success() {
        return Err(LpmError::ExitCode(exit_code_from_status(&status)));
    }

    Ok(())
}

#[cfg(unix)]
fn wait_for_child(child: &mut Child) -> Result<ExitStatus, LpmError> {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let pid = child.id() as libc::pid_t;
    let mut signals = Signals::new([SIGINT, SIGTERM])
        .map_err(|e| LpmError::Script(format!("failed to install exec signal handlers: {e}")))?;
    let handle = signals.handle();
    let forwarder = thread::spawn(move || {
        for signal in signals.forever() {
            // SAFETY: `pid` comes from a live child process spawned by this
            // function. `kill` is best-effort; wait below remains authoritative.
            unsafe {
                libc::kill(pid, signal);
            }
        }
    });

    let status = child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for exec child process: {e}")));
    handle.close();
    let _ = forwarder.join();
    status
}

#[cfg(not(unix))]
fn wait_for_child(child: &mut Child) -> Result<ExitStatus, LpmError> {
    child
        .wait()
        .map_err(|e| LpmError::Script(format!("failed to wait for exec child process: {e}")))
}

fn resolve_exec_path(project_dir: &Path, file_path: &str) -> Result<PathBuf, LpmError> {
    let file = Path::new(file_path);
    let resolved = if file.is_absolute() {
        file.to_path_buf()
    } else {
        let mut path =
            PathBuf::with_capacity(project_dir.as_os_str().len() + file.as_os_str().len() + 1);
        path.push(project_dir);
        path.push(file);
        path
    };

    if !resolved.exists() {
        return Err(LpmError::Script(format!(
            "file not found: {}",
            resolved.display()
        )));
    }

    Ok(resolved)
}

fn detect_file_kind(path: &Path) -> Result<ExecFileKind, LpmError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "js" | "mjs" | "cjs" => Ok(ExecFileKind::JavaScript),
        "ts" | "mts" | "cts" => Ok(ExecFileKind::TypeScript),
        "tsx" => Ok(ExecFileKind::Tsx),
        _ => {
            let file_type = if ext.is_empty() {
                "with no extension".to_string()
            } else {
                format!("'.{ext}'")
            };
            Err(LpmError::Script(format!(
                "unsupported file type {file_type} - supported: {SUPPORTED_FILE_TYPES}"
            )))
        }
    }
}

fn choose_exec_strategy(
    file_kind: ExecFileKind,
    project_dir: &Path,
    node_version: Option<&str>,
    options: &ExecOptions,
) -> Result<ExecStrategy, LpmError> {
    if !options.plain_node
        && let Some(strategy) =
            lpm_typescript_strategy(file_kind, project_dir, node_version, options)?
    {
        return Ok(strategy);
    }

    match file_kind {
        ExecFileKind::JavaScript => Ok(ExecStrategy::Node),
        ExecFileKind::TypeScript => {
            if let Some(version) = node_version
                && let Some(strategy) = node_typescript_strategy(version)
            {
                return Ok(strategy);
            }

            if let Some(binary) = find_local_tsx_binary(project_dir) {
                return Ok(ExecStrategy::LocalTsx { binary });
            }

            Err(no_safe_typescript_runtime_error(node_version))
        }
        ExecFileKind::Tsx => Err(no_safe_tsx_runtime_error(node_version, options.plain_node)),
    }
}

fn lpm_typescript_strategy(
    file_kind: ExecFileKind,
    project_dir: &Path,
    node_version: Option<&str>,
    options: &ExecOptions,
) -> Result<Option<ExecStrategy>, LpmError> {
    if file_kind == ExecFileKind::JavaScript {
        return Ok(None);
    }

    if !supports_lpm_ts_runtime(node_version) {
        return Ok(match file_kind {
            ExecFileKind::JavaScript | ExecFileKind::TypeScript => None,
            ExecFileKind::Tsx => {
                find_local_tsx_binary(project_dir).map(|binary| ExecStrategy::LocalTsx { binary })
            }
        });
    }

    let runtime_root = lpm_ts_runtime_root(options)?;
    let loader = ensure_lpm_ts_runtime_loader(&runtime_root)?;
    let cache_dir = runtime_root.join("transform-cache");

    Ok(Some(ExecStrategy::LpmTsRuntime { loader, cache_dir }))
}

fn supports_lpm_ts_runtime(node_version: Option<&str>) -> bool {
    let Some(version) = node_version else {
        return false;
    };
    let (major, minor) = parse_major_minor(version);
    major > 23 || (major == 23 && minor >= 6) || (major == 22 && minor >= 18)
}

fn node_typescript_strategy(version: &str) -> Option<ExecStrategy> {
    let (major, minor) = parse_major_minor(version);
    if major > 23 || (major == 23 && minor >= 6) || (major == 22 && minor >= 18) {
        return Some(ExecStrategy::Node);
    }
    if (major == 22 && minor >= 6) || major == 23 {
        return Some(ExecStrategy::NodeStripTypes);
    }
    None
}

fn lpm_ts_runtime_root(options: &ExecOptions) -> Result<PathBuf, LpmError> {
    if let Some(root) = &options.runtime_cache_root {
        return Ok(root.clone());
    }
    Ok(LpmRoot::from_env()?
        .cache_root()
        .join("exec-ts-runtime")
        .join(format!("v{LPM_TS_RUNTIME_LOADER_VERSION}")))
}

fn ensure_lpm_ts_runtime_loader(runtime_root: &Path) -> Result<PathBuf, LpmError> {
    let loader_path = runtime_root.join("lpm-ts-runtime-loader.cjs");
    fs::create_dir_all(runtime_root).map_err(|e| {
        LpmError::Script(format!(
            "failed to create LPM TS runtime cache at {}: {e}",
            runtime_root.display()
        ))
    })?;

    let desired_hash = sha256_hex(LPM_TS_RUNTIME_LOADER_SOURCE.as_bytes());
    let needs_write = match fs::read(&loader_path) {
        Ok(existing) => sha256_hex(&existing) != desired_hash,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            return Err(LpmError::Script(format!(
                "failed to read LPM TS runtime loader at {}: {e}",
                loader_path.display()
            )));
        }
    };

    if needs_write {
        let tmp_path =
            runtime_root.join(format!(".lpm-ts-runtime-loader.{}.tmp", std::process::id()));
        {
            let mut file = fs::File::create(&tmp_path).map_err(|e| {
                LpmError::Script(format!(
                    "failed to stage LPM TS runtime loader at {}: {e}",
                    tmp_path.display()
                ))
            })?;
            file.write_all(LPM_TS_RUNTIME_LOADER_SOURCE.as_bytes())
                .map_err(|e| {
                    LpmError::Script(format!(
                        "failed to write LPM TS runtime loader at {}: {e}",
                        tmp_path.display()
                    ))
                })?;
        }
        fs::rename(&tmp_path, &loader_path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            LpmError::Script(format!(
                "failed to install LPM TS runtime loader at {}: {e}",
                loader_path.display()
            ))
        })?;
    }

    Ok(loader_path)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn lpm_ts_runtime_node_options(loader: &Path) -> String {
    format!(
        "{LPM_TS_RUNTIME_NODE_OPTIONS_PREFIX} --require={}",
        quote_node_options_path(loader)
    )
}

fn quote_node_options_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

fn runtime_for_strategy(strategy: &ExecStrategy, node_version: Option<String>) -> ExecRuntime {
    match strategy {
        ExecStrategy::Node | ExecStrategy::NodeStripTypes => ExecRuntime::Node {
            version: node_version,
        },
        ExecStrategy::LpmTsRuntime { loader, .. } => ExecRuntime::LpmTsRuntime {
            node_version,
            loader: loader.clone(),
        },
        ExecStrategy::LocalTsx { binary } => ExecRuntime::LocalTsx {
            binary: binary.clone(),
        },
    }
}

fn build_command_plan(
    project_dir: &Path,
    strategy: &ExecStrategy,
    file_path: &str,
    extra_args: &[String],
    path: String,
) -> (ExecCommandPlan, Option<NodeLaunchConfig>) {
    match strategy {
        ExecStrategy::Node => {
            let node = build_node_launch_config(
                file_path,
                extra_args,
                path,
                Vec::new(),
                Vec::new(),
                ChildPropagationMode::Disabled,
            );
            (node.to_command_plan(), Some(node))
        }
        ExecStrategy::NodeStripTypes => {
            let node = build_node_launch_config(
                file_path,
                extra_args,
                path,
                vec!["--experimental-strip-types".to_string()],
                Vec::new(),
                ChildPropagationMode::Disabled,
            );
            (node.to_command_plan(), Some(node))
        }
        ExecStrategy::LpmTsRuntime { loader, cache_dir } => {
            let node_options = lpm_ts_runtime_node_options(loader);
            let node = build_node_launch_config(
                file_path,
                extra_args,
                path,
                Vec::new(),
                vec![
                    (
                        "LPM_TS_RUNTIME_PROJECT_DIR".to_string(),
                        project_dir.to_string_lossy().to_string(),
                    ),
                    (
                        "LPM_TS_RUNTIME_CACHE_DIR".to_string(),
                        cache_dir.to_string_lossy().to_string(),
                    ),
                    ("NODE_OPTIONS".to_string(), node_options),
                ],
                ChildPropagationMode::LpmTsRuntime,
            );
            (node.to_command_plan(), Some(node))
        }
        ExecStrategy::LocalTsx { binary } => {
            let mut args = Vec::with_capacity(extra_args.len() + 1);
            args.push(file_path.to_string());
            args.extend(extra_args.iter().cloned());

            (
                ExecCommandPlan {
                    program: binary.clone(),
                    args,
                    path,
                    env_overrides: Vec::new(),
                },
                None,
            )
        }
    }
}

fn build_node_launch_config(
    file_path: &str,
    extra_args: &[String],
    path: String,
    node_flags: Vec<String>,
    env_overrides: Vec<(String, String)>,
    child_propagation: ChildPropagationMode,
) -> NodeLaunchConfig {
    let mut entry_args = Vec::with_capacity(extra_args.len() + 1);
    entry_args.push(file_path.to_string());
    entry_args.extend(extra_args.iter().cloned());

    NodeLaunchConfig {
        program: PathBuf::from("node"),
        node_flags,
        entry_args,
        path,
        env_overrides,
        child_propagation,
    }
}

fn find_local_tsx_binary(project_dir: &Path) -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["tsx.cmd", "tsx.exe", "tsx"]
    } else {
        &["tsx"]
    };

    for bin_dir in bin_path::find_bin_dirs(project_dir) {
        for name in names {
            let candidate = bin_dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn no_safe_typescript_runtime_error(node_version: Option<&str>) -> LpmError {
    let runtime_detail = node_version.map_or_else(
        || "no compatible Node.js runtime was detected".to_string(),
        |version| format!("detected Node.js {version}, which cannot safely execute TypeScript"),
    );
    LpmError::Script(format!(
        "{runtime_detail}. LPM will not fall back to `npx tsx` because that can download and execute npm code outside LPM's install-policy/security model. Run `lpm use node@22.18+` to use the LPM-owned TS runtime, or install and pin a local `tsx` dev dependency with LPM, then retry."
    ))
}

fn no_safe_tsx_runtime_error(node_version: Option<&str>, plain_node: bool) -> LpmError {
    if plain_node {
        return LpmError::Script(
            "`--plain-node` disables the LPM TS runtime, and Node.js built-in TypeScript execution does not support .tsx files. Run without `--plain-node`, or install and invoke a project-pinned TSX runtime explicitly.".to_string(),
        );
    }

    let runtime_detail = node_version.map_or_else(
        || "no compatible Node.js runtime was detected for the LPM TS runtime".to_string(),
        |version| {
            format!(
                "detected Node.js {version}, which cannot load the LPM TS runtime required for .tsx files"
            )
        },
    );
    LpmError::Script(format!(
        "{runtime_detail}. LPM will not fall back to `npx tsx` because that can download and execute npm code outside LPM's install-policy/security model. Run `lpm use node@22.18+` or install and pin a local `tsx` dev dependency with LPM, then retry."
    ))
}

/// Detect the Node.js version that `lpm exec` will actually see on PATH.
#[cfg(test)]
fn detect_effective_node_version(project_dir: &Path) -> Option<String> {
    let path = bin_path::build_path_with_bins(project_dir);
    detect_effective_node_version_with_path(&path)
}

fn detect_effective_node_version_with_path(path: &str) -> Option<String> {
    let mut command = Command::new("node");
    command
        .arg("--version")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    shell::strip_inherited_env_hooks(&mut command);
    let output = command.output().ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8(output.stdout).ok()?;
    let trimmed = version.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse major.minor from a version string like "22.6.0" into (22, 6).
fn parse_major_minor(version: &str) -> (u32, u32) {
    let mut parts = version.trim_start_matches('v').split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

#[cfg(not(unix))]
fn exit_code_from_status(status: &ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(unix)]
fn exit_code_from_status(status: &ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path).expect("script must exist").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("failed to mark script executable");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    fn write_fake_node(project_dir: &Path, version: &str) {
        let bin_dir = project_dir.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();

        #[cfg(unix)]
        {
            let node_path = bin_dir.join("node");
            fs::write(&node_path, format!("#!/bin/sh\necho {version}\n")).unwrap();
            make_executable(&node_path);
        }

        #[cfg(windows)]
        {
            let node_path = bin_dir.join("node.cmd");
            fs::write(&node_path, format!("@echo off\r\necho {version}\r\n")).unwrap();
        }
    }

    fn write_local_tsx(project_dir: &Path) -> PathBuf {
        let bin_dir = project_dir.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let tsx_path = if cfg!(windows) {
            bin_dir.join("tsx.cmd")
        } else {
            bin_dir.join("tsx")
        };
        let script = if cfg!(windows) {
            "@echo off\r\necho tsx\r\n"
        } else {
            "#!/bin/sh\necho tsx\n"
        };
        fs::write(&tsx_path, script).unwrap();
        make_executable(&tsx_path);
        tsx_path
    }

    fn write_project_file(project_dir: &Path, file_name: &str) {
        fs::write(project_dir.join("package.json"), "{}").unwrap();
        fs::write(project_dir.join(file_name), "console.log('hello')").unwrap();
    }

    fn test_options(project_dir: &Path) -> ExecOptions {
        ExecOptions {
            runtime_cache_root: Some(project_dir.join(".lpm-test-exec-runtime")),
            ..ExecOptions::default()
        }
    }

    fn plain_node_options(project_dir: &Path) -> ExecOptions {
        ExecOptions {
            plain_node: true,
            runtime_cache_root: Some(project_dir.join(".lpm-test-exec-runtime")),
            ..ExecOptions::default()
        }
    }

    #[test]
    fn exec_file_runs_javascript_with_node() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.js");

        let options = test_options(dir.path());
        let result = exec_file_with_options(dir.path(), "hello.js", &[], &options);
        assert!(result.is_ok(), "JavaScript exec should run through node");
    }

    #[test]
    fn exec_file_forwards_extra_args_to_javascript() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(
            dir.path().join("args.js"),
            "process.exit(process.argv.includes('--port') ? 0 : 1)",
        )
        .unwrap();

        let options = test_options(dir.path());
        let result = exec_file_with_options(
            dir.path(),
            "args.js",
            &["--port".into(), "3000".into()],
            &options,
        );
        assert!(
            result.is_ok(),
            "extra args including --port should pass through"
        );
    }

    #[test]
    fn build_exec_plan_errors_when_target_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let options = test_options(dir.path());
        let err = build_exec_plan(dir.path(), "nonexistent.js", &[], &options).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn build_exec_plan_errors_when_extension_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("data.csv"), "a,b,c").unwrap();

        let options = test_options(dir.path());
        let err = build_exec_plan(dir.path(), "data.csv", &[], &options).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(".csv"),
            "error should mention the extension"
        );
        assert!(
            message.contains(".ts"),
            "error should list supported file types"
        );
    }

    #[test]
    fn build_exec_plan_uses_node_for_javascript_files() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.mjs");

        write_fake_node(dir.path(), "v20.5.0");
        let options = test_options(dir.path());
        let plan = build_exec_plan(dir.path(), "hello.mjs", &[], &options).unwrap();

        assert_eq!(plan.file_kind, ExecFileKind::JavaScript);
        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert_eq!(plan.command.program, PathBuf::from("node"));
    }

    #[test]
    fn build_exec_plan_keeps_javascript_on_node_when_lpm_runtime_is_available() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.js");
        write_fake_node(dir.path(), "v22.18.0");
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.js", &[], &options).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert!(plan.command.env_overrides.is_empty());
        assert!(matches!(
            plan.node_launch
                .as_ref()
                .expect("node launch config")
                .child_propagation,
            ChildPropagationMode::Disabled
        ));
    }

    #[test]
    fn build_exec_plan_uses_lpm_ts_runtime_for_typescript_when_available() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v23.6.0");
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert_eq!(plan.file_kind, ExecFileKind::TypeScript);
        assert!(matches!(plan.strategy, ExecStrategy::LpmTsRuntime { .. }));
        assert_eq!(plan.command.args, vec!["hello.ts"]);
        assert!(
            plan.command
                .env_overrides
                .iter()
                .any(|(key, value)| key == "NODE_OPTIONS"
                    && value.contains("lpm-ts-runtime-loader.cjs")),
            "LPM TS runtime must install its controlled NODE_OPTIONS"
        );
        assert!(matches!(
            plan.node_launch
                .as_ref()
                .expect("node launch config")
                .child_propagation,
            ChildPropagationMode::LpmTsRuntime
        ));
    }

    #[test]
    fn build_exec_plan_uses_strip_types_for_node_22_6_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.6.0");
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::NodeStripTypes);
        assert_eq!(
            plan.command.args,
            vec!["--experimental-strip-types", "hello.ts"]
        );
    }

    #[test]
    fn build_exec_plan_prefers_strip_types_over_local_tsx_for_node_22_6_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.6.0");
        write_local_tsx(dir.path());
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::NodeStripTypes);
        assert_eq!(
            plan.command.args,
            vec!["--experimental-strip-types", "hello.ts"]
        );
    }

    #[test]
    fn build_exec_plan_uses_lpm_ts_runtime_for_node_22_18() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.18.0");
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert!(matches!(plan.strategy, ExecStrategy::LpmTsRuntime { .. }));
        assert_eq!(plan.command.args, vec!["hello.ts"]);
    }

    #[test]
    fn build_exec_plan_uses_local_tsx_when_node_cannot_run_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v20.5.0");
        let tsx_path = write_local_tsx(dir.path());
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert_eq!(
            plan.strategy,
            ExecStrategy::LocalTsx {
                binary: tsx_path.clone()
            }
        );
        assert_eq!(plan.command.program, tsx_path);
    }

    #[test]
    fn build_exec_plan_uses_lpm_ts_runtime_for_tsx_when_node_supports_it() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v22.18.0");
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "view.tsx", &[], &options).unwrap();

        assert!(matches!(plan.strategy, ExecStrategy::LpmTsRuntime { .. }));
        assert_eq!(plan.command.program, PathBuf::from("node"));
    }

    #[test]
    fn build_exec_plan_uses_local_tsx_for_tsx_when_node_cannot_load_lpm_runtime() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v20.5.0");
        let tsx_path = write_local_tsx(dir.path());
        let options = test_options(dir.path());

        let plan = build_exec_plan(dir.path(), "view.tsx", &[], &options).unwrap();

        assert_eq!(
            plan.strategy,
            ExecStrategy::LocalTsx {
                binary: tsx_path.clone()
            }
        );
        assert_eq!(plan.command.program, tsx_path);
    }

    #[test]
    fn build_exec_plan_refuses_tsx_without_lpm_runtime_or_local_tsx() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v20.5.0");
        let options = test_options(dir.path());

        let err = build_exec_plan(dir.path(), "view.tsx", &[], &options).unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("will not fall back to `npx tsx`"),
            "TSX fallback error must explain that unsafe npx is refused: {message}"
        );
    }

    #[test]
    fn build_exec_plan_plain_node_uses_native_typescript_without_lpm_runtime() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.18.0");
        let options = plain_node_options(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert!(plan.command.env_overrides.is_empty());
        assert!(matches!(
            plan.node_launch
                .as_ref()
                .expect("node launch config")
                .child_propagation,
            ChildPropagationMode::Disabled
        ));
    }

    #[test]
    fn build_exec_plan_plain_node_refuses_tsx_without_lpm_runtime() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v22.18.0");
        let options = plain_node_options(dir.path());

        let err = build_exec_plan(dir.path(), "view.tsx", &[], &options).unwrap_err();

        assert!(
            err.to_string().contains("`--plain-node` disables"),
            "plain-node TSX error must explain the disabled augmentation: {err}"
        );
    }

    #[test]
    fn build_exec_plan_refuses_typescript_without_safe_runtime() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v20.5.0");
        let options = test_options(dir.path());

        let err = build_exec_plan(dir.path(), "hello.ts", &[], &options).unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("will not fall back to `npx tsx`"),
            "TypeScript fallback error must explain why npx is refused: {message}"
        );
        assert!(
            message.contains("lpm use node@22.18+"),
            "TypeScript fallback error must suggest a managed Node runtime: {message}"
        );
    }

    #[test]
    fn build_exec_plan_preserves_relative_file_argument() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("script.js"), "console.log('nested')").unwrap();

        write_fake_node(dir.path(), "v20.5.0");
        let options = test_options(dir.path());
        let plan = build_exec_plan(dir.path(), "src/script.js", &[], &options).unwrap();

        assert_eq!(plan.command.args, vec!["src/script.js"]);
    }

    #[test]
    fn exec_file_returns_exit_code_from_failing_script() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("fail.js"), "process.exit(42)").unwrap();

        let options = test_options(dir.path());
        let err = exec_file_with_options(dir.path(), "fail.js", &[], &options).unwrap_err();

        match err {
            LpmError::ExitCode(code) => assert_eq!(code, 42),
            other => panic!("expected ExitCode(42), got: {other}"),
        }
    }

    #[test]
    fn parse_major_minor_accepts_node_version_shapes() {
        assert_eq!(parse_major_minor("22.6.0"), (22, 6));
        assert_eq!(parse_major_minor("v23.6.1"), (23, 6));
        assert_eq!(parse_major_minor("20.20.2"), (20, 20));
        assert_eq!(parse_major_minor("24"), (24, 0));
        assert_eq!(parse_major_minor("abc.def"), (0, 0));
    }

    #[test]
    fn describe_exec_target_uses_the_planned_runtime_label() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v23.6.0");
        let options = test_options(dir.path());

        let target = describe_exec_target_with_options(dir.path(), "hello.ts", &options).unwrap();

        assert_eq!(target.runtime_label, "Node.js v23.6.0 + LPM TS runtime");
    }

    #[test]
    fn detect_effective_node_version_reads_the_exec_path_node() {
        let dir = tempfile::tempdir().unwrap();
        write_fake_node(dir.path(), "v22.9.0");

        assert_eq!(
            detect_effective_node_version(dir.path()).as_deref(),
            Some("v22.9.0")
        );
    }
}
