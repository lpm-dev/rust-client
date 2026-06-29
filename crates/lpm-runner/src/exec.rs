//! Direct file execution for `lpm exec src/seed.ts`.
//!
//! Execution is planned in explicit stages: resolve the target, classify the
//! file, resolve the effective runtime, choose a strategy, then spawn the
//! command directly without a shell.

use crate::bin_path::{self, ManagedRuntimeHint};
use crate::dotenv;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const SUPPORTED_FILE_TYPES: &str = ".js, .mjs, .cjs, .ts, .tsx, .mts, .cts";

#[derive(Debug, Clone)]
pub struct ExecTargetDescription {
    pub runtime_label: String,
}

#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub env_mode: Option<String>,
    pub no_env_check: bool,
    pub managed_runtime_hint: ManagedRuntimeHint,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            env_mode: None,
            no_env_check: false,
            managed_runtime_hint: ManagedRuntimeHint::Unknown,
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
    Node { version: Option<String> },
    LocalTsx { binary: PathBuf },
}

impl ExecRuntime {
    fn display_label(&self) -> String {
        match self {
            Self::Node { version } => version.as_deref().map_or_else(
                || "Node.js".to_string(),
                |version| format!("Node.js {version}"),
            ),
            Self::LocalTsx { .. } => "local tsx".to_string(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExecStrategy {
    Node,
    NodeStripTypes,
    LocalTsx { binary: PathBuf },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecCommandPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecPlan {
    pub resolved_path: PathBuf,
    pub file_kind: ExecFileKind,
    pub runtime: ExecRuntime,
    pub strategy: ExecStrategy,
    pub command: ExecCommandPlan,
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
    let strategy = choose_exec_strategy(file_kind, project_dir, node_version.as_deref())?;
    let runtime = runtime_for_strategy(&strategy, node_version);
    let command = build_command_plan(&strategy, file_path, extra_args, path);

    Ok(ExecPlan {
        resolved_path,
        file_kind,
        runtime,
        strategy,
        command,
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

    if !env_vars.is_empty() {
        command.envs(&env_vars);
    }
    command.env("PATH", &plan.command.path);

    let status = command.status().map_err(|e| {
        LpmError::Script(format!(
            "failed to execute '{}': {e}",
            plan.command.program.display()
        ))
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(exit_code_from_status(&status)));
    }

    Ok(())
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
) -> Result<ExecStrategy, LpmError> {
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
        ExecFileKind::Tsx => {
            if let Some(binary) = find_local_tsx_binary(project_dir) {
                return Ok(ExecStrategy::LocalTsx { binary });
            }

            Err(no_safe_tsx_runtime_error(node_version))
        }
    }
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

fn runtime_for_strategy(strategy: &ExecStrategy, node_version: Option<String>) -> ExecRuntime {
    match strategy {
        ExecStrategy::Node | ExecStrategy::NodeStripTypes => ExecRuntime::Node {
            version: node_version,
        },
        ExecStrategy::LocalTsx { binary } => ExecRuntime::LocalTsx {
            binary: binary.clone(),
        },
    }
}

fn build_command_plan(
    strategy: &ExecStrategy,
    file_path: &str,
    extra_args: &[String],
    path: String,
) -> ExecCommandPlan {
    let mut args = Vec::with_capacity(extra_args.len() + 2);
    let program = match strategy {
        ExecStrategy::Node => PathBuf::from("node"),
        ExecStrategy::NodeStripTypes => {
            args.push("--experimental-strip-types".to_string());
            PathBuf::from("node")
        }
        ExecStrategy::LocalTsx { binary } => binary.clone(),
    };
    args.push(file_path.to_string());
    args.extend(extra_args.iter().cloned());

    ExecCommandPlan {
        program,
        args,
        path,
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
        "{runtime_detail}. LPM will not fall back to `npx tsx` because that can download and execute npm code outside LPM's install-policy/security model. Run `lpm use node@22.6+` or install and pin a local `tsx` dev dependency with LPM, then retry."
    ))
}

fn no_safe_tsx_runtime_error(node_version: Option<&str>) -> LpmError {
    let runtime_detail = node_version.map_or_else(
        || "no compatible TSX runtime was detected".to_string(),
        |version| {
            format!(
                "detected Node.js {version}, but Node.js built-in TypeScript execution does not support .tsx files"
            )
        },
    );
    LpmError::Script(format!(
        "{runtime_detail}. TSX requires a project-local `tsx` runtime. LPM will not fall back to `npx tsx` because that can download and execute npm code outside LPM's install-policy/security model. Install and pin a local `tsx` dev dependency with LPM, then retry."
    ))
}

/// Detect the Node.js version that `lpm exec` will actually see on PATH.
#[cfg(test)]
fn detect_effective_node_version(project_dir: &Path) -> Option<String> {
    let path = bin_path::build_path_with_bins(project_dir);
    detect_effective_node_version_with_path(&path)
}

fn detect_effective_node_version_with_path(path: &str) -> Option<String> {
    let output = Command::new("node")
        .arg("--version")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

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

    #[test]
    fn exec_file_runs_javascript_with_node() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.js");

        let result = exec_file(dir.path(), "hello.js", &[]);
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

        let result = exec_file(dir.path(), "args.js", &["--port".into(), "3000".into()]);
        assert!(
            result.is_ok(),
            "extra args including --port should pass through"
        );
    }

    #[test]
    fn build_exec_plan_errors_when_target_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let err = build_exec_plan(dir.path(), "nonexistent.js", &[], &ExecOptions::default())
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn build_exec_plan_errors_when_extension_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("data.csv"), "a,b,c").unwrap();

        let err =
            build_exec_plan(dir.path(), "data.csv", &[], &ExecOptions::default()).unwrap_err();
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

        let plan = build_exec_plan(dir.path(), "hello.mjs", &[], &ExecOptions::default()).unwrap();

        assert_eq!(plan.file_kind, ExecFileKind::JavaScript);
        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert_eq!(plan.command.program, PathBuf::from("node"));
    }

    #[test]
    fn build_exec_plan_uses_native_node_typescript_when_available() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v23.6.0");

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &ExecOptions::default()).unwrap();

        assert_eq!(plan.file_kind, ExecFileKind::TypeScript);
        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert_eq!(plan.command.args, vec!["hello.ts"]);
    }

    #[test]
    fn build_exec_plan_uses_strip_types_for_node_22_6_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.6.0");

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &ExecOptions::default()).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::NodeStripTypes);
        assert_eq!(
            plan.command.args,
            vec!["--experimental-strip-types", "hello.ts"]
        );
    }

    #[test]
    fn build_exec_plan_uses_native_node_typescript_for_node_22_18() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v22.18.0");

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &ExecOptions::default()).unwrap();

        assert_eq!(plan.strategy, ExecStrategy::Node);
        assert_eq!(plan.command.args, vec!["hello.ts"]);
    }

    #[test]
    fn build_exec_plan_uses_local_tsx_when_node_cannot_run_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v20.5.0");
        let tsx_path = write_local_tsx(dir.path());

        let plan = build_exec_plan(dir.path(), "hello.ts", &[], &ExecOptions::default()).unwrap();

        assert_eq!(
            plan.strategy,
            ExecStrategy::LocalTsx {
                binary: tsx_path.clone()
            }
        );
        assert_eq!(plan.command.program, tsx_path);
    }

    #[test]
    fn build_exec_plan_uses_local_tsx_for_tsx_even_when_node_supports_typescript() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v22.18.0");
        let tsx_path = write_local_tsx(dir.path());

        let plan = build_exec_plan(dir.path(), "view.tsx", &[], &ExecOptions::default()).unwrap();

        assert_eq!(
            plan.strategy,
            ExecStrategy::LocalTsx {
                binary: tsx_path.clone()
            }
        );
        assert_eq!(plan.command.program, tsx_path);
    }

    #[test]
    fn build_exec_plan_refuses_tsx_without_local_tsx() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "view.tsx");
        write_fake_node(dir.path(), "v22.18.0");

        let err =
            build_exec_plan(dir.path(), "view.tsx", &[], &ExecOptions::default()).unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("TSX requires a project-local `tsx`"),
            "TSX fallback error must explain the local tsx requirement: {message}"
        );
    }

    #[test]
    fn build_exec_plan_refuses_typescript_without_safe_runtime() {
        let dir = tempfile::tempdir().unwrap();
        write_project_file(dir.path(), "hello.ts");
        write_fake_node(dir.path(), "v20.5.0");

        let err =
            build_exec_plan(dir.path(), "hello.ts", &[], &ExecOptions::default()).unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("will not fall back to `npx tsx`"),
            "TypeScript fallback error must explain why npx is refused: {message}"
        );
        assert!(
            message.contains("lpm use node@22.6+"),
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

        let plan =
            build_exec_plan(dir.path(), "src/script.js", &[], &ExecOptions::default()).unwrap();

        assert_eq!(plan.command.args, vec!["src/script.js"]);
    }

    #[test]
    fn exec_file_returns_exit_code_from_failing_script() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("fail.js"), "process.exit(42)").unwrap();

        let err = exec_file(dir.path(), "fail.js", &[]).unwrap_err();

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

        let target = describe_exec_target(dir.path(), "hello.ts").unwrap();

        assert_eq!(target.runtime_label, "Node.js v23.6.0");
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
