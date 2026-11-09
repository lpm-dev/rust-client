//! Tools that act on a project on this machine by running the LPM CLI:
//! `lpm_install`, `lpm_add`, and `lpm_audit`.

use lpm_common::PackageName;
use lpm_common::process_output::CaptureSession;
use lpm_registry::RegistryClient;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// How long `lpm install` and `lpm add` may run.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long `lpm audit` may run.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// How long a stopped command has to stop what it started before it is
/// killed. `lpm install` stops a lifecycle script's process group of its own,
/// which a kill of the command's group doesn't reach.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// The most output kept from each of a command's stdout and stderr.
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

/// The most of a failed command's stderr quoted back to the agent.
const STDERR_TAIL_CHARS: usize = 4_000;

/// Commands running at once. Each is a whole CLI run, and an agent can ask
/// for many in one turn.
const CONCURRENT_COMMANDS: usize = 4;

/// The longest version, path, alias, target, or configuration value taken.
const MAX_ARGUMENT_CHARS: usize = 1_024;

/// The most configuration entries `lpm_add` takes.
const MAX_CONFIG_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalTool {
    Install,
    Add,
    Audit,
}

impl LocalTool {
    const ALL: [Self; 3] = [Self::Install, Self::Add, Self::Audit];

    pub(super) fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Install => "lpm_install",
            Self::Add => "lpm_add",
            Self::Audit => "lpm_audit",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Add => "add",
            Self::Audit => "audit",
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::Install | Self::Add => CHANGE_TIMEOUT,
            Self::Audit => AUDIT_TIMEOUT,
        }
    }
}

const PROJECT_PATH: &str =
    "Absolute path of the project's directory, which holds its package.json or Package.swift.";
const PACKAGE_NAME: &str = "Package name, as owner.package-name or @lpm.dev/owner.package-name.";

/// The local tools' definitions, in the order they are listed.
pub(super) fn definitions() -> &'static [Tool] {
    static DEFINITIONS: LazyLock<Vec<Tool>> = LazyLock::new(|| {
        let definitions = serde_json::json!([
            {
                "name": "lpm_install",
                "title": "Install an LPM.dev package",
                "description": "Install an LPM.dev package into a project as a dependency, with `lpm install`. A JavaScript package goes into node_modules and package.json, and a Swift package into Package.swift. Use it for libraries, utilities, and SDKs. Returns the command's JSON result.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "projectPath": { "type": "string", "description": PROJECT_PATH },
                        "name": { "type": "string", "description": PACKAGE_NAME },
                        "version": { "type": "string", "description": "Version or range to install. Defaults to the latest version." }
                    },
                    "required": ["projectPath", "name"],
                    "additionalProperties": false
                },
                "annotations": {
                    "title": "Install an LPM.dev package",
                    "readOnlyHint": false,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": true
                }
            },
            {
                "name": "lpm_add",
                "title": "Add an LPM.dev package's source",
                "description": "Copy an LPM.dev package's source files into a project to customize them, with `lpm add`. Use it for UI components, blocks, and templates. Returns the command's JSON result.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "projectPath": { "type": "string", "description": PROJECT_PATH },
                        "name": { "type": "string", "description": PACKAGE_NAME },
                        "version": { "type": "string", "description": "Version or range to add. Defaults to the latest version." },
                        "path": { "type": "string", "description": "Directory for the files, relative to the project, such as src/components/ui." },
                        "alias": { "type": "string", "description": "Import alias prefix for the copied files' imports, such as @/components/ui." },
                        "target": { "type": "string", "description": "For a Swift package, the target that receives the files." },
                        "force": { "type": "boolean", "description": "Overwrite files that already exist." },
                        "installDeps": { "type": "boolean", "description": "Install the package's dependencies too. Defaults to true." },
                        "config": {
                            "type": "object",
                            "additionalProperties": { "type": "string" },
                            "description": "Choices the package's configuration offers, as key-value pairs, such as { \"styling\": \"panda\" }."
                        }
                    },
                    "required": ["projectPath", "name"],
                    "additionalProperties": false
                },
                "annotations": {
                    "title": "Add an LPM.dev package's source",
                    "readOnlyHint": false,
                    "destructiveHint": true,
                    "idempotentHint": false,
                    "openWorldHint": true
                }
            },
            {
                "name": "lpm_audit",
                "title": "Audit a project's dependencies",
                "description": "Check a project's installed dependencies with `lpm audit`: known vulnerabilities, behavior such as eval or shell use, AI security findings, quality, and lifecycle scripts. Findings don't make the call fail. Returns the command's JSON report.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "projectPath": { "type": "string", "description": PROJECT_PATH }
                    },
                    "required": ["projectPath"],
                    "additionalProperties": false
                },
                "annotations": {
                    "title": "Audit a project's dependencies",
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": true
                }
            }
        ]);
        serde_json::from_value(definitions).expect("local MCP tool definitions are valid")
    });
    &DEFINITIONS
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallArguments {
    project_path: String,
    name: String,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AddArguments {
    project_path: String,
    name: String,
    version: Option<String>,
    path: Option<String>,
    alias: Option<String>,
    target: Option<String>,
    force: Option<bool>,
    install_deps: Option<bool>,
    config: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditArguments {
    project_path: String,
}

/// A local tool call, checked and ready to run.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    project: PathBuf,
    args: Vec<String>,
}

pub(super) struct LocalTools {
    executable: PathBuf,
    /// The registry options this server runs with, which each command it
    /// runs takes too, since a `--registry` flag isn't inherited.
    global_args: Vec<String>,
    /// The `--token` this server runs with. Each command gets it as
    /// `LPM_TOKEN`, which ranks above a stored login as the flag does, and
    /// stays out of the command line, where other users can read it.
    token: Option<SecretString>,
    permits: Arc<tokio::sync::Semaphore>,
    spawn: Spawn,
}

impl LocalTools {
    pub(super) fn new(
        executable: PathBuf,
        client: &RegistryClient,
        explicit_token: Option<String>,
    ) -> Self {
        let mut global_args = vec![format!("--registry={}", client.base_url())];
        if client.allow_insecure() {
            global_args.push("--insecure".to_owned());
        }
        Self {
            executable,
            global_args,
            token: explicit_token
                .filter(|token| !token.is_empty())
                .map(SecretString::from),
            permits: Arc::new(tokio::sync::Semaphore::new(CONCURRENT_COMMANDS)),
            spawn: std::process::Command::spawn,
        }
    }

    /// Run `tool`. A call the tool can't run, such as one with a missing
    /// project, is a tool result that says why, so the agent can correct it.
    pub(super) async fn call(
        &self,
        tool: LocalTool,
        arguments: Option<JsonObject>,
        cancel: CancellationToken,
    ) -> CallToolResult {
        let mut invocation = match invocation(tool, arguments.unwrap_or_default()) {
            Ok(invocation) => invocation,
            Err(reason) => return tool_error(reason),
        };
        invocation
            .args
            .splice(0..0, self.global_args.iter().cloned());
        let command = format!("lpm {}", tool.command());
        let permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return tool_error(format!("`{command}` was cancelled.")),
            permit = self.permits.acquire() => permit,
        };
        let Ok(_permit) = permit else {
            return tool_error(format!("`{}` is unavailable", tool.name()));
        };
        let token = self.token.as_ref().map(ExposeSecret::expose_secret);
        match run(
            &self.executable,
            invocation,
            token,
            tool.timeout(),
            cancel,
            self.spawn,
        )
        .await
        {
            Ok(Ran::Finished(output)) => result_of(tool, &command, &output),
            Ok(Ran::TimedOut) => tool_error(format!(
                "`{command}` didn't finish within {} minutes and was stopped.",
                tool.timeout().as_secs() / 60
            )),
            Ok(Ran::Cancelled) => tool_error(format!("`{command}` was cancelled.")),
            Err(error) => tool_error(format!("`{command}` couldn't run: {error}")),
        }
    }
}

fn tool_error(text: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text.into())])
}

fn invocation(tool: LocalTool, arguments: JsonObject) -> Result<Invocation, String> {
    let arguments = serde_json::Value::Object(arguments);
    let invalid =
        |error: serde_json::Error| format!("Invalid arguments for `{}`: {error}", tool.name());
    match tool {
        LocalTool::Install => {
            let arguments: InstallArguments = serde_json::from_value(arguments).map_err(invalid)?;
            Ok(Invocation {
                project: project_directory(&arguments.project_path)?,
                args: vec![
                    "install".to_owned(),
                    package_spec(&arguments.name, arguments.version.as_deref(), None)?,
                    "--json".to_owned(),
                ],
            })
        }
        LocalTool::Add => {
            let arguments: AddArguments = serde_json::from_value(arguments).map_err(invalid)?;
            let mut args = vec![
                "add".to_owned(),
                package_spec(
                    &arguments.name,
                    arguments.version.as_deref(),
                    arguments.config.as_ref(),
                )?,
                "--yes".to_owned(),
                "--json".to_owned(),
            ];
            if let Some(path) = &arguments.path {
                args.push(format!("--path={}", project_relative_path(path)?));
            }
            if let Some(alias) = &arguments.alias {
                args.push(format!("--alias={}", plain_value("alias", alias)?));
            }
            if let Some(target) = &arguments.target {
                args.push(format!("--target={}", plain_value("target", target)?));
            }
            if arguments.force == Some(true) {
                args.push("--force".to_owned());
            }
            if arguments.install_deps == Some(false) {
                args.push("--no-install-deps".to_owned());
            }
            Ok(Invocation {
                project: project_directory(&arguments.project_path)?,
                args,
            })
        }
        LocalTool::Audit => {
            let arguments: AuditArguments = serde_json::from_value(arguments).map_err(invalid)?;
            Ok(Invocation {
                project: project_directory(&arguments.project_path)?,
                args: vec!["audit".to_owned(), "--json".to_owned()],
            })
        }
    }
}

/// The project directory a call names, resolved through any links. An
/// agent's own working directory may not be the user's project, so the path
/// is required and must be absolute.
fn project_directory(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(format!(
            "projectPath must be an absolute path to the project's directory, not {}.",
            path.display()
        ));
    }
    let directory = path
        .canonicalize()
        .map_err(|error| format!("projectPath {} can't be used: {error}.", path.display()))?;
    if !directory.is_dir() {
        return Err(format!(
            "projectPath {} is not a directory.",
            directory.display()
        ));
    }
    Ok(directory)
}

/// `@lpm.dev/owner.name[@version][?config]`, from a name given with or
/// without its `@lpm.dev/` scope.
fn package_spec(
    name: &str,
    version: Option<&str>,
    config: Option<&BTreeMap<String, String>>,
) -> Result<String, String> {
    let scoped = if name.starts_with("@lpm.dev/") {
        name.to_owned()
    } else if name.starts_with('@') {
        return Err(format!(
            "{name} isn't an LPM.dev package. These tools take LPM.dev packages, named owner.package-name or @lpm.dev/owner.package-name."
        ));
    } else {
        format!("@lpm.dev/{name}")
    };
    let mut spec = PackageName::parse(&scoped)
        .map_err(|error| format!("{name} isn't a valid LPM.dev package name: {error}"))?
        .scoped();
    if let Some(version) = version {
        let version = version.trim();
        if version.is_empty()
            || version.chars().count() > MAX_ARGUMENT_CHARS
            || version.chars().any(|character| {
                !(' '..='~').contains(&character) || matches!(character, '?' | '#')
            })
        {
            return Err(format!(
                "version must be a version, range, or tag in printable ASCII, not {version:?}."
            ));
        }
        spec.push('@');
        spec.push_str(version);
    }
    if let Some(config) = config.filter(|config| !config.is_empty()) {
        if config.len() > MAX_CONFIG_ENTRIES {
            return Err(format!(
                "config takes at most {MAX_CONFIG_ENTRIES} entries."
            ));
        }
        for (index, (key, value)) in config.iter().enumerate() {
            if key.is_empty() {
                return Err("config keys can't be empty.".to_owned());
            }
            if key.chars().count() > MAX_ARGUMENT_CHARS
                || value.chars().count() > MAX_ARGUMENT_CHARS
            {
                return Err(format!(
                    "config keys and values are at most {MAX_ARGUMENT_CHARS} characters."
                ));
            }
            spec.push(if index == 0 { '?' } else { '&' });
            spec.push_str(&urlencoding::encode(key));
            spec.push('=');
            spec.push_str(&urlencoding::encode(value));
        }
    }
    Ok(spec)
}

/// A directory inside the project, given relative to it.
fn project_relative_path(path: &str) -> Result<&str, String> {
    let relative = Path::new(path);
    if path.is_empty()
        || path.chars().count() > MAX_ARGUMENT_CHARS
        || path.chars().any(char::is_control)
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!(
            "path must be a directory inside the project, relative to it, such as src/components/ui, not {path:?}."
        ));
    }
    Ok(path)
}

fn plain_value<'a>(field: &str, value: &'a str) -> Result<&'a str, String> {
    if value.is_empty()
        || value.chars().count() > MAX_ARGUMENT_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{field} must be text of at most {MAX_ARGUMENT_CHARS} characters, without control characters."
        ));
    }
    Ok(value)
}

/// Starts a command's process. Tests count starts through it.
type Spawn = fn(&mut std::process::Command) -> std::io::Result<std::process::Child>;

enum Ran {
    Finished(std::process::Output),
    TimedOut,
    Cancelled,
}

/// Run the CLI for `invocation` in its project, stopping the command and
/// every process it started when `timeout` passes or `cancel` fires.
async fn run(
    executable: &Path,
    invocation: Invocation,
    token: Option<&str>,
    timeout: Duration,
    cancel: CancellationToken,
    spawn: Spawn,
) -> std::io::Result<Ran> {
    if cancel.is_cancelled() {
        return Ok(Ran::Cancelled);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_on_drop = StopOnDrop(Arc::clone(&stop));
    let mut command = std::process::Command::new(executable);
    command
        .args(&invocation.args)
        .current_dir(&invocation.project)
        .env("NO_COLOR", "1");
    if let Some(token) = token {
        command.env("LPM_TOKEN", token);
    }
    let deadline = Instant::now() + timeout;
    let watcher = {
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            cancel.cancelled().await;
            stop.store(true, Ordering::Release);
        })
    };
    let worker_stop = Arc::clone(&stop);
    let outcome = tokio::task::spawn_blocking(move || {
        let mut timed_out = false;
        let mut session = CaptureSession::default();
        let output = session.capture_output_with_spawn_and_grace(
            &mut command,
            OUTPUT_LIMIT,
            |_| {
                if worker_stop.load(Ordering::Acquire) {
                    return Some(STOP_SIGNAL);
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    return Some(STOP_SIGNAL);
                }
                None
            },
            spawn,
            STOP_GRACE,
        );
        (output, timed_out)
    })
    .await;
    watcher.abort();
    // Read before the guard drops, since dropping it stops a command too.
    let cancelled = stop.load(Ordering::Acquire);
    drop(stop_on_drop);
    let (output, timed_out) = outcome.map_err(std::io::Error::other)?;
    let output = output?;
    Ok(if timed_out {
        Ran::TimedOut
    } else if cancelled {
        Ran::Cancelled
    } else {
        Ran::Finished(output)
    })
}

#[cfg(unix)]
const STOP_SIGNAL: i32 = libc::SIGTERM;
#[cfg(not(unix))]
const STOP_SIGNAL: i32 = 15;

/// Stops the command when the call is dropped, as when a client cancels it
/// or disconnects, so no command outlives the request that started it.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The tool result for a command that ran to the end: its JSON output, which
/// is an error when the command reports failure. `lpm audit` exits 1 when it
/// finds problems, which is its report, not a failure.
fn result_of(tool: LocalTool, command: &str, output: &std::process::Output) -> CallToolResult {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .filter(serde_json::Value::is_object);
    let Some(report) = report.filter(|_| output.stdout.len() < OUTPUT_LIMIT) else {
        let status = output
            .status
            .code()
            .map_or_else(|| "a signal".to_owned(), |code| format!("status {code}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = lpm_common::sanitize_terminal_multiline(stderr.trim());
        let tail: String = {
            let skip = stderr.chars().count().saturating_sub(STDERR_TAIL_CHARS);
            stderr.chars().skip(skip).collect()
        };
        return tool_error(if tail.is_empty() {
            format!("`{command}` exited with {status} without a JSON result.")
        } else {
            format!("`{command}` exited with {status} without a JSON result:\n{tail}")
        });
    };
    let reported_failure = report.get("success") == Some(&serde_json::Value::Bool(false));
    let failed = reported_failure || (tool != LocalTool::Audit && !output.status.success());
    let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| report.to_string());
    if failed {
        CallToolResult::error(vec![ContentBlock::text(text)])
    } else {
        CallToolResult::success(vec![ContentBlock::text(text)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    fn arguments(value: serde_json::Value) -> JsonObject {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn definitions_list_the_three_local_tools_with_their_required_project() {
        let names: Vec<_> = definitions()
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect();
        assert_eq!(names, ["lpm_install", "lpm_add", "lpm_audit"]);
        for tool in definitions() {
            assert_eq!(LocalTool::named(&tool.name).unwrap().name(), tool.name);
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("projectPath")),
                "{} must require projectPath",
                tool.name
            );
        }
        assert_eq!(LocalTool::named("lpm_search"), None);
    }

    #[test]
    fn install_runs_lpm_install_for_the_scoped_package_in_the_canonical_project() {
        let project = tempfile::tempdir().unwrap();

        let invocation = invocation(
            LocalTool::Install,
            arguments(json!({
                "projectPath": project.path().to_str().unwrap(),
                "name": "acme.forms",
                "version": "^2.1.0",
            })),
        )
        .unwrap();

        assert_eq!(invocation.project, project.path().canonicalize().unwrap());
        assert_eq!(
            invocation.args,
            ["install", "@lpm.dev/acme.forms@^2.1.0", "--json"]
        );
    }

    #[test]
    fn add_passes_every_option_as_one_argument_each() {
        let project = tempfile::tempdir().unwrap();

        let invocation = invocation(
            LocalTool::Add,
            arguments(json!({
                "projectPath": project.path().to_str().unwrap(),
                "name": "@lpm.dev/acme.dialog",
                "path": "src/components/ui",
                "alias": "@/components/ui",
                "target": "App",
                "force": true,
                "installDeps": false,
                "config": { "styling": "panda css", "mode": "a&b=c" },
            })),
        )
        .unwrap();

        assert_eq!(
            invocation.args,
            [
                "add",
                "@lpm.dev/acme.dialog?mode=a%26b%3Dc&styling=panda%20css",
                "--yes",
                "--json",
                "--path=src/components/ui",
                "--alias=@/components/ui",
                "--target=App",
                "--force",
                "--no-install-deps",
            ]
        );
    }

    #[test]
    fn audit_needs_only_the_project() {
        let project = tempfile::tempdir().unwrap();

        let invocation = invocation(
            LocalTool::Audit,
            arguments(json!({ "projectPath": project.path().to_str().unwrap() })),
        )
        .unwrap();

        assert_eq!(invocation.args, ["audit", "--json"]);
    }

    #[test]
    fn calls_without_an_absolute_existing_project_directory_are_refused() {
        let project = tempfile::tempdir().unwrap();
        let file = project.path().join("package.json");
        std::fs::write(&file, "{}").unwrap();

        for (path, expected) in [
            ("relative/project", "must be an absolute path"),
            (
                project.path().join("missing").to_str().unwrap(),
                "can't be used",
            ),
            (file.to_str().unwrap(), "is not a directory"),
        ] {
            let error = invocation(LocalTool::Audit, arguments(json!({ "projectPath": path })))
                .unwrap_err();
            assert!(error.contains(expected), "{path}: {error}");
        }
        let missing = invocation(LocalTool::Audit, JsonObject::new()).unwrap_err();
        assert!(missing.contains("projectPath"), "{missing}");
    }

    #[test]
    fn packages_outside_lpm_dev_and_malformed_names_are_refused() {
        for name in ["@other/pkg", "react", "acme..forms", "@lpm.dev/../escape"] {
            assert!(
                package_spec(name, None, None).is_err(),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn versions_that_could_change_the_spec_are_refused() {
        for version in [
            "",
            "1.0.0?evil=1",
            "1.0.0#frag",
            "1.0.0\n2.0.0",
            "2.0.0\u{7}",
            "ünï",
        ] {
            assert!(
                package_spec("acme.forms", Some(version), None).is_err(),
                "{version:?} must be refused"
            );
        }
        assert_eq!(
            package_spec("acme.forms", Some(">=1.2 <2"), None).unwrap(),
            "@lpm.dev/acme.forms@>=1.2 <2"
        );
    }

    #[test]
    fn add_paths_must_stay_inside_the_project() {
        for path in ["../outside", "/etc", "src/../../outside", "", "a\nb"] {
            assert!(
                project_relative_path(path).is_err(),
                "{path:?} must be refused"
            );
        }
        assert_eq!(project_relative_path("./src/ui").unwrap(), "./src/ui");
    }

    #[test]
    fn unknown_arguments_are_refused_so_a_typo_is_not_ignored() {
        let project = tempfile::tempdir().unwrap();

        let error = invocation(
            LocalTool::Install,
            arguments(json!({
                "projectPath": project.path().to_str().unwrap(),
                "name": "acme.forms",
                "dev": true,
            })),
        )
        .unwrap_err();

        assert!(error.contains("unknown field `dev`"), "{error}");
    }

    #[cfg(unix)]
    fn output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_audit_with_findings_is_its_report_not_a_failure() {
        let report = r#"{"vulnerabilities":[{"id":"GHSA-1"}]}"#;

        let audit = result_of(LocalTool::Audit, "lpm audit", &output(1, report, ""));
        let install = result_of(LocalTool::Install, "lpm install", &output(1, report, ""));
        let refused = result_of(
            LocalTool::Audit,
            "lpm audit",
            &output(1, r#"{"success":false,"error":"no lockfile"}"#, ""),
        );

        assert_eq!(audit.is_error, Some(false));
        assert_eq!(install.is_error, Some(true));
        assert_eq!(refused.is_error, Some(true));
    }

    #[cfg(unix)]
    #[test]
    fn a_command_without_json_output_reports_its_status_and_stderr() {
        let result = result_of(
            LocalTool::Install,
            "lpm install",
            &output(2, "", "error: \u{1b}[31mbroken\u{1b}[0m\n"),
        );

        assert_eq!(result.is_error, Some(true));
        let text = serde_json::to_value(&result.content[0]).unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(text.contains("exited with status 2"), "{text}");
        assert!(text.contains("broken"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_past_its_deadline_is_stopped_with_everything_it_started() {
        let project = tempfile::tempdir().unwrap();
        let marker = project.path().join("survivor");
        let script = project.path().join("slow.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n(sleep 2; touch '{}') &\nsleep 30\n",
                marker.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let started = Instant::now();
        let ran = run(
            &script,
            Invocation {
                project: project.path().to_path_buf(),
                args: Vec::new(),
            },
            None,
            Duration::from_millis(300),
            CancellationToken::new(),
            std::process::Command::spawn,
        )
        .await
        .unwrap();

        assert!(matches!(ran, Ran::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !marker.exists(),
            "a background process the command started must be stopped with it"
        );
    }

    /// An executable script in `dir` that runs `body`.
    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("tool.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    static STARTS_WHILE_QUEUED: AtomicUsize = AtomicUsize::new(0);
    static STARTS_AFTER_CANCEL: AtomicUsize = AtomicUsize::new(0);

    fn spawn_counting_queued(
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        STARTS_WHILE_QUEUED.fetch_add(1, Ordering::SeqCst);
        command.spawn()
    }

    fn spawn_counting_cancelled(
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        STARTS_AFTER_CANCEL.fetch_add(1, Ordering::SeqCst);
        command.spawn()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_call_cancelled_while_it_waits_for_a_slot_never_starts_its_command() {
        let project = tempfile::tempdir().unwrap();
        let tool = script(project.path(), r#"echo '{"success":true}'"#);
        let mut tools = LocalTools::new(tool, &RegistryClient::new(), None);
        tools.spawn = spawn_counting_queued;
        let busy = Arc::clone(&tools.permits)
            .acquire_many_owned(CONCURRENT_COMMANDS as u32)
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let arguments = serde_json::json!({ "projectPath": project.path().to_str().unwrap() });

        let (result, ()) = tokio::join!(
            tools.call(
                LocalTool::Audit,
                arguments.as_object().cloned(),
                cancel.clone()
            ),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                cancel.cancel();
                tokio::time::sleep(Duration::from_millis(100)).await;
                drop(busy);
            },
        );

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            STARTS_WHILE_QUEUED.load(Ordering::SeqCst),
            0,
            "a call cancelled while queued must not start its command"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_call_cancelled_before_its_command_starts_never_starts_it() {
        let project = tempfile::tempdir().unwrap();
        let tool = script(project.path(), "exit 0");
        let cancel = CancellationToken::new();
        cancel.cancel();

        let ran = run(
            &tool,
            Invocation {
                project: project.path().to_path_buf(),
                args: Vec::new(),
            },
            None,
            Duration::from_secs(60),
            cancel,
            spawn_counting_cancelled,
        )
        .await
        .unwrap();

        assert!(matches!(ran, Ran::Cancelled));
        assert_eq!(STARTS_AFTER_CANCEL.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commands_run_with_the_servers_explicit_token_as_lpm_token() {
        let project = tempfile::tempdir().unwrap();
        let tool = script(
            project.path(),
            r#"printf '{"success":true,"token":"%s","args":"%s"}' "$LPM_TOKEN" "$*""#,
        );
        let tools = LocalTools::new(tool, &RegistryClient::new(), Some("flag-token".to_owned()));
        let arguments = serde_json::json!({ "projectPath": project.path().to_str().unwrap() });

        let result = tools
            .call(
                LocalTool::Audit,
                arguments.as_object().cloned(),
                CancellationToken::new(),
            )
            .await;

        let text = serde_json::to_value(&result.content[0]).unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned();
        let report: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["token"], "flag-token");
        assert!(
            !report["args"].as_str().unwrap().contains("flag-token"),
            "the token must stay out of the command line: {report}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_that_finishes_is_reported_with_its_output() {
        let project = tempfile::tempdir().unwrap();

        let ran = run(
            Path::new("/bin/echo"),
            Invocation {
                project: project.path().to_path_buf(),
                args: vec![r#"{"success":true}"#.to_owned()],
            },
            None,
            Duration::from_secs(60),
            CancellationToken::new(),
            std::process::Command::spawn,
        )
        .await
        .unwrap();

        let Ran::Finished(output) = ran else {
            panic!("a command that exits on its own has finished");
        };
        assert!(output.status.success());
        assert_eq!(output.stdout, b"{\"success\":true}\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_cancelled_call_stops_its_command() {
        let project = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.cancel();
        });

        let started = Instant::now();
        let ran = run(
            Path::new("/bin/sleep"),
            Invocation {
                project: project.path().to_path_buf(),
                args: vec!["30".to_owned()],
            },
            None,
            Duration::from_secs(60),
            cancel,
            std::process::Command::spawn,
        )
        .await
        .unwrap();

        assert!(matches!(ran, Ran::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
