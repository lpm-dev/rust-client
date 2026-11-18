use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::io::Write as _;
use std::path::{Path, PathBuf};

const DEV_PREINSTALL: &str = "pnpm:devPreinstall";
const AFTER_INSTALL_PHASES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
];

/// Whether `lpm install` runs the script `name` of the project or of a
/// workspace member.
pub(crate) fn is_install_lifecycle_script(name: &str) -> bool {
    name == DEV_PREINSTALL || AFTER_INSTALL_PHASES.contains(&name)
}

#[cfg(test)]
pub(crate) fn install_lifecycle_scripts() -> impl Iterator<Item = &'static str> {
    std::iter::once(DEV_PREINSTALL).chain(AFTER_INSTALL_PHASES.iter().copied())
}

#[derive(Debug, Clone)]
pub struct RootProjectLifecycle {
    package_name: Option<String>,
    package_version: Option<String>,
    dev_preinstall: Option<RootLifecycleScript>,
    after_install: Vec<RootLifecycleScript>,
}

#[derive(Debug, Clone)]
struct RootLifecycleScript {
    phase: &'static str,
    command: RootCommand,
}

#[derive(Debug, Clone)]
enum RootCommand {
    /// What the manifest names for the phase.
    Named(String),
    /// The `install` a `binding.gyp` beside the manifest implies.
    NativeBuild,
}

/// Where the implied build's `node-gyp` comes from.
#[derive(Debug, PartialEq, Eq)]
enum NodeGyp {
    /// A command the script's `PATH` holds.
    Command,
    /// A script `node` runs: the one the caller's `npm_config_node_gyp`
    /// names, or `bin/node-gyp.js` of the npm beside `node`.
    Script(PathBuf),
}

impl NodeGyp {
    /// As npm orders them: a command the project's own packages supply,
    /// the script the caller names, the one of the npm beside the host's
    /// `node`, and then any command further along `PATH`. `host_path` is
    /// the script's `PATH` after the project's own entries.
    fn find(
        project_bins: &[PathBuf],
        host_path: &std::ffi::OsStr,
        named_by_caller: Option<PathBuf>,
    ) -> Option<Self> {
        if project_bins
            .iter()
            .any(|directory| holds_node_gyp(directory))
        {
            return Some(Self::Command);
        }
        if let Some(script) = named_by_caller {
            return Some(Self::Script(script));
        }
        if let Some(script) = super::rebuild::npm_node_gyp_beside_node_on(host_path) {
            return Some(Self::Script(script));
        }
        std::env::split_paths(host_path)
            .any(|directory| holds_node_gyp(&directory))
            .then_some(Self::Command)
    }

    /// The command line that builds with it. A script reaches the line
    /// through a variable, so neither shell reads its path as anything
    /// but a path. The variable is one of LPM's own: the runner passes a
    /// script no `npm_config_node_gyp` but the caller's, under whatever
    /// case the caller wrote it in.
    fn command(&self) -> &'static str {
        match self {
            Self::Command => lpm_security::native_build::IMPLIED_INSTALL_SCRIPT,
            Self::Script(_) if cfg!(windows) => r#"node "%LPM_NODE_GYP_SCRIPT%" rebuild"#,
            Self::Script(_) => r#"node "$LPM_NODE_GYP_SCRIPT" rebuild"#,
        }
    }

    /// What the command's environment gains for it.
    fn environment(&self) -> Option<(String, String)> {
        match self {
            Self::Script(script) => Some((
                NODE_GYP_SCRIPT.to_string(),
                script.to_string_lossy().into_owned(),
            )),
            Self::Command => None,
        }
    }
}

/// Names the script the implied build runs to its command line.
const NODE_GYP_SCRIPT: &str = "LPM_NODE_GYP_SCRIPT";

fn holds_node_gyp(directory: &Path) -> bool {
    let commands: &[&str] = if cfg!(windows) {
        &["node-gyp.cmd", "node-gyp.exe", "node-gyp.bat"]
    } else {
        &["node-gyp"]
    };
    commands
        .iter()
        .any(|command| directory.join(command).is_file())
}

impl RootProjectLifecycle {
    pub fn load(project_dir: &Path) -> Result<Self, LpmError> {
        let pkg_json_path = project_dir.join("package.json");
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
        Ok(Self::from_package(project_dir, &pkg))
    }

    /// The scripts of the package at `project_dir`. One with a
    /// `binding.gyp` gets the `install` npm gives it when its manifest
    /// names none.
    pub fn from_package(project_dir: &Path, pkg: &lpm_workspace::PackageJson) -> Self {
        let dev_preinstall = script_for_phase(&pkg.scripts, DEV_PREINSTALL);
        // npm follows a link to the file here, where a dependency's must
        // be a file of its own.
        let builds_binding_gyp = lpm_security::native_build::scripts_leave_install_to_binding_gyp(
            pkg.scripts.get("install").map(String::as_str),
            pkg.scripts.get("preinstall").map(String::as_str),
            pkg.gypfile,
        ) && project_dir
            .join(lpm_security::native_build::BINDING_GYP)
            .is_file();
        let mut after_install = Vec::with_capacity(AFTER_INSTALL_PHASES.len());
        for phase in AFTER_INSTALL_PHASES {
            if let Some(script) = script_for_phase(&pkg.scripts, phase) {
                after_install.push(script);
            } else if *phase == "install" && builds_binding_gyp {
                after_install.push(RootLifecycleScript {
                    phase,
                    command: RootCommand::NativeBuild,
                });
            }
        }

        Self {
            package_name: pkg.name.clone(),
            package_version: pkg.version.clone(),
            dev_preinstall,
            after_install,
        }
    }

    pub fn has_dev_preinstall(&self) -> bool {
        self.dev_preinstall.is_some()
    }

    pub fn has_scripts(&self) -> bool {
        self.dev_preinstall.is_some() || !self.after_install.is_empty()
    }

    pub fn run_dev_preinstall(
        &self,
        project_dir: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        match &self.dev_preinstall {
            Some(script) => self.run_script(project_dir, script, json_output),
            None => Ok(()),
        }
    }

    pub fn run_after_successful_install(
        &self,
        project_dir: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        for script in &self.after_install {
            self.run_script(project_dir, script, json_output)?;
        }
        Ok(())
    }

    fn run_script(
        &self,
        project_dir: &Path,
        script: &RootLifecycleScript,
        json_output: bool,
    ) -> Result<(), LpmError> {
        if !json_output {
            install_ui::phase_line(crate::install_ui::terminal_line!(
                "Running root lifecycle {}",
                install_ui::yellow(script.phase)
            ));
        }

        let (command, node_gyp) = match &script.command {
            RootCommand::Named(command) => (command.as_str(), None),
            RootCommand::NativeBuild => {
                let node_gyp = find_node_gyp(project_dir)?;
                (node_gyp.command(), node_gyp.environment())
            }
        };
        // npm names the script as its manifest would, whichever node-gyp
        // it runs with.
        let named = match &script.command {
            RootCommand::Named(command) => command.as_str(),
            RootCommand::NativeBuild => lpm_security::native_build::IMPLIED_INSTALL_SCRIPT,
        };
        let mut envs = self.envs_for(project_dir, script.phase, named)?;
        envs.extend(node_gyp);
        let result = if json_output {
            let output = lpm_runner::script::run_command_buffered_with_envs(
                project_dir,
                command,
                &[],
                None,
                &envs,
                &ManagedRuntimeHint::Unknown,
            );
            match output {
                Ok(output) => {
                    forward_script_output_to_stderr(&output.stdout)?;
                    forward_script_output_to_stderr(&output.stderr)?;
                    Ok(())
                }
                Err(LpmError::ScriptWithOutput {
                    code,
                    stdout,
                    stderr,
                }) => {
                    forward_script_output_to_stderr(&stdout)?;
                    forward_script_output_to_stderr(&stderr)?;
                    Err(LpmError::ExitCode(code))
                }
                Err(err) => Err(err),
            }
        } else {
            lpm_runner::script::run_command_with_envs(
                project_dir,
                command,
                &[],
                None,
                &envs,
                &ManagedRuntimeHint::Unknown,
            )
        };

        match result {
            Ok(()) => Ok(()),
            Err(LpmError::ExitCode(code)) => Err(LpmError::ScriptPhase {
                phase: script.phase.to_string(),
                code,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Err(err) => Err(err),
        }
    }

    fn envs_for(
        &self,
        project_dir: &Path,
        phase: &str,
        command: &str,
    ) -> Result<Vec<(String, String)>, LpmError> {
        let context = lpm_runner::npm_context::NpmScriptContext::new(
            self.package_name.as_deref(),
            self.package_version.as_deref(),
            project_dir,
            &std::env::current_dir()?,
        );
        let mut envs = context.envs(phase, command).to_vec();
        if let Some(root) = super::install::workspace_lockfile::active_install_root() {
            envs.push(lpm_common::parent_install_lock_environment(&root)?);
        }
        Ok(envs)
    }
}

fn script_for_phase(
    scripts: &std::collections::HashMap<String, String>,
    phase: &'static str,
) -> Option<RootLifecycleScript> {
    scripts
        .get(phase)
        .filter(|command| !command.trim().is_empty())
        .map(|command| RootLifecycleScript {
            phase,
            command: RootCommand::Named(command.clone()),
        })
}

/// `path` without the project's own command directories. A package may
/// supply a `node` there, and the npm that offers its node-gyp is the one
/// beside the host's.
fn without_project_bins(
    path: &std::ffi::OsStr,
    project_bins: &[PathBuf],
) -> Result<std::ffi::OsString, LpmError> {
    std::env::join_paths(
        std::env::split_paths(path).filter(|directory| !project_bins.contains(directory)),
    )
    .map_err(|error| LpmError::Script(format!("PATH can't be searched for node-gyp: {error}")))
}

/// The `node-gyp` the build of `project_dir`'s `binding.gyp` starts, looked
/// for where the script that runs it will look.
fn find_node_gyp(project_dir: &Path) -> Result<NodeGyp, LpmError> {
    let path = lpm_runner::bin_path::build_path_with_bins_pre_resolved(
        project_dir,
        &ManagedRuntimeHint::Unknown,
    )?;
    let project_bins = lpm_runner::bin_path::find_bin_dirs(project_dir);
    let host_path = without_project_bins(std::ffi::OsStr::new(&path), &project_bins)?;
    // npm reads its settings from the environment under any case.
    let named_by_caller = std::env::vars_os().find_map(|(name, script)| {
        (name.eq_ignore_ascii_case(super::rebuild::NPM_CONFIG_NODE_GYP) && !script.is_empty())
            .then(|| PathBuf::from(script))
    });
    NodeGyp::find(&project_bins, &host_path, named_by_caller).ok_or_else(|| {
        LpmError::Script(format!(
            "{} has a binding.gyp, which an install builds with node-gyp, and none was found: \
             no installed package supplies it, npm isn't installed beside node, and it isn't \
             on PATH. Add node-gyp to devDependencies, or set \"gypfile\": false in \
             package.json to leave the file unbuilt.",
            project_dir.display()
        ))
    })
}

fn forward_script_output_to_stderr(output: &str) -> Result<(), LpmError> {
    if output.is_empty() {
        return Ok(());
    }
    std::io::stderr()
        .write_all(lpm_common::sanitize_terminal_multiline(output).as_bytes())
        .map_err(LpmError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND: &str = if cfg!(windows) {
        "node-gyp.cmd"
    } else {
        "node-gyp"
    };

    fn package(manifest: serde_json::Value) -> lpm_workspace::PackageJson {
        serde_json::from_value(manifest).unwrap()
    }

    fn phases(lifecycle: &RootProjectLifecycle) -> Vec<&'static str> {
        lifecycle
            .after_install
            .iter()
            .map(|script| script.phase)
            .collect()
    }

    #[test]
    fn a_binding_gyp_beside_the_manifest_implies_an_install_in_its_place_among_the_phases() {
        let project = tempfile::tempdir().unwrap();
        let manifest = package(serde_json::json!({
            "scripts": { "postinstall": "node after.js", "prepare": "node prepare.js" }
        }));
        assert_eq!(
            phases(&RootProjectLifecycle::from_package(
                project.path(),
                &manifest
            )),
            ["postinstall", "prepare"]
        );

        std::fs::write(project.path().join("binding.gyp"), "{}").unwrap();
        let lifecycle = RootProjectLifecycle::from_package(project.path(), &manifest);
        assert_eq!(phases(&lifecycle), ["install", "postinstall", "prepare"]);
        assert!(matches!(
            lifecycle.after_install[0].command,
            RootCommand::NativeBuild
        ));
        assert!(lifecycle.has_scripts());
    }

    #[test]
    fn a_manifest_that_speaks_for_its_install_implies_none() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("binding.gyp"), "{}").unwrap();
        for manifest in [
            serde_json::json!({ "gypfile": false }),
            serde_json::json!({ "scripts": { "install": "node build.js" } }),
            serde_json::json!({ "scripts": { "preinstall": "node check.js" } }),
        ] {
            let lifecycle = RootProjectLifecycle::from_package(project.path(), &package(manifest));
            assert!(
                !lifecycle
                    .after_install
                    .iter()
                    .any(|script| matches!(script.command, RootCommand::NativeBuild)),
                "{lifecycle:?}"
            );
        }
    }

    #[test]
    fn node_gyp_comes_from_the_project_then_the_caller_then_npm_then_path() {
        let root = tempfile::tempdir().unwrap();
        let project_bin = root.path().join("project-bin");
        let empty_bin = root.path().join("empty-bin");
        let global_bin = root.path().join("global-bin");
        for directory in [&project_bin, &empty_bin, &global_bin] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::write(project_bin.join(COMMAND), "").unwrap();
        std::fs::write(global_bin.join(COMMAND), "").unwrap();
        let node_bin = crate::commands::rebuild::node_with_npm_for_test(&root.path().join("host"));
        let script = crate::commands::rebuild::npm_node_gyp_beside_node_on(node_bin.as_os_str())
            .expect("the fixture's npm holds node-gyp");
        let path = std::env::join_paths([&node_bin, &global_bin]).unwrap();
        let without_npm = std::env::join_paths([&empty_bin, &global_bin]).unwrap();
        let without_any = empty_bin.as_os_str();
        let named = PathBuf::from("named-by-the-caller.js");

        assert_eq!(
            NodeGyp::find(
                std::slice::from_ref(&project_bin),
                &path,
                Some(named.clone())
            ),
            Some(NodeGyp::Command)
        );
        assert_eq!(
            NodeGyp::find(std::slice::from_ref(&empty_bin), &path, Some(named.clone())),
            Some(NodeGyp::Script(named))
        );
        assert_eq!(
            NodeGyp::find(&[], &path, None),
            Some(NodeGyp::Script(script))
        );
        assert_eq!(
            NodeGyp::find(&[], &without_npm, None),
            Some(NodeGyp::Command)
        );
        assert_eq!(NodeGyp::find(&[], without_any, None), None);
    }

    #[test]
    fn a_node_among_the_project_s_commands_does_not_hide_the_npm_beside_the_host_s() {
        let root = tempfile::tempdir().unwrap();
        let project_bin = root.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&project_bin).unwrap();
        std::fs::write(
            project_bin.join(if cfg!(windows) { "node.exe" } else { "node" }),
            "",
        )
        .unwrap();
        let node_bin = crate::commands::rebuild::node_with_npm_for_test(&root.path().join("host"));
        let script = crate::commands::rebuild::npm_node_gyp_beside_node_on(node_bin.as_os_str());
        assert!(script.is_some());
        let path = std::env::join_paths([&project_bin, &node_bin]).unwrap();
        assert_eq!(
            crate::commands::rebuild::npm_node_gyp_beside_node_on(&path),
            None,
            "the project's node is first on the script's PATH"
        );

        let host_path = without_project_bins(&path, std::slice::from_ref(&project_bin)).unwrap();

        assert_eq!(
            NodeGyp::find(&[project_bin], &host_path, None),
            script.map(NodeGyp::Script)
        );
    }

    #[test]
    fn a_script_reaches_the_build_through_a_variable_and_never_the_command_line() {
        let path = if cfg!(windows) {
            r"C:\SDK%USERNAME%\node's & co\node-gyp.js"
        } else {
            "/opt/node's $HOME/node-gyp.js"
        };
        let script = NodeGyp::Script(PathBuf::from(path));

        assert!(!script.command().contains("node-gyp.js"));
        assert!(script.command().contains(NODE_GYP_SCRIPT));
        assert_eq!(
            script.environment(),
            Some((NODE_GYP_SCRIPT.to_string(), path.to_string()))
        );
        assert_eq!(NodeGyp::Command.environment(), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_binding_gyp_that_is_a_link_to_a_file_is_built_as_npm_builds_it() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("shared.gyp"), "{}").unwrap();
        std::os::unix::fs::symlink("shared.gyp", project.path().join("binding.gyp")).unwrap();

        let lifecycle =
            RootProjectLifecycle::from_package(project.path(), &package(serde_json::json!({})));

        assert_eq!(phases(&lifecycle), ["install"]);
    }
}
