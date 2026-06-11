use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::io::Write as _;
use std::path::Path;

const DEV_PREINSTALL: &str = "pnpm:devPreinstall";
const AFTER_INSTALL_PHASES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
];

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
    command: String,
}

impl RootProjectLifecycle {
    pub fn load(project_dir: &Path) -> Result<Self, LpmError> {
        let pkg_json_path = project_dir.join("package.json");
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;

        let dev_preinstall = script_for_phase(&pkg.scripts, DEV_PREINSTALL);
        let mut after_install = Vec::with_capacity(AFTER_INSTALL_PHASES.len());
        for phase in AFTER_INSTALL_PHASES {
            if let Some(script) = script_for_phase(&pkg.scripts, phase) {
                after_install.push(script);
            }
        }

        Ok(Self {
            package_name: pkg.name,
            package_version: pkg.version,
            dev_preinstall,
            after_install,
        })
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
            install_ui::phase(&format!(
                "Running root lifecycle {}",
                install_ui::yellow(script.phase)
            ));
        }

        let envs = self.envs_for(script);
        let result = if json_output {
            let output = lpm_runner::script::run_command_buffered_with_envs(
                project_dir,
                &script.command,
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
                    Err(LpmError::Script(format!(
                        "root lifecycle script `{}` failed with exit code {code}",
                        script.phase
                    )))
                }
                Err(err) => Err(err),
            }
        } else {
            lpm_runner::script::run_command_with_envs(
                project_dir,
                &script.command,
                &[],
                None,
                &envs,
                &ManagedRuntimeHint::Unknown,
            )
        };

        match result {
            Ok(()) => Ok(()),
            Err(LpmError::ExitCode(code)) => Err(LpmError::Script(format!(
                "root lifecycle script `{}` failed with exit code {code}",
                script.phase
            ))),
            Err(err) => Err(err),
        }
    }

    fn envs_for(&self, script: &RootLifecycleScript) -> Vec<(String, String)> {
        let mut envs = Vec::with_capacity(4);
        envs.push(("npm_lifecycle_event".to_string(), script.phase.to_string()));
        envs.push(("npm_lifecycle_script".to_string(), script.command.clone()));
        if let Some(name) = &self.package_name {
            envs.push(("npm_package_name".to_string(), name.clone()));
        }
        if let Some(version) = &self.package_version {
            envs.push(("npm_package_version".to_string(), version.clone()));
        }
        envs
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
            command: command.clone(),
        })
}

fn forward_script_output_to_stderr(output: &str) -> Result<(), LpmError> {
    if output.is_empty() {
        return Ok(());
    }
    std::io::stderr()
        .write_all(output.as_bytes())
        .map_err(LpmError::Io)
}
