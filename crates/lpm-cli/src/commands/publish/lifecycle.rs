use crate::install_ui;
use lpm_common::LpmError;
use std::io::IsTerminal as _;
use std::path::Path;
use std::time::Duration;

const BEFORE_PACK_PHASES: &[&str] = &["prepublishOnly", "prepack", "prepare"];
const AFTER_PACK_PHASES: &[&str] = &["postpack"];
const AFTER_PUBLISH_PHASES: &[&str] = &["publish", "postpublish"];
const PUBLISH_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) struct PublishLifecycle {
    package_name: String,
    package_version: String,
    before_pack: Vec<PublishLifecycleScript>,
    after_pack: Vec<PublishLifecycleScript>,
    after_publish: Vec<PublishLifecycleScript>,
}

#[derive(Debug)]
struct PublishLifecycleScript {
    phase: &'static str,
    command: String,
}

impl PublishLifecycle {
    pub(crate) fn load_for_publish(
        project_dir: &Path,
        yes: bool,
        ignore_scripts: bool,
        json_output: bool,
    ) -> Result<Option<Self>, LpmError> {
        Self::load(
            project_dir,
            yes,
            ignore_scripts,
            json_output,
            true,
            "publish",
        )
    }

    pub(crate) fn load_for_stage(
        project_dir: &Path,
        yes: bool,
        ignore_scripts: bool,
        json_output: bool,
    ) -> Result<Option<Self>, LpmError> {
        Self::load(
            project_dir,
            yes,
            ignore_scripts,
            json_output,
            false,
            "stage",
        )
    }

    fn load(
        project_dir: &Path,
        yes: bool,
        ignore_scripts: bool,
        json_output: bool,
        include_publish_phases: bool,
        operation: &str,
    ) -> Result<Option<Self>, LpmError> {
        if ignore_scripts {
            return Ok(None);
        }
        let package = lpm_workspace::read_package_json(&project_dir.join("package.json")).map_err(
            |error| {
                LpmError::Script(format!(
                    "failed to read package.json lifecycle scripts: {error}"
                ))
            },
        )?;
        let before_pack = scripts_for_phases(&package.scripts, BEFORE_PACK_PHASES);
        let after_pack = scripts_for_phases(&package.scripts, AFTER_PACK_PHASES);
        let after_publish = if include_publish_phases {
            scripts_for_phases(&package.scripts, AFTER_PUBLISH_PHASES)
        } else {
            Vec::new()
        };
        let script_count = before_pack.len() + after_pack.len() + after_publish.len();
        if script_count == 0 {
            return Ok(None);
        }
        require_consent(yes, json_output, operation, script_count)?;
        Ok(Some(Self {
            package_name: package.name.unwrap_or_else(|| "<anonymous>".into()),
            package_version: package.version.unwrap_or_else(|| "0.0.0".into()),
            before_pack,
            after_pack,
            after_publish,
        }))
    }

    pub(crate) fn run_before_pack(
        &self,
        project_dir: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        self.run_scripts(project_dir, &self.before_pack, json_output)
    }

    pub(crate) fn run_after_pack(
        &self,
        project_dir: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        self.run_scripts(project_dir, &self.after_pack, json_output)
    }

    pub(crate) fn run_after_publish(
        &self,
        project_dir: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        self.run_scripts(project_dir, &self.after_publish, json_output)
    }

    fn run_scripts(
        &self,
        project_dir: &Path,
        scripts: &[PublishLifecycleScript],
        json_output: bool,
    ) -> Result<(), LpmError> {
        for script in scripts {
            self.run_script(project_dir, script, json_output)?;
        }
        Ok(())
    }

    fn run_script(
        &self,
        project_dir: &Path,
        script: &PublishLifecycleScript,
        json_output: bool,
    ) -> Result<(), LpmError> {
        if !json_output {
            install_ui::phase_line(crate::install_ui::terminal_line!(
                "Running publish lifecycle {}",
                install_ui::yellow(script.phase)
            ));
        }
        let runtime = tempfile::Builder::new()
            .prefix("lpm-publish-lifecycle-")
            .tempdir()
            .map_err(LpmError::Io)?;
        let store_root = runtime.path().join("store");
        std::fs::create_dir(&store_root).map_err(LpmError::Io)?;
        let envs = self.envs_for(project_dir, runtime.path(), script);
        crate::commands::rebuild::execute_publish_lifecycle_script(
            &script.command,
            &self.package_name,
            &self.package_version,
            project_dir,
            &envs,
            &store_root,
            runtime.path(),
            runtime.path(),
            PUBLISH_LIFECYCLE_TIMEOUT,
        )
        .map_err(|error| {
            LpmError::Script(format!(
                "publish lifecycle script `{}` failed: {error}",
                script.phase
            ))
        })
    }

    fn envs_for(
        &self,
        project_dir: &Path,
        runtime_dir: &Path,
        script: &PublishLifecycleScript,
    ) -> Vec<(String, String)> {
        let inherited_path = std::env::var("PATH").ok();
        let mut envs = Vec::with_capacity(14);
        envs.push((
            "PATH".into(),
            crate::commands::rebuild::publish_lifecycle_path(
                project_dir,
                inherited_path.as_deref(),
            ),
        ));
        let runtime = runtime_dir.display().to_string();
        envs.push(("HOME".into(), runtime.clone()));
        envs.push(("TMPDIR".into(), runtime.clone()));
        envs.push(("TMP".into(), runtime.clone()));
        envs.push(("TEMP".into(), runtime));
        envs.push(("INIT_CWD".into(), project_dir.display().to_string()));
        envs.push(("npm_lifecycle_event".into(), script.phase.into()));
        envs.push(("npm_lifecycle_script".into(), script.command.clone()));
        envs.push(("npm_package_name".into(), self.package_name.clone()));
        envs.push(("npm_package_version".into(), self.package_version.clone()));
        for key in ["SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC"] {
            if let Ok(value) = std::env::var(key) {
                envs.push((key.into(), value));
            }
        }
        envs
    }
}

fn require_consent(
    yes: bool,
    json_output: bool,
    operation: &str,
    script_count: usize,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    let interactive =
        !json_output && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    if !interactive {
        return Err(LpmError::Script(format!(
            "{operation} lifecycle scripts require an explicit choice in non-interactive mode; pass `--yes` to run them or `--ignore-scripts` to skip them"
        )));
    }
    let confirmed = cliclack::confirm(crate::prompt::untrusted(format!(
        "Run {script_count} package lifecycle script(s) for this {operation}?"
    )))
    .initial_value(false)
    .interact()
    .map_err(crate::prompt::prompt_err)?;
    if confirmed {
        Ok(())
    } else {
        Err(LpmError::Script(format!(
            "{operation} lifecycle scripts were not authorized; rerun with `--ignore-scripts` to skip them"
        )))
    }
}

fn scripts_for_phases(
    scripts: &std::collections::HashMap<String, String>,
    phases: &'static [&'static str],
) -> Vec<PublishLifecycleScript> {
    phases
        .iter()
        .filter_map(|phase| {
            scripts
                .get(*phase)
                .filter(|command| !command.trim().is_empty())
                .map(|command| PublishLifecycleScript {
                    phase,
                    command: command.clone(),
                })
        })
        .collect()
}
