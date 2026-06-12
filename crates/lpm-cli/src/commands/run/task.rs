use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
use std::collections::HashMap;
use std::path::Path;

/// Check if a task is a meta-task: has dependsOn but no command and no
/// package.json script. Meta-tasks succeed once all deps complete.
///
/// `pkg_scripts` is the pre-read `package.json` `scripts` map (or `None` if
/// no `package.json` exists). Callers thread this in instead of letting the
/// helper re-read `package.json` per task — `run_tasks_sequential` /
/// `run_tasks_parallel` would otherwise pay one read per task in the
/// dependsOn-but-no-command case.
pub(super) fn is_meta_task(
    task_name: &str,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    pkg_scripts: Option<&HashMap<String, String>>,
) -> bool {
    // Has task config with dependsOn?
    let has_deps = tasks
        .get(task_name)
        .is_some_and(|tc| !tc.depends_on.is_empty());
    if !has_deps {
        return false;
    }

    // Has a command in lpm.json?
    let has_command = tasks
        .get(task_name)
        .and_then(|tc| tc.command.as_ref())
        .is_some();
    if has_command {
        return false;
    }

    // Has a script in package.json?
    if pkg_scripts.is_some_and(|s| s.contains_key(task_name)) {
        return false;
    }

    true // dependsOn exists, but no command/script — it's a meta-task
}

/// Resolve and run a task: checks lpm.json command first, then package.json script.
pub(super) fn run_task(
    project_dir: &Path,
    task_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    // Check lpm.json for command override
    if let Some(command) = tasks.get(task_name).and_then(|tc| tc.command.as_ref()) {
        return lpm_runner::script::run_command(
            project_dir,
            command,
            extra_args,
            env_mode,
            bin_hint,
        );
    }
    // Fall back to package.json script
    lpm_runner::script::run_script(project_dir, task_name, extra_args, env_mode, bin_hint)
}

/// Resolve and run a task with tee-captured output (for caching).
pub(super) fn run_task_captured(
    project_dir: &Path,
    task_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    tasks: &HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<lpm_runner::script::ScriptOutput, LpmError> {
    // Check lpm.json for command override
    if let Some(command) = tasks.get(task_name).and_then(|tc| tc.command.as_ref()) {
        return lpm_runner::script::run_command_captured(
            project_dir,
            command,
            extra_args,
            env_mode,
            bin_hint,
        );
    }
    // Fall back to package.json script
    lpm_runner::script::run_script_captured(project_dir, task_name, extra_args, env_mode, bin_hint)
}

pub(super) fn reject_direct_hidden_scripts(scripts: &[String]) -> Result<(), LpmError> {
    if lpm_runner::script::hidden_script_direct_invocation_allowed() {
        return Ok(());
    }
    let hidden: Vec<&str> = scripts
        .iter()
        .map(String::as_str)
        .filter(|name| lpm_runner::script::is_hidden_script_name(name))
        .collect();
    if hidden.is_empty() {
        return Ok(());
    }
    Err(LpmError::Script(format!(
        "hidden script{} {} cannot be invoked directly",
        if hidden.len() == 1 { "" } else { "s" },
        hidden.join(", ")
    )))
}
