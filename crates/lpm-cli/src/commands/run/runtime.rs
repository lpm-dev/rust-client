use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::{ManagedRuntimeBin, ManagedRuntimeHint};
use lpm_runtime::effective::PathNodeVersionCache;
use std::path::Path;

fn runtime_display_name(runtime: &str) -> &str {
    match runtime {
        "node" => "Node.js",
        other => other,
    }
}

/// Ensure required managed runtimes are available before running scripts.
///
/// Detects version requirements from project config, auto-installs if needed,
/// prints the runtime version in use, and returns a pre-resolved PATH hint for
/// downstream script execution.
pub async fn ensure_runtime(project_dir: &Path) -> Result<ManagedRuntimeHint, LpmError> {
    let detected = lpm_runtime::detect::detect_runtime_versions(project_dir)?;
    Ok(ensure_detected_runtimes(detected).await)
}

/// Apply managed runtime selectors, then validate the selected Node against
/// `package.json > engines.node` without treating that constraint as a selector.
pub async fn prepare_runtime(
    project_dir: &Path,
    json_output: bool,
) -> Result<ManagedRuntimeHint, LpmError> {
    let detected = lpm_runtime::detect::detect_runtime_versions(project_dir)?;
    let hint = ensure_detected_runtimes(detected).await;
    validate_runtime(project_dir, &hint, json_output)?;
    Ok(hint)
}

/// Validate the Node resolved from the exact PATH constructed for scripts.
pub fn validate_runtime(
    project_dir: &Path,
    hint: &ManagedRuntimeHint,
    json_output: bool,
) -> Result<(), LpmError> {
    let requirements =
        crate::engine_check::resolve_execution_node_engine_requirements(project_dir)?;
    if requirements.is_empty() {
        return Ok(());
    }
    let script_path = lpm_runner::bin_path::build_path_with_bins_pre_resolved(project_dir, hint)?;
    let effective_node = lpm_runtime::effective::resolve_node_on_path_with_fingerprint(
        project_dir,
        std::ffi::OsStr::new(&script_path),
    );
    for requirement in requirements {
        crate::engine_check::enforce_resolved_node_requirement_for_run(
            requirement.required,
            requirement.engine_strict,
            requirement.source,
            effective_node.clone(),
            json_output,
        )?;
    }
    Ok(())
}

/// Validate a workspace member while reusing probes for shared Node executables.
pub fn validate_runtime_with_cache(
    project_dir: &Path,
    hint: &ManagedRuntimeHint,
    json_output: bool,
    node_versions: &mut PathNodeVersionCache,
) -> Result<(), LpmError> {
    let requirements =
        crate::engine_check::resolve_execution_node_engine_requirements(project_dir)?;
    validate_runtime_requirements_with_cache(
        project_dir,
        hint,
        json_output,
        node_versions,
        &requirements,
    )
}

pub fn validate_runtime_requirements_with_cache(
    project_dir: &Path,
    hint: &ManagedRuntimeHint,
    json_output: bool,
    node_versions: &mut PathNodeVersionCache,
    requirements: &[crate::engine_check::NodeEngineRequirement],
) -> Result<(), LpmError> {
    if requirements.is_empty() {
        return Ok(());
    }
    let script_path = lpm_runner::bin_path::build_path_with_bins_pre_resolved(project_dir, hint)?;
    let effective_node = node_versions.resolve(project_dir, std::ffi::OsStr::new(&script_path));
    for requirement in requirements {
        crate::engine_check::enforce_resolved_node_requirement_for_run(
            requirement.required.clone(),
            requirement.engine_strict,
            requirement.source.clone(),
            effective_node.clone(),
            json_output,
        )?;
    }
    Ok(())
}

/// Ensure already-detected managed runtimes are available before running scripts.
///
/// This preserves the runtime status UI and PATH hint while allowing callers to
/// complete fallible configuration reads before starting unrelated work.
pub async fn ensure_detected_runtimes(
    detected: Vec<lpm_runtime::detect::DetectedRuntimeVersion>,
) -> ManagedRuntimeHint {
    let statuses = lpm_runtime::ensure_detected_runtimes(detected).await;
    if statuses.is_empty() {
        return ManagedRuntimeHint::Absent;
    }

    let mut bin_dirs = Vec::with_capacity(statuses.len());
    for status in statuses {
        match status {
            lpm_runtime::RuntimeStatus::Ready {
                runtime,
                version,
                source,
                bin_dir,
            } => {
                install_ui::phase_line(crate::install_ui::terminal_line!(
                    "Using {} {} ({})",
                    runtime_display_name(runtime.as_str()),
                    install_ui::status_ok(&version),
                    install_ui::dim(&format!("from {source}"))
                ));
                bin_dirs.push(ManagedRuntimeBin {
                    runtime,
                    version,
                    bin_dir,
                });
            }
            lpm_runtime::RuntimeStatus::Installed {
                runtime,
                version,
                source,
                bin_dir,
            } => {
                install_ui::done_line(crate::install_ui::terminal_line!(
                    "Auto-installed {} {} (from {})",
                    runtime_display_name(runtime.as_str()),
                    install_ui::status_ok(&version),
                    source,
                ));
                bin_dirs.push(ManagedRuntimeBin {
                    runtime,
                    version,
                    bin_dir,
                });
            }
            lpm_runtime::RuntimeStatus::NotInstalled {
                runtime,
                spec,
                source,
            } => {
                install_ui::warn_line(crate::install_ui::terminal_line!(
                    "{} requires {} {}, but it's not installed. Using the first {} on script PATH.",
                    source,
                    runtime_display_name(runtime.as_str()),
                    install_ui::yellow(&spec),
                    runtime_display_name(runtime.as_str()),
                ));
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "    {} {}",
                    install_ui::dim("Run:"),
                    install_ui::yellow(&format!("lpm use {}@{spec}", runtime.as_str())),
                ));
            }
        }
    }

    match bin_dirs.len() {
        0 => ManagedRuntimeHint::Absent,
        _ => ManagedRuntimeHint::Resolved(bin_dirs),
    }
}
