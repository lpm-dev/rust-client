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
    let detected = detect_runtime_selectors_with_workspace_root(project_dir)?;
    let hint = ensure_detected_runtimes(detected).await;
    validate_runtime(project_dir, &hint, json_output)?;
    Ok(hint)
}

/// The project's runtime selectors, with the workspace root's selector for
/// each runtime the project doesn't select itself: workspace members inherit
/// root pins. Both are read before anything installs, so a root runtime the
/// member overrides is never downloaded.
fn detect_runtime_selectors_with_workspace_root(
    project_dir: &Path,
) -> Result<Vec<lpm_runtime::detect::DetectedRuntimeVersion>, LpmError> {
    let mut detected = lpm_runtime::detect::detect_runtime_versions(project_dir)?;
    let Some(root) = lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .filter(|root| root != project_dir)
    else {
        return Ok(detected);
    };
    for inherited in lpm_runtime::detect::detect_runtime_versions(&root)? {
        let selected_here = detected
            .iter()
            .any(|own| own.runtime == inherited.runtime && own.is_runtime_selector());
        if inherited.is_runtime_selector() && !selected_here {
            detected.push(inherited);
        }
    }
    Ok(detected)
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
    let effective_node = crate::engine_check::path_node_versions()
        .resolve(project_dir, std::ffi::OsStr::new(&script_path));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_with_root_pins(root_pins: &str, member_pins: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("lpm.json"), root_pins).unwrap();
        let member = dir.path().join("packages/web");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), r#"{"name":"web"}"#).unwrap();
        if let Some(pins) = member_pins {
            std::fs::write(member.join("lpm.json"), pins).unwrap();
        }
        dir
    }

    fn selected_specs(project: &Path) -> Vec<(lpm_runtime::detect::RuntimeKind, String)> {
        let mut specs: Vec<_> = detect_runtime_selectors_with_workspace_root(project)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.is_runtime_selector())
            .map(|entry| (entry.runtime, entry.spec))
            .collect();
        specs.sort_by_key(|(runtime, _)| format!("{runtime:?}"));
        specs
    }

    #[test]
    fn a_member_inherits_the_workspace_root_runtime_pins() {
        let dir = workspace_with_root_pins(r#"{"runtime":{"node":"22.12.0"}}"#, None);

        assert_eq!(
            selected_specs(&dir.path().join("packages/web")),
            vec![(
                lpm_runtime::detect::RuntimeKind::Node,
                "22.12.0".to_string()
            )]
        );
    }

    #[test]
    fn a_member_pin_overrides_only_its_own_runtime() {
        let dir = workspace_with_root_pins(
            r#"{"runtime":{"node":"22.12.0","bun":"1.2.0"}}"#,
            Some(r#"{"runtime":{"node":"20.18.0"}}"#),
        );

        assert_eq!(
            selected_specs(&dir.path().join("packages/web")),
            vec![
                (lpm_runtime::detect::RuntimeKind::Bun, "1.2.0".to_string()),
                (
                    lpm_runtime::detect::RuntimeKind::Node,
                    "20.18.0".to_string()
                ),
            ]
        );
    }
}
