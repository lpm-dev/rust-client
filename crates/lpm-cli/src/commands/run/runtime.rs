use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint;
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
                install_ui::phase(&format!(
                    "Using {} {} ({})",
                    runtime_display_name(runtime.as_str()),
                    install_ui::status_ok(&version),
                    install_ui::dim(&format!("from {source}"))
                ));
                bin_dirs.push(bin_dir);
            }
            lpm_runtime::RuntimeStatus::Installed {
                runtime,
                version,
                source,
                bin_dir,
            } => {
                install_ui::done(&format!(
                    "Auto-installed {} {} (from {})",
                    runtime_display_name(runtime.as_str()),
                    install_ui::status_ok(&version),
                    source,
                ));
                bin_dirs.push(bin_dir);
            }
            lpm_runtime::RuntimeStatus::NotInstalled {
                runtime,
                spec,
                source,
            } => {
                install_ui::warn(&format!(
                    "{} requires {} {}, but it's not installed. Using system {}.",
                    source,
                    runtime_display_name(runtime.as_str()),
                    install_ui::yellow(&spec),
                    runtime_display_name(runtime.as_str()),
                ));
                install_ui::detail(&format!(
                    "    {} {}",
                    install_ui::dim("Run:"),
                    install_ui::yellow(&format!("lpm use {}@{spec}", runtime.as_str())),
                ));
            }
        }
    }

    match bin_dirs.len() {
        0 => ManagedRuntimeHint::Absent,
        1 => ManagedRuntimeHint::Bin(bin_dirs.remove(0)),
        _ => ManagedRuntimeHint::Bins(bin_dirs),
    }
}
