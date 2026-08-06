use std::path::Path;
use std::process::{Command, Stdio};

/// Get system Bun version by running `bun --version`.
pub(super) fn get_system_bun_version(
    project_dir: &Path,
) -> lpm_runtime::detect::DetectionResult<Option<String>> {
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir)?;
    let Ok(output) = Command::new("bun")
        .arg("--version")
        .env("PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return Ok(None);
    };

    if output.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    } else {
        Ok(None)
    }
}
