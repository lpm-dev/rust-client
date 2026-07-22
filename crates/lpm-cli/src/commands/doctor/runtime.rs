use std::path::Path;
use std::process::{Command, Stdio};

/// Extract node version spec from doctor detail message.
pub(super) fn extract_node_spec_from_detail(detail: &str) -> Option<String> {
    // "... pinned >=22 from ... Run: lpm use node@22"
    if let Some(pos) = detail.find("node@") {
        let after = &detail[pos + 5..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"')
            .unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    // Fallback: "not found — run: lpm use node@22"
    None
}

// --- Check helpers ---

/// Get system Node.js version by running `node --version`.
pub(super) fn get_system_node_version(
    project_dir: &Path,
) -> lpm_runtime::detect::DetectionResult<Option<String>> {
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir)?;
    let Ok(output) = Command::new("node")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_node_spec_works() {
        let detail = "not found — pinned >=22 from .nvmrc. Run: lpm use node@22";
        let spec = extract_node_spec_from_detail(detail);
        assert_eq!(spec, Some("22".to_string()));
    }

    #[test]
    fn extract_node_spec_none_when_missing() {
        let detail = "v20.0.0 (system, no version pinned)";
        let spec = extract_node_spec_from_detail(detail);
        assert!(spec.is_none());
    }
}
