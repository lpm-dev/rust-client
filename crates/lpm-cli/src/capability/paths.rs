use super::{CapabilityParseError, CapabilitySet};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(super) fn parse_paths(
    scripts: &serde_json::Value,
    field: &str,
    manifest: &Path,
) -> Result<BTreeSet<String>, CapabilityParseError> {
    let invalid = || CapabilityParseError::ShapeMismatch {
        path: manifest.display().to_string(),
        field: format!("lpm.scripts.{field}"),
        expected: "an array of nonempty paths without control characters".to_string(),
    };
    let Some(value) = scripts.get(field) else {
        return Ok(BTreeSet::new());
    };
    value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|entry| {
            let path = entry.as_str().ok_or_else(invalid)?;
            if path.is_empty() || path.chars().any(char::is_control) {
                return Err(invalid());
            }
            Ok(path.to_string())
        })
        .collect()
}

impl CapabilitySet {
    pub fn from_project(manifest: &Path) -> Result<Self, CapabilityParseError> {
        let mut request = Self::from_package_json(manifest)?;
        let config = crate::commands::config::GlobalConfig::load();
        let user_read = config
            .get_str_array("script-read-allow")
            .unwrap_or_default();
        if request.read_allow.is_empty() && request.write_dirs.is_empty() && user_read.is_empty() {
            return Ok(request);
        }
        let project = manifest.parent().unwrap_or_else(|| Path::new("."));
        let home = dirs::home_dir();
        let max_write_roots: Vec<_> = config
            .get_str_array("max-sandbox-write-roots")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| {
                if let Some(rest) = entry.strip_prefix("~/") {
                    home.as_ref().map(|home| home.join(rest))
                } else if entry == "~" {
                    home.clone()
                } else {
                    let path = PathBuf::from(entry);
                    path.is_absolute().then_some(path)
                }
            })
            .collect();
        let failure = |error: lpm_sandbox::SandboxError| CapabilityParseError::Io {
            path: manifest.display().to_string(),
            source: error.to_string(),
        };
        let reads = lpm_sandbox::resolve_sandbox_read_allow(
            project,
            &request.read_allow.iter().cloned().collect::<Vec<_>>(),
            &user_read,
        )
        .map_err(failure)?;
        let writes = lpm_sandbox::load_sandbox_write_dirs(
            manifest,
            project,
            &max_write_roots,
            home.as_deref(),
        )
        .map_err(failure)?;
        let encode = |paths: Vec<PathBuf>| -> Result<BTreeSet<String>, CapabilityParseError> {
            paths
                .into_iter()
                .map(|path| {
                    path.into_os_string()
                        .into_string()
                        .map_err(|_| CapabilityParseError::Io {
                            path: manifest.display().to_string(),
                            source: "sandbox permission paths must use UTF-8".to_string(),
                        })
                })
                .collect()
        };
        request.read_allow = encode(reads)?;
        request.write_dirs = encode(writes)?;
        Ok(request)
    }
}
