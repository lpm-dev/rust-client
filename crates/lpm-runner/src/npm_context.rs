//! Per-phase npm script metadata, independent of environment loading and spawning.

use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const KEYS: [&str; 6] = [
    "npm_lifecycle_event",
    "npm_lifecycle_script",
    "npm_package_name",
    "npm_package_version",
    "npm_package_json",
    "INIT_CWD",
];

pub struct NpmScriptContext {
    name: String,
    version: String,
    manifest: PathBuf,
    invocation_dir: PathBuf,
}

impl NpmScriptContext {
    pub fn new(
        name: Option<&str>,
        version: Option<&str>,
        package_dir: &Path,
        invocation_dir: &Path,
    ) -> Self {
        Self {
            name: name.unwrap_or_default().to_string(),
            version: version.unwrap_or_default().to_string(),
            manifest: if package_dir.is_absolute() {
                package_dir.to_path_buf()
            } else {
                invocation_dir.join(package_dir)
            }
            .join("package.json"),
            invocation_dir: invocation_dir.to_path_buf(),
        }
    }

    pub fn load(package_dir: &Path, invocation_dir: &Path) -> Result<Self, LpmError> {
        let package = match lpm_workspace::read_package_json(&package_dir.join("package.json")) {
            Ok(package) => Some(package),
            Err(lpm_workspace::WorkspaceError::NotFound(_)) => None,
            Err(error) => {
                return Err(LpmError::Script(format!(
                    "failed to read package.json: {error}"
                )));
            }
        };
        Ok(Self::new(
            package.as_ref().and_then(|p| p.name.as_deref()),
            package.as_ref().and_then(|p| p.version.as_deref()),
            package_dir,
            invocation_dir,
        ))
    }

    pub fn envs(&self, phase: &str, command: &str) -> [(String, String); 6] {
        let mut values = [
            phase.to_string(),
            command.to_string(),
            self.name.clone(),
            self.version.clone(),
            self.manifest.to_string_lossy().into_owned(),
            self.invocation_dir.to_string_lossy().into_owned(),
        ];
        std::array::from_fn(|index| (KEYS[index].to_string(), std::mem::take(&mut values[index])))
    }

    pub fn apply(&self, environment: &mut HashMap<String, String>, phase: &str, command: &str) {
        environment.retain(|key, _| !KEYS.iter().any(|managed| managed_key_matches(key, managed)));
        environment.extend(self.envs(phase, command));
    }
}

fn managed_key_matches(key: &str, managed: &str) -> bool {
    if cfg!(windows) {
        key.eq_ignore_ascii_case(managed)
    } else {
        key == managed
    }
}
