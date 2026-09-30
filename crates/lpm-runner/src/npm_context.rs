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

    /// Apply logical npm paths to a cache-key environment, never to a spawned child.
    /// Paths outside the workspace remain absolute and location-sensitive.
    pub fn apply_portable_cache_context(
        &self,
        environment: &mut HashMap<String, String>,
        phase: &str,
        command: &str,
        workspace_root: &Path,
    ) -> Result<(), LpmError> {
        self.apply(environment, phase, command);
        let root = workspace_root.canonicalize()?;
        for (key, path) in [
            ("npm_package_json", &self.manifest),
            ("INIT_CWD", &self.invocation_dir),
        ] {
            let canonical = if key == "npm_package_json" && !path.exists() {
                self.manifest
                    .parent()
                    .unwrap_or(&self.invocation_dir)
                    .canonicalize()?
                    .join("package.json")
            } else {
                path.canonicalize()?
            };
            if let Ok(relative) = canonical.strip_prefix(&root) {
                environment.insert(key.into(), portable_cache_path(relative));
            }
        }
        Ok(())
    }
}

fn portable_cache_path(relative: &Path) -> String {
    match relative.to_str() {
        Some(path) => format!("workspace:{}", path.replace(std::path::MAIN_SEPARATOR, "/")),
        None => format!(
            "workspace-bytes:{}",
            hex::encode(relative.as_os_str().as_encoded_bytes())
        ),
    }
}

fn managed_key_matches(key: &str, managed: &str) -> bool {
    if cfg!(windows) {
        key.eq_ignore_ascii_case(managed)
    } else {
        key == managed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_context_preserves_logical_package_and_invocation_locations() {
        let workspace = tempfile::tempdir().unwrap();
        let member = workspace.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), "{}").unwrap();
        let context = NpmScriptContext::new(Some("app"), None, &member, workspace.path());
        let mut hashed = HashMap::new();
        context
            .apply_portable_cache_context(&mut hashed, "build", "node build.js", workspace.path())
            .unwrap();
        assert_eq!(
            hashed["npm_package_json"],
            "workspace:packages/app/package.json"
        );
        assert_eq!(hashed["INIT_CWD"], "workspace:");
        let mut child = HashMap::new();
        context.apply(&mut child, "build", "node build.js");
        assert_eq!(
            child["npm_package_json"],
            member.join("package.json").to_string_lossy()
        );
        assert_eq!(child["INIT_CWD"], workspace.path().to_string_lossy());
        NpmScriptContext::new(Some("app"), None, &member, &member)
            .apply_portable_cache_context(&mut hashed, "build", "node build.js", workspace.path())
            .unwrap();
        assert_eq!(hashed["INIT_CWD"], "workspace:packages/app");
    }

    #[test]
    fn portable_context_retains_external_invocation_paths_and_allows_missing_manifests() {
        let project = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let context = NpmScriptContext::new(None, None, project.path(), external.path());
        let mut hashed = HashMap::new();
        context
            .apply_portable_cache_context(&mut hashed, "build", "echo done", project.path())
            .unwrap();
        assert_eq!(hashed["npm_package_json"], "workspace:package.json");
        assert_eq!(hashed["INIT_CWD"], external.path().to_string_lossy());
    }

    #[cfg(unix)]
    #[test]
    fn portable_context_keeps_distinct_non_utf8_member_paths_distinct() {
        use std::os::unix::ffi::OsStringExt;
        let first = PathBuf::from(std::ffi::OsString::from_vec(b"member-\xff".to_vec()))
            .join("package.json");
        let second = PathBuf::from(std::ffi::OsString::from_vec(b"member-\xfe".to_vec()))
            .join("package.json");
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        assert_ne!(portable_cache_path(&first), portable_cache_path(&second));
    }
}
