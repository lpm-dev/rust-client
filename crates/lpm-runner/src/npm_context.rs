//! Per-phase npm script metadata, independent of environment loading and spawning.

use lpm_common::LpmError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub(crate) const KEYS: [&str; 6] = [
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

    /// Replace the npm lifecycle variables in `environment`, whose keys and
    /// values may be `String`s or `OsString`s.
    pub fn apply<K, V>(&self, environment: &mut HashMap<K, V>, phase: &str, command: &str)
    where
        K: From<String> + AsRef<std::ffi::OsStr> + Eq + std::hash::Hash,
        V: From<String>,
    {
        environment.retain(|key, _| {
            !KEYS
                .iter()
                .any(|managed| managed_key_matches(key.as_ref(), managed))
        });
        environment.extend(
            self.envs(phase, command)
                .into_iter()
                .map(|(key, value)| (K::from(key), V::from(value))),
        );
    }

    /// `npm_package_json` as a task-cache key sees it: as a path under
    /// `root`, the workspace root, so that checkouts at other paths share the
    /// key. A manifest outside `root` stays absolute. The script itself still
    /// gets the real path from [`Self::apply`].
    pub fn portable_manifest_path(&self, root: &Path) -> Result<String, LpmError> {
        let root = root.canonicalize()?;
        let manifest = match self.manifest.canonicalize() {
            Ok(manifest) => manifest,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self
                .manifest
                .parent()
                .unwrap_or(&self.invocation_dir)
                .canonicalize()?
                .join("package.json"),
            Err(error) => return Err(error.into()),
        };
        Ok(portable_cache_path(&manifest, &root))
    }
}

fn portable_cache_path(path: &Path, root: &Path) -> String {
    let Ok(relative) = path.strip_prefix(root) else {
        return path.to_string_lossy().into_owned();
    };
    match relative.to_str() {
        Some(relative) => format!(
            "workspace:{}",
            relative.replace(std::path::MAIN_SEPARATOR, "/")
        ),
        // Two names that differ only in bytes a lossy copy would replace
        // must not share a key.
        None => format!(
            "workspace-bytes:{}",
            hex::encode(relative.as_os_str().as_encoded_bytes())
        ),
    }
}

fn managed_key_matches(key: &std::ffi::OsStr, managed: &str) -> bool {
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
    fn portable_manifest_path_is_relative_to_the_workspace_root() {
        let workspace = tempfile::tempdir().unwrap();
        let member = workspace.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), "{}").unwrap();
        for invocation_dir in [workspace.path(), member.as_path()] {
            let context = NpmScriptContext::new(Some("app"), None, &member, invocation_dir);
            assert_eq!(
                context.portable_manifest_path(workspace.path()).unwrap(),
                "workspace:packages/app/package.json"
            );
        }
    }

    #[test]
    fn portable_manifest_paths_match_for_checkouts_at_other_paths() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for checkout in [first.path(), second.path()] {
            std::fs::write(checkout.join("package.json"), "{}").unwrap();
        }
        let path = |checkout: &Path| {
            NpmScriptContext::new(None, None, checkout, checkout)
                .portable_manifest_path(checkout)
                .unwrap()
        };
        assert_eq!(path(first.path()), path(second.path()));
    }

    #[test]
    fn script_still_gets_the_real_paths() {
        let project = tempfile::tempdir().unwrap();
        let context = NpmScriptContext::new(None, None, project.path(), project.path());
        let mut environment = HashMap::<String, String>::new();
        context.apply(&mut environment, "build", "node build.js");
        assert_eq!(
            environment["npm_package_json"],
            project.path().join("package.json").to_string_lossy()
        );
        assert_eq!(environment["INIT_CWD"], project.path().to_string_lossy());
    }

    #[test]
    fn a_missing_manifest_still_has_a_portable_path() {
        let project = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let context = NpmScriptContext::new(None, None, project.path(), elsewhere.path());
        assert_eq!(
            context.portable_manifest_path(project.path()).unwrap(),
            "workspace:package.json"
        );
    }

    #[test]
    fn a_manifest_outside_the_root_stays_absolute() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("package.json"), "{}").unwrap();
        let context = NpmScriptContext::new(None, None, outside.path(), outside.path());
        assert_eq!(
            context.portable_manifest_path(root.path()).unwrap(),
            outside
                .path()
                .canonicalize()
                .unwrap()
                .join("package.json")
                .to_string_lossy()
        );
    }

    #[cfg(unix)]
    #[test]
    fn names_that_differ_only_in_non_utf8_bytes_stay_distinct() {
        use std::os::unix::ffi::OsStringExt;

        let root = Path::new("/workspace");
        let first = root.join(std::ffi::OsString::from_vec(b"member-\xff".to_vec()));
        let second = root.join(std::ffi::OsString::from_vec(b"member-\xfe".to_vec()));
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        assert_ne!(
            portable_cache_path(&first, root),
            portable_cache_path(&second, root)
        );
    }
}
