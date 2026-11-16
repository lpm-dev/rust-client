//! npm's own `node-gyp`, offered to a lifecycle script that no installed
//! package supplies one to, as npm offers it to the scripts it runs.

use lpm_linker::v2::LifecycleBin;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const NODE: &str = if cfg!(windows) { "node.exe" } else { "node" };
const SHIM: &str = if cfg!(windows) {
    "node-gyp.cmd"
} else {
    "node-gyp"
};

/// The `node-gyp` of the npm installed beside a Node.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BundledNodeGyp {
    /// `bin/node-gyp.js`, which npm names to scripts as `npm_config_node_gyp`.
    pub(super) script: PathBuf,
    /// npm's `node_modules`, which holds `node-gyp` and what it requires.
    pub(super) modules: PathBuf,
    version: String,
}

impl BundledNodeGyp {
    /// The one beside the `node` a script finds first on `path`. An
    /// installer puts npm under the directory that holds `node.exe` on
    /// Windows and under `lib` beside `bin` elsewhere; a `node` reached
    /// through a link is looked beside too.
    ///
    /// `path` is the host's: the caller's entries that hold no package's
    /// commands. A `node` that is, or leads to, a file inside a package
    /// offers nothing, because what sits beside it is that package's to
    /// choose, and the command would run it for a script that was never
    /// approved to run that package's code.
    pub(super) fn beside_node_on(path: &OsStr) -> Option<Self> {
        let node = std::env::split_paths(path)
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(NODE))
            .find(|candidate| candidate.is_file())?;
        let resolved = node.canonicalize().ok()?;
        if in_a_package(&node) || in_a_package(&resolved) {
            return None;
        }
        [node, resolved]
            .iter()
            .filter_map(|node| npm_modules_beside(node))
            .find_map(Self::in_modules)
    }

    fn in_modules(modules: PathBuf) -> Option<Self> {
        let modules = modules.canonicalize().ok()?;
        let package = modules.join("node-gyp");
        let script = package
            .join("bin")
            .join("node-gyp.js")
            .canonicalize()
            .ok()?;
        if !script.is_file() || !script.starts_with(&modules) {
            return None;
        }
        let manifest = lpm_common::read_file_capped(
            &package.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .ok()?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).ok()?;
        // The version goes into the shim as a comment, so it keeps only
        // what a version is written with.
        let version: String = manifest
            .get("version")?
            .as_str()?
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
            .take(64)
            .collect();
        Some(Self {
            script,
            modules,
            version,
        })
    }

    /// Writes the `node-gyp` command into `directory`, which it creates.
    /// The command's text names the version, so a build cached with one
    /// `node-gyp` isn't taken for a build with another.
    pub(super) fn write_command(&self, directory: &Path) -> std::io::Result<LifecycleBin> {
        std::fs::create_dir_all(directory)?;
        let shim = directory.join(SHIM);
        std::fs::write(&shim, self.command_text())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(LifecycleBin {
            name: "node-gyp".to_string(),
            shim,
            target: self.script.clone(),
        })
    }

    fn command_text(&self) -> String {
        let script = self.script.to_string_lossy();
        if cfg!(windows) {
            format!(
                "@ECHO off\r\nREM node-gyp {}, from the npm beside node\r\nnode \"{}\" %*\r\n",
                self.version,
                script.replace('%', "%%"),
            )
        } else {
            format!(
                "#!/bin/sh\n# node-gyp {}, from the npm beside node\nexec node '{}' \"$@\"\n",
                self.version,
                script.replace('\'', r"'\''"),
            )
        }
    }
}

fn in_a_package(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "node_modules")
}

fn npm_modules_beside(node: &Path) -> Option<PathBuf> {
    let directory = node.parent()?;
    let global_modules = if cfg!(windows) {
        directory.join("node_modules")
    } else {
        directory.parent()?.join("lib").join("node_modules")
    };
    Some(global_modules.join("npm").join("node_modules"))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A Node installation under `prefix` whose npm ships `node-gyp` as
    /// `script` says, and the directory to put on `PATH` for it.
    pub(in crate::commands::rebuild) fn node_with_npm(
        prefix: &Path,
        version: &str,
        script: &str,
    ) -> PathBuf {
        let bin = if cfg!(windows) {
            prefix.to_path_buf()
        } else {
            prefix.join("bin")
        };
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join(NODE), "").unwrap();
        let package = npm_modules_beside(&bin.join(NODE))
            .unwrap()
            .join("node-gyp");
        std::fs::create_dir_all(package.join("bin")).unwrap();
        std::fs::write(package.join("bin").join("node-gyp.js"), script).unwrap();
        std::fs::write(
            package.join("package.json"),
            serde_json::json!({ "name": "node-gyp", "version": version }).to_string(),
        )
        .unwrap();
        bin
    }

    #[test]
    fn the_node_gyp_of_the_npm_beside_the_first_node_on_path_is_found() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let without_node = root_path.join("empty");
        std::fs::create_dir(&without_node).unwrap();
        let bin = node_with_npm(&root_path.join("node"), "11.2.0", "");
        let path = std::env::join_paths([&without_node, &bin]).unwrap();

        let found = BundledNodeGyp::beside_node_on(&path).unwrap();

        assert!(found.script.ends_with("node-gyp/bin/node-gyp.js"));
        assert!(found.script.starts_with(&found.modules));
        assert!(found.modules.ends_with("npm/node_modules"));
        assert_eq!(found.version, "11.2.0");
    }

    #[cfg(unix)]
    #[test]
    fn a_node_that_leads_into_a_package_offers_none() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let package_bin = node_with_npm(
            &root_path.join("project/node_modules/claims-node"),
            "11.2.0",
            "",
        );
        let host_bin = root_path.join("host-bin");
        std::fs::create_dir(&host_bin).unwrap();
        std::os::unix::fs::symlink(package_bin.join(NODE), host_bin.join(NODE)).unwrap();

        assert_eq!(BundledNodeGyp::beside_node_on(host_bin.as_os_str()), None);
        assert_eq!(
            BundledNodeGyp::beside_node_on(package_bin.as_os_str()),
            None
        );
    }

    #[test]
    fn a_node_without_npm_or_a_path_without_node_offers_none() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        assert_eq!(BundledNodeGyp::beside_node_on(bin.as_os_str()), None);

        std::fs::write(bin.join(NODE), "").unwrap();
        assert_eq!(BundledNodeGyp::beside_node_on(bin.as_os_str()), None);
    }

    #[test]
    fn the_command_names_the_script_and_only_a_version_from_the_manifest() {
        let root = tempfile::tempdir().unwrap();
        let bin = node_with_npm(root.path(), "11.2.0\nrm -rf /", "");
        let found = BundledNodeGyp::beside_node_on(bin.as_os_str()).unwrap();

        let command = found.write_command(&root.path().join("offered")).unwrap();

        let text = std::fs::read_to_string(&command.shim).unwrap();
        assert!(text.contains("node-gyp 11.2.0rm-rf,"), "{text}");
        assert!(text.contains(&*found.script.to_string_lossy()), "{text}");
        assert_eq!(text.lines().count(), 3, "{text}");
        assert_eq!(command.name, "node-gyp");
        assert_eq!(command.target, found.script);
    }
}
