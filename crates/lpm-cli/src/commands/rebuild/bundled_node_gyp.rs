//! npm's own `node-gyp`, offered to a lifecycle script that no installed
//! package supplies one to, as npm offers it to the scripts it runs.

use lpm_linker::v2::LifecycleBin;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

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
    /// The one beside the `node` a script finds first on `path`, the
    /// host's: see [`lpm_runner::node_gyp::NpmNodeGyp::beside_node_on`].
    pub(super) fn beside_node_on(path: &OsStr) -> Option<Self> {
        let npm = lpm_runner::node_gyp::NpmNodeGyp::beside_node_on(path)?;
        Some(Self {
            script: npm.script,
            modules: npm.modules,
            version: npm.version,
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
        if cfg!(windows) {
            return windows_command_text(&self.version);
        }
        format!(
            "#!/bin/sh\n# node-gyp {}, from the npm beside node\nexec node '{}' \"$@\"\n",
            self.version,
            self.script.to_string_lossy().replace('\'', r"'\''"),
        )
    }
}

/// The `.cmd` file that runs the offered node-gyp. It names the script
/// through the variable a build is given its path in, and so holds no
/// path of its own: cmd.exe reads a batch file in the console's code
/// page, and would get a folder with letters outside it wrong.
fn windows_command_text(version: &str) -> String {
    format!(
        "{}@REM node-gyp {version}, from the npm beside node\r\n{}",
        lpm_common::symlink::WINDOWS_CMD_SHIM_PREAMBLE,
        lpm_common::symlink::windows_node_cmd_shim_body(
            &format!("%{}%", super::script_execution::NPM_CONFIG_NODE_GYP),
            None,
        ),
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn the_windows_command_holds_no_path_for_cmd_to_misread() {
        let text = windows_command_text("11.5.0");

        assert!(text.is_ascii());
        assert!(text.contains("DisableDelayedExpansion"), "{text}");
        assert!(text.contains("\"%npm_config_node_gyp%\" %*"), "{text}");
        assert!(
            text.lines()
                .all(|line| line.starts_with('@') || line.starts_with(':'))
        );
    }

    /// A Node installation under `prefix` whose npm ships `node-gyp` as
    /// `script` says, and the directory to put on `PATH` for it.
    pub(in crate::commands::rebuild) fn node_with_npm(
        prefix: &Path,
        version: &str,
        script: &str,
    ) -> PathBuf {
        let (bin, node, global_modules) = if cfg!(windows) {
            (
                prefix.to_path_buf(),
                "node.exe",
                prefix.join("node_modules"),
            )
        } else {
            (prefix.join("bin"), "node", prefix.join("lib/node_modules"))
        };
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join(node), "").unwrap();
        let package = global_modules.join("npm/node_modules/node-gyp");
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
    fn the_command_names_the_script_and_only_a_version_from_the_manifest() {
        let root = tempfile::tempdir().unwrap();
        let bin = node_with_npm(root.path(), "11.2.0\nrm -rf /", "");
        let found = BundledNodeGyp::beside_node_on(bin.as_os_str()).unwrap();

        let command = found.write_command(&root.path().join("offered")).unwrap();

        let text = std::fs::read_to_string(&command.shim).unwrap();
        assert!(text.contains("node-gyp 11.2.0rm-rf,"), "{text}");
        let script = found.script.to_string_lossy();
        if cfg!(windows) {
            assert!(!text.contains(&*script), "{text}");
            assert!(text.contains("\"%npm_config_node_gyp%\" %*"), "{text}");
        } else {
            assert!(text.contains(&*script), "{text}");
            assert_eq!(text.lines().count(), 3, "{text}");
        }
        assert_eq!(command.name, "node-gyp");
        assert_eq!(command.target, found.script);
    }
}
