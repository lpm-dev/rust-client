//! npm's own `node-gyp`, offered to the scripts a project runs.
//!
//! npm puts a `node-gyp` command on the `PATH` of every script it runs,
//! after the project's own commands and before the caller's, so a script
//! that names `node-gyp` builds without the project installing one. The
//! command runs the script `npm_config_node_gyp` names, and otherwise the
//! one npm ships. LPM offers the same, from the npm installed beside
//! `node`.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

const NODE: &str = if cfg!(windows) { "node.exe" } else { "node" };

static OFFERED_TO_SCRIPTS: AtomicBool = AtomicBool::new(false);

/// Has every `PATH` this process builds for a script hold npm's `node-gyp`
/// where npm is installed beside `node`. The commands are files in the LPM
/// home, so only the command-line program asks for them: a test or another
/// program that builds a `PATH` writes nothing.
pub fn offer_to_scripts() {
    OFFERED_TO_SCRIPTS.store(true, Ordering::Relaxed);
}

/// The `node-gyp` of the npm installed beside a Node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmNodeGyp {
    /// `bin/node-gyp.js`, which npm names to scripts as `npm_config_node_gyp`.
    pub script: PathBuf,
    /// npm's `node_modules`, which holds `node-gyp` and what it requires.
    pub modules: PathBuf,
    /// Its version, kept to the characters a version is written with.
    pub version: String,
}

impl NpmNodeGyp {
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
    pub fn beside_node_on(path: &OsStr) -> Option<Self> {
        Self::beside_node_in(std::env::split_paths(path))
    }

    fn beside_node_in(directories: impl Iterator<Item = PathBuf>) -> Option<Self> {
        let node = directories
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
        // Node can't start a script named with the prefix a resolved path
        // carries on Windows.
        let script = lpm_common::symlink::windows_plain_path(&script);
        let manifest = lpm_common::read_file_capped(
            &package.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .ok()?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).ok()?;
        // The version goes into a command file as a comment, so it keeps
        // only what a version is written with.
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

    /// Writes the commands that run this `node-gyp` into a directory of
    /// their own under `parent`, named after the script so two Nodes'
    /// commands never replace one another, and returns that directory.
    /// What is already there and reads the same is left alone.
    ///
    /// The directory goes on the `PATH` of every script, ahead of the
    /// caller's own entries, so it is the user's alone and holds these
    /// commands and nothing else: anything more would answer to its name
    /// in every project.
    fn write_commands(&self, parent: &Path) -> std::io::Result<PathBuf> {
        let name = Sha256::digest(self.script.as_os_str().as_encoded_bytes());
        let directory = parent.join(&hex::encode(name)[..16]);
        private_directory(parent)?;
        private_directory(&directory)?;
        let files = self.command_files();
        for (file, contents) in &files {
            let path = directory.join(file);
            if is_private_file_holding(&path, contents) {
                continue;
            }
            lpm_common::write_file_atomic_with_options(
                &path,
                contents,
                lpm_common::AtomicWriteOptions::new()
                    .owner_only()
                    .unix_mode(COMMAND_MODE),
            )?;
        }
        for entry in std::fs::read_dir(&directory)? {
            let found = entry?.file_name();
            if !files.iter().any(|(file, _)| found == *file) {
                return Err(std::io::Error::other(format!(
                    "{} holds {}, which LPM didn't put there",
                    directory.display(),
                    found.to_string_lossy()
                )));
            }
        }
        Ok(directory)
    }

    fn command_files(&self) -> Vec<(&'static str, String)> {
        if cfg!(windows) {
            vec![
                ("node-gyp.cmd", windows_command_text(&self.version)),
                (TRAMPOLINE, trampoline_text(&self.script)),
                (
                    "node-gyp",
                    shell_command_text(
                        &self.version,
                        &format!("\"$(dirname \"$0\")/{TRAMPOLINE}\""),
                    ),
                ),
            ]
        } else {
            let script = self.script.to_string_lossy().replace('\'', r"'\''");
            vec![(
                "node-gyp",
                shell_command_text(&self.version, &format!("'{script}'")),
            )]
        }
    }
}

/// A command's permissions where the system has modes: its owner's alone.
const COMMAND_MODE: u32 = 0o700;

/// Makes `directory` one only its owner reaches, creating it if needed,
/// and refuses a link in its place. Where the system has modes, a
/// directory with exactly these is the user's own: nobody else could have
/// been let in to read it. One with other modes is given these, which
/// only its owner may do. Windows hands a new directory the access of the
/// LPM home above it.
fn private_directory(directory: &Path) -> std::io::Result<()> {
    let found = match std::fs::symlink_metadata(directory) {
        Ok(found) => found,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, COMMAND_MODE);
            builder.create(directory)?;
            std::fs::symlink_metadata(directory)?
        }
        Err(error) => return Err(error),
    };
    if !found.is_dir() || lpm_common::is_symlink_or_junction(&found) {
        return Err(std::io::Error::other(format!(
            "{} isn't a directory of its own",
            directory.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if found.permissions().mode() & 0o7777 != COMMAND_MODE {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(COMMAND_MODE))?;
        }
    }
    Ok(())
}

/// Whether `path` is a file of its own that holds `contents` and, where
/// the system has modes, is its owner's alone.
fn is_private_file_holding(path: &Path, contents: &str) -> bool {
    let Ok(found) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !found.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if found.permissions().mode() & 0o7777 != COMMAND_MODE {
            return false;
        }
    }
    std::fs::read(path).is_ok_and(|current| current == contents.as_bytes())
}

/// The file beside the Windows commands that loads npm's script. They name
/// it and not the script: cmd.exe reads a batch file in the console's code
/// page and would get a folder with letters outside it wrong, where Node
/// reads this file as UTF-8. Its extension keeps it CommonJS under an LPM
/// home that sits below a `package.json` of another type.
const TRAMPOLINE: &str = "node-gyp.cjs";

fn trampoline_text(script: &Path) -> String {
    format!(
        "require({})\n",
        serde_json::Value::String(script.to_string_lossy().into_owned())
    )
}

/// `own` is npm's script as the shell is to read it.
fn shell_command_text(version: &str, own: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # node-gyp as npm offers it to the scripts it runs: the one\n\
         # npm_config_node_gyp names, else npm's own, {version}.\n\
         if [ -n \"$npm_config_node_gyp\" ]; then\n  exec node \"$npm_config_node_gyp\" \"$@\"\nfi\n\
         if [ -n \"$NPM_CONFIG_NODE_GYP\" ]; then\n  exec node \"$NPM_CONFIG_NODE_GYP\" \"$@\"\nfi\n\
         exec node {own} \"$@\"\n"
    )
}

/// Each of the two endings runs Node as the batch file's last act, so the
/// first never falls through to the label.
fn windows_command_text(version: &str) -> String {
    format!(
        "{}@REM node-gyp as npm offers it: the one npm_config_node_gyp names, else npm's own, {version}\r\n\
         @IF DEFINED npm_config_node_gyp GOTO named\r\n\
         {}:named\r\n{}",
        lpm_common::symlink::WINDOWS_CMD_SHIM_PREAMBLE,
        lpm_common::symlink::windows_node_cmd_shim_body(&format!("%dp0%{TRAMPOLINE}"), None),
        lpm_common::symlink::windows_node_cmd_shim_body("%npm_config_node_gyp%", None),
    )
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

/// The directory that goes on a script's `PATH` after the project's own
/// commands: it holds the `node-gyp` of the npm beside the `node` found
/// first in `host`, the directories that follow on that `PATH`. `None`
/// where nothing asked for the offer, no such npm is installed, or the
/// commands can't be written, which leaves the script the `PATH` it had.
pub(crate) fn command_directory(host: &[PathBuf]) -> Option<PathBuf> {
    if !OFFERED_TO_SCRIPTS.load(Ordering::Relaxed) {
        return None;
    }
    // One command runs many scripts with the same host directories.
    static FOUND: OnceLock<Mutex<HashMap<OsString, Option<PathBuf>>>> = OnceLock::new();
    let key = std::env::join_paths(host).ok()?;
    let mut found = FOUND
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(directory) = found.get(&key) {
        return directory.clone();
    }
    let directory = NpmNodeGyp::beside_node_in(host.iter().cloned()).and_then(|npm| {
        let commands = lpm_common::LpmRoot::from_env()
            .ok()?
            .cache_root()
            .join("node-gyp-bin");
        npm.write_commands(&commands)
            .inspect_err(|error| tracing::debug!("npm's node-gyp isn't offered: {error}"))
            .ok()
    });
    found.insert(key, directory.clone());
    directory
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A Node installation under `prefix` whose npm ships `node-gyp` as
    /// `script` says, and the directory to put on `PATH` for it.
    pub(crate) fn node_with_npm(prefix: &Path, version: &str, script: &str) -> PathBuf {
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

        let found = NpmNodeGyp::beside_node_on(&path).unwrap();

        assert!(found.script.ends_with("node-gyp/bin/node-gyp.js"));
        assert!(
            found
                .script
                .starts_with(lpm_common::symlink::windows_plain_path(&found.modules))
        );
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

        assert_eq!(NpmNodeGyp::beside_node_on(host_bin.as_os_str()), None);
        assert_eq!(NpmNodeGyp::beside_node_on(package_bin.as_os_str()), None);
    }

    #[test]
    fn a_node_without_npm_or_a_path_without_node_offers_none() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        assert_eq!(NpmNodeGyp::beside_node_on(bin.as_os_str()), None);

        std::fs::write(bin.join(NODE), "").unwrap();
        assert_eq!(NpmNodeGyp::beside_node_on(bin.as_os_str()), None);
    }

    #[test]
    fn the_commands_go_into_a_directory_of_the_script_s_own_and_are_written_once() {
        let root = tempfile::tempdir().unwrap();
        let first = NpmNodeGyp::beside_node_on(
            node_with_npm(&root.path().join("one"), "11.2.0", "").as_os_str(),
        )
        .unwrap();
        let second = NpmNodeGyp::beside_node_on(
            node_with_npm(&root.path().join("two"), "11.2.0", "").as_os_str(),
        )
        .unwrap();
        let parent = root.path().join("commands");

        let directory = first.write_commands(&parent).unwrap();
        assert_eq!(directory.parent(), Some(parent.as_path()));
        assert_ne!(second.write_commands(&parent).unwrap(), directory);
        let command = directory.join(if cfg!(windows) {
            "node-gyp.cmd"
        } else {
            "node-gyp"
        });
        let written = std::fs::metadata(&command).unwrap().modified().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&parent, &directory, &command] {
                let mode = std::fs::metadata(path).unwrap().permissions().mode();
                assert_eq!(mode & 0o7777, 0o700, "{}", path.display());
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(first.write_commands(&parent).unwrap(), directory);
        assert_eq!(
            std::fs::metadata(&command).unwrap().modified().unwrap(),
            written,
            "a command that already reads the same isn't written again"
        );

        std::fs::write(&command, "something else").unwrap();
        first.write_commands(&parent).unwrap();
        assert_eq!(
            std::fs::read_to_string(&command).unwrap(),
            first.command_files()[0].1
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_others_could_change_or_that_holds_more_is_made_private_or_refused() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let npm = NpmNodeGyp::beside_node_on(
            node_with_npm(&root.path().join("node"), "11.2.0", "").as_os_str(),
        )
        .unwrap();
        let parent = root.path().join("commands");
        let directory = npm.write_commands(&parent).unwrap();
        let command = directory.join("node-gyp");
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;

        for path in [&parent, &directory, &command] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        npm.write_commands(&parent).unwrap();
        for path in [&parent, &directory, &command] {
            assert_eq!(mode(path), 0o700, "{}", path.display());
        }

        let elsewhere = root.path().join("elsewhere");
        std::fs::write(&elsewhere, npm.command_files()[0].1.as_bytes()).unwrap();
        std::fs::remove_file(&command).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &command).unwrap();
        npm.write_commands(&parent).unwrap();
        assert!(
            std::fs::symlink_metadata(&command).unwrap().is_file(),
            "a link that reads the same is replaced by a file of the directory's own"
        );

        std::fs::write(directory.join("node"), "").unwrap();
        let refused = npm.write_commands(&parent).unwrap_err();
        assert!(refused.to_string().contains("node"), "{refused}");
        std::fs::remove_file(directory.join("node")).unwrap();

        std::fs::remove_dir_all(&directory).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &directory).unwrap();
        assert!(npm.write_commands(&parent).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_command_runs_the_script_the_caller_names_and_otherwise_npm_s_own() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        // A path a shell would read as more than a path if it weren't quoted.
        let prefix = root_path.join("it's $HOME `here`");
        let npm =
            NpmNodeGyp::beside_node_on(node_with_npm(&prefix, "11.2.0", "").as_os_str()).unwrap();
        let directory = npm.write_commands(&root_path.join("commands")).unwrap();
        let fake_node = root_path.join("fake-node");
        std::fs::create_dir(&fake_node).unwrap();
        std::fs::write(fake_node.join("node"), "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                fake_node.join("node"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let run = |named: &[(&str, &str)]| {
            let output = std::process::Command::new(directory.join("node-gyp"))
                .args(["rebuild", "two words"])
                .env_remove("npm_config_node_gyp")
                .env_remove("NPM_CONFIG_NODE_GYP")
                .envs(named.iter().copied())
                .env(
                    "PATH",
                    std::env::join_paths([&fake_node, Path::new("/bin")]).unwrap(),
                )
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stdout).unwrap()
        };

        assert_eq!(
            run(&[]),
            format!("{}\nrebuild\ntwo words\n", npm.script.display())
        );
        assert_eq!(
            run(&[("npm_config_node_gyp", "/named/node-gyp.js")]),
            "/named/node-gyp.js\nrebuild\ntwo words\n"
        );
        assert_eq!(
            run(&[("NPM_CONFIG_NODE_GYP", "/NAMED/node-gyp.js")]),
            "/NAMED/node-gyp.js\nrebuild\ntwo words\n"
        );
    }

    #[test]
    fn the_windows_command_holds_no_path_for_cmd_to_misread() {
        let text = windows_command_text("11.5.0");

        assert!(text.is_ascii());
        assert!(text.contains("DisableDelayedExpansion"), "{text}");
        let named = text.find(":named\r\n").unwrap();
        let own = text.find("\"%dp0%node-gyp.cjs\" %*\r\n").unwrap();
        let caller = text.find("\"%npm_config_node_gyp%\" %*\r\n").unwrap();
        assert!(
            text.find("@IF DEFINED npm_config_node_gyp GOTO named\r\n")
                .unwrap()
                < own
                && own < named
                && named < caller,
            "{text}"
        );
        assert!(
            text.lines()
                .all(|line| line.starts_with('@') || line.starts_with(':')),
            "{text}"
        );
        assert_eq!(
            trampoline_text(Path::new(r"C:\Users\Zoë\node-gyp.js")),
            "require(\"C:\\\\Users\\\\Zoë\\\\node-gyp.js\")\n"
        );
    }

    #[test]
    fn no_directory_is_offered_or_written_until_the_program_asks_for_it() {
        let root = tempfile::tempdir().unwrap();
        let bin = node_with_npm(&root.path().join("node"), "11.2.0", "");

        assert!(!OFFERED_TO_SCRIPTS.load(Ordering::Relaxed));
        assert_eq!(command_directory(&[bin]), None);
    }
}
