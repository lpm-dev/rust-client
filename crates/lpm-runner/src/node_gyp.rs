//! npm's own `node-gyp`, offered to the scripts a project runs.
//!
//! npm puts a `node-gyp` command on the `PATH` of every script it runs,
//! after the project's own commands and before the caller's, so a script
//! that names `node-gyp` builds without the project installing one. The
//! command runs the script `npm_config_node_gyp` names, and otherwise the
//! one npm ships. LPM offers the same, from the npm installed beside
//! `node`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

const NODE: &str = if cfg!(windows) { "node.exe" } else { "node" };

static OFFERED_TO_SCRIPTS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, PartialEq, Eq)]
struct StatStamp {
    len: u64,
    mtime: Option<std::time::SystemTime>,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

impl StatStamp {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            len: meta.len(),
            mtime: meta.modified().ok(),
            #[cfg(unix)]
            ino: meta.ino(),
            #[cfg(unix)]
            ctime: meta.ctime(),
            #[cfg(unix)]
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    link: StatStamp,
    /// Populated when the path is a symlink so edits to the symlink target
    /// invalidate cached metadata even when the symlink entry itself is unchanged.
    target: Option<StatStamp>,
}

impl FileStamp {
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            link: StatStamp::from_metadata(meta),
            target: None,
        }
    }

    fn from_path(path: &Path) -> Option<Self> {
        let lmeta = std::fs::symlink_metadata(path).ok()?;
        let target = if lmeta.file_type().is_symlink() {
            std::fs::metadata(path)
                .ok()
                .as_ref()
                .map(StatStamp::from_metadata)
        } else {
            None
        };
        Some(Self {
            link: StatStamp::from_metadata(&lmeta),
            target,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct NodeGypCacheKey {
    node_path: PathBuf,
    node_stamp: FileStamp,
}

impl NodeGypCacheKey {
    fn from_node(node: &Path, meta: &std::fs::Metadata) -> Self {
        Self {
            node_path: node.to_path_buf(),
            node_stamp: FileStamp::from_metadata(meta),
        }
    }
}

#[derive(Clone)]
struct CachedNodeGypHit {
    value: NpmNodeGyp,
    script_stamp: FileStamp,
    manifest_path: PathBuf,
    manifest_stamp: FileStamp,
}

#[derive(Clone)]
enum CachedNodeGypOutcome {
    Hit(Box<CachedNodeGypHit>),
    Miss {
        checked_paths: Vec<(PathBuf, Option<FileStamp>)>,
    },
}

impl CachedNodeGypOutcome {
    fn is_fresh(&self) -> bool {
        match self {
            Self::Hit(hit) => {
                FileStamp::from_path(&hit.value.script).as_ref() == Some(&hit.script_stamp)
                    && FileStamp::from_path(&hit.manifest_path).as_ref()
                        == Some(&hit.manifest_stamp)
            }
            Self::Miss { checked_paths } => checked_paths
                .iter()
                .all(|(path, expected)| FileStamp::from_path(path) == *expected),
        }
    }

    fn value(&self) -> Option<NpmNodeGyp> {
        match self {
            Self::Hit(hit) => Some(hit.value.clone()),
            Self::Miss { .. } => None,
        }
    }
}

const MAX_NODE_GYP_CACHE_ENTRIES: usize = 8;

type NodeGypCacheEntry = (NodeGypCacheKey, CachedNodeGypOutcome);

fn node_gyp_cache() -> &'static std::sync::Mutex<Vec<NodeGypCacheEntry>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<NodeGypCacheEntry>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn lookup_cached_node_gyp(key: &NodeGypCacheKey) -> Option<Option<NpmNodeGyp>> {
    let outcome = {
        let cache = node_gyp_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache
            .iter()
            .find(|(cached_key, _)| cached_key == key)
            .map(|(_, outcome)| outcome.clone())
    }?;
    if outcome.is_fresh() {
        Some(outcome.value())
    } else {
        None
    }
}

fn store_cached_node_gyp(key: NodeGypCacheKey, outcome: CachedNodeGypOutcome) {
    let mut cache = node_gyp_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, existing)) = cache.iter_mut().find(|(cached_key, _)| cached_key == &key) {
        *existing = outcome;
        return;
    }
    if cache.len() >= MAX_NODE_GYP_CACHE_ENTRIES {
        cache.remove(0);
    }
    cache.push((key, outcome));
}

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
        let meta = std::fs::metadata(&node).ok()?;
        let cache_key = NodeGypCacheKey::from_node(&node, &meta);
        if let Some(cached) = lookup_cached_node_gyp(&cache_key) {
            return cached;
        }
        let resolved = node.canonicalize().ok()?;
        let (result, outcome) = if in_a_package(&node) || in_a_package(&resolved) {
            (
                None,
                CachedNodeGypOutcome::Miss {
                    checked_paths: Vec::new(),
                },
            )
        } else {
            let candidate_dirs: Vec<PathBuf> = [node, resolved]
                .iter()
                .filter_map(|node| npm_modules_beside(node))
                .collect();
            let found = candidate_dirs.iter().cloned().find_map(Self::in_modules);
            match found {
                Some(value) => {
                    let manifest_path = value.modules.join("node-gyp").join("package.json");
                    let outcome = match (
                        FileStamp::from_path(&value.script),
                        FileStamp::from_path(&manifest_path),
                    ) {
                        (Some(script_stamp), Some(manifest_stamp)) => {
                            Some(CachedNodeGypOutcome::Hit(Box::new(CachedNodeGypHit {
                                value: value.clone(),
                                script_stamp,
                                manifest_path,
                                manifest_stamp,
                            })))
                        }
                        _ => None,
                    };
                    if let Some(outcome) = outcome {
                        store_cached_node_gyp(cache_key, outcome);
                    }
                    return Some(value);
                }
                None => {
                    let mut checked_paths = Vec::with_capacity(candidate_dirs.len() * 5);
                    for dir in candidate_dirs {
                        let pkg_dir = dir.join("node-gyp");
                        let bin_dir = pkg_dir.join("bin");
                        for watched in [
                            dir,
                            pkg_dir.clone(),
                            pkg_dir.join("package.json"),
                            bin_dir.clone(),
                            bin_dir.join("node-gyp.js"),
                        ] {
                            let stamp = FileStamp::from_path(&watched);
                            checked_paths.push((watched, stamp));
                        }
                    }
                    (None, CachedNodeGypOutcome::Miss { checked_paths })
                }
            }
        };
        store_cached_node_gyp(cache_key, outcome);
        result
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
        struct KeyIsVersion(bool);
        impl<'de> serde::Deserialize<'de> for KeyIsVersion {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct KeyVisitor;
                impl serde::de::Visitor<'_> for KeyVisitor {
                    type Value = KeyIsVersion;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a JSON object key")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(KeyIsVersion(value == "version"))
                    }

                    fn visit_borrowed_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(KeyIsVersion(value == "version"))
                    }
                }
                deserializer.deserialize_str(KeyVisitor)
            }
        }
        struct NodeGypManifest {
            version: Option<String>,
        }
        impl<'de> serde::Deserialize<'de> for NodeGypManifest {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = NodeGypManifest;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a package.json object")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::MapAccess<'de>,
                    {
                        let mut version = None;
                        while let Some(KeyIsVersion(is_ver)) = map.next_key::<KeyIsVersion>()? {
                            if is_ver {
                                let value: serde_json::Value = map.next_value()?;
                                version = value.as_str().map(str::to_owned);
                            } else {
                                let _: serde::de::IgnoredAny = map.next_value()?;
                            }
                        }
                        Ok(NodeGypManifest { version })
                    }
                }
                deserializer.deserialize_map(Visitor)
            }
        }

        let manifest = lpm_common::read_file_capped(
            &package.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .ok()?;
        let manifest: NodeGypManifest = serde_json::from_slice(&manifest).ok()?;
        // The version goes into a command file as a comment, so it keeps
        // only what a version is written with.
        let version: String = manifest
            .version?
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
    let commands = lpm_common::LpmRoot::from_env()
        .ok()?
        .cache_root()
        .join("node-gyp-bin");
    command_directory_in(host, &commands)
}

struct CachedWrittenCommands {
    version: String,
    directory: PathBuf,
    file_stamps: Vec<(&'static str, FileStamp)>,
}

impl CachedWrittenCommands {
    fn is_fresh(&self, expected_version: &str) -> bool {
        self.version == expected_version
            && self.directory.is_dir()
            && self.file_stamps.iter().all(|(name, expected)| {
                FileStamp::from_path(&self.directory.join(name)).as_ref() == Some(expected)
            })
    }
}

fn command_directory_in(host: &[PathBuf], commands: &Path) -> Option<PathBuf> {
    command_directory_in_with_hook(host, commands, || {})
}

fn command_directory_in_with_hook(
    host: &[PathBuf],
    commands: &Path,
    after_write: impl FnOnce(),
) -> Option<PathBuf> {
    // Re-check `NpmNodeGyp::beside_node_in` (which is stamp-cached) so manifest
    // upgrades or repaired installations are observed immediately, and key
    // cached command directories by `(commands_root, script)` with per-file stamps
    // so A -> B -> A version changes and deleted shims always rewrite cleanly.
    let npm = NpmNodeGyp::beside_node_in(host.iter().cloned())?;
    type WrittenCommandKey = (PathBuf, PathBuf);
    static WRITTEN: OnceLock<Mutex<HashMap<WrittenCommandKey, CachedWrittenCommands>>> =
        OnceLock::new();
    let key = (commands.to_path_buf(), npm.script.clone());
    let mut written = WRITTEN
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = written.get(&key)
        && entry.is_fresh(&npm.version)
    {
        return Some(entry.directory.clone());
    }
    let directory = npm
        .write_commands(commands)
        .inspect_err(|error| tracing::debug!("npm's node-gyp isn't offered: {error}"))
        .ok()?;
    after_write();
    let file_stamps: Option<Vec<(&'static str, FileStamp)>> = npm
        .command_files()
        .into_iter()
        .map(|(name, expected)| {
            Some((
                name,
                verified_written_shim_stamp(&directory.join(name), expected.as_bytes())?,
            ))
        })
        .collect();
    if let Some(file_stamps) = file_stamps {
        if written.len() >= MAX_NODE_GYP_CACHE_ENTRIES && !written.contains_key(&key) {
            written.clear();
        }
        written.insert(
            key,
            CachedWrittenCommands {
                version: npm.version.clone(),
                directory: directory.clone(),
                file_stamps,
            },
        );
    }
    Some(directory)
}

/// Bind a shim file's cached stamp directly to the bytes we just wrote, so a
/// concurrent writer in another process cannot have its stamps cached under
/// this process's version.
fn verified_written_shim_stamp(path: &Path, expected: &[u8]) -> Option<FileStamp> {
    use std::io::Read as _;

    let mut file = lpm_common::open_nofollow(path).ok()?;
    let pre_meta = file.metadata().ok()?;
    if !pre_meta.is_file() || pre_meta.len() != expected.len() as u64 {
        return None;
    }
    let pre = FileStamp::from_metadata(&pre_meta);
    let mut bytes = Vec::with_capacity(expected.len());
    file.by_ref()
        .take(expected.len().saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes != expected {
        return None;
    }
    let post_fd = FileStamp::from_metadata(&file.metadata().ok()?);
    let post_path = FileStamp::from_path(path)?;
    (post_fd == pre && post_path == pre).then_some(pre)
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

    #[test]
    fn node_gyp_manifest_rejects_array_and_accepts_duplicate_version_last_wins() {
        let root = tempfile::tempdir().unwrap();
        let modules = root.path().join("node_modules");
        let bin_dir = modules.join("node-gyp").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("node-gyp.js"), "// stub").unwrap();

        std::fs::write(
            modules.join("node-gyp").join("package.json"),
            r#"["9.0.0"]"#,
        )
        .unwrap();
        assert!(NpmNodeGyp::in_modules(modules.clone()).is_none());

        std::fs::write(
            modules.join("node-gyp").join("package.json"),
            r#"{"version":"8.0.0","version":"10.1.0"}"#,
        )
        .unwrap();
        let resolved = NpmNodeGyp::in_modules(modules).expect("duplicate version should parse");
        assert_eq!(resolved.version, "10.1.0");
    }

    #[test]
    fn node_gyp_cache_invalidates_when_sibling_manifest_changes_and_evicts_oldest_entries() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let bin = node_with_npm(&root_path.join("node-primary"), "11.2.0", "// v1");
        let first = NpmNodeGyp::beside_node_on(bin.as_os_str()).expect("first lookup should hit");
        assert_eq!(first.version, "11.2.0");

        let cached = NpmNodeGyp::beside_node_on(bin.as_os_str()).expect("cached lookup should hit");
        assert_eq!(cached, first);

        // Mutate sibling node-gyp/package.json without touching the node binary.
        let manifest_path = first.modules.join("node-gyp").join("package.json");
        std::fs::write(
            &manifest_path,
            r#"{"name":"node-gyp","version":"12.3.4-beta.1"}"#,
        )
        .unwrap();
        let updated = NpmNodeGyp::beside_node_on(bin.as_os_str())
            .expect("lookup after sibling manifest edit should observe new version");
        assert_eq!(updated.version, "12.3.4-beta.1");

        // A miss beside an existing node binary must invalidate once npm's node-gyp is installed
        // WITHOUT modifying bin/node (so the cache key stays identical and miss-invalidation runs).
        let miss_prefix = root_path.join("node-miss-then-hit");
        let miss_bin = if cfg!(windows) {
            miss_prefix
        } else {
            miss_prefix.join("bin")
        };
        std::fs::create_dir_all(&miss_bin).unwrap();
        std::fs::write(miss_bin.join(NODE), "").unwrap();
        assert!(NpmNodeGyp::beside_node_on(miss_bin.as_os_str()).is_none());

        // Pre-create an incomplete `node-gyp` directory (missing package.json + script),
        // cache a second miss, then repair it in place inside the existing `node-gyp` dir.
        let miss_pkg = npm_modules_beside(&miss_bin.join(NODE))
            .unwrap()
            .join("node-gyp");
        std::fs::create_dir_all(miss_pkg.join("bin")).unwrap();
        assert!(NpmNodeGyp::beside_node_on(miss_bin.as_os_str()).is_none());

        std::fs::write(miss_pkg.join("bin").join("node-gyp.js"), "// repaired").unwrap();
        std::fs::write(
            miss_pkg.join("package.json"),
            r#"{"name":"node-gyp","version":"11.9.0"}"#,
        )
        .unwrap();
        let recovered = NpmNodeGyp::beside_node_on(miss_bin.as_os_str())
            .expect("miss entry must invalidate when files appear inside an existing node-gyp dir");
        assert_eq!(recovered.version, "11.9.0");

        // Exercise `command_directory_in` with the same PATH: once after a miss is
        // repaired in place, and again after the sibling manifest updates to a newer version.
        let cmd_prefix = root_path.join("node-cmd-dir");
        let cmd_bin = if cfg!(windows) {
            cmd_prefix
        } else {
            cmd_prefix.join("bin")
        };
        std::fs::create_dir_all(&cmd_bin).unwrap();
        std::fs::write(cmd_bin.join(NODE), "").unwrap();
        let cmd_pkg = npm_modules_beside(&cmd_bin.join(NODE))
            .unwrap()
            .join("node-gyp");
        std::fs::create_dir_all(cmd_pkg.join("bin")).unwrap();
        let host_dirs = vec![cmd_bin];
        let commands_root = root_path.join("node-gyp-bin");
        assert!(
            command_directory_in(&host_dirs, &commands_root).is_none(),
            "incomplete node-gyp installation must return None"
        );
        std::fs::write(cmd_pkg.join("bin").join("node-gyp.js"), "// v1").unwrap();
        std::fs::write(
            cmd_pkg.join("package.json"),
            r#"{"name":"node-gyp","version":"11.4.0"}"#,
        )
        .unwrap();
        let first_cmd_dir = command_directory_in(&host_dirs, &commands_root)
            .expect("command_directory must observe in-place repair on the same PATH");
        let shim_name = if cfg!(windows) {
            "node-gyp.cmd"
        } else {
            "node-gyp"
        };
        let first_shim = std::fs::read_to_string(first_cmd_dir.join(shim_name)).unwrap();
        assert!(
            first_shim.contains("11.4.0"),
            "initial shim should carry 11.4.0, got: {first_shim}"
        );
        std::fs::write(
            cmd_pkg.join("package.json"),
            r#"{"name":"node-gyp","version":"12.0.0-upgrade.1"}"#,
        )
        .unwrap();
        let second_cmd_dir = command_directory_in(&host_dirs, &commands_root)
            .expect("command_directory must observe manifest upgrade on the same PATH");
        assert_eq!(
            first_cmd_dir, second_cmd_dir,
            "same script path reuses its command directory"
        );
        let second_shim = std::fs::read_to_string(second_cmd_dir.join(shim_name)).unwrap();
        assert!(
            second_shim.contains("12.0.0-upgrade.1"),
            "upgraded manifest version must rewrite the shim in place, got: {second_shim}"
        );

        // Downgrading back to the earlier version (A -> B -> A) must rewrite the shim
        // rather than hitting a stale `(root, script, A)` entry while B is on disk.
        std::fs::write(
            cmd_pkg.join("package.json"),
            r#"{"name":"node-gyp","version":"11.4.0"}"#,
        )
        .unwrap();
        let reverted_cmd_dir = command_directory_in(&host_dirs, &commands_root)
            .expect("command_directory must observe A -> B -> A version revert");
        let reverted_shim = std::fs::read_to_string(reverted_cmd_dir.join(shim_name)).unwrap();
        assert!(
            reverted_shim.contains("11.4.0"),
            "reverting to earlier version must rewrite the shim back to 11.4.0, got: {reverted_shim}"
        );

        // Deleting a generated shim file must cause command_directory_in to recreate it.
        std::fs::remove_file(reverted_cmd_dir.join(shim_name)).unwrap();
        let repaired_cmd_dir = command_directory_in(&host_dirs, &commands_root)
            .expect("command_directory must recreate deleted shim files");
        assert!(
            repaired_cmd_dir.join(shim_name).is_file(),
            "deleted shim file must be recreated"
        );

        // Symlinked manifest target updates must invalidate the cached metadata stamp.
        #[cfg(unix)]
        {
            let sym_prefix = root_path.join("node-symlink-manifest");
            let sym_bin = sym_prefix.join("bin");
            std::fs::create_dir_all(&sym_bin).unwrap();
            std::fs::write(sym_bin.join(NODE), "").unwrap();
            let sym_pkg = npm_modules_beside(&sym_bin.join(NODE))
                .unwrap()
                .join("node-gyp");
            std::fs::create_dir_all(sym_pkg.join("bin")).unwrap();
            std::fs::write(sym_pkg.join("bin").join("node-gyp.js"), "// symlinked").unwrap();
            let real_manifest = root_path.join("real-node-gyp-package.json");
            std::fs::write(&real_manifest, r#"{"name":"node-gyp","version":"10.1.0"}"#).unwrap();
            std::os::unix::fs::symlink(&real_manifest, sym_pkg.join("package.json")).unwrap();
            let first = NpmNodeGyp::beside_node_on(sym_bin.as_os_str()).expect("initial hit");
            assert_eq!(first.version, "10.1.0");

            std::fs::write(
                &real_manifest,
                r#"{"name":"node-gyp","version":"10.2.0-updated"}"#,
            )
            .unwrap();
            let second = NpmNodeGyp::beside_node_on(sym_bin.as_os_str())
                .expect("symlink target edit must invalidate cache");
            assert_eq!(second.version, "10.2.0-updated");
        }

        // Populate more distinct installations than MAX_NODE_GYP_CACHE_ENTRIES and verify bound.
        for idx in 0..(MAX_NODE_GYP_CACHE_ENTRIES + 4) {
            let extra_bin =
                node_with_npm(&root_path.join(format!("node-extra-{idx}")), "11.0.0", "");
            assert!(NpmNodeGyp::beside_node_on(extra_bin.as_os_str()).is_some());
        }
        let cache_len = node_gyp_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        assert!(
            cache_len <= MAX_NODE_GYP_CACHE_ENTRIES,
            "cache size {cache_len} exceeded bound {MAX_NODE_GYP_CACHE_ENTRIES}"
        );
    }

    #[test]
    fn concurrent_command_directory_writes_keep_version_and_shim_stamps_consistent() {
        let root = tempfile::tempdir().unwrap();
        let prefix = root.path().join("node-race");
        let commands = root.path().join("commands");
        let bin = node_with_npm(&prefix, "11.0.0", "console.log('ok');");
        let manifest = NpmNodeGyp::beside_node_on(bin.as_os_str())
            .expect("initial node-gyp")
            .modules
            .join("node-gyp")
            .join("package.json");

        let (writer_a_paused_tx, writer_a_paused_rx) = std::sync::mpsc::sync_channel(1);
        let bin_b = bin.clone();
        let commands_b = commands.clone();
        let manifest_b = manifest.clone();
        let thread_b = std::thread::spawn(move || {
            writer_a_paused_rx.recv().unwrap();
            std::fs::write(
                &manifest_b,
                r#"{"name":"node-gyp","version":"12.0.0-racer"}"#,
            )
            .unwrap();
            command_directory_in(&[bin_b], &commands_b).expect("writer B command dir")
        });

        let dir_a =
            command_directory_in_with_hook(std::slice::from_ref(&bin), &commands, move || {
                writer_a_paused_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
            })
            .expect("writer A command dir");
        let _dir_b = thread_b.join().unwrap();

        // Restore version 11.0.0 and request its command directory again.
        // If writer A captured writer B's 12.0.0 shim stamps under version 11.0.0,
        // this call falsely hits the cache and leaves 12.0.0 shims on disk.
        std::fs::write(&manifest, r#"{"name":"node-gyp","version":"11.0.0"}"#).unwrap();
        let dir_restored = command_directory_in(&[bin], &commands).expect("restored 11.0.0 dir");
        assert_eq!(dir_restored, dir_a);
        let shim_name = if cfg!(windows) {
            "node-gyp.cmd"
        } else {
            "node-gyp"
        };
        let shim_text = std::fs::read_to_string(dir_restored.join(shim_name)).unwrap();
        assert!(
            !shim_text.contains("12.0.0-racer"),
            "restored 11.0.0 lookup must not serve cached 12.0.0 shims:\n{shim_text}"
        );
    }

    #[test]
    fn external_process_overwrite_during_write_cannot_poison_version_shim_stamps() {
        let root = tempfile::tempdir().unwrap();
        let prefix = root.path().join("node-ext-race");
        let commands = root.path().join("commands");
        let bin = node_with_npm(&prefix, "11.0.0", "console.log('ok');");
        let npm_initial = NpmNodeGyp::beside_node_on(bin.as_os_str()).expect("initial node-gyp");
        let shim_name = if cfg!(windows) {
            "node-gyp.cmd"
        } else {
            "node-gyp"
        };
        let other_process_npm = NpmNodeGyp {
            script: npm_initial.script,
            modules: npm_initial.modules,
            version: "12.0.0-external".to_string(),
        };
        let commands_for_hook = commands.clone();

        // Simulate an external process rewriting the shared commands dir right after
        // process A writes its shims and before process A captures stamps.
        let dir_a =
            command_directory_in_with_hook(std::slice::from_ref(&bin), &commands, move || {
                other_process_npm
                    .write_commands(&commands_for_hook)
                    .expect("external writer");
            })
            .expect("writer A command dir");

        // Next request for 11.0.0 must NOT treat the external 12.0.0 shim on disk as
        // a valid cached 11.0.0 shim.
        let dir_next = command_directory_in(&[bin], &commands).expect("second 11.0.0 lookup");
        assert_eq!(dir_next, dir_a);
        let shim_text = std::fs::read_to_string(dir_next.join(shim_name)).unwrap();
        assert!(
            shim_text.contains("11.0.0") && !shim_text.contains("12.0.0-external"),
            "cached stamps must not accept an externally overwritten shim:\n{shim_text}"
        );
    }
}
