//! Identify the Node executable that a script `PATH` selects.
//!
//! An earlier `node --version` result may stand in for a new probe only when
//! the selected executable is a real Node binary with an unchanged
//! fingerprint. Launchers such as shell scripts and version-manager shims can
//! print a different version without changing on disk, so they are always
//! probed.
//!
//! The fingerprint also covers the version files and settings that Node
//! version managers read. A native shim that passes the binary checks still
//! changes its fingerprint when those inputs select a different version.

use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::path::{Path, PathBuf};

const FINGERPRINT_DOMAIN: &[u8] = b"lpm-node-runtime-fingerprint-v2\0script-path";
/// Node binaries are tens of megabytes; version-manager shims are far smaller.
const MIN_NODE_BINARY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SYMLINK_HOPS: usize = 40;
const MAX_SELECTOR_FILE_BYTES: u64 = 64 * 1024;
const MANAGER_VARIABLE_PREFIXES: [&str; 6] =
    ["ASDF_", "MISE_", "RTX_", "NODENV_", "VOLTA_", "PROTO_"];
const DEFAULT_TOOL_VERSIONS_FILE: &str = ".tool-versions";

/// Fingerprinted Node executable selected by a script's cwd and `PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScriptNodeIdentity {
    pub(crate) canonical_executable: PathBuf,
    pub(crate) fingerprint: String,
    /// Whether the executable is a real Node binary rather than a launcher.
    pub(crate) node_binary: bool,
}

/// Identify the Node executable at `executable`. Runtimes under
/// `managed_node_root` are identified by the executable alone.
pub(crate) fn script_node_identity(
    executable: &Path,
    cwd: &Path,
    path: &OsStr,
    managed_node_root: Option<&Path>,
) -> Option<ScriptNodeIdentity> {
    identity_with_environment(
        executable,
        cwd,
        path,
        managed_node_root,
        &SelectorEnvironment::from_process(),
    )
}

fn identity_with_environment(
    executable: &Path,
    cwd: &Path,
    path: &OsStr,
    managed_node_root: Option<&Path>,
    environment: &SelectorEnvironment,
) -> Option<ScriptNodeIdentity> {
    let canonical_executable = executable.canonicalize().ok()?;
    let metadata = canonical_executable.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let node_binary = is_node_binary(&canonical_executable, &metadata);

    let mut hasher = FieldHasher::new(FINGERPRINT_DOMAIN);
    hash_symlink_chain(&mut hasher, executable);
    hasher.os(canonical_executable.as_os_str());
    crate::effective::update_with_file_metadata(&mut hasher.0, &metadata);
    if managed_node_root.is_some_and(|root| canonical_executable.starts_with(root)) {
        // Each managed runtime is installed under its own version, so no
        // project input can change the version it reports.
        hasher.bytes(b"managed");
    } else {
        if !node_binary {
            // A launcher can resolve helpers through the script PATH and read
            // files relative to the working directory.
            hasher.bytes(b"launcher");
            hasher.os(cwd.canonicalize().ok()?.as_os_str());
            hasher.os(path);
        }
        hash_version_selectors(&mut hasher, cwd, environment);
    }

    Some(ScriptNodeIdentity {
        canonical_executable,
        fingerprint: hasher.finish(),
        node_binary,
    })
}

fn is_node_binary(canonical: &Path, metadata: &Metadata) -> bool {
    #[cfg(debug_assertions)]
    if let Some(test_binary) = std::env::var_os("LPM_TEST_NODE_BINARY") {
        return Path::new(&test_binary)
            .canonicalize()
            .is_ok_and(|test_binary| test_binary == canonical);
    }

    let named_node = canonical.file_name().is_some_and(|name| {
        #[cfg(windows)]
        {
            name.eq_ignore_ascii_case("node.exe")
        }
        #[cfg(not(windows))]
        {
            name == "node"
        }
    });
    if !named_node || metadata.len() < MIN_NODE_BINARY_BYTES {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // Version managers hard-link one shim binary under several tool names.
        if metadata.nlink() != 1 {
            return false;
        }
    }
    #[cfg(windows)]
    if canonical.with_extension("shim").exists() {
        // Scoop shims read their target from this sidecar.
        return false;
    }
    has_native_executable_header(canonical)
}

fn has_native_executable_header(path: &Path) -> bool {
    use std::io::Read;

    let mut header = [0_u8; 4];
    if std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_err()
    {
        return false;
    }
    matches!(
        header,
        [0x7f, b'E', b'L', b'F']
            | [0xfe, 0xed, 0xfa, 0xce | 0xcf]
            | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            | [b'M', b'Z', _, _]
    )
}

/// Hash each link target from the `PATH` entry to the executable, since a
/// manager can switch versions by retargeting a link to the same launcher.
fn hash_symlink_chain(hasher: &mut FieldHasher, executable: &Path) {
    let mut link = executable.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        let Ok(target) = std::fs::read_link(&link) else {
            return;
        };
        hasher.os(target.as_os_str());
        link = match link.parent() {
            Some(parent) => parent.join(&target),
            None => target,
        };
    }
}

struct SelectorEnvironment {
    home: Option<PathBuf>,
    config_home: Option<PathBuf>,
    /// Version-manager variables, sorted by name.
    variables: Vec<(OsString, OsString)>,
}

impl SelectorEnvironment {
    fn from_process() -> Self {
        let mut variables: Vec<_> = std::env::vars_os()
            .filter(|(name, _)| is_manager_variable(name))
            .collect();
        variables.sort();
        Self {
            home: dirs::home_dir(),
            config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            variables,
        }
    }

    fn variable(&self, name: &str) -> Option<&OsStr> {
        self.variables
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_os_str())
    }

    fn directory(&self, variable: &str, home_relative: &str) -> Option<PathBuf> {
        self.variable(variable)
            .map(PathBuf::from)
            .or_else(|| self.home.as_ref().map(|home| home.join(home_relative)))
    }
}

fn is_manager_variable(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        let name = name.to_ascii_uppercase();
        MANAGER_VARIABLE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
}

fn hash_version_selectors(hasher: &mut FieldHasher, cwd: &Path, environment: &SelectorEnvironment) {
    hasher.bytes(b"selectors");
    for (name, value) in &environment.variables {
        hasher.os(name);
        hasher.os(value);
    }

    let tool_versions = environment
        .variable("ASDF_DEFAULT_TOOL_VERSIONS_FILENAME")
        .unwrap_or(OsStr::new(DEFAULT_TOOL_VERSIONS_FILE));
    for directory in cwd.ancestors() {
        hash_project_selectors(hasher, directory, tool_versions);
    }

    let mut global_files = Vec::with_capacity(6);
    global_files.extend(
        environment
            .variable("ASDF_CONFIG_FILE")
            .map(PathBuf::from)
            .or_else(|| environment.home.as_ref().map(|home| home.join(".asdfrc"))),
    );
    global_files.extend(
        environment
            .home
            .as_ref()
            .map(|home| home.join(tool_versions)),
    );
    global_files.extend(
        environment
            .directory("NODENV_ROOT", ".nodenv")
            .map(|root| root.join("version")),
    );
    global_files.extend(
        environment
            .directory("VOLTA_HOME", ".volta")
            .map(|root| root.join("tools/user/platform.json")),
    );
    global_files.extend(
        environment
            .directory("PROTO_HOME", ".proto")
            .map(|root| root.join(".prototools")),
    );
    global_files.extend(
        environment
            .variable("MISE_GLOBAL_CONFIG_FILE")
            .map(PathBuf::from),
    );
    for file in &global_files {
        hash_selector_file(hasher, file);
    }

    let mise_config = environment
        .variable("MISE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .config_home
                .as_ref()
                .map(|config| config.join("mise"))
        })
        .or_else(|| {
            environment
                .home
                .as_ref()
                .map(|home| home.join(".config/mise"))
        });
    if let Some(directory) = mise_config {
        hash_mise_directory(hasher, &directory);
    }
    #[cfg(unix)]
    hash_mise_directory(hasher, Path::new("/etc/mise"));
}

fn hash_project_selectors(hasher: &mut FieldHasher, directory: &Path, tool_versions: &OsStr) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut names: Vec<OsString> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| is_project_selector(name, tool_versions))
        .collect();
    names.sort();
    for name in names {
        let path = directory.join(&name);
        match name.to_str() {
            Some("package.json") => hash_package_json_selectors(hasher, &path),
            Some(".config") => {
                hash_mise_files(hasher, &path, is_mise_config_file);
                hash_mise_directory(hasher, &path.join("mise"));
            }
            Some("mise" | ".mise") => hash_mise_directory(hasher, &path),
            _ => hash_selector_file(hasher, &path),
        }
    }
}

fn is_project_selector(name: &OsStr, tool_versions: &OsStr) -> bool {
    name == tool_versions
        || name.to_str().is_some_and(|name| {
            matches!(
                name,
                ".nvmrc"
                    | ".node-version"
                    | ".prototools"
                    | "package.json"
                    | ".config"
                    | "mise"
                    | ".mise"
            ) || is_mise_config_file(name)
        })
}

fn is_mise_config_file(name: &str) -> bool {
    [".mise.", "mise.", ".rtx.", "rtx."]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        && name.ends_with(".toml")
}

/// Hash the TOML files of a mise configuration directory and its `conf.d`.
fn hash_mise_directory(hasher: &mut FieldHasher, directory: &Path) {
    hash_mise_files(hasher, directory, |name| name.ends_with(".toml"));
    hash_mise_files(hasher, &directory.join("conf.d"), |name| {
        name.ends_with(".toml")
    });
}

fn hash_mise_files(hasher: &mut FieldHasher, directory: &Path, include: impl Fn(&str) -> bool) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().is_some_and(&include))
        .map(|entry| entry.path())
        .collect();
    files.sort();
    for file in files {
        hash_selector_file(hasher, &file);
    }
}

/// Volta pins Node in `package.json`; other fields change with every
/// dependency edit and do not select a runtime.
fn hash_package_json_selectors(hasher: &mut FieldHasher, path: &Path) {
    let Ok((bytes, _)) = lpm_common::read_regular_file_capped_with_metadata(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) else {
        return;
    };
    hasher.os(path.as_os_str());
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(manifest) => {
            for field in ["volta", "devEngines"] {
                hasher.bytes(field.as_bytes());
                match manifest.get(field) {
                    Some(value) => hasher.bytes(value.to_string().as_bytes()),
                    None => hasher.bytes(b""),
                }
            }
        }
        Err(_) => hasher.bytes(&bytes),
    }
}

fn hash_selector_file(hasher: &mut FieldHasher, path: &Path) {
    match lpm_common::read_regular_file_capped_with_metadata(path, MAX_SELECTOR_FILE_BYTES) {
        Ok((bytes, _)) => {
            hasher.os(path.as_os_str());
            hasher.bytes(&bytes);
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
        Err(_) => {
            // Oversized or unreadable: its metadata still changes when it is replaced.
            hasher.os(path.as_os_str());
            hasher.bytes(b"metadata");
            if let Ok(metadata) = path.metadata() {
                crate::effective::update_with_file_metadata(&mut hasher.0, &metadata);
            }
        }
    }
}

/// SHA-256 over length-prefixed fields, so adjacent values cannot run together.
struct FieldHasher(Sha256);

impl FieldHasher {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.bytes(domain);
        hasher
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    #[cfg(unix)]
    fn os(&mut self, value: &OsStr) {
        use std::os::unix::ffi::OsStrExt;

        self.bytes(value.as_bytes());
    }

    #[cfg(windows)]
    fn os(&mut self, value: &OsStr) {
        use std::os::windows::ffi::OsStrExt;

        let units: Vec<u8> = value.encode_wide().flat_map(u16::to_le_bytes).collect();
        self.bytes(&units);
    }

    #[cfg(not(any(unix, windows)))]
    fn os(&mut self, value: &OsStr) {
        self.bytes(value.to_string_lossy().as_bytes());
    }

    fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

/// Write a sparse file that passes the Node binary checks but cannot run.
#[cfg(test)]
pub(crate) fn write_unrunnable_node_binary(path: &Path) {
    use std::io::Write;

    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(&[0x7f, b'E', b'L', b'F']).unwrap();
    file.set_len(MIN_NODE_BINARY_BYTES).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(windows)]
    const NODE: &str = "node.exe";
    #[cfg(not(windows))]
    const NODE: &str = "node";

    fn environment(home: &Path) -> SelectorEnvironment {
        SelectorEnvironment {
            home: Some(home.to_path_buf()),
            config_home: None,
            variables: Vec::new(),
        }
    }

    fn identity(
        executable: &Path,
        cwd: &Path,
        path: &OsStr,
        environment: &SelectorEnvironment,
    ) -> ScriptNodeIdentity {
        identity_with_environment(executable, cwd, path, None, environment).unwrap()
    }

    #[cfg(unix)]
    fn write_launcher(path: &Path, output: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, format!("#!/bin/sh\necho {output}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn node_binary_requires_a_large_native_executable_named_node() {
        let dir = tempfile::tempdir().unwrap();
        let home = environment(dir.path());
        let accepted = dir.path().join(NODE);
        write_unrunnable_node_binary(&accepted);
        assert!(identity(&accepted, dir.path(), OsStr::new(""), &home).node_binary);

        let renamed = dir.path().join("node-shim");
        fs::copy(&accepted, &renamed).unwrap();
        assert!(!identity(&renamed, dir.path(), OsStr::new(""), &home).node_binary);

        let small = tempfile::tempdir().unwrap();
        let small_node = small.path().join(NODE);
        fs::write(&small_node, [0x7f, b'E', b'L', b'F', 0, 0, 0, 0]).unwrap();
        assert!(!identity(&small_node, small.path(), OsStr::new(""), &home).node_binary);

        let script = tempfile::tempdir().unwrap();
        let script_node = script.path().join(NODE);
        fs::write(&script_node, "#!/bin/sh\necho v22.0.0\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&script_node)
            .unwrap()
            .set_len(MIN_NODE_BINARY_BYTES)
            .unwrap();
        assert!(!identity(&script_node, script.path(), OsStr::new(""), &home).node_binary);
    }

    #[cfg(unix)]
    #[test]
    fn shared_or_differently_named_shims_are_launchers() {
        let dir = tempfile::tempdir().unwrap();
        let home = environment(dir.path());
        let shim = dir.path().join("volta-shim");
        write_unrunnable_node_binary(&shim);
        let linked = dir.path().join("node");
        std::os::unix::fs::symlink(&shim, &linked).unwrap();
        assert!(!identity(&linked, dir.path(), OsStr::new(""), &home).node_binary);

        let hard_linked = tempfile::tempdir().unwrap();
        let node = hard_linked.path().join("node");
        write_unrunnable_node_binary(&node);
        fs::hard_link(&node, hard_linked.path().join("npm")).unwrap();
        assert!(!identity(&node, hard_linked.path(), OsStr::new(""), &home).node_binary);
    }

    #[cfg(unix)]
    #[test]
    fn only_launcher_fingerprints_cover_the_search_path() {
        let bin = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let home = environment(project.path());
        let node = bin.path().join("node");
        write_unrunnable_node_binary(&node);
        let first_path = std::env::join_paths([bin.path()]).unwrap();
        let second_path = std::env::join_paths([bin.path(), project.path()]).unwrap();
        assert_eq!(
            identity(&node, project.path(), &first_path, &home).fingerprint,
            identity(&node, project.path(), &second_path, &home).fingerprint
        );

        let launcher_bin = tempfile::tempdir().unwrap();
        let launcher = launcher_bin.path().join("node");
        write_launcher(&launcher, "v22.0.0");
        assert_ne!(
            identity(&launcher, project.path(), &first_path, &home).fingerprint,
            identity(&launcher, project.path(), &second_path, &home).fingerprint
        );
    }

    #[test]
    fn fingerprint_changes_with_version_manager_selectors() {
        let bin = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let node = bin.path().join(NODE);
        write_unrunnable_node_binary(&node);
        let mut environment = environment(home.path());
        let path = OsStr::new("");
        let mut previous = identity(&node, &project, path, &environment).fingerprint;
        let mut assert_changed = |label: &str, environment: &SelectorEnvironment| {
            let next = identity(&node, &project, path, environment).fingerprint;
            assert_ne!(next, previous, "{label} did not change the fingerprint");
            previous = next;
        };

        fs::write(project.join(".nvmrc"), "22\n").unwrap();
        assert_changed(".nvmrc", &environment);
        fs::write(root.path().join(".tool-versions"), "nodejs 20.11.0\n").unwrap();
        assert_changed("ancestor .tool-versions", &environment);
        fs::write(project.join("mise.local.toml"), "[tools]\nnode = \"22\"\n").unwrap();
        assert_changed("mise.local.toml", &environment);
        fs::create_dir_all(project.join(".config/mise/conf.d")).unwrap();
        fs::write(
            project.join(".config/mise/conf.d/node.toml"),
            "[tools]\nnode = \"20\"\n",
        )
        .unwrap();
        assert_changed(".config/mise/conf.d", &environment);
        fs::write(
            project.join("package.json"),
            r#"{"volta":{"node":"20.11.0"}}"#,
        )
        .unwrap();
        assert_changed("package.json volta", &environment);
        fs::create_dir_all(home.path().join(".volta/tools/user")).unwrap();
        fs::write(
            home.path().join(".volta/tools/user/platform.json"),
            r#"{"node":{"runtime":"22.1.0"}}"#,
        )
        .unwrap();
        assert_changed("Volta default", &environment);
        environment
            .variables
            .push(("MISE_NODE_VERSION".into(), "20".into()));
        assert_changed("MISE_NODE_VERSION", &environment);

        fs::write(
            project.join("package.json"),
            r#"{"volta":{"node":"20.11.0"},"dependencies":{"react":"19.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(
            identity(&node, &project, path, &environment).fingerprint,
            previous,
            "package.json fields that do not select Node changed the fingerprint"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retargeting_a_link_to_the_same_launcher_changes_the_fingerprint() {
        let bin = tempfile::tempdir().unwrap();
        let home = environment(bin.path());
        write_launcher(&bin.path().join("launcher"), "v22.0.0");
        for version in ["20", "22"] {
            std::os::unix::fs::symlink("launcher", bin.path().join(format!(".node-{version}")))
                .unwrap();
        }
        let node = bin.path().join("node");
        std::os::unix::fs::symlink(".node-20", &node).unwrap();
        let before = identity(&node, bin.path(), OsStr::new(""), &home);
        fs::remove_file(&node).unwrap();
        std::os::unix::fs::symlink(".node-22", &node).unwrap();
        let after = identity(&node, bin.path(), OsStr::new(""), &home);

        assert_eq!(before.canonical_executable, after.canonical_executable);
        assert_ne!(before.fingerprint, after.fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn managed_runtime_fingerprint_ignores_the_project_context() {
        let managed_root = tempfile::tempdir().unwrap();
        let bin = managed_root.path().join("22.0.0/bin");
        fs::create_dir_all(&bin).unwrap();
        let node = bin.join("node");
        write_launcher(&node, "v22.0.0");
        let managed_root = managed_root.path().canonicalize().unwrap();
        let home = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        fs::write(second.path().join(".nvmrc"), "20\n").unwrap();
        let fingerprint = |cwd: &Path, path: &OsStr| {
            identity_with_environment(&node, cwd, path, Some(&managed_root), &environment)
                .unwrap()
                .fingerprint
        };

        assert_eq!(
            fingerprint(first.path(), OsStr::new("/first")),
            fingerprint(second.path(), OsStr::new("/second"))
        );
    }

    #[test]
    fn manager_variables_are_selected_by_prefix() {
        for name in [
            "MISE_NODE_VERSION",
            "VOLTA_HOME",
            "ASDF_DATA_DIR",
            "PROTO_NODE_VERSION",
        ] {
            assert!(is_manager_variable(OsStr::new(name)), "{name}");
        }
        for name in ["PATH", "NODE_OPTIONS", "HOME", "__MISE_DIFF"] {
            assert!(!is_manager_variable(OsStr::new(name)), "{name}");
        }
    }
}
