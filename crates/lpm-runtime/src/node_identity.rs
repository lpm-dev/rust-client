//! Identify the Node or Bun executable that a script `PATH` selects.
//!
//! An earlier `--version` result may stand in for a new probe only when the
//! selected executable is the runtime's own binary with an unchanged
//! fingerprint. Launchers such as shell scripts and version-manager shims can
//! print a different version without changing on disk, so they are always
//! probed.
//!
//! The fingerprint also covers the version files and settings that version
//! managers read. A native shim that passes the binary checks still changes
//! its fingerprint when those inputs select a different version.

use crate::detect::RuntimeKind;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const FINGERPRINT_DOMAIN: &[u8] = b"lpm-node-runtime-fingerprint-v2\0script-path";
/// Node binaries are tens of megabytes; version-manager shims are far smaller.
const MIN_NODE_BINARY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SYMLINK_HOPS: usize = 40;
const MAX_SELECTOR_FILE_BYTES: u64 = 64 * 1024;
const MANAGER_VARIABLE_PREFIXES: [&str; 6] =
    ["ASDF_", "MISE_", "RTX_", "NODENV_", "VOLTA_", "PROTO_"];
const DEFAULT_TOOL_VERSIONS_FILE: &str = ".tool-versions";

/// Fingerprinted Node or Bun executable selected by a script's cwd and `PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScriptNodeIdentity {
    pub(crate) canonical_executable: PathBuf,
    pub(crate) fingerprint: String,
    /// Whether the executable is the runtime's own binary rather than a
    /// launcher.
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
    IdentityContext::new(cwd, path, environment).identify(
        executable,
        managed_node_root,
        RuntimeKind::Node,
    )
}

pub(crate) fn script_runtime_fingerprints(
    executables: &[Option<PathBuf>; 2],
    cwd: &Path,
    path: &OsStr,
    roots: [Option<&Path>; 2],
) -> [Option<String>; 2] {
    script_runtime_identities(
        executables,
        cwd,
        path,
        roots,
        &SelectorEnvironment::from_process(),
    )
    .map(|identity| identity.map(|identity| identity.fingerprint))
}

/// Identify Node and Bun while reading their shared version selectors once.
pub(crate) fn script_runtime_identities(
    executables: &[Option<PathBuf>; 2],
    cwd: &Path,
    path: &OsStr,
    roots: [Option<&Path>; 2],
    environment: &SelectorEnvironment,
) -> [Option<ScriptNodeIdentity>; 2] {
    let context = IdentityContext::new(cwd, path, environment);
    std::array::from_fn(|index| {
        let runtime = [RuntimeKind::Node, RuntimeKind::Bun][index];
        context.identify(executables[index].as_deref()?, roots[index], runtime)
    })
}

struct IdentityContext<'a> {
    cwd: &'a Path,
    path: &'a OsStr,
    environment: &'a SelectorEnvironment,
    selectors: OnceLock<String>,
}

impl<'a> IdentityContext<'a> {
    fn new(cwd: &'a Path, path: &'a OsStr, environment: &'a SelectorEnvironment) -> Self {
        Self {
            cwd,
            path,
            environment,
            selectors: OnceLock::new(),
        }
    }

    fn identify(
        &self,
        executable: &Path,
        managed_node_root: Option<&Path>,
        runtime: RuntimeKind,
    ) -> Option<ScriptNodeIdentity> {
        let canonical_executable = executable.canonicalize().ok()?;
        let metadata = canonical_executable.metadata().ok()?;
        if !metadata.is_file() {
            return None;
        }
        let node_binary = is_runtime_binary(&canonical_executable, &metadata, runtime)
            && !is_version_manager_shim(
                executable,
                &canonical_executable,
                self.cwd,
                self.environment,
            );

        let mut hasher = FieldHasher::new(FINGERPRINT_DOMAIN);
        hasher.bytes(runtime.as_str().as_bytes());
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
                hasher.os(self.cwd.canonicalize().ok()?.as_os_str());
                hasher.os(self.path);
            }
            let selectors = self.selectors.get_or_init(|| {
                let mut selectors = FieldHasher::new(b"runtime-version-selectors");
                hash_version_selectors(
                    &mut selectors,
                    self.cwd,
                    self.environment,
                    ProjectFileNames::Absolute,
                );
                selectors.finish()
            });
            hasher.bytes(selectors.as_bytes());
        }

        Some(ScriptNodeIdentity {
            canonical_executable,
            fingerprint: hasher.finish(),
            node_binary,
        })
    }
}

/// What a script `PATH` selects for a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeExecutable {
    /// The runtime's own binary.
    Binary,
    /// A version manager's shim: it runs the release that its version
    /// selectors choose. Some managers (mise, proto) also apply environment
    /// settings from those same files.
    VersionManagerShim,
    /// Any other launcher. It can change the environment or the flags that
    /// the runtime gets, so its version alone doesn't describe what runs.
    Launcher,
}

/// Classify an identified runtime executable, `executable` being its `PATH`
/// entry for a script in `cwd`.
pub(crate) fn classify_identified(
    identity: &ScriptNodeIdentity,
    executable: &Path,
    cwd: &Path,
    environment: &SelectorEnvironment,
) -> RuntimeExecutable {
    if identity.node_binary {
        RuntimeExecutable::Binary
    } else if is_version_manager_shim(executable, &identity.canonical_executable, cwd, environment)
    {
        RuntimeExecutable::VersionManagerShim
    } else {
        RuntimeExecutable::Launcher
    }
}

/// A key under which a version-manager shim's version can be reused within
/// one command: the shim, the manager settings, and the version files around
/// `cwd` named by file rather than by path. Two workspace members that read
/// the same version files get the same key.
pub(crate) fn shim_selection_key(
    executable: &Path,
    canonical: &Path,
    cwd: &Path,
    environment: &SelectorEnvironment,
    runtime: RuntimeKind,
) -> Option<String> {
    let metadata = canonical.metadata().ok()?;
    let mut hasher = FieldHasher::new(b"lpm-task-shim-selection-v1");
    hasher.bytes(runtime.as_str().as_bytes());
    hash_symlink_chain(&mut hasher, executable);
    hasher.os(canonical.as_os_str());
    crate::effective::update_with_file_metadata(&mut hasher.0, &metadata);
    // Which ancestors mise reads depends on where a directory is relative to
    // a ceiling, so no two directories share a key then.
    let names = if environment.variable("MISE_CEILING_PATHS").is_some() {
        hasher.bytes(b"directory-specific");
        hasher.os(cwd.as_os_str());
        ProjectFileNames::Absolute
    } else {
        ProjectFileNames::Local
    };
    hash_version_selectors(&mut hasher, cwd, environment, names);
    Some(hasher.finish())
}

/// Digest of the version files from `cwd` up to the workspace `root`, named
/// by their paths from `root`, so that checkouts at other paths agree. A
/// shim's version and the environment that some managers set come from these
/// files.
pub(crate) fn workspace_selector_digest(
    cwd: &Path,
    root: &Path,
    environment: &SelectorEnvironment,
) -> Option<String> {
    let cwd = cwd.canonicalize().ok()?;
    let root = root.canonicalize().ok()?;
    if !cwd.starts_with(&root) {
        return None;
    }
    let files = SelectorFiles::of(environment);
    let mut hasher = FieldHasher::new(b"lpm-task-workspace-selectors-v1");
    for directory in cwd.ancestors() {
        hash_project_selectors(&mut hasher, directory, files, ProjectFileNames::From(&root));
        if directory == root {
            break;
        }
    }
    Some(hasher.finish())
}

/// Shims link to their manager's binary, or live in its shim directory. A
/// link into the project or `node_modules` is the project's own launcher,
/// whatever its name.
fn is_version_manager_shim(
    executable: &Path,
    canonical: &Path,
    cwd: &Path,
    environment: &SelectorEnvironment,
) -> bool {
    let project_owned = canonical
        .components()
        .any(|component| component.as_os_str() == "node_modules")
        || cwd
            .canonicalize()
            .is_ok_and(|project| canonical.starts_with(project));
    if !project_owned
        && canonical
            .file_stem()
            .and_then(OsStr::to_str)
            .is_some_and(|stem| matches!(stem, "mise" | "rtx" | "volta-shim" | "proto-shim"))
    {
        return true;
    }
    let Some(directory) = executable
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
    else {
        return false;
    };
    // Volta's Windows installer copies volta-shim.exe as node.exe next to it.
    if ["volta-shim.exe", "volta-shim"]
        .iter()
        .any(|shim| directory.join(shim).is_file())
    {
        return true;
    }
    [
        environment.volta_home().map(|root| root.join("bin")),
        environment
            .directory("ASDF_DATA_DIR", ".asdf")
            .map(|root| root.join("shims")),
        environment
            .directory("NODENV_ROOT", ".nodenv")
            .map(|root| root.join("shims")),
        environment
            .directory("PROTO_HOME", ".proto")
            .map(|root| root.join("shims")),
        environment.mise_shims(),
    ]
    .into_iter()
    .flatten()
    .any(|shims| shims.canonicalize().is_ok_and(|shims| shims == directory))
}

fn is_runtime_binary(canonical: &Path, metadata: &Metadata, runtime: RuntimeKind) -> bool {
    #[cfg(debug_assertions)]
    if runtime == RuntimeKind::Node
        && let Some(test_binary) = std::env::var_os("LPM_TEST_NODE_BINARY")
    {
        return Path::new(&test_binary)
            .canonicalize()
            .is_ok_and(|test_binary| test_binary == canonical);
    }

    // The npm `bun` package ships `bin/bun.exe` on every platform.
    let named_node = canonical.file_name().is_some_and(|name| {
        let windows_name = match runtime {
            RuntimeKind::Node => "node.exe",
            RuntimeKind::Bun => "bun.exe",
        };
        if cfg!(windows) {
            name.eq_ignore_ascii_case(windows_name)
        } else {
            name == runtime.binary_name() || name == windows_name
        }
    });
    if !named_node || metadata.len() < MIN_NODE_BINARY_BYTES {
        return false;
    }
    #[cfg(windows)]
    if canonical.with_extension("shim").exists() {
        // Scoop shims read their target from this sidecar.
        return false;
    }
    let Ok(mut file) = std::fs::File::open(canonical) else {
        return false;
    };
    // Version managers hard-link one shim binary under several tool names,
    // as mise does on Windows in its `hardlink` shim mode.
    if !lpm_common::link_count(&file).is_ok_and(|links| links == 1) {
        return false;
    }
    has_native_executable_header(&mut file)
}

fn has_native_executable_header(file: &mut std::fs::File) -> bool {
    use std::io::Read;

    let mut header = [0_u8; 4];
    if file.read_exact(&mut header).is_err() {
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

/// Where version managers look for their settings, and the manager variables
/// a script sees.
#[derive(Debug, Clone)]
pub(crate) struct SelectorEnvironment {
    home: Option<PathBuf>,
    config_home: Option<PathBuf>,
    data_home: Option<PathBuf>,
    /// `%LOCALAPPDATA%` on Windows, where Volta and mise keep their data.
    local_data: Option<PathBuf>,
    /// Version-manager variables, sorted by name.
    variables: Vec<(OsString, OsString)>,
}

impl SelectorEnvironment {
    pub(crate) fn from_process() -> Self {
        Self::with_script_variables(std::iter::empty::<(OsString, OsString)>())
    }

    /// The process environment with `script` variables layered over it, as a
    /// script whose project environment sets them sees it.
    pub(crate) fn with_script_variables(
        script: impl IntoIterator<Item = (impl Into<OsString>, impl Into<OsString>)>,
    ) -> Self {
        let mut variables: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(name, _)| is_manager_variable(name))
            .collect();
        for (name, value) in script {
            let name = name.into();
            if !is_manager_variable(&name) {
                continue;
            }
            variables.retain(|(existing, _)| !same_variable(existing, &name));
            variables.push((name, value.into()));
        }
        variables.sort();
        Self {
            home: dirs::home_dir(),
            config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            data_home: std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
            local_data: if cfg!(windows) {
                dirs::data_local_dir()
            } else {
                None
            },
            variables,
        }
    }

    fn volta_home(&self) -> Option<PathBuf> {
        self.variable("VOLTA_HOME")
            .map(PathBuf::from)
            .or_else(|| match &self.local_data {
                Some(local) => Some(local.join("Volta")),
                None => self.home.as_ref().map(|home| home.join(".volta")),
            })
    }

    fn mise_shims(&self) -> Option<PathBuf> {
        if let Some(shims) = self.variable("MISE_SHIMS_DIR") {
            return Some(PathBuf::from(shims));
        }
        self.variable("MISE_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| self.local_data.as_ref().map(|local| local.join("mise")))
            .or_else(|| self.data_home.as_ref().map(|data| data.join("mise")))
            .or_else(|| {
                self.home
                    .as_ref()
                    .map(|home| home.join(".local/share/mise"))
            })
            .map(|data| data.join("shims"))
    }

    /// The file name mise reads as each directory's config, when the user
    /// renamed it.
    fn mise_config_file(&self) -> Option<&OsStr> {
        self.variable("MISE_DEFAULT_CONFIG_FILENAME")
    }

    /// The manager variables, for a probe that must select what the script
    /// selects.
    pub(crate) fn variables(&self) -> &[(OsString, OsString)] {
        &self.variables
    }

    fn tool_versions_file(&self) -> &OsStr {
        self.variable("ASDF_DEFAULT_TOOL_VERSIONS_FILENAME")
            .unwrap_or(OsStr::new(DEFAULT_TOOL_VERSIONS_FILE))
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

/// Whether `name` is a version-manager variable, which can select the
/// runtime that a shim runs.
pub(crate) fn is_manager_variable(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        let name = name.to_ascii_uppercase();
        MANAGER_VARIABLE_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
}

fn same_variable(left: &OsStr, right: &OsStr) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// How project version files are named in a hash.
#[derive(Clone, Copy)]
enum ProjectFileNames<'a> {
    /// By absolute path, for a fingerprint that stays on this machine.
    Absolute,
    /// By path from the directory each one is found in, so that directories
    /// with the same files hash alike wherever they are. Each directory that
    /// has version files is marked, so the order of the files still counts.
    Local,
    /// By path from a fixed root.
    From(&'a Path),
}

impl ProjectFileNames<'_> {
    fn hash(self, hasher: &mut FieldHasher, directory: &Path, path: &Path) {
        let base = match self {
            Self::Absolute => {
                hasher.os(path.as_os_str());
                return;
            }
            Self::Local => directory,
            Self::From(root) => root,
        };
        hasher.os(path.strip_prefix(base).unwrap_or(path).as_os_str());
    }
}

fn hash_version_selectors(
    hasher: &mut FieldHasher,
    cwd: &Path,
    environment: &SelectorEnvironment,
    names: ProjectFileNames<'_>,
) {
    hasher.bytes(b"selectors");
    for (name, value) in &environment.variables {
        hasher.os(name);
        hasher.os(value);
    }

    let files = SelectorFiles::of(environment);
    for directory in cwd.ancestors() {
        hash_project_selectors(hasher, directory, files, names);
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
            .map(|home| home.join(files.tool_versions)),
    );
    global_files.extend(
        environment
            .directory("NODENV_ROOT", ".nodenv")
            .map(|root| root.join("version")),
    );
    global_files.extend(
        environment
            .volta_home()
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
        hash_selector_file(hasher, file, file, ProjectFileNames::Absolute);
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
        hash_mise_directory(hasher, &directory, &directory, ProjectFileNames::Absolute);
    }
    #[cfg(unix)]
    hash_mise_directory(
        hasher,
        Path::new("/etc/mise"),
        Path::new("/etc/mise"),
        ProjectFileNames::Absolute,
    );
}

/// The renamable version-file names a directory's selectors use.
#[derive(Clone, Copy)]
struct SelectorFiles<'a> {
    tool_versions: &'a OsStr,
    mise_config: Option<&'a OsStr>,
}

impl<'a> SelectorFiles<'a> {
    fn of(environment: &'a SelectorEnvironment) -> Self {
        Self {
            tool_versions: environment.tool_versions_file(),
            mise_config: environment.mise_config_file(),
        }
    }
}

fn hash_project_selectors(
    hasher: &mut FieldHasher,
    directory: &Path,
    files: SelectorFiles<'_>,
    names: ProjectFileNames<'_>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut selectors: Vec<OsString> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| is_project_selector(name, files))
        .collect();
    if selectors.is_empty() {
        return;
    }
    selectors.sort();
    if matches!(names, ProjectFileNames::Local) {
        hasher.bytes(b"directory");
    }
    for name in selectors {
        let path = directory.join(&name);
        match name.to_str() {
            Some("package.json") => hash_package_json_selectors(hasher, directory, &path, names),
            Some(".config") => {
                hash_mise_files(hasher, directory, &path, is_mise_config_file, names);
                hash_mise_directory(hasher, directory, &path.join("mise"), names);
            }
            Some("mise" | ".mise") => hash_mise_directory(hasher, directory, &path, names),
            _ => hash_selector_file(hasher, directory, &path, names),
        }
    }
}

fn is_project_selector(name: &OsStr, files: SelectorFiles<'_>) -> bool {
    name == files.tool_versions
        || files.mise_config == Some(name)
        || name.to_str().is_some_and(|name| {
            matches!(
                name,
                ".nvmrc"
                    | ".node-version"
                    | ".bun-version"
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
/// `base` is the directory that `names` measures project paths from.
fn hash_mise_directory(
    hasher: &mut FieldHasher,
    base: &Path,
    directory: &Path,
    names: ProjectFileNames<'_>,
) {
    hash_mise_files(
        hasher,
        base,
        directory,
        |name| name.ends_with(".toml"),
        names,
    );
    hash_mise_files(
        hasher,
        base,
        &directory.join("conf.d"),
        |name| name.ends_with(".toml"),
        names,
    );
}

fn hash_mise_files(
    hasher: &mut FieldHasher,
    base: &Path,
    directory: &Path,
    include: impl Fn(&str) -> bool,
    names: ProjectFileNames<'_>,
) {
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
        hash_selector_file(hasher, base, &file, names);
    }
}

/// The `package.json` fields that select a runtime: Volta's pin and
/// `devEngines`. Other fields change with every dependency edit and do not
/// select one.
const PACKAGE_SELECTOR_FIELDS: [&str; 2] = ["volta", "devEngines"];
/// `engines` only constrains the runtime LPM runs, but nodenv's
/// package-json-engine plugin selects a release from it, so keys that a
/// shim's version is shared under cover it too.
const SHIM_PACKAGE_SELECTOR_FIELDS: [&str; 3] = ["volta", "devEngines", "engines"];
/// How many `volta.extends` links are followed.
const MAX_VOLTA_EXTENDS: usize = 8;

fn hash_package_json_selectors(
    hasher: &mut FieldHasher,
    base: &Path,
    path: &Path,
    names: ProjectFileNames<'_>,
) {
    let Some(bytes) = read_manifest(path) else {
        return;
    };
    names.hash(hasher, base, path);
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(manifest) => {
            let fields: &[&str] = match names {
                ProjectFileNames::Absolute => &PACKAGE_SELECTOR_FIELDS,
                ProjectFileNames::Local | ProjectFileNames::From(_) => {
                    &SHIM_PACKAGE_SELECTOR_FIELDS
                }
            };
            for field in fields {
                hasher.bytes(field.as_bytes());
                match manifest.get(field) {
                    Some(value) => hasher.bytes(value.to_string().as_bytes()),
                    None => hasher.bytes(b""),
                }
            }
            hash_volta_extends(hasher, path, &manifest);
        }
        Err(_) => hasher.bytes(&bytes),
    }
}

fn read_manifest(path: &Path) -> Option<Vec<u8>> {
    lpm_common::read_regular_file_capped_with_metadata(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .ok()
        .map(|(bytes, _)| bytes)
}

/// Volta reads its pin from the file `volta.extends` names, which need not be
/// an ancestor. Each linked pin is hashed by content, so two directories
/// whose links lead to different pins never share a key.
fn hash_volta_extends(hasher: &mut FieldHasher, path: &Path, manifest: &serde_json::Value) {
    let mut current = path.to_path_buf();
    let mut extends = manifest.pointer("/volta/extends").cloned();
    for _ in 0..MAX_VOLTA_EXTENDS {
        let Some(serde_json::Value::String(target)) = extends else {
            return;
        };
        hasher.bytes(b"volta-extends");
        let Some(next) = current.parent().map(|parent| parent.join(&target)) else {
            return;
        };
        let pin = read_manifest(&next)
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let Some(pin) = pin else {
            hasher.bytes(b"unreadable");
            return;
        };
        let volta = pin.get("volta").cloned().unwrap_or_default();
        hasher.bytes(volta.to_string().as_bytes());
        extends = volta.get("extends").cloned();
        current = next;
    }
    if extends.is_some() {
        // Volta follows a longer chain; past this point only the file's own
        // location tells two chains apart.
        hasher.bytes(b"volta-extends-deeper");
        hasher.os(current.as_os_str());
    }
}

fn hash_selector_file(
    hasher: &mut FieldHasher,
    base: &Path,
    path: &Path,
    names: ProjectFileNames<'_>,
) {
    match lpm_common::read_regular_file_capped_with_metadata(path, MAX_SELECTOR_FILE_BYTES) {
        Ok((bytes, _)) => {
            names.hash(hasher, base, path);
            hasher.bytes(&bytes);
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
        Err(_) => {
            // Oversized or unreadable: its metadata still changes when it is replaced.
            names.hash(hasher, base, path);
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
        hex::encode(self.0.finalize())
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
            data_home: None,
            local_data: None,
            variables: Vec::new(),
        }
    }

    fn is_shim(path: &Path, cwd: &Path, environment: &SelectorEnvironment) -> bool {
        is_version_manager_shim(path, &path.canonicalize().unwrap(), cwd, environment)
    }

    #[cfg(unix)]
    #[test]
    fn version_manager_shims_are_told_from_other_launchers() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        let shim = |relative: &str| {
            let path = home.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_launcher(&path, "v22.0.0");
            path
        };

        for shim_dir in [
            ".asdf/shims",
            ".nodenv/shims",
            ".volta/bin",
            ".proto/shims",
            ".local/share/mise/shims",
        ] {
            let node = shim(&format!("{shim_dir}/{NODE}"));
            assert!(is_shim(&node, project.path(), &environment), "{shim_dir}");
        }

        let manager = shim("tools/mise");
        let linked = home.path().join("anywhere/node");
        fs::create_dir_all(linked.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&manager, &linked).unwrap();
        assert!(is_shim(&linked, project.path(), &environment));

        let wrapper = shim("project/node_modules/.bin/node");
        assert!(!is_shim(&wrapper, project.path(), &environment));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_manager_named_binary_inside_the_project_is_not_a_shim() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        for target in ["tools/mise", "node_modules/volta/volta-shim"] {
            let target = project.path().join(target);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            write_launcher(&target, "v22.0.0");
            let link = project.path().join(format!(
                "bin-{}",
                target.file_name().unwrap().to_string_lossy()
            ));
            fs::create_dir_all(&link).unwrap();
            let node = link.join(NODE);
            std::os::unix::fs::symlink(&target, &node).unwrap();
            assert!(
                !is_shim(&node, project.path(), &environment),
                "{}",
                target.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_manager_directory_variable_moves_its_shims() {
        let home = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut environment = environment(home.path());
        environment.variables = vec![(
            "ASDF_DATA_DIR".into(),
            data.path().as_os_str().to_os_string(),
        )];
        let node = data.path().join("shims").join(NODE);
        fs::create_dir_all(node.parent().unwrap()).unwrap();
        write_launcher(&node, "v22.0.0");
        assert!(is_shim(&node, project.path(), &environment));
    }

    #[test]
    fn a_runtime_sized_binary_in_a_shim_directory_is_not_a_runtime_binary() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        let shims = home.path().join(".local/share/mise/shims");
        fs::create_dir_all(&shims).unwrap();
        let node = shims.join(NODE);
        write_unrunnable_node_binary(&node);
        let identity = identity(
            &node,
            project.path(),
            project.path().as_os_str(),
            &environment,
        );
        assert!(
            !identity.node_binary,
            "a hard-linked shim that looks like Node must not have its version recorded"
        );
    }

    #[test]
    fn the_npm_bun_package_binary_named_bun_exe_is_a_runtime_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bun = dir.path().join("bun.exe");
        write_unrunnable_node_binary(&bun);
        assert!(is_runtime_binary(
            &bun.canonicalize().unwrap(),
            &bun.metadata().unwrap(),
            RuntimeKind::Bun
        ));
    }

    #[test]
    fn script_manager_variables_override_the_process_ones() {
        let environment =
            SelectorEnvironment::with_script_variables([("NODENV_VERSION", "18"), ("PATH", "/x")]);
        assert_eq!(
            environment.variable("NODENV_VERSION"),
            Some(OsStr::new("18"))
        );
        assert!(environment.variable("PATH").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn shim_selection_key_ignores_where_the_same_version_files_are() {
        let home = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        let shim = home.path().join(".asdf/shims").join(NODE);
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        write_launcher(&shim, "v22.0.0");
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join(".tool-versions"), "nodejs 22.11.0\n").unwrap();
        let shallow = workspace.path().join("packages/a");
        let deep = workspace.path().join("apps/web/b");
        let pinned = workspace.path().join("packages/c");
        for member in [&shallow, &deep, &pinned] {
            fs::create_dir_all(member).unwrap();
            fs::write(member.join("package.json"), r#"{"name":"m"}"#).unwrap();
        }
        fs::write(pinned.join(".nvmrc"), "20\n").unwrap();
        let key = |cwd: &Path| {
            shim_selection_key(
                &shim,
                &shim.canonicalize().unwrap(),
                cwd,
                &environment,
                RuntimeKind::Node,
            )
            .unwrap()
        };
        assert_eq!(key(&shallow), key(&deep));
        assert_ne!(key(&shallow), key(&pinned));
    }

    #[cfg(unix)]
    #[test]
    fn mise_shims_dir_and_windows_style_data_dirs_hold_shims() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
        let mut environment = environment(home.path());
        environment.variables = vec![(
            "MISE_SHIMS_DIR".into(),
            custom.path().as_os_str().to_os_string(),
        )];
        environment.local_data = Some(local.path().to_path_buf());
        for shims in [custom.path().to_path_buf(), local.path().join("Volta/bin")] {
            fs::create_dir_all(&shims).unwrap();
            let node = shims.join(NODE);
            write_launcher(&node, "v22.0.0");
            assert!(
                is_shim(&node, project.path(), &environment),
                "{}",
                shims.display()
            );
        }

        environment.variables.clear();
        let shims = local.path().join("mise/shims");
        fs::create_dir_all(&shims).unwrap();
        let node = shims.join(NODE);
        write_launcher(&node, "v22.0.0");
        assert!(is_shim(&node, project.path(), &environment));
    }

    /// Shim selection keys for members `a` and `b` of a workspace whose
    /// directories `prepare` fills in.
    #[cfg(unix)]
    fn member_keys(
        environment: &SelectorEnvironment,
        prepare: impl FnOnce(&Path, &Path, &Path),
    ) -> (String, String) {
        let home = tempfile::tempdir().unwrap();
        let shim = home.path().join(".asdf/shims").join(NODE);
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        write_launcher(&shim, "v22.0.0");
        let workspace = tempfile::tempdir().unwrap();
        let a = workspace.path().join("packages/a");
        let b = workspace.path().join("apps/b");
        for member in [&a, &b] {
            fs::create_dir_all(member).unwrap();
        }
        prepare(workspace.path(), &a, &b);
        let canonical = shim.canonicalize().unwrap();
        let key = |cwd: &Path| {
            shim_selection_key(&shim, &canonical, cwd, environment, RuntimeKind::Node).unwrap()
        };
        (key(&a), key(&b))
    }

    #[cfg(unix)]
    #[test]
    fn members_whose_engines_differ_never_share_a_shim_key() {
        let environment = environment(Path::new("/nonexistent-home"));
        let (a, b) = member_keys(&environment, |_, a, b| {
            fs::write(a.join("package.json"), r#"{"engines":{"node":"18"}}"#).unwrap();
            fs::write(b.join("package.json"), r#"{"engines":{"node":"20"}}"#).unwrap();
        });
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn an_engines_edit_leaves_the_local_runtime_fingerprint_unchanged() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        let node = project.path().join("bin").join(NODE);
        fs::create_dir_all(node.parent().unwrap()).unwrap();
        write_launcher(&node, "v22.0.0");
        let fingerprint = |engines: &str| {
            fs::write(
                project.path().join("package.json"),
                format!(r#"{{"engines":{{"node":"{engines}"}}}}"#),
            )
            .unwrap();
            identity(
                &node,
                project.path(),
                node.parent().unwrap().as_os_str(),
                &environment,
            )
            .fingerprint
        };
        assert_eq!(
            fingerprint("18"),
            fingerprint("20"),
            "engines constrains the runtime LPM runs; it doesn't select one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn members_whose_volta_extends_lead_to_different_pins_never_share_a_shim_key() {
        let environment = environment(Path::new("/nonexistent-home"));
        let pins = |node_a: &'static str, node_b: &'static str| {
            member_keys(&environment, move |root, a, b| {
                for (member, node) in [(a, node_a), (b, node_b)] {
                    let shared = member.parent().unwrap().join("shared");
                    fs::create_dir_all(&shared).unwrap();
                    fs::write(
                        shared.join("package.json"),
                        format!(r#"{{"volta":{{"node":"{node}"}}}}"#),
                    )
                    .unwrap();
                    fs::write(
                        member.join("package.json"),
                        r#"{"volta":{"extends":"../shared/package.json"}}"#,
                    )
                    .unwrap();
                }
                let _ = root;
            })
        };
        let (a, b) = pins("18.20.0", "20.11.0");
        assert_ne!(a, b, "different linked pins");
        let (a, b) = pins("20.11.0", "20.11.0");
        assert_eq!(a, b, "the same linked pin");
    }

    #[test]
    fn a_node_next_to_volta_shim_is_a_volta_shim() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let program_files = tempfile::tempdir().unwrap();
        let environment = environment(home.path());
        // Volta's Windows installer copies volta-shim.exe as node.exe.
        fs::write(program_files.path().join("volta-shim.exe"), b"MZ").unwrap();
        let node = program_files.path().join(NODE);
        fs::write(&node, b"MZ").unwrap();
        assert!(is_shim(&node, project.path(), &environment));
    }

    #[cfg(unix)]
    #[test]
    fn volta_extends_chains_that_differ_past_the_followed_links_never_share_a_shim_key() {
        let environment = environment(Path::new("/nonexistent-home"));
        let (a, b) = member_keys(&environment, |_, a, b| {
            for (member, last) in [(a, "18.20.0"), (b, "20.11.0")] {
                let links = member.join("links");
                fs::create_dir_all(&links).unwrap();
                fs::write(
                    member.join("package.json"),
                    r#"{"volta":{"extends":"links/0.json"}}"#,
                )
                .unwrap();
                for index in 0..=MAX_VOLTA_EXTENDS {
                    let volta = if index == MAX_VOLTA_EXTENDS {
                        format!(r#"{{"node":"{last}"}}"#)
                    } else {
                        format!(r#"{{"extends":"{}.json"}}"#, index + 1)
                    };
                    fs::write(
                        links.join(format!("{index}.json")),
                        format!(r#"{{"volta":{volta}}}"#),
                    )
                    .unwrap();
                }
            }
        });
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn a_mise_ceiling_keeps_shim_keys_apart_by_position() {
        let mut environment = environment(Path::new("/nonexistent-home"));
        environment.variables = vec![("MISE_CEILING_PATHS".into(), "/elsewhere".into())];
        let (a, b) = member_keys(&environment, |_, _, _| {});
        assert_ne!(a, b);
    }

    #[test]
    fn a_renamed_mise_config_file_is_a_version_file() {
        let mut environment = environment(Path::new("/nonexistent-home"));
        environment.variables = vec![("MISE_DEFAULT_CONFIG_FILENAME".into(), "tools.toml".into())];
        let root = tempfile::tempdir().unwrap();
        let digest = || workspace_selector_digest(root.path(), root.path(), &environment).unwrap();
        let empty = digest();
        fs::write(root.path().join("tools.toml"), "[tools]\nnode = '22'\n").unwrap();
        assert_ne!(digest(), empty);
    }

    #[test]
    fn workspace_selector_digest_names_files_from_the_root() {
        let environment = environment(Path::new("/nonexistent-home"));
        let checkouts = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        for checkout in &checkouts {
            fs::create_dir_all(checkout.path().join("packages/app")).unwrap();
            fs::write(
                checkout.path().join("mise.toml"),
                "[env]\nNODE_ENV = 'production'\n",
            )
            .unwrap();
        }
        let digest = |root: &Path| {
            workspace_selector_digest(&root.join("packages/app"), root, &environment).unwrap()
        };
        let [first, second] = &checkouts;
        assert_eq!(digest(first.path()), digest(second.path()));

        fs::write(
            second.path().join("mise.toml"),
            "[env]\nNODE_ENV = 'development'\n",
        )
        .unwrap();
        assert_ne!(
            digest(first.path()),
            digest(second.path()),
            "a mise [env] change must change the digest"
        );
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
