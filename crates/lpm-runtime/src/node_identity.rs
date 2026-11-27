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
        let binary_match = classify_runtime_binary(
            &canonical_executable,
            &metadata,
            runtime,
            self.environment.has_loader_override(),
        );
        let mut node_binary = !matches!(binary_match, RuntimeBinaryMatch::NotBinary)
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
        if node_binary
            && let RuntimeBinaryMatch::DynamicLibnode(ref resolved) = binary_match
            && !hash_resolved_libnode(&mut hasher, resolved)
        {
            node_binary = false;
        }
        if managed_node_root.is_some_and(|root| canonical_executable.starts_with(root)) {
            // Each managed runtime is installed under its own version, so no
            // project input can change the version it reports.
            hasher.bytes(b"managed");
        } else {
            if !node_binary {
                // A launcher can resolve helpers through the script PATH, read
                // files relative to the working directory, or load libraries
                // redirected by dynamic-loader environment variables.
                hasher.bytes(b"launcher");
                hasher.os(self.cwd.canonicalize().ok()?.as_os_str());
                hasher.os(self.path);
                if !self.environment.loader_overrides().is_empty() {
                    hasher.bytes(b"loader-overrides");
                    for (name, value) in self.environment.loader_overrides() {
                        hasher.os(name);
                        hasher.os(value);
                    }
                }
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

struct ResolvedLibnode {
    soname: String,
    canonical_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    include_ld_so_cache: bool,
}

enum RuntimeBinaryMatch {
    NotBinary,
    StaticBinary,
    DynamicLibnode(ResolvedLibnode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ElfArch {
    elf_class: u8,
    e_machine: u16,
}

impl ElfArch {
    #[cfg(any(target_os = "linux", test))]
    fn glibc_ld_so_cache_flags(self) -> Option<(u32, bool)> {
        const ELFCLASS32: u8 = 1;
        const ELFCLASS64: u8 = 2;
        const EM_386: u16 = 3;
        const EM_PPC64: u16 = 21;
        const EM_S390: u16 = 22;
        const EM_X86_64: u16 = 62;
        const EM_AARCH64: u16 = 183;

        match (self.elf_class, self.e_machine) {
            (ELFCLASS64, EM_X86_64) => Some((0x0300, false)),
            (ELFCLASS64, EM_AARCH64) => Some((0x0a00, false)),
            (ELFCLASS32, EM_386) => Some((0x0000, true)),
            (ELFCLASS64, EM_PPC64) => Some((0x0500, false)),
            (ELFCLASS64, EM_S390) => Some((0x0400, false)),
            _ => None,
        }
    }

    #[cfg(test)]
    fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self {
                elf_class: 2,
                e_machine: 62,
            })
        } else if cfg!(target_arch = "aarch64") {
            Some(Self {
                elf_class: 2,
                e_machine: 183,
            })
        } else if cfg!(target_arch = "x86") {
            Some(Self {
                elf_class: 1,
                e_machine: 3,
            })
        } else if cfg!(target_arch = "powerpc64") {
            Some(Self {
                elf_class: 2,
                e_machine: 21,
            })
        } else if cfg!(target_arch = "s390x") {
            Some(Self {
                elf_class: 2,
                e_machine: 22,
            })
        } else {
            None
        }
    }
}

enum DynamicLibnodeSpec {
    Elf {
        soname: String,
        rpath: Option<String>,
        runpath: Option<String>,
        interp: Option<String>,
        arch: ElfArch,
    },
    MachO {
        install_name: String,
        rpaths: Vec<String>,
    },
}

/// Fold resolved dynamic `libnode` identity into `hasher` when `canonical` is a
/// small dynamically-linked Node executable. Returns `false` if a small binary
/// cannot be resolved to a concrete `libnode` file (fail-closed).
pub(crate) fn hash_dynamic_libnode_for_binary(
    hasher: &mut Sha256,
    canonical: &Path,
    metadata: &Metadata,
    runtime: RuntimeKind,
    has_loader_override: bool,
) -> bool {
    if runtime != RuntimeKind::Node || metadata.len() >= MIN_NODE_BINARY_BYTES {
        return true;
    }
    match classify_runtime_binary(canonical, metadata, runtime, has_loader_override) {
        RuntimeBinaryMatch::StaticBinary => true,
        RuntimeBinaryMatch::DynamicLibnode(resolved) => {
            let mut field_hasher = FieldHasher::new(b"lpm-task-dynamic-libnode-v1");
            if !hash_resolved_libnode(&mut field_hasher, &resolved) {
                return false;
            }
            hasher.update(field_hasher.finish().as_bytes());
            true
        }
        RuntimeBinaryMatch::NotBinary => false,
    }
}

#[cfg(test)]
fn is_runtime_binary(canonical: &Path, metadata: &Metadata, runtime: RuntimeKind) -> bool {
    !matches!(
        classify_runtime_binary(canonical, metadata, runtime, false),
        RuntimeBinaryMatch::NotBinary
    )
}

fn classify_runtime_binary(
    canonical: &Path,
    metadata: &Metadata,
    runtime: RuntimeKind,
    has_loader_override: bool,
) -> RuntimeBinaryMatch {
    #[cfg(debug_assertions)]
    if runtime == RuntimeKind::Node
        && let Some(test_binary) = std::env::var_os("LPM_TEST_NODE_BINARY")
    {
        return if Path::new(&test_binary)
            .canonicalize()
            .is_ok_and(|test_binary| test_binary == canonical)
        {
            RuntimeBinaryMatch::StaticBinary
        } else {
            RuntimeBinaryMatch::NotBinary
        };
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
    if !named_node {
        return RuntimeBinaryMatch::NotBinary;
    }
    #[cfg(windows)]
    if canonical.with_extension("shim").exists() {
        // Scoop shims read their target from this sidecar.
        return RuntimeBinaryMatch::NotBinary;
    }
    let Ok(mut file) = std::fs::File::open(canonical) else {
        return RuntimeBinaryMatch::NotBinary;
    };
    // Version managers hard-link one shim binary under several tool names,
    // as mise does on Windows in its `hardlink` shim mode.
    if !lpm_common::link_count(&file).is_ok_and(|links| links == 1) {
        return RuntimeBinaryMatch::NotBinary;
    }
    if metadata.len() >= MIN_NODE_BINARY_BYTES {
        return if has_native_executable_header(&mut file) {
            RuntimeBinaryMatch::StaticBinary
        } else {
            RuntimeBinaryMatch::NotBinary
        };
    }
    if runtime == RuntimeKind::Node
        && !has_loader_override
        && let Some(spec) = dynamic_libnode_dependency(&mut file, metadata.len())
        && let Some(resolved) = resolve_dynamic_libnode(canonical, spec)
    {
        return RuntimeBinaryMatch::DynamicLibnode(resolved);
    }
    RuntimeBinaryMatch::NotBinary
}

/// Loader variables that can preempt or alter `libnode` resolution even when
/// the binary's own rpath/install-name points to an existing file.
/// (`DYLD_FALLBACK_LIBRARY_PATH` is omitted because dyld only consults it when
/// the primary `@rpath`/install-name lookup misses, where we already fail closed.)
const DYNAMIC_LOADER_OVERRIDE_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_VERSIONED_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_ROOT_PATH",
    "DYLD_SHARED_CACHE_DIR",
];

pub(crate) fn is_dynamic_loader_override_var(name: &OsStr) -> bool {
    DYNAMIC_LOADER_OVERRIDE_VARS
        .iter()
        .any(|candidate| same_variable(name, OsStr::new(candidate)))
}

#[cfg(test)]
fn has_dynamic_loader_override_env(mut lookup: impl FnMut(&str) -> Option<OsString>) -> bool {
    DYNAMIC_LOADER_OVERRIDE_VARS
        .iter()
        .any(|var| lookup(var).is_some_and(|value| !value.is_empty()))
}

fn has_linux_ld_so_preload() -> bool {
    #[cfg(target_os = "linux")]
    {
        match std::fs::metadata("/etc/ld.so.preload") {
            Ok(meta) if meta.len() > 0 => return true,
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return true,
            _ => {}
        }
    }
    false
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

fn is_libnode_soname(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base == "libnode.so"
        || base.starts_with("libnode.so.")
        || (base.starts_with("libnode-") && base.contains(".so"))
        || base == "libnode.dylib"
        || (base.starts_with("libnode.") && base.ends_with(".dylib"))
}

fn read_exact_at(file: &mut std::fs::File, offset: u64, len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn read_u16_endian(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_u32_endian(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn read_u64_endian(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(if little_endian {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

fn dynamic_libnode_dependency(
    file: &mut std::fs::File,
    file_len: u64,
) -> Option<DynamicLibnodeSpec> {
    let magic = read_exact_at(file, 0, 4)?;
    match magic.as_slice() {
        [0x7f, b'E', b'L', b'F'] => elf_libnode_dependency(file, file_len),
        [0xcf, 0xfa, 0xed, 0xfe] => macho64_libnode_dependency_at(file, 0, file_len, true),
        [0xfe, 0xed, 0xfa, 0xcf] => macho64_libnode_dependency_at(file, 0, file_len, false),
        [0xca, 0xfe, 0xba, 0xbe] => fat_macho_libnode_dependency(file, file_len, false, false),
        [0xbe, 0xba, 0xfe, 0xca] => fat_macho_libnode_dependency(file, file_len, false, true),
        [0xca, 0xfe, 0xba, 0xbf] => fat_macho_libnode_dependency(file, file_len, true, false),
        [0xbf, 0xba, 0xfe, 0xca] => fat_macho_libnode_dependency(file, file_len, true, true),
        _ => None,
    }
}

fn read_cstr(table: &[u8], offset: u64) -> Option<&str> {
    let start = usize::try_from(offset).ok()?;
    let tail = table.get(start..)?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    std::str::from_utf8(&tail[..end]).ok()
}

fn elf_libnode_dependency(file: &mut std::fs::File, file_len: u64) -> Option<DynamicLibnodeSpec> {
    const MAX_PHNUM: usize = 128;
    const MAX_DYNAMIC_BYTES: u64 = 256 * 1024;
    const MAX_STRTAB_BYTES: u64 = 1024 * 1024;
    const MAX_INTERP_BYTES: u64 = 4096;
    const MAX_NEEDED: usize = 256;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;
    const DT_STRSZ: u64 = 10;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;

    let ident = read_exact_at(file, 0, 16)?;
    let is_64 = match ident[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little_endian = match ident[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let ehdr_len = if is_64 { 64 } else { 52 };
    let ehdr = read_exact_at(file, 0, ehdr_len)?;
    let arch = ElfArch {
        elf_class: ident[4],
        e_machine: read_u16_endian(&ehdr, 18, little_endian)?,
    };
    let (phoff, phentsize, phnum) = if is_64 {
        (
            read_u64_endian(&ehdr, 32, little_endian)?,
            usize::from(read_u16_endian(&ehdr, 54, little_endian)?),
            usize::from(read_u16_endian(&ehdr, 56, little_endian)?),
        )
    } else {
        (
            u64::from(read_u32_endian(&ehdr, 28, little_endian)?),
            usize::from(read_u16_endian(&ehdr, 42, little_endian)?),
            usize::from(read_u16_endian(&ehdr, 44, little_endian)?),
        )
    };
    let expected_phentsize = if is_64 { 56 } else { 32 };
    if phentsize != expected_phentsize || phnum == 0 || phnum > MAX_PHNUM {
        return None;
    }
    let ph_table_bytes = phentsize.checked_mul(phnum)?;
    if phoff.checked_add(ph_table_bytes as u64)? > file_len {
        return None;
    }
    let ph_table = read_exact_at(file, phoff, ph_table_bytes)?;

    let mut load_segments: Vec<(u64, u64, u64)> = Vec::new();
    let mut dynamic_segment: Option<(u64, u64)> = None;
    let mut interp_segment: Option<(u64, u64)> = None;
    for index in 0..phnum {
        let base = index * phentsize;
        let p_type = read_u32_endian(&ph_table, base, little_endian)?;
        let (p_offset, p_vaddr, p_filesz) = if is_64 {
            (
                read_u64_endian(&ph_table, base + 8, little_endian)?,
                read_u64_endian(&ph_table, base + 16, little_endian)?,
                read_u64_endian(&ph_table, base + 32, little_endian)?,
            )
        } else {
            (
                u64::from(read_u32_endian(&ph_table, base + 4, little_endian)?),
                u64::from(read_u32_endian(&ph_table, base + 8, little_endian)?),
                u64::from(read_u32_endian(&ph_table, base + 16, little_endian)?),
            )
        };
        if p_type == PT_LOAD {
            load_segments.push((p_vaddr, p_offset, p_filesz));
        } else if p_type == PT_DYNAMIC && dynamic_segment.is_none() {
            dynamic_segment = Some((p_offset, p_filesz));
        } else if p_type == PT_INTERP && interp_segment.is_none() {
            interp_segment = Some((p_offset, p_filesz));
        }
    }

    let (dyn_offset, dyn_size) = dynamic_segment?;
    if dyn_size == 0 || dyn_size > MAX_DYNAMIC_BYTES || dyn_offset.checked_add(dyn_size)? > file_len
    {
        return None;
    }
    let dyn_bytes = read_exact_at(file, dyn_offset, usize::try_from(dyn_size).ok()?)?;
    let entry_size = if is_64 { 16 } else { 8 };
    let mut needed_offsets: Vec<u64> = Vec::new();
    let mut strtab_vaddr: Option<u64> = None;
    let mut strtab_size: Option<u64> = None;
    let mut rpath_offset: Option<u64> = None;
    let mut runpath_offset: Option<u64> = None;

    for chunk in dyn_bytes.chunks_exact(entry_size) {
        let (tag, val) = if is_64 {
            (
                read_u64_endian(chunk, 0, little_endian)?,
                read_u64_endian(chunk, 8, little_endian)?,
            )
        } else {
            (
                u64::from(read_u32_endian(chunk, 0, little_endian)?),
                u64::from(read_u32_endian(chunk, 4, little_endian)?),
            )
        };
        match tag {
            DT_NULL => break,
            DT_NEEDED => {
                if needed_offsets.len() < MAX_NEEDED {
                    needed_offsets.push(val);
                }
            }
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_STRSZ => strtab_size = Some(val),
            DT_RPATH => rpath_offset = Some(val),
            DT_RUNPATH => runpath_offset = Some(val),
            _ => {}
        }
    }

    let strtab_vaddr = strtab_vaddr?;
    let strtab_size = strtab_size?;
    if needed_offsets.is_empty() || strtab_size == 0 || strtab_size > MAX_STRTAB_BYTES {
        return None;
    }
    let strtab_offset = load_segments
        .iter()
        .find_map(|&(p_vaddr, p_offset, p_filesz)| {
            let delta = strtab_vaddr.checked_sub(p_vaddr)?;
            if delta.checked_add(strtab_size)? <= p_filesz {
                p_offset.checked_add(delta)
            } else {
                None
            }
        })?;
    if strtab_offset.checked_add(strtab_size)? > file_len {
        return None;
    }
    let strtab = read_exact_at(file, strtab_offset, usize::try_from(strtab_size).ok()?)?;
    let mut matched_soname: Option<String> = None;
    for offset in needed_offsets {
        if let Some(name) = read_cstr(&strtab, offset)
            && is_libnode_soname(name)
        {
            if matched_soname.is_some() {
                return None;
            }
            matched_soname = Some(name.to_string());
        }
    }
    let soname = matched_soname?;
    let rpath = match rpath_offset {
        Some(offset) => Some(read_cstr(&strtab, offset)?.to_string()),
        None => None,
    };
    let runpath = match runpath_offset {
        Some(offset) => Some(read_cstr(&strtab, offset)?.to_string()),
        None => None,
    };
    let interp = if let Some((interp_offset, interp_size)) = interp_segment
        && interp_size > 0
        && interp_size <= MAX_INTERP_BYTES
        && interp_offset.checked_add(interp_size)? <= file_len
    {
        let raw = read_exact_at(file, interp_offset, usize::try_from(interp_size).ok()?)?;
        read_cstr(&raw, 0).map(str::to_string)
    } else {
        None
    };
    Some(DynamicLibnodeSpec::Elf {
        soname,
        rpath,
        runpath,
        interp,
        arch,
    })
}

fn fat_macho_libnode_dependency(
    file: &mut std::fs::File,
    file_len: u64,
    is_64: bool,
    little_endian: bool,
) -> Option<DynamicLibnodeSpec> {
    const MAX_FAT_ARCH: usize = 16;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    let target_cputype = if cfg!(target_arch = "aarch64") {
        CPU_TYPE_ARM64
    } else if cfg!(target_arch = "x86_64") {
        CPU_TYPE_X86_64
    } else {
        return None;
    };

    let header = read_exact_at(file, 0, 8)?;
    let nfat_arch = usize::try_from(read_u32_endian(&header, 4, little_endian)?).ok()?;
    if nfat_arch == 0 || nfat_arch > MAX_FAT_ARCH {
        return None;
    }
    let entry_size: usize = if is_64 { 32 } else { 20 };
    let table_len = entry_size.checked_mul(nfat_arch)?;
    if 8u64.checked_add(table_len as u64)? > file_len {
        return None;
    }
    let table = read_exact_at(file, 8, table_len)?;
    for index in 0..nfat_arch {
        let base = index * entry_size;
        let cputype = read_u32_endian(&table, base, little_endian)?;
        if cputype != target_cputype {
            continue;
        }
        let (slice_offset, slice_size) = if is_64 {
            (
                read_u64_endian(&table, base + 8, little_endian)?,
                read_u64_endian(&table, base + 16, little_endian)?,
            )
        } else {
            (
                u64::from(read_u32_endian(&table, base + 8, little_endian)?),
                u64::from(read_u32_endian(&table, base + 12, little_endian)?),
            )
        };
        if slice_size < 32 || slice_offset.checked_add(slice_size)? > file_len {
            return None;
        }
        let slice_magic = read_exact_at(file, slice_offset, 4)?;
        return match slice_magic.as_slice() {
            [0xcf, 0xfa, 0xed, 0xfe] => {
                macho64_libnode_dependency_at(file, slice_offset, slice_size, true)
            }
            [0xfe, 0xed, 0xfa, 0xcf] => {
                macho64_libnode_dependency_at(file, slice_offset, slice_size, false)
            }
            _ => None,
        };
    }
    None
}

fn macho64_libnode_dependency_at(
    file: &mut std::fs::File,
    slice_offset: u64,
    slice_len: u64,
    little_endian: bool,
) -> Option<DynamicLibnodeSpec> {
    const MAX_NCMDS: usize = 512;
    const MAX_SIZEOFCMDS: u64 = 1024 * 1024;
    const MAX_RPATHS: usize = 64;
    const LC_LOAD_DYLIB: u32 = 0x0c;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
    const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
    const LC_RPATH: u32 = 0x8000_001c;

    let header = read_exact_at(file, slice_offset, 32)?;
    let ncmds = usize::try_from(read_u32_endian(&header, 16, little_endian)?).ok()?;
    let sizeofcmds = u64::from(read_u32_endian(&header, 20, little_endian)?);
    if ncmds == 0
        || ncmds > MAX_NCMDS
        || sizeofcmds == 0
        || sizeofcmds > MAX_SIZEOFCMDS
        || 32u64.checked_add(sizeofcmds)? > slice_len
    {
        return None;
    }
    let cmds = read_exact_at(
        file,
        slice_offset.checked_add(32)?,
        usize::try_from(sizeofcmds).ok()?,
    )?;
    let mut cursor = 0usize;
    let mut install_name: Option<String> = None;
    let mut rpaths: Vec<String> = Vec::new();
    for _ in 0..ncmds {
        if cursor + 8 > cmds.len() {
            return None;
        }
        let cmd = read_u32_endian(&cmds, cursor, little_endian)?;
        let cmdsize = usize::try_from(read_u32_endian(&cmds, cursor + 4, little_endian)?).ok()?;
        if cmdsize < 8 || cursor.checked_add(cmdsize)? > cmds.len() {
            return None;
        }
        if matches!(
            cmd,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
        ) && cmdsize >= 24
        {
            let name_offset =
                usize::try_from(read_u32_endian(&cmds, cursor + 8, little_endian)?).ok()?;
            if name_offset < cmdsize {
                let tail = &cmds[cursor + name_offset..cursor + cmdsize];
                let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                if let Ok(name) = std::str::from_utf8(&tail[..end])
                    && is_libnode_soname(name)
                {
                    if install_name.is_some() {
                        return None;
                    }
                    install_name = Some(name.to_string());
                }
            }
        } else if cmd == LC_RPATH && cmdsize >= 12 {
            let path_offset =
                usize::try_from(read_u32_endian(&cmds, cursor + 8, little_endian)?).ok()?;
            if path_offset < cmdsize && rpaths.len() < MAX_RPATHS {
                let tail = &cmds[cursor + path_offset..cursor + cmdsize];
                let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                let path = std::str::from_utf8(&tail[..end]).ok()?;
                rpaths.push(path.to_string());
            }
        }
        cursor += cmdsize;
    }
    Some(DynamicLibnodeSpec::MachO {
        install_name: install_name?,
        rpaths,
    })
}

fn expand_elf_rpath_entry(entry: &str, exe_dir: &Path) -> Option<PathBuf> {
    if entry.is_empty() {
        return None;
    }
    let exe_dir_str = exe_dir.to_str()?;
    let expanded = entry
        .replace("${ORIGIN}", exe_dir_str)
        .replace("$ORIGIN", exe_dir_str);
    if expanded.contains('$') {
        return None;
    }
    let path = PathBuf::from(expanded);
    path.is_absolute().then_some(path)
}

fn expand_macho_path(raw: &str, exe_dir: &Path) -> Option<PathBuf> {
    if let Some(rest) = raw
        .strip_prefix("@executable_path/")
        .or_else(|| raw.strip_prefix("@loader_path/"))
    {
        return Some(exe_dir.join(rest));
    }
    if raw == "@executable_path" || raw == "@loader_path" {
        return Some(exe_dir.to_path_buf());
    }
    if raw.starts_with('@') {
        return None;
    }
    let path = PathBuf::from(raw);
    path.is_absolute().then_some(path)
}

fn canonical_regular_file(candidate: &Path) -> Option<PathBuf> {
    let canonical = candidate.canonicalize().ok()?;
    let meta = canonical.metadata().ok()?;
    meta.is_file().then_some(canonical)
}

fn resolve_dynamic_libnode(
    canonical_executable: &Path,
    spec: DynamicLibnodeSpec,
) -> Option<ResolvedLibnode> {
    let exe_dir = canonical_executable.parent()?;
    match spec {
        DynamicLibnodeSpec::Elf {
            soname,
            rpath,
            runpath,
            interp,
            arch,
        } => {
            #[cfg(not(target_os = "linux"))]
            let _ = (&interp, arch);
            if soname.contains('/') {
                let direct = Path::new(&soname);
                if !direct.is_absolute() {
                    return None;
                }
                let canonical_path = canonical_regular_file(direct)?;
                return Some(ResolvedLibnode {
                    soname,
                    canonical_path,
                    include_ld_so_cache: false,
                });
            }
            // Per ELF ld.so rules (with LD_LIBRARY_PATH stripped): DT_RUNPATH
            // supersedes DT_RPATH; otherwise DT_RPATH is searched before
            // ld.so.cache and default system library directories. If a search
            // directory contains a `glibc-hwcaps` subdirectory, fail closed
            // because glibc may load a hardware-capability variant instead.
            let active_search = runpath.as_deref().or(rpath.as_deref());
            if let Some(search_list) = active_search {
                for entry in search_list.split(':') {
                    let dir = expand_elf_rpath_entry(entry, exe_dir)?;
                    if dir_has_glibc_hwcap_variant(&dir, &soname) {
                        return None;
                    }
                    if let Some(canonical_path) = canonical_regular_file(&dir.join(&soname)) {
                        return Some(ResolvedLibnode {
                            soname,
                            canonical_path,
                            include_ld_so_cache: false,
                        });
                    }
                }
            }
            #[cfg(target_os = "linux")]
            {
                if let Some(resolved) =
                    resolve_linux_system_libnode(&soname, interp.as_deref(), arch)
                {
                    return Some(resolved);
                }
            }
            None
        }
        DynamicLibnodeSpec::MachO {
            install_name,
            rpaths,
        } => {
            if let Some(suffix) = install_name.strip_prefix("@rpath/") {
                for rpath in &rpaths {
                    let dir = expand_macho_path(rpath, exe_dir)?;
                    if let Some(canonical_path) = canonical_regular_file(&dir.join(suffix)) {
                        return Some(ResolvedLibnode {
                            soname: install_name,
                            canonical_path,
                            include_ld_so_cache: false,
                        });
                    }
                }
                return None;
            }
            let direct = expand_macho_path(&install_name, exe_dir)?;
            let canonical_path = canonical_regular_file(&direct)?;
            Some(ResolvedLibnode {
                soname: install_name,
                canonical_path,
                include_ld_so_cache: false,
            })
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxElfLoader {
    Glibc,
    Musl,
    Unknown,
}

#[cfg(any(target_os = "linux", test))]
fn classify_linux_elf_loader(interp: Option<&str>) -> LinuxElfLoader {
    let Some(interp) = interp else {
        return LinuxElfLoader::Unknown;
    };
    let Some(basename) = Path::new(interp).file_name().and_then(|name| name.to_str()) else {
        return LinuxElfLoader::Unknown;
    };
    if basename.starts_with("ld-musl-") {
        LinuxElfLoader::Musl
    } else if basename.starts_with("ld-linux")
        || basename.starts_with("ld64.so")
        || basename == "ld.so.1"
    {
        LinuxElfLoader::Glibc
    } else {
        LinuxElfLoader::Unknown
    }
}

/// Returns true when `dir/glibc-hwcaps` exists and either contains a variant
/// matching `soname` or cannot be inspected (fail closed).
fn dir_has_glibc_hwcap_variant(dir: &Path, soname: &str) -> bool {
    let hwcaps_dir = dir.join("glibc-hwcaps");
    if !hwcaps_dir.is_dir() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(&hwcaps_dir) else {
        return true;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return true;
        };
        if entry.path().join(soname).exists() {
            return true;
        }
    }
    false
}

/// Derive the musl loader's `ld-musl-<arch>.path` configuration file from its
/// ELF `PT_INTERP` path (preserving custom sysroot prefixes).
#[cfg(any(target_os = "linux", test))]
fn musl_path_file_for_interp(interp: &str) -> Option<PathBuf> {
    if !interp.starts_with('/')
        || interp.as_bytes().contains(&0)
        || interp.split('/').any(|segment| segment == "..")
    {
        return None;
    }
    let last_slash = interp.rfind('/')?;
    let basename = &interp[last_slash + 1..];
    let arch = basename.strip_prefix("ld-musl-")?.strip_suffix(".so.1")?;
    if arch.is_empty()
        || !arch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    // Match musl's ldso/dynlink.c textual prefix rule: take everything before the
    // second-to-last `/` (or empty prefix when there is only one `/`), then append
    // `/etc/ld-musl-<arch>.path`.
    let before_last = &interp[..last_slash];
    let prefix = match before_last.rfind('/') {
        Some(penultimate_slash) => &interp[..penultimate_slash],
        None => "",
    };
    Some(PathBuf::from(format!("{prefix}/etc/ld-musl-{arch}.path")))
}

/// Parse glibc's `glibc-ld.so.cache1.1` binary table (pure new format or
/// compat old+new format) and return the unique non-hwcap library path matching
/// `soname` for the target binary's ELF class/architecture. Returns `None`
/// (fail closed) on any ambiguity, hwcap variant, or unrecognized table format.
#[cfg(any(target_os = "linux", test))]
fn lookup_soname_in_glibc_ld_so_cache(
    bytes: &[u8],
    soname: &str,
    arch: ElfArch,
) -> Option<PathBuf> {
    const NEW_MAGIC: &[u8] = b"glibc-ld.so.cache1.1";
    const OLD_MAGIC: &[u8] = b"ld.so-1.7.0";
    const NEW_HEADER_LEN: usize = 48;
    const NEW_ENTRY_LEN: usize = 24;
    const OLD_HEADER_LEN: usize = 16;
    const OLD_ENTRY_LEN: usize = 12;
    const MAX_LIBS: usize = 65_536;
    const FLAG_TYPE_MASK: u32 = 0x00ff;
    const FLAG_ELF: u32 = 0x0001;
    const FLAG_ELF_LIBC6: u32 = 0x0003;
    const FLAG_ARCH_MASK: u32 = 0xff00;

    let (expected_arch_flag, allow_plain_elf_type) = arch.glibc_ld_so_cache_flags()?;
    let new_header_offset = if bytes.starts_with(NEW_MAGIC) {
        0usize
    } else if bytes.starts_with(OLD_MAGIC) && bytes.len() >= OLD_HEADER_LEN {
        let old_nlibs = usize::try_from(u32::from_ne_bytes(bytes[12..16].try_into().ok()?)).ok()?;
        if old_nlibs > MAX_LIBS {
            return None;
        }
        let after_old = OLD_HEADER_LEN.checked_add(old_nlibs.checked_mul(OLD_ENTRY_LEN)?)?;
        let aligned = (after_old.checked_add(7)?) & !7;
        if bytes.get(aligned..)?.starts_with(NEW_MAGIC) {
            aligned
        } else if bytes.get(after_old..)?.starts_with(NEW_MAGIC) {
            after_old
        } else {
            return None;
        }
    } else {
        return None;
    };

    let section = bytes.get(new_header_offset..)?;
    if section.len() < NEW_HEADER_LEN {
        return None;
    }
    let nlibs = usize::try_from(u32::from_ne_bytes(section[20..24].try_into().ok()?)).ok()?;
    if nlibs > MAX_LIBS {
        return None;
    }
    let entries_end = NEW_HEADER_LEN.checked_add(nlibs.checked_mul(NEW_ENTRY_LEN)?)?;
    if entries_end > section.len() {
        return None;
    }

    let read_cstr = |offset: u32| -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let tail = section.get(start..)?;
        let nul = tail.iter().position(|&b| b == 0)?;
        Some(&tail[..nul])
    };

    let target = soname.as_bytes();
    let mut matched: Option<PathBuf> = None;
    for index in 0..nlibs {
        let base = NEW_HEADER_LEN + index * NEW_ENTRY_LEN;
        let entry = &section[base..base + NEW_ENTRY_LEN];
        let flags = u32::from_ne_bytes(entry[0..4].try_into().ok()?);
        let key_off = u32::from_ne_bytes(entry[4..8].try_into().ok()?);
        let val_off = u32::from_ne_bytes(entry[8..12].try_into().ok()?);
        let hwcap = u64::from_ne_bytes(entry[16..24].try_into().ok()?);
        let entry_type = flags & FLAG_TYPE_MASK;
        let type_matches = if allow_plain_elf_type {
            matches!(entry_type, FLAG_ELF | FLAG_ELF_LIBC6)
        } else {
            entry_type == FLAG_ELF_LIBC6
        };
        if !type_matches || (flags & FLAG_ARCH_MASK) != expected_arch_flag {
            continue;
        }
        let key_bytes = read_cstr(key_off)?;
        if key_bytes != target {
            continue;
        }
        // Any hwcap entry or duplicate soname mapping is ambiguous: fail closed.
        if hwcap != 0 || matched.is_some() {
            return None;
        }
        let val_bytes = read_cstr(val_off)?;
        let val_str = std::str::from_utf8(val_bytes).ok()?;
        if val_str.is_empty() {
            return None;
        }
        matched = Some(PathBuf::from(val_str));
    }
    matched
}

#[cfg(target_os = "linux")]
fn resolve_linux_system_libnode(
    soname: &str,
    interp: Option<&str>,
    arch: ElfArch,
) -> Option<ResolvedLibnode> {
    let loader = classify_linux_elf_loader(interp);
    let musl_path_file = if loader == LinuxElfLoader::Musl {
        Some(musl_path_file_for_interp(interp?)?)
    } else {
        None
    };
    let default_musl_dirs = [
        PathBuf::from("/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib"),
    ];
    resolve_linux_system_libnode_with(
        soname,
        loader,
        arch,
        Path::new("/etc/ld.so.cache"),
        musl_path_file.as_deref(),
        &default_musl_dirs,
    )
}

#[cfg(any(target_os = "linux", test))]
fn resolve_linux_system_libnode_with(
    soname: &str,
    loader: LinuxElfLoader,
    arch: ElfArch,
    ld_so_cache_path: &Path,
    musl_path_file: Option<&Path>,
    default_musl_dirs: &[PathBuf],
) -> Option<ResolvedLibnode> {
    const MAX_LD_SO_CACHE_BYTES: u64 = 16 * 1024 * 1024;
    match loader {
        LinuxElfLoader::Glibc => {
            let cache_bytes =
                lpm_common::read_file_capped(ld_so_cache_path, MAX_LD_SO_CACHE_BYTES).ok()?;
            let resolved = lookup_soname_in_glibc_ld_so_cache(&cache_bytes, soname, arch)?;
            if resolved
                .parent()
                .is_some_and(|parent| dir_has_glibc_hwcap_variant(parent, soname))
            {
                return None;
            }
            let canonical_path = canonical_regular_file(&resolved)?;
            Some(ResolvedLibnode {
                soname: soname.to_owned(),
                canonical_path,
                include_ld_so_cache: true,
            })
        }
        LinuxElfLoader::Musl => {
            let search_dirs: Vec<PathBuf> = match musl_path_file {
                Some(path_file) => match lpm_common::read_text_file_capped(path_file, 64 * 1024) {
                    Ok(raw) => raw
                        .split([':', '\n'])
                        .map(str::trim)
                        .filter(|dir| !dir.is_empty())
                        .map(PathBuf::from)
                        .collect(),
                    Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                        default_musl_dirs.to_vec()
                    }
                    Err(_) => return None,
                },
                None => default_musl_dirs.to_vec(),
            };
            let mut found: Option<PathBuf> = None;
            for dir in search_dirs {
                if let Some(canonical_path) = canonical_regular_file(&dir.join(soname)) {
                    if let Some(prev) = &found {
                        if prev != &canonical_path {
                            return None;
                        }
                    } else {
                        found = Some(canonical_path);
                    }
                }
            }
            found.map(|canonical_path| ResolvedLibnode {
                soname: soname.to_owned(),
                canonical_path,
                include_ld_so_cache: false,
            })
        }
        LinuxElfLoader::Unknown => None,
    }
}

fn hash_file_metadata_with_ctime(hasher: &mut FieldHasher, metadata: &Metadata) {
    crate::effective::update_with_file_metadata(&mut hasher.0, metadata);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        hasher.0.update(metadata.ctime().to_le_bytes());
        hasher.0.update(metadata.ctime_nsec().to_le_bytes());
    }
}

fn hash_resolved_libnode(hasher: &mut FieldHasher, resolved: &ResolvedLibnode) -> bool {
    let Ok(meta) = resolved.canonical_path.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    hasher.bytes(b"dynamic-libnode");
    hasher.bytes(resolved.soname.as_bytes());
    hasher.os(resolved.canonical_path.as_os_str());
    hash_file_metadata_with_ctime(hasher, &meta);
    #[cfg(target_os = "linux")]
    if resolved.include_ld_so_cache {
        let Ok(cache_meta) = std::fs::metadata("/etc/ld.so.cache") else {
            return false;
        };
        hasher.bytes(b"ld-so-cache");
        hash_file_metadata_with_ctime(hasher, &cache_meta);
    }
    true
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
    /// Active dynamic-loader override variables (sorted by name, non-empty).
    loader_overrides: Vec<(OsString, OsString)>,
    /// Whether any process/script dynamic-loader override or `/etc/ld.so.preload`
    /// is active (forces dynamically-linked small `node` binaries to fail closed).
    has_loader_override: bool,
}

impl SelectorEnvironment {
    pub(crate) fn from_process() -> Self {
        Self::with_script_variables(std::iter::empty::<(OsString, OsString)>())
    }

    pub(crate) fn has_loader_override(&self) -> bool {
        self.has_loader_override
    }

    pub(crate) fn loader_overrides(&self) -> &[(OsString, OsString)] {
        &self.loader_overrides
    }

    /// The process environment with `script` variables layered over it, as a
    /// script whose project environment sets them sees it.
    pub(crate) fn with_script_variables(
        script: impl IntoIterator<Item = (impl Into<OsString>, impl Into<OsString>)>,
    ) -> Self {
        let mut variables: Vec<(OsString, OsString)> = Vec::new();
        let mut loader_overrides: Vec<(OsString, OsString)> = Vec::new();
        for (name, value) in std::env::vars_os() {
            if is_dynamic_loader_override_var(&name) && !value.is_empty() {
                loader_overrides.push((name.clone(), value.clone()));
            }
            if is_manager_variable(&name) {
                variables.push((name, value));
            }
        }
        for (name, value) in script {
            let name = name.into();
            let value = value.into();
            if is_dynamic_loader_override_var(&name) {
                loader_overrides.retain(|(existing, _)| !same_variable(existing, &name));
                if !value.is_empty() {
                    loader_overrides.push((name.clone(), value.clone()));
                }
            }
            if !is_manager_variable(&name) {
                continue;
            }
            variables.retain(|(existing, _)| !same_variable(existing, &name));
            variables.push((name, value));
        }
        variables.sort();
        loader_overrides.sort();
        let has_loader_override = has_linux_ld_so_preload() || !loader_overrides.is_empty();
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
            loader_overrides,
            has_loader_override,
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
            loader_overrides: Vec::new(),
            has_loader_override: false,
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

    fn build_synthetic_elf64_with_needed(
        needed: &[&str],
        rpath: Option<&str>,
        runpath: Option<&str>,
    ) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut add_str = |s: &str| -> u64 {
            let off = strtab.len() as u64;
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
            off
        };
        let mut needed_offsets = Vec::new();
        for name in needed {
            needed_offsets.push(add_str(name));
        }
        let rpath_off = rpath.map(&mut add_str);
        let runpath_off = runpath.map(&mut add_str);

        let ehdr_size = 64usize;
        let phdr_size = 56usize;
        let phnum = 2usize;
        let dyn_entries = needed_offsets.len()
            + usize::from(rpath_off.is_some())
            + usize::from(runpath_off.is_some())
            + 3; // DT_STRTAB, DT_STRSZ, DT_NULL
        let dyn_size = dyn_entries * 16;
        let dyn_offset = ehdr_size + phnum * phdr_size;
        let strtab_offset = dyn_offset + dyn_size;
        let total_size = strtab_offset + strtab.len();

        let mut buf = vec![0u8; total_size];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        buf[32..40].copy_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
        buf[54..56].copy_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum

        let base_vaddr = 0x400000u64;
        // Program header 0: PT_LOAD covering the entire file
        let p0 = ehdr_size;
        buf[p0..p0 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        buf[p0 + 8..p0 + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        buf[p0 + 16..p0 + 24].copy_from_slice(&base_vaddr.to_le_bytes()); // p_vaddr
        buf[p0 + 32..p0 + 40].copy_from_slice(&(total_size as u64).to_le_bytes()); // p_filesz
        buf[p0 + 40..p0 + 48].copy_from_slice(&(total_size as u64).to_le_bytes()); // p_memsz

        // Program header 1: PT_DYNAMIC
        let p1 = ehdr_size + phdr_size;
        buf[p1..p1 + 4].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        buf[p1 + 8..p1 + 16].copy_from_slice(&(dyn_offset as u64).to_le_bytes()); // p_offset
        buf[p1 + 16..p1 + 24].copy_from_slice(&(base_vaddr + dyn_offset as u64).to_le_bytes());
        buf[p1 + 32..p1 + 40].copy_from_slice(&(dyn_size as u64).to_le_bytes()); // p_filesz

        let mut cursor = dyn_offset;
        let mut push_dyn = |tag: u64, val: u64| {
            buf[cursor..cursor + 8].copy_from_slice(&tag.to_le_bytes());
            buf[cursor + 8..cursor + 16].copy_from_slice(&val.to_le_bytes());
            cursor += 16;
        };
        for offset in needed_offsets {
            push_dyn(1, offset); // DT_NEEDED
        }
        if let Some(off) = rpath_off {
            push_dyn(15, off); // DT_RPATH
        }
        if let Some(off) = runpath_off {
            push_dyn(29, off); // DT_RUNPATH
        }
        push_dyn(5, base_vaddr + strtab_offset as u64); // DT_STRTAB
        push_dyn(10, strtab.len() as u64); // DT_STRSZ
        push_dyn(0, 0); // DT_NULL

        buf[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);
        buf
    }

    fn build_synthetic_macho64(install_name: &str, rpaths: &[&str]) -> Vec<u8> {
        const LC_LOAD_DYLIB: u32 = 0x0c;
        const LC_RPATH: u32 = 0x8000_001c;

        let mut cmds = Vec::new();
        // LC_LOAD_DYLIB: 24-byte header + null-terminated install_name, 8-byte aligned.
        let dylib_raw = 24 + install_name.len() + 1;
        let dylib_cmdsize = (dylib_raw + 7) & !7;
        cmds.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
        cmds.extend_from_slice(&(dylib_cmdsize as u32).to_le_bytes());
        cmds.extend_from_slice(&24u32.to_le_bytes()); // name offset
        cmds.extend_from_slice(&[0u8; 12]); // timestamp, current_version, compat_version
        cmds.extend_from_slice(install_name.as_bytes());
        cmds.push(0);
        cmds.resize(dylib_cmdsize, 0);

        for rpath in rpaths {
            let start = cmds.len();
            let raw = 12 + rpath.len() + 1;
            let cmdsize = (raw + 7) & !7;
            cmds.extend_from_slice(&LC_RPATH.to_le_bytes());
            cmds.extend_from_slice(&(cmdsize as u32).to_le_bytes());
            cmds.extend_from_slice(&12u32.to_le_bytes()); // path offset
            cmds.extend_from_slice(rpath.as_bytes());
            cmds.push(0);
            cmds.resize(start + cmdsize, 0);
        }

        let ncmds = 1 + rpaths.len();
        let mut buf = Vec::with_capacity(32 + cmds.len());
        buf.extend_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]); // MH_MAGIC_64 (LE)
        buf.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // cputype
        buf.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        buf.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        buf.extend_from_slice(&(ncmds as u32).to_le_bytes());
        buf.extend_from_slice(&(cmds.len() as u32).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&cmds);
        buf
    }

    fn build_synthetic_fat_macho(slice: &[u8]) -> Vec<u8> {
        let host_cputype: u32 = if cfg!(target_arch = "aarch64") {
            0x0100_000c
        } else {
            0x0100_0007
        };
        let other_cputype: u32 = if cfg!(target_arch = "aarch64") {
            0x0100_0007
        } else {
            0x0100_000c
        };
        let header_len = 8 + 2 * 20; // fat_header + 2 fat_arch entries
        let slice_offset = 64u32;
        let mut buf = Vec::with_capacity(slice_offset as usize + slice.len());
        buf.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // FAT_MAGIC (BE)
        buf.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch = 2
        // First arch: non-host dummy
        buf.extend_from_slice(&other_cputype.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&slice_offset.to_be_bytes());
        buf.extend_from_slice(&(slice.len() as u32).to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Second arch: host slice
        buf.extend_from_slice(&host_cputype.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&slice_offset.to_be_bytes());
        buf.extend_from_slice(&(slice.len() as u32).to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(buf.len(), header_len);
        buf.resize(slice_offset as usize, 0);
        buf.extend_from_slice(slice);
        buf
    }

    #[test]
    fn dynamically_linked_small_node_elf_respects_runpath_tracks_ctime_and_fails_closed_when_unresolved()
     {
        let prefix = tempfile::tempdir().unwrap();
        let bin_dir = prefix.path().join("bin");
        let custom_dir = prefix.path().join("custom");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&custom_dir).unwrap();
        let home = environment(prefix.path());

        // Decoy libnode in bin_dir must NOT be picked up (ld.so never searches bin_dir).
        // Use an impossible soname so host system libraries can never satisfy it.
        const TEST_SONAME: &str = "libnode.so.99999";
        fs::write(bin_dir.join(TEST_SONAME), b"decoy").unwrap();
        let unresolvable = bin_dir.join(NODE);
        fs::write(
            &unresolvable,
            build_synthetic_elf64_with_needed(&["libc.so.6", TEST_SONAME], None, None),
        )
        .unwrap();
        assert!(
            !identity(&unresolvable, prefix.path(), OsStr::new(""), &home).node_binary,
            "ELF without resolvable libnode must fail closed as launcher"
        );

        // ELF with DT_RUNPATH=$ORIGIN/../custom resolves concrete libnode and ignores decoy.
        let dyn_node = bin_dir.join(NODE);
        fs::write(
            &dyn_node,
            build_synthetic_elf64_with_needed(
                &["libc.so.6", TEST_SONAME],
                None,
                Some("$ORIGIN/../custom"),
            ),
        )
        .unwrap();
        let libnode = custom_dir.join(TEST_SONAME);
        fs::write(&libnode, b"v20.11.0").unwrap();
        let first = identity(&dyn_node, prefix.path(), OsStr::new(""), &home);
        assert!(
            first.node_binary,
            "ELF with concrete RUNPATH libnode.so must be recognized as real node binary"
        );
        #[cfg(unix)]
        {
            // Same-length library replacement with preserved mtime must still change fingerprint (ctime).
            let orig_mtime = fs::metadata(&libnode).unwrap().modified().unwrap();
            fs::write(&libnode, b"v20.19.0").unwrap();
            fs::set_times(&libnode, fs::FileTimes::new().set_modified(orig_mtime)).unwrap();
            let second = identity(&dyn_node, prefix.path(), OsStr::new(""), &home);
            assert_ne!(
                first.fingerprint, second.fingerprint,
                "same-size preserved-mtime libnode upgrade must invalidate fingerprint via ctime"
            );
        }

        // An unrelated `glibc-hwcaps` directory does not block resolution, while
        // a matching `glibc-hwcaps/<variant>/<soname>` entry must fail closed.
        let hwcaps_dir = custom_dir.join("glibc-hwcaps");
        let hwcaps_variant = hwcaps_dir.join("x86-64-v3");
        fs::create_dir_all(&hwcaps_variant).unwrap();
        assert!(
            identity(&dyn_node, prefix.path(), OsStr::new(""), &home).node_binary,
            "unrelated glibc-hwcaps directory without matching soname should still resolve"
        );
        fs::write(hwcaps_variant.join(TEST_SONAME), b"hwcap-variant").unwrap();
        assert!(
            !identity(&dyn_node, prefix.path(), OsStr::new(""), &home).node_binary,
            "RUNPATH directory containing a glibc-hwcaps variant for libnode must fail closed"
        );
        fs::remove_dir_all(&hwcaps_dir).unwrap();

        // Distinct LD_LIBRARY_PATH values must fail closed AND yield distinct fingerprints.
        let mut env_a = environment(prefix.path());
        env_a.loader_overrides =
            vec![(OsString::from("LD_LIBRARY_PATH"), OsString::from("/opt/a"))];
        env_a.has_loader_override = true;
        let mut env_b = environment(prefix.path());
        env_b.loader_overrides =
            vec![(OsString::from("LD_LIBRARY_PATH"), OsString::from("/opt/b"))];
        env_b.has_loader_override = true;
        let id_a = identity(&dyn_node, prefix.path(), OsStr::new(""), &env_a);
        let id_b = identity(&dyn_node, prefix.path(), OsStr::new(""), &env_b);
        assert!(!id_a.node_binary && !id_b.node_binary);
        assert_ne!(
            id_a.fingerprint, id_b.fingerprint,
            "different LD_LIBRARY_PATH values must produce distinct launcher fingerprints"
        );

        // Relative/empty RUNPATH depends on cwd and must fail closed.
        fs::write(
            &dyn_node,
            build_synthetic_elf64_with_needed(
                &["libc.so.6", TEST_SONAME],
                None,
                Some(":$ORIGIN/../custom"),
            ),
        )
        .unwrap();
        assert!(
            !identity(&dyn_node, prefix.path(), OsStr::new(""), &home).node_binary,
            "empty RUNPATH entry (cwd-relative) must fail closed"
        );

        // Non-libnode small ELF stays launcher.
        let shim_dir = tempfile::tempdir().unwrap();
        let shim_elf = shim_dir.path().join(NODE);
        fs::write(
            &shim_elf,
            build_synthetic_elf64_with_needed(&["libc.so.6", "libdl.so.2"], None, None),
        )
        .unwrap();
        assert!(
            !identity(&shim_elf, shim_dir.path(), OsStr::new(""), &home).node_binary,
            "small ELF without libnode DT_NEEDED must stay classified as a launcher"
        );
    }

    #[test]
    fn dynamically_linked_small_node_macho_thin_and_fat_resolve_lc_rpath_and_fail_closed() {
        let prefix = tempfile::tempdir().unwrap();
        let bin_dir = prefix.path().join("bin");
        let lib_dir = prefix.path().join("lib");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&lib_dir).unwrap();
        let home = environment(prefix.path());

        let thin_node = bin_dir.join(NODE);
        let thin_bytes =
            build_synthetic_macho64("@rpath/libnode.127.dylib", &["@executable_path/../lib"]);
        fs::write(&thin_node, &thin_bytes).unwrap();
        // Before libnode exists, must fail closed as launcher.
        assert!(
            !identity(&thin_node, prefix.path(), OsStr::new(""), &home).node_binary,
            "Mach-O with unresolved @rpath/libnode must fail closed"
        );

        let libnode = lib_dir.join("libnode.127.dylib");
        fs::write(&libnode, b"dylib-v22.0.0").unwrap();
        let thin_id = identity(&thin_node, prefix.path(), OsStr::new(""), &home);
        assert!(
            thin_id.node_binary,
            "thin 64-bit Mach-O with resolvable LC_RPATH libnode must be recognized"
        );

        // Universal/fat Mach-O wrapping the thin slice must also resolve on x86_64/arm64 hosts.
        let fat_bytes = build_synthetic_fat_macho(&thin_bytes);
        fs::write(&thin_node, &fat_bytes).unwrap();
        let fat_id = identity(&thin_node, prefix.path(), OsStr::new(""), &home);
        assert!(
            fat_id.node_binary,
            "universal fat Mach-O with host slice must recognize dynamic libnode"
        );

        // Truncated/malformed load command bounds must fail closed cleanly without panicking.
        let mut malformed = thin_bytes;
        malformed.truncate(40);
        fs::write(&thin_node, &malformed).unwrap();
        assert!(
            !identity(&thin_node, prefix.path(), OsStr::new(""), &home).node_binary,
            "malformed Mach-O load commands must fail closed"
        );
    }

    #[test]
    fn dynamic_loader_override_env_vars_fail_closed() {
        assert!(!has_dynamic_loader_override_env(|_| None));
        assert!(!has_dynamic_loader_override_env(|_| Some(OsString::new())));
        for var in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ] {
            assert!(
                has_dynamic_loader_override_env(|name| {
                    (name == var).then(|| OsString::from("/tmp/evil.so"))
                }),
                "{var} must trigger dynamic libnode fail-closed guard"
            );
            let script_env = SelectorEnvironment::with_script_variables([(var, "/tmp/evil.so")]);
            assert!(
                script_env.has_loader_override(),
                "script-level {var} must mark SelectorEnvironment as loader-overridden"
            );
        }
    }

    #[test]
    fn dynamic_libnode_task_fingerprint_tracks_libnode_upgrades() {
        let prefix = tempfile::tempdir().unwrap();
        let bin_dir = prefix.path().join("bin");
        let lib_dir = prefix.path().join("lib");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&lib_dir).unwrap();
        let node = bin_dir.join(NODE);
        let libnode = lib_dir.join("libnode.127.dylib");
        fs::write(&libnode, b"v22.0.0").unwrap();
        fs::write(
            &node,
            build_synthetic_macho64("@rpath/libnode.127.dylib", &["@executable_path/../lib"]),
        )
        .unwrap();
        let canonical = node.canonicalize().unwrap();
        let meta = canonical.metadata().unwrap();

        let mut h1 = Sha256::new();
        assert!(hash_dynamic_libnode_for_binary(
            &mut h1,
            &canonical,
            &meta,
            RuntimeKind::Node,
            false
        ));
        let d1 = h1.finalize();

        let mut h_override = Sha256::new();
        assert!(
            !hash_dynamic_libnode_for_binary(
                &mut h_override,
                &canonical,
                &meta,
                RuntimeKind::Node,
                true
            ),
            "active loader override must fail closed in task binary fingerprint helper"
        );

        fs::write(&libnode, b"v22.9.0-new").unwrap();
        let mut h2 = Sha256::new();
        assert!(hash_dynamic_libnode_for_binary(
            &mut h2,
            &canonical,
            &meta,
            RuntimeKind::Node,
            false
        ));
        let d2 = h2.finalize();
        assert_ne!(
            d1, d2,
            "task binary fingerprint helper must reflect libnode upgrades"
        );

        fs::remove_file(&libnode).unwrap();
        let mut h3 = Sha256::new();
        assert!(
            !hash_dynamic_libnode_for_binary(&mut h3, &canonical, &meta, RuntimeKind::Node, false),
            "missing libnode must fail closed in task binary fingerprint helper"
        );
    }

    #[test]
    fn glibc_ld_so_cache_parser_resolves_unique_entry_and_fails_closed_on_hwcaps_or_ambiguity() {
        let Some(host_arch) = ElfArch::host() else {
            return;
        };
        let Some((arch_flag, _)) = host_arch.glibc_ld_so_cache_flags() else {
            return;
        };
        let build_new_cache = |entries: &[(&str, &str, u32, u64)]| -> Vec<u8> {
            let entries_offset = 48usize;
            let strings_offset = entries_offset + entries.len() * 24;
            let mut string_table = Vec::new();
            let mut encoded_entries = Vec::new();
            for (soname, path, flags, hwcap) in entries {
                let key_off = (strings_offset + string_table.len()) as u32;
                string_table.extend_from_slice(soname.as_bytes());
                string_table.push(0);
                let val_off = (strings_offset + string_table.len()) as u32;
                string_table.extend_from_slice(path.as_bytes());
                string_table.push(0);
                encoded_entries.extend_from_slice(&flags.to_ne_bytes());
                encoded_entries.extend_from_slice(&key_off.to_ne_bytes());
                encoded_entries.extend_from_slice(&val_off.to_ne_bytes());
                encoded_entries.extend_from_slice(&0u32.to_ne_bytes());
                encoded_entries.extend_from_slice(&hwcap.to_ne_bytes());
            }
            let mut buf = Vec::with_capacity(strings_offset + string_table.len());
            buf.extend_from_slice(b"glibc-ld.so.cache1.1");
            buf.extend_from_slice(&(entries.len() as u32).to_ne_bytes());
            buf.extend_from_slice(&(string_table.len() as u32).to_ne_bytes());
            buf.resize(48, 0);
            buf.extend_from_slice(&encoded_entries);
            buf.extend_from_slice(&string_table);
            buf
        };

        let host_flags = 0x0003 | arch_flag;
        // Unique match selects the exact path from ld.so.cache (e.g. /usr/local/lib).
        let unique = build_new_cache(&[
            ("libc.so.6", "/lib/libc.so.6", host_flags, 0),
            (
                "libnode.so.109",
                "/usr/local/lib/libnode.so.109",
                host_flags,
                0,
            ),
        ]);
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&unique, "libnode.so.109", host_arch),
            Some(PathBuf::from("/usr/local/lib/libnode.so.109"))
        );

        // Target ELF arch drives the filter (not compile-time host arch):
        // x86_64 ignores legacy FLAG_ELF (0x01) and i386 matches FLAG_ELF | 0x0000.
        let x86_64_arch = ElfArch {
            elf_class: 2,
            e_machine: 62,
        };
        let i386_arch = ElfArch {
            elf_class: 1,
            e_machine: 3,
        };
        let unknown_arch = ElfArch {
            elf_class: 2,
            e_machine: 243,
        };
        let multiarch_cache = build_new_cache(&[
            ("libnode.so.109", "/usr/lib32/libnode.so.109", 0x0001, 0),
            (
                "libnode.so.109",
                "/usr/lib64/libnode.so.109",
                0x0003 | 0x0300,
                0,
            ),
        ]);
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&multiarch_cache, "libnode.so.109", x86_64_arch),
            Some(PathBuf::from("/usr/lib64/libnode.so.109"))
        );
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&multiarch_cache, "libnode.so.109", i386_arch),
            Some(PathBuf::from("/usr/lib32/libnode.so.109"))
        );
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&multiarch_cache, "libnode.so.109", unknown_arch),
            None
        );

        // Compat old+new wrapper (ld.so-1.7.0 prefix before glibc-ld.so.cache1.1).
        let mut compat = Vec::new();
        compat.extend_from_slice(b"ld.so-1.7.0\0");
        compat.extend_from_slice(&1u32.to_ne_bytes()); // 1 old entry (12 bytes) -> offset 28 -> aligned 32
        compat.extend_from_slice(&[0u8; 16]);
        compat.extend_from_slice(&unique);
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&compat, "libnode.so.109", host_arch),
            Some(PathBuf::from("/usr/local/lib/libnode.so.109"))
        );

        // Hardware-capability variant (hwcap != 0) must fail closed.
        let hwcaps = build_new_cache(&[(
            "libnode.so.109",
            "/usr/lib/glibc-hwcaps/x86-64-v3/libnode.so.109",
            host_flags,
            1 << 62,
        )]);
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&hwcaps, "libnode.so.109", host_arch),
            None
        );

        // Duplicate entries for the same soname must fail closed.
        let ambiguous = build_new_cache(&[
            (
                "libnode.so.109",
                "/usr/local/lib/libnode.so.109",
                host_flags,
                0,
            ),
            ("libnode.so.109", "/usr/lib/libnode.so.109", host_flags, 0),
        ]);
        assert_eq!(
            lookup_soname_in_glibc_ld_so_cache(&ambiguous, "libnode.so.109", host_arch),
            None
        );
    }

    #[test]
    fn linux_system_libnode_resolver_uses_interpreter_instead_of_falling_back_to_musl() {
        let dir = tempfile::tempdir().unwrap();
        let musl_dir = dir.path().join("musl-lib");
        fs::create_dir_all(&musl_dir).unwrap();
        let musl_libnode = musl_dir.join("libnode.so.109");
        fs::write(&musl_libnode, b"musl libnode").unwrap();
        let missing_cache = dir.path().join("missing-ld.so.cache");
        let arch = ElfArch {
            elf_class: 2,
            e_machine: 62,
        };

        assert_eq!(
            classify_linux_elf_loader(Some("/lib64/ld-linux-x86-64.so.2")),
            LinuxElfLoader::Glibc
        );
        assert_eq!(
            classify_linux_elf_loader(Some("/lib/ld-linux-aarch64.so.1")),
            LinuxElfLoader::Glibc
        );
        assert_eq!(
            classify_linux_elf_loader(Some("/lib/ld-musl-aarch64.so.1")),
            LinuxElfLoader::Musl
        );
        assert_eq!(classify_linux_elf_loader(None), LinuxElfLoader::Unknown);

        assert_eq!(
            musl_path_file_for_interp("/lib/ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/usr/lib/ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/usr/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/opt/sysroot/lib/ld-musl-aarch64.so.1"),
            Some(PathBuf::from("/opt/sysroot/etc/ld-musl-aarch64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/opt/sysroot/lib64/ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/opt/sysroot/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/custom/ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/opt//ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/opt/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/lib//ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/lib/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/lib/./ld-musl-x86_64.so.1"),
            Some(PathBuf::from("/lib/etc/ld-musl-x86_64.path"))
        );
        assert_eq!(
            musl_path_file_for_interp("/opt/../lib/ld-musl-x86_64.so.1"),
            None
        );

        // Glibc executable with an unavailable ld.so.cache must fail closed and never
        // resolve a library from musl search directories.
        assert!(
            resolve_linux_system_libnode_with(
                "libnode.so.109",
                LinuxElfLoader::Glibc,
                arch,
                &missing_cache,
                None,
                std::slice::from_ref(&musl_dir),
            )
            .is_none()
        );

        // Unknown interpreter must also fail closed.
        assert!(
            resolve_linux_system_libnode_with(
                "libnode.so.109",
                LinuxElfLoader::Unknown,
                arch,
                &missing_cache,
                None,
                std::slice::from_ref(&musl_dir),
            )
            .is_none()
        );

        // Musl executable resolves unambiguously from musl search dirs when path file is missing.
        let missing_musl_path = dir.path().join("missing-ld-musl.path");
        let resolved = resolve_linux_system_libnode_with(
            "libnode.so.109",
            LinuxElfLoader::Musl,
            arch,
            &missing_cache,
            Some(&missing_musl_path),
            std::slice::from_ref(&musl_dir),
        )
        .expect("musl interpreter must resolve libnode from musl search dirs");
        assert_eq!(
            resolved.canonical_path,
            musl_libnode.canonicalize().unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_glibc_ld_so_cache_resolves_libc_when_present() {
        let Some(host_arch) = ElfArch::host() else {
            return;
        };
        let cache_path = Path::new("/etc/ld.so.cache");
        let Ok(bytes) = lpm_common::read_file_capped(cache_path, 16 * 1024 * 1024) else {
            return;
        };
        let resolved = lookup_soname_in_glibc_ld_so_cache(&bytes, "libc.so.6", host_arch);
        assert!(
            resolved.is_some(),
            "host /etc/ld.so.cache must resolve libc.so.6 using real glibc LIBC6 flags"
        );
    }

    #[test]
    fn musl_loader_fails_closed_when_path_file_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let default_lib = dir.path().join("default-lib");
        std::fs::create_dir_all(&default_lib).unwrap();
        std::fs::write(default_lib.join("libnode.so.109"), b"default").unwrap();
        let unreadable_path_file = dir.path().join("ld-musl.path");
        std::fs::create_dir_all(&unreadable_path_file).unwrap();

        let resolved = resolve_linux_system_libnode_with(
            "libnode.so.109",
            LinuxElfLoader::Musl,
            ElfArch {
                elf_class: 2,
                e_machine: 62,
            },
            &dir.path().join("unused.cache"),
            Some(&unreadable_path_file),
            &[default_lib],
        );
        assert!(
            resolved.is_none(),
            "musl loader must fail closed instead of falling back to defaults when path file read fails"
        );
    }
}
