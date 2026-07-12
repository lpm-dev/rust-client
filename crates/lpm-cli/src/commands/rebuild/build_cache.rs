use super::scripts::ScriptablePackage;
use crate::capability::CapabilitySet;
use lpm_sandbox::{SandboxMode, SandboxOptions, SandboxPosture};
use lpm_security::EXECUTED_INSTALL_PHASES;
use lpm_store::v2::{
    BuildCacheKey, BuildKeyInputs, BuildPlatformFingerprint, BuildRuntimeFingerprint,
    BuildSandboxFingerprint, BuildScriptFingerprint, PlatformTuple,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

pub(super) struct BuildCacheScratch {
    path: PathBuf,
}

impl BuildCacheScratch {
    pub(super) fn create(package_dir: &Path) -> std::io::Result<Self> {
        let link_dir = package_dir
            .ancestors()
            .find(|ancestor| ancestor.join(lpm_store::v2::LINK_META_FILENAME).is_file())
            .ok_or_else(|| std::io::Error::other("package is not inside a v2 link entry"))?;
        let path = link_dir.join(format!(
            ".lpm-build-tmp.{}.{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }

    #[inline]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BuildCacheScratch {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::debug!(
                "failed to remove build-cache scratch directory at {}: {error}",
                self.path.display()
            );
        }
    }
}

pub(super) struct BuildCacheInvocation {
    dependency_closure_hash: String,
    platform: BuildPlatformFingerprint,
    runtime: BuildRuntimeFingerprint,
    sandbox: BuildSandboxFingerprint,
    environment_hash: String,
    environment: HashMap<String, String>,
    native_toolchain_hash: OnceLock<Option<String>>,
}

impl BuildCacheInvocation {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        lockfile: &lpm_lockfile::Lockfile,
        environment: &HashMap<String, String>,
        sandbox_mode: SandboxMode,
        posture: &SandboxPosture,
        sandbox_options: &SandboxOptions,
        extra_write_dirs: &[PathBuf],
        extra_read_paths: &[PathBuf],
        capabilities: &CapabilitySet,
    ) -> Option<Self> {
        if sandbox_mode != SandboxMode::Enforce {
            debug_bypass("sandbox is not enforcing");
            return None;
        }
        if !matches!(posture, SandboxPosture::Strict) || !sandbox_options.deny_outbound_network {
            debug_bypass("outbound network denial is not effective");
            return None;
        }
        if !extra_write_dirs.is_empty() || !extra_read_paths.is_empty() {
            debug_bypass("project widened sandbox paths");
            return None;
        }
        if !capabilities.is_at_baseline() {
            debug_bypass("project widened lifecycle capabilities");
            return None;
        }
        let Some(runtime) = detect_node_runtime(environment) else {
            debug_bypass("Node runtime fingerprint unavailable");
            return None;
        };
        let platform = PlatformTuple::current();
        Some(Self {
            dependency_closure_hash: hash_lockfile_graph(lockfile),
            platform: BuildPlatformFingerprint {
                os: platform.os,
                architecture: platform.cpu,
                libc: platform.libc.unwrap_or_default(),
                cpu_features_hash: cpu_features_hash(),
            },
            runtime,
            sandbox: BuildSandboxFingerprint {
                mode: "enforce".into(),
                posture: "strict".into(),
                network_denied: true,
                environment_scrubbed: true,
                allowed_inputs_hash: hash_allowed_inputs(capabilities),
            },
            environment_hash: hash_build_environment(environment),
            environment: environment.clone(),
            native_toolchain_hash: OnceLock::new(),
        })
    }
}

fn debug_bypass(reason: &str) {
    tracing::debug!(target: "lpm_cli::build_cache", "bypass: {reason}");
}

pub(super) fn is_cacheable_native_build(package: &ScriptablePackage) -> bool {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return false;
    }
    package.scripts.values().any(|command| {
        command.contains("node-gyp")
            || command.contains("node-gyp-build")
            || command.contains("prebuild-install")
            || (package.name == "esbuild" && command.contains("install.js"))
            || (package.name == "sharp" && command.contains("install/"))
    })
}

pub(super) fn marker_requires_key_validation(package: &ScriptablePackage) -> bool {
    package.build_marker_key.is_some() && is_cacheable_native_build(package)
}

pub(super) fn read_build_marker_key(marker_path: &Path) -> Option<String> {
    let bytes = std::fs::read(marker_path).ok()?;
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub(super) fn build_key_for_package(
    invocation: &BuildCacheInvocation,
    package: &ScriptablePackage,
) -> Option<BuildCacheKey> {
    let Some(graph_key_digest) = package.graph_key_digest.as_ref() else {
        debug_bypass(&format!("{} has no v2 graph identity", package.name));
        return None;
    };
    if !is_cacheable_native_build(package) {
        debug_bypass(&format!(
            "{} lifecycle command is not a recognized native build",
            package.name
        ));
        return None;
    }
    let mut scripts = Vec::with_capacity(EXECUTED_INSTALL_PHASES.len());
    for phase in EXECUTED_INSTALL_PHASES {
        if let Some(command) = package.scripts.get(*phase) {
            scripts.push(BuildScriptFingerprint {
                phase: (*phase).to_string(),
                command: command.clone(),
            });
        }
    }
    let toolchain_hash = if package
        .scripts
        .values()
        .any(|command| command.contains("node-gyp"))
    {
        let Some(hash) = invocation
            .native_toolchain_hash
            .get_or_init(|| hash_toolchain(&invocation.environment).ok())
            .clone()
        else {
            debug_bypass("native toolchain fingerprint unavailable");
            return None;
        };
        hash
    } else {
        "runtime-and-dependency-graph-v1".to_string()
    };
    Some(BuildCacheKey::derive(&BuildKeyInputs {
        source_integrity: package.source_integrity.clone(),
        graph_key_digest: graph_key_digest.clone(),
        dependency_closure_hash: invocation.dependency_closure_hash.clone(),
        scripts,
        platform: invocation.platform.clone(),
        runtime: invocation.runtime.clone(),
        sandbox: invocation.sandbox.clone(),
        environment_hash: invocation.environment_hash.clone(),
        toolchain_hash,
    }))
}

pub(super) fn read_v2_graph_key_digest(package_dir: &Path) -> Option<String> {
    let link_dir = package_dir.parent()?.parent()?;
    lpm_store::v2::LinkMeta::read_from(link_dir)
        .ok()
        .map(|metadata| metadata.graph_key_digest_hex)
}

fn detect_node_runtime(environment: &HashMap<String, String>) -> Option<BuildRuntimeFingerprint> {
    let output = Command::new("node")
        .arg("-p")
        .arg("JSON.stringify({version:process.version,modules:process.versions.modules||'',napi:process.versions.napi||'',engine:process.versions.v8||'',execPath:process.execPath})")
        .env_clear()
        .envs(environment)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let executable = PathBuf::from(value.get("execPath")?.as_str()?);
    Some(BuildRuntimeFingerprint {
        runtime: "node".into(),
        version: value
            .get("version")?
            .as_str()?
            .trim_start_matches('v')
            .into(),
        modules_abi: value.get("modules")?.as_str()?.into(),
        napi: value.get("napi")?.as_str()?.into(),
        engine: value.get("engine")?.as_str()?.into(),
        executable_hash: runtime_executable_identity(&executable).ok()?,
    })
}

fn hash_lockfile_graph(lockfile: &lpm_lockfile::Lockfile) -> String {
    let mut rows = lockfile
        .packages
        .iter()
        .map(|package| {
            format!(
                "{}\0{}\0{}\0{}",
                package.name,
                package.version,
                package.integrity.as_deref().unwrap_or(""),
                package.source.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    hash_records(rows.iter().map(String::as_bytes))
}

fn hash_build_environment(environment: &HashMap<String, String>) -> String {
    const BUILD_ENVIRONMENT: &[&str] = &[
        "AR",
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "CXX",
        "CXXFLAGS",
        "LDFLAGS",
        "MACOSX_DEPLOYMENT_TARGET",
        "MAKEFLAGS",
        "npm_config_arch",
        "npm_config_build_from_source",
        "npm_config_devdir",
        "npm_config_libc",
        "npm_config_nodedir",
        "npm_config_node_gyp",
        "npm_config_runtime",
        "npm_config_target",
        "npm_config_target_arch",
    ];
    let mut records = Vec::with_capacity(BUILD_ENVIRONMENT.len());
    for name in BUILD_ENVIRONMENT {
        let value = environment
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map_or("", |(_, value)| value.as_str());
        records.push(format!("{name}\0{value}"));
    }
    hash_records(records.iter().map(String::as_bytes))
}

fn hash_toolchain(environment: &HashMap<String, String>) -> std::io::Result<String> {
    const PROBES: &[(&str, &[&str])] = &[
        ("python3", &["--version"]),
        ("make", &["--version"]),
        ("cc", &["--version"]),
        ("c++", &["--version"]),
        ("clang", &["--version"]),
        ("ld", &["-v"]),
        ("xcrun", &["--show-sdk-path"]),
        ("xcrun", &["--show-sdk-version"]),
        ("rustc", &["-vV"]),
        ("cargo", &["-V"]),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-toolchain-v1\0");
    for (program, args) in PROBES {
        hasher.update(program.as_bytes());
        hasher.update(b"\0");
        if let Ok(output) = Command::new(program)
            .args(*args)
            .env_clear()
            .envs(environment)
            .output()
        {
            hasher.update(&output.stdout[..output.stdout.len().min(16 * 1024)]);
            hasher.update(&output.stderr[..output.stderr.len().min(16 * 1024)]);
        }
        hasher.update(b"\x1e");
    }
    if let Some(home) = environment
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("HOME"))
        .map(|(_, value)| PathBuf::from(value))
        .or_else(dirs::home_dir)
    {
        hash_directory_tree(&home.join(".node-gyp"), &mut hasher)?;
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

fn hash_directory_tree(root: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    hasher.update(b"directory-tree-v1\0");
    if !root.exists() {
        hasher.update(b"absent");
        return Ok(());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut buffer = [0_u8; 64 * 1024];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap_or(&path);
            hash_os_path(hasher, relative);
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                hasher.update(b"d");
                pending.push(path);
            } else if file_type.is_file() {
                hasher.update(b"f");
                let mut file = std::fs::File::open(path)?;
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
            } else if file_type.is_symlink() {
                hasher.update(b"l");
                hash_os_path(hasher, &std::fs::read_link(path)?);
            } else {
                hasher.update(b"s");
            }
            hasher.update(b"\x1e");
        }
    }
    Ok(())
}

fn hash_os_path(hasher: &mut Sha256, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    #[cfg(not(unix))]
    {
        let value = path.to_string_lossy();
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
}

fn cpu_features_hash() -> String {
    let mut features = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        for (name, enabled) in [
            ("sse2", std::is_x86_feature_detected!("sse2")),
            ("sse4.2", std::is_x86_feature_detected!("sse4.2")),
            ("avx", std::is_x86_feature_detected!("avx")),
            ("avx2", std::is_x86_feature_detected!("avx2")),
            ("fma", std::is_x86_feature_detected!("fma")),
        ] {
            if enabled {
                features.push(name);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        features.push("aarch64");
    }
    hash_records(features.iter().map(|feature| feature.as_bytes()))
}

fn hash_allowed_inputs(capabilities: &CapabilitySet) -> String {
    let records = [
        capabilities.canonical_hash(),
        "package-local-writes".into(),
        "graph-local-reads".into(),
        "network-denied".into(),
    ];
    hash_records(records.iter().map(String::as_bytes))
}

fn hash_records<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = Sha256::new();
    for record in records {
        hasher.update((record.len() as u64).to_le_bytes());
        hasher.update(record);
    }
    format!("sha256-{}", hex::encode(hasher.finalize()))
}

fn runtime_executable_identity(path: &Path) -> std::io::Result<String> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-runtime-executable-v1\0");
    hash_os_path(&mut hasher, &canonical);
    hasher.update(metadata.len().to_le_bytes());
    if let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        hasher.update(duration.as_secs().to_le_bytes());
        hasher.update(duration.subsec_nanos().to_le_bytes());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn build_environment_hash_ignores_unrelated_values() {
        let mut first = HashMap::new();
        first.insert("UNRELATED".into(), "one".into());
        let mut second = HashMap::new();
        second.insert("UNRELATED".into(), "two".into());
        assert_eq!(
            hash_build_environment(&first),
            hash_build_environment(&second)
        );
    }

    #[test]
    fn build_environment_hash_changes_with_compiler_flags() {
        let mut first = HashMap::new();
        first.insert("CFLAGS".into(), "-O2".into());
        let mut second = HashMap::new();
        second.insert("CFLAGS".into(), "-O3".into());
        assert_ne!(
            hash_build_environment(&first),
            hash_build_environment(&second)
        );
    }

    #[test]
    fn build_marker_reader_accepts_only_cache_key_shape() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join(".lpm-built");
        let key = "a".repeat(64);
        std::fs::write(&marker, &key).unwrap();

        assert_eq!(read_build_marker_key(&marker), Some(key));
    }

    #[test]
    fn build_marker_reader_preserves_legacy_and_corrupt_markers_as_unkeyed() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join(".lpm-built");
        std::fs::write(&marker, b"").unwrap();
        assert!(read_build_marker_key(&marker).is_none());

        std::fs::write(&marker, "G".repeat(64)).unwrap();
        assert!(read_build_marker_key(&marker).is_none());
    }

    #[test]
    fn directory_tree_hash_changes_when_node_headers_change() {
        let temp = tempfile::tempdir().unwrap();
        let headers = temp.path().join("include/node");
        std::fs::create_dir_all(&headers).unwrap();
        std::fs::write(headers.join("node.h"), b"first").unwrap();
        let mut first = Sha256::new();
        hash_directory_tree(temp.path(), &mut first).unwrap();

        std::fs::write(headers.join("node.h"), b"second").unwrap();
        let mut second = Sha256::new();
        hash_directory_tree(temp.path(), &mut second).unwrap();

        assert_ne!(first.finalize(), second.finalize());
    }
}
