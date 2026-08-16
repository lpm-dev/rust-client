//! Cache key computation for task caching.
//!
//! A cache key is a SHA-256 hash of everything that affects a task's output:
//! - Source files matching input globs
//! - The complete package.json contract
//! - The command string
//! - Environment variables
//! - Node.js version

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use lpm_common::LpmError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

const ECOSYSTEM_LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.lock",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceContractFingerprint([u8; 32]);

#[derive(Clone, Debug)]
pub struct FilesystemValidation {
    root: PathBuf,
    fixed_names: Vec<String>,
    globs: Vec<String>,
    fingerprint: [u8; 32],
}

impl FilesystemValidation {
    pub fn is_unchanged(&self) -> Result<bool, LpmError> {
        Ok(
            compute_validation_fingerprint(&self.root, &self.fixed_names, &self.globs)?
                == self.fingerprint,
        )
    }
}

pub struct WorkspaceContractSnapshot {
    pub fingerprint: WorkspaceContractFingerprint,
    pub validation: FilesystemValidation,
}

pub struct CacheKeySnapshot {
    pub key: String,
    pub validation: FilesystemValidation,
}

pub fn compute_dependency_fingerprint(dependency_identities: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hash_record(&mut hasher, 0, &[b"task-dependencies-v1"]);
    let mut identities: Vec<_> = dependency_identities.iter().collect();
    identities.sort_unstable();
    for (task, identity) in identities {
        hash_record(&mut hasher, 1, &[task.as_bytes(), identity.as_bytes()]);
    }
    hex::encode(hasher.finalize())
}

/// Compute a cache key for a task.
///
/// The key is a hex-encoded SHA-256 hash of all inputs that affect the output.
/// Includes a format version prefix so key format changes invalidate old caches.
pub fn compute_cache_key(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<String, LpmError> {
    compute_cache_key_with_workspace_root(
        project_dir,
        None,
        &[],
        command,
        extra_args,
        runtime_identities,
        input_globs,
        env_vars,
        package_json,
    )
}

/// Compute a task cache key with an optional containing-workspace contract.
#[expect(
    clippy::too_many_arguments,
    reason = "cache identity inputs are separate typed domains"
)]
pub fn compute_cache_key_with_workspace_root(
    project_dir: &Path,
    workspace_root: Option<&Path>,
    dependency_identities: &[(String, String)],
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<String, LpmError> {
    let workspace_contract = workspace_root
        .map(compute_workspace_contract_fingerprint)
        .transpose()?;
    compute_cache_key_with_workspace_contract(
        project_dir,
        workspace_contract.as_ref(),
        dependency_identities,
        command,
        extra_args,
        runtime_identities,
        input_globs,
        env_vars,
        package_json,
    )
}

/// Compute a task cache key with a precomputed containing-workspace contract.
#[expect(
    clippy::too_many_arguments,
    reason = "cache identity inputs are separate typed domains"
)]
pub fn compute_cache_key_with_workspace_contract(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceContractFingerprint>,
    dependency_identities: &[(String, String)],
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<String, LpmError> {
    Ok(compute_cache_key_snapshot_with_workspace_contract(
        project_dir,
        workspace_contract,
        dependency_identities,
        command,
        extra_args,
        runtime_identities,
        input_globs,
        env_vars,
        package_json,
    )?
    .key)
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache identity inputs are separate typed domains"
)]
pub fn compute_cache_key_snapshot_with_workspace_contract(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceContractFingerprint>,
    dependency_identities: &[(String, String)],
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<CacheKeySnapshot, LpmError> {
    for _ in 0..3 {
        let before = capture_cache_input_validation(project_dir, input_globs)?;
        let key = compute_cache_key_inner(
            project_dir,
            workspace_contract,
            dependency_identities,
            command,
            extra_args,
            runtime_identities,
            input_globs,
            env_vars,
            package_json,
        )?;
        let after = capture_cache_input_validation(project_dir, input_globs)?;
        if before.fingerprint == after.fingerprint {
            return Ok(CacheKeySnapshot {
                key,
                validation: after,
            });
        }
    }
    Err(LpmError::Task(
        "task cache inputs changed while their identity was captured".into(),
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache identity inputs are separate typed domains"
)]
fn compute_cache_key_inner(
    project_dir: &Path,
    workspace_contract: Option<&WorkspaceContractFingerprint>,
    dependency_identities: &[(String, String)],
    command: &str,
    extra_args: &[String],
    runtime_identities: &[(String, String)],
    input_globs: &[String],
    env_vars: &HashMap<String, String>,
    package_json: &str,
) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();

    hash_record(&mut hasher, 0, &[b"cache-v7"]);

    hash_record(&mut hasher, 1, &[command.as_bytes()]);

    // The task contract itself affects cache validity even when callers use
    // custom input globs. Hash the project config independently so changes to
    // outputs, environments, or dependency edges cannot reuse an older entry.
    let project = open_project_directory(project_dir)?;
    hash_implicit_project_file(&mut hasher, &project, "config", "lpm.json")?;
    hash_implicit_project_file(
        &mut hasher,
        &project,
        "workspace-config",
        "pnpm-workspace.yaml",
    )?;
    let has_text_lock = hash_implicit_project_file(&mut hasher, &project, "lockfile", "lpm.lock")?;
    if !has_text_lock {
        hash_implicit_project_file(&mut hasher, &project, "lockfile", "lpm.lockb")?;
    }
    for name in ECOSYSTEM_LOCKFILES {
        hash_implicit_project_file(&mut hasher, &project, "lockfile", name)?;
    }
    if let Some(workspace_contract) = workspace_contract {
        hash_record(&mut hasher, 9, &[&workspace_contract.0]);
    }
    let mut dependency_identities: Vec<_> = dependency_identities.iter().collect();
    dependency_identities.sort_unstable();
    for (task, identity) in dependency_identities {
        hash_record(&mut hasher, 8, &[task.as_bytes(), identity.as_bytes()]);
    }

    for argument in extra_args {
        hash_record(&mut hasher, 2, &[argument.as_bytes()]);
    }

    for (runtime, identity) in runtime_identities {
        hash_record(&mut hasher, 3, &[runtime.as_bytes(), identity.as_bytes()]);
    }

    // 2. Complete package contract, canonicalized for deterministic key ordering.
    let canonical_package = canonicalize_json(package_json);
    hash_record(&mut hasher, 4, &[canonical_package.as_bytes()]);

    // 3. Environment variables (sorted by key)
    let mut env_keys: Vec<&String> = env_vars.keys().collect();
    env_keys.sort();
    for key in env_keys {
        hash_record(&mut hasher, 5, &[key.as_bytes(), env_vars[key].as_bytes()]);
    }

    // 4. Source file contents matching input globs
    let files = collect_input_files(project_dir, input_globs)?;
    for (path, content_hash) in &files {
        let path_bytes = encode_relative_path(path)?;
        hash_record(&mut hasher, 6, &[&path_bytes, content_hash.as_bytes()]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn compute_workspace_contract_fingerprint(
    workspace_root: &Path,
) -> Result<WorkspaceContractFingerprint, LpmError> {
    Ok(compute_workspace_contract_snapshot(workspace_root)?.fingerprint)
}

pub fn compute_workspace_contract_snapshot(
    workspace_root: &Path,
) -> Result<WorkspaceContractSnapshot, LpmError> {
    for _ in 0..3 {
        let before = capture_workspace_contract_validation(workspace_root)?;
        let fingerprint = compute_workspace_contract_fingerprint_inner(workspace_root)?;
        let after = capture_workspace_contract_validation(workspace_root)?;
        if before.fingerprint == after.fingerprint {
            return Ok(WorkspaceContractSnapshot {
                fingerprint,
                validation: after,
            });
        }
    }
    Err(LpmError::Task(
        "workspace cache contract changed while its identity was captured".into(),
    ))
}

fn compute_workspace_contract_fingerprint_inner(
    workspace_root: &Path,
) -> Result<WorkspaceContractFingerprint, LpmError> {
    let mut hasher = Sha256::new();
    hash_record(&mut hasher, 0, &[b"workspace-contract-v1"]);
    let workspace = open_project_directory(workspace_root)?;
    for name in ["package.json", "lpm.json", "pnpm-workspace.yaml"] {
        hash_implicit_project_file(&mut hasher, &workspace, "workspace-config", name)?;
    }
    let has_text_lock =
        hash_implicit_project_file(&mut hasher, &workspace, "workspace-lockfile", "lpm.lock")?;
    if !has_text_lock {
        hash_implicit_project_file(&mut hasher, &workspace, "workspace-lockfile", "lpm.lockb")?;
    }
    for name in ECOSYSTEM_LOCKFILES {
        hash_implicit_project_file(&mut hasher, &workspace, "workspace-lockfile", name)?;
    }
    Ok(WorkspaceContractFingerprint(hasher.finalize().into()))
}

pub fn capture_task_output_validation(
    project_dir: &Path,
    output_globs: &[String],
) -> Result<FilesystemValidation, LpmError> {
    capture_filesystem_validation(project_dir, Vec::new(), output_globs.to_vec())
}

fn capture_cache_input_validation(
    project_dir: &Path,
    input_globs: &[String],
) -> Result<FilesystemValidation, LpmError> {
    let mut fixed_names = BTreeSet::from([
        "package.json".to_string(),
        "lpm.json".to_string(),
        "pnpm-workspace.yaml".to_string(),
        "lpm.lock".to_string(),
        "lpm.lockb".to_string(),
    ]);
    fixed_names.extend(ECOSYSTEM_LOCKFILES.iter().map(|name| (*name).to_string()));
    capture_filesystem_validation(
        project_dir,
        fixed_names.into_iter().collect(),
        input_globs.to_vec(),
    )
}

fn capture_workspace_contract_validation(
    workspace_root: &Path,
) -> Result<FilesystemValidation, LpmError> {
    let mut fixed_names = BTreeSet::from([
        "package.json".to_string(),
        "lpm.json".to_string(),
        "pnpm-workspace.yaml".to_string(),
        "lpm.lock".to_string(),
        "lpm.lockb".to_string(),
    ]);
    fixed_names.extend(ECOSYSTEM_LOCKFILES.iter().map(|name| (*name).to_string()));
    capture_filesystem_validation(
        workspace_root,
        fixed_names.into_iter().collect(),
        Vec::new(),
    )
}

fn capture_filesystem_validation(
    root: &Path,
    fixed_names: Vec<String>,
    globs: Vec<String>,
) -> Result<FilesystemValidation, LpmError> {
    let root = root.canonicalize().map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache validation root {}: {error}",
            root.display()
        ))
    })?;
    let fingerprint = compute_validation_fingerprint(&root, &fixed_names, &globs)?;
    Ok(FilesystemValidation {
        root,
        fixed_names,
        globs,
        fingerprint,
    })
}

fn compute_validation_fingerprint(
    root: &Path,
    fixed_names: &[String],
    globs: &[String],
) -> Result<[u8; 32], LpmError> {
    let canonical_root = root.canonicalize().map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache validation root {}: {error}",
            root.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hash_record(&mut hasher, 0, &[b"task-filesystem-validation-v1"]);
    hash_validation_path(&mut hasher, b"root", &canonical_root, true)?;

    for name in fixed_names {
        let path = canonical_root.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => hash_validation_path(&mut hasher, name.as_bytes(), &path, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hash_record(&mut hasher, 20, &[name.as_bytes(), b"missing"]);
            }
            Err(error) => {
                return Err(LpmError::Task(format!(
                    "failed to inspect task cache validation path {}: {error}",
                    path.display()
                )));
            }
        }
    }

    let mut entries = BTreeSet::new();
    for pattern in globs {
        if !crate::cache::validate_glob_pattern(pattern) {
            return Err(LpmError::Task(format!(
                "invalid task cache validation glob: {pattern}"
            )));
        }
        for expanded in expand_glob(pattern) {
            let rooted = lpm_common::rooted_project_glob(&canonical_root, &expanded);
            let matches = glob::glob(&rooted).map_err(|error| {
                LpmError::Task(format!(
                    "invalid task cache validation glob {pattern:?}: {error}"
                ))
            })?;
            for entry in matches {
                let entry = entry.map_err(|error| {
                    LpmError::Task(format!(
                        "failed to expand task cache validation glob {pattern:?}: {error}"
                    ))
                })?;
                let relative = entry.strip_prefix(&canonical_root).map_err(|_| {
                    LpmError::Task(format!(
                        "task cache validation path is outside project: {}",
                        entry.display()
                    ))
                })?;
                entries.insert(relative.to_path_buf());
            }
        }
    }

    let mut lexical_components = BTreeSet::new();
    for relative in &entries {
        let mut component_path = PathBuf::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(LpmError::Task(format!(
                    "invalid task cache validation path: {}",
                    relative.display()
                )));
            };
            component_path.push(name);
            lexical_components.insert(component_path.clone());
        }
    }
    for relative in lexical_components {
        let path = canonical_root.join(&relative);
        let key = os_str_bytes(relative.as_os_str());
        hash_validation_path(&mut hasher, &key, &path, false)?;
    }
    for relative in entries {
        let path = canonical_root.join(&relative);
        let resolved = path.canonicalize().map_err(|error| {
            LpmError::Task(format!(
                "failed to resolve task cache validation path {}: {error}",
                path.display()
            ))
        })?;
        let resolved_relative = resolved.strip_prefix(&canonical_root).map_err(|_| {
            LpmError::Task(format!(
                "task cache validation path resolves outside project: {}",
                path.display()
            ))
        })?;
        let mut key = os_str_bytes(relative.as_os_str());
        key.push(0);
        key.extend_from_slice(&os_str_bytes(resolved_relative.as_os_str()));
        hash_validation_path(&mut hasher, &key, &resolved, true)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_validation_path(
    hasher: &mut Sha256,
    key: &[u8],
    path: &Path,
    follow: bool,
) -> Result<(), LpmError> {
    let metadata = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    }
    .map_err(|error| {
        LpmError::Task(format!(
            "failed to inspect task cache validation path {}: {error}",
            path.display()
        ))
    })?;
    let is_link = lpm_common::is_symlink_or_junction(&metadata);
    let metadata_bytes = if metadata.is_dir() && !is_link {
        metadata_object_identity_bytes(&metadata)
    } else {
        metadata_identity_bytes(&metadata)
    };
    if is_link {
        let target = std::fs::read_link(path).map_err(|error| {
            LpmError::Task(format!(
                "failed to read task cache validation link {}: {error}",
                path.display()
            ))
        })?;
        let target_bytes = os_str_bytes(target.as_os_str());
        hash_record(hasher, 21, &[key, &metadata_bytes, &target_bytes]);
    } else {
        hash_record(hasher, 21, &[key, &metadata_bytes]);
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_object_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    use std::os::unix::fs::MetadataExt as _;

    let mut bytes = Vec::with_capacity(24);
    for value in [metadata.dev(), metadata.ino(), metadata.mode() as u64] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
fn metadata_object_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    use std::os::windows::fs::MetadataExt as _;

    let mut bytes = Vec::with_capacity(32);
    for value in [
        metadata.file_attributes() as u64,
        metadata.creation_time(),
        metadata.volume_serial_number().unwrap_or(0) as u64,
        metadata.file_index().unwrap_or(0),
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(not(any(unix, windows)))]
fn metadata_object_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    format!("{:?}", metadata.file_type()).into_bytes()
}

#[cfg(unix)]
pub(crate) fn metadata_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    use std::os::unix::fs::MetadataExt as _;

    let mut bytes = Vec::with_capacity(80);
    for value in [
        metadata.dev(),
        metadata.ino(),
        metadata.mode() as u64,
        metadata.size(),
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
        metadata.ctime() as u64,
        metadata.ctime_nsec() as u64,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
pub(crate) fn metadata_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    use std::os::windows::fs::MetadataExt as _;

    let mut bytes = Vec::with_capacity(72);
    for value in [
        metadata.file_attributes() as u64,
        metadata.creation_time(),
        metadata.last_write_time(),
        metadata.file_size(),
        metadata.volume_serial_number().unwrap_or(0) as u64,
        metadata.number_of_links().unwrap_or(0) as u64,
        metadata.file_index().unwrap_or(0),
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn metadata_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    format!("{metadata:?}").into_bytes()
}

fn hash_record(hasher: &mut Sha256, kind: u8, fields: &[&[u8]]) {
    hasher.update([kind]);
    hasher.update((fields.len() as u64).to_le_bytes());
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
}

/// Collect input files matching glob patterns and hash their contents.
///
/// Returns sorted (relative_path, content_sha256_hex) pairs.
fn collect_input_files(
    project_dir: &Path,
    globs: &[String],
) -> Result<Vec<(PathBuf, String)>, LpmError> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let canonical_project = project_dir.canonicalize().map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    let project = Dir::open_ambient_dir(&canonical_project, cap_std::ambient_authority())?;

    for pattern in globs {
        if !crate::cache::validate_glob_pattern(pattern) {
            return Err(LpmError::Task(format!(
                "invalid task cache input glob: {pattern}"
            )));
        }

        // "src/**" → also match "src/**/*" for files at any depth
        let patterns = expand_glob(pattern);

        for pat in &patterns {
            let pattern_str = lpm_common::rooted_project_glob(project_dir, pat);

            let entries = glob::glob(&pattern_str).map_err(|error| {
                LpmError::Task(format!(
                    "invalid task cache input glob {pattern:?}: {error}"
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    LpmError::Task(format!(
                        "failed to expand task cache input glob {pattern:?}: {error}"
                    ))
                })?;
                let resolved = entry.canonicalize().map_err(|error| {
                    LpmError::Task(format!(
                        "failed to resolve task cache input {}: {error}",
                        entry.display()
                    ))
                })?;
                if !resolved.starts_with(&canonical_project) {
                    return Err(LpmError::Task(format!(
                        "task cache input resolves outside project: {}",
                        entry.display()
                    )));
                }
                let metadata = std::fs::metadata(&resolved)?;
                if !metadata.is_file() {
                    continue;
                }
                let relative = entry.strip_prefix(project_dir).map_err(|_| {
                    LpmError::Task(format!(
                        "task cache input is outside project path: {}",
                        entry.display()
                    ))
                })?;
                let relative = relative.to_path_buf();
                if seen.insert(relative.clone()) {
                    let resolved_relative =
                        resolved.strip_prefix(&canonical_project).map_err(|_| {
                            LpmError::Task(format!(
                                "task cache input resolves outside project: {}",
                                entry.display()
                            ))
                        })?;
                    let mut file = open_project_file_nofollow(&project, resolved_relative)?;
                    let content_hash = sha256_hex_reader(&mut file).map_err(|error| {
                        LpmError::Task(format!(
                            "failed to hash task cache input {}: {error}",
                            entry.display()
                        ))
                    })?;
                    let identity_hash =
                        hash_input_path_identity(project_dir, &relative, &metadata, &content_hash)?;
                    files.push((relative, identity_hash));
                }
            }
        }
    }

    // Sort for deterministic ordering
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn hash_input_path_identity(
    project_dir: &Path,
    relative: &Path,
    resolved_metadata: &std::fs::Metadata,
    content_hash: &str,
) -> Result<String, LpmError> {
    let mut hasher = Sha256::new();
    hash_record(&mut hasher, 0, &[b"task-input-v3"]);
    let mut current = project_dir.to_path_buf();
    let mut relative_component = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache input path: {}",
                relative.display()
            )));
        };
        current.push(name);
        relative_component.push(name);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            LpmError::Task(format!(
                "failed to inspect task cache input {}: {error}",
                current.display()
            ))
        })?;
        if lpm_common::is_symlink_or_junction(&metadata) {
            let target = std::fs::read_link(&current).map_err(|error| {
                LpmError::Task(format!(
                    "failed to read task cache input link {}: {error}",
                    current.display()
                ))
            })?;
            let component_bytes = os_str_bytes(relative_component.as_os_str());
            let target_bytes = os_str_bytes(target.as_os_str());
            hash_record(&mut hasher, 1, &[&component_bytes, &target_bytes]);
        }
    }
    let semantic_metadata = input_semantic_metadata_bytes(resolved_metadata);
    hash_record(
        &mut hasher,
        2,
        &[&semantic_metadata, content_hash.as_bytes()],
    );
    Ok(hex::encode(hasher.finalize()))
}

fn encode_relative_path(path: &Path) -> Result<Vec<u8>, LpmError> {
    let mut encoded = Vec::with_capacity(64);
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache input path: {}",
                path.display()
            )));
        };
        let (encoding, bytes) = if let Some(text) = name.to_str() {
            (0u8, text.as_bytes().to_vec())
        } else {
            (1u8, os_str_bytes(name))
        };
        encoded.push(encoding);
        encoded.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&bytes);
    }
    Ok(encoded)
}

#[cfg(unix)]
fn input_semantic_metadata_bytes(metadata: &std::fs::Metadata) -> [u8; 4] {
    use std::os::unix::fs::MetadataExt as _;

    (metadata.mode() & 0o111).to_le_bytes()
}

#[cfg(not(unix))]
fn input_semantic_metadata_bytes(_metadata: &std::fs::Metadata) -> [u8; 0] {
    []
}

#[cfg(unix)]
fn os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;
    value.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
fn os_str_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

fn open_project_file_nofollow(project: &Dir, relative: &Path) -> Result<std::fs::File, LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = project.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache input path: {}",
                relative.display()
            )));
        };
        if components.peek().is_some() {
            parent = parent.open_dir_nofollow(name).map_err(|error| {
                LpmError::Task(format!(
                    "task cache input parent is unsafe at {}: {error}",
                    relative.display()
                ))
            })?;
            continue;
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options).map_err(|error| {
            LpmError::Task(format!(
                "failed to open task cache input {} without following links: {error}",
                relative.display()
            ))
        })?;
        if !file.metadata()?.is_file() {
            return Err(LpmError::Task(format!(
                "task cache input is not a real file: {}",
                relative.display()
            )));
        }
        return Ok(file.into_std());
    }
    Err(LpmError::Task("invalid empty task cache input path".into()))
}

fn expand_glob(pattern: &str) -> Vec<String> {
    let mut patterns = vec![pattern.to_string()];
    if pattern.ends_with("/**") {
        patterns.push(format!("{pattern}/*"));
    }
    patterns
}

#[cfg(test)]
fn target_stays_in_project(entry: &Path, project_dir: &Path) -> bool {
    entry.canonicalize().is_ok_and(|entry| {
        project_dir
            .canonicalize()
            .is_ok_and(|project| entry.starts_with(project))
    })
}

fn open_project_directory(project_dir: &Path) -> Result<Dir, LpmError> {
    let canonical_project = project_dir.canonicalize().map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    Dir::open_ambient_dir(&canonical_project, cap_std::ambient_authority()).map_err(|error| {
        LpmError::Task(format!(
            "failed to open task cache project directory {}: {error}",
            canonical_project.display()
        ))
    })
}

fn hash_implicit_project_file(
    hasher: &mut Sha256,
    project: &Dir,
    kind: &str,
    name: &str,
) -> Result<bool, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match project.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LpmError::Task(format!(
                "failed to open task cache {kind} file '{name}' without following links: {error}"
            )));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        LpmError::Task(format!(
            "failed to inspect task cache {kind} file '{name}': {error}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(LpmError::Task(format!(
            "task cache {kind} file '{name}' is not a regular file"
        )));
    }
    let hash = sha256_hex_reader(&mut file.into_std()).map_err(|error| {
        LpmError::Task(format!(
            "failed to hash task cache {kind} file '{name}': {error}"
        ))
    })?;
    hash_implicit_file_value(hasher, kind, name, &hash);
    Ok(true)
}

fn hash_implicit_file_value(hasher: &mut Sha256, kind: &str, name: &str, value: &str) {
    hash_record(
        hasher,
        7,
        &[kind.as_bytes(), name.as_bytes(), value.as_bytes()],
    );
}

/// Compute SHA-256 hex string of a file using streaming reads.
///
/// Reads in 8 KiB chunks to avoid loading large files entirely into memory.
fn sha256_hex_reader(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
fn sha256_hex_file(path: &Path) -> std::io::Result<String> {
    sha256_hex_reader(&mut std::fs::File::open(path)?)
}

/// Canonicalize a JSON string so key ordering is deterministic.
///
/// Parses the JSON, explicitly sorts object keys recursively via `BTreeMap`,
/// then re-serializes. If parsing fails, returns the original string as-is.
fn canonicalize_json(json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => {
            let canonical = canonicalize_value(&value);
            serde_json::to_string(&canonical).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

/// Recursively sort all object keys using BTreeMap for deterministic output.
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

/// Simple hex encoding (avoid pulling in the `hex` crate).
///
/// Pre-allocates the output string to avoid per-byte allocations.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn compute_cache_key(
        project_dir: &Path,
        command: &str,
        extra_args: &[String],
        runtime_identities: &[(String, String)],
        input_globs: &[String],
        env_vars: &HashMap<String, String>,
        deps_json: &str,
    ) -> String {
        super::compute_cache_key(
            project_dir,
            command,
            extra_args,
            runtime_identities,
            input_globs,
            env_vars,
            deps_json,
        )
        .unwrap()
    }

    fn collect_input_files(project_dir: &Path, globs: &[String]) -> Vec<(PathBuf, String)> {
        super::collect_input_files(project_dir, globs).unwrap()
    }

    #[test]
    fn deterministic_key() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/index.js"), "console.log('hi')").unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let env = HashMap::new();
        let key1 = compute_cache_key(
            dir.path(),
            "echo build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "echo build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn different_command_different_key() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(dir.path(), "echo a", &[], &[], &[], &env, "{}");
        let key2 = compute_cache_key(dir.path(), "echo b", &[], &[], &[], &env, "{}");
        assert_ne!(key1, key2);
    }

    #[test]
    fn lpm_json_change_invalidates_cache_with_custom_inputs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("source.txt"), "source").unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"tasks":{}}"#).unwrap();
        let env = HashMap::new();
        let inputs = ["source.txt".into()];
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        fs::write(
            dir.path().join("lpm.json"),
            r#"{"tasks":{"build":{"dependsOn":["generate"]}}}"#,
        )
        .unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn authoritative_lockfile_change_invalidates_cache_with_custom_inputs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("source.txt"), "source").unwrap();
        fs::write(dir.path().join("lpm.lock"), "resolution = 1").unwrap();
        let env = HashMap::new();
        let inputs = ["source.txt".into()];
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        fs::write(dir.path().join("lpm.lock"), "resolution = 2").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &inputs, &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn derived_binary_lockfile_does_not_duplicate_authoritative_lockfile_identity() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.lock"), "resolution = 1").unwrap();
        fs::write(dir.path().join("lpm.lockb"), "derived one").unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        fs::write(dir.path().join("lpm.lockb"), "derived two").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        assert_eq!(key1, key2);
    }

    #[test]
    fn ecosystem_lockfile_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pnpm-lock.yaml"), "version: 1").unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        fs::write(dir.path().join("pnpm-lock.yaml"), "version: 2").unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        assert_ne!(key1, key2);
    }

    #[test]
    fn pnpm_workspace_file_change_invalidates_root_task_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n",
        )
        .unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - apps/*\n",
        )
        .unwrap();
        let key2 = compute_cache_key(dir.path(), "build", &[], &[], &[], &env, "{}");

        assert_ne!(key1, key2);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_contract_rejects_symlinked_lockfiles() {
        let workspace = tempfile::tempdir().unwrap();
        let member = workspace.path().join("packages/app");
        fs::create_dir_all(&member).unwrap();
        fs::write(workspace.path().join("real.lock"), "resolution = 1").unwrap();
        std::os::unix::fs::symlink(
            workspace.path().join("real.lock"),
            workspace.path().join("lpm.lock"),
        )
        .unwrap();

        let error = compute_cache_key_with_workspace_root(
            &member,
            Some(workspace.path()),
            &[],
            "build",
            &[],
            &[],
            &[],
            &HashMap::new(),
            "{}",
        )
        .unwrap_err();

        assert!(error.to_string().contains("workspace-lockfile"));
    }

    #[test]
    fn different_env_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut env1 = HashMap::new();
        env1.insert("NODE_ENV".into(), "development".into());

        let mut env2 = HashMap::new();
        env2.insert("NODE_ENV".into(), "production".into());

        let key1 = compute_cache_key(dir.path(), "echo", &[], &[], &[], &env1, "{}");
        let key2 = compute_cache_key(dir.path(), "echo", &[], &[], &[], &env2, "{}");
        assert_ne!(key1, key2);
    }

    #[test]
    fn environment_hash_framing_distinguishes_embedded_record_text() {
        let dir = tempfile::tempdir().unwrap();
        let one_variable = HashMap::from([("A".into(), "x\nenv:B=y".into())]);
        let two_variables = HashMap::from([("A".into(), "x".into()), ("B".into(), "y".into())]);

        let one_key = compute_cache_key(dir.path(), "build", &[], &[], &[], &one_variable, "{}");
        let two_keys = compute_cache_key(dir.path(), "build", &[], &[], &[], &two_variables, "{}");

        assert_ne!(one_key, two_keys);
    }

    #[test]
    fn file_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/index.js"), "v1").unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );

        fs::write(dir.path().join("src/index.js"), "v2").unwrap();

        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &env,
            "{}",
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn deps_json_ordering_does_not_affect_key() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        // Two different JSON key orderings of the same data
        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"react":"^19","lodash":"^4"}"#,
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"lodash":"^4","react":"^19"}"#,
        );
        assert_eq!(
            key1, key2,
            "different JSON key ordering should produce same cache key"
        );
    }

    #[test]
    fn canonicalize_json_sorts_keys() {
        let a = canonicalize_json(r#"{"b":"2","a":"1"}"#);
        let b = canonicalize_json(r#"{"a":"1","b":"2"}"#);
        assert_eq!(a, b);
    }

    #[test]
    fn canonicalize_json_invalid_passthrough() {
        let result = canonicalize_json("not-json");
        assert_eq!(result, "not-json");
    }

    #[test]
    fn deps_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"react":"^18"}"#,
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[],
            &[],
            &env,
            r#"{"react":"^19"}"#,
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_cli_arguments_produce_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &["--target".into(), "node".into()],
            &[],
            &[],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &["--target".into(), "browser".into()],
            &[],
            &[],
            &env,
            "{}",
        );

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_runtime_identities_produce_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();

        let key1 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[("node".into(), "fingerprint-a".into())],
            &[],
            &env,
            "{}",
        );
        let key2 = compute_cache_key(
            dir.path(),
            "build",
            &[],
            &[("node".into(), "fingerprint-b".into())],
            &[],
            &env,
            "{}",
        );

        assert_ne!(key1, key2);
    }

    #[test]
    fn upstream_task_identity_change_invalidates_cache() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key_with_workspace_root(
            dir.path(),
            None,
            &[("@test/utils#build".into(), "identity-v1".into())],
            "build",
            &[],
            &[],
            &[],
            &env,
            "{}",
        )
        .unwrap();
        let key2 = compute_cache_key_with_workspace_root(
            dir.path(),
            None,
            &[("@test/utils#build".into(), "identity-v2".into())],
            "build",
            &[],
            &[],
            &[],
            &env,
            "{}",
        )
        .unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn upstream_task_identity_order_does_not_change_cache_key() {
        let dir = tempfile::tempdir().unwrap();
        let env = HashMap::new();
        let key1 = compute_cache_key_with_workspace_root(
            dir.path(),
            None,
            &[
                ("@test/core#build".into(), "core".into()),
                ("@test/utils#build".into(), "utils".into()),
            ],
            "build",
            &[],
            &[],
            &[],
            &env,
            "{}",
        )
        .unwrap();
        let key2 = compute_cache_key_with_workspace_root(
            dir.path(),
            None,
            &[
                ("@test/utils#build".into(), "utils".into()),
                ("@test/core#build".into(), "core".into()),
            ],
            "build",
            &[],
            &[],
            &[],
            &env,
            "{}",
        )
        .unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn dependency_fingerprint_is_independent_of_graph_iteration_order() {
        let first = compute_dependency_fingerprint(&[
            ("local:build".into(), "build-key".into()),
            ("workspace:@test/core#build".into(), "core-key".into()),
        ]);
        let second = compute_dependency_fingerprint(&[
            ("workspace:@test/core#build".into(), "core-key".into()),
            ("local:build".into(), "build-key".into()),
        ]);

        assert_eq!(first, second);
    }

    #[test]
    fn dependency_identity_change_alters_the_fingerprint() {
        let first =
            compute_dependency_fingerprint(&[("local:build".into(), "build-key-v1".into())]);
        let second =
            compute_dependency_fingerprint(&[("local:build".into(), "build-key-v2".into())]);

        assert_ne!(first, second);
    }

    #[test]
    fn input_hashing_handles_glob_metacharacters_in_project_path() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project[abc]");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join("src/index.js"), "input").unwrap();

        let files = collect_input_files(&project, &["src/**".into()]);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, Path::new("src/index.js"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn input_hashing_keeps_distinct_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("src")).unwrap();
        fs::write(
            project
                .path()
                .join("src")
                .join(std::ffi::OsString::from_vec(vec![0x80])),
            "first",
        )
        .unwrap();
        fs::write(
            project
                .path()
                .join("src")
                .join(std::ffi::OsString::from_vec(vec![0x81])),
            "second",
        )
        .unwrap();

        let files = collect_input_files(project.path(), &["src/**".into()]);

        assert_eq!(files.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn input_path_encoding_keeps_distinct_non_utf8_components() {
        use std::os::unix::ffi::OsStringExt as _;

        let first = PathBuf::from(std::ffi::OsString::from_vec(vec![0x80]));
        let second = PathBuf::from(std::ffi::OsString::from_vec(vec![0x81]));

        assert_ne!(
            encode_relative_path(&first).unwrap(),
            encode_relative_path(&second).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_permission_change_alters_the_cache_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("src")).unwrap();
        let input = project.path().join("src/tool");
        fs::write(&input, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        let first = compute_cache_key(
            project.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &HashMap::new(),
            "{}",
        );

        fs::set_permissions(&input, fs::Permissions::from_mode(0o755)).unwrap();
        let second = compute_cache_key(
            project.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &HashMap::new(),
            "{}",
        );

        assert_ne!(first, second);
    }

    #[cfg(windows)]
    #[test]
    fn junction_retarget_alters_the_cache_key() {
        let project = tempfile::tempdir().unwrap();
        let first_target = project.path().join("first");
        let second_target = project.path().join("second");
        fs::create_dir(&first_target).unwrap();
        fs::create_dir(&second_target).unwrap();
        fs::write(first_target.join("value.txt"), "same").unwrap();
        fs::write(second_target.join("value.txt"), "same").unwrap();
        let input = project.path().join("src");
        lpm_common::create_dir_symlink_or_junction(&first_target, &input).unwrap();
        let first = compute_cache_key(
            project.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &HashMap::new(),
            "{}",
        );

        lpm_common::remove_symlink_or_junction_entry(&input).unwrap();
        lpm_common::create_dir_symlink_or_junction(&second_target, &input).unwrap();
        let second = compute_cache_key(
            project.path(),
            "build",
            &[],
            &[],
            &["src/**".into()],
            &HashMap::new(),
            "{}",
        );

        assert_ne!(first, second);
    }

    #[test]
    fn input_validation_ignores_unmatched_project_entries() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("src")).unwrap();
        fs::write(project.path().join("src/input.js"), "input").unwrap();
        let validation =
            capture_cache_input_validation(project.path(), &["src/**".into()]).unwrap();

        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/output.js"), "output").unwrap();

        assert!(validation.is_unchanged().unwrap());
    }

    // -- canonicalize_value sorts keys explicitly --

    #[test]
    fn canonicalize_value_sorts_nested_keys() {
        use serde_json::json;
        let a = json!({"z": 1, "a": {"c": 3, "b": 2}});
        let b = json!({"a": {"b": 2, "c": 3}, "z": 1});
        let ca = serde_json::to_string(&canonicalize_value(&a)).unwrap();
        let cb = serde_json::to_string(&canonicalize_value(&b)).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn canonicalize_value_handles_arrays() {
        use serde_json::json;
        let val = json!([{"b": 2, "a": 1}, {"d": 4, "c": 3}]);
        let canonical = canonicalize_value(&val);
        let s = serde_json::to_string(&canonical).unwrap();
        assert_eq!(s, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
    }

    // -- streaming file hash --

    #[test]
    fn sha256_hex_file_correct_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").unwrap();

        let hash = sha256_hex_file(&path).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // -- hex encoding --

    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex::encode([0x00, 0xff, 0x0a, 0xab]), "00ff0aab");
        assert_eq!(hex::encode([]), "");
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    /// A regular file under project_dir is accepted by the containment helper.
    #[test]
    fn target_stays_in_project_accepts_regular_file_under_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        let file = dir.path().join("src/index.js");
        fs::write(&file, "ok").unwrap();
        assert!(target_stays_in_project(&file, dir.path()));
    }

    /// A committed symlink outside the project must not enter the cache key.
    #[cfg(unix)]
    #[test]
    fn target_stays_in_project_rejects_symlink_pointing_outside() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.env");
        fs::write(&secret, "API_KEY=hunter2").unwrap();

        let link = project.path().join("escape");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        assert!(
            !target_stays_in_project(&link, project.path()),
            "symlink to a file outside project_dir must be refused"
        );
    }

    /// A broken symlink also fails closed because canonicalization fails.
    /// Without this we'd silently swallow the entry instead of
    /// flagging it.
    #[cfg(unix)]
    #[test]
    fn target_stays_in_project_rejects_broken_symlink() {
        let project = tempfile::tempdir().unwrap();
        let link = project.path().join("dangling");
        std::os::unix::fs::symlink(project.path().join("does-not-exist"), &link).unwrap();
        assert!(!target_stays_in_project(&link, project.path()));
    }
}
