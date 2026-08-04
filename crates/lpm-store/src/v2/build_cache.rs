//! Content-addressed artifacts produced by dependency lifecycle builds.

use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};

use super::fs_util::{
    create_tmp_dir_locked, ensure_store_tier_dir_locked, materialize_into, materialize_into_inner,
    tmp_sibling,
};
use super::store::Store;
use super::tree_hash::{ObjectTreeStats, compute_object_tree_integrities};

const BUILD_KEY_SCHEMA: &[u8] = b"lpm-build-key-v1\0";
const BUILD_ARTIFACT_SCHEMA: u32 = 1;
const BUILD_PACKAGE_DIR: &str = "package";
const BUILD_MANIFEST_FILE: &str = "manifest.json";
/// Sentinel written inside every atomically published build artifact.
pub const BUILD_ARTIFACT_COMPLETE_FILENAME: &str = ".lpm-build-complete";
const BUILD_MANIFEST_MAX_BYTES: u64 = 256 * 1024;

/// One lifecycle phase and its exact command body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildScriptFingerprint {
    /// Lifecycle phase name, normally `preinstall`, `install`, or `postinstall`.
    pub phase: String,
    /// Exact command passed to the lifecycle shell.
    pub command: String,
}

/// Host compatibility dimensions that can affect native output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlatformFingerprint {
    /// npm-compatible operating-system name.
    pub os: String,
    /// npm-compatible CPU architecture name.
    pub architecture: String,
    /// Linux libc family, or an empty string on other systems.
    pub libc: String,
    /// Canonical digest of the host's compatible CPU feature set.
    pub cpu_features_hash: String,
}

/// Runtime identity observed from the executable used by lifecycle scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRuntimeFingerprint {
    /// Runtime family, initially `node`.
    pub runtime: String,
    /// Exact runtime version.
    pub version: String,
    /// Native-module ABI reported by the runtime.
    pub modules_abi: String,
    /// N-API version reported by the runtime.
    pub napi: String,
    /// Embedded JavaScript-engine version.
    pub engine: String,
    /// Digest identifying the resolved runtime executable.
    pub executable_hash: String,
}

/// Effective containment and allowed-input policy for one build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSandboxFingerprint {
    /// Requested runtime mode.
    pub mode: String,
    /// Effective backend posture after platform degradation decisions.
    pub posture: String,
    /// Whether outbound network access was denied.
    pub network_denied: bool,
    /// Whether credential and ambient environment scrubbing was active.
    pub environment_scrubbed: bool,
    /// Canonical hash of readable and writable input policy.
    pub allowed_inputs_hash: String,
}

/// Complete deterministic input set for a dependency build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildKeyInputs {
    /// Integrity of the pristine source object.
    pub source_integrity: String,
    /// Full graph-key digest for the materialized dependency context.
    pub graph_key_digest: String,
    /// Digest of dependency sources and dependency build identities.
    pub dependency_closure_hash: String,
    /// Executed lifecycle phases in execution order.
    pub scripts: Vec<BuildScriptFingerprint>,
    /// Host compatibility fingerprint.
    pub platform: BuildPlatformFingerprint,
    /// Runtime/ABI fingerprint.
    pub runtime: BuildRuntimeFingerprint,
    /// Effective sandbox fingerprint.
    pub sandbox: BuildSandboxFingerprint,
    /// Digest of the complete environment exposed to the lifecycle script.
    pub environment_hash: String,
    /// Digest of discoverable compiler, SDK, and build-tool identities.
    pub toolchain_hash: String,
}

/// Filesystem-safe digest identifying interchangeable build output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BuildCacheKey(String);

impl BuildCacheKey {
    /// Derive a key from every input that can affect lifecycle output.
    pub fn derive(inputs: &BuildKeyInputs) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BUILD_KEY_SCHEMA);
        hash_field(&mut hasher, b"source", inputs.source_integrity.as_bytes());
        hash_field(&mut hasher, b"graph", inputs.graph_key_digest.as_bytes());
        hash_field(
            &mut hasher,
            b"dependency_closure",
            inputs.dependency_closure_hash.as_bytes(),
        );
        for script in &inputs.scripts {
            hash_field(&mut hasher, b"phase", script.phase.as_bytes());
            hash_field(&mut hasher, b"command", script.command.as_bytes());
        }
        hash_field(&mut hasher, b"os", inputs.platform.os.as_bytes());
        hash_field(
            &mut hasher,
            b"architecture",
            inputs.platform.architecture.as_bytes(),
        );
        hash_field(&mut hasher, b"libc", inputs.platform.libc.as_bytes());
        hash_field(
            &mut hasher,
            b"cpu_features",
            inputs.platform.cpu_features_hash.as_bytes(),
        );
        hash_field(&mut hasher, b"runtime", inputs.runtime.runtime.as_bytes());
        hash_field(
            &mut hasher,
            b"runtime_version",
            inputs.runtime.version.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"modules_abi",
            inputs.runtime.modules_abi.as_bytes(),
        );
        hash_field(&mut hasher, b"napi", inputs.runtime.napi.as_bytes());
        hash_field(&mut hasher, b"engine", inputs.runtime.engine.as_bytes());
        hash_field(
            &mut hasher,
            b"runtime_executable",
            inputs.runtime.executable_hash.as_bytes(),
        );
        hash_field(&mut hasher, b"sandbox_mode", inputs.sandbox.mode.as_bytes());
        hash_field(
            &mut hasher,
            b"sandbox_posture",
            inputs.sandbox.posture.as_bytes(),
        );
        hash_bool(
            &mut hasher,
            b"network_denied",
            inputs.sandbox.network_denied,
        );
        hash_bool(
            &mut hasher,
            b"environment_scrubbed",
            inputs.sandbox.environment_scrubbed,
        );
        hash_field(
            &mut hasher,
            b"allowed_inputs",
            inputs.sandbox.allowed_inputs_hash.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"environment",
            inputs.environment_hash.as_bytes(),
        );
        hash_field(&mut hasher, b"toolchain", inputs.toolchain_hash.as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    /// Lowercase hexadecimal representation used as the directory name.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn hash_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(label);
    hasher.update(b"\0");
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_bool(hasher: &mut blake3::Hasher, label: &[u8], value: bool) {
    hash_field(hasher, label, &[u8::from(value)]);
}

/// Integrity and provenance metadata for a completed build artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildArtifactManifest {
    /// On-disk manifest schema.
    pub schema: u32,
    /// Cache key owning this artifact.
    pub key: String,
    /// Integrity of the pristine source object.
    pub source_integrity: String,
    /// SHA-256 tree digest of the complete built package.
    pub output_integrity: String,
    /// Number of files in the built package.
    pub file_count: u64,
    /// Total bytes in regular files.
    pub unpacked_bytes: u64,
    /// Time spent executing lifecycle commands when this artifact was created.
    pub lifecycle_duration_ms: u64,
    /// Artifact publication time.
    pub created_at: DateTime<Utc>,
}

/// A validated build artifact ready to restore.
#[derive(Debug, Clone)]
pub struct BuildArtifact {
    /// Content-addressed artifact directory.
    pub directory: PathBuf,
    /// Validated artifact manifest.
    pub manifest: BuildArtifactManifest,
}

impl BuildArtifact {
    /// Directory containing the complete built package tree.
    #[inline]
    pub fn package_dir(&self) -> PathBuf {
        self.directory.join(BUILD_PACKAGE_DIR)
    }
}

/// Result of publishing a successful lifecycle build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildArtifactPublish {
    /// This call published a new artifact.
    Published,
    /// An equivalent complete artifact already existed.
    Existing,
}

impl Store {
    /// Return a validated local build artifact, or `None` on a miss or corruption.
    pub fn reusable_build_artifact(
        &self,
        key: &BuildCacheKey,
    ) -> Result<Option<BuildArtifact>, LpmError> {
        let dir = self.paths().build_artifact_dir(key);
        if !dir.is_dir() || !dir.join(BUILD_ARTIFACT_COMPLETE_FILENAME).is_file() {
            return Ok(None);
        }
        let manifest = match read_manifest(&dir) {
            Ok(manifest) if manifest.key == key.as_str() => manifest,
            Ok(_) | Err(_) => return Ok(None),
        };
        let package_dir = dir.join(BUILD_PACKAGE_DIR);
        if !package_dir.is_dir() || !tree_has_safe_symlinks(&package_dir)? {
            return Ok(None);
        }
        let actual = compute_object_tree_integrities(&package_dir)?;
        if actual.content != manifest.output_integrity
            || actual.stats.file_count != manifest.file_count
            || actual.stats.unpacked_bytes != manifest.unpacked_bytes
        {
            return Ok(None);
        }
        if let Ok(file) = std::fs::File::options()
            .write(true)
            .open(dir.join(BUILD_ARTIFACT_COMPLETE_FILENAME))
        {
            let _ = file.set_modified(std::time::SystemTime::now());
        }
        Ok(Some(BuildArtifact {
            directory: dir,
            manifest,
        }))
    }

    /// Publish a successful package-local lifecycle build atomically.
    pub fn publish_build_artifact(
        &self,
        key: &BuildCacheKey,
        source_integrity: &str,
        built_package_dir: &Path,
        lifecycle_duration_ms: u64,
        replace_existing: bool,
    ) -> Result<BuildArtifactPublish, LpmError> {
        if !replace_existing && self.reusable_build_artifact(key)?.is_some() {
            return Ok(BuildArtifactPublish::Existing);
        }
        if !tree_has_safe_symlinks(built_package_dir)? {
            return Err(LpmError::Store(format!(
                "refusing to cache lifecycle output at {} because it contains an escaping symlink",
                built_package_dir.display()
            )));
        }
        ensure_store_tier_dir_locked(self.paths().builds_root()).map_err(|error| {
            LpmError::Store(format!(
                "failed to create virtual-store builds directory: {error}"
            ))
        })?;

        let final_dir = self.paths().build_artifact_dir(key);
        if final_dir.exists() {
            std::fs::remove_dir_all(&final_dir).map_err(|error| {
                LpmError::Store(format!(
                    "failed to remove corrupt build artifact at {}: {error}",
                    final_dir.display()
                ))
            })?;
        }
        let tmp_dir = tmp_sibling(&final_dir);
        create_tmp_dir_locked(&tmp_dir).map_err(|error| {
            LpmError::Store(format!(
                "failed to create build artifact staging directory at {}: {error}",
                tmp_dir.display()
            ))
        })?;

        let staged_package = tmp_dir.join(BUILD_PACKAGE_DIR);
        let publish_result = (|| {
            materialize_into_inner(built_package_dir, built_package_dir, &staged_package, true)?;
            let tree = compute_object_tree_integrities(&staged_package)?;
            let manifest = manifest_from_tree(
                key,
                source_integrity,
                &tree.stats,
                tree.content,
                lifecycle_duration_ms,
            );
            let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| {
                LpmError::Store(format!(
                    "failed to serialize build artifact manifest: {error}"
                ))
            })?;
            std::fs::write(tmp_dir.join(BUILD_MANIFEST_FILE), bytes)?;
            std::fs::write(tmp_dir.join(BUILD_ARTIFACT_COMPLETE_FILENAME), b"")?;
            Ok::<(), LpmError>(())
        })();
        if let Err(error) = publish_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }

        match std::fs::rename(&tmp_dir, &final_dir) {
            Ok(()) => Ok(BuildArtifactPublish::Published),
            Err(error) if final_dir.exists() => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                if self.reusable_build_artifact(key)?.is_some() {
                    Ok(BuildArtifactPublish::Existing)
                } else {
                    Err(LpmError::Store(format!(
                        "concurrent build artifact publication left an invalid entry at {}: {error}",
                        final_dir.display()
                    )))
                }
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!(
                    "failed to publish build artifact at {}: {error}",
                    final_dir.display()
                )))
            }
        }
    }

    /// Restore a validated build artifact over a materialized package tree.
    pub fn restore_build_artifact(
        &self,
        artifact: &BuildArtifact,
        destination: &Path,
    ) -> Result<(), LpmError> {
        let staged = tmp_sibling(destination);
        materialize_into_inner(
            &artifact.package_dir(),
            &artifact.package_dir(),
            &staged,
            true,
        )?;
        replace_with_staged_tree(destination, &staged)
    }

    /// Replace a built link-package tree with its verified pristine object.
    pub fn restore_pristine_package(
        &self,
        pristine_object_dir: &Path,
        destination: &Path,
    ) -> Result<(), LpmError> {
        let staged = tmp_sibling(destination);
        materialize_into(pristine_object_dir, &staged)?;
        replace_with_staged_tree(destination, &staged)
    }
}

fn replace_with_staged_tree(destination: &Path, staged: &Path) -> Result<(), LpmError> {
    let parent = destination.parent().ok_or_else(|| {
        LpmError::Store(format!(
            "package-tree destination has no parent: {}",
            destination.display()
        ))
    })?;
    let backup =
        destination.with_extension(format!("lpm-build-backup.{:016x}", rand::random::<u64>()));
    if destination.exists() {
        std::fs::rename(destination, &backup).map_err(|error| {
            let _ = std::fs::remove_dir_all(staged);
            LpmError::Store(format!(
                "failed to stage existing package tree at {}: {error}",
                destination.display()
            ))
        })?;
    }
    if let Err(error) = std::fs::rename(staged, destination) {
        if backup.exists() {
            let _ = std::fs::rename(&backup, destination);
        }
        let _ = std::fs::remove_dir_all(staged);
        return Err(LpmError::Store(format!(
            "failed to restore build artifact into {} from {}: {error}",
            destination.display(),
            parent.display()
        )));
    }
    if backup.exists() {
        std::fs::remove_dir_all(&backup).map_err(|error| {
            LpmError::Store(format!(
                "restored build artifact but failed to remove backup at {}: {error}",
                backup.display()
            ))
        })?;
    }
    Ok(())
}

fn manifest_from_tree(
    key: &BuildCacheKey,
    source_integrity: &str,
    stats: &ObjectTreeStats,
    output_integrity: String,
    lifecycle_duration_ms: u64,
) -> BuildArtifactManifest {
    BuildArtifactManifest {
        schema: BUILD_ARTIFACT_SCHEMA,
        key: key.as_str().to_string(),
        source_integrity: source_integrity.to_string(),
        output_integrity,
        file_count: stats.file_count,
        unpacked_bytes: stats.unpacked_bytes,
        lifecycle_duration_ms,
        created_at: Utc::now(),
    }
}

fn read_manifest(dir: &Path) -> Result<BuildArtifactManifest, LpmError> {
    let path = dir.join(BUILD_MANIFEST_FILE);
    let metadata = std::fs::metadata(&path)?;
    if metadata.len() > BUILD_MANIFEST_MAX_BYTES {
        return Err(LpmError::Store(format!(
            "build artifact manifest exceeds {} bytes at {}",
            BUILD_MANIFEST_MAX_BYTES,
            path.display()
        )));
    }
    let bytes = std::fs::read(&path)?;
    let manifest: BuildArtifactManifest = serde_json::from_slice(&bytes).map_err(|error| {
        LpmError::Store(format!(
            "failed to parse build artifact manifest at {}: {error}",
            path.display()
        ))
    })?;
    if manifest.schema != BUILD_ARTIFACT_SCHEMA {
        return Err(LpmError::Store(format!(
            "unsupported build artifact schema {} at {}",
            manifest.schema,
            path.display()
        )));
    }
    Ok(manifest)
}

fn tree_has_safe_symlinks(root: &Path) -> Result<bool, LpmError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_symlink() {
                let target = std::fs::read_link(&path)?;
                let relative_parent = path
                    .parent()
                    .and_then(|parent| parent.strip_prefix(root).ok())
                    .unwrap_or_else(|| Path::new(""));
                if !relative_target_stays_in_root(relative_parent, &target) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn relative_target_stays_in_root(parent: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth = parent.components().count();
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth = depth.saturating_add(1),
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> BuildKeyInputs {
        BuildKeyInputs {
            source_integrity: "sha512-source".into(),
            graph_key_digest: "graph".into(),
            dependency_closure_hash: "closure".into(),
            scripts: vec![BuildScriptFingerprint {
                phase: "install".into(),
                command: "node-gyp rebuild".into(),
            }],
            platform: BuildPlatformFingerprint {
                os: "linux".into(),
                architecture: "x64".into(),
                libc: "glibc".into(),
                cpu_features_hash: "cpu".into(),
            },
            runtime: BuildRuntimeFingerprint {
                runtime: "node".into(),
                version: "22.12.0".into(),
                modules_abi: "127".into(),
                napi: "10".into(),
                engine: "12.4".into(),
                executable_hash: "node-binary".into(),
            },
            sandbox: BuildSandboxFingerprint {
                mode: "enforce".into(),
                posture: "strict".into(),
                network_denied: true,
                environment_scrubbed: true,
                allowed_inputs_hash: "policy".into(),
            },
            environment_hash: "env".into(),
            toolchain_hash: "toolchain".into(),
        }
    }

    #[test]
    fn build_key_is_deterministic_for_identical_inputs() {
        let inputs = sample_inputs();
        assert_eq!(
            BuildCacheKey::derive(&inputs),
            BuildCacheKey::derive(&inputs)
        );
    }

    #[test]
    fn build_key_changes_when_node_abi_changes() {
        let first = sample_inputs();
        let mut second = first.clone();
        second.runtime.modules_abi = "131".into();
        assert_ne!(
            BuildCacheKey::derive(&first),
            BuildCacheKey::derive(&second)
        );
    }

    #[test]
    fn build_key_changes_when_sandbox_policy_changes() {
        let first = sample_inputs();
        let mut second = first.clone();
        second.sandbox.network_denied = false;
        assert_ne!(
            BuildCacheKey::derive(&first),
            BuildCacheKey::derive(&second)
        );
    }

    #[test]
    fn build_artifact_round_trip_restores_complete_tree() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir_all(source.join("build/Release")).unwrap();
        std::fs::write(source.join("package.json"), b"{}").unwrap();
        std::fs::write(source.join("build/Release/addon.node"), b"native").unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("stale"), b"stale").unwrap();
        let key = BuildCacheKey::derive(&sample_inputs());

        let published = store
            .publish_build_artifact(&key, "sha512-source", &source, 125, false)
            .unwrap();
        let artifact = store.reusable_build_artifact(&key).unwrap().unwrap();
        store
            .restore_build_artifact(&artifact, &destination)
            .unwrap();

        assert_eq!(published, BuildArtifactPublish::Published);
        assert_eq!(artifact.manifest.lifecycle_duration_ms, 125);
        assert_eq!(
            std::fs::read(destination.join("build/Release/addon.node")).unwrap(),
            b"native"
        );
        assert!(!destination.join("stale").exists());
    }

    #[test]
    fn build_lock_path_is_stable_and_separate_from_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let key = BuildCacheKey::derive(&sample_inputs());

        let lock_path = store.paths().build_lock_path(&key);

        assert_eq!(
            lock_path,
            temp.path()
                .join("store/build-locks")
                .join(format!("{}.lock", key.as_str()))
        );
        assert!(!lock_path.starts_with(store.paths().builds_root()));
    }

    #[test]
    fn build_entry_lock_path_is_keyed_by_graph_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let graph_key = "a".repeat(64);

        assert_eq!(
            store.paths().build_entry_lock_path(&graph_key).unwrap(),
            temp.path()
                .join("store/build-entry-locks")
                .join(format!("{graph_key}.lock"))
        );
    }

    #[test]
    fn build_entry_lock_path_rejects_traversal_digest() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));

        assert!(
            store
                .paths()
                .build_entry_lock_path("../../outside")
                .is_err()
        );
    }

    #[test]
    fn build_artifact_corruption_is_a_cache_miss() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("package.json"), b"{}").unwrap();
        let key = BuildCacheKey::derive(&sample_inputs());
        store
            .publish_build_artifact(&key, "sha512-source", &source, 125, false)
            .unwrap();
        let artifact_dir = store.paths().build_artifact_dir(&key);
        std::fs::write(artifact_dir.join("package/package.json"), b"corrupt").unwrap();

        assert!(store.reusable_build_artifact(&key).unwrap().is_none());
    }

    #[test]
    fn pristine_restore_replaces_previous_build_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let pristine = temp.path().join("pristine");
        let destination = temp.path().join("destination");
        std::fs::create_dir_all(&pristine).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(pristine.join("package.json"), b"{}").unwrap();
        std::fs::write(destination.join("old-build.node"), b"old").unwrap();

        store
            .restore_pristine_package(&pristine, &destination)
            .unwrap();

        assert!(destination.join("package.json").is_file());
        assert!(!destination.join("old-build.node").exists());
    }

    #[test]
    fn forced_publication_replaces_existing_artifact_for_same_key() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("output.node"), b"first").unwrap();
        let key = BuildCacheKey::derive(&sample_inputs());
        store
            .publish_build_artifact(&key, "sha512-source", &source, 10, false)
            .unwrap();

        std::fs::write(source.join("output.node"), b"second").unwrap();
        store
            .publish_build_artifact(&key, "sha512-source", &source, 20, true)
            .unwrap();
        let artifact = store.reusable_build_artifact(&key).unwrap().unwrap();

        assert_eq!(
            std::fs::read(artifact.package_dir().join("output.node")).unwrap(),
            b"second"
        );
        assert_eq!(artifact.manifest.lifecycle_duration_ms, 20);
    }

    #[cfg(unix)]
    #[test]
    fn build_artifact_rejects_symlink_that_escapes_package() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = Store::at(temp.path().join("store"));
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("package.json"), b"{}").unwrap();
        symlink("../secret", source.join("escape")).unwrap();
        let key = BuildCacheKey::derive(&sample_inputs());

        let error = store
            .publish_build_artifact(&key, "sha512-source", &source, 125, false)
            .unwrap_err();
        assert!(error.to_string().contains("escaping symlink"));
    }
}
