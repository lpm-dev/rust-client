//! Portable runtime content identities with independent local race validation.

use crate::detect::RuntimeKind;
use crate::effective::{hash_os_string, runtime_executable_in_path, update_with_file_metadata};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const RUNTIMES: [RuntimeKind; 2] = [RuntimeKind::Node, RuntimeKind::Bun];
type DigestCell = Arc<OnceLock<Option<String>>>;

struct SelectedRuntime {
    canonical: PathBuf,
    fingerprint: String,
    native: bool,
}

/// Content inputs for a relocatable task and local evidence used to validate them.
pub struct PortableRuntimeSnapshot {
    identities: Vec<(String, String)>,
    cwd: PathBuf,
    path: OsString,
    local: [Option<String>; 2],
}

impl PortableRuntimeSnapshot {
    /// Capture the actual script PATH. Unrecognized launchers retain local identity.
    /// Returns None if a selected executable changes or cannot be fingerprinted.
    pub fn capture(cwd: &Path, path: &OsStr) -> Option<Self> {
        let selected = selected_runtimes(cwd, path)?;
        let local = std::array::from_fn(|index| {
            selected[index]
                .as_ref()
                .map(|runtime| runtime.fingerprint.clone())
        });
        let mut identities = Vec::with_capacity(3);
        identities.push(("task-cache-platform".into(), platform_identity()));
        for (runtime, selected) in RUNTIMES.into_iter().zip(&selected) {
            let identity = match selected {
                None => "missing".into(),
                Some(selected) if selected.native => {
                    let digest = executable_digest(&selected.canonical, &selected.fingerprint)?;
                    format!("content:{digest}")
                }
                // A launcher's bytes cannot establish portable execution equivalence.
                Some(selected) => format!("local:{}", selected.fingerprint),
            };
            identities.push((format!("{}-executable", runtime.as_str()), identity));
        }
        let snapshot = Self {
            identities,
            cwd: cwd.to_path_buf(),
            path: path.to_os_string(),
            local,
        };
        snapshot.is_unchanged().then_some(snapshot)
    }

    pub fn identities(&self) -> &[(String, String)] {
        &self.identities
    }

    /// Recheck PATH selection and filesystem state without reading large binaries.
    pub fn is_unchanged(&self) -> bool {
        selected_runtimes(&self.cwd, &self.path).is_some_and(|selected| {
            selected.iter().zip(&self.local).all(|(selected, local)| {
                selected.as_ref().map(|runtime| &runtime.fingerprint) == local.as_ref()
            })
        })
    }
}

fn platform_identity() -> String {
    format!(
        "portable-task-v1/{}/{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        lpm_common::platform::detect_libc().unwrap_or("none")
    )
}

fn selected_runtimes(cwd: &Path, path: &OsStr) -> Option<[Option<SelectedRuntime>; 2]> {
    let mut identities = [None, None];
    for (index, runtime) in RUNTIMES.into_iter().enumerate() {
        if let Some(executable) = runtime_executable_in_path(cwd, path, runtime) {
            let canonical = executable.canonicalize().ok()?;
            let metadata = canonical.metadata().ok()?;
            let native = native_runtime(runtime, &canonical, &metadata);
            let physical = local_fingerprint(&canonical)?;
            let fingerprint = if native {
                physical
            } else {
                let mut hasher = Sha256::new();
                hasher.update(b"lpm-task-launcher-v1\0");
                hasher.update(physical.as_bytes());
                for value in [cwd.as_os_str(), path] {
                    hasher.update((value.len() as u64).to_le_bytes());
                    hash_os_string(&mut hasher, value);
                }
                // Version-manager selectors also apply to launchers that choose Bun.
                hasher.update(
                    crate::effective::probe_node_fingerprint_on_path(cwd, path)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                format!("{:x}", hasher.finalize())
            };
            identities[index] = Some(SelectedRuntime {
                canonical,
                fingerprint,
                native,
            });
        }
    }
    Some(identities)
}

fn local_fingerprint(canonical: &Path) -> Option<String> {
    let metadata = canonical.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-task-runtime-local-v1\0");
    hash_os_string(&mut hasher, canonical.as_os_str());
    update_with_file_metadata(&mut hasher, &metadata);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // ctime prevents reuse after an edit that restores the old mtime.
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn native_runtime(runtime: RuntimeKind, canonical: &Path, metadata: &std::fs::Metadata) -> bool {
    if runtime == RuntimeKind::Node {
        return crate::node_identity::is_node_binary(canonical, metadata);
    }
    let named_bun = canonical.file_name().is_some_and(|name| {
        if cfg!(windows) {
            name.eq_ignore_ascii_case("bun.exe")
        } else {
            name == "bun"
        }
    });
    if !named_bun || metadata.len() < 16 * 1024 * 1024 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return false;
        }
    }
    #[cfg(windows)]
    if canonical.with_extension("shim").exists() {
        return false;
    }
    crate::node_identity::has_native_executable_header(canonical)
}

fn executable_digest(canonical: &Path, fingerprint: &str) -> Option<String> {
    static DIGESTS: OnceLock<Mutex<HashMap<String, DigestCell>>> = OnceLock::new();
    let cell = DIGESTS
        .get_or_init(Mutex::default)
        .lock()
        .ok()?
        .entry(fingerprint.to_string())
        .or_default()
        .clone();
    cell.get_or_init(|| {
        let directory = lpm_common::paths::LpmRoot::from_env()
            .ok()
            .map(|root| root.cache_metadata().join("runtime-digests-v1"));
        read_or_hash_digest(canonical, fingerprint, directory.as_deref())
    })
    .clone()
}

fn read_or_hash_digest(
    canonical: &Path,
    fingerprint: &str,
    directory: Option<&Path>,
) -> Option<String> {
    let record = directory.map(|dir| dir.join(fingerprint));
    if let Some(record) = &record
        && let Ok(digest) = lpm_common::read_text_file_capped_nofollow(record, 64)
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Some(digest);
    }

    let mut file = File::open(canonical).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let length = file.read(&mut buffer).ok()?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    if local_fingerprint(canonical).as_deref() != Some(fingerprint) {
        return None;
    }
    let digest = format!("{:x}", hasher.finalize());
    if let (Some(directory), Some(record)) = (directory, record) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        if builder.create(directory).is_ok() {
            let _ = lpm_common::write_file_atomic_with_options(
                &record,
                &digest,
                lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
            );
        }
    }
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_depends_on_contents_rather_than_path_or_inode() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, b"runtime bytes").unwrap();
        std::fs::copy(&first, &second).unwrap();
        let a = local_fingerprint(&first).unwrap();
        let b = local_fingerprint(&second).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            read_or_hash_digest(&first, &a, None),
            read_or_hash_digest(&second, &b, None)
        );
    }

    #[test]
    fn runtime_edit_invalidates_record_even_with_preserved_size_and_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("node");
        let records = dir.path().join("records");
        std::fs::write(&binary, b"first runtime").unwrap();
        let modified = binary.metadata().unwrap().modified().unwrap();
        let before = local_fingerprint(&binary).unwrap();
        let digest = read_or_hash_digest(&binary, &before, Some(&records)).unwrap();
        assert_eq!(
            read_or_hash_digest(&binary, &before, Some(&records)).unwrap(),
            digest
        );
        std::fs::write(&binary, b"other runtime").unwrap();
        File::options()
            .write(true)
            .open(&binary)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        #[cfg(unix)]
        {
            let after = local_fingerprint(&binary).unwrap();
            assert_ne!(before, after);
            assert_ne!(
                digest,
                read_or_hash_digest(&binary, &after, Some(&records)).unwrap()
            );
        }
        assert!(read_or_hash_digest(&binary, "wrong fingerprint", None).is_none());
    }

    #[test]
    fn malformed_or_linked_digest_records_are_recomputed() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("node");
        let records = dir.path().join("records");
        std::fs::create_dir(&records).unwrap();
        std::fs::write(&binary, b"runtime bytes").unwrap();
        let fingerprint = local_fingerprint(&binary).unwrap();
        let expected = read_or_hash_digest(&binary, &fingerprint, None).unwrap();
        let record = records.join(&fingerprint);
        for bad in ["not a digest".to_string(), "a".repeat(65)] {
            std::fs::write(&record, bad).unwrap();
            assert_eq!(
                read_or_hash_digest(&binary, &fingerprint, Some(&records)).unwrap(),
                expected
            );
        }
        #[cfg(unix)]
        {
            std::fs::remove_file(&record).unwrap();
            let target = dir.path().join("target");
            std::fs::write(&target, "b".repeat(64)).unwrap();
            std::os::unix::fs::symlink(&target, &record).unwrap();
            assert_eq!(
                read_or_hash_digest(&binary, &fingerprint, Some(&records)).unwrap(),
                expected
            );
            assert_eq!(std::fs::read_to_string(target).unwrap(), "b".repeat(64));
        }
    }

    #[test]
    fn runtime_snapshot_detects_selection_and_selector_changes() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir
            .path()
            .join(if cfg!(windows) { "node.cmd" } else { "node" });
        std::fs::write(&bin, b"echo launcher").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let snapshot =
            PortableRuntimeSnapshot::capture(dir.path(), dir.path().as_os_str()).unwrap();
        assert!(snapshot.is_unchanged());
        assert!(snapshot.identities()[1].1.starts_with("local:"));
        std::fs::write(dir.path().join(".tool-versions"), "nodejs 24.0.0").unwrap();
        assert!(!snapshot.is_unchanged());
        let snapshot =
            PortableRuntimeSnapshot::capture(dir.path(), dir.path().as_os_str()).unwrap();
        std::fs::remove_file(bin).unwrap();
        assert!(!snapshot.is_unchanged());
    }

    #[test]
    fn launcher_identity_keeps_working_directory_and_path_boundaries_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a");
        let second = dir.path().join("abin");
        let shared = dir.path().join("shared");
        for path in [&first, &second, &shared] {
            std::fs::create_dir(path).unwrap();
        }
        let launcher = shared.join(if cfg!(windows) { "bun.cmd" } else { "bun" });
        std::fs::write(&launcher, b"echo launcher").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let first_path = std::env::join_paths([Path::new("bin"), &shared]).unwrap();
        let second_path = std::env::join_paths([Path::new(""), &shared]).unwrap();
        let a = PortableRuntimeSnapshot::capture(&first, &first_path).unwrap();
        let b = PortableRuntimeSnapshot::capture(&second, &second_path).unwrap();
        assert!(a.identities()[2].1.starts_with("local:"));
        assert_ne!(a.identities(), b.identities());
    }

    #[test]
    fn bun_identity_requires_a_native_executable_without_a_shim_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let bun = dir
            .path()
            .join(if cfg!(windows) { "bun.exe" } else { "bun" });
        std::fs::write(&bun, b"#!/bin/sh\necho launcher").unwrap();
        assert!(!native_runtime(
            RuntimeKind::Bun,
            &bun,
            &bun.metadata().unwrap()
        ));
        crate::node_identity::write_unrunnable_node_binary(&bun);
        assert!(native_runtime(
            RuntimeKind::Bun,
            &bun,
            &bun.metadata().unwrap()
        ));
        #[cfg(windows)]
        {
            std::fs::write(bun.with_extension("shim"), "target=another-runtime").unwrap();
            assert!(!native_runtime(
                RuntimeKind::Bun,
                &bun,
                &bun.metadata().unwrap()
            ));
        }
    }
}
