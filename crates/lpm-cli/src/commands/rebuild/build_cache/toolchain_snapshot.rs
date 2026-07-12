use super::{
    hash_optional_file, hash_os_path, hash_records, host_package_state_paths,
    is_project_controlled_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_AGE: Duration = Duration::from_secs(60 * 60);
const MAX_BYTES: u64 = 256 * 1024;
const SCHEMA: u32 = 1;

#[derive(Clone)]
pub(super) struct ToolchainFingerprintCache {
    directory: PathBuf,
}

impl ToolchainFingerprintCache {
    pub(super) fn from_lpm_root(root: lpm_common::LpmRoot) -> Self {
        Self {
            directory: root.cache_metadata().join("native-toolchains/v1"),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn entry_path(&self, base_key: &str) -> Option<PathBuf> {
        let digest = base_key.strip_prefix("sha256-")?;
        is_lower_hex_digest(digest).then(|| self.directory.join(format!("{digest}.json")))
    }
}

#[derive(Serialize, Deserialize)]
struct ToolchainFingerprintSnapshot {
    schema: u32,
    base_key: String,
    fingerprint: String,
    validation_hash: String,
    pkg_config_paths: Vec<PathBuf>,
    created_unix_seconds: u64,
    entry_hash: String,
}

pub(super) struct ComputedToolchainFingerprint {
    pub(super) fingerprint: String,
    pub(super) pkg_config_paths: Vec<PathBuf>,
}

pub(super) fn cached_toolchain_fingerprint<F>(
    cache: &ToolchainFingerprintCache,
    base_key: &str,
    environment: &HashMap<String, String>,
    project_dir: &Path,
    compute: &mut F,
) -> std::io::Result<String>
where
    F: FnMut() -> std::io::Result<ComputedToolchainFingerprint>,
{
    let Some(entry_path) = cache.entry_path(base_key) else {
        return Ok(compute()?.fingerprint);
    };
    if std::fs::create_dir_all(&cache.directory).is_err() {
        return Ok(compute()?.fingerprint);
    }
    let lock_path = entry_path.with_extension("lock");
    let Ok(_lock) = lpm_common::acquire_exclusive_lock(&lock_path) else {
        return Ok(compute()?.fingerprint);
    };
    if let Some(snapshot) = read_snapshot(&entry_path, base_key)
        && snapshot_paths_are_allowed(&snapshot, environment, project_dir)
        && validation_hash(environment, &snapshot.pkg_config_paths)
            .is_ok_and(|current| current == snapshot.validation_hash)
    {
        tracing::debug!(target: "lpm_cli::build_cache", "native toolchain snapshot hit");
        return Ok(snapshot.fingerprint);
    }
    tracing::debug!(target: "lpm_cli::build_cache", "native toolchain snapshot miss");
    let computed = compute()?;
    let validation_hash = validation_hash(environment, &computed.pkg_config_paths)?;
    let created_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut snapshot = ToolchainFingerprintSnapshot {
        schema: SCHEMA,
        base_key: base_key.to_owned(),
        fingerprint: computed.fingerprint.clone(),
        validation_hash,
        pkg_config_paths: computed.pkg_config_paths,
        created_unix_seconds,
        entry_hash: String::new(),
    };
    snapshot.entry_hash = entry_hash(&snapshot);
    if let Err(error) = write_snapshot(&entry_path, &snapshot) {
        tracing::debug!(
            target: "lpm_cli::build_cache",
            path = %entry_path.display(),
            "failed to persist native toolchain snapshot: {error}"
        );
    }
    Ok(computed.fingerprint)
}

fn read_snapshot(path: &Path, expected_base_key: &str) -> Option<ToolchainFingerprintSnapshot> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_BYTES {
        return None;
    }
    let snapshot: ToolchainFingerprintSnapshot = serde_json::from_reader(file).ok()?;
    if snapshot.schema != SCHEMA
        || snapshot.base_key != expected_base_key
        || !is_sha256_fingerprint(&snapshot.fingerprint)
        || !is_sha256_fingerprint(&snapshot.validation_hash)
        || snapshot.pkg_config_paths.len() > 128
        || snapshot.entry_hash != entry_hash(&snapshot)
    {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let age = now.checked_sub(snapshot.created_unix_seconds)?;
    (age <= MAX_AGE.as_secs()).then_some(snapshot)
}

fn snapshot_paths_are_allowed(
    snapshot: &ToolchainFingerprintSnapshot,
    environment: &HashMap<String, String>,
    project_dir: &Path,
) -> bool {
    let configured_paths = environment
        .iter()
        .filter(|(key, _)| {
            key.eq_ignore_ascii_case("PKG_CONFIG_PATH")
                || key.eq_ignore_ascii_case("PKG_CONFIG_LIBDIR")
        })
        .flat_map(|(_, value)| std::env::split_paths(value))
        .collect::<Vec<_>>();
    snapshot.pkg_config_paths.iter().all(|path| {
        let is_configured = configured_paths.iter().any(|configured| configured == path);
        path.is_absolute()
            && path.as_os_str().len() <= 4096
            && (is_configured
                || (path.file_name().is_some_and(|name| name == "pkgconfig")
                    && !is_project_controlled_path(path, project_dir)))
    })
}

fn entry_hash(snapshot: &ToolchainFingerprintSnapshot) -> String {
    let mut records = Vec::with_capacity(snapshot.pkg_config_paths.len() + 6);
    records.push(format!("schema\0{}", snapshot.schema));
    records.push(format!("base\0{}", snapshot.base_key));
    records.push(format!("fingerprint\0{}", snapshot.fingerprint));
    records.push(format!("validation\0{}", snapshot.validation_hash));
    records.push(format!("created\0{}", snapshot.created_unix_seconds));
    records.extend(
        snapshot
            .pkg_config_paths
            .iter()
            .map(|path| format!("pkg-config\0{}", path.display())),
    );
    hash_records(records.iter().map(String::as_bytes))
}

fn write_snapshot(path: &Path, snapshot: &ToolchainFingerprintSnapshot) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("toolchain snapshot has no parent directory"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".native-toolchain-")
        .tempfile_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), snapshot)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .map(|_| ())
}

fn validation_hash(
    environment: &HashMap<String, String>,
    pkg_config_paths: &[PathBuf],
) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-toolchain-validation-v1\0");
    for path in [
        Path::new("/etc/os-release"),
        Path::new("/etc/ld.so.cache"),
        Path::new("/etc/hostname"),
        Path::new("/proc/sys/kernel/osrelease"),
        Path::new("/proc/sys/kernel/version"),
        Path::new("/System/Library/CoreServices/SystemVersion.plist"),
        Path::new("/var/db/xcode_select_link"),
    ] {
        hash_path_metadata(path, &mut hasher)?;
        if path != Path::new("/var/db/xcode_select_link") {
            hash_optional_file(path, &mut hasher)?;
        }
    }
    for path in host_package_state_paths().iter().map(Path::new) {
        hash_metadata_tree(path, &mut hasher)?;
    }
    for path in pkg_config_paths {
        hash_metadata_tree(path, &mut hasher)?;
    }
    for cellar in [
        Path::new("/opt/homebrew/Cellar"),
        Path::new("/usr/local/Cellar"),
        Path::new("/home/linuxbrew/.linuxbrew/Cellar"),
    ] {
        hash_homebrew_metadata(cellar, &mut hasher)?;
    }
    #[cfg(target_os = "macos")]
    for receipts in [
        Path::new("/var/db/receipts"),
        Path::new("/Library/Apple/System/Library/Receipts"),
    ] {
        hash_extension_metadata(receipts, "plist", &mut hasher)?;
    }
    if let Some(home) = environment
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("HOME"))
        .map(|(_, value)| PathBuf::from(value))
        .or_else(dirs::home_dir)
    {
        hash_metadata_tree(&home.join(".node-gyp"), &mut hasher)?;
        hash_rustup_metadata(&home.join(".rustup"), &mut hasher)?;
    }
    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

fn hash_metadata_tree(root: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    hasher.update(b"metadata-tree-v1\0");
    hash_os_path(hasher, root);
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(b"absent\x1e");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    hash_metadata_record(hasher, &root_metadata);
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Ok(());
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            hash_os_path(hasher, path.strip_prefix(root).unwrap_or(&path));
            let metadata = std::fs::symlink_metadata(&path)?;
            hash_metadata_record(hasher, &metadata);
            if metadata.file_type().is_symlink() {
                hash_os_path(hasher, &std::fs::read_link(path)?);
            } else if metadata.is_dir() {
                pending.push(path);
            }
            hasher.update(b"\x1e");
        }
    }
    Ok(())
}

fn hash_path_metadata(path: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    hash_os_path(hasher, path);
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            hash_metadata_record(hasher, &metadata);
            if metadata.file_type().is_symlink() {
                hash_os_path(hasher, &std::fs::read_link(path)?);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => hasher.update(b"absent"),
        Err(error) => return Err(error),
    }
    hasher.update(b"\x1e");
    Ok(())
}

fn hash_metadata_record(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    let file_type = metadata.file_type();
    hasher.update(if file_type.is_dir() {
        b"d".as_slice()
    } else if file_type.is_file() {
        b"f".as_slice()
    } else if file_type.is_symlink() {
        b"l".as_slice()
    } else {
        b"s".as_slice()
    });
    hasher.update(metadata.len().to_le_bytes());
    if let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(UNIX_EPOCH)
    {
        hasher.update(duration.as_secs().to_le_bytes());
        hasher.update(duration.subsec_nanos().to_le_bytes());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        hasher.update(metadata.mode().to_le_bytes());
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }
}

fn hash_homebrew_metadata(root: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    hash_os_path(hasher, root);
    let mut formulae = match std::fs::read_dir(root) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(b"absent\x1e");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    formulae.sort_unstable_by_key(std::fs::DirEntry::file_name);
    for formula in formulae {
        if !formula.file_type()?.is_dir() {
            continue;
        }
        hash_os_path(hasher, Path::new(&formula.file_name()));
        let mut versions = std::fs::read_dir(formula.path())?.collect::<Result<Vec<_>, _>>()?;
        versions.sort_unstable_by_key(std::fs::DirEntry::file_name);
        for version in versions {
            if version.file_type()?.is_dir() {
                hash_os_path(hasher, Path::new(&version.file_name()));
                hash_path_metadata(&version.path().join("INSTALL_RECEIPT.json"), hasher)?;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn hash_extension_metadata(
    root: &Path,
    extension: &str,
    hasher: &mut Sha256,
) -> std::io::Result<()> {
    hash_os_path(hasher, root);
    let mut paths = match std::fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|value| value == extension))
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(b"absent\x1e");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    paths.sort_unstable();
    for path in paths {
        hash_path_metadata(&path, hasher)?;
    }
    Ok(())
}

fn hash_rustup_metadata(root: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    hash_path_metadata(&root.join("settings.toml"), hasher)?;
    let toolchains = root.join("toolchains");
    let mut entries = match std::fs::read_dir(&toolchains) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        hash_os_path(hasher, Path::new(&entry.file_name()));
        for executable in ["rustc", "cargo"] {
            hash_path_metadata(&entry.path().join("bin").join(executable), hasher)?;
        }
    }
    Ok(())
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("sha256-")
        .is_some_and(is_lower_hex_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn environment(temp: &tempfile::TempDir) -> HashMap<String, String> {
        HashMap::from([(
            "HOME".to_string(),
            temp.path().join("home").display().to_string(),
        )])
    }

    #[test]
    fn unchanged_tracked_inputs_reuse_persisted_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let tracked = temp.path().join("pkgconfig");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&tracked).unwrap();
        std::fs::write(tracked.join("native.pc"), b"Version: 1\n").unwrap();
        let environment = environment(&temp);
        let cache_dir = temp.path().join("cache");
        let first_cache = ToolchainFingerprintCache::for_test(cache_dir.clone());
        let base_key = format!("sha256-{}", "b".repeat(64));
        let computations = Cell::new(0_u32);
        let mut compute = || {
            computations.set(computations.get() + 1);
            Ok(ComputedToolchainFingerprint {
                fingerprint: format!("sha256-{}", "1".repeat(64)),
                pkg_config_paths: vec![tracked.clone()],
            })
        };

        let first = cached_toolchain_fingerprint(
            &first_cache,
            &base_key,
            &environment,
            &project,
            &mut compute,
        )
        .unwrap();
        let second_cache = ToolchainFingerprintCache::for_test(cache_dir);
        let second = cached_toolchain_fingerprint(
            &second_cache,
            &base_key,
            &environment,
            &project,
            &mut compute,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(computations.get(), 1);
    }

    #[test]
    fn changed_tracked_input_recomputes_persisted_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let tracked = temp.path().join("pkgconfig");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&tracked).unwrap();
        let tracked_file = tracked.join("native.pc");
        std::fs::write(&tracked_file, b"Version: 1\n").unwrap();
        let environment = environment(&temp);
        let cache = ToolchainFingerprintCache::for_test(temp.path().join("cache"));
        let base_key = format!("sha256-{}", "b".repeat(64));
        let computations = Cell::new(0_u32);
        let mut compute = || {
            let count = computations.get() + 1;
            computations.set(count);
            Ok(ComputedToolchainFingerprint {
                fingerprint: format!("sha256-{}", count.to_string().repeat(64)),
                pkg_config_paths: vec![tracked.clone()],
            })
        };

        let first =
            cached_toolchain_fingerprint(&cache, &base_key, &environment, &project, &mut compute)
                .unwrap();
        std::fs::write(&tracked_file, b"Version: 2 with a different size\n").unwrap();
        let second =
            cached_toolchain_fingerprint(&cache, &base_key, &environment, &project, &mut compute)
                .unwrap();

        assert_ne!(first, second);
        assert_eq!(computations.get(), 2);
    }

    #[test]
    fn corrupt_snapshot_is_ignored_and_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let environment = environment(&temp);
        let cache = ToolchainFingerprintCache::for_test(temp.path().join("cache"));
        let base_key = format!("sha256-{}", "b".repeat(64));
        let entry = cache.entry_path(&base_key).unwrap();
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, b"{not valid json").unwrap();
        let computations = Cell::new(0_u32);
        let mut compute = || {
            computations.set(computations.get() + 1);
            Ok(ComputedToolchainFingerprint {
                fingerprint: format!("sha256-{}", "1".repeat(64)),
                pkg_config_paths: Vec::new(),
            })
        };

        cached_toolchain_fingerprint(&cache, &base_key, &environment, &project, &mut compute)
            .unwrap();

        assert_eq!(computations.get(), 1);
        assert!(read_snapshot(&entry, &base_key).is_some());
    }

    #[test]
    fn expired_snapshot_recomputes_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let environment = environment(&temp);
        let cache = ToolchainFingerprintCache::for_test(temp.path().join("cache"));
        let base_key = format!("sha256-{}", "b".repeat(64));
        let computations = Cell::new(0_u32);
        let mut compute = || {
            let count = computations.get() + 1;
            computations.set(count);
            Ok(ComputedToolchainFingerprint {
                fingerprint: format!("sha256-{}", count.to_string().repeat(64)),
                pkg_config_paths: Vec::new(),
            })
        };
        cached_toolchain_fingerprint(&cache, &base_key, &environment, &project, &mut compute)
            .unwrap();
        let entry = cache.entry_path(&base_key).unwrap();
        let mut snapshot = read_snapshot(&entry, &base_key).unwrap();
        snapshot.created_unix_seconds = 0;
        snapshot.entry_hash = entry_hash(&snapshot);
        write_snapshot(&entry, &snapshot).unwrap();

        cached_toolchain_fingerprint(&cache, &base_key, &environment, &project, &mut compute)
            .unwrap();

        assert_eq!(computations.get(), 2);
    }

    #[test]
    fn snapshot_rejects_unconfigured_broad_scan_root() {
        let snapshot = ToolchainFingerprintSnapshot {
            schema: SCHEMA,
            base_key: format!("sha256-{}", "b".repeat(64)),
            fingerprint: format!("sha256-{}", "1".repeat(64)),
            validation_hash: format!("sha256-{}", "2".repeat(64)),
            pkg_config_paths: vec![PathBuf::from("/")],
            created_unix_seconds: 1,
            entry_hash: String::new(),
        };

        assert!(!snapshot_paths_are_allowed(
            &snapshot,
            &HashMap::new(),
            Path::new("/project")
        ));
    }
}
