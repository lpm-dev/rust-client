//! Local task cache — store outputs on miss, restore on hit, replay stdout.
//!
//! Cache layout:
//! ```text
//! ~/.lpm/cache/tasks/
//!   {cache-key}/
//!     meta.json       ← timing, command, key info
//!     stdout.log      ← captured stdout
//!     stderr.log      ← captured stderr
//!     outputs.tar.gz  ← archived output files
//! ```

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use lpm_common::{LpmError, LpmRoot};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(test)]
#[derive(Clone)]
struct CacheRaceBarrier {
    target: PathBuf,
    validated: std::sync::Arc<std::sync::Barrier>,
    resume: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
static SNAPSHOT_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static ARCHIVE_SIZE_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static RESTORE_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static STAGED_OUTPUT_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static PUBLISHED_OUTPUT_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
static STAGED_TREE_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static RECOVERY_BACKUP_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static PROJECT_PATH_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static CACHE_FILE_READ_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static CACHE_STORE_STAGING_RACE_BARRIER: std::sync::Mutex<Vec<CacheRaceBarrier>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone)]
struct StagedFileFinalizeFailure {
    project: PathBuf,
    relative: PathBuf,
}

#[cfg(test)]
static STAGED_FILE_FINALIZE_FAILURE: std::sync::Mutex<Option<StagedFileFinalizeFailure>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
#[derive(Clone)]
struct BackupSyncFailure {
    project: PathBuf,
    relative: PathBuf,
}

#[cfg(test)]
static BACKUP_SYNC_FAILURE: std::sync::Mutex<Option<BackupSyncFailure>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
static STAGING_CLEANUP_FAILURE: std::sync::Mutex<Option<std::ffi::OsString>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
std::thread_local! {
    static RESTORE_DURABILITY_SYNC_COUNT: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn record_restore_durability_sync() {
    RESTORE_DURABILITY_SYNC_COUNT.with(|count| {
        if let Some(current) = count.get() {
            count.set(Some(current + 1));
        }
    });
}

#[cfg(not(test))]
fn record_restore_durability_sync() {}

#[cfg(test)]
fn count_restore_durability_syncs<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    RESTORE_DURABILITY_SYNC_COUNT.with(|count| count.set(Some(0)));
    let result = operation();
    let syncs = RESTORE_DURABILITY_SYNC_COUNT.with(|count| count.replace(None).unwrap_or(0));
    (result, syncs)
}

#[cfg(test)]
fn wait_for_cache_race_barrier(barriers: &std::sync::Mutex<Vec<CacheRaceBarrier>>, target: &Path) {
    let barriers = barriers.lock().expect("cache race barrier lock").clone();
    if let Some(barrier) = barriers.into_iter().find(|barrier| {
        barrier.target == target
            || matches!(
                (
                    std::fs::canonicalize(&barrier.target),
                    std::fs::canonicalize(target)
                ),
                (Ok(expected), Ok(actual)) if expected == actual
            )
    }) {
        barrier.validated.wait();
        barrier.resume.wait();
    }
}

/// Base directory for task cache.
///
/// Routes through [`LpmRoot::from_env`] so `$LPM_HOME` overrides and the
/// single canonical home-resolution rule are honored here too.
pub fn cache_dir() -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Task(format!("could not determine LPM home: {e}")))?;
    Ok(cache_dir_with_root(&root))
}

fn cache_dir_with_root(root: &LpmRoot) -> PathBuf {
    root.cache_tasks()
}

struct OpenTaskCache {
    tasks: Dir,
    path: PathBuf,
}

fn open_task_cache(root: &LpmRoot, create: bool) -> Result<Option<OpenTaskCache>, LpmError> {
    if create {
        std::fs::create_dir_all(root.root())?;
    }
    let lpm = match Dir::open_ambient_dir(root.root(), cap_std::ambient_authority()) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(cache) = open_or_create_directory(&lpm, "cache", create, "task cache parent")? else {
        return Ok(None);
    };
    let Some(tasks) = open_or_create_directory(&cache, "tasks", create, "task cache directory")?
    else {
        return Ok(None);
    };
    Ok(Some(OpenTaskCache {
        tasks,
        path: root.cache_tasks(),
    }))
}

fn open_cache_root(root: &LpmRoot, create: bool) -> Result<Option<(Dir, PathBuf)>, LpmError> {
    if create {
        std::fs::create_dir_all(root.root())?;
    }
    let lpm = match Dir::open_ambient_dir(root.root(), cap_std::ambient_authority()) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(
        open_or_create_directory(&lpm, "cache", create, "cache directory")?
            .map(|cache| (cache, root.cache_root())),
    )
}

fn open_or_create_directory(
    parent: &Dir,
    name: &str,
    create: bool,
    label: &str,
) -> Result<Option<Dir>, LpmError> {
    let open = || parent.open_dir_nofollow(name);
    match open() {
        Ok(dir) => {
            restrict_open_directory(&dir, label)?;
            Ok(Some(dir))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match parent.create_dir(name) {
                Ok(()) => sync_open_directory(parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let dir = open().map_err(|error| {
                LpmError::Task(format!(
                    "failed to open {label} without following links: {error}"
                ))
            })?;
            restrict_open_directory(&dir, label)?;
            Ok(Some(dir))
        }
        Err(error) => Err(LpmError::Task(format!(
            "failed to open {label} without following links: {error}"
        ))),
    }
}

#[cfg(unix)]
fn restrict_open_directory(dir: &Dir, label: &str) -> Result<(), LpmError> {
    use cap_std::fs::PermissionsExt as _;

    dir.set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
        .map_err(|error| LpmError::Task(format!("failed to restrict {label} permissions: {error}")))
}

#[cfg(not(unix))]
fn restrict_open_directory(_dir: &Dir, _label: &str) -> Result<(), LpmError> {
    Ok(())
}

fn sync_open_directory(directory: &Dir) -> Result<(), std::io::Error> {
    record_restore_durability_sync();
    #[cfg(unix)]
    directory.try_clone()?.into_std_file().sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

/// Get the cache directory for a specific cache key.
///
/// Validates that the key contains only hex characters to prevent path traversal.
pub fn cache_entry_dir(key: &str) -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|e| LpmError::Task(format!("could not determine LPM home: {e}")))?;
    cache_entry_dir_with_root(&root, key)
}

fn cache_entry_dir_with_root(root: &LpmRoot, key: &str) -> Result<PathBuf, LpmError> {
    validate_cache_key(key)?;
    Ok(cache_dir_with_root(root).join(key))
}

fn validate_cache_key(key: &str) -> Result<(), LpmError> {
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(LpmError::Task(format!(
            "invalid cache key (must be hex only): {key}"
        )));
    }
    Ok(())
}

fn cache_entry_lock_path(root: &LpmRoot, key: &str) -> Result<PathBuf, LpmError> {
    validate_cache_key(key)?;
    Ok(root
        .cache_root()
        .join(".task-locks")
        .join(format!("{key}.lock")))
}

#[cfg(test)]
fn project_restore_lock_path(root: &LpmRoot, project_dir: &Path) -> Result<PathBuf, LpmError> {
    let canonical_project = canonical_project_dir(project_dir)?;
    Ok(canonical_project_restore_lock_path(
        root,
        &canonical_project,
    ))
}

fn canonical_project_dir(project_dir: &Path) -> Result<PathBuf, LpmError> {
    let canonical_project = std::fs::canonicalize(project_dir).map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task cache project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    ensure_real_directory(&canonical_project, "task cache project directory")?;
    Ok(canonical_project)
}

struct OpenProject {
    path: PathBuf,
    dir: Dir,
}

fn open_project(project_dir: &Path) -> Result<OpenProject, LpmError> {
    let path = canonical_project_dir(project_dir)?;
    let dir = Dir::open_ambient_dir(&path, cap_std::ambient_authority())?;
    Ok(OpenProject { path, dir })
}

fn verify_open_project(project: &OpenProject) -> Result<(), LpmError> {
    verify_open_directory_path(&project.dir, &project.path, "task cache project directory")
}

fn verify_open_directory_path(opened: &Dir, path: &Path, label: &str) -> Result<(), LpmError> {
    let current = open_directory_path_nofollow(path).map_err(|error| {
        LpmError::Task(format!(
            "{label} changed while it was open at {}: {error}",
            path.display()
        ))
    })?;
    let expected = same_file::Handle::from_file(opened.try_clone()?.into_std_file())?;
    let current = same_file::Handle::from_file(current.into_std_file())?;
    if expected != current {
        return Err(LpmError::Task(format!(
            "{label} changed while it was open: {}",
            path.display()
        )));
    }
    Ok(())
}

fn open_directory_path_nofollow(path: &Path) -> Result<Dir, std::io::Error> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("directory path has no file name: {}", path.display()),
        )
    })?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())?;
    parent.open_dir_nofollow(name)
}

fn canonical_project_restore_lock_path(root: &LpmRoot, canonical_project: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hash_path_identity(&mut hasher, canonical_project);
    root.cache_tasks()
        .join(".locks")
        .join(format!("project-{:x}.lock", hasher.finalize()))
}

#[cfg(unix)]
fn hash_path_identity(hasher: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    hasher.update(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_path_identity(hasher: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
}

/// Check if a cache entry exists for the given key.
pub fn has_cache_hit(key: &str) -> bool {
    let Ok(root) = LpmRoot::from_env() else {
        return false;
    };
    has_cache_hit_with_root(&root, key)
}

fn has_cache_hit_with_root(root: &LpmRoot, key: &str) -> bool {
    let Ok(Some(cache)) = open_task_cache(root, false) else {
        return false;
    };
    open_cache_entry(&cache, key).is_ok_and(|entry| {
        open_cache_entry_file(&entry, "meta.json", "task cache metadata")
            .is_ok_and(|file| file.is_some())
            && open_cache_entry_file(&entry, "stdout.log", "task cache replay log")
                .is_ok_and(|file| file.is_some())
            && open_cache_entry_file(&entry, "stderr.log", "task cache replay log")
                .is_ok_and(|file| file.is_some())
    })
}

/// Restore cached outputs to the project directory.
///
/// Returns the cached stdout content for replay.
pub fn restore_cache(
    key: &str,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    restore_cache_if(key, project_dir, output_globs, || Ok(true))?.ok_or_else(|| {
        LpmError::Task("unconditional task cache restore was unexpectedly rejected".into())
    })
}

pub fn restore_cache_if(
    key: &str,
    project_dir: &Path,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    restore_cache_with_root_if(&root, key, project_dir, output_globs, validate)
}

#[cfg(test)]
fn restore_cache_with_root(
    root: &LpmRoot,
    key: &str,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    restore_cache_with_root_if(root, key, project_dir, output_globs, || Ok(true))?.ok_or_else(
        || LpmError::Task("unconditional task cache restore was unexpectedly rejected".into()),
    )
}

fn restore_cache_with_root_if(
    root: &LpmRoot,
    key: &str,
    project_dir: &Path,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    validate_cache_key(key)?;
    let project = open_project(project_dir)?;
    let cache = open_task_cache(root, false)?.ok_or_else(|| {
        LpmError::Task(format!(
            "task cache directory is missing: {}",
            root.cache_tasks().display()
        ))
    })?;
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _entry_lock =
            lpm_common::acquire_single_file_shared_lock(cache_entry_lock_path(root, key)?)?;
        let _project_lock = lpm_common::acquire_single_file_exclusive_lock(
            canonical_project_restore_lock_path(root, &project.path),
        )?;
        #[cfg(test)]
        wait_for_cache_race_barrier(&PROJECT_PATH_RACE_BARRIER, &project.path);
        verify_open_project(&project)?;
        restore_cache_locked_if(root, &cache, key, &project, output_globs, validate)
    })
}

fn restore_cache_locked_if(
    root: &LpmRoot,
    cache: &OpenTaskCache,
    key: &str,
    project: &OpenProject,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    let entry = open_cache_entry(cache, key)?;
    let meta = read_cache_meta(&entry, key)?;
    let stdout = read_cache_log(&entry, "stdout.log")?;
    let stderr = read_cache_log(&entry, "stderr.log")?;
    let archive = open_cache_entry_file(&entry, "outputs.tar.gz", "task cache archive")?;

    if meta.output_file_count > 0 && archive.is_none() {
        return Err(LpmError::Task(
            "cache entry is missing outputs archive".into(),
        ));
    }
    let accepted = if let Some(archive) = archive {
        #[cfg(test)]
        wait_for_cache_race_barrier(
            &CACHE_FILE_READ_RACE_BARRIER,
            &entry.path.join("outputs.tar.gz"),
        );
        restore_archive_with_expected_count_if(
            root,
            archive,
            project,
            meta.output_file_count,
            output_globs,
            validate,
        )?
    } else {
        validate()?
    };
    if !accepted {
        return Ok(None);
    }

    Ok(Some(CacheHit {
        meta,
        stdout,
        stderr,
    }))
}

/// Store task outputs to cache.
pub fn store_cache(
    key: &str,
    project_dir: &Path,
    command: &str,
    output_globs: &[String],
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    store_cache_with_root(
        &root,
        key,
        project_dir,
        command,
        output_globs,
        stdout,
        stderr,
        duration_ms,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache publication needs the complete entry payload"
)]
fn store_cache_with_root(
    root: &LpmRoot,
    key: &str,
    project_dir: &Path,
    command: &str,
    output_globs: &[String],
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
) -> Result<(), LpmError> {
    validate_cache_key(key)?;
    validate_cache_log_len("stdout.log", stdout.as_bytes())?;
    validate_cache_log_len("stderr.log", stderr.as_bytes())?;
    let canonical_project = canonical_project_dir(project_dir)?;
    let cache = open_task_cache(root, true)?.expect("created task cache directory");
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _entry_lock =
            lpm_common::acquire_single_file_exclusive_lock(cache_entry_lock_path(root, key)?)?;
        if validate_local_cache_entry(&cache, key).is_ok() {
            return Ok(());
        }
        let _project_lock = lpm_common::acquire_single_file_shared_lock(
            canonical_project_restore_lock_path(root, &canonical_project),
        )?;
        store_cache_locked(
            key,
            &cache,
            &canonical_project,
            command,
            output_globs,
            stdout,
            stderr,
            duration_ms,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "cache publication needs the complete entry payload"
)]
fn store_cache_locked(
    key: &str,
    cache: &OpenTaskCache,
    project_dir: &Path,
    command: &str,
    output_globs: &[String],
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
) -> Result<(), LpmError> {
    let entry = cache.path.join(key);
    let (staging_name, staging) = create_private_cache_directory(&cache.tasks)?;
    #[cfg(test)]
    wait_for_cache_race_barrier(&CACHE_STORE_STAGING_RACE_BARRIER, &cache.path);
    let result = (|| {
        write_private_cache_file(&staging, "stdout.log", stdout.as_bytes())?;
        write_private_cache_file(&staging, "stderr.log", stderr.as_bytes())?;
        let output_file_count = if output_globs.is_empty() {
            0
        } else {
            let mut archive = create_private_cache_file(&staging, "outputs.tar.gz")?;
            create_archive_in_file(project_dir, output_globs, &mut archive)?
        };
        let meta = CacheMeta {
            command: command.to_string(),
            cache_key: key.to_string(),
            duration_ms,
            output_file_count,
        };
        let meta_json = serde_json::to_vec_pretty(&meta)
            .map_err(|error| LpmError::Task(format!("failed to serialize cache meta: {error}")))?;
        write_private_cache_file(&staging, "meta.json", &meta_json)?;
        sync_open_directory(&staging)?;

        remove_open_directory_entry(&cache.tasks, std::ffi::OsStr::new(key))?;
        cache
            .tasks
            .rename(Path::new(&staging_name), &cache.tasks, Path::new(key))?;
        sync_open_directory(&cache.tasks)?;
        let published = cache.tasks.open_dir_nofollow(key)?;
        let staged_identity = same_file::Handle::from_file(staging.try_clone()?.into_std_file())?;
        let published_identity = same_file::Handle::from_file(published.into_std_file())?;
        if staged_identity != published_identity {
            return Err(LpmError::Task(format!(
                "task cache entry changed while it was published: {}",
                entry.display()
            )));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = cleanup_private_cache_directory(&cache.tasks, &staging_name, staging);
    }
    result?;
    tracing::debug!("cached task output to {}", entry.display());
    Ok(())
}

fn cleanup_private_cache_directory(parent: &Dir, name: &str, staging: Dir) -> Result<(), LpmError> {
    clean_open_cache_ephemeral(&staging)?;
    drop(staging);
    match parent.remove_dir(name) {
        Ok(()) => sync_open_directory(parent)?,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::DirectoryNotEmpty
                    | std::io::ErrorKind::NotADirectory
            ) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn create_private_cache_directory(parent: &Dir) -> Result<(String, Dir), LpmError> {
    let mut last_collision = None;
    for _ in 0..32 {
        let name = random_private_name(".task-cache-stage-")?;
        match parent.create_dir(&name) {
            Ok(()) => {
                let dir = parent.open_dir_nofollow(&name)?;
                restrict_open_directory(&dir, "task cache staging directory")?;
                sync_open_directory(parent)?;
                return Ok((name, dir));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(last_collision
        .unwrap_or_else(|| std::io::Error::other("could not create task cache staging directory"))
        .into())
}

fn random_private_name(prefix: &str) -> Result<String, LpmError> {
    use std::fmt::Write as _;

    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| LpmError::Task(format!("failed to create cache name: {error}")))?;
    let mut name = String::with_capacity(prefix.len() + random.len() * 2);
    name.push_str(prefix);
    for byte in random {
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(name)
}

fn create_private_cache_file(dir: &Dir, name: &str) -> Result<std::fs::File, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = dir.open_with(name, &options)?.into_std();
    set_open_file_permissions_restricted(&file)?;
    Ok(file)
}

fn write_private_cache_file(dir: &Dir, name: &str, bytes: &[u8]) -> Result<(), LpmError> {
    let mut file = create_private_cache_file(dir, name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct OpenCacheEntry {
    dir: Dir,
    path: PathBuf,
}

fn open_cache_entry(cache: &OpenTaskCache, key: &str) -> Result<OpenCacheEntry, LpmError> {
    validate_cache_key(key)?;
    let dir = cache.tasks.open_dir_nofollow(key).map_err(|error| {
        LpmError::Task(format!(
            "failed to open task cache entry {}: {error}",
            cache.path.join(key).display()
        ))
    })?;
    Ok(OpenCacheEntry {
        dir,
        path: cache.path.join(key),
    })
}

fn open_cache_entry_file(
    entry: &OpenCacheEntry,
    name: &str,
    label: &str,
) -> Result<Option<std::fs::File>, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match entry.dir.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Task(format!(
                "{label} is not a real file or could not be opened without following links: {}: {error}",
                entry.path.join(name).display()
            )));
        }
    };
    if !file.metadata()?.is_file() {
        return Err(LpmError::Task(format!(
            "{label} is not a real file: {}",
            entry.path.join(name).display()
        )));
    }
    Ok(Some(file.into_std()))
}

fn require_cache_entry_file(
    entry: &OpenCacheEntry,
    name: &str,
    label: &str,
) -> Result<std::fs::File, LpmError> {
    open_cache_entry_file(entry, name, label)?.ok_or_else(|| {
        LpmError::Task(format!(
            "{label} is missing: {}",
            entry.path.join(name).display()
        ))
    })
}

fn validate_local_cache_entry(cache: &OpenTaskCache, key: &str) -> Result<(), LpmError> {
    let entry = open_cache_entry(cache, key)?;
    let meta = read_cache_meta(&entry, key)?;
    drop(read_cache_log(&entry, "stdout.log")?);
    drop(read_cache_log(&entry, "stderr.log")?);
    let archive = open_cache_entry_file(&entry, "outputs.tar.gz", "task cache archive")?;
    if meta.output_file_count > 0 && archive.is_none() {
        return Err(LpmError::Task(
            "cache entry is missing outputs archive".into(),
        ));
    }
    let actual_count = archive
        .map(|archive| scan_cache_archive(archive, "task cache archive"))
        .transpose()?
        .unwrap_or(0);
    if actual_count != meta.output_file_count {
        return Err(LpmError::Task(format!(
            "cache entry output count mismatch (expected {}, found {actual_count})",
            meta.output_file_count
        )));
    }
    Ok(())
}

fn read_cache_meta(entry: &OpenCacheEntry, expected_key: &str) -> Result<CacheMeta, LpmError> {
    let meta_path = entry.path.join("meta.json");
    let file = require_cache_entry_file(entry, "meta.json", "task cache metadata")?;
    #[cfg(test)]
    wait_for_cache_race_barrier(&CACHE_FILE_READ_RACE_BARRIER, &meta_path);
    let (meta_bytes, _) = lpm_common::read_file_capped_from_open_file(
        file,
        &meta_path,
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Task(format!("failed to read cache meta: {error}")))?;
    let meta: CacheMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|error| LpmError::Task(format!("failed to parse cache meta: {error}")))?;
    if meta.cache_key != expected_key {
        return Err(LpmError::Task(format!(
            "cache entry key mismatch (expected {expected_key}, got {})",
            meta.cache_key
        )));
    }
    Ok(meta)
}

fn read_cache_log(entry: &OpenCacheEntry, name: &str) -> Result<String, LpmError> {
    let path = entry.path.join(name);
    let file = require_cache_entry_file(entry, name, "task cache replay log")?;
    let (bytes, _) = lpm_common::read_file_capped_from_open_file(file, &path, MAX_CACHE_LOG_BYTES)
        .map_err(|error| match error {
            lpm_common::BoundedReadError::TooLarge { .. } => LpmError::Task(format!(
                "cache {name} is oversized (limit: {MAX_CACHE_LOG_BYTES} bytes)"
            )),
            error => LpmError::Task(format!("failed to read cache {name}: {error}")),
        })?;
    String::from_utf8(bytes)
        .map_err(|error| LpmError::Task(format!("cache {name} is not valid UTF-8: {error}")))
}

fn validate_cache_log_len(name: &str, bytes: &[u8]) -> Result<(), LpmError> {
    if bytes.len() as u64 > MAX_CACHE_LOG_BYTES {
        return Err(LpmError::Task(format!(
            "cache {name} is oversized ({} > {MAX_CACHE_LOG_BYTES} bytes)",
            bytes.len()
        )));
    }
    Ok(())
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| LpmError::Task(format!("failed to inspect {label}: {error}")))?;
    if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(LpmError::Task(format!(
            "{label} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
fn ensure_real_file(path: &Path, label: &str) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| LpmError::Task(format!("failed to inspect {label}: {error}")))?;
    if !metadata.is_file() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(LpmError::Task(format!(
            "{label} is not a real file: {}",
            path.display()
        )));
    }
    Ok(())
}

pub struct RemoteArtifactCreate<'a> {
    pub key: &'a str,
    pub project_dir: &'a Path,
    pub command: &'a str,
    pub output_globs: &'a [String],
    pub stdout: &'a str,
    pub stderr: &'a str,
    pub duration_ms: u64,
    pub artifact_path: &'a Path,
}

/// Create a portable remote-cache artifact for a successful task run.
pub fn create_remote_artifact(args: RemoteArtifactCreate<'_>) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    create_remote_artifact_with_root(&root, args)
}

fn create_remote_artifact_with_root(
    root: &LpmRoot,
    args: RemoteArtifactCreate<'_>,
) -> Result<(), LpmError> {
    validate_cache_key(args.key)?;
    validate_cache_log_len("stdout.log", args.stdout.as_bytes())?;
    validate_cache_log_len("stderr.log", args.stderr.as_bytes())?;
    let canonical_project = canonical_project_dir(args.project_dir)?;
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _project_lock = lpm_common::acquire_single_file_shared_lock(
            canonical_project_restore_lock_path(root, &canonical_project),
        )?;
        create_remote_artifact_locked(RemoteArtifactCreate {
            key: args.key,
            project_dir: &canonical_project,
            command: args.command,
            output_globs: args.output_globs,
            stdout: args.stdout,
            stderr: args.stderr,
            duration_ms: args.duration_ms,
            artifact_path: args.artifact_path,
        })
    })
}

fn create_remote_artifact_locked(args: RemoteArtifactCreate<'_>) -> Result<(), LpmError> {
    if std::fs::symlink_metadata(args.artifact_path)
        .is_ok_and(|metadata| lpm_common::is_symlink_or_junction(&metadata))
    {
        return Err(LpmError::Task(format!(
            "remote cache artifact destination must not be a symlink or junction: {}",
            args.artifact_path.display()
        )));
    }
    let output_files =
        remote_artifact_output_files(args.project_dir, args.output_globs, args.artifact_path)?;
    lpm_common::write_file_atomic_with(
        args.artifact_path,
        lpm_common::AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
        |file| write_remote_artifact(&args, file, &output_files),
    )
}

/// Create a portable remote-cache artifact through an already-open file.
///
/// Callers that already own a private temporary file can keep hashing and
/// upload bound to that same descriptor instead of reopening its pathname.
pub fn create_remote_artifact_in_file(
    args: RemoteArtifactCreate<'_>,
    artifact: &mut std::fs::File,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    validate_cache_key(args.key)?;
    validate_cache_log_len("stdout.log", args.stdout.as_bytes())?;
    validate_cache_log_len("stderr.log", args.stderr.as_bytes())?;
    let canonical_project = canonical_project_dir(args.project_dir)?;
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _project_lock = lpm_common::acquire_single_file_shared_lock(
            canonical_project_restore_lock_path(&root, &canonical_project),
        )?;
        let canonical_args = RemoteArtifactCreate {
            key: args.key,
            project_dir: &canonical_project,
            command: args.command,
            output_globs: args.output_globs,
            stdout: args.stdout,
            stderr: args.stderr,
            duration_ms: args.duration_ms,
            artifact_path: args.artifact_path,
        };
        let output_files = remote_artifact_output_files(
            canonical_args.project_dir,
            canonical_args.output_globs,
            canonical_args.artifact_path,
        )?;
        write_remote_artifact(&canonical_args, artifact, &output_files)
    })
}

fn remote_artifact_output_files(
    project_dir: &Path,
    output_globs: &[String],
    artifact_path: &Path,
) -> Result<Vec<PathBuf>, LpmError> {
    let mut output_files = collect_output_files(project_dir, output_globs)?;
    let artifact_parent = artifact_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let (Ok(parent), Some(name)) = (artifact_parent.canonicalize(), artifact_path.file_name()) {
        let destination = parent.join(name);
        if let Ok(relative) = destination.strip_prefix(project_dir) {
            output_files.retain(|output| output != relative);
        }
    }
    Ok(output_files)
}

fn write_remote_artifact(
    args: &RemoteArtifactCreate<'_>,
    artifact: &mut std::fs::File,
    output_files: &[PathBuf],
) -> Result<(), LpmError> {
    artifact.set_len(0)?;
    artifact.rewind()?;
    set_open_file_permissions_restricted(artifact)?;
    let canonical_project = std::fs::canonicalize(args.project_dir)?;
    let project = Dir::open_ambient_dir(&canonical_project, cap_std::ambient_authority())?;
    let enc = flate2::write::GzEncoder::new(artifact, flate2::Compression::fast());
    let mut builder = tar::Builder::new(enc);

    append_collected_output_files(
        &mut builder,
        args.project_dir,
        &project,
        output_files,
        Some(Path::new("outputs")),
    )?;
    let output_file_count = output_files.len();

    let meta = CacheMeta {
        command: args.command.to_string(),
        cache_key: args.key.to_string(),
        duration_ms: args.duration_ms,
        output_file_count,
    };
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| LpmError::Task(format!("failed to serialize remote cache meta: {e}")))?;

    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/meta.json"),
        meta_json.as_bytes(),
    )?;
    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/stdout.log"),
        args.stdout.as_bytes(),
    )?;
    append_bytes(
        &mut builder,
        Path::new(".lpm-cache/stderr.log"),
        args.stderr.as_bytes(),
    )?;

    builder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finalize remote cache artifact: {e}")))?;
    let encoder = builder.into_inner().map_err(|e| {
        LpmError::Task(format!(
            "failed to finish remote cache artifact archive: {e}"
        ))
    })?;
    let artifact = encoder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finish remote cache gzip stream: {e}")))?;
    artifact.flush()?;
    artifact.sync_all()?;
    artifact.rewind()?;

    Ok(())
}

/// Restore a portable remote-cache artifact into a project directory.
pub fn restore_remote_artifact(
    expected_key: &str,
    artifact_path: &Path,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    let artifact = open_file_path_nofollow(artifact_path, "remote cache artifact")?;
    restore_remote_artifact_file_with_root(&root, expected_key, artifact, project_dir, output_globs)
}

/// Restore a portable remote-cache artifact from an already-verified file.
pub fn restore_remote_artifact_from_file(
    expected_key: &str,
    artifact: std::fs::File,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    restore_remote_artifact_from_file_if(expected_key, artifact, project_dir, output_globs, || {
        Ok(true)
    })?
    .ok_or_else(|| {
        LpmError::Task("unconditional remote cache restore was unexpectedly rejected".into())
    })
}

pub fn restore_remote_artifact_from_file_if(
    expected_key: &str,
    artifact: std::fs::File,
    project_dir: &Path,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    restore_remote_artifact_file_with_root_if(
        &root,
        expected_key,
        artifact,
        project_dir,
        output_globs,
        validate,
    )
}

#[cfg(test)]
fn restore_remote_artifact_with_root(
    root: &LpmRoot,
    expected_key: &str,
    artifact_path: &Path,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    let artifact = open_file_path_nofollow(artifact_path, "remote cache artifact")?;
    restore_remote_artifact_file_with_root(root, expected_key, artifact, project_dir, output_globs)
}

fn restore_remote_artifact_file_with_root(
    root: &LpmRoot,
    expected_key: &str,
    artifact: std::fs::File,
    project_dir: &Path,
    output_globs: &[String],
) -> Result<CacheHit, LpmError> {
    restore_remote_artifact_file_with_root_if(
        root,
        expected_key,
        artifact,
        project_dir,
        output_globs,
        || Ok(true),
    )?
    .ok_or_else(|| {
        LpmError::Task("unconditional remote cache restore was unexpectedly rejected".into())
    })
}

fn restore_remote_artifact_file_with_root_if(
    root: &LpmRoot,
    expected_key: &str,
    mut artifact: std::fs::File,
    project_dir: &Path,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    validate_cache_key(expected_key)?;
    artifact.rewind()?;
    let project = open_project(project_dir)?;
    lpm_common::with_shared_lock(root.cache_clean_lock(), || {
        let _project_lock = lpm_common::acquire_single_file_exclusive_lock(
            canonical_project_restore_lock_path(root, &project.path),
        )?;
        verify_open_project(&project)?;
        restore_remote_artifact_locked_if(
            root,
            expected_key,
            artifact,
            &project,
            output_globs,
            validate,
        )
    })
}

fn restore_remote_artifact_locked_if(
    root: &LpmRoot,
    expected_key: &str,
    file: std::fs::File,
    project: &OpenProject,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<Option<CacheHit>, LpmError> {
    let dec = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);

    let mut total_bytes: u64 = 0;
    let mut entries_seen: usize = 0;
    let mut meta_json: Option<String> = None;
    let mut stdout: Option<String> = None;
    let mut stderr: Option<String> = None;
    let mut staged_outputs = StagedOutputs::new_with_project(root, project)?;

    for entry in archive
        .entries()
        .map_err(|e| LpmError::Task(format!("failed to read remote cache artifact entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| {
            LpmError::Task(format!("failed to read remote cache artifact entry: {e}"))
        })?;

        entries_seen += 1;
        if entries_seen > MAX_CACHE_ARCHIVE_ENTRIES {
            return Err(LpmError::Task(format!(
                "remote cache artifact exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| LpmError::Task(format!("failed to read entry path: {e}")))?
            .to_path_buf();
        validate_archive_path(&path, "remote cache artifact")?;
        validate_archive_entry_type(&entry, &path, "remote cache artifact")?;

        let entry_size = entry.header().size().unwrap_or(0);
        check_archive_size_limits(entry_size, &mut total_bytes, &path, "remote cache artifact")?;

        if path == Path::new(".lpm-cache/meta.json") {
            if meta_json.is_some() {
                return Err(LpmError::Task(
                    "remote cache artifact contains duplicate metadata".into(),
                ));
            }
            validate_text_entry_size(entry_size, lpm_common::STATE_FILE_SIZE_CAP_BYTES, &path)?;
            meta_json = Some(read_entry_to_string(&mut entry, &path)?);
            continue;
        }
        if path == Path::new(".lpm-cache/stdout.log") {
            if stdout.is_some() {
                return Err(LpmError::Task(
                    "remote cache artifact contains duplicate stdout.log".into(),
                ));
            }
            validate_text_entry_size(entry_size, MAX_CACHE_LOG_BYTES, &path)?;
            stdout = Some(read_entry_to_string(&mut entry, &path)?);
            continue;
        }
        if path == Path::new(".lpm-cache/stderr.log") {
            if stderr.is_some() {
                return Err(LpmError::Task(
                    "remote cache artifact contains duplicate stderr.log".into(),
                ));
            }
            validate_text_entry_size(entry_size, MAX_CACHE_LOG_BYTES, &path)?;
            stderr = Some(read_entry_to_string(&mut entry, &path)?);
            continue;
        }

        let Ok(rel) = path.strip_prefix("outputs") else {
            return Err(LpmError::Task(format!(
                "remote cache artifact contains unexpected entry: {}",
                path.display()
            )));
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        staged_outputs.append(&mut entry, rel)?;
    }

    let meta_json = meta_json.ok_or_else(|| {
        LpmError::Task("remote cache artifact is missing .lpm-cache/meta.json".into())
    })?;
    let meta: CacheMeta = serde_json::from_str(&meta_json)
        .map_err(|e| LpmError::Task(format!("failed to parse remote cache meta: {e}")))?;

    if meta.cache_key != expected_key {
        return Err(LpmError::Task(format!(
            "remote cache artifact key mismatch (expected {expected_key}, got {})",
            meta.cache_key
        )));
    }
    if meta.output_file_count != staged_outputs.file_count() {
        return Err(LpmError::Task(format!(
            "remote cache artifact output count mismatch (expected {}, found {})",
            meta.output_file_count,
            staged_outputs.file_count()
        )));
    }
    let stdout = stdout.ok_or_else(|| {
        LpmError::Task("remote cache artifact is missing .lpm-cache/stdout.log".into())
    })?;
    let stderr = stderr.ok_or_else(|| {
        LpmError::Task("remote cache artifact is missing .lpm-cache/stderr.log".into())
    })?;

    if !staged_outputs.apply_if(output_globs, validate)? {
        return Ok(None);
    }

    Ok(Some(CacheHit {
        meta,
        stdout,
        stderr,
    }))
}

fn open_file_path_nofollow(path: &Path, label: &str) -> Result<std::fs::File, LpmError> {
    let name = path.file_name().ok_or_else(|| {
        LpmError::Task(format!("{label} path has no file name: {}", path.display()))
    })?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options).map_err(|error| {
        LpmError::Task(format!(
            "failed to open {label} without following links at {}: {error}",
            path.display()
        ))
    })?;
    if !file.metadata()?.is_file() {
        return Err(LpmError::Task(format!(
            "{label} is not a real file: {}",
            path.display()
        )));
    }
    Ok(file.into_std())
}

/// Clean the entire task cache.
pub fn clean_cache() -> Result<u64, LpmError> {
    let root = LpmRoot::from_env()
        .map_err(|error| LpmError::Task(format!("could not determine LPM home: {error}")))?;
    clean_cache_with_root(&root)
}

fn clean_cache_with_root(root: &LpmRoot) -> Result<u64, LpmError> {
    let Some(cache) = open_task_cache(root, false)? else {
        return Ok(0);
    };
    lpm_common::with_exclusive_lock(root.cache_clean_lock(), || clean_open_cache(&cache.tasks))
}

#[cfg(all(test, unix))]
fn clean_cache_locked(dir: &Path) -> Result<u64, LpmError> {
    ensure_real_directory(dir, "task cache directory")?;
    let cache = Dir::open_ambient_dir(dir, cap_std::ambient_authority())?;
    clean_open_cache(&cache)
}

fn clean_open_cache(dir: &Dir) -> Result<u64, LpmError> {
    clear_open_directory(dir, true)
}

fn clean_open_cache_ephemeral(dir: &Dir) -> Result<u64, LpmError> {
    clear_open_directory(dir, false)
}

fn clear_open_directory(dir: &Dir, durable: bool) -> Result<u64, LpmError> {
    let mut count = 0u64;
    for entry in dir.entries()? {
        let entry = entry?;
        remove_open_directory_entry_inner(dir, &entry.file_name(), durable)?;
        count += 1;
    }
    if durable {
        sync_open_directory(dir)?;
    }
    Ok(count)
}

fn remove_open_directory_entry(dir: &Dir, name: &std::ffi::OsStr) -> Result<(), LpmError> {
    remove_open_directory_entry_inner(dir, name, true)?;
    sync_open_directory(dir)?;
    Ok(())
}

fn remove_open_directory_entry_inner(
    dir: &Dir,
    name: &std::ffi::OsStr,
    durable: bool,
) -> Result<(), LpmError> {
    let metadata = match dir.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !cap_metadata_is_link_or_reparse(&metadata) {
        let child = dir.open_dir_nofollow(name)?;
        clear_open_directory(&child, durable)?;
        drop(child);
        match dir.remove_dir(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    } else {
        match dir.remove_file_or_symlink(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn cap_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn cap_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

/// Cache hit result.
#[derive(Debug)]
pub struct CacheHit {
    pub meta: CacheMeta,
    pub stdout: String,
    pub stderr: String,
}

/// Cache entry metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CacheMeta {
    pub command: String,
    pub cache_key: String,
    pub duration_ms: u64,
    /// Number of output files archived (for integrity check on restore).
    #[serde(default)]
    pub output_file_count: usize,
}

/// Create a .tar.gz archive of files matching output globs.
/// Returns the number of files archived.
#[cfg(test)]
fn create_archive(
    project_dir: &Path,
    output_globs: &[String],
    archive_path: &Path,
) -> Result<usize, LpmError> {
    let mut file = std::fs::File::create(archive_path)?;
    let file_count = create_archive_in_file(project_dir, output_globs, &mut file)?;
    tracing::debug!("archived {file_count} files to {}", archive_path.display());
    Ok(file_count)
}

fn create_archive_in_file(
    project_dir: &Path,
    output_globs: &[String],
    file: &mut std::fs::File,
) -> Result<usize, LpmError> {
    file.set_len(0)?;
    file.rewind()?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(enc);

    let file_count = append_output_files(&mut builder, project_dir, output_globs, None)?;

    builder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finalize archive: {e}")))?;
    let encoder = builder
        .into_inner()
        .map_err(|e| LpmError::Task(format!("failed to finish task cache archive: {e}")))?;
    let file = encoder
        .finish()
        .map_err(|e| LpmError::Task(format!("failed to finish task cache gzip stream: {e}")))?;
    file.flush()?;
    file.sync_all()?;
    file.rewind()?;
    Ok(file_count)
}

fn append_output_files<W: Write>(
    builder: &mut tar::Builder<W>,
    project_dir: &Path,
    output_globs: &[String],
    archive_prefix: Option<&Path>,
) -> Result<usize, LpmError> {
    let canonical_project = std::fs::canonicalize(project_dir).map_err(|error| {
        LpmError::Task(format!(
            "failed to resolve task output project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    let project = Dir::open_ambient_dir(&canonical_project, cap_std::ambient_authority())?;
    let output_files = collect_output_files(project_dir, output_globs)?;

    append_collected_output_files(
        builder,
        project_dir,
        &project,
        &output_files,
        archive_prefix,
    )?;

    Ok(output_files.len())
}

fn append_collected_output_files<W: Write>(
    builder: &mut tar::Builder<W>,
    project_dir: &Path,
    project: &Dir,
    output_files: &[PathBuf],
    archive_prefix: Option<&Path>,
) -> Result<(), LpmError> {
    let mut total_bytes = 0;

    for relative in output_files {
        let archive_name =
            archive_prefix.map_or_else(|| relative.clone(), |prefix| prefix.join(relative));
        #[cfg(test)]
        wait_for_cache_race_barrier(&SNAPSHOT_RACE_BARRIER, &project_dir.join(relative));
        let mut source = open_project_file_nofollow(project, relative, "task output")?;
        let metadata = source.metadata()?;
        let size = metadata.len();
        let identity = crate::hasher::archive_metadata_identity_bytes(&source, &metadata);
        check_archive_size_limits(size, &mut total_bytes, relative, "task output archive")?;
        #[cfg(test)]
        wait_for_cache_race_barrier(&ARCHIVE_SIZE_RACE_BARRIER, &project_dir.join(relative));
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(size);
        header.set_cksum();
        {
            let mut limited = (&mut source).take(size);
            builder
                .append_data(&mut header, &archive_name, &mut limited)
                .map_err(|error| {
                    LpmError::Task(format!(
                        "failed to add {} to archive: {error}",
                        project_dir.join(relative).display()
                    ))
                })?;
            if limited.limit() != 0 {
                return Err(LpmError::Task(format!(
                    "task output became shorter while archiving: {}",
                    project_dir.join(relative).display()
                )));
            }
        }
        let mut extra = [0u8; 1];
        let final_metadata = source.metadata()?;
        if source.read(&mut extra)? != 0
            || crate::hasher::archive_metadata_identity_bytes(&source, &final_metadata) != identity
        {
            return Err(LpmError::Task(format!(
                "task output changed while archiving: {}",
                project_dir.join(relative).display()
            )));
        }
    }

    Ok(())
}

fn collect_output_files(
    project_dir: &Path,
    output_globs: &[String],
) -> Result<Vec<PathBuf>, LpmError> {
    let mut files = HashSet::new();

    for pattern in output_globs {
        lpm_common::validate_project_glob(pattern).map_err(|reason| {
            LpmError::Task(format!("invalid output glob {pattern:?}: {reason}"))
        })?;
        for expanded in expand_glob_pattern(pattern) {
            let rooted = lpm_common::rooted_project_glob(project_dir, &expanded);
            let entries = glob::glob(&rooted).map_err(|error| {
                LpmError::Task(format!("invalid output glob {pattern:?}: {error}"))
            })?;
            for matched in entries {
                let entry = matched.map_err(|error| {
                    LpmError::Task(format!("failed to expand output glob {pattern:?}: {error}"))
                })?;
                let metadata = std::fs::symlink_metadata(&entry).map_err(|error| {
                    LpmError::Task(format!(
                        "failed to inspect task output {}: {error}",
                        entry.display()
                    ))
                })?;
                if lpm_common::is_symlink_or_junction(&metadata) {
                    return Err(LpmError::Task(format!(
                        "task output must not be a symlink or junction: {}",
                        entry.display()
                    )));
                }
                if !metadata.is_file() {
                    continue;
                }
                let relative = entry.strip_prefix(project_dir).map_err(|_| {
                    LpmError::Task(format!(
                        "task output is outside project path: {}",
                        entry.display()
                    ))
                })?;
                if is_restore_internal_path(relative) {
                    continue;
                }
                validate_archive_path(relative, "task output")?;
                if files.insert(relative.to_path_buf()) && files.len() > MAX_CACHE_ARCHIVE_ENTRIES {
                    return Err(LpmError::Task(format!(
                        "task output set exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
                    )));
                }
            }
        }
    }

    let mut files: Vec<_> = files.into_iter().collect();
    files.sort_unstable();
    Ok(files)
}

fn open_project_file_nofollow(
    project: &Dir,
    relative: &Path,
    label: &str,
) -> Result<std::fs::File, LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = project.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid {label} path: {}",
                relative.display()
            )));
        };
        if components.peek().is_some() {
            parent = parent.open_dir_nofollow(name).map_err(|error| {
                LpmError::Task(format!(
                    "{label} parent is unsafe or resolves outside project at {}: {error}",
                    relative.display()
                ))
            })?;
            continue;
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options).map_err(|error| {
            LpmError::Task(format!(
                "failed to open {label} {} without following links: {error}",
                relative.display()
            ))
        })?;
        if !file.metadata()?.is_file() {
            return Err(LpmError::Task(format!(
                "{label} is not a real file: {}",
                relative.display()
            )));
        }
        return Ok(file.into_std());
    }
    Err(LpmError::Task(format!("invalid empty {label} path")))
}

fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    bytes: &[u8],
) -> Result<(), LpmError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .map_err(|e| LpmError::Task(format!("failed to add {} to artifact: {e}", path.display())))
}

/// Expand a glob pattern to cover both directories and files at any depth.
/// "dist/**" → ["dist/**", "dist/**/*"]
fn expand_glob_pattern(pattern: &str) -> Vec<String> {
    let mut patterns = vec![pattern.to_string()];
    if pattern.ends_with("/**") {
        patterns.push(format!("{pattern}/*"));
    }
    patterns
}

fn is_restore_internal_path(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        name.to_string_lossy().starts_with(RESTORE_TEMP_PREFIX)
    })
}

const MAX_CACHE_LOG_BYTES: u64 = lpm_common::TASK_OUTPUT_CAPTURE_BYTES as u64 + 64;

/// Hard cap on one restored cache entry.
const MAX_CACHE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on all restored bytes from one cache archive.
const MAX_CACHE_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;

/// Hard cap on entries from one cache archive.
const MAX_CACHE_ARCHIVE_ENTRIES: usize = 100_000;

const RESTORE_TEMP_PREFIX: &str = ".lpm-cache-restore-";
mod restore;

#[cfg(test)]
use restore::{
    RESTORE_JOURNAL_MAGIC, RESTORE_OWNER_NAME, RestoreTransaction,
    mark_restore_registration_committed_for_test, register_restore_for_test, restore_archive,
    write_restore_committed_for_test, write_restore_journal,
};
use restore::{StagedOutputs, restore_archive_with_expected_count_if, scan_cache_archive};
fn normalize_archive_path(path: &Path, label: &str) -> Result<PathBuf, LpmError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(LpmError::Task(format!(
                    "path traversal in {label}: {}",
                    path.display()
                )));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(LpmError::Task(format!(
            "empty path in {label}: {}",
            path.display()
        )));
    }
    Ok(normalized)
}

fn validate_text_entry_size(size: u64, cap: u64, path: &Path) -> Result<(), LpmError> {
    if size > cap {
        return Err(LpmError::Task(format!(
            "remote cache artifact entry is oversized ({} > {cap} bytes): {}",
            size,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn set_staged_file_permissions(file: &std::fs::File, mode: u32) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
    Ok(())
}

#[cfg(unix)]
fn set_open_file_permissions_restricted(file: &std::fs::File) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_open_file_permissions_restricted(_file: &std::fs::File) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(not(unix))]
fn set_staged_file_permissions(_file: &std::fs::File, _mode: u32) -> Result<(), LpmError> {
    Ok(())
}

fn validate_archive_path(path: &Path, label: &str) -> Result<(), LpmError> {
    if path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(LpmError::Task(format!(
            "path traversal in {label}: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_archive_entry_type(
    entry: &tar::Entry<'_, impl Read>,
    path: &Path,
    label: &str,
) -> Result<(), LpmError> {
    let header_type = entry.header().entry_type();
    if !(header_type.is_file() || header_type.is_dir()) {
        return Err(LpmError::Task(format!(
            "{label} contains non-regular entry ({:?}): {}",
            header_type,
            path.display(),
        )));
    }
    Ok(())
}

fn check_archive_size_limits(
    entry_size: u64,
    total_bytes: &mut u64,
    path: &Path,
    label: &str,
) -> Result<(), LpmError> {
    if entry_size > MAX_CACHE_ENTRY_BYTES {
        return Err(LpmError::Task(format!(
            "{label} entry exceeds size cap ({} > {} bytes): {}",
            entry_size,
            MAX_CACHE_ENTRY_BYTES,
            path.display(),
        )));
    }
    *total_bytes = total_bytes.saturating_add(entry_size);
    if *total_bytes > MAX_CACHE_ARCHIVE_BYTES {
        return Err(LpmError::Task(format!(
            "{label} exceeds aggregate cap ({MAX_CACHE_ARCHIVE_BYTES} bytes)"
        )));
    }
    Ok(())
}

fn read_entry_to_string(
    entry: &mut tar::Entry<'_, impl Read>,
    path: &Path,
) -> Result<String, LpmError> {
    let mut content = String::new();
    entry
        .read_to_string(&mut content)
        .map_err(|e| LpmError::Task(format!("failed to read {}: {e}", path.display())))?;
    Ok(content)
}

/// Validate a glob pattern to prevent directory escape.
///
/// Rejects patterns that start with `../`, `/`, or contain `/../`.
pub fn validate_glob_pattern(pattern: &str) -> bool {
    lpm_common::validate_project_glob(pattern).is_ok()
}

/// Set directory permissions to 0o700 (owner only) on Unix.
#[cfg(all(test, unix))]
fn set_dir_permissions_restricted(path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms).map_err(|e| {
        LpmError::Task(format!(
            "failed to set permissions on {}: {e}",
            path.display()
        ))
    })
}

/// No-op on non-Unix platforms.
#[cfg(all(test, not(unix)))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "non-Unix stub keeps the same fallible helper signature"
)]
fn set_dir_permissions_restricted(_path: &Path) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TestCache {
        _home: tempfile::TempDir,
        root: LpmRoot,
    }

    impl TestCache {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            let root = LpmRoot::from_dir(home.path());
            Self { _home: home, root }
        }

        fn entry(&self, key: &str) -> PathBuf {
            cache_entry_dir_with_root(&self.root, key).unwrap()
        }

        fn has_hit(&self, key: &str) -> bool {
            has_cache_hit_with_root(&self.root, key)
        }

        #[expect(
            clippy::too_many_arguments,
            reason = "test helper mirrors the cache publication contract"
        )]
        fn store(
            &self,
            key: &str,
            project_dir: &Path,
            command: &str,
            output_globs: &[String],
            stdout: &str,
            stderr: &str,
            duration_ms: u64,
        ) -> Result<(), LpmError> {
            store_cache_with_root(
                &self.root,
                key,
                project_dir,
                command,
                output_globs,
                stdout,
                stderr,
                duration_ms,
            )
        }

        fn restore(&self, key: &str, project_dir: &Path) -> Result<CacheHit, LpmError> {
            restore_cache_with_root(&self.root, key, project_dir, &[])
        }

        fn create_remote(&self, args: RemoteArtifactCreate<'_>) -> Result<(), LpmError> {
            create_remote_artifact_with_root(&self.root, args)
        }

        fn restore_remote(
            &self,
            key: &str,
            artifact_path: &Path,
            project_dir: &Path,
        ) -> Result<CacheHit, LpmError> {
            restore_remote_artifact_with_root(&self.root, key, artifact_path, project_dir, &[])
        }

        fn restore_remote_exact(
            &self,
            key: &str,
            artifact_path: &Path,
            project_dir: &Path,
            output_globs: &[String],
        ) -> Result<CacheHit, LpmError> {
            restore_remote_artifact_with_root(
                &self.root,
                key,
                artifact_path,
                project_dir,
                output_globs,
            )
        }
    }

    fn unique_key(_prefix: &str) -> String {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let hash = Sha256::digest(format!("{_prefix}-{ts}").as_bytes());
        // Return hex-only key (satisfies cache_entry_dir validation)
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    fn mark_restore_directory_owned(path: &Path) {
        set_dir_permissions_restricted(path).unwrap();
        let owner = path.join(RESTORE_OWNER_NAME);
        fs::write(&owner, RESTORE_JOURNAL_MAGIC).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn install_race_barrier(
        slot: &std::sync::Mutex<Vec<CacheRaceBarrier>>,
        target: PathBuf,
    ) -> CacheRaceBarrier {
        let barrier = CacheRaceBarrier {
            target,
            validated: std::sync::Arc::new(std::sync::Barrier::new(2)),
            resume: std::sync::Arc::new(std::sync::Barrier::new(2)),
        };
        slot.lock().unwrap().push(barrier.clone());
        barrier
    }

    fn clear_race_barrier(
        slot: &std::sync::Mutex<Vec<CacheRaceBarrier>>,
        barrier: &CacheRaceBarrier,
    ) {
        slot.lock()
            .unwrap()
            .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.validated, &barrier.validated));
    }

    #[test]
    fn cache_miss_returns_false() {
        let cache = TestCache::new();
        assert!(!cache.has_hit("deadbeef0123456789abcdef"));
    }

    #[test]
    fn store_and_restore_roundtrip() {
        let cache = TestCache::new();
        let dir = tempfile::tempdir().unwrap();

        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "built output").unwrap();
        fs::write(dir.path().join("dist/style.css"), "body {}").unwrap();

        let key = unique_key("roundtrip");

        cache
            .store(
                &key,
                dir.path(),
                "echo build",
                &["dist/**".into()],
                "build output\n",
                "",
                1234,
            )
            .unwrap();

        assert!(cache.has_hit(&key), "cache entry should exist after store");

        // Delete the output files
        fs::remove_dir_all(dir.path().join("dist")).unwrap();
        assert!(!dir.path().join("dist/index.js").exists());

        // Restore
        let hit = cache.restore(&key, dir.path()).unwrap();
        assert_eq!(hit.meta.command, "echo build");
        assert_eq!(hit.meta.duration_ms, 1234);
        assert_eq!(hit.stdout, "build output\n");
        assert!(
            dir.path().join("dist/index.js").exists(),
            "dist/index.js should be restored"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
            "built output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_cache_store_does_not_delete_a_replacement_staging_directory() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("value.txt"), "outside").unwrap();
        symlink(
            outside.path().join("value.txt"),
            project.path().join("dist/value.txt"),
        )
        .unwrap();

        let cache_path = cache_dir_with_root(&cache.root);
        let barrier = install_race_barrier(&CACHE_STORE_STAGING_RACE_BARRIER, cache_path.clone());
        let root = cache.root;
        let project_path = project.path().to_path_buf();
        let key = unique_key("replaced-store-staging");
        let worker = std::thread::spawn(move || {
            store_cache_with_root(
                &root,
                &key,
                &project_path,
                "build",
                &["dist/**".into()],
                "",
                "",
                1,
            )
        });

        barrier.validated.wait();
        let staging_name = fs::read_dir(&cache_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .find(|name| name.to_string_lossy().starts_with(".task-cache-stage-"))
            .expect("cache staging directory");
        let staging_path = cache_path.join(&staging_name);
        fs::rename(&staging_path, cache_path.join("moved-staging")).unwrap();
        fs::create_dir(&staging_path).unwrap();
        fs::write(staging_path.join("sentinel"), "must remain").unwrap();
        barrier.resume.wait();

        assert!(worker.join().unwrap().is_err());
        clear_race_barrier(&CACHE_STORE_STAGING_RACE_BARRIER, &barrier);
        assert_eq!(
            fs::read_to_string(staging_path.join("sentinel")).unwrap(),
            "must remain"
        );
    }

    #[test]
    fn restore_preserves_the_archived_file_modification_time() {
        use std::time::{Duration, SystemTime};

        let project = tempfile::tempdir().unwrap();
        let output = project.path().join("dist/value.txt");
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        fs::write(&output, "built output").unwrap();
        let archived_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        fs::File::options()
            .write(true)
            .open(&output)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(archived_time))
            .unwrap();
        let archive = project.path().join("outputs.tar.gz");
        create_archive(project.path(), &["dist/**".into()], &archive).unwrap();
        fs::remove_dir_all(project.path().join("dist")).unwrap();

        restore_archive(&archive, project.path()).unwrap();

        let restored = fs::metadata(output).unwrap().modified().unwrap();
        assert_eq!(
            restored
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            archived_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    #[test]
    fn remote_artifact_roundtrip_restores_outputs_and_logs() {
        let cache = TestCache::new();
        let dir = tempfile::tempdir().unwrap();

        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "remote output").unwrap();

        let key = unique_key("remote-roundtrip");
        let artifact_path = dir.path().join("remote-artifact.tar.gz");

        cache
            .create_remote(RemoteArtifactCreate {
                key: &key,
                project_dir: dir.path(),
                command: "node build.js",
                output_globs: &["dist/**".into()],
                stdout: "remote stdout\n",
                stderr: "remote stderr\n",
                duration_ms: 4321,
                artifact_path: &artifact_path,
            })
            .unwrap();

        fs::remove_dir_all(dir.path().join("dist")).unwrap();

        let hit = cache
            .restore_remote(&key, &artifact_path, dir.path())
            .unwrap();

        assert_eq!(hit.meta.command, "node build.js");
        assert_eq!(hit.meta.cache_key, key);
        assert_eq!(hit.meta.duration_ms, 4321);
        assert_eq!(hit.meta.output_file_count, 1);
        assert_eq!(hit.stdout, "remote stdout\n");
        assert_eq!(hit.stderr, "remote stderr\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/index.js")).unwrap(),
            "remote output"
        );
    }

    #[test]
    fn remote_restore_uses_the_verified_open_artifact_after_path_replacement() {
        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "verified").unwrap();
        let artifact_path = source.path().join("artifact.tar.gz");
        cache
            .create_remote(RemoteArtifactCreate {
                key: "deadbeef",
                project_dir: source.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();
        let verified = fs::File::open(&artifact_path).unwrap();
        fs::rename(&artifact_path, source.path().join("verified.tar.gz")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "replacement").unwrap();
        cache
            .create_remote(RemoteArtifactCreate {
                key: "deadbeef",
                project_dir: source.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();
        let target = tempfile::tempdir().unwrap();

        restore_remote_artifact_file_with_root(
            &cache.root,
            "deadbeef",
            verified,
            target.path(),
            &[],
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(target.path().join("dist/value.txt")).unwrap(),
            "verified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_artifact_creation_rejects_a_linked_destination_file() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "cached").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("sentinel");
        fs::write(&sentinel, "must-remain").unwrap();
        let artifact_path = project.path().join("artifact.tar.gz");
        symlink(&sentinel, &artifact_path).unwrap();

        let result = cache.create_remote(RemoteArtifactCreate {
            key: "deadbeef",
            project_dir: project.path(),
            command: "build",
            output_globs: &["dist/**".into()],
            stdout: "",
            stderr: "",
            duration_ms: 1,
            artifact_path: &artifact_path,
        });

        assert!(
            result.is_err(),
            "a linked artifact destination was accepted"
        );
        assert_eq!(fs::read_to_string(sentinel).unwrap(), "must-remain");
    }

    #[cfg(unix)]
    #[test]
    fn remote_artifact_creation_failure_preserves_an_existing_artifact() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("value.txt"), "outside").unwrap();
        symlink(
            outside.path().join("value.txt"),
            project.path().join("dist/value.txt"),
        )
        .unwrap();
        let artifact_path = project.path().join("artifact.tar.gz");
        fs::write(&artifact_path, "previous-artifact").unwrap();

        let result = cache.create_remote(RemoteArtifactCreate {
            key: "deadbeef",
            project_dir: project.path(),
            command: "build",
            output_globs: &["dist/**".into()],
            stdout: "",
            stderr: "",
            duration_ms: 1,
            artifact_path: &artifact_path,
        });

        assert!(result.is_err(), "an unsafe output did not fail publication");
        assert_eq!(
            fs::read_to_string(artifact_path).unwrap(),
            "previous-artifact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_artifact_publication_sets_private_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "cached").unwrap();
        let artifact_path = project.path().join("artifact.tar.gz");
        fs::write(&artifact_path, "previous").unwrap();
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o644)).unwrap();

        cache
            .create_remote(RemoteArtifactCreate {
                key: "deadbeef",
                project_dir: project.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();

        assert_eq!(
            fs::metadata(artifact_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn remote_artifact_does_not_include_its_own_destination() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "cached").unwrap();
        let artifact_path = project.path().join("dist/artifact.tar.gz");

        cache
            .create_remote(RemoteArtifactCreate {
                key: "deadbeef",
                project_dir: project.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();

        let decoder = flate2::read::GzDecoder::new(fs::File::open(artifact_path).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect();
        assert!(!entries.contains(&PathBuf::from("outputs/dist/artifact.tar.gz")));
    }

    #[test]
    fn remote_artifact_restore_removes_files_absent_from_the_artifact() {
        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/current.txt"), "remote output").unwrap();
        let key = unique_key("remote-exact-outputs");
        let artifact_path = source.path().join("artifact.tar.gz");
        cache
            .create_remote(RemoteArtifactCreate {
                key: &key,
                project_dir: source.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();

        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join("dist")).unwrap();
        fs::write(target.path().join("dist/current.txt"), "old").unwrap();
        fs::write(target.path().join("dist/stale.txt"), "stale").unwrap();

        cache
            .restore_remote_exact(&key, &artifact_path, target.path(), &["dist/**".into()])
            .unwrap();

        assert_eq!(
            fs::read_to_string(target.path().join("dist/current.txt")).unwrap(),
            "remote output"
        );
        assert!(!target.path().join("dist/stale.txt").exists());
    }

    #[test]
    fn remote_artifact_rejects_cache_key_mismatch() {
        let cache = TestCache::new();
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), "remote output").unwrap();

        let key = unique_key("remote-key");
        let artifact_path = dir.path().join("remote-key.tar.gz");
        cache
            .create_remote(RemoteArtifactCreate {
                key: &key,
                project_dir: dir.path(),
                command: "node build.js",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();

        let err = cache
            .restore_remote("deadbeef", &artifact_path, dir.path())
            .unwrap_err();
        assert!(
            err.to_string().contains("key mismatch"),
            "mismatched remote artifact key must be rejected, got: {err}"
        );
    }

    #[test]
    fn remote_artifact_rejects_unexpected_top_level_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let cache = TestCache::new();
        let dir = tempfile::tempdir().unwrap();
        let artifact_path = dir.path().join("unexpected.tar.gz");
        let key = unique_key("remote-unexpected");

        {
            let file = fs::File::create(&artifact_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let meta = CacheMeta {
                command: "build".into(),
                cache_key: key.clone(),
                duration_ms: 1,
                output_file_count: 0,
            };
            let meta_json = serde_json::to_string(&meta).unwrap();
            append_bytes(
                &mut builder,
                Path::new(".lpm-cache/meta.json"),
                meta_json.as_bytes(),
            )
            .unwrap();
            append_bytes(&mut builder, Path::new("outside.txt"), b"nope").unwrap();
            builder.finish().unwrap();
        }

        let err = cache
            .restore_remote(&key, &artifact_path, dir.path())
            .unwrap_err();
        assert!(
            err.to_string().contains("unexpected entry"),
            "unexpected top-level entries must be rejected, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_archive_rejects_output_symlink_outside_project() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "outside-secret").unwrap();
        symlink(outside.path(), project.path().join("dist")).unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let archive_path = archive_dir.path().join("outputs.tar.gz");

        let error = create_archive(project.path(), &["dist/**".into()], &archive_path)
            .expect_err("an output symlink outside the project must be rejected");

        assert!(
            error.to_string().contains("outside project"),
            "output symlink error was unclear: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_archive_rejects_symlink_outputs_inside_the_project() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("source.txt"), "source").unwrap();
        symlink("../source.txt", project.path().join("dist/value.txt")).unwrap();

        let error = create_archive(
            project.path(),
            &["dist/**".into()],
            &project.path().join("outputs.tar.gz"),
        )
        .expect_err("symlink output semantics must not change during restore");

        assert!(
            error.to_string().contains("symlink"),
            "symlink output error was unclear: {error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn project_lock_identity_matches_case_aliases_on_case_insensitive_volumes() {
        let project = std::env::current_dir().unwrap();
        let Some(project_text) = project.to_str() else {
            return;
        };
        let alias = PathBuf::from(project_text.replacen("/Users/", "/users/", 1));
        if alias == project || !alias.exists() {
            return;
        }
        let root_dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(root_dir.path());

        assert_eq!(
            project_restore_lock_path(&root, &project).unwrap(),
            project_restore_lock_path(&root, &alias).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_keeps_the_project_identity_that_its_lock_protects() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "cached").unwrap();
        let key = unique_key("project-retarget-race");
        cache
            .store(&key, source.path(), "build", &["dist/**".into()], "", "", 1)
            .unwrap();

        let targets = tempfile::tempdir().unwrap();
        let first = targets.path().join("first");
        let second = targets.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let alias = targets.path().join("project");
        symlink(&first, &alias).unwrap();
        let barrier = install_race_barrier(&PROJECT_PATH_RACE_BARRIER, alias.clone());
        let root = cache.root;
        let worker_key = key;
        let worker_alias = alias.clone();
        let worker = std::thread::spawn(move || {
            restore_cache_with_root(&root, &worker_key, &worker_alias, &[])
        });

        barrier.validated.wait();
        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&PROJECT_PATH_RACE_BARRIER, &barrier);
        result.unwrap();

        assert_eq!(
            fs::read_to_string(first.join("dist/value.txt")).unwrap(),
            "cached"
        );
        assert!(
            !second.join("dist/value.txt").exists(),
            "restore mutated a project that its lock did not protect"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_replacement_of_the_canonical_project_after_locking() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "cached").unwrap();
        let key = unique_key("canonical-project-replacement");
        cache
            .store(&key, source.path(), "build", &["dist/**".into()], "", "", 1)
            .unwrap();

        let targets = tempfile::tempdir().unwrap();
        let project = targets.path().join("project");
        let moved_project = targets.path().join("moved-project");
        let replacement = targets.path().join("replacement");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&replacement).unwrap();
        let barrier = install_race_barrier(&PROJECT_PATH_RACE_BARRIER, project.clone());
        let root = cache.root;
        let worker_key = key;
        let worker_project = project.clone();
        let worker = std::thread::spawn(move || {
            restore_cache_with_root(&root, &worker_key, &worker_project, &[])
        });

        barrier.validated.wait();
        fs::rename(&project, &moved_project).unwrap();
        symlink(&replacement, &project).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&PROJECT_PATH_RACE_BARRIER, &barrier);

        assert!(
            result.is_err(),
            "restore accepted a replacement for its locked project directory"
        );
        assert!(!moved_project.join("dist/value.txt").exists());
        assert!(!replacement.join("dist/value.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cache_metadata_read_uses_the_file_that_passed_validation() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let key = unique_key("metadata-retarget-race");
        cache
            .store(&key, project.path(), "build", &[], "", "", 1)
            .unwrap();
        let entry = cache.entry(&key);
        let metadata_path = entry.join("meta.json");
        let outside = tempfile::tempdir().unwrap();
        let outside_metadata = outside.path().join("meta.json");
        fs::write(
            &outside_metadata,
            serde_json::to_vec(&CacheMeta {
                command: "external".into(),
                cache_key: key.clone(),
                duration_ms: 999,
                output_file_count: 0,
            })
            .unwrap(),
        )
        .unwrap();
        let barrier = install_race_barrier(&CACHE_FILE_READ_RACE_BARRIER, metadata_path.clone());
        let root = cache.root;
        let worker_key = key;
        let worker_project = project.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            restore_cache_with_root(&root, &worker_key, &worker_project, &[])
        });

        barrier.validated.wait();
        fs::remove_file(&metadata_path).unwrap();
        symlink(&outside_metadata, &metadata_path).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&CACHE_FILE_READ_RACE_BARRIER, &barrier);

        assert_eq!(
            result.unwrap().meta.duration_ms,
            1,
            "cache metadata read followed a file swapped in after validation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_archive_read_uses_the_file_that_passed_validation() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "cached-value").unwrap();
        let key = unique_key("archive-retarget-race");
        cache
            .store(&key, source.path(), "build", &["dist/**".into()], "", "", 1)
            .unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("dist")).unwrap();
        fs::write(outside.path().join("dist/value.txt"), "external-value").unwrap();
        let outside_archive = outside.path().join("outside.tar.gz");
        create_archive(outside.path(), &["dist/**".into()], &outside_archive).unwrap();
        let archive_path = cache.entry(&key).join("outputs.tar.gz");
        let target = tempfile::tempdir().unwrap();
        let barrier = install_race_barrier(&CACHE_FILE_READ_RACE_BARRIER, archive_path.clone());
        let root = cache.root;
        let worker_key = key;
        let worker_target = target.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            restore_cache_with_root(&root, &worker_key, &worker_target, &[])
        });

        barrier.validated.wait();
        fs::remove_file(&archive_path).unwrap();
        symlink(&outside_archive, &archive_path).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&CACHE_FILE_READ_RACE_BARRIER, &barrier);
        result.unwrap();

        assert_eq!(
            fs::read_to_string(target.path().join("dist/value.txt")).unwrap(),
            "cached-value",
            "cache restore followed an archive swapped in after validation"
        );
    }

    #[test]
    fn create_archive_handles_glob_metacharacters_in_project_path() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project[abc]");
        fs::create_dir_all(project.join("dist")).unwrap();
        fs::write(project.join("dist/value.txt"), "value").unwrap();
        let archive_path = root.path().join("outputs.tar.gz");

        let file_count = create_archive(&project, &["dist/**".into()], &archive_path).unwrap();

        assert_eq!(file_count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn cache_snapshot_rejects_an_output_replaced_by_a_symlink_after_validation() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "inside").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "outside-secret").unwrap();
        let key = unique_key("snapshot-symlink-race");
        let barrier = install_race_barrier(
            &SNAPSHOT_RACE_BARRIER,
            project.path().join("dist/value.txt"),
        );
        let root = cache.root;
        let project_path = project.path().to_path_buf();
        let worker_key = key;
        let worker = std::thread::spawn(move || {
            store_cache_with_root(
                &root,
                &worker_key,
                &project_path,
                "build",
                &["dist/**".into()],
                "",
                "",
                1,
            )
        });

        barrier.validated.wait();
        fs::remove_file(project.path().join("dist/value.txt")).unwrap();
        symlink(
            outside.path().join("secret.txt"),
            project.path().join("dist/value.txt"),
        )
        .unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&SNAPSHOT_RACE_BARRIER, &barrier);

        assert!(
            result.is_err(),
            "a raced output symlink was archived outside the project"
        );
    }

    #[test]
    fn cache_snapshot_rejects_file_growth_after_size_validation() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        let output = project.path().join("dist/value.txt");
        fs::write(&output, "a").unwrap();
        let archive_path = project.path().join("outputs.tar.gz");
        let barrier = install_race_barrier(&ARCHIVE_SIZE_RACE_BARRIER, output.clone());
        let project_path = project.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            create_archive(&project_path, &["dist/**".into()], &archive_path)
        });

        barrier.validated.wait();
        fs::OpenOptions::new()
            .append(true)
            .open(&output)
            .unwrap()
            .write_all(b"b")
            .unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&ARCHIVE_SIZE_RACE_BARRIER, &barrier);

        assert!(
            result.is_err(),
            "a task output that grew after size validation was archived"
        );
    }

    #[test]
    fn cache_snapshot_rejects_same_size_rewrite_after_validation() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        let output = project.path().join("dist/value.txt");
        fs::write(&output, "before").unwrap();
        let archive_path = project.path().join("outputs.tar.gz");
        let barrier = install_race_barrier(&ARCHIVE_SIZE_RACE_BARRIER, output.clone());
        let project_path = project.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            create_archive(&project_path, &["dist/**".into()], &archive_path)
        });

        barrier.validated.wait();
        fs::write(&output, "after!").unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&ARCHIVE_SIZE_RACE_BARRIER, &barrier);

        assert!(
            result.is_err(),
            "a task output rewritten after validation was archived"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_remote_artifact_rejects_preexisting_symlink_destination() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "remote-value").unwrap();
        let artifact_path = source.path().join("artifact.tar.gz");
        let key = unique_key("remote-destination-symlink");
        cache
            .create_remote(RemoteArtifactCreate {
                key: &key,
                project_dir: source.path(),
                command: "build",
                output_globs: &["dist/**".into()],
                stdout: "",
                stderr: "",
                duration_ms: 1,
                artifact_path: &artifact_path,
            })
            .unwrap();

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("value.txt"), "outside-original").unwrap();
        symlink(outside.path(), target.path().join("dist")).unwrap();

        let result = cache.restore_remote(&key, &artifact_path, target.path());

        assert!(result.is_err(), "a symlink destination was accepted");
        assert_eq!(
            fs::read_to_string(outside.path().join("value.txt")).unwrap(),
            "outside-original"
        );
    }

    #[test]
    fn restore_remote_artifact_validation_failure_leaves_project_unchanged() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let cache = TestCache::new();
        let artifact_dir = tempfile::tempdir().unwrap();
        let artifact_path = artifact_dir.path().join("missing-meta.tar.gz");
        {
            let file = fs::File::create(&artifact_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);
            append_bytes(
                &mut builder,
                Path::new("outputs/dist/value.txt"),
                b"rejected-value",
            )
            .unwrap();
            builder.finish().unwrap();
        }

        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join("dist")).unwrap();
        fs::write(target.path().join("dist/value.txt"), "original-value").unwrap();

        let result = cache.restore_remote("deadbeef", &artifact_path, target.path());

        assert!(result.is_err(), "an artifact without metadata was accepted");
        assert_eq!(
            fs::read_to_string(target.path().join("dist/value.txt")).unwrap(),
            "original-value"
        );
    }

    #[test]
    fn restore_archive_failure_leaves_project_unchanged() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let archive_dir = tempfile::tempdir().unwrap();
        let archive_path = archive_dir.path().join("partially-invalid.tar.gz");
        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);
            append_bytes(&mut builder, Path::new("dist/value.txt"), b"rejected-value").unwrap();

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("dist/link").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join("dist")).unwrap();
        fs::write(target.path().join("dist/value.txt"), "original-value").unwrap();

        let result = restore_archive(&archive_path, target.path());

        assert!(result.is_err(), "an archive with a symlink was accepted");
        assert_eq!(
            fs::read_to_string(target.path().join("dist/value.txt")).unwrap(),
            "original-value"
        );
    }

    #[test]
    fn restore_does_not_apply_output_that_failed_to_finalize() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "cached-value").unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let archive_path = archive_dir.path().join("outputs.tar.gz");
        create_archive(source.path(), &["dist/**".into()], &archive_path).unwrap();

        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join("dist")).unwrap();
        fs::write(target.path().join("dist/value.txt"), "original-value").unwrap();
        *STAGED_FILE_FINALIZE_FAILURE.lock().unwrap() = Some(StagedFileFinalizeFailure {
            project: std::fs::canonicalize(target.path()).unwrap(),
            relative: PathBuf::from("dist/value.txt"),
        });

        let result = restore_archive(&archive_path, target.path());
        *STAGED_FILE_FINALIZE_FAILURE.lock().unwrap() = None;

        let error = result.expect_err("an unfinished staged output was applied");
        assert!(
            error
                .to_string()
                .contains("finalize staged task cache output")
        );
        assert_eq!(
            fs::read_to_string(target.path().join("dist/value.txt")).unwrap(),
            "original-value"
        );
    }

    #[test]
    fn restoring_many_new_outputs_uses_a_bounded_number_of_durability_syncs() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        for index in 0..64 {
            fs::write(
                source.path().join(format!("dist/value-{index:02}.txt")),
                format!("cached-value-{index}"),
            )
            .unwrap();
        }
        let archive_dir = tempfile::tempdir().unwrap();
        let archive_path = archive_dir.path().join("outputs.tar.gz");
        create_archive(source.path(), &["dist/**".into()], &archive_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let (result, syncs) =
            count_restore_durability_syncs(|| restore_archive(&archive_path, target.path()));

        result.unwrap();
        assert!(
            syncs <= 16,
            "restoring 64 reconstructible outputs issued {syncs} durability syncs"
        );
    }

    #[test]
    fn restoring_a_deep_new_output_uses_a_bounded_number_of_durability_syncs() {
        let source = tempfile::tempdir().unwrap();
        let mut relative = PathBuf::from("dist");
        for index in 0..64 {
            relative.push(format!("level-{index:02}"));
        }
        fs::create_dir_all(source.path().join(&relative)).unwrap();
        relative.push("value.txt");
        fs::write(source.path().join(&relative), "cached-value").unwrap();
        let archive_dir = tempfile::tempdir().unwrap();
        let archive_path = archive_dir.path().join("outputs.tar.gz");
        create_archive(source.path(), &["dist/**".into()], &archive_path).unwrap();
        let target = tempfile::tempdir().unwrap();

        let (result, syncs) =
            count_restore_durability_syncs(|| restore_archive(&archive_path, target.path()));

        result.unwrap();
        assert!(
            syncs <= 16,
            "restoring one deeply nested reconstructible output issued {syncs} durability syncs"
        );
    }

    #[test]
    fn restore_transaction_rolls_back_files_after_apply_failure() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("existing.txt"), "original").unwrap();
        fs::write(project.path().join("blocked"), "must-remain").unwrap();

        let staging = tempfile::tempdir_in(project.path()).unwrap();
        let outputs = staging.path().join("outputs");
        let backups = staging.path().join("backups");
        fs::create_dir_all(outputs.join("blocked")).unwrap();
        fs::create_dir(&backups).unwrap();
        fs::write(outputs.join("existing.txt"), "replacement").unwrap();
        fs::write(outputs.join("blocked/value.txt"), "rejected").unwrap();

        let mut transaction =
            RestoreTransaction::new(project.path().to_path_buf(), staging.path(), 2).unwrap();
        transaction
            .install(Path::new("existing.txt"), true)
            .unwrap();
        let error = transaction
            .install(Path::new("blocked/value.txt"), false)
            .expect_err("an incompatible parent must fail the restore");
        drop(transaction.rollback_error(error));

        assert_eq!(
            fs::read_to_string(project.path().join("existing.txt")).unwrap(),
            "original"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("blocked")).unwrap(),
            "must-remain"
        );
    }

    #[test]
    fn restore_install_sync_failure_preserves_the_original_output() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("value.txt"), "original").unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir(staging.path().join("outputs")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        fs::write(staging.path().join("outputs/value.txt"), "replacement").unwrap();
        let project_path = project.path().to_path_buf();
        *BACKUP_SYNC_FAILURE.lock().unwrap() = Some(BackupSyncFailure {
            project: project_path.clone(),
            relative: PathBuf::from("value.txt"),
        });

        let mut transaction = RestoreTransaction::new(project_path, staging.path(), 1).unwrap();
        let result = transaction.install(Path::new("value.txt"), true);
        *BACKUP_SYNC_FAILURE.lock().unwrap() = None;
        drop(transaction);

        assert!(
            result.is_err(),
            "the injected sync failure was not observed"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("value.txt"))
                .ok()
                .as_deref(),
            Some("original")
        );
    }

    #[test]
    fn stale_output_backup_sync_failure_preserves_the_original_output() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("stale.txt"), "original").unwrap();
        let staged = StagedOutputs::new(&cache.root, project.path()).unwrap();
        let canonical_project = std::fs::canonicalize(project.path()).unwrap();
        *BACKUP_SYNC_FAILURE.lock().unwrap() = Some(BackupSyncFailure {
            project: canonical_project,
            relative: PathBuf::from("stale.txt"),
        });

        let result = staged.apply(&["stale.txt".into()]);
        *BACKUP_SYNC_FAILURE.lock().unwrap() = None;

        assert!(
            result.is_err(),
            "the injected sync failure was not observed"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("stale.txt"))
                .ok()
                .as_deref(),
            Some("original")
        );
    }

    #[test]
    fn restore_uses_the_verified_staging_directory_after_its_path_is_replaced() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let archive_path = project.path().join("staged.tar.gz");
        {
            let file = fs::File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(encoder);
            append_bytes(&mut builder, Path::new("dist/value.txt"), b"verified").unwrap();
            builder.finish().unwrap();
        }
        let file = fs::File::open(&archive_path).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        let mut staged = StagedOutputs::new(&cache.root, project.path()).unwrap();
        staged
            .append(&mut entry, Path::new("dist/value.txt"))
            .unwrap();

        let staging_path = staged.temp_path().to_path_buf();
        let moved_staging = project.path().join("moved-staging");
        fs::rename(&staging_path, &moved_staging).unwrap();
        fs::create_dir_all(staging_path.join("outputs/dist")).unwrap();
        fs::create_dir(staging_path.join("backups")).unwrap();
        fs::write(staging_path.join("outputs/dist/value.txt"), "attacker").unwrap();

        staged.apply(&[]).unwrap();

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "verified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_a_parent_replaced_by_a_symlink_after_validation() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir_all(staging.path().join("outputs/dist")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        fs::write(staging.path().join("outputs/dist/value.txt"), "cached").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let barrier =
            install_race_barrier(&RESTORE_RACE_BARRIER, project.path().join("dist/value.txt"));
        let project_path = project.path().to_path_buf();
        let staging_path = staging.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let mut transaction = RestoreTransaction::new(project_path, &staging_path, 1).unwrap();
            match transaction.install(Path::new("dist/value.txt"), false) {
                Ok(()) => transaction.commit(),
                Err(error) => Err(error),
            }
        });

        barrier.validated.wait();
        fs::rename(
            project.path().join("dist"),
            project.path().join("original-dist"),
        )
        .unwrap();
        symlink(outside.path(), project.path().join("dist")).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&RESTORE_RACE_BARRIER, &barrier);

        assert!(
            result.is_err(),
            "a raced restore parent redirected output outside the project"
        );
        assert!(
            !outside.path().join("value.txt").exists(),
            "restore wrote through a raced parent symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_never_publishes_a_staged_output_replaced_after_validation() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir_all(staging.path().join("outputs/dist")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        let staged_output = staging.path().join("outputs/dist/value.txt");
        fs::write(&staged_output, "verified").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("value.txt"), "attacker").unwrap();
        let barrier = install_race_barrier(
            &STAGED_OUTPUT_RACE_BARRIER,
            project.path().join("dist/value.txt"),
        );
        let project_path = project.path().to_path_buf();
        let staging_path = staging.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let mut transaction = RestoreTransaction::new(project_path, &staging_path, 1).unwrap();
            transaction.install(Path::new("dist/value.txt"), false)?;
            transaction.commit()
        });
        barrier.validated.wait();
        fs::rename(&staged_output, staging.path().join("verified-away")).unwrap();
        symlink(outside.path().join("value.txt"), &staged_output).unwrap();
        barrier.resume.wait();

        let result = worker.join().unwrap();
        clear_race_barrier(&STAGED_OUTPUT_RACE_BARRIER, &barrier);

        assert!(
            result.is_ok(),
            "restore could not use its verified source: {result:?}"
        );
        let restored = project.path().join("dist/value.txt");
        assert!(
            !fs::symlink_metadata(&restored)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(restored).unwrap(), "verified");
    }

    #[test]
    fn restore_keeps_an_inode_receipt_for_each_published_file_until_commit() {
        let project = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir_all(staging.path().join("outputs/dist")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        let staged_output = staging.path().join("outputs/dist/value.txt");
        fs::write(&staged_output, "verified").unwrap();
        let destination = project.path().join("dist/value.txt");
        let barrier = install_race_barrier(&PUBLISHED_OUTPUT_RACE_BARRIER, destination.clone());
        let project_path = project.path().to_path_buf();
        let staging_path = staging.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let mut transaction = RestoreTransaction::new(project_path, &staging_path, 1).unwrap();
            transaction.install(Path::new("dist/value.txt"), false)?;
            transaction.commit()
        });

        barrier.validated.wait();
        let staged_identity = same_file::Handle::from_path(&staged_output).unwrap();
        let destination_identity = same_file::Handle::from_path(&destination).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&PUBLISHED_OUTPUT_RACE_BARRIER, &barrier);

        result.unwrap();
        assert_eq!(staged_identity, destination_identity);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn restore_rolls_back_an_atomically_installed_output_tree_after_a_later_failure() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("blocked"), "must-remain").unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir_all(staging.path().join("outputs/dist")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        fs::write(staging.path().join("outputs/dist/value.txt"), "cached").unwrap();
        let mut transaction =
            RestoreTransaction::new(project.path().to_path_buf(), staging.path(), 2).unwrap();
        transaction
            .install_missing_top_level_trees(&[PathBuf::from("dist/value.txt")])
            .unwrap();

        let error = transaction
            .install(Path::new("blocked/value.txt"), false)
            .expect_err("the incompatible later output was accepted");
        let (_, rollback_failed) = transaction.rollback_error(error);

        assert!(
            !rollback_failed,
            "the installed output tree was not rolled back"
        );
        assert!(!project.path().join("dist").exists());
        assert_eq!(
            fs::read_to_string(project.path().join("blocked")).unwrap(),
            "must-remain"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn restore_rejects_a_top_level_staging_tree_replaced_after_validation() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(project.path()).unwrap();
        fs::create_dir_all(staging.path().join("outputs/dist")).unwrap();
        fs::create_dir(staging.path().join("backups")).unwrap();
        fs::write(staging.path().join("outputs/dist/value.txt"), "verified").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel.txt"), "outside").unwrap();
        let barrier = install_race_barrier(&STAGED_TREE_RACE_BARRIER, project.path().join("dist"));
        let project_path = project.path().to_path_buf();
        let staging_path = staging.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let mut transaction = RestoreTransaction::new(project_path, &staging_path, 1).unwrap();
            transaction.install_missing_top_level_trees(&[PathBuf::from("dist/value.txt")])
        });

        barrier.validated.wait();
        fs::rename(
            staging.path().join("outputs/dist"),
            staging.path().join("verified-away"),
        )
        .unwrap();
        symlink(outside.path(), staging.path().join("outputs/dist")).unwrap();
        barrier.resume.wait();
        let result = worker.join().unwrap();
        clear_race_barrier(&STAGED_TREE_RACE_BARRIER, &barrier);

        assert!(result.is_err(), "a replaced staging tree was published");
        assert!(!project.path().join("dist").exists());
        assert_eq!(
            fs::read_to_string(staging.path().join("verified-away/value.txt")).unwrap(),
            "verified"
        );
        assert_eq!(
            fs::read_to_string(outside.path().join("sentinel.txt")).unwrap(),
            "outside"
        );
    }

    #[test]
    fn a_new_restore_recovers_an_interrupted_restore_before_staging() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-interrupted");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "replacement").unwrap();
        fs::write(abandoned.join("backups/dist/value.txt"), "original").unwrap();

        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "original"
        );
        assert!(
            !abandoned.exists(),
            "recovered restore directory was not removed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_restore_uses_the_verified_backup_after_its_path_is_replaced() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-replaced-backup");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "replacement").unwrap();
        let backup = abandoned.join("backups/dist/value.txt");
        fs::write(&backup, "original").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("value.txt"), "attacker").unwrap();
        let barrier = install_race_barrier(&RECOVERY_BACKUP_RACE_BARRIER, backup.clone());
        let root = cache.root;
        let project_path = project.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            drop(StagedOutputs::new(&root, &project_path).unwrap());
        });

        barrier.validated.wait();
        fs::rename(&backup, abandoned.join("backups/dist/verified-away")).unwrap();
        symlink(outside.path().join("value.txt"), &backup).unwrap();
        barrier.resume.wait();
        worker.join().unwrap();
        clear_race_barrier(&RECOVERY_BACKUP_RACE_BARRIER, &barrier);

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "original"
        );
    }

    #[test]
    fn cache_clean_preserves_interrupted_restore_recovery_records() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-clean-recovery");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "original").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::rename(
            project.path().join("dist/value.txt"),
            abandoned.join("backups/dist/value.txt"),
        )
        .unwrap();

        clean_cache_with_root(&cache.root).unwrap();
        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_registry_rejection_does_not_chmod_a_link_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let cache = TestCache::new();
        fs::create_dir_all(cache.root.cache_tasks()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o755)).unwrap();
        symlink(
            outside.path(),
            cache.root.cache_root().join(".task-restores"),
        )
        .unwrap();
        let project = tempfile::tempdir().unwrap();

        let result = StagedOutputs::new(&cache.root, project.path());

        assert!(result.is_err(), "a linked restore registry was accepted");
        assert_eq!(
            fs::metadata(outside.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn interrupted_restore_recovery_removes_a_newly_installed_per_file_output() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-interrupted-new");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::write(abandoned.join("outputs/dist/value.txt"), "installed").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::hard_link(
            abandoned.join("outputs/dist/value.txt"),
            project.path().join("dist/value.txt"),
        )
        .unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert!(
            !project.path().join("dist/value.txt").exists(),
            "recovery kept an output that did not exist before the interrupted restore"
        );
    }

    #[test]
    fn failed_staging_cleanup_remains_discoverable_for_the_next_restore() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let staged = StagedOutputs::new(&cache.root, project.path()).unwrap();
        let abandoned = staged.temp_path().to_path_buf();
        *STAGING_CLEANUP_FAILURE.lock().unwrap() = Some(
            abandoned
                .file_name()
                .expect("restore staging directory name")
                .to_os_string(),
        );

        drop(staged);
        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert!(
            !abandoned.exists(),
            "failed cleanup removed its recovery registration"
        );
    }

    #[test]
    fn committed_restore_recovery_preserves_published_outputs() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-committed");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "installed").unwrap();
        fs::write(abandoned.join("backups/dist/value.txt"), "original").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        write_restore_committed_for_test(&abandoned).unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "installed"
        );
        assert!(
            !abandoned.exists(),
            "committed restore staging directory was not removed"
        );
    }

    #[test]
    fn committed_restore_recovery_survives_commit_marker_cleanup() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-committed-cleanup");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "installed").unwrap();
        fs::write(abandoned.join("backups/dist/value.txt"), "original").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        write_restore_committed_for_test(&abandoned).unwrap();
        mark_restore_registration_committed_for_test(&cache.root, project.path(), &abandoned)
            .unwrap();
        fs::remove_file(abandoned.join("committed")).unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "installed"
        );
    }

    #[test]
    fn a_new_restore_removes_an_abandoned_pre_apply_staging_directory() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-staging");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir(abandoned.join("backups")).unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::write(abandoned.join("outputs/dist/value.txt"), "staged").unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert!(
            !abandoned.exists(),
            "abandoned pre-apply staging directory was not removed"
        );
    }

    #[test]
    fn interrupted_restore_recovery_ignores_an_unowned_lookalike_directory() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-user-data");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "keep").unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "keep"
        );
        assert!(abandoned.exists(), "unowned project data was removed");
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_restore_recovery_ignores_a_forged_owner_with_open_permissions() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-forged-owner");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        fs::write(abandoned.join(RESTORE_OWNER_NAME), RESTORE_JOURNAL_MAGIC).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "keep").unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "keep"
        );
        assert!(abandoned.exists(), "forged project data was removed");
    }

    #[test]
    fn interrupted_restore_recovery_ignores_a_forged_owner_with_restricted_permissions() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project
            .path()
            .join(".lpm-cache-restore-forged-private-owner");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        mark_restore_directory_owned(&abandoned);
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "keep").unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "keep"
        );
        assert!(abandoned.exists(), "forged project data was removed");
    }

    #[test]
    fn interrupted_restore_recovery_ignores_an_oversized_owner_marker() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-oversized-owner");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist")).unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();
        mark_restore_directory_owned(&abandoned);
        fs::write(
            abandoned.join(RESTORE_OWNER_NAME),
            [RESTORE_JOURNAL_MAGIC, b"extra"].concat(),
        )
        .unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "keep").unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "keep"
        );
        assert!(abandoned.exists(), "invalid project data was removed");
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_restore_recovery_rejects_a_linked_backup_root() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-linked-backup");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "replacement").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("dist")).unwrap();
        fs::write(outside.path().join("dist/value.txt"), "outside").unwrap();
        symlink(outside.path(), abandoned.join("backups")).unwrap();

        let error = match StagedOutputs::new(&cache.root, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("a linked recovery backup root must be rejected"),
        };

        assert!(
            error.to_string().contains("backup"),
            "linked backup diagnostic was unclear: {error}"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "replacement"
        );
        assert_eq!(
            fs::read_to_string(outside.path().join("dist/value.txt")).unwrap(),
            "outside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_restore_recovery_rejects_a_linked_backup_parent() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project
            .path()
            .join(".lpm-cache-restore-linked-backup-parent");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir(abandoned.join("backups")).unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "replacement").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("dist")).unwrap();
        fs::write(outside.path().join("dist/value.txt"), "outside").unwrap();
        symlink(outside.path().join("dist"), abandoned.join("backups/dist")).unwrap();

        let error = match StagedOutputs::new(&cache.root, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("a linked recovery backup parent must be rejected"),
        };

        assert!(
            error.to_string().contains("backup"),
            "linked backup parent diagnostic was unclear: {error}"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "replacement"
        );
        assert_eq!(
            fs::read_to_string(outside.path().join("dist/value.txt")).unwrap(),
            "outside"
        );
    }

    #[test]
    fn interrupted_restore_recovery_rejects_a_directory_backup() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-directory-backup");
        fs::create_dir_all(abandoned.join("outputs/dist")).unwrap();
        fs::create_dir_all(abandoned.join("backups/dist/value.txt")).unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "replacement").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/value.txt")],
        )
        .unwrap();

        let error = match StagedOutputs::new(&cache.root, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("a directory recovery backup must be rejected"),
        };

        assert!(
            error.to_string().contains("backup"),
            "directory backup diagnostic was unclear: {error}"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "replacement"
        );
        assert!(abandoned.join("backups/dist/value.txt").is_dir());
    }

    #[test]
    fn interrupted_restore_recovery_removes_parent_directories_created_after_the_journal() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let abandoned = project.path().join(".lpm-cache-restore-created-parent");
        fs::create_dir_all(abandoned.join("outputs/dist/nested")).unwrap();
        fs::create_dir(abandoned.join("backups")).unwrap();
        register_restore_for_test(&cache.root, project.path(), &abandoned).unwrap();
        fs::write(abandoned.join("outputs/dist/nested/value.txt"), "staged").unwrap();
        write_restore_journal(
            &abandoned,
            project.path(),
            &[PathBuf::from("dist/nested/value.txt")],
        )
        .unwrap();
        fs::create_dir_all(project.path().join("dist/nested")).unwrap();

        drop(StagedOutputs::new(&cache.root, project.path()).unwrap());

        assert!(
            !project.path().join("dist").exists(),
            "recovery left a parent directory that did not predate the restore"
        );
    }

    #[test]
    fn preserve_recovery_data_keeps_the_staging_directory() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        let mut staged = StagedOutputs::new(&cache.root, project.path()).unwrap();
        let staging_path = staged.temp_path().to_path_buf();

        let error = staged.preserve_recovery_data(LpmError::Task("rollback failed".into()));

        assert!(staging_path.exists(), "recovery data was deleted");
        assert!(
            error
                .to_string()
                .contains(&staging_path.display().to_string()),
            "recovery path was omitted from the error: {error}"
        );
        fs::remove_dir_all(staging_path).unwrap();
    }

    #[test]
    fn restore_cache_rejects_missing_archive_when_metadata_declares_outputs() {
        let cache = TestCache::new();
        let key = unique_key("missing-archive");
        let entry = cache.entry(&key);
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("stdout.log"), "").unwrap();
        fs::write(entry.join("stderr.log"), "").unwrap();
        fs::write(
            entry.join("meta.json"),
            serde_json::to_vec(&CacheMeta {
                command: "build".into(),
                cache_key: key.clone(),
                duration_ms: 1,
                output_file_count: 1,
            })
            .unwrap(),
        )
        .unwrap();

        let project = tempfile::tempdir().unwrap();
        let error = match cache.restore(&key, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("metadata that declares outputs requires an archive"),
        };

        assert!(
            error.to_string().contains("missing outputs archive"),
            "missing archive error was unclear: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_cache_rejects_symlinked_archive_file() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        let key = unique_key("symlinked-archive");
        let entry = cache.entry(&key);
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("stdout.log"), "").unwrap();
        fs::write(entry.join("stderr.log"), "").unwrap();
        fs::write(
            entry.join("meta.json"),
            serde_json::to_vec(&CacheMeta {
                command: "build".into(),
                cache_key: key.clone(),
                duration_ms: 1,
                output_file_count: 1,
            })
            .unwrap(),
        )
        .unwrap();

        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("dist")).unwrap();
        fs::write(source.path().join("dist/value.txt"), "outside-cache").unwrap();
        let outside_archive = source.path().join("outside.tar.gz");
        create_archive(source.path(), &["dist/**".into()], &outside_archive).unwrap();
        symlink(&outside_archive, entry.join("outputs.tar.gz")).unwrap();

        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "original").unwrap();
        let error = cache
            .restore(&key, project.path())
            .expect_err("a symlinked local archive must be rejected");

        assert!(
            error.to_string().contains("not a real file"),
            "symlinked archive error was unclear: {error}"
        );
        assert_eq!(
            fs::read_to_string(project.path().join("dist/value.txt")).unwrap(),
            "original"
        );
    }

    #[test]
    fn restore_cache_rejects_metadata_for_a_different_key() {
        let cache = TestCache::new();
        let key = unique_key("metadata-key");
        let entry = cache.entry(&key);
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("stdout.log"), "").unwrap();
        fs::write(entry.join("stderr.log"), "").unwrap();
        fs::write(
            entry.join("meta.json"),
            serde_json::to_vec(&CacheMeta {
                command: "build".into(),
                cache_key: "deadbeef".into(),
                duration_ms: 1,
                output_file_count: 0,
            })
            .unwrap(),
        )
        .unwrap();

        let project = tempfile::tempdir().unwrap();
        let error = match cache.restore(&key, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("metadata from a different cache key must be rejected"),
        };

        assert!(
            error.to_string().contains("key mismatch"),
            "cache key mismatch error was unclear: {error}"
        );
    }

    #[test]
    fn restore_cache_rejects_log_larger_than_capture_limit() {
        let cache = TestCache::new();
        let key = unique_key("oversized-log");
        let entry = cache.entry(&key);
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("stdout.log"), vec![b'x'; 10 * 1024 * 1024 + 65]).unwrap();
        fs::write(entry.join("stderr.log"), "").unwrap();
        fs::write(
            entry.join("meta.json"),
            serde_json::to_vec(&CacheMeta {
                command: "build".into(),
                cache_key: key.clone(),
                duration_ms: 1,
                output_file_count: 0,
            })
            .unwrap(),
        )
        .unwrap();

        let project = tempfile::tempdir().unwrap();
        let error = match cache.restore(&key, project.path()) {
            Err(error) => error,
            Ok(_) => panic!("an oversized replay log must be rejected"),
        };

        assert!(
            error.to_string().contains("stdout.log") && error.to_string().contains("oversized"),
            "oversized replay log error was unclear: {error}"
        );
    }

    #[test]
    fn concurrent_cache_stores_publish_one_complete_entry() {
        use std::sync::{Arc, Barrier};

        let cache = TestCache::new();
        let key = unique_key("concurrent-store");
        let barrier = Arc::new(Barrier::new(4));
        let mut projects = Vec::with_capacity(4);
        let mut expected = Vec::with_capacity(4);

        for producer in 0..4u8 {
            let project = tempfile::tempdir().unwrap();
            fs::create_dir_all(project.path().join("dist")).unwrap();
            let mut payload = vec![0u8; 8 * 1024 * 1024];
            let mut state = u64::from(producer) + 1;
            for byte in &mut payload {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            fs::write(project.path().join("dist/payload.bin"), &payload).unwrap();
            expected.push(payload);
            projects.push(project);
        }

        std::thread::scope(|scope| {
            for (producer, project) in projects.iter().enumerate() {
                let key = &key;
                let cache = &cache;
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    cache
                        .store(
                            key,
                            project.path(),
                            &format!("build-{producer}"),
                            &["dist/**".into()],
                            &format!("stdout-{producer}"),
                            "",
                            producer as u64,
                        )
                        .unwrap();
                });
            }
        });

        let restored = tempfile::tempdir().unwrap();
        let hit = cache.restore(&key, restored.path()).unwrap();
        let producer: usize = hit
            .meta
            .command
            .strip_prefix("build-")
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(hit.stdout, format!("stdout-{producer}"));
        assert_eq!(
            fs::read(restored.path().join("dist/payload.bin")).unwrap(),
            expected[producer]
        );
    }

    #[test]
    fn existing_cache_entry_does_not_wait_for_the_project_snapshot_lock() {
        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "cached").unwrap();
        let key = unique_key("existing-entry-project-lock");
        cache
            .store(
                &key,
                project.path(),
                "build",
                &["dist/**".into()],
                "",
                "",
                1,
            )
            .unwrap();
        let project_lock = lpm_common::acquire_single_file_exclusive_lock(
            project_restore_lock_path(&cache.root, project.path()).unwrap(),
        )
        .unwrap();
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let root = cache.root;
        let project_path = project.path().to_path_buf();
        let worker_key = key;
        let worker = std::thread::spawn(move || {
            let result = store_cache_with_root(
                &root,
                &worker_key,
                &project_path,
                "build",
                &["dist/**".into()],
                "",
                "",
                1,
            );
            completed_tx.send(()).unwrap();
            result
        });

        let completed = completed_rx.recv_timeout(std::time::Duration::from_secs(1));
        drop(project_lock);
        let result = worker.join().unwrap();

        result.unwrap();
        assert!(
            completed.is_ok(),
            "an existing cache entry waited for an unnecessary project snapshot lock"
        );
    }

    #[test]
    fn store_cache_waits_for_an_active_project_restore() {
        use std::sync::mpsc;
        use std::time::Duration;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "value").unwrap();
        let key = unique_key("store-project-lock");
        let restore_lock = lpm_common::acquire_single_file_exclusive_lock(
            project_restore_lock_path(&cache.root, project.path()).unwrap(),
        )
        .unwrap();
        let (finished_tx, finished_rx) = mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let result = cache.store(
                    &key,
                    project.path(),
                    "build",
                    &["dist/**".into()],
                    "",
                    "",
                    1,
                );
                finished_tx.send(result).unwrap();
            });

            assert!(
                finished_rx
                    .recv_timeout(Duration::from_millis(200))
                    .is_err(),
                "cache snapshot did not wait for the active project restore"
            );
            drop(restore_lock);
            finished_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("cache snapshot remained blocked")
                .unwrap();
        });
    }

    #[test]
    fn remote_artifact_creation_waits_for_an_active_project_restore() {
        use std::sync::mpsc;
        use std::time::Duration;

        let cache = TestCache::new();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir(project.path().join("dist")).unwrap();
        fs::write(project.path().join("dist/value.txt"), "value").unwrap();
        let key = unique_key("remote-project-lock");
        let restore_lock = lpm_common::acquire_single_file_exclusive_lock(
            project_restore_lock_path(&cache.root, project.path()).unwrap(),
        )
        .unwrap();
        let artifact_dir = tempfile::tempdir().unwrap();
        let artifact = artifact_dir.path().join("artifact.tar.gz");
        let (finished_tx, finished_rx) = mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let result = cache.create_remote(RemoteArtifactCreate {
                    key: &key,
                    project_dir: project.path(),
                    command: "build",
                    output_globs: &["dist/**".into()],
                    stdout: "",
                    stderr: "",
                    duration_ms: 1,
                    artifact_path: &artifact,
                });
                finished_tx.send(result).unwrap();
            });

            assert!(
                finished_rx
                    .recv_timeout(Duration::from_millis(200))
                    .is_err(),
                "remote snapshot did not wait for the active project restore"
            );
            drop(restore_lock);
            finished_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("remote snapshot remained blocked")
                .unwrap();
        });
    }

    // -- zip-slip prevention --

    #[test]
    fn restore_archive_rejects_path_traversal() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("evil.tar.gz");

        // Create a tar.gz with a path-traversal entry by writing raw header bytes.
        // The `tar` crate's `set_path` rejects `..` so we write the header manually.
        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let data = b"pwned";
            let mut header = tar::Header::new_gnu();
            // Use a benign path first, then overwrite the raw name bytes
            header.set_path("placeholder.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);

            // Overwrite the name field (first 100 bytes) with "../escape.txt"
            let evil_path = b"../escape.txt";
            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..evil_path.len()].copy_from_slice(evil_path);
            header.set_cksum();

            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let result = restore_archive(&archive_path, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal"),
            "error should mention path traversal, got: {err}"
        );
    }

    #[test]
    fn restore_archive_rejects_absolute_paths() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("absolute.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(enc);

            let data = b"pwned";
            let mut header = tar::Header::new_gnu();
            header.set_path("placeholder.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);

            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            let absolute_path = b"/absolute-escape.txt";
            raw[..absolute_path.len()].copy_from_slice(absolute_path);
            header.set_cksum();

            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        let result = restore_archive(&archive_path, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal"),
            "absolute archive paths should be rejected before unpack, got: {err}"
        );
    }

    #[test]
    fn restore_archive_allows_normal_paths() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("good.tar.gz");

        // Create a normal tar.gz
        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let data = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_path("dist/output.js").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.finish().unwrap();
        }

        restore_archive(&archive_path, dir.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("dist/output.js")).unwrap(),
            "hello"
        );
    }

    /// A symlink entry can disclose arbitrary files after restoration.
    #[test]
    fn restore_archive_refuses_symlink_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("symlink.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("evil-link").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let err = restore_archive(&archive_path, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular entry"),
            "symlink must be rejected; got: {msg}"
        );
    }

    /// FIFOs and device entries have no legitimate task-output meaning.
    #[test]
    fn restore_archive_refuses_fifo_entry() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("fifo.tar.gz");

        {
            let file = fs::File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(file, Compression::fast());
            let mut builder = Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Fifo);
            header.set_path("evil-fifo").unwrap();
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
            builder.finish().unwrap();
        }

        let err = restore_archive(&archive_path, dir.path()).unwrap_err();
        assert!(err.to_string().contains("non-regular entry"));
    }

    // -- glob pattern validation --

    #[test]
    fn validate_glob_rejects_parent_traversal() {
        assert!(!validate_glob_pattern("../../etc/passwd"));
        assert!(!validate_glob_pattern("../secret"));
        assert!(!validate_glob_pattern(".."));
        assert!(!validate_glob_pattern("..\\secret"));
        assert!(!validate_glob_pattern("dist\\..\\..\\secret"));
    }

    #[test]
    fn validate_glob_rejects_absolute_paths() {
        assert!(!validate_glob_pattern("/etc/shadow"));
        assert!(!validate_glob_pattern("/tmp/foo"));
        assert!(!validate_glob_pattern("C:\\temp\\foo"));
        assert!(!validate_glob_pattern("\\\\server\\share\\foo"));
    }

    #[test]
    fn validate_glob_rejects_embedded_traversal() {
        assert!(!validate_glob_pattern("src/../../etc/passwd"));
    }

    #[test]
    fn validate_glob_accepts_normal_patterns() {
        assert!(validate_glob_pattern("src/**"));
        assert!(validate_glob_pattern("dist/**/*"));
        assert!(validate_glob_pattern("*.js"));
        assert!(validate_glob_pattern("package.json"));
    }

    // -- cache directory permissions --

    #[cfg(unix)]
    #[test]
    fn cache_dir_permissions_are_700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("restricted");
        fs::create_dir_all(&sub).unwrap();
        set_dir_permissions_restricted(&sub).unwrap();

        let perms = fs::metadata(&sub).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o700,
            "directory should have 0o700 permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn clean_cache_unlinks_directory_symlinks_without_touching_targets() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("tasks");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("stale-file"), "stale").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep.txt"), "keep").unwrap();
        symlink(outside.path(), cache.join("linked-entry")).unwrap();

        assert_eq!(clean_cache_locked(&cache).unwrap(), 2);
        assert!(fs::read_dir(&cache).unwrap().next().is_none());
        assert_eq!(
            fs::read_to_string(outside.path().join("keep.txt")).unwrap(),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_store_rejects_a_linked_task_cache_root() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        fs::create_dir(cache.root.cache_root()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), "must-remain").unwrap();
        symlink(outside.path(), cache.root.cache_tasks()).unwrap();
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("output.txt"), "output").unwrap();

        let result = cache.store(
            "deadbeef",
            project.path(),
            "build",
            &["output.txt".into()],
            "",
            "",
            1,
        );

        assert!(result.is_err(), "a linked task cache root was accepted");
        assert_eq!(
            fs::read_to_string(outside.path().join("sentinel")).unwrap(),
            "must-remain"
        );
        assert!(!outside.path().join("deadbeef").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cache_clean_rejects_a_linked_task_cache_root() {
        use std::os::unix::fs::symlink;

        let cache = TestCache::new();
        fs::create_dir(cache.root.cache_root()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), "must-remain").unwrap();
        symlink(outside.path(), cache.root.cache_tasks()).unwrap();

        let result = clean_cache_with_root(&cache.root);

        assert!(result.is_err(), "a linked task cache root was cleaned");
        assert_eq!(
            fs::read_to_string(outside.path().join("sentinel")).unwrap(),
            "must-remain"
        );
    }

    // -- cache key validation --

    #[test]
    fn cache_entry_dir_rejects_path_traversal_key() {
        let cache = TestCache::new();
        let result = cache_entry_dir_with_root(&cache.root, "../etc/passwd");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid cache key"),
            "should reject non-hex key, got: {err}"
        );
    }

    #[test]
    fn cache_entry_dir_rejects_empty_key() {
        let cache = TestCache::new();
        assert!(cache_entry_dir_with_root(&cache.root, "").is_err());
    }

    #[test]
    fn cache_entry_dir_accepts_valid_hex_key() {
        let cache = TestCache::new();
        let result = cache_entry_dir_with_root(&cache.root, "abcdef0123456789");
        assert!(result.is_ok());
    }
}
